//! Small, genuinely-distributed threshold ML-DSA-65 aggregation driver.
//!
//! This binary is the Rust half of a real 3-party distributed signing run. It
//! never runs the MPC itself; the companion orchestrator
//! `scripts/run_small_distributed_aggregation.py` drives the real MP-SPDZ MAMA
//! (malicious, dishonest-majority) `mldsa65_expandmask` circuit across three
//! parties. This binary only:
//!
//!   * `emit-inputs` — deals a trusted-setup ML-DSA-65 key, derives `mu` and the
//!     coordinator-side `rhopp`, asserts the `rhopp` consistency gate, XOR-splits
//!     `K` and `rnd` into per-party MPC inputs, and writes the exact
//!     `Input-P{p}-0` byte assignments the circuit consumes.
//!   * `sign` — imports the real per-party `Binary-Output-P{p}-0` additive-mask
//!     shares, checks byte-exact FIPS 204 equivalence, then runs the custody
//!     distributed Sign_internal path and the standard ML-DSA verifier on the
//!     produced signature.
//!
//! The signing key here is a locally dealt trusted-setup secret split into
//! Shamir shares, so this is emphatically NOT a no-single-secret nor dealerless
//! path. `no_single_secret_signing_path` is and stays `false`.

#[cfg(not(feature = "raw-real-mldsa"))]
fn main() {
    eprintln!(
        "small_distributed_aggregation requires the raw-real-mldsa feature; \
         re-run with `cargo run --features raw-real-mldsa --bin small_distributed_aggregation`"
    );
    std::process::exit(2);
}

#[cfg(feature = "raw-real-mldsa")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    driver::main()
}

#[cfg(feature = "raw-real-mldsa")]
mod driver {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };

    use lattice_aggregation::{
        backend::Mldsa65Backend, import_expandmask_attempt, keygen_from_seed, mpc_input_assignment,
        provision_signer_custody_handles_from_seed_for_test, sign_internal_empty_ctx,
        signing_set_lagrange_weights, strict_distributed_sign_from_custody_and_mask_outputs,
        CustodySigningInputs, MaskConsumptionLedger, RealMldsa65Backend, ValidatorId,
        XorShareSet32, BINARY_OUTPUT_BYTE_LEN, MODULE_L,
    };

    /// Retry step of the signer's rejection loop (matches `(..).step_by(L)`).
    const KAPPA_STEP: u16 = MODULE_L as u16;

    // ---- small hex + arg helpers -------------------------------------------

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
        let text = text.trim();
        if !text.len().is_multiple_of(2) {
            return Err(format!("hex string has odd length: {}", text.len()));
        }
        (0..text.len() / 2)
            .map(|index| {
                u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
                    .map_err(|error| format!("invalid hex: {error}"))
            })
            .collect()
    }

    fn parse_flags(args: &[String]) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        let mut index = 0;
        while index < args.len() {
            let token = &args[index];
            if let Some(key) = token.strip_prefix("--") {
                if index + 1 < args.len() && !args[index + 1].starts_with("--") {
                    map.insert(key.to_string(), args[index + 1].clone());
                    index += 2;
                } else {
                    map.insert(key.to_string(), "true".to_string());
                    index += 1;
                }
            } else {
                index += 1;
            }
        }
        map
    }

    fn require<'a>(flags: &'a BTreeMap<String, String>, key: &str) -> Result<&'a String, String> {
        flags
            .get(key)
            .ok_or_else(|| format!("missing required flag --{key}"))
    }

    fn seed32(flags: &BTreeMap<String, String>, key: &str) -> Result<[u8; 32], String> {
        let bytes = hex_decode(require(flags, key)?)?;
        if bytes.len() != 32 {
            return Err(format!("--{key} must be 32 bytes, got {}", bytes.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn parse_validators(text: &str) -> Result<Vec<ValidatorId>, String> {
        text.split(',')
            .map(|piece| {
                piece
                    .trim()
                    .parse::<u16>()
                    .map(ValidatorId)
                    .map_err(|error| format!("invalid validator id '{piece}': {error}"))
            })
            .collect()
    }

    fn parse_kappa_list(text: &str) -> Result<Vec<u16>, String> {
        text.split(',')
            .filter(|piece| !piece.trim().is_empty())
            .map(|piece| {
                piece
                    .trim()
                    .parse::<u16>()
                    .map_err(|error| format!("invalid kappa '{piece}': {error}"))
            })
            .collect()
    }

    // ---- deterministic setup material --------------------------------------

    fn shake256_xof(chunks: &[&[u8]], out_len: usize) -> Vec<u8> {
        let mut hasher = Shake256::default();
        for chunk in chunks {
            hasher.update(chunk);
        }
        let mut out = vec![0u8; out_len];
        hasher.finalize_xof().read(&mut out);
        out
    }

    /// `mu = SHAKE256(tr || 0x00 || 0x00 || message)` truncated to 64 bytes.
    fn compute_mu(tr: &[u8; 64], message: &[u8]) -> [u8; 64] {
        let bytes = shake256_xof(&[tr, &[0u8], &[0u8], message], 64);
        let mut mu = [0u8; 64];
        mu.copy_from_slice(&bytes);
        mu
    }

    /// `rhopp = SHAKE256(k_seed || rnd || mu)` truncated to 64 bytes.
    fn compute_rhopp(k_seed: &[u8; 32], rnd: &[u8; 32], mu: &[u8; 64]) -> [u8; 64] {
        let bytes = shake256_xof(&[k_seed, rnd, mu], 64);
        let mut rhopp = [0u8; 64];
        rhopp.copy_from_slice(&bytes);
        rhopp
    }

    /// Deterministic DKG-transcript digest bound into linkage / provisioning.
    fn dkg_transcript_digest(
        seed: &[u8; 32],
        threshold: u16,
        validators: &[ValidatorId],
    ) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(b"small-distributed-aggregation/dkg-transcript/v1");
        hasher.update(seed);
        hasher.update(&threshold.to_le_bytes());
        hasher.update(&(validators.len() as u64).to_be_bytes());
        for validator in validators {
            hasher.update(&validator.0.to_le_bytes());
        }
        let mut digest = [0u8; 32];
        hasher.finalize_xof().read(&mut digest);
        digest
    }

    /// Deterministic material used to Shamir-split `s1`/`s2` into custody shares.
    fn share_seed_material(seed: &[u8; 32]) -> Vec<u8> {
        let mut material = b"small-distributed-aggregation/share-seed/v1".to_vec();
        material.extend_from_slice(seed);
        material
    }

    /// XOR-split a 32-byte secret into exactly `parties` shares that XOR back to
    /// the secret. Deterministic in `seed` so emit-inputs is reproducible.
    fn xor_split(
        secret: &[u8; 32],
        parties: usize,
        label: &[u8],
        seed: &[u8; 32],
    ) -> XorShareSet32 {
        let mut shares: Vec<[u8; 32]> = Vec::with_capacity(parties);
        let mut aggregate = [0u8; 32];
        for player in 0..parties - 1 {
            let mut hasher = Shake256::default();
            hasher.update(label);
            hasher.update(seed);
            hasher.update(&(player as u32).to_le_bytes());
            let mut share = [0u8; 32];
            hasher.finalize_xof().read(&mut share);
            for (accumulator, byte) in aggregate.iter_mut().zip(share.iter()) {
                *accumulator ^= *byte;
            }
            shares.push(share);
        }
        let mut last = [0u8; 32];
        for (index, byte) in last.iter_mut().enumerate() {
            *byte = secret[index] ^ aggregate[index];
        }
        shares.push(last);
        XorShareSet32::new(shares)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, bytes);
        hex_encode(&hasher.finalize())
    }

    // ---- emit-inputs -------------------------------------------------------

    fn emit_inputs(flags: &BTreeMap<String, String>) -> Result<(), String> {
        let seed = seed32(flags, "seed")?;
        let rnd = seed32(flags, "rnd")?;
        let message = require(flags, "message")?.clone();
        let threshold: u16 = require(flags, "threshold")?
            .parse()
            .map_err(|error| format!("invalid threshold: {error}"))?;
        let validators = parse_validators(require(flags, "validators")?)?;
        let run_dir = PathBuf::from(require(flags, "run-dir")?);

        if (validators.len() as u16) < threshold || threshold == 0 {
            return Err(format!(
                "threshold {threshold} incompatible with {} validators",
                validators.len()
            ));
        }
        let parties = threshold as usize;

        // Trusted-setup keygen: derive K (k_seed) and tr.
        let secret = keygen_from_seed(&seed).map_err(|error| format!("keygen: {error:?}"))?;
        let mu = compute_mu(&secret.tr, message.as_bytes());
        let expected_rhopp = compute_rhopp(&secret.k_seed, &rnd, &mu);

        // Provision custody handles + coordinator context (also gives ctx.rhopp).
        let dkg_digest = dkg_transcript_digest(&seed, threshold, &validators);
        let material = share_seed_material(&seed);
        let (_handles, ctx) = provision_signer_custody_handles_from_seed_for_test(
            &seed,
            &rnd,
            message.as_bytes(),
            threshold,
            &validators,
            dkg_digest,
            &material,
        )
        .map_err(|error| format!("provision handles: {error:?}"))?;

        // CONSISTENCY GATE: the ctx.rhopp the custody path will use must equal
        // SHAKE256(k_seed || rnd || mu), which is exactly what the MPC computes
        // internally after XOR-reconstructing K and rnd. Do NOT disable this.
        if ctx.rhopp != expected_rhopp {
            return Err(format!(
                "rhopp consistency gate FAILED: ctx.rhopp={} expected SHAKE256(K||rnd||mu)={}",
                hex_encode(&ctx.rhopp),
                hex_encode(&expected_rhopp)
            ));
        }

        // Preflight: run the local FIPS signer to learn how many rejection
        // retries this (seed, rnd, message) needs. Because the custody path uses
        // the identical rhopp and rejection predicates, the accepted kappa_base
        // here is exactly the one the distributed run will accept at.
        let (_sig, _z, local_rejected) = sign_internal_empty_ctx(&secret, message.as_bytes(), &rnd)
            .map_err(|error| format!("local preflight sign: {error:?}"))?;
        let local_accepted_kappa_base = local_rejected.saturating_mul(u32::from(KAPPA_STEP));

        // XOR-split K and rnd across the parties; build per-player MPC inputs.
        let k_shares = xor_split(
            &secret.k_seed,
            parties,
            b"mldsa-expandmask-key-share",
            &seed,
        );
        let rnd_shares = xor_split(&rnd, parties, b"mldsa-expandmask-rnd-share", &seed);

        let player_data = run_dir.join("Player-Data");
        fs::create_dir_all(&player_data).map_err(|error| format!("mkdir Player-Data: {error}"))?;
        for player in 0..parties {
            let values = mpc_input_assignment(player, &k_shares, &rnd_shares, &mu);
            let line = values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            let path = player_data.join(format!("Input-P{player}-0"));
            fs::write(&path, format!("{line}\n"))
                .map_err(|error| format!("write {}: {error}", path.display()))?;
        }

        // params.json — public evidence + preflight guidance for the orchestrator.
        let validators_json = validators
            .iter()
            .map(|validator| validator.0.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let params = format!(
            "{{\n  \"schema\": \"small-distributed-aggregation:params:v1\",\n  \
             \"threshold\": {threshold},\n  \"parties\": {parties},\n  \
             \"validators\": [{validators_json}],\n  \
             \"message\": {message:?},\n  \
             \"seed_hex\": \"{seed_hex}\",\n  \"rnd_hex\": \"{rnd_hex}\",\n  \
             \"mu_hex\": \"{mu_hex}\",\n  \"rhopp_hex\": \"{rhopp_hex}\",\n  \
             \"tr_hex\": \"{tr_hex}\",\n  \"public_key_hex\": \"{pk_hex}\",\n  \
             \"dkg_transcript_digest_hex\": \"{dkg_hex}\",\n  \
             \"local_rejected_attempts\": {local_rejected},\n  \
             \"local_accepted_kappa_base\": {local_accepted_kappa_base},\n  \
             \"kappa_step\": {step}\n}}\n",
            seed_hex = hex_encode(&seed),
            rnd_hex = hex_encode(&rnd),
            mu_hex = hex_encode(&mu),
            rhopp_hex = hex_encode(&ctx.rhopp),
            tr_hex = hex_encode(&ctx.tr),
            pk_hex = hex_encode(&ctx.public_key.0),
            dkg_hex = hex_encode(&dkg_digest),
            step = KAPPA_STEP,
        );
        let params_path = run_dir.join("params.json");
        fs::write(&params_path, &params)
            .map_err(|error| format!("write {}: {error}", params_path.display()))?;

        println!(
            "emit-inputs OK: parties={parties} rhopp_consistency=asserted \
             local_rejected_attempts={local_rejected} \
             local_accepted_kappa_base={local_accepted_kappa_base} \
             inputs={}",
            player_data.display()
        );
        Ok(())
    }

    // ---- sign --------------------------------------------------------------

    fn read_party_blob(base: &Path, kappa: u16, player: usize) -> Result<Vec<u8>, String> {
        let path = base
            .join(format!("kappa-{kappa}"))
            .join("Player-Data")
            .join(format!("Binary-Output-P{player}-0"));
        let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
        if bytes.len() != BINARY_OUTPUT_BYTE_LEN {
            return Err(format!(
                "{} is {} bytes, expected {}",
                path.display(),
                bytes.len(),
                BINARY_OUTPUT_BYTE_LEN
            ));
        }
        Ok(bytes)
    }

    fn sign(flags: &BTreeMap<String, String>) -> Result<(), String> {
        let seed = seed32(flags, "seed")?;
        let rnd = seed32(flags, "rnd")?;
        let message = require(flags, "message")?.clone();
        let threshold: u16 = require(flags, "threshold")?
            .parse()
            .map_err(|error| format!("invalid threshold: {error}"))?;
        let validators = parse_validators(require(flags, "validators")?)?;
        let run_dir = PathBuf::from(require(flags, "run-dir")?);
        let kappa_list = parse_kappa_list(require(flags, "kappa-list")?)?;
        let malicious_verified = require(flags, "malicious-verified")?.trim() == "true";

        let parties = threshold as usize;
        let signing_set = signing_set_lagrange_weights(&validators, threshold)
            .map_err(|error| format!("signing set: {error:?}"))?;

        // Re-provision the identical custody handles + context deterministically.
        let dkg_digest = dkg_transcript_digest(&seed, threshold, &validators);
        let material = share_seed_material(&seed);
        let (handles, ctx) = provision_signer_custody_handles_from_seed_for_test(
            &seed,
            &rnd,
            message.as_bytes(),
            threshold,
            &validators,
            dkg_digest,
            &material,
        )
        .map_err(|error| format!("provision handles: {error:?}"))?;

        // Import each requested kappa's real per-party MPC outputs into an
        // additive-mask attempt with fail-closed FIPS equivalence.
        let mut attempts = Vec::with_capacity(kappa_list.len());
        let mut per_kappa_party_sha256: Vec<(u16, Vec<String>)> = Vec::new();
        let mut mpc_digest_hasher = Shake256::default();
        Update::update(
            &mut mpc_digest_hasher,
            b"small-distributed-aggregation/mpc-transcript/v1",
        );
        for &kappa in &kappa_list {
            let mut party_blobs = Vec::with_capacity(parties);
            let mut party_hashes = Vec::with_capacity(parties);
            for player in 0..parties {
                let blob = read_party_blob(&run_dir, kappa, player)?;
                let hash = sha256_hex(&blob);
                Update::update(&mut mpc_digest_hasher, &kappa.to_le_bytes());
                Update::update(&mut mpc_digest_hasher, &(player as u32).to_le_bytes());
                Update::update(&mut mpc_digest_hasher, blob.as_slice());
                party_hashes.push(hash);
                party_blobs.push(blob);
            }
            per_kappa_party_sha256.push((kappa, party_hashes));
            let attempt = import_expandmask_attempt(
                &signing_set,
                &party_blobs,
                kappa,
                &ctx.rhopp,
                malicious_verified,
            )
            .map_err(|error| format!("import kappa {kappa}: {error:?}"))?;
            attempts.push(attempt);
        }
        let mut mpc_transcript_digest = [0u8; 32];
        mpc_digest_hasher
            .finalize_xof()
            .read(&mut mpc_transcript_digest);

        // Report the honest equivalence state per attempt before signing.
        let equivalence_report: Vec<(u16, bool, bool)> = attempts
            .iter()
            .map(|attempt| {
                (
                    attempt.kappa_base,
                    attempt.exact_expandmask_equivalence_verified,
                    attempt.malicious_mpc_verified,
                )
            })
            .collect();

        // Build the custody-signing inputs from the coordinator context.
        let inputs = CustodySigningInputs {
            public_key: &ctx.public_key,
            rho: &ctx.rho,
            tr: &ctx.tr,
            t0: &ctx.t0,
            rhopp: &ctx.rhopp,
            dkg_transcript_digest: &ctx.dkg_transcript_digest,
            mpc_transcript_digest: &mpc_transcript_digest,
            message: message.as_bytes(),
            threshold,
            validators: &validators,
        };

        let mut ledger = MaskConsumptionLedger::new();
        let sign_result = strict_distributed_sign_from_custody_and_mask_outputs(
            &inputs,
            &handles,
            &attempts,
            &mut ledger,
        );

        match sign_result {
            Ok(package) => {
                let standard_verifier_accepted = RealMldsa65Backend::verify_standard(
                    &package.public_key,
                    message.as_bytes(),
                    &package.signature,
                )
                .map_err(|error| format!("verify_standard: {error:?}"))?;
                let accepted_kappa = package.rejected_attempts * u32::from(KAPPA_STEP);
                let signature_hex = hex_encode(&package.signature.0);
                let signature_sha256 = sha256_hex(&package.signature.0);

                let equivalence_json = equivalence_report
                    .iter()
                    .map(|(kappa, equiv, mal)| {
                        format!(
                            "{{\"kappa\":{kappa},\"exact_equivalence\":{equiv},\
                             \"malicious_verified\":{mal}}}"
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let per_kappa_json = per_kappa_party_sha256
                    .iter()
                    .map(|(kappa, hashes)| {
                        let joined = hashes
                            .iter()
                            .map(|hash| format!("\"{hash}\""))
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("{{\"kappa\":{kappa},\"party_sha256\":[{joined}]}}")
                    })
                    .collect::<Vec<_>>()
                    .join(",");

                println!(
                    "{{\n  \"result\": \"accepted\",\n  \
                     \"accepted_kappa\": {accepted_kappa},\n  \
                     \"rejected_attempts\": {rejected},\n  \
                     \"standard_verifier_accepted\": {standard_verifier_accepted},\n  \
                     \"signature_len\": {siglen},\n  \
                     \"signature_sha256\": \"{signature_sha256}\",\n  \
                     \"end_to_end_linkage_digest_hex\": \"{linkage}\",\n  \
                     \"mask_input_binding_digest_hex\": \"{binding}\",\n  \
                     \"mpc_transcript_digest_hex\": \"{mpc_digest}\",\n  \
                     \"partial_count\": {partial_count},\n  \
                     \"additive_mask_outputs_consumed\": {consumed},\n  \
                     \"signer_consumes_custody_held_shares_without_export\": {no_export},\n  \
                     \"coordinator_holds_no_plaintext_share_vector\": {no_vector},\n  \
                     \"no_single_secret_signing_path\": {no_single},\n  \
                     \"malicious_verified_input\": {malicious_verified},\n  \
                     \"per_kappa_equivalence\": [{equivalence_json}],\n  \
                     \"per_kappa_party_sha256\": [{per_kappa_json}],\n  \
                     \"signature_hex\": \"{signature_hex}\"\n}}",
                    rejected = package.rejected_attempts,
                    siglen = package.signature.0.len(),
                    linkage = hex_encode(&package.end_to_end_linkage_digest),
                    binding = hex_encode(&package.mask_input_binding_digest),
                    mpc_digest = hex_encode(&mpc_transcript_digest),
                    partial_count = package.partial_count,
                    consumed = package.additive_mask_outputs_consumed,
                    no_export = package.signer_consumes_custody_held_shares_without_export,
                    no_vector = package.coordinator_holds_no_plaintext_share_vector,
                    no_single = package.no_single_secret_signing_path,
                );

                if !standard_verifier_accepted {
                    return Err("standard verifier REJECTED the produced signature".to_string());
                }
                Ok(())
            }
            Err(error) => {
                let equivalence_json = equivalence_report
                    .iter()
                    .map(|(kappa, equiv, mal)| {
                        format!(
                            "{{\"kappa\":{kappa},\"exact_equivalence\":{equiv},\
                             \"malicious_verified\":{mal}}}"
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{{\n  \"result\": \"rejected\",\n  \
                     \"error\": {error:?},\n  \
                     \"standard_verifier_accepted\": false,\n  \
                     \"kappa_list\": {kappa_list:?},\n  \
                     \"malicious_verified_input\": {malicious_verified},\n  \
                     \"per_kappa_equivalence\": [{equivalence_json}],\n  \
                     \"no_single_secret_signing_path\": false\n}}"
                );
                Err(format!(
                    "custody distributed sign did not accept: {error:?} \
                     (kappa_list={kappa_list:?}) — this is an honest negative result"
                ))
            }
        }
    }

    // ---- entry -------------------------------------------------------------

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let subcommand = args.first().cloned().unwrap_or_default();
        let flags = parse_flags(&args);
        let result = match subcommand.as_str() {
            "emit-inputs" => emit_inputs(&flags),
            "sign" => sign(&flags),
            other => Err(format!(
                "unknown subcommand '{other}'; expected 'emit-inputs' or 'sign'"
            )),
        };
        result.map_err(|error| -> Box<dyn std::error::Error> { error.into() })
    }
}
