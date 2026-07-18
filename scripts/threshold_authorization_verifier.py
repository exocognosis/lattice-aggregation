#!/usr/bin/env python3
"""Reviewed threshold-authorization verifier adapter for campaign promotion.

This verifier checks Ed25519 signatures over a canonical per-authorizer message.
It is intentionally narrow: the structural 10,000-validator and 24-case campaign
checks stay in ``validate_internal_aggregation_campaign_capture.py``; this module
only supplies the missing cryptographic signature-verification callback.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError as error:  # pragma: no cover - exercised only on bad hosts
    InvalidSignature = None
    Ed25519PublicKey = None
    CRYPTOGRAPHY_IMPORT_ERROR = error
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


VERIFIER_ID = "reviewed-ed25519-threshold-authorization-v1"
SIGNED_MESSAGE_SCHEMA = "lattice-aggregation:threshold-authorization-signed-message:v1"


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def implementation_sha256():
    return sha256_bytes(Path(__file__).read_bytes())


def verifier_profile():
    return {
        "verifier_id": VERIFIER_ID,
        "verifier_implementation_sha256": implementation_sha256(),
    }


def load_json(path):
    with Path(path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def decode_hex(value, field, expected_len=None):
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a hex string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{field} must be valid hex") from error
    if expected_len is not None and len(decoded) != expected_len:
        raise ValueError(f"{field} must be {expected_len} bytes")
    return decoded


def signed_authorization_message(certificate, request, committee, authorizer):
    return {
        "schema": SIGNED_MESSAGE_SCHEMA,
        "campaign_id": certificate.get("campaign_id"),
        "request_sha256": certificate.get("request_sha256"),
        "request_campaign_id": request.get("campaign_id"),
        "validator_count": certificate.get("validator_count"),
        "threshold": certificate.get("threshold"),
        "validator_set_digest_hex": certificate.get("validator_set_digest_hex"),
        "committee_size": committee.get("committee_size"),
        "committee_digest_hex": committee.get("committee_digest_hex"),
        "session_binding_digest_hex": committee.get("session_binding_digest_hex"),
        "validator_id": authorizer.get("validator_id"),
        "public_key_digest_hex": authorizer.get("public_key_digest_hex"),
        "signature_scheme": "ed25519",
    }


class Ed25519ThresholdAuthorizationVerifier:
    verifier_id = VERIFIER_ID

    def __init__(self):
        if CRYPTOGRAPHY_IMPORT_ERROR is not None:
            raise RuntimeError(
                "cryptography package is required for Ed25519 authorization verification"
            ) from CRYPTOGRAPHY_IMPORT_ERROR
        self.implementation_sha256 = implementation_sha256()
        self.last_errors = []

    def __call__(self, certificate, request):
        self.last_errors = self.verify(certificate, request)
        return not self.last_errors

    def verify(self, certificate, request):
        errors = []
        if not isinstance(certificate, dict):
            return ["certificate must be an object"]
        if not isinstance(request, dict):
            return ["request must be an object"]
        expected_request_digest = sha256_bytes(canonical_json(request).encode("utf-8"))
        if certificate.get("request_sha256") != expected_request_digest:
            errors.append("certificate request digest does not match request bytes")
        committees = certificate.get("committee_authorizations")
        if not isinstance(committees, list):
            return errors + ["committee_authorizations must be a list"]
        threshold = certificate.get("threshold")
        for committee in committees:
            if not isinstance(committee, dict):
                errors.append("committee record must be an object")
                continue
            authorizers = committee.get("authorizer_records")
            if not isinstance(authorizers, list):
                errors.append(
                    f"authorizer_records missing for committee {committee.get('committee_size')}"
                )
                continue
            if isinstance(threshold, int) and len(authorizers) < threshold:
                errors.append(
                    f"committee {committee.get('committee_size')} has fewer than threshold authorizers"
                )
            seen = set()
            public_key_digests = set()
            for authorizer in authorizers:
                errors.extend(self.verify_authorizer(certificate, request, committee, authorizer))
                validator_id = authorizer.get("validator_id") if isinstance(authorizer, dict) else None
                if validator_id in seen:
                    errors.append(
                        f"duplicate authorizer validator_id in committee {committee.get('committee_size')}: {validator_id}"
                    )
                seen.add(validator_id)
                digest = (
                    authorizer.get("public_key_digest_hex")
                    if isinstance(authorizer, dict)
                    else None
                )
                if digest in public_key_digests:
                    errors.append(
                        f"duplicate authorizer public key digest in committee {committee.get('committee_size')}: {digest}"
                    )
                public_key_digests.add(digest)
        return errors

    def verify_authorizer(self, certificate, request, committee, authorizer):
        if not isinstance(authorizer, dict):
            return ["authorizer record must be an object"]
        errors = []
        if authorizer.get("signature_scheme") != "ed25519":
            errors.append("authorizer signature_scheme must be ed25519")
        try:
            public_key = decode_hex(authorizer.get("public_key_hex"), "public_key_hex", 32)
            signature = decode_hex(authorizer.get("signature_hex"), "signature_hex", 64)
        except ValueError as error:
            return errors + [str(error)]
        public_key_digest = sha256_bytes(public_key)
        if authorizer.get("public_key_digest_hex") != public_key_digest:
            errors.append("authorizer public key digest mismatch")
        if authorizer.get("signature_digest_hex") != sha256_bytes(signature):
            errors.append("authorizer signature digest mismatch")
        message = canonical_json(
            signed_authorization_message(certificate, request, committee, authorizer)
        ).encode("utf-8")
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        except InvalidSignature:
            errors.append("authorizer signature verification failed")
        except ValueError as error:
            errors.append(f"authorizer public key invalid: {error}")
        return errors


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Verify threshold authorization certificates with Ed25519 authorizer signatures"
    )
    parser.add_argument("--profile", action="store_true", help="print verifier profile JSON")
    parser.add_argument(
        "--implementation-sha256",
        action="store_true",
        help="print only the verifier implementation SHA-256",
    )
    parser.add_argument("--request", help="campaign request JSON for --certificate")
    parser.add_argument("--certificate", help="authorization certificate JSON to verify")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    if args.implementation_sha256:
        print(implementation_sha256())
        return 0
    if args.profile:
        print(canonical_json(verifier_profile()), end="")
        return 0
    if not args.request or not args.certificate:
        raise SystemExit("--request and --certificate are required unless printing profile data")
    verifier = Ed25519ThresholdAuthorizationVerifier()
    request = load_json(args.request)
    certificate = load_json(args.certificate)
    errors = verifier.verify(certificate, request)
    result = {
        "verified": not errors,
        "verifier_id": verifier.verifier_id,
        "verifier_implementation_sha256": verifier.implementation_sha256,
        "errors": errors,
    }
    print(canonical_json(result), end="")
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
