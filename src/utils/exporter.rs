//! Academic export helpers for simulation telemetry.

use std::fmt::Write;

use crate::adapter::actor::SessionMetrics;

/// Compile empirical session measurements into a LaTeX table.
pub fn generate_latex_table(
    experiment_label: &str,
    validator_count: u16,
    datasets: &[SessionMetrics],
) -> String {
    if datasets.is_empty() {
        return "% No telemetry data provided for LaTeX export.\n".to_string();
    }

    let count = datasets.len() as f64;
    let total_bytes: usize = datasets
        .iter()
        .map(|metric| metric.network_bytes_transmitted)
        .sum();
    let mean_bytes = total_bytes as f64 / count;

    let total_duration_ns: u64 = datasets.iter().map(|metric| metric.total_duration_ns).sum();
    let mean_duration_ms = (total_duration_ns as f64 / count) / 1_000_000.0;

    let total_aborts: u32 = datasets
        .iter()
        .map(|metric| metric.abort_and_retry_count)
        .sum();
    let mean_aborts = total_aborts as f64 / count;

    let variance: f64 = datasets
        .iter()
        .map(|metric| {
            let duration_ms = metric.total_duration_ns as f64 / 1_000_000.0;
            let diff = duration_ms - mean_duration_ms;
            diff * diff
        })
        .sum();
    let std_dev_ms = if count > 1.0 {
        (variance / (count - 1.0)).sqrt()
    } else {
        0.0
    };

    let mut output = String::new();
    writeln!(
        &mut output,
        "% Auto-generated academic telemetry table for Section V"
    )
    .expect("writing to string cannot fail");
    writeln!(&mut output, "\\begin{{table}}[h]").expect("writing to string cannot fail");
    writeln!(&mut output, "\\centering").expect("writing to string cannot fail");
    writeln!(&mut output, "\\begin{{tabular}}{{l r r r r}}")
        .expect("writing to string cannot fail");
    writeln!(&mut output, "\\hline").expect("writing to string cannot fail");
    writeln!(
        &mut output,
        "Experiment & Validators ($N$) & Latency (ms $\\pm \\sigma$) & Aborts (Avg) & Bandwidth (Bytes) \\\\"
    )
    .expect("writing to string cannot fail");
    writeln!(&mut output, "\\hline").expect("writing to string cannot fail");
    writeln!(
        &mut output,
        "{experiment_label} & {validator_count} & {mean_duration_ms:.3} $\\pm$ {std_dev_ms:.2} & {mean_aborts:.1} & {mean_bytes:.0} \\\\"
    )
    .expect("writing to string cannot fail");
    writeln!(&mut output, "\\hline").expect("writing to string cannot fail");
    writeln!(&mut output, "\\end{{tabular}}").expect("writing to string cannot fail");
    writeln!(
        &mut output,
        "\\caption{{Empirical evaluation profile for post-quantum threshold signatures.}}"
    )
    .expect("writing to string cannot fail");
    writeln!(
        &mut output,
        "\\label{{tab:pqc_threshold_metrics_{}}}",
        latex_label_slug(experiment_label)
    )
    .expect("writing to string cannot fail");
    writeln!(&mut output, "\\end{{table}}").expect("writing to string cannot fail");

    output
}

/// Format session measurements as PGFPlots-compatible CSV.
pub fn generate_pgfplots_csv(datasets: &[SessionMetrics]) -> String {
    let mut csv = String::from("session_id,duration_ms,aborts,bandwidth_bytes\n");
    for (index, metric) in datasets.iter().enumerate() {
        writeln!(
            &mut csv,
            "{},{:.4},{},{}",
            index,
            metric.total_duration_ns as f64 / 1_000_000.0,
            metric.abort_and_retry_count,
            metric.network_bytes_transmitted
        )
        .expect("writing to string cannot fail");
    }
    csv
}

fn latex_label_slug(label: &str) -> String {
    let mut slug = String::new();
    for character in label.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            slug.push(character);
        } else if (character.is_ascii_whitespace() || character == '-' || character == '_')
            && !slug.ends_with('_')
        {
            slug.push('_');
        }
    }

    let slug = slug.trim_matches('_').to_string();
    if slug.is_empty() {
        "experiment".to_string()
    } else {
        slug
    }
}

#[cfg(test)]
mod exporter_tests {
    use super::*;

    #[test]
    fn test_academic_latex_table_generation_properties() {
        let trial_1 = SessionMetrics {
            total_duration_ns: 25_000_000,
            abort_and_retry_count: 0,
            network_bytes_transmitted: 3309,
        };
        let trial_2 = SessionMetrics {
            total_duration_ns: 35_000_000,
            abort_and_retry_count: 1,
            network_bytes_transmitted: 6618,
        };

        let metrics_dataset = vec![trial_1, trial_2];

        let latex_output = generate_latex_table("Ideal LAN Mesh", 4, &metrics_dataset);
        let csv_output = generate_pgfplots_csv(&metrics_dataset);

        assert!(latex_output.contains("\\begin{table}"));
        assert!(latex_output.contains("\\centering"));
        assert!(latex_output.contains("Ideal LAN Mesh"));
        assert!(latex_output.contains("30.000"));
        assert!(latex_output.contains("\\label{tab:pqc_threshold_metrics_ideal_lan_mesh}"));
        assert!(csv_output.starts_with("session_id,duration_ms,aborts,bandwidth_bytes"));
    }

    #[test]
    fn empty_latex_export_returns_comment() {
        assert_eq!(
            generate_latex_table("Empty", 0, &[]),
            "% No telemetry data provided for LaTeX export.\n"
        );
    }

    #[test]
    fn pgfplots_csv_formats_rows() {
        let metrics = [SessionMetrics {
            total_duration_ns: 1_500_000,
            abort_and_retry_count: 2,
            network_bytes_transmitted: 12,
        }];

        assert_eq!(
            generate_pgfplots_csv(&metrics),
            "session_id,duration_ms,aborts,bandwidth_bytes\n0,1.5000,2,12\n"
        );
    }
}
