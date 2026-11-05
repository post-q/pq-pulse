mod detect;
mod model;
mod normalize;
mod providers;
mod render;

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use clap::Parser;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use render::Format;

use detect::{ScanContext, check_domain};

const DEFAULT_JOBS: u16 = 4;

#[derive(Debug)]
enum Mode {
    Single(String),
    List(String, String),
}

#[derive(Debug, Parser)]
#[command(
    name = "pq-pulse",
    version,
    about = "Post-quantum TLS key-exchange probe with CDN/edge/vendor attribution",
    long_about = "Probes the public web endpoint (443) and every MX record (TCP/25, 587, 465) \
                  for post-quantum key exchange, and attributes the endpoint's infrastructure \
                  and CDN/edge termination.",
    after_help = "List files take one domain per line; '#' comments, blank lines and CRLF are tolerated."
)]
struct Cli {
    /// Domain to probe (single-domain mode)
    #[arg(required_unless_present = "list", conflicts_with = "list")]
    domain: Option<String>,

    /// Batch mode: probe every domain in <LIST_FILE>, write one record per line to <OUTPUT_FILE>
    #[arg(long, num_args = 2, value_names = ["LIST_FILE", "OUTPUT_FILE"])]
    list: Vec<String>,

    /// Worker count for --list
    #[arg(
        long,
        requires = "list",
        default_value_t = DEFAULT_JOBS,
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    jobs: u16,

    /// Output format [default: text, json for --list]
    #[arg(long, value_enum)]
    format: Option<FormatArg>,

    /// Shorthand for --format json
    #[arg(long)]
    json: bool,

    /// Hide the progress bar in --list mode
    #[arg(long)]
    no_progress: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum FormatArg {
    Text,
    Json,
}

fn clean_domain(line: &str) -> Option<String> {
    let without_comment = match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    };
    let domain = without_comment.replace('\r', "").trim().to_string();
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

fn run_single(host: &str, format: Format) -> Result<(), Box<dyn std::error::Error>> {
    let renderer = format.renderer();
    let context = ScanContext::unlimited();
    match check_domain(host, &context) {
        Ok(report) => {
            println!("{}", renderer.document(&report));
            Ok(())
        }
        Err(err) if format == Format::Json => {
            println!("{}", renderer.error_document(host, &err.to_string()));
            exit(1)
        }
        Err(err) => Err(err.into()),
    }
}

fn run_list(
    list_file: &str,
    output_file: &str,
    format: Format,
    progress: bool,
    jobs: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let renderer = format.renderer();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_file)?;

    let content = std::fs::read_to_string(list_file)
        .map_err(|err| format!("could not read list file {list_file}: {err}"))?;

    let domains: Vec<String> = content.lines().filter_map(clean_domain).collect();

    let context = Arc::new(ScanContext::polite());

    let pb = if progress {
        let pb =
            ProgressBar::with_draw_target(Some(domains.len() as u64), ProgressDrawTarget::stdout());
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {elapsed_precise} [{bar:30.cyan/blue}] {pos}/{len} {msg}",
            )
            .unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(250));
        Some(pb)
    } else {
        None
    };

    let pending: Mutex<VecDeque<(usize, String)>> =
        Mutex::new(domains.iter().cloned().enumerate().collect());
    let results: Mutex<Vec<Option<Result<crate::model::DomainReport, String>>>> =
        Mutex::new((0..domains.len()).map(|_| None).collect());

    let workers = jobs.min(domains.len().max(1));
    thread::scope(|scope| {
        for _ in 0..workers {
            let pending = &pending;
            let results = &results;
            let context = &context;
            let pb = pb.as_ref();
            scope.spawn(move || {
                loop {
                    let Some((index, domain)) = pending.lock().unwrap().pop_front() else {
                        break;
                    };
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        check_domain(&domain, context)
                    }))
                    .map_err(|_| "internal probe failure".to_string())
                    .and_then(|report| report.map_err(|err| err.to_string()));
                    if let (Some(pb), Err(err)) = (pb, &outcome) {
                        pb.println(format!("{domain} -> ERROR: {err}"));
                    }
                    results.lock().unwrap()[index] = Some(outcome);
                    if let Some(pb) = pb {
                        pb.inc(1);
                    }
                }
            });
        }
    });

    for (domain, result) in domains.iter().zip(results.into_inner().unwrap()) {
        match result {
            Some(Ok(report)) => writeln!(file, "{}", renderer.record(&report))?,
            Some(Err(err)) => writeln!(file, "{}", renderer.error_record(domain, &err))?,
            None => writeln!(
                file,
                "{}",
                renderer.error_record(domain, "internal probe failure")
            )?,
        }
    }

    if let Some(pb) = pb {
        pb.finish();
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if let Err(_existing) = rustls::crypto::aws_lc_rs::default_provider().install_default() {}

    let mode = if let [list_file, output_file] = cli.list.as_slice() {
        Mode::List(list_file.clone(), output_file.clone())
    } else {
        Mode::Single(cli.domain.expect("clap requires <domain> unless --list"))
    };

    let format = cli
        .format
        .map(|arg| match arg {
            FormatArg::Text => Format::Text,
            FormatArg::Json => Format::Json,
        })
        .unwrap_or(match mode {
            Mode::List(..) => Format::Json,
            Mode::Single(_) => Format::Text,
        });

    match mode {
        Mode::Single(host) => run_single(&host, format),
        Mode::List(list_file, output_file) => run_list(
            &list_file,
            &output_file,
            format,
            !cli.no_progress,
            usize::from(cli.jobs),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_domain_matches_run_kx_list_rules() {
        assert_eq!(clean_domain("example.com"), Some("example.com".to_string()));
        assert_eq!(
            clean_domain("  example.com  "),
            Some("example.com".to_string())
        );
        assert_eq!(
            clean_domain("example.com\r"),
            Some("example.com".to_string())
        );
        assert_eq!(
            clean_domain("\rexample.com\r\n"),
            Some("example.com".to_string())
        );
        assert_eq!(
            clean_domain("example.com # comment"),
            Some("example.com".to_string())
        );
        assert_eq!(clean_domain("# comment only"), None);
        assert_eq!(clean_domain("   # x"), None);
        assert_eq!(clean_domain(""), None);
        assert_eq!(clean_domain("   "), None);
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
