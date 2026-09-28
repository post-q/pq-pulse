mod detect;
mod model;
mod normalize;
mod providers;
mod render;

use std::collections::VecDeque;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use render::Format;

use detect::{ScanContext, check_domain};

const DEFAULT_JOBS: usize = 4;

#[derive(Debug)]
enum Mode {
    Single(String),
    List(String, String),
}

#[derive(Debug)]
struct Cli {
    mode: Mode,
    format: Format,
    progress: bool,
    jobs: usize,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut format: Option<Format> = None;
    let mut list = false;
    let mut progress = true;
    let mut jobs: Option<usize> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--list" => list = true,
            "--json" => format = Some(Format::Json),
            "--no-progress" => progress = false,
            "--jobs" => {
                let Some(value) = iter.next() else {
                    return Err("--jobs requires a positive number".to_string());
                };
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| format!("--jobs expects a positive number, got {value:?}"))?;
                if parsed == 0 {
                    return Err("--jobs expects a positive number".to_string());
                }
                jobs = Some(parsed);
            }
            "--format" => {
                let Some(value) = iter.next() else {
                    return Err("--format requires a value (text, json)".to_string());
                };
                format = Some(value.parse::<Format>()?);
            }
            other => positional.push(other.to_string()),
        }
    }

    let mode = if list {
        match positional.as_slice() {
            [list_file, output_file] => Mode::List(list_file.clone(), output_file.clone()),
            _ => return Err("--list requires exactly <list-file> <output-file>".to_string()),
        }
    } else {
        if jobs.is_some() {
            return Err("--jobs is only valid together with --list".to_string());
        }
        match positional.as_slice() {
            [host] => Mode::Single(host.clone()),
            _ => return Err("expected exactly one <domain>".to_string()),
        }
    };

    let default_format = if list { Format::Json } else { Format::Text };
    Ok(Cli {
        mode,
        format: format.unwrap_or(default_format),
        progress,
        jobs: jobs.unwrap_or(DEFAULT_JOBS),
    })
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

fn usage() -> ! {
    eprintln!("usage: pq-pulse [--format text|json] <domain>");
    eprintln!(
        "       pq-pulse --list <list-file> <output-file> [--jobs N] [--format text|json] [--no-progress]"
    );
    eprintln!("       (--json is shorthand for --format json)");
    exit(2)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();

    if let Err(_existing) = rustls::crypto::aws_lc_rs::default_provider().install_default() {}

    let cli = match parse_args(&args) {
        Ok(cli) => cli,
        Err(reason) => {
            eprintln!("{reason}");
            usage()
        }
    };

    match cli.mode {
        Mode::Single(host) => run_single(&host, cli.format),
        Mode::List(list_file, output_file) => {
            run_list(&list_file, &output_file, cli.format, cli.progress, cli.jobs)
        }
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
    fn parse_args_defaults_and_formats() {
        let single = |args: &[&str]| {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            parse_args(&owned)
        };

        let cli = single(&["example.com"]).unwrap();
        assert_eq!(cli.format, Format::Text);
        assert!(cli.progress);

        let cli = single(&["--json", "example.com"]).unwrap();
        assert_eq!(cli.format, Format::Json);

        let cli = single(&["--list", "in.txt", "out.jsonl"]).unwrap();
        assert_eq!(cli.format, Format::Json);
        assert!(cli.progress);
        assert_eq!(cli.jobs, DEFAULT_JOBS);

        let cli = single(&["--list", "in.txt", "out.jsonl", "--jobs", "8"]).unwrap();
        assert_eq!(cli.jobs, 8);

        let cli = single(&["--list", "in.txt", "out.jsonl", "--no-progress"]).unwrap();
        assert!(!cli.progress);

        let cli = single(&["--list", "in.txt", "out.txt", "--format", "text"]).unwrap();
        assert_eq!(cli.format, Format::Text);

        assert!(single(&["--format", "csv", "example.com"]).is_err());
        assert!(single(&["--format", "yaml", "example.com"]).is_err());
        assert!(single(&[]).is_err());
        assert!(single(&["--list", "only-one-arg"]).is_err());
        assert!(single(&["--jobs", "8", "example.com"]).is_err());
        assert!(single(&["--list", "in.txt", "out.jsonl", "--jobs", "0"]).is_err());
        assert!(single(&["--list", "in.txt", "out.jsonl", "--jobs", "many"]).is_err());
        assert!(single(&["--list", "in.txt", "out.jsonl", "--jobs"]).is_err());
    }
}
