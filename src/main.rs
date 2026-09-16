mod detect;
mod model;
mod render;

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::exit;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use render::Format;

use detect::check_domain;

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
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut format: Option<Format> = None;
    let mut list = false;
    let mut progress = true;
    let mut positional: Vec<String> = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--list" => list = true,
            "--json" => format = Some(Format::Json),
            "--no-progress" => progress = false,
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
    match check_domain(host) {
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

    for domain in domains {
        if let Some(pb) = &pb {
            pb.set_message(domain.clone());
        }
        match check_domain(&domain) {
            Ok(report) => {
                writeln!(file, "{}", renderer.record(&report))?;
            }
            Err(err) => {
                if let Some(pb) = &pb {
                    pb.println(format!("{domain} -> ERROR: {err}"));
                }
                writeln!(file, "{}", renderer.error_record(&domain, &err.to_string()))?;
            }
        }
        if let Some(pb) = &pb {
            pb.inc(1);
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
        "       pq-pulse --list <list-file> <output-file> [--format text|json] [--no-progress]"
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
            run_list(&list_file, &output_file, cli.format, cli.progress)
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

        let cli = single(&["--list", "in.txt", "out.jsonl", "--no-progress"]).unwrap();
        assert!(!cli.progress);

        let cli = single(&["--list", "in.txt", "out.txt", "--format", "text"]).unwrap();
        assert_eq!(cli.format, Format::Text);

        assert!(single(&["--format", "csv", "example.com"]).is_err());
        assert!(single(&["--format", "yaml", "example.com"]).is_err());
        assert!(single(&[]).is_err());
        assert!(single(&["--list", "only-one-arg"]).is_err());
    }
}
