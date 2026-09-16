mod json;
mod text;

pub use json::JsonRenderer;
pub use text::TextRenderer;

use crate::model::DomainReport;

/// A presentation of a `DomainReport`. Implementations are pure:
/// they format state and never perform I/O.
pub trait Renderer {
    /// One domain's report as a single record (NDJSON line, text block).
    fn record(&self, report: &DomainReport) -> String;

    /// A standalone document for one domain's report.
    fn document(&self, report: &DomainReport) -> String {
        self.record(report)
    }

    /// A record for a domain that failed to check.
    fn error_record(&self, domain: &str, error: &str) -> String;

    /// A standalone document for a domain that failed to check.
    fn error_document(&self, domain: &str, error: &str) -> String {
        self.error_record(domain, error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

impl std::str::FromStr for Format {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            other => Err(format!("unknown format {other:?} (expected text or json)")),
        }
    }
}

impl Format {
    pub fn renderer(self) -> Box<dyn Renderer> {
        match self {
            Format::Text => Box::new(TextRenderer),
            Format::Json => Box::new(JsonRenderer),
        }
    }
}
