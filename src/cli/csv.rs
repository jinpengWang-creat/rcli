use std::str::FromStr;

use clap::Parser;

use crate::{process_csv, CmdExecutor};

use super::verify_file;

#[derive(Debug, Parser)]
pub struct CsvOpts {
    #[arg(short, long, value_parser = verify_file)]
    pub input: String,

    #[arg(short, long)]
    pub output: Option<String>,

    #[arg(short, long, default_value = "json", value_parser = parse_format)]
    pub format: OutputFormat,

    #[arg(short, long, default_value_t = ',')]
    pub delimiter: char,

    #[arg(long)]
    pub no_header: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    Yaml,
}

impl FromStr for OutputFormat {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_ref() {
            "json" => Ok(OutputFormat::Json),
            "yaml" => Ok(OutputFormat::Yaml),
            v => anyhow::bail!("Unsupported format: {}", v),
        }
    }
}

impl From<OutputFormat> for &str {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Json => "json",
            OutputFormat::Yaml => "yaml",
        }
    }
}

fn parse_format(format: &str) -> anyhow::Result<OutputFormat, anyhow::Error> {
    format.parse()
}

impl CmdExecutor for CsvOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let output = self.output.unwrap_or_else(|| match self.format {
            OutputFormat::Json => "output.json".to_string(),
            OutputFormat::Yaml => "output.yaml".to_string(),
        });
        process_csv(
            &self.input,
            &output,
            self.format,
            self.delimiter,
            self.no_header,
        )
    }
}
