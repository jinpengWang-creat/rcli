use std::fs;

use serde_json::Value;

use crate::opts::{CsvOpts, OutputFormat};

pub fn process_csv(opt: CsvOpts) -> anyhow::Result<()> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(opt.delimiter as u8)
        .has_headers(opt.header)
        .from_path(opt.input)?;
    let mut result = Vec::with_capacity(128);
    let headers = reader.headers()?.clone();
    for record in reader.records() {
        let record = record?;
        let json_value = headers.iter().zip(record.iter()).collect::<Value>();
        result.push(json_value);
    }
    let json = match opt.format {
        OutputFormat::Json => serde_json::to_string_pretty(&result)?,
        OutputFormat::Yaml => serde_yaml::to_string(&result)?,
    };

    let output = opt.output.unwrap_or_else(|| match opt.format {
        OutputFormat::Json => "output.json".to_string(),
        OutputFormat::Yaml => "output.yaml".to_string(),
    });
    fs::write(output, json)?;
    Ok(())
}
