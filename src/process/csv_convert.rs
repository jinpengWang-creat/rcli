use std::fs;

use serde_json::Value;

use crate::opts::OutputFormat;

pub fn process_csv(
    input: &str,
    output: &str,
    format: OutputFormat,
    delimiter: char,
    no_header: bool,
) -> anyhow::Result<()> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter as u8)
        .has_headers(!no_header)
        .from_path(input)?;
    let mut result = Vec::with_capacity(128);
    let headers = reader.headers()?.clone();
    for record in reader.records() {
        let record = record?;
        let json_value = headers.iter().zip(record.iter()).collect::<Value>();
        result.push(json_value);
    }
    let json = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&result)?,
        OutputFormat::Yaml => serde_yaml::to_string(&result)?,
    };

    fs::write(output, json)?;
    Ok(())
}
