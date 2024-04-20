use std::fs;

use serde::{Deserialize, Serialize};

use crate::opts::CsvOpt;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Player {
    name: String,
    position: String,
    #[serde(rename = "DOB")]
    dob: String,
    nationality: String,
    #[serde(rename = "Kit Number")]
    kit: u8,
}

pub fn process_csv(opt: CsvOpt) -> anyhow::Result<()> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(opt.delimiter as u8)
        .has_headers(opt.header)
        .from_path(opt.input)?;
    let mut result = Vec::with_capacity(128);
    for record in reader.deserialize() {
        let player: Player = record?;
        result.push(player);
    }
    let json = serde_json::to_string_pretty(&result)?;
    fs::write(&opt.output, json)?;
    Ok(())
}
