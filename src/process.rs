use std::fs;

use serde::{Deserialize, Serialize};

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

pub fn process_csv(input: &str, output: &str) -> anyhow::Result<()> {
    let mut reader = csv::Reader::from_path(input)?;
    let mut result = Vec::with_capacity(128);
    for record in reader.deserialize() {
        let player: Player = record?;
        result.push(player);
    }
    let json = serde_json::to_string_pretty(&result)?;
    fs::write(output, json)?;
    Ok(())
}
