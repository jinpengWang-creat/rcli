use std::{
    fs::{self, File},
    io::Read,
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};

use crate::cli::Base64Format;

pub fn process_encode(input: &str, format: Base64Format, output: &str) -> anyhow::Result<()> {
    let mut reader = get_reader(input)?;
    let mut buff = Vec::new();
    reader.read_to_end(&mut buff)?;

    let encoded = match format {
        Base64Format::Standard => STANDARD.encode(buff),
        Base64Format::UrlSafe => URL_SAFE_NO_PAD.encode(buff),
    };
    fs::write(output, encoded)?;
    Ok(())
}

pub fn process_decode(input: &str, format: Base64Format) -> anyhow::Result<()> {
    let mut reader = get_reader(input)?;
    let mut buff = String::new();
    reader.read_to_string(&mut buff)?;
    // avoid accidental newlines
    let buff = buff.trim();
    let decoded = match format {
        Base64Format::Standard => STANDARD.decode(buff)?,
        Base64Format::UrlSafe => URL_SAFE_NO_PAD.decode(buff)?,
    };

    println!("{}", String::from_utf8(decoded)?);
    Ok(())
}

fn get_reader(input: &str) -> anyhow::Result<Box<dyn Read>> {
    let reader: Box<dyn Read> = if input == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(input)?)
    };
    Ok(reader)
}
