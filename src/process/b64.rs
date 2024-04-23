use std::io::Read;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};

use crate::{cli::Base64Format, utils::get_reader};

pub fn process_encode(input: &str, format: Base64Format) -> anyhow::Result<String> {
    let mut reader = get_reader(input)?;
    let mut buff = Vec::new();
    reader.read_to_end(&mut buff)?;

    let encoded = match format {
        Base64Format::Standard => STANDARD.encode(buff),
        Base64Format::UrlSafe => URL_SAFE_NO_PAD.encode(buff),
    };
    Ok(encoded)
}

pub fn process_decode(input: &str, format: Base64Format) -> anyhow::Result<Vec<u8>> {
    let mut reader = get_reader(input)?;
    let mut buff = String::new();
    reader.read_to_string(&mut buff)?;
    // avoid accidental newlines
    let buff = buff.trim();
    let decoded = match format {
        Base64Format::Standard => STANDARD.decode(buff)?,
        Base64Format::UrlSafe => URL_SAFE_NO_PAD.decode(buff)?,
    };

    Ok(decoded)
}
