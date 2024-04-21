use std::{fmt, str::FromStr};

use anyhow::Ok;
use clap::{Parser, Subcommand};

use super::verify_input_file;

#[derive(Debug, Subcommand)]
pub enum Base64SubCommand {
    #[command(name = "encode", about = "Encode a string to base64")]
    Encode(Base64EncodeOpts),
    #[command(name = "decode", about = "Decode a base64 string")]
    Decode(Base64DecodeOpts),
}

#[derive(Debug, Parser)]
pub struct Base64EncodeOpts {
    #[arg(short, long, default_value = "-", value_parser = verify_input_file)]
    pub input: String,
    #[arg(long, default_value = "standard", value_parser = parse_base64_format)]
    pub format: Base64Format,
    #[arg(long, default_value = "encoded.txt")]
    pub output: String,
}

#[derive(Debug, Parser)]
pub struct Base64DecodeOpts {
    #[arg(short, long, default_value = "-", value_parser = verify_input_file)]
    pub input: String,
    #[arg(long, default_value = "standard", value_parser = parse_base64_format)]
    pub format: Base64Format,
}

#[derive(Debug, Parser, Clone, Copy)]
pub enum Base64Format {
    Standard,
    UrlSafe,
}

impl From<Base64Format> for &str {
    fn from(value: Base64Format) -> Self {
        match value {
            Base64Format::Standard => "standard",
            Base64Format::UrlSafe => "urlsafe",
        }
    }
}

impl FromStr for Base64Format {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "standard" => Ok(Base64Format::Standard),
            "urlsafe" => Ok(Base64Format::UrlSafe),
            v => anyhow::bail!("Unsupported type: {:?}", v),
        }
    }
}

fn parse_base64_format(input: &str) -> Result<Base64Format, anyhow::Error> {
    input.parse()
}

impl fmt::Display for Base64Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&str>::into(*self))
    }
}
