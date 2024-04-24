use std::{path::PathBuf, str::FromStr};

use clap::{Parser, Subcommand};

use super::{verify_file, verify_path};

#[derive(Debug, Subcommand)]
pub enum TextSubCommand {
    #[command(about = "Sign a message with a private/shared key")]
    Sign(TextSignOpts),
    #[command(about = "Verify a signed message")]
    Verify(TextVerifyOpts),
    #[command(about = "Generate a new key")]
    Generate(TextKeyGenerateOpts),
    #[command(about = "Encrypt a message")]
    Encrypt(TextEncryptOpts),
    #[command(about = "Decrypt a ciphertext")]
    Decrypt(TextDecryptOpts),
}

#[derive(Debug, Parser)]
pub struct TextSignOpts {
    #[arg(short, long, default_value = "-", value_parser = verify_file)]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(long, default_value = "blake3", value_parser = parse_text_sign_verify_format)]
    pub format: TextSignVerifyFormat,
    #[arg(long, default_value = "fixtures/sign.txt")]
    pub output: String,
}

#[derive(Debug, Parser)]
pub struct TextVerifyOpts {
    #[arg(short, long, default_value = "-", value_parser = verify_file)]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(long, default_value = "blake3", value_parser = parse_text_sign_verify_format)]
    pub format: TextSignVerifyFormat,
    #[arg(short, long)]
    pub sign: String,
}

#[derive(Debug, Parser)]
pub struct TextKeyGenerateOpts {
    #[arg(long, default_value = "blake3", value_parser = parse_text_key_generate_format)]
    pub format: TextKeyGenerateFormat,

    #[arg(short, long, value_parser = verify_path)]
    pub output: PathBuf,
}

#[derive(Debug, Parser)]
pub struct TextEncryptOpts {
    #[arg(short, long, default_value = "-", value_parser = verify_file)]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(short, long, value_parser = verify_file)]
    pub nonce: String,
    #[arg(long, default_value = "chacha20poly1305", value_parser = parse_text_encrypt_decrypt_format)]
    pub format: TextEncryptDecryptFormat,
    #[arg(long, default_value = "fixtures/encrypt.txt")]
    pub output: String,
}

#[derive(Debug, Parser)]
pub struct TextDecryptOpts {
    #[arg(short, long, default_value = "-", value_parser = verify_file)]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(short, long, value_parser = verify_file)]
    pub nonce: String,
    #[arg(long, default_value = "chacha20poly1305", value_parser = parse_text_encrypt_decrypt_format)]
    pub format: TextEncryptDecryptFormat,
}

#[derive(Debug, Parser, Clone, Copy)]
pub enum TextSignVerifyFormat {
    Blake3,
    Ed25519,
}

#[derive(Debug, Parser, Clone, Copy)]
pub enum TextKeyGenerateFormat {
    Blake3,
    Ed25519,
    Chacha20poly1305,
}

#[derive(Debug, Parser, Clone, Copy)]
pub enum TextEncryptDecryptFormat {
    Chacha20poly1305,
}

impl From<TextSignVerifyFormat> for &str {
    fn from(value: TextSignVerifyFormat) -> Self {
        match value {
            TextSignVerifyFormat::Blake3 => "blake3",
            TextSignVerifyFormat::Ed25519 => "ed25519",
        }
    }
}

impl FromStr for TextSignVerifyFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(TextSignVerifyFormat::Blake3),
            "ed25519" => Ok(TextSignVerifyFormat::Ed25519),
            v => anyhow::bail!("Unsupported type: {:?}", v),
        }
    }
}

impl From<TextKeyGenerateFormat> for &str {
    fn from(value: TextKeyGenerateFormat) -> Self {
        match value {
            TextKeyGenerateFormat::Blake3 => "blake3",
            TextKeyGenerateFormat::Ed25519 => "ed25519",
            TextKeyGenerateFormat::Chacha20poly1305 => "chacha20poly1305",
        }
    }
}

impl FromStr for TextKeyGenerateFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(TextKeyGenerateFormat::Blake3),
            "ed25519" => Ok(TextKeyGenerateFormat::Ed25519),
            "chacha20poly1305" => Ok(TextKeyGenerateFormat::Chacha20poly1305),
            v => anyhow::bail!("Unsupported type: {:?}", v),
        }
    }
}

impl From<TextEncryptDecryptFormat> for &str {
    fn from(value: TextEncryptDecryptFormat) -> Self {
        match value {
            TextEncryptDecryptFormat::Chacha20poly1305 => "chacha20poly1305",
        }
    }
}

impl FromStr for TextEncryptDecryptFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chacha20poly1305" => Ok(TextEncryptDecryptFormat::Chacha20poly1305),
            v => anyhow::bail!("Unsupported type: {:?}", v),
        }
    }
}

fn parse_text_sign_verify_format(format: &str) -> Result<TextSignVerifyFormat, anyhow::Error> {
    format.parse()
}

fn parse_text_key_generate_format(format: &str) -> Result<TextKeyGenerateFormat, anyhow::Error> {
    format.parse()
}

fn parse_text_encrypt_decrypt_format(
    format: &str,
) -> Result<TextEncryptDecryptFormat, anyhow::Error> {
    format.parse()
}
