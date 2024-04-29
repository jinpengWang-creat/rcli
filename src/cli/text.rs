use std::{path::PathBuf, str::FromStr};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use enum_dispatch::enum_dispatch;
use tokio::fs;

use crate::{
    process_text_decrypt, process_text_encrypt, process_text_generate, process_text_sign,
    process_text_verify, CmdExecutor,
};

use super::{verify_file, verify_path};

#[derive(Debug, Subcommand)]
#[enum_dispatch(CmdExecutor)]
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

impl CmdExecutor for TextSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let signature = process_text_sign(&self.input, &self.key, self.format)?;
        let signed = URL_SAFE_NO_PAD.encode(signature);
        fs::write(&self.output, signed).await?;
        Ok(())
    }
}

impl CmdExecutor for TextVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let sign = URL_SAFE_NO_PAD.decode(&self.sign)?;
        let is_match = process_text_verify(&self.input, &self.key, self.format, &sign)?;
        println!("is_match: {is_match}");
        Ok(())
    }
}

impl CmdExecutor for TextKeyGenerateOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let key = process_text_generate(self.format)?;
        match self.format {
            TextKeyGenerateFormat::Blake3 => {
                let key = &key[0];
                let filename = self.output.join("blakes.txt");
                fs::write(filename, key).await?;
            }
            TextKeyGenerateFormat::Ed25519 => {
                let sk = &key[0];
                let filename = self.output.join("ed25519.sk");
                fs::write(filename, sk).await?;
                let pk = &key[1];
                let filename = self.output.join("ed25519.pk");
                fs::write(filename, pk).await?;
            }
            TextKeyGenerateFormat::Chacha20poly1305 => {
                let sk = &key[0];
                let filename = self.output.join("chacha20poly1305.key");
                fs::write(filename, sk).await?;
                let pk = &key[1];
                let filename = self.output.join("chacha20poly1305.nonce");
                fs::write(filename, pk).await?;
            }
        }
        Ok(())
    }
}

impl CmdExecutor for TextEncryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let ciphertext = process_text_encrypt(&self.input, &self.key, &self.nonce, self.format)?;
        let ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
        fs::write(self.output, ciphertext).await?;
        Ok(())
    }
}

impl CmdExecutor for TextDecryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let plaintext = process_text_decrypt(&self.input, &self.key, &self.nonce, self.format)?;
        println!("plaintext: {}", String::from_utf8(plaintext)?);
        Ok(())
    }
}
