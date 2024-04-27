use std::fs;

use clap::Parser;
use rcli::{
    process_csv, process_decode, process_encode, process_genpass, process_http_serve,
    process_jwt_sign, process_text_decrypt, process_text_encrypt, process_text_generate,
    process_text_sign, process_text_verify, Base64SubCommand, HttpSubCommand, JwtSubCommand, Opts,
    OutputFormat, SubCommand, TextKeyGenerateFormat, TextSubCommand,
};
use zxcvbn::zxcvbn;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::CSV(opt) => {
            let output = opt.output.unwrap_or_else(|| match opt.format {
                OutputFormat::Json => "output.json".to_string(),
                OutputFormat::Yaml => "output.yaml".to_string(),
            });
            process_csv(
                &opt.input,
                &output,
                opt.format,
                opt.delimiter,
                opt.no_header,
            )?
        }
        SubCommand::GenPass(opt) => {
            let password = process_genpass(
                opt.length,
                opt.no_uppercase,
                opt.no_lowercase,
                opt.no_number,
                opt.no_symbol,
            )?;
            println!("{}", password);
            let estimate = zxcvbn(&password, &[])?;
            eprintln!("Password strength: {:?}", estimate.score())
        }
        SubCommand::Base64(cmd) => match cmd {
            Base64SubCommand::Encode(opts) => {
                let encoded = process_encode(&opts.input, opts.format)?;
                fs::write(&opts.output, encoded)?;
            }
            Base64SubCommand::Decode(opts) => {
                let decode = process_decode(&opts.input, opts.format)?;
                println!("decode: {:?}", String::from_utf8(decode));
            }
        },
        SubCommand::Text(subcmd) => match subcmd {
            TextSubCommand::Sign(opts) => {
                let signature = process_text_sign(&opts.input, &opts.key, opts.format)?;
                fs::write(&opts.output, signature)?;
            }
            TextSubCommand::Verify(opts) => {
                let is_match =
                    process_text_verify(&opts.input, &opts.key, opts.format, &opts.sign)?;
                println!("is_match: {is_match}");
            }
            TextSubCommand::Generate(opts) => {
                let key = process_text_generate(opts.format)?;
                match opts.format {
                    TextKeyGenerateFormat::Blake3 => {
                        let key = &key[0];
                        let filename = opts.output.join("blakes.txt");
                        fs::write(filename, key)?;
                    }
                    TextKeyGenerateFormat::Ed25519 => {
                        let sk = &key[0];
                        let filename = opts.output.join("ed25519.sk");
                        fs::write(filename, sk)?;
                        let pk = &key[1];
                        let filename = opts.output.join("ed25519.pk");
                        fs::write(filename, pk)?;
                    }
                    TextKeyGenerateFormat::Chacha20poly1305 => {
                        let sk = &key[0];
                        let filename = opts.output.join("chacha20poly1305.key");
                        fs::write(filename, sk)?;
                        let pk = &key[1];
                        let filename = opts.output.join("chacha20poly1305.nonce");
                        fs::write(filename, pk)?;
                    }
                }
            }
            TextSubCommand::Encrypt(opts) => {
                let ciphertext =
                    process_text_encrypt(&opts.input, &opts.key, &opts.nonce, opts.format)?;
                fs::write(opts.output, ciphertext)?;
            }
            TextSubCommand::Decrypt(opts) => {
                let plaintext =
                    process_text_decrypt(&opts.input, &opts.key, &opts.nonce, opts.format)?;
                println!("plaintext: {}", String::from_utf8(plaintext)?);
            }
        },
        SubCommand::Jwt(subcmd) => match subcmd {
            JwtSubCommand::Sign(opts) => {
                let token = process_jwt_sign(
                    opts.alg,
                    opts.aud.as_deref(),
                    opts.exp,
                    opts.iat,
                    opts.iss.as_deref(),
                    opts.sub.as_deref(),
                    "3&5rpiG$z1L5DzVQwnQ+AM9swQwuXKEY",
                )?;
                println!("{:?}", token);
            }
            JwtSubCommand::Verify(_opts) => {
                println!("verify a jwt")
            }
        },
        SubCommand::Http(subcmd) => match subcmd {
            HttpSubCommand::Serve(opts) => process_http_serve(opts.dir, opts.port).await?,
        },
    }
    Ok(())
}
