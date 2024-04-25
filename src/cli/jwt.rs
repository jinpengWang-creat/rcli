use std::str::FromStr;

use clap::{Parser, Subcommand};
use jsonwebtoken::Algorithm;
#[derive(Debug, Subcommand)]
pub enum JwtSubCommand {
    #[command(about = "Sign a jwt")]
    Sign(JwtSignOpts),
    #[command(about = "Verify a jwt")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    /// Audience
    #[arg(long)]
    pub aud: Option<String>,

    /// Expiration time (as UTC timestamp)
    #[arg(long)]
    pub exp: usize,

    /// Issued at (as UTC timestamp)
    #[arg(long)]
    pub iat: Option<usize>,

    /// Issuer
    #[arg(long)]
    pub iss: Option<String>,

    /// Not Before (as UTC timestamp)
    #[arg(long)]
    pub nbf: Option<usize>,

    /// Subject (whom token refers to)
    #[arg(long)]
    pub sub: Option<String>,

    /// Output filename
    #[arg(long, default_value = "fixtures/jwt.txt")]
    pub output: String,

    /// The algorithm used
    #[arg(long, default_value = "HS256", value_parser = parse_jwt_head_algorithm)]
    pub alg: Algorithm,
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {}

fn parse_jwt_head_algorithm(al: &str) -> Result<Algorithm, jsonwebtoken::errors::Error> {
    al.parse()
}

#[derive(Debug)]
struct ExpireTime(usize);

impl FromStr for ExpireTime {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let times = s.trim();
        let unit = &times[(times.len() - 1)..];
        let times = &times[..(times.len() - 1)];
        let times: usize = times.parse()?;
        let current_time = jsonwebtoken::get_current_timestamp() as usize;
        let expire_time = match unit {
            "s" => current_time + times,
            "m" => current_time + times * 60,
            "h" => current_time + times * 60 * 60,
            "d" => current_time + times * 60 * 60 * 24,
            _ => anyhow::bail!("Unsupport unit: {}", unit),
        };
        Ok(ExpireTime(expire_time))
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::ExpireTime;

    #[test]
    fn test_unit_of_timestrap() {
        let start_time = jsonwebtoken::get_current_timestamp();
        println!("interval {:?}", (start_time));
        thread::sleep(Duration::from_secs(5));
        let end_time = jsonwebtoken::get_current_timestamp();
        println!("interval {:?}", (end_time));
    }

    #[test]
    fn test_expire_time_from_str() {
        let s = "10s";
        let expire_time: ExpireTime = s.parse().unwrap();
        println!("{:?}", jsonwebtoken::get_current_timestamp());
        println!("{:?}", expire_time);
    }
}
