use crate::{process_jwt_sign, process_jwt_verify, CmdExecutor};

use super::verify_file;
use anyhow::Result;
use clap::{Parser, Subcommand};
use enum_dispatch::enum_dispatch;
use jsonwebtoken::Algorithm;
use std::str::FromStr;

#[derive(Debug, Subcommand)]
#[enum_dispatch(CmdExecutor)]
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

    /// Expiration time (format: time + unit; eg. 10d;  unit: s,m,h,d)
    #[arg(long, default_value = "3m", value_parser = parse_jwt_expire_time)]
    pub exp: ExpireTime,

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
pub struct JwtVerifyOpts {
    /// The algorithm used
    #[arg(long, default_value = "HS256", value_parser = parse_jwt_head_algorithm)]
    pub alg: Algorithm,
    /// token
    #[arg(long, default_value = "-", value_parser = verify_file)]
    pub input: String,

    /// Audience
    #[arg(long)]
    pub aud: Option<Vec<String>>,
}

fn parse_jwt_head_algorithm(al: &str) -> Result<Algorithm, jsonwebtoken::errors::Error> {
    al.parse()
}

fn parse_jwt_expire_time(time: &str) -> Result<ExpireTime> {
    time.parse()
}

#[derive(Debug, Clone, Copy)]
pub struct ExpireTime(pub usize);

impl FromStr for ExpireTime {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let time = s.trim();
        let unit = &time[(time.len() - 1)..];
        let time = &time[..(time.len() - 1)];
        let time: usize = time.parse()?;
        let current_time = jsonwebtoken::get_current_timestamp() as usize;
        let expire_time = match unit {
            "s" => current_time + time,
            "m" => current_time + time * 60,
            "h" => current_time + time * 60 * 60,
            "d" => current_time + time * 60 * 60 * 24,
            _ => anyhow::bail!("Unsupported unit: {}", unit),
        };
        Ok(ExpireTime(expire_time))
    }
}

impl CmdExecutor for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token = process_jwt_sign(
            self.alg,
            self.aud.as_deref(),
            self.exp,
            self.sub.as_deref(),
            "secret",
        )?;
        println!("{:?}", token);
        Ok(())
    }
}

impl CmdExecutor for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        process_jwt_verify(self.alg, self.aud.as_deref(), &self.input, "secret")
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
        let s = "14d";
        let expire_time: ExpireTime = s.parse().unwrap();
        let cur_time = jsonwebtoken::get_current_timestamp() as usize;
        let expire = cur_time + 14 * 24 * 60 * 60;
        assert_eq!(expire, expire_time.0)
    }
}
