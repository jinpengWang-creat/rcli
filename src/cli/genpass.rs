use crate::{process_genpass, CmdExecutor};
use clap::Parser;
use zxcvbn::zxcvbn;

#[derive(Debug, Parser)]
pub struct GenPassOpts {
    #[arg(short, long, default_value_t = 16)]
    pub length: u8,

    #[arg(long)]
    pub no_uppercase: bool,

    #[arg(long)]
    pub no_lowercase: bool,

    #[arg(long)]
    pub no_number: bool,

    #[arg(long)]
    pub no_symbol: bool,
}

impl CmdExecutor for GenPassOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let password = process_genpass(
            self.length,
            self.no_uppercase,
            self.no_lowercase,
            self.no_number,
            self.no_symbol,
        )?;
        println!("{}", password);
        let estimate = zxcvbn(&password, &[])?;
        eprintln!("Password strength: {:?}", estimate.score());
        Ok(())
    }
}
