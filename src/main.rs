use clap::Parser;
use rcli::{process_csv, process_genpass, Opts, SubCommand};
use zxcvbn::zxcvbn;

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::CSV(opt) => process_csv(opt)?,
        SubCommand::GenPass(opt) => {
            let password = process_genpass(
                opt.length,
                opt.no_uppercase,
                opt.no_lowercase,
                opt.no_number,
                opt.no_symbol,
            )?;
            println!("password: {:?}", password);
            let estimate = zxcvbn(&password, &[])?;
            println!("Password strength: {:?}", estimate.score())
        }
    }
    Ok(())
}
