use clap::Parser;
use rcli::{process_csv, process_genpass, Opts, OutputFormat, SubCommand};
use zxcvbn::zxcvbn;

fn main() -> anyhow::Result<()> {
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
            println!("password: {:?}", password);
            let estimate = zxcvbn(&password, &[])?;
            println!("Password strength: {:?}", estimate.score())
        }
    }
    Ok(())
}
