use std::path::PathBuf;

use clap::{Parser, Subcommand};

use super::verify_path;

#[derive(Debug, Subcommand)]
pub enum HttpSubCommand {
    /// Serve a directory over HTTP
    #[command(about = "Serve a directory over HTTP")]
    Serve(HttpServeOpts),
}

#[derive(Debug, Parser)]
pub struct HttpServeOpts {
    /// Direction path
    #[arg(short, long, default_value = ".", value_parser = verify_path)]
    pub dir: PathBuf,
    /// Server port
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,
}
