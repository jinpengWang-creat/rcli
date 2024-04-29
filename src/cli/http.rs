use std::path::PathBuf;

use clap::{Parser, Subcommand};
use enum_dispatch::enum_dispatch;

use crate::{process_http_serve, CmdExecutor};

use super::verify_path;

#[derive(Debug, Subcommand)]
#[enum_dispatch(CmdExecutor)]
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

impl CmdExecutor for HttpServeOpts {
    async fn execute(self) -> anyhow::Result<()> {
        process_http_serve(self.dir, self.port).await
    }
}
