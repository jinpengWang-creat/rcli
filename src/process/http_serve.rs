use anyhow::Result;
use std::path::Path;
use tracing::info;

pub fn process_http_serve(path: &Path, port: u16) -> Result<()> {
    info!("Serving {:?} on port {}", path, port);
    Ok(())
}
