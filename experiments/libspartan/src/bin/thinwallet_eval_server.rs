use anyhow::{Context, Result};
use libspartan_patched::remote_eval::{run_server, ServerConfig};
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| "127.0.0.1:39451".into());
    let work_dir = PathBuf::from(
        args.next()
            .unwrap_or_else(|| "results/remote-eval-server".into()),
    );
    std::fs::create_dir_all(&work_dir).context("create server work directory")?;
    run_server(ServerConfig { endpoint, work_dir }).map_err(anyhow::Error::msg)
}
