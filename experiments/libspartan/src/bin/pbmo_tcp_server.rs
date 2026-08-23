use anyhow::{anyhow, Context, Result};
use preprocessed_pbmo::{handle_tcp_connection, TransportRequestHeader, BACKEND_REVISION};
use serde::Serialize;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;

#[derive(Serialize)]
struct ServerStartup<'a> {
    classification: &'a str,
    listen: String,
    backend_revision: &'a str,
    authentication: &'a str,
    key_id_sha256: String,
}

fn bases(m: usize) -> Vec<curve25519_dalek::ristretto::RistrettoPoint> {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
    let mut shake = Shake256::default();
    shake.update(b"gens_r1cs_sat");
    shake.update(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let mut reader = shake.finalize_xof();
    (0..m)
        .map(|_| {
            let mut uniform = [0u8; 64];
            reader.read(&mut uniform);
            curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&uniform)
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn main() -> Result<()> {
    let listen =
        std::env::var("THINWALLET_PBMO_LISTEN").unwrap_or_else(|_| "127.0.0.1:39173".into());
    let key_path = PathBuf::from(
        std::env::var("THINWALLET_PBMO_PSK_FILE")
            .context("THINWALLET_PBMO_PSK_FILE is required")?,
    );
    let metrics_path = PathBuf::from(
        std::env::var("THINWALLET_PBMO_SERVER_METRICS")
            .unwrap_or_else(|_| "results/v5b/raw/server_connections.jsonl".into()),
    );
    let key_bytes = fs::read(&key_path).context("read PBMO PSK")?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow!("PBMO PSK must be exactly 32 bytes"))?;
    if let Some(parent) = metrics_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let listener = TcpListener::bind(&listen).with_context(|| format!("bind {listen}"))?;
    let startup = ServerStartup {
        classification: "CONTROLLED_AUTHENTICATED_EXPERIMENT_TRANSPORT",
        listen: listener.local_addr()?.to_string(),
        backend_revision: BACKEND_REVISION,
        authentication: "HMAC-SHA256 PSK frame authentication; plaintext private LAN; not production channel security",
        key_id_sha256: sha256_hex(&key),
    };
    println!("{}", serde_json::to_string(&startup)?);
    let max_connections = std::env::var("THINWALLET_PBMO_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    for (index, incoming) in listener.incoming().enumerate() {
        let stream = incoming?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(120)))?;
        stream.set_nodelay(true)?;
        let record = handle_tcp_connection(
            stream,
            &key,
            index as u64 + 1,
            BACKEND_REVISION,
            |header: &TransportRequestHeader| {
                if header.m > (1 << 20) || header.q > (1 << 20) {
                    return Err(preprocessed_pbmo::PbmoTransportError::Protocol(
                        "server dimension limit exceeded".into(),
                    ));
                }
                Ok(bases(header.m as usize))
            },
        );
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&metrics_path)?;
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        if index as u64 + 1 >= max_connections {
            break;
        }
    }
    Ok(())
}
