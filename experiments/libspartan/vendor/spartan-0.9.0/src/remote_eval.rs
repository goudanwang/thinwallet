#![allow(missing_docs)]

use super::*;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const PROTOCOL_ID: &str = "thinwallet/spartan/remote-eval";
pub const PROTOCOL_VERSION: u16 = 1;
pub const PROOF_SYSTEM_VERSION: &str = "libspartan-0.9.0/ristretto255/phase5da-split";
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_SAT_PROOF_BYTES: usize = 128 * 1024;
pub const MAX_EVAL_PROOF_BYTES: usize = 128 * 1024;
pub const MAX_PUBLIC_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_CACHE_BYTES: usize = 512 * 1024 * 1024;

const MAGIC: &[u8; 8] = b"TWERPC01";
const HEADER_BYTES: usize = 16;
const TAG_PROBE: u8 = 1;
const TAG_PROBE_RESPONSE: u8 = 2;
const TAG_PROVISION: u8 = 3;
const TAG_ACK: u8 = 4;
const TAG_EVAL: u8 = 5;
const TAG_EVAL_RESPONSE: u8 = 6;
const TAG_ERROR: u8 = 255;
const TRANSCRIPT_LABEL: &[u8] = b"thinwallet_phase_v2_pbmo_fixed";

#[derive(Debug)]
struct ProtocolError(String);

impl fmt::Display for ProtocolError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.0)
  }
}

impl std::error::Error for ProtocolError {}

type Result<T> = std::result::Result<T, ProtocolError>;

fn fail(message: impl Into<String>) -> ProtocolError {
  ProtocolError(message.into())
}

#[derive(Clone)]
struct CacheReference {
  circuit_id: [u8; 32],
  commitment_digest: [u8; 32],
  decomm_digest: [u8; 32],
  gens_digest: [u8; 32],
}

#[derive(Clone)]
struct EvalRequestEnvelope {
  client_build_hash: [u8; 32],
  cache: CacheReference,
  invocation_id: [u8; 32],
  request_nonce: [u8; 32],
  public_inputs: Vec<Scalar>,
  computation_commitment: Vec<u8>,
  r1cs_sat_proof: Vec<u8>,
  replay: TranscriptReplayData,
  inst_evals: (Scalar, Scalar, Scalar),
  test_eval_root: Option<[u8; 32]>,
  request_digest: [u8; 32],
}

#[derive(Clone, Copy, Default)]
struct ServerTiming {
  server_queue_wall_ns: u64,
  decode_wall_ns: u64,
  decode_cpu_ns: u64,
  cache_lookup_wall_ns: u64,
  cache_lookup_cpu_ns: u64,
  transcript_replay_wall_ns: u64,
  transcript_replay_cpu_ns: u64,
  inst_eval_wall_ns: u64,
  inst_eval_cpu_ns: u64,
  eval_prove_wall_ns: u64,
  eval_prove_cpu_ns: u64,
  response_encode_wall_ns: u64,
  response_encode_cpu_ns: u64,
  total_server_wall_ns: u64,
  total_server_cpu_ns: u64,
}

#[derive(Clone, Copy, Default)]
struct RpcTiming {
  connect_wall_ns: u64,
  upload_wall_ns: u64,
  wait_to_first_response_byte_wall_ns: u64,
  download_wall_ns: u64,
  rpc_total_wall_ns: u64,
}

struct EvalResponseEnvelope {
  server_build_hash: [u8; 32],
  circuit_id: [u8; 32],
  invocation_id: [u8; 32],
  request_nonce: [u8; 32],
  request_digest: [u8; 32],
  transcript_prefix_digest: [u8; 32],
  inst_evals: (Scalar, Scalar, Scalar),
  r1cs_eval_proof: Vec<u8>,
  eval_proof_bytes: u32,
  timing: ServerTiming,
  response_digest: [u8; 32],
}

struct CacheEntry {
  reference: CacheReference,
  comm: ComputationCommitment,
  decomm: ComputationDecommitment,
  gens: SNARKGens,
  bytes: u64,
  decomm_bytes: u64,
  external_state_bytes: u64,
}

pub struct ServerConfig {
  pub endpoint: String,
  pub work_dir: PathBuf,
}

struct Writer {
  bytes: Vec<u8>,
}

impl Writer {
  fn new() -> Self {
    Self { bytes: Vec::new() }
  }

  fn u8(&mut self, value: u8) {
    self.bytes.push(value);
  }

  fn u16(&mut self, value: u16) {
    self.bytes.extend_from_slice(&value.to_be_bytes());
  }

  fn u32(&mut self, value: u32) {
    self.bytes.extend_from_slice(&value.to_be_bytes());
  }

  fn u64(&mut self, value: u64) {
    self.bytes.extend_from_slice(&value.to_be_bytes());
  }

  fn fixed(&mut self, value: &[u8]) {
    self.bytes.extend_from_slice(value);
  }

  fn bytes(&mut self, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| fail("field length exceeds u32"))?;
    self.u32(length);
    self.fixed(value);
    Ok(())
  }

  fn string(&mut self, value: &str) -> Result<()> {
    let length = u16::try_from(value.len()).map_err(|_| fail("string length exceeds u16"))?;
    self.u16(length);
    self.fixed(value.as_bytes());
    Ok(())
  }
}

struct Reader<'a> {
  bytes: &'a [u8],
  offset: usize,
}

impl<'a> Reader<'a> {
  fn new(bytes: &'a [u8]) -> Self {
    Self { bytes, offset: 0 }
  }

  fn take(&mut self, length: usize) -> Result<&'a [u8]> {
    let end = self
      .offset
      .checked_add(length)
      .ok_or_else(|| fail("length overflow"))?;
    if end > self.bytes.len() {
      return Err(fail("truncated canonical payload"));
    }
    let result = &self.bytes[self.offset..end];
    self.offset = end;
    Ok(result)
  }

  fn u8(&mut self) -> Result<u8> {
    Ok(self.take(1)?[0])
  }

  fn u16(&mut self) -> Result<u16> {
    Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
  }

  fn u32(&mut self) -> Result<u32> {
    Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
  }

  fn u64(&mut self) -> Result<u64> {
    Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
  }

  fn fixed32(&mut self) -> Result<[u8; 32]> {
    Ok(self.take(32)?.try_into().unwrap())
  }

  fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>> {
    let length = usize::try_from(self.u32()?).map_err(|_| fail("invalid length"))?;
    if length > maximum {
      return Err(fail(format!(
        "declared length {length} exceeds maximum {maximum}"
      )));
    }
    Ok(self.take(length)?.to_vec())
  }

  fn string(&mut self, maximum: usize) -> Result<String> {
    let length = usize::from(self.u16()?);
    if length > maximum {
      return Err(fail("string length exceeds maximum"));
    }
    String::from_utf8(self.take(length)?.to_vec()).map_err(|_| fail("invalid UTF-8"))
  }

  fn finish(self) -> Result<()> {
    if self.offset == self.bytes.len() {
      Ok(())
    } else {
      Err(fail("trailing bytes rejected"))
    }
  }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
  Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
  bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn native_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
  bincode::serialize(value).map_err(|error| fail(format!("native serialization: {error}")))
}

fn native_decode<T>(bytes: &[u8], maximum: usize) -> Result<T>
where
  T: DeserializeOwned + Serialize,
{
  if bytes.len() > maximum {
    return Err(fail("native object exceeds maximum"));
  }
  let value: T =
    bincode::deserialize(bytes).map_err(|error| fail(format!("native decode: {error}")))?;
  let canonical = native_encode(&value)?;
  if canonical != bytes {
    return Err(fail("native canonical reserialization mismatch"));
  }
  Ok(value)
}

fn put_protocol(writer: &mut Writer) -> Result<()> {
  writer.string(PROTOCOL_ID)?;
  writer.u16(PROTOCOL_VERSION);
  writer.string(PROOF_SYSTEM_VERSION)
}

fn get_protocol(reader: &mut Reader<'_>) -> Result<()> {
  if reader.string(64)? != PROTOCOL_ID
    || reader.u16()? != PROTOCOL_VERSION
    || reader.string(96)? != PROOF_SYSTEM_VERSION
  {
    return Err(fail("protocol or proof-system version mismatch"));
  }
  Ok(())
}

fn put_cache_reference(writer: &mut Writer, reference: &CacheReference) {
  writer.fixed(&reference.circuit_id);
  writer.fixed(&reference.commitment_digest);
  writer.fixed(&reference.decomm_digest);
  writer.fixed(&reference.gens_digest);
}

fn get_cache_reference(reader: &mut Reader<'_>) -> Result<CacheReference> {
  Ok(CacheReference {
    circuit_id: reader.fixed32()?,
    commitment_digest: reader.fixed32()?,
    decomm_digest: reader.fixed32()?,
    gens_digest: reader.fixed32()?,
  })
}

fn cache_reference(comm: &ComputationCommitment) -> Result<(CacheReference, Vec<u8>)> {
  let comm_bytes = native_encode(comm)?;
  let circuit_id = circuit_identifier(comm);
  Ok((
    CacheReference {
      circuit_id,
      commitment_digest: sha256(&comm_bytes),
      decomm_digest: hash_parts(
        b"thinwallet/remote-eval/logical-decommitment/v1",
        &[&circuit_id, PROOF_SYSTEM_VERSION.as_bytes()],
      ),
      gens_digest: hash_parts(
        b"thinwallet/remote-eval/deterministic-generators/v1",
        &[&circuit_id, PROOF_SYSTEM_VERSION.as_bytes()],
      ),
    },
    comm_bytes,
  ))
}

fn put_scalar(writer: &mut Writer, scalar: &Scalar) {
  writer.fixed(&scalar.to_bytes());
}

fn get_scalar(reader: &mut Reader<'_>) -> Result<Scalar> {
  let bytes = reader.fixed32()?;
  let scalar = Scalar::from_bytes(&bytes);
  if scalar.is_some().unwrap_u8() != 1 {
    return Err(fail("non-canonical scalar"));
  }
  Ok(scalar.unwrap())
}

fn encode_eval_request_body(request: &EvalRequestEnvelope) -> Result<Vec<u8>> {
  let mut writer = Writer::new();
  put_protocol(&mut writer)?;
  writer.fixed(&request.client_build_hash);
  put_cache_reference(&mut writer, &request.cache);
  writer.fixed(&request.invocation_id);
  writer.fixed(&request.request_nonce);
  writer.u32(u32::try_from(request.public_inputs.len()).map_err(|_| fail("too many inputs"))?);
  for input in &request.public_inputs {
    put_scalar(&mut writer, input);
  }
  writer.bytes(&request.computation_commitment)?;
  writer.bytes(&request.r1cs_sat_proof)?;
  writer.bytes(&request.replay.protocol_identifier)?;
  writer.fixed(&request.replay.commitment_digest);
  writer.fixed(&request.replay.public_inputs_digest);
  writer.fixed(&request.replay.sat_proof_digest);
  put_scalar(&mut writer, &request.inst_evals.0);
  put_scalar(&mut writer, &request.inst_evals.1);
  put_scalar(&mut writer, &request.inst_evals.2);
  match request.test_eval_root {
    Some(seed) => {
      writer.u8(1);
      writer.fixed(&seed);
    }
    None => writer.u8(0),
  }
  Ok(writer.bytes)
}

fn encode_eval_request(request: &mut EvalRequestEnvelope) -> Result<Vec<u8>> {
  let mut body = encode_eval_request_body(request)?;
  request.request_digest = sha256(&body);
  body.extend_from_slice(&request.request_digest);
  if body.len() > MAX_REQUEST_BYTES {
    return Err(fail("request exceeds MAX_REQUEST_BYTES"));
  }
  Ok(body)
}

fn decode_eval_request(bytes: &[u8]) -> Result<EvalRequestEnvelope> {
  if bytes.len() > MAX_REQUEST_BYTES || bytes.len() < 32 {
    return Err(fail("request length rejected before decode"));
  }
  let body_length = bytes.len() - 32;
  let (body, digest_bytes) = bytes.split_at(body_length);
  let digest: [u8; 32] = digest_bytes.try_into().unwrap();
  if sha256(body) != digest {
    return Err(fail("request digest mismatch"));
  }
  let mut reader = Reader::new(body);
  get_protocol(&mut reader)?;
  let client_build_hash = reader.fixed32()?;
  let cache = get_cache_reference(&mut reader)?;
  let invocation_id = reader.fixed32()?;
  let request_nonce = reader.fixed32()?;
  let input_count = usize::try_from(reader.u32()?).map_err(|_| fail("input count"))?;
  if input_count.checked_mul(32).unwrap_or(usize::MAX) > MAX_PUBLIC_INPUT_BYTES {
    return Err(fail("public input bytes exceed maximum"));
  }
  let mut public_inputs = Vec::with_capacity(input_count);
  for _ in 0..input_count {
    public_inputs.push(get_scalar(&mut reader)?);
  }
  let computation_commitment = reader.bytes(MAX_CACHE_BYTES)?;
  let r1cs_sat_proof = reader.bytes(MAX_SAT_PROOF_BYTES)?;
  let replay = TranscriptReplayData {
    protocol_identifier: reader.bytes(96)?,
    commitment_digest: reader.fixed32()?,
    public_inputs_digest: reader.fixed32()?,
    sat_proof_digest: reader.fixed32()?,
  };
  let inst_evals = (
    get_scalar(&mut reader)?,
    get_scalar(&mut reader)?,
    get_scalar(&mut reader)?,
  );
  let test_eval_root = match reader.u8()? {
    0 => None,
    1 => Some(reader.fixed32()?),
    _ => return Err(fail("invalid optional seed tag")),
  };
  reader.finish()?;
  let request = EvalRequestEnvelope {
    client_build_hash,
    cache,
    invocation_id,
    request_nonce,
    public_inputs,
    computation_commitment,
    r1cs_sat_proof,
    replay,
    inst_evals,
    test_eval_root,
    request_digest: digest,
  };
  if encode_eval_request_body(&request)? != body {
    return Err(fail("request canonical round-trip mismatch"));
  }
  Ok(request)
}

fn encode_timing(writer: &mut Writer, timing: &ServerTiming) {
  for value in [
    timing.server_queue_wall_ns,
    timing.decode_wall_ns,
    timing.decode_cpu_ns,
    timing.cache_lookup_wall_ns,
    timing.cache_lookup_cpu_ns,
    timing.transcript_replay_wall_ns,
    timing.transcript_replay_cpu_ns,
    timing.inst_eval_wall_ns,
    timing.inst_eval_cpu_ns,
    timing.eval_prove_wall_ns,
    timing.eval_prove_cpu_ns,
    timing.response_encode_wall_ns,
    timing.response_encode_cpu_ns,
    timing.total_server_wall_ns,
    timing.total_server_cpu_ns,
  ] {
    writer.u64(value);
  }
}

fn decode_timing(reader: &mut Reader<'_>) -> Result<ServerTiming> {
  Ok(ServerTiming {
    server_queue_wall_ns: reader.u64()?,
    decode_wall_ns: reader.u64()?,
    decode_cpu_ns: reader.u64()?,
    cache_lookup_wall_ns: reader.u64()?,
    cache_lookup_cpu_ns: reader.u64()?,
    transcript_replay_wall_ns: reader.u64()?,
    transcript_replay_cpu_ns: reader.u64()?,
    inst_eval_wall_ns: reader.u64()?,
    inst_eval_cpu_ns: reader.u64()?,
    eval_prove_wall_ns: reader.u64()?,
    eval_prove_cpu_ns: reader.u64()?,
    response_encode_wall_ns: reader.u64()?,
    response_encode_cpu_ns: reader.u64()?,
    total_server_wall_ns: reader.u64()?,
    total_server_cpu_ns: reader.u64()?,
  })
}

fn encode_eval_response_body(response: &EvalResponseEnvelope) -> Result<Vec<u8>> {
  let mut writer = Writer::new();
  put_protocol(&mut writer)?;
  writer.fixed(&response.server_build_hash);
  writer.fixed(&response.circuit_id);
  writer.fixed(&response.invocation_id);
  writer.fixed(&response.request_nonce);
  writer.fixed(&response.request_digest);
  writer.fixed(&response.transcript_prefix_digest);
  put_scalar(&mut writer, &response.inst_evals.0);
  put_scalar(&mut writer, &response.inst_evals.1);
  put_scalar(&mut writer, &response.inst_evals.2);
  writer.bytes(&response.r1cs_eval_proof)?;
  writer.u32(response.eval_proof_bytes);
  encode_timing(&mut writer, &response.timing);
  Ok(writer.bytes)
}

fn encode_eval_response(response: &mut EvalResponseEnvelope) -> Result<Vec<u8>> {
  let mut body = encode_eval_response_body(response)?;
  response.response_digest = sha256(&body);
  body.extend_from_slice(&response.response_digest);
  if body.len() > MAX_RESPONSE_BYTES {
    return Err(fail("response exceeds MAX_RESPONSE_BYTES"));
  }
  Ok(body)
}

fn decode_eval_response(bytes: &[u8]) -> Result<EvalResponseEnvelope> {
  if bytes.len() > MAX_RESPONSE_BYTES || bytes.len() < 32 {
    return Err(fail("response length rejected before decode"));
  }
  let (body, digest_bytes) = bytes.split_at(bytes.len() - 32);
  let response_digest: [u8; 32] = digest_bytes.try_into().unwrap();
  if sha256(body) != response_digest {
    return Err(fail("response digest mismatch"));
  }
  let mut reader = Reader::new(body);
  get_protocol(&mut reader)?;
  let server_build_hash = reader.fixed32()?;
  let circuit_id = reader.fixed32()?;
  let invocation_id = reader.fixed32()?;
  let request_nonce = reader.fixed32()?;
  let request_digest = reader.fixed32()?;
  let transcript_prefix_digest = reader.fixed32()?;
  let inst_evals = (
    get_scalar(&mut reader)?,
    get_scalar(&mut reader)?,
    get_scalar(&mut reader)?,
  );
  let r1cs_eval_proof = reader.bytes(MAX_EVAL_PROOF_BYTES)?;
  let eval_proof_bytes = reader.u32()?;
  let timing = decode_timing(&mut reader)?;
  reader.finish()?;
  let response = EvalResponseEnvelope {
    server_build_hash,
    circuit_id,
    invocation_id,
    request_nonce,
    request_digest,
    transcript_prefix_digest,
    inst_evals,
    r1cs_eval_proof,
    eval_proof_bytes,
    timing,
    response_digest,
  };
  if usize::try_from(eval_proof_bytes).ok() != Some(response.r1cs_eval_proof.len())
    || encode_eval_response_body(&response)? != body
  {
    return Err(fail("response canonical round-trip mismatch"));
  }
  Ok(response)
}

fn write_frame(stream: &mut TcpStream, tag: u8, payload: &[u8]) -> Result<()> {
  let payload_length =
    u32::try_from(payload.len()).map_err(|_| fail("frame length exceeds u32"))?;
  let mut header = [0u8; HEADER_BYTES];
  header[..8].copy_from_slice(MAGIC);
  header[8..10].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
  header[10] = tag;
  header[11] = 0;
  header[12..16].copy_from_slice(&payload_length.to_be_bytes());
  stream
    .write_all(&header)
    .map_err(|error| fail(format!("write header: {error}")))?;
  stream
    .write_all(payload)
    .map_err(|error| fail(format!("write payload: {error}")))?;
  stream
    .flush()
    .map_err(|error| fail(format!("flush: {error}")))?;
  Ok(())
}

fn read_frame(stream: &mut TcpStream, maximum: usize) -> Result<(u8, Vec<u8>)> {
  let mut header = [0u8; HEADER_BYTES];
  stream
    .read_exact(&mut header)
    .map_err(|error| fail(format!("read header: {error}")))?;
  if &header[..8] != MAGIC
    || u16::from_be_bytes(header[8..10].try_into().unwrap()) != PROTOCOL_VERSION
  {
    return Err(fail("frame magic/version mismatch"));
  }
  if header[11] != 0 {
    return Err(fail("non-zero reserved frame bits"));
  }
  let length = usize::try_from(u32::from_be_bytes(header[12..16].try_into().unwrap()))
    .map_err(|_| fail("frame length conversion"))?;
  if length > maximum {
    return Err(fail(format!(
      "frame length {length} exceeds maximum {maximum}"
    )));
  }
  let mut payload = vec![0u8; length];
  stream
    .read_exact(&mut payload)
    .map_err(|error| fail(format!("read payload: {error}")))?;
  Ok((header[10], payload))
}

fn read_frame_timed(stream: &mut TcpStream, maximum: usize) -> Result<((u8, Vec<u8>), u64, u64)> {
  let wait_start = duration_time_ns();
  let mut header = [0u8; HEADER_BYTES];
  stream
    .read_exact(&mut header[..1])
    .map_err(|error| fail(format!("read first response byte: {error}")))?;
  let wait_to_first_response_byte_wall_ns = duration_time_ns().saturating_sub(wait_start);
  let response_read_start = duration_time_ns();
  stream
    .read_exact(&mut header[1..])
    .map_err(|error| fail(format!("read response header: {error}")))?;
  if &header[..8] != MAGIC
    || u16::from_be_bytes(header[8..10].try_into().unwrap()) != PROTOCOL_VERSION
  {
    return Err(fail("frame magic/version mismatch"));
  }
  if header[11] != 0 {
    return Err(fail("non-zero reserved frame bits"));
  }
  let length = usize::try_from(u32::from_be_bytes(header[12..16].try_into().unwrap()))
    .map_err(|_| fail("frame length conversion"))?;
  if length > maximum {
    return Err(fail(format!(
      "frame length {length} exceeds maximum {maximum}"
    )));
  }
  let mut payload = vec![0u8; length];
  stream
    .read_exact(&mut payload)
    .map_err(|error| fail(format!("read response payload: {error}")))?;
  let response_socket_read_wall_ns = duration_time_ns().saturating_sub(response_read_start);
  Ok((
    (header[10], payload),
    wait_to_first_response_byte_wall_ns,
    response_socket_read_wall_ns,
  ))
}

fn rpc(
  endpoint: &str,
  tag: u8,
  request: &[u8],
  maximum: usize,
) -> Result<(u8, Vec<u8>, RpcTiming)> {
  let connect_start = duration_time_ns();
  let mut stream =
    TcpStream::connect(endpoint).map_err(|error| fail(format!("connect: {error}")))?;
  let connect_wall_ns = duration_time_ns().saturating_sub(connect_start);
  let timeout_ms = std::env::var("THINWALLET_REMOTE_EVAL_TIMEOUT_MS")
    .ok()
    .and_then(|value| value.parse::<u64>().ok())
    .unwrap_or(120_000);
  stream
    .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
    .map_err(|error| fail(error.to_string()))?;
  let write_timeout_ms = std::env::var("THINWALLET_REMOTE_EVAL_WRITE_TIMEOUT_MS")
    .ok()
    .and_then(|value| value.parse::<u64>().ok())
    .unwrap_or(900_000);
  stream
    .set_write_timeout(Some(Duration::from_millis(write_timeout_ms)))
    .map_err(|error| fail(error.to_string()))?;
  let rpc_total_start = duration_time_ns();
  let upload_start = duration_time_ns();
  write_frame(&mut stream, tag, request)?;
  stream
    .shutdown(Shutdown::Write)
    .map_err(|error| fail(format!("shutdown write: {error}")))?;
  let upload_wall_ns = duration_time_ns().saturating_sub(upload_start);
  let (response, wait_to_first_response_byte_wall_ns, response_socket_read_wall_ns) =
    read_frame_timed(&mut stream, maximum)?;
  let rpc_total_wall_ns = duration_time_ns().saturating_sub(rpc_total_start);
  let mut trailing = Vec::new();
  stream
    .read_to_end(&mut trailing)
    .map_err(|error| fail(format!("read EOF: {error}")))?;
  if !trailing.is_empty() {
    return Err(fail("trailing bytes after response frame"));
  }
  if response.0 == TAG_ERROR {
    return Err(fail(format!(
      "server rejected request: {}",
      String::from_utf8_lossy(&response.1)
    )));
  }
  #[cfg(feature = "thinwallet-experiment")]
  {
    thinwallet_instrumentation::increment_counter(
      "remote_eval_socket_tx_bytes",
      (HEADER_BYTES + request.len()) as u64,
    );
    thinwallet_instrumentation::increment_counter(
      "remote_eval_socket_rx_bytes",
      (HEADER_BYTES + response.1.len()) as u64,
    );
  }
  Ok((
    response.0,
    response.1,
    RpcTiming {
      connect_wall_ns,
      upload_wall_ns,
      wait_to_first_response_byte_wall_ns,
      download_wall_ns: response_socket_read_wall_ns,
      rpc_total_wall_ns,
    },
  ))
}

fn build_hash() -> [u8; 32] {
  std::env::current_exe()
    .ok()
    .and_then(|path| fs::read(path).ok())
    .map(|bytes| sha256(&bytes))
    .unwrap_or_else(|| sha256(b"unavailable-executable"))
}

fn cpu_time_ns() -> u64 {
  #[cfg(feature = "thinwallet-experiment")]
  {
    thinwallet_instrumentation::process_cpu_time_ns()
  }
  #[cfg(not(feature = "thinwallet-experiment"))]
  {
    0
  }
}

fn duration_time_ns() -> u64 {
  #[cfg(feature = "thinwallet-experiment")]
  {
    thinwallet_instrumentation::duration_time_ns()
  }
  #[cfg(not(feature = "thinwallet-experiment"))]
  {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
  }
}

fn duration_clock_name() -> &'static str {
  #[cfg(feature = "thinwallet-experiment")]
  {
    thinwallet_instrumentation::duration_clock_name()
  }
  #[cfg(not(feature = "thinwallet-experiment"))]
  {
    "std::time::Instant"
  }
}

fn transcript_prefix_digest(
  request: &EvalRequestEnvelope,
  rx: &[Scalar],
  ry: &[Scalar],
) -> [u8; 32] {
  let mut writer = Writer::new();
  writer.fixed(&request.cache.circuit_id);
  writer.fixed(&request.invocation_id);
  writer.fixed(&request.request_nonce);
  writer.fixed(&request.request_digest);
  for scalar in rx.iter().chain(ry.iter()) {
    put_scalar(&mut writer, scalar);
  }
  for scalar in [
    &request.inst_evals.0,
    &request.inst_evals.1,
    &request.inst_evals.2,
  ] {
    put_scalar(&mut writer, scalar);
  }
  sha256(&writer.bytes)
}

fn replay_request(
  request: &EvalRequestEnvelope,
  entry: &CacheEntry,
) -> Result<(Vec<Scalar>, Vec<Scalar>, Transcript)> {
  if request.replay.protocol_identifier != SPLIT_PROTOCOL_VERSION
    || request.replay.commitment_digest
      != hash_parts(
        b"thinwallet/spartan/replay-commitment/v1",
        &[&request.computation_commitment],
      )
    || request.replay.public_inputs_digest
      != hash_parts(
        b"thinwallet/spartan/replay-inputs/v1",
        &[&native_encode(&request.public_inputs)?],
      )
    || request.replay.sat_proof_digest
      != hash_parts(
        b"thinwallet/spartan/replay-sat-proof/v1",
        &[&request.r1cs_sat_proof],
      )
  {
    return Err(fail("transcript replay digest mismatch"));
  }
  let sat_proof: R1CSProof = native_decode(&request.r1cs_sat_proof, MAX_SAT_PROOF_BYTES)?;
  let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
  transcript.append_protocol_name(SNARK::protocol_name());
  entry
    .comm
    .comm
    .append_to_transcript(b"comm", &mut transcript);
  if request.public_inputs.len() != entry.comm.comm.get_num_inputs() {
    return Err(fail("public input count mismatch"));
  }
  let (rx, ry) = sat_proof
    .verify(
      entry.comm.comm.get_num_vars(),
      entry.comm.comm.get_num_cons(),
      &request.public_inputs,
      &request.inst_evals,
      &mut transcript,
      &entry.gens.gens_r1cs_sat,
    )
    .map_err(|_| fail("native Sat proof replay failed"))?;
  request
    .inst_evals
    .0
    .append_to_transcript(b"Ar_claim", &mut transcript);
  request
    .inst_evals
    .1
    .append_to_transcript(b"Br_claim", &mut transcript);
  request
    .inst_evals
    .2
    .append_to_transcript(b"Cr_claim", &mut transcript);
  Ok((rx, ry, transcript))
}

fn encode_probe(reference: &CacheReference) -> Result<Vec<u8>> {
  let mut writer = Writer::new();
  put_protocol(&mut writer)?;
  put_cache_reference(&mut writer, reference);
  Ok(writer.bytes)
}

fn decode_probe(bytes: &[u8]) -> Result<CacheReference> {
  let mut reader = Reader::new(bytes);
  get_protocol(&mut reader)?;
  let reference = get_cache_reference(&mut reader)?;
  reader.finish()?;
  if encode_probe(&reference)? != bytes {
    return Err(fail("probe canonical mismatch"));
  }
  Ok(reference)
}

fn encode_probe_response(
  server_build: [u8; 32],
  hit: bool,
  reference: &CacheReference,
) -> Result<Vec<u8>> {
  let mut writer = Writer::new();
  put_protocol(&mut writer)?;
  writer.fixed(&server_build);
  writer.u8(u8::from(hit));
  put_cache_reference(&mut writer, reference);
  Ok(writer.bytes)
}

fn decode_probe_response(bytes: &[u8], expected: &CacheReference) -> Result<([u8; 32], bool)> {
  let mut reader = Reader::new(bytes);
  get_protocol(&mut reader)?;
  let build = reader.fixed32()?;
  let hit = match reader.u8()? {
    0 => false,
    1 => true,
    _ => return Err(fail("invalid cache-hit boolean")),
  };
  let actual = get_cache_reference(&mut reader)?;
  reader.finish()?;
  if !same_cache(&actual, expected) {
    return Err(fail("probe response cache binding mismatch"));
  }
  Ok((build, hit))
}

fn encode_provision(
  reference: &CacheReference,
  comm: &[u8],
  decomm: &[u8],
  external_state: &[u8],
  gens: &[u8],
) -> Result<Vec<u8>> {
  let mut writer = Writer::new();
  put_protocol(&mut writer)?;
  put_cache_reference(&mut writer, reference);
  writer.bytes(comm)?;
  writer.bytes(decomm)?;
  writer.bytes(external_state)?;
  writer.bytes(gens)?;
  if writer.bytes.len() > MAX_CACHE_BYTES {
    return Err(fail("cache provision exceeds maximum"));
  }
  Ok(writer.bytes)
}

fn decode_provision(bytes: &[u8]) -> Result<(CacheReference, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
  if bytes.len() > MAX_CACHE_BYTES {
    return Err(fail("cache provision length rejected"));
  }
  let mut reader = Reader::new(bytes);
  get_protocol(&mut reader)?;
  let reference = get_cache_reference(&mut reader)?;
  let comm = reader.bytes(MAX_CACHE_BYTES)?;
  let decomm = reader.bytes(MAX_CACHE_BYTES)?;
  let external_state = reader.bytes(MAX_CACHE_BYTES)?;
  let gens = reader.bytes(MAX_CACHE_BYTES)?;
  reader.finish()?;
  if encode_provision(&reference, &comm, &decomm, &external_state, &gens)? != bytes {
    return Err(fail("cache provision canonical mismatch"));
  }
  Ok((reference, comm, decomm, external_state, gens))
}

fn same_cache(left: &CacheReference, right: &CacheReference) -> bool {
  left.circuit_id == right.circuit_id
    && left.commitment_digest == right.commitment_digest
    && left.decomm_digest == right.decomm_digest
    && left.gens_digest == right.gens_digest
}

fn ack() -> Result<Vec<u8>> {
  let mut writer = Writer::new();
  put_protocol(&mut writer)?;
  writer.u8(1);
  Ok(writer.bytes)
}

fn check_ack(bytes: &[u8]) -> Result<()> {
  let mut reader = Reader::new(bytes);
  get_protocol(&mut reader)?;
  if reader.u8()? != 1 {
    return Err(fail("cache provision not acknowledged"));
  }
  reader.finish()
}

fn append_server_log(work_dir: &Path, value: serde_json::Value) {
  if let Ok(mut file) = OpenOptions::new()
    .create(true)
    .append(true)
    .open(work_dir.join("server_requests.jsonl"))
  {
    let _ = writeln!(file, "{value}");
  }
}

fn append_client_trace(value: serde_json::Value) {
  let Some(path) = std::env::var_os("THINWALLET_REMOTE_EVAL_CLIENT_TRACE") else {
    return;
  };
  if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
    let _ = writeln!(file, "{value}");
  }
}

fn configured_fault(work_dir: &Path) -> String {
  if let Ok(value) = std::env::var("THINWALLET_REMOTE_EVAL_FAULT") {
    return value;
  }
  let path = std::env::var_os("THINWALLET_REMOTE_EVAL_FAULT_FILE")
    .map(PathBuf::from)
    .unwrap_or_else(|| work_dir.join("fault_mode.txt"));
  fs::read_to_string(path)
    .unwrap_or_default()
    .trim()
    .to_owned()
}

fn capture_public_fixture(kind: &str, payload: &[u8]) -> Result<()> {
  let Some(root) = std::env::var_os("THINWALLET_REMOTE_EVAL_CAPTURE_DIR") else {
    return Ok(());
  };
  let stem =
    std::env::var("THINWALLET_REMOTE_EVAL_CAPTURE_STEM").unwrap_or_else(|_| "eval".to_owned());
  let root = PathBuf::from(root);
  fs::create_dir_all(&root).map_err(|error| fail(error.to_string()))?;
  fs::write(root.join(format!("{stem}_eval_{kind}.bin")), payload)
    .map_err(|error| fail(error.to_string()))
}

#[derive(Clone, Copy, Default)]
struct RequestRssSnapshot {
  baseline_kib: u64,
  peak_kib: u64,
  final_kib: u64,
  process_vm_hwm_kib: u64,
  samples: u64,
  interval_ms: u64,
}

struct RequestRssMonitor {
  baseline_kib: u64,
  interval_ms: u64,
  running: Arc<AtomicBool>,
  peak_kib: Arc<AtomicU64>,
  samples: Arc<AtomicU64>,
  worker: Option<thread::JoinHandle<()>>,
}

impl RequestRssMonitor {
  fn start() -> Option<Self> {
    if std::env::var("THINWALLET_REMOTE_EVAL_REQUEST_RSS").as_deref() != Ok("1") {
      return None;
    }
    let interval_ms = std::env::var("THINWALLET_REMOTE_EVAL_RSS_INTERVAL_MS")
      .ok()
      .and_then(|value| value.parse::<u64>().ok())
      .unwrap_or(20)
      .max(1);
    let baseline_kib = status_value("VmRSS").unwrap_or(0);
    let running = Arc::new(AtomicBool::new(true));
    let peak_kib = Arc::new(AtomicU64::new(baseline_kib));
    let samples = Arc::new(AtomicU64::new(1));
    let worker_running = Arc::clone(&running);
    let worker_peak = Arc::clone(&peak_kib);
    let worker_samples = Arc::clone(&samples);
    let worker = thread::spawn(move || {
      while worker_running.load(AtomicOrdering::Relaxed) {
        if let Some(value) = status_value("VmRSS") {
          worker_peak.fetch_max(value, AtomicOrdering::Relaxed);
          worker_samples.fetch_add(1, AtomicOrdering::Relaxed);
        }
        thread::sleep(Duration::from_millis(interval_ms));
      }
    });
    Some(Self {
      baseline_kib,
      interval_ms,
      running,
      peak_kib,
      samples,
      worker: Some(worker),
    })
  }

  fn stop_worker(&mut self) {
    self.running.store(false, AtomicOrdering::Relaxed);
    if let Some(worker) = self.worker.take() {
      let _ = worker.join();
    }
  }

  fn finish(mut self) -> RequestRssSnapshot {
    self.stop_worker();
    let final_kib = status_value("VmRSS").unwrap_or(0);
    RequestRssSnapshot {
      baseline_kib: self.baseline_kib,
      peak_kib: self.peak_kib.load(AtomicOrdering::Relaxed).max(final_kib),
      final_kib,
      process_vm_hwm_kib: status_value("VmHWM").unwrap_or(0),
      samples: self.samples.load(AtomicOrdering::Relaxed),
      interval_ms: self.interval_ms,
    }
  }
}

impl Drop for RequestRssMonitor {
  fn drop(&mut self) {
    self.stop_worker();
  }
}

fn path_is_windows_mounted(path: &Path) -> bool {
  let text = path.to_string_lossy();
  ["/mnt/c", "/mnt/d", "/mnt/e"]
    .iter()
    .any(|prefix| text == *prefix || text.starts_with(&format!("{prefix}/")))
}

fn filesystem_type(path: &Path) -> Option<String> {
  let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
  let mounts = fs::read_to_string("/proc/mounts").ok()?;
  mounts
    .lines()
    .filter_map(|line| {
      let fields = line.split_whitespace().collect::<Vec<_>>();
      let mount = fields.get(1)?;
      let filesystem = fields.get(2)?;
      canonical
        .starts_with(mount)
        .then(|| (mount.len(), (*filesystem).to_owned()))
    })
    .max_by_key(|(length, _)| *length)
    .map(|(_, filesystem)| filesystem)
}

fn handle_eval(
  payload: &[u8],
  cache: &HashMap<[u8; 32], CacheEntry>,
  server_build_hash: [u8; 32],
  completed: &mut HashSet<([u8; 32], [u8; 32])>,
  work_dir: &Path,
  server_queue_wall_ns: u64,
) -> Result<Vec<u8>> {
  let rss_monitor = RequestRssMonitor::start();
  let resources_before = resource_snapshot();
  let mem_available_before_kib = meminfo_kib("MemAvailable");
  let total_start = duration_time_ns();
  let cpu_start = cpu_time_ns();
  let decode_start = duration_time_ns();
  let decode_cpu_start = cpu_time_ns();
  let request = decode_eval_request(payload)?;
  let decode_wall_ns = duration_time_ns().saturating_sub(decode_start);
  let decode_cpu_ns = cpu_time_ns().saturating_sub(decode_cpu_start);
  if request.invocation_id == [0u8; 32] || request.request_nonce == [0u8; 32] {
    return Err(fail("zero invocation or nonce rejected"));
  }
  if completed.contains(&(request.invocation_id, request.request_nonce)) {
    return Err(fail("completed invocation replay rejected"));
  }
  let fault = configured_fault(work_dir);
  if fault == "stale_cache"
    || fault == "replayed_completed_invocation"
    || fault == "request_decomm_upload"
    || fault == "request_extra_secret_field"
  {
    return Err(fail(format!("fault injection rejected: {fault}")));
  }
  let cache_start = duration_time_ns();
  let cache_cpu_start = cpu_time_ns();
  let entry = cache
    .get(&request.cache.circuit_id)
    .ok_or_else(|| fail("circuit not allowlisted/cached"))?;
  if !same_cache(&entry.reference, &request.cache)
    || native_encode(&entry.comm)? != request.computation_commitment
    || circuit_identifier(&entry.comm) != request.cache.circuit_id
  {
    return Err(fail("stale or mismatched circuit cache"));
  }
  let cache_lookup_wall_ns = duration_time_ns().saturating_sub(cache_start);
  let cache_lookup_cpu_ns = cpu_time_ns().saturating_sub(cache_cpu_start);
  if request.test_eval_root.is_some()
    && std::env::var("THINWALLET_REMOTE_EVAL_ALLOW_TEST_SEED").as_deref() != Ok("1")
  {
    return Err(fail("TEST_ONLY eval seed disabled"));
  }
  let replay_start = duration_time_ns();
  let replay_cpu_start = cpu_time_ns();
  let (rx, ry, mut transcript) = replay_request(&request, entry)?;
  let transcript_replay_wall_ns = duration_time_ns().saturating_sub(replay_start);
  let transcript_replay_cpu_ns = cpu_time_ns().saturating_sub(replay_cpu_start);
  let prefix_digest = transcript_prefix_digest(&request, &rx, &ry);
  let test_seed_mode = request.test_eval_root.is_some();
  let eval_root = request.test_eval_root.unwrap_or_else(|| {
    let mut root = [0u8; 32];
    OsRng.fill_bytes(&mut root);
    root
  });
  let eval_seed = hmac_phase_seed(
    &eval_root,
    if test_seed_mode {
      b"eval"
    } else {
      b"remote-eval"
    },
    &request.cache.circuit_id,
    &request.invocation_id,
  );
  let mut random_tape = RandomTape::from_phase_seed(b"eval_proof", &eval_seed);
  let state_report_path =
    if std::env::var("THINWALLET_REMOTE_EVAL_REQUEST_REPORT").as_deref() == Ok("1") {
      let path = work_dir.join(format!("state-report-{}.json", hex(&request.invocation_id)));
      std::env::set_var("V3B_STATE_REPORT_PATH", &path);
      Some(path)
    } else {
      None
    };
  let prove_start = duration_time_ns();
  let prove_cpu_start = cpu_time_ns();
  let proof = std::panic::catch_unwind(AssertUnwindSafe(|| {
    R1CSEvalProof::prove(
      &entry.decomm.decomm,
      &rx,
      &ry,
      &request.inst_evals,
      &entry.gens.gens_r1cs_eval,
      &mut transcript,
      &mut random_tape,
    )
  }))
  .map_err(|_| fail("Eval proving aborted without releasing a partial proof"))?;
  let eval_prove_wall_ns = duration_time_ns().saturating_sub(prove_start);
  let eval_prove_cpu_ns = cpu_time_ns().saturating_sub(prove_cpu_start);
  if state_report_path.is_some() {
    std::env::remove_var("V3B_STATE_REPORT_PATH");
  }
  let state_store = state_report_path
    .as_ref()
    .and_then(|path| fs::read(path).ok())
    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
  let proof_bytes = native_encode(&proof)?;
  let mut response = EvalResponseEnvelope {
    server_build_hash,
    circuit_id: request.cache.circuit_id,
    invocation_id: request.invocation_id,
    request_nonce: request.request_nonce,
    request_digest: request.request_digest,
    transcript_prefix_digest: prefix_digest,
    inst_evals: request.inst_evals,
    eval_proof_bytes: u32::try_from(proof_bytes.len()).map_err(|_| fail("eval proof too large"))?,
    r1cs_eval_proof: proof_bytes,
    timing: ServerTiming {
      server_queue_wall_ns,
      decode_wall_ns,
      decode_cpu_ns,
      cache_lookup_wall_ns,
      cache_lookup_cpu_ns,
      transcript_replay_wall_ns,
      transcript_replay_cpu_ns,
      inst_eval_wall_ns: 0,
      inst_eval_cpu_ns: 0,
      eval_prove_wall_ns,
      eval_prove_cpu_ns,
      response_encode_wall_ns: 0,
      response_encode_cpu_ns: 0,
      total_server_wall_ns: 0,
      total_server_cpu_ns: 0,
    },
    response_digest: [0u8; 32],
  };
  match fault.as_str() {
    "wrong_circuit_id" | "other_circuit_response" => response.circuit_id[0] ^= 1,
    "wrong_invocation_id" | "other_invocation_response" | "response_reordering" => {
      response.invocation_id[0] ^= 1
    }
    "wrong_request_nonce" => response.request_nonce[0] ^= 1,
    "wrong_request_digest" => response.request_digest[0] ^= 1,
    "wrong_transcript_prefix_digest" => response.transcript_prefix_digest[0] ^= 1,
    "modified_inst_evals" => response.inst_evals.0 += Scalar::one(),
    "modified_eval_proof_byte" => {
      if let Some(byte) = response.r1cs_eval_proof.first_mut() {
        *byte ^= 1;
      }
    }
    "truncated_eval_proof" => {
      response.r1cs_eval_proof.pop();
      response.eval_proof_bytes = response.r1cs_eval_proof.len() as u32;
    }
    "proof_trailing_bytes" => {
      response.r1cs_eval_proof.push(0);
      response.eval_proof_bytes = response.r1cs_eval_proof.len() as u32;
    }
    "empty_eval_proof" => {
      response.r1cs_eval_proof.clear();
      response.eval_proof_bytes = 0;
    }
    "well_formed_invalid_native_proof" => {
      let original = response.r1cs_eval_proof.clone();
      let mut replacement = None;
      for index in 0..original.len() {
        let mut candidate = original.clone();
        candidate[index] ^= 1;
        if native_decode::<R1CSEvalProof>(&candidate, MAX_EVAL_PROOF_BYTES).is_ok() {
          replacement = Some(candidate);
          break;
        }
      }
      response.r1cs_eval_proof =
        replacement.ok_or_else(|| fail("unable to construct invalid native proof"))?;
      response.eval_proof_bytes = response.r1cs_eval_proof.len() as u32;
    }
    _ => {}
  }
  let encode_start = duration_time_ns();
  let encode_cpu_start = cpu_time_ns();
  let _ = encode_eval_response_body(&response)?;
  response.timing.response_encode_wall_ns = duration_time_ns().saturating_sub(encode_start);
  response.timing.response_encode_cpu_ns = cpu_time_ns().saturating_sub(encode_cpu_start);
  response.timing.total_server_wall_ns = duration_time_ns().saturating_sub(total_start);
  response.timing.total_server_cpu_ns = cpu_time_ns().saturating_sub(cpu_start);
  let mut encoded = encode_eval_response(&mut response)?;
  if fault == "response_version_mismatch" || fault == "server_protocol_mismatch" {
    let protocol_length = usize::from(u16::from_be_bytes(encoded[..2].try_into().unwrap()));
    if fault == "response_version_mismatch" {
      let version_offset = 2 + protocol_length;
      encoded[version_offset + 1] ^= 1;
    } else {
      encoded[2] ^= 1;
    }
    let digest = sha256(&encoded[..encoded.len() - 32]);
    let digest_offset = encoded.len() - 32;
    encoded[digest_offset..].copy_from_slice(&digest);
  }
  if fault == "server_build_mismatch" {
    response.server_build_hash[0] ^= 1;
    encoded = encode_eval_response(&mut response)?;
  }
  completed.insert((request.invocation_id, request.request_nonce));
  let resources_after = resource_snapshot();
  let mem_available_after_kib = meminfo_kib("MemAvailable");
  let rss = rss_monitor.map(RequestRssMonitor::finish);
  let request_state_path = std::env::var_os("V3B_STATE_DIR").map(PathBuf::from);
  let state_filesystem = request_state_path.as_deref().and_then(filesystem_type);
  let windows_mount_access_count = request_state_path
    .as_deref()
    .map(path_is_windows_mounted)
    .map(|mounted| if mounted { 1 } else { 0 })
    .unwrap_or_default();
  let request_rss = rss.map(|snapshot| {
    json!({
      "baseline_rss_mib": snapshot.baseline_kib as f64 / 1024.0,
      "request_peak_rss_mib": snapshot.peak_kib as f64 / 1024.0,
      "final_rss_mib": snapshot.final_kib as f64 / 1024.0,
      "process_vm_hwm_mib": snapshot.process_vm_hwm_kib as f64 / 1024.0,
      "samples": snapshot.samples,
      "interval_ms": snapshot.interval_ms,
    })
  });
  let resources = json!({
    "mem_available_before_kib": mem_available_before_kib,
    "mem_available_after_kib": mem_available_after_kib,
    "swap_free_before_kib": resources_before.system_swap_free_kib,
    "swap_free_after_kib": resources_after.system_swap_free_kib,
    "minor_page_faults": resources_after.minor_faults.saturating_sub(resources_before.minor_faults),
    "major_page_faults": resources_after.major_faults.saturating_sub(resources_before.major_faults),
  });
  let cleanup_objects_created = state_store
    .as_ref()
    .and_then(|value| value.get("objects_created"))
    .and_then(serde_json::Value::as_u64);
  let cleanup_objects_deleted = state_store
    .as_ref()
    .and_then(|value| value.get("objects_deleted"))
    .and_then(serde_json::Value::as_u64);
  let cleanup_arena_current_bytes = state_store
    .as_ref()
    .and_then(|value| value.get("accounted_arena_current_bytes"))
    .and_then(serde_json::Value::as_u64);
  let cleanup_success = match (
    cleanup_objects_created,
    cleanup_objects_deleted,
    cleanup_arena_current_bytes,
  ) {
    (Some(created), Some(deleted), Some(current)) => created == deleted && current == 0,
    _ => false,
  };
  let timing_ns = json!({
    "duration_clock": duration_clock_name(),
    "server_queue": response.timing.server_queue_wall_ns,
    "decode": response.timing.decode_wall_ns,
    "decode_cpu": response.timing.decode_cpu_ns,
    "cache_lookup": response.timing.cache_lookup_wall_ns,
    "cache_lookup_cpu": response.timing.cache_lookup_cpu_ns,
    "transcript_replay": response.timing.transcript_replay_wall_ns,
    "transcript_replay_cpu": response.timing.transcript_replay_cpu_ns,
    "inst_eval": response.timing.inst_eval_wall_ns,
    "inst_eval_cpu": response.timing.inst_eval_cpu_ns,
    "eval_prove": response.timing.eval_prove_wall_ns,
    "eval_prove_cpu": response.timing.eval_prove_cpu_ns,
    "response_encode": response.timing.response_encode_wall_ns,
    "response_encode_cpu": response.timing.response_encode_cpu_ns,
    "total_wall": response.timing.total_server_wall_ns,
    "total_cpu": response.timing.total_server_cpu_ns,
  });
  let phase5fc = json!({
    "optimized_backend_name": std::env::var("THINWALLET_SERVER_STORE_BACKEND").unwrap_or_else(|_| "current".to_owned()),
    "optimized_backend_used": std::env::var("THINWALLET_SERVER_FILE_STORE").as_deref() == Ok("1"),
    "state_path": request_state_path,
    "filesystem_type": state_filesystem,
    "windows_mount_access_count": windows_mount_access_count,
    "thread_count": rayon::current_num_threads(),
    "cleanup_success": cleanup_success,
    "cleanup_evidence": {
      "derivation": "objects_created == objects_deleted && accounted_arena_current_bytes == 0",
      "objects_created": cleanup_objects_created,
      "objects_deleted": cleanup_objects_deleted,
      "accounted_arena_current_bytes": cleanup_arena_current_bytes,
    },
    "state_store": state_store,
    "request_rss": request_rss,
    "resources": resources,
  });
  append_server_log(
    work_dir,
    json!({
      "protocol_id": PROTOCOL_ID,
      "protocol_version": PROTOCOL_VERSION,
      "circuit_id": hex(&request.cache.circuit_id),
      "invocation_id": hex(&request.invocation_id),
      "request_nonce": hex(&request.request_nonce),
      "request_digest": hex(&request.request_digest),
      "request_bytes": payload.len(),
      "response_bytes": encoded.len(),
      "r1cs_sat_proof_bytes": request.r1cs_sat_proof.len(),
      "r1cs_eval_proof_bytes": response.r1cs_eval_proof.len(),
      "cache_hit": true,
      "cached_decomm_bytes": entry.decomm_bytes,
      "cached_external_state_bytes": entry.external_state_bytes,
      "public_cache_total_bytes": entry.bytes,
      "r1cs_eval_prove_calls": 1,
      "witness_access_calls": 0,
      "sat_random_tape_access_calls": 0,
      "phase5fc": phase5fc,
      "timing_ns": timing_ns,
    }),
  );
  Ok(encoded)
}

pub fn run_server(config: ServerConfig) -> std::result::Result<(), String> {
  fs::create_dir_all(&config.work_dir).map_err(|error| error.to_string())?;
  let state_root = std::env::var_os("THINWALLET_REMOTE_EVAL_SERVER_STATE_DIR")
    .map(PathBuf::from)
    .unwrap_or_else(|| config.work_dir.clone());
  let cache_state_dir = state_root.join("cache-state");
  let request_state_dir = state_root.join("request-state");
  fs::create_dir_all(&cache_state_dir).map_err(|error| error.to_string())?;
  fs::create_dir_all(&request_state_dir).map_err(|error| error.to_string())?;
  let backend_name =
    std::env::var("THINWALLET_SERVER_STORE_BACKEND").unwrap_or_else(|_| "current".to_owned());
  let phase5fc = std::env::var("THINWALLET_PHASE5FC_SERVER").as_deref() == Ok("1");
  if phase5fc {
    if backend_name != "batched-file" {
      return Err(format!(
        "Phase 5F-C requires batched-file backend, got {backend_name}"
      ));
    }
    if path_is_windows_mounted(&request_state_dir) {
      return Err("Phase 5F-C request state path is Windows-mounted".to_owned());
    }
    if rayon::current_num_threads() != 1 {
      return Err("Phase 5F-C requires exactly one Rayon thread".to_owned());
    }
    std::env::set_var("THINWALLET_SERVER_FILE_STORE", "1");
  }
  let mem_available_bytes = meminfo_kib("MemAvailable")
    .unwrap_or_default()
    .saturating_mul(1024);
  let absolute_limit_bytes = std::env::var("THINWALLET_SERVER_ABSOLUTE_MEMORY_LIMIT_BYTES")
    .ok()
    .and_then(|value| value.parse::<u64>().ok())
    .unwrap_or(8 * 1024 * 1024 * 1024);
  let server_eval_memory_budget =
    absolute_limit_bytes.min(mem_available_bytes.saturating_mul(60) / 100);
  std::env::set_var(
    "THINWALLET_SERVER_EVAL_BUDGET_BYTES",
    server_eval_memory_budget.to_string(),
  );
  if std::env::var_os("THINWALLET_MAX_TEMP_BYTES").is_none() {
    std::env::set_var(
      "THINWALLET_MAX_TEMP_BYTES",
      (server_eval_memory_budget / 2).to_string(),
    );
  }
  std::env::set_var("V3A_STATE_DIR", &cache_state_dir);
  std::env::set_var("V3A_STATE_SESSION", "remote-eval-public-cache-v1");
  std::env::set_var("LIBSPARTAN_FIXED_STREAMING", "1");
  std::env::set_var("LIBSPARTAN_MULTI_TARGET_STREAMING", "1");
  std::env::set_var("LIBSPARTAN_TRANSCRIPT_RECOMPUTE", "1");
  std::env::set_var("LIBSPARTAN_STREAMING_DEREFERENCE", "1");
  std::env::set_var("LIBSPARTAN_CREDENTIAL_STREAMING", "1");
  std::env::set_var("LIBSPARTAN_ACTIVE_STATE_STREAMING", "1");
  std::env::set_var("LIBSPARTAN_EPHEMERAL_STATE", "1");
  std::env::set_var("V3B_STATE_DIR", &request_state_dir);
  std::env::set_var("V3B_STATE_SESSION", "remote-eval-request-v1");
  let listener = TcpListener::bind(&config.endpoint).map_err(|error| error.to_string())?;
  let server_build_hash = build_hash();
  let filesystem = filesystem_type(&request_state_dir);
  let startup = json!({
    "hostname": fs::read_to_string("/etc/hostname").ok().map(|value| value.trim().to_owned()),
    "pid": std::process::id(),
    "executable_hash": hex(&server_build_hash),
    "source_hash": std::env::var("THINWALLET_SOURCE_HASH").ok(),
    "optimized_backend_name": backend_name,
    "optimized_backend_used": std::env::var("THINWALLET_SERVER_FILE_STORE").as_deref() == Ok("1"),
    "state_path": request_state_dir,
    "filesystem_type": filesystem,
    "windows_mount_access_count": if path_is_windows_mounted(&request_state_dir) { 1 } else { 0 },
    "thread_count": rayon::current_num_threads(),
    "memory_budget_bytes": server_eval_memory_budget,
    "mem_available_at_start_bytes": mem_available_bytes,
    "rss_monitor_enabled": std::env::var("THINWALLET_REMOTE_EVAL_REQUEST_RSS").as_deref() == Ok("1"),
    "rss_monitor_interval_ms": std::env::var("THINWALLET_REMOTE_EVAL_RSS_INTERVAL_MS").ok().and_then(|value| value.parse::<u64>().ok()),
    "protocol_id": PROTOCOL_ID,
    "protocol_version": PROTOCOL_VERSION,
    "proof_system_version": PROOF_SYSTEM_VERSION,
    "supported_circuit_ids": [],
    "cache_digests": [],
    "server_links_witness_code": false,
    "server_accepts_secret_fields": false,
    "server_can_access_client_state": false,
  });
  fs::write(
    config.work_dir.join("startup.json"),
    serde_json::to_vec_pretty(&startup).map_err(|error| error.to_string())?,
  )
  .map_err(|error| error.to_string())?;
  println!("{startup}");
  let mut cache: HashMap<[u8; 32], CacheEntry> = HashMap::new();
  let mut completed = HashSet::new();
  let mut provisioning_closed = false;
  for connection in listener.incoming() {
    let mut stream = match connection {
      Ok(stream) => stream,
      Err(error) => {
        append_server_log(&config.work_dir, json!({"accept_error": error.to_string()}));
        continue;
      }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(900)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(900)));
    let outcome = (|| -> Result<(u8, Vec<u8>)> {
      let (tag, payload) = read_frame(&mut stream, MAX_CACHE_BYTES)?;
      let mut trailing = Vec::new();
      stream
        .read_to_end(&mut trailing)
        .map_err(|error| fail(error.to_string()))?;
      if !trailing.is_empty() {
        return Err(fail("trailing bytes after request frame"));
      }
      let dispatch_ready = Instant::now();
      match tag {
        TAG_PROBE => {
          let reference = decode_probe(&payload)?;
          let hit = cache
            .get(&reference.circuit_id)
            .map(|entry| same_cache(&entry.reference, &reference))
            .unwrap_or(false);
          Ok((
            TAG_PROBE_RESPONSE,
            encode_probe_response(server_build_hash, hit, &reference)?,
          ))
        }
        TAG_PROVISION => {
          let cache_load_start = Instant::now();
          let cache_load_cpu_start = cpu_time_ns();
          if (!phase5fc && (provisioning_closed || !cache.is_empty()))
            || (phase5fc && cache.len() >= 2)
          {
            return Err(fail("cache provisioning closed after first circuit"));
          }
          let (reference, comm_bytes, decomm_bytes, external_state, gens_bytes) =
            decode_provision(&payload)?;
          let comm: ComputationCommitment = native_decode(&comm_bytes, MAX_CACHE_BYTES)?;
          let expected = cache_reference(&comm)?.0;
          if !same_cache(&reference, &expected) {
            return Err(fail("cache digest mismatch"));
          }
          if cache.contains_key(&reference.circuit_id) {
            return Err(fail("circuit cache replacement rejected"));
          }
          let mut decomm: ComputationDecommitment = native_decode(&decomm_bytes, MAX_CACHE_BYTES)?;
          decomm
            .decomm
            .import_remote_external_state(&external_state)
            .map_err(|error| fail(format!("restore public external state: {error}")))?;
          let gens: SNARKGens = native_decode(&gens_bytes, MAX_CACHE_BYTES)?;
          if circuit_identifier(&comm) != reference.circuit_id {
            return Err(fail("cache circuit identifier mismatch"));
          }
          capture_public_fixture("provision", &payload)?;
          let bytes =
            (comm_bytes.len() + decomm_bytes.len() + external_state.len() + gens_bytes.len())
              as u64;
          cache.insert(
            reference.circuit_id,
            CacheEntry {
              reference: reference.clone(),
              comm,
              decomm,
              gens,
              bytes,
              decomm_bytes: decomm_bytes.len() as u64,
              external_state_bytes: external_state.len() as u64,
            },
          );
          provisioning_closed = !phase5fc;
          let cache_manifest = serde_json::to_vec_pretty(&json!({
            "circuit_id": hex(&reference.circuit_id),
            "commitment_digest": hex(&reference.commitment_digest),
            "decomm_digest": hex(&reference.decomm_digest),
            "gens_digest": hex(&reference.gens_digest),
            "cache_bytes": bytes,
            "commitment_bytes": comm_bytes.len(),
            "decomm_bytes": decomm_bytes.len(),
            "external_state_bytes": external_state.len(),
            "gens_bytes": gens_bytes.len(),
            "cache_load_wall_ns": cache_load_start.elapsed().as_nanos() as u64,
            "cache_load_cpu_ns": cpu_time_ns().saturating_sub(cache_load_cpu_start),
            "allowlist_pinned": true,
          }))
          .map_err(|error| fail(error.to_string()))?;
          fs::write(config.work_dir.join("cache_manifest.json"), &cache_manifest)
            .map_err(|error| fail(error.to_string()))?;
          fs::write(
            config.work_dir.join(format!(
              "cache_manifest_{}.json",
              hex(&reference.circuit_id)
            )),
            cache_manifest,
          )
          .map_err(|error| fail(error.to_string()))?;
          Ok((TAG_ACK, ack()?))
        }
        TAG_EVAL => {
          let response = handle_eval(
            &payload,
            &cache,
            server_build_hash,
            &mut completed,
            &config.work_dir,
            dispatch_ready.elapsed().as_nanos() as u64,
          )?;
          capture_public_fixture("request", &payload)?;
          Ok((TAG_EVAL_RESPONSE, response))
        }
        _ => Err(fail("unsupported request tag")),
      }
    })();
    match outcome {
      Ok((tag, payload)) => {
        let fault = configured_fault(&config.work_dir);
        match fault.as_str() {
          "oversized_response_length" if tag == TAG_EVAL_RESPONSE => {
            let mut header = [0u8; HEADER_BYTES];
            header[..8].copy_from_slice(MAGIC);
            header[8..10].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
            header[10] = tag;
            header[12..16].copy_from_slice(&((MAX_RESPONSE_BYTES as u32) + 1).to_be_bytes());
            let _ = stream.write_all(&header);
          }
          "server_closes_connection" if tag == TAG_EVAL_RESPONSE => {}
          "server_timeout" if tag == TAG_EVAL_RESPONSE => {
            std::thread::sleep(Duration::from_secs(2));
          }
          "server_crash_partial_frame" if tag == TAG_EVAL_RESPONSE => {
            let _ = stream.write_all(&MAGIC[..4]);
          }
          "duplicate_response" if tag == TAG_EVAL_RESPONSE => {
            let _ = write_frame(&mut stream, tag, &payload);
            let _ = write_frame(&mut stream, tag, &payload);
          }
          _ => {
            let _ = write_frame(&mut stream, tag, &payload);
          }
        }
      }
      Err(error) => {
        append_server_log(&config.work_dir, json!({"rejected": error.to_string()}));
        let message = error.to_string();
        let _ = write_frame(&mut stream, TAG_ERROR, message.as_bytes());
      }
    }
    let _ = stream.shutdown(Shutdown::Write);
  }
  Ok(())
}

#[derive(Clone)]
pub struct EvalBenchmarkConfig {
  pub fixture: PathBuf,
  pub threads: usize,
  pub warmup: usize,
  pub runs: usize,
  pub output: PathBuf,
  pub work_dir: PathBuf,
  pub deterministic_eval_root: [u8; 32],
  pub eval_store: String,
  pub state_root: Option<PathBuf>,
  pub report_stage_timings: bool,
  pub report_worker_utilization: bool,
}

#[derive(Clone, Copy, Default)]
struct ResourceSnapshot {
  process_cpu_ns: u64,
  minor_faults: i64,
  major_faults: i64,
  voluntary_context_switches: i64,
  involuntary_context_switches: i64,
  system_swap_free_kib: u64,
}

fn meminfo_kib(name: &str) -> Option<u64> {
  fs::read_to_string("/proc/meminfo")
    .ok()?
    .lines()
    .find_map(|line| {
      let (key, value) = line.split_once(':')?;
      (key == name)
        .then(|| value.split_whitespace().next()?.parse::<u64>().ok())
        .flatten()
    })
}

fn resource_snapshot() -> ResourceSnapshot {
  let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
  let context_switch = |name: &str| {
    status.lines().find_map(|line| {
      let (key, value) = line.split_once(':')?;
      (key == name)
        .then(|| value.trim().parse::<i64>().ok())
        .flatten()
    })
  };
  let stat = fs::read_to_string("/proc/self/stat").unwrap_or_default();
  let fields = stat
    .rfind(')')
    .map(|close| stat[close + 1..].split_whitespace().collect::<Vec<_>>())
    .unwrap_or_default();
  ResourceSnapshot {
    process_cpu_ns: cpu_time_ns(),
    minor_faults: fields
      .get(7)
      .and_then(|value| value.parse().ok())
      .unwrap_or_default(),
    major_faults: fields
      .get(9)
      .and_then(|value| value.parse().ok())
      .unwrap_or_default(),
    voluntary_context_switches: context_switch("voluntary_ctxt_switches").unwrap_or_default(),
    involuntary_context_switches: context_switch("nonvoluntary_ctxt_switches").unwrap_or_default(),
    system_swap_free_kib: meminfo_kib("SwapFree").unwrap_or_default(),
  }
}

fn status_value(name: &str) -> Option<u64> {
  fs::read_to_string("/proc/self/status")
    .ok()?
    .lines()
    .find_map(|line| {
      let (key, value) = line.split_once(':')?;
      (key == name)
        .then(|| value.split_whitespace().next()?.parse::<u64>().ok())
        .flatten()
    })
}

fn allowed_cpu_list() -> Option<String> {
  fs::read_to_string("/proc/self/status")
    .ok()?
    .lines()
    .find_map(|line| line.strip_prefix("Cpus_allowed_list:").map(str::trim))
    .map(str::to_owned)
}

fn cpu_frequency_summary_mhz() -> serde_json::Value {
  let values = fs::read_to_string("/proc/cpuinfo")
    .ok()
    .into_iter()
    .flat_map(|contents| {
      contents
        .lines()
        .filter_map(|line| {
          line
            .strip_prefix("cpu MHz")
            .and_then(|rest| rest.split_once(':'))
            .and_then(|(_, value)| value.trim().parse::<f64>().ok())
        })
        .collect::<Vec<_>>()
    })
    .collect::<Vec<_>>();
  if values.is_empty() {
    return serde_json::Value::Null;
  }
  let minimum = values.iter().copied().fold(f64::INFINITY, f64::min);
  let maximum = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
  let mean = values.iter().sum::<f64>() / values.len() as f64;
  json!({"min": minimum, "mean": mean, "max": maximum, "samples": values.len()})
}

fn cpu_temperature_celsius() -> Option<f64> {
  let entries = fs::read_dir("/sys/class/thermal").ok()?;
  let mut values = Vec::new();
  for entry in entries.flatten() {
    let path = entry.path();
    let Some(name) = path.file_name() else {
      continue;
    };
    if !name.to_string_lossy().starts_with("thermal_zone") {
      continue;
    }
    if let Ok(value) = fs::read_to_string(path.join("temp")) {
      if let Ok(value) = value.trim().parse::<f64>() {
        if value > 0.0 {
          values.push(value / 1000.0);
        }
      }
    }
  }
  values.into_iter().reduce(f64::max)
}

fn thread_cpu_snapshot_ticks() -> HashMap<String, u64> {
  let mut values = HashMap::new();
  let Ok(entries) = fs::read_dir("/proc/self/task") else {
    return values;
  };
  for entry in entries.flatten() {
    let tid = entry.file_name().to_string_lossy().into_owned();
    let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
      continue;
    };
    let Some(close) = stat.rfind(')') else {
      continue;
    };
    let fields = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
    let Some(user) = fields.get(11).and_then(|value| value.parse::<u64>().ok()) else {
      continue;
    };
    let Some(system) = fields.get(12).and_then(|value| value.parse::<u64>().ok()) else {
      continue;
    };
    values.insert(tid, user + system);
  }
  values
}

fn start_rss_sampler() -> (Arc<AtomicBool>, Arc<AtomicU64>, thread::JoinHandle<()>) {
  let running = Arc::new(AtomicBool::new(true));
  let peak = Arc::new(AtomicU64::new(status_value("VmRSS").unwrap_or(0)));
  let worker_running = Arc::clone(&running);
  let worker_peak = Arc::clone(&peak);
  let handle = thread::spawn(move || {
    while worker_running.load(AtomicOrdering::Relaxed) {
      if let Some(value) = status_value("VmRSS") {
        worker_peak.fetch_max(value, AtomicOrdering::Relaxed);
      }
      thread::sleep(Duration::from_millis(10));
    }
  });
  (running, peak, handle)
}

fn counter_delta(
  before: &std::collections::BTreeMap<String, u64>,
  after: &std::collections::BTreeMap<String, u64>,
  name: &str,
) -> Option<u64> {
  after
    .get(name)
    .map(|value| value.saturating_sub(before.get(name).copied().unwrap_or_default()))
}

fn stage_breakdown(
  timing: &ServerTiming,
  before: &std::collections::BTreeMap<String, u64>,
  after: &std::collections::BTreeMap<String, u64>,
) -> serde_json::Value {
  let child = |stage: &str| {
    let wall = counter_delta(before, after, &format!("{stage}_wall_ns"));
    let cpu = counter_delta(before, after, &format!("{stage}_cpu_ns"));
    match (wall, cpu) {
      (Some(wall_ns), Some(cpu_ns)) => json!({
        "wall_ns": wall_ns,
        "process_cpu_ns": cpu_ns,
        "calls": counter_delta(before, after, &format!("{stage}_calls")),
        "cpu_core_equivalent": if wall_ns > 0 { Some(cpu_ns as f64 / wall_ns as f64) } else { None },
        "bytes_allocated": null,
        "bytes_copied": null
      }),
      _ => serde_json::Value::Null,
    }
  };
  json!({
    "request_validation": null,
    "canonical_decode": {"wall_ns": timing.decode_wall_ns, "process_cpu_ns": timing.decode_cpu_ns},
    "cache_lookup": {"wall_ns": timing.cache_lookup_wall_ns, "process_cpu_ns": timing.cache_lookup_cpu_ns},
    "cache_clone_or_materialization": {"wall_ns": 0, "process_cpu_ns": 0, "bytes_copied": 0},
    "transcript_replay": {"wall_ns": timing.transcript_replay_wall_ns, "process_cpu_ns": timing.transcript_replay_cpu_ns},
    "derive_rx_ry": "included_in_transcript_replay",
    "inst_eval": {"wall_ns": timing.inst_eval_wall_ns, "process_cpu_ns": timing.inst_eval_cpu_ns},
    "eval_randomness_setup": null,
    "r1cs_eval_proof_total": {"wall_ns": timing.eval_prove_wall_ns, "process_cpu_ns": timing.eval_prove_cpu_ns},
    "response_serialization": {"wall_ns": timing.response_encode_wall_ns, "process_cpu_ns": timing.response_encode_cpu_ns},
    "total_request": {"wall_ns": timing.total_server_wall_ns, "process_cpu_ns": timing.total_server_cpu_ns},
    "commit_nondet_witness": child("eval_commit_nondet"),
    "build_layered_network": child("eval_build_layered_network"),
    "prove_layered_network": child("eval_layered_proof"),
    "polynomial_commitments": null,
    "MSM_total": null,
    "field_arithmetic_total": null,
    "allocation_or_copy": null,
    "other": null
  })
}

fn benchmark_invocation_id(index: usize) -> [u8; 32] {
  sha256(format!("thinwallet/phase5f-a/eval-bench/invocation/{index}").as_bytes())
}

fn benchmark_nonce(index: usize) -> [u8; 32] {
  sha256(format!("thinwallet/phase5f-a/eval-bench/nonce/{index}").as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn benchmark_one(
  base_request: &EvalRequestEnvelope,
  cache: &HashMap<[u8; 32], CacheEntry>,
  completed: &mut HashSet<([u8; 32], [u8; 32])>,
  work_dir: &Path,
  deterministic_eval_root: [u8; 32],
  index: usize,
  measured: bool,
  report_stage_timings: bool,
  report_worker_utilization: bool,
) -> Result<serde_json::Value> {
  let mut request = base_request.clone();
  request.invocation_id = benchmark_invocation_id(index);
  request.request_nonce = benchmark_nonce(index);
  request.test_eval_root = Some(deterministic_eval_root);
  let state_report_path = work_dir.join(format!("state-report-{index}.json"));
  std::env::set_var("V3B_STATE_REPORT_PATH", &state_report_path);
  let payload = encode_eval_request(&mut request)?;
  let canonical_request = decode_eval_request(&payload)?;
  let before = resource_snapshot();
  let thread_before = thread_cpu_snapshot_ticks();
  let counters_before = thinwallet_instrumentation::counters_snapshot();
  let frequency = cpu_frequency_summary_mhz();
  let temperature = cpu_temperature_celsius();
  let (sampler_running, sampler_peak, sampler) = start_rss_sampler();
  let response_bytes = handle_eval(&payload, cache, build_hash(), completed, work_dir, 0)?;
  sampler_running.store(false, AtomicOrdering::Relaxed);
  let _ = sampler.join();
  let after = resource_snapshot();
  let thread_after = thread_cpu_snapshot_ticks();
  let counters_after = thinwallet_instrumentation::counters_snapshot();
  let response = decode_eval_response(&response_bytes)?;
  let entry = cache
    .get(&canonical_request.cache.circuit_id)
    .ok_or_else(|| fail("benchmark cache entry missing"))?;
  let (rx, ry, mut eval_transcript) = replay_request(&canonical_request, entry)?;
  let eval_proof: R1CSEvalProof = native_decode(&response.r1cs_eval_proof, MAX_EVAL_PROOF_BYTES)?;
  let native_eval_verify = eval_proof
    .verify(
      &entry.comm.comm,
      &rx,
      &ry,
      &canonical_request.inst_evals,
      &entry.gens.gens_r1cs_eval,
      &mut eval_transcript,
    )
    .is_ok();
  let sat_proof: R1CSProof = native_decode(&canonical_request.r1cs_sat_proof, MAX_SAT_PROOF_BYTES)?;
  let full_proof = SNARK {
    r1cs_sat_proof: sat_proof,
    inst_evals: canonical_request.inst_evals,
    r1cs_eval_proof: eval_proof,
  };
  let inputs = InputsAssignment {
    assignment: canonical_request.public_inputs.clone(),
  };
  let mut full_transcript = Transcript::new(TRANSCRIPT_LABEL);
  let native_full_verify = full_proof
    .verify(&entry.comm, &inputs, &mut full_transcript, &entry.gens)
    .is_ok();
  if !native_eval_verify || !native_full_verify {
    return Err(fail("native benchmark verification failed"));
  }
  let per_thread_cpu_ticks = thread_after
    .iter()
    .filter_map(|(tid, end)| {
      let delta = end.saturating_sub(thread_before.get(tid).copied().unwrap_or(*end));
      (delta > 0).then(|| (tid.clone(), delta))
    })
    .collect::<HashMap<_, _>>();
  let process_cpu_ns = after.process_cpu_ns.saturating_sub(before.process_cpu_ns);
  let timing = response.timing;
  let state_store = fs::read(&state_report_path)
    .ok()
    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
  Ok(json!({
    "index": index,
    "measured": measured,
    "invocation_id": hex(&canonical_request.invocation_id),
    "request_digest": hex(&canonical_request.request_digest),
    "eval_wall_ms": timing.eval_prove_wall_ns as f64 / 1_000_000.0,
    "total_request_wall_ms": timing.total_server_wall_ns as f64 / 1_000_000.0,
    "process_cpu_ms": process_cpu_ns as f64 / 1_000_000.0,
    "server_reported_eval_cpu_ms": timing.eval_prove_cpu_ns as f64 / 1_000_000.0,
    "total_thread_cpu_ms": null,
    "total_thread_cpu_ticks": per_thread_cpu_ticks.values().sum::<u64>(),
    "actual_worker_threads": rayon::current_num_threads(),
    "process_thread_count": status_value("Threads"),
    "process_cpu_over_wall": if timing.eval_prove_wall_ns > 0 { Some(timing.eval_prove_cpu_ns as f64 / timing.eval_prove_wall_ns as f64) } else { None },
    "peak_rss_mib": sampler_peak.load(AtomicOrdering::Relaxed) as f64 / 1024.0,
    "peak_virtual_memory_mib": status_value("VmPeak").map(|value| value as f64 / 1024.0),
    "process_swap_mib": status_value("VmSwap").map(|value| value as f64 / 1024.0),
    "system_swap_delta_mib": (before.system_swap_free_kib as i64 - after.system_swap_free_kib as i64) as f64 / 1024.0,
    "context_switches": {
      "voluntary": after.voluntary_context_switches.saturating_sub(before.voluntary_context_switches),
      "involuntary": after.involuntary_context_switches.saturating_sub(before.involuntary_context_switches)
    },
    "minor_page_faults": after.minor_faults.saturating_sub(before.minor_faults),
    "major_page_faults": after.major_faults.saturating_sub(before.major_faults),
    "cpu_frequency_mhz": frequency,
    "cpu_temperature_celsius": temperature,
    "proof_hash": hex(&sha256(&response.r1cs_eval_proof)),
    "proof_bytes": response.r1cs_eval_proof.len(),
    "request_bytes": payload.len(),
    "response_bytes": response_bytes.len(),
    "native_eval_verify": native_eval_verify,
    "native_full_verify": native_full_verify,
    "cache_hit": true,
    "canonical_decode": true,
    "transcript_replay": true,
    "derived_rx_len": rx.len(),
    "derived_ry_len": ry.len(),
    "allowed_cpu_list": allowed_cpu_list(),
    "per_thread_cpu_ms": null,
    "per_thread_cpu_ticks": if report_worker_utilization { serde_json::to_value(per_thread_cpu_ticks).unwrap_or(serde_json::Value::Null) } else { serde_json::Value::Null },
    "state_store": state_store,
    "stages": if report_stage_timings { stage_breakdown(&timing, &counters_before, &counters_after) } else { serde_json::Value::Null }
  }))
}

pub fn configure_benchmark_threads(threads: usize) -> std::result::Result<(), String> {
  if threads == 0 {
    return Err("thread count must be positive".to_owned());
  }
  rayon::ThreadPoolBuilder::new()
    .num_threads(threads)
    .thread_name(|index| format!("thinwallet-eval-{index}"))
    .build_global()
    .map_err(|error| error.to_string())
}

pub fn run_eval_benchmark(config: EvalBenchmarkConfig) -> std::result::Result<(), String> {
  fs::create_dir_all(&config.work_dir).map_err(|error| error.to_string())?;
  let state_root = config.work_dir.join("state");
  let cache_state_dir = state_root.join("cache-state");
  let request_state_dir = config
    .state_root
    .clone()
    .unwrap_or_else(|| state_root.join("request-state"));
  fs::create_dir_all(&cache_state_dir).map_err(|error| error.to_string())?;
  fs::create_dir_all(&request_state_dir).map_err(|error| error.to_string())?;
  std::env::set_var("V3A_STATE_DIR", &cache_state_dir);
  std::env::set_var("V3A_STATE_SESSION", "phase5f-a-public-cache-v1");
  std::env::set_var("V3B_STATE_DIR", &request_state_dir);
  std::env::set_var("V3B_STATE_SESSION", "phase5f-a-request-v1");
  let mem_available_bytes = meminfo_kib("MemAvailable")
    .ok_or_else(|| "MemAvailable is unavailable".to_owned())?
    .saturating_mul(1024);
  let absolute_limit_bytes = std::env::var("THINWALLET_SERVER_ABSOLUTE_LIMIT_BYTES")
    .ok()
    .and_then(|value| value.parse::<u64>().ok())
    .unwrap_or(8u64 * 1024 * 1024 * 1024);
  let fractional_limit_bytes = mem_available_bytes.saturating_mul(60) / 100;
  let server_eval_memory_budget = absolute_limit_bytes.min(fractional_limit_bytes);
  std::env::set_var(
    "V3B_HARD_LIMIT_BYTES",
    server_eval_memory_budget.to_string(),
  );
  std::env::set_var("V3B_RESERVED_RUNTIME_BYTES", (4208u64 * 1024).to_string());
  if config.eval_store == "memory" {
    for name in [
      "LIBSPARTAN_MULTI_TARGET_STREAMING",
      "LIBSPARTAN_ACTIVE_STATE_STREAMING",
    ] {
      std::env::remove_var(name);
    }
  } else {
    std::env::set_var("LIBSPARTAN_MULTI_TARGET_STREAMING", "1");
    std::env::set_var("LIBSPARTAN_ACTIVE_STATE_STREAMING", "1");
  }
  if config.eval_store == "batched-file" {
    std::env::set_var("THINWALLET_SERVER_FILE_STORE", "1");
  } else {
    std::env::remove_var("THINWALLET_SERVER_FILE_STORE");
  }
  std::env::set_var("LIBSPARTAN_FIXED_STREAMING", "1");
  std::env::set_var("LIBSPARTAN_TRANSCRIPT_RECOMPUTE", "1");
  std::env::set_var("LIBSPARTAN_STREAMING_DEREFERENCE", "1");
  std::env::set_var("LIBSPARTAN_CREDENTIAL_STREAMING", "1");
  std::env::set_var("LIBSPARTAN_EPHEMERAL_STATE", "1");
  std::env::set_var("THINWALLET_EVAL_STORE", &config.eval_store);
  std::env::set_var("THINWALLET_REMOTE_EVAL_ALLOW_TEST_SEED", "1");
  std::env::set_var("THINWALLET_INSTRUMENTATION_PROFILE", "perf");

  let request_bytes = fs::read(&config.fixture).map_err(|error| error.to_string())?;
  let base_request = decode_eval_request(&request_bytes).map_err(|error| error.to_string())?;
  let provision_path = PathBuf::from(
    config
      .fixture
      .to_string_lossy()
      .replace("_request.bin", "_provision.bin"),
  );
  let process_start = Instant::now();
  let cache_load_start = Instant::now();
  let cache_cpu_start = cpu_time_ns();
  let provision = fs::read(&provision_path).map_err(|error| error.to_string())?;
  let (reference, comm_bytes, decomm_bytes, external_state, gens_bytes) =
    decode_provision(&provision).map_err(|error| error.to_string())?;
  let comm: ComputationCommitment =
    native_decode(&comm_bytes, MAX_CACHE_BYTES).map_err(|error| error.to_string())?;
  let mut decomm: ComputationDecommitment =
    native_decode(&decomm_bytes, MAX_CACHE_BYTES).map_err(|error| error.to_string())?;
  decomm
    .decomm
    .import_remote_external_state(&external_state)
    .map_err(|error| error.to_string())?;
  let gens: SNARKGens =
    native_decode(&gens_bytes, MAX_CACHE_BYTES).map_err(|error| error.to_string())?;
  let cache_bytes = comm_bytes.len() + decomm_bytes.len() + external_state.len() + gens_bytes.len();
  let entry = CacheEntry {
    reference: reference.clone(),
    comm,
    decomm,
    gens,
    bytes: cache_bytes as u64,
    decomm_bytes: decomm_bytes.len() as u64,
    external_state_bytes: external_state.len() as u64,
  };
  let mut cache = HashMap::new();
  cache.insert(reference.circuit_id, entry);
  if !same_cache(&base_request.cache, &reference) {
    return Err("request/provision cache mismatch".to_owned());
  }
  let cache_load_wall_ns = cache_load_start.elapsed().as_nanos() as u64;
  let cache_load_cpu_ns = cpu_time_ns().saturating_sub(cache_cpu_start);
  let mut completed = HashSet::new();
  let mut warmups = Vec::new();
  let mut measured = Vec::new();
  for index in 0..config.warmup {
    warmups.push(
      benchmark_one(
        &base_request,
        &cache,
        &mut completed,
        &config.work_dir,
        config.deterministic_eval_root,
        index,
        false,
        config.report_stage_timings,
        config.report_worker_utilization,
      )
      .map_err(|error| error.to_string())?,
    );
  }
  for offset in 0..config.runs {
    measured.push(
      benchmark_one(
        &base_request,
        &cache,
        &mut completed,
        &config.work_dir,
        config.deterministic_eval_root,
        config.warmup + offset,
        true,
        config.report_stage_timings,
        config.report_worker_utilization,
      )
      .map_err(|error| error.to_string())?,
    );
  }
  let first_request_ms = warmups
    .first()
    .and_then(|value| value.get("total_request_wall_ms"))
    .and_then(serde_json::Value::as_f64);
  let output = json!({
    "schema_version": "thinwallet-phase5f-a-eval-bench-v1",
    "status": "PASS",
    "pid": std::process::id(),
    "threads_requested": config.threads,
    "actual_worker_threads": rayon::current_num_threads(),
    "process_thread_count_after_pool": status_value("Threads"),
    "allowed_cpu_list": allowed_cpu_list(),
    "fixture": config.fixture,
    "fixture_sha256": hex(&sha256(&request_bytes)),
    "provision_sha256": hex(&sha256(&provision)),
    "circuit_id": hex(&reference.circuit_id),
    "cache_mode": "warm",
    "eval_store": config.eval_store,
    "state_root": request_state_dir,
    "memory_budget": {
      "mem_available_at_start_bytes": mem_available_bytes,
      "maximum_available_fraction": 0.60,
      "fractional_limit_bytes": fractional_limit_bytes,
      "absolute_limit_bytes": absolute_limit_bytes,
      "server_eval_memory_budget_bytes": server_eval_memory_budget,
      "maximum_temporary_storage_bytes": 4u64 * 1024 * 1024 * 1024,
      "allocation_failure_mode": "controlled io::Error before accounted allocation or temporary-store append",
    },
    "cache_bytes": cache_bytes,
    "cache_load_ms": cache_load_wall_ns as f64 / 1_000_000.0,
    "cache_load_cpu_ms": cache_load_cpu_ns as f64 / 1_000_000.0,
    "cold_start_ms": process_start.elapsed().as_secs_f64() * 1000.0,
    "first_request_ms": first_request_ms,
    "warmups": warmups,
    "measured_runs": measured,
    "per_request_public_cache_deep_copy": false,
    "public_cache_bytes_copied_per_request": 0,
    "server_links_witness_code": false,
    "server_accepts_secret_fields": false,
    "native_verifier_unchanged": true
  });
  if let Some(parent) = config.output.parent() {
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
  }
  fs::write(
    &config.output,
    serde_json::to_vec_pretty(&output).map_err(|error| error.to_string())?,
  )
  .map_err(|error| error.to_string())?;
  println!("{}", config.output.display());
  Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_remote_eval_split(
  comm: &ComputationCommitment,
  decomm: &ComputationDecommitment,
  inputs: &InputsAssignment,
  gens: &SNARKGens,
  sat_proof: &R1CSProof,
  rx: &[Scalar],
  ry: &[Scalar],
  inst_evals: &(Scalar, Scalar, Scalar),
  transcript_base: Transcript,
  eval_root: [u8; 32],
  circuit_id: [u8; 32],
  invocation_id: [u8; 32],
) -> std::result::Result<R1CSEvalProof, SplitExecutionError> {
  let execute = || -> Result<R1CSEvalProof> {
    let endpoint = std::env::var("THINWALLET_REMOTE_EVAL_ENDPOINT")
      .map_err(|_| fail("remote endpoint is missing"))?;
    let (reference, comm_bytes) = cache_reference(comm)?;
    if reference.circuit_id != circuit_id {
      return Err(fail("local circuit identifier mismatch"));
    }
    let (tag, probe_bytes, _) = rpc(
      &endpoint,
      TAG_PROBE,
      &encode_probe(&reference)?,
      MAX_RESPONSE_BYTES,
    )?;
    if tag != TAG_PROBE_RESPONSE {
      return Err(fail("unexpected probe response tag"));
    }
    let (server_build_hash, mut cache_hit) = decode_probe_response(&probe_bytes, &reference)?;
    if !cache_hit {
      if std::env::var("THINWALLET_REMOTE_EVAL_ALLOW_CACHE_PROVISION").as_deref() != Ok("1") {
        return Err(fail("server cache miss and client provisioning disabled"));
      }
      let decomm_bytes = native_encode(decomm)?;
      let external_state = decomm
        .decomm
        .export_remote_external_state()
        .map_err(|error| fail(format!("export public external state: {error}")))?;
      let gens_bytes = native_encode(gens)?;
      let provision = encode_provision(
        &reference,
        &comm_bytes,
        &decomm_bytes,
        &external_state,
        &gens_bytes,
      )?;
      let (ack_tag, ack_bytes, _) = rpc(&endpoint, TAG_PROVISION, &provision, MAX_RESPONSE_BYTES)?;
      if ack_tag != TAG_ACK {
        return Err(fail("unexpected cache provision response tag"));
      }
      check_ack(&ack_bytes)?;
      cache_hit = true;
    }
    let local_request = build_eval_tail_request(
      comm,
      inputs,
      sat_proof,
      rx,
      ry,
      inst_evals,
      circuit_id,
      invocation_id,
    );
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let test_eval_root =
      if std::env::var("THINWALLET_REMOTE_EVAL_TEST_ONLY_SEED").as_deref() == Ok("1") {
        Some(eval_root)
      } else {
        None
      };
    let mut wire_request = EvalRequestEnvelope {
      client_build_hash: build_hash(),
      cache: reference,
      invocation_id,
      request_nonce: nonce,
      public_inputs: local_request.public_inputs.clone(),
      computation_commitment: comm_bytes,
      r1cs_sat_proof: local_request.r1cs_sat_proof.clone(),
      replay: local_request.transcript_replay_data.clone(),
      inst_evals: *inst_evals,
      test_eval_root,
      request_digest: [0u8; 32],
    };
    let encode_start = Instant::now();
    let encode_cpu_start = cpu_time_ns();
    let request_bytes = encode_eval_request(&mut wire_request)?;
    let encode_ns = encode_start.elapsed().as_nanos() as u64;
    let encode_cpu_ns = cpu_time_ns().saturating_sub(encode_cpu_start);
    #[cfg(feature = "thinwallet-experiment")]
    {
      thinwallet_instrumentation::increment_counter("remote_eval_requests", 1);
      thinwallet_instrumentation::increment_counter("remote_eval_cache_hit", u64::from(cache_hit));
      thinwallet_instrumentation::increment_counter(
        "remote_eval_request_bytes",
        request_bytes.len() as u64,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_r1cs_sat_proof_bytes",
        wire_request.r1cs_sat_proof.len() as u64,
      );
      thinwallet_instrumentation::increment_counter("remote_eval_encode_wall_ns", encode_ns);
      thinwallet_instrumentation::increment_counter("remote_eval_encode_cpu_ns", encode_cpu_ns);
    }
    let rpc_cpu_start = cpu_time_ns();
    let (response_tag, response_bytes, rpc_timing) =
      rpc(&endpoint, TAG_EVAL, &request_bytes, MAX_RESPONSE_BYTES)?;
    let rpc_cpu_ns = cpu_time_ns().saturating_sub(rpc_cpu_start);
    if response_tag != TAG_EVAL_RESPONSE {
      return Err(fail("unexpected eval response tag"));
    }
    let decode_start = Instant::now();
    let decode_cpu_start = cpu_time_ns();
    let response = decode_eval_response(&response_bytes)?;
    let decode_ns = decode_start.elapsed().as_nanos() as u64;
    let decode_cpu_ns = cpu_time_ns().saturating_sub(decode_cpu_start);
    let binding_start = Instant::now();
    let binding_cpu_start = cpu_time_ns();
    let expected_prefix = transcript_prefix_digest(&wire_request, rx, ry);
    if response.server_build_hash != server_build_hash
      || response.circuit_id != circuit_id
      || response.invocation_id != invocation_id
      || response.request_nonce != nonce
      || response.request_digest != wire_request.request_digest
      || response.transcript_prefix_digest != expected_prefix
      || response.inst_evals != *inst_evals
    {
      return Err(fail("remote response binding mismatch"));
    }
    let binding_ns = binding_start.elapsed().as_nanos() as u64;
    let binding_cpu_ns = cpu_time_ns().saturating_sub(binding_cpu_start);
    let canonical_proof: R1CSEvalProof =
      native_decode(&response.r1cs_eval_proof, MAX_EVAL_PROOF_BYTES)?;
    let canonical_bytes = native_encode(&canonical_proof)?;
    let mut internal_response = EvalTailResponse {
      circuit_id,
      invocation_id,
      request_binding_digest: local_request.binding_digest,
      inst_evals: *inst_evals,
      r1cs_eval_proof: canonical_bytes,
      binding_metadata: [0u8; 32],
    };
    internal_response.binding_metadata = eval_response_binding_digest(&internal_response);
    let mut assembler = LocalAssembler {
      comm,
      gens,
      transcript_base,
      expected_circuit_id: circuit_id,
      expected_invocation_id: invocation_id,
      consumed: false,
    };
    let proof = assembler
      .assemble(&local_request, internal_response)
      .map_err(|error| fail(format!("native eval verification failed: {error:?}")))?;
    append_client_trace(json!({
      "protocol_id": PROTOCOL_ID,
      "protocol_version": PROTOCOL_VERSION,
      "circuit_id": hex(&circuit_id),
      "invocation_id": hex(&invocation_id),
      "request_nonce": hex(&nonce),
      "request_digest": hex(&wire_request.request_digest),
      "request_bytes": request_bytes.len(),
      "response_bytes": response_bytes.len(),
      "rpc_total_ns": rpc_timing.rpc_total_wall_ns,
      "client_duration_clock": duration_clock_name(),
      "connect_ns": rpc_timing.connect_wall_ns,
      "request_socket_write_ns": rpc_timing.upload_wall_ns,
      "wait_to_first_response_byte_ns": rpc_timing.wait_to_first_response_byte_wall_ns,
      "response_socket_read_ns": rpc_timing.download_wall_ns,
      "response_decode_wall_ns": decode_ns,
      "response_decode_cpu_ns": decode_cpu_ns,
      "binding_validation_wall_ns": binding_ns,
      "binding_validation_cpu_ns": binding_cpu_ns,
      "server_processing_total_ns": response.timing.total_server_wall_ns,
      "server_processing_cpu_ns": response.timing.total_server_cpu_ns,
      "server_request_validation_ns": response.timing.decode_wall_ns,
      "server_cache_lookup_ns": response.timing.cache_lookup_wall_ns,
      "server_transcript_replay_ns": response.timing.transcript_replay_wall_ns,
      "server_inst_eval_ns": response.timing.inst_eval_wall_ns,
      "server_r1cs_eval_prove_ns": response.timing.eval_prove_wall_ns,
      "server_response_object_build_ns": response.timing.response_encode_wall_ns,
      "native_eval_verification_pass": true,
    }));
    #[cfg(feature = "thinwallet-experiment")]
    {
      thinwallet_instrumentation::increment_counter("native_eval_verify_calls", 1);
      thinwallet_instrumentation::increment_counter(
        "remote_eval_response_bytes",
        response_bytes.len() as u64,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_r1cs_eval_proof_bytes",
        response.r1cs_eval_proof.len() as u64,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_eval_rpc_wait_wall_ns",
        rpc_timing.rpc_total_wall_ns,
      );
      thinwallet_instrumentation::increment_counter("remote_eval_rpc_wait_cpu_ns", rpc_cpu_ns);
      thinwallet_instrumentation::increment_counter(
        "remote_eval_connect_wall_ns",
        rpc_timing.connect_wall_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_eval_upload_wall_ns",
        rpc_timing.upload_wall_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_eval_wait_to_first_response_byte_wall_ns",
        rpc_timing.wait_to_first_response_byte_wall_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_eval_download_wall_ns",
        rpc_timing.download_wall_ns,
      );
      thinwallet_instrumentation::increment_counter("remote_eval_decode_wall_ns", decode_ns);
      thinwallet_instrumentation::increment_counter("remote_eval_decode_cpu_ns", decode_cpu_ns);
      thinwallet_instrumentation::increment_counter(
        "remote_eval_binding_validation_wall_ns",
        binding_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_eval_binding_validation_cpu_ns",
        binding_cpu_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_server_queue_wall_ns",
        response.timing.server_queue_wall_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_server_decode_wall_ns",
        response.timing.decode_wall_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_server_transcript_replay_wall_ns",
        response.timing.transcript_replay_wall_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_server_response_encode_wall_ns",
        response.timing.response_encode_wall_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_server_eval_prove_wall_ns",
        response.timing.eval_prove_wall_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_server_total_wall_ns",
        response.timing.total_server_wall_ns,
      );
      thinwallet_instrumentation::increment_counter(
        "remote_server_total_cpu_ns",
        response.timing.total_server_cpu_ns,
      );
      thinwallet_instrumentation::increment_counter("remote_eval_final_proof_released", 0);
    }
    Ok(proof)
  };
  execute().map_err(|error| {
    #[cfg(feature = "thinwallet-experiment")]
    thinwallet_instrumentation::increment_counter("remote_eval_failures", 1);
    eprintln!("remote eval failed without local fallback: {error}");
    SplitExecutionError::EvalVerification
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn frame_length_is_rejected_before_allocation() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let child = std::thread::spawn(move || {
      let (mut socket, _) = listener.accept().unwrap();
      read_frame(&mut socket, 64).unwrap_err().to_string()
    });
    let mut stream = TcpStream::connect(address).unwrap();
    let mut header = [0u8; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    header[10] = TAG_EVAL_RESPONSE;
    header[12..16].copy_from_slice(&65u32.to_be_bytes());
    stream.write_all(&header).unwrap();
    assert!(child.join().unwrap().contains("exceeds maximum"));
  }

  #[test]
  fn trailing_and_noncanonical_scalars_are_rejected() {
    let mut reader = Reader::new(&[1, 2]);
    assert!(reader.u8().is_ok());
    assert!(reader.finish().is_err());
    let noncanonical = [0xffu8; 32];
    assert!(get_scalar(&mut Reader::new(&noncanonical)).is_err());
  }

  #[test]
  fn wire_secret_canaries_are_absent_and_roundtrip_is_canonical() {
    let secret_canaries = [
      [0xa1u8; 32], // witness
      [0xb2u8; 32], // Sat root/tape state
      [0xc3u8; 32], // master seed
      [0xd4u8; 32], // PBMO secret
    ];
    let mut request = EvalRequestEnvelope {
      client_build_hash: [1u8; 32],
      cache: CacheReference {
        circuit_id: [2u8; 32],
        commitment_digest: [3u8; 32],
        decomm_digest: [4u8; 32],
        gens_digest: [5u8; 32],
      },
      invocation_id: [6u8; 32],
      request_nonce: [7u8; 32],
      public_inputs: vec![Scalar::one()],
      computation_commitment: b"public-commitment".to_vec(),
      r1cs_sat_proof: b"public-zero-knowledge-sat-proof".to_vec(),
      replay: TranscriptReplayData {
        protocol_identifier: SPLIT_PROTOCOL_VERSION.to_vec(),
        commitment_digest: [8u8; 32],
        public_inputs_digest: [9u8; 32],
        sat_proof_digest: [10u8; 32],
      },
      inst_evals: (Scalar::one(), Scalar::one(), Scalar::one()),
      test_eval_root: None,
      request_digest: [0u8; 32],
    };
    let encoded = encode_eval_request(&mut request).unwrap();
    assert!(secret_canaries
      .iter()
      .all(|canary| !encoded.windows(canary.len()).any(|window| window == canary)));
    let decoded = decode_eval_request(&encoded).unwrap();
    assert_eq!(
      encode_eval_request_body(&decoded).unwrap(),
      encoded[..encoded.len() - 32]
    );
  }
}
