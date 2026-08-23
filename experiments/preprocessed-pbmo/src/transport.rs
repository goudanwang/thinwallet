use crate::{GroupElement, Scalar};
use curve25519_dalek::traits::VartimeMultiscalarMul;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

pub const WIRE_PROTOCOL_VERSION: u16 = 1;
pub const CURVE_IDENTIFIER: &str = "ristretto255/curve25519-dalek-4.1.3";
pub const INTEGRITY_HMAC_SHA256: &str = "hmac-sha256-psk";
const MAGIC: &[u8; 8] = b"TWPBMO1\0";
const FRAME_HEADER_BYTES: usize = 84;
const MAX_FRAME_PAYLOAD: usize = 1 << 20;
const POINT_BYTES: usize = 32;
const SCALAR_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum PbmoTransportError {
    #[error("transport I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport authentication failed")]
    Authentication,
    #[error("transport protocol rejected: {0}")]
    Protocol(String),
    #[error("transport state error: {0}")]
    State(String),
}

pub type Result<T> = std::result::Result<T, PbmoTransportError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransportRequestHeader {
    pub protocol_version: u16,
    pub backend_revision: String,
    pub curve_identifier: String,
    pub basis_digest: [u8; 32],
    pub q: u32,
    pub m: u32,
    pub output_count: u32,
    pub token_session_digest: [u8; 32],
    pub workload_identifier: String,
    pub expected_scalar_count: u64,
    pub request_byte_length: u64,
    pub integrity_mode: String,
    pub nonce_challenge_context: [u8; 32],
    pub expected_chunk_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportChunk {
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub row: u32,
    pub col_start: u32,
    pub col_end: u32,
    pub scalars: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct TransportResponse {
    pub request_digest: [u8; 32],
    pub points: Vec<GroupElement>,
    pub server_validation_ms: f64,
    pub server_queue_ms: f64,
    pub server_msm_ms: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransportMetrics {
    pub transport: String,
    pub endpoint: Option<String>,
    pub connect_ms: f64,
    pub upload_ms: f64,
    pub download_ms: f64,
    pub total_ms: f64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub chunk_count: u32,
    pub client_serialization_buffer_peak_bytes: usize,
    pub socket_send_buffer_bytes: Option<usize>,
    pub socket_receive_buffer_bytes: Option<usize>,
    pub request_digest: Option<String>,
    pub server_validation_ms: Option<f64>,
    pub server_queue_ms: Option<f64>,
    pub server_msm_ms: Option<f64>,
    pub connection_count: u64,
    pub request_frame_count: u64,
    pub response_frame_count: u64,
    pub request_header_bytes: u64,
    pub request_scalar_bytes: u64,
    pub request_authentication_bytes: u64,
    pub response_point_bytes: u64,
    pub response_metadata_bytes: u64,
    pub response_authentication_bytes: u64,
    pub connect_ns: u64,
    pub upload_ns: u64,
    pub server_wait_ns: Option<u64>,
    pub download_ns: u64,
    pub response_decode_ns: u64,
}

pub trait PbmoTransport: Send {
    fn reserve_session(&mut self, session_digest: [u8; 32]) -> Result<()>;
    fn send_request_header(&mut self, header: &TransportRequestHeader) -> Result<()>;
    fn send_masked_chunk(&mut self, chunk: &TransportChunk) -> Result<()>;
    fn finish_request(&mut self) -> Result<[u8; 32]>;
    fn receive_response(&mut self) -> Result<TransportResponse>;
    fn abort_session(&mut self, reason: &str) -> Result<()>;
    fn metrics(&self) -> &TransportMetrics;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum FrameType {
    RequestHeader = 1,
    MaskedChunk = 2,
    FinishRequest = 3,
    ResponseHeader = 4,
    ResponseBody = 5,
    Error = 6,
    Abort = 7,
}

impl TryFrom<u8> for FrameType {
    type Error = PbmoTransportError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::RequestHeader),
            2 => Ok(Self::MaskedChunk),
            3 => Ok(Self::FinishRequest),
            4 => Ok(Self::ResponseHeader),
            5 => Ok(Self::ResponseBody),
            6 => Ok(Self::Error),
            7 => Ok(Self::Abort),
            _ => Err(PbmoTransportError::Protocol("unknown frame type".into())),
        }
    }
}

struct WireFrame {
    frame_type: FrameType,
    sequence: u32,
    session_digest: [u8; 32],
    payload: Vec<u8>,
}

fn tag_frame(
    key: &[u8; 32],
    frame_type: FrameType,
    sequence: u32,
    session_digest: &[u8; 32],
    payload: &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length");
    mac.update(b"thinwallet/pbmo-wire-frame/v1");
    mac.update(MAGIC);
    mac.update(&WIRE_PROTOCOL_VERSION.to_be_bytes());
    mac.update(&[frame_type as u8, 0]);
    mac.update(&sequence.to_be_bytes());
    mac.update(&(payload.len() as u32).to_be_bytes());
    mac.update(session_digest);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn write_frame(
    stream: &mut TcpStream,
    key: &[u8; 32],
    frame_type: FrameType,
    sequence: u32,
    session_digest: [u8; 32],
    payload: &[u8],
) -> Result<usize> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(PbmoTransportError::Protocol("oversized frame".into()));
    }
    let tag = tag_frame(key, frame_type, sequence, &session_digest, payload);
    let mut header = Vec::with_capacity(FRAME_HEADER_BYTES);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&WIRE_PROTOCOL_VERSION.to_be_bytes());
    header.push(frame_type as u8);
    header.push(0);
    header.extend_from_slice(&sequence.to_be_bytes());
    header.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    header.extend_from_slice(&session_digest);
    header.extend_from_slice(&tag);
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(header.len() + payload.len())
}

fn read_frame(stream: &mut TcpStream, key: &[u8; 32]) -> Result<(WireFrame, usize)> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    stream.read_exact(&mut header)?;
    if &header[..8] != MAGIC {
        return Err(PbmoTransportError::Protocol("wrong frame magic".into()));
    }
    if u16::from_be_bytes(header[8..10].try_into().unwrap()) != WIRE_PROTOCOL_VERSION {
        return Err(PbmoTransportError::Protocol(
            "unsupported wire version".into(),
        ));
    }
    let frame_type = FrameType::try_from(header[10])?;
    if header[11] != 0 {
        return Err(PbmoTransportError::Protocol(
            "unsupported frame flags".into(),
        ));
    }
    let sequence = u32::from_be_bytes(header[12..16].try_into().unwrap());
    let payload_len = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(PbmoTransportError::Protocol("oversized frame".into()));
    }
    let mut session_digest = [0u8; 32];
    session_digest.copy_from_slice(&header[20..52]);
    let mut expected_tag = [0u8; 32];
    expected_tag.copy_from_slice(&header[52..84]);
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload)?;
    let actual_tag = tag_frame(key, frame_type, sequence, &session_digest, &payload);
    if actual_tag != expected_tag {
        return Err(PbmoTransportError::Authentication);
    }
    Ok((
        WireFrame {
            frame_type,
            sequence,
            session_digest,
            payload,
        },
        FRAME_HEADER_BYTES + payload_len,
    ))
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len())
        .map_err(|_| PbmoTransportError::Protocol("string too long".into()))?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| PbmoTransportError::Protocol("length overflow".into()))?;
        if end > self.bytes.len() {
            return Err(PbmoTransportError::Protocol("truncated payload".into()));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
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
    fn array32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn string(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| PbmoTransportError::Protocol("invalid UTF-8".into()))
    }
    fn finish(self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PbmoTransportError::Protocol(
                "trailing payload bytes".into(),
            ))
        }
    }
}

fn encode_request_header(header: &TransportRequestHeader) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&header.protocol_version.to_be_bytes());
    put_string(&mut output, &header.backend_revision)?;
    put_string(&mut output, &header.curve_identifier)?;
    output.extend_from_slice(&header.basis_digest);
    output.extend_from_slice(&header.q.to_be_bytes());
    output.extend_from_slice(&header.m.to_be_bytes());
    output.extend_from_slice(&header.output_count.to_be_bytes());
    output.extend_from_slice(&header.token_session_digest);
    put_string(&mut output, &header.workload_identifier)?;
    output.extend_from_slice(&header.expected_scalar_count.to_be_bytes());
    output.extend_from_slice(&header.request_byte_length.to_be_bytes());
    put_string(&mut output, &header.integrity_mode)?;
    output.extend_from_slice(&header.nonce_challenge_context);
    output.extend_from_slice(&header.expected_chunk_count.to_be_bytes());
    Ok(output)
}

fn decode_request_header(bytes: &[u8]) -> Result<TransportRequestHeader> {
    let mut cursor = Cursor::new(bytes);
    let header = TransportRequestHeader {
        protocol_version: cursor.u16()?,
        backend_revision: cursor.string()?,
        curve_identifier: cursor.string()?,
        basis_digest: cursor.array32()?,
        q: cursor.u32()?,
        m: cursor.u32()?,
        output_count: cursor.u32()?,
        token_session_digest: cursor.array32()?,
        workload_identifier: cursor.string()?,
        expected_scalar_count: cursor.u64()?,
        request_byte_length: cursor.u64()?,
        integrity_mode: cursor.string()?,
        nonce_challenge_context: cursor.array32()?,
        expected_chunk_count: cursor.u32()?,
    };
    cursor.finish()?;
    Ok(header)
}

fn encode_chunk(chunk: &TransportChunk) -> Result<Vec<u8>> {
    if chunk.col_end < chunk.col_start
        || chunk.scalars.len() != (chunk.col_end - chunk.col_start) as usize
    {
        return Err(PbmoTransportError::Protocol(
            "malformed chunk dimensions".into(),
        ));
    }
    let mut output = Vec::with_capacity(24 + chunk.scalars.len() * SCALAR_BYTES);
    output.extend_from_slice(&chunk.chunk_index.to_be_bytes());
    output.extend_from_slice(&chunk.total_chunks.to_be_bytes());
    output.extend_from_slice(&chunk.row.to_be_bytes());
    output.extend_from_slice(&chunk.col_start.to_be_bytes());
    output.extend_from_slice(&chunk.col_end.to_be_bytes());
    output.extend_from_slice(&(chunk.scalars.len() as u32).to_be_bytes());
    for scalar in &chunk.scalars {
        output.extend_from_slice(scalar);
    }
    Ok(output)
}

fn decode_chunk(bytes: &[u8]) -> Result<TransportChunk> {
    let mut cursor = Cursor::new(bytes);
    let chunk_index = cursor.u32()?;
    let total_chunks = cursor.u32()?;
    let row = cursor.u32()?;
    let col_start = cursor.u32()?;
    let col_end = cursor.u32()?;
    let scalar_count = cursor.u32()? as usize;
    if scalar_count > MAX_FRAME_PAYLOAD / SCALAR_BYTES {
        return Err(PbmoTransportError::Protocol(
            "oversized scalar chunk".into(),
        ));
    }
    let scalars = (0..scalar_count)
        .map(|_| cursor.array32())
        .collect::<Result<Vec<_>>>()?;
    cursor.finish()?;
    let chunk = TransportChunk {
        chunk_index,
        total_chunks,
        row,
        col_start,
        col_end,
        scalars,
    };
    if chunk.col_end < chunk.col_start
        || chunk.scalars.len() != (chunk.col_end - chunk.col_start) as usize
    {
        return Err(PbmoTransportError::Protocol(
            "malformed chunk dimensions".into(),
        ));
    }
    Ok(chunk)
}

fn request_hasher(header_payload: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"thinwallet/pbmo-wire-request/v1");
    hasher.update((header_payload.len() as u64).to_be_bytes());
    hasher.update(header_payload);
    hasher
}

fn update_request_hasher(hasher: &mut Sha256, chunk_payload: &[u8]) {
    hasher.update((chunk_payload.len() as u64).to_be_bytes());
    hasher.update(chunk_payload);
}

fn finalize_digest(hasher: Sha256) -> [u8; 32] {
    hasher.finalize().into()
}

fn encode_finish(chunk_count: u32, scalar_count: u64, digest: [u8; 32]) -> Vec<u8> {
    let mut output = Vec::with_capacity(44);
    output.extend_from_slice(&chunk_count.to_be_bytes());
    output.extend_from_slice(&scalar_count.to_be_bytes());
    output.extend_from_slice(&digest);
    output
}

fn decode_finish(bytes: &[u8]) -> Result<(u32, u64, [u8; 32])> {
    let mut cursor = Cursor::new(bytes);
    let value = (cursor.u32()?, cursor.u64()?, cursor.array32()?);
    cursor.finish()?;
    Ok(value)
}

fn encode_response_header(
    request_digest: [u8; 32],
    output_count: u32,
    response_len: u64,
    validation_ns: u64,
    queue_ns: u64,
    msm_ns: u64,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&request_digest);
    output.extend_from_slice(&output_count.to_be_bytes());
    output.extend_from_slice(&(POINT_BYTES as u16).to_be_bytes());
    output.extend_from_slice(&response_len.to_be_bytes());
    output.extend_from_slice(&validation_ns.to_be_bytes());
    output.extend_from_slice(&queue_ns.to_be_bytes());
    output.extend_from_slice(&msm_ns.to_be_bytes());
    output
}

fn decode_response_header(bytes: &[u8]) -> Result<([u8; 32], u32, u64, u64, u64, u64)> {
    let mut cursor = Cursor::new(bytes);
    if cursor.u16()? != 0 {
        return Err(PbmoTransportError::Protocol("server status failure".into()));
    }
    let digest = cursor.array32()?;
    let outputs = cursor.u32()?;
    if cursor.u16()? as usize != POINT_BYTES {
        return Err(PbmoTransportError::Protocol(
            "wrong encoded point size".into(),
        ));
    }
    let response_len = cursor.u64()?;
    let validation_ns = cursor.u64()?;
    let queue_ns = cursor.u64()?;
    let msm_ns = cursor.u64()?;
    cursor.finish()?;
    Ok((
        digest,
        outputs,
        response_len,
        validation_ns,
        queue_ns,
        msm_ns,
    ))
}

fn encode_error(message: &str) -> Vec<u8> {
    let bytes = message.as_bytes();
    let len = bytes.len().min(512);
    let mut output = Vec::with_capacity(2 + len);
    output.extend_from_slice(&(len as u16).to_be_bytes());
    output.extend_from_slice(&bytes[..len]);
    output
}

fn decode_error(bytes: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(bytes);
    let len = cursor.u16()? as usize;
    let message = String::from_utf8_lossy(cursor.take(len)?).to_string();
    cursor.finish()?;
    Ok(message)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn socket_buffers(stream: &TcpStream) -> (Option<usize>, Option<usize>) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut send = 0i32;
        let mut receive = 0i32;
        let mut send_len = std::mem::size_of::<i32>() as libc::socklen_t;
        let mut receive_len = send_len;
        let send_status = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &mut send as *mut _ as *mut _,
                &mut send_len,
            )
        };
        let receive_status = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &mut receive as *mut _ as *mut _,
                &mut receive_len,
            )
        };
        return (
            (send_status == 0).then_some(send.max(0) as usize),
            (receive_status == 0).then_some(receive.max(0) as usize),
        );
    }
    #[cfg(not(unix))]
    {
        (None, None)
    }
}

fn configure_bounded_socket_buffers(stream: &TcpStream, bytes: i32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let length = std::mem::size_of::<i32>() as libc::socklen_t;
        let send = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &bytes as *const _ as *const _,
                length,
            )
        };
        let receive = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &bytes as *const _ as *const _,
                length,
            )
        };
        if send != 0 || receive != 0 {
            return Err(PbmoTransportError::Io(std::io::Error::last_os_error()));
        }
    }
    #[cfg(not(unix))]
    let _ = (stream, bytes);
    Ok(())
}

pub struct TcpTransport {
    endpoint: SocketAddr,
    key: [u8; 32],
    connect_timeout: Duration,
    io_timeout: Duration,
    stream: Option<TcpStream>,
    session_digest: Option<[u8; 32]>,
    sequence: u32,
    request_hasher: Option<Sha256>,
    scalar_count: u64,
    metrics: TransportMetrics,
    started: Option<Instant>,
}

impl TcpTransport {
    pub fn new(
        endpoint: SocketAddr,
        key: [u8; 32],
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Self {
        Self {
            endpoint,
            key,
            connect_timeout,
            io_timeout,
            stream: None,
            session_digest: None,
            sequence: 0,
            request_hasher: None,
            scalar_count: 0,
            metrics: TransportMetrics {
                transport: "tcp".into(),
                endpoint: Some(endpoint.to_string()),
                ..TransportMetrics::default()
            },
            started: None,
        }
    }

    fn stream(&mut self) -> Result<&mut TcpStream> {
        self.stream
            .as_mut()
            .ok_or_else(|| PbmoTransportError::State("TCP session not connected".into()))
    }

    fn checkpoint(&self) {
        let Some(path) = std::env::var_os("THINWALLET_PBMO_CLIENT_TRANSPORT_TRACE") else {
            return;
        };
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.metrics) {
            let _ = std::fs::write(path, bytes);
        }
    }
}

impl PbmoTransport for TcpTransport {
    fn reserve_session(&mut self, session_digest: [u8; 32]) -> Result<()> {
        if self.stream.is_some() {
            return Err(PbmoTransportError::State("session already reserved".into()));
        }
        let started = Instant::now();
        let stream = TcpStream::connect_timeout(&self.endpoint, self.connect_timeout)?;
        stream.set_read_timeout(Some(self.io_timeout))?;
        stream.set_write_timeout(Some(self.io_timeout))?;
        stream.set_nodelay(true)?;
        configure_bounded_socket_buffers(&stream, 64 * 1024)?;
        let (send, receive) = socket_buffers(&stream);
        self.metrics.connect_ms = started.elapsed().as_secs_f64() * 1000.0;
        self.metrics.connect_ns = started.elapsed().as_nanos() as u64;
        self.metrics.connection_count += 1;
        self.metrics.socket_send_buffer_bytes = send;
        self.metrics.socket_receive_buffer_bytes = receive;
        self.session_digest = Some(session_digest);
        self.stream = Some(stream);
        self.started = Some(Instant::now());
        self.checkpoint();
        Ok(())
    }

    fn send_request_header(&mut self, header: &TransportRequestHeader) -> Result<()> {
        if Some(header.token_session_digest) != self.session_digest {
            return Err(PbmoTransportError::State(
                "header/session digest mismatch".into(),
            ));
        }
        let payload = encode_request_header(header)?;
        let session_digest = self.session_digest.unwrap();
        let key = self.key;
        let sequence = self.sequence;
        let started = Instant::now();
        let bytes = write_frame(
            self.stream()?,
            &key,
            FrameType::RequestHeader,
            sequence,
            session_digest,
            &payload,
        )?;
        self.metrics.upload_ms += started.elapsed().as_secs_f64() * 1000.0;
        self.metrics.upload_ns = self
            .metrics
            .upload_ns
            .saturating_add(started.elapsed().as_nanos() as u64);
        self.metrics.request_bytes += bytes as u64;
        self.metrics.request_frame_count += 1;
        self.metrics.request_header_bytes += (FRAME_HEADER_BYTES - 32 + payload.len()) as u64;
        self.metrics.request_authentication_bytes += 32;
        self.metrics.client_serialization_buffer_peak_bytes = self
            .metrics
            .client_serialization_buffer_peak_bytes
            .max(payload.len());
        self.sequence += 1;
        self.request_hasher = Some(request_hasher(&payload));
        self.checkpoint();
        Ok(())
    }

    fn send_masked_chunk(&mut self, chunk: &TransportChunk) -> Result<()> {
        let payload = encode_chunk(chunk)?;
        let session_digest = self
            .session_digest
            .ok_or_else(|| PbmoTransportError::State("session not reserved".into()))?;
        let key = self.key;
        let sequence = self.sequence;
        let started = Instant::now();
        let bytes = write_frame(
            self.stream()?,
            &key,
            FrameType::MaskedChunk,
            sequence,
            session_digest,
            &payload,
        )?;
        self.metrics.upload_ms += started.elapsed().as_secs_f64() * 1000.0;
        self.metrics.upload_ns = self
            .metrics
            .upload_ns
            .saturating_add(started.elapsed().as_nanos() as u64);
        self.metrics.request_bytes += bytes as u64;
        self.metrics.request_frame_count += 1;
        self.metrics.request_header_bytes += (FRAME_HEADER_BYTES - 32 + 24) as u64;
        self.metrics.request_scalar_bytes += (chunk.scalars.len() * SCALAR_BYTES) as u64;
        self.metrics.request_authentication_bytes += 32;
        self.metrics.client_serialization_buffer_peak_bytes = self
            .metrics
            .client_serialization_buffer_peak_bytes
            .max(payload.len());
        self.metrics.chunk_count += 1;
        self.scalar_count += chunk.scalars.len() as u64;
        self.sequence += 1;
        update_request_hasher(
            self.request_hasher
                .as_mut()
                .ok_or_else(|| PbmoTransportError::State("header not sent".into()))?,
            &payload,
        );
        self.checkpoint();
        Ok(())
    }

    fn finish_request(&mut self) -> Result<[u8; 32]> {
        let digest = finalize_digest(
            self.request_hasher
                .take()
                .ok_or_else(|| PbmoTransportError::State("header not sent".into()))?,
        );
        let payload = encode_finish(self.metrics.chunk_count, self.scalar_count, digest);
        let session_digest = self.session_digest.unwrap();
        let key = self.key;
        let sequence = self.sequence;
        let started = Instant::now();
        let bytes = write_frame(
            self.stream()?,
            &key,
            FrameType::FinishRequest,
            sequence,
            session_digest,
            &payload,
        )?;
        self.metrics.upload_ms += started.elapsed().as_secs_f64() * 1000.0;
        self.metrics.upload_ns = self
            .metrics
            .upload_ns
            .saturating_add(started.elapsed().as_nanos() as u64);
        self.metrics.request_bytes += bytes as u64;
        self.metrics.request_frame_count += 1;
        self.metrics.request_header_bytes += (FRAME_HEADER_BYTES - 32 + payload.len()) as u64;
        self.metrics.request_authentication_bytes += 32;
        self.metrics.request_digest = Some(hex(&digest));
        self.sequence += 1;
        self.checkpoint();
        Ok(digest)
    }

    fn receive_response(&mut self) -> Result<TransportResponse> {
        let session_digest = self.session_digest.unwrap();
        let key = self.key;
        let started = Instant::now();
        let (header, header_bytes) = read_frame(self.stream()?, &key)?;
        if header.session_digest != session_digest {
            return Err(PbmoTransportError::Protocol(
                "response for another session".into(),
            ));
        }
        if header.frame_type == FrameType::Error {
            return Err(PbmoTransportError::Protocol(decode_error(&header.payload)?));
        }
        if header.frame_type != FrameType::ResponseHeader {
            return Err(PbmoTransportError::Protocol(
                "expected response header".into(),
            ));
        }
        self.metrics.response_bytes += header_bytes as u64;
        self.metrics.response_frame_count += 1;
        self.metrics.response_metadata_bytes +=
            (FRAME_HEADER_BYTES - 32 + header.payload.len()) as u64;
        self.metrics.response_authentication_bytes += 32;
        self.checkpoint();
        let (request_digest, output_count, response_len, validation_ns, queue_ns, msm_ns) =
            decode_response_header(&header.payload)?;
        if self.metrics.request_digest.as_deref() != Some(&hex(&request_digest)) {
            return Err(PbmoTransportError::Protocol(
                "response request digest mismatch".into(),
            ));
        }
        let (body, body_bytes) = read_frame(self.stream()?, &key)?;
        if body.frame_type != FrameType::ResponseBody || body.session_digest != session_digest {
            return Err(PbmoTransportError::Protocol(
                "malformed response body".into(),
            ));
        }
        if body.payload.len() as u64 != response_len
            || body.payload.len() != output_count as usize * POINT_BYTES
        {
            return Err(PbmoTransportError::Protocol(
                "response length mismatch".into(),
            ));
        }
        #[cfg(feature = "thinwallet-experiment")]
        let decode_phase = thinwallet_instrumentation::PhaseGuard::begin("pbmo_response_decode");
        let decode_started = Instant::now();
        let mut points = Vec::with_capacity(output_count as usize);
        for bytes in body.payload.chunks_exact(POINT_BYTES) {
            let compressed =
                curve25519_dalek::ristretto::CompressedRistretto(bytes.try_into().unwrap());
            points.push(
                compressed.decompress().ok_or_else(|| {
                    PbmoTransportError::Protocol("malformed response point".into())
                })?,
            );
        }
        self.metrics.response_decode_ns = decode_started.elapsed().as_nanos() as u64;
        #[cfg(feature = "thinwallet-experiment")]
        drop(decode_phase);
        self.metrics.download_ms += started.elapsed().as_secs_f64() * 1000.0;
        self.metrics.download_ns = self
            .metrics
            .download_ns
            .saturating_add(started.elapsed().as_nanos() as u64);
        self.metrics.response_bytes += body_bytes as u64;
        self.metrics.response_frame_count += 1;
        self.metrics.response_metadata_bytes += (FRAME_HEADER_BYTES - 32) as u64;
        self.metrics.response_point_bytes += body.payload.len() as u64;
        self.metrics.response_authentication_bytes += 32;
        self.metrics.server_validation_ms = Some(validation_ns as f64 / 1_000_000.0);
        self.metrics.server_queue_ms = Some(queue_ns as f64 / 1_000_000.0);
        self.metrics.server_msm_ms = Some(msm_ns as f64 / 1_000_000.0);
        self.metrics.server_wait_ns = Some(
            validation_ns
                .saturating_add(queue_ns)
                .saturating_add(msm_ns),
        );
        self.metrics.total_ms = self
            .started
            .map(|time| time.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or_default();
        self.checkpoint();
        Ok(TransportResponse {
            request_digest,
            points,
            server_validation_ms: validation_ns as f64 / 1_000_000.0,
            server_queue_ms: queue_ns as f64 / 1_000_000.0,
            server_msm_ms: msm_ns as f64 / 1_000_000.0,
        })
    }

    fn abort_session(&mut self, reason: &str) -> Result<()> {
        if let (Some(mut stream), Some(session_digest)) = (self.stream.take(), self.session_digest)
        {
            let payload = encode_error(reason);
            let _ = write_frame(
                &mut stream,
                &self.key,
                FrameType::Abort,
                self.sequence,
                session_digest,
                &payload,
            );
            let _ = stream.shutdown(Shutdown::Both);
        }
        self.checkpoint();
        Ok(())
    }

    fn metrics(&self) -> &TransportMetrics {
        &self.metrics
    }
}

pub struct LoopbackTransport {
    bases: Vec<GroupElement>,
    session_digest: Option<[u8; 32]>,
    header: Option<TransportRequestHeader>,
    rows: Vec<Vec<Scalar>>,
    next_col: Vec<usize>,
    next_chunk: u32,
    request_hasher: Option<Sha256>,
    request_digest: Option<[u8; 32]>,
    response: Option<TransportResponse>,
    metrics: TransportMetrics,
    scalar_count: u64,
    started: Option<Instant>,
}

impl LoopbackTransport {
    pub fn new(bases: Vec<GroupElement>) -> Self {
        Self {
            bases,
            session_digest: None,
            header: None,
            rows: Vec::new(),
            next_col: Vec::new(),
            next_chunk: 0,
            request_hasher: None,
            request_digest: None,
            response: None,
            metrics: TransportMetrics {
                transport: "loopback-transport".into(),
                ..TransportMetrics::default()
            },
            scalar_count: 0,
            started: None,
        }
    }
}

impl PbmoTransport for LoopbackTransport {
    fn reserve_session(&mut self, session_digest: [u8; 32]) -> Result<()> {
        self.session_digest = Some(session_digest);
        self.started = Some(Instant::now());
        Ok(())
    }
    fn send_request_header(&mut self, header: &TransportRequestHeader) -> Result<()> {
        validate_header(header, &self.bases, crate::BACKEND_REVISION)?;
        if Some(header.token_session_digest) != self.session_digest {
            return Err(PbmoTransportError::Protocol(
                "session digest mismatch".into(),
            ));
        }
        let payload = encode_request_header(header)?;
        self.metrics.request_bytes += (FRAME_HEADER_BYTES + payload.len()) as u64;
        self.metrics.client_serialization_buffer_peak_bytes = payload.len();
        self.rows = vec![Vec::with_capacity(header.m as usize); header.q as usize];
        self.next_col = vec![0; header.q as usize];
        self.request_hasher = Some(request_hasher(&payload));
        self.header = Some(header.clone());
        Ok(())
    }
    fn send_masked_chunk(&mut self, chunk: &TransportChunk) -> Result<()> {
        let header = self
            .header
            .as_ref()
            .ok_or_else(|| PbmoTransportError::State("header not sent".into()))?;
        validate_chunk(chunk, header, self.next_chunk, &self.next_col)?;
        let payload = encode_chunk(chunk)?;
        let row = chunk.row as usize;
        for bytes in &chunk.scalars {
            self.rows[row].push(
                Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
                    .ok_or_else(|| PbmoTransportError::Protocol("malformed scalar".into()))?,
            );
        }
        self.next_col[row] = chunk.col_end as usize;
        self.next_chunk += 1;
        self.scalar_count += chunk.scalars.len() as u64;
        self.metrics.chunk_count += 1;
        self.metrics.request_bytes += (FRAME_HEADER_BYTES + payload.len()) as u64;
        self.metrics.client_serialization_buffer_peak_bytes = self
            .metrics
            .client_serialization_buffer_peak_bytes
            .max(payload.len());
        update_request_hasher(self.request_hasher.as_mut().unwrap(), &payload);
        Ok(())
    }
    fn finish_request(&mut self) -> Result<[u8; 32]> {
        let header = self.header.as_ref().unwrap();
        validate_complete(header, self.next_chunk, self.scalar_count, &self.next_col)?;
        let digest = finalize_digest(self.request_hasher.take().unwrap());
        self.request_digest = Some(digest);
        self.metrics.request_digest = Some(hex(&digest));
        self.metrics.request_bytes += FRAME_HEADER_BYTES as u64 + 44;
        let msm = Instant::now();
        let points = self
            .rows
            .iter()
            .map(|row| GroupElement::vartime_multiscalar_mul(row, &self.bases))
            .collect::<Vec<_>>();
        let msm_ms = msm.elapsed().as_secs_f64() * 1000.0;
        self.response = Some(TransportResponse {
            request_digest: digest,
            points,
            server_validation_ms: 0.0,
            server_queue_ms: 0.0,
            server_msm_ms: msm_ms,
        });
        self.metrics.server_validation_ms = Some(0.0);
        self.metrics.server_queue_ms = Some(0.0);
        self.metrics.server_msm_ms = Some(msm_ms);
        Ok(digest)
    }
    fn receive_response(&mut self) -> Result<TransportResponse> {
        let response = self
            .response
            .take()
            .ok_or_else(|| PbmoTransportError::State("request not finished".into()))?;
        self.metrics.response_bytes =
            (2 * FRAME_HEADER_BYTES + 74 + response.points.len() * POINT_BYTES) as u64;
        self.metrics.total_ms = self
            .started
            .map(|time| time.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or_default();
        Ok(response)
    }
    fn abort_session(&mut self, _reason: &str) -> Result<()> {
        self.rows.clear();
        Ok(())
    }
    fn metrics(&self) -> &TransportMetrics {
        &self.metrics
    }
}

fn validate_header(
    header: &TransportRequestHeader,
    bases: &[GroupElement],
    expected_backend: &str,
) -> Result<()> {
    if header.protocol_version != WIRE_PROTOCOL_VERSION {
        return Err(PbmoTransportError::Protocol(
            "unsupported protocol version".into(),
        ));
    }
    if header.backend_revision != expected_backend {
        return Err(PbmoTransportError::Protocol(
            "wrong backend revision".into(),
        ));
    }
    if header.curve_identifier != CURVE_IDENTIFIER {
        return Err(PbmoTransportError::Protocol(
            "wrong curve identifier".into(),
        ));
    }
    if header.q == 0
        || header.m == 0
        || header.output_count != header.q
        || header.m as usize != bases.len()
    {
        return Err(PbmoTransportError::Protocol(
            "wrong q/m/output dimensions".into(),
        ));
    }
    if header.basis_digest != crate::basis_digest(bases) {
        return Err(PbmoTransportError::Protocol("wrong basis digest".into()));
    }
    if header.expected_scalar_count != header.q as u64 * header.m as u64 {
        return Err(PbmoTransportError::Protocol(
            "incorrect scalar count".into(),
        ));
    }
    if header.request_byte_length != header.expected_scalar_count * SCALAR_BYTES as u64 {
        return Err(PbmoTransportError::Protocol(
            "incorrect request byte length".into(),
        ));
    }
    if header.expected_chunk_count == 0 || header.integrity_mode != INTEGRITY_HMAC_SHA256 {
        return Err(PbmoTransportError::Protocol(
            "unsupported integrity mode/chunk count".into(),
        ));
    }
    Ok(())
}

fn validate_chunk(
    chunk: &TransportChunk,
    header: &TransportRequestHeader,
    next_chunk: u32,
    next_col: &[usize],
) -> Result<()> {
    if chunk.chunk_index != next_chunk {
        return Err(PbmoTransportError::Protocol(
            "duplicate, missing, or out-of-order chunk".into(),
        ));
    }
    if chunk.total_chunks != header.expected_chunk_count || chunk.row >= header.q {
        return Err(PbmoTransportError::Protocol("wrong chunk binding".into()));
    }
    let row = chunk.row as usize;
    if chunk.col_start as usize != next_col[row]
        || chunk.col_end > header.m
        || chunk.col_end <= chunk.col_start
    {
        return Err(PbmoTransportError::Protocol(
            "out-of-order chunk range".into(),
        ));
    }
    if chunk.scalars.len() != (chunk.col_end - chunk.col_start) as usize {
        return Err(PbmoTransportError::Protocol(
            "chunk scalar count mismatch".into(),
        ));
    }
    Ok(())
}

fn validate_complete(
    header: &TransportRequestHeader,
    chunks: u32,
    scalars: u64,
    next_col: &[usize],
) -> Result<()> {
    if chunks != header.expected_chunk_count
        || scalars != header.expected_scalar_count
        || next_col.iter().any(|value| *value != header.m as usize)
    {
        return Err(PbmoTransportError::Protocol("incomplete request".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConnectionMetrics {
    pub connection_id: u64,
    pub peer_ip_family: String,
    pub connection_accepted_unix_ms: u128,
    pub first_request_byte_after_accept_ms: Option<f64>,
    pub complete_request_received_after_accept_ms: Option<f64>,
    pub request_validation_completed_after_accept_ms: Option<f64>,
    pub msm_started_after_accept_ms: Option<f64>,
    pub msm_completed_after_accept_ms: Option<f64>,
    pub first_response_byte_after_accept_ms: Option<f64>,
    pub final_response_byte_after_accept_ms: Option<f64>,
    pub connection_closed_after_accept_ms: f64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub chunks_received: u32,
    pub scalars_received: u64,
    pub server_receive_buffer_peak_bytes: usize,
    pub msm_started: bool,
    pub msm_completed: bool,
    pub outputs: u32,
    pub request_digest: Option<String>,
    pub session_digest: Option<String>,
    pub status: String,
    pub error: Option<String>,
}

pub fn handle_tcp_connection<F>(
    mut stream: TcpStream,
    key: &[u8; 32],
    connection_id: u64,
    expected_backend: &str,
    mut resolve_bases: F,
) -> ServerConnectionMetrics
where
    F: FnMut(&TransportRequestHeader) -> Result<Vec<GroupElement>>,
{
    let accepted = Instant::now();
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let peer_ip_family = stream
        .peer_addr()
        .map(|addr| if addr.is_ipv4() { "ipv4" } else { "ipv6" }.to_string())
        .unwrap_or_else(|_| "unknown".into());
    let mut record = ServerConnectionMetrics {
        connection_id,
        peer_ip_family,
        connection_accepted_unix_ms: unix_ms,
        first_request_byte_after_accept_ms: None,
        complete_request_received_after_accept_ms: None,
        request_validation_completed_after_accept_ms: None,
        msm_started_after_accept_ms: None,
        msm_completed_after_accept_ms: None,
        first_response_byte_after_accept_ms: None,
        final_response_byte_after_accept_ms: None,
        connection_closed_after_accept_ms: 0.0,
        request_bytes: 0,
        response_bytes: 0,
        chunks_received: 0,
        scalars_received: 0,
        server_receive_buffer_peak_bytes: 0,
        msm_started: false,
        msm_completed: false,
        outputs: 0,
        request_digest: None,
        session_digest: None,
        status: "REJECTED".into(),
        error: None,
    };
    let result = (|| -> Result<()> {
        let (first, bytes) = read_frame(&mut stream, key)?;
        record.first_request_byte_after_accept_ms = Some(accepted.elapsed().as_secs_f64() * 1000.0);
        record.request_bytes += bytes as u64;
        if first.frame_type != FrameType::RequestHeader || first.sequence != 0 {
            return Err(PbmoTransportError::Protocol(
                "expected initial request header".into(),
            ));
        }
        let header = decode_request_header(&first.payload)?;
        if header.token_session_digest != first.session_digest {
            return Err(PbmoTransportError::Protocol(
                "header/session substitution".into(),
            ));
        }
        record.session_digest = Some(hex(&first.session_digest));
        let bases = resolve_bases(&header)?;
        validate_header(&header, &bases, expected_backend)?;
        let mut hasher = request_hasher(&first.payload);
        let mut rows = vec![Vec::<Scalar>::with_capacity(header.m as usize); header.q as usize];
        let mut next_col = vec![0usize; header.q as usize];
        let mut next_chunk = 0u32;
        let mut scalar_count = 0u64;
        loop {
            let (frame, bytes) = read_frame(&mut stream, key)?;
            record.request_bytes += bytes as u64;
            if frame.session_digest != first.session_digest {
                return Err(PbmoTransportError::Protocol(
                    "request-session substitution".into(),
                ));
            }
            match frame.frame_type {
                FrameType::MaskedChunk => {
                    if frame.sequence != next_chunk + 1 {
                        return Err(PbmoTransportError::Protocol(
                            "frame sequence mismatch".into(),
                        ));
                    }
                    let chunk = decode_chunk(&frame.payload)?;
                    validate_chunk(&chunk, &header, next_chunk, &next_col)?;
                    let row = chunk.row as usize;
                    for bytes in &chunk.scalars {
                        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
                            .ok_or_else(|| {
                            PbmoTransportError::Protocol("malformed scalar".into())
                        })?;
                        rows[row].push(scalar);
                    }
                    next_col[row] = chunk.col_end as usize;
                    next_chunk += 1;
                    scalar_count += chunk.scalars.len() as u64;
                    record.chunks_received = next_chunk;
                    record.scalars_received = scalar_count;
                    record.server_receive_buffer_peak_bytes = record
                        .server_receive_buffer_peak_bytes
                        .max(frame.payload.len())
                        .max(scalar_count as usize * SCALAR_BYTES);
                    update_request_hasher(&mut hasher, &frame.payload);
                }
                FrameType::FinishRequest => {
                    if frame.sequence != next_chunk + 1 {
                        return Err(PbmoTransportError::Protocol(
                            "finish sequence mismatch".into(),
                        ));
                    }
                    let (claimed_chunks, claimed_scalars, claimed_digest) =
                        decode_finish(&frame.payload)?;
                    record.complete_request_received_after_accept_ms =
                        Some(accepted.elapsed().as_secs_f64() * 1000.0);
                    let validation_start = Instant::now();
                    validate_complete(&header, next_chunk, scalar_count, &next_col)?;
                    let actual_digest = finalize_digest(hasher);
                    if claimed_chunks != next_chunk
                        || claimed_scalars != scalar_count
                        || claimed_digest != actual_digest
                    {
                        return Err(PbmoTransportError::Protocol(
                            "finish/request digest mismatch".into(),
                        ));
                    }
                    record.request_digest = Some(hex(&actual_digest));
                    record.request_validation_completed_after_accept_ms =
                        Some(accepted.elapsed().as_secs_f64() * 1000.0);
                    server_phase_event("REQUEST_VALIDATED");
                    let queue_start = Instant::now();
                    let queue_ns = queue_start.elapsed().as_nanos() as u64;
                    record.msm_started = true;
                    record.msm_started_after_accept_ms =
                        Some(accepted.elapsed().as_secs_f64() * 1000.0);
                    server_phase_event("MSM_STARTED");
                    let msm_start = Instant::now();
                    let outputs = rows
                        .iter()
                        .map(|row| GroupElement::vartime_multiscalar_mul(row, &bases))
                        .collect::<Vec<_>>();
                    let msm_ns = msm_start.elapsed().as_nanos() as u64;
                    record.msm_completed = true;
                    record.msm_completed_after_accept_ms =
                        Some(accepted.elapsed().as_secs_f64() * 1000.0);
                    record.outputs = outputs.len() as u32;
                    server_phase_event("MSM_COMPLETED");
                    let body = outputs
                        .iter()
                        .flat_map(|point| point.compress().to_bytes())
                        .collect::<Vec<_>>();
                    let validation_ns = validation_start.elapsed().as_nanos() as u64;
                    let response_header = encode_response_header(
                        actual_digest,
                        outputs.len() as u32,
                        body.len() as u64,
                        validation_ns,
                        queue_ns,
                        msm_ns,
                    );
                    record.first_response_byte_after_accept_ms =
                        Some(accepted.elapsed().as_secs_f64() * 1000.0);
                    record.response_bytes += write_frame(
                        &mut stream,
                        key,
                        FrameType::ResponseHeader,
                        0,
                        first.session_digest,
                        &response_header,
                    )? as u64;
                    server_phase_event("RESPONSE_HEADER_SENT");
                    record.response_bytes += write_frame(
                        &mut stream,
                        key,
                        FrameType::ResponseBody,
                        1,
                        first.session_digest,
                        &body,
                    )? as u64;
                    record.final_response_byte_after_accept_ms =
                        Some(accepted.elapsed().as_secs_f64() * 1000.0);
                    record.status = "PASS".into();
                    break;
                }
                FrameType::Abort => {
                    return Err(PbmoTransportError::Protocol(
                        "client aborted session".into(),
                    ))
                }
                _ => {
                    return Err(PbmoTransportError::Protocol(
                        "unexpected request frame".into(),
                    ))
                }
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        record.error = Some(error.to_string());
        let session = record
            .session_digest
            .as_deref()
            .and_then(|value| {
                if value.len() != 64 {
                    return None;
                }
                let mut bytes = [0u8; 32];
                for index in 0..32 {
                    bytes[index] = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
                }
                Some(bytes)
            })
            .unwrap_or([0; 32]);
        let payload = encode_error(record.error.as_deref().unwrap_or("rejected"));
        if let Ok(bytes) = write_frame(&mut stream, key, FrameType::Error, 0, session, &payload) {
            record.response_bytes += bytes as u64;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    record.connection_closed_after_accept_ms = accepted.elapsed().as_secs_f64() * 1000.0;
    record
}

fn server_phase_event(name: &str) {
    if let Some(path) = std::env::var_os("THINWALLET_PBMO_SERVER_EVENT_PATH") {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(file, "{name}");
            let _ = file.sync_all();
        }
    }
    if std::env::var("THINWALLET_PBMO_SERVER_PAUSE_AT").as_deref() == Ok(name) {
        let pause = std::env::var("THINWALLET_PBMO_SERVER_PAUSE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(120_000);
        std::thread::sleep(Duration::from_millis(pause));
    }
}

/// Runs malformed and incomplete requests over real localhost sockets and
/// returns the server's own records, including whether any MSM started.
pub fn run_transport_rejection_suite() -> Vec<ServerConnectionMetrics> {
    let key = [0x51u8; 32];
    let bases = (1..=100)
        .map(|value| {
            Scalar::from(value as u64) * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
        })
        .collect::<Vec<_>>();
    let base_digest = crate::basis_digest(&bases);
    let cases = [
        "disconnect_before_header",
        "disconnect_after_partial_header",
        "disconnect_after_header",
        "disconnect_at_1_percent_upload",
        "disconnect_at_50_percent_upload",
        "disconnect_after_final_chunk_before_finish",
        "malformed_final_frame",
        "unsupported_version",
        "basis_digest_substitution",
        "q_m_substitution",
        "request_session_substitution",
        "duplicated_chunk",
        "reordered_chunk",
        "malformed_scalar",
        "server_authentication_key_mismatch",
    ];
    cases
        .iter()
        .enumerate()
        .map(|(case_index, case)| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("probe bind");
            let endpoint = listener.local_addr().unwrap();
            let server_bases = bases.clone();
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                handle_tcp_connection(
                    stream,
                    &key,
                    case_index as u64 + 1,
                    crate::BACKEND_REVISION,
                    |_| Ok(server_bases.clone()),
                )
            });
            let mut stream = TcpStream::connect(endpoint).expect("probe connect");
            let session = [case_index as u8 + 1; 32];
            if *case == "disconnect_before_header" {
                drop(stream);
                return server.join().unwrap();
            }
            if *case == "disconnect_after_partial_header" {
                stream.write_all(&MAGIC[..4]).unwrap();
                drop(stream);
                return server.join().unwrap();
            }
            let mut header = TransportRequestHeader {
                protocol_version: WIRE_PROTOCOL_VERSION,
                backend_revision: crate::BACKEND_REVISION.into(),
                curve_identifier: CURVE_IDENTIFIER.into(),
                basis_digest: base_digest,
                q: 2,
                m: 100,
                output_count: 2,
                token_session_digest: session,
                workload_identifier: format!("rejection-probe/{case}"),
                expected_scalar_count: 200,
                request_byte_length: 6400,
                integrity_mode: INTEGRITY_HMAC_SHA256.into(),
                nonce_challenge_context: [0x31; 32],
                expected_chunk_count: 100,
            };
            match *case {
                "unsupported_version" => header.protocol_version += 1,
                "basis_digest_substitution" => header.basis_digest[0] ^= 1,
                "q_m_substitution" => header.m = 99,
                _ => {}
            }
            let payload = encode_request_header(&header).unwrap();
            let frame_session = if *case == "request_session_substitution" {
                [0xa5; 32]
            } else {
                session
            };
            let frame_key = if *case == "server_authentication_key_mismatch" {
                [0x52; 32]
            } else {
                key
            };
            let _ = write_frame(
                &mut stream,
                &frame_key,
                FrameType::RequestHeader,
                0,
                frame_session,
                &payload,
            );
            if matches!(
                *case,
                "disconnect_after_header"
                    | "unsupported_version"
                    | "basis_digest_substitution"
                    | "q_m_substitution"
                    | "request_session_substitution"
                    | "server_authentication_key_mismatch"
            ) {
                drop(stream);
                return server.join().unwrap();
            }
            let mut hasher = request_hasher(&payload);
            let send_count = match *case {
                "disconnect_at_1_percent_upload" => 1,
                "disconnect_at_50_percent_upload" => 50,
                "duplicated_chunk" | "reordered_chunk" | "malformed_scalar" => 1,
                _ => 100,
            };
            for index in 0..send_count {
                let logical = if *case == "reordered_chunk" && index == 0 {
                    1
                } else {
                    index
                };
                let row = logical / 50;
                let part = logical % 50;
                let start = part * 2;
                let mut scalars = vec![
                    Scalar::from((logical * 2 + 1) as u64).to_bytes(),
                    Scalar::from((logical * 2 + 2) as u64).to_bytes(),
                ];
                if *case == "malformed_scalar" {
                    scalars[0] = [0xff; 32];
                }
                let chunk = TransportChunk {
                    chunk_index: logical as u32,
                    total_chunks: 100,
                    row: row as u32,
                    col_start: start as u32,
                    col_end: (start + 2) as u32,
                    scalars,
                };
                let chunk_payload = encode_chunk(&chunk).unwrap();
                let _ = write_frame(
                    &mut stream,
                    &key,
                    FrameType::MaskedChunk,
                    index as u32 + 1,
                    session,
                    &chunk_payload,
                );
                update_request_hasher(&mut hasher, &chunk_payload);
                if *case == "duplicated_chunk" {
                    let _ = write_frame(
                        &mut stream,
                        &key,
                        FrameType::MaskedChunk,
                        2,
                        session,
                        &chunk_payload,
                    );
                }
            }
            if matches!(
                *case,
                "disconnect_at_1_percent_upload"
                    | "disconnect_at_50_percent_upload"
                    | "disconnect_after_final_chunk_before_finish"
                    | "duplicated_chunk"
                    | "reordered_chunk"
                    | "malformed_scalar"
            ) {
                drop(stream);
                return server.join().unwrap();
            }
            let digest = finalize_digest(hasher);
            let finish = encode_finish(99, 200, digest);
            let _ = write_frame(
                &mut stream,
                &key,
                FrameType::FinishRequest,
                101,
                session,
                &finish,
            );
            drop(stream);
            server.join().unwrap()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    fn fixture() -> (
        Vec<GroupElement>,
        TransportRequestHeader,
        Vec<TransportChunk>,
    ) {
        let q = 2usize;
        let m = 4usize;
        let bases = (1..=m)
            .map(|value| Scalar::from(value as u64) * RISTRETTO_BASEPOINT_POINT)
            .collect::<Vec<_>>();
        let session = [7u8; 32];
        let header = TransportRequestHeader {
            protocol_version: WIRE_PROTOCOL_VERSION,
            backend_revision: crate::BACKEND_REVISION.into(),
            curve_identifier: CURVE_IDENTIFIER.into(),
            basis_digest: crate::basis_digest(&bases),
            q: q as u32,
            m: m as u32,
            output_count: q as u32,
            token_session_digest: session,
            workload_identifier: "test:v1".into(),
            expected_scalar_count: (q * m) as u64,
            request_byte_length: (q * m * 32) as u64,
            integrity_mode: INTEGRITY_HMAC_SHA256.into(),
            nonce_challenge_context: [8; 32],
            expected_chunk_count: 4,
        };
        let chunks = (0..q)
            .flat_map(|row| {
                (0..2).map(move |part| {
                    let start = part * 2;
                    TransportChunk {
                        chunk_index: (row * 2 + part) as u32,
                        total_chunks: 4,
                        row: row as u32,
                        col_start: start as u32,
                        col_end: (start + 2) as u32,
                        scalars: (start..start + 2)
                            .map(|col| Scalar::from((row * m + col + 1) as u64).to_bytes())
                            .collect(),
                    }
                })
            })
            .collect();
        (bases, header, chunks)
    }

    #[test]
    fn loopback_transport_computes_ordered_outputs() {
        let (bases, header, chunks) = fixture();
        let mut transport = LoopbackTransport::new(bases.clone());
        transport
            .reserve_session(header.token_session_digest)
            .unwrap();
        transport.send_request_header(&header).unwrap();
        for chunk in &chunks {
            transport.send_masked_chunk(chunk).unwrap();
        }
        transport.finish_request().unwrap();
        let response = transport.receive_response().unwrap();
        let expected = (0..2)
            .map(|row| {
                let scalars = (0..4)
                    .map(|col| Scalar::from((row * 4 + col + 1) as u64))
                    .collect::<Vec<_>>();
                GroupElement::vartime_multiscalar_mul(&scalars, &bases)
            })
            .collect::<Vec<_>>();
        assert_eq!(response.points, expected);
    }

    #[test]
    fn loopback_rejects_duplicate_and_malformed_scalar() {
        let (bases, header, mut chunks) = fixture();
        let mut transport = LoopbackTransport::new(bases);
        transport
            .reserve_session(header.token_session_digest)
            .unwrap();
        transport.send_request_header(&header).unwrap();
        transport.send_masked_chunk(&chunks[0]).unwrap();
        assert!(transport.send_masked_chunk(&chunks[0]).is_err());
        chunks[1].scalars[0] = [0xff; 32];
        assert!(
            Option::<Scalar>::from(Scalar::from_canonical_bytes(chunks[1].scalars[0])).is_none()
        );
    }

    #[test]
    fn incomplete_and_malformed_socket_requests_never_start_msm() {
        let records = run_transport_rejection_suite();
        assert_eq!(records.len(), 15);
        assert!(records.iter().all(|record| !record.msm_started));
        assert!(records.iter().all(|record| record.status == "REJECTED"));
    }

    fn bad_response_error(case: &str) -> String {
        let key = [0x61; 32];
        let (bases, header, chunks) = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let expected_session = header.token_session_digest;
        let case_owned = case.to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut finish = None;
            for _ in 0..6 {
                let (frame, _) = read_frame(&mut stream, &key).unwrap();
                if frame.frame_type == FrameType::FinishRequest {
                    finish = Some(decode_finish(&frame.payload).unwrap());
                }
            }
            let request_digest = finish.unwrap().2;
            let session = if case_owned == "response_session_replay" {
                [0xa7; 32]
            } else {
                expected_session
            };
            let response_key = if case_owned == "server_authentication_mismatch" {
                [0x62; 32]
            } else {
                key
            };
            let digest = if case_owned == "response_request_replay" {
                [0xb8; 32]
            } else {
                request_digest
            };
            let response_header = encode_response_header(digest, 2, 64, 1, 2, 3);
            write_frame(
                &mut stream,
                &response_key,
                FrameType::ResponseHeader,
                0,
                session,
                &response_header,
            )
            .unwrap();
            let mut body = vec![0u8; 64];
            if case_owned == "malformed_response_point" {
                body[..32].fill(0xff);
            }
            let _ = write_frame(
                &mut stream,
                &response_key,
                FrameType::ResponseBody,
                1,
                session,
                &body,
            );
        });
        let mut client = TcpTransport::new(
            endpoint,
            key,
            Duration::from_secs(2),
            Duration::from_secs(2),
        );
        client.reserve_session(header.token_session_digest).unwrap();
        client.send_request_header(&header).unwrap();
        for chunk in &chunks {
            client.send_masked_chunk(chunk).unwrap();
        }
        client.finish_request().unwrap();
        let error = client.receive_response().unwrap_err().to_string();
        server.join().unwrap();
        drop(bases);
        error
    }

    #[test]
    fn client_rejects_malformed_and_replayed_responses() {
        assert!(bad_response_error("malformed_response_point").contains("malformed response point"));
        assert!(bad_response_error("response_session_replay").contains("another session"));
        assert!(bad_response_error("response_request_replay").contains("request digest mismatch"));
        assert!(bad_response_error("server_authentication_mismatch").contains("authentication"));
    }
}
