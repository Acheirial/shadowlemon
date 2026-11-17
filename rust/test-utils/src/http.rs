//! The small subset of HTTP/1.1 used by the integration helpers.

use sha1::{Digest, Sha1};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt};

/// Build the GET request used by `sockshttpclient`.
pub fn build_get(host: &str, port: u16) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: shadowlemon-test-utils/0.2\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
    )
    .into_bytes()
}

/// Read one request head. Returns `false` when the peer closed the connection
/// before sending any byte, which is the normal end of a keep-alive stream.
pub async fn read_request_head<R>(reader: &mut R) -> Result<bool, String>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .map_err(|error| format!("failed to read HTTP request: {error}"))?;
    if n == 0 {
        return Ok(false);
    }
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|error| format!("failed to read HTTP request header: {error}"))?;
        if n == 0 {
            return Err("HTTP request headers ended prematurely".to_owned());
        }
        if line == "\r\n" || line == "\n" {
            return Ok(true);
        }
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Read a response with a `Content-Length` body. Chunked encoding is not used
/// by the test server and is intentionally unsupported here.
pub async fn read_response<R>(reader: &mut R) -> Result<HttpResponse, String>
where
    R: AsyncBufRead + AsyncRead + Unpin,
{
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .map_err(|error| format!("failed to read HTTP status line: {error}"))?;
    if n == 0 {
        return Err("HTTP response is empty".to_owned());
    }
    let status = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("malformed HTTP status line: {line:?}"))?
        .parse::<u16>()
        .map_err(|_| format!("malformed HTTP status line: {line:?}"))?;

    let mut headers = Vec::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|error| format!("failed to read HTTP header: {error}"))?;
        if n == 0 {
            return Err("HTTP response headers ended prematurely".to_owned());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line
            .trim_end_matches(['\r', '\n'])
            .split_once(':')
            .ok_or_else(|| format!("malformed HTTP header: {line:?}"))?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| {
            value
                .parse::<usize>()
                .map_err(|_| format!("invalid Content-Length: {value:?}"))
        })
        .transpose()?
        .ok_or_else(|| "HTTP response has no Content-Length header".to_owned())?;

    let mut body = vec![0u8; length];
    if length > 0 {
        reader
            .read_exact(&mut body)
            .await
            .map_err(|error| format!("failed to read HTTP response body: {error}"))?;
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

/// Lower-case hexadecimal SHA-1 of a byte slice.
pub fn sha1_hex(data: &[u8]) -> String {
    let digest = Sha1::digest(data);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
