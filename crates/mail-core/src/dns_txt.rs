//! Dependency-free DNS TXT lookup for customer domain verification.
//!
//! Security invariants:
//!
//! - exactly one question (type TXT, class IN) is ever sent, to the
//!   configured resolver address only;
//! - a reply is accepted only when its transaction id, QR flag and source
//!   address match the query that was just sent, so an off-path datagram
//!   cannot stand in for resolver evidence;
//! - every failure path returns a static error message: resolver addresses,
//!   response bytes and I/O causes never leave this module.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use uuid::Uuid;

const DNS_HEADER_LEN: usize = 12;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_MX: u16 = 15;
const DNS_CLASS_IN: u16 = 1;
const MAX_RESPONSE_LEN: usize = 4096;
const MAX_ANSWERS: u16 = 8;
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS query name is invalid")]
    InvalidName,
    #[error("DNS query timed out")]
    Timeout,
    #[error("DNS response was malformed")]
    MalformedResponse,
    #[error("DNS query failed")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct DnsTxtResolver {
    server: SocketAddr,
    timeout: Duration,
}

impl DnsTxtResolver {
    /// Resolver address from `NULLAPART_DNS_RESOLVER` (`host:port`), falling
    /// back to the default public resolver when unset or unusable.
    pub fn from_env() -> Self {
        match std::env::var("NULLAPART_DNS_RESOLVER") {
            Ok(raw) => match Self::parse_server(raw.trim()) {
                Some(server) => Self {
                    server,
                    timeout: DEFAULT_TIMEOUT,
                },
                None => {
                    tracing::warn!(
                        "NULLAPART_DNS_RESOLVER is not a usable host:port; using the default resolver"
                    );
                    Self::default()
                },
            },
            Err(_) => Self::default(),
        }
    }

    /// Explicit resolver for a caller that already resolved its address, such
    /// as the verification tests that run against a local UDP socket.
    pub fn with_server(server: SocketAddr, timeout: Duration) -> Self {
        Self { server, timeout }
    }

    pub async fn lookup(&self, name: &str) -> Result<Vec<String>, DnsError> {
        let query = build_query(name, DNS_TYPE_TXT)?;
        let bind_address = if self.server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind_address).await?;
        socket.send_to(&query, self.server).await?;

        let mut buffer = [0u8; MAX_RESPONSE_LEN];
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(DnsError::Timeout);
            }
            let received =
                match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
                    Ok(Ok((received, from))) => {
                        if from != self.server {
                            continue;
                        }
                        received
                    },
                    Ok(Err(error)) => return Err(DnsError::Io(error)),
                    Err(_) => return Err(DnsError::Timeout),
                };
            return parse_txt_response(&query[..2], &buffer[..received]);
        }
    }

    pub async fn lookup_mx(&self, name: &str) -> Result<Vec<String>, DnsError> {
        let query = build_query(name, DNS_TYPE_MX)?;
        let bind_address = if self.server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind_address).await?;
        socket.send_to(&query, self.server).await?;

        let mut buffer = [0u8; MAX_RESPONSE_LEN];
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(DnsError::Timeout);
            }
            let received =
                match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
                    Ok(Ok((received, from))) => {
                        if from != self.server {
                            continue;
                        }
                        received
                    },
                    Ok(Err(error)) => return Err(DnsError::Io(error)),
                    Err(_) => return Err(DnsError::Timeout),
                };
            return parse_mx_response(&query[..2], &buffer[..received]);
        }
    }

    fn parse_server(raw: &str) -> Option<SocketAddr> {
        if let Ok(address) = raw.parse::<SocketAddr>() {
            return Some(address);
        }
        let (host, port) = raw.rsplit_once(':')?;
        if host.is_empty() {
            return None;
        }
        let port: u16 = port.parse().ok()?;
        (host, port).to_socket_addrs().ok()?.next()
    }
}

impl Default for DnsTxtResolver {
    fn default() -> Self {
        Self {
            server: SocketAddr::from(([1, 1, 1, 1], 53)),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// Verification labels may carry the `_` prefix used by ownership challenges.
fn validate_name(name: &str) -> Result<(), DnsError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(DnsError::InvalidName);
    }
    let mut label_count = 0usize;
    for label in name.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(DnsError::InvalidName);
        }
        let bytes = label.as_bytes();
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
        {
            return Err(DnsError::InvalidName);
        }
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return Err(DnsError::InvalidName);
        }
        label_count += 1;
    }
    if label_count < 2 {
        return Err(DnsError::InvalidName);
    }
    Ok(())
}

fn build_query(name: &str, record_type: u16) -> Result<Vec<u8>, DnsError> {
    validate_name(name)?;
    let identifier = Uuid::new_v4();
    let mut message = Vec::with_capacity(name.len() + 18);
    message.extend_from_slice(&identifier.as_bytes()[..2]);
    // QR=0, opcode=0, AA=0, TC=0, RD=1, RCODE=0
    message.extend_from_slice(&[0x01, 0x00]);
    message.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&record_type.to_be_bytes());
    message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(message)
}

fn parse_txt_response(query_id: &[u8], packet: &[u8]) -> Result<Vec<String>, DnsError> {
    if packet.len() < DNS_HEADER_LEN || packet[..2] != *query_id {
        return Err(DnsError::MalformedResponse);
    }
    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 {
        return Err(DnsError::MalformedResponse);
    }
    if flags & 0x0200 != 0 {
        return Err(DnsError::MalformedResponse);
    }
    let response_code = flags & 0x000F;
    if response_code == 3 {
        return Ok(Vec::new());
    }
    if response_code != 0 {
        return Err(DnsError::MalformedResponse);
    }
    let question_count = read_u16(packet, 4)?;
    let answer_count = read_u16(packet, 6)?;
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..question_count {
        offset = skip_name(packet, offset)?;
        offset = advance(offset, 4, packet)?;
    }
    let mut records = Vec::new();
    for _ in 0..answer_count.min(MAX_ANSWERS) {
        offset = skip_name(packet, offset)?;
        let record_type = read_u16(packet, offset)?;
        let record_class = read_u16(packet, offset + 2)?;
        let data_length = read_u16(packet, offset + 8)? as usize;
        offset = advance(offset, 10, packet)?;
        let end = advance(offset, data_length, packet)?;
        if record_type == DNS_TYPE_TXT && record_class == DNS_CLASS_IN {
            records.push(decode_txt(&packet[offset..end])?);
        }
        offset = end;
    }
    Ok(records)
}

fn parse_mx_response(query_id: &[u8], packet: &[u8]) -> Result<Vec<String>, DnsError> {
    if packet.len() < DNS_HEADER_LEN || packet[..2] != *query_id {
        return Err(DnsError::MalformedResponse);
    }
    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 || flags & 0x0200 != 0 {
        return Err(DnsError::MalformedResponse);
    }
    let response_code = flags & 0x000F;
    if response_code == 3 {
        return Ok(Vec::new());
    }
    if response_code != 0 {
        return Err(DnsError::MalformedResponse);
    }
    let question_count = read_u16(packet, 4)?;
    let answer_count = read_u16(packet, 6)?;
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..question_count {
        offset = skip_name(packet, offset)?;
        offset = advance(offset, 4, packet)?;
    }
    let mut records = Vec::new();
    for _ in 0..answer_count.min(MAX_ANSWERS) {
        offset = skip_name(packet, offset)?;
        let record_type = read_u16(packet, offset)?;
        let record_class = read_u16(packet, offset + 2)?;
        let data_length = read_u16(packet, offset + 8)? as usize;
        offset = advance(offset, 10, packet)?;
        let end = advance(offset, data_length, packet)?;
        if record_type == DNS_TYPE_MX && record_class == DNS_CLASS_IN && data_length >= 3 {
            let exchange = decode_name(packet, offset + 2)?;
            records.push(exchange);
        }
        offset = end;
    }
    Ok(records)
}

/// Steps over a (possibly pointer-terminated) encoded name.
fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    loop {
        let length = *packet.get(offset).ok_or(DnsError::MalformedResponse)?;
        match length & 0xC0 {
            0x00 => {
                if length == 0 {
                    return Ok(offset + 1);
                }
                offset = advance(offset, 1 + length as usize, packet)?;
            },
            0xC0 => {
                packet.get(offset + 1).ok_or(DnsError::MalformedResponse)?;
                return Ok(offset + 2);
            },
            _ => return Err(DnsError::MalformedResponse),
        }
    }
}

fn decode_name(packet: &[u8], mut offset: usize) -> Result<String, DnsError> {
    let mut labels = Vec::new();
    let mut jumps = 0usize;
    loop {
        let length = *packet.get(offset).ok_or(DnsError::MalformedResponse)?;
        match length & 0xC0 {
            0x00 => {
                if length == 0 {
                    break;
                }
                offset += 1;
                let end = advance(offset, length as usize, packet)?;
                let label = std::str::from_utf8(&packet[offset..end])
                    .map_err(|_| DnsError::MalformedResponse)?;
                labels.push(label.to_ascii_lowercase());
                offset = end;
            },
            0xC0 => {
                let pointer_low = *packet.get(offset + 1).ok_or(DnsError::MalformedResponse)?;
                let pointer = (((length as u16 & 0x3F) << 8) | pointer_low as u16) as usize;
                offset = pointer;
                jumps += 1;
                if jumps > 8 {
                    return Err(DnsError::MalformedResponse);
                }
            },
            _ => return Err(DnsError::MalformedResponse),
        }
    }
    if labels.is_empty() {
        return Err(DnsError::MalformedResponse);
    }
    Ok(labels.join("."))
}

fn decode_txt(data: &[u8]) -> Result<String, DnsError> {
    let mut text = String::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        let length = data[cursor] as usize;
        cursor += 1;
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or(DnsError::MalformedResponse)?;
        text.push_str(&String::from_utf8_lossy(&data[cursor..end]));
        cursor = end;
    }
    Ok(text)
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsError> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or(DnsError::MalformedResponse)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn advance(offset: usize, count: usize, packet: &[u8]) -> Result<usize, DnsError> {
    offset
        .checked_add(count)
        .filter(|next| *next <= packet.len())
        .ok_or(DnsError::MalformedResponse)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::net::UdpSocket;

    use super::*;

    fn txt_rdata(chunks: &[&str]) -> Vec<u8> {
        let mut data = Vec::new();
        for chunk in chunks {
            data.push(chunk.len() as u8);
            data.extend_from_slice(chunk.as_bytes());
        }
        data
    }

    fn txt_response(query: &[u8], rdata: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&query[DNS_HEADER_LEN..]);
        response.push(0xC0);
        response.push(0x0C);
        response.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(rdata);
        response
    }

    fn encoded_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in name.split('.') {
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);
        encoded
    }

    fn mx_response(query: &[u8], preference: u16, exchange: &str) -> Vec<u8> {
        let mut rdata = preference.to_be_bytes().to_vec();
        rdata.extend_from_slice(&encoded_name(exchange));
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&query[DNS_HEADER_LEN..]);
        response.push(0xC0);
        response.push(0x0C);
        response.extend_from_slice(&DNS_TYPE_MX.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);
        response
    }

    async fn spawn_responder<F>(reply: F) -> SocketAddr
    where
        F: FnOnce(&[u8]) -> Vec<u8> + Send + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("loopback UDP binds");
        let address = socket.local_addr().expect("bound socket has an address");
        tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            if let Ok((received, from)) = socket.recv_from(&mut buffer).await {
                let response = reply(&buffer[..received]);
                if response.is_empty() {
                    return;
                }
                let _ = socket.send_to(&response, from).await;
            }
        });
        address
    }

    #[test]
    fn verification_query_names_are_accepted_and_invalid_shapes_are_rejected() {
        assert!(validate_name("_nullapart-verify.example.test").is_ok());
        assert!(validate_name("mail.example.test").is_ok());
        assert!(validate_name("xn--bcher-kva.example.test").is_ok());

        let long_label = "a".repeat(64) + ".example.test";
        let long_name = "a.".repeat(130) + "test";
        for invalid in [
            "",
            "single",
            ".example.test",
            "example.test.",
            "mail..example.test",
            "-mail.example.test",
            "mail-.example.test",
            "mail example.test",
            "mail!.example.test",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(
                matches!(validate_name(invalid), Err(DnsError::InvalidName)),
                "{invalid} must be rejected"
            );
        }
    }

    #[test]
    fn query_message_asks_one_txt_question() {
        let message =
            build_query("mail.example.test", DNS_TYPE_TXT).expect("valid name builds a query");
        assert_eq!(message[2], 0x01);
        assert_eq!(message[3], 0x00);
        assert_eq!(read_u16(&message, 4).expect("qdcount reads"), 1);
        assert_eq!(read_u16(&message, 6).expect("ancount reads"), 0);
        assert_eq!(
            &message[message.len() - 4..],
            &[0x00, DNS_TYPE_TXT as u8, 0x00, DNS_CLASS_IN as u8]
        );
    }

    #[test]
    fn unusable_resolver_addresses_fall_back() {
        assert_eq!(
            DnsTxtResolver::parse_server("1.1.1.1:53"),
            Some(SocketAddr::from(([1, 1, 1, 1], 53)))
        );
        assert_eq!(DnsTxtResolver::parse_server("1.1.1.1"), None);
        assert_eq!(DnsTxtResolver::parse_server(""), None);
        assert_eq!(DnsTxtResolver::parse_server(":"), None);
    }

    #[test]
    fn unusable_responses_are_rejected() {
        let query =
            build_query("mail.example.test", DNS_TYPE_TXT).expect("valid name builds a query");
        let identifier = query[..2].to_vec();

        let mut truncated = txt_response(&query, &txt_rdata(&["a"]));
        truncated.truncate(DNS_HEADER_LEN - 1);
        assert!(matches!(
            parse_txt_response(&identifier, &truncated),
            Err(DnsError::MalformedResponse)
        ));

        let mut not_a_response = txt_response(&query, &txt_rdata(&["a"]));
        not_a_response[2] = 0x00;
        assert!(matches!(
            parse_txt_response(&identifier, &not_a_response),
            Err(DnsError::MalformedResponse)
        ));

        let mut truncated_flag = txt_response(&query, &txt_rdata(&["a"]));
        truncated_flag[2] |= 0x02;
        assert!(matches!(
            parse_txt_response(&identifier, &truncated_flag),
            Err(DnsError::MalformedResponse)
        ));

        let mut servfail = txt_response(&query, &txt_rdata(&["a"]));
        servfail[3] = 0x02;
        assert!(matches!(
            parse_txt_response(&identifier, &servfail),
            Err(DnsError::MalformedResponse)
        ));

        let mut nxdomain = txt_response(&query, &[]);
        nxdomain[3] = 0x03;
        assert_eq!(
            parse_txt_response(&identifier, &nxdomain).expect("nxdomain is empty evidence"),
            Vec::<String>::new()
        );

        let mut foreign_identifier = txt_response(&query, &txt_rdata(&["a"]));
        foreign_identifier[0] ^= 0xFF;
        foreign_identifier[1] ^= 0xFF;
        assert!(matches!(
            parse_txt_response(&identifier, &foreign_identifier),
            Err(DnsError::MalformedResponse)
        ));
    }

    #[tokio::test]
    async fn lookup_returns_txt_strings_from_the_configured_resolver() {
        let address =
            spawn_responder(|query| txt_response(query, &txt_rdata(&["nullapart-", "verify=tok"])))
                .await;
        let resolver = DnsTxtResolver::with_server(address, Duration::from_secs(2));
        let records = resolver
            .lookup("_nullapart-verify.example.test")
            .await
            .expect("the local resolver answers");
        assert_eq!(records, vec!["nullapart-verify=tok".to_string()]);
    }

    #[tokio::test]
    async fn lookup_mx_returns_exchange_names_from_the_configured_resolver() {
        let address = spawn_responder(|query| mx_response(query, 10, "mail.example.test")).await;
        let resolver = DnsTxtResolver::with_server(address, Duration::from_secs(2));
        let records = resolver
            .lookup_mx("example.test")
            .await
            .expect("the local resolver answers");
        assert_eq!(records, vec!["mail.example.test".to_string()]);
    }

    #[tokio::test]
    async fn lookup_rejects_a_reply_for_another_identifier() {
        let address = spawn_responder(|query| {
            let mut response = txt_response(query, &txt_rdata(&["nullapart-verify=tok"]));
            response[0] ^= 0xFF;
            response[1] ^= 0xFF;
            response
        })
        .await;
        let resolver = DnsTxtResolver::with_server(address, Duration::from_secs(2));
        let result = resolver.lookup("_nullapart-verify.example.test").await;
        assert!(matches!(result, Err(DnsError::MalformedResponse)));
    }

    #[tokio::test]
    async fn lookup_bounds_a_silent_resolver() {
        let address = spawn_responder(|_| Vec::new()).await;
        let resolver = DnsTxtResolver::with_server(address, Duration::from_millis(100));
        let result = resolver.lookup("_nullapart-verify.example.test").await;
        assert!(matches!(result, Err(DnsError::Timeout)));
    }
}
