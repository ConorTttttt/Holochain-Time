//! Roughtime (RFC 10049, October 2026) request building and response
//! verification.
//!
//! Holochain zomes cannot open UDP sockets, so a client (UI, CLI or oracle
//! sidecar) performs the exchange and hands the raw request and response
//! packets to a zome. Everything needed to judge them is in the bytes: the
//! long-term key signs a delegation, the delegated key signs a Merkle root, and
//! the request packet is a leaf of that tree. Validators re-run this module on
//! the stored packets and reach the same verdict without trusting the client.
//!
//! Wire format summary (RFC 10049 sections 4-5):
//! - packet = "ROUGHTIM" (u64 LE magic) || u32 LE length || message
//! - message = u32 N || (N-1) u32 offsets || N u32 tags || values,
//!   tags strictly ascending by their little-endian u32 value,
//!   offsets multiples of 4 and non-decreasing.
//! - H(x) = SHA-512(x)[..32]; leaf = H(0x00 || request packet);
//!   node = H(0x01 || left || right).
//! - MIDP: u64 LE Unix seconds; RADI: u32 LE seconds, non-zero; true time lies
//!   in the open interval (MIDP - RADI, MIDP + RADI).

use alloc::format;
use alloc::vec::Vec;

use crate::error::{malformed, Error, Result};
use crate::hash::{h, Hash32};
use crate::interval::TimeInterval;
use crate::verifier::Ed25519Verifier;

/// Little-endian bytes of the packet magic 0x4d49544847554f52.
pub const MAGIC: [u8; 8] = *b"ROUGHTIM";
/// Roughtime version 1 as published in RFC 10049.
pub const VERSION_RFC: u32 = 0x0000_0001;
/// The version used by servers built to the late Internet-Drafts. Identical to
/// version 1 except for the capitalisation of the signature context strings.
pub const VERSION_DRAFT: u32 = 0x8000_000c;
/// Minimum request packet size recommended for UDP (RFC 10049 section 5.1).
pub const MIN_REQUEST_SIZE: usize = 1024;
/// Maximum accepted request packet, including the 12-byte frame.
pub const MAX_REQUEST_PACKET_SIZE: usize = 4 * 1024;
/// Maximum accepted response packet, including the 12-byte frame.
pub const MAX_RESPONSE_PACKET_SIZE: usize = 16 * 1024;
const MAX_MESSAGE_SIZE: usize = MAX_RESPONSE_PACKET_SIZE - 12;

/// Tag constants (RFC 10049 section 12.3), as little-endian u32 values.
/// Each is the tag's ASCII name read as a little-endian u32.
#[allow(missing_docs)]
pub mod tag {
    pub const SIG: u32 = 0x0047_4953;
    pub const VER: u32 = 0x0052_4556;
    pub const SRV: u32 = 0x0056_5253;
    pub const NONC: u32 = 0x434e_4f4e;
    pub const DELE: u32 = 0x454c_4544;
    pub const TYPE: u32 = 0x4550_5954;
    pub const PATH: u32 = 0x4854_4150;
    pub const RADI: u32 = 0x4944_4152;
    pub const PUBK: u32 = 0x4b42_5550;
    pub const MIDP: u32 = 0x5044_494d;
    pub const SREP: u32 = 0x5045_5253;
    pub const VERS: u32 = 0x5352_4556;
    pub const MINT: u32 = 0x544e_494d;
    pub const ROOT: u32 = 0x544f_4f52;
    pub const CERT: u32 = 0x5452_4543;
    pub const MAXT: u32 = 0x5458_414d;
    pub const INDX: u32 = 0x5844_4e49;
    pub const ZZZZ: u32 = 0x5a5a_5a5a;
}

const CTX_SREP_RFC: &[u8] = b"Roughtime v1 response signature\0";
const CTX_DELE_RFC: &[u8] = b"Roughtime v1 delegation signature\0";
const CTX_SREP_DRAFT: &[u8] = b"RoughTime v1 response signature\0";
const CTX_DELE_DRAFT: &[u8] = b"RoughTime v1 delegation signature\0";

const MAX_TAGS: usize = 64;
const MAX_PATH_HASHES: usize = 32;
const MAX_VERSIONS: usize = 32;

fn context_strings(version: u32) -> Result<(&'static [u8], &'static [u8])> {
    match version {
        VERSION_RFC => Ok((CTX_SREP_RFC, CTX_DELE_RFC)),
        VERSION_DRAFT => Ok((CTX_SREP_DRAFT, CTX_DELE_DRAFT)),
        other => Err(Error::UnsupportedVersion(other)),
    }
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn exact_u32(v: &[u8], what: &str) -> Result<u32> {
    if v.len() != 4 {
        return malformed(format!("{what} must be 4 bytes, got {}", v.len()));
    }
    Ok(u32_le(v))
}

fn exact_u64(v: &[u8], what: &str) -> Result<u64> {
    if v.len() != 8 {
        return malformed(format!("{what} must be 8 bytes, got {}", v.len()));
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(v);
    Ok(u64::from_le_bytes(a))
}

fn exact_32<'a>(v: &'a [u8], what: &str) -> Result<&'a [u8; 32]> {
    v.try_into()
        .or_else(|_| malformed(format!("{what} must be 32 bytes, got {}", v.len())))
}

fn exact_64<'a>(v: &'a [u8], what: &str) -> Result<&'a [u8; 64]> {
    v.try_into()
        .or_else(|_| malformed(format!("{what} must be 64 bytes, got {}", v.len())))
}

fn u32_list(v: &[u8], what: &str) -> Result<Vec<u32>> {
    if v.is_empty() || !v.len().is_multiple_of(4) || v.len() / 4 > MAX_VERSIONS {
        return malformed(format!("{what} must hold 1 to {MAX_VERSIONS} u32 values"));
    }
    Ok(v.chunks(4).map(u32_le).collect())
}

/// A parsed Roughtime message: tag/value pairs borrowing from the input.
#[derive(Debug, Clone)]
pub struct Message<'a> {
    tags: Vec<u32>,
    values: Vec<&'a [u8]>,
}

impl<'a> Message<'a> {
    /// Parse a message (not a framed packet), enforcing the RFC's layout rules.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        // Reject oversized nested messages before allocating offset/tag vectors.
        if buf.len() > MAX_MESSAGE_SIZE {
            return malformed("Roughtime message exceeds maximum size");
        }
        if buf.len() < 4 {
            return malformed("message shorter than its tag count");
        }
        let n = u32_le(&buf[0..4]) as usize;
        if n == 0 {
            if buf.len() != 4 {
                return malformed("empty Roughtime message has trailing bytes");
            }
            return Ok(Self {
                tags: Vec::new(),
                values: Vec::new(),
            });
        }
        if n > MAX_TAGS {
            return malformed(format!("message has {n} tags, more than {MAX_TAGS}"));
        }
        let header_len = 8 * n; // 4 (N) + 4*(N-1) offsets + 4*N tags
        if buf.len() < header_len {
            return malformed("message shorter than its header");
        }
        let values_area = &buf[header_len..];

        let mut offsets = Vec::with_capacity(n + 1);
        offsets.push(0usize);
        for i in 0..n - 1 {
            let at = 4 + 4 * i;
            let off = u32_le(&buf[at..at + 4]) as usize;
            if !off.is_multiple_of(4) {
                return malformed("offset is not a multiple of 4");
            }
            if off < *offsets.last().unwrap() || off > values_area.len() {
                return malformed("offsets are not non-decreasing within the message");
            }
            offsets.push(off);
        }
        offsets.push(values_area.len());

        let tags_at = 4 * n;
        let mut tags = Vec::with_capacity(n);
        for i in 0..n {
            let at = tags_at + 4 * i;
            let t = u32_le(&buf[at..at + 4]);
            if let Some(&prev) = tags.last() {
                if t <= prev {
                    return malformed("tags are not strictly ascending");
                }
            }
            tags.push(t);
        }

        let values = (0..n)
            .map(|i| &values_area[offsets[i]..offsets[i + 1]])
            .collect();
        Ok(Self { tags, values })
    }

    /// The value for `tag`, if present.
    pub fn get(&self, tag: u32) -> Option<&'a [u8]> {
        self.tags.binary_search(&tag).ok().map(|i| self.values[i])
    }

    /// The value for `tag`, or a `Malformed` error naming it.
    pub fn require(&self, tag: u32, name: &str) -> Result<&'a [u8]> {
        self.get(tag)
            .ok_or_else(|| Error::Malformed(format!("missing {name} tag")))
    }

    /// Number of tags in the message.
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// True when the message has no tags.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

/// Strip and check the packet framing, returning the inner message bytes.
pub fn unframe(packet: &[u8]) -> Result<&[u8]> {
    if packet.len() > MAX_RESPONSE_PACKET_SIZE {
        return malformed("Roughtime packet exceeds maximum response size");
    }
    if packet.len() < 12 {
        return malformed("packet shorter than its 12-byte frame");
    }
    if packet[0..8] != MAGIC {
        return malformed("packet does not start with ROUGHTIM");
    }
    let len = u32_le(&packet[8..12]) as usize;
    // checked: 12 + u32::MAX wraps on 32-bit targets such as wasm32.
    if Some(packet.len()) != len.checked_add(12) {
        return malformed("packet length field does not match its size");
    }
    Ok(&packet[12..])
}

/// Serialize tag/value pairs into a message. Pairs are sorted by tag; values
/// must have lengths that are multiples of 4 except possibly the last.
pub fn encode_message(mut pairs: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    pairs.sort_by_key(|(t, _)| *t);
    let n = pairs.len();
    let mut out = Vec::new();
    out.extend_from_slice(&(n as u32).to_le_bytes());
    let mut off = 0u32;
    for (_, v) in pairs.iter().take(n.saturating_sub(1)) {
        off += v.len() as u32;
        out.extend_from_slice(&off.to_le_bytes());
    }
    for (t, _) in &pairs {
        out.extend_from_slice(&t.to_le_bytes());
    }
    for (_, v) in &pairs {
        out.extend_from_slice(v);
    }
    out
}

/// Wrap a message in the ROUGHTIM frame.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + message.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&(message.len() as u32).to_le_bytes());
    out.extend_from_slice(message);
    out
}

/// SRV value: H(0xff || long-term public key) (RFC 10049 section 5.1.4).
pub fn srv_commitment(server_public_key: &[u8; 32]) -> Hash32 {
    h(&[&[0xff], server_public_key])
}

/// Build a framed request for `nonce`, offering `versions` (sorted and
/// deduplicated here), optionally naming the server, padded with ZZZZ to the
/// recommended 1024 bytes.
pub fn build_request(nonce: &[u8; 32], versions: &[u32], server: Option<&[u8; 32]>) -> Vec<u8> {
    let mut vers: Vec<u32> = versions.to_vec();
    vers.sort_unstable();
    vers.dedup();
    let ver_bytes: Vec<u8> = vers.iter().flat_map(|v| v.to_le_bytes()).collect();

    let mut pairs = Vec::new();
    pairs.push((tag::VER, ver_bytes));
    if let Some(pk) = server {
        pairs.push((tag::SRV, srv_commitment(pk).to_vec()));
    }
    pairs.push((tag::NONC, nonce.to_vec()));
    pairs.push((tag::TYPE, 0u32.to_le_bytes().to_vec()));

    let n = pairs.len() + 1; // + ZZZZ
    let used: usize = 12 + 8 * n + pairs.iter().map(|(_, v)| v.len()).sum::<usize>();
    let pad = MIN_REQUEST_SIZE.saturating_sub(used);
    pairs.push((tag::ZZZZ, alloc::vec![0u8; pad]));
    frame(&encode_message(pairs))
}

/// Nonce for the next probe in a chained sequence: H(previous response || rand)
/// (RFC 10049 section 8.2). Chaining makes later responses provably later, so
/// inconsistent servers can be caught.
pub fn chained_nonce(previous_response_packet: &[u8], rand: &[u8; 32]) -> Hash32 {
    h(&[previous_response_packet, rand])
}

/// Facts a verified response establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRoughtime {
    /// The server's long-term key that ultimately vouches for this time.
    pub server_public_key: [u8; 32],
    /// The negotiated protocol version.
    pub version: u32,
    /// The request nonce the response is bound to.
    pub nonce: [u8; 32],
    /// MIDP, Unix seconds.
    pub midpoint_s: u64,
    /// RADI, seconds.
    pub radius_s: u32,
}

impl VerifiedRoughtime {
    /// The closed microsecond interval that contains the RFC's open interval
    /// (MIDP - RADI, MIDP + RADI).
    pub fn interval(&self) -> Result<TimeInterval> {
        let mid = i64::try_from(self.midpoint_s).map_err(|_| Error::Overflow)?;
        let rad = i64::from(self.radius_s);
        let lo = mid.checked_sub(rad).ok_or(Error::Overflow)?;
        let hi = mid.checked_add(rad).ok_or(Error::Overflow)?;
        TimeInterval::new(
            lo.checked_mul(1_000_000).ok_or(Error::Overflow)?,
            hi.checked_mul(1_000_000).ok_or(Error::Overflow)?,
        )
    }
}

/// Verify a Roughtime exchange against a trusted long-term key.
///
/// Checks, in order: framing; request NONC and VER; response TYPE, NONC echo;
/// SREP fields (VER offered by the client and listed in VERS, non-zero RADI);
/// the delegation signature by `server_public_key`; the SREP signature by the
/// delegated key; MINT <= MIDP <= MAXT; and the Merkle path from
/// H(0x00 || request) to ROOT with no leftover index bits.
pub fn verify_response(
    server_public_key: &[u8; 32],
    request_packet: &[u8],
    response_packet: &[u8],
    verifier: &dyn Ed25519Verifier,
) -> Result<VerifiedRoughtime> {
    // Bound the work before packet parsing, Merkle hashing, and Ed25519.
    if request_packet.len() > MAX_REQUEST_PACKET_SIZE {
        return malformed("Roughtime request exceeds maximum size");
    }
    if response_packet.len() > MAX_RESPONSE_PACKET_SIZE {
        return malformed("Roughtime response exceeds maximum size");
    }

    // Request side.
    let req = Message::parse(unframe(request_packet)?)?;
    let req_nonce = *exact_32(req.require(tag::NONC, "request NONC")?, "request NONC")?;
    // If the client asked for a specific server, that name must agree with
    // the long-term key used to authenticate the response. Reject key swaps
    // even when the other key happens to be trusted by the deployment.
    if let Some(requested_server) = req.get(tag::SRV) {
        let requested = exact_32(requested_server, "request SRV")?;
        if requested != &srv_commitment(server_public_key) {
            return malformed("request SRV does not identify the verifying server key");
        }
    }
    let offered = u32_list(req.require(tag::VER, "request VER")?, "request VER")?;
    if offered.windows(2).any(|w| w[0] >= w[1]) {
        return malformed("request VER is not strictly ascending");
    }
    if let Some(t) = req.get(tag::TYPE) {
        if exact_u32(t, "request TYPE")? != 0 {
            return malformed("request TYPE is not 0");
        }
    }

    // Response top level.
    let resp = Message::parse(unframe(response_packet)?)?;
    let sig = exact_64(resp.require(tag::SIG, "SIG")?, "SIG")?;
    let resp_nonce = exact_32(resp.require(tag::NONC, "response NONC")?, "response NONC")?;
    if resp_nonce != &req_nonce {
        return Err(Error::NonceMismatch);
    }
    let path = resp.require(tag::PATH, "PATH")?;
    if !path.len().is_multiple_of(32) || path.len() / 32 > MAX_PATH_HASHES {
        return malformed("PATH must be at most 32 hashes of 32 bytes");
    }
    let indx = exact_u32(resp.require(tag::INDX, "INDX")?, "INDX")?;
    let srep_bytes = resp.require(tag::SREP, "SREP")?;
    let cert_bytes = resp.require(tag::CERT, "CERT")?;

    // SREP.
    let srep = Message::parse(srep_bytes)?;
    let version = exact_u32(srep.require(tag::VER, "SREP VER")?, "SREP VER")?;
    let (ctx_srep, ctx_dele) = context_strings(version)?;
    if !offered.contains(&version) {
        return malformed("server chose a version the request did not offer");
    }
    let vers = u32_list(srep.require(tag::VERS, "VERS")?, "VERS")?;
    if vers.windows(2).any(|w| w[0] >= w[1]) || !vers.contains(&version) {
        return malformed("VERS is not ascending or does not list VER");
    }
    // RFC 10049 requires TYPE = 1 on responses. Draft-era servers predate it,
    // so it is only mandatory for version 1.
    match resp.get(tag::TYPE) {
        Some(t) if exact_u32(t, "response TYPE")? != 1 => {
            return malformed("response TYPE is not 1")
        }
        None if version == VERSION_RFC => return malformed("missing response TYPE tag"),
        _ => {}
    }
    let radius_s = exact_u32(srep.require(tag::RADI, "RADI")?, "RADI")?;
    if radius_s == 0 {
        return malformed("RADI must not be zero");
    }
    let midpoint_s = exact_u64(srep.require(tag::MIDP, "MIDP")?, "MIDP")?;
    let root = exact_32(srep.require(tag::ROOT, "ROOT")?, "ROOT")?;

    // CERT and DELE.
    let cert = Message::parse(cert_bytes)?;
    let cert_sig = exact_64(cert.require(tag::SIG, "CERT SIG")?, "CERT SIG")?;
    let dele_bytes = cert.require(tag::DELE, "DELE")?;
    let dele = Message::parse(dele_bytes)?;
    let online_key = exact_32(dele.require(tag::PUBK, "PUBK")?, "PUBK")?;
    let mint = exact_u64(dele.require(tag::MINT, "MINT")?, "MINT")?;
    let maxt = exact_u64(dele.require(tag::MAXT, "MAXT")?, "MAXT")?;

    let mut dele_msg = Vec::with_capacity(ctx_dele.len() + dele_bytes.len());
    dele_msg.extend_from_slice(ctx_dele);
    dele_msg.extend_from_slice(dele_bytes);
    if !verifier.verify(server_public_key, &dele_msg, cert_sig)? {
        return Err(Error::BadSignature(
            "delegation (CERT) signature by the long-term key",
        ));
    }

    let mut srep_msg = Vec::with_capacity(ctx_srep.len() + srep_bytes.len());
    srep_msg.extend_from_slice(ctx_srep);
    srep_msg.extend_from_slice(srep_bytes);
    if !verifier.verify(online_key, &srep_msg, sig)? {
        return Err(Error::BadSignature(
            "response (SREP) signature by the delegated key",
        ));
    }

    if !(mint <= midpoint_s && midpoint_s <= maxt) {
        return Err(Error::DelegationOutOfRange {
            midpoint: midpoint_s,
            mint,
            maxt,
        });
    }

    // Merkle inclusion of the exact request packet.
    let mut node = h(&[&[0x00], request_packet]);
    let mut index = indx;
    for sibling in path.chunks(32) {
        node = if index & 1 == 0 {
            h(&[&[0x01], &node, sibling])
        } else {
            h(&[&[0x01], sibling, &node])
        };
        index >>= 1;
    }
    if index != 0 || &node != root {
        return Err(Error::MerkleMismatch);
    }

    Ok(VerifiedRoughtime {
        server_public_key: *server_public_key,
        version,
        nonce: req_nonce,
        midpoint_s,
        radius_s,
    })
}

/// A Roughtime causality violation: response `later` was requested with a
/// nonce derived from `earlier`, so it was signed afterwards, yet its interval
/// ends before `earlier`'s interval begins. At least one of the two servers lied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalityViolation {
    /// Index of the earlier response in the checked sequence.
    pub earlier: usize,
    /// Index of the later response in the checked sequence.
    pub later: usize,
}

/// Check a chained sequence of verified responses (in request order) for the
/// RFC 10049 section 8.2 condition MIDP_i - RADI_i <= MIDP_j + RADI_j for i < j.
/// The caller must already have checked that each nonce chains from the
/// previous response with [`chained_nonce`].
pub fn find_causality_violation(chain: &[VerifiedRoughtime]) -> Option<CausalityViolation> {
    for j in 0..chain.len() {
        for i in 0..j {
            let lo_i = chain[i].midpoint_s as i128 - chain[i].radius_s as i128;
            let hi_j = chain[j].midpoint_s as i128 + chain[j].radius_s as i128;
            if lo_i > hi_j {
                return Some(CausalityViolation {
                    earlier: i,
                    later: j,
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_constants_match_ascii() {
        for (name, value) in [
            (b"SIG\0", tag::SIG),
            (b"VER\0", tag::VER),
            (b"SRV\0", tag::SRV),
            (b"NONC", tag::NONC),
            (b"DELE", tag::DELE),
            (b"TYPE", tag::TYPE),
            (b"PATH", tag::PATH),
            (b"RADI", tag::RADI),
            (b"PUBK", tag::PUBK),
            (b"MIDP", tag::MIDP),
            (b"SREP", tag::SREP),
            (b"VERS", tag::VERS),
            (b"MINT", tag::MINT),
            (b"ROOT", tag::ROOT),
            (b"CERT", tag::CERT),
            (b"MAXT", tag::MAXT),
            (b"INDX", tag::INDX),
            (b"ZZZZ", tag::ZZZZ),
        ] {
            assert_eq!(
                u32::from_le_bytes(*name),
                value,
                "{}",
                core::str::from_utf8(name).unwrap()
            );
        }
    }

    #[test]
    fn built_request_is_1024_bytes_and_parses() {
        let req = build_request(&[7u8; 32], &[VERSION_DRAFT, VERSION_RFC], Some(&[1u8; 32]));
        assert_eq!(req.len(), MIN_REQUEST_SIZE);
        let msg = Message::parse(unframe(&req).unwrap()).unwrap();
        assert_eq!(msg.get(tag::NONC).unwrap(), &[7u8; 32]);
        assert_eq!(msg.get(tag::TYPE).unwrap(), &[0, 0, 0, 0]);
        assert_eq!(
            u32_list(msg.get(tag::VER).unwrap(), "VER").unwrap(),
            alloc::vec![VERSION_RFC, VERSION_DRAFT]
        );
        assert_eq!(msg.get(tag::SRV).unwrap(), &srv_commitment(&[1u8; 32]));
    }

    #[test]
    fn parser_rejects_unsorted_tags_and_bad_offsets() {
        // Two tags out of order.
        let mut bad = Vec::new();
        bad.extend_from_slice(&2u32.to_le_bytes());
        bad.extend_from_slice(&4u32.to_le_bytes());
        bad.extend_from_slice(&tag::TYPE.to_le_bytes());
        bad.extend_from_slice(&tag::NONC.to_le_bytes());
        bad.extend_from_slice(&[0u8; 8]);
        assert!(Message::parse(&bad).is_err());

        // Offset not a multiple of 4.
        let mut bad = Vec::new();
        bad.extend_from_slice(&2u32.to_le_bytes());
        bad.extend_from_slice(&3u32.to_le_bytes());
        bad.extend_from_slice(&tag::NONC.to_le_bytes());
        bad.extend_from_slice(&tag::TYPE.to_le_bytes());
        bad.extend_from_slice(&[0u8; 8]);
        assert!(Message::parse(&bad).is_err());

        // Offset past the end.
        let mut bad = Vec::new();
        bad.extend_from_slice(&2u32.to_le_bytes());
        bad.extend_from_slice(&64u32.to_le_bytes());
        bad.extend_from_slice(&tag::NONC.to_le_bytes());
        bad.extend_from_slice(&tag::TYPE.to_le_bytes());
        bad.extend_from_slice(&[0u8; 8]);
        assert!(Message::parse(&bad).is_err());
    }

    #[test]
    fn size_budgets_reject_oversized_messages_and_packets() {
        let largest = encode_message(alloc::vec![(
            tag::ZZZZ,
            alloc::vec![0u8; MAX_MESSAGE_SIZE - 8]
        )]);
        assert_eq!(largest.len(), MAX_MESSAGE_SIZE);
        assert!(Message::parse(&largest).is_ok());
        assert_eq!(frame(&largest).len(), MAX_RESPONSE_PACKET_SIZE);
        assert!(unframe(&frame(&largest)).is_ok());

        let over = encode_message(alloc::vec![(
            tag::ZZZZ,
            alloc::vec![0u8; MAX_MESSAGE_SIZE - 7]
        )]);
        assert_eq!(over.len(), MAX_MESSAGE_SIZE + 1);
        assert!(matches!(Message::parse(&over), Err(Error::Malformed(_))));
        assert!(matches!(unframe(&frame(&over)), Err(Error::Malformed(_))));

        assert!(Message::parse(&0u32.to_le_bytes()).unwrap().is_empty());
        assert!(matches!(
            Message::parse(&[0u8; 8]),
            Err(Error::Malformed(_))
        ));
    }

    #[cfg(feature = "dalek")]
    #[test]
    fn verify_response_rejects_large_packets_before_crypto() {
        let request = build_request(&[7u8; 32], &[VERSION_RFC], None);
        let large_request = frame(&encode_message(alloc::vec![(
            tag::ZZZZ,
            alloc::vec![0u8; MAX_REQUEST_PACKET_SIZE - 19],
        )]));
        assert_eq!(large_request.len(), MAX_REQUEST_PACKET_SIZE + 1);
        assert!(matches!(
            verify_response(&[0u8; 32], &large_request, &request, &crate::DalekVerifier),
            Err(Error::Malformed(_))
        ));
        let large_response = frame(&encode_message(alloc::vec![(
            tag::ZZZZ,
            alloc::vec![0u8; MAX_MESSAGE_SIZE - 7],
        )]));
        assert!(matches!(
            verify_response(&[0u8; 32], &request, &large_response, &crate::DalekVerifier),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn unframe_checks_length_exactly() {
        let mut p = frame(&[1, 0, 0, 0, 0x4e, 0x4f, 0x4e, 0x43]);
        assert!(unframe(&p).is_ok());
        p.push(0);
        assert!(unframe(&p).is_err());
    }

    #[test]
    fn causality_check() {
        let mk = |m, r| VerifiedRoughtime {
            server_public_key: [0; 32],
            version: VERSION_RFC,
            nonce: [0; 32],
            midpoint_s: m,
            radius_s: r,
        };
        assert_eq!(
            find_causality_violation(&[mk(100, 2), mk(101, 2), mk(99, 3)]),
            None
        );
        assert_eq!(
            find_causality_violation(&[mk(100, 2), mk(90, 2)]),
            Some(CausalityViolation {
                earlier: 0,
                later: 1
            })
        );
    }
}
