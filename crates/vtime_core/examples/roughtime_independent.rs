//! Auditable multi-operator Roughtime acquisition and offline replay.
//!
//! Usage (39-byte Holochain raw hash encodings, 78 hex chars each):
//!
//! ```text
//! cargo run -p vtime_core --example roughtime_independent -- --live \
//!   config/roughtime-independent-sources.json <dna-hex> <target-action-hex> \
//!   > sprint11-receipt.json
//! cargo run -p vtime_core --example roughtime_independent -- --verify \
//!   config/roughtime-independent-sources.json sprint11-receipt.json \
//!   <dna-hex> <target-action-hex>
//! ```
//!
//! This intentionally never reduces the three-source requirement. The JSON
//! receipt contains actual framed wire bytes for later offline verification.

use std::fs;
use std::io;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vtime_core::evidence::{
    check_independent_roughtime_sources, verify_independent_roughtime_quorum,
    IndependentRoughtimeSource, RoughtimeEvidence, TimePolicy,
};
use vtime_core::hash::to_hex;
use vtime_core::keys::roughtime_key_from_b64;
use vtime_core::roughtime::{
    build_request, verify_response, MAX_RESPONSE_PACKET_SIZE, VERSION_DRAFT, VERSION_RFC,
};
use vtime_core::seal::seal_nonce;
use vtime_core::DalekVerifier;

#[derive(Deserialize)]
struct Config {
    schema: String,
    sources: Vec<Source>,
}

#[derive(Deserialize)]
struct Source {
    name: String,
    operator: String,
    address: String,
    public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Attempt {
    name: String,
    operator: String,
    outcome: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Receipt {
    schema: String,
    dna_hex: String,
    target_hex: String,
    nonce_hex: String,
    attempts: Vec<Attempt>,
    evidence: Vec<RoughtimeEvidence>,
}

fn decode_hash39(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if hex.len() != 78 || !hex.is_ascii() {
        return Err("expected exactly 78 ASCII hex digits for a 39-byte Holochain hash".into());
    }
    let mut bytes = Vec::with_capacity(39);
    for pair in hex.as_bytes().as_chunks::<2>().0 {
        let s = std::str::from_utf8(pair)?;
        bytes.push(u8::from_str_radix(s, 16)?);
    }
    Ok(bytes)
}

fn policy_and_registry(
    config: &Config,
) -> Result<(TimePolicy, Vec<IndependentRoughtimeSource>), Box<dyn std::error::Error>> {
    if config.schema != "hc-vtime/independent-roughtime/v1" {
        return Err("unknown independent-source config schema".into());
    }
    let sources: Vec<IndependentRoughtimeSource> = config
        .sources
        .iter()
        .map(|s| {
            Ok(IndependentRoughtimeSource {
                operator: s.operator.clone(),
                public_key: roughtime_key_from_b64(&s.public_key)?,
            })
        })
        .collect::<vtime_core::Result<_>>()?;
    let policy = TimePolicy {
        roughtime_servers: sources.iter().map(|s| s.public_key).collect(),
        oracles: Vec::new(),
        max_faulty: 1,
        min_sources: 3,
        max_radius_us: 10_000_000,
        oracle_dna: None,
    };
    check_independent_roughtime_sources(&sources, &policy)?;
    Ok((policy, sources))
}

fn query(address: &str, request: &[u8]) -> io::Result<Vec<u8>> {
    // Connect the datagram socket to avoid accepting unsolicited replies
    // from other network addresses. Ed25519 verification is still mandatory.
    let mut last = io::Error::other("no usable UDP address");
    for addr in address.to_socket_addrs()? {
        let attempt = (|| {
            let bind = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind)?;
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.set_write_timeout(Some(Duration::from_secs(3)))?;
            socket.connect(addr)?;
            socket.send(request)?;
            let mut response = [0u8; MAX_RESPONSE_PACKET_SIZE + 1];
            let len = socket.recv(&mut response)?;
            if len > MAX_RESPONSE_PACKET_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Roughtime UDP response exceeds bounded packet size",
                ));
            }
            Ok(response[..len].to_vec())
        })();
        match attempt {
            Ok(bytes) => return Ok(bytes),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let (live, config_path, receipt_path, dna_text, target_text) = match args.as_slice() {
        [_, mode, config, dna, target] if mode == "--live" => {
            (true, config.as_str(), None, dna.as_str(), target.as_str())
        }
        [_, mode, config, receipt, dna, target] if mode == "--verify" => {
            (false, config.as_str(), Some(receipt.as_str()), dna.as_str(), target.as_str())
        }
        _ => return Err("usage: roughtime_independent --live CONFIG DNA_HEX TARGET_HEX | --verify CONFIG RECEIPT DNA_HEX TARGET_HEX".into()),
    };
    let config: Config = serde_json::from_str(&fs::read_to_string(config_path)?)?;
    let (policy, sources) = policy_and_registry(&config)?;
    let dna = decode_hash39(dna_text)?;
    let target = decode_hash39(target_text)?;
    let nonce = seal_nonce(&dna, &target);

    let receipt = if live {
        let mut receipt = Receipt {
            schema: "hc-vtime/roughtime-receipt/v1".to_owned(),
            dna_hex: to_hex(&dna),
            target_hex: to_hex(&target),
            nonce_hex: to_hex(&nonce),
            attempts: Vec::new(),
            evidence: Vec::new(),
        };
        for (source, identity) in config.sources.iter().zip(sources.iter()) {
            let request = build_request(
                &nonce,
                &[VERSION_RFC, VERSION_DRAFT],
                Some(&identity.public_key),
            );
            let result = query(&source.address, &request).and_then(|response| {
                verify_response(&identity.public_key, &request, &response, &DalekVerifier)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                receipt.evidence.push(RoughtimeEvidence {
                    server_public_key: identity.public_key.to_vec(),
                    request,
                    response,
                });
                Ok(())
            });
            let outcome = match result {
                Ok(()) => "verified".to_owned(),
                Err(e) => format!("unavailable-or-invalid: {e}"),
            };
            eprintln!("{} [{}]: {}", source.name, source.operator, outcome);
            receipt.attempts.push(Attempt {
                name: source.name.clone(),
                operator: source.operator.clone(),
                outcome,
            });
        }
        // Save even failed acquisition attempts as inspectable diagnostics.
        println!("{}", serde_json::to_string_pretty(&receipt)?);
        receipt
    } else {
        let path = receipt_path.ok_or("missing receipt path")?;
        let receipt: Receipt = serde_json::from_str(&fs::read_to_string(path)?)?;
        if receipt.schema != "hc-vtime/roughtime-receipt/v1"
            || !receipt.dna_hex.eq_ignore_ascii_case(dna_text)
            || !receipt.target_hex.eq_ignore_ascii_case(target_text)
            || receipt.nonce_hex != to_hex(&nonce)
        {
            return Err("receipt has wrong DNA, target or expected nonce".into());
        }
        receipt
    };

    let verified = verify_independent_roughtime_quorum(
        &receipt.evidence,
        &sources,
        &policy,
        &DalekVerifier,
        &nonce,
    )?;
    // Structured observations allow Sprint 23 to pin and independently
    // audit the exact signed intervals without re-implementing Roughtime in
    // Python. The native verifier checked the long-term signature, delegated
    // certificate, signed SREP, Merkle inclusion, nonce, version and quorum.
    // These observations do NOT establish source ownership or true freshness.
    let intervals: Vec<_> = verified
        .iter()
        .map(|source| serde_json::json!({
            "key_hex": to_hex(source.source.key()),
            "earliest_us": source.interval.earliest_us,
            "latest_us": source.interval.latest_us
        }))
        .collect();
    eprintln!(
        "HC_RT_VERIFIED {}",
        serde_json::to_string(&serde_json::json!({
            "schema": "hc-vtime/native-roughtime-verification/v1",
            "dna_hex": to_hex(&dna),
            "target_hex": to_hex(&target),
            "nonce_hex": to_hex(&nonce),
            "verified_count": verified.len(),
            "intervals": intervals,
            "operator_independence_proven": false,
            "same_target_replay_prevented": false
        }))?
    );
    eprintln!(
        "ACCEPTED: {} independently configured operators, all signatures and target nonce verified",
        verified.len()
    );
    // A cryptographic acceptance is NOT an independent audit of operator
    // ownership and does NOT establish absolute time freshness by itself.
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("REJECTED: {e}");
        std::process::exit(1);
    }
}
