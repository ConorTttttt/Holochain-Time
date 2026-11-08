//! Fetch one Roughtime reading over UDP and print it as JSON evidence.
//!
//! Zomes cannot open sockets, so a client (this tool, a Tauri backend, or an
//! oracle sidecar) performs the exchange and passes the bytes to the zome.
//! The output verifies offline before it is printed, so a bad server or a bad
//! key is caught here rather than in validation.
//!
//! ```text
//! cargo run -p vtime_core --example roughtime_fetch -- \
//!     <host:port> <server key, standard base64> <nonce, 64 hex chars>
//! ```
//!
//! For a seal, get the nonce from the zome's `seal_nonce_for(target)`; for an
//! anchor, any fresh random nonce will do.

use std::net::UdpSocket;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use vtime_core::hash::hex32;
use vtime_core::keys::roughtime_key_from_b64;
use vtime_core::roughtime::{build_request, verify_response, VERSION_DRAFT, VERSION_RFC};
use vtime_core::DalekVerifier;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: roughtime_fetch <host:port> <server key b64> <nonce hex>");
        std::process::exit(2);
    }
    let key = roughtime_key_from_b64(&args[2])?;
    let nonce = hex32(&args[3])?;
    let request = build_request(&nonce, &[VERSION_RFC, VERSION_DRAFT], Some(&key));

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.send_to(&request, &args[1])?;
    let mut buf = [0u8; 2048];
    let (len, _) = socket.recv_from(&mut buf)?;
    let response = buf[..len].to_vec();

    let v = verify_response(&key, &request, &response, &DalekVerifier)?;
    eprintln!(
        "verified: version 0x{:08x}, midpoint {} s, radius {} s",
        v.version, v.midpoint_s, v.radius_s
    );
    println!(
        "{{\"server_public_key\":\"{}\",\"request\":\"{}\",\"response\":\"{}\"}}",
        STANDARD.encode(key),
        STANDARD.encode(&request),
        STANDARD.encode(&response)
    );
    Ok(())
}
