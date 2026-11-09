//! Print only public test keys, never signing material.
use base64::{engine::general_purpose::STANDARD, Engine};
use hc_vtime_conductor_smoke::fixtures::test_public_keys;
fn main() {
    let keys: Vec<String> = test_public_keys().iter().map(|k| STANDARD.encode(k)).collect();
    println!("{}", serde_json::json!({"test_only": true, "roughtime_servers": keys}));
}
