# ADR 003 — Roughtime packet-size budgets

**Status:** Proposed pending native CI, interoperability and security review  
**Related:** #10, #4, #7, #12

## Context

Client-supplied Roughtime request/response bytes can be stored and independently reverified by Holochain zomes. Prior checks bounded tag count, version-list count and Merkle path depth but did not constrain the size of a framed packet or nested message. Oversized unknown tags/padding can consume CPU, memory, transit and storage before verification.

## Decision

- Maximum request: **4 KiB (4096 bytes)** including the 12-byte frame.
- Maximum response: **16 KiB (16384 bytes)** including the frame.
- Maximum parsed message: **16372 bytes**; check length before allocating tag and offset vectors, including for nested CERT/SREP/DELE messages.
- In `verify_response`, reject oversized requests and responses before parsing, hashing or signature verification.
- `unframe` enforces the response-size ceiling regardless of caller.
- Reject trailing bytes after the zero-tag count of an otherwise empty RFC message.
- The reference UDP client accepts a one-byte oversize sentinel and fails explicitly instead of treating a truncated datagram as evidence.

These 4/16 KiB thresholds are **application limits**, not universal RFC 10049 requirements. Standard 1024-byte padded requests are still accepted. Verify deployed RFC and draft-server response sizes before treating the limits as production policy.

## Acceptance tests

- A structured max-size message parses; an extra byte fails.
- A 16384-byte framed response passes framing; 16385 bytes fails.
- A 4097-byte request fails in `verify_response` before signature verification.
- A zero-tag message with trailing bytes fails.
- Existing Roughenough interoperability tests and pinned Holochain 0.7 native/WASM CI must remain green.

## Limitations and compatibility

This protects the core verifier, not the Holochain input deserializer, remote call count or `get_links` DHT index queries. It does **not** establish completeness of evidence, oracle throughput, or conductor reliability.

Existing stored evidence beyond these thresholds would be newly rejected. `vtime_core` is linked into integrity and coordinator zomes; any integrity WASM change can change DNA hash/network identity and migration requirements. Review rollout under #12 and avoid accepting production money until compatibility and live network testing are complete.

## Reference

[Soushi888 Holochain agent skill](https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain), targeting HDK 0.7.1 / HDI 0.8.1.
