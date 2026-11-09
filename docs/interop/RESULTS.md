# Sprint 18 — Compatibility acceptance record

**State (GitHub-first implementation): NOT YET EXECUTED on a Rust/Holochain toolchain.**

| Acceptance check | Evidence status |
| --- | --- |
| Regenerate deterministic signed oracle MessagePack vector | Script and committed SHA-256 prepared; CI/local run pending |
| Independently verify the same oracle signature in Python | Python reference checker prepared; CI/local run pending |
| Verify independent Python RFC Roughtime response in Rust | Golden fixture and Rust regression prepared; native run pending |
| Verify 13 Roughenough-server Merkle responses through both paths | Rust reference-server regression prepared; native run pending |
| Unknown-field and unsupported-version rejection | Strict codec and negative tests prepared; native run pending |
| Malformed binary, truncated and over-budget input rejection | Native regressions prepared; execution pending |
| Real 3-conductor signed-test-only verification | Handoff to existing signed-quorum suite; execution pending |
| Combined exact-SHA result and checksummed logs | `scripts/interop/run.sh` prepared; execution pending |
| Production envelope deployment and migration | **Out of scope; no production changes** |

**No green build, independent source availability, network interoperability
measurement or release approval is claimed from source-only additions.**

Record after execution: exact SHA, tooling versions, Python package versions,
each step exit code, generated log/checksum path, any failing vector ID and
approved disposition. Preserve failed fixture bytes when sharing reproducers,
but remove host paths and secrets from logs first. Wider release remains NO-GO.
