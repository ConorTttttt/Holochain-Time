# Sprint 13 — Performance baseline (pending measurements)

**Measurement status:** NOT RUN. No p50, p95, p99, CPU, RSS, throughput,
rejection-rate or operating-limit numbers have been observed yet.

The implementation in `integration/load/` and `scripts/load/run.py` is a
repeatable measurement *method*, not itself performance evidence. Running the
instructions in [README.md](README.md) generates an exact-commit
`baseline.md` and machine-readable `report.json` outside this repository.

| Dimension | Initial baseline |
| --- | --- |
| 120 simultaneous signed seal calls | Not measured |
| p50/p95/p99 latency (all calls) | Not measured |
| Conductor CPU usage (Linux host, sampled process tree) | Not measured |
| Conductor RSS memory (Linux host, sampled process tree) | Not measured |
| 33-witness and 33-Roughtime-item rejection under load | Tests prepared; not run |
| Overlimit Roughtime request and response packets | Tests prepared; not run |
| 256-action ancestry boundary and arithmetic overflow | Existing native test will run; no result captured |
| Repetition across runs/hosts | Not measured |
| Operationally defensible throughput / capacity limits | **Undetermined** |

This document deliberately contains no synthetic benchmark values.
Sprint acceptance requires real logs and failure distributions, plus a clear
statement of missing network/load environments. The independent production
release decision remains **NO-GO**.
