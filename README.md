# 🛡️ Vanguard SRE: State & Rollback Engine (v2)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Status: MVP](https://img.shields.io/badge/status-MVP-success.svg)]()
[![Platform: Linux/WSL2](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-lightgrey.svg)]()

**Vanguard SRE** is a robust, enterprise-grade execution framework designed for Autonomous AI Agents. It provides a deterministic, 3-layer rollback mechanism encompassing **Context, Workspaces/Processes, and External Effects**. 

By utilizing Directed Acyclic Graphs (DAG), Write-Ahead Logging (WAL), and cryptographic Content-Addressable Storage (CAS), Vanguard SRE ensures that AI agents can fail safely, revert to the last verified anchor, and learn from structural constraints without corrupting the operational environment.

---

## 🚀 Core Architecture

Vanguard SRE is built on the Python standard library and operates strictly on Linux/WSL2 (ext4) environments, leveraging OS-level primitives (`fcntl`, `os.fork`, `/proc`, and `git`).

| Module | Layer | Description |
|---|---|---|
| `arbiter.py` | **Lifecycle** | The core orchestration loop. Manages steps, WAL rollbacks, diagnostic replans, constraint injections, and escalation protocols. |
| `audit.py` | **DAG** | Directed Acyclic Graph execution tracker. Supports Sibling Preservation, cycle detection, and strict `ANCHOR_COMMITTED` states. |
| `blobstore.py` | **Storage** | Content-Addressable Storage (CAS) with SHA-256 integrity. Writes ensure safety before event emissions. |
| `effects.py` | **Effects (L3)** | External effect ledger with `ToolSchema`. Implements Idempotent keys, WAL (intent/commit), and Replay mechanics for safe retries. |
| `transponder.py` | **Telemetry** | Single-writer, HMAC-chained event log. Secures external anchors and auto-truncates torn tails for crash resilience. |
| `verifier.py` | **Validation** | External verifier running in isolated sub-processes. Supports `goal` and `guard` invariants without exposing expectations to the agent. |
| `workspace.py` | **State (L2/L4)** | Git-backed workspace anchoring and Level 4 process group isolation (tracks and kills processes via `/proc`). |

---

## ⚙️ How It Works: The Step Lifecycle

1. **Schema Resolution:** The Arbiter determines the step class via `ToolSchema`, stripping internal agent flags to prevent context poisoning.
2. **Pre-flight Storage:** Arguments and historical context are persisted as CAS blobs *before* the `STEP_STARTED` event is emitted.
3. **Effect Ledger Execution:** Actions are routed through the `EffectLedger` (Replay / UNKNOWN / Approval flows).
4. **Verification & Commit:** Terminal steps are audited by the `ExternalVerifier`. On `SUCCESS`, a git-commit is created -> `STEP_COMPLETED` -> `ANCHOR_COMMITTED`.
5. **Deterministic Rollback (PATCH):** If verification fails, a `ROLLBACK_TRIGGERED` WAL event fires. The Workspace is restored, orphan processes are explicitly killed, and the history reverts to the last snapshot. 
6. **Constraint Injection:** A negative contract constraint is injected dynamically at the *end* of the agent's prompt, preserving LLM prefix-caching while preventing repeated failures.

---

## 🧪 Testing & Validation

The framework includes a comprehensive test suite validating resilience under extreme conditions:
* **Crash Tolerance:** Survives 500 `fork` + `SIGKILL` cycles with write fragmentation.
* **Log Integrity:** Successfully detects mid-file tampering, torn tails, and stale anchors.
* **Process Management:** Correctly terminates orphan background processes and reclaims ports via strict `/proc` tracking.
* **State Recovery:** Handles infinite loops, `ImportError`, flaky tests, and incomplete rollbacks with 100 consecutive successful `git restore` operations.

```bash
# Run the test suite (Default: SRE_CRASH_CYCLES=500)
python3 -m unittest -v tests.test_sre


⚠️ Known Limitations & Trade-offs (MVP)
As an MVP (Steps 1–7), the architecture makes several intentional trade-offs to prioritize speed and reliability:

UID Sandbox Constraints: Code executes under the same UID. Malicious agent code could theoretically access specification files. Mitigation: True containerization is planned for the next operational phase.

Dependency Environments: .venv and node_modules are tracked via lock-file hashes but are not snapshotted or rolled back directly. Dependency installation must be treated as an L3 Effect.

Background Process Lifespan: Branch background processes are terminated during every snapshot() and restore().

JSON Canonicalization: Float canonicalization utilizes Python's repr() for round-trip safety, which is not strictly RFC 8785 compliant (though int, str, bool, null, list, and dict are).

Anchor Security: An anchor.json stored in the same directory as the log only protects against untrusted tail truncation. For full rollback protection, anchor_dir must be mounted on an external host or volume.

Built for the deterministic execution of Autonomous Cyber-Systems.