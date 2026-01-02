# MIT License © 2025 Motohiro Suzuki
# SPEC_155.md
# Stage155｜QSP v1.0 (Research Grade) Release Candidate Specification

## 0. Summary

**QSP (Quantum-Safe Protocol)** is a research-grade protocol skeleton that integrates:

- **PQC authentication** (signature; currently stub/Ed25519 fallback allowed)
- **Hybrid key supply** (QKD + PQC-KEM) as **separable** inputs
- **HKDF-based key schedule**
- **AEAD-protected data + AEAD-protected control frames**
- **Automatic rekey** with **epoch continuity** and strict **nonce binding**

Stage155 is a **Release Candidate** focused on:
- readable spec + reproducibility,
- minimal state machine,
- message boundary discipline,
- baseline bench/fuzz to validate implementation integrity.

> IMPORTANT: Stage155 is a research prototype.  
> It is **NOT** a formal security proof and **NOT** production-ready.

---

## 1. Threat Model

### 1.1 Adversary capabilities
The adversary may:
- observe, intercept, replay, drop, delay, reorder packets (active network attacker)
- inject malformed frames
- attempt to desynchronize peers (epoch/seq confusion)
- attempt cryptographic forgery (signature/KEM compromise attempts, AEAD tampering)

The adversary does **not**:
- break standard cryptographic primitives instantly (unless explicitly stated in “Limitations”)
- access endpoint memory on a correct implementation (no endpoint compromise model here)

### 1.2 Out of scope
- endpoint compromise / malware on client/server
- side-channels (timing/power/cache)
- traffic analysis resistance
- DoS resistance beyond “safe failure” behavior
- key management outside the protocol (storage, rotation policy, PKI, etc.)

---

## 2. Security & Engineering Goals

### 2.1 Security goals (research-grade)
- **Message boundary integrity**: all control frames remain control frames, protected by AEAD.
- **Replay and reordering robustness**: strict binding of (epoch, seq) to nonce and AEAD.
- **Epoch continuity**: rekey advances epoch in a synchronized and verifiable manner.
- **Fail-closed behavior**: on mismatch or decryption failure, close with explicit reason.

### 2.2 Engineering goals
- reproducible, minimal code paths
- clearly separable “crypto suite” swap points
- tests/bench/fuzz entry points

---

## 3. Protocol Vocabulary

### 3.1 Identifiers
- **session_id**: u64 chosen by server during handshake.
- **epoch**: u32 logical key generation index. Starts at 1 after handshake.
- **seq**: u32 per-session transmit sequence (implementation may mask).
- **nonce**: 12 bytes derived strictly as:
  - `nonce = epoch(4 bytes) || seq(8 bytes)` (big-endian)

### 3.2 Frame types
All traffic is in **MessageFrame**:

- `FT_HANDSHAKE` (1): handshake frames (Stage155: dev handshake)
- `FT_APP_DATA`  (2): encrypted application payload
- `FT_REKEY`     (3): AEAD-protected control frame
- `FT_CLOSE`     (4): AEAD-protected control frame

Binary frame format is (network order):
- type: u8
- flags: u8
- session_id: u64
- epoch: u32
- seq: u32
- payload_len: u32
- payload: bytes

---

## 4. Cryptographic Components (Algorithm Agility Points)

Stage155 defines boundaries (swap points) but allows stub backends for runnable demos.

### 4.1 Signature (AUTH)
**Swap point**: `crypto/sig_backends.py` (or equivalent abstraction)

- goal: authenticate handshake transcript / identity
- Stage155 implementation status:
  - may use Ed25519 via `cryptography` if available
  - otherwise stub HMAC-based signature backend for agility scaffolding

> NOTE: Stub signatures are not PQC secure; they exist to validate structure and swap points.

### 4.2 KEM (PQC-KEM)
**Swap point**: `crypto/kem.py`
- Stage155: stub KEM backend by default
- intended: Kyber/ML-KEM via proper library at later stage

### 4.3 QKD KeySource
**Swap point**: `keysources/qkd_e91.py` (stub now), later replaced by Qiskit E91 source.

### 4.4 Key mixing (KDF)
**Swap point**: HKDF-SHA256
- `K_session_epoch1 = HKDF( IKM, salt, info, key_len )`

### 4.5 AEAD
**Swap point**: AES-GCM (cryptography) or fallback demo AEAD (NOT secure)
- Control frames must remain AEAD-protected (boundary discipline).

---

## 5. Handshake

### 5.1 Stage155 requirement (current status)
Stage155 documents current handshake as **dev handshake**:
- purpose: ensure **both sides derive identical key material deterministically**
- does **NOT** yet include full “AUTH + KEM + QKD mix” handshake

### 5.2 Current dev handshake (Stage153-style)
Wire flow:
1) Client → Server: `CHLO || client_nonce(32)`
2) Server → Client: `SHLO || server_nonce(32) || session_id(u64)`

Derived shared material:
- `ikm_base = SHA256("QSP153" || client_nonce || server_nonce)`
- `ikm = HKDF(ikm_base, salt=SHA256("QSP153-salt"), info="qsp-stage153-handshake-ikm", length=32)`
- handshake returns `(session_id, key_material_dict)` where `key_material_dict["kem"]=ikm`

> This guarantees handshake always returns key material and prevents `None`-type failures.

### 5.3 v1.0 implementation requirement (planned)
**AUTH + KEM + QKD mix** will be explicitly specified and implemented after RC stabilization:
- authenticate transcript via PQC signature
- derive IKM from both KEM shared secret and QKD raw key
- mix with HKDF with domain separation

(Tracked as next stage once RC is accepted.)

---

## 6. Established State & Data Protection

### 6.1 Session key schedule
- epoch starts at 1 after handshake.
- session maintains at most **two epoch keys** (previous + current) to preserve continuity.

### 6.2 Nonce derivation
Nonce is strict:
- `nonce = epoch(4) || seq(8)`  
and payload includes a nonce prefix for strict check (implementation can enforce prefix).

### 6.3 APP_DATA protection
For outbound:
- choose `epoch=current_epoch`
- increment `seq`
- encrypt:
  - `ct = AEAD_Encrypt(key[epoch], nonce(epoch,seq), aad="app", plaintext)`
  - payload may prefix nonce for strict verification

For inbound:
- decrypt using frame epoch/seq and strict nonce equality check.

---

## 7. Rekey (FT_REKEY)

### 7.1 Server-led rekey (recommended)
- server initiates `REKEY_INIT` protected under current epoch key
- client replies `REKEY_ACK` protected under current epoch key
- both derive `new_key` and commit epoch advancement

### 7.2 Rekey plaintext format (inside AEAD)
Magic + message type + new_epoch + material/confirm:

- `RK54 || T_INIT || new_epoch(u32) || material(32)`
- `RK54 || T_ACK  || new_epoch(u32) || confirm(32)`
- `confirm = SHA256(material || "ack")`

### 7.3 Commit policy (Stage155)
- client commits **immediately after sending ACK**
- server commits **after verifying ACK**
- if ACK is not received and server closes, session ends (expected in minimal model)

### 7.4 Continuity & mismatch handling
- epoch mismatch is explicitly detected and triggers **FT_CLOSE** with reason.

---

## 8. Close (FT_CLOSE)

`FT_CLOSE` is always AEAD-protected under current epoch key.

Plaintext:
- reason(u16) || message(utf-8)

Minimum CloseReason set:
- NORMAL=0
- PROTOCOL_ERROR=10
- AEAD_DECRYPT_FAILED=20
- EPOCH_MISMATCH=30
- REKEY_FAILED=40
- INTERNAL_ERROR=90

---

## 9. State Machine

States:
- `Handshake`
- `Established`
- `Rekey` (inflight)
- `Closed`

### 9.1 Handshake
- upon success: create Session(epoch=1), keys[1]=K1 → Established
- upon failure: abort/close

### 9.2 Established
- accept `FT_APP_DATA` (decrypt+process)
- accept `FT_REKEY` (handle init/ack)
- accept `FT_CLOSE` (close)
- auto-rekey trigger may transition → Rekey

### 9.3 Rekey
- server inflight state set after sending INIT
- client responds with ACK and commits
- server commits after ACK verification
- return to Established with epoch advanced

### 9.4 Closed
- no further frames processed

---

## 10. Reproducibility

### 10.1 Runtime
- Python 3.10+ recommended
- Optional: `cryptography` for AES-GCM / Ed25519

### 10.2 Run commands (example)
Server:
```bash
python3 run_server155.py
Client:

bash
コードをコピーする
python3 run_client155.py
10.3 Bench / Fuzz
Bench entry (module execution):

bash
コードをコピーする
python3 -m bench.bench_rekey155
Example observed result (your run):

loops: 2000

warmup: 50

elapsed_sec: 0.051733

ops_per_sec: 38660.4 rekey/s

final_epoch: 2051

Fuzz entry:

bash
コードをコピーする
python3 -m fuzz.fuzz_rekey155 --cases 300 --steps 2000 --seed 1
Example observed result (your run):

cases: 300

steps/case: 2000

mutate_prob: 0.15

result: OK

10.4 Interpretation of bench/fuzz results (honest statement)
These results do not prove cryptographic security.

They do validate implementation integrity against:

state-machine violations,

malformed input handling,

rekey inflight constraints,

epoch/seq/nonce consistency enforcement,

safe-fail behavior (close on mismatch).

11. Known Limitations (Stage155 RC)
Handshake is currently a dev handshake (nonce exchange / deterministic IKM) and not full AUTH+KEM+QKD.

Stub crypto backends may be enabled for runnable demo and are not secure.

No formal proof, no side-channel hardening, no DoS resistance guarantees.

12. Roadmap (Post-RC)
v1.0 handshake: Signature authentication + KEM + QKD mixing

replace stub KEM with ML-KEM (Kyber) via vetted library

integrate real E91 QKD (Qiskit) KeySource

expand tests/ for interoperability and regression