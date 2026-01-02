# MIT License © 2025 Motohiro Suzuki
# README.md
# Stage155｜QSP v1.0 (Research Grade) Release Candidate

QSP (Quantum-Safe Protocol) is a research-grade protocol skeleton integrating:
- **PQC authentication (boundary + swap points)**
- **Hybrid key supply (QKD + KEM)**
- **HKDF key schedule**
- **AEAD-protected APP_DATA + AEAD-protected control frames**
- **Automatic rekey** with epoch continuity and strict nonce binding

> This repository is a **research prototype**.  
> It is **NOT** a production-ready secure protocol and **NOT** a security proof.

---

## What you can do in 30 seconds

### 1) Start server
```bash
python3 run_server155.py
You should see:

[server] listening on 127.0.0.1:9000

2) Run client
bash
コードをコピーする
python3 run_client155.py
You should see:

handshake complete

echo messages

rekey ACK sent and epoch increments

normal close

Protocol Overview
Message Types
FT_HANDSHAKE (1) : handshake frames (Stage155: dev handshake)

FT_APP_DATA (2) : encrypted application data

FT_REKEY (3) : AEAD-protected rekey control

FT_CLOSE (4) : AEAD-protected close control

Rekey Model (server-led)
server sends REKEY_INIT (protected under current epoch key)

client sends REKEY_ACK (protected under current epoch key)

both derive & commit the next epoch key

epoch mismatch is detected and closed explicitly

Strict Nonce Binding
Nonce is strictly derived:

nonce = epoch(4 bytes) || seq(8 bytes)
and payload may prefix nonce to enforce strict equality.

Repro Commands
Bench (rekey throughput)
bash
コードをコピーする
python3 -m bench.bench_rekey155
Example observed result (your run):

loops: 2000

warmup: 50

elapsed_sec: 0.051733

ops_per_sec: 38660.4 rekey/s

final_epoch: 2051

Fuzz (state machine / malformed input robustness)
bash
コードをコピーする
python3 -m fuzz.fuzz_rekey155 --cases 300 --steps 2000 --seed 1
Example observed result (your run):

cases: 300

steps/case: 2000

mutate_prob: 0.15

result: OK

Honest interpretation (for labs / companies)
Bench/Fuzz results do not prove cryptographic security

They do validate:

state machine integrity (including rekey inflight constraints)

epoch/seq/nonce consistency checks

safe failure behavior (close on mismatch)

robustness against malformed frames

Folder Responsibilities (high-level)
protocol/

session state machine (epoch/seq/nonce)

rekey + close (control frames)

handshake glue (Stage155: dev handshake)

transport/

MessageFrame binary format

async stream I/O helpers

crypto/

algorithm agility boundaries (sig/kem/aead/kdf)

keysources/

QKD and KEM key sources (hybrid policy)

bench/

micro-benchmark entry points

fuzz/

fuzz harness entry points

tests/

minimal protocol invariants (epoch/seq/nonce/rekey/close)

Documentation
Specification: SPEC_155.md
Threat model, goals, messages, state machine, crypto swap points, reproducibility.

(Optional) Architecture diagram:

ARCHITECTURE_155.md and/or ARCHITECTURE_155.png/svg

License
MIT License © 2025 Motohiro Suzuki
(See file headers and repository license if included.)