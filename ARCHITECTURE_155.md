# ARCHITECTURE_155.md
MIT License © 2025 Motohiro Suzuki

## Stage155 | QSP v1.0 (Research Grade)  
### Architecture Overview（提出用・設計全体図）

---

## 1. 目的と位置づけ

Stage155 は **QSP v1.0（Research Grade）Release Candidate** として、
以下を満たすことを目的とする研究用プロトコル設計・実装である。

- PQC（署名・KEM）と QKD を **役割分離・可換設計** で統合
- AEAD により保護されたデータフレームおよび制御フレーム
- Epoch / Seq に基づく安全な Rekey 遷移
- bench / fuzz による **実装健全性の検証**

> **注意**  
> 本成果物は研究・設計検証を目的としたものであり、  
> 実運用における安全性の証明や正式な暗号評価を主張するものではない。

---

## 2. 全体アーキテクチャ（1枚図）

```mermaid
flowchart LR
    subgraph API
        RS[run_server155.py]
        RC[run_client155.py]
    end

    subgraph Protocol
        PC[ProtocolCore]
        SM[State Machine]
        HS[Handshake]
        RK[Rekey]
        SS[Session]
    end

    subgraph Crypto
        SIG[Signature]
        KEM[KEM]
        AEAD[AEAD]
        KDF[HKDF]
    end

    subgraph KeySources
        QKD[QKD E91]
        PQC[PQC-KEM]
        HYB[HybridKeySource]
    end

    subgraph Transport
        IO[AsyncFrameIO]
        MF[MessageFrame]
    end

    RS --> PC
    RC --> PC

    PC --> SM
    PC --> SS
    SM --> HS
    SM --> RK

    HS --> SIG
    HS --> KEM
    HS --> QKD

    RK --> KDF
    SS --> AEAD

    HYB --> QKD
    HYB --> PQC
    PC --> HYB

    PC --> IO
    IO --> MF
3. レイヤ構造と責務分離
api/
サーバ・クライアント実行入口

デモおよび再現手順の最小単位

例: run_server155.py, run_client155.py

protocol/
プロトコル中核ロジック

状態機械・ハンドシェイク・Rekey 制御

主要構成:

ProtocolCore

Session

handshake

rekey

errors

crypto/
暗号アルゴリズム抽象化レイヤ

差し替え可能な境界

署名（sig）

KEM

AEAD

HKDF（KDF）

keysources/
鍵供給の責務を集約

QKD / PQC-KEM / Hybrid を分離

「鍵をどう得るか」と「どう使うか」を明確に分離

transport/
フレーム入出力とシリアライズ

プロトコル本体から I/O を隔離

tests/
単体テスト・状態検証

bench/
性能評価（例：rekey throughput）

正常系パスの速度・安定性確認

fuzz/
乱択入力による状態遷移健全性検証

異常系での close / error handling 確認

repro/
実行ログ・再現条件・依存関係の記録

vendor/
外部依存（将来の PQC / QKD 実装差し替え用）

4. メッセージ種別と状態機械
フレーム種別
FT_HANDSHAKE
認証・鍵合意（dev段階では nonce 交換）

FT_APP_DATA
AEAD で保護されたアプリケーションデータ

FT_REKEY
AEAD で保護された制御フレーム（epoch 遷移）

FT_CLOSE
正常終了 / エラー終了通知

状態遷移
scss
コードをコピーする
Handshake
   ↓
Established
   ↓ (server-led)
Rekey
   ↓
Established
   ↓
Closed
Epoch 不一致、AEAD 失敗時は 即 FT_CLOSE

Rekey 中の多重開始は拒否（inflight 制御）

5. Crypto Suite の差し替え点（重要）
Stage155 の中核設計思想は Algorithm Agility にある。

要素	レイヤ	差し替え方法
Signature	crypto/sig	backend 切替
KEM	crypto/kem	backend 切替
QKD	keysources	実装差替（stub → 実機）
AEAD	crypto/aead	実装差替
KDF	crypto/kdf	HKDF 派生変更

差し替えは protocol 層に影響を与えない設計とする。

6. v1.0 実装要件との関係
署名：Handshake 認証点として位置づけ

KEM：耐量子鍵供給の一要素

QKD：追加鍵源（単独使用しない）

KDF：QKD + KEM の混合点

AEAD：APP_DATA / REKEY / CLOSE を一貫して保護

7. 再現・検証への導線
仕様定義：SPEC_155.md

実行手順：README.md

性能評価：bench/

健全性検証：fuzz/

本アーキテクチャ文書は
「設計の読み物」 として SPEC / README を補完する役割を持つ。

8. まとめ
Stage155 は、

プロトコル構造が読める

差し替え点が明確

bench / fuzz により実装健全性を確認済み

という点で、
研究機関・企業・大学への提出に耐える設計ドキュメント一式 を構成する。

以上。