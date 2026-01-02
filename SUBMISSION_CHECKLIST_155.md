SUBMISSION_CHECKLIST_155.md

Stage155 | QSP v1.0 (Research Grade) – Submission Checklist

1. 研究グレードであることの明示（最重要）

 本成果物は 研究用プロトタイプ である

 実運用での安全性の証明や暗号強度の保証を主張しない

 bench / fuzz は 実装健全性の検証 であり、
セキュリティ証明ではない

統一表現（SPEC / README / ARCHITECTURE で一致）：

本成果物は研究用プロトタイプであり、
実運用での安全性の証明や暗号強度の保証を主張しない。

2. 実装スコープの明確化（誤解防止）

 Handshake は dev 段階（nonce 交換）

 署名 / KEM / QKD は 完全統合前

 本段階の主眼は 状態機械・epoch / nonce / rekey 設計

参照：

SPEC_155.md（Threat model / State machine）

ARCHITECTURE_155.md（責務分離・差し替え点）

3. プロトコル要素の整理確認

 フレーム種別が3文書で一致している

FT_HANDSHAKE

FT_APP_DATA

FT_REKEY

FT_CLOSE

 Rekey ルールが一致している

server-led

inflight 禁止

epoch mismatch → close

4. bench / fuzz の位置づけ（数値の意味）

 bench は 性能参考値（例：rekey throughput）

 fuzz は 不正入力耐性・状態機械健全性 の確認

 「安全性証明ではない」旨を明記

再現コマンド：

python3 -m bench.bench_rekey155
python3 -m fuzz.fuzz_rekey155 --cases 300 --steps 2000 --seed 1

5. 提出時の想定読者

 大学・研究機関（設計思想の確認）

 企業（将来の差し替え可能性の確認）

 実装レビュー（状態機械・責務分離）

まとめ

本リポジトリは
「研究として読める」「誤解を生まない」
状態で提出可能である。