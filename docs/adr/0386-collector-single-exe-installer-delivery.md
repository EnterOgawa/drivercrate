# ADR 0386: 収集用setupの最終配布形式を単体セットアップEXEとする

- 状態: 採用。以下の未実装記述は決定時の履歴であり、後続ADR0387〜0389で単体EXEを実装・ローカル生成し有限受入した。変更後の公開snapshot/配布物再受入は別条件。
- 決定日: 2026-10-20
- 対象工程: G13-I7r231h15s11b3bvq2。後続の設計・実装・検証はs11c2/c3/c4へ分離する。

## 決定

利用者の最新指示「最終的には収集用インストーラーもexe方式としてほしい。」に従い、
一般利用者向けの最終収集setupは、単体でdownloadできるWindows x64セットアップEXEとする。
配布名は仮に`DriverCrateCollectorSetup-<version>-windows-x64.exe`とし、実装時に確定する。
利用者による手動ZIP展開、`Install.cmd`、開発環境、外部Pythonの事前準備を導入の必須手順にしない。

収集本体、必要なruntimeとlicense/notice、初期台帳・索引を含む可搬dataを同梱する。
初期研究dataを公開可能な署名索引、実端末への適合確認、導入許可へ読み替えない。
既存のpackage検証、新規配置、保護workspace、移設・再開処理を再利用する計画とし、
ZIPの拡張子変更や既存の通常buildの`DriverCrateCollectorSetup.exe`を提示しただけで完成としない。
ZIPは開発検証用または内部形式として残してよいが、最終導入の必須手順にはしない。

自己解凍方式、embedded resource方式、builder/framework等の実装選定は本ADRでは固定しない。
本決定による第三者依存の追加は行わず、後続設計で配布条件と既存検証との接続を確認する。

## 安全境界

署名秘密鍵、credential、端末固有の保護stateを同梱しない。移設先では既存契約に従って
検証・importし、保護storeを初期化する。待機・失敗・予算の来歴と明示再開を維持する。
setupの導入だけでは収集開始、規約同意、Task登録、GitHub認証・公開を暗黙に実行せず、
それぞれの操作に必要な明示確認へ結合する。

Windows x64の検証、UAC、Defender、ACL、hash・署名、payload閉集合、license/notice検証を弱めない。
検証済みの同梱内容だけを安全な作業領域から扱い、配置先や既存設定を検証回避のために変更しない
具体設計は後続工程で行う。EXE方式の採用自体をこの安全性の実装・受入と表現しない。
公開・実配布は別の明示承認を要する。

## 現在の成果物との差

2026-10-18の未署名v5/x64 previewはZIPと`Install.cmd`による配布形態であり、通常buildには
native `DriverCrateCollectorSetup.exe`が存在する。必要な内容をまとめた単体配布EXEは
未実装・未生成・未受入である。

既存ZIPの同一PCでの配置・検査、非通信初期化、停止export/import、人工中断からのresume、
解除・設定/seed保持の有限受入はそのまま保持する。現通常ReleaseのSetup/CollectorとZIP同梱版は
hashが異なり、ZIPには最新の日次pipelineとTask登録入口が含まれない。単体EXE化、
最新機能を含むpackage更新、実日次運用、別PCの実受入を完了済みにはしない。
これは決定時の現物比較であり、原状態報告は保守側に保持する。現公開契約は本書と
[ADR0387](0387-collector-embedded-bootstrap-and-local-index.md)以後、再現入口は同梱builder/installer試験とする。

## 後続の完了条件

- s11c2: 同梱範囲、検証・作業領域・配置・解除・保持、同意境界、実装方式を設計する。
- s11c3: 受入済みの最新日次機能を含む単体EXEを実装・生成し、実装と生成を記録する。
- s11c4: 内容・改変拒否、配置・解除・data保持、最新日次内容の同梱、外部Python等の準備不要、
  未同意の収集/Task/公開開始拒否を有限に検証する。同一PCの確認と別PCの実受入を別に記録する。

以上の後続工程は決定時には未着手だった。現在の有限受入範囲はADR0387〜0389を参照する。
本ADRは方針記録であり、source変更、build、package生成、起動、Task操作、実配布は行わない。
