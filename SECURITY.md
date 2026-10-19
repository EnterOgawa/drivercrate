# Security Policy

## 脆弱性の報告

未公開の脆弱性は、公開 Issue へ詳細を投稿せず、GitHub の
[Private vulnerability reporting](https://github.com/EnterOgawa/drivercrate/security/advisories/new)
から報告してください。機密性のある端末情報、hardware ID、serial number、認証情報、完全な
ログは添付しないでください。再現に必要な最小情報へ一般化してください。

GitHub の非公開報告機能を利用できない場合は、機密情報を含めずに「非公開の連絡経路が必要」
という Issue を作成してください。

## 対象バージョン

公開済みの最新リリースだけを修正対象とします。0.x は初期開発版であり、API と UI は互換性を
保たず変更される場合があります。

## セキュリティ境界

DriverCrateはWindows Update Agent、Windows Driver Store、実装済みの公式vendor catalogを使用する
ローカル管理者アプリです。Windows Update、WSUS、Windowsの署名検証、組織ポリシーを迂回しません。
次は脆弱性報告の対象です。

- 表示していない更新を選択またはインストールできる状態不整合
- 古い scan session や偽造 identity の受理
- 更新 metadata による UI 境界の改変、memory corruption、任意コード実行
- torrent/P2P、未文書の外部通信、secret または端末識別子の漏えい
- UAC、Windows Update policy、署名検証を迂回する挙動
- 公式allowlist外hostへの接続、redirect追跡、未検証publisherの実行

Windows Update/WSUSやvendor公式service自体の障害、driver固有の不具合、管理者が承認した更新の
内容はDriverCrateの制御範囲外です。ただしDriverCrate側の処理が被害を拡大する場合は報告対象です。
