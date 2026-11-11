# Release checklist — DriverCrate 1.0.6 App

対象は利用者向けAppとApp用Setupだけです。私有Collector/収集用Setup/定義/registry、driver本体や実端末情報は公開しません。
この一覧は工程条件であり、未完了項目を過去版の成功で埋めません。最新のrelease指示は必要なsource push/tag/Release登録を含み、
既存Publicへの反映のための汎用再承認flowは追加しません。新たなvisibility変更は別判断です。

変更点は[1.0.6のリリースノート](release-notes-1.0.6.md)に記載します。

## Sourceと検証

- [ ] CMake正本、VERSIONINFO、package、Release title、tag v1.0.6を一致させる。
- [ ] consumerの明示集合についてpath/mode/checkout byte/SHA-256、include/fixture/文書link、license/noticeを固定する。
- [ ] 私有source/registry/定義、work、鍵、credential、inventory、driver、build/PDB、個人絶対pathを除外する。
- [ ] 公開mainの既履歴を親として保持する。Private履歴の混入・force・root作り直しをしない。
- [ ] 最終snapshot自身から唯一buildでfresh x64 Debug/Releaseのconsumer全targetと固定したunit/UI/関連Python/PSを確認する。
- [ ] format/source規約/DoxygenとRelease静的解析を確認し、原失敗・未実施を保持する。
- [ ] 通常公開profile/公開鍵/policy、実導入同意・復旧・失効・privacyを維持する。

## 署名と配布

- [ ] snapshot/source/cacheの結合を保ち、最終Appの原byte/profileを受入する。
- [ ] 指定SDK hash・証明書・chainを検査し、既helperのApp roleで署名する。秘密鍵をexportせずPINを保存しない。
- [ ] 署名以外の原byte保持、指定signer、時刻証明、WinVerifyTrustを確認する。
- [ ] 公開snapshot自身のpackage-app-setup.ps1から署名App/profile・公開README/NOTICE・App用issを包装する。Private側scriptとの混成を避ける。
- [ ] Inno SignTool/SignedUninstallerで内部engine/解除EXEとouterを署名し、通常user用Setupの版・発行元・署名・5file展開を確認する。内部PEへAppのAMD64 gateを流用しない。
- [ ] 署名後App/profile/shaを一致させ、五fileだけのZIPを展開照合して最終checksumを計算する。
- [ ] Setup/ZIPのREADME画像・guideを同版tagのURLへ解決し、source版の相対参照も維持する。
- [ ] output直下の固定名を更新し、旧変更byteを外へ保全する。私有配布物と実行時logは保持する。
- [ ] 候補配布物を保全後、唯一buildを通常source/optionsへ戻してD/R復帰を確認する。失敗時もfinallyで復帰する。

## 公開とreadback

- [ ] source/配布物/必要検証と未確認を主担当が受入する。署名前の実績を署名後の実導入成功へ換算しない。
- [ ] 通常commit/pushと明示tagを行い、--verify-tag付きdraft Releaseへ検証済みSetup/checksum・ZIP/checksumの四assetの明示pathを添付する。
- [ ] draftの四assetのsize/SHA-256を照合してから正式latestへ公開する。未完成のlatestや既v1.0.4/v1.0.5の変更を行わない。
- [ ] commit/tag/Release/version/asset byteとSHA-256をremoteから確認する。output/*、--clobber、不確定操作の盲目的retryは使わない。

全台帳の同時fresh成功、七日自然運用、全機器への実導入、別PC移設は今回App Releaseの一律前提にしません。
索引の原署名/hash/期限・既公開asset/authorityは維持します。
