# ADR 0392: 収集用アンインストールの所有Task解除

- 日付: 2026-10-21
- 状態: 実装前契約。G13-I7r249u1〜u4、主担当確認はu5。

## 契約

利用者の解除依頼に従い、native setupの明示uninstallへTask Schedulerの解除を接続する。
配置時の自動登録は追加しない。既存の本番Daily229／Smoke229を今回の試験で変更しない。

対象名は既存登録scriptのroot folder内Daily229／Smoke229の二つに限定するが、名前だけでは削除しない。
導入済みv6 packageへ結合した登録／local Action切替後、登録scriptが保護root直下へ固定名の所有receiptを
新規保存する。schema、絶対package root、package manifest hash、Task path、登録後XMLの
Settings/Enabledだけをtrue／falseへ置換した二つのXML hash、owner/group/DACLのSDDL hashを結合する。
明示local Action切替はDisabledで終了するため、その後の別途明示Enableと解除後の再実行を同じ
所有pinで照合する。他の設定や日程の変更を許可しない。
receiptとrootはSYSTEM／Administratorsだけをowner／write許可する通常file／directoryであり、
reparse・hardlink・非保護ACL・不明fieldを拒否する。管理者の悪意や同時変更からの隔離は保証しない。
旧receiptの後付け生成や既存Taskの暗黙adoptは行わない。登録後receipt保存失敗は登録失敗として表示し、
Taskを自動削除／停止せず、未所有として保持する。

native解除は管理file削除前に全対象をread-onlyで事前検査する。所有TaskのXML／SDDLを照合し、
running／queued／instanceありなら中止する。全Task事前検査後に各対象を再照合し、Enabledだけを
falseにして自然起動を抑止し、予め固定したdisabled XMLとSDDL、running instanceなしを再確認して
DeleteTask(0)を呼ぶ。Stop／Runは呼ばない。削除後の不存在を確認するまでprogramを削除しない。
disable後失敗や一部だけ削除された場合もreceipt／program／dataを保持し、再実行は保存済みdisabled
hashと既に不存在の対象を受理する。元のEnabledを自動復帰しない。

未所有の同名Taskは削除しない。Task XMLがこのpackage rootを参照する場合は旧所有不明として解除を
止め、別の明示手順が必要と表示する。他のrootの同名Taskは保持する。Task取得の権限／COM／不明な
失敗を不存在へ変換しない。現在の登録contract外の別名／別folder Taskの探索・解除は対象外である。
固定rootの文字列表現の別名・管理者の同時変更を完全には検出できない。Task Schedulerには削除の
compare-and-swapがないため、同時にTask管理操作を行わないことを前提にする。

設定・seed・work・未知file・待機／安全state・自己setupと解除入口を保持する。Task確認失敗時は
管理fileを一件も削除しない。既存のfile削除途中失敗の自動rollback／完全再開は今回追加しない。

## 有限な検証と配布

u2は上記のnative共通policy／COM adapter／登録receipt保存を実装する。
u3はfake schedulerで所有成功、不存在、非所有、receipt／XML／SDDL改変、running／queued、
権限／取得／disable／削除／readback失敗、一部削除後の再実行とfile削除順序を検査する。
変更targetを唯一buildのDebug／Releaseでbuildし、関連回帰とformat／comment／script gateを確認する。
実Taskの登録／解除試験は行わず未確認とする。u4は新outへ収集用EXEとsource候補を生成し、
全payload／manifest／licenseと秘密／運用state非混入を確認する。旧成果物の受入を新byteへ転用しない。
公開snapshot自身の全target初回受入、実公開と署名は別工程である。

## 一次仕様

- [IRegisteredTask](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-iregisteredtask)
- [GetInstances](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iregisteredtask-getinstances): 管理者contextで全instanceを取得する。
- [GetSecurityDescriptor](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iregisteredtask-getsecuritydescriptor)
- [DeleteTask](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-deletetask): flagsは0、失敗HRESULTを保持する。
