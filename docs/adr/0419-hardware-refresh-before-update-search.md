# ADR 0419: 通常更新検索の前にWindowsハードウェア再検出を一回行う

- 日付: 2026-10-28
- 状態: 採用、実装前決定。内部検証と通常実機受入を分離する。
- 対応: G13-I7r266b、ADR0416/0418を維持。

## 背景

利用者は通常「更新を検索」の前にハードウェア変更scanを要求した。既存のPnP現在属性列挙は
Windowsに再検出を要求する処理ではない。574/575のfresh検索ではEthernet二件の名前fallbackが
動作しており、元画像の名称未確認二行と固定二NICの対応・元画像原因は未確定のままである。

## 決定

通常UIの開始承認後、既存workerのScanCommandで旧session/選択/準備権限を失効し、
Windows root再検出→現在PnP inventory再列挙→既存更新検索を直列実行する。別button/設定や
メーカー別分岐を増やさない。内部再監査、取得時適合検査、metadata専用検索、導入後のread-only確認へ
再検出を追加しない。UI threadで同期PnP APIやprivilege操作を行わない。

`CM_Locate_DevNodeW(..., nullptr, CM_LOCATE_DEVNODE_NORMAL)`でlocal rootを取得し、
`CM_Reenumerate_DevNode(root, CM_REENUMERATE_SYNCHRONOUS)`を一回だけ呼ぶ。
ASYNCHRONOUS/RETRY_INSTALLATION、無条件retry、全PnP安定化待機は追加しない。
同期完了はdevice stackへの要求の完了を表し、bus更新報告・全device出現/開始・driver導入完了を
保証しない。Windows自身が行う構成/自動適用は、DriverCrateの明示選択導入の成功とは別である。

必要なSeLoadDriverPrivilegeは、現在process tokenに既に存在する権限だけを一時的に有効化する。
AdjustTokenPrivilegesのBOOLだけで成功にせず、ERROR_NOT_ALL_ASSIGNEDも明示失敗とし、
保存したPreviousStateで元の属性へ復帰しtoken HANDLEを閉じる。既に有効なら元のまま保持する。
主処理と復帰のerrorを別々に保持する。UAC/ユーザー権利割当/Group Policy/Driver Store/WUAの
設定を回避・変更しない。権限がない場合に別tokenへ昇格・再試行しない。

再検出や権限復帰に失敗した場合は、要求した前提段階が不成立なので後続検索を停止する。
既存失敗結果・dialogへ渡し、更新なし/最新へ変換しない。結果には失敗段階、元error domain
(CONFIGRET/Win32/HRESULT)と元値、復帰errorを保持する。成功事実も同operationの完了DTOに保持し、
既存status帯で確認可能にする。新ログ基盤は設けない。

取消し/closeは既存operation信号を利用する。同期APIを強制中断せず、呼出し前と復帰後で取消しを
観測し、後続Providerを開始しない。 未開始queueの通常ScanCommandも、再検出seamの有無によらず
Provider開始前に取消しを確定する。内部再監査はこのcommandを通さない既存の直呼出しであり、
その取消し/列挙契約へ変更を入れない。旧完了は既存operation照合で不適用とし、新検索は新sessionで
再列挙する。同時実行は既存controller/worker直列化を維持する。

進捗はhardware 0/1→1/1を0→5%、既存Provider 5→90%、索引90→99%、終端100%とする。
処理待ちだけで増加させず、通常検索中の高水位で後退を防ぐ。再検出未実行の内部fixtureでは
従来のProvider 0→90%を維持する。

production二引数worker constructorだけがnative callbackを設定する。Providerを差し替える
既存test constructorと内部AccessのServicesは空をnativeへ補完しない。新native処理は完全な
低位transport表で試験し、欠損表/実API混在を拒否する。unit/UIから実CM/権限変更を呼ばない。

未取得metadataは導入候補数/checkboxへ昇格せず、「取得準備」で内容・適用性検査後に選択できることを
既存statusへ案内する。未知deviceを推測で隠さず、FriendlyName欠損時DeviceDesc名とCode28を保持する。

## 一次資料

- [CM_Reenumerate_DevNode](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_reenumerate_devnode): flags、同期保証範囲、SeLoadDriverPrivilege、CONFIGRET。
- [CM_Locate_DevNodeW](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_locate_devnodew): nullptrによるlocal root取得とCONFIGRET。
- [AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges): 既存権限のみ、ERROR_NOT_ALL_ASSIGNED、PreviousState復帰。

## 検証と限界

完全fakeでAPI順/一回性/権限なし/CONFIGRET/復帰失敗/取消し、workerの再検出→inventory→query、
連続scanの更新/旧session拒否、UI進捗/metadata案内を有限確認する。実機の通常再検出と
Windows自動反映は266cで主担当受入後に確認する。実装・人工fixture成功を実機成功へ継承しない。
