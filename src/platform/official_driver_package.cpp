//------------------------------------------------------------------------------
/**
 * @file official_driver_package.cpp
 * @brief 公式標準INF driver package検証実装
 * @version 02.09.03
 * @date 2026/09/03
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CAT member／PnP照合追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  DriverVer日付取得追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  INF signature allowlist追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  参照file埋込み署名検証追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用Provider名検証mode追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  SYS不要printer構造policy追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  圧縮実行program拒否追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  選択的driver閉包policy追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  INF section必要文字数の型修正
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  INF解析のstack使用量を削減
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Windows検証済みsignerの共通署名policyを追加
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  明示依存の存在観測を内容署名から分離
 * Ver.01.03.00 Shunji Ogawa  2026/10/04  無作用の空CoInstaller参照だけを有限検査で受理
 * Ver.01.04.00 Shunji Ogawa  2026/10/05  非実行参照棚卸しと導入検査を別契約に分離
 * Ver.01.05.00 Shunji Ogawa  2026/10/05  保守参照の先頭現在directory表記だけを正規化
 * Ver.01.05.01 Shunji Ogawa  2026/10/05  空sourceでもINF自身のCAT member検証を必須にする
 * Ver.01.06.00 Shunji Ogawa  2026/10/05  保守参照棚卸しで両方の標準INF識別子を受理
 * Ver.01.07.00 Shunji Ogawa  2026/10/05  非圧縮EXEだけを保守参照byteとして限定受理
 * Ver.01.08.00 Shunji Ogawa  2026/10/05  選択導入処理の非実行作用・参照棚卸しを追加
 * Ver.01.09.00 Shunji Ogawa  2026/10/05  実測した節容量停止へ有限な共通棚卸し拡張を追加
 * Ver.01.10.00 Shunji Ogawa  2026/10/06  選択処理の未解釈範囲を有限な不足観測へ分離
 * Ver.01.11.00 Shunji Ogawa  2026/10/07  保守専用の全現在OS選択と厳密null service構造を解析
 * Ver.01.12.00 Shunji Ogawa  2026/10/07  有限行読取と明示seedからのfile位置棚卸しを追加
 * Ver.01.12.01 Shunji Ogawa  2026/10/07  keyなし登録行の禁止marker検査とAddSoftware拒否を補う
 * Ver.01.13.00 Shunji Ogawa  2026/10/07  保守named serviceの必須構造と限定null認定を分離
 * Ver.01.14.00 Shunji Ogawa  2026/10/07  保守binaryの展開済み位置を明示named導入先と元sourceへ限定照合
 * Ver.01.14.01 Shunji Ogawa  2026/10/07  同HINF named13の非absolute展開を不正へ変換せず未対応保持
 * Ver.01.15.00 Shunji Ogawa  2026/10/07  一意な到達named13の相対全targetを同名・同subdirの元sourceへ限定接続
 * Ver.01.16.00 Shunji Ogawa  2026/10/08  同行eventlogの独立子Uを保持した最終参照だけでサービス名markerを分離
 * Ver.01.17.00 Shunji Ogawa  2026/10/08  同元byteと全値・一意callerを証明した単一EventMessageFile位置を遅延接続
 * Ver.01.18.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続
 * Ver.01.19.00 Shunji Ogawa  2026/10/13  元現在OS選択のCopyINFと必要SWC関係を役割別に検査
 * Ver.01.20.00 Shunji Ogawa  2026/10/13  Windows元node基本名からdevice別必要構成を解析
 * Ver.01.21.00 Shunji Ogawa  2026/10/13  必要SWCのWin32 service参照EXEを同INFのコピーとsourceへ限定
 * Ver.01.21.01 Shunji Ogawa  2026/10/13  展開済みServiceBinaryを同HINFの完全copy宛先へ照合
 * Ver.01.21.02 Shunji Ogawa  2026/10/13  サービス節の列挙異常時に部分EXE集合を破棄
 * Ver.01.22.00 Shunji Ogawa  2026/10/13  必要Win32 serviceの位置付きsourceと標準DIRID・正式flagsを限定接続
 * Ver.01.23.00 Shunji Ogawa  2026/10/13  同INF媒体とfile相対位置を共通readerで内容検査へ結合
 * Ver.01.24.00 Shunji Ogawa  2026/10/13  元媒体位置readerを選択Needs payload検査と共用
 * Ver.01.25.00 Shunji Ogawa  2026/10/14  元Models節と公開ID種別の同INF読取りを追加
 * Ver.01.26.00 Shunji Ogawa  2026/10/14  同Windows INF/CAT検査から実publisherの非許可metadataを追加
 * Ver.01.27.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続
 * Ver.01.28.00 Shunji Ogawa  2026/11/03  標準Componentのnull・コピー・Type1とSystem device serviceを検査
 * Ver.01.29.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.30.00 Shunji Ogawa  2026/11/05  同元CoInstallerと非実行Type1内容検査を必要参照へ結合
 * Ver.01.31.00 Shunji Ogawa  2026/11/06  Windows管理driver付属DATAと原source位置の非実行検査を追加
 * Ver.01.32.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続
 * Ver.01.33.00 Shunji Ogawa  2026/11/10  明示client targetと同INF hashのModels観測を結合
 * Ver.01.33.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.33.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.33.03 Shunji Ogawa  2026/11/13  元適用性errorへ固定失敗leafとcode由来だけを接続
 * Ver.01.33.04 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.34.00 Shunji Ogawa  2026/11/15  opaque IDと正式storage内容・全潜在null importを導入資格から分離
 * Ver.01.35.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.36.00 Shunji Ogawa  2026/11/16  MTD正式対と目的別root境界を追加
 * Ver.01.37.00 Shunji Ogawa  2026/11/17  MTDの全原COPY行とCAT memberを保持
 * Ver.01.38.00 Shunji Ogawa  2026/11/17  TapeDriveの正式Class名とGUIDの一意対を検査
 * Ver.01.39.00 Shunji Ogawa  2026/11/17  宣言Server scopeとpolicy・Models・identityを分離接続
 * Ver.01.40.00 Shunji Ogawa  2026/11/18  Models一SDKだけの非公開単独thread fixtureを追加
 * Ver.01.40.01 Shunji Ogawa  2026/11/18  正規Strings空値と限定System nullの明示空source節を区別
 * Ver.01.41.00 Shunji Ogawa  2026/11/18  CopyINF由来の限定registry-only内容と通常導入拒否を分離
 * Ver.01.41.01 Shunji Ogawa  2026/11/18  必須collectorの単独コメントだけで1-byte原文の非ASCIIを不透明に保持
 * Ver.01.42.00 Shunji Ogawa  2026/11/18  明示client Modelsの観測点へ26200を限定追加
 * Ver.01.43.00 Shunji Ogawa  2026/11/19  収集元のデバイス別プロパティページを実Modelsと同じコピーへ結合
 * Ver.01.44.00 Shunji Ogawa  2026/11/19  表示用の独自クラス登録を収集と端末内容検査で確認
 * Ver.01.45.00 Shunji Ogawa  2026/11/19  AMD64向け全導入節から使用する媒体ファイルを確認
 * Ver.01.46.00 Shunji Ogawa  2026/11/19  Windowsの選択行を同じ元Modelsの節とIDで確認
 * Ver.01.47.00 Shunji Ogawa  2026/11/19  選択された元クラス節の表示名と内蔵アイコンを読み取る
 * Ver.01.48.00 Shunji Ogawa  2026/11/19  独自クラスの読取りを同じworkerの完全API表で行う
 * Ver.01.49.00 Shunji Ogawa  2026/11/20  収集のINF作用調査に共有節訪問と長いバイナリ値の有限枠を設定
 * Ver.01.50.00 Shunji Ogawa  2026/11/20  空媒体のSDHostをWindows標準INFの収集依存検査へ接続
 * Ver.01.51.00 Shunji Ogawa  2026/11/20  Windows標準Portsのプロパティページを元基本節の所有に限定
 * Ver.01.52.00 Shunji Ogawa  2026/11/20  標準NVMeを参照する原SCSIAdapterの空媒体と選択節を照合
 * Ver.01.53.00 Shunji Ogawa  2026/11/20  収集時の標準メディアチェンジャーの原作用を検査
 * Ver.01.54.00 Shunji Ogawa  2026/11/21  収集時の一意行数と延べ読取行数を分けて制限
 * Ver.01.55.00 Shunji Ogawa  2026/11/21  収集で標準AHCIへ委譲する元HDCの空媒体と三節を照合
 * Ver.01.56.00 Shunji Ogawa  2026/11/21  正式メディアチェンジャーの端末選択内容を検証
 * Ver.01.57.00 Shunji Ogawa  2026/11/21  元SYSを持つHDCの収集用選択とコピーを照合
 * Ver.01.58.00 Shunji Ogawa  2026/11/21  元SYSを持つHDCを管理者領域の実選択検査へ接続
 * Ver.01.59.00 Shunji Ogawa  2026/11/21  署名済みSCSIAdapterの単独コピー警告を元コピー照合へ接続
 * Ver.01.60.00 Shunji Ogawa  2026/11/21  HDCの元AMD64 Modelsから基本節とServicesを照合
 * Ver.01.61.00 Shunji Ogawa  2026/11/21  CopyINFの有効な参照に続く末尾空フィールドを区別
 * Ver.01.62.00 Shunji Ogawa  2026/11/21  自己媒体Portsの元SYSと標準プロパティページを識別
 * Ver.01.63.00 Shunji Ogawa  2026/11/22  Modelsの原順と種別を保った一意ID検索を改善
 * Ver.01.64.00 Shunji Ogawa  2026/11/22  公式対象と元Models全行の読取り証拠を生成
 * Ver.01.65.00 Shunji Ogawa  2026/11/22  元CAT所属を確認した収集INFにModelsの別計数を接続
 * Ver.01.66.00 Shunji Ogawa  2026/11/22  公式対象のWindows導入節を有限な作用棚卸しへ接続
 * Ver.01.67.00 Shunji Ogawa  2026/11/22  公式Net対象のイベント参照を同じSYSとWindows標準DLLへ結合
 * Ver.01.68.00 Shunji Ogawa  2026/11/22  公式Modelsの別用途と物理PCI Ethernet属性・全ファイル用途を検査
 * Ver.01.69.00 Shunji Ogawa  2026/11/22  元Modelsと保存証拠の共通上限を参照
 * Ver.01.70.00 Shunji Ogawa  2026/11/22  公式対象の元Modelsと署名済みINFの一意ClassGUIDを結合
 * Ver.01.71.00 Shunji Ogawa  2026/11/22  Windows選択nodeを現OSの一意な公式Models行へ照合
 * Ver.01.72.00 Shunji Ogawa  2026/11/22  照合済みの公式Models行から導入節と必要関係を取得
 * Ver.01.73.00 Shunji Ogawa  2026/11/22  公式Netの実選択と同じ媒体・サービス・標準DLLを再検査
 * Ver.01.74.00 Shunji Ogawa  2026/11/22  公式Netの元選択の同梱Needsを局所欠落と区別
 * Ver.01.75.00 Shunji Ogawa  2026/11/22  同一INFの共通レジストリ節の観測を起点間で再利用
 * Ver.01.76.00 Shunji Ogawa  2026/11/22  公式Netの無線LAN拡張と元コピーを収集内で照合
 * Ver.01.77.00 Shunji Ogawa  2026/11/22  公式Netの端末実選択で同梱依存と元媒体を再検査
 * Ver.01.78.00 Shunji Ogawa  2026/11/22  署名済み公式Netの旧登録と不在媒体の逆参照を照合
 * Ver.01.79.00 Shunji Ogawa  2026/11/22  公式無線LANの単一リストコピーと個別設定削除を照合
 * Ver.01.80.00 Shunji Ogawa  2026/11/22  選択SCSIAdapterの要求時起動補助サービスと元署名EXEを照合
 * Ver.01.81.00 Shunji Ogawa  2026/11/23  Systemイベントを指定するストレージ補助サービスの選択範囲を検査
 * Ver.01.82.00 Shunji Ogawa  2026/11/23  自動起動補助サービスの元コピーと署名を読み取り依存検査へ渡す
 * Ver.01.83.00 Shunji Ogawa  2026/11/23  ストレージの実選択から同梱INFへの空ドライバー委譲を読む
 * Ver.01.84.00 Shunji Ogawa  2026/11/23  空ドライバー委譲を現在Modelsとノードの完全ID列に照合
 * Ver.01.85.00 Shunji Ogawa  2026/11/23  選択節のイベントメッセージDLLをSystem32と元CATへ結合
 * Ver.01.86.00 Shunji Ogawa  2026/11/23  固定したストレージ元INFのModels一行と全IDを照合
 * Ver.01.86.01 Shunji Ogawa  2026/11/23  同一の有線Netイベント二資源に続く終端区切りを照合
 * Ver.01.86.02 Shunji Ogawa  2026/11/23  必須System補助INFのドット区切り文字列名を照合
 * Ver.01.86.03 Shunji Ogawa  2026/11/23  必須System補助の原byte検査を既存の本人所有領域に接続
 * Ver.01.87.00 Shunji Ogawa  2026/11/24  収集用Systemの全サービス走査と実行ファイル付き宣言の上限を分離
 * Ver.01.88.00 Shunji Ogawa  2026/11/24  公式CABの不在媒体に同元INFと同梱INFの逆参照検査を接続
 * Ver.01.89.00 Shunji Ogawa  2026/11/24  公式CABの別アーキテクチャ媒体をコピーとサービスの全逆参照に結合
 * Ver.01.90.00 Shunji Ogawa  2026/11/24  公式PCI無線LANの単一コピーにある同CATのSYSとDATを検査
 * Ver.01.91.00 Shunji Ogawa  2026/11/24  元の詳細設定にあるIEEE 802.11ax列挙ラベルを照合
 * Ver.01.92.00 Shunji Ogawa  2026/11/24  収集で無線LANのインターフェース属性と共有ログ設定を照合
 * Ver.01.93.00 Shunji Ogawa  2026/11/24  同梱無線バスの旧名を使う署名済み単一SYSを収集で照合
 * Ver.01.94.00 Shunji Ogawa  2026/11/24  公式USB Bluetoothの空媒体と元選択を収集で照合
 * Ver.01.95.00 Shunji Ogawa  2026/11/24  同梱Needsの検査結果を元のクラスごとに扱う
 * Ver.01.96.00 Shunji Ogawa  2026/11/24  混在シリアルの二選択の元媒体と登録作用を照合
 * Ver.01.97.00 Shunji Ogawa  2026/11/24  混在シリアルで確認した正式クラスを同梱依存検査へ引き継ぐ
 * Ver.01.98.00 Shunji Ogawa  2026/11/24  混在シリアルの公式対象で同じ元導入節を照合
 * Ver.01.99.00 Shunji Ogawa  2026/11/24  不在媒体検査で引用符付きサービスの元値を照合
 * Ver.02.00.00 Shunji Ogawa  2026/11/24  USB無線の選択コピーを元媒体と配置先に照合
 * Ver.02.01.00 Shunji Ogawa  2026/11/24  USB無線の二つの元サービスを同じ選択コピーに照合
 * Ver.02.02.00 Shunji Ogawa  2026/11/24  物理USB無線の属性とWi-Fi 7表示用途を棚卸し
 * Ver.02.03.00 Shunji Ogawa  2026/11/24  選択USB無線の機器登録とイベントと同梱参照を照合
 * Ver.02.04.00 Shunji Ogawa  2026/11/24  USB無線の補助実行ファイルと同梱DLLの直接依存を照合
 * Ver.02.05.00 Shunji Ogawa  2026/11/24  収集専用の独自クラス登録と旧節の参照を検査
 * Ver.02.06.00 Shunji Ogawa  2026/11/24  公式CABの元Modelsと同梱WinUSBへの委譲を照合
 * Ver.02.06.01 Shunji Ogawa  2026/11/24  必須の空サービス補助INFの旧媒体名を照合
 * Ver.02.07.00 Shunji Ogawa  2026/11/24  収集でストレージ基本導入節のプロパティページを照合
 * Ver.02.08.00 Shunji Ogawa  2026/11/24  複数の自己媒体Ports選択と共有標準ページを収集用に照合
 * Ver.02.09.00 Shunji Ogawa  2026/11/24  表示用独自クラスの単一KMDFドライバーを収集で照合
 * Ver.02.09.01 Shunji Ogawa  2026/11/26  前方宣言の関数契約と外部Needsの引数説明を補完
 * Ver.02.09.02 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * Ver.02.09.03 Shunji Ogawa  2026/11/26  同梱INFの列挙値ごとに前置契約を記載
 * </pre>
 *
 * @note SetupAPIをINF構文と現在platformの選択規則の正本とし、外部文字列からpathを直接生成せず、ZIP検証済みentryとの完全一致だけを受理します
 */
//------------------------------------------------------------------------------

#include "platform/official_driver_package.h"
#include "platform/official_inf_models_native_internal.h"
#include "platform/inf_dependency_native_internal.h"
#include "platform/common_driver_package.h"
#include "core/pending_reference_version.h"
#include "platform/collector_property_page_export_internal.h"
#include "platform/driver_package_signature_internal.h"
#include "platform/driver_store_inf_transport_internal.h"
#include <appmodel.h>

#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/official_mapped_file.h"
#include "platform/official_resource_content.h"

#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <objbase.h>
// Class GUIDの実体をこのTUで定義し、別Providerのobject所有へ依存しません
#include <initguid.h>
#include <devguid.h>
#include <Windows.h>
#include <WinTrust.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace drivercrate::official_inf_models_native_detail {
namespace {
thread_local const ScopedFixture *activeModelsFixture{} ;	// 同owner threadの一scopeだけです
}
//------------------------------------------------------------------------------
/**
 * @brief 検証済み一APIを同threadへ排他的に固定します
 * @param[in] calls 完全な低位表です
 */
//------------------------------------------------------------------------------
ScopedFixture::ScopedFixture( const Calls calls) noexcept
	: ownerThread_( GetCurrentThreadId()), calls_( calls)
{
	activeModelsFixture = this ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同owner threadの低位表だけを解除します
 * @note 別thread破棄は契約違反として終端し、dangling表を使用しません
 */
//------------------------------------------------------------------------------
ScopedFixture::~ScopedFixture() noexcept
{
	// 異threadや所有の差替えを解除成功へ補完しません
	if( GetCurrentThreadId() != ownerThread_ || activeModelsFixture != this) {
		std::terminate() ;
	}

	activeModelsFixture = nullptr ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元scopeの完全表を同期借用します
 * @return 本scope生存中の不変表です
 */
//------------------------------------------------------------------------------
const Calls &ScopedFixture::calls() const noexcept
{
	// 他threadからscopeの借用を認めません
	if( GetCurrentThreadId() != ownerThread_) {
		std::terminate() ;
	}

	return calls_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同threadの低位表を非権限で観測します
 * @return scopeがある場合だけその不変表、通常製品ではnullptrです
 */
//------------------------------------------------------------------------------
const Calls *activeCalls() noexcept
{
	return activeModelsFixture ? &activeModelsFixture->calls() : nullptr ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原SDK又は明示scopeの同署名APIを同期呼出しします
 * @param[in] context 原HINFのManufacturer contextです
 * @param[in] platform 原alternate-platformです。NULLの意味を変更しません
 * @param[out] buffer 元SDKの有界受信先です。size queryではnullptrです
 * @param[in] capacity 元bufferの文字数です
 * @param[out] required 元SDKの必要文字数です。null可です
 * @param[in] reserved 元SDKの予約引数です
 * @return 元BOOLです。LastErrorを変換せず、FALSE直後の原値をcallerが保持します
 */
//------------------------------------------------------------------------------
BOOL WINAPI actualModelsSection( PINFCONTEXT context, PSP_ALTPLATFORM_INFO platform, PWSTR buffer,
								const DWORD capacity, PDWORD required, PVOID reserved)
{
	const auto calls = activeCalls() ;	// scope外だけ元SDKを使用します
	return calls ? calls->getActualModelsSection( context, platform, buffer, capacity, required,
												 reserved)
				 : ::SetupDiGetActualModelsSectionW( context, platform, buffer, capacity, required,
													reserved) ;
}
#ifdef DRIVERCRATE_INTERNAL_INDEX_TESTS
//------------------------------------------------------------------------------
/**
 * @brief 欠落/本SDK混入/同thread入れ子を拒否します
 * @param[in] calls 欠落しないfake一関数の表です
 * @return 一owner scope、拒否又は確保不能ではnullptrです
 */
//------------------------------------------------------------------------------
std::unique_ptr<ScopedFixture> Access::create( const Calls calls) noexcept
{
	// 明示fakeの欠落をnative呼出しへfallbackしません
	if( activeModelsFixture || !calls.getActualModelsSection ||
	   calls.getActualModelsSection == &::SetupDiGetActualModelsSectionW) {
		return nullptr ;
	}

	try {
		return std::unique_ptr<ScopedFixture>( new ScopedFixture( calls)) ;
	} catch( ...) {
		return nullptr ;
	}
}
#endif
} // namespace drivercrate::official_inf_models_native_detail

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義
//------------------------------------------------------------------------------

constexpr std::size_t MAXIMUM_INF_FIELD_CHARACTERS	   = 4096U ;	// 一INF fieldの文字数上限
constexpr std::size_t MAXIMUM_MODEL_SECTION_CHARACTERS = 256U ;		// Models section名上限
constexpr std::size_t MAXIMUM_HARDWARE_ID_CHARACTERS   = 256U ;		// 一PnP IDの文字数上限

// Archive内に未参照でも存在を許可しない従来のprogram拡張子群
constexpr std::array<std::wstring_view, 31> REJECTED_UNREFERENCED_PROGRAM_EXTENSIONS{
	L".bat", L".cmd",  L".com",	 L".exe", L".hta", L".js",	L".jse", L".msi",
	L".ps1", L".psd1", L".psm1", L".reg", L".scr", L".vbe", L".vbs", L".wsf",
	L".ba_", L".cm_",  L".co_",	 L".ex_", L".ht_", L".j_",	L".js_", L".ms_",
	L".ps_", L".psd_", L".psm_", L".re_", L".sc_", L".vb_", L".ws_"} ;

// INF閉包から除外するprogram、installer、archive、firmware拡張子群
constexpr std::array<std::wstring_view, 81> REJECTED_REFERENCED_EXTENSIONS{
	L".7z",			L".appx", L".appxbundle", L".bat",	L".bin",   L".bio", L".bz2", L".cab",
	L".cap",		L".cmd",  L".com",		  L".dfu",	L".dfuse", L".efi", L".elf", L".exe",
	L".fd",			L".fls",  L".ftf",		  L".fw",	L".gz",	   L".hex", L".hta", L".ihx",
	L".img",		L".iso",  L".js",		  L".jse",	L".kdz",   L".mbn", L".msi", L".msix",
	L".msixbundle", L".msp",  L".msu",		  L".ofp",	L".ova",   L".ovf", L".pac", L".pit",
	L".ps1",		L".psd1", L".psm1",		  L".qcow", L".qcow2", L".rar", L".reg", L".rom",
	L".scr",		L".sin",  L".tar",		  L".tgz",	L".tot",   L".txz", L".uf2", L".vbe",
	L".vbs",		L".vfd",  L".vhd",		  L".vhdx", L".vmdk",  L".wsf", L".xz",	 L".zip",
	L".ba_",		L".ca_",  L".cm_",		  L".co_",	L".ex_",   L".ht_", L".j_",	 L".js_",
	L".ms_",		L".ps_",  L".psd_",		  L".psm_", L".re_",   L".sc_", L".vb_", L".ws_",
	L".zi_"} ;

constexpr std::array<std::wstring_view, 8> REJECTED_INF_DIRECTIVES{
	L"AddSoftware",			L"CopyINF",
	L"RegisterDlls",		L"RunPostSetupCommands",
	L"RunPreSetupCommands", L"UnregisterDlls",
	L"UpdateInis",			L"UpdateIniFields"} ;	// 実行または外部登録directive

constexpr std::size_t MAXIMUM_INF_SECTIONS = 4096U ;				// 一INFから静的解析するsection数上限
constexpr LONG		  MAXIMUM_EMPTY_CO_INSTALLER_LINES		= 2L ;	// AddRegとCopyFiles各一行の上限
constexpr DWORD		  MAXIMUM_EMPTY_CO_INSTALLER_REFERENCES = 16U ;	// 一指示の空節参照数上限

constexpr std::size_t MAXIMUM_INSTALL_INVENTORY_SECTIONS  = 1024U ;	// 非実行棚卸しの訪問節上限
constexpr std::size_t MAXIMUM_INSTALL_INVENTORY_LINES	  = 4096U ;	// 各走査段階の累積行数上限
constexpr std::size_t MAXIMUM_INSTALL_INVENTORY_ITEMS	  = 4096U ;	// 作用と参照それぞれの保持上限
constexpr DWORD		  MAXIMUM_INSTALL_INVENTORY_FIELDS	  = 64U ;	// 一行の値field数上限
constexpr std::size_t MAXIMUM_COLLECTION_INVENTORY_VISITS = 2048U ;	// 収集の全起点を通じた節訪問上限
constexpr std::size_t MAXIMUM_COLLECTION_INVENTORY_LINES  = 8192U ;	// 収集で実際に読み取る行数の上限
constexpr DWORD		  MAXIMUM_COLLECTION_BINARY_FIELDS	  = 128U ;	// HKRバイナリ行の全field数上限

//------------------------------------------------------------------------------
/**
 * @brief 元Type1宣言を同INFのDriverStoreコピーへ検証します
 * @param[in] inf 呼出し中だけ借用する読取り専用INFです
 * @param[in] software 元AddSoftwareを持つDDInstall.Software節です
 * @param[in,out] line 元AddSoftwareの全fieldを読むcontextです
 * @param[in] contentOnly 他Classは内容だけ検査し、導入許可へ変換しない場合trueです
 * @param[out] source 非nullなら全成功時だけ同元source相対位置、失敗時は空です
 * @param[out] unassessed 非nullなら当該参照が内容専用の場合true、失敗時はfalseです
 * @return 標準Type1の役割・原コピー成功0、不正・未対応時はHRESULTです
 * @note 非SWCの内容成功は未評価作用のままです。実行せず、署名・適合・導入許可は後段の責務です
 */
//------------------------------------------------------------------------------
NativeError			  validateRequiredSoftwareDeclaration( HINF inf, std::wstring_view software,
														  INFCONTEXT &line, bool contentOnly = false,
														  std::wstring *source	   = nullptr,
														  bool		   *unassessed = nullptr) ;

/** @brief 同じ原INFの登録所有先と後段照合の要求を検査中だけ保持します */
struct PropertyPageContext {
	/// 各AMD64所有先の実節とその原AddReg節です
	std::vector<std::pair<std::wstring, std::wstring>> owners ;
	/// 明示AMD64 Modelsに由来する実在DDInstallです
	std::vector<std::wstring>						   modelInstalls ;
	/// 元DDInstallへの先頭fieldの参照を認める宣言済みModelsです
	std::vector<std::wstring>						   directModelSections ;
	/// 全所有先で一致した原DLLとcallbackです。媒体基準の相対位置です
	std::optional<OfficialInfPropertyPage>			   binding ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元ストレージの基本導入節にあるプロパティページを一意に照合します
 * @param[in] inf 読取り中の同じ原INFです
 * @return 同じ元所有と元コピーの証拠です。不成立または関係なしでは空です
 * @note 空の結果は通常の全行検査に渡し、未検査の登録を許可しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] PropertyPageContext readCollectorStoragePropertyPage( HINF inf) ;

/** @brief 公式範囲付きNetの登録節と不在の旧媒体を同じ証明で所有します */
struct InactiveCoInstaller {
	/// 他節から参照されない単一の登録節です
	std::wstring				 registry ;
	/// 他節から参照されない同じ登録のコピー節です
	std::wstring				 copy ;
	/// 元INFと同じ原媒体に宣言された旧DLLと随伴データの位置です
	std::array<std::wstring, 2U> files ;
} ;

/** @brief 原CABと保護同梱INFの逆参照検査中だけ所有する節の境界です */
struct ScopedMediaIsolation {
	/// 欠落したDLLの呼出しを持つ未到達登録節です。なければ空です
	std::wstring		   registration ;
	/// 現在のSYSを参照するx86専用のコピー、サービスと呼出し元の節名です
	std::set<std::wstring> x86Sections ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同INFの正式CoInstallers文脈と元DLLコピーに結合した登録節を取得します
 * @param[in] inf 同期中だけ借用する元INFです
 * @param[out] registrySections 全成功時だけ検査済み元登録節です。失敗時は空です
 * @param[in,out] pages 明示収集rootだけの原登録です。他用途はnullです
 * @return 全節の構造検査成功0、不明作用・参照不一致・容量超過のHRESULTです
 * @note DLLを実行せず、同じCATの全file検証は後段で必須です
 */
//------------------------------------------------------------------------------
NativeError collectRequiredCoInstallerRegistry( HINF						  inf,
											   std::vector<std::wstring> &registrySections,
											   PropertyPageContext		 *pages) ;

/** @brief 棚卸しsectionの行形式。異なる形式で同じ節を再解釈しない */
enum class InstallInventorySectionKind {
	/// Directiveとその明示参照を読む
	DIRECTIVES,
	/// AddReg／DelRegのregistry行を読む
	REGISTRY,
	/// File list・command等の値を解釈せず有限行として読む
	DATA_ROWS,
	/// 保守専用のCopyFiles listで明示source名を読む
	COPY_FILE_ROWS,
} ;

/** @brief 同じINF内で有限走査するsectionと行形式 */
struct InstallInventorySection {
	/// 元INF内のsection名。解析中だけ所有する
	std::wstring				name ;
	/// section行の解釈区分
	InstallInventorySectionKind kind{InstallInventorySectionKind::DIRECTIVES} ;
} ;

//------------------------------------------------------------------------------
// 内部class定義
//------------------------------------------------------------------------------

/**
 * @brief SetupAPIのINF handleをscope終了時に閉じる
 */
class UniqueInf final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief SetupOpenInfFileWの結果を受け取り、単独所有する
     *
     * @param[in] handle SetupCloseInfFileで閉じる所有INF handle
     */
	//------------------------------------------------------------------------------
	explicit UniqueInf( const HINF handle) noexcept : handle_( handle)
	{
	}

	//------------------------------------------------------------------------------
	/**
     * @brief INF handleを閉じる
     *
     * 有効なINF handleだけを一度SetupCloseInfFileで閉じる
     */
	//------------------------------------------------------------------------------
	~UniqueInf()
	{
		// 有効な所有INF handleだけを解放する
		if( handle_ != INVALID_HANDLE_VALUE) {
			SetupCloseInfFile( handle_) ;
		}
	}

	/**
	 * @brief 所有INF handleの複製構築をコンパイル時に禁止します
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです
	 * @note 削除宣言だけで関数本体やresource操作はありません
	 */
	UniqueInf( const UniqueInf &other) = delete ;
	/**
	 * @brief 所有INF handleの複製代入をコンパイル時に禁止します
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです
	 * @note 削除宣言だけで関数本体やresource操作はありません
	 */
	UniqueInf &operator=( const UniqueInf &other) = delete ;
	/**
	 * @brief 所有INF handleの移動構築をコンパイル時に禁止します
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです
	 * @note 削除宣言だけで関数本体やresource操作はありません
	 */
	UniqueInf( UniqueInf &&other) = delete ;
	/**
	 * @brief 所有INF handleの移動代入をコンパイル時に禁止します
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです
	 * @note 削除宣言だけで関数本体やresource操作はありません
	 */
	UniqueInf		  &operator=( UniqueInf &&other) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief INF handleを参照する
     *
     * 所有権を移さず、現在scopeのSetupAPI呼出しだけに使用する
     * @return 本instanceが所有するINF handle
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HINF get() const noexcept
	{
		return handle_ ;
	}

private:
	/// Destructorで閉じる所有INF handle
	HINF handle_{INVALID_HANDLE_VALUE} ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをNativeErrorへ変換する
 *
 * Provider共通結果へ元の診断値を保持する
 *
 * @param[in] error SetupAPIまたはfile APIが返したerror code
 * @return HRESULT_FROM_WIN32で変換したbit pattern
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows ordinal規則で文字列を比較する
 *
 * File名、INF識別子およびallowlistを同一規則で比較する
 *
 * @param[in] left 比較する一方の文字列
 * @param[in] right 比較する他方の文字列
 * @return 大文字小文字を除き完全一致する場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool stringsEqual( const std::wstring_view left,
								const std::wstring_view right) noexcept
{
	// Windows比較APIの長さ型を超える文字列を比較へ渡さない
	if( left.size() > static_cast<std::size_t>( std::numeric_limits<int>::max()) ||
	   right.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return false ;
	}

	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 文字列が有限allowlistへ含まれるか確認する
 *
 * 部分一致やUnicode正規化でProvider／classを拡張しない
 *
 * @param[in] value 検証対象文字列
 * @param[in] allowed 空を含まない許可文字列群
 * @return 一つの許可値へ完全一致する場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAllowedValue( const std::wstring_view				   value,
								  const std::span<const std::wstring_view> allowed) noexcept
{
	return std::ranges::any_of( allowed, [value]( const std::wstring_view candidate) {
		return stringsEqual( value, candidate) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF contextの指定fieldを有限文字列として取得する
 *
 * 必要長を先に取得し、固定長bufferによる切捨てを防ぐ
 *
 * @param[in] context SetupAPIが返した有効なline context
 * @param[in] fieldIndex 0がkey、1以降がvalueのfield番号
 * @param[out] value 成功時のnull終端を除く展開済み文字列
 * @return 成功時は0、不正fieldまたは上限超過時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readInfField( INFCONTEXT &context, const DWORD fieldIndex,
									   std::wstring &value)
{
	value.clear() ;
	DWORD required{} ;	// Null終端を含む必要文字数
	// 必要長照会でbuffer不足以外の失敗を検出したら診断値を返す
	if( SetupGetStringFieldW( &context, fieldIndex, nullptr, 0, &required) == FALSE &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 空または上限超過のINF fieldを取得しない
	if( required <= 1 || required > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::vector<wchar_t> buffer ;	// SetupAPIから文字列を受信する有限buffer
	try {
		buffer.resize( required) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	// INF field本文の取得失敗を元のWindows診断値で返す
	if( SetupGetStringFieldW( &context, fieldIndex, buffer.data(), static_cast<DWORD>( buffer.size()),
							nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	value.assign( buffer.data()) ;
	return value.empty() ? nativeErrorFromWin32( ERROR_INVALID_DATA) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF sectionの単一directive fieldを取得する
 *
 * 必須directiveをSetupAPIのINF規則で検索する
 *
 * @param[in] inf 読取り中のINF handle
 * @param[in] section 検索するsection名
 * @param[in] key 検索するdirective名
 * @param[in] fieldIndex 取得するvalueのfield番号
 * @param[out] value 成功時の展開済み文字列
 * @return 成功時は0、欠落または不正field時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readInfDirective( const HINF inf, const wchar_t *const section,
										   const wchar_t *const key, const DWORD fieldIndex,
										   std::wstring &value)
{
	INFCONTEXT context{} ;	// 一致したdirectiveのline context
	// 指定directiveを取得できなければ必須値を推測しない
	if( SetupFindFirstLineW( inf, section, key, &context) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	return readInfField( context, fieldIndex, value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ZIP検証済みentryに相対pathが存在するか確認する
 *
 * INF由来pathが展開済みpackageの外へ出ないことを確認する
 *
 * @param[in] entries ZIP central directoryで検証済みのfile群
 * @param[in] relativePath Workspace基準の相対path
 * @return 大文字小文字を除き完全一致するentryがある場合は`true`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool containsEntry( const std::span<const OfficialZipEntry> entries,
								 const std::wstring_view				 relativePath) noexcept
{
	return std::ranges::any_of( entries, [relativePath]( const OfficialZipEntry &entry) {
		return stringsEqual( entry.relativePath, relativePath) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 相対pathの拡張子を小文字ASCIIで取得する
 *
 * 実行形式混入とSYS必須条件をcaseに依存せず判定する
 *
 * @param[in] path ZIP検証済みのASCII相対path
 * @return 最終要素のdotから始まる小文字拡張子
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring lowerExtension( const std::wstring_view path)
{
	const std::size_t separator = path.find_last_of( L'\\') ;	// 最終directory separator位置
	const std::size_t dot		= path.find_last_of( L'.') ;	// 最終dot位置
	// file名部分にdotがない相対pathは拡張子なしとして扱う
	if( dot == std::wstring_view::npos ||
	   (separator != std::wstring_view::npos && dot < separator)) {
		return {} ;
	}

	std::wstring extension( path.substr( dot)) ;	// 小文字化する拡張子
	std::transform( extension.begin(), extension.end(), extension.begin(),
				   []( const wchar_t character) {
					   return character >= L'A' && character <= L'Z'
								  ? static_cast<wchar_t>( character - L'A' + L'a')
								  : character ;
				   }) ;
	return extension ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示参照先とその装飾節が同INF内の空節であることを確認する
 *
 * @param[in] inf 読取り中の借用INF handle
 * @param[in] section Null終端された参照先section名
 * @return 全参照先が存在する空節なら0、不正参照または非空節ならHRESULT
 * @note 外部INFの読込みや再帰的参照解決を行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateEmptyInfReference( const HINF inf, const wchar_t *section)
{
	const std::wstring_view reference( section) ;	// SetupAPIで展開した参照名
	// 未解決文字列、直接file、空名や曖昧なsection名は許可しない
	if( reference.empty() || reference.size() > MAXIMUM_MODEL_SECTION_CHARACTERS ||
	   !std::ranges::all_of( reference, []( const wchar_t character) noexcept {
		   return (character >= L'A' && character <= L'Z') ||
				  (character >= L'a' && character <= L'z') ||
				  (character >= L'0' && character <= L'9') || character == L'_' ||
				  character == L'.' || character == L'-' ;
	   })) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 欠落節と非空節を空参照へ読み替えず、明示的な空節だけを認める
	if( SetupGetLineCountW( inf, section) != 0) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> name{} ;	// 装飾節の列挙領域
	// 同じbase名から派生する装飾節にも処理行がないことを有限数で確認する
	for( std::size_t index = 0; index < MAXIMUM_INF_SECTIONS; ++index) {
		UINT required{} ;	// 終端を含むsection名の必要文字数
		// 正常終端だけを成功とし、過長名などのAPI失敗を保持する
		if( SetupEnumInfSectionsW( inf, static_cast<UINT>( index), name.data(),
								 static_cast<UINT>( name.size()), &required) == FALSE) {
			const DWORD error = GetLastError() ;	// 列挙停止理由
			return error == ERROR_NO_MORE_ITEMS ? 0 : nativeErrorFromWin32( error) ;
		}

		// 空名やbuffer外の応答を装飾節照合へ渡さない
		if( required <= 1U || required > name.size()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::wstring_view candidate( name.data()) ;	// 列挙された同INF内section名
		// 装飾節の実登録やコピーを空base節で隠す構造は拒否する
		if( candidate.size() > reference.size() && candidate[reference.size()] == L'.' &&
		   stringsEqual( candidate.substr( 0, reference.size()), reference) &&
		   SetupGetLineCountW( inf, name.data()) != 0) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 無作用のCoInstaller節だけを明示空参照で限定受理する
 *
 * @param[in] inf 読取り中の借用INF handle
 * @param[in] section Null終端されたCoInstallers節名
 * @return 空節または各一行までのAddReg／CopyFiles空参照なら0、それ以外はHRESULT
 * @note 各指示は最大16参照。実DLL登録、循環、外部依存、未知指示を解決・実行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateEmptyCoInstallers( const HINF inf, const wchar_t *section)
{
	const LONG lineCount = SetupGetLineCountW( inf, section) ;	// 同名節を含む処理行数
	// 参照行のない既存節は追加CoInstaller動作を持たない
	if( lineCount == 0) {
		return 0 ;
	}

	// 既知二指示以上の処理や欠落節を空参照として解釈しない
	if( lineCount < 0 || lineCount > MAXIMUM_EMPTY_CO_INSTALLER_LINES) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	INFCONTEXT line{} ;	// 有限数で読み取る指示行
	// 観測済み行数に対する先頭取得失敗は不正データとする
	if( SetupFindFirstLineW( inf, section, nullptr, &line) == FALSE) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	bool seenAddReg	   = false ;											// AddReg指示の重複拒否用
	bool seenCopyFiles = false ;											// CopyFiles指示の重複拒否用
	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> value{} ;	// keyまたは参照名
	// 観測された最大二行を読み取り、既知指示とその全fieldを確認する
	for( LONG lineIndex = 0; lineIndex < lineCount; ++lineIndex) {
		// 非key行や過長keyを許可済み指示へ読み替えない
		if( SetupGetStringFieldW( &line, 0, value.data(), static_cast<DWORD>( value.size()),
								nullptr) == FALSE) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		const bool isAddReg	   = stringsEqual( value.data(), L"AddReg") ;		// 許可済み登録指示
		const bool isCopyFiles = stringsEqual( value.data(), L"CopyFiles") ;	// 許可済みコピー指示
		// 未知指示と重複指示を空参照の許可経路へ通さない
		if( (!isAddReg && !isCopyFiles) || (isAddReg && seenAddReg) ||
		   (isCopyFiles && seenCopyFiles)) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		seenAddReg		   = seenAddReg || isAddReg ;
		seenCopyFiles	   = seenCopyFiles || isCopyFiles ;
		const DWORD fields = SetupGetFieldCount( &line) ;	// keyを除く参照field数
		// 空または過大な参照集合を走査しない
		if( fields == 0 || fields > MAXIMUM_EMPTY_CO_INSTALLER_REFERENCES) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// 全参照を有限数で展開し、既存空節であることを確認する
		for( DWORD field = 1U; field <= fields; ++field) {
			// 展開失敗や過長参照を無作用として受理しない
			if( SetupGetStringFieldW( &line, field, value.data(), static_cast<DWORD>( value.size()),
									nullptr) == FALSE) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			const NativeError error = validateEmptyInfReference( inf, value.data()) ;	// 空参照判定
			// 一つでも非空・不正なら節全体の受理を中止する
			if( error != 0) {
				return error ;
			}
		}

		// 既知行数の途中で列挙が終わった場合は部分検証で成功にしない
		if( lineIndex + 1 < lineCount && SetupFindNextLine( &line, &line) == FALSE) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief INFの既知の実行・software登録経路を静的検査する
 *
 * Installerを起動せず全section名、行本文とdirective keyを有限数検査し、
 * 既知command・外部INF登録とRun登録を拒否し、必要構成だけを同INFの元参照へ結合します
 * keyなしCopyFilesとregistry行も本文を検査し、一般unknownの無作用保証へは使わない
 *
 * @param[in] inf 読取り中のINF handle
 * @param[in] rejectExternalDependencies 未解決の外部依存を方式未対応として拒否する場合true
 * @param[out] hasExternalDependencies 明示依存directiveを一件以上観測した場合true。充足を表さない
 * @param[in] allowRequiredDriverComponents CopyINF/AddComponentを後段の有限関係検査へ残す場合true
 * @param[in] contentOnly 非SWCのType1を非実行内容検査だけへ残す場合trueです
 * @param[out] unassessed 非nullなら未評価software作用の存在です。失敗時は部分値を使いません
 * @param[in] purpose 非権限の検査用途です。明示収集rootだけが元プロパティページを検査します
 * @param[out] propertyPage 非nullなら全成功時だけ同一原DLLの後段照合要求です
 * @param[in] inboxPageRegistry 元基本節と一意に照合した標準Portsページの登録節です。空は適用外です
 * @param[in] inactiveRegistry 公式範囲付きNetで全逆参照を確認した唯一の登録節です。空は従来検査です
 * @param[in] serialPages 私有シリアル媒体で所有先を確認した元ページ。通常はnullです
 * @return 禁止directiveがなく、追加作用が指定modeの限定検査を満たす場合0です
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateInfInstallActions(
	const HINF inf, const bool rejectExternalDependencies, bool &hasExternalDependencies,
	const bool allowRequiredDriverComponents = false, const bool contentOnly = false,
	bool								   *unassessed = nullptr,
	OfficialInfInspectionPurpose			purpose = OfficialInfInspectionPurpose::STANDARD_DRIVER,
	std::optional<OfficialInfPropertyPage> *propertyPage = nullptr,
	std::wstring_view inboxPageRegistry = {}, std::wstring_view inactiveRegistry = {},
	const PropertyPageContext *serialPages = nullptr)
{
	hasExternalDependencies = false ;
	// 内容検査の作用観測を別INFから引き継ぎません
	if( unassessed != nullptr) {
		*unassessed = false ;
	}

	PropertyPageContext pages ;	// 同じ原INF内で共有する所有関係と後段照合要求です
	const bool collectorPages = purpose == OfficialInfInspectionPurpose::COLLECTOR_CONTENT &&
								propertyPage != nullptr ;	// 照合結果を受け取れる収集用途だけです
	std::wstring storageClass ;								// 空Dependenciesを判定する元クラス名
	// 空の依存宣言は端末側の正式ストレージ用途だけで受理する
	const bool	 deviceStorage =
		purpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE &&
		readInfDirective( inf, L"Version", L"Class", 1U, storageClass) == 0 &&
		(stringsEqual( storageClass, L"SCSIAdapter") || stringsEqual( storageClass, L"MTD")) ;
	std::vector<std::wstring> coInstallerRegistry ;	// 同元DLLコピーへ検査済みの登録節だけです
	// 必要構成modeだけで正式文脈の全登録を先に検証し、列挙順に依存しません
	if( allowRequiredDriverComponents) {
		const auto error =
			// 元診断です
			collectRequiredCoInstallerRegistry( inf, coInstallerRegistry,
											   collectorPages ? &pages : nullptr) ;
		// 一節の不正を他の正常登録で隠しません
		if( error != 0) {
			return error ;
		}
	}

	// 既存のcompanion登録と混ぜず、収集だけで基本導入節の同じ元作用を照合します
	if( collectorPages && allowRequiredDriverComponents && !pages.binding &&
	   coInstallerRegistry.empty()) {
		pages = readCollectorStoragePropertyPage( inf) ;
	}

	// 収集で確認した混在媒体の登録節だけを、同じ全節の逆参照検査へ渡す
	if( serialPages != nullptr) {
		// 既存の共同インストーラーを混在シリアルのページに読み替えない
		if( !collectorPages || pages.binding || !coInstallerRegistry.empty()) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		pages = *serialPages ;
	}

	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U>
									 sectionBuffer{} ;	// 現在section名の固定長受信領域
	const std::unique_ptr<wchar_t[]> keyBuffer(
		// Directive key受信領域
		new( std::nothrow) wchar_t[MAXIMUM_INF_FIELD_CHARACTERS]) ;
	const std::unique_ptr<wchar_t[]> lineBuffer(
		// 展開後line受信領域
		new( std::nothrow) wchar_t[MAXIMUM_INF_FIELD_CHARACTERS]) ;
	// directive検査bufferを確保できなければ検証を開始しない
	if( !keyBuffer || !lineBuffer) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}

	std::size_t pageLines{} ;	// 新しい所有関係の逆参照を走査する全section共通の予算です
	// SetupAPIが列挙するsectionを固定上限まで調べる
	for( std::size_t sectionIndex = 0; sectionIndex < MAXIMUM_INF_SECTIONS; ++sectionIndex) {
		UINT required{} ;	// Null終端を含む現在section名の必要文字数
		// INF section列挙の正常終端とAPI失敗を区別する
		if( SetupEnumInfSectionsW( inf, static_cast<UINT>( sectionIndex), sectionBuffer.data(),
								 static_cast<UINT>( sectionBuffer.size()), &required) == FALSE) {
			const DWORD error = GetLastError() ;	// 列挙終了または構文失敗理由
			// すべての元sectionと呼出し元が確定してから後段の必須検査へ渡します
			if( error == ERROR_NO_MORE_ITEMS && propertyPage != nullptr) {
				*propertyPage = std::move( pages.binding) ;
			}

			return error == ERROR_NO_MORE_ITEMS ? 0 : nativeErrorFromWin32( error) ;
		}

		// 空またはbuffer範囲を超えるsection名を拒否する
		if( required <= 1U || static_cast<std::size_t>( required) > sectionBuffer.size()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const std::wstring_view section( sectionBuffer.data()) ;	// 現在検査するsection名
		// デバイス別例外とクラス全体の登録を同じ原本で採用しません
		if( pages.binding &&
		   (stringsEqual( section.substr( 0U, section.find( L'.')), L"ClassInstall32") ||
			stringsEqual( section.substr( 0U, section.find( L'.')), L"ClassInstall"))) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		const auto sectionBase =
			// 媒体やメーカーの元metadataです
			section.substr( 0U, section.find( L'.')) ;
		// 実行節の参照ではない媒体やVersionの値を区別します
		const bool metadata =
			stringsEqual( section, L"Version") || stringsEqual( section, L"Manufacturer") ||
			stringsEqual( sectionBase, L"SourceDisksNames") ||
			stringsEqual( sectionBase, L"SourceDisksFiles") ||
			stringsEqual( section, L"DestinationDirs") || stringsEqual( section, L"ControlFlags") ;
		constexpr std::wstring_view CO_INSTALLERS_SUFFIX =
			L".CoInstallers" ;	// 任意DLLを登録し得るsection suffix
		// CoInstallers sectionは明示参照先が空の場合だけdriver-only経路で受理する
		if( !allowRequiredDriverComponents && section.size() >= CO_INSTALLERS_SUFFIX.size() &&
		   stringsEqual( section.substr( section.size() - CO_INSTALLERS_SUFFIX.size()),
						CO_INSTALLERS_SUFFIX)) {
			const NativeError error =
				// 空参照判定
				validateEmptyCoInstallers( inf, sectionBuffer.data()) ;
			// 実登録・コピー・未知動作を含む節は従来どおり拒否する
			if( error != 0) {
				return error ;
			}
		}

		INFCONTEXT line{} ;	// 現在sectionで列挙するdirective line
		// 先頭行を取得できないsectionはdirective走査を省略する
		if( SetupFindFirstLineW( inf, sectionBuffer.data(), nullptr, &line) == FALSE) {
			continue ;
		}

		// 全line本文を先に検査し、keyなし登録行も既知禁止作用から除外する
		do {
			// 新しい登録がある場合だけ、別文脈の検査も元INF全体の有限上限へ含めます
			if( pages.binding && ++pageLines > MAXIMUM_INSTALL_INVENTORY_LINES) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			DWORD lineCharacters{} ;	// Null終端を含む現在line全体の必要文字数
			SetLastError( ERROR_SUCCESS) ;
			// INF行長の照会でbuffer不足以外の失敗を検出したら中止する
			if( SetupGetLineTextW( &line, nullptr, nullptr, nullptr, nullptr, 0, &lineCharacters) ==
				   FALSE &&
			   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			std::array<wchar_t, 32U> emptyDirective{} ;	// 空Dependenciesのkeyだけを有限照合します
			const bool				 emptyStorageDependencies =
				deviceStorage && lineCharacters == 1U && SetupGetFieldCount( &line) <= 1U &&
				SetupGetStringFieldW( &line, 0U, emptyDirective.data(),
									 static_cast<DWORD>( emptyDirective.size()), nullptr) &&
				stringsEqual( emptyDirective.data(),
							 L"Dependencies") ;	// 原明示空を不在へ補完しません
			const bool stringsSection =
				stringsEqual( section, L"Strings") ||
				(section.size() == 12U && stringsEqual( section.substr( 0U, 8U), L"Strings.") &&
				 std::ranges::all_of( section.substr( 8U), []( const wchar_t character) {
					 return (character >= L'0' && character <= L'9') ||
							(character >= L'a' && character <= L'f') ||
							(character >= L'A' && character <= L'F') ;
				 })) ;							  // 四桁hex以外のlocale名へ空値例外を渡しません
			std::array<wchar_t, 1U> emptyValue{} ;		// SetupAPIが返す終端だけの実valueです
			DWORD					valueCharacters{} ;	// 空valueでも実読取成功と必要長を要求します
			const bool				emptyStringsValue =
				stringsSection && lineCharacters == 1U && SetupGetFieldCount( &line) == 1U &&
				SetupGetStringFieldW( &line, 0U, keyBuffer.get(),
									 static_cast<DWORD>( MAXIMUM_INF_FIELD_CHARACTERS), nullptr) &&
				keyBuffer[0U] != L'\0' &&
				SetupGetStringFieldW( &line, 1U, emptyValue.data(),
									 static_cast<DWORD>( emptyValue.size()), &valueCharacters) &&
				// 欠損keyや複数fieldを認めません
				valueCharacters == 1U && emptyValue[0U] == L'\0' ;
			// 空metadataと既空依存以外の欠損行・上限超過は従来どおり拒否します
			if( (lineCharacters <= 1U && !emptyStorageDependencies && !emptyStringsValue) ||
			   lineCharacters > MAXIMUM_INF_FIELD_CHARACTERS) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// INF行本文を取得できなければ実行経路検査を中止する
			if( SetupGetLineTextW( &line, nullptr, nullptr, nullptr, lineBuffer.get(),
								 static_cast<DWORD>( MAXIMUM_INF_FIELD_CHARACTERS),
								 nullptr) == FALSE) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			const std::size_t lineLength =
				std::char_traits<wchar_t>::length( lineBuffer.get()) ;	// Null終端を除く文字数
			std::transform( lineBuffer.get(), lineBuffer.get() + lineLength, lineBuffer.get(),
						   []( const wchar_t character) noexcept {
							   return character >= L'A' && character <= L'Z'
										  ? static_cast<wchar_t>( character - L'A' + L'a')
										  : character ;
						   }) ;
			const std::wstring_view lowerLine( lineBuffer.get(),
											  lineLength) ;	// 小文字化済みline
			// 正式文脈も全逆参照の証明もない登録とRun登録を拒否する
			if( (lowerLine.find( L"coinstallers32") != std::wstring_view::npos &&
				!stringsEqual( inactiveRegistry, section) &&
				!std::ranges::any_of( coInstallerRegistry,
									 [section]( const auto &value) {
										 return stringsEqual(
											 value, section) ;	// 元検査済み登録節だけを借用します
									 })) ||
			   lowerLine.find( L"\\currentversion\\run") != std::wstring_view::npos) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			std::array<wchar_t, 32U> valueName{} ;	// 登録行の元値名だけを照合します
			std::array<wchar_t, 32U> root{} ;		// 実registry rootと通常のmetadataを区別します
			// collectorで他HW・サービス・クラス・孤立節にある同名の登録を採用しません
			if( collectorPages && SetupGetFieldCount( &line) >= 3U &&
			   SetupGetStringFieldW( &line, 3U, valueName.data(),
									static_cast<DWORD>( valueName.size()), nullptr) &&
			   stringsEqual( valueName.data(), L"EnumPropPages32") &&
			   SetupGetStringFieldW( &line, 1U, root.data(), static_cast<DWORD>( root.size()),
									nullptr) &&
			   stringsEqual( std::wstring_view( root.data()).substr( 0U, 2U), L"HK") &&
			   !stringsEqual( inboxPageRegistry, section) &&
			   !std::ranges::any_of( pages.owners, [&]( const auto &owner) {
				   return stringsEqual( owner.second, section) ;
			   })) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			DWORD keyCharacters{} ;	// Null終端を含むdirective keyの必要文字数
			SetLastError( ERROR_SUCCESS) ;
			// key長の照会失敗時はkeyを持たない行とbuffer不足を区別する
			if( SetupGetStringFieldW( &line, 0, nullptr, 0, &keyCharacters) == FALSE) {
				const DWORD keyError = GetLastError() ;	// 事前照会のSetupAPI結果
				// 本文検証済みのCopyFiles・registry行はdirective key検査だけを省く
				if( keyError != ERROR_INSUFFICIENT_BUFFER) {
					continue ;
				}
			}

			// 空または上限超過のdirective keyを拒否する
			if( keyCharacters <= 1U || keyCharacters > MAXIMUM_INF_FIELD_CHARACTERS) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// directive key本文の取得失敗を保持して返す
			if( SetupGetStringFieldW( &line, 0, keyBuffer.get(),
									static_cast<DWORD>( MAXIMUM_INF_FIELD_CHARACTERS),
									nullptr) == FALSE) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			const std::wstring_view key( keyBuffer.get()) ;	// 現在lineのdirective key
			// 別の導入文脈によるregistry又はcompanionの参照を受理しません
			if( pages.binding && !stringsSection &&
			   (!metadata || stringsEqual( key, L"AddReg") || stringsEqual( key, L"DelReg") ||
				stringsEqual( key, L"BitReg") || stringsEqual( key, L"Needs"))) {
				const auto fields = SetupGetFieldCount( &line) ;	// 判定対象は展開後の全fieldです
				// 過大な参照行の未検査部分を残しません
				if( fields > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}

				// 全ownerのうち同じregistryを参照する元AddRegだけを受理します
				for( DWORD field = 1U; field <= fields; ++field) {
					// 元fieldの読取不能から空値を合成しません
					if( !SetupGetStringFieldW( &line, field, lineBuffer.get(),
											 static_cast<DWORD>( MAXIMUM_INF_FIELD_CHARACTERS),
											 nullptr)) {
						return nativeErrorFromWin32( GetLastError()) ;
					}

					const std::wstring_view target( lineBuffer.get()) ;	// 原参照の完全値です
					const bool registry = std::ranges::any_of( pages.owners, [&]( const auto &owner) {
						return stringsEqual( owner.second, target) ;
					}) ; // 共有登録でも所有者ごとに検査します
					// 同じ元Modelsの第1 fieldだけがDDInstallを直接選択できます
					const bool declaredModel =
						field == 1U && std::ranges::any_of( pages.directModelSections,
														   [section]( const auto &model) {
															   return stringsEqual( model, section) ;
														   }) ;
					// 基本導入節へ到達できるのは、元Modelsが指定した導入名fieldだけです
					// 明示Needsや他のregistry操作から既登録の文脈を借用しません
					if( (!declaredModel && std::ranges::any_of( pages.owners,
															  [&]( const auto &owner) {
																  return stringsEqual( owner.first,
																					  target) ;
															  })) ||
					   (registry && (!stringsEqual( key, L"AddReg") ||
									 !std::ranges::any_of( pages.owners, [&]( const auto &owner) {
										 return stringsEqual( owner.first, section) &&
												stringsEqual( owner.second, target) ;
									 })))) {
						return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
					}
				}
			}

			// 共通構成modeだけで正式ComponentのType1を同じ原copyへ検証します
			if( allowRequiredDriverComponents && stringsEqual( key, L"AddSoftware")) {
				bool	   declarationUnassessed{} ;	// 同原参照だけの非許可観測です
				const auto error =
					// 元Type1の診断です
					validateRequiredSoftwareDeclaration( inf, section, line, contentOnly, nullptr,
														&declarationUnassessed) ;
				// 不正宣言を従来の一律拒否や後続の正常行で隠しません
				if( error != 0) {
					return error ;
				}

				// 後続の正常参照で以前の未評価作用を消しません
				if( unassessed != nullptr) {
					*unassessed = *unassessed || declarationUnassessed ;
				}

				continue ;
			}

			// 明示依存の存在だけを観測し、選択sectionや充足を推測しない
			if( stringsEqual( key, L"Include") || stringsEqual( key, L"Needs") ||
			   stringsEqual( key, L"AddComponent") ||
			   (allowRequiredDriverComponents && stringsEqual( key, L"CopyINF"))) {
				hasExternalDependencies = true ;
				// 拒否policyを指定した既存経路では従来どおり解析を中止する
				if( rejectExternalDependencies) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}
			}

			// 実行経路を作る禁止directiveを検出したらINFを拒否する
			if( isAllowedValue( key, REJECTED_INF_DIRECTIVES) &&
			   !(allowRequiredDriverComponents && stringsEqual( key, L"CopyINF"))) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

		} while( SetupFindNextLine( &line, &line) != FALSE) ;
	}

	return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 相対pathの親directoryと子要素を結合する
 *
 * 空のsource directoryは親を維持し、結果の安全性はworkspace.pathで再検証する
 *
 * @param[in] parent 空またはseparatorで終わらない親相対path
 * @param[in] child 空または結合する子相対path
 * @return `\\`区切りで結合した相対path
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring joinRelativePath( const std::wstring_view parent, std::wstring_view child)
{
	// INF媒体の明示current-directory接頭辞だけを同じ相対位置へ解決します
	while( child.starts_with( L".\\")) {
		child.remove_prefix( 2U) ;
	}

	// directoryの`.`だけは同じ親を表し、`..`や途中segmentは補正しません
	if( child == L".") {
		child = {} ;
	}

	// 子要素が空の場合は親pathをそのまま保持する
	if( child.empty()) {
		return std::wstring( parent) ;
	}

	// 親pathが空の場合は不要な先頭区切りを付けない
	if( parent.empty()) {
		return std::wstring( child) ;
	}

	return std::wstring( parent) + L"\\" + std::wstring( child) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保守相対参照の先頭にある現在directory表記だけを除く
 * @param[in] relative SetupAPI取得済みの有限field。呼出し側が参照中の文字列を所有する
 * @return 元文字列を借用するview。親参照・絶対path・内部dot等は変更せず後段で拒否する
 * @note 単独dotは空directoryとする。CopyINFでは空参照として別途拒否する
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring_view stripReferenceCurrentDirectory( std::wstring_view relative) noexcept
{
	// 有限fieldの先頭にある明示現在directoryだけを取り除く
	while( relative.starts_with( L".\\") || relative.starts_with( L"./")) {
		relative.remove_prefix( 2U) ;
	}

	return relative == L"." ? std::wstring_view{} : relative ;
}

//------------------------------------------------------------------------------
/**
 * @brief 大文字小文字を無視して一意な文字列を追加する
 *
 * 同じPnP IDやfileを重複して上限消費しないために使う
 *
 * @param[in,out] values 一意性を維持する文字列群
 * @param[in] value 所有権を移して追加する候補文字列
 * @return 新規追加した場合は`true`、既存値の場合は`false`
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool appendUnique( std::vector<std::wstring> &values, std::wstring value)
{
	// 大小文字を除いて既存値と一致する場合は重複追加しない
	if( std::ranges::any_of( values, [&value]( const std::wstring &current) {
		   return stringsEqual( current, value) ;
	   })) {
		return false ;
	}

	values.push_back( std::move( value)) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief native ModelsのPnP IDを用途上限付きのopaque文字列として検査します
 * @param[in] value Windowsが元fieldから読み取った原caseのIDです
 * @return 非空・256文字以内の表示可能ASCIIでcommaを含まない場合trueです
 * @note 区切り・bus・GUID・asteriskを解釈しません。0x7F除外と256文字はアプリ側の制限です
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validNativeModelsId( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= MAXIMUM_HARDWARE_ID_CHARACTERS &&
		   std::ranges::all_of( value, []( const wchar_t character) noexcept {
			   return character >= L'!' && character <= L'~' && character != L',' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在platform用Models sectionからPnP IDを収集する
 *
 * SetupDiGetActualModelsSectionをWindowsのTargetOSVersion選択規則の正本とし、x86専用sectionを候補化しない
 *
 * @param[in] inf 読取り中のINF handle
 * @param[in] maximumHardwareIds 保持する一意ID数上限
 * @param[out] hardwareIds 成功時の現在OS／architecture用PnP ID群
 * @param[out] published 新metadata用途だけの元節/種別です。Nullでは既存ID列だけを保持します
 * @param[in] alternatePlatform NULLは現在OS、非NULLはcollectorが検証したV3観測点です
 * @return 一件以上取得時は0、適用section欠落または上限超過時HRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectHardwareIds(
	const HINF inf, const std::size_t maximumHardwareIds, std::vector<std::wstring> &hardwareIds,
	std::vector<OfficialInfPublishedModelSection> *published		 = nullptr,
	PSP_ALTPLATFORM_INFO						   alternatePlatform = nullptr)
{
	hardwareIds.clear() ;
	// 新receiptの部分集合を別INFへ持ち越しません
	if( published != nullptr) {
		published->clear() ;
	}

	// 検査済みASCII IDの比較にだけ使う無捕捉比較器です
	auto lessId = []( const std::wstring &left, const std::wstring &right) noexcept {
		return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
									static_cast<int>( right.size()), TRUE) == CSTR_LESS_THAN ;
	} ;
	using SeenIds = std::set<std::wstring, decltype( lessId)> ;
	SeenIds seenIds( lessId) ;	// 一意性だけを索引で確認し、呼出し元には元順と最初の元表記を返します

	INFCONTEXT manufacturer{} ;	// 現在処理するManufacturer line
	// Manufacturer sectionがなければModels対応を推測しない
	if( SetupFindFirstLineW( inf, L"Manufacturer", nullptr, &manufacturer) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 全manufacturerについて、現在platformにWindowsが選ぶModels sectionだけを調べる
	do {
		DWORD required{} ;	// Null終端を含むModels section名の必要文字数
		// 現在platform用Models sectionの必要長が取得不能または不正なら除外する
		if( official_inf_models_native_detail::actualModelsSection(
			   &manufacturer, alternatePlatform, nullptr, 0, &required, nullptr) == FALSE ||
		   required <= 1 || required > MAXIMUM_MODEL_SECTION_CHARACTERS) {
			continue ;
		}

		std::vector<wchar_t> sectionBuffer( required) ;	// Models section名の受信buffer
		// 現在platform用Models sectionを取得できない項目を除外する
		if( official_inf_models_native_detail::actualModelsSection(
			   &manufacturer, alternatePlatform, sectionBuffer.data(),
			   static_cast<DWORD>( sectionBuffer.size()), nullptr, nullptr) == FALSE) {
			continue ;
		}

		INFCONTEXT model{} ;	// 選択されたModels sectionの現在line
		// 対象Models sectionに読取り可能な先頭行がなければ除外する
		if( SetupFindFirstLineW( inf, sectionBuffer.data(), nullptr, &model) == FALSE) {
			continue ;
		}

		OfficialInfPublishedModelSection section ;		// 新metadata用途だけの原選択節です
		SeenIds							 seenHardware ;	// 元節のHardware欄で最初の出現を確認します
		SeenIds seenCompatible ;						// 同値でもCompatible欄の出現を独立して保持します
		// 既存callerへ新metadataの容量条件を追加しません
		if( published != nullptr) {
			// 公開節の上限や重複を部分identityへ丸めません
			if( published->size() >= 128U || std::ranges::any_of( *published, [&]( const auto &value) {
				   return value.modelSection == sectionBuffer.data() ;
			   })) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			section.modelSection = sectionBuffer.data() ;
		}

		// Models sectionの全lineからHardware IDとcompatible IDを取得する
		do {
			const DWORD fields = SetupGetFieldCount( &model) ;	// Keyを除くfield数
			// Models行に必要なinstall sectionとID fieldが揃わなければ拒否する
			if( fields < 2) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// Field 1はinstall sectionであるため、field 2以降のPnP IDだけを保持する
			for( DWORD field = 2; field <= fields; ++field) {
				std::wstring	  hardwareId ;	// 現在lineから展開したPnP ID
				// Models行のPnP ID fieldを読み取った結果。適用対象へ登録する前に確認する
				const NativeError readResult = readInfField( model, field, hardwareId) ;
				// 原IDを区切りやbusで変換せず、用途上限と文字境界だけを検査します
				if( readResult != 0 || !validNativeModelsId( hardwareId)) {
					return readResult != 0 ? readResult : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				// 新receiptだけで元fieldのHardware/Compatible区分を保存します
				if( published != nullptr) {
					auto &seen =
						// 元field種別の索引です
						field == 2U ? seenHardware : seenCompatible ;
					auto &ids = field == 2U ? section.hardwareIds
											: section.compatibleIds ;	// 元順の型付き列です
					// 同じ型の二つ目以降の表記は元順の列へ加えません
					if( seen.insert( hardwareId).second) {
						ids.push_back( hardwareId) ;
					}
				}

				// 重複除去後のPnP ID数が上限を超えたら部分集合を破棄する
				if( seenIds.insert( hardwareId).second) {
					// 新しい一意IDを加える前に既存の上限へ収まることを確認します
					if( hardwareIds.size() == maximumHardwareIds) {
						hardwareIds.clear() ;
						return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
					}

					hardwareIds.push_back( std::move( hardwareId)) ;
				}
			}
		} while( SetupFindNextLine( &model, &model) != FALSE) ;
		// 一節の全行成功後だけ原節を新receiptへ結合します
		if( published != nullptr) {
			published->push_back( std::move( section)) ;
		}
	} while( SetupFindNextLine( &manufacturer, &manufacturer) != FALSE) ;

	return hardwareIds.empty() ? nativeErrorFromWin32( ERROR_NOT_FOUND) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同INFのsource IDへ結んだfile subdirと媒体pathを完全取得します
 * @param[in] inf 同期呼出し中だけ借用する元INFです
 * @param[in] fileName pathを含まない元source file名です
 * @param[out] sourceDirectory 成功時は元file subdir、失敗時は空です
 * @param[out] mediaDirectory 成功時は同source IDのinstallation-root相対媒体path、失敗時は空です
 * @return 完全取得成功0、欠損・重複・過長・部分取得のHRESULTです。非zero原診断を維持します
 * @pre 二つの出力は別の格納先であり、fileNameともaliasしないこと
 * @note Windowsのamd64優先解決を使い、媒体root記法の先頭と末尾一backslashだけを相対意味へ変換します
 *       保護workspaceとservice固有の安全path検査は呼出側で必須です。fileを取得・実行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readInfSourceDirectories( HINF inf, const std::wstring &fileName,
												   std::wstring &sourceDirectory,
												   std::wstring &mediaDirectory)
{
	sourceDirectory.clear() ;
	mediaDirectory.clear() ;
	INFCONTEXT sourceLine{} ;	// Windowsと同じarchitecture優先の元行です
	INFCONTEXT duplicate{} ;	// 同元keyの曖昧性だけを確認する借用contextです
	// 別fileや別architectureの行から位置を補完しません
	if( !SetupFindFirstLineW( inf, L"SourceDisksFiles.amd64", fileName.c_str(), &sourceLine) &&
	   !SetupFindFirstLineW( inf, L"SourceDisksFiles", fileName.c_str(), &sourceLine)) {
		const auto error = GetLastError() ;	// 元行読取り診断です
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	// 同じ有効file名の競合を先頭行採用で隠しません
	if( SetupFindNextMatchLineW( &sourceLine, fileName.c_str(), &duplicate)) {
		return nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	UINT  sourceId{} ;	// 同INFのSourceDisksNamesを引く元媒体IDです
	DWORD required{} ;	// 終端込みsource subdir必要文字数です
	SetLastError( ERROR_SUCCESS) ;
	// 有限な二段取得の必要長照会以外の失敗を許可へ変換しません
	if( !SetupGetSourceFileLocationW( inf, nullptr, fileName.c_str(), &sourceId, nullptr, 0U,
									&required) &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		const auto error = GetLastError() ;	// 補助API前の元診断です
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	// 不正な必要長を部分位置や過大bufferへ変換しません
	if( required == 0U || required > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	const UINT			 expectedSourceId = sourceId ;	// 二段で同媒体へのbindingを保持します
	std::vector<wchar_t> source( required) ;			// 同期中だけ所有する有限subdirです
	DWORD				 readRequired{} ;				// 二段目の完全必要長です
	SetLastError( ERROR_SUCCESS) ;
	// 元媒体または完全値が取得できない場合は部分許可を公開しません
	if( !SetupGetSourceFileLocationW( inf, nullptr, fileName.c_str(), &sourceId, source.data(),
									static_cast<DWORD>( source.size()), &readRequired)) {
		const auto error = GetLastError() ;	// 原取得診断です
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	const auto sourceEnd = std::ranges::find( source, L'\0') ;	// 有限値の終端です
	// 必要長・終端・source IDの一致だけで元file subdirを保持します
	if( sourceId != expectedSourceId || sourceEnd == source.end() || readRequired != required ||
	   static_cast<std::size_t>( sourceEnd - source.begin()) + 1U != required) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const auto mediaKey = std::to_wstring( sourceId) ;	// Windowsの媒体ID keyです
	INFCONTEXT mediaLine{} ;							// 同INF・同IDのarchitecture優先元媒体行です
	// 別IDやrootへの暗黙fallbackで媒体欠損を隠しません
	if( !SetupFindFirstLineW( inf, L"SourceDisksNames.amd64", mediaKey.c_str(), &mediaLine) &&
	   !SetupFindFirstLineW( inf, L"SourceDisksNames", mediaKey.c_str(), &mediaLine)) {
		const auto error = GetLastError() ;	// 元媒体行診断です
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	// 同source IDの競合を名称一致や先頭行で救済しません
	if( SetupFindNextMatchLineW( &mediaLine, mediaKey.c_str(), &duplicate)) {
		return nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	DWORD mediaRequired{} ;	// 終端込み元媒体path必要文字数です
	SetLastError( ERROR_SUCCESS) ;
	// 同IDの媒体位置が取得できない場合は空媒体を補完しません
	if( !SetupGetSourceInfoW( inf, sourceId, SRCINFO_PATH, nullptr, 0U, &mediaRequired) &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		const auto error = GetLastError() ;	// 原媒体照会診断です
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	// 媒体位置も有限な完全値だけを受信します
	if( mediaRequired == 0U || mediaRequired > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	std::vector<wchar_t> media( static_cast<std::size_t>( mediaRequired) +
							   1U) ;			// 元必要長に末尾一区切り分だけ余裕を持つ有限領域です
	DWORD				 mediaReadRequired{} ;	// 二段目の元媒体必要長です
	SetLastError( ERROR_SUCCESS) ;
	// 部分取得は同名byteのsource許可へ昇格しません
	if( !SetupGetSourceInfoW( inf, sourceId, SRCINFO_PATH, media.data(),
							static_cast<DWORD>( media.size()), &mediaReadRequired)) {
		const auto error = GetLastError() ;	// 原媒体取得診断です
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	const auto mediaEnd = std::ranges::find( media, L'\0') ;	// 有限元媒体終端です
	const auto mediaLength =
		// NULを含まない実媒体文字数です
		static_cast<std::size_t>( mediaEnd - media.begin()) ;
	const bool trailingDelimiter = mediaLength == mediaRequired && mediaLength != 0U &&
								   // 実APIで必要長に含まれない末尾一区切りだけです
								   media[mediaLength - 1U] == L'\\' ;
	// 通常のNUL一致または実観測した末尾一区切り差以外の部分値・長さ差を拒否します
	if( mediaEnd == media.end() || mediaReadRequired != mediaRequired ||
	   (mediaLength + 1U != mediaRequired && !trailingDelimiter)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring_view mediaPath( media.data(),
								mediaLength) ;	// 完全取得済みinstallation root相対値です
	// 非空root-only媒体を正規化で空媒体へ変えず、元両出力を空のまま拒否します
	if( !mediaPath.empty() &&
	   std::ranges::all_of( mediaPath, []( const wchar_t value) { return value == L'\\' ; })) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// quoted末尾区切りを同じ媒体directoryへ結び、途中の区切りや任意文字は削除しません
	if( trailingDelimiter) {
		mediaPath.remove_suffix( 1U) ;
	}

	// 公式INFの一先頭backslashは媒体root相対です。UNCの二先頭は次の安全検査へ残します
	if( mediaPath.starts_with( L"\\") && !mediaPath.starts_with( L"\\\\")) {
		mediaPath.remove_prefix( 1U) ;
	}

	// 両方の完全取得に成功した後だけ、同IDの位置を公開します
	sourceDirectory.assign( source.data(), required - 1U) ;
	mediaDirectory.assign( mediaPath) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在architecture用SourceDisksFilesを検証する
 *
 * x64装飾sectionを優先し、SetupGetSourceFileLocationが返すdirectoryをworkspace境界とZIP entryへ再照合する。Printer以外は呼出側
 * policyによりSYSを必須にする
 *
 * @param[in] inf 読取り中のINF handle
 * @param[in] workspace 安全な絶対path変換を行う保護workspace
 * @param[in] entries ZIP検証済みfile群
 * @param[in] infParent INFのworkspace基準親directory
 * @param[in] maximumFiles 保持する一意参照file数上限
 * @param[in] requireDriverBinary SYS参照を必須にする場合true
 * @param[out] sourceFiles 成功時のworkspace基準参照file群
 * @param[in] referenceSection nullなら従来の導入検査、非nullなら保守棚卸しの固定source節
 * @param[in] allowReferencedExecutablesForContent 元EXE/MSI/CABを非実行の内容検査に含める場合true
 * @param[in] serviceExecutables 同INFの必要SWC serviceと同節コピーを検査した相対source位置です。包括許可ではありません
 * @param[out] unassessedPrograms 非null時だけ同INFの正式copy/serviceに未結合の参照を数値でなくboolへ保持します
 * @param[in] allowWindowsDriverData 元script/program参照を非実行DATAとして全CAT検査へ渡す場合trueです。導入操作は別検査です
 * @param[in] includeCommonFallback AMD64専用媒体表に加えて共通媒体表の有効な行も確認する場合true
 * @param[in] requiredSources 元AMD64の全導入節から証明した必要ファイルの完全パス。空は従来の存在検査
 * @param[in] inactiveSources 同署名INFの全逆参照を検査した不在媒体の完全位置。空は従来の存在検査
 * @param[in] x86Sources 同じ元CABのx86専用と確認した実ファイルの完全位置です
 * @return 全参照fileが存在しpolicyを満たす場合は0
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectSourceFiles(
	const HINF inf, const OfficialDownloadWorkspace &workspace,
	const std::span<const OfficialZipEntry> entries, const std::wstring_view infParent,
	const std::size_t maximumFiles, const bool requireDriverBinary,
	std::vector<std::wstring> &sourceFiles, const wchar_t *const referenceSection = nullptr,
	const bool							allowReferencedExecutablesForContent = false,
	const std::span<const std::wstring> serviceExecutables = {}, bool *unassessedPrograms = nullptr,
	const bool allowWindowsDriverData = false, const bool includeCommonFallback = false,
	std::span<const std::wstring> requiredSources = {},
	std::span<const std::wstring> inactiveSources = {},
	std::span<const std::wstring> x86Sources	  = {})
{
	sourceFiles.clear() ;
	// 任意の前回flagを今回の元参照へ引き継ぎません
	if( unassessedPrograms != nullptr) {
		*unassessedPrograms = false ;
	}

	INFCONTEXT source{} ;	// 現在処理するSourceDisksFiles line
	bool	   commonFallback = includeCommonFallback && referenceSection == nullptr &&
						  // AMD64表の後に共通表を読む
						  SetupGetLineCountW( inf, L"SourceDisksFiles.amd64") > 0L ;
	// amd64用と共通のSourceDisksFilesのどちらもなければ参照fileを推測しない
	if( referenceSection != nullptr
		   ? SetupFindFirstLineW( inf, referenceSection, nullptr, &source) == FALSE
		   : (SetupFindFirstLineW( inf, L"SourceDisksFiles.amd64", nullptr, &source) == FALSE &&
			  SetupFindFirstLineW( inf, L"SourceDisksFiles", nullptr, &source) == FALSE)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	bool hasDriverBinary{} ;	// `true`の場合は少なくとも一つのSYSが存在する
	bool hasDriverData{} ;		// BIN/DFU/MBNはSYSに伴う受動参照データとしてだけ扱います
	// 有効な全宣言の元位置を検査してから不存在の扱いを決める
	do {
		std::wstring fileName ;										// SourceDisksFiles lineのkeyであるfile名
		NativeError	 result = readInfField( source, 0, fileName) ;	// Key取得結果
		// source file名の取得失敗やpath区切り混入を検出したら部分結果を破棄する
		if( result != 0 || fileName.find_first_of( L"/\\") != std::wstring::npos) {
			sourceFiles.clear() ;
			return result != 0 ? result : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::wstring sourceDirectory ;	// 同INF・同source IDの完全file subdirです
		std::wstring mediaDirectory ;	// 同じ媒体のinstallation-root相対pathです
		result = readInfSourceDirectories( inf, fileName, sourceDirectory, mediaDirectory) ;
		// 通常導入でも媒体pathを捨てず、欠損・曖昧・部分取得の原診断を保持します
		if( result != 0) {
			sourceFiles.clear() ;
			return result ;
		}

		const std::wstring_view mediaPath =
			referenceSection != nullptr
				? stripReferenceCurrentDirectory( mediaDirectory)
				: std::wstring_view( mediaDirectory) ;	// 保守だけの現在directory解決
		const std::wstring_view fileDirectory =
			referenceSection != nullptr
				? stripReferenceCurrentDirectory( sourceDirectory)
				: std::wstring_view( sourceDirectory) ;							// 通常の元file subdirを保持します
		std::wstring relativePath = joinRelativePath( infParent, mediaPath) ;	// 媒体基準位置
		relativePath			  = joinRelativePath( relativePath, fileDirectory) ;
		relativePath			  = joinRelativePath( relativePath, fileName) ;
		// 不正な媒体位置は未使用として処理しない
		if( workspace.path( relativePath).empty()) {
			sourceFiles.clear() ;
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		// 壊れた圧縮ソースと、本当に存在しない未使用宣言を区別する
		if( !containsEntry( entries, relativePath)) {
			auto	   alias = relativePath ;					// 同じ媒体位置の標準圧縮別名
			const auto dot	 = fileName.find_last_of( L'.') ;	// 標準の三文字拡張子だけを認識する
			// 圧縮に対応する場合は元位置の最後の一文字だけを置き換える
			if( dot != fileName.npos && fileName.size() - dot == 4U) {
				alias.back() = L'_' ;
			}

			// 全導入節の証明が成立した場合も必要な元ファイルや圧縮別名を省かない
			if( !containsEntry( entries, alias) &&
			   ((!requiredSources.empty() && std::ranges::none_of( requiredSources,
																  [&]( const auto &required) {
																	  return stringsEqual(
																		  relativePath, required) ;
																  })) ||
				std::ranges::any_of( inactiveSources, [&]( const auto &inactive) {
					return stringsEqual( relativePath, inactive) ;
				}))) {
				continue ;
			}

			sourceFiles.clear() ;
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		// 事前に証明した同一の現物だけをAMD64の照合対象から外します
		if( std::ranges::any_of( x86Sources, [&]( const auto &sourcePath) {
			   return stringsEqual( relativePath, sourcePath) ;
		   })) {
			continue ;
		}

		const std::wstring extension  = lowerExtension( relativePath) ;	// 参照file拡張子
		const bool		   driverData = extension == L".bin" || extension == L".dfu" ||
								// 拡張子だけでflash動作と推測しません
								extension == L".mbn" || extension == L".elf" ;
		const bool serviceExecutable =	// 同INFのcopy全宛先へ結んだ位置付き元sourceだけです
			(extension == L".exe" || extension == L".msi") &&
			std::ranges::any_of( serviceExecutables, [&]( const auto &name) {
				return stringsEqual(
					name, joinRelativePath( joinRelativePath( mediaPath, fileDirectory), fileName)) ;
			}) ;
		const bool contentProgram =
			extension == L".exe" || extension == L".msi" ||
			// 実行を推測しない元参照の区分です
			extension == L".cab" ||
			(allowWindowsDriverData &&
			 std::ranges::find( REJECTED_UNREFERENCED_PROGRAM_EXTENSIONS, extension) !=
				 REJECTED_UNREFERENCED_PROGRAM_EXTENSIONS.end()) ;
		// 保守内容EXEと同INFの必要service EXE以外は、参照program・archive・firmware拒否を維持します
		if( referenceSection == nullptr &&
		   std::ranges::find( REJECTED_REFERENCED_EXTENSIONS, extension) !=
			   REJECTED_REFERENCED_EXTENSIONS.end() &&
		   !(allowReferencedExecutablesForContent &&
			 (extension == L".exe" || extension == L".msi" || extension == L".cab")) &&
		   !(allowWindowsDriverData && contentProgram) && !serviceExecutable && !driverData) {
			sourceFiles.clear() ;
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// 内容許可だけの原参照を、既存導入経路のdriver-only合格へ流用しません
		if( unassessedPrograms != nullptr &&
		   (allowReferencedExecutablesForContent || allowWindowsDriverData) && contentProgram &&
		   !serviceExecutable) {
			*unassessedPrograms = true ;
		}

		hasDriverBinary = hasDriverBinary || extension == L".sys" ;
		hasDriverData	= hasDriverData || driverData ;
		// 重複除去後の参照file数が上限を超えたら部分結果を破棄する
		if( appendUnique( sourceFiles, std::move( relativePath)) &&
		   sourceFiles.size() > maximumFiles) {
			sourceFiles.clear() ;
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}
	} while( SetupFindNextLine( &source, &source) ||
			(std::exchange( commonFallback, false) &&
			 SetupFindFirstLineW( inf, L"SourceDisksFiles", nullptr, &source))) ;

	// 証明した必要ファイルは同じ閉包に入り、後段で元CATに照合される
	if( std::ranges::any_of( requiredSources, [&]( const auto &required) {
		   return std::ranges::none_of( sourceFiles, [&]( const auto &sourceFile) {
			   return stringsEqual( sourceFile, required) ;
		   }) ;
	   })) {
		sourceFiles.clear() ;
		return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
	}

	return !sourceFiles.empty() && (!(requireDriverBinary || hasDriverData) || hasDriverBinary)
			   ? 0
			   : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF用catalog file名を現在architecture向けに取得する
 *
 * x64、NT、共通の順に有限探索し、複数候補を推測しない
 *
 * @param[in] inf 読取り中のINF handle
 * @param[out] catalogFile 成功時のdirectoryを含まないCAT file名
 * @return 必須directive取得時は0、欠落またはpath不正時HRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readCatalogFile( const HINF inf, std::wstring &catalogFile)
{
	// x64固有、NT共通、無装飾の順でCAT指定を照合するkey集合
	constexpr std::array KEYS{L"CatalogFile.ntamd64", L"CatalogFile.NT", L"CatalogFile"} ;
	NativeError			 result = nativeErrorFromWin32( ERROR_LINE_NOT_FOUND) ;	// 最終検索結果
	// Platform固有directiveから共通directiveの順に最初の一件だけを取得する
	for( const wchar_t *const key : KEYS) {
		result = readInfDirective( inf, L"Version", key, 1, catalogFile) ;
		// 優先順で最初に取得できたcatalog指定を採用する
		if( result == 0) {
			break ;
		}
	}

	// catalog名の取得失敗、path要素混入、CAT以外の拡張子を拒否する
	if( result != 0 || catalogFile.find_first_of( L"/\\") != std::wstring::npos ||
	   !stringsEqual( lowerExtension( catalogFile), L".cat")) {
		catalogFile.clear() ;
		return result != 0 ? result : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 空fieldも含め、棚卸しの一fieldを有限文字列へ読む
 * @param[in,out] line SetupAPIから取得した借用行context
 * @param[in] field 値を取得するfield番号
 * @param[out] value 成功時の値。空も許可し、失敗時は空
 * @return 読取成功0、過長またはSetupAPI失敗のHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readInstallInventoryField( INFCONTEXT &line, DWORD field,
													std::wstring &value)
{
	value.clear() ;
	std::array<wchar_t, MAXIMUM_INF_FIELD_CHARACTERS> buffer{} ;	// 有限の同期受信領域
	// 値の切捨てを認めず、空fieldとAPI失敗を区別する
	if( SetupGetStringFieldW( &line, field, buffer.data(), static_cast<DWORD>( buffer.size()),
							nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	value = buffer.data() ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Section名の長さと構文区切りを検証する
 * @param[in] name 外部から取得したsection名
 * @return 空・過長・NUL・path・構文区切りがない場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validInstallInventorySectionName( std::wstring_view name) noexcept
{
	return !name.empty() && name.size() <= 254U &&
		   name.find_first_of( std::wstring_view( L"\0\r\n[]\\/", 7U)) == std::wstring_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief Models所属を確認済みの導入名を指定Windowsの実在DDInstallへ解決する
 * @param[in] inf 同期借用するINF handle
 * @param[in] base 同じWindows用Modelsで確認した安全な導入名
 * @param[out] selected 成功時だけ実在する節名を保持する
 * @param[in] requested Models選択と同じSetupAPIのOS情報。nullは現在OS
 * @return Windows選択と実在確認成功0、選択失敗または節欠落のHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError resolveActualInstallInventorySection(
	HINF inf, const std::wstring &base, std::wstring &selected,
	PSP_ALTPLATFORM_INFO requested = nullptr)
{
	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS> section{} ;	// 解決したDDInstall名
	DWORD required{} ;													// APIが返すNUL込み文字数です。byte数ではありません
	// Windowsの修飾選択を使用し、独自のarchitecture suffix推測を行わない
	if( SetupDiGetActualSectionToInstallExW( inf, base.c_str(), requested, section.data(),
										   static_cast<DWORD>( section.size()), &required, nullptr,
										   nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const auto end =
		// 固定文字容量内の実終端です
		std::find( section.begin(), section.end(), L'\0') ;
	// 必要文字数と終端を確認し、未修飾fallbackの実在も別に要求します
	if( required == 0U || required > section.size() || end == section.end() ||
	   !validInstallInventorySectionName(
		   std::wstring_view( section.data(), static_cast<std::size_t>( end - section.begin()))) ||
	   SetupGetLineCountW( inf, section.data()) < 0) {
		return nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND) ;
	}

	selected = section.data() ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現OS用Modelsに属する導入名をDDInstallの実在節へ解決する
 * @param[in] inf 本呼出し中有効な読取専用handle
 * @param[in] base 入力検証済みの導入名
 * @param[out] selected 成功時だけ実在する選択節名を保持する
 * @return Modelsとの一致と実在を確認した場合0、未登録・欠落・容量・API失敗のHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError selectInstallInventorySection( HINF inf, const std::wstring &base,
														std::wstring &selected)
{
	INFCONTEXT manufacturer{} ;	// 現OS向けModelsを選ぶメーカー行
	// Modelsへの所属を確認できない入力を任意節指定として通さない
	if( SetupFindFirstLineW( inf, L"Manufacturer", nullptr, &manufacturer) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	std::size_t lines{} ;		// メーカー行とModels行の累積上限消費
	bool		found = false ;	// 少なくとも一つの現OS Modelsに導入名がある場合true
	// 全メーカーを有限に調べ、旧OS・別architectureのModelsを使わない
	do {
		// 先頭行から上限を消費し、メーカー行だけの過大入力も拒否する
		if( ++lines > MAXIMUM_INSTALL_INVENTORY_LINES) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS> models{} ;	// 現OS用節名
		// 現OSに選べないメーカーは対象外にし、別Modelsへfallbackしない
		if( SetupDiGetActualModelsSectionW( &manufacturer, nullptr, models.data(),
										  static_cast<DWORD>( models.size()), nullptr,
										  nullptr) == FALSE) {
			const DWORD error = GetLastError() ;	// 対象外と容量・構文失敗を区別する
			// 節選択の容量失敗を対象外として握り潰さない
			if( error != ERROR_NO_COMPAT_DRIVERS && error != ERROR_SECTION_NOT_FOUND) {
				return nativeErrorFromWin32( error) ;
			}

			continue ;
		}

		INFCONTEXT model{} ;	// 選択されたModels内の行
		// 欠落Modelsを現在の適合モデルと推測しない
		if( SetupFindFirstLineW( inf, models.data(), nullptr, &model) == FALSE) {
			continue ;
		}

		// 導入名fieldだけを読み、PnP ID fieldを取得・保持しない
		do {
			// 共有Modelsの再登場も走査量に数え、無制限な重複処理を止める
			if( ++lines > MAXIMUM_INSTALL_INVENTORY_LINES) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::wstring	  name ;									// 比較中だけ所有する導入名
			const NativeError error = readInfField( model, 1U, name) ;	// 必須fieldの取得結果
			// 不正Models行を読み飛ばして部分集合の承認を行わない
			if( error != 0 || SetupGetFieldCount( &model) < 2U ||
			   !validInstallInventorySectionName( name)) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			found = found || stringsEqual( name, base) ;
		} while( SetupFindNextLine( &model, &model) != FALSE) ;
	} while( SetupFindNextLine( &manufacturer, &manufacturer) != FALSE) ;
	// 現OSのModelsにない導入名をWindowsへ解決させない
	if( !found) {
		return nativeErrorFromWin32( ERROR_NOT_FOUND) ;
	}

	return resolveActualInstallInventorySection( inf, base, selected) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ローカルsectionを一度だけ有限queueへ追加する
 * @param[in,out] pending 単独所有する最大1,024節の走査queue
 * @param[in] name 入力検証済みのsection名
 * @param[in] kind section行形式
 * @return 追加・同形式既存時0、矛盾形式・容量違反のHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError queueInstallInventorySection(
	std::vector<InstallInventorySection> &pending, const std::wstring &name,
	InstallInventorySectionKind kind)
{
	const auto prior = std::ranges::find_if( pending, [&name]( const InstallInventorySection &item) {
		return stringsEqual( item.name, name) ;
	}) ; // 共有・循環でも同じ節を繰り返し走査しない
	// 同一節の二つの異なる解釈を黙って統合しない
	if( prior != pending.end()) {
		return prior->kind == kind ? 0 : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 1,024節を超える到達graphを部分成功として返さない
	if( pending.size() >= MAXIMUM_INSTALL_INVENTORY_SECTIONS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	pending.push_back( {name, kind}) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 棚卸しdirectiveの宣言種類を分類する
 * @param[in] key 展開済みの有限key。値は参照しない
 * @return 既知の宣言種類またはUNKNOWN_DIRECTIVE
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialInfInstallEffectKind installInventoryEffectKind(
	std::wstring_view key) noexcept
{
	// 実行指示は内容署名や標準処理へ読み替えない
	if( stringsEqual( key, L"RunPreSetupCommands") || stringsEqual( key, L"RunPostSetupCommands")) {
		return OfficialInfInstallEffectKind::COMMAND_EXECUTION ;
	}

	// DLL登録も任意codeに到達し得る独立した宣言として保持する
	if( stringsEqual( key, L"RegisterDlls") || stringsEqual( key, L"UnregisterDlls")) {
		return OfficialInfInstallEffectKind::DLL_REGISTRATION ;
	}

	// 別INF取込みを通常のfile copyと区別する
	if( stringsEqual( key, L"CopyINF")) {
		return OfficialInfInstallEffectKind::COPY_INF ;
	}

	// 参照の存在と外部依存充足を別に記録する
	if( stringsEqual( key, L"Include") || stringsEqual( key, L"Needs") ||
	   stringsEqual( key, L"AddComponent")) {
		return OfficialInfInstallEffectKind::EXPLICIT_DEPENDENCY ;
	}

	constexpr std::array<std::wstring_view, 42> known{
		L"CopyFiles",
		L"AddReg",
		L"DelReg",
		L"DelFiles",
		L"RenFiles",
		L"BitReg",
		L"AddProperty",
		L"DelProperty",
		L"DriverVer",
		L"FeatureScore",
		L"ExcludeID",
		L"Reboot",
		L"LogConfig",
		L"ProfileItems",
		L"UpdateInis",
		L"UpdateIniFields",
		L"Ini2Reg",
		L"AddService",
		L"DelService",
		L"AddInterface",
		L"AddSoftware",
		L"KmdfService",
		L"UmdfService",
		L"UmdfServiceOrder",
		L"ServiceBinary",
		L"ServiceType",
		L"StartType",
		L"ErrorControl",
		L"DisplayName",
		L"Description",
		L"LoadOrderGroup",
		L"Dependencies",
		L"BootFlags",
		L"KmdfLibraryVersion",
		L"UmdfLibraryVersion",
		L"UmdfServiceBinary",
		L"UmdfDeviceGroup",
		L"UmdfDispatcher",
		L"ComponentIDs",
		L"SoftwareType",
		L"SoftwareId",
		L"EventMessageFile"} ;	// 既知宣言であって実行許可ではない
	return isAllowedValue( key, known) ? OfficialInfInstallEffectKind::STANDARD_DIRECTIVE
									  : OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現棚卸しが辿らない宣言範囲を既知種類へ分離する
 * @param[in] key この行だけの有限directive名
 * @param[in] values 値は同期借用し、本文を結果へ保存しない
 * @return 一宣言の不足種類。該当なしも全構文の完全性を示さない
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<OfficialInfInstallCoverageKind> installInventoryCoverageKind(
	std::wstring_view key, std::span<const std::wstring> values)
{
	constexpr std::array<std::wstring_view, 7> unfollowed{
		L"AddProperty", L"DelProperty",		L"LogConfig", L"ProfileItems",
		L"UpdateInis",	L"UpdateIniFields", L"Ini2Reg"} ;	// 既知だが今回参照先を走査しない形式
	// 宣言の認識と参照先解釈の完了を混同しない
	if( isAllowedValue( key, unfollowed)) {
		return OfficialInfInstallCoverageKind::UNFOLLOWED_SECTION_REFERENCES ;
	}

	// 第4 fieldだけがevent-log節で、後続の種類や名称を節として扱わない
	if( stringsEqual( key, L"AddService") && values.size() > 3U && !values[3].empty()) {
		return OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG ;
	}

	// 独立softwareの予約を標準driverだけの作用と認定しない
	if( stringsEqual( key, L"AddSoftware")) {
		return OfficialInfInstallCoverageKind::SOFTWARE_INSTALLATION_NOT_ASSESSED ;
	}

	// 未知を無作用へ読み替えず、元作用enumと別の不足も保持する
	if( installInventoryEffectKind( key) == OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE) {
		return OfficialInfInstallCoverageKind::UNKNOWN_DIRECTIVE ;
	}

	return std::nullopt ;
}

/** @brief 同じ固定INFのレジストリ節で全行読取りが成立した観測です */
struct MaintenanceSharedRegistrySection {
	/// 同じINF内のレジストリ節の元名です
	std::wstring					   section ;
	/// この節の全行数です。起点別の観測へ加算します
	LONG							   lines{} ;
	/// この節から元順に得られたCoInstallers32作用の件数です
	std::size_t						   coInstallers{} ;
	/// 元行順の用途と識別結果です。同じ値が複数回現れた場合も保持します
	std::vector<MaintenanceInfFileUse> fileUses ;
} ;

/** @brief 一INFの全選択が共同消費する有限走査予算 */
struct MaintenanceStructureBudget {
	/// 収集内容の非実行作用調査だけで共有節とバイナリ行の追加枠を使う
	bool											collectionContent{} ;
	/// 公式範囲で別用途の解釈を禁止する、同じOSの全検証済みModelsセクション
	std::span<const OfficialInfScopedModelsSection> modelSections ;
	/// 公式範囲の全Hardware IDがPCIで正式Netクラスの場合だけ有効
	bool											scopedPciNet{} ;
	/// 公式範囲の全Hardware IDがUSBで正式Netクラスの場合だけ有効
	bool											scopedUsbNet{} ;
	/// 公式範囲を検査する収集workerの同期取消し照会
	const std::function<bool()>					   *cancellation{} ;
	/// 収集で初めて訪問した節名と用途の組。延べ訪問数とは別に上限を保つ
	std::vector<InstallInventorySection>			distinctSections ;
	/// 同期中の同じHINFで全行読取りを終えたレジストリ節だけを保持する
	std::vector<MaintenanceSharedRegistrySection>	sharedRegistry ;
	/// 公式収集の同じ固定元INFだけが読取り済み観測を再利用できます
	HINF											sharedRegistryInf{} ;
	/// Models・Version・source・選択到達節で実際に読み取った累積行数
	std::size_t										lines{} ;
	/// 共通宣言の行と収集で初めて訪問した節・用途の行数
	std::size_t										distinctLines{} ;
	/// 全選択で訪問した節数。共有節の再観測も消費する
	std::size_t										sections{} ;
	/// 全選択で保持した作用数
	std::size_t										effects{} ;
	/// 全選択で保持した明示参照数
	std::size_t										references{} ;
	/// 全選択で保持したservice構造数
	std::size_t										services{} ;
	/// 全選択で保持した具体的診断数
	std::size_t										issues{} ;
	/// 全選択で保持した用途観測数
	std::size_t										fileUses{} ;
	/// 全選択で保持した未解釈作用の観測数
	std::size_t										coverageGaps{} ;
} ;

/** @brief 有限queueで到達したnamed copyの元destinationとsourceを保持する私有観測 */
struct MaintenanceCopyDestination {
	/// 同じINFでCopyFilesから到達したlist名
	std::wstring section ;
	/// 読取済み行の展開後destination名。導入先の充足証拠ではない
	std::wstring destination ;
	/// 明示別名または省略時のdestinationと同名の元source名
	std::wstring source ;
	/// 全値証明へ結合した同元raw行。通常readerでは未結合
	std::size_t	 rawRow{MAXIMUM_INSTALL_INVENTORY_ITEMS} ;
} ;

/** @brief 同INFのnamed固有DestinationDirsとWindowsの非実行展開結果 */
struct MaintenanceDestinationDirectory {
	/// 到達したnamed copy listと完全一致する元key
	std::wstring  section ;
	/// 全数値解析に成功した明示DIRID。未対応値を既知directoryへ補完しない
	std::uint32_t dirid{} ;
	/// DestinationDirsの安全相対subdir。媒体pathとは別の値
	std::wstring  subdirectory ;
	/// 同HINFのSetupAPIが返した導入先directory。fileをopenしない
	std::wstring  expandedDirectory ;
	/// 位置根拠の元診断。成功0、未対応とAPI失敗は非零
	NativeError	  error{nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
	/// 元keyと全fieldを比較したraw行
	std::size_t	  rawRow{MAXIMUM_INSTALL_INVENTORY_ITEMS} ;
	/// 同じ二段target APIの必要長・取得長・終端が一致した場合true
	bool		  targetComplete{} ;
} ;

/** @brief 構築済み私有vectorを同期借用する一copyの位置根拠cache */
struct MaintenanceCopyBinding {
	/// 構築完了したcopiesの一行。cache使用中に元vectorを変更しない
	const MaintenanceCopyDestination	  *copy{} ;
	/// 構築完了したdirectoriesの一意entry。未確定ではnull
	const MaintenanceDestinationDirectory *directory{} ;
	/// 同HINFの展開済み全target。成功根拠がある場合だけ保持する
	std::wstring						   fullTarget ;
	/// 同じ明示DIRID／subdir／destinationの全raw target
	std::wstring						   rawTarget ;
	/// 未確定・重複・未対応の元診断。根拠一意なら0
	NativeError							   error{nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 失敗を未対応・合格で上書きしないよう個別構造結果を併合する
 * @param[in,out] target 集約先。未検査から開始できる
 * @param[in] source 一つの観測結果。診断値は最初の同段階を保持する
 */
//------------------------------------------------------------------------------
void mergeMaintenanceFinding( MaintenanceInspectionFinding		&target,
							 const MaintenanceInspectionFinding &source) noexcept
{
	// 最初の結果と、既知失敗への昇格だけを優先して元診断を保持する
	if( target.state == MaintenanceInspectionState::NOT_CHECKED ||
	   (source.state == MaintenanceInspectionState::FAILED && target.state != source.state) ||
	   (source.state == MaintenanceInspectionState::UNSUPPORTED &&
		target.state == MaintenanceInspectionState::PASSED)) {
		target = source ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元宣言へ結合した個別診断を保持し選択parserへ射影する
 * @param[in,out] install この選択だけの構造観測
 * @param[in] section 元の節名。同期借用して所有copyへ移す
 * @param[in] directive 元のdirective名
 * @param[in] reason 具体的な未対応または不正理由
 * @param[in] finding 元HRESULTを持つ独立結果
 */
//------------------------------------------------------------------------------
void addMaintenanceIssue( MaintenanceInfInstallStructure &install, const std::wstring &section,
						 const std::wstring &directive, MaintenanceInfStructureReason reason,
						 MaintenanceInspectionFinding finding)
{
	install.issues.push_back( {section, directive, reason, finding}) ;
	mergeMaintenanceFinding( install.parser, finding) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開後の全flags fieldを厳密なuint32十進／十六進へ変換する
 * @param[in] value SetupAPIが選択localeで展開した全field。借用のみ
 * @param[out] flags 成功時だけ更新する。失敗時に0や2を補完しない
 * @param[out] reason 失敗時の具体的理由。成功時の値は使用しない
 * @return 数値成功PASSED、未展開・未対応表現UNSUPPORTED、不正・overflowはFAILED
 * @note 元Strings単値がWindows内で切捨てられていないことまでは検証しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] MaintenanceInspectionFinding parseMaintenanceFlags(
	std::wstring_view value, std::uint32_t &flags, MaintenanceInfStructureReason &reason) noexcept
{
	// 残ったtokenを未定義・循環のどちらとも数値へ補完しない
	if( value.find( L'%') != std::wstring_view::npos) {
		reason = MaintenanceInfStructureReason::UNRESOLVED_FLAGS_TOKEN ;
		return {MaintenanceInspectionState::UNSUPPORTED, nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
	}

	// Windowsの符号付き許可表現を今回のunsigned形式へ黙って補正しない
	if( value.starts_with( L"+")) {
		reason = MaintenanceInfStructureReason::FLAGS_FORMAT_NOT_SUPPORTED ;
		return {MaintenanceInspectionState::UNSUPPORTED, nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
	}

	std::uint32_t radix = 10U ;	// 0x prefixの場合だけ基数を切り替える
	// 十六進を明示したfieldのprefixだけを除き、残り全文を検査する
	if( value.starts_with( L"0x") || value.starts_with( L"0X")) {
		radix = 16U ;
		value.remove_prefix( 2U) ;
	}

	// 明示空flagsとprefixだけでは数値を確定できない
	if( value.empty()) {
		reason = MaintenanceInfStructureReason::MISSING_SERVICE_FIELD ;
		return {MaintenanceInspectionState::FAILED, nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
	}

	std::uint32_t parsed{} ;	// 全文字成功まで出力へ反映しない
	// 全桁を一度ずつ解析し、不正文字または追加前overflowで終了する
	for( const wchar_t character : value) {
		std::uint32_t digit = radix ;	// 未対応文字は基数以上として拒否する
		// ASCII十進数字だけを数値へ変換する
		if( character >= L'0' && character <= L'9') {
			digit = static_cast<std::uint32_t>( character - L'0') ;
		}
		// 十六進の大文字A～Fを同じ数値へ変換する
		else if( radix == 16U && character >= L'A' && character <= L'F') {
			digit = static_cast<std::uint32_t>( character - L'A') + 10U ;
		}
		// 十六進の小文字a～fも別の桁表現として扱う
		else if( radix == 16U && character >= L'a' && character <= L'f') {
			digit = static_cast<std::uint32_t>( character - L'a') + 10U ;
		}

		// 負号・空白・非数値を全field検査で拒否し、部分数値を返さない
		if( digit >= radix) {
			reason = MaintenanceInfStructureReason::INVALID_FLAGS_NUMBER ;
			return {MaintenanceInspectionState::FAILED, nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
		}

		// 乗算・加算の前にuint32上限を判定し、wraparoundを成功としない
		if( parsed > (std::numeric_limits<std::uint32_t>::max() - digit) / radix) {
			reason = MaintenanceInfStructureReason::FLAGS_OVERFLOW ;
			return {MaintenanceInspectionState::FAILED,
					nativeErrorFromWin32( ERROR_ARITHMETIC_OVERFLOW)} ;
		}

		parsed = parsed * radix + digit ;
	}

	flags = parsed ;
	return {MaintenanceInspectionState::PASSED, 0} ;
}

// 公式Netの収集棚卸しが元行から識別した無線設定の表示用途
constexpr std::wstring_view WIRELESS_PARAMETER_LABEL = L"WirelessParameterLabel" ;
// 単一コピー形では別実ファイルの可能性を確認済み用途に含めません
constexpr std::wstring_view WIRELESS_BARE_REGISTRY_FILE = L"WirelessBareRegistryFileNotAssessed" ;

//------------------------------------------------------------------------------
/**
 * @brief 設定の元AddReg行をスラッシュ入りの無線表示文字列として識別する
 * @param[in] values 同じ元行でSetupAPIが展開した全フィールド。同期中だけ借用する
 * @param[in] scopedUsbWireless 公式USB無線の同じ選択の列挙に限り、Wi-Fi 7の元表記を認識します
 * @return HKRの詳細設定にある記述または列挙ラベルで、全スラッシュが既知表記の場合true
 */
//------------------------------------------------------------------------------
bool isWirelessParameterLabel( std::span<const std::wstring> values, bool scopedUsbWireless)
{
	constexpr std::wstring_view	  prefix = L"Ndi\\Params\\" ;	// 詳細設定のHKR内キー
	std::uint32_t				  flags{} ;						// 元データ型とレジストリ動作のフラグ
	MaintenanceInfStructureReason reason{} ;					// SetupAPI展開後の元数値解析の診断
	// 表示用キーへ登録する一つのREG_SZだけを判定する
	if( values.size() != 5U || !stringsEqual( values[0], L"HKR") ||
	   !stringsEqual( std::wstring_view{values[1]}.substr( 0U, prefix.size()), prefix) ||
	   parseMaintenanceFlags( values[3], flags, reason).state !=
		   MaintenanceInspectionState::PASSED ||
	   flags != 0U) {
		return false ;
	}

	const auto property =
		std::wstring_view{values[1]}.substr( prefix.size()) ;	// 単一の設定名と任意のenum
	const auto delimiter = property.find( L'\\') ;				// 設定名の末尾
	// 設定自体の説明は列挙子のサブキーには置かない
	const bool description = delimiter == property.npos && stringsEqual( values[2], L"ParamDesc") ;
	const bool enumLabel   = delimiter != property.npos && !values[2].empty() &&
						   stringsEqual( property.substr( delimiter), L"\\enum") &&
						   std::ranges::all_of( values[2], []( wchar_t character) {
							   return character >= L'0' && character <= L'9' ;
						   }) ;	   // 数値列挙子のラベルだけを確認する
	const auto &label = values[4] ;	// 比較対象の元表示文言
	// 別の登録用途、実パス、展開トークン、制御文字は未検査用途に残す
	if( property.empty() || delimiter == 0U || (!description && !enumLabel) ||
	   label.find( L'/') == label.npos || label.find_first_of( L"\\:%\r\n\t") != label.npos) {
		return false ;
	}

	constexpr std::array<std::wstring_view, 10U> terms{
		L"802.11a/b/g",	   L"802.11a/g", L"802.11b/g",	  L"802.11b/g/n",
		L"802.11b/g/n/ax", L"802.11a/n", L"802.11a/n/ac", L"802.11a/n/ac/ax",
		L"802.11n/ac",	   L"RTS/CTS"} ;	// 規格と制御方式の完全な語
	constexpr std::array<std::wstring_view, 3U> USB_WIFI7_LABELS{
		L"802.11ax/be", L"802.11a/n/ac/ax/be", L"802.11b/g/n/ax/be"} ;	// 元列挙にあるWi-Fi 7表記です
	// 全スラッシュについて語の境界を照合し、パスの部分一致を認めない
	for( auto slash = label.find( L'/'); slash != label.npos;) {
		const auto separator = label.find_last_of( L" (", slash) ;				// 元の左側区切り
		const auto start	 = separator == label.npos ? 0U : separator + 1U ;	// 完全な語の開始位置
		const auto end		 = label.find_first_of( L" )", slash) ;				// 完全な語の後ろの区切り
		const auto term =
			std::wstring_view{label}.substr( start, end - start) ;	// 境界を持つ完全な表示語です
		// 未知のスラッシュ表記を元ファイル用途から除外しない
		if( !isAllowedValue( term, terms) &&
		   !(scopedUsbWireless && enumLabel && isAllowedValue( term, USB_WIFI7_LABELS))) {
			return false ;
		}

		slash = end == label.npos ? label.npos : label.find( L'/', end) ;
	}

	return true ;
}

/** @brief 元のqueryと実readを補助APIより前に捕捉する私有記録 */
struct MaintenanceFieldRead {
	/// 元必要長queryのBOOL
	BOOL  query{} ;
	/// query直後の元error
	DWORD queryError{} ;
	/// queryの終端込み必要長
	DWORD required{} ;
	/// 元実readのBOOL
	BOOL  read{} ;
	/// read直後の元error
	DWORD readError{} ;
	/// 実readの終端込み必要長
	DWORD readRequired{} ;
	/// 有限buffer内で終端を確認した場合true
	bool  terminated{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 空を許可する既存readerへ必要長の上限確認を付ける
 * @param[in,out] line 同期借用するSetupAPI行
 * @param[in] field 値field番号。0はkey
 * @param[out] value 成功時の全展開値。失敗時は空
 * @param[out] proof 非nullなら同じ二呼出しの元結果を捕捉する。通常構造読取はnull
 * @return 成功0、終端込み4,096文字超過はERROR_BUFFER_OVERFLOW、読取失敗は元HRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readMaintenanceField( INFCONTEXT &line, DWORD field, std::wstring &value,
											   MaintenanceFieldRead *proof = nullptr)
{
	value.clear() ;
	// Windowsが返す展開後の必要文字数。元Strings原長ではない
	DWORD		required{} ;
	const BOOL	query	   = SetupGetStringFieldW( &line, field, nullptr, 0U, &required) ;	// 元query
	const DWORD queryError = GetLastError() ;												// 追加観測より前に元errorを保持する
	// 明示outだけへ元観測を渡し、通常readerの戻り値を変えない
	if( proof != nullptr) {
		*proof = {query, queryError, required} ;
	}

	// 必要長の読取失敗を空値へ変換しない
	if( query == FALSE && queryError != ERROR_INSUFFICIENT_BUFFER) {
		return nativeErrorFromWin32( queryError) ;
	}

	// 境界超過を個別flags診断へ分離できるよう固有HRESULTを返す
	if( required > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	// null opt-outでは従来の実readと空field契約をそのまま使う
	if( proof == nullptr) {
		return readInstallInventoryField( line, field, value) ;
	}

	std::array<wchar_t, MAXIMUM_INF_FIELD_CHARACTERS> buffer{} ;	// 元と同じ有限buffer
	proof->read		 = SetupGetStringFieldW( &line, field, buffer.data(),
											static_cast<DWORD>( buffer.size()), &proof->readRequired) ;
	proof->readError = GetLastError() ;
	// 元read失敗を私有保留へ弱めず、そのHRESULTで全体拒否する
	if( proof->read == FALSE) {
		return nativeErrorFromWin32( proof->readError) ;
	}

	const auto end	  = std::ranges::find( buffer, L'\0') ;	// 有限内の最初の終端
	proof->terminated = end != buffer.end() ;
	// 終端のない成功bufferを所有文字列へ変換しない
	if( !proof->terminated) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	value.assign( buffer.begin(), end) ;
	return 0 ;
}

// 私有原byte・全recordの共同byte上限
constexpr std::size_t MAXIMUM_MAINTENANCE_PROOF_BYTES = 1024U * 1024U ;
// 単一の署名済みNet原本と保護された依存文書にそれぞれ適用する上限です
constexpr std::size_t MAXIMUM_INACTIVE_CO_INSTALLER_BYTES = 4U * 1024U * 1024U ;
// 言語別の元定義行も含めて省略せず検査する有限上限です
constexpr std::size_t MAXIMUM_INACTIVE_CO_INSTALLER_ITEMS = 24576U ;
// 一時全field値・有限caller／binding indexの保守byte予約。raw offsetと共同1MiBへ含める
constexpr std::size_t MAINTENANCE_PROOF_OVERHEAD_BYTES = 256U * 1024U ;
// 私有行indexの未結合値。公開identityへ渡さない
constexpr std::size_t NO_MAINTENANCE_RAW_ROW = MAXIMUM_INSTALL_INVENTORY_ITEMS ;

/** @brief 一回の原snapshot上のcode unit範囲を借用する */
struct MaintenanceRawSpan {
	/// BOMを除くcode unit開始位置
	std::size_t begin{} ;
	/// 終端を含まないcode unit数
	std::size_t size{} ;
} ;

/** @brief case非依存merge後の節envelope */
struct MaintenanceRawSection {
	/// 原byte上の元節名。別decoded本文を保持しない
	MaintenanceRawSpan name ;
	/// merge後の非空entry数
	std::size_t		   count{} ;
} ;

/** @brief 同section・ordinalの原keyと全fieldの一意結合 */
struct MaintenanceRawRow {
	/// merge後の節index
	std::size_t		   section{} ;
	/// 0始まりのmerge後entry ordinal
	std::size_t		   ordinal{} ;
	/// keyなし行は空範囲
	MaintenanceRawSpan key ;
	/// field offset vectorの開始位置
	std::size_t		   firstField{} ;
	/// keyを除く厳密field数
	std::size_t		   fields{} ;
	/// 全API値が原値と一致した場合true
	bool			   verified{} ;
	/// built-in13の全target比較を最後へ保留するfield。0は保留なし
	std::size_t		   deferredField{} ;
	/// 全取得済み値fieldのbitmap。64fieldを切り捨てない
	std::uint64_t	   observed{} ;
	/// 元keyの有無もAPIへ比較した場合true
	bool			   keyObserved{} ;
} ;

/** @brief 元用途と原data行をindexだけで結ぶ撤回可能な位置stage */
struct MaintenanceRegistryDataProof {
	/// 同元byteの行index
	std::size_t row{} ;
	/// 元install.fileUsesのdata一件
	std::size_t use{} ;
	/// 元queueのREGISTRY index
	std::size_t queue{} ;
	/// 最終append先。親markerの分離後に補正する
	std::size_t file{NO_MAINTENANCE_RAW_ROW} ;
	/// 一意EventLog callerを全queue終了後に認定した場合true
	bool		caller{} ;
	/// 全target／sourceが成立した元source用途index。最後まで公開位置へ反映しない
	std::size_t sourceFile{NO_MAINTENANCE_RAW_ROW} ;
} ;

/**
 * @brief 同期readerだけで元byte・私有component・全値証明を所有する
 * @note HINFより先に構築して後に破棄する。共有Windows／Tempへlockを掛けない
 * 私有失敗は予約を撤回し元Uを保持する。元byte不一致だけは既存全体拒否へ返す
 */
class MaintenanceInfByteProof final {
public:
	/**
	 * @brief 空の私有証明を構築する
	 */
	MaintenanceInfByteProof() = default ;
	/**
	 * @brief HINF解放後に元fileとprivate componentを逆順に閉じる
	 */
	~MaintenanceInfByteProof() noexcept
	{
		// 元fileのshare境界をHINF終了まで維持する
		if( file_ != INVALID_HANDLE_VALUE) {
			CloseHandle( file_) ;
		}

		// 私有rootまでの取得済みdirectoryだけを逆順に解放する
		while( handleCount_ != 0U) {
			CloseHandle( handles_[--handleCount_]) ;
		}
	}
	/**
	 * @brief 同期leaseの複製をコンパイル時に禁止します
	 * @param[in] other 呼出し不能な元proofです。借用・変更・resource移動を行いません
	 * @note 削除宣言だけで関数本体はありません
	 */
	MaintenanceInfByteProof( const MaintenanceInfByteProof &other) = delete ;
	/**
	 * @brief 同期leaseの代入をコンパイル時に禁止します
	 * @param[in] other 呼出し不能な元proofです。借用・変更・resource移動を行いません
	 * @note 削除宣言だけで関数本体はありません
	 */
	MaintenanceInfByteProof &operator=( const MaintenanceInfByteProof &other) = delete ;
	/**
	 * @brief 現在全値証明へ使用できる場合trueを返す
	 * @return 私有proofが失効していなければtrue
	 */
	[[nodiscard]] bool		 active() const noexcept
	{
		return active_ ;
	}
	/**
	 * @brief 固定済みの同署名INF全体で旧共同インストーラーへの参照がないことを確認します
	 * @param[in] inf 同じバイトを保持中に開いた読取専用HINFです
	 * @param[in] bytes HINFを閉じるまで同ファイルの書き換えと置換を防ぐ元バイトです
	 * @param[in,out] inactive 元CABでは全確認後の候補を返し、Windows依存では同じ名前を照合します
	 * @param[in] storeInf 空は元CABです。Windows依存では署名と同じ対応StoreのINF絶対パスです
	 * @return 全節・全行・全フィールドの照合と逆参照の検査が成立した場合trueです
	 */
	[[nodiscard]] bool inactiveCoInstaller( HINF inf, std::span<const std::byte> bytes,
										   InactiveCoInstaller &inactive,
										   std::wstring_view	storeInf = {}) ;
	/**
	 * @brief 収集INFのクラス登録を別の導入節として再利用できないことを確認する
	 * @param[in] inf 同じ元バイトを固定中に開いた読取り専用HINF
	 * @param[in] bytes HINFの存続中に置換を防ぐ元INFの全バイト
	 * @param[in] registrations Windowsで確認したクラス節と登録先の対
	 * @return 元の全節・全フィールドと多言語文字列で参照が分離されていればtrue
	 */
	[[nodiscard]] bool isolatedClassRegistration(
		HINF inf, std::span<const std::byte> bytes,
		std::span<const std::pair<std::wstring, std::wstring>> registrations) ;
	/**
	 * @brief 全節と全言語から、不在媒体とx86専用媒体への逆参照を検査します
	 * @param[in] inf 同じ元バイトを保持中に開いた読取専用HINFです
	 * @param[in] bytes 固定中の元INFの全バイトです
	 * @param[in] leaf 証明する元媒体名です。DLLは不在の候補、SYSはx86専用の候補です
	 * @param[in,out] isolation 元CABの節の境界を成功時に返します。同梱側はその元境界を借用します
	 * @param[in] inbox 保護された同梱INFを検査する場合trueです
	 * @param[out] wifiDependency 元INFで同梱Wi-Fiバスを参照するかを成功時に返します
	 * @return 全値の照合と逆参照の不存在を確認できた場合trueです
	 */
	[[nodiscard]] bool		  proveScopedMediaIsolation( HINF inf, std::span<const std::byte> bytes,
														std::wstring_view	  leaf,
														ScopedMediaIsolation &isolation, bool inbox,
														bool &wifiDependency) ;
	/**
	 * @brief 同じ元サービス節の引用符付きDIRID 13宣言を元コピー名に照合します
	 * @param[in] bytes 読取専用HINFと同時に保持する元INFです
	 * @param[in] service 元の補助サービス構成節です
	 * @param[in] leaf 元コピーの単独EXE名です
	 * @return 元節の一意なリテラル宣言が同じEXE名を指定した場合trueです
	 */
	[[nodiscard]] bool		  matchesScopedUsbStoreService( std::span<const std::byte> bytes,
														   std::wstring_view		  service,
														   std::wstring_view		  leaf) ;
	/**
	 * @brief 同原byteの全潜在節を限定registry-only System形式へ照合します
	 * @param[in] inf 同snapshot取得後に開いた読取専用HINFです。同期中だけ借用します
	 * @param[in] catalog 同原INFから選択済みのCAT名です。全装飾宣言も同じ名を要求します
	 * @param[out] matched 全節と全fieldが成立した場合だけtrueです。失敗時はfalseです
	 * @return 読取完了又は形式不一致0、Windows読取失敗は元HRESULTです
	 * @note collector必須importの分類だけです。未知proofを成功へ補完せず、旧nullや作用gapを変更しません
	 */
	[[nodiscard]] NativeError requiredRegistryContent( HINF inf, std::wstring_view catalog,
													  bool &matched)
	{
		matched = false ;
		// raw全体証明と一意なsection envelopeのない形式を例外へ渡しません
		if( !active_ || duplicateSections_) {
			return 0 ;
		}

		// 元source付き形式は通常のfile検査へ残し、空以外のsourceを省略しません
		for( const auto &section : sections_) {
			const auto name	  = text( section.name) ;	// 同原名の短命copyです
			const bool source = stringsEqual( name, L"SourceDisksFiles") ||
								stringsEqual( name, L"SourceDisksFiles.amd64") ||
								stringsEqual( name, L"SourceDisksNames") ||
								// 既明示空の四標準名だけです
								stringsEqual( name, L"SourceDisksNames.amd64") ;
			// 非空sourceはこの例外の対象ではありません
			if( source && section.count != 0U) {
				return 0 ;
			}
		}

		const auto error = verifyRequiredRegistryRows( inf) ;	// 全API値と元全fieldの一致です
		// Windowsの実読取失敗をローカル形式不一致で上書きしません
		if( error != 0 || !active_) {
			return error ;
		}

		// 同raw名の一意なsectionだけをindexへ解決し、別HINFへ問い合わせません
		const auto sectionIndex = [this]( std::wstring_view name) {
			return static_cast<std::size_t>(
				std::ranges::find_if(
					sections_,
					[&]( const auto &item) { return stringsEqual( text( item.name), name) ; }) -
				sections_.begin()) ;
		} ;
		// 全rowがsection順に確定済みなので、同sectionの先頭だけを借用します
		const auto firstRow = [this]( std::size_t section) {
			return static_cast<std::size_t>(
				std::ranges::lower_bound( rows_, section, {}, &MaintenanceRawRow::section) -
				rows_.begin()) ;
		} ;
		const auto manufacturer = sectionIndex( L"Manufacturer") ;	// 全architectureの宣言元です
		// 宣言なしのSystemをregistry-onlyへ推測しません
		if( manufacturer == sections_.size() || sections_[manufacturer].count == 0U) {
			return 0 ;
		}

		std::vector<std::size_t>  models ;	// 全明示Modelsの同raw indexです
		std::vector<std::wstring> bases ;	// 全Modelsが宣言するDDInstall基名です
		// 全manufacturer行と全装飾を同じ原fieldから列挙します
		for( std::size_t index = firstRow( manufacturer);
			index < rows_.size() && rows_[index].section == manufacturer; ++index) {
			std::wstring			  key ;		// 宣言行の元keyです
			std::vector<std::wstring> values ;	// この一行だけの展開済み値です
			// 欠損fieldや不正なModels基名を別の正常行で救済しません
			if( !requiredRegistryValues( index, key, values) || key.empty() || values.empty() ||
			   !validInstallInventorySectionName( values.front())) {
				return 0 ;
			}

			const auto plain = sectionIndex( values.front()) ;	// 存在する未装飾Modelsです
			// 未装飾節も元potential集合へ含めます
			if( plain != sections_.size()) {
				models.push_back( plain) ;
			}

			// 明示装飾は非選択architectureも欠落を許しません
			for( std::size_t field = 1U; field < values.size(); ++field) {
				const auto decorated =
					// 元全名です
					sectionIndex( values.front() + L"." + values[field]) ;
				// 未知名や欠損節を現在OSの選択へ縮約しません
				if( !validInstallInventorySectionName( values[field]) ||
				   decorated == sections_.size()) {
					return 0 ;
				}

				models.push_back( decorated) ;
			}

			// 未装飾だけを宣言した行にも実在節を要求します
			if( values.size() == 1U && plain == sections_.size()) {
				return 0 ;
			}

			// 既Models上限を越えた宣言を切り捨てません
			if( models.size() > 128U) {
				return 0 ;
			}
		}

		std::ranges::sort( models) ;
		models.erase( std::unique( models.begin(), models.end()), models.end()) ;
		// 空Models集合から例外を発行しません
		if( models.empty()) {
			return 0 ;
		}

		// 全potential ModelsのIDとDDInstall基名を検査します
		for( const auto model : models) {
			// 明示空Modelsは元IDの証拠になりません
			if( sections_[model].count == 0U) {
				return 0 ;
			}

			// 各行の全fieldを元順で確認し、最初の公開IDだけへ縮小しません
			for( std::size_t index = firstRow( model);
				index < rows_.size() && rows_[index].section == model; ++index) {
				std::wstring			  key ;		// 同Models行の表示keyです
				std::vector<std::wstring> values ;	// 基名と全元IDです
				// 不正基名やID省略をnullへ読み替えません
				if( !requiredRegistryValues( index, key, values) || key.empty() ||
				   values.size() < 2U || !validInstallInventorySectionName( values.front())) {
					return 0 ;
				}

				static_cast<void>( appendUnique( bases, values.front())) ;
				// 同field由来の全Hardware/Compatible IDを検査します
				for( std::size_t field = 1U; field < values.size(); ++field) {
					// 非選択節の不正IDも内容成功から除外しません
					if( !validNativeModelsId( values[field])) {
						return 0 ;
					}
				}
			}
		}

		std::vector<std::size_t> installs ;					// 元Modelsに一意所属する実install節です
		std::vector<std::size_t> services ;					// 実installに対を要求するservice節です
		std::vector<bool>		 observed( bases.size()) ;	// 全baseの実在処理です
		std::wstring			 registry ;					// 全installが同一の一節だけへ結ぶ参照名です
		// 全sectionを見て、既知のDDInstall装飾と正確なservice対だけを抽出します
		for( std::size_t section = 0U; section < sections_.size(); ++section) {
			const auto					name   = text( sections_[section].name) ;	// 元section名です
			constexpr std::wstring_view SUFFIX = L".Services" ;						// 一対だけのsuffixです
			const bool					service =
				name.size() > SUFFIX.size() &&
				stringsEqual( std::wstring_view{name}.substr( name.size() - SUFFIX.size()),
							 SUFFIX) ;	// 元対です
			const std::wstring_view install =
				service ? std::wstring_view{name}.substr( 0U, name.size() - SUFFIX.size())
						: std::wstring_view{name} ;	// serviceから元install名だけを外します
			std::size_t matches{} ;					// 複数baseへ所属する曖昧名を拒否します
			std::size_t owner{} ;					// 一致したbaseだけのindexです
			// 全baseへ一度ずつ照合し、prefix一致だけで所有を補完しません
			for( std::size_t base = 0U; base < bases.size(); ++base) {
				// 既知NT装飾だけを同baseの潜在処理とします
				if( requiredRegistryInstallName( install, bases[base])) {
					++matches ;
					owner = base ;
				}
			}

			// 無関係節は後の閉集合検査で判定します
			if( matches == 0U) {
				continue ;
			}

			// 曖昧所属や追加行を単一の処理へ縮約しません
			if( matches != 1U || sections_[section].count != 1U) {
				return 0 ;
			}

			std::wstring			  key ;		// 同一行の元directiveです
			std::vector<std::wstring> values ;	// 全fieldを省略せず比較します
			// API全値の一致しない行を原参照へ使いません
			if( !requiredRegistryValues( firstRow( section), key, values)) {
				return 0 ;
			}

			// 空名serviceだけを正確な二fieldとflagsへ結びます
			if( service) {
				std::uint32_t				  flags{} ;		// serviceとregistryのflagsを混同しません
				MaintenanceInfStructureReason reason{} ;	// 数値不一致だけのローカル理由です
				// 余分fieldとnamed serviceを例外へ渡しません
				if( !stringsEqual( key, L"AddService") || values.size() != 2U || !values[0].empty() ||
				   parseMaintenanceFlags( values[1], flags, reason).state !=
					   MaintenanceInspectionState::PASSED ||
				   flags != SPSVCINST_ASSOCSERVICE || sectionIndex( install) == sections_.size()) {
					return 0 ;
				}

				services.push_back( section) ;
			} else {
				// 全installは同じ既存の一registry節とservice対だけを参照します
				if( !stringsEqual( key, L"AddReg") || values.size() != 1U ||
				   !validInstallInventorySectionName( values[0]) ||
				   sectionIndex( values[0]) == sections_.size() ||
				   (!registry.empty() && !stringsEqual( registry, values[0])) ||
				   sectionIndex( name + std::wstring{SUFFIX}) == sections_.size()) {
					return 0 ;
				}

				registry		= values[0] ;
				observed[owner] = true ;
				installs.push_back( section) ;
			}
		}

		// 全baseの実在処理と同数のservice対がなければ成立させません
		if( registry.empty() || installs.empty() || services.size() != installs.size() ||
		   !std::ranges::all_of( observed, []( bool value) { return value ; })) {
			return 0 ;
		}

		const auto registrySection = sectionIndex( registry) ;	// 元の同一registry節です
		// registryをmetadata/Models/install/serviceと重ねません
		if( registrySection == manufacturer ||
		   std::ranges::find( models, registrySection) != models.end() ||
		   std::ranges::find( installs, registrySection) != installs.end() ||
		   std::ranges::find( services, registrySection) != services.end() ||
		   sections_[registrySection].count != 1U) {
			return 0 ;
		}

		std::wstring				  key ;			// HKR行にはkeyがないことも原byte/APIで確認済みです
		std::vector<std::wstring>	  values ;		// 正確な五fieldだけの短命copyです
		std::uint32_t				  flags{} ;		// registryの型/flagsです
		std::uint32_t				  dataValue{} ;	// 単一DWORDをuint32全範囲で検査します
		MaintenanceInfStructureReason reason{} ;	// 符号/overflow/未解決tokenの拒否理由です
		// field0不存在と全五fieldを別に扱い、未評価の別root/文字列型を救済しません
		if( !requiredRegistryValues( firstRow( registrySection), key, values) || !key.empty() ||
		   values.size() != 5U || !stringsEqual( values[0], L"HKR") ||
		   !requiredRegistrySubkey( values[1]) || !requiredRegistryWord( values[2]) ||
		   parseMaintenanceFlags( values[3], flags, reason).state !=
			   MaintenanceInspectionState::PASSED ||
		   flags != 0x00010001U ||
		   parseMaintenanceFlags( values[4], dataValue, reason).state !=
			   MaintenanceInspectionState::PASSED) {
			return 0 ;
		}

		bool classSeen{} ;	// Systemの正規対を独立に確認します
		bool guidSeen{} ;	// 重複metadataも後の閉集合で拒否します
		// 全節を既知の閉集合へ照合し、孤立作用も除外しません
		for( std::size_t section = 0U; section < sections_.size(); ++section) {
			const auto name = text( sections_[section].name) ;	// 原節名を元caseのまま借用します
			// graphで検証した節だけを先に扱います
			if( section == manufacturer || section == registrySection ||
			   std::ranges::find( models, section) != models.end() ||
			   std::ranges::find( installs, section) != installs.end() ||
			   std::ranges::find( services, section) != services.end() ||
			   (isStrings( name) && validStringsName( name))) {
				continue ;
			}

			// 既標準source/mediaの明示空以外を例外へ入れません
			if( stringsEqual( name, L"SourceDisksFiles") ||
			   stringsEqual( name, L"SourceDisksFiles.amd64") ||
			   stringsEqual( name, L"SourceDisksNames") ||
			   stringsEqual( name, L"SourceDisksNames.amd64")) {
				// 全行0だけがこの経路での許可条件です
				if( sections_[section].count != 0U) {
					return 0 ;
				}

				continue ;
			}

			// 未知の節をmetadataとして飛ばしません
			if( !stringsEqual( name, L"Version") && !stringsEqual( name, L"ControlFlags")) {
				return 0 ;
			}

			std::vector<std::wstring> keys ;	// 同節のkey重複を先頭値で隠しません
			// 全metadata行のkeyと厳密field数を検査します
			for( std::size_t index = firstRow( section);
				index < rows_.size() && rows_[index].section == section; ++index) {
				std::wstring			  rowKey ;	// 同rowの元keyです
				std::vector<std::wstring> fields ;	// 元全fieldを確認します
				// 不明なkeyと重複は例外を不成立にします
				if( !requiredRegistryValues( index, rowKey, fields) || rowKey.empty() ||
				   std::ranges::any_of(
					   keys, [&]( const auto &value) { return stringsEqual( value, rowKey) ; })) {
					return 0 ;
				}

				keys.push_back( rowKey) ;
				// ControlFlagsは元の除外表示だけです
				if( stringsEqual( name, L"ControlFlags")) {
					// 未知処理や余分fieldを表示metadataへ混ぜません
					if( !stringsEqual( rowKey, L"ExcludeFromSelect") || fields.size() != 1U ||
					   fields[0] != L"*") {
						return 0 ;
					}

					continue ;
				}

				constexpr std::array VERSION_KEYS{
					std::wstring_view{L"Signature"},  std::wstring_view{L"Class"},
					std::wstring_view{L"ClassGUID"},  std::wstring_view{L"Provider"},
					std::wstring_view{L"DriverVer"},  std::wstring_view{L"CatalogFile"},
					std::wstring_view{L"PnpLockdown"}} ;	// 閉じたmetadataです
				const bool catalogKey =
					stringsEqual( rowKey, L"CatalogFile") ||
					(rowKey.size() > 12U && stringsEqual( std::wstring_view{rowKey}.substr( 0U, 12U),
														 L"CatalogFile.")) ;	// 元装飾も検査します
				// 全metadataのfield数を固定し、別architecture CATを無視しません
				if( (!isAllowedValue( rowKey, VERSION_KEYS) && !catalogKey) ||
				   fields.size() != (stringsEqual( rowKey, L"DriverVer") ? 2U : 1U) ||
				   (catalogKey && !stringsEqual( fields[0], catalog))) {
					return 0 ;
				}

				// 元ClassとGUIDは両方の正式値へ結びます
				if( stringsEqual( rowKey, L"Class")) {
					classSeen = stringsEqual( fields[0], L"System") ;
				}
				// 正式GUIDの確認をClass名だけの成功で置き換えません
				else if( stringsEqual( rowKey, L"ClassGUID")) {
					guidSeen = stringsEqual( fields[0], L"{4d36e97d-e325-11ce-bfc1-08002be10318}") ;
				}
			}
		}

		matched = classSeen && guidSeen ;
		return 0 ;
	}
	/**
	 * @brief 私有予約を全て撤回し、元処理の容量へ返す
	 */
	void disable() noexcept
	{
		active_ = false ;
		std::string{}.swap( bytes_) ;
		std::vector<MaintenanceRawSection>{}.swap( sections_) ;
		std::vector<MaintenanceRawRow>{}.swap( rows_) ;
		std::vector<MaintenanceRawSpan>{}.swap( fields_) ;
		std::vector<MaintenanceRegistryDataProof>{}.swap( data) ;
		std::vector<std::pair<std::size_t, std::size_t>>{}.swap( sourceRows) ;
		std::vector<std::pair<std::size_t, std::size_t>>{}.swap( controlUses) ;
	}
	/**
	 * @brief 既存保護workspace内の元fileを一回だけ順序snapshotへ固定する
	 * @param[in] workspace 元ファイルを所有する同じ保護workspace
	 * @param[in] path workspace.pathで検証済みの元absolute path
	 * @param[in] relativePath 同じ元相対位置
	 * @param[in] entry 元固定entryのsizeとhash
	 * @param[in] registryOnlyProof 必須collectorのregistry proofだけがtrueを渡し、単独コメントの上位バイトとドット区切りの文字列名を扱います
	 * @return 私有成功／保留0、本人領域の照合失敗は元HRESULT、固定size／hash不一致はTRUST_E_BAD_DIGEST
	 */
	[[nodiscard]] NativeError open( const OfficialDownloadWorkspace &workspace,
								   const std::wstring &path, std::wstring_view relativePath,
								   const OfficialZipEntry &entry,
								   bool					   registryOnlyProof = false) noexcept
	{
		try {
			// 生成経路を確認できない入力や私有byte超過は従来readerへ渡す
			if( path.size() <= relativePath.size() ||
			   entry.uncompressedSize > MAXIMUM_MAINTENANCE_PROOF_BYTES -
											MAINTENANCE_PROOF_OVERHEAD_BYTES - sizeof( *this)) {
				return 0 ;
			}

			const bool ownedRegistrySnapshot =
				registryOnlyProof &&
				workspace.protectionMode() ==
					OfficialWorkspaceMode::CURRENT_USER_INSPECTION ;	// 同CopyINF由来の本人収集だけ
			const std::wstring root =
				// 私有rootだけ
				path.substr( 0U, path.size() - relativePath.size() - 1U) ;
			// 本人所有の必須補助以外は、従来のWindows Tempの直下だけを対象とする
			if( !ownedRegistrySnapshot) {
				std::array<wchar_t, MAX_PATH> windows{} ;	// Windowsから得る従来の共有anchor
				const UINT					  length = GetWindowsDirectoryW(
					   // 元OSの絶対位置
					   windows.data(), static_cast<UINT>( windows.size())) ;
				// Windowsの原位置が確定しなければ別の領域を使わない
				if( length == 0U || length >= windows.size()) {
					return 0 ;
				}

				const std::wstring anchor =
					// 保持対象外の共有親
					std::wstring( windows.data()) + L"\\Temp\\" ;
				// 既存生成経路の直下でない私有rootを新たなtrust anchorへしない
				if( root.size() <= anchor.size() ||
				   !stringsEqual( std::wstring_view( root).substr( 0U, anchor.size()), anchor) ||
				   root.find( L'\\', anchor.size()) != root.npos) {
					return 0 ;
				}
			}

			std::wstring component = root ;	// private rootから元INF親までだけを保持する
			std::size_t	 next{} ;			// 元相対pathの次component
			DWORD		 volume{} ;			// 全private HANDLEの同volume拘束
			// 最多64のordinary componentを一度ずつ開き、write／delete shareを許さない
			for( ;;) {
				// 共同component上限ではprivate proofだけを保留する
				if( handleCount_ == handles_.size()) {
					return 0 ;
				}

				const HANDLE handle = CreateFileW(
					component.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
					FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
					nullptr) ;	// 私有directory lease
				// share競合や取得失敗をretryで成立させない
				if( handle == INVALID_HANDLE_VALUE) {
					return 0 ;
				}

				handles_[handleCount_++] = handle ;
				BY_HANDLE_FILE_INFORMATION info{} ;	// 同HANDLEのordinary／volume／identity
				// reparseや上位再結合を観測した場合は元Uを保持する
				if( !ordinary( handle, component, true, info) ||
				   (handleCount_ > 1U && info.dwVolumeSerialNumber != volume)) {
					return 0 ;
				}

				volume				 = info.dwVolumeSerialNumber ;
				const auto separator = relativePath.find( L'\\', next) ;	// 元安全pathの次親要素
				// 元INFの親まで固定した後だけfileを開く
				if( separator == relativePath.npos) {
					break ;
				}

				component += L"\\" + std::wstring( relativePath.substr( next, separator - next)) ;
				next = separator + 1U ;
			}

			file_ = CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
								FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;
			BY_HANDLE_FILE_INFORMATION before{} ;	// 元fileの同HANDLE identityとsize
			// private取得失敗は元hash読取の失敗結果へ混ぜない
			if( file_ == INVALID_HANDLE_VALUE || !ordinary( file_, path, false, before) ||
			   before.dwVolumeSerialNumber != volume) {
				return 0 ;
			}

			const std::uint64_t size =
				(static_cast<std::uint64_t>( before.nFileSizeHigh) << 32U) |
				before.nFileSizeLow ;	// 元sizeと一致しなければbyte整合全体失敗
			// 元固定sizeの不一致をprivate未知へ弱めない
			if( size != entry.uncompressedSize) {
				return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}

			// 親と原ファイルを保持した状態で、本人所有と同じfile identityを再照合する
			if( ownedRegistrySnapshot) {
				const auto error = workspace.verifyInspectionSnapshot(
					relativePath, file_, entry.uncompressedSize) ;	// 元保護領域と同じ一リンクの証拠
				// 検証できない本人領域で原バイトの証明を作らない
				if( error != 0) {
					return error ;
				}
			}

			bytes_.resize( static_cast<std::size_t>( size)) ;
			std::size_t offset{} ;	// 一回の順序snapshotで完了したbyte数
			// 同HANDLEからだけ有限chunkを順序どおり読み、短いreadを完全値へ補完しない
			while( offset < bytes_.size()) {
				const DWORD requested = static_cast<DWORD>(
					(std::min)( bytes_.size() - offset, std::size_t{65536U})) ;	// chunk byte数
				DWORD read{} ;													// このchunkだけの実byte数
				// private I/O失敗は元readerへ戻す
				if( ReadFile( file_, bytes_.data() + offset, requested, &read, nullptr) == FALSE ||
				   read == 0U) {
					disable() ;
					return 0 ;
				}

				offset += read ;
			}

			char					   extra{} ;	// 同HANDLEの確認済みEOF
			DWORD					   read{} ;		// EOF照会の実byte数
			BY_HANDLE_FILE_INFORMATION after{} ;	// snapshot終端の同identity
			// 未確認EOFとidentity照会失敗はprivate保留へ戻す
			if( ReadFile( file_, &extra, 1U, &read, nullptr) == FALSE ||
			   GetFileInformationByHandle( file_, &after) == FALSE) {
				disable() ;
				return 0 ;
			}

			// EOF／size／file identityの実不一致は既存byte整合失敗を保持する
			if( read != 0U || before.dwVolumeSerialNumber != after.dwVolumeSerialNumber ||
			   before.nFileIndexHigh != after.nFileIndexHigh ||
			   before.nFileIndexLow != after.nFileIndexLow ||
			   before.nFileSizeHigh != after.nFileSizeHigh ||
			   before.nFileSizeLow != after.nFileSizeLow) {
				return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}

			std::wstring hash ;	// 原byteに既存hash入口だけを使う
			// private hash API失敗を元hash結果へ上書きしない
			if( computeBytesSha256( bytes_, hash) != 0) {
				disable() ;
				return 0 ;
			}

			// 元entryの明示hashとの全一致を要求する
			if( !entry.sha256.empty() && !stringsEqual( hash, entry.sha256)) {
				return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}

			hash_			   = std::move( hash) ;
			registryOnlyProof_ = registryOnlyProof ;
			active_			   = scan( registryOnlyProof) ;
			// 未対応encoding／構文／quotaを正常parserの新拒否へ変えない
			if( !active_) {
				disable() ;
			}

			return 0 ;
		} catch( const std::bad_alloc &) {
			// 私有allocationだけを撤回し、元allocationのHRESULTは元callerが扱う
			disable() ;
			return 0 ;
		}
	}
	/**
	 * @brief 元通常hashへ一回のsnapshotを完全照合する
	 * @param[in] hash 同じreaderが通常入口で取得した元hash
	 * @return snapshotを取得していない保留は0。不一致はTRUST_E_BAD_DIGEST
	 */
	[[nodiscard]] NativeError matchHash( std::wstring_view hash) const noexcept
	{
		return hash_.empty() || stringsEqual( hash_, hash)
				   ? 0
				   : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	}
	/**
	 * @brief 元処理に必要な共同項目を優先し、私有予約を撤回する
	 * @param[in] coreItems 元保持量。private recordを含まない
	 */
	void capacity( std::size_t coreItems) noexcept
	{
		// coreの必要量をprivate予約で全体失敗へ変えない
		if( active_ && (coreItems > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
					   items() > MAXIMUM_INSTALL_INVENTORY_ITEMS - coreItems ||
					   storage() > MAXIMUM_MAINTENANCE_PROOF_BYTES)) {
			disable() ;
		}
	}
	/**
	 * @brief 同raw節countと元API countからmerged ordinalを一意に結ぶ
	 * @param[in] section 元APIで取得した節名
	 * @param[in] ordinal 同節の元0始まりindex
	 * @param[in] count 元APIの確定全行数
	 * @param[in] fields 元APIの厳密field数
	 * @return 原row index。保留では未結合値
	 */
	[[nodiscard]] std::size_t row( std::wstring_view section, LONG ordinal, LONG count,
								  DWORD fields) noexcept
	{
		try {
			// 失効証明へ新しい原行を補完しない
			if( !active_) {
				return NO_MAINTENANCE_RAW_ROW ;
			}

			std::size_t index{} ;	// 原節indexの探索位置
			// 全有限section名をcase非依存で一度の選択へ結ぶ
			while( index < sections_.size() && !stringsEqual( text( sections_[index].name), section)) {
				++index ;
			}

			// 行数差と原節不在を先頭row検索で救済しない
			if( index == sections_.size() || count < 0 ||
			   sections_[index].count != static_cast<std::size_t>( count)) {
				disable() ;
				return NO_MAINTENANCE_RAW_ROW ;
			}

			const auto found =
				std::ranges::lower_bound( rows_, std::pair{index, static_cast<std::size_t>( ordinal)},
										 {}, []( const auto &item) {
											 return std::pair{item.section, item.ordinal} ;
										 }) ; // 同rowだけを一意選択
			// 全field数差をstrict5行へ縮めない
			if( found == rows_.end() || found->section != index ||
			   found->ordinal != static_cast<std::size_t>( ordinal) || found->fields != fields) {
				disable() ;
				return NO_MAINTENANCE_RAW_ROW ;
			}

			// 同raw行の再readを一回の全値証拠へ合成しない
			if( found->keyObserved || found->observed != 0U) {
				disable() ;
				return NO_MAINTENANCE_RAW_ROW ;
			}

			found->verified = true ;
			return static_cast<std::size_t>( found - rows_.begin()) ;
		} catch( const std::bad_alloc &) {
			disable() ;
			return NO_MAINTENANCE_RAW_ROW ;
		}
	}
	/**
	 * @brief 同じ元query／readから一fieldの全値を比較する
	 * @param[in] index 同raw行index
	 * @param[in] field 0はkey、1以降は元field
	 * @param[in] value 元coreが一度だけ取得した全値。複写して保持しない
	 * @param[in] read 同じ二API呼出しの直後の結果
	 */
	void field( std::size_t index, std::size_t field, std::wstring_view value,
			   const MaintenanceFieldRead &read) noexcept
	{
		try {
			// 既に撤回したprivate行を参照しない
			if( !active_ || index >= rows_.size()) {
				return ;
			}

			auto		&item = rows_[index] ;	// 同元rowの私有状態
			std::wstring expanded ;				// 一fieldだけの有限な独立展開
			const auto	 raw =
				// 元全範囲
				field == 0U ? item.key : fields_[item.firstField + field - 1U] ;
			const bool complete =
				(read.query != FALSE || read.queryError == ERROR_INSUFFICIENT_BUFFER) &&
				read.read != FALSE && read.terminated && read.required == value.size() + 1U &&
				// 部分bufferを成功証拠へ使わない
				read.readRequired == read.required ;
			// 原literal／一段Stringsと元全取得値を独立照合する
			if( !complete || !expand( raw, expanded)) {
				item.verified = false ;
				return ;
			}

			// 唯一の先頭DIRID13だけはnamed full targetが揃うまで保留する
			if( expanded.starts_with( L"%13%\\")) {
				const auto key = text( item.key) ;	// 原keyからfieldの狭い役割を確認する
				const bool targetField =
					(item.key.size == 0U && item.fields == 5U && field == 5U) ||
					(stringsEqual( key, L"ServiceBinary") && item.fields == 1U &&
					 // 唯一の保留用途
					 field == 1U) ;
				// 同rowで二つのDIRID用途を部分比較へ変えない
				if( !targetField || item.deferredField != 0U) {
					item.verified = false ;
				}

				item.deferredField = field ;
			}
			// token-freeな全値の差はcaseやsuffix救済を行わない
			else if( expanded != value || expanded.size() + 1U != read.required) {
				// 全code unitの差はcaseやsuffix救済を行わない
				item.verified = false ;
			}

			// keyと全64fieldを別に記録し、未読fieldを成功へ通さない
			if( field == 0U) {
				item.keyObserved = true ;
			} else {
				item.observed |= std::uint64_t{1U} << (field - 1U) ;
			}
		} catch( const std::bad_alloc &) {
			disable() ;
		}
	}
	/**
	 * @brief core未取得fieldだけを同context内で一回補助取得する
	 * @param[in,out] line 元の同rowcontext。保持しない
	 * @param[in] index 原row index
	 * @param[in] first 最初の未取得field
	 * @param[in] last 最後の未取得field
	 */
	void extra( INFCONTEXT &line, std::size_t index, DWORD first, DWORD last) noexcept
	{
		const DWORD originalError = GetLastError() ;	// 元API結果へ補助errorを混入させない
		try {
			// 未取得fieldだけを一回ずつ補い、query／readを全INFで8192以内へ拘束する
			for( DWORD number = first; active_ && index < rows_.size() && number <= last; ++number) {
				// 私有API予算の枯渇は元field読取を失敗させない
				if( extraCalls_ > 8192U - 2U) {
					disable() ;
					break ;
				}

				extraCalls_ += 2U ;
				// strict原keyなしの同rowだけは失敗bufferを読まず、不存在queryの数値を捕捉する
				if( number == 0U && rows_[index].key.size == 0U) {
					DWORD		required{} ;	// keyなしqueryの終端込み必要長
					const BOOL	query  = SetupGetStringFieldW( &line, 0U, nullptr, 0U,
															  &required) ;	// 同context一回だけ
					const DWORD native = GetLastError() ;					// 元の補助結果を直後に固定する
					// 87単体では採用せず、最終verifiedが同row全field成功も要求する
					if( query == FALSE && native == ERROR_INVALID_PARAMETER && required == 0U) {
						rows_[index].keyObserved = true ;
						continue ;
					}

					// 別結果をkey不存在へ推測変換しない
					disable() ;
					break ;
				}

				std::wstring		 value ;	// 未取得fieldだけの短命な補助値
				MaintenanceFieldRead read{} ;	// 同query／readの完全性
				const NativeError	 error =
					// 私有読取結果
					readMaintenanceField( line, number, value, &read) ;
				// 補助失敗で元成功をwhole failureへ変更しない
				if( error != 0) {
					disable() ;
					break ;
				}

				field( index, number, value, read) ;
			}
		} catch( const std::bad_alloc &) {
			disable() ;
		}

		SetLastError( originalError) ;
	}
	/**
	 * @brief 元raw行を同期期間だけ参照する
	 * @param[in] index 私有原row index
	 * @return 同raw行。callerはactiveとrangeを先に確認する
	 */
	[[nodiscard]] const MaintenanceRawRow &get( std::size_t index) const noexcept
	{
		return rows_[index] ;
	}
	/**
	 * @brief keyと厳密全fieldの取得・比較完了を確認する
	 * @param[in] index 同raw row index
	 * @return 全field bitmapとkeyが揃った一行だけtrue
	 */
	[[nodiscard]] bool verified( std::size_t index) const noexcept
	{
		// 失効／未結合のprivate indexを参照しない
		if( !active_ || index >= rows_.size()) {
			return false ;
		}

		const auto &row		 = rows_[index] ;	// 同原rowの比較状態
		const auto	expected = row.fields == 64U ? (std::numeric_limits<std::uint64_t>::max)()
												 : (std::uint64_t{1U} << row.fields) -
													   1U ;	// 全64bitの場合のshift overflowを避ける
		return row.verified && row.keyObserved && row.observed == expected ;
	}
	/**
	 * @brief 元source観測と原rowを私有indexだけでstageする
	 * @param[in] row 同元raw row
	 * @param[in] file 元observed.filesへのindex
	 */
	void source( std::size_t row, std::size_t file) noexcept
	{
		try {
			// 全値の不足するsourceを後のbindingへ再readしない
			if( !verified( row)) {
				return ;
			}

			sourceRows.emplace_back( row, file) ;
			capacity( 0U) ;
		} catch( const std::bad_alloc &) {
			disable() ;
		}
	}
	/**
	 * @brief 一件の元registry data位置だけを最後までstageする
	 * @param[in] row 同raw row
	 * @param[in] use 元use ordinal
	 * @param[in] queue 元registry queue index
	 */
	void registry( std::size_t row, std::size_t use, std::size_t queue) noexcept
	{
		try {
			// 未読key／auxや全値不一致をcaller成功だけで補完しない
			if( !verified( row)) {
				return ;
			}

			data.push_back( {row, use, queue}) ;
			capacity( 0U) ;
		} catch( const std::bad_alloc &) {
			disable() ;
		}
	}
	/**
	 * @brief 遅延DIRID全値を元制御用途の一件へ結ぶ
	 * @param[in] row 同raw row
	 * @param[in] use 同じ行の元fileUse index
	 */
	void control( std::size_t row, std::size_t use) noexcept
	{
		try {
			// DIRID13の未結合値を別binary名から補完しない
			if( !verified( row) || rows_[row].deferredField == 0U) {
				return ;
			}

			controlUses.emplace_back( row, use) ;
			capacity( 0U) ;
		} catch( const std::bad_alloc &) {
			disable() ;
		}
	}
	/**
	 * @brief 原fieldの一段Strings全展開を取得する
	 * @param[in] index 原row index
	 * @param[in] field 0はkey
	 * @param[out] value 成功時の有限全値
	 * @return 失効・展開不明ならfalse
	 */
	[[nodiscard]] bool value( std::size_t index, std::size_t field, std::wstring &value) noexcept
	{
		try {
			// 撤回済みoffsetを借用しない
			if( !active_ || index >= rows_.size()) {
				return false ;
			}

			const auto &item = rows_[index] ;	// 同元row
			return expand( field == 0U ? item.key : fields_[item.firstField + field - 1U], value) ;
		} catch( const std::bad_alloc &) {
			disable() ;
			return false ;
		}
	}
	/// 一件の元data用途だけを結ぶ私有stage。失効時に全解放する
	std::vector<MaintenanceRegistryDataProof>		 data ;
	/// 元source行indexと元観測用途indexだけを保持する。再API取得に使わない
	std::vector<std::pair<std::size_t, std::size_t>> sourceRows ;
	/// 同原制御行の遅延DIRID fieldと元binary用途の一意index
	std::vector<std::pair<std::size_t, std::size_t>> controlUses ;

private:
	/**
	 * @brief raw全行と同HINFの厳密field数・全値を一回ずつ比較します
	 * @param[in] inf 同snapshotに結ぶ読取専用HINFです。同期中だけ借用します
	 * @return Windows読取失敗は元HRESULT、完了又は私有証明不成立は0です
	 * @note 私有不成立時はactiveを撤回し、呼出側は新例外を許可しません
	 */
	[[nodiscard]] NativeError verifyRequiredRegistryRows( HINF inf)
	{
		// 全raw sectionの行数をWindowsへ照合し、節の一部だけを使いません
		for( std::size_t section = 0U; section < sections_.size(); ++section) {
			const auto name	 = text( sections_[section].name) ;			// 同原名の同期copyです
			const LONG count = SetupGetLineCountW( inf, name.c_str()) ;	// 直後の元結果です
			// 実在raw節をWindowsが読めなければ原失敗を保持します
			if( count < 0L) {
				const DWORD native = GetLastError() ;	// 失敗0を成功へ補完しません
				return native != ERROR_SUCCESS ? nativeErrorFromWin32( native) : E_UNEXPECTED ;
			}

			// merge/count差は私有証明を撤回し、旧readerへ残します
			if( static_cast<std::size_t>( count) != sections_[section].count) {
				disable() ;
				return 0 ;
			}

			// 明示空節にはFirstLineの不存在を成功根拠に使いません
			if( count == 0L) {
				continue ;
			}

			INFCONTEXT line{} ;	// 同sectionだけのWindows rowです
			// 非空raw節の最初の読取失敗を空節へ読み替えません
			if( !SetupFindFirstLineW( inf, name.c_str(), nullptr, &line)) {
				const DWORD native = GetLastError() ;	// 他API前の元値です
				return native != ERROR_SUCCESS ? nativeErrorFromWin32( native) : E_UNEXPECTED ;
			}

			// 全ordinalのkeyと全fieldを一回ずつ原byteへ照合します
			for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
				const DWORD fields = SetupGetFieldCount( &line) ;	// 末尾空fieldも含む元数です
				const auto	index =
					// 同raw一行への一意bindingです
					row( name, ordinal, count, fields) ;
				// 不明rowやfield数差を新形式へ渡しません
				if( !active_ || index == NO_MAINTENANCE_RAW_ROW) {
					return 0 ;
				}

				// keyなし行のfield0不存在は、raw keyなしと同じquery結果へ限定します
				if( rows_[index].key.size == 0U) {
					DWORD		required{} ;	// keyなしqueryの初期容量です
					const BOOL	query  = SetupGetStringFieldW( &line, 0U, nullptr, 0U,
															  &required) ;	// keyなし行のfield照会です
					const DWORD native = GetLastError() ;					// expected87も元bitで捕捉します
					// 成功や異なる失敗をkey不存在へ補完しません
					if( query != FALSE || native != ERROR_INVALID_PARAMETER || required != 0U) {
						return query == FALSE && native != ERROR_SUCCESS
								   ? nativeErrorFromWin32( native)
								   : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					rows_[index].keyObserved = true ;
				}

				// key付き行はfield0も同じ完全readへ含めます
				for( DWORD fieldNumber = rows_[index].key.size == 0U ? 1U : 0U;
					fieldNumber <= fields; ++fieldNumber) {
					std::wstring		 value ;	// この一fieldだけの元Windows値です
					MaintenanceFieldRead read{} ;	// 同query/readの終端と必要長です
					const auto			 error = readMaintenanceField( line, fieldNumber, value,
																	  &read) ;	// 元field読取の結果です
					// 実読取失敗は元HRESULTのまま返します
					if( error != 0) {
						return error ;
					}

					field( index, fieldNumber, value, read) ;
					// allocation等の私有撤回後に古いrowを参照しません
					if( !active_) {
						return 0 ;
					}
				}

				// 原展開/必要長/全fieldの不一致は新分類を成立させません
				if( !verified( index)) {
					disable() ;
					return 0 ;
				}

				// 最終行以外には同sectionの次rowを要求します
				if( ordinal + 1L < count && !SetupFindNextLine( &line, &line)) {
					const DWORD native = GetLastError() ;	// 終端の推測で行不足を隠しません
					return native != ERROR_SUCCESS ? nativeErrorFromWin32( native) : E_UNEXPECTED ;
				}
			}
		}

		return 0 ;
	}
	/**
	 * @brief 全Windows値へ一致済みの一行だけを短命な比較値へ展開します
	 * @param[in] index 同raw rowの有効indexです
	 * @param[out] key 成功時の元key、keyなしでは空です
	 * @param[out] values 成功時の全fieldです。失敗時に使用しません
	 * @return 全fieldを同原byteへ結べる場合だけtrueです
	 * @note 新しいWindows読取や権限を発行せず、展開後も既field上限を維持します
	 */
	[[nodiscard]] bool requiredRegistryValues( std::size_t index, std::wstring &key,
											  std::vector<std::wstring> &values)
	{
		key.clear() ;
		values.clear() ;
		// 未検証rowを先頭値から補完しません
		if( !verified( index) || !value( index, 0U, key)) {
			return false ;
		}

		const auto count = rows_[index].fields ;	// 同元rowの厳密field数です
		// この一行の有限全値だけを原順で取得します
		for( std::size_t field = 1U; field <= count; ++field) {
			std::wstring textValue ;	// 次の一fieldだけの所有値です
			// 未解決tokenや私有撤回で部分値を使用しません
			if( !value( index, field, textValue)) {
				return false ;
			}

			values.push_back( std::move( textValue)) ;
		}

		return true ;
	}
	/**
	 * @brief 限定registry path segment又はnamed valueの文字集合を検査します
	 * @param[in] value 同原fieldの全値です。空/default/path用途は許可しません
	 * @return boundedなASCII英数/underscore/hyphen/periodだけならtrueです
	 * @note 名前からdriver動作の無害性を認定せず、特定メーカー値を使用しません
	 */
	[[nodiscard]] static bool requiredRegistryWord( std::wstring_view value) noexcept
	{
		return !value.empty() && value != L"." && value != L".." &&
			   value.size() < MAXIMUM_INF_FIELD_CHARACTERS &&
			   std::ranges::all_of(
				   value,
				   []( wchar_t character) {
					   return (character >= L'a' && character <= L'z') ||
							  (character >= L'A' && character <= L'Z') ||
							  (character >= L'0' && character <= L'9') || character == L'_' ||
							  character == L'-' || character == L'.' ;
				   }) ;
	}
	/**
	 * @brief HKRのParameters直下から始まる非空相対子pathだけを検査します
	 * @param[in] value 同原subkeyの全値です
	 * @return 全segmentが限定文字集合で空/相対逸脱がなければtrueです
	 * @note 他rootや全体registry、実書込み、device適用性を認可しません
	 */
	[[nodiscard]] static bool requiredRegistrySubkey( std::wstring_view value) noexcept
	{
		constexpr std::wstring_view PREFIX = L"Parameters\\" ;	// 非空子を要求する相対rootです
		// rootだけ/絶対path/異なるrootを許可しません
		if( value.size() <= PREFIX.size() ||
		   !stringsEqual( value.substr( 0U, PREFIX.size()), PREFIX)) {
			return false ;
		}

		value.remove_prefix( PREFIX.size()) ;
		// 全segmentを有限入力の末尾まで検査し、空やdot逸脱を隠しません
		for( ;;) {
			const auto separator = value.find( L'\\') ;	// 次の元segment境界です
			// 一segmentの禁止文字で全形式を拒否します
			if( !requiredRegistryWord( value.substr( 0U, separator))) {
				return false ;
			}

			// 最後の非空segmentまで成立した場合だけ完了します
			if( separator == value.npos) {
				return true ;
			}

			value.remove_prefix( separator + 1U) ;
		}
	}
	/**
	 * @brief 同Models基名又は既知NT装飾だけを実install節へ結びます
	 * @param[in] name service suffixを除いた元section名です
	 * @param[in] base 同Modelsの元DDInstall基名です
	 * @return 一意な基名又はNT/既知archと非空数値OS装飾ならtrueです
	 * @note 未知suffixと空OS componentを救済せず、現在OSの適用性は認定しません
	 */
	[[nodiscard]] static bool requiredRegistryInstallName( std::wstring_view name,
														  std::wstring_view base) noexcept
	{
		// 明示基名の実節もpotentialとして扱います
		if( stringsEqual( name, base)) {
			return true ;
		}

		// 単なるprefix一致をModels所属とみなしません
		if( name.size() <= base.size() + 1U || name[base.size()] != L'.' ||
		   !stringsEqual( name.substr( 0U, base.size()), base)) {
			return false ;
		}

		name.remove_prefix( base.size() + 1U) ;
		const auto			 separator = name.find( L'.') ;	// NT architecture名の元境界です
		constexpr std::array ARCHITECTURES{
			std::wstring_view{L"NT"},
			std::wstring_view{L"NTamd64"},
			std::wstring_view{L"NTx86"},
			std::wstring_view{L"NTarm"},
			std::wstring_view{L"NTarm64"},
			std::wstring_view{L"NTia64"}} ;	// 非選択の既知名も内容から除外しません
		// 未知architectureを一般NTへ読み替えません
		if( !isAllowedValue( name.substr( 0U, separator), ARCHITECTURES)) {
			return false ;
		}

		// 共通又はarchitectureだけの装飾はここで確定します
		if( separator == name.npos) {
			return true ;
		}

		name.remove_prefix( separator + 1U) ;
		std::size_t components{} ;	// 過大なOS装飾を無制限に解釈しません
		// 数値OS componentを元末尾まで検査します
		for( ;;) {
			const auto end		 = name.find( L'.') ;		// 一数値fieldの元境界です
			const auto component = name.substr( 0U, end) ;	// 非空数値だけの短命viewです
			// 未知/空/過大の装飾はこの新形式では不成立です
			if( ++components > 5U || component.empty() ||
			   !std::ranges::all_of( component, []( wchar_t character) {
				   return character >= L'0' && character <= L'9' ;
			   })) {
				return false ;
			}

			// 最後の完全数値まで検査した場合だけ所属を認めます
			if( end == name.npos) {
				return true ;
			}

			name.remove_prefix( end + 1U) ;
		}
	}
	/**
	 * @brief 同HANDLEの通常種別・最終pathをtrusted上位と照合する
	 * @param[in] handle private所有HANDLE
	 * @param[in] path 既存workspaceの元path
	 * @param[in] directory trueはdirectory
	 * @param[out] info 同HANDLEの元identity
	 * @return reparseなし・通常種別・全path一致ならtrue
	 */
	[[nodiscard]] static bool ordinary( HANDLE handle, const std::wstring &path, bool directory,
									   BY_HANDLE_FILE_INFORMATION &info) noexcept
	{
		std::array<wchar_t, MAX_PATH + 8U> final{} ;	// private最終path観測の有限buffer
		const DWORD						   size =
			GetFinalPathNameByHandleW( handle, final.data(), static_cast<DWORD>( final.size()),
									  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 最終解決先
		return GetFileInformationByHandle( handle, &info) != FALSE &&
			   (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U &&
			   ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) == directory &&
			   size > 4U && size < final.size() &&
			   std::wstring_view( final.data(), 4U) == L"\\\\?\\" &&
			   stringsEqual( std::wstring_view( final.data() + 4U, size - 4U), path) ;
	}
	/**
	 * @brief 原snapshotの一code unitを借用する
	 * @param[in] index 検証済みcode unit位置
	 * @return ASCIIまたはUTF-16LE code unit
	 */
	[[nodiscard]] wchar_t character( std::size_t index) const noexcept
	{
		const auto offset = start_ + index * width_ ;						// 元byte位置
		const auto low	  = static_cast<unsigned char>( bytes_[offset]) ;	// 低位byte
		return static_cast<wchar_t>(
			width_ == 1U
				? low
				: low | (static_cast<unsigned int>( static_cast<unsigned char>( bytes_[offset + 1U]))
						 << 8U)) ;
	}
	/**
	 * @brief 一つの有限raw範囲だけを比較用文字列へ写す
	 * @param[in] span 原byte上の範囲
	 * @return 全code unitの比較用値。保持しない
	 */
	[[nodiscard]] std::wstring text( MaintenanceRawSpan span) const
	{
		std::wstring value ;	// 一範囲だけの比較値
		value.reserve( span.size) ;
		// 原code unitを順序どおり一回だけ写す
		for( std::size_t index = 0U; index < span.size; ++index) {
			value.push_back( character( span.begin + index)) ;
		}

		return value ;
	}
	/**
	 * @brief 一対の起動引用符を持つ元の単独Driver Store実行名を読みます
	 * @param[in] raw 三重引用符と周辺空白を含む署名INFの単一元フィールドです
	 * @return 正規形の実行名を元文字列から借用します。照合不能の場合は空です
	 * @note 実配置とコピー、サービス作用は後段が元パッケージへ結びます
	 */
	[[nodiscard]] static std::wstring_view quotedStoreServiceLeaf( std::wstring_view raw) noexcept
	{
		const auto first = raw.find_first_not_of( L" \t") ;	// 元フィールドの構文先頭です
		// 空フィールドに実行名を補いません
		if( first == raw.npos) {
			return {} ;
		}

		raw = raw.substr( first, raw.find_last_not_of( L" \t") - first + 1U) ;
		constexpr std::wstring_view PREFIX = L"\"\"\"%13%\\" ;	// エスケープした開始と元DIRIDです
		constexpr std::wstring_view SUFFIX = L"\"\"\"" ;		// エスケープした終端です
		// 未確定のDIRIDや閉じ引用符から定義を補いません
		if( !raw.starts_with( PREFIX) || !raw.ends_with( SUFFIX) ||
		   raw.size() <= PREFIX.size() + SUFFIX.size()) {
			return {} ;
		}

		// 引用符と固定パスを除いた、照合対象となる実行ファイルの単独名
		const auto leaf = raw.substr( PREFIX.size(), raw.size() - PREFIX.size() - SUFFIX.size()) ;
		// 元の単独EXE名を取り出し、パスや引数に展開できる形式を除きます
		if( leaf.size() <= 4U || !stringsEqual( leaf.substr( leaf.size() - 4U), L".exe") ||
		   !inactiveIdentifier( leaf) || !isSafeOfficialArchiveMember( leaf, L'\\')) {
			return {} ;
		}

		return leaf ;
	}
	/**
	 * @brief 一fieldのouter quoteとunquoted周辺spaceだけを除く
	 * @param[in,out] span 元field範囲。成功時だけ有効なliteral範囲
	 * @param[in] stringsValue 文字列定義値に限り対応しない単独percentを文字として扱います
	 * @return quote連結／continuation／不均衡percentなしならtrue
	 */
	[[nodiscard]] bool literal( MaintenanceRawSpan &span, bool stringsValue = false) const noexcept
	{
		// unquoted両端space／tabだけを取り除く
		while( span.size != 0U &&
			  (character( span.begin) == L' ' || character( span.begin) == L'\t')) {
			++span.begin ;
			--span.size ;
		}

		// 末尾のsyntax外space／tabだけを取り除く
		while( span.size != 0U && (character( span.begin + span.size - 1U) == L' ' ||
								  character( span.begin + span.size - 1U) == L'\t')) {
			--span.size ;
		}

		// 一組のouter quoteだけを受理し、本文内のquoteを後で拒否する
		if( span.size >= 2U && character( span.begin) == L'"' &&
		   character( span.begin + span.size - 1U) == L'"') {
			++span.begin ;
			span.size -= 2U ;
		}

		bool percent{} ;	// 一段tokenの対応するpercent
		// 不明syntaxを飛ばしてordinalを作らず、同一物理行の全literalを検査する
		for( std::size_t index = 0U; index < span.size; ++index) {
			const auto value = character( span.begin + index) ;	// 原code unit
			// quote連結／二重quoteは最小形式外として保留する
			if( value == L'"') {
				return false ;
			}

			// token delimiterの全対応を確認する
			if( value == L'%') {
				percent = !percent ;
			}
		}

		return (!percent || stringsValue) && span.size < MAXIMUM_INF_FIELD_CHARACTERS ;
	}
	/**
	 * @brief private byteとrecordの総保持byte数を返す
	 * @return capacityで確保された全private byte。元core値は複写しない
	 */
	[[nodiscard]] std::size_t storage() const noexcept
	{
		return MAINTENANCE_PROOF_OVERHEAD_BYTES + sizeof( *this) + bytes_.capacity() +
			   hash_.capacity() * sizeof( wchar_t) +
			   sections_.capacity() * sizeof( MaintenanceRawSection) +
			   rows_.capacity() * sizeof( MaintenanceRawRow) +
			   fields_.capacity() * sizeof( MaintenanceRawSpan) +
			   data.capacity() * sizeof( MaintenanceRegistryDataProof) +
			   (sourceRows.capacity() + controlUses.capacity()) *
				   sizeof( std::pair<std::size_t, std::size_t>) ;
	}
	/**
	 * @brief 全private record／binding indexの共同項目数を返す
	 * @return 原offsetを含む全private record数
	 */
	[[nodiscard]] std::size_t items() const noexcept
	{
		return sections_.size() + rows_.size() + fields_.size() + data.size() + sourceRows.size() +
			   controlUses.size() ;
	}
	/**
	 * @brief 原encodingと有限物理行・節・全field envelopeを一回だけ走査する
	 * @param[in] allowFullLineCommentBytes trueは1-byte物理行の最初の非space/tabがsemicolonの時だけhigh-bit comment byteを不透明に許します。control/実syntax/UTF-16LEは変更しません
	 * @param[in] inactiveCoInstallerProof 署名済みNetに限る容量と文字列定義の検査を行う場合trueです
	 * @param[in] allowRegistryContinuation 署名済みNetでAddRegのコンマ後だけを論理行として照合する場合trueです
	 * @param[in] allowQuotedStoreService 元CABの不在媒体証明で単一ServiceBinaryの引用を読取る場合trueです
	 * @param[in] classRegistrationProof trueは独自クラス証明側が高位バイトを文字列定義の値に限定します
	 * @return 最小形式内かつ全共同上限内ならtrue
	 */
	[[nodiscard]] bool scan( bool allowFullLineCommentBytes, bool inactiveCoInstallerProof = false,
							bool allowRegistryContinuation = false,
							bool allowQuotedStoreService   = false,
							bool classRegistrationProof	   = false)
	{
		width_ = bytes_.size() >= 2U && static_cast<unsigned char>( bytes_[0]) == 0xffU &&
						 static_cast<unsigned char>( bytes_[1]) == 0xfeU
					 ? 2U
					 : 1U ;
		start_ = width_ == 2U ? 2U : 0U ;
		// UTF-16LEの半code unitを推測decodeしない
		if( (bytes_.size() - start_) % width_ != 0U) {
			return false ;
		}

		const auto length = (bytes_.size() - start_) / width_ ;	// 全raw code unit数
		bool	   surrogate{} ;								// 直前high surrogateへの対応要求
		bool	   leadingSpace = true ;						// 物理行の先頭space/tab以外をまだ読んでいない場合trueです
		bool	   fullLineComment{} ;							// 最初の非space/tabがASCII semicolonだった場合だけtrueです
		// 原全byteのencoding／controlを検査し、NULや不正surrogateを飛ばさない
		for( std::size_t index = 0U; index < length; ++index) {
			const auto value = character( index) ;	// 同snapshotの一code unit
			// CR/LFごとに物理行の先頭判定を戻し、前行のコメント許可を引き継ぎません
			if( value == L'\r' || value == L'\n') {
				leadingSpace	= true ;
				fullLineComment = false ;
			}
			// 最初の非space/tabだけを分類し、inlineや引用内のsemicolonへ許可を広げません
			else if( leadingSpace && value != L' ' && value != L'\t') {
				fullLineComment = value == L';' ;
				leadingSpace	= false ;
			}

			// 禁止controlはコメントでも拒否し、opt-inの1-byte単独コメントだけでhigh-bitを許します
			if( (value < 0x20 && value != L'\t' && value != L'\r' && value != L'\n') ||
			   value == 0x7f ||
			   (width_ == 1U && value > 0x7e && !classRegistrationProof &&
				!(allowFullLineCommentBytes && fullLineComment))) {
				return false ;
			}

			// high surrogateの直後にlowを要求する
			if( surrogate && (value < 0xdc00 || value > 0xdfff)) {
				return false ;
			}

			// 単独low surrogateを正常なcode unit列へしない
			if( !surrogate && value >= 0xdc00 && value <= 0xdfff) {
				return false ;
			}

			surrogate = value >= 0xd800 && value <= 0xdbff ;
		}

		// 未完high surrogateの末尾を切り捨てない
		if( surrogate) {
			return false ;
		}

		std::size_t next{} ;							// 原physical line開始位置
		std::size_t lines{} ;							// 全seed共同raw counter
		std::size_t envelopes{} ;						// 同名節も元envelopeとして数える
		std::size_t section = NO_MAINTENANCE_RAW_ROW ;	// 現在のmerge先
		const auto	maximumBytes =
			 inactiveCoInstallerProof
				 ? MAXIMUM_INACTIVE_CO_INSTALLER_BYTES
				 : MAXIMUM_MAINTENANCE_PROOF_BYTES ;	// 読取用途ごとの保持予算です
		const auto maximumItems =
			inactiveCoInstallerProof
				? MAXIMUM_INACTIVE_CO_INSTALLER_ITEMS
				: MAXIMUM_INSTALL_INVENTORY_ITEMS ;	// offsetを含む原項目予算です
		bool stringsValue{} ;						// 公式Netの原文字列定義値だけで単独percentを保持します
		// 原lineを一回ずつ走査し、未知syntaxではINF全private proofを閉じる
		while( next < length) {
			// 有限raw physical line上限をseedでresetしない
			if( ++lines > 16384U) {
				return false ;
			}

			const auto beginning = next ;	// 元lineの先頭
			// CR／LFまでの単一物理行だけを扱う
			while( next < length && character( next) != L'\r' && character( next) != L'\n') {
				++next ;
			}

			const auto physicalEnd = next ;			// 改行前の物理行末です
			auto	   ending	   = physicalEnd ;	// comment除去前の行末
			// CRLFは一physical lineとして数える
			if( next < length && character( next++) == L'\r' && next < length &&
			   character( next) == L'\n') {
				++next ;
			}

			bool quote{} ;	// quote内semicolonをcommentにしない
			// comment境界を原line内だけで確定する
			for( auto index = beginning; index < ending; ++index) {
				// quote境界を同physical lineに拘束する
				if( character( index) == L'"') {
					quote = !quote ;
				}

				// 引用外semicolonだけをcommentへ分離する
				if( !quote && character( index) == L';') {
					ending = index ;
					break ;
				}
			}

			MaintenanceRawSpan span{beginning, ending - beginning} ;	// 元line内のsyntax範囲
			// lineの外側spaceだけを除去する
			while( span.size != 0U &&
				  (character( span.begin) == L' ' || character( span.begin) == L'\t')) {
				++span.begin ;
				--span.size ;
			}

			// line末尾のsyntax外spaceを除去する
			while( span.size != 0U && (character( span.begin + span.size - 1U) == L' ' ||
									  character( span.begin + span.size - 1U) == L'\t')) {
				--span.size ;
			}

			// 空line／commentだけを除き、非空entry ordinalを保持する
			if( span.size == 0U) {
				continue ;
			}

			const auto last = span.begin + span.size - 1U ;	// 行末の有効な一文字です
			// 引用を次の物理行へ持ち越さず、元行の解釈が曖昧なら拒否します
			if( quote) {
				return false ;
			}

			// 名前を途中で合成できる継続は認めず、AddRegの項目境界だけを再読します
			if( character( last) == L'\\') {
				const auto raw	  = text( {span.begin, span.size - 1U}) ;	// 継続記号を除く元値です
				const auto equals = raw.find( L'=') ;						// 正式な指示キーの終端です
				const auto keyEnd =
					// 左辺の末尾です
					raw.find_last_not_of( L" \t", equals == 0U ? 0U : equals - 1U) ;
				const auto comma = raw.find_last_not_of( L" \t") ;	// 最後の有効な区切りです
				// 空の次行、コメント、他の指示および名前分割を一行へ含めません
				if( !allowRegistryContinuation || ending != physicalEnd || next >= length ||
				   (character( next) != L' ' && character( next) != L'\t') || equals == raw.npos ||
				   keyEnd == raw.npos || comma == raw.npos ||
				   !stringsEqual( std::wstring_view{raw}.substr( 0U, keyEnd + 1U), L"AddReg") ||
				   raw[comma] != L',') {
					return false ;
				}

				// 元バイトを変更せず、解析用コピーのコンマ以降の継続と改行だけを空白にします
				for( auto index = last; index < next; ++index) {
					const auto offset = start_ + index * width_ ;	// 同じcode unitのコピー位置です
					bytes_[offset]	  = ' ' ;
					// UTF-16LEの空白へ置き換えます
					if( width_ == 2U) {
						bytes_[offset + 1U] = '\0' ;
					}
				}

				next = beginning ;
				continue ;
			}

			// 元section envelopeはtoken-freeな一組bracketだけに限る
			if( character( span.begin) == L'[') {
				// 過大／未閉headerをprivate保留する
				if( ++envelopes > 1024U || span.size < 3U ||
				   character( span.begin + span.size - 1U) != L']') {
					return false ;
				}

				++span.begin ;
				span.size -= 2U ;
				const auto name = text( span) ;	// section名だけの比較値
				// header内tokenや構文曖昧を許さない
				if( !validInstallInventorySectionName( name) ||
				   name.find_first_of( L"%\"=,") != name.npos) {
					return false ;
				}

				// 空の不正locale envelopeも候補から飛ばさず、INF全private proofを保留する
				if( isStrings( name) && !validStringsName( name)) {
					return false ;
				}

				section = 0U ;
				// case違い同名sectionを原byte順にmergeする
				while( section < sections_.size() &&
					  !stringsEqual( text( sections_[section].name), name)) {
					++section ;
				}

				// 新collector認定用には全同名envelopeの存在を保持し、旧merge条件は変えません
				duplicateSections_ = duplicateSections_ || section < sections_.size() ;
				// Strings familyの重複headerはlocale推測で救済しない
				if( section < sections_.size() && isStrings( name)) {
					return false ;
				}

				// 最初の原envelopeだけを名前offsetとして保持する
				if( section == sections_.size()) {
					sections_.push_back( {span}) ;
				}

				stringsValue = inactiveCoInstallerProof && isStrings( name) ;
				continue ;
			}

			// section外entryを飛ばして次sectionのordinalを作らない
			if( section == NO_MAINTENANCE_RAW_ROW || rows_.size() >= maximumItems) {
				return false ;
			}

			MaintenanceRawRow row{
				section, sections_[section].count++, {}, fields_.size()} ;	// 一entryのoffsetだけ
			std::size_t first = span.begin ;								// keyまたは最初のfield開始
			const auto	end	  = span.begin + span.size ;					// 同physical line終端
			quote			  = false ;
			bool hasKey{} ;	// 最初の引用外等号だけがkey境界
			// keyと全comma fieldをquoteの内外で区別する
			for( auto index = span.begin; index <= end; ++index) {
				const auto value =
					// 末尾empty fieldも保持する
					index == end ? L',' : character( index) ;
				// quote内commaを別fieldへsplitしない
				if( value == L'"') {
					quote = !quote ;
				}

				// 最初の引用外等号はkey付き行として独立保持する
				if( !quote && value == L'=' && first == span.begin && !hasKey && row.fields == 0U) {
					row.key = {first, index - first} ;
					// 不正key形式はkeyなしへ縮めない
					if( !literal( row.key) || row.key.size == 0U) {
						return false ;
					}

					hasKey = true ;
					first  = index + 1U ;
				}
				// 引用外commaだけを全field境界にし、末尾emptyも保持する
				else if( !quote && value == L',') {
					MaintenanceRawSpan field{first, index - first} ;	// emptyを含む全field
					const auto		   original = field ;				// 必要時だけ照合する元の引用符付き範囲です
					// fieldの共通上限を維持します
					if( ++row.fields > 64U) {
						return false ;
					}

					// 元CABの不在証明でだけ、末尾の単一ServiceBinaryを限定形として再読します
					if( !literal( field, stringsValue)) {
						// 追加フィールドや文字列定義の引用構造は不明なまま拒否します
						if( !allowQuotedStoreService || stringsValue || !hasKey || index != end ||
						   row.fields != 1U || !stringsEqual( text( row.key), L"ServiceBinary") ||
						   quotedStoreServiceLeaf( text( original)).empty()) {
							return false ;
						}

						field = original ;
					}

					fields_.push_back( field) ;
					first = index + 1U ;
				}
			}

			rows_.push_back( row) ;
			// offsetもprivate recordとしてbyte／共同item上限に含める
			if( storage() > maximumBytes || items() > maximumItems) {
				return false ;
			}
		}

		std::ranges::sort( rows_, {},
						  []( const auto &row) { return std::pair{row.section, row.ordinal} ; }) ;
		// 全Strings候補のkey構造と13shadowを確認し、不正localeを除外しない
		for( const auto &row : rows_) {
			const auto name = text( sections_[row.section].name) ;	// 原候補section名
			// Strings以外の通常sectionへlocale規則を追加しない
			if( !isStrings( name)) {
				continue ;
			}

			const auto key = text( row.key) ;	// 原Strings識別子
			// 一valueでない定義とbuilt-in shadowはprivate保留する
			if( !validStringsName( name) || row.fields != 1U || key == L"13" ||
			   !(inactiveCoInstallerProof ? inactiveIdentifier( key)
										  : identifier( key, registryOnlyProof_))) {
				return false ;
			}
		}

		return storage() <= maximumBytes && items() <= maximumItems ;
	}
	/**
	 * @brief 公式Netの節・媒体・文字列で構造記号を除いた名前だけを検査します
	 * @param[in] value 元バイト上の完全名です
	 * @return ASCII英数字・underscore・hyphen・dotの非空名の場合trueです
	 */
	[[nodiscard]] static bool inactiveIdentifier( std::wstring_view value) noexcept
	{
		return !value.empty() && std::ranges::all_of( value, []( const wchar_t character) {
			return (character >= L'a' && character <= L'z') ||
				   (character >= L'A' && character <= L'Z') ||
				   (character >= L'0' && character <= L'9') || character == L'_' ||
				   character == L'-' || character == L'.' ;
		}) ;
	}
	/**
	 * @brief ASCII token識別子の最小形式を検査する
	 * @param[in] value 全token名
	 * @param[in] dotted 必須System補助INFの文字列名でドット区切りを許す場合だけtrueです
	 * @return 空でないASCII英数字とアンダースコア、又は許可されたドット区切りの名前ならtrueです
	 */
	[[nodiscard]] static bool identifier( std::wstring_view value, bool dotted = false) noexcept
	{
		return !value.empty() &&
			   (!dotted || (value.front() != L'.' && value.back() != L'.' &&
							value.find( L"..") == value.npos)) &&
			   std::ranges::all_of( value, [dotted]( wchar_t character) {
				   return (character >= L'a' && character <= L'z') ||
						  (character >= L'A' && character <= L'Z') ||
						  (character >= L'0' && character <= L'9') || character == L'_' ||
						  (dotted && character == L'.') ;
			   }) ;
	}
	/**
	 * @brief defaultとdecorated Strings familyを区別する
	 * @param[in] name 元section名
	 * @return Strings familyならtrue
	 */
	[[nodiscard]] static bool isStrings( std::wstring_view name) noexcept
	{
		return stringsEqual( name, L"Strings") ||
			   (name.size() >= 8U && stringsEqual( name.substr( 0U, 8U), L"Strings.")) ;
	}
	/**
	 * @brief defaultまたは四桁hex LanguageIDだけを採用する
	 * @param[in] name 原Strings section名
	 * @return 最小locale形式ならtrue
	 */
	[[nodiscard]] static bool validStringsName( std::wstring_view name) noexcept
	{
		return stringsEqual( name, L"Strings") ||
			   (name.size() == 12U && std::ranges::all_of( name.substr( 8U), []( wchar_t character) {
					return (character >= L'0' && character <= L'9') ||
						   (character >= L'a' && character <= L'f') ||
						   (character >= L'A' && character <= L'F') ;
				})) ;
	}
	/**
	 * @brief 全default／decorated定義が一意同値の一段tokenだけを展開する
	 * @param[in] span 原field全範囲
	 * @param[out] output 独立展開した全code unit。終端込み4096以内
	 * @return 全locale・全literalを確定できればtrue
	 */
	[[nodiscard]] bool expand( MaintenanceRawSpan span, std::wstring &output) const
	{
		const auto raw = text( span) ;	// 一fieldだけの原全値
		output.clear() ;
		std::size_t next{} ;	// 原全literalを順序どおり消費する
		bool		dirid{} ;	// 先頭13を一度だけ許す
		// tokenとliteralを一段だけ処理し、再帰や環境展開を行わない
		while( next < raw.size()) {
			// token外literalは一文字ずつ全体へ残す
			if( raw[next] != L'%') {
				output.push_back( raw[next++]) ;
			} else {
				const auto end = raw.find( L'%', next + 1U) ;	// 同tokenの閉delimiter
				// 不均衡percentをescapeと推測しない
				if( end == raw.npos) {
					return false ;
				}

				const auto key =
					// token全名
					std::wstring_view( raw).substr( next + 1U, end - next - 1U) ;
				// 唯一のbuilt-inはdata先頭の一回だけ保持する
				if( key == L"13") {
					// 中間・反復DIRID13を部分pathへ補正しない
					if( next != 0U || dirid) {
						return false ;
					}

					dirid = true ;
					output += L"%13%" ;
				} else {
					// 未対応token形式をStrings名へ補完しない
					if( !identifier( key, registryOnlyProof_)) {
						return false ;
					}

					std::wstring literal ;			// 最初の全定義だけを比較中に所有する
					bool		 haveDefault{} ;	// default欠損localeを推測しない
					std::size_t	 definitions{} ;	// 全candidate Strings section数
					// defaultと全decorated候補を省略せず、各keyの一意な全literalを比較する
					for( std::size_t section = 0U; section < sections_.size(); ++section) {
						const auto name = text( sections_[section].name) ;	// 一候補名
						// 通常sectionをStrings定義へ使わない
						if( !isStrings( name)) {
							continue ;
						}

						std::size_t	 matches{} ;	// このcandidate内の同key全定義数
						std::wstring value ;		// この候補のtoken-free全literal
						const auto	 begin = std::ranges::lower_bound(
							  rows_, section, {}, &MaintenanceRawRow::section) ;	// 元candidate範囲
						// 同candidateだけの定義を一度ずつ確認し、重複を先頭へ絞らない
						for( auto row = begin; row != rows_.end() && row->section == section;
							++row) {
							// 原key全名が一致する定義だけを数える
							if( stringsEqual( text( row->key), key)) {
								++matches ;
								value = text( fields_[row->firstField]) ;
							}
						}

						// 全候補の欠損・nested token・過長・不一致を除外して成功させない
						if( matches != 1U || value.find( L'%') != value.npos ||
						   value.size() >= 4096U || (definitions != 0U && literal != value)) {
							return false ;
						}

						literal = std::move( value) ;
						++definitions ;
						haveDefault = haveDefault || stringsEqual( name, L"Strings") ;
					}

					// 未定義やdefault欠損をOS localeの推測で補わない
					if( definitions == 0U || !haveDefault ||
					   literal.size() > 4095U - output.size()) {
						return false ;
					}

					output += literal ;
				}

				next = end + 1U ;
			}

			// 原全展開の上限には終端一文字を含める
			if( output.size() >= 4096U) {
				return false ;
			}
		}

		return true ;
	}
	/// private directoryの所有HANDLE。最多64、共有anchorは含まない
	std::array<HANDLE, 64U>			   handles_{} ;
	/// 取得済みprivate component数
	std::size_t						   handleCount_{} ;
	/// 元通常fileの読取専用所有HANDLE
	HANDLE							   file_{INVALID_HANDLE_VALUE} ;
	/// 一回の原snapshot。再decode本文を保持しない
	std::string						   bytes_ ;
	/// snapshot取得時の既存SHA-256
	std::wstring					   hash_ ;
	/// 原section envelopeのmerge index
	std::vector<MaintenanceRawSection> sections_ ;
	/// 原rowordinalと全field offsetの結合
	std::vector<MaintenanceRawRow>	   rows_ ;
	/// 元byteに借用する全field offset
	std::vector<MaintenanceRawSpan>	   fields_ ;
	/// BOMを除く原code unit開始byte
	std::size_t						   start_{} ;
	/// ASCIIは1、BOM UTF-16LEは2
	std::size_t						   width_{1U} ;
	/// 新collector形式だけが参照する同名section envelopeの存在です
	bool							   duplicateSections_{} ;
	/// 必須System importの時だけドット区切りの文字列名を照合します
	bool							   registryOnlyProof_{} ;
	/// 全seed共同の追加query／read消費
	std::size_t						   extraCalls_{} ;
	/// 位置認定へ使用できるprivate proof状態
	bool							   active_{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 保守読取で明示空・不存在とその他のAPI失敗を分離する
 * @param[in] inf 正常に開いた単独INF handle
 * @param[in] name 元明示節名
 * @param[out] count 成功時は行数、不存在なら-1
 * @return 観測成功0、不存在以外の元HRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError maintenanceLineCount( HINF inf, const std::wstring &name, LONG &count)
{
	SetLastError( ERROR_SUCCESS) ;
	count = SetupGetLineCountW( inf, name.c_str()) ;
	// 明示空と実在節は確定した行数で返す
	if( count >= 0) {
		return 0 ;
	}

	const DWORD error = GetLastError() ;	// 不在とAPI失敗を直後に固定する
	// 正常handleでの文書化された不在だけを-1として保持する
	if( count == -1L && (error == ERROR_SECTION_NOT_FOUND || error == ERROR_SUCCESS)) {
		return 0 ;
	}

	return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 確定行数内の一行をindexで取得し、途中終了を正常終端へ変換しない
 * @param[in] inf 単独INF handle
 * @param[in] name 実在を確認した元節名
 * @param[in] ordinal 非負の行index
 * @param[out] line 成功時だけの借用行context
 * @return 取得成功0、元API診断。診断欠落も不正として返す
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError maintenanceLineAt( HINF inf, const std::wstring &name, LONG ordinal,
											INFCONTEXT &line)
{
	SetLastError( ERROR_SUCCESS) ;
	// 確定行数の全行が取得できなければ部分参照を返さない
	if( SetupGetLineByIndexW( inf, name.c_str(), static_cast<DWORD>( ordinal), &line) == FALSE) {
		const DWORD error = GetLastError() ;	// 元読取診断
		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsが選ぶModelsの全一意DDInstall名を一回の有限走査へ集める
 * @param[in] inf 同期借用するINF handle
 * @param[in,out] budget 全選択共通のModels読取予算
 * @param[out] names 成功時の元導入名群。署名・device適合ではない
 * @param[in] amd64Only trueは原Manufacturerが指定した明示NTamd64 Modelsだけを使用します
 * @param[in] requested 元配布の明示観測点。nullは現在OS
 * @return 一つ以上の指定OSまたは現在OSの選択名を取得した場合0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectMaintenanceInstallNames( HINF						 inf,
														 MaintenanceStructureBudget &budget,
														 std::vector<std::wstring>	&names,
														 bool				  amd64Only = false,
														 PSP_ALTPLATFORM_INFO requested = nullptr)
{
	LONG		manufacturerCount{} ;	// 全メーカーの確定行数
	NativeError countError =
		// 不在区分
		maintenanceLineCount( inf, L"Manufacturer", manufacturerCount) ;
	// Manufacturer不在・空・過大とAPI失敗から任意DDInstallを選ばない
	if( countError != 0 || manufacturerCount <= 0 || manufacturerCount > 4096L) {
		return countError != 0 ? countError : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 全メーカーについて、Windowsが該当OSで選ぶModelsを有限に調べる
	for( LONG row = 0L; row < manufacturerCount; ++row) {
		INFCONTEXT manufacturer{} ;	// 対象OSのModelsをWindowsへ選ばせる一行
		countError = maintenanceLineAt( inf, L"Manufacturer", row, manufacturer) ;
		// 途中の読取不能をメーカー集合の正常終端にしない
		if( countError != 0) {
			return countError ;
		}

		// 対象外メーカーも行予算へ含める
		if( ++budget.lines > MAXIMUM_INSTALL_INVENTORY_LINES) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS> models{} ;	// 選択された節名
		// Windowsが対象外としたメーカーだけを飛ばし、容量・API失敗は保持する
		if( SetupDiGetActualModelsSectionW( &manufacturer, requested, models.data(),
										  static_cast<DWORD>( models.size()), nullptr,
										  nullptr) == FALSE) {
			const DWORD error = GetLastError() ;	// 対象なしと実失敗を区別する
			// 未対応OSのModelsをfallbackで戻さない
			if( error != ERROR_NO_COMPAT_DRIVERS && error != ERROR_SECTION_NOT_FOUND) {
				return nativeErrorFromWin32( error) ;
			}

			continue ;
		}

		const std::wstring modelName( models.data()) ;	// Windowsが選んだ元節名
		// 元device所有者の証明では、Windowsが選択した明示NTamd64装飾を要求します
		if( amd64Only) {
			std::wstring base ;												// 同じ原Manufacturer行のModels基本名です
			const auto	 error = readInfField( manufacturer, 1U, base) ;	// 元行の読取結果です
			// 原基本名の欠落を任意のsection suffixで補いません
			if( error != 0) {
				return error ;
			}

			const auto prefix = base + L".NTamd64" ;	// 完全architecture又はそのOS装飾です
			// 無装飾や他architectureのModelsは登録所有者にしません
			if( modelName.size() < prefix.size() ||
			   !stringsEqual( std::wstring_view( modelName).substr( 0U, prefix.size()), prefix) ||
			   (modelName.size() != prefix.size() && modelName[prefix.size()] != L'.')) {
				// 明示配布対象が別の装飾へ解決した場合は、他のメーカー行の成功で補わない
				if( requested != nullptr) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				continue ;
			}

			const auto fields = SetupGetFieldCount( &manufacturer) ;	// 同一行の元TargetOSVersionです
			bool declared{} ;											// 実際のAMD64選択が原Manufacturer自身に宣言された場合だけ立てます
			// 省略・過大な宣言を実Modelsの所有資格にしません
			if( fields < 2U || fields > 32U) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// Windowsが選択した装飾名を同じ行の完全な元fieldに照合します
			for( DWORD field = 2U; field <= fields; ++field) {
				std::wstring decoration ;	// 元の一つのTargetOSVersionです
				const auto	 fieldError =
					// 原読取結果です
					readInfField( manufacturer, field, decoration) ;
				// 展開不明の宣言を別の選択の証拠へ混ぜません
				if( fieldError != 0) {
					return fieldError ;
				}

				declared = declared || stringsEqual( modelName, base + L"." + decoration) ;
			}

			// 暗黙の同名sectionを原AMD64宣言へ補いません
			if( !declared) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}
		}

		LONG modelCount{} ;	// 選択節の確定行数
		countError = maintenanceLineCount( inf, modelName, modelCount) ;
		// 選択Modelsの不在・空・過大とAPI失敗では部分集合を返さない
		if( countError != 0 || modelCount <= 0 || modelCount > 4096L) {
			return countError != 0 ? countError : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// Windowsが選んだ全Models行を読み、一意の導入名を有限に保持する
		for( LONG modelRow = 0L; modelRow < modelCount; ++modelRow) {
			INFCONTEXT model{} ;	// 選択Models内の現在行
			countError = maintenanceLineAt( inf, modelName, modelRow, model) ;
			// 全Modelsの途中の失敗を先頭選択成功で隠さない
			if( countError != 0) {
				return countError ;
			}

			// Modelsとメーカーの累積行数を全INF予算へ拘束する
			if( ++budget.lines > MAXIMUM_INSTALL_INVENTORY_LINES) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::wstring	  name ;									// 必須の元DDInstall名
			const NativeError error = readInfField( model, 1U, name) ;	// Windows展開結果
			// 不正行と過大fieldを読み飛ばして先頭選択だけを認定しない
			if( error != 0 || SetupGetFieldCount( &model) < 2U ||
			   SetupGetFieldCount( &model) > MAXIMUM_INSTALL_INVENTORY_FIELDS ||
			   !validInstallInventorySectionName( name)) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// 収集元の所有先に使う行は実際の原IDへの結合を確認します
			if( amd64Only) {
				std::wstring hardwareId ;										// 元行の第2fieldにある実IDです
				const auto	 idError = readInfField( model, 2U, hardwareId) ;	// 空IDは受理しません
				// 実deviceを表さない行から登録所有者を生成しません
				if( idError != 0 || hardwareId.size() > MAXIMUM_HARDWARE_ID_CHARACTERS) {
					return idError != 0 ? idError : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}
			}

			// 一意な導入名を共通の節予算内に保ちます
			if( appendUnique( names, std::move( name)) &&
			   names.size() > MAXIMUM_INSTALL_INVENTORY_SECTIONS) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}
		}
	}

	return names.empty() ? nativeErrorFromWin32( ERROR_NOT_FOUND) : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief AddServiceのnamed構造と限定nullを分けて非実行で読む
 * @param[in,out] install この選択の構造と診断
 * @param[in] section 元宣言節
 * @param[in] values 空fieldを含む全展開値。flags過長時だけ第2値は空
 * @param[in] flagsReadError flagsの個別長さ診断。0の場合は展開値を解析する
 * @param[in] expectedServices 選択DDInstallと同じ装飾のServices節
 * @param[in] scopedUsbWireless 公式USB無線の元サービスを追加で棚卸しする場合trueです
 */
//------------------------------------------------------------------------------
void observeMaintenanceService( MaintenanceInfInstallStructure &install, const std::wstring &section,
							   std::span<const std::wstring> values, NativeError flagsReadError,
							   const std::wstring &expectedServices, bool scopedUsbWireless)
{
	MaintenanceInfServiceStructure service ;	// 空名もそのまま保持する独立した観測
	service.section	   = section ;
	service.fieldCount = static_cast<std::uint32_t>( values.size()) ;
	service.parser	   = {MaintenanceInspectionState::PASSED, 0} ;
	// 第1fieldが存在する場合は、空と欠落の差を元field数で保持する
	if( !values.empty()) {
		service.serviceName = values[0] ;
	}

	MaintenanceInfStructureReason reason =
		MaintenanceInfStructureReason::MISSING_SERVICE_FIELD ;	// 数値失敗時だけ意味を持つ理由
	std::uint32_t				 parsedFlags{} ;				// 成功後だけoptional flagsへ格納する
	MaintenanceInspectionFinding finding{MaintenanceInspectionState::FAILED,
										 // 欠落fieldを数値0にしない
										 nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
	// 過長flagsは通常の読取失敗と区別して個別不正結果へ残す
	if( flagsReadError != 0) {
		reason		  = MaintenanceInfStructureReason::FLAGS_TOO_LONG ;
		finding.error = flagsReadError ;
	}
	// Namedの省略flagsは空fieldと非空の必須参照を持つ形だけを既定0として扱う
	else if( !service.serviceName.empty() && values.size() >= 3U && values[1].empty() &&
			!values[2].empty()) {
		finding = {MaintenanceInspectionState::PASSED, 0} ;
	}
	// Fieldが揃った場合だけ、展開後の全文字を数値へ解析する
	else if( values.size() >= 2U) {
		finding = parseMaintenanceFlags( values[1], parsedFlags, reason) ;
	}

	// 有効なflagsだけを保持し、失敗をoptional値の0へ変換しない
	if( finding.state == MaintenanceInspectionState::PASSED) {
		service.flags = parsedFlags ;
	} else {
		service.parser = finding ;
		addMaintenanceIssue( install, section, L"AddService", reason, finding) ;
	}

	// 明示空第3fieldは無参照、欠落第3fieldも正当な2-field nullとして保持する
	if( values.size() >= 3U) {
		service.serviceInstallSection = values[2] ;
	}

	// Event-log参照は第4fieldだけを保持し、後続値を節名へ変換しない
	if( values.size() >= 4U) {
		service.eventLogSection = values[3] ;
	}

	const MaintenanceInspectionFinding unsupported{MaintenanceInspectionState::UNSUPPORTED,
												   // 未評価構成の診断値
												   nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
	// 未展開named identityを実在serviceの構造として認定しない
	if( !service.serviceName.empty() &&
	   (service.serviceName.find( L'%') != std::wstring::npos ||
		service.serviceInstallSection.find( L'%') != std::wstring::npos ||
		service.eventLogSection.find( L'%') != std::wstring::npos)) {
		mergeMaintenanceFinding( service.parser, unsupported) ;
		addMaintenanceIssue( install, section, L"AddService",
							MaintenanceInfStructureReason::NAMED_SERVICE_NOT_ASSESSED, unsupported) ;
	}

	const bool scopedStartService = scopedUsbWireless && !service.serviceName.empty() &&
									values.size() == 3U &&
									stringsEqual( section, expectedServices) &&
									service.flags ==
										// 後段で作用を照合する元補助行です
										static_cast<std::uint32_t>( SPSVCINST_STARTSERVICE) ;
	// 通常のnamedは補助0と関連2、nullは2に限定し、USBの明示起動は同じ選択でのみ棚卸しします
	if( service.flags.has_value() && *service.flags != 2U &&
	   (service.serviceName.empty() || *service.flags != 0U) && !scopedStartService) {
		mergeMaintenanceFinding( service.parser, unsupported) ;
		addMaintenanceIssue( install, section, L"AddService",
							MaintenanceInfStructureReason::FLAGS_NOT_SUPPORTED, unsupported) ;
	}

	// Namedの必須参照欠落をnullの無参照構造へ読み替えない
	if( !service.serviceName.empty() && service.serviceInstallSection.empty()) {
		const MaintenanceInspectionFinding missing{MaintenanceInspectionState::FAILED,
												   // 欠落診断
												   nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
		mergeMaintenanceFinding( service.parser, missing) ;
		addMaintenanceIssue( install, section, L"AddService",
							MaintenanceInfStructureReason::MISSING_SERVICE_FIELD, missing) ;
	}

	// Empty名でも非空の参照節がある構成を無参照nullへ昇格しない
	if( service.serviceName.empty() &&
	   (!service.serviceInstallSection.empty() || !service.eventLogSection.empty())) {
		mergeMaintenanceFinding( service.parser, unsupported) ;
		addMaintenanceIssue( install, section, L"AddService",
							MaintenanceInfStructureReason::NULL_SERVICE_SECTION_REFERENCE,
							unsupported) ;
	}

	// 非対応節と後続event作用fieldは明示診断として保持する
	if( !stringsEqual( section, expectedServices) || values.size() > 4U) {
		mergeMaintenanceFinding( service.parser, unsupported) ;
		addMaintenanceIssue( install, section, L"AddService",
							MaintenanceInfStructureReason::SERVICE_DECLARATION_NOT_SUPPORTED,
							unsupported) ;
	}

	install.services.push_back( std::move( service)) ;
}

// Named service-installの必須項目。位置と起動意味の完全審査は別の境界
constexpr std::array<std::wstring_view, 4U> MAINTENANCE_SERVICE_FIELDS{
	L"ServiceType", L"StartType", L"ErrorControl", L"ServiceBinary"} ;

/** @brief 既存有限queueが読んだservice必須行の構造。本文や数値を所有しない */
struct MaintenanceServiceFieldObservation {
	/// 読取元節の所有copy。named参照との結合だけに使う
	std::wstring				 section ;
	/// 四つの必須directiveの所有copy
	std::wstring				 directive ;
	/// 非空一fieldと限定数値形式の到達状態。byte・署名・実行意味ではない
	MaintenanceInspectionFinding finding ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 読取済みの必須service行を限定構造として確認する
 * @param[in] key 必須四項目の一つ。呼出し中だけ借用する
 * @param[in] values 同じqueueで読んだ全展開値。保存しない
 * @return 構造認識PASSED、値欠落・不正FAILED、tokenと未対応値UNSUPPORTED
 * @note ServiceBinaryの位置・実byteは既存参照readerへ委ね、SCMの完全validatorを作らない
 */
//------------------------------------------------------------------------------
[[nodiscard]] MaintenanceInspectionFinding observeMaintenanceServiceField(
	std::wstring_view key, std::span<const std::wstring> values) noexcept
{
	// 必須一値の欠落と多fieldを先頭値で成功へ補完しない
	if( values.size() != 1U || values.front().empty()) {
		return {MaintenanceInspectionState::FAILED, nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
	}

	// Binaryの非空宣言だけをここで確認し、未知位置や未取得byteは後段へ残す
	if( stringsEqual( key, L"ServiceBinary")) {
		return {MaintenanceInspectionState::PASSED, 0} ;
	}

	std::uint32_t					   value{} ;	// 全field成功まで部分数値を使用しない
	MaintenanceInfStructureReason	   reason{} ;	// 数値readerの内部理由。外向き理由へ流用しない
	const MaintenanceInspectionFinding finding =
		// 既存の厳密uint32境界
		parseMaintenanceFlags( values.front(), value, reason) ;
	// 不正・token・overflowの元状態とHRESULTを保持する
	if( finding.state != MaintenanceInspectionState::PASSED) {
		return finding ;
	}

	const bool known =
		stringsEqual( key, L"ServiceType")
			? value == 1U || value == 2U || value == 0x10U || value == 0x20U || value == 0x110U ||
				  value == 0x120U
			: value <= (stringsEqual( key, L"StartType") ? 4U : 3U) ;	// 一次仕様の数値集合だけ
	return known ? finding
				 : MaintenanceInspectionFinding{MaintenanceInspectionState::UNSUPPORTED,
												nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Namedの必須参照と読取済み四項目を照合し具体的不足を保持する
 * @param[in,out] install 同じ有限queueのservice・参照・用途観測
 * @param[in] fields 読取済み必須行。最大4,096で同期借用する
 * @return 観測成功0、診断または用途の保持上限超過のHRESULT
 * @note 不足用途で全integrityを昇格させず、既知署名FAILEDは後段の既存優先規則で保持する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError assessMaintenanceNamedServices(
	MaintenanceInfInstallStructure					   &install,
	std::span<const MaintenanceServiceFieldObservation> fields)
{
	// 全namedを同じ元参照へ照合し、shared節を追加走査しない
	for( auto &service : install.services) {
		// Nullの初期認定とnamed必須四項目の責務を分ける
		if( service.serviceName.empty()) {
			continue ;
		}

		// 明示event-log参照の不在も、optionalという理由で無参照成功にしない
		if( !service.eventLogSection.empty() &&
		   service.eventLogSection.find( L'%') == std::wstring::npos) {
			const bool present = std::ranges::any_of(
				install.inventory.references, [&service]( const auto &reference) {
					return stringsEqual( reference.section, service.section) &&
						   stringsEqual( reference.directive, L"AddService") &&
						   stringsEqual( reference.target, service.eventLogSection) &&
						   reference.targetPresent ;
				}) ; // 同宣言の非空event-log節だけ
			// 照会済み節欠落の元診断を全integrity未検査と分離する
			if( !present) {
				const MaintenanceInspectionFinding missing{
					MaintenanceInspectionState::FAILED,
					// 元参照節の不在
					nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND)} ;
				mergeMaintenanceFinding( service.parser, missing) ;
				addMaintenanceIssue(
					install, service.section, L"AddService",
					MaintenanceInfStructureReason::SERVICE_DECLARATION_NOT_SUPPORTED, missing) ;
			}
		}

		// 空・未展開参照は先行診断で保持し、tokenを実在節として追加認定しない
		if( !service.serviceInstallSection.empty() &&
		   service.serviceInstallSection.find( L'%') == std::wstring::npos) {
			const bool present = std::ranges::any_of(
				install.inventory.references, [&service]( const auto &reference) {
					return stringsEqual( reference.section, service.section) &&
						   stringsEqual( reference.directive, L"AddService") &&
						   stringsEqual( reference.target, service.serviceInstallSection) &&
						   reference.targetPresent ;
				}) ; // 同じ元宣言と明示節の存在だけ
			// 元queueが確認した不在を空service節として成功へ変換しない
			if( !present) {
				const MaintenanceInspectionFinding missing{
					MaintenanceInspectionState::FAILED,
					// 元節の欠落診断
					nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND)} ;
				mergeMaintenanceFinding( service.parser, missing) ;
				addMaintenanceIssue(
					install, service.section, L"AddService",
					MaintenanceInfStructureReason::SERVICE_DECLARATION_NOT_SUPPORTED, missing) ;
			} else {
				// 必須四項目を同じ節へ結び、別の節の項目で欠落を補完しない
				for( const auto key : MAINTENANCE_SERVICE_FIELDS) {
					const auto matches =
						std::ranges::count_if( fields, [&service, key]( const auto &field) {
							return stringsEqual( field.section, service.serviceInstallSection) &&
								   stringsEqual( field.directive, key) ;
						}) ; // 読取済み集合の件数。優先行は推測しない
					MaintenanceInspectionFinding  finding{MaintenanceInspectionState::PASSED,
														  0} ;	// 個別項目
					MaintenanceInfStructureReason reason = MaintenanceInfStructureReason::
						SERVICE_DECLARATION_NOT_SUPPORTED ;	// 値不足・未対応
					// 項目欠落を既定値で埋めず、必須構造の失敗として残す
					if( matches == 0) {
						reason	= MaintenanceInfStructureReason::MISSING_SERVICE_FIELD ;
						finding = {MaintenanceInspectionState::FAILED,
								   nativeErrorFromWin32( ERROR_INVALID_DATA)} ;
					}
					// 重複行の処理順序を独自に決定しない
					else if( matches != 1) {
						finding = {MaintenanceInspectionState::UNSUPPORTED,
								   nativeErrorFromWin32( ERROR_NOT_SUPPORTED)} ;
					} else {
						finding =
							std::ranges::find_if( fields, [&service, key]( const auto &field) {
								return stringsEqual( field.section, service.serviceInstallSection) &&
									   stringsEqual( field.directive, key) ;
							})->finding ; // 一意の読取済み結果だけを同期借用する
					}

					// 数値・空値の既知失敗を後続未対応で上書きしない
					if( finding.state != MaintenanceInspectionState::PASSED) {
						mergeMaintenanceFinding( service.parser, finding) ;
						addMaintenanceIssue( install, service.serviceInstallSection,
											std::wstring( key), reason, finding) ;
					}
				}
			}
		}

		// 未評価namedの構造不足を全file参照完了へ昇格させない
		if( service.parser.state != MaintenanceInspectionState::PASSED) {
			install.fileUses.push_back( {service.section, L"NamedServiceStructureNotAssessed", {}}) ;
		}

		// 不足も共同保持上限を消費し、過大集合を切り捨てない
		if( install.issues.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
		   install.fileUses.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既知の一明示参照を有限queueとworker内観測へ結合する
 * @param[in] inf 同期借用するINF handle
 * @param[in] workspace path境界の検証だけに借用する保護領域
 * @param[in] entries 固定されたpackage一覧
 * @param[in] parent 元INFのpackage相対親位置
 * @param[in] section 元宣言節
 * @param[in] key 元directive
 * @param[in] value 明示参照field。所有copyへ移す
 * @param[in] kind 参照種別。存在だけで署名を認定しない
 * @param[in] targetKind 同INF節を辿る場合の行形式
 * @param[in,out] pending 有限な到達節queue
 * @param[in,out] inventory 欠落参照も残す選択観測
 * @return 安全な参照観測成功0、不正path・節形式・容量のHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError addMaintenanceReference(
	HINF inf, const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view parent, const std::wstring &section, const std::wstring &key,
	std::wstring value, OfficialInfInstallReferenceKind kind,
	InstallInventorySectionKind targetKind, std::vector<InstallInventorySection> &pending,
	OfficialInfInstallInventory &inventory)
{
	bool present = false ;	// 元inventory／同INF節の存在だけを観測する
	// Local節だけを同じINFで辿り、外部のNeedsを推測して開かない
	if( kind == OfficialInfInstallReferenceKind::LOCAL_SECTION) {
		// 空・過長・path的な節名を拒否する
		if( !validInstallInventorySectionName( value)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		LONG			  count{} ;													// 明示空と不在、API失敗を区別する行数
		const NativeError countError = maintenanceLineCount( inf, value, count) ;	// 元診断
		// 不在以外のAPI失敗を参照欠落へ変換しない
		if( countError != 0) {
			return countError ;
		}

		present = count >= 0 ;
		// 実在節だけを有限queueへ追加し、欠落を観測から削除しない
		if( present) {
			// 参照先の形式とqueue容量を既存境界で確認した結果
			const NativeError error = queueInstallInventorySection( pending, value, targetKind) ;
			// 循環・共有の再走査と矛盾した行形式を既存helperで制限する
			if( error != 0) {
				return error ;
			}
		}
	} else {
		const std::wstring_view child = stripReferenceCurrentDirectory( value) ;	// 原参照名
		// 明示空を親位置へ補完しない
		if( child.empty()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		value = joinRelativePath( parent, child) ;
		// Fileは元packageの安全な位置だけを参照し、外部探索を行わない
		if( workspace.path( value).empty() || (kind != OfficialInfInstallReferenceKind::DIRECT_FILE &&
											 lowerExtension( value) != L".inf")) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		present = containsEntry( entries, value) ;
	}

	inventory.references.push_back( {section, key, std::move( value), kind, present}) ;
	return inventory.references.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS
			   ? nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)
			   : 0 ;
}

// 私有indexの未観測値。実queue・用途indexへ補完しない
constexpr std::size_t NO_MAINTENANCE_EVENTLOG_INDEX = MAXIMUM_INSTALL_INVENTORY_ITEMS ;

/**
 * @brief 同じ有限queueの節文脈と読取完了だけを保持します
 * @note 本文を複写せず、既存queue indexを借用する一同期呼出しの私有記録です
 */
struct MaintenanceEventLogSectionProof {
	/// Seedも含む参照元数。二つ以上なら混在を保留する
	std::size_t incoming{} ;
	/// 一意AddReg／DelReg元のqueue index。混在時は成功根拠にしない
	std::size_t registryParent{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// このREGISTRYの具体的子Uの元fileUses index
	std::size_t registryUse{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// 非空REGISTRYの元coverage gap index。fallback appendとの結合だけに使う
	std::size_t registryGap{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// 同eventlogの独立した具体的子U index
	std::size_t childUse{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// 同eventlogの非空子REGISTRY gap index
	std::size_t childGap{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// このDIRECTIVESから辿ったAddReg／DelRegのfield数
	std::size_t children{} ;
	/// 元全行読取を完了した場合だけtrue
	bool		complete{} ;
	/// 全行が非空AddReg／DelRegの形だけならtrue。空節はfalse
	bool		registryDirectivesOnly{true} ;
	/// 全子の一意文脈と読取完了を証明できる場合だけtrue
	bool		childrenValid{true} ;
	/// 元EventLog全制御行の全値が同byteへ結合した場合true
	bool		fullValues{true} ;
	/// 第4fieldからの処理がAddRegのみならtrue。DelRegを新data認定へ使わない
	bool		addRegOnly{true} ;
	/// 同registry内のEventMessageFile全設定行数。型の違う重複も数える
	std::size_t eventMessageSettings{} ;
} ;

/**
 * @brief 一AddService行の親markerと同eventlog子Uだけを私有結合します
 * @note 明示out-paramの所有vectorをcallerが借用し、公開型や永続stateへ保存しません
 */
struct MaintenanceEventLogMarkerProof {
	/// 当該行が作った親fileUses index。名前だけのfilterには使わない
	std::size_t marker{} ;
	/// 当該行の元service観測index。最終named評価後だけ認定する
	std::size_t service{} ;
	/// Services節内の元行ordinal
	LONG		row{} ;
	/// 同行第4fieldのDIRECTIVES queue index
	std::size_t eventSection{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// 分離後も残す具体的子Uの元fileUses index
	std::size_t childUse{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// sourceなしfallbackの元REGISTRY gap index
	std::size_t childGap{NO_MAINTENANCE_EVENTLOG_INDEX} ;
	/// 同AddService keyと全4fieldへ結合したraw行
	std::size_t rawRow{NO_MAINTENANCE_RAW_ROW} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief INFの指定節から一意な必須値を32ビットの符号なし整数として読み取ります
 * @param[in] inf 同期呼び出し中だけ借用する有効なINFハンドルです
 * @param[in] section 必須値を探す元INFの節名です
 * @param[in] key 必須の数値ディレクティブ名です。null不可の終端付き文字列です
 * @param[out] value 成功時に数値を格納し、失敗時は呼び出し前の値を保持します
 * @return 成功時は0、欠落・重複・解釈できない値ではHRESULTです
 * @throws std::bad_alloc 展開済みの文字列を保持するメモリを確保できない場合です
 */
//------------------------------------------------------------------------------
NativeError readRequiredServiceScalar( HINF inf, const std::wstring &section, const wchar_t *key,
									  std::uint32_t &value) ;

// 公式PCI Netの正式クラスと物理ネットワークの一値属性
constexpr std::array<std::wstring_view, 2U> NET_CLASS{L"Net",
													  L"{4d36e972-e325-11ce-bfc1-08002be10318}"} ;
// 物理ネットワークで共通の元属性名とその順序
constexpr std::array PHYSICAL_NET_ATTRIBUTES{L"Characteristics", L"BusType", L"*IfType",
											 L"*MediaType", L"*PhysicalMediaType"} ;
constexpr std::array<std::uint32_t, PHYSICAL_NET_ATTRIBUTES.size()> PCI_ETHERNET_VALUES{
	0x04U, 5U, 6U, 0U, 14U} ;	// 物理PCI、Ethernetインターフェースと媒体の組合せ
constexpr std::array<std::uint32_t, PHYSICAL_NET_ATTRIBUTES.size()> PCI_WIRELESS_VALUES{
	0x04U, 5U, 71U, 16U, 9U} ;	// 物理PCI、IEEE 802.11インターフェースとNative 802.11媒体
constexpr std::array<std::uint32_t, PHYSICAL_NET_ATTRIBUTES.size()> USB_WIRELESS_VALUES{
	0x84U, 15U, 71U, 16U, 9U} ;	// 物理USB、IEEE 802.11インターフェースとNative 802.11媒体
constexpr std::array<std::pair<const wchar_t *, std::uint32_t>, 6U>
				   PCI_WIRELESS_INTERFACE_ATTRIBUTES{{{L"NumberOfNetworkInterfaces", 5U},
													  {L"*IfConnectorPresent", 1U},
													  {L"*ConnectionType", 1U},
													  {L"*DirectionType", 0U},
													  {L"*AccessType", 2U},
													  {L"*HardwareLoopback", 0U}}} ;	// 確認した無線構成の追加属性

//------------------------------------------------------------------------------
/**
 * @brief 確認済み無線構成に対応する追加属性を元の基本節から照合する
 * @param[in] inf 元の署名とハッシュを確認した読取り専用INF
 * @param[in] install Windowsが選んだ基本導入節の完全名
 * @return すべての追加属性が重複のない一値で一致するときtrue
 * @pre 同じ基本節の物理バスと無線属性を別に確認すること
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readScopedWirelessInterfaceAttributes( HINF inf, const std::wstring &install)
{
	return std::ranges::all_of( PCI_WIRELESS_INTERFACE_ATTRIBUTES, [&]( const auto &attribute) {
		std::uint32_t actual{} ;	// 同じ基本節で確認した一つの元数値
		return readRequiredServiceScalar( inf, install, attribute.first, actual) == 0U &&
			   actual == attribute.second ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 物理ネットワークの5属性を同じ基本導入節の一意な元数値へ結ぶ
 * @param[in] inf 元Modelsと同じ読取専用INF
 * @param[in] install Windowsが解決した正確な基本導入名
 * @param[in] expected 対象とするインターフェースと媒体の値を定義順に保持した組合せ
 * @return 要求した物理バスとネットワーク種別の全値が一致した場合true
 * @note Characteristicsは物理と任意のプロパティ表示フラグだけを認める
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readScopedNetworkAttributes(
	HINF inf, const std::wstring &install,
	const std::array<std::uint32_t, PHYSICAL_NET_ATTRIBUTES.size()> &expected)
{
	// 同じ基本節から一意な全属性を読み、複数行や異なる媒体を組み合わせない
	for( std::size_t index = 0U; index < PHYSICAL_NET_ATTRIBUTES.size(); ++index) {
		const auto	 *key = PHYSICAL_NET_ATTRIBUTES[index] ;	// 同じ順序の既知属性名
		std::uint32_t value{} ;									// 同元節の重複しない一値
		// 欠落・重複・数値不正を既定値へ置換しない
		if( readRequiredServiceScalar( inf, install, key, value) != 0) {
			return false ;
		}

		// プロパティ表示フラグを持つ元の物理デバイスも照合します
		if( value != expected[index] && !(stringsEqual( key, L"Characteristics") && value == 0x84U)) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一DDInstallと同じ装飾の付随節を全INF予算内で非実行観測する
 * @param[in] inf 同期借用するINF handle
 * @param[in] workspace path境界だけに使用する保護領域
 * @param[in] entries 固定package一覧
 * @param[in] parent 元INFの安全な相対親位置
 * @param[in,out] budget 全選択共通の有限予算
 * @param[in,out] install Models所属とWindowsの実在選択を確認した観測
 * @param[in] explicitSeeds 非空なら原明示節だけを使い、付随suffixを追加しない
 * @param[in,out] copyDestinations 非nullなら同じ読取済みnamed行を最大4,096件保持する私有sidecar。nullでは通常の構造観測だけを行い、所有権を
 *                   取得しない
 * @param[out] eventLogProofs 非nullなら同行親markerと子Uの私有証明を返します。全体失敗時はcallerが破棄し、私有容量・曖昧時は元markerを保持します
 * @param[in,out] byteProof 非nullなら同元byteの全値・元data indexを私有結合する
 * @return 全節観測成功0。読取・不正参照・容量失敗は全体拒否のHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectMaintenanceInstallStructure(
	HINF inf, const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view parent, MaintenanceStructureBudget &budget,
	MaintenanceInfInstallStructure &install, std::span<const std::wstring> explicitSeeds = {},
	std::vector<MaintenanceCopyDestination>		*copyDestinations = nullptr,
	std::vector<MaintenanceEventLogMarkerProof> *eventLogProofs	  = nullptr,
	MaintenanceInfByteProof						*byteProof		  = nullptr)
{
	install.parser						   = {MaintenanceInspectionState::PASSED, 0} ;
	OfficialInfInstallInventory &inventory = install.inventory ;	// この選択だけのgraph
	const bool					 usbWireless =
		budget.scopedUsbNet && budget.collectionContent &&
		workspace.protectionMode() == OfficialWorkspaceMode::CURRENT_USER_INSPECTION &&
		readScopedNetworkAttributes( inf, inventory.selectedInstallSection,
									USB_WIRELESS_VALUES) ;	// 同じUSB無線選択です
	const bool pciWireless =
		budget.scopedPciNet && budget.sharedRegistryInf == inf &&
		readScopedNetworkAttributes( inf, inventory.selectedInstallSection,
									PCI_WIRELESS_VALUES) ;	// 同じ基本節の物理無線属性
	const bool pciNet =
		pciWireless ||
		(budget.scopedPciNet &&
		 readScopedNetworkAttributes( inf, inventory.selectedInstallSection,
									 PCI_ETHERNET_VALUES)) ;	// 元属性を確認した公式Netの選択
	const bool wirelessInterfaceAttributes =
		(pciWireless || usbWireless) &&
		workspace.protectionMode() == OfficialWorkspaceMode::CURRENT_USER_INSPECTION &&
		readScopedWirelessInterfaceAttributes(
			inf, inventory.selectedInstallSection) ;				// 元の6属性が揃う私有収集
	std::vector<MaintenanceServiceFieldObservation> serviceFields ;	// 同じ有限queueの必須行だけ
	std::vector<InstallInventorySection>			pending{
				   {inventory.selectedInstallSection, InstallInventorySectionKind::DIRECTIVES}} ;	// 訪問queue
	// 同queueのindexだけを所有する
	std::vector<MaintenanceEventLogSectionProof> eventSections ;
	// 通常構造readerの状態を変更しない
	bool										 eventProofEnabled = eventLogProofs != nullptr ;
	bool byteQueueComplete = byteProof != nullptr ;	// 最終caller認定まで全制御行を共同評価する
	// 同期callerの前回証明を今回の同行へ流用しない
	if( eventLogProofs != nullptr) {
		eventLogProofs->clear() ;
	}

	// 依存先の原明示節へsuffix補完せず、同じ一queueで共有節を除去する
	if( !explicitSeeds.empty()) {
		pending.clear() ;
		// 呼出し側が存在確認した原seedだけを有限queueへ加える
		for( const auto &seed : explicitSeeds) {
			const NativeError seedError = queueInstallInventorySection(
				pending, seed, InstallInventorySectionKind::DIRECTIVES) ;	// 一意な明示seed
			// 過大・形式矛盾のseedを部分集合へ切り詰めない
			if( seedError != 0) {
				return seedError ;
			}
		}
	}

	const std::wstring servicesSection = inventory.selectedInstallSection + L".Services" ;	// 同装飾
	constexpr std::
		array<std::wstring_view, 9>
			SUFFIXES{L".HW",
					 L".Services",
					 L".CoInstallers",
					 L".Interfaces",
					 L".Components",
					 L".Software",
					 L".Wdf",
					 L".Events",
					 L".LogConfigOverride"} ;	// 既存棚卸しと同じ有限付随節集合
	// 選択DDInstallと完全一致する付随節だけをseedへ加える
	for( const auto suffix : SUFFIXES) {
		// 依存先Needsへ推測suffixを加えず、構造選択だけで付随節を加える
		if( !explicitSeeds.empty()) {
			break ;
		}

		const std::wstring name = inventory.selectedInstallSection + std::wstring( suffix) ;	// 元節
		LONG			   count{} ;															// 不在と明示空の区別
		const NativeError  countError = maintenanceLineCount( inf, name, count) ;				// 元診断
		// 不在以外のAPI失敗を無参照の根拠にしない
		if( countError != 0) {
			return countError ;
		}

		// 他OS装飾や不在付随節を別の選択へfallbackしない
		if( count < 0) {
			continue ;
		}

		pending.push_back( {name, InstallInventorySectionKind::DIRECTIVES}) ;
		// 非空CoInstaller節の存在を作用なしへ変換しない
		if( stringsEqual( suffix, L".CoInstallers") && count > 0) {
			inventory.effects.push_back(
				{name, L"CoInstallers", OfficialInfInstallEffectKind::COINSTALLER}) ;
		}
	}

	// Seedの文脈を明示し、後からeventlogとして再利用された節を一意としない
	if( eventProofEnabled) {
		eventSections.resize( pending.size()) ;
		// 元seedはそれぞれ独立した到達文脈を一件消費する
		for( auto &section : eventSections) {
			section.incoming = 1U ;
		}
	}

	const auto maximumVisits =
		budget.collectionContent
			? MAXIMUM_COLLECTION_INVENTORY_VISITS
			: MAXIMUM_INSTALL_INVENTORY_SECTIONS ;	// 用途ごとの全起点に共通の上限
	const auto maximumLines =
		budget.collectionContent
			? MAXIMUM_COLLECTION_INVENTORY_LINES
			: MAXIMUM_INSTALL_INVENTORY_LINES ;	// 各起点から実際に読み取る行の上限
	// 共有・循環を一度に止める有限queueを末尾追加分まで調べる
	for( std::size_t index = 0U; index < pending.size(); ++index) {
		const InstallInventorySection current = pending[index] ;	// Queue再確保から独立したcopy
		// 予算を消費する照合の途中でも利用者の取消しを元の診断として返します
		if( budget.cancellation && *budget.cancellation && (*budget.cancellation)()) {
			return nativeErrorFromWin32( ERROR_CANCELLED) ;
		}

		// 公式範囲の起点・付随節・参照先を別の行形式と兼用させない
		if( !budget.modelSections.empty() &&
		   (std::ranges::any_of( budget.modelSections,
								[&]( const auto &section) {
									return stringsEqual( section.modelSection, current.name) ;
								}) ||
			std::ranges::any_of( budget.distinctSections, [&]( const auto &section) {
				return section.kind != current.kind && stringsEqual( section.name, current.name) ;
			}))) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const bool shareRegistry =
			budget.sharedRegistryInf && budget.sharedRegistryInf == inf &&
			current.kind == InstallInventorySectionKind::REGISTRY && !eventLogProofs &&
			!byteProof ;	// 公式範囲の通常棚卸しだけで、私有の元行証明は毎回独立に読む
		const auto shared = shareRegistry
								? std::ranges::find_if( budget.sharedRegistry,
													   [&]( const auto &section) {
														   return section.section == current.name ;
													   })
								: budget.sharedRegistry.end() ;		// 同じ固定INFの同じ行形式で得た観測
		const bool reused = shared != budget.sharedRegistry.end() ;	// すでに全読取り済みです
		LONG	   count{} ;										// 今回の起点から訪問する全行数です
		// 共有節の原観測を使う場合も、起点側の訪問と行数は維持します
		if( reused) {
			count = shared->lines ;
		} else {
			const auto countError =
				// 初回訪問で得る元読取診断
				maintenanceLineCount( inf, current.name, count) ;
			// 不在以外の読取失敗を容量診断へ置換しない
			if( countError != 0U) {
				return countError ;
			}
		}

		// 全訪問と実際に読み取る元行数を、それぞれ既存の有限枠へ拘束する
		if( ++budget.sections > maximumVisits || count < 0 ||
		   (!reused && static_cast<std::size_t>( count) > maximumLines - budget.lines)) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 共有節の再訪へ備え、一意な節名と用途を従来と同じ上限へ拘束する
		if( budget.collectionContent &&
		   std::ranges::none_of( budget.distinctSections, [&]( const auto &section) {
			   return section.kind == current.kind && stringsEqual( section.name, current.name) ;
		   })) {
			// 初回の節と用途だけを一意節・一意行の両上限へ加える
			const auto lines = static_cast<std::size_t>( count) ;	// この節で初めて読む行数
			// 新しい一意節を保持する前に節数と行数を制限する
			if( budget.distinctSections.size() >= MAXIMUM_INSTALL_INVENTORY_SECTIONS ||
			   lines > MAXIMUM_INSTALL_INVENTORY_LINES - budget.distinctLines) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			budget.distinctSections.push_back( current) ;
			budget.distinctLines += lines ;
		}

		inventory.visitedSections.push_back( current.name) ;
		// 明示空節を子Uの証明へ使わず、読取完了だけを保持する
		if( eventProofEnabled && count == 0) {
			eventSections[index].complete				= true ;
			eventSections[index].registryDirectivesOnly = false ;
		}

		// 明示空節を読取失敗へ変換しない
		if( count == 0) {
			continue ;
		}

		// Registryとdata本文の作用解釈は全file参照検査とは別の不足へ保持する
		if( current.kind != InstallInventorySectionKind::DIRECTIVES &&
		   current.kind != InstallInventorySectionKind::COPY_FILE_ROWS) {
			inventory.coverageGaps.push_back(
				{current.name,
				 {},
				 current.kind == InstallInventorySectionKind::REGISTRY
					 ? OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED
					 : OfficialInfInstallCoverageKind::DATA_ROWS_NOT_INTERPRETED}) ;
			// 非空registryの元gapだけをfallback用途へ結合し、別節を代用しない
			if( eventProofEnabled && current.kind == InstallInventorySectionKind::REGISTRY) {
				eventSections[index].registryGap = inventory.coverageGaps.size() - 1U ;
			}
		}

		// 共通節から得た作用と用途は、訪問先の元名を保持してこの起点にも付けます
		if( reused) {
			// 再利用でも起点の作用・用途の保持上限を守ります
			if( inventory.effects.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   install.fileUses.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   inventory.coverageGaps.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   shared->coInstallers > MAXIMUM_INSTALL_INVENTORY_ITEMS - inventory.effects.size() ||
			   shared->fileUses.size() >
				   MAXIMUM_INSTALL_INVENTORY_ITEMS - install.fileUses.size()) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			inventory.scannedLines += static_cast<std::size_t>( count) ;
			inventory.effects.insert(
				inventory.effects.end(), shared->coInstallers,
				{current.name, L"CoInstallers32", OfficialInfInstallEffectKind::COINSTALLER}) ;
			// 元行の用途型・値・順序をそのまま再利用する
			install.fileUses.insert( install.fileUses.end(), shared->fileUses.begin(),
									shared->fileUses.end()) ;

			continue ;
		}

		const auto effectsBefore  = inventory.effects.size() ;	// この節の最初の作用位置
		const auto fileUsesBefore = install.fileUses.size() ;	// この節の最初の用途位置
		// 確定した全行を順に読み、途中終了と過大fieldを拒否する
		for( LONG row = 0; row < count; ++row) {
			// 後続coreの保持量をprivate予約で奪わない
			if( byteProof != nullptr) {
				byteProof->capacity( budget.effects + budget.references + budget.services +
									budget.issues + budget.fileUses + budget.coverageGaps +
									inventory.effects.size() + inventory.references.size() +
									inventory.coverageGaps.size() + install.services.size() +
									install.issues.size() + install.fileUses.size() +
									serviceFields.size() + pending.size() + eventSections.size() +
									(eventLogProofs == nullptr ? 0U : eventLogProofs->size()) +
									(copyDestinations == nullptr ? 0U : copyDestinations->size())) ;
			}

			INFCONTEXT		  line{} ;	// 確定indexで取得する現在行
			const NativeError lineError =
				// 元診断
				maintenanceLineAt( inf, current.name, row, line) ;
			// 途中失敗を正常終端へ変換しない
			if( lineError != 0) {
				return lineError ;
			}

			++budget.lines ;
			++inventory.scannedLines ;
			const DWORD fields = SetupGetFieldCount( &line) ;	// Keyを除く元field数
			// 収集のレジストリ行だけを形式確認のために追加で読む
			const bool	wideRegistry = fields > MAXIMUM_INSTALL_INVENTORY_FIELDS ;
			// 他の用途や収集用の行上限を超えた入力は拒否します
			if( wideRegistry && (!budget.collectionContent ||
								current.kind != InstallInventorySectionKind::REGISTRY ||
								fields > MAXIMUM_COLLECTION_BINARY_FIELDS)) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			const std::size_t rawRow =
				byteProof == nullptr ? NO_MAINTENANCE_RAW_ROW
									 : byteProof->row( current.name, row, count,
													  fields) ;	// 同section count／ordinalの全値結合

			std::wstring key ;	// Directive節以外の本文をkeyとして保持しない
			// 処理節では空keyを不正として検出する
			if( current.kind == InstallInventorySectionKind::DIRECTIVES) {
				MaintenanceFieldRead read{} ;	// 同じ元query／readの結果だけ
				const NativeError	 error = readMaintenanceField(
					   line, 0U, key,
					   byteProof != nullptr && byteProof->active() ? &read : nullptr) ;	// 一宣言のkey
				// 読取不能宣言を未知の正常行として読み飛ばさない
				if( error != 0 || key.empty()) {
					return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				// 元keyを追加APIより前に全比較する
				if( byteProof != nullptr) {
					byteProof->field( rawRow, 0U, key, read) ;
				}
			} else {
				// 元coreが未取得のkey有無だけを同context内で一回補う
				if( byteProof != nullptr) {
					byteProof->extra( line, rawRow, 0U, 0U) ;
				}
			}

			std::vector<std::wstring> values ;				// この行だけの全値。command本文は外へ保持しない
			NativeError				  flagsReadError{} ;	// 個別過長flagsだけを構造へ残す
			// 空値を含む全fieldを有限に読み、切捨てbufferを使わない
			for( DWORD field = 1U; field <= fields; ++field) {
				std::wstring		 value ;	// 一つの展開後field
				MaintenanceFieldRead read{} ;	// 元結果を同時捕捉し、再readしない
				const NativeError	 error =
					// 長さを先に照会
					readMaintenanceField( line, field, value,
										 byteProof != nullptr && byteProof->active() ? &read
																					 : nullptr) ;
				// 過長flagsは個別不正、他の読取不能は全体失敗として分離する
				if( error != 0) {
					// flagsだけの有限長失敗は0や2へ補完せず観測結果に残す
					if( stringsEqual( key, L"AddService") && field == 2U &&
					   error == nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)) {
						flagsReadError = error ;
					} else {
						return error ;
					}
				}

				// 元の成功値だけを同raw fieldへ全比較する
				if( error == 0 && byteProof != nullptr) {
					byteProof->field( rawRow, field, value, read) ;
				}

				values.push_back( std::move( value)) ;
			}

			// HKRの純粋なバイナリ値以外へ追加枠を適用しない
			if( wideRegistry) {
				std::uint32_t				  flags{} ;		// 展開値で確認したレジストリ型
				MaintenanceInfStructureReason reason{} ;	// 数値解析に失敗したときの元理由
				// HKRのキー名とバイナリ型、各byteの16進表記をすべて確認します
				if( !stringsEqual( values[0], L"HKR") || values[2].empty() ||
				   parseMaintenanceFlags( values[3], flags, reason).state !=
					   MaintenanceInspectionState::PASSED ||
				   flags != FLG_ADDREG_TYPE_BINARY ||
				   !std::ranges::all_of(
					   std::span{values}.subspan( 4U), []( const std::wstring &byte) {
						   return byte.size() == 2U &&
								  byte.find_first_not_of( L"0123456789abcdefABCDEF") == byte.npos ;
					   })) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}
			}

			// 制御行と到達copyの全値不足を後のcaller名一致で補完しない
			if( byteProof != nullptr &&
			   (current.kind == InstallInventorySectionKind::DIRECTIVES ||
				current.kind == InstallInventorySectionKind::COPY_FILE_ROWS)) {
				byteQueueComplete = byteQueueComplete && byteProof->verified( rawRow) ;
			}

			// EventLogの全行はAddRegのみと全raw値の一致を独立に確認する
			if( eventProofEnabled && current.kind == InstallInventorySectionKind::DIRECTIVES) {
				eventSections[index].fullValues = eventSections[index].fullValues &&
												  byteProof != nullptr &&
												  byteProof->verified( rawRow) ;
				eventSections[index].addRegOnly = eventSections[index].addRegOnly &&
												  stringsEqual( key, L"AddReg") && !values.empty() ;
			}

			// 必須service行は一度の有限読取結果だけを保持し、後から到達するnamedにも結ぶ
			// 第4field本文は既存follow可能なregistry宣言だけで全行を構成する必要がある
			if( eventProofEnabled && current.kind == InstallInventorySectionKind::DIRECTIVES &&
			   (!(stringsEqual( key, L"AddReg") || stringsEqual( key, L"DelReg")) || values.empty() ||
				std::ranges::any_of( values, []( const auto &value) {
					return !validInstallInventorySectionName( value) ||
						   value.find( L'%') != std::wstring::npos ;
				}))) {
				eventSections[index].registryDirectivesOnly = false ;
			}

			// 必須service行は一度の有限読取結果だけを保持し、後から到達するnamedにも結ぶ
			if( current.kind == InstallInventorySectionKind::DIRECTIVES &&
			   isAllowedValue( key, MAINTENANCE_SERVICE_FIELDS)) {
				serviceFields.push_back(
					{current.name, key, observeMaintenanceServiceField( key, values)}) ;
			}

			// Data file listの観測を無参照証明へ使わず、具体的用途として残す
			if( current.kind == InstallInventorySectionKind::COPY_FILE_ROWS) {
				// Source名省略時はdestination名を使い、別名copyを先頭名へ潰さない
				if( values.empty() || values.front().empty() || values.size() > 4U) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				install.fileUses.push_back(
					{current.name, L"CopyFileSource",
					 values.size() >= 2U && !values[1].empty() ? values[1] : values.front()}) ;
				// 展開済みbinary照合用の別名を同じ行から保持し、listを再走査しない
				if( copyDestinations != nullptr) {
					// 全seedで共有する保持上限を行ごとにresetしない
					if( copyDestinations->size() >= MAXIMUM_INSTALL_INVENTORY_ITEMS) {
						return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
					}

					copyDestinations->push_back(
						{current.name, values.front(),
						 values.size() >= 2U && !values[1].empty() ? values[1] : values.front(),
						 rawRow}) ;
				}
			}
			// 不透明なdata用途は既知CopyFiles listとは区別する
			else if( current.kind == InstallInventorySectionKind::DATA_ROWS) {
				install.fileUses.push_back( {current.name, L"DataRowsNotInterpreted", {}}) ;
			}
			// Registry行の具体的範囲を保持し、全file用途を解釈したと称さない
			else if( current.kind == InstallInventorySectionKind::REGISTRY) {
				// Registryのroot／subkeyが欠落した不正入力を拒否する
				if( values.size() < 2U) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				// 同値名への別型・別flags・重複行も一意設定の分母へ残す
				if( eventProofEnabled && values.size() >= 3U &&
				   stringsEqual( values[2], L"EventMessageFile")) {
					++eventSections[index].eventMessageSettings ;
				}

				// 値名で明示されたCoInstallerだけを具体的作用として保持する
				if( values.size() >= 3U && stringsEqual( values[2], L"CoInstallers32")) {
					inventory.effects.push_back( {current.name, L"CoInstallers32",
												 OfficialInfInstallEffectKind::COINSTALLER}) ;
				}

				// Registry作用とfile用途を分離し、具体的file表記があるdataだけを残す
				for( std::size_t field = 4U; field < values.size(); ++field) {
					const std::wstring &value = values[field] ;	// この原dataだけの同期借用
					const auto			extension =
						// 元データの拡張子だけを観測します
						lowerExtension( value) ;
					const bool scopedNet =
						budget.sharedRegistryInf == inf &&
						(budget.scopedPciNet || usbWireless) ;	// 同じ元Netの登録用途を拾います
					// パス表現または実行コードの拡張子を持ち、明示ファイルとして照合すべき値
					const bool explicitFile = value.find_first_of( L"\\/%") != value.npos ||
											  extension == L".dll" || extension == L".sys" ||
											  extension == L".exe" ;
					// 限定Netの既知の非実行拡張子として、単独名でも元媒体に照合すべき値
					const bool bareFile =
						scopedNet && !explicitFile &&
						(extension == L".txt" || extension == L".dat" || extension == L".inf" ||
						 isAllowedValue( extension, REJECTED_REFERENCED_EXTENSIONS)) ;
					// File位置／token／binary名の具体的な未追跡用途を無参照へ変換しない
					if( explicitFile || bareFile) {
						const bool settingLabel = scopedNet && field == 4U &&
												  // 元値を確認できた収集用の表示観測
												  isWirelessParameterLabel( values, usbWireless) ;
						install.fileUses.push_back(
							{current.name,
							 settingLabel ? std::wstring{WIRELESS_PARAMETER_LABEL}
							 : bareFile	  ? std::wstring{WIRELESS_BARE_REGISTRY_FILE}
										  : L"RegistryFileUseNotAssessed",
							 value}) ;
						std::uint32_t				  flags{} ;		// この元rowだけのexact type
						MaintenanceInfStructureReason reason{} ;	// 新private判定にだけ使う
						// keyなしstrict5fieldの単一EventMessageFileだけを元use ordinalへstageする
						if( byteProof != nullptr && byteProof->verified( rawRow) &&
						   byteProof->get( rawRow).key.size == 0U && values.size() == 5U &&
						   field == 4U && stringsEqual( values[0], L"HKR") && values[1].empty() &&
						   stringsEqual( values[2], L"EventMessageFile") && !value.empty() &&
						   parseMaintenanceFlags( values[3], flags, reason).state ==
							   MaintenanceInspectionState::PASSED &&
						   flags == 0x00020000U) {
							byteProof->registry( rawRow, install.fileUses.size() - 1U, index) ;
						}

						// 元読取が保持した最初の独立子Uだけをindexで結ぶ
						if( eventProofEnabled &&
						   eventSections[index].registryUse == NO_MAINTENANCE_EVENTLOG_INDEX) {
							eventSections[index].registryUse = install.fileUses.size() - 1U ;
						}
					}
				}
			} else {
				std::size_t rowProof = NO_MAINTENANCE_EVENTLOG_INDEX ;	// 同行だけのout-param index
				// 全値を検査した物理ネットワーク属性を同一基本節だけで認識する
				const bool	netAttribute =
					(pciNet || usbWireless) &&
					stringsEqual( current.name, inventory.selectedInstallSection) &&
					(std::ranges::any_of(
						 PHYSICAL_NET_ATTRIBUTES,
						 [&]( const auto *attribute) { return stringsEqual( key, attribute) ; }) ||
					 (wirelessInterfaceAttributes &&
					  std::ranges::any_of( PCI_WIRELESS_INTERFACE_ATTRIBUTES,
										  [&]( const auto &attribute) {
											  return stringsEqual( key, attribute.first) ;
										  }))) ; // 照合済み基本節の属性だけ
				// 検証済みのNet属性を標準作用に分類し、それ以外は共通の分類を使用します
				const OfficialInfInstallEffectKind effect =
					netAttribute ? OfficialInfInstallEffectKind::STANDARD_DIRECTIVE
								 : installInventoryEffectKind( key) ;
				inventory.effects.push_back( {current.name, key, effect}) ;
				// 検証済みNet属性を除き、この元ディレクティブに残る検査上の不足区分
				const auto gap =
					netAttribute ? std::nullopt : installInventoryCoverageKind( key, values) ;
				// 未追跡directive・未解決依存を新しいcaller証明の外へ捨てない
				if( effect == OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE ||
				   (gap.has_value() &&
					*gap != OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG) ||
				   stringsEqual( key, L"Include") || stringsEqual( key, L"Needs")) {
					byteQueueComplete = false ;
				}

				// 具体的な未解釈作用を元宣言へ結合する
				if( gap.has_value()) {
					inventory.coverageGaps.push_back( {current.name, key, *gap}) ;
				}

				// 未知directiveを限定nullの完全対応へ通さない
				if( effect == OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE) {
					addMaintenanceIssue( install, current.name, key,
										MaintenanceInfStructureReason::UNKNOWN_DIRECTIVE,
										{MaintenanceInspectionState::UNSUPPORTED,
										 nativeErrorFromWin32( ERROR_NOT_SUPPORTED)}) ;
				}

				// Serviceはempty第一fieldと2-field形式を保守readerだけで扱う
				if( stringsEqual( key, L"AddService")) {
					observeMaintenanceService( install, current.name, values, flagsReadError,
											  servicesSection, usbWireless) ;
				}

				// 未追跡だった具体的file用途を保持し、位置・byte・署名の未検査を隠さない
				if( stringsEqual( key, L"CopyINF") || stringsEqual( key, L"AddComponent") ||
				   stringsEqual( key, L"ServiceBinary") || stringsEqual( key, L"UmdfServiceBinary") ||
				   stringsEqual( key, L"EventMessageFile") ||
				   effect == OfficialInfInstallEffectKind::UNKNOWN_DIRECTIVE || gap.has_value()) {
					install.fileUses.push_back(
						{current.name, key, values.empty() ? std::wstring{} : values.front()}) ;
					// 同元ServiceBinaryのDIRID13全値だけを最後のnamed target比較へstageする
					if( byteProof != nullptr && stringsEqual( key, L"ServiceBinary")) {
						byteProof->control( rawRow, install.fileUses.size() - 1U) ;
					}

					// 厳密4fieldのnamed行だけを候補にし、最終service成功は後段で確認する
					if( eventProofEnabled && stringsEqual( key, L"AddService") &&
					   values.size() == 4U && !values[0].empty() && !values[2].empty() &&
					   !values[3].empty()) {
						rowProof = eventLogProofs->size() ;
						eventLogProofs->push_back(
							{install.fileUses.size() - 1U, install.services.size() - 1U, row}) ;
						eventLogProofs->back().rawRow = rawRow ;
					}
				}

				// 同INF参照・package相対file・外部依存を既知directiveだけで区別する
				for( std::size_t field = 0U; field < values.size(); ++field) {
					std::wstring target = values[field] ;	// 参照だけを結果へ残す所有copy
					OfficialInfInstallReferenceKind kind =
						OfficialInfInstallReferenceKind::LOCAL_SECTION ;	// 既定境界
					InstallInventorySectionKind targetKind =
						InstallInventorySectionKind::DATA_ROWS ;	// 不透明dataが既定
					bool follow = false ;							// 未知fieldを任意節参照へ変換しない
					// Registry処理の明示節は別行形式で辿る
					if( stringsEqual( key, L"AddReg") || stringsEqual( key, L"DelReg")) {
						follow	   = true ;
						targetKind = InstallInventorySectionKind::REGISTRY ;
					}
					// 外部INF参照は元packageだけの存在観測に限定する
					else if( stringsEqual( key, L"Include") || stringsEqual( key, L"CopyINF")) {
						follow = true ;
						kind   = stringsEqual( key, L"Include")
									 ? OfficialInfInstallReferenceKind::INCLUDE_INF
									 : OfficialInfInstallReferenceKind::COPY_INF ;
					}
					// Needsの明示名をそのまま使い、suffixや別節Includeを借用しない
					else if( stringsEqual( key, L"Needs")) {
						follow	   = true ;
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
					}
					// Nullでは空第3／第4fieldを参照欠落にせず、非空参照だけを辿る
					else if( stringsEqual( key, L"AddService")) {
						follow	   = (field == 2U || field == 3U) && !target.empty() ;
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
					}
					// 指定第3fieldだけが処理節であり、後続flagsを節にしない
					else if( stringsEqual( key, L"AddInterface") ||
							stringsEqual( key, L"AddComponent") ||
							stringsEqual( key, L"AddSoftware")) {
						follow	   = field == 2U ;
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
					}
					// WDFは指定第2fieldだけを処理節として辿る
					else if( stringsEqual( key, L"KmdfService") ||
							stringsEqual( key, L"UmdfService")) {
						follow	   = field == 1U ;
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
					}
					// 直接CopyFilesとfile list節を区別して有限に観測する
					else if( stringsEqual( key, L"CopyFiles")) {
						follow	   = true ;
						targetKind = InstallInventorySectionKind::COPY_FILE_ROWS ;
						install.fileUses.push_back( {current.name, key, target}) ;
						// @fileを節名に読み替えずpackage相対参照へ渡す
						if( target.starts_with( L"@")) {
							target.erase( 0U, 1U) ;
							kind = OfficialInfInstallReferenceKind::DIRECT_FILE ;
						}
					}

					// 明示参照を持つfieldだけを有限な既存queueへ追加する
					if( follow) {
						const NativeError error = addMaintenanceReference(
							inf, workspace, entries, parent, current.name, key, std::move( target),
							kind, targetKind, pending, inventory) ;	// 元境界
						// 不正参照や容量失敗ではINF全体の部分観測を破棄する
						if( error != 0) {
							return error ;
						}

						// 欠落したregistry子節は他の子Uで補完せず、元親markerを保留する
						if( eventProofEnabled &&
						   kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
						   targetKind == InstallInventorySectionKind::REGISTRY &&
						   !inventory.references.back().targetPresent) {
							eventSections[index].childrenValid = false ;
						}

						// 既存queueへ入った同INF参照だけを私有文脈へ結ぶ。再readはしない
						if( eventProofEnabled &&
						   kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
						   inventory.references.back().targetPresent) {
							eventSections.resize( pending.size()) ;
							const auto targetEntry =
								std::ranges::find_if( pending, [&inventory]( const auto &entry) {
									return stringsEqual( entry.name,
														inventory.references.back().target) ;
								}) ; // 元queueの一意indexだけを同期借用する
							const std::size_t targetIndex = static_cast<std::size_t>(
								targetEntry - pending.begin()) ;				// 実在queue内
							auto &targetProof = eventSections[targetIndex] ;	// 再確保後の一要素だけ
							++targetProof.incoming ;
							// 一意registry caller以外の共有文脈は双方を保留する
							if( targetKind == InstallInventorySectionKind::REGISTRY) {
								++eventSections[index].children ;
								// 最初のcallerだけを保持し、二番目を先頭callerへ統合しない
								if( targetProof.incoming == 1U) {
									targetProof.registryParent = index ;
								} else {
									eventSections[index].childrenValid = false ;
									// 元callerも共有の影響を受けるため証明を保留する
									if( targetProof.registryParent !=
									   NO_MAINTENANCE_EVENTLOG_INDEX) {
										eventSections[targetProof.registryParent].childrenValid =
											false ;
									}
								}
							}

							// 第3fieldや別callerでは当該行のeventlog結合を作らない
							if( rowProof != NO_MAINTENANCE_EVENTLOG_INDEX && field == 3U) {
								eventLogProofs->at( rowProof).eventSection = targetIndex ;
							}
						}
					}
				}
			}

			// 一選択の中間保持量も固定上限を超えさせない
			if( inventory.effects.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   inventory.coverageGaps.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   serviceFields.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   install.services.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   install.issues.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
			   install.fileUses.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			// 私有保持も共同項目枠へ含める。証明限界は元readerの成功を拒否へ変えない
			if( eventProofEnabled &&
			   (eventSections.size() + eventLogProofs->size() + budget.references +
					inventory.references.size() + budget.fileUses + install.fileUses.size() +
					inventory.effects.size() + inventory.coverageGaps.size() +
					serviceFields.size() + install.services.size() + install.issues.size() >
				MAXIMUM_INSTALL_INVENTORY_ITEMS)) {
				eventProofEnabled = false ;
				eventSections.clear() ;
				eventLogProofs->clear() ;
			}

			// 増加直後にも共同core必要量を優先してprivate予約を撤回する
			if( byteProof != nullptr) {
				byteProof->capacity(
					budget.effects + budget.references + budget.services + budget.issues +
					budget.fileUses + budget.coverageGaps + inventory.effects.size() +
					inventory.references.size() + inventory.coverageGaps.size() +
					serviceFields.size() + install.services.size() + install.issues.size() +
					install.fileUses.size() + pending.size() + eventSections.size() +
					(eventLogProofs == nullptr ? 0U : eventLogProofs->size()) +
					(copyDestinations == nullptr ? 0U : copyDestinations->size())) ;
			}
		}

		// 確定した全行の成功後だけ読取完了を認定する
		if( eventProofEnabled) {
			eventSections[index].complete = true ;
		}

		// レジストリ節の全行が成立した場合だけ、次の起点で再利用できる観測を保持します
		if( shareRegistry) {
			MaintenanceSharedRegistrySection verified{
				current.name,
				count,
				inventory.effects.size() - effectsBefore,
				{}} ;	// この節から得た同一種類の作用と元行順の用途
			// この節の用途型と値だけを元行順に残す
			const auto uses =
				// 現節で追加した元用途
				std::span( install.fileUses).subspan( fileUsesBefore) ;
			verified.fileUses.assign( uses.begin(), uses.end()) ;

			budget.sharedRegistry.push_back( std::move( verified)) ;
		}
	}

	const NativeError namedError =
		// 再読取しない照合
		assessMaintenanceNamedServices( install, serviceFields) ;
	// 必須構造の不足保持で上限を超えた場合は部分観測を公開しない
	if( namedError != 0) {
		return namedError ;
	}

	// 全queueを一回だけ照合し、子Uとread完了を一意な元callerへ集約する
	if( eventProofEnabled) {
		// 各元registryの私有indexだけを順に処理し、親ごとの全節再探索をしない
		for( const auto &child : eventSections) {
			// registryへ至る元callerがない節を別eventlogの証明へ使わない
			if( child.registryParent == NO_MAINTENANCE_EVENTLOG_INDEX) {
				continue ;
			}

			auto &event			= eventSections[child.registryParent] ;	// 読取済みの元DIRECTIVESだけ
			event.childrenValid = event.childrenValid && child.complete && child.incoming == 1U ;
			// 同eventlogから到達した具体的Uだけを保持する
			if( event.childUse == NO_MAINTENANCE_EVENTLOG_INDEX) {
				event.childUse = child.registryUse ;
			}

			// 非空子節の元gapをsourceなしfallbackへ結ぶ
			if( event.childGap == NO_MAINTENANCE_EVENTLOG_INDEX) {
				event.childGap = child.registryGap ;
			}
		}

		// 同行serviceの最終PASSEDと一意な第4field文脈だけをcallerへ残す
		for( auto &proof : *eventLogProofs) {
			// 未結合の第4fieldには子のindexを補完しない
			if( proof.eventSection != NO_MAINTENANCE_EVENTLOG_INDEX) {
				proof.childUse = eventSections[proof.eventSection].childUse ;
				proof.childGap = eventSections[proof.eventSection].childGap ;
			}
		}

		// 元proof順で成功条件だけを残し、サービス名の一致で結び直さない
		std::erase_if( *eventLogProofs, [&install, &eventSections]( const auto &proof) {
			// 未実在・未結合の第4fieldから親markerを外さない
			if( proof.eventSection == NO_MAINTENANCE_EVENTLOG_INDEX) {
				return true ;
			}

			const auto &service = install.services[proof.service] ;		// 同行だけの最終観測
			const auto &event	= eventSections[proof.eventSection] ;	// 同行第4fieldの元queue
			return service.parser.state != MaintenanceInspectionState::PASSED ||
				   !service.flags.has_value() || (*service.flags != 0U && *service.flags != 2U) ||
				   !event.complete || event.incoming != 1U || !event.registryDirectivesOnly ||
				   !event.childrenValid || event.children == 0U ||
				   (proof.childUse == NO_MAINTENANCE_EVENTLOG_INDEX &&
					proof.childGap == NO_MAINTENANCE_EVENTLOG_INDEX) ;
		}) ;
		// 最終named PASSEDと同第4fieldのAddReg-only一意callerだけをdataへ結ぶ
		if( byteProof != nullptr && byteProof->active() && byteQueueComplete) {
			// 同元data indexだけを一度ずつ確認し、後からの共有callerを反映する
			for( auto &candidate : byteProof->data) {
				const auto &registry = eventSections[candidate.queue] ;	// 元REGISTRYの全caller
				// 別caller／同値名複数rowを一意設定へ絞らない
				if( registry.incoming != 1U ||
				   registry.registryParent == NO_MAINTENANCE_EVENTLOG_INDEX ||
				   registry.eventMessageSettings != 1U) {
					continue ;
				}

				const auto &event = eventSections[registry.registryParent] ;	// 同第4fieldの元節
				candidate.caller  = event.complete && event.incoming == 1U && event.fullValues &&
								   event.addRegOnly && event.childrenValid &&
								   std::ranges::any_of( *eventLogProofs, [&]( const auto &proof) {
									   return proof.eventSection == registry.registryParent &&
											  byteProof->verified( proof.rawRow) ;
								   }) ; // 名称からAddServiceを結び直さない
			}
		}
	}

	const auto associated = std::ranges::count_if( install.services, []( const auto &service) {
		return service.flags.has_value() && (*service.flags & 2U) != 0U ;
	}) ; // SPSVCINST_ASSOCSERVICEのbit観測数。literal比較だけで数えない
	// 複数associated serviceを先頭nullの成功で隠さない
	if( associated > 1U) {
		addMaintenanceIssue(
			install, servicesSection, L"AddService",
			MaintenanceInfStructureReason::MULTIPLE_ASSOCIATED_SERVICES,
			{MaintenanceInspectionState::UNSUPPORTED, nativeErrorFromWin32( ERROR_NOT_SUPPORTED)}) ;
		// Namedの矛盾したassociated構成を全参照完了へ昇格させない
		if( std::ranges::any_of( install.services,
							   []( const auto &service) { return !service.serviceName.empty() ; })) {
			install.fileUses.push_back(
				{servicesSection, L"NamedServiceAssociationNotAssessed", {}}) ;
		}
	}

	const bool nullObserved = std::ranges::any_of( install.services, []( const auto &service) {
		return service.serviceName.empty() && service.flags.has_value() && *service.flags == 2U ;
	}) ; // 構造観測であり、全file不在の認証ではない
	const bool dependencies = std::ranges::any_of( inventory.effects, []( const auto &effect) {
		return effect.kind == OfficialInfInstallEffectKind::EXPLICIT_DEPENDENCY ;
	}) ; // 同節の依存存在だけを観測する
	install.contentKind =
		nullObserved && (!install.fileUses.empty() || dependencies)
			? MaintenanceInfContentKind::MIXED
		: nullObserved && install.parser.state == MaintenanceInspectionState::PASSED
			? MaintenanceInfContentKind::NULL_DRIVER
		: !install.fileUses.empty() ? MaintenanceInfContentKind::PACKAGE_FILES
									: MaintenanceInfContentKind::UNKNOWN ;
	budget.effects += inventory.effects.size() ;
	budget.references += inventory.references.size() ;
	budget.services += install.services.size() ;
	budget.issues += install.issues.size() ;
	budget.fileUses += install.fileUses.size() ;
	budget.coverageGaps += inventory.coverageGaps.size() ;
	return budget.effects > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   budget.references > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   budget.services > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   budget.issues > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   budget.fileUses > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   budget.coverageGaps > MAXIMUM_INSTALL_INVENTORY_ITEMS
			   ? nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)
			   : 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正式クラス名又はGUIDを含むINFに一意な正式対を要求する
 * @param[in] inf 同workerの検査中だけ借用する有効な読取り専用HINF
 * @param[in] expected 正式なクラス名とクラスGUIDの順の組
 * @return 無関係Class又は一意な正式対は0、取り違え・重複・不正fieldはERROR_INVALID_DATAのHRESULT
 * @note SetupAPIが展開した全Class/ClassGUID行をcase-insensitive比較し、他Classの既存GUID規則を変更しない
 * @see docs/adr/0507-standard-tapedrive-class-and-content-boundary.md
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError validateSetupClassPair( const HINF								  inf,
												 const std::array<std::wstring_view, 2U> &expected)
{
	constexpr std::array		 keys{std::wstring_view{L"Class"},
							  std::wstring_view{L"ClassGUID"}} ;	// 原Versionの二属性
	std::array<std::wstring, 2U> firstValues ;						// 各属性の最初の原展開値
	std::array<std::size_t, 2U>	 counts{} ;							// 同名行を省略しない原件数
	bool classObserved{} ;											// 正式名又は正式GUIDを一行以上観測した場合だけ厳密対を要求
	bool malformed{} ;												// 関連入力の不正fieldを後続の正常行で上書きしない
	// 有限な元INF内の両属性の全行を調べ、後置した正式対の偽装も検出する
	for( std::size_t index = 0U; index < keys.size(); ++index) {
		INFCONTEXT line{} ;	// 現在の同属性行
		// 属性欠測は関連対の最終検査で拒否し、無関係Classには従来規則を残す
		if( !SetupFindFirstLineW( inf, L"Version", keys[index].data(), &line)) {
			continue ;
		}

		// 同名の最終行まで検査し、重複を最初の一値へ正規化しない
		do {
			std::wstring value ;									// 現在行のSetupAPI展開値
			const auto	 error = readInfField( line, 1U, value) ;	// 元fieldの読取り結果
			malformed		   = malformed || error != 0 || SetupGetFieldCount( &line) != 1U ;
			classObserved = classObserved || (error == 0 && stringsEqual( value, expected[index])) ;
			// 各属性の一値目だけを保持し、追加行は件数へ残す
			if( ++counts[index] == 1U) {
				firstValues[index] = std::move( value) ;
			}

			INFCONTEXT next{} ;	// 同名の次行。API終端では現在行を再利用しない
			// 最終同名行でこの属性の検査を終える
			if( !SetupFindNextMatchLineW( &line, keys[index].data(), &next)) {
				break ;
			}

			line = next ;
		} while( true) ;
	}

	// 正式対の両方向偽装と余分fieldを拒否する
	if( classObserved &&
	   (malformed || counts[0] != 1U || counts[1] != 1U ||
		!stringsEqual( firstValues[0], expected[0]) || !stringsEqual( firstValues[1], expected[1]))) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

// Windowsが定義するテープドライブの正式クラスとGUID
constexpr std::array<std::wstring_view, 2U> TAPE_DRIVE_CLASS{
	L"TapeDrive", L"{6d807884-7d21-11cf-801c-08002be10318}"} ;
// Windowsが定義するメディアチェンジャーの正式クラスとGUID
constexpr std::array<std::wstring_view, 2U> MEDIUM_CHANGER_CLASS{
	L"MediumChanger", L"{ce5939ae-ebde-11d0-b181-0000f8753ec4}"} ;
// Windowsが定義するHDCの正式クラスとGUID
constexpr std::array<std::wstring_view, 2U>			HDC_CLASS{L"HDC",
													  L"{4d36e96a-e325-11ce-bfc1-08002be10318}"} ;

//------------------------------------------------------------------------------
/**
 * @brief 対応するWindows x64の指定をSetupAPIの代替プラットフォーム入力へ変換します
 * @param[in] platform OSの版・ビルド・製品種別・アーキテクチャ・SuiteMaskの指定です
 * @return 対応する指定ではSP_ALTPLATFORM_INFO_V3、対象外ではstd::nulloptです
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<SP_ALTPLATFORM_INFO_V3> nativeModelsPlatform(
	const OfficialInfModelsPlatform &platform) ;

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 現OSの全DDInstallまたは元Modelsで検証した公式範囲を有限に解析する
 * @param[in] workspace 同期借用する保護領域。呼出し中の変更は禁止する
 * @param[in] entries 固定済みの最大32,768 entry。INFは一意で最大4 MiB
 * @param[in] infRelativePath 安全な一INF相対path。worker外へ保存しない
 * @param[in] policy 有限ID／source上限と内容Class・Provider・構文識別子のpolicy
 * @param[out] structure 全体読取・元byte再照合に成功した場合だけ観測を保持する
 * @param[in] scopedModels 署名済み収集閉包の同一INFのModels証拠。通常の全起点はnull
 * @param[in] cancellation 同収集workerの同期取消し照会。通常の読取りはnull
 * @param[in] inboxNeeds 公式NetまたはUSB Bluetoothの元選択を同じ署名済み閉包へ結ぶ検査。それ以外はnull
 * @return 全観測完了0。全体入力・読取・容量・改変・例外失敗ではHRESULTと空結果
 * @note 不正宣言と未評価の作用は元診断を保持する。全起点で1,024節訪問・4,096行・各4,096項目を共有し、一行を64値に制限する
 *       収集内容では一意な節名と用途を1,024、共通宣言と一意節の行を4,096に保つ
 *       延べ節訪問は2,048、実読取行は8,192、HKRバイナリ行の全値は128まで許容する
 *       固定元INFの公式範囲では全行確認済みレジストリ節の観測を起点別に再利用する
 *       SetupAPIが展開した値を読み、依存閉包の充足・署名・端末適合・導入許可は発行しない
 * @see docs/adr/0534-bounded-collection-inf-registry-inventory.md
 * @see docs/adr/0551-bounded-shared-inf-inventory-lines.md
 * @see docs/adr/0311-maintenance-inf-structure-and-install-policy-separation.md
 */
//------------------------------------------------------------------------------
NativeError inspectMaintenanceInfStructure(
	const OfficialDownloadWorkspace &workspace, const std::span<const OfficialZipEntry> entries,
	const std::wstring_view infRelativePath, const OfficialInfInspectionPolicy &policy,
	MaintenanceInfStructure &structure, const OfficialInfScopedModelsEvidence *scopedModels,
	const std::function<bool()> *cancellation, const ScopedInboxNeedsVerifier *inboxNeeds)
{
	structure = {} ;
	try {
		const std::wstring path = workspace.path( infRelativePath) ;	// 元INFの保護された読取位置
		const auto entry = std::ranges::find_if( entries, [infRelativePath]( const auto &item) {
			return stringsEqual( item.relativePath, infRelativePath) ;
		}) ; // 固定entryとの一意結合
		const bool invalidProvider = policy.acceptAnyProvider
										 ? !policy.acceptedProviders.empty()
										 : policy.acceptedProviders.empty() ;	// 矛盾policyを拒否
		// 一意の最大4 MiB INFと既存内容policyの有限範囲だけを受理する
		if( path.empty() || entries.empty() || entries.size() > 32'768U || entry == entries.end() ||
		   lowerExtension( infRelativePath) != L".inf" || entry->uncompressedSize == 0U ||
		   entry->uncompressedSize > 4U * 1024U * 1024U || policy.maximumHardwareIds == 0U ||
		   policy.maximumHardwareIds > 4096U || policy.maximumSourceFiles == 0U ||
		   policy.maximumSourceFiles > 8192U || policy.acceptedClasses.empty() ||
		   policy.acceptedSignatures.empty() || invalidProvider ||
		   std::ranges::count_if( entries, [infRelativePath]( const auto &item) {
			   return stringsEqual( item.relativePath, infRelativePath) ;
		   }) != 1) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		OfficialMappedFile original ;	// 公式範囲では元INFをHINFの終了まで固定する
		// 今回の検査に収集専用の証拠を適用できるかを保持します
		const bool		   collectionContent =
			policy.purpose == OfficialInfInspectionPurpose::COLLECTOR_CONTENT ;
		// 明示したModelsの証拠がある経路は、元INFを同ハッシュに結び付けます
		if( scopedModels) {
			// 収集用途・元INFの内容・Models行がそろわない証拠を拒否します
			if( !collectionContent || scopedModels->sections.empty() ||
			   !stringsEqual( entry->sha256, scopedModels->infSha256)) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// 元INFを上限付き読取り用に開いた際の診断値
			const auto openError = original.open( path, 4U * 1024U * 1024U) ;
			// 固定する原ファイルを開けなかった場合は後続の選択に進みません
			if( openError != 0) {
				return openError ;
			}
		}

		NativeError error = verifyOfficialFileMetadata(
			path, {entry->uncompressedSize, entry->sha256}) ;	// 元byte拘束
		// 不一致入力から部分構造を返さない
		if( error != 0) {
			return error ;
		}

		MaintenanceInfStructure inspected ;	// 全体成功時だけ出力へ移す保守専用型
		inspected.infRelativePath = infRelativePath ;
		error					  = computeFileSha256( path, inspected.infSha256) ;
		// 元hashを固定できない場合は構造観測へ進まない
		if( error != 0) {
			return error ;
		}

		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 読取handleはscopeが単独所有
		// 全体構文を開けない入力は空結果で診断値だけを返す
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		std::wstring signature ;	// INF構文識別子。CAT暗号署名とは別
		error = readInfDirective( inf.get(), L"Version", L"Signature", 1U, signature) ;
		// 未取得または内容policy外の構文識別子を補正しない
		if( error != 0 || !isAllowedValue( signature, policy.acceptedSignatures)) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		error = readInfDirective( inf.get(), L"Version", L"Class", 1U, inspected.className) ;
		// 必須Classの読取不能は全体失敗、未知Classの意味は後で個別未対応へ分離する
		if( error != 0) {
			return error ;
		}

		error = readInfDirective( inf.get(), L"Version", L"Provider", 1U, inspected.providerName) ;
		// Provider表示名を署名者や公式由来の証拠へ変換しない
		if( error != 0 || (!policy.acceptAnyProvider &&
						  !isAllowedValue( inspected.providerName, policy.acceptedProviders))) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		error = readInfDirective( inf.get(), L"Version", L"DriverVer", 1U, inspected.driverDate) ;
		// 必須日付の読取不能を欠損の正常値へ変換しない
		if( error != 0) {
			return error ;
		}

		error = readInfDirective( inf.get(), L"Version", L"DriverVer", 2U, inspected.driverVersion) ;
		// Versionを推測した候補identityへ使用しない
		if( error != 0) {
			return error ;
		}

		std::wstring catalog ;	// 既存CAT helperが返した現在architecture用file名
		error = readCatalogFile( inf.get(), catalog) ;
		// Root CATの必須宣言をnull構造でも省略しない
		if( error != 0) {
			return error ;
		}

		const std::size_t separator =
			// 元INFの安全な親区切り
			infRelativePath.find_last_of( L'\\') ;
		const std::wstring_view parent =
			separator == std::wstring_view::npos
				? std::wstring_view{}
				: infRelativePath.substr( 0U, separator) ;	// Package内親位置
		inspected.catalogRelativePath = joinRelativePath( parent, catalog) ;
		// CAT位置は固定entryとの存在だけを確認し、署名成功としない
		if( workspace.path( inspected.catalogRelativePath).empty() ||
		   !containsEntry( entries, inspected.catalogRelativePath)) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		// 対象範囲の全起点で共通の保守読取予算を使う
		MaintenanceStructureBudget			  budget{.collectionContent = collectionContent} ;
		std::vector<std::wstring>			  names ;		// 検査範囲に属する一意導入名
		std::optional<SP_ALTPLATFORM_INFO_V3> requested ;	// Models選択と同じ明示OS
		// 公式範囲のModelsがある場合は、同じ元行を現在の検査へ明示的に結び付けます
		if( scopedModels) {
			inspected.officialHardwareScope = true ;
			budget.modelSections			= scopedModels->sections ;
			budget.cancellation				= cancellation ;
			budget.sharedRegistryInf		= inf.get() ;
			// 宣言された対象OSがあるときはSetupAPIの明示観測点へ変換します
			if( scopedModels->platform) {
				requested = nativeModelsPlatform( *scopedModels->platform) ;
				// 明示OSを表現できない場合に端末の現在OSへ読み替えません
				if( !requested) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}
			}

			// 元の完全Hardware欄と結合した行だけを起点にする
			for( const auto &section : scopedModels->sections) {
				// 照合した節の全一致行を走査し、実際の導入名とHardware IDを記録します
				for( const auto &match : section.matches) {
					// 対象IDの予算を超えた行や安全に照合できない導入節を受け付けません
					if( inspected.hardwareIds.size() >= policy.maximumHardwareIds ||
					   !validInstallInventorySectionName( match.installBase)) {
						return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					inspected.hardwareIds.push_back( match.hardwareId) ;
					static_cast<void>( appendUnique( names, match.installBase)) ;
				}
			}

			// 検証に使える実導入節を一つも得られない証拠を拒否します
			if( names.empty()) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// 全対象がPCIのNetである場合だけ、限定Netとして媒体と効果を検査します
			if( stringsEqual( inspected.className, NET_CLASS.front()) &&
			   std::ranges::all_of( inspected.hardwareIds, []( const auto &id) {
				   return stringsEqual( std::wstring_view( id).substr( 0U, 4U), L"PCI\\") ;
			   })) {
				error = validateSetupClassPair( inf.get(), NET_CLASS) ;
				// 明示選択の解析失敗を全端末向けの解析結果で補いません
				if( error != 0) {
					return error ;
				}

				budget.scopedPciNet = true ;
			}

			// 公式に固定したUSB対象のみに、同じNetクラスの元属性とサービスを接続します
			if( collectionContent && stringsEqual( inspected.className, NET_CLASS.front()) &&
			   std::ranges::all_of( inspected.hardwareIds, []( const auto &id) {
				   return stringsEqual( std::wstring_view{id}.substr( 0U, 8U), L"USB\\VID_") ;
			   })) {
				error = validateSetupClassPair( inf.get(), NET_CLASS) ;
				// Windowsの元クラスが曖昧ならUSB向けの棚卸しを開始しません
				if( error != 0U) {
					return error ;
				}

				budget.scopedUsbNet = true ;
			}
		} else {
			error = collectMaintenanceInstallNames( inf.get(), budget, names) ;
			// 構造の検査が成功した場合だけ、元INFの後続照合を実行します
			if( error == 0) {
				error =
					collectHardwareIds( inf.get(), policy.maximumHardwareIds, inspected.hardwareIds) ;
			}

			// 公式範囲の元作用を確定できなかったときは原診断を返します
			if( error != 0) {
				return error ;
			}
		}

		LONG versionCount{} ;	// Version節の確定行数
		error = maintenanceLineCount( inf.get(), L"Version", versionCount) ;
		// 必須Versionの不在・容量・API失敗を正常な終端へ変換しない
		if( error != 0 || versionCount <= 0 || versionCount > 4096L) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 選択queue外のVersionも全行予算へ含め、LayoutFileを見落とさない
		for( LONG row = 0L; row < versionCount; ++row) {
			INFCONTEXT version{} ;	// Versionの現在行
			error = maintenanceLineAt( inf.get(), L"Version", row, version) ;
			// 全Version行が読めなければ部分観測を返さない
			if( error != 0) {
				return error ;
			}

			// Versionの過大入力を部分走査に切り詰めない
			if( ++budget.lines > MAXIMUM_INSTALL_INVENTORY_LINES) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::wstring key ;	// この行のVersion directive
			error = readMaintenanceField( version, 0U, key) ;
			// Version行の読取不能を見逃さない
			if( error != 0 || SetupGetFieldCount( &version) > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			// LayoutFileの参照を名前だけでinbox署名済みへ認定しない
			if( stringsEqual( key, L"LayoutFile")) {
				// 明示された各参照を未検査用途として保持する
				for( DWORD field = 1U; field <= SetupGetFieldCount( &version); ++field) {
					std::wstring target ;	// LayoutFileの原明示参照
					error = readMaintenanceField( version, field, target) ;
					// 読取不能参照を空用途へ変換しない
					if( error != 0) {
						return error ;
					}

					inspected.fileUses.push_back( {L"Version", key, std::move( target)}) ;
					// Versionの多値参照も保持量上限を回避させない
					if( inspected.fileUses.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
						return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
					}
				}
			}
		}

		const wchar_t *sourceSection = L"SourceDisksFiles.amd64" ;	// 現architectureを先に観測する
		LONG		   sourceCount{} ;								// 不在と空節を区別
		error = maintenanceLineCount( inf.get(), sourceSection, sourceCount) ;
		// source API失敗をsource不在へ変換しない
		if( error != 0) {
			return error ;
		}

		// Architecture固有節がない場合だけ共通節を観測する
		if( sourceCount < 0) {
			sourceSection = L"SourceDisksFiles" ;
			error		  = maintenanceLineCount( inf.get(), sourceSection, sourceCount) ;
			// 共通sourceのAPI失敗も不在へ弱めない
			if( error != 0) {
				return error ;
			}
		}

		inspected.sourceSectionPresent = sourceCount >= 0 ;
		// 非空source宣言は構造として読み、位置解決は後続の閉包検査へ残す
		if( sourceCount > 0) {
			// 過大source節を部分空集合へ変換しない
			if( static_cast<std::size_t>( sourceCount) >
			   MAXIMUM_INSTALL_INVENTORY_LINES - budget.lines) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			// 全source宣言を有限に観測する。SYS不在だけでnullやinboxを認定しない
			for( LONG row = 0L; row < sourceCount; ++row) {
				INFCONTEXT source{} ;	// Source宣言の現在行
				error = maintenanceLineAt( inf.get(), sourceSection, row, source) ;
				// source行の途中失敗で空閉包を作らない
				if( error != 0) {
					return error ;
				}

				++budget.lines ;
				std::wstring name ;	// 参照宣言のfile名
				error = readInfField( source, 0U, name) ;
				// File名を安全なpackage相対位置に限定し、実byte不在はまだ評価しない
				if( error != 0 || name.find_first_of( L"/\\") != std::wstring::npos ||
				   workspace.path( joinRelativePath( parent, name)).empty()) {
					return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				// Source集合がpolicy上限を超える場合は元宣言を切り捨てない
				if( appendUnique( inspected.sourceFileNames, std::move( name)) &&
				   inspected.sourceFileNames.size() > policy.maximumSourceFiles) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}
			}
		}

		// 共通宣言は全行を一意行の上限へ加える
		budget.distinctLines = budget.lines ;
		budget.fileUses		 = inspected.fileUses.size() ;
		inspected.parser	 = {MaintenanceInspectionState::PASSED, 0} ;
		// 検査範囲の全一意導入名を分母へ残す
		for( const std::wstring &name : names) {
			MaintenanceInfInstallStructure install ;	// 一選択の所有観測
			install.inventory.infRelativePath	 = inspected.infRelativePath ;
			install.inventory.infSha256			 = inspected.infSha256 ;
			install.inventory.baseInstallSection = name ;
			error								 = resolveActualInstallInventorySection(
				   inf.get(), name, install.inventory.selectedInstallSection,
				   requested ? reinterpret_cast<PSP_ALTPLATFORM_INFO>( &*requested) : nullptr) ;
			// 明示範囲の必須関係を検証できない候補を収集結果へ残しません
			if( scopedModels && error != 0) {
				return error ;
			}

			// 実在選択の欠落は不正構造の個別行として残し、他の選択を削除しない
			if( error != 0) {
				install.parser = {MaintenanceInspectionState::FAILED, error} ;
			} else {
				error = inspectMaintenanceInstallStructure( inf.get(), workspace, entries, parent,
														   budget, install) ;
				// 容量・全体読取・不正参照の失敗では部分構造を破棄する
				if( error != 0) {
					return error ;
				}
			}

			// 未知Classは具体的理由を各選択へ保持し、導入Class表を広げない
			if( !isAllowedValue( inspected.className, policy.acceptedClasses)) {
				addMaintenanceIssue( install, L"Version", L"Class",
									MaintenanceInfStructureReason::CLASS_NOT_SUPPORTED,
									{MaintenanceInspectionState::UNSUPPORTED,
									 nativeErrorFromWin32( ERROR_NOT_SUPPORTED)}) ;
				// Class診断も全INFの独立保持予算へ加える
				if( ++budget.issues > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}
			}

			// Source宣言を持つnullはfile構造との併存へ残し、無参照としない
			if( !inspected.sourceFileNames.empty() || !inspected.fileUses.empty()) {
				install.contentKind =
					install.contentKind == MaintenanceInfContentKind::NULL_DRIVER ||
							install.contentKind == MaintenanceInfContentKind::MIXED
						? MaintenanceInfContentKind::MIXED
						: MaintenanceInfContentKind::PACKAGE_FILES ;
			}

			mergeMaintenanceFinding( inspected.parser, install.parser) ;
			// 異なる選択構造をMIXEDとし、UNKNOWNを先頭成功で隠さない
			if( inspected.installs.empty()) {
				inspected.contentKind = install.contentKind ;
			}
			// 後続の異なる構造も分母へ残し、先頭構造で全INFを確定しない
			else if( inspected.contentKind != install.contentKind) {
				inspected.contentKind = MaintenanceInfContentKind::MIXED ;
			}

			// 明示依存の各宣言を数え、由来・byte・署名・全到達節は未照会に残す
			bool requiresInboxProof{} ;	// 元INFの外へ到達するNeedsを検査する必要がある場合trueです
			// 局所欠落を同梱依存と混同せず、元選択の全参照を保持する
			for( const auto &reference : install.inventory.references) {
				// 同じINF内に無い節は、公式範囲で独立した充足証拠が必要です
				if( scopedModels && !reference.targetPresent &&
				   reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION) {
					// 同じ閉包の証拠を検査できるNeedsだけを後段へ渡す
					if( !inboxNeeds || !*inboxNeeds ||
					   !stringsEqual( reference.directive, L"Needs")) {
						return nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND) ;
					}

					requiresInboxProof = true ;
				}

				// 同節Include／Needs／AddComponentの明示辺だけを依存summaryへ射影する
				if( reference.kind == OfficialInfInstallReferenceKind::INCLUDE_INF ||
				   stringsEqual( reference.directive, L"Needs") ||
				   stringsEqual( reference.directive, L"AddComponent")) {
					++inspected.dependency.observedReferenceCount ;
					inspected.dependency.state = MaintenanceInfDependencyState::OBSERVED ;
				}
			}

			// missing Needsが同じ元選択から検査済みWindows INFへ解決することを一度確認する
			if( requiresInboxProof) {
				error = (*inboxNeeds)( install.inventory) ;
				// 同梱側の署名、作用又は参照不成立を局所棚卸しで補わない
				if( error != 0U) {
					return error ;
				}

				install.wifiBusNeedsVerified = stringsEqual( inspected.className, NET_CLASS.front()) ;
			}

			inspected.installs.push_back( std::move( install)) ;
		}

		error = verifyOfficialFileMetadata( path, {entry->uncompressedSize, inspected.infSha256}) ;
		// 元byte改変と全体失敗では独立署名未検査の部分構造を公開しない
		if( error != 0) {
			return error ;
		}

		// 取消しが入った収集からは、全到達を終えていても新しい証拠を返しません
		if( scopedModels && cancellation && *cancellation && (*cancellation)()) {
			return nativeErrorFromWin32( ERROR_CANCELLED) ;
		}

		structure = std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 現OSのModelsに属する導入名とその作用・参照を実行せず棚卸しする
 * @param[in] workspace 同期借用する保護領域。呼出し中の変更は禁止する
 * @param[in] entries 有限の元package一覧。対象INFは一意で実size一致を要求する
 * @param[in] infRelativePath 最大4 MiBの一INFの安全な相対path
 * @param[in] baseInstallSection 現OS用Modelsの第1 fieldと一致する最大254文字の導入名
 * @param[out] inventory 全観測と元byte再照合に成功した場合のみ保持し、失敗時は空
 * @return 有限棚卸し成功0、入力・選択・容量・改変・SetupAPI失敗のHRESULT
 * @note worker内でblockingする。署名・端末適合・依存充足・導入作用の許可を発行しない。最大1,024節・4,096行・作用4,096・参照4,096・一行64 field。別
 *       INFを開かず通常作用拒否を変更しない
 * @see docs/adr/0264-selected-inf-install-inventory.md
 * @see docs/adr/0266-selected-inf-inventory-capacity-expansion.md
 * @see docs/adr/0268-selected-inf-reference-context-and-coverage.md
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialInfInstallInventory( const OfficialDownloadWorkspace		  &workspace,
											   const std::span<const OfficialZipEntry> entries,
											   const std::wstring_view		infRelativePath,
											   const std::wstring_view		baseInstallSection,
											   OfficialInfInstallInventory &inventory)
{
	inventory = {} ;
	try {
		const std::wstring path = workspace.path( infRelativePath) ;	// 保護領域内だけのINF読取位置
		const auto		   entry =
			std::ranges::find_if( entries, [infRelativePath]( const OfficialZipEntry &item) {
				return stringsEqual( item.relativePath, infRelativePath) ;
			}) ; // 呼出し元の有限inventoryと対象INFを結合する
		// 一意の有限INFとModels用の導入名だけを受け取る
		if( path.empty() || entries.size() > 32'768U || entry == entries.end() ||
		   entry->uncompressedSize == 0U || entry->uncompressedSize > 4U * 1024U * 1024U ||
		   lowerExtension( infRelativePath) != L".inf" ||
		   !validInstallInventorySectionName( baseInstallSection) ||
		   std::ranges::count_if( entries, [infRelativePath]( const OfficialZipEntry &item) {
			   return stringsEqual( item.relativePath, infRelativePath) ;
		   }) != 1) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		NativeError error = verifyOfficialFileMetadata(
			path, {entry->uncompressedSize, entry->sha256}) ;	// 実size一致を先に要求する
		// 入力metadata不一致のbyteを解析しない
		if( error != 0) {
			return error ;
		}

		OfficialInfInstallInventory inspected ;	// 全成功時だけ出力へ移す独立した観測型
		error = computeFileSha256( path, inspected.infSha256) ;
		// CAT署名ではない元byte結合にも失敗した場合は停止する
		if( error != 0) {
			return error ;
		}

		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 無cacheの読取専用handle
		// INF構文読取失敗を元の診断値で返す
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		std::wstring signature ;	// 構文識別子だけ。暗号署名ではない
		error = readInfDirective( inf.get(), L"Version", L"Signature", 1U, signature) ;
		// 標準二構文以外の値を正規化して受理しない
		if( error != 0 ||
		   (!stringsEqual( signature, L"$Windows NT$") && !stringsEqual( signature, L"$Chicago$"))) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		inspected.infRelativePath	 = infRelativePath ;
		inspected.baseInstallSection = baseInstallSection ;
		error = selectInstallInventorySection( inf.get(), inspected.baseInstallSection,
											  inspected.selectedInstallSection) ;
		// 未登録・未実在・対象外を空の正常結果へ変換しない
		if( error != 0) {
			return error ;
		}

		std::vector<InstallInventorySection> pending{
			{inspected.selectedInstallSection,
			 InstallInventorySectionKind::DIRECTIVES}} ;	// 一度だけ処理する到達graph
		constexpr std::array<std::wstring_view, 9>
			suffixes{L".HW",
					 L".Services",
					 L".CoInstallers",
					 L".Interfaces",
					 L".Components",
					 L".Software",
					 L".Wdf",
					 L".Events",
					 L".LogConfigOverride"} ;	// 今回解釈する既知の付随節
		// 選択DDInstallと完全一致する付随節だけを走査する
		for( const auto suffix : suffixes) {
			const std::wstring name =
				inspected.selectedInstallSection + std::wstring( suffix) ;	// 実sectionの付随名
			const LONG lineCount =
				// 不在と空節を区別する
				SetupGetLineCountW( inf.get(), name.c_str()) ;
			// 不在の任意付随節は参照欠落ではなく対象なし
			if( lineCount < 0) {
				continue ;
			}

			pending.push_back( {name, InstallInventorySectionKind::DIRECTIVES}) ;
			// 非空CoInstaller節の宣言は作用なしとしない
			if( stringsEqual( suffix, L".CoInstallers") && lineCount > 0) {
				inspected.effects.push_back(
					{name, L"CoInstallers", OfficialInfInstallEffectKind::COINSTALLER}) ;
			}
		}

		const std::size_t separator = infRelativePath.find_last_of( L'\\') ;	// 安全なINF親の区切り
		const std::wstring_view parent =
			separator == std::wstring_view::npos
				? std::wstring_view{}
				: infRelativePath.substr( 0, separator) ;	// 元INFと同じ親以下だけのfile参照
		// 動的に増える有限queueを順に処理し、循環でも既存節を再走査しない
		for( std::size_t index = 0; index < pending.size(); ++index) {
			const InstallInventorySection current =
				pending[index] ;	// Queue再確保の影響を受けない所有copy
			inspected.visitedSections.push_back( current.name) ;
			const LONG lineCount =
				// 現在節の全行数
				SetupGetLineCountW( inf.get(), current.name.c_str()) ;
			// 累積上限を先に確認し、過大節を部分列挙しない
			if( lineCount < 0 || static_cast<std::size_t>( lineCount) >
									MAXIMUM_INSTALL_INVENTORY_LINES - inspected.scannedLines) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			INFCONTEXT line{} ;	// 現在節の行context
			// 明示空節には行読取が不要だが、非空節の取得失敗は拒否する
			if( lineCount == 0) {
				continue ;
			}

			// 非空data・registry本文を完全解釈したという誤認を防ぐ
			if( current.kind != InstallInventorySectionKind::DIRECTIVES) {
				inspected.coverageGaps.push_back(
					{current.name,
					 {},
					 current.kind == InstallInventorySectionKind::REGISTRY
						 ? OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED
						 : OfficialInfInstallCoverageKind::DATA_ROWS_NOT_INTERPRETED}) ;
			}

			// 不正な先頭行を読み飛ばさない
			if( SetupFindFirstLineW( inf.get(), current.name.c_str(), nullptr, &line) == FALSE) {
				return nativeErrorFromWin32( GetLastError()) ;
			}

			// 観測した全行を有限fieldへ読み、途中終了で成功にしない
			for( LONG row = 0; row < lineCount; ++row) {
				++inspected.scannedLines ;
				const DWORD fields = SetupGetFieldCount( &line) ;	// Keyを除く値数
				// 過大field集合を走査しない
				if( fields > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}

				std::vector<std::wstring> values ;	// この行だけの値。結果へ本文を保持しない
				// 空値を含め、全fieldの上限を確認する
				for( DWORD field = 1U; field <= fields; ++field) {
					std::wstring value ;	// 個別の有限受信値
					error = readInstallInventoryField( line, field, value) ;
					// 過長・展開失敗を未知の正常値として隠さない
					if( error != 0) {
						return error ;
					}

					values.push_back( std::move( value)) ;
				}

				// Registry行の宣言種類だけを観測し、値やcommand本文は保持しない
				if( current.kind == InstallInventorySectionKind::REGISTRY) {
					// Registry行のroot・subkeyが欠ける不正入力を拒否する
					if( values.size() < 2U) {
						return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					// CoInstaller値名を普通のregistry宣言へ読み替えない
					if( values.size() >= 3U && stringsEqual( values[2], L"CoInstallers32")) {
						inspected.effects.push_back( {current.name, L"CoInstallers32",
													 OfficialInfInstallEffectKind::COINSTALLER}) ;
					}

					std::wstring subkey = values[1] ;	// 比較中だけ保持するregistry位置
					std::transform( subkey.begin(), subkey.end(), subkey.begin(),
								   []( wchar_t character) {
									   return character >= L'A' && character <= L'Z'
												  ? static_cast<wchar_t>( character - L'A' + L'a')
												  : character ;
								   }) ; // ASCIIの既知registry位置だけを比較する
					// 自動起動位置の宣言は実行の観測ではなく独立の要確認種類とする
					if( subkey.find( L"\\currentversion\\run") != std::wstring::npos) {
						inspected.effects.push_back(
							{current.name, L"RegistryAutorun",
							 OfficialInfInstallEffectKind::REGISTRY_AUTORUN}) ;
					}
				}
				// 処理節だけをdirectiveとして解釈し、不透明data行へ同じ規則を適用しない
				else if( current.kind == InstallInventorySectionKind::DIRECTIVES) {
					std::wstring key ;	// この行のdirective名だけを保持する
					error = readInstallInventoryField( line, 0U, key) ;
					// Keyを持たない不正行を既知directiveへ読み替えない
					if( error != 0 || key.empty()) {
						return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					inspected.effects.push_back(
						{current.name, key, installInventoryEffectKind( key)}) ;
					const auto gap =
						// 一宣言の解析不足
						installInventoryCoverageKind( key, values) ;
					// 本文を保存せず、不足を元節とdirectiveへ結合する
					if( gap.has_value()) {
						inspected.coverageGaps.push_back( {current.name, key, *gap}) ;
					}

					InstallInventorySectionKind targetKind =
						InstallInventorySectionKind::DATA_ROWS ;	// Data節は再解釈しない
					OfficialInfInstallReferenceKind referenceKind =
						OfficialInfInstallReferenceKind::LOCAL_SECTION ;	// 同INF参照が既定
					std::size_t start{} ;									// 参照値の先頭index。後で処理するdirectiveだけが有効
					bool		references = false ;						// このdirectiveに既知の参照形式がある場合true
					// Registry節はdirective節と区別して辿る
					if( stringsEqual( key, L"AddReg") || stringsEqual( key, L"DelReg")) {
						targetKind = InstallInventorySectionKind::REGISTRY ;
						references = true ;
					}
					// 別INFの存在だけを記録し、同じINF内の処理節として開かない
					else if( stringsEqual( key, L"Include") || stringsEqual( key, L"CopyINF")) {
						referenceKind = stringsEqual( key, L"Include")
											? OfficialInfInstallReferenceKind::INCLUDE_INF
											: OfficialInfInstallReferenceKind::COPY_INF ;
						references	  = true ;
					}
					// Needsのローカル存在と外部依存の未確認を分離する
					else if( stringsEqual( key, L"Needs")) {
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
						references = true ;
					}
					// Service等の指定第3 fieldだけを処理節参照にする
					else if( stringsEqual( key, L"AddService") ||
							stringsEqual( key, L"AddInterface") ||
							stringsEqual( key, L"AddComponent") ||
							stringsEqual( key, L"AddSoftware")) {
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
						start	   = 2U ;
						references = true ;
					}
					// WDF宣言では指定第2 fieldだけを処理節参照にする
					else if( stringsEqual( key, L"KmdfService") ||
							stringsEqual( key, L"UmdfService")) {
						targetKind = InstallInventorySectionKind::DIRECTIVES ;
						start	   = 1U ;
						references = true ;
					}
					// File・登録・commandのdata節は有限に読むが本文を解釈・保持しない
					else if( stringsEqual( key, L"CopyFiles") || stringsEqual( key, L"DelFiles") ||
							stringsEqual( key, L"RenFiles") || stringsEqual( key, L"BitReg") ||
							stringsEqual( key, L"RegisterDlls") ||
							stringsEqual( key, L"UnregisterDlls") ||
							stringsEqual( key, L"RunPreSetupCommands") ||
							stringsEqual( key, L"RunPostSetupCommands")) {
						references = true ;
					}

					// 必須参照fieldがない場合は不正宣言として拒否する
					if( references && values.size() <= start) {
						return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					// 参照形式が既知のdirectiveだけを有限に辿る
					for( std::size_t field = start; references && field < values.size(); ++field) {
						std::wstring target = values[field] ;	// 個別の参照名だけを結果へ保持する
						OfficialInfInstallReferenceKind kind =
							referenceKind ;	// 直接fileである場合のみ変更する
						// CopyFilesの直接file記法はsectionではない
						if( stringsEqual( key, L"CopyFiles") && target.starts_with( L"@")) {
							target.erase( 0U, 1U) ;
							kind = OfficialInfInstallReferenceKind::DIRECT_FILE ;
						}

						bool present = false ;	// ローカル存在だけで、実byte・依存充足ではない
						// File参照はpackage境界へ結合し、別INFを開かない
						if( kind != OfficialInfInstallReferenceKind::LOCAL_SECTION) {
							const std::wstring_view child =
								// 元の参照名を借用する
								stripReferenceCurrentDirectory( target) ;
							// 空参照をINF親directoryの参照として保持しない
							if( child.empty()) {
								return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
							}

							target = joinRelativePath( parent, child) ;
							// 不正pathとINFではないInclude／CopyINFを拒否する
							if( workspace.path( target).empty() ||
							   (kind != OfficialInfInstallReferenceKind::DIRECT_FILE &&
								lowerExtension( target) != L".inf")) {
								return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
							}

							present = containsEntry( entries, target) ;
						} else {
							// 過長・path的参照をsection名として採用しない
							if( !validInstallInventorySectionName( target)) {
								return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
							}

							present = SetupGetLineCountW( inf.get(), target.c_str()) >= 0 ;
							// 欠落参照は保持するが、他のsectionから推測補完しない
							if( present) {
								error = queueInstallInventorySection( pending, target, targetKind) ;
								// Queue容量と矛盾した節解釈は部分結果を破棄する
								if( error != 0) {
									return error ;
								}
							}
						}

						inspected.references.push_back( {current.name, key, target, kind, present}) ;
						// 確保量を固定上限へ拘束する
						if( inspected.references.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
							return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
						}

						// Service等は指定field一つだけがsection参照で、後続flagは辿らない
						if( start > 0U) {
							break ;
						}
					}
				}

				// Registry検出を含む全宣言数を固定上限へ拘束する
				if( inspected.effects.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS ||
				   inspected.coverageGaps.size() > MAXIMUM_INSTALL_INVENTORY_LINES) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}

				// 確定行数の途中で走査が終わった場合は成功にしない
				if( row + 1 < lineCount && SetupFindNextLine( &line, &line) == FALSE) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}
			}
		}

		error = verifyOfficialFileMetadata( path, {entry->uncompressedSize, inspected.infSha256}) ;
		// 解析後の元byte不一致では部分観測を公開しない
		if( error != 0) {
			return error ;
		}

		inventory = std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 実行せずに保守用の全sourceとCopyINFを列挙する
 * @param[in] workspace INF実byteを所有する同期借用の保護領域
 * @param[in] entries 検証済み元archive metadata。未取得sourceを含められる
 * @param[in] infRelativePath 読取済みINFの安全な相対path
 * @param[out] inventory 成功時だけ参照集合を保持し、失敗時は到達stage以外を空にする
 * @return 棚卸し成功時0、最初の構文・path・容量違反のHRESULT
 * @note PnP IDを保持せず、署名・用途・適用性・導入を承認しない。Version構文識別子は$Windows NT$と$Chicago$を受理する。暗号署名の代わりにしない
 *       BlockingするためUI threadで呼ばない。CopyINFの再帰と実byte検証は呼出し側が必要。媒体・source subdir・CopyINFの先頭現在directory表記だけを
 *       除き、残りは既存path境界で検証する
 * @see docs/adr/0244-maintenance-inf-reference-inventory.md
 * @see docs/adr/0246-maintenance-relative-references-and-direct-content.md
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialInfReferences( const OfficialDownloadWorkspace		&workspace,
										 const std::span<const OfficialZipEntry> entries,
										 const std::wstring_view				 infRelativePath,
										 OfficialInfReferenceInventory			&inventory)
{
	inventory = {} ;
	OfficialInfReferenceInventory inspected ;	// 非合格の保守参照集合
	// 失敗時は参照集合を公開せず、到達段階だけを残す同期callback
	const auto					  fail = [&inventory, &inspected]( const NativeError error) {
		   inventory	   = {} ;
		   inventory.stage = inspected.stage ;
		   return error ;
	} ;
	try {
		const std::wstring absolutePath = workspace.path( infRelativePath) ;	// 保護領域内の読取位置
		const auto		   original =
			std::ranges::find_if( entries, [infRelativePath]( const OfficialZipEntry &entry) {
				return stringsEqual( entry.relativePath, infRelativePath) ;
			}) ; // 元inventoryの同一INFだけを対象にする
		// 入力境界とINF上限を検証する
		if( absolutePath.empty() || entries.size() > 32'768U || original == entries.end() ||
		   original->uncompressedSize > 4U * 1024U * 1024U ||
		   lowerExtension( infRelativePath) != L".inf") {
			return fail( static_cast<NativeError>( E_INVALIDARG)) ;
		}

		const UniqueInf inf( SetupOpenInfFileW( absolutePath.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 実行せずに構文だけを読む
		// 構文読取失敗をそのまま残す
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return fail( nativeErrorFromWin32( GetLastError())) ;
		}

		inspected.stage = OfficialInfReferenceStage::VERSION ;
		std::wstring signature ;	// Version節の宣言値。CAT署名ではない
		NativeError	 error =
			// 読取結果
			readInfDirective( inf.get(), L"Version", L"Signature", 1, signature) ;
		// 未知signatureを推測しない
		if( error != 0 ||
		   (!stringsEqual( signature, L"$Windows NT$") && !stringsEqual( signature, L"$Chicago$"))) {
			return fail( error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
		}

		error = readInfDirective( inf.get(), L"Version", L"Class", 1, inspected.className) ;
		// Class欠落を正常な未知classへ変換しない
		if( error != 0) {
			return fail( error) ;
		}

		std::wstring catalog ;	// Directoryを含まないCAT名
		error = readCatalogFile( inf.get(), catalog) ;
		// 対応CATを推測しない
		if( error != 0) {
			return fail( error) ;
		}

		const std::size_t		slash  = infRelativePath.find_last_of( L"/\\") ;	// 元INFの親区切り
		const std::wstring_view parent = slash == std::wstring_view::npos
											 ? std::wstring_view{}
											 : infRelativePath.substr( 0, slash) ;	// 安全な親相対位置
		inspected.infRelativePath	   = infRelativePath ;
		inspected.catalogRelativePath  = joinRelativePath( parent, catalog) ;
		// 元CAT metadataを必須にする
		if( workspace.path( inspected.catalogRelativePath).empty() ||
		   !containsEntry( entries, inspected.catalogRelativePath)) {
			return fail( nativeErrorFromWin32( ERROR_FILE_NOT_FOUND)) ;
		}

		inspected.stage = OfficialInfReferenceStage::SOURCES ;
		constexpr std::array SOURCE_SECTIONS{L"SourceDisksFiles.amd64",
											 L"SourceDisksFiles"} ;	// 保守用和集合
		// 共通節の追加fileも省略しない
		for( const wchar_t *const section : SOURCE_SECTIONS) {
			const LONG lineCount = SetupGetLineCountW( inf.get(), section) ;	// 節の存在と行数
			// 重複行を含むsource節そのものにも有限上限を設ける
			if( lineCount > 8'192L) {
				return fail( nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)) ;
			}

			// 不在以外のAPI失敗を拒否する
			if( lineCount == -1 && GetLastError() != ERROR_SECTION_NOT_FOUND) {
				return fail( nativeErrorFromWin32( GetLastError())) ;
			}

			// 存在しない節と空節はsource参照を持たない
			if( lineCount <= 0) {
				continue ;
			}

			std::vector<std::wstring> sectionFiles ;	// 現在節だけの有限参照集合
			error = collectSourceFiles( inf.get(), workspace, entries, parent, 8'192U, false,
									   sectionFiles, section) ;
			// 欠落sourceを部分棚卸し合格へ変換しない
			if( error != 0) {
				return fail( error) ;
			}

			// architecture優先解決した重複参照を一意にする
			for( std::wstring &path : sectionFiles) {
				// 和集合の上限も維持する
				if( appendUnique( inspected.sourceFiles, std::move( path)) &&
				   inspected.sourceFiles.size() > 8'192U) {
					return fail( nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)) ;
				}
			}
		}

		inspected.stage = OfficialInfReferenceStage::DEPENDENCIES ;
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U>
			 sectionBuffer{} ;	// 全section名受信領域
		bool ended{} ;			// SetupAPIの正常終端を確認した場合だけtrue
		// 全sectionを有限走査する
		for( std::size_t index = 0; index < MAXIMUM_INF_SECTIONS; ++index) {
			// 正常終端と失敗を区別する
			if( SetupEnumInfSectionsW( inf.get(), static_cast<UINT>( index), sectionBuffer.data(),
									 static_cast<UINT>( sectionBuffer.size()), nullptr) == FALSE) {
				// 部分列挙を合格にしない
				if( GetLastError() != ERROR_NO_MORE_ITEMS) {
					return fail( nativeErrorFromWin32( GetLastError())) ;
				}

				ended = true ;
				break ;
			}

			INFCONTEXT line{} ;	// 現在sectionのline
			// 空節を飛ばす
			if( SetupFindFirstLineW( inf.get(), sectionBuffer.data(), nullptr, &line) == FALSE) {
				continue ;
			}

			// 生line本文やPnP IDを出力せず、依存keyだけを読む
			do {
				std::wstring key ;				// 現在lineのkey。Keyなし行は対象外
				DWORD		 keyCharacters{} ;	// Keyなし行と過長keyを分ける必要文字数
				SetLastError( ERROR_SUCCESS) ;
				// Keyなしの一覧行を依存directiveとして解析しない
				if( SetupGetStringFieldW( &line, 0, nullptr, 0, &keyCharacters) == FALSE &&
				   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
					continue ;
				}

				// 空の先頭fieldはkeyなし行であり、CopyINFの空valueとは区別する
				if( keyCharacters <= 1U) {
					continue ;
				}

				// 過長keyをkeyなし行へ変換しない
				if( keyCharacters > MAXIMUM_INF_FIELD_CHARACTERS) {
					return fail( nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
				}

				const NativeError keyError = readInfField( line, 0, key) ;	// 有限keyの取得結果
				// 確保失敗や有限keyの受信失敗を省略しない
				if( keyError != 0) {
					return fail( keyError) ;
				}

				// 存在だけを保持し、依存充足としない
				if( stringsEqual( key, L"Include") || stringsEqual( key, L"Needs") ||
				   stringsEqual( key, L"AddComponent")) {
					inspected.hasExternalDependencies = true ;
				}

				// CopyINF以外の文字列をpathへ変換しない
				if( !stringsEqual( key, L"CopyINF")) {
					continue ;
				}

				const DWORD fields = SetupGetFieldCount( &line) ;	// CopyINFの一行参照数
				// 無限fieldや空依存を拒否する
				if( fields == 0 || fields > 1'024U) {
					return fail( nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
				}

				// Strings展開済みの各参照を検査する
				for( DWORD field = 1; field <= fields; ++field) {
					std::wstring child ;	// 子INFへの相対参照
					const bool	 atOptionalEnd =
						field > 1U && field == fields ;	// 先行参照に続く最後のフィールドか
					error = atOptionalEnd ? readInstallInventoryField( line, field, child)
										  : readInfField( line, field, child) ;
					// 先行参照を読み終えた後の末尾空フィールドはファイル名を表さない
					if( error == 0 && atOptionalEnd && child.empty()) {
						continue ;
					}

					// 保守参照だけの先頭現在directoryを解決し、他の危険要素は残す
					if( error == 0) {
						child = std::wstring( stripReferenceCurrentDirectory( child)) ;
					}

					// 未展開・絶対・非INFを拒否する
					if( error != 0 || child.find( L'%') != std::wstring::npos || child.empty() ||
					   child.front() == L'\\' || child.front() == L'/' ||
					   lowerExtension( child) != L".inf") {
						return fail( error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
					}

					std::wstring relative = joinRelativePath( parent, child) ;	// 同じ親以下の参照
					// traversal等を既存workspace境界で拒否する
					if( workspace.path( relative).empty()) {
						return fail( nativeErrorFromWin32( ERROR_INVALID_DATA)) ;
					}

					// 全section合計の参照数を制限する
					if( appendUnique( inspected.copyInfPaths, std::move( relative)) &&
					   inspected.copyInfPaths.size() > 1'024U) {
						return fail( nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW)) ;
					}
				}
			} while( SetupFindNextLine( &line, &line) != FALSE) ;
		}

		// Section上限到達を正常終端へ変換しない
		if( !ended) {
			return fail( nativeErrorFromWin32( ERROR_TOO_MANY_NAMES)) ;
		}

		bool actionDependencies{} ;	// 既存導入検査の中途観測は棚卸しの全走査結果に代用しない
		inspected.installActionsError =
			validateInfInstallActions( inf.get(), true, actionDependencies) ;
		inspected.stage = OfficialInfReferenceStage::INVENTORIED ;
		inventory		= std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) { // 確保失敗時も部分参照を公開しない
		return fail( static_cast<NativeError>( E_OUTOFMEMORY)) ;
	}
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
namespace {
//------------------------------------------------------------------------------
/**
 * @brief 同service-install節の一意な必須一値を既存INF readerで読みます
 * @param[in] inf 同期中だけ借用する元INF handleです
 * @param[in] section named service-install節の実名です
 * @param[in] key 同節の必須directiveです
 * @param[out] value 成功時だけ元一値を保持し、失敗時は空です
 * @return 読取成功0、欠損・多値・重複の元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError readRequiredServiceField( HINF inf, const std::wstring &section, const wchar_t *key,
									 std::wstring &value)
{
	value.clear() ;
	INFCONTEXT line{} ;	// 同HINFの必須行を一度だけ借用します
	// 一意一値を持たない必須項目を先頭値で補完しません
	if( !SetupFindFirstLineW( inf, section.c_str(), key, &line) || SetupGetFieldCount( &line) != 1U) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const auto error = readInfField( line, 1U, value) ;	// 既存の有限・展開済みfield読取です
	INFCONTEXT duplicate{} ;							// 同keyの二行目を採用しません
	// 相反する重複必須行から都合のよい一値を選びません
	if( error != 0 || SetupFindNextMatchLineW( &line, key, &duplicate)) {
		value.clear() ;
		return error != 0 ? error : nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief INFの指定節から一意な必須値を32ビットの符号なし整数として読み取ります
 * @param[in] inf 同期呼び出し中だけ借用する有効なINFハンドルです
 * @param[in] section 必須値を探す元INFの節名です
 * @param[in] key 必須の数値ディレクティブ名です。null不可の終端付き文字列です
 * @param[out] value 成功時に数値を格納し、失敗時は呼び出し前の値を保持します
 * @return 成功時は0、欠落・重複・解釈できない値ではHRESULTです
 * @throws std::bad_alloc 展開済みの文字列を保持するメモリを確保できない場合です
 */
//------------------------------------------------------------------------------
NativeError readRequiredServiceScalar( HINF inf, const std::wstring &section, const wchar_t *key,
									  std::uint32_t &value)
{
	std::wstring text ;															// 原数値文字列の全値です
	const auto	 error = readRequiredServiceField( inf, section, key, text) ;	// 同元一値の診断です
	// 欠損・重複を数値0へ変換しません
	if( error != 0) {
		return error ;
	}

	MaintenanceInfStructureReason reason{} ;							// 既存readerの診断だけを同期借用します
	const auto parsed = parseMaintenanceFlags( text, value, reason) ;	// 全値の厳密uint32解析です
	return parsed.state == MaintenanceInspectionState::PASSED ? 0
		   : parsed.error != 0								  ? parsed.error
							   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 必要serviceのsubdirを相対directoryの有限形式へ限定します
 * @param[in] directory 同期比較中だけ借用する元subdirです。空はrootです
 * @return 絶対・空要素・traversal・不正文字・末尾dot/spaceを持たない場合trueです
 * @note 元値を正規化しません。sourceの実位置は別途workspace/memberへ照合します
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validRequiredServiceSubdirectory( std::wstring_view directory) noexcept
{
	// 空directoryは明示rootの正常形です
	if( directory.empty()) {
		return true ;
	}

	std::size_t beginning{} ;	// 元要素の開始位置です
	// 各元要素を一度ずつ検査し、不正要素または全文終端で終了します
	while( beginning < directory.size()) {
		const auto separator = directory.find( L'\\', beginning) ;	// 元相対要素の区切りです
		const auto ending =
			// 同要素の終端です
			separator == directory.npos ? directory.size() : separator ;
		const auto component =
			// 補正しない原要素です
			directory.substr( beginning, ending - beginning) ;
		// 危険な要素をWindowsのpath補正で安全な別位置へ読み替えません
		if( component.empty() || component.size() > 255U || component == L"." ||
		   component == L".." || component.back() == L'.' || component.back() == L' ' ||
		   component.find_first_of( L"<>/%:\"|?*\t\r\n") != component.npos ||
		   std::ranges::any_of( component,
							   []( wchar_t value) { return value < L' ' || value > L'~' ; })) {
			return false ;
		}

		const auto stem =
			// 同期中だけ借用する予約名判定です
			component.substr( 0U, component.find( L'.')) ;
		// DOS device名を通常directoryへ補正しません
		if( stringsEqual( stem, L"CON") || stringsEqual( stem, L"PRN") || stringsEqual( stem, L"AUX") ||
		   stringsEqual( stem, L"NUL") ||
		   (stem.size() == 4U && stem[3U] >= L'1' && stem[3U] <= L'9' &&
			(stringsEqual( stem.substr( 0U, 3U), L"COM") ||
			 stringsEqual( stem.substr( 0U, 3U), L"LPT")))) {
			return false ;
		}

		// 全文終端だけを正常形として確定します
		if( separator == directory.npos) {
			return true ;
		}

		beginning = separator + 1U ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同INFのservice source subdirと媒体pathを共通SetupAPI readerから取得します
 * @param[in] inf 同期中だけ借用する元INFです
 * @param[in] executable 検査済みの同名source fileです
 * @param[out] directory 成功時だけ元SourceDisksFiles相対directoryです。失敗時は空です
 * @param[out] mediaDirectory 成功時だけ同元source IDの安全な媒体相対pathです。失敗時は空です
 * @return 完全取得成功0、欠損・過長・重複・安全相対path逸脱のHRESULTです
 * @pre 出力二つは別の格納先であり、executableともaliasしないこと
 * @note DIRID13一致用subdirに媒体pathを混ぜません。実byteは既存内容検査が照合します
 */
//------------------------------------------------------------------------------
NativeError readRequiredServiceSourceDirectory( HINF inf, const std::wstring &executable,
											   std::wstring &directory,
											   std::wstring &mediaDirectory)
{
	directory.clear() ;
	mediaDirectory.clear() ;
	// 共通reader成功まで出力へ公開しないfile subdirです
	std::wstring source ;
	std::wstring media ;																// 同source IDの完全な元媒体位置です
	const auto	 error = readInfSourceDirectories( inf, executable, source, media) ;	// 原位置診断です
	// 共通位置取得失敗の部分値をservice許可集合へ追加しません
	if( error != 0) {
		return error ;
	}

	// 既存serviceのASCII相対segment境界を媒体とfile subdirの両方へ適用します
	if( !validRequiredServiceSubdirectory( source) || !validRequiredServiceSubdirectory( media)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	directory	   = std::move( source) ;
	mediaDirectory = std::move( media) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定fieldの元文字列とWindowsの数値が同じ要求値を持つことを確認します
 * @param[in,out] row 読取り中の元行です
 * @param[in] field 対象の元field番号です
 * @param[in] expected 要求する非負の値です
 * @param[in] allowEmpty 空fieldに省略時の意味を認める場合trueです
 * @return 全桁と元Windows値が一致した場合又は認めた明示空でtrueです
 */
//------------------------------------------------------------------------------
bool propertyPageNumber( INFCONTEXT &row, DWORD field, std::uint32_t expected, bool allowEmpty)
{
	std::wstring text ;	// SetupAPIが返した完全な元fieldです
	// 読取失敗を省略へ補完しません
	if( readInstallInventoryField( row, field, text) != 0) {
		return false ;
	}

	// 許可したfieldでだけ型やflagsの省略を認識します
	if( text.empty()) {
		return allowEmpty ;
	}

	std::uint32_t				  parsed{} ;	// 共通readerによる全桁の結果です
	int							  native{} ;	// 元Windowsの解釈です
	MaintenanceInfStructureReason reason{} ;	// 元数値readerの内部診断です
	return parseMaintenanceFlags( text, parsed, reason).state ==
			   MaintenanceInspectionState::PASSED &&
		   parsed == expected && SetupGetIntField( &row, field, &native) && native >= 0 &&
		   static_cast<std::uint32_t>( native) == expected ;
}

//------------------------------------------------------------------------------
/**
 * @brief OS組込みのClass GUIDまたは登録済みの別Classとの衝突を拒否する
 * @param[in] className 元INFが宣言したクラス名
 * @param[in] guid 元INFの単一宣言から解析したGUID
 * @param[in] api 同workerに固定したクラスの読取り専用API表
 * @return 独自クラスの識別が成立すれば0、衝突・照会失敗はHRESULT
 * @note 既存クラスのハンドラー等は導入時に別途確認する
 */
//------------------------------------------------------------------------------
NativeError checkDeclarativeClassIdentity( const std::wstring &className, const GUID &guid,
										  const SetupClassReadApi &api)
{
	// 未登録のWindows標準クラスも、独自名によるGUIDの借用を許可しない
	const std::array standardClasses{
		&GUID_DEVCLASS_1394,
		&GUID_DEVCLASS_1394DEBUG,
		&GUID_DEVCLASS_61883,
		&GUID_DEVCLASS_ADAPTER,
		&GUID_DEVCLASS_APMSUPPORT,
		&GUID_DEVCLASS_AUDIOPROCESSINGOBJECT,
		&GUID_DEVCLASS_AVC,
		&GUID_DEVCLASS_BATTERY,
		&GUID_DEVCLASS_BIOMETRIC,
		&GUID_DEVCLASS_BLUETOOTH,
		&GUID_DEVCLASS_CAMERA,
		&GUID_DEVCLASS_CDROM,
		&GUID_DEVCLASS_COMPUTEACCELERATOR,
		&GUID_DEVCLASS_COMPUTER,
		&GUID_DEVCLASS_DECODER,
		&GUID_DEVCLASS_DISKDRIVE,
		&GUID_DEVCLASS_DISPLAY,
		&GUID_DEVCLASS_DOT4,
		&GUID_DEVCLASS_DOT4PRINT,
		&GUID_DEVCLASS_EHSTORAGESILO,
		&GUID_DEVCLASS_ENUM1394,
		&GUID_DEVCLASS_EXTENSION,
		&GUID_DEVCLASS_FDC,
		&GUID_DEVCLASS_FIRMWARE,
		&GUID_DEVCLASS_FLOPPYDISK,
		&GUID_DEVCLASS_GENERIC,
		&GUID_DEVCLASS_GPS,
		&GUID_DEVCLASS_HDC,
		&GUID_DEVCLASS_HIDCLASS,
		&GUID_DEVCLASS_HOLOGRAPHIC,
		&GUID_DEVCLASS_I3C,
		&GUID_DEVCLASS_IMAGE,
		&GUID_DEVCLASS_INFINIBAND,
		&GUID_DEVCLASS_INFRARED,
		&GUID_DEVCLASS_KEYBOARD,
		&GUID_DEVCLASS_LEGACYDRIVER,
		&GUID_DEVCLASS_MEDIA,
		&GUID_DEVCLASS_MEDIUM_CHANGER,
		&GUID_DEVCLASS_MEMORY,
		&GUID_DEVCLASS_MODEM,
		&GUID_DEVCLASS_MONITOR,
		&GUID_DEVCLASS_MOUSE,
		&GUID_DEVCLASS_MTD,
		&GUID_DEVCLASS_MULTIFUNCTION,
		&GUID_DEVCLASS_MULTIPORTSERIAL,
		&GUID_DEVCLASS_NET,
		&GUID_DEVCLASS_NETCLIENT,
		&GUID_DEVCLASS_NETDRIVER,
		&GUID_DEVCLASS_NETSERVICE,
		&GUID_DEVCLASS_NETTRANS,
		&GUID_DEVCLASS_NETUIO,
		&GUID_DEVCLASS_NODRIVER,
		&GUID_DEVCLASS_PCMCIA,
		&GUID_DEVCLASS_PNPPRINTERS,
		&GUID_DEVCLASS_PORTS,
		&GUID_DEVCLASS_PRIMITIVE,
		&GUID_DEVCLASS_PRINTER,
		&GUID_DEVCLASS_PRINTERUPGRADE,
		&GUID_DEVCLASS_PRINTQUEUE,
		&GUID_DEVCLASS_PROCESSOR,
		&GUID_DEVCLASS_SBP2,
		&GUID_DEVCLASS_SCMDISK,
		&GUID_DEVCLASS_SCMVOLUME,
		&GUID_DEVCLASS_SCSIADAPTER,
		&GUID_DEVCLASS_SECURITYACCELERATOR,
		&GUID_DEVCLASS_SENSOR,
		&GUID_DEVCLASS_SIDESHOW,
		&GUID_DEVCLASS_SMARTCARDREADER,
		&GUID_DEVCLASS_SMRDISK,
		&GUID_DEVCLASS_SMRVOLUME,
		&GUID_DEVCLASS_SOFTWARECOMPONENT,
		&GUID_DEVCLASS_SOUND,
		&GUID_DEVCLASS_SYSTEM,
		&GUID_DEVCLASS_TAPEDRIVE,
		&GUID_DEVCLASS_THERMAL,
		&GUID_DEVCLASS_UNKNOWN,
		&GUID_DEVCLASS_UCM,
		&GUID_DEVCLASS_USB,
		&GUID_DEVCLASS_VOLUME,
		&GUID_DEVCLASS_VOLUMESNAPSHOT,
		&GUID_DEVCLASS_WCEUSBS,
		&GUID_DEVCLASS_WPD,
		&GUID_DEVCLASS_FSFILTER_TOP,
		&GUID_DEVCLASS_FSFILTER_ACTIVITYMONITOR,
		&GUID_DEVCLASS_FSFILTER_UNDELETE,
		&GUID_DEVCLASS_FSFILTER_ANTIVIRUS,
		&GUID_DEVCLASS_FSFILTER_REPLICATION,
		&GUID_DEVCLASS_FSFILTER_CONTINUOUSBACKUP,
		&GUID_DEVCLASS_FSFILTER_CONTENTSCREENER,
		&GUID_DEVCLASS_FSFILTER_QUOTAMANAGEMENT,
		&GUID_DEVCLASS_FSFILTER_SYSTEMRECOVERY,
		&GUID_DEVCLASS_FSFILTER_CFSMETADATASERVER,
		&GUID_DEVCLASS_FSFILTER_HSM,
		&GUID_DEVCLASS_FSFILTER_COMPRESSION,
		&GUID_DEVCLASS_FSFILTER_ENCRYPTION,
		&GUID_DEVCLASS_FSFILTER_VIRTUALIZATION,
		&GUID_DEVCLASS_FSFILTER_PHYSICALQUOTAMANAGEMENT,
		&GUID_DEVCLASS_FSFILTER_OPENFILEBACKUP,
		&GUID_DEVCLASS_FSFILTER_SECURITYENHANCER,
		&GUID_DEVCLASS_FSFILTER_COPYPROTECTION,
		&GUID_DEVCLASS_FSFILTER_BOTTOM,
		&GUID_DEVCLASS_FSFILTER_SYSTEM,
		&GUID_DEVCLASS_FSFILTER_INFRASTRUCTURE,
	} ; // Windows SDKのセットアップクラス識別子
	// Microsoft公開一覧にはSDKのdevguid.hに定義されないセットアップクラスもある
	constexpr std::array documentedClasses{
		GUID{0xd94ee5d8U,
			 0xd189U,
			 0x4994U,
			 {0x83, 0xd2, 0xf6, 0x8d, 0x7d, 0x41, 0xb0, 0xe6}},	// Securitydevices
		GUID{0x75416e63U,
			 0x5912U,
			 0x4dfaU,
			 {0xae, 0x8f, 0x3e, 0xfa, 0xcc, 0xaf, 0xfb, 0x14}},	// NvmeDisk
		GUID{0x88bae032U,
			 0x5a81U,
			 0x49f0U,
			 {0xbc, 0x3d, 0xa4, 0xff, 0x13, 0x82, 0x16, 0xd6}},	// USBDevice
		GUID{0x62f9c741U,
			 0xb25aU,
			 0x46ceU,
			 {0xb5, 0x4c, 0x9b, 0xcc, 0xce, 0x08, 0xb6, 0xf2}},	// SoftwareDevice
		GUID{0xc166523cU,
			 0xfe0cU,
			 0x4a94U,
			 {0xa5, 0x86, 0xf1, 0xa8, 0x0c, 0xfb, 0xbf, 0x3e}},	// AudioEndpoint
	} ;
	constexpr std::wstring_view standardNames[]{
		L"1394",
		L"1394DEBUG",
		L"61883",
		L"ADAPTER",
		L"APMSUPPORT",
		L"AUDIOENDPOINT",
		L"AUDIOPROCESSINGOBJECT",
		L"AVC",
		L"BATTERY",
		L"BIOMETRIC",
		L"BLUETOOTH",
		L"CAMERA",
		L"CDROM",
		L"COMPUTEACCELERATOR",
		L"COMPUTER",
		L"DECODER",
		L"DISKDRIVE",
		L"DISPLAY",
		L"DOT4",
		L"DOT4PRINT",
		L"EHSTORAGESILO",
		L"ENUM1394",
		L"EXTENSION",
		L"FDC",
		L"FIRMWARE",
		L"FLOPPYDISK",
		L"GENERIC",
		L"GPS",
		L"HDC",
		L"HIDCLASS",
		L"HOLOGRAPHIC",
		L"I3C",
		L"IMAGE",
		L"INFINIBAND",
		L"INFRARED",
		L"KEYBOARD",
		L"LEGACYDRIVER",
		L"MEDIA",
		L"MEDIUMCHANGER",
		L"MEDIUM_CHANGER",
		L"MEMORY",
		L"MODEM",
		L"MONITOR",
		L"MOUSE",
		L"MTD",
		L"MULTIFUNCTION",
		L"MULTIPORTSERIAL",
		L"NET",
		L"NETCLIENT",
		L"NETDRIVER",
		L"NETSERVICE",
		L"NETTRANS",
		L"NETUIO",
		L"NODRIVER",
		L"NVMEDISK",
		L"PCMCIA",
		L"PNPPRINTERS",
		L"PORTS",
		L"PRIMITIVE",
		L"PRINTER",
		L"PRINTERUPGRADE",
		L"PRINTQUEUE",
		L"PROCESSOR",
		L"SBP2",
		L"SCMDISK",
		L"SCMVOLUME",
		L"SCSIADAPTER",
		L"SECURITYACCELERATOR",
		L"SECURITYDEVICES",
		L"SENSOR",
		L"SIDESHOW",
		L"SMARTCARDREADER",
		L"SMRDISK",
		L"SMRVOLUME",
		L"SOFTWARECOMPONENT",
		L"SOFTWAREDEVICE",
		L"SOUND",
		L"SYSTEM",
		L"TAPEDRIVE",
		L"THERMAL",
		L"UCM",
		L"UNKNOWN",
		L"USB",
		L"USBDEVICE",
		L"VOLUME",
		L"VOLUMESNAPSHOT",
		L"WCEUSBS",
		L"WPD",
	} ; // Windows SDKとMicrosoft公開一覧の既知クラス名
	// Windowsの既知クラス名またはGUIDを独自クラスの識別に使用させない
	if( IsEqualGUID( guid, GUID_NULL) || isAllowedValue( className, standardNames) ||
	   std::ranges::any_of( documentedClasses,
						   [&]( const GUID &known) { return IsEqualGUID( guid, known) ; }) ||
	   std::ranges::any_of( standardClasses,
						   [&]( const GUID *known) { return IsEqualGUID( guid, *known) ; })) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::array<wchar_t, MAX_CLASS_NAME_LEN> name{} ;	// 同GUIDの既登録名
	SetLastError( ERROR_SUCCESS) ;
	const bool registeredByGuid = api.className( &guid, name.data(), static_cast<DWORD>( name.size()),
												nullptr) != FALSE ;	// 逆方向の照会との整合に使用する
	// GUIDの照会で登録済みクラスが見つかった場合は実際の登録名を確認する
	if( registeredByGuid) {
		// 登録済みGUIDの別名を拒否する
		if( !stringsEqual( name.data(), className)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	} else {
		const DWORD error = GetLastError() ;	// GUIDの不在と照会失敗を区別する
		// 未登録を表さないWindowsの照会失敗を伝える
		if( error != ERROR_INVALID_CLASS && error != ERROR_FILE_NOT_FOUND) {
			return nativeErrorFromWin32( error ? error : ERROR_INVALID_DATA) ;
		}
	}

	GUID  registered{} ;	// 同名クラスに対応する登録済みGUID
	DWORD count{} ;			// 同名に別GUIDがある場合は最大一件の照会が失敗する
	SetLastError( ERROR_SUCCESS) ;
	// 同名の重複または逆引き失敗を未登録へ補完しない
	if( !api.classGuids( className.c_str(), &registered, 1U, &count)) {
		const DWORD error = GetLastError() ;	// 逆方向の元照会結果
		return nativeErrorFromWin32( error ? error : ERROR_INVALID_DATA) ;
	}

	return (registeredByGuid ? (count == 1U && IsEqualGUID( guid, registered)) : count == 0U)
			   ? 0
			   : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全Manufacturerの宣言が参照する潜在Modelsの元名を取得する
 * @param[in] inf 同期借用する読み取り専用INF
 * @param[in] amd64Only 明示的な他architectureだけを除く場合true
 * @param[out] models 元宣言の候補名。起点の存在は後段で照合する
 * @param[in,out] rows 今回の元宣言の読取予算
 * @param[in] nativeHdc 版指定のない明示AMD64行を持つHDCの旧Modelsを選択集合から外す場合true
 * @return 全件を有限に読取できた場合true。失敗時は部分出力を使用しない
 */
//------------------------------------------------------------------------------
bool collectDeclaredModelSections( HINF inf, bool amd64Only, std::vector<std::wstring> &models,
								  std::size_t &rows, bool nativeHdc) ;

//------------------------------------------------------------------------------
/**
 * @brief 収集INFのクラス登録を別の導入節として再利用できないことを確認する
 * @param[in] inf 同じ元バイトを固定中に開いた読取り専用HINF
 * @param[in] bytes HINFの存続中に置換を防ぐ元INFの全バイト
 * @param[in] registrations Windowsで確認したクラス節と登録先の対
 * @return 元の全節・全フィールドと多言語文字列で参照が分離されていればtrue
 */
//------------------------------------------------------------------------------
bool MaintenanceInfByteProof::isolatedClassRegistration(
	HINF inf, std::span<const std::byte> bytes,
	std::span<const std::pair<std::wstring, std::wstring>> registrations)
{
	// 元ファイルが固定されていない場合はWindowsの選択結果だけで例外を認めない
	if( bytes.empty() || bytes.size() > MAXIMUM_INACTIVE_CO_INSTALLER_BYTES) {
		return false ;
	}

	bytes_.resize( bytes.size()) ;
	std::ranges::copy( bytes, std::as_writable_bytes( std::span{bytes_}).begin()) ;
	// 原節の物理重複や分割構文をWindowsの統合済み行へ縮約しない
	if( !scan( true, true, false, false, true) || duplicateSections_) {
		return false ;
	}

	const auto family = []( std::wstring_view value, std::wstring_view base) {
		return stringsEqual( value, base) ||
			   (value.size() > base.size() && value[base.size()] == L'.' &&
				stringsEqual( value.substr( 0U, base.size()), base)) ;
	} ; // Windowsが修飾節へ解決し得る元の名前を比較する
	const auto aliases = [&]( std::wstring_view value) {
		const auto first = value.find_first_not_of( L" \t") ;	// 引用内にも参照を隠させない
		// 空の登録fieldには参照がない
		if( first == value.npos) {
			return false ;
		}

		value = value.substr( first, value.find_last_not_of( L" \t") - first + 1U) ;
		return family( value, L"ClassInstall32") || family( value, L"ClassInstall") ||
			   std::ranges::any_of( registrations, [&]( const auto &entry) {
				   return family( value, entry.second) || family( entry.second, value) ;
			   }) ;
	} ; // 同期中だけ全クラス名と元AddReg節を借用する

	std::vector<std::wstring> defaultStrings ;	// すべての言語で使える元の既定文字列
	std::vector<std::wstring> names ;			// 原構文から確認済みの節名
	std::vector<std::wstring> models ;			// 全Manufacturerから確認したモデル表示表
	std::size_t				  modelRows{} ;		// 元Manufacturer行の有限読取予算
	// 表示名と節参照を区別できないModels構成に文字列置換を認めない
	if( !collectDeclaredModelSections( inf, false, models, modelRows, false)) {
		return false ;
	}

	names.reserve( sections_.size()) ;
	// 元section envelopeをWindowsの行数と照合する
	for( const auto &section : sections_) {
		const auto &name = names.emplace_back( text( section.name)) ;	// 元節の表記
		// 不明な名前やWindowsが異なる行構造で読んだ節による再利用を拒否する
		if( !inactiveIdentifier( name) ||
		   SetupGetLineCountW( inf, name.c_str()) != static_cast<LONG>( section.count)) {
			return false ;
		}
	}

	// 現在の言語で選ばれない文字列にも登録先を組み立てる元値を許さない
	for( const auto &row : rows_) {
		const auto &name = names[row.section] ;	// 同行の元節
		// 文字列定義以外は参照元として後で確認する
		if( !isStrings( name)) {
			continue ;
		}

		const auto key	 = text( row.key) ;					// 同言語内の元文字列識別子
		const auto value = text( fields_[row.firstField]) ;	// 展開していない表示値
		const auto first = value.find_first_not_of( L' ') ;	// 表示値の最初の非空白文字
		// 別の指示・節名や間接リソース参照を生成できる文字列を拒否する
		if( value.empty() || value.size() > 256U ||
		   value.find_first_of( L"\t\"%,=[]") != value.npos || first == value.npos ||
		   value[first] == L'@' || aliases( value) ||
		   std::ranges::all_of(
			   key, []( const wchar_t digit) { return digit >= L'0' && digit <= L'9' ; })) {
			return false ;
		}

		// 既定文字列がない言語依存の参照や重複を採用しない
		if( stringsEqual( name, L"Strings") && !appendUnique( defaultStrings, key)) {
			return false ;
		}
	}

	// Models・サービス・コピー節も含め、全節の元キーと値を位置付きで調べる
	for( const auto &row : rows_) {
		const auto &name = names[row.section] ;	// 同行の元節
		// 定義表は前段の全言語検査だけを適用する
		if( isStrings( name)) {
			continue ;
		}

		const auto key		= text( row.key) ;	// 元行の未展開キー
		const auto owner	= std::ranges::find_if( registrations, [&]( const auto &entry) {
			   return stringsEqual( name, entry.first) ;
		   }) ; // この節がクラス登録先を参照できるかを判断する
		const bool registry = std::ranges::any_of( registrations, [&]( const auto &entry) {
			return stringsEqual( name, entry.second) ;
		}) ; // 登録キーと値の文字列置換を表示名に限定する
		const bool model	= std::ranges::any_of( models, [&]( const auto &item) {
			   return stringsEqual( item, name) ;
		   }) ; // Models内ではキーだけが表示名になる
		// キーも別役割の名前になり得るため値に含めて検査する
		for( std::size_t index = 0U; index <= row.fields; ++index) {
			const auto value =
				// 元の置換前の値
				index == 0U ? key : text( fields_[row.firstField + index - 1U]) ;
			// 指定されたクラス節からの唯一のリテラルAddRegだけが登録先を参照できる
			if( aliases( value)) {
				// 登録済みの所有元と既知のAddReg一行の形がそろう場合だけクラス登録として扱います
				if( owner == registrations.end() || !stringsEqual( key, L"AddReg") ||
				   row.fields != 1U || index != 1U || !stringsEqual( value, owner->second)) {
					return false ;
				}
			}

			// 構造部分ではコードページの違いで節名や区切りを変化させない
			if( std::ranges::any_of( value,
								   []( const wchar_t character) { return character > 0x7e ; })) {
				return false ;
			}

			// リテラル値には文字列展開の証明を必要としない
			if( value.find( L'%') == value.npos) {
				continue ;
			}

			// サービス実行パスの標準DIRIDは節名の文字列置換から除く
			if( !model && !registry && owner == registrations.end() && index == 1U &&
			   row.fields == 1U && stringsEqual( key, L"ServiceBinary") &&
			   (value.starts_with( L"%10%\\") || value.starts_with( L"%12%\\")) &&
			   value.find( L'%', 4U) == value.npos) {
				continue ;
			}

			const bool classDisplay = registry && index == 5U &&
									  // 登録節で許可するクラス既定表示名
									  text( fields_[row.firstField + 2U]).empty() ;
			const bool modelDisplay =
				!registry && index == 0U &&
				(model || stringsEqual( name, L"Manufacturer")) ;	// ManufacturerとModelsの表示キー
			const bool metadataDisplay =
				!registry && !model && index == 1U &&
				(family( name, L"SourceDisksNames") || (stringsEqual( name, L"Version") &&
													   // 元媒体と提供元の表示名
													   stringsEqual( key, L"Provider"))) ;
			// 認識した表示位置だけで全言語確認済みの単独文字列を使用する
			if( owner != registrations.end() || !(classDisplay || modelDisplay || metadataDisplay) ||
			   value.size() < 3U || value.front() != L'%' || value.back() != L'%') {
				return false ;
			}

			const auto token =
				// 単独の展開名
				std::wstring_view( value).substr( 1U, value.size() - 2U) ;
			// 元Stringsにない値や複数のtokenを連結した値に節参照を隠させない
			if( std::ranges::none_of( defaultStrings,
									[&]( const auto &item) { return stringsEqual( item, token) ; })) {
				return false ;
			}
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief ClassInstall32のAddRegからクラス既定値と有限の表示属性を読み取る
 * @param[in] inf 借用する読み取り専用INF
 * @param[in] section ClassInstall32が参照するAddReg節の名前
 * @param[out] registration 任意の出力先。全行が成立した場合だけ表示名とアイコンを設定する
 * @param[out] noInstallClass nullは従来形式。指定時だけNoInstallClass文字列1を許し、成立後に有無を返す
 * @return 許可する値だけを一意に読めた場合true
 * @note HKRはクラスキーを表す。別文脈からの参照は呼出し側で照合する
 */
//------------------------------------------------------------------------------
bool readDeclarativeClassValues( HINF inf, const std::wstring &section,
								OfficialInfDeclarativeClassRegistration *registration	= nullptr,
								bool									*noInstallClass = nullptr)
{
	const LONG		   count	= SetupGetLineCountW( inf, section.c_str()) ;	// Windowsが解釈した行数
	const std::wstring security = section + L".security" ;						// Windowsが自動参照するACL指定
	// 登録行の欠損・過剰と同名のアクセス権指定を拒否する
	if( count < 1L || count > (noInstallClass ? 3L : 2L) ||
	   SetupGetLineCountW( inf, security.c_str()) >= 0L) {
		return false ;
	}

	std::wstring	   displayName ;	// クラスの既定値への元表示名
	std::optional<int> icon ;			// 内蔵アイコンの元番号
	bool			   marker{} ;		// 収集でだけ許すクラスの非手動追加指定
	// 各登録行の値名・型・値を元の順番で確認する
	for( LONG index = 0L; index < count; ++index) {
		INFCONTEXT	 row{} ;	// クラスキーの元登録行
		std::wstring field ;	// 検査中の展開済みfield
		std::wstring value ;	// 同キーへ保存する文字列
		// クラスキー直下のREG_SZを記述した元行だけを調べる
		if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( index), &row) ||
		   SetupGetFieldCount( &row) != 5U || readInstallInventoryField( row, 0U, field) == 0 ||
		   readInfField( row, 1U, field) != 0 || !stringsEqual( field, L"HKR") ||
		   readInstallInventoryField( row, 2U, field) != 0 || !field.empty() ||
		   readInstallInventoryField( row, 3U, field) != 0 ||
		   !propertyPageNumber( row, 4U, 0U, true) || readInfField( row, 5U, value) != 0) {
			return false ;
		}

		// クラスキーの既定値は表示名として一度だけ受理する
		if( field.empty() && displayName.empty()) {
			const auto first = value.find_first_not_of( L" \t") ;	// 有効な表示文字の先頭
			// 空名・間接リソース参照・制御文字を含む表示名を拒否する
			if( value.size() > 256U || first == value.npos || value[first] == L'@' ||
			   std::ranges::any_of( value, []( const wchar_t character) {
				   return character < L' ' || (character >= 0x7FU && character <= 0x9FU) ;
			   })) {
				return false ;
			}

			displayName = std::move( value) ;
			continue ;
		}

		// 元クラスの非手動追加指定は収集時の文字列1一件だけを認める
		if( noInstallClass && !marker && stringsEqual( field, L"NoInstallClass") && value == L"1") {
			marker = true ;
			continue ;
		}

		int number{} ;	// Windowsが同じREG_SZの数値を解釈した結果
		// 追加値はWindows内蔵アイコンを表す負の番号に限定する
		if( !stringsEqual( field, L"Icon") || icon || value.size() < 2U || value.size() > 6U ||
		   value.front() != L'-' ||
		   !std::ranges::all_of(
			   std::wstring_view( value).substr( 1U),
			   []( const wchar_t digit) { return digit >= L'0' && digit <= L'9' ; }) ||
		   !SetupGetIntField( &row, 5U, &number) || number >= 0 || number < -65535) {
			return false ;
		}

		icon = number ;
	}

	// アイコンだけの節は表示名付きのクラス登録になりません
	if( displayName.empty()) {
		return false ;
	}

	// 元セクション全行を確認した表示情報だけを返します
	if( registration) {
		registration->displayName = std::move( displayName) ;
		registration->builtInIcon = icon ;
	}

	// 全登録行の検査を終えた場合だけ新しい指定の有無を呼出し元へ渡す
	if( noInstallClass) {
		*noInstallClass = marker ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief クラス用の登録節を別の導入文脈へ参照していないことを確認する
 * @param[in] inf 借用する読み取り専用INF
 * @param[in] sections Windowsが列挙した全節
 * @param[in] registrations クラス節と各クラスキー用AddReg節の対
 * @return 全参照の文脈が一致すればtrue
 */
//------------------------------------------------------------------------------
bool hasIsolatedClassRegistration(
	HINF inf, const std::vector<std::wstring> &sections,
	const std::vector<std::pair<std::wstring, std::wstring>> &registrations)
{
	constexpr std::array keys{L"AddReg", L"DelReg", L"BitReg",
							  L"Needs"} ;	// クラス登録を参照し得る指示
	// 登録節を参照できるすべての元節を走査する
	for( const auto &section : sections) {
		// 文字列定義のキーを導入指示に読み替えない
		if( stringsEqual( std::wstring_view( section).substr( 0U, section.find( L'.')), L"Strings")) {
			continue ;
		}

		// 各種類の登録参照を元のWindows解釈から調べる
		for( const auto *key : keys) {
			INFCONTEXT row{} ;	// 同節の参照宣言
			// 現在節にない指示は参照集合に含めない
			if( !SetupFindFirstLineW( inf, section.c_str(), key, &row)) {
				continue ;
			}

			// 同じ種類の後続指示も確認する
			do {
				const DWORD count = SetupGetFieldCount( &row) ;	// 展開済み参照の件数
				// 先頭の参照が正しくても残りの参照を省略しない
				for( DWORD field = 1U; field <= count; ++field) {
					std::wstring target ;	// 元の参照先
					// 参照先の読取失敗を空値にしない
					if( readInstallInventoryField( row, field, target) != 0) {
						return false ;
					}

					// 登録先を借用せず、別のクラスinstallもNeedsで適用しない
					bool classRegistry{} ;	// 現在値がクラス用の登録節を指すか
					bool ownedAddReg{} ;	// 同じクラス節からの正規参照か
					// 現参照をすべてのクラス節と登録節へ照合する
					for( const auto &[owner, registry] : registrations) {
						// クラス節を別の登録やNeedsから呼び出させない
						if( stringsEqual( owner, target)) {
							return false ;
						}

						// 登録節と現在の指示元が正規の対か確認する
						if( stringsEqual( registry, target)) {
							classRegistry = true ;
							ownedAddReg	  = ownedAddReg || stringsEqual( section, owner) ;
						}
					}

					// クラス用の登録節は対応するClassInstall32のAddRegからだけ参照する
					if( classRegistry && (!ownedAddReg || !stringsEqual( key, L"AddReg"))) {
						return false ;
					}
				}
			} while( SetupFindNextMatchLineW( &row, key, &row)) ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief クラス節の唯一のAddRegから同じ元INFの登録先を取得する
 * @param[in] inf 借用する読み取り専用INF
 * @param[in] section 元INFにあるクラス節名
 * @param[out] registry 唯一の登録参照を読めた場合に設定する
 * @return 追加指示のない一意の登録参照であればtrue
 */
//------------------------------------------------------------------------------
bool readDeclarativeClassTarget( HINF inf, const std::wstring &section, std::wstring &registry)
{
	INFCONTEXT directive{} ;	// 同クラスキーを指す唯一の登録宣言
	return SetupGetLineCountW( inf, section.c_str()) == 1L &&
		   SetupFindFirstLineW( inf, section.c_str(), L"AddReg", &directive) &&
		   SetupGetFieldCount( &directive) == 1U && readInfField( directive, 1U, registry) == 0 &&
		   validInstallInventorySectionName( registry) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 独自クラスの定義を元INFの表示用登録として確認する
 * @param[in] inf 借用する読み取り専用INF
 * @param[in] path 同じ保護INFの絶対path
 * @param[in] className 元INFのClass名
 * @param[out] classGuid 元INFの一意なClassGUID。失敗時は空
 * @param[out] registration 任意の出力先。現在OS用の検査済みクラス節と表示値を設定する
 * @param[in] collectionBytes HINFの存続中に固定した収集INFの全バイト。空の場合は従来の登録だけを扱う
 * @param[in] collectionPlatform 収集Modelsと同じ対象OS。nullは現在OS
 * @param[out] collectorClassInfSha256 追加形式に合格した場合だけ固定中に計算したINFハッシュを返す
 * @return 対象x64の登録を全て確認した場合0、未対応・不正・Windows失敗のHRESULT
 * @note 内容判定だけを行う。レジストリやファイルの変更と導入資格の発行は行わない
 */
//------------------------------------------------------------------------------
NativeError inspectDeclarativeSetupClass(
	HINF inf, const std::wstring &path, const std::wstring &className, std::wstring &classGuid,
	OfficialInfDeclarativeClassRegistration *registration			 = nullptr,
	std::span<const std::byte>				 collectionBytes		 = {},
	const OfficialInfModelsPlatform			*collectionPlatform		 = nullptr,
	std::wstring							*collectorClassInfSha256 = nullptr)
{
	classGuid.clear() ;
	const auto	unsupported = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;	// 未認識の登録形式
	const auto &driverStore = driver_store_inf_detail::transport() ;		// 世代と端末を共有する読取り表
	// 独自クラスを扱わない試験表では実Windowsの登録情報を借りない
	if( !driverStore.declarativeClass) {
		return unsupported ;
	}

	INFCONTEXT								name{} ;		// Versionの元Class宣言
	INFCONTEXT								declared{} ;	// Versionの元GUID宣言
	INFCONTEXT								duplicate{} ;	// 一意性確認用の次の元宣言
	std::wstring							literal ;		// 保護INFに明記されたGUID
	GUID									parsed{} ;		// 元GUIDの解析値
	GUID									native{} ;		// 元INFからWindowsが取得したGUID
	std::array<wchar_t, MAX_CLASS_NAME_LEN> nativeName{} ;	// 元INFからWindowsが取得した名前
	// 一意の元Class名とGUIDがWindowsの認識と一致することを要求する
	if( !SetupFindFirstLineW( inf, L"Version", L"Class", &name) || SetupGetFieldCount( &name) != 1U ||
	   SetupFindNextMatchLineW( &name, L"Class", &duplicate) ||
	   !SetupFindFirstLineW( inf, L"Version", L"ClassGUID", &declared) ||
	   SetupGetFieldCount( &declared) != 1U ||
	   SetupFindNextMatchLineW( &declared, L"ClassGUID", &duplicate) ||
	   readInfField( declared, 1U, literal) != 0 || literal.size() != 38U ||
	   CLSIDFromString( literal.c_str(), &parsed) != S_OK ||
	   !driverStore.infClass( path.c_str(), &native, nativeName.data(),
							 static_cast<DWORD>( nativeName.size()), nullptr) ||
	   !IsEqualGUID( native, parsed) || !stringsEqual( className, nativeName.data())) {
		return unsupported ;
	}

	const auto identity = checkDeclarativeClassIdentity(
		className, parsed, driverStore.declarativeClass->observation) ;	// 同名とGUIDの衝突
	// 登録の衝突または照会失敗があれば元診断を返す
	if( identity != 0) {
		return identity ;
	}

	std::vector<std::wstring>						   sections ;			// 参照元の全文脈を後から照合する
	std::vector<std::pair<std::wstring, std::wstring>> registrations ;		// x64用クラス節とAddReg節
	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> buffer{} ;	// 元節名の受信領域
	std::wstring legacyRegistry ;											// 旧節が宣言する登録先。現行の実選択と最後に比較する
	bool		 hasClassMarker{} ;											// 収集で追加したクラス値を一件以上読んだ場合true
	// Windowsが解釈した全節を既存の上限内で調べる
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		SetLastError( ERROR_SUCCESS) ;
		// 列挙が終わったときに参照の分離を確認する
		if( !SetupEnumInfSectionsW( inf, index, buffer.data(), static_cast<UINT>( buffer.size()),
								  nullptr)) {
			const DWORD error = GetLastError() ;	// 正常終端と列挙失敗を区別する
			// 途中の列挙失敗から部分合格を返さない
			if( error != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( error ? error : ERROR_INVALID_DATA) ;
			}

			// x64向けのクラス登録を少なくとも一つ確認する
			if( registrations.empty()) {
				return unsupported ;
			}

			const bool extended =
				hasClassMarker || !legacyRegistry.empty() ;		// 収集専用の追加検査が必要な形
			OfficialInfDeclarativeClassRegistration display ;	// 全参照の合格後に返す表示情報
			// 導入用の表示情報と追加収集ではWindowsの実選択に登録先を結び付ける
			if( registration || extended) {
				auto requested = collectionPlatform ? nativeModelsPlatform( *collectionPlatform)
													: std::nullopt ;	// 同じModelsに使用する対象OS
				// 対象OSが不明な場合にホスト現在OSの選択を流用しない
				if( collectionPlatform && !requested) {
					return unsupported ;
				}

				std::wstring resolved ;	// Windowsが解決した実在ClassInstall32節
				// Windows SDKは先頭cbSizeでV3を識別するため既定版ポインタ表記へ変換する
				const auto	 resolveError = resolveActualInstallInventorySection(
					  inf, L"ClassInstall32", resolved,
					  requested ? reinterpret_cast<PSP_ALTPLATFORM_INFO>( &*requested) : nullptr) ;
				// 元クラス節と同じ読取規則で選べる場合だけ表示情報を付けます
				if( resolveError != 0U) {
					return resolveError ;
				}

				const auto selected = std::ranges::find_if( registrations, [&]( const auto &entry) {
					return stringsEqual( entry.first, resolved) ;
				}) ; // 全作用を確認済みの元クラス節
				// 旧節が対象Windowsで選ばれない別の登録先を持つ場合は保留する
				if( selected == registrations.end() ||
				   (!legacyRegistry.empty() && !stringsEqual( selected->second, legacyRegistry))) {
					return unsupported ;
				}

				// 端末用の表示値は従来の許可範囲で取得する
				if( registration) {
					// 追加判定を端末用の読取り結果へ渡さない
					if( !readDeclarativeClassValues( inf, selected->second, &display)) {
						return unsupported ;
					}

					display.section	  = selected->first ;
					display.classGuid = literal ;
				}
			}

			// 旧節からの正規参照を他役割の参照と区別する
			if( !legacyRegistry.empty()) {
				registrations.emplace_back( L"ClassInstall", std::move( legacyRegistry)) ;
			}

			// 既存の逆参照証明を維持し、追加形式では元の全フィールドも検査する
			if( !hasIsolatedClassRegistration( inf, sections, registrations) ||
			   (extended && !MaintenanceInfByteProof{}.isolatedClassRegistration(
								inf, collectionBytes, registrations))) {
				return unsupported ;
			}

			// 収集の追加形式は固定した元INFを展開履歴と署名検査に結び付ける
			if( extended) {
				// 後続で照合できる所有先がなければ構造結果を返さない
				if( !collectorClassInfSha256) {
					return unsupported ;
				}

				const auto hashError =
					// 固定中の実バイト
					computeFileSha256( path, *collectorClassInfSha256) ;
				// 読取り失敗を空ハッシュの通常形式へ変更しない
				if( hashError != 0U) {
					return hashError ;
				}
			}

			// 全参照を確認できた時点で端末用の表示情報を確定する
			if( registration) {
				*registration = std::move( display) ;
			}

			classGuid = std::move( literal) ;
			return 0 ;
		}

		const auto &section = sections.emplace_back( buffer.data()) ;	// Windows列挙の元表記
		// 修飾を外したクラス節の名前
		const std::wstring_view base = std::wstring_view( section).substr( 0U, section.find( L'.')) ;
		// ClassInstall32以外の節は参照元として必要な名前だけを保持する
		if( !stringsEqual( base, L"ClassInstall32")) {
			// 未修飾の旧節は固定した収集INFの一意な参照だけを確認する
			if( stringsEqual( base, L"ClassInstall") &&
			   (collectionBytes.empty() || !stringsEqual( section, base) ||
				!legacyRegistry.empty() ||
				!readDeclarativeClassTarget( inf, section, legacyRegistry))) {
				return unsupported ;
			}

			continue ;
		}

		const auto suffix = std::wstring_view( section).substr( base.size()) ;	// Windowsの節修飾
		// Windowsが文書化した非x64用のクラス節修飾
		constexpr std::array otherArchitectures{
			std::wstring_view( L".ntx86"), std::wstring_view( L".ntia64"),
			std::wstring_view( L".ntarm"), std::wstring_view( L".ntarm64")} ;
		// 他アーキテクチャ専用のクラス節はx64で実行されない
		if( isAllowedValue( suffix, otherArchitectures)) {
			continue ;
		}

		std::wstring registry ;	// 同原INFにある登録節名
		bool		 marker{} ;	// 元のクラス登録に指定された収集用値
		// x64で選択されるクラス節は検証済みAddReg一つを参照する
		if( (!suffix.empty() && !stringsEqual( suffix, L".nt") &&
			!stringsEqual( suffix, L".ntamd64")) ||
		   !readDeclarativeClassTarget( inf, section, registry) ||
		   !readDeclarativeClassValues( inf, registry, nullptr,
									   collectionBytes.empty() ? nullptr : &marker)) {
			return unsupported ;
		}

		hasClassMarker = hasClassMarker || marker ;
		registrations.emplace_back( section, std::move( registry)) ;
	}

	return nativeErrorFromWin32( ERROR_TOO_MANY_NAMES) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同DDInstallの明示標準DIRID同名コピーを位置付きservice sourceへ一意に結びます
 * @param[in] inf 同期中だけ借用する元INFです
 * @param[in] install 元Services suffixを外した実在DDInstallです
 * @param[in] executable 同じ元ServiceBinaryの単一file名です
 * @param[in] binary 同じ元ServiceBinaryの展開済み全値です。空は実行を伴わない原コピーだけを検査します
 * @param[out] sourceRelative 成功時だけ元媒体path・source subdirと同名EXEを結んだ位置です。失敗時は空です
 * @param[in] driverStoreOnly Type1の原コピーをDIRID13だけへ限定する場合trueです
 * @param[in] systemDirectoryOnly CoInstallerの原コピーを完全system directoryへ限定する場合trueです
 * @param[in] propertyPageFlags 原ページの同名コピーを検査する場合の厳密なflagsです。指定時は改名・一時名を許さずDIRID11へ限定します
 * @return 一意な同名コピー成功0、欠損・rename・未対応DIRID・位置不一致・曖昧・容量のHRESULTです
 * @note コピーは実行しません。元file byte/位置/CATの確認は既存source readerとintegrity検査です
 */
//------------------------------------------------------------------------------
NativeError inspectRequiredServiceCopy( HINF inf, const std::wstring &install,
									   const std::wstring &executable, const std::wstring &binary,
									   std::wstring &sourceRelative, bool driverStoreOnly = false,
									   bool							systemDirectoryOnly = false,
									   std::optional<std::uint32_t> propertyPageFlags	= {})
{
	sourceRelative.clear() ;
	INFCONTEXT copy{} ;	// 同実在DDInstallの原CopyFilesです
	// 別節や別INFのコピーからserviceの導入位置を推測しません
	if( !SetupFindFirstLineW( inf, install.c_str(), L"CopyFiles", &copy)) {
		return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
	}

	std::size_t	 matches{} ;		// 同sourceと同DIRIDの一意コピー数です
	std::size_t	 declarations{} ;	// 全CopyFiles宣言の共同上限です
	std::size_t	 rows{} ;			// 到達list全体の行予算です
	std::wstring validatedSource ;	// 全CopyFiles検査の成功まで出力へ公開しない位置です
	// 同DDInstallの全CopyFilesを有限に読み、任意の先頭listを採用しません
	do {
		const auto fields = SetupGetFieldCount( &copy) ;	// 全原list指定数です
		// 過大または欠損宣言を空コピー成功にしません
		if( ++declarations > 32U || fields == 0U || fields > 32U) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 各元参照の同名sourceと明示導入先を照合します
		for( DWORD field = 1U; field <= fields; ++field) {
			std::wstring list ;										// 既存readerで展開した元参照です
			const auto	 error = readInfField( copy, field, list) ;	// 参照の全値診断です
			// 欠損または不正なlist名を推測参照へ変換しません
			if( error != 0 || (!list.starts_with( L"@") && !validInstallInventorySectionName( list))) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			const bool	direct = list.starts_with( L"@") ;	// Windowsの直接source記法です
			std::size_t copies{} ;							// この一参照内の同名コピー数です
			// 直接コピーの元file名だけをServiceBinaryへ照合します
			if( direct) {
				copies = stringsEqual( std::wstring_view( list).substr( 1U), executable) ? 1U : 0U ;
			} else {
				INFCONTEXT file{} ;	// 同HINFの実在CopyFiles list行です
				// 明示された空listは無作用です。欠落節は後段の失敗を保持します
				if( SetupGetLineCountW( inf, list.c_str()) == 0) {
					continue ;
				}

				// 不在の参照listを別のcopyへ補完しません
				if( !SetupFindFirstLineW( inf, list.c_str(), nullptr, &file)) {
					return nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND) ;
				}

				// 到達listの全fileを読み、renameを同名sourceの許可へ変換しません
				do {
					std::wstring target ;	// 原コピー先file名です
					// 容量超過や部分fieldの失敗を許可根拠にしません
					if( ++rows > 4096U || readInfField( file, 1U, target) != 0) {
						return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					// 同じ元DLLを改名した別の行や対象行の一時名・flagsもコピーの根拠にしません
					if( propertyPageFlags) {
						const auto count = SetupGetFieldCount( &file) ;				// 元file行の完全なfield数です
						const bool selected = stringsEqual( target, executable) ;	// 目的の元DLLです
						std::wstring original ;										// 明示sourceがあればrenameの方向も照合します
						// 別DLLの宛先へのrenameと元DLLへの異なるsourceのrenameを共に拒否します
						if( (count >= 2U && readInstallInventoryField( file, 2U, original) != 0) ||
						   (!original.empty() && stringsEqual( original, executable) != selected)) {
							return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
						}

						// 同じDLLの単純コピーだけを扱い、他fileの合法なflagsをDLLへ借用しません
						if( selected) {
							std::wstring temporary ;	// 非空の一時名を許しません
							std::wstring key ;			// 元file listの値行にdirectiveを混ぜません
							const bool	 expectedFlags =
								  count == 4U
									  ? propertyPageNumber( file, 4U, *propertyPageFlags,
														   *propertyPageFlags == 0U)
									  : *propertyPageFlags == 0U ;	// 明示でない非零値を補いません
							// 完全な元行だけを使用し、同名を含む未知の後続fieldを捨てません
							if( count > 4U ||
							   (readInstallInventoryField( file, 0U, key) == 0 &&
								!stringsEqual( key, target)) ||
							   (count >= 3U &&
								(readInstallInventoryField( file, 3U, temporary) != 0 ||
								 !temporary.empty())) ||
							   !expectedFlags) {
								return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
							}
						}
					}

					// このserviceの実binary名に一致する行だけを一意に結びます
					if( stringsEqual( target, executable)) {
						std::wstring source ;	// 空はWindowsの同名source記法です
						// 異なるsourceのrenameを同じbyteの許可へ読み替えません
						if( SetupGetFieldCount( &file) > 1U &&
						   (readInstallInventoryField( file, 2U, source) != 0 ||
							(!source.empty() && !stringsEqual( source, executable)))) {
							return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
						}

						++copies ;
					}
				} while( SetupFindNextLine( &file, &file)) ;
			}

			// 無関係なfile listの導入先をこのserviceの根拠へ借用しません
			if( copies == 0U) {
				continue ;
			}

			// 非零の原flagsは明示したファイル一覧からだけ読めます
			if( direct && propertyPageFlags.value_or( 0U) != 0U) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			auto	   destinationKey = direct ? L"DefaultDestDir" : list.c_str() ;	// 明示元keyです
			INFCONTEXT destination{} ;												// 同INFの明示DIRIDです
			int		   dirid{} ;													// 有限なWindows標準DIRIDです
			std::wstring subdirectory ;												// 元copy先の相対全subdirです
			// Windowsと同じく、個別listに指定がない場合だけ明示DefaultDestDirを使います
			if( !SetupFindFirstLineW( inf, L"DestinationDirs", destinationKey, &destination)) {
				destinationKey = L"DefaultDestDir" ;
			}

			// DIRID・subdir不一致をbasenameだけのsource許可へ変換しません
			if( !SetupFindFirstLineW( inf, L"DestinationDirs", destinationKey, &destination) ||
			   !SetupGetIntField( &destination, 1U, &dirid) ||
			   (dirid != 11 && dirid != 12 && dirid != 13 &&
				!(systemDirectoryOnly && dirid == 10)) ||
			   (driverStoreOnly && dirid != 13) ||
			   (propertyPageFlags && !propertyPageNumber( destination, 1U, 11U, false)) ||
			   (systemDirectoryOnly && dirid != 10 && dirid != 11) ||
			   SetupGetFieldCount( &destination) > 2U ||
			   (SetupGetFieldCount( &destination) == 2U &&
				(readInstallInventoryField( destination, 2U, subdirectory) != 0 ||
				 !validRequiredServiceSubdirectory( subdirectory) ||
				 (propertyPageFlags && !subdirectory.empty())))) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			std::wstring sourceDirectory ;	// 同INFの完全な元file subdirです
			std::wstring mediaDirectory ;	// 同source IDの完全な元媒体pathです
			const auto	 sourceError = readRequiredServiceSourceDirectory(
				  inf, executable, sourceDirectory, mediaDirectory) ;	// 原診断です
			// DIRID13は元source/destination subdir一致を必須とし、他DIRIDは同元sourceを保持します
			if( sourceError != 0 || (dirid == 13 && !stringsEqual( sourceDirectory, subdirectory))) {
				return sourceError != 0 ? sourceError : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			INFCONTEXT duplicate{} ;	// 同導入先の重複指定です
			// 一意のコピーと導入先だけから参照許可を作ります
			if( SetupFindNextMatchLineW( &destination, destinationKey, &duplicate) ||
			   (matches += copies) > 1U) {
				return nativeErrorFromWin32( ERROR_DUP_NAME) ;
			}

			const auto targetSection = direct ? nullptr : list.c_str() ;	// 同元copyのAPI指定です
			DWORD	   required{} ;											// Windowsが解決する同宛先の終端込み長です
			SetLastError( ERROR_SUCCESS) ;
			// 生DIRID tokenと展開値を比較せず、同HINFの同copy先を有限に取得します
			if( !SetupGetTargetPathW( inf, nullptr, targetSection, nullptr, 0U, &required) &&
			   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				const auto native = GetLastError() ;	// 原宛先APIの診断です
				return nativeErrorFromWin32( native == ERROR_SUCCESS ? ERROR_INVALID_DATA : native) ;
			}

			// 部分値や過大宛先を同leafの許可へ切り詰めません
			if( required <= 1U || required > MAXIMUM_INF_FIELD_CHARACTERS) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::vector<wchar_t> target( required) ;	// 同期中だけ所有する有限宛先です
			DWORD				 readRequired{} ;		// 同APIの実取得長です
			// 同元の二段目に失敗した部分宛先を使いません
			if( !SetupGetTargetPathW( inf, nullptr, targetSection, target.data(),
									static_cast<DWORD>( target.size()), &readRequired)) {
				const auto native = GetLastError() ;	// 補助比較前の原診断です
				return nativeErrorFromWin32( native == ERROR_SUCCESS ? ERROR_INVALID_DATA : native) ;
			}

			const auto end = std::ranges::find( target, L'\0') ;	// 有限bufferの原終端です
			// 完全な同宛先全値だけを比較し、basenameや任意絶対pathを許可しません
			if( end == target.end() || readRequired != required ||
			   static_cast<std::size_t>( end - target.begin()) + 1U != required ||
			   (!binary.empty() &&
				!stringsEqual( binary,
							  joinRelativePath( std::wstring_view( target.data(), required - 1U),
											   executable)))) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// CoInstallerはDIRIDの見かけでなくWindowsの完全system directoryへ限定します
			if( systemDirectoryOnly) {
				std::array<wchar_t, MAX_PATH> systemDirectory{} ;	// 現x64 OSの完全宛先です
				const auto					  length = GetSystemDirectoryW( systemDirectory.data(),
																		   // 原API長です
																		   static_cast<UINT>( systemDirectory.size())) ;
				// 明示10/system32以外の任意subdirや不完全な宛先を許可しません
				if( length == 0U || length >= systemDirectory.size() ||
				   !stringsEqual( std::wstring_view( target.data(), required - 1U),
								 systemDirectory.data())) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}
			}

			validatedSource =
				joinRelativePath( joinRelativePath( mediaDirectory, sourceDirectory), executable) ;
		}
	} while( SetupFindNextMatchLineW( &copy, L"CopyFiles", &copy)) ;

	// 全宣言が終わった一意成功だけで位置付きsourceを公開します
	if( matches == 1U) {
		sourceRelative = std::move( validatedSource) ;
		return 0 ;
	}

	return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同INFのManufacturer/Modelsから参照されたDDInstallを確認します
 * @param[in] inf 同期中だけ借用する原INFです
 * @param[in] install 検査する元DDInstall名です
 * @return 元Modelsの基本名または正式NT装飾へ一致する場合trueです
 * @note 別INF・表示名・service節から根拠を生成せず、全OS宣言を有限に読みます
 */
//------------------------------------------------------------------------------
bool hasModelsInstallReference( HINF inf, std::wstring_view install)
{
	INFCONTEXT manufacturer{} ;	// 原Manufacturerの有限列挙です
	// Modelsのない任意sectionをdeviceの導入文脈へ変換しません
	if( !SetupFindFirstLineW( inf, L"Manufacturer", nullptr, &manufacturer)) {
		return false ;
	}

	std::size_t manufacturers{} ;	// 全Manufacturerの共同上限です
	std::size_t rows{} ;			// 全Modelsの共同行上限です
	// 各原Manufacturerで明示されたbaseと装飾だけを読みます
	do {
		std::wstring base ;											// 同原行のModels基本名です
		const auto	 fields = SetupGetFieldCount( &manufacturer) ;	// 原section指定数です
		// 過大・欠損のManufacturerを任意section探索へ補正しません
		if( ++manufacturers > 64U || fields == 0U || fields > 32U ||
		   readInfField( manufacturer, 1U, base) != 0 || !validInstallInventorySectionName( base)) {
			return false ;
		}

		// 無装飾baseと全明示装飾の元Modelsを有限に調べます
		for( DWORD field = 1U; field <= fields; ++field) {
			std::wstring models = base ;	// 先頭fieldは無装飾Models自身です
			// 装飾は元Manufacturer fieldの全値だけから組み立てます
			if( field > 1U) {
				std::wstring decoration ;	// 原NTamd64等のTargetOSVersionです
				// 未解決文字列やpathをModels名へ取り込みません
				if( readInfField( manufacturer, field, decoration) != 0 ||
				   !validInstallInventorySectionName( decoration)) {
					return false ;
				}

				models += L"." + decoration ;
			}

			INFCONTEXT model{} ;	// 原Modelsのdevice行だけを読みます
			// 一部OSだけの無装飾不在を別sectionへ置き換えません
			if( !SetupFindFirstLineW( inf, models.c_str(), nullptr, &model)) {
				continue ;
			}

			// 全原Models行の最初のDDInstall fieldだけを照合します
			do {
				std::wstring named ;	// 原ModelsからのDDInstall基本名です
				// 行予算や不正参照を途中の一致として受理しません
				if( ++rows > 8192U || readInfField( model, 1U, named) != 0 ||
				   !validInstallInventorySectionName( named)) {
					return false ;
				}

				// 無装飾の実名を直接結びます
				if( stringsEqual( install, named)) {
					return true ;
				}

				// 同基本名の正式NT装飾だけをdeviceの文脈へ結びます
				if( install.size() > named.size() + 1U && install[named.size()] == L'.' &&
				   stringsEqual( install.substr( 0U, named.size()), named)) {
					const auto suffix		= install.substr( named.size() + 1U) ;	// 元NT装飾です
					const auto separator	= suffix.find( L'.') ;					// 任意OS版の開始です
					const auto architecture = suffix.substr( 0U, separator) ;		// 完全な装飾種別です
					const bool known =
						stringsEqual( architecture, L"NT") ||
						stringsEqual( architecture, L"NTamd64") ||
						stringsEqual( architecture, L"NTx86") ||
						stringsEqual( architecture, L"NTarm64") ||
						stringsEqual( architecture, L"NTarm") ||
						stringsEqual( architecture,
									 L"NTia64") ;	// Windowsが定義するarchitecture記法です
					// OS版部分へ任意の作用suffixを混ぜません
					if( known && (separator == suffix.npos ||
								 (separator + 1U < suffix.size() &&
								  std::ranges::all_of(
									  suffix.substr( separator + 1U), []( const wchar_t value) {
										  return (value >= L'0' && value <= L'9') || value == L'.' ;
									  })))) {
						return true ;
					}
				}
			} while( SetupFindNextLine( &model, &model)) ;
		}
	} while( SetupFindNextLine( &manufacturer, &manufacturer)) ;

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集元の登録を、正式Class対・WindowsのAMD64所有先・一つの元コピーへ結びます
 * @param[in] inf 読取り中の同じ原INFです
 * @param[in,out] row 元AddReg行の借用contextです
 * @param[in] install 元DDInstall名です
 * @param[in] section AddRegとCopyFilesの実在する元所有節です
 * @param[in] registry 同じ元所有節のAddReg参照です
 * @param[in,out] pages 確認済みの全所有先と同一原DLLの後段照合要求です
 * @param[in] copyFlags 同じ元所有節のコピー行に必要な元flagsです
 * @return 同一元の一意な宣言で0、形式・位置・所有の不一致は元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError bindCollectorPropertyPage( HINF inf, INFCONTEXT &row, const std::wstring &install,
									  const std::wstring &section, const std::wstring &registry,
									  PropertyPageContext &pages, std::uint32_t copyFlags = 0U)
{
	const auto unsupported = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;	// 限定形式の不成立です
	// 最初の元登録でだけclassと全明示AMD64 Modelsの実DDInstallを求めます
	if( pages.owners.empty()) {
		const auto unique = [&]( const wchar_t *key, const wchar_t *expected) {
			INFCONTEXT	 first{} ;	// 同Versionの原宣言です
			INFCONTEXT	 next{} ;	// 同一keyの重複を検出します
			std::wstring value ;	// 元fieldを完全に読みます
			return SetupFindFirstLineW( inf, L"Version", key, &first) &&
				   SetupGetFieldCount( &first) == 1U && readInfField( first, 1U, value) == 0 &&
				   stringsEqual( value, expected) && !SetupFindNextMatchLineW( &first, key, &next) ;
		} ; // 同じ原HINFの一意なClass宣言だけを扱います
		// Class名だけ又はownerに無関係なGUIDを例外へ流しません
		if( !unique( L"Class", L"SCSIAdapter") ||
		   !unique( L"ClassGUID", L"{4d36e97b-e325-11ce-bfc1-08002be10318}")) {
			return unsupported ;
		}

		MaintenanceStructureBudget budget{} ;										// 既存Modelsの有限予算を同じrootへ適用します
		std::vector<std::wstring>  names ;											// 明示AMD64 Modelsの元DDInstall基名です
		auto error = collectMaintenanceInstallNames( inf, budget, names, true) ;	// 実選択読取です
		// 他architecture又は欠落のModelsを補いません
		if( error != 0) {
			return error ;
		}

		// Windowsが実際に選択するDDInstallを基名ごとに一度だけ解決します
		for( const auto &base : names) {
			std::wstring actual ;	// 同HINFの実在DDInstallです
			error = resolveActualInstallInventorySection( inf, base, actual) ;
			// 欠落ownerを似た節名から生成しません
			if( error != 0) {
				return error ;
			}

			static_cast<void>( appendUnique( pages.modelInstalls, std::move( actual))) ;
		}
	}

	// 参照元ごとに証明し、同じ所有先への多重REG_SZ書込みを採用しません
	if( !std::ranges::any_of( pages.modelInstalls,
							[&]( const auto &name) { return stringsEqual( name, install) ; }) ||
	   std::ranges::any_of( pages.owners,
						   [&]( const auto &owner) { return stringsEqual( owner.first, section) ; }) ||
	   SetupGetFieldCount( &row) != 5U) {
		return unsupported ;
	}

	std::wstring declaration ;	// DLLとcallbackを含む単一の元文字列です
	std::wstring key ;			// 名前付きdirectiveをデータ行に再解釈しません
	// 生のREG_SZ型・単一scalarと元のfield構造を要求します
	if( readInstallInventoryField( row, 0U, key) == 0 || !propertyPageNumber( row, 4U, 0U, true) ||
	   readInfField( row, 5U, declaration) != 0) {
		return unsupported ;
	}

	const auto separator = declaration.find( L',') ;	// 唯一のDLL/関数名境界です
	// callbackの省略、複数の値、空のleafを受理しません
	if( separator == declaration.npos || separator == 0U || separator + 1U == declaration.size()) {
		return unsupported ;
	}

	auto left = std::wstring_view( declaration).substr( 0U, separator) ;	// 区切りの空白だけを除きます
	auto right =
		// WDK例のcomma-spaceを含みます
		std::wstring_view( declaration).substr( separator + 1U) ;
	left = left.substr( 0U, left.find_last_not_of( L" \t") + 1U) ;
	right.remove_prefix( (std::min)( right.size(), right.find_first_not_of( L" \t"))) ;
	const std::wstring dll( left) ;			// 元leafの大小文字を保持します
	const std::wstring callback( right) ;	// 実exportとの比較ではcaseを保存します
	const auto		   identifier = []( wchar_t c) {
		return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') ||
			   c == L'_' ;
	} ; // path・追加引数・序数指定を認めない限定ASCII名です
	// 元DLL名を別pathへ正規化せず、明示された名前付きcallbackを要求します
	if( dll.empty() || dll.front() == L'.' || dll.size() > 255U ||
	   !isSafeOfficialArchiveMember( dll, L'\\') || lowerExtension( dll) != L".dll" ||
	   !std::ranges::all_of( dll,
							[&]( wchar_t c) { return identifier( c) || c == L'.' || c == L'-' ; }) ||
	   callback.empty() || callback.size() > 256U || !std::ranges::all_of( callback, identifier)) {
		return unsupported ;
	}

	std::wstring source ;	// 同媒体の全subdirを含む元DLL位置です
	// 同じ所有先の唯一の原DLLと完全system directoryの診断です
	const auto	 copyError =
		inspectRequiredServiceCopy( inf, section, dll, L"", source, false, true, copyFlags) ;
	// 実System32宛先・元SourceDisksFileと既登録所有先のDLL/名前に一致する場合だけ残します
	if( copyError != 0 ||
	   (pages.binding && (!stringsEqual( pages.binding->sourceRelativePath, source) ||
						  pages.binding->callback != callback))) {
		return copyError != 0 ? copyError : unsupported ;
	}

	pages.owners.emplace_back( section, registry) ;
	pages.binding = OfficialInfPropertyPage{std::move( source), callback} ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同INFの正式CoInstallers文脈と元DLLコピーに結合した登録節を取得します
 * @param[in] inf 同期中だけ借用する元INFです
 * @param[out] registrySections 全成功時だけ検査済み元登録節です。失敗時は空です
 * @param[in,out] pages 明示収集rootだけの原登録です。他用途はnullです
 * @return 全節の構造検査成功0、不明作用・参照不一致・容量超過のHRESULTです
 * @note DLLを実行せず、同じCATの全file検証は後段で必須です
 */
//------------------------------------------------------------------------------
NativeError collectRequiredCoInstallerRegistry( HINF						  inf,
											   std::vector<std::wstring> &registrySections,
											   PropertyPageContext		 *pages)
{
	registrySections.clear() ;
	std::vector<std::wstring>	inspected ;					// 全節の成功まで公開しない元参照です
	constexpr std::wstring_view SUFFIX = L".CoInstallers" ;	// Windowsの元device登録文脈です
	std::size_t					rows{} ;					// 全登録行の共同有限予算です
	// 元INFの全CoInstallersを有限に確認し、一つの正常節で残りを省きません
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> buffer{} ;	// 元節名の固定領域です
		// 正常な全節終端だけで検査済み登録節を公開します
		if( !SetupEnumInfSectionsW( inf, index, buffer.data(), static_cast<UINT>( buffer.size()),
								  nullptr)) {
			const auto error = GetLastError() ;	// API失敗と正常終端を分けます
			// 途中失敗の部分集合を成功へ変換しません
			if( error != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( error) ;
			}

			registrySections = std::move( inspected) ;
			return 0 ;
		}

		const std::wstring section( buffer.data()) ;	// 同期中だけ所有する元節名です
		// 他suffixへCoInstallerの限定許可を渡しません
		if( section.size() <= SUFFIX.size() ||
		   !stringsEqual( std::wstring_view( section).substr( section.size() - SUFFIX.size()),
						 SUFFIX)) {
			continue ;
		}

		// 既存の空節・全空参照の契約をそのまま維持します
		if( validateEmptyCoInstallers( inf, section.c_str()) == 0) {
			continue ;
		}

		const auto install =
			// 元DDInstallです
			section.substr( 0U, section.size() - SUFFIX.size()) ;
		// 任意sectionや欠損DDInstallの登録を標準device構成へ昇格しません
		if( SetupGetLineCountW( inf, install.c_str()) < 0 ||
		   !hasModelsInstallReference( inf, install) ||
		   SetupGetLineCountW( inf, section.c_str()) > MAXIMUM_EMPTY_CO_INSTALLER_LINES) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		INFCONTEXT directive{} ;	// 当該節の最大二行です
		// 不整合な先頭取得を空節にしません
		if( !SetupFindFirstLineW( inf, section.c_str(), nullptr, &directive)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		bool		addReg{} ;			// 一回だけの標準登録指示です
		bool		copyFiles{} ;		// 一回だけの同元コピー指示です
		std::size_t registrations{} ;	// 実コピーへ結合した元DLL数です
		// 未知指示や重複指示を含む節は拒否します
		do {
			std::wstring key ;										// 当該節の原directive名です
			const auto	 fields = SetupGetFieldCount( &directive) ;	// 全元参照数です
			// 指示名・field数の不正を部分正常へ読み替えません
			if( readInfField( directive, 0U, key) != 0 || fields == 0U || fields > 16U ||
			   (!stringsEqual( key, L"AddReg") && !stringsEqual( key, L"CopyFiles")) ||
			   (stringsEqual( key, L"AddReg") && addReg) ||
			   (stringsEqual( key, L"CopyFiles") && copyFiles)) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// コピー全体は各登録の同元位置検査と後段の全source/CAT検証へ結びます
			if( stringsEqual( key, L"CopyFiles")) {
				copyFiles = true ;
				continue ;
			}

			addReg = true ;
			// 全原AddReg参照の全registry行を有限に検査します
			for( DWORD field = 1U; field <= fields; ++field) {
				std::wstring registry ;	// 同元INFの登録先sectionです
				// 不正参照や装飾による別作用の隠蔽を許可しません
				if( readInfField( directive, field, registry) != 0 ||
				   !validInstallInventorySectionName( registry)) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				INFCONTEXT row{} ;	// 当該元登録の全fieldです
				// 明示空参照だけを旧契約の無作用として保持します
				if( SetupGetLineCountW( inf, registry.c_str()) == 0 &&
				   validateEmptyInfReference( inf, registry.c_str()) == 0) {
					continue ;
				}

				// 存在しない元登録を空の正常値へ変換しません
				if( !SetupFindFirstLineW( inf, registry.c_str(), nullptr, &row)) {
					return nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND) ;
				}

				// 全行に同じdevice-local形式を要求し、他rootやcommandを混ぜません
				do {
					std::wstring root ;									// 原registry rootです
					std::wstring subkey ;								// 空のdevice software keyだけです
					std::wstring valueName ;							// 32以外はopaqueな元identifierです
					int			 flags{} ;								// 正式REG_MULTI_SZのみです
					const auto	 values = SetupGetFieldCount( &row) ;	// root等を含む原field数です
					// 有限の完全行とdevice内の空subkeyだけを受理します
					if( ++rows > 256U || values < 5U || values > 20U ||
					   readInfField( row, 1U, root) != 0 || !stringsEqual( root, L"HKR") ||
					   readInstallInventoryField( row, 2U, subkey) != 0 || !subkey.empty() ||
					   readInfField( row, 3U, valueName) != 0 ||
					   !validInstallInventorySectionName( valueName)) {
						return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
					}

					// 同名のプロパティページをMULTI_SZや他の用途の登録へ読み替えません
					if( stringsEqual( valueName, L"EnumPropPages32")) {
						// この登録所有者を原コピーへ結んだ診断です
						const auto error = pages ? bindCollectorPropertyPage(
													   inf, row, install, section, registry, *pages)
												 : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
						// 一所有先でも不成立なら共有登録全体を返しません
						if( error != 0 || ++registrations > 32U) {
							return error != 0 ? error : nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
						}

						continue ;
					}

					// 従来のCoInstallers32とopaque登録には元のMULTI_SZ条件を保持します
					if( !SetupGetIntField( &row, 4U, &flags) || flags != 0x00010000) {
						return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
					}

					// 各元MULTI_SZ要素を同じコピー元DLLとentrypointへ限定します
					for( DWORD value = 5U; value <= values; ++value) {
						std::wstring declaration ;	// 変換せず保持するDLL,entrypointの原値です
						// 空・過長・未解決文字列を実体の推測へ使いません
						if( readInfField( row, value, declaration) != 0) {
							return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
						}

						const auto separator = declaration.find( L',') ;	// 任意entrypointの境界です
						const auto trim		 = []( std::wstring_view text) {
							 const auto first =
								 // 原空白だけを除きます
								 text.find_first_not_of( L" \t") ;
							 return first == text.npos
											? std::wstring_view{}
											: text.substr( first,
														  text.find_last_not_of( L" \t") - first + 1U) ;
						} ; // 解析比較にだけ使用し、原INFを書き換えません
						const std::wstring dll( trim(
							// 原leafです
							std::wstring_view( declaration).substr( 0U, separator))) ;
						const auto		   entry =
							separator == declaration.npos
										? std::wstring_view{}
										: trim( std::wstring_view( declaration)
												   .substr( separator + 1U)) ;	// 原entrypointです
						// pathやshell表現をDLL名・entrypointへ補正しません
						if( lowerExtension( dll) != L".dll" ||
						   !validInstallInventorySectionName( dll) ||
						   (separator != declaration.npos &&
							(entry.empty() ||
							 !std::ranges::all_of( entry, []( const wchar_t character) {
								 return (character >= L'A' && character <= L'Z') ||
										(character >= L'a' && character <= L'z') ||
										(character >= L'0' && character <= L'9') ||
										character == L'_' ;
							 })))) {
							return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
						}

						std::wstring source ;	// 同INFの一意なsystem directoryコピー元です
						const auto	 error = inspectRequiredServiceCopy(
							  inf, section, dll, L"", source, false, true) ;	// 元位置診断です
						// 別DDInstall・別file・rename・別宛先のコピーで代用しません
						if( error != 0 || ++registrations > 32U) {
							return error != 0 ? error : nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
						}
					}
				} while( SetupFindNextLine( &row, &row)) ;
				static_cast<void>( appendUnique( inspected, std::move( registry))) ;
			}
		} while( SetupFindNextLine( &directive, &directive)) ;

		// 実登録と同じ文脈の元コピーを対で要求します
		if( !addReg || !copyFiles || registrations == 0U) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同節に元コピーへ結んだ関連kernel serviceがあるか検査します
 * @param[in] inf 呼出し中だけ借用する原INFです
 * @param[in] services Win32 serviceと同じ元Services節です
 * @return 同DDInstallの関連kernelと元コピーが確認できた場合trueです
 */
//------------------------------------------------------------------------------
bool hasAssociatedKernelService( HINF inf, const std::wstring &services)
{
	INFCONTEXT kernel{} ;	// 同deviceの元service宣言です
	// 別deviceや外部serviceの名称から関連kernelを補完しません
	if( !SetupFindFirstLineW( inf, services.c_str(), L"AddService", &kernel)) {
		return false ;
	}

	std::size_t declarations{} ;	// 同一節の有限service数です
	// 同節の関連kernelと同INFのコピーだけを有限に探します
	do {
		std::wstring  name ;	// 原kernelのservice名です
		std::wstring  install ;	// 同元service-install節です
		int			  flags{} ;	// 関連function driverの正式flagです
		std::uint32_t type{} ;	// kernel以外を親の証拠にしません
		// 完全な関連kernel宣言だけを依存の候補にします
		if( ++declarations <= 32U && SetupGetFieldCount( &kernel) >= 3U &&
		   SetupGetFieldCount( &kernel) <= 6U && readInfField( kernel, 1U, name) == 0 &&
		   SetupGetIntField( &kernel, 2U, &flags) && flags == SPSVCINST_ASSOCSERVICE &&
		   readInfField( kernel, 3U, install) == 0 &&
		   readRequiredServiceScalar( inf, install, L"ServiceType", type) == 0 &&
		   type == SERVICE_KERNEL_DRIVER) {
			std::wstring binary ;	// 同じ元kernelの完全な導入先です
			// service-installの欠損を同DDInstallという名前だけで救済しません
			if( readRequiredServiceField( inf, install, L"ServiceBinary", binary) != 0) {
				return false ;
			}

			const auto separator = binary.find_last_of( L'\\') ;	// 元leafの位置です
			const auto file		 = binary.substr(
				 // 既存sourceへ結ぶ名前です
				 separator == binary.npos ? 0U : separator + 1U) ;
			std::wstring source ;	// 元コピーの一意相対名です
			const auto	 basic = services.substr(
				  0U,
				  services.size() -
					  std::wstring_view{L".Services"}.size()) ;	// 呼出し側で検査した同DDInstallです
			// 同じ元SYSを同じ宛先へコピーする関連だけを必要serviceの根拠にします
			if( lowerExtension( file) == L".sys" &&
			   inspectRequiredServiceCopy( inf, basic, file, binary, source) == 0) {
				return true ;
			}
		}
	} while( SetupFindNextMatchLineW( &kernel, L"AddService", &kernel)) ;

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元AddServiceの任意event-logとDependenciesを標準形式として有限に読みます
 * @param[in] inf 同期中だけ借用する原INFです
 * @param[in,out] line 同じ元named AddService宣言です
 * @param[in] section 元service-install節です
 * @return 任意値の欠損・不正参照・過大宣言を除く場合0です
 * @note 原INFの値を変更せず、外部serviceの存在や実行成功を推測しません
 */
//------------------------------------------------------------------------------
NativeError validateRequiredServiceOptions( HINF inf, INFCONTEXT &line, const std::wstring &section)
{
	const auto fields = SetupGetFieldCount( &line) ;	// Windows標準の最大六fieldです
	// 必須三fieldを省略や未知の追加作用へ補正しません
	if( fields < 3U || fields > 6U) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring eventSection ;	// 省略時は追加event-logを持ちません
	std::wstring eventType ;	// 空はWindowsのSystem既定です
	std::wstring eventName ;	// 空は原ServiceNameをWindowsが使用します
	// 原参照がある場合だけ同じHINFの実在節を要求します
	if( fields >= 4U &&
	   (readInstallInventoryField( line, 4U, eventSection) != 0 ||
		(!eventSection.empty() && (!validInstallInventorySectionName( eventSection) ||
								   SetupGetLineCountW( inf, eventSection.c_str()) < 0)))) {
		return nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND) ;
	}

	// 別の任意event-log typeを既知値へ補正しません
	if( fields >= 5U &&
	   (readInstallInventoryField( line, 5U, eventType) != 0 ||
		(!eventType.empty() && !stringsEqual( eventType, L"System") &&
		 !stringsEqual( eventType, L"Security") && !stringsEqual( eventType, L"Application")))) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 値の全読取りとregistry名の通常境界を確認し、commandとして解釈しません
	if( fields >= 6U &&
	   (readInstallInventoryField( line, 6U, eventName) != 0 || eventName.size() > 256U ||
		eventName.find_first_of( L"\\/%\r\n") != eventName.npos)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	INFCONTEXT dependency{} ;	// 明示時だけ読む元service/group集合です
	// Dependencies省略はWindows標準の省略であり、関連kernel不在の証拠にはしません
	if( !SetupFindFirstLineW( inf, section.c_str(), L"Dependencies", &dependency)) {
		return 0 ;
	}

	const auto count = SetupGetFieldCount( &dependency) ;	// 同原宣言の有限field数です
	INFCONTEXT duplicate{} ;								// 二重宣言を先頭だけで採用しません
	// 過大・曖昧な依存リストを部分的な正常集合へ縮約しません
	if( count > 32U || SetupFindNextMatchLineW( &dependency, L"Dependencies", &duplicate)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 明示service名と先頭+のload-order groupを原順で読みます
	for( DWORD field = 1U; field <= count; ++field) {
		std::wstring name ;	// 原名だけを保持し、存在や起動成功を生成しません
		// 空の単一値は既定の空依存、その他の不正名は未対応へ残します
		if( readInstallInventoryField( dependency, field, name) != 0 || name.size() > 256U ||
		   (name.empty() && count != 1U) || name == L"+" ||
		   name.find_first_of( L"\\/%\r\n") != name.npos) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同INFの元AddServiceを役割と必須作用へ限定して検査します
 * @param[in] inf 同期中だけ借用する元INFです
 * @param[in] services 元AddServiceを読み取った節名です
 * @param[in,out] line 同節の原行contextです。参照を保存しません
 * @param[in] role 正式Class/GUIDに対応する内容役割です
 * @param[out] executable Win32必要serviceの場合だけ位置付き相対sourceを返します。それ以外・失敗時は空です
 * @param[in] systemDeviceService 正式Systemの同節関連kernelへの依存を要求する場合trueです
 * @return 成功0、未対応種別・欠損・誤role・位置/copy不一致のHRESULTです
 * @note kernel/file-systemの既存境界を維持し、Win32は0x10/0x20の有限形式だけを扱います
 */
//------------------------------------------------------------------------------
NativeError inspectRequiredServiceDeclaration( HINF inf, const std::wstring &services,
											  INFCONTEXT &line, DriverPlanRole role,
											  std::wstring &executable,
											  bool			systemDeviceService = false)
{
	executable.clear() ;
	std::wstring serviceName ;	// 空名はWindows標準null serviceだけを表します
	int			 nullFlags{} ;	// 正式な二fieldの関連flagだけを使います
	// named serviceの必須節を読む前に、正確なnull宣言を別形式として扱います
	if( readInstallInventoryField( line, 1U, serviceName) == 0 && serviceName.empty()) {
		return role != DriverPlanRole::EXTENSION && SetupGetFieldCount( &line) == 2U &&
					   SetupGetIntField( &line, 2U, &nullFlags) &&
					   nullFlags == SPSVCINST_ASSOCSERVICE
				   ? 0
				   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::wstring  section ;	// 元named service-install節です
	std::uint32_t type{} ;	// 未知文字列を補正しない原スカラーです
	// 実在named節と厳密ServiceTypeを必要とします
	if( readInfField( line, 3U, section) != 0 || !validInstallInventorySectionName( section) ||
	   readRequiredServiceScalar( inf, section, L"ServiceType", type) != 0) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto options =
		// 元の任意値だけの診断です
		validateRequiredServiceOptions( inf, line, section) ;
	// 不正な任意fieldを先行する必須三値の正常で隠しません
	if( options != 0) {
		return options ;
	}

	// kernel/file-systemにWin32のEXE許可を付与しません
	if( type == SERVICE_KERNEL_DRIVER || type == SERVICE_FILE_SYSTEM_DRIVER) {
		return 0 ;
	}

	constexpr std::wstring_view SERVICES_SUFFIX = L".Services" ;	// 同DDInstallへの原結合です
	// 必要SWCだけに明示Win32二種を認め、複合/誤roleを推測補正しません
	if( (role != DriverPlanRole::DRIVER_COMPONENT && !systemDeviceService) ||
	   (type != SERVICE_WIN32_OWN_PROCESS && type != SERVICE_WIN32_SHARE_PROCESS) ||
	   services.size() <= SERVICES_SUFFIX.size() ||
	   !stringsEqual( std::wstring_view( services).substr( services.size() - SERVICES_SUFFIX.size()),
					 SERVICES_SUFFIX) ||
	   SetupGetFieldCount( &line) > 6U) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// SystemのWin32を任意appにせず、同節の関連kernelと元コピーへ結びます
	if( systemDeviceService && !hasAssociatedKernelService( inf, services)) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto install =
		// 同元基本節です
		services.substr( 0U, services.size() - SERVICES_SUFFIX.size()) ;
	std::wstring  name ;		// 非空named serviceだけを扱います
	std::wstring  flags ;		// 空または厳密uint32の原AddService flagsです
	std::uint32_t start{} ;		// Win32のAUTO/DEMANDだけです
	std::uint32_t control{} ;	// 正式ErrorControlのスカラーです
	std::wstring  binary ;		// 元ServiceBinaryの全値です
	// 全必須値と同DDInstall実在を確認し、別節のserviceを許可へ転用しません
	if( SetupGetLineCountW( inf, install.c_str()) < 0 ||
	   (systemDeviceService && !hasModelsInstallReference( inf, install)) ||
	   readInfField( line, 1U, name) != 0 || readInstallInventoryField( line, 2U, flags) != 0 ||
	   readRequiredServiceScalar( inf, section, L"StartType", start) != 0 ||
	   (start != SERVICE_AUTO_START && start != SERVICE_DEMAND_START) ||
	   readRequiredServiceScalar( inf, section, L"ErrorControl", control) != 0 || control > 3U ||
	   readRequiredServiceField( inf, section, L"ServiceBinary", binary) != 0) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// Win32必要SWCに作用が定義された既存OS共通の正式flagsだけです
	constexpr std::uint32_t ALLOWED_SERVICE_FLAGS =
		SPSVCINST_NOCLOBBER_DISPLAYNAME | SPSVCINST_NOCLOBBER_STARTTYPE |
		SPSVCINST_NOCLOBBER_ERRORCONTROL | SPSVCINST_NOCLOBBER_LOADORDERGROUP |
		SPSVCINST_NOCLOBBER_DEPENDENCIES | SPSVCINST_NOCLOBBER_DESCRIPTION |
		SPSVCINST_NOCLOBBER_REQUIREDPRIVILEGES | SPSVCINST_STARTSERVICE ;
	std::uint32_t				  parsedFlags{} ;	// 空fieldだけを正式な省略0として扱います
	MaintenanceInfStructureReason flagReason{} ;	// 原厳密readerの同期診断です
	// ASSOCSERVICE/unknown/security上書き等をWin32の一般許可へ含めません
	if( (!flags.empty() && parseMaintenanceFlags( flags, parsedFlags, flagReason).state !=
							  MaintenanceInspectionState::PASSED) ||
	   (parsedFlags & ~ALLOWED_SERVICE_FLAGS) != 0U) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto separator = binary.find_last_of( L'\\') ;	// 展開済み全targetの元leaf境界です
	const auto file		 = binary.substr(
		 // copy候補だけのleafです
		 separator == std::wstring::npos ? 0U : separator + 1U) ;
	// leafに引数や未知tokenを認めず、完全なbinaryの位置比較は後段でも必須にします
	if( file.empty() || file.find_first_of( L"%\\/:\"\t\r\n ") != std::wstring::npos ||
	   lowerExtension( file) != L".exe") {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::wstring sourceRelative ;	// 同元copyへ結んだ位置付きsourceです
	// 同節の元全宛先との比較診断です
	const auto	 error = inspectRequiredServiceCopy( inf, install, file, binary, sourceRelative) ;
	// 別sourceや別DDInstallのコピーを実行許可へ補完しません
	if( error != 0) {
		return error ;
	}

	executable = std::move( sourceRelative) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正式SWCまたは関連kernelに結合したdevice serviceの有限EXE source集合を取得します
 * @param[in] inf 同期中だけ借用する元INFです
 * @param[in] className 既にVersionから検査した原Classです
 * @param[out] executables 正常終端時は同INFの全検査済み一意相対source位置です。失敗時は空です
 * @param[in] contentOnly 内容検査として対象クラス外の実行参照を未評価に保つ場合はtrueです
 * @param[in] collectorSystemBudget 本人保護領域の収集用途でSystemの全宣言を走査する場合はtrueです
 * @return 全宣言の検査成功0、列挙異常/誤GUID/未知service/容量/参照不一致のHRESULTです
 * @note 収集時のSystemは全宣言を有限に検査し、EXE参照の上限は従来どおりです。全CAT/member/hashを後段で要求します
 */
//------------------------------------------------------------------------------
NativeError collectRequiredServiceExecutables( HINF inf, std::wstring_view className,
											  std::vector<std::wstring> &executables,
											  bool						 contentOnly = false,
											  bool collectorSystemBudget			 = false)
{
	executables.clear() ;
	const bool component = stringsEqual( className, L"SoftwareComponent") ;	// 正式SWCの役割です
	const bool system	 = stringsEqual( className, L"System") ;			// 正式System名の宣言です
	// 既存System/SWC以外の内容検査は全programを未評価のまま保持し、新しい導入許可を生成しません
	if( contentOnly && !component && !system) {
		return 0 ;
	}

	// Extensionへ基本driver serviceの実行許可を渡しません
	if( stringsEqual( className, L"Extension")) {
		return 0 ;
	}

	std::wstring guid ;	// 同原Versionの正式役割GUIDです
	const auto	 guidError =
		// 原GUID取得の診断です
		readInfDirective( inf, L"Version", L"ClassGUID", 1U, guid) ;
	// 通常deviceのWin32は同節の関連kernelへ結びます
	const bool systemDeviceService = !component ;	// 通常deviceは同節の関連kernelを要求します
	constexpr std::array<std::wstring_view, 2U> SYSTEM_CLASS{
		L"System", L"{4d36e97d-e325-11ce-bfc1-08002be10318}"} ;	// Windows正式対です
	// 正式Systemという既存役割のGUIDを別ClassのGUIDへ読み替えません
	if( system && (guidError != 0 || !stringsEqual( guid, SYSTEM_CLASS[1]))) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 拡張した上限は余分なClass/GUID宣言のない正式対にだけ使います
	if( system && collectorSystemBudget && validateSetupClassPair( inf, SYSTEM_CLASS) != 0) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// Class名だけではサービス型componentを認定しません
	if( component &&
	   (guidError != 0 || !stringsEqual( guid, L"{5c4c3332-344d-483c-8739-259e934c9cc8}"))) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	constexpr std::size_t MAXIMUM_PROGRAM_DECLARATIONS =
		32U ;	// 従来の実行参照付きサービス宣言の上限です
	const auto maximumDeclarations =
		system && collectorSystemBudget
			? MAXIMUM_INSTALL_INVENTORY_LINES
			: MAXIMUM_PROGRAM_DECLARATIONS ;	// 収集Systemでも原行の有限予算です
	std::size_t services{} ;					// 全節で共同消費する有限service宣言数です
	std::size_t programServices{} ;				// 同じEXEを参照する場合も宣言ごとに数えます
	// 非選択/別OSの潜在serviceも同元INFの内容検査から除きません
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> section{} ;	// 有限元節名です
		// 完全な全節終端だけを成功にします
		if( !SetupEnumInfSectionsW( inf, index, section.data(), static_cast<UINT>( section.size()),
								  nullptr)) {
			const auto error = GetLastError() ;	// 原列挙の終端/失敗です
			// 正常終端だけが全検査済み集合を保持し、途中の診断では部分許可を破棄します
			if( error != ERROR_NO_MORE_ITEMS) {
				executables.clear() ;
				return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
			}

			return 0 ;
		}

		INFCONTEXT service{} ;	// 同節の元AddServiceです
		// serviceなしの構成INFを任意appに読み替えません
		if( !SetupFindFirstLineW( inf, section.data(), L"AddService", &service)) {
			continue ;
		}

		// 全named serviceを同役割/同節へ結び、一宣言の成功で残りを省きません
		do {
			std::wstring executable ;	// 検査済み同INFのsource名だけです
			// 同元serviceの宣言・全宛先比較の診断です
			const auto	 error = inspectRequiredServiceDeclaration(
				  inf, section.data(), service,
				  component ? DriverPlanRole::DRIVER_COMPONENT : DriverPlanRole::BASE_DRIVER,
				  executable, systemDeviceService) ;
			// 未対応や容量超過では部分EXE集合を公開しません
			if( ++services > maximumDeclarations || error != 0) {
				executables.clear() ;
				return error != 0 ? error : nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			// kernel等の空出力はWin32のsource許可へ含めません
			if( !executable.empty()) {
				// 同じ実行ファイルを使う複数の宣言にも従来の枠を使います
				if( ++programServices > MAXIMUM_PROGRAM_DECLARATIONS) {
					executables.clear() ;
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}

				static_cast<void>( appendUnique( executables, std::move( executable))) ;
			}
		} while( SetupFindNextMatchLineW( &service, L"AddService", &service)) ;
	}

	executables.clear() ;
	return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Type1宣言を同INFのDriverStoreコピーへ検証します
 * @param[in] inf 呼出し中だけ借用する読取り専用INFです
 * @param[in] software 元AddSoftwareを持つDDInstall.Software節です
 * @param[in,out] line 元AddSoftwareの全fieldを読むcontextです
 * @param[in] contentOnly 他Classは内容だけ検査し、導入許可へ変換しない場合trueです
 * @param[out] source 非nullなら全成功時だけ同元source相対位置、失敗時は空です
 * @param[out] unassessed 非nullなら当該参照が内容専用の場合true、失敗時はfalseです
 * @return 標準Type1の役割・原コピー成功0、不正・未対応時はHRESULTです
 * @note 非SWCの内容成功は未評価作用のままです。実行せず、署名・適合・導入許可は後段の責務です
 */
//------------------------------------------------------------------------------
NativeError validateRequiredSoftwareDeclaration( HINF inf, std::wstring_view software,
												INFCONTEXT &line, bool contentOnly,
												std::wstring *source, bool *unassessed)
{
	// 未評価の部分観測を前回の参照から引き継ぎません
	if( unassessed != nullptr) {
		*unassessed = false ;
	}

	// 部分解析値を呼出側のsource許可へ残しません
	if( source != nullptr) {
		source->clear() ;
	}

	constexpr std::wstring_view SUFFIX = L".Software" ;	// Windowsの元設置文脈です
	std::wstring				className ;				// 元Class/GUIDを同じHINFから取得します
	std::wstring				guid ;					// 名称だけではComponentにしません
	std::wstring				name ;					// 原SoftwareNameです
	std::wstring				flags ;					// 省略0または正式0/1だけです
	std::wstring				section ;				// 元software-install節です
	int							parsedFlags{} ;			// Windowsが解析した原数値です
	// Type1を正規ComponentのDDInstall.Software内だけへ限定します
	if( software.size() <= SUFFIX.size() ||
	   !stringsEqual( software.substr( software.size() - SUFFIX.size()), SUFFIX) ||
	   readInfDirective( inf, L"Version", L"Class", 1U, className) != 0 ||
	   readInfDirective( inf, L"Version", L"ClassGUID", 1U, guid) != 0 ||
	   (!contentOnly && (!stringsEqual( className, L"SoftwareComponent") ||
						 !stringsEqual( guid, L"{5c4c3332-344d-483c-8739-259e934c9cc8}"))) ||
	   SetupGetFieldCount( &line) != 3U || readInfField( line, 1U, name) != 0 ||
	   readInstallInventoryField( line, 2U, flags) != 0 ||
	   (!flags.empty() &&
		(!SetupGetIntField( &line, 2U, &parsedFlags) || parsedFlags < 0 || parsedFlags > 1)) ||
	   readInfField( line, 3U, section) != 0 || !validInstallInventorySectionName( section)) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const std::wstring install(
		// 元設置節です
		software.substr( 0U, software.size() - SUFFIX.size())) ;
	std::uint32_t type{} ;	// Type2等をType1へ縮約しません
	std::wstring  binary ;	// 引数はこの値に混ぜず、Windowsが原SoftwareArgumentsを扱います
	std::wstring  version ;	// Type1必須版です
	// 元設置節・必須Type1三値を完全に取得します
	if( SetupGetLineCountW( inf, install.c_str()) < 0 ||
	   (!contentOnly && !hasModelsInstallReference( inf, install)) ||
	   readRequiredServiceScalar( inf, section, L"SoftwareType", type) != 0) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// Store関連は原PFNの非実行内容だけを検査し、Type1の実行許可へ読み替えません
	if( type == 2U && contentOnly) {
		std::wstring identifier ;	// 同元宣言の完全PFN URIです
		// 任意URLや不正なpackage identityをStore参照として認めません
		if( readRequiredServiceField( inf, section, L"SoftwareID", identifier) != 0 ||
		   !identifier.starts_with( L"pfn://") ||
		   VerifyPackageFamilyName( identifier.c_str() + 6U) != ERROR_SUCCESS) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// software取得・実行を行わず、既存の未評価作用へ残します
		if( unassessed != nullptr) {
			*unassessed = true ;
		}

		return 0 ;
	}

	// Type1の必要三値と版を省略・補正しません
	if( type != 1U || readRequiredServiceField( inf, section, L"SoftwareBinary", binary) != 0 ||
	   readRequiredServiceField( inf, section, L"SoftwareVersion", version) != 0 ||
	   !parseFourPartDriverVersion( version).has_value()) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto separator = binary.find_last_of( L'\\') ;	// 元binaryの全位置を後段でも比較します
	const auto file =
		// 原binaryのleafです
		binary.substr( separator == binary.npos ? 0U : separator + 1U) ;
	const auto extension = lowerExtension( file) ;	// Windows Type1が扱う二形式だけです
	// 直接shell commandや別形式を標準Type1 binaryへ変換しません
	if( !validRequiredServiceSubdirectory( file) || file.find( L'\\') != file.npos ||
	   (extension != L".exe" && extension != L".msi")) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::wstring inspected ;	// 同INFの元DriverStoreコピーだけを検証します
	const auto	 error =
		inspectRequiredServiceCopy( inf, install, file, separator == binary.npos ? L"" : binary,
								   inspected, true) ;	// 原コピー診断です
	// 全成功かつ明示された出力先だけへ位置を公開します
	if( error == 0 && source != nullptr) {
		*source = std::move( inspected) ;
	}

	// 他ClassのType1内容成功を標準Componentの導入許可へ昇格しません
	if( error == 0 && unassessed != nullptr && contentOnly &&
	   (!stringsEqual( className, L"SoftwareComponent") ||
		!stringsEqual( guid, L"{5c4c3332-344d-483c-8739-259e934c9cc8}"))) {
		*unassessed = true ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正式Componentの明示コピーだけを同INFの参照program集合へ結びます
 * @param[in] inf 呼出し中だけ借用する原INFです
 * @param[in] className 既に読んだ原Classです
 * @param[in,out] executables 元serviceと同じsource位置の集合です。失敗時は呼出側が破棄します
 * @return 全コピー・原Type1の検証成功0、欠損・曖昧・不正配置時はHRESULTです
 * @note 内容のコピーを検証するだけで、programの独自実行を許可しません
 */
//------------------------------------------------------------------------------
NativeError collectRequiredCopyExecutables( HINF inf, std::wstring_view className,
										   std::vector<std::wstring> &executables)
{
	// コピー専用programの追加は正式SWCだけです。Systemは既存serviceの位置証拠を使います
	if( !stringsEqual( className, L"SoftwareComponent")) {
		return 0 ;
	}

	std::size_t rows{} ;	// 全節・全listで共同消費する有限予算です
	// importされる元節を有限に読み、別INFや同名検索へ進みません
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U>
			section{} ;	// 同期中だけ所有する元節名です
		// 正常な全節終端だけを成功にします
		if( !SetupEnumInfSectionsW( inf, index, section.data(), static_cast<UINT>( section.size()),
								  nullptr)) {
			const auto error = GetLastError() ;	// API失敗と正常終端を分けます
			return error == ERROR_NO_MORE_ITEMS ? 0 : nativeErrorFromWin32( error) ;
		}

		INFCONTEXT copy{} ;	// 同節の明示CopyFilesです
		// コピー宣言のない節に参照作用を補完しません
		if( !SetupFindFirstLineW( inf, section.data(), L"CopyFiles", &copy)) {
			continue ;
		}

		// 同じ元install節の全CopyFilesを検査します
		do {
			// 一宣言のfield上限を残りのlistで回避しません
			if( SetupGetFieldCount( &copy) == 0U || SetupGetFieldCount( &copy) > 32U) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			// 参照された全listの元fileだけを列挙します
			for( DWORD field = 1U; field <= SetupGetFieldCount( &copy); ++field) {
				std::wstring list ;	// 原listまたは直接sourceです
				// 欠損listを別節の正常コピーで代用しません
				if( readInfField( copy, field, list) != 0 ||
				   (!list.starts_with( L"@") && !validInstallInventorySectionName( list))) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				const bool direct = list.starts_with( L"@") ;	// 明示直接コピーです
				INFCONTEXT file{} ;								// 元listの現在行です
				// 存在しない参照listを空として受理しません
				if( !direct && !SetupFindFirstLineW( inf, list.c_str(), nullptr, &file)) {
					return nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND) ;
				}

				// 各元copy targetを一度ずつ有限に調べます
				do {
					std::wstring name ;	// 同名programだけをsourceへ結びます
					// 累積過大と元file名読取り失敗を打切り成功にしません
					if( ++rows > MAXIMUM_INSTALL_INVENTORY_LINES ||
					   (!direct && readInfField( file, 1U, name) != 0)) {
						return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
					}

					// @sourceは元値のまま使い、pathの補正をしません
					if( direct) {
						name = list.substr( 1U) ;
					}

					const auto extension =
						// 他の受動dataは既存source検査へ委ねます
						lowerExtension( name) ;
					// programのコピーは元位置を検査し、実行を追加しません
					if( extension == L".exe" || extension == L".msi") {
						std::wstring source ;	// 同INFの一意なコピー元です
						// 同DDInstallの元copy全位置を検査します
						const auto	 error =
							inspectRequiredServiceCopy( inf, section.data(), name, L"", source) ;
						// 不正な後続コピーも部分的な許可へ縮約しません
						if( error != 0) {
							return error ;
						}

						static_cast<void>( appendUnique( executables, std::move( source))) ;
					}
				} while( !direct && SetupFindNextLine( &file, &file)) ;
			}
		} while( SetupFindNextMatchLineW( &copy, L"CopyFiles", &copy)) ;
	}

	return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自身のfile作用を持たずInclude/Needsを継承する正式Systemの内容形式を確認します
 * @param[in] inf 同期中だけ借用する原INFです
 * @return 同じ原節にInclude/Needsを持ち、copy/source/serviceを宣言しない場合trueです
 * @note 継承先の実在・Windows由来・適合や導入許可を生成しません
 */
//------------------------------------------------------------------------------
bool isInheritedSystemContent( HINF inf)
{
	std::wstring guid ;	// 名称だけでSystem形式を認定しません
	// 元正式GUID以外は既存のsource検査を継続します
	if( readInfDirective( inf, L"Version", L"ClassGUID", 1U, guid) != 0 ||
	   !stringsEqual( guid, L"{4d36e97d-e325-11ce-bfc1-08002be10318}")) {
		return false ;
	}

	bool paired{} ;	// 元の同じ節でIncludeとNeedsを観測した場合だけ成立します
	// 全潜在節を読み、自身のコピーやserviceを継承だけの形式へ読み替えません
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U>
			section{} ;	// 同元INF内の有限名です
		// 正常な全節終端だけで形式を確定します
		if( !SetupEnumInfSectionsW( inf, index, section.data(), static_cast<UINT>( section.size()),
								  nullptr)) {
			return GetLastError() == ERROR_NO_MORE_ITEMS && paired ;
		}

		// 対象外architectureも含め、自身のsource宣言は既存検査から除きません
		const std::wstring_view sectionName{section.data()} ;	// 元名のcaseを変更しない比較viewです
		constexpr std::wstring_view SOURCE_PREFIX =
			L"SourceDisksFiles." ;	// architecture装飾の元prefixだけです
		// architecture装飾もcaseに依存せず元source宣言として扱います
		if( stringsEqual( sectionName, L"SourceDisksFiles") ||
		   (sectionName.size() >= SOURCE_PREFIX.size() &&
			stringsEqual( sectionName.substr( 0U, SOURCE_PREFIX.size()), SOURCE_PREFIX))) {
			return false ;
		}

		INFCONTEXT own{} ;	// 元の明示作用を照会するだけのcontextです
		// 欠損copy/serviceを正規のfileなし形式で救済しません
		if( SetupFindFirstLineW( inf, section.data(), L"CopyFiles", &own) ||
		   SetupFindFirstLineW( inf, section.data(), L"ServiceBinary", &own) ||
		   SetupFindFirstLineW( inf, section.data(), L"AddService", &own)) {
			return false ;
		}

		INFCONTEXT include{} ;	// 同じ原節の明示依存だけです
		INFCONTEXT needs{} ;	// 同じ原節の依存sectionだけです
		// Includeだけの記載や他節のNeedsで対を補完しません
		if( !SetupFindFirstLineW( inf, section.data(), L"Include", &include) ||
		   !SetupFindFirstLineW( inf, section.data(), L"Needs", &needs)) {
			continue ;
		}

		// 元fieldを有限に読み、継承元を任意pathや不正節名へ展開しません
		for( const bool files : {true, false}) {
			auto	  &line	 = files ? include : needs ;	// 同期中だけ借用する原contextです
			const auto count = SetupGetFieldCount( &line) ;	// 同原宣言の全field数です
			// 過大または空の依存を一部だけの対へ変えません
			if( count == 0U || count > 32U) {
				return false ;
			}

			// 宣言されたINF名または節名を原順で検査します
			for( DWORD field = 1U; field <= count; ++field) {
				std::wstring value ;	// 公開しない元依存名です
				// 不正名を別Windows INFや任意fileへ補正しません
				if( readInfField( line, field, value) != 0 ||
				   !validInstallInventorySectionName( value) ||
				   (files && lowerExtension( value) != L".inf")) {
					return false ;
				}
			}
		}

		paired = true ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 対象外と確定できるWindowsのarchitecture修飾を識別する
 * @param[in] decoration 区切りのdotを除いたarchitecture名
 * @return Windows x64で使用しない既知のarchitectureを名乗る場合true
 */
//------------------------------------------------------------------------------
bool isNonAmd64Decoration( std::wstring_view decoration)
{
	constexpr std::wstring_view names[]{L"NTx86", L"NTia64", L"NTarm",
										L"NTarm64"} ;	// 明示的な他architecture
	return isAllowedValue( decoration, names) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全Manufacturerの宣言が参照する潜在Modelsの元名を取得する
 * @param[in] inf 同期借用する読み取り専用INF
 * @param[in] amd64Only 明示的な他architectureだけを除く場合true
 * @param[out] models 元宣言の候補名。起点の存在は後段で照合する
 * @param[in,out] rows 今回の元宣言の読取予算
 * @param[in] nativeHdc 版指定のない明示AMD64行を持つHDCの旧Modelsを選択集合から外す場合true
 * @return 全件を有限に読取できた場合true。失敗時は部分出力を使用しない
 */
//------------------------------------------------------------------------------
bool collectDeclaredModelSections( HINF inf, bool amd64Only, std::vector<std::wstring> &models,
								  std::size_t &rows, bool nativeHdc = false)
{
	INFCONTEXT manufacturer{} ;	// 現OSだけへ縮約しない元全行です
	// 元ModelsのないSystemをnull driverと推測しません
	if( !SetupFindFirstLineW( inf, L"Manufacturer", nullptr, &manufacturer)) {
		return false ;
	}

	// 全manufacturerの装飾を原順に辿り、非x64行も内容から除きません
	do {
		std::wstring base ;											// 同じ原行だけのModels基名です
		const auto	 count = SetupGetFieldCount( &manufacturer) ;	// 元装飾の有限数です
		// 欠損・過大・不正節名を現在OSの正常節で補完しません
		if( ++rows > MAXIMUM_INSTALL_INVENTORY_LINES || count == 0U || count > 64U ||
		   readInfField( manufacturer, 1U, base) != 0 || !validInstallInventorySectionName( base)) {
			return false ;
		}

		std::wstring target ;	// 一つだけ宣言されたAMD64の元修飾名
		// 版指定なしの単一AMD64宣言が全対象を覆う場合だけ旧Modelsを除く
		const bool	 exactAmd64 = nativeHdc && amd64Only && count == 2U &&
								readInfField( manufacturer, 2U, target) == 0U &&
								stringsEqual( target, L"NTamd64") ;
		// OS版による絞り込みがある場合は、未修飾の候補も保持する
		if( !exactAmd64 && SetupGetLineCountW( inf, base.c_str()) >= 0) {
			static_cast<void>( appendUnique( models, base)) ;
		}

		// 版指定に一致しないWindowsが使う可能性のあるプラットフォーム用Modelsも含める
		if( amd64Only && !exactAmd64) {
			constexpr std::wstring_view fallbacks[]{L".NTamd64", L".NT"} ;	// x64またはNT共通の候補
			// 実在する各フォールバック節を明示装飾と同じ集合で確認する
			for( const auto suffix : fallbacks) {
				auto candidate = base + std::wstring( suffix) ;	// 元のフォールバック節名
				// 未定義の候補へ別の節の行を流用しない
				if( SetupGetLineCountW( inf, candidate.c_str()) >= 0L) {
					static_cast<void>( appendUnique( models, std::move( candidate))) ;
				}
			}
		}

		// 明示された全architecture/OS節を一件ずつ要求します
		for( DWORD field = 2U; field <= count; ++field) {
			std::wstring decoration ;	// 元TargetOSVersionを解釈し直しません
			// 不正装飾を別の節名へ補正しません
			if( readInfField( manufacturer, field, decoration) != 0 ||
			   !validInstallInventorySectionName( decoration)) {
				return false ;
			}

			const auto architecture =
				std::wstring_view( decoration)
					.substr( 0U, decoration.find( L'.')) ;	// 元TargetOSVersionの先頭
			// AMD64証明では明示的に異なる既知architectureだけを除く
			if( !amd64Only || !isNonAmd64Decoration( architecture)) {
				static_cast<void>( appendUnique( models, base + L"." + decoration)) ;
			}
		}

		// 未装飾だけを宣言した行にも実在Modelsを要求します
		if( count == 1U && SetupGetLineCountW( inf, base.c_str()) < 0) {
			return false ;
		}

		// 潜在Modelsを有限集合より増やしません
		if( models.size() > 128U) {
			return false ;
		}
	} while( SetupFindNextLine( &manufacturer, &manufacturer)) ;

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全Manufacturerの潜在ModelsとDDInstallの元名を既存行予算で読み取る
 * @param[in] inf 同期借用する元読取専用INF
 * @param[in] amd64Only 明示された他architectureを除く場合true
 * @param[out] models 元宣言のModels名
 * @param[out] bases 全Models行が指定するDDInstall基本名
 * @param[in,out] rows ManufacturerとModels全行の共有読取予算
 * @param[in] nativeHdc 明示AMD64だけを使うHDCの旧Models扱いを指定する
 * @return 全読取が成立した場合true。失敗時は部分出力を使用しない
 */
//------------------------------------------------------------------------------
bool collectDeclaredModelBases( HINF inf, bool amd64Only, std::vector<std::wstring> &models,
							   std::vector<std::wstring> &bases, std::size_t &rows,
							   bool nativeHdc = false)
{
	// Manufacturerの全宣言を確定できない場合は潜在導入名の証拠を作りません
	if( !collectDeclaredModelSections( inf, amd64Only, models, rows, nativeHdc)) {
		return false ;
	}

	// 全明示Modelsの全IDとDDInstallを検査し、異architectureの作用を隠しません
	for( const auto &model : models) {
		INFCONTEXT line{} ;	// 同じ元Modelsの現在行です
		// 明示空のModelsは該当するOSで導入しない指定として扱う
		if( amd64Only && SetupGetLineCountW( inf, model.c_str()) == 0L) {
			continue ;
		}

		// 存在しない/空Modelsからnull成功を生成しません
		if( !SetupFindFirstLineW( inf, model.c_str(), nullptr, &line)) {
			return false ;
		}

		// 同Modelsの全行を共有予算以内で検査します
		do {
			std::wstring base ;									// 原第1 fieldの役割を保持します
			const auto	 fields = SetupGetFieldCount( &line) ;	// ID省略を拒否します
			// 一部だけの正常Modelsを全体成功へ変換しません
			if( ++rows > MAXIMUM_INSTALL_INVENTORY_LINES || fields < 2U || fields > 64U ||
			   readInfField( line, 1U, base) != 0 || !validInstallInventorySectionName( base)) {
				return false ;
			}

			static_cast<void>( appendUnique( bases, std::move( base))) ;
			// 全fieldの元opaque IDを保持可能な文字境界で確認します
			for( DWORD field = 2U; field <= fields; ++field) {
				std::wstring id ;	// kindの書換えや区切り補完をしません
				// hidden architectureの不正IDもnull成功から除外します
				if( readInfField( line, field, id) != 0 || !validNativeModelsId( id)) {
					return false ;
				}
			}
		} while( SetupFindNextLine( &line, &line)) ;
	}

	return !bases.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元ストレージの基本導入節にあるプロパティページを一意に照合します
 * @param[in] inf 読取り中の同じ原INFです
 * @return 同じ元所有と元コピーの証拠です。不成立または関係なしでは空です
 * @note 空の結果は通常の全行検査に渡し、未検査の登録を許可しません
 */
//------------------------------------------------------------------------------
PropertyPageContext readCollectorStoragePropertyPage( HINF inf)
{
	std::wstring className ;	// 関係のないクラスの宣言を調べないための元クラス名です
	// 骨格の候補だけを選び、ClassGUIDと宣言の一意性は共通の所有検査へ渡します
	if( readInfDirective( inf, L"Version", L"Class", 1U, className) != 0U ||
	   !stringsEqual( className, L"SCSIAdapter")) {
		return {} ;
	}

	PropertyPageContext		  pages ;	// 全確認まで返さない同じ元INFの所有証拠です
	std::vector<std::wstring> bases ;	// 全元Manufacturerに結ばれたDDInstallです
	std::size_t				  rows{} ;	// メーカーと全Models行の共有観測数です
	// 他Modelsが別の導入節を指定する包材を同じ所有関係へまとめません
	if( !collectDeclaredModelBases( inf, false, pages.directModelSections, bases, rows) ||
	   bases.size() != 1U) {
		return {} ;
	}

	std::wstring install ;		// SetupAPIが現在の元INFから選んだ実在節です
	INFCONTEXT	 addReg{} ;		// 同じ基本導入節の直接登録です
	INFCONTEXT	 duplicate{} ;	// 同じ指示の二重指定を検出します
	std::wstring registry ;		// 元AddRegが指す一つの登録節です
	// 元Modelsと同名で選択成立した節の単独AddRegだけを所有元にします
	if( resolveActualInstallInventorySection( inf, bases.front(), install) != 0U ||
	   !stringsEqual( install, bases.front()) ||
	   !SetupFindFirstLineW( inf, install.c_str(), L"AddReg", &addReg) ||
	   SetupFindNextMatchLineW( &addReg, L"AddReg", &duplicate) ||
	   SetupGetFieldCount( &addReg) != 1U || readInfField( addReg, 1U, registry) != 0U ||
	   !validInstallInventorySectionName( registry)) {
		return {} ;
	}

	INFCONTEXT	 row{} ;		// 同じ元登録節の完全なREG_SZ行です
	std::wstring root ;			// 元機器ソフトウェアキーを指すHKRです
	std::wstring subkey ;		// 元機器キー直下を示す明示空です
	std::wstring valueName ;	// 正規プロパティページの元値名です
	// 別の作用を持たない単一登録から同じ署名済みDLLへ結び付けます
	if( SetupGetLineCountW( inf, registry.c_str()) != 1L ||
	   !SetupGetLineByIndexW( inf, registry.c_str(), 0U, &row) ||
	   readInfField( row, 1U, root) != 0U || !stringsEqual( root, L"HKR") ||
	   readInstallInventoryField( row, 2U, subkey) != 0U || !subkey.empty() ||
	   readInfField( row, 3U, valueName) != 0U || !stringsEqual( valueName, L"EnumPropPages32")) {
		return {} ;
	}

	constexpr std::uint32_t COPY_FLAGS = 0x4002U ;	// コピー省略不可と使用中コピーの原指定です
	// 元登録と同名System32コピーの全部が成立した場合だけ通常の署名検査へ渡します
	if( bindCollectorPropertyPage( inf, row, install, install, registry, pages, COPY_FLAGS) != 0U) {
		return {} ;
	}

	return pages ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Servicesの行が明示的な空の関連サービスを指定するか確認する
 * @param[in,out] line AddService指示を指す借用行
 * @return 空名と正確な関連サービスflagsだけの場合true
 */
//------------------------------------------------------------------------------
bool isAssociatedNullService( INFCONTEXT &line)
{
	std::wstring				  name ;		// 空欄を保持する元サービス名
	std::wstring				  rawFlags ;	// Windowsが読み取った全flags
	std::uint32_t				  flags{} ;		// 数値解析後の元値
	MaintenanceInfStructureReason reason{} ;	// 共通数値readerの診断
	return SetupGetFieldCount( &line) == 2U && readInstallInventoryField( line, 1U, name) == 0 &&
		   name.empty() && readInstallInventoryField( line, 2U, rawFlags) == 0 &&
		   parseMaintenanceFlags( rawFlags, flags, reason).state ==
			   MaintenanceInspectionState::PASSED &&
		   flags == SPSVCINST_ASSOCSERVICE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 標準Windowsシリアルポートのページ値を完全名で照合する
 * @param[in] value 元のデバイス相対登録の文字列値
 * @return 標準DLLのleafと大小文字を区別する実export名が一致する場合true
 * @note DLLの実在、署名、exportは後段で固定ファイルに対して確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isStandardSerialPropertyPage( std::wstring_view value)
{
	const auto comma = value.find( L',') ;	// DLLとexportの境界
	// 境界がない値を別形式のページ名から補わない
	if( comma == value.npos) {
		return false ;
	}

	const auto library		 = value.substr( 0U, comma) ;				// 元のDLL leaf
	const auto function		 = value.substr( comma + 1U) ;				// 元のexport名
	const auto libraryEnd	 = library.find_last_not_of( L" \t") ;		// 区切り直前の空白
	const auto functionStart = function.find_first_not_of( L" \t") ;	// 区切り直後の空白
	return libraryEnd != library.npos && functionStart != function.npos &&
		   stringsEqual( library.substr( 0U, libraryEnd + 1U), L"MsPorts.dll") &&
		   function.substr( functionStart) == L"SerialPortPropPageProvider" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Ports基本節の唯一のAddRegが標準Windowsプロパティページを指定することを確認する
 * @param[in] inf 同期中に借用する元INFです
 * @param[in] base 元Modelsが選んだ実在DDInstallです
 * @param[out] registry 成功時に元所有の登録節名を保存します
 * @return HKRの単一REG_SZ、同じDLL名、完全なexport名に一致する場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readInboxPortsPropertyPage( HINF inf, const std::wstring &base,
											  std::wstring &registry)
{
	INFCONTEXT directive{} ;	// 元基本節が直接所有するAddRegです
	INFCONTEXT entry{} ;		// 同じAddRegが参照する唯一の元データ行です
	// 別の基本節や付随節の登録を、この選択の所有に読み替えません
	if( !SetupFindFirstLineW( inf, base.c_str(), L"AddReg", &directive) ||
	   SetupGetFieldCount( &directive) != 1U || readInfField( directive, 1U, registry) != 0 ||
	   !validInstallInventorySectionName( registry) ||
	   SetupGetLineCountW( inf, registry.c_str()) != 1L ||
	   !SetupGetLineByIndexW( inf, registry.c_str(), 0U, &entry) ||
	   SetupGetFieldCount( &entry) != 5U) {
		return false ;
	}

	std::wstring key ;		// 名前付きdirectiveを無名データ行と混同しません
	std::wstring root ;		// 元HKRの書込み先です
	std::wstring subkey ;	// 元デバイスキーの直下だけを採用します
	std::wstring name ;		// 元登録の値名です
	std::wstring value ;	// 元DLL名とexportを含む単一値です
	// 型、元キーとスコープが異なる登録は従来の検査へ残します
	if( readInstallInventoryField( entry, 0U, key) != nativeErrorFromWin32( ERROR_INVALID_PARAMETER) ||
	   readInfField( entry, 1U, root) != 0 || !stringsEqual( root, L"HKR") ||
	   readInstallInventoryField( entry, 2U, subkey) != 0 || !subkey.empty() ||
	   readInfField( entry, 3U, name) != 0 || !stringsEqual( name, L"EnumPropPages32") ||
	   !propertyPageNumber( entry, 4U, 0U, true) || readInfField( entry, 5U, value) != 0) {
		return false ;
	}

	return isStandardSerialPropertyPage( value) ;
}

/** @brief 収集のために元の作用を照合する同梱INFの種類です */
enum class CollectorInboxKind {
	/// SDバスの元選択です
	SD_HOST,
	/// シリアルとプロパティページの元選択です
	PORTS,
	/// Windows標準NVMeへ空媒体で委譲する元選択です
	NVME,
	/// Windows標準AHCIへ空媒体で委譲する元選択です
	AHCI
} ;

//------------------------------------------------------------------------------
/**
 * @brief NVMe元基本節のコピー・削除参照がそれぞれ実在する空節かを確認する
 * @param[in] inf 同期中に借用する元INFです
 * @param[in] base SetupAPIが選択した実在の元基本節です
 * @param[out] lists 成功時だけコピーと削除の正確な参照名を保持します
 * @return 両方の参照が別々の空節へ一意に結び付く場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readInboxNvmeEmptyLists( HINF inf, const std::wstring &base,
										   OfficialInfInboxNvmeLists &lists)
{
	const auto read = [&]( const wchar_t *key, std::wstring &list) {
		INFCONTEXT line{} ;			// 元基本節が直接宣言する一行です
		INFCONTEXT duplicate{} ;	// 同じ指定が追加されていないことを確認します
		// 直接コピーや実在しない節を空リストに読み替えません
		if( !SetupFindFirstLineW( inf, base.c_str(), key, &line) ||
		   SetupFindNextMatchLineW( &line, key, &duplicate) || SetupGetFieldCount( &line) != 1U ||
		   readInfField( line, 1U, list) != 0 || !validInstallInventorySectionName( list) ||
		   list.front() == L'@' || SetupGetLineCountW( inf, list.c_str()) != 0L) {
			return false ;
		}

		LONG securityRows{} ;	// 空リストに付随する権限指定の有無です
		return maintenanceLineCount( inf, list + L".security", securityRows) == 0 &&
			   securityRows == -1L ;
	} ; // 同じ元基本節に属するリスト宣言だけを読みます
	return read( L"CopyFiles", lists.copy) && read( L"DelFiles", lists.remove) &&
		   !stringsEqual( lists.copy, lists.remove) ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVMe元INFの媒体名が未使用の表示ラベルだけかを確認する
 * @param[in] inf 同期中に借用する元INFです
 * @return 媒体識別子1の単独表示名だけが所在を指さず宣言されている場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isInboxNvmeMediaLabel( HINF inf)
{
	INFCONTEXT	 line{} ;	// 元媒体表で唯一認める一行です
	std::wstring label ;	// ファイル位置を持たない元表示名です
	std::wstring value ;	// タグ・未使用欄・媒体位置を空値として確認します
	return SetupGetLineCountW( inf, L"SourceDisksNames") == 1L &&
		   SetupFindFirstLineW( inf, L"SourceDisksNames", L"1", &line) &&
		   SetupGetFieldCount( &line) == 4U && readInfField( line, 1U, label) == 0 &&
		   !label.empty() && readInstallInventoryField( line, 2U, value) == 0 && value.empty() &&
		   readInstallInventoryField( line, 3U, value) == 0 && value.empty() &&
		   readInstallInventoryField( line, 4U, value) == 0 && value.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows標準INFへ委譲する元導入節を収集検査用に抽出する
 * @param[in] inf 同期中に借用する原INFです
 * @param[in] kind 読み取る標準INFへの元委譲形式です
 * @param[out] package 正式GUIDと実在する検査seed群を保持します
 * @return 元選択と空媒体を確認した場合0、読み取り・不正構造・容量失敗のHRESULTです
 * @note CATや依存の成功はこの関数の後段で検証します
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectInboxInstallGroups( HINF inf, CollectorInboxKind kind,
													OfficialInfPackage &package)
{
	const bool ports = kind == CollectorInboxKind::PORTS ;	// 元基本節にPortsページがある形式です
	const bool nvme	 = kind == CollectorInboxKind::NVME ;	// 元コピーと削除が空のNVMe形式です
	const bool ahci	 = kind == CollectorInboxKind::AHCI ;	// 標準AHCIへ三つの節を委譲する形式です
	const std::wstring_view classGuid =
		ahci	? HDC_CLASS.back()
		: nvme	? L"{4d36e97b-e325-11ce-bfc1-08002be10318}"
		: ports ? L"{4d36e978-e325-11ce-bfc1-08002be10318}"
				: L"{a0a588a4-c46f-4b37-b7ea-c82fe89870c6}" ;	// 元形式の正式GUIDです
	INFCONTEXT first{} ;										// Class名またはGUIDの先頭行です
	INFCONTEXT duplicate{} ;									// 同じkeyの追加行を検出します
	const auto error = readInfDirective( inf, L"Version", L"ClassGUID", 1U,
										package.classGuid) ;	// 元GUIDの読取結果です
	// 正式な対を確認し、重複行や後続fieldに別の対を隠せないようにします
	if( error != 0 || !stringsEqual( package.classGuid, classGuid) ||
	   !SetupFindFirstLineW( inf, L"Version", L"ClassGUID", &first) ||
	   SetupGetFieldCount( &first) != 1U ||
	   SetupFindNextMatchLineW( &first, L"ClassGUID", &duplicate) ||
	   !SetupFindFirstLineW( inf, L"Version", L"Class", &first) ||
	   SetupGetFieldCount( &first) != 1U || SetupFindNextMatchLineW( &first, L"Class", &duplicate)) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::vector<std::wstring> models ;			// 全architectureのModels名です
	std::vector<std::wstring> declaredBases ;	// 全Modelsにある元基本名です
	std::size_t				  rows{} ;			// 全宣言を共有する行予算です
	// 全元Modelsを確認し、アーキテクチャ別のModelsを作用節として扱いません
	if( !collectDeclaredModelBases( inf, false, models, declaredBases, rows)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	MaintenanceStructureBudget budget ;	// 現在OSが選ぶModelsの読取予算です
	std::vector<std::wstring>  bases ;	// 適用可能なModelsにある基本名です
	auto					   result =
		// 現在OSでの選択結果です
		collectMaintenanceInstallNames( inf, budget, bases, ports || nvme || ahci) ;
	// SetupAPIが選ぶ全Modelsが特定できた場合だけ、依存検査を要求できます
	if( result != 0) {
		return result ;
	}

	std::vector<std::wstring> selectedSections ;	// 同じ実在DDInstallを一件にまとめます
	// 現在OS用の各基本名を、そのOSで実在する節へ解決します
	for( const auto &base : bases) {
		std::wstring selected ;	// SetupAPIが選んだ実在節名です
		result = resolveActualInstallInventorySection( inf, base, selected) ;
		// 一つの選択失敗を他の正常選択で補いません
		if( result != 0) {
			return result ;
		}

		static_cast<void>( appendUnique( selectedSections, std::move( selected))) ;
	}

	std::vector<std::wstring> verifiedSections ;	// 空媒体の元構造が成立した節の集合です
	// ページや空リストの所有は元基本節一つに固定します
	if( (ports || nvme || ahci) && selectedSections.size() != 1U) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// AHCI原配布のOEMパッケージ条件に別の作用や式を追加しない
	if( ahci) {
		const std::wstring metadata = L"PackageInfo" ;	// OEM元配布が宣言した既知の節
		std::wstring	   name, condition ;			// 元の表示名とOEMパッケージ条件
		// 元配布が持つ二行を両方読み、条件を推定で補わない
		if( SetupGetLineCountW( inf, metadata.c_str()) != 2L ||
		   readRequiredServiceField( inf, metadata, L"Name", name) != 0 || name != L"Chipset" ||
		   readRequiredServiceField( inf, metadata, L"Condition", condition) != 0 ||
		   condition != L"Provider(Microsoft)||InstalledDriverName(Chipset)||Provider()") {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	// 各実在DDInstallとその付随節を同じ検査単位に保ちます
	for( const auto &selected : selectedSections) {
		std::vector<std::wstring> seeds{selected} ;	// 先頭は元の実DDInstallです
		// 元DDInstallと同じ修飾を持つHWとServicesだけを追加します
		for( const auto *suffix : {L".HW", L".Services"}) {
			const auto section = selected + suffix ;	// 読み取る付随節名です
			LONG	   count{} ;						// 不在と明示空を区別する行数です
			result = maintenanceLineCount( inf, section, count) ;
			// API失敗を節不在として扱いません
			if( result != 0) {
				return result ;
			}

			// 実在する節は空であっても後段の構造検査へ渡します
			if( count >= 0L) {
				seeds.push_back( section) ;
			}
		}

		// Portsの元基本節だけに、正規Windowsページの元AddRegと同じ所有節を認めます
		if( ports &&
		   !readInboxPortsPropertyPage( inf, selected, package.collectorInboxPropertyPageSection)) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// NVMeは元の三節と空リストを確認し、媒体の欠測と区別します
		if( nvme &&
		   (seeds.size() != 3U || SetupGetLineCountW( inf, L"SourceDisksFiles") != 0L ||
			!readInboxNvmeEmptyLists( inf, selected, package.collectorInboxNvmeLists.emplace()))) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// 標準AHCIの空媒体と唯一の基本節の順位、同じ選択の三節を確認する
		if( ahci) {
			std::wstring score ;	// 元基本節に明示されたrankの一要素
			// 不在や別の元順位を空媒体の成功に含めない
			if( seeds.size() != 3U || SetupGetLineCountW( inf, L"SourceDisksNames") != 0L ||
			   SetupGetLineCountW( inf, L"SourceDisksFiles") != 0L ||
			   readRequiredServiceField( inf, selected, L"FeatureScore", score) != 0 ||
			   score != L"80") {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}
		}

		// 各元選択節の明示した委譲と、確認した単独のページだけを扱います
		for( const auto &seed : seeds) {
			INFCONTEXT include{} ;	// 同じ元節のInclude行です
			INFCONTEXT needs{} ;	// 同じ元節のNeeds行です
			const bool ownsPage =
				ports && stringsEqual( seed, selected) ;	// 元基本節の一作用だけが増えます
			const bool ownsEmptyLists =
				nvme && stringsEqual( seed, selected) ;	// 元基本節の二つの空リストだけです
			const bool ownsFeatureScore =
				ahci && stringsEqual( seed, selected) ;	// 同じ基本節の順位宣言
			// 依存宣言以外の行や片側だけの参照を許可しません
			if( SetupGetLineCountW( inf, seed.c_str()) != (ownsEmptyLists					  ? 4L
														 : (ownsPage || ownsFeatureScore) ? 3L
																						  : 2L) ||
			   !SetupFindFirstLineW( inf, seed.c_str(), L"Include", &include) ||
			   !SetupFindFirstLineW( inf, seed.c_str(), L"Needs", &needs)) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			std::wstring included ;	// 元Portsが明示するWindows標準INF名です
			// Portsの限定ページと別の委譲先を同じ検査へ混ぜません
			if( ports && (SetupGetFieldCount( &include) != 1U || SetupGetFieldCount( &needs) != 1U ||
						 readInfField( include, 1U, included) != 0 ||
						 !stringsEqual( included, L"msports.inf"))) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// ストレージの三つの元節を、正規Windows INFの対応作用へ一対一で結ぶ
			if( nvme || ahci) {
				std::wstring needed ;												// 元INFが明示した委譲先の節です
				const auto	*file	= ahci ? L"mshdc.inf" : L"stornvme.inf" ;		// 正規Windowsの元INF名
				const auto	*base	= ahci ? L"msahci_Inst" : L"Stornvme_Inst" ;	// Windows側の基本節
				const auto	 target = base + seed.substr( selected.size()) ;		// 元の節種別を保持します
				// 複数の参照や別の標準INFを同じ証拠へ結びません
				if( SetupGetFieldCount( &include) != 1U || SetupGetFieldCount( &needs) != 1U ||
				   readInfField( include, 1U, included) != 0 || !stringsEqual( included, file) ||
				   readInfField( needs, 1U, needed) != 0 || !stringsEqual( needed, target)) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}
			}

			static_cast<void>( appendUnique( verifiedSections, seed)) ;
		}

		package.collectorInboxInstallGroups.push_back( std::move( seeds)) ;
	}

	// 全節を検査し、媒体や別の作用への参照が潜在節にないことを確認します
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U>
			buffer{} ;	// 列挙した元節名の固定領域です
		// 全節を正常に読み終えた場合だけ、元構造を成功とします
		if( !SetupEnumInfSectionsW( inf, index, buffer.data(), static_cast<UINT>( buffer.size()),
								  nullptr)) {
			const DWORD enumerationError = GetLastError() ;	// 正常終端か元API失敗かを示します
			return enumerationError == ERROR_NO_MORE_ITEMS ? 0
														   : nativeErrorFromWin32( enumerationError) ;
		}

		const std::wstring_view section{buffer.data()} ;	// 元の修飾を含む節名です
		const auto				prefix =
			// 媒体宣言は全architectureを検査します
			section.substr( 0U, section.find( L'.')) ;
		// 空媒体には各元形式の未使用の既定宛先だけを認めます
		if( (ports || nvme) && stringsEqual( section, L"DestinationDirs") &&
		   SetupGetLineCountW( inf, buffer.data()) == 1L) {
			INFCONTEXT destination{} ;	// 元が宣言した一つの既定宛先です
			// その他の媒体定義やsubdirectoryを無作用にはしません
			if( !SetupFindFirstLineW( inf, buffer.data(), L"DefaultDestDir", &destination) ||
			   SetupGetFieldCount( &destination) != 1U ||
			   !propertyPageNumber( destination, 1U, nvme ? 12U : 11U, false)) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			continue ;
		}

		// NVMeは元の表示名だけを持つ共通媒体行を使用できます
		if( nvme && stringsEqual( section, L"SourceDisksNames") && isInboxNvmeMediaLabel( inf)) {
			continue ;
		}

		// 宣言された媒体と宛先は、どの修飾でも空であることを要求します
		if( stringsEqual( prefix, L"SourceDisksFiles") || stringsEqual( prefix, L"SourceDisksNames") ||
		   stringsEqual( section, L"DestinationDirs")) {
			// 実行時媒体や照会失敗があれば継承形式として扱いません
			if( SetupGetLineCountW( inf, buffer.data()) != 0L) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			continue ;
		}

		// Versionは他INFの媒体表を参照できるため、別途確認します
		if( stringsEqual( section, L"Version")) {
			INFCONTEXT line{} ;	// 他INFの媒体参照を調べるための行です
			// 別の媒体やINFを持ち込むVersionの参照を空媒体扱いしません
			if( SetupFindFirstLineW( inf, buffer.data(), L"LayoutFile", &line)) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			continue ;
		}

		// 選択外節や未知の付随節を検査済みの導入作用へ含めません
		if( !stringsEqual( section, L"Manufacturer") && !stringsEqual( section, L"ControlFlags") &&
		   !(ahci && stringsEqual( section, L"PackageInfo")) && !stringsEqual( prefix, L"Strings") &&
		   !stringsEqual( section, package.collectorInboxPropertyPageSection) &&
		   !(nvme && (stringsEqual( section, package.collectorInboxNvmeLists->copy) ||
					  stringsEqual( section, package.collectorInboxNvmeLists->remove))) &&
		   !std::ranges::any_of( models,
								[&]( const auto &name) { return stringsEqual( name, section) ; }) &&
		   !std::ranges::any_of( verifiedSections,
								[&]( const auto &name) { return stringsEqual( name, section) ; })) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正式Systemの必須null importを全architectureと全節の閉集合で確認します
 * @param[in] inf 同期中だけ借用する原INFです
 * @return 全Modelsが実在空DDInstallと正確な空名flags2 serviceだけを参照する場合trueです
 * @note source/copy/未知作用を省略しません。現在OSの一選択だけで別architectureを救済しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isRequiredNullSystemContent( const HINF inf)
{
	std::wstring guid ;			// 名称だけで正式Systemを認定しません
	INFCONTEXT	 guidLine{} ;	// 同じ元Versionの一意性だけを確認します
	INFCONTEXT	 duplicate{} ;	// 別値を先頭値で隠しません
	// 異なるClassGUIDや重複GUIDをfileなし例外へ渡しません
	if( readInfDirective( inf, L"Version", L"ClassGUID", 1U, guid) != 0 ||
	   !stringsEqual( guid, L"{4d36e97d-e325-11ce-bfc1-08002be10318}") ||
	   !SetupFindFirstLineW( inf, L"Version", L"ClassGUID", &guidLine) ||
	   SetupFindNextMatchLineW( &guidLine, L"ClassGUID", &duplicate)) {
		return false ;
	}

	std::vector<std::wstring> models ;	// 元全architectureのModels
	std::vector<std::wstring> bases ;	// 元全Modelsが指定するDDInstall
	std::size_t				  rows{} ;	// 元宣言と全節の共有行予算
	// 全潜在Modelsを読めない場合はnull形式を認めない
	if( !collectDeclaredModelBases( inf, false, models, bases, rows)) {
		return false ;
	}

	std::size_t				  services{} ;		// 正確な空serviceだけを数えます
	std::vector<std::wstring> observedBases ;	// 全Modelsの参照先が実在することを確認します
	// 全潜在節を閉集合へ照合し、source/隠れたcopy/作用の取りこぼしを防ぎます
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> buffer{} ;	// 有限元名です
		// 全節の正常終端だけでnull形式を確定します
		if( !SetupEnumInfSectionsW( inf, index, buffer.data(), static_cast<UINT>( buffer.size()),
								  nullptr)) {
			return GetLastError() == ERROR_NO_MORE_ITEMS && services != 0U && !bases.empty() &&
				   observedBases.size() == bases.size() ;
		}

		const std::wstring section{buffer.data()} ;	// 元caseを維持する名前です
		const auto		   inModels = std::ranges::any_of( models, [&]( const auto &name) {
			return stringsEqual( section, name) ;
		}) ; // 先に全行を検査したModelsだけです
		// 文字列とModels自体は作用節ではありません
		if( inModels || stringsEqual( section, L"Manufacturer") ||
		   stringsEqual( section, L"Strings") ||
		   (section.size() > 8U &&
			stringsEqual( std::wstring_view{section}.substr( 0U, 8U), L"Strings."))) {
			continue ;
		}

		// 閉じたnull形式だけで標準媒体節の明示空を扱います
		if( stringsEqual( section, L"SourceDisksFiles") ||
		   stringsEqual( section, L"SourceDisksFiles.amd64") ||
		   stringsEqual( section, L"SourceDisksFiles.arm64") ||
		   stringsEqual( section, L"SourceDisksFiles.ia64") ||
		   stringsEqual( section, L"SourceDisksFiles.x86") ||
		   stringsEqual( section, L"SourceDisksNames") ||
		   stringsEqual( section, L"SourceDisksNames.amd64")) {
			// 非空や読取失敗をsource欠落と同じ成功へ変えません
			if( SetupGetLineCountW( inf, section.c_str()) != 0L) {
				return false ;
			}

			continue ;
		}

		// Version/ControlFlagsにも未知作用や参照を追加させません
		if( stringsEqual( section, L"Version") || stringsEqual( section, L"ControlFlags")) {
			INFCONTEXT line{} ;	// 全元metadata行です
			// 明示空metadataは追加作用を持ちません
			if( !SetupFindFirstLineW( inf, section.c_str(), nullptr, &line)) {
				continue ;
			}

			// 必須値は通常構造検査が要求し、ここでは未知keyを拒否します
			do {
				std::wstring		 key ;	// 作用をmetadataへ読み替えません
				constexpr std::array VERSION_KEYS{
					std::wstring_view{L"Signature"},  std::wstring_view{L"Class"},
					std::wstring_view{L"ClassGUID"},  std::wstring_view{L"Provider"},
					std::wstring_view{L"DriverVer"},  std::wstring_view{L"CatalogFile"},
					std::wstring_view{L"PnpLockdown"}} ;	// 狭いnull形式だけです
				// 知らないfile作用や全体registry作用を無視しません
				if( ++rows > MAXIMUM_INSTALL_INVENTORY_LINES || readInfField( line, 0U, key) != 0 ||
				   (stringsEqual( section, L"Version")
						? (!isAllowedValue( key, VERSION_KEYS) &&
						   !(key.size() > 12U &&
							 stringsEqual( std::wstring_view{key}.substr( 0U, 12U), L"CatalogFile.")))
						: !stringsEqual( key, L"ExcludeFromSelect"))) {
					return false ;
				}
			} while( SetupFindNextLine( &line, &line)) ;
			continue ;
		}

		constexpr std::wstring_view SUFFIX = L".Services" ;	// 元DDInstallへの結合だけです
		const bool					service =
			section.size() > SUFFIX.size() &&
			stringsEqual( std::wstring_view{section}.substr( section.size() - SUFFIX.size()),
						 SUFFIX) ;	// 空service形式です
		const auto install = service ? section.substr( 0U, section.size() - SUFFIX.size())
									 : section ;	// 元空DDInstallです
		const bool belongs = std::ranges::any_of( bases, [&]( const auto &base) {
			return stringsEqual( install, base) ||
				   (install.size() > base.size() && install[base.size()] == L'.' &&
					stringsEqual( std::wstring_view{install}.substr( 0U, base.size()), base)) ;
		}) ; // 全元Modelsの基本名だけを借用します
		// 未参照節も含め、追加file/registry/service節を空成功へ救済しません
		if( !belongs || SetupGetLineCountW( inf, install.c_str()) != 0L ||
		   SetupGetLineCountW( inf, (install + std::wstring{SUFFIX}).c_str()) != 1L) {
			return false ;
		}

		// Modelsが列挙した各基本名に実在する空DDInstallを要求します
		for( const auto &base : bases) {
			// 同じ元基本名の装飾節だけを既検査として記録します
			if( stringsEqual( install, base) ||
			   (install.size() > base.size() && install[base.size()] == L'.' &&
				stringsEqual( std::wstring_view{install}.substr( 0U, base.size()), base))) {
				static_cast<void>( appendUnique( observedBases, base)) ;
			}
		}

		// 空DDInstallは対になる正確なservice節で後続検査します
		if( !service) {
			continue ;
		}

		INFCONTEXT line{} ;	// 唯一の元AddService
		// 空名とASSOCSERVICEだけをnullの根拠とする
		if( !SetupFindFirstLineW( inf, section.c_str(), L"AddService", &line) ||
		   !isAssociatedNullService( line)) {
			return false ;
		}

		++services ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief システム定義の節の基名と任意の装飾境界を区別する
 * @param[in] name 元INFで列挙された節名
 * @param[in] base 既知のシステム定義節の基名
 * @return 完全な基名かドット装飾付きの場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesInfSectionFamily( std::wstring_view name, std::wstring_view base)
{
	return stringsEqual( name, base) || (name.size() > base.size() && name[base.size()] == L'.' &&
										stringsEqual( name.substr( 0U, base.size()), base)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Modelsの基本導入名が同じModelsを処理節または付随節として参照するか調べる
 * @param[in] modelName 署名と全行証拠を確認した保護対象の節名
 * @param[in] installBase Manufacturerが宣言したModels行の導入基本名
 * @return Windowsの基本導入節・付随節になり得る形で一致した場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool usesModelsAsInstallSection( std::wstring_view modelName,
											  std::wstring_view installBase)
{
	// DDInstallの基本名に付加される登録・導入用の節接尾辞
	constexpr std::array<std::wstring_view, 11> companion{
		L"HW",	L"Services", L"CoInstallers",	   L"Interfaces", L"Components", L"Software",
		L"Wdf", L"Events",	 L"LogConfigOverride", L"FactDef",	  L"Filters"} ;
	// 基本名からの関係を調べるために認識する既存のプラットフォーム装飾
	constexpr std::array<std::wstring_view, 6> platform{L"NT",		L"NTamd64", L"NTx86",
														L"NTarm64", L"NTarm",	L"NTia64"} ;
	// 基本導入名と完全一致するModelsは別用途と衝突します
	if( stringsEqual( modelName, installBase)) {
		return true ;
	}

	// 同じ導入基本名の系列以外の節を別用途の参照に数えません
	if( !matchesInfSectionFamily( modelName, installBase)) {
		return false ;
	}

	// 同系列と確認したModels名から切り出した装飾部分
	const auto suffix = modelName.substr( installBase.size() + 1U) ;
	// プラットフォーム装飾と付随節名の区切り位置
	const auto dot = suffix.find( L'.') ;
	return isAllowedValue( suffix, companion) || isAllowedValue( suffix, platform) ||
		   (dot != suffix.npos && isAllowedValue( suffix.substr( 0U, dot), platform) &&
			isAllowedValue( suffix.substr( dot + 1U), companion)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全節走査の一行から、署名済みModelsを別用途で指定する参照だけを拒否する
 * @param[in] line SetupAPIが返した同INFの行
 * @param[in] sectionName この行の元セクション名
 * @param[in] key Windowsが展開した行キー
 * @param[in] modelRow Manufacturerで宣言済みのModels行ならtrue
 * @param[in] models 別用途の読取りを禁止する公式Models節
 * @return 兼用がなければ0、参照読取不能・容量・節兼用はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError checkScopedModelsRole(
	INFCONTEXT &line, std::wstring_view sectionName, std::wstring_view key, bool modelRow,
	std::span<const OfficialInfScopedModelsSection> models)
{
	// 署名済みModelsを別用途で使う参照に共通の拒否値
	const auto invalid = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	// 借用したModels一覧を参照し、指定名と完全一致する節を調べる同期比較
	const auto namesModel = [&]( std::wstring_view name) {
		return std::ranges::any_of(
			models, [name]( const auto &model) { return stringsEqual( model.modelSection, name) ; }) ;
	} ;
	// Models行自体では最初のフィールドを導入基本名として検査します
	if( modelRow) {
		std::wstring base ;	// 元Models行第1フィールドの導入基本名
		// 元Models行の導入名を読んだ際の診断値
		const auto	 error = readInfField( line, 1U, base) ;
		// 導入基本名の読取り失敗を無参照として扱いません
		if( error != 0) {
			return error ;
		}

		return std::ranges::any_of( models,
								   [&]( const auto &model) {
									   return usesModelsAsInstallSection( model.modelSection, base) ;
								   })
				   ? invalid
				   : 0 ;
	}

	// 既知のデータセクション内のキーや文字列に参照の意味を与えない
	if( matchesInfSectionFamily( sectionName, L"Strings") ||
	   stringsEqual( sectionName, L"Manufacturer") || stringsEqual( sectionName, L"Version") ||
	   stringsEqual( sectionName, L"ControlFlags") ||
	   matchesInfSectionFamily( sectionName, L"SourceDisksFiles") ||
	   matchesInfSectionFamily( sectionName, L"SourceDisksNames")) {
		return 0 ;
	}

	// 配置先一覧でModels名がCopyFilesリストとして参照される形を拒否します
	if( stringsEqual( sectionName, L"DestinationDirs")) {
		return namesModel( key) ? invalid : 0 ;
	}

	// 最初のフィールドから順に別用途の節を列挙するディレクティブ
	constexpr std::array<std::wstring_view, 18> lists{L"CopyFiles",
													  L"DelFiles",
													  L"RenFiles",
													  L"AddReg",
													  L"DelReg",
													  L"BitReg",
													  L"AddProperty",
													  L"DelProperty",
													  L"LogConfig",
													  L"ProfileItems",
													  L"UpdateInis",
													  L"UpdateIniFields",
													  L"Ini2Reg",
													  L"Needs",
													  L"RegisterDlls",
													  L"UnregisterDlls",
													  L"RunPreSetupCommands",
													  L"RunPostSetupCommands"} ;
	// 第2フィールドを他の節への参照として調べるディレクティブ
	constexpr std::array<std::wstring_view, 5>	second{L"KmdfService", L"UmdfService",
													   L"AddEventProvider", L"UpdateAutoLogger",
													   L"AddAutoLoggerProvider"} ;
	// 第3フィールドを他の節への参照として調べるディレクティブ
	constexpr std::array<std::wstring_view, 6>	third{L"AddInterface",	L"AddComponent",
													  L"AddSoftware",	L"AddFilter",
													  L"AddAutoLogger", L"AddChannel"} ;
	// 今回のINF行でSetupAPIが認識したフィールド数
	const DWORD									fields = SetupGetFieldCount( &line) ;
	// 別用途の節を参照するフィールドの先頭と末尾。未指定の位置は0
	DWORD										first{}, last{} ;
	// 節の一覧を取る命令では最初から該当フィールドを照合します
	if( isAllowedValue( key, lists) || stringsEqual( key, L"AddTrigger")) {
		first = 1U ;
		last  = fields ;
	}
	// インターフェース導入節と障害時動作は先頭フィールドを照合します
	else if( matchesInfSectionFamily( sectionName, L"InterfaceInstall32") ||
			stringsEqual( key, L"FailureActions")) {
		first = last = 1U ;
	}
	// 第2フィールドが処理節を指す命令では、その位置だけを判定します
	else if( isAllowedValue( key, second)) {
		first = last = 2U ;
	}
	// 第3フィールドが処理節を指す命令では、その位置だけを判定します
	else if( isAllowedValue( key, third)) {
		first = last = 3U ;
	}
	// サービス登録では定義本体と後続のイベント節の位置を区別します
	else if( stringsEqual( key, L"AddService")) {
		first = 3U ;
		last  = 4U ;
	} else {
		return 0 ;
	}

	// 元行のフィールド上限を超えた場合は部分的な照合を返しません
	if( fields > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	// 単独ファイルの表記を節への参照から除外するCopyFilesかを保持します
	const bool copy = stringsEqual( key, L"CopyFiles") ;
	// 指定したリストに付随するSecurity節も検査する必要があるかを示します
	const bool hasSecurity = copy || stringsEqual( key, L"AddReg") ;
	// 節参照が定義されるフィールドを実フィールド数まで走査します
	for( DWORD field = first; field <= std::min( last, fields); ++field) {
		std::wstring name ;	// 実際に節参照を持つ位置の元展開値
		// その位置の元展開値を読み取った診断値
		const auto	 error = readInstallInventoryField( line, field, name) ;
		// 展開値が不明な参照を空の参照として通しません
		if( error != 0) {
			return error ;
		}

		// Models名または暗黙のSecurity節と衝突する別用途を拒否します
		if( !name.empty() && !(copy && name.starts_with( L"@")) &&
		   (namesModel( name) || (hasSecurity && namesModel( name + L".Security")))) {
			return invalid ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元現在OS選択からCopyINFと必要SWC関係を有限に解析します
 * @param[in] inf 呼出し終了まで生存する読取専用Windows INFです
 * @param[in] workspace 安全な相対pathだけを解決する保護所有者です
 * @param[in] entries 元archiveの有限inventoryです
 * @param[in,out] package 既にClass/ID/参照fileを検査した元metadataです
 * @param[in] selectedBasicSection 私有nodeで確認した基本名です。空なら全importの内容関係だけを解析します
 * @param[in] cancellation 公式Modelsの収集処理と同じ取消し照会です
 * @param[in] scopedRow 元INFを固定して全Modelsを照合した同じ行です。通常解析と内容解析ではnullです
 * @return 全関係解析0、欠損・曖昧・role不一致・容量・未対応は元HRESULTです
 * @note byte/CATの検査や導入は呼出し側です。Include/Needsの充足を推測しません
 */
//------------------------------------------------------------------------------
NativeError inspectRequiredDriverRelations( HINF inf, const OfficialDownloadWorkspace &workspace,
										   std::span<const OfficialZipEntry> entries,
										   OfficialInfPackage				&package,
										   std::wstring_view			selectedBasicSection = {},
										   const std::function<bool()> *cancellation	= nullptr,
										   const OfficialInfScopedModelMatch *scopedRow = nullptr)
{
	// 役割は元Classの正式値だけから決め、名称や公開索引の申告を使いません
	if( stringsEqual( package.className, L"Extension")) {
		package.role = DriverPlanRole::EXTENSION ;
	}

	// SoftwareComponentも正式Classだけで分類し、Extensionの規則を借用しません
	if( stringsEqual( package.className, L"SoftwareComponent")) {
		package.role = DriverPlanRole::DRIVER_COMPONENT ;
	}

	// 公式範囲では全Modelsを確認した元行がある場合だけ実導入節を読みます
	if( scopedRow && (!package.scopedModels || scopedRow->modelRow == 0U ||
					 !stringsEqual( selectedBasicSection, scopedRow->installBase))) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 公式Modelsの証拠は、同じ基本ドライバーと元の選択行に限定します
	if( package.scopedModels && (package.role != DriverPlanRole::BASE_DRIVER ||
								(!selectedBasicSection.empty() && !scopedRow))) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 追加役割の正式GUIDを省略・補完しません
	if( package.role != DriverPlanRole::BASE_DRIVER) {
		// 元Versionの役割GUID読取診断です
		NativeError error = readInfDirective( inf, L"Version", L"ClassGUID", 1U, package.classGuid) ;
		const auto	expected =
			 package.role == DriverPlanRole::EXTENSION
				 ? L"{e2f84ce7-8efa-411c-aa69-97454ca4cb57}"
				 : L"{5c4c3332-344d-483c-8739-259e934c9cc8}" ;	// Microsoftの役割GUIDです
		// 別役割をbase Classの一致規則へ押し込みません
		if( error != 0 || !stringsEqual( package.classGuid, expected)) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	// ExtensionIdの実GUIDを検査し、同じ名称からidentityを作りません
	if( package.role == DriverPlanRole::EXTENSION) {
		// 元ExtensionIdの読取診断を構文失敗と別に保持します
		NativeError error =
			readInfDirective( inf, L"Version", L"ExtensionId", 1U, package.extensionId) ;
		GUID identity{} ;	// 構文と同一identityを確定する元GUIDです
		// 空・不正・zeroの拡張identityを競合判定に使用しません
		if( error != 0 || FAILED( CLSIDFromString( package.extensionId.c_str(), &identity)) ||
		   IsEqualGUID( identity, GUID_NULL)) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::array<wchar_t, 39U> canonical{} ;	// brace付きGUIDと終端の固定上限です
		// GUIDの表記差から同identityの競合を回避させません
		if( StringFromGUID2( identity, canonical.data(), static_cast<int>( canonical.size())) == 0) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		package.extensionId.assign( canonical.data()) ;
	}

	NativeError error{} ;	// 全import解析と私有選択解析の独立診断です
	// 同deviceの私有node名がある場合だけ、現OS Models所属と実在節を確認します
	if( !selectedBasicSection.empty()) {
		// 不正な基本名を任意実在節の指定へ変換しません
		if( !validInstallInventorySectionName( selectedBasicSection)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 選んだ導入基本節の所有文字列。元INFの照合中に参照します
		const std::wstring basicName{selectedBasicSection} ;
		// 公式範囲では同じ元INFの全Modelsと唯一の所属を既に確認しています
		error = scopedRow
					? resolveActualInstallInventorySection( inf, basicName,
														   package.selectedInstallSection)
					: selectInstallInventorySection( inf, basicName, package.selectedInstallSection) ;
		// Windowsの基本名fallbackも同元INFの実在を必要とします
		if( error != 0) {
			return error ;
		}
	}

	const auto		   separator = package.infRelativePath.find_last_of( L'\\') ;	// 元INF親の境界です
	// 元INFと同じ保護package内でだけ相対参照を解決します
	const std::wstring parent =
		separator == std::wstring::npos ? L"" : package.infRelativePath.substr( 0U, separator) ;
	// 公式証拠を指定した場合だけ同期中に借用するModels節一覧
	const auto scoped =
		package.scopedModels
			? std::span<const OfficialInfScopedModelsSection>( package.scopedModels->sections)
			: std::span<const OfficialInfScopedModelsSection>{} ;
	std::vector<std::wstring> declaredModels ;	// 他OS用を含むManufacturerの元指定
	// Manufacturerから読み出した元行数。全体予算の消費を集計します
	std::size_t				  manufacturerRows{} ;
	// 公式範囲の別用途参照を検査する前にManufacturerの全宣言を確定します
	if( !scoped.empty() &&
	   !collectDeclaredModelSections( inf, false, declaredModels, manufacturerRows)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::size_t countedModels{} ;	// 署名済みの全Models節とこのHINFの走査を照合します
	// SetupCopyOEMInfの全節CopyINF再帰importに備え、全宣言を切り捨てず照合します
	for( UINT sectionIndex = 0U; sectionIndex < MAXIMUM_INF_SECTIONS; ++sectionIndex) {
		// 全節の走査中に取消しが到達した場合は照合を終了します
		if( cancellation && *cancellation && (*cancellation)()) {
			return nativeErrorFromWin32( ERROR_CANCELLED) ;
		}

		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> section{} ;	// 一節の有限名です
		// 正常な全節終端だけを受理します
		if( !SetupEnumInfSectionsW( inf, sectionIndex, section.data(),
								  static_cast<UINT>( section.size()), nullptr)) {
			const DWORD last = GetLastError() ;	// 終端とAPI失敗を分けます
			// 正常終端以外を部分検査成功にしません
			if( last != ERROR_NO_MORE_ITEMS) {
				return nativeErrorFromWin32( last) ;
			}

			break ;
		}

		// 上限の最後でも追加節がある入力を打ち切り成功にしません
		if( sectionIndex + 1U == MAXIMUM_INF_SECTIONS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 内部所有表だけが実parserで読んだ原節を私有資格へ記録します
		if( const auto api = inf_dependency_native_detail::activeApi() ;
		   api && api->observedSection) {
			api->observedSection( workspace.path( package.infRelativePath), section.data()) ;
		}

		std::size_t modelRows{} ;		// 既存上限の外で数えてよい実在Models節の行数です
		LONG		expectedRows{} ;	// 全節走査で確認する元行数
		// 現在の節がManufacturerから宣言されたModels節かを保持します
		bool		declaredModel{} ;
		// 明示Modelsの証拠を適用する場合は、現在節を許可された用途と照合します
		if( !scoped.empty()) {
			// SetupAPIが返した現在節名の借用範囲
			const std::wstring_view sectionName{section.data()} ;
			declaredModel = std::ranges::any_of( declaredModels, [sectionName]( const auto &name) {
				return stringsEqual( sectionName, name) ;
			}) ;
			// 証拠中で現在節の元完全名に対応する位置
			const auto match = std::ranges::find_if( scoped, [&section]( const auto &model) {
				return stringsEqual( section.data(), model.modelSection) ;
			}) ;
			// 同名の元Modelsを見つけた場合でも、固定節や別用途の系列との衝突を拒否します
			if( match != scoped.end()) {
				// ドライバーINFで専用の意味があり、Modelsとして扱えない固定節名
				constexpr std::array<std::wstring_view, 4> exact{
					L"Version", L"Manufacturer", L"ControlFlags", L"DestinationDirs"} ;
				// 同じ基本名の装飾済み節を含めてModelsと併用できない系列
				constexpr std::array<std::wstring_view, 6> families{
					L"DefaultInstall", L"ClassInstall32",	L"InterfaceInstall32",
					L"Strings",		   L"SourceDisksFiles", L"SourceDisksNames"} ;
				// Manufacturerの宣言を持ち、かつ別用途の固定節・系列に該当しないことを要求します
				if( !declaredModel || isAllowedValue( sectionName, exact) ||
				   std::ranges::any_of( families, [sectionName]( auto name) {
					   return matchesInfSectionFamily( sectionName, name) ;
				   })) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				modelRows = match->modelRows ;
				++countedModels ;
			}

			expectedRows = SetupGetLineCountW( inf, section.data()) ;
			// 節の実行数を読み取れない場合は署名済み件数の照合を中止します
			if( expectedRows < 0L) {
				return nativeErrorFromWin32( GetLastError()) ;
			}
		}

		INFCONTEXT line{} ;	// 全明示directiveの読取contextです
		// 明示空節には必要関係を補完しません
		if( !SetupFindFirstLineW( inf, section.data(), nullptr, &line)) {
			// 空のモデルとして採用する場合は元件数と観測件数の両方を確認します
			if( modelRows != 0U || expectedRows != 0L) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			continue ;
		}

		std::size_t lines{} ;	// 一節の有限行数です
		// 全行のInclude/NeedsとCopyINFを原節へ結合します
		do {
			// 長い節の解析中に区切りごとに取消しを確認します
			if( lines % 64U == 0U && cancellation && *cancellation && (*cancellation)()) {
				return nativeErrorFromWin32( ERROR_CANCELLED) ;
			}

			// 過大な節を一部の正常構成へ切り詰めません
			if( ++lines > (modelRows == 0U ? 4096U : modelRows)) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			std::wstring key ;	// keyなしdata行は既存作用検査へ委ねます
			// data行にdirectiveを推測しません
			if( readInfField( line, 0U, key) != 0) {
				// Models節で正しい行を読み出せなければ元指定の証拠と一致しません
				if( declaredModel) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				continue ;
			}

			// 公式範囲と照合する場合は、一行ずつ他用途との衝突を確認します
			if( !scoped.empty()) {
				error = checkScopedModelsRole( line, section.data(), key, declaredModel, scoped) ;
				// 元Modelsの別用途使用などが見つかった場合は原診断を返します
				if( error != 0) {
					return error ;
				}
			}

			// SYSTEM/PACKAGE参照の未確認をfalseへ書き換えません
			if( stringsEqual( key, L"Include") || stringsEqual( key, L"Needs")) {
				package.unresolvedIncludeNeeds = true ;
			}

			// SourceDisksFiles不在の役割はfile参照を持てません
			if( package.sourceFiles.empty() &&
			   (stringsEqual( key, L"CopyFiles") || stringsEqual( key, L"ServiceBinary"))) {
				const auto &nvme =
					package.collectorInboxNvmeLists ;	// 元構造で確認した空のコピー節です
				std::wstring list ;						// 同じ基本節で現在読み取ったコピー指定です
				// 元NVMeの空コピーだけを、媒体を必要としない作用として保持します
				if( nvme && stringsEqual( key, L"CopyFiles") &&
				   package.collectorInboxInstallGroups.size() == 1U &&
				   !package.collectorInboxInstallGroups.front().empty() &&
				   stringsEqual( section.data(),
								package.collectorInboxInstallGroups.front().front()) &&
				   SetupGetFieldCount( &line) == 1U && readInfField( line, 1U, list) == 0 &&
				   stringsEqual( list, nvme->copy)) {
					continue ;
				}

				return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
			}

			// import全内容の役割作用を検査し、非選択serviceもWin32 appへ読み替えません
			if( package.role != DriverPlanRole::BASE_DRIVER && stringsEqual( key, L"AddService")) {
				std::wstring executable ;	// 同INFの必要Win32 serviceだけが返す元EXE名です
				int			 flags{} ;		// Extensionのfunction-driver関連付けを拒否する原flagsです
				// Extensionに基本driver serviceの権限を混ぜません
				if( package.role == DriverPlanRole::EXTENSION &&
				   (!SetupGetIntField( &line, 2U, &flags) || (flags & 2) != 0)) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				// 全潜在importの実作用もdriver-only検査から除きません
				if( const auto serviceError = inspectRequiredServiceDeclaration(
					   inf, section.data(), line, package.role, executable) ;
				   serviceError != 0) {
					return serviceError ;
				}
			}

			// 元CopyINFだけを再帰閉包の参照へ渡します
			if( stringsEqual( key, L"CopyINF")) {
				const auto fields = SetupGetFieldCount( &line) ;	// 全原fieldです
				// 欠損・過大な参照を正常な空集合にしません
				if( fields == 0U || fields > 32U) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				// 各相対参照の位置と元archive実在を確認します
				for( DWORD field = 1U; field <= fields; ++field) {
					std::wstring child ;	// 元INF相対参照です
					const bool	 atOptionalEnd =
						field > 1U && field == fields ;	// 先行参照に続く最後のフィールドか
					error = atOptionalEnd ? readInstallInventoryField( line, field, child)
										  : readInfField( line, field, child) ;
					// 保守の参照列挙と同じ末尾空フィールドだけを除外する
					if( error == 0 && atOptionalEnd && child.empty()) {
						continue ;
					}

					const auto path =
						// 安全性はworkspaceでも検査します
						joinRelativePath( parent, child) ;
					// 不正位置は拒否し、正しい原相対名の欠損は内容と独立した未解決へ残します
					if( error != 0 || lowerExtension( path) != L".inf" ||
					   workspace.path( path).empty()) {
						return error != 0 ? error : nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
					}

					// 内容署名を全CopyINF依存の解決成功へ変換しません
					if( !containsEntry( entries, path)) {
						static_cast<void>( appendUnique( package.unresolvedCopyInfPaths, path)) ;
					}

					static_cast<void>( appendUnique( package.requiredInfPaths, path)) ;
					// 選択処理の元参照と全節import参照を別に保持します
					if( stringsEqual( section.data(), package.selectedInstallSection)) {
						static_cast<void>( appendUnique( package.activeRequiredInfPaths, path)) ;
					}
				}
			}
		} while( SetupFindNextLine( &line, &line)) ;

		// 別枠の節も全行を通常の関係走査へ通すため、途中終了を受理しません
		if( (!scoped.empty() && lines != static_cast<std::size_t>( expectedRows)) ||
		   (modelRows != 0U && lines != modelRows)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	// 元証拠のModels節がすべて実INFから見つかったことを要求します
	if( package.scopedModels && countedModels != package.scopedModels->sections.size()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 内容検査だけでは全importを保持して終え、device別必要子を推測しません
	if( selectedBasicSection.empty()) {
		return 0 ;
	}

	const auto componentsSection =
		package.selectedInstallSection + L".Components" ;	// 選択元の子宣言です
	INFCONTEXT component{} ;								// AddComponentだけを有限に読みます
	// 元宣言がある場合だけ必要子を作り、同梱名から必要性を作りません
	if( SetupFindFirstLineW( inf, componentsSection.c_str(), L"AddComponent", &component)) {
		// 元AddComponentを全件保持し、一意名とSWC IDを結びます
		do {
			OfficialInfComponentReference reference ;	// 一つの元子宣言です
			std::wstring				  section ;		// ComponentIDsを持つ元sectionです
			error = readInfField( component, 1U, reference.name) ;
			// 元name/sectionと予約flags以外を受理しません
			if( error != 0 || SetupGetFieldCount( &component) != 3U ||
			   readInfField( component, 3U, section) != 0 ||
			   !validInstallInventorySectionName( section)) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			std::array<wchar_t, 32U> flags{} ;	// 空または0だけの予約fieldです
			// 将来flagsを既知の0へ補正しません
			if( !SetupGetStringFieldW( &component, 2U, flags.data(), static_cast<DWORD>( flags.size()),
									 nullptr) ||
			   (flags[0] != L'\0' && std::wstring_view( flags.data()) != L"0")) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			INFCONTEXT ids{} ;	// 元必須ComponentIDsです
			// 必須IDを名称から補完しません
			if( !SetupFindFirstLineW( inf, section.c_str(), L"ComponentIDs", &ids) ||
			   SetupGetFieldCount( &ids) == 0U || SetupGetFieldCount( &ids) > 32U) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// 原文の各ComponentIDにWindowsのSWC接頭辞を結合します
			for( DWORD field = 1U; field <= SetupGetFieldCount( &ids); ++field) {
				std::wstring id ;	// 元ComponentIDです。端末IDの外部送信は行いません
				error = readInfField( ids, field, id) ;
				// 空・過大・既接頭辞・異なるbusのIDを推測変換しません
				if( error != 0 || id.size() > 192U || id.find( L'\\') != std::wstring::npos) {
					return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				static_cast<void>( appendUnique( reference.hardwareIds, L"SWC\\" + id)) ;
			}

			// 一意名・有限数を守り、曖昧な子の全導入をしません
			if( package.requiredComponents.size() >= 8U ||
			   std::ranges::any_of( package.requiredComponents, [&]( const auto &value) {
				   return stringsEqual( value.name, reference.name) ;
			   })) {
				return nativeErrorFromWin32( ERROR_DUP_NAME) ;
			}

			package.requiredComponents.push_back( std::move( reference)) ;
		} while( SetupFindNextMatchLineW( &component, L"AddComponent", &component)) ;
	}

	// SWCにfunction serviceは必須でありません。ある場合だけ具体的作用を検査します
	if( package.role != DriverPlanRole::BASE_DRIVER) {
		const auto services = package.selectedInstallSection + L".Services" ;	// 元選択service節です
		INFCONTEXT service{} ;													// 元AddServiceの全driver-only検査です
		// Serviceなしのdriver構成INFをClassだけで任意appへ読み替えません
		if( SetupFindFirstLineW( inf, services.c_str(), L"AddService", &service)) {
			// 全serviceを同INFの役割と元コピーへ再照合し、内容許可を単独authorityにしません
			do {
				std::wstring executable ;	// 同必要SWCの限定Win32 EXE名です
				int			 flags{} ;		// 追加serviceの作用flagsです
				// Extensionにfunction driver serviceを関連付けません
				if( package.role == DriverPlanRole::EXTENSION &&
				   (!SetupGetIntField( &service, 2U, &flags) || (flags & 2) != 0)) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				// 欠損・未知/複合種別・誤roleを方式未対応へ残し、必要Win32 serviceを任意appと混同しません
				if( const auto serviceError = inspectRequiredServiceDeclaration(
					   inf, services, service, package.role, executable) ;
				   serviceError != 0) {
					return serviceError ;
				}
			} while( SetupFindNextMatchLineW( &service, L"AddService", &service)) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 読取り中の元INFから全潜在importと実選択の必要関係を取得します
 * @param[in] inf 同じ元INFの読取専用handleです
 * @param[in] workspace 同元INFを所有する保護領域です
 * @param[in] entries 全潜在importを含む閉包の一覧です
 * @param[in] original 同元INFの既存内容検査結果です
 * @param[in] basicSection 実Windows選択から取得した未修飾基本節です
 * @param[in] scopedRow 同元INFの全Models照合済みの行です。通常解析ではnullです
 * @param[out] selected 実選択の関係を追加した元metadataです。失敗時は空です
 * @return 元閉包と実選択を確認した場合0、照合または読取り失敗はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError readSelectedInfRelations( HINF inf, const OfficialDownloadWorkspace &workspace,
									 std::span<const OfficialZipEntry>	entries,
									 const OfficialInfPackage		   &original,
									 std::wstring_view					basicSection,
									 const OfficialInfScopedModelMatch *scopedRow,
									 OfficialInfPackage				   &selected)
{
	try {
		auto parsed = original ;	// 全importと元検査の用途を維持します
		parsed.selectedInstallSection.clear() ;
		parsed.selectedBasicSection = basicSection ;
		parsed.selectedNativeRank.reset() ;
		parsed.activeRequiredInfPaths.clear() ;
		parsed.requiredComponents.clear() ;
		// 同じ元基本節で必要なINF関係を再解析した診断値
		const auto error = inspectRequiredDriverRelations( inf, workspace, entries, parsed,
														  basicSection, nullptr, scopedRow) ;
		// 必要なINF関係が元の検査から変わっていれば導入判断を引き継ぎません
		if( error != 0 || parsed.requiredInfPaths != original.requiredInfPaths) {
			return error ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		selected = std::move( parsed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同元CopyINFの内容検査用ClassをWindows readerから読みます
 * @param[in] workspace 原INFを所有する保護領域です
 * @param[in] infRelativePath 同領域内の元INFです
 * @param[out] className 非空Class/有効非zero GUID/既知Firmware範囲外を確認した原名です
 * @return 元読取成功0、不正・不明・既知FirmwareはHRESULTです
 * @note importの非実行内容だけです。root policy、適合または導入能力を変更しません
 */
//------------------------------------------------------------------------------
NativeError readOfficialInfImportClass( const OfficialDownloadWorkspace &workspace,
									   std::wstring_view infRelativePath, std::wstring &className)
{
	className.clear() ;
	const auto path = workspace.path( infRelativePath) ;	// 同元の安全なINF pathだけです
	std::array<wchar_t, MAX_PATH> name{} ;					// 元Windows Classの完全有限値です
	GUID						  guid{} ;					// 同元Windows readerからのClassGUIDです
	const GUID					  empty{} ;					// 未指定を内容成功にしません
	DWORD						  required{} ;				// NUL込み原必要文字数です
	// 原構文/原ClassGUIDを必要とし、未知表や元値の補正で認定しません
	if( path.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// Windows読取そのものの失敗は原数値のまま保持します
	if( !SetupDiGetINFClassW( path.c_str(), &guid, name.data(), static_cast<DWORD>( name.size()),
							&required)) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 有効な元Class/GUIDでも既知Firmwareを通常driver内容へ混入させません
	if( required < 2U || required > name.size() || IsEqualGUID( guid, empty) ||
	   IsEqualGUID( guid, GUID_DEVCLASS_FIRMWARE) || stringsEqual( name.data(), L"Firmware")) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	className = name.data() ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元INFの全現在architecture source相対位置を非実行で読み取ります
 * @param[in] workspace 元INFを保持する保護領域です
 * @param[in] infRelativePath 同領域内の元INF相対位置です
 * @param[in] maximumFiles 元sourceの有限件数上限です
 * @param[out] paths 全成功時だけ同INF/同媒体に結合する安全相対pathです。失敗時は空です
 * @param[in] includeCommonFallback AMD64専用表に加えて有効な共通媒体行を列挙する場合true
 * @return 全取得成功0、欠損・過長・不正位置・容量超過のHRESULTです
 * @note 原圧縮sourceの探索準備だけです。実byte/CAT/導入可能性の証明ではありません
 */
//------------------------------------------------------------------------------
NativeError readOfficialInfSourcePaths( const OfficialDownloadWorkspace &workspace,
									   std::wstring_view infRelativePath, std::size_t maximumFiles,
									   std::vector<std::wstring> &paths, bool includeCommonFallback)
{
	paths.clear() ;
	const auto path = workspace.path( infRelativePath) ;	// 元保護INFだけの完全位置です
	// 外部fileや無限のsource集合を読みません
	if( path.empty() || maximumFiles == 0U || maximumFiles > 8192U ||
	   lowerExtension( infRelativePath) != L".inf") {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 同期読取所有者です
		// INFを開けない場合に元sourceを推測しません
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		INFCONTEXT row{} ;	// 元amd64優先source宣言です
		bool	   commonFallback =
			includeCommonFallback && SetupGetLineCountW( inf.get(), L"SourceDisksFiles.amd64") >
										 0L ;	// AMD64表の後に確認する共通表
		// sourceなしのimportは空集合のまま保持します
		if( !SetupFindFirstLineW( inf.get(), L"SourceDisksFiles.amd64", nullptr, &row) &&
		   !SetupFindFirstLineW( inf.get(), L"SourceDisksFiles", nullptr, &row)) {
			return 0 ;
		}

		const auto separator = infRelativePath.find_last_of( L'\\') ;	// 元INF親の境界です
		const auto parent =
			separator == infRelativePath.npos
				? std::wstring_view{}
				: infRelativePath.substr( 0U, separator) ;	// 同package内だけの基準です
		std::vector<std::wstring> inspected ;				// 全成功まで公開しない元位置です
		// 全sourceのfile subdirと媒体を同INFへ結びます
		do {
			std::wstring name ;									// 元file名です
			std::wstring directory ;							// 同元fileのsource subdirです
			std::wstring media ;								// 同元source IDの媒体pathです
			const auto	 error = readInfField( row, 0U, name) ;	// 元key診断です
			// 不正名をpath補正で救済しません
			if( error != 0 || name.find_first_of( L"/\\") != name.npos) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			const auto locationError =
				// 元位置診断です
				readInfSourceDirectories( inf.get(), name, directory, media) ;
			// 必須位置の不成立を空directoryへ補完しません
			if( locationError != 0) {
				return locationError ;
			}

			auto relative =
				joinRelativePath( joinRelativePath( joinRelativePath( parent, media), directory),
								 name) ;	// 原位置だけの結合です
			// traversalや容量超過を部分集合へ縮約しません
			if( workspace.path( relative).empty() ||
			   (appendUnique( inspected, std::move( relative)) && inspected.size() > maximumFiles)) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}
		} while( SetupFindNextLine( &row, &row) ||
				(std::exchange( commonFallback, false) &&
				 SetupFindFirstLineW( inf.get(), L"SourceDisksFiles", nullptr, &row))) ;
		paths = std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同保護元INFの私有node基本名から選択節の機能関係だけを解析します
 * @param[in] workspace 元byte検査済みINFを所有し、同期終了まで生存する保護領域です
 * @param[in] entries 全潜在importを含む元hash付きinventoryです。呼出し中だけ借用します
 * @param[in] original 同保護元INFの内容検査metadataです。選択成功や導入権限は表しません
 * @param[in] selectedBasicSection 同device/native nodeで確認した未修飾基本名です。空・NUL・過長は禁止です
 * @param[out] selected 成功時だけ全importと選択機能関係を保持するcopyです。失敗時は空です
 * @return 現OS Models所属/Windows装飾選択/実節/機能関係の確認0、その他は元HRESULTです
 * @pre originalとselectedは異なるobjectです。同じ元byteの再確認を呼出し側で行います
 * @note Worker内のread-only解析です。呼出し側の全byte再検査と同issuer bindingを代替しません
 */
//------------------------------------------------------------------------------

NativeError inspectSelectedOfficialInfRelations( const OfficialDownloadWorkspace	 &workspace,
												std::span<const OfficialZipEntry> entries,
												const OfficialInfPackage		 &original,
												std::wstring_view	selectedBasicSection,
												OfficialInfPackage &selected)
{
	selected		= {} ;
	const auto path = workspace.path( original.infRelativePath) ;	// 同保護元INF完全pathです
	// 公開文字列の空指定を内容検査だけの成功へ変換しません
	if( (original.inspectionPurpose != OfficialInfInspectionPurpose::STANDARD_DRIVER &&
		original.inspectionPurpose != OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE &&
		original.inspectionPurpose != OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT) ||
	   original.requiredNullCompanion || original.requiredRegistryOnlyCompanion || path.empty() ||
	   !validInstallInventorySectionName( selectedBasicSection) ||
	   !containsEntry( entries, original.infRelativePath)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	UINT			errorLine{} ;	// 元INF構文失敗の行数です。外へ実pathを公開しません
	const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
										  &errorLine)) ;	// 同期read-only所有handleです
	// 不在または不正の元INFを別INFで補完しません
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	return readSelectedInfRelations( inf.get(), workspace, entries, original, selectedBasicSection,
									nullptr, selected) ;
}

namespace {
/** @brief 同元sourceとWindows解決済みの一コピー先です。実行stepではありません */
struct WindowsDriverCopy {
	/// 全内容/CATへ結合する元source相対位置です
	std::wstring source ;
	/// Windowsが同元DestinationDirsから解決した完全コピー先です
	std::wstring target ;
	/// 元DestinationDirsのDIRIDです
	int			 dirid{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 実選択DDInstallのcopy/service/software関係だけを有限に読みます
 * @param[in] inf 同元の読取専用HINFです
 * @param[in] selected 私有native基本名に結合する元選択です
 * @param[out] inventory 成功時だけ必要関係を保持します。完全棚卸しではありません
 * @return 正式関係読取成功0、元節/参照/有限容量の診断です
 * @note registry本文の未知vendor dataを処理許可へ変換せず、全内容の既知禁止作用検査を別に維持します
 */
//------------------------------------------------------------------------------
NativeError readWindowsDriverScopeReferences( HINF inf, const OfficialInfPackage &selected,
											 OfficialInfInstallInventory &inventory)
{
	OfficialInfInstallInventory made ;	// 全成功まで外へ出さない元関係です
	const auto					error =
		selectInstallInventorySection( inf, selected.selectedBasicSection,
									  made.selectedInstallSection) ;	// Windowsの実装飾選択です
	// 任意節や別Modelsへ選択を補完しません
	if( error != 0 || !stringsEqual( made.selectedInstallSection, selected.selectedInstallSection)) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_RETRY) ;
	}

	constexpr std::array suffixes{
		L"",		  L".HW",  L".Services", L".CoInstallers", L".Interfaces", L".Components",
		L".Software", L".Wdf", L".Events"} ;	// Windowsの同選択付随文脈だけです
	constexpr std::array keys{L"CopyFiles", L"AddService",
							  L"AddSoftware"} ;	// 本scopeの正式結合だけです
	std::size_t			 declarations{} ;		// 元関係の全宣言が共同消費する有限行数です
	// 同元selectedの付随節だけを読み、別deviceの潜在節を実行集合へ追加しません
	for( const auto suffix : suffixes) {
		const auto section = made.selectedInstallSection + suffix ;	// 同HINFの実選択文脈です
		// 非実在の任意付随節を不足にしません
		if( SetupGetLineCountW( inf, section.c_str()) < 0L) {
			continue ;
		}

		// opaqueなregistry本文をdataの完全意味解析へ広げず、元関係だけを読みます
		for( const auto key : keys) {
			INFCONTEXT row{} ;	// 同節の全duplicate keyを読むcursorです
			// 明示関係のない元文脈は無関係なmetadataのまま保持します
			if( !SetupFindFirstLineW( inf, section.c_str(), key, &row)) {
				continue ;
			}

			// 全duplicate行を有限に読み、先頭行だけを当該deviceのscopeにしません
			do {
				const auto fields = SetupGetFieldCount( &row) ;	// 既知正式関係だけのfield数です
				// 過大関係を部分成功へ切り詰めません
				if( ++declarations > MAXIMUM_INSTALL_INVENTORY_LINES || fields == 0U ||
				   fields > 32U) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}

				made.effects.push_back(
					{section, key, OfficialInfInstallEffectKind::STANDARD_DIRECTIVE}) ;
				// service/softwareの元行は後段の正式readerで全fieldを再検査します
				if( !stringsEqual( key, L"CopyFiles")) {
					continue ;
				}

				// 元全CopyFiles listまたは直接file指定を保持します
				for( DWORD field = 1U; field <= fields; ++field) {
					std::wstring target ;											// 同元参照の全値です
					const auto	 readError = readInfField( row, field, target) ;	// 元有限読取診断です
					const bool	 direct	   = target.starts_with( L"@") ;			// Windowsの直接file形式です
					// 不正節名を任意pathや他INFへ補完しません
					if( readError != 0 || (!direct && !validInstallInventorySectionName( target))) {
						return readError != 0 ? readError
											  : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					// 直接fileの実source照合は後段でSDF/媒体/同元CAT位置へ結びます
					if( direct) {
						target.erase( 0U, 1U) ;
					}

					const bool present = direct || SetupGetLineCountW( inf, target.c_str()) >=
													   0L ;	// 明示空と不在を分けます
					made.references.push_back( {section, key, std::move( target),
											   direct
												   ? OfficialInfInstallReferenceKind::DIRECT_FILE
												   : OfficialInfInstallReferenceKind::LOCAL_SECTION,
											   present}) ;
				}
			} while( SetupFindNextMatchLineW( &row, key, &row)) ;
		}
	}

	inventory = std::move( made) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択コピー先を同HINFのWindows driver/system directoryへ限定します
 * @param[in] inf 原読取専用INFです
 * @param[in] list 空は直接file指定で、他は原CopyFiles listです
 * @param[out] dirid 元Windows DIRIDです
 * @param[out] subdirectory 元相対subdirectoryです
 * @param[out] target Windowsの完全解決先です
 * @return 全成功0、外部/不正/曖昧な導入先はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError readWindowsDriverCopyDestination( HINF inf, const std::wstring &list, int &dirid,
											 std::wstring &subdirectory, std::wstring &target)
{
	auto	   key = list.empty() ? L"DefaultDestDir" : list.c_str() ;	// 同元の明示宛先だけです
	INFCONTEXT line{} ;													// 同HINFの原DestinationDirs行です
	// 個別指定の不在だけをWindows標準の既定へ接続します
	if( !SetupFindFirstLineW( inf, L"DestinationDirs", key, &line)) {
		key = L"DefaultDestDir" ;
	}

	INFCONTEXT duplicate{} ;	// 重複元指定を先頭採用しません
	// driver store/system以外のfile配置を通常driver操作へ追加しません
	if( !SetupFindFirstLineW( inf, L"DestinationDirs", key, &line) ||
	   !SetupGetIntField( &line, 1U, &dirid) || SetupGetFieldCount( &line) > 2U ||
	   SetupFindNextMatchLineW( &line, key, &duplicate) ||
	   (SetupGetFieldCount( &line) == 2U &&
		readInstallInventoryField( line, 2U, subdirectory) != 0) ||
	   !validRequiredServiceSubdirectory( subdirectory) ||
	   (dirid != 11 && dirid != 12 && dirid != 13 &&
		!(dirid == 10 &&
		  (stringsEqual( subdirectory, L"System32") || stringsEqual( subdirectory, L"SysWOW64") ||
		   (subdirectory.size() > 9U && subdirectory[8U] == L'\\' &&
			stringsEqual( std::wstring_view( subdirectory).substr( 0U, 8U), L"SysWOW64")))))) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	DWORD	   required{} ;											// WindowsのNUL込み必要文字数です
	const auto section = list.empty() ? nullptr : list.c_str() ;	// 同じ原copy listだけです
	SetLastError( ERROR_SUCCESS) ;
	// 解決失敗をDIRID tokenの文字列置換で補完しません
	if( !SetupGetTargetPathW( inf, nullptr, section, nullptr, 0U, &required) &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	// 原宛先を切り詰めず、既存field上限を維持します
	if( required < 2U || required > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	std::vector<wchar_t> buffer( required) ;	// 同期APIの完全宛先です
	DWORD				 actual{} ;				// 二段目の元必要長です
	// 途中失敗や終端差を正常な宛先へ変換しません
	if( !SetupGetTargetPathW( inf, nullptr, section, buffer.data(), required, &actual) ||
	   actual != required || buffer.back() != L'\0' ||
	   std::char_traits<wchar_t>::length( buffer.data()) + 1U != required) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	target = buffer.data() ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのコピー指示を同じINFに記載された媒体位置とWindowsの宛先へ解決する
 * @param[in] inf 同期借用する元INF
 * @param[in] parent 元INFの保護領域内の親ディレクトリ
 * @param[in] list 元コピー節。直接コピーの場合は空
 * @param[in] targetName コピー先のファイル名
 * @param[in] sourceName 媒体上の元ファイル名
 * @param[out] made 解決した相対ソース位置と完全なコピー先
 * @param[in,out] diagnostic 任意の最初の固定診断
 * @return 解決成功0、欠損・不正な名前・配置の不一致はHRESULT
 * @note 保存済み媒体にファイルがあるかは呼出し側が確認する
 */
//------------------------------------------------------------------------------
NativeError resolveWindowsDriverCopy( HINF inf, std::wstring_view parent, const std::wstring &list,
									 const std::wstring &targetName, const std::wstring &sourceName,
									 WindowsDriverCopy			  &made,
									 RequiredInfBindingDiagnostic *diagnostic = nullptr)
{
	// leafを別directoryや外部pathへ補正しません
	if( targetName.empty() || sourceName.empty() || targetName.find( L'\\') != targetName.npos ||
	   sourceName.find( L'\\') != sourceName.npos || !validRequiredServiceSubdirectory( targetName) ||
	   !validRequiredServiceSubdirectory( sourceName)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::wstring destination ;		// Windowsが解決した同listのdirectoryです
	std::wstring subdirectory ;		// 元copy先の全相対subdirです
	std::wstring sourceDirectory ;	// 原SDFの同名file subdirです
	std::wstring medium ;			// 原source IDの媒体位置です
	auto		 error = readWindowsDriverCopyDestination( inf, list, made.dirid, subdirectory,
														  destination) ;	// 原宛先診断です
	// 同元sourceと宛先が揃うまで関係を成立させません
	if( error == 0) {
		error = readRequiredServiceSourceDirectory( inf, sourceName, sourceDirectory, medium) ;
	}

	// DIRID13は元source相対位置を保持するWindows driver store契約です
	if( error != 0 || (made.dirid == 13 && !stringsEqual( subdirectory, sourceDirectory))) {
		return diagnostic ? diagnostic->reject(
								error != 0 ? error : nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
								error != 0 ? InfBindingReject::WINDOWS_COPY
										   : InfBindingReject::DIRID13_SOURCE)
						  : (error != 0 ? error : nativeErrorFromWin32( ERROR_NOT_SUPPORTED)) ;
	}

	made.source = joinRelativePath(
		parent, joinRelativePath( joinRelativePath( medium, sourceDirectory), sourceName)) ;
	made.target = joinRelativePath( destination, targetName) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一原CopyFiles行を元source/CAT所有位置とWindows宛先へ結びます
 * @param[in] inf 原読取専用HINFです
 * @param[in] workspace 同期借用する保護所有領域です
 * @param[in] entries 全内容の実hash付き一覧です
 * @param[in] package 元選択INFの全source一覧です
 * @param[in] list 空は直接コピー、他は原listです
 * @param[in] targetName 原コピー先leafです
 * @param[in] sourceName 原source leafです。renameを保持します
 * @param[in,out] copies 同操作の最大4096コピーです
 * @param[in,out] diagnostic null可の最初の固定拒否段階です
 * @return 同元位置/安全なWindows配置成功0、それ以外はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError bindWindowsDriverCopy( HINF inf, const OfficialDownloadWorkspace &workspace,
								  std::span<const OfficialZipEntry> entries,
								  const OfficialInfPackage &package, const std::wstring &list,
								  const std::wstring &targetName, const std::wstring &sourceName,
								  std::vector<WindowsDriverCopy> &copies,
								  RequiredInfBindingDiagnostic	 *diagnostic = nullptr)
{
	WindowsDriverCopy made ;														// 完全な元sourceとWindows宛先
	const auto		  separator = package.infRelativePath.find_last_of( L'\\') ;	// 元INF親位置
	const auto		  parent	= separator == package.infRelativePath.npos
									  ? std::wstring_view{}
									  : std::wstring_view( package.infRelativePath)
									.substr( 0U, separator) ;	// 同containerだけを解決する
	const auto error = resolveWindowsDriverCopy( inf, parent, list, targetName, sourceName, made,
												diagnostic) ;	// 原コピー宣言の解決結果
	// 元コピー方向と宛先の解決失敗を伝える
	if( error != 0) {
		return error ;
	}

	// 正規source以外や未検査fileを元署名から借用しません
	if( workspace.path( made.source).empty() || !containsEntry( entries, made.source) ||
	   std::ranges::none_of( package.sourceFiles,
							[&]( const auto &path) { return stringsEqual( path, made.source) ; })) {
		return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
	}

	const auto prior = std::ranges::find_if( copies, [&]( const auto &copy) {
		return stringsEqual( copy.target, made.target) ;
	}) ; // 同宛先の衝突です
	// 同じbyteの共有コピーだけを再利用します
	if( prior != copies.end()) {
		return stringsEqual( prior->source, made.source) ? 0 : nativeErrorFromWin32( ERROR_DUP_NAME) ;
	}

	// 選択graphの既存行予算をコピー保持にも維持します
	if( copies.size() >= MAXIMUM_INSTALL_INVENTORY_LINES) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	copies.push_back( std::move( made)) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択service binaryを元コピーの完全宛先へ結びます
 * @param[in] binary Windowsが展開した原ServiceBinaryです。元引数を保持します
 * @param[in] copies 同selected graphの検査済みコピーです
 * @param[in] kernel trueは引数なしSYS、falseは元Win32 EXEだけです
 * @return 正確な元コピーと型へ一意に結合する場合trueです
 * @note 引数を実行せずvendor binary内部の作用も推測しません
 */
//------------------------------------------------------------------------------
bool boundWindowsServiceBinary( std::wstring_view binary, std::span<const WindowsDriverCopy> copies,
							   bool kernel)
{
	std::size_t matches{} ;	// 一つの元完全宛先だけを認めます
	// 元コピーごとの全pathを先に比較し、最後のslashや空白で実行名を推測しません
	for( const auto &copy : copies) {
		const auto extension = lowerExtension( copy.target) ;	// 元コピー先の正式種別です
		// 実行型に該当しない受動DATAをservice binaryへ昇格しません
		if( extension != (kernel ? L".sys" : L".exe")) {
			continue ;
		}

		auto	   path	  = binary ;					// 内側quoteを含む原値を同期比較します
		const bool quoted = path.starts_with( L"\"") ;	// Windows形式の完全path引用です
		// 引用開始だけを対応し、元引数を正規化しません
		if( quoted) {
			path.remove_prefix( 1U) ;
		}

		// 完全path未満の一致を許可根拠に使いません
		if( path.size() < copy.target.size() ||
		   !stringsEqual( path.substr( 0U, copy.target.size()), copy.target)) {
			continue ;
		}

		path.remove_prefix( copy.target.size()) ;
		// quoteの終端を欠くpathを起動可能な元宣言へ読み替えません
		if( quoted) {
			// 閉じ引用符のない元値は不明なlauncherとして拒否します
			if( !path.starts_with( L"\"")) {
				continue ;
			}

			path.remove_prefix( 1U) ;
		}

		// SYSは引数を持たず、EXEは完全path境界後の原引数だけを保持します
		if( (!path.empty() && (kernel || (path.front() != L' ' && path.front() != L'\t'))) ||
		   path.find_first_of( L"\r\n") != path.npos) {
			continue ;
		}

		++matches ;
	}

	return matches == 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択した補助サービスの明示Systemイベント参照を検査します
 * @param[in] inf 元INFの同期借用handleです
 * @param[in] section 同じINFのイベント登録節名です
 * @param[in] logName 元行が明示したログの名前です
 * @param[in] sourceName 元行が明示した展開済みのイベント源名です
 * @return 実在する元節、Systemログ、単一の有効な元イベント源がそろう場合trueです
 * @note イベント節の作用や既存登録の所有は後段で確認します
 */
//------------------------------------------------------------------------------
bool validNamedStorageSystemEvent( HINF inf, const std::wstring &section, std::wstring_view logName,
								  std::wstring_view sourceName)
{
	return validInstallInventorySectionName( section) &&
		   SetupGetLineCountW( inf, section.c_str()) > 0 && stringsEqual( logName, L"System") &&
		   validInstallInventorySectionName( sourceName) && sourceName.find( L'%') == sourceName.npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief DDInstallがコピーする元ファイルを同じINFの媒体とWindows宛先に結ぶ
 * @param[in] inf 読み取り専用の元INF
 * @param[in] parent 保護領域内のINF親ディレクトリ
 * @param[in] install 検査対象の実在するDDInstall節
 * @param[in,out] rows 対象全体で共有する導入行の読取予算
 * @param[out] copies 元媒体と宛先の関係。失敗時は部分結果を使用しない
 * @return 全コピー関係を読めた場合true
 */
//------------------------------------------------------------------------------
bool collectAmd64InstallCopies( HINF inf, std::wstring_view parent, const std::wstring &install,
							   std::size_t &rows, std::vector<WindowsDriverCopy> &copies)
{
	INFCONTEXT directive{} ;	// 同DDInstallの現在行
	// 空のDDInstallは後段で明示的な空サービスと照合する
	if( SetupGetLineCountW( inf, install.c_str()) == 0L) {
		return true ;
	}

	// 実在する全行を取得できない場合は部分的なコピー証明を使わない
	if( !SetupFindFirstLineW( inf, install.c_str(), nullptr, &directive)) {
		return false ;
	}

	// 他節の継承や任意の登録指示をコピーだけの形に読み替えない
	do {
		std::wstring key ;										// 元指示の名前
		const auto	 fields = SetupGetFieldCount( &directive) ;	// 元のコピー先指定数
		// 指示と全フィールドの読み取りを有限に保つ
		if( ++rows > MAXIMUM_INSTALL_INVENTORY_LINES || fields == 0U || fields > 64U ||
		   readInfField( directive, 0U, key) != 0 || !stringsEqual( key, L"CopyFiles")) {
			return false ;
		}

		// 直接コピーと各コピー節を区別して処理する
		for( DWORD field = 1U; field <= fields; ++field) {
			std::wstring list ;	// コピー節名または@で始まる直接コピー
			// 空・不正な指定からコピー元を推定しない
			if( readInfField( directive, field, list) != 0) {
				return false ;
			}

			const bool direct = list.starts_with( L"@") ;								// CopyFilesの直接コピー構文
			const LONG count  = direct ? 1L : SetupGetLineCountW( inf, list.c_str()) ;	// 元コピー行数
			// 欠落した節や付随する権限指定を省略しない
			if( count <= 0L ||
			   static_cast<std::size_t>( count) > MAXIMUM_INSTALL_INVENTORY_LINES - rows ||
			   (!direct && (!validInstallInventorySectionName( list) ||
							SetupGetLineCountW( inf, (list + L".security").c_str()) >= 0L))) {
				return false ;
			}

			// 名前を変更するコピーでも媒体上の元名を保持する
			for( LONG index = 0L; index < count; ++index) {
				++rows ;
				std::wstring target = direct ? list.substr( 1U) : std::wstring{} ;	// 元の宛先名
				std::wstring source ;												// 元の媒体上ファイル名
				INFCONTEXT	 row{} ;												// 名前付きコピー節の現在行
				// 名前付きコピー節の全フィールドを確認する
				if( !direct &&
				   (!SetupGetLineByIndexW( inf, list.c_str(), static_cast<DWORD>( index), &row) ||
					SetupGetFieldCount( &row) > 2U || readInfField( row, 1U, target) != 0 ||
					(SetupGetFieldCount( &row) == 2U &&
					 readInstallInventoryField( row, 2U, source) != 0))) {
					return false ;
				}

				WindowsDriverCopy copy ;	// 既存の媒体・宛先境界で解決する元コピー
				// 必要な元ファイルのSDF行や宛先を取得できない場合は保留する
				if( resolveWindowsDriverCopy( inf, parent, direct ? std::wstring{} : list, target,
											source.empty() ? target : source, copy) != 0) {
					return false ;
				}

				const auto existing = std::ranges::find_if( copies, [&]( const auto &known) {
					return stringsEqual( known.target, copy.target) ;
				}) ; // 同じ宛先の元ファイルを照合する
				// 異なる元ファイルの同一宛先へのコピー順を推定しない
				if( existing != copies.end()) {
					// 完全に同じコピーだけを同じ関係として扱う
					if( !stringsEqual( existing->source, copy.source)) {
						return false ;
					}
				} else {
					copies.push_back( std::move( copy)) ;
				}
			}
		}
	} while( SetupFindNextLine( &directive, &directive)) ;

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief DDInstallの全サービスが元コピーか明示の空サービスを参照することを確認する
 * @param[in] inf 読み取り専用の元INF
 * @param[in] install 確認済みの元DDInstall
 * @param[in] copies 同DDInstallから解決したコピー関係
 * @param[in,out] rows 共有する導入行の読取予算
 * @return 全サービスを確認できた場合true
 */
//------------------------------------------------------------------------------
bool checkAmd64InstallServices( HINF inf, const std::wstring &install,
							   std::span<const WindowsDriverCopy> copies, std::size_t &rows)
{
	const auto services = install + L".Services" ;						// 同DDInstallのサービス節
	const auto count	= SetupGetLineCountW( inf, services.c_str()) ;	// サービス指示の全行数
	INFCONTEXT row{} ;													// 現在の元AddService行
	// コピーのない節は追加のない関連nullサービスだけを認識する
	if( copies.empty()) {
		return count == 1L && ++rows <= MAXIMUM_INSTALL_INVENTORY_LINES &&
			   SetupFindFirstLineW( inf, services.c_str(), L"AddService", &row) &&
			   isAssociatedNullService( row) ;
	}

	// コピーを伴う場合は全サービス行を確認する
	if( count <= 0L || static_cast<std::size_t>( count) > MAXIMUM_INSTALL_INVENTORY_LINES - rows ||
	   !SetupFindFirstLineW( inf, services.c_str(), nullptr, &row)) {
		return false ;
	}

	// イベント節や外部登録への未知の参照から不要ファイルを推定しない
	do {
		++rows ;
		std::wstring serviceName ;	// 元サービス名
		std::wstring section ;		// 同INFにあるサービスの定義節
		std::wstring key ;			// 元指示の名前
		int			 flags{} ;		// Windowsが解析したAddService flags
		// 追加オペランドを先頭のサービス参照で隠さない
		if( readInfField( row, 0U, key) != 0 || !stringsEqual( key, L"AddService") ||
		   SetupGetFieldCount( &row) != 3U || !SetupGetIntField( &row, 2U, &flags) || flags < 0 ||
		   readInfField( row, 1U, serviceName) != 0 || readInfField( row, 3U, section) != 0 ||
		   !validInstallInventorySectionName( section)) {
			return false ;
		}

		INFCONTEXT setting{} ;	// 同サービス定義の現在行
		// サービス定義の不在を別節の同名値で補完しない
		if( !SetupFindFirstLineW( inf, section.c_str(), nullptr, &setting)) {
			return false ;
		}

		constexpr std::wstring_view keys[]{
			L"ServiceType", L"StartType",	   L"ErrorControl", L"ServiceBinary", L"DisplayName",
			L"Description", L"LoadOrderGroup", L"Dependencies"} ;	// 追加の媒体参照を持たない既知項目
		// 定義全体を確認し、別節を実行する指示を素通ししない
		do {
			// 一つの正常なServiceBinaryで別の作用を隠さない
			if( ++rows > MAXIMUM_INSTALL_INVENTORY_LINES || readInfField( setting, 0U, key) != 0 ||
			   !isAllowedValue( key, keys)) {
				return false ;
			}

			// サービス表示に使う間接リソースはコピーの検査だけで未使用と証明できない
			if( stringsEqual( key, L"DisplayName") || stringsEqual( key, L"Description")) {
				std::wstring label ;	// Windowsが展開したサービスの表示文字列
				// 値を完全に取得してから間接リソース指定か確認する
				if( SetupGetFieldCount( &setting) != 1U ||
				   readInstallInventoryField( setting, 1U, label) != 0) {
					return false ;
				}

				const auto first = label.find_first_not_of( L" \t\r\n") ;	// 先頭の有効文字
				// SCMが読む別モジュールの指定があれば元のファイル存在検査を使う
				if( first != label.npos && label[first] == L'@') {
					return false ;
				}
			}
		} while( SetupFindNextLine( &setting, &setting)) ;

		std::wstring  binary ;	// Windowsが展開した完全な元バイナリ指定
		std::uint32_t type{} ;	// INFが指定したサービスの種類
		// カーネルサービスを同じDDInstallの完全な元コピーへ結ぶ
		if( readRequiredServiceScalar( inf, section, L"ServiceType", type) != 0 ||
		   (type != 1U && type != 2U) ||
		   readRequiredServiceField( inf, section, L"ServiceBinary", binary) != 0 ||
		   !boundWindowsServiceBinary( binary, copies, true)) {
			return false ;
		}
	} while( SetupFindNextLine( &row, &row)) ;

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief AMD64 Modelsから到達する導入節の全候補を確認する
 * @param[in] inf 読み取り専用の元INF
 * @param[in] declarativeClass 表示情報だけのクラス登録を確認済みの場合true
 * @param[in,out] rows 対象全体で共有する導入行の読取予算
 * @param[out] installs 全候補の実在DDInstall。失敗時は部分出力を使わない
 * @param[in] nativeHdc HDCの署名済みSYSへ結ぶ選択とHW節を検査する場合true
 * @param[out] uniqueBase 非nullなら全Modelsが一つの元基本名へ一致することを要求し、その名前を保持する
 * @return 全候補と付随節を有限に確認できた場合true
 * @note 基本節とServicesの各行は呼び出し元で別途検査する
 */
//------------------------------------------------------------------------------
bool collectAmd64InstallSections( HINF inf, bool declarativeClass, std::size_t &rows,
								 std::vector<std::wstring> &installs, bool nativeHdc = false,
								 std::wstring *uniqueBase = nullptr)
{
	std::vector<std::wstring> models ;		// 元Manufacturerで宣言された潜在Models
	std::vector<std::wstring> bases ;		// 全元Modelsが指定するDDInstall基本名
	INFCONTEXT				  layout{} ;	// 別INFの媒体情報への参照
	// 他の媒体表と未解決のModelsを現在OSの正常行から補完しない
	if( SetupFindFirstLineW( inf, L"Version", L"LayoutFile", &layout) ||
	   !collectDeclaredModelBases( inf, true, models, bases, rows, nativeHdc) ||
	   bases.size() > 128U || (uniqueBase != nullptr && bases.size() != 1U)) {
		return false ;
	}

	constexpr std::wstring_view suffixes[]{L"", L".nt", L".ntamd64"} ;	// WindowsのAMD64導入節候補
	// 元Modelsが指定する基本名ごとにWindowsが解決できることを確かめる
	for( const auto &base : bases) {
		std::wstring resolved ;	// 元Windowsが選択した実節名
		// 実在しないfallbackを有効なモデルとして扱わない
		if( resolveActualInstallInventorySection( inf, base, resolved) != 0) {
			return false ;
		}

		// 他の候補にも参照があれば必要ファイルへ残す
		for( const auto suffix : suffixes) {
			auto install = base + std::wstring( suffix) ;	// 現在のAMD64選択候補
			// 存在する候補だけを確認済み集合へ加える
			if( SetupGetLineCountW( inf, install.c_str()) >= 0L) {
				static_cast<void>( appendUnique( installs, std::move( install))) ;
			}
		}

		// Windowsの実選択が既知の候補形式か確認する
		if( std::ranges::none_of( installs,
								[&]( const auto &name) { return stringsEqual( resolved, name) ; })) {
			return false ;
		}
	}

	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> buffer{} ;		// 元節名の受信領域
	bool													   enumerated{} ;	// 全節の正常終端
	// 選択され得る別の作用節がないことを有限に検査する
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		// 終端とAPI失敗を区別する
		if( !SetupEnumInfSectionsW( inf, index, buffer.data(), static_cast<UINT>( buffer.size()),
								  nullptr)) {
			enumerated = GetLastError() == ERROR_NO_MORE_ITEMS ;
			break ;
		}

		const std::wstring_view section( buffer.data()) ;							// Windowsが列挙した元名
		const auto				kind = section.substr( 0U, section.find( L'.')) ;	// 上位節の区分
		// 共通文字列以外による参照差や、別の入口に属する作用を閉包に含められない
		if( (stringsEqual( kind, L"Strings") && section.size() > kind.size()) ||
		   stringsEqual( kind, L"InterfaceInstall32") || stringsEqual( kind, L"DefaultInstall") ||
		   stringsEqual( kind, L"ClassInstall") ||
		   (!declarativeClass && stringsEqual( kind, L"ClassInstall32"))) {
			return false ;
		}

		const auto known = std::ranges::any_of( installs, [&]( const auto &install) {
			return stringsEqual( section, install) ||
				   stringsEqual( section, install + L".Services") ||
				   (nativeHdc && stringsEqual( section, install + L".HW")) ;
		}) ; // 呼出し元が全行を検査する節だけを認める
		// 未到達と断定できない付随節は読み飛ばさない
		if( !known && SetupGetLineCountW( inf, buffer.data()) != 0L &&
		   std::ranges::any_of( bases, [&]( const auto &base) {
			   // 完全な名前とdotで区切った同DDInstallの付随節だけを照合する
			   if( section.size() <= base.size() || section[base.size()] != L'.' ||
				  !stringsEqual( section.substr( 0U, base.size()), base)) {
				   return false ;
			   }

			   const auto rest = section.substr( base.size() + 1U) ;	// 元DDInstallに連なる修飾
			   return !isNonAmd64Decoration( rest.substr( 0U, rest.find( L'.'))) ;
		   })) {
			return false ;
		}
	}

	// 一意の元基本名は全節の読取りが正常に終了した場合だけ保持する
	if( enumerated && uniqueBase != nullptr) {
		*uniqueBase = std::move( bases.front()) ;
	}

	return enumerated ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元基本節のAddRegを同じSYS、シリアル種別、Windows標準ページへ結び付ける
 * @param[in] inf 読み取り中の元INF
 * @param[in] install 元Modelsから解決した実在DDInstall
 * @param[in] driver 元サービスと同じSYSのleaf
 * @param[out] pageSection 標準ページを所有する元AddReg節。失敗時の途中値は使わない
 * @return HKR直下の三値が一意に成立した場合true
 * @note 元登録の用途を読み取る。DLLの実在検査やレジストリ書込みは行わない
 */
//------------------------------------------------------------------------------
bool readNativePortsRegistry( HINF inf, const std::wstring &install, std::wstring_view driver,
							 std::wstring &pageSection)
{
	INFCONTEXT directive{} ;	// 元基本節のAddReg行
	// 別の基本節や付随節を当該端末の書込みへ結ばない
	if( !SetupFindFirstLineW( inf, install.c_str(), L"AddReg", &directive)) {
		return false ;
	}

	const auto fields = SetupGetFieldCount( &directive) ;	// 元AddRegの参照節数
	// 三つの元値をすべて読むため、各値の独立節を含む有限参照だけを認める
	if( fields == 0U || fields > 3U) {
		return false ;
	}

	std::vector<std::wstring> sections ;				// 参照の重複を検出する元節名
	bool					  module{}, subclass{} ;	// 各元値を一度だけ確認する
	// 引用・Strings展開後の元参照を順に検査する
	for( DWORD field = 1U; field <= fields; ++field) {
		std::wstring section ;	// 元DDInstallから到達する各AddReg節
		// 不明な参照先や別の権限指定を読み飛ばさない
		if( readInfField( directive, field, section) != 0 ||
		   !validInstallInventorySectionName( section) || !appendUnique( sections, section) ||
		   SetupGetLineCountW( inf, (section + L".security").c_str()) >= 0L) {
			return false ;
		}

		const auto count = SetupGetLineCountW( inf, section.c_str()) ;	// 同元節の全行数
		// 不在、空、追加値を正しい参照として扱わない
		if( count < 1L || count > 3L) {
			return false ;
		}

		// 元行のスコープと全フィールドを確かめる
		for( LONG index = 0L; index < count; ++index) {
			INFCONTEXT	 entry{} ;							// 元AddReg行
			std::wstring key, root, subkey, name, value ;	// 元登録を構成する文字列
			// デバイス相対の無名五欄だけを読み、追加引数や別subkeyを拒否する
			if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( index), &entry) ||
			   SetupGetFieldCount( &entry) != 5U ||
			   readInstallInventoryField( entry, 0U, key) !=
				   nativeErrorFromWin32( ERROR_INVALID_PARAMETER) ||
			   readInfField( entry, 1U, root) != 0 || !stringsEqual( root, L"HKR") ||
			   readInstallInventoryField( entry, 2U, subkey) != 0 || !subkey.empty() ||
			   readInfField( entry, 3U, name) != 0 || readInfField( entry, 5U, value) != 0) {
				return false ;
			}

			// SYSの記述は元サービスが使う同じleafに限定する
			if( !module && stringsEqual( name, L"NTMPDriver") &&
			   propertyPageNumber( entry, 4U, 0U, true) && stringsEqual( value, driver)) {
				module = true ;
			}
			// PortSubClassは元バイナリの一バイト値だけを扱う
			else if( !subclass && stringsEqual( name, L"PortSubClass") &&
					propertyPageNumber( entry, 4U, 1U, false) && value == L"01") {
				subclass = true ;
			}
			// 登録節と正規DLLの関数名を同じ一行へ結ぶ
			else if( pageSection.empty() && stringsEqual( name, L"EnumPropPages32") &&
					propertyPageNumber( entry, 4U, 0U, true) &&
					isStandardSerialPropertyPage( value)) {
				pageSection = section ;
			} else {
				return false ;
			}
		}
	}

	return module && subclass && !pageSection.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自己のSYSを持つ正式Portsの元コピー、関連サービスと標準ページを読む
 * @param[in] inf 読み取り中の元INF
 * @param[in] relativePath 元アーカイブ内のINFの完全な相対位置
 * @return 有限な元構造がすべて成立した場合だけその関係。その他は空
 * @note 元CAT、コピーの実バイトとWindows標準DLLは後段で独立に検査する
 */
//------------------------------------------------------------------------------
std::optional<OfficialInfNativePortsPage> readNativePortsPropertyPage(
	HINF inf, std::wstring_view relativePath)
{
	std::wstring			  basic ;					// 全AMD64 Modelsが共有する未修飾の選択名
	std::wstring			  className, classGuid ;	// 同じVersionが宣言する正式Portsの識別
	std::size_t				  rows{} ;					// 全元Modelsの読取予算
	std::vector<std::wstring> installs ;				// AMD64で解決された全元基本節
	// 正式なPortsクラスと一つの実基本節に限り、他役割の登録へ拡張しない
	if( readRequiredServiceField( inf, L"Version", L"Class", className) != 0 ||
	   !stringsEqual( className, L"Ports") ||
	   readRequiredServiceField( inf, L"Version", L"ClassGUID", classGuid) != 0 ||
	   !stringsEqual( classGuid, L"{4d36e978-e325-11ce-bfc1-08002be10318}") ||
	   !collectAmd64InstallSections( inf, false, rows, installs, false, &basic) ||
	   installs.size() != 1U) {
		return std::nullopt ;
	}

	const auto	&install = installs.front() ;	// AMD64全Modelsに共通する実元節
	INFCONTEXT	 copyLine{}, copyRow{} ;		// 唯一の元コピー宣言とコピー行
	std::wstring list, driver ;					// 元コピー節と同名SYSのleaf
	// 基本節は一コピーと一AddRegを所有し、同名SYS一行だけを元媒体へ結ぶ
	if( SetupGetLineCountW( inf, install.c_str()) != 2L ||
	   !SetupFindFirstLineW( inf, install.c_str(), L"CopyFiles", &copyLine) ||
	   SetupGetFieldCount( &copyLine) != 1U || readInfField( copyLine, 1U, list) != 0 ||
	   list.starts_with( L"@") || !validInstallInventorySectionName( list) ||
	   SetupGetLineCountW( inf, list.c_str()) != 1L ||
	   SetupGetLineCountW( inf, (list + L".security").c_str()) >= 0L ||
	   !SetupGetLineByIndexW( inf, list.c_str(), 0U, &copyRow) ||
	   SetupGetFieldCount( &copyRow) != 1U || readInfField( copyRow, 1U, driver) != 0 ||
	   lowerExtension( driver) != L".sys") {
		return std::nullopt ;
	}

	const auto		  separator = relativePath.find_last_of( L'\\') ;	// 元INFの媒体内の親境界
	const auto		  parent	= separator == relativePath.npos
									  ? std::wstring_view{}
									  : relativePath.substr( 0U, separator) ;	// 元媒体の親位置
	WindowsDriverCopy copy ;													// 元SYSの媒体位置と正確なコピー予定先
	// Driver Storeの元相対位置と同名コピーを維持する
	if( resolveWindowsDriverCopy( inf, parent, list, driver, driver, copy) != 0 || copy.dirid != 13) {
		return std::nullopt ;
	}

	const auto	  services = install + L".Services" ;	// 選択基本節が所有する元サービス節
	INFCONTEXT	  serviceLine{} ;						// 唯一の元関連カーネルの宣言
	int			  flags{} ;								// 宣言された関連フラグ
	std::wstring  name, service, display, binary ;		// 原サービス名、原節、表示名とBinary
	std::uint32_t type{}, start{}, control{} ;			// 元カーネル種別、開始、エラー制御
	// 選択したSYS以外のサービス、イベント登録と他のサービス作用を受け入れない
	if( SetupGetLineCountW( inf, services.c_str()) != 1L ||
	   !SetupFindFirstLineW( inf, services.c_str(), L"AddService", &serviceLine) ||
	   SetupGetFieldCount( &serviceLine) != 3U || !SetupGetIntField( &serviceLine, 2U, &flags) ||
	   flags != SPSVCINST_ASSOCSERVICE || readInfField( serviceLine, 1U, name) != 0 ||
	   !validRequiredServiceSubdirectory( name) || name.find( L'\\') != name.npos ||
	   readInfField( serviceLine, 3U, service) != 0 || !validInstallInventorySectionName( service) ||
	   SetupGetLineCountW( inf, service.c_str()) != 5L ||
	   readRequiredServiceField( inf, service, L"DisplayName", display) != 0 ||
	   readRequiredServiceScalar( inf, service, L"ServiceType", type) != 0 ||
	   type != SERVICE_KERNEL_DRIVER ||
	   readRequiredServiceScalar( inf, service, L"StartType", start) != 0 ||
	   start != SERVICE_DEMAND_START ||
	   readRequiredServiceScalar( inf, service, L"ErrorControl", control) != 0 ||
	   control != SERVICE_ERROR_NORMAL ||
	   readRequiredServiceField( inf, service, L"ServiceBinary", binary) != 0 ||
	   !boundWindowsServiceBinary( binary, std::span{&copy, 1U}, true)) {
		return std::nullopt ;
	}

	std::wstring pageSection ;	// 関連SYSと同選択に属する正規ページの登録節
	// 元三値がすべて揃うまで部分的な構造を後段へ渡さない
	if( !readNativePortsRegistry( inf, install, driver, pageSection)) {
		return std::nullopt ;
	}

	return OfficialInfNativePortsPage{std::move( basic), install, std::move( pageSection),
									  std::move( copy.source)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元宣言の全fieldを、重複のない一行から読む
 * @param[in] inf 検査中のINF
 * @param[in] section 元作用節
 * @param[in] key 読み取る識別子
 * @param[out] values 指定数の元値。失敗時の途中値は使用しない
 * @return 完全な一行を読み取った場合true
 */
//------------------------------------------------------------------------------
bool readSerialDirective( HINF inf, const std::wstring &section, const wchar_t *key,
						 const std::span<std::wstring> values)
{
	INFCONTEXT row{} ;			// 元宣言の一行
	INFCONTEXT duplicate{} ;	// 同じ宣言の後続行
	// 重複や未検査の引数を、最初の値だけで解決しない
	if( !SetupFindFirstLineW( inf, section.c_str(), key, &row) ||
	   SetupGetFieldCount( &row) != values.size() ||
	   SetupFindNextMatchLineW( &row, key, &duplicate)) {
		return false ;
	}

	DWORD index = 1U ;	// SetupAPIのfield番号は1から開始
	// 作用の所有者・値・順序を保持するため、元の全fieldを読む
	for( auto &value : values) {
		// 空または読めない元参照先を別の節から補わない
		if( readInfField( row, index++, value) != 0U) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択が唯一参照するWindowsシリアル列挙INFと節名を照合する
 * @param[in] inf 検査中のINF
 * @param[in] section 元基本節またはそのServices節
 * @param[in] expected 指定するWindowsの元節名
 * @return 唯一のIncludeとNeedsが元の組と一致した場合true
 */
//------------------------------------------------------------------------------
bool hasSerialEnumeratorNeeds( HINF inf, const std::wstring &section, std::wstring_view expected)
{
	std::wstring value ;	// 一件だけの展開済み参照先
	return readRequiredServiceField( inf, section, L"Include", value) == 0U &&
		   stringsEqual( value, L"msports.inf") &&
		   readRequiredServiceField( inf, section, L"Needs", value) == 0U &&
		   stringsEqual( value, expected) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元レジストリ登録一行をデバイス相対の指定型へ限定する
 * @param[in] inf 検査中のINF
 * @param[in] section 元選択から参照するAddReg
 * @param[in] index 元節内の0始まりの順序
 * @param[in] expectedName 必要な元の値名
 * @param[in] flags 期待する正確な書込み型
 * @param[out] value 成功時の元登録データ。失敗時は使用しない
 * @return 無名五項目とHKR直下、指定した値名と型を確認した場合true
 */
//------------------------------------------------------------------------------
bool readSerialRegistration( HINF inf, const std::wstring &section, const DWORD index,
							std::wstring_view expectedName, const std::uint32_t flags,
							std::wstring &value)
{
	INFCONTEXT	 row{} ;	// 元節の順序と型を照合する一行
	std::wstring field ;	// 無名行の検査、root、subkeyおよび値名に用いる
	return SetupGetLineByIndexW( inf, section.c_str(), index, &row) &&
		   SetupGetFieldCount( &row) == 5U &&
		   readInstallInventoryField( row, 0U, field) ==
			   nativeErrorFromWin32( ERROR_INVALID_PARAMETER) &&
		   readInfField( row, 1U, field) == 0U && stringsEqual( field, L"HKR") &&
		   readInstallInventoryField( row, 2U, field) == 0U && field.empty() &&
		   readInfField( row, 3U, field) == 0U && stringsEqual( field, expectedName) &&
		   propertyPageNumber( row, 4U, flags, flags == 0U) && readInfField( row, 5U, value) == 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Portsの個別設定を指定されたHKR文脈とDWORD型へ限定して読む
 * @param[in] inf 呼出し中だけ借用する元INF
 * @param[in] section 同じ選択が参照する元設定節
 * @param[in] subkey 機器キーの直下またはサービスのParameters
 * @param[in] flags その文脈で要求する厳密なDWORD書込みflags
 * @param[in,out] names 同じ登録文脈内で既出の値名。失敗時の途中値は使わない
 * @return 全行が同じ文脈に閉じ、重複や未評価の行がない場合true
 */
//------------------------------------------------------------------------------
bool readSharedPortsSettings( HINF inf, const std::wstring &section, std::wstring_view subkey,
							 std::uint32_t flags, std::vector<std::wstring> &names)
{
	// Windowsが機器やサービス制御に使う値は個別設定として扱わない
	constexpr std::wstring_view RESERVED[]{L"UpperFilters",
										   L"LowerFilters",
										   L"ConfigFlags",
										   L"Capabilities",
										   L"DeviceCharacteristics",
										   L"DeviceType",
										   L"Exclusive",
										   L"Security",
										   L"SecuritySDS",
										   L"DeviceInterfaceGUIDs",
										   L"DeviceInterfaceGUID",
										   L"Driver",
										   L"Service",
										   L"Class",
										   L"ClassGUID",
										   L"CoInstallers32",
										   L"Installer32",
										   L"EnumPropPages32",
										   L"PortSubClass",
										   L"PortName",
										   L"NTMPDriver",
										   L"InfPath",
										   L"InfSection",
										   L"ServiceDll",
										   L"ServiceMain"} ;
	const auto count = SetupGetLineCountW( inf, section.c_str()) ;	// 元節の全書込み数
	// 欠落節と別の権限指定を空の個別設定として採用しない
	if( !validInstallInventorySectionName( section) || count < 1L || count > 16L ||
	   SetupGetLineCountW( inf, (section + L".security").c_str()) >= 0L) {
		return false ;
	}

	// 選択中の設定を全件読み、別のキーや重複値による上書きを拒否する
	for( LONG index = 0L; index < count; ++index) {
		INFCONTEXT					  row{} ;		// 元の設定行
		std::wstring				  field ;		// 型・ルート・相対位置を照合する元値
		std::wstring				  name ;		// 同じ文脈に属する元設定名
		std::uint32_t				  value{} ;		// 元DWORDの全桁を読んだ値
		int							  native{} ;	// SetupAPIによる同じ32ビット値
		MaintenanceInfStructureReason reason{} ;	// 共通数値readerの診断
		// 元の作用がDWORDの単一機器設定または関連サービス設定として成立することを確かめる
		if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( index), &row) ||
		   SetupGetFieldCount( &row) != 5U ||
		   readInstallInventoryField( row, 0U, field) !=
			   nativeErrorFromWin32( ERROR_INVALID_PARAMETER) ||
		   readInfField( row, 1U, field) != 0U || !stringsEqual( field, L"HKR") ||
		   readInstallInventoryField( row, 2U, field) != 0U || !stringsEqual( field, subkey) ||
		   readInfField( row, 3U, name) != 0U || name.empty() || name.size() > 80U ||
		   name.find_first_not_of(
			   L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != name.npos ||
		   isAllowedValue( name, RESERVED) || !propertyPageNumber( row, 4U, flags, false) ||
		   readInfField( row, 5U, field) != 0U ||
		   parseMaintenanceFlags( field, value, reason).state !=
			   MaintenanceInspectionState::PASSED ||
		   !SetupGetIntField( &row, 5U, &native) || static_cast<std::uint32_t>( native) != value ||
		   !appendUnique( names, std::move( name))) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共有ページを登録する一つの元DDInstallと全付随節を検査する
 * @param[in] inf 呼出し中だけ借用する元INF
 * @param[in] install 元INFでWindowsが解決できる同じ実DDInstall名
 * @param[in,out] allowed 成功時に作用を確認した全節を閉集合へ加える
 * @param[out] copy 元DDInstallが選ぶ共有コピー節
 * @param[out] registry 元DDInstallが所有する共有ソフトウェア登録節
 * @param[out] service 元選択の関連サービス名と元サービス定義節
 * @return 唯一のコピー、標準ページ、関連サービスと個別HW設定だけの場合true
 */
//------------------------------------------------------------------------------
bool readSharedPortsInstall( HINF inf, const std::wstring &install,
							std::vector<std::wstring> &allowed, std::wstring &copy,
							std::wstring &registry, std::array<std::wstring, 2U> &service)
{
	const auto					 services = install + L".Services" ;	// 元関連サービスの所有節
	const auto					 hardware = install + L".HW" ;			// 同元選択の機器設定節
	std::array<std::wstring, 1U> copyEntry ;							// 共有コピーの一参照
	std::array<std::wstring, 1U> registryEntry ;						// 標準ページを直接所有する一参照
	std::array<std::wstring, 3U> serviceEntry ;							// AddServiceの元名、flags、読取り先
	INFCONTEXT					 line{} ;								// 同一関連サービスのflagsを数値照合する元行
	// 非実行の内容検査に結び付ける三つの用途を同じ元選択から取得する
	if( SetupGetLineCountW( inf, install.c_str()) != 2L ||
	   !readSerialDirective( inf, install, L"CopyFiles", copyEntry) ||
	   !validInstallInventorySectionName( copyEntry.front()) ||
	   copyEntry.front().starts_with( L"@") ||
	   !readSerialDirective( inf, install, L"AddReg", registryEntry) ||
	   !validInstallInventorySectionName( registryEntry.front()) ||
	   SetupGetLineCountW( inf, services.c_str()) != 1L ||
	   !readSerialDirective( inf, services, L"AddService", serviceEntry) ||
	   !SetupFindFirstLineW( inf, services.c_str(), L"AddService", &line) ||
	   !propertyPageNumber( line, 2U, SPSVCINST_ASSOCSERVICE, false) ||
	   !validRequiredServiceSubdirectory( serviceEntry[0]) ||
	   serviceEntry[0].find( L'\\') != std::wstring::npos ||
	   !validInstallInventorySectionName( serviceEntry[2]) ||
	   SetupGetLineCountW( inf, hardware.c_str()) != 1L ||
	   !SetupFindFirstLineW( inf, hardware.c_str(), L"AddReg", &line)) {
		return false ;
	}

	const auto fields = SetupGetFieldCount( &line) ;	// 共有設定と選択別設定の元参照数
	// 未確認の追加設定や空参照が部分的に通らないようにする
	if( fields == 0U || fields > 4U) {
		return false ;
	}

	std::vector<std::wstring> names ;	// 一つのHWキーに書く全値名
	// 元参照を順に辿り、共有節を含めて同じ機器キーへの書込みを照合する
	for( DWORD field = 1U; field <= fields; ++field) {
		std::wstring section ;	// 元HWが参照する設定節
		// 解析できない節を閉集合へ加えない
		if( readInfField( line, field, section) != 0U ||
		   !readSharedPortsSettings( inf, section, L"", FLG_ADDREG_TYPE_DWORD, names)) {
			return false ;
		}

		static_cast<void>( appendUnique( allowed, std::move( section))) ;
	}

	static_cast<void>( appendUnique( allowed, install)) ;
	static_cast<void>( appendUnique( allowed, hardware)) ;
	static_cast<void>( appendUnique( allowed, services)) ;
	copy	 = std::move( copyEntry.front()) ;
	registry = std::move( registryEntry.front()) ;
	service	 = {std::move( serviceEntry[0]), std::move( serviceEntry[2])} ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通SYSを持つPortsの複数選択と標準ページを収集用に静的照合する
 * @param[in] inf 同じ元INFの読取り専用handle
 * @param[in] relativePath 書庫内の元INF位置
 * @return 全節とコピー／サービス／設定の所有が閉じる場合だけ後段の検査要求
 * @note 元CAT、実AMD64 SYSとWindows標準DLLは共通閉包の後段で検証する
 * @see docs/adr/0590-collector-shared-native-ports-property-page.md
 */
//------------------------------------------------------------------------------
std::optional<OfficialInfCollectorSharedPortsPage> readCollectorSharedPortsPage(
	HINF inf, std::wstring_view relativePath)
{
	std::wstring			  classGuid ;						// 正式Portsの元GUID
	std::size_t				  rows{} ;							// 同じINFのAMD64 Models読取り予算
	std::vector<std::wstring> active ;							// 元AMD64 Modelsから解決される選択候補
	constexpr std::size_t	  MAXIMUM_PORTS_INSTALLS = 16U ;	// 共有する元全選択の有限枠
	// 複数のAMD64選択に対する検査に限り、従来の単一選択に代入しない
	if( readRequiredServiceField( inf, L"Version", L"ClassGUID", classGuid) != 0U ||
	   !stringsEqual( classGuid, L"{4d36e978-e325-11ce-bfc1-08002be10318}") ||
	   !collectAmd64InstallSections( inf, false, rows, active, true) || active.size() < 2U ||
	   active.size() > MAXIMUM_PORTS_INSTALLS) {
		return std::nullopt ;
	}

	std::vector<std::wstring> allowed ;				// 既知の宣言と検査済み作用の閉集合
	std::vector<std::wstring> declared ;			// 未装飾と旧architectureを含む元基本名
	std::size_t				  declarationRows{} ;	// 全元ManufacturerとModelsの独立読取り数
	// 全Modelsを検査し、元版や他architectureの参照を未宣言のまま許さない
	if( !collectDeclaredModelBases( inf, false, allowed, declared, declarationRows) ||
	   declared.size() > MAXIMUM_PORTS_INSTALLS) {
		return std::nullopt ;
	}

	constexpr std::wstring_view METADATA[]{L"Version",
										   L"ControlFlags",
										   L"Manufacturer",
										   L"SourceDisksNames",
										   L"SourceDisksFiles",
										   L"SourceDisksNames.amd64",
										   L"SourceDisksFiles.amd64",
										   L"DestinationDirs",
										   L"Strings"} ;					// 共通またはAMD64媒体を含む基礎宣言
	std::vector<std::wstring>	installs ;									// 参照外の同じ形状も含め検査する実DDInstall
	std::vector<std::wstring>	sections ;									// 未検査節の滞留を防ぐ元全節
	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> buffer{} ;	// SetupAPIの元節名
	bool													   ended{} ;	// 全節の正常終端
	const auto contains = []( std::span<const std::wstring> names, std::wstring_view name) {
		return std::ranges::any_of(
			names, [name]( const auto &candidate) { return stringsEqual( name, candidate) ; }) ;
	} ; // 呼出し中だけ借用した元節名を完全比較する
	// 推定の逆参照に頼らず、元の全節を列挙して作用を分類する
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		// 列挙失敗は正常終端として扱わない
		if( !SetupEnumInfSectionsW( inf, index, buffer.data(), static_cast<UINT>( buffer.size()),
								  nullptr)) {
			ended = GetLastError() == ERROR_NO_MORE_ITEMS ;
			break ;
		}

		const std::wstring_view section( buffer.data()) ;	// 元節名
		// 作用を持たない既知の宣言は閉集合へ重複して加えない
		if( isAllowedValue( section, METADATA) || contains( allowed, section)) {
			continue ;
		}

		sections.emplace_back( section) ;
		// 旧選択の残存節も完全な同じ実DDInstallとして検査する
		if( section.size() > 3U && stringsEqual( section.substr( section.size() - 3U), L".NT")) {
			const std::wstring base( section.substr( 0U, section.size() - 3U)) ;	// 元基本名
			std::wstring	   resolved ;											// Windowsが解決した元選択名
			// 他の修飾先や別の作用が同じ登録を借りないようにする
			if( installs.size() >= MAXIMUM_PORTS_INSTALLS ||
			   !validInstallInventorySectionName( base) ||
			   resolveActualInstallInventorySection( inf, base, resolved) != 0U ||
			   !stringsEqual( section, resolved)) {
				return std::nullopt ;
			}

			installs.emplace_back( section) ;
		}
	}

	// 全AMD64選択と宣言済みの各基本名が既知の形状に含まれることを確かめる
	if( !ended ||
	   !std::ranges::all_of( active, [&]( const auto &name) { return contains( installs, name) ; }) ||
	   !std::ranges::all_of( declared,
							[&]( const auto &base) { return contains( installs, base + L".NT") ; })) {
		return std::nullopt ;
	}

	std::wstring				 sharedCopy ;		// 全選択で一致する元コピー節
	std::wstring				 sharedRegistry ;	// 全選択で一致する元標準ページの所有節
	std::array<std::wstring, 2U> sharedService ;	// 全選択が共有する関連サービス名と定義節
	// 実選択と残存選択の全作用を同じ元コピー、登録、サービスへ結び付ける
	for( const auto &install : installs) {
		std::wstring				 copy ;		// 当該選択の元コピー節
		std::wstring				 registry ;	// 当該選択の元登録節
		std::array<std::wstring, 2U> service ;	// 当該選択の元サービス名と定義節
		// 一つの不成立を他の正常選択で補完しない
		if( !readSharedPortsInstall( inf, install, allowed, copy, registry, service)) {
			return std::nullopt ;
		}

		// 先頭だけが共有部分の比較基準を定める
		if( sharedCopy.empty()) {
			sharedCopy	   = std::move( copy) ;
			sharedRegistry = std::move( registry) ;
			sharedService  = std::move( service) ;
			continue ;
		}

		// 選択によって所有や元媒体が変わる場合に共有ページを認定しない
		if( !stringsEqual( copy, sharedCopy) || !stringsEqual( registry, sharedRegistry) ||
		   !stringsEqual( service[0], sharedService[0]) ||
		   !stringsEqual( service[1], sharedService[1])) {
			return std::nullopt ;
		}
	}

	INFCONTEXT	 copyRow{} ;										// 共有SYSを指定する唯一の原行
	INFCONTEXT	 destination{} ;									// 共有SYSの唯一の元宛先
	std::wstring driver ;											// 元同名コピーのSYS leaf
	std::wstring empty ;											// 省略のコピー元と一時名を照合する空field
	const auto	 separator = relativePath.find_last_of( L'\\') ;	// 同じ書庫内の元INF親境界
	// 書庫ルートのINFは空の親位置に結ぶ
	const auto	 parent = relativePath.substr( 0U, separator == relativePath.npos ? 0U : separator) ;
	WindowsDriverCopy copy ;	// Windowsが解決した元SYSと実コピー先
	// 同じ元SYSからDIRID 12へコピーし、新しい配置済み版を維持する元指定を読む
	if( SetupGetLineCountW( inf, sharedCopy.c_str()) != 1L ||
	   !SetupGetLineByIndexW( inf, sharedCopy.c_str(), 0U, &copyRow) ||
	   SetupGetFieldCount( &copyRow) != 4U || readInfField( copyRow, 1U, driver) != 0U ||
	   lowerExtension( driver) != L".sys" || readInstallInventoryField( copyRow, 2U, empty) != 0U ||
	   !empty.empty() || readInstallInventoryField( copyRow, 3U, empty) != 0U || !empty.empty() ||
	   !propertyPageNumber( copyRow, 4U, COPYFLG_NO_VERSION_DIALOG, false) ||
	   SetupGetLineCountW( inf, L"DestinationDirs") != 1L ||
	   (!SetupFindFirstLineW( inf, L"DestinationDirs", sharedCopy.c_str(), &destination) &&
		!SetupFindFirstLineW( inf, L"DestinationDirs", L"DefaultDestDir", &destination)) ||
	   SetupGetFieldCount( &destination) != 1U || !propertyPageNumber( destination, 1U, 12U, false) ||
	   resolveWindowsDriverCopy( inf, parent, sharedCopy, driver, driver, copy) != 0U ||
	   copy.dirid != 12) {
		return std::nullopt ;
	}

	const auto					&service = sharedService[1] ;	// 全選択の同じ関連サービス定義
	std::wstring				 value ;						// 元サービスBinaryまたは標準登録のデータ
	std::uint32_t				 scalar{} ;						// 原Type、開始、ErrorControlを読み取る値
	std::array<std::wstring, 1U> parameters ;					// 同じ関連サービス配下の設定節
	std::vector<std::wstring>	 serviceNames ;					// サービス文脈内の既出設定名
	// 別のサービス、別媒体とページの型、共有登録の余剰行を許可しない
	if( SetupGetLineCountW( inf, service.c_str()) != 5L ||
	   readRequiredServiceScalar( inf, service, L"ServiceType", scalar) != 0U ||
	   scalar != SERVICE_KERNEL_DRIVER ||
	   readRequiredServiceScalar( inf, service, L"StartType", scalar) != 0U ||
	   scalar != SERVICE_DEMAND_START ||
	   readRequiredServiceScalar( inf, service, L"ErrorControl", scalar) != 0U ||
	   scalar != SERVICE_ERROR_NORMAL ||
	   readRequiredServiceField( inf, service, L"ServiceBinary", value) != 0U ||
	   !boundWindowsServiceBinary( value, std::span{&copy, 1U}, true) ||
	   !readSerialDirective( inf, service, L"AddReg", parameters) ||
	   !readSharedPortsSettings( inf, parameters.front(), L"Parameters",
								FLG_ADDREG_TYPE_DWORD | FLG_ADDREG_NOCLOBBER, serviceNames) ||
	   SetupGetLineCountW( inf, sharedRegistry.c_str()) != 2L ||
	   !readSerialRegistration( inf, sharedRegistry, 0U, L"PortSubClass", FLG_ADDREG_TYPE_BINARY,
							   value) ||
	   value != L"01" ||
	   !readSerialRegistration( inf, sharedRegistry, 1U, L"EnumPropPages32", 0U, value) ||
	   !isStandardSerialPropertyPage( value)) {
		return std::nullopt ;
	}

	static_cast<void>( appendUnique( allowed, sharedCopy)) ;
	static_cast<void>( appendUnique( allowed, sharedRegistry)) ;
	static_cast<void>( appendUnique( allowed, service)) ;
	static_cast<void>( appendUnique( allowed, parameters.front())) ;
	// 個別に認めた節以外を保持しないことで、非選択や別文脈からの逆参照も拒否する
	if( !std::ranges::all_of( sections,
							[&]( const auto &section) { return contains( allowed, section) ; })) {
		return std::nullopt ;
	}

	return OfficialInfCollectorSharedPortsPage{std::move( sharedRegistry), std::move( copy.source)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのコピー節を、明示Windows宛先と同名の元媒体へ解決する
 * @param[in] inf 検査中のINF
 * @param[in] list 実DDInstallが宣言した元リスト名
 * @param[in] expectedDirectory 要求する明示DIRID
 * @param[in] extension 要求する元ファイルの拡張子
 * @param[out] leaf 成功時のコピー元とコピー先に共通するleaf
 * @param[out] copy 同じ一行の元媒体位置とWindowsのコピー先
 * @return 明示先と同名コピーだけが存在する場合true
 */
//------------------------------------------------------------------------------
bool readSerialMediaCopy( HINF inf, const std::wstring &list, const std::uint32_t expectedDirectory,
						 std::wstring_view extension, std::wstring &leaf, WindowsDriverCopy &copy)
{
	INFCONTEXT	 row{} ;			// 元コピー一覧の唯一の通常ファイル
	INFCONTEXT	 destination{} ;	// 元コピー一覧に対する明示宛先
	std::wstring key ;				// SetupAPIが単独のコピー名に返す見出し
	return validInstallInventorySectionName( list) && SetupGetLineCountW( inf, list.c_str()) == 1L &&
		   SetupGetLineByIndexW( inf, list.c_str(), 0U, &row) && SetupGetFieldCount( &row) == 1U &&
		   readInfField( row, 1U, leaf) == 0U && lowerExtension( leaf) == extension &&
		   readInfField( row, 0U, key) == 0U && stringsEqual( key, leaf) &&
		   SetupFindFirstLineW( inf, L"DestinationDirs", list.c_str(), &destination) &&
		   SetupGetFieldCount( &destination) == 1U &&
		   propertyPageNumber( destination, 1U, expectedDirectory, false) &&
		   resolveWindowsDriverCopy( inf, {}, list, leaf, leaf, copy) == 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの元選択が共有するベンダーの関連カーネルサービスを照合する
 * @param[in] inf 検査中のINF
 * @param[in] section 両選択から同じ名前で指定されたサービスの実体節
 * @param[in] driver 同元INFのコピーで確定した自前SYSの元媒体と宛先
 * @return 六つの既知行だけで同じSYSを指す要求時開始サービスの場合true
 */
//------------------------------------------------------------------------------
bool matchesSerialMediaService( HINF inf, const std::wstring &section,
							   const WindowsDriverCopy &driver)
{
	std::wstring  value ;		// サービスの表示名・実体パス・所属グループ
	std::uint32_t scalar{} ;	// Windowsの数値readerで検証済みの種別等
	return validInstallInventorySectionName( section) &&
		   SetupGetLineCountW( inf, section.c_str()) == 6L &&
		   readRequiredServiceField( inf, section, L"DisplayName", value) == 0U &&
		   readRequiredServiceScalar( inf, section, L"ServiceType", scalar) == 0U &&
		   scalar == SERVICE_KERNEL_DRIVER &&
		   readRequiredServiceScalar( inf, section, L"StartType", scalar) == 0U &&
		   scalar == SERVICE_DEMAND_START &&
		   readRequiredServiceScalar( inf, section, L"ErrorControl", scalar) == 0U &&
		   scalar == SERVICE_ERROR_NORMAL &&
		   readRequiredServiceField( inf, section, L"ServiceBinary", value) == 0U &&
		   boundWindowsServiceBinary( value, std::span{&driver, 1U}, true) &&
		   readRequiredServiceField( inf, section, L"LoadOrderGroup", value) == 0U &&
		   stringsEqual( value, L"Base") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元INFの両AMD64選択にある自前媒体とWindowsシリアル列挙の参照を照合する
 * @param[in] inf 私有収集の元INF
 * @param[out] pages 検証済みDLLと各選択が直接所有するAddReg。失敗時は使用しない
 * @param[out] media 共通SYSと二つの依存検査要求。失敗時は使用しない
 * @return 全元作用と所有節が既知の範囲に閉じている場合true
 */
//------------------------------------------------------------------------------
bool readCollectorSerialMedia( HINF inf, PropertyPageContext &pages,
							  OfficialInfCollectorSerialMedia &media)
{
	std::wstring			   value ;		// 一意のクラスと各登録値の共通読み取り
	std::vector<std::wstring>  sections ;	// 元Modelsと検証済み作用だけの閉じた節集合
	std::vector<std::wstring>  declared ;	// 全潜在DDInstallの元基本名
	std::size_t				   rows{} ;		// 元Modelsの共有読取り予算
	MaintenanceStructureBudget budget ;		// Windowsが選んだ明示AMD64選択の読取り予算
	std::vector<std::wstring>  bases ;		// Windowsが選んだ二つの基本名
	INFCONTEXT				   layout{} ;	// 別INFの媒体表を持ち込む指定の有無
	// 正式クラスと同じ公開Modelsの全選択を入力の境界にする
	if( readRequiredServiceField( inf, L"Version", L"ClassGUID", value) != 0U ||
	   !stringsEqual( value, L"{4d36e978-e325-11ce-bfc1-08002be10318}") ||
	   readRequiredServiceField( inf, L"Version", L"Class", value) != 0U ||
	   !stringsEqual( value, L"Ports") ||
	   SetupFindFirstLineW( inf, L"Version", L"LayoutFile", &layout) ||
	   !collectDeclaredModelBases( inf, true, sections, declared, rows) ||
	   collectMaintenanceInstallNames( inf, budget, bases, true) != 0U || bases.size() != 2U ||
	   declared.size() != bases.size()) {
		return false ;
	}

	std::array<std::wstring, 2U> copies ;	// 最初の選択から確定する共通SYSとDLLのCopyFiles
	std::array<std::wstring, 3U> service ;	// 両選択に共通するAddServiceの全field
	std::uint32_t firstDeviceType{} ;		// 最初の選択の元DWORD。同じ値を別機種へ流用しない
	std::wstring  driverLeaf ;				// 同名コピーとNTMPDriverを結ぶ自前SYS名
	std::wstring  pageValue ;				// EnumPropPages32の元DLL名とcallback
	constexpr std::wstring_view SERIAL_PAGE_CALLBACK =
		L"SerialPortPropPageProvider" ;	// 読み取るDLLの公開名
	// 二つの明示AMD64選択について個別の全作用と共有媒体・サービスを照合する
	for( const auto &base : bases) {
		std::wstring install ;	// Windowsが解決した元DDInstall
		// 同じ元版に含まれない基本名や未解決節を採用しない
		if( std::ranges::none_of( declared,
								[&]( const auto &name) { return stringsEqual( base, name) ; }) ||
		   resolveActualInstallInventorySection( inf, base, install) != 0U) {
			return false ;
		}

		const auto	 hardware = install + L".HW" ;			// 同じ元DDInstallの機器登録
		const auto	 services = install + L".Services" ;	// 同じ元DDInstallのサービス登録
		std::wstring registry ;								// 元基本節が直接参照するレジストリ節
		std::wstring hardwareRegistry ;						// HW節が直接参照する上位フィルター登録節
		std::array<std::wstring, 2U>  selectedCopies ;		// この選択の元コピー値
		std::array<std::wstring, 3U>  selectedService ;		// この選択の元関連サービス値
		std::uint32_t				  deviceType{} ;		// 正規DWORDの読取り値
		MaintenanceInfStructureReason reason{} ;			// 数値readerの診断分類
		// 既知の組合せに追加作用や別INFを混ぜない
		if( SetupGetLineCountW( inf, install.c_str()) != 4L ||
		   !hasSerialEnumeratorNeeds( inf, install, L"SerialEnumerator.NT") ||
		   !readSerialDirective( inf, install, L"CopyFiles", selectedCopies) ||
		   readRequiredServiceField( inf, install, L"AddReg", registry) != 0U ||
		   SetupGetLineCountW( inf, hardware.c_str()) != 1L ||
		   readRequiredServiceField( inf, hardware, L"AddReg", hardwareRegistry) != 0U ||
		   SetupGetLineCountW( inf, hardwareRegistry.c_str()) != 1L ||
		   !readSerialRegistration( inf, hardwareRegistry, 0U, L"UpperFilters", 0x10000U, value) ||
		   !stringsEqual( value, L"Serenum") || SetupGetLineCountW( inf, services.c_str()) != 3L ||
		   !hasSerialEnumeratorNeeds( inf, services, L"SerialEnumerator.NT.Services") ||
		   !readSerialDirective( inf, services, L"AddService", selectedService) ||
		   SetupGetLineCountW( inf, registry.c_str()) != 4L) {
			return false ;
		}

		// 初回選択から二つの共有媒体とサービスの元契約を固定する
		if( media.groups.empty()) {
			WindowsDriverCopy driver ;	// 元SYSとドライバー宛先
			WindowsDriverCopy dll ;		// 元DLLとWindowsシステム宛先
			std::wstring	  dllLeaf ;	// 登録が参照する同じDLL名
			INFCONTEXT		  flags{} ;	// 関連サービスの元flags
			// 未検査の宛先と別の標準Serenumをベンダーのサービスに混ぜない
			if( !readSerialMediaCopy( inf, selectedCopies[0], 12U, L".sys", driverLeaf, driver) ||
			   !readSerialMediaCopy( inf, selectedCopies[1], 11U, L".dll", dllLeaf, dll) ||
			   !validRequiredServiceSubdirectory( selectedService[0]) ||
			   selectedService[0].find( L'\\') != std::wstring::npos ||
			   stringsEqual( selectedService[0], L"Serenum") ||
			   !SetupFindFirstLineW( inf, services.c_str(), L"AddService", &flags) ||
			   !propertyPageNumber( flags, 2U, SPSVCINST_ASSOCSERVICE, false) ||
			   !matchesSerialMediaService( inf, selectedService[2], driver) ||
			   !appendUnique( sections, selectedCopies[0]) ||
			   !appendUnique( sections, selectedCopies[1]) ||
			   !appendUnique( sections, selectedService[2])) {
				return false ;
			}

			copies			   = selectedCopies ;
			service			   = selectedService ;
			media.driverSource = std::move( driver.source) ;
			pages.binding =
				OfficialInfPropertyPage{std::move( dll.source), std::wstring( SERIAL_PAGE_CALLBACK)} ;
			pageValue = dllLeaf + L"," + std::wstring( SERIAL_PAGE_CALLBACK) ;
		}

		// 片方だけの別媒体、元順序と異なる登録、他選択と共有する登録節を拒否する
		if( copies != selectedCopies || service != selectedService ||
		   !readSerialRegistration( inf, registry, 0U, L"NTMPDriver", 0U, value) ||
		   !stringsEqual( value, L"*ntkern") ||
		   !readSerialRegistration( inf, registry, 1U, L"NTMPDriver", 0U, value) ||
		   !stringsEqual( value, driverLeaf) ||
		   !readSerialRegistration( inf, registry, 2U, L"EnumPropPages32", 0U, value) ||
		   value != pageValue ||
		   !readSerialRegistration( inf, registry, 3U, L"DevType", 0x10001U, value) ||
		   parseMaintenanceFlags( value, deviceType, reason).state !=
			   MaintenanceInspectionState::PASSED ||
		   deviceType == 0U || deviceType == firstDeviceType || !appendUnique( sections, install) ||
		   !appendUnique( sections, hardware) || !appendUnique( sections, services) ||
		   !appendUnique( sections, registry) || !appendUnique( sections, hardwareRegistry)) {
			return false ;
		}

		firstDeviceType = deviceType ;
		pages.owners.emplace_back( install, std::move( registry)) ;
		media.groups.push_back( {std::move( install), hardware, services}) ;
	}

	constexpr std::wstring_view metadata[]{
		L"Version",			 L"Manufacturer",			L"Strings",
		L"SourceDisksFiles", L"SourceDisksNames.amd64", L"SourceDisksNames.x86",
		L"DestinationDirs"} ;			// 元配布が使う非作用節
	INFCONTEXT defaultDestination{} ;	// 元宣言の既定宛先
	// 余分な媒体ファイルや未検査のコピー先指定を残さない
	if( SetupGetLineCountW( inf, L"SourceDisksFiles") != 2L ||
	   SetupGetLineCountW( inf, L"DestinationDirs") != 3L ||
	   !SetupFindFirstLineW( inf, L"DestinationDirs", L"DefaultDestDir", &defaultDestination) ||
	   SetupGetFieldCount( &defaultDestination) != 1U ||
	   !propertyPageNumber( defaultDestination, 1U, 12U, false)) {
		return false ;
	}

	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> name{} ;	// 一節の完全な元名
	// 元節一覧を最後まで読み、追加の.securityや未知の別作用節を拒否する
	for( UINT index = 0U; index < MAXIMUM_INF_SECTIONS; ++index) {
		// 一覧の正常終了と元API失敗を区別する
		if( !SetupEnumInfSectionsW( inf, index, name.data(), static_cast<UINT>( name.size()),
								  nullptr)) {
			return GetLastError() == ERROR_NO_MORE_ITEMS ;
		}

		// 元選択または既知の媒体・表示節だけを許す
		if( !isAllowedValue( name.data(), metadata) &&
		   std::ranges::none_of(
			   sections, [&]( const auto &section) { return stringsEqual( name.data(), section) ; })) {
			return false ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原SYSを持つHDCで検査すべき全AMD64導入節と付随節を集める
 * @param[in] inf 同期借用する読取専用INF
 * @param[out] groups 全候補の基本節、実在するHW節とServices節。失敗時は空
 * @return 元Modelsの全候補が検査対象の節形式ならtrue
 * @note 各節の内容、コピー元とCAT、共有作用は後段で照合する
 */
//------------------------------------------------------------------------------
bool collectHdcInstallGroups( HINF inf, std::vector<std::vector<std::wstring>> &groups)
{
	groups.clear() ;
	std::size_t				  rows{} ;		// ManufacturerとModelsが共有する読取予算
	std::vector<std::wstring> installs ;	// Windowsが選択できる基本節の全候補
	// 空の候補や調べられなかったAMD64 Modelsから検査を始めない
	if( !collectAmd64InstallSections( inf, false, rows, installs, true) || installs.empty()) {
		return false ;
	}

	constexpr std::wstring_view decoration = L".ntamd64" ;	// 今回検査する明示AMD64節の修飾
	std::vector<std::vector<std::wstring>> selected ;		// 全候補が成立してから返す検査要求
	// すべての選択が後段の同じコピーと作用検査を通るように節を組み立てる
	for( const auto &install : installs) {
		// 元AMD64 Modelsが選んだ基本節に明示AMD64修飾があるか調べる
		const bool decorated =
			install.size() > decoration.size() &&
			stringsEqual( std::wstring_view{install}.substr( install.size() - decoration.size()),
						 decoration) ;
		auto	   hardware		 = install + L".HW" ;							// 元選択に結び付くデバイス設定と共有作用
		auto	   services		 = install + L".Services" ;						// 元選択に結び付くカーネルサービス
		const auto hardwareRows	 = SetupGetLineCountW( inf, hardware.c_str()) ;	// 付随節の正式な存在
		const auto hardwareError = GetLastError() ;								// HW節不在と読取り障害の区別
		// 一つの元サービス宣言は両構成で必須
		if( SetupGetLineCountW( inf, services.c_str()) != 1L) {
			return false ;
		}

		// 明示AMD64の三節は既存の全作用検査へ渡す
		if( decorated && hardwareRows > 0L) {
			selected.push_back( {install, std::move( hardware), std::move( services)}) ;
			continue ;
		}

		// 修飾を含む別形式、HW節の異常、基本節の追加行は二節の構成へ流さない
		if( install.find( L'.') != install.npos || hardwareRows >= 0L ||
		   hardwareError != ERROR_SECTION_NOT_FOUND ||
		   SetupGetLineCountW( inf, install.c_str()) != 1L) {
			return false ;
		}

		selected.push_back( {install, std::move( services)}) ;
	}

	groups = std::move( selected) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief AMD64 Modelsの全候補から必要ファイルの保護領域内パスを確定する
 * @param[in] inf 読み取り専用の元INF
 * @param[in] parent 保護領域内のINF親ディレクトリ
 * @param[in] declarativeClass 表示情報だけのクラス登録を確認済みの場合true
 * @param[out] sources 全候補が必要とするファイル。失敗時は部分出力を使わない
 * @return 未確定の節や作用を残さず全候補を確認できた場合true
 * @note 許容される作用形の内容検査だけに使う。署名・導入資格は別途確認する
 */
//------------------------------------------------------------------------------
bool collectProvenAmd64Sources( HINF inf, std::wstring_view parent, bool declarativeClass,
							   std::vector<std::wstring> &sources)
{
	std::size_t				  rows{} ;		// 全宣言と導入節の共有予算
	std::vector<std::wstring> installs ;	// x64が選び得る全DDInstall
	// 全節を走査できなかった場合は元の全媒体検査を使う
	if( !collectAmd64InstallSections( inf, declarativeClass, rows, installs)) {
		return false ;
	}

	// 各候補を独立に確認し、サービスが別候補のコピーを借りないようにする
	for( const auto &install : installs) {
		std::vector<WindowsDriverCopy> copies ;	// この候補の元ファイルと宛先
		// 未解決の作用が一つでもあれば欠落の例外を無効にする
		if( !collectAmd64InstallCopies( inf, parent, install, rows, copies) ||
		   !checkAmd64InstallServices( inf, install, copies, rows)) {
			return false ;
		}

		// 必要ファイルを元位置のまま全候補の和集合へ加える
		for( auto &copy : copies) {
			static_cast<void>( appendUnique( sources, std::move( copy.source))) ;
		}
	}

	return !sources.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ原INFの全言語・全参照を旧共同インストーラーの限定形式に照合します
 * @param[in] inf 固定済み元ファイルを開いた読取専用HINFです
 * @param[in] bytes HINFと同じ原バイトです。呼出し側が検査完了まで固定します
 * @param[in,out] inactive 元CABでは成功時の節と媒体を保持し、同梱依存では同じ比較対象を借用します
 * @param[in] storeInf 空は元CABです。Windows依存では署名と同じ対応StoreのINF絶対パスです
 * @return 全節・全行・全値が成立し、呼出し元の登録とコピーへの逆参照がなければtrueです
 */
//------------------------------------------------------------------------------
bool MaintenanceInfByteProof::inactiveCoInstaller( HINF inf, std::span<const std::byte> bytes,
												  InactiveCoInstaller &inactive,
												  std::wstring_view	   storeInf)
{
	const bool dependency = !storeInf.empty() ;	// 同じ証明で範囲を限定したWindows側の確認です
	// 実際に固定した一つの原バイトだけを有限に解析します
	if( bytes.empty() || bytes.size() > MAXIMUM_INACTIVE_CO_INSTALLER_BYTES) {
		return false ;
	}

	bytes_.resize( bytes.size()) ;
	std::ranges::copy( bytes, std::as_writable_bytes( std::span{bytes_}).begin()) ;
	// 同名別envelopeや未解釈の文字列構文を既存のSetupAPI結果から推定しません
	if( !scan( false, true) || duplicateSections_) {
		return false ;
	}

	const auto sectionName = [this]( const MaintenanceRawRow &row) {
		return text( sections_[row.section].name) ;
	} ; // 一行の同原節名だけを短時間借用します
	const auto value = [this]( const MaintenanceRawRow &row, std::size_t field) {
		return text( field == 0U ? row.key : fields_[row.firstField + field - 1U]) ;
	} ; // SetupAPIで照合する前の同物理フィールドです
	const auto findSection = [this]( std::wstring_view name) {
		return std::ranges::find_if(
			sections_, [&]( const auto &section) { return stringsEqual( text( section.name), name) ; }) ;
	} ; // 大小文字の別名を新しい節として扱いません
	const auto fold = []( std::wstring name) {
		std::ranges::transform( name, name.begin(), []( const wchar_t character) {
			return character >= L'A' && character <= L'Z'
					   ? static_cast<wchar_t>( character - L'A' + L'a')
					   : character ;
		}) ;
		return name ;
	} ; // 比較対象の節名・媒体名はASCIIの限定語彙です
	std::vector<std::wstring> models ;			// 表示keyに限って言語展開を許す元Modelsです
	std::vector<std::wstring> bases ;			// 全AMD64 Modelsの元導入先です
	std::size_t				  declarations{} ;	// 各版のModelsも含めた共同行数です
	// 元英語・現地語の表示名で別の導入先を選ばないよう全元Modelsを先に取得します
	if( dependency ? !collectDeclaredModelSections( inf, true, models, declarations)
				  : !collectDeclaredModelBases( inf, true, models, bases, declarations)) {
		return false ;
	}

	// 公式対象外の行も含め、AMD64が選ぶ基本節の元実在を確認します
	for( const auto &base : bases) {
		std::wstring selected ;	// 現行Windowsが元Modelsから選んだ節です
		// 選択不能な別行を現在選択中の公式行で補完しません
		if( resolveActualInstallInventorySection( inf, base, selected) != 0 ||
		   findSection( selected) == sections_.end()) {
			return false ;
		}
	}

	// 依存文書には元CABで認定した同じ禁止対象を使います
	if( !dependency) {
		constexpr std::wstring_view REG_SUFFIX	= L".AddReg" ;		// 予約節にならない明示登録節です
		constexpr std::wstring_view COPY_SUFFIX = L".CopyFiles" ;	// 同じ基本名の旧コピー節です
		// 全行から一つだけの正確なHKR登録を求め、別用途の登録を合わせません
		for( const auto &row : rows_) {
			// 元値名が違う行はこの候補の証明へ使いません
			if( row.fields < 3U || !stringsEqual( value( row, 3U), L"CoInstallers32")) {
				continue ;
			}

			const auto name = sectionName( row) ;	// 登録の所有を検査する元節名です
			const auto registrationValue =
				// DLLとexportです
				row.fields == 5U ? value( row, 5U) : std::wstring{} ;
			const auto comma = registrationValue.find( L',') ;	// 先頭DLLと完全exportの境界です
			// 登録が複数、追加フィールド、別root、他の登録節用途を含む場合は拒否します
			if( !inactive.registry.empty() || row.key.size != 0U || row.fields != 5U ||
			   sections_[row.section].count != 1U || !stringsEqual( value( row, 1U), L"HKR") ||
			   !value( row, 2U).empty() || value( row, 4U) != L"0x10000" ||
			   name.size() <= REG_SUFFIX.size() ||
			   !stringsEqual( std::wstring_view{name}.substr( name.size() - REG_SUFFIX.size()),
							 REG_SUFFIX) ||
			   !identifier( std::wstring_view{name}.substr( 0U, name.size() - REG_SUFFIX.size())) ||
			   comma == registrationValue.npos ||
			   !identifier( std::wstring_view{registrationValue}.substr( comma + 1U))) {
				return false ;
			}

			inactive.registry = name ;
			inactive.copy =
				name.substr( 0U, name.size() - REG_SUFFIX.size()) + std::wstring{COPY_SUFFIX} ;
			inactive.files[0] = fold( registrationValue.substr( 0U, comma)) ;
			// 登録先を単一DLLの名前とexportに限定します
			if( !inactiveIdentifier( inactive.files[0]) || !inactive.files[0].ends_with( L".dll") ||
			   !identifier( std::wstring_view{inactive.files[0]}.substr(
				   0U, inactive.files[0].size() - 4U))) {
				return false ;
			}

			inactive.files[1] =
				inactive.files[0].substr( 0U, inactive.files[0].size() - 4U) + L".dat" ;
		}

		// 単一の元登録と二つの元コピーを持たない形から例外を発行しません
		if( inactive.registry.empty() || findSection( inactive.copy) == sections_.end() ||
		   findSection( inactive.copy)->count != inactive.files.size()) {
			return false ;
		}
	}

	const std::array blocked{fold( inactive.registry), fold( inactive.copy), fold( inactive.files[0]),
							 // 同節と同媒体への逆参照を調べます
							 fold( inactive.files[1])} ;
	const auto		 references = [&blocked, &fold]( const std::wstring &field) {
		  const auto lowered = fold( field) ;	// パス・値・節の大小文字を同じ比較に使います
		  return lowered.find( L'~') != lowered.npos ||
				 lowered.find( L"coinstallers32") != lowered.npos ||
				 std::ranges::any_of(
					 blocked, [&]( const auto &name) { return lowered.find( name) != lowered.npos ; }) ;
	} ; // 省略別名など未解決の媒体参照も証明から外します
	std::map<std::wstring, std::set<std::wstring>>
						   definitions ;							// 全言語の元文字列を短時間だけ保持します
	std::set<std::wstring> defaultDefinitions ;						// 全OSで参照できる既定文字列を要求します
	std::set<std::pair<std::size_t, std::wstring>> definitionKeys ;	// 言語内重複を検出します
	// 既定・装飾を含めた全元文字列の構文と予約名への衝突を先に確認します
	for( const auto &row : rows_) {
		const auto section = sectionName( row) ;	// 同元Stringsの装飾を判別します
		// 文字列定義に属さない行を文字列展開へ混入させません
		if( !isStrings( section)) {
			continue ;
		}

		const auto name	   = fold( value( row, 0U)) ;	// 同言語内の大文字小文字非依存名です
		const auto content = value( row, 1U) ;			// 他の言語で選ばれる元表示値も省略しません
		// 重複、別tokenへ再展開できる値、節・ファイル等との衝突を許しません
		if( !definitionKeys.emplace( row.section, name).second || references( name) ||
		   references( content) || (content.find( L'%') != content.find_last_of( L'%')) ||
		   (!content.empty() && content.find_first_not_of( L" \t") != content.npos &&
			content[content.find_first_not_of( L" \t")] == L'@') ||
		   name == L"12" || name == L"13" || name == L"systemroot") {
			return false ;
		}

		definitions[name].insert( content) ;
		// 現在言語でだけ定義される識別子に構造の証明を依存させません
		if( stringsEqual( section, L"Strings")) {
			defaultDefinitions.insert( name) ;
		}
	}

	std::set<std::wstring>		  copyRows ;		// 同元コピー行の名前を一意に確認します
	std::set<std::wstring>		  mediaRows ;		// 同元媒体表の名前を一意に確認します
	bool						  destination{} ;	// 元コピー先の一件を確認する場合trueです
	std::vector<std::wstring>	  includeSections ;	// 同梱INFの正規参照がある元節です
	std::vector<std::wstring>	  needsSections ;	// 同梱INFの節を要求する同原節です
	std::array<wchar_t, MAX_PATH> system{} ;		// 固定DIRID12とWindows標準パスの比較起点です
	// 同梱DLLの照合に使うシステムディレクトリ名の実長。単位は文字
	const auto systemSize = GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
	// SetupAPIが展開する固定位置が計算できなければ未知tokenを許可しません
	if( systemSize == 0U || systemSize >= system.size()) {
		return false ;
	}

	std::set<std::wstring> nativeSections ;	// 現行SetupAPIの完全節名集合です
	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U>
				nativeName{} ;		// 同HINFから読む元名です
	std::size_t resourceRows{} ;	// 保護された同梱INFのMUI文字列だけの追加読取予算です
	// SetupAPIはStringsを前へ移動するため、順序ではなく一意な節の全体を照合します
	for( UINT index = 0U; index <= MAXIMUM_INF_SECTIONS; ++index) {
		// 正常終端以外のAPI失敗で部分集合を確定しません
		if( !SetupEnumInfSectionsW( inf, index, nativeName.data(),
								  static_cast<UINT>( nativeName.size()), nullptr)) {
			// 終端以外は実読取失敗です
			if( GetLastError() != ERROR_NO_MORE_ITEMS) {
				return false ;
			}

			break ;
		}

		const auto name = fold( nativeName.data()) ;	// Windowsが返した完全節名です
		// 二重列挙や未確認の節を元バイトに補いません
		if( index == MAXIMUM_INF_SECTIONS || !nativeSections.insert( name).second) {
			return false ;
		}

		// Windowsが別順序で返す同じ原節は元バイトと後で照合します
		if( findSection( name) != sections_.end()) {
			continue ;
		}

		const auto count =
			// OSが補う現在言語の文字列だけです
			SetupGetLineCountW( inf, name.c_str()) ;
		// 元配布では原バイトに存在しない節を拒否します。同梱INFに限りMUI表示文を読みます
		if( !dependency || !isStrings( name) || !validStringsName( name) || count <= 0L ||
		   static_cast<std::size_t>( count) > MAXIMUM_INSTALL_INVENTORY_LINES - resourceRows) {
			return false ;
		}

		resourceRows += static_cast<std::size_t>( count) ;
		std::set<std::wstring> keys ;	// 同じ言語の重複定義を拒否します
		// 同梱の追加節は元の表示tokenだけを供給でき、全行を確認します
		for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
			INFCONTEXT	 line{} ;	// 一つのMUI表示行です
			std::wstring key ;		// 元同梱INFが定義した表示識別子です
			std::wstring content ;	// 現在言語の表示値です
			// MUIを新しい参照や間接資源指定の根拠にしません
			if( !SetupGetLineByIndexW( inf, name.c_str(), static_cast<DWORD>( ordinal), &line) ||
			   SetupGetFieldCount( &line) != 1U || readMaintenanceField( line, 0U, key) != 0 ||
			   readMaintenanceField( line, 1U, content) != 0 || !inactiveIdentifier( key) ||
			   references( content) || content.find_first_of( L"%@") != content.npos ||
			   !keys.insert( fold( key)).second || !defaultDefinitions.contains( fold( key))) {
				return false ;
			}

			definitions[fold( key)].insert( std::move( content)) ;
		}
	}

	constexpr std::
		wstring_view
				ACTION_KEYS[]{L"AddReg",		  L"DelReg",	   L"CopyFiles",
							  L"Include",		  L"Needs",		   L"AddService",
							  L"Characteristics", L"BusType",	   L"FeatureScore",
							  L"*IfType",		  L"*MediaType",   L"*PhysicalMediaType",
							  L"DisplayName",	  L"Description",  L"ServiceType",
							  L"StartType",		  L"ErrorControl", L"ServiceBinary",
							  L"LoadOrderGroup"} ;	// 原Netと保護された依存文書で役割を判断できる指示だけです
	std::size_t rowIndex{} ;						// 元全節と同順に読み終えた行数です
	// 全節名・行数を元バイトとSetupAPIの完全列挙へ照合します
	for( std::size_t sectionIndex = 0U; sectionIndex < sections_.size(); ++sectionIndex) {
		const auto section = text( sections_[sectionIndex].name) ;	// 同じ元envelopeの完全名です
		// 別の節や暗黙の導入入口を実現する節は例外に含めません
		if( !nativeSections.contains( fold( section)) || !inactiveIdentifier( section) ||
		   SetupGetLineCountW( inf, section.c_str()) !=
			   static_cast<LONG>( sections_[sectionIndex].count) ||
		   matchesInfSectionFamily( section, L"ClassInstall") ||
		   matchesInfSectionFamily( section, L"ClassInstall32") ||
		   matchesInfSectionFamily( section, L"DefaultInstall") ||
		   matchesInfSectionFamily( section, L"InterfaceInstall32") ||
		   fold( section).ends_with( L".coinstallers") ||
		   (references( section) && (dependency || (!stringsEqual( section, inactive.registry) &&
												   !stringsEqual( section, inactive.copy))))) {
			return false ;
		}

		const bool model = stringsEqual( section, L"Manufacturer") ||
						   std::ranges::any_of( models, [&]( const auto &modelName) {
							   return stringsEqual( modelName, section) ;
						   }) ;					  // 表示keyを扱う元Modelsだけです
		const bool string	= isStrings( section) ;	// 参照のない定義表を区別します
		const bool metadata = stringsEqual( section, L"Version") ||
							  stringsEqual( section, L"ControlFlags") ||
							  stringsEqual( section, L"DestinationDirs") ||
							  matchesInfSectionFamily( section, L"SourceDisksFiles") ||
							  // 元宣言の専用フィールドです
							  matchesInfSectionFamily( section, L"SourceDisksNames") ;
		// 同じINFで休止中の構成に限って許可する登録節かを示します
		const bool registration = !dependency && stringsEqual( section, inactive.registry) ;
		// 同じINFの休止中構成が所有するコピー節かを示します
		const bool copying = !dependency && stringsEqual( section, inactive.copy) ;
		// 同sidecarの別行が追加されても省かず、全ordinalとfieldを取得します
		for( DWORD ordinal = 0U; ordinal < sections_[sectionIndex].count; ++ordinal, ++rowIndex) {
			const auto &row = rows_[rowIndex] ;	// 同じ物理行から確定した元値の範囲です
			INFCONTEXT	line{} ;				// 該当するSetupAPI行だけを借用します
			const auto	key = value( row, 0U) ;	// 展開前の元keyです
			// 役割不明の指示や実行・参照フィールドを無作用と認定しません
			if( !model && !string && !metadata && !key.empty() &&
			   !isAllowedValue( key, ACTION_KEYS)) {
				return false ;
			}

			// Windowsが読み取った行とfield数が一致する場合だけ元バイトを証明に使います
			if( !SetupGetLineByIndexW( inf, section.c_str(), ordinal, &line) ||
			   SetupGetFieldCount( &line) != row.fields) {
				return false ;
			}

			const auto media = fold( key) ;	// 先に確認した元媒体二件だけと比較します
			// 休止中構成に固有のコピーリストへ割り当てた配置先かを示します
			const bool ownDest = !dependency && stringsEqual( section, L"DestinationDirs") &&
								 stringsEqual( key, inactive.copy) ;
			// 休止中構成が所有する既知のファイルを元媒体欄に登録したかを示します
			const bool ownMedia = !dependency && stringsEqual( section, L"SourceDisksFiles") &&
								  std::ranges::find( inactive.files, media) != inactive.files.end() ;
			// 正確な同名コピーに限り、別ソース・改名・一時名を認めません
			if( copying &&
			   (row.key.size != 0U || row.fields != 4U ||
				std::ranges::find( inactive.files, fold( value( row, 1U))) == inactive.files.end() ||
				!copyRows.insert( fold( value( row, 1U))).second || !value( row, 2U).empty() ||
				!value( row, 3U).empty() || value( row, 4U) != L"0x04")) {
				return false ;
			}

			// 正式な同じSystem32コピー先と元媒体を一意に対応付けます
			if( (ownDest && (std::exchange( destination, true) || row.fields != 1U ||
							value( row, 1U) != L"11")) ||
			   (ownMedia &&
				(!mediaRows.insert( media).second || row.fields != 1U || value( row, 1U) != L"1"))) {
				return false ;
			}

			// 支持される同梱INFと三つの元節に限り、外部からの参照を独立検査へ渡します
			if( !model && !string &&
			   (stringsEqual( key, L"Include") || stringsEqual( key, L"Needs"))) {
				const bool include = stringsEqual( key, L"Include") ;	// 元INF名と元節名を区別します
				const auto target  = value( row, 1U) ;					// 元の外部参照値です
				// 元INFに紐付けて個別に照合するWi-Fiバスの処理節
				constexpr std::wstring_view NEEDS[]{L"VWiFiBus.CopyFiles", L"VWiFiBus.Services",
													L"VWiFiBus.PnPFilterRegistration.Hw"} ;
				// Windows側から新たなINFを取り込まず、元CABの名前の曖昧さも拒否します
				if( row.fields != 1U ||
				   (dependency && (include || findSection( target) == sections_.end())) ||
				   (!dependency && (include ? !stringsEqual( target, L"netvwifibus.inf")
											: (!isAllowedValue( target, NEEDS) ||
											   findSection( target) != sections_.end()))) ||
				   !appendUnique( include ? includeSections : needsSections, section)) {
					return false ;
				}
			}

			// 別の文書・作用が新しい文脈から元コピーと登録へ到達する経路を認めません
			if( !model && !string &&
			   (stringsEqual( key, L"CopyINF") || stringsEqual( key, L"LayoutFile"))) {
				return false ;
			}

			// Keyを持たない行も実field0の不存在を照合します
			for( DWORD field = 0U; field <= row.fields; ++field) {
				std::wstring current ;					// SetupAPIが現在言語で返した完全値です
				const auto	 raw = value( row, field) ;	// 同一フィールドの元バイトです
				// Windowsの大文字化で同名になり得る非ASCIIを参照位置へ通しません
				if( !string && !std::ranges::all_of(
								  raw, []( wchar_t character) { return character <= L'\x7f' ; })) {
					return false ;
				}

				MaintenanceFieldRead fieldRead{} ;	// 同じ原queryと実読取の完全長です
				// 元フィールドの読出結果。同じ行での累積読出量を更新します
				const auto			 error = readMaintenanceField( line, field, current, &fieldRead) ;
				// 空field0の値を別の節キーと解釈しません
				if( field == 0U && raw.empty() &&
				   error == nativeErrorFromWin32( ERROR_INVALID_PARAMETER) &&
				   fieldRead.required == 0U) {
					continue ;
				}

				const bool loneDependencyCopy =
					dependency && stringsEqual( section, L"CopyKMDriver") && field == 0U &&
					row.key.size == 0U && row.fields == 1U &&
					// Windowsが単独の無keyコピー名をfield0にも返します
					current == value( row, 1U) ;
				// 同じ休止中構成に固有の登録・コピー・媒体定義に限る例外
				const bool exempt =
					registration || copying || (field == 0U && (ownDest || ownMedia)) ;
				// 未読値や別の文脈による直接・別名参照を取りこぼしません
				if( error != 0 || !fieldRead.terminated ||
				   fieldRead.required != current.size() + 1U ||
				   fieldRead.readRequired != fieldRead.required ||
				   (!exempt && (references( raw) || references( current)))) {
					return false ;
				}

				// 定義表にある元値と通常のリテラルは、そのままの全値を比較します
				if( string || raw.find( L'%') == raw.npos) {
					// 定義のない行や外部展開を単なるリテラルに読み替えません
					if( raw != current && !loneDependencyCopy) {
						return false ;
					}

					continue ;
				}

				// サービスの実ファイルを指すと認める単独の値の位置
				const bool service = field == 1U && stringsEqual( key, L"ServiceBinary") ;
				// イベントメッセージ用の値として解析する既知のHKR行の形と値の位置
				const bool event = field == 5U && row.fields == 5U && row.key.size == 0U &&
								   stringsEqual( value( row, 1U), L"HKR") && value( row, 2U).empty() &&
								   stringsEqual( value( row, 3U), L"EventMessageFile") ;
				constexpr std::wstring_view EVENT_PATH =
					L"%%SystemRoot%%\\System32\\" ;	// Windows標準イベント位置です
				// 固定DIRIDに続く元ファイルは単独leafに限り、さらに別のtokenを展開しません
				const bool builtInService = service && raw.size() > 5U &&
											inactiveIdentifier( std::wstring_view{raw}.substr( 5U)) ;
				// 同じ元パスの完全一致だけを認めます
				if( (builtInService && raw.starts_with( L"%12%\\") &&
					stringsEqual( current,
								 std::wstring{system.data()} + L"\\drivers" + raw.substr( 4U))) ||
				   (dependency && builtInService && raw.starts_with( L"%13%\\") &&
					stringsEqual( current,
								 std::wstring{storeInf.substr( 0U, storeInf.find_last_of( L'\\'))} +
									 raw.substr( 4U))) ||
				   (event && raw.starts_with( EVENT_PATH) &&
					inactiveIdentifier( std::wstring_view{raw}.substr( EVENT_PATH.size())) &&
					current == L"%SystemRoot%" + raw.substr( 14U))) {
					continue ;
				}

				const auto logicalKey = fold( key) ;	// 宣言した表示箇所だけを照合します
				// 元の無線設定に許容する既知のパラメーター行の値かを示します
				const bool parameter =
					field == 5U && row.fields == 5U && row.key.size == 0U &&
					stringsEqual( value( row, 1U), L"HKR") && value( row, 4U) == L"0" &&
					((fold( value( row, 2U)).starts_with( L"ndi\\params\\") &&
					  (fold( value( row, 2U)).ends_with( L"\\enum") ||
					   stringsEqual( value( row, 3U), L"ParamDesc"))) ||
					 (value( row, 2U).empty() && stringsEqual( value( row, 3U), L"Locale"))) ;
				// 展開値をファイル・設定の作用から除外できる既知の表示位置
				const bool display =
					(field == 0U && model) ||
					(field == 1U &&
					 ((stringsEqual( section, L"Version") && logicalKey == L"provider") ||
					  stringsEqual( section, L"SourceDisksNames") || logicalKey == L"displayname" ||
					  (dependency && logicalKey == L"description"))) ||
					parameter ;
				const auto token	= raw.size() > 2U && raw.front() == L'%' && raw.back() == L'%'
										  ? fold( raw.substr( 1U, raw.size() - 2U))
										  : std::wstring{} ;		// 一つの表示token以外を展開しません
				const auto possible = definitions.find( token) ;	// 全言語の元定義です
				// 参照を作る位置へのtoken、別言語のみの定義、未知の展開を拒否します
				if( !display || !defaultDefinitions.contains( token) ||
				   possible == definitions.end() || !possible->second.contains( current)) {
					return false ;
				}
			}
		}
	}

	// 一部の行・節だけで無作用を確定しません
	if( rowIndex != rows_.size() ||
	   (dependency && (findSection( L"VWiFiBus.CopyFiles") == sections_.end() ||
					   findSection( L"VWiFiBus.Services") == sections_.end() ||
					   findSection( L"VWiFiBus.PnPFilterRegistration.Hw") == sections_.end()))) {
		return false ;
	}

	// 原CABの依存は同じ節の元Include/Needsの対に限定します
	return dependency ||
		   (copyRows.size() == inactive.files.size() && mediaRows.size() == inactive.files.size() &&
			destination && !includeSections.empty() && includeSections == needsSections) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全節と全言語から、不在媒体とx86専用媒体への逆参照を検査します
 * @param[in] inf 同じ元バイトを保持中に開いた読取専用HINFです
 * @param[in] bytes 固定中の元INFの全バイトです
 * @param[in] leaf 証明する元媒体名です。DLLは不在の候補、SYSはx86専用の候補です
 * @param[in,out] isolation 元CABの節の境界を成功時に返します。同梱側はその元境界を借用します
 * @param[in] inbox 保護された同梱INFを検査する場合trueです
 * @param[out] wifiDependency 元INFで同梱Wi-Fiバスを参照するかを成功時に返します
 * @return 全値の照合と逆参照の不存在を確認できた場合trueです
 */
//------------------------------------------------------------------------------
bool MaintenanceInfByteProof::proveScopedMediaIsolation( HINF inf, std::span<const std::byte> bytes,
														std::wstring_view	  leaf,
														ScopedMediaIsolation &isolation, bool inbox,
														bool &wifiDependency)
{
	const bool x86 = stringsEqual( lowerExtension( leaf), L".sys") ;	// 実在媒体のx86専用証明です
	// 公式Netの既存raw readerと同じ元構文、容量、重複境界を使います
	if( bytes.empty() || bytes.size() > MAXIMUM_INACTIVE_CO_INSTALLER_BYTES ||
	   !inactiveIdentifier( leaf) || (!x86 && !stringsEqual( lowerExtension( leaf), L".dll"))) {
		return false ;
	}

	bytes_.resize( bytes.size()) ;
	std::ranges::copy( bytes, std::as_writable_bytes( std::span{bytes_}).begin()) ;
	const bool allowQuotedStoreService = !inbox && !x86 ;	// 元CABの不在DLLの証明に限ります
	// 未解決の原バイトを整形や推定で補いません
	if( !scan( false, true, x86 && !inbox, allowQuotedStoreService) || duplicateSections_) {
		return false ;
	}

	const auto fold = []( std::wstring_view value) {
		std::wstring result( value) ;	// メディアと節の比較に使うASCII小文字です
		std::ranges::transform( result, result.begin(), []( wchar_t character) {
			return character >= L'A' && character <= L'Z'
					   ? static_cast<wchar_t>( character - L'A' + L'a')
					   : character ;
		}) ;
		return result ;
	} ; // UTF-16の元文字を保持し、構造名のASCII大小だけを揃えます
	const auto field = [this]( const MaintenanceRawRow &row, std::size_t index) {
		return text( index == 0U ? row.key : fields_[row.firstField + index - 1U]) ;
	} ; // 空のkeyと位置付きの元値を区別します
	const auto fileName		  = fold( leaf) ;	// 元媒体の完全名です
	auto	   compressedName = fileName ;		// 元セットアップが探す圧縮名です
	compressedName.back()	  = L'_' ;
	const auto extensibilityPath =
		L"%%systemroot%%\\system32\\" + fileName ;	// 未到達登録内の固定位置です
	std::size_t	 registrationRow = rows_.size() ;	// 例外にする元登録行は最大一件です
	std::wstring observedRegistration =
		inbox ? fold( isolation.registration) : std::wstring{} ;	// 検査する登録節です
	std::set<std::wstring>						   defaultStrings ;	// 元INFの既定文字列名です
	std::set<std::pair<std::size_t, std::wstring>> stringKeys ;		// 同言語の元定義の重複を検出します
	std::map<std::wstring, std::set<std::wstring>> strings ;		// 全言語の元文字列値です
	std::vector<std::wstring>					   models ;			// 表示名に展開を許す元Modelsの節です
	std::set<std::wstring>						   legacyModels ;	// 選択経路から外れた旧OSの表です
	std::size_t modelRows{} ;										// 元ManufacturerとModelsの読取上限です
	// OSが補う文書でも未知の表示名や装飾を推測しません
	if( !collectDeclaredModelSections( inf, false, models, modelRows)) {
		return false ;
	}

	// 登録の対象節と全言語の展開元を原値から先に固定します
	for( std::size_t ordinal = 0U; ordinal < rows_.size(); ++ordinal) {
		const auto &row		= rows_[ordinal] ;						// 展開前の同じ元行です
		const auto	section = text( sections_[row.section].name) ;	// 元行が属する節です
		// 残存するVista・Windows 7の表は元Manufacturerと同じ基名の場合だけ候補にします
		if( x86 && !inbox && stringsEqual( section, L"Manufacturer") && row.fields != 0U) {
			const auto base = field( row, 1U) ;	// 元行の展開されていないModels基名です
			constexpr std::wstring_view legacyDecorations[]{
				L".NTamd64.6.0", L".NTamd64.6.1", L".NTx86.6.0",
				L".NTx86.6.1"} ;	// 旧OSに限定する装飾です
			// 宣言済みの表は通常の表示名検査で扱い、未使用という根拠へ含めません
			for( const auto decoration : legacyDecorations) {
				const auto name = base + std::wstring( decoration) ;	// 元表の完全名です
				// 同じ基名と有限の旧OS装飾で実在する表だけを後段で照合します
				if( inactiveIdentifier( base) && SetupGetLineCountW( inf, name.c_str()) > 0L &&
				   std::ranges::none_of(
					   models, [&]( const auto &model) { return stringsEqual( name, model) ; })) {
					legacyModels.insert( fold( name)) ;
				}
			}
		}

		// 同じ節に二つの自然言語定義を混ぜず、再帰とビルトインの上書きを拒否します
		if( isStrings( section)) {
			const auto key	 = fold( field( row, 0U)) ;	// 同言語内の定義名です
			const auto value = field( row, 1U) ;		// どの言語でも別tokenを生成しない元値です
			// 別トークンやビルトインの再定義があるINFは媒体を省略できません
			if( value.find( L'%') != value.find_last_of( L'%') || key == L"12" || key == L"13" ||
			   key == L"systemroot" || !stringKeys.emplace( row.section, key).second) {
				return false ;
			}

			strings[key].insert( value) ;

			// 既定定義のないローカルtokenから参照を補完しません
			if( stringsEqual( section, L"Strings")) {
				defaultStrings.insert( key) ;
			}
		}

		// 同元のIHV登録だけを未到達の候補にします
		if( !inbox && !x86 && row.key.size == 0U && row.fields == 5U &&
		   stringsEqual( field( row, 1U), L"HKR") &&
		   stringsEqual( field( row, 2U), L"Ndi\\IHVExtensions") &&
		   stringsEqual( field( row, 3U), L"ExtensibilityDLL") && field( row, 4U) == L"0" &&
		   fold( field( row, 5U)) == extensibilityPath) {
			// 予約節や登録の併存は独立した未到達節と判定しません
			if( !observedRegistration.empty() || !inactiveIdentifier( section) ||
			   !fold( section).ends_with( L".reg")) {
				return false ;
			}

			observedRegistration = fold( section) ;
			registrationRow		 = ordinal ;
		}
	}

	std::wstring		   x86Copy ;					// 唯一のx86コピー節です
	std::wstring		   x86Service ;					// 唯一のx86サービス節です
	std::size_t			   copyRow	  = rows_.size() ;	// SYS名を認めるコピー行です
	std::size_t			   serviceRow = rows_.size() ;	// 同じSYSを認めるサービス行です
	std::set<std::wstring> x86Installers ;				// コピーとサービスを両方持つx86起点です
	std::set<std::wstring> restricted =
		inbox ? isolation.x86Sections : std::set<std::wstring>{} ;	// 同梱側も調べる節名です
	// 実在する候補はx86宣言、同名コピーとカーネルサービスがそろうものだけを検査します
	if( x86 && !inbox) {
		const auto driverPath = L"%12%\\" + fileName ;	// x86の標準ドライバー配置先です
		// ファイル名に対して型付きの元コピーとサービスだけを先に特定します
		for( std::size_t ordinal = 0U; ordinal < rows_.size(); ++ordinal) {
			const auto &row		= rows_[ordinal] ;								// 展開前の厳密な一行です
			const auto	section = fold( text( sections_[row.section].name)) ;	// x86装飾を持つ元節です
			// x86装飾を持つ節でだけ同名コピーと標準パスを観測します
			if( !section.ends_with( L".ntx86") || !inactiveIdentifier( section)) {
				continue ;
			}

			// 元コピーの改名、仮名や追加方式を許しません
			if( row.key.size == 0U && row.fields == 4U && fold( field( row, 1U)) == fileName &&
			   field( row, 2U).empty() && field( row, 3U).empty() && field( row, 4U) == L"6") {
				// 同名ファイルを複数のコピー節で許しません
				if( copyRow != rows_.size()) {
					return false ;
				}

				copyRow = ordinal ;
				x86Copy = section ;
			}

			// 同じSYSを標準ドライバー位置から実行するカーネルサービスです
			if( row.fields == 1U && stringsEqual( field( row, 0U), L"ServiceBinary") &&
			   fold( field( row, 1U)) == driverPath) {
				std::wstring type ;	// SetupAPIが返したサービスの元種別です
				// 複数の所有元、カーネル以外の種別または不明な指示は保留します
				if( serviceRow != rows_.size() ||
				   readInfDirective( inf, section.c_str(), L"ServiceType", 1U, type) != 0 ||
				   type != L"1") {
					return false ;
				}

				serviceRow = ordinal ;
				x86Service = section ;
			}
		}

		// 両用途の元節が必要で、同一節の別名への置換は行いません
		if( x86Copy.empty() || x86Service.empty() || x86Copy == x86Service) {
			return false ;
		}

		std::set<std::wstring> services ;	// 元サービスを使うx86起点です
		// 二つの役割を実際に呼び出すx86導入節を確定します
		for( const auto &row : rows_) {
			const auto section =
				// コピーまたはServicesの候補節です
				fold( text( sections_[row.section].name)) ;
			const auto key = fold( field( row, 0U)) ;	// 照合する指示名です
			// コピーは単一の同名ファイルへの限定指示です
			if( key == L"copyfiles" && section.ends_with( L".ntx86") && row.fields == 1U &&
			   fold( field( row, 1U)) == x86Copy) {
				x86Installers.insert( section) ;
			}

			constexpr std::wstring_view servicesSuffix = L".services" ;	// x86基礎節との接続です
			// サービスは同じx86起点の付随節からのみ扱います
			if( key == L"addservice" && section.ends_with( L".ntx86.services") &&
			   (row.fields == 3U || row.fields == 4U) && fold( field( row, 3U)) == x86Service) {
				services.insert( section.substr( 0U, section.size() - servicesSuffix.size())) ;
			}
		}

		// コピーとサービスを別の導入起点から組み合わせず、節の数も制限します
		if( x86Installers.empty() || x86Installers.size() > 16U || x86Installers != services) {
			return false ;
		}

		restricted = x86Installers ;
		restricted.insert( x86Copy) ;
		restricted.insert( x86Service) ;
	}

	// 後段の逆参照と同梱INFの検査でも旧OSの表が別用途で使われていないことを確認します
	restricted.insert( legacyModels.begin(), legacyModels.end()) ;
	const auto references = [&]( std::wstring_view value) {
		const auto current	= fold( value) ;	// 先頭や別パスに隠れた元ファイル名も検査します
		const bool nonAscii = std::ranges::any_of( value, []( wchar_t character) {
			return character > L'\x7f' ;
		}) ; // Windowsの大文字化でASCII別名と一致する可能性がある値です
		const auto contains = [&]( std::wstring_view name) {
			return current.find( name) != current.npos ||
				   (nonAscii &&
					!std::ranges::search( current, name, []( wchar_t left, wchar_t right) {
						 return CompareStringOrdinal( &left, 1, &right, 1, TRUE) == CSTR_EQUAL ;
					 }).empty()) ;
		} ; // 文字列中のファイル名と節名をWindowsの大小比較でも照合します
		return current.find( L'~') != current.npos || contains( fileName) ||
			   contains( compressedName) ||
			   (!observedRegistration.empty() && contains( observedRegistration)) ||
			   std::ranges::any_of( restricted, contains) ;
	} ; // 不在媒体、圧縮・短縮別名、元登録節への参照を全値で調べます
	std::set<std::wstring> nativeSections ;	// 同HINFの完全な節名集合です
	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U>
				sectionBuffer{} ;	// 一つの節名を受け取ります
	std::size_t extraStringRows{} ;	// Windowsの言語資源の全行数です
	// 原値にない節やWindowsの列挙不成立から、参照なしの結果を作りません
	for( UINT index = 0U; index <= MAXIMUM_INF_SECTIONS; ++index) {
		// 正常な終端までの全節でなければ構造が分かりません
		if( !SetupEnumInfSectionsW( inf, index, sectionBuffer.data(),
								  static_cast<UINT>( sectionBuffer.size()), nullptr)) {
			// 読取りエラーを正常な終端と区別します
			if( GetLastError() != ERROR_NO_MORE_ITEMS) {
				return false ;
			}

			break ;
		}

		// 上限超過と同名節の反復で残る構造を推定しません
		if( index == MAXIMUM_INF_SECTIONS ||
		   !nativeSections.insert( fold( sectionBuffer.data())).second) {
			return false ;
		}

		const std::wstring_view section{sectionBuffer.data()} ;	// Windowsが返した元節名です
		// 物理INFの元節は後で全値を比較し、追加言語資源と混ぜません
		if( std::ranges::any_of(
			   sections_, [&]( const auto &raw) { return stringsEqual( text( raw.name), section) ; })) {
			continue ;
		}

		const auto count = SetupGetLineCountW( inf, sectionBuffer.data()) ;	// 追加言語資源の行数です
		// 保護同梱INFが補う有界の表示資源以外から意味を追加しません
		if( !inbox || !validStringsName( section) || count <= 0L ||
		   static_cast<std::size_t>( count) > MAXIMUM_INSTALL_INVENTORY_LINES - extraStringRows) {
			return false ;
		}

		extraStringRows += static_cast<std::size_t>( count) ;
		std::set<std::wstring> addedKeys ;	// 同一の追加言語内での重複を拒否します
		// 既定値と同じキーの完全な表示値だけを検査して保持します
		for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
			INFCONTEXT	 line{} ;	// Windowsの追加言語の一行です
			std::wstring key ;		// 展開元の既定文字列名です
			std::wstring value ;	// 同名の表示値です
			// 元定義以外のキーやパスを作る言語資源は使いません
			if( !SetupGetLineByIndexW( inf, sectionBuffer.data(), static_cast<DWORD>( ordinal),
									 &line) ||
			   SetupGetFieldCount( &line) != 1U || readMaintenanceField( line, 0U, key) != 0 ||
			   readMaintenanceField( line, 1U, value) != 0 || !defaultStrings.contains( fold( key)) ||
			   !addedKeys.insert( fold( key)).second || references( value) ||
			   value.find_first_of( L"%@") != value.npos) {
				return false ;
			}

			strings[fold( key)].insert( std::move( value)) ;
		}
	}

	std::set<std::size_t> includes ;		// 既知Wi-Fiバスを指定する元節です
	std::set<std::size_t> needs ;			// 同じ元節で既知Wi-Fiバスを使う宣言です
	std::size_t			  mediaRows{} ;		// 不在として判定する同名元媒体の宣言数です
	bool				  commonMedia{} ;	// x86と重なる共通の媒体宣言を確認済みです
	bool				  x86Media{} ;		// 同一ディスクのx86宣言を確認済みです
	bool				  destination{} ;	// コピー節の元宛先を確認済みです
	// すべての節構造と原行をSetupAPIの実読取りへ対応させます
	for( const auto &section : sections_) {
		const auto name = fold( text( section.name)) ;	// 元envelopeの完全名です
		const bool x86Header =
			!inbox && x86 &&
			(restricted.contains( name) ||
			 std::ranges::any_of( x86Installers, [&]( const auto &install) {
				 return name == install + L".services" || name == install + L".hw" ;
			 })) ; // 元のx86起点と確認した付随節だけです
		// 観測した登録節の表題以外に参照を持つ節を拒否します
		if( !nativeSections.contains( name) ||
		   SetupGetLineCountW( inf, name.c_str()) != static_cast<LONG>( section.count) ||
		   (references( name) && (inbox || (name != observedRegistration && !x86Header)))) {
			return false ;
		}
	}

	// 全fieldの原値と現在言語の値を検査し、対象外のAMD64節も確認します
	for( std::size_t ordinal = 0U; ordinal < rows_.size(); ++ordinal) {
		const auto &row		= rows_[ordinal] ;								// 同じ元行のoffsetです
		const auto	section = fold( text( sections_[row.section].name)) ;	// 元行が属する節です
		const auto	key		= fold( field( row, 0U)) ;						// 原指示を別言語の値から推測しません
		const bool	legacy	= legacyModels.contains( section) ;				// 元対象外の旧OSの表です
		const bool	model	= legacy || std::ranges::any_of( models, [&]( const auto &name) {
								  return stringsEqual( name, section) ;
							  }) ; // 表示名が左辺にあるModelsです
		// 旧表の全行を表示名・基本導入節・PnP IDの形式へ限定します
		if( legacy &&
		   (key.size() < 3U || key.front() != L'%' || key.back() != L'%' || row.fields < 2U ||
			row.fields > MAXIMUM_INSTALL_INVENTORY_FIELDS || !inactiveIdentifier( field( row, 1U)))) {
			return false ;
		}

		const bool media = !inbox && !x86 && key == fileName &&
						   (section == L"sourcedisksfiles" ||
							// 裏付けを取る一行です
							section == L"sourcedisksfiles.amd64") ;
		// 同梱のx86専用媒体を装飾済みの元媒体欄に載せる場合
		const bool x86Disk = !inbox && x86 && key == fileName && section == L"sourcedisksfiles.x86" ;
		// 同梱のx86専用媒体が共用の元媒体欄にも宣言される場合
		const bool commonDisk = !inbox && x86 && key == fileName && section == L"sourcedisksfiles" ;
		// x86専用リストが元INF内で持つ配置先宣言かを示します
		const bool x86Destination =
			!inbox && x86 && section == L"destinationdirs" && key == x86Copy ;
		// x86導入節が同じx86専用リストだけをコピーする既知の命令かを示します
		const bool x86CopyCall = !inbox && x86 && x86Installers.contains( section) &&
								 key == L"copyfiles" && row.fields == 1U &&
								 fold( field( row, 1U)) == x86Copy ;
		// x86導入節のサービス欄が同じx86専用の元サービスだけを参照するかを示します
		const bool x86ServiceCall =
			!inbox && x86 && key == L"addservice" && section.ends_with( L".services") &&
			x86Installers.contains( section.substr( 0U, section.size() - 9U)) &&
			(row.fields == 3U || row.fields == 4U) && fold( field( row, 3U)) == x86Service ;
		INFCONTEXT line{} ;	// 同一ordinalのSetupAPI行です
		// 元行の差異や別文書を暗黙に取り込む宣言で証明を打ち切ります
		if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( row.ordinal), &line) ||
		   SetupGetFieldCount( &line) != row.fields || (media && ++mediaRows != 1U) ||
		   key == L"copyinf" || key == L"layoutfile" || key == L"addcomponent") {
			return false ;
		}

		// 同じディスクの単一行と標準ドライバー宛先が元の両宣言で成立する場合だけ使用します
		if( ((x86Disk || commonDisk) && (row.fields != 1U || field( row, 1U) != L"1" ||
										std::exchange( x86Disk ? x86Media : commonMedia, true))) ||
		   (x86Destination &&
			(row.fields != 1U || field( row, 1U) != L"12" || std::exchange( destination, true)))) {
			return false ;
		}

		// 外部辺は元バスの既知の組だけを許し、同梱側では固定文書の局所節を要求します
		if( key == L"include" || key == L"needs") {
			const auto					value = field( row, 1U) ;	// 元のリテラル値です
			// 元選択と同じ外部バスINFに限って照合するコピー・サービス・登録節
			constexpr std::wstring_view BUS_NEEDS[]{L"VWiFiBus.CopyFiles", L"VWiFiBus.Services",
													L"VWiFiBus.PnPFilterRegistration",
													L"VWiFiBus.PnPFilterRegistration.Hw"} ;
			const bool					include = key == L"include" ;	// 同じ節の対を区別します
			// 依存先の名や由来が曖昧な文書を起点にしません
			if( row.fields != 1U ||
			   (inbox ? include || SetupGetLineCountW( inf, value.c_str()) < 0L
					  : !(include ? stringsEqual( value, L"netvwifibus.inf")
								  : isAllowedValue( value, BUS_NEEDS) &&
										!nativeSections.contains( fold( value)))) ||
			   !(include ? includes : needs).insert( row.section).second) {
				return false ;
			}
		}

		// 候補登録内に別方式の指示を混ぜないことを確認します
		if( !inbox && section == observedRegistration &&
		   (row.key.size != 0U || row.fields != 5U || !stringsEqual( field( row, 1U), L"HKR") ||
			!stringsEqual( field( row, 2U), L"Ndi\\IHVExtensions"))) {
			return false ;
		}

		// キーなし行の先頭値はfield 1で全量照合します
		for( DWORD index = row.key.size == 0U ? 1U : 0U; index <= row.fields; ++index) {
			const auto	 raw = field( row, index) ;	// 展開前の完全フィールドです
			std::wstring value ;					// SetupAPIが実際に読んだ完全フィールドです
			// 対象名の出現を許可する、既知の元行とフィールド位置の組み合わせ
			const bool	 occurrence =
				((media || x86Disk || commonDisk || x86Destination) && index == 0U) ||
				(ordinal == registrationRow && index == 5U) ||
				((ordinal == copyRow || ordinal == serviceRow || x86CopyCall) && index == 1U) ||
				(x86ServiceCall && index == 3U) ;
			// 元と実読取りの双方で逆参照を認める位置を限定します
			if( readMaintenanceField( line, index, value) != 0 ||
			   (!occurrence && (references( raw) || references( value)))) {
				return false ;
			}

			const auto quotedLeaf =
				allowQuotedStoreService && index == 1U && key == L"servicebinary"
					? quotedStoreServiceLeaf( raw)
					: std::wstring_view{} ;	// 元の引用符を保持した単独EXE名です
			// 引用符付きの元宣言は、同じ節の一意な読取値とサービス種別に対応させます
			if( !quotedLeaf.empty()) {
				std::wstring expected{L"\".\\"} ;	// 配置未設定の読取HINFでのDIRID 13です
				expected.append( quotedLeaf).append( L"\"") ;
				std::wstring  uniqueValue ;		// 独立した唯一のサービス実行値です
				std::uint32_t serviceType{} ;	// 元INFで宣言されたサービス種別です
				// 読取りの不一致、重複、別種別は逆参照の証明に使いません
				if( row.fields != 1U || value != expected ||
				   readRequiredServiceField( inf, section, L"ServiceBinary", uniqueValue) != 0 ||
				   uniqueValue != value ||
				   readRequiredServiceScalar( inf, section, L"ServiceType", serviceType) != 0 ||
				   serviceType != SERVICE_WIN32_OWN_PROCESS) {
					return false ;
				}

				continue ;
			}

			// 旧表と導入節の装飾解決が重なる場合や、旧表にID以外の値を含む場合は保留します
			if( (model && index == 1U &&
				std::ranges::any_of(
					legacyModels,
					[&]( const auto &table) { return matchesInfSectionFamily( table, value) ; })) ||
			   (legacy && index >= 2U && !validNativeModelsId( value))) {
				return false ;
			}

			// 一つの完全tokenか固定Windows位置だけを認め、別名を合成できる展開を拒否します
			if( isStrings( section) || raw.find( L'%') == raw.npos) {
				// リテラルの実読取りが違う形式から逆参照なしを推定しません
				if( raw != value) {
					return false ;
				}

				continue ;
			}

			const auto token = raw.size() > 2U && raw.front() == L'%' && raw.back() == L'%'
								   ? fold( std::wstring_view{raw}.substr( 1U, raw.size() - 2U))
								   : std::wstring{} ;	// 展開する一つの名前です
			const auto path	 = fold( raw) ;				// 固定接頭辞を比較する元パスです
			constexpr std::wstring_view SYSTEM_PATH =
				L"%%systemroot%%\\system32\\" ;	// 元INFの固定イベント位置です
			const bool fixed =
				(index == 1U && key == L"servicebinary" &&
				 (path.starts_with( L"%12%\\") || path.starts_with( L"%13%\\")) &&
				 inactiveIdentifier( std::wstring_view{path}.substr( 5U))) ||
				(index == 5U && row.key.size == 0U && path.starts_with( SYSTEM_PATH) &&
				 inactiveIdentifier( std::wstring_view{path}.substr( SYSTEM_PATH.size())) &&
				 (occurrence ||
				  // 固定Windows位置です
				  stringsEqual( field( row, 3U), L"EventMessageFile"))) ;
			// 固定位置には後続トークンを認めません
			if( fixed) {
				continue ;
			}

			const auto possible = strings.find( token) ;	// 元定義の全言語に共通する値を確認します
			const bool modelName =
				// 元表示名だけです
				index == 0U && (section == L"manufacturer" || model) ;
			const bool headerName =
				index == 1U && (key == L"displayname" || key == L"description" ||
								(section == L"version" && key == L"provider") ||
								// 参照に使わない表示です
								section == L"sourcedisksnames") ;
			const bool parameterName = index == 5U && row.fields == 5U && row.key.size == 0U &&
									   stringsEqual( field( row, 1U), L"HKR") &&
									   field( row, 4U) == L"0" &&
									   (fold( field( row, 2U)).starts_with( L"ndi\\params\\") ||
										(field( row, 2U).empty() &&
										 // パラメーターの表示です
										 stringsEqual( field( row, 3U), L"Locale"))) ;
			const bool helpText =
				x86 && !inbox && index == 5U && row.fields == 5U && row.key.size == 0U &&
				stringsEqual( field( row, 1U), L"HKR") && stringsEqual( field( row, 2U), L"Ndi") &&
				stringsEqual( field( row, 3U), L"HelpText") &&
				(field( row, 4U).empty() || field( row, 4U) == L"0") ;	// 間接参照を含まない説明です
			// 指示名に文字列置換を許さず、作用値は全言語で同値を要求します
			if( !inactiveIdentifier( token) || !defaultStrings.contains( token) ||
			   possible == strings.end() || !possible->second.contains( value) ||
			   (index == 0U && !modelName) ||
			   (possible->second.size() != 1U &&
				!(modelName || headerName || parameterName || helpText)) ||
			   (helpText && std::ranges::any_of( possible->second, []( const auto &label) {
					return label.find_first_of( L"%@") != label.npos ;
				}))) {
				return false ;
			}
		}
	}

	// 外部辺の組と一件の不在宣言が完全な場合だけ結果を返します
	if( !inbox &&
	   (includes != needs || (x86 ? !(commonMedia && x86Media && destination) : mediaRows != 1U))) {
		return false ;
	}

	isolation.registration = std::move( observedRegistration) ;
	isolation.x86Sections  = std::move( restricted) ;
	wifiDependency		   = !includes.empty() ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows標準DLLとコピーするドライバーのイベント参照値を作る
 * @param[in] windowsResource クラスに対応する固定Windows標準DLL名
 * @param[in] driverName 同元コピーのドライバーフォルダー内ファイル名
 * @return 元INFの展開後と同じ形式の二つのファイル参照
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring driverEventFileValue( std::wstring_view windowsResource,
												std::wstring_view driverName)
{
	// Windowsの標準イベントDLLを結合する環境変数ベースの元表記
	std::wstring resources{L"%SystemRoot%\\System32\\"} ;
	resources.append( windowsResource)
		.append( L";%SystemRoot%\\System32\\drivers\\")
		.append( driverName) ;
	return resources ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じサービスのSystemイベント登録を元の二つの値に限定する
 * @param[in] inf 読取り専用の元INF
 * @param[in] eventSection 元AddServiceのイベント登録節
 * @param[in] resources 呼出し側が元の媒体構成へ結んだイベント用ファイル参照の全値
 * @param[out] registrySection 非null時に成功した登録先の元セクション名を返す
 * @return 型と全参照先の確認が済んだ場合true
 * @note Windows保護資源とSYSの署名検査は呼び出し元の閉包検査で行う
 */
//------------------------------------------------------------------------------
bool checkSystemDriverEventLog( HINF inf, const std::wstring &eventSection,
							   std::wstring_view resources, std::wstring *registrySection = nullptr)
{
	std::wstring registry ;	// 元サービスの唯一のイベント登録先
	// 一件のAddRegを別ログや追加の登録指示で置換しない
	if( !validInstallInventorySectionName( eventSection) ||
	   SetupGetLineCountW( inf, eventSection.c_str()) != 1L ||
	   readRequiredServiceField( inf, eventSection, L"AddReg", registry) != 0 ||
	   !validInstallInventorySectionName( registry) ||
	   SetupGetLineCountW( inf, registry.c_str()) != 2L ||
	   SetupGetLineCountW( inf, (registry + L".Security").c_str()) >= 0L) {
		return false ;
	}

	bool messageSeen{} ;	// 元EventMessageFileの一意性を確認する
	bool typesSeen{} ;		// 元TypesSupportedの一意性を確認する
	// イベント資源と種別の二行を順番に確認する
	for( DWORD index = 0U; index < 2U; ++index) {
		INFCONTEXT	 row{} ;					// 同サービスのイベント登録行
		std::wstring root, key, value, data ;	// 元登録の位置、値名、データ
		int			 flags{} ;					// SetupAPIが解析した元レジストリ型
		// 現イベントソースの名前付き値以外への作用を拒否する
		if( !SetupGetLineByIndexW( inf, registry.c_str(), index, &row) ||
		   SetupGetFieldCount( &row) != 5U || readInfField( row, 1U, root) != 0 ||
		   !stringsEqual( root, L"HKR") || readInstallInventoryField( row, 2U, key) != 0 ||
		   !key.empty() || readInfField( row, 3U, value) != 0 ||
		   !SetupGetIntField( &row, 4U, &flags) || readInfField( row, 5U, data) != 0) {
			return false ;
		}

		// イベント資源はWindows資源と同CATのドライバーだけとする
		if( !messageSeen && stringsEqual( value, L"EventMessageFile") && flags == 0x20000 &&
		   stringsEqual( data, resources)) {
			messageSeen = true ;
		}
		// イベント種別は元の一つのDWORD値を確認する
		else if( !typesSeen && stringsEqual( value, L"TypesSupported") && flags == 0x10001 &&
				data == L"7") {
			typesSeen = true ;
		} else {
			return false ;
		}
	}

	// 両方のイベント値を検証済みで呼出し側が求めたときだけ登録節名を渡します
	if( messageSeen && typesSeen && registrySection) {
		*registrySection = std::move( registry) ;
	}

	return messageSeen && typesSeen ;
}

//------------------------------------------------------------------------------
/**
 * @brief メディアチェンジャーのAMD64選択を一つのコピーと起動サービスに結ぶ
 * @param[in] inf 読取り専用の元INF
 * @param[in] parent 保護領域内のINF親ディレクトリ
 * @param[in] package 同じINFから読んだ元CAT、媒体位置、必要構成
 * @return 元コピー、サービス、イベント作用をすべて確認した場合true
 * @note 収集と端末選択で元の構造を確認する。元サービスを登録・起動しない
 */
//------------------------------------------------------------------------------
bool checkMediumChanger( HINF inf, std::wstring_view parent, const OfficialInfPackage &package)
{
	std::size_t					   rows{} ;		// 元Modelsと選択節の共有読取り上限
	std::vector<std::wstring>	   installs ;	// 元AMD64の導入候補
	std::vector<WindowsDriverCopy> copies ;		// 同AMD64選択の媒体と全宛先
	std::wstring				   excluded ;	// 元INFが宣言した選択除外の値
	// 元の一意なAMD64選択、元CATの一SYS、元の選択除外を同時に要求する
	if( package.hasExternalDependencies || package.hasUnassessedProgramReferences ||
	   !package.requiredInfPaths.empty() || !package.requiredComponents.empty() ||
	   package.sourceFiles.size() != 1U || SetupGetLineCountW( inf, L"ControlFlags") != 1L ||
	   readRequiredServiceField( inf, L"ControlFlags", L"ExcludeFromSelect", excluded) != 0 ||
	   excluded != L"*" || !collectAmd64InstallSections( inf, false, rows, installs) ||
	   installs.size() != 1U ||
	   !collectAmd64InstallCopies( inf, parent, installs.front(), rows, copies) ||
	   copies.size() != 1U || copies.front().dirid != 12 ||
	   !stringsEqual( copies.front().source, package.sourceFiles.front())) {
		return false ;
	}

	const auto &copy = copies.front() ;	// 同一CATに属する唯一のSYSコピー
	// 同じSYSのイベント資源に使うコピー先の名前
	const auto	driverName = copy.target.substr( copy.target.find_last_of( L"\\") + 1U) ;
	std::array<wchar_t, MAX_PATH> system{} ;	// 同じWindowsのシステムフォルダー
	// 現在のシステム位置として読み取れた文字数
	const auto length = GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
	// イベント参照先とコピー先が同じSystem32の直下のdriversにあることを確認する
	if( length == 0U || length >= system.size() ||
	   !stringsEqual( copy.target,
					 std::wstring( system.data(), length) + L"\\drivers\\" + driverName)) {
		return false ;
	}

	const auto	 services = installs.front() + L".Services" ;	// 検証したDDInstallに属するサービス節
	INFCONTEXT	 add{} ;										// 唯一の元関連サービス宣言
	int			 flags{} ;										// 元の関連サービスフラグ
	std::wstring name, service, event ;							// 元サービス名と所有する二節
	// 追加サービス、別ログ指定、未知のサービスフラグを拒否する
	if( SetupGetLineCountW( inf, services.c_str()) != 1L ||
	   !SetupFindFirstLineW( inf, services.c_str(), L"AddService", &add) ||
	   SetupGetFieldCount( &add) != 4U || !SetupGetIntField( &add, 2U, &flags) || flags != 2 ||
	   readInfField( add, 1U, name) != 0 || name.empty() || name.size() > 256U ||
	   name.find( L'\\') != name.npos || !validRequiredServiceSubdirectory( name) ||
	   readInfField( add, 3U, service) != 0 || !validInstallInventorySectionName( service) ||
	   readInfField( add, 4U, event) != 0 || SetupGetLineCountW( inf, service.c_str()) != 6L) {
		return false ;
	}

	std::uint32_t type{}, start{}, control{} ;	// 元のサービス種別、開始種別、失敗時制御
	std::wstring  binary, group, dependency ;	// 元のバイナリ、起動順、グループ依存
	return readRequiredServiceScalar( inf, service, L"ServiceType", type) == 0 && type == 1U &&
		   readRequiredServiceScalar( inf, service, L"StartType", start) == 0 && start == 1U &&
		   readRequiredServiceScalar( inf, service, L"ErrorControl", control) == 0 &&
		   control == 1U && readRequiredServiceField( inf, service, L"ServiceBinary", binary) == 0 &&
		   boundWindowsServiceBinary( binary, copies, true) &&
		   readRequiredServiceField( inf, service, L"LoadOrderGroup", group) == 0 &&
		   stringsEqual( group, L"SCSI Class") &&
		   readRequiredServiceField( inf, service, L"Dependencies", dependency) == 0 &&
		   stringsEqual( dependency, L"+SCSI Miniport") &&
		   checkSystemDriverEventLog( inf, event, driverEventFileValue( L"IoLogMsg.dll", driverName)) ;
}

/** @brief 元コピー節で許容する行数、明示先、コピー方式です */
struct ScopedNetworkCopyListRule {
	/// 一節で照合する最大行数です
	LONG		  maximumRows ;
	/// 0は従来の宛先解決、その他は一つの明示DIRIDと同名コピーを要求します
	std::uint32_t sameNameDirid ;
	/// 元行のコピー欄が持つ値です
	int			  flags ;
	/// 省略を許さない場合trueです
	bool		  requireFlags ;
	/// 元行数、キーなし、明示ソースなしを要求する場合trueです
	bool		  exactShape{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 公式Netの一つの名前付きコピー節の全行を元媒体と宛先へ結ぶ
 * @param[in] inf 元署名とハッシュを確認した同じ読取専用INF
 * @param[in] workspace 元ファイルの保護領域
 * @param[in] entries 実ハッシュ付きの元抽出一覧
 * @param[in] package 検査済みの元INFと媒体集合
 * @param[in] list 同じ実起点の元CopyFiles参照
 * @param[in] rule 行数、同名の明示宛先、元フラグを照合する条件です
 * @param[in,out] copies 元コピーとWindowsの宛先。失敗時の部分結果は使用しない
 * @param[in,out] uses 検証済みのコピー用途。失敗時の部分結果は使用しない
 * @return 元媒体と宛先の照合成功は0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError bindScopedNetworkCopyList( HINF inf, const OfficialDownloadWorkspace &workspace,
									  std::span<const OfficialZipEntry>	  entries,
									  const OfficialInfPackage			 &package,
									  const OfficialInfInstallReference	 &list,
									  const ScopedNetworkCopyListRule	 &rule,
									  std::vector<WindowsDriverCopy>	 &copies,
									  std::vector<MaintenanceInfFileUse> &uses)
{
	const auto	  count		  = SetupGetLineCountW( inf, list.target.c_str()) ;	// 名前付き節の元行数
	const auto	  unsupported = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;	// 未検査の構成
	std::uint32_t dirid{} ;														// 同名コピーを許す明示の元宛先です
	// 元節の全行を確認し、別の権限や直接コピーの暗黙指定を借りない
	if( list.kind != OfficialInfInstallReferenceKind::LOCAL_SECTION || !list.targetPresent ||
	   count <= 0L || count > rule.maximumRows || (rule.exactShape && count != rule.maximumRows) ||
	   (rule.sameNameDirid != 0U &&
		(readRequiredServiceScalar( inf, L"DestinationDirs", list.target.c_str(), dirid) != 0 ||
		 dirid != rule.sameNameDirid)) ||
	   SetupGetLineCountW( inf, (list.target + L".Security").c_str()) >= 0L) {
		return unsupported ;
	}

	uses.push_back( {list.section, L"CopyFiles", list.target}) ;
	// コンテナー内の元媒体と完全宛先をコピー行ごとに確認する
	for( LONG index = 0L; index < count; ++index) {
		INFCONTEXT row{} ;	// 同じ元節の一行
		// 元行が読めない場合は中断し、先行行で検査を完了しない
		if( !SetupGetLineByIndexW( inf, list.target.c_str(), static_cast<DWORD>( index), &row)) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		const auto	 fields = SetupGetFieldCount( &row) ;	// 省略を含めた元フィールド数
		std::wstring name, mediaName, temporary ;			// 宛先と元媒体名、原一時名欄
		std::wstring key ;									// 元のコピー行に名前付きのキーがある場合はその値です
		int			 flags{} ;								// SetupAPIが解析した元コピーのフラグ
		// 各コピー方式の元フィールド、明示フラグと同名条件を個別に検査する
		if( fields == 0U || fields > 4U || readInfField( row, 1U, name) != 0 ||
		   (fields >= 2U && readInstallInventoryField( row, 2U, mediaName) != 0) ||
		   (rule.exactShape &&
			(!mediaName.empty() || readInstallInventoryField( row, 0U, key) == 0)) ||
		   (rule.sameNameDirid != 0U && !mediaName.empty() && !stringsEqual( mediaName, name)) ||
		   (fields >= 3U &&
			(readInstallInventoryField( row, 3U, temporary) != 0 || !temporary.empty())) ||
		   (rule.requireFlags && fields != 4U) ||
		   (fields == 4U && (!SetupGetIntField( &row, 4U, &flags) || flags != rule.flags))) {
			return unsupported ;
		}

		const auto &source		  = mediaName.empty() ? name : mediaName ;	// 元の同名指定を解決する
		const auto	previousCount = copies.size() ;							// 別行と同じ宛先を検出するための件数
		const auto	error = bindWindowsDriverCopy( inf, workspace, entries, package, list.target,
												  name, source, copies) ;	// 元コピーの閉包照合
		// 署名済みであっても重複コピー先や不明媒体を検査済みとしない
		if( error != 0 || copies.size() != previousCount + 1U) {
			return error != 0 ? error : unsupported ;
		}

		uses.push_back( {list.target, L"CopyFileSource", source}) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief USB無線機器の同じ導入節で、SYSと補助サービスの元コピーを照合します
 * @param[in] inf 同じ元INFを開く読取専用HINFです
 * @param[in] workspace 元配布物の保護領域です
 * @param[in] entries 元CABの全解決済み媒体です
 * @param[in] package 同じINFの元CATへ所属する媒体の確認済み集合です
 * @param[in] inventory 実選択済みの導入節と元参照です
 * @param[in] systemDirectory Windows標準APIで得た同端末のSystem32です
 * @param[out] copies 成功時だけ保持する選択コピーです
 * @param[out] uses 成功時だけ保持する元コピー用途です
 * @return 元コピーの全照合成功は0、最初の失敗はHRESULTです
 * @note サービスの起動や登録、共有設定の用途は後段で別途評価します
 */
//------------------------------------------------------------------------------
NativeError bindScopedUsbWirelessCopies( HINF inf, const OfficialDownloadWorkspace &workspace,
										std::span<const OfficialZipEntry>	entries,
										const OfficialInfPackage		   &package,
										const OfficialInfInstallInventory  &inventory,
										const std::wstring				   &systemDirectory,
										std::vector<WindowsDriverCopy>	   &copies,
										std::vector<MaintenanceInfFileUse> &uses)
{
	constexpr ScopedNetworkCopyListRule DRIVER{1L, 12U, COPYFLG_NOSKIP, true,
											   true} ;	// 選択元SYS一件です
	constexpr ScopedNetworkCopyListRule WORKER{4L, 13U, COPYFLG_OVERWRITE_OLDER_ONLY, true,
											   true} ;						// 元EXEとDLL三件です
	const auto unsupported = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;	// 未評価の媒体構成です
	std::vector<WindowsDriverCopy>	   made ;								// 元の全コピーが成立するまで外に渡しません
	std::vector<MaintenanceInfFileUse> covered ;							// 同じ導入節の元コピー用途です
	bool							   driverSeen{} ;						// 明示のSYSコピー節を一件だけ保持します
	bool workerSeen{} ;														// 明示の補助サービスコピー節を一件だけ保持します
	// 選択された基本節の二つの名前付き参照だけから元媒体を解決します
	for( const auto &reference :
		inventory.references | std::views::filter( []( const auto &reference) {
			return stringsEqual( reference.directive, L"CopyFiles") ;
		})) {
		std::uint32_t dirid{} ;	// 同じ元リストで明示された宛先です
		// 別の導入節や既定宛先から都合のよいコピーを借りません
		if( !stringsEqual( reference.section, inventory.selectedInstallSection) ||
		   readRequiredServiceScalar( inf, L"DestinationDirs", reference.target.c_str(), dirid) !=
			   0 ||
		   (dirid != DRIVER.sameNameDirid && dirid != WORKER.sameNameDirid)) {
			return unsupported ;
		}

		const bool	kernel = dirid == DRIVER.sameNameDirid ;	// SYSのコピー節を選んだ場合trueです
		auto	   &seen   = kernel ? driverSeen : workerSeen ;	// 対応する一節の有無です
		const auto &rule   = kernel ? DRIVER : WORKER ;			// 元DIRIDとコピー方式です
		// 同じ役割の二つ目を受理しません
		if( std::exchange( seen, true)) {
			return unsupported ;
		}

		const auto previous = made.size() ;	// この一節で追加する範囲です
		const auto error	= bindScopedNetworkCopyList( inf, workspace, entries, package, reference,
														rule, made, covered) ;	// 共通の元コピー照合です
		// 同じ元役割の必須行が一件でも欠ければ確定しません
		if( error != 0 || made.size() - previous != static_cast<std::size_t>( rule.maximumRows)) {
			return error != 0 ? error : unsupported ;
		}

		const auto	directory = kernel ? joinRelativePath( systemDirectory, L"drivers")
									   : std::wstring{L"."} ;	// 元HINFで対応する標準配置先です
		std::size_t executables{} ;								// 補助節に含む単独EXEの件数です
		// それぞれの完全宛先を同じ原名へ結び付け、別型の媒体を役割に算入しません
		for( const auto &copy : std::span{made}.subspan( previous)) {
			// 元コピーの相対位置から抽出した、補助ファイルの実名
			const auto leaf =
				std::wstring_view{copy.source}.substr( copy.source.find_last_of( L'\\') + 1U) ;
			const auto extension = lowerExtension( leaf) ;	// 元媒体の役割です
			// リダイレクト先や別名、元と異なる実行形式を受理しません
			if( !stringsEqual( copy.target, joinRelativePath( directory, leaf)) ||
			   (kernel ? extension != L".sys" : extension != L".exe" && extension != L".dll")) {
				return unsupported ;
			}

			executables += extension == L".exe" ? 1U : 0U ;
		}

		// 補助サービス用EXEが一件に定まる場合だけ対応するDLL群へ結びます
		if( !kernel && executables != 1U) {
			return unsupported ;
		}
	}

	// CAB全体の署名済み媒体の各一件に過不足なく対応する場合だけ返します
	if( !driverSeen || !workerSeen || made.size() != package.sourceFiles.size() ||
	   std::ranges::any_of( package.sourceFiles, [&]( const auto &source) {
		   return std::ranges::count_if( made, [&]( const auto &copy) {
					  return stringsEqual( copy.source, source) ;
				  }) != 1 ;
	   })) {
		return unsupported ;
	}

	copies = std::move( made) ;
	uses   = std::move( covered) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief USB無線の関連カーネルサービスと補助サービスを同選択のコピー先へ照合します
 * @param[in] inf 同じ元INFの読取専用HINFです
 * @param[in] install 同選択のAddService構造と元導入節です
 * @param[in] originalBytes 同じHINFの元INFバイトです
 * @param[in] copies 同選択の元CATと配置先を照合済みのコピーです
 * @param[in,out] uses 両サービスの完全値が一致した場合だけ元用途を追加します
 * @return 元の二つのサービスに過不足がなく同選択のコピー先へ結び付く場合trueです
 * @note 共有設定、イベントログ本文、実署名と実際の起動はこの関数で扱いません
 */
//------------------------------------------------------------------------------
bool bindScopedUsbWirelessServices( HINF inf, const MaintenanceInfInstallStructure &install,
								   std::span<const std::byte>		   originalBytes,
								   std::span<const WindowsDriverCopy>  copies,
								   std::vector<MaintenanceInfFileUse> &uses)
{
	const auto kernel = std::ranges::find_if( install.services, []( const auto &service) {
		return service.flags == static_cast<std::uint32_t>( SPSVCINST_ASSOCSERVICE) ;
	}) ; // 元機器の関連サービスです
	const auto worker = std::ranges::find_if( install.services, []( const auto &service) {
		return service.flags == static_cast<std::uint32_t>( SPSVCINST_STARTSERVICE) ;
	}) ; // 元の起動要求を持つ補助サービスです
	const auto serviceSection =
		install.inventory.selectedInstallSection + L".Services" ;	// 同装飾の元宣言節です
	const auto validDeclaration = [&]( const MaintenanceInfServiceStructure &service) {
		return service.parser.state == MaintenanceInspectionState::PASSED &&
			   stringsEqual( service.section, serviceSection) &&
			   validInstallInventorySectionName( service.serviceInstallSection) &&
			   !service.serviceName.empty() && service.serviceName.size() <= 256U &&
			   service.serviceName.find( L'\\') == service.serviceName.npos &&
			   validRequiredServiceSubdirectory( service.serviceName) ;
	} ; // 今回の元サービス節を同期借用し、名前と宣言元を照合します
	// 別節のサービス、同じサービス、追加フラグ、余分な元欄を既知の役割へ割り当てません
	if( install.services.size() != 2U || kernel == install.services.end() ||
	   worker == install.services.end() || !validDeclaration( *kernel) ||
	   !validDeclaration( *worker) || kernel->fieldCount != 4U || worker->fieldCount != 3U ||
	   !validInstallInventorySectionName( kernel->eventLogSection) ||
	   !worker->eventLogSection.empty() || stringsEqual( kernel->serviceName, worker->serviceName) ||
	   stringsEqual( kernel->serviceInstallSection, worker->serviceInstallSection)) {
		return false ;
	}

	const auto sys = std::ranges::find_if( copies, []( const auto &copy) {
		return copy.dirid == 12 && lowerExtension( copy.target) == L".sys" ;
	}) ; // 同選択で一意に照合した元カーネルSYSです
	const auto exe = std::ranges::find_if( copies, []( const auto &copy) {
		return copy.dirid == 13 && lowerExtension( copy.target) == L".exe" ;
	}) ; // 同選択で一意に照合した元補助EXEです
	// 検査済みの実体が欠けた場合は、名前からコピー先を補いません
	if( sys == copies.end() || exe == copies.end()) {
		return false ;
	}

	const auto &kernelConfig = kernel->serviceInstallSection ;	// 元のカーネル設定節です
	const auto &workerConfig = worker->serviceInstallSection ;	// 元の補助サービス設定節です
	const auto	scalarIs	 = [&]( const std::wstring &section, const wchar_t *key,
							   std::uint32_t expected) {
		 std::uint32_t actual{} ;	// 一意な元数値は読取成功時だけ比較します
		 return readRequiredServiceScalar( inf, section, key, actual) == 0U && actual == expected ;
	} ; // 同じ読取HINFを同期借用します
	const auto valueIs = [&]( const std::wstring &section, const wchar_t *key,
							 std::wstring_view expected) {
		std::wstring actual ;	// 元の一値を省略や分割なしで読みます
		return readRequiredServiceField( inf, section, key, actual) == 0U &&
			   stringsEqual( actual, expected) ;
	} ; // 同じ読取HINFを同期借用します
	std::wstring kernelBinary ;	// 元カーネルサービスの完全なバイナリ値です
	std::wstring workerBinary ;	// 元補助サービスの引用符付き完全値です
	std::wstring displayName ;	// 個々の元表示名の存在を照会します
	const auto	 quotedTarget =
		L"\"" + exe->target + L"\"" ;	// 同元コピーから構成した引用符付き完全値です
	MaintenanceInfByteProof proof ;		// DIRID展開前の原宣言を解析する有限readerです
	// 自動起動EXEの追加引数・依存の変更と、両設定節の未知行や重複を認定しません
	if( SetupGetLineCountW( inf, kernelConfig.c_str()) != 6L ||
	   !scalarIs( kernelConfig, L"ServiceType", SERVICE_KERNEL_DRIVER) ||
	   !scalarIs( kernelConfig, L"StartType", SERVICE_DEMAND_START) ||
	   !scalarIs( kernelConfig, L"ErrorControl", SERVICE_ERROR_NORMAL) ||
	   !valueIs( kernelConfig, L"LoadOrderGroup", L"NDIS") ||
	   readRequiredServiceField( inf, kernelConfig, L"DisplayName", displayName) != 0U ||
	   readRequiredServiceField( inf, kernelConfig, L"ServiceBinary", kernelBinary) != 0U ||
	   !stringsEqual( kernelBinary, sys->target) ||
	   SetupGetLineCountW( inf, workerConfig.c_str()) != 7L ||
	   !scalarIs( workerConfig, L"ServiceType", SERVICE_WIN32_OWN_PROCESS) ||
	   !scalarIs( workerConfig, L"StartType", SERVICE_AUTO_START) ||
	   !scalarIs( workerConfig, L"ErrorControl", SERVICE_ERROR_IGNORE) ||
	   !valueIs( workerConfig, L"LoadOrderGroup", kernel->serviceName) ||
	   !valueIs( workerConfig, L"Dependencies", kernel->serviceName) ||
	   readRequiredServiceField( inf, workerConfig, L"DisplayName", displayName) != 0U ||
	   readRequiredServiceField( inf, workerConfig, L"ServiceBinary", workerBinary) != 0U ||
	   !stringsEqual( workerBinary, quotedTarget) ||
	   !proof.matchesScopedUsbStoreService( originalBytes, workerConfig, exe->source)) {
		return false ;
	}

	uses.push_back( {kernelConfig, L"ServiceBinary", std::move( kernelBinary)}) ;
	uses.push_back( {workerConfig, L"ServiceBinary", std::move( workerBinary)}) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ元サービス節の引用符付きDIRID 13宣言を元コピー名に照合します
 * @param[in] bytes 読取専用HINFと同時に保持する元INFです
 * @param[in] service 元の補助サービス構成節です
 * @param[in] leaf 元コピーの単独EXE名です
 * @return 元節の一意なリテラル宣言が同じEXE名を指定した場合trueです
 */
//------------------------------------------------------------------------------
bool MaintenanceInfByteProof::matchesScopedUsbStoreService( std::span<const std::byte> bytes,
														   std::wstring_view		  service,
														   std::wstring_view		  leaf)
{
	// 元バイトが不明または容量外の場合は、展開後の一致だけで元宣言を認定しません
	if( bytes.empty() || bytes.size() > MAXIMUM_INACTIVE_CO_INSTALLER_BYTES || leaf.empty()) {
		return false ;
	}

	bytes_.resize( bytes.size()) ;
	std::ranges::copy( bytes, std::as_writable_bytes( std::span{bytes_}).begin()) ;
	// 同じ有限パーサーで元節の重複や不明構文を拒否します
	if( !scan( false, true, false, true) || duplicateSections_) {
		return false ;
	}

	const auto section = std::ranges::find_if( sections_, [&]( const auto &item) {
		return stringsEqual( text( item.name), service) ;
	}) ; // 同じ元設定節だけを名前で照合します
	// 設定節がなければ別節の同名キーを使いません
	if( section == sections_.end()) {
		return false ;
	}

	const auto index = static_cast<std::size_t>( section - sections_.begin()) ;	// 元節の一意位置です
	bool	   found{} ;														// 一つの元バイナリ欄を照合した場合trueです
	// 解析済み元行だけを対象に、同設定節の物理的な指定を一件に絞ります
	for( const auto &row : rows_) {
		// 他節のバイナリを同じ補助サービスの一部にしません
		if( row.section != index || !stringsEqual( text( row.key), L"ServiceBinary")) {
			continue ;
		}

		// 元の展開元を、同じ見かけの相対パスやStrings別名へ置き換えません
		if( std::exchange( found, true) || row.fields != 1U ||
		   !stringsEqual( quotedStoreServiceLeaf( text( fields_[row.firstField])), leaf)) {
			return false ;
		}
	}

	return found ;
}

//------------------------------------------------------------------------------
/**
 * @brief コピーする無線LAN拡張DLLを同じ基本節だけの元登録値へ結ぶ
 * @param[in] inf 元署名とハッシュを確認した同じ読取専用INF
 * @param[in] install 一つの元DDInstallの全参照とファイル用途
 * @param[in] name 検証したSystem32コピー先のファイル名
 * @param[in,out] uses 当該元用途だけを成功時に追加する
 * @return 同じコピー先を指す一意なHKR登録を確認した場合true
 */
//------------------------------------------------------------------------------
bool bindScopedWirelessExtension( HINF inf, const MaintenanceInfInstallStructure &install,
								 std::wstring_view name, std::vector<MaintenanceInfFileUse> &uses)
{
	std::wstring path{L"%SystemRoot%\\system32\\"} ;	// 元登録が使用する完全なWindows資源表記
	path.append( name) ;
	const auto registry = std::ranges::find_if( install.fileUses, [&]( const auto &use) {
		return stringsEqual( use.directive, L"RegistryFileUseNotAssessed") &&
			   stringsEqual( use.target, path) ;
	}) ; // 同じコピー先を持つ元のファイル用途
	// 他サービスや複数のAddReg文脈へ共用する登録を認定しない
	if( registry == install.fileUses.end() ||
	   SetupGetLineCountW( inf, registry->section.c_str()) != 1L ||
	   SetupGetLineCountW( inf, (registry->section + L".Security").c_str()) >= 0L ||
	   std::ranges::count_if( install.inventory.references,
							 [&]( const auto &reference) {
								 return reference.kind ==
											OfficialInfInstallReferenceKind::LOCAL_SECTION &&
										stringsEqual( reference.target, registry->section) ;
							 }) != 1 ||
	   std::ranges::none_of( install.inventory.references, [&]( const auto &reference) {
		   return reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
				  reference.targetPresent && stringsEqual( reference.directive, L"AddReg") &&
				  stringsEqual( reference.section, install.inventory.selectedInstallSection) &&
				  stringsEqual( reference.target, registry->section) ;
	   })) {
		return false ;
	}

	INFCONTEXT	 row{} ;					// 同じ元AddRegの唯一の行
	std::wstring root, key, value, data ;	// 元登録の相対キー、値と文字列データ
	int			 flags{} ;					// SetupAPIが読み取る型指定
	// HKR内の無線LAN拡張だけに限定し、コマンドや別レジストリ型を許可しない
	if( !SetupGetLineByIndexW( inf, registry->section.c_str(), 0U, &row) ||
	   SetupGetFieldCount( &row) != 5U || readInfField( row, 1U, root) != 0 ||
	   !stringsEqual( root, L"HKR") || readInfField( row, 2U, key) != 0 ||
	   !stringsEqual( key, L"Ndi\\IHVExtensions") || readInfField( row, 3U, value) != 0 ||
	   !stringsEqual( value, L"ExtensibilityDLL") || !SetupGetIntField( &row, 4U, &flags) ||
	   flags != 0 || readInfField( row, 5U, data) != 0 || !stringsEqual( data, path)) {
		return false ;
	}

	uses.push_back( *registry) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief DelRegが削除できるデバイスの個別設定名を検査します
 * @param[in] name 元行から読んだ単一の設定名です
 * @return 単一のASCII設定名で、Windowsが予約する制御名に該当しない場合trueです
 */
//------------------------------------------------------------------------------
bool isScopedWirelessParameterName( std::wstring_view name)
{
	constexpr std::wstring_view STANDARD_SETTINGS[]{
		L"*WakeOnMagicPacket", L"*WakeOnPattern",
		L"*PacketCoalescing"} ;	// 元無線設定で許す受動の標準プロパティです
	// 予約の接頭文字を持つ名前は既知の設定だけを扱います
	if( name.starts_with( L"*")) {
		return isAllowedValue( name, STANDARD_SETTINGS) ;
	}

	constexpr std::wstring_view RESERVED[]{
		L"AddReg",
		L"DelReg",
		L"UpperFilters",
		L"LowerFilters",
		L"ClassInstall32",
		L"DeviceInterfaceGUIDs",
		L"InterfaceGuid",
		L"Driver",
		L"DriverDesc",
		L"DriverVersion",
		L"DriverDate",
		L"ProviderName",
		L"MatchingDeviceId",
		L"InfPath",
		L"InfSection",
		L"InfSectionExt",
		L"ComponentId",
		L"NetCfgInstanceId",
		L"Ndi",
		L"Params",
		L"Defaults",
		L"Characteristics",
		L"BusType",
		L"IfType",
		L"MediaType",
		L"PhysicalMediaType",
		L"Linkage",
		L"Bind",
		L"Export",
		L"Route",
		L"UpperRange",
		L"LowerRange",
		L"FilterClass",
		L"FilterType",
		L"FilterRunType",
		L"Service",
		L"Services",
		L"ServiceDll",
		L"ServiceMain",
		L"ImagePath",
		L"Start",
		L"StartOverride",
		L"Type",
		L"ErrorControl",
		L"DependOnService",
		L"DependOnGroup",
		L"Group",
		L"BootFlags",
		L"ObjectName",
		L"Security",
		L"Run",
		L"RunOnce",
		L"RunOnceEx",
		L"Command",
		L"CmdLine",
		L"IsolatedCommand",
		L"Debugger",
		L"DllName",
		L"ExtensibilityDLL",
		L"EventMessageFile",
		L"TypesSupported"} ;	// デバイスとサービスの登録・起動・識別に使われる値名です
	constexpr std::wstring_view RESERVED_FAMILIES[]{
		L"CoInstallers", L"CoDeviceInstallers", L"EnumPropPages",
		L"Installer"} ;	// Microsoftの登録名とその装飾をまとめて拒否します
	// パス、空名、既定値、特殊文字、制御名を個別設定に読み替えません
	return !name.empty() && name.size() <= 64U &&
		   std::ranges::all_of( name,
							   []( wchar_t character) {
								   return (character >= L'a' && character <= L'z') ||
										  (character >= L'A' && character <= L'Z') ||
										  (character >= L'0' && character <= L'9') ||
										  character == L'_' ;
							   }) &&
		   !isAllowedValue( name, RESERVED) &&
		   std::ranges::none_of( RESERVED_FAMILIES, [name]( const auto family) {
			   return stringsEqual( name.substr( 0U, family.size()), family) ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択基本節が所有するDelRegの全行をデバイスの個別設定へ限定します
 * @param[in] inf 同一の署名・原ハッシュで固定した読み取り専用INFです
 * @param[in] inventory 公式Modelsの同じ一選択から得た全参照です
 * @return 不在または全行の型と所有が確認できれば0、未評価・曖昧な作用はHRESULTです
 * @note 別のAddRegやサービスのHKR文脈を借用せず、登録の削除は実行しません
 */
//------------------------------------------------------------------------------
NativeError checkScopedWirelessDeletes( HINF inf, const OfficialInfInstallInventory &inventory)
{
	const auto unsupported =
		// 未評価の削除を保持する診断です
		nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	const auto isDelete = []( const auto &item) {
		return stringsEqual( item.directive, L"DelReg") ;
	} ; // 同じ選択で観測した削除だけを抽出します
	// 選択したインベントリーにある最初の削除節への参照位置
	const auto reference = std::ranges::find_if( inventory.references, isDelete) ;
	// 実際の削除作用数。参照だけと区別して閉包を確認します
	const auto effects = std::ranges::count_if( inventory.effects, isDelete) ;
	// 削除のない元選択にも、未解決の宣言がないことを確認します
	if( reference == inventory.references.end()) {
		return effects == 0 ? 0U : unsupported ;
	}

	std::wstring target ;	// 選択基本節が指す唯一の元登録節です
	// 同じ起点の一意な明示参照だけを使用し、別節・別作用と共用しません
	if( effects != 1 || std::ranges::count_if( inventory.references, isDelete) != 1 ||
	   !stringsEqual( reference->section, inventory.selectedInstallSection) ||
	   reference->kind != OfficialInfInstallReferenceKind::LOCAL_SECTION ||
	   !reference->targetPresent || !validInstallInventorySectionName( reference->target) ||
	   readRequiredServiceField( inf, inventory.selectedInstallSection, L"DelReg", target) != 0U ||
	   !stringsEqual( target, reference->target) ||
	   std::ranges::count_if( inventory.references, [&]( const auto &use) {
		   return use.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
				  stringsEqual( use.target, target) ;
	   }) != 1) {
		return unsupported ;
	}

	LONG count{} ;		// 元削除リストの全行数です
	LONG security{} ;	// 同節への独立した権限宣言の有無です
	// 削除先を選択した元節の実行数と、この読み取りの診断値を得ます
	auto error = maintenanceLineCount( inf, target, count) ;
	// 元対象に必要な権限節の読取り失敗を不在で補完しません
	if( error == 0U) {
		error = maintenanceLineCount( inf, target + L".Security", security) ;
	}

	// 空・未知・過大な削除リストに個別設定の確認を発行しません
	if( error != 0U || count <= 0L || security >= 0L ||
	   static_cast<std::size_t>( count) > MAXIMUM_INSTALL_INVENTORY_LINES) {
		return error != 0U ? error : unsupported ;
	}

	std::vector<std::pair<std::wstring, std::wstring>> locations ;	// 同一キーと値の重複を検出します
	// 元行を全部読み、最初の正常な削除だけで後続を承認しません
	for( LONG index = 0L; index < count; ++index) {
		INFCONTEXT row{} ;	// 同じ削除節の元行です
		error = maintenanceLineAt( inf, target, index, row) ;
		// 元行が読めない場合は部分成功を返しません
		if( error != 0U) {
			return error ;
		}

		const auto	 fields = SetupGetFieldCount( &row) ;	// 省略された値名と空値名を区別します
		std::wstring key ;									// key付きの曖昧なDelReg行を識別します
		std::wstring root ;									// 元の相対registry rootです
		std::wstring subkey ;								// 元の完全な相対サブキー名です
		std::wstring value ;								// 名前付き値か、フィールドなしの場合は空です
		// 明示HKRのkeyなし2/3-fieldだけに限定し、追加flagsや既定値を削除しません
		if( (fields != 2U && fields != 3U) ||
		   readInfField( row, 0U, key) != nativeErrorFromWin32( ERROR_INVALID_PARAMETER) ||
		   readInfField( row, 1U, root) != 0U || !stringsEqual( root, L"HKR") ||
		   readInstallInventoryField( row, 2U, subkey) != 0U ||
		   (fields == 3U && readInfField( row, 3U, value) != 0U)) {
			return unsupported ;
		}

		constexpr std::wstring_view PARAMETERS = L"Ndi\\params\\" ;	// 単一パラメーターの親です
		// デバイス固有の既知パラメーター値だけを削除する行かを示します
		const bool					namedValue = fields == 3U &&
								(subkey.empty() || stringsEqual( subkey, L"defaults")) &&
								isScopedWirelessParameterName( value) ;
		// 既知パラメーター専用の子キーを削除する行かを示します
		const bool parameterKey =
			fields == 2U && subkey.size() > PARAMETERS.size() &&
			stringsEqual( std::wstring_view{subkey}.substr( 0U, PARAMETERS.size()), PARAMETERS) &&
			isScopedWirelessParameterName( std::wstring_view{subkey}.substr( PARAMETERS.size())) ;
		// 広いキー、予約済み名、同じ目的への重複を無害な削除として数えません
		if( (!namedValue && !parameterKey) ||
		   std::ranges::any_of( locations, [&]( const auto &location) {
			   return stringsEqual( location.first, subkey) && stringsEqual( location.second, value) ;
		   })) {
			return unsupported ;
		}

		locations.emplace_back( std::move( subkey), std::move( value)) ;
	}

	return 0U ;
}

/** @brief 選択INFから読取り済みの共有無線ログ設定一行 */
struct ScopedWirelessRegistryWrite {
	/// 元のHKRまたはHKLMを基点にしたサブキー
	std::wstring  subkey ;
	/// 設定の名前
	std::wstring  name ;
	/// SetupAPIが読み取ったフラグ
	std::uint32_t flags{} ;
	/// 一つの完全な元データ
	std::wstring  value ;
} ;

/** @brief 一つの既知ログ設定の元スキーマ */
struct ScopedWirelessLoggerValue {
	/// 既知のAutoLoggerセッション名
	std::wstring_view session ;
	/// 同じセッションの直下の一つのプロバイダーを対象とする場合true
	bool			  provider{} ;
	/// セッションまたはプロバイダーの値名
	std::wstring_view name ;
	/// DWORDの値。GUID型の場合は使用しない
	std::uint32_t	  value{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 無線ログ設定の全行が既知のセッションとプロバイダーに閉じることを確認する
 * @param[in] writes 同じ基本導入節に直接属する署名済みAddRegの共有行
 * @param[in] usbWireless USB無線の元17行を要求する場合trueです
 * @return USBは元17行、PCIは空または所定18行が完全かつ一意ならtrueです
 * @note 元INFの作用を非実行で確認する。端末の現在設定や導入資格は評価しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchScopedWirelessLogger( std::span<const ScopedWirelessRegistryWrite> writes,
											 bool usbWireless = false)
{
	// 既知の無線ログセッションにつながるWindowsの元レジストリ接頭部
	constexpr std::wstring_view PREFIX = L"SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\" ;
	constexpr std::wstring_view TRACE  = L"WifiDriverSession" ;			// Windowsの無線ログ設定
	constexpr std::wstring_view IHV	   = L"WifiDriverIHVSession" ;		// 無線アダプターのログ設定
	constexpr std::wstring_view REPRO  = L"WifiDriverIHVSessionRepro" ;	// 再現用ログ設定
	constexpr std::array<ScopedWirelessLoggerValue, 18U> definitions{{
		{TRACE, false, L"Start", 0U},
		{IHV, false, L"GUID", 0U},
		{IHV, false, L"Start", 1U},
		{IHV, false, L"BufferSize", 80U},
		{IHV, false, L"LogFileMode", 2U},
		{IHV, false, L"MaxFileSize", 8U},
		{IHV, false, L"MaximumBuffers", 16U},
		{IHV, false, L"MinimumBuffers", 2U},
		{IHV, false, L"FlushTimer", 1U},
		{IHV, true, L"Enabled", 1U},
		{IHV, true, L"EnableLevel", 1U},
		{IHV, true, L"EnableFlags", 3U},
		{IHV, true, L"Status", 0U},
		{REPRO, false, L"Start", 1U},
		{REPRO, true, L"Enabled", 1U},
		{REPRO, true, L"EnableLevel", 1U},
		{REPRO, true, L"EnableFlags", 3U},
		{REPRO, true, L"Status", 0U},
	}} ; // 観測済みの共有設定全体の値と型
	// 共有設定が存在しない場合と不完全な場合を区別する
	if( writes.size() != definitions.size() - (usbWireless ? 1U : 0U)) {
		return !usbWireless && writes.empty() ;
	}

	const auto readGuid = []( const std::wstring &text, GUID &output) {
		return text.size() == 38U && text.front() == L'{' && text.back() == L'}' &&
			   CLSIDFromString( text.c_str(), &output) == S_OK && !IsEqualGUID( output, GUID_NULL) ;
	} ; // 完全な括弧付きGUIDだけを元の値またはプロバイダー名として読む
	std::array<bool, definitions.size()> matched{} ;			// 各設定の指定を一回までに制限する
	GUID								 sessionId{} ;			// 通常ログの元セッションGUID
	GUID								 providerId{} ;			// 通常ログの元プロバイダーGUID
	GUID								 reproProviderId{} ;	// 再現用ログの元プロバイダーGUID
	// 元行の順に依存せず、各行に一つの既知の役割を要求する
	for( const auto &write : writes) {
		const std::wstring_view subkey{write.subkey} ;	// 元の絶対サブキーを借用する
		// 同名の別レジストリ位置を照合に使わない
		if( !stringsEqual( subkey.substr( 0U, PREFIX.size()), PREFIX)) {
			return false ;
		}

		const auto relative = subkey.substr( PREFIX.size()) ;	// 既知の親配下の元位置
		const auto divider	= relative.find( L'\\') ;			// プロバイダーがある場合の境界
		const auto session	= relative.substr( 0U, divider) ;	// 元のセッション名
		const bool provider = divider != relative.npos ;		// 直下のプロバイダー行であること
		const auto rule		= std::ranges::find_if( definitions, [&]( const auto &entry) {
			return stringsEqual( entry.session, session) && entry.provider == provider &&
				   stringsEqual( entry.name, write.name) ;
		}) ; // 型と値を判定するために照合した一規則
		// 不明な設定や重複指定を正しい行の成功で補わない
		if( rule == definitions.end() || (usbWireless && stringsEqual( rule->name, L"FlushTimer")) ||
		   std::exchange( matched[static_cast<std::size_t>( rule - definitions.begin())], true)) {
			return false ;
		}

		// プロバイダーの全設定は同じセッション内の一つの正規GUIDに結ぶ
		if( provider) {
			GUID  parsed{} ;	// 今回の元行が指定するプロバイダー
			auto &expected =
				// 同セッションの既観測ID
				stringsEqual( session, IHV) ? providerId : reproProviderId ;
			const auto usbProvider =
				stringsEqual( session, IHV)
					? L"{7b99cac3-85da-419b-a46d-452d9e1d1659}"
					: L"{0d520601-c0c1-4a23-a8d0-cc5b8ac77517}" ;	// 元USBの二つの独立したログ提供者です
			// 別階層や同じセッション内の別プロバイダーを拒否する
			if( (usbWireless && !stringsEqual( relative.substr( divider + 1U), usbProvider)) ||
			   !readGuid( std::wstring{relative.substr( divider + 1U)}, parsed) ||
			   (!IsEqualGUID( expected, GUID_NULL) && !IsEqualGUID( parsed, expected))) {
				return false ;
			}

			expected = parsed ;
		}

		// セッションGUIDは一つのREG_SZとしてのみ認める
		if( stringsEqual( rule->name, L"GUID")) {
			// OSや他のログセッションへ誘導する間接値は使わない
			if( write.flags != FLG_ADDREG_TYPE_SZ || !readGuid( write.value, sessionId) ||
			   (usbWireless &&
				!stringsEqual( write.value, L"{810F5633-19B2-4BC7-BB98-5574411A7053}"))) {
				return false ;
			}
		} else {
			std::uint32_t				  value{} ;		// 元DWORD値
			MaintenanceInfStructureReason reason{} ;	// 既存の全数値読取りの診断
			// 型やオプション、元数値の差を部分一致として受理しない
			if( write.flags != FLG_ADDREG_TYPE_DWORD ||
			   parseMaintenanceFlags( write.value, value, reason).state !=
				   MaintenanceInspectionState::PASSED ||
			   value != rule->value) {
				return false ;
			}
		}
	}

	return !IsEqualGUID( sessionId, providerId) && !IsEqualGUID( sessionId, reproProviderId) &&
		   !IsEqualGUID( providerId, reproProviderId) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択機器のMSI設定に使われる元の4行を照合する
 * @param[in] inf 同じ署名済みINFの読取りハンドル
 * @param[in] section 選択した.HWから一意に参照されたAddReg節
 * @param[in] count 元節の全行数
 * @return 元の3欄の2行と名前付きDWORDの2行が成立する場合true
 * @note 3欄の行を別のフラグ表現と同じ動作とは推定しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool checkScopedWirelessMsi( HINF inf, const std::wstring &section, LONG count)
{
	constexpr std::wstring_view keys[]{
		L"Interrupt Management",
		L"Interrupt Management\\MessageSignaledInterruptProperties"} ;	// 対象機器内の元キーです
	// 追加または欠落のある機器設定から既知の作用を作らない
	if( count != 4L) {
		return false ;
	}

	// 元行の順序と欄の意味を維持して全行を照合する
	for( LONG index = 0L; index < count; ++index) {
		INFCONTEXT	 row{} ;				// 同じ元設定の一行
		std::wstring root ;					// 元hiveの完全名
		std::wstring path ;					// 元サブキーの完全名
		std::wstring name ;					// 第3欄の完全値
		const bool	 initial = index < 2L ;	// 最初の2行は元欄数を維持する
		// 別場所の設定や値を同じ相対キーへ結び付けない
		if( maintenanceLineAt( inf, section, index, row) != 0U ||
		   SetupGetFieldCount( &row) != (initial ? 3U : 5U) || readInfField( row, 1U, root) != 0U ||
		   !stringsEqual( root, L"HKR") || readInfField( row, 2U, path) != 0U ||
		   !stringsEqual( path, keys[index == 0L ? 0U : 1U]) || readInfField( row, 3U, name) != 0U ||
		   !stringsEqual( name, initial		 ? L"0x00000010"
							   : index == 2L ? L"MSISupported"
											 : L"MessageNumberLimit")) {
			return false ;
		}

		int flags{} ;	// 名前付き行にだけある元フラグ値です
		int value{} ;	// 名前付き行の元DWORD値です
		// 名前付き設定は既知の二つのDWORD値だけです
		if( !initial && (!SetupGetIntField( &row, 4U, &flags) || flags != FLG_ADDREG_TYPE_DWORD ||
						!SetupGetIntField( &row, 5U, &value) || value != 1)) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集用無線LANのAddReg到達先で共有レジストリと対象機器の元設定を確認する
 * @param[in] inf 同じ元署名と全ハッシュを確認した読取り専用INF
 * @param[in] inventory 一つの公式選択の元参照と実在節
 * @param[in] service 元SYSのカーネルサービスとして確認した名前
 * @param[in] requireMsi 追加属性と同じ選択のMSI設定も確認する場合true
 * @return 確認済み範囲のみの場合true。不明なhive、兼用、追加作用はfalse
 * @note 設定やセッションを書き換えない。選択外の節は導入根拠に使わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool checkScopedWirelessRegistry( HINF								  inf,
											   const OfficialInfInstallInventory &inventory,
											   const std::wstring &service, bool requireMsi)
{
	std::vector<std::wstring>				 inspected ;				// 既に確認したAddReg到達節
	std::vector<ScopedWirelessRegistryWrite> writes ;					// 唯一の共有節から得た全行
	std::size_t								 total{} ;					// 同じ選択で再読取りする全行数
	const auto hardware	  = inventory.selectedInstallSection + L".HW" ;	// 選択機器設定を所有する元節
	const auto parameters = L"SYSTEM\\CurrentControlSet\\Services\\" + service +
							L"\\Parameters" ;	// 同じサービスの元設定先
	bool msi{} ;								// 選択機器からの元設定を確認したこと
	bool dma{} ;								// 同サービスへの一意なDMA宣言を確認したこと
	// Windowsが実際に解決したAddRegだけを元作用の起点にする
	for( const auto &reference : inventory.references) {
		// コピーやイベント親など、別用途の参照は元ファイル検査で扱う
		if( !stringsEqual( reference.directive, L"AddReg")) {
			continue ;
		}

		// 不明な参照を空のAddRegへ読み替えない
		if( reference.kind != OfficialInfInstallReferenceKind::LOCAL_SECTION ||
		   !reference.targetPresent || !validInstallInventorySectionName( reference.target)) {
			return false ;
		}

		// 同じ共有節の再読取りを避け、実際の呼出し数は共有行を見つけた際に照合する
		if( !appendUnique( inspected, reference.target)) {
			continue ;
		}

		LONG count{} ;		// 元AddReg節の全行数
		LONG security{} ;	// 同名のSecurity節の有無
		// 元節の欠落、権限変更、読取上限超過を別の正しい節で補完しない
		if( maintenanceLineCount( inf, reference.target, count) != 0U || count < 0L ||
		   static_cast<std::size_t>( count) > MAXIMUM_INSTALL_INVENTORY_LINES - total ||
		   maintenanceLineCount( inf, reference.target + L".Security", security) != 0U ||
		   security >= 0L) {
			return false ;
		}

		total += static_cast<std::size_t>( count) ;
		// 追加属性のある構成で機器設定を別節の作用から借用しない
		if( requireMsi && stringsEqual( reference.section, hardware)) {
			// 導入節のMSIは一つの明示AddRegだけが所有する
			if( msi || SetupGetLineCountW( inf, hardware.c_str()) != 1L ||
			   !checkScopedWirelessMsi( inf, reference.target, count) ||
			   std::ranges::count_if( inventory.references, [&]( const auto &use) {
				   return use.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
						  stringsEqual( use.target, reference.target) ;
			   }) != 1) {
				return false ;
			}

			msi = true ;
		}

		bool directSharedSection{} ;	// この節の最初の共有行で呼出し元を確認したこと
		// すべての元AddReg行を確認し、最初のデバイス相対行だけで節を分類しない
		for( LONG index = 0; index < count; ++index) {
			INFCONTEXT	 row{} ;	// 同じ署名INFの実在行
			std::wstring root ;		// 元のregistry hive
			// 読取失敗やキー付きのAddRegを相対設定と推定しない
			if( maintenanceLineAt( inf, reference.target, index, row) != 0U ||
			   readInfField( row, 0U, root) != nativeErrorFromWin32( ERROR_INVALID_PARAMETER) ||
			   readInfField( row, 1U, root) != 0U) {
				return false ;
			}

			// HKRのファイル参照と削除は既存の専用検査を維持する
			if( stringsEqual( root, L"HKR")) {
				continue ;
			}

			// 共有設定は直接AddRegだけが所有し、別文脈や兼用を認めない
			if( !directSharedSection &&
			   (!stringsEqual( reference.section, inventory.selectedInstallSection) ||
				std::ranges::count_if( inventory.references, [&]( const auto &use) {
					return use.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
						   stringsEqual( use.target, reference.target) ;
				}) != 1)) {
				return false ;
			}

			ScopedWirelessRegistryWrite	  write ;		// 元の共有行から得た全設定
			std::wstring				  flags ;		// 元フラグの完全な数値文字列
			MaintenanceInfStructureReason reason{} ;	// 全数値読取りの診断
			// 色々な型、外部hiveや予約文字列の読取を共有ログの書式に含めない
			if( !stringsEqual( root, L"HKLM") || SetupGetFieldCount( &row) != 5U ||
			   readInfField( row, 2U, write.subkey) != 0U ||
			   readInfField( row, 3U, write.name) != 0U || readInfField( row, 4U, flags) != 0U ||
			   readInfField( row, 5U, write.value) != 0U ||
			   parseMaintenanceFlags( flags, write.flags, reason).state !=
				   MaintenanceInspectionState::PASSED) {
				return false ;
			}

			// 別の直接一行節で宣言した関連サービス自身のDMA属性だけを照合する
			if( stringsEqual( write.name, L"DmaRemappingCompatible")) {
				std::uint32_t setting{} ;	// 元のDWORD値
				// 別サービス、重複、元設定先の変更を許可しない
				if( count != 1L || std::exchange( dma, true) || service.find( L'\\') != service.npos ||
				   !validRequiredServiceSubdirectory( service) ||
				   !stringsEqual( write.subkey, parameters) ||
				   write.flags != FLG_ADDREG_TYPE_DWORD ||
				   parseMaintenanceFlags( write.value, setting, reason).state !=
					   MaintenanceInspectionState::PASSED ||
				   setting != 1U) {
					return false ;
				}

				continue ;
			}

			// 共有ログの全18行は一つの直接節だけが所有する
			if( (!directSharedSection && !writes.empty()) || writes.size() == 18U) {
				return false ;
			}

			directSharedSection = true ;
			writes.push_back( std::move( write)) ;
		}
	}

	return (!requireMsi || msi) && matchScopedWirelessLogger( writes) ;
}

//------------------------------------------------------------------------------
/**
 * @brief USB無線の対象デバイスだけに相対的な設定データを照合します
 * @param[in] values 元AddRegの展開済み5欄です。同じ選択のHKRを指定します
 * @param[in] flags 元のAddReg登録型です。空欄は既定の文字列型です
 * @return 個別設定・その列挙ラベル・元の空のファイル設定の場合trueです
 */
//------------------------------------------------------------------------------
bool checkScopedUsbWirelessParameter( const std::array<std::wstring, 5U> &values,
									 std::uint32_t						 flags)
{
	const auto					 &path = values[1] ;	// 元の相対サブキーです
	const auto					 &name = values[2] ;	// デバイスの設定名または列挙値です
	const auto					 &data = values[4] ;	// 元の一つのデータ値です
	std::uint32_t				  number{} ;			// 数値設定の全値です
	MaintenanceInfStructureReason reason{} ;			// 数値解析の元診断です
	const bool					  numeric =
		parseMaintenanceFlags( data, number, reason).state ==
		MaintenanceInspectionState::PASSED ;	// 文字列として記録する設定値も一数値に限定できます
	// 元のルート設定と既定値は名前付き数値を基本とします
	if( path.empty() || stringsEqual( path, L"defaults")) {
		// 外部ファイルの参照、既定での鍵設定、別種類の登録へ意味を変えません
		if( flags == FLG_ADDREG_TYPE_SZ && path.empty()) {
			constexpr std::wstring_view EMPTY_VALUES[]{L"PwrLimitFile", L"DefaultKey0",
													   L"DefaultKey1", L"DefaultKey2",
													   L"DefaultKey3"} ;	// 元の未指定設定です
			// 元の未指定値に外部ファイル名や鍵を追加しません
			if( isAllowedValue( name, EMPTY_VALUES)) {
				return data.empty() ;
			}

			// 既定キーは元の未選択値を維持します
			if( stringsEqual( name, L"DefaultKeyID")) {
				return data == L"0" ;
			}

			constexpr std::wstring_view LED_VALUES[]{
				L"LEDCtrlMode", L"LEDConfig", L"LEDToggleArgs",
				L"LEDToggleIntervals"} ;	// 元LED設定にある数値列です
			// LEDの列挙値をパスや設定式へ変更しません
			if( isAllowedValue( name, LED_VALUES)) {
				return !data.empty() && std::ranges::all_of( data, []( wchar_t character) {
					return (character >= L'0' && character <= L'9') || character == L',' ||
						   character == L';' ;
				}) ;
			}
		}

		return !values[3].empty() && isScopedWirelessParameterName( name) && numeric &&
			   (flags == FLG_ADDREG_TYPE_SZ ||
				(path.empty() && flags == FLG_ADDREG_TYPE_DWORD &&
				 (stringsEqual( name, L"CoreAMSDU") || stringsEqual( name, L"rx_ampdu_num")))) ;
	}

	constexpr std::wstring_view PARAMS = L"Ndi\\Params\\" ;	// 詳細設定の明示親です
	// デバイスの詳細設定から別のキー階層や展開型に移動しません
	if( flags != FLG_ADDREG_TYPE_SZ || values[3].empty() ||
	   !stringsEqual( std::wstring_view{path}.substr( 0U, PARAMS.size()), PARAMS)) {
		return false ;
	}

	const auto parameter = std::wstring_view{path}.substr( PARAMS.size()) ;	// 同じ設定の元子キーです
	const auto separator = parameter.find( L'\\') ;							// 値の説明か列挙子かを区別します
	// 予約名への置換や二重階層を詳細設定として扱いません
	if( !isScopedWirelessParameterName( parameter.substr( 0U, separator))) {
		return false ;
	}

	const bool plainText = !data.empty() && data.find_first_of( L"\\/:%\r\n\t") ==
												data.npos ;	// 参照を持たない表示データです
	// 同じ設定の直下の型・既定値、説明、数値列挙子だけを許容します
	if( separator == parameter.npos) {
		return (stringsEqual( name, L"Type") && stringsEqual( data, L"enum")) ||
			   (stringsEqual( name, L"Default") && numeric) ||
			   (stringsEqual( name, L"ParamDesc") &&
				(plainText || isWirelessParameterLabel( values, true))) ;
	}

	return stringsEqual( parameter.substr( separator), L"\\enum") && !name.empty() &&
		   std::ranges::all_of(
			   name, []( wchar_t character) { return character >= L'0' && character <= L'9' ; }) &&
		   (plainText || isWirelessParameterLabel( values, true)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式USB無線の同じ選択が直接所有する登録と表示用途を照合します
 * @param[in] inf 同じ元INFを固定して開いたHINFです
 * @param[in] install 同じ選択の全参照と同梱依存の証拠です
 * @param[in] eventSection 既存検査で確認したカーネル側の元イベント節です
 * @param[in] eventRegistry その元イベント節だけが所有する登録節です
 * @param[in,out] uses 照合した表示用途を追加します。失敗時の部分結果は使用しません
 * @return 選択機器の相対設定と一意な共有設定が元値に結び付く場合trueです
 */
//------------------------------------------------------------------------------
bool checkScopedUsbWirelessRegistry( HINF inf, const MaintenanceInfInstallStructure &install,
									const std::wstring				   &eventSection,
									const std::wstring				   &eventRegistry,
									std::vector<MaintenanceInfFileUse> &uses)
{
	const auto &inventory = install.inventory ;		// 同じ元選択で観測した有限参照です
	std::vector<ScopedWirelessRegistryWrite> logs ;	// 一つの直接参照節が所有する共有設定です
	std::vector<std::pair<std::wstring, std::wstring>>
				 locations ;			// 同じ対象キーと値の重複を拒否します
	std::wstring interfaceSection ;		// 元のNDI三行を持つ一つの機器登録節です
	std::size_t	 interfaceValues{} ;	// 同じ元節で検査した三種類の数です
	bool		 serviceSupport{} ;		// 補助サービスを使う元デバイス設定です
	// Windows依存を確認した場合にだけ仮想Wi-Fiを含める、許容インターフェースの下位範囲
	const auto	 lowerRange =
		  install.wifiBusNeedsVerified ? L"wlan,ethernet,vwifi" : L"wlan,ethernet" ;
	// 同じ元選択の各AddRegから、Windowsが実際に読み取った全行を照合します
	for( const auto &reference : inventory.references | std::views::filter( []( const auto &item) {
									return stringsEqual( item.directive, L"AddReg") ;
								})) {
		// 既存イベント検査が確認した親子を同じHKR文脈のデバイス設定へ混ぜません
		if( stringsEqual( reference.section, eventSection) &&
		   stringsEqual( reference.target, eventRegistry)) {
			continue ;
		}

		LONG count{} ;		// 読取りの対象行数です
		LONG security{} ;	// 元節に付加された権限の有無です
		// 選択基本節以外からの兼用を拒否し、元の全行数を収集の予算内に保ちます
		if( reference.kind != OfficialInfInstallReferenceKind::LOCAL_SECTION ||
		   !reference.targetPresent ||
		   !stringsEqual( reference.section, inventory.selectedInstallSection) ||
		   !validInstallInventorySectionName( reference.target) ||
		   std::ranges::count_if( inventory.references,
								 [&]( const auto &other) {
									 return other.kind ==
												OfficialInfInstallReferenceKind::LOCAL_SECTION &&
											stringsEqual( other.target, reference.target) ;
								 }) != 1 ||
		   maintenanceLineCount( inf, reference.target, count) != 0U || count <= 0L ||
		   static_cast<std::size_t>( count) >
			   MAXIMUM_INSTALL_INVENTORY_LINES - locations.size() - logs.size() ||
		   maintenanceLineCount( inf, reference.target + L".Security", security) != 0U ||
		   security >= 0L) {
			return false ;
		}

		bool sharedSection{} ;	// この元節が共有設定の行を所有したことです
		// 名前付きキー、同じ位置の繰返し、別hiveや登録型を一行ずつ確認します
		for( LONG index = 0; index < count; ++index) {
			INFCONTEXT					 row{} ;	// 同じ節の現在行です
			std::wstring				 key ;		// キーなし行を確かめるための元キーです
			std::array<std::wstring, 5U> values ;	// SetupAPIの元5欄です
			// 曖昧なキーや追加欄を元の設定に組み入れません
			if( maintenanceLineAt( inf, reference.target, index, row) != 0U ||
			   SetupGetFieldCount( &row) != values.size() ||
			   readInfField( row, 0U, key) != nativeErrorFromWin32( ERROR_INVALID_PARAMETER)) {
				return false ;
			}

			// 空の値や既定の型欄も区別して全欄を順に読み取ります
			for( DWORD field = 0; field < values.size(); ++field) {
				// 一欄でも読めない場合は元登録を部分的に認定しません
				if( readInstallInventoryField( row, field + 1U, values[field]) != 0U) {
					return false ;
				}
			}

			std::uint32_t				  flags{} ;		// 明示欄の元のレジストリ型です
			MaintenanceInfStructureReason reason{} ;	// 型欄の数値解析の元診断です
			// 空欄と未知フラグを区別します
			if( !values[3].empty() && parseMaintenanceFlags( values[3], flags, reason).state !=
										 MaintenanceInspectionState::PASSED) {
				return false ;
			}

			// 共有書込みは元の一つのAddRegだけが所有し、ログ照合に全欄を渡します
			if( stringsEqual( values[0], L"HKLM")) {
				// 別節への分割、型省略、追加の共有書込みは同じ元ログに含めません
				if( (!sharedSection && !logs.empty()) || values[3].empty() || logs.size() == 17U) {
					return false ;
				}

				sharedSection = true ;
				logs.push_back(
					{std::move( values[1]), std::move( values[2]), flags, std::move( values[4])}) ;
				continue ;
			}

			// デバイス相対の別hiveや同じ書込みの再定義を拒否します
			if( !stringsEqual( values[0], L"HKR") ||
			   std::ranges::any_of( locations, [&]( const auto &location) {
				   return stringsEqual( location.first, values[1]) &&
						  stringsEqual( location.second, values[2]) ;
			   })) {
				return false ;
			}

			const bool interfaceValue = stringsEqual( values[1], L"Ndi") ||
										// 元のNDI登録行です
										stringsEqual( values[1], L"Ndi\\Interfaces") ;
			// 元のNDIのサービス別名と上下の媒体範囲は同じ3行の節で確認します
			if( interfaceValue) {
				const bool serviceName = stringsEqual( values[1], L"Ndi") ;	// サービス別名の行です
				// 同じデバイス用の三行で、種類・元別名・媒体範囲を維持します
				if( count != 3L || flags != FLG_ADDREG_TYPE_SZ || values[3].empty() ||
				   (!interfaceSection.empty() &&
					!stringsEqual( interfaceSection, reference.target)) ||
				   (serviceName ? !stringsEqual( values[2], L"Service") ||
									  !stringsEqual( values[4], L"rtwlanu")
								: !((stringsEqual( values[2], L"UpperRange") &&
									 stringsEqual( values[4], L"ndis5,mdcwifi")) ||
									(stringsEqual( values[2], L"LowerRange") &&
									 stringsEqual( values[4], lowerRange))))) {
					return false ;
				}

				interfaceSection = reference.target ;
				++interfaceValues ;
			}
			// 補助サービス利用の設定は選択デバイス直下の元一値へ結びます
			else if( stringsEqual( values[2], L"RTSrvcLibSupport")) {
				// 別設定や重複行で補助サービスの元設定を上書きしません
				if( !values[1].empty() || values[3].empty() || flags != FLG_ADDREG_TYPE_SZ ||
				   values[4] != L"3" || std::exchange( serviceSupport, true)) {
					return false ;
				}
			}
			// 残る相対設定を数値や表示設定として確認します
			else if( !checkScopedUsbWirelessParameter( values, flags)) {
				return false ;
			}

			// 別の登録節を借りず、自ら照合した表示用途を保持します
			if( isWirelessParameterLabel( values, true)) {
				uses.push_back(
					{reference.target, std::wstring{WIRELESS_PARAMETER_LABEL}, values[4]}) ;
			}

			locations.emplace_back( std::move( values[1]), std::move( values[2])) ;
		}
	}

	return interfaceValues == 3U && serviceSupport && matchScopedWirelessLogger( logs, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択USB無線の外部参照を同じWindowsが確認した三つの対または不在へ照合します
 * @param[in] install 同じ元選択の読み取り結果と同梱INFの検証状態です
 * @return 元の外部参照がそろい、別用途や局所節への置換がない場合trueです
 */
//------------------------------------------------------------------------------
bool checkScopedUsbWirelessInbox( const MaintenanceInfInstallStructure &install)
{
	const auto &inventory	 = install.inventory ;	// 同じ元選択の元参照です
	auto		dependencies = inventory.references | std::views::filter( []( const auto &reference) {
							   return reference.kind == OfficialInfInstallReferenceKind::INCLUDE_INF ||
									  stringsEqual( reference.directive, L"Needs") ;
						   }) ; // 外部・局所のNeedsを区別する前の全参照です
	// 同梱証拠のない構成は、局所のNeedsを含めて元の明示依存を持ちません
	if( !install.wifiBusNeedsVerified) {
		return std::ranges::empty( dependencies) ;
	}

	constexpr std::wstring_view SUFFIXES[]{L"", L".Services", L".HW"} ;	// 同じ元選択の参照元です
	constexpr std::wstring_view NEEDS[]{
		L"VWiFiBus.CopyFiles", L"VWiFiBus.Services",
		L"VWiFiBus.PnPFilterRegistration.Hw"} ;	// 同じWindows同梱INFにある三つの元用途です
	// 個々の対以外に別INFや第四の参照を取り込みません
	if( std::ranges::distance( dependencies) != 6) {
		return false ;
	}

	// 同じ三つの元節の各一対を照合し、対を別節の成功から組み立てません
	for( std::size_t index = 0U; index < std::size( SUFFIXES); ++index) {
		// 確認中の用途に対応する、実選択の装飾済み付随節名
		const auto section = inventory.selectedInstallSection + std::wstring{SUFFIXES[index]} ;
		const bool includeFound =
			std::ranges::count_if( dependencies, [&]( const auto &reference) {
				return reference.kind == OfficialInfInstallReferenceKind::INCLUDE_INF &&
					   stringsEqual( reference.section, section) &&
					   stringsEqual( reference.directive, L"Include") &&
					   stringsEqual( reference.target, L"netvwifibus.inf") ;
			}) == 1 ; // 同梱INFだけを指定する元の明示Includeです
		const bool needsFound =
			std::ranges::count_if( dependencies, [&]( const auto &reference) {
				return reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
					   !reference.targetPresent && stringsEqual( reference.section, section) &&
					   stringsEqual( reference.directive, L"Needs") &&
					   stringsEqual( reference.target, NEEDS[index]) ;
			}) == 1 ; // 同梱側で検証される一用途です。局所の同名節は対象外です
		// 元の同じ参照元から二つ揃わないと、その構成の同梱依存を使用できません
		if( !includeFound || !needsFound) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択USB無線の元起点でコピーとサービス以外の全作用・用途を照合します
 * @param[in] inf 同じ元の署名済みINFを固定した読み取りハンドルです
 * @param[in] install 元コピーと二つのサービスを確認した同じ選択です
 * @param[in,out] uses 照合した元用途の組です。全作用に成功した場合だけ利用します
 * @return 同梱・元属性・イベント・登録と全用途の範囲が成立した場合trueです
 * @note 実バイトの実行形式と補助EXEからの依存確認は後段です
 */
//------------------------------------------------------------------------------
bool bindScopedUsbWirelessEffects( HINF inf, const MaintenanceInfInstallStructure &install,
								  std::vector<MaintenanceInfFileUse> &uses)
{
	const auto &inventory = install.inventory ;					// 同じ元選択の宣言と不足を照合します
	const auto &base	  = inventory.selectedInstallSection ;	// 元の選択基本節です
	const auto	hardware  = base + L".HW" ;						// 選択した機器への明示節です
	const auto	services  = base + L".Services" ;				// 同じ選択のサービス宣言節です
	const bool	inbox = install.wifiBusNeedsVerified ;			// 保護Windowsで確認した依存がある場合trueです
	const auto	kernel = std::ranges::find_if( install.services, []( const auto &service) {
		 return service.flags == static_cast<std::uint32_t>( SPSVCINST_ASSOCSERVICE) ;
	 }) ;						  // 元の二サービスからイベントを持つ側を得ます
	std::uint32_t featureScore{} ;	// 公式Netの同選択にある元スコアです
	// 元の選択外からの付随設定や、別の同梱参照を含む未知構成を拒否します
	if( install.parser.state != MaintenanceInspectionState::PASSED ||
	   kernel == install.services.end() || !checkScopedUsbWirelessInbox( install) ||
	   SetupGetLineCountW( inf, services.c_str()) != (inbox ? 4L : 2L) ||
	   (inbox ? SetupGetLineCountW( inf, hardware.c_str()) != 2L
			  : SetupGetLineCountW( inf, hardware.c_str()) > 0L) ||
	   SetupGetLineCountW( inf, (base + L".Filters").c_str()) >= 0L ||
	   SetupGetLineCountW( inf, (base + L".FactDef").c_str()) >= 0L ||
	   readRequiredServiceScalar( inf, base, L"FeatureScore", featureScore) != 0U ||
	   featureScore != 0xFEU) {
		return false ;
	}

	// 同梱依存がある元構成は追加属性を持ちません。別構成では6つの元値が必要です
	if( inbox
		   ? std::ranges::any_of(
				 PCI_WIRELESS_INTERFACE_ATTRIBUTES,
				 [&]( const auto &attribute) {
					 INFCONTEXT line{} ;	// 既知の追加属性が元に存在するかを確認します
					 return SetupFindFirstLineW( inf, base.c_str(), attribute.first, &line) != FALSE ;
				 })
		   : !readScopedWirelessInterfaceAttributes( inf, base)) {
		return false ;
	}

	constexpr std::wstring_view RESOURCES =
		L"%SystemRoot%\\System32\\netevent.dll" ;	// 既存Windows保護資源です
	std::wstring eventRegistry ;					// 元のイベント登録が所有する二行の節です
	// イベントの参照先とレジストリ所有元を元カーネルの一組に限定します
	if( !checkSystemDriverEventLog( inf, kernel->eventLogSection, RESOURCES, &eventRegistry)) {
		return false ;
	}

	const auto ownsUniqueSection = [&]( std::wstring_view section, std::wstring_view directive,
									   std::wstring_view target) {
		return std::ranges::count_if(
				   inventory.references,
				   [&]( const auto &reference) {
					   return reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
							  stringsEqual( reference.target, target) ;
				   }) == 1 &&
			   std::ranges::any_of( inventory.references, [&]( const auto &reference) {
				   return reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
						  reference.targetPresent && stringsEqual( reference.section, section) &&
						  stringsEqual( reference.directive, directive) &&
						  stringsEqual( reference.target, target) ;
			   }) ;
	} ; // 同じ選択の参照一覧を同期借用し、別HKR文脈での共用を検出します
	// 同一イベントの親と登録の子を期待した二つの元参照からだけ取得します
	if( !ownsUniqueSection( services, L"AddService", kernel->eventLogSection) ||
	   !ownsUniqueSection( kernel->eventLogSection, L"AddReg", eventRegistry) ||
	   !checkScopedUsbWirelessRegistry( inf, install, kernel->eventLogSection, eventRegistry,
									   uses)) {
		return false ;
	}

	constexpr std::wstring_view BASE_DIRECTIVES[]{L"AddReg", L"CopyFiles",
												  L"FeatureScore"} ;	// 既検査の基本作用です
	// コピーやイベントと同じ元起点に追加の導入・削除・実行役割を認めません
	if( std::ranges::any_of( inventory.effects, [&]( const auto &effect) {
		   const auto key = std::wstring_view{effect.directive} ;	// 実際に読んだ元宣言名です
		   // 依存は元の三節に属する照合済みのものに限定します
		   if( stringsEqual( key, L"Include") || stringsEqual( key, L"Needs")) {
			   return !inbox || !(stringsEqual( effect.section, base) ||
								  stringsEqual( effect.section, services) ||
								  stringsEqual( effect.section, hardware)) ;
		   }

		   // 基本節では元のコピー・登録・属性以外の指示を許容しません
		   if( stringsEqual( effect.section, base)) {
			   return !isAllowedValue( key, BASE_DIRECTIVES) &&
					  std::ranges::none_of(
						  PHYSICAL_NET_ATTRIBUTES,
						  [&]( const auto *attribute) { return stringsEqual( key, attribute) ; }) &&
					  (inbox || std::ranges::none_of( PCI_WIRELESS_INTERFACE_ATTRIBUTES,
													 [&]( const auto &attribute) {
														 return stringsEqual( key, attribute.first) ;
													 })) ;
		   }

		   // 起動宣言の所有節に別のサービス操作を加えません
		   if( stringsEqual( effect.section, services)) {
			   return !stringsEqual( key, L"AddService") ;
		   }

		   // 元イベントは一つの登録だけに結びます
		   if( stringsEqual( effect.section, kernel->eventLogSection)) {
			   return !stringsEqual( key, L"AddReg") ;
		   }

		   return std::ranges::none_of( install.services, [&]( const auto &service) {
			   return stringsEqual( effect.section, service.serviceInstallSection) ;
		   }) ; // 二つのサービス設定の全キーは同じ元検査で既に照合済みです
	   })) {
		return false ;
	}

	uses.push_back( {services, L"AddService", kernel->serviceName}) ;
	uses.push_back( {eventRegistry, L"RegistryFileUseNotAssessed", std::wstring{RESOURCES}}) ;
	// 登録とイベントの不足印は今照合した同一の参照だけに対応させます
	return std::ranges::all_of(
			   inventory.coverageGaps,
			   [&]( const auto &gap) {
				   return (gap.kind ==
							   OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG &&
						   stringsEqual( gap.section, services) &&
						   stringsEqual( gap.directive, L"AddService")) ||
						  (gap.kind ==
							   OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED &&
						   std::ranges::any_of( inventory.references, [&]( const auto &reference) {
							   return stringsEqual( reference.directive, L"AddReg") &&
									  stringsEqual( reference.target, gap.section) ;
						   })) ;
			   }) &&
		   std::ranges::is_permutation(
			   install.fileUses, uses, []( const auto &actual, const auto &expected) {
				   return stringsEqual( actual.section, expected.section) &&
						  stringsEqual( actual.directive, expected.directive) &&
						  stringsEqual( actual.target, expected.target) ;
			   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief USB無線の元コピーを同じCATとDriver Store配置に固定してPEの直接依存を照合します
 * @param[in] workspace 元INF、CATと全媒体を保持する保護領域です
 * @param[in] entries 公式書庫から抽出した元ファイルの位置、サイズと全ハッシュです
 * @param[in] package 固定INFの元CATと全参照ファイルです
 * @param[in] copies 同じ選択節からWindowsが解決した元コピーの全体です
 * @return 元位置・署名・全バイト・直接依存が成立した場合0、最初の不成立はHRESULTです
 * @note 同じ元INFは呼出し側が固定します。モジュールの実行や端末適用は確認しません
 */
//------------------------------------------------------------------------------
NativeError verifyScopedUsbWirelessPe( const OfficialDownloadWorkspace	&workspace,
									  std::span<const OfficialZipEntry>	 entries,
									  const OfficialInfPackage			&package,
									  std::span<const WindowsDriverCopy> copies)
{
	constexpr std::size_t SOURCE_COUNT = 5U ;	// 元SYSと同じDriver Storeの四つの元媒体です
	const auto			  invalid =
		// 媒体の結合ができない場合の診断です
		nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	// 元コピーの分母にないファイルを閉包へ加えません
	if( copies.size() != SOURCE_COUNT) {
		return invalid ;
	}

	std::array<OfficialMappedFile, SOURCE_COUNT>
					   members ;	// CAT照合からPE読取りまで元の五媒体を固定します
	OfficialMappedFile catalog ;	// 同じ原CATを署名再検査と元媒体照合の間に固定します
	const auto		   pin = [&]( std::wstring_view source, OfficialMappedFile &fixed) {
		const auto member = std::ranges::find_if( entries, [&]( const auto &entry) {
			return stringsEqual( entry.relativePath, source) ;
		}) ; // 元書庫の完全な相対位置です
		// 別名や未署名の元候補を既知の書庫の位置にはめ込みません
		if( member == entries.end() || member->sha256.size() != 64U) {
			return invalid ;
		}

		const auto path = workspace.path( member->relativePath) ;	// 同じ保護領域内だけの元位置です
		const auto error =
			// 同じ元file全体の読取固定です
			fixed.open( path, MAXIMUM_PROPERTY_PAGE_DLL_BYTES) ;
		return error != 0U
						   ? error
						   : verifyOfficialFileMetadata( path, {member->uncompressedSize, member->sha256}) ;
	} ; // 元書庫の照合値を同期借用します

	auto error = pin( package.catalogRelativePath, catalog) ;	// 同じ原書庫のCATを固定しました
	// 書庫と一致しない元CATから同梱媒体を認定しません
	if( error != 0U) {
		return error ;
	}

	std::array<CollectorPeFile, 4U> files ;			// 同じDIRID 13に入る元PEの名前と読取範囲です
	std::size_t						fileCount{} ;	// 同じDriver Storeの元PEの観測数です
	// 各媒体を元コピーの位置で固定し、同じDriver StoreのPEだけを依存検査へ渡します
	for( std::size_t index = 0U; index < copies.size(); ++index) {
		const auto &copy = copies[index] ;	// 同じ元選択の一コピーです
		error			 = pin( copy.source, members[index]) ;
		// 不明な元ファイルを同じ名前の別媒体で補完しません
		if( error != 0U) {
			return error ;
		}

		// カーネルSYSは元CATの分母に残し、補助EXEの依存名としては使用しません
		if( copy.dirid == 13) {
			constexpr std::wstring_view DIRECTORY =
				L".\\" ;	// SetupAPIが返す同じDriver Storeの配置です
			// 別配置や元ファイル数の矛盾を名前の一致から採用しません
			if( fileCount >= files.size() || !copy.target.starts_with( DIRECTORY)) {
				return invalid ;
			}

			files[fileCount++] = {std::wstring_view{copy.target}.substr( DIRECTORY.size()),
								  members[index].bytes()} ;
		}
	}

	// 同じ元CATと全媒体を固定したまま元INF署名と同じカタログメンバーを確認します
	if( fileCount != files.size()) {
		return invalid ;
	}

	error = verifyWindowsInfPackageIntegrity( workspace, package) ;
	return error != 0U ? error : inspectScopedUsbWirelessPeImports( files) ;
}

/** @brief 同じ選択の検査済み元コピー用途です */
struct ScopedNetworkSource {
	/// 実バイトと元CATを確認するワークスペース内の元位置です
	std::wstring relativePath ;
	/// SYSまたはDLLのため同じ実体にAMD64形式も求める場合trueです
	bool		 requiresAmd64{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 公式NetのイベントSYSと付随する検証済みコピーを同じ元起点へ結ぶ
 * @param[in] inf 元署名とハッシュを確認した同じ読取専用INF
 * @param[in] workspace 元ファイルの保護領域
 * @param[in] entries 実ハッシュ付きの元抽出一覧
 * @param[in] package 検査済みの元INFと媒体集合
 * @param[in] install 公式対象から選ばれた一つの導入起点の作用棚卸し
 * @param[in] systemDirectory 収集側WindowsのGetSystemDirectoryWの実値
 * @param[out] sources 元SYSを先頭とする検査対象媒体の位置と用途です。失敗時は使用しません
 * @param[out] complete 起点の全ファイル用途が同じ検証に結び付いた場合true
 * @param[in] originalBytes 同じHINFの固定元INFです。USBの引用符を元バイトで照合します
 * @return 型・元参照と配置の照合成功は0、未対応または媒体エラーはHRESULT
 */
//------------------------------------------------------------------------------
NativeError bindScopedNetworkEventSources( HINF inf, const OfficialDownloadWorkspace &workspace,
										  std::span<const OfficialZipEntry>		entries,
										  const OfficialInfPackage			   &package,
										  const MaintenanceInfInstallStructure &install,
										  const std::wstring				   &systemDirectory,
										  std::vector<ScopedNetworkSource> &sources, bool &complete,
										  std::span<const std::byte> originalBytes = {})
{
	complete = false ;
	sources.clear() ;
	const auto &inventory	= install.inventory ;							// 同一元起点の作用・用途を保持する
	const auto	unsupported = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;	// 未確認構成の元診断
	const bool	scopedUsb =
		package.scopedModels &&
		workspace.protectionMode() == OfficialWorkspaceMode::CURRENT_USER_INSPECTION &&
		std::ranges::any_of( package.scopedModels->sections, [&]( const auto &section) {
			return std::ranges::any_of( section.matches, [&]( const auto &match) {
				return stringsEqual( match.installBase, inventory.baseInstallSection) &&
					   stringsEqual( std::wstring_view{match.hardwareId}.substr( 0U, 8U),
									L"USB\\VID_") ;
			}) ;
		}) ; // 公式対象のUSB無線導入節を検査する場合trueです
	// 公式USBの同じ導入節だけを検査し、既存のPCI経路へ混ぜません
	if( scopedUsb && install.services.size() == 2U && package.sourceFiles.size() == 5U &&
	   readScopedNetworkAttributes( inf, inventory.selectedInstallSection, USB_WIRELESS_VALUES)) {
		std::vector<WindowsDriverCopy>	   bound ;	// 同じ選択の確認済みコピーです
		std::vector<MaintenanceInfFileUse> uses ;	// 元コピーの照合結果です
		// 同じ元媒体の限定USB無線コピーを導入作用へ照合した診断値
		auto error = bindScopedUsbWirelessCopies( inf, workspace, entries, package, inventory,
												 systemDirectory, bound, uses) ;
		// 元コピーの失敗は保持し、別の媒体でサービスの起動値を構成しません
		if( error != 0U) {
			return error ;
		}

		// 二サービスと同じ選択の残りの作用のいずれかに不足があれば照合を終えます
		if( !bindScopedUsbWirelessServices( inf, install, originalBytes, bound, uses) ||
		   !bindScopedUsbWirelessEffects( inf, install, uses)) {
			return unsupported ;
		}

		error = verifyScopedUsbWirelessPe( workspace, entries, package, bound) ;
		// 補助EXEの直接依存を同じ元閉包に結べなければ検査済みの範囲を広げません
		if( error != 0U) {
			return error ;
		}

		// 元カーネルSYSを先頭に、全元媒体を後続検査へ渡します
		for( const auto dirid : {12, 13}) {
			// 照合済みの各コピーを走査し、元媒体に結び付いた配置だけを追加します
			for( auto &copy : bound) {
				// この配置に属する同じ元媒体だけを追加します
				if( copy.dirid == dirid) {
					sources.push_back( {std::move( copy.source), true}) ;
				}
			}
		}

		complete = true ;
		return 0U ;
	}

	// 同じ元起点にある名前付きコピーの参照を同期中だけ借用する
	auto	   copies	 = inventory.references | std::views::filter( []( const auto &reference) {
					   return stringsEqual( reference.directive, L"CopyFiles") ;
				   }) ;
	const bool wifiBus	 = install.wifiBusNeedsVerified ;	// 同じ元選択へ結んだ同梱依存の検査結果
	const auto listCount = std::ranges::distance( copies) ;	// 公式選択の明示コピー参照の数です
	const bool singleListDat =
		workspace.protectionMode() == OfficialWorkspaceMode::CURRENT_USER_INSPECTION &&
		listCount == 1 && package.sourceFiles.size() == 2U &&
		std::ranges::any_of( package.sourceFiles, []( const auto &source) {
			return lowerExtension( source) == L".dat" ;
		}) ; // 収集の二媒体にあるDATを実コピーに結びます
	const bool singleListWireless =
		// 同梱形または物理無線の二媒体を検査します
		listCount == 1 && (wifiBus || singleListDat) ;
	const auto hardware =
		inventory.selectedInstallSection + L".HW" ;	// 同梱旧名を要求する元選択のHW節
	const bool singleLegacySys =
		singleListWireless && wifiBus &&
		workspace.protectionMode() == OfficialWorkspaceMode::CURRENT_USER_INSPECTION &&
		package.sourceFiles.size() == 1U &&
		lowerExtension( package.sourceFiles.front()) == L".sys" &&
		std::ranges::count_if( inventory.references, [&]( const auto &reference) {
			return reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
				   !reference.targetPresent && stringsEqual( reference.section, hardware) &&
				   stringsEqual( reference.directive, L"Needs") &&
				   stringsEqual( reference.target, L"VWiFiBus.PnPFilterRegistration") ;
		}) == 1 ; // 同梱旧名の実依存と単一SYSを持つ私有収集です
	const std::size_t singleFileCount =
		singleLegacySys ? 1U : 2U ;							// 明示単一リストで照合する元媒体数
	const bool wireless = wifiBus || singleListWireless ;	// 元の物理無線属性の検査を要する形です
	const bool extraAttributes =
		workspace.protectionMode() == OfficialWorkspaceMode::CURRENT_USER_INSPECTION &&
		readScopedWirelessInterfaceAttributes(
			inf, inventory.selectedInstallSection) ;	// 追加属性を読み取る収集構成です
	// 検査済みの同梱依存と物理無線の両条件を別に扱い、元リストの追加削除や名前変更を許可しません
	if( (wireless &&
		!readScopedNetworkAttributes( inf, inventory.selectedInstallSection, PCI_WIRELESS_VALUES)) ||
	   listCount != (wifiBus && !singleListWireless ? 2 : 1) || install.services.size() != 1U ||
	   std::ranges::any_of( inventory.effects, []( const auto &effect) {
		   return stringsEqual( effect.directive, L"DelFiles") ||
				  stringsEqual( effect.directive, L"RenFiles") ;
	   })) {
		return unsupported ;
	}

	// 追加属性の照合を別の媒体構成へ拡張しない
	if( extraAttributes && !singleListDat) {
		return unsupported ;
	}

	// 単一リスト形では同CAT内の余分な媒体や同じ選択の未評価作用を加えません
	if( singleListWireless &&
	   (package.sourceFiles.size() != singleFileCount ||
		(!wifiBus &&
		 std::ranges::any_of( inventory.references,
							 []( const auto &reference) {
								 return reference.kind ==
											OfficialInfInstallReferenceKind::INCLUDE_INF ||
										stringsEqual( reference.directive, L"Needs") ;
							 })) ||
		std::ranges::any_of( inventory.effects, []( const auto &effect) {
			return effect.kind != OfficialInfInstallEffectKind::STANDARD_DIRECTIVE &&
				   !(effect.kind == OfficialInfInstallEffectKind::EXPLICIT_DEPENDENCY &&
					 (stringsEqual( effect.directive, L"Include") ||
					  stringsEqual( effect.directive, L"Needs"))) ;
		}))) {
		return unsupported ;
	}

	// 個別設定の範囲を証明できない削除があれば、この新しい媒体構成を受理しません
	if( singleListWireless) {
		const auto error =
			// 同じ基本節が所有する元削除です
			checkScopedWirelessDeletes( inf, inventory) ;
		// 元の不明な削除をファイル検査の成功で上書きしません
		if( error != 0U) {
			return error ;
		}
	}

	const auto &service = install.services.front() ;	// 同起点の唯一の関連サービス
	const auto	serviceSection =
		inventory.selectedInstallSection + L".Services" ;	// 同じ起点のサービス節
	// 元関連サービスと検査済み同梱依存の形を固定する
	if( !stringsEqual( service.section, serviceSection) || service.fieldCount != 4U ||
	   service.flags != 2U || service.serviceName.empty() || service.eventLogSection.empty() ||
	   service.parser.state != MaintenanceInspectionState::PASSED ||
	   SetupGetLineCountW( inf, serviceSection.c_str()) != (wifiBus ? 3L : 1L)) {
		return unsupported ;
	}

	std::vector<WindowsDriverCopy>	   bound ;		// 一起点だけの元媒体と宛先
	std::vector<MaintenanceInfFileUse> covered ;	// 起点の全ファイル用途に照合する元宣言
	const ScopedNetworkCopyListRule	   rule{
		   wireless && !singleLegacySys ? 2L : 1L, singleListWireless ? 12U : 0U,
		singleLegacySys ? COPYFLG_NOSKIP | COPYFLG_NOVERSIONCHECK : COPYFLG_NOSKIP,
		singleLegacySys} ;	// 従来のネットワーク構成の元コピー条件です
	// 全名前付きコピーを同じ起点から確認する
	for( const auto &copy : copies) {
		// 他の付随節のコピーを基本節のコピーへ帰属させない
		if( !stringsEqual( copy.section, inventory.selectedInstallSection)) {
			return unsupported ;
		}

		const auto error = bindScopedNetworkCopyList( inf, workspace, entries, package, copy, rule,
													 bound, covered) ;	// 全元コピーの照合
		// 一節の失敗を別節の成功で上書きしない
		if( error != 0) {
			return error ;
		}
	}

	const auto pathLeaf = []( const std::wstring &path) {
		return path.substr( path.find_last_of( L'\\') + 1U) ;
	} ; // 検査済みWindows宛先から非所有参照を残さずファイル名を得る
	// 元のコピー型と完全宛先を機能ごとに照合する
	const auto findCopy = [&]( int dirid, std::wstring_view extension,
							  const std::wstring &directory) {
		return std::ranges::find_if( bound, [&]( const auto &copy) {
			return copy.dirid == dirid && lowerExtension( copy.target) == extension &&
				   stringsEqual( copy.target, directory + L"\\" + pathLeaf( copy.target)) ;
		}) ;
	} ; // 全元コピーとその確定宛先を同期借用する
	const auto	  driverDirectory = systemDirectory + L"\\drivers" ;			// DIRID 12の完全宛先
	const auto	  driver		  = findCopy( 12, L".sys", driverDirectory) ;	// 元イベントのSYS
	std::uint32_t type{} ;														// 元の関連サービス種別
	std::wstring  binary, registry ;											// 元のサービスバイナリとイベント登録節
	// コピーがなければ元サービスやイベント先を推定しません
	if( bound.size() != (singleListWireless ? singleFileCount
						: wifiBus		   ? 3U
										   : 1U) ||
	   driver == bound.end()) {
		return unsupported ;
	}

	auto eventFiles = singleListWireless ? std::wstring{L"%SystemRoot%\\System32\\netevent.dll"}
										 : driverEventFileValue( L"netevent.dll",
																// 元イベント資源の全値です
																pathLeaf( driver->target)) ;
	// 実カーネルサービスとイベントを同じコピー先のSYSへ結ぶ
	if( readRequiredServiceScalar( inf, service.serviceInstallSection, L"ServiceType", type) != 0 ||
	   type != 1U ||
	   readRequiredServiceField( inf, service.serviceInstallSection, L"ServiceBinary", binary) !=
		   0 ||
	   !boundWindowsServiceBinary( binary, bound, true)) {
		return unsupported ;
	}

	// 同梱旧名を使う単一SYSは要求時起動と通常の失敗時制御を元サービスで照合する
	if( singleLegacySys) {
		std::uint32_t start{} ;		// 元の起動種別
		std::uint32_t control{} ;	// 元の失敗時制御
		// 起動サービスや曖昧な複数値を既知の収集形へ加えない
		if( readRequiredServiceScalar( inf, service.serviceInstallSection, L"StartType", start) !=
			   0U ||
		   start != 3U ||
		   readRequiredServiceScalar( inf, service.serviceInstallSection, L"ErrorControl",
									 control) != 0U ||
		   control != 1U) {
			return unsupported ;
		}
	}

	// 機器および共有設定は同じSYSの関連サービスを確定してから照合する
	if( (singleListDat || singleLegacySys) &&
	   !checkScopedWirelessRegistry( inf, inventory, service.serviceName, extraAttributes)) {
		return unsupported ;
	}

	// 同じ有線Netの二資源に最後の区切りだけがある場合は、元表記のまま全値を照合する
	if( !checkSystemDriverEventLog( inf, service.eventLogSection, eventFiles, &registry)) {
		eventFiles.push_back( L';') ;
		// 末尾一箇所の違いに限定し、追加資源や無線LANの別構成を受け入れない
		if( wireless ||
		   !checkSystemDriverEventLog( inf, service.eventLogSection, eventFiles, &registry)) {
			return unsupported ;
		}
	}

	// 同じ起点内でイベント節とイベント登録節を別のサービスやHKR文脈に兼用させない
	if( std::ranges::count_if( inventory.references, [&]( const auto &reference) {
		   return reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
				  (stringsEqual( reference.target, service.eventLogSection) ||
				   stringsEqual( reference.target, registry)) ;
	   }) != 2) {
		return unsupported ;
	}

	covered.push_back( {service.section, L"AddService", service.serviceName}) ;
	covered.push_back( {service.serviceInstallSection, L"ServiceBinary", binary}) ;
	covered.push_back( {registry, L"RegistryFileUseNotAssessed", eventFiles}) ;
	sources.push_back( {driver->source, true}) ;
	// 一つの名前付きコピーにある補助データを、同じDIRID 12と同元CATへ結びます
	if( singleListWireless && !singleLegacySys) {
		const auto data = findCopy( 12, singleListDat ? L".dat" : L".txt",
								   driverDirectory) ;	// 同じ元リストの補助データです
		// 別ディレクトリ、別形式、別の実体を補助データとして束縛しません
		if( data == bound.end()) {
			return unsupported ;
		}

		sources.push_back( {data->source, false}) ;
	}
	// 複数リスト形では補助データと拡張DLLへの唯一の登録を維持します
	else if( wifiBus && !singleLegacySys) {
		const auto data = findCopy( 12, L".dat", driverDirectory) ;	// カーネルSYSと同配置の補助データ
		const auto extension =
			// Windows System32の無線LAN拡張
			findCopy( 11, L".dll", systemDirectory) ;
		// 未知のファイルや別配置へのDLL登録を閉包の一部にしない
		if( data == bound.end() || extension == bound.end() ||
		   !bindScopedWirelessExtension( inf, install, pathLeaf( extension->target), covered)) {
			return unsupported ;
		}

		sources.push_back( {data->source, false}) ;
		sources.push_back( {extension->source, true}) ;
	}

	// 両方の無線構成で、別HKR文脈の文字列を既知の表示用途として扱いません
	if( wireless) {
		// 完全な元行で型を確定し、同じ基本節の一意なAddRegから参照されたラベルだけを照合済みにする
		for( const auto &use : install.fileUses) {
			// 他の未確認データやサービス文脈の表示用途は全参照の未完了として残す
			if( stringsEqual( use.directive, WIRELESS_PARAMETER_LABEL) &&
			   std::ranges::count_if(
				   inventory.references,
				   [&]( const auto &reference) {
					   return reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
							  stringsEqual( reference.target, use.section) ;
				   }) == 1 &&
			   std::ranges::any_of( inventory.references, [&]( const auto &reference) {
				   return reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
						  reference.targetPresent && stringsEqual( reference.directive, L"AddReg") &&
						  stringsEqual( reference.section, inventory.selectedInstallSection) &&
						  stringsEqual( reference.target, use.section) ;
			   })) {
				covered.push_back( use) ;
			}
		}
	}

	auto observedUses =
		install.fileUses | std::views::filter( [&]( const auto &use) {
			return singleListWireless || !stringsEqual( use.directive, WIRELESS_BARE_REGISTRY_FILE) ;
		}) ; // 旧形の従来分母は追加した裸の媒体用途を含めません
	// 同じ起点で結合済みの用途だけを数え、追加用途や別型の不足を保持する
	complete =
		install.parser.state == MaintenanceInspectionState::PASSED &&
		std::ranges::distance( observedUses) == static_cast<std::ptrdiff_t>( covered.size()) &&
		std::ranges::all_of( covered,
							[&]( const auto &expected) {
								return std::ranges::count_if( observedUses, [&]( const auto &actual) {
										   return stringsEqual( actual.section, expected.section) &&
												  stringsEqual( actual.directive,
															   expected.directive) &&
												  stringsEqual( actual.target, expected.target) ;
									   }) == 1 ;
							}) &&
		std::ranges::all_of(
			inventory.coverageGaps,
			[]( const auto &gap) {
				return gap.kind == OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED ||
					   gap.kind == OfficialInfInstallCoverageKind::UNFOLLOWED_SERVICE_EVENTLOG ;
			}) &&
		SetupGetLineCountW( inf, (inventory.selectedInstallSection + L".Filters").c_str()) < 0L &&
		SetupGetLineCountW( inf, (inventory.selectedInstallSection + L".FactDef").c_str()) < 0L ;
	return 0 ;
}
} // namespace

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 現OSの元ModelsでWindows互換ノードの基本節と順序付きID列を一意に照合する
 * @param[in] inf 保持済み元INFの読取りhandle
 * @param[in] package 完全な元公開IDを持つ共通内容検査のmetadata
 * @param[in] modelsSection 元署名レコードのModels節
 * @param[in] basicSection Windowsが選択した基本導入節
 * @param[in] nodeIds nodeの元Hardware IDとCompatible ID。同期中だけ借用する
 * @return 元の一行に完全一致すれば0、それ以外は最初の元HRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyCurrentInfModelsRow( const HINF inf, const OfficialInfPackage &package,
									  const std::wstring		   &modelsSection,
									  std::wstring_view				basicSection,
									  std::span<const std::wstring> nodeIds)
{
	std::vector<std::wstring>					  ids ;		// 元の型付きModels集計と同順の全ID
	std::vector<OfficialInfPublishedModelSection> models ;	// Windowsが選んだ現在OSの元Models
	// 同じINFの現在OS向けModelsを元ID列と共に読み込んだ診断値
	const auto error = collectHardwareIds( inf, 4096U, ids, &models) ;
	// 現在OSが選ばない元Modelsを外部から指定させない
	if( error != 0 || ids != package.hardwareIds ||
	   std::ranges::count_if( models, [&]( const auto &model) {
		   return stringsEqual( model.modelSection, modelsSection) ;
	   }) != 1) {
		return error != 0 ? error : nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
	}

	const auto rowCount =
		// 現在OSの元Models行数
		SetupGetLineCountW( inf, modelsSection.c_str()) ;
	// Windowsが選ぶ節の全行を有限に確定する
	if( rowCount <= 0L || static_cast<std::size_t>( rowCount) > MAXIMUM_INSTALL_INVENTORY_LINES) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::size_t matched{} ;	// 一致する元Models行数
	// 記載順が同じ型付きID列と、Windowsの基本節名の両方を照合する
	for( LONG offset = 0L; offset < rowCount; ++offset) {
		INFCONTEXT	 row{} ;	// 現在OSの元Modelsの一行
		std::wstring original ;	// 原行が指定するDDInstall基本名
		// 元フィールドの読み取り失敗を部分結果へ丸めない
		if( !SetupGetLineByIndexW( inf, modelsSection.c_str(), static_cast<DWORD>( offset), &row) ||
		   readInfField( row, 1U, original) != 0) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 他の導入節やID数が異なる行を先頭一致だけで選ばない
		if( !stringsEqual( original, basicSection) ||
		   SetupGetFieldCount( &row) != nodeIds.size() + 1U) {
			continue ;
		}

		bool exact = true ;	// 同じ元行の全IDが一致した状態
		// 第2fieldはHardware ID、第3field以降はCompatible IDとして位置を保つ
		for( std::size_t index = 0U; index < nodeIds.size(); ++index) {
			std::wstring id ;	// 原順の現在ID
			// 欠損は空の識別子に読み替えない
			if( readInfField( row, static_cast<DWORD>( index + 2U), id) != 0) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			exact = exact && stringsEqual( id, nodeIds[index]) ;
		}

		matched += exact ? 1U : 0U ;
	}

	// 二つ以上の元行が完全一致した場合も一意の選択にしない
	if( matched != 1U) {
		return nativeErrorFromWin32( matched == 0U ? ERROR_NOT_FOUND : ERROR_DUP_NAME) ;
	}

	return 0U ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief ストレージのWindows実選択を固定した元INFの現在OS用Modelsの一行へ照合する
 * @param[in] workspace 原閉包の管理者保護領域
 * @param[in] entries 元閉包のファイルと原サイズ・SHA-256
 * @param[in] package 内容検査済みの元ストレージ基本INF
 * @param[in] modelsSection 元署名レコードの現在OS用Models節
 * @param[in] basicSection Windowsの実選択ノードが返した未修飾DDInstall
 * @param[in] nodeIds 同ノードの主Hardware IDと元順の全Compatible ID
 * @return 同じ原バイトと一意な元行が成立すれば0、失敗時はHRESULT
 * @pre 呼出し側で同じ元閉包のCAT署名と元レコードの端末範囲を確認する
 * @note 読取りだけを行う。端末の順位、作用、変更の資格は別に確認する
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialStorageInfModelSelection( const OfficialDownloadWorkspace	&workspace,
												   std::span<const OfficialZipEntry> entries,
												   const OfficialInfPackage			&package,
												   std::wstring_view				 modelsSection,
												   std::wstring_view				 basicSection,
												   std::span<const std::wstring>	 nodeIds)
{
	// 管理者領域の同じ基本INFだけを使い、欠損や過大な選択は照合しない
	if( workspace.protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR ||
	   package.inspectionPurpose != OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ||
	   package.role != DriverPlanRole::BASE_DRIVER || package.requiredNullCompanion ||
	   package.requiredRegistryOnlyCompanion || entries.empty() || entries.size() > 32'768U ||
	   !validInstallInventorySectionName( modelsSection) ||
	   !validInstallInventorySectionName( basicSection) || nodeIds.empty() || nodeIds.size() > 63U ||
	   !std::ranges::all_of( nodeIds, validNativeModelsId)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto isSource = [&package]( const OfficialZipEntry &entry) {
			return stringsEqual( entry.relativePath, package.infRelativePath) ;
		} ; // 同じ保護領域で検査済みの元INF名だけを同期中に照合する
		const auto entry = std::ranges::find_if( entries, isSource) ;	// 元のサイズとハッシュ
		const auto path	 = workspace.path( package.infRelativePath) ;	// 同保護領域内の元ファイル
		// 閉包の同名重複や検査根拠がないファイルを元Models照合に使わない
		if( path.empty() || entry == entries.end() || entry->uncompressedSize == 0U ||
		   entry->sha256.size() != 64U || std::ranges::count_if( entries, isSource) != 1) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		OfficialMappedFile pinned ;											// 読取り完了まで同じ元ファイルと親の置換を防ぐ
		auto			   error = pinned.open( path, 4U * 1024U * 1024U) ;	// 固定時の元HRESULT
		// ファイルを固定してから元サイズとハッシュを確認する
		if( error == 0U) {
			error = verifyOfficialFileMetadata( path, {entry->uncompressedSize, entry->sha256}) ;
		}

		// 元バイトの同一性が成立するまでSetupAPIで節を読まない
		if( error != 0U) {
			return error ;
		}

		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 固定した元INFの読取りハンドル
		// 元APIの失敗を一意な行の検出へ変換しない
		if( inf.get() == INVALID_HANDLE_VALUE) {
			const auto openError = GetLastError() ;	// SetupAPIの直後に読む原診断
			return nativeErrorFromWin32( openError ? openError : ERROR_INVALID_DATA) ;
		}

		return verifyCurrentInfModelsRow( inf.get(), package, std::wstring( modelsSection),
										 basicSection, nodeIds) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元INFの現在OS用Modelsと互換nodeの基本節・全IDを照合し、必要時は初回クラス登録を読む
 * @param[in] workspace 検査済みの元ファイルを所有する保護領域
 * @param[in] package 端末の独自クラス内容検査で得た元閉包のmetadata
 * @param[in] expectedSha256 Models照合時の元INFハッシュ
 * @param[in] modelsSection 元recordが使用する現在OS用Models節
 * @param[in] basicSection Windows互換nodeが返したDDInstall基本名
 * @param[in] nodeIds 元nodeのHardware IDと順序付きCompatible ID
 * @param[out] role 元行の処理まで確定した場合の作用
 * @param[out] classRegistration 任意の出力先。実ドライバーで確認できた元クラス登録だけを渡す
 * @return 一意な原行と作用を確認した場合0、失敗はHRESULT
 * @note 原行と必要ファイルの読み取りだけを行い、導入資格を発行しない
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialInfSelectedModelRole(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	std::wstring_view expectedSha256, const std::wstring &modelsSection,
	const std::wstring &basicSection, std::span<const std::wstring> nodeIds,
	OfficialInfSelectedModelRole						   &role,
	std::optional<OfficialInfDeclarativeClassRegistration> *classRegistration)
{
	role = OfficialInfSelectedModelRole::UNASSESSED ;
	// 失敗や空サービスの結果に以前の計画を残さない
	if( classRegistration) {
		classRegistration->reset() ;
	}

	// 読み取り用途で検査済みの元閉包と、完全なnode識別を要求する
	if( package.inspectionPurpose != OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ||
	   expectedSha256.size() != 64U || !validInstallInventorySectionName( modelsSection) ||
	   !validInstallInventorySectionName( basicSection) || nodeIds.empty() || nodeIds.size() > 63U) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto	 path = workspace.path( package.infRelativePath) ;	// 同保護領域の元INF
		std::wstring hash ;												// 元INFの前後読取ハッシュ
		auto		 error = computeFileSha256( path, hash) ;			// 読み取り前の元INFを固定する
		// 同じ取得の別INFや変更後の原データを使わない
		if( error != 0 || hash != expectedSha256) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_CRC) ;
		}

		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 元INFの読取ハンドル
		// 元INFが読めない場合は端末の観測だけで補わない
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 実互換nodeを現在OSで選ばれた元Modelsの一行へ結ぶ
		error = verifyCurrentInfModelsRow( inf.get(), package, modelsSection, basicSection, nodeIds) ;
		// 元行が一意に決まらない場合は作用を評価しない
		if( error != 0U) {
			return error ;
		}

		const auto separator = package.infRelativePath.find_last_of( L'\\') ;	// 元INFの配置
		const auto parent =
			separator == package.infRelativePath.npos
				? std::wstring_view{}
				: std::wstring_view( package.infRelativePath).substr( 0U, separator) ;	// 同じ配置の親
		std::wstring			  install ;												// Windowsが解決した実在する導入節
		std::vector<std::wstring> sources ;												// 同じ元INFが必要とするコピー元
		// 内容検査の元閉包と、全AMD64候補の既知の作用を再確認する
		if( resolveActualInstallInventorySection( inf.get(), basicSection, install) != 0 ||
		   !collectProvenAmd64Sources( inf.get(), parent, true, sources) ||
		   std::ranges::any_of( sources, [&]( const auto &source) {
			   return std::ranges::none_of( package.sourceFiles, [&]( const auto &present) {
				   return stringsEqual( present, source) ;
			   }) ;
		   })) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		const auto selectedLines =
			// 証明済みの実導入行数
			SetupGetLineCountW( inf.get(), install.c_str()) ;
		// 実ドライバーの行は同じコピーに結合した関連サービスが一つの場合だけ扱う
		if( selectedLines > 0L) {
			INFCONTEXT service{} ;							// 同じDDInstallの元AddService
			const auto services = install + L".Services" ;	// 証明済みの同サービス節
			// 関連サービスの元宣言が消えた場合は未評価とする
			if( !SetupFindFirstLineW( inf.get(), services.c_str(), L"AddService", &service)) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			std::size_t associated{} ;	// 同deviceに関連付けるサービスの件数
			// 最初のサービスで判定せず、元AddServiceの全行を対象にする
			do {
				int flags{} ;	// Windowsが解釈する元flags
				// 元flagsを取得できない行を対象なしへ丸めない
				if( !SetupGetIntField( &service, 2U, &flags)) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				associated += (flags & SPSVCINST_ASSOCSERVICE) != 0 ? 1U : 0U ;
			} while( SetupFindNextMatchLineW( &service, L"AddService", &service)) ;

			// 複数を一件へ選び直さず、関連の欠損も許可しない
			if( associated != 1U) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}
		}

		std::optional<OfficialInfDeclarativeClassRegistration>
			registration ;	// 後続hash確認前の元クラス表示情報
		// 空サービスにクラス登録計画を発行せず、実ドライバーの同一INFからだけ読む
		if( selectedLines > 0L && classRegistration) {
			std::wstring guid ;	// 元クラス節を確認した同じINFのClassGUID
			error = inspectDeclarativeSetupClass( inf.get(), path, package.className, guid,
												 &registration.emplace()) ;
			// 先行内容検査と同じ元クラスに結び付いた値だけを保持する
			if( error != 0U || !stringsEqual( guid, package.classGuid)) {
				return error != 0U ? error : nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
			}
		}

		error = computeFileSha256( path, hash) ;
		// 読み取り中に変更された元INFや消えた節を作用判定へ渡さない
		if( error != 0 || hash != expectedSha256 || selectedLines < 0L) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_CRC) ;
		}

		role = selectedLines == 0L ? OfficialInfSelectedModelRole::NULL_DRIVER
								   : OfficialInfSelectedModelRole::KERNEL_DRIVER ;
		// 前後で一致した元ハッシュと表示値を一組で渡す
		if( registration) {
			registration->infSha256 = std::move( hash) ;
			*classRegistration		= std::move( registration) ;
		}

		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 選択元INFのWindows管理driver package範囲を非実行で再検査します
 * @param[in] workspace 全内容検査済み元fileを所有する保護領域です
 * @param[in] entries 全原参照のsize/hash付き閉包です。CAT検証は呼出側が別に要求します
 * @param[in] selected native compatible nodeから選んだ原DDInstall関係です
 * @param[out] diagnostic 任意の最初の固定拒否です。合否に使いません
 * @return 選択copy/source/Windows宛先/関連service/softwareの結合成功0、それ以外はHRESULTです
 * @note 本関数は実行能力を持ちません。元byte/CAT再検証後の私有factoryから使用します。vendor内部作用やDisplay Type1のWindows実行対応を証明せず、元未評
 *       価flagも変更しません
 */
//------------------------------------------------------------------------------
NativeError inspectSelectedWindowsDriverPackageScope( const OfficialDownloadWorkspace  &workspace,
													 std::span<const OfficialZipEntry> entries,
													 const OfficialInfPackage		  &selected,
													 RequiredInfBindingDiagnostic	  *diagnostic)
{
	try {
		OfficialInfPackage actual ;	// 同元実DDInstallの関係を公開DTOと独立して読み直します
		auto			   error = inspectSelectedOfficialInfRelations( workspace, entries, selected,
																	   selected.selectedBasicSection,
																	   actual) ;	// 同native基本名の実関係診断です
		// 元選択の必要INF/Componentを任意の空集合や別節へ差し替えません
		if( error != 0 || actual.selectedInstallSection != selected.selectedInstallSection ||
		   actual.activeRequiredInfPaths != selected.activeRequiredInfPaths ||
		   actual.requiredComponents != selected.requiredComponents) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		const UniqueInf inf( SetupOpenInfFileW( workspace.path( selected.infRelativePath).c_str(),
											  nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 元INFだけのread-only handleです
		// 同元byteを開けない場合は元Windows診断を維持します
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		OfficialInfInstallInventory inventory ;	// 実選択の正式copy/service/software関係だけです
		error = readWindowsDriverScopeReferences( inf.get(), selected, inventory) ;
		// 棚卸し成功や公開DTOを実選択関係の代わりにしません
		if( error != 0) {
			return error ;
		}

		std::vector<WindowsDriverCopy> copies ;	// DATAコピーと実行操作を分離する元位置証拠です
		// 実選択graphの全CopyFilesを読み、非選択全sourceの内容検査とは分けます
		for( const auto &reference : inventory.references) {
			// 外部依存の効果充足は既存Needs検査で扱います
			if( !stringsEqual( reference.directive, L"CopyFiles")) {
				continue ;
			}

			// 欠損listを空コピー成功へ変換しません
			if( !reference.targetPresent) {
				return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
			}

			// 直接コピーも原source/既定宛先へ結びます
			if( reference.kind == OfficialInfInstallReferenceKind::DIRECT_FILE) {
				const auto separator =
					// 元参照のleaf境界です
					reference.target.find_last_of( L'\\') ;
				const auto name = reference.target.substr(
					// 元file名です
					separator == reference.target.npos ? 0U : separator + 1U) ;
				error = bindWindowsDriverCopy( inf.get(), workspace, entries, selected, L"", name,
											  name, copies, diagnostic) ;
			} else {
				const auto count =
					// 空と不在を分けます
					SetupGetLineCountW( inf.get(), reference.target.c_str()) ;
				// 不在や過大listを部分コピー成功へ変換しません
				if( count < 0L || count > static_cast<LONG>( MAXIMUM_INSTALL_INVENTORY_LINES)) {
					return nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND) ;
				}

				// 同listの全行をWindowsの原rename/sourceのまま読みます
				for( LONG row = 0L; row < count; ++row) {
					INFCONTEXT	 line{} ;		// 同原CopyFilesの一行です
					std::wstring target ;		// 元コピー先leafです
					std::wstring source ;		// 元source leafです。空は元同名です
					std::wstring temporary ;	// 元temporary leafを外部pathへ拡張しません
					// 明示fieldの欠損/外部temporary/過大構文を先頭値で通しません
					if( !SetupGetLineByIndexW( inf.get(), reference.target.c_str(),
											 static_cast<DWORD>( row), &line) ||
					   SetupGetFieldCount( &line) > 4U || readInfField( line, 1U, target) != 0 ||
					   (SetupGetFieldCount( &line) > 1U &&
						readInstallInventoryField( line, 2U, source) != 0) ||
					   (SetupGetFieldCount( &line) > 2U &&
						(readInstallInventoryField( line, 3U, temporary) != 0 ||
						 !validRequiredServiceSubdirectory( temporary) ||
						 temporary.find( L'\\') != temporary.npos))) {
						return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					error = bindWindowsDriverCopy(
						inf.get(), workspace, entries, selected, reference.target, target,
						source.empty() ? target : source, copies, diagnostic) ;
					// 一原コピーの不成立で通常scope全体を拒否します
					if( error != 0) {
						return error ;
					}
				}
			}

			// 直接コピーの原診断も保持します
			if( error != 0) {
				return error ;
			}
		}

		std::vector<std::wstring> serviceSections ;		// 同graphの元AddService宣言節だけです
		std::vector<std::wstring> softwareSections ;	// 同graphの元AddSoftware宣言節だけです
		// 既知禁止操作と元service/softwareを選択scopeに結びます。未知metadataは無作用と認定しません
		for( const auto &effect : inventory.effects) {
			// 明示command/DLL登録/autorunは通常Windows driver scopeへ追加しません
			if( effect.kind == OfficialInfInstallEffectKind::COMMAND_EXECUTION ||
			   effect.kind == OfficialInfInstallEffectKind::DLL_REGISTRATION ||
			   effect.kind == OfficialInfInstallEffectKind::REGISTRY_AUTORUN) {
				return diagnostic ? diagnostic->reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
													   static_cast<InfBindingReject>( 200U + 0U))
								  : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// 同service節の重複行を一走査へまとめ、全AddService行を後段で読みます
			if( stringsEqual( effect.directive, L"AddService")) {
				static_cast<void>( appendUnique( serviceSections, effect.section)) ;
			}

			// 全AddSoftware行を同様に保持し、先頭だけを採用しません
			if( stringsEqual( effect.directive, L"AddSoftware")) {
				static_cast<void>( appendUnique( softwareSections, effect.section)) ;
			}
		}

		std::size_t associatedKernels{} ;	// 同選択の原関連SYSだけです
		std::size_t win32Services{} ;		// 原コピーへ結合したWindows-managed service数です
		std::size_t services{} ;			// 全named serviceの有限数です
		bool		namedStorageEvent{} ;	// Systemのイベント源を明示する補助サービスを読んだか
		// 原selected graphの全serviceを同元source/完全宛先へ結びます
		for( const auto &section : serviceSections) {
			INFCONTEXT line{} ;	// 同節の全元AddService行です
			// inventoryの元宣言が不在へ変わった場合は拒否します
			if( !SetupFindFirstLineW( inf.get(), section.c_str(), L"AddService", &line)) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			// 一つのservice成功で後続行のscopeを省略しません
			do {
				const auto fields =
					// Windowsが解析した元AddServiceの欄数
					SetupGetFieldCount( &line) ;
				std::wstring name ;		// 元service名です。外部へ出しません
				std::wstring install ;	// 同HINFの原service-install節です
				int			 flags{} ;	// Windowsが解析した原AddService flagsです
				// Null serviceは既存検査に委ね、未評価packageの認定根拠へ使いません
				if( ++services > 32U || fields < 3U || (fields > 4U && fields != 6U) ||
				   readInfField( line, 1U, name) != 0 || !SetupGetIntField( &line, 2U, &flags) ||
				   readInfField( line, 3U, install) != 0 ||
				   !validInstallInventorySectionName( install)) {
					return diagnostic
							   ? diagnostic->reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
													static_cast<InfBindingReject>( 200U + 1U))
							   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				std::uint32_t type{} ;		// 元ServiceTypeです
				std::uint32_t start{} ;		// 元StartTypeです
				std::uint32_t control{} ;	// 元ErrorControlです
				std::wstring  binary ;		// 元全path/引数を保持します
				// 必須service宣言を別節の値で補完しません
				if( readRequiredServiceScalar( inf.get(), install, L"ServiceType", type) != 0 ||
				   readRequiredServiceScalar( inf.get(), install, L"StartType", start) != 0 ||
				   start > 4U ||
				   readRequiredServiceScalar( inf.get(), install, L"ErrorControl", control) != 0 ||
				   control > 3U ||
				   readRequiredServiceField( inf.get(), install, L"ServiceBinary", binary) != 0) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				const bool kernel = type == 1U || type == 2U ;	// 元kernel/file-system serviceです
				// 6欄の選択範囲は同じSCSIAdapterの自動起動補助サービスとSystemイベントに限定します
				if( fields == 6U) {
					std::wstring eventInstall ;	// 同一INFに書かれたイベント登録節
					std::wstring eventLog ;		// 元宣言が明示したWindowsログ名
					std::wstring eventSource ;	// 同じログ内の単一イベント源名
					// 引数なし・改名なしの元Driver Storeコピーだけを数えます
					const auto	 matchingCopies =
						std::ranges::count_if( copies, [&]( const auto &copy) {
							const auto source = std::wstring_view( copy.source) ;	// 元媒体の相対位置
							const auto separator = source.find_last_of( L'\\') ;	// 元leafの直前
							// 元と宛先のleafを比較し、Driver Storeへの改名コピーを拒む
							const auto leaf =
								source.substr( separator == source.npos ? 0U : separator + 1U) ;
							const auto target =
								// Windowsが解決した宛先
								std::wstring_view( copy.target) ;
							const auto targetSeparator =
								// 宛先leafの直前
								target.find_last_of( L'\\') ;
							return copy.dirid == 13 && lowerExtension( target) == L".exe" &&
								   targetSeparator != target.npos && stringsEqual( binary, target) &&
								   stringsEqual( leaf, target.substr( targetSeparator + 1U)) ;
						}) ;

					// 別のサービス種別・ログ・節や他者のコピーを元関係の成立へ変換しません
					if( namedStorageEvent || selected.role != DriverPlanRole::BASE_DRIVER ||
					   !stringsEqual( selected.className, L"SCSIAdapter") ||
					   !stringsEqual( selected.classGuid,
									 L"{4d36e97b-e325-11ce-bfc1-08002be10318}") ||
					   !stringsEqual( section, selected.selectedInstallSection + L".Services") ||
					   flags != 0 || type != 0x10U || start != 2U || control != 1U ||
					   readInfField( line, 4U, eventInstall) != 0 ||
					   readInfField( line, 5U, eventLog) != 0 ||
					   readInfField( line, 6U, eventSource) != 0 || matchingCopies != 1 ||
					   !validNamedStorageSystemEvent( inf.get(), eventInstall, eventLog,
													 eventSource)) {
						return diagnostic
								   ? diagnostic->reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
														static_cast<InfBindingReject>( 200U + 1U))
								   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
					}

					namedStorageEvent = true ;
				}

				// 外部system launcherや別packageのbinaryへserviceを結びません
				if( (!kernel && type != 0x10U && type != 0x20U) ||
				   !boundWindowsServiceBinary( binary, copies, kernel)) {
					return diagnostic
							   ? diagnostic->reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
													static_cast<InfBindingReject>( 200U + 2U))
							   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				associatedKernels += kernel && (flags & 2) != 0 ? 1U : 0U ;
				win32Services += kernel ? 0U : 1U ;
			} while( SetupFindNextMatchLineW( &line, L"AddService", &line)) ;
		}

		// 通常deviceの付属programを独立appとして認定せず、原関連kernelとの結合を要求します
		if( (selected.role == DriverPlanRole::BASE_DRIVER &&
			(win32Services != 0U || !softwareSections.empty()) && associatedKernels != 1U) ||
		   (namedStorageEvent && (services != 2U || win32Services != 1U))) {
			return diagnostic ? diagnostic->reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
												   static_cast<InfBindingReject>( 200U + 3U))
							  : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// 元選択DDInstallの全softwareを検査し、他ModelsのType2を当該計画へ追加しません
		for( const auto &section : softwareSections) {
			INFCONTEXT line{} ;	// 同元AddSoftware全行です
			// 原宣言の消失を空scope成功にしません
			if( !SetupFindFirstLineW( inf.get(), section.c_str(), L"AddSoftware", &line)) {
				return nativeErrorFromWin32( ERROR_RETRY) ;
			}

			// duplicate keyを含む全元行をWindowsの順序のまま検査します
			do {
				std::wstring  source ;	// 元Type1の同INF/DIRID13コピーだけです
				std::wstring  install ;	// 元software-installです
				std::wstring  version ;	// 原driver版との関連を確認します
				std::wstring  binary ;	// 独立MSI/app取得へ昇格させません
				std::uint32_t type{} ;	// selected Type2は当該driver-only計画に含めません
				// 元正式コピーへ結合しないprogramやStore取得を通常driver計画へ追加しません
				if( validateRequiredSoftwareDeclaration( inf.get(), section, line, true, &source,
													   nullptr) != 0 ||
				   readInfField( line, 3U, install) != 0 ||
				   readRequiredServiceScalar( inf.get(), install, L"SoftwareType", type) != 0 ||
				   type != 1U ||
				   readRequiredServiceField( inf.get(), install, L"SoftwareVersion", version) != 0 ||
				   readRequiredServiceField( inf.get(), install, L"SoftwareBinary", binary) != 0 ||
				   lowerExtension( binary) != L".exe" || version != selected.driverVersion) {
					return diagnostic
							   ? diagnostic->reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
													static_cast<InfBindingReject>( 200U + 4U))
							   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				INFCONTEXT arguments{} ;	// Windows SoftwareArgumentsの原comma-separated listです
				INFCONTEXT duplicate{} ;	// 一宣言の複数行を任意結合しません
				// 必要なdevice文脈を原全引数で確認し、独自のcommand行を生成しません
				if( !SetupFindFirstLineW( inf.get(), install.c_str(), L"SoftwareArguments",
										&arguments) ||
				   SetupGetFieldCount( &arguments) == 0U || SetupGetFieldCount( &arguments) > 32U ||
				   SetupFindNextMatchLineW( &arguments, L"SoftwareArguments", &duplicate)) {
					return diagnostic
							   ? diagnostic->reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
													static_cast<InfBindingReject>( 200U + 5U))
							   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				bool deviceBound{} ;				// 同原宣言に正式device-instance placeholderがある事実だけです
				std::size_t argumentCharacters{} ;	// 元全引数の既存field容量を共同保持します
				// 全元引数を原順に読み、先頭一値の仮定や独自の連結/起動を行いません
				for( DWORD field = 1U; field <= SetupGetFieldCount( &arguments); ++field) {
					std::wstring value ;	// 一つの原引数です。製品から実行しません
					// 空/過大引数の部分をdevice結合成功へ変換しません
					if( readInfField( arguments, field, value) != 0 ||
					   value.size() > MAXIMUM_INF_FIELD_CHARACTERS - argumentCharacters) {
						return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
					}

					argumentCharacters += value.size() ;
					deviceBound = deviceBound || value.find( L"<<DeviceInstanceID>>") != value.npos ;
				}

				// 元device文脈に結合しない独立programを通常driver範囲へ追加しません
				if( !deviceBound) {
					return diagnostic
							   ? diagnostic->reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
													static_cast<InfBindingReject>( 200U + 6U))
							   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				// 同選択source/copyのない潜在宣言を当該driver構成へ借用しません
				if( std::ranges::none_of( copies, [&]( const auto &copy) {
					   return copy.dirid == 13 && stringsEqual( copy.source, source) &&
							  stringsEqual( copy.target, binary) ;
				   })) {
					return diagnostic
							   ? diagnostic->reject( nativeErrorFromWin32( ERROR_NOT_SUPPORTED),
													static_cast<InfBindingReject>( 200U + 7U))
							   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}
			} while( SetupFindNextMatchLineW( &line, L"AddSoftware", &line)) ;
		}

		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 元INF行の全値を省略や追加なしで読みます
 * @param[in] row 照合済みの元行。呼出し中だけ借用します
 * @param[out] fields 原順の全fieldです。失敗時の部分値は使用できません
 * @return 読取り成功0、最初の元field診断はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError readStorageInfRowFields( INFCONTEXT &row, std::vector<std::wstring> &fields)
{
	// 明示空を含む元fieldだけを順に読みます
	for( DWORD field = 1U; field <= SetupGetFieldCount( &row); ++field) {
		std::wstring value ;													// 元fieldの完全値です
		const auto	 error = readInstallInventoryField( row, field, value) ;	// 元field診断です
		// 読取失敗を明示空や省略へ置換しません
		if( error != 0U) {
			return error ;
		}

		fields.push_back( std::move( value)) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの選択節について空ドライバーのNeeds宣言と二行だけの委譲を読む
 * @param[in] inf 同期中有効な元INFの読取りhandle
 * @param[in] section 現在OSが選択した導入節または同じサービス節
 * @param[in] expectedNeeds この文脈の正確な同梱INF内の参照先
 * @param[in,out] delegates 二節のいずれかが空ドライバーのNeedsを参照するとtrueを保持する
 * @param[out] matched 元の二行がこの文脈の委譲と一致した場合true
 * @return 全行の確認または明示節の不存在は0、読取り不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readStorageNullDriverSection( HINF inf, const std::wstring &section,
										 std::wstring_view expectedNeeds, bool &delegates,
										 bool &matched)
{
	matched = false ;
	SetLastError( ERROR_SUCCESS) ;
	const auto count = SetupGetLineCountW( inf, section.c_str()) ;	// この節の全原行数
	// 任意の付随節の不存在を観測として保持し、API失敗は元診断を返す
	if( count < 0L) {
		const auto error = GetLastError() ;	// 行数照会直後のWindows診断
		return error == ERROR_SECTION_NOT_FOUND
				   ? 0U
				   : nativeErrorFromWin32( error ? error : ERROR_INVALID_DATA) ;
	}

	// 大きすぎる節から部分的な委譲を抽出しない
	if( static_cast<std::size_t>( count) > MAXIMUM_INSTALL_INVENTORY_LINES) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	bool include{} ;	// この節で正規の同梱INFを指す一欄のIncludeを確認したか
	bool needs{} ;		// この節で対応する一欄のNeedsを確認したか
	// 追加作用や重複を、最初に見つかった二行だけの一致で隠さない
	for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
		INFCONTEXT line{} ;	// 現在の原行を読む同HINFの行context
		// 一行でも読み取れなければ選択節全体の判定を止める
		if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( ordinal), &line)) {
			const auto error = GetLastError() ;	// 原行照会直後のWindows診断
			return nativeErrorFromWin32( error ? error : ERROR_INVALID_DATA) ;
		}

		std::wstring key ;													// 現在のSetupAPIが返すdirective名
		auto		 error = readInstallInventoryField( line, 0U, key) ;	// 元欄の読取り診断
		// 解析失敗を不在の作用へ変換しない
		if( error != 0U) {
			return error ;
		}

		const bool isInclude = stringsEqual( key, L"Include") ;	// 同梱INFを指定する行か
		const bool isNeeds	 = stringsEqual( key, L"Needs") ;	// 同梱の作用を要求する行か
		// これ以外の行は原件数に残し、委譲の作用へ数えない
		if( !isInclude && !isNeeds) {
			continue ;
		}

		// 多過ぎる参照を先頭の既知値だけへ縮約しない
		if( SetupGetFieldCount( &line) > 32U) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::vector<std::wstring> fields ;	// 明示空を含む現在行の全展開値
		error = readStorageInfRowFields( line, fields) ;
		// 一部の欄から完全な委譲を認定しない
		if( error != 0U) {
			return error ;
		}

		// IncludeとNeedsの元役割を維持し、文脈の異なる参照を一致にしない
		if( isInclude) {
			include =
				include || (fields.size() == 1U && stringsEqual( fields.front(), L"machine.inf")) ;
		} else {
			needs = needs || (fields.size() == 1U && stringsEqual( fields.front(), expectedNeeds)) ;
			delegates = delegates || std::ranges::any_of( fields, []( const auto &value) {
							return stringsEqual( value, L"NO_DRV") ||
								   stringsEqual( value, L"NO_DRV.Services") ;
						}) ; // 同梱の空ドライバーを名指しした時点で、不完全な宣言も後段で拒否する
		}
	}

	matched = count == 2L && include && needs ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの確認済み委譲節に別の作用節やレイアウト指定が付かないことを確認する
 * @param[in] inf 元INFの非実行読取りhandle
 * @param[in] base 元Modelsから得た同じ導入の基本名
 * @param[in] install 現OSで選択した正規導入節
 * @param[in] services 同選択に付随する正規サービス節
 * @return 付随する原作用がない場合0、追加節や列挙失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyStorageNullDriverRelatedSections( HINF inf, std::wstring_view base,
												   std::wstring_view install,
												   std::wstring_view services)
{
	INFCONTEXT layout{} ;	// 選択節から独立して適用され得る元レイアウト指定
	SetLastError( ERROR_SUCCESS) ;
	// 明示された外部レイアウトの作用を二行の委譲へ含めない
	if( SetupFindFirstLineW( inf, L"Version", L"LayoutFile", &layout)) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto layoutError = GetLastError() ;	// 元レイアウト照会の診断
	// 行の不存在以外の失敗を読み終えたことにしない
	if( layoutError != ERROR_SUCCESS && layoutError != ERROR_LINE_NOT_FOUND) {
		return nativeErrorFromWin32( layoutError) ;
	}

	std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> name{} ;	// SetupAPIの元節名
	// 元基本節の装飾と付随節を有限に確認し、追加作用を黙って除外しない
	for( UINT index = 0U; index <= MAXIMUM_INF_SECTIONS; ++index) {
		SetLastError( ERROR_SUCCESS) ;
		// 正常終端だけを漏れのない列挙として扱う
		if( !SetupEnumInfSectionsW( inf, index, name.data(), static_cast<UINT>( name.size()),
								  nullptr)) {
			const auto error = GetLastError() ;	// 列挙終了かAPI失敗かを示す元診断
			return error == ERROR_NO_MORE_ITEMS
					   ? 0U
					   : nativeErrorFromWin32( error ? error : ERROR_INVALID_DATA) ;
		}

		// 上限を越えた節列挙から関係の不存在を判断しない
		if( index == MAXIMUM_INF_SECTIONS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		const std::wstring_view section{name.data()} ;	// 現在の元INF節の完全名
		// 別の装飾や付随節、全体の登録節が残る形式を委譲だけとして扱わない
		if( (matchesInfSectionFamily( section, base) && !stringsEqual( section, install) &&
			!stringsEqual( section, services)) ||
		   matchesInfSectionFamily( section, L"ClassInstall32") ||
		   matchesInfSectionFamily( section, L"InterfaceInstall32") ||
		   matchesInfSectionFamily( section, L"DefaultInstall")) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元INF節の全directiveを後段の作用照合へ保持します
 * @param[in] inf 元INFを開いた同期借用handleです
 * @param[in] section 選択に対応する同じINFの節名です
 * @param[out] directives 元順、名前と全fieldです。失敗時の部分値は使用できません
 * @return 全行の読取り成功0、元節又はfieldの不成立はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError readStorageInfDirectives( HINF inf, const std::wstring &section,
									 std::vector<StorageServiceDirective> &directives)
{
	const auto count = SetupGetLineCountW( inf, section.c_str()) ;	// 元節全体の実際の行数です
	// 元節の不在や過大な行数を既知の必須値だけに縮約しません
	if( count < 0L || count > 4096L) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 後段が別作用を照合できるよう原順で全行を読みます
	for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
		INFCONTEXT				row{} ;		// 原サービス構成節の一行です
		StorageServiceDirective directive ;	// 行位置、directiveと全fieldを所有します
		directive.ordinal = static_cast<std::uint32_t>( ordinal) ;
		// 元directiveや過大なfieldを先頭一致へ縮約しません
		if( !SetupGetLineByIndexW( inf, section.c_str(), static_cast<DWORD>( ordinal), &row) ||
		   readInfField( row, 0U, directive.key) != 0U || SetupGetFieldCount( &row) > 64U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const auto error = readStorageInfRowFields( row, directive.fields) ;	// 元全fieldの診断です
		// 部分行を完全な作用へ変換しません
		if( error != 0U) {
			return error ;
		}

		directives.push_back( std::move( directive)) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択節の直接EXEコピー行をDriver Storeの元CATメンバーへ結びます
 * @param[in] inf 元INFを開いた同期借用handleです
 * @param[in] entries 同元CAT検査済み閉包です
 * @param[in] reference 同じ選択節が参照した直接コピーです
 * @param[in] copy 元媒体・Windows宛先の解決済みの組です
 * @param[out] result 完全成立した場合だけ元行とコピーを保持します
 * @return 一意の同名EXEと元行が成立する場合0、その他はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError readDirectStorageAuxiliaryCopy( HINF inf, std::span<const OfficialZipEntry> entries,
										   const OfficialInfInstallReference &reference,
										   const WindowsDriverCopy			 &copy,
										   SelectedStorageCopyFact			 &result)
{
	// 直接コピーにある名前と宛先のleafを固定し、他の配置やpathを補完しません
	if( copy.dirid != 13 || reference.target.find_first_of( L"\\/") != reference.target.npos ||
	   lowerExtension( reference.target) != L".exe") {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const auto sameSource = [&]( const OfficialZipEntry &entry) {
		return stringsEqual( entry.relativePath, copy.source) ;
	} ; // 元閉包の完全相対位置だけを同期比較します
	const auto member = std::ranges::find_if( entries, sameSource) ;	// 同CATメンバー
	// 閉包にない元ファイルや同名メンバーを先頭採用しません
	if( member == entries.end() || member->uncompressedSize == 0U || member->sha256.size() != 64U ||
	   std::ranges::count_if( entries, sameSource) != 1) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	std::vector<StorageServiceDirective> rows ;										// 同選択節から保持する元行
	const auto error = readStorageInfDirectives( inf, reference.section, rows) ;	// 元読取結果
	// 元節を読めない場合はコピー先だけから元行を組み立てません
	if( error != 0U) {
		return error ;
	}

	const auto field = L"@" + reference.target ;	// 同INFの直接コピー指示
	const auto row	 = std::ranges::find_if( rows, [&]( const auto &item) {
		  return stringsEqual( item.key, L"CopyFiles") &&
				 std::ranges::any_of( item.fields,
									 [&]( const auto &value) { return stringsEqual( value, field) ; }) ;
	  }) ; // 呼出し側が重複コピーを拒否する同一の元行
	// 解決済みコピーが照合対象の元行に存在する場合だけ渡します
	if( row == rows.end()) {
		return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
	}

	result = {reference.section, row->ordinal, std::move( row->fields), copy.source,
			  copy.target,		 copy.dirid,   member->sha256,		   member->uncompressedSize} ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元CATに結合済みの補助EXEを同じファイルを保持したまま検査します
 * @param[in] workspace 元閉包を保持する管理者保護領域です
 * @param[in] copy 元EXEのCATに結合した相対位置、SHA-256と完全byte数です
 * @param[in] publisher CATで保護された元INFのProvider値です
 * @return 元byte、AMD64アプリケーション形式、埋込み署名とpublisherが成立すれば0、その他はHRESULTです
 * @note 署名はキャッシュで検証します。EXEのロード、実行、サービス構成の操作を行いません
 */
//------------------------------------------------------------------------------
NativeError verifyStorageAuxiliaryImage( const OfficialDownloadWorkspace &workspace,
										const SelectedStorageCopyFact	&copy,
										std::wstring_view				 publisher)
{
	constexpr std::uint64_t MAXIMUM_PE_BYTES =
		128ULL * 1024ULL * 1024ULL ;									// 共通PE readerの上限です
	const auto		   path = workspace.path( copy.source) ;			// 閉包の同じ通常fileだけを開きます
	OfficialMappedFile pinned ;											// 検査中は親とファイルの置換を防ぐ読取りownerです
	auto			   error = pinned.open( path, MAXIMUM_PE_BYTES) ;	// 最初の元診断を保持します
	// 親又は元ファイルを固定できなければ署名も別のファイルから借用しません
	if( error != 0U) {
		return error ;
	}

	error = verifyOfficialFileMetadata( path, {copy.bytes, copy.sha256}) ;
	// 元CAT memberの完全byte条件を満たしたファイルだけを形式検査へ渡します
	if( error == 0U) {
		error = verifyAmd64PeFile( path) ;
	}

	// 読取又はAMD64形式の元診断を保持します
	if( error != 0U) {
		return error ;
	}

	const auto		   bytes = pinned.bytes() ;	// 共通PE readerと同じ固定byteです
	IMAGE_DOS_HEADER   dos{} ;					// 共通PE readerで読取り済みのDOS headerです
	IMAGE_NT_HEADERS64 pe{} ;					// 共通PE readerで範囲を確認したPE32+ headerです
	std::memcpy( &dos, bytes.data(), sizeof( dos)) ;
	std::memcpy( &pe, bytes.data() + static_cast<std::size_t>( dos.e_lfanew), sizeof( pe)) ;
	// DLL・カーネルimage・Windowsアプリケーション以外のsubsystemをEXEへ読み替えません
	if( (pe.FileHeader.Characteristics & (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL |
										 IMAGE_FILE_SYSTEM)) != IMAGE_FILE_EXECUTABLE_IMAGE ||
	   (pe.OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI &&
		pe.OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI)) {
		return nativeErrorFromWin32( ERROR_BAD_EXE_FORMAT) ;
	}

	return verifyAuthenticodePublisherCachedOnly( path, std::span{&publisher, 1U}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 補助サービスを元選択のSystem32またはDriver Storeの署名付きEXE一件に結びます
 * @param[in] inf 元INFの同期借用handleです
 * @param[in] workspace 元閉包を保持する管理者保護領域です
 * @param[in] selected 元CATに結合したSCSIAdapter選択です
 * @param[in] associated 関連カーネルサービスの元構成です
 * @param[in,out] auxiliary 元AddServiceと元コピーを持ちます。成功時に同節の全fieldを保持します
 * @return 元節に対応する開始種別、コピー先、EXEの署名が成立すれば0、その他はHRESULTです
 * @note Securityの意味とイベント・既存サービス・コピー先の作用は後段で照合します
 */
//------------------------------------------------------------------------------
NativeError bindSelectedStorageAuxiliaryService( HINF								  inf,
												const OfficialDownloadWorkspace		 &workspace,
												const OfficialInfPackage			 &selected,
												const SelectedStorageServiceFacts	 &associated,
												SelectedStorageAuxiliaryServiceFacts &auxiliary)
{
	// 元の関連カーネルサービスと別のServiceName・構成節に限定します
	if( associated.flags != SPSVCINST_ASSOCSERVICE || associated.type != SERVICE_KERNEL_DRIVER ||
	   stringsEqual( associated.name, auxiliary.name) ||
	   stringsEqual( associated.installSection, auxiliary.installSection) ||
	   auxiliary.name.find( L'\\') != auxiliary.name.npos ||
	   !validRequiredServiceSubdirectory( auxiliary.name)) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// どちらの開始種別も同じ専用Win32 processの引数なしの完全パスを要求します
	if( readRequiredServiceScalar( inf, auxiliary.installSection, L"ServiceType", auxiliary.type) !=
		   0U ||
	   readRequiredServiceScalar( inf, auxiliary.installSection, L"StartType", auxiliary.start) !=
		   0U ||
	   readRequiredServiceScalar( inf, auxiliary.installSection, L"ErrorControl",
								 auxiliary.errorControl) != 0U ||
	   readRequiredServiceField( inf, auxiliary.installSection, L"ServiceBinary",
								auxiliary.binary) != 0U ||
	   auxiliary.type != SERVICE_WIN32_OWN_PROCESS ||
	   auxiliary.errorControl > SERVICE_ERROR_CRITICAL ||
	   !stringsEqual( auxiliary.binary, auxiliary.copy.target)) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const bool driverStore = auxiliary.copy.dirid == 13 ;	// 元直接コピーの別用途を示します
	// Driver Storeの自動起動では同じ元六欄に書かれた名前付きSystemイベントを要求します
	if( driverStore) {
		const auto &fields = auxiliary.addServiceFields ;	// 元イベント節と名前を含む六欄
		// 省略や別ログを元宣言へ補完しません
		if( auxiliary.start != SERVICE_AUTO_START ||
		   auxiliary.errorControl != SERVICE_ERROR_NORMAL || fields.size() != 6U ||
		   !validNamedStorageSystemEvent( inf, fields[3], fields[4], fields[5])) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	} else {
		std::array<wchar_t, MAX_PATH> system{} ;	// 現在のWindowsが解決するSystem32です
		const auto					  length =
			// 元必要長
			GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
		// 従来の要求時起動では明示SecurityとSystem32直下の再起動時置換を照合します
		if( auxiliary.start != SERVICE_DEMAND_START ||
		   readRequiredServiceField( inf, auxiliary.installSection, L"Security",
									auxiliary.security) != 0U ||
		   auxiliary.binary.find_first_of( L" \t\r\n") != auxiliary.binary.npos || length == 0U ||
		   length >= system.size() || auxiliary.copy.dirid != 11 ||
		   auxiliary.copy.fields.size() != 4U ||
		   !stringsEqual( auxiliary.copy.target, joinRelativePath( {system.data(), length},
																 auxiliary.copy.fields.front()))) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	const auto error = readStorageInfDirectives( inf, auxiliary.installSection,
												auxiliary.directives) ;	// 元全行の診断です
	// 元全行を読めない場合は署名成功から構成を補完しません
	if( error != 0U) {
		return error ;
	}

	// 自動起動では省略を明示値や重複Securityに置き換えません
	if( driverStore && std::ranges::any_of( auxiliary.directives, []( const auto &directive) {
		   return stringsEqual( directive.key, L"Security") ;
	   })) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	return verifyStorageAuxiliaryImage( workspace, auxiliary.copy, selected.providerName) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief ストレージの実選択節を、Windows同梱INFへの空ドライバー委譲の原宣言に照合する
 * @param[in] workspace CAT検査済み元INFを保護する領域。同期中だけ借用する
 * @param[in] entries 元閉包のSHA-256とサイズを持つ一覧。同期中だけ借用する
 * @param[in] selected 元のWindows互換ノードに結ぶストレージの選択関係
 * @param[in] modelsSection 同じ元署名レコードの現在OS用Models節
 * @param[in] nodeIds Windows互換ノードが保持した順序付きHardware IDとCompatible ID
 * @param[out] matched 選択節とサービス節の委譲だけが完全に一致した場合true。失敗と通常の選択はfalse
 * @return 照合完了0、委譲を宣言する節の不正や読取り失敗はHRESULT
 * @pre 呼出し側は同じ原閉包のCAT署名と端末の選択関係を確認する
 * @note Windows側の参照先、実端末への適用、導入資格は呼出し側で別に判定する
 */
//------------------------------------------------------------------------------
NativeError inspectSelectedStorageNullDriverDelegation( const OfficialDownloadWorkspace	&workspace,
													   std::span<const OfficialZipEntry> entries,
													   const OfficialInfPackage			&selected,
													   const std::wstring			&modelsSection,
													   std::span<const std::wstring> nodeIds,
													   bool							&matched)
{
	matched = false ;
	// 専用のストレージ検査を通っていない用途にはこの委譲判定を適用しない
	if( selected.inspectionPurpose != OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE) {
		return 0U ;
	}

	// 信頼を確認済みの基本INFと現選択に限定し、未確定の入力から節を作らない
	if( workspace.protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR ||
	   selected.role != DriverPlanRole::BASE_DRIVER || selected.requiredNullCompanion ||
	   selected.requiredRegistryOnlyCompanion || entries.empty() || entries.size() > 32'768U ||
	   !validInstallInventorySectionName( modelsSection) || nodeIds.empty() ||
	   nodeIds.size() > 63U || !validInstallInventorySectionName( selected.selectedBasicSection) ||
	   !validInstallInventorySectionName( selected.selectedInstallSection)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto isSource = [&]( const auto &entry) {
			return stringsEqual( entry.relativePath, selected.infRelativePath) ;
		} ; // この呼出しが借用する同元閉包のINFだけを照合する
		const auto entry =
			// 元INFの署名済み内容に結ぶハッシュとサイズ
			std::ranges::find_if( entries, isSource) ;
		const auto path = workspace.path( selected.infRelativePath) ;	// 同保護領域内の原INF位置
		// 不在・同名重複・元証拠不足の入力を別のINFに結び付けない
		if( path.empty() || entry == entries.end() || entry->uncompressedSize == 0U ||
		   entry->sha256.size() != 64U || std::ranges::count_if( entries, isSource) != 1) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		OfficialMappedFile pinned ;								// SetupAPIの読取りを終えるまで元INFを変更・置換させない
		auto error = pinned.open( path, 4U * 1024U * 1024U) ;	// 元INFを保護して開いた結果
		const OfficialFileMetadataPolicy policy{entry->uncompressedSize,
												entry->sha256} ;	// 同元CAT検査が使用した完全バイト
		// 別の時点や出所で検証された内容に置き換えない
		if( error == 0U) {
			error = verifyOfficialFileMetadata( path, policy) ;
		}

		// 固定と原バイト照合が完了してからSetupAPIを使う
		if( error != 0U) {
			return error ;
		}

		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// 同じ元INFだけを開く読取りhandle
		// 元INFの読取り失敗を通常選択へ変更しない
		if( inf.get() == INVALID_HANDLE_VALUE) {
			const auto openError = GetLastError() ;	// SetupAPIの失敗直後の元診断
			return nativeErrorFromWin32( openError ? openError : ERROR_INVALID_DATA) ;
		}

		std::wstring install ;	// 同じWindowsが現在OSのModelsから解決した選択節名
		error = selectInstallInventorySection( inf.get(), selected.selectedBasicSection, install) ;
		// 元のModels所属と実装飾選択を同一の入口で再確認する
		if( error != 0U || !stringsEqual( install, selected.selectedInstallSection)) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		const auto services = install + L".Services" ;	// 同選択に限定した正規サービス節
		bool	   delegates{} ;						// いずれかの選択節が専用のNeedsを宣言したか
		bool	   installMatched{} ;					// 基本節の正確な委譲を確認したか
		bool	   servicesMatched{} ;					// サービス節の正確な委譲を確認したか
		error =
			readStorageNullDriverSection( inf.get(), install, L"NO_DRV", delegates, installMatched) ;
		// 基本節を確認できた場合だけ、同じ選択のサービス節も読む
		if( error == 0U) {
			error = readStorageNullDriverSection( inf.get(), services, L"NO_DRV.Services", delegates,
												 servicesMatched) ;
		}

		// 読取り失敗は元診断を伝え、委譲を宣言しない選択は通常の処理に残す
		if( error != 0U || !delegates) {
			return error ;
		}

		// 一方だけの委譲や、同じ選択に付く別の必要構成を空ドライバーへ縮約しない
		if( !installMatched || !servicesMatched || !selected.activeRequiredInfPaths.empty() ||
		   !selected.requiredComponents.empty()) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		error = verifyStorageNullDriverRelatedSections( inf.get(), selected.selectedBasicSection,
													   install, services) ;
		// 同じ署名付きModelsの一行とWindows互換ノードが一致する場合だけ委譲を確認する
		if( error == 0U) {
			error = verifyCurrentInfModelsRow( inf.get(), selected, modelsSection,
											  selected.selectedBasicSection, nodeIds) ;
		}

		// 全作用が一致した場合だけ、読取り終了時の完全バイトを照合する
		if( error == 0U) {
			error = verifyOfficialFileMetadata( path, policy) ;
		}

		matched = error == 0U ;
		return error ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief イベント用DLLの元コピーリストが明示的にSystem32直下を指定することを確認する
 * @param[in] inf 元署名文書のHINFを同期借用する
 * @param[in] list 元の名前付きコピー節。空は受理しない
 * @return 元DestinationDirsに重複のない単一DIRID 11があればtrue
 * @note 既定宛先とサブディレクトリは認めない。実配置やシステムの変更は行わない
 */
//------------------------------------------------------------------------------
bool hasExplicitStorageEventCopyDestination( HINF inf, const std::wstring &list)
{
	INFCONTEXT line{} ;			// 元コピー節固有のDestinationDirs行
	INFCONTEXT duplicate{} ;	// 同名の別行の検出にだけ使う
	int		   dirid{} ;		// 元INFが明示するWindows宛先番号
	return !list.empty() && !stringsEqual( list, L"DefaultDestDir") &&
		   SetupFindFirstLineW( inf, L"DestinationDirs", list.c_str(), &line) &&
		   SetupGetFieldCount( &line) == 1U && SetupGetIntField( &line, 1U, &dirid) && dirid == 11 &&
		   !SetupFindNextMatchLineW( &line, list.c_str(), &duplicate) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同原選択storageの関連サービスと、該当する場合はSCSIAdapterの補助サービスを読み取ります
 * @param[in] workspace 端末検査またはHDC収集検査が所有する保護領域
 * @param[in] entries 同原CAT検査済み閉包の全hash/sizeです
 * @param[in] selected 元native nodeまたはHDCのAMD64 Modelsから解決した選択関係
 * @param[out] facts SYSと該当する補助EXE・イベント用DLLの元コピーと型が成立した場合だけ保持します。失敗時は空です
 * @return 元全fieldと該当する補助EXEの署名確認に成功した場合0、その他はHRESULTです
 * @note 署名確認はキャッシュ内で行います。サービスの作用と端末上の導入資格は後段で検査します
 */
//------------------------------------------------------------------------------
NativeError readSelectedStorageServiceFacts( const OfficialDownloadWorkspace	 &workspace,
											std::span<const OfficialZipEntry> entries,
											const OfficialInfPackage		 &selected,
											SelectedStorageServiceFacts		 &facts)
{
	facts = {} ;
	// 選択class名とGUIDが正式MTD対かの判定です
	const bool mtd = stringsEqual( selected.className, L"MTD") &&
					 stringsEqual( selected.classGuid, L"{4d36e970-e325-11ce-bfc1-08002be10318}") ;
	// 選択class名とGUIDが正式SCSI対かの判定です
	const bool scsi = stringsEqual( selected.className, L"SCSIAdapter") &&
					  stringsEqual( selected.classGuid, L"{4d36e97b-e325-11ce-bfc1-08002be10318}") ;
	// Windowsが定義するメディアチェンジャーの正式対
	const bool changer = stringsEqual( selected.className, MEDIUM_CHANGER_CLASS.front()) &&
						 stringsEqual( selected.classGuid, MEDIUM_CHANGER_CLASS.back()) ;
	// 端末の元検査用途と管理者保護領域が揃うことの判定
	const bool administratorStorage =
		workspace.protectionMode() == OfficialWorkspaceMode::ADMINISTRATOR &&
		selected.inspectionPurpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ;
	// 従来の端末ストレージで使う正式クラスと用途の組合せ
	const bool deviceStorage = administratorStorage && (scsi || mtd || changer) ;
	const auto hdcGroup =
		std::ranges::find_if( selected.nativeHdcInstallGroups, [&]( const auto &group) {
			return (group.size() == 2U || group.size() == 3U) &&
				   stringsEqual( group.front(), selected.selectedInstallSection) ;
		}) ; // 同じ元AMD64 Modelsに含まれる同梱SYSの実選択
	const bool nativeHdc =
		(administratorStorage ||
		 selected.inspectionPurpose == OfficialInfInspectionPurpose::COLLECTOR_CONTENT) &&
		stringsEqual( selected.className, HDC_CLASS.front()) &&
		stringsEqual( selected.classGuid, HDC_CLASS.back()) &&
		hdcGroup != selected.nativeHdcInstallGroups.end() ;	// 正式な元選択グループと用途
	// 許可した検査用途で確定した選択節だけから元事実を返す
	if( (!deviceStorage && !nativeHdc) || selected.requiredRegistryOnlyCompanion ||
	   selected.selectedInstallSection.empty()) {
		return E_INVALIDARG ;
	}

	const UniqueInf inf( SetupOpenInfFileW( workspace.path( selected.infRelativePath).c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
										  nullptr)) ;	// 同原文だけです
	// 原読取失敗を既metadataで補完しません
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	OfficialInfInstallInventory inventory ;	// 同選択の元コピーとservice参照です
	// 下位検査の最初の診断を後続へ返す一時値です
	auto error = readWindowsDriverScopeReferences( inf.get(), selected, inventory) ;
	// 原選択の欠損を先頭節へ置換しません
	if( error != 0U) {
		return error ;
	}

	// 原ブートSYSの同名直接コピーだけをHDCの選択に結び付ける
	if( nativeHdc &&
	   (inventory.references.size() != 1U ||
		inventory.references.front().kind != OfficialInfInstallReferenceKind::DIRECT_FILE ||
		!stringsEqual( inventory.references.front().section, selected.selectedInstallSection) ||
		lowerExtension( inventory.references.front().target) != L".sys")) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::vector<WindowsDriverCopy>		   copies ;				// 同INFの一意source/宛先です
	std::vector<SelectedStorageCopyFact>   mtdCopies ;			// 原行/元CAT/宛先の一対一です
	std::optional<SelectedStorageCopyFact> auxiliaryCopy ;		// 同選択の再起動置換または直接コピーのEXE
	std::optional<SelectedStorageCopyFact> eventMessageCopy ;	// 同選択の名前付きイベント用DLL
	std::size_t copyRows{} ;									// copy呼出しごとの原行数で、同一宛先の繰返しも数えます
	const bool	directAuxiliaryScope =
		administratorStorage && scsi && selected.role == DriverPlanRole::BASE_DRIVER &&
		std::ranges::any_of( inventory.references, [&]( const auto &reference) {
			return reference.kind == OfficialInfInstallReferenceKind::DIRECT_FILE &&
				   stringsEqual( reference.directive, L"CopyFiles") &&
				   stringsEqual( reference.section, selected.selectedInstallSection) &&
				   lowerExtension( reference.target) == L".exe" ;
		}) ; // 同じ元節に直接EXEがあるときだけDLLとの組を調べる
	// 実選択CopyFilesだけを既コピー検査へ渡します
	for( const auto &reference : inventory.references) {
		// その他の作用は後段の全行評価へ残します
		if( !stringsEqual( reference.directive, L"CopyFiles")) {
			continue ;
		}

		// 未解決の元コピーを空集合へ変換しません
		if( !reference.targetPresent) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		// 直接コピーも同源/同宛先へ結びます
		if( reference.kind == OfficialInfInstallReferenceKind::DIRECT_FILE) {
			++copyRows ;
			// 初期MTDの制御queueは原sectionだけを再構成します
			if( mtd) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// 原完全名を失わずleafを取り出す境界です
			const auto slash = reference.target.find_last_of( L'\\') ;
			// 同原文又は完全Windows pathから得る元の正確な名前です
			const auto name =
				reference.target.substr( slash == reference.target.npos ? 0U : slash + 1U) ;
			const auto previousCopies = copies.size() ;	// 同宛先の繰り返しも検出する元件数
			error = bindWindowsDriverCopy( inf.get(), workspace, entries, selected, L"", name, name,
										  copies) ;
			// 選択SCSIAdapterの直接EXEを自動起動補助サービスの唯一の媒体へ結びます
			if( error == 0U && administratorStorage && scsi &&
			   selected.role == DriverPlanRole::BASE_DRIVER && lowerExtension( name) == L".exe") {
				// 同じ選択節外のコピーや二回の同宛先を補助サービスへ結びません
				if( auxiliaryCopy || copies.size() != previousCopies + 1U ||
				   !stringsEqual( reference.section, selected.selectedInstallSection)) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				error = readDirectStorageAuxiliaryCopy( inf.get(), entries, reference, copies.back(),
													   auxiliaryCopy.emplace()) ;
			}
		} else {
			// 同原文の全参照又は行数を上限と照合する数です
			const auto count = SetupGetLineCountW( inf.get(), reference.target.c_str()) ;
			const auto securitySection =
				reference.target + L".security" ;	// コピーACL作用を通常copyへ縮約しません
			SetLastError( ERROR_SUCCESS) ;
			// 元copy security宣言の存在を確認する行数です
			const auto securityRows = SetupGetLineCountW( inf.get(), securitySection.c_str()) ;
			// security宣言照会直後の元Windows診断です
			const auto securityError = GetLastError() ;
			// 元CopyFilesの未知権限作用は登録前に保留します
			if( securityRows >= 0L ||
			   (securityError != ERROR_SUCCESS && securityError != ERROR_SECTION_NOT_FOUND)) {
				return securityRows >= 0L ? nativeErrorFromWin32( ERROR_NOT_SUPPORTED)
										  : nativeErrorFromWin32( securityError) ;
			}

			// 不在/過大コピーを部分成功へ縮約しません
			if( count < 0L || count > 4096L) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// 原renameと空fieldを一行ずつ消費します
			for( LONG ordinal = 0L; ordinal < count; ++ordinal) {
				++copyRows ;
				// 同原節の一行を完全fieldで読むcursor又は所有値です
				INFCONTEXT	 row{} ;
				std::wstring target ;					// 原copy先leafです
				std::wstring source ;					// 原copy元leafです。省略を同名へ解釈する前の値です
				std::wstring temporary ;				// 初期資格で受理しない一時file名です
				std::vector<std::wstring> rawFields ;	// 原省略を補完しない完全な行です
				// コピーflagsを含む余分な行は旧scope検査と同じ境界に残します
				if( !SetupGetLineByIndexW( inf.get(), reference.target.c_str(),
										 static_cast<DWORD>( ordinal), &row) ||
				   SetupGetFieldCount( &row) == 0U || SetupGetFieldCount( &row) > 4U ||
				   readInfField( row, 1U, target) != 0U ||
				   (SetupGetFieldCount( &row) > 1U &&
					readInstallInventoryField( row, 2U, source) != 0U) ||
				   (SetupGetFieldCount( &row) > 2U &&
					(readInstallInventoryField( row, 3U, temporary) != 0U || !temporary.empty()))) {
					return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
				}

				std::uint32_t flags{} ;	// 明示fieldがない場合はコピー追加作用なしです
				// 明示されたコピー作用を原欄から読みます
				if( SetupGetFieldCount( &row) == 4U) {
					std::wstring				  rawFlags ;	// 省略fieldと明示0を区別して読みます
					// 元数値readerの具体的な不正/未対応区分です
					MaintenanceInfStructureReason reason{} ;
					// 元フラグを推測やビット部分一致で補完しません
					if( readInstallInventoryField( row, 4U, rawFlags) != 0U ||
					   (!rawFlags.empty() && parseMaintenanceFlags( rawFlags, flags, reason).state !=
												 MaintenanceInspectionState::PASSED)) {
						return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
					}
				}

				// 同選択の同名EXEに限って再起動置換の原行を保持します
				const bool auxiliaryRow =
					flags == COPYFLG_FORCE_FILE_IN_USE && administratorStorage && scsi &&
					selected.role == DriverPlanRole::BASE_DRIVER && count == 1L && !auxiliaryCopy &&
					stringsEqual( reference.section, selected.selectedInstallSection) &&
					stringsEqual( source, target) && lowerExtension( target) == L".exe" ;
				// 閉包内でイベント資源のコピーと認められる単一のDLL行かを示します
				const bool eventRow =
					directAuxiliaryScope && count == 1L && !eventMessageCopy &&
					stringsEqual( reference.section, selected.selectedInstallSection) &&
					SetupGetFieldCount( &row) == 1U && lowerExtension( target) == L".dll" ;
				// メッセージリストに使う一つのファイル名と明示System32宛先だけを受理する
				if( eventRow) {
					DWORD		 keyLength{} ;	// データ行にキーがある場合の元文字数
					// SetupAPIから同じコピー行のキー文字数を取得できたかを保持します
					const BOOL	 keyed	  = SetupGetStringFieldW( &row, 0U, nullptr, 0U, &keyLength) ;
					const DWORD	 keyError = GetLastError() ;	// 同じ元APIの診断
					std::wstring key ;							// SetupAPIが単一欄から返す場合がある同名キー
					// キー付きなら元ファイル名の一致を、キーなしなら列挙APIの欠損扱いを確認します
					const bool	 sameName =
						  keyed ? readInfField( row, 0U, key) == 0U && stringsEqual( key, target)
								: keyError == ERROR_INVALID_PARAMETER && keyLength == 0U ;
					// 別名キー、リスト区切り、Windows標準資源との衝突を拒否する
					if( !sameName || target.find_first_of( L"\\/;") != target.npos ||
					   stringsEqual( target, L"IoLogMsg.dll") ||
					   !hasExplicitStorageEventCopyDestination( inf.get(), reference.target)) {
						return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
					}
				}

				// 従来の警告フラグと、同選択の単一同名補助EXEの再起動置換だけを扱います
				if( flags != 0U && !(scsi && flags == COPYFLG_WARN_IF_SKIP) && !auxiliaryRow) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				// MTD・補助EXE・イベント用DLLの原コピー欄を省略せず保持する
				if( mtd || auxiliaryRow || eventRow) {
					// 選択device以外の文脈からコピーを再構成しません
					if( !stringsEqual( reference.section, selected.selectedInstallSection)) {
						return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
					}

					error = readStorageInfRowFields( row, rawFields) ;
					// 元INF field読取の失敗を保持します
					if( error != 0U) {
						return error ;
					}
				}

				// 現在section追加前の原COPY件数です
				const auto previousCopies = copies.size() ;
				error =
					bindWindowsDriverCopy( inf.get(), workspace, entries, selected, reference.target,
										  target, source.empty() ? target : source, copies) ;
				// 同名別sourceを後続コピー成功で救済しません
				if( error != 0U) {
					return error ;
				}

				// 元コピー行を同CATのメンバーと一対一に結ぶ
				if( mtd || auxiliaryRow || eventRow) {
					// 同targetの繰返しを一原queue行へ縮約しません
					if( copies.size() != previousCopies + 1U) {
						return nativeErrorFromWin32( ERROR_DUP_NAME) ;
					}

					// 追加した同原COPY行です
					const auto &copy = copies.back() ;
					// 同COPYの原CAT memberです
					const auto	member = std::ranges::find_if( entries, [&]( const auto &entry) {
						 return stringsEqual( entry.relativePath, copy.source) ;
					 }) ;
					// 元CAT memberのhashが欠損または不正なら採用しません
					if( member == entries.end() || member->sha256.size() != 64U ||
					   !std::ranges::all_of( member->sha256, []( wchar_t value) {
						   return (value >= L'0' && value <= L'9') ||
								  (value >= L'a' && value <= L'f') ;
					   })) {
						return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					SelectedStorageCopyFact fact{
						reference.target,	  static_cast<std::uint32_t>( ordinal),
						std::move( rawFields), copy.source,
						copy.target,		  copy.dirid,
						member->sha256,		  member->uncompressedSize} ;	// 原行と全byteです
					// 補助サービスと付随するイベントDLLは唯一の元メンバーに限定する
					if( auxiliaryRow || eventRow) {
						// 同名CAT memberの重複やサイズ不明を最初の候補へ縮約しません
						if( copy.dirid != 11 || member->uncompressedSize == 0U ||
						   std::ranges::count_if( entries, [&]( const auto &entry) {
							   return stringsEqual( entry.relativePath, copy.source) ;
						   }) != 1) {
							return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
						}

						// イベント用DLLは完全byteとPE資源の形式を同じファイルから確認する
						if( eventRow) {
							std::array<wchar_t, MAX_PATH + 1U> system{} ;	// Windowsが返す実System32
							const auto						   systemLength =
								GetSystemDirectoryW( system.data(),
													// 限定した正規宛先の長さ
													static_cast<UINT>( system.size())) ;
							// 元DIRIDの解決結果も正規ディレクトリと同名leafに一致させる
							if( systemLength == 0U || systemLength >= system.size() ||
							   !stringsEqual(
								   fact.target,
								   joinRelativePath( std::wstring_view{system.data(), systemLength},
													target))) {
								return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
							}

							const auto path = workspace.path( fact.source) ;	// 同元閉包の実パス
							OfficialMappedFile pinned ;							// 親と元ファイルを保持する読取り用マッピング
							error = pinned.open( path, 64ULL * 1024ULL * 1024ULL) ;
							// 固定中の元バイトを同じCATメンバーのサイズとハッシュに照合する
							if( error == 0U) {
								error = verifyOfficialFileMetadata( path, {fact.bytes, fact.sha256}) ;
							}

							// 元バイトが一致した場合だけDLLの非実行形式を調べる
							if( error == 0U) {
								error = verifyOfficialEventMessageResourceDll( pinned.bytes()) ;
							}

							// 一つでも不成立なら同じ選択のファイル証拠に含めない
							if( error != 0U) {
								return error ;
							}

							eventMessageCopy = std::move( fact) ;
						} else {
							auxiliaryCopy = std::move( fact) ;
						}
					} else {
						mtdCopies.push_back( std::move( fact)) ;
					}
				}
			}
		}

		// 直接コピーの元診断も失いません
		if( error != 0U) {
			return error ;
		}
	}

	// 元CATに収録される唯一のSYSをWindowsのドライバーディレクトリに結び付ける
	if( nativeHdc && (copies.size() != 1U || copies.front().dirid != 12 ||
					 (hdcGroup->size() == 3U &&
					  (selected.sourceFiles.size() != 1U ||
					   !stringsEqual( copies.front().source, selected.sourceFiles.front()))))) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	SelectedStorageServiceFacts made ;	// 全成立まで非権限の原事実だけを所有します
	made.className				= selected.className ;
	made.classGuid				= selected.classGuid ;
	made.mtdCopies				= std::move( mtdCopies) ;
	made.infRelativePath		= selected.infRelativePath ;
	made.selectedInstallSection = selected.selectedInstallSection ;
	made.servicesSection		= selected.selectedInstallSection + L".Services" ;
	const auto expectedCopies	= eventMessageCopy ? 3U : 2U ;	// SYS、補助EXEと明示されたDLLの件数
	// イベント資源のない既存構成を含め、同じDDInstallの元コピーだけを結び付ける
	if( eventMessageCopy && (!auxiliaryCopy || auxiliaryCopy->dirid != 13)) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 選択と異なる節、追加コピー、同名の繰返しを一つの閉包として採用しない
	if( auxiliaryCopy && (copyRows != expectedCopies || copies.size() != expectedCopies ||
						 inventory.references.size() != expectedCopies ||
						 std::ranges::any_of( inventory.references,
											 [&]( const auto &reference) {
												 return !stringsEqual( reference.section,
																	  made.selectedInstallSection) ;
											 }) ||
						 std::ranges::any_of( inventory.effects, [&]( const auto &effect) {
							 return stringsEqual( effect.directive, L"AddService") &&
									!stringsEqual( effect.section, made.servicesSection) ;
						 }))) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 元Services節に存在する全行数です
	const auto serviceRows = SetupGetLineCountW( inf.get(), made.servicesSection.c_str()) ;
	// 空/欠損serviceを新規kernelと推測しません
	if( serviceRows < 1L || serviceRows > 4096L) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	bool found{} ;	// 元関連サービス行を保持済みかの判定です
	// AddServiceの原ordinalと全fieldを固定します
	for( LONG ordinal = 0L; ordinal < serviceRows; ++ordinal) {
		// 同原節の一行を完全fieldで読むcursor又は所有値です
		INFCONTEXT	 row{} ;
		// 同原行の正確なdirective名です
		std::wstring key ;
		// 全行を読めない節から部分factsを返しません
		if( !SetupGetLineByIndexW( inf.get(), made.servicesSection.c_str(),
								 static_cast<DWORD>( ordinal), &row) ||
		   readInfField( row, 0U, key) != 0U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// Include/Needs等の意味は全作用評価で検査します
		if( !stringsEqual( key, L"AddService")) {
			continue ;
		}

		const auto fieldCount = SetupGetFieldCount( &row) ;	// 元AddServiceの項目数
		// 六欄は同じDriver Storeの直接EXEを持つ補助行だけに限定します
		if( fieldCount < 3U || (fieldCount > 4U && (fieldCount != 6U || !auxiliaryCopy ||
												   auxiliaryCopy->dirid != 13))) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		std::vector<std::wstring> fields ;	// 元AddServiceの明示空を含む全fieldです
		error = readStorageInfRowFields( row, fields) ;
		// 原fieldの不在を既定値に補完しません
		if( error != 0U) {
			return error ;
		}

		int flags{} ;	// Windowsが解析した元AddService全flagです
		// named sourceの不在/数値不正を既定へ変更しません
		if( fields[0].empty() || !validInstallInventorySectionName( fields[2]) ||
		   !SetupGetIntField( &row, 2U, &flags)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 六欄の補助サービスを関連カーネルサービスや他のフラグへ振り替えません
		if( fieldCount == 6U && flags != 0) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// 同じDDInstallの元EXEコピーに対応するフラグ0だけを独立サービスへ保持します
		if( auxiliaryCopy && flags == 0) {
			// DLL付き宣言は同じサービス行がSystemの明示イベント源を持つ場合に限定する
			if( eventMessageCopy &&
			   (fields.size() != 6U || !stringsEqual( fields[4], L"System") || fields[5].empty())) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// 二つ目の補助サービスへ同じコピーを流用しません
			if( made.auxiliary) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			auto &auxiliary = made.auxiliary.emplace() ;	// 同原選択に属する補助サービス一件です
			auxiliary.addServiceOrdinal = static_cast<std::uint32_t>( ordinal) ;
			auxiliary.name				= fields[0] ;
			auxiliary.installSection	= fields[2] ;
			auxiliary.addServiceFields	= std::move( fields) ;
			auxiliary.copy				= std::move( *auxiliaryCopy) ;
			auxiliary.eventMessageCopy	= std::move( eventMessageCopy) ;
			continue ;
		}

		// 関連サービスの複数行を先頭一致へ縮約しません
		if( found) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		found				   = true ;
		made.addServiceOrdinal = static_cast<std::uint32_t>( ordinal) ;
		made.name			   = fields[0] ;
		made.installSection	   = fields[2] ;
		made.addServiceFields  = std::move( fields) ;
		made.flags			   = static_cast<std::uint32_t>( flags) ;
	}

	// 元補助コピーを持つ選択でサービス行が欠損するときは部分factsを返しません
	if( auxiliaryCopy && !made.auxiliary) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 必須値は既一意readerで重複/複数fieldも拒否します
	if( !found ||
	   readRequiredServiceScalar( inf.get(), made.installSection, L"ServiceType", made.type) != 0U ||
	   readRequiredServiceScalar( inf.get(), made.installSection, L"StartType", made.start) != 0U ||
	   readRequiredServiceScalar( inf.get(), made.installSection, L"ErrorControl",
								 made.errorControl) != 0U ||
	   readRequiredServiceField( inf.get(), made.installSection, L"ServiceBinary", made.binary) !=
		   0U ||
	   !boundWindowsServiceBinary( made.binary, copies, true)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	error = readStorageInfDirectives( inf.get(), made.installSection, made.directives) ;
	// 後続行の未知設定を先頭必須値の成功へ縮約しません
	if( error != 0U) {
		return error ;
	}

	// 既存カーネルサービスのoptional値を元順に読み、全作用の原directiveも保持します
	for( const auto &directive : made.directives) {
		// optional値の不在と明示空を別のまま固定します
		if( stringsEqual( directive.key, L"LoadOrderGroup")) {
			// groupの重複や複数値を先頭値へ縮約しません
			if( made.group || directive.fields.size() != 1U) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			made.group = directive.fields.front() ;
		}
		// Dependenciesは省略と明示空を区別して原順で保持します
		else if( stringsEqual( directive.key, L"Dependencies")) {
			// 重複した依存宣言を一つへ併合しません
			if( made.dependencies) {
				return nativeErrorFromWin32( ERROR_DUP_NAME) ;
			}

			made.dependencies = directive.fields ;
		}
		// modern BootFlagsを旧registry表現と分けて読みます
		else if( stringsEqual( directive.key, L"BootFlags")) {
			// 元fieldの全値です。省略や失敗を既定値へ補完しません
			std::uint32_t value{} ;
			// 重複/不正BootFlagsを既定値で補完しません
			if( made.bootFlags || readRequiredServiceScalar( inf.get(), made.installSection,
														   L"BootFlags", value) != 0U) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			made.bootFlags = value ;
		}
	}

	// 原完全宛先と一致するSYSだけを一意sourceへ結びます
	for( const auto &copy : copies) {
		// 同じ完全Windows宛先のSYSだけを一意sourceへ結びます
		if( (copy.dirid == 12 || copy.dirid == 13) && stringsEqual( made.binary, copy.target)) {
			// 二つ目のbinary sourceを先頭一致で救済しません
			if( !made.binarySource.empty()) {
				return nativeErrorFromWin32( ERROR_DUP_NAME) ;
			}

			made.binarySource = copy.source ;
			made.binaryTarget = copy.target ;
		}
	}

	const auto source = std::ranges::find_if( entries, [&]( const auto &entry) {
		return stringsEqual( entry.relativePath, made.binarySource) ;
	}) ; // 同原CAT memberだけです
	// 型だけの架空SYSやCAT外byteをsource証拠へしません
	if( source == entries.end() || made.binarySource.empty()) {
		return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
	}

	made.binarySha256 = source->sha256 ;
	made.binaryBytes  = source->uncompressedSize ;
	// 正式MTDだけassociated SYSと共有DLLを区別します
	if( mtd) {
		// 全元コピーを一associated SYS又はDIRID11のDLLへ一対一に分類します
		std::wstring systemSection ;
		// associated SYSに対応する原COPY件数です
		std::size_t	 systemCopies{} ;
		// 全原COPYをSYSまたはDIRID11のDLLへ分類します
		for( const auto &copy : made.mtdCopies) {
			// 選択SYSに対応する原COPYを確認します
			if( stringsEqual( copy.target, made.binaryTarget)) {
				// SYS重複やDIRID・拡張子不一致を拒否します
				if( ++systemCopies != 1U || (copy.dirid != 12 && copy.dirid != 13) ||
				   lowerExtension( copy.target) != L".sys") {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				systemSection = copy.section ;
			}
			// SYS以外のCOPYを安全な共有DLLに限定します
			else if( copy.dirid != 11 || lowerExtension( copy.target) != L".dll" ||
					lowerExtension( copy.source) != L".dll") {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}
		}

		// SYS欠損や未分類COPYを許可しません
		if( systemCopies != 1U || std::ranges::any_of( made.mtdCopies, [&]( const auto &copy) {
			   return !stringsEqual( copy.target, made.binaryTarget) &&
					  stringsEqual( copy.section, systemSection) ;
		   })) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	error = verifyAmd64PeFile( workspace.path( made.binarySource)) ;
	// 関連SYSを検査した同じ選択でだけ補助EXEの原構成と署名を照合します
	if( error == 0U && made.auxiliary) {
		error = bindSelectedStorageAuxiliaryService( inf.get(), workspace, selected, made,
													*made.auxiliary) ;
	}

	// AMD64形式が成立した元factsだけを返します
	if( error == 0U) {
		facts = std::move( made) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式対象Windowsが選ぶ実導入節を検証済み混在シリアルの二選択へ結ぶ
 * @param[in] inf 同じ元INFの読み取り専用handle
 * @param[in] requested 公式配布対象を指定したWindowsの観測点。非nullを要求する
 * @param[in] media 自前媒体と同梱依存を検査した二つの元選択
 * @return 二選択が過不足なく一意に一致すれば0。読み取りや不一致は元HRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] static NativeError checkCollectorSerialTargetSelections(
	HINF inf, PSP_ALTPLATFORM_INFO requested, const OfficialInfCollectorSerialMedia &media)
{
	// 現在OSの暗黙選択や片方だけの成立で公式対象を認めない
	if( requested == nullptr || media.groups.size() != 2U || media.groups[0].size() != 3U ||
	   media.groups[1].size() != 3U) {
		return E_INVALIDARG ;
	}

	MaintenanceStructureBudget budget ;	// 同じ元INFのModels行数上限
	std::vector<std::wstring>  bases ;	// 明示対象に該当する元の基本名
	const auto				   models =
		// SetupAPIの明示選択
		collectMaintenanceInstallNames( inf, budget, bases, true, requested) ;
	// 読めない元行、欠落、余剰を現在OSの選択で代用しない
	if( models != 0U || bases.size() != media.groups.size()) {
		return models != 0U ? models : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	std::vector<std::wstring> selected ;	// 一対一で得られた実DDInstall
	// 原宣言の基本名ごとに同じ観測点の実DDInstallをWindowsへ解決させる
	for( const auto &base : bases) {
		std::wstring actual ;	// Windowsが選んだ実在する導入節
		const auto	 resolved =
			// 明示対象の元診断
			resolveActualInstallInventorySection( inf, base, actual, requested) ;
		// 解決した全節が検査済み元選択のいずれかに一意に一致しなければ公開Modelsを返さない
		if( resolved != 0U ||
		   std::ranges::none_of(
			   media.groups,
			   [&]( const auto &group) { return stringsEqual( group.front(), actual) ; }) ||
		   !appendUnique( selected, std::move( actual))) {
			return resolved != 0U ? resolved : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同所有INFの前後hashとWindows Models選択を一つの読取りへ結びます
 * @param[in] workspace 元保護workspaceです
 * @param[in] package 元構造検査です
 * @param[out] identity 完全成功時だけ返す元identityです
 * @param[in] alternatePlatform NULLは現在OS、それ以外は検証済みV3です
 * @param[in] expectedInfSha256 明示target時の元INF hashです
 * @param[out] diagnostic null可の元固定診断です
 * @return 全原identity成立0、元の読取/不一致HRESULTです
 */
//------------------------------------------------------------------------------
static NativeError readPublishedIdentity( const OfficialDownloadWorkspace &workspace,
										 const OfficialInfPackage		 &package,
										 OfficialInfPublishedIdentity	 &identity,
										 PSP_ALTPLATFORM_INFO			  alternatePlatform,
										 std::wstring_view				  expectedInfSha256,
										 InfFailureDiagnostic			 *diagnostic = nullptr)
{
	identity = {} ;
	const auto path =
		// 元保護workspaceだけの読取り位置です
		workspace.path( package.infRelativePath) ;
	// DTOだけを公開identityへ昇格せず、通常構造検査の有限ID列を要求します
	if( path.empty() || package.hardwareIds.empty() || package.hardwareIds.size() > 4096U) {
		markInfFailure( diagnostic, InfDiagnosticStage::INPUT,
					   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		OfficialInfPublishedIdentity parsed ;						// 全成立前は外へ出さない一時値です
		auto error = computeFileSha256( path, parsed.infSha256) ;	// 元原INFの先行identityです
		// 読取り前の原byte未確認を成功へ補完しません
		if( error != 0 || (!expectedInfSha256.empty() && parsed.infSha256 != expectedInfSha256)) {
			markInfFailure( diagnostic,
						   error != 0 ? InfDiagnosticStage::HASH_BEFORE
									  : InfDiagnosticStage::HASH_MATCH,
						   error != 0 ? InfDiagnosticOrigin::UNRECORDED
									  : InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			return error != 0 ? error : nativeErrorFromWin32( ERROR_CRC) ;
		}

		UINT			errorLine{} ;	// 元HINFの構文診断位置です
		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  &errorLine)) ;	// Read-onlyです
		// 実HINFを開けない場合は元Windows codeを返します
		if( inf.get() == INVALID_HANDLE_VALUE) {
			const DWORD openError = GetLastError() ;	// 元HINF失敗直後の原codeです
			markInfFailure( diagnostic, InfDiagnosticStage::IDENTITY_OPEN,
						   InfDiagnosticOrigin::NATIVE_API, openError) ;
			return nativeErrorFromWin32( openError) ;
		}

		error = readInfDirective( inf.get(), L"Version", L"ClassGUID", 1U, parsed.classGuid) ;
		GUID classGuid{} ;	// 元ClassGUIDの構文だけを確認します
		// 不明ClassGUIDをdevice classや名前から生成しません
		if( error != 0 || parsed.classGuid.size() != 38U ||
		   CLSIDFromString( parsed.classGuid.c_str(), &classGuid) != S_OK) {
			markInfFailure( diagnostic,
						   error != 0 ? InfDiagnosticStage::IDENTITY_CLASS_READ
									  : InfDiagnosticStage::IDENTITY_CLASS_VALUE,
						   error != 0 ? InfDiagnosticOrigin::UNRECORDED
									  : InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::vector<std::wstring> ids ;	// 既存readerの元順ID列です
		error = collectHardwareIds( inf.get(), 4096U, ids, &parsed.models,
								   alternatePlatform) ;	// 同readerへだけ新用途を追加します
		// 元構造検査と異なるID列や節不足を公開identityへ変えません
		if( error != 0 || (alternatePlatform == nullptr && ids != package.hardwareIds) ||
		   parsed.models.empty()) {
			markInfFailure( diagnostic,
						   error != 0 ? InfDiagnosticStage::IDENTITY_MODELS
									  : InfDiagnosticStage::IDENTITY_TUPLE,
						   error != 0 ? InfDiagnosticOrigin::UNRECORDED
									  : InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			return error != 0 ? error : nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
		}

		// 私有混在媒体の対象Modelsから、同じ検査済み元選択へ解決できる場合だけ先へ進む
		if( package.collectorSerialMedia) {
			error = checkCollectorSerialTargetSelections( inf.get(), alternatePlatform,
														 *package.collectorSerialMedia) ;
			// 公式対象と同梱検査済み元選択の差を一覧化の成功にしない
			if( error != 0U) {
				markInfFailure( diagnostic, InfDiagnosticStage::IDENTITY_MODELS,
							   InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
				return error ;
			}
		}

		std::wstring finalHash ;	// Metadata読取り後の元INF原byteです
		error = computeFileSha256( path, finalHash) ;
		// 前後hash不一致を部分metadataの正常化で隠しません
		if( error != 0 || finalHash != parsed.infSha256) {
			markInfFailure( diagnostic,
						   error != 0 ? InfDiagnosticStage::HASH_AFTER
									  : InfDiagnosticStage::HASH_MATCH,
						   error != 0 ? InfDiagnosticOrigin::UNRECORDED
									  : InfDiagnosticOrigin::INTERNAL_CONTRACT) ;
			return error != 0 ? error : nativeErrorFromWin32( ERROR_CRC) ;
		}

		identity = std::move( parsed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元packageと一致する現OS公開IDを同HINFから原節名/種別付きで読み取ります
 * @param[in] workspace 保護された元INFを所有するworkspaceです
 * @param[in] package 通常構造検査で得た元INF相対pathと全ID列です
 * @param[out] identity 成功時だけ同INF前後hash/原ClassGUID/全Models節です。失敗時は空です
 * @param[out] diagnostic 同失敗だけの任意leafです。null可、実行判定には使いません
 * @return 有限な原metadataの全一致時0、欠損/上限/改変時は元HRESULTです
 * @note Read-onlyのmetadataです。CAT/member/公式性/実端末照合/取得同意を代替しません
 */
//------------------------------------------------------------------------------
NativeError readOfficialInfPublishedIdentity( const OfficialDownloadWorkspace &workspace,
											 const OfficialInfPackage		 &package,
											 OfficialInfPublishedIdentity	 &identity,
											 InfFailureDiagnostic			 *diagnostic)
{
	// 任意出力の旧leafを同じ評価へ持ち越しません
	if( diagnostic) {
		*diagnostic = {} ;
	}

	const auto error = readPublishedIdentity( workspace, package, identity, nullptr, {},
											 diagnostic) ;	// 元同期結果です
	return finishInfFailure( diagnostic, InfDiagnosticPath::PUBLISHED_IDENTITY, error) ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 対応するWindows x64の指定をSetupAPIの代替プラットフォーム入力へ変換します
 * @param[in] platform OSの版・ビルド・製品種別・アーキテクチャ・SuiteMaskの指定です
 * @return 対応する指定ではSP_ALTPLATFORM_INFO_V3、対象外ではstd::nulloptです
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<SP_ALTPLATFORM_INFO_V3> nativeModelsPlatform(
	const OfficialInfModelsPlatform &platform)
{
	const bool client = platform.productType == VER_NT_WORKSTATION &&
						(platform.buildNumber == 19045U || platform.buildNumber == 26100U ||
						 // 旧client二点と正規floorの明示観測点です
						 platform.buildNumber == 26200U) ;
	const bool server = (platform.productType == VER_NT_SERVER ||
						 platform.productType == VER_NT_DOMAIN_CONTROLLER) &&
						(platform.buildNumber == 14393U || platform.buildNumber == 17763U ||
						 platform.buildNumber == 20348U ||
						 // 明示四Server観測点だけです
						 platform.buildNumber == 26100U) ;
	// 明示targetだけを拡張し、default NULL/currentOSや共通閉包guardを変更しません
	if( platform.majorVersion != 10U || platform.minorVersion != 0U ||
	   platform.processorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 || (!client && !server) ||
	   platform.suiteMask != 0U) {
		return std::nullopt ;
	}

	SP_ALTPLATFORM_INFO_V3 requested{} ;	// 同呼出しだけの明示SDK V3です
	requested.cbSize				= sizeof( requested) ;
	requested.Platform				= VER_PLATFORM_WIN32_NT ;
	requested.MajorVersion			= platform.majorVersion ;
	requested.MinorVersion			= platform.minorVersion ;
	requested.BuildNumber			= platform.buildNumber ;
	requested.ProcessorArchitecture = platform.processorArchitecture ;
	requested.ProductType			= platform.productType ;
	requested.SuiteMask				= platform.suiteMask ;
	requested.Flags					= SP_ALTPLATFORM_FLAGS_SUITE_MASK ;
	return requested ;
}

/** @brief 正規の元行との一致を大小文字を区別せずに記録します */
struct ScopedHardwareIdLess {
	/**
	 * @brief 検査済みの2つのHardware IDをWindows順序で比較します
	 * @param[in] left 左側の元IDです
	 * @param[in] right 右側の元IDです
	 * @return 左側が右側より前にある場合はtrueです
	 */
	bool operator()( const std::wstring &left, const std::wstring &right) const noexcept
	{
		return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
									static_cast<int>( right.size()), TRUE) == CSTR_LESS_THAN ;
	}
} ;
using ScopedHardwareIds = std::map<std::wstring, bool, ScopedHardwareIdLess> ;

/** @brief 一つの元INFを通じたModelsの走査量です */
struct ScopedModelsBudget {
	/// Metadataを検査したModels行の合計です
	std::uint32_t rows{} ;
	/// HardwareとCompatibleの合計フィールド数です
	std::uint32_t ids{} ;
} ;

/** @brief 現OSの全Models行から探すWindows nodeの元フィールドと一意な位置です */
struct ScopedModelsSelection {
	/// Windows nodeが返した未修飾DDInstall基本名です
	std::wstring_view			  basicSection ;
	/// 先頭のHardware IDに続くCompatible IDをWindowsの順序で借用します
	std::span<const std::wstring> nodeIds ;
	/// 同じ基本名と全ID列が成立した元Models節です。未検出時は空です
	std::wstring				  modelSection{} ;
	/// 同節の1から始まる元行位置です。未検出時は0です
	std::uint32_t				  modelRow{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元Modelsのダイジェストに符号なし32-bit LEの区切りを加えます
 * @param[in,out] bytes 所有する節単位の正規バイト列です
 * @param[in] value フィールド数または文字数です
 */
//------------------------------------------------------------------------------
void appendModelsNumber( std::string &bytes, const std::uint32_t value)
{
	// 32ビット値を下位から8ビットずつ、ダイジェスト用の固定順序で追加します
	for( unsigned shift = 0U; shift < 32U; shift += 8U) {
		bytes.push_back( static_cast<char>( (value >> shift) & 0xFFU)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsが展開した一フィールドを長さ付きUTF-16LEで保持します
 * @param[in,out] bytes 所有する節単位の正規バイト列です
 * @param[in] value 構文と長さを検証済みの元フィールドです
 */
//------------------------------------------------------------------------------
void appendModelsField( std::string &bytes, const std::wstring_view value)
{
	static_assert( sizeof( wchar_t) == 2U) ;
	appendModelsNumber( bytes, static_cast<std::uint32_t>( value.size())) ;
	bytes.append( reinterpret_cast<const char *>( value.data()), value.size() * sizeof( wchar_t)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsが選んだ節名を同じManufacturer行の原宣言で確認します
 * @param[in,out] manufacturer SetupAPIの元Manufacturer行です
 * @param[in] selected Windowsが同じ行から選んだ節名です
 * @return 一致時0、欠損や読取り失敗はHRESULTです
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyScopedModelsDeclaration( INFCONTEXT			   &manufacturer,
														const std::wstring_view selected)
{
	const DWORD	 fields = SetupGetFieldCount( &manufacturer) ;	// 元基本名と装飾です
	std::wstring base ;											// 宣言された元基本名です
	// Manufacturerの元行から安全に取得できた単一の基本名と有限の装飾欄を要求します
	if( fields == 0U || fields > 32U || readInfField( manufacturer, 1U, base) != 0 ||
	   !validInstallInventorySectionName( base)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	bool declared = stringsEqual( selected, base) ;	// 無装飾名は同じ宣言だけで成立します
	// Manufacturer行が宣言した各装飾を走査してWindowsの選択名を確認します
	for( DWORD field = 2U; field <= fields; ++field) {
		std::wstring decoration ;	// Manufacturerの元装飾です
		// 読取り不能または安全に照合できない装飾を含む元行を拒否します
		if( readInfField( manufacturer, field, decoration) != 0 ||
		   !validInstallInventorySectionName( decoration)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		declared = declared || stringsEqual( selected, base + L"." + decoration) ;
	}

	return declared ? 0 : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsが選んだ節の全行を読み、公式Hardware欄の位置と全行の証拠を作ります
 * @param[in] inf 同期領域に保持した元HINFです
 * @param[in,out] scope 全節を通じて公式対象の一意性を確認します
 * @param[in,out] budget 元INF全体の走査予算です
 * @param[in,out] section 元節名と完了時の全行証拠です
 * @param[in] cancellation 同期中の取消し照会です
 * @param[in,out] selection 全選択節の中で一意に成立したnodeの位置です。nullなら照合しません
 * @return 全行の証拠が成立した場合は0、読取りや上限の失敗はHRESULTです
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readScopedModelsSection( const HINF inf, ScopedHardwareIds &scope,
												  ScopedModelsBudget			 &budget,
												  OfficialInfScopedModelsSection &section,
												  const std::function<bool()>	 &cancellation,
												  ScopedModelsSelection			 *selection)
{
	const LONG count = SetupGetLineCountW( inf, section.modelSection.c_str()) ;	// 元節の確定行数です
	// 行のない元節を実際の対象行として扱いません
	if( count <= 0L) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	section.modelRows = static_cast<std::uint32_t>( count) ;
	// 全観測点で許可するModels行の残枠を超える節を拒否します
	if( section.modelRows > OFFICIAL_SCOPED_MODELS_MAX_ROWS - budget.rows) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	budget.rows += section.modelRows ;
	INFCONTEXT line{} ;	// 一度開いた元節の現在行です
	// 最初の元行を取得できない場合は宣言件数の途中結果を残しません
	if( const auto error = maintenanceLineAt( inf, section.modelSection, 0L, line) ; error != 0) {
		return error ;
	}

	std::string bytes{"DRIVERCRATE_MODELS_V1"} ;	// 同じ型付き元行だけに使う証拠の領域です
	bytes.push_back( '\0') ;
	// 元行番号を維持したまま宣言した件数の全Models行を確認します
	for( std::uint32_t row = 1U; row <= section.modelRows; ++row) {
		// 元Models行の読取りを続ける前に取消しを反映します
		if( cancellation && cancellation()) {
			return nativeErrorFromWin32( ERROR_CANCELLED) ;
		}

		const DWORD	 fields = SetupGetFieldCount( &line) ;	// 基本節と各型のIDです
		std::wstring value ;								// 一フィールドずつ再利用します
		// 件数の不足・上限超過や表示欄の読取り失敗がある行を除外せず拒否します
		if( fields < 2U || fields > MAXIMUM_INSTALL_INVENTORY_FIELDS ||
		   readInfField( line, 0U, value) != 0 || value.empty()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		const auto idCount = fields - 1U ;	// 第2フィールド以降だけを数えます
		// IDの全フィールドを読むための残枠を確認します
		if( idCount > OFFICIAL_SCOPED_MODELS_MAX_ID_FIELDS - budget.ids) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		budget.ids += idCount ;
		section.idFields += idCount ;
		std::wstring installBase ;	// 同元行の第1フィールドです
		// 読取り可能で正規の導入基本節名だけを照合に使用します
		if( readInfField( line, 1U, installBase) != 0 ||
		   !validInstallInventorySectionName( installBase)) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		appendModelsNumber( bytes, fields) ;
		appendModelsField( bytes, installBase) ;
		// Compatible欄を含めて順序と件数が一致する元行だけを候補にします
		bool selectedRow = selection && idCount == selection->nodeIds.size() &&
						   stringsEqual( installBase, selection->basicSection) ;
		// 元の全IDを順に読み、digestとnode照合の両方に同じ値を使います
		for( DWORD field = 2U; field <= fields; ++field) {
			const auto error = readInfField( line, field, value) ;	// Windows展開後の元値です
			// 解析できないIDを除外せず元のModels全行を検査します
			if( error != 0 || !validNativeModelsId( value)) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			// 証拠のフィールド位置でHardwareとCompatibleの種別を保持します
			appendModelsField( bytes, value) ;
			selectedRow = selectedRow && stringsEqual( value, selection->nodeIds[field - 2U]) ;
			// 完全な公式対象との一致はHardware ID欄でのみ記録します
			if( field == 2U) {
				const auto target = scope.find( value) ;	// 公式対象だけを元Hardware欄から探します
				// 公式の対象に含まれるIDについて元位置を記録します
				if( target != scope.end()) {
					// 同じ公式対象IDに複数の元行を割り当てません
					if( target->second) {
						return nativeErrorFromWin32( ERROR_DUP_NAME) ;
					}

					target->second = true ;
					section.matches.push_back( {row, value, installBase}) ;
				}
			}
		}

		// 公式対象外を含む全行で同じnodeの元位置が複数なら確定しません
		if( selectedRow) {
			// 別の元行にも同じDDInstallと型付きID列があれば選択され得る位置は不明です
			if( selection->modelRow != 0U) {
				return nativeErrorFromWin32( ERROR_DUP_NAME) ;
			}

			selection->modelSection = section.modelSection ;
			selection->modelRow		= row ;
		}

		// 確定行数の手前で列挙が止まった場合は部分証拠を破棄します
		if( row < section.modelRows) {
			SetLastError( ERROR_SUCCESS) ;
			// 宣言件数まで次の元行を列挙できない場合は不整合とします
			if( !SetupFindNextLine( &line, &line)) {
				const auto error = GetLastError() ;	// 行数の途中の読取り失敗です
				return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
			}
		}
	}

	return computeDriverContainerSha256( bytes, section.orderedRowsSha256) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示OS用のすべての元Models節を読取り、部分成功を残しません
 * @param[in] inf 同期処理中だけ借用する元HINFです
 * @param[in] platform 採用済み観測点です。nullは現在OSです
 * @param[in,out] scope 公式対象の出現を全節にわたり保持します
 * @param[out] sections 全行と公式対象を検査した元節です
 * @param[in] cancellation 同期中の取消し照会です
 * @param[in,out] selection 全選択節の中で一意に成立したnodeの位置です。nullなら照合しません
 * @return 全選択節を通じて公式対象全件が一意に成立した場合は0です
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readScopedModelsSections(
	const HINF inf, const PSP_ALTPLATFORM_INFO platform, ScopedHardwareIds &scope,
	std::vector<OfficialInfScopedModelsSection> &sections,
	const std::function<bool()> &cancellation, ScopedModelsSelection *selection)
{
	const LONG count = SetupGetLineCountW( inf, L"Manufacturer") ;	// 当該INFの全宣言数です
	// Manufacturerの全行が得られる有限の入力だけで照合します
	if( count <= 0L || count > 4096L) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	ScopedModelsBudget budget ;	// 同じINFの全Windows選択節へ適用します
	// Manufacturerの全行を元順に読み、明示OSに対するWindowsの実選択を求めます
	for( LONG index = 0L; index < count; ++index) {
		// 各Manufacturer行の処理前に取消しを確認します
		if( cancellation && cancellation()) {
			return nativeErrorFromWin32( ERROR_CANCELLED) ;
		}

		INFCONTEXT manufacturer{} ;	// SetupAPIが返す元宣言です
		// Manufacturer行の読み取りに失敗した場合に部分一覧を返しません
		if( const auto error = maintenanceLineAt( inf, L"Manufacturer", index, manufacturer) ;
		   error != 0) {
			return error ;
		}

		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS> name{} ;	// 有限の元選択節名です
		SetLastError( ERROR_SUCCESS) ;
		// Windowsから選択節を得られない場合は対象外と失敗を区別します
		if( !official_inf_models_native_detail::actualModelsSection(
			   &manufacturer, platform, name.data(), static_cast<DWORD>( name.size()), nullptr,
			   nullptr)) {
			const auto error = GetLastError() ;	// 対象外と読取り失敗を区別します
			// 通常の適用外以外の診断は他の節が成功しても保持します
			if( error != ERROR_NO_COMPAT_DRIVERS && error != ERROR_SECTION_NOT_FOUND) {
				return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
			}

			continue ;
		}

		OfficialInfScopedModelsSection section ;	// 全行成功後だけ出力に加えます
		section.modelSection = name.data() ;
		// 有限の件数、正規の節名、元宣言の一意性を確認してから採用します
		if( sections.size() >= OFFICIAL_SCOPED_MODELS_MAX_SECTIONS ||
		   !validInstallInventorySectionName( section.modelSection) ||
		   std::ranges::any_of( sections, [&section]( const auto &previous) {
			   // 一時の節名を借用し、同じ元節の多重宣言を拒否します
			   return stringsEqual( previous.modelSection, section.modelSection) ;
		   })) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 現在の選択名が同じManufacturer行に明記されているかを確認した診断値
		auto error = verifyScopedModelsDeclaration( manufacturer, section.modelSection) ;
		// 元行の宣言が一致した場合だけ実選択の内容を読みます
		if( error == 0) {
			error = readScopedModelsSection( inf, scope, budget, section, cancellation, selection) ;
		}

		// 選択節の検査に失敗した場合は同時に検査した他の節も確定しません
		if( error != 0) {
			return error ;
		}

		sections.push_back( std::move( section)) ;
	}

	return !sections.empty() && std::ranges::all_of( scope,
													[]( const auto &entry) {
														// 各公式Hardware IDが全選択節のHardware欄に見つかったことを確認します
														return entry.second ;
													})
			   ? 0
			   : nativeErrorFromWin32( ERROR_NOT_FOUND) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同所有INFのhashを固定し、collectorの明示client/Server観測点でModelsを読みます
 * @param[in] workspace 元保護workspaceです
 * @param[in] package 元構造検査済みpackageです
 * @param[in] platform 採用済みAMD64のOSとbuildです
 * @param[in] expectedInfSha256 同じ現OS構造検査から得た元INF hashです
 * @param[out] identity 成功した同targetの元Modelsです。失敗時は空です
 * @return 実Windows読取り成功0、不明targetや改変時は元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError readOfficialInfPublishedIdentityForPlatform( const OfficialDownloadWorkspace &workspace,
														const OfficialInfPackage		&package,
														const OfficialInfModelsPlatform &platform,
														const std::wstring_view expectedInfSha256,
														OfficialInfPublishedIdentity &identity)
{
	identity	   = {} ;
	auto requested = nativeModelsPlatform( platform) ;	// 同呼出しだけの明示観測点です
	// 信頼できる明示観測点と元INFのSHA-256指定がそろう場合だけ確認します
	if( !requested || expectedInfSha256.size() != 64U) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	return readPublishedIdentity( workspace, package, identity,
								 reinterpret_cast<PSP_ALTPLATFORM_INFO>( &*requested),
								 expectedInfSha256) ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 同じ元INFに属する全Modelsの証拠と公式対象の元位置を確認します
 * @param[in] workspace 展開済みの元INFを保持する保護領域です
 * @param[in] infRelativePath 元INFの同領域内の相対パスです
 * @param[in] expectedInfSha256 読取り前後を固定する元INF SHA-256です
 * @param[in] platform 採用済みAMD64観測点です。nullは現在OSです
 * @param[in] hardwareScope 公式配布の完全Hardware IDの集合です
 * @param[out] evidence 全行の証拠です。失敗または取消し時は空です
 * @param[in] cancellation 同期読取りの取消し照会です
 * @param[in,out] selection 任意のnode全フィールドと一意な元位置です。nullなら照合しません
 * @return 全行を確認できた場合は0、最初の失敗のHRESULTです
 * @note 元CATの信頼や、取得・配置・導入の許可は発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readScopedModelsEvidence(
	const OfficialDownloadWorkspace &workspace, const std::wstring_view infRelativePath,
	const std::wstring_view expectedInfSha256, const OfficialInfModelsPlatform *platform,
	const std::span<const std::wstring> hardwareScope, OfficialInfScopedModelsEvidence &evidence,
	const std::function<bool()> &cancellation, ScopedModelsSelection *selection)
{
	evidence = {} ;
	auto requested =
		platform ? nativeModelsPlatform( *platform) : std::nullopt ;	// 明示時だけ変換します
	// 観測点、元INFの識別、公式対象の有限集合を受理できる場合だけファイル照合へ進みます
	if( (platform && !requested) || expectedInfSha256.size() != 64U || hardwareScope.empty() ||
	   hardwareScope.size() > OFFICIAL_SCOPED_MODELS_MAX_TARGETS ||
	   lowerExtension( infRelativePath) != L".inf" ||
	   expectedInfSha256.find_first_not_of( L"0123456789abcdef") != std::wstring_view::npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		ScopedHardwareIds scope ;	// 公式対象と各Hardware欄の一致を結びます
		// 公式対象の完全IDを一件ずつ登録して元行の一致有無を管理します
		for( const auto &id : hardwareScope) {
			// 不正なIDや重複対象を除いて残りだけを成功扱いしません
			if( !validNativeModelsId( id) || !scope.emplace( id, false).second) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}
		}

		// 元ファイルを開く前に取消しを確認します
		if( cancellation && cancellation()) {
			return nativeErrorFromWin32( ERROR_CANCELLED) ;
		}

		const auto path = workspace.path( infRelativePath) ;	// 元保護領域だけを使用します
		WIN32_FILE_ATTRIBUTE_DATA attributes{} ;				// 同INFの通常ファイル容量です
		// 検査済み閉包で安全な元パスを得られなければ読み取りません
		if( path.empty()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		// 元INFの属性を読めない場合は診断を保持して中断します
		if( !GetFileAttributesExW( path.c_str(), GetFileExInfoStandard, &attributes)) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 再解析先、ディレクトリ、空または上限超過のファイルを対象にしません
		if( (attributes.dwFileAttributes &
			(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
		   attributes.nFileSizeHigh != 0U || attributes.nFileSizeLow == 0U ||
		   attributes.nFileSizeLow > 4U * 1024U * 1024U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 元の実バイト数と期待するSHA-256を一緒に固定する検証ポリシー
		const OfficialFileMetadataPolicy filePolicy{attributes.nFileSizeLow, expectedInfSha256} ;
		// 元ファイルを開く前にサイズとハッシュを照合した診断値
		auto							 error = verifyOfficialFileMetadata( path, filePolicy) ;
		// 公式の証拠に一致しない元ファイルをSetupAPIへ渡しません
		if( error != 0) {
			return error ;
		}

		// 作業領域の元INFだけをキャッシュに頼らず開く所有ハンドル
		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;
		// 元ファイルをINFとして開けない場合はSetupAPIの診断を返します
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		OfficialInfScopedModelsEvidence parsed ;	// 成功時だけ同じ元hashと全証拠を出します
		error = readScopedModelsSections(
			inf.get(), requested ? reinterpret_cast<PSP_ALTPLATFORM_INFO>( &*requested) : nullptr,
			scope, parsed.sections, cancellation, selection) ;
		// 元Modelsと公式の一致位置が確定しなかった場合は結果を作りません
		if( error != 0) {
			return error ;
		}

		error = verifyOfficialFileMetadata( path, filePolicy) ;
		// 読取り期間に元ファイルが変化した場合や取消しが到達した場合は証拠を確定しません
		if( error != 0 || (cancellation && cancellation())) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_CANCELLED) ;
		}

		parsed.infSha256 = expectedInfSha256 ;
		// 明示観測点を使った検査では、その指定を元の証拠に保持します
		if( platform) {
			parsed.platform = *platform ;
		}

		evidence = std::move( parsed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 署名付きの元Models節証拠と現OSで読み直した同じ節を比較します
 * @param[in] expected 上流で署名との結合を確認済みの元節です
 * @param[in] actual Windowsが現OS用に選択して読み取った元節です
 * @return 元節名、行数、全型付き行のdigest、元対象の順序と内容が厳密に同じ場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sameScopedModelsSection( const OfficialInfScopedModelsSection &expected,
										   const OfficialInfScopedModelsSection &actual)
{
	return expected.modelSection == actual.modelSection && expected.modelRows == actual.modelRows &&
		   expected.idFields == actual.idFields &&
		   expected.orderedRowsSha256 == actual.orderedRowsSha256 &&
		   std::ranges::equal( expected.matches, actual.matches,
							  []( const auto &first, const auto &second) {
								  // 署名に結ぶ元証拠は綴りと順序を変更せず比較します
								  return first.modelRow == second.modelRow &&
										 first.hardwareId == second.hardwareId &&
										 first.installBase == second.installBase ;
							  }) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同じ元INFに属する全Modelsの証拠と公式対象の元位置を確認します
 * @param[in] workspace 展開済みの元INFを保持する保護領域です
 * @param[in] infRelativePath 元INFの同領域内の相対パスです
 * @param[in] expectedInfSha256 読取り前後を固定する元INF SHA-256です
 * @param[in] platform 採用済みAMD64観測点です。nullは現在OSです
 * @param[in] hardwareScope 公式配布の完全Hardware IDの集合です
 * @param[out] evidence 全行の証拠です。失敗または取消し時は空です
 * @param[in] cancellation 同期読取りの取消し照会です
 * @return 全行を確認できた場合は0、最初の失敗のHRESULTです
 * @note 元CATの信頼や、取得・配置・導入の許可は発行しません
 */
//------------------------------------------------------------------------------
NativeError readOfficialInfScopedModels( const OfficialDownloadWorkspace	   &workspace,
										const std::wstring_view				infRelativePath,
										const std::wstring_view				expectedInfSha256,
										const OfficialInfModelsPlatform	   *platform,
										const std::span<const std::wstring> hardwareScope,
										OfficialInfScopedModelsEvidence	   &evidence,
										const std::function<bool()>		   &cancellation)
{
	return readScopedModelsEvidence( workspace, infRelativePath, expectedInfSha256, platform,
									hardwareScope, evidence, cancellation, nullptr) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現OSが選ぶ元Modelsの全行から、Windows nodeの厳密な一行を署名済みの元位置に結びます
 * @param[in] workspace 同じ元INFを保持する保護領域です
 * @param[in] package 上流で署名済み原証拠と結合した同INFの基本driverです
 * @param[in] modelsSection 同証拠の選択対象が指定する元Models節です
 * @param[in] basicSection Windows nodeが返した未修飾DDInstall基本名です
 * @param[in] nodeIds 同nodeの先頭Hardware IDとそれに続く全Compatible IDです。順序を維持します
 * @param[out] selected 元証拠の一意な行です。失敗時は空です
 * @return 同じ元INFの前後hashと現OSの全証拠・対象行が一致した場合は0、失敗はHRESULTです
 * @pre selectedは入力の領域を参照しません
 * @note 読取り専用です。端末の現在Hardware ID、Windowsの順位や実行権限は呼出し側で検証します
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialInfScopedModelSelection( const OfficialDownloadWorkspace	 &workspace,
												  const OfficialInfPackage			 &package,
												  const std::wstring_view			  modelsSection,
												  const std::wstring_view			  basicSection,
												  const std::span<const std::wstring> nodeIds,
												  OfficialInfScopedModelMatch		 &selected)
{
	selected = {} ;
	// 元証拠のないINFや別のdriver役割から対象を作りません
	if( !package.scopedModels || package.role != DriverPlanRole::BASE_DRIVER) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 元nodeの型付き完全ID列を上限内で維持します
	if( !validInstallInventorySectionName( modelsSection) ||
	   !validInstallInventorySectionName( basicSection) || nodeIds.empty() ||
	   nodeIds.size() >= MAXIMUM_INSTALL_INVENTORY_FIELDS ||
	   !std::ranges::all_of( nodeIds, validNativeModelsId)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto &proof = *package.scopedModels ;	// 同元INFと全公式対象を固定した証拠です
		// 不足する節や上限外の元証拠を使用しません
		if( proof.sections.empty() || proof.sections.size() > OFFICIAL_SCOPED_MODELS_MAX_SECTIONS) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		std::vector<std::wstring> hardwareScope ;	// 元証拠の対象Hardware IDだけを再読取りに渡します
		// 全節の元対象を同じ有限範囲で読み直します
		for( const auto &section : proof.sections) {
			// 元対象数の上限を節ごとに作り直しません
			if( section.matches.size() > OFFICIAL_SCOPED_MODELS_MAX_TARGETS - hardwareScope.size()) {
				return static_cast<NativeError>( E_ACCESSDENIED) ;
			}

			// 証拠にある全対象を同じ型のHardware欄から引き直します
			for( const auto &row : section.matches) {
				// 不正な元Hardware値を再読取りの起点にしません
				if( !validNativeModelsId( row.hardwareId)) {
					return static_cast<NativeError>( E_ACCESSDENIED) ;
				}

				hardwareScope.push_back( row.hardwareId) ;
			}
		}

		const auto path = workspace.path( package.infRelativePath) ;	// 同じ保護領域上の元INFです
		OfficialMappedFile original ;									// 前後hashとModels読取りの間、元INFと先祖を固定します
		auto error = original.open( path, 4U * 1024U * 1024U) ;			// 同一元byteの読取り固定です
		// 元byteを固定できない場合に別ファイルを読みません
		if( error != 0) {
			return error ;
		}

		ScopedModelsSelection			node{basicSection, nodeIds} ;	// 全有効節から照合するnodeです
		OfficialInfScopedModelsEvidence current ;						// 現OS用に読み直した全型付き行の証拠です
		error = readScopedModelsEvidence( workspace, package.infRelativePath, proof.infSha256,
										 nullptr, hardwareScope, current, {}, &node) ;
		// 読取失敗や重複があれば部分結果を扱いません
		if( error != 0) {
			return error ;
		}

		// 別OS向けの元節や、同じ型付き行がない選択を元証拠へ結びません
		if( node.modelRow == 0U || !stringsEqual( node.modelSection, modelsSection) ||
		   current.infSha256 != proof.infSha256 ||
		   !std::ranges::equal( proof.sections, current.sections, sameScopedModelsSection)) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// Windowsが選んだ元Models節に対応する署名済み節の位置
		const auto section = std::ranges::find( proof.sections, node.modelSection,
											   &OfficialInfScopedModelsSection::modelSection) ;
		// 一致した元節からだけ元行番号を探します
		if( section == proof.sections.end()) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// 同じ節内でWindows互換ノードが指定した元行の位置
		const auto match = std::ranges::find( section->matches, node.modelRow,
											 &OfficialInfScopedModelMatch::modelRow) ;
		// Compatible欄だけの別名や元証拠の対象にない行は返しません
		if( match == section->matches.end() || !stringsEqual( match->hardwareId, nodeIds.front()) ||
		   !stringsEqual( match->installBase, basicSection)) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		OfficialInfScopedModelMatch verified = *match ;	// 全検証とcopy完了後だけ結果を出します
		selected							 = std::move( verified) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元INFを固定して公式Modelsの同じ行とWindows導入節の関係を読み取ります
 * @param[in] workspace 元INFと全参照を保持する管理者保護領域です
 * @param[in] entries 元署名を確認した閉包の全ファイルと全潜在importです
 * @param[in] original 同元INFに結合済みの原証拠と内容結果です
 * @param[in] modelsSection 元署名レコードの対象Models節です
 * @param[in] basicSection 端末のWindows nodeが返したDDInstall基本名です
 * @param[in] nodeIds 同じnodeのHardware IDと全Compatible IDを型の順に並べた列です
 * @param[out] matchedRow 確定した公式対象の元行です。失敗時は空です
 * @param[out] selected 照合した同じINFの選択関係です。失敗時は空です
 * @return 原行と同じ選択の関係に成功した場合0、元診断はHRESULTです
 * @pre 入力と出力を別に保持し、呼出側で元索引と全閉包の署名を確認します
 * @note この読取りはWindowsのnode選択を変更せず、作用や導入の許可を発行しません
 */
//------------------------------------------------------------------------------
NativeError inspectSelectedScopedInfRelations(
	const OfficialDownloadWorkspace &workspace, const std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &original, const std::wstring_view modelsSection,
	const std::wstring_view basicSection, const std::span<const std::wstring> nodeIds,
	OfficialInfScopedModelMatch &matchedRow, OfficialInfPackage &selected)
{
	matchedRow = {} ;
	// 元の検査済み結果を選択結果の書込みで上書きしないようエイリアスを拒否します
	if( &original == &selected) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	selected = {} ;
	// 収集時の元Modelsと管理者保護領域がそろう基本選択だけを対象にします
	if( !original.scopedModels ||
	   original.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
	   original.requiredNullCompanion || original.requiredRegistryOnlyCompanion ||
	   workspace.protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	try {
		// 元INFの完全相対位置と実ハッシュを照合する閉包のメンバー
		const auto member =
			std::ranges::find( entries, original.infRelativePath, &OfficialZipEntry::relativePath) ;
		// 元INFを証拠と同じ閉包から確定できなければ選択結果を発行しません
		if( member == entries.end() || member->sha256 != original.scopedModels->infSha256) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		// 保護された領域で元INFに割り当てたパス
		const auto		   path = workspace.path( original.infRelativePath) ;
		OfficialMappedFile pinned ;	// 元行の照合と必要関係の読取りの間、元byteを固定します
		// 元INFを固定ハンドルで借用できたかを示す診断値
		auto			   error = pinned.open( path, 4U * 1024U * 1024U) ;
		// 元ファイルを固定できないままWindowsの選択節を読みません
		if( error != 0U) {
			return error ;
		}

		OfficialInfScopedModelMatch row ;	// 同じ元INFの全Modelsを照合した実選択です
		error = verifyOfficialInfScopedModelSelection( workspace, original, modelsSection,
													  basicSection, nodeIds, row) ;
		// 元の検査で確認した内容に一致しないファイルを開きません
		if( error != 0U) {
			return error ;
		}

		// SetupAPIで同じ元ファイルを選択照合に使う所有ハンドル
		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;
		// 元INFを読み込めない場合は実選択を作らず診断を保持します
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		error = readSelectedInfRelations( inf.get(), workspace, entries, original, row.installBase,
										 &row, selected) ;
		// 同じ元行への照合が成立した場合だけ一致情報を出力へ渡します
		if( error == 0U) {
			matchedRow = std::move( row) ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 選択INFが指定する同階層の元CATを非実行で特定します
 * @param[in] workspace 展開済みの元INFを保持する領域です
 * @param[in] infRelativePath 所有済みの元INF相対パスです
 * @param[out] catalogRelativePath 同位置の元CAT相対パスです。失敗時は空です
 * @return 安全な元CAT名が成立した場合は0、読取り失敗はHRESULTです
 * @note 展開前の名前の読取りです。Windows署名やCAT所属をまだ確認しません
 */
//------------------------------------------------------------------------------
NativeError readOfficialInfCatalogPath( const OfficialDownloadWorkspace &workspace,
									   const std::wstring_view			infRelativePath,
									   std::wstring					   &catalogRelativePath)
{
	catalogRelativePath.clear() ;
	try {
		const auto path = workspace.path( infRelativePath) ;	// 同アーカイブ内の元INFだけです
		// 元の保護領域内でINFを示す有効な入力だけを開きます
		if( path.empty() || lowerExtension( infRelativePath) != L".inf") {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		OfficialMappedFile origin ;	// Windows読取り中だけ元INFを固定します
		// 元INFを上限付き読取り用に固定した診断値
		const auto		   error = origin.open( path, 4U * 1024U * 1024U) ;
		// 元INFを固定できない場合はCATの特定に進みません
		if( error != 0) {
			return error ;
		}

		// 元宣言を現在のWindows規則で読む所有INFハンドル
		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;
		// CATの元宣言を読む前に、INFを開いた診断を確認します
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		std::wstring name ;	// Versionが指定した元CATの単一名です
		// 署名カタログの指定を元のVersion節から得た診断値
		const auto	 catalogError = readCatalogFile( inf.get(), name) ;
		// 元CATの宣言が取得できない場合に既知の名前で補完しません
		if( catalogError != 0) {
			return catalogError ;
		}

		const auto separator = infRelativePath.find_last_of( L'\\') ;	// 元INFの親です
		// 同じ階層のCATを特定するための元INFの親相対位置。直下なら空
		const auto parent	= separator == infRelativePath.npos
								  ? std::wstring_view{}
								  : infRelativePath.substr( 0U, separator) ;
		catalogRelativePath = joinRelativePath( parent, name) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

namespace {
// USB Bluetoothで使用する正式なクラス名とGUID
constexpr std::array<std::wstring_view, 2U> BLUETOOTH_CLASS{
	L"Bluetooth", L"{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}"} ;

//------------------------------------------------------------------------------
/**
 * @brief 署名済み元INFの全Modelsと公式Hardware欄の結合を収集構造に保持します
 * @param[in] workspace 元INFとCATを持つ同じ保護領域です
 * @param[in] request 元展開ハッシュと公式配布対象です
 * @param[in] infPath 選択した絶対INFパスです
 * @param[in] inf 同一の固定済み元INFを開いたSetupAPI handleです
 * @param[in,out] catalog 元CATを後続の構造検査終了まで固定する所有者です
 * @param[in,out] package 同INFの構造と、成功時の元Models証拠です
 * @return 読取りと初期署名が成立した場合は0、最初の失敗はHRESULTです
 * @pre 呼出し側が元INFをwrite/delete共有なしで固定しています
 * @note 先行署名はINF単体です。最終の全参照ファイル署名は別に必要です
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectAuthenticatedScopedModels(
	const OfficialDownloadWorkspace &workspace, const OfficialInfScopedModelsRequest &request,
	const std::wstring_view infPath, const HINF inf, OfficialMappedFile &catalog,
	OfficialInfPackage &package)
{
	const auto catalogPath = workspace.path( package.catalogRelativePath) ;	// 元Version指定先です
	// 元CATを読取り中に固定した診断値
	auto	   error = catalog.open( catalogPath, 512ULL * 1024ULL * 1024ULL) ;
	// 元CATの所在を固定できないまま元INFとの関係を作りません
	if( error != 0) {
		return error ;
	}

	error =
		verifyOfficialFileMetadata( catalogPath, {catalog.bytes().size(), request.catalogSha256}) ;
	// 元CATの検査が通った場合だけ元INFのハッシュを続けて照合します
	if( error == 0) {
		error = verifyOfficialFileMetadata( infPath, {std::nullopt, request.infSha256}) ;
	}

	// INFとCATのいずれかが元証拠と異なる場合はModelsの照合を始めません
	if( error != 0) {
		return error ;
	}

	OfficialInfPackage selectedOnly ;	// 先行段階では元INFとCATの所属だけを確認します
	selectedOnly.infRelativePath	 = package.infRelativePath ;
	selectedOnly.catalogRelativePath = package.catalogRelativePath ;
	error							 = verifyWindowsInfPackageIntegrity( workspace, selectedOnly) ;
	// 元Modelsの検査で戻った診断を保持し、部分的な対象一覧を返しません
	if( error != 0) {
		return error ;
	}

	// 元INFの最初のClassGuid宣言を借用するSetupAPIの行情報
	INFCONTEXT originalClass{} ;
	// ClassGuidの追加宣言がないかを確認する行情報
	INFCONTEXT duplicateClass{} ;
	// 元INFから読み取ったクラス識別子。比較に成功してから採用する
	GUID	   identifier{} ;
	// 元GUIDを一意に読めない場合は名前やWindowsのクラス表から補いません
	if( !SetupFindFirstLineW( inf, L"Version", L"ClassGUID", &originalClass) ||
	   SetupGetFieldCount( &originalClass) != 1U ||
	   SetupFindNextMatchLineW( &originalClass, L"ClassGUID", &duplicateClass) ||
	   readInfField( originalClass, 1U, package.classGuid) != 0 || package.classGuid.size() != 38U ||
	   CLSIDFromString( package.classGuid.c_str(), &identifier) != S_OK ||
	   IsEqualGUID( identifier, GUID_NULL)) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	OfficialInfScopedModelsEvidence evidence ;	// 署名成立後だけ拡張Modelsを読みます
	error = readOfficialInfScopedModels( workspace, package.infRelativePath, request.infSha256,
										request.platform, request.hardwareIds, evidence,
										request.cancellation != nullptr ? *request.cancellation
																		: std::function<bool()>{}) ;
	// クラスと元媒体を確定できない場合は公開候補に使う構造を返しません
	if( error != 0) {
		return error ;
	}

	// 署名済み証拠の全Models節から公式一致行を抽出します
	for( const auto &section : evidence.sections) {
		// 元節との関係を保持したまま、各一致行の完全Hardware IDを候補に加えます
		for( const auto &match : section.matches) {
			package.hardwareIds.push_back( match.hardwareId) ;
		}
	}

	package.scopedModels = std::move( evidence) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 完全なUSB VIDとPIDを持つ元Hardware IDを識別する
 * @param[in] id 公式明細と署名付きModelsで一致したID
 * @return VIDとPIDの二要素を完全に持つ場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isUsbVidPid( std::wstring_view id)
{
	constexpr std::wstring_view HEX_DIGITS = L"0123456789abcdefABCDEF" ;	// USB識別子の各桁
	return id.size() == 21U && stringsEqual( id.substr( 0U, 8U), L"USB\\VID_") &&
		   stringsEqual( id.substr( 12U, 5U), L"&PID_") &&
		   id.substr( 8U, 4U).find_first_not_of( HEX_DIGITS) == id.npos &&
		   id.substr( 17U, 4U).find_first_not_of( HEX_DIGITS) == id.npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元INFに列挙した役割の節だけが一度ずつ存在することを確認する
 * @param[in] inf 同期中に借用する元HINF
 * @param[in] permitted 元構造で確認する少数の必須節名
 * @return 全節が元構造と一致すれば0、欠損・追加・重複・読取失敗はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyExactInfSections( HINF								inf,
												 std::span<const std::wstring_view> permitted)
{
	const auto			  unsupported = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;	// 元形式の不一致
	std::array<bool, 24U> seen{} ;														// 各役割の元節を一度読んだ場合だけtrue
	// 上限の外にある別構造を部分成功にしない
	if( permitted.size() > seen.size()) {
		return E_INVALIDARG ;
	}

	// 許可された元の節数まで確認し、さらに一回の列挙で正常終端を検査する
	for( UINT index = 0U; index <= permitted.size(); ++index) {
		std::array<wchar_t, MAXIMUM_MODEL_SECTION_CHARACTERS + 1U> name{} ;	// 列挙した元節名
		// 正常終端だけを全節の読み取り成功として採用する
		if( !SetupEnumInfSectionsW( inf, index, name.data(), static_cast<UINT>( name.size()),
								  nullptr)) {
			const auto error = GetLastError() ;	// 元列挙の終端又は読取り失敗
			return error == ERROR_NO_MORE_ITEMS ? (index == permitted.size() ? 0U : unsupported)
												: nativeErrorFromWin32( error) ;
		}

		const auto found = std::ranges::find_if( permitted, [&]( const auto section) {
			return stringsEqual( section, name.data()) ;
		}) ; // 列挙した元節と一致する役割だけを選ぶ
		// 不明な節や、二つの役割が同じ名前を持つ節では完全な集合を得られない
		if( found == permitted.end() ||
		   std::exchange( seen[static_cast<std::size_t>( found - permitted.begin())], true)) {
			return unsupported ;
		}
	}

	return unsupported ;
}

//------------------------------------------------------------------------------
/**
 * @brief USB Bluetoothの公式対象を自身の媒体がない三つの同梱委譲節へ結ぶ
 * @param[in] inf 元CAT所属とハッシュを確認した同じ元INFを読み取る有効なハンドル
 * @param[in] entries 同じCABから得た元ファイルの一覧
 * @param[in,out] package 元署名と公式範囲を確認済みの基本INF。全検査成功時に元選択を保存する
 * @return 元選択と空媒体が一致した場合0、未対応の作用・別の対象・読取り失敗時はHRESULT
 * @note 同梱INFの署名や作用は別の必須検査に委ねる。実端末の導入資格は与えない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectUsbBluetoothInboxGroup( HINF							  inf,
														std::span<const OfficialZipEntry> entries,
														OfficialInfPackage				 &package)
{
	const auto unsupported = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;	// 元限定形式に合わない場合
	// 自己媒体やクラスの異なる配布を空媒体として扱わない
	if( entries.size() != 2U || !package.scopedModels ||
	   package.scopedModels->sections.size() != 1U ||
	   !stringsEqual( package.className, BLUETOOTH_CLASS.front()) ||
	   !stringsEqual( package.classGuid, BLUETOOTH_CLASS.back()) ||
	   validateSetupClassPair( inf, BLUETOOTH_CLASS) != 0 ||
	   !containsEntry( entries, package.infRelativePath) ||
	   !containsEntry( entries, package.catalogRelativePath)) {
		return unsupported ;
	}

	const auto &scope  = *package.scopedModels ;	// 同じ元INFを読んだ対象OSとModelsの全件
	const auto &models = scope.sections.front() ;	// この形式は一つのModels節を使用する
	// 公式の完全Hardware欄と同じ全Models行を要求し、他用途のIDや追加行を含めない
	if( !scope.platform || scope.platform->processorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 ||
	   scope.platform->productType != VER_NT_WORKSTATION || models.matches.empty() ||
	   models.matches.size() != models.modelRows ||
	   !std::ranges::all_of( models.matches, [&]( const auto &match) {
		   return isUsbVidPid( match.hardwareId) &&
				  stringsEqual( match.installBase, models.matches.front().installBase) ;
	   })) {
		return unsupported ;
	}

	const auto target = nativeModelsPlatform( *scope.platform) ;	// 明示された公式の対象OS
	// 現在のWindowsへ代替して別の選択を読み取らない
	if( !target) {
		return unsupported ;
	}

	auto		 platform = *target ;	// SetupAPIが同期借用する対象OSの作業値
	std::wstring base ;					// 同じModels行からWindowsが解決する実DDInstall名
	// 対象OSが解決できない元基本名を推定で置き換えない
	if( const auto error =
		   resolveActualInstallInventorySection( inf, models.matches.front().installBase, base,
												reinterpret_cast<PSP_ALTPLATFORM_INFO>( &platform)) ;
	   error != 0U) {
		return error ;
	}

	std::vector<std::wstring> seeds{base, base + L".HW", base + L".Services"} ;	// 元の三委譲節
	constexpr std::array	  targets{L"BthUsb.NT", L"BthUsb.NT.HW",
								  L"BthUsb.NT.Services"} ;	// 同梱側の対応節
	constexpr std::array	  lineCounts{3L, 3L, 2L} ;		// 参照を含む元各節の全行数
	std::wstring			  value ;						// 各元行の一意な展開済みフィールド
	// 元の三節から同梱INFの対応節だけを参照することを確認する
	for( std::size_t index = 0U; index < seeds.size(); ++index) {
		const auto &seed = seeds[index] ;	// Windowsが選択した基本又は同修飾の付随節
		// 重複・追加の作用を許可された参照へ縮約しない
		if( SetupGetLineCountW( inf, seed.c_str()) != lineCounts[index] ||
		   readRequiredServiceField( inf, seed, L"Include", value) != 0U ||
		   !stringsEqual( value, L"bth.inf") ||
		   readRequiredServiceField( inf, seed, L"Needs", value) != 0U ||
		   !stringsEqual( value, targets[index])) {
			return unsupported ;
		}
	}

	std::uint32_t score{} ;		// 元基本節の順位に使われる値
	std::wstring  registry ;	// 元HW節だけが参照する機器登録節
	INFCONTEXT	  row{} ;		// 機器登録の唯一の元行
	// 順位指定と、機器直下に置く唯一のDWORDを個別に確認する
	if( readRequiredServiceScalar( inf, base, L"FeatureScore", score) != 0U || score != 0xf0U ||
	   readRequiredServiceField( inf, seeds[1], L"AddReg", registry) != 0U ||
	   !validInstallInventorySectionName( registry) ||
	   SetupGetLineCountW( inf, registry.c_str()) != 1L ||
	   !SetupFindFirstLineW( inf, registry.c_str(), nullptr, &row) ||
	   SetupGetFieldCount( &row) != 5U || readInfField( row, 1U, value) != 0U ||
	   !stringsEqual( value, L"HKR") || readInstallInventoryField( row, 2U, value) != 0U ||
	   !value.empty() || readInfField( row, 3U, value) != 0U ||
	   !stringsEqual( value, L"VsMsftOpCode") || !propertyPageNumber( row, 4U, 0x10001U, false) ||
	   !propertyPageNumber( row, 5U, 0xfc78U, false)) {
		return unsupported ;
	}

	const std::array<std::wstring_view, 8U> permitted{
		L"Version", L"Manufacturer", models.modelSection, seeds[0], seeds[1],
		seeds[2],	registry,		 L"Strings"} ;	// 空媒体で読み取る役割ごとの元節
	// Versionから別INFの媒体を持ち込む配布を除外する
	if( SetupFindFirstLineW( inf, L"Version", L"LayoutFile", &row)) {
		return unsupported ;
	}

	const auto error =
		// 他の作用を参照する節を含まない元INF
		verifyExactInfSections( inf, permitted) ;
	// 全節が同じ原構造の範囲に収まる場合だけ選択を保存する
	if( error == 0U) {
		package.collectorInboxInstallGroups.push_back( std::move( seeds)) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式USB対象を元INFの三委譲節と単一の機器相対GUIDへ結ぶ
 * @param[in] inf 元CATと公式Modelsに照合した同じ元INFの読取りハンドル
 * @param[in] entries 同じ公式CABから得た全元ファイル
 * @param[in,out] package 独自クラス登録の検査済み基本INF。全検査成功時だけ委譲と登録節を保存する
 * @return 全ての元作用が限定構造と一致した場合0、未対応・欠損・読取り失敗はHRESULT
 * @note 同梱側の署名、ファイルと作用は後段で独立に検査する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectWinUsbInboxGroup( HINF								inf,
												  std::span<const OfficialZipEntry> entries,
												  OfficialInfPackage			   &package)
{
	const auto unsupported =
		// 公式CABの元構造が異なる場合
		nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	// 元のINFとCATだけを持つ基本媒体に限定する
	if( entries.size() != 2U || !package.scopedModels ||
	   package.scopedModels->sections.size() != 1U ||
	   !containsEntry( entries, package.infRelativePath) ||
	   !containsEntry( entries, package.catalogRelativePath)) {
		return unsupported ;
	}

	const auto				 &scope	 = *package.scopedModels ;	// 公式の全Hardware対象と元ハッシュ
	const auto				 &models = scope.sections.front() ;	// 対象OSで採用した唯一のModels節
	std::vector<std::wstring> modelSections ;					// 全Manufacturerが参照する元節
	std::size_t				  manufacturerRows{} ;				// 元Manufacturerの有限読取り数
	// 対象外のModels、元Compatible欄、別導入節を同じ一つの選択として扱わない
	if( !scope.platform || scope.platform->processorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 ||
	   scope.platform->productType != VER_NT_WORKSTATION || models.matches.empty() ||
	   models.matches.size() != models.modelRows || models.idFields != models.modelRows ||
	   !collectDeclaredModelSections( inf, false, modelSections, manufacturerRows) ||
	   manufacturerRows != 1U || modelSections.size() != 1U ||
	   !stringsEqual( modelSections.front(), models.modelSection) ||
	   !std::ranges::all_of( models.matches, [&]( const auto &match) {
		   return isUsbVidPid( match.hardwareId) &&
				  stringsEqual( match.installBase, models.matches.front().installBase) ;
	   })) {
		return unsupported ;
	}

	auto platform = nativeModelsPlatform( *scope.platform) ;	// SetupAPIの対象に使う既知クライアントOS
	// ホストの代替選択を公式対象の結果にしない
	if( !platform) {
		return unsupported ;
	}

	// SetupAPIは先頭サイズでV3を識別するため、同じ構造を既定型のアドレスで渡す
	auto		*requested = reinterpret_cast<PSP_ALTPLATFORM_INFO>( &*platform) ;
	std::wstring base ;				// 公式Modelsの実在基本節
	std::wstring classSection ;		// 同じOSが選ぶ表示用クラス節
	std::wstring classRegistry ;	// 検査済みクラス表示値を持つ元節
	// 認めたクラス登録と機器自身の登録を独立した節として確認する
	if( resolveActualInstallInventorySection( inf, models.matches.front().installBase, base,
											requested) != 0U ||
	   resolveActualInstallInventorySection( inf, L"ClassInstall32", classSection, requested) !=
		   0U ||
	   readRequiredServiceField( inf, classSection, L"AddReg", classRegistry) != 0U) {
		return unsupported ;
	}

	std::vector<std::wstring> seeds{base, base + L".HW",
									base + L".Services"} ;	// 元基本と付随の選択節
	constexpr std::array	  targets{L"WINUSB.NT", L"WINUSB.NT.HW",
								  L"WINUSB.NT.Services"} ;	// 同梱の対応節
	constexpr std::array	  counts{2L, 3L, 2L} ;			// 委譲と単一機器登録を含む元の全行数
	std::wstring			  value ;						// 各元行を展開した一値
	// 全選択節を同じ正規INFの同じ役割へ限定し、別作用を元の行数で検出する
	for( std::size_t index = 0U; index < seeds.size(); ++index) {
		const auto &seed = seeds[index] ;	// 一つの基本又は付随節
		// 委譲以外のコピー、サービス、フィルター等を含む選択には進まない
		if( SetupGetLineCountW( inf, seed.c_str()) != counts[index] ||
		   readRequiredServiceField( inf, seed, L"Include", value) != 0U ||
		   !stringsEqual( value, L"winusb.inf") ||
		   readRequiredServiceField( inf, seed, L"Needs", value) != 0U ||
		   !stringsEqual( value, targets[index])) {
			return unsupported ;
		}
	}

	std::wstring registry ;			// HWが直接参照する機器相対登録節
	INFCONTEXT	 row{} ;			// 登録節の唯一の無名データ行
	GUID		 interfaceId{} ;	// 空でない完全GUIDだけを受理する解析先
	// HKR直下のGUID列だけを受理し、別scope、型、複数値、追加行を拒否する
	if( readRequiredServiceField( inf, seeds[1], L"AddReg", registry) != 0U ||
	   !validInstallInventorySectionName( registry) ||
	   SetupGetLineCountW( inf, registry.c_str()) != 1L ||
	   !SetupGetLineByIndexW( inf, registry.c_str(), 0U, &row) || SetupGetFieldCount( &row) != 5U ||
	   readInstallInventoryField( row, 0U, value) != nativeErrorFromWin32( ERROR_INVALID_PARAMETER) ||
	   readInfField( row, 1U, value) != 0U || !stringsEqual( value, L"HKR") ||
	   readInstallInventoryField( row, 2U, value) != 0U || !value.empty() ||
	   readInfField( row, 3U, value) != 0U || !stringsEqual( value, L"DeviceInterfaceGUIDs") ||
	   !propertyPageNumber( row, 4U, 0x10000U, false) || readInfField( row, 5U, value) != 0U ||
	   value.size() != 38U || CLSIDFromString( value.c_str(), &interfaceId) != S_OK ||
	   IsEqualGUID( interfaceId, GUID{})) {
		return unsupported ;
	}

	// 別の媒体レイアウトを元Versionへ委譲する形は二ファイルとして扱わない
	if( SetupFindFirstLineW( inf, L"Version", L"LayoutFile", &row)) {
		return unsupported ;
	}

	const std::array<std::wstring_view, 10U> permitted{
		L"Version",	  L"Manufacturer", models.modelSection,
		classSection, classRegistry,   seeds[0],
		seeds[1],	  seeds[2],		   registry,
		L"Strings"} ;	// 元署名から使用する全節名
	const auto error =
		// 隠れた媒体、別選択、追加作用の節を拒否する
		verifyExactInfSections( inf, permitted) ;
	// 元の全節を確認してから依存検査に一組として引き渡す
	if( error == 0U) {
		package.collectorInboxWinUsbRegistrySection = std::move( registry) ;
		package.collectorInboxInstallGroups.push_back( std::move( seeds)) ;
	}

	return error ;
}

/** @brief 同じ元CABで判定した二種類の完全媒体位置です */
struct ScopedMediaSources {
	/// 元INFが参照しないと確認した不在媒体です
	std::vector<std::wstring> missing ;
	/// AMD64が参照しないと確認したx86の実在媒体です
	std::vector<std::wstring> x86 ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 公式単体CABの不在媒体とx86専用媒体の完全位置を確認します
 * @param[in] workspace 元CABを開いた保護領域です
 * @param[in] entries 同じCABの全ファイル一覧です
 * @param[in] inf 元INFを固定中に開いた読取専用HINFです
 * @param[in] bytes 同HINFを保持する元INFバイトです
 * @param[in] package 元CAT所属を確認した基本INFです
 * @param[in] parent CAB内のINF親位置です
 * @return 元参照から独立した媒体の完全位置です。証明の不成立は空です
 */
//------------------------------------------------------------------------------
[[nodiscard]] ScopedMediaSources readScopedMediaSources( const OfficialDownloadWorkspace	 &workspace,
														std::span<const OfficialZipEntry> entries,
														HINF inf, std::span<const std::byte> bytes,
														const OfficialInfPackage &package,
														std::wstring_view		  parent)
{
	// 元CAT所属済みNetの同一CABだけを扱い、別文書や言語資源への暗黙の参照を拒否します
	if( !package.scopedModels || validateSetupClassPair( inf, NET_CLASS) != 0 ||
	   workspace.protectionMode() != OfficialWorkspaceMode::CURRENT_USER_INSPECTION ||
	   std::ranges::any_of( entries, [&]( const auto &entry) {
		   const auto extension = lowerExtension( entry.relativePath) ;	// 同容器の文書・言語資源です
		   return extension == L".in_" || extension == L".mui" ||
				  (extension == L".inf" &&
				   !stringsEqual( entry.relativePath, package.infRelativePath)) ;
	   })) {
		return {} ;
	}

	ScopedMediaSources		  isolated ;	// 既存の媒体検査へ渡す根拠付きの原位置です
	std::vector<std::wstring> reviewed ;	// 装飾表と元表で同じ候補の証明を繰り返しません
	// AMD64媒体表と共通表の元行を、従来と同じ順に調べます
	for( const auto *section : {L"SourceDisksFiles.amd64", L"SourceDisksFiles"}) {
		INFCONTEXT row{} ;	// いま確認する媒体の宣言です
		// 空または不在の表に候補を作りません
		if( !SetupFindFirstLineW( inf, section, nullptr, &row)) {
			continue ;
		}

		// 同じディスクのDLLとx86候補のSYSだけを調べ、他の媒体は従来どおり扱います
		do {
			std::wstring leaf ;				// パスを含まない元ファイル名です
			std::wstring directory ;		// SetupAPIが返した元ファイルの配置先です
			std::wstring diskDirectory ;	// 元ディスク相対位置です
			// 元位置が曖昧な行は従来の媒体検査へ委ねます
			if( readInfField( row, 0U, leaf) != 0) {
				continue ;
			}

			const auto extension = lowerExtension( leaf) ;	// 候補を選ぶ元拡張子です
			const bool x86		 = extension == L".sys" ;	// x86実在媒体の候補です
			// 同じ元ディスクに結びつく一意のファイル位置を要求します
			if( (!x86 && extension != L".dll") || leaf.find_first_of( L"/\\~%") != leaf.npos ||
			   SetupGetFieldCount( &row) != 1U ||
			   readInfSourceDirectories( inf, leaf, directory, diskDirectory) != 0 ||
			   !directory.empty() || !diskDirectory.empty() ||
			   std::ranges::any_of( reviewed,
								   [&]( const auto &known) { return stringsEqual( known, leaf) ; })) {
				continue ;
			}

			auto compressed		= leaf ;	// 末尾一字を置換するWindowsの標準圧縮名です
			compressed.back()	= L'_' ;
			const auto sameLeaf = std::ranges::count_if( entries, [&]( const auto &entry) {
				const auto name = std::wstring_view{entry.relativePath} ;	// CAB内の任意の階層です
				const auto filename =
					// 同名と圧縮名を調べます
					name.substr( name.find_last_of( L"\\/") + 1U) ;
				return stringsEqual( filename, leaf) || stringsEqual( filename, compressed) ;
			}) ;
			const auto path		= joinRelativePath( parent, leaf) ;	// 親位置を含む元の要求位置です
			INFCONTEXT x86Disk{} ;									// 明示のx86媒体行です
			// 不在の証明には別位置も含めて0件、x86側は同じ位置の通常ファイル一件だけを要求します
			if( x86 ? sameLeaf != 1 || !containsEntry( entries, path) ||
						 !SetupFindFirstLineW( inf, L"SourceDisksFiles.x86", leaf.c_str(),
											  &x86Disk) ||
						 SetupGetLineCountW( inf, L"SourceDisksNames.x86") > 0L
				   : sameLeaf != 0) {
				continue ;
			}

			// 同じCABで高価な全INF照合を無制限に繰り返しません
			if( reviewed.size() >= 4U) {
				return {} ;
			}

			reviewed.push_back( leaf) ;
			MaintenanceInfByteProof proof ;		// 同元バイトの完全性と全参照の検査を所有します
			ScopedMediaIsolation	boundary ;	// 観測した元の節境界です
			bool wifiDependency{} ;				// 元INFがnetvwifibus.infを参照するときtrueです
			// 全値を確定できない場合はその媒体を省略しません
			if( !proof.proveScopedMediaIsolation( inf, bytes, leaf, boundary, false,
												wifiDependency)) {
				continue ;
			}

			// 元CABの外へ出る場合は、同じ依存の保護バイトからも逆参照を確認します
			if( wifiDependency &&
			   inf_dependency_native_detail::inspectProtectedWifiBusInf(
				   workspace, [&]( const std::wstring		&windowsInf, std::wstring_view,
								  std::span<const std::byte> windowsBytes) {
					   const UniqueInf		   source( SetupOpenInfFileW(
						   windowsInf.c_str(), nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
						   nullptr)) ;					// 固定同梱INFの読取handleです
					   MaintenanceInfByteProof inbox ;	// 同梱の物理構造と全値を確認します
					   bool nested{} ;					// 同梱側が別INFへ出る構成は証明から除きます
					   return source.get() != INVALID_HANDLE_VALUE &&
									  inbox.proveScopedMediaIsolation( source.get(), windowsBytes,
																	  leaf, boundary, true,
																	  nested) &&
									  !nested
								  ? 0
								  : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				   }) != 0) {
				continue ;
			}

			(x86 ? isolated.x86 : isolated.missing).push_back( path) ;
		} while( SetupFindNextLine( &row, &row)) ;
	}

	return isolated ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名と公式Modelsを確認したNetで、旧登録と不在媒体への逆参照を調べます
 * @param[in] workspace 元CABだけを展開した保護領域です
 * @param[in] entries 同じ階層の全ファイル一覧です
 * @param[in] inf 固定済み元INFを開いた読取専用handleです
 * @param[in] bytes 同HINFを閉じる間も所有する元バイトです
 * @param[in] package 原署名と公式範囲を確認した同じINFの位置と証拠です
 * @param[out] proof 登録・関連媒体・保護済み同梱INFの全照合成立時だけ保持します
 * @return 全証明が成立した場合0です。未解決の用途は元拒否と同じHRESULTです
 */
//------------------------------------------------------------------------------
NativeError inspectInactiveCoInstaller( const OfficialDownloadWorkspace	&workspace,
									   std::span<const OfficialZipEntry> entries, HINF inf,
									   std::span<const std::byte> bytes,
									   const OfficialInfPackage	 &package,
									   InactiveCoInstaller		 &proof)
{
	const auto unsupported = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;	// 元作用ゲートの拒否です
	// 同じ署名・公式Modelsの証明を持たない通常の呼出しを扱いません
	if( !package.scopedModels || !stringsEqual( package.classGuid, NET_CLASS.back()) ||
	   validateSetupClassPair( inf, NET_CLASS) != 0) {
		return unsupported ;
	}

	InactiveCoInstaller		observed ;	// 誤った一部結果を他モードに引き継ぎません
	MaintenanceInfByteProof raw ;		// 固定元INFの全行と全言語を参照します
	// 規定に合わない元構造には従来の作用拒否を返します
	if( !raw.inactiveCoInstaller( inf, bytes, observed)) {
		return unsupported ;
	}

	// 元媒体の実体と圧縮別名、元INFと同梱依存を隠すCAB内の別INFを拒否します
	for( const auto &entry : entries) {
		const auto path		 = std::wstring_view{entry.relativePath} ;			// 元archiveの実位置です
		const auto leaf		 = path.substr( path.find_last_of( L"\\") + 1U) ;	// 同名の別親も検査します
		const auto extension = lowerExtension( leaf) ;							// 同じ容器の別INFとその圧縮名を見ます
		// 別の原文書から同登録を参照できる場合は全体を保留します
		if( extension == L".in_" ||
		   (extension == L".inf" && !stringsEqual( path, package.infRelativePath)) ||
		   std::ranges::any_of( observed.files, [&]( const auto &file) {
			   auto compressed	 = file ;	// 同じ元媒体でWindowsが探す圧縮名です
			   compressed.back() = L'_' ;
			   return stringsEqual( leaf, file) || stringsEqual( leaf, compressed) ;
		   })) {
			return unsupported ;
		}
	}

	const auto error = inf_dependency_native_detail::inspectProtectedWifiBusInf(
		workspace, [&]( const std::wstring &windowsInf, std::wstring_view storeInf,
					   std::span<const std::byte> windowsBytes) {
			const UniqueInf			input( SetupOpenInfFileW(
				windowsInf.c_str(), nullptr, INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;
			MaintenanceInfByteProof dependency ;	// Windowsが固定した同じ元バイトを照合します
			return input.get() != INVALID_HANDLE_VALUE &&
						   dependency.inactiveCoInstaller( input.get(), windowsBytes, observed,
														  storeInf)
					   ? 0
					   : unsupported ;
		}) ; // 元CABの証明と固定同梱INFが同時に有効な間だけ参照関係を確かめます
	// 外部依存の由来や全行を確定できない場合も従来の拒否を保持します
	if( error != 0) {
		return unsupported ;
	}

	const auto separator = package.infRelativePath.find_last_of( L"\\") ;	// INF親位置の境界です
	const auto parent	 = separator == package.infRelativePath.npos
							   ? std::wstring_view{}
							   : std::wstring_view{package.infRelativePath}.substr(
									 0U, separator) ;	// 同階層の元パスです
	// 元媒体表の実SetupAPIが同じ有限位置を返す場合だけ不在証明を引き渡します
	for( auto &file : observed.files) {
		std::wstring source ;	// その媒体表の元ファイル位置です
		std::wstring media ;	// 同じディスクIDが示す元配置です
		// 別subdirectory・別媒体の不在をこの証明で救済しません
		if( readInfSourceDirectories( inf, file, source, media) != 0 ||
		   !stripReferenceCurrentDirectory( source).empty() ||
		   !stripReferenceCurrentDirectory( media).empty()) {
			return unsupported ;
		}

		file = joinRelativePath( parent, file) ;
	}

	proof = std::move( observed) ;
	return 0 ;
}
} // namespace

#ifdef DRIVERCRATE_INTERNAL_INDEX_TESTS
//------------------------------------------------------------------------------
/**
 * @brief 架空INF全体で指定した媒体への逆参照を調べます
 * @param[in] path 所有試験領域の元INF絶対パスです
 * @param[in] leaf 試験対象の不在DLLまたはx86のSYS名です。パスを含みません
 * @return 元INF内の限定構造と全値が成立し、外部依存がなければtrueです
 * @note 元署名・媒体・収集資格を発行しない内部試験です
 */
//------------------------------------------------------------------------------
bool official_inf_models_native_detail::Access::inspectScopedMediaIsolation( std::wstring_view path,
																			std::wstring_view leaf)
{
	OfficialMappedFile pinned ;	// 架空の原バイトをHINFより長く保持します
	// 元INFのバイトを保護読取りできる場合だけ構造を比較します
	if( pinned.open( path, MAXIMUM_INACTIVE_CO_INSTALLER_BYTES) != 0) {
		return false ;
	}

	const std::wstring		absolute{path} ;	// SetupAPI用の終端付き試験パスです
	const UniqueInf			inf( SetupOpenInfFileW( absolute.c_str(), nullptr,
												  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
												  nullptr)) ;	// 同じ元INFを解析する読取り専用handleです
	MaintenanceInfByteProof proof ;								// 元フィールドの比較結果を同期所有します
	ScopedMediaIsolation	boundary ;							// 成立時だけ保持する元の節境界です
	bool					wifiDependency{} ;					// 架空の入力から実Windowsの依存へ進まないようにします
	return inf.get() != INVALID_HANDLE_VALUE &&
		   proof.proveScopedMediaIsolation( inf.get(), pinned.bytes(), leaf, boundary, false,
										   wifiDependency) &&
		   !wifiDependency ;
}

//------------------------------------------------------------------------------
/**
 * @brief 所有fixtureの全元構造と通常の作用拒否を同じ元INFで比較します
 * @param[in] path 架空fixtureの保護領域にある有限絶対パスです
 * @return 同じバイトの逆参照証明と限定作用検査に合格し、通常検査で拒否した場合だけtrueです
 * @note 署名根拠や収集結果を返さず、通常の検査入口へ接続しません
 */
//------------------------------------------------------------------------------
bool official_inf_models_native_detail::Access::inspectInactiveRegistration( std::wstring_view path)
{
	OfficialMappedFile pinned ;	// 架空の同じ原バイトをHINFより長く保持します
	// 架空INFの元バイトが固定できなければ結果を返しません
	if( pinned.open( path, MAXIMUM_INACTIVE_CO_INSTALLER_BYTES) != 0) {
		return false ;
	}

	const std::wstring absolute{path} ;	// SetupAPI用の同期終端パスです
	// 試験ファイルをWindowsのINFパーサーで調べる所有ハンドル
	const UniqueInf	   inf( SetupOpenInfFileW( absolute.c_str(), nullptr,
											 INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;
	// 実SetupAPIも開けた同じfixtureだけを検査します
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return false ;
	}

	bool					dependencies{} ;	// 同Fixtureの元依存の有無です
	InactiveCoInstaller		registration ;		// 構造成立時だけ確認する限定節です
	MaintenanceInfByteProof raw ;				// 通常の署名段階と独立した元構造を同期所有します
	return validateInfInstallActions( inf.get(), false, dependencies, true) ==
			   nativeErrorFromWin32( ERROR_NOT_SUPPORTED) &&
		   raw.inactiveCoInstaller( inf.get(), pinned.bytes(), registration) &&
		   validateInfInstallActions( inf.get(), false, dependencies, true, false, nullptr,
									 OfficialInfInspectionPurpose::COLLECTOR_CONTENT, nullptr, {},
									 registration.registry) == 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空INFで既存の棚卸しと新しいコピー構成だけを照合します
 * @param[in] workspace 架空fixtureの元INFを持つ保護領域です
 * @param[in] entries 架空の同梱元媒体だけの一覧です
 * @param[in] inboxVerified 試験上の同梱依存確認結果です
 * @param[out] complete 元の全用途を照合した場合true、失敗時はfalseです
 * @return 作用とコピー構成が成立した場合0、最初の失敗はHRESULTです
 * @note 現Windowsの既存INF解析だけを使い、由来・署名・導入資格を作りません
 */
//------------------------------------------------------------------------------
NativeError official_inf_models_native_detail::Access::inspectScopedWirelessProfile(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	bool inboxVerified, bool &complete)
{
	complete				 = false ;
	const auto		absolute = workspace.path( L"fixture.inf") ;	// 試験領域が所有する唯一の元INFです
	// 元試験INFのコピー構造を読み取る同一呼出し用の所有ハンドル
	const UniqueInf inf( SetupOpenInfFileW( absolute.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;
	// 元構文を開けなければコピーへの照合を始めません
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	MaintenanceInfInstallStructure install ;	// 架空の元選択作用と参照です
	install.inventory.baseInstallSection = L"Install" ;
	auto error							 = resolveActualInstallInventorySection(
		  inf.get(), install.inventory.baseInstallSection,
		  install.inventory.selectedInstallSection) ;	// 同じ元INFにある実導入節です
	// 選択不能から元用途を作りません
	if( error != 0U) {
		return error ;
	}

	MaintenanceStructureBudget budget ;	// 本番と同じ有限な棚卸し条件です
	budget.collectionContent = true ;
	budget.scopedPciNet		 = true ;
	budget.sharedRegistryInf = inf.get() ;
	error = inspectMaintenanceInstallStructure( inf.get(), workspace, entries, {}, budget, install) ;
	// 解析不能な作用を確認済みとして扱いません
	if( error != 0U) {
		return error ;
	}

	install.wifiBusNeedsVerified = inboxVerified ;
	OfficialInfPackage package ;	// 照合対象の元媒体位置だけを持つ架空の構造です
	// 試験ごとの固定媒体を照合分母へ保持します
	for( const auto &entry : entries) {
		package.sourceFiles.push_back( entry.relativePath) ;
	}

	std::array<wchar_t, MAX_PATH> system{} ;	// 実SetupAPIの標準コピー先と比較します
	// 既知のWindows標準パスを照合するために取得したディレクトリ名の文字数
	const auto length = GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
	// 元宛先となるSystem32の完全位置を取得します
	if( length == 0U || length >= system.size()) {
		return nativeErrorFromWin32( ERROR_PATH_NOT_FOUND) ;
	}

	std::vector<ScopedNetworkSource> sources ;	// 元コピーの用途型だけを確認します
	return bindScopedNetworkEventSources( inf.get(), workspace, entries, package, install,
										 std::wstring( system.data(), length), sources, complete) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空USB無線INFの同じ選択のコピー、サービスと作用を指定範囲で対照します
 * @param[in] workspace 架空fixture.infと媒体名を保持する試験領域です
 * @param[in] entries 元CABの媒体に相当する架空の元名です
 * @param[in] selection 確認する範囲と架空の同梱依存状態です
 * @return 指定した照合の全成功は0、それ以外は元HRESULTです
 * @note 実署名、導入許可、公開候補を発行しない内部試験です
 */
//------------------------------------------------------------------------------
NativeError official_inf_models_native_detail::Access::inspectScopedUsbWirelessProfile(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	ScopedUsbWirelessCheck selection)
{
	OfficialInfPackage package ;	// 架空INFと媒体位置の検査にだけ使います
	package.infRelativePath		 = L"fixture.inf" ;
	package.selectedBasicSection = L"Install" ;
	const auto absolute = workspace.path( package.infRelativePath) ;				// 同じ元試験INFの位置です
	OfficialMappedFile original ;													// 試験INFの同じバイトをHINFの解放まで保護します
	auto error = original.open( absolute, MAXIMUM_INACTIVE_CO_INSTALLER_BYTES) ;	// 元固定の診断です
	// 同じ元バイトを解析できない場合は別のINFを代用しません
	if( error != 0U) {
		return error ;
	}

	// 架空無線ドライバーの実導入選択を読む所有ハンドル
	const UniqueInf inf( SetupOpenInfFileW( absolute.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;
	// 存在しない元INFにコピー集合を生成しません
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	error = selectInstallInventorySection( inf.get(), package.selectedBasicSection,
										  package.selectedInstallSection) ;	// 同実装飾の元選択です
	// 読取れない元選択を汎用コピー節で代用しません
	if( error != 0) {
		return error ;
	}

	OfficialInfInstallInventory inventory ;	// 同じWindows選択から導く元参照です
	error = readWindowsDriverScopeReferences( inf.get(), package, inventory) ;
	// 選択元の不正な関係はその診断を保持します
	if( error != 0) {
		return error ;
	}

	// B7a対照の架空媒体を同じ元位置の分母にします
	for( const auto &entry : entries) {
		package.sourceFiles.push_back( entry.relativePath) ;
	}

	std::array<wchar_t, MAX_PATH> system{} ;	// 同Windowsの標準コピー先です
	// 同梱媒体と区別する標準ディレクトリ名の文字数
	const auto length = GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
	// Windowsの解決先が不明なら試験でも続けません
	if( length == 0U || length >= system.size()) {
		return nativeErrorFromWin32( ERROR_PATH_NOT_FOUND) ;
	}

	std::vector<WindowsDriverCopy>	   bound ;	// 検査する架空コピー集合です
	std::vector<MaintenanceInfFileUse> uses ;	// 元コピー用途の対応です
	error = bindScopedUsbWirelessCopies( inf.get(), workspace, entries, package, inventory,
										std::wstring( system.data(), length), bound, uses) ;
	// コピー対照はここで結果を保持し、コピー失敗をサービス検査で補完しません
	if( error != 0U || selection == ScopedUsbWirelessCheck::COPIES) {
		return error ;
	}

	MaintenanceInfInstallStructure install ;	// 元の実選択で読んだサービス集合です
	install.inventory.baseInstallSection	 = package.selectedBasicSection ;
	install.inventory.selectedInstallSection = package.selectedInstallSection ;
	MaintenanceStructureBudget budget ;	// 本番の元宣言棚卸しと同じ有限枠です
	budget.collectionContent = true ;
	budget.scopedUsbNet		 = true ;
	budget.sharedRegistryInf = inf.get() ;
	error = inspectMaintenanceInstallStructure( inf.get(), workspace, entries, {}, budget, install) ;
	// 元宣言の読取りに失敗した場合は部分結果を渡しません
	if( error != 0U) {
		return error ;
	}

	// 異なる元サービスの作用を元コピーの成功で補完しません
	if( !bindScopedUsbWirelessServices( inf.get(), install, original.bytes(), bound, uses)) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 元サービスだけを対照する場合は共有設定の条件を追加しません
	if( selection == ScopedUsbWirelessCheck::SERVICES) {
		return 0U ;
	}

	install.wifiBusNeedsVerified = selection == ScopedUsbWirelessCheck::EFFECTS_WITH_INBOX ;
	return bindScopedUsbWirelessEffects( inf.get(), install, uses)
			   ? 0U
			   : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空の登録行を共通の表示用途判定に通します
 * @param[in] values SetupAPI展開後を模した登録行の全欄です
 * @param[in] usbWireless trueは公式USB無線と照合できた選択を模します
 * @return 元の表示形式と一致した場合trueです
 * @note 実ファイルや登録内容に変更を加えない内部試験です
 */
//------------------------------------------------------------------------------
bool official_inf_models_native_detail::Access::inspectScopedWirelessLabel(
	std::span<const std::wstring> values, bool usbWireless)
{
	return isWirelessParameterLabel( values, usbWireless) ;
}
#endif

//------------------------------------------------------------------------------
/**
 * @brief 展開済み標準INF packageの構造と現在OSへの適用sectionを検証する。展開済み標準INF packageを検証する。SetupAPIの構文とplatform選択結果を
 *        使用し、CAT署名前にpackageの有限性、driver-only境界、参照file存在を確認する
 * @param[in] workspace ZIP展開fileを所有する保護workspace
 * @param[in] entries ZIP検証で確定した全通常file。Directory entryは含めない。 ZIP検証済みの全通常file
 * @param[in] infRelativePath 検証対象INFのworkspace基準相対path。 検証するINF相対path
 * @param[in] policy 件数上限、許可class、ProviderおよびINF signature。 件数上限、許可class／Provider／signature
 * @param[out] package 成功時の検証済み構造。失敗時は空にする。 成功時だけ更新する検証済み構造
 * @param[in] scopedModels 元CABと同じCATを選んだ収集元の限定要求です。通常はnullです
 * @return 成功時は0、INF構文、適用section、参照fileまたはpolicy違反時はHRESULT。 全構造検証成功時は0、最初の違反はHRESULT
 * @note 本関数はfileを変更せず、catalog署名とmember hashは別の署名検証で確認する。TapeDrive名又は正式GUIDには一意な正式対を要求する
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialInfPackage( const OfficialDownloadWorkspace		 &workspace,
									  const std::span<const OfficialZipEntry> entries,
									  const std::wstring_view				  infRelativePath,
									  const OfficialInfInspectionPolicy		 &policy,
									  OfficialInfPackage					 &package,
									  const OfficialInfScopedModelsRequest	 *scopedModels)
{
	package							 = {} ;
	const bool invalidProviderPolicy =	// 固定allowlistと汎用modeの矛盾状態
		policy.acceptAnyProvider ? !policy.acceptedProviders.empty()
								 : policy.acceptedProviders.empty() ;
	// inventory、各上限、class・Provider・signature policyと選択INFを事前検証する
	if( entries.empty() || policy.maximumHardwareIds == 0 || policy.maximumSourceFiles == 0 ||
	   policy.acceptedClasses.empty() || invalidProviderPolicy ||
	   policy.acceptedSignatures.empty() ||
	   !stringsEqual( lowerExtension( infRelativePath), L".inf") ||
	   !containsEntry( entries, infRelativePath)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 混在シリアルの検査は元INF直下を所有する私有収集の構造検査に限定する
	if( policy.collectorSerialMedia &&
	   (policy.purpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
		!policy.rejectInstallActions || scopedModels != nullptr ||
		workspace.protectionMode() != OfficialWorkspaceMode::CURRENT_USER_INSPECTION ||
		infRelativePath.find( L'\\') != std::wstring_view::npos)) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 従来Providerはarchive全体、選択的閉包は後段のINF参照fileだけを拒否する
	if( policy.rejectUnreferencedPrograms &&
	   std::ranges::any_of( entries, []( const OfficialZipEntry &entry) {
		   const std::wstring extension = lowerExtension( entry.relativePath) ;	// 現在entryの拡張子
		   return std::ranges::find( REJECTED_UNREFERENCED_PROGRAM_EXTENSIONS, extension) !=
				  REJECTED_UNREFERENCED_PROGRAM_EXTENSIONS.end() ;
	   })) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	const std::wstring infPath = workspace.path( infRelativePath) ;	// 検証対象INF絶対path
	// INFの保護pathを解決できなければ解析を開始しない
	if( infPath.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	OfficialMappedFile scopedInfPin ;		// 元INFの限定証明ではHINFより先に固定する
	OfficialMappedFile scopedCatalogPin ;	// 署名で使用した同CATを構造検査終了まで固定します
	const auto		   infEntry = std::ranges::find_if( entries, [&]( const auto &entry) {
		return stringsEqual( entry.relativePath, infRelativePath) ;
	}) ; // 共通候補一覧と同じ比較で収集用の元INFを見つける
	const bool		   collectionClassPin =
		policy.purpose == OfficialInfInspectionPurpose::COLLECTOR_CONTENT &&
		policy.rejectInstallActions && infEntry != entries.end() &&
		infEntry->uncompressedSize != 0U &&
		infEntry->uncompressedSize <=
			MAXIMUM_INACTIVE_CO_INSTALLER_BYTES ;	// 原全節を追加検査できる範囲
	// 公式Models証拠または収集用シリアル媒体を使う検査で、元INFの固定を要求します
	const bool requiredInfPin = scopedModels != nullptr || policy.collectorSerialMedia ;
	// 明示された元配布を構造検査中に別のINFへ差し替えられないようにする
	if( requiredInfPin || collectionClassPin) {
		// 元CAB範囲付き検査と元シリアル媒体の明示用途を別々に扱う
		if( scopedModels != nullptr &&
		   (policy.purpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
			!policy.rejectInstallActions || !policy.allowRequiredDriverComponents ||
			scopedModels->infSha256.size() != 64U || scopedModels->catalogSha256.size() != 64U)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		// 元バイトの保持が必須の用途ではWindows構文検査を中止する
		// 独自クラスの追加判定は固定に失敗した場合に空の元証拠を受け取る
		if( const auto error = scopedInfPin.open( infPath, MAXIMUM_INACTIVE_CO_INSTALLER_BYTES) ;
		   error != 0 && requiredInfPin) {
			return error ;
		}
	}

	MaintenanceInfByteProof requiredRegistryProof ;	// 新分類だけが使う原byteと全fieldの証明です
	const bool				registryPurpose =
		policy.purpose == OfficialInfInspectionPurpose::REQUIRED_COLLECTOR_IMPORT &&
		policy.allowRequiredDriverComponents && policy.allowWindowsManagedDriverDataForContent &&
		policy.acceptedClasses.size() == 1U &&
		// root/Storageの許可ではありません
		stringsEqual( policy.acceptedClasses.front(), L"System") ;
	// 同CopyINF子のSystem policyだけでHINFより先に原snapshotを固定します
	if( registryPurpose) {
		const auto entry = std::ranges::find( entries, infRelativePath,
											 &OfficialZipEntry::relativePath) ;	// 元inventoryです
		// 元entryなしを通常readerの成功へ補完しません
		if( entry == entries.end()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const auto error =
			requiredRegistryProof.open( workspace, infPath, infRelativePath, *entry,
									   true) ;	// このregistry用途だけに元領域とドット名を結ぶ
		// 実byte不一致を既内容成功で救済しません
		if( error != 0) {
			return error ;
		}
	}

	UINT			errorLine{} ;	// INF構文errorが発生した一origin line
	const UniqueInf inf( SetupOpenInfFileW( infPath.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
										  &errorLine)) ;	// 読取り専用INF handle
	// INFを開けなければWindows診断値を保持して返す
	if( inf.get() == INVALID_HANDLE_VALUE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	try {
		OfficialInfPackage inspected ;	// 全検証成功時だけ出力へ移す一時構造
		inspected.inspectionPurpose = policy.purpose ;
		inspected.infRelativePath	= infRelativePath ;
		const bool collectorInbox =
			policy.purpose == OfficialInfInspectionPurpose::COLLECTOR_CONTENT &&
			policy.rejectInstallActions ;	// 端末側には追加の収集用途を広げません
		std::wstring candidateClass ;		// 静的検査に正規Portsの限定登録を渡すための先読みです
		NativeError	 result{} ;				// 各元構造検査の診断です
		const bool	 ports =
			(collectorInbox || policy.purpose == OfficialInfInspectionPurpose::STANDARD_DRIVER) &&
			readInfDirective( inf.get(), L"Version", L"Class", 1U, candidateClass) == 0 &&
			// 正式Portsの二つの元構造を確認する
			stringsEqual( candidateClass, L"Ports") ;
		// 空媒体の委譲形を従来順で静的作用の検査へ渡す
		if( collectorInbox && ports && !policy.collectorSerialMedia) {
			OfficialInfPackage inbox ;	// 途中で失敗した選択や登録節を元結果へ移しません
			result = collectInboxInstallGroups( inf.get(), CollectorInboxKind::PORTS, inbox) ;
			// メモリ不足を通常Portsの形式不成立として扱いません
			if( result == E_OUTOFMEMORY) {
				return result ;
			}

			// 成立した収集専用構造だけを後段の署名と依存検査へ渡します
			if( result == 0) {
				inspected.classGuid = std::move( inbox.classGuid) ;
				inspected.collectorInboxInstallGroups =
					std::move( inbox.collectorInboxInstallGroups) ;
				inspected.collectorInboxPropertyPageSection =
					std::move( inbox.collectorInboxPropertyPageSection) ;
			}
		}

		// 自己媒体の元構造を空媒体の委譲結果へ混ぜない
		if( ports && inspected.collectorInboxInstallGroups.empty() && !policy.collectorSerialMedia) {
			inspected.nativePortsPage = readNativePortsPropertyPage( inf.get(), infRelativePath) ;
			// 私有内容だけで共有登録を証明し、従来の端末用または公開v6の結果へ流用しない
			if( collectorInbox && !inspected.nativePortsPage && scopedModels == nullptr) {
				inspected.collectorSharedPortsPage =
					readCollectorSharedPortsPage( inf.get(), infRelativePath) ;
			}
		}

		std::optional<OfficialInfPropertyPage>
							propertyPage ;	// 元配布物にDLLを持つ既存形式の照合要求です
		PropertyPageContext serialPages ;	// 元シリアルの各選択から確認したページの所有先
		// 混在媒体を選んだ場合は二つの全選択が通るまで、いずれの元登録も許可しない
		if( policy.collectorSerialMedia &&
		   (!ports ||
			!readCollectorSerialMedia( inf.get(), serialPages,
									  inspected.collectorSerialMedia.emplace()) ||
			readRequiredServiceField( inf.get(), L"Version", L"ClassGUID", inspected.classGuid) !=
				0U)) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		bool				unassessedActions{} ;	// 原softwareの内容専用観測です
		InactiveCoInstaller inactive ;				// 同署名のNetだけに存在し得る一登録と不在媒体です
		// 既存の全行静的検査を確認した元登録節とともに実行します
		if( policy.rejectInstallActions || policy.rejectExternalDependencies) {
			// 同じ元INFで所有を証明したページ登録節だけを全行検査へ渡す
			const std::wstring_view pageRegistry =
				inspected.nativePortsPage ? inspected.nativePortsPage->registrySection
				: inspected.collectorSharedPortsPage
					? inspected.collectorSharedPortsPage->registrySection
					: inspected.collectorInboxPropertyPageSection ;
			const auto validate = [&]( std::wstring_view registry = {}) {
				return validateInfInstallActions(
					inf.get(), policy.rejectExternalDependencies, inspected.hasExternalDependencies,
					policy.allowRequiredDriverComponents,
					policy.allowReferencedExecutablesForContent, &unassessedActions, policy.purpose,
					&propertyPage, pageRegistry, registry,
					inspected.collectorSerialMedia ? &serialPages : nullptr) ;
			} ; // 従来の全拒否条件を同じpolicyで読み直します
			result = validate() ;
			// 元拒否がある公式CAB Netだけで、原署名を確認してから全逆参照の証明を試みます
			if( result == nativeErrorFromWin32( ERROR_NOT_SUPPORTED) && scopedModels &&
			   scopedModels->sameDirectCabinet && collectorInbox &&
			   readInfDirective( inf.get(), L"Version", L"Class", 1U, candidateClass) == 0 &&
			   stringsEqual( candidateClass, NET_CLASS.front()) &&
			   readOfficialInfCatalogPath( workspace, infRelativePath,
										  inspected.catalogRelativePath) == 0 &&
			   containsEntry( entries, inspected.catalogRelativePath) &&
			   inspectAuthenticatedScopedModels( workspace, *scopedModels, infPath, inf.get(),
												scopedCatalogPin, inspected) == 0 &&
			   inspectInactiveCoInstaller( workspace, entries, inf.get(), scopedInfPin.bytes(),
										  inspected, inactive) == 0) {
				result = validate( inactive.registry) ;
			}

			// 静的な拒否は別経路で上書きしません
			if( result != 0) {
				return result ;
			}
		}

		std::wstring signature ;	// `[Version]`のWindows INF signatureです
		result = readInfDirective( inf.get(), L"Version", L"Signature", 1, signature) ;
		// INF Signature値が取得不能または許可外なら拒否する
		if( result != 0 || !isAllowedValue( signature, policy.acceptedSignatures)) {
			return result != 0 ? result : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		result = readInfDirective( inf.get(), L"Version", L"Class", 1, inspected.className) ;
		// Classを取得できない元INFに推定値を補わない
		if( result != 0) {
			return result ;
		}

		result = validateSetupClassPair( inf.get(), MEDIUM_CHANGER_CLASS) ;
		// 正式名とGUIDの不一致を通常のクラスとして受理しない
		if( result != 0) {
			return result ;
		}

		// 元INFが宣言した正式クラスを確認する
		const bool mediumChanger = stringsEqual( inspected.className, MEDIUM_CHANGER_CLASS.front()) ;
		// 正式メディアチェンジャーの起動時作用を収集または端末選択で評価する
		if( mediumChanger) {
			// 端末の選択検査に使う用途と管理者領域の組
			const bool selectedStorage =
				policy.purpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE &&
				policy.rejectInstallActions &&
				workspace.protectionMode() == OfficialWorkspaceMode::ADMINISTRATOR ;
			// 収集または端末の選択以外の呼び出しでは拒否する
			if( !collectorInbox && !selectedStorage) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			inspected.classGuid = MEDIUM_CHANGER_CLASS.back() ;
		}

		const bool collectorSdHost = collectorInbox &&
									 // 既採用の空媒体形式です
									 stringsEqual( inspected.className, L"SDHost") ;
		// SDHostは既存の静的作用検査の後で委譲先を確認します
		if( collectorSdHost) {
			result = collectInboxInstallGroups( inf.get(), CollectorInboxKind::SD_HOST, inspected) ;
			// 形式不成立を後続の構造結果で上書きしません
			if( result != 0) {
				return result ;
			}
		}

		result = validateSetupClassPair( inf.get(), HDC_CLASS) ;
		// 正式GUIDを別名で宣言した元配布に同梱AHCIの検査を適用しない
		if( result != 0) {
			return result ;
		}

		// HDCの集約用途は収集領域と管理者領域の端末選択
		const bool endpointStorage =
			policy.purpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE &&
			policy.rejectInstallActions &&
			workspace.protectionMode() == OfficialWorkspaceMode::ADMINISTRATOR ;
		// 取扱いを許可する用途と正式HDCの組合せ
		const bool scopedHdc = (collectorInbox || endpointStorage) &&
							   stringsEqual( inspected.className, HDC_CLASS.front()) ;
		// 同梱SYSの元選択とWindows委譲の収集構造を確認する
		if( scopedHdc) {
			const bool ownMedia =	// 元INFのAMD64または共通媒体に宣言がある状態
				SetupGetLineCountW( inf.get(), L"SourceDisksFiles.amd64") > 0L ||
				SetupGetLineCountW( inf.get(), L"SourceDisksFiles") > 0L ;
			// コピー元を持つ形式では全AMD64の基本節と付随節を集める
			if( ownMedia) {
				// 未検査のAMD64選択が残る原INFを受理しない
				if( !collectHdcInstallGroups( inf.get(), inspected.nativeHdcInstallGroups)) {
					return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
				}

				inspected.classGuid = HDC_CLASS.back() ;
			}
			// Windowsの付属ドライバーへの委譲形は収集領域で扱う
			else if( collectorInbox) {
				result = collectInboxInstallGroups( inf.get(), CollectorInboxKind::AHCI, inspected) ;
				// 空媒体の委譲に必要な参照や元作用の不足を保留する
				if( result != 0) {
					return result ;
				}
			} else {
				// 端末の同梱SYS用途には原媒体の実ファイルが必要
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}
		}

		// 許可一覧外は収集rootと端末の内容検査だけで表示用の元登録を確認する
		const bool declarativeClass =
			!isAllowedValue( inspected.className, policy.acceptedClasses) && !collectorSdHost &&
			!scopedHdc && !mediumChanger ;	// 元登録の確認を必要とする独自クラス
		// 既知クラスの許可一覧は従来の経路を維持する
		if( declarativeClass) {
			// 読取専用の共通rootで作用検査を有効にした場合に限る
			if( !policy.rejectInstallActions ||
			   (policy.purpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT &&
				policy.purpose != OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE)) {
				return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
			}

			result = inspectDeclarativeSetupClass(
				inf.get(), infPath, inspected.className, inspected.classGuid, nullptr,
				collectionClassPin ? scopedInfPin.bytes() : std::span<const std::byte>{},
				scopedModels ? scopedModels->platform : nullptr,
				&inspected.collectorClassInfSha256) ;
			// 独自クラスの不成立を後続結果で上書きしない
			if( result != 0) {
				return result ;
			}

			// 端末の独自クラス結果に読み取り専用の用途を付ける
			if( policy.purpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE) {
				inspected.inspectionPurpose =
					OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT ;
			}
		}

		result = validateSetupClassPair( inf.get(), TAPE_DRIVE_CLASS) ;
		// 許可Class名へTapeDrive GUIDを取り違えた内容を正式driverへ昇格しない
		if( result != 0) {
			return result ;
		}

		// MTD GUIDを他名の先頭又は追加行として隠す偽装を通常用途でも拒否します
		if( !stringsEqual( inspected.className, L"MTD")) {
			// VersionのClassGUID行です
			INFCONTEXT line{} ;
			// MTD GUIDの偽装がないかVersion内の全行を確認します
			if( SetupFindFirstLineW( inf.get(), L"Version", L"ClassGUID", &line)) {
				// 同名ClassGUID行を原順で検査します
				do {
					// 同ClassGUID行の原文字列です
					std::wstring guid ;
					// 別classでMTD GUIDを名乗るINFを拒否します
					if( readInfField( line, 1U, guid) == 0 &&
					   stringsEqual( guid, L"{4d36e970-e325-11ce-bfc1-08002be10318}")) {
						return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
					}

					// 次のClassGUID行です
					INFCONTEXT next{} ;
					// ClassGUIDの最終行で検査を終えます
					if( !SetupFindNextMatchLineW( &line, L"ClassGUID", &next)) {
						break ;
					}

					line = next ;
				} while( true) ;
			}
		}

		// 正式storage GUIDを別Class名で通常deviceへ偽装しません
		if( policy.purpose != OfficialInfInspectionPurpose::STANDARD_DRIVER) {
			std::wstring guid ;	// 既存非storageのGUID欠測は従来の後段読取へ残します
			// 原GUIDがstorageを名乗る場合だけ正式Classとの対を要求します
			if( readInfDirective( inf.get(), L"Version", L"ClassGUID", 1U, guid) == 0 &&
			   stringsEqual( guid, L"{4d36e97b-e325-11ce-bfc1-08002be10318}") &&
			   !stringsEqual( inspected.className, L"SCSIAdapter")) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}
		}

		// 正式storage内容を名称だけで認定せず、通常driver構造へ追加しません
		const bool scsi = stringsEqual( inspected.className, L"SCSIAdapter") ;
		// 検査した正式class名がMTDかの判定です
		const bool mtd = stringsEqual( inspected.className, L"MTD") ;
		// 正式SCSIまたはMTDではGUID行の一意性を検査します
		if( scsi || mtd) {
			INFCONTEXT first{} ;		// 同元GUIDの一意性です
			INFCONTEXT duplicate{} ;	// 二つ目を無視しません
			result = readInfDirective( inf.get(), L"Version", L"ClassGUID", 1U, inspected.classGuid) ;
			// 通常policy・不正GUID・重複GUIDをstorage内容合格へ変換しません
			if( policy.purpose == OfficialInfInspectionPurpose::STANDARD_DRIVER ||
			   (mtd && policy.purpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT &&
				policy.purpose != OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE) ||
			   result != 0 ||
			   !stringsEqual( inspected.classGuid,
							 mtd ? L"{4d36e970-e325-11ce-bfc1-08002be10318}"
								 : L"{4d36e97b-e325-11ce-bfc1-08002be10318}") ||
			   !SetupFindFirstLineW( inf.get(), L"Version", L"ClassGUID", &first) ||
			   SetupFindNextMatchLineW( &first, L"ClassGUID", &duplicate) ||
			   !SetupFindFirstLineW( inf.get(), L"Version", L"Class", &first) ||
			   SetupFindNextMatchLineW( &first, L"Class", &duplicate)) {
				return result != 0 ? result : nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}
		}

		// 既非storageは従来用途へ戻し、appの追加Classだけに新用途を残します
		if( inspected.inspectionPurpose == OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE &&
		   !scsi && !mtd && !mediumChanger && !scopedHdc) {
			inspected.inspectionPurpose = OfficialInfInspectionPurpose::STANDARD_DRIVER ;
		}

		result = readInfDirective( inf.get(), L"Version", L"Provider", 1, inspected.providerName) ;
		// 非空Provider値とProvider policyの対応を要求する
		if( result != 0 || inspected.providerName.empty() ||
		   (!policy.acceptAnyProvider &&
			!isAllowedValue( inspected.providerName, policy.acceptedProviders))) {
			return result != 0 ? result : nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
		}

		result = readInfDirective( inf.get(), L"Version", L"DriverVer", 1, inspected.driverDate) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( result != 0) {
			return result ;
		}

		result = readInfDirective( inf.get(), L"Version", L"DriverVer", 2, inspected.driverVersion) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( result != 0) {
			return result ;
		}

		std::wstring catalogFile ;	// Version sectionが指定するCAT file名
		result = readCatalogFile( inf.get(), catalogFile) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( result != 0) {
			return result ;
		}

		const std::size_t		separator = infRelativePath.find_last_of( L'\\') ;	// INF親位置
		// Package内のINF親directory。Root直下では空のview
		const std::wstring_view infParent = separator == std::wstring_view::npos
												? std::wstring_view{}
												: infRelativePath.substr( 0, separator) ;
		inspected.catalogRelativePath	  = joinRelativePath( infParent, catalogFile) ;
		// 対応CATがworkspaceとinventoryに存在しなければpackageを採用しない
		if( workspace.path( inspected.catalogRelativePath).empty() ||
		   !containsEntry( entries, inspected.catalogRelativePath)) {
			return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
		}

		result =
			inspected.scopedModels ? 0
			: scopedModels == nullptr
				? collectHardwareIds( inf.get(), policy.maximumHardwareIds, inspected.hardwareIds)
				: inspectAuthenticatedScopedModels( workspace, *scopedModels, infPath, inf.get(),
												   scopedCatalogPin, inspected) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( result != 0) {
			return result ;
		}

		std::vector<std::wstring>
			serviceExecutables ;	// 同INFの必要SWC/元service/copyに限定する内容集合です
		// 既存構成modeだけで正式SWCの元作用を検査し、一般EXE allow flagを作りません
		if( policy.allowRequiredDriverComponents) {
			const bool collectorSystemBudget =
				policy.purpose == OfficialInfInspectionPurpose::COLLECTOR_CONTENT &&
				workspace.protectionMode() ==
					OfficialWorkspaceMode::CURRENT_USER_INSPECTION ;	// 本人領域の収集限定です
			result = collectRequiredServiceExecutables(
				inf.get(), inspected.className, serviceExecutables,
				policy.allowReferencedExecutablesForContent, collectorSystemBudget) ;
			// 同serviceの完全な根拠がなければsource byteを許可しません
			if( result != 0) {
				return result ;
			}

			result =
				collectRequiredCopyExecutables( inf.get(), inspected.className, serviceExecutables) ;
			// 元コピーの位置不一致をserviceの正常集合で隠しません
			if( result != 0) {
				return result ;
			}
		}

		// CopyINF import用途の正式Systemだけに、全潜在節を閉じたnull形式を認めます
		inspected.requiredNullCompanion =
			(policy.purpose == OfficialInfInspectionPurpose::REQUIRED_COLLECTOR_IMPORT ||
			 policy.purpose == OfficialInfInspectionPurpose::REQUIRED_STORAGE_IMPORT) &&
			stringsEqual( inspected.className, L"System") && isRequiredNullSystemContent( inf.get()) ;
		// 非空AddRegの限定内容はpure-nullへ混ぜず、独立した原全節証明を要求します
		if( registryPurpose && !inspected.requiredNullCompanion &&
		   stringsEqual( inspected.className, L"System")) {
			result = requiredRegistryProof.requiredRegistryContent(
				inf.get(), catalogFile, inspected.requiredRegistryOnlyCompanion) ;
			// 元Windows失敗をsource検索の後続errorで上書きしません
			if( result != 0) {
				return result ;
			}
		}

		// 自身のfileを持たない役割・継承・限定null/registry内容だけです。CATは後段で必須です
		const bool noOwnSourceFiles =
			policy.allowRequiredDriverComponents &&
			(stringsEqual( inspected.className, L"Extension") ||
			 stringsEqual( inspected.className, L"SoftwareComponent") ||
			 inspected.requiredNullCompanion || inspected.requiredRegistryOnlyCompanion ||
			 (stringsEqual( inspected.className, L"System") &&
			  isInheritedSystemContent( inf.get()))) &&
			(inspected.requiredNullCompanion || inspected.requiredRegistryOnlyCompanion ||
			 (SetupGetLineCountW( inf.get(), L"SourceDisksFiles.amd64") < 0L &&
			  SetupGetLineCountW( inf.get(), L"SourceDisksFiles") < 0L)) ;
		// 欠落を確認する追加判定は元パッケージの内容検査に限る
		const bool allowProvenAbsence =
			policy.rejectInstallActions &&
			(inspected.inspectionPurpose == OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
			 inspected.inspectionPurpose ==
				 OfficialInfInspectionPurpose::DECLARATIVE_CLASS_CONTENT) ;
		ScopedMediaSources isolatedMedia ;	// 同じ元署名に結んだ不在媒体です
		// 先行の共同インストーラー証明で確認した元位置を保持します
		if( !inactive.registry.empty()) {
			isolatedMedia.missing.assign( inactive.files.begin(), inactive.files.end()) ;
		}

		// 署名と対象範囲が成立した同じ元CABにだけ新しい不在証明を試みます
		if( scopedModels && scopedModels->sameDirectCabinet && inspected.scopedModels &&
		   inspected.className == L"Net" && !noOwnSourceFiles) {
			auto inspectedMedia =
				readScopedMediaSources( workspace, entries, inf.get(), scopedInfPin.bytes(),
									   inspected, infParent) ;	// 元CAB内の完全位置だけです
			isolatedMedia.missing.insert( isolatedMedia.missing.end(),
										 inspectedMedia.missing.begin(),
										 inspectedMedia.missing.end()) ;
			isolatedMedia.x86 = std::move( inspectedMedia.x86) ;
		}

		const auto checkSources = [&]( std::span<const std::wstring> required) {
			return collectSourceFiles(
				inf.get(), workspace, entries, infParent, policy.maximumSourceFiles,
				policy.requireDriverBinary, inspected.sourceFiles, nullptr,
				policy.allowReferencedExecutablesForContent, serviceExecutables,
				&inspected.hasUnassessedProgramReferences,
				policy.allowWindowsManagedDriverDataForContent, allowProvenAbsence, required,
				isolatedMedia.missing, isolatedMedia.x86) ;
		} ; // 通常検査と同じ元位置・存在・種類の確認
		result = (noOwnSourceFiles || !inspected.collectorInboxInstallGroups.empty())
					 ? 0
					 : checkSources( {}) ;
		// 元USB対象を署名で確認した直CABだけを、自己媒体なしの同梱依存検査へ送る
		if( result == nativeErrorFromWin32( ERROR_LINE_NOT_FOUND) && scopedModels &&
		   scopedModels->sameDirectCabinet && collectorInbox &&
		   stringsEqual( inspected.className, BLUETOOTH_CLASS.front())) {
			result = collectUsbBluetoothInboxGroup( inf.get(), entries, inspected) ;
		}

		// 表示用の独自クラスを検査した公式直CABだけで、WinUSBの完全委譲を確認する
		if( result == nativeErrorFromWin32( ERROR_LINE_NOT_FOUND) && scopedModels &&
		   scopedModels->sameDirectCabinet && collectorInbox && declarativeClass) {
			result = collectWinUsbInboxGroup( inf.get(), entries, inspected) ;
		}

		// 媒体の先頭行が無い場合は、元NVMe委譲の空リストが実在することを確認します
		if( scsi && collectorInbox && result == nativeErrorFromWin32( ERROR_LINE_NOT_FOUND)) {
			OfficialInfPackage inbox ;	// 成立した元構造だけを署名後の検査へ引き渡します
			const auto matched = collectInboxInstallGroups( inf.get(), CollectorInboxKind::NVME,
														   inbox) ;	// 元節と媒体を読み取った結果です
			// APIの資源不足を元の媒体欠落と区別します
			if( matched == E_OUTOFMEMORY) {
				return matched ;
			}

			// 空媒体の構造が全部成立した場合だけ、署名付き依存検査の要求へ進めます
			if( matched == 0) {
				inspected.collectorInboxInstallGroups =
					std::move( inbox.collectorInboxInstallGroups) ;
				inspected.collectorInboxNvmeLists = std::move( inbox.collectorInboxNvmeLists) ;
				result							  = 0 ;
			}
		}

		// 実際に媒体ファイルが不足する内容用途だけでAMD64全節の証明を試みる
		if( result == nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) && allowProvenAbsence) {
			std::vector<std::wstring> required ;	// AMD64の全候補が参照する正確な元ファイル
			// 未知の作用や不明な節があれば元の拒否を保持する
			if( collectProvenAmd64Sources( inf.get(), infParent, declarativeClass, required)) {
				result = checkSources( required) ;
			}
		}

		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( result != 0) {
			return result ;
		}

		// 元SYSの閉包と関連サービスが一致したときだけ自己媒体の根拠を保持する
		if( inspected.nativePortsPage && (inspected.sourceFiles.size() != 1U ||
										 !stringsEqual( inspected.sourceFiles.front(),
													   inspected.nativePortsPage->driverSource))) {
			// 収集で認めた元ページだけを残し、元SYSの不足を隠さない
			if( collectorInbox) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			inspected.nativePortsPage.reset() ;
		}

		// 共有ページでも媒体表が同じ一つの実SYSに閉じることを要求する
		if( inspected.collectorSharedPortsPage &&
		   (inspected.sourceFiles.size() != 1U ||
			!stringsEqual( inspected.sourceFiles.front(),
						  inspected.collectorSharedPortsPage->driverSource))) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 登録の媒体位置を同じINFの全sourceへ結び、別rootの同名DLLを拒否します
		if( propertyPage) {
			const auto path =
				// 元root付き位置です
				joinRelativePath( infParent, propertyPage->sourceRelativePath) ;
			const auto member = std::ranges::find_if( inspected.sourceFiles, [&]( const auto &name) {
				return stringsEqual( name, path) ;
			}) ; // 同一CAT照合が必須の原memberです
			// 通常のsource列挙に存在しない媒体位置を後段で補いません
			if( member == inspected.sourceFiles.end()) {
				return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
			}

			propertyPage->sourceRelativePath = *member ;
			inspected.collectorPropertyPage	 = std::move( propertyPage) ;
		}

		// 混在媒体はWindows同梱側を参照していても、元SYSとDLLを両方検査する
		if( inspected.collectorSerialMedia &&
		   (inspected.sourceFiles.size() != 2U || !inspected.collectorPropertyPage ||
			std::ranges::none_of( inspected.sourceFiles, [&]( const auto &source) {
				return stringsEqual( source, inspected.collectorSerialMedia->driverSource) ;
			}))) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		inspected.hasUnassessedProgramReferences =
			inspected.hasUnassessedProgramReferences || unassessedActions ;
		// 元検証済みClass/ID/fileからだけ必要構成を解析します
		if( policy.allowRequiredDriverComponents) {
			result =
				inspectRequiredDriverRelations( inf.get(), workspace, entries, inspected, {},
											   scopedModels ? scopedModels->cancellation : nullptr) ;
			// 不足・曖昧な関係から部分的な導入metadataを返しません
			if( result != 0) {
				return result ;
			}

			// 未検査CopyINFを内容合格の閉集合へ昇格しません
			if( policy.purpose != OfficialInfInspectionPurpose::STANDARD_DRIVER &&
			   !inspected.unresolvedCopyInfPaths.empty()) {
				return nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
			}
		}

		// 同じAMD64選択でコピー、起動サービス、Systemイベントの全参照を確認する
		if( mediumChanger && !checkMediumChanger( inf.get(), infParent, inspected)) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		// 元二節の形式は、署名閉包に入る別アーキテクチャのSYSを実選択とは別に保持する
		const bool hdcWithCommonMedia =
			!inspected.nativeHdcInstallGroups.empty() &&
			std::ranges::all_of( inspected.nativeHdcInstallGroups,
								[]( const auto &group) { return group.size() == 2U ; }) ;
		// この形式では外部依存やSYS以外の実行ファイルを同じブートサービスへ結合しない
		if( !inspected.nativeHdcInstallGroups.empty() &&
		   (inspected.sourceFiles.empty() ||
			(!hdcWithCommonMedia && inspected.sourceFiles.size() != 1U) ||
			std::ranges::any_of( inspected.sourceFiles,
								[]( const auto &name) { return lowerExtension( name) != L".sys" ; }) ||
			inspected.hasExternalDependencies || inspected.unresolvedIncludeNeeds ||
			inspected.hasUnassessedProgramReferences || !inspected.requiredInfPaths.empty() ||
			!inspected.requiredComponents.empty())) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		package = std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		package = {} ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
namespace {

//------------------------------------------------------------------------------
/**
 * @brief 共通または固定signer policyでWindows署名とCATを検査する
 * @param[in] workspace INF閉包の所有領域
 * @param[in] package 静的検査済みINF
 * @param[in] acceptedSigners 固定policyのsigner群
 * @param[in] windowsPolicy Windows検証済みの非空signerを使用する場合true
 * @param[out] publisher 非null時だけ全署名/同CAT成功後の実DigitalSignerです。省略可です
 * @return Windows署名、CATとsigner条件に合格した場合0
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyInfCatalogSignature(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::span<const std::wstring_view> acceptedSigners, const bool windowsPolicy,
	std::wstring *publisher = nullptr)
{
	const std::wstring infPath = workspace.path( package.infRelativePath) ;	// INF絶対path
	const std::wstring expectedCatalogPath =
		// 検証対象workspace内CAT絶対path
		workspace.path( package.catalogRelativePath) ;
	// 固定signerとWindows検証済みsignerのpolicyを混在させない
	if( infPath.empty() || expectedCatalogPath.empty() ||
	   (windowsPolicy ? !acceptedSigners.empty() : acceptedSigners.empty())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	SP_INF_SIGNER_INFO_W signer{} ;	// SetupAPIが返すcatalogと署名者情報
	signer.cbSize = sizeof( signer) ;
	// WindowsのINF署名検証失敗を元の診断値で返す
	if( driver_package_signature_detail::setupVerifyInf( infPath.c_str(), nullptr, &signer) ==
	   FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	const std::wstring_view actualCatalog( signer.CatalogFile) ;	// SetupAPIが署名に使用したCAT
	const std::wstring_view actualSigner( signer.DigitalSigner) ;	// 検証済みsigner表示名
	// File名だけで別directoryのCATを誤認しないよう、workspace内絶対pathへ完全一致させる
	if( !stringsEqual( actualCatalog, expectedCatalogPath)) {
		return nativeErrorFromWin32( ERROR_INVALID_NAME) ;
	}

	// 非空のWindows検証済みsignerを要求し、固定policyならallowlistも照合する
	if( actualSigner.empty() || (!windowsPolicy && !isAllowedValue( actualSigner, acceptedSigners))) {
		return nativeErrorFromWin32( ERROR_ACCESS_DENIED) ;
	}

	// 同原CATへ結合した実署名者だけを任意の非許可metadataへ写します
	if( publisher != nullptr) {
		publisher->assign( actualSigner) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同一の署名検証とCAT member処理を両policyで共有する
 * @param[in] workspace INF閉包の所有領域
 * @param[in] package 静的検査済みINF
 * @param[in] acceptedSigners 固定policyのsigner群
 * @param[in] windowsPolicy Windows検証済みの非空signerを使用する場合true
 * @return 全署名と全memberが一致した場合0
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyInfPackageIntegrity(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::span<const std::wstring_view> acceptedSigners, const bool windowsPolicy)
{
	OfficialMappedFile classInfPin ;	// 特例を認めた元INFの固定をCAT検査完了まで保持する
	// 収集の追加形式でだけ元INFをもう一度固定し、検査後の置換を拒否する
	if( !package.collectorClassInfSha256.empty()) {
		// 追加のクラス判定を端末や別の署名用途で採用しない
		if( !windowsPolicy ||
		   package.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		const auto classInfPath = workspace.path( package.infRelativePath) ;	// 構造検査を行った元INF
		// クラス登録の元INFを上限付きで固定した結果
		const auto pinError = classInfPin.open( classInfPath, MAXIMUM_INACTIVE_CO_INSTALLER_BYTES) ;
		// 同一の保護ファイルを開けない場合は後続のCATへ渡さない
		if( pinError != 0U) {
			return pinError ;
		}

		const auto metadataError = verifyOfficialFileMetadata(
			classInfPath,
			{std::nullopt, package.collectorClassInfSha256}) ;	// 追加判定時の完全SHA-256
		// 元ハッシュへ照合できた同じファイルだけを固定したまま検査する
		if( metadataError != 0U) {
			return metadataError ;
		}
	}

	// INFとCATの整合性・署名・許可publisherの検証結果
	const NativeError signatureError =
		verifyInfCatalogSignature( workspace, package, acceptedSigners, windowsPolicy) ;
	// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
	if( signatureError != 0) {
		return signatureError ;
	}

	const std::wstring catalogPath =
		// 検証済みCAT絶対path
		workspace.path( package.catalogRelativePath) ;
	const std::wstring infPath = workspace.path( package.infRelativePath) ;	// INF絶対path
	// 参照fileがないINFも自身のCAT照合を必須とし、INFやCATの欠落だけは拒否する
	if( catalogPath.empty() || infPath.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		std::vector<std::wstring> memberPaths ;	// CAT member検証するINFと参照file群
		memberPaths.reserve( package.sourceFiles.size() + 1U) ;
		memberPaths.push_back( infPath) ;
		// INFが現在architectureで参照した全fileを同じCATへ結び付ける
		for( const std::wstring &relativePath : package.sourceFiles) {
			const std::wstring memberPath = workspace.path( relativePath) ;	// Member絶対path
			// 参照memberをworkspace内へ解決できなければCAT照合を中止する
			if( memberPath.empty()) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			memberPaths.push_back( memberPath) ;
		}

		return verifyOfficialCatalogMembers( catalogPath, memberPaths) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief INFと対応catalogのWindows driver署名およびsigner allowlistを検証する。INFと対応catalogの署名を検証する
 *        SetupVerifyInfFileをWindows driver署名の正本とし、返されたcatalogとsignerをProvider固定allowlistへ完全一致させる
 * @param[in] workspace Package fileを所有する保護workspace
 * @param[in] package 構造検証済みのINF package
 * @param[in] acceptedSigners 許可するWindows driver signer表示名群。 許可するdriver signer表示名群
 * @return 署名とcatalog名とsignerが一致した場合は0、それ以外はHRESULT。 署名、catalog名、signer一致時は0、それ以外はHRESULT
 * @note SetupVerifyInfFileはblockingし得るためProvider worker threadから呼び出す
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialInfCatalogSignature(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::span<const std::wstring_view> acceptedSigners)
{
	return verifyInfCatalogSignature( workspace, package, acceptedSigners, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INF署名、signer、およびINFと全参照fileのcatalog member hashを検証する。INF package全体のcatalog整合性を検証する
 *        SetupAPIでINF signerを確定した後、INF自身と全参照fileを同じCATのmemberとして検証し、部分検証を候補化しない。静的参照検査でsourceが0件と確定した場合も、
 *        INF自身のmember検証を省略しない
 * @param[in] workspace Package fileを所有する保護workspace
 * @param[in] package 構造検証済みのINF package
 * @param[in] acceptedSigners 許可するWindows driver signer表示名群。 許可するdriver signer表示名群
 * @return 全署名・hash検証成功時は0、最初に失敗した検証のHRESULT。 署名と全member hashが有効なら0、それ以外はHRESULT
 * @note 本関数の成功後だけ、現在deviceとのlocal PnP ID照合へ進める
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialInfPackageIntegrity(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::span<const std::wstring_view> acceptedSigners)
{
	return verifyInfPackageIntegrity( workspace, package, acceptedSigners, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsが検証したsignerと同一CATの全memberを共通経路で検査する
 * @param[in] workspace INF閉包を所有する保護領域
 * @param[in] package 構造と全参照fileを検査したINF
 * @return SetupVerifyInfFile成功、非空signer、同一CAT、全member合格時0、それ以外はHRESULT
 * @note Maker表示名をsignerと比較しない。Windows署名失敗やtrust未確立を成功へ変換しない。静的参照検査でsourceが0件と確定した場合も、INF自身を必ずCATへ照合
 *       する。収集または端末選択の標準メディアチェンジャーでは同CATのAMD64 SYSとWindowsの保護イベント資源を確認する
 * @note 混在シリアルの私有収集では、元SYSを同じ保護領域で固定し、CAT照合後にAMD64形式を確認する
 * @note Blockingするためworkerから呼ぶ。成功は導入policy・実device適合・公式由来を保証しない
 */
//------------------------------------------------------------------------------
NativeError verifyWindowsInfPackageIntegrity( const OfficialDownloadWorkspace &workspace,
											 const OfficialInfPackage		 &package)
{
	OfficialMappedFile serialDriver ;	// 同じ元SYSをCAT照合と形式検査の間で固定する
	// 混在シリアルは保護された私有収集領域の元SYSだけを固定する
	if( package.collectorSerialMedia) {
		// 内容用途の結果を端末用の署名ゲートへ差し替えない
		if( package.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
		   workspace.protectionMode() != OfficialWorkspaceMode::CURRENT_USER_INSPECTION) {
			return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		}

		const auto path =
			// 結合した元バイナリ
			workspace.path( package.collectorSerialMedia->driverSource) ;
		const auto pinned =
			// 元書庫の一件上限内で固定
			serialDriver.open( path, 16U * 1024U * 1024U) ;
		// 同じ実体を固定できない場合は署名成功を返さない
		if( pinned != 0U) {
			return pinned ;
		}
	}

	// 元CATと全参照の署名検査結果
	const auto integrity = verifyInfPackageIntegrity( workspace, package, {}, true) ;
	// 照合した同じ元SYSかつAMD64として読める場合だけ媒体を受理する
	if( integrity == 0U && package.collectorSerialMedia) {
		return verifyAmd64PeFile( workspace.path( package.collectorSerialMedia->driverSource)) ;
	}

	// 正式メディアチェンジャーの元CATを検証してから専用の資源検査へ渡す
	if( integrity != 0 || !stringsEqual( package.className, MEDIUM_CHANGER_CLASS.front())) {
		return integrity ;
	}

	// 端末の追加検査では管理者保護領域を必要とする
	if( package.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT &&
	   (package.inspectionPurpose != OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE ||
		workspace.protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR)) {
		return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	}

	// 正式GUIDと唯一の元SYSを検証対象にする
	if( package.sourceFiles.size() != 1U ||
	   !stringsEqual( package.classGuid, MEDIUM_CHANGER_CLASS.back())) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// 同CATの元SYSのアーキテクチャ検査結果
	const auto binary = verifyAmd64PeFile( workspace.path( package.sourceFiles.front())) ;
	// 元SYSの形式が不成立ならイベント資源の検査を止める
	if( binary != 0) {
		return binary ;
	}

	std::array<wchar_t, MAX_PATH> system{} ;	// 元イベントの参照先となるWindowsの絶対位置
	// 現在のシステム位置として読み取れた文字数
	const auto length = GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
	// 空または切り詰められた位置を参照先に使わない
	if( length == 0U || length >= system.size()) {
		return nativeErrorFromWin32( ERROR_PATH_NOT_FOUND) ;
	}

	WindowsSystemFileTrust proof ;	// 元Windowsイベント資源の保護とキャッシュ署名の検査結果
	return verifyWindowsSystemFileCachedOnly(
		std::wstring( system.data(), length) + L"\\IoLogMsg.dll", proof) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元媒体を閉包のハッシュと用途別のファイル形式へ照合する
 * @param[in] workspace 同じ元CATを検査した閉包を保持する領域です
 * @param[in] entries 実バイトから得た元ファイルの一覧です
 * @param[in] source 一実選択でコピーを結んだ元ファイルの相対位置です
 * @param[out] member 元バイトが一致した場合だけの一覧内エントリです
 * @param[in] executable SYSまたは無線LAN拡張DLLにAMD64形式を要求する場合trueです
 * @return 同じ媒体のサイズ、ハッシュ、必要なAMD64形式が成立した場合0、それ以外はHRESULTです
 */
//------------------------------------------------------------------------------
static NativeError verifyScopedArchiveSource( const OfficialDownloadWorkspace		&workspace,
											 const std::span<const OfficialZipEntry> entries,
											 const std::wstring_view				 source,
											 const OfficialZipEntry				   *&member,
											 const bool executable = true)
{
	member = nullptr ;
	// 元媒体が閉包内の全ハッシュ付きエントリを指すことを確認する
	const auto found = std::ranges::find_if(
		entries, [&]( const auto &file) { return stringsEqual( file.relativePath, source) ; }) ;
	// 元位置やハッシュの欠落を媒体の合格へ補完しない
	if( found == entries.end() || found->sha256.size() != 64U) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const auto path	 = workspace.path( found->relativePath) ;	// 閉包で保護された元位置
	auto	   error = verifyOfficialFileMetadata(
		  path, {found->uncompressedSize, found->sha256}) ;	// 元バイトの照合結果
	// 補助データの元バイトは照合するが、実行形式の判定はSYSとDLLに適用する
	if( error == 0U && executable) {
		error = verifyAmd64PeFile( path) ;
	}

	// すべての元媒体検査後にだけ閉包の一覧項目を借用して返す
	if( error == 0U) {
		member = &*found ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 単一SYSからなる表示クラスの選択と全関連節を照合する
 * @param[in] inf 同じ署名済み元INFを保持する読み取り専用handle
 * @param[in] install Windowsが対象OSで解決した実導入節
 * @param[in] registration 検査済み表示クラス登録
 * @param[in] model 同じ対象OSが選んだ唯一のModels節
 * @param[out] copy 成立時だけ確定する同名SYSのコピー位置
 * @return クラス・コピー・サービス・KMDFの全宣言が成立した場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] static bool readScopedDeclarativeKernelCopy(
	HINF inf, const std::wstring &install,
	const OfficialInfDeclarativeClassRegistration &registration, std::wstring_view model,
	WindowsDriverCopy &copy)
{
	std::wstring registry ;										// クラスの表示値だけを持つ元節
	std::wstring list ;											// 同名SYSをコピーする元節
	const auto	 services	  = install + L".Services" ;		// 唯一の関連サービスの所有節
	const auto	 coinstallers = install + L".CoInstallers" ;	// 空の二参照を保持する元節
	const auto	 wdf		  = install + L".Wdf" ;				// 同じサービスに属するKMDF指定
	std::wstring coRegistry ;									// 参照される空の登録節
	std::wstring coCopy ;										// 参照される空のコピー節
	INFCONTEXT	 serviceRow{} ;									// サービスを追加する唯一の元行
	INFCONTEXT	 wdfRow{} ;										// 同じサービスを指定するKMDFの元行
	std::wstring serviceName ;									// 関連カーネルサービスの元名
	std::wstring service ;										// 同サービスの構成節
	std::wstring library ;										// 同サービスのKMDF設定節
	std::wstring value ;										// 展開した元文字列
	// 追加処理を持たない所有節と各一意の明示参照だけを検査する
	if( !readDeclarativeClassTarget( inf, registration.section, registry) ||
	   SetupGetLineCountW( inf, install.c_str()) != 1L ||
	   readRequiredServiceField( inf, install, L"CopyFiles", list) != 0U ||
	   !validInstallInventorySectionName( list) || SetupGetLineCountW( inf, services.c_str()) != 1L ||
	   !SetupFindFirstLineW( inf, services.c_str(), L"AddService", &serviceRow) ||
	   SetupGetFieldCount( &serviceRow) != 3U || readInfField( serviceRow, 1U, serviceName) != 0U ||
	   !validInstallInventorySectionName( serviceName) ||
	   !propertyPageNumber( serviceRow, 2U, SPSVCINST_ASSOCSERVICE, false) ||
	   readInfField( serviceRow, 3U, service) != 0U || !validInstallInventorySectionName( service) ||
	   SetupGetLineCountW( inf, coinstallers.c_str()) != 2L ||
	   readRequiredServiceField( inf, coinstallers, L"AddReg", coRegistry) != 0U ||
	   readRequiredServiceField( inf, coinstallers, L"CopyFiles", coCopy) != 0U ||
	   validateEmptyCoInstallers( inf, coinstallers.c_str()) != 0U ||
	   SetupGetLineCountW( inf, wdf.c_str()) != 1L ||
	   !SetupFindFirstLineW( inf, wdf.c_str(), L"KmdfService", &wdfRow) ||
	   SetupGetFieldCount( &wdfRow) != 2U || readInfField( wdfRow, 1U, value) != 0U ||
	   !stringsEqual( value, serviceName) || readInfField( wdfRow, 2U, library) != 0U ||
	   !validInstallInventorySectionName( library) ||
	   SetupGetLineCountW( inf, library.c_str()) != 1L ||
	   readRequiredServiceField( inf, library, L"KmdfLibraryVersion", value) != 0U ||
	   value != L"1.15") {
		return false ;
	}

	// 既存OSに含まれるKMDFを宣言する形式だけを扱い、別の条件を持つ節を拒否する
	const std::array<std::wstring_view, 18U> permitted{L"Version",
													   L"DestinationDirs",
													   registration.section,
													   registry,
													   L"SourceDisksNames",
													   L"SourceDisksFiles",
													   L"Manufacturer",
													   model,
													   install,
													   list,
													   services,
													   service,
													   coinstallers,
													   coRegistry,
													   coCopy,
													   wdf,
													   library,
													   L"Strings"} ;
	constexpr std::array					 versionKeys{
		L"Signature", L"Class",		  L"ClassGUID",
		L"Provider",  L"CatalogFile", L"DriverVer"} ;	// 外部媒体へのVersion委譲を許さない
	INFCONTEXT	  copyRow{} ;							// 改名を持たない元コピー行
	std::wstring  leaf ;								// 選択と媒体で共通のSYS名
	std::uint32_t scalar{} ;							// Windows数値readerの元サービス値
	// 元節の全体、媒体一行、空コピーの宛先と関連サービスの全宣言を確認する
	return verifyExactInfSections( inf, permitted) == 0U &&
		   SetupGetLineCountW( inf, L"Version") == static_cast<LONG>( versionKeys.size()) &&
		   std::ranges::all_of( versionKeys,
							   [inf]( const auto key) {
								   INFCONTEXT row{} ;	// 元INFの同じVersion項目を同期中だけ借用する
								   return SetupFindFirstLineW( inf, L"Version", key, &row) != FALSE ;
							   }) &&
		   SetupGetLineCountW( inf, L"DestinationDirs") == 2L &&
		   readRequiredServiceScalar( inf, L"DestinationDirs", L"DefaultDestDir", scalar) == 0U &&
		   scalar == 12U &&
		   readRequiredServiceScalar( inf, L"DestinationDirs", coCopy.c_str(), scalar) == 0U &&
		   scalar == 11U && SetupGetLineCountW( inf, L"SourceDisksNames") == 1L &&
		   SetupGetLineCountW( inf, L"SourceDisksFiles") == 1L &&
		   SetupGetLineCountW( inf, list.c_str()) == 1L &&
		   SetupGetLineByIndexW( inf, list.c_str(), 0U, &copyRow) &&
		   SetupGetFieldCount( &copyRow) == 1U && readInfField( copyRow, 1U, leaf) == 0U &&
		   readInfField( copyRow, 0U, value) == 0U && stringsEqual( value, leaf) &&
		   lowerExtension( leaf) == L".sys" &&
		   resolveWindowsDriverCopy( inf, {}, list, leaf, leaf, copy) == 0U && copy.dirid == 12 &&
		   stringsEqual( copy.source, leaf) && SetupGetLineCountW( inf, service.c_str()) == 5L &&
		   readRequiredServiceField( inf, service, L"DisplayName", value) == 0U && !value.empty() &&
		   !value.starts_with( L"@") &&
		   readRequiredServiceScalar( inf, service, L"ServiceType", scalar) == 0U &&
		   scalar == SERVICE_KERNEL_DRIVER &&
		   readRequiredServiceScalar( inf, service, L"StartType", scalar) == 0U &&
		   scalar == SERVICE_DEMAND_START &&
		   readRequiredServiceScalar( inf, service, L"ErrorControl", scalar) == 0U &&
		   scalar == SERVICE_ERROR_NORMAL &&
		   readRequiredServiceField( inf, service, L"ServiceBinary", value) == 0U &&
		   boundWindowsServiceBinary( value, std::span{&copy, 1U}, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式対象を同じCABの表示クラスと単一の署名済みKMDF媒体へ結ぶ
 * @param[in] workspace 署名検査済みの元閉包を保持する保護領域
 * @param[in] entries 同じCABの展開時ハッシュを持つ全ファイル
 * @param[in] package 公式Modelsと全CAT所属を検査済みの基本INF
 * @return 表示クラスと同じAMD64 SYSの全参照を照合できた場合true
 * @note 初回収集用の内容証拠だけを返し、端末の導入資格を発行しない
 */
//------------------------------------------------------------------------------
bool verifyScopedDeclarativeKernelReferences( const OfficialDownloadWorkspace  &workspace,
											 std::span<const OfficialZipEntry> entries,
											 const OfficialInfPackage		  &package)
{
	// 同じCABの三ファイルと一つのAMD64 Modelsに結び、外部媒体を追加しない
	if( package.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
	   package.role != DriverPlanRole::BASE_DRIVER || !package.scopedModels ||
	   !package.scopedModels->platform || package.scopedModels->sections.size() != 1U ||
	   entries.size() != 3U || package.sourceFiles.size() != 1U || package.requiredNullCompanion ||
	   package.requiredRegistryOnlyCompanion || !package.activeRequiredInfPaths.empty() ||
	   !package.unresolvedCopyInfPaths.empty() || !package.requiredComponents.empty()) {
		return false ;
	}

	const auto &scope	 = *package.scopedModels ;	// 公式配布の元照合証拠
	const auto &platform = *scope.platform ;		// 明示したWindows対象
	const auto &models	 = scope.sections.front() ;	// 公式範囲を保持した元Models
	// KMDF 1.15を同梱するWindowsと、一つの実導入節に結ぶPCI対象だけを扱う
	if( platform.processorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 ||
	   platform.majorVersion != 10U || platform.buildNumber < 10240U || models.matches.empty() ||
	   !std::ranges::all_of(
		   models.matches,
		   [&]( const auto &model) {
			   return stringsEqual( model.installBase, models.matches.front().installBase) &&
					  stringsEqual( std::wstring_view{model.hardwareId}.substr( 0U, 4U), L"PCI\\") ;
		   })) {
		return false ;
	}

	// 同じ公式選択の元INFを閉包に結び付けるメンバー
	const auto entry =
		std::ranges::find( entries, package.infRelativePath, &OfficialZipEntry::relativePath) ;
	const auto		   path = workspace.path( package.infRelativePath) ;	// 同元INFと展開時hashの位置
	OfficialMappedFile original ;											// HINFを閉じるまで元INFを保持する
	// 一致した元バイトの保護コピーだけをSetupAPIに渡す
	if( entry == entries.end() || entry->sha256 != scope.infSha256 ||
	   original.open( path, 4U * 1024U * 1024U) != 0U ||
	   verifyOfficialFileMetadata( path, {entry->uncompressedSize, entry->sha256}) != 0U) {
		return false ;
	}

	// 署名済みの元INFから実際の表示クラス作用を読む所有ハンドル
	const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
										  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;
	auto requested = nativeModelsPlatform( platform) ;		// 同じ対象を選ぶSetupAPIの代替プラットフォーム
	std::wstring							install ;		// 元の唯一の実導入節
	std::wstring							guid ;			// Windowsと照合したクラスGUID
	OfficialInfDeclarativeClassRegistration registration ;	// 元表示クラスの検査済み登録
	WindowsDriverCopy						copy ;			// 一つのAMD64 SYSの元コピー
	std::vector<std::wstring>				declared ;		// 正規Manufacturerの全Models節
	std::size_t manufacturerRows{} ;						// 別アーキテクチャや別節を隠さない元行数
	// クラスの衝突・別文脈参照を既存検査で拒否し、実選択と元全節を確認する
	if( inf.get() == INVALID_HANDLE_VALUE || !requested ||
	   !collectDeclaredModelSections( inf.get(), false, declared, manufacturerRows) ||
	   manufacturerRows != 1U || declared.size() != 1U ||
	   !stringsEqual( declared.front(), models.modelSection) ||
	   inspectDeclarativeSetupClass( inf.get(), path, package.className, guid, &registration, {},
									&platform) != 0U ||
	   !stringsEqual( guid, package.classGuid) ||
	   // SDKの先頭サイズでV3を識別させ、既定altplatformのポインタ表記で渡す
	   resolveActualInstallInventorySection( inf.get(), models.matches.front().installBase, install,
											reinterpret_cast<PSP_ALTPLATFORM_INFO>( &*requested)) !=
		   0U ||
	   !readScopedDeclarativeKernelCopy( inf.get(), install, registration, models.modelSection,
										copy) ||
	   !stringsEqual( copy.source, package.sourceFiles.front())) {
		return false ;
	}

	const OfficialZipEntry *member{} ;	// 同じ元CATで検査した一つの媒体の展開時エントリ
	return verifyScopedArchiveSource( workspace, entries, copy.source, member) == 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式Net対象のイベント参照を署名済みSYSと収集側Windows標準DLLへ結ぶ
 * @param[in] workspace 元INF・CATと参照ファイルの同一保護領域
 * @param[in] entries 実ハッシュを固定した元閉包のファイル一覧
 * @param[in] package 同一元CATと公式Modelsを検査した基本INF
 * @param[in,out] effects 同じ元INFと起点の作用棚卸し。全検査が終わった場合だけ起点数を返す
 * @return 対象なしまたは全結合成功は0、形式・署名・パス・ファイル差異はHRESULT
 * @pre 同じ元閉包のWindows INF署名と全CATメンバー検査が成功済み
 * @note 収集機のWindows DLLを検査し、端末の状態や導入資格は認定しない
 */
//------------------------------------------------------------------------------
NativeError verifyScopedNetworkEventFiles( const OfficialDownloadWorkspace  &workspace,
										  std::span<const OfficialZipEntry> entries,
										  const OfficialInfPackage		   &package,
										  MaintenanceInfStructure		   &effects)
{
	effects.networkEventFileInstallCount = 0U ;
	// 公式範囲付きのNet以外には、このイベント資源照合を適用しません
	if( !package.scopedModels || !stringsEqual( package.className, L"Net")) {
		return 0 ;
	}

	effects.referenceCoverage = MaintenanceInfReferenceCoverage::NOT_CHECKED ;

	// 導入作用にイベント登録を伴うサービスがあるかを同期で調べる比較器
	const auto hasEvent = []( const auto &install) {
		return std::ranges::any_of(
			install.services, []( const auto &service) { return !service.eventLogSection.empty() ; }) ;
	} ;
	// イベント資源の参照がない導入集合では追加のファイル照合を省略します
	if( std::ranges::none_of( effects.installs, hasEvent)) {
		return 0 ;
	}

	try {
		// 元選択が指したINFを同じ保護閉包で見つけた位置
		const auto entry = std::ranges::find_if( entries, [&]( const auto &file) {
			return stringsEqual( file.relativePath, package.infRelativePath) ;
		}) ;
		// 元証拠の適用範囲、元INFのパスと実ハッシュがすべて一致することを要求します
		if( !effects.officialHardwareScope || entries.size() > 32'768U ||
		   !stringsEqual( effects.infRelativePath, package.infRelativePath) ||
		   effects.infSha256 != package.scopedModels->infSha256 || entry == entries.end() ||
		   entry->sha256 != effects.infSha256) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// 元INFに割り当てた保護領域内のパス
		const auto		   path = workspace.path( package.infRelativePath) ;
		OfficialMappedFile original ;	// HINFの全読取りが終わるまで元INFを固定する
		// 元ファイルを変更されない状態で読み取るため固定した診断値
		auto			   error = original.open( path, 4U * 1024U * 1024U) ;
		// ファイルを固定できた場合だけ、検査済みの元サイズとハッシュへ照合します
		if( error == 0) {
			error = verifyOfficialFileMetadata( path, {entry->uncompressedSize, entry->sha256}) ;
		}

		// 署名済みの元内容と照合できないファイルを作用解析に渡しません
		if( error != 0) {
			return error ;
		}

		// 固定した元INFのイベント節を読むSetupAPIの所有ハンドル
		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;
		// 元INFを開けない場合は資源の照合を始めません
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		error = validateSetupClassPair( inf.get(), NET_CLASS) ;
		// Windows標準資源との照合に必要な元作用が不明なら診断を返します
		if( error != 0) {
			return error ;
		}

		std::array<wchar_t, MAX_PATH> system{} ;	// 環境変数以外から得る正規のSystem32
		// システムDLLの既定ディレクトリを取得した文字数
		const auto length = GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
		// 読み出せなかったパスや切り詰められたパスから資源を選びません
		if( length == 0U || length >= system.size()) {
			return nativeErrorFromWin32( ERROR_PATH_NOT_FOUND) ;
		}

		// 現在のWindowsシステムディレクトリ。元の標準資源を照合するときに借用します
		const std::wstring		  systemDirectory( system.data(), length) ;
		std::vector<std::wstring> executableSources ;	// 元SYSと追加DLLの照合位置
		std::vector<std::wstring> dataSources ;			// 元補助データの照合位置
		std::size_t				  installCount{} ;		// 元イベントと媒体を照合した起点数
		bool					  complete =
			// 全起点と共通部に未検査用途が残らない場合だけ有効
			effects.fileUses.empty() ;
		// 同じ元起点ごとに全ファイル用途を照合する
		for( const auto &install : effects.installs | std::views::filter( hasEvent)) {
			std::vector<ScopedNetworkSource> sources ;	// SYSを先頭に保持した同じ起点の全コピー元
			bool allUses{} ;							// 同じ起点でファイル参照を全件検査した場合だけ有効
			error =
				bindScopedNetworkEventSources( inf.get(), workspace, entries, package, install,
											  systemDirectory, sources, allUses, original.bytes()) ;
			// 元起点の失敗を別の起点の同一SYSで代替しない
			if( error != 0) {
				return error ;
			}

			// 元の用途型だけで媒体を再検査し、未確認形式を配列位置から推測しません
			for( auto &source : sources) {
				static_cast<void>(
					appendUnique( source.requiresAmd64 ? executableSources : dataSources,
								 std::move( source.relativePath))) ;
			}

			const bool hasDependencies =
				std::ranges::any_of( install.inventory.references, []( const auto &reference) {
					return reference.kind == OfficialInfInstallReferenceKind::INCLUDE_INF ||
						   stringsEqual( reference.directive, L"Needs") ||
						   stringsEqual( reference.directive, L"AddComponent") ;
				}) ; // 起点の明示依存だけを見る
			complete = complete && allUses && (!hasDependencies || install.wifiBusNeedsVerified) ;
			++installCount ;
		}

		// 同一CATで検査済みの全媒体を元ハッシュと用途別の形式に再照合する
		for( const bool executable : {true, false}) {
			// 同じ型で同じ元媒体は一度だけ読み直す
			for( const auto &source : executable ? executableSources : dataSources) {
				const OfficialZipEntry *member{} ;	// 再照合した元ファイル位置
				error = verifyScopedArchiveSource( workspace, entries, source, member, executable) ;
				// 一つでも元バイトから変われば起点数や検査完了を返さない
				if( error != 0) {
					return error ;
				}
			}
		}

		WindowsSystemFileTrust proof ;	// 実行せず、固定Windowsファイルの権限と署名を確認する
		error = verifyWindowsSystemFileCachedOnly( systemDirectory + L"\\netevent.dll", proof) ;
		// 全対象の資源照合に成功した時点で証拠件数を確定します
		if( error == 0) {
			effects.networkEventFileInstallCount = installCount ;
			effects.referenceCoverage = complete && installCount == effects.installs.size()
											? MaintenanceInfReferenceCoverage::COMPLETE
											: MaintenanceInfReferenceCoverage::INCOMPLETE ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 現在の端末で選択したNet導入節の媒体とWindows標準イベント資源を検査します
 * @param[in] workspace 同じ元INFと全CATメンバーを含む管理者保護領域です
 * @param[in] entries 元署名を検査した閉包の実ハッシュ一覧です
 * @param[in] selected 元Models照合済みの基本節と現OSの実導入節を保持します
 * @param[out] effects 完全な実作用と再検査用のWindowsファイル証拠です
 * @param[in] inboxNeeds 同一元CABと現在のWindowsへ外部Needsを照合する同期検査です。同梱依存のない経路はnullです
 * @return 一実選択の全ファイル用途と標準資源を確認した場合0、失敗はHRESULTです
 * @pre 呼出し側で署名済みの元配布物、元CATと端末の一意選択を確認します
 * @note 元INFと媒体を読取り専用で扱い、導入資格を発行しません
 */
//------------------------------------------------------------------------------
NativeError verifySelectedScopedNetworkInfEffects( const OfficialDownloadWorkspace  &workspace,
												  std::span<const OfficialZipEntry> entries,
												  const OfficialInfPackage		   &selected,
												  OfficialScopedNetworkEffects	   &effects,
												  const ScopedInboxNeedsVerifier   *inboxNeeds)
{
	effects = {} ;
	// この限定Net経路で検証できない作用に返す共通診断値
	const auto unsupported = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	// 元の公式範囲、現在Netクラス、保護された選択がそろった場合だけ検査します
	if( !selected.scopedModels || !stringsEqual( selected.className, NET_CLASS.front()) ||
	   !stringsEqual( selected.classGuid, NET_CLASS.back()) ||
	   selected.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
	   selected.role != DriverPlanRole::BASE_DRIVER || selected.requiredNullCompanion ||
	   selected.requiredRegistryOnlyCompanion || !selected.activeRequiredInfPaths.empty() ||
	   !selected.requiredComponents.empty() ||
	   workspace.protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR ||
	   entries.size() > 32'768U ||
	   !validInstallInventorySectionName( selected.selectedBasicSection) ||
	   !validInstallInventorySectionName( selected.selectedInstallSection)) {
		return unsupported ;
	}

	try {
		// 同じINFの署名済みModels証拠。作用の照合中だけ借用します
		const auto &proof = *selected.scopedModels ;
		// 実導入基本名と対象IDに対応する公式元行が署名済み一覧に存在するかを保持します
		const bool	officialBranch = std::ranges::any_of( proof.sections, [&]( const auto &section) {
			 return std::ranges::any_of( section.matches, [&]( const auto &row) {
				 return stringsEqual( row.installBase, selected.selectedBasicSection) &&
						stringsEqual( std::wstring_view{row.hardwareId}.substr( 0U, 4U), L"PCI\\") ;
			 }) ;
		 }) ;
		// 公式Modelsに結び付かないWindowsの選択を照合済みと扱いません
		if( !officialBranch) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// 実選択のINFが元閉包にあるかを調べる位置
		const auto entry =
			std::ranges::find( entries, selected.infRelativePath, &OfficialZipEntry::relativePath) ;
		// 公式元行のINFハッシュと同じ閉包の実ハッシュに一致しない選択を拒否します
		if( entry == entries.end() || entry->sha256 != proof.infSha256) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		// 選択INFに対応する保護領域内のパス
		const auto		   path = workspace.path( selected.infRelativePath) ;
		OfficialMappedFile pinned ;	// 元版と実選択を読む間は元INFの差替えを許可しません
		// 作用の再検査中に元INFを固定した際の診断値
		auto			   error = pinned.open( path, 4U * 1024U * 1024U) ;
		// 元ファイルを固定できた場合だけ、閉包の元サイズとハッシュを照合します
		if( error == 0U) {
			error = verifyOfficialFileMetadata( path, {entry->uncompressedSize, entry->sha256}) ;
		}

		// 検査済みの原内容を固定できないときは導入作用の読取りを行いません
		if( error != 0U) {
			return error ;
		}

		// 同じ元INFから作用を再読するSetupAPIの所有ハンドル
		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr)) ;
		// 元INFを現在環境で開けない場合は元のエラーを返します
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		error = validateSetupClassPair( inf.get(), NET_CLASS) ;
		// 元選択の内容検査が失敗した時点で診断を返します
		if( error != 0U) {
			return error ;
		}

		MaintenanceInfInstallStructure install ;	// 同一選択とその付随節だけを保持します
		install.inventory.infRelativePath	 = selected.infRelativePath ;
		install.inventory.infSha256			 = proof.infSha256 ;
		install.inventory.baseInstallSection = selected.selectedBasicSection ;
		error = resolveActualInstallInventorySection( inf.get(), selected.selectedBasicSection,
													 install.inventory.selectedInstallSection) ;
		// 読み戻した装飾済み導入節が選択時と異なる場合、同じ作用として扱いません
		if( error != 0U ||
		   install.inventory.selectedInstallSection != selected.selectedInstallSection) {
			return error != 0U ? error : nativeErrorFromWin32( ERROR_RETRY) ;
		}

		INFCONTEXT layout{} ;	// 選択節の外にある全INF共通の必要宣言です
		SetLastError( ERROR_SUCCESS) ;
		// 外部のレイアウト登録が必要なINFはこの限定作用では完結しません
		if( SetupFindFirstLineW( inf.get(), L"Version", L"LayoutFile", &layout)) {
			return unsupported ;
		}

		// 外部レイアウト宣言の有無を調べた直後のWin32診断値
		const auto layoutError = GetLastError() ;
		// 正常な行の不在とSetupAPIの読取りエラーを区別します
		if( layoutError != ERROR_SUCCESS && layoutError != ERROR_LINE_NOT_FOUND) {
			return nativeErrorFromWin32( layoutError) ;
		}

		// 選択INFの保存位置から切り出す親ディレクトリとの境界
		const auto				   separator = selected.infRelativePath.find_last_of( L'\\') ;
		// 同一階層の参照を解決するためのINFの親相対位置。直下なら空
		const auto				   parent = separator == std::wstring::npos
												? std::wstring_view{}
												: std::wstring_view{selected.infRelativePath}.substr( 0U, separator) ;
		MaintenanceStructureBudget budget ;	// 元の作用解析と同じ有限枠です
		budget.collectionContent = true ;
		budget.modelSections	 = proof.sections ;
		budget.scopedPciNet		 = true ;
		// 同梱依存を確認できる入口だけが無線の元属性と表示用途を解釈します
		budget.sharedRegistryInf = inboxNeeds ? inf.get() : nullptr ;
		error = inspectMaintenanceInstallStructure( inf.get(), workspace, entries, parent, budget,
												   install) ;
		// 元導入節の媒体や作用の一式を検査できない場合は結果を発行しません
		if( error != 0U) {
			return error ;
		}

		const auto &references = install.inventory.references ;	// 同じ元実選択の全参照です
		// 別パッケージの取込みと未評価の子導入を単一選択へ加えません
		if( std::ranges::any_of( references, []( const auto &reference) {
			   return stringsEqual( reference.directive, L"CopyINF") ||
					  stringsEqual( reference.directive, L"AddComponent") ;
		   })) {
			return unsupported ;
		}

		// 明示依存は同じ元選択で実際に照合した同梱依存だけを受理します
		if( std::ranges::any_of( references, []( const auto &reference) {
			   return reference.kind == OfficialInfInstallReferenceKind::INCLUDE_INF ||
					  stringsEqual( reference.directive, L"Needs") ;
		   })) {
			// Includeだけや元INF内だけのNeedsを確認済み同梱作用に変換しません
			if( !inboxNeeds || !*inboxNeeds ||
			   std::ranges::none_of( references, []( const auto &reference) {
				   return reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
						  !reference.targetPresent && stringsEqual( reference.directive, L"Needs") ;
			   })) {
				return unsupported ;
			}

			error = (*inboxNeeds)( install.inventory) ;
			// 同梱INF・実コピー・現在サービスの不成立を旧内容検査で補完しません
			if( error != 0U) {
				return error ;
			}

			install.wifiBusNeedsVerified = true ;
		}

		// Windows標準ディレクトリを取得する終端込みのバッファー
		std::array<wchar_t, MAX_PATH> system{} ;
		// 標準資源の照合先として使うWindowsシステムディレクトリ名の文字数
		const auto length = GetSystemDirectoryW( system.data(), static_cast<UINT>( system.size())) ;
		// パス取得失敗やバッファー不足の場合は標準資源の証拠を発行しません
		if( length == 0U || length >= system.size()) {
			return nativeErrorFromWin32( ERROR_PATH_NOT_FOUND) ;
		}

		// 現在のWindows標準DLLを解決するために所有するディレクトリ名
		const std::wstring				 systemDirectory( system.data(), length) ;
		std::vector<ScopedNetworkSource> sources ;	// 元SYSを先頭とする検査対象媒体の全相対位置
		// 全作用の照合が済んだ場合だけ立つ出力フラグ
		bool							 complete{} ;
		error = bindScopedNetworkEventSources( inf.get(), workspace, entries, selected, install,
											  systemDirectory, sources, complete, pinned.bytes()) ;
		// 照合が部分的に成立した結果で媒体や標準イベント資源を確定しません
		if( error != 0U || !complete) {
			return error != 0U ? error : unsupported ;
		}

		std::vector<OfficialScopedNetworkSourceFile>
			sourceFiles ;	// 同じ元コピーの用途順と全バイトです
		// 検証した同元コピーの役割によって実バイトと必要なAMD64形式を照合します
		for( const auto &source : sources) {
			const OfficialZipEntry *member{} ;	// 同じ署名閉包の確認済み元媒体です
			error = verifyScopedArchiveSource( workspace, entries, source.relativePath, member,
											  source.requiresAmd64) ;
			// 途中の実バイトまたは必要AMD64型の不成立で証拠を破棄します
			if( error != 0U) {
				return error ;
			}

			sourceFiles.push_back( {member->relativePath, member->sha256, member->uncompressedSize}) ;
		}

		// 現在のWindows標準DLLについて確認したファイルと信頼の証拠
		WindowsSystemFileTrust eventResource ;
		error =
			verifyWindowsSystemFileCachedOnly( systemDirectory + L"\\netevent.dll", eventResource) ;
		// 標準イベント資源の信頼検査に失敗した場合は元診断を返します
		if( error != 0U) {
			return error ;
		}

		effects = {proof.infSha256,
				   selected.selectedBasicSection,
				   selected.selectedInstallSection,
				   install.services.front().serviceName,
				   std::move( sourceFiles),
				   std::move( eventResource)} ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同保護INF/CATの全memberを検査して実Windows signer名だけを返します
 * @param[in] workspace 同原閉包を所有する保護領域です
 * @param[in] package 同原INFとCATを示す構造検査済みmetadataです
 * @param[out] publisher 同Windows署名/全member成功時だけ実DigitalSignerです。失敗時空です
 * @return 同exact CAT、Windows署名、全member成功0、失敗は元HRESULTです
 * @note INF Providerを代入せず、公式性/実端末適合/導入許可を発行しません。Workerでblockingします
 */
//------------------------------------------------------------------------------
NativeError readWindowsInfPackagePublisher( const OfficialDownloadWorkspace &workspace,
										   const OfficialInfPackage		   &package,
										   std::wstring					   &publisher)
{
	publisher.clear() ;
	const auto error =
		// 全CAT/memberの既存policyです
		verifyInfPackageIntegrity( workspace, package, {}, true) ;
	// 全member未確認のsigner名を検証済みpublisherへ昇格させません
	if( error != 0U) {
		return error ;
	}

	return verifyInfCatalogSignature( workspace, package, {}, true, &publisher) ;
}

//------------------------------------------------------------------------------
/**
 * @brief INFが参照する全fileのAuthenticode署名とpublisherを検証する。INF参照fileの埋込み署名を検証する。固定SHA-256で拘束したarchive内の実行
 *        binaryを個別検証し、未署名fileまたは異なるpublisherを一件でも受理しない
 * @param[in] workspace Package fileを所有する保護workspace
 * @param[in] package 構造検証済みでsourceFilesが確定したINF package。 構造検証済みのINF package
 * @param[in] requiredRelativePaths 署名とINF参照を必須にするworkspace相対path群。 署名を必須にする相対path群
 * @param[in] acceptedSigners 許可する埋込み署名publisher表示名群。 許可する署名publisher表示名群
 * @return 全指定fileのINF参照、署名、publisherが有効なら0、最初の失敗はHRESULT。 全参照fileの署名とpublisherが有効なら0
 * @note CAT member hashを置換する一般fallbackではなく、固定archive hashと併用する
 */
//------------------------------------------------------------------------------
NativeError verifyOfficialInfEmbeddedFileSignatures(
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const std::span<const std::wstring_view> requiredRelativePaths,
	const std::span<const std::wstring_view> acceptedSigners)
{
	// INF参照、必須署名対象、署名者allowlistが欠けた検証要求を拒否する
	if( package.sourceFiles.empty() || requiredRelativePaths.empty() || acceptedSigners.empty()) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// 固定policyの全fileをINF参照集合と同じpublisherへ拘束する
	for( std::size_t index = 0; index < requiredRelativePaths.size(); ++index) {
		const std::wstring_view relativePath = requiredRelativePaths[index] ;	// 現在の固定path
		const bool				duplicate =
			std::ranges::any_of( requiredRelativePaths.first( index),
								[relativePath]( const std::wstring_view previous) noexcept {
									return stringsEqual( relativePath, previous) ;
								}) ; // 先行pathとの重複状態
		const bool referenced = std::ranges::any_of(
			package.sourceFiles, [relativePath]( const std::wstring &sourceFile) noexcept {
				return stringsEqual( relativePath, sourceFile) ;
			}) ; // INF参照集合との一致状態
		// 不正、重複、INF未参照のpathを埋込署名検証対象にしない
		if( relativePath.empty() || relativePath.find( L'\0') != std::wstring_view::npos ||
		   duplicate || !referenced) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const std::wstring path = workspace.path( relativePath) ;	// 参照fileの絶対path
		// 署名対象fileを保護workspace内へ解決できなければ拒否する
		if( path.empty()) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		const NativeError error =
			// 埋込み署名検証結果
			verifyAuthenticodePublisher( path, acceptedSigners) ;
		// 検出した失敗を後続処理で上書きせず、同じ診断値を呼出し元へ返す
		if( error != 0) {
			return error ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief INFの検証済みPnP IDを現在deviceのHardware IDとCompatible IDへ照合する。INFを現在deviceのPnP IDへ照合する。PnP IDは
 *        worker内だけで大文字小文字を除く完全一致に使用し、部分一致、prefix一致、空IDによる適用範囲拡張を行わない
 * @param[in] package 構造検証済みのINF package
 * @param[in] deviceHardwareIds 現在deviceからworker内で取得したHardware ID群。 現在deviceのHardware ID群
 * @param[in] deviceCompatibleIds 現在deviceからworker内で取得したCompatible ID群。 現在deviceのCompatible ID群
 * @return Hardware ID、Compatible IDの優先順で得た完全一致結果。該当なしはNone
 * @note IDはnetwork、UI、logへ渡さず、呼出し中のlocal matchingだけに使用する
 */
//------------------------------------------------------------------------------
OfficialInfDeviceMatch matchOfficialInfToDevice(
	const OfficialInfPackage &package, const std::span<const std::wstring_view> deviceHardwareIds,
	const std::span<const std::wstring_view> deviceCompatibleIds) noexcept
{
	const auto matchesPackage = [&package]( const std::wstring_view deviceId) {
		// 空のdevice IDをINFとの一致として扱わない
		if( deviceId.empty()) {
			return false ;
		}

		return std::ranges::any_of( package.hardwareIds, [deviceId]( const std::wstring &packageId) {
			return !packageId.empty() && stringsEqual( packageId, deviceId) ;
		}) ;
	} ; // 一つの現在device IDがINFの有限ID群へ完全一致するかを調べる処理

	// Hardware IDはCompatible IDより具体的なため、先に一致を確定する
	if( std::ranges::any_of( deviceHardwareIds, matchesPackage)) {
		return OfficialInfDeviceMatch::HARDWARE_ID ;
	}

	// compatible IDによる一致はHardware ID一致と区別して返す
	if( std::ranges::any_of( deviceCompatibleIds, matchesPackage)) {
		return OfficialInfDeviceMatch::COMPATIBLE_ID ;
	}

	return OfficialInfDeviceMatch::NONE ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 一file名の明示source媒体位置を固定memberへ結合する
 * @param[in] inf 単独INFの同期handle
 * @param[in] workspace 安全相対位置の確認に借用する
 * @param[in] entries 閉じた元member一覧
 * @param[in] parent 元INFのpackage相対親位置
 * @param[in] binaryTarget trueなら既知DIRID表記のbinary名をsource名へ対応させる
 * @param[in,out] reference 元用途と展開値を持ち、位置観測を受け取る
 * @param[in] requiredSubdirectory DIRID13の新照合時だけのSourceDisksFiles subdir期待。媒体pathは含めない
 * @return 観測成功0、不正path・容量・不在以外の読取失敗HRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError locateMaintenanceSource(
	HINF inf, const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view parent, bool binaryTarget, MaintenanceInfFileReference &reference,
	std::optional<std::wstring_view> requiredSubdirectory = std::nullopt)
{
	std::wstring_view name = reference.target ;	// 原値を変更せずsource名だけを借用する
	// DIRIDはpackage sourceとの対応にだけ使い、system payload位置を認証しない
	if( binaryTarget && (name.starts_with( L"%11%\\") || name.starts_with( L"%12%\\") ||
						name.starts_with( L"%13%\\"))) {
		name.remove_prefix( 5U) ;
	}

	// 未展開tokenと未対応binary位置をbasename推測で救済しない
	if( name.empty() || name.find( L'%') != name.npos ||
	   (binaryTarget && name.find_first_of( L"/\\") != name.npos)) {
		reference.location = MaintenanceInfFileLocation::UNSUPPORTED ;
		reference.error	   = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		return 0 ;
	}

	// Source名はfile名だけに限定し、traversalを未対応へ弱めない
	if( name.find_first_of( L"/\\") != name.npos ||
	   workspace.path( joinRelativePath( parent, name)).empty()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const std::wstring fileName( name) ;	// SetupAPIへ渡す終端付き元source名
	UINT			   sourceId{} ;			// SourceDisksNamesと対応する媒体ID
	DWORD			   required{} ;			// 終端込みsource相対directory必要長
	SetLastError( ERROR_SUCCESS) ;
	// source節不在・位置未定義は具体的な用途未対応として残す
	if( SetupGetSourceFileLocationW( inf, nullptr, fileName.c_str(), &sourceId, nullptr, 0U,
								   &required) == FALSE &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		const DWORD error = GetLastError() ;	// 原位置照会の直後の診断
		// 明示source未発見だけはdriver全体の構文不正と区別する
		if( error == ERROR_LINE_NOT_FOUND || error == ERROR_SECTION_NOT_FOUND ||
		   error == ERROR_FILE_NOT_FOUND) {
			reference.location = MaintenanceInfFileLocation::UNSUPPORTED ;
			reference.error	   = nativeErrorFromWin32( error) ;
			return 0 ;
		}

		return nativeErrorFromWin32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error) ;
	}

	// 不正・過長の必要長を切り詰めず、有限bufferだけを確保する
	if( required == 0U || required > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	std::vector<wchar_t> directory( required) ;	// SourceDisksFilesの有限相対位置
	// 二段目のAPI失敗から部分位置を作らない
	if( SetupGetSourceFileLocationW( inf, nullptr, fileName.c_str(), &sourceId, directory.data(),
								   static_cast<DWORD>( directory.size()), nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	DWORD mediaRequired{} ;	// 終端込み媒体path必要長
	// source位置だけで媒体pathを省略しない
	if( SetupGetSourceInfoW( inf, sourceId, SRCINFO_PATH, nullptr, 0U, &mediaRequired) == FALSE &&
	   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		reference.location = MaintenanceInfFileLocation::UNSUPPORTED ;
		reference.error	   = nativeErrorFromWin32( GetLastError()) ;
		return 0 ;
	}

	// 媒体pathの過長・不正必要長を拒否する
	if( mediaRequired == 0U || mediaRequired > MAXIMUM_INF_FIELD_CHARACTERS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	std::vector<wchar_t> media( mediaRequired) ;	// SourceDisksNamesの有限媒体位置
	// 媒体読取失敗後にroot directoryを補完しない
	if( SetupGetSourceInfoW( inf, sourceId, SRCINFO_PATH, media.data(),
						   static_cast<DWORD>( media.size()), nullptr) == FALSE) {
		return nativeErrorFromWin32( GetLastError()) ;
	}

	reference.relativePath = joinRelativePath( parent, stripReferenceCurrentDirectory( media.data())) ;
	reference.relativePath =
		joinRelativePath( reference.relativePath, stripReferenceCurrentDirectory( directory.data())) ;
	reference.relativePath = joinRelativePath( reference.relativePath, fileName) ;
	// 逸脱した媒体位置は空位置へ変換せず全体を拒否する
	if( workspace.path( reference.relativePath).empty()) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	// DIRID13のsource subdirだけを照合し、SourceDisksNamesの媒体pathを混ぜない
	if( requiredSubdirectory.has_value() && !stringsEqual( directory.data(), *requiredSubdirectory)) {
		reference.relativePath.clear() ;
		reference.location = MaintenanceInfFileLocation::UNSUPPORTED ;
		reference.error	   = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
		return 0 ;
	}

	const auto count = std::ranges::count_if( entries, [&reference]( const auto &entry) {
		return stringsEqual( entry.relativePath, reference.relativePath) ;
	}) ; // 同位置の衝突も先頭候補へ絞らない
	// 重複memberは閉じた位置根拠として扱わない
	if( count > 1) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	reference.location =
		count == 1 ? MaintenanceInfFileLocation::LOCATED : MaintenanceInfFileLocation::MISSING ;
	reference.error = count == 1 ? 0 : nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 到達named list固有の明示導入先を同INFの有限metadataから一度だけ観測する
 * @param[in] inf 同期借用する単独HINF。Appendとdirectory再割当てを行わない
 * @param[in] workspace 相対subdirの安全境界だけへ借用する
 * @param[in] copies 既存queueの同じ読取済み行。最大4,096項目
 * @param[in,out] budget Version・source・全seedと共同消費する予算
 * @param[in,out] inventory metadataの節・行もclosure累積計測へ含める
 * @param[out] directories named固有の元宣言と展開結果。defaultを根拠にしない
 * @param[in,out] byteProof 非nullなら同HINF・同rowの全field証明へ元取得値を結ぶ。通常読取はnull
 * @return 観測成功0、不正数値・path・読取・容量失敗は元HRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readMaintenanceDestinationDirectories(
	HINF inf, const OfficialDownloadWorkspace &workspace,
	std::span<const MaintenanceCopyDestination> copies, MaintenanceStructureBudget &budget,
	OfficialInfInstallInventory					 &inventory,
	std::vector<MaintenanceDestinationDirectory> &directories,
	MaintenanceInfByteProof						 *byteProof = nullptr)
{
	// 不要なmetadata走査と、queueが既に読んだ節の再走査を追加しない
	if( copies.empty() || std::ranges::any_of( inventory.visitedSections, []( const auto &section) {
		   return stringsEqual( section, L"DestinationDirs") ;
	   })) {
		return 0 ;
	}

	const std::wstring section = L"DestinationDirs" ;						// 単独INFの明示metadata名
	LONG			   count{} ;											// 明示空と不存在を別に保持する行数
	NativeError		   error = maintenanceLineCount( inf, section, count) ;	// 元読取診断
	// API失敗をdefaultや空の成功へ変換しない
	if( error != 0) {
		return error ;
	}

	// 不在の明示導入先からWindows-directoryを推測しない
	if( count < 0) {
		return 0 ;
	}

	// metadataも同じ節・全行予算へ含め、各listで上限をresetしない
	if( ++budget.sections > MAXIMUM_INSTALL_INVENTORY_SECTIONS ||
	   static_cast<std::size_t>( count) > MAXIMUM_INSTALL_INVENTORY_LINES - budget.lines) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	inventory.visitedSections.push_back( section) ;
	// 確定した全metadata行を一度ずつ読み、現在到達listと同じkeyだけを保持する
	for( LONG row = 0L; row < count; ++row) {
		INFCONTEXT line{} ;	// 単独INFの元indexに結ぶ借用context
		error = maintenanceLineAt( inf, section, row, line) ;
		// 途中失敗を正常な節終端へ変換しない
		if( error != 0) {
			return error ;
		}

		++budget.lines ;
		++inventory.scannedLines ;
		const DWORD fields = SetupGetFieldCount( &line) ;	// key以外の元field数
		// 未到達keyの行も共同field上限を迂回させない
		if( fields > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::wstring		 key ;	// defaultとnamed固有keyを混同しない元値
		const auto			 rawRow = byteProof == nullptr
										  ? NO_MAINTENANCE_RAW_ROW
										  : byteProof->row( section, row, count, fields) ;	// 同元metadata行
		MaintenanceFieldRead keyRead{} ;													// 元keyの同じ二API結果
		error = readMaintenanceField(
			line, 0U, key, byteProof != nullptr && byteProof->active() ? &keyRead : nullptr) ;
		// 読取不能keyを未知の正常行として捨てない
		if( error != 0) {
			return error ;
		}

		// 元keyを再readせずにraw全値へ結ぶ
		if( byteProof != nullptr) {
			byteProof->field( rawRow, 0U, key, keyRead) ;
		}

		// default・未知key・未到達listは展開済み位置の成功根拠にしない
		if( stringsEqual( key, L"DefaultDestDir") ||
		   !std::ranges::any_of(
			   copies, [&key]( const auto &copy) { return stringsEqual( copy.section, key) ; })) {
			continue ;
		}

		// 保持量を同じ一INFの最大項目数へ制限する
		if( directories.size() >= MAXIMUM_INSTALL_INVENTORY_ITEMS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		MaintenanceDestinationDirectory directory ;	// 全展開成功まで私有の部分観測
		directory.section = std::move( key) ;
		directory.rawRow  = rawRow ;
		// DIRID欠落は合法な未知値と区別し、不正な元行を拒否する
		if( fields == 0U) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		std::wstring		 dirid ;		// Windowsが返した全数値field
		MaintenanceFieldRead diridRead{} ;	// 元DIRIDの全取得
		error = readMaintenanceField(
			line, 1U, dirid, byteProof != nullptr && byteProof->active() ? &diridRead : nullptr) ;
		// 必要長超過と読取失敗を部分数値へ補完しない
		if( error != 0) {
			return error ;
		}

		// 元数値の全field比較を意味の数値解釈と分ける
		if( byteProof != nullptr) {
			byteProof->field( rawRow, 1U, dirid, diridRead) ;
		}

		MaintenanceInfStructureReason reason{} ;										// 同じ厳密数値readerの失敗分類
		const auto finding = parseMaintenanceFlags( dirid, directory.dirid, reason) ;	// 全数値解析
		// 具体的な数値不正・overflowは位置未知へ弱めない
		if( finding.state == MaintenanceInspectionState::FAILED) {
			return finding.error ;
		}

		// 明示subdirは媒体位置と分け、元fieldの全必要長を検査する
		if( fields >= 2U) {
			MaintenanceFieldRead subdirectoryRead{} ;	// 元subdirの同query／read
			error = readMaintenanceField(
				line, 2U, directory.subdirectory,
				byteProof != nullptr && byteProof->active() ? &subdirectoryRead : nullptr) ;
			// 読取不能値を空directoryへ補完しない
			if( error != 0) {
				return error ;
			}

			// 元取得値の全長・全code unitを同byteへ比較する
			if( byteProof != nullptr) {
				byteProof->field( rawRow, 2U, directory.subdirectory, subdirectoryRead) ;
			}

			// token残留は位置未対応として保持し、不正pathと混同しない
			if( directory.subdirectory.find( L'%') == std::wstring::npos &&
			   !directory.subdirectory.empty() && workspace.path( directory.subdirectory).empty()) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}
		}

		// 元coreが未取得のauxだけを同contextで一度補う
		if( byteProof != nullptr && fields >= 3U) {
			byteProof->extra( line, rawRow, 3U, fields) ;
		}

		// 現対応三DIRID・二field以内・安全subdirだけをAPI照会候補にする
		if( finding.state == MaintenanceInspectionState::PASSED && fields <= 2U &&
		   (directory.dirid == 11U || directory.dirid == 12U || directory.dirid == 13U) &&
		   directory.subdirectory.find( L'%') == std::wstring::npos) {
			directory.error = 0 ;
		}

		directories.push_back( std::move( directory)) ;
		// private metadata増加でも元core必要量を優先して予約撤回する
		if( byteProof != nullptr) {
			byteProof->capacity( budget.effects + budget.references + budget.services +
								budget.issues + budget.fileUses + budget.coverageGaps +
								copies.size() + directories.size() +
								inventory.visitedSections.size()) ;
		}
	}

	// 一意なnamed entryごとに二段階APIを一度だけ使い、default fallbackと重複を避ける
	for( auto &directory : directories) {
		// 未対応宣言と同key重複は先頭の展開値を成功根拠にしない
		if( directory.error != 0 ||
		   std::ranges::count_if( directories, [&directory]( const auto &candidate) {
			   return stringsEqual( candidate.section, directory.section) ;
		   }) != 1) {
			continue ;
		}

		DWORD required{} ;	// 終端込みのWindows展開後文字数
		SetLastError( ERROR_SUCCESS) ;
		// 明示named keyで照会し、APIが解決できない位置は元診断を保持する
		if( SetupGetTargetPathW( inf, nullptr, directory.section.c_str(), nullptr, 0U, &required) ==
			   FALSE &&
		   GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			const DWORD native = GetLastError() ;	// 直後の原API診断
			directory.error =
				nativeErrorFromWin32( native == ERROR_SUCCESS ? ERROR_INVALID_DATA : native) ;
			continue ;
		}

		// 一回の必要長も共同readerと同じ4,096文字へ拘束し、切捨てない
		if( required == 0U || required > MAXIMUM_INF_FIELD_CHARACTERS) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::vector<wchar_t> path( required) ;	// 呼出し中だけの有限終端付きbuffer
		DWORD				 readRequired{} ;	// 同じ二段target取得の必要長をprivateだけへ捕捉する
		SetLastError( ERROR_SUCCESS) ;
		// 二段目の失敗後に部分pathをdirectoryへ保存しない
		if( SetupGetTargetPathW( inf, nullptr, directory.section.c_str(), path.data(),
							   static_cast<DWORD>( path.size()),
							   byteProof != nullptr && byteProof->active() ? &readRequired
																		   : nullptr) == FALSE) {
			const DWORD native = GetLastError() ;	// buffer取得の原診断
			directory.error =
				nativeErrorFromWin32( native == ERROR_SUCCESS ? ERROR_INVALID_DATA : native) ;
			continue ;
		}

		directory.expandedDirectory = path.data() ;
		directory.targetComplete	= byteProof != nullptr && byteProof->active() &&
								   std::ranges::find( path, L'\0') != path.end() &&
								   readRequired == required &&
								   directory.expandedDirectory.size() + 1U == required ;
		// 空のAPI出力をraw DIRID対応の展開成功へ昇格しない
		if( directory.expandedDirectory.empty()) {
			directory.error = nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 構築完了したnamed行とdirectoryを一度だけ結び、反復検索とpath再生成を除く
 * @param[in] workspace destination leafの安全性だけへ同期借用する
 * @param[in] copies 最大4,096行の構築済みvectorを借用する。使用中の再確保・変更は禁止する
 * @param[in] directories 同INFの構築済みmetadata。cache使用中に変更しない
 * @param[out] bindings 同scope内だけで有効な非所有pointerと元状態・全targetを最大4,096件保持する
 * @return 構築成功0、不正destination・保持量／target長超過は元HRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError bindMaintenanceCopyDestinations(
	const OfficialDownloadWorkspace &workspace, std::span<const MaintenanceCopyDestination> copies,
	std::span<const MaintenanceDestinationDirectory> directories,
	std::vector<MaintenanceCopyBinding>				&bindings)
{
	// 私有cacheも元readerと同じ保持上限へ拘束し、分割・resetをしない
	if( copies.size() > MAXIMUM_INSTALL_INVENTORY_ITEMS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	bindings.reserve( copies.size()) ;
	// 全到達copyを一度ずつ元named entryへ結び、各binaryでdirectoryを再検索しない
	for( const auto &copy : copies) {
		// 現在使用するnamed destinationは安全leafだけに制限する
		if( copy.destination.find_first_of( L"/\\") != std::wstring::npos ||
		   workspace.path( copy.destination).empty()) {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		MaintenanceCopyBinding binding ;	// 一致後も元vectorの同期借用だけを保持する
		binding.copy	 = &copy ;
		const auto count = std::ranges::count_if( directories, [&copy]( const auto &directory) {
			return stringsEqual( directory.section, copy.section) ;
		}) ; // 同keyの全候補数。重複を先頭へ絞らない
		// 固有entry不在と重複も原copyに結ぶ元状態として保持する
		if( count != 1) {
			binding.error = nativeErrorFromWin32( count > 1 ? ERROR_DUP_NAME : ERROR_NOT_SUPPORTED) ;
		} else {
			const auto directory = std::ranges::find_if( directories, [&copy]( const auto &item) {
				return stringsEqual( item.section, copy.section) ;
			}) ; // 一意と確認済みの元metadata
			binding.directory	 = &*directory ;
			binding.error		 = directory->error ;
			// 未展開destination tokenを既知leafへ補完しない
			if( copy.destination.find( L'%') != std::wstring::npos && binding.error == 0) {
				binding.error = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			// 全targetを一度だけ作り、元fieldと同じ必要長上限を維持する
			if( binding.error == 0) {
				binding.fullTarget =
					joinRelativePath( directory->expandedDirectory, copy.destination) ;
				binding.rawTarget = L"%" + std::to_wstring( directory->dirid) + L"%\\" +
									joinRelativePath( directory->subdirectory, copy.destination) ;
				// 終端込み4,096文字を超える合成pathも切り詰めない
				if( binding.fullTarget.size() >= MAXIMUM_INF_FIELD_CHARACTERS ||
				   binding.rawTarget.size() >= MAXIMUM_INF_FIELD_CHARACTERS) {
					return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
				}
			}
		}

		bindings.push_back( std::move( binding)) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同HINFの成功した到達named13相対全targetとの一致だけを判定する
 * @param[in] target 元binaryの展開後全値。先頭dotを取り除かず同期借用する
 * @param[in] binding 構築完了した元copyと明示directoryのcache。使用中に変更しない
 * @return 明示13・非空dot-relative出力・全値一致ならtrue。それ以外はfalse
 * @note 一宣言の対応だけを示し、候補一意性・元source・実Storeの充足は判定しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesMaintenanceRelative13Target(
	std::wstring_view target, const MaintenanceCopyBinding &binding) noexcept
{
	return target.starts_with( L".\\") && binding.error == 0 && binding.directory != nullptr &&
		   binding.directory->dirid == 13U &&
		   (binding.directory->expandedDirectory == L"." ||
			binding.directory->expandedDirectory.starts_with( L".\\")) &&
		   stringsEqual( target, binding.fullTarget) ;
}

//------------------------------------------------------------------------------
/**
 * @brief binaryの展開済み導入先を到達named copyの明示sourceだけへ限定対応させる
 * @param[in] inf 同じ一INFの同期handle
 * @param[in] workspace 元sourceの安全相対位置にだけ借用する
 * @param[in] entries 閉じた元member集合。system targetを探索しない
 * @param[in] parent 元INFのpackage相対親位置
 * @param[in] bindings 構築完了した元vectorを同期借用する全到達named行のcache
 * @param[in] sourceObservations 元readerが既に読んだsource用途を含む観測。呼出し中のappendは禁止する
 * @param[in,out] reference 元binary用途を維持し、位置と元診断だけを更新する
 * @return 観測成功0、不正path・source読取・容量等の全体拒否HRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError locateMaintenanceBinarySource(
	HINF inf, const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	std::wstring_view parent, std::span<const MaintenanceCopyBinding> bindings,
	std::span<const MaintenanceInfFileReference> sourceObservations,
	MaintenanceInfFileReference					&reference)
{
	std::wstring_view legacyName = reference.target ;	// 旧同名source対応の借用だけ
	// 旧raw三prefixの同名leaf対応を新しいabsolute fallbackと混同しない
	if( legacyName.starts_with( L"%11%\\") || legacyName.starts_with( L"%12%\\") ||
	   legacyName.starts_with( L"%13%\\")) {
		legacyName.remove_prefix( 5U) ;
	}

	// 旧裸leafだけは元媒体と固定memberの既存境界をそのまま使う
	if( legacyName.find_first_of( L"/\\") == legacyName.npos) {
		return locateMaintenanceSource( inf, workspace, entries, parent, true, reference) ;
	}

	std::wstring_view target = reference.target ;	// 正規化せず全値を借用する
	const bool		  drivePath =
		target.size() >= 3U &&
		((target[0] >= L'A' && target[0] <= L'Z') || (target[0] >= L'a' && target[0] <= L'z')) &&
		// 現APIで扱うdrive形式だけ
		target[1] == L':' && target[2] == L'\\' ;
	const auto relative13Matches =
		!drivePath && target.starts_with( L".\\")
			? std::ranges::count_if( bindings,
									[target]( const auto &binding) {
										return matchesMaintenanceRelative13Target( target, binding) ;
									})
			: 0 ;	// 先頭dotの除外と候補選択で同じ全値条件を使い、位置成功は後段へ分ける
	std::wstring_view components =
		drivePath
			? target.substr( 3U)
			: (relative13Matches != 0 ? target.substr( 2U) : target) ;	// 元の残り全要素を検査する
	std::size_t beginning{} ;											// 各原path要素の開始位置
	// 元全pathのdot移動を一度だけ検査し、正規化で未知位置を救済しない
	while( beginning < components.size()) {
		const auto separator = components.find_first_of( L"/\\", beginning) ;	// 元区切り
		const auto ending =
			// 要素終端
			separator == components.npos ? components.size() : separator ;
		const auto component = components.substr( beginning, ending - beginning) ;	// 原要素
		// traversalを単なる未対応binary位置へ弱めない
		if( component == L"." || component == L"..") {
			return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		beginning = ending + 1U ;
	}

	// UNC／device pathは照合対象外。drive以外のcolonとADSだけは不正として拒否する
	if( !target.starts_with( L"\\\\") && components.find( L':') != components.npos) {
		return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
	}

	const auto separator = target.find_last_of( L"/\\") ;			// 保留候補のleafだけを借用する位置
	const auto leaf		 = target.substr( separator + 1U) ;			// leaf一致だけで成功は作らない
	const MaintenanceCopyDestination	  *selected{} ;				// 全候補一意確認後だけ使用する非所有pointer
	const MaintenanceDestinationDirectory *selectedDirectory{} ;	// 同scopeの元named entry
	std::size_t							   matches{} ;				// 全pathが一致した全候補数
	NativeError uncertain{} ;										// 同leafで位置根拠を確定できない候補の元診断
	bool		selectedRelative13{} ;								// 新相対対応だけに元source行の一意性を追加する
	// 到達named copyだけを全件比較し、未到達listや任意absoluteのbasenameへfallbackしない
	for( const auto &binding : bindings) {
		const auto &copy = *binding.copy ;	// 構築完了した元行の同scope借用
		// 固有entry不在・重複・未対応の同leaf候補を一意成功から消さない
		if( binding.error != 0) {
			// 未確定同leafの候補を消して一意成功を作らない
			if( stringsEqual( copy.destination, leaf)) {
				uncertain = binding.error ;
			}

			continue ;
		}

		// 全値一致だけで候補を数え、Windows-prefixやbasenameでは受理しない
		if( (drivePath && stringsEqual( target, binding.fullTarget)) ||
		   stringsEqual( target, binding.rawTarget) ||
		   matchesMaintenanceRelative13Target( target, binding)) {
			++matches ;
			selected		   = &copy ;
			selectedDirectory  = binding.directory ;
			selectedRelative13 = matchesMaintenanceRelative13Target( target, binding) ;
		}
	}

	reference.location = MaintenanceInfFileLocation::UNSUPPORTED ;
	reference.error	   = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
	// 未確定候補と全pathの曖昧を元診断付きで残す
	if( matches != 1U || uncertain != 0) {
		reference.error = matches > 1U || relative13Matches > 1
							  ? nativeErrorFromWin32( ERROR_DUP_NAME)
							  : (uncertain != 0 ? uncertain : reference.error) ;
		return 0 ;
	}

	// DIRID13はrenameを新対応へ入れず、実Driver Storeの充足も保証しない
	if( selectedDirectory->dirid == 13U && !stringsEqual( selected->destination, selected->source)) {
		return 0 ;
	}

	// 新相対13は既に有限読取したsource一行だけへ結び、SetupAPIの先頭選択で重複を消さない
	if( selectedRelative13) {
		const MaintenanceInfFileReference *observedSource{} ;	// 同期借用中だけ有効な元source観測
		std::size_t sourceMatches{} ;							// 同名の全元source行数。使用先用途を数えない
		// 元source宣言だけを全件確認し、一照会の間は借用元へappendしない
		for( const auto &observation : sourceObservations) {
			// 用途名とsource全名が一致する元観測だけを候補へ残す
			if( stringsEqual( observation.directive, L"SourceDisksFiles") &&
			   stringsEqual( observation.target, selected->source)) {
				++sourceMatches ;
				observedSource = &observation ;
			}
		}

		// 未観測fallbackと同名複数行を推測補完せず、元不足または重複診断を残す
		if( sourceMatches != 1U) {
			reference.error =
				nativeErrorFromWin32( sourceMatches > 1U ? ERROR_DUP_NAME : ERROR_NOT_SUPPORTED) ;
			return 0 ;
		}

		// 元source APIの未対応・MISSINGを今回のtarget一致で成功へ取り消さない
		if( observedSource->location != MaintenanceInfFileLocation::LOCATED) {
			reference.relativePath = observedSource->relativePath ;
			reference.location	   = observedSource->location ;
			reference.error		   = observedSource->error ;
			return 0 ;
		}
	}

	MaintenanceInfFileReference source = reference ;	// binary原値を保持するための一時source照会
	source.target					   = selected->source ;
	const auto requiredSubdirectory =
		selectedDirectory->dirid == 13U
			? std::optional<std::wstring_view>{selectedDirectory->subdirectory}
			: std::nullopt ;	// SourceDisksFiles subdirだけの追加条件
	const NativeError error =
		locateMaintenanceSource( inf, workspace, entries, parent, false, source,
								requiredSubdirectory) ;	// 元媒体と固定member
	// sourceの不正・容量・重大な読取失敗は位置未知へ弱めない
	if( error != 0) {
		return error ;
	}

	reference.relativePath = std::move( source.relativePath) ;
	reference.location	   = source.location ;
	reference.error		   = source.error ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全元値とnamed13／成功済み元sourceだけから位置stageの一意source indexを返す
 * @param[in,out] proof 同HINF・同元byteの私有証明。allocation失敗では撤回する
 * @param[in] rawRow 元dataまたは制御行index
 * @param[in] field 元全target field番号
 * @param[in] target coreが一度だけ読んだAPI全値
 * @param[in] bindings 同じqueueの到達named copyと元metadata
 * @param[in] sources 既に観測済みの元source用途。再API取得しない
 * @return 全値・一意source成立時の元観測index。未知では未結合値
 * @note prefix／basename／dot除去を成功根拠にせず、同leafの不確定候補を保持する
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::size_t locateMaintenanceCompleteValueSource(
	MaintenanceInfByteProof &proof, std::size_t rawRow, std::size_t field, std::wstring_view target,
	std::span<const MaintenanceCopyBinding>		 bindings,
	std::span<const MaintenanceInfFileReference> sources)
{
	// 未読fieldの行をcaller成功で補完しない
	if( !proof.verified( rawRow)) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	std::wstring expanded ;	// 原全targetだけの短命な独立一段展開
	// 私有展開失敗は元Uを保持する
	if( !proof.value( rawRow, field, expanded)) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	const auto separator = target.find_last_of( L"/\\") ;	// 未確定同leafの診断にだけ使用する
	const auto leaf =
		// 成功比較には使わない
		target.substr( separator == target.npos ? 0U : separator + 1U) ;
	const MaintenanceCopyBinding *selected{} ;	// 全候補の一意確認後だけ借用する
	std::size_t					  matches{} ;	// 原data全値に一致した全binding数
	bool						  uncertain{} ;	// 同leafの不確定候補を成功集合から捨てない
	// 全到達named行の元全targetだけを比較し、任意directoryへ探索しない
	for( const auto &binding : bindings) {
		const auto &copy	  = *binding.copy ;		// 同queueで取得済みの元copy
		const auto *directory = binding.directory ;	// 一意named metadataのみ
		// 元copy／全metadata不足、空subdir、renameを私有成功へ救済しない
		if( binding.error != 0 || directory == nullptr || directory->dirid != 13U ||
		   directory->subdirectory.empty() || !directory->targetComplete ||
		   !proof.verified( copy.rawRow) || !proof.verified( directory->rawRow) ||
		   proof.get( copy.rawRow).key.size != 0U || copy.destination != copy.source) {
			uncertain = uncertain || stringsEqual( copy.destination, leaf) ;
			continue ;
		}

		// 原data全体と同named raw／full target、API全値を完全一致させる
		if( (expanded == binding.rawTarget || expanded == binding.fullTarget) &&
		   (target == binding.rawTarget || target == binding.fullTarget)) {
			++matches ;
			selected = &binding ;
		}
	}

	// 部分一致・同leafの不確定候補や全target重複を一意成功へ絞らない
	if( matches != 1U || uncertain || selected == nullptr) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	std::size_t sourceFile = NO_MAINTENANCE_RAW_ROW ;	// 再読取しない元source用途index
	std::size_t sourceMatches{} ;						// 選択x64 source全行の同名数
	// 元metadata用途だけを数え、copy用途とdedup集合をsource一意性へ転用しない
	for( std::size_t index = 0U; index < sources.size(); ++index) {
		const auto &source = sources[index] ;	// 同期借用する元位置観測
		// 全source名が一致する全行を残す
		if( stringsEqual( source.directive, L"SourceDisksFiles") &&
		   stringsEqual( source.target, selected->copy->source)) {
			++sourceMatches ;
			sourceFile = index ;
		}
	}

	// missing／duplicate／未観測sourceは元Uを保持する
	if( sourceMatches != 1U || sourceFile >= sources.size() ||
	   sources[sourceFile].location != MaintenanceInfFileLocation::LOCATED ||
	   sources[sourceFile].error != 0) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	const auto source = std::ranges::find_if( proof.sourceRows, [sourceFile]( const auto &row) {
		return row.second == sourceFile ;
	}) ; // 同原source API観測の私有rowだけへ結ぶ
	// 元sourceのkeyと厳密全aux fieldが揃っていることを要求する
	if( source == proof.sourceRows.end() || !proof.verified( source->first) ||
	   proof.get( source->first).fields < 2U) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	const std::size_t sourceRow = source->first ;	// allocation後のvector借用を残さないindex
	std::wstring	  subdirectory ;				// 同rowの原source subdir全値
	// 元SourceDisksFilesとDestinationDirsの非空subdir全値を完全一致させる
	if( !proof.value( sourceRow, 2U, subdirectory) ||
	   subdirectory != selected->directory->subdirectory) {
		return NO_MAINTENANCE_RAW_ROW ;
	}

	return sourceFile ;
}

//------------------------------------------------------------------------------
/**
 * @brief 有限保持量を確認して原用途と位置を棚卸しへ加える
 * @param[in,out] references 同じ一INFの累積観測
 * @param[in] file 全観測値を所有する一file用途
 * @return 追加成功0、保持量超過のHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError appendMaintenanceFile( MaintenanceInfReferences   &references,
												MaintenanceInfFileReference file)
{
	// 不足行も分母に残し、過大な用途集合を切り捨てない
	if( references.files.size() >= MAXIMUM_INSTALL_INVENTORY_ITEMS) {
		return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
	}

	// 位置未確定と欠落は全参照coverageの完了へ昇格させない
	if( file.location != MaintenanceInfFileLocation::LOCATED) {
		references.referenceCoverage = MaintenanceInfReferenceCoverage::INCOMPLETE ;
	}

	// root／CAT以外の実在sourceだけを有限な署名member候補へ加える
	if( file.location == MaintenanceInfFileLocation::LOCATED &&
	   !stringsEqual( file.relativePath, references.infRelativePath) &&
	   !stringsEqual( file.relativePath, references.catalogRelativePath)) {
		static_cast<void>( appendUnique( references.sourceFiles, std::wstring( file.relativePath))) ;
	}

	references.files.push_back( std::move( file)) ;
	return 0 ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 一INFの明示seedからlocal file用途と同節依存を同期・有限に棚卸しする
 * @param[in] workspace 呼出し全期間固定される保護所有領域
 * @param[in] entries 閉じたarchive member一覧。未抽出memberも位置照合に使う
 * @param[in] infRelativePath 読取前後に元byteへ一致させる最大4 MiBのINF
 * @param[in] seeds 原明示節群。0～1,024。suffix補完と別節Include借用をしない
 * @param[in] policy 既存の内容参照数と非圧縮EXE限定条件。導入policyへ転用しない
 * @param[out] references 全体成功時の位置観測。全体読取・path・容量失敗では空
 * @return 観測成功0、重大な読取・入力・容量・元byte差のHRESULT
 * @pre 入力と出力はaliasしない。workerから同期呼出しし、同時にworkspaceを変更しない
 * @note 一INF4 MiB、1,024節／4,096行・参照／64 field。依存先の解決と署名は別検査。展開済みbinaryは到達named list固有DestinationDirsと
 *       明示sourceへ限定照合する。親default文脈のない直接copy／defaultは位置未対応のまま保持する。DIRID13は同名とSourceDisksFiles／
 *       DestinationDirs subdir一致を追加要求する。同HINFの成功したdot-relative named13全targetは全候補・元source行の一意性も要求する
 *       LOCATEDとcoverageは固定package内の元source位置だけで、実byte／CATは後段で検証する。実Driver Store導入先の充足・端末適合・rank／grantと導入
 *       許可は未確認のまま分離する
 * @see docs/adr/0313-maintenance-expanded-service-binary-source-binding.md
 * @see docs/adr/0314-maintenance-unstaged-dirid13-source-content-separation.md
 */
//------------------------------------------------------------------------------
NativeError inspectMaintenanceInfReferences( const OfficialDownloadWorkspace	  &workspace,
											std::span<const OfficialZipEntry>  entries,
											std::wstring_view				   infRelativePath,
											std::span<const std::wstring>	   seeds,
											const OfficialInfInspectionPolicy &policy,
											MaintenanceInfReferences		  &references)
{
	references = {} ;
	try {
		const std::wstring path = workspace.path( infRelativePath) ;	// 保護領域の単独元位置
		const auto entry = std::ranges::find_if( entries, [infRelativePath]( const auto &item) {
			return stringsEqual( item.relativePath, infRelativePath) ;
		}) ; // 閉じた元memberだけの同期借用
		// 未固定・過大・重複入力と不正seedから参照集合を作らない
		if( path.empty() || entries.empty() || entries.size() > 32'768U || entry == entries.end() ||
		   lowerExtension( infRelativePath) != L".inf" || entry->uncompressedSize == 0U ||
		   entry->uncompressedSize > 4U * 1024U * 1024U || seeds.size() > 1024U ||
		   policy.maximumSourceFiles == 0U || policy.maximumSourceFiles > 8192U ||
		   std::ranges::count_if( entries, [infRelativePath]( const auto &item) {
			   return stringsEqual( item.relativePath, infRelativePath) ;
		   }) != 1) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		MaintenanceInfByteProof byteProof ;	// HINFより前に構築し、HINF先closeを保持する
		NativeError				error =
			// 元fileの一回のbyte snapshot
			byteProof.open( workspace, path, infRelativePath, *entry) ;
		// snapshotの実size／hash不一致は既存全体拒否へ結ぶ
		if( error != 0) {
			return error ;
		}

		error = verifyOfficialFileMetadata( path,
										   {entry->uncompressedSize, entry->sha256}) ;	// 元byte照合
		// 改変を部分参照の成功へ変換しない
		if( error != 0) {
			return error ;
		}

		MaintenanceInfReferences observed ;	// 全体再確認後だけ公開するworker内所有物
		observed.infRelativePath   = infRelativePath ;
		observed.referenceCoverage = MaintenanceInfReferenceCoverage::COMPLETE ;
		error					   = computeFileSha256( path, observed.infSha256) ;
		// 原hashを取得できない入力を解析しない
		if( error != 0) {
			return error ;
		}

		error = byteProof.matchHash( observed.infSha256) ;
		// 同一snapshotと通常hashの不一致から部分結果を公開しない
		if( error != 0) {
			return error ;
		}

		const UniqueInf inf( SetupOpenInfFileW( path.c_str(), nullptr,
											  INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE,
											  nullptr)) ;	// scopeが単独所有しAppendしない
		// 構文読取不能を空参照へ変換しない
		if( inf.get() == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		const auto	 separator = infRelativePath.find_last_of( L'\\') ;	// 安全な元親位置
		const auto	 parent	   = separator == infRelativePath.npos
									 ? std::wstring_view{}
									 : infRelativePath.substr( 0U, separator) ;	// 呼出し中だけの借用
		std::wstring catalog ;													// 現x64用CATの明示file名
		error = readCatalogFile( inf.get(), catalog) ;
		// 依存資料のCAT未宣言を構文不正へ潰さず、その他の読取失敗は保持する
		if( error != 0 && error != nativeErrorFromWin32( ERROR_LINE_NOT_FOUND) &&
		   error != nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND)) {
			return error ;
		}

		observed.catalogRelativePath =
			catalog.empty() ? std::wstring{} : joinRelativePath( parent, catalog) ;
		const auto cat = std::ranges::find_if( entries, [&observed]( const auto &item) {
			return stringsEqual( item.relativePath, observed.catalogRelativePath) ;
		}) ; // 元CAT位置と有限sizeの確認
		// 明示CATの不正位置と同位置衝突を未確認へ弱めない
		if( !catalog.empty() && (workspace.path( observed.catalogRelativePath).empty() ||
								std::ranges::count_if( entries, [&observed]( const auto &item) {
									return stringsEqual( item.relativePath,
														observed.catalogRelativePath) ;
								}) > 1)) {
			return static_cast<NativeError>( E_INVALIDARG) ;
		}

		// 実在CATの一file上限を後段抽出前に維持する
		if( cat != entries.end() &&
		   (cat->uncompressedSize == 0U || cat->uncompressedSize > 32U * 1024U * 1024U)) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		observed.files.push_back( {L"Version", L"INF", std::wstring( infRelativePath),
								  std::wstring( infRelativePath),
								  MaintenanceInfFileLocation::LOCATED, 0}) ;
		error = appendMaintenanceFile(
			observed,
			{L"Version", L"CatalogFile", catalog, observed.catalogRelativePath,
			 catalog.empty() ? MaintenanceInfFileLocation::UNSUPPORTED
							 : (cat == entries.end() ? MaintenanceInfFileLocation::MISSING
													 : MaintenanceInfFileLocation::LOCATED),
			 catalog.empty()
				 ? nativeErrorFromWin32( ERROR_LINE_NOT_FOUND)
				 : (cat == entries.end() ? nativeErrorFromWin32( ERROR_FILE_NOT_FOUND) : 0)}) ;
		// CAT不足も有限保持量へ含め、空閉包を合格にしない
		if( error != 0) {
			return error ;
		}

		MaintenanceStructureBudget budget ;			// Version・source・全seedの共通予算
		LONG					   versionCount{} ;	// Versionの確定行数
		error = maintenanceLineCount( inf.get(), L"Version", versionCount) ;
		// 必須Versionの不在と読取失敗を部分成功にしない
		if( error != 0 || versionCount <= 0 || versionCount > 4096L) {
			return error != 0 ? error : nativeErrorFromWin32( ERROR_INVALID_DATA) ;
		}

		// Queue外のLayoutFileも同じ有限行予算で観測する
		for( LONG row = 0L; row < versionCount; ++row) {
			INFCONTEXT line{} ;	// Versionの原行
			error = maintenanceLineAt( inf.get(), L"Version", row, line) ;
			// 途中失敗と過多fieldを正常終端へ変換しない
			if( error != 0 || SetupGetFieldCount( &line) > 64U) {
				return error != 0 ? error : nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			++budget.lines ;
			std::wstring key ;	// Versionの原directive
			error = readMaintenanceField( line, 0U, key) ;
			// 読取不能keyを無関係行として飛ばさない
			if( error != 0) {
				return error ;
			}

			// LayoutFileの全原参照を未解決の用途として保持する
			if( stringsEqual( key, L"LayoutFile")) {
				const DWORD fields = SetupGetFieldCount( &line) ;	// 原参照数
				// 明示空も無参照へ変換せず一観測として残す
				for( DWORD field = 1U; field <= (std::max)( fields, DWORD{1U}); ++field) {
					std::wstring target ;	// 原LayoutFile値
					error = fields == 0U ? 0 : readMaintenanceField( line, field, target) ;
					// 読取不能の参照を空用途へ変換しない
					if( error != 0) {
						return error ;
					}

					error = appendMaintenanceFile( observed,
												  {L"Version",
												   key,
												   std::move( target),
												   {},
												   MaintenanceInfFileLocation::UNSUPPORTED,
												   nativeErrorFromWin32( ERROR_NOT_SUPPORTED)}) ;
					// 多値参照も保持上限を回避させない
					if( error != 0) {
						return error ;
					}
				}
			}
		}

		std::wstring sourceSection = L"SourceDisksFiles.amd64" ;	// x64を先に照会する
		LONG		 sourceCount{} ;								// 不在と明示空を区別する
		error = maintenanceLineCount( inf.get(), sourceSection, sourceCount) ;
		// API失敗をsource不在にしない
		if( error != 0) {
			return error ;
		}

		// x64節不在の場合だけ共通節を照会する
		if( sourceCount < 0) {
			sourceSection = L"SourceDisksFiles" ;
			error		  = maintenanceLineCount( inf.get(), sourceSection, sourceCount) ;
			// 共通節の読取失敗を不在へ弱めない
			if( error != 0) {
				return error ;
			}
		}

		observed.sourceSectionPresent = sourceCount >= 0 ;
		// source全行と到達節の共同予算を加算前に確認する
		if( sourceCount > 0 && static_cast<std::size_t>( sourceCount) > 4096U - budget.lines) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 通常source宣言を全部残し、使用先だけで元source集合を縮小しない
		for( LONG row = 0L; row < sourceCount; ++row) {
			INFCONTEXT line{} ;	// Sourceの原行
			error = maintenanceLineAt( inf.get(), sourceSection, row, line) ;
			// 確定行数の途中の失敗を空集合へ変換しない
			if( error != 0) {
				return error ;
			}

			++budget.lines ;
			MaintenanceInfFileReference file{sourceSection, L"SourceDisksFiles"} ;	// 元用途
			// source行の余剰fieldも有限上限を迂回させない
			const DWORD fields = SetupGetFieldCount( &line) ;	// 元sourceの厳密全field数
			// 元field数の上限をprivate追加fieldとは独立に維持する
			if( fields > MAXIMUM_INSTALL_INVENTORY_FIELDS) {
				return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
			}

			byteProof.capacity( observed.files.size() + budget.fileUses + budget.references) ;
			const auto			 rawRow = byteProof.row( sourceSection, row, sourceCount,
														fields) ;	// 元x64優先選択と同ordinal
			MaintenanceFieldRead keyRead{} ;						// 元source keyだけの既存取得
			error = readMaintenanceField( line, 0U, file.target,
										 byteProof.active() ? &keyRead : nullptr) ;
			// 元keyの成功結果だけをextra観測より前に捕捉する
			if( error == 0) {
				byteProof.field( rawRow, 0U, file.target, keyRead) ;
			}

			// file名取得に成功した場合だけ安全なsource位置を照会する
			if( error == 0) {
				error = locateMaintenanceSource( inf.get(), workspace, entries, parent, false, file) ;
			}

			// 不正媒体位置と重大な読取失敗をsourceなしへ変換しない
			if( error != 0) {
				return error ;
			}

			// 元位置照会が成功してから未取得auxだけを同contextで一度補う
			byteProof.extra( line, rawRow, 1U, fields) ;
			byteProof.source( rawRow, observed.files.size()) ;

			error = appendMaintenanceFile( observed, std::move( file)) ;
			// 不足行を切り捨てて閉包合格を作らない
			if( error != 0) {
				return error ;
			}

			byteProof.capacity( observed.files.size() + budget.fileUses + budget.references) ;
		}

		std::vector<std::wstring> presentSeeds ;	// 明示名だけの実在seed
		// 不在seedも観測へ残し、実在節だけをlocal queueへ渡す
		for( const auto &seed : seeds) {
			LONG count{} ;	// 原seedの存在と行数
			// path的なseed名を原節として解釈しない
			if( !validInstallInventorySectionName( seed)) {
				return nativeErrorFromWin32( ERROR_INVALID_DATA) ;
			}

			error = maintenanceLineCount( inf.get(), seed, count) ;
			// 不在以外のAPI失敗を欠落へ変換しない
			if( error != 0) {
				return error ;
			}

			// 実在seedだけを一意に加え、独自suffixを使わない
			if( count >= 0) {
				static_cast<void>( appendUnique( presentSeeds, std::wstring( seed))) ;
			} else {
				error = appendMaintenanceFile( observed,
											  {seed,
											   L"SeedSection",
											   seed,
											   {},
											   MaintenanceInfFileLocation::MISSING,
											   nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND)}) ;
				// 不在seedの保持数も有限に制限する
				if( error != 0) {
					return error ;
				}
			}
		}

		MaintenanceInfInstallStructure				install ;			// 明示seedだけの到達local観測
		std::vector<MaintenanceCopyDestination>		copies ;			// 同じ読取済みnamed行の私有sidecar
		std::vector<MaintenanceEventLogMarkerProof> eventLogProofs ;	// このreferenceだけの同行証明
		// Includeのみの資料もsource／CATを観測し、seedを捏造しない
		if( !presentSeeds.empty()) {
			install.inventory.selectedInstallSection = presentSeeds.front() ;
			error = inspectMaintenanceInstallStructure( inf.get(), workspace, entries, parent,
													   budget, install, presentSeeds, &copies,
													   &eventLogProofs, &byteProof) ;
			// 全体読取・容量失敗後に部分local閉包を返さない
			if( error != 0) {
				return error ;
			}
		}

		std::vector<MaintenanceDestinationDirectory> directories ;	// defaultを含めない元named根拠
		error = readMaintenanceDestinationDirectories( inf.get(), workspace, copies, budget,
													  install.inventory, directories, &byteProof) ;
		// metadataの不正・容量・読取失敗後に部分参照を返さない
		if( error != 0) {
			return error ;
		}

		std::vector<MaintenanceCopyBinding> bindings ;	// 構築完了vectorだけを同scopeで借用するcache
		error = bindMaintenanceCopyDestinations( workspace, copies, directories, bindings) ;
		// 私有cacheの不正・容量失敗後に部分参照を返さない
		if( error != 0) {
			return error ;
		}

		const std::size_t sourceObservationCount =
			// 元sourceを含む構築済み観測範囲
			observed.files.size() ;
		byteProof.capacity( observed.files.size() + budget.effects + budget.references +
						   budget.services + budget.issues + budget.fileUses + budget.coverageGaps +
						   copies.size() + directories.size() + bindings.size() +
						   eventLogProofs.size()) ;
		bool fullControlTargets =
			byteProof.active() &&
			install.parser.state ==
				MaintenanceInspectionState::PASSED ;	// 後続associated矛盾も最後に確認する
		// 同原制御行の元用途だけを順に全比較する。typed一時用途をappendしない
		for( std::size_t index = 0U; byteProof.active() && index < byteProof.controlUses.size();
			++index) {
			const auto control =
				byteProof.controlUses[index] ;									// private失効に備えてindexを値で保持する
			const auto field   = byteProof.get( control.first).deferredField ;	// 元deferred field
			fullControlTargets = fullControlTargets && control.second < install.fileUses.size() &&
								 locateMaintenanceCompleteValueSource(
									 byteProof, control.first, field,
									 install.fileUses[control.second].target, bindings,
									 std::span<const MaintenanceInfFileReference>( observed.files)
										 .first( sourceObservationCount)) < sourceObservationCount ;
		}

		// 原data一件の位置候補だけをstageし、後続core／byte確認前に反映しない
		for( std::size_t index = 0U;
			byteProof.active() && fullControlTargets && index < byteProof.data.size(); ++index) {
			const auto candidate = byteProof.data[index] ;	// private allocation失敗後に借用しない
			// 同行最終callerの未成立は元Uを保持する
			if( !candidate.caller || candidate.use >= install.fileUses.size()) {
				continue ;
			}

			const auto source = locateMaintenanceCompleteValueSource(
				byteProof, candidate.row, 5U, install.fileUses[candidate.use].target, bindings,
				std::span<const MaintenanceInfFileReference>( observed.files)
					.first( sourceObservationCount)) ;	// 同元sourceのみ
			// 私有失効後のdata vectorへ書かない
			if( byteProof.active()) {
				byteProof.data[index].sourceFile = source ;
			}
		}

		// 同期indexの保持も共同項目上限へ含め、限界時は分離を保留する
		if( eventLogProofs.size() * 2U + install.fileUses.size() * 2U +
			   install.inventory.coverageGaps.size() * 2U + observed.files.size() >
		   MAXIMUM_INSTALL_INVENTORY_ITEMS) {
			eventLogProofs.clear() ;
		}

		std::vector<std::size_t> useFiles ;	// 元fileUses indexから最終用途indexへの私有結合
		std::vector<std::size_t> gapFiles ;	// 元registry gapからfallback用途への私有結合
		// 証明が残る場合だけ有限indexを確保し、通常用途の保持量を増設しない
		if( !eventLogProofs.empty()) {
			useFiles.resize( install.fileUses.size(), NO_MAINTENANCE_EVENTLOG_INDEX) ;
			gapFiles.resize( install.inventory.coverageGaps.size(), NO_MAINTENANCE_EVENTLOG_INDEX) ;
		}

		// 原用途ごとにsource位置を対応させ、借用終了後だけ用途をappendする
		for( std::size_t useOrdinal = 0U; useOrdinal < install.fileUses.size(); ++useOrdinal) {
			const auto &use = install.fileUses[useOrdinal] ;							// 同行proofを名前だけで結び直さない
			MaintenanceInfFileReference file{use.section, use.directive, use.target} ;	// 元用途copy
			const bool					directCopy = stringsEqual( use.directive, L"CopyFiles") &&
									// 直接source名の表記
									file.target.starts_with( L"@") ;
			// File-list名そのものをpayloadとして照会しない
			if( stringsEqual( use.directive, L"CopyFiles") && !directCopy) {
				continue ;
			}

			// 直接CopyFilesの@だけを除き、source名の安全境界は維持する
			if( directCopy) {
				file.target.erase( 0U, 1U) ;
			}

			const bool binary = stringsEqual( use.directive, L"ServiceBinary") ||
								stringsEqual( use.directive, L"UmdfServiceBinary") ||
								// 既知のfile用途
								stringsEqual( use.directive, L"EventMessageFile") ;
			// package sourceに結べる既知用途だけを位置解決する
			if( directCopy || binary || stringsEqual( use.directive, L"CopyFileSource")) {
				error = binary ? locateMaintenanceBinarySource(
									 inf.get(), workspace, entries, parent, bindings,
									 std::span<const MaintenanceInfFileReference>( observed.files)
										 .first( sourceObservationCount),
									 file)
							   : locateMaintenanceSource( inf.get(), workspace, entries, parent,
														 false, file) ;
				// 不正位置・読取失敗を用途未対応へ弱めない
				if( error != 0) {
					return error ;
				}
			} else {
				file.location = MaintenanceInfFileLocation::UNSUPPORTED ;
				file.error	  = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}

			error = appendMaintenanceFile( observed, std::move( file)) ;
			// 原用途を切り捨てて参照完了にしない
			if( error != 0) {
				return error ;
			}

			// 同元use一件の最終append位置だけを結び、typed用途を増やさない
			if( byteProof.active()) {
				const auto candidate = std::ranges::lower_bound(
					byteProof.data, useOrdinal, {},
					&MaintenanceRegistryDataProof::use) ;	// 原use順の一意indexだけを検索する
				// 元use ordinalの完全一致だけを最後の位置反映へ渡す
				if( candidate != byteProof.data.end() && candidate->use == useOrdinal) {
					candidate->file = observed.files.size() - 1U ;
				}

				byteProof.capacity( observed.files.size() + budget.effects + budget.references +
								   budget.services + budget.issues + budget.fileUses +
								   budget.coverageGaps + copies.size() + directories.size() +
								   bindings.size() + eventLogProofs.size() + useFiles.size() +
								   gapFiles.size()) ;
			}

			// 追加成功した元用途の位置だけを保持し、skip行へ位置を捏造しない
			if( !useFiles.empty()) {
				useFiles[useOrdinal] = observed.files.size() - 1U ;
			}
		}

		// 欠落local節はNeeds以外の具体的な未解決用途へ残す
		for( const auto &reference : install.inventory.references) {
			// Needsは依存核が同節Includeと共に解決し、local不在だけで不正としない
			if( reference.kind == OfficialInfInstallReferenceKind::LOCAL_SECTION &&
			   !reference.targetPresent && !stringsEqual( reference.directive, L"Needs")) {
				error = appendMaintenanceFile( observed,
											  {reference.section,
											   reference.directive,
											   reference.target,
											   {},
											   MaintenanceInfFileLocation::MISSING,
											   nativeErrorFromWin32( ERROR_SECTION_NOT_FOUND)}) ;
				// 欠落用途も保持上限へ含める
				if( error != 0) {
					return error ;
				}
			}
		}

		// sourceなしregistryは作用未評価と未知file用途を区別して不足を具体的に残す
		for( std::size_t gapOrdinal = 0U; gapOrdinal < install.inventory.coverageGaps.size();
			++gapOrdinal) {
			const auto &gap = install.inventory.coverageGaps[gapOrdinal] ;	// 元fallbackの一意ordinal
			// 通常sourceの証拠を単なるregistry作用未評価で取り消さない
			if( !observed.sourceSectionPresent &&
			   gap.kind == OfficialInfInstallCoverageKind::REGISTRY_SCOPE_NOT_ASSESSED) {
				error =
					appendMaintenanceFile( observed, {gap.section,
													 L"RegistryFileUsesNotAssessed",
													 {},
													 {},
													 MaintenanceInfFileLocation::UNSUPPORTED,
													 nativeErrorFromWin32( ERROR_NOT_SUPPORTED)}) ;
				// 不足行の累積保持量も有限にする
				if( error != 0) {
					return error ;
				}

				// 同eventlog子節の元gapに対応したappend済みUだけを証明へ使う
				if( !gapFiles.empty()) {
					gapFiles[gapOrdinal] = observed.files.size() - 1U ;
				}
			}
		}

		// 全fallback append後に同referenceの独立Uを確認し、同行親一件だけを分離する
		if( !eventLogProofs.empty() &&
		   observed.referenceCoverage == MaintenanceInfReferenceCoverage::INCOMPLETE &&
		   useFiles.size() + gapFiles.size() + eventLogProofs.size() * 2U + observed.files.size() <=
			   MAXIMUM_INSTALL_INVENTORY_ITEMS) {
			std::vector<std::size_t> separated ;	// 証明済み親の最終index。上限は元proof数
			// 各同行proofを二つの既存indexへ定数回結び、全親×全用途を再探索しない
			for( const auto &proof : eventLogProofs) {
				const std::size_t marker = useFiles[proof.marker] ;	// 当該AddService行の元用途
				const std::size_t child =
					proof.childUse != NO_MAINTENANCE_EVENTLOG_INDEX
						? useFiles[proof.childUse]
						: (proof.childGap != NO_MAINTENANCE_EVENTLOG_INDEX
							   ? gapFiles[proof.childGap]
							   : NO_MAINTENANCE_EVENTLOG_INDEX) ;	// 別節やSYSTEM不足を代用しない
				// Appendされなかった子Uや同一用途を独立不足として認めない
				if( marker >= observed.files.size() || child >= observed.files.size() ||
				   marker == child) {
					continue ;
				}

				const auto &parentFile = observed.files[marker] ;	// 行結合済みの元親
				const auto &childFile  = observed.files[child] ;	// 同queueから来たappend済み子
				// 新dataの位置成立を57の独立子Uとして便乗させず、元親markerを保持する
				if( byteProof.active() &&
				   std::ranges::any_of( byteProof.data, [child]( const auto &candidate) {
					   return candidate.file == child &&
							  candidate.sourceFile != NO_MAINTENANCE_RAW_ROW ;
				   })) {
					continue ;
				}

				// 元Uのkind・HRESULTを保持できる形だけを分離し、file充足へ昇格させない
				if( stringsEqual( parentFile.directive, L"AddService") &&
				   parentFile.location == MaintenanceInfFileLocation::UNSUPPORTED &&
				   parentFile.error == nativeErrorFromWin32( ERROR_NOT_SUPPORTED) &&
				   (stringsEqual( childFile.directive, L"RegistryFileUseNotAssessed") ||
					stringsEqual( childFile.directive, L"RegistryFileUsesNotAssessed")) &&
				   childFile.location == MaintenanceInfFileLocation::UNSUPPORTED &&
				   childFile.error == nativeErrorFromWin32( ERROR_NOT_SUPPORTED)) {
					separated.push_back( marker) ;
				}
			}

			// 元順序filter用の有限index
			std::ranges::sort( separated) ;
			// 親だけの分離によるordinal移動を元data一件のindexへ反映する
			if( byteProof.active()) {
				// 元順序のprivate data indexだけを一度ずつ補正する
				for( auto &candidate : byteProof.data) {
					// 未appendの用途へ位置indexを補完しない
					if( candidate.file < observed.files.size()) {
						candidate.file -= static_cast<std::size_t>(
							std::ranges::lower_bound( separated, candidate.file) -
							separated.begin()) ;
					}
				}
			}

			std::size_t fileOrdinal{} ;			// 元最終用途のordinal。survivorの相対順序を維持する
			std::size_t separatedOrdinal{} ;	// 同行親の昇順indexだけを一度ずつ消費する
			// 子Uは分離集合に含めず、元coverage・inventory・contentを変更しない
			std::erase_if( observed.files,
						  [&separated, &fileOrdinal, &separatedOrdinal]( const auto &) {
							  const bool remove = separatedOrdinal < separated.size() &&
												  separated[separatedOrdinal] ==
													  fileOrdinal ;	// 文字列照合filterはしない
							  ++fileOrdinal ;
							  // 証明済み親だけを一件消費し、未証明用途は全て保持する
							  if( remove) {
								  ++separatedOrdinal ;
							  }

							  return remove ;
						  }) ;
		}

		// 従来の参照分類を同じ正本集合で維持し、内容専用EXEだけを限定受理する
		for( const auto &file : observed.sourceFiles) {
			const std::wstring extension = lowerExtension( file) ;	// 元参照fileの拡張子
			// 未対応program／archive／firmwareをnull認識で許可しない
			if( std::ranges::find( REJECTED_REFERENCED_EXTENSIONS, extension) !=
				   REJECTED_REFERENCED_EXTENSIONS.end() &&
			   !(extension == L".exe" && policy.allowReferencedExecutablesForContent)) {
				return nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
			}
		}

		// 元policyの一INF参照数を新棚卸しでも維持する
		if( observed.sourceFiles.size() > policy.maximumSourceFiles) {
			return nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		}

		observed.inventory				   = std::move( install.inventory) ;
		observed.inventory.infRelativePath = observed.infRelativePath ;
		observed.inventory.infSha256	   = observed.infSha256 ;
		observed.inventory.scannedLines +=
			static_cast<std::uint32_t>( versionCount + (std::max)( sourceCount, 0L)) ;
		error = verifyOfficialFileMetadata( path, {entry->uncompressedSize, observed.infSha256}) ;
		// 終了時の元byte差は部分結果を全て破棄する
		if( error != 0) {
			return error ;
		}

		byteProof.capacity( observed.files.size() + budget.effects + budget.references +
						   budget.services + budget.issues + budget.fileUses + budget.coverageGaps +
						   copies.size() + directories.size() + bindings.size() +
						   eventLogProofs.size() + useFiles.size() + gapFiles.size()) ;
		// 元読取・容量・全byte確認の成功後だけ元data位置を最後に反映する
		if( byteProof.active()) {
			try {
				// 一意全targetが成立した元data用途だけを元順序で反映する
				for( const auto &candidate : byteProof.data) {
					// 私有保留と未appendは元identity／U／HRESULTをそのまま保持する
					if( candidate.file >= observed.files.size() ||
					   candidate.sourceFile >= sourceObservationCount) {
						continue ;
					}

					auto &file		  = observed.files[candidate.file] ;	// 元registry data用途だけ
					file.relativePath = observed.files[candidate.sourceFile].relativePath ;
					file.location	  = MaintenanceInfFileLocation::LOCATED ;
					file.error		  = 0 ;
				}
			} catch( const std::bad_alloc &) {
				// 私有位置反映のallocation失敗では全stageを撤回し、正常元結果を全体拒否しない
				for( const auto &candidate : byteProof.data) {
					// 変更可能だった元dataだけを元Uへ戻す
					if( candidate.file < observed.files.size()) {
						auto &file = observed.files[candidate.file] ;	// 元用途のidentityは保持する
						file.relativePath.clear() ;
						file.location = MaintenanceInfFileLocation::UNSUPPORTED ;
						file.error	  = nativeErrorFromWin32( ERROR_NOT_SUPPORTED) ;
					}
				}

				byteProof.disable() ;
			}
		}

		references = std::move( observed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( const std::length_error &) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じHINF/source IDの完全source/media応答を共有します
 * @param[in] inf 同期借用する一INF handleです
 * @param[in] fileName 元basenameです
 * @param[out] sourceDirectory 完全取得した元subdirです
 * @param[out] mediaDirectory installation-root相対の元媒体です
 * @return 完全取得0、欠損・曖昧・部分応答・root-only policy拒否のHRESULTです
 * @note 保護領域とCAT/member検査は呼出し側で別途必要です
 */
//------------------------------------------------------------------------------
NativeError readOfficialInfSourceDirectories( void *inf, const std::wstring &fileName,
											 std::wstring &sourceDirectory,
											 std::wstring &mediaDirectory)
{
	return readInfSourceDirectories( inf, fileName, sourceDirectory, mediaDirectory) ;
}
} // namespace drivercrate
