//------------------------------------------------------------------------------
/**
 * @file signed_index_candidate_binding_tests.cpp
 * @brief 真署名索引から通常候補とfake指定導入へ接続する有限fixtureを検証します
 * @version 01.64.01
 * @date 2026/10/24
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/10/12  低位fixtureと通常候補試験の宣言・所有期間を説明
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  二device部分失敗と実UI共有の低位worker factoryを追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  完全登録root・真初回・INF別拒否とdevice別callを固定
 * Ver.01.02.01 Shunji Ogawa  2026/10/12  低位callbackとhelperの引数・返却・借用契約を補足
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  実CAT memberと低位署名期待hashの不一致を固定
 * Ver.01.05.00 Shunji Ogawa  2026/10/13  元Class未確定と実INF/native Classの完全低位条件を固定
 * Ver.01.06.00 Shunji Ogawa  2026/10/13  元親と必要SWC子の完全低位fixtureを追加
 * Ver.01.07.00 Shunji Ogawa  2026/10/13  元native節と全import CAT/hash差を完全低位へ接続
 * Ver.01.08.00 Shunji Ogawa  2026/10/13  必要Win32 service EXEを元INF ownerへ結ぶ完全低位条件を追加
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  固定subdir serviceの完全相対位置を同元INF CAT ownerへ結合
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  新媒体24条件の完全member位置と二CAT拒否を固定
 * Ver.01.11.00 Shunji Ogawa  2026/10/13  完全五APIとSYSTEM元byte/効果とPACKAGE改変観測を接続
 * Ver.01.12.00 Shunji Ogawa  2026/10/14  他node必要ID失敗と二node一致を低位propertyへ固定
 * Ver.01.13.00 Shunji Ogawa  2026/10/15  R04で全present再列挙を指定node照会から独立観測
 * Ver.01.14.00 Shunji Ogawa  2026/10/15  完全低位署名factoryから同期観測を登録
 * Ver.01.15.00 Shunji Ogawa  2026/10/15  登録Extensionへの書換権限と全byte保持を実fileで確認
 * Ver.01.16.00 Shunji Ogawa  2026/10/15  archive128/129境界にも全ownerの署名低位表を固定
 * Ver.01.17.00 Shunji Ogawa  2026/10/15  fake復旧前同期とjoin後の非署名counter観測を追加
 * Ver.01.17.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける
 * Ver.01.18.00 Shunji Ogawa  2026/10/16  索引通信結果の可視導線と同版publicationの画面受入を追加
 * Ver.01.18.01 Shunji Ogawa  2026/10/19  取得前参照の欠損値と現在情報・検証INF情報の分離を確認
 * Ver.01.19.00 Shunji Ogawa  2026/10/23 実producerの新ID/原INF/共有取得を通常workerへ接続
 * Ver.01.20.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合
 * Ver.01.21.00 Shunji Ogawa  2026/10/24  原Intel packageの実署名/完全tupleを通常workerへ接続
 * Ver.01.21.01 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示
 * Ver.01.22.00 Shunji Ogawa  2026/10/27  同ID二機能の完全初回/他node不足と選択一件を回帰
 * Ver.01.23.00 Shunji Ogawa  2026/10/27  最小full-rankの順序・同点・読取不足・直前変化を回帰
 * Ver.01.24.00 Shunji Ogawa  2026/10/28  同ID二件batchと成功した自己状態だけの変化を回帰
 * Ver.01.25.00 Shunji Ogawa  2026/10/28  選択対象の導入後実観測と現在行の自動更新を接続
 * Ver.01.26.00 Shunji Ogawa  2026/10/28  既検証WUA候補と未取得索引の明示混在fixtureを追加
 * Ver.01.27.00 Shunji Ogawa  2026/11/03  原INF参照の版投影と非導入境界を確認
 * Ver.01.28.00 Shunji Ogawa  2026/11/06  driver DATAとstage-only importの通常保護導入を検査
 * Ver.01.29.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続
 * Ver.01.30.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続
 * Ver.01.31.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続
 * Ver.01.31.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.31.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.31.03 Shunji Ogawa  2026/11/12  導入前保護失敗に結合した一回の明示復元なし続行を接続
 * Ver.01.31.04 Shunji Ogawa  2026/11/13  元適用性errorへ固定失敗leafとcode由来だけを接続
 * Ver.01.31.05 Shunji Ogawa  2026/11/13  bounded opaque PnP IDのrank照合と限定回帰を接続
 * Ver.01.31.06 Shunji Ogawa  2026/11/13  Needs AddRegの元拒否leafを既匿名診断へ接続
 * Ver.01.31.07 Shunji Ogawa  2026/11/13  SYSTEM標準媒体登録の実parser正負経路を接続
 * Ver.01.31.08 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.32.00 Shunji Ogawa  2026/11/16  storage通常選択と完全native表の正負・原結果を検証
 * Ver.01.33.00 Shunji Ogawa  2026/11/16  MTD原Classの低位deviceとINF読取を追加
 * Ver.01.34.00 Shunji Ogawa  2026/11/17  MTD同原copyと指定DIFの完全fake正負を検証
 * Ver.01.35.00 Shunji Ogawa  2026/11/17  必要子proofと役割別ACLの正負を通常操作で検査
 * Ver.01.36.00 Shunji Ogawa  2026/11/18  P3同scan fullhost観測と取得直前拒否を接続
 * Ver.01.36.01 Shunji Ogawa  2026/11/18  retained拒否の実到達境界を独立契約へ明示
 * Ver.01.37.00 Shunji Ogawa  2026/11/18  P4純粋比較と非空所有pipeline/最終Models・host拒否を接続
 * Ver.01.37.01 Shunji Ogawa  2026/11/18  SDK macro衝突を避け既Access定義の直接依存を補完
 * Ver.01.37.02 Shunji Ogawa  2026/11/18  P4の単一scanから元cached summaryと実counterを観測
 * Ver.01.37.03 Shunji Ogawa  2026/11/18  借用issuer生存中のsession失効へfixture破棄順を訂正
 * Ver.01.37.04 Shunji Ogawa  2026/11/18  P4不一致の元summaryと監査結果を数値だけで観測
 * Ver.01.37.05 Shunji Ogawa  2026/11/18  原署名fakeとseal診断・二root所有と公開拒否集計を整合
 * Ver.01.38.00 Shunji Ogawa  2026/11/19  正規Client26200条件の限定通常scan/取得とhost拒否を検証
 * Ver.01.39.00 Shunji Ogawa  2026/11/19  24H2最低26100の独立回帰と旧条件を接続
 * Ver.01.39.01 Shunji Ogawa  2026/11/19  Server新scan回復試験で単調増加する計画IDを使用
 * Ver.01.39.02 Shunji Ogawa  2026/11/19  Server新scanの二つの取得rootを同じ人工署名fixtureで検証
 * Ver.01.39.03 Shunji Ogawa  2026/11/19  失効した元列挙からの監査と取得再開始を検証
 * Ver.01.40.00 Shunji Ogawa  2026/11/19  AWS原レコードの通常取得計画とNitro確認を検証
 * Ver.01.40.01 Shunji Ogawa  2026/11/19  単体試験専用のfixture依存をUI試験のリンクから除外
 * Ver.01.41.00 Shunji Ogawa  2026/11/19  独自クラスの二つの登録状態と元配布物の指定導入を通しで検証
 * Ver.01.42.00 Shunji Ogawa  2026/11/20  本文とCatalog追加欄を同じ端末で照合し元期限前後の取得を検証
 * Ver.01.43.00 Shunji Ogawa  2026/11/20  Catalog候補の端末ID変化と登録・適用前の期限を保護付き導入で検証
 * Ver.01.44.00 Shunji Ogawa  2026/11/20  機種別追加欄の同スキャン照合と取得保留を検証
 * Ver.01.45.00 Shunji Ogawa  2026/11/20  型番再観測による取得許可・送信拒否と本文継続を検証
 * Ver.01.46.00 Shunji Ogawa  2026/11/20  機種別候補の発行と登録・指定適用直前の再照合を検証
 * Ver.01.47.00 Shunji Ogawa  2026/11/20  ファームウェア確認の接続前に取得を保留する試験を追加
 * Ver.01.48.00 Shunji Ogawa  2026/11/20  同一端末の全HardwareIdsから必須群の一意性と競合を検証
 * Ver.01.49.00 Shunji Ogawa  2026/11/20  同じ元行の端末別確認対象と確認後の取得保留を検証
 * Ver.01.50.00 Shunji Ogawa  2026/11/20  現在の端末属性で元のファームウェア群を再観測
 * Ver.01.51.00 Shunji Ogawa  2026/11/20  ファームウェア群の競合による保留と個別承認後の取得・再検査を検証
 * Ver.01.52.00 Shunji Ogawa  2026/11/20  承認した端末への候補発行と登録・指定適用直前のファームウェア群を検証
 * Ver.01.53.00 Shunji Ogawa  2026/11/20  機器の最終再観測中に取得許可が失効する登録・適用を検証
 * Ver.01.54.00 Shunji Ogawa  2026/11/21  メディアチェンジャーの端末と起動グループを架空Windows応答に追加
 * Ver.01.55.00 Shunji Ogawa  2026/11/21  HDCの正式クラスと適用直前の起動順変化を架空Windows応答に追加
 * Ver.01.56.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの端末フィルターの型・競合・読取り失敗を検査
 * Ver.01.57.00 Shunji Ogawa  2026/11/22  保存したZIP規約の通常同意と取得前照合を検査
 * Ver.01.58.00 Shunji Ogawa  2026/11/22  現在の元端末と完全Hardware IDの独立再照合を検証
 * Ver.01.59.00 Shunji Ogawa  2026/11/23  通常スキャンで署名済みWiX行の端末条件と元期限を検証
 * Ver.01.60.00 Shunji Ogawa  2026/11/23  同端末のWiX表示専用参照と空の取得計画を検証
 * Ver.01.61.00 Shunji Ogawa  2026/11/23  WiX検査専用計画を元本文と通常導入へ分離して検証
 * Ver.01.62.00 Shunji Ogawa  2026/11/23  通常ワーカーでWiXの元アンカーと転送・待機・期限を検証
 * Ver.01.63.00 Shunji Ogawa  2026/11/23  同じ候補行と元計画のWiX検査専用結合を検証
 * Ver.01.63.01 Shunji Ogawa  2026/11/23  受信を終えた同一ハッシュでも不正なWiX内容を拒否することを検証
 * Ver.01.63.02 Shunji Ogawa  2026/11/23  元対象が一致するWiX表示行だけの私有機器参照を検証
 * Ver.01.64.00 Shunji Ogawa  2026/11/23  元規約の差し替え、欠損、重複とスキャンの違いを検証
 * Ver.01.64.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#include "signed_index_candidate_binding_tests.h"
#include "platform/composite_update_provider.h"
#include "platform/common_driver_package.h"
#include "platform/driver_store_provider.h"
#include "platform/official_file_verifier.h"
#include "platform/official_download_grant.h"
#include "platform/official_download_workspace.h"
#include "platform/official_http_transport.h"
#include "platform/inf_dependency_native_internal.h"
#include "platform/official_inf_models_native_internal.h"
#include "platform/signed_index_acquisition_adapter.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "platform/signed_index_record_lookup.h"
#include "platform/signed_index_records.h"
#include "platform/storage_inf_effects_internal.h"
#include "platform/windows_product_type.h"
#include "core/restore_point_service.h"
#include "core/operation_controller.h"
#include "core/candidate_selection.h"
#include "core/candidate_audit.h"
#include "core/device_observation.h"
#include "core/official_download_delegation.h"
#include "core/provider_registry.h"
#include "core/pending_reference_version.h"
#include "platform/mtd_shared_file_internal.h"
#include "platform/mtd_queue_internal.h"
#include "platform/mtd_handler_internal.h"
#include <Windows.h>
#include <Softpub.h>
#include <devpkey.h>
#include <devguid.h>
#include <cfg.h>
#include <miniz.h>
#include <sddl.h>
#include <winhttp.h>
#include <array>
#include <chrono>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <initializer_list>
#include <iostream>
#include <atomic>
#include <fstream>
#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <set>
#include <utility>
#include <vector>

namespace drivercrate {
/** @brief 完全fakeの同期中だけ元必要子proofの拒否を観測します */
class RequiredChildBindingProbe final {
public:
	/**
	 * @brief 元選択親の導出子名へ、別所有entryの衝突を一回だけ作ります
	 * @param[in,out] store 完全fakeが同workerで所有する元Providerです
	 * @return 既存entryを変更せず一意な試験entryを追加した場合trueです
	 */
	[[nodiscard]] static bool insertCollision( DriverStoreProvider &store) noexcept
	{
		try {
			// 元親が一件で子scope開始前の場合だけ衝突を作ります
			if( store.activeInstallDevices_.size() != 1U || store.activeRequiredChild_) {
				return false ;
			}

			// 元親から製品が導出する最初の必要子identityです
			const auto identity = store.activeInstallDevices_.front() + L"/required-component-1" ;
			return store.deviceInstances_.emplace( identity, L"other-owned-instance").second ;
		} catch( ...) {
			return false ;
		}
	}
	/**
	 * @brief 同衝突entryが元の値のままであるかを同worker内で確認します
	 * @param[in] store 完全fakeが同workerで借用する元Providerです
	 * @return 元entryが残り、子proofを発行していなければtrueです
	 */
	[[nodiscard]] static bool collisionIntact( const DriverStoreProvider &store) noexcept
	{
		try {
			// 同じ元親とscope終了を確認できなければ保持を認定しません
			if( store.activeInstallDevices_.size() != 1U || store.activeRequiredChild_) {
				return false ;
			}

			// 子の発行前に別所有として挿入したidentityです
			const auto identity = store.activeInstallDevices_.front() + L"/required-component-1" ;
			// 原衝突entryの現在位置です
			const auto entry = store.deviceInstances_.find( identity) ;
			return entry != store.deviceInstances_.end() &&
				   entry->second == L"other-owned-instance" ;
		} catch( ...) {
			return false ;
		}
	}
	/**
	 * @brief 実操作中の元proofを保持し、別親・役割・issuer等の拒否を個別に照合します
	 * @param[in,out] store 同workerに属する本物の元Providerです
	 * @return 未到達は0、元proofと十一の独立拒否を下位12 bitへ記録します
	 * @note 所有状態は終了前に復元し、fake以外のAPIや導入結果を変更しません
	 */
	[[nodiscard]] static std::uint32_t inspect( DriverStoreProvider &store) noexcept
	{
		// 実操作が同期所有する元proofだけを借用します
		const auto *original = store.activeRequiredChild_ ;
		// 元子scopeの成立前は到達値を生成しません
		if( !original || !original->inspection || !original->inspection->workspace ||
		   !original->package) {
			return 0U ;
		}

		// 各負例の後も元proofへ戻すscope終了処理です
		const auto restore = [&]( void *) noexcept { store.activeRequiredChild_ = original ; } ;
		// 例外を含め元proofを同期scopeへ復元します
		const std::unique_ptr<void, decltype( restore)> guard{&store, restore} ;
		try {
			// 元検査に結合した同じ保護workspaceです
			const auto	 &workspace = *original->inspection->workspace ;
			// 元planが指定した同一packageです
			const auto	 &package = *original->package ;
			// 実列挙された同一子identityです
			const auto	  child = original->childIdentity ;
			// 独立した正負の成立を記録するbit集合です
			std::uint32_t checks{} ;
			// 本物の同期scopeが成立していることを各負例の前に確認します
			if( store.ownsBindingDevice( child, workspace, package)) {
				checks |= 1U << 0U ;
			}

			// 一項目だけ変えたproofが拒否されたことを記録します
			const auto rejected = [&]( auto change, const unsigned bit) {
				// 元proofは変更せず局所copyへ一条件だけ注入します
				auto altered = *original ;
				change( altered) ;
				store.activeRequiredChild_ = &altered ;
				// 元子bindingの所有を偽造できない場合だけbitを立てます
				if( !store.ownsBindingDevice( child, workspace, package)) {
					checks |= 1U << bit ;
				}

				store.activeRequiredChild_ = original ;
			} ;
			rejected( []( auto &proof) { proof.parentIdentity = L"other-parent" ; }, 1U) ;
			rejected( []( auto &proof) { proof.roleIndex = static_cast<std::size_t>( -1) ; }, 2U) ;
			rejected( []( auto &proof) { ++proof.operation ; }, 4U) ;
			rejected( []( auto &proof) { ++proof.session ; }, 5U) ;
			rejected( []( auto &proof) { proof.parentBindingToken = 0U ; }, 8U) ;
			rejected( []( auto &proof) { proof.parentInstance = L"other-instance" ; }, 9U) ;
			rejected( []( auto &proof) { proof.childIdentity = L"other-child" ; }, 10U) ;
			rejected( []( auto &proof) { proof.plan = nullptr ; }, 11U) ;

			// 別issuerには同scan状況を与えても元親bindingは存在しません
			DriverStoreProvider outsider ;
			outsider.scanSessionId_			 = store.scanSessionId_ ;
			outsider.ownerThreadId_			 = store.ownerThreadId_ ;
			outsider.activeInstallOperation_ = store.activeInstallOperation_ ;
			outsider.activeInstallDevices_	 = store.activeInstallDevices_ ;
			outsider.activeIndexDevices_	 = store.activeIndexDevices_ ;
			outsider.pendingIndexDevices_	 = store.pendingIndexDevices_ ;
			outsider.indexInventory_		 = store.indexInventory_ ;
			outsider.installProofInventory_	 = store.installProofInventory_ ;
			outsider.deviceInstances_		 = store.deviceInstances_ ;
			outsider.activeRequiredChild_	 = original ;
			// 元issuer以外では同じ子を所有できません
			if( !outsider.ownsBindingDevice( child, workspace, package)) {
				checks |= 1U << 3U ;
			}

			// 異なる元packageまたは別workspaceを元proofへ代入しません
			if( !original->inspection->closure.packages.empty() &&
			   !store.ownsBindingDevice( child, workspace,
										original->inspection->closure.packages.front())) {
				checks |= 1U << 6U ;
			}

			// 元検査とは別の空workspaceを不一致入力にします
			OfficialDownloadWorkspace otherWorkspace ;
			// 別workspaceは元proofの所有対象ではありません
			if( !store.ownsBindingDevice( child, otherWorkspace, package)) {
				checks |= 1U << 7U ;
			}

			return checks ;
		} catch( ...) {
			return 0U ;
		}
	}
} ;
} // namespace drivercrate

namespace drivercrate::test {
/** @brief 所有workspaceの独立I/O試験だけが共有file内部段階を呼びます */
struct MtdSharedFileFixtureAccess {
	/**
	 * @brief 同owned sourceを単独file試験へ結びます
	 * @param[in,out] operation 同試験の共有file操作です
	 * @param[in] registeredInf 同fixtureの架空登録pathです
	 * @param[in] sources 所有workspace内sourceの完全pathです
	 * @return 元source検査のHRESULTです
	 */
	static NativeError bind( MtdSharedFileOperation &operation, std::wstring_view registeredInf,
							std::span<const std::wstring> sources)
	{
		return operation.bindQueueSources( registeredInf, sources) ;
	}
	/**
	 * @brief 同owned sourceのfile配置だけを独立試験します
	 * @param[in,out] operation 同試験の共有file操作です
	 * @param[in] cancelled 同期中の取消しfakeです
	 * @param[out] result 原file部分作用です
	 * @return 元file操作のHRESULTです
	 */
	static NativeError satisfy( MtdSharedFileOperation	   &operation,
							   const std::function<bool()> &cancelled, MtdSharedFileResult &result)
	{
		return operation.satisfy( cancelled, []() -> NativeError { return 0U ; }, result) ;
	}
} ;

/** @brief 所有workspaceでqueue通知時の取消しを独立試験します */
struct MtdQueueFixtureAccess {
	/**
	 * @brief 同所有fixtureの原queueから実照合を経て制御queueを作ります
	 * @param[in] original 同fixtureの元queueです
	 * @param[in] registeredInf 同fixtureの架空登録INFです
	 * @param[in,out] workspace 同所有元領域です
	 * @param[in] facts 同原copy集合です
	 * @param[in,out] files 同共有file操作です
	 * @param[out] result 照合成立時のqueueです
	 * @return 元queue照合のHRESULTです
	 */
	static NativeError prepare( HSPFILEQ original, std::wstring_view registeredInf,
							   OfficialDownloadWorkspace		  &workspace,
							   const SelectedStorageServiceFacts  &facts,
							   MtdSharedFileOperation			  &files,
							   std::unique_ptr<MtdQualifiedQueue> &result)
	{
		return MtdQualifiedQueue::prepare( original, registeredInf, workspace, facts, files, result) ;
	}
	/**
	 * @brief 同fixtureのqueue callbackを取消し条件付きで実行します
	 * @param[in,out] queue 同所有の照合済みqueueです
	 * @param[in] cancelled callback時の取消しfakeです
	 * @param[out] result 元copyと部分作用です
	 * @return 元queue操作のHRESULTです
	 */
	static NativeError commit( MtdQualifiedQueue &queue, const std::function<bool()> &cancelled,
							  MtdQueueResult &result)
	{
		return queue.commit( nullptr, cancelled, []() -> NativeError { return 0U ; }, result) ;
	}
} ;
namespace {
// 通常Ports内容とWindows nodeが完全一致する固定class
constexpr GUID PORTS_CLASS{
	0x4d36e978, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}} ;
// Net一種へ処理を限定していないことを確認する別の通常class
constexpr GUID NET_CLASS{
	0x4d36e972, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}} ;
// 実在端末や元メーカーの登録と独立した人工クラスです
constexpr GUID DECLARATIVE_CLASS{
	0xc054bd69, 0xa76e, 0x4caa, {0xa9, 0x15, 0xe3, 0xce, 0x9a, 0x28, 0x5b, 0x62}} ;
constexpr wchar_t DECLARATIVE_NAME[] = L"DCFixtureBridge" ;	// 合成INFが宣言するクラスです
constexpr wchar_t DECLARATIVE_STORE[] =
	L"System32\\DriverStore\\FileRepository\\fixture.inf_amd64_fixture\\" ;	// 所有する人工Storeです
// 元storage INFとnative現在nodeを同じ正式Classへ結びます
constexpr GUID STORAGE_CLASS{
	0x4d36e97b, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}} ;
// fakeが受け入れる正式MTD class GUIDです
constexpr GUID MTD_CLASS{
	0x4d36e970, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}} ;
// 架空のメディアチェンジャーの正式クラスGUID
constexpr GUID MEDIUM_CHANGER_CLASS{
	0xce5939ae, 0xebde, 0x11d0, {0xb1, 0x81, 0x00, 0x00, 0xf8, 0x75, 0x3e, 0xc4}} ;
// 架空IDEコントローラーのINFと端末ClassGUIDを結ぶ正式クラス
constexpr GUID HDC_CLASS{
	0x4d36e96a, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}} ;
// 必要SoftwareComponentの元Class/GUIDです
constexpr GUID COMPONENT_CLASS{
	0x5c4c3332, 0x344d, 0x483c, {0x87, 0x39, 0x25, 0x9e, 0x93, 0x4c, 0x9c, 0xc8}} ;
// 必要Extensionの元Class/GUIDです
constexpr GUID EXTENSION_CLASS{
	0xe2f84ce7, 0x8efa, 0x411c, {0xaa, 0x69, 0x97, 0x45, 0x4c, 0xa4, 0xcb, 0x57}} ;
//------------------------------------------------------------------------------
/**
 * @brief 同実INF byteのClassを返す低位fakeの宣言です
 * @param[in] path 同期中だけ借用する非nullのNUL終端INF pathです。通常は隔離file、明示Intel replayでは元保護INFです
 * @param[out] guid 成功時のClassGUIDです。nullは拒否します
 * @param[out] name capacity文字のClass名bufferです。成功時にNUL終端し、容量不足を拒否します
 * @param[in] capacity nameのUTF-16文字容量です
 * @param[out] required 必要なClass名文字容量の出力です。nullは拒否します
 * @return Class情報の取得/出力成功時TRUE、入力・file・容量の拒否時FALSEと元LastErrorです
 * @note 通常の人工scopeは1MiB以下の隔離INFだけを読みます。originalIntelArchiveの明示replayではSetupDiGetINFClassWへ委譲します
 *       driver導入は行いません
 */
//------------------------------------------------------------------------------
BOOL WINAPI infClass( PCWSTR path, LPGUID guid, PWSTR name, DWORD capacity, PDWORD required) ;
//------------------------------------------------------------------------------
/**
 * @brief MTD専用tableの部分指定を確認する未実行fake slotです
 * @param[in] set 呼出しに使用しない架空setです
 * @param[in] device 呼出しに使用しない架空deviceです
 * @param[in] driver 呼出しに使用しない架空nodeです
 * @return 呼出しを許さないため常にFALSEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI incompleteMtdSelected( [[maybe_unused]] HDEVINFO			  set,
								  [[maybe_unused]] PSP_DEVINFO_DATA	  device,
								  [[maybe_unused]] PSP_DRVINFO_DATA_W driver)
{
	return FALSE ;
}
/** @brief 未呼出し前提のAPI表構造だけをABI別に固定します */
template <typename Function> struct UncalledMtdSlot ;
/** @brief 構造検査中に誤って低位slotを呼んだ場合は試験を停止します */
template <typename Result, typename... Arguments>
struct UncalledMtdSlot<Result( WINAPI *)( Arguments...)> {
	//------------------------------------------------------------------------------
	/**
	 * @brief 実device/fileを呼ばず誤呼出しを停止します
	 * @param[in] args 実行できない架空ABI引数です
	 * @return 正常には返りません
	 */
	//------------------------------------------------------------------------------
	[[noreturn]] static Result WINAPI invoke( [[maybe_unused]] Arguments... args)
	{
		std::abort() ;
	}
} ;
/** @brief 一handler propertyの低位API応答です */
struct MtdFixtureProperty {
	/// 元getterが返すWindows errorです
	DWORD				   error{ERROR_NOT_FOUND} ;
	/// 元getterが返すproperty型です
	DEVPROPTYPE			   type{} ;
	/// 元getterが返す値のbyteです
	std::vector<std::byte> bytes ;
	/// 容量照会後に消える条件です
	bool				   vanishAfterSizing{} ;
} ;
/** @brief fake queueの一原copyです */
struct MtdFixtureCopy {
	/// 元copy sourceです
	std::wstring source ;
	/// 元copy targetです
	std::wstring target ;
	/// 元API copy flagsです
	DWORD		 flags{} ;
} ;
/** @brief 所有する一fake queueとその原copyです */
struct MtdFixtureQueue {
	/// このfake queueが割当済みならtrueです
	bool						used{} ;
	/// 元queueならtrueです
	bool						original{} ;
	/// 同queueに登録されたcopy行です
	std::vector<MtdFixtureCopy> copies ;
} ;
/** @brief 一意な所有workspace内だけへ実file操作を投影する内部fakeです */
struct MtdFileFixture {
	/**
	 * @brief 同fixtureが所有する競合writerだけを閉じます
	 */
	~MtdFileFixture()
	{
		// fixtureが所有する競合writerだけを閉じます
		if( existingWriter != INVALID_HANDLE_VALUE) {
			::CloseHandle( existingWriter) ;
		}
	}
	/// 同fixtureで注入する有限条件です
	MtdFixtureScenario							scenario{MtdFixtureScenario::BOTH_ABSENT} ;
	/// 写像するWindows rootです
	std::wstring								windowsRoot ;
	/// 所有する元package rootです
	std::wstring								sourceRoot ;
	/// 非空時だけ元Windowsの文字列を一意所有volumeへ写像します
	std::wstring								logicalVolume ;
	/// 一意所有volumeの実pathです
	std::wstring								physicalVolume ;
	/// 人工の登録INF source directoryです
	std::wstring								storeDirectory ;
	/// 所有するfake queueです
	std::array<MtdFixtureQueue, 4U>				queues ;
	/// 人工deviceごとの選択nodeです
	std::array<SP_DRVINFO_DATA_W, 32U>			selected{} ;
	/// 選択nodeの有無です
	std::array<bool, 32U>						hasSelected{} ;
	/// 既存targetの元file IDです
	std::array<std::optional<FILE_ID_INFO>, 2U> initialTargetIds ;
	/// file DIFの呼出し数です
	std::uint32_t								filesDifs{} ;
	/// 選択DIFの呼出し数です
	std::uint32_t								installDifs{} ;
	/// 制御queueのcommit数です
	std::uint32_t								commits{} ;
	/// Windows root照会の回数です
	std::uint32_t								windowsRootChecks{} ;
	/// node選択の回数です
	std::uint32_t								selectedSets{} ;
	/// queue照合の回数です
	std::uint32_t								queueScans{} ;
	/// temp flushの回数です
	std::uint32_t								flushes{} ;
	/// 非置換renameの成功数です
	std::uint32_t								successfulRenames{} ;
	/// 実際に観測したsource rootです
	std::wstring								observedSourceRoot ;
	/// 所有範囲外のqueue操作を拒否した場合trueです
	bool										queueOutsideOwned{} ;
	/// 復旧成立前に共有先へ到達した場合trueです
	bool										beforeRestoreAccess{} ;
	/// 競合条件でfixtureが所有するwriterです
	HANDLE										existingWriter{INVALID_HANDLE_VALUE} ;
	/// 非置換後のpath観測差を注入した場合trueです
	bool										pathFaultInjected{} ;
	/// 所有handleと開いたpathの対応です
	std::unordered_map<HANDLE, std::wstring>	handles ;
	/// rename後のhandleとpathの対応です
	std::unordered_map<HANDLE, std::wstring>	renamed ;
	/// 人工security不一致のtargetです
	std::wstring								badSecurityTarget ;
	/// 競合挿入先のtargetです
	std::wstring								raceTarget ;
	/// 競合側が作るbyteです
	std::string									raceBytes ;
	/// 競合を注入済みならtrueです
	bool										raceInjected{} ;
	/// tempへのwrite回数です
	std::uint32_t								writes{} ;
	/// write失敗を注入する回数です
	std::optional<std::uint32_t>				failWriteOrdinal ;
	/// 人工class installer propertyです
	MtdFixtureProperty							classInstaller ;
	/// 人工class co-installer propertyです
	MtdFixtureProperty							classCoInstallers ;
	/// 人工device co-installer propertyです
	MtdFixtureProperty							deviceCoInstallers ;
} ;
// 同worker中だけ有効な所有file fixtureです
thread_local MtdFileFixture *activeMtdFiles = nullptr ;

//------------------------------------------------------------------------------
/**
 * @brief 一人工propertyの容量照会と本読取をWindows ABIで返します
 * @param[in] value 同fixtureの原状態です
 * @param[out] type 元property型です
 * @param[out] buffer 呼出し側の任意領域です
 * @param[in] capacity 出力容量です
 * @param[out] required 元byte数です
 * @return 原状態と容量に応じた低位応答です
 */
//------------------------------------------------------------------------------
BOOL mtdFixtureProperty( const MtdFixtureProperty &value, DEVPROPTYPE *type, PBYTE buffer,
						DWORD capacity, PDWORD required)
{
	// property型を返せない不正引数を拒否します
	if( !type) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// 人工propertyの元errorを返します
	if( value.error != ERROR_SUCCESS) {
		SetLastError( value.error) ;
		return FALSE ;
	}

	*type = value.type ;
	// 容量出力がある場合だけ原byte数を返します
	if( required) {
		*required = static_cast<DWORD>( value.bytes.size()) ;
	}

	// 本読取bufferの容量不足をWindows ABIで返します
	if( !buffer || capacity < value.bytes.size()) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	// 容量照会後に消えたpropertyを不在応答として注入します
	if( value.vanishAfterSizing) {
		SetLastError( ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	std::memcpy( buffer, value.bytes.data(), value.bytes.size()) ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同MTD classのinstaller又はco-installer propertyを返します
 * @param[in] classGuid 同fixtureの正式classです
 * @param[in] key 要求propertyです
 * @param[out] type 元property型です
 * @param[out] buffer 呼出し側の任意領域です
 * @param[in] capacity 出力容量です
 * @param[out] required 元byte数です
 * @param[in] flags setup class指定だけです
 * @return 原状態と容量に応じた低位応答です
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureClassProperty( const GUID *classGuid, const DEVPROPKEY *key, DEVPROPTYPE *type,
									PBYTE buffer, DWORD capacity, PDWORD required, DWORD flags)
{
	// 別class、未知key、flags差を完全fakeの外へ出しません
	if( !activeMtdFiles || !classGuid || !IsEqualGUID( *classGuid, MTD_CLASS) || !key ||
	   flags != DICLASSPROP_INSTALLER) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// 正式class property keyを型とIDで比較します
	const auto same = [&]( const DEVPROPKEY &expected) {
		return key->pid == expected.pid && IsEqualGUID( key->fmtid, expected.fmtid) ;
	} ;
	// class installerの人工propertyを返します
	if( same( DEVPKEY_DeviceClass_ClassInstaller)) {
		return mtdFixtureProperty( activeMtdFiles->classInstaller, type, buffer, capacity, required) ;
	}

	// class co-installerの人工propertyを返します
	if( same( DEVPKEY_DeviceClass_ClassCoInstallers)) {
		return mtdFixtureProperty( activeMtdFiles->classCoInstallers, type, buffer, capacity,
								  required) ;
	}

	SetLastError( ERROR_INVALID_REG_PROPERTY) ;
	return FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの所有rootとその読取専用祖先だけへfile openを制限します
 * @param[in] path 元完全pathです
 * @param[in] write 新規temp作成の場合trueです
 * @return 予定した所有範囲に限定される場合trueです
 */
//------------------------------------------------------------------------------
bool mtdFixturePath( std::wstring_view path, bool write)
{
	// 所有workspace外や親参照を含むpathを拒否します
	if( !activeMtdFiles || path.empty() || path.find( L"..") != path.npos) {
		return false ;
	}

	// 所有root内のpathかを判定します
	const auto within = [&]( std::wstring_view root) {
		return path.size() >= root.size() &&
			   CompareStringOrdinal( path.data(), static_cast<int>( root.size()), root.data(),
									static_cast<int>( root.size()), TRUE) == CSTR_EQUAL &&
			   (path.size() == root.size() || path[root.size()] == L'\\') ;
	} ;
	// 書込先を所有する人工System32配下へ限定します
	if( write) {
		return within( activeMtdFiles->windowsRoot + L"\\System32") ;
	}

	// 所有rootまでの親pathかを判定します
	const auto ancestor = [&]( std::wstring_view root) {
		return path.size() <= root.size() &&
			   CompareStringOrdinal( path.data(), static_cast<int>( path.size()), root.data(),
									static_cast<int>( path.size()), TRUE) == CSTR_EQUAL ;
	} ;
	return within( activeMtdFiles->windowsRoot) || within( activeMtdFiles->sourceRoot) ||
		   ancestor( activeMtdFiles->windowsRoot) || ancestor( activeMtdFiles->sourceRoot) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Windows pathだけを所有workspace上の別位置へ写像します
 * @param[in] path fake ABIで観測した元完全pathです
 * @return 所有workspaceへの実path又は元source pathです
 */
//------------------------------------------------------------------------------
std::wstring mtdFixturePhysical( std::wstring_view path)
{
	// 同workerの所有file fixture状態です
	const auto &state = *activeMtdFiles ;
	// 元package sourceを論理volume写像から除外する判定です
	const bool	originalSource =
		!state.sourceRoot.empty() && path.size() >= state.sourceRoot.size() &&
		CompareStringOrdinal( path.data(), static_cast<int>( state.sourceRoot.size()),
							 state.sourceRoot.c_str(), static_cast<int>( state.sourceRoot.size()),
							 TRUE) == CSTR_EQUAL &&
		(path.size() == state.sourceRoot.size() || path[state.sourceRoot.size()] == L'\\') ;
	// Windows表示pathだけを所有volumeへ写像し元sourceは維持します
	if( !originalSource && !state.logicalVolume.empty() &&
	   path.size() >= state.logicalVolume.size() &&
	   CompareStringOrdinal( path.data(), static_cast<int>( state.logicalVolume.size()),
							state.logicalVolume.c_str(),
							static_cast<int>( state.logicalVolume.size()), TRUE) == CSTR_EQUAL) {
		return state.physicalVolume +
			   (path.size() == state.logicalVolume.size()
					? L""
					: L"\\" + std::wstring{path.substr( state.logicalVolume.size())}) ;
	}

	return std::wstring{path} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 所有workspace内のfileだけを低位ABIで開きます
 * @param[in] path 検査対象の完全pathです
 * @param[in] access 元要求アクセスです
 * @param[in] share 元共有flagsです
 * @param[in] security 元security属性です
 * @param[in] creation 元作成modeです
 * @param[in] flags 元属性とopen flagsです
 * @param[in] templateFile 元templateです
 * @return 所有scopeのhandle又は拒否時INVALID_HANDLE_VALUEです
 */
//------------------------------------------------------------------------------
HANDLE WINAPI mtdFixtureCreate( LPCWSTR path, DWORD access, DWORD share,
							   LPSECURITY_ATTRIBUTES security, DWORD creation, DWORD flags,
							   HANDLE templateFile)
{
	// 要求アクセスがwriteまたはdeleteを含むかです
	const bool write = (access & (GENERIC_WRITE | DELETE)) != 0U ;
	// 所有外path、不正creation、未対応アクセスを拒否します
	if( !path || !mtdFixturePath( path, write) || (write && creation != CREATE_NEW) ||
	   (!write && creation != OPEN_EXISTING)) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return INVALID_HANDLE_VALUE ;
	}

	// 所有tempの作成失敗を指定したfixtureだけで注入します
	if( write && activeMtdFiles->scenario == MtdFixtureScenario::TEMP_CREATE_FAILURE) {
		SetLastError( ERROR_DISK_FULL) ;
		return INVALID_HANDLE_VALUE ;
	}

	// 所有volumeに写像した実pathです
	const auto physical = mtdFixturePhysical( path) ;
	// 所有workspaceで開いた実file handleです
	const auto handle =
		::CreateFileW( physical.c_str(), access, share, security, creation, flags, templateFile) ;
	// 開けた所有handleと元pathの対応を記録します
	if( handle != INVALID_HANDLE_VALUE) {
		activeMtdFiles->handles.emplace( handle, path) ;
	}

	return handle ;
}

//------------------------------------------------------------------------------
/**
 * @brief fakeが所有するhandleか確認します
 * @param[in] handle 同scopeに渡ったhandleです
 * @return 所有中だけtrueです
 */
//------------------------------------------------------------------------------
bool mtdFixtureHandle( HANDLE handle)
{
	// このfixtureが開いたhandleだけを認めます
	if( activeMtdFiles && activeMtdFiles->handles.contains( handle)) {
		return true ;
	}

	SetLastError( ERROR_INVALID_HANDLE) ;
	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 所有handleの通常属性を返します
 * @param[in] handle 同scopeのfileです
 * @param[out] info 元Windows情報です
 * @return 所有handleの読取結果です
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureInfo( HANDLE handle, LPBY_HANDLE_FILE_INFORMATION info)
{
	// 所有handle以外やWindows属性取得の失敗を通しません
	if( !mtdFixtureHandle( handle) || !::GetFileInformationByHandle( handle, info)) {
		return FALSE ;
	}

	// reparse負例を注入する人工targetです
	const auto	reparseTarget = activeMtdFiles->windowsRoot + L"\\System32\\fixture-a.dll" ;
	// 同handleを開いた元Windows pathです
	const auto &path = activeMtdFiles->handles.at( handle) ;
	// 対象handleが負例targetかの判定です
	const bool	isTarget =
		CompareStringOrdinal( path.c_str(), -1, reparseTarget.c_str(), -1, TRUE) == CSTR_EQUAL ;
	// reparse負例に使う人工System32親です
	const auto parent = activeMtdFiles->windowsRoot + L"\\System32" ;
	// 選択条件のtargetまたは親だけをreparse属性にします
	if( (activeMtdFiles->scenario == MtdFixtureScenario::REPARSE_TARGET && isTarget) ||
	   (activeMtdFiles->scenario == MtdFixtureScenario::REPARSE_PARENT &&
		CompareStringOrdinal( path.c_str(), -1, parent.c_str(), -1, TRUE) == CSTR_EQUAL)) {
		info->dwFileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT ;
	}

	// 選択したtargetだけ複数hardlinkの観測を注入します
	if( activeMtdFiles->scenario == MtdFixtureScenario::HARDLINK_TARGET && isTarget) {
		info->nNumberOfLinks = 2U ;
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 所有handleの型付き属性を返します
 * @param[in] handle 同scopeのfileです
 * @param[in] kind 元情報型です
 * @param[out] output 呼出し元領域です
 * @param[in] size 出力領域byte数です
 * @return 所有handleの読取結果です
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureInfoEx( HANDLE handle, FILE_INFO_BY_HANDLE_CLASS kind, LPVOID output,
							 DWORD size)
{
	return mtdFixtureHandle( handle) ? ::GetFileInformationByHandleEx( handle, kind, output, size)
									: FALSE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 所有handleの実pathを返します
 * @param[in] handle 同scopeのfileです
 * @param[out] output 呼出し元文字領域です
 * @param[in] capacity 文字容量です
 * @param[in] flags 元path flagsです
 * @return 所有handleのWindows返却値です
 */
//------------------------------------------------------------------------------
DWORD WINAPI mtdFixtureFinalPath( HANDLE handle, LPWSTR output, DWORD capacity, DWORD flags)
{
	// 所有していないhandleからpathを返しません
	if( !mtdFixtureHandle( handle)) {
		return 0U ;
	}

	// 実handleから返された最終path長です
	auto length = ::GetFinalPathNameByHandleW( handle, output, capacity, flags) ;
	// 所有volume内の実pathだけを人工Windows pathへ戻します
	if( !activeMtdFiles->logicalVolume.empty() && length > 0U && length < capacity) {
		// 実最終pathの借用viewです
		std::wstring_view actual{output, length} ;
		// 比較前にWindowsのDOS接頭辞を除きます
		if( actual.starts_with( L"\\\\?\\")) {
			actual.remove_prefix( 4U) ;
		}

		// 一意所有volumeの実pathです
		const auto &physical = activeMtdFiles->physicalVolume ;
		// 所有volumeの一致部分だけを論理volumeへ変換します
		if( actual.size() >= physical.size() &&
		   CompareStringOrdinal( actual.data(), static_cast<int>( physical.size()), physical.c_str(),
								static_cast<int>( physical.size()), TRUE) == CSTR_EQUAL &&
		   (actual.size() == physical.size() || actual[physical.size()] == L'\\')) {
			// 比較へ戻す論理Windows pathです
			std::wstring logical = L"\\\\?\\" + activeMtdFiles->logicalVolume ;
			// volume以下の相対部分を論理pathへ復元します
			if( actual.size() > physical.size()) {
				logical += actual.substr( physical.size() + 1U) ;
			}

			// 出力容量不足をWindows ABIで返します
			if( logical.size() + 1U > capacity) {
				return static_cast<DWORD>( logical.size() + 1U) ;
			}

			std::copy( logical.begin(), logical.end(), output) ;
			output[logical.size()] = L'\0' ;
			length				   = static_cast<DWORD>( logical.size()) ;
		}
	}

	// rename済みhandleに対応する元targetです
	const auto found = activeMtdFiles->renamed.find( handle) ;
	// 指定された負例でrename後のpath差を一回だけ注入します
	if( found != activeMtdFiles->renamed.end() && length > 0U && length < capacity &&
	   activeMtdFiles->scenario == MtdFixtureScenario::RENAME_VERIFY_FAILURE &&
	   !activeMtdFiles->pathFaultInjected && found->second.ends_with( L"\\fixture-a.dll")) {
		output[length - 1U]				  = L'x' ;
		activeMtdFiles->pathFaultInjected = true ;
	}

	// rename後の実handle pathと元targetを独立観測します
	if( found != activeMtdFiles->renamed.end() && length > 0U && length < capacity) {
		// rename後に実APIが返したpathです
		std::wstring_view observed{output, length} ;
		// 観測pathからDOS接頭辞を除いて比較します
		if( observed.starts_with( L"\\\\?\\")) {
			observed.remove_prefix( 4U) ;
		}

		// 観測pathと期待pathのordinal比較です
		const auto equals = [&]( std::wstring_view expected) {
			return observed.size() == expected.size() &&
				   CompareStringOrdinal( observed.data(), static_cast<int>( observed.size()),
										expected.data(), static_cast<int>( expected.size()),
										TRUE) == CSTR_EQUAL ;
		} ;
		std::cout << "MTD_RENAME_HANDLE_PATH target=" << equals( found->second)
				  << " previous=" << equals( activeMtdFiles->handles.at( handle)) << " targetExists="
				  << (::GetFileAttributesW( mtdFixturePhysical( found->second).c_str()) !=
					  INVALID_FILE_ATTRIBUTES)
				  << " observedLength=" << observed.size()
				  << " expectedLength=" << found->second.size() << '\n' ;
		// 最初に不一致となる文字位置です
		std::size_t difference{} ;
		// 最初に異なる位置まで比較を進めます
		while( difference < observed.size() && difference < found->second.size() &&
			  towlower( observed[difference]) == towlower( found->second[difference])) {
			++difference ;
		}

		std::cout << "MTD_RENAME_PATH_DIFF index=" << difference ;
		// 実際の差分付近だけを有限に出力します
		for( std::size_t offset = 0U; offset < 6U && difference + offset < observed.size();
			++offset) {
			std::cout << " got" << offset << '='
					  << static_cast<unsigned>( observed[difference + offset]) ;
		}

		// 期待pathの対応部分だけを有限に出力します
		for( std::size_t offset = 0U; offset < 6U && difference + offset < found->second.size();
			++offset) {
			std::cout << " want" << offset << '='
					  << static_cast<unsigned>( found->second[difference + offset]) ;
		}

		std::cout << '\n' ;
		// 観測pathのleaf区切りです
		const auto observedSlash = observed.find_last_of( L'\\') ;
		// 期待pathのleaf区切りです
		const auto expectedSlash = found->second.find_last_of( L'\\') ;
		std::wcout << L"MTD_RENAME_SYNTHETIC_LEAF observed="
				   << observed.substr( observedSlash == observed.npos ? 0U : observedSlash + 1U)
				   << L" expected="
				   << std::wstring_view{found->second}.substr(
						  expectedSlash == found->second.npos ? 0U : expectedSlash + 1U)
				   << L'\n' ;
	}

	return length ;
}
//------------------------------------------------------------------------------
/**
 * @brief 所有fixtureのtarget volumeだけの空き容量を照会します
 * @param[in] path 所有target directoryです
 * @param[out] available 呼出し主体へ利用可能なbyte数です
 * @param[out] total volume容量です
 * @param[out] freeBytes volume空きbyte数です
 * @return 所有target volumeのWindows返却値です
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureFreeSpace( LPCWSTR path, PULARGE_INTEGER available, PULARGE_INTEGER total,
								PULARGE_INTEGER freeBytes)
{
	// 所有領域以外の容量照会を拒否します
	if( !path || !mtdFixturePath( path, true)) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// 容量照会に使う所有pathです
	const auto physical = mtdFixturePhysical( path) ;
	return ::GetDiskFreeSpaceExW( physical.c_str(), available, total, freeBytes) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 保護principalを模した明示security descriptorを返します
 * @param[in] handle 同scopeのfileです
 * @param[in] kind 元object型です
 * @param[in] info 要求security情報です
 * @param[out] owner 生成descriptor内のownerです
 * @param[out] group 使用しないgroupです
 * @param[out] dacl 生成descriptor内のDACLです
 * @param[out] sacl 使用しないSACLです
 * @param[out] descriptor 呼出し元が解放するdescriptorです
 * @return 生成成功0、対象外又は生成失敗はWindows errorです
 */
//------------------------------------------------------------------------------
DWORD WINAPI mtdFixtureSecurity( HANDLE handle, SE_OBJECT_TYPE kind, SECURITY_INFORMATION info,
								PSID *owner, PSID *group, PACL *dacl, PACL *sacl,
								PSECURITY_DESCRIPTOR *descriptor)
{
	// 所有handleと要求したowner・DACL以外の照会を拒否します
	if( !mtdFixtureHandle( handle) || kind != SE_FILE_OBJECT || !owner || !dacl || !descriptor ||
	   info != (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)) {
		return ERROR_INVALID_PARAMETER ;
	}

	// 要求されたgroup出力だけを空にします
	if( group) {
		*group = nullptr ;
	}

	// 要求されたSACL出力だけを空にします
	if( sacl) {
		*sacl = nullptr ;
	}

	// security観測対象の元Windows pathです
	const auto &path = activeMtdFiles->handles.at( handle) ;
	// 不正DACL負例の対象かの判定です
	const bool	bad =
		!activeMtdFiles->badSecurityTarget.empty() &&
		CompareStringOrdinal( path.c_str(), -1, activeMtdFiles->badSecurityTarget.c_str(), -1,
							 TRUE) == CSTR_EQUAL ;
	// 不正owner負例に使う人工targetです
	const auto badOwnerTarget = activeMtdFiles->windowsRoot + L"\\System32\\fixture-a.dll" ;
	// 同targetへ不正ownerを注入する判定です
	const bool badOwner =
		activeMtdFiles->scenario == MtdFixtureScenario::BAD_OWNER &&
		CompareStringOrdinal( path.c_str(), -1, badOwnerTarget.c_str(), -1, TRUE) == CSTR_EQUAL ;
	// Windows pathの有限fakeだけで実観測した祖先ACLの形を再現します
	const auto &files = *activeMtdFiles ;
	// Windows pathの大文字小文字を区別せず同じ対象か照合します
	const auto	samePath = []( const std::wstring &left, const std::wstring &right) {
		 return CompareStringOrdinal( left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_EQUAL ;
	} ;
	// 通常の保護descriptorは祖先以外と単独fileの正例です
	std::wstring	   sddl = L"O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)" ;
	// 三親に共通する固定されたWindows保守主体です
	const std::wstring maintainer =
		L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" ;
	// 元hostと同じowner・group・保護DACL flagsです
	const std::wstring hostPrefix = L"O:" + maintainer + L"G:" + maintainer + L"D:PAI" ;
	// 写像対象のvolume rootだけを実観測に似せます
	if( !files.logicalVolume.empty() && samePath( path, files.logicalVolume)) {
		// 実観測のACE順・flags・権限を保ち、非公開SIDだけ既知の非信頼SIDへ写します
		sddl = hostPrefix + L"(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)"
							L"(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
							L"(A;;0x1000a1;;;AC)" ;
		// 禁止権の負例は同じ祖先に各権限を一つずつ加えます
		switch( files.scenario) {
			// 別主体による既存childの削除を拒否します
			case MtdFixtureScenario::ANCESTOR_DELETE_CHILD:
				sddl += L"(A;;0x00000040;;;AU)" ;
				break ;

			// 祖先自身の削除権を拒否します
			case MtdFixtureScenario::ANCESTOR_DELETE:
				sddl += L"(A;;0x00010000;;;AU)" ;
				break ;

			// 祖先のDACL変更権を拒否します
			case MtdFixtureScenario::ANCESTOR_WRITE_DAC:
				sddl += L"(A;;0x00040000;;;AU)" ;
				break ;

			// 祖先の所有者変更権を拒否します
			case MtdFixtureScenario::ANCESTOR_WRITE_OWNER:
				sddl += L"(A;;0x00080000;;;AU)" ;
				break ;

			// 祖先の新規file作成権を拒否します
			case MtdFixtureScenario::ANCESTOR_WRITE_FILE:
				sddl += L"(A;;0x00000002;;;AU)" ;
				break ;

			// 他条件は実観測に似た祖先だけを維持します
			default:
				break ;
		}
	}

	// WindowsとSystem32は原観測の既知SIDと全ACEで保護状態を再現します
	if( !files.logicalVolume.empty() &&
	   (samePath( path, files.windowsRoot) || samePath( path, files.windowsRoot + L"\\System32"))) {
		sddl = hostPrefix +
			   L"(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)"
			   L"(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)"
			   L"(A;;0x1200a9;;;BU)(A;CIIO;GA;;;" +
			   maintainer + L")(A;;FA;;;" + maintainer +
			   L")(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)"
			   L"(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)" ;
	}

	// volume rootから一つ下の実在childを個別に保護します
	const auto slash = files.windowsRoot.find( L'\\', 3U) ;
	// root直下の実在する最初のpathを示します
	const auto firstChild = files.windowsRoot.substr( 0U, slash) ;
	// 次childへの限定負例だけにdescriptor差を注入します
	if( !files.logicalVolume.empty() && samePath( path, firstChild)) {
		// 継承遮断のないchildは保護済みにしません
		if( files.scenario == MtdFixtureScenario::ANCESTOR_UNPROTECTED_CHILD) {
			sddl = L"O:BAG:BAD:(A;;FA;;;BA)(A;;FA;;;SY)" ;
		} else {
			// 保護付きでも非信頼の書込み権があれば拒否します
			if( files.scenario == MtdFixtureScenario::ANCESTOR_CHILD_WRITE) {
				sddl += L"(A;;0x00000002;;;AU)" ;
			}
		}
	}

	// 配置直親とStore source直親では同じ0x4も許しません
	if( (files.scenario == MtdFixtureScenario::DESTINATION_PARENT_ADD_DIRECTORY &&
		samePath( path, files.windowsRoot + L"\\System32")) ||
	   (files.scenario == MtdFixtureScenario::STORE_PARENT_ADD_DIRECTORY &&
		!files.storeDirectory.empty() && samePath( path, files.storeDirectory))) {
		sddl += L"(A;;0x00000004;;;AU)" ;
	}

	// 他のtarget負例は既存のownerとDACLを独立に偽装します
	if( badOwner) {
		sddl = L"O:WDG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)" ;
	} else {
		// 不正ownerと不正DACLは同時に注入しません
		if( bad) {
			sddl = L"O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;WD)" ;
		}
	}

	// 選択条件に応じた人工owner・DACLを作成できなければ元errorを返します
	if( !ConvertStringSecurityDescriptorToSecurityDescriptorW( sddl.c_str(), SDDL_REVISION_1,
															 descriptor, nullptr)) {
		return GetLastError() ;
	}

	// descriptorから返るdefaultとpresent flagsです
	BOOL defaulted{}, present{} ;
	// descriptorからownerとDACLを抽出できなければ所有bufferを解放します
	if( !GetSecurityDescriptorOwner( *descriptor, owner, &defaulted) ||
	   !GetSecurityDescriptorDacl( *descriptor, &present, dacl, &defaulted) || !present) {
		// descriptor抽出直後の元errorです
		const auto error = GetLastError() ;
		::LocalFree( *descriptor) ;
		*descriptor = nullptr ;
		return error ;
	}

	return ERROR_SUCCESS ;
}
//------------------------------------------------------------------------------
/**
 * @brief fakeが返したsecurity領域を解放します
 * @param[in] value 同fakeが所有した領域です
 * @return 元LocalFree結果です
 */
//------------------------------------------------------------------------------
HLOCAL WINAPI mtdFixtureFree( HLOCAL value)
{
	return ::LocalFree( value) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 所有handleから元byteを読みます
 * @param[in] handle 同scopeのfileです
 * @param[out] buffer 呼出し元領域です
 * @param[in] count 要求byte数です
 * @param[out] read 実読取byte数です
 * @param[in,out] overlap 元同期条件です
 * @return 所有handleのWindows読取結果です
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureRead( HANDLE handle, LPVOID buffer, DWORD count, LPDWORD read,
						   LPOVERLAPPED overlap)
{
	// 所有handle以外へのreadを拒否します
	if( !mtdFixtureHandle( handle)) {
		return FALSE ;
	}

	// read失敗を注入する人工DLL targetです
	const auto target = activeMtdFiles->windowsRoot + L"\\System32\\fixture-a.dll" ;
	// 指定した原DLLだけでread失敗を注入します
	if( activeMtdFiles->scenario == MtdFixtureScenario::READ_FAILURE &&
	   CompareStringOrdinal( activeMtdFiles->handles.at( handle).c_str(), -1, target.c_str(), -1,
							TRUE) == CSTR_EQUAL) {
		SetLastError( ERROR_READ_FAULT) ;
		return FALSE ;
	}

	return ::ReadFile( handle, buffer, count, read, overlap) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 所有temp handleだけへbyteを書きます
 * @param[in] handle 同scopeのfileです
 * @param[in] buffer 元byteです
 * @param[in] count 要求byte数です
 * @param[out] written 実書込byte数です
 * @param[in,out] overlap 元同期条件です
 * @return 所有tempのWindows書込結果です
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureWrite( HANDLE handle, LPCVOID buffer, DWORD count, LPDWORD written,
							LPOVERLAPPED overlap)
{
	// 所有範囲外へのwriteを拒否します
	if( !mtdFixtureHandle( handle) || !mtdFixturePath( activeMtdFiles->handles.at( handle), true)) {
		return FALSE ;
	}

	// 指定順のtemp writeだけを失敗させます
	if( activeMtdFiles->failWriteOrdinal &&
	   activeMtdFiles->writes++ == *activeMtdFiles->failWriteOrdinal) {
		SetLastError( ERROR_WRITE_FAULT) ;
		return FALSE ;
	}

	return ::WriteFile( handle, buffer, count, written, overlap) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 所有tempの書込みをflushします
 * @param[in] handle 同scopeのfileです
 * @return 所有tempのWindows返却値です
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureFlush( HANDLE handle)
{
	// 所有handle以外のflushを拒否します
	if( !mtdFixtureHandle( handle)) {
		return FALSE ;
	}

	// 選択条件だけでflush失敗を注入します
	if( activeMtdFiles->scenario == MtdFixtureScenario::FLUSH_FAILURE) {
		SetLastError( ERROR_WRITE_FAULT) ;
		return FALSE ;
	}

	// 所有handleの実flush結果です
	const auto flushed = ::FlushFileBuffers( handle) ;
	// 実際に成功した所有temp flushだけを数えます
	if( flushed) {
		++activeMtdFiles->flushes ;
	}

	return flushed ;
}
//------------------------------------------------------------------------------
/**
 * @brief 所有tempだけのrename又は削除指定を実行します
 * @param[in] handle 同scopeのfileです
 * @param[in] kind 元情報型です
 * @param[in] data 元情報です
 * @param[in] size 元情報byte数です
 * @return 所有tempへのWindows返却値です
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureSetInfo( HANDLE handle, FILE_INFO_BY_HANDLE_CLASS kind, LPVOID data,
							  DWORD size)
{
	// 所有外または未対応のfile情報変更を拒否します
	if( !mtdFixtureHandle( handle) || !mtdFixturePath( activeMtdFiles->handles.at( handle), true) ||
	   (kind != FileRenameInfo && kind != FileDispositionInfo)) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// rename情報は元Windows pathと所有先の対応を検証します
	if( kind == FileRenameInfo) {
		// 呼出し側から借用したrename構造です
		const auto info = static_cast<const FILE_RENAME_INFO *>( data) ;
		// FileNameまでの固定header byte数です
		const auto prefix = offsetof( FILE_RENAME_INFO, FileName) ;
		// 非置換・絶対target・文字数と終端の契約を検査します
		if( !info || size < prefix + sizeof( wchar_t) ||
		   info->FileNameLength % sizeof( wchar_t) != 0U ||
		   info->FileNameLength > size - prefix - sizeof( wchar_t) ||
		   info->FileName[info->FileNameLength / sizeof( wchar_t)] != L'\0' ||
		   info->ReplaceIfExists != FALSE || info->RootDirectory != nullptr ||
		   !mtdFixturePath(
			   std::wstring_view{info->FileName, info->FileNameLength / sizeof( wchar_t)}, true)) {
			SetLastError( ERROR_INVALID_PARAMETER) ;
			return FALSE ;
		}

		// 元rename構造のWindows target文字列です
		const std::wstring target{info->FileName, info->FileNameLength / sizeof( wchar_t)} ;
		// そのtargetを写像した所有pathです
		const auto		   physicalTarget = mtdFixturePhysical( target) ;
		// rename失敗の固定負例を注入します
		if( activeMtdFiles->scenario == MtdFixtureScenario::RENAME_FAILURE) {
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		// 指定された競合先だけをrename直前に一度作ります
		if( !activeMtdFiles->raceInjected && !activeMtdFiles->raceTarget.empty() &&
		   CompareStringOrdinal( target.c_str(), -1, activeMtdFiles->raceTarget.c_str(), -1, TRUE) ==
			   CSTR_EQUAL) {
			// 競合条件だけで所有workspaceに作る他者役handleです
			const HANDLE competitor =
				::CreateFileW( physicalTarget.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
							  CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr) ;
			// 競合fileを作れない場合は成功を合成しません
			if( competitor == INVALID_HANDLE_VALUE) {
				return FALSE ;
			}

			// 競合fileへの書込byte数です
			DWORD	   count{} ;
			// 競合byteの実write成否です
			const bool written = ::WriteFile( competitor, activeMtdFiles->raceBytes.data(),
											 static_cast<DWORD>( activeMtdFiles->raceBytes.size()),
											 &count, nullptr) != FALSE &&
								 count == activeMtdFiles->raceBytes.size() ;
			::CloseHandle( competitor) ;
			// 競合byteのwrite失敗を保持します
			if( !written) {
				SetLastError( ERROR_WRITE_FAULT) ;
				return FALSE ;
			}

			activeMtdFiles->raceInjected = true ;
		}

		// Windows表示targetを所有volumeへ変換してから実APIを呼びます
		if( physicalTarget != target) {
			// 写像後targetのUTF-16 byte数です
			const auto			   bytes = physicalTarget.size() * sizeof( wchar_t) ;
			// NULを含む写像済みrename構造bufferです
			std::vector<std::byte> converted( prefix + bytes + sizeof( wchar_t), std::byte{}) ;
			// 写像済みrename構造の借用viewです
			auto translated				= reinterpret_cast<FILE_RENAME_INFO *>( converted.data()) ;
			translated->ReplaceIfExists = FALSE ;
			translated->RootDirectory	= nullptr ;
			translated->FileNameLength	= static_cast<DWORD>( bytes) ;
			std::memcpy( translated->FileName, physicalTarget.data(), bytes) ;
			// 所有pathへ写像した実rename API結果です
			const BOOL result = ::SetFileInformationByHandle( handle, kind, translated,
															 static_cast<DWORD>( converted.size())) ;
			// rename成功時だけ元handleとWindows targetを対応付けます
			if( result) {
				activeMtdFiles->renamed[handle] = target ;
				++activeMtdFiles->successfulRenames ;
			}

			return result ;
		}
	}

	// 所有handleに対する実file情報変更結果です
	const BOOL result = ::SetFileInformationByHandle( handle, kind, data, size) ;
	// 未変換pathのrename成功も観測に保持します
	if( result && kind == FileRenameInfo && data && size >= sizeof( FILE_RENAME_INFO)) {
		// 成功したrenameの元構造です
		const auto info = static_cast<const FILE_RENAME_INFO *>( data) ;
		activeMtdFiles->renamed[handle] =
			std::wstring{info->FileName, info->FileNameLength / sizeof( wchar_t)} ;
		++activeMtdFiles->successfulRenames ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief fakeが開いたhandleだけを閉じます
 * @param[in] handle 同scopeの所有handleです
 * @return Windowsのclose結果です
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureClose( HANDLE handle)
{
	// 所有handle以外を閉じません
	if( !mtdFixtureHandle( handle)) {
		return FALSE ;
	}

	activeMtdFiles->handles.erase( handle) ;
	activeMtdFiles->renamed.erase( handle) ;
	return ::CloseHandle( handle) ;
}
/** @brief 対象付き候補の発行後に低位端末属性と登録時点の観測を切り替えます */
struct CatalogInstallFixture {
	/// 第一端末のHardwareIdsに返すNUL区切りのID列です。空なら元の属性です
	std::wstring_view hardwareIds ;
	/// 第一端末のCompatibleIdsへ返す単一IDです。空なら元の属性です
	std::wstring_view compatibleId ;
	/// 復元開始後かつ最初の登録前に、登録先のWindows rootを返した実回数です
	unsigned		  registrationRootReads{} ;
	/// 切り替えたHardwareIds全体を低位APIが返した回数です
	unsigned		  changedHardwareReads{} ;
	/// 元IDが移ったCompatibleIdsを低位APIが返した回数です
	unsigned		  changedCompatibleReads{} ;
	/// 人工配布物のHTTP送信回数です
	unsigned		  sends{} ;
	/// 一台目へ最初に返す元Hardware IDです。空なら既定の人工IDです
	std::wstring_view originalHardwareId ;
	/// trueの場合はID属性の変更を登録後から適用します
	bool			  changeIdsAfterStage{} ;
	/// trueの場合は復元APIを呼ばないServer経路でも元登録先の照会を計数します
	bool			  observeRegistrationOnServer{} ;
} ;
/** @brief 成功DTOでなく低位APIの状態だけを有限所有します */
struct NativeFixtureState {
	/// 対象付き候補の試験workerが停止するまで借用する低位入力と実測です
	CatalogInstallFixture				  *catalogInstall{} ;
	/// 同worker内だけの非所有元Providerです。同期fakeがproofを観測します
	DriverStoreProvider					  *bindingStore{} ;
	/// 元子scopeの成立と各別条件の拒否を表す非機密bitです
	std::uint32_t						   requiredChildProofChecks{} ;
	/// 元子scope内で観測できた回数です
	std::uint32_t						   requiredChildProofRuns{} ;
	/// 初回子観測の後だけ与える低位の変化です
	bool								   requiredChildEvidenceChanged{} ;
	/// 他所有entryの衝突を人工mapへ追加できた場合trueです
	bool								   requiredChildCollisionSeeded{} ;
	/// 衝突entryの同worker内確認回数です
	std::uint32_t						   requiredChildCollisionChecks{} ;
	/// 最後の確認で元entryが保持された場合trueです
	bool								   requiredChildCollisionPreserved{} ;
	/// storageのstage/import/指定APIの低位順序だけです
	std::vector<std::wstring>			   storageCalls ;
	/// 元人工INFの正式storage Classへだけ同じ完全API表を結びます
	bool								   storage{} ;
	/// 復旧開始後、配置前の登録guardが行ったWindows root照会です
	std::uint32_t						   declarativePreStageRootReads{} ;
	/// 同じOEM INFから保持対象の人工Storeを照会した回数です
	std::uint32_t						   declarativeStoreReads{} ;
	/// MTDの原Classだけを既storage条件から区別します
	bool								   mtd{} ;
	/// 架空配布が正式メディアチェンジャーの場合に有効
	bool								   mediumChanger{} ;
	/// 架空配布がIDEコントローラー用の正式HDCクラスの場合に有効
	bool								   hdc{} ;
	/// 同MTD操作の所有fileとqueue fakeです
	MtdFileFixture						   mtdFiles ;
	/// 同MTD操作の有限条件です
	MtdFixtureScenario					   mtdScenario{MtdFixtureScenario::BOTH_ABSENT} ;
	/// 人工二DLLの元byteです
	std::array<std::string, 2U>			   mtdDllBodies ;
	/// 人工SYSの元byteです
	std::string							   mtdSysBody ;
	/// 人工登録INFの元byteです
	std::string							   mtdInfBody ;
	/// 旧指定APIのfake呼出し数です
	std::uint32_t						   legacyInstalls{} ;
	/// UIが元READY終端を受け取った後だけ注入する観測差です
	std::atomic<bool>					   originalEvidenceChanged{} ;
	/// 同workerの実NativeLoader終了再確認済み結果です
	std::vector<InfDependencyNativeResult> originalEffects ;
	/// 同parserが読んだ原file hash/節名の私有集合です
	std::set<std::wstring>				   originalSections ;
	/// Windows側のCompatible IDへだけ返すopaque literalです。署名record/INF/結果DTOは変更しません
	std::wstring						   opaqueCompatibleId ;
	/// 第二端末のHardwareIdsに追加する人工IDです。空の場合は元の単一IDです
	std::wstring_view					   additionalSecondDeviceHardwareId ;
	/// 混在条件の明示fake WUA導入数です。通常OSのAPI呼出しを含みません
	std::uint32_t						   managedInstalls{} ;
	/// 新producerの三deviceだけに使う、認証record由来の公開identityです。空は元fixtureです
	std::vector<DistributionBindingDevice> distributionDevices ;
	/// 原三recordの完全INF tupleだけです
	std::vector<driver_package_signature_detail::OriginalInfMetadata> originalInfs ;
	/// 元Intel一件replayだけが実INF metadata読取と既存native署名adapterを使います
	bool															  originalIntelArchive{} ;
	/// 現在driver属性の照会失敗を初回導入へ補完させない有限条件です
	bool															  distributionCurrentUnknown{} ;
	/// fake復旧直前に同workerだけが呼ぶ有限同期です。空は通常の元fixtureを維持します
	std::function<void()>											  beforeRestore ;
	/// 同元登録Extensionへの変更権限probe回数です
	std::uint32_t													  registeredExtensionProbes{} ;
	/// Windowsの実共有規則で拒否されたprobe回数です
	std::uint32_t													  registeredExtensionBlocked{} ;
	/// 最後のprobeの元Windows診断です
	DWORD															  registeredExtensionError{} ;
	/// 同登録INFのprobe前後全byte一致を保持します
	bool										   registeredExtensionBytesUnchanged{true} ;
	/// 元ZIPの追加roleを持つ場合だけ親の指定API後のpropertyを変更します
	bool										   requiredRoles{} ;
	/// 元AddComponentへ結合する人工SWCを含む場合trueです
	bool										   componentChild{} ;
	/// 二つまでの必要SWC子の指定呼出し数です
	std::array<std::uint32_t, 2U>				   childInstalls{} ;
	/// 実Windows INFを使わない保護された登録rootの所有です
	OfficialDownloadWorkspace					   registration ;
	/// 完全root APIへ返す隔離Windows rootです。通常出力へ出しません
	std::wstring								   windowsRoot ;
	/// 固定低位状態の拒否または初回条件です
	SignedIndexBindingNativeCase				   nativeCase{SignedIndexBindingNativeCase::NORMAL} ;
	/// 公表後の原API状態だけを変更した場合trueです
	bool										   changed{} ;
	/// 二番目deviceを失敗させる既存部分条件です
	bool										   partialFailure{} ;
	/// INF検索で観測した元pathの有限集合です
	std::vector<std::wstring>					   sourceInfs ;
	/// 各deviceの指定導入が一度だけであることを観測します
	std::array<std::uint32_t, 4U>				   deviceInstalls{} ;
	/// 同IDbatchでは指定API成功後だけ当該deviceの現在属性を反映します
	bool										   reflectOwnInstall{} ;
	/// 新しい正常caseだけ再起動不要を明示します
	bool										   noReboot{} ;
	/// 直接Driver Storeの二target正例だけが互換新版nodeを発行します
	bool										   localDriverCandidates{} ;
	/// 指定APIへ到達した回数と分けた成功反映数です
	std::array<std::uint32_t, 4U>				   appliedDeviceInstalls{} ;
	/// 成功した元指定INFのbasenameだけを同deviceの現在propertyへ反映します
	std::array<std::wstring, 4U>				   appliedInfNames ;
	/// 原指定nodeの完全版/provider/dateだけを当該deviceへ反映します
	std::array<SP_DRVINFO_DATA_W, 4U>			   appliedNodes{} ;
	/// 全7caseは四つのmanaged意図を同scanへ限定します
	std::size_t									   originalManagedCount{1U} ;
	/// 完全表で位置を認定した後だけのpackage hash読取件数です
	std::size_t									   originalMappingHashReads{} ;
	/// 原七選択のmanaged四件だけを失敗させる固定負例です
	bool										   originalManagedFailure{} ;
	/// 第一成功後に第二の低位条件だけを変える事前固定入力です
	SignedIndexBindingBatchFault				   batchFault{SignedIndexBindingBatchFault::NONE} ;
	/// 原INFの実byte変更を一回だけに限定する印です
	bool										   batchContentChanged{} ;
	/// 一handleの検索条件です
	std::array<SP_DEVINSTALL_PARAMS_W, 32>		   parameters{} ;
	/// 生存handleです
	std::array<bool, 32>						   used{} ;
	/// 本体へ通常propertyとして返す現在版です
	std::wstring								   currentVersion{L"0.9.0.0"} ;
	/// 現在driverだけの発行元です。候補INFの発行元とは独立に固定します
	std::wstring								   currentProvider{L"Fixture Vendor"} ;
	/// 固定個別失敗または再起動条件です
	unsigned									   mode{} ;
	/// 一般NetまたはPortsの固定fixtureです
	bool										   network{} ;
	/// P4のnative隔離だけでlegacy dependency観測を完全client fakeへ固定します
	bool										   p4ExplicitClientContext{} ;
	/// 二つの独立recordに対応する人工present deviceを列挙する場合trueです
	bool										   multiple{} ;
	/// 復旧fakeの開始／終了回数です
	std::uint32_t								   restoreBegins{} ;
	/// 復旧fake終了の実回数です
	std::uint32_t								   restoreCompletes{} ;
	/// 復旧開始を元ERROR_ACCESS_DENIEDで拒否する場合trueです
	bool										   restoreFailure{} ;
	/// 偽stageを元ERROR_ACCESS_DENIEDで拒否し指定導入を止める場合trueです
	bool										   stagingFailure{} ;
	/// 最大二stageのexact INF pathを固定長bufferへ保持します。外部出力しません
	std::array<std::array<wchar_t, MAX_PATH>, 32U> stagedPaths{} ;
	/// 指定導入のpath/node/版/provider/flags一致を全callで確認した場合trueです
	bool										   specifiedBindingMatches{true} ;
	/// 実低位呼出し数です
	std::uint32_t								   opens{} ;
	/// 実低位解放数です
	std::uint32_t								   closes{} ;
	/// 実fake stage数です
	std::uint32_t								   stages{} ;
	/// 実fake指定install数です
	std::uint32_t								   installs{} ;
	/// 元Windows rank呼出しの実回数です
	std::uint32_t								   rankCalls{} ;
	/// 空pathとinstalled-only flagsを照合済みの現在node照会回数です
	std::uint32_t								   installedOnlyQueries{} ;
	/// 全present列挙開始だけを数え、指定device/node再確認を自動scanへ混ぜません
	std::uint32_t								   allPresentInventoryOpens{} ;
	/// 同閉包PACKAGE必要INFへの署名照会回数です
	std::uint32_t								   dependencyPackageObservations{} ;
	/// SYSTEM必要効果の全payload CAT照合回数です
	std::uint32_t								   dependencySystemEffectChecks{} ;
	/// SYSTEM必要INFをstageしようとした実低位call数です
	std::uint32_t								   dependencySystemStageCalls{} ;
	/// 完全低位表のOS version到達回数です
	std::uint32_t								   dependencyVersionCalls{} ;
	/// 依存INF署名到達回数です
	std::uint32_t								   dependencyInfCalls{} ;
	/// 依存CAT署名到達回数です
	std::uint32_t								   dependencyCatalogCalls{} ;
	/// 同完全表の隔離Windows起点照会回数です
	std::uint32_t								   dependencyWindowsDirectoryCalls{} ;
	/// 同完全表の対応Store独立照会回数です
	std::uint32_t								   dependencyDriverStoreCalls{} ;
	/// 元署名応答の有限終端と非空条件の実観測です
	bool										   dependencySignerResponsesValid{true} ;
	/// PACKAGE署名応答の四条件bitです。pathや署名本文を出力しません
	std::uint32_t								   dependencySignerMask{} ;
	/// 同元root INFへの署名観測順です。終端応答だけの拒否に使います
	std::uint32_t								   dependencyRootSignerCalls{} ;
} ;
thread_local NativeFixtureState *activeNative = nullptr ;	// 一workerの固定低位状態です

//------------------------------------------------------------------------------
/**
 * @brief 架空のストレージ配布に対応する端末クラスを返す
 * @return 現fixtureの正式クラスGUID
 * @pre このスレッドで架空Windows応答が有効
 */
//------------------------------------------------------------------------------
const GUID						&fixtureStorageClass() noexcept
{
	return activeNative->mtd			 ? MTD_CLASS
		   : activeNative->mediumChanger ? MEDIUM_CHANGER_CLASS
		   : activeNative->hdc			 ? HDC_CLASS
										 : STORAGE_CLASS ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同workerが独自クラスの元INFとWindows API表を使うか確認します
 * @return 独自クラスの有限ケースの場合trueです
 */
//------------------------------------------------------------------------------
bool declarativeCase() noexcept
{
	return activeNative &&
		   activeNative->nativeCase >= SignedIndexBindingNativeCase::DECLARATIVE_INITIAL &&
		   activeNative->nativeCase <= SignedIndexBindingNativeCase::DECLARATIVE_OTHER_DRIVER ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元INFの導入先クラスが登録されている時点か確認します
 * @return 既登録ケースまたは指定された配置後の変化ならtrueです
 */
//------------------------------------------------------------------------------
bool declarativeRegistered() noexcept
{
	return declarativeCase() &&
		   (activeNative->nativeCase == SignedIndexBindingNativeCase::DECLARATIVE_REGISTERED ||
			(activeNative->nativeCase ==
				 SignedIndexBindingNativeCase::DECLARATIVE_CLASS_AFTER_STAGE &&
			 activeNative->stages != 0U)) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 第一の実fake指定成功後だけ、指定した第二の低位faultを有効にします
 * @param[in] fault 事前固定した元低位条件です
 * @param[in] instance 今回照会した人工nodeです
 * @return 同workerの第一成功後かつ第二の一致したfaultだけtrueです
 */
//------------------------------------------------------------------------------
bool batchFaultApplies( const SignedIndexBindingBatchFault fault, const DEVINST instance) noexcept
{
	return activeNative && activeNative->reflectOwnInstall && instance == 2U &&
		   activeNative->appliedDeviceInstalls[0] != 0U && activeNative->batchFault == fault ;
}
//------------------------------------------------------------------------------
/**
 * @brief 隔離登録Extensionだけへの変更権限と元全byteを実file APIで確認します
 * @note 同workerのbase stageと指定API入口から同期使用し、実Windows INFへ触れません。書換条件は許可された場合に一byte追記し、DELETE条件は権限openだ
 *       けで終了します
 */
//------------------------------------------------------------------------------
void probeRegisteredExtension()
{
	// 固定した二条件以外にはfile変更の試行を追加しません
	if( !activeNative || (activeNative->nativeCase !=
							 SignedIndexBindingNativeCase::EXTENSION_REGISTERED_WRITE_PROBE &&
						 activeNative->nativeCase !=
							 SignedIndexBindingNativeCase::EXTENSION_REGISTERED_DELETE_PROBE)) {
		return ;
	}

	const auto	 path = activeNative->stagedPaths.front().data() ;		// 元隔離登録INFだけを借用します
	std::wstring before ;												// 変更権限open前の全byte hashです
	std::wstring after ;												// 変更権限open終端後の全byte hashです
	const bool	 beforeRead = computeFileSha256( path, before) == 0 ;	// 欠測を一致へ補完しません
	const bool	 write =
		activeNative->nativeCase ==
		SignedIndexBindingNativeCase::EXTENSION_REGISTERED_WRITE_PROBE ;	// 作用を固定します
	++activeNative->registeredExtensionProbes ;
	const HANDLE opened					   = CreateFileW( path, write ? GENERIC_WRITE : DELETE,
														 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
														 nullptr, OPEN_EXISTING, 0U,
														 nullptr) ;	// 同期probeの所有handleです
	activeNative->registeredExtensionError = opened == INVALID_HANDLE_VALUE ? GetLastError() : 0U ;
	// 拒否された変更権限だけをblockedへ数え、元診断を維持します
	if( opened == INVALID_HANDLE_VALUE) {
		++activeNative->registeredExtensionBlocked ;
	} else {
		const std::unique_ptr<void, decltype( &CloseHandle)> handle{opened,
																   &CloseHandle} ;	// 必ず解放します
		// 修正前の実書換可否を、成功DTOへ触れず元登録fileだけで再現します
		if( write) {
			DWORD	   written{} ;	// 意図した一byteの完了数です
			const char byte = ';' ;	// 元INF hashを必ず変える追記です
			const bool changed =
				SetFilePointer( handle.get(), 0L, nullptr, FILE_END) != INVALID_SET_FILE_POINTER &&
				WriteFile( handle.get(), &byte, 1U, &written, nullptr) &&
				// Windowsの実書込結果です
				written == 1U ;
			activeNative->registeredExtensionBytesUnchanged &= !changed ;
		}
	}

	activeNative->registeredExtensionBytesUnchanged &=
		beforeRead && computeFileSha256( path, after) == 0 && before == after ;
}
/** @brief 原payloadと完全低位署名/起動表だけを所有する人工状態です */
struct InstallerFixtureState {
	/// 原payloadの全実byte hashです
	std::wstring					hash ;
	/// Windows VERIFYへ渡された元保護pathです。外へ出しません
	std::wstring					path ;
	/// 事前固定した署名/publisher/起動拒否条件です
	SignedIndexBindingNativeCase	condition{} ;
	/// 非機密の原低位観測です
	SignedIndexInstallerObservation observation ;
	/// 元query/findへ返す人工certificateです
	CERT_CONTEXT					certificate{} ;
	/// 原processの終了codeです。driver導入済みではありません
	DWORD							exitCode{} ;
} ;
// 同workerだけが完全表へ結ぶ人工状態です
thread_local InstallerFixtureState *activeInstallerFixture{} ;
//------------------------------------------------------------------------------
/**
 * @brief 低位Windows境界でも実file全byteを元hashへ結合します
 * @param[in] path 元保護fileです
 * @return 全hash一致時trueです。実trustや起動を呼びません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool					installerBytes( const wchar_t *path)
{
	std::wstring hash ;	// 非公開の実検査値です
	return activeInstallerFixture && path && computeFileSha256( path, hash) == 0 &&
		   hash == activeInstallerFixture->hash ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原fileとWindows Authenticode policyの全設定を確認します
 * @param[in] parent nullのABI親です
 * @param[in] action Generic Verify V2です
 * @param[in,out] value 元WINTRUST_DATAです
 * @return 原正例0またはTRUST_E_BAD_DIGESTです。実trustを呼びません
 */
//------------------------------------------------------------------------------
LONG WINAPI installerVerify( HWND parent, GUID *action, LPVOID value)
{
	const GUID expected = WINTRUST_ACTION_GENERIC_VERIFY_V2 ;	// 製品と同policyです
	// 欠損・別policyを成功へ補完しません
	if( !activeInstallerFixture || parent || !action || !IsEqualGUID( *action, expected) || !value) {
		return TRUST_E_BAD_DIGEST ;
	}

	const auto &trust = *static_cast<WINTRUST_DATA *>( value) ;	// 同期ABIの同型値です
	// 元実byte・完全Windows policy・ABIの全条件の照合値です
	const bool	valid = trust.cbStruct == sizeof( trust) && trust.dwUIChoice == WTD_UI_NONE &&
					   trust.fdwRevocationChecks == WTD_REVOKE_WHOLECHAIN &&
					   trust.dwUnionChoice == WTD_CHOICE_FILE &&
					   trust.dwProvFlags == WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT &&
					   trust.pFile && installerBytes( trust.pFile->pcwszFilePath) &&
					   (trust.dwStateAction == WTD_STATEACTION_VERIFY ||
						trust.dwStateAction == WTD_STATEACTION_CLOSE) ;
	activeInstallerFixture->observation.valid &= valid ;
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( !valid || activeInstallerFixture->condition ==
					 SignedIndexBindingNativeCase::INSTALLER_SIGNATURE_FAILURE) {
		return TRUST_E_BAD_DIGEST ;
	}

	activeInstallerFixture->path = trust.pFile->pcwszFilePath ;
	return ERROR_SUCCESS ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同実fileのembedded signerだけを人工queryへ結合します
 * @param[in] objectType FILEです
 * @param[in] object 元完全pathです
 * @param[in] content PKCS7 embeddedです
 * @param[in] format BINARYです
 * @param[in] flags 0です
 * @param[out] encoding X509/PKCS7です
 * @param[out] type Embeddedです
 * @param[out] outputFormat BINARYです
 * @param[out] store 人工storeです
 * @param[out] message 人工messageです
 * @param[out] context nullだけです
 * @return 全byte/ABIが一致時TRUEです。実CryptQueryObjectは呼びません
 */
//------------------------------------------------------------------------------
BOOL WINAPI installerQuery( DWORD objectType, const void *object, DWORD content, DWORD format,
						   DWORD flags, DWORD *encoding, DWORD *type, DWORD *outputFormat,
						   HCERTSTORE *store, HCRYPTMSG *message, const void **context)
{
	// 別fileと不完全なqueryを拒否します
	if( !activeInstallerFixture || objectType != CERT_QUERY_OBJECT_FILE ||
	   !installerBytes( static_cast<const wchar_t *>( object)) ||
	   content != CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED ||
	   format != CERT_QUERY_FORMAT_FLAG_BINARY || flags || !encoding || !type || !outputFormat ||
	   !store || !message || context) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	*encoding	  = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING ;
	*type		  = CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED ;
	*outputFormat = CERT_QUERY_FORMAT_BINARY ;
	*store		  = activeInstallerFixture ;
	*message	  = activeInstallerFixture ;
	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同queryの原issuer/serialを二段階で返します
 * @param[in] message 元人工messageです
 * @param[in] type SIGNER_INFOです
 * @param[in] index 0です
 * @param[out] output Nullなら必要長です
 * @param[in,out] bytes 終端出力長です
 * @return 原ABI一致時TRUEです。実messageは使用しません
 */
//------------------------------------------------------------------------------
BOOL WINAPI installerMessage( HCRYPTMSG message, DWORD type, DWORD index, void *output, DWORD *bytes)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( !activeInstallerFixture || message != activeInstallerFixture ||
	   type != CMSG_SIGNER_INFO_PARAM || index || !bytes) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	// 元scopeだけで使用する有限な検査値です。未知を成功へ補完しません
	CMSG_SIGNER_INFO signer{} ;
	static BYTE		 identity = 1U ;	// 人工issuer/serialの固定byteです
	signer.Issuer			  = {1U, &identity} ;
	signer.SerialNumber		  = {1U, &identity} ;
	// 受信buffer未指定では必要長だけを返し、本文を発行しません
	if( !output) {
		*bytes = sizeof( signer) ;
		return TRUE ;
	}

	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( *bytes < sizeof( signer)) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::memcpy( output, &signer, sizeof( signer)) ;
	*bytes = sizeof( signer) ;
	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原issuer/serialへ人工certificateを一意に結合します
 * @param[in] store 元人工storeです
 * @param[in] encoding X509/PKCS7です
 * @param[in] flags 0です
 * @param[in] type SUBJECT_CERTです
 * @param[in] match 同issuer/serialのkeyです
 * @param[in] previous nullです
 * @return 人工certificateまたは空です。実storeへ触れません
 */
//------------------------------------------------------------------------------
PCCERT_CONTEXT WINAPI installerFind( HCERTSTORE store, DWORD encoding, DWORD flags, DWORD type,
									const void *match, PCCERT_CONTEXT previous)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( !activeInstallerFixture || store != activeInstallerFixture ||
	   encoding != (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING) || flags ||
	   type != CERT_FIND_SUBJECT_CERT || !match || previous) {
		SetLastError( ERROR_INVALID_DATA) ;
		return nullptr ;
	}

	const auto &key = *static_cast<const CERT_INFO *>( match) ;	// 同CAPI ABI keyです
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( key.Issuer.cbData != 1U || key.SerialNumber.cbData != 1U || !key.Issuer.pbData ||
	   !key.SerialNumber.pbData || key.Issuer.pbData[0] != 1U || key.SerialNumber.pbData[0] != 1U) {
		SetLastError( ERROR_INVALID_DATA) ;
		return nullptr ;
	}

	return &activeInstallerFixture->certificate ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原signer名を二段階で返し期待publisher差を保存します
 * @param[in] certificate 元人工certificateです
 * @param[in] type SIMPLE_DISPLAYです
 * @param[in] flags 0です
 * @param[in] parameters nullです
 * @param[out] output Nullなら必要長です
 * @param[in] capacity wchar_t上限です
 * @return 終端込み原名長です。実certificateを読みません
 */
//------------------------------------------------------------------------------
DWORD WINAPI installerName( PCCERT_CONTEXT certificate, DWORD type, DWORD flags, void *parameters,
						   LPWSTR output, DWORD capacity)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( !activeInstallerFixture || certificate != &activeInstallerFixture->certificate ||
	   type != CERT_NAME_SIMPLE_DISPLAY_TYPE || flags || parameters) {
		return 0U ;
	}

	// 原signer名です。期待publisherの差を正例へ置換しません
	const std::wstring name = activeInstallerFixture->condition ==
									  SignedIndexBindingNativeCase::INSTALLER_PUBLISHER_FAILURE
								  ? L"Wrong publisher"
								  : L"Synthetic publisher" ;
	// 終端または元集合の有限必要数です。成功数を推測しません
	const auto		   count = static_cast<DWORD>( name.size() + 1U) ;
	// 受信buffer未指定では必要長だけを返し、本文を発行しません
	if( !output) {
		return count ;
	}

	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( capacity < count) {
		return 0U ;
	}

	wcscpy_s( output, capacity, name.c_str()) ;
	return count ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原人工certificateだけを返却します
 * @param[in] certificate 元構造です
 * @return 元構造ならTRUEです。実certificateを解放しません
 */
//------------------------------------------------------------------------------
BOOL WINAPI installerFree( PCCERT_CONTEXT certificate)
{
	return activeInstallerFixture && certificate == &activeInstallerFixture->certificate ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原人工messageだけを返却します
 * @param[in] message 元構造です
 * @return 元構造ならTRUEです。実messageを解放しません
 */
//------------------------------------------------------------------------------
BOOL WINAPI installerCloseMessage( HCRYPTMSG message)
{
	return activeInstallerFixture && message == activeInstallerFixture ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原人工storeだけを返却します
 * @param[in] store 元構造です
 * @param[in] flags 0です
 * @return 元構造ならTRUEです。実storeを解放しません
 */
//------------------------------------------------------------------------------
BOOL WINAPI installerCloseStore( HCERTSTORE store, DWORD flags)
{
	return activeInstallerFixture && store == activeInstallerFixture && !flags ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原全byteとexact非silent commandだけを受理します
 * @param[in] application 原EXEまたは固定msiexecです
 * @param[in,out] command 引用済み元commandです
 * @param[in] processAttributes nullです
 * @param[in] threadAttributes nullです
 * @param[in] inherit FALSEです
 * @param[in] flags 0です
 * @param[in] environment nullです
 * @param[in] directory 固定System32です
 * @param[in] startup 非silent UI設定です
 * @param[out] handles 人工二handleです
 * @return 原正例TRUEまたは元ACCESS_DENIEDです。実processは作成しません
 */
//------------------------------------------------------------------------------
BOOL WINAPI installerCreate( LPCWSTR application, LPWSTR command,
							LPSECURITY_ATTRIBUTES processAttributes,
							LPSECURITY_ATTRIBUTES threadAttributes, BOOL inherit, DWORD flags,
							LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,
							LPPROCESS_INFORMATION handles)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( !activeInstallerFixture || !application || !command || !directory || !startup || !handles ||
	   !installerBytes( activeInstallerFixture->path.c_str())) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	// 固定Windows msiexecと原MSIだけに認める別方式です
	const bool msi = std::wstring_view{application} == L"C:\\Windows\\System32\\msiexec.exe" ;
	// 元保護pathだけを含むexact非silent command期待です
	const std::wstring expected = L"\"" + std::wstring{application} + L"\"" +
								  (msi ? L" /i \"" + activeInstallerFixture->path + L"\"" : L"") ;
	// 元実byte・完全Windows policy・ABIの全条件の照合値です
	const bool valid = !processAttributes && !threadAttributes && !inherit && !flags &&
					   !environment && std::wstring_view{directory} == L"C:\\Windows\\System32" &&
					   startup->cb == sizeof( *startup) && !startup->dwFlags &&
					   std::wstring_view{command} == expected &&
					   (msi || std::wstring_view{application} == activeInstallerFixture->path) ;
	activeInstallerFixture->observation.valid &= valid ;
	++activeInstallerFixture->observation.launches ;
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( !valid || activeInstallerFixture->condition ==
					 SignedIndexBindingNativeCase::INSTALLER_LAUNCH_FAILURE) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	handles->hProcess				 = activeInstallerFixture ;
	handles->hThread				 = &activeInstallerFixture->certificate ;
	activeInstallerFixture->exitCode = msi ? ERROR_SUCCESS_REBOOT_REQUIRED : ERROR_SUCCESS ;
	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 人工processの終端だけを返します
 * @param[in] process 元人工processです
 * @param[in] timeout INFINITEです
 * @return 原processならWAIT_OBJECT_0です。実待機は行いません
 */
//------------------------------------------------------------------------------
DWORD WINAPI installerWait( HANDLE process, DWORD timeout)
{
	return activeInstallerFixture && process == activeInstallerFixture && timeout == INFINITE
			   ? WAIT_OBJECT_0
			   : WAIT_FAILED ;
}
//------------------------------------------------------------------------------
/**
 * @brief 人工processの原終了codeだけを返します
 * @param[in] process 元人工processです
 * @param[out] code 原終了codeです
 * @return 原processならTRUEです。driver導入を合成しません
 */
//------------------------------------------------------------------------------
BOOL WINAPI installerExit( HANDLE process, LPDWORD code)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( !activeInstallerFixture || process != activeInstallerFixture || !code) {
		return FALSE ;
	}

	*code = activeInstallerFixture->exitCode ;
	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同起動の人工二handleだけを返却します
 * @param[in] handle 元processまたはthreadです
 * @return 原二handleならTRUEです。実handleを閉じません
 */
//------------------------------------------------------------------------------
BOOL WINAPI installerClose( HANDLE handle)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( !activeInstallerFixture ||
	   (handle != activeInstallerFixture && handle != &activeInstallerFixture->certificate)) {
		return FALSE ;
	}

	++activeInstallerFixture->observation.closes ;
	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 固定Windows標準directoryだけを返します
 * @param[out] output 終端付き受信です
 * @param[in] capacity wchar_t上限です
 * @return 原directoryの長さです。実systemへ触れません
 */
//------------------------------------------------------------------------------
UINT WINAPI installerSystemDirectory( LPWSTR output, UINT capacity)
{
	const std::wstring path = L"C:\\Windows\\System32" ;	// 実起動へ渡さない架空固定値です
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
	if( !output || capacity <= path.size()) {
		return 0U ;
	}

	wcscpy_s( output, capacity, path.c_str()) ;
	return static_cast<UINT>( path.size()) ;
}
//------------------------------------------------------------------------------
/**
 * @brief Class未確定初回の固定した追加低位条件か確認します
 * @return 新しいClass条件の有限範囲に属する場合trueです
 */
//------------------------------------------------------------------------------
bool unknownClassScenario() noexcept
{
	return activeNative &&
		   activeNative->nativeCase >= SignedIndexBindingNativeCase::INITIAL_CLASS_MISSING &&
		   activeNative->nativeCase <= SignedIndexBindingNativeCase::INITIAL_CLASS_AFTER_STAGE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元deviceのClassが既知へ変わった固定条件を判定します
 * @param[in] instance 同じ低位呼出し対象の人工nodeです。既存必要roleの既定値は第一親です
 * @return 原低位状態の変更条件が成立した場合だけtrueです
 */
//------------------------------------------------------------------------------
bool observedClassChanged( const DEVINST instance = 1U) noexcept
{
	return activeNative &&
		   ((activeNative->reflectOwnInstall && instance >= 1U &&
			 instance <= activeNative->deviceInstalls.size() &&
			 activeNative->appliedDeviceInstalls[instance - 1U] != 0U) ||
			(activeNative->requiredRoles && activeNative->deviceInstalls[0] != 0U) ||
			(activeNative->changed &&
			 (activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_CLASS_CHANGED ||
			  activeNative->nativeCase == SignedIndexBindingNativeCase::KNOWN_CLASS_MISMATCH ||
			  activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_DRIVER_ADDED)) ||
			(activeNative->stages != 0U &&
			 activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_CLASS_AFTER_STAGE)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同workerのnative現在状態が明示初回条件か確認します
 * @return 属性欠損とCode28を返す固定状態の場合trueです
 */
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
/**
 * @brief exact storage現serviceを持つ有限caseだけを識別します
 * @return 実SCMへfallbackしない原証拠fixtureならtrueです
 */
//------------------------------------------------------------------------------
bool storageServicePresent() noexcept
{
	return activeNative && activeNative->storage &&
		   (activeNative->nativeCase == SignedIndexBindingNativeCase::STORAGE_EXISTING_SERVICE ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::STORAGE_SHARED_INITIAL ||
			activeNative->nativeCase ==
				SignedIndexBindingNativeCase::STORAGE_SHARED_WRONG_SERVICE ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::STORAGE_SHARED_INCOMPATIBLE ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::STORAGE_SHARED_AMBIGUOUS ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::STORAGE_SERVICE_CHANGED ||
			activeNative->nativeCase ==
				SignedIndexBindingNativeCase::STORAGE_SERVICE_CHANGED_AFTER_STAGE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CMのexact service照会だけが返す第二adapterを識別します
 * @param[in] instance 完全低位表の元nodeです
 * @return 元shared serviceを既使用の第二adapterならtrueです
 */
//------------------------------------------------------------------------------
bool storageOwnerPeer( DEVINST instance) noexcept
{
	return storageServicePresent() && instance == 2U &&
		   activeNative->nativeCase >= SignedIndexBindingNativeCase::STORAGE_SHARED_INITIAL &&
		   activeNative->nativeCase <= SignedIndexBindingNativeCase::STORAGE_SHARED_AMBIGUOUS ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Windows低位条件だけから人工NO_DRIVER状態を決めます
 * @return 明示初回caseの未反映対象ならtrue、既知現在driver又は反映後ならfalseです
 * @note 版の空文字だけで初回を作らず、実端末や成功DTOを参照しません
 */
//------------------------------------------------------------------------------
bool initialState() noexcept
{
	return activeNative &&
		   ((declarativeCase() &&
			 activeNative->nativeCase != SignedIndexBindingNativeCase::DECLARATIVE_REGISTERED) ||
			(unknownClassScenario() &&
			 !(activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_DRIVER_ADDED &&
			   activeNative->changed)) ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL ||
			(storageServicePresent() &&
			 activeNative->nativeCase >= SignedIndexBindingNativeCase::STORAGE_SHARED_INITIAL &&
			 activeNative->nativeCase <= SignedIndexBindingNativeCase::STORAGE_SHARED_AMBIGUOUS) ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::CONTRADICTORY_NODE ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::DISAPPEARED ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::PROPERTY_FAILURE ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::MISSING_RANK ||
			(activeNative->nativeCase == SignedIndexBindingNativeCase::DRIVER_ADDED &&
			 !activeNative->changed)) ;
}
//------------------------------------------------------------------------------
/**
 * @brief Fake registrationの保護rootを一度だけ作ります。実OS登録先へ書込みません
 * @param[in,out] state 一workerの隔離所有です
 * @return 実fixture workspace生成が完了した場合trueです
 */
//------------------------------------------------------------------------------
bool initializeRegistration( NativeFixtureState &state)
{
	// 同workerへ重複したrootを作成しません
	if( !state.windowsRoot.empty()) {
		return true ;
	}

	HANDLE marker = INVALID_HANDLE_VALUE ;	// 隔離INF directoryの生成fileです
	// 既存rootを再利用せず本体と同じ保護workspaceへ固定します
	if( state.registration.initialize( L"index-stage-fixture", 1U) != 0U ||
	   state.registration.createFile( L"INF\\marker.tmp", marker) != 0U) {
		return false ;
	}

	CloseHandle( marker) ;
	const auto path = state.registration.path( L"INF\\marker.tmp") ;	// 同workspace所有pathです
	state.windowsRoot =
		path.substr( 0U, path.size() - std::wstring_view{L"\\INF\\marker.tmp"}.size()) ;
	return !state.windowsRoot.empty() ;
}
//------------------------------------------------------------------------------
/**
 * @brief 固定handleを有限indexへ戻します。WinAPI ABI境界だけのpointer表現です
 * @param[in] set Fake生成handleです
 * @return 有効なindex、または有限上限です
 */
//------------------------------------------------------------------------------
std::size_t setIndex( HDEVINFO set) noexcept
{
	const auto value = reinterpret_cast<std::uintptr_t>( set) ;	// 実pointerをdereferenceしません
	return value >= 0x100U && value < 0x120U ? static_cast<std::size_t>( value - 0x100U) : 32U ;
}
//------------------------------------------------------------------------------
/**
 * @brief Nativeへfallbackせず固定handleを生成します
 * @return 有限fake handleです
 */
//------------------------------------------------------------------------------
HDEVINFO createSet() noexcept
{
	// worker固定状態がなければnative handle生成へfallbackしません
	if( !activeNative) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return INVALID_HANDLE_VALUE ;
	}

	// 有限handle枠を順番に探し、試験resourceを上限内へ保ちます
	for( std::size_t i = 0U; i < activeNative->used.size(); ++i) {
		// 未使用の枠だけを生成し、同handleの二重所有を防ぎます
		if( !activeNative->used[i]) {
			activeNative->used[i]			   = true ;
			activeNative->parameters[i]		   = {} ;
			activeNative->parameters[i].cbSize = sizeof( SP_DEVINSTALL_PARAMS_W) ;
			++activeNative->opens ;
			return reinterpret_cast<HDEVINFO>(
				// SDK opaque handleです
				static_cast<std::uintptr_t>( 0x100U + i)) ;
		}
	}

	SetLastError( ERROR_TOO_MANY_OPEN_FILES) ;
	return INVALID_HANDLE_VALUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同workerのpresent全class列挙に限って有限fake handleを発行します
 * @param[in] classGuid ABIで借用するclass指定です。このfixtureは全classのflagsを検査します
 * @param[in] enumerator ABIで借用する列挙名です。実端末を列挙しません
 * @param[in] parent ABIで渡される親Windowです。画面を作成しません
 * @param[in] flags present全classの完全一致を要求する検索条件です
 * @return 有効なfake handle、条件不一致時はINVALID_HANDLE_VALUEと元errorです
 * @note activeNativeを同worker threadでだけ借用し、closeInventoryで解放します
 */
//------------------------------------------------------------------------------
HDEVINFO WINAPI openInventory( [[maybe_unused]] const GUID *classGuid,
							  [[maybe_unused]] PCWSTR enumerator, [[maybe_unused]] HWND parent,
							  DWORD flags)
{
	// 本体のpresent全class列挙条件と異なる入力を拒否します
	if( flags != (DIGCF_ALLCLASSES | DIGCF_PRESENT)) {
		SetLastError( ERROR_INVALID_FLAGS) ;
		return INVALID_HANDLE_VALUE ;
	}

	// 同workerの全present開始だけを数え、結果DTOや返却handleを変更しません
	if( activeNative != nullptr) {
		++activeNative->allPresentInventoryOpens ;
	}

	return createSet() ;
}
//------------------------------------------------------------------------------
/**
 * @brief 指定INF照合用の有限fake device集合を生成します
 * @param[in] classGuid ABIで借用するclass指定です。native集合は作成しません
 * @param[in] parent ABIで渡される親Windowです。画面を作成しません
 * @return 所有するfake handle、枠不足時はINVALID_HANDLE_VALUEと元errorです
 * @note 同workerのactiveNativeを借用し、closeInventoryで解放します
 */
//------------------------------------------------------------------------------
HDEVINFO WINAPI createInventory( [[maybe_unused]] const GUID *classGuid,
								[[maybe_unused]] HWND		 parent)
{
	return createSet() ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同workerで所有するfake handleを一度だけ解放します
 * @param[in] set createSetで生成したopaque handleです
 * @return 解放時TRUE、無効または二重解放時FALSEとERROR_INVALID_HANDLEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI closeInventory( HDEVINFO set)
{
	// Fake handleを参照する前に確認する有限slot位置
	const auto i = setIndex( set) ;
	// 無効または解放済みhandleの再解放を拒否します
	if( !activeNative || i == 32U || !activeNative->used[i]) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	activeNative->used[i] = false ;
	++activeNative->closes ;
	// 衝突後の各低位handle終端で、別所有entryが削除されていないか確認します
	if( activeNative->requiredChildCollisionSeeded && activeNative->bindingStore) {
		++activeNative->requiredChildCollisionChecks ;
		activeNative->requiredChildCollisionPreserved =
			RequiredChildBindingProbe::collisionIntact( *activeNative->bindingStore) ;
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 有限の人工deviceを列挙し、原Windows終端を返します
 * @param[in] set ABIの集合handleです。このfixtureはactiveNativeの固定集合を使います
 * @param[in] index 0から始まる人工device位置です
 * @param[in,out] device 非nullかつSDK cbSizeを持つ借用出力です。成功時だけnodeを設定します
 * @return 成功時TRUE、上限でERROR_NO_MORE_ITEMS、不正出力でERROR_INVALID_PARAMETERのFALSEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI enumInventory( [[maybe_unused]] HDEVINFO set, DWORD index, PSP_DEVINFO_DATA device)
{
	// 固定一または二人工device以降は正式な列挙終端を返します
	const auto parents =
		activeNative && !activeNative->distributionDevices.empty()
			? static_cast<unsigned>( activeNative->distributionDevices.size())
		: activeNative && activeNative->nativeCase ==
							  SignedIndexBindingNativeCase::INITIAL_SAME_ID_OTHER_INCOMPLETE
			? 3U
		: activeNative && activeNative->multiple ? 2U
												 : 1U ;	// 元親数です
	const bool children =
		activeNative && activeNative->componentChild && activeNative->installs != 0U &&
		activeNative->nativeCase !=
			SignedIndexBindingNativeCase::REQUIRED_CHILD_PENDING ;	// 生成待ちを分離します
	// 元base指定後・子列挙時だけ別所有identityを衝突させます
	if( children && index >= parents && activeNative->bindingStore &&
	   activeNative->nativeCase ==
		   SignedIndexBindingNativeCase::REQUIRED_CHILD_IDENTITY_COLLISION &&
	   !activeNative->requiredChildCollisionSeeded) {
		activeNative->requiredChildCollisionSeeded =
			RequiredChildBindingProbe::insertCollision( *activeNative->bindingStore) ;
	}

	// 親と実生成済みの必要子だけをpresent集合へ返します
	const auto childCount =	// 同ID/同親の曖昧負例だけは二つの実present fake子です
		children ? parents + (activeNative->nativeCase ==
									  SignedIndexBindingNativeCase::REQUIRED_CHILD_AMBIGUOUS
								  ? 1U
								  : 0U)
				 : 0U ;
	// 不在fixtureと親/実present子の完全な列挙終端を分けます
	if( !activeNative || index >= parents + childCount) {
		SetLastError( ERROR_NO_MORE_ITEMS) ;
		return FALSE ;
	}

	// 欠損deviceとSDK cbSize不一致を拒否します
	if( !device || device->cbSize != sizeof( SP_DEVINFO_DATA)) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	device->ClassGuid =
		unknownClassScenario() && !observedClassChanged( index + 1U)
			? (activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_CLASS_UNKNOWN
				   ? GUID_DEVCLASS_UNKNOWN
				   : GUID_NULL)
			: (activeNative->nativeCase == SignedIndexBindingNativeCase::KNOWN_CLASS_MISMATCH &&
					   activeNative->changed
				   ? NET_CLASS
			   : activeNative->storage ? fixtureStorageClass()
			   : activeNative->network ? NET_CLASS
									   : PORTS_CLASS) ;
	// 初回端末のUnknownと既登録クラスを互換一覧構築前の元情報にします
	if( declarativeCase()) {
		device->ClassGuid = initialState() ? GUID_DEVCLASS_UNKNOWN : DECLARATIVE_CLASS ;
	}

	// 親と必要SWCの役割を異なるnative Classで返します
	if( index >= parents) {
		device->ClassGuid = COMPONENT_CLASS ;
		device->DevInst	  = 3U + index - parents ;
	} else {
		device->DevInst =
			activeNative->nativeCase ==
						SignedIndexBindingNativeCase::INITIAL_SAME_ID_OTHER_INCOMPLETE &&
					index == 2U
				? 5U
				: index + 1U ;
	}

	// 原recordの人工device投影では列挙とpropertyに同じClassを返します
	if( activeNative->originalIntelArchive && index < activeNative->distributionDevices.size() &&
	   FAILED( IIDFromString( activeNative->distributionDevices[index].classGuid.c_str(),
							&device->ClassGuid))) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 固定人工instanceだけを同集合のdeviceへ解決します
 * @param[in] set 有限集合handleです
 * @param[in] instance 同期呼出し中借用する非null終端付き人工instanceです
 * @param[in] parent ABIの親Windowです。画面を作成しません
 * @param[in] flags 0だけを受理する開き方です
 * @param[in,out] device SDK cbSizeを持つ借用出力です。成功時だけnodeを設定します
 * @return 固定instance解決時TRUE、それ以外は元errorを持つFALSEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI openDevice( HDEVINFO set, PCWSTR instance, [[maybe_unused]] HWND parent, DWORD flags,
					   PSP_DEVINFO_DATA device)
{
	// exact service filterのpeerだけを開き、scanの全present列挙へ追加しません
	if( activeNative && instance && flags == 0U && storageOwnerPeer( 2U) &&
	   std::wstring_view{instance} == L"TESTBUS\\SYNTH_0002\\FIXTURE") {
		device->DevInst	  = 2U ;
		device->ClassGuid = STORAGE_CLASS ;
		return TRUE ;
	}

	// 新producerの公開IDから作る架空instanceだけを同じ列挙nodeへ解決します
	if( activeNative && !activeNative->distributionDevices.empty() && instance && flags == 0U) {
		// 固定三nodeの全元identityを検査し、未知instanceを先頭へ補完しません
		for( std::size_t index = 0U; index < activeNative->distributionDevices.size(); ++index) {
			// 完全一致した人工instanceだけへ元nodeを返します
			if( std::wstring_view{instance} ==
			   activeNative->distributionDevices[index].hardwareId + L"\\FIXTURE") {
				return enumInventory( set, static_cast<DWORD>( index), device) ;
			}
		}

		SetLastError( ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	// 元AddComponentの一意な人工子だけを完全tableで開きます
	if( activeNative && activeNative->componentChild && instance && flags == 0U &&
	   (std::wstring_view{instance} == L"SWC\\SYNTH_COMPONENT\\CHILD1" ||
		std::wstring_view{instance} == L"SWC\\SYNTH_COMPONENT\\CHILD2")) {
		device->ClassGuid = COMPONENT_CLASS ;
		device->DevInst	  = std::wstring_view{instance}.ends_with( L"CHILD2") ? 4U : 3U ;
		return TRUE ;
	}

	// 第三の不足nodeは第一/第二deviceへaliasしません
	if( activeNative &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_SAME_ID_OTHER_INCOMPLETE &&
	   instance && std::wstring_view{instance} == L"TESTBUS\\SYNTH_0003\\FIXTURE" && flags == 0U) {
		return enumInventory( set, 2U, device) ;
	}

	// 固定instanceとflagsが完全一致する呼出しだけを受理します
	if( !activeNative || !instance || flags != 0U ||
	   (std::wstring_view{instance} != L"TESTBUS\\SYNTH_0001\\FIXTURE" &&
		(!activeNative->multiple ||
		 std::wstring_view{instance} != L"TESTBUS\\SYNTH_0002\\FIXTURE"))) {
		std::cout << "Fixed openDevice rejected: flags " << flags << ", input length "
				  << (instance ? std::wcslen( instance) : 0U) << ", expected equality "
				  << (instance && std::wstring_view{instance} == L"TESTBUS\\SYNTH_0001\\FIXTURE")
				  << '\n' ;
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	return enumInventory(
		set, std::wstring_view{instance} == L"TESTBUS\\SYNTH_0002\\FIXTURE" ? 1U : 0U, device) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実端末IDを参照せず人工instanceの二段階照会を処理します
 * @param[in] set ABIの集合handleです。このfixtureは固定device位置を参照します
 * @param[in] device 同期中借用するdeviceです。nullは第一人工deviceを意味します
 * @param[out] buffer 終端込み出力先です。nullまたは不足時は書込みません
 * @param[in] capacity bufferのwchar_t要素数です
 * @param[out] required null可の必要要素数です。終端を含みます
 * @return 全値コピー時TRUE、buffer不足時FALSEとERROR_INSUFFICIENT_BUFFERです
 */
//------------------------------------------------------------------------------
BOOL WINAPI instanceId( [[maybe_unused]] HDEVINFO set, PSP_DEVINFO_DATA device, PWSTR buffer,
					   DWORD capacity, PDWORD required)
{
	// 原fixture不在で追加第三nodeの条件を参照せず、元診断で拒否します
	if( !activeNative) {
		SetLastError( ERROR_INVALID_STATE) ;
		return FALSE ;
	}

	// 実端末IDを参照しない人工instance。二段階照会で同じ値を返す
	const std::wstring dynamicValue =
		activeNative && !activeNative->distributionDevices.empty() && device &&
				device->DevInst > 0U && device->DevInst <= activeNative->distributionDevices.size()
			? activeNative->distributionDevices[device->DevInst - 1U].hardwareId + L"\\FIXTURE"
			: L"" ;	// 新三nodeだけの人工instanceです
	const std::wstring_view value =
		!dynamicValue.empty() ? std::wstring_view{dynamicValue}
		: device && device->DevInst == 5U &&
				activeNative->nativeCase ==
					SignedIndexBindingNativeCase::INITIAL_SAME_ID_OTHER_INCOMPLETE
			? L"TESTBUS\\SYNTH_0003\\FIXTURE"
		: device && device->DevInst >= 3U
			? (device->DevInst == 4U ? L"SWC\\SYNTH_COMPONENT\\CHILD2"
									 : L"SWC\\SYNTH_COMPONENT\\CHILD1")
		: device && device->DevInst == 2U
			? L"TESTBUS\\SYNTH_0002\\FIXTURE"
			: L"TESTBUS\\SYNTH_0001\\FIXTURE" ;	// 元deviceへ結ぶ人工instanceです
	// 固定人工instanceの終端を含むwchar_t要素数
	const auto length = static_cast<DWORD>( value.size() + 1U) ;
	// 必要長出力が指定された場合だけ終端込み長を返します
	if( required) {
		*required = length ;
	}

	// 二段階照会の不足bufferへ元Windows errorを返します
	if( !buffer || capacity < length) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::copy( value.begin(), value.end(), buffer) ;
	buffer[value.size()] = L'\0' ;
	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同人工状態のCode28または既知driver状態を返します
 * @param[out] status 非nullのnode状態出力です。成功時だけ更新します
 * @param[out] problem 非nullの問題code出力です。成功時だけ更新します
 * @param[in] instance ABIの人工nodeです。このfixtureは同workerの固定状態を使用します
 * @param[in] flags 0だけを受理する条件です
 * @return 成功時CR_SUCCESS、不正出力またはflags時CR_INVALID_FLAGです
 */
//------------------------------------------------------------------------------
CONFIGRET WINAPI nodeStatus( PULONG status, PULONG problem, [[maybe_unused]] DEVINST instance,
							ULONG flags)
{
	// 不完全なnode-status出力と未知flagsを拒否します
	if( !status || !problem || flags != 0U) {
		return CR_INVALID_FLAG ;
	}

	const bool initial =
		initialState() && !storageOwnerPeer( instance) &&
		(instance <= 2U || (activeNative && !activeNative->distributionDevices.empty())) &&
		!(activeNative && instance >= 1U && instance <= activeNative->deviceInstalls.size() &&
		  ((activeNative->requiredRoles && activeNative->deviceInstalls[instance - 1U] != 0U) ||
		   (activeNative->reflectOwnInstall &&
			activeNative->appliedDeviceInstalls[instance - 1U] != 0U))) ;	// 実fake API後だけです
	*status	 = initial ? DN_HAS_PROBLEM : DN_STARTED | DN_DRIVER_LOADED ;
	*problem = initial ? CM_PROB_FAILED_INSTALL : 0U ;
	// 第一自身だけの変化と異なり、第二自身の実問題変化は直前再検証へ残します
	if( batchFaultApplies( SignedIndexBindingBatchFault::SECOND_STATE_CHANGED, instance)) {
		*problem = CM_PROB_DISABLED ;
	}

	// 正常scanとbase指定後を分け、実fake API後の親startedだけを欠く負例です
	if( activeNative && instance <= 2U && activeNative->deviceInstalls[instance - 1U] != 0U &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_PARENT_NOT_STARTED) {
		*status = DN_DRIVER_LOADED ;
	}

	// Code28以外の問題を初回導入の証明へ流用しません
	if( activeNative && activeNative->changed &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_NOT_CODE28) {
		*problem = CM_PROB_DISABLED ;
	}

	return CR_SUCCESS ;
}
//------------------------------------------------------------------------------
/**
 * @brief property keyのGUIDと番号を完全比較します
 * @param[in] a 同期中借用する第一keyです
 * @param[in] b 同期中借用する第二keyです
 * @return 両要素が同じ場合trueです
 */
//------------------------------------------------------------------------------
bool sameKey( const DEVPROPKEY &a, const DEVPROPKEY &b) noexcept
{
	return a.pid == b.pid && IsEqualGUID( a.fmtid, b.fmtid) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 現在nodeと候補nodeの固定日付をWindows表現へ変換します
 * @param[in] candidate trueは候補日付、falseは現在日付を選びます
 * @return 固定SYSTEMTIMEから変換した所有FILETIMEです
 */
//------------------------------------------------------------------------------
FILETIME date( bool candidate) noexcept
{
	// 現在版と候補版へ返す固定UTC日付。実時計を参照しない
	SYSTEMTIME time{} ;
	time.wYear	= 2026 ;
	time.wMonth = 10 ;
	time.wDay	= candidate ? 11 : 1 ;
	// Windows表現へ変換した固定日付の所有出力
	FILETIME result{} ;
	SystemTimeToFileTime( &time, &result) ;
	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 固定人工propertyと明示NOT_FOUNDを型付きの二段階照会へ返します
 * @param[in] set ABIの集合handleです。このfixtureはactiveNativeの状態を使います
 * @param[in] device 同期中借用するdeviceです。nullは第一人工deviceを選びます
 * @param[in] key 非nullの要求property keyです
 * @param[out] type 非nullのWindows型出力です。対応propertyを照会した場合更新します
 * @param[out] buffer 借用byte出力です。nullまたは容量不足時は書込みません
 * @param[in] capacity bufferのbyte容量です
 * @param[out] required null可の必要byte数です。既知propertyでは不足時にも返します
 * @param[in] flags 0だけを受理します
 * @return 成功時TRUE、欠損・不正・不足時は保持したWindows errorを持つFALSEです
 * @note 同workerだけでactiveNativeを借用し、実Windows propertyへfallbackしません
 */
//------------------------------------------------------------------------------
BOOL WINAPI property( [[maybe_unused]] HDEVINFO set, PSP_DEVINFO_DATA device, const DEVPROPKEY *key,
					 DEVPROPTYPE *type, PBYTE buffer, DWORD capacity, PDWORD required, DWORD flags)
{
	// 固定状態・property・型出力・flagsの欠損を拒否します
	if( !activeNative || !key || !type || flags != 0U) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// device co-installerの人工propertyを返します
	if( activeMtdFiles && sameKey( *key, DEVPKEY_Device_DriverCoInstallers)) {
		return mtdFixtureProperty( activeMtdFiles->deviceCoInstallers, type, buffer, capacity,
								  required) ;
	}

	// stage後に変化したhardware属性の負例を注入します
	if( activeNative->mtdScenario == MtdFixtureScenario::HW_AFTER_STAGE && activeNative->stages &&
	   sameKey( *key, DEVPKEY_Device_DevType)) {
		*type = DEVPROP_TYPE_UINT32 ;
		// 要求された場合だけDWORD必要長を返します
		if( required) {
			*required = sizeof( std::uint32_t) ;
		}

		// hardware propertyの容量不足をWindows ABIで返します
		if( !buffer || capacity < sizeof( std::uint32_t)) {
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		// hardware属性負例で返す人工DWORDです
		const std::uint32_t value = 7U ;
		std::memcpy( buffer, &value, sizeof( value)) ;
		return TRUE ;
	}

	// 第一対象の成功後、完全rank監査の現在Class APIだけを元13で拒否します
	if( activeNative->changed &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::DIAG_CURRENT_PROPERTY &&
	   sameKey( *key, DEVPKEY_Device_Class)) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	// Classの元読取失敗と上限を正式不存在へ置換しません
	if( activeNative->changed &&
	   ((sameKey( *key, DEVPKEY_Device_Class) &&
		 activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_FAILURE) ||
		(sameKey( *key, DEVPKEY_Device_ClassGuid) &&
		 activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_GUID_FAILURE))) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// 固定property上限超過を元Windowsの必要量応答として返します
	if( activeNative->changed && sameKey( *key, DEVPKEY_Device_Class) &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_LIMIT) {
		*type = DEVPROP_TYPE_STRING ;
		// 元必要長出力を指定された場合だけ設定します
		if( required) {
			*required = 64U * 1024U + 2U ;
		}

		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	// Classの不存在を空や型不正から分離し、後段の完全表へ同じ値を返します
	if( unknownClassScenario() && !observedClassChanged( device ? device->DevInst : 0U) &&
	   (sameKey( *key, DEVPKEY_Device_Class) || sameKey( *key, DEVPKEY_Device_ClassGuid)) &&
	   activeNative->nativeCase != SignedIndexBindingNativeCase::INITIAL_CLASS_UNKNOWN &&
	   !(activeNative->changed &&
		 (activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_INVALID ||
		  activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_EMPTY ||
		  activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_CONTRADICTORY))) {
		SetLastError( ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	// 元property failureを現在欠損や初回合格へ変換しません
	if( sameKey( *key, DEVPKEY_Device_Driver) &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::PROPERTY_FAILURE &&
	   activeNative->changed) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// 初回の全現在属性は空文字でなく正式なNOT_FOUNDで返します
	const bool child = device && device->DevInst >= 3U && device->DevInst != 5U &&
					   // 元必要SWCです
					   activeNative->distributionDevices.empty() ;
	// 現在観測の照会失敗をCode28の完全不存在として扱わせません
	if( activeNative->distributionCurrentUnknown &&
	   (sameKey( *key, DEVPKEY_Device_Driver) || sameKey( *key, DEVPKEY_Device_DriverInfPath) ||
		sameKey( *key, DEVPKEY_Device_DriverVersion) || sameKey( *key, DEVPKEY_Device_DriverDate) ||
		sameKey( *key, DEVPKEY_Device_DriverProvider) ||
		sameKey( *key, DEVPKEY_Device_MatchingDeviceId))) {
		SetLastError( sameKey( *key, DEVPKEY_Device_Driver) ? ERROR_ACCESS_DENIED : ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	const bool updated =
		!child && device && device->DevInst >= 1U &&
		device->DevInst <= activeNative->deviceInstalls.size() &&
		((activeNative->requiredRoles &&
		  activeNative->deviceInstalls[device->DevInst - 1U] != 0U) ||
		 (activeNative->reflectOwnInstall &&
		  activeNative->appliedDeviceInstalls[device->DevInst - 1U] != 0U)) ;	// 親個別API後だけです
	// API後の現在版読取失敗を、未導入又は旧版の観測へ変換しません
	if( updated &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::STORAGE_POST_READ_FAILURE &&
	   sameKey( *key, DEVPKEY_Device_DriverVersion)) {
		SetLastError( ERROR_READ_FAULT) ;
		return FALSE ;
	}

	// 初回の不存在とquery失敗を維持し、親API後とSWC子へ初回欠損を流用しません
	if( (initialState() && !storageOwnerPeer( device ? device->DevInst : 0U) && !updated && !child &&
		((sameKey( *key, DEVPKEY_Device_Driver) &&
		  !(activeNative->changed &&
			activeNative->nativeCase ==
				SignedIndexBindingNativeCase::INITIAL_DRIVER_KEY_PRESENT)) ||
		 sameKey( *key, DEVPKEY_Device_DriverInfPath) ||
		 sameKey( *key, DEVPKEY_Device_DriverVersion) || sameKey( *key, DEVPKEY_Device_DriverDate) ||
		 sameKey( *key, DEVPKEY_Device_DriverProvider) ||
		 sameKey( *key, DEVPKEY_Device_MatchingDeviceId))) ||
	   (activeNative->nativeCase == SignedIndexBindingNativeCase::BLANK_CURRENT &&
		sameKey( *key, DEVPKEY_Device_DriverVersion)) ||
	   (initialState() &&
		(sameKey( *key, DEVPKEY_Device_FriendlyName) || sameKey( *key, DEVPKEY_Device_DeviceDesc)))) {
		SetLastError( ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	std::wstring text ;	// 固定ASCII人工値だけです
	const void	*data{} ;
	// 今回のpropertyが要求するbyte長
	DWORD		 bytes{} ;
	// 現在driver日付。同期memcpyまで借用する所有値
	FILETIME	 time = date( updated) ;
	// 同modeのNetまたはPortsの固定通常class
	GUID		 guid =
		unknownClassScenario() && !observedClassChanged( device ? device->DevInst : 0U)
					? (activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_CLASS_UNKNOWN
						   ? GUID_DEVCLASS_UNKNOWN
						   : GUID_NULL)
					: (activeNative->nativeCase == SignedIndexBindingNativeCase::KNOWN_CLASS_MISMATCH &&
					   activeNative->changed
						   ? NET_CLASS
					   : activeNative->storage ? fixtureStorageClass()
					   : activeNative->network ? NET_CLASS
											   : PORTS_CLASS) ;
	// 端末のクラスはステージングで生じた対象クラス登録とは独立に保持します
	if( declarativeCase()) {
		guid = initialState() ? GUID_DEVCLASS_UNKNOWN : DECLARATIVE_CLASS ;
	}

	// 原公開Classを人工present deviceへだけ投影します
	if( activeNative->originalIntelArchive && device && device->DevInst >= 1U &&
	   device->DevInst <= activeNative->distributionDevices.size()) {
		const auto &item =
			activeNative
				->distributionDevices[device->DevInst -
									  1U] ;	// この同期だけで保持する元値です。許可の代用にしません
		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( IIDFromString( item.classGuid.c_str(), &guid) !=
		   S_OK) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			SetLastError( ERROR_INVALID_DATA) ;
			return FALSE ;
		}

		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( updated) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			time = activeNative->appliedNodes[device->DevInst - 1U].DriverDate ;
		}
	}

	DEVPROP_BOOLEAN present =
		((updated &&
		  activeNative->nativeCase == SignedIndexBindingNativeCase::STORAGE_POST_ABSENT) ||
		 ((activeNative->nativeCase == SignedIndexBindingNativeCase::DISAPPEARED ||
		   activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_DISAPPEARED) &&
		  activeNative->changed))
			? DEVPROP_FALSE
			: DEVPROP_TRUE ;										// 型付きの原present属性です
	const auto			   *scoped = activeNative->catalogInstall ;	// 対象付き試験の元端末属性です
	const std::wstring_view hardware =
		scoped && device && device->DevInst == 1U && !scoped->originalHardwareId.empty()
			? scoped->originalHardwareId
		: !activeNative->distributionDevices.empty() && device && device->DevInst > 0U &&
				device->DevInst <= activeNative->distributionDevices.size()
			? std::wstring_view{activeNative->distributionDevices[device->DevInst - 1U].hardwareId}
		: activeNative->nativeCase == SignedIndexBindingNativeCase::DECLARATIVE_NULL_ROW
			? L"TESTBUS\\SYNTH_NULL"
		: storageOwnerPeer( device ? device->DevInst : 0U) ? L"TESTBUS\\SYNTH_0001"
		: child											  ? L"SWC\\SYNTH_COMPONENT"
		: activeNative->changed &&
				activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_PNP_CHANGED
			? L"TESTBUS\\SYNTH_CHANGED"
		: device && device->DevInst == 2U &&
				activeNative->nativeCase != SignedIndexBindingNativeCase::INDEX_NON_UNIQUE &&
				activeNative->nativeCase != SignedIndexBindingNativeCase::INITIAL_SAME_ID &&
				activeNative->nativeCase !=
					SignedIndexBindingNativeCase::INITIAL_SAME_ID_OTHER_INCOMPLETE
			? L"TESTBUS\\SYNTH_0002"
			: L"TESTBUS\\SYNTH_0001" ;	// 同deviceだけの人工公開IDです
	// ClassGUID要求はSDK GUID型と実byte長で返します
	// SoftwareComponentはbaseのClassへ偽装しません
	if( child) {
		guid = activeNative->requiredChildEvidenceChanged &&
					   activeNative->nativeCase ==
						   SignedIndexBindingNativeCase::REQUIRED_CHILD_CLASS_CHANGED
				   ? NET_CLASS
				   : COMPONENT_CLASS ;
	}

	// 元propertyごとに型と値を固定し、未照会属性を推測しません
	if( sameKey( *key, DEVPKEY_Device_IsPresent)) {
		*type = DEVPROP_TYPE_BOOLEAN ;
		data  = &present ;
		bytes = sizeof( present) ;
	}
	// 原driver keyは既知状態と初回状態を区別する実propertyです
	else if( sameKey( *key, DEVPKEY_Device_ClassGuid)) {
		*type = DEVPROP_TYPE_GUID ;
		data  = &guid ;
		bytes = sizeof( guid) ;
	}
	// 現在date要求はFILETIME型と実byte長で返します
	else if( sameKey( *key, DEVPKEY_Device_DriverDate)) {
		*type = DEVPROP_TYPE_FILETIME ;
		data  = &time ;
		bytes = sizeof( time) ;
	} else {
		*type = DEVPROP_TYPE_STRING ;
		// ID列はHardwareとCompatibleを重複させずMULTI_SZ型で返します
		if( sameKey( *key, DEVPKEY_Device_HardwareIds) ||
		   sameKey( *key, DEVPKEY_Device_CompatibleIds)) {
			// 他nodeの必要native属性失敗を元errorへ保持し、positive DTOを外部から生成しません
			if( device && sameKey( *key, DEVPKEY_Device_CompatibleIds) &&
			   ((activeNative->nativeCase == SignedIndexBindingNativeCase::INDEX_VERIFIED_PARTIAL &&
				 device->DevInst == 2U) ||
				(activeNative->nativeCase ==
					 SignedIndexBindingNativeCase::INITIAL_SAME_ID_OTHER_INCOMPLETE &&
				 device->DevInst == 5U))) {
				SetLastError( ERROR_ACCESS_DENIED) ;
				return FALSE ;
			}

			*type = DEVPROP_TYPE_STRING_LIST ;
			text  = sameKey( *key, DEVPKEY_Device_CompatibleIds)
						? (child && activeNative->requiredChildEvidenceChanged &&
								   activeNative->nativeCase ==
									   SignedIndexBindingNativeCase::REQUIRED_CHILD_ID_CHANGED
							   ? L"TESTBUS\\CHANGED_COMPAT"
						   : activeNative->nativeCase ==
								   SignedIndexBindingNativeCase::DECLARATIVE_NULL_ROW
							   ? L"TESTBUS\\UNUSED_COMPAT"
						   : !activeNative->opaqueCompatibleId.empty()
							   ? std::wstring_view{activeNative->opaqueCompatibleId}
							   : L"TESTBUS\\SYNTH_COMPAT")
						: hardware ;
			// 同一instanceの二つのID属性だけを候補発行後に変えます
			if( auto *catalog = activeNative->catalogInstall ;
			   catalog && device && device->DevInst == 1U) {
				const bool isHardware =
					// 照会された元属性です
					sameKey( *key, DEVPKEY_Device_HardwareIds) ;
				const auto replacement = isHardware ? catalog->hardwareIds
													: catalog->compatibleId ;	// この属性の試験値です
				// size queryと読取りで同じ型と値を返し、実際の読取りだけを数えます
				if( !replacement.empty() &&
				   (!catalog->changeIdsAfterStage || activeNative->stages != 0U)) {
					text = replacement ;
					// 型付きの全値を出力できた呼出しだけを変更後の観測に数えます
					if( buffer && capacity >= (text.size() + 2U) * sizeof( wchar_t)) {
						++(isHardware ? catalog->changedHardwareReads
									  : catalog->changedCompatibleReads) ;
					}
				}
			}

			// 同じPnPインスタンスのHardwareIdsに二つ目のIDを独立したMULTI_SZ要素として返します
			if( device && device->DevInst == 2U && sameKey( *key, DEVPKEY_Device_HardwareIds) &&
			   !activeNative->additionalSecondDeviceHardwareId.empty()) {
				text.push_back( L'\0') ;
				text.append( activeNative->additionalSecondDeviceHardwareId) ;
			}

			text.push_back( L'\0') ;
		}
		// 現在INF要求だけへ固定人工公開名を返します
		else if( sameKey( *key, DEVPKEY_Device_Driver)) {
			text = declarativeCase() ? L"{c054bd69-a76e-4caa-a915-e3ce9a285b62}\\0001"
									 : L"{4d36e978-e325-11ce-bfc1-08002be10318}\\0001" ;
		}
		// 現在INF要求だけへ固定公開名を返します
		else if( sameKey( *key, DEVPKEY_Device_DriverInfPath)) {
			text = updated && device->DevInst >= 1U &&
						   device->DevInst <= activeNative->appliedInfNames.size() &&
						   !activeNative->appliedInfNames[device->DevInst - 1U].empty()
					   ? activeNative->appliedInfNames[device->DevInst - 1U]
					   : L"oemfixture.inf" ;
		}
		// 現在版要求へ各試験modeの既知版を返します
		else if( sameKey( *key, DEVPKEY_Device_DriverVersion)) {
			text = updated ? L"1.0.0.0" : activeNative->currentVersion ;
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( updated &&
			   activeNative
				   ->originalIntelArchive) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				const auto version =
					activeNative->appliedNodes[device->DevInst - 1U]
						.DriverVersion ;	// この同期だけで保持する元値です。許可の代用にしません
				text = std::to_wstring( (version >> 48U) & 0xffffU) + L"." +
					   std::to_wstring( (version >> 32U) & 0xffffU) + L"." +
					   std::to_wstring( (version >> 16U) & 0xffffU) + L"." +
					   std::to_wstring( version & 0xffffU) ;
			}
		}
		// providerとmanufacturerの要求へ固定人工vendorを返します
		else if( sameKey( *key, DEVPKEY_Device_DriverProvider) ||
				sameKey( *key, DEVPKEY_Device_Manufacturer)) {
			text = sameKey( *key, DEVPKEY_Device_DriverProvider) && !updated
					   ? activeNative->currentProvider
					   : L"Fixture Vendor" ;
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( updated &&
			   activeNative
				   ->originalIntelArchive &&	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			   sameKey( *key, DEVPKEY_Device_DriverProvider)) {
				text = activeNative->appliedNodes[device->DevInst - 1U].ProviderName ;
			}
		}
		// Class要求へNetまたはPortsの固定classを返します
		else if( sameKey( *key, DEVPKEY_Device_Class)) {
			text =
				child				? L"SoftwareComponent"
				: declarativeCase() ? (initialState() ? L"Unknown" : DECLARATIVE_NAME)
				: activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_CLASS_UNKNOWN
					? L"Unknown"
				: activeNative->nativeCase == SignedIndexBindingNativeCase::KNOWN_CLASS_MISMATCH &&
						activeNative->changed
					? L"Net"
				: activeNative->mtd			  ? L"MTD"
				: activeNative->mediumChanger ? L"MediumChanger"
				: activeNative->hdc			  ? L"HDC"
				: activeNative->storage		  ? L"SCSIAdapter"
				: activeNative->network		  ? L"Net"
											  : L"Ports" ;
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( activeNative->originalIntelArchive && device &&
			   device->DevInst >=
				   1U &&	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			   device->DevInst <= activeNative->distributionDevices.size()) {
				text = activeNative->distributionDevices[device->DevInst - 1U].className ;
			}

			// 空文字と不正型を正式NOT_FOUNDから区別します
			if( activeNative->changed &&
			   activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_EMPTY) {
				text.clear() ;
			}

			// 同長の文字列bufferでも元typeをUINT32へ変更した拒否入力です
			if( activeNative->changed &&
			   activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_INVALID) {
				*type = DEVPROP_TYPE_UINT32 ;
			}
		}
		// matching ID要求へ人工Hardware IDを返します
		else if( sameKey( *key, DEVPKEY_Device_MatchingDeviceId)) {
			text = hardware ;
		}
		// enumerator要求へ人工bus名を返します
		else if( sameKey( *key, DEVPKEY_Device_EnumeratorName)) {
			text = L"TESTBUS" ;
		}
		// service要求へ固定人工service名を返します
		else if( sameKey( *key, DEVPKEY_Device_Service) && activeNative->storage) {
			// 明示NO_DRIVERのservice不存在を照会失敗と区別します
			if( initialState() && !storageOwnerPeer( device ? device->DevInst : 0U)) {
				SetLastError( ERROR_NOT_FOUND) ;
				return FALSE ;
			}

			text = storageServicePresent() || updated ? L"FixtureStorage" : L"FixtureOldStorage" ;
			// 名前衝突のpeerを正当な同service所有へ補完しません
			if( storageOwnerPeer( device ? device->DevInst : 0U) &&
			   activeNative->nativeCase ==
				   SignedIndexBindingNativeCase::STORAGE_SHARED_WRONG_SERVICE) {
				text = L"UnrelatedService" ;
			}
		}
		// 元SWC子の親だけを返し、別deviceへaliasしません
		else if( sameKey( *key, DEVPKEY_Device_Parent) && child) {
			text = activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_WRONG_PARENT
					   ? L"TESTBUS\\WRONG_PARENT\\FIXTURE"
				   : device->DevInst == 4U &&
						   activeNative->nativeCase !=
							   SignedIndexBindingNativeCase::REQUIRED_CHILD_AMBIGUOUS
					   ? L"TESTBUS\\SYNTH_0002\\FIXTURE"
					   : L"TESTBUS\\SYNTH_0001\\FIXTURE" ;
		}
		// 必要子の現在serviceは他属性の値を借用しません
		else if( sameKey( *key, DEVPKEY_Device_Service)) {
			text = L"fixture" ;
		}
		// device表示要求へprivacy安全な人工名を返します
		else if( sameKey( *key, DEVPKEY_Device_FriendlyName) ||
				sameKey( *key, DEVPKEY_Device_DeviceDesc)) {
			text = L"Fixture Device" ;
		} else {
			SetLastError( ERROR_NOT_FOUND) ;
			return FALSE ;
		}

		text.push_back( L'\0') ;
		data  = text.data() ;
		bytes = static_cast<DWORD>( text.size() * sizeof( wchar_t)) ;
	}

	// 必要byte長の出力先がある場合だけ値を返します
	if( required) {
		*required = bytes ;
	}

	// propertyの二段階照会へ元buffer不足を返します
	if( !buffer || capacity < bytes) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::memcpy( buffer, data, bytes) ;
	SetLastError( ERROR_SUCCESS) ;
	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同fake handleが所有する検索条件をコピーします
 * @param[in] set 有限fake handleです
 * @param[in] device ABIで借用するdeviceです。handle別の保存条件を正本にします
 * @param[out] params 非null出力です。成功時に保存条件全体を設定します
 * @return 成功時TRUE、不正handleまたは出力欠損時FALSEとERROR_INVALID_HANDLEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI getParameters( HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device,
						  PSP_DEVINSTALL_PARAMS_W params)
{
	// 全検索条件を所有するfake handleの有限slot位置
	const auto i = setIndex( set) ;
	// 無効handleまたは欠損条件出力を拒否します
	if( !activeNative || i == 32U || !params) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	*params = activeNative->parameters[i] ;
	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同handleの検索条件をSDK cbSize確認後だけ更新します
 * @param[in] set 有限fake handleです
 * @param[in] device ABIで借用するdeviceです。handle別の保存条件を正本にします
 * @param[in] params 同期中借用する非nullかつ正しいcbSizeの条件です
 * @return 成功時TRUE、不正入力時FALSEとERROR_INVALID_HANDLEで保存値を変更しません
 */
//------------------------------------------------------------------------------
BOOL WINAPI setParameters( HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device,
						  PSP_DEVINSTALL_PARAMS_W params)
{
	// 更新対象のfake検索条件の有限slot。失敗時は変更しない
	const auto i = setIndex( set) ;
	// 無効handleとSDK cbSize不一致の検索条件を拒否します
	if( !activeNative || i == 32U || !params || params->cbSize != sizeof( *params)) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	// 最終parameter復旧失敗の固定負例を注入します
	if( activeNative->mtdScenario == MtdFixtureScenario::PARAM_CLEANUP_FAILURE && activeMtdFiles &&
	   activeMtdFiles->installDifs != 0U && activeMtdFiles->hasSelected[i] &&
	   (params->Flags & DI_NOFILECOPY) == 0U) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	activeNative->parameters[i] = *params ;
	// 検証済みsource検索だけを同期中の保護byte差替え試験へ保持します
	if( params->DriverPath[0] != L'\0' &&
	   std::ranges::find( activeNative->sourceInfs, std::wstring( params->DriverPath)) ==
		   activeNative->sourceInfs.end()) {
		activeNative->sourceInfs.emplace_back( params->DriverPath) ;
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 固定現在版をWindows driver nodeの版数表現へ投影します
 * @return 同activeNativeの三つの既知現在版に対応する所有数値です
 * @pre 同workerのactiveNativeが設定済みです
 */
//------------------------------------------------------------------------------
std::uint64_t packedCurrent() noexcept
{
	return activeNative->currentVersion == L"0.9.0.0"	? 9ULL << 32U
		   : activeNative->currentVersion == L"2.0.0.0" ? 2ULL << 48U
														: 1ULL << 48U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原検索条件を照合しinstalled-onlyの完全照会回数を保持します
 * @param[in] set 有限fake handleです
 * @param[in] device ABIで借用するdeviceです。handle別の条件を検査します
 * @param[in] type SPDIT_COMPATDRIVERだけを受理します
 * @return 全条件成立時TRUE、不正typeまたは矛盾したinstalled-only条件時FALSEと元errorです
 * @pre 同workerのactiveNativeが設定済みです
 */
//------------------------------------------------------------------------------
BOOL WINAPI buildDrivers( HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device, DWORD type)
{
	const auto slot = setIndex( set) ;	// 元handleが所有する検索条件の有限位置です
	// 互換driver構築以外のtypeと無効handleを拒否します
	if( slot == 32U || type != SPDIT_COMPATDRIVER) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	const auto &parameters = activeNative->parameters[slot] ;	// 同handleへ設定された全条件です
	// Installed-only証拠はsingle-INF解除と空pathを満たした原callだけへ数えます
	if( (parameters.FlagsEx & DI_FLAGSEX_INSTALLEDDRIVER) != 0U) {
		// 矛盾する検索条件を空一覧の成功へ変換しません
		if( (parameters.Flags & DI_ENUMSINGLEINF) != 0U || parameters.DriverPath[0] != L'\0' ||
		   (parameters.FlagsEx & DI_FLAGSEX_ALLOWEXCLUDEDDRVS) == 0U) {
			SetLastError( ERROR_INVALID_PARAMETER) ;
			return FALSE ;
		}

		++activeNative->installedOnlyQueries ;
	}

	// 候補単一INFの一覧構築だけが返却ClassGUIDを更新します。元propertyは変更しません
	if( parameters.DriverPath[0] != L'\0' && device) {
		device->ClassGuid =
			activeNative->nativeCase == SignedIndexBindingNativeCase::NATIVE_CLASS_MISMATCH
				? NET_CLASS
			: declarativeCase()		? DECLARATIVE_CLASS
			: activeNative->storage ? fixtureStorageClass()
			: activeNative->network ? NET_CLASS
									: PORTS_CLASS ;
		// 必要roleのnative Classは同実INF byteから返します
		if( activeNative->requiredRoles || activeNative->originalIntelArchive) {
			std::array<wchar_t, 128U> name{} ;		// 有限返却名です
			DWORD					  required{} ;	// NUL込み必要数です
			// 役割別実INF未確認では成功nodeを生成しません
			if( !infClass( parameters.DriverPath, &device->ClassGuid, name.data(),
						 static_cast<DWORD>( name.size()), &required)) {
				return FALSE ;
			}
		}
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同じ元INFをSetupAPIで読み、fake Windows nodeのmetadataへ結びます
 * @param[in] path 同保護workspaceの選択INFです
 * @param[out] driver 同じ原DriverVer/Providerから作る人工nodeです
 * @return 全directive読取成功true、失敗falseです
 * @note 適用性とrankだけがfakeです。metadataは固定成功値へ置換しません
 */
//------------------------------------------------------------------------------
bool readDistributionDriverNode( const wchar_t *path, SP_DRVINFO_DATA_W &driver)
{
	const auto raw = SetupOpenInfFileW( path, nullptr, INF_STYLE_WIN4,
									   nullptr) ;	// 同元INFのread-only handleです
	// 読めなかった元INFから人工metadataを発行しません
	if( raw == INVALID_HANDLE_VALUE) {
		return false ;
	}

	const std::unique_ptr<void, decltype( &SetupCloseInfFile)> inf{
		raw, &SetupCloseInfFile} ;			// 例外時も閉じます
	std::array<wchar_t, 256U> version{} ;	// 四要素版の有限bufferです
	std::array<wchar_t, 256U> dateText{} ;	// 原日付の有限bufferです
	INFCONTEXT				  line{} ;		// Version節だけの同期cursorです
	// ProviderのStrings展開と同一DriverVerの二fieldをWindowsに読ませます
	if( !SetupFindFirstLineW( inf.get(), L"Version", L"Provider", &line) ||
	   !SetupGetStringFieldW( &line, 1U, driver.ProviderName, LINE_LEN, nullptr) ||
	   !SetupFindFirstLineW( inf.get(), L"Version", L"DriverVer", &line) ||
	   !SetupGetStringFieldW( &line, 1U, dateText.data(), static_cast<DWORD>( dateText.size()),
							 nullptr) ||
	   !SetupGetStringFieldW( &line, 2U, version.data(), static_cast<DWORD>( version.size()),
							 nullptr)) {
		return false ;
	}

	std::array<unsigned, 4U> parts{} ;		// 元版の四つの16bit要素です
	SYSTEMTIME				 day{} ;		// 元日付のWindows変換入力です
	unsigned				 month{} ;		// sscanf境界でだけ所有する原月です
	unsigned				 dateDay{} ;	// 同じ原日です
	unsigned				 year{} ;		// 同じ原年です
	// 不正な日付/版を固定成功metadataへ補完しません
	if( swscanf_s( version.data(), L"%u.%u.%u.%u", &parts[0], &parts[1], &parts[2], &parts[3]) != 4 ||
	   std::ranges::any_of( parts, []( const auto value) { return value > 65535U ; }) ||
	   swscanf_s( dateText.data(), L"%u/%u/%u", &month, &dateDay, &year) != 3 || year > 65535U ||
	   month > 12U || dateDay > 31U) {
		return false ;
	}

	day.wYear			 = static_cast<WORD>( year) ;
	day.wMonth			 = static_cast<WORD>( month) ;
	day.wDay			 = static_cast<WORD>( dateDay) ;
	driver.DriverVersion = (static_cast<std::uint64_t>( parts[0]) << 48U) |
						   (static_cast<std::uint64_t>( parts[1]) << 32U) |
						   (static_cast<std::uint64_t>( parts[2]) << 16U) | parts[3] ;
	return SystemTimeToFileTime( &day, &driver.DriverDate) != FALSE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原INF検索と現在検索を区別し固定nodeまたは明示的空終端を返します
 * @param[in] set 保存検索条件を持つ有限fake handleです
 * @param[in] device ABIで借用するdeviceです。handle別の固定nodeを使用します
 * @param[in] type SPDIT_COMPATDRIVERだけを受理します
 * @param[in] index 通常は0だけ、rank試験は固定二件/三件/512件を返す有限位置です
 * @param[in,out] driver 非nullかつSDK cbSizeを持つ借用出力です。成功時だけnodeを設定します
 * @return 成功時TRUE、非適用・空終端・原観測失敗時FALSEとそのWindows errorです
 */
//------------------------------------------------------------------------------
BOOL WINAPI enumDrivers( HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device, DWORD type,
						DWORD index, PSP_DRVINFO_DATA_W driver)
{
	// 互換列挙type・driver出力・SDK cbSizeを厳密に照合します
	if( type != SPDIT_COMPATDRIVER || !driver || driver->cbSize != sizeof( *driver)) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// 互換nodeを発行する同検索条件の有限位置
	const auto i = setIndex( set) ;
	// 所有していない検索handleを拒否します
	if( !activeNative || i == 32U) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	// 指定INF検索なら候補node、空なら現在driver nodeを返す区分
	const bool candidate = activeNative->parameters[i].DriverPath[0] != L'\0' ;
	const bool rankCase =
		candidate && activeNative->nativeCase >= SignedIndexBindingNativeCase::RANK_BEST_FIRST &&
		activeNative->nativeCase <=
			SignedIndexBindingNativeCase::RANK_STAGE_TIED ;	// 原低位rank条件です
	const bool batchTied = candidate && device &&
						   batchFaultApplies( SignedIndexBindingBatchFault::SECOND_RANK_TIED,
											 device->DevInst) ;	// 第二の実同点です
	const bool batchUnknown = candidate && device &&
							  batchFaultApplies( SignedIndexBindingBatchFault::SECOND_RANK_UNKNOWN,
												device->DevInst) ;	// 第二の正式空終端です
	const DWORD count =
		candidate && storageOwnerPeer( device ? device->DevInst : 0U) &&
				activeNative->nativeCase ==
					SignedIndexBindingNativeCase::STORAGE_SHARED_INCOMPATIBLE
			? 0U
		: candidate && storageOwnerPeer( device ? device->DevInst : 0U) &&
				activeNative->nativeCase == SignedIndexBindingNativeCase::STORAGE_SHARED_AMBIGUOUS
			? 2U
		: batchUnknown																	   ? 0U
		: batchTied																		   ? 2U
		: !rankCase																		   ? 1U
		: activeNative->nativeCase == SignedIndexBindingNativeCase::RANK_NO_CANDIDATE	   ? 0U
		: activeNative->nativeCase == SignedIndexBindingNativeCase::RANK_ENUMERATION_LIMIT ? 512U
		: activeNative->nativeCase == SignedIndexBindingNativeCase::RANK_TIE_THEN_BETTER
			? 3U
			: 2U ;	// candidate以外の現在nodeは一件のままです
	// 固定件数の後に元の正常終端または明示した途中障害を返します
	if( index >= count) {
		SetLastError( rankCase && activeNative->nativeCase ==
									 SignedIndexBindingNativeCase::RANK_ENUMERATION_ERROR
						 ? ERROR_IO_DEVICE
						 : ERROR_NO_MORE_ITEMS) ;
		return FALSE ;
	}

	const bool updated =
		device && device->DevInst >= 1U && device->DevInst <= activeNative->deviceInstalls.size() &&
		((activeNative->requiredRoles &&
		  activeNative->deviceInstalls[device->DevInst - 1U] != 0U) ||
		 (activeNative->reflectOwnInstall &&
		  activeNative->appliedDeviceInstalls[device->DevInst - 1U] != 0U)) ;	// 親個別指定API後です
	// 正式空終端と原installed-only列挙失敗を別入力へ保持します
	if( !candidate && activeNative->changed &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_ENUMERATION_FAILURE) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// 明示初回はinstalled-only構築の完全な空終端を必要とします
	if( !candidate && !updated &&
	   (!device || device->DevInst <= 2U || !activeNative->distributionDevices.empty()) &&
	   initialState() && !storageOwnerPeer( device ? device->DevInst : 0U) &&
	   activeNative->nativeCase != SignedIndexBindingNativeCase::CONTRADICTORY_NODE &&
	   !(activeNative->changed &&
		 activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_INSTALLED_NODE)) {
		SetLastError( ERROR_NO_MORE_ITEMS) ;
		return FALSE ;
	}

	// 非適用と観測失敗は別の元Windows結果へ保ちます
	if( candidate && activeNative->parameters[i].DriverPath[0] != L'\0') {
		const std::wstring path =
			activeNative->parameters[i].DriverPath ;				// このhandleへ指定された原INFです
		const bool alternate = path.ends_with( L"alternate.inf") ;	// 元第二INFだけの条件です
		// 選択外importの実元IDはpresent親/必要子に適合しません
		if( path.ends_with( L"importonly.inf")) {
			SetLastError( ERROR_NO_MORE_ITEMS) ;
			return FALSE ;
		}

		// 元source INFの全非適用だけをinstalled/current検索と区別します
		if( activeNative->nativeCase == SignedIndexBindingNativeCase::MULTI_ALL_NONAPPLICABLE &&
		   (path.ends_with( L"\\fixture.inf") || path.ends_with( L"\\alternate.inf"))) {
			SetLastError( ERROR_NO_MORE_ITEMS) ;
			return FALSE ;
		}

		// 第二INFの非適用と観測失敗を別の元diagnosticで返します
		if( alternate &&
		   (activeNative->nativeCase == SignedIndexBindingNativeCase::MULTI_NONAPPLICABLE ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::MULTI_UNKNOWN)) {
			SetLastError( activeNative->nativeCase ==
								 SignedIndexBindingNativeCase::MULTI_NONAPPLICABLE
							 ? ERROR_NO_MORE_ITEMS
							 : ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}
	}

	const bool localCandidate = activeNative->localDriverCandidates &&
								(activeNative->parameters[i].FlagsEx &
								 DI_FLAGSEX_INSTALLEDDRIVER) == 0U ;	// 現在属性と互換新版を分けます
	driver->DriverVersion = candidate || updated || localCandidate ? 1ULL << 48U : packedCurrent() ;
	// 登録nodeが元指定nodeと変わった条件だけを原APIへ返します
	if( candidate && activeNative->stages != 0U &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::STAGE_WRONG_NODE &&
	   std::wstring_view{activeNative->parameters[i].DriverPath}.starts_with(
		   activeNative->windowsRoot)) {
		driver->DriverVersion = 2ULL << 48U ;
	}

	driver->DriverDate = date( candidate || updated || localCandidate) ;
	wcscpy_s( driver->ProviderName, candidate || updated || localCandidate
									   ? L"Fixture Vendor"
									   : activeNative->currentProvider.c_str()) ;
	wcscpy_s( driver->MfgName, L"Fixture Vendor") ;
	wcscpy_s( driver->Description, L"Fixture Device") ;
	driver->Reserved = rankCase ? static_cast<ULONG_PTR>( index) + 1U : 1U ;
	// 元tupleの一要素だけが異なる低rank nodeを同じ列挙へ混ぜます
	if( rankCase && index == 1U) {
		// Provider完全一致をrankの良さで補完しません
		if( activeNative->nativeCase == SignedIndexBindingNativeCase::RANK_OTHER_PROVIDER) {
			wcscpy_s( driver->ProviderName, L"Other Fixture Vendor") ;
		}

		// Packed版完全一致を表示版から推測しません
		if( activeNative->nativeCase == SignedIndexBindingNativeCase::RANK_OTHER_VERSION) {
			driver->DriverVersion = 2ULL << 48U ;
		}

		// 暦日が異なるnodeは低rankでも元候補へ含めません
		if( activeNative->nativeCase == SignedIndexBindingNativeCase::RANK_OTHER_DATE) {
			driver->DriverDate = date( false) ;
		}
	}

	// 原三recordの事後current nodeも当該指定nodeだけから反映します
	if( !candidate && updated && activeNative->originalIntelArchive && device) {
		*driver = activeNative->appliedNodes[device->DevInst - 1U] ;
	}

	// 新三deviceの適合fakeは元認証INF名へ限定し、node metadataは実本文から読みます
	if( candidate && !activeNative->distributionDevices.empty()) {
		// 別INF/device組を適用可能なnodeとして返しません
		std::wstring originalHash ;
		bool		 stagedOriginal{} ;	// この同期/fixtureが所有する資源又は原状態です
		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( device &&
		   device->DevInst >= 1U &&	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
		   device->DevInst <= activeNative->distributionDevices.size() &&
		   activeNative->originalIntelArchive && !activeNative->originalInfs.empty()) {
			const auto name =	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
				std::filesystem::path{
					activeNative->distributionDevices[device->DevInst - 1U].infIdentity}
					.filename()
					.wstring() ;
			const auto expected =	// 固定契約から作る独立した正負の期待です
				std::ranges::find( activeNative->originalInfs, name,
								  &driver_package_signature_detail::OriginalInfMetadata::infName) ;
			stagedOriginal =
				expected != activeNative->originalInfs.end() &&
				computeFileSha256( activeNative->parameters[i].DriverPath, originalHash) == 0U &&
				originalHash == expected->infSha256 ;
		}

		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( !device ||
		   device->DevInst == 0U ||	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
		   device->DevInst > activeNative->distributionDevices.size() ||
		   (!stagedOriginal &&
			std::filesystem::path{activeNative->parameters[i].DriverPath}.filename().native() !=
				std::filesystem::path{
					activeNative->distributionDevices[device->DevInst - 1U].infIdentity}
					.filename()
					.native())) {
			SetLastError( ERROR_NO_MORE_ITEMS) ;
			return FALSE ;
		}

		return readDistributionDriverNode( activeNative->parameters[i].DriverPath, *driver) ? TRUE
																						   : FALSE ;
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同検索handleの元INFと固定sectionをdetailへ返します
 * @param[in] set 保存検索条件を持つ有限fake handleです
 * @param[in] device ABIで借用するdeviceです。同元deviceの基本名選択を返します
 * @param[in] driver ABIで借用するnodeです。固定detailを返しnativeを呼びません
 * @param[in,out] detail 借用出力です。nullまたは不足時は書込みません。固定C44はstatic field後FALSEです
 * @param[in] capacity detailのbyte容量です
 * @param[out] required null可の必要byte数です。不足時にも返します
 * @return 完全detail成功TRUE、容量不足/無効handle/固定C44の可変部分不足はFALSEと元診断です
 */
//------------------------------------------------------------------------------
BOOL WINAPI driverDetail( HDEVINFO set, PSP_DEVINFO_DATA device, PSP_DRVINFO_DATA_W driver,
						 PSP_DRVINFO_DETAIL_DATA_W detail, DWORD capacity, PDWORD required)
{
	const auto i	 = setIndex( set) ;	// この呼出しで選択した検索パラメーター
	const bool model = declarativeCase() && i < 32U &&
					   activeNative->parameters[i].DriverPath[0] ;	// 元行を持つ単一INFの照会
	const bool nullRow =
		model && activeNative->nativeCase ==
					 SignedIndexBindingNativeCase::DECLARATIVE_NULL_ROW ;	// 無作用の元行
	const bool reorder =
		model &&
		activeNative->nativeCase == SignedIndexBindingNativeCase::DECLARATIVE_ROW_AFTER_STAGE &&
		std::wstring_view{activeNative->parameters[i].DriverPath} ==
			activeNative->stagedPaths[0].data() ;	// 登録先nodeだけの順序差
	constexpr wchar_t kernelIds[] =
		L"TESTBUS\\SYNTH_0001\0TESTBUS\\SYNTH_COMPAT\0TESTBUS\\SYNTH_FALLBACK\0" ;	// 元行の二重終端
	constexpr wchar_t reorderedIds[] =
		L"TESTBUS\\SYNTH_0001\0TESTBUS\\SYNTH_FALLBACK\0TESTBUS\\SYNTH_COMPAT\0" ;	// 同じ文字数とID集合
	constexpr wchar_t nullIds[] = L"TESTBUS\\SYNTH_NULL" ;							// 互換IDなしの一行
	const auto		  ids		= nullRow	? std::span<const wchar_t>{nullIds}
								  : reorder ? std::span<const wchar_t>{reorderedIds}
											: std::span<const wchar_t>{kernelIds} ;	// APIで返す全可変領域
	const DWORD		  bytes =
		  model
				  ? static_cast<DWORD>( offsetof( SP_DRVINFO_DETAIL_DATA_W, HardwareID) + ids.size_bytes())
				  : sizeof( SP_DRVINFO_DETAIL_DATA_W) ;	// 二段階の両方で返す元byte長
	// 必要detail byte長の出力先がある場合だけ値を返します
	if( required) {
		*required = bytes ;
	}

	// detail二段階照会の不足bufferを元errorで返します
	if( !detail || capacity < bytes) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	// 無効handleへ人工INF detailを返しません
	if( !activeNative || i == 32U) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	// 元二段階照会の本体APIだけへ、第一対象成功後の固定失敗を与えます
	if( activeNative->changed && activeNative->parameters[i].DriverPath[0] &&
	   (activeNative->nativeCase == SignedIndexBindingNativeCase::DIAG_DETAIL_API ||
		activeNative->nativeCase == SignedIndexBindingNativeCase::DIAG_DETAIL_ZERO)) {
		SetLastError( activeNative->nativeCase == SignedIndexBindingNativeCase::DIAG_DETAIL_ZERO
						 ? ERROR_SUCCESS
						 : ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	wcscpy_s( detail->InfFileName, activeNative->parameters[i].DriverPath[0]
									  ? activeNative->parameters[i].DriverPath
									  : L"oemfixture.inf") ;
	wcscpy_s( detail->SectionName, L"Install") ;
	// 型の違う元Hardware IDと互換IDをWindowsの長さ・位置・二重終端で返します
	if( model) {
		detail->CompatIDsOffset = static_cast<DWORD>( std::wcslen( ids.data()) + 1U) ;
		detail->CompatIDsLength = static_cast<DWORD>( ids.size()) - detail->CompatIDsOffset ;
		std::memcpy( reinterpret_cast<std::byte *>( detail) +
						offsetof( SP_DRVINFO_DETAIL_DATA_W, HardwareID),
					ids.data(), ids.size_bytes()) ;
		wcscpy_s( detail->SectionName, nullRow ? L"NoDriver" : L"Install") ;
	}

	// 子の元観測後だけ異なるnode節を返し、同tupleへ補完させません
	if( device && device->DevInst >= 3U && activeNative->requiredChildEvidenceChanged &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_CHILD_NODE_CHANGED &&
	   activeNative->parameters[i].DriverPath[0]) {
		wcscpy_s( detail->SectionName, L"InstallChanged") ;
	}

	// 元Intelの人工nodeは同保護INFの元Models行から実install節を読みます
	if( activeNative->originalIntelArchive && activeNative->parameters[i].DriverPath[0] != L'\0') {
		// 別nodeを原公開tupleへ補完しません
		if( !device || device->DevInst == 0U ||
		   device->DevInst > activeNative->distributionDevices.size()) {
			SetLastError( ERROR_INVALID_DATA) ;
			return FALSE ;
		}

		const auto &original =
			activeNative->distributionDevices[device->DevInst - 1U] ;	// 元fake IDです
		const auto raw = SetupOpenInfFileW( activeNative->parameters[i].DriverPath, nullptr,
										   INF_STYLE_WIN4, nullptr) ;	// 同owned INFです
		// 元INF読取に失敗した場合は節を人工成功値へ補完しません
		if( raw == INVALID_HANDLE_VALUE) {
			return FALSE ;
		}

		const std::unique_ptr<void, decltype( &SetupCloseInfFile)> inf{
			raw, &SetupCloseInfFile} ;	// 元HINFのownerです
		INFCONTEXT line{} ;				// 同Modelsの同期cursorです
		bool	   found{} ;			// 原Hardware IDに一致した一行だけを採用します
		// 同原Models節だけを有限に走査し、他節のIDへ切り替えません
		for( LONG index = 0; index < SetupGetLineCountW( inf.get(), original.modelSection.c_str());
			++index) {
			std::array<wchar_t, 512U> id{} ;	// 一行の元Hardware IDです
			// 元Windows readerが返した全IDを人工nodeの明示IDへ比較します
			if( SetupGetLineByIndexW( inf.get(), original.modelSection.c_str(),
									static_cast<DWORD>( index), &line) &&
			   SetupGetStringFieldW( &line, 2U, id.data(), static_cast<DWORD>( id.size()), nullptr) &&
			   original.hardwareId == id.data()) {
				found = SetupGetStringFieldW( &line, 1U, detail->SectionName, LINE_LEN, nullptr) !=
						FALSE ;
				break ;
			}
		}

		// 元節を読めない人工適合nodeは拒否します
		if( !found) {
			SetLastError( ERROR_INVALID_DATA) ;
			return FALSE ;
		}
	}

	const bool candidate =
		activeNative->parameters[i].DriverPath[0] != L'\0' ;	// 元単一INF照会だけです
	// 後続nodeのdetail失敗は先行成功で上書きしません
	if( candidate && driver && driver->Reserved == 2U &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::RANK_LATE_DETAIL_ERROR) {
		SetLastError( ERROR_READ_FAULT) ;
		return FALSE ;
	}

	// 同basenameでも別完全pathの低rank nodeは元候補へ混ぜません
	if( candidate && driver && driver->Reserved == 2U &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::RANK_OTHER_INF) {
		wcscpy_s( detail->InfFileName, L"D:\\fictional-other-root\\fixture.inf") ;
	}

	// 現在driverのdetailを選択節の拒否入力で置き換えません
	if( candidate) {
		const auto condition = activeNative->nativeCase ;	// 原低位detail条件です
		// 元nodeの空基本名を解析成功へ補完させません
		if( condition == SignedIndexBindingNativeCase::SECTION_EMPTY) {
			detail->SectionName[0] = L'\0' ;
		}

		// 元nodeの不正な節文法を渡します
		if( condition == SignedIndexBindingNativeCase::SECTION_INVALID) {
			wcscpy_s( detail->SectionName, L"Bad/Section") ;
		}

		// 同Modelsにはあるが実節を欠くfallback基本名です
		if( condition == SignedIndexBindingNativeCase::SECTION_MISSING_FALLBACK) {
			wcscpy_s( detail->SectionName, L"MissingInstall") ;
		}

		// 同filenameの別完全pathへ変更し、basename一致の誤受入を防ぎます
		if( condition == SignedIndexBindingNativeCase::SECTION_OTHER_INF) {
			wcscpy_s( detail->InfFileName, L"D:\\fictional-other-root\\fixture.inf") ;
		}

		// 元parentだけの別node基本名を返し、必要子のInstallを変更しません
		if( device && device->DevInst <= 2U &&
		   (condition == SignedIndexBindingNativeCase::SECTION_OTHER_MODEL ||
			(condition == SignedIndexBindingNativeCase::SHARED_SECTION_SUCCESS &&
			 device->DevInst == 2U) ||
			(condition == SignedIndexBindingNativeCase::SECTION_CHANGED &&
			 activeNative->changed))) {
			wcscpy_s( detail->SectionName, L"OtherInstall") ;
		}

		// 装飾済み名をnativeの基本名契約へ誤って返します
		if( condition == SignedIndexBindingNativeCase::SECTION_DECORATED) {
			wcscpy_s( detail->SectionName, L"Install.NTamd64") ;
		}

		// 別architectureだけの元Models基本名です
		if( condition == SignedIndexBindingNativeCase::SECTION_OTHER_OS) {
			wcscpy_s( detail->SectionName, L"ForeignOs") ;
		}

		// LINE_LENの終端を失わせ、配列外読取を許可しません
		if( condition == SignedIndexBindingNativeCase::SECTION_UNTERMINATED) {
			std::fill( std::begin( detail->SectionName), std::end( detail->SectionName), L'X') ;
		}

		// 全static fieldを書込んでも可変IDの不足を元FALSEとして保持します
		if( condition == SignedIndexBindingNativeCase::SECTION_DETAIL_INCOMPLETE) {
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		// MAX_PATH内NULがない完全path返却を不正detailへ保持します
		if( condition == SignedIndexBindingNativeCase::SECTION_INF_UNTERMINATED) {
			std::fill( std::begin( detail->InfFileName), std::end( detail->InfFileName), L'X') ;
		}
	}

	// API成功/空metadataとAPI FALSE/元13を区別する入力です
	if( activeNative->changed && activeNative->parameters[i].DriverPath[0] &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::DIAG_DETAIL_EMPTY) {
		detail->SectionName[0] = L'\0' ;
		SetLastError( ERROR_SUCCESS) ;
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原検索条件に結び付く候補rankと現在rankを別々に返します
 * @param[in] set 保存検索条件を持つ有限fake handleです
 * @param[in] device ABIで借用するdeviceです。handleの元検索条件を使用します
 * @param[in] driver ABIで借用するnodeです。固定rankを返しnativeを呼びません
 * @param[in,out] params 非nullの借用rank出力です。成功時だけRankを更新します
 * @return 成功時TRUE、必要rank欠損または無効入力時FALSEと元errorです
 * @note 同workerだけでcounterを更新し、登録後のrank差を成功へ補完しません
 */
//------------------------------------------------------------------------------
BOOL WINAPI driverRank( HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device,
					   PSP_DRVINFO_DATA_W driver, PSP_DRVINSTALL_PARAMS params)
{
	// Rank観測を記録するfake handleの有限slot
	const auto i = setIndex( set) ;
	// rank出力の欠損と無効handleを拒否します
	if( !activeNative || i == 32U || !params) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	++activeNative->rankCalls ;
	// 第一対象成功後の同候補rank APIだけを拒否します
	if( activeNative->changed &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::DIAG_RANK_API &&
	   activeNative->parameters[i].DriverPath[0]) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	// 必要rankの欠損を架空の成功rankへ変換しません
	if( activeNative->nativeCase == SignedIndexBindingNativeCase::MISSING_RANK &&
	   activeNative->parameters[i].DriverPath[0]) {
		SetLastError( ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	params->Rank = activeNative->parameters[i].DriverPath[0] ? 1U : 0xFFFU ;
	// 子の元観測後だけ同候補nodeのWindows rankを変えます
	if( device && device->DevInst >= 3U && activeNative->requiredChildEvidenceChanged &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_CHILD_RANK_CHANGED &&
	   activeNative->parameters[i].DriverPath[0]) {
		params->Rank = 2U ;
	}

	// 固定rank群はnodeの列挙順ではなく原低位identityへ結びます
	if( activeNative->parameters[i].DriverPath[0] && driver &&
	   activeNative->nativeCase >= SignedIndexBindingNativeCase::RANK_BEST_FIRST &&
	   activeNative->nativeCase <= SignedIndexBindingNativeCase::RANK_STAGE_TIED) {
		const auto condition = activeNative->nativeCase ;	// 一caseだけを同期借用します
		const auto ordinal	 = driver->Reserved ;			// 原列挙が返した一始まりnodeです
		// 後続rankの元読取り失敗を低いrankへ補完しません
		if( ordinal == 2U && condition == SignedIndexBindingNativeCase::RANK_LATE_ERROR) {
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		params->Rank = ordinal == 1U ? 1U : 0x2001U ;
		// 両列挙順でも同じ唯一最良を要求します
		if( condition == SignedIndexBindingNativeCase::RANK_BEST_LAST) {
			params->Rank = ordinal == 2U ? 1U : 0x2001U ;
		}

		// 初期同点の後に低rankが現れるケースです
		if( condition == SignedIndexBindingNativeCase::RANK_TIE_THEN_BETTER) {
			params->Rank = ordinal == 3U ? 1U : 0x2001U ;
		}

		// 低rankでも別tupleならnodeを混ぜないための負例です
		if( ordinal == 2U && condition >= SignedIndexBindingNativeCase::RANK_OTHER_PROVIDER &&
		   condition <= SignedIndexBindingNativeCase::RANK_OTHER_INF) {
			params->Rank = 0U ;
		}

		const bool staged = std::wstring_view{activeNative->parameters[i].DriverPath}.starts_with(
			activeNative->windowsRoot) ;	// 元source変化と登録先だけの変化を区別します
		// 同点は全nodeの正常終端後も拒否する必要があります
		if( condition == SignedIndexBindingNativeCase::RANK_BEST_TIED ||
		   (ordinal == 2U &&
			((activeNative->changed &&
			  condition == SignedIndexBindingNativeCase::RANK_TIE_CHANGED) ||
			 (staged && condition == SignedIndexBindingNativeCase::RANK_STAGE_TIED)))) {
			params->Rank = 1U ;
		}

		// 旧winnerが残るまま別nodeが最良となる直前変化です
		if( ordinal == 2U &&
		   ((activeNative->changed &&
			 condition == SignedIndexBindingNativeCase::RANK_WINNER_CHANGED) ||
			(staged && condition == SignedIndexBindingNativeCase::RANK_STAGE_BETTER))) {
			params->Rank = 0U ;
		}
	}

	// 登録後だけのrank変化を変更直前guardへ与えます
	if( activeNative->nativeCase == SignedIndexBindingNativeCase::STAGE_WRONG_RANK &&
	   std::wstring_view{activeNative->parameters[i].DriverPath}.starts_with(
		   activeNative->windowsRoot)) {
		params->Rank = 2U ;
	}

	// queue commit後だけrank変更を注入します
	if( activeNative->mtdScenario == MtdFixtureScenario::RANK_AFTER_COMMIT &&
	   activeNative->mtdFiles.commits != 0U) {
		params->Rank = 2U ;
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 固定互換driver一覧の終了条件を照合します
 * @param[in] set ABIの集合handleです。実Windows一覧を解放しません
 * @param[in] device ABIで借用するdeviceです。実端末へ触れません
 * @param[in] type SPDIT_COMPATDRIVERだけを受理します
 * @return 正しい一覧typeならTRUE、それ以外はFALSEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI destroyDrivers( [[maybe_unused]] HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device,
						   DWORD type)
{
	return type == SPDIT_COMPATDRIVER ? TRUE : FALSE ;
}
//------------------------------------------------------------------------------
/**
 * @brief fake stageが選択した三つの元ファイルを同workerの人工Storeへ配置します
 * @param[in] source 署名索引から取得・展開した元INFの絶対パスです
 * @return 三つの実ファイルを所有するStoreへ全byte配置した場合trueです
 */
//------------------------------------------------------------------------------
bool stageDeclarativeStore( PCWSTR source)
{
	const auto parent = std::filesystem::path{source}.parent_path() ;	// 元INF閉包の親です
	// 別CATと別SYSの負例でもINFを含む三つの位置と長さを同一にします
	for( const std::wstring_view name : {L"fixture.inf", L"fixture.cat", L"fixture.sys"}) {
		std::ifstream input{parent / name,
							std::ios::binary | std::ios::ate} ;	// 元byteだけを借ります
		const auto	  length = input.tellg() ;					// 確保前の元長です
		// 元配布物の読み取りに失敗したfixtureは配置成功として返しません
		if( !input || length <= 0 || length > 65536) {
			return false ;
		}

		std::string bytes( static_cast<std::size_t>( length), '\0') ;	// このmemberの元byteです
		input.seekg( 0) ;
		input.read( bytes.data(), static_cast<std::streamsize>( bytes.size())) ;
		// ひとつの配置ファイルだけを同長の別byteにする負例です
		if( (activeNative->nativeCase == SignedIndexBindingNativeCase::DECLARATIVE_OTHER_CATALOG &&
			name == L"fixture.cat") ||
		   (activeNative->nativeCase == SignedIndexBindingNativeCase::DECLARATIVE_OTHER_DRIVER &&
			name == L"fixture.sys")) {
			bytes.front() ^= 1 ;
		}

		HANDLE file = INVALID_HANDLE_VALUE ;	// 本処理だけが書き込む新しいStore memberです
		// 保護領域が新たに所有したfile以外へ書きません
		if( !input || activeNative->registration.createFile(
						 std::wstring{DECLARATIVE_STORE} + std::wstring{name}, file) != 0U) {
			return false ;
		}

		const std::unique_ptr<void, decltype( &CloseHandle)> owner{
			file, &CloseHandle} ;	// この反復で解放します
		DWORD written{} ;			// 全長が配置されたことを確認する実byte数です
		// 部分書き込みが起きたfixtureを元hashの不一致へ読み替えません
		if( !WriteFile( file, bytes.data(), static_cast<DWORD>( bytes.size()), &written, nullptr) ||
		   written != bytes.size()) {
			return false ;
		}
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元INF実byteを隔離登録rootへ一回copyし登録pathを返します
 * @param[in] source 同期中借用する非null終端付き元INF pathです
 * @param[in] media nullだけを受理するmedia引数です
 * @param[in] type SPOST_PATHだけを受理します
 * @param[in] flags SP_COPY_NOOVERWRITEだけを受理します
 * @param[out] destination 終端込み登録pathの借用出力です。成功時だけ設定します
 * @param[in] capacity destinationのwchar_t要素数です
 * @param[out] required null可の終端込み必要要素数です。成功pathを作成後に設定します
 * @param[out] component nullだけを受理します。basename pointerを発行しません
 * @return 完全copyと所有確認時TRUE、それ以外は元Windows errorを持つFALSEです
 * @note 実Windows INFへ書込みません。失敗前に作成した隔離fileもregistrationが所有します
 */
//------------------------------------------------------------------------------
BOOL WINAPI stage( PCWSTR source, PCWSTR media, DWORD type, DWORD flags, PWSTR destination,
				  DWORD capacity, PDWORD required, PWSTR *component)
{
	// 必要SYSTEM参照のstage要求は成功/失敗にかかわらず別に数えます
	if( activeNative && source && std::wstring_view{source}.ends_with( L"\\peer.inf")) {
		++activeNative->dependencySystemStageCalls ;
	}

	// 指定path stageのmedia・type・flags・component条件を厳密照合します
	if( !activeNative || !source || media || type != SPOST_PATH || flags != SP_COPY_NOOVERWRITE ||
	   component) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// 呼出しは一度だけ数え、実登録先とは独立の隔離fileを作ります
	const auto ordinal = activeNative->stages++ ;
	// 元stage順を秘密pathを含まない人工member名だけで保持します
	if( activeNative->storage) {
		activeNative->storageCalls.push_back( L"stage:" +
											 std::filesystem::path{source}.filename().wstring()) ;
	}

	// 先行Extensionのguardがbase stage中にも生存することを実共有規則で確認します
	if( ordinal == 1U) {
		probeRegisteredExtension() ;
	}

	// 既存stage失敗は元HRESULTのまま返します
	if( activeNative->stagingFailure ||
	   (activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_STAGE_PARTIAL &&
		ordinal == 1U)) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// 固定予約を超えるstageを実OSへfallbackしません
	if( ordinal >= activeNative->stagedPaths.size()) {
		SetLastError( ERROR_NOT_ENOUGH_MEMORY) ;
		return FALSE ;
	}

	const auto name =
		(activeNative->nativeCase == SignedIndexBindingNativeCase::STAGE_EXTERNAL ? L"external\\"
																				  : L"INF\\") +
		std::wstring{L"oem"} + std::to_wstring( 42U + ordinal) + L".inf" ;	// 隔離登録先の有限名です
	std::wstring registered ;												// このworkspaceが予約した元絶対pathです
	// 未追跡pathや既存fileを登録先として使いません
	if( activeNative->registration.prepareExternalFile( name, registered) != 0U ||
	   !CopyFileW( source, registered.c_str(), TRUE)) {
		SetLastError( ERROR_IO_DEVICE) ;
		return FALSE ;
	}

	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;	// 元sourceの実byte長です
	// 同byte長で所有へ取り込めなければ成功stage値を返しません
	if( !GetFileAttributesExW( source, GetFileExInfoStandard, &attributes) ||
	   activeNative->registration.adoptFile(
		   name, (static_cast<std::uint64_t>( attributes.nFileSizeHigh) << 32U) |
					 attributes.nFileSizeLow) != 0U) {
		SetLastError( ERROR_IO_DEVICE) ;
		return FALSE ;
	}

	// 内容差条件だけは返却前の隔離fileへ実byte差を作ります
	if( activeNative->nativeCase == SignedIndexBindingNativeCase::STAGE_CHANGED) {
		const HANDLE changed =
			CreateFileW( registered.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						0U, nullptr) ;	// 隔離fileだけの変更handleです
		DWORD	   written{} ;			// 同fixture fileへの一byte書込数です
		const char byte = 'X' ;			// 元INFの全hashとsizeを変える有限差です
		// 書込handleを作れない場合も成功へ補完しません
		if( changed == INVALID_HANDLE_VALUE) {
			return FALSE ;
		}

		SetFilePointer( changed, 0L, nullptr, FILE_END) ;
		const bool wrote = WriteFile( changed, &byte, 1U, &written, nullptr) != FALSE &&
						   // 意図した原byte差の作成結果です
						   written == 1U ;
		CloseHandle( changed) ;
		// 意図した内容差を作れなければfixture自身の失敗として拒否します
		if( !wrote) {
			SetLastError( ERROR_IO_DEVICE) ;
			return FALSE ;
		}
	}

	const auto length = registered.size() + 1U ;	// 実返却pathの終端込み要素数です
	// 保護stage先bufferの必要長を満たさなければ拒否します
	if( length >= MAX_PATH || !destination || capacity < length) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	wcscpy_s( destination, capacity, registered.c_str()) ;
	// 必要stage先長の出力先がある場合だけ値を返します
	if( required) {
		*required = static_cast<DWORD>(
			length +
			(activeNative->nativeCase == SignedIndexBindingNativeCase::STAGE_BAD_LENGTH ? 1U : 0U)) ;
	}

	wcscpy_s( activeNative->stagedPaths[ordinal].data(), MAX_PATH, registered.c_str()) ;
	// 同じOEM INFでも元CATとSYSの配置を独立に検査できるようStoreを作成します
	if( declarativeCase() && !stageDeclarativeStore( source)) {
		SetLastError( ERROR_WRITE_FAULT) ;
		return FALSE ;
	}

	// stage後だけ未知class handlerを出現させます
	if( activeNative->mtdScenario == MtdFixtureScenario::HANDLER_AFTER_STAGE && activeMtdFiles) {
		// 未知handlerとして注入するNUL終端文字列です
		const std::array<wchar_t, 2U> value{L'x', L'\0'} ;
		// 変更する人工class installer propertyです
		auto						 &property = activeMtdFiles->classInstaller ;
		property.error						   = ERROR_SUCCESS ;
		property.type						   = DEVPROP_TYPE_STRING ;
		property.bytes.resize( sizeof( value)) ;
		std::memcpy( property.bytes.data(), value.data(), sizeof( value)) ;
	}

	// 既登録の元byteにもreadbackを必要とするWindows応答です
	if( activeNative->nativeCase == SignedIndexBindingNativeCase::STORAGE_STAGE_EXISTS) {
		SetLastError( ERROR_FILE_EXISTS) ;
		return FALSE ;
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元登録pathと完全指定nodeの一致時だけfake導入を一度記録します
 * @param[in] parent ABIの親Windowです。画面を作成しません
 * @param[in] set 元検索条件を持つ有限fake handleです
 * @param[in] device 非nullの選択済み人工deviceです
 * @param[in] driver 非nullの完全指定nodeです。元登録path・版・provider・予約値へ照合します
 * @param[in] flags 0だけを受理します
 * @param[out] reboot 非null出力です。実行した人工対象の結果だけを設定します
 * @return 固定導入成功時TRUE、不正bindingまたは原導入失敗時FALSEと元errorです
 * @note 実DiInstallDeviceを呼びません。個別実行回数と元部分失敗を同workerに保持します
 */
//------------------------------------------------------------------------------
BOOL WINAPI install( [[maybe_unused]] HWND parent, HDEVINFO set, PSP_DEVINFO_DATA device,
					PSP_DRVINFO_DATA_W driver, DWORD flags, PBOOL reboot)
{
	// 指定driver・flags・再起動出力の欠損を拒否します
	if( !activeNative || !driver || !device || flags != 0U || !reboot) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	const auto slot = setIndex( set) ;	// 同指定driver検索条件を所有する有限slotです
	const bool child =
		device->DevInst >= 3U && activeNative->distributionDevices.empty() ;	// 元必要SWCだけです
	SP_DRVINFO_DATA_W expected{} ;												// 固定契約から作る独立した正負の期待です
	expected.cbSize			= sizeof( expected) ;
	const bool originalNode =	// 元選択/原文へ結合した所有値です
		activeNative->originalIntelArchive && slot < 32U &&
		readDistributionDriverNode( activeNative->parameters[slot].DriverPath, expected) ;
	const bool nodeMatches =	// 独立した条件又は到達件数です。別条件の成功を借用しません
		originalNode ? driver->DriverVersion == expected.DriverVersion &&
						   std::wstring_view{driver->ProviderName} == expected.ProviderName &&
						   CompareFileTime( &driver->DriverDate, &expected.DriverDate) == 0
					 : driver->DriverVersion == (1ULL << 48U) &&
						   std::wstring_view{driver->ProviderName} == L"Fixture Vendor" ;
	const bool bindingMatches =
		slot < 32U && device->DevInst >= 1U && device->DevInst <= 4U &&
		(child ? activeNative->componentChild &&
					 activeNative->childInstalls[device->DevInst - 3U] == 0U
			   : activeNative->deviceInstalls[device->DevInst - 1U] == 0U) &&
		((activeNative->localDriverCandidates &&
		  activeNative->parameters[slot].DriverPath[0] == L'\0') ||
		 std::ranges::any_of(
			 activeNative->stagedPaths,
			 [&]( const auto &path) {
				 return !path.empty() && path.front() != L'\0' &&
						std::wstring_view{activeNative->parameters[slot].DriverPath} == path.data() ;
			 })) &&
		driver->cbSize == sizeof( *driver) && nodeMatches &&
		// 元nodeの完全指定です
		driver->Reserved ==
			(activeNative->nativeCase == SignedIndexBindingNativeCase::RANK_BEST_LAST		  ? 2U
			 : activeNative->nativeCase == SignedIndexBindingNativeCase::RANK_TIE_THEN_BETTER ? 3U
																							  : 1U) ;
	activeNative->specifiedBindingMatches &= bindingMatches ;
	// 未登録pathや別nodeを指定するcallは固定成功fakeでも拒否します
	if( !bindingMatches) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	// 指定APIを呼ぶ時点まで同登録byteを固定する契約です
	probeRegisteredExtension() ;
	++activeNative->installs ;
	++activeNative->legacyInstalls ;
	// 非null/flags0はbindingMatches成立後の元API事実です
	if( activeNative->storage) {
		activeNative->storageCalls.push_back( L"install:nonnull:flags0") ;
	}

	// Baseと必要子を役割別に一回だけ記録します
	if( child) {
		++activeNative->childInstalls[device->DevInst - 3U] ;
	} else {
		++activeNative->deviceInstalls[device->DevInst - 1U] ;
	}

	*reboot = !activeNative->noReboot && (activeNative->mode == 4U ||
										  (activeNative->multiple && device->DevInst == 1U))
				  ? TRUE
				  : FALSE ;
	// FALSEの欠落診断を0の成功へ上げない追加C31の低位入力です
	if( !child &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_BASE_DIAGNOSTIC_MISSING) {
		SetLastError( ERROR_SUCCESS) ;
		return FALSE ;
	}

	// 既存拒否の元ERROR_ACCESS_DENIEDを欠落診断と混同しません
	if( activeNative->mode == 3U || (activeNative->partialFailure && device->DevInst == 2U) ||
	   batchFaultApplies( SignedIndexBindingBatchFault::SECOND_API_DENIED, device->DevInst) ||
	   (child &&
		activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_CHILD_FAILURE) ||
	   (!child &&
		activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_BASE_FAILURE)) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// 完了した自己deviceだけを反映し、第二の未実行状態は変更しません
	if( !child && activeNative->reflectOwnInstall) {
		++activeNative->appliedDeviceInstalls[device->DevInst - 1U] ;
		activeNative->appliedNodes[device->DevInst - 1U] = *driver ;
		activeNative->appliedInfNames[device->DevInst - 1U] =
			activeNative->parameters[slot].DriverPath[0]
				? std::filesystem::path( activeNative->parameters[slot].DriverPath)
					  .filename()
					  .wstring()
				: L"oemfixture.inf" ;
	}

	return TRUE ;
}
//------------------------------------------------------------------------------
/**
 * @brief 有限fixtureのx64 native architectureを返します
 * @param[out] system 非nullの借用SYSTEM_INFOです。内容を初期化しAMD64だけを設定します
 * @pre systemは呼出し側が同期中所有する有効出力です
 */
//------------------------------------------------------------------------------
void WINAPI architecture( LPSYSTEM_INFO system)
{
	// 元子bindingが実低位へ到達した同期中だけ同proofの拒否を試験します
	if( activeNative && activeNative->bindingStore && activeNative->requiredChildProofRuns == 0U) {
		// 同worker中に成立した元proofの正負観測です
		const auto checks = RequiredChildBindingProbe::inspect( *activeNative->bindingStore) ;
		// 元proofへの到達を観測できた場合だけ記録します
		if( checks != 0U) {
			activeNative->requiredChildProofChecks = checks ;
			++activeNative->requiredChildProofRuns ;
			// 最初の子観測が済んだ後だけ、一条件の低位変化を有効にします
			activeNative->requiredChildEvidenceChanged = true ;
		}
	}

	*system						   = {} ;
	system->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実Windows directoryへfallbackせず隔離rootの完全値を返します
 * @param[out] buffer 所有rootの終端付き出力です
 * @param[in] capacity wchar_t要素数です
 * @return 成功時は終端を除く長さ、buffer不足時は必要長です
 */
//------------------------------------------------------------------------------
UINT WINAPI windowsDirectory( LPWSTR buffer, UINT capacity)
{
	// Workerへ固定した完全rootがなければnativeを呼びません
	if( !activeNative || activeNative->windowsRoot.empty()) {
		SetLastError( ERROR_INVALID_DATA) ;
		return 0U ;
	}

	const auto length =
		// 有限workspaceの長さです
		static_cast<UINT>( activeNative->windowsRoot.size()) ;
	// 元Windows APIの不足buffer契約を保持します
	if( !buffer || capacity <= length) {
		return length + 1U ;
	}

	wcscpy_s( buffer, capacity, activeNative->windowsRoot.c_str()) ;
	// 元同意の復旧後、登録より前にguardがWindows rootを確認した時点だけを記録します
	if( declarativeCase() && activeNative->restoreBegins != 0U && activeNative->stages == 0U) {
		++activeNative->declarativePreStageRootReads ;
	}

	// 対象付き候補の登録先が確定した時点を時計・機種照会と独立に記録します
	if( activeNative->catalogInstall && activeNative->stages == 0U &&
	   (activeNative->restoreBegins != 0U ||
		activeNative->catalogInstall->observeRegistrationOnServer)) {
		++activeNative->catalogInstall->registrationRootReads ;
	}

	return length ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同検査rootの実INF byteへClass名/GUID返却を結合します
 * @param[in] path 同期中だけ借用する非nullのNUL終端INF pathです。通常は隔離file、明示Intel replayでは元保護INFです
 * @param[out] guid 成功時のClassGUIDです。nullは拒否します
 * @param[out] name capacity文字のClass名bufferです。成功時にNUL終端し、容量不足を拒否します
 * @param[in] capacity nameのUTF-16文字容量です
 * @param[out] required 必要なClass名文字容量の任意出力です。独自クラスの元内容検査では省略できます
 * @return Class情報の取得/出力成功時TRUE、入力・file・容量の拒否時FALSEと元LastErrorです
 * @note 通常の人工scopeは1MiB以下の隔離INFだけを読みます。originalIntelArchiveの明示replayではSetupDiGetINFClassWへ委譲します
 *       driver導入は行いません
 * @see infClass(PCWSTR,LPGUID,PWSTR,DWORD,PDWORD)
 */
//------------------------------------------------------------------------------
BOOL WINAPI infClass( PCWSTR path, LPGUID guid, PWSTR name, DWORD capacity, PDWORD required)
{
	// 原Intel replayだけは元保護INFのClassをWindows readerからそのまま返します
	if( activeNative && activeNative->originalIntelArchive) {
		return SetupDiGetINFClassW( path, guid, name, capacity, required) ;
	}

	// 任意成功DTOを受けず、同scopeの実INF fileと完全出力を要求します
	if( !activeNative || !path || !guid || !name || (!required && !declarativeCase())) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// 第一対象成功後の同Class読取APIだけへ元13を返します
	if( activeNative->changed &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::DIAG_CLASS_API) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	std::ifstream input{std::filesystem::path{path},
						std::ios::binary | std::ios::ate} ;	// 同検査rootの実byteです
	const auto	  length = input.tellg() ;					// 確保前に有限長を確認します
	// 固定fixtureの実byteを読めない場合はnative成功で補完しません
	if( !input || length <= 0 || length > 1024 * 1024) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	std::string bytes( static_cast<std::size_t>( length), '\0') ;	// 上限確認済みの原INFです
	input.seekg( 0) ;
	input.read( bytes.data(), static_cast<std::streamsize>( bytes.size())) ;
	// 独自クラスは同じ保護INFの名前とGUIDの両宣言がある場合だけ応答します
	if( declarativeCase()) {
		// 想定の実byteを読み切れない場合はクラス名とGUIDを合成しません
		if( !input || bytes.find( "\r\nClass=DCFixtureBridge\r\n") == bytes.npos ||
		   bytes.find( "\r\nClassGuid={c054bd69-a76e-4caa-a915-e3ce9a285b62}\r\n") == bytes.npos) {
			SetLastError( ERROR_INVALID_DATA) ;
			return FALSE ;
		}

		// 実APIの任意出力と固定長バッファの契約を保ちます
		if( required) {
			*required = static_cast<DWORD>( std::size( DECLARATIVE_NAME)) ;
		}

		// 切り詰めたクラス名を成功として返しません
		if( capacity < std::size( DECLARATIVE_NAME)) {
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		*guid = DECLARATIVE_CLASS ;
		std::ranges::copy( DECLARATIVE_NAME, name) ;
		return TRUE ;
	}

	const bool network =
		// 元INF directiveだけです
		bytes.find( "\nClass=Net\r\n") != std::string::npos ;
	const bool ports =
		// 元INF directiveだけです
		bytes.find( "\nClass=Ports\r\n") != std::string::npos ;
	// 同元用途が端末storage専用であるという非権限分類です
	const bool storage = bytes.find( "\nClass=SCSIAdapter\r\n") != std::string::npos ;
	// 人工INFの正式MTD classを識別します
	const bool mtd = bytes.find( "\nClass=MTD\r\n") != std::string::npos ;
	// 同じINFが宣言する正式メディアチェンジャーを照合する
	const bool changer = bytes.find( "\nClass=MediumChanger\r\n") != std::string::npos ;
	// 選択した元INFが宣言する正式IDEコントローラーを照合する
	const bool hdc = bytes.find( "\nClass=HDC\r\n") != std::string::npos ;
	const bool extension =
		// 元役割Classの厳密行です
		bytes.find( "\nClass=Extension\r\n") != std::string::npos ;
	const bool component =
		// 元SWC Classの厳密行です
		bytes.find( "\nClass=SoftwareComponent\r\n") != std::string::npos ;
	const std::string_view expectedGuid =
		mtd			? "ClassGuid={4d36e970-e325-11ce-bfc1-08002be10318}\r\n"
		: changer	? "ClassGuid={ce5939ae-ebde-11d0-b181-0000f8753ec4}\r\n"
		: hdc		? "ClassGuid={4d36e96a-e325-11ce-bfc1-08002be10318}\r\n"
		: storage	? "ClassGuid={4d36e97b-e325-11ce-bfc1-08002be10318}\r\n"
		: extension ? "ClassGuid={e2f84ce7-8efa-411c-aa69-97454ca4cb57}\r\n"
		: component ? "ClassGuid={5c4c3332-344d-483c-8739-259e934c9cc8}\r\n"
		: network
			? "ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
			: "ClassGuid={4d36e978-e325-11ce-bfc1-08002be10318}\r\n" ;	// 固定実INFの完全GUIDです
	// 間違ったraw Class/GUIDや部分読取をClass成功へ補完しません
	if( !input ||
	   static_cast<unsigned>( network) + static_cast<unsigned>( ports) +
			   static_cast<unsigned>( extension) + static_cast<unsigned>( component) +
			   static_cast<unsigned>( storage) + static_cast<unsigned>( mtd) +
			   static_cast<unsigned>( changer) + static_cast<unsigned>( hdc) !=
		   1U ||
	   bytes.find( expectedGuid) == std::string::npos) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	const std::wstring_view value =
		mtd			? L"MTD"
		: changer	? L"MediumChanger"
		: hdc		? L"HDC"
		: storage	? L"SCSIAdapter"
		: extension ? L"Extension"
		: component ? L"SoftwareComponent"
		: activeNative->nativeCase == SignedIndexBindingNativeCase::INF_CLASS_MISMATCH ? L"Net"
		: network																	   ? L"Net"
				  : L"Ports" ;	// Class不一致は原API返却だけを変更します
	*required = static_cast<DWORD>( value.size() + 1U) ;
	// 出力不足を切詰めたClass名へ変換しません
	if( capacity < *required) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	*guid = mtd			? MTD_CLASS
			: changer	? MEDIUM_CHANGER_CLASS
			: hdc		? HDC_CLASS
			: storage	? STORAGE_CLASS
			: extension ? EXTENSION_CLASS
			: component ? COMPONENT_CLASS
			: network	? NET_CLASS
						: PORTS_CLASS ;
	std::copy( value.begin(), value.end(), name) ;
	name[value.size()] = L'\0' ;
	// API成功でも未知GUIDの内部整合拒否を区別します
	if( activeNative->changed &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::DIAG_CLASS_VALUE) {
		*guid = GUID_NULL ;
	}

	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief exact serviceの有限所有adapter一覧に必要な文字容量を返します
 * @param[out] size 非null時だけ二重NULを含むwchar_t数です
 * @param[in] service FixtureStorageの正確な元名です
 * @param[in] flags SERVICE/PRESENT/DONOTGENERATEの同組合せだけです
 * @return 人工所有集合の確認時CR_SUCCESS、未知入力はCONFIGRET失敗です
 * @note 実CMを呼ばず、非present一覧や全device探索へ補完しません
 */
//------------------------------------------------------------------------------
CONFIGRET WINAPI serviceDeviceListSize( PULONG size, PCWSTR service, ULONG flags)
{
	// source fixtureでもexact serviceと副作用禁止flagsを必要とします
	if( !activeNative || !size || !service ||
	   flags != (CM_GETIDLIST_FILTER_SERVICE | CM_GETIDLIST_FILTER_PRESENT |
				 CM_GETIDLIST_DONOTGENERATE)) {
		return CR_INVALID_FLAG ;
	}

	// 元byte又は所有adapterの同期中の単独保持です
	const std::wstring_view owner = storageServicePresent()
										? (storageOwnerPeer( 2U) ? L"TESTBUS\\SYNTH_0002\\FIXTURE"
																: L"TESTBUS\\SYNTH_0001\\FIXTURE")
										: L"" ;
	*size						  = owner.empty() ? 2U : static_cast<ULONG>( owner.size() + 2U) ;
	return CR_SUCCESS ;
}

//------------------------------------------------------------------------------
/**
 * @brief exact serviceの人工全所有adapterを二重NUL付きで返します
 * @param[in] service 同元service名です。同期中だけ借用します
 * @param[out] buffer size文字の出力です。不足/未知入力時は書込みません
 * @param[in] size wchar_t容量です。終端二つを含みます
 * @param[in] flags SERVICE/PRESENT/DONOTGENERATEだけです
 * @return 全一覧返却時CR_SUCCESS、不足又は未知入力はCONFIGRET失敗です
 * @note 実Windowsへfallbackせず、新device生成もしません
 */
//------------------------------------------------------------------------------
CONFIGRET WINAPI serviceDeviceList( PCWSTR service, PZZWSTR buffer, ULONG size, ULONG flags)
{
	// 元APIが要求した終端込み容量です
	ULONG	   required{} ;
	// 下位検査の最初の診断を後続へ返す一時値です
	const auto error = serviceDeviceListSize( &required, service, flags) ;
	// 空の元所有集合を実Windowsから補完しません
	if( error != CR_SUCCESS || !buffer || size < required) {
		return error != CR_SUCCESS ? error : CR_BUFFER_SMALL ;
	}

	// 元byte又は所有adapterの同期中の単独保持です
	const std::wstring_view owner = storageServicePresent()
										? (storageOwnerPeer( 2U) ? L"TESTBUS\\SYNTH_0002\\FIXTURE"
																: L"TESTBUS\\SYNTH_0001\\FIXTURE")
										: L"" ;
	std::copy( owner.begin(), owner.end(), buffer) ;
	buffer[owner.size()]	  = L'\0' ;
	buffer[owner.size() + 1U] = L'\0' ;
	return CR_SUCCESS ;
}

//------------------------------------------------------------------------------
/**
 * @brief MTD targetの元Windows文字列を返しsourceを同所有workspaceへ結びます
 * @param[out] buffer 元rootを受ける領域です
 * @param[in] capacity UTF-16文字容量です
 * @return 元rootの文字数又は不足時の必要容量です
 */
//------------------------------------------------------------------------------
UINT WINAPI mtdFixtureWindows( LPWSTR buffer, UINT capacity)
{
	// MTD fixtureが有効でなければWindows rootを返しません
	if( !activeNative || !activeNative->mtd || !activeMtdFiles) {
		SetLastError( ERROR_INVALID_STATE) ;
		return 0U ;
	}

	// 復旧成立前の共有先接触を拒否し観測へ残します
	if( activeNative->restoreBegins == 0U || activeNative->restoreFailure) {
		activeMtdFiles->beforeRestoreAccess = true ;
		SetLastError( ERROR_ACCESS_DENIED) ;
		return 0U ;
	}

	++activeMtdFiles->windowsRootChecks ;
	// 同fixtureの原INFからsource directoryを特定します
	for( const auto &path : activeNative->sourceInfs) {
		// 人工Windows root以外の同原fixture INFだけを選びます
		if( path.ends_with( L"\\fixture.inf") && !path.starts_with( activeNative->windowsRoot)) {
			activeMtdFiles->sourceRoot = path.substr( 0U, path.find_last_of( L'\\')) ;
			break ;
		}
	}

	// 同原INFが見つからない場合は架空sourceを補完しません
	if( activeMtdFiles->sourceRoot.empty()) {
		SetLastError( ERROR_NOT_FOUND) ;
		return 0U ;
	}

	// fakeが返す論理Windows rootです
	const auto &root = activeMtdFiles->windowsRoot ;
	// Windows directory出力の必要容量を返します
	if( !buffer || capacity <= root.size()) {
		return static_cast<UINT>( root.size() + 1U) ;
	}

	std::copy( root.begin(), root.end(), buffer) ;
	buffer[root.size()] = L'\0' ;
	return static_cast<UINT>( root.size()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief MTDの有界fake queue handleを同所有状態へ戻します
 * @param[in] queue 同workerが作った架空handleです
 * @return 同操作のqueue又は不正時nullptrです
 */
//------------------------------------------------------------------------------
MtdFixtureQueue *mtdFixtureQueue( HSPFILEQ queue)
{
	// fake queue handleのslot番号を求める値です
	const auto value = reinterpret_cast<std::uintptr_t>( queue) ;
	// 所有していないfake queue handleを拒否します
	if( !activeMtdFiles || value < 0x400U || value >= 0x404U ||
	   !activeMtdFiles->queues[value - 0x400U].used) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return nullptr ;
	}

	return &activeMtdFiles->queues[value - 0x400U] ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未使用のfake queueを一つだけ作ります
 * @return 所有queue又は上限時INVALID_HANDLE_VALUEです
 */
//------------------------------------------------------------------------------
HSPFILEQ WINAPI mtdFixtureOpenQueue()
{
	// 有効fixture内でだけqueueを割り当てます
	if( activeMtdFiles) {
		// 未使用の所有queue slotを探します
		for( std::size_t i = 0U; i < activeMtdFiles->queues.size(); ++i) {
			// 現在の所有queue slotです
			auto &queue = activeMtdFiles->queues[i] ;
			// 最初の未使用slotだけを初期化して返します
			if( !queue.used) {
				queue	   = {} ;
				queue.used = true ;
				return reinterpret_cast<HSPFILEQ>( 0x400U + i) ;
			}
		}
	}

	SetLastError( ERROR_NOT_ENOUGH_MEMORY) ;
	return INVALID_HANDLE_VALUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同操作のfake queueだけを閉じます
 * @param[in] handle 同fixtureのqueueです
 * @return 所有queueを解放できた場合TRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureCloseQueue( HSPFILEQ handle)
{
	// close対象の所有queueです
	auto *queue = mtdFixtureQueue( handle) ;
	// 未知queueのcloseを拒否します
	if( !queue) {
		return FALSE ;
	}

	*queue = {} ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief queueのcopy/delete/rename件数を人工stateから返します
 * @param[in] handle 同fixtureのqueueです
 * @param[in] operation 元操作種別です
 * @param[out] count 同種別の件数です
 * @return 入力と所有queueが正しければTRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureQueueCount( HSPFILEQ handle, UINT operation, PUINT count)
{
	// 件数照会する所有queueです
	const auto *queue = mtdFixtureQueue( handle) ;
	// 未知queueや不正な操作種別・出力を拒否します
	if( !queue || !count || operation > FILEOP_DELETE) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	*count = operation == FILEOP_COPY ? static_cast<UINT>( queue->copies.size()) : 0U ;
	// 原queueにdeleteが混じる固定負例を注入します
	if( queue->original && operation == FILEOP_DELETE && activeNative &&
	   activeNative->mtdScenario == MtdFixtureScenario::QUEUE_DELETE) {
		*count = 1U ;
	}

	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保持した各copyをWindowsと同じSCAN callbackへ渡します
 * @param[in] handle 同fixtureのqueueです
 * @param[in] flags 元scan flagsです
 * @param[in] window 対話を行わないnullです
 * @param[in] callback 製品の公開tuple照合です
 * @param[in,out] context callbackが借用する元状態です
 * @param[out] result 元scan結果です
 * @return 全callback成立時TRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureScanQueue( HSPFILEQ handle, DWORD flags, HWND window,
								PSP_FILE_CALLBACK_W callback, PVOID context, PDWORD result)
{
	// scan対象の所有queueです
	const auto *queue = mtdFixtureQueue( handle) ;
	// 公開scanのflags、callback、引数を正確に要求します
	if( !queue || flags != SPQ_SCAN_USE_CALLBACKEX || window || !callback || !result) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// fake queueの全copy tupleを原順でcallbackへ返します
	for( const auto &copy : queue->copies) {
		// scan callbackへ渡す原copy tupleです
		FILEPATHS_W path{copy.target.c_str(), copy.source.c_str(), ERROR_FILE_NOT_FOUND,
						 copy.flags} ;
		// callbackが拒否した時点で元abortを返します
		if( callback( context, SPFILENOTIFY_QUEUESCAN_EX, reinterpret_cast<UINT_PTR>( &path), 0U) !=
		   NO_ERROR) {
			SetLastError( ERROR_OPERATION_ABORTED) ;
			return FALSE ;
		}
	}

	*result = 0U ;
	++activeMtdFiles->queueScans ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 所有sourceから既知人工INFを開く架空handleです
 * @param[in] path 同原INFの完全pathです
 * @param[in] cls 指定しないclassです
 * @param[in] style 元INF読取flagsです
 * @param[out] line 使用しないnullです
 * @return 一致時の架空handle又はINVALID_HANDLE_VALUEです
 */
//------------------------------------------------------------------------------
HINF WINAPI mtdFixtureOpenInf( PCWSTR path, PCWSTR cls, DWORD style, PUINT line)
{
	// 同人工INF以外や未知open flagsを拒否します
	if( !activeMtdFiles || !path || cls || line ||
	   style != (INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE) ||
	   std::wstring_view{path} != activeMtdFiles->sourceRoot + L"\\fixture.inf") {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return INVALID_HANDLE_VALUE ;
	}

	return reinterpret_cast<HINF>( 0x500U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同登録INFだけを隔離した人工Storeの原位置へ対応させます
 * @param[in] registered 同登録INFです
 * @param[in] alternate 指定しないplatformです
 * @param[in] locale 指定しないlocaleです
 * @param[out] buffer 正式位置の出力先です
 * @param[in] capacity 出力先の文字容量です
 * @param[out] required 必要な文字数です
 * @return 同fixtureのStoreを照合できた場合TRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureStoreLocation( PCWSTR registered, PSP_ALTPLATFORM_INFO alternate,
									PCWSTR locale, PWSTR buffer, DWORD capacity, PDWORD required)
{
	// 指定された人工Store source以外は不在を返します
	if( !activeNative || !activeMtdFiles ||
	   (activeNative->mtdScenario != MtdFixtureScenario::STORE_SOURCE &&
		activeNative->mtdScenario != MtdFixtureScenario::STORE_PARENT_ADD_DIRECTORY) ||
	   !registered || alternate || locale || !required ||
	   std::ranges::none_of( activeNative->stagedPaths, [&]( const auto &path) {
		   return path.front() && std::wstring_view{registered} == path.data() ;
	   })) {
		SetLastError( ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	// 人工Storeに置く登録INF pathです
	const auto value = activeMtdFiles->storeDirectory + L"\\fixture.inf" ;
	*required		 = static_cast<DWORD>( value.size() + 1U) ;
	// Store位置出力の容量不足をWindows ABIで返します
	if( !buffer || capacity < *required) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::copy( value.begin(), value.end(), buffer) ;
	buffer[value.size()] = L'\0' ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空INF handleだけを閉じます
 * @param[in] inf 同fixtureの架空handleです
 * @return 戻り値はありません
 */
//------------------------------------------------------------------------------
VOID WINAPI mtdFixtureCloseInf( [[maybe_unused]] HINF inf)
{
}

//------------------------------------------------------------------------------
/**
 * @brief 原sectionとflagsからfake queueの完全copy tupleを構築します
 * @param[in,out] queue 所有するqueueです
 * @param[in] section 元INFのsectionです
 * @param[in] flags 元API CopyStyleです
 * @return 既知sectionだけを追加できた場合trueです
 */
//------------------------------------------------------------------------------
bool mtdFixtureAddSection( MtdFixtureQueue &queue, std::wstring_view section, DWORD flags)
{
	// 所有fixtureがなければqueueへ追加しません
	if( !activeMtdFiles) {
		return false ;
	}

	// 原fixture packageの所有source rootです
	const auto &source = activeMtdFiles->sourceRoot ;
	// 表示する人工Windows rootです
	const auto &root = activeMtdFiles->windowsRoot ;
	// SYS sectionには元flags0のcopyを一件作ります
	if( section == L"Files" && flags == 0U) {
		queue.copies.push_back(
			{source + L"\\fixture.sys", root + L"\\System32\\drivers\\fixture.sys", 0U}) ;
		return true ;
	}

	// DLL sectionは元flags0または制御NOOVERWRITEに限定します
	if( section == L"SharedDlls" && (flags == 0U || flags == SP_COPY_FORCE_NOOVERWRITE)) {
		// 原二DLLそれぞれのcopy tupleを追加します
		for( const auto leaf : {L"fixture-a.dll", L"fixture-b.dll"}) {
			queue.copies.push_back( {source + L"\\" + leaf, root + L"\\System32\\" + leaf, flags}) ;
		}

		return true ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同原INFの一sectionだけをfake制御queueへ加えます
 * @param[in] handle 同fixtureのqueueです
 * @param[in] root 同原source rootです
 * @param[in] inf 同原INFの架空handleです
 * @param[in] list 使用しないnullです
 * @param[in] section 元sectionです
 * @param[in] flags APIの追加copy flagsです
 * @return 全引数と原sectionが一致した場合TRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureQueueSection( HSPFILEQ handle, PCWSTR root, HINF inf, HINF list,
								   PCWSTR section, DWORD flags)
{
	// section追加先の所有queueです
	auto *queue = mtdFixtureQueue( handle) ;
	// 同原queue・INF・section・source以外の追加を拒否します
	if( !queue || !root || !section || inf != reinterpret_cast<HINF>( 0x500U) || list ||
	   std::wstring_view{root} != activeMtdFiles->sourceRoot ||
	   !mtdFixtureAddSection( *queue, section, flags)) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	// 制御DLLのflags差を負例として注入します
	if( activeNative && activeNative->mtdScenario == MtdFixtureScenario::CONTROL_FLAGS &&
	   std::wstring_view{section} == L"SharedDlls" && !queue->copies.empty()) {
		queue->copies.back().flags = 0U ;
	}

	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同deviceの元selected nodeだけをfakeへ保存します
 * @param[in] set 同fixtureのdevice集合です
 * @param[in] device 同選択deviceです
 * @param[in] driver 同選択nodeです
 * @return 同所有範囲のnodeだけTRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureSetSelected( HDEVINFO set, PSP_DEVINFO_DATA device, PSP_DRVINFO_DATA_W driver)
{
	// 選択先deviceのfake集合indexです
	const auto index = setIndex( set) ;
	// deviceとdriver nodeの選択引数を完全fakeで検証します
	if( !activeMtdFiles || index >= 32U || !device || !driver || driver->cbSize != sizeof( *driver)) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	activeMtdFiles->selected[index]	   = *driver ;
	activeMtdFiles->hasSelected[index] = true ;
	++activeMtdFiles->selectedSets ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同deviceのfake selected nodeをそのまま読み戻します
 * @param[in] set 同fixtureのdevice集合です
 * @param[in] device 同選択deviceです
 * @param[out] driver 同選択nodeの出力です
 * @return 元nodeを読み戻せた場合TRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureGetSelected( HDEVINFO set, PSP_DEVINFO_DATA device, PSP_DRVINFO_DATA_W driver)
{
	// 選択を読戻すdeviceのfake集合indexです
	const auto index = setIndex( set) ;
	// 以前に同deviceで選択したnodeだけを返します
	if( !activeMtdFiles || index >= 32U || !device || !driver ||
	   !activeMtdFiles->hasSelected[index]) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	*driver = activeMtdFiles->selected[index] ;
	// 指定条件だけで選択nodeの変化を注入します
	if( activeNative && activeNative->mtdScenario == MtdFixtureScenario::SELECTED_NODE_CHANGED) {
		++driver->Reserved ;
	}

	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief fake queueの通知と所有workspaceのSYS copyだけを実行します
 * @param[in] parent 元親windowです。操作には使用しません
 * @param[in] handle 同fixtureの制御queueです
 * @param[in] callback 製品の通知判定です
 * @param[in,out] context callbackが借用する元状態です
 * @return 全通知と所有領域内I/Oが成立した場合TRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureCommitQueue( [[maybe_unused]] HWND parent, HSPFILEQ handle,
								  PSP_FILE_CALLBACK_W callback, PVOID context)
{
	// commit対象の所有queueです
	const auto *queue = mtdFixtureQueue( handle) ;
	// 所有queueとcallbackがなければcommitしません
	if( !queue || !callback || !activeMtdFiles) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	++activeMtdFiles->commits ;
	// Windows通知を同callbackへ送る関数です
	const auto emit = [&]( UINT code, UINT_PTR first, UINT_PTR second) {
		return callback( context, code, first, second) != 0U ;
	} ;
	// queue開始通知をcallbackが拒否すれば元abortを返します
	if( !emit( SPFILENOTIFY_STARTQUEUE, 0U, 0U) ||
	   !emit( SPFILENOTIFY_STARTSUBQUEUE, FILEOP_COPY, queue->copies.size())) {
		SetLastError( ERROR_OPERATION_ABORTED) ;
		return FALSE ;
	}

	// 所有queueの各原copyについてWindows通知を再現します
	for( const auto &copy : queue->copies) {
		// 元sourceのdirectoryとleafを分ける位置です
		const auto slash = copy.source.find_last_of( L'\\') ;
		// sourceを媒体directoryとleafに分けられなければ拒否します
		if( slash == copy.source.npos) {
			return FALSE ;
		}

		// 媒体通知のsource directoryです
		const auto	   directory = copy.source.substr( 0U, slash) ;
		// 媒体通知のsource leafです
		const auto	   leaf = copy.source.substr( slash + 1U) ;
		// callbackへ返す原媒体tupleです
		SOURCE_MEDIA_W media{nullptr,			nullptr,	  L"fixture",
							 directory.c_str(), leaf.c_str(), copy.flags} ;
		// callbackへ返す原COPY tupleです
		FILEPATHS_W	   path{copy.target.c_str(), copy.source.c_str(), 0U, copy.flags} ;
		// 媒体要求またはcopy開始のcallback拒否をabortにします
		if( !emit( SPFILENOTIFY_NEEDMEDIA, reinterpret_cast<UINT_PTR>( &media), 0U) ||
		   !emit( SPFILENOTIFY_STARTCOPY, reinterpret_cast<UINT_PTR>( &path), 0U)) {
			SetLastError( ERROR_OPERATION_ABORTED) ;
			return FALSE ;
		}

		// sourceとtargetが所有範囲内でなければ実copyしません
		if( !mtdFixturePath( copy.source, false) || !mtdFixturePath( copy.target, true)) {
			activeMtdFiles->queueOutsideOwned = true ;
			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		// targetを写像した所有実pathです
		const auto physical = mtdFixturePhysical( copy.target) ;
		// SYS元flags0とDLLの非置換flagsを分けます
		if( copy.flags == 0U) {
			// SYS遅延の固定負例だけWindows遅延通知を送ります
			if( activeNative->mtdScenario == MtdFixtureScenario::SYSTEM_DELAYED) {
				// 遅延通知をcallbackが拒否すれば元abortを返します
				if( !emit( SPFILENOTIFY_FILEOPDELAYED, reinterpret_cast<UINT_PTR>( &path), 0U)) {
					SetLastError( ERROR_OPERATION_ABORTED) ;
					return FALSE ;
				}
			}
			// 所有workspace内SYS copyの実失敗を返します
			else if( !::CopyFileW( copy.source.c_str(), physical.c_str(), FALSE)) {
				return FALSE ;
			}
		}
		// DLLの非置換flagsや先行配置が欠ければ失敗にします
		else if( copy.flags != SP_COPY_FORCE_NOOVERWRITE ||
				::GetFileAttributesW( physical.c_str()) == INVALID_FILE_ATTRIBUTES) {
			SetLastError( ERROR_INVALID_DATA) ;
			return FALSE ;
		}

		// 指定条件ではDLL遅延通知を送り拒否を確認します
		if( copy.flags == SP_COPY_FORCE_NOOVERWRITE &&
		   activeNative->mtdScenario == MtdFixtureScenario::DLL_DELAYED &&
		   !emit( SPFILENOTIFY_FILEOPDELAYED, reinterpret_cast<UINT_PTR>( &path), 0U)) {
			SetLastError( ERROR_OPERATION_ABORTED) ;
			return FALSE ;
		}

		// copy終端通知を拒否された場合はqueueを中止します
		if( !emit( SPFILENOTIFY_ENDCOPY, reinterpret_cast<UINT_PTR>( &path), 0U)) {
			SetLastError( ERROR_OPERATION_ABORTED) ;
			return FALSE ;
		}

		// SYS copy後の未知通知を固定負例として送ります
		if( copy.flags == 0U && activeNative->mtdScenario == MtdFixtureScenario::UNKNOWN_CALLBACK &&
		   !emit( 0xdeadU, 0U, 0U)) {
			SetLastError( ERROR_OPERATION_ABORTED) ;
			return FALSE ;
		}
	}

	// subqueueとqueueの終端通知を確認します
	if( !emit( SPFILENOTIFY_ENDSUBQUEUE, FILEOP_COPY, 0U) || !emit( SPFILENOTIFY_ENDQUEUE, TRUE, 0U)) {
		SetLastError( ERROR_OPERATION_ABORTED) ;
		return FALSE ;
	}

	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同選択nodeのDIFだけを完全fake stateへ投影します
 * @param[in] code 同選択へのDIF種別です
 * @param[in] set 同fixtureのdevice集合です
 * @param[in] device 同選択deviceです
 * @return 元paramsと対象が成立した場合TRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI mtdFixtureCallInstaller( DI_FUNCTION code, HDEVINFO set, PSP_DEVINFO_DATA device)
{
	// 同人工deviceの集合indexです
	const auto index = setIndex( set) ;
	// 同人工device・選択nodeがなければDIFを拒否します
	if( !activeNative || !activeMtdFiles || index >= 32U || !device ||
	   !activeMtdFiles->hasSelected[index]) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// 同deviceの人工install parameterです
	auto &params = activeNative->parameters[index] ;
	// file DIFでは原queueとparameterを検査します
	if( code == DIF_INSTALLDEVICEFILES) {
		// file DIFが構成する所有原queueです
		auto *queue = mtdFixtureQueue( params.FileQueue) ;
		// NOVCPと原queueが成立しないfile DIFを拒否します
		if( !queue || (params.Flags & (DI_NOVCP | DI_NOFILECOPY)) != DI_NOVCP ||
		   !mtdFixtureAddSection( *queue, L"Files", 0U) ||
		   !mtdFixtureAddSection( *queue, L"SharedDlls", 0U)) {
			SetLastError( ERROR_INVALID_DATA) ;
			return FALSE ;
		}

		queue->original = true ;
		// 原queueの指定負例だけを注入します
		switch( activeNative->mtdScenario) {
			// 原queueのCOPY欠損を注入します
			case MtdFixtureScenario::QUEUE_MISSING:
				queue->copies.pop_back() ;
				break ;

			// 原COPYの重複を注入します
			case MtdFixtureScenario::QUEUE_DUPLICATE:
				queue->copies.back() = queue->copies[1] ;
				break ;

			// 元行にないCOPYを注入します
			case MtdFixtureScenario::QUEUE_EXTRA:
				queue->copies.push_back( queue->copies.back()) ;
				break ;

			// 原COPY flags差を注入します
			case MtdFixtureScenario::QUEUE_FLAGS:
				queue->copies.back().flags = SP_COPY_FORCE_NOOVERWRITE ;
				break ;

			// 原source差を注入します
			case MtdFixtureScenario::QUEUE_SOURCE:
				queue->copies.back().source += L".other" ;
				break ;

			// 同登録INFの人工Store sourceを返します
			case MtdFixtureScenario::STORE_SOURCE:
			case MtdFixtureScenario::STORE_PARENT_ADD_DIRECTORY:
				// 同人工Store packageの対応sourceへ全行を写します
				for( auto &copy : queue->copies) {
					copy.source = activeMtdFiles->storeDirectory + L"\\" +
								  std::filesystem::path{copy.source}.filename().wstring() ;
				}

				break ;

			// 指定されたqueue変更がない場合は原行を保持します
			default:
				break ;
		}

		++activeMtdFiles->filesDifs ;
		// file DIF後にparameterが変化する負例を注入します
		if( activeNative->mtdScenario == MtdFixtureScenario::PARAMS_CHANGED_AFTER_FILES) {
			params.Flags |= DI_NOFILECOPY ;
		}

		return TRUE ;
	}

	// copy充足後のNOFILECOPY指定DIFだけを評価します
	if( code == DIF_INSTALLDEVICE && !params.FileQueue &&
	   (params.Flags & (DI_NOVCP | DI_NOFILECOPY)) == DI_NOFILECOPY &&
	   activeMtdFiles->commits == 1U && device->DevInst == 1U) {
		// 同deviceで明示選択されたnodeです
		const auto &selected = activeMtdFiles->selected[index] ;
		// 同選択nodeと元INF tupleの一致です
		const bool	matches =
			selected.Reserved == 1U && selected.DriverVersion == (1ULL << 48U) &&
			std::wstring_view{selected.ProviderName} == L"Fixture Vendor" &&
			std::ranges::any_of( activeNative->stagedPaths, [&]( const auto &path) {
				return path.front() && std::wstring_view{params.DriverPath} == path.data() ;
			}) ;
		activeNative->specifiedBindingMatches &= matches ;
		// 元選択nodeのtupleが違えば指定DIFを拒否します
		if( !matches) {
			SetLastError( ERROR_INVALID_DATA) ;
			return FALSE ;
		}

		++activeMtdFiles->installDifs ;
		++activeNative->installs ;
		++activeNative->deviceInstalls[0] ;
		activeNative->storageCalls.push_back( L"mtd:dif-selected:nofilecopy") ;
		// 選択DIF自体の失敗と再起動flagsを注入します
		if( activeNative->mtdScenario == MtdFixtureScenario::INSTALL_FAILURE) {
			// 負例が再起動を要求する場合だけWindows flagsを返します
			if( !activeNative->noReboot) {
				params.Flags |= DI_NEEDREBOOT ;
			}

			SetLastError( ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}

		// fake成功を同deviceの現在nodeへ反映する条件です
		if( activeNative->reflectOwnInstall) {
			++activeNative->appliedDeviceInstalls[0] ;
			activeNative->appliedNodes[0] = selected ;
			activeNative->appliedInfNames[0] =
				std::filesystem::path( params.DriverPath).filename().wstring() ;
		}

		// 指定DIF後の保持再照合失敗を注入します
		if( activeNative->mtdScenario == MtdFixtureScenario::POST_DIF_VERIFY_FAILURE) {
			activeMtdFiles->badSecurityTarget =
				activeMtdFiles->windowsRoot + L"\\System32\\fixture-a.dll" ;
		}

		// 指定DIFの再起動見込みをWindows flagsで返します
		if( !activeNative->noReboot) {
			params.Flags |= DI_NEEDREBOOT ;
		}

		return TRUE ;
	}

	SetLastError( ERROR_INVALID_DATA) ;
	return FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief ローカルの人工クラスGUIDを登録済みの名前へ解決します
 * @param[in] guid 署名済みINFが宣言したGUIDです
 * @param[out] buffer 終端付きの登録名を返す領域です
 * @param[in] capacity 出力の文字数です
 * @param[out] required 終端込み必要文字数の任意出力です
 * @return 既登録で十分な容量があればTRUE、未登録ではERROR_INVALID_CLASSです
 */
//------------------------------------------------------------------------------
BOOL WINAPI declarativeClassName( const GUID *guid, PWSTR buffer, DWORD capacity, PDWORD required)
{
	// 違うGUIDや無効なworkerを元クラスの不存在に変えません
	if( !declarativeCase() || !guid || !IsEqualGUID( *guid, DECLARATIVE_CLASS)) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// 初回登録以前のWindowsの正式な不在を返します
	if( !declarativeRegistered()) {
		SetLastError( ERROR_INVALID_CLASS) ;
		return FALSE ;
	}

	// 元内容の読取りでは必要文字数は省略されます
	if( required) {
		*required = static_cast<DWORD>( std::size( DECLARATIVE_NAME)) ;
	}

	// 名前の部分一致を許さず、出力は全長を要求します
	if( !buffer || capacity < std::size( DECLARATIVE_NAME)) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::ranges::copy( DECLARATIVE_NAME, buffer) ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同名の人工クラス登録を逆引きします
 * @param[in] name 元のクラス名です
 * @param[out] buffer 一致する唯一のGUIDを受け取ります
 * @param[in] capacity 呼出し側のGUID容量です
 * @param[out] count 既登録は一件、未登録は零件です
 * @return 正常列挙は零件でもTRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI declarativeClassGuids( PCWSTR name, LPGUID buffer, DWORD capacity, PDWORD count)
{
	// 人工登録と対応する元名だけを逆引きします
	if( !declarativeCase() || !name || std::wstring_view{name} != DECLARATIVE_NAME || !count ||
	   !buffer || capacity != 1U) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	*count = declarativeRegistered() ? 1U : 0U ;
	// 初回登録でGUID出力へ架空の値を入れません
	if( *count) {
		*buffer = DECLARATIVE_CLASS ;
	}

	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 導入先クラスのローカル読取キーを模擬します
 * @param[in] guid 対象の独自クラスです
 * @param[in] access 値の読取り権限です
 * @param[in] flags セットアップクラスの指定です
 * @param[in] machine ローカルのためnullです
 * @param[in] reserved 予約引数です
 * @return 既登録は同workerの借用識別子、未登録はINVALID_HANDLE_VALUEです
 */
//------------------------------------------------------------------------------
HKEY WINAPI declarativeOpenClassKey( const GUID *guid, REGSAM access, DWORD flags, PCWSTR machine,
									PVOID reserved)
{
	// 実レジストリや書込み権限を必要とする要求は拒否します
	if( !declarativeCase() || !guid || !IsEqualGUID( *guid, DECLARATIVE_CLASS) ||
	   access != KEY_QUERY_VALUE || flags != DIOCR_INSTALLER || machine || reserved) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return static_cast<HKEY>( INVALID_HANDLE_VALUE) ;
	}

	// 登録名と逆引きに対応するキー不存在を独立に返します
	if( !declarativeRegistered()) {
		SetLastError( ERROR_FILE_NOT_FOUND) ;
		return static_cast<HKEY>( INVALID_HANDLE_VALUE) ;
	}

	return reinterpret_cast<HKEY>( activeNative) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 人工クラスにハンドラーとフィルターが登録されていない応答を返します
 * @param[in] guid 同workerが観測する対象クラスです
 * @param[in] key 四つのクラスプロパティのいずれかです
 * @param[out] type 要求する型の出力です
 * @param[out] buffer 容量照会で省略される領域です
 * @param[in] capacity byte単位の出力容量です
 * @param[out] required 容量照会の必要byte数です
 * @param[in] flags installerクラスの照会指定です
 * @return 対象キーの容量照会だけが正式なERROR_NOT_FOUNDです
 */
//------------------------------------------------------------------------------
BOOL WINAPI declarativeClassProperty( const GUID *guid, const DEVPROPKEY *key, DEVPROPTYPE *type,
									 PBYTE buffer, DWORD capacity, PDWORD required, DWORD flags)
{
	const bool valid = declarativeRegistered() && guid && IsEqualGUID( *guid, DECLARATIVE_CLASS) &&
					   key &&
					   (sameKey( *key, DEVPKEY_DeviceClass_ClassInstaller) ||
						sameKey( *key, DEVPKEY_DeviceClass_PropPageProvider) ||
						sameKey( *key, DEVPKEY_DeviceClass_UpperFilters) ||
						sameKey( *key, DEVPKEY_DeviceClass_LowerFilters)) &&
					   type && !buffer && capacity == 0U && required &&
					   // 正式な読取り要求です
					   flags == DICLASSPROP_INSTALLER ;
	SetLastError( valid ? ERROR_NOT_FOUND : ERROR_INVALID_PARAMETER) ;
	return FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択した元端末に能動的な登録がない状態を返します
 * @param[in] set 同workerの情報集合です
 * @param[in] device 元のクラスを持つ端末です
 * @param[in] key 端末の四つの作用プロパティのいずれかです
 * @param[out] type 要求する型を受け取る出力です
 * @param[out] buffer 容量照会時に省略される出力です
 * @param[in] capacity byte単位の出力容量です
 * @param[out] required 同じ照会の必要byte数です
 * @param[in] flags ローカル照会の予約flagsです
 * @return 元端末への完全な容量照会だけにERROR_NOT_FOUNDを返します
 */
//------------------------------------------------------------------------------
BOOL WINAPI declarativeDeviceProperty( HDEVINFO set, PSP_DEVINFO_DATA device, const DEVPROPKEY *key,
									  DEVPROPTYPE *type, PBYTE buffer, DWORD capacity,
									  PDWORD required, DWORD flags)
{
	const bool valid =
		declarativeCase() && setIndex( set) < 32U && device && device->DevInst == 1U &&
		IsEqualGUID( device->ClassGuid,
					initialState() ? GUID_DEVCLASS_UNKNOWN : DECLARATIVE_CLASS) &&
		key &&
		(sameKey( *key, DEVPKEY_Device_DriverCoInstallers) ||
		 sameKey( *key, DEVPKEY_Device_DriverPropPageProvider) ||
		 sameKey( *key, DEVPKEY_Device_UpperFilters) ||
		 sameKey( *key, DEVPKEY_Device_LowerFilters)) &&
		type && !buffer && capacity == 0U && required && flags == 0U ;	// 元端末の照会だけです
	SetLastError( valid ? ERROR_NOT_FOUND : ERROR_INVALID_PARAMETER) ;
	return FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共有コインストーラーキーの読取りを模擬します
 * @param[in] root machineローカルの定数ハンドルです
 * @param[in] path 共有キーの完全名です
 * @param[in] options 予約値です
 * @param[in] access 値を読むための権限です
 * @param[out] key 同workerだけが解放できる人工ハンドルです
 * @return 指定された読取りだけにERROR_SUCCESSを返します
 */
//------------------------------------------------------------------------------
LSTATUS WINAPI declarativeOpenKey( HKEY root, PCWSTR path, DWORD options, REGSAM access, PHKEY key)
{
	// コインストーラーのGUID別の値を他のキーの不在で補いません
	if( !declarativeCase() || root != HKEY_LOCAL_MACHINE || !path ||
	   std::wstring_view{path} != L"SYSTEM\\CurrentControlSet\\Control\\CoDeviceInstallers" ||
	   options != 0U || access != KEY_QUERY_VALUE || !key) {
		return ERROR_INVALID_PARAMETER ;
	}

	*key = reinterpret_cast<HKEY>( &activeNative->nativeCase) ;
	return ERROR_SUCCESS ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元対象クラスのコインストーラー値を明示的な不在として返します
 * @param[in] key 同workerが開いた共有キーです
 * @param[in] name 対象クラスのGUID文字列です
 * @param[in] reserved 予約引数です
 * @param[out] type レジストリ値の型出力です
 * @param[out] data 容量照会時に省略される出力です
 * @param[in,out] size 必要byte数の入出力です
 * @return 正しいGUIDの初回容量照会だけにERROR_FILE_NOT_FOUNDを返します
 */
//------------------------------------------------------------------------------
LSTATUS WINAPI declarativeReadValue( HKEY key, PCWSTR name, LPDWORD reserved, LPDWORD type,
									LPBYTE data, LPDWORD size)
{
	GUID parsed{} ;	// この値が属するGUIDの全体
	return declarativeCase() && key == reinterpret_cast<HKEY>( &activeNative->nativeCase) && name &&
				   SUCCEEDED( IIDFromString( name, &parsed)) &&
				   IsEqualGUID( parsed, DECLARATIVE_CLASS) && !reserved && type && !data && size &&
				   *size == 0
			   ? ERROR_FILE_NOT_FOUND
			   : ERROR_INVALID_PARAMETER ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同workerの二種類の読取りキーだけを受け付けます
 * @param[in] key 独自クラスまたは共有コインストーラーの人工ハンドルです
 * @return 同workerが発行したキーはERROR_SUCCESSです
 */
//------------------------------------------------------------------------------
LSTATUS WINAPI declarativeCloseKey( HKEY key)
{
	return declarativeCase() && (key == reinterpret_cast<HKEY>( activeNative) ||
								 key == reinterpret_cast<HKEY>( &activeNative->nativeCase))
			   ? ERROR_SUCCESS
			   : ERROR_INVALID_HANDLE ;
}

//------------------------------------------------------------------------------
/**
 * @brief fake stageが返したOEM INFから同じ保護領域のFileRepositoryを解決します
 * @param[in] inf ステージングが実際に返したINFの完全パスです
 * @param[in] alternate 省略したプラットフォームです
 * @param[in] locale 省略したロケールです
 * @param[out] buffer 同じ所有領域に置いた元INFのパスを返します
 * @param[in] capacity 文字単位の出力容量です
 * @param[out] required 終端込み必要文字数の任意出力です
 * @return 正規のOEM INFと全パスを確認できればTRUEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI declarativeStoreLocation( PCWSTR inf, PSP_ALTPLATFORM_INFO alternate, PCWSTR locale,
									 PWSTR buffer, DWORD capacity, PDWORD required)
{
	// ほかの登録先や実Windowsから一致するINFを探しません
	if( !declarativeCase() || !inf || activeNative->stages != 1U ||
	   std::wstring_view{inf} != activeNative->stagedPaths[0].data() || alternate || locale) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	const auto path = activeNative->registration.path( std::wstring{DECLARATIVE_STORE} +
													  L"fixture.inf") ;	// 所有Storeの元INF
	// SDKの必要長出力は省略できます
	if( required) {
		*required = static_cast<DWORD>( path.size() + 1U) ;
	}

	// 空パスまたは部分パスを返しません
	if( !buffer || path.empty() || capacity <= path.size()) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	++activeNative->declarativeStoreReads ;
	wcscpy_s( buffer, capacity, path.c_str()) ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 独自クラスの読取り境界に同じworkerのfake群を割り当てます
 * @return 実Windows関数を含まない名前・登録・全作用・配置先の完全表です
 */
//------------------------------------------------------------------------------
driver_store_inf_detail::DeclarativeClassTransport declarativeCalls()
{
	return {{declarativeClassName, declarativeClassGuids, declarativeOpenClassKey,
			 declarativeClassProperty, declarativeDeviceProperty, declarativeOpenKey,
			 declarativeReadValue, declarativeCloseKey},
			declarativeStoreLocation} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全native境界を同workerの完全fixture表へ固定します
 * @return SetupAPI/CM/NewDevの実native pointerを含まない所有tableです
 * @note 各callbackは有効scopeの同thread内でactiveNativeを同期借用し、実端末へ補完しません
 */
//------------------------------------------------------------------------------
driver_store_inf_detail::Transport calls()
{
	driver_store_inf_detail::Transport result{.inventory = {openInventory, enumInventory, property,
															instanceId, closeInventory, nodeStatus},
											  .create	 = createInventory,
											  .open		 = openDevice,
											  .build	 = buildDrivers,
											  .enumerate = enumDrivers,
											  .detail	 = driverDetail,
											  .getParameters		 = getParameters,
											  .setParameters		 = setParameters,
											  .rank					 = driverRank,
											  .destroyDrivers		 = destroyDrivers,
											  .stage				 = stage,
											  .install				 = install,
											  .architecture			 = architecture,
											  .windowsDirectory		 = windowsDirectory,
											  .infClass				 = infClass,
											  .serviceDeviceListSize = serviceDeviceListSize,
											  .serviceDeviceList	 = serviceDeviceList} ;
	// 独自クラスに限り、同じターゲットと隔離Storeにだけ応答する読取り表を使います
	if( declarativeCase()) {
		result.declarativeClass = declarativeCalls() ;
	}

	// MTD対象だけ完全低位fake表を有効にします
	if( activeNative && activeNative->mtd &&
	   activeNative->mtdScenario != MtdFixtureScenario::TABLE_EMPTY) {
		// MTD専用slot群です
		auto &mtd = result.mtd ;
		mtd		  = {.setSelected	   = mtdFixtureSetSelected,
					 .getSelected	   = mtdFixtureGetSelected,
					 .callInstaller	   = mtdFixtureCallInstaller,
					 .openQueue		   = mtdFixtureOpenQueue,
					 .queueCount	   = mtdFixtureQueueCount,
					 .scanQueue		   = mtdFixtureScanQueue,
					 .queueSection	   = mtdFixtureQueueSection,
					 .commitQueue	   = mtdFixtureCommitQueue,
					 .closeQueue	   = mtdFixtureCloseQueue,
					 .openInf		   = mtdFixtureOpenInf,
					 .closeInf		   = mtdFixtureCloseInf,
					 .storeLocation	   = mtdFixtureStoreLocation,
					 .windowsDirectory = mtdFixtureWindows,
					 .openClassKey	   = &UncalledMtdSlot<decltype( mtd.openClassKey)>::invoke,
					 .openDeviceKey	   = &UncalledMtdSlot<decltype( mtd.openDeviceKey)>::invoke,
					 .classProperty	   = mtdFixtureClassProperty,
					 .queryRegistry	   = &UncalledMtdSlot<decltype( mtd.queryRegistry)>::invoke,
					 .closeRegistry	   = &UncalledMtdSlot<decltype( mtd.closeRegistry)>::invoke,
					 .createFile	   = mtdFixtureCreate,
					 .fileInfo		   = mtdFixtureInfo,
					 .fileInfoEx	   = mtdFixtureInfoEx,
					 .finalPath		   = mtdFixtureFinalPath,
					 .freeSpace		   = mtdFixtureFreeSpace,
					 .securityInfo	   = mtdFixtureSecurity,
					 .localFree		   = mtdFixtureFree,
					 .readFile		   = mtdFixtureRead,
					 .writeFile		   = mtdFixtureWrite,
					 .flushFile		   = mtdFixtureFlush,
					 .setFileInfo	   = mtdFixtureSetInfo,
					 .closeHandle	   = mtdFixtureClose} ;
	}

	return result ;
}
/** @brief 既検証一候補を同scanへ発行し、元選択だけを実OS変更なしで導入するWUA fakeです */
class MixedManagedProvider final : public IUpdateProvider {
public:
	/**
	 * @brief 同workerの非機密counterだけを共有所有します
	 * @param[in] state 完全低位fixtureと同じ寿命の観測先です
	 */
	explicit MixedManagedProvider( std::shared_ptr<NativeFixtureState> state)
		: state_( std::move( state))
	{
	}
	/**
	 * @brief 同scanの既検証候補を一件だけ発行します
	 * @param[in] session 元workerのscanです
	 * @param[in] options 明示Provider集合です。外部通信に使用しません
	 * @param[in] progress 本fakeでは通知しない同期先です
	 * @return 同sessionの一件の表示候補です
	 */
	ScanResult scan( const ScanSessionId session, const ScanOptions &options,
					const ProviderProgressCallback &progress) override
	{
		static_cast<void>( options) ;
		static_cast<void>( progress) ;
		session_  = session ;
		consumed_ = false ;
		std::vector<UpdateCandidate>
			candidates ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
		// 同所有fixtureの全対象を順に検査します
		for( std::size_t i = 0U; i < state_->originalManagedCount;
			++i) {						// 同所有fixtureの全対象を順に確認します
			UpdateCandidate candidate ;	// 実機情報を持たない架空の管理候補です
			candidate.identity		   = L"mixed-managed-candidate" ;
			candidate.packageIdentity  = L"mixed-managed-package" ;
			candidate.deviceIdentity   = L"mixed-managed-device" ;
			candidate.providerId	   = WINDOWS_UPDATE_PROVIDER_ID ;
			candidate.model			   = L"Fictional managed adapter" ;
			candidate.title			   = candidate.model ;
			candidate.provider		   = L"Fixture Vendor" ;
			candidate.version		   = L"1.0.0.0" ;
			candidate.action		   = DriverAction::UPDATE ;
			candidate.discoveryBasis   = CandidateDiscoveryBasis::MANAGED_SERVICE ;
			candidate.audit			   = makeWindowsManagedCandidateAudit( false) ;
			candidate.installable	   = true ;
			candidate.eulaAccepted	   = true ;
			candidate.allContentCached = true ;
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( state_->originalManagedCount !=
			   1U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				const auto suffix = L"-" +
									// 元field/型の全消費を確認する局所位置又は閉じた分類です
									std::to_wstring( i) ;
				candidate.identity += suffix ;
				candidate.packageIdentity += suffix ;
				candidate.deviceIdentity += suffix ;
				candidate.model += suffix ;
				candidate.title = candidate.model ;
			}

			candidates.push_back( std::move( candidate)) ;
		}

		return {.succeeded	   = true,
				.scanSessionId = session,
				.outcome	   = OutcomeCode::SUCCESS,
				.state		   = ProviderScanState::CANDIDATES_AVAILABLE,
				.candidates	   = std::move( candidates)} ;
	}
	/**
	 * @brief 同scanの唯一の元明示選択だけへfake個別結果を返します
	 * @param[in] session scanと完全一致させる元sessionです
	 * @param[in] identities Canonical registryから渡された元選択です
	 * @param[in] parentWindow 同scopeの試験親です。外部Windowを操作しません
	 * @param[in] progress 本fakeでは通知しない同期先です
	 * @return 不正選択は失敗、正しい一件だけ実I/Oなしの個別結果です
	 */
	InstallResult install( const ScanSessionId				  session,
						  const std::span<const std::wstring> identities,
						  const std::uintptr_t				  parentWindow,
						  const ProviderProgressCallback	 &progress) override
	{
		static_cast<void>( parentWindow) ;
		static_cast<void>( progress) ;
		// 全四件の元opaque identity/session/順序/一回消費をfake自身でも照合します
		if( session == 0U || session != session_ || consumed_ ||
		   identities.size() != state_->originalManagedCount) {
			throw std::runtime_error( "managed selection binding rejected") ;
		}

		InstallResult result ;	// 同原文/操作へ結ぶ検査又は結果の所有値です
		result.succeeded	   = !state_->originalManagedFailure ;
		result.downloadOutcome = OutcomeCode::SUCCESS ;
		result.installOutcome =
			state_->originalManagedFailure ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS ;
		result.installError =
			state_->originalManagedFailure ? static_cast<NativeError>( E_ACCESSDENIED) : 0U ;
		// 同所有fixtureの全対象を順に検査します
		for( std::size_t i = 0U; i < identities.size();
			++i) {					// 同所有fixtureの全対象を順に確認します
			const auto expected =	// 固定契約から作る独立した正負の期待です
				std::wstring{L"mixed-managed-candidate"} +
				(state_->originalManagedCount == 1U ? L"" : L"-" + std::to_wstring( i)) ;
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( identities[i] !=
			   expected) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				throw std::runtime_error( "managed original ordinal rejected") ;
			}

			result.updates.push_back( {.identity		   = identities[i],
									  .downloadOutcome = OutcomeCode::SUCCESS,
									  .installOutcome  = result.installOutcome,
									  .installError	   = result.installError}) ;
		}

		consumed_ = true ;
		state_->managedInstalls += static_cast<std::uint32_t>( identities.size()) ;
		return result ;
	}

private:
	/// 同workerだけで更新するfake counterです
	std::shared_ptr<NativeFixtureState> state_ ;
	/// 一回の元scanだけへ実行を限定するsessionです
	ScanSessionId						session_{} ;
	/// 一つの元選択を二回実行しません
	bool								consumed_{} ;
} ;
/** @brief Windows復旧APIを呼ばず既存保護契約へ結果を返します */
class FakeRestore final : public IRestorePointService {
public:
	/// 同fakeの実行済みcallbackからだけ作る明示観測です
	RestorePointProtectionResult			   fakeProtection_{.disposition =
													   RestorePointDisposition::UNAVAILABLE} ;
	/**
	 * @brief 完全fakeの原開始/終了に対応した観測を返します
	 * @return 本番APIを呼ばない観測です
	 */
	[[nodiscard]] RestorePointProtectionResult protection() const noexcept override
	{
		return fakeProtection_ ;
	}

	/**
	 * @brief 復旧開始の固定成功または元失敗だけを返します
	 * @param[in] description 同期中借用する操作説明です。保存せず実復旧APIを呼びません
	 * @return 固定sequence42の成功、または元E_ACCESSDENIEDの失敗です
	 */
	RestorePointOperationResult begin(
		[[maybe_unused]] std::wstring_view description) noexcept override
	{
		const auto result = [&]() noexcept -> RestorePointOperationResult {
			// 同workerの固定復旧境界だけを観測し、実System Restoreへfallbackしません
			if( activeNative) {
				// 制御した遅延を実復旧APIへ渡さず、例外時もworker境界を越えません
				if( activeNative->beforeRestore) {
					try {
						activeNative->beforeRestore() ;
					} catch( ...) {
						return {OutcomeCode::FAILURE, static_cast<NativeError>( E_UNEXPECTED), 0} ;
					}
				}

				++activeNative->restoreBegins ;
				// 復旧開始失敗は元HRESULTを返してProvider導入を止めます
				if( activeNative->restoreFailure) {
					return {OutcomeCode::FAILURE,
							activeNative->nativeCase ==
									SignedIndexBindingNativeCase::RESTORE_DISABLED
								? static_cast<NativeError>( 0x80070422U)
								: static_cast<NativeError>( E_ACCESSDENIED),
							0} ;
				}
			}

			return {OutcomeCode::SUCCESS, 0U, 42} ;
		}() ; // 元fake API結果とcounterはそのままです
		fakeProtection_ = {.disposition	   = RestorePointDisposition::WINDOWS_SELECTED_POINT,
						   .verification   = result.outcome == OutcomeCode::SUCCESS &&
													 result.error == 0 && result.sequenceNumber > 0
												 ? OutcomeCode::SUCCESS
												 : OutcomeCode::FAILURE,
						   .error		   = result.error,
						   .sequenceNumber = result.sequenceNumber,
						   .createdUtc	   = 1,
						   .localDay	   = 20261110U,
						   .verifiedBefore = result.outcome == OutcomeCode::SUCCESS &&
											 result.error == 0 && result.sequenceNumber > 0,
						   .nativeBeginCalled = true} ;
		return result ;
	}
	/**
	 * @brief 開始済みfake sequenceの終了通知と元終了失敗を保持します
	 * @param[in] sequence 元開始が返したsequenceです
	 * @return 同sequenceの成功、または同sequenceを保持する元E_ACCESSDENIEDの失敗です
	 */
	RestorePointOperationResult complete( std::int64_t sequence) noexcept override
	{
		const auto result = [&]() noexcept -> RestorePointOperationResult {
			// 開始したfake復旧だけの終了通知回数を保持します
			if( activeNative) {
				++activeNative->restoreCompletes ;
				// 完了失敗は導入個別結果を消さずcontrollerへ元診断を返します
				if( activeNative->nativeCase == SignedIndexBindingNativeCase::RESTORE_END_FAILURE ||
				   activeNative->nativeCase ==
					   SignedIndexBindingNativeCase::INITIAL_RESTORE_END_FAILURE) {
					return {OutcomeCode::FAILURE, static_cast<NativeError>( E_ACCESSDENIED),
							sequence} ;
				}
			}

			return {OutcomeCode::SUCCESS, 0U, sequence} ;
		}() ; // 元fake API結果とcounterはそのままです
		fakeProtection_.nativeEndCalled = true ;
		fakeProtection_.verifiedAfter	= result.outcome == OutcomeCode::SUCCESS &&
										result.error == 0 &&
										result.sequenceNumber == fakeProtection_.sequenceNumber ;
		fakeProtection_.verification =
			fakeProtection_.verifiedBefore && fakeProtection_.verifiedAfter ? OutcomeCode::SUCCESS
																			: OutcomeCode::FAILURE ;
		// 元fake終了診断を実在確認へ保持します
		if( result.error != 0) {
			fakeProtection_.error = result.error ;
		}

		return result ;
	}
} ;
//------------------------------------------------------------------------------
/**
 * @brief 有限な協調待機で要求operationの実worker eventを取り出します
 * @param[in,out] worker 同期待機中生存するworkerです。queueを順に消費します
 * @param[in] kind 待機するevent種別です
 * @param[in] operation 元要求operationです
 * @param[in] timeout 既定小型fixtureは五秒、明示実archiveだけ最大600秒の待機枠です
 * @return 一致したeventの所有値、期限時はnulloptです
 * @note workerのUI側threadで使用し、mutexを保持して待ちません
 */
//------------------------------------------------------------------------------
std::optional<WorkerEvent> waitEvent( ProviderWorker &worker, WorkerEventKind kind,
									 OperationId				operation,
									 const std::chrono::seconds timeout = std::chrono::seconds{5})
{
	// 製品予算を変更せず、このtest観測だけへ有限な単調時計期限を設定します
	const auto deadline =
		std::chrono::steady_clock::now() + std::min( timeout, std::chrono::seconds{600}) ;
	// 有限期限まで同workerの実event到着を待ちます
	while( std::chrono::steady_clock::now() < deadline) {
		// 取り出した実eventを順番に確認します
		for( auto &event : worker.takeEvents()) {
			// 要求kindとoperationが完全一致したeventだけを返します
			if( event.kind == kind && event.operationId == operation) {
				return std::move( event) ;
			}
		}

		std::this_thread::sleep_for( std::chrono::milliseconds{2}) ;
	}

	return std::nullopt ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元ZIPの全member実byteから完全署名fixture期待値を作ります
 * @param[in] zip 同期解析中生存する人工ZIP全byteの借用viewです
 * @param[in] depth 0はouter、1は現在の一段nestedです。二段を拒否します
 * @return 各元INF/CAT/member名と実SHA-256を所有する集合です
 * @throws std::runtime_error 元ZIP・member・hash計算を確認できない場合です
 * @note 展開したheapは各反復で解放し、実署名や実端末の合格を発行しません
 */
//------------------------------------------------------------------------------
std::vector<driver_package_signature_detail::FixtureFile> signatureFiles( std::string_view zip,
																		 const unsigned depth = 0U)
{
	mz_zip_archive archive{} ;
	// 非空ZIPを解析できなければ正常member証拠を作りません
	if( !mz_zip_reader_init_mem( &archive, zip.data(), zip.size(), 0U)) {
		throw std::runtime_error( "fixture ZIP invalid") ;
	}

	// 全原memberの名前と実SHA-256を所有する固定期待値集合
	std::vector<driver_package_signature_detail::FixtureFile> result ;
	std::vector<std::pair<std::wstring, std::wstring>>
		catalogOwners ;	// storage人工原INFの明示CATです
	// 固定INF・SYS・CATの全実member hashを採取します
	for( mz_uint index = 0U; index < mz_zip_reader_get_num_files( &archive); ++index) {
		mz_zip_archive_file_stat stat{} ;	// 原ZIPのexact member名です
		// 未知memberを署名成功表へ取り込まず完全なdriver閉包だけを固定します
		if( !mz_zip_reader_file_stat( &archive, index, &stat) || stat.m_is_directory) {
			mz_zip_reader_end( &archive) ;
			throw std::runtime_error( "fixture member invalid") ;
		}

		const auto *name = stat.m_filename ;	// 同原containerで固定した名前です
		// 展開した現在memberのbyte数
		std::size_t bytes{} ;
		void	   *raw = mz_zip_reader_extract_file_to_heap( &archive, name, &bytes, 0U) ;
		// 欠損member時はZIPを解放してfixtureを拒否します
		if( !raw) {
			mz_zip_reader_end( &archive) ;
			throw std::runtime_error( "fixture member missing") ;
		}

		// 同反復の展開byteをmz_freeで解放する単独所有者
		const std::unique_ptr<void, decltype( &mz_free)> owner{raw, &mz_free} ;
		// 一段nestedの原memberも元byteから読み、同名同内容だけを同じ低位期待へ結びます
		if( std::string_view{name}.ends_with( ".zip")) {
			// 二段nestedは現在の有限fixtureへ取り込みません
			if( depth != 0U) {
				mz_zip_reader_end( &archive) ;
				throw std::runtime_error( "fixture nested depth invalid") ;
			}

			auto nested = signatureFiles( {static_cast<const char *>( raw), bytes},
										 depth + 1U) ;	// 同内側ZIPだけです
			result.insert( result.end(), nested.begin(), nested.end()) ;
			continue ;
		}

		// CNGで計算する同memberのSHA-256出力
		std::wstring hash ;
		// 実member全byteを署名fixtureの固定期待hashへ結ぶ計算結果
		const auto	 error =
			computeBytesSha256( std::string_view{static_cast<const char *>( raw), bytes}, hash) ;
		// 実member hash失敗を署名成功fixtureへ換算しません
		if( error != 0U) {
			mz_zip_reader_end( &archive) ;
			throw std::runtime_error( "fixture member hash failure") ;
		}

		// 固定ASCII member名を所有するWindows文字列
		std::wstring wide ;
		// 固定ASCII member名をlosslessにWindows名へ変換します
		for( const char character : std::string_view{name}) {
			wide.push_back( static_cast<wchar_t>( character)) ;
		}

		std::replace( wide.begin(), wide.end(), L'/',
					 L'\\') ;	// 実ZIP位置を既存workspaceと同じ区切りへ保持します
		// shared CATの関係も、同人工INFが明示する元byteから読みます
		if( (zip.find( "Class=SCSIAdapter\r\n") != zip.npos ||
			zip.find( "Class=MediumChanger\r\n") != zip.npos ||
			zip.find( "Class=HDC\r\n") != zip.npos || zip.find( "Class=MTD\r\n") != zip.npos) &&
		   wide.ends_with( L".inf")) {
			// 同人工INFの全元byteを同期借用します
			const std::string_view	   body{static_cast<const char *>( raw), bytes} ;
			// 元節内の行位置/key/全fieldです
			constexpr std::string_view directive = "\nCatalogFile=" ;
			// 元field又は原sectionの開始位置です
			const auto				   start = body.find( directive) ;
			// 各人工INFが明示するCAT名だけを共有関係へ固定します
			if( start != body.npos) {
				// 元全byte又は文字列要素の先頭です
				const auto	 first = start + directive.size() ;
				// 元fieldの正式終端です
				const auto	 last = body.find( "\r\n", first) ;
				// 同原INFが明示するCAT名です
				const auto	 declaredCatalog = body.substr( first, last - first) ;
				// 同じ原CAT byteの所有位置又は名前です
				std::wstring catalog ;
				// 人工ASCIIの原CAT名だけをlosslessに変換します
				for( const auto character : declaredCatalog) {
					catalog.push_back( static_cast<wchar_t>( character)) ;
				}

				catalogOwners.emplace_back( std::move( catalog), wide) ;
			}
		}

		const auto dot = wide.find_last_of( L'.') ;	// 各完全閉包のbasename境界です
		const auto ownerName =
			// EXEは同原サービスINFの固定ownerで、basenameから別INFを生成しません
			(zip.find( "Class=MTD\r\n") != zip.npos &&
			 (wide == L"fixture-a.dll" || wide == L"fixture-b.dll"))
				? std::wstring{L"fixture.inf"}
			: wide == L"component_service.exe" || wide == L"extra.exe" ||
					wide == L"service_bin\\component_service.exe" ||
					wide == L"service_bin\\amd64\\component_service.exe" ||
					wide == L"source_bin\\component_service.exe" ||
					wide == L"service_bin\\extra.exe" || wide == L"media\\component_service.exe" ||
					wide == L"media\\service_bin\\component_service.exe" ||
					wide == L"media\\amd64\\service_bin\\nested\\component_service.exe" ||
					wide == L"media\\source_bin\\component_service.exe" ||
					wide == L"media2\\component_service.exe" || wide == L"media\\extra.exe" ||
					wide == L"other_media\\component_service.exe"
				? std::wstring{L"component.inf"}
				: wide.substr( 0U, dot) + L".inf" ;
		result.push_back( {std::move( wide), std::move( hash), ownerName}) ;
	}

	mz_zip_reader_end( &archive) ;
	// 複数owned workspaceに現れる同名同内容を一つの厳密期待へ結び、別byteは拒否します
	std::vector<driver_package_signature_detail::FixtureFile>
		unique ;	// 同名/同hash/同ownerだけの集合です
	// 全元memberを同名の原byte/ownerへ対応させます
	for( const auto &file : result) {
		const auto previous = std::ranges::find_if( unique, [&]( const auto &value) {
			return value.name == file.name ;
		}) ; // 同相対memberだけです
		// 初回の原memberだけを期待集合へ追加します
		if( previous == unique.end()) {
			unique.push_back( file) ;
			continue ;
		}

		// 同名でも別byteやownerなら署名期待を流用しません
		if( previous->sha256 != file.sha256 || previous->infOwner != file.infOwner) {
			throw std::runtime_error( "fixture same member different bytes") ;
		}
	}

	// 同CAT原byteを別ownerとして複製せず、各INFの明示した共有関係だけを保持します
	for( const auto &[name, owner] : catalogOwners) {
		// 元byteを同期中だけ保持する読取専用fileです
		const auto file =
			std::ranges::find( unique, name, &driver_package_signature_detail::FixtureFile::name) ;
		// 同一CATの元owner以外だけを明示aliasへ追加します
		if( file != unique.end() && file->infOwner != owner &&
		   std::ranges::find( file->additionalInfOwners, owner) == file->additionalInfOwners.end()) {
			file->additionalInfOwners.push_back( owner) ;
		}
	}

	return unique ;
}
}
// tests/unit/signed_index_candidate_binding_tests.hの同宣言を契約の正本とする
//------------------------------------------------------------------------------
/**
 * @brief 二deviceまでの固定低位Windows境界を実workerへ結びます
 * @param[in] services 真署名隔離store・完全HTTP・固定UTCの所有callbackです
 * @param[in] zip 全member hashを固定する非空原ZIPです。欠損CAT負例は期待表だけを完全にします
 * @param[in] partial 二record/二deviceを作ります。共有正常条件以外では二番目指定導入だけを失敗させます
 * @param[in] restoreFailure 復旧開始を拒否しProviderへ到達させません
 * @param[in] stagingFailure SetupCopyOEMInfWだけを元ERROR_ACCESS_DENIEDで拒否します
 * @param[in] nativeCase 元Windows property/node/rank/登録先へ与える有限状態です
 * @param[in] installerPayload 原実byteを完全署名/起動fakeで確認する架空EXE/MSIです
 * @param[in] observeWorkerStart 低位署名scope開始時の同期観測です。空は何もしません。Worker停止まで所有し、callback自身が借用stateの寿命を保持
 *                   します。署名検証の返却値を変更しません
 * @param[in] beforeRestore fake復旧開始直前の有限な同期callbackです。空は何もしません。同workerだけが呼び、callbackは借用状態を所有します。例外は
 *                   fake復旧失敗へ変換します
 * @param[in] reflectOwnInstall 指定API成功後に当該deviceだけの現在状態を反映する場合trueです
 * @param[in] batchFault 第一指定成功後だけ第二または元byte/期限へ与える低位拒否入力です
 * @param[in] localDriverCandidates 同じ二nativeの互換Driver Store新版を発行する有限条件です
 * @param[in] noReboot この正常caseだけ再起動要求を返さない場合trueです
 * @param[in] opaqueCompatibleId 非空時はWindows側Compatible IDだけへ同じASCII literalを返します
 * @param[in] original 元公開record/原archiveの完全私有入力です。nullは既架空fixtureです
 * @param[in] mtdScenario MTD同原copyにだけ与える低位fake条件です
 * @return 実workerと非機密call観測。Native成功fallbackはありません
 */
//------------------------------------------------------------------------------
SignedIndexBindingWorker makeSignedIndexBindingWorker(
	provider_worker_index_detail::Services services, const std::string_view zip, const bool partial,
	const bool restoreFailure, const bool stagingFailure,
	const SignedIndexBindingNativeCase nativeCase, const std::string_view installerPayload,
	std::function<void()> observeWorkerStart, std::function<void()> beforeRestore,
	const bool reflectOwnInstall, const SignedIndexBindingBatchFault batchFault,
	const bool localDriverCandidates, const bool noReboot, std::wstring opaqueCompatibleId,
	const OriginalSelectionBindingInput *original, const MtdFixtureScenario mtdScenario)
{

	auto native			= std::make_shared<NativeFixtureState>() ;	// 同worker低位状態の共有所有です
	native->mtd			= zip.find( "Class=MTD\r\n") != std::string_view::npos ;
	native->mtdScenario = mtdScenario ;
	// MTD人工archiveから各元memberを一回固定します
	if( native->mtd) {
		mz_zip_archive archive{} ;
		// 人工archiveを開けなければfixtureを中止します
		if( !mz_zip_reader_init_mem( &archive, zip.data(), zip.size(), 0U)) {
			throw std::runtime_error( "MTD fixture archive unavailable") ;
		}

		// 二DLL・SYS・INFを原順に人工archiveから読みます
		for( std::size_t index = 0U; index < native->mtdDllBodies.size() + 2U; ++index) {
			// 人工archiveから抽出したmemberのbyte数です
			std::size_t bytes{} ;
			// 原順の人工member名です
			const char *name = index == 0U	 ? "fixture-a.dll"
							   : index == 1U ? "fixture-b.dll"
							   : index == 2U ? "fixture.sys"
											 : "fixture.inf" ;
			void	   *body = mz_zip_reader_extract_file_to_heap( &archive, name, &bytes, 0U) ;
			// member欠損や予定外sizeをfixture成功にしません
			if( !body || (index < 3U && bytes != 1024U) || bytes == 0U || bytes > 1048576U) {
				// 抽出済みbufferだけを解放します
				if( body) {
					mz_free( body) ;
				}

				mz_zip_reader_end( &archive) ;
				throw std::runtime_error( "MTD fixture member unavailable") ;
			}

			// 抽出した原member byteの保存先です
			auto &destination = index < native->mtdDllBodies.size() ? native->mtdDllBodies[index]
								: index == 2U						? native->mtdSysBody
																	: native->mtdInfBody ;
			destination.assign( static_cast<const char *>( body), bytes) ;
			mz_free( body) ;
		}

		mz_zip_reader_end( &archive) ;
	}

	native->mediumChanger = zip.find( "Class=MediumChanger\r\n") != zip.npos ;
	native->hdc			  = zip.find( "Class=HDC\r\n") != zip.npos ;
	native->storage		  = native->mtd || native->mediumChanger || native->hdc ||
					  zip.find( "Class=SCSIAdapter\r\n") != zip.npos ;
	// storageだけ元native再起動値をTRUEにします。別FALSE caseはnoRebootへ結びます
	if( native->storage) {
		native->mode = 4U ;
	}

	native->opaqueCompatibleId = std::move( opaqueCompatibleId) ;
	native->beforeRestore	   = std::move( beforeRestore) ;
	// 固定した入力条件だけを分離し、他対象や期待へ流用しません
	if( original) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
		// 固定した入力条件だけを分離し、他対象や期待へ流用しません
		if( original->devices.size() != 4U ||
		   original->infs.size() !=
			   3U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			throw std::runtime_error( "original binding shape rejected") ;
		}

		native->distributionDevices	   = original->devices ;
		native->originalInfs		   = original->infs ;
		native->originalIntelArchive   = true ;
		native->originalManagedCount   = 4U ;
		native->originalManagedFailure = original->managedFailure ;
	}

	native->reflectOwnInstall	  = reflectOwnInstall ;
	native->localDriverCandidates = localDriverCandidates ;
	native->noReboot			  = noReboot ;
	native->batchFault			  = batchFault ;
	const auto originalUtc		  = services.utc ;	// 原信頼時刻callbackを同workerだけで借用します
	// 第一成功前は元UTC/byteを保ち、第二前だけ期限または実byteを一回変更します
	services.utc = [native, originalUtc]() -> std::optional<std::chrono::sys_seconds> {
		const auto now = originalUtc ? originalUtc() : std::nullopt ;	// 欠測は補完しません
		// 最初の配置前、および元Storeを再確認した実適用直前のそれぞれで元recordを失効させます
		if( now &&
		   ((native->nativeCase == SignedIndexBindingNativeCase::DECLARATIVE_EXPIRED_BEFORE_STAGE &&
			 native->declarativePreStageRootReads != 0U) ||
			(native->nativeCase == SignedIndexBindingNativeCase::DECLARATIVE_EXPIRED_AFTER_STAGE &&
			 native->declarativeStoreReads != 0U))) {
			return *now + std::chrono::minutes{4} ;
		}

		// 指定した作用境界だけ同Clockを元期限後へ進めます
		if( now && ((native->mtdScenario == MtdFixtureScenario::EXPIRED_BEFORE_STAGE &&
					native->mtdFiles.windowsRootChecks != 0U && native->stages == 0U) ||
				   (native->mtdScenario == MtdFixtureScenario::EXPIRED_BEFORE_FILE_DIF &&
					native->mtdFiles.selectedSets != 0U && native->mtdFiles.filesDifs == 0U) ||
				   (native->mtdScenario == MtdFixtureScenario::EXPIRED_BEFORE_SHARED &&
					native->mtdFiles.queueScans >= 2U && native->mtdFiles.flushes == 0U) ||
				   (native->mtdScenario == MtdFixtureScenario::EXPIRED_BEFORE_FIRST_RENAME &&
					native->mtdFiles.flushes >= 1U && native->mtdFiles.successfulRenames == 0U) ||
				   (native->mtdScenario == MtdFixtureScenario::EXPIRED_BEFORE_SECOND_RENAME &&
					native->mtdFiles.flushes >= 2U && native->mtdFiles.successfulRenames == 1U) ||
				   (native->mtdScenario == MtdFixtureScenario::EXPIRED_BEFORE_COMMIT &&
					native->mtdFiles.successfulRenames >= 2U && native->mtdFiles.commits == 0U) ||
				   (native->mtdScenario == MtdFixtureScenario::EXPIRED_AFTER_COMMIT &&
					native->mtdFiles.commits != 0U))) {
			return *now + std::chrono::days{3650} ;
		}

		// 元内容成功後のexpiryだけを変え、service/rank変化から分離します
		if( now && native->changed &&
		   native->nativeCase == SignedIndexBindingNativeCase::STORAGE_EXPIRED) {
			return *now + std::chrono::days{3650} ;
		}

		// 実fake指定成功後だけ負例を発生させ、準備時の成功根拠は変更しません
		if( native->reflectOwnInstall && native->appliedDeviceInstalls[0] != 0U) {
			// 原期限を延長せず、後続の元期限切れ拒否を確認します
			if( native->batchFault == SignedIndexBindingBatchFault::RECORD_EXPIRED && now) {
				return *now + std::chrono::days{3650} ;
			}

			// 元保護INFの全byte検査が第二でも必須であることを実fileで確認します
			if( native->batchFault == SignedIndexBindingBatchFault::CONTENT_CHANGED &&
			   !native->batchContentChanged) {
				// 隔離workspaceの元候補INFだけを一回変更し、実Windows登録先へ触れません
				for( const auto &path : native->sourceInfs) {
					// 保護された人工source INF一件を選び、別形式のfileは変更しません
					if( std::filesystem::path{path}.filename() == L"fixture.inf" &&
					   !path.starts_with( native->windowsRoot)) {
						std::ofstream stream{std::filesystem::path{path},
											 std::ios::binary |
												 std::ios::app} ;	// 同元byteへの有限一回追記です
						stream << "; changed second batch INF\r\n" ;
						stream.close() ;
						// 書換失敗を製品側拒否成功へ数えません
						if( stream.fail()) {
							throw std::runtime_error( "batch source mutation failed") ;
						}

						native->batchContentChanged = true ;
						break ;
					}
				}

				// 未到達の負例を内容再検証成功と混同しません
				if( !native->batchContentChanged) {
					throw std::runtime_error( "batch source unavailable") ;
				}
			}
		}

		return now ;
	} ; // 元結果DTOやprivate proofを直接変更しません
	native->requiredRoles = zip.find( "extension.inf") != std::string_view::npos ||
							zip.find( "component.inf") != std::string_view::npos ;
	native->componentChild = zip.find( "component.inf") != std::string_view::npos ;
	native->multiple	   = partial ||
					   nativeCase == SignedIndexBindingNativeCase::INDEX_VERIFIED_PARTIAL ||
					   nativeCase == SignedIndexBindingNativeCase::INDEX_NON_UNIQUE ||
					   nativeCase == SignedIndexBindingNativeCase::INITIAL_SAME_ID ||
					   nativeCase == SignedIndexBindingNativeCase::INITIAL_SAME_ID_OTHER_INCOMPLETE ;
	native->partialFailure = partial &&
							 nativeCase != SignedIndexBindingNativeCase::SHARED_SUCCESS &&
							 nativeCase != SignedIndexBindingNativeCase::SHARED_SECTION_SUCCESS ;
	native->nativeCase	   = nativeCase ;
	native->restoreFailure = restoreFailure ;
	native->stagingFailure = stagingFailure ;
	// 同版の既導入baseでも明示指定導入のcallを別観測します
	if( nativeCase == SignedIndexBindingNativeCase::EXTENSION_BASE_ALREADY_CURRENT) {
		native->currentVersion = L"1.0.0.0" ;
	}

	// 元通常publicationの同版分類を、DTO変更なしで原Windows現在観測へ結びます
	if( nativeCase == SignedIndexBindingNativeCase::NORMAL_SAME_VERSION) {
		native->currentVersion = L"1.0.0.0" ;
	}

	// 版だけを理由に通常の旧版明示選択を拒否させません
	if( nativeCase == SignedIndexBindingNativeCase::STORAGE_OLDER) {
		native->currentVersion = L"2.0.0.0" ;
	}

	auto	   files = signatureFiles( zip) ;	// 全原memberを同じ実byte期待値へ固定します
	const bool missingImportCatalog =
		!native->storage &&
		// 固定欠損CAT負例だけを完全低位期待表へ通します
		std::ranges::any_of( files,
							[]( const auto &file) { return file.name == L"importonly.inf" ; }) &&
		!std::ranges::any_of( files,
							 []( const auto &file) { return file.name == L"importonly.cat" ; }) ;
	// 実CATを生成せず、製品が実file欠損を拒否する完全API表を作ります
	if( missingImportCatalog) {
		const auto catalog = std::ranges::find_if( files, []( const auto &file) {
			return file.name == L"fixture.cat" ;
		}) ; // 同一人工CAT byteです
		// 既知の元CAT期待値がない表を正常fixtureへ補完しません
		if( catalog == files.end()) {
			throw std::runtime_error( "Missing catalog fixture expectation unavailable") ;
		}

		files.push_back( {L"importonly.cat", catalog->sha256, L"importonly.inf"}) ;
	}

	const bool missingComponentCatalog =	// 新C87の実欠損を期待表だけへ通します
		std::ranges::any_of( files,
							[]( const auto &file) { return file.name == L"component.inf" ; }) &&
		!std::ranges::any_of( files, []( const auto &file) { return file.name == L"component.cat" ; }) ;
	// 元CAT byteを生成せず、製品の実FILE_NOT_FOUND拒否まで完全API表を開始します
	if( missingComponentCatalog) {
		const auto catalog = std::ranges::find_if( files, []( const auto &file) {
			return file.name == L"fixture.cat" ;
		}) ; // 元人工CATの期待hashです
		// 期待値のない欠損表を成功fixtureへ補完しません
		if( catalog == files.end()) {
			throw std::runtime_error( "Missing component catalog expectation unavailable") ;
		}

		files.push_back( {L"component.cat", catalog->sha256, L"component.inf"}) ;
	}

	// 原サービスEXE全byteを維持し、署名低位の一期待値だけを拒否条件にします
	if( nativeCase == SignedIndexBindingNativeCase::SERVICE_EXE_MEMBER_FAILURE ||
	   nativeCase == SignedIndexBindingNativeCase::SERVICE_EXE_OTHER_OWNER) {
		// 全元memberのうちサービスEXEだけを変更し、他ownerの期待値を保存します
		for( auto &file : files) {
			// 原EXE名の完全一致だけを拒否入力へ与えます
			if( file.name == L"component_service.exe" ||
			   file.name == L"service_bin\\component_service.exe" ||
			   file.name == L"media\\component_service.exe") {
				// CAT memberの所有者拒否と実hash拒否を独立の元条件にします
				if( nativeCase == SignedIndexBindingNativeCase::SERVICE_EXE_OTHER_OWNER) {
					file.infOwner = L"fixture.inf" ;
				} else {
					file.sha256.front() = file.sha256.front() == L'0' ? L'1' : L'0' ;
				}
			}
		}
	}

	// 一つのCAT期待hash差だけを署名低位表へ入れ、実CAB byteと元payload hashを保持します
	if( nativeCase == SignedIndexBindingNativeCase::CAB_MEMBER_FAILURE) {
		// 元閉包のCATだけを識別し、他のINF/SYS期待値を変更しません
		for( auto &file : files) {
			// 実hashとの差を必ず一hex文字だけに固定します
			if( file.name.ends_with( L".cat") && !file.sha256.empty()) {
				file.sha256.front() = file.sha256.front() == L'0' ? L'1' : L'0' ;
			}
		}
	}

	// 選択外import一ownerのCAT失敗もbase閉包全体の拒否へ残します
	if( nativeCase == SignedIndexBindingNativeCase::IMPORT_MEMBER_FAILURE) {
		// 元import-only CATの期待hashだけを変更し、原payloadを不変更で保持します
		for( auto &file : files) {
			// 別ownerの成功で未選択CAT失敗を隠しません
			if( file.name == L"importonly.cat" && !file.sha256.empty()) {
				file.sha256.front() = file.sha256.front() == L'0' ? L'1' : L'0' ;
			}
		}
	}

	auto signature = std::make_shared<driver_package_signature_detail::ScopedFixture *>(
		nullptr) ;	// 停止前だけ借用します
	/** @brief 同worker threadの完全な人工Driver Store表を開始します
	 * @return 登録rootが生成できた完全scope。失敗時は空でnativeへ補完しません
	 */
	services.driverStoreFixture = [native]() {
		activeNative = native.get() ;
		// 完全rootを生成できなければ不完全fakeを製品へ渡しません
		if( !initializeRegistration( *native)) {
			return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
		}

		// MTD fixtureだけ一意所有workspaceへWindows pathを写像します
		if( native->mtd) {
			// 論理Windows rootを受け取るbufferです
			std::array<wchar_t, MAX_PATH> root{} ;
			// Windows rootの返却文字数です
			const auto length = ::GetWindowsDirectoryW( root.data(), static_cast<UINT>( root.size())) ;
			// Windows rootの取得失敗や不正pathでfixtureを止めます
			if( length < 3U || length >= root.size() || root[1] != L':' || root[2] != L'\\') {
				return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
			}

			// 同workerのMTD所有file状態です
			auto &files	   = native->mtdFiles ;
			files.scenario = native->mtdScenario ;
			files.windowsRoot.assign( root.data(), length) ;
			files.logicalVolume	 = files.windowsRoot.substr( 0U, 3U) ;
			files.physicalVolume = native->registration.path( L"mtd-virtual") ;
			// 所有System32の写像先を固定するmarker pathです
			const auto markerPath = L"mtd-virtual\\" + files.windowsRoot.substr( 3U) +
									L"\\System32\\drivers\\marker.tmp" ;
			// 所有markerのfile handleです
			HANDLE marker = INVALID_HANDLE_VALUE ;
			// 所有volumeとmarkerを準備できなければfixtureを止めます
			if( files.physicalVolume.empty() ||
			   native->registration.createFile( markerPath, marker) != 0U) {
				return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
			}

			::CloseHandle( marker) ;
			// 同登録INFの人工Store sourceを使う条件です
			if( native->mtdScenario == MtdFixtureScenario::STORE_SOURCE ||
			   native->mtdScenario == MtdFixtureScenario::STORE_PARENT_ADD_DIRECTORY) {
				// 同原INFに結ぶ人工Store package名です
				constexpr std::wstring_view package = L"fixture.inf_amd64_0000000000000000" ;
				files.storeDirectory				= files.windowsRoot +
									   L"\\System32\\DriverStore\\FileRepository\\" +
									   std::wstring{package} ;
				// 所有workspace内の人工Store package pathです
				const auto prefix = L"mtd-virtual\\" + files.windowsRoot.substr( 3U) +
									L"\\System32\\DriverStore\\FileRepository\\" +
									std::wstring{package} + L"\\" ;
				// 同原INF・SYS・二DLLの人工Store memberです
				const std::array<std::pair<std::wstring_view, std::string_view>, 4U> members{
					{{L"fixture.inf", native->mtdInfBody},
					 {L"fixture.sys", native->mtdSysBody},
					 {L"fixture-a.dll", native->mtdDllBodies[0]},
					 {L"fixture-b.dll", native->mtdDllBodies[1]}}} ;
				// 同原INFと全人工memberを所有Storeへ書きます
				for( const auto &[name, body] : members) {
					// 現在作る所有memberのhandleです
					HANDLE file = INVALID_HANDLE_VALUE ;
					// 所有memberを作れなければfixtureを成立させません
					if( native->registration.createFile( prefix + std::wstring{name}, file) != 0U) {
						return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
					}

					// 人工memberへwriteしたbyte数です
					DWORD	   written{} ;
					// 人工memberの全write成否です
					const auto ok = ::WriteFile( file, body.data(), static_cast<DWORD>( body.size()),
												&written, nullptr) &&
									written == body.size() ;
					::CloseHandle( file) ;
					// 人工Store memberの部分writeを成功にしません
					if( !ok) {
						return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
					}
				}
			}

			// 人工SYSの所有pathです
			const auto systemPath = L"mtd-virtual\\" + files.windowsRoot.substr( 3U) +
									L"\\System32\\drivers\\fixture.sys" ;
			// 初回device条件と旧SYS存在を分離します
			if( native->nativeCase == SignedIndexBindingNativeCase::INITIAL) {
				// 不在SYSを保持する外部file予約名です
				std::wstring reserved ;
				// 新規SYSの所有予約が失敗した場合は止めます
				if( native->registration.prepareExternalFile( systemPath, reserved) != 0U) {
					return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
				}
			} else {
				// 旧SYS fixtureの所有handleです
				HANDLE old = INVALID_HANDLE_VALUE ;
				// 旧SYS fixtureを作れなければ止めます
				if( native->registration.createFile( systemPath, old) != 0U) {
					return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
				}

				// 旧SYSとして保存する識別用byteです
				constexpr std::string_view previous = "owned previous system driver" ;
				// 旧SYSへwriteしたbyte数です
				DWORD					   written{} ;
				// 旧SYSの全write成否です
				const auto				   ok =
					::WriteFile( old, previous.data(), static_cast<DWORD>( previous.size()), &written,
								nullptr) &&
					written == previous.size() ;
				::CloseHandle( old) ;
				// 旧SYSの部分writeを成功にしません
				if( !ok) {
					return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
				}
			}

			// 二DLLを各指定条件に従って用意します
			for( std::size_t index = 0U; index < native->mtdDllBodies.size(); ++index) {
				// 今回準備する人工DLL名です
				const auto name = index == 0U ? L"fixture-a.dll" : L"fixture-b.dll" ;
				// DLL targetを写像した所有相対pathです
				const auto relative =
					L"mtd-virtual\\" + files.windowsRoot.substr( 3U) + L"\\System32\\" + name ;
				// 指定scenarioで同DLLを事前に作るかの判定です
				const bool existing =
					native->mtdScenario == MtdFixtureScenario::BOTH_EXIST ||
					(native->mtdScenario == MtdFixtureScenario::MIXED && index == 0U) ||
					((native->mtdScenario == MtdFixtureScenario::FOREIGN_EXISTING ||
					  native->mtdScenario == MtdFixtureScenario::BAD_DACL ||
					  native->mtdScenario == MtdFixtureScenario::BAD_OWNER ||
					  native->mtdScenario == MtdFixtureScenario::EXISTING_WRITER ||
					  native->mtdScenario == MtdFixtureScenario::REPARSE_TARGET ||
					  native->mtdScenario == MtdFixtureScenario::HARDLINK_TARGET ||
					  native->mtdScenario == MtdFixtureScenario::READ_FAILURE) &&
					 index == 0U) ;
				// 既存条件では同byteまたは指定した異byteを事前に作ります
				if( existing) {
					// 既存DLLの所有handleです
					HANDLE handle = INVALID_HANDLE_VALUE ;
					// 所有targetを作れなければfixtureを止めます
					if( native->registration.createFile( relative, handle) != 0U) {
						return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
					}

					// 既存DLLへ書く元byteまたは異byte負例です
					auto body = native->mtdDllBodies[index] ;
					// 異byte既存の負例だけ原DLLの一byteを変えます
					if( native->mtdScenario == MtdFixtureScenario::FOREIGN_EXISTING) {
						body[0] ^= 1 ;
					}

					// 既存DLLへwriteしたbyte数です
					DWORD	   written{} ;
					// 既存DLLの全write成否です
					const auto ok =
						::WriteFile( handle, body.data(), static_cast<DWORD>( body.size()), &written,
									nullptr) &&
						written == body.size() ;
					// 既存DLLの元file IDです
					FILE_ID_INFO identity{} ;
					// 既存DLL file IDの取得成否です
					const bool	 hasIdentity =
						::GetFileInformationByHandleEx( handle, FileIdInfo, &identity,
													   sizeof( identity)) != FALSE ;
					::CloseHandle( handle) ;
					// 既存DLLの全writeとfile ID観測を要求します
					if( !ok || !hasIdentity) {
						return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
					}

					files.initialTargetIds[index] = identity ;
				} else {
					// 不在DLLを保持する外部file予約名です
					std::wstring reserved ;
					// 不在targetの所有予約を作れなければ止めます
					if( native->registration.prepareExternalFile( relative, reserved) != 0U) {
						return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
					}
				}
			}

			// 指定targetだけ不正DACLとして観測させます
			if( native->mtdScenario == MtdFixtureScenario::BAD_DACL) {
				files.badSecurityTarget = files.windowsRoot + L"\\System32\\fixture-a.dll" ;
			}

			// 既存writerの負例だけ所有writerを保持します
			if( native->mtdScenario == MtdFixtureScenario::EXISTING_WRITER) {
				// 競合writerが開く所有targetの相対pathです
				const auto relative =
					L"mtd-virtual\\" + files.windowsRoot.substr( 3U) + L"\\System32\\fixture-a.dll" ;
				files.existingWriter =
					::CreateFileW( native->registration.path( relative).c_str(), GENERIC_WRITE,
								  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
								  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;
				// 競合writerを開けなければ負例を実行しません
				if( files.existingWriter == INVALID_HANDLE_VALUE) {
					return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
				}
			}

			// 指定されたtemp write順で部分失敗を注入します
			if( native->mtdScenario == MtdFixtureScenario::PARTIAL_WRITE) {
				files.failWriteOrdinal = 1U ;
			}

			// rename直前に同byteまたは異byteの競合を用意します
			if( native->mtdScenario == MtdFixtureScenario::RACE_DIFFERENT ||
			   native->mtdScenario == MtdFixtureScenario::RACE_SAME) {
				files.raceTarget = files.windowsRoot + L"\\System32\\fixture-a.dll" ;
				files.raceBytes	 = native->mtdDllBodies[0] ;
				// 異byte競合だけ一byteを変えます
				if( native->mtdScenario == MtdFixtureScenario::RACE_DIFFERENT) {
					files.raceBytes[0] ^= 1 ;
				}
			}

			// 未知handler登録の固定負例を用意します
			if( native->mtdScenario == MtdFixtureScenario::HANDLER_PRESENT) {
				// 未知handlerとして返す人工文字列です
				const std::array<wchar_t, 2U> value{L'x', L'\0'} ;
				files.classInstaller.error = ERROR_SUCCESS ;
				files.classInstaller.type  = DEVPROP_TYPE_STRING ;
				files.classInstaller.bytes.resize( sizeof( value)) ;
				std::memcpy( files.classInstaller.bytes.data(), value.data(), sizeof( value)) ;
			}
			// handler propertyの権限失敗を注入します
			else if( native->mtdScenario == MtdFixtureScenario::HANDLER_DENIED) {
				files.classInstaller.error = ERROR_ACCESS_DENIED ;
			}

			activeMtdFiles = &files ;
		}

		return driver_store_inf_detail::Access::create( calls()) ;
	} ; // 一workerの同threadに完全な低位呼出し表を固定します
	/** @brief 全原member hashへ結合したCAT検証scopeを開始します
	 * @return Worker終端まで所有する完全scopeです。観測pointerは同threadだけで借用します
	 */
	services.signatureFixture = [files, signature, partial,
								 observeWorkerStart = std::move( observeWorkerStart)]() {
		// 空でない内部観測だけを同workerへ登録し、元署名scopeの検証結果は変更しません
		if( observeWorkerStart) {
			observeWorkerStart() ;
		}

		auto scope = driver_package_signature_detail::Access::create(
			files, 129U) ;	// 共通archive128上限の超過一件も完全閉包として検証します
		*signature = scope.get() ;
		return scope ;
	} ; // 二recordでは二保護rootを実hashへ固定します
	/** @brief 既存byteと同worker署名表に完全五APIを結びます
	 * @return 実OS trustへfallbackしない所有scopeです
	 */
	services.dependencyFixture = [native]() {
		inf_dependency_native_detail::Api api ;	// 必須五APIを全て所有します
		// 同NativeLoaderの全終了検査済みtupleだけを証拠へ借用します
		if( native->storage) {
			api.observedResult = [native]( const InfDependencyNativeResult &result) {
				native->originalEffects.push_back( result) ;
			} ;
		}

		// 登録後に元の起動順だけを変え、適用直前の再照合を検証する
		if( (native->mediumChanger || native->hdc) &&
		   native->nativeCase != SignedIndexBindingNativeCase::STORAGE_LOAD_ORDER_MISSING) {
			api.storageLoadOrder = [native]( StorageLoadOrder &out) -> NativeError {
				// 元観測の成立後、登録後の照合だけに変更した順序を返す
				const bool moved = native->stages != 0U &&
								   native->nativeCase ==
									   SignedIndexBindingNativeCase::STORAGE_LOAD_ORDER_AFTER_STAGE ;
				// IDEは対象の位置を保ったまま、先行する二グループの順序を入れ替える
				if( native->hdc) {
					constexpr wchar_t original[] =
						L"Boot Bus Extender\0Boot File System\0System Bus Extender\0" ;	// 元の起動順
					constexpr wchar_t reordered[] =
						L"Boot File System\0Boot Bus Extender\0System Bus Extender\0" ;	// 登録後の起動順
					return moved ? inspectStorageLoadOrder( reordered, out, true)
								 : inspectStorageLoadOrder( original, out, true) ;
				}

				out = {5U, moved ? 9U : 8U, std::nullopt, {}} ;
				return 0U ;
			} ;
		}

		// exact新serviceの正式不存在だけを返し、実SCMへfallbackしません
		api.storageService = [native]( std::wstring_view		 name,
									  SystemServiceEvidence &out) -> NativeError {
			out = {} ;
			// 全graphの関連service宣言数です
			const bool associated = name == L"FixtureStorage" && storageServicePresent() ;
			// 現在serviceと区別する元Windows依存の分類です
			const bool dependency = name == L"InboxFixture" || name == L"ExternalFixture" ;
			// 正式不存在だけを返し、未設定/照会失敗とは区別します
			if( !associated && !dependency) {
				return HRESULT_FROM_WIN32( ERROR_SERVICE_DOES_NOT_EXIST) ;
			}

			out.name		 = name ;
			out.type		 = SERVICE_KERNEL_DRIVER ;
			out.start		 = associated ? SERVICE_SYSTEM_START : SERVICE_DEMAND_START ;
			out.errorControl = SERVICE_ERROR_SEVERE ;
			out.group =
				associated ? (native->mediumChanger ? L"SCSI Class" : L"SCSI Miniport") : L"" ;
			out.binary	= native->registration.path( name == L"InboxFixture"
														? L"System32\\drivers\\dep.sys"
														: L"System32\\drivers\\old_fixture.sys") ;
			out.display = L"Old kernel configuration legitimately differs from new package" ;
			// 元公開後又は必要null登録後のconfig差だけを与えます
			if( (native->nativeCase == SignedIndexBindingNativeCase::STORAGE_SERVICE_CHANGED &&
				native->changed) ||
			   (native->nativeCase ==
					SignedIndexBindingNativeCase::STORAGE_SERVICE_CHANGED_AFTER_STAGE &&
				native->stages != 0U)) {
				out.display += L" changed" ;
			}

			// 同原文又はSDの全byteを取得する一時所有です
			PSECURITY_DESCRIPTOR raw{} ;
			// 元read-only型validatorを通す人工保守主体SDをscope所有します
			if( !ConvertStringSecurityDescriptorToSecurityDescriptorW(
				   L"O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &raw, nullptr)) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			// 人工SDをscope終了で必ず解放する単独所有者です
			const std::unique_ptr<void, decltype( &LocalFree)> security{raw, &LocalFree} ;
			// 元全byte又は文字列要素の先頭です
			const auto first = static_cast<const std::byte *>( security.get()) ;
			out.security.assign( first, first + GetSecurityDescriptorLength( security.get())) ;
			return 0U ;
		} ;
		// 欠落したstorage callbackから実SCMへ接続しません
		if( native->nativeCase == SignedIndexBindingNativeCase::STORAGE_SERVICE_CALLBACK_MISSING) {
			api.storageService = {} ;
		}

		// 同隔離Windows起点と対応Storeへ同byteで固定する人工SYSTEM INFです
		std::string systemInf =
			"[Version]\r\nSignature=\"$WINDOWS NT$\"\r\nClass=System\r\n"
			"ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\r\n"
			"Provider=Fixture\r\nDriverVer=01/01/2026,1.0.0.0\r\nCatalogFile=peer.cat\r\n"
			"[Shared]\r\nCopyFiles=@dep.sys\r\n[DestinationDirs]\r\nDefaultDestDir=12\r\n"
			"[SourceDisksNames]\r\n1=Fixture\r\n[SourceDisksFiles]\r\ndep.sys=1\r\n" ;
		// 元SYSTEM byteだけへ未採用AddRegを与え、成功DTOを合成しません
		if( native->nativeCase == SignedIndexBindingNativeCase::NEEDS_ADDREG_FLAGS ||
		   native->nativeCase == SignedIndexBindingNativeCase::NEEDS_SYSTEM_MEDIA ||
		   native->nativeCase == SignedIndexBindingNativeCase::NEEDS_SYSTEM_REGISTRATION) {
			const auto shared = systemInf.find( "[Shared]\r\n") ;	// 元の正確な節位置です
			// 入力の欠落を別節への追加で補完しません
			if( shared == systemInf.npos) {
				throw std::runtime_error( "Needs AddReg fixture section missing") ;
			}

			systemInf.insert( shared + std::string_view( "[Shared]\r\n").size(),
							 "AddReg=Settings\r\n") ;
			// 正例は原SYSTEMの媒体scopeであり、packageの成功DTOを作りません
			systemInf +=
				native->nativeCase != SignedIndexBindingNativeCase::NEEDS_ADDREG_FLAGS
					? "[Settings]\r\nHKLM,SYSTEM\\CurrentControlSet\\Control\\MediaCategories\\"
					  "{10000000-0000-4000-8000-000000000001},Name,0,Fixture category\r\n"
					: "[Settings]\r\nHKR,,PrivateRegistrySetting,0x00010000,ordinary\r\n" ;
			// 固定登録も同原INFの実byteから評価し、必要計画へ成功boolを注入しません
			if( native->nativeCase == SignedIndexBindingNativeCase::NEEDS_SYSTEM_REGISTRATION) {
				systemInf +=
					"HKLM,SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce,FixtureRegister,0,\""
					"rundll32.exe streamci,StreamingDeviceSetup {10000000-0000-4000-8000-000000000003},"
					"{10000000-0000-4000-8000-000000000004},{10000000-0000-4000-8000-000000000005}\"\r\n" ;
			}
		}

		const auto storeRelative =
			L"System32\\DriverStore\\FileRepository\\fixture\\peer.inf" ;	// 明示対応Storeです
		const auto catalogRelative =
			L"System32\\CatRoot\\fixture\\peer.cat" ;					// 同署名CATの固定位置です
		std::vector<std::pair<std::wstring, std::wstring>> expected ;	// 実fileの元全hashです
		const auto write = [&]( const std::wstring &relative, std::string_view bytes) {
			HANDLE handle = INVALID_HANDLE_VALUE ;	// 隔離workspaceの単独所有fileです
			// 実OSのWindows配下へ書込みません
			if( native->registration.createFile( relative, handle) != 0) {
				return false ;
			}

			DWORD	   written{} ;	// 完全な小さい人工byteだけです
			const bool ok = WriteFile( handle, bytes.data(), static_cast<DWORD>( bytes.size()),
									  &written, nullptr) != FALSE ;	// 全byteの実書込みです
			CloseHandle( handle) ;
			std::wstring hash ;											// 原byteへ結合します
			const auto	 path = native->registration.path( relative) ;	// 同隔離所有者の完全pathです
			// 部分取得を期待値へ昇格しません
			if( !ok || written != bytes.size() || computeFileSha256( path, hash) != 0) {
				return false ;
			}

			expected.emplace_back( path, std::move( hash)) ;
			return true ;
		} ; // scope作成前に全人工fileを固定します
		// 全fixtureを隔離所有し、SYSTEM既提供と対応Storeを別fileとして検査します
		if( !write( L"INF\\peer.inf", systemInf) || !write( storeRelative, systemInf) ||
		   !write( catalogRelative, "fixture-catalog") ||
		   !write( L"System32\\DriverStore\\FileRepository\\fixture\\dep.sys",
				  "fixture-system-payload") ||
		   !write( L"System32\\drivers\\dep.sys",
				  native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_PAYLOAD_CHANGED
					  ? "changed-system-payload"
					  : "fixture-system-payload")) {
			return std::unique_ptr<inf_dependency_native_detail::ScopedFixture>{} ;
		}

		// associated vendor旧byteとWindows依存proofを別の元fileとして保持します
		if( native->storage && (!write( L"System32\\drivers\\old_fixture.sys",
									  "older protected synthetic kernel bytes") ||
							   !write( L"System32\\IoLogMsg.dll", "fictional system helper"))) {
			return std::unique_ptr<inf_dependency_native_detail::ScopedFixture>{} ;
		}

		// 実SYSTEMと同じ二段転送を、完全に人工のINBOX/Store/CATへ閉じます
		if( native->storage) {
			// 同OS/INFの元version文脈です
			const std::string version =
				"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=System\r\n"
				"ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture Windows\r\n"
				"DriverVer=01/01/2026,1.0.0.0\r\nCatalogFile=peer.cat\r\n" ;
			// 同INBOX/Storeへ固定する人工pci.infの原本文です
			const auto pci = version +
							 "[PciIoSpaceNotRequired.HW]\r\nAddReg=NoIoSpace\r\n[NoIoSpace]\r\n"
							 "HKR,e5b3b5ac-9725-4f78-963f-03dfb1d828c7,IoNotRequired,0x10001,1\r\n" ;
			// 元転送又はarchitectureの独立した有限入力です
			const auto machine =
				version +
				"[PciIoSpaceNotRequired.HW]\r\nInclude=pci.inf\r\nNeeds=PciIoSpaceNotRequired.HW\r\n" ;
			// 二段転送用の全INBOX/Store人工byteを同じscopeへ閉じます
			if( !write( L"INF\\pci.inf", pci) || !write( L"INF\\machine.inf", machine) ||
			   !write( L"System32\\DriverStore\\FileRepository\\fixture\\pci.inf", pci) ||
			   !write( L"System32\\DriverStore\\FileRepository\\fixture\\machine.inf", machine)) {
				return std::unique_ptr<inf_dependency_native_detail::ScopedFixture>{} ;
			}
		}

		// 新登録条件の二helperも同じ所有rootに非実行byteとして固定します
		if( native->nativeCase == SignedIndexBindingNativeCase::NEEDS_SYSTEM_REGISTRATION &&
		   (!write( L"System32\\rundll32.exe", "fictional system helper") ||
			!write( L"System32\\streamci.dll", "fictional system helper"))) {
			return std::unique_ptr<inf_dependency_native_detail::ScopedFixture>{} ;
		}

		api.systemFileTrust = [native, expected]( const std::wstring		&path,
												 WindowsSystemFileTrust &proof) -> NativeError {
			const auto found = std::ranges::find_if( expected, [&]( const auto &entry) {
				return entry.first == path ;
			}) ; // 全原file期待だけです
			// 別helper又は元hash差を人工trustで補完しません
			if( (path != native->registration.path( L"System32\\rundll32.exe") &&
				path != native->registration.path( L"System32\\streamci.dll") &&
				!(native->storage &&
				  (path == native->registration.path( L"System32\\IoLogMsg.dll") ||
				   path == native->registration.path( L"System32\\drivers\\dep.sys")))) ||
			   found == expected.end()) {
				return E_INVALIDARG ;
			}

			proof.filePath = path ;
			// 同原fileの種別と全byte長を確認するWindows属性です
			WIN32_FILE_ATTRIBUTE_DATA attributes{} ;
			// 実fixture fileの全byte長を確認できなければtrustを生成しません
			if( !GetFileAttributesExW( path.c_str(), GetFileExInfoStandard, &attributes)) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			proof.fileBytes = (static_cast<std::uint64_t>( attributes.nFileSizeHigh) << 32U) |
							  attributes.nFileSizeLow ;
			proof.fileSecurity = {std::byte{1U}} ;
			// 元helperのtrust拒否と登録後の原tuple差を分離します
			if( native->nativeCase == SignedIndexBindingNativeCase::STORAGE_HELPER_REJECTED) {
				return TRUST_E_SUBJECT_NOT_TRUSTED ;
			}

			// 必要null登録後だけ元helperの保護証拠を変えます
			if( native->nativeCase ==
				   SignedIndexBindingNativeCase::STORAGE_HELPER_CHANGED_AFTER_STAGE &&
			   native->stages != 0U) {
				proof.fileSecurity.push_back( std::byte{2U}) ;
			}

			const auto error = computeFileSha256( path, proof.fileSha256) ;	// 元byteを再確認します
			return error != 0U ? error
				   : proof.fileSha256 == found->second
					   ? 0U
					   : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		} ; // 人工署名/SDの元期待であり、実Windows trustの成功証拠ではありません

		// 同名二観測を先頭へ絞らせない追加入力です
		if( native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_AMBIGUOUS &&
		   !write( L"System32\\peer.inf", systemInf)) {
			return std::unique_ptr<inf_dependency_native_detail::ScopedFixture>{} ;
		}

		auto versions = std::make_shared<std::size_t>( 0U) ;	// 同runの開始終了を観測します
		api.version	  = [native, versions]( OSVERSIONINFOEXW &version, SYSTEM_INFO &system) {
			  ++native->dependencyVersionCalls ;
			  // 新P4隔離fixtureの欠落から実host APIへfallbackしません
			  if( native->p4ExplicitClientContext) {
				  version.dwMajorVersion		= 10U ;
				  version.dwMinorVersion		= 0U ;
				  version.dwBuildNumber			= 26100U ;
				  version.wProductType			= VER_NT_WORKSTATION ;
				  version.wSuiteMask			= 0U ;
				  system.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 ;
				  return NativeError{} ;
			  }

			  // storage分母は固定したOS/architectureだけを完全tableから返します
			  if( native->storage) {
				  version.dwMajorVersion = 10U ;
				  version.dwMinorVersion = 0U ;
				  version.dwBuildNumber =
					  native->nativeCase == SignedIndexBindingNativeCase::STORAGE_OLD_BOOT_FLAGS_OS
						  ? 25397U
						  : 26200U ;
				  version.wProductType			= VER_NT_WORKSTATION ;
				  system.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 ;
				  ++*versions ;
				  return static_cast<NativeError>( 0U) ;
			  }

			  // 未観測を成功文脈へ補正しません
			  if( native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_NOT_OBSERVED) {
				  return static_cast<NativeError>( E_FAIL) ;
			  }

			  using Query = LONG( WINAPI *)( OSVERSIONINFOEXW *) ;	// 公式ABIのread-only境界です
			  const HMODULE module =
				  // 既存moduleを借用し、解放しません
				  GetModuleHandleW( L"ntdll.dll") ;
			  // Module取得の失敗を関数addressの照会へ渡しません
			  if( module == nullptr) {
				  return static_cast<NativeError>( E_FAIL) ;
			  }

			  const auto query = reinterpret_cast<Query>( GetProcAddress(
				  // 読取専用の公式ABIです
				  module, "RtlGetVersion")) ;
			  // OS情報の読取以外のinventoryを実行しません
			  if( query == nullptr || query( &version) != 0) {
				  return static_cast<NativeError>( E_FAIL) ;
			  }

			  GetNativeSystemInfo( &system) ;
			  const auto observation = ++*versions ;	// 同runの文脈観測順です
			  // 終了時文脈差を元のOS成功で隠させません
			  if( observation > 1U) {
				  // OS build差をarchitecture差と独立に固定します
				  if( native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_CONTEXT_CHANGED) {
					  ++version.dwBuildNumber ;
				  }

				  // 元native architectureだけを終了時に変えます
				  if( native->nativeCase ==
					 SignedIndexBindingNativeCase::DEPENDENCY_ARCHITECTURE_CHANGED) {
					  system.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64 ;
				  }

				  // 同OS buildのclient/serverだけを変えます
				  if( native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_SERVER_CHANGED) {
					  version.wProductType = version.wProductType == VER_NT_WORKSTATION
												 ? VER_NT_SERVER
												 : VER_NT_WORKSTATION ;
				  }

				  // 同architectureとbuildを保持してOS minorだけを変えます
				  if( native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_OS_CHANGED) {
					  ++version.dwMinorVersion ;
				  }
			  }

			  return static_cast<NativeError>( 0) ;
		} ; // OS照会だけの原文脈を保持します
		api.windowsDirectory = [native]( std::wstring &path) {
			++native->dependencyWindowsDirectoryCalls ;
			path = native->windowsRoot ;
			return static_cast<NativeError>( 0) ;
		} ; // 起点は同隔離所有者だけです
		api.infSignature = [native, catalogRelative]( const std::wstring	  &path,
													 SP_INF_SIGNER_INFO_W &signer) {
			++native->dependencyInfCalls ;
			// 同元rootへの終了照会を、別INF署名の回数から推測しません
			if( path.ends_with( L"\\fixture.inf")) {
				++native->dependencyRootSignerCalls ;
			}

			// 同閉包PACKAGE必要INFへ到達した元署名callだけを数えます
			if( !path.starts_with( native->windowsRoot) && path.ends_with( L"\\component.inf")) {
				++native->dependencyPackageObservations ;
			}

			// SYSTEMの人工署名は元隔離位置だけです
			if( path.starts_with( native->windowsRoot)) {
				// 署名拒否をOriginだけで救済させません
				if( native->nativeCase ==
				   SignedIndexBindingNativeCase::DEPENDENCY_SIGNATURE_REJECTED) {
					return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
				}

				wcscpy_s( signer.CatalogFile, native->registration.path( catalogRelative).c_str()) ;
				wcscpy_s( signer.DigitalSigner, L"Microsoft Windows fixture") ;
				signer.SignerScore = SIGNERSCORE_INBOX ;
				return static_cast<NativeError>( 0) ;
			}

			const bool succeeded =
				driver_package_signature_detail::setupVerifyInf( path.c_str(), nullptr, &signer) !=
				FALSE ;	// 同元APIの応答です
			// 元byte/CATを変更せず、低位署名応答の全非NULだけを再現します
			if( succeeded &&
			   (native->nativeCase ==
					SignedIndexBindingNativeCase::DEPENDENCY_SIGNER_UNTERMINATED ||
				(native->nativeCase ==
					 SignedIndexBindingNativeCase::DEPENDENCY_SIGNER_RECHECK_UNTERMINATED &&
				 native->dependencyRootSignerCalls > 1U && path.ends_with( L"\\fixture.inf")))) {
				std::ranges::fill( signer.CatalogFile, L'X') ;
				std::ranges::fill( signer.DigitalSigner, L'X') ;
			}

			// 非空CATから署名者の存在を推測させません
			if( succeeded &&
			   (native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_SIGNER_EMPTY ||
				(native->nativeCase ==
					 SignedIndexBindingNativeCase::DEPENDENCY_SIGNER_RECHECK_EMPTY &&
				 native->dependencyRootSignerCalls > 1U && path.ends_with( L"\\fixture.inf")))) {
				signer.DigitalSigner[0] = L'\0' ;
			}

			native->dependencySignerMask =
				(signer.CatalogFile[MAX_PATH - 1U] == L'\0' ? 1U : 0U) |
				(signer.DigitalSigner[MAX_PATH - 1U] == L'\0' ? 2U : 0U) |
				(signer.CatalogFile[0] != L'\0' ? 4U : 0U) |
				(signer.DigitalSigner[0] != L'\0' ? 8U : 0U) ;
			native->dependencySignerResponsesValid &=
				!succeeded || (std::wstring_view{signer.CatalogFile, MAX_PATH}.find( L'\0') !=
								   std::wstring_view::npos &&
							   std::wstring_view{signer.DigitalSigner, MAX_PATH}.find( L'\0') !=
								   std::wstring_view::npos &&
							   signer.CatalogFile[0] != L'\0' && signer.DigitalSigner[0] != L'\0') ;
			return succeeded ? static_cast<NativeError>( 0)
							 : static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		} ; // PACKAGEは元全hash署名表へ戻します
		api.catalogSignature = [native, expected]( const std::wstring		   &catalog,
												  std::span<const std::wstring> members) {
			++native->dependencyCatalogCalls ;
			// PACKAGEは共通全CAT/member境界を維持します
			if( !catalog.starts_with( native->windowsRoot)) {
				return verifyOfficialCatalogMembers( catalog, members) ;
			}

			// INFの署名だけでなく全実payload/既存宛先の効果検査へ到達したcallを数えます
			if( members.size() == 2U) {
				++native->dependencySystemEffectChecks ;
			}

			std::vector<std::wstring> paths{catalog} ;	// SYSTEMのCAT自身も実hashへ結合します
			paths.insert( paths.end(), members.begin(), members.end()) ;
			// 同隔離閉包の全実byteだけを人工署名対象にします
			for( const auto &path : paths) {
				const auto	 original = std::ranges::find_if( expected, [&]( const auto &entry) {
					  return entry.first == path ;
				  }) ;			   // 同元期待だけです
				std::wstring hash ;	// 同じ実fileの終了byteです
				// 任意pathや改変を名前だけで合格にしません
				if( original == expected.end() || computeFileSha256( path, hash) != 0 ||
				   hash != original->second) {
					return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
				}
			}

			return static_cast<NativeError>( 0) ;
		} ; // 全member原hashを保持します
		api.driverStore = [native, storeRelative]( const std::wstring &path, std::wstring &store) {
			++native->dependencyDriverStoreCalls ;
			// exact人工INBOXの二つだけを独立Store原byteへ対応させます
			if( native->storage && (path == native->registration.path( L"INF\\pci.inf") ||
								   path == native->registration.path( L"INF\\machine.inf"))) {
				store =
					native->registration.path( L"System32\\DriverStore\\FileRepository\\fixture\\" +
											  std::filesystem::path{path}.filename().wstring()) ;
				return static_cast<NativeError>( 0U) ;
			}

			// 明示二SYSTEM起点だけを対応させます
			if( path != native->registration.path( L"INF\\peer.inf") &&
			   path != native->registration.path( L"System32\\peer.inf")) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			store = native->registration.path( storeRelative) ;
			return static_cast<NativeError>( 0) ;
		} ; // SYSTEM fileをPACKAGEへ複写しません
		return inf_dependency_native_detail::Access::create( std::move( api)) ;
	} ; // 同workerが停止するまで完全表と元byteを所有します
	auto installer = std::make_shared<InstallerFixtureState>() ;	// 同worker専用の原低位状態です
	installer->condition = nativeCase ;
	// EXE/MSIの人工正例は全hashへ固定し完全表を対で結合します
	if( !installerPayload.empty()) {
		// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません
		if( computeBytesSha256( installerPayload, installer->hash) != 0) {
			throw std::runtime_error( "installer fixture hash") ;
		}

		/** @brief 原payload hashと期待publisherへ完全Authenticode表を結びます
		 * @return 同workerだけで所有する完全scopeです。不完全表は受理しません
		 */
		services.authenticodeFixture = [installer]() {
			activeInstallerFixture = installer.get() ;
			return driver_package_signature_detail::Access::createAuthenticode(
				{&installerVerify, &installerQuery, &installerMessage, &installerFind,
				 &installerName, &installerFree, &installerCloseMessage, &installerCloseStore}) ;
		} ;
		/** @brief 実processを起動しない完全低位installer表を開始します
		 * @return 同workerだけで所有する完全scopeです。部分native fallbackはありません
		 */
		services.installerFixture = []() {
			return signed_index_candidate_binding_detail::Access::createInstaller(
				{&installerCreate, &installerWait, &installerExit, &installerClose,
				 &installerSystemDirectory}) ;
		} ;
	}

	// 原三archive条件だけはmetadata bootstrapと実cache-only CAT検査へ置換します
	if( original) {
		const auto input = std::make_shared<OriginalSelectionBindingInput>(
			*original) ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
		services.signatureFixture = [input, signature]() {
			auto scope =	// 同原文/操作へ結ぶ検査又は結果の所有値です
				driver_package_signature_detail::Access::createOriginalAdapter( input->infs) ;
			*signature = scope.get() ;
			return scope ;
		} ; // score/issuerは人工、原CAT/member/hash/trustは実検査です
		services.dependencyFixture = [native, input]() {
			inf_dependency_native_detail::Api api ;
			std::array<wchar_t, MAX_PATH>
					   windows{} ;	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
			const auto length =		// 元全長又は共同予算の有限件数です
				GetWindowsDirectoryW( windows.data(), static_cast<UINT>( windows.size())) ;
			// 固定した入力条件だけを分離し、他対象や期待へ流用しません
			if( length == 0U || length >= windows.size() ||
			   input->systemStoreFiles
				   .empty() ||	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
			   input->systemStoreFiles.size() > 64U) {
				throw std::runtime_error( "original system input missing") ;
			}

			const std::wstring canonicalWindows{	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
												windows.data(), length} ;
			// 自身の所有Storeだけへ有限な原fileを正確に配置します
			for( const auto &[relative, source] : input->systemStoreFiles) {
				std::ifstream file{
					std::filesystem::path{source},
					std::ios::binary |
						std::ios::ate} ;			// この同期/fixtureが所有する資源又は原状態です
				const auto size = file.tellg() ;	// 元全長又は共同予算の有限件数です
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( !file || size <= 0 ||
				   size > 32 * 1024 *
							  1024 ||	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				   !relative.starts_with( L"Store\\")) {
					throw std::runtime_error( "original projected file unavailable") ;
				}

				std::string bytes( static_cast<std::size_t>( size),
								  '\0') ;	// 元全長又は共同予算の有限件数です
				file.seekg( 0) ;
				file.read( bytes.data(), size) ;
				HANDLE handle =
					INVALID_HANDLE_VALUE ;	// この同期/fixtureが所有する資源又は原状態です
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( !file || native->registration.createFile( relative, handle) !=
								0U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
					throw std::runtime_error( "original projected file creation rejected") ;
				}

				std::unique_ptr<void, decltype( &CloseHandle)> owner{
					handle, &CloseHandle} ;	// 元権限/署名の照合中だけ使う証拠です
				DWORD written{} ;			// 実操作から得た観測値です。独立期待とは分けます
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( !WriteFile(
					   handle, bytes.data(), static_cast<DWORD>( bytes.size()),
					   &written,	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
					   nullptr) ||
				   written != bytes.size()) {
					throw std::runtime_error( "original projected file incomplete") ;
				}

				owner.reset() ;
				std::wstring before, after ;
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( computeFileSha256( source, before) !=
					   0U ||	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				   computeFileSha256( native->registration.path( relative), after) != 0U ||
				   before != after) {
					throw std::runtime_error( "original projected file hash mismatch") ;
				}
			}

			api.projectedStore = &native->registration ;
			const auto allowed = std::make_shared<
				std::set<std::wstring>>() ;	// この同期だけで保持する元値です。許可の代用にしません
			const auto systemCatalogs = std::make_shared<
				std::set<std::wstring>>() ;	// 原byteに結ぶ完全hash又は元CATの証拠です
			// 同所有fixtureの全対象を順に検査します
			for( const auto leaf :	// 同所有fixtureの全対象を順に確認します
				{L"ks.inf", L"wdmaudio.inf", L"usbvideo.inf", L"kscaptur.inf", L"pci.inf"}) {
				allowed->insert( canonicalWindows + L"\\INF\\" + leaf) ;
			}

			// 同所有fixtureの全対象を順に検査します
			for( const auto leaf : {L"rundll32.exe", L"streamci.dll",
								   L"vfwwdm32.dll"}) {	// 同所有fixtureの全対象を順に確認します
				allowed->insert( canonicalWindows + L"\\System32\\" + leaf) ;
			}

			allowed->insert( canonicalWindows + L"\\System32\\drivers\\WdmCompanionFilter.sys") ;
			// 同所有fixtureの全対象を順に検査します
			for( const auto &[relative, source] :
				input->systemStoreFiles) {	// 同所有fixtureの全対象を順に確認します
				allowed->insert( native->registration.path( relative)) ;
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				// 元完全表の明示fileだけです
				allowed->insert( source) ;
			}

			// 同所有fixtureの全対象を順に検査します
			for( const auto &[canonical, relative] :
				input->providedProjection) {	// 同所有fixtureの全対象を順に確認します
				allowed->insert( canonical) ;
			}

			api.readPath = [native, input, canonicalWindows, allowed](
							   std::wstring_view canonical, std::wstring &physical) -> NativeError {
				physical.clear() ;
				// 明示負例だけは二つの正規SYSTEM INF候補をともに不在へ固定します
				if( !input->unavailableSystemInf.empty() &&
				   (CompareStringOrdinal(
						std::wstring{canonical}.c_str(), -1,
						(canonicalWindows + L"\\INF\\" + input->unavailableSystemInf).c_str(), -1,
						TRUE) == CSTR_EQUAL ||
					CompareStringOrdinal(
						std::wstring{canonical}.c_str(), -1,
						(canonicalWindows + L"\\System32\\" + input->unavailableSystemInf).c_str(),
						-1, TRUE) == CSTR_EQUAL)) {
					return HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND) ;
				}

				// 元recordのINF metadataを分類するだけで、まだfile本文は読みません
				const auto package = std::ranges::find_if( input->infs, [&]( const auto &inf) {
					return CompareStringOrdinal( std::filesystem::path{canonical}.filename().c_str(),
												-1, inf.infName.c_str(), -1, TRUE) == CSTR_EQUAL ;
				}) ; // 原三INFのmetadataだけで位置認定はしません
				// 元providerが保持した同候補の完全path以外はhash読取前に拒否します
				if( package != input->infs.end()) {
					// 同providerが保持する原候補完全pathへの所属を確認します
					const bool knownSource =
						std::ranges::any_of( native->sourceInfs, [&]( const auto &path) {
							return path.size() == canonical.size() &&
								   CompareStringOrdinal(
									   path.data(), static_cast<int>( path.size()), canonical.data(),
									   static_cast<int>( canonical.size()), TRUE) == CSTR_EQUAL ;
						}) ; // 同じbasenameの別directoryを所有scopeへ取り込みません
					// 不明位置をbyte一致だけでadoptしません
					if( !knownSource) {
						return HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND) ;
					}

					std::wstring hash ;	// 位置認定後にだけ読む元packageの完全hashです
					++native->originalMappingHashReads ;
					const auto error =
						// 元読取errorです
						computeFileSha256( std::wstring{canonical}, hash) ;
					// 同候補の元byte差は他の原recordへ付け替えません
					if( error != 0U || hash != package->infSha256) {
						return error != 0U ? error : static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
					}

					allowed->insert( std::wstring{canonical}) ;
				}

				// 明示canonicalと所有Storeの一対だけを検索します
				const auto projected =
					std::ranges::find_if( input->providedProjection, [&]( const auto &entry) {
						return entry.first.size() == canonical.size() &&
							   CompareStringOrdinal(
								   entry.first.data(), static_cast<int>( entry.first.size()),
								   canonical.data(), static_cast<int>( canonical.size()),
								   TRUE) == CSTR_EQUAL ;
					}) ; // 明示canonicalと所有Store実byteの一対だけです
				// 実提供先の投影は未知pathや他directory探索にfallbackしません
				if( projected != input->providedProjection.end()) {
					physical = native->registration.path( projected->second) ;
					return physical.empty() ? E_INVALIDARG : 0U ;
				}

				// Windows表記の大小文字に関係なく、完全表に無い全位置を拒否します
				if( std::ranges::none_of( *allowed, [&]( const auto &path) {
					   return path.size() == canonical.size() &&
							  CompareStringOrdinal(
								  path.data(), static_cast<int>( path.size()), canonical.data(),
								  static_cast<int>( canonical.size()), TRUE) == CSTR_EQUAL ;
				   })) {
					return HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND) ;
				}

				physical = canonical ;
				return 0U ;
			} ; // 完全表の不足を実filesystemへ補完しません
			std::wstring unknownWindows =
				canonicalWindows ;	// 実Windowsと大小文字だけ異なる未知pathです
			// 表記差を使って完全表の拒否を迂回しません
			for( auto &c : unknownWindows) {
				// 元大文字を小文字へ写し、実Windowsとは異なる表記を作ります
				if( c >= L'A' && c <= L'Z') {
					c += L'a' - L'A' ;
				}
				// 元小文字も逆へ写し、同じ通常化文字列を渡しません
				else if( c >= L'a' && c <= L'z') {
					c -= L'a' - L'A' ;
				}
			}

			unknownWindows += L"\\System32\\unregistered-synthetic.sys" ;
			const auto unknownPackage =
				native->registration.path( L"unregistered\\" +
										  // 原INFと同名でも所有候補に無い位置です
										  input->infs.front().infName) ;
			const auto beforeHashes =
				native->originalMappingHashReads ;	// 不明位置からの実hash読取を検出します
			std::wstring unused ;					// 拒否時は出力も空のままです
			// 二負例は未登録位置で必ず原不在となり、file本文の読取を呼びません
			if( api.readPath( unknownWindows, unused) !=
				   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)) ||
			   !unused.empty() ||
			   api.readPath( unknownPackage, unused) !=
				   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)) ||
			   !unused.empty() || native->originalMappingHashReads != beforeHashes) {
				throw std::runtime_error( "original unknown path boundary rejected") ;
			}

			std::cout << "ORIGINAL_MAPPING_GUARDS rejected=2 prehash=0\n" << std::flush ;

			api.version = [native]( OSVERSIONINFOEXW &version, SYSTEM_INFO &system) -> NativeError {
				++native->dependencyVersionCalls ;
				using Query		   = LONG( WINAPI *)( OSVERSIONINFOEXW *) ;
				const auto address =	// この同期/fixtureが所有する資源又は原状態です
					GetProcAddress( GetModuleHandleW( L"ntdll.dll"), "RtlGetVersion") ;
				Query query{} ;	// この同期/fixtureが所有する資源又は原状態です
				static_assert( sizeof( query) == sizeof( address)) ;
				std::memcpy( &query, &address, sizeof( query)) ;
				GetNativeSystemInfo( &system) ;
				return query && query( &version) == 0 ? 0U : static_cast<NativeError>( E_FAIL) ;
			} ;
			api.windowsDirectory = [native, canonicalWindows]( std::wstring &out) -> NativeError {
				++native->dependencyWindowsDirectoryCalls ;
				out = canonicalWindows ;
				return 0U ;
			} ;
			api.infSignature = [native, input, canonicalWindows, allowed,
								systemCatalogs]( const std::wstring	 &path,
												SP_INF_SIGNER_INFO_W &signer) -> NativeError {
				++native->dependencyInfCalls ;
				std::wstring catalog ;	// 原byteに結ぶ完全hash又は元CATの証拠です
				const auto	 name =
					std::filesystem::path{path}
						.filename()
						.wstring() ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
				const bool system = path == canonicalWindows + L"\\INF\\" +
												name ;	// 元権限/署名の照合中だけ使う証拠です
				// 正確な五SYSTEM原INFか元三PACKAGE tupleだけを受理します
				if( system) {
					// 固定した入力条件だけを分離し、他対象や期待へ流用しません
					if( name != L"ks.inf" && name != L"wdmaudio.inf" &&
					   name !=
						   L"usbvideo.inf" &&	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
					   name != L"kscaptur.inf" &&
					   name != L"pci.inf") {
						return E_INVALIDARG ;
					}

					WindowsSystemFileTrust proof ;	// 元権限/署名の照合中だけ使う証拠です
					const auto			   error =	// 直後に保持した元API又は検査errorです
						driver_package_signature_detail::Access::verifySystemCatalogFile( path,
																						 proof) ;
					// 固定した入力条件だけを分離し、他対象や期待へ流用しません
					if( error != 0U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
						return error ;
					}

					catalog = proof.catalogPath ;
					allowed->insert( catalog) ;
					systemCatalogs->insert( catalog) ;
				} else {
					const auto found =
						std::ranges::find(	// この同期だけで保持する元値です。許可の代用にしません
							input->infs, name,
							&driver_package_signature_detail::OriginalInfMetadata::infName) ;
					std::wstring hash ;	// 原byteに結ぶ完全hash又は元CATの証拠です
					// 固定した入力条件だけを分離し、他対象や期待へ流用しません
					if( found == input->infs.end() ||
					   computeFileSha256( path, hash) !=
						   0U ||	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
					   hash != found->infSha256) {
						return TRUST_E_BAD_DIGEST ;
					}

					catalog =
						(std::filesystem::path{path}.parent_path() / found->catalogName).wstring() ;
					const std::array<std::wstring, 1U> members{
						path} ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
					const auto error = verifyOfficialCatalogMembers(
						catalog, members) ;	// 直後に保持した元API又は検査errorです
					// 固定した入力条件だけを分離し、他対象や期待へ流用しません
					if( error != 0U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
						return error ;
					}
				}

				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( catalog.empty() ||
				   catalog.size() >=
					   MAX_PATH) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
					return E_INVALIDARG ;
				}

				allowed->insert( catalog) ;
				wcscpy_s( signer.CatalogFile, catalog.c_str()) ;
				wcscpy_s( signer.DigitalSigner, L"Original CAT verified; score bootstrap") ;
				signer.SignerScore = system ? SIGNERSCORE_INBOX : 0U ;
				return 0U ;
			} ;
			api.catalogSignature = [native, input, systemCatalogs](
									   const std::wstring			&catalog,
									   std::span<const std::wstring> members) -> NativeError {
				++native->dependencyCatalogCalls ;
				std::vector<std::wstring>
					physical ;	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
				// 同所有fixtureの全対象を順に検査します
				for( const auto &member : members) {	// 同所有fixtureの全対象を順に確認します
					const auto projected =				// この同期だけで保持する元値です。許可の代用にしません
						std::ranges::find_if( input->providedProjection, [&]( const auto &entry) {
							return entry.first.size() == member.size() &&
								   CompareStringOrdinal(
									   entry.first.data(), static_cast<int>( entry.first.size()),
									   member.data(), static_cast<int>( member.size()),
									   TRUE) == CSTR_EQUAL ;
						}) ;
					physical.push_back( projected == input->providedProjection.end()
										   ? member
										   : native->registration.path( projected->second)) ;
				}

				return systemCatalogs->contains( catalog)
						   ? driver_package_signature_detail::Access::verifyWindowsCatalogMembers(
								 catalog, physical)
						   : verifyOfficialCatalogMembers( catalog, physical) ;
			} ;
			api.driverStore = [native, canonicalWindows]( const std::wstring &path,
														 std::wstring		&out) -> NativeError {
				++native->dependencyDriverStoreCalls ;
				const auto name =
					std::filesystem::path{path}
						.filename()
						.wstring() ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( path !=
					   canonicalWindows + L"\\INF\\" +
						   name ||	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
				   (name != L"ks.inf" && name != L"wdmaudio.inf" && name != L"usbvideo.inf" &&
					name != L"kscaptur.inf" && name != L"pci.inf")) {
					return E_INVALIDARG ;
				}

				out = native->registration.path( L"Store\\" + name + L"\\" + name) ;
				return 0U ;
			} ;
			api.systemFileTrust = [input, native,
								   allowed]( const std::wstring	   &path,
											WindowsSystemFileTrust &proof) -> NativeError {
				const auto projected =	// この同期だけで保持する元値です。許可の代用にしません
					std::ranges::find_if( input->providedProjection, [&]( const auto &entry) {
						return entry.first.size() == path.size() &&
							   CompareStringOrdinal(
								   entry.first.data(), static_cast<int>( entry.first.size()),
								   path.data(), static_cast<int>( path.size()), TRUE) == CSTR_EQUAL ;
					}) ;
				std::wstring actual = path ;	// 実操作から得た観測値です。独立期待とは分けます
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( projected !=
				   input->providedProjection
					   .end()) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
					const auto
						source =	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
						std::ranges::find( input->systemStoreFiles, projected->second,
										  &std::pair<std::wstring, std::wstring>::first) ;
					// 固定した入力条件だけを分離し、他対象や期待へ流用しません
					if( source ==
					   input->systemStoreFiles
						   .end()) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
						return E_INVALIDARG ;
					}

					actual = source->second ;
				}

				const auto error = verifyWindowsSystemFileCachedOnly(
					actual, proof) ;	// 直後に保持した元API又は検査errorです
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( error == 0U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
					proof.filePath = path ;
					// 固定した入力条件だけを分離し、他対象や期待へ流用しません
					if( !proof.catalogPath
							.empty()) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
						allowed->insert( proof.catalogPath) ;
					}
				}

				return error ;
			} ; // 私有提供先/SDの投影と原file実trustを混同しません
			api.systemService = [native]( std::wstring_view		name,
										 SystemServiceEvidence &proof) -> NativeError {
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( CompareStringOrdinal(
					   std::wstring{name}.c_str(), -1, L"WdmCompanionFilter",
					   -1,	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
					   TRUE) != CSTR_EQUAL) {
					return E_INVALIDARG ;
				}

				const auto error =
					// 直後に保持した元API又は検査errorです
					readSystemServiceEvidence( name, proof) ;
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( error == 0U &&
				   native->originalEvidenceChanged
					   .load()) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
					proof.display += L" changed observation" ;
				}

				return error ;
			} ;
			api.observedSection = [native]( std::wstring_view path, std::wstring_view section) {
				std::wstring hash ;	// 原byteに結ぶ完全hash又は元CATの証拠です
				// 固定した入力条件だけを分離し、他対象や期待へ流用しません
				if( computeFileSha256( std::wstring{path}, hash) !=
				   0U) {	// 固定した原入力/負例だけを処理し、他条件の期待を変更しません
					throw std::runtime_error( "original section identity missing") ;
				}

				native->originalSections.insert( hash + L"|" + std::wstring{section}) ;
			} ; // 読取observerは署名/意味検査の成功を生成しません
			api.observedResult = [native]( const InfDependencyNativeResult &result) {
				native->originalEffects.push_back( result) ;
			} ;
			return inf_dependency_native_detail::Access::create( std::move( api)) ;
		} ; // 全署名/cache-only/CAT/memberとtyped作用は実parserへ渡します
	}

	SignedIndexBindingWorker result ;	// 実workerと同終端後観測の所有返却です
	result.observeStorageCalls	   = [native]() { return native->storageCalls ; } ;
	result.observeOriginalSections = [native]() { return native->originalSections ; } ;
	result.observeOriginalEffects  = [native]() { return native->originalEffects ; } ;
	result.changeOriginalEvidence  = [native]() { native->originalEvidenceChanged.store( true) ; } ;
	/** @brief Worker操作終端後の非機密installer counterだけを返します
	 * @return 原launch数とhandle解放数です。成功DTOを生成しません
	 */
	result.observeOriginalNative = [native]() { return native->deviceInstalls ; } ;
	result.observeInstaller		 = [installer]() {
		 return installer->observation ;
	} ; // 非機密counterだけです
	/** @brief WorkerのCOM MTA内で通常の複合Providerを生成します
	 * @return 元候補を発行する通常Providerの所有権です
	 */
	const auto providerFactory = [native]() {
		auto provider = std::make_unique<CompositeUpdateProvider>() ;	// 本物の元registryです
		// Worker寿命内の既ownerを同threadの低位fakeだけで借用します
		native->bindingStore =
			&signed_index_candidate_binding_detail::Access::driverStoreFixture( *provider) ;
		// 全test workerで実WUAへのfallbackを閉じ、設定で有効な場合も完全fakeだけを使用します
		if( !signed_index_candidate_binding_detail::Access::setManagedFixture(
			   *provider, std::make_shared<MixedManagedProvider>( native))) {
			throw std::runtime_error( "mixed managed fixture unavailable") ;
		}

		return provider ;
	} ;
	/** @brief 実復旧操作を呼ばない元の復旧fixtureを生成します
	 * @return 開始・終了・原失敗を観測する復旧fixtureの所有権です
	 */
	const auto restoreFactory = []() { return std::make_unique<FakeRestore>() ; } ;
	// 明示されたホスト取得判定は標準の許可用fixtureで上書きしません
	result.worker = services.beginHostAcquisition
						? provider_worker_index_detail::Access::create(
							  providerFactory, restoreFactory, std::move( services))
						: provider_worker_index_detail::Access::createAcquisitionFixture(
							  providerFactory, restoreFactory, std::move( services)) ;
	/** @brief 同期済みの低位counterだけをcopyし、署名scopeを参照しません
	 * @return 同operation終端またはstop/join後だけ読む非機密観測です
	 */
	const auto nativeSnapshot = [native]() {
		// 同worker終端後に読む低位callと結果のsnapshotです
		SignedIndexBindingObservation snapshot{
			native->stages,
			native->installs,
			native->opens,
			native->closes,
			native->restoreBegins,
			native->restoreCompletes,
			native->specifiedBindingMatches,
			{},
			std::array<std::uint32_t, 2U>{native->deviceInstalls[0], native->deviceInstalls[1]},
			native->installedOnlyQueries,
			native->rankCalls,
			native->dependencyPackageObservations,
			native->dependencySystemEffectChecks,
			native->dependencySystemStageCalls,
			native->dependencyVersionCalls,
			native->dependencyInfCalls,
			native->dependencyCatalogCalls,
			native->dependencyWindowsDirectoryCalls,
			native->dependencyDriverStoreCalls,
			native->dependencySignerResponsesValid,
			native->dependencySignerMask,
			native->allPresentInventoryOpens,
			native->registeredExtensionProbes,
			native->registeredExtensionBlocked,
			native->registeredExtensionError,
			native->registeredExtensionBytesUnchanged,
			native->currentVersion == L"1.0.0.0",
			native->managedInstalls,
			native->mtdFiles.filesDifs,
			native->mtdFiles.commits,
			native->mtdFiles.installDifs,
			native->mtdFiles.queueOutsideOwned,
			native->mtdFiles.beforeRestoreAccess,
			native->legacyInstalls} ;
		snapshot.declarativePreStageRootReads	 = native->declarativePreStageRootReads ;
		snapshot.declarativeStoreReads			 = native->declarativeStoreReads ;
		snapshot.requiredChildProofChecks		 = native->requiredChildProofChecks ;
		snapshot.requiredChildProofRuns			 = native->requiredChildProofRuns ;
		snapshot.requiredChildInstalls			 = native->childInstalls ;
		snapshot.requiredChildCollisionChecks	 = native->requiredChildCollisionChecks ;
		snapshot.requiredChildCollisionPreserved = native->requiredChildCollisionPreserved ;
		// 所有workspaceに写像したMTD targetだけを実fileで観測します
		if( native->mtd && !native->mtdFiles.windowsRoot.empty()) {
			// 所有workspaceへ写像した人工System32相対pathです
			const auto base =
				L"mtd-virtual\\" + native->mtdFiles.windowsRoot.substr( 3U) + L"\\System32\\" ;
			// 所有fileの全byteが期待値と一致するかを確認します
			const auto matches = [&]( std::wstring_view relative, std::string_view expected) {
				std::wstring actualHash, expectedHash ;
				return computeFileSha256( native->registration.path( relative), actualHash) == 0U &&
					   computeBytesSha256( expected, expectedHash) == 0U &&
					   actualHash == expectedHash ;
			} ;
			// 二DLLの存在・原byte・元file IDを個別に確認します
			for( std::size_t i = 0U; i < 2U; ++i) {
				// 現在DLLの所有相対pathです
				const auto relative = base + (i == 0U ? L"fixture-a.dll" : L"fixture-b.dll") ;
				// 同DLLの所有実pathです
				const auto path = native->registration.path( relative) ;
				snapshot.mtdTargetExists[i] =
					::GetFileAttributesW( path.c_str()) != INVALID_FILE_ATTRIBUTES ;
				snapshot.mtdTargetMatches[i] = matches( relative, native->mtdDllBodies[i]) ;
				// 既存targetだけについて元file IDの保持を確認します
				if( native->mtdFiles.initialTargetIds[i]) {
					// 既存targetの現在IDを読む所有handleです
					const HANDLE handle = ::CreateFileW(
						path.c_str(), FILE_READ_ATTRIBUTES,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
						OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;
					// 現在targetのfile IDです
					FILE_ID_INFO current{} ;
					// targetを開けた場合だけ現在IDを読みます
					if( handle != INVALID_HANDLE_VALUE) {
						// file IDの実読取成否です
						const bool read =
							::GetFileInformationByHandleEx( handle, FileIdInfo, &current,
														   sizeof( current)) != FALSE ;
						::CloseHandle( handle) ;
						// preflight前に記録した元file IDです
						const auto &old = *native->mtdFiles.initialTargetIds[i] ;
						snapshot.mtdTargetPriorIdPreserved[i] =
							read && current.VolumeSerialNumber == old.VolumeSerialNumber &&
							std::memcmp( &current.FileId, &old.FileId, sizeof( current.FileId)) == 0 ;
					}
				}
			}

			// 異byte既存または競合のbyteを独立に再読取します
			if( native->mtdScenario == MtdFixtureScenario::FOREIGN_EXISTING ||
			   native->mtdScenario == MtdFixtureScenario::RACE_DIFFERENT) {
				// 異byteが保持されたか比較する期待値です
				auto foreign = native->mtdDllBodies[0] ;
				foreign[0] ^= 1 ;
				snapshot.mtdForeignPreserved = matches( base + L"fixture-a.dll", foreign) ;
			}

			snapshot.mtdSysMatches = matches( base + L"drivers\\fixture.sys", native->mtdSysBody) ;
			snapshot.mtdSysOldMatches =
				matches( base + L"drivers\\fixture.sys", "owned previous system driver") ;
		}

		return snapshot ;
	} ; // 非atomic値は元終端の同期後またはstop/join後だけ読みます
	result.observeAfterStop = nativeSnapshot ;
	/** @brief 元終端後かつ署名scope生存中の観測へだけ署名receiptを加えます
	 * @return 同worker終端eventと同期した元低位counterと署名観測です
	 */
	result.observe = [nativeSnapshot, signature]() {
		auto observed = nativeSnapshot() ;	// 同終端eventの同期済み低位counterです
		observed.signature =
			*signature ? (*signature)->receipt() : driver_package_signature_detail::Receipt{} ;
		return observed ;
	} ; // Worker停止後はobserveAfterStopだけを使用します
	/** @brief Join後に低位集合と登録INFの変更非共有handleの解放を照合します
	 * @return 集合数一致と全隔離登録fileへの変更権限open成功時だけtrueです
	 * @note 登録fileは変更・削除せず、各probe handleを同slot内で解放します
	 */
	result.allNativeHandlesClosed = [native]() {
		// SetupAPI集合の未解放を登録fileの後確認で隠しません
		if( native->opens != native->closes) {
			return false ;
		}

		// 全終端経路で登録INFのpinが解放され、後のWindows処理を妨げないことを確認します
		for( const auto &path : native->stagedPaths) {
			// 未実行の予約slotから存在pathを作りません
			if( path.front() == L'\0') {
				continue ;
			}

			const HANDLE opened = CreateFileW(
				path.data(), GENERIC_WRITE | DELETE,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0U,
				nullptr) ;	// 権限openだけでbyte変更と削除は行いません
			// 全登録guardが解放された事実を同隔離fileの共有規則で確認します
			if( opened == INVALID_HANDLE_VALUE) {
				return false ;
			}

			const std::unique_ptr<void, decltype( &CloseHandle)> handle{
				opened, &CloseHandle} ;	// 同slot内で解放します
		}

		return true ;
	} ; // Join後にだけ読む共有counterです
	// 結果DTOを変更しません
	/** @brief Idle workerへ送る前に原の低位現在状態だけを変更します
	 * @note 成功DTOや公開候補を変更せず、元再照合による拒否を検証します
	 */
	result.changeNativeState = [native]() {
		native->changed = true ;
		// この固定条件だけは元保護閉包のimport-only byteを実際に変更します
		if( native->nativeCase == SignedIndexBindingNativeCase::IMPORT_HASH_CHANGED ||
		   native->nativeCase == SignedIndexBindingNativeCase::SERVICE_EXE_HASH_CHANGED ||
		   native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_PACKAGE_CHANGED) {
			bool changed{} ;	// 必ず対象byteへ到達した事実だけを保持します
			// Fake source検索で記録した保護fixture親からだけ対象を解決します
			for( const auto &source : native->sourceInfs) {
				const auto path = std::filesystem::path( source) ;	// Fixtureだけの元完全pathです
				// 登録rootや他INFをhash拒否の入力へ変更しません
				if( path.filename() != L"fixture.inf" || source.starts_with( native->windowsRoot)) {
					continue ;
				}

				const auto target =
					// 同保護元閉包の実在importだけです
					path.parent_path() /
					(native->nativeCase == SignedIndexBindingNativeCase::IMPORT_HASH_CHANGED
						 ? L"importonly.inf"
					 : native->nativeCase ==
							 SignedIndexBindingNativeCase::DEPENDENCY_PACKAGE_CHANGED
						 ? L"component.inf"
						 : L"component_service.exe") ;
				// 検査前未実在を変更成功へ補完しません
				if( std::filesystem::is_regular_file( target)) {
					std::ofstream stream( target,
										 std::ios::binary |
											 std::ios::app) ;	// 同期fixture byteだけを所有します
					stream << "; changed original import bytes\r\n" ;
					stream.close() ;
					changed = !stream.fail() ;
				}
			}

			// 実byte未変更のままhash差拒否の合格を宣言しません
			if( !changed) {
				throw std::runtime_error( "Original import mutation not reached") ;
			}
		}
	} ; // Worker Idleと元operation終端後だけ呼出し、公開結果を変更しません
	return result ;
}
// tests/unit/signed_index_candidate_binding_tests.hの同宣言を契約の正本とする
//------------------------------------------------------------------------------
/**
 * @brief 同ID二deviceを通常準備し、一件選択と二件batchのfake指定導入を確認します
 * @param[in,out] context 原assertion集計先です
 * @param[in] services 真署名隔離store・完全fake HTTP・固定UTCです
 * @param[in] zip 原INF/SYS/CATの実人工archiveです
 */
//------------------------------------------------------------------------------
void testAuthenticatedSameIdDevices( TestContext							  &context,
									provider_worker_index_detail::Services services,
									std::string_view					   zip)
{
	const auto		 firstFailures = context.failureCount() ;	// 本追加の失敗だけを別記します
	const std::array cases{
		std::tuple{SignedIndexBindingNativeCase::INDEX_NON_UNIQUE, false,
				   SignedIndexBindingBatchFault::NONE},
		std::tuple{SignedIndexBindingNativeCase::INITIAL_SAME_ID, false,
				   SignedIndexBindingBatchFault::NONE},
		std::tuple{SignedIndexBindingNativeCase::INITIAL_SAME_ID_OTHER_INCOMPLETE, false,
				   SignedIndexBindingBatchFault::NONE},
		std::tuple{SignedIndexBindingNativeCase::INDEX_NON_UNIQUE, true,
				   SignedIndexBindingBatchFault::NONE},
		std::tuple{SignedIndexBindingNativeCase::INITIAL_SAME_ID, true,
				   SignedIndexBindingBatchFault::NONE},
		std::tuple{SignedIndexBindingNativeCase::INITIAL_SAME_ID_OTHER_INCOMPLETE, true,
				   SignedIndexBindingBatchFault::NONE},
		std::tuple{SignedIndexBindingNativeCase::INITIAL_SAME_ID, true,
				   SignedIndexBindingBatchFault::SECOND_STATE_CHANGED},
		std::tuple{SignedIndexBindingNativeCase::INITIAL_SAME_ID, true,
				   SignedIndexBindingBatchFault::SECOND_RANK_UNKNOWN},
		std::tuple{SignedIndexBindingNativeCase::INITIAL_SAME_ID, true,
				   SignedIndexBindingBatchFault::SECOND_RANK_TIED},
		std::tuple{SignedIndexBindingNativeCase::INITIAL_SAME_ID, true,
				   SignedIndexBindingBatchFault::SECOND_API_DENIED},
		std::tuple{SignedIndexBindingNativeCase::INITIAL_SAME_ID, true,
				   SignedIndexBindingBatchFault::CONTENT_CHANGED},
		std::tuple{SignedIndexBindingNativeCase::INITIAL_SAME_ID, true,
				   SignedIndexBindingBatchFault::RECORD_EXPIRED}} ;	// 元分母を固定します
	// 各完全低位captureを別workerで作り、成功DTOやprivate証拠を直接生成しません
	for( const auto &[nativeCase, batch, fault] : cases) {
		auto bound = makeSignedIndexBindingWorker( services, zip, false, false, false, nativeCase,
												  {}, {}, {}, batch, fault) ;	// 同queueです
		OperationController controller ;										// 通常UIと同じ選択・失効状態です
		ScanOptions			options ;											// Driver Storeと元署名索引だけです
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
									   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		const auto scan				= controller.beginScan() ;	// 同operationを終端まで所有します
		DRIVERCRATE_EXPECT( context,
						   scan.accepted && bound.worker->requestScan( scan.operationId, options)) ;
		auto scanned = waitEvent( *bound.worker, WorkerEventKind::SCAN_COMPLETED,
								 scan.operationId) ;	// 実終端です
		DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan &&
										scanned->preparationPlan->targets.size() == 1U &&
										scanned->preparationPlan->targets[0].deviceCount == 2U) ;
		// 前提不足を候補成功へ補完せず、同workerを正常停止します
		if( !scanned || !scanned->preparationPlan ||
		   scanned->preparationPlan->targets.size() != 1U) {
			bound.worker->stop() ;
			continue ;
		}

		const auto &plan = *scanned->preparationPlan ;	// 元共有payload一件です
		DRIVERCRATE_EXPECT(
			context, std::ranges::count_if( scanned->scanResult.candidates, []( const auto &value) {
						 return value.providerId == SIGNED_INDEX_PROVIDER_ID && !value.current ;
					 }) == 2) ;
		// 第三nodeの不足を二機能の肯定観測で全体成功へ上書きしません
		if( nativeCase == SignedIndexBindingNativeCase::INITIAL_SAME_ID_OTHER_INCOMPLETE) {
			DRIVERCRATE_EXPECT( context, scanned->indexSummary.status == IndexScanStatus::PARTIAL &&
											scanned->indexSummary.error != 0U &&
											scanned->indexSummary.undeterminedRelations != 0U) ;
		} else {
			DRIVERCRATE_EXPECT( context, scanned->indexSummary.nonUniqueRelations == 1U &&
											scanned->indexSummary.matchedRelations == 0U) ;
		}

		DRIVERCRATE_EXPECT( context,
						   controller.completeScan( scan.operationId, scanned->scanResult) &&
							   controller.setPreparationPlan( scan.operationId, plan)) ;
		OfficialPreparationApproval approval{
			0U,
			plan.scanSessionId,
			plan.planId,
			plan.limits,
			{{plan.targets[0], true, false, false, false}}} ;				// 取得承認だけです
		const auto preparation = controller.beginPreparation( approval) ;	// 導入同意と分離します
		DRIVERCRATE_EXPECT( context,
						   preparation.accepted && bound.worker->requestPreparation( approval)) ;
		auto prepared = waitEvent( *bound.worker, WorkerEventKind::PREPARATION_COMPLETED,
								  approval.operationId) ;	// 原取得終端です
		std::vector<UpdateCandidate> candidates ;			// 実publicationだけを保持します
		// 全監査から発行済み候補だけを読みます
		if( prepared) {
			// 同取得終端の全監査から原候補だけを保持します
			for( const auto &report : prepared->preparationResult.auditReports) {
				candidates.insert( candidates.end(), report.publishedCandidates.begin(),
								  report.publishedCandidates.end()) ;
			}
		}

		DRIVERCRATE_EXPECT( context, prepared && prepared->preparationResult.items.size() == 1U &&
										candidates.size() == 2U && bound.observe().stages == 0U &&
										bound.observe().installs == 0U) ;
		// 未到達を配列参照や期待候補の合成で隠しません
		if( !prepared || candidates.size() != 2U) {
			bound.worker->stop() ;
			continue ;
		}

		DRIVERCRATE_EXPECT(
			context, candidates[0].deviceIdentity != candidates[1].deviceIdentity &&
						 candidates[0].packageIdentity == candidates[1].packageIdentity &&
						 std::ranges::all_of( candidates, [&]( const auto &value) {
							 return value.installable && value.assessment &&
									isCandidateAssessmentReady( *value.assessment) &&
									(nativeCase == SignedIndexBindingNativeCase::INDEX_NON_UNIQUE ||
									 value.action == DriverAction::INITIAL_INSTALL) ;
						 })) ;
		DRIVERCRATE_EXPECT( context, controller.completePreparation( prepared->preparationResult,
																   scanned->scanResult.candidates)) ;
		const std::vector<std::wstring> selected =
			batch ? std::vector{candidates[0].identity, candidates[1].identity}
				  : std::vector{candidates[1].identity} ;	// 明示集合の順序と件数です
		const auto installation =
			controller.beginInstall( plan.scanSessionId, selected,
									InstallConfirmation::CONFIRMED) ;	// 完全fakeの明示集合です
		DRIVERCRATE_EXPECT( context, installation.accepted &&
										bound.worker->requestInstall(
											installation.operationId, plan.scanSessionId, selected,
											nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
		auto installed = waitEvent( *bound.worker, WorkerEventKind::INSTALL_COMPLETED,
								   installation.operationId) ;	// fake終端です
		DRIVERCRATE_EXPECT(
			context,
			installed && installed->installResult.updates.size() == selected.size() &&
				installed->installResult.updates[0].identity == selected[0] &&
				installed->installResult.updates[0].installOutcome == OutcomeCode::SUCCESS) ;
		const auto observed = bound.observe() ;								// 同operationの原低位観測です
		const bool rejected = fault != SignedIndexBindingBatchFault::NONE ;	// 第二だけの拒否です
		// 全選択の個別原結果を保持し、第一の成功だけでbatch完了にしません
		if( installed) {
			DRIVERCRATE_EXPECT( context,
							   installed->installResult.currentDevices.size() == selected.size()) ;
			// 完全fakeの同workerで選択deviceだけを再openし、元sessionへ結合した実観測を運びます
			for( const auto &current : installed->installResult.currentDevices) {
				const auto candidate = std::find_if(
					candidates.begin(), candidates.end(), [&current]( const auto &value) {
						return value.deviceIdentity == current.observation.deviceIdentity ;
					}) ; // 元二deviceとの対応です
				DRIVERCRATE_EXPECT(
					context, candidate != candidates.end() &&
								 std::find( selected.begin(), selected.end(), candidate->identity) !=
									 selected.end() &&
								 current.error == 0U &&
								 isDeviceObservationBound( current.observation, plan.scanSessionId,
														  candidate->deviceIdentity)) ;
			}

			// 表示identityと原エラー/API到達数を非機密のまま記録します
			for( std::size_t index = 0U; index < installed->installResult.updates.size(); ++index) {
				const auto &item		   = installed->installResult.updates[index] ;	// 元結果です
				const bool	secondRejected = rejected && index == 1U ;					// 第一は成功を保持します
				DRIVERCRATE_EXPECT( context, item.identity == selected[index] &&
												(item.installOutcome == OutcomeCode::SUCCESS) ==
													!secondRejected &&
												(item.installError == 0U) == !secondRejected) ;
				// 元指定APIのACCESS_DENIEDはauthority拒否や別HRESULTへ上書きしません
				if( secondRejected && fault == SignedIndexBindingBatchFault::SECOND_API_DENIED) {
					DRIVERCRATE_EXPECT( context, item.installError ==
													static_cast<NativeError>( E_ACCESSDENIED)) ;
				}

				// 唯一最良を失う第二nodeは元の曖昧性診断を保持します
				if( secondRejected && fault == SignedIndexBindingBatchFault::SECOND_RANK_TIED) {
					DRIVERCRATE_EXPECT(
						context, item.installError ==
									 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_DUP_NAME))) ;
				}

				// 原期限は第一の成功で延長しません
				if( secondRejected && fault == SignedIndexBindingBatchFault::RECORD_EXPIRED) {
					DRIVERCRATE_EXPECT(
						context, item.installError ==
									 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT))) ;
				}

				std::cout << "SAME_ID_BATCH case=" << static_cast<unsigned>( nativeCase)
						  << " fault=" << static_cast<unsigned>( fault)
						  << " selected=" << selected.size() << " item=" << index + 1U
						  << " error=" << item.installError
						  << " roles=" << item.requiredRoles.size()
						  << " device1Calls=" << observed.deviceInstalls[0]
						  << " device2Calls=" << observed.deviceInstalls[1]
						  << " stages=" << observed.stages << '\n' ;
			}
		}

		const bool secondReached = !rejected ||
								   // 原API拒否と前段拒否です
								   fault == SignedIndexBindingBatchFault::SECOND_API_DENIED ;
		DRIVERCRATE_EXPECT(
			context, observed.stages == 1U &&
						 observed.installs == (batch && !secondReached ? 1U : selected.size()) &&
						 observed.deviceInstalls[0] == (batch ? 1U : 0U) &&
						 observed.deviceInstalls[1] == (secondReached ? 1U : 0U) &&
						 observed.restoreBegins == 1U && observed.restoreCompletes == 1U) ;
		bound.worker->stop() ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
	}

	std::cout << "Authenticated per-device cases: " << cases.size()
			  << ", failures: " << context.failureCount() - firstFailures
			  << ", shared acquisition=1, explicit one/two device selection, real OS changes=0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 独自クラスの元署名recordから端末照合と明示した指定導入を検証します
 * @param[in,out] context 各ケースの候補・同意・低位操作回数の集計先です
 * @param[in] services RAM署名store・固定時計・完全HTTP fakeを持つworker入力です
 * @param[in] zip 非実行の人工INF・CAT・SYSを含む元配布物です
 */
//------------------------------------------------------------------------------
void runDeclarativeClassBindingCases( TestContext						   &context,
									 provider_worker_index_detail::Services services,
									 const std::string_view					zip)
{
	using Case = SignedIndexBindingNativeCase ;
	using driver_store_inf_detail::Access ;
	const auto firstFailure = context.failureCount() ;	// 本グループの開始時点です
	auto	   transport	= calls() ;					// 既存の完全fakeにだけ独自クラス表を加えます
	DRIVERCRATE_EXPECT( context,
					   !transport.declarativeClass && Access::create( transport) != nullptr) ;
	transport.declarativeClass.emplace() ;
	DRIVERCRATE_EXPECT( context, !Access::create( transport)) ;
	transport.declarativeClass = declarativeCalls() ;
	DRIVERCRATE_EXPECT( context, Access::create( transport) != nullptr) ;
	// 読取り表は全slotについて、欠落と同じ実Windows APIの混入を個別に拒否します
	const auto rejectSlot = [&]( auto member, auto nativeApi) {
		auto changedTable = transport ;	// 一項目だけを差し替える完全表の複写です
		changedTable.declarativeClass->observation.*member = nullptr ;
		DRIVERCRATE_EXPECT( context, !Access::create( changedTable)) ;
		changedTable.declarativeClass->observation.*member = nativeApi ;
		DRIVERCRATE_EXPECT( context, !Access::create( changedTable)) ;
	} ;
	rejectSlot( &SetupClassReadApi::className, &SetupDiClassNameFromGuidW) ;
	rejectSlot( &SetupClassReadApi::classGuids, &SetupDiClassGuidsFromNameW) ;
	rejectSlot( &SetupClassReadApi::openClassKey, &SetupDiOpenClassRegKeyExW) ;
	rejectSlot( &SetupClassReadApi::classProperty, &SetupDiGetClassPropertyW) ;
	rejectSlot( &SetupClassReadApi::deviceProperty, &SetupDiGetDevicePropertyW) ;
	rejectSlot( &SetupClassReadApi::openKey, &RegOpenKeyExW) ;
	rejectSlot( &SetupClassReadApi::readValue, &RegQueryValueExW) ;
	rejectSlot( &SetupClassReadApi::closeKey, &RegCloseKey) ;
	transport.declarativeClass				  = declarativeCalls() ;
	transport.declarativeClass->storeLocation = nullptr ;
	DRIVERCRATE_EXPECT( context, !Access::create( transport)) ;
	transport.declarativeClass				  = declarativeCalls() ;
	transport.declarativeClass->storeLocation = &SetupGetInfDriverStoreLocationW ;
	DRIVERCRATE_EXPECT( context, !Access::create( transport)) ;

	constexpr NativeError expired =
		// 固定した元期限です
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
	constexpr NativeError changed =
		// 元行またはクラスの差です
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
	constexpr NativeError digest =
		// 同長で別のCATまたはSYSです
		static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
	const struct {
		const char *name ;			// 集計で表示する人工入力です
		Case		condition ;		// Windowsに与える端末・配置・時計の条件です
		unsigned	candidates ;	// 元内容から発行されるべき候補数です
		unsigned	stages ;		// fake SetupCopyOEMInfWの呼出し数です
		unsigned	installs ;		// 非nullの指定nodeでのDiInstallDevice呼出し数です
		NativeError error ;			// 実行結果に残すべき元診断です
	} cases[]{
		{"first-registration", Case::DECLARATIVE_INITIAL, 1U, 1U, 1U, 0U},
		{"already-registered", Case::DECLARATIVE_REGISTERED, 1U, 1U, 1U, 0U},
		{"null-service", Case::DECLARATIVE_NULL_ROW, 0U, 0U, 0U, 0U},
		{"expired-before-stage", Case::DECLARATIVE_EXPIRED_BEFORE_STAGE, 1U, 0U, 0U, expired},
		{"expired-before-apply", Case::DECLARATIVE_EXPIRED_AFTER_STAGE, 1U, 1U, 0U, expired},
		{"registration-changed", Case::DECLARATIVE_CLASS_AFTER_STAGE, 1U, 1U, 0U, changed},
		{"staged-row-reordered", Case::DECLARATIVE_ROW_AFTER_STAGE, 1U, 1U, 0U, changed},
		{"same-inf-other-cat", Case::DECLARATIVE_OTHER_CATALOG, 1U, 1U, 0U, digest},
		{"same-inf-other-sys", Case::DECLARATIVE_OTHER_DRIVER, 1U, 1U, 0U, digest},
	} ;
	static_assert( std::size( cases) == DECLARATIVE_BINDING_CASE_COUNT) ;
	// 独立workerを使い、前のケースの登録状態や同意を次に引き継ぎません
	for( const auto &example : cases) {
		auto bound = makeSignedIndexBindingWorker(
			services, zip, false, false, false, example.condition) ;	// 元storeとWindows低位fakeです
		OperationController controller ;								// 本体と同じ操作ID・選択・明示同意の所有者です
		ScanOptions			options ;									// Driver Storeと署名済み索引だけを有効にします
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
									   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		const auto scan				= controller.beginScan() ;	// このケースの元検索です
		DRIVERCRATE_EXPECT( context,
						   scan.accepted && bound.worker->requestScan( scan.operationId, options)) ;
		auto scanned = waitEvent( *bound.worker, WorkerEventKind::SCAN_COMPLETED,
								 scan.operationId) ;	// 検索終端です
		DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan &&
										scanned->preparationPlan->targets.size() == 1U) ;
		// 取得計画の欠損を空サービスの正常な候補なしと数えません
		if( !scanned || !scanned->preparationPlan ||
		   scanned->preparationPlan->targets.size() != 1U) {
			std::cout << "DECLARATIVE_BINDING case=" << example.name << " no request plan\n" ;
			bound.worker->stop() ;
			continue ;
		}

		const auto &plan = *scanned->preparationPlan ;	// 元一件の取得計画です
		DRIVERCRATE_EXPECT( context,
						   controller.completeScan( scan.operationId, scanned->scanResult) &&
							   controller.setPreparationPlan( scan.operationId, plan)) ;
		OfficialPreparationApproval approval{
			0U, plan.scanSessionId, plan.planId, plan.limits, {}} ;	// 取得の同意です
		approval.decisions.push_back( {plan.targets.front(), true, false, false, false}) ;
		const auto request = controller.beginPreparation( approval) ;	// 本体が割り当てる取得操作です
		DRIVERCRATE_EXPECT( context, request.accepted && bound.worker->requestPreparation( approval)) ;
		auto prepared = waitEvent( *bound.worker, WorkerEventKind::PREPARATION_COMPLETED,
								  approval.operationId) ;	// 内容・適合監査の終端です
		DRIVERCRATE_EXPECT( context, prepared && prepared->indexPreparation.items.size() == 1U &&
										prepared->preparationResult.auditReports.size() == 1U) ;
		// 内容監査へ到達していない失敗を通常拒否の証拠にしません
		if( !prepared || prepared->indexPreparation.items.size() != 1U ||
		   prepared->preparationResult.auditReports.size() != 1U) {
			std::cout << "DECLARATIVE_BINDING case=" << example.name << " missing content report\n" ;
			bound.worker->stop() ;
			continue ;
		}

		const auto &item =
			// 同じ元参照の取得と検査結果です
			prepared->indexPreparation.items.front() ;
		const auto &report = prepared->preparationResult.auditReports.front() ;	// 同scanの元候補です
		const auto &candidates = report.publishedCandidates ;					// 実際に発行した候補だけを確認します
		const auto	beforeConsent = bound.observe() ;							// stage・復元・指定導入の開始前です
		std::cout << "DECLARATIVE_BINDING case=" << example.name
				  << " acquisition=" << item.acquisitionError << " content=" << item.contentError
				  << " acceptedINF=" << item.acceptedInfCount
				  << " examined=" << report.examinedPairCount
				  << " applicable=" << report.applicablePairCount
				  << " failedPairs=" << report.failedPairCount
				  << " pairError=" << report.firstPairError
				  << " publicationError=" << report.publication.firstError
				  << " candidates=" << candidates.size() << '\n' ;
		DRIVERCRATE_EXPECT( context,
						   item.acquisitionError == 0U && item.contentError == 0U &&
							   item.acceptedInfCount == 1U && report.examinedPairCount == 1U &&
							   report.failedPairCount == 0U && report.firstPairError == 0U &&
							   report.applicablePairCount == example.candidates &&
							   candidates.size() == example.candidates) ;
		DRIVERCRATE_EXPECT(
			context,
			beforeConsent.signature.setupCalls > 0U && beforeConsent.signature.verifyCalls > 0U &&
				beforeConsent.signature.rejectedCalls == 0U && beforeConsent.stages == 0U &&
				beforeConsent.installs == 0U && beforeConsent.restoreBegins == 0U &&
				beforeConsent.declarativePreStageRootReads == 0U) ;
		DRIVERCRATE_EXPECT( context, controller.completePreparation( prepared->preparationResult,
																   scanned->scanResult.candidates)) ;
		// 空サービス行は取得と内容合格後も選択できる指定導入候補を発行しません
		if( example.candidates == 0U || candidates.size() != 1U) {
			bound.worker->stop() ;
			DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
			continue ;
		}

		const auto &candidate = candidates.front() ;	// 完全な所有経路で発行した一件です
		DRIVERCRATE_EXPECT( context, candidate.assessment &&
										isCandidateAssessmentReady( *candidate.assessment)) ;
		const auto &registration =
			candidate.setupClassRegistration ;	// 最終同意画面へ渡す初回登録の表示です
		// 既登録クラスには新規登録の表示を発行せず、初回登録では元INFの全値を読みます
		if( example.condition == Case::DECLARATIVE_REGISTERED) {
			DRIVERCRATE_EXPECT( context, !registration) ;
		} else {
			DRIVERCRATE_EXPECT(
				context, registration && registration->className == L"DCFixtureBridge" &&
							 registration->classGuid == L"{c054bd69-a76e-4caa-a915-e3ce9a285b62}" &&
							 registration->displayName == L"Fixture bridge devices" &&
							 registration->builtInIcon == -10) ;
		}

		const std::array selected{candidate.identity} ;	// 元の一端末・一行だけを明示します
		const auto		 refused = controller.beginInstall(
			  plan.scanSessionId, selected, InstallConfirmation::NOT_CONFIRMED) ;	// 取消しの元結果です
		DRIVERCRATE_EXPECT( context, !refused.accepted &&
										refused.error == BeginError::CONFIRMATION_REQUIRED &&
										bound.observe().restoreBegins == 0U) ;
		const auto installRequest =
			controller.beginInstall( plan.scanSessionId, selected,
									InstallConfirmation::CONFIRMED) ;	// 同じ選択への明示同意です
		DRIVERCRATE_EXPECT( context,
						   installRequest.accepted &&
							   bound.worker->requestInstall(
								   installRequest.operationId, plan.scanSessionId, selected,
								   nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
		auto	   installed = waitEvent( *bound.worker, WorkerEventKind::INSTALL_COMPLETED,
										 installRequest.operationId) ;	// fake復元と実workerの終端です
		const auto after	 = bound.observe() ;						// Windows ABIの実呼出し数です
		DRIVERCRATE_EXPECT( context, installed && installed->installResult.updates.size() == 1U) ;
		// 個別の元診断を集約だけの成功または保留へ読み替えません
		if( installed && installed->installResult.updates.size() == 1U) {
			const auto &update =
				// 指定した候補一件の結果です
				installed->installResult.updates.front() ;
			std::cout << "DECLARATIVE_INSTALL case=" << example.name
					  << " error=" << update.installError << " restore=" << after.restoreBegins
					  << "/" << after.restoreCompletes
					  << " preStageRoot=" << after.declarativePreStageRootReads
					  << " storeLookup=" << after.declarativeStoreReads << " stage=" << after.stages
					  << " apply=" << after.installs << '\n' ;
			DRIVERCRATE_EXPECT( context,
							   update.identity == candidate.identity &&
								   update.installError == example.error &&
								   update.installOutcome == (example.error ? OutcomeCode::FAILURE
																		   : OutcomeCode::SUCCESS)) ;
			DRIVERCRATE_EXPECT( context, controller.completeInstall( installRequest.operationId,
																   installed->installResult)) ;
		}

		DRIVERCRATE_EXPECT( context,
						   after.stages == example.stages && after.installs == example.installs &&
							   after.deviceInstalls[0] == example.installs &&
							   after.deviceInstalls[1] == 0U && after.specifiedBindingMatches &&
							   after.restoreBegins == 1U && after.restoreCompletes == 1U) ;
		DRIVERCRATE_EXPECT( context,
						   after.declarativePreStageRootReads == (example.stages == 0U ? 1U : 2U) &&
							   after.declarativeStoreReads >= example.stages) ;
		bound.worker->stop() ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
	}

	std::cout << "Declarative class binding cases=" << std::size( cases)
			  << " failures=" << context.failureCount() - firstFailure << '\n' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元tuple内の唯一最小rankと全列挙・指定直前の変化を通常workerで確認します
 * @param[in,out] context 原assertionと失敗を保持する集計先です
 * @param[in] services 真署名隔離store、完全fake HTTP、固定UTCの所有callbackです
 * @param[in] zip 元人工INF/SYS/CAT全byteです。実Windowsのstage/導入/復元は呼びません
 */
//------------------------------------------------------------------------------
void testUniqueWindowsRankBinding( TestContext							&context,
								  provider_worker_index_detail::Services services,
								  const std::string_view				 zip)
{
	const auto			 firstFailures = context.failureCount() ;	// 本回帰の元失敗差だけを報告します
	constexpr std::array cases{
		SignedIndexBindingNativeCase::RANK_BEST_FIRST,
		SignedIndexBindingNativeCase::RANK_BEST_LAST,
		SignedIndexBindingNativeCase::RANK_BEST_TIED,
		SignedIndexBindingNativeCase::RANK_TIE_THEN_BETTER,
		SignedIndexBindingNativeCase::RANK_OTHER_PROVIDER,
		SignedIndexBindingNativeCase::RANK_OTHER_VERSION,
		SignedIndexBindingNativeCase::RANK_OTHER_DATE,
		SignedIndexBindingNativeCase::RANK_OTHER_INF,
		SignedIndexBindingNativeCase::RANK_LATE_ERROR,
		SignedIndexBindingNativeCase::RANK_LATE_DETAIL_ERROR,
		SignedIndexBindingNativeCase::RANK_ENUMERATION_ERROR,
		SignedIndexBindingNativeCase::RANK_ENUMERATION_LIMIT,
		SignedIndexBindingNativeCase::RANK_NO_CANDIDATE,
		SignedIndexBindingNativeCase::RANK_WINNER_CHANGED,
		SignedIndexBindingNativeCase::RANK_TIE_CHANGED,
		SignedIndexBindingNativeCase::RANK_STAGE_BETTER,
		SignedIndexBindingNativeCase::RANK_STAGE_TIED} ;	// 実行前に分母を固定します
	// 各caseは独立した真署名storeと同workerの完全低位tableを使用します
	for( const auto nativeCase : cases) {
		auto				bound = makeSignedIndexBindingWorker( services, zip, false, false, false,
																 nativeCase) ;	// 全低位fakeです
		OperationController controller ;										// 通常のscan/準備/選択/失効状態機械です
		ScanOptions			options ;											// 元Driver Storeと署名索引だけを有効にします
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
									   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		const auto scan				= controller.beginScan() ;	// 同scanの終端まで保持します
		DRIVERCRATE_EXPECT( context,
						   scan.accepted && bound.worker->requestScan( scan.operationId, options)) ;
		auto scanned = waitEvent( *bound.worker, WorkerEventKind::SCAN_COMPLETED,
								 scan.operationId) ;	// 同queueの終端です
		DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan &&
										scanned->preparationPlan->targets.size() == 1U) ;
		// 前提未達を負例成功へ数えず、同workerを正常停止します
		if( !scanned || !scanned->preparationPlan ||
		   scanned->preparationPlan->targets.size() != 1U) {
			bound.worker->stop() ;
			continue ;
		}

		const auto &plan = *scanned->preparationPlan ;	// 原一取得groupを同期借用します
		DRIVERCRATE_EXPECT( context,
						   controller.completeScan( scan.operationId, scanned->scanResult) &&
							   controller.setPreparationPlan( scan.operationId, plan)) ;
		OfficialPreparationApproval approval{
			0U, plan.scanSessionId, plan.planId, plan.limits, {}} ;	// 取得だけの同意です
		approval.decisions.push_back( {plan.targets[0], true, false, false, false}) ;
		const auto preparation =
			// 導入同意とは別operationです
			controller.beginPreparation( approval) ;
		DRIVERCRATE_EXPECT( context,
						   preparation.accepted && bound.worker->requestPreparation( approval)) ;
		auto prepared = waitEvent( *bound.worker, WorkerEventKind::PREPARATION_COMPLETED,
								  approval.operationId) ;	// 元終端です
		std::vector<UpdateCandidate> candidates ;			// 元publicationだけを保持します
		NativeError					 diagnostic{} ;			// 元拒否を数値のまま残します
		// 成功候補を合成せず、実workerの元監査を読みます
		if( prepared) {
			// 元のpair失敗とbinding拒否を区別して保存します
			for( const auto &report : prepared->preparationResult.auditReports) {
				candidates.insert( candidates.end(), report.publishedCandidates.begin(),
								  report.publishedCandidates.end()) ;
				diagnostic = report.publication.firstError ? report.publication.firstError
														   : report.firstPairError ;
			}
		}

		const bool preparationRejected =
			nativeCase == SignedIndexBindingNativeCase::RANK_BEST_TIED ||
			nativeCase == SignedIndexBindingNativeCase::RANK_OTHER_DATE ||
			nativeCase == SignedIndexBindingNativeCase::RANK_OTHER_INF ||
			(nativeCase >= SignedIndexBindingNativeCase::RANK_LATE_ERROR &&
			 nativeCase <=
				 SignedIndexBindingNativeCase::
					 RANK_NO_CANDIDATE) ;	// 正常終端前の不足と元tuple不一致を含む八負例です
		DRIVERCRATE_EXPECT( context,
						   prepared && prepared->indexPreparation.items.size() == 1U &&
							   prepared->indexPreparation.items[0].acquisitionError == 0U &&
							   prepared->indexPreparation.items[0].contentError == 0U &&
							   prepared->indexPreparation.items[0].acceptedInfCount == 1U &&
							   candidates.size() == (preparationRejected ? 0U : 1U) &&
							   bound.observe().stages == 0U && bound.observe().installs == 0U) ;
		// 元最良同点とAPI/上限失敗は原HRESULTも確認します
		if( nativeCase == SignedIndexBindingNativeCase::RANK_BEST_TIED) {
			DRIVERCRATE_EXPECT( context, diagnostic == static_cast<NativeError>(
														  HRESULT_FROM_WIN32( ERROR_DUP_NAME))) ;
		}

		// 前段の既存rank監査が元date/pathより広い場合、その不一致拒否を維持します
		if( nativeCase == SignedIndexBindingNativeCase::RANK_OTHER_DATE ||
		   nativeCase == SignedIndexBindingNativeCase::RANK_OTHER_INF) {
			DRIVERCRATE_EXPECT(
				context, diagnostic == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY))) ;
		}

		// 途中障害の原codeを別の曖昧性診断へ置換しません
		if( nativeCase == SignedIndexBindingNativeCase::RANK_LATE_ERROR ||
		   nativeCase == SignedIndexBindingNativeCase::RANK_LATE_DETAIL_ERROR ||
		   nativeCase == SignedIndexBindingNativeCase::RANK_ENUMERATION_ERROR ||
		   nativeCase == SignedIndexBindingNativeCase::RANK_ENUMERATION_LIMIT) {
			const DWORD expected =
				nativeCase == SignedIndexBindingNativeCase::RANK_LATE_ERROR ? ERROR_ACCESS_DENIED
				: nativeCase == SignedIndexBindingNativeCase::RANK_LATE_DETAIL_ERROR
					? ERROR_READ_FAULT
				: nativeCase == SignedIndexBindingNativeCase::RANK_ENUMERATION_ERROR
					? ERROR_IO_DEVICE
					: ERROR_TOO_MANY_NAMES ;	// 元Windows診断です
			DRIVERCRATE_EXPECT( context, diagnostic ==
											static_cast<NativeError>( HRESULT_FROM_WIN32( expected))) ;
		}

		// 必要な候補がなければ実導入経路へ進めません
		if( preparationRejected || !prepared || candidates.size() != 1U) {
			std::cout << "UNIQUE_WINDOWS_RANK case=" << static_cast<unsigned>( nativeCase)
					  << " candidates=" << candidates.size() << " error=" << diagnostic
					  << " stage=0 install=0\n" ;
			bound.worker->stop() ;
			DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
			continue ;
		}

		DRIVERCRATE_EXPECT( context,
						   candidates[0].assessment &&
							   isCandidateAssessmentReady( *candidates[0].assessment) &&
							   controller.completePreparation( prepared->preparationResult,
															  scanned->scanResult.candidates)) ;
		const bool changedBeforeInstall =
			nativeCase == SignedIndexBindingNativeCase::RANK_WINNER_CHANGED ||
			nativeCase ==
				SignedIndexBindingNativeCase::RANK_TIE_CHANGED ;	// 公表後の元低位だけを変えます
		// 結果DTOへ触れずに現在nodeの原rankだけを変更します
		if( changedBeforeInstall) {
			bound.changeNativeState() ;
		}

		const bool stageChanged = nativeCase == SignedIndexBindingNativeCase::RANK_STAGE_BETTER ||
								  // 登録先だけの変化です
								  nativeCase == SignedIndexBindingNativeCase::RANK_STAGE_TIED ;
		const std::array selected{candidates[0].identity} ;	// 明示した一deviceだけです
		const auto		 installation = controller.beginInstall(
			  plan.scanSessionId, selected, InstallConfirmation::CONFIRMED) ;	// 全作用はfakeです
		DRIVERCRATE_EXPECT( context, installation.accepted &&
										bound.worker->requestInstall(
											installation.operationId, plan.scanSessionId, selected,
											nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
		auto	   installed = waitEvent( *bound.worker, WorkerEventKind::INSTALL_COMPLETED,
										 installation.operationId) ;	// fake終端まで待ちます
		const bool rejected	 = changedBeforeInstall || stageChanged ;	// 拒否を成功へ丸めません
		DRIVERCRATE_EXPECT( context,
						   installed && installed->installResult.updates.size() == 1U &&
							   installed->installResult.updates[0].installOutcome ==
								   (rejected ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS)) ;
		const auto observed = bound.observe() ;	// operation終端後だけ低位counterを読みます
		DRIVERCRATE_EXPECT( context, observed.stages == (changedBeforeInstall ? 0U : 1U) &&
										observed.installs == (rejected ? 0U : 1U) &&
										observed.deviceInstalls[1] == 0U &&
										observed.specifiedBindingMatches) ;
		// 同operation完了後の旧scan/候補を再選択させません
		if( installed) {
			DRIVERCRATE_EXPECT(
				context,
				controller.completeInstall( installation.operationId, installed->installResult) &&
					!controller
						 .beginInstall( plan.scanSessionId, selected, InstallConfirmation::CONFIRMED)
						 .accepted) ;
		}

		std::cout << "UNIQUE_WINDOWS_RANK case=" << static_cast<unsigned>( nativeCase)
				  << " candidates=1 stage=" << observed.stages << " install=" << observed.installs
				  << " real changes=0\n" ;
		bound.worker->stop() ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
	}

	std::cout << "Unique Windows rank cases: " << cases.size()
			  << ", failures: " << context.failureCount() - firstFailures
			  << ", real OS changes=0\n" ;
}

/** @brief 選択端末の上位フィルターの二段階読取りを模擬する元データです */
struct WifiBusFilterReadCase {
	/// 終端を含む原UTF-16データです
	std::span<const wchar_t> value ;
	/// 最初の容量照会の診断です
	DWORD					 firstError{ERROR_INSUFFICIENT_BUFFER} ;
	/// 本データ取得の診断です
	DWORD					 secondError{ERROR_SUCCESS} ;
	/// 容量照会が返す元型です
	DEVPROPTYPE				 firstType{DEVPROP_TYPE_STRING_LIST} ;
	/// 本データ取得が返す元型です
	DEVPROPTYPE				 secondType{DEVPROP_TYPE_STRING_LIST} ;
	/// 検査で期待する最終エラーです
	DWORD					 expectedError{ERROR_SUCCESS} ;
	/// 検査が返す元観測状態です
	MtdHandlerState			 expectedState{MtdHandlerState::PRESENT} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 選択した一端末の上位フィルターだけを架空の二段階観測へ結びます
 * @param[in] set 元観測を保持する同期中の架空handleです
 * @param[in] device 同じ固定devnodeです
 * @param[in] key 上位フィルターの固定keyです
 * @param[out] type 当該呼び出しの型です
 * @param[out] buffer 容量照会ではnull、本取得では元バイトの出力です
 * @param[in] capacity 出力容量のバイト数です
 * @param[out] required 呼び出しが返す元容量です
 * @param[in] flags 予約値0です
 * @return 元結果成功でTRUE、容量照会と元失敗では診断を設定してFALSEです
 */
//------------------------------------------------------------------------------
BOOL WINAPI wifiBusFilterFixtureProperty( HDEVINFO set, PSP_DEVINFO_DATA device,
										 const DEVPROPKEY *key, DEVPROPTYPE *type, PBYTE buffer,
										 DWORD capacity, PDWORD required, DWORD flags)
{
	// 別端末・別キーの読取りは元値を返さず失敗させます
	if( !set || !device || device->DevInst != 42U || !key ||
	   !sameKey( *key, DEVPKEY_Device_UpperFilters) || !type || !required || flags != 0U) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	const auto &fixture = *static_cast<const WifiBusFilterReadCase *>( set) ;	// 同期間だけ借用します
	*required			= static_cast<DWORD>( fixture.value.size_bytes()) ;
	// 最初の照会は元型と容量だけを観測します
	if( !buffer) {
		*type = fixture.firstType ;
		SetLastError( fixture.firstError) ;
		return FALSE ;
	}

	// 正しい容量でも二回目が独立に失敗し得ることを確認します
	if( capacity != *required || fixture.secondError != ERROR_SUCCESS) {
		SetLastError( capacity != *required ? ERROR_INSUFFICIENT_BUFFER : fixture.secondError) ;
		return FALSE ;
	}

	*type = fixture.secondType ;
	std::memcpy( buffer, fixture.value.data(), capacity) ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 上位フィルターの置換に必要な選択端末の読取りを正負対照で確認します
 * @param[in,out] context 同processの有限な検査集計です
 * @note 端末の列挙、フィルター変更や導入APIは呼びません
 */
//------------------------------------------------------------------------------
void testWifiBusUpperFilters( TestContext &context)
{
	constexpr wchar_t	  EMPTY[]	   = L"" ;						// 単一終端で返る元の空値です
	constexpr wchar_t	  EMPTY_PAIR[] = L"\0" ;					// 二重終端で返る元の空値です
	constexpr wchar_t	  SINGLE[]	   = L"VWifiBus\0" ;			// 大小文字の異なる同じサービスです
	constexpr wchar_t	  OTHER[]	   = L"fixture1\0" ;			// 同じ長さでも別のフィルターです
	constexpr wchar_t	  MULTIPLE[]   = L"vwifibus\0fixture1\0" ;	// 置換で失われる別要素があります
	constexpr wchar_t	  DUPLICATE[]  = L"vwifibus\0vwifibus\0" ;	// 単一に縮約できない元値です
	constexpr wchar_t	  NO_TERMINATOR[] = L"vwifibus" ;			// 二重終端を欠いています
	WifiBusFilterReadCase cases[]{
		{{},
		 ERROR_NOT_FOUND,
		 ERROR_SUCCESS,
		 DEVPROP_TYPE_EMPTY,
		 DEVPROP_TYPE_EMPTY,
		 ERROR_SUCCESS,
		 MtdHandlerState::ABSENT},
		{EMPTY, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, DEVPROP_TYPE_STRING_LIST,
		 DEVPROP_TYPE_STRING_LIST, ERROR_SUCCESS, MtdHandlerState::EMPTY_LIST},
		{EMPTY_PAIR, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, DEVPROP_TYPE_STRING_LIST,
		 DEVPROP_TYPE_STRING_LIST, ERROR_SUCCESS, MtdHandlerState::EMPTY_LIST},
		{SINGLE},
		{OTHER, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, DEVPROP_TYPE_STRING_LIST,
		 DEVPROP_TYPE_STRING_LIST, ERROR_NOT_SUPPORTED},
		{MULTIPLE, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, DEVPROP_TYPE_STRING_LIST,
		 DEVPROP_TYPE_STRING_LIST, ERROR_NOT_SUPPORTED},
		{DUPLICATE, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, DEVPROP_TYPE_STRING_LIST,
		 DEVPROP_TYPE_STRING_LIST, ERROR_NOT_SUPPORTED},
		{NO_TERMINATOR, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, DEVPROP_TYPE_STRING_LIST,
		 DEVPROP_TYPE_STRING_LIST, ERROR_INVALID_DATA},
		{SINGLE, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, DEVPROP_TYPE_STRING_LIST,
		 DEVPROP_TYPE_STRING, ERROR_INVALID_DATA},
		{SINGLE, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND, DEVPROP_TYPE_STRING_LIST,
		 DEVPROP_TYPE_STRING_LIST, ERROR_RETRY},
		{{},
		 ERROR_ACCESS_DENIED,
		 ERROR_SUCCESS,
		 DEVPROP_TYPE_EMPTY,
		 DEVPROP_TYPE_EMPTY,
		 ERROR_ACCESS_DENIED},
	} ; // 同端末について確認する元観測と期待値です
	SP_DEVINFO_DATA device{} ;	// 架空の選択端末です
	device.cbSize  = sizeof( device) ;
	device.DevInst = 42U ;
	// 不在、空、単一、大きさや型の違いと読取り失敗を独立に照合します
	for( auto &fixture : cases) {
		MtdHandlerProperty observed ;	// 検査後の原値です
		// 架空APIで返した型と元状態を実readerが採用した結果です
		const auto		   error =
			observeWifiBusUpperFilters( &fixture, device, wifiBusFilterFixtureProperty, observed) ;
		DRIVERCRATE_EXPECT( context, error == HRESULT_FROM_WIN32( fixture.expectedError)) ;
		// 成功した値は型と全byteが元のままであることも検査します
		if( error == 0U) {
			DRIVERCRATE_EXPECT( context, observed.state == fixture.expectedState) ;
			DRIVERCRATE_EXPECT( context, observed.type == fixture.secondType) ;
			DRIVERCRATE_EXPECT( context,
							   std::ranges::equal( observed.bytes, std::as_bytes( fixture.value))) ;
		} else {
			DRIVERCRATE_EXPECT( context, observed.bytes.empty()) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 真署名reload・実HTTP fake・正常ZIPを通常本体へ接続します
 * @param[in,out] context Assertion正本です
 * @param[in] services 真署名store・固定UTC・完全HTTPの依存です
 * @param[in] zip 非空INF/SYS/CATの実原containerです
 * @param[in] network Net classの固定fixtureならtrueです
 */
//------------------------------------------------------------------------------
void runSignedIndexCandidateBindingTests( TestContext						   &context,
										 provider_worker_index_detail::Services services,
										 const std::string_view zip, const bool network)
{
	// 通常一recordのPorts fixtureだけで新private個別観測の三条件を一回確認します
	if( !network) {
		testWifiBusUpperFilters( context) ;
		testAuthenticatedSameIdDevices( context, services, zip) ;
		testUniqueWindowsRankBinding( context, services, zip) ;
	}

	// 今回の限定試験の開始assertion数
	const auto before = context.assertionCount() ;
	// 開始時の失敗数。既存失敗を今回の結果へ加算しない
	const auto failures = context.failureCount() ;
	// 元ZIPから採取した全memberの実hash期待値
	const auto files  = signatureFiles( zip) ;
	const auto source = services.load( services.utc()) ;	// 実署名済みfixtureの元配布申告です
	DRIVERCRATE_EXPECT(
		context, source.snapshot && source.snapshot->schemaReceipt().records().size() == 1U &&
					 source.snapshot->schemaReceipt().records().front().version.value == "1.2.3.4") ;
	// 他node不足を残す実private positiveから版投影/同sessionの新版確認へ接続します
	if( !network) {
		auto bound = makeSignedIndexBindingWorker(
			services, zip, false, false, false,
			SignedIndexBindingNativeCase::
				INDEX_VERIFIED_PARTIAL) ;	// 低位APIだけを固定した通常workerです
		auto controllerOwner =
			std::make_unique<OperationController>() ;		// 大きい原stateをheapへ所有します
		auto	   &controller = *controllerOwner ;			// 同scopeの実受付/終端を借用します
		const auto	begin	   = controller.beginScan() ;	// 正の元operationです
		ScanOptions options ;								// 索引と現在観測だけです
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring( DRIVER_STORE_PROVIDER_ID),
									   std::wstring( SIGNED_INDEX_PROVIDER_ID)} ;
		DRIVERCRATE_EXPECT( context,
						   begin.accepted && bound.worker->requestScan( begin.operationId, options)) ;
		const auto scanned = waitEvent( *bound.worker, WorkerEventKind::SCAN_COMPLETED,
									   begin.operationId) ;	// 通常makeReferencesの実結果です
		DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded &&
										scanned->preparationPlan &&
										scanned->indexSummary.verifiedPartialRelations > 0U &&
										scanned->indexSummary.undeterminedRelations > 0U) ;
		// 正当な参照がある場合だけ、公開DTOを作り足さず元結果を比較します
		if( scanned && scanned->preparationPlan) {
			std::size_t newer{} ;	// 実makeReferences由来の新版確認数だけです
			// 同元record/deviceの非導入参照を検査します
			for( const auto &candidate : scanned->scanResult.candidates) {
				// 現在行と他Providerは参照件数へ含めません
				if( candidate.providerId != SIGNED_INDEX_PROVIDER_ID || candidate.current) {
					continue ;
				}

				const auto relation = classifyPendingReferenceVersion(
					candidate, scanned->scanResult.candidates,
					scanned->scanResult.scanSessionId) ;	// 原観測だけです
				newer += relation == PendingReferenceVersion::NEWER ;
				DRIVERCRATE_EXPECT(
					context,
					candidate.version == L"1.2.3.4" && !candidate.installable &&
						!candidate.recommended && candidate.action == DriverAction::NONE &&
						candidate.packageIdentity.empty() &&
						!candidate.preparationTargetIdentity.empty() &&
						isCandidateDetailsValid( candidate, scanned->scanResult.scanSessionId)) ;
			}

			DRIVERCRATE_EXPECT(
				context,
				newer == 1U && controller.completeScan( begin.operationId, scanned->scanResult) &&
					controller.setPreparationPlan( begin.operationId, *scanned->preparationPlan)) ;
		}

		bound.worker->stop() ;
		DRIVERCRATE_EXPECT( context, bound.observe().stages == 0U && bound.observe().installs == 0U) ;
		std::cout
			<< "PENDING_REFERENCE_PARTIAL_CONNECTION nativeProof=1 expectedNewer=1 installs=0\n" ;
	}

	DRIVERCRATE_EXPECT( context, !driver_store_inf_detail::Access::create(
									{})) ;	// 不完全表のnative fallbackを拒否します
	const auto ownerInf = std::ranges::find_if( files, []( const auto &file) {
		return file.name.ends_with( L".inf") ;
	}) ; // 元ZIPから既に固定したroot直下INFです
	DRIVERCRATE_EXPECT( context, ownerInf != files.end()) ;
	// 実ownerがある場合だけ十二不正名を同じ完全表へ追加してfactory拒否を確認します
	if( ownerInf != files.end()) {
		constexpr std::array<std::wstring_view, 12U> INVALID_MEMBER_NAMES{
			L"..\\component_service.exe",
			L"\\component_service.exe",
			L"bin\\..\\component_service.exe",
			L"bin\\",
			L"bin\\\\component_service.exe",
			L"bin/component_service.exe",
			L"bin:payload.exe",
			L"bin\\CON.exe",
			L"bin\\nul.dll",
			L"bin\\LPT1.exe",
			L"bin\\bad<name.exe",
			L"bin\\bad\u0080.exe"} ;	// 元七と新五の固定拒否分母です
		// 元INF/CAT/hashを保持し、各不正segmentだけを一度ずつfactoryへ渡します
		for( const auto name : INVALID_MEMBER_NAMES) {
			auto invalid = files ;	// 各条件で独立所有する完全表です
			invalid.push_back( {std::wstring( name), std::wstring( 64U, L'0'), ownerInf->name}) ;
			DRIVERCRATE_EXPECT(
				context, !driver_package_signature_detail::Access::create( std::move( invalid))) ;
		}
	}

	// Netは通常更新一回、Portsは版分類・失敗・再起動を別modeで確認します
	for( unsigned mode = 0U; mode < (network ? 1U : 6U); ++mode) {
		// 同workerが寿命内だけ借用する低位API状態の共有所有者
		auto native				= std::make_shared<NativeFixtureState>() ;
		native->mode			= mode ;
		native->nativeCase		= mode == 5U ? SignedIndexBindingNativeCase::INITIAL
											 : SignedIndexBindingNativeCase::NORMAL ;
		native->network			= network ;
		native->currentVersion	= mode == 1U ? L"1.0.0.0" : mode == 2U ? L"2.0.0.0" : L"0.9.0.0" ;
		native->currentProvider = L"Current Fixture Vendor" ;
		// 一modeのworker寿命へ固定する完全fake依存のcopy
		auto fixed	   = services ;
		auto signature = std::make_shared<driver_package_signature_detail::ScopedFixture *>(
			nullptr) ;	// Idle workerでだけreceiptを借用します
		fixed.driverStoreFixture = [native]() {
			activeNative = native.get() ;
			// 既存正常試験も実登録root内の別fileを必要とします
			if( !initializeRegistration( *native)) {
				return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
			}

			return driver_store_inf_detail::Access::create( calls()) ;
		} ;
		fixed.signatureFixture = [files, signature]() {
			// 全member期待値を所有しworker停止まで有効な署名表の単独所有者
			auto scope = driver_package_signature_detail::Access::create( files) ;
			*signature = scope.get() ;
			return scope ;
		} ;
		// 通常command queueを使用し全fake依存の寿命を所有する隔離worker
		auto worker = provider_worker_index_detail::Access::createAcquisitionFixture(
			[]() { return std::make_unique<CompositeUpdateProvider>() ; },
			[]() { return std::make_unique<FakeRestore>() ; }, std::move( fixed)) ;
		DRIVERCRATE_EXPECT( context, worker != nullptr) ;
		// worker生成が失敗した試験を導入成功へ進めません
		if( !worker) {
			continue ;
		}

		// 同scanのDriver Storeと索引だけを明示選択する設定
		ScanOptions options ;
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
									   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		auto controllerOwner =
			std::make_unique<OperationController>() ;	// 元scopeで原stateを所有します
		auto	  &controller = *controllerOwner ;		// MainWindowと同じ実core状態機械です
		// 元scan operationの開始許可とidentity
		const auto scan = controller.beginScan() ;
		DRIVERCRATE_EXPECT( context,
						   scan.accepted && worker->requestScan( scan.operationId, options)) ;
		// 同scanの実終端event。以後の同期確認期間を通して所有する
		auto scanned = waitEvent( *worker, WorkerEventKind::SCAN_COMPLETED, scan.operationId) ;
		DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded &&
										scanned->preparationPlan &&
										scanned->indexPreparation.plannedTargets == 1U) ;
		// 同scan準備planがない場合はworkerを停止して拒否を残します
		if( !scanned || !scanned->preparationPlan) {
			worker->stop() ;
			continue ;
		}

		// 内容検査前の非導入参照行数。内容合格候補へ計上しない
		const auto references =
			std::ranges::count_if( scanned->scanResult.candidates, []( const auto &candidate) {
				return candidate.providerId == SIGNED_INDEX_PROVIDER_ID && !candidate.installable ;
			}) ;
		DRIVERCRATE_EXPECT( context, references == 1) ;
		const auto reference =
			std::ranges::find_if( scanned->scanResult.candidates, []( const auto &candidate) {
				return candidate.providerId == SIGNED_INDEX_PROVIDER_ID && !candidate.installable ;
			}) ; // 内容検査前に通常画面へ渡された実参照行です
		// 参照が実在した場合だけ同deviceの現在観測と欠損情報を比較します
		if( reference != scanned->scanResult.candidates.end()) {
			const auto current =
				std::ranges::find_if( scanned->scanResult.candidates, [&]( const auto &candidate) {
					return candidate.current &&
						   candidate.deviceIdentity == reference->deviceIdentity ;
				}) ; // 元scanが所有する現在行を変更せず借用します
			DRIVERCRATE_EXPECT( context, current != scanned->scanResult.candidates.end()) ;
			// 現在版が既知の正例と未導入の正例を同じ参照規則で確認します
			if( current != scanned->scanResult.candidates.end()) {
				DRIVERCRATE_EXPECT(
					context,
					current->version == (mode == 5U ? L"" : native->currentVersion) &&
						current->version != L"1.2.3.4" &&
						current->provider == (mode == 5U ? L"" : native->currentProvider) &&
						(mode == 5U ||
						 (!current->provider.empty() && !current->driverDate.empty()))) ;
				DRIVERCRATE_EXPECT( context,
								   reference->manufacturer == current->manufacturer &&
									   reference->model == current->model &&
									   reference->driverClass == current->driverClass &&
									   reference->deviceClassGuid == current->deviceClassGuid &&
									   reference->discoveryBus == current->discoveryBus) ;
			}

			DRIVERCRATE_EXPECT(
				context,
				reference->version ==
						(source.snapshot->schemaReceipt().records().front().inspectionStage ==
								 IndexInspectionStage::CONTENT_INSPECTED
							 ? L"1.2.3.4"
							 : L"") &&
					reference->provider.empty() && reference->driverDate.empty() &&
					reference->displayDownloadSize.empty() &&
					reference->maximumDownloadBytes == 0U && reference->packageIdentity.empty() &&
					!reference->eulaAccepted && !reference->rebootMayBeRequired &&
					!reference->browseOnly && reference->requiredExtensionCount == 0U &&
					reference->requiredDriverComponentCount == 0U) ;
			DRIVERCRATE_EXPECT(
				context, !reference->current && !reference->installable &&
							 !reference->recommended && !reference->allContentCached &&
							 !reference->assessment && !reference->metadataDistribution &&
							 !reference->deviceObservation &&
							 !reference->releaseObservationDifference &&
							 reference->action == DriverAction::NONE &&
							 reference->defaultPreference == CandidateDefaultPreference::NONE) ;
		}

		// scanned所有eventから同期処理中だけ借用する原計画
		const auto &plan = *scanned->preparationPlan ;
		DRIVERCRATE_EXPECT( context,
						   controller.completeScan( scan.operationId, scanned->scanResult) &&
							   controller.state() == ApplicationState::SCAN_READY &&
							   controller.setPreparationPlan( scan.operationId, plan)) ;
		// 元計画と有限予算に限定した取得承認
		OfficialPreparationApproval approval{0U, plan.scanSessionId, plan.planId, plan.limits, {}} ;
		// planの元順序どおり各対象の明示承認を構築します
		for( const auto &target : plan.targets) {
			approval.decisions.push_back( {target, true, false, false, false}) ;
		}

		// 新取得operationの開始許可。原scan operationと分離する
		const auto preparation = controller.beginPreparation( approval) ;
		DRIVERCRATE_EXPECT( context, preparation.accepted && worker->requestPreparation( approval)) ;
		// 同取得operationの実byte・内容・適合・publication終端event
		auto prepared =
			waitEvent( *worker, WorkerEventKind::PREPARATION_COMPLETED, approval.operationId) ;
		// 本体が実bindingから発行した候補の所有copy
		std::vector<UpdateCandidate> candidates ;
		// 実準備eventがある場合だけ段階別診断を観測します
		if( prepared) {
			// 各本体監査の元HRESULTと内容・適合・公開件数を保存します
			for( const auto &report : prepared->preparationResult.auditReports) {
				std::cout << "Index audit: content " << static_cast<unsigned>( report.content) << '/'
						  << report.contentError << ", accepted " << report.acceptedInfCount
						  << ", first content " << report.firstContentRejection << ", pairs "
						  << report.examinedPairCount << '/' << report.applicablePairCount << '/'
						  << report.failedPairCount << ", first pair " << report.firstPairError
						  << ", publication " << report.publication.firstError << '\n' ;
				// DriverStore binding由来の元拒否は単一/必要構成と最初の位置が欠測しません
				if( report.publication.firstError != 0) {
					DRIVERCRATE_EXPECT( context, (report.publication.bindingPath == 1U ||
												 report.publication.bindingPath == 2U) &&
													report.publication.bindingRejection != 0U) ;
				}

				candidates.insert( candidates.end(), report.publishedCandidates.begin(),
								  report.publishedCandidates.end()) ;
			}
		}

		// 元の内容拒否診断を期待値で置き換えず保持します
		if( prepared) {
			// 各正規取得のseal付き内容検査件数を保存します
			for( const auto &item : prepared->indexPreparation.items) {
				std::cout << "Index exact content: acquired " << item.acquisitionError
						  << ", content " << item.contentError << ", accepted "
						  << item.acceptedInfCount << ", rejected signature "
						  << item.signatureRejectedInfCount << ", first INF "
						  << item.firstInfRejection << '\n' ;
			}
		}

		std::cout << "Index pipeline " << (network ? "Net" : "Ports") << " mode " << mode
				  << ": references " << references << ", published " << candidates.size()
				  << ", preparation HRESULT "
				  << (prepared ? prepared->preparationResult.controlError : 0xFFFFFFFFU)
				  << ", Windows set opens " << native->opens << ", rank calls " << native->rankCalls
				  << '\n' ;
		DRIVERCRATE_EXPECT( context, prepared && candidates.size() == 1U) ;
		// 公開候補がない試験では未到達を残してworkerを停止します
		if( candidates.empty()) {
			worker->stop() ;
			continue ;
		}

		DRIVERCRATE_EXPECT( context,
						   controller.completePreparation( prepared->preparationResult,
														  scanned->scanResult.candidates) &&
							   controller.state() == ApplicationState::SCAN_READY) ;
		// 非空を確認した同publication候補。導入終端まで借用する
		const auto &candidate = candidates.front() ;
		DRIVERCRATE_EXPECT(
			context, candidate.provider == L"Fixture Vendor" && candidate.version == L"1.0.0.0" &&
						 candidate.provider != native->currentProvider &&
						 candidate.version != L"1.2.3.4" && candidate.driverDate == L"2026/10/11") ;
		DRIVERCRATE_EXPECT( context,
						   candidate.installable && !candidate.recommended &&
							   candidate.defaultPreference == CandidateDefaultPreference::NONE &&
							   candidate.discoveryBasis ==
								   CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
							   candidate.action == (mode == 1U	 ? DriverAction::REINSTALL
													: mode == 2U ? DriverAction::DOWNGRADE
													: mode == 5U ? DriverAction::INITIAL_INSTALL
																 : DriverAction::UPDATE)) ;
		// 同controllerが公開・許可した唯一の選択identity
		const std::array selected{candidate.identity} ;
		// 明示同意なしではfake指定導入へ到達しないことを確認する結果
		const auto		 refusal = controller.beginInstall( plan.scanSessionId, selected,
														   InstallConfirmation::NOT_CONFIRMED) ;
		DRIVERCRATE_EXPECT( context, !refusal.accepted && native->installs == 0U) ;
		// 同session・同選択へ結合した明示導入operation
		const auto installation =
			controller.beginInstall( plan.scanSessionId, selected, InstallConfirmation::CONFIRMED) ;
		DRIVERCRATE_EXPECT( context, installation.accepted &&
										worker->requestInstall(
											installation.operationId, plan.scanSessionId, selected,
											nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
		// 取得結果と導入結果を分離した同operationの実終端event
		auto result =
			waitEvent( *worker, WorkerEventKind::INSTALL_COMPLETED, installation.operationId) ;
		DRIVERCRATE_EXPECT( context, result && result->installResult.updates.size() == 1U) ;
		// 実個別結果一件が得られた場合だけcontroller終端と結果保持を検証します
		if( result && result->installResult.updates.size() == 1U) {
			DRIVERCRATE_EXPECT( context, controller.completeInstall( installation.operationId,
																   result->installResult) &&
											controller.scanSessionId() == 0U) ;
			// 存在確認済みの選択一件の個別結果。result寿命内だけ借用する
			const auto &item = result->installResult.updates.front() ;
			DRIVERCRATE_EXPECT( context,
							   item.identity == candidate.identity &&
								   item.downloadOutcome == OutcomeCode::SUCCESS &&
								   item.installOutcome ==
									   (mode == 3U ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS) &&
								   item.rebootRequired == (mode == 4U)) ;
			std::cout << "Index pipeline " << (network ? "Net" : "Ports") << " mode " << mode
					  << ": fake stage " << native->stages << ", fake specified install "
					  << native->installs << ", result HRESULT " << item.installError << ", reboot "
					  << result->installResult.rebootRequired << ", real OS changes 0\n" ;
		}

		// 完了event受領後のidle workerでは全署名callが終了済みで、低位receiptだけを読みます
		if( *signature) {
			// 全署名処理終了後の固定低位call観測のcopy
			const auto receipt = (*signature)->receipt() ;
			DRIVERCRATE_EXPECT( context, receipt.setupCalls > 0U && receipt.verifyCalls >= 2U &&
											receipt.verifyCalls == receipt.closeCalls &&
											receipt.rejectedCalls == 0U) ;
			std::cout << "Index signature wrapper receipt: SetupVerify " << receipt.setupCalls
					  << ", WVT VERIFY " << receipt.verifyCalls << ", CLOSE " << receipt.closeCalls
					  << ", rejected " << receipt.rejectedCalls << '\n' ;
		}

		worker->stop() ;
		// 初回正例は実installed-only照会条件を通った場合だけ成立します
		if( mode == 5U) {
			DRIVERCRATE_EXPECT( context, native->installedOnlyQueries >= 3U) ;
		}

		DRIVERCRATE_EXPECT( context, native->stages == 1U && native->installs == 1U &&
										native->opens == native->closes) ;
	}

	std::cout << "Index candidate binding assertions: " << context.assertionCount() - before
			  << ", failures: " << context.failureCount() - failures
			  << ", native CAT positive UNCONFIRMED\n" ;
}

// tests/unit/signed_index_candidate_binding_tests.hの同宣言を契約の正本とする
//------------------------------------------------------------------------------
/**
 * @brief 実producerの原byteと三deviceを通常workerの候補publicationまで通します
 * @param[in,out] context 元assertion集計先です
 * @param[in] services RAM認証隔離store・完全HTTP・固定UTCの所有依存です
 * @param[in] zipA A二製品が共有する原archiveです
 * @param[in] zipB B一製品の別原archiveです
 * @param[in] devices 同じ認証recordから読んだ三identityです
 * @param[in] scenario 0は正常、1は初回、2はID、3はClass、4はINF path、5はrank、6はCAT hash、7は現在状態未知です
 */
//------------------------------------------------------------------------------
void runDistributionApplicationBindingTests( TestContext							  &context,
											provider_worker_index_detail::Services services,
											const std::string &zipA, const std::string &zipB,
											std::vector<DistributionBindingDevice> devices,
											const unsigned						   scenario)
{
	const auto before	= context.assertionCount() ;				// 今回の有限caseの開始値です
	const auto failures = context.failureCount() ;					// 元失敗を保持します
	auto	   native	= std::make_shared<NativeFixtureState>() ;	// 既存完全低位fakeの所有者です
	native->distributionDevices		   = std::move( devices) ;
	native->network					   = scenario != 3U ;
	native->nativeCase				   = scenario == 1U ? SignedIndexBindingNativeCase::INITIAL
										 : scenario == 4U ? SignedIndexBindingNativeCase::SECTION_OTHER_INF
										 : scenario == 5U ? SignedIndexBindingNativeCase::MISSING_RANK
														  : SignedIndexBindingNativeCase::NORMAL ;
	native->distributionCurrentUnknown = scenario == 7U ;
	// 元recordへ手を加えず、人工local側IDだけを不一致にします
	if( scenario == 2U) {
		native->distributionDevices.front().hardwareId = L"TESTBUS\\UNKNOWN_LOCAL_0099" ;
	}

	auto files		= signatureFiles( zipA) ;	// 原ZIP全memberの実hashです
	auto otherFiles = signatureFiles( zipB) ;	// 別payloadの実hashです
	files.insert( files.end(), otherFiles.begin(), otherFiles.end()) ;
	// 原archive byteを維持し、A一CATの期待hashだけを不一致にします
	if( scenario == 6U) {
		const auto catalog = std::ranges::find_if(
			files, []( const auto &file) { return file.name.ends_with( L".cat") ; }) ;	// 元一CATです
		DRIVERCRATE_EXPECT( context, catalog != files.end()) ;
		catalog->sha256.front() = catalog->sha256.front() == L'0' ? L'1' : L'0' ;
	}

	services.driverStoreFixture = [native]() {
		activeNative = native.get() ;
		// 元guardが要求する隔離rootの初期化失敗はnative fallbackへ変換しません
		if( !initializeRegistration( *native)) {
			return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
		}

		return driver_store_inf_detail::Access::create( calls()) ;
	} ; // 同worker停止まで全低位表を所有します
	services.signatureFixture = [files]() {
		return driver_package_signature_detail::Access::create( files, 4U) ;
	} ; // 同一archiveの全INFと別archiveを完全hashへ結合します
	services.beginAcquisition = []( SignedIndexAcquisitionAdapter				 &adapter,
								   std::shared_ptr<const SignedIndexRecordLookup> lookup,
								   IndexLookupContext current, IndexTargetOs os,
								   std::optional<std::chrono::sys_seconds> now) {
		return adapter.begin( std::move( lookup), current, os, now) ;
	} ; // 元producer keyIdを変更せず、製品と同じ固定取得policyへ渡します
	auto worker = provider_worker_index_detail::Access::create(
		[]() { return std::make_unique<CompositeUpdateProvider>() ; },
		[]() { return std::make_unique<FakeRestore>() ; },
		// 実導入は要求しません
		std::move( services)) ;
	ScanOptions options ;	// 現在行と同じ署名索引だけを有効にします
	options.useDefaultProviders = false ;
	options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
								   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
	OperationController controller ;					// 通常UIと同じ状態管理です
	const auto			scan = controller.beginScan() ;	// 元scan operationです
	DRIVERCRATE_EXPECT( context, scan.accepted && worker->requestScan( scan.operationId, options)) ;
	auto scanned = waitEvent( *worker, WorkerEventKind::SCAN_COMPLETED,
							 scan.operationId) ;	// 同終端まで所有します
	DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded &&
									(scenario == 3U || scanned->preparationPlan)) ;
	// 材料不成立を後段の負例合格へ数えず、同workerを終端まで停止します
	if( !scanned || (scenario != 3U && !scanned->preparationPlan)) {
		worker->stop() ;
		throw std::runtime_error( "distribution application scan fixture failed") ;
	}

	const OfficialPreparationPlan emptyPlan{} ;	// 全未照合では元workerがplanを発行しません
	const auto					 &plan = scanned->preparationPlan ? *scanned->preparationPlan
																  : emptyPlan ;	// 同adapterが作った取得groupです
	const auto					  expectedTargets = scenario == 3U	 ? 0U
													: scenario == 2U ? 1U
																	 : 2U ;	// ID不一致のBは取得対象から除外されます
	DRIVERCRATE_EXPECT( context, plan.targets.size() == expectedTargets) ;
	// Descriptor JSON同値ではなく、通常APIの二取得targetと共有device数を確認します
	if( scenario == 0U || scenario == 1U) {
		DRIVERCRATE_EXPECT( context, std::ranges::count_if( plan.targets,
														  []( const auto &target) {
															  return target.deviceCount == 2U ;
														  }) == 1 &&
										std::ranges::count_if( plan.targets, []( const auto &target) {
											return target.deviceCount == 1U ;
										}) == 1) ;
	}

	std::size_t currentCount{} ;	// 三つの現在行を元観測のまま確認します
	// 現在行の欠損とCode28/未知を独立に確認し、元結果を変更しません
	for( const auto &candidate : scanned->scanResult.candidates) {
		// 現在代表行だけがdriverの元観測を保持します
		if( candidate.current) {
			++currentCount ;
			DRIVERCRATE_EXPECT( context, candidate.deviceObservation.has_value()) ;
			// Code28正例では全現在driver属性が正式に欠損し、未知とは区別されます
			if( scenario == 1U && candidate.deviceObservation) {
				DRIVERCRATE_EXPECT( context,
								   candidate.version.empty() &&
									   candidate.deviceObservation->driverPresence ==
										   DeviceDriverPresence::NOT_INSTALLED &&
									   candidate.deviceObservation->node.problemCode == 28U) ;
			}

			// 現在版欠損だけのquery失敗はCode28初回と分け、未知のまま保持します
			if( scenario == 7U && candidate.deviceObservation) {
				DRIVERCRATE_EXPECT( context, candidate.version.empty() &&
												candidate.deviceObservation->driverPresence ==
													DeviceDriverPresence::UNKNOWN &&
												!candidate.deviceObservation->node.problemCode) ;
			}
		}
	}

	DRIVERCRATE_EXPECT( context, currentCount == 3U) ;
	std::vector<UpdateCandidate> candidates ;			// 実publicationだけを保持します
	std::size_t					 failedPairs{} ;		// 部分失敗を全成功へ丸めない元件数です
	std::size_t					 signatureRejected{} ;	// 同じ原summaryの個別CAT拒否数です
	// Class不一致で取得対象がない場合は通信/内容監査を要求しません
	if( !plan.targets.empty()) {
		DRIVERCRATE_EXPECT( context,
						   controller.completeScan( scan.operationId, scanned->scanResult) &&
							   controller.setPreparationPlan( scan.operationId, plan)) ;
		OfficialPreparationApproval approval{0U,
											 plan.scanSessionId,
											 plan.planId,
											 plan.limits,
											 {}} ;	// 同じ元groupだけの明示取得同意です
		// 各元targetを一回だけ取得する同意を固定します
		for( const auto &target : plan.targets) {
			approval.decisions.push_back( {target, true, false, false, false}) ;
		}

		const auto preparation = controller.beginPreparation( approval) ;	// 導入同意は発行しません
		DRIVERCRATE_EXPECT( context, preparation.accepted && worker->requestPreparation( approval)) ;
		auto prepared = waitEvent( *worker, WorkerEventKind::PREPARATION_COMPLETED,
								  approval.operationId) ;	// 同じlive workerの終端です
		DRIVERCRATE_EXPECT(
			context, prepared && prepared->indexPreparation.items.size() == plan.targets.size() &&
						 (scenario == 7U ? prepared->preparationResult.auditReports.empty()
										 : prepared->preparationResult.auditReports.size() ==
											   plan.targets.size())) ;
		// 元reportから成功/失敗の両分母をそのまま保存します
		if( prepared) {
			// 全元取得項目の個別署名拒否を成功候補数と独立に保持します
			for( const auto &item : prepared->indexPreparation.items) {
				signatureRejected += item.signatureRejectedInfCount ;
				std::cout << "DISTRIBUTION_CONTENT_SUMMARY scenario=" << scenario
						  << " parsed=" << item.parsedInfCount
						  << " accepted=" << item.acceptedInfCount
						  << " signatureRejected=" << item.signatureRejectedInfCount
						  << " firstInfError=" << item.firstInfRejection << '\n' ;
			}

			// 一CAT拒否を含む同packageの個別失敗を、全成功件数へ丸めず元summaryへ残します
			if( scenario == 6U) {
				DRIVERCRATE_EXPECT(
					context,
					std::ranges::count_if( prepared->indexPreparation.items, []( const auto &item) {
						return item.signatureRejectedInfCount == 1U ;
					}) == 1) ;
			}

			// 同じ元取得groupごとに内容/適合/publicationを集計します
			for( const auto &report : prepared->preparationResult.auditReports) {
				failedPairs += report.failedPairCount ;
				candidates.insert( candidates.end(), report.publishedCandidates.begin(),
								  report.publishedCandidates.end()) ;
				std::cout << "DISTRIBUTION_BIND_REPORT scenario=" << scenario
						  << " acceptedInf=" << report.acceptedInfCount
						  << " content=" << static_cast<unsigned>( report.content) << '/'
						  << report.contentError << " pairs=" << report.examinedPairCount << '/'
						  << report.applicablePairCount << '/' << report.failedPairCount
						  << " publication=" << static_cast<unsigned>( report.publication.state)
						  << '/' << report.publication.firstError << '\n' ;
			}

			// 新scanで元plan/sessionを失効させ、旧承認を新operationで再送しても拒否します
			if( scenario == 0U && !candidates.empty()) {
				DRIVERCRATE_EXPECT( context,
								   controller.completePreparation( prepared->preparationResult,
																  scanned->scanResult.candidates)) ;
				const std::array<std::wstring, 1U> unknown{
					L"unknown-index-candidate"} ;	// 元画面に存在しないIDです
				DRIVERCRATE_EXPECT( context, !controller
												 .beginInstall( plan.scanSessionId, unknown,
															   InstallConfirmation::CONFIRMED)
												 .accepted) ;
				const std::array<std::wstring, 1U> selected{	// 実publication由来のIDです
															candidates.front().identity} ;
				DRIVERCRATE_EXPECT( context, !controller
												 .beginInstall( plan.scanSessionId + 1U, selected,
															   InstallConfirmation::CONFIRMED)
												 .accepted) ;
				DRIVERCRATE_EXPECT( context, worker->requestScan( 100U, options)) ;
				const auto rescanned = waitEvent( *worker, WorkerEventKind::SCAN_COMPLETED,
												 100U) ;	// 同じlive workerの次scanです
				DRIVERCRATE_EXPECT( context, rescanned && rescanned->scanResult.scanSessionId >
															 plan.scanSessionId) ;
				approval.operationId = 101U ;
				DRIVERCRATE_EXPECT( context, worker->requestPreparation( approval)) ;
				const auto stale = waitEvent( *worker, WorkerEventKind::PREPARATION_COMPLETED,
											 101U) ;	// 新scan後の旧同意です
				DRIVERCRATE_EXPECT( context, stale && stale->preparationResult.approvalError !=
														 OfficialPreparationError::NONE) ;
			}
		}
	}

	const auto expectedCandidates = scenario == 0U || scenario == 1U ? 3U
									: scenario == 2U || scenario == 6U
										? 2U
										: 0U ;	// 固定全八caseの分母です
	DRIVERCRATE_EXPECT( context, candidates.size() == expectedCandidates) ;
	std::vector<std::wstring> expectedVersions ;	// 同じ認証recordから得た全元版です
	std::vector<std::wstring> observedVersions ;	// 同じ通常publicationから得た全表示版です
	// 元三recordの版集合を固定し、本文変更後の版をcodeへ追加登録しません
	for( const auto &device : native->distributionDevices) {
		expectedVersions.push_back( device.expectedVersion) ;
	}

	// 表示へ渡される元候補の実本文metadataとactionを確認します
	for( const auto &candidate : candidates) {
		observedVersions.push_back( candidate.version) ;
		DRIVERCRATE_EXPECT( context, candidate.installable &&
										candidate.driverDate == L"2026/10/22" &&
										std::ranges::find( expectedVersions, candidate.version) !=
											expectedVersions.end() &&
										(candidate.provider == L"Alpha Synthetic Vendor" ||
										 candidate.provider == L"Beta Synthetic Vendor")) ;
		DRIVERCRATE_EXPECT( context,
						   candidate.action == (scenario == 1U ? DriverAction::INITIAL_INSTALL
															   : DriverAction::UPDATE)) ;
		std::wcout << L"DISTRIBUTION_DISPLAY scenario=" << scenario << L" version="
				   << candidate.version << L" provider=" << candidate.provider << L" date="
				   << candidate.driverDate << L" action=" << static_cast<unsigned>( candidate.action)
				   << L'\n' ;
	}

	// 正常/初回の全版多重集合を照合し、一件の版変化を別device版で隠しません
	if( scenario == 0U || scenario == 1U) {
		std::ranges::sort( expectedVersions) ;
		std::ranges::sort( observedVersions) ;
		DRIVERCRATE_EXPECT( context, expectedVersions == observedVersions) ;
	}

	// 内容不一致の一INF失敗を全成功として扱わず、元成功候補と並存させます
	if( scenario == 6U) {
		DRIVERCRATE_EXPECT( context, candidates.size() < 3U) ;
	}

	worker->stop() ;
	DRIVERCRATE_EXPECT( context, native->stages == 0U && native->installs == 0U &&
									native->restoreBegins == 0U && native->opens == native->closes) ;
	std::cout << "DISTRIBUTION_APPLICATION scenario=" << scenario
			  << " targets=" << plan.targets.size() << " candidates=" << candidates.size()
			  << " failedPairs=" << failedPairs << " signatureRejected=" << signatureRejected
			  << " assertions=" << context.assertionCount() - before
			  << " failures=" << context.failureCount() - failures
			  << " actualCatAccepted=0 installs=0\n" ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元Intel archiveを明示fake deviceと通常workerへ結び、native内容署名を検査します
 * @param[in,out] context 元assertion集計先です
 * @param[in] services RAM署名store・明示historical UTC・完全fake HTTPの所有依存です
 * @param[in] device 原公開tupleから明示した一架空deviceです。実端末ではありません
 * @param[in] scenario 0は正常、1は誤archive byte、2は同意欠落、3は原ID集合欠損の別copyです
 * @note 実Windows署名APIを使い、実導入/復旧/実inventoryは行いません
 */
//------------------------------------------------------------------------------
void runNativeIntelArchiveBindingCase( TestContext							&context,
									  provider_worker_index_detail::Services services,
									  DistributionBindingDevice device, const unsigned scenario)
{
	const auto before = context.assertionCount() ;					// 同一件の元分母です
	auto	   native = std::make_shared<NativeFixtureState>() ;	// 実端末を使わない低位状態です
	native->distributionDevices.push_back( std::move( device)) ;
	native->network				 = true ;
	native->originalIntelArchive = true ;
	auto signature = std::make_shared<driver_package_signature_detail::ScopedFixture *>(
		nullptr) ;	// 停止前だけの借用です
	services.driverStoreFixture = [native]() {
		activeNative = native.get() ;
		// 元所有rootの失敗を実Windows rootへ補完しません
		if( !initializeRegistration( *native)) {
			return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
		}

		return driver_store_inf_detail::Access::create( calls()) ;
	} ; // 同workerだけの完全inventory低位表です
	services.signatureFixture = [signature]() {
		auto scope =
			// 元実APIへの委譲です
			driver_package_signature_detail::Access::createNativeAdapter() ;
		*signature = scope.get() ;
		return scope ;
	} ; // 元publisherを人工値へ置換しません
	services.beginAcquisition = []( SignedIndexAcquisitionAdapter				 &adapter,
								   std::shared_ptr<const SignedIndexRecordLookup> lookup,
								   IndexLookupContext current, IndexTargetOs os,
								   std::optional<std::chrono::sys_seconds> now) {
		return adapter.begin( std::move( lookup), current, os, now) ;
	} ; // 元配布keyIdの通常policyです
	auto worker = provider_worker_index_detail::Access::create(
		[]() { return std::make_unique<CompositeUpdateProvider>() ; },
		[]() { return std::make_unique<FakeRestore>() ; },
		// 実復旧は呼びません
		std::move( services)) ;
	ScanOptions options ;	// 他のnetwork Providerを開始しません
	options.useDefaultProviders = false ;
	options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
								   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
	DRIVERCRATE_EXPECT( context, worker && worker->requestScan( 1U, options)) ;
	auto scanned = waitEvent( *worker, WorkerEventKind::SCAN_COMPLETED, 1U) ;	// 元scanの終端です
	DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded &&
									scanned->preparationPlan &&
									scanned->preparationPlan->targets.size() == 1U) ;
	// 材料不成立を後段のtuple拒否成功へ数えません
	if( !scanned || !scanned->preparationPlan || scanned->preparationPlan->targets.size() != 1U) {
		worker->stop() ;
		throw std::runtime_error( "native Intel scan/terms/lookup not ready") ;
	}

	const auto &plan   = *scanned->preparationPlan ;	// 同adapterが発行した一targetです
	const auto &target = plan.targets.front() ;			// URLを生成せず元targetを使用します
	DRIVERCRATE_EXPECT( context, target.deviceCount == 1U &&
									target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED &&
									!target.eulaText.empty() && !target.eulaRevision.empty()) ;
	OfficialPreparationApproval approval{
		2U,
		plan.scanSessionId,
		plan.planId,
		plan.limits,
		{{target, true, scenario != 2U, false, false}}} ;	// 取得規約の明示fake同意だけです
	DRIVERCRATE_EXPECT( context, worker->requestPreparation( approval)) ;
	auto prepared =
		// 全INFの終端です
		waitEvent( *worker, WorkerEventKind::PREPARATION_COMPLETED, 2U, std::chrono::seconds{600}) ;
	DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
	std::size_t published{} ;		// 実publicationだけを数えます
	std::size_t totalInfs{} ;		// 成功/個別拒否を含む全INF数です
	std::size_t parsed{} ;			// 解析通過数です。全72件はtotalInfsへ保持します
	std::size_t accepted{} ;		// 内容合格を対象binding成功と混同しません
	std::size_t rejected{} ;		// 元署名拒否の分母です
	NativeError firstInfError{} ;	// 個別拒否の最初の元診断です
	// 元終端がある場合だけ内容とbinding結果を読みます
	if( prepared) {
		// 同意欠落では元approval拒否と取得未開始を確認します
		if( scenario == 2U) {
			DRIVERCRATE_EXPECT( context, prepared->preparationResult.approvalError !=
												OfficialPreparationError::NONE &&
											prepared->preparationResult.auditReports.empty()) ;
		} else {
			DRIVERCRATE_EXPECT( context, prepared->preparationResult.approvalError ==
												OfficialPreparationError::NONE &&
											prepared->indexPreparation.items.size() == 1U) ;
		}

		// 失敗行を分母から除かず原summaryを保持します
		for( const auto &item : prepared->indexPreparation.items) {
			totalInfs += item.infCount ;
			parsed += item.parsedInfCount ;
			accepted += item.acceptedInfCount ;
			rejected += item.signatureRejectedInfCount ;
			firstInfError = item.firstInfRejection ;
			std::cout << "NATIVE_INTEL_CONTENT scenario=" << scenario
					  << " acquisition=" << static_cast<unsigned>( item.acquisition) << '/'
					  << item.acquisitionError << " inputBound=" << item.inputBound
					  << " content=" << static_cast<unsigned>( item.content) << '/'
					  << item.contentError << '\n' ;
			// 誤archive byteは内容/適合へ進む前の元取得hash境界で拒否されます
			if( scenario == 1U) {
				DRIVERCRATE_EXPECT( context,
								   item.acquisition !=
										   OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION &&
									   item.acquisitionError != 0U && !item.inputBound &&
									   item.content == IndexedDriverInspectionState::NOT_STARTED) ;
			} else {
				DRIVERCRATE_EXPECT(
					context,
					item.acquisition == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION &&
						item.acquisitionError == 0U && item.inputBound &&
						item.content == IndexedDriverInspectionState::INSPECTION_COMPLETED &&
						item.contentError == 0U) ;
			}
		}

		// 元pair/opaque bindingを通って発行された候補だけを確認します
		for( const auto &report : prepared->preparationResult.auditReports) {
			published += report.publishedCandidates.size() ;
			std::cout << "NATIVE_INTEL_BIND_REPORT scenario=" << scenario
					  << " acceptedInf=" << report.acceptedInfCount
					  << " pairs=" << report.examinedPairCount << '/' << report.applicablePairCount
					  << '/' << report.failedPairCount
					  << " publication=" << static_cast<unsigned>( report.publication.state) << '/'
					  << report.publication.firstError << '\n' ;
			// 一ID欠損copyは同実archive検査後の完全tuple不一致だけで候補を失います
			if( scenario == 3U) {
				DRIVERCRATE_EXPECT( context, report.applicablePairCount == 0U &&
												report.publishedCandidates.empty()) ;
			}

			// 版/発行元/日付を原実INF本文と比較します
			for( const auto &candidate : report.publishedCandidates) {
				DRIVERCRATE_EXPECT( context, candidate.installable &&
												candidate.version == L"2.1.5.7" &&
												candidate.provider == L"Intel" &&
												candidate.driverDate == L"2025/09/03" &&
												candidate.action == DriverAction::UPDATE) ;
			}
		}
	}

	DRIVERCRATE_EXPECT( context, published == (scenario == 0U ? 1U : 0U)) ;
	// 正常/tuple拒否の両方で原archiveの全INFを処理します
	if( scenario == 0U || scenario == 3U) {
		DRIVERCRATE_EXPECT( context, totalInfs == 72U && parsed <= totalInfs && accepted != 0U &&
										*signature && (*signature)->receipt().setupCalls != 0U &&
										(*signature)->receipt().verifyCalls != 0U &&
										(*signature)->receipt().verifyCalls ==
											(*signature)->receipt().closeCalls) ;
	}

	const auto observed = *signature
							  ? (*signature)->receipt()
							  : driver_package_signature_detail::Receipt{} ;	// 停止前の同期観測です
	// 誤byte/同意欠落では元Windows署名検査も開始しません
	if( scenario == 1U || scenario == 2U) {
		DRIVERCRATE_EXPECT( context, observed.setupCalls == 0U && observed.verifyCalls == 0U) ;
	}

	worker->stop() ;
	DRIVERCRATE_EXPECT( context, native->stages == 0U && native->installs == 0U &&
									native->restoreBegins == 0U && native->opens == native->closes) ;
	std::cout
		<< "NATIVE_INTEL_APPLICATION scenario=" << scenario << " targets=1 candidates=" << published
		<< " totalInfs=" << totalInfs << " parsed=" << parsed
		<< " closureRejected=" << totalInfs - parsed << " accepted=" << accepted
		<< " signatureRejected=" << rejected << " firstInfError=" << firstInfError
		<< " nativeSetup=" << observed.setupCalls << " nativeVerify=" << observed.verifyCalls
		<< " nativeClose=" << observed.closeCalls
		<< " fakeInventory=1 historicalClock=1 driverHttp=0 certificateNetwork=unobserved installs=0 assertions="
		<< context.assertionCount() - before << '\n' ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同じ有効storage原byteから用途/collector内容だけの権限生成を拒否します
 * @param[in,out] context 有限assertion集計です
 * @param[in] zip 元正常caseの人工archive全byteです
 * @note 完全fakeを使用し、Driver Store登録/実導入/実復旧を呼びません
 */
//------------------------------------------------------------------------------
void runStorageAuthorizationBoundaryTests( TestContext &context, std::string_view zip)
{
	static_assert( !std::is_default_constructible_v<StorageInfQualification>) ;
	static_assert( !std::is_constructible_v<StorageInfQualification, SelectedStorageServiceFacts>) ;
	static_assert( !std::is_convertible_v<CollectorInfContentInspection, CommonInfInspection>) ;
	auto native		= std::make_shared<NativeFixtureState>() ;	// このthreadだけの完全隔離Windowsです
	native->storage = true ;
	activeNative	= native.get() ;
	DRIVERCRATE_EXPECT( context, initializeRegistration( *native)) ;
	const auto table = calls() ;	// 欠損をnative補完しない低位表です
	// 完全表の一callbackだけを欠損させる独立負例です
	auto	   missing			  = table ;
	missing.serviceDeviceListSize = nullptr ;
	DRIVERCRATE_EXPECT( context, !driver_store_inf_detail::Access::create( missing)) ;
	missing					  = table ;
	missing.serviceDeviceList = nullptr ;
	DRIVERCRATE_EXPECT( context, !driver_store_inf_detail::Access::create( missing)) ;
	// MTD専用slotの部分表と実native混在は旧fakeへ補完しません
	missing					= table ;
	missing.mtd.setSelected = incompleteMtdSelected ;
	DRIVERCRATE_EXPECT( context, !driver_store_inf_detail::Access::create( missing)) ;
	missing.mtd.setSelected = SetupDiSetSelectedDriverW ;
	DRIVERCRATE_EXPECT( context, !driver_store_inf_detail::Access::create( missing)) ;
	// 未呼出しslotで全表の受理と各slot欠損を独立に検査します
	auto complete = table ;
	complete.mtd  = {.setSelected	= &UncalledMtdSlot<decltype( complete.mtd.setSelected)>::invoke,
					 .getSelected	= &UncalledMtdSlot<decltype( complete.mtd.getSelected)>::invoke,
					 .callInstaller = &UncalledMtdSlot<decltype( complete.mtd.callInstaller)>::invoke,
					 .openQueue		= &UncalledMtdSlot<decltype( complete.mtd.openQueue)>::invoke,
					 .queueCount	= &UncalledMtdSlot<decltype( complete.mtd.queueCount)>::invoke,
					 .scanQueue		= &UncalledMtdSlot<decltype( complete.mtd.scanQueue)>::invoke,
					 .queueSection	= &UncalledMtdSlot<decltype( complete.mtd.queueSection)>::invoke,
					 .commitQueue	= &UncalledMtdSlot<decltype( complete.mtd.commitQueue)>::invoke,
					 .closeQueue	= &UncalledMtdSlot<decltype( complete.mtd.closeQueue)>::invoke,
					 .openInf		= &UncalledMtdSlot<decltype( complete.mtd.openInf)>::invoke,
					 .closeInf		= &UncalledMtdSlot<decltype( complete.mtd.closeInf)>::invoke,
					 .storeLocation = &UncalledMtdSlot<decltype( complete.mtd.storeLocation)>::invoke,
					 .windowsDirectory =
						 &UncalledMtdSlot<decltype( complete.mtd.windowsDirectory)>::invoke,
					 .openClassKey	= &UncalledMtdSlot<decltype( complete.mtd.openClassKey)>::invoke,
					 .openDeviceKey = &UncalledMtdSlot<decltype( complete.mtd.openDeviceKey)>::invoke,
					 .classProperty = &UncalledMtdSlot<decltype( complete.mtd.classProperty)>::invoke,
					 .queryRegistry = &UncalledMtdSlot<decltype( complete.mtd.queryRegistry)>::invoke,
					 .closeRegistry = &UncalledMtdSlot<decltype( complete.mtd.closeRegistry)>::invoke,
					 .createFile	= &UncalledMtdSlot<decltype( complete.mtd.createFile)>::invoke,
					 .fileInfo		= &UncalledMtdSlot<decltype( complete.mtd.fileInfo)>::invoke,
					 .fileInfoEx	= &UncalledMtdSlot<decltype( complete.mtd.fileInfoEx)>::invoke,
					 .finalPath		= &UncalledMtdSlot<decltype( complete.mtd.finalPath)>::invoke,
					 .freeSpace		= &UncalledMtdSlot<decltype( complete.mtd.freeSpace)>::invoke,
					 .securityInfo	= &UncalledMtdSlot<decltype( complete.mtd.securityInfo)>::invoke,
					 .localFree		= &UncalledMtdSlot<decltype( complete.mtd.localFree)>::invoke,
					 .readFile		= &UncalledMtdSlot<decltype( complete.mtd.readFile)>::invoke,
					 .writeFile		= &UncalledMtdSlot<decltype( complete.mtd.writeFile)>::invoke,
					 .flushFile		= &UncalledMtdSlot<decltype( complete.mtd.flushFile)>::invoke,
					 .setFileInfo	= &UncalledMtdSlot<decltype( complete.mtd.setFileInfo)>::invoke,
					 .closeHandle	= &UncalledMtdSlot<decltype( complete.mtd.closeHandle)>::invoke} ;
	// 全slotを備えた低位fake表のscopeです
	auto completeScope = driver_store_inf_detail::Access::create( complete) ;
	DRIVERCRATE_EXPECT( context, completeScope != nullptr) ;
	completeScope.reset() ;
	// 一slot欠損を作りnative混入拒否を確認する関数です
	const auto rejectMissing = [&]( auto member) {
		// 欠損を注入するfake表の複写です
		auto broken		   = complete ;
		broken.mtd.*member = nullptr ;
		DRIVERCRATE_EXPECT( context, !driver_store_inf_detail::Access::create( broken)) ;
	} ;
	using Mtd = driver_store_inf_detail::MtdTransport ;
	rejectMissing( &Mtd::setSelected) ;
	rejectMissing( &Mtd::getSelected) ;
	rejectMissing( &Mtd::callInstaller) ;
	rejectMissing( &Mtd::openQueue) ;
	rejectMissing( &Mtd::queueCount) ;
	rejectMissing( &Mtd::scanQueue) ;
	rejectMissing( &Mtd::queueSection) ;
	rejectMissing( &Mtd::commitQueue) ;
	rejectMissing( &Mtd::closeQueue) ;
	rejectMissing( &Mtd::openInf) ;
	rejectMissing( &Mtd::closeInf) ;
	rejectMissing( &Mtd::storeLocation) ;
	rejectMissing( &Mtd::windowsDirectory) ;
	rejectMissing( &Mtd::openClassKey) ;
	rejectMissing( &Mtd::openDeviceKey) ;
	rejectMissing( &Mtd::classProperty) ;
	rejectMissing( &Mtd::queryRegistry) ;
	rejectMissing( &Mtd::closeRegistry) ;
	rejectMissing( &Mtd::createFile) ;
	rejectMissing( &Mtd::fileInfo) ;
	rejectMissing( &Mtd::fileInfoEx) ;
	rejectMissing( &Mtd::finalPath) ;
	rejectMissing( &Mtd::freeSpace) ;
	rejectMissing( &Mtd::securityInfo) ;
	rejectMissing( &Mtd::localFree) ;
	rejectMissing( &Mtd::readFile) ;
	rejectMissing( &Mtd::writeFile) ;
	rejectMissing( &Mtd::flushFile) ;
	rejectMissing( &Mtd::setFileInfo) ;
	rejectMissing( &Mtd::closeHandle) ;
	complete.mtd.setSelected = SetupDiSetSelectedDriverW ;
	DRIVERCRATE_EXPECT( context, !driver_store_inf_detail::Access::create( complete)) ;
	// 実fileは一意に新規作成したfixture rootだけへ限定します
	complete.mtd.setSelected	  = &UncalledMtdSlot<decltype( complete.mtd.setSelected)>::invoke ;
	complete.mtd.classProperty	  = mtdFixtureClassProperty ;
	complete.mtd.windowsDirectory = windowsDirectory ;
	complete.mtd.openQueue		  = mtdFixtureOpenQueue ;
	complete.mtd.queueCount		  = mtdFixtureQueueCount ;
	complete.mtd.scanQueue		  = mtdFixtureScanQueue ;
	complete.mtd.queueSection	  = mtdFixtureQueueSection ;
	complete.mtd.commitQueue	  = mtdFixtureCommitQueue ;
	complete.mtd.closeQueue		  = mtdFixtureCloseQueue ;
	complete.mtd.openInf		  = mtdFixtureOpenInf ;
	complete.mtd.closeInf		  = mtdFixtureCloseInf ;
	complete.mtd.createFile		  = mtdFixtureCreate ;
	complete.mtd.fileInfo		  = mtdFixtureInfo ;
	complete.mtd.fileInfoEx		  = mtdFixtureInfoEx ;
	complete.mtd.finalPath		  = mtdFixtureFinalPath ;
	complete.mtd.freeSpace		  = mtdFixtureFreeSpace ;
	complete.mtd.securityInfo	  = mtdFixtureSecurity ;
	complete.mtd.localFree		  = mtdFixtureFree ;
	complete.mtd.readFile		  = mtdFixtureRead ;
	complete.mtd.writeFile		  = mtdFixtureWrite ;
	complete.mtd.flushFile		  = mtdFixtureFlush ;
	complete.mtd.setFileInfo	  = mtdFixtureSetInfo ;
	complete.mtd.closeHandle	  = mtdFixtureClose ;
	// 原DLLを置く一意所有source workspaceです
	OfficialDownloadWorkspace mtdSource ;
	DRIVERCRATE_EXPECT( context, mtdSource.initialize( L"mtd-io-fixture", 853U) == 0U) ;
	// 独立に固定する二DLL名と元byteです
	const std::array<std::pair<std::wstring, std::string>, 2U> originals{
		std::pair{std::wstring{L"fixture-a.dll"}, std::string{"synthetic file A"}},
		std::pair{std::wstring{L"fixture-b.dll"}, std::string{"synthetic file B"}}} ;
	// 所有workspace内だけに全byteを書く関数です
	const auto writeOwned = [&]( OfficialDownloadWorkspace &area, std::wstring_view name,
								std::string_view bytes) {
		// 新規所有fileのhandleです
		HANDLE file = INVALID_HANDLE_VALUE ;
		// 所有file作成に失敗すれば元byteを作ったことにしません
		if( area.createFile( name, file) != 0U) {
			return false ;
		}

		// 所有fileへwriteしたbyte数です
		DWORD	   count{} ;
		// 所有fileの全write成否です
		const bool ok = ::WriteFile( file, bytes.data(), static_cast<DWORD>( bytes.size()), &count,
									nullptr) != FALSE &&
						count == bytes.size() ;
		::CloseHandle( file) ;
		return ok ;
	} ;
	// 原二DLLを独立した所有sourceに準備します
	for( const auto &[name, body] : originals) {
		DRIVERCRATE_EXPECT( context, writeOwned( mtdSource, name, body)) ;
	}

	DRIVERCRATE_EXPECT( context, writeOwned( mtdSource, L"fixture.sys", "synthetic SYS")) ;
	DRIVERCRATE_EXPECT( context, writeOwned( mtdSource, L"fixture.inf", "synthetic original INF")) ;
	// 人工SYSの原SHA-256です
	std::wstring systemHash ;
	DRIVERCRATE_EXPECT( context,
					   computeFileSha256( mtdSource.path( L"fixture.sys"), systemHash) == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   writeOwned( native->registration, L"System32\\mtd-marker.tmp", "owned")) ;
	// 同内部試験の所有file fakeです
	MtdFileFixture mtdFiles ;
	mtdFiles.windowsRoot = native->windowsRoot ;
	// 原DLLの所有source pathです
	const auto sourcePath = mtdSource.path( originals.front().first) ;
	mtdFiles.sourceRoot	  = sourcePath.substr( 0U, sourcePath.find_last_of( L'\\')) ;
	activeMtdFiles		  = &mtdFiles ;
	// handler propertyを照会する人工deviceです
	SP_DEVINFO_DATA handlerDevice{} ;
	handlerDevice.cbSize	= sizeof( handlerDevice) ;
	handlerDevice.ClassGuid = MTD_CLASS ;
	handlerDevice.DevInst	= 1U ;
	{
		// MTD slotなしの既fake表scopeです
		auto				  emptyScope = driver_store_inf_detail::Access::create( table) ;
		// 欠損slotを照会したhandler結果です
		MtdHandlerObservation observation ;
		DRIVERCRATE_EXPECT(
			context, emptyScope &&
						 inspectMtdHandlers( reinterpret_cast<HDEVINFO>( 0x100U), handlerDevice,
											observation) ==
							 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER))) ;
	}
	// 全MTD slotを備えたfile fake scopeです
	auto fileScope = driver_store_inf_detail::Access::create( complete) ;
	DRIVERCRATE_EXPECT( context, fileScope != nullptr) ;
	// 型と原byteを持つ人工handler propertyを作ります
	const auto handlerValue = []( DEVPROPTYPE type, const std::vector<wchar_t> &value) {
		// 返却する人工handler propertyです
		MtdFixtureProperty result ;
		result.error = ERROR_SUCCESS ;
		result.type	 = type ;
		result.bytes.resize( value.size() * sizeof( wchar_t)) ;
		std::memcpy( result.bytes.data(), value.data(), result.bytes.size()) ;
		return result ;
	} ;
	// handler propertyの不在・空・登録・不正・権限失敗を別条件で確認します
	for( unsigned scenario = 0U; scenario < 10U && fileScope; ++scenario) {
		mtdFiles.classInstaller		= {} ;
		mtdFiles.classCoInstallers	= {} ;
		mtdFiles.deviceCoInstallers = {} ;
		// 正規空listのclassとdevice co-installerを作ります
		if( scenario == 1U) {
			mtdFiles.classCoInstallers	= handlerValue( DEVPROP_TYPE_STRING_LIST, {L'\0', L'\0'}) ;
			mtdFiles.deviceCoInstallers = handlerValue( DEVPROP_TYPE_STRING_LIST, {L'\0', L'\0'}) ;
		}
		// 非空class installerの登録を注入します
		else if( scenario == 2U) {
			mtdFiles.classInstaller = handlerValue( DEVPROP_TYPE_STRING, {L'x', L'\0'}) ;
		}
		// 非空class co-installerの登録を注入します
		else if( scenario == 3U) {
			mtdFiles.classCoInstallers =
				handlerValue( DEVPROP_TYPE_STRING_LIST, {L'x', L'\0', L'\0'}) ;
		}
		// 非空device co-installerの登録を注入します
		else if( scenario == 4U) {
			mtdFiles.deviceCoInstallers =
				handlerValue( DEVPROP_TYPE_STRING_LIST, {L'x', L'\0', L'\0'}) ;
		}
		// class installerの権限失敗を注入します
		else if( scenario == 5U) {
			mtdFiles.classInstaller.error = ERROR_ACCESS_DENIED ;
		}
		// device co-installerの権限失敗を注入します
		else if( scenario == 6U) {
			mtdFiles.deviceCoInstallers.error = ERROR_ACCESS_DENIED ;
		}
		// class listの型不一致を注入します
		else if( scenario == 7U) {
			mtdFiles.classCoInstallers = handlerValue( DEVPROP_TYPE_STRING, {L'x', L'\0'}) ;
		}
		// device listの終端欠損を注入します
		else if( scenario == 8U) {
			mtdFiles.deviceCoInstallers = handlerValue( DEVPROP_TYPE_STRING_LIST, {L'x', L'\0'}) ;
		}
		// 容量照会後のclass list消失を注入します
		else if( scenario == 9U) {
			mtdFiles.classCoInstallers =
				handlerValue( DEVPROP_TYPE_STRING_LIST, {L'x', L'\0', L'\0'}) ;
			mtdFiles.classCoInstallers.vanishAfterSizing = true ;
		}

		// scenarioごとの三handler観測です
		MtdHandlerObservation observation ;
		// handler検査の元診断です
		const auto			  error =
			inspectMtdHandlers( reinterpret_cast<HDEVINFO>( 0x100U), handlerDevice, observation) ;
		// scenarioごとに固定した期待HRESULTです
		const NativeError expected =
			scenario < 2U	? static_cast<NativeError>( 0)
			: scenario < 5U ? static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))
			: scenario < 7U ? static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED))
			: scenario < 9U ? static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA))
							: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
		DRIVERCRATE_EXPECT( context, error == expected) ;
		// 全property正式不在の観測を確認します
		if( scenario == 0U) {
			DRIVERCRATE_EXPECT( context,
							   observation.classInstaller.state == MtdHandlerState::ABSENT &&
								   observation.classCoInstallers.state == MtdHandlerState::ABSENT &&
								   observation.deviceCoInstallers.state == MtdHandlerState::ABSENT) ;
		}
		// 正規空listを不在と分けて確認します
		else if( scenario == 1U) {
			DRIVERCRATE_EXPECT(
				context, observation.classCoInstallers.state == MtdHandlerState::EMPTY_LIST &&
							 observation.deviceCoInstallers.state == MtdHandlerState::EMPTY_LIST) ;
		}

		std::cout << "MTD_HANDLER_PROPERTY scenario=" << scenario << " error=" << error << '\n' ;
	}

	mtdFiles.classInstaller		= {} ;
	mtdFiles.classCoInstallers	= {} ;
	mtdFiles.deviceCoInstallers = {} ;
	// 既存・不在・混在の共有fileを別scenarioで確認します
	for( unsigned scenario = 0U; scenario < 3U && fileScope; ++scenario) {
		// 正常file scenarioの原MTD serviceとCOPY集合です
		SelectedStorageServiceFacts facts ;
		facts.className		  = L"MTD" ;
		facts.classGuid		  = L"{4d36e970-e325-11ce-bfc1-08002be10318}" ;
		facts.infRelativePath = L"fixture.inf" ;
		facts.binaryTarget	  = native->windowsRoot + L"\\System32\\drivers\\fixture.sys" ;
		facts.binarySource	  = L"fixture.sys" ;
		facts.binarySha256	  = systemHash ;
		facts.binaryBytes	  = std::string_view{"synthetic SYS"}.size() ;
		// 同fixtureのassociated SYS COPYです
		SelectedStorageCopyFact system ;
		system.section = L"Files" ;
		system.dirid   = 12 ;
		system.target  = facts.binaryTarget ;
		system.source  = facts.binarySource ;
		system.sha256  = facts.binarySha256 ;
		system.bytes   = facts.binaryBytes ;
		facts.mtdCopies.push_back( std::move( system)) ;
		// 二DLLの所有target名です
		std::array<std::wstring, 2U> names ;
		// 各DLLに一意な所有targetと元COPYを割り当てます
		for( std::size_t index = 0U; index < originals.size(); ++index) {
			names[index] = L"System32\\mtd-" + std::to_wstring( scenario) + L"-" +
						   std::to_wstring( index) + L".dll" ;
			// 同targetを既存状態にするかの判定です
			const bool exists = scenario == 0U || (scenario == 2U && index == 0U) ;
			// 既存条件だけ所有targetへ原byteを書きます
			if( exists) {
				DRIVERCRATE_EXPECT( context, writeOwned( native->registration, names[index],
													   originals[index].second)) ;
			} else {
				// 不在targetの外部file予約名です
				std::wstring reserved ;
				DRIVERCRATE_EXPECT( context, native->registration.prepareExternalFile(
												names[index], reserved) == 0U) ;
			}

			// 同DLLの原COPYとCAT member factです
			SelectedStorageCopyFact copy ;
			copy.section = L"SharedDlls" ;
			copy.ordinal = static_cast<std::uint32_t>( index) ;
			copy.fields	 = {originals[index].first} ;
			copy.source	 = originals[index].first ;
			copy.target	 = native->registration.path( names[index]) ;
			copy.dirid	 = 11 ;
			copy.bytes	 = originals[index].second.size() ;
			DRIVERCRATE_EXPECT( context,
							   computeFileSha256( mtdSource.path( copy.source), copy.sha256) == 0U) ;
			facts.mtdCopies.push_back( std::move( copy)) ;
		}

		// preflight成功時の共有file operationです
		std::unique_ptr<MtdSharedFileOperation> operation ;
		// 共有file preflightの元診断です
		const auto prepared = MtdSharedFileOperation::prepare( mtdSource, facts, operation) ;
		DRIVERCRATE_EXPECT( context, prepared == 0U && operation) ;
		// preflight失敗時は元診断を出力して後続の成功と区別します
		if( !operation) {
			std::cout << "MTD_FILE_PREPARE scenario=" << scenario << " error=" << prepared << '\n' ;
			continue ;
		}

		// 原順に固定するqueue sourceです
		std::vector<std::wstring> queueSources ;
		// 全原COPYに対応する所有sourceをqueueへ固定します
		for( const auto &copy : facts.mtdCopies) {
			queueSources.push_back( mtdSource.path( copy.source)) ;
		}

		DRIVERCRATE_EXPECT( context, MtdSharedFileFixtureAccess::bind(
										*operation, L"fixture-registered.inf", queueSources) == 0U) ;
		// 共有充足の新規・再利用・失敗の結果です
		MtdSharedFileResult result ;
		// 共有充足の元診断です
		const auto			satisfied = MtdSharedFileFixtureAccess::satisfy( *operation, {}, result) ;
		std::cout << "MTD_FILE_OPERATION scenario=" << scenario << " error=" << satisfied
				  << " renamed=" << result.renameSucceeded << " created=" << result.created
				  << " reused=" << result.reused << " cleanupUncertain=" << result.cleanupUncertain
				  << " stage=" << result.failureStage << '\n' ;
		DRIVERCRATE_EXPECT( context, satisfied == 0U && !result.cleanupUncertain &&
										result.renameSucceeded == (scenario == 0U	? 0U
																   : scenario == 1U ? 2U
																					: 1U) &&
										result.created == (scenario == 0U	? 0U
														   : scenario == 1U ? 2U
																			: 1U) &&
										result.reused == (scenario == 0U   ? 2U
														  : scenario == 1U ? 0U
																		   : 1U) &&
										operation->verify() == 0U) ;
		operation.reset() ;
		// 新規配置したtargetの原byteを独立に検査します
		for( std::size_t index = 0U; index < originals.size(); ++index) {
			// 既存として再利用したtargetを新規配置に数えません
			if( scenario == 0U || (scenario == 2U && index == 0U)) {
				continue ;
			}

			DRIVERCRATE_EXPECT( context, native->registration.adoptFile(
											names[index], originals[index].second.size()) == 0U) ;
		}
	}

	// 衝突・既存異byte・権限・writer・途中失敗を独立した原操作で確認します
	for( unsigned scenario = 0U; scenario < 7U && fileScope; ++scenario) {
		// 負例用の原MTD serviceとCOPY集合です
		SelectedStorageServiceFacts facts ;
		facts.className		  = L"MTD" ;
		facts.classGuid		  = L"{4d36e970-e325-11ce-bfc1-08002be10318}" ;
		facts.infRelativePath = L"fixture.inf" ;
		facts.binaryTarget	  = native->windowsRoot + L"\\System32\\drivers\\fixture.sys" ;
		facts.binarySource	  = L"fixture.sys" ;
		facts.binarySha256	  = systemHash ;
		facts.binaryBytes	  = std::string_view{"synthetic SYS"}.size() ;
		// 負例用のassociated SYS COPYです
		SelectedStorageCopyFact system ;
		system.section = L"Files" ;
		system.dirid   = 12 ;
		system.target  = facts.binaryTarget ;
		system.source  = facts.binarySource ;
		system.sha256  = facts.binarySha256 ;
		system.bytes   = facts.binaryBytes ;
		facts.mtdCopies.push_back( std::move( system)) ;
		// 負例ごとの二DLL所有target名です
		std::array<std::wstring, 2U> names ;
		// 負例ごとに一意な所有targetを準備します
		for( std::size_t index = 0U; index < originals.size(); ++index) {
			names[index] = L"System32\\mtd-negative-" + std::to_wstring( scenario) + L"-" +
						   std::to_wstring( index) + L".dll" ;
			// 既存先を使う負例だけ事前にtargetを作ります
			if( scenario < 3U) {
				// 指定条件の既存同byteまたは異byteです
				const auto body = scenario == 0U && index == 0U
									  ? std::string_view{"foreign-byte-xxx"}
									  : std::string_view{originals[index].second} ;
				DRIVERCRATE_EXPECT( context, writeOwned( native->registration, names[index], body)) ;
			} else {
				// 不在targetの外部file予約名です
				std::wstring reserved ;
				DRIVERCRATE_EXPECT( context, native->registration.prepareExternalFile(
												names[index], reserved) == 0U) ;
			}

			// 同DLLの原COPYとCAT member factです
			SelectedStorageCopyFact copy ;
			copy.section = L"SharedDlls" ;
			copy.ordinal = static_cast<std::uint32_t>( index) ;
			copy.fields	 = {originals[index].first} ;
			copy.source	 = originals[index].first ;
			copy.target	 = native->registration.path( names[index]) ;
			copy.dirid	 = 11 ;
			copy.bytes	 = originals[index].second.size() ;
			DRIVERCRATE_EXPECT( context,
							   computeFileSha256( mtdSource.path( copy.source), copy.sha256) == 0U) ;
			facts.mtdCopies.push_back( std::move( copy)) ;
		}

		// 負例に使う最初のDLL targetです
		const auto first		   = native->registration.path( names.front()) ;
		mtdFiles.badSecurityTarget = scenario == 1U ? first : L"" ;
		// 所有targetを占有する競合writerです
		HANDLE writer = INVALID_HANDLE_VALUE ;
		// 既存writer負例だけ同targetを占有します
		if( scenario == 2U) {
			writer = ::CreateFileW( first.c_str(), GENERIC_WRITE,
								   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
								   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;
			DRIVERCRATE_EXPECT( context, writer != INVALID_HANDLE_VALUE) ;
		}

		mtdFiles.raceTarget	  = scenario == 3U || scenario == 4U ? first : L"" ;
		mtdFiles.raceBytes	  = scenario == 3U ? "competitor-data!" : originals.front().second ;
		mtdFiles.raceInjected = false ;
		mtdFiles.writes		  = 0U ;
		mtdFiles.failWriteOrdinal =
			scenario == 5U ? std::optional<std::uint32_t>{1U} : std::nullopt ;
		// 負例preflight成功時の共有file operationです
		std::unique_ptr<MtdSharedFileOperation> operation ;
		// 負例preflightの元診断です
		const auto prepared = MtdSharedFileOperation::prepare( mtdSource, facts, operation) ;
		// fixture所有writerだけを閉じます
		if( writer != INVALID_HANDLE_VALUE) {
			::CloseHandle( writer) ;
		}

		// 初期preflight拒否の各元errorを独立に確認します
		if( scenario < 3U) {
			// scenarioごとに固定したpreflightの期待Windows errorです
			const auto expected = scenario == 0U   ? ERROR_CRC
								  : scenario == 1U ? ERROR_ACCESS_DENIED
												   : ERROR_SHARING_VIOLATION ;
			DRIVERCRATE_EXPECT(
				context,
				!operation && prepared == static_cast<NativeError>( HRESULT_FROM_WIN32( expected))) ;
			std::cout << "MTD_FILE_NEGATIVE scenario=" << scenario << " prepare=" << prepared
					  << " expected=" << expected << '\n' ;
		} else {
			DRIVERCRATE_EXPECT( context, prepared == 0U && operation) ;
			// preflight成功時だけsource bindingと後続作用を検査します
			if( operation) {
				// 全原COPYの所有sourceです
				std::vector<std::wstring> queueSources ;
				// 全原COPYのsourceを原順に固定します
				for( const auto &copy : facts.mtdCopies) {
					queueSources.push_back( mtdSource.path( copy.source)) ;
				}

				DRIVERCRATE_EXPECT(
					context, MtdSharedFileFixtureAccess::bind( *operation, L"fixture-registered.inf",
															  queueSources) == 0U) ;
				// 共有充足の部分結果です
				MtdSharedFileResult result ;
				// 共有充足または内部取消しの元診断です
				const auto			error = MtdSharedFileFixtureAccess::satisfy(
					 *operation,
					 scenario == 6U ? std::function<bool()>{[] { return true ; }}
											: std::function<bool()>{},
					 result) ;
				std::cout << "MTD_FILE_NEGATIVE scenario=" << scenario << " error=" << error
						  << " renamed=" << result.renameSucceeded << " created=" << result.created
						  << " reused=" << result.reused << " stage=" << result.failureStage
						  << " race=" << mtdFiles.raceInjected << '\n' ;
				// 競合した異byte targetが保持されたことを確認します
				if( scenario == 3U) {
					std::wstring expectedHash, actualHash ;
					DRIVERCRATE_EXPECT(
						context, error != 0U && mtdFiles.raceInjected &&
									 result.renameSucceeded == 0U && result.created == 0U &&
									 !result.cleanupUncertain &&
									 computeBytesSha256( mtdFiles.raceBytes, expectedHash) == 0U &&
									 computeFileSha256( first, actualHash) == 0U &&
									 expectedHash == actualHash) ;
				}
				// 同byte競合は再利用として分けて確認します
				else if( scenario == 4U) {
					DRIVERCRATE_EXPECT( context, error == 0U && mtdFiles.raceInjected &&
													result.renameSucceeded == 1U &&
													result.created == 1U && result.reused == 1U &&
													!result.cleanupUncertain) ;
				}
				// 内部取消しの元errorと既部分作用を確認します
				else if( scenario == 5U) {
					DRIVERCRATE_EXPECT(
						context,
						error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WRITE_FAULT)) &&
							result.renameSucceeded == 1U && result.created == 1U &&
							!result.cleanupUncertain) ;
				} else {
					DRIVERCRATE_EXPECT(
						context,
						error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) &&
							result.renameSucceeded == 0U && result.created == 0U) ;
				}

				operation.reset() ;
			}

			// 存在する所有targetだけを部分作用として確認します
			for( std::size_t index = 0U; index < names.size(); ++index) {
				// 部分作用を確認する所有target pathです
				const auto path = native->registration.path( names[index]) ;
				// 未配置のtargetを存在済みとして数えません
				if( ::GetFileAttributesW( path.c_str()) == INVALID_FILE_ATTRIBUTES) {
					continue ;
				}

				// 同targetで期待するbyte数です
				const auto size = scenario == 3U && index == 0U ? mtdFiles.raceBytes.size()
																: originals[index].second.size() ;
				DRIVERCRATE_EXPECT( context,
								   native->registration.adoptFile( names[index], size) == 0U) ;
			}
		}

		mtdFiles.badSecurityTarget.clear() ;
		mtdFiles.raceTarget.clear() ;
		mtdFiles.failWriteOrdinal.reset() ;
	}

	// 個別fileが成立した後、queue callbackの取消しでSYSと指定DIFへ進まないことを確認します
	{
		// 内部queue取消し用の原MTD serviceとCOPY集合です
		SelectedStorageServiceFacts facts ;
		facts.className		  = L"MTD" ;
		facts.classGuid		  = L"{4d36e970-e325-11ce-bfc1-08002be10318}" ;
		facts.infRelativePath = L"fixture.inf" ;
		facts.binaryTarget	  = native->windowsRoot + L"\\System32\\drivers\\fixture.sys" ;
		facts.binarySource	  = L"fixture.sys" ;
		facts.binarySha256	  = systemHash ;
		facts.binaryBytes	  = std::string_view{"synthetic SYS"}.size() ;
		// 同取消しfixtureのassociated SYS COPYです
		SelectedStorageCopyFact system ;
		system.section = L"Files" ;
		system.dirid   = 12 ;
		system.target  = facts.binaryTarget ;
		system.source  = facts.binarySource ;
		system.sha256  = facts.binarySha256 ;
		system.bytes   = facts.binaryBytes ;
		facts.mtdCopies.push_back( std::move( system)) ;
		// queue取消しfixtureの二DLLを不在targetとして用意します
		for( std::size_t index = 0U; index < originals.size(); ++index) {
			// 不在DLLの外部file予約名です
			std::wstring reserved ;
			DRIVERCRATE_EXPECT( context,
							   native->registration.prepareExternalFile(
								   L"System32\\" + originals[index].first, reserved) == 0U) ;
			// 同DLLの原COPYとCAT member factです
			SelectedStorageCopyFact copy ;
			copy.section = L"SharedDlls" ;
			copy.ordinal = static_cast<std::uint32_t>( index) ;
			copy.fields	 = {originals[index].first} ;
			copy.source	 = originals[index].first ;
			copy.target	 = native->windowsRoot + L"\\System32\\" + originals[index].first ;
			copy.dirid	 = 11 ;
			copy.bytes	 = originals[index].second.size() ;
			DRIVERCRATE_EXPECT( context,
							   computeFileSha256( mtdSource.path( copy.source), copy.sha256) == 0U) ;
			facts.mtdCopies.push_back( std::move( copy)) ;
		}

		// 所有する人工原queueです
		const auto original = mtdFixtureOpenQueue() ;
		// 同原queueの借用状態です
		auto	  *rawQueue = mtdFixtureQueue( original) ;
		DRIVERCRATE_EXPECT( context, rawQueue && mtdFixtureAddSection( *rawQueue, L"Files", 0U) &&
										mtdFixtureAddSection( *rawQueue, L"SharedDlls", 0U)) ;
		// 共有file preflightで作るoperationです
		std::unique_ptr<MtdSharedFileOperation> files ;
		// 共有file preflightの元診断です
		const auto prepared = MtdSharedFileOperation::prepare( mtdSource, facts, files) ;
		DRIVERCRATE_EXPECT( context, prepared == 0U && files) ;
		// 原queue照合後に所有する制御queueです
		std::unique_ptr<MtdQualifiedQueue> queue ;
		// 共有preflight成功後だけ制御queueを構成します
		if( files) {
			// 元tuple照合の元診断です
			const auto inspected = MtdQueueFixtureAccess::prepare(
				original, L"fixture-registered.inf", mtdSource, facts, *files, queue) ;
			DRIVERCRATE_EXPECT( context, inspected == 0U && queue) ;
		}

		// 制御queue成功後だけ内部取消しを送ります
		if( queue) {
			// 内部queue取消しの部分結果です
			MtdQueueResult outcome ;
			// 内部queue commitの元診断です
			const auto	   error = MtdQueueFixtureAccess::commit(
				*queue, [&] { return outcome.commitStarted ; }, outcome) ;
			std::cout << "MTD_QUEUE_CANCEL error=" << error << " created=" << outcome.shared.created
					  << " queue=" << outcome.commitStarted << '/' << outcome.commitCompleted
					  << '\n' ;
			DRIVERCRATE_EXPECT(
				context, error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) &&
							 outcome.shared.created == 2U && outcome.shared.renameSucceeded == 2U &&
							 outcome.commitStarted && !outcome.commitCompleted &&
							 mtdFiles.commits == 1U) ;
		}

		queue.reset() ;
		files.reset() ;
		// 所有する原fake queueだけを閉じます
		if( rawQueue) {
			DRIVERCRATE_EXPECT( context, mtdFixtureCloseQueue( original)) ;
		}

		// 内部取消し後の各所有targetを独立に検証します
		for( const auto &[name, body] : originals) {
			DRIVERCRATE_EXPECT(
				context, native->registration.adoptFile( L"System32\\" + name, body.size()) == 0U) ;
		}
	}
	DRIVERCRATE_EXPECT( context, mtdFiles.handles.empty()) ;
	fileScope.reset() ;
	activeMtdFiles = nullptr ;
	// 同threadの完全低位fakeだけを所有するscopeです
	auto transport = driver_store_inf_detail::Access::create( table) ;
	// 全元INF/CAT/memberを実byteへ照合する人工署名scopeです
	auto signature = driver_package_signature_detail::Access::create( signatureFiles( zip), 2U) ;
	DRIVERCRATE_EXPECT( context, transport && signature) ;
	OfficialDownloadWorkspace source ;	// 元ZIPをscope終了まで保持します
	DRIVERCRATE_EXPECT( context, source.initialize( L"storage-boundary", 853U) == 0U) ;
	// 同原文又はSDの全byteを取得する一時所有です
	HANDLE raw = INVALID_HANDLE_VALUE ;
	DRIVERCRATE_EXPECT( context, source.createFile( L"payload.zip", raw) == 0U) ;
	// 原byteの完全copyを照合する実書込数です
	DWORD	   written{} ;
	// 隔離所有fileへ全原byteを書いたWindows結果です
	const bool copied =
		WriteFile( raw, zip.data(), static_cast<DWORD>( zip.size()), &written, nullptr) != FALSE ;
	CloseHandle( raw) ;
	DRIVERCRATE_EXPECT( context, copied && written == zip.size()) ;
	std::wstring hash ;	// 全archive原byteへ固定します
	DRIVERCRATE_EXPECT( context, computeFileSha256( source.path( L"payload.zip"), hash) == 0U) ;
	// 原archiveの完全path/size/hashへ固定した内容入力です
	const DriverArchiveInput input{853U, source.path( L"payload.zip"), zip.size(), hash} ;
	// 同原byte又は同deviceに結ぶ元明示選択の閉集合です
	const std::array<std::pair<std::wstring_view, std::wstring_view>, 1U> selected{
		{{L"", L"fixture.inf"}}} ;
	CommonDriverPackageInspection normal ;	// 旧通常Class policyの拒否を保持します
	DRIVERCRATE_EXPECT(
		context, inspectSelectedCommonDriverPackages( input, OfficialDriverArchiveFormat::ZIP,
													 selected, normal) == 0U &&
					 normal.infs.size() == 1U &&
					 normal.infs.front().state == CommonInfInspectionState::CLOSURE_REJECTED &&
					 normal.infs.front().error ==
						 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED))) ;
	CollectorDriverPackageContent collector ;	// 内容成功だけの独立型です
	DRIVERCRATE_EXPECT( context,
					   inspectCollectorDriverPackageContent( input, OfficialDriverArchiveFormat::ZIP,
															selected, collector) == 0U &&
						   collector.infs.size() == 1U &&
						   collector.infs.front().state == CommonInfInspectionState::VERIFIED) ;
	CommonDriverPackageInspection app ;	// 端末用独立再検査も単独ではgrantではありません
	DRIVERCRATE_EXPECT( context, inspectSelectedDeviceDriverPackages(
									input, OfficialDriverArchiveFormat::ZIP, selected, app) == 0U &&
									app.infs.size() == 1U &&
									app.infs.front().state == CommonInfInspectionState::VERIFIED) ;
	// 全byteが有効な場合だけ、通常native入口の用途偽造拒否を確認します
	if( app.infs.size() == 1U && app.infs.front().state == CommonInfInspectionState::VERIFIED &&
	   collector.infs.size() == 1U &&
	   collector.infs.front().state == CommonInfInspectionState::VERIFIED) {
		DriverStoreProvider		  outsider ;	// 私有factoryが発行していないissuerです
		OfficialDriverRankAudit	  audit ;		// permissionに使わず入口の拒否位置を確認します
		// 私有factoryが発行していない元tokenの出力です
		OfficialInfInstallBinding binding ;
		// 全成功まで外へ発行しない原内容検査の所有結果です
		const auto				 &inspected = app.infs.front() ;
		// 同元storage原INFの独立内容です
		const auto				 &root = inspected.closure.packages.front() ;
		// 同じ有効raw byteの用途だけを変え、全入口拒否を確認します
		for( const auto purpose : {OfficialInfInspectionPurpose::STANDARD_DRIVER,
								  OfficialInfInspectionPurpose::COLLECTOR_CONTENT,
								  OfficialInfInspectionPurpose::DEVICE_STORAGE_CANDIDATE}) {
			auto forged				 = root ;	// 同じ完全原byte/正式Classを保ち、用途だけを変えます
			forged.inspectionPurpose = purpose ;
			// 元拒否地点を非秘密数値だけで確認する任意出力です
			RequiredInfBindingDiagnostic diagnostic ;
			DRIVERCRATE_EXPECT(
				context,
				outsider.createOfficialInfInstallBinding(
					853U, L"forged-device", *inspected.workspace, forged, L"Fixture Vendor",
					L"0.9.0.0", L"2026/01/01", audit, binding, &diagnostic) ==
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) &&
					binding.token == 0U && diagnostic.rejection == InfBindingReject::INPUT &&
					native->rankCalls == 0U) ;
		}

		auto forged =
			inspected ;	// collector由来のraw PACKAGEを手製Common DTOへ移してもgrantしません
		forged.closure			   = collector.infs.front().closure ;
		forged.requiredInfPackages = collector.infs.front().requiredInfPackages ;
		DRIVERCRATE_EXPECT( context, reverifyCommonDriverInf( forged) != 0U) ;
		DRIVERCRATE_EXPECT(
			context, outsider.createOfficialInfInstallBinding(
						 853U, L"forged-device", *inspected.workspace,
						 collector.infs.front().closure.packages.front(), L"Fixture Vendor",
						 L"0.9.0.0", L"2026/01/01", audit, binding) ==
							 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) &&
						 binding.token == 0U) ;
	}

	DRIVERCRATE_EXPECT( context,
					   native->stages == 0U && native->installs == 0U && native->rankCalls == 0U) ;
	signature.reset() ;
	transport.reset() ;
	activeNative = nullptr ;
	std::cout
		<< "STORAGE_AUTHORIZATION validSameBytes=1 normalRejected=1 collectorNonGrant=1 purposeNonGrant=1 missingApiFallback=0 stage=0 install=0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief storageを通常索引/同意/復旧/登録guard/flags0指定と元結果まで通します
 * @param[in,out] context 有限assertion集計です
 * @param[in] services 真署名隔離storeと完全HTTPです
 * @param[in] zip 全原byteへ固定した人工driver archiveです
 * @param[in] expected 低位注入と独立した期待呼出し/結果です
 * @note 同deviceの元候補を使い、実driver install/復元/HTTPへfallbackしません
 */
//------------------------------------------------------------------------------
void runStorageDriverBindingCase( TestContext						   &context,
								 provider_worker_index_detail::Services services,
								 std::string_view zip, const StorageBindingTestInput &expected)
{
	// 元の時刻は保持し、登録後の適用前だけ有効期限を越える状態を作る
	if( expected.nativeCase == SignedIndexBindingNativeCase::STORAGE_RECORD_EXPIRES_AFTER_STAGE) {
		services.utc = [read = std::move( services.utc)]() {
			// 通常の時刻供給関数が返した元観測を使う
			auto utc = read() ;
			// 登録が実行済みの場合だけ同じ取得許可を失効させる
			if( utc && activeNative && activeNative->stages != 0U) {
				*utc += std::chrono::days{30} ;
			}

			return utc ;
		} ;
	}

	// 変更前の元観測を後続比較まで保持します
	const auto before = context.assertionCount() ;
	// 当該case開始前の元失敗数です
	const auto failures = context.failureCount() ;
	// 同原索引と完全Windows表を所有する実workerです
	auto	   bound =
		makeSignedIndexBindingWorker( std::move( services), zip, false, expected.restoreFailure,
									 expected.stagingFailure, expected.nativeCase, {}, {}, {},
									 expected.reflectOwnInstall, SignedIndexBindingBatchFault::NONE,
									 false, expected.noReboot, {}, nullptr, expected.mtdScenario) ;
	// 元scan/選択/同意/失効を管理する製品状態機械です
	OperationController controller ;
	// 実WUA等を起動せず元二Providerだけを使用するscan条件です
	ScanOptions			options ;
	options.useDefaultProviders = false ;
	options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
								   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
	// 元新scanのoperation識別と受付結果です
	const auto scan = controller.beginScan() ;
	DRIVERCRATE_EXPECT( context, scan.accepted && bound.worker &&
									bound.worker->requestScan( scan.operationId, options)) ;
	// 同workerの元scan終端と実取得計画です
	auto scanned = waitEvent( *bound.worker, WorkerEventKind::SCAN_COMPLETED, scan.operationId) ;
	// scan prerequisite不足を具体的に出力します
	if( scanned && (!scanned->preparationPlan || scanned->preparationPlan->targets.size() != 1U)) {
		std::cout << "STORAGE_SCAN_PREREQUISITE succeeded=" << scanned->scanResult.succeeded
				  << " error=" << scanned->scanResult.error
				  << " state=" << static_cast<unsigned>( scanned->scanResult.state)
				  << " candidates=" << scanned->scanResult.candidates.size()
				  << " plan=" << scanned->preparationPlan.has_value() << '\n' ;
		// 各providerの元scan結果を確認します
		for( const auto &report : scanned->scanResult.providerReports) {
			std::cout << "STORAGE_SCAN_PROVIDER state=" << static_cast<unsigned>( report.state)
					  << " error=" << report.error << " candidates=" << report.candidateCount
					  << '\n' ;
		}

		// 実際に投影された各候補を確認します
		for( const auto &candidate : scanned->scanResult.candidates) {
			std::wcout << L"STORAGE_SCAN_CANDIDATE class=" << candidate.driverClass << L" guid="
					   << candidate.deviceClassGuid << L" provider=" << candidate.providerId
					   << L'\n' ;
		}
	}

	DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan &&
									scanned->preparationPlan->targets.size() == 1U) ;
	// 元scanの取得対象がない場合は材料不成立を負例成功へ数えません
	if( !scanned || !scanned->preparationPlan || scanned->preparationPlan->targets.size() != 1U) {
		bound.worker->stop() ;
		throw std::runtime_error( "storage scan prerequisite failed") ;
	}

	// 元scanで発行された一取得計画です
	const auto plan = *scanned->preparationPlan ;
	// 手製candidateで補完しない元索引参照です
	const auto reference =
		std::ranges::find_if( scanned->scanResult.candidates, []( const auto &value) {
			return !value.current && value.providerId == SIGNED_INDEX_PROVIDER_ID ;
		}) ;
	DRIVERCRATE_EXPECT( context,
					   reference != scanned->scanResult.candidates.end() &&
						   controller.completeScan( scan.operationId, scanned->scanResult) &&
						   controller.setPreparationPlan( scan.operationId, plan)) ;
	// 同scan/元選択/取得条件に結ぶ本人同意です
	OfficialPreparationApproval approval{0U,
										 plan.scanSessionId,
										 plan.planId,
										 plan.limits,
										 {{plan.targets.front(), true, false, false, false}}} ;
	// 手製候補ではなく通常scanで表示された元一候補を明示指定します
	if( reference != scanned->scanResult.candidates.end()) {
		approval.installIntentIdentities.push_back( reference->identity) ;
	}

	// 同元取得を開始するoperationの受付結果です
	const auto preparation = controller.beginPreparation( approval) ;
	DRIVERCRATE_EXPECT( context, preparation.accepted && bound.worker->requestPreparation( approval)) ;
	// 元取得/内容/適用性を実処理した終端です
	auto prepared =
		waitEvent( *bound.worker, WorkerEventKind::PREPARATION_COMPLETED, approval.operationId) ;
	DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
	// 元auditが実発行した候補だけを所有する集合です
	std::vector<UpdateCandidate> candidates ;
	// 同取得の元成功と拒否を別々に保存します
	if( prepared) {
		// 同取得の全auditを候補数/固定拒否/内容診断へ照合します
		for( const auto &report : prepared->preparationResult.auditReports) {
			candidates.insert( candidates.end(), report.publishedCandidates.begin(),
							  report.publishedCandidates.end()) ;
			std::cout << "STORAGE_BIND_AUDIT case=" << static_cast<unsigned>( expected.nativeCase)
					  << " accepted=" << report.acceptedInfCount
					  << " firstContent=" << report.firstContentRejection
					  << " publication=" << report.publication.firstError
					  << " stage=" << report.publication.bindingStage
					  << " candidates=" << report.publishedCandidates.size() << '\n' ;
			// 想定した原拒否地点/codeを別の素材失敗で救済しません
			if( expected.rejectionError) {
				DRIVERCRATE_EXPECT( context,
								   report.publication.firstError == *expected.rejectionError) ;
			}

			// 元拒否地点を別の早期失敗で救済しません
			if( expected.rejectionStage) {
				DRIVERCRATE_EXPECT( context,
								   report.publication.bindingStage == *expected.rejectionStage) ;
			}

			// 内容不成立を後段factory拒否と誤認しません
			if( expected.contentError) {
				DRIVERCRATE_EXPECT( context,
								   report.firstContentRejection == *expected.contentError &&
									   report.acceptedInfCount == 0U) ;
			} else {
				DRIVERCRATE_EXPECT( context, report.acceptedInfCount == 1U &&
												report.firstContentRejection == 0U) ;
			}
		}
	}

	DRIVERCRATE_EXPECT( context, candidates.size() == (expected.qualified ? 1U : 0U)) ;
	// 対象限定postcheckが全device再scanしないことを比較する基準です
	const auto scansBefore = bound.observe().allPresentInventoryOpens ;
	// 元全作用資格のない場合は復旧/登録/導入が全て未実行です
	if( !expected.qualified || candidates.size() != 1U || !prepared) {
		// 独立検査で得た現在又は元終端の観測です
		const auto observed = bound.observe() ;
		DRIVERCRATE_EXPECT( context, observed.stages == 0U && observed.installs == 0U &&
										observed.restoreBegins == 0U) ;
		// MTD人工INFだけ二DLLと型付き属性を確認します
		if( zip.find( "Class=MTD\r\n") != zip.npos) {
			DRIVERCRATE_EXPECT( context,
							   observed.mtdFilesDifs == 0U && observed.mtdCommits == 0U &&
								   observed.mtdInstallDifs == 0U && observed.legacyInstalls == 0U &&
								   !observed.mtdOutsideOwned && !observed.mtdBeforeRestoreAccess) ;
			std::cout << "MTD_FAKE_REJECT scenario=" << static_cast<unsigned>( expected.mtdScenario)
					  << " nativeFallback=0 dif=0 restore=0\n" ;
		}

		bound.worker->stop() ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
		std::cout << "STORAGE_BIND_REJECT assertions=" << context.assertionCount() - before
				  << " failures=" << context.failureCount() - failures << " stage=0 install=0\n" ;
		return ;
	}

	// 同原record/deviceで実発行した唯一候補です
	const auto &candidate = candidates.front() ;
	DRIVERCRATE_EXPECT(
		context, candidate.installable && candidate.storageChange &&
					 candidate.requiredExtensionCount == 0U &&
					 candidate.requiredDriverComponentCount == 0U &&
					 candidate.storageChange->requiredImportCount == expected.imports &&
					 candidate.assessment &&
					 candidate.assessment->installMethod == CandidateInstallMethod::STANDARD_INF) ;
	// MTD候補の表示用storage作用を検証します
	if( zip.find( "Class=MTD\r\n") != zip.npos && candidate.storageChange) {
		DRIVERCRATE_EXPECT( context,
						   candidate.storageChange->sharedDllCount == 2U &&
							   candidate.storageChange->mtdDeviceType == 7U &&
							   candidate.storageChange->mtdDeviceCharacteristics == 0x101U) ;
	}

	DRIVERCRATE_EXPECT( context,
					   prepared->preparationResult.installResolutions.size() == 1U &&
						   prepared->preparationResult.installResolutions.front().state ==
							   (expected.nativeCase == SignedIndexBindingNativeCase::STORAGE_OLDER
									? PreparedInstallResolutionState::DOWNGRADE_REQUIRES_SELECTION
									: PreparedInstallResolutionState::READY)) ;
	DRIVERCRATE_EXPECT( context, controller.completePreparation( prepared->preparationResult,
															   scanned->scanResult.candidates)) ;
	// 同原byte又は同deviceに結ぶ元明示選択の閉集合です
	const std::array selected{candidate.identity} ;
	DRIVERCRATE_EXPECT(
		context,
		!controller.beginInstall( plan.scanSessionId, selected, InstallConfirmation::NOT_CONFIRMED)
			 .accepted) ;
	DRIVERCRATE_EXPECT(
		context,
		!controller.beginInstall( plan.scanSessionId + 1U, selected, InstallConfirmation::CONFIRMED)
			 .accepted) ;
	// 同意前に共有先へ触れていないことを確認します
	if( zip.find( "Class=MTD\r\n") != zip.npos) {
		// 同意前に独立読取した低位call観測です
		const auto beforeConsent = bound.observe() ;
		DRIVERCRATE_EXPECT( context,
						   beforeConsent.restoreBegins == 0U && beforeConsent.stages == 0U &&
							   beforeConsent.mtdFilesDifs == 0U && beforeConsent.mtdCommits == 0U &&
							   beforeConsent.mtdInstallDifs == 0U &&
							   !beforeConsent.mtdBeforeRestoreAccess) ;
	}

	// 正例の同byteを保持し、原低位の公開後変化だけを与えます
	if( expected.changeNative) {
		bound.changeNativeState() ;
	}

	// 同scanの明示選択に結ぶ今回の導入操作です
	const auto install =
		controller.beginInstall( plan.scanSessionId, selected, InstallConfirmation::CONFIRMED) ;
	DRIVERCRATE_EXPECT( context, install.accepted &&
									bound.worker->requestInstall(
										install.operationId, plan.scanSessionId, selected, nullptr,
										InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
	// 実workerのfake指定導入と保護の全終端です
	auto installed =
		waitEvent( *bound.worker, WorkerEventKind::INSTALL_COMPLETED, install.operationId) ;
	DRIVERCRATE_EXPECT( context, installed.has_value()) ;
	// 独立検査で得た現在又は元終端の観測です
	const auto observed = bound.observe() ;
	// 人工INFがMTDかの判定です
	const bool isMtd = zip.find( "Class=MTD\r\n") != zip.npos ;
	// MTDの各低位DIFとcopy結果を独立観測します
	if( isMtd) {
		std::cout << "MTD_FAKE_CALLS scenario=" << static_cast<unsigned>( expected.mtdScenario)
				  << " filesDif=" << observed.mtdFilesDifs << " commits=" << observed.mtdCommits
				  << " installDif=" << observed.mtdInstallDifs
				  << " legacy=" << observed.legacyInstalls
				  << " outside=" << observed.mtdOutsideOwned
				  << " preRestore=" << observed.mtdBeforeRestoreAccess
				  << " sysNew=" << observed.mtdSysMatches << " sysOld=" << observed.mtdSysOldMatches
				  << '\n' ;
		DRIVERCRATE_EXPECT( context, observed.legacyInstalls == 0U && !observed.mtdOutsideOwned &&
										!observed.mtdBeforeRestoreAccess) ;
		// 成功条件では各DIFとcommitが一回であることを確認します
		if( expected.succeeded) {
			DRIVERCRATE_EXPECT( context, observed.mtdFilesDifs == 1U && observed.mtdCommits == 1U &&
											observed.mtdInstallDifs == 1U) ;
		}

		// 成功条件では二DLLが元byteに一致することを確認します
		if( expected.succeeded) {
			DRIVERCRATE_EXPECT( context,
							   observed.mtdTargetMatches[0] && observed.mtdTargetMatches[1]) ;
			// 既存または混在条件では元file ID保持を確認します
			if( expected.mtdScenario == MtdFixtureScenario::BOTH_EXIST ||
			   expected.mtdScenario == MtdFixtureScenario::MIXED) {
				DRIVERCRATE_EXPECT( context, observed.mtdTargetPriorIdPreserved[0]) ;
			}

			// 両既存条件では二件目のIDも保持されることを確認します
			if( expected.mtdScenario == MtdFixtureScenario::BOTH_EXIST) {
				DRIVERCRATE_EXPECT( context, observed.mtdTargetPriorIdPreserved[1]) ;
			}

			// SYS遅延時は通常copy済みと混同しません
			if( expected.mtdScenario == MtdFixtureScenario::SYSTEM_DELAYED) {
				DRIVERCRATE_EXPECT( context, !observed.mtdSysMatches && observed.mtdSysOldMatches) ;
			} else {
				DRIVERCRATE_EXPECT( context, observed.mtdSysMatches && !observed.mtdSysOldMatches) ;
			}
		}
		// 異byte既存や競合の元byteが保持されたことを確認します
		else if( expected.mtdScenario == MtdFixtureScenario::FOREIGN_EXISTING ||
				expected.mtdScenario == MtdFixtureScenario::RACE_DIFFERENT) {
			DRIVERCRATE_EXPECT( context, observed.mtdForeignPreserved &&
											!observed.mtdTargetMatches[0] &&
											observed.mtdSysOldMatches && !observed.mtdSysMatches) ;
		}
	}

	DRIVERCRATE_EXPECT(
		context, observed.stages == expected.stages && observed.installs == expected.installs &&
					 observed.specifiedBindingMatches && observed.deviceInstalls[1] == 0U &&
					 observed.dependencySystemStageCalls == 0U &&
					 observed.allPresentInventoryOpens == scansBefore) ;
	DRIVERCRATE_EXPECT( context,
					   observed.restoreBegins == (expected.changeNative ? 0U : 1U) &&
						   observed.restoreCompletes ==
							   (expected.restoreFailure || expected.changeNative ? 0U : 1U)) ;
	// API成否/原error/NeedReboot/対象限定read-only反映を別々に確認します
	if( installed) {
		// 成功確定まで部分値を外へ出さない当該結果です
		const auto &result = installed->installResult ;
		// 復旧拒否時にstageと共有作用がないことを確認します
		if( isMtd && expected.restoreFailure) {
			DRIVERCRATE_EXPECT( context,
							   result.restoreStoppedBeforeProvider &&
								   result.restorePointCreation.outcome == OutcomeCode::FAILURE &&
								   result.restorePointCreation.error ==
									   static_cast<NativeError>( E_ACCESSDENIED)) ;
		}

		DRIVERCRATE_EXPECT( context, result.succeeded == expected.succeeded &&
										controller.completeInstall( install.operationId, result)) ;
		DRIVERCRATE_EXPECT( context, (expected.installs == 0U && !expected.executionError) ||
										result.updates.size() == 1U) ;
		// 元一候補の結果がある場合だけ個別native診断を照合します
		if( !result.updates.empty()) {
			// 当該候補のstage/API/原errorを分けた所有結果です
			const auto &update = result.updates.front() ;
			// MTD操作を開始した場合だけ共有結果を個別確認します
			if( isMtd && !expected.restoreFailure && !expected.changeNative &&
			   !update.requiredRoles.empty()) {
				// 実行結果に結ばれた共有copy詳細です
				const auto &shared = update.requiredRoles.front().sharedCopy ;
				DRIVERCRATE_EXPECT( context, shared.has_value()) ;
				// 共有結果がある場合はその部分状態を出力します
				if( shared) {
					std::cout << "MTD_FAKE_RESULT preflight="
							  << static_cast<unsigned>( shared->preflightOutcome)
							  << " copy=" << static_cast<unsigned>( shared->copyOutcome)
							  << " copyError=" << shared->copyError
							  << " renamed=" << shared->renameSucceeded
							  << " created=" << shared->created << " reused=" << shared->reused
							  << " queue=" << shared->queueStarted << '/' << shared->queueCompleted
							  << " sysDelayed=" << shared->systemDelayed << '\n' ;
					// 成功時の既存再利用数と新規配置数を独立に確認します
					if( expected.succeeded) {
						// scenarioごとに期待する既存DLL数です
						const auto existing =
							expected.mtdScenario == MtdFixtureScenario::BOTH_EXIST ? 2U
							: expected.mtdScenario == MtdFixtureScenario::MIXED ||
									expected.mtdScenario == MtdFixtureScenario::RACE_SAME
								? 1U
								: 0U ;
						DRIVERCRATE_EXPECT(
							context,
							shared->preflightOutcome == OutcomeCode::SUCCESS &&
								shared->copyOutcome == OutcomeCode::SUCCESS &&
								shared->copyError == 0U && shared->created == 2U - existing &&
								shared->renameSucceeded == shared->created &&
								shared->reused == existing && shared->queueStarted &&
								shared->queueCompleted && !shared->cleanupUncertain &&
								!shared->parameterCleanupError &&
								shared->systemDelayed ==
									(expected.mtdScenario == MtdFixtureScenario::SYSTEM_DELAYED)) ;
					}
					// 異byte targetの事前拒否と元内容保持を確認します
					else if( expected.mtdScenario == MtdFixtureScenario::FOREIGN_EXISTING ||
							expected.mtdScenario == MtdFixtureScenario::BAD_DACL ||
							expected.mtdScenario == MtdFixtureScenario::BAD_OWNER ||
							expected.mtdScenario == MtdFixtureScenario::EXISTING_WRITER ||
							expected.mtdScenario == MtdFixtureScenario::REPARSE_TARGET ||
							expected.mtdScenario == MtdFixtureScenario::REPARSE_PARENT ||
							expected.mtdScenario == MtdFixtureScenario::HARDLINK_TARGET ||
							expected.mtdScenario == MtdFixtureScenario::READ_FAILURE) {
						DRIVERCRATE_EXPECT(
							context,
							shared->preflightOutcome == OutcomeCode::FAILURE &&
								shared->copyOutcome == OutcomeCode::NOT_STARTED &&
								!shared->renameSucceeded && !shared->queueStarted &&
								observed.mtdFilesDifs == 0U && observed.mtdCommits == 0U &&
								(expected.mtdScenario == MtdFixtureScenario::REPARSE_PARENT ||
								 observed.mtdTargetPriorIdPreserved[0]) &&
								observed.mtdSysOldMatches) ;
					}
					// 祖先と配置直親の拒否はstage前に無作用で止まります
					else if( expected.mtdScenario == MtdFixtureScenario::ANCESTOR_DELETE_CHILD ||
							expected.mtdScenario == MtdFixtureScenario::ANCESTOR_DELETE ||
							expected.mtdScenario == MtdFixtureScenario::ANCESTOR_WRITE_DAC ||
							expected.mtdScenario == MtdFixtureScenario::ANCESTOR_WRITE_OWNER ||
							expected.mtdScenario == MtdFixtureScenario::ANCESTOR_WRITE_FILE ||
							expected.mtdScenario ==
								MtdFixtureScenario::ANCESTOR_UNPROTECTED_CHILD ||
							expected.mtdScenario == MtdFixtureScenario::ANCESTOR_CHILD_WRITE ||
							expected.mtdScenario ==
								MtdFixtureScenario::DESTINATION_PARENT_ADD_DIRECTORY) {
						DRIVERCRATE_EXPECT(
							context, shared->preflightOutcome == OutcomeCode::FAILURE &&
										 shared->copyOutcome == OutcomeCode::NOT_STARTED &&
										 !shared->renameSucceeded && !shared->queueStarted &&
										 observed.mtdFilesDifs == 0U && observed.mtdCommits == 0U &&
										 !observed.mtdTargetExists[0] &&
										 !observed.mtdTargetExists[1] && observed.mtdSysOldMatches) ;
					}
					// Store直親の拒否は登録後であっても共有配置やcommitを行いません
					else if( expected.mtdScenario ==
							MtdFixtureScenario::STORE_PARENT_ADD_DIRECTORY) {
						DRIVERCRATE_EXPECT(
							context, !shared->renameSucceeded && !shared->queueStarted &&
										 observed.mtdCommits == 0U &&
										 !observed.mtdTargetExists[0] &&
										 !observed.mtdTargetExists[1] && observed.mtdSysOldMatches) ;
					}
					// temp書込等の途中失敗をcopy失敗として確認します
					else if( expected.mtdScenario == MtdFixtureScenario::PARTIAL_WRITE ||
							expected.mtdScenario ==
								MtdFixtureScenario::EXPIRED_BEFORE_SECOND_RENAME) {
						DRIVERCRATE_EXPECT(
							context, shared->copyOutcome == OutcomeCode::FAILURE &&
										 shared->renameSucceeded == 1U && shared->created == 1U &&
										 !shared->queueStarted && observed.mtdTargetMatches[0] &&
										 !observed.mtdTargetExists[1] &&
										 observed.mtdSysOldMatches && !shared->cleanupUncertain) ;
					}
					// rename成功後の確認失敗を配置未実施にしません
					else if( expected.mtdScenario == MtdFixtureScenario::RENAME_VERIFY_FAILURE) {
						DRIVERCRATE_EXPECT(
							context, shared->copyOutcome == OutcomeCode::FAILURE &&
										 shared->renameSucceeded == 1U && shared->created == 0U &&
										 !shared->queueStarted && observed.mtdTargetMatches[0] &&
										 !observed.mtdTargetExists[1] && observed.mtdSysOldMatches) ;
					}
					// stage後のhandler・属性変化による部分状態を確認します
					else if( expected.mtdScenario == MtdFixtureScenario::HANDLER_AFTER_STAGE ||
							expected.mtdScenario == MtdFixtureScenario::HW_AFTER_STAGE ||
							expected.mtdScenario == MtdFixtureScenario::SELECTED_NODE_CHANGED ||
							expected.mtdScenario == MtdFixtureScenario::EXPIRED_BEFORE_STAGE ||
							expected.mtdScenario == MtdFixtureScenario::EXPIRED_BEFORE_FILE_DIF) {
						DRIVERCRATE_EXPECT(
							context, shared->copyOutcome == OutcomeCode::NOT_STARTED &&
										 !shared->renameSucceeded && !shared->queueStarted &&
										 observed.mtdFilesDifs == 0U && observed.mtdSysOldMatches &&
										 shared->preflightOutcome == OutcomeCode::SUCCESS) ;
					}
					// 未知callbackやDLL遅延による部分作用を確認します
					else if( expected.mtdScenario == MtdFixtureScenario::UNKNOWN_CALLBACK ||
							expected.mtdScenario == MtdFixtureScenario::DLL_DELAYED) {
						DRIVERCRATE_EXPECT(
							context, shared->copyOutcome == OutcomeCode::FAILURE &&
										 shared->created == 2U && shared->queueStarted &&
										 !shared->queueCompleted && observed.mtdCommits == 1U &&
										 observed.mtdInstallDifs == 0U &&
										 observed.mtdTargetMatches[0] &&
										 observed.mtdTargetMatches[1] && observed.mtdSysMatches) ;
					}
					// queue commit前失効では既配置だけを保持します
					else if( expected.mtdScenario == MtdFixtureScenario::EXPIRED_BEFORE_COMMIT) {
						DRIVERCRATE_EXPECT(
							context,
							shared->copyOutcome == OutcomeCode::FAILURE && shared->created == 2U &&
								!shared->queueStarted && observed.mtdCommits == 0U &&
								observed.mtdTargetMatches[0] && observed.mtdTargetMatches[1] &&
								observed.mtdSysOldMatches &&
								result.installOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
					}
					// queue commit後の失効等ではSYS作用を保持します
					else if( expected.mtdScenario == MtdFixtureScenario::EXPIRED_AFTER_COMMIT ||
							expected.mtdScenario == MtdFixtureScenario::RANK_AFTER_COMMIT) {
						DRIVERCRATE_EXPECT(
							context,
							shared->copyOutcome == OutcomeCode::SUCCESS && shared->created == 2U &&
								shared->queueCompleted && observed.mtdCommits == 1U &&
								observed.mtdInstallDifs == 0U && observed.mtdSysMatches &&
								update.requiredRoles.front().installOutcome ==
									OutcomeCode::NOT_STARTED &&
								result.installOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
					}
					// 選択DIF失敗や終了後検証失敗をcopy成功と区別します
					else if( expected.mtdScenario == MtdFixtureScenario::INSTALL_FAILURE ||
							expected.mtdScenario == MtdFixtureScenario::POST_DIF_VERIFY_FAILURE ||
							expected.mtdScenario == MtdFixtureScenario::PARAM_CLEANUP_FAILURE) {
						DRIVERCRATE_EXPECT(
							context, shared->copyOutcome == OutcomeCode::SUCCESS &&
										 shared->created == 2U && shared->queueStarted &&
										 shared->queueCompleted && observed.mtdCommits == 1U &&
										 observed.mtdInstallDifs == 1U && observed.mtdSysMatches) ;
						// DIF自体が成功した条件の後続失敗を別に確認します
						if( expected.mtdScenario != MtdFixtureScenario::INSTALL_FAILURE) {
							DRIVERCRATE_EXPECT(
								context,
								update.requiredRoles.front().installOutcome ==
										OutcomeCode::SUCCESS &&
									update.requiredRoles.front().reflection ==
										DriverPlanReflectionState::INSTALL_API_COMPLETED &&
									result.installOutcome == OutcomeCode::SUCCEEDED_WITH_ERRORS &&
									(expected.mtdScenario ==
											 MtdFixtureScenario::POST_DIF_VERIFY_FAILURE
										 ? shared->postVerifyError != 0U
										 : shared->parameterCleanupError != 0U)) ;
						}
					} else {
						DRIVERCRATE_EXPECT(
							context, shared->copyOutcome == OutcomeCode::FAILURE &&
										 shared->renameSucceeded == 0U && !shared->queueStarted &&
										 observed.mtdFilesDifs == 1U && observed.mtdCommits == 0U &&
										 observed.mtdInstallDifs == 0U &&
										 observed.mtdSysOldMatches) ;
					}
				}
			}

			// 指定したstage/API失敗の元HRESULTをそのまま要求します
			if( expected.executionError) {
				DRIVERCRATE_EXPECT( context, update.installError == *expected.executionError) ;
			}

			DRIVERCRATE_EXPECT(
				context,
				update.requiredImports.size() ==
					(expected.restoreFailure || expected.changeNative ? 0U : expected.imports)) ;
			DRIVERCRATE_EXPECT( context, update.rebootRequired ==
												(expected.installs != 0U && !expected.noReboot) &&
											result.rebootRequired == update.rebootRequired) ;
			// 全登録分母と原失敗を保持し、未実行baseをnull成功から補いません
			if( expected.imports != 0U && !expected.restoreFailure && !expected.changeNative) {
				// 必要null自身の登録guardで失敗する負例の期待分類です
				const bool nullFailed =
					expected.stagingFailure ||
					expected.nativeCase == SignedIndexBindingNativeCase::STAGE_CHANGED ||
					expected.nativeCase == SignedIndexBindingNativeCase::STAGE_EXTERNAL ||
					expected.nativeCase == SignedIndexBindingNativeCase::STAGE_BAD_LENGTH ;
				DRIVERCRATE_EXPECT(
					context,
					update.requiredRoles.size() == 1U &&
						update.requiredRoles.front().role == DriverPlanRole::BASE_DRIVER &&
						update.requiredImports.front().outcome ==
							(nullFailed ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS) &&
						(nullFailed ? update.requiredImports.front().error == update.installError
									: update.requiredImports.front().error == 0U)) ;
				// 部分登録後の結果は登録済みの原証拠を残します
				if( !expected.succeeded) {
					DRIVERCRATE_EXPECT( context,
									   result.installOutcome ==
										   (nullFailed ? OutcomeCode::FAILURE
													   : OutcomeCode::SUCCEEDED_WITH_ERRORS)) ;
				}

				// 未実行nativeと登録後の指定準備失敗を別々に確認します
				if( expected.installs == 0U) {
					const bool nodeGuardRejected =
						expected.nativeCase == SignedIndexBindingNativeCase::STAGE_WRONG_NODE ||
						expected.nativeCase == SignedIndexBindingNativeCase::STAGE_WRONG_RANK ||
						expected.nativeCase == SignedIndexBindingNativeCase::
												   RANK_STAGE_TIED ;	// base登録後の指定準備失敗です
					DRIVERCRATE_EXPECT( context,
									   update.requiredRoles.front().installOutcome ==
											   (nodeGuardRejected ? OutcomeCode::FAILURE
																  : OutcomeCode::NOT_STARTED) &&
										   update.requiredRoles.front().stageOutcome ==
											   (nodeGuardRejected ? OutcomeCode::SUCCESS
												: nullFailed	  ? OutcomeCode::NOT_STARTED
																  : OutcomeCode::FAILURE)) ;
				}
			}

			DRIVERCRATE_EXPECT(
				context,
				!expected.succeeded ||
					(update.installError == 0U && update.rebootRequired == !expected.noReboot &&
					 std::ranges::all_of( update.requiredImports, []( const auto &item) {
						 return item.outcome == OutcomeCode::SUCCESS && item.error == 0U ;
					 }))) ;
			// Windows指定APIの診断欠落を実ERROR_INVALID_DATAと区別します
			if( expected.nativeCase ==
			   SignedIndexBindingNativeCase::REQUIRED_BASE_DIAGNOSTIC_MISSING) {
				DRIVERCRATE_EXPECT( context,
								   !update.requiredRoles.empty() &&
									   update.requiredRoles.front().installDiagnosticMissing &&
									   update.installError != 0U) ;
			}
		}

		// API成功の対象限定postcheckだけを現在反映へ比較します
		if( expected.succeeded) {
			DRIVERCRATE_EXPECT(
				context,
				result.currentDevices.size() == 1U &&
					result.currentDevices.front().selectedTargetMatched ==
						(expected.reflectOwnInstall &&
						 expected.nativeCase != SignedIndexBindingNativeCase::STORAGE_POST_ABSENT &&
						 expected.nativeCase !=
							 SignedIndexBindingNativeCase::STORAGE_POST_READ_FAILURE)) ;
			// 同成功API後の不在と原読取失敗を別の結果へ保持します
			if( result.currentDevices.size() == 1U &&
			   expected.nativeCase == SignedIndexBindingNativeCase::STORAGE_POST_ABSENT) {
				DRIVERCRATE_EXPECT( context, result.currentDevices.front().error ==
												static_cast<NativeError>(
													HRESULT_FROM_WIN32( ERROR_NO_SUCH_DEVINST))) ;
			}

			// 現在版照会失敗を旧版や非presentの観測へ変換しません
			if( result.currentDevices.size() == 1U &&
			   expected.nativeCase == SignedIndexBindingNativeCase::STORAGE_POST_READ_FAILURE) {
				DRIVERCRATE_EXPECT(
					context,
					result.currentDevices.front().observation.version.state ==
							DevicePropertyReadState::FAILED &&
						result.currentDevices.front().observation.version.diagnostic.code ==
							ERROR_READ_FAULT) ;
			}
		}
	}

	// 同原選択の全作用と必要serviceの観測です
	const auto effects = bound.observeOriginalEffects() ;
	DRIVERCRATE_EXPECT( context, !effects.empty() && effects.front().storageEffects &&
									effects.front().storageEffects->service.start ==
										candidate.storageChange->startType) ;
	// 原source literalから独立に、開始/errorの書換えとoptional省略の合成を検出します
	if( !effects.empty() && effects.front().storageEffects) {
		const auto &service =
			// 完成した非権限raw factsだけを借用します
			effects.front().storageEffects->service ;
		const auto originalStart = zip.find( "StartType=0\r\n") != zip.npos ? 0U
								   : zip.find( "StartType=1\r\n") != zip.npos
									   ? 1U
									   : 3U ;	// 元sourceの一意な開始方式です
		const auto originalError = zip.find( "ErrorControl=0\r\n") != zip.npos	? 0U
								   : zip.find( "ErrorControl=2\r\n") != zip.npos ? 2U
								   : zip.find( "ErrorControl=3\r\n") != zip.npos
									   ? 3U
									   : 1U ;	// 元sourceの原数値です
		DRIVERCRATE_EXPECT(
			context, service.start == originalStart && service.errorControl == originalError &&
						 service.type == 1U && service.flags == 2U &&
						 service.binaryBytes == 1024U && service.binarySource == L"fixture.sys") ;
		// MTDの全原COPYとhardware属性を結果へ保持します
		if( isMtd) {
			DRIVERCRATE_EXPECT( context,
							   service.mtdCopies.size() == 3U &&
								   std::ranges::count_if( service.mtdCopies, []( const auto &copy) {
									   return copy.dirid == 11 && copy.fields.size() == 1U ;
								   }) == 2) ;
		}

		DRIVERCRATE_EXPECT(
			context,
			service.group.has_value() == (zip.find( "LoadOrderGroup=") != zip.npos) &&
				service.dependencies.has_value() == (zip.find( "Dependencies=") != zip.npos) &&
				service.bootFlags.has_value() == (zip.find( "BootFlags=") != zip.npos)) ;
		DRIVERCRATE_EXPECT(
			context,
			std::ranges::count_if( service.directives,
								  [&]( const auto &item) {
									  return item.key == L"StartType" &&
											 item.fields == std::vector<std::wstring>{
																std::to_wstring( originalStart)} ;
								  }) == 1 &&
				std::ranges::count_if( service.directives, [&]( const auto &item) {
					return item.key == L"ErrorControl" &&
						   item.fields == std::vector<std::wstring>{std::to_wstring( originalError)} ;
				}) == 1) ;
	}

	// 全原tupleを独立期待へ照合し、3fieldのflags/data補完を見逃しません
	if( expected.arecaEquivalent && !effects.empty() && effects.front().storageEffects) {
		// 同原文又はSDの全byteを取得する一時所有です
		const auto &raw = *effects.front().storageEffects ;
		DRIVERCRATE_EXPECT( context,
						   raw.sharedDiskTimeout == 90U &&
							   raw.service.addServiceFields ==
								   std::vector<std::wstring>(
									   {L"FixtureStorage", L"2", L"StorageService", L"EventLog"}) &&
							   candidate.storageChange->sharedDiskTimeout == 90U) ;
		const auto row = [&]( StorageInfAction action, SystemInfContext scope,
							 std::wstring_view section, std::uint32_t ordinal,
							 std::vector<std::wstring> fields) {
			return std::ranges::count_if( raw.effects, [&]( const auto &item) {
					   return item.action == action && item.original.source.scope == scope &&
							  item.original.source.name == section &&
							  item.original.row.ordinal == ordinal &&
							  item.original.row.values == fields ;
				   }) == 1 ;
		} ; // 同期借用だけで元値/大小文字/順序/型を確認します
		DRIVERCRATE_EXPECT(
			context,
			row( StorageInfAction::REGISTRY_VALUE, SystemInfContext::HARDWARE, L"HardwareSettings",
				2U, {L"HKR", L"Interrupt Management", L"0x00000010"}) &&
				row( StorageInfAction::REGISTRY_VALUE, SystemInfContext::HARDWARE,
					L"HardwareSettings", 3U,
					{L"HKR", L"Interrupt Management\\MessageSignaledInterruptProperties",
					 L"0x00000010"})) ;
		DRIVERCRATE_EXPECT(
			context,
			row( StorageInfAction::REGISTRY_VALUE, SystemInfContext::DEVICE, L"SharedDisk", 1U,
				{L"HKLM",
				 L"SYSTEM\\CurrentControlSet\\Services\\FixtureStorage\\Parameters\\Device",
				 L"MaximumSGList", L"0x10001", L"4096"}) &&
				row( StorageInfAction::REGISTRY_VALUE, SystemInfContext::DEVICE, L"SharedDisk", 2U,
					{L"HKLM",
					 L"SYSTEM\\CurrentControlSet\\Services\\FixtureStorage\\Parameters\\Device",
					 L"NumberOfRequests", L"0x10001", L"257"})) ;
		DRIVERCRATE_EXPECT(
			context,
			row( StorageInfAction::HARDWARE_VALUE_DELETE, SystemInfContext::HARDWARE,
				L"LegacyScsiPort", 0U, {L"HKR", L"ScsiPort", L"BusNumber"}) &&
				row( StorageInfAction::HARDWARE_VALUE_DELETE, SystemInfContext::HARDWARE,
					L"LegacyScsiPort", 1U, {L"HKR", L"ScsiPort", L"LegacyInterfaceType"}) &&
				row( StorageInfAction::HARDWARE_VALUE_DELETE, SystemInfContext::HARDWARE,
					L"LegacyScsiPort", 2U, {L"HKR", L"ScsiPort", L"SlotNumber"})) ;
		DRIVERCRATE_EXPECT( context, row( StorageInfAction::EVENT_RESOURCE,
										SystemInfContext::EVENT_LOG, L"EventResources", 1U,
										{L"HKR", L"", L"TypesSupported", L"0x10001", L"7"}) &&
										!raw.service.dependencies && !raw.service.bootFlags) ;
		DRIVERCRATE_EXPECT(
			context, effects.front().systemEffects.size() >= 1U &&
						 std::ranges::any_of( effects.front().systemEffects, []( const auto &item) {
							 return item.source.name == L"NoIoSpace" &&
									item.row.values == std::vector<std::wstring>{
														   L"HKR",
														   L"e5b3b5ac-9725-4f78-963f-03dfb1d828c7",
														   L"IoNotRequired", L"0x10001", L"1"} ;
						 })) ;
	}

	bound.worker->stop() ;
	// 原fake stage/指定APIの実観測列です
	const auto calls = bound.observeStorageCalls() ;
	// 全stageだけを数え、必要nullを別device installへ変換しません
	DRIVERCRATE_EXPECT( context, calls.size() == expected.stages + expected.installs &&
									bound.allNativeHandlesClosed()) ;
	// 元import→base→非null指定の順序を件数とは独立に確認します
	if( !calls.empty()) {
		DRIVERCRATE_EXPECT( context, calls.front() == (expected.imports ? L"stage:importonly.inf"
																	   : L"stage:fixture.inf")) ;
	}

	// 必要nullの後に元baseだけが登録される順序を確認します
	if( expected.stages > expected.imports && expected.imports != 0U) {
		DRIVERCRATE_EXPECT( context, calls[expected.imports] == L"stage:fixture.inf") ;
	}

	// 指定APIが呼ばれた場合だけ末尾の非null/flags0を要求します
	if( expected.installs != 0U) {
		DRIVERCRATE_EXPECT( context, calls.back() == (zip.find( "Class=MTD\r\n") != zip.npos
														 ? L"mtd:dif-selected:nofilecopy"
														 : L"install:nonnull:flags0")) ;
	}

	DRIVERCRATE_EXPECT( context, std::ranges::none_of( calls, []( const auto &call) {
						   return call == L"stage:unselected.inf" ;
					   })) ;
	std::cout << "STORAGE_BIND_NATIVE case=" << static_cast<unsigned>( expected.nativeCase)
			  << " stage=" << observed.stages << " install=" << observed.installs
			  << " restore=" << observed.restoreBegins << '/' << observed.restoreCompletes
			  << " start=" << candidate.storageChange->startType << " imports=" << expected.imports
			  << " assertions=" << context.assertionCount() - before
			  << " failures=" << context.failureCount() - failures << " realInstall=0 sequence=" ;
	// 人工member名だけを固定call列へ出します
	for( const auto &call : calls) {
		// 元の人工ASCII literalだけを診断列へ射影します
		for( const auto character : call) {
			std::cout << (character <= 0x7f ? static_cast<char>( character) : '?') ;
		}

		std::cout << ',' ;
	}

	std::cout << '\n' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同原人工ZIPから通常候補/明示選択/fakeNewDevと保護境界を検査します
 * @param[in,out] context 有限assertion集計です
 * @param[in] services 真署名隔離storeと完全HTTPです
 * @param[in] zip 同取得と全内容期待hashへ固定する原ZIPです
 * @note 実driver/復旧/通信へfallbackしません
 */
//------------------------------------------------------------------------------
void runWindowsManagedDriverBindingTests( TestContext						   &context,
										 provider_worker_index_detail::Services services,
										 std::string_view						zip)
{
	const bool badScope =
		// 元INFからの固定負例だけです
		zip.find( "scope-fixture-reject") != zip.npos ;
	const unsigned modes = badScope ? 1U : 5U ;	// 通常/復旧失敗/原hash差/CAT拒否/staleを分離します
	// 同元取得ごとに新scan/新native低位表を所有し、成功状態を持ち越しません
	for( unsigned mode = 0U; mode < modes; ++mode) {
		const auto nativeCase = mode == 2U ? SignedIndexBindingNativeCase::IMPORT_HASH_CHANGED
								: mode == 3U
									? SignedIndexBindingNativeCase::IMPORT_MEMBER_FAILURE
									: SignedIndexBindingNativeCase::NORMAL ;	// 元低位条件だけです
		auto	   bound = makeSignedIndexBindingWorker( services, zip, false, mode == 1U, false,
														nativeCase) ;	// 完全fake native/復旧です
		OperationController controller ;								// 通常本体と同じ選択/同意/session状態機械です
		ScanOptions			options ;									// 実WUA/公式HTTPを開始しません
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring( DRIVER_STORE_PROVIDER_ID),
									   std::wstring( SIGNED_INDEX_PROVIDER_ID)} ;
		const auto scan				= controller.beginScan() ;	// 通常元scanの正のoperationです
		DRIVERCRATE_EXPECT( context,
						   scan.accepted && bound.worker->requestScan( scan.operationId, options)) ;
		auto scanned = waitEvent( *bound.worker, WorkerEventKind::SCAN_COMPLETED,
								 scan.operationId) ;	// 元終端です
		DRIVERCRATE_EXPECT( context, scanned && scanned->preparationPlan &&
										scanned->preparationPlan->targets.size() == 1U) ;
		// 前提不足を負例の成功へ変換しません
		if( !scanned || !scanned->preparationPlan ||
		   scanned->preparationPlan->targets.size() != 1U) {
			bound.worker->stop() ;
			throw std::runtime_error( "managed driver scan prerequisite") ;
		}

		const auto plan = *scanned->preparationPlan ;	// 同scanの元取得対象です
		DRIVERCRATE_EXPECT( context,
						   controller.completeScan( scan.operationId, scanned->scanResult) &&
							   controller.setPreparationPlan( scan.operationId, plan)) ;
		OfficialPreparationApproval approval{
			0U,
			plan.scanSessionId,
			plan.planId,
			plan.limits,
			{{plan.targets.front(), true, false, false, false}}} ;	// 検査取得だけの人工同意です
		const auto preparation =
			// 通常受付でoperationを固定します
			controller.beginPreparation( approval) ;
		DRIVERCRATE_EXPECT( context,
						   preparation.accepted && bound.worker->requestPreparation( approval)) ;
		auto prepared = waitEvent( *bound.worker, WorkerEventKind::PREPARATION_COMPLETED,
								  approval.operationId) ;	// 元取得/検査/候補の終端です
		DRIVERCRATE_EXPECT( context, prepared.has_value()) ;
		std::vector<UpdateCandidate> candidates ;	// 実publicationだけです。合成しません
		// 元候補と原拒否を同じreportから読みます
		if( prepared) {
			// 同一元taskの全pair結果を保持します
			for( const auto &report : prepared->preparationResult.auditReports) {
				candidates.insert( candidates.end(), report.publishedCandidates.begin(),
								  report.publishedCandidates.end()) ;
				std::cout << "WINDOWS_MANAGED_AUDIT mode=" << mode << " badScope=" << badScope
						  << " content=" << report.contentError
						  << " rejected=" << report.firstContentRejection
						  << " binding=" << report.publication.firstError << '\n' ;
			}
		}

		const bool contentRejected = badScope || mode == 3U ;	// 元scope/CAT拒否だけです
		DRIVERCRATE_EXPECT( context, candidates.size() == (contentRejected ? 0U : 1U)) ;
		// 前段拒否は復旧/Windows指定APIを呼ばないまま終端させます
		if( contentRejected || candidates.size() != 1U || !prepared) {
			DRIVERCRATE_EXPECT( context, bound.observe().stages == 0U &&
											bound.observe().installs == 0U &&
											bound.observe().restoreBegins == 0U) ;
			bound.worker->stop() ;
			DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
			continue ;
		}

		const auto &candidate = candidates.front() ;	// 同scanの唯一の通常candidateです
		DRIVERCRATE_EXPECT( context, candidate.installable && candidate.assessment &&
										candidate.assessment->installMethod ==
											CandidateInstallMethod::STANDARD_INF &&
										candidate.action == DriverAction::UPDATE &&
										candidate.requiredExtensionCount == 0U &&
										candidate.requiredDriverComponentCount == 0U) ;
		DRIVERCRATE_EXPECT( context, controller.completePreparation( prepared->preparationResult,
																   scanned->scanResult.candidates)) ;
		const std::array selected{candidate.identity} ;	// 一deviceを明示選択します
		DRIVERCRATE_EXPECT( context, !controller
										 .beginInstall( plan.scanSessionId, selected,
													   InstallConfirmation::NOT_CONFIRMED)
										 .accepted) ;
		DRIVERCRATE_EXPECT( context, !controller
										 .beginInstall( plan.scanSessionId + 1U, selected,
													   InstallConfirmation::CONFIRMED)
										 .accepted) ;
		DRIVERCRATE_EXPECT( context, bound.observe().stages == 0U &&
										bound.observe().installs == 0U &&
										bound.observe().restoreBegins == 0U) ;
		// staleはworkerでも旧sessionの元guardを確認し、正しいsessionへ補完しません
		if( mode == 4U) {
			const bool queued = bound.worker->requestInstall(
				900U, plan.scanSessionId + 1U, selected, nullptr,
				InstallProtectionMode::WINDOWS_RESTORE_POINT) ;	// 全変更APIはfakeです
			// 受付後の拒否も原終端を待ってから数えます
			if( queued) {
				auto rejected = waitEvent( *bound.worker, WorkerEventKind::INSTALL_COMPLETED,
										  900U) ;	// stale元operationです
				DRIVERCRATE_EXPECT( context, rejected && !rejected->installResult.succeeded) ;
			}

			DRIVERCRATE_EXPECT( context,
							   bound.observe().stages == 0U && bound.observe().installs == 0U) ;
			bound.worker->stop() ;
			DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
			continue ;
		}

		// 同保護importの元byteだけを変更し、成功候補や私有計画は書換えません
		if( mode == 2U) {
			bound.changeNativeState() ;
		}

		const auto install = controller.beginInstall(
			plan.scanSessionId, selected, InstallConfirmation::CONFIRMED) ;	// 正の明示導入です
		DRIVERCRATE_EXPECT( context, install.accepted &&
										bound.worker->requestInstall(
											install.operationId, plan.scanSessionId, selected,
											nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
		auto installed = waitEvent( *bound.worker, WorkerEventKind::INSTALL_COMPLETED,
								   install.operationId) ;	// fake NewDev/復旧の元終端です
		DRIVERCRATE_EXPECT( context, installed.has_value()) ;
		const auto observation = bound.observe() ;	// 同終端同期後だけの元counterです
		const bool success	   = mode == 0U ;		// 復旧/原hash負例を成功へ補正しません
		DRIVERCRATE_EXPECT( context, observation.stages == (success ? 1U : 0U) &&
										observation.installs == (success ? 1U : 0U)) ;
		DRIVERCRATE_EXPECT( context, observation.restoreBegins == (mode == 2U ? 0U : 1U) &&
										observation.restoreCompletes == (success ? 1U : 0U)) ;
		// 復旧結果と各対象の元結果を通常controllerへ保持します
		if( installed) {
			DRIVERCRATE_EXPECT( context, installed->installResult.succeeded == success &&
											controller.completeInstall( install.operationId,
																	   installed->installResult)) ;
		}

		std::cout << "WINDOWS_MANAGED_NATIVE mode=" << mode << " stage=" << observation.stages
				  << " install=" << observation.installs << " restore=" << observation.restoreBegins
				  << '/' << observation.restoreCompletes
				  << " otherDeviceInstalls=" << observation.deviceInstalls[1]
				  << " realOsChanges=0 independentProgramSteps=0\n" ;
		bound.worker->stop() ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
	}
}

// UI試験はこの単体試験群が使うmetadata_inventory_testsのfixtureをリンクしません
#if !defined( DRIVERCRATE_INTERNAL_UI_TESTS)
//------------------------------------------------------------------------------
/**
 * @brief P4の同thread人工store/本文を既完全HTTP fakeへ結びます
 * @param[in] store 元RAM署名codecで保存した隔離storeです
 * @param[in] clock 元fixtureが所有する信頼UTCです
 * @param[in] zip 非空人工driver又は明示空containerの原byteです
 * @param[in] sent 元send回数だけを記録する非権限observerです
 * @return 実HTTP/DNS/costへfallbackしない既通常serviceです
 * @note 呼出threadだけで使い、host/native/signatureの完全表はcallerが別に所有します
 */
//------------------------------------------------------------------------------
provider_worker_index_detail::Services makeServerP4PipelineServices(
	std::shared_ptr<SignedIndexStore> store, std::shared_ptr<std::chrono::sys_seconds> clock,
	std::string_view zip, std::function<void()> sent) ;

//------------------------------------------------------------------------------
/**
 * @brief 規約と元ZIPを完全置換HTTPへ結びます
 * @param[in] bodies 配布ページ、規約文書、ZIPの原バイトです
 * @param[in] now 期限を検査する固定UTCです
 * @param[in] changed trueは承認後の規約文書だけを変更します
 * @param[in] retained 二つの独立対象が同じZIPを共有する試験です
 * @param[out] sends 同じfixtureが記録する送信数の読取りです
 * @return 実HTTPを呼ばない同期依存です
 */
//------------------------------------------------------------------------------
std::function<OfficialHttpTransport()> archiveTermsConsumerTransport(
	const std::array<std::string_view, 3> &bodies, std::chrono::sys_seconds now, bool changed,
	bool retained, std::function<std::size_t()> &sends) ;

/** @brief 実HINFのManufacturerだけへ応答するD16低位SDK状態です */
struct ServerP4ModelsState {
	/// 異ABI/不正引数を成功へ数えない持続flagです
	bool	 contractValid{true} ;
	/// 正候補後にだけ別の実在Models節を選びます
	bool	 other{} ;
	/// 有効なsize-queryの実回数です
	unsigned queries{} ;
	/// 有効なbuffer出力の実回数です
	unsigned reads{} ;
} ;
thread_local ServerP4ModelsState *serverP4Models{} ;	// 一owner scope中だけ借用します
//------------------------------------------------------------------------------
/**
 * @brief 実Manufacturerの一SDKへ固定節名だけを原ABIで返します
 * @param[in] context 実HINFのManufacturer contextです
 * @param[in] platform currentOS専用のnullptrです
 * @param[out] buffer 同SDKの受信先です。size queryではnullptrです
 * @param[in] capacity 元buffer文字数です
 * @param[out] required NUL込み必要文字数です。null可です
 * @param[in] reserved 予約nullptrです
 * @return 原BOOLと直後のWin32 errorです。小bufferへ書込みません
 */
//------------------------------------------------------------------------------
BOOL WINAPI serverP4ActualModels( PINFCONTEXT context, PSP_ALTPLATFORM_INFO platform, PWSTR buffer,
								 const DWORD capacity, PDWORD required, PVOID reserved)
{
	// 偽HINF/非NULL platform/予約値を元SDKへfallbackしません
	if( !serverP4Models || !context || !context->Inf || context->Inf == INVALID_HANDLE_VALUE ||
	   platform || reserved || (!buffer && (capacity != 0U || !required))) {
		// 実owner stateがある場合だけABI拒否の持続flagを残します
		if( serverP4Models) {
			serverP4Models->contractValid = false ;
		}

		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	std::array<wchar_t, 64U> base{} ;	// 実contextが原Manufacturerか確かめます
	DWORD					 size{} ;	// 原SDK fieldの必要文字数です
	// 実HINFの元Manufacturer field以外には応答しません
	if( !SetupGetStringFieldW( context, 1U, base.data(), static_cast<DWORD>( base.size()), &size) ||
	   std::wstring_view{base.data()} != L"Models") {
		serverP4Models->contractValid = false ;
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	const std::wstring_view section =
		serverP4Models->other ? L"Models.Other" : L"Models.NTamd64" ;	// 同不変INFの二実節だけです
	const auto needed = static_cast<DWORD>( section.size() + 1U) ;		// NUL込み文字数です
	// 要求された必要文字数だけを元SDK出力へ返します
	if( required) {
		*required = needed ;
	}

	// 有効なsize queryは成功し、LastErrorを成功根拠に使いません
	if( !buffer) {
		++serverP4Models->queries ;
		return TRUE ;
	}

	// 不足bufferは一文字も書換えません
	if( capacity < needed) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::copy( section.begin(), section.end(), buffer) ;
	buffer[section.size()] = L'\0' ;
	++serverP4Models->reads ;
	return TRUE ;
}

//------------------------------------------------------------------------------
/**
 * @brief D16の同SDK scope/ABI/buffer/復元を独立literalへ照合します
 * @param[in,out] context 共通assertionです
 * @param[in] path 元正候補が所有する不変INFです
 * @param[in,out] state 同thread SDK応答の所有状態です
 * @note 成功identity DTO/候補/元byteを変更せず、scope外のnative表を復元します
 */
//------------------------------------------------------------------------------
void serverP4ModelsContract( TestContext &context, const std::wstring &path,
							ServerP4ModelsState &state)
{
	using namespace official_inf_models_native_detail ;
	DRIVERCRATE_EXPECT( context, activeCalls() == nullptr && !Access::create( {}) &&
									!Access::create( {&::SetupDiGetActualModelsSectionW})) ;
	const HINF inf =
		// 同実INFだけです
		SetupOpenInfFileW( path.c_str(), nullptr, INF_STYLE_WIN4, nullptr) ;
	DRIVERCRATE_EXPECT( context, inf != INVALID_HANDLE_VALUE) ;
	// 実INF前提の欠損を低位fake成功へ数えません
	if( inf == INVALID_HANDLE_VALUE) {
		throw std::runtime_error( "P4 SDK contract INF missing") ;
	}

	INFCONTEXT line{} ;	// 同HINFの元Manufacturerです
	const bool found =
		// 実fieldです
		SetupFindFirstLineW( inf, L"Manufacturer", nullptr, &line) != FALSE ;
	DRIVERCRATE_EXPECT( context, found) ;
	serverP4Models = &state ;
	auto scope	   = Access::create( {&serverP4ActualModels}) ;	// 一APIだけの完全な低位表です
	DRIVERCRATE_EXPECT( context, scope && activeCalls() && !Access::create( {&serverP4ActualModels})) ;
	bool		otherThreadEmpty{} ;	// thread-local境界の実観測です
	std::thread other(
		[&]() { otherThreadEmpty = activeCalls() == nullptr ; }) ;	// 他threadへ同表を貸しません
	other.join() ;
	DRIVERCRATE_EXPECT( context, otherThreadEmpty) ;
	DWORD required{} ;	// 独立literalの必要文字数です
	DRIVERCRATE_EXPECT( context,
					   actualModelsSection( &line, nullptr, nullptr, 0U, &required, nullptr) &&
						   required == 15U) ;
	std::array<wchar_t, 2U> smallBuffer{L'X', L'Y'} ;	// 小bufferの不変期待です
	SetLastError( ERROR_SUCCESS) ;
	const auto smallResult = actualModelsSection( &line, nullptr, smallBuffer.data(), 2U, &required,
												 nullptr) ;	// 意図した不足だけです
	const auto smallError  = GetLastError() ;				// FALSE直後の元codeです
	DRIVERCRATE_EXPECT( context, !smallResult && smallError == ERROR_INSUFFICIENT_BUFFER &&
									required == 15U && smallBuffer[0] == L'X' &&
									smallBuffer[1] == L'Y') ;
	std::array<wchar_t, 32U> section{} ;	// 十分な固定受信先です
	DRIVERCRATE_EXPECT(
		context, actualModelsSection( &line, nullptr, section.data(),
									 static_cast<DWORD>( section.size()), nullptr, nullptr) &&
					 std::wstring_view{section.data()} == L"Models.NTamd64" && state.contractValid) ;
	DRIVERCRATE_EXPECT( context,
					   !actualModelsSection( nullptr, nullptr, section.data(),
											static_cast<DWORD>( section.size()), nullptr, nullptr) &&
						   GetLastError() == ERROR_INVALID_PARAMETER && !state.contractValid) ;
	// 意図した不正引数は上の独立assertionにだけ属します
	state.contractValid = true ;
	SP_ALTPLATFORM_INFO wrongPlatform{} ;	// NULL以外を明示拒否する独立入力です
	DRIVERCRATE_EXPECT( context,
					   !actualModelsSection( &line, &wrongPlatform, section.data(),
											static_cast<DWORD>( section.size()), nullptr, nullptr) &&
						   GetLastError() == ERROR_INVALID_PARAMETER && !state.contractValid) ;
	state.contractValid = true ;
	DRIVERCRATE_EXPECT( context, !actualModelsSection( &line, nullptr, section.data(),
													 static_cast<DWORD>( section.size()), nullptr,
													 reinterpret_cast<PVOID>( 1U)) &&
									GetLastError() == ERROR_INVALID_PARAMETER &&
									!state.contractValid) ;
	state.contractValid = true ;
	DRIVERCRATE_EXPECT( context,
					   !actualModelsSection( &line, nullptr, nullptr, 1U, &required, nullptr) &&
						   GetLastError() == ERROR_INVALID_PARAMETER && !state.contractValid) ;
	state.contractValid = true ;
	scope.reset() ;
	serverP4Models = nullptr ;
	SetupCloseInfFile( inf) ;
	DRIVERCRATE_EXPECT( context, activeCalls() == nullptr) ;
}

/** @brief 期待値と別に入力phase/counterを保持する同thread低位状態です */
struct ServerP4Observation {
	/// 元matrixの一意IDです
	std::string			id ;
	/// 実初回と比較する独立literalです
	WindowsHostPlatform platform ;
	/// 0は取得、1はaudit、2は最終指定導入、3はretained入力です
	unsigned			phase{} ;
	/// 同phaseの実host callback数です
	unsigned			phaseCalls{} ;
	/// 全phaseの実host callback数です
	unsigned			callbacks{} ;
	/// 完全fake HTTPの実send数です
	unsigned			sends{} ;
	/// READY直前に実発行された未公開tokenの観測数です
	unsigned			minted{} ;
	/// 再現した拒否後の正当な新scanだけはfaultを解除します
	bool				recover{} ;
	/// Aの実候補commit後だけBのfaultを有効にします
	bool				retainedTarget{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 固定phaseのliteral faultだけを元fullhost観測へ与えます
 * @param[in,out] state 同threadの一case状態です
 * @return 原domain/bits付き観測です。元scope/期待/recordは書換えません
 * @throws std::runtime_error D11の明示observer例外だけです
 */
//------------------------------------------------------------------------------
WindowsHostPlatformObservation serverP4Observe( ServerP4Observation &state)
{
	++state.callbacks ;
	++state.phaseCalls ;
	WindowsHostPlatformObservation value{
		WindowsHostObservationState::OBSERVED, state.platform, WindowsHostErrorDomain::NTSTATUS,
		WindowsHostObservationStage::VERSION, 0U} ;	// 成功原statusです
	const auto &id = state.id ;						// 固定入力IDだけでfaultを選びます
	const bool	auditFault =
		state.phase == 1U &&
		((state.phaseCalls == 1U &&
		  (id == "P4_D01_AUDIT_CHANGED_BUILD" || id == "P4_D02_AUDIT_WIN32_FAILURE" ||
		   id == "P4_D03_AUDIT_NTSTATUS_FAILURE" || id == "P4_D12_AUDIT_STALE_LATCH_SEQUENCE")) ||
		 (state.phaseCalls == 2U && id == "P4_D04_AFTER_MODELS_CHANGED_PRODUCT") ||
		 (state.phaseCalls == 3U && id == "P4_D05_BEFORE_TOKEN_CHANGED_SUITE") ||
		 (state.phaseCalls == 4U && (id == "P4_D06_PREPUBLICATION_ARM64" ||
									 (id == "P4_D18_RETAINED_MODELS_THEN_HOST_CHANGE" &&
									  state.retainedTarget)))) ;	// 製品phaseと独立したliteral順です
	const bool finalFault =
		state.phase == 2U && state.phaseCalls == 3U &&
		id != "P4_D16_FINAL_MODELS_MISMATCH" ;	// 最後のcurrentOS比較後だけhostを変更します
	const bool retainedFault = state.phase == 3U && state.phaseCalls == 1U &&
							   // 全A/B照合後だけです
							   id == "P4_D17_RETAINED_FRESH_FAILURE" ;
	// 未到達phaseや新正当scanへ旧faultを引き継ぎません
	if( state.recover || (!auditFault && !finalFault && !retainedFault)) {
		return value ;
	}

	// Win32 MODULE失敗の原domainと126を返します
	if( id == "P4_D02_AUDIT_WIN32_FAILURE" || id == "P4_D08_FINAL_WIN32_FAILURE") {
		return {WindowsHostObservationState::API_FAILED, std::nullopt,
				WindowsHostErrorDomain::WIN32_CODE, WindowsHostObservationStage::MODULE, 126U} ;
	}

	// NTSTATUS失敗の原32bitを変換せず返します
	if( id == "P4_D03_AUDIT_NTSTATUS_FAILURE" || id == "P4_D09_FINAL_NTSTATUS_FAILURE" ||
	   id == "P4_D13_FINAL_UNKNOWN_LATCH_SEQUENCE" || retainedFault) {
		return {WindowsHostObservationState::API_FAILED, std::nullopt,
				WindowsHostErrorDomain::NTSTATUS, WindowsHostObservationStage::VERSION,
				0xc0000001U} ;
	}

	// 未観測は成功tupleやnative errorを補完しません
	if( id == "P4_D10_FINAL_UNOBSERVED") {
		return {} ;
	}

	// 指定D11だけが所有observerの例外を送出します
	if( id == "P4_D11_FINAL_OBSERVER_THROW") {
		throw std::runtime_error( "P4 explicit observer fault") ;
	}

	// Models後のproduct一field差だけを与えます
	if( id == "P4_D04_AFTER_MODELS_CHANGED_PRODUCT") {
		value.value->productType = 2U ;
	}
	// suite差を未知へ丸めません
	else if( id == "P4_D05_BEFORE_TOKEN_CHANGED_SUITE" ||
			id == "P4_D18_RETAINED_MODELS_THEN_HOST_CHANGE") {
		value.value->suiteMask = 0U ;
	}
	// 完全な新unsupported値もSTALEです
	else if( id == "P4_D06_PREPUBLICATION_ARM64") {
		value.value->nativeArchitecture = 12U ;
	}
	// productの既知差です
	else if( id == "P4_D14_FINAL_KNOWN_PRODUCT4") {
		value.value->productType = 4U ;
	}
	// 必要field欠損だけUNKNOWNです
	else if( id == "P4_D15_FINAL_BUILD_UNKNOWN") {
		value.value->buildNumber = 0U ;
	} else { // 元matrixのbuild差だけです
		value.value->buildNumber = 20348U ;
	}

	return value ;
}

/** @brief 正常DTOを注入せず、通常sessionと低位完全fakeだけを所有します */
class ServerP4Harness final {
public:
	/// 期待値を生成しない実counterとphaseです
	ServerP4Observation												state ;
	/// 原clockを変える負例だけで共有するUTCです
	std::shared_ptr<std::chrono::sys_seconds>						clock ;
	/// 実低位Windows状態です。実端末のIDを使いません
	NativeFixtureState												native ;
	/// 低位表をproviderより長く所有します
	std::unique_ptr<driver_store_inf_detail::ScopedFixture>			drivers ;
	/// CAT/全memberの実人工hashを所有します
	std::unique_ptr<driver_package_signature_detail::ScopedFixture> signatures ;
	/// 完全な同collector文脈を所有します
	std::unique_ptr<inf_dependency_native_detail::ScopedFixture>	dependencies ;
	/// 原署名/raw/codec/storeと同fake HTTPです
	provider_worker_index_detail::Services							services ;
	/// 同threadの正常Compositeです
	std::unique_ptr<CompositeUpdateProvider>						provider ;
	/// 原scan/context/byte/ledgerの私有ownerです
	SignedIndexScanSession											session ;
	/// 初回認可後だけ借用し、新authorizerを作りません
	SignedIndexAcquisitionAdapter								   *adapter{} ;
	/// 元が非constである独立lookup copyです。負例はrelationだけを変えます
	std::shared_ptr<SignedIndexRecordLookup>						lookup ;
	/// 原三IDと初回hostは入替えません
	IndexScanHostSnapshot											original ;
	/// 通常validatorへ渡す元factory出力の所有copyです。内容や権限を補完しません
	std::vector<UpdateCandidate>									displayedCandidates ;
	/**
	 * @brief 非空認証入力を同threadの既完全fakeへ結びます
	 * @param[in] store 真署名codecの隔離storeです
	 * @param[in] now 元fixture UTCです
	 * @param[in] zip 同recordへ署名した原人工byteです
	 * @param[in] id 元入力IDです
	 * @param[in] platform 独立literalの原hostです
	 * @param[in] roots 0は既caseのroot数、非0は新fixtureの明示owner root数です
	 * @param[in] signatureZip 本文前で停止する保存原取得試験だけで使う人工署名用ZIPです
	 * @param[in] originalInf 保存原INFの同名CATをWindowsのキャッシュ済み信頼で検査するための固定値です
	 */
	ServerP4Harness(
		std::shared_ptr<SignedIndexStore> store, const std::chrono::sys_seconds now,
		const std::string_view zip, const std::string_view id, const WindowsHostPlatform platform,
		const unsigned roots = 0U, const std::string_view signatureZip = {},
		std::optional<driver_package_signature_detail::OriginalInfMetadata> originalInf = {})
		: state{std::string{id}, platform}, clock( std::make_shared<std::chrono::sys_seconds>( now))
	{
		activeNative			  = &native ;
		native.opaqueCompatibleId = L"TESTBUS\\P4_COMPAT_0001" ;
		native.currentProvider	  = L"Current Fixture Vendor" ;
		// 自作登録rootの欠損を実Windowsへfallbackしません
		if( !initializeRegistration( native)) {
			throw std::runtime_error( "P4 owned native fixture initialization") ;
		}

		drivers = driver_store_inf_detail::Access::create( calls()) ;
		auto files =
			// 人工閉包の元hashです
			signatureFiles( signatureZip.empty() ? zip : signatureZip) ;
		// 原CAT/member検証だけの拒否条件を用意します
		if( id == "P4_C06_CAT_REJECT") {
			const auto file = std::ranges::find_if( files, []( const auto &value) {
				return value.name == L"fixture.sys" ;
			}) ; // 狙ったmemberだけです
			// 狙ったSYSがないfixtureをCAT負例合格へ数えません
			if( file == files.end()) {
				throw std::runtime_error( "P4 CAT negative premise missing") ;
			}

			// CAT低位応答だけを拒否させます
			file->sha256.assign( 64U, L'0') ;
		}

		const auto signatureRoots =
			roots != 0U ? roots :
						// 二回取得するcaseに限り、同原hash集合の二root-owner組を許します
				id == "P4_C14_RETAINED_NONEMPTY_SUCCESS" ||
					id == "P4_C15_RETAINED_BAD_TARGET_HASH" ||
					id == "P4_C16_RETAINED_TARGET_EXPIRED" ||
					id == "P4_D12_AUDIT_STALE_LATCH_SEQUENCE" ||
					id == "P4_D13_FINAL_UNKNOWN_LATCH_SEQUENCE" ||
					id == "P4_D17_RETAINED_FRESH_FAILURE" ||
					id == "P4_D18_RETAINED_MODELS_THEN_HOST_CHANGE"
				? 2U
				: 1U ;
		// 公式ZIPの対照では人工署名表を使わず、同じ原INF・CATと閉包の原バイトを検査します
		if( originalInf) {
			signatures = driver_package_signature_detail::Access::createOriginalAdapter(
				{std::move( *originalInf)}) ;
		} else {
			signatures =
				driver_package_signature_detail::Access::create( std::move( files), signatureRoots) ;
		}

		inf_dependency_native_detail::Api api ;	// 五APIの欠落から実Windowsへ進みません
		api.version = []( OSVERSIONINFOEXW &version, SYSTEM_INFO &system) {
			version.dwMajorVersion		  = 10U ;
			version.dwMinorVersion		  = 0U ;
			version.dwBuildNumber		  = 26100U ;
			version.wProductType		  = VER_NT_WORKSTATION ;
			version.wSuiteMask			  = 0U ;
			system.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 ;
			return NativeError{} ;
		} ; // common closureの既collector client文脈です。Server実SDK資格ではありません
		api.windowsDirectory = [this]( std::wstring &path) {
			path = native.windowsRoot ;
			return NativeError{} ;
		} ;
		api.infSignature = []( const std::wstring &path, SP_INF_SIGNER_INFO_W &signer) {
			return driver_package_signature_detail::setupVerifyInf( path.c_str(), nullptr, &signer)
					   ? NativeError{}
					   : static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		} ;
		api.catalogSignature = []( const std::wstring				 &path,
								  const std::span<const std::wstring> members) {
			return verifyOfficialCatalogMembers( path, members) ;
		} ;
		api.driverStore = []( const std::wstring &, std::wstring &path) {
			path.clear() ;
			return static_cast<NativeError>( E_NOTIMPL) ;
		} ;
		dependencies = inf_dependency_native_detail::Access::create( std::move( api)) ;
		// 一つでも欠ける低位表から実APIへfallbackしません
		if( !drivers || !signatures || !dependencies) {
			throw std::runtime_error( "P4 complete low-level fixture missing") ;
		}

		services =
			makeServerP4PipelineServices( std::move( store), clock, zip, [this]() { ++state.sends ; }) ;
		services.hostPlatform = [this]() { return serverP4Observe( state) ; } ;
		services.beginHostAcquisition =
			[this]( SignedIndexAcquisitionAdapter				 &issuer,
				   std::shared_ptr<const SignedIndexRecordLookup> source,
				   const IndexLookupContext context, IndexScanHostSnapshot host,
				   WindowsHostPlatformObserver					 observer,
				   const std::optional<std::chrono::sys_seconds> time) {
				adapter	 = &issuer ;
				lookup	 = std::make_shared<SignedIndexRecordLookup>( *source) ;
				original = host ;
				std::cout << "P4_SCAN_CONTEXT case=" << state.id
						  << " operation=" << context.operationId
						  << " scan=" << context.scanSessionId
						  << " inventory=" << context.inventoryGeneration << '\n' ;
				return signed_index_acquisition_detail::Access::beginHostFixture(
					issuer, lookup, context, std::move( host), std::move( observer), time) ;
			} ; // コピーは既native lease/原byteを保持し、無認証lookupを作りません
		provider = std::make_unique<CompositeUpdateProvider>() ;
	}
	/**
	 * @brief issuer生存中に全route/token/ledgerを失効してから低位借用を解除します
	 */
	~ServerP4Harness()
	{
		// 借用issuerが生存する間に全route/token/ledgerを失効します
		session.invalidate() ;
		// 失効後に所有providerを破棄します
		provider.reset() ;
		// 両cleanupの終端後だけ低位fakeの借用を解除します
		activeNative = nullptr ;
	}
	/**
	 * @brief 実capture→認証lookup→adapter計画→元参照行を接続します
	 * @param[in,out] context 共通assertionです
	 * @param[in] sessionId 新しい正のscan IDです
	 * @param[in] planId 同じ準備管理で単調増加する取得計画IDです
	 * @param[in] expectedStatus 索引スキャンの独立した期待結果です
	 * @return 同ownerが実生成した取得計画です
	 */
	OfficialPreparationPlan plan( TestContext &context, const ScanSessionId sessionId,
								 const std::uint64_t   planId		  = 1U,
								 const IndexScanStatus expectedStatus = IndexScanStatus::COMPLETED)
	{
		signed_index_candidate_binding_detail::Access::bind( *provider, session, services,
															sessionId + 100U) ;
		ScanOptions options ;	// 公式HTTP/WUAを起動しません
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
									   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		const auto callbacksBefore	= state.callbacks ;	// 元初回host観測の実差分だけです
		auto	   scanned			= provider->scan( sessionId, options,
													 []( const ProviderProgress &) {}) ;	// 完全低位captureです
		const auto index = signed_index_candidate_binding_detail::Access::cachedSummaryForFixture(
			*provider) ;	// registry内の原一回だけを使い、resolverを再発行しません
		std::cout << "P4_SCAN case=" << state.id << " scanned=" << scanned.succeeded
				  << " cachedStatus=" << static_cast<unsigned>( index.status)
				  << " errorBits=" << static_cast<std::uint32_t>( index.error)
				  << " resolverCalls=" << index.resolverCalls
				  << " initialHostCalls=" << state.callbacks - callbacksBefore
				  << " adapter=" << (adapter != nullptr) << " lookup=" << static_cast<bool>( lookup)
				  << '\n' ;
		DRIVERCRATE_EXPECT( context, scanned.succeeded && index.status == expectedStatus) ;
		DRIVERCRATE_EXPECT( context, state.callbacks - callbacksBefore == 1U) ;
		auto result = provider->preparationPlan( sessionId, planId)
						  .value_or( OfficialPreparationPlan{sessionId,
															planId,
															DEFAULT_OFFICIAL_PREPARATION_LIMITS,
															{}}) ;	// 通常owner計画です
		IndexPreparationSummary summary ;							// 権限ではない元計画summaryです
		DRIVERCRATE_EXPECT( context, session.augmentPreparationPlan( result, services, summary,
																   scanned.candidates) == 0U) ;
		signed_index_candidate_binding_detail::Access::publishReferences( *provider, result,
																		 scanned) ;
		displayedCandidates = scanned.candidates ;
		return result ;
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief 元計画の一対象を明示承認し、通常取得と非実行検査の実結果を確認します
 * @param[in,out] context 共通の試験集計です
 * @param[in,out] run スキャンと完全な低位fakeを所有します
 * @param[in,out] preparation 同計画の元承認・取得状態です
 * @param[in] plan 通常スキャンが発行した元計画です
 * @param[in] target 元計画から選んだ一対象です
 * @param[in] operationId 取得操作に使う単調増加IDです
 * @param[in] expectedBytes 成功時に受け取る原byte数です。0は送信前拒否です
 * @param[in] scoped 機種別の取得成功時は元参照と同じ一端末の導入候補を検証します
 * @param[in] cancelPublication 機種別取得の監査完了後、候補反映直前だけで取消します
 */
//------------------------------------------------------------------------------
static void acquirePlatformConsumerTarget( TestContext &context, ServerP4Harness &run,
										  OfficialPreparationSession	  &preparation,
										  const OfficialPreparationPlan	  &plan,
										  const OfficialPreparationTarget &target,
										  const OperationId				   operationId,
										  const std::size_t expectedBytes, const bool scoped,
										  const bool cancelPublication = false)
{
	DRIVERCRATE_EXPECT( context, preparation.initialize( plan) == OfficialPreparationError::NONE) ;
	OfficialPreparationApproval approval{operationId,
										 plan.scanSessionId,
										 plan.planId,
										 plan.limits,
										 {}} ;	// 他の対象へ選択を流用しません
	// 一操作で選んだ一対象だけを承認します
	for( const auto &item : plan.targets) {
		approval.decisions.push_back( {item, item.identity == target.identity, false, false, false}) ;
	}

	const auto sendsBefore = run.state.sends ;	// この操作が発生させた送信だけを検査します
	const auto acquired	   = executeOfficialPreparation(
		   preparation, approval,
		   [&]( const OfficialPreparationTask &task, const PreparationCancellation &cancel) {
			   return run.session.acquireForInspection( preparation, task, run.services, cancel) ;
		   },
		   [] { return false ; }, []( const OfficialPreparationProgress &) {}) ;	// 通常取得入口です
	const auto summary = run.session.preparationSummary( operationId) ;				// 実取得・内容検査の結果です
	// 明示承認した取得対象に対応する元取得の個別結果
	const auto transfer =
		std::ranges::find( acquired.items, target.identity, &OfficialPreparationItem::identity) ;
	const bool		  allowed		= expectedBytes != 0U ;				// 期待する原配布物の明示byte数です
	const NativeError expectedError = allowed ? S_OK : E_ACCESSDENIED ;	// 元拒否HRESULTです
	DRIVERCRATE_EXPECT( context, acquired.approvalError == OfficialPreparationError::NONE &&
									acquired.controlError == 0U && summary.items.size() == 1U &&
									transfer != acquired.items.end()) ;
	// 期待した対象の終端を欠く試験を送信前拒否の成功に数えません
	if( summary.items.size() == 1U && transfer != acquired.items.end()) {
		const auto &item = summary.items.front() ;	// 元対象と共通検査の一致を確認します
		DRIVERCRATE_EXPECT(
			context, item.targetIdentity == target.identity &&
						 item.acquisitionError == expectedError && item.inputBound == allowed &&
						 item.acceptedInfCount == (allowed ? 1U : 0U) &&
						 transfer->result.state ==
							 (allowed ? OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION
									  : OfficialPreparationItemState::REJECTED) &&
						 transfer->result.error == expectedError &&
						 transfer->result.byteCount == expectedBytes) ;
	}

	// 取消し用の独立した操作では候補を反映せず、一回の監査で終了します
	if( allowed && scoped && cancelPublication) {
		const auto rankBeforeCancellation = run.native.rankCalls ;	// 候補監査の到達を確認します
		unsigned   cancellationCalls{} ;							// 複製routing反映の直前に受け取る照会数です
		const auto cancelled = run.provider->preparationAuditReports( acquired, [&] {
			++cancellationCalls ;
			return true ;
		}) ; // 同じ取得操作の保留候補だけを取り消します
		DRIVERCRATE_EXPECT( context, cancellationCalls == 1U && cancelled.empty() &&
										run.native.rankCalls > rankBeforeCancellation) ;
	}
	// 正規化後の型番と元HardwareIdsが同じ場合、一端末の候補だけを発行します
	else if( allowed && scoped) {
		const auto reports = run.provider->preparationAuditReports( acquired) ;	// 通常の候補監査です
		// 通常画面で同じ取得対象を指す表示候補の位置
		const auto reference = std::ranges::find( run.displayedCandidates, target.identity,
												 &UpdateCandidate::preparationTargetIdentity) ;
		DRIVERCRATE_EXPECT( context, reference != run.displayedCandidates.end() &&
										!reference->installable && reports.size() == 1U &&
										reports.front().publishedCandidates.size() == 1U) ;
		// 元参照がない場合や複数候補の場合に別端末を成功へ換算しません
		if( reference != run.displayedCandidates.end() && reports.size() == 1U &&
		   reports.front().publishedCandidates.size() == 1U) {
			const auto &candidate =
				// 元参照の実候補です
				reports.front().publishedCandidates.front() ;
			DRIVERCRATE_EXPECT(
				context,
				candidate.installable && candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
					candidate.deviceIdentity == reference->deviceIdentity &&
					candidate.preparationTargetIdentity == target.identity &&
					candidate.assessment && isCandidateAssessmentReady( *candidate.assessment)) ;
		}
	}

	DRIVERCRATE_EXPECT( context, run.state.sends - sendsBefore == (allowed ? 1U : 0U) &&
									run.native.stages == 0U && run.native.installs == 0U &&
									run.native.opens == run.native.closes) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 機種別の元署名行を端末別の承認から通常workerの登録・指定適用へ通します
 * @param[in,out] context 各操作の試験集計です
 * @param[in] store 本文と機種別追加欄を再認証する隔離ストアです
 * @param[in] nowUtc 両欄の有効時刻です
 * @param[in] baseZip 本文の人工配布物です
 * @param[in] scopedZip 機種別の人工配布物です
 * @param[in] cases 同じ署名索引で試す端末条件と変更時点です
 * @param[in] alternateId 公式の同じ群で適用を許す別の完全IDです。従来行では空です
 * @param[in] conflictingId 元IDとの併存で群が競合する別の完全IDです。従来行では空です
 * @note HTTP、復元、登録、指定適用は通常workerの完全な低位fakeで実行します
 */
//------------------------------------------------------------------------------
static void testPlatformDeviceInstallBoundaries(
	TestContext &context, const std::shared_ptr<SignedIndexStore> &store,
	const std::chrono::sys_seconds nowUtc, const std::string_view baseZip,
	const std::string_view scopedZip, const std::initializer_list<std::string_view> cases,
	const std::wstring_view alternateId = {}, const std::wstring_view conflictingId = {})
{
	constexpr std::wstring_view HARDWARE =
		L"PCI\\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF" ;		// 元Models位置0です
	const bool	 firmware = !conflictingId.empty() ;	// この索引では端末別の明示確認を求めます
	std::wstring conflictingIds{HARDWARE} ;				// 元IDと別群IDの両方を一台から返すMULTI_SZの内容です
	conflictingIds.push_back( L'\0') ;
	conflictingIds.append( conflictingId) ;
	const bool server = isWindowsServer() ;	// 試験機の種類に合わせて通常workerの復旧モードを選びます
	// 試験のOSに対応する、実際の導入操作が要求する復旧方式
	const auto protection = server ? InstallProtectionMode::SERVER_WITHOUT_RESTORE_POINT
								   : InstallProtectionMode::WINDOWS_RESTORE_POINT ;
	// 各操作で変える元観測と、到達を許す低位境界を独立して固定します
	for( const auto id : cases) {
		const bool baseline	  = id == "baseline" ;						// 同じ署名索引の本文を選びます
		const bool unreadable = id == "unreadable-before-preflight" ;	// 型番観測の欠測です
		// 導入前に端末観測が変化または失敗し、Providerへ進まない対照かを示します
		const bool preflightMachineFault = id == "type-before-preflight" || unreadable ;
		const bool beforeStage = id == "type-before-stage" ;	// 登録root読取後に型番を変えます
		const bool beforeApply = id == "type-before-apply" ;	// 登録が一回済んでから型番を変えます
		const bool groupBeforeStage =
			// 登録直前だけ別群を加えます
			id == "firmware-conflict-before-stage" ;
		const bool groupBeforeApply =
			// 指定適用直前だけ別群を加えます
			id == "firmware-conflict-before-apply" ;
		const bool expiresAtStage =
			// 登録直前の機器観測中に失効します
			id == "firmware-expires-during-stage-observation" ;
		const bool expiresAtApply =
			// 適用直前の機器観測中に失効します
			id == "firmware-expires-during-apply-observation" ;
		const bool alternate =
			// 指定適用直前に同群の別IDだけを残します
			id == "firmware-same-group-before-apply" ;
		const bool removed = id == "hardware-removed" ;	// 候補発行後のHardwareIdsで一致しません
		const bool moved =
			// 登録後はCompatibleIdsだけに元IDがあります
			id == "hardware-moved-after-stage" ;
		const auto body = baseline ? baseZip : scopedZip ;	// 選んだ元レコードに署名した別ZIPです
		auto	   state =
			std::make_shared<CatalogInstallFixture>() ;	// Worker停止まで低位状態を所有します
		state->originalHardwareId = baseline ? std::wstring_view{} : HARDWARE ;
		bool	 afterCandidate{} ;				// 終端イベント間だけで元観測を切り替えます
		unsigned installMachineReads{} ;		// 候補発行後に実際に観測された回数です
		unsigned changedMachineReads{} ;		// 指定境界で変更後の型番を返した回数です
		bool	 expiredDuringObservation{} ;	// 元機器の読取りを開始してから失効したことを保持します
		auto	 clock =
			std::make_shared<std::chrono::sys_seconds>( nowUtc) ;	// 失効と取り違えない一定時刻です
		auto services =
			// 同worker内の人工HTTPです
			makeServerP4PipelineServices( store, clock, {}, {}) ;
		services.hostPlatform = [] {
			return WindowsHostPlatformObservation{WindowsHostObservationState::OBSERVED,
												  WindowsHostPlatform{10U, 0U, 20348U, 9U, 3U, 0U},
												  WindowsHostErrorDomain::NTSTATUS,
												  WindowsHostObservationStage::VERSION, 0U} ;
		} ; // 元レコードに一致する固定のWindows Server 2022 x64です
		services.platformMachine = [&] {
			// 候補発行後も指定の低位境界を観測するまでは元の型番を返します
			if( afterCandidate) {
				++installMachineReads ;
				// 元機器・群は一致したまま、最後の観測途中で取得許可の上限へ進めます
				if( (expiresAtStage && state->registrationRootReads != 0U) ||
				   (expiresAtApply && activeNative && activeNative->stages != 0U)) {
					*clock					 = nowUtc + std::chrono::minutes{15} ;
					expiredDuringObservation = true ;
				}

				// 各境界で機種を読むまで通常の順位と端末属性を保ち、その後の群照合にだけ変更を渡します
				if( (groupBeforeStage && state->registrationRootReads != 0U) ||
				   ((groupBeforeApply || alternate) && activeNative &&
					activeNative->stages != 0U)) {
					state->hardwareIds =
						alternate ? alternateId : std::wstring_view{conflictingIds} ;
				}

				// 同じ許可表の別型番と、型番を取得できない場合を元観測へ返します
				if( preflightMachineFault || (beforeStage && state->registrationRootReads != 0U) ||
				   (beforeApply && activeNative && activeNative->stages != 0U) || baseline) {
					++changedMachineReads ;
					return parseIndexPlatformMachine( L"Lenovo", unreadable ? L"" : L"Z9Z2") ;
				}
			}

			return parseIndexPlatformMachine( L"Lenovo", L" z9z1cto1ww ") ;
		} ; // 機種観測と登録境界だけを同workerの同期中に読みます
		const auto start = [state, store, clock, body] {
			// 低位fakeが未初期化なら登録や実適用へ進めません
			if( !activeNative) {
				throw std::runtime_error( "platform install native fixture missing") ;
			}

			activeNative->catalogInstall		  = state.get() ;
			activeNative->p4ExplicitClientContext = true ;
			activeNative->multiple				  = true ;
			activeNative->noReboot				  = true ;
			static_cast<void>(
				makeServerP4PipelineServices( store, clock, body, [state] { ++state->sends ; })) ;
		} ; // 二端末と元の一配布物をworkerの寿命内で所有します
		auto bound = makeSignedIndexBindingWorker( std::move( services), body, false, false, false,
												  SignedIndexBindingNativeCase::NORMAL, {},
												  start) ;	// 低位変更はこの隔離fixtureに限定します
		OperationController controller ;					// 通常の明示選択と同意を管理します
		ScanOptions			options ;						// 人工Driver Storeと元署名索引の二経路だけです
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
									   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		const auto scan				= controller.beginScan() ;	// 各例の新しい元スキャンです
		DRIVERCRATE_EXPECT( context, bound.worker && scan.accepted &&
										bound.worker->requestScan( scan.operationId, options)) ;
		// 完全fakeを持たないworkerでは後続の操作を始めません
		if( !bound.worker) {
			continue ;
		}

		auto scanned = waitEvent( *bound.worker, WorkerEventKind::SCAN_COMPLETED,
								 scan.operationId) ;	// 元の取得計画を持つイベントです
		DRIVERCRATE_EXPECT(
			context, scanned && scanned->scanResult.succeeded && scanned->preparationPlan &&
						 scanned->preparationPlan->targets.size() == 1U && state->sends == 0U) ;
		// 一件の元対象を特定できない例を候補発行後の確認へ進めません
		if( !scanned || !scanned->preparationPlan ||
		   scanned->preparationPlan->targets.size() != 1U) {
			continue ;
		}

		const auto &plan	  = *scanned->preparationPlan ;	// 同じスキャンの元計画です
		const auto &target	  = plan.targets.front() ;		// 指定した元IDで照合した一台の対象です
		const auto	reference = std::ranges::find(
			 scanned->scanResult.candidates, target.identity,
			 &UpdateCandidate::preparationTargetIdentity) ;	// 内容検査前の同一対象です
		DRIVERCRATE_EXPECT(
			context,
			target.deviceCount == 1U && reference != scanned->scanResult.candidates.end() &&
				!reference->installable && target.firmwareCondition.has_value() == firmware &&
				target.requiresPrerequisiteConfirmation == firmware &&
				(!firmware ||
				 (target.firmwareCondition->deviceIdentity == reference->deviceIdentity &&
				  target.firmwareCondition->groupIndex == 0U &&
				  target.firmwareCondition->versionLabel == L"R1.2_rc-1")) &&
				target.eulaSourceSubject ==
					(baseline ? L"fixture-source (https://vendor.example/)"
							  : L"platform-scope-source (https://windows-server.lenovo.com/)") &&
				controller.completeScan( scan.operationId, scanned->scanResult) &&
				controller.setPreparationPlan( scan.operationId, plan)) ;
		OfficialPreparationApproval approval{
			0U,
			plan.scanSessionId,
			plan.planId,
			plan.limits,
			{{target, true, false, false,
			  firmware}}} ;	// この端末の表示済み条件を確認して取得を承認します
		const auto request =
			// 元スキャンの内容検査へ進みます
			controller.beginPreparation( approval) ;
		DRIVERCRATE_EXPECT( context, request.accepted && bound.worker->requestPreparation( approval)) ;
		auto prepared =
			waitEvent( *bound.worker, WorkerEventKind::PREPARATION_COMPLETED,
					  request.operationId) ;	// 元配布物の実取得・内容検査・候補発行の終端です
		DRIVERCRATE_EXPECT(
			context,
			prepared && prepared->indexPreparation.items.size() == 1U &&
				prepared->indexPreparation.items.front().inputBound &&
				prepared->indexPreparation.items.front().acceptedInfCount == 1U &&
				prepared->preparationResult.auditReports.size() == 1U &&
				prepared->preparationResult.auditReports.front().publishedCandidates.size() == 1U) ;
		// 実候補を得る前の失敗を導入拒否として扱いません
		if( !prepared || prepared->preparationResult.auditReports.size() != 1U ||
		   prepared->preparationResult.auditReports.front().publishedCandidates.size() != 1U ||
		   reference == scanned->scanResult.candidates.end()) {
			// 候補発行前に止まった理由を低位パスと元数値だけで表示します
			if( prepared) {
				// 元取得の終端に含まれる各結果を照合します
				for( const auto &item : prepared->indexPreparation.items) {
					std::cout << "PLATFORM_INSTALL_PREPARE case=" << id
							  << " acquisition=" << item.acquisitionError
							  << " input=" << item.inputBound << " content=" << item.contentError
							  << " accepted=" << item.acceptedInfCount << '\n' ;
				}

				// 取得と候補監査の元診断を別々に保持します
				for( const auto &report : prepared->preparationResult.auditReports) {
					std::cout << "PLATFORM_INSTALL_AUDIT case=" << id
							  << " content=" << report.contentError
							  << " pair=" << report.firstPairError
							  << " publish=" << report.publication.firstError
							  << " candidates=" << report.publishedCandidates.size() << '\n' ;
				}
			}

			continue ;
		}

		// 通常取得と検査を経て昇格した、元配布と同じ一候補
		const auto &candidate =
			prepared->preparationResult.auditReports.front().publishedCandidates.front() ;
		DRIVERCRATE_EXPECT(
			context,
			candidate.installable && candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
				candidate.preparationTargetIdentity == target.identity &&
				candidate.deviceIdentity == reference->deviceIdentity && candidate.assessment &&
				isCandidateAssessmentReady( *candidate.assessment) &&
				candidate.assessment->installMethod == CandidateInstallMethod::STANDARD_INF &&
				controller.completePreparation( prepared->preparationResult,
											   scanned->scanResult.candidates)) ;
		const auto before = bound.observe() ;	// 取得後も同意前は復元・登録・適用が0です
		DRIVERCRATE_EXPECT( context, state->sends == 1U && before.stages == 0U &&
										before.installs == 0U && before.restoreBegins == 0U &&
										state->registrationRootReads == 0U) ;
		afterCandidate					   = true ;
		state->observeRegistrationOnServer = server ;
		// 同一instanceの端末属性だけを変更します。登録後の場合は先に元IDで登録させます
		if( removed || moved) {
			state->hardwareIds		   = L"PCI\\VEN_FFFF&DEV_0001&SUBSYS_4444FFFF" ;
			state->compatibleId		   = moved ? HARDWARE : std::wstring_view{} ;
			state->changeIdsAfterStage = moved ;
		}

		const std::array selection{candidate.identity} ;	// 元候補一件だけへ明示導入します
		// 実コントローラーで明示同意を適用して得た導入操作の開始結果
		const auto		 operation =
			controller.beginInstall( plan.scanSessionId, selection, InstallConfirmation::CONFIRMED) ;
		DRIVERCRATE_EXPECT( context, operation.accepted &&
										bound.worker->requestInstall( operation.operationId,
																	 plan.scanSessionId, selection,
																	 nullptr, protection)) ;
		auto	   installed = waitEvent( *bound.worker, WorkerEventKind::INSTALL_COMPLETED,
										 operation.operationId) ;	// 元の個別結果と選択保持の終端です
		const auto observed	 = bound.observe() ;					// 登録・指定適用を独立に計数します
		// Provider実行前に端末条件が崩れる対照の期待値
		const bool preflightFailure = preflightMachineFault || removed ;
		const bool success			= id == "stable" || id == "firmware-stable" || alternate ||
							 baseline ;	// 適用を許す試験条件です
		// クライアントで事前照合が成立した場合だけ期待する復元準備回数
		const unsigned restores = server || preflightFailure ? 0U : 1U ;
		const auto stages = (success || beforeApply || moved || groupBeforeApply || expiresAtApply)
								? 1U
								: 0U ;	// 登録に到達する回数です
		DRIVERCRATE_EXPECT(
			context,
			observed.restoreBegins == restores && observed.restoreCompletes == restores &&
				observed.stages == stages && observed.installs == (success ? 1U : 0U) &&
				observed.deviceInstalls[0] == observed.installs &&
				observed.deviceInstalls[1] == 0U && observed.specifiedBindingMatches &&
				state->sends == 1U && (state->registrationRootReads != 0U) == !preflightFailure &&
				(state->changedHardwareReads != 0U) ==
					(removed || moved || groupBeforeStage || groupBeforeApply || alternate) &&
				(state->changedCompatibleReads != 0U) == moved &&
				expiredDuringObservation == (expiresAtStage || expiresAtApply) &&
				(installMachineReads != 0U) == (!baseline && !removed) &&
				(changedMachineReads != 0U) ==
					(preflightMachineFault || beforeStage || beforeApply)) ;
		DRIVERCRATE_EXPECT( context,
						   installed && installed->installResult.updates.size() == 1U &&
							   installed->installRetention &&
							   installed->installRetention->providerEntered == !preflightFailure) ;
		// 元個別結果と集計が同じ作用境界に元HRESULTを保持することを確認します
		if( installed && installed->installResult.updates.size() == 1U) {
			const auto		 &result = installed->installResult ;	// 操作全体の結果です
			const auto		 &update = result.updates.front() ;		// 実際に選んだ一台の結果です
			// 現在の対象又は群が元承認から変わればWindowsの再確認を求めます
			const NativeError error = expiredDuringObservation ? HRESULT_FROM_WIN32( ERROR_TIMEOUT)
									  : (removed || moved || groupBeforeStage || groupBeforeApply)
										  ? HRESULT_FROM_WIN32( ERROR_RETRY)
									  : success ? S_OK
												: E_ACCESSDENIED ;
			DRIVERCRATE_EXPECT(
				context, result.succeeded == success && !result.rebootRequired &&
							 update.identity == candidate.identity &&
							 result.downloadError == (preflightFailure ? error : S_OK) &&
							 result.installError == (preflightFailure ? S_OK : error) &&
							 update.downloadError == result.downloadError &&
							 update.installError == result.installError &&
							 update.downloadOutcome ==
								 (preflightFailure ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS) &&
							 update.installOutcome == (preflightFailure ? OutcomeCode::NOT_STARTED
													   : success		? OutcomeCode::SUCCESS
																		: OutcomeCode::FAILURE) &&
							 controller.completeInstall( operation.operationId, result,
														installed->installRetention
															? &*installed->installRetention
															: nullptr)) ;
			std::cout << "PLATFORM_INSTALL case=" << id << " downloadError=" << result.downloadError
					  << " installError=" << result.installError
					  << " machine=" << installMachineReads << " changed=" << changedMachineReads
					  << " root=" << state->registrationRootReads << " stage=" << observed.stages
					  << " device1=" << observed.deviceInstalls[0]
					  << " device2=" << observed.deviceInstalls[1] << '\n' ;
		}

		bound.worker->stop() ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 機種別レコードを同じ端末の通常スキャンと取得計画へ渡します
 * @param[in,out] context 共通の試験集計です
 * @param[in] store 本文と機種別追加欄を再認証する隔離ストアです
 * @param[in] unrecognizedStore 別の配布元が同じ型番を示す対照ストアです
 * @param[in] nowUtc 両欄の有効時刻です
 * @param[in] expiry 機種別追加欄の元期限です
 * @param[in] baseZip 本文の元レコードが参照する人工ZIPです
 * @param[in] scopedZip 機種別追加欄の元レコードが参照する別の人工ZIPです
 */
//------------------------------------------------------------------------------
void runPlatformDeviceConsumerScan( TestContext &context, std::shared_ptr<SignedIndexStore> store,
								   std::shared_ptr<SignedIndexStore> unrecognizedStore,
								   const std::chrono::sys_seconds	 nowUtc,
								   const std::chrono::sys_seconds	 expiry,
								   const std::string_view baseZip, const std::string_view scopedZip)
{
	using State	 = IndexRecordMatchState ;
	using Reason = IndexRecordMatchReason ;
	using Vendor = IndexPlatformMachineVendor ;
	constexpr WindowsHostPlatform HOST{10U, 0U, 20348U, 9U, 3U, 0U} ;	// Windows Server 2022 x64です
	constexpr ScanSessionId		  SESSION	  = 853390U ;				// 各スキャン所有者の固定試験sessionです
	constexpr OperationId		  ACQUISITION = 853391U ;				// 元計画から一対象を取得する操作です
	constexpr std::wstring_view	  FIRST =
		L"PCI\\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF" ;	// 元Models位置0です
	constexpr std::wstring_view LAST =
		L"PCI\\VEN_FFFF&DEV_0001&SUBSYS_2222FFFF&REV_01" ;	// 元Models位置3です
	constexpr std::wstring_view OTHER =
		L"PCI\\VEN_FFFF&DEV_0001&SUBSYS_4444FFFF" ;					// 元Modelsにある対象外IDです
	constexpr std::wstring_view BASELINE = L"TESTBUS\\SYNTH_0001" ;	// 本文専用のIDです
	/** @brief 元スキャンで認められた機種別取得を評価する時点です */
	enum class TransferCase {
		NONE,				///< 取得を開始せず元計画だけを確認します
		STABLE,				///< 許可された型番を同じ正規化表記で再確認します
		CANCEL_PUBLICATION,	///< 適用性の監査後、候補の反映直前に取り消します
		TYPE_CHANGED,		///< 計画後に許可表内の別型番へ変わります
		UNAVAILABLE,		///< 計画後に型番が不明になります
		LATE_CHANGE,		///< grant後に許可表内の別型番へ変わります
		BASELINE,			///< 機種別拒否後に元本文を同じ計画から取得します
	} ;
	/** @brief 端末観測と追加レコードの独立した期待を持つ一例です */
	struct Case {
		std::string_view		   id ;								///< 診断用の人工入力名です
		std::wstring_view		   manufacturer ;					///< 端末の製造元応答です
		std::wstring_view		   product ;						///< 端末の型番応答です
		std::wstring_view		   hardware ;						///< 第2端末のHardwareIdsです
		std::optional<std::size_t> matchedIndex ;					///< 正常時だけ期待する対象IDの元位置です
		std::optional<Reason>	   machineRejection ;				///< 個別IDへ進めないときの元理由です
		TransferCase			   transfer{TransferCase::NONE} ;	///< 元計画後の取得動作です
	} ;
	// 採用・不一致・未判定を既知の元観測ごとに固定します
	const std::array<Case, 13U> cases{{
		{"first-hardware", L"Lenovo", L"z9z1", FIRST, 0U, std::nullopt, TransferCase::STABLE},
		{"cancel-publication", L"Lenovo", L"z9z1", FIRST, 0U, std::nullopt,
		 TransferCase::CANCEL_PUBLICATION},
		{"last-hardware", L"Lenovo", L"Z9Z2CTO1WW", LAST, 3U, std::nullopt},
		{"outside-scope", L"Lenovo", L"Z9Z1", OTHER, std::nullopt, std::nullopt},
		{"compatible-only", L"Lenovo", L"Z9Z1", OTHER, std::nullopt, std::nullopt},
		{"wrong-type", L"Lenovo", L"Z9Z3", FIRST, std::nullopt, Reason::PLATFORM_MACHINE_MISMATCH},
		{"wrong-vendor", L"Synthetic Manufacturer", L"Z9Z1", FIRST, std::nullopt,
		 Reason::PLATFORM_MACHINE_MISMATCH},
		{"unknown-type", L"Lenovo", L"Z9Z1 suffix", FIRST, std::nullopt,
		 Reason::PLATFORM_MACHINE_UNAVAILABLE},
		{"unrecognized-authority", L"Lenovo", L"Z9Z1", FIRST, std::nullopt,
		 Reason::PLATFORM_MACHINE_UNAVAILABLE},
		{"changed-type-after-plan", L"Lenovo", L"Z9Z1", FIRST, 0U, std::nullopt,
		 TransferCase::TYPE_CHANGED},
		{"type-unavailable-after-plan", L"Lenovo", L"Z9Z1", FIRST, 0U, std::nullopt,
		 TransferCase::UNAVAILABLE},
		{"changed-type-before-dispatch", L"Lenovo", L"Z9Z1", FIRST, 0U, std::nullopt,
		 TransferCase::LATE_CHANGE},
		{"baseline-after-scoped-rejection", L"Lenovo", L"Z9Z1", FIRST, 0U, std::nullopt,
		 TransferCase::BASELINE},
	}} ;
	// 各例を独立した同スキャン所有者に通し、別例のprivate証拠を流用しません
	for( const auto &fixture : cases) {
		const bool unrecognized =
			// 似た文字列の別配布元です
			fixture.id == "unrecognized-authority" ;
		unsigned		machineCalls{} ;			// 端末機種情報を要求した回数です
		unsigned		transports{} ;				// grant成立後に低位HTTP生成へ到達した回数です
		auto			product = fixture.product ;	// 取得時の観測を制御する人工型番です
		const auto		body	= fixture.transfer == TransferCase::BASELINE
									  ? baseZip
									  : scopedZip ;	// 選択を許可する原ZIPです
		ServerP4Harness run{unrecognized ? unrecognizedStore : store, nowUtc, body, fixture.id,
							HOST} ;	// 通常の端末列挙を完全な低位fakeで実行します
		run.services.platformMachine = [&] {
			++machineCalls ;
			return parseIndexPlatformMachine( fixture.manufacturer, product) ;
		} ;
		// 本文の端末と機種別の端末は同じスキャンに含め、互いのIDを借りません
		for( const auto hardware : {BASELINE, fixture.hardware}) {
			run.native.distributionDevices.push_back(
				{std::wstring{hardware}, L"fixture.inf", L"Models.NTamd64", L"1.0.0.0",
				 L"{4d36e978-e325-11ce-bfc1-08002be10318}", L"Ports"}) ;
		}

		// 同じ対象IDを端末のCompatibleIdsだけへ載せ、種別の誤使用を検出します
		if( fixture.id == "compatible-only") {
			run.native.opaqueCompatibleId = FIRST ;
		}

		const auto status = fixture.machineRejection == Reason::PLATFORM_MACHINE_UNAVAILABLE
								? IndexScanStatus::PARTIAL
								: IndexScanStatus::COMPLETED ;		// 不明と確定不一致を区別します
		const auto plan = run.plan( context, SESSION, 1U, status) ;	// 元端末関係から得た通常計画です
		const std::size_t expectedTargets =
			fixture.matchedIndex ? 2U : 1U ;	// 本文だけは全例で成立します
		const auto scan = signed_index_candidate_binding_detail::Access::cachedSummaryForFixture(
			*run.provider) ;	// 端末へ実際に問い合わせた件数と元Modelsの分母です
		DRIVERCRATE_EXPECT( context,
						   scan.totalRecords == 2U && scan.processedRecords == 2U &&
							   scan.totalPublicIds == 5U && scan.processedPublicIds == 5U &&
							   scan.resolverCalls == (fixture.machineRejection ? 1U : 3U) &&
							   scan.matchedRelations == (fixture.matchedIndex ? 2U : 1U) &&
							   machineCalls == (unrecognized ? 0U : 1U) && scan.error == 0U) ;
		DRIVERCRATE_EXPECT( context, plan.targets.size() == expectedTargets && run.lookup &&
										run.state.sends == 0U && run.native.stages == 0U &&
										run.native.installs == 0U) ;
		// スキャンの元lookupと本文対象が成立した例だけで原領域と証拠を検査します
		if( !run.lookup || plan.targets.size() != expectedTargets) {
			continue ;
		}

		const auto &snapshot = run.lookup->snapshot() ;		// スキャンが再認証した原保存値です
		const auto	records	 = snapshot.consumerRecords() ;	// 本文と機種別の追加行です
		DRIVERCRATE_EXPECT( context, records.size() == 2U && records[1U].platformDeviceScope &&
										records[1U].publishedIdentityEvidence.pnpIds.size() == 4U &&
										records[1U].platformDeviceScope->machineVendor ==
											(unrecognized ? Vendor::UNKNOWN : Vendor::LENOVO) &&
										snapshot.consumerRecordRegion( 1U).expiresAtUtc == expiry) ;
		// 署名領域の前提が壊れた場合に別レコードで取得を試みません
		if( records.size() != 2U) {
			continue ;
		}

		std::wstring baselineHash ;	// 本文の原レコードを取得計画と照合するdigestです
		std::wstring scopedHash ;	// 機種別の元レコードを取得計画と照合するdigestです
		DRIVERCRATE_EXPECT( context,
						   records[0U].recordId == "platform-baseline" &&
							   computeBytesSha256( records[0U].originalBytes, baselineHash) == 0U &&
							   computeBytesSha256( records[1U].originalBytes, scopedHash) == 0U &&
							   baselineHash != scopedHash) ;
		// 元の通常配布を識別するハッシュに対応する計画上の取得対象
		const auto baselineTarget = std::ranges::find( plan.targets, baselineHash,
													  &OfficialPreparationTarget::releaseIdentity) ;
		// 公式Models配布を通常配布と区別する計画上の取得対象
		const auto scopedTarget = std::ranges::find( plan.targets, scopedHash,
													&OfficialPreparationTarget::releaseIdentity) ;
		DRIVERCRATE_EXPECT(
			context, baselineTarget != plan.targets.end() && baselineTarget->deviceCount == 1U &&
						 (scopedTarget != plan.targets.end()) == fixture.matchedIndex.has_value()) ;
		const auto relations = run.lookup->relations() ;	// 既native resolverだけが発行した関係です
		// 本文とは別の機種条件付き元行の結果を確認します
		const auto scoped = std::ranges::find( relations, 1U, &IndexRecordRelation::recordIndex) ;
		// 機種が不明又は不一致ならID位置や端末証拠のないレコード単位の結果です
		if( fixture.machineRejection) {
			// 型番の不明を確認済みの不一致として扱いません
			const auto state = *fixture.machineRejection == Reason::PLATFORM_MACHINE_UNAVAILABLE
								   ? State::UNDETERMINED
								   : State::UNMATCHED ;
			DRIVERCRATE_EXPECT( context, scoped != relations.end() &&
											scoped->reason == *fixture.machineRejection &&
											scoped->state == state && !scoped->publicIdIndex &&
											!scoped->deviceIdentity && !scoped->deviceProof) ;
		}
		// 対象のHardwareIdsが一意に一致した例では原位置と私有端末証拠を保持します
		else if( fixture.matchedIndex) {
			DRIVERCRATE_EXPECT( context, scoped != relations.end() &&
											scoped->state == State::MATCHED &&
											scoped->publicIdIndex == fixture.matchedIndex &&
											scoped->deviceIdentity && scoped->deviceProof &&
											scoped->context.scanSessionId == SESSION &&
											scoped->context.operationId == SESSION + 100U) ;
			DRIVERCRATE_EXPECT(
				context,
				scopedTarget != plan.targets.end() && scopedTarget->deviceCount == 1U &&
					std::ranges::any_of( run.displayedCandidates, [&]( const auto &candidate) {
						return !candidate.installable &&
							   candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
							   candidate.preparationTargetIdentity == scopedTarget->identity ;
					})) ;
			// 元recordと端末を参照できる場合だけHardwareIds専用の私有証拠を再照合します
			if( scoped != relations.end() && scoped->deviceProof && scoped->deviceIdentity &&
			   *fixture.matchedIndex < records[1U].publishedIdentityEvidence.pnpIds.size()) {
				const auto &evidence =
					records[1U].publishedIdentityEvidence ;	// 対象付きv4の元Modelsです
				const auto &id =
					evidence.pnpIds[*fixture.matchedIndex] ;	// 対象位置の原Hardware IDです
				const auto *machine =
					// 同じ列挙に結合した観測です
					snapshot.platformMachine( scoped->context) ;
				auto otherInventory = scoped->context ;	// 別の端末列挙から原観測を再利用できません
				++otherInventory.inventoryGeneration ;
				DRIVERCRATE_EXPECT( context,
								   machine != nullptr && machine->vendor == Vendor::LENOVO &&
									   machine->machineType ==
										   (*fixture.matchedIndex == 0U ? "Z9Z1" : "Z9Z2") &&
									   snapshot.platformMachine( otherInventory) == nullptr) ;
				DRIVERCRATE_EXPECT( context,
								   scoped->deviceProof->matches(
									   scoped->context, id.kind, id.value, evidence.classGuid,
									   GetCurrentThreadId(), scoped->relatedDevices, scoped->error,
									   scoped->resolutionCompleted, *scoped->deviceIdentity, true)) ;
			}
		}
		// 完了した不一致IDは既存の件数へ集約し、取得可能な関係として保持しません
		else {
			DRIVERCRATE_EXPECT( context,
							   scoped == relations.end() && scan.definitiveNoRelationIds == 4U) ;
		}

		// 計画だけの入力、または正しい元対象を欠く入力では操作を作りません
		if( fixture.transfer == TransferCase::NONE || baselineTarget == plan.targets.end() ||
		   scopedTarget == plan.targets.end()) {
			continue ;
		}

		const bool cancelPublication =
			fixture.transfer ==
			TransferCase::CANCEL_PUBLICATION ;	// 元の権限を維持して発行前だけ停止します
		const bool stable = fixture.transfer == TransferCase::STABLE ||
							cancelPublication ;								// 生の表示値だけは変えます
		const bool late = fixture.transfer == TransferCase::LATE_CHANGE ;	// grantと送信を分離します
		// grant成立後に初めてtransportを作る負例だけは、ここでは型番を変えません
		if( !late) {
			product = stable										  ? L" z9z1cto1ww "
					  : fixture.transfer == TransferCase::UNAVAILABLE ? L""
																	  : L"Z9Z2" ;
		}

		run.services.httpTransport = [&product, &transports, late,
									  transport = run.services.httpTransport] {
			++transports ;
			// grant取得後・送信直前に同じ許可表の別型番へ変えます
			if( late) {
				product = L"Z9Z2" ;
			}

			return transport() ;
		} ;
		OfficialPreparationSession preparation ;	// 両対象の元計画へ同じ承認状態を保持します
		acquirePlatformConsumerTarget( context, run, preparation, plan, *scopedTarget, ACQUISITION,
									  stable ? scopedZip.size() : 0U, true, cancelPublication) ;
		DRIVERCRATE_EXPECT( context, transports == (stable || late ? 1U : 0U) &&
										machineCalls >= (stable || late ? 3U : 2U)) ;
		// 拒否した機種別対象を選ばず、同じscanで元本文の別対象が取得できることを確認します
		if( fixture.transfer == TransferCase::BASELINE) {
			auto next = plan ;	// 同じscanから残した本文だけを新準備計画にします
			++next.planId ;
			next.targets = {*baselineTarget} ;
			DRIVERCRATE_EXPECT( context, run.session.retainPreparationPlan( next, run.services) &&
											next.targets.size() == 1U) ;
			const auto previousCalls = machineCalls ;	// 機種条件を持たない本文には再観測不要です
			acquirePlatformConsumerTarget( context, run, preparation, next, *baselineTarget,
										  ACQUISITION + 1U, baseZip.size(), false) ;
			DRIVERCRATE_EXPECT( context, transports == 1U && machineCalls == previousCalls) ;
		}
	}

	ServerP4Harness afterExpiry{store, expiry, baseZip, "platform-expired-at-scan",
								HOST} ;		// 期限ちょうどの新スキャンです
	unsigned		expiredMachineCalls{} ;	// 期限切れの機種条件で余分な観測を要求しません
	afterExpiry.services.platformMachine = [&] {
		++expiredMachineCalls ;
		return parseIndexPlatformMachine( L"Lenovo", L"Z9Z1") ;
	} ;
	const auto plan = afterExpiry.plan( context, SESSION) ;	// 追加欄期限ちょうどの通常スキャンです
	const auto scan = signed_index_candidate_binding_detail::Access::cachedSummaryForFixture(
		*afterExpiry.provider) ;	// 本文だけが照合され、その取得対象を残します
	DRIVERCRATE_EXPECT( context, scan.supplementStatus == IndexAssetSupplementStatus::EXPIRED &&
									scan.totalRecords == 1U && scan.totalPublicIds == 1U &&
									scan.resolverCalls == 1U && plan.targets.size() == 1U &&
									expiredMachineCalls == 0U && afterExpiry.state.sends == 0U) ;
	testPlatformDeviceInstallBoundaries(
		context, store, nowUtc, baseZip, scopedZip,
		{"stable", "type-before-preflight", "unreadable-before-preflight", "type-before-stage",
		 "type-before-apply", "hardware-removed", "hardware-moved-after-stage", "baseline"}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 別々に承認した二台を一回の取得と端末ごとの独立した内容検査へ結びます
 * @param[in,out] context 元操作の結果を集計します
 * @param[in] store 同じ配布物を二群に指定した試験索引です
 * @param[in] nowUtc 元署名と配布物が有効な時刻です
 * @param[in] zip 取得元に結合した人工配布物です
 * @param[in] host 配布条件に合う試験用Windowsです
 * @param[in] firstGroupId 第一群に一意に該当する完全IDです
 * @param[in] secondGroupId 第二群に一意に該当する完全IDです
 */
//------------------------------------------------------------------------------
static void testPlatformFirmwareRetainedInspection( TestContext							   &context,
												   const std::shared_ptr<SignedIndexStore> &store,
												   const std::chrono::sys_seconds			nowUtc,
												   const std::string_view					zip,
												   const WindowsHostPlatform				host,
												   const std::wstring_view firstGroupId,
												   const std::wstring_view secondGroupId)
{
	constexpr ScanSessionId SESSION = 853536U ;	// 各試験の元スキャンです
	constexpr NativeError	RETRY	= static_cast<NativeError>(
		// 端末条件変更に対する元の拒否です
		HRESULT_FROM_WIN32( ERROR_RETRY)) ;
	// 一台分の承認から同じ端末の指定導入候補だけが発行されたかを照合します
	const auto publishesTo = []( const std::vector<OfficialPreparationAuditReport> &reports,
								const OfficialPreparationTarget					  &target) {
		// 候補の重複や元の承認が異なる監査を、一件の成功として扱いません
		if( reports.size() != 1U || reports.front().targetIdentity != target.identity ||
		   reports.front().publishedCandidates.size() != 1U || !target.firmwareCondition) {
			return false ;
		}

		const auto &candidate = reports.front().publishedCandidates.front() ;	// 元承認の一件です
		return candidate.installable && candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
			   candidate.preparationTargetIdentity == target.identity &&
			   candidate.deviceIdentity == target.firmwareCondition->deviceIdentity &&
			   candidate.assessment && isCandidateAssessmentReady( *candidate.assessment) ;
	} ;
	// 独立した元スキャンでBの安定時と別群追加時を比較します
	for( const bool groupConflict : {false, true}) {
		ServerP4Harness run{
			store,
			nowUtc,
			zip,
			groupConflict ? "platform-firmware-retained-conflict" : "platform-firmware-retained-stable",
			host,
			2U} ;	// 一回の取得と二台分の独立検査を許す署名試験です
		run.services.platformMachine = [] { return parseIndexPlatformMachine( L"Lenovo", L"Z9Z1") ; } ;
		// Bを第二端末に固定し、元IDを残したまま別群のIDを追加できるようにします
		for( const auto hardware : {secondGroupId, firstGroupId}) {
			run.native.distributionDevices.push_back(
				{std::wstring{hardware}, L"fixture.inf", L"Models.NTamd64", L"1.0.0.0",
				 L"{4d36e978-e325-11ce-bfc1-08002be10318}", L"Ports"}) ;
		}

		const auto plan	  = run.plan( context, SESSION) ;	// 通常スキャンが作った元計画です
		const auto first  = std::ranges::find_if( plan.targets, []( const auto &target) {
			 return target.firmwareCondition && target.firmwareCondition->groupIndex == 1U ;
		 }) ; // 最初に取得するAです
		const auto second = std::ranges::find_if( plan.targets, []( const auto &target) {
			return target.firmwareCondition && target.firmwareCondition->groupIndex == 0U ;
		}) ; // 次に独立承認するBです
		DRIVERCRATE_EXPECT( context, plan.targets.size() == 2U && first != plan.targets.end() &&
										second != plan.targets.end() && run.state.sends == 0U) ;
		// 元確認対象が欠けたときは別端末で試験を続けません
		if( first == plan.targets.end() || second == plan.targets.end()) {
			continue ;
		}

		DRIVERCRATE_EXPECT( context, first->releaseIdentity == second->releaseIdentity &&
										first->identity != second->identity &&
										first->firmwareCondition->deviceIdentity !=
											second->firmwareCondition->deviceIdentity) ;
		OfficialPreparationSession preparation ;	// 同スキャン内で実承認と元予算を管理します
		const auto				   execute = [&]( const OfficialPreparationPlan	 &activePlan,
								 const OfficialPreparationTarget &selected,
								 const OperationId				  operation) {
			DRIVERCRATE_EXPECT( context, preparation.initialize( activePlan) ==
															OfficialPreparationError::NONE) ;
			// 明示確認を元スキャンとこの操作へ結びます
			OfficialPreparationApproval approval{
				operation, SESSION, activePlan.planId, activePlan.limits, {}} ;
			// 選択した一台の元条件にだけ明示確認を付けます
			for( const auto &target : activePlan.targets) {
				const bool accepted =
					// 選んだ元端末にだけ確認を付けます
					target.identity == selected.identity ;
				approval.decisions.push_back( {target, accepted, false, false, accepted}) ;
			}

			return executeOfficialPreparation(
				preparation, approval,
				[&]( const OfficialPreparationTask &task, const PreparationCancellation &cancel) {
					return run.session.acquireForInspection( preparation, task, run.services,
																			cancel) ;
				},
				[] { return false ; }, []( const OfficialPreparationProgress &) {}) ;
		} ;
		const auto acquired = execute( plan, *first, SESSION + 1U) ;	// Aが承認した実行結果です
		const auto summary =
			// Aの取得と独立内容検査です
			run.session.preparationSummary( acquired.operationId) ;
		const auto transfer =
			std::ranges::find( acquired.items, first->identity,
							  &OfficialPreparationItem::identity) ;	// Aの取得終端を借用します
		DRIVERCRATE_EXPECT(
			context,
			acquired.approvalError == OfficialPreparationError::NONE &&
				acquired.controlError == 0U && transfer != acquired.items.end() &&
				transfer->result.state == OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
				transfer->result.error == 0U && transfer->result.byteCount == zip.size() &&
				!transfer->result.localInspection && summary.items.size() == 1U &&
				summary.items.front().targetIdentity == first->identity &&
				!summary.items.front().reusedOwnedBody && summary.items.front().inputBound &&
				summary.items.front().content ==
					IndexedDriverInspectionState::INSPECTION_COMPLETED &&
				summary.items.front().contentError == 0U &&
				summary.items.front().acceptedInfCount == 1U && run.state.sends == 1U &&
				run.signatures->receipt().inspectionRoots == 1U) ;
		const auto transferReports =
			// Aの取得後の候補発行を確認します
			run.provider->preparationAuditReports( acquired) ;
		DRIVERCRATE_EXPECT( context, publishesTo( transferReports, *first)) ;

		auto next = plan ;	// Bは新計画で別の明示確認を受けます
		++next.planId ;
		next.targets = {*second} ;
		const bool retained =
			// 未選択だったBを維持します
			run.session.retainPreparationPlan( next, run.services) ;
		DRIVERCRATE_EXPECT( context, retained && next.targets.size() == 1U) ;
		// 原計画から維持できたBだけを新しく承認します
		if( !retained || next.targets.size() != 1U) {
			continue ;
		}

		// 新計画の発行後にだけ元Bと競合するIDを追加します
		if( groupConflict) {
			run.native.additionalSecondDeviceHardwareId = secondGroupId ;
		}

		const auto local =
			// Bの独立した承認結果です
			execute( next, next.targets.front(), SESSION + 2U) ;
		const auto localSummary =
			// Bの再利用と検査結果を確認します
			run.session.preparationSummary( local.operationId) ;
		DRIVERCRATE_EXPECT( context, local.approvalError == OfficialPreparationError::NONE &&
										local.controlError == 0U && local.items.size() == 1U &&
										localSummary.items.size() == 1U && run.state.sends == 1U &&
										run.native.stages == 0U && run.native.installs == 0U) ;
		// Bの実終端と内容結果の両方がある場合だけ、再利用の成否を照合します
		if( local.items.size() != 1U || localSummary.items.size() != 1U) {
			continue ;
		}

		const auto &result = local.items.front().result ;	// 準備操作で確定したBの終端です
		const auto &item   = localSummary.items.front() ;	// 取得と内容を分けたBの診断です
		DRIVERCRATE_EXPECT( context, local.items.front().identity == second->identity &&
										item.targetIdentity == second->identity &&
										result.byteCount == 0U) ;
		// Bの競合はLOCAL claimと独立署名検査へ進みません
		if( groupConflict) {
			DRIVERCRATE_EXPECT( context, result.state == OfficialPreparationItemState::REJECTED &&
											result.error == RETRY && !result.localInspection &&
											item.acquisitionError == RETRY &&
											!item.reusedOwnedBody && !item.inputBound &&
											item.acceptedInfCount == 0U &&
											run.signatures->receipt().inspectionRoots == 1U) ;
		} else {
			DRIVERCRATE_EXPECT(
				context, result.state == OfficialPreparationItemState::LOCAL_INSPECTION_COMPLETED &&
							 result.error == 0U && result.localInspection && item.reusedOwnedBody &&
							 item.inputBound &&
							 item.content == IndexedDriverInspectionState::INSPECTION_COMPLETED &&
							 item.contentError == 0U && item.acceptedInfCount == 1U &&
							 run.signatures->receipt().inspectionRoots == 2U) ;
		}

		const auto localReports =
			// B自身の確認が成立した場合だけ、その端末の導入候補を発行します
			run.provider->preparationAuditReports( local) ;
		DRIVERCRATE_EXPECT( context, groupConflict ? localReports.empty()
												  : publishesTo( localReports, *second)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 通常スキャンの端末別確認と、現在のファームウェア群に応じた取得・保留を検証します
 * @param[in,out] context 元スキャンの確認結果を集計します
 * @param[in] store RAM内の試験鍵で確定した本文と機器別追加行です
 * @param[in] nowUtc 両領域が有効な試験時刻です
 * @param[in] baseZip 同じ索引の従来行が参照する試験ZIPです
 * @param[in] scopedZip ファームウェア条件がある元レコードに結合した試験ZIPです
 * @note 端末と通信を試験用の応答へ置き換えます
 */
//------------------------------------------------------------------------------
void runPlatformFirmwareConsumerHold( TestContext &context, std::shared_ptr<SignedIndexStore> store,
									 const std::chrono::sys_seconds nowUtc,
									 const std::string_view			baseZip,
									 const std::string_view			scopedZip)
{
	using Match = IndexPlatformFirmwareMatchState ;
	constexpr WindowsHostPlatform HOST{10U, 0U, 20348U, 9U, 3U, 0U} ;						// 配布条件のServerです
	constexpr ScanSessionId		  SESSION  = 853532U ;										// 各独立workerの操作文脈です
	constexpr std::wstring_view	  BASELINE = L"TESTBUS\\SYNTH_0001" ;						// 従来行の対照です
	constexpr std::wstring_view	  PRIMARY  = L"PCI\\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF" ;	// 第1群です
	constexpr std::wstring_view	  SAME_GROUP =
		L"pci\\ven_ffff&dev_0001&subsys_2222ffff&rev_01" ;	// 同じ群にある別の完全IDです
	constexpr std::wstring_view OTHER_GROUP =
		L"PCI\\VEN_FFFF&DEV_0001&SUBSYS_4444FFFF" ;			// 同一版の別群にある完全IDです
	constexpr std::wstring_view VERSION = L"R1.2_rc-1" ;	// 人工署名行の二群が要求する元の表記です
	// スキャン後の群競合で新たな確認を求める元エラーです
	constexpr NativeError		FIRMWARE_GROUP_CHANGED =
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY)) ;
	constexpr NativeError AMBIGUOUS_GROUP =
		// 群競合の元エラーです
		static_cast<NativeError>( E_ACCESSDENIED) ;
	// 同じ原レコードを、端末内二群と端末間で独立した二群の両方に照合します
	for( const bool ambiguous : {false, true}) {
		ServerP4Harness run{store, nowUtc, baseZip,
							ambiguous ? "platform-firmware-conflict" : "platform-firmware-unique",
							HOST} ;	// 例ごとに同じ署名索引を読む独立workerです
		run.services.platformMachine = [] { return parseIndexPlatformMachine( L"Lenovo", L"Z9Z1") ; } ;
		run.native.additionalSecondDeviceHardwareId = ambiguous ? OTHER_GROUP : SAME_GROUP ;
		// 本文と機種別の端末を同じスキャンへ含めます
		for( const auto hardware : {BASELINE, PRIMARY}) {
			run.native.distributionDevices.push_back(
				{std::wstring{hardware}, L"fixture.inf", L"Models.NTamd64", L"1.0.0.0",
				 L"{4d36e978-e325-11ce-bfc1-08002be10318}", L"Ports"}) ;
		}

		// 別群IDは選択端末の互換属性と別端末のHardwareIdsへそれぞれ載せます
		if( !ambiguous) {
			run.native.opaqueCompatibleId = OTHER_GROUP ;
			run.native.distributionDevices.push_back(
				{std::wstring{OTHER_GROUP}, L"fixture.inf", L"Models.NTamd64", L"1.0.0.0",
				 L"{4d36e978-e325-11ce-bfc1-08002be10318}", L"Ports"}) ;
		}

		const auto		  plan = run.plan( context, SESSION) ;		// 通常スキャンの取得計画です
		const std::size_t expectedTargets = ambiguous ? 1U : 3U ;	// 従来行と独立した端末別対象です
		DRIVERCRATE_EXPECT( context, run.lookup && run.adapter &&
										plan.targets.size() == expectedTargets &&
										run.state.sends == 0U) ;
		// 元の照合結果を取得できた場合だけ同じスキャンの証拠を調べます
		if( !run.lookup || !run.adapter || plan.targets.size() != expectedTargets) {
			continue ;
		}

		const auto records = run.lookup->snapshot().consumerRecords() ;	// 認証済みの本文と追加行です
		DRIVERCRATE_EXPECT( context, records.size() == 2U && records[1U].recordSchemaVersion == 5U &&
										records[1U].platformFirmwareGroups.size() == 2U &&
										records[1U].platformFirmwareGroups[0U].versionLabel ==
											records[1U].platformFirmwareGroups[1U].versionLabel) ;
		// 欠損した元行を別レコードで補いません
		if( records.size() != 2U) {
			continue ;
		}

		std::wstring firmwareDigest ;	// 二台の確認対象が共有する署名済み元行のハッシュです
		DRIVERCRATE_EXPECT( context,
						   computeBytesSha256( records[1U].originalBytes, firmwareDigest) == 0U) ;
		const auto relations = run.lookup->relations() ;			// 通常の端末列挙に結合された関係です
		const auto thread	 = GetCurrentThreadId() ;				// スキャンを実行した実所有スレッドです
		std::array<std::optional<std::wstring_view>, 4U> devices ;	// 元Models位置別の端末です
		std::array<const OfficialPreparationTarget *, 4U>
			targets{} ;	// 元Models位置別に同じ計画から借用します
		// 追加行の全関係で同一端末の判定と計画の対象を照合します
		for( std::size_t index{}; index < relations.size(); ++index) {
			const auto &relation = relations[index] ;	// adapterが受け取る元関係です
			// 従来行の取得可否は同じ計画の対照で確認します
			if( relation.recordIndex != 1U) {
				continue ;
			}

			DRIVERCRATE_EXPECT( context, relation.state == IndexRecordMatchState::MATCHED &&
											relation.publicIdIndex &&
											*relation.publicIdIndex < devices.size() &&
											relation.deviceProof && relation.deviceIdentity) ;
			// 元関係が成立していない場合に擬似証拠で群を判定しません
			if( !relation.publicIdIndex || *relation.publicIdIndex >= devices.size() ||
			   !relation.deviceProof || !relation.deviceIdentity) {
				continue ;
			}

			const auto publicId = *relation.publicIdIndex ;	// 署名済みModels上の位置です
			DRIVERCRATE_EXPECT( context, !devices[publicId]) ;
			devices[publicId] = *relation.deviceIdentity ;
			const auto match  = relation.deviceProof->platformFirmwareMatch(
				 records[1U], relation.context, thread,
				 *relation.deviceIdentity) ;						// 元端末の判定です
			const std::size_t group = publicId == 2U ? 1U : 0U ;	// 元公式群の順序です
			DRIVERCRATE_EXPECT(
				context, match.state == (ambiguous ? Match::AMBIGUOUS : Match::UNIQUE) &&
							 match.groupIndex ==
								 (ambiguous ? std::nullopt : std::optional<std::size_t>{group})) ;
			SignedIndexPreparationDescription
					   description ;	// 描画用の名前を再指定せず、同じ対象を再取得します
			const auto result = run.adapter->describe( index, relation.context, nowUtc, plan.limits,
													  description) ;	// 元の通常adapterで再照合します
			// 同一端末で同じ版の別群が競合する場合は確認対象を発行しません
			if( ambiguous) {
				DRIVERCRATE_EXPECT( context,
								   result == AMBIGUOUS_GROUP && !description.target &&
									   description.reason == "PLATFORM_FIRMWARE_GROUP_AMBIGUOUS") ;
				continue ;
			}

			DRIVERCRATE_EXPECT( context, result == 0U && description.target) ;
			// 一意の関係を計画に収録された同じ完全対象へ結びます
			if( description.target) {
				const auto target = std::ranges::find(
					plan.targets, *description.target) ;	// 同一の表示と承認の内容です
				DRIVERCRATE_EXPECT( context, target != plan.targets.end()) ;
				// 計画にある場合だけ元関係との結合を保持します
				if( target != plan.targets.end()) {
					targets[publicId] = &*target ;
					DRIVERCRATE_EXPECT(
						context,
						target->deviceCount == 1U && target->releaseIdentity == firmwareDigest &&
							target->firmwareCondition &&
							target->firmwareCondition->deviceIdentity == *relation.deviceIdentity &&
							target->firmwareCondition->groupIndex == group &&
							target->firmwareCondition->versionLabel == VERSION) ;
				}
			}

			// 一意の元証拠を別の列挙又は別スレッドで再利用しません
			if( publicId == 0U) {
				auto stale = relation.context ;	// 次の列挙世代を表す不一致文脈です
				++stale.inventoryGeneration ;
				const auto otherContext = relation.deviceProof->platformFirmwareMatch(
					records[1U], stale, thread,
					*relation.deviceIdentity) ;	// 元proofのまま文脈だけが異なります
				const auto otherThread = relation.deviceProof->platformFirmwareMatch(
					records[1U], relation.context, thread + 1U,
					*relation.deviceIdentity) ;	// 元proofのままスレッドだけが異なります
				DRIVERCRATE_EXPECT( context, otherContext.state == Match::UNAVAILABLE &&
												!otherContext.groupIndex &&
												otherThread.state == Match::UNAVAILABLE &&
												!otherThread.groupIndex) ;
			}
		}

		DRIVERCRATE_EXPECT(
			context, devices[0U] && !devices[1U] && devices[2U] &&
						 (ambiguous ? devices[0U] == devices[2U] && !devices[3U]
									: devices[0U] == devices[3U] && devices[0U] != devices[2U])) ;
		std::wstring digest ;	// 従来行の原ハッシュです
		DRIVERCRATE_EXPECT( context, computeBytesSha256( records[0U].originalBytes, digest) == 0U) ;
		const auto baseline =
			std::ranges::find( plan.targets, digest,
							  &OfficialPreparationTarget::releaseIdentity) ;	// 同じ索引の対照です
		DRIVERCRATE_EXPECT( context, baseline != plan.targets.end() &&
										!baseline->firmwareCondition && run.state.sends == 0U) ;
		// 従来行を別対象で補わず、確認対象の公開を誤って導入へ進めません
		if( baseline == plan.targets.end()) {
			continue ;
		}

		OfficialPreparationSession preparation ;	// 同じスキャン内の承認と予約を維持します
		auto baselinePlan = plan ;					// 確認後は未選択の従来行だけを残す次計画にします
		// 一意の二台に独立した確認を提示し、群が競合するようになった一台の取得を保留します
		if( !ambiguous) {
			DRIVERCRATE_EXPECT( context, targets[0U] && !targets[1U] && targets[2U] &&
											targets[0U] == targets[3U] &&
											targets[0U]->identity != targets[2U]->identity) ;
			// 元スキャンの機器が保持されている間の現在HardwareIdsを確認します
			if( devices[0U] && devices[2U]) {
				const auto &driverStore =
					signed_index_candidate_binding_detail::Access::driverStoreFixture(
						*run.provider) ;							// 同じ模擬端末とスキャンを所有します
				const std::wstring selected{*devices[0U]} ;			// 第1群を確認した同じ端末です
				const std::wstring peer{*devices[2U]} ;				// 同じ配布を使う別の端末です
				const auto		   origin = run.original.context ;	// 同じスキャンの元観測です
				DRIVERCRATE_EXPECT( context, driverStore.reobserveIndexFirmwareGroup(
												origin, selected, records[1U], 0U) == 0U &&
												driverStore.reobserveIndexFirmwareGroup(
													origin, peer, records[1U], 1U) == 0U) ;
				// 群が同じでも元の一件だけを完全照合し、互換属性と別端末を一致にしません
				DRIVERCRATE_EXPECT(
					context,
					driverStore.reobserveIndexHardwareId( origin, selected, PRIMARY) == 0U &&
						driverStore.reobserveIndexHardwareId( origin, selected, SAME_GROUP) == 0U &&
						driverStore.reobserveIndexHardwareId( origin, selected, OTHER_GROUP) ==
							FIRMWARE_GROUP_CHANGED &&
						driverStore.reobserveIndexHardwareId( origin, peer, PRIMARY) ==
							FIRMWARE_GROUP_CHANGED) ;
				// 第1群の元IDが残っていても異なる公式群が追加されると再確認を求めます
				run.native.additionalSecondDeviceHardwareId = OTHER_GROUP ;
				DRIVERCRATE_EXPECT(
					context,
					driverStore.reobserveIndexFirmwareGroup( origin, selected, records[1U], 0U) ==
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY))) ;
				// 同じ群の別IDが消えても残りの完全IDで一意に照合できます
				run.native.additionalSecondDeviceHardwareId = {} ;
				// 元端末が維持されても選んだ完全値が消えた場合は再確認します
				DRIVERCRATE_EXPECT(
					context, driverStore.reobserveIndexHardwareId( origin, selected, SAME_GROUP) ==
								 FIRMWARE_GROUP_CHANGED) ;
				DRIVERCRATE_EXPECT(
					context,
					driverStore.reobserveIndexFirmwareGroup( origin, selected, records[1U], 0U) ==
							0U &&
						driverStore.reobserveIndexFirmwareGroup( origin, peer, records[1U], 0U) ==
							static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY))) ;
				// 重複した異常MULTI_SZの読取り失敗を別の公式群の一致に変換しません
				run.native.additionalSecondDeviceHardwareId = PRIMARY ;
				DRIVERCRATE_EXPECT(
					context,
					driverStore.reobserveIndexFirmwareGroup( origin, selected, records[1U], 0U) ==
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA))) ;
				auto stale = origin ;	// 現在の列挙とは異なる文脈です
				++stale.inventoryGeneration ;
				DRIVERCRATE_EXPECT( context, driverStore.reobserveIndexFirmwareGroup(
												stale, selected, records[1U], 0U) ==
												static_cast<NativeError>( E_ACCESSDENIED)) ;
				DRIVERCRATE_EXPECT( context,
								   driverStore.reobserveIndexHardwareId( stale, selected, PRIMARY) ==
									   static_cast<NativeError>( E_ACCESSDENIED)) ;
				run.native.additionalSecondDeviceHardwareId = SAME_GROUP ;
				const auto previousCase	  = run.native.nativeCase ;	// 再観測条件を元に戻す値です
				const bool previousChange = run.native.changed ;	// 変更を加える前の状態です
				run.native.nativeCase	  = SignedIndexBindingNativeCase::DISAPPEARED ;
				run.native.changed		  = true ;
				// 元HardwareIdsが残っても取り外された端末を取得対象へ復活させません
				DRIVERCRATE_EXPECT(
					context, driverStore.reobserveIndexHardwareId( origin, selected, PRIMARY) != 0U) ;
				run.native.nativeCase = previousCase ;
				run.native.changed	  = previousChange ;
			}

			// 各端末の通常参照と確認対象を、同じスキャンの現在行へ照合します
			for( const auto publicId : {0U, 2U}) {
				const auto *target = targets[publicId] ;	// 同じ元行の一台だけに対応します
				// 確認対象が欠損した端末を別端末の参照で補いません
				if( !target || !devices[publicId]) {
					continue ;
				}

				const auto current =
					std::ranges::find_if( run.displayedCandidates, [&]( const auto &candidate) {
						return candidate.current && candidate.deviceIdentity == *devices[publicId] ;
					}) ; // 同じ端末の通常行の表示名です
				const auto reference = std::ranges::find(
					run.displayedCandidates, target->identity,
					&UpdateCandidate::preparationTargetIdentity) ;	// 通常の取得前参照です
				DRIVERCRATE_EXPECT(
					context,
					reference != run.displayedCandidates.end() && !reference->installable &&
						reference->deviceIdentity == *devices[publicId] &&
						std::ranges::count( run.displayedCandidates, target->identity,
										   &UpdateCandidate::preparationTargetIdentity) == 1 &&
						current != run.displayedCandidates.end()) ;
				// 普通のデバイス表示名が取れた場合だけ必須バージョンとともに照合します
				if( current != run.displayedCandidates.end()) {
					const auto &name = current->model.empty()
										   ? current->title
										   : current->model ;	// 現在行の表示名です
					DRIVERCRATE_EXPECT(
						context,
						!name.empty() && target->requiresPrerequisiteConfirmation &&
							target->terms == OfficialPreparationTerms::CONFIRMED_NO_CONSENT &&
							target->prerequisiteText.find( name) != std::wstring::npos &&
							target->prerequisiteText.find( VERSION) != std::wstring::npos) ;
				}
			}

			// 確認対象が生成されなければ元の取得入口へ進みません
			if( !targets[0U]) {
				continue ;
			}

			DRIVERCRATE_EXPECT( context,
							   preparation.initialize( plan) == OfficialPreparationError::NONE) ;
			OfficialPreparationApproval approval{
				SESSION + 1U, SESSION, plan.planId, plan.limits, {}} ;	// 元の全対象を載せる承認です
			// 本人が確認した同じ一台だけを承認します
			for( const auto &target : plan.targets) {
				const bool selected =
					// 本人確認を一台へ限定します
					target.identity == targets[0U]->identity ;
				approval.decisions.push_back( {target, selected, false, false, selected}) ;
			}

			// 計画確定後に元IDを残したまま別群のIDを足し、grant発行前の競合をつくります
			run.native.additionalSecondDeviceHardwareId = OTHER_GROUP ;
			const auto acquired							= executeOfficialPreparation(
				preparation, approval,
				[&]( const OfficialPreparationTask &task, const PreparationCancellation &cancel) {
					RecordScopedDownloadGrant grant ;	// 実claimに対しても未発行のままです
					const auto				  now = static_cast<std::uint64_t>(
						   // 元の試験時刻です
						   nowUtc.time_since_epoch().count()) ;
					DRIVERCRATE_EXPECT(
						context,
						run.adapter->claimApprovedRecord( preparation, task, run.original.context,
																				 now, grant) == FIRMWARE_GROUP_CHANGED &&
							grant.metadata().state == OfficialDownloadGrantState::NOT_REQUESTED &&
							grant.metadata().grantId == 0U) ;
					return run.session.acquireForInspection( preparation, task, run.services,
																					cancel) ;
				},
				[] { return false ; },
				[]( const OfficialPreparationProgress &) {}) ;	// 通常取得入口です
			const auto transfer =
				std::ranges::find( acquired.items, targets[0U]->identity,
								  &OfficialPreparationItem::identity) ;	// 元対象の取得終端です
			const auto summary =
				// 元取得結果です
				run.session.preparationSummary( approval.operationId) ;
			DRIVERCRATE_EXPECT(
				context, acquired.approvalError == OfficialPreparationError::NONE &&
							 acquired.controlError == 0U && transfer != acquired.items.end() &&
							 transfer->result.state == OfficialPreparationItemState::REJECTED &&
							 transfer->result.error == FIRMWARE_GROUP_CHANGED &&
							 transfer->result.byteCount == 0U && summary.items.size() == 1U &&
							 !summary.items.front().inputBound &&
							 summary.items.front().acquisitionError == FIRMWARE_GROUP_CHANGED &&
							 run.state.sends == 0U && run.native.stages == 0U &&
							 run.native.installs == 0U) ;

			++baselinePlan.planId ;
			baselinePlan.targets = {*baseline} ;
			DRIVERCRATE_EXPECT( context,
							   run.session.retainPreparationPlan( baselinePlan, run.services) &&
								   baselinePlan.targets.size() == 1U) ;
		}

		acquirePlatformConsumerTarget( context, run, preparation, baselinePlan, *baseline,
									  SESSION + 2U, baseZip.size(), false) ;
		DRIVERCRATE_EXPECT( context, run.state.sends == 1U && run.native.stages == 0U &&
										run.native.installs == 0U) ;
	}

	testPlatformFirmwareRetainedInspection( context, store, nowUtc, scopedZip, HOST, PRIMARY,
										   OTHER_GROUP) ;
	testPlatformDeviceInstallBoundaries(
		context, store, nowUtc, baseZip, scopedZip,
		{"firmware-stable", "firmware-conflict-before-stage", "firmware-conflict-before-apply",
		 "firmware-same-group-before-apply", "firmware-expires-during-stage-observation",
		 "firmware-expires-during-apply-observation"},
		SAME_GROUP, OTHER_GROUP) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名索引の元候補を通常workerの復元・登録・指定適用で検証します
 * @param[in,out] context 元候補と低位呼出しの試験集計です
 * @param[in] store 本文とCatalog追加欄を再認証する隔離ストアです
 * @param[in] nowUtc 取得前の信頼時刻です
 * @param[in] expiry 追加欄全体の原期限です
 * @param[in] baseZip 本文の元配布物です
 * @param[in] catalogZip Catalogの人工配布物です
 * @note Windows変更とHTTPは各workerの完全な低位fakeへ結合します
 */
//------------------------------------------------------------------------------
static void testCatalogInstallBoundaries( TestContext							 &context,
										 const std::shared_ptr<SignedIndexStore> &store,
										 const std::chrono::sys_seconds			  nowUtc,
										 const std::chrono::sys_seconds			  expiry,
										 const std::string_view					  baseZip,
										 const std::string_view					  catalogZip)
{
	// 短期限の別行が決めた境界と、同端末の属性変化を独立した操作で確認します
	for( const std::string_view id :
		{"hardware-match", "hardware-removed", "moved-to-compatible", "expires-before-registration",
		 "expires-before-application", "base-after-supplement-expiry"}) {
		const bool moved = id == "moved-to-compatible" ;				// 元Hardware IDを互換属性だけへ移します
		const bool lostHardware = moved || id == "hardware-removed" ;	// 同じinstanceの属性変化です
		const bool beforeRegistration =
			// 登録root確認後の原期限です
			id == "expires-before-registration" ;
		const bool beforeApplication = id == "expires-before-application" ;	// 登録成功後の原期限です
		const bool ordinary =
			// 長い元期限を持つ本文の対照です
			id == "base-after-supplement-expiry" ;
		const auto body = ordinary ? baseZip : catalogZip ;	// 選択した一件の元ZIPです
		auto	   state =
			std::make_shared<CatalogInstallFixture>() ;	// worker停止まで低位入力を所有します
		auto clock =
			std::make_shared<std::chrono::sys_seconds>( nowUtc) ;	// 送信と署名条件が読む同じ時計です
		auto services		  = makeServerP4PipelineServices( store, clock, {},
															 {}) ;	// 完全なHTTP、費用、隔離索引の依存です
		services.hostPlatform = [] {
			return WindowsHostPlatformObservation{WindowsHostObservationState::OBSERVED,
												  WindowsHostPlatform{10U, 0U, 26100U, 9U, 1U, 0U},
												  WindowsHostErrorDomain::NTSTATUS,
												  WindowsHostObservationStage::VERSION, 0U} ;
		} ; // 同じWindows 11端末を列挙時から操作終了まで返します
		services.utc = [clock, state, beforeRegistration, beforeApplication, expiry]() {
			// 指定の低位境界へ到達した時だけ時計を進め、後続の保持候補でも時刻を戻しません
			if( activeNative && ((beforeRegistration && state->registrationRootReads != 0U) ||
								(beforeApplication && activeNative->stages != 0U))) {
				*clock = expiry ;
			}

			return std::optional{*clock} ;
		} ;
		services.httpTransport = [transport = services.httpTransport, clock]() {
			auto fake	= transport() ;	// 名前解決から本文まで人工HTTPです
			fake.utcNow = [clock] {
				return static_cast<std::uint64_t>( clock->time_since_epoch().count()) ;
			} ;
			return fake ;
		} ;
		// 各workerだけのHTTP本文と元端末を用意し、二台から一台だけを索引候補にします
		const auto start = [state, store, clock, body] {
			// 完全なDriver Store fakeを開始できなければ試験を中止します
			if( !activeNative) {
				throw std::runtime_error( "catalog install native fixture missing") ;
			}

			activeNative->catalogInstall		  = state.get() ;
			activeNative->p4ExplicitClientContext = true ;
			activeNative->multiple				  = true ;
			activeNative->noReboot				  = true ;
			static_cast<void>(
				makeServerP4PipelineServices( store, clock, body, [state] { ++state->sends ; })) ;
		} ;
		auto bound = makeSignedIndexBindingWorker( std::move( services), body, false, false, false,
												  SignedIndexBindingNativeCase::NORMAL, {},
												  start) ;	// 各変更APIと復元は既存のfakeです
		OperationController controller ;					// 通常画面の選択・承認の所有者です
		ScanOptions			options ;						// 元索引と人工Driver Storeだけを検索します
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
									   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		// 別端末の通常候補が期限到達後も同じscan内で保持される例です
		if( beforeApplication) {
			options.enabledProviderIds.emplace_back( WINDOWS_UPDATE_PROVIDER_ID) ;
		}

		const auto scan = controller.beginScan() ;	// 元の一回のscanです
		DRIVERCRATE_EXPECT( context, bound.worker && scan.accepted &&
										bound.worker->requestScan( scan.operationId, options)) ;
		// 完全fakeを持つworker以外へ要求を送りません
		if( !bound.worker) {
			continue ;
		}

		auto scanned = waitEvent( *bound.worker, WorkerEventKind::SCAN_COMPLETED,
								 scan.operationId) ;	// 元の取得計画です
		DRIVERCRATE_EXPECT(
			context, scanned && scanned->scanResult.succeeded && scanned->preparationPlan &&
						 scanned->preparationPlan->targets.size() == 2U && state->sends == 0U) ;
		// 元計画のないfixtureをID消失や期限切れとして扱いません
		if( !scanned || !scanned->preparationPlan) {
			continue ;
		}

		const auto &plan = *scanned->preparationPlan ;	// 本文と追加欄が独立した元対象です
		const auto	source =
			 ordinary
				 ? L"fixture-source (https://vendor.example/)"
				 : L"catalog-source (https://www.catalog.update.microsoft.com/)" ;	// 独立した取得元の識別です
		const auto target = std::ranges::find(
			plan.targets, source,
			&OfficialPreparationTarget::eulaSourceSubject) ;	// 発行済みの選択対象です
		DRIVERCRATE_EXPECT( context,
						   target != plan.targets.end() && target->deviceCount == 1U &&
							   controller.completeScan( scan.operationId, scanned->scanResult) &&
							   controller.setPreparationPlan( scan.operationId, plan)) ;
		// 一件の元選択を得られない場合は以後の準備を実行しません
		if( target == plan.targets.end()) {
			continue ;
		}

		OfficialPreparationApproval approval{
			0U, plan.scanSessionId, plan.planId, plan.limits, {}} ;	// 一件への明示承認です
		// 本文と追加欄を同じ承認で取得しません
		for( const auto &item : plan.targets) {
			approval.decisions.push_back(
				{item, item.identity == target->identity, false, false, false}) ;
		}

		const auto request = controller.beginPreparation( approval) ;	// workerへ渡す元操作です
		DRIVERCRATE_EXPECT( context, request.accepted && bound.worker->requestPreparation( approval)) ;
		auto prepared = waitEvent( *bound.worker, WorkerEventKind::PREPARATION_COMPLETED,
								  request.operationId) ;	// 内容検査後の実候補です
		DRIVERCRATE_EXPECT(
			context,
			prepared && prepared->indexPreparation.items.size() == 1U &&
				prepared->indexPreparation.items.front().inputBound &&
				prepared->indexPreparation.items.front().acceptedInfCount == 1U &&
				prepared->preparationResult.auditReports.size() == 1U &&
				prepared->preparationResult.auditReports.front().publishedCandidates.size() == 1U) ;
		// 候補発行前の失敗を導入境界での拒否に数えません
		if( !prepared || prepared->preparationResult.auditReports.size() != 1U ||
		   prepared->preparationResult.auditReports.front().publishedCandidates.size() != 1U) {
			continue ;
		}

		const auto &candidate = prepared->preparationResult.auditReports.front()
									.publishedCandidates.front() ;	// 実際に発行した一端末の候補です
		DRIVERCRATE_EXPECT(
			context,
			candidate.providerId == SIGNED_INDEX_PROVIDER_ID && candidate.installable &&
				candidate.preparationTargetIdentity == target->identity && candidate.assessment &&
				isCandidateAssessmentReady( *candidate.assessment) &&
				candidate.assessment->installMethod == CandidateInstallMethod::STANDARD_INF &&
				controller.completePreparation( prepared->preparationResult,
											   scanned->scanResult.candidates)) ;
		const auto before = bound.observe() ;	// 作用開始前の低位呼出しです
		DRIVERCRATE_EXPECT( context, state->sends == 1U && before.stages == 0U &&
										before.installs == 0U && before.restoreBegins == 0U &&
										state->registrationRootReads == 0U) ;
		// 本文は追加欄の原期限でも有効です。他の例ではその一秒前に導入操作へ進みます
		*clock = ordinary ? expiry : expiry - std::chrono::seconds{1} ;
		// 実候補発行後もinstanceと現在driverのMatchingDeviceIdを保ち、二つの元propertyだけに変化を与えます
		if( lostHardware) {
			state->hardwareIds	= L"TESTBUS\\OTHER_HARDWARE" ;
			state->compatibleId = moved ? L"TESTBUS\\SYNTH_0001" : L"" ;
		}

		// 同じworkerの復旧・指定適用・保持結果を通常controllerへ戻し、元選択だけを実行します
		const auto install = [&]( const std::wstring &identity) {
			const std::array selection{identity} ;	// 一操作一端末の元表示IDです
			const auto		 operation = controller.beginInstall(
				  plan.scanSessionId, selection, InstallConfirmation::CONFIRMED) ;	// 本人同意です
			DRIVERCRATE_EXPECT( context,
							   operation.accepted &&
								   bound.worker->requestInstall(
									   operation.operationId, plan.scanSessionId, selection,
									   nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
			auto event = waitEvent( *bound.worker, WorkerEventKind::INSTALL_COMPLETED,
								   operation.operationId) ;	// 保護付き操作の終端です
			DRIVERCRATE_EXPECT(
				context, event && event->installResult.updates.size() == 1U &&
							 event->installResult.updates.front().identity == identity &&
							 event->installRetention &&
							 controller.completeInstall( operation.operationId, event->installResult,
														&*event->installRetention)) ;
			return event ;
		} ;
		const auto installed = install( candidate.identity) ;	// 元の署名済み候補への一回の操作です
		const auto observed	 = bound.observe() ;				// 各Win32 fakeと復旧fakeの実回数です
		const bool succeeds =
			!lostHardware && !beforeRegistration && !beforeApplication ;	// 正常な二経路です
		const unsigned stages =
			lostHardware || beforeRegistration ? 0U : 1U ;	// 達するべき登録回数です
		DRIVERCRATE_EXPECT(
			context, observed.restoreBegins == (lostHardware ? 0U : 1U) &&
						 observed.restoreCompletes == observed.restoreBegins &&
						 observed.stages == stages && observed.installs == (succeeds ? 1U : 0U) &&
						 observed.deviceInstalls[0] == observed.installs &&
						 observed.deviceInstalls[1] == 0U && observed.specifiedBindingMatches &&
						 (state->changedHardwareReads != 0U) == lostHardware &&
						 (state->changedCompatibleReads != 0U) == moved &&
						 (state->registrationRootReads != 0U) == !lostHardware &&
						 state->sends == 1U) ;
		// 初期や個別結果の欠損を元HRESULTでの停止と認定しません
		if( installed && installed->installResult.updates.size() == 1U) {
			const auto		 &result = installed->installResult ;	// 同じ元operationの集計です
			const auto		 &update = result.updates.front() ;		// 指定した一件の端末結果です
			const NativeError error =
				lostHardware ? HRESULT_FROM_WIN32( ERROR_RETRY)
				: succeeds	 ? S_OK
							 : HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;	// 束縛の変化と期限を区別します
			DRIVERCRATE_EXPECT(
				context, result.succeeded == succeeds && !result.rebootRequired &&
							 result.downloadError == (lostHardware ? error : S_OK) &&
							 update.downloadError == result.downloadError &&
							 result.installError == (lostHardware ? S_OK : error) &&
							 update.installError == result.installError &&
							 update.downloadOutcome ==
								 (lostHardware ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS) &&
							 update.installOutcome == (lostHardware ? OutcomeCode::NOT_STARTED
													   : succeeds	? OutcomeCode::SUCCESS
																	: OutcomeCode::FAILURE) &&
							 installed->installRetention &&
							 installed->installRetention->providerEntered == !lostHardware) ;
			std::cout << "CATALOG_INSTALL case=" << id << " downloadError=" << result.downloadError
					  << " installError=" << result.installError
					  << " hardwareReads=" << state->changedHardwareReads
					  << " compatibleReads=" << state->changedCompatibleReads
					  << " restore=" << observed.restoreBegins << '/' << observed.restoreCompletes
					  << " registrationRoot=" << state->registrationRootReads
					  << " stage=" << observed.stages << " device1=" << observed.deviceInstalls[0]
					  << " device2=" << observed.deviceInstalls[1] << '\n' ;
		}

		// 登録後にCatalogだけが失効した同じscanで、元の別端末に属するWUA候補を明示選択します
		if( beforeApplication && installed && installed->installRetention) {
			const auto managed =
				std::ranges::find( scanned->scanResult.candidates, WINDOWS_UPDATE_PROVIDER_ID,
								  &UpdateCandidate::providerId) ;	// 元scanの別経路です
			DRIVERCRATE_EXPECT(
				context, managed != scanned->scanResult.candidates.end() && managed->installable &&
							 managed->deviceIdentity != candidate.deviceIdentity &&
							 std::ranges::any_of(
								 installed->installRetention->candidates, [&]( const auto &entry) {
									 return entry.identity == managed->identity &&
											entry.deviceIdentity == managed->deviceIdentity ;
								 })) ;
			// 実際に表示した別端末の元候補だけへ二回目の操作を渡します
			if( managed != scanned->scanResult.candidates.end()) {
				const auto other =
					// 元期限を戻さず同scanの別操作を開始します
					install( managed->identity) ;
				const auto after =
					// 登録済みINFに対する操作を繰り返していないことも確認します
					bound.observe() ;
				DRIVERCRATE_EXPECT( context,
								   other && other->installResult.succeeded &&
									   after.managedInstalls == 1U && after.restoreBegins == 2U &&
									   after.restoreCompletes == 2U && after.stages == 1U &&
									   after.installs == 0U && state->sends == 1U) ;
				std::cout << "CATALOG_RETAINED managed=" << after.managedInstalls
						  << " restore=" << after.restoreBegins << '/' << after.restoreCompletes
						  << " stage=" << after.stages << " apply=" << after.installs << '\n' ;
			}
		}

		DRIVERCRATE_EXPECT( context, *clock == (beforeRegistration || beforeApplication || ordinary
												   ? expiry
												   : expiry - std::chrono::seconds{1})) ;
		bound.worker->stop() ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 本文とCatalog追加欄を通常スキャンの端末照合・取得と期限境界で検証します
 * @param[in,out] context 共通の試験集計です
 * @param[in] store 両欄の署名済み原転送byteを再読できる隔離ストアです
 * @param[in] nowUtc 両欄が使用できる開始時刻です
 * @param[in] expiry 別行の期限で決まる追加欄全体の原期限です
 * @param[in] baseZip 本文の元レコードが参照する人工ZIPです
 * @param[in] catalogZip 対象付きレコードが参照する人工ZIPです
 * @param[in] baseDigest 本文の展開前に用意した元JSONのSHA-256です
 * @param[in] supplementDigest 追加欄の元JSON全体のSHA-256です
 */
//------------------------------------------------------------------------------
void runCatalogSupplementConsumerScan( TestContext &context, std::shared_ptr<SignedIndexStore> store,
									  const std::chrono::sys_seconds nowUtc,
									  const std::chrono::sys_seconds expiry,
									  const std::string_view		 baseZip,
									  const std::string_view		 catalogZip,
									  const IndexManifestSha256		&baseDigest,
									  const IndexManifestSha256		&supplementDigest)
{
	constexpr WindowsHostPlatform host{10U, 0U, 26100U,
									   9U,	1U, 0U} ;	// 全例で固定したWindows 11 x64です
	// 同じ隔離ストアを、各例の独立したスキャンと列挙で再読します
	for( const auto id : std::array<std::string_view, 4U>{"hardware", "compatible-only",
														 "expired-at-scan", "expired-at-claim"}) {
		const bool compatibleOnly = id == "compatible-only" ;	// 同じ公開IDを互換属性だけに返します
		const bool expiredScan =
			// 追加欄の期限ちょうどに新規スキャンします
			id == "expired-at-scan" ;
		const bool expiredClaim =
			// スキャン後、承認済み取得の直前に時計を進めます
			id == "expired-at-claim" ;
		const auto		body = expiredScan ? baseZip : catalogZip ;	// 選択する一件の元配布物です
		ServerP4Harness run{store, expiredScan ? expiry : nowUtc, body, id,
							host} ;	// 完全な低位模擬端末です
		// 通信境界の試験時計もスキャン・取得許可と同じ時刻を返します
		run.services.httpTransport = [transport = run.services.httpTransport, clock = run.clock]() {
			auto fake	= transport() ;	// 全てのHTTP・名前解決を既存の低位fakeに保持します
			fake.utcNow = [clock] {
				return static_cast<std::uint64_t>( clock->time_since_epoch().count()) ;
			} ;
			return fake ;
		} ;
		// 同じ一台からHardwareIdsだけの一致を除き、従来の本文はCompatibleIdsで照合できます
		if( compatibleOnly) {
			run.native.distributionDevices.push_back(
				{L"TESTBUS\\OTHER_HARDWARE", L"fixture.inf", L"Models.NTamd64", L"1.0.0.0",
				 L"{4d36e978-e325-11ce-bfc1-08002be10318}", L"Ports"}) ;
			run.native.opaqueCompatibleId = L"TESTBUS\\SYNTH_0001" ;
		}

		const auto plan = run.plan( context, 853362U) ;	// 通常の列挙と認証lookupが用意する元計画です
		const auto scan = signed_index_candidate_binding_detail::Access::cachedSummaryForFixture(
			*run.provider) ;	// 同一スキャンの観測です
		const std::size_t expectedRecords =
			expiredScan ? 1U : 2U ;	// 短期限の非対象行は端末件数へ含めません
		const std::size_t expectedTargets =
			compatibleOnly || expiredScan ? 1U : 2U ;	// 本文は四例とも一件です
		DRIVERCRATE_EXPECT(
			context,
			scan.status == IndexScanStatus::COMPLETED &&
				scan.storeStatus == IndexStoreStatus::SNAPSHOT_READY &&
				scan.totalRecords == expectedRecords && scan.processedRecords == expectedRecords &&
				scan.remainingRecords == 0U && scan.resolverCalls == expectedRecords &&
				scan.matchedRelations == expectedTargets &&
				scan.definitiveNoRelationIds == (compatibleOnly ? 1U : 0U) && scan.error == 0U) ;
		DRIVERCRATE_EXPECT(
			context,
			scan.supplementStatus == (expiredScan ? IndexAssetSupplementStatus::EXPIRED
												  : IndexAssetSupplementStatus::BYTE_VALIDATED) &&
				(expiredScan
					 ? !scan.supplementRecordsStatus
					 : scan.supplementRecordsStatus == IndexRecordsStatus::SCHEMA_VALIDATED)) ;
		const auto references =
			std::ranges::count_if( run.displayedCandidates, []( const auto &item) {
				return item.identity.starts_with( L"index-reference-") ;
			}) ; // 端末ごとに通常表示が発行した未検査参照です
		DRIVERCRATE_EXPECT( context, plan.targets.size() == expectedTargets &&
										static_cast<std::size_t>( references) == expectedTargets &&
										run.state.sends == 0U && run.native.stages == 0U &&
										run.native.installs == 0U && run.lookup) ;
		// 端末が作ったlookupを欠く場合は原領域も後続取得も認定しません
		if( !run.lookup) {
			continue ;
		}

		const auto &snapshot = run.lookup->snapshot() ;		// 署名再検証後の同一スキャン所有値です
		const auto	records	 = snapshot.consumerRecords() ;	// 旧本文の直後に有効な対象行を借用します
		DRIVERCRATE_EXPECT( context, snapshot.schemaReceipt().records().size() == 1U &&
										snapshot.schemaReceipt().indexSha256() == baseDigest &&
										baseDigest != supplementDigest &&
										records.size() == expectedRecords) ;
		// 欠損した位置を添字で参照しません
		if( records.size() != expectedRecords || plan.targets.size() != expectedTargets) {
			continue ;
		}

		const auto base = snapshot.consumerRecordRegion( 0U) ;	// 追加欄が失効しても有効な本文です
		const auto manifestExpiry = std::chrono::sys_days{std::chrono::year{2026} / 10 / 25} +
									std::chrono::hours{5} ;	// 署名manifestの原期限です
		DRIVERCRATE_EXPECT(
			context, records[0U].recordId == "fixture-base" &&
						 records[0U].recordSchemaVersion == 2U && base.indexSha256 == baseDigest &&
						 base.expiresAtUtc == manifestExpiry && base.sources.size() == 1U &&
						 base.sources.front().sourceId == "fixture-source") ;
		std::wstring baseRecordHash ;	// 展開済み本文の各行と計画を結ぶ元byteのhashです
		DRIVERCRATE_EXPECT( context,
						   computeBytesSha256( records[0U].originalBytes, baseRecordHash) == 0U) ;
		const auto baseline = std::ranges::find(
			plan.targets, baseRecordHash,
			&OfficialPreparationTarget::releaseIdentity) ;	// 通常計画内の本文の位置です
		DRIVERCRATE_EXPECT( context, baseline != plan.targets.end() && baseline->deviceCount == 1U &&
										baseline->eulaSourceSubject ==
											L"fixture-source (https://vendor.example/)") ;
		auto selected = baseline ;	// 期限切れの新スキャンでは本文を明示選択します
		// 同一署名・別の原取得元・別の領域期限を持つ行を、期限前のスキャンだけに要求します
		if( !expiredScan) {
			const auto region =
				// 計算済みの追加欄全体の原hashと期限です
				snapshot.consumerRecordRegion( 1U) ;
			const auto &row = records[1U] ;	// このv3行の取得証拠は追加欄の原期限より長く有効です
			DRIVERCRATE_EXPECT(
				context, row.recordId == "fixture-catalog" && row.recordSchemaVersion == 3U &&
							 row.catalogHardwareScope && region.indexSha256 == supplementDigest &&
							 region.expiresAtUtc == expiry && region.sources.size() == 1U &&
							 region.sources.front().sourceId == "catalog-source" &&
							 row.acquisitionDescriptor && row.acquisitionDescriptor->attestation &&
							 row.acquisitionDescriptor->attestation->validUntilUtc > expiry) ;
			std::wstring catalogRecordHash ;	// 別領域の元行から得た計画のrelease identityです
			DRIVERCRATE_EXPECT( context,
							   computeBytesSha256( row.originalBytes, catalogRecordHash) == 0U &&
								   catalogRecordHash != baseRecordHash) ;
			selected = std::ranges::find( plan.targets, catalogRecordHash,
										 &OfficialPreparationTarget::releaseIdentity) ;
			const auto relation =
				std::ranges::find_if( run.lookup->relations(), []( const auto &item) {
					return item.recordIndex == 1U && item.state == IndexRecordMatchState::MATCHED ;
				}) ; // 通常のnative resolverが発行した元端末への関係だけを探します
			// CompatibleIdsだけの端末では元HardwareIdsの権限と取得対象を発行しません
			if( compatibleOnly) {
				DRIVERCRATE_EXPECT( context, selected == plan.targets.end() &&
												relation == run.lookup->relations().end()) ;
				std::cout << "CATALOG_CONSUMER_SCAN case=" << id << " records=" << scan.totalRecords
						  << " targets=" << plan.targets.size() << " references=" << references
						  << " noRelation=" << scan.definitiveNoRelationIds
						  << " fakeSends=" << run.state.sends << '\n' ;
				continue ;
			}

			DRIVERCRATE_EXPECT(
				context, selected != plan.targets.end() && selected->deviceCount == 1U &&
							 selected->eulaSourceSubject ==
								 L"catalog-source (https://www.catalog.update.microsoft.com/)" &&
							 relation != run.lookup->relations().end() &&
							 relation->publicIdIndex == 0U && relation->deviceIdentity &&
							 relation->deviceProof) ;
		}

		// 通常計画が選択可能にしなかった対象へ取得要求を作りません
		if( selected == plan.targets.end()) {
			continue ;
		}

		// 計画作成後に追加欄だけを失効させ、元レコードの個別期限内での拒否を測ります
		if( expiredClaim) {
			*run.clock = expiry ;
		}

		OfficialPreparationSession preparation ;	// このスキャンの明示承認を所有します
		DRIVERCRATE_EXPECT( context, preparation.initialize( plan) == OfficialPreparationError::NONE) ;
		OfficialPreparationApproval approval{853363U,
											 plan.scanSessionId,
											 plan.planId,
											 plan.limits,
											 {}} ;	// 元の各対象へ選択の有無を記録します
		// 元計画内の一件だけを選択し、本文と追加欄をまとめて承認しません
		for( const auto &target : plan.targets) {
			approval.decisions.push_back(
				{target, target.identity == selected->identity, false, false, false}) ;
		}

		const auto acquired = executeOfficialPreparation(
			preparation, approval,
			[&]( const OfficialPreparationTask &task, const PreparationCancellation &cancel) {
				return run.session.acquireForInspection( preparation, task, run.services, cancel) ;
			},
			[] { return false ; },
			[]( const OfficialPreparationProgress &) {}) ;	// 承認済みの一件だけを低位fakeへ渡します
		const auto summary =
			// 実際の取得と内容検査の終端です
			run.session.preparationSummary( approval.operationId) ;
		const auto reports =
			// 通常の適用性検査と候補発行です
			run.provider->preparationAuditReports( acquired) ;
		std::size_t published{} ;	// 実際に発行された全候補を数えます
		// 他の元レコードに対応する候補が紛れ込んでいないかも照合します
		for( const auto &report : reports) {
			published += report.publishedCandidates.size() ;
			// 取得成功だけを選択された導入可能候補の発行へ換算しません
			for( const auto &candidate : report.publishedCandidates) {
				DRIVERCRATE_EXPECT( context,
								   candidate.installable &&
									   candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
									   candidate.preparationTargetIdentity == selected->identity) ;
			}
		}

		DRIVERCRATE_EXPECT( context, acquired.approvalError == OfficialPreparationError::NONE &&
										acquired.controlError == 0U && summary.items.size() == 1U &&
										summary.items.front().targetIdentity == selected->identity) ;
		// 終端を欠く結果を期限切れによる拒否と見なしません
		if( summary.items.size() == 1U) {
			const auto		 &item = summary.items.front() ;	// 同じ選択に対する取得・内容の実測です
			const NativeError expectedError = expiredClaim ? HRESULT_FROM_WIN32( ERROR_TIMEOUT)
														   : S_OK ;	// 同じ符号付きの元HRESULTです
			DRIVERCRATE_EXPECT( context, item.acquisitionError == expectedError &&
											item.inputBound == !expiredClaim &&
											item.acceptedInfCount == (expiredClaim ? 0U : 1U)) ;
		}

		DRIVERCRATE_EXPECT( context, run.state.sends == (expiredClaim ? 0U : 1U) &&
										published == (expiredClaim ? 0U : 1U) &&
										run.native.stages == 0U && run.native.installs == 0U &&
										run.native.opens == run.native.closes) ;
		std::cout << "CATALOG_CONSUMER_SCAN case=" << id << " records=" << scan.totalRecords
				  << " targets=" << plan.targets.size() << " references=" << references
				  << " fakeSends=" << run.state.sends << " candidates=" << published
				  << " stages=" << run.native.stages << " installs=" << run.native.installs << '\n' ;
	}

	testCatalogInstallBoundaries( context, store, nowUtc, expiry, baseZip, catalogZip) ;
}

/** @brief 模擬したページ・本体の応答と送信先の実測をworker内に保持します */
struct WixWorkerHttp {
	/// 公式ページに返す現時点のHTMLです
	std::string_view								   page ;
	/// CDNが返す元EXEに見立てた非実行の人工データです
	std::string										   payload ;
	/// 301に待機秒数を付ける場合trueです
	bool											   retryAfter{} ;
	/// 署名索引と異なるCDNパスを301に返す場合trueです
	bool											   otherLocation{} ;
	/// 実送信直前までに渡された模擬接続先です
	std::wstring									   host ;
	/// 実送信直前までに渡された模擬要求パスです
	std::wstring									   path ;
	/// fake sendが受け取った順序の全接続先とパスです
	std::vector<std::pair<std::wstring, std::wstring>> sends ;
	/// 現在の応答本文から渡し終えたバイト数です
	std::size_t										   offset{} ;

	/**
	 * @brief 現在の要求に対応する本文を参照します
	 * @return 同workerのfakeが保有するHTML、本体、または空の本文です
	 */
	[[nodiscard]] std::string_view					   body() const
	{
		return path == L"/support"			   ? page
			   : host == L"cdn.vendor.example" ? std::string_view{payload}
											   : std::string_view{} ;
	}
} ;

thread_local WixWorkerHttp	*activeWixWorkerHttp{} ;	// 同workerだけが試験で借用する元応答です

//------------------------------------------------------------------------------
/**
 * @brief 既存の完全な偽WinHTTPを、元ページ・301・CDN各応答に接続します
 * @param[in,out] transport 既存の完全な偽I/Oを所有し、応答側だけ置換します
 * @param[in,out] fixture 終端までworker内でだけ借用する送信履歴と元応答です
 * @return 元ネットワークAPIを呼ばない同じtransportです
 */
//------------------------------------------------------------------------------
static OfficialHttpTransport wixWorkerTransport( OfficialHttpTransport transport,
												WixWorkerHttp		 &fixture)
{
	activeWixWorkerHttp = &fixture ;
	transport.connect	= []( HINTERNET, LPCWSTR host, INTERNET_PORT port, DWORD) -> HINTERNET {
		  // 他のポートまたは未知の接続先にも実ネットワークを使いません
		  if( !host || port != INTERNET_DEFAULT_HTTPS_PORT) {
			  SetLastError( ERROR_INVALID_PARAMETER) ;
			  return nullptr ;
		  }

		  activeWixWorkerHttp->host = host ;
		  return activeWixWorkerHttp ;
	} ; // 模擬接続はworker所有の応答表を参照します
	transport.openRequest = []( HINTERNET, LPCWSTR method, LPCWSTR path, LPCWSTR, LPCWSTR, LPCWSTR *,
							   DWORD flags) -> HINTERNET {
		// HTTPSのGETを要求する通常入口だけが偽応答へ到達します
		if( !method || std::wstring_view{method} != L"GET" || !path ||
		   (flags & WINHTTP_FLAG_SECURE) == 0U) {
			SetLastError( ERROR_INVALID_PARAMETER) ;
			return nullptr ;
		}

		activeWixWorkerHttp->path = path ;
		return activeWixWorkerHttp ;
	} ; // 共通HTTPから受けたパスを次の送信に結びます
	transport.sendRequest = []( HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR) -> BOOL {
		auto &http = *activeWixWorkerHttp ;	// 送信の呼出しごとに元宛先を保存します
		http.sends.emplace_back( http.host, http.path) ;
		http.offset = 0U ;
		return TRUE ;
	} ; // PAGE・元本体・CDNの順序を呼出し側で独立して照合します
	transport.queryHeaders = []( HINTERNET, DWORD info, LPCWSTR, LPVOID output, LPDWORD size,
								LPDWORD index) -> BOOL {
		const auto &http	 = *activeWixWorkerHttp ;		// 一要求につき一つの元HTTP応答です
		const bool	page	 = http.path == L"/support" ;	// メタデータ取得です
		const bool	redirect = http.host == L"vendor.example" &&
							  // 元アンカーの応答です
							  http.path == L"/download/fixture.exe" ;
		// StatusはWinHTTPの数値照会へ渡します
		if( info == (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER)) {
			*static_cast<DWORD *>( output) = redirect ? 301U : 200U ;
			*size						  = sizeof( DWORD) ;
			return TRUE ;
		}

		// 同名ヘッダーの二行目を探す共通照会に偽の重複を返しません
		if( index && *index != 0U) {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		std::wstring value ;	// 同じ応答に実在するヘッダーの値です
		// 通信の段階ごとに、状態やContent-Typeなど問い合わせ対象の検査値を返します
		switch( info) {
			// Content-TypeはPAGEと本体で分けます
			case WINHTTP_QUERY_CONTENT_TYPE:
				value = page ? L"text/html; charset=utf-8" : L"application/octet-stream" ;
				break ;

			// 本文と同じバイト数を宣言します
			case WINHTTP_QUERY_CONTENT_LENGTH:
				value = std::to_wstring( http.body().size()) ;
				break ;

			// 固定の同パスCDNだけを転送先として返します
			case WINHTTP_QUERY_LOCATION:
				value = !redirect ? L""
						: http.otherLocation
							? L"https://cdn.vendor.example/download/replacement.exe"
							: L"https://cdn.vendor.example/download/fixture.exe" ;
				break ;

			// 301に明示した待機は120秒間有効です
			case WINHTTP_QUERY_RETRY_AFTER:
				value = redirect && http.retryAfter ? L"120" : L"" ;
				break ;

			// その他のヘッダーを合成しません
			default:
				break ;
		}

		// 元応答に存在する値だけを返します
		if( value.empty()) {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		const auto required =
			// 終端を含む必要バイト数です
			static_cast<DWORD>( (value.size() + 1U) * sizeof( wchar_t)) ;
		// 容量照会を行位置の消費に換算しません
		if( !output || *size < required) {
			*size = required ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		std::memcpy( output, value.c_str(), required) ;
		*size = required - static_cast<DWORD>( sizeof( wchar_t)) ;
		// 同名値は本照会成功後だけ一行進めます
		if( index) {
			++*index ;
		}

		return TRUE ;
	} ; // 現要求番号に対応する応答からだけ有限値を返します
	transport.queryAvailable = []( HINTERNET, LPDWORD available) -> BOOL {
		const auto &http = *activeWixWorkerHttp ;	// PAGEかCDNの有限応答です
		*available		 = static_cast<DWORD>( http.body().size() - http.offset) ;
		return TRUE ;
	} ; // 同一本文で読み取れる残量だけを返します
	transport.readData = []( HINTERNET, LPVOID output, DWORD requested, LPDWORD read) -> BOOL {
		auto	  &http = *activeWixWorkerHttp ;	// 読取り位置を現在応答の本文内だけで進めます
		const auto body = http.body() ;				// 今の応答本文だけを借用します
		const auto count =
			std::min<std::size_t>( requested, body.size() - http.offset) ;	// 返却可能なバイト数です
		// 空本文を示す応答ではコピー元を参照しません
		if( count != 0U) {
			std::memcpy( output, body.data() + http.offset, count) ;
		}

		http.offset += count ;
		*read = static_cast<DWORD>( count) ;
		return TRUE ;
	} ; // 原バイトを共通HTTPと保護workspaceに渡します
	return transport ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常ワーカーに同じ署名索引の検査専用対象一つだけの明示取得を依頼します
 * @param[in,out] context 共通の試験集計です
 * @param[in,out] worker 隔離ストアと完全な低位fakeを使う実Workerです
 * @param[in] operationId 検索に使う操作IDです。続く取得に次のIDを使います
 * @param[in] beforePreparation 検索終端後、承認の直前に試験の低位入力だけを切り替えます
 * @param[out] reference 検索が返した表示専用参照の写しです
 * @param[out] sessionId 検索が返した元セッションです
 * @return PREPARATION_COMPLETEDイベントです。元要求または終端を欠く場合は空です
 */
//------------------------------------------------------------------------------
static std::optional<WorkerEvent> prepareWixWorkerTarget(
	TestContext &context, ProviderWorker &worker, const OperationId operationId,
	const std::function<void()> &beforePreparation, std::wstring &reference,
	ScanSessionId &sessionId)
{
	ScanOptions options ;	// 端末内Driver Storeと署名索引の入口だけを使用します
	options.useDefaultProviders = false ;
	options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
								   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
	const bool queued			= worker.requestScan( operationId, options) ;	// 本物の検索キューです
	DRIVERCRATE_EXPECT( context, queued) ;
	// 受付を欠く場合は検索からの取得成立を認定しません
	if( !queued) {
		return std::nullopt ;
	}

	const auto scanned =
		// 通常の検索終端です
		waitEvent( worker, WorkerEventKind::SCAN_COMPLETED, operationId) ;
	DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded &&
									scanned->preparationPlan &&
									scanned->preparationPlan->targets.size() == 2U) ;
	// 元計画と照合済みの表示行からだけ次の操作を組み立てます
	if( !scanned || !scanned->preparationPlan) {
		return std::nullopt ;
	}

	const auto &plan = *scanned->preparationPlan ;	// 同じ検索で発行された元計画です
	const auto	visible =
		std::ranges::find_if( scanned->scanResult.candidates, []( const auto &candidate) {
			return candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
				   candidate.preparationTargetIdentity.empty() &&
				   !candidate.inspectionTargetIdentity.empty() ;
		}) ; // 本文の通常参照と異なる表示行だけを選びます
	DRIVERCRATE_EXPECT( context,
					   visible != scanned->scanResult.candidates.end() && !visible->installable) ;
	// 検査専用の結合を持った元候補を確認できなければ承認へ進みません
	if( visible == scanned->scanResult.candidates.end()) {
		return std::nullopt ;
	}

	const auto target =
		std::ranges::find( plan.targets, visible->inspectionTargetIdentity,
						  &OfficialPreparationTarget::identity) ;	// 同じ行の元対象です
	const bool boundTarget = target != plan.targets.end() &&
							 target->terms == OfficialPreparationTerms::INSPECTION_ONLY &&
							 target->providerId == visible->providerId &&
							 // 元機器だけです
							 target->deviceCount == 1U ;
	DRIVERCRATE_EXPECT( context, boundTarget) ;
	// 策定した計画と表示行が結合しない場合は取得の入力を作りません
	if( !boundTarget) {
		return std::nullopt ;
	}

	reference = visible->identity ;
	sessionId = plan.scanSessionId ;
	OfficialPreparationApproval approval{operationId + 1U,
										 sessionId,
										 plan.planId,
										 plan.limits,
										 {}} ;	// 規約・導入意思を含まない検査承認です
	// 計画の全対象を保ちながら、元WiX一件だけを明示選択します
	for( const auto &item : plan.targets) {
		approval.decisions.push_back(
			{item, item.identity == target->identity, false, false, false}) ;
	}

	beforePreparation() ;
	const bool approved = worker.requestPreparation( approval) ;	// 承認を通常取得キューへ渡します
	DRIVERCRATE_EXPECT( context, approved) ;
	return approved
			   ? waitEvent( worker, WorkerEventKind::PREPARATION_COMPLETED, approval.operationId)
			   : std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名索引を通常ワーカーで取得し、元ページ・待機・期限・原本と導入の境界を検証します
 * @param[in,out] context 共通の試験集計です
 * @param[in] store 本文とWiXの追加欄の元バイトを持つ隔離ストアです
 * @param[in] nowUtc 両領域の有効期間内に固定する時計です
 * @param[in] expiry 追加欄の原期限です
 * @param[in] baseZip 既存の低位署名fakeを初期化する本文用の人工ZIPです
 * @param[in] payload 署名済みSHA-256に結び付けた実行不能の人工データです
 */
//------------------------------------------------------------------------------
static void testWixWorkerPreparation( TestContext							 &context,
									 const std::shared_ptr<SignedIndexStore> &store,
									 const std::chrono::sys_seconds			  nowUtc,
									 const std::chrono::sys_seconds			  expiry,
									 const std::string_view baseZip, const std::string_view payload)
{
	constexpr std::string_view PAGE =
		// 以前のページ内容を模倣せず、現在の元アンカーを返します
		R"(<html><body><a href="https://vendor.example/download/fixture.exe">Current link</a></body></html>)" ;
	constexpr std::string_view CHANGED_PAGE =
		// 公式先の別リンクです
		R"(<html><body><a href="https://vendor.example/download/replacement.exe">Replacement</a></body></html>)" ;
	constexpr std::string_view MISSING_ANCHOR =
		// コメント内の元文字列は実アンカーになりません
		R"(<html><body><!-- <a href="https://vendor.example/download/fixture.exe">Old</a> --></body></html>)" ;
	constexpr auto RETRY = static_cast<NativeError>(
		// 同workerの待機中と端末変化の原診断です
		HRESULT_FROM_WIN32( ERROR_RETRY)) ;
	constexpr auto REDIRECT_FAILED = static_cast<NativeError>( HRESULT_FROM_WIN32(
		ERROR_WINHTTP_REDIRECT_FAILED)) ;	// 301の待機または変更で転送を止めた診断です
	constexpr auto BAD_FORMAT	   = static_cast<NativeError>(
		 // 人工データのPE構造を拒否します
		 HRESULT_FROM_WIN32( ERROR_BAD_FORMAT)) ;
	using Destination =
		std::pair<std::wstring, std::wstring> ;	// 人工HTTPに渡った接続先と要求パスです
	const std::array sends{
		Destination{L"vendor.example", L"/support"},
		Destination{L"vendor.example", L"/download/fixture.exe"},
		Destination{L"cdn.vendor.example", L"/download/fixture.exe"}} ;	// 独立した正規送信順です
	/** @brief 通常ワーカーから独立して固定する各例の期待です */
	struct Case {
		/// 非機密の試験名です
		std::string_view id ;
		/// 今回の承認だけへ返す人工HTMLです
		std::string_view page ;
		/// 最初の承認での送信数です
		std::size_t		 requests ;
		/// ワーカーが通知する取得の元HRESULTです
		NativeError		 acquisitionError ;
		/// ワーカーが通知する別の内容HRESULTです
		NativeError		 contentError{} ;
	} ;
	constexpr std::array cases{
		Case{"exact-anchor", PAGE, 3U, 0U, BAD_FORMAT},
		Case{"changed-anchor", CHANGED_PAGE, 1U, static_cast<NativeError>( E_ACCESSDENIED)},
		Case{"missing-anchor", MISSING_ANCHOR, 1U, static_cast<NativeError>( E_ACCESSDENIED)},
		Case{"different-location", PAGE, 2U, REDIRECT_FAILED},
		Case{"retry-after", PAGE, 2U, REDIRECT_FAILED},
		Case{"expired", PAGE, 0U, static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT))},
		Case{"expired-while-binding", PAGE, 3U, 0U,
			 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT))},
		Case{"stale-host", PAGE, 0U,
			 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH))},
		Case{"stale-hardware", PAGE, 0U, RETRY},
		Case{"different-raw-hash", PAGE, 3U, 0U,
			 // 元応答や時計だけを変えます
			 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC))}} ;
	// ケースごとに別のworkerを所有し、待機だけは同じworker内の再スキャンで確かめます
	for( const auto &test : cases) {
		auto http  = std::make_shared<WixWorkerHttp>() ;	// 送信と原応答をworker停止まで所有します
		http->page = test.page ;
		http->payload.assign( payload) ;
		http->retryAfter	= test.id == "retry-after" ;
		http->otherLocation = test.id == "different-location" ;
		// 正常本体と同じ長さのまま一バイトだけ変え、署名済み原ハッシュを照合させます
		if( test.id == "different-raw-hash") {
			http->payload.back() ^= 1 ;
		}

		auto clock =
			std::make_shared<std::chrono::sys_seconds>( nowUtc) ;	// HTTP・署名・待機に共通の時刻です
		auto host = std::make_shared<WindowsHostPlatform>(
			WindowsHostPlatform{10U, 0U, 26100U, 9U, 1U, 0U}) ;	// 元端末はWindows 11 x64です
		auto native = std::make_shared<
			CatalogInstallFixture>() ;	// 同じinstanceの元HardwareIdsだけを切り替えます
		auto services = makeServerP4PipelineServices(
			store, clock, {}, {}) ;	// 完全な偽HTTP、回線、時計、隔離署名ストアです
		services.hostPlatform = [host, clock, http, &test, expiry] {
			// 全応答の受信後に行う端末再照会まで元期限内だった場合も保持前に失効させます
			if( test.id == "expired-while-binding" && http->sends.size() == 3U) {
				*clock = expiry ;
			}

			return WindowsHostPlatformObservation{WindowsHostObservationState::OBSERVED, *host,
												  WindowsHostErrorDomain::NTSTATUS,
												  WindowsHostObservationStage::VERSION, 0U} ;
		} ; // 同worker終端まで元時刻・応答・固定ケースを借用します
		services.httpTransport = [base = services.httpTransport, clock, http] {
			auto transport	 = wixWorkerTransport( base(), *http) ;	// 元の完全置換transportを使います
			transport.utcNow = [clock] {
				return static_cast<std::uint64_t>( clock->time_since_epoch().count()) ;
			} ;
			return transport ;
		} ; // 返却する各関数ポインタはworker寿命内の人工応答を借用します
		const auto start = [native] {
			activeNative->catalogInstall		  = native.get() ;
			activeNative->p4ExplicitClientContext = true ;
		} ; // 端末を開く既存の低位fakeの初期化完了後、同じ端末の照会だけを切り替えます
		auto bound = makeSignedIndexBindingWorker( std::move( services), baseZip, false, false, false,
												  SignedIndexBindingNativeCase::NORMAL, {},
												  start) ;	// 復元・登録・指定適用も完全なfakeです
		DRIVERCRATE_EXPECT( context, bound.worker) ;
		// 完全な低位表を得られなければ端末やHTTPを呼びません
		if( !bound.worker) {
			continue ;
		}

		const auto replaceObservation = [&] {
			// 期限後には目的のページへ接続せず、失効した同scan承認を拒否します
			if( test.id == "expired") {
				*clock = expiry ;
			}
			// 署名索引で許すOSでもscan時の完全tupleから変わった場合は拒否します
			else if( test.id == "stale-host") {
				++host->buildNumber ;
			}
			// 同じinstanceの現在HardwareIdsだけから元一致を取り除きます
			else if( test.id == "stale-hardware") {
				native->hardwareIds = L"TESTBUS\\OTHER_HARDWARE" ;
			}
		} ; // SCAN_COMPLETEDから次の要求までだけ低位の人工状態を更新します
		const auto check = [&]( const std::optional<WorkerEvent> &event,
							   const NativeError acquisitionError, const NativeError contentError) {
			DRIVERCRATE_EXPECT( context, event &&
											event->preparationResult.approvalError ==
												OfficialPreparationError::NONE &&
											event->preparationResult.controlError == 0U &&
											event->preparationResult.installResolutions.empty() &&
											event->indexPreparation.items.size() == 1U) ;
			// 取得終端のない例は、原アンカーや端末の意図した拒否として数えません
			if( !event || event->indexPreparation.items.size() != 1U) {
				return ;
			}

			const auto &item =
				// 同操作の取得・内容の公開結果です
				event->indexPreparation.items.front() ;
			const auto transfer =
				std::ranges::find( event->preparationResult.items, item.targetIdentity,
								  &OfficialPreparationItem::identity) ;	// 選択した一件の実転送です
			DRIVERCRATE_EXPECT( context, transfer != event->preparationResult.items.end() &&
											transfer->result.error == acquisitionError &&
											transfer->result.byteCount ==
												(acquisitionError == 0U ? payload.size() : 0U)) ;
			DRIVERCRATE_EXPECT(
				context, item.acquisitionError == acquisitionError &&
							 item.contentError == contentError && item.acceptedInfCount == 0U &&
							 item.inputBound == (contentError == BAD_FORMAT) &&
							 std::ranges::all_of( event->preparationResult.auditReports,
												 []( const auto &report) {
													 return report.publishedCandidates.empty() ;
												 })) ;
			// 受信完了は専用内容検査や原ハッシュの不一致とは独立した状態です
			if( acquisitionError == 0U) {
				DRIVERCRATE_EXPECT(
					context,
					transfer != event->preparationResult.items.end() &&
						transfer->result.state ==
							OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION &&
						item.acquisition == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION &&
						item.content == (item.inputBound
											 ? IndexedDriverInspectionState::INSPECTION_FAILED
											 : IndexedDriverInspectionState::INPUT_REJECTED)) ;
			}
		} ; // 検索や取得と同じ元選択の公開結果だけを読みます
		std::wstring		  reference ;				// 通常検索中の同じ端末の表示専用IDです
		ScanSessionId		  sessionId{} ;				// 通常検索が発行する元セッションです
		constexpr OperationId FIRST_SCAN = 853674U ;	// 同workerの要求は単調に進めます
		const auto			  prepared =
			prepareWixWorkerTarget( context, *bound.worker, FIRST_SCAN, replaceObservation,
								   reference, sessionId) ;	// 本物の承認を通常ワーカーへ渡します
		check( prepared, test.acquisitionError, test.contentError) ;
		DRIVERCRATE_EXPECT( context,
						   std::ranges::equal( http->sends, std::span{sends}.first( test.requests))) ;
		// 新しい元計画を使っても元301の待機を越えるまではPAGEにも接続しません
		if( http->retryAfter) {
			http->retryAfter = false ;
			*clock			 = nowUtc + std::chrono::seconds{119} ;
			check( prepareWixWorkerTarget(
					  context, *bound.worker, FIRST_SCAN + 2U, [] {}, reference, sessionId),
				  RETRY, 0U) ;
			DRIVERCRATE_EXPECT( context,
							   std::ranges::equal( http->sends, std::span{sends}.first( 2U))) ;
			*clock = nowUtc + std::chrono::seconds{120} ;
			check( prepareWixWorkerTarget(
					  context, *bound.worker, FIRST_SCAN + 4U, [] {}, reference, sessionId),
				  0U, BAD_FORMAT) ;
			DRIVERCRATE_EXPECT( context,
							   http->sends.size() == 5U &&
								   std::ranges::equal( std::span{http->sends}.subspan( 2U), sends)) ;
		}

		// 正常な原配布を取得した後も、元表示行を導入要求に渡すと実Workerが拒否します
		if( test.id == "exact-anchor" && prepared && !reference.empty()) {
			const std::array selection{reference} ;	// 元表示専用IDを明示して渡します
			const bool		 queued = bound.worker->requestInstall(
				  FIRST_SCAN + 2U, sessionId, selection, nullptr,
				  InstallProtectionMode::WINDOWS_RESTORE_POINT) ;	// 通常の導入キューです
			const auto rejected =
				queued
					? waitEvent( *bound.worker, WorkerEventKind::INSTALL_COMPLETED, FIRST_SCAN + 2U)
					: std::nullopt ;	// 本物の操作終端です
			DRIVERCRATE_EXPECT( context, rejected && !rejected->installResult.succeeded &&
											rejected->installResult.downloadError ==
												static_cast<NativeError>( E_INVALIDARG) &&
											rejected->installResult.installOutcome ==
												OutcomeCode::NOT_STARTED) ;
		}

		bound.worker->stop() ;
		const auto nativeCalls = bound.observeAfterStop() ;	// 全worker停止後の実変更境界の呼出しです
		DRIVERCRATE_EXPECT( context, nativeCalls.stages == 0U && nativeCalls.installs == 0U &&
										nativeCalls.restoreBegins == 0U &&
										bound.allNativeHandlesClosed()) ;
		std::cout << "WIX_WORKER_PREPARATION case=" << test.id
				  << " fakeSends=" << http->sends.size()
				  << " changedHardwareReads=" << native->changedHardwareReads
				  << " stages=" << nativeCalls.stages << " installs=" << nativeCalls.installs
				  << '\n' ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ選択と取得後の元規約だけを導入同意と認めることを確認します
 * @param[in,out] context 共通の試験集計です
 */
//------------------------------------------------------------------------------
static void testWixInstallConsents( TestContext &context)
{
	using signed_index_candidate_binding_detail::Access ;
	const auto terms = std::make_shared<const WixTermsPresentation>() ;			// 元操作の表示証拠です
	const auto copy	 = std::make_shared<const WixTermsPresentation>( *terms) ;	// 同じ文言の別取得です
	const std::array<std::wstring, 2U> selected{L"ordinary-fixture",
												L"wix-consent-fixture"} ;	// 混在選択です
	const std::array exact{WixInstallConsent{selected.back(), terms}} ;		// 同じ元規約を確認しました
	const std::array changed{WixInstallConsent{selected.back(), copy}} ;	// 別の表示を引き継ぎました
	const std::array duplicate{exact.front(), exact.front()} ;				// 一候補に同じ規約を重ねた要求です
	const std::array extra{													// 通常候補にも同意を移しました
						   exact.front(), WixInstallConsent{selected.front(), terms}} ;
	const std::array wrong{WixInstallConsent{selected.front(), terms}} ;	// 別候補への付け替えです
	DRIVERCRATE_EXPECT( context, Access::validateWixConsentsForFixture( terms, 83U, selected, exact)) ;
	DRIVERCRATE_EXPECT( context, !Access::validateWixConsentsForFixture( terms, 83U, selected, {})) ;
	DRIVERCRATE_EXPECT( context,
					   !Access::validateWixConsentsForFixture( terms, 83U, selected, changed)) ;
	DRIVERCRATE_EXPECT( context,
					   !Access::validateWixConsentsForFixture( terms, 83U, selected, duplicate)) ;
	DRIVERCRATE_EXPECT( context,
					   !Access::validateWixConsentsForFixture( terms, 83U, selected, extra)) ;
	DRIVERCRATE_EXPECT( context,
					   !Access::validateWixConsentsForFixture( terms, 83U, selected, wrong)) ;
	DRIVERCRATE_EXPECT( context,
					   !Access::validateWixConsentsForFixture( terms, 84U, selected, exact)) ;
	DRIVERCRATE_EXPECT( context,
					   !Access::validateWixConsentsForFixture( nullptr, 83U, selected, exact)) ;
	DRIVERCRATE_EXPECT( context, !Access::validateWixConsentsForFixture( terms, 83U, {}, exact)) ;
	DRIVERCRATE_EXPECT( context, Access::validateWixConsentsForFixture( terms, 83U, {}, {})) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名索引から通常スキャンと承認済みWiX検査取得の境界を検証します
 * @param[in,out] context 共通の試験集計です
 * @param[in] store 本文とWiXの元追加欄を保持する隔離ストアです
 * @param[in] nowUtc 両領域の有効期間内に固定する時計です
 * @param[in] expiry 追加欄の原期限と同値の拒否を検査する時刻です
 * @param[in] baseZip 既存の低位署名fakeを初期化する本文用の人工ZIPです
 * @param[in] payload 追加欄の実SHA-256に結び、転送試験に使用する非実行の人工バイト列です
 */
//------------------------------------------------------------------------------
void runWixSupplementConsumerScan( TestContext &context, std::shared_ptr<SignedIndexStore> store,
								  const std::chrono::sys_seconds nowUtc,
								  const std::chrono::sys_seconds expiry,
								  const std::string_view baseZip, const std::string_view payload)
{
	testWixInstallConsents( context) ;
	constexpr WindowsHostPlatform WIN11{10U, 0U, 26100U, 9U, 1U, 0U} ;	// 正常なWindows 11 x64です
	constexpr WindowsHostPlatform WIN10{10U, 0U, 19045U, 9U, 1U, 0U} ;	// 同じ製品種別の別OSです
	constexpr WindowsHostPlatform SERVER{10U, 0U, 26100U, 9U, 3U, 0U} ;	// 同じbuildの別製品種別です
	constexpr WindowsHostPlatform ARM64{10U, 0U, 26100U, 12U, 1U, 0U} ;	// 同じOSの別native archです
	/** @brief 元索引から推測しない端末観測と照合の期待です */
	struct ScanCase {
		/// 試験出力に使う固定名です
		std::string_view	id ;
		/// 模擬OS観測が返す元tupleです
		WindowsHostPlatform host ;
		/// 本文を含む実resolverの呼出し期待数です
		std::size_t			resolverCalls ;
		/// 本文を含む一意な端末関係の期待数です
		std::size_t			matches ;
	} ;
	// 照合を行う四例と、WiX照合を開始しない六例の独立した分母です
	constexpr std::array cases{ScanCase{"hardware", WIN11, 2U, 2U},
							   ScanCase{"changed-inspection-target", WIN11, 2U, 2U},
							   ScanCase{"compatible-only", WIN11, 2U, 1U},
							   ScanCase{"wrong-os", WIN10, 1U, 1U},
							   ScanCase{"wrong-product", SERVER, 1U, 1U},
							   ScanCase{"wrong-architecture", ARM64, 1U, 1U},
							   ScanCase{"missing-observer", WIN11, 1U, 1U},
							   ScanCase{"failed-observation", WIN11, 1U, 1U},
							   ScanCase{"expired", WIN11, 1U, 1U},
							   ScanCase{"expired-before-publication", WIN11, 2U, 2U}} ;
	const auto			 isReadOnlyReference = []( const UpdateCandidate &candidate) {
		  return candidate.providerId == SIGNED_INDEX_PROVIDER_ID &&
				 candidate.preparationTargetIdentity.empty() ;
	} ; // 表示文言に依存せず、従来の取得対象と表示専用参照を識別します
	// 各対照で同じ署名索引を再読し、前回スキャンの端末属性と観測を再利用しません
	for( const auto &fixture : cases) {
		const bool expired = fixture.id == "expired" ;	// 追加欄の原期限ちょうどです
		const bool expiresBeforePublication =
			// 照合と計画の生成時には元追加欄が有効です
			fixture.id == "expired-before-publication" ;
		const bool compatibleOnly =
			// 端末側の互換属性だけに一致を置きます
			fixture.id == "compatible-only" ;
		const bool missingObserver = fixture.id == "missing-observer" ;	// 旧対象OSだけを渡します
		const bool failedObservation =
			// 元観測がAPI失敗を返します
			fixture.id == "failed-observation" ;
		ServerP4Harness run{store, expired ? expiry : nowUtc, baseZip, fixture.id,
							fixture.host} ;	// 通常のDriver Store captureと完全な低位fakeです
		// WiXの候補結合でも試験署名の固定policyは使い、元lookupだけは走査が凍結した値を渡します
		run.services.beginHostAcquisition =
			[]( SignedIndexAcquisitionAdapter				 &issuer,
			   std::shared_ptr<const SignedIndexRecordLookup> source,
			   const IndexLookupContext context, IndexScanHostSnapshot host,
			   WindowsHostPlatformObserver					 observer,
			   const std::optional<std::chrono::sys_seconds> time) {
				return signed_index_acquisition_detail::Access::beginHostFixture(
					issuer, std::move( source), context, std::move( host), std::move( observer), time) ;
			} ; // 実際の外部policyや通信を呼ばず、人工署名を既存の有限資格へ照合します
		// 旧OSのenumは欠測とAPI失敗の場合にも同じ値を返します
		run.services.targetOs = [] { return std::optional{IndexTargetOs::WINDOWS_11} ; } ;
		// 同じ公開IDを端末のHardwareIdsから取り除き、旧本文はCompatibleIdsで一致させます
		if( compatibleOnly) {
			run.native.distributionDevices.push_back(
				{L"TESTBUS\\OTHER_HARDWARE", L"fixture.inf", L"Models.NTamd64", L"1.0.0.0",
				 L"{4d36e978-e325-11ce-bfc1-08002be10318}", L"Ports"}) ;
			run.native.opaqueCompatibleId = L"TESTBUS\\SYNTH_0001" ;
		}

		// 観測関数そのものを渡さず、同じWindows 11の旧enumだけで進まないことを検査します
		if( missingObserver) {
			run.services.hostPlatform = {} ;
		}

		// 観測関数が存在しても元APIの失敗を成功観測へ変更しません
		if( failedObservation) {
			run.services.hostPlatform = [&state = run.state] {
				++state.callbacks ;
				return WindowsHostPlatformObservation{
					WindowsHostObservationState::API_FAILED, std::nullopt,
					WindowsHostErrorDomain::NTSTATUS, WindowsHostObservationStage::VERSION,
					0xc0000001U} ;
			} ; // 同期スキャン中だけ元試行の呼出数を記録します
		}

		constexpr ScanSessionId SESSION_ID = 853572U ;	// 独立したProviderの同一スキャンを結びます
		signed_index_candidate_binding_detail::Access::bind( *run.provider, run.session,
															run.services, SESSION_ID + 100U) ;
		ScanOptions options ;	// この二経路の同期スキャンだけを実行します
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
									   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		auto scanned				= run.provider->scan(
			   SESSION_ID, options, []( const ProviderProgress &) {}) ;	// 通常の一回の端末列挙です
		const auto summary = signed_index_candidate_binding_detail::Access::cachedSummaryForFixture(
			*run.provider) ;										// 同じスキャンが保持する実照合の件数です
		const std::size_t expectedRecords	= expired ? 1U : 2U ;	// 元本文は全例に残ります
		const std::size_t expectedPublicIds = expired ? 1U : 4U ;	// 有効な追加欄の全原IDを数えます
		const bool		  hostUnavailable =
			missingObserver || failedObservation ;	// 元端末観測を確定できない二例です
		DRIVERCRATE_EXPECT(
			context,
			scanned.succeeded && summary.storeStatus == IndexStoreStatus::SNAPSHOT_READY &&
				summary.lookupStatus == IndexRecordLookupStatus::LOOKUP_READY &&
				summary.status ==
					(hostUnavailable ? IndexScanStatus::PARTIAL : IndexScanStatus::COMPLETED) &&
				summary.undeterminedRelations == (hostUnavailable ? 1U : 0U) &&
				summary.totalRecords == expectedRecords &&
				summary.processedRecords == expectedRecords && summary.remainingRecords == 0U &&
				summary.totalPublicIds == expectedPublicIds &&
				summary.processedPublicIds == expectedPublicIds) ;
		DRIVERCRATE_EXPECT(
			context,
			summary.supplementStatus == (expired ? IndexAssetSupplementStatus::EXPIRED
												 : IndexAssetSupplementStatus::BYTE_VALIDATED) &&
				(expired
					 ? !summary.supplementRecordsStatus
					 : summary.supplementRecordsStatus == IndexRecordsStatus::SCHEMA_VALIDATED)) ;
		DRIVERCRATE_EXPECT( context, summary.resolverCalls == fixture.resolverCalls &&
										summary.matchedRelations == fixture.matches &&
										summary.relatedDeviceCount == fixture.matches) ;
		// 正常hostでは元役割とワイルドカードの二件が照合されず、互換属性だけの場合は完全一致もありません
		if( fixture.resolverCalls == 2U) {
			DRIVERCRATE_EXPECT( context,
							   summary.definitiveNoRelationIds == (compatibleOnly ? 3U : 2U)) ;
		}

		DRIVERCRATE_EXPECT( context, run.state.callbacks == (missingObserver ? 0U : 1U) &&
										!run.adapter && !run.lookup) ;
		constexpr std::uint64_t PLAN_ID = 1U ;	// 新規Providerの最初の計画です
		// 通常Providerの計画が空なら同じ上限の空計画を用意します
		auto					plan = run.provider->preparationPlan( SESSION_ID, PLAN_ID)
						.value_or( OfficialPreparationPlan{
							SESSION_ID, PLAN_ID, DEFAULT_OFFICIAL_PREPARATION_LIMITS, {}}) ;
		IndexPreparationSummary preparation ;	// 同一スキャンの取得診断を受け取ります
		DRIVERCRATE_EXPECT( context, run.session.augmentPreparationPlan(
										plan, run.services, preparation, scanned.candidates) == 0U) ;
		const bool changedTarget =
			// 元対象の一項目を変える対照です
			fixture.id == "changed-inspection-target" ;
		const bool expectReference =
			// 端末の完全一致です
			fixture.id == "hardware" || changedTarget ;
		const std::size_t expectedInspectionTargets =
			expectReference || expiresBeforePublication
				? 1U
				: 0U ;	// 計画の生成時に有効な完全一致だけです
		// 正常hostの対照で従来本文と別の検査専用計画の件数を確認します
		if( expectReference || expiresBeforePublication || expired) {
			DRIVERCRATE_EXPECT( context, preparation.authorityError == 0U &&
											plan.targets.size() == 1U + expectedInspectionTargets) ;
		}

		const auto inspectionTargets = std::ranges::count(
			plan.targets, OfficialPreparationTerms::INSPECTION_ONLY,
			&OfficialPreparationTarget::terms) ;	// 別の本文候補には適用されない元条件です
		DRIVERCRATE_EXPECT( context, static_cast<std::size_t>( inspectionTargets) ==
										expectedInspectionTargets) ;

		// 照合済みの追加欄も時刻が元期限に達した場合は公開しません
		if( expiresBeforePublication) {
			*run.clock = expiry ;
		}

		const auto inspectionTarget = std::ranges::find(
			plan.targets, OfficialPreparationTerms::INSPECTION_ONLY,
			&OfficialPreparationTarget::terms) ;	// 取得issuerが元の条件で発行した対象です
		// 表示用IDを維持したまま対象の完全値を変え、結合が失敗することを確認します
		if( changedTarget && inspectionTarget != plan.targets.end()) {
			++inspectionTarget->parserRevision ;
		}

		signed_index_candidate_binding_detail::Access::publishReferences( *run.provider, plan,
																		 scanned) ;
		const auto references =
			std::ranges::count_if( scanned.candidates,
								  isReadOnlyReference) ;	// 実際に表示へ発行された行を数えます
		const auto current = std::ranges::find( scanned.candidates, true,
											   &UpdateCandidate::current) ;	// 同一端末の現在行です
		const auto indexCandidates =
			std::ranges::count( scanned.candidates, std::wstring{SIGNED_INDEX_PROVIDER_ID},
							   &UpdateCandidate::providerId) ;	// 全索引表示行です
		DRIVERCRATE_EXPECT( context, references == (expectReference ? 1 : 0) &&
										static_cast<std::size_t>( indexCandidates - references) ==
											plan.targets.size() - expectedInspectionTargets) ;
		// 取得対象に結び付く各行は、従来本文と同じ同意条件を持つ計画だけに対応します
		for( const auto &target : plan.targets) {
			// この取得対象を既存の通常導入行へ結ぶ表示候補を探します
			const auto base = std::ranges::find( scanned.candidates, target.identity,
												&UpdateCandidate::preparationTargetIdentity) ;
			// WiXは明示された検査専用で、通常の導入候補と規約同意を発行しません
			if( target.terms == OfficialPreparationTerms::INSPECTION_ONLY) {
				const auto mapped = std::ranges::count(
					scanned.candidates, target.identity,
					&UpdateCandidate::inspectionTargetIdentity) ;	// 一件の検査専用結合です
				DRIVERCRATE_EXPECT( context,
								   target.providerId == SIGNED_INDEX_PROVIDER_ID &&
									   base == scanned.candidates.end() &&
									   mapped == (expectReference && !changedTarget ? 1 : 0)) ;
				continue ;
			}

			DRIVERCRATE_EXPECT( context,
							   target.providerId == SIGNED_INDEX_PROVIDER_ID &&
								   target.terms == OfficialPreparationTerms::CONFIRMED_NO_CONSENT &&
								   base != scanned.candidates.end() &&
								   base->providerId == SIGNED_INDEX_PROVIDER_ID &&
								   base->inspectionTargetIdentity.empty()) ;
		}

		const auto reference =
			std::ranges::find_if( scanned.candidates,
								 isReadOnlyReference) ;	// 同じスキャンで発行された索引行です
		// 表示専用参照が発行された場合は元端末・元INF版と実行不可を検査します
		if( reference != scanned.candidates.end()) {
			// 同じ元取得との完全一致があった場合だけ、後続の検査に必要な元機器の関係を保持します
			if( inspectionTarget != plan.targets.end()) {
				DRIVERCRATE_EXPECT( context, signed_index_candidate_binding_detail::Access::
													wixReferenceRelationCountForFixture(
														run.session, *inspectionTarget,
														*reference) == (changedTarget ? 0U : 1U)) ;
			}

			DRIVERCRATE_EXPECT(
				context,
				current != scanned.candidates.end() && !reference->deviceIdentity.empty() &&
					reference->deviceIdentity == current->deviceIdentity &&
					reference->version == L"1.2.3.4" && !reference->detailDisplayIdentity.empty() &&
					reference->identity.starts_with( L"index-reference-") &&
					reference->discoveryBasis ==
						CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION) ;
			DRIVERCRATE_EXPECT(
				context, !reference->current && !reference->assessment && !reference->installable &&
							 !reference->recommended && !reference->allContentCached &&
							 reference->packageIdentity.empty() &&
							 reference->action == DriverAction::NONE &&
							 reference->defaultPreference == CandidateDefaultPreference::NONE) ;
			DRIVERCRATE_EXPECT(
				context,
				reference->audit.sourceOrigin == CandidateAuditGateState::PASSED &&
					reference->audit.inspectionDownload == CandidateAuditGateState::PENDING &&
					reference->audit.contentIntegrity == CandidateAuditGateState::PENDING &&
					reference->audit.systemApplicability == CandidateAuditGateState::PENDING) ;
			const std::array selection{reference->identity} ;	// 表示行を選択として直接渡します
			DRIVERCRATE_EXPECT(
				context, !run.provider->isRetainedPreparationReference( reference->identity, plan) &&
							 run.provider->beginInstallOperation( SESSION_ID + 101U, SESSION_ID,
																 selection) == E_INVALIDARG) ;
		}

		DRIVERCRATE_EXPECT( context, run.state.sends == 0U && run.native.stages == 0U &&
										run.native.installs == 0U && run.native.opens != 0U &&
										run.native.opens == run.native.closes) ;
		std::cout << "WIX_CONSUMER_SCAN case=" << fixture.id << " records=" << summary.totalRecords
				  << " resolverCalls=" << summary.resolverCalls
				  << " matches=" << summary.matchedRelations << " targets=" << plan.targets.size()
				  << " readOnlyReferences=" << references << '\n' ;
	}

	testWixWorkerPreparation( context, store, nowUtc, expiry, baseZip, payload) ;

	// 本文の取得権限がない場合も、通常workerは同じ端末の表示専用参照を終了イベントへ渡します
	auto clock = std::make_shared<std::chrono::sys_seconds>( nowUtc) ;	// 署名と照合に使う固定UTCです
	unsigned sends{} ;													// Worker停止後だけ送信回数を読みます
	auto	 services =
		// 全通信を低位fakeに限定します
		makeServerP4PipelineServices( store, clock, baseZip, {}) ;
	services.hostPlatform = [platform = WIN11] {
		return WindowsHostPlatformObservation{WindowsHostObservationState::OBSERVED, platform,
											  WindowsHostErrorDomain::NTSTATUS,
											  WindowsHostObservationStage::VERSION, 0U} ;
	} ; // 完全一致時に使った元hostを同じ固定tupleで返します
	services.beginHostAcquisition = []( auto &&...) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	} ; // 元照合を変更せず、取得権限だけを拒否します
	const auto start = [store, clock, baseZip, &sends] {
		static_cast<void>(
			makeServerP4PipelineServices( store, clock, baseZip, [&sends] { ++sends ; })) ;
	} ; // Worker内に送信observerを設定します。停止までは元fixtureが借用先を所有します
	// 実workerと同じCompositeを完全な低位fakeで動かします
	auto bound = makeSignedIndexBindingWorker( std::move( services), baseZip, false, false, false,
											  SignedIndexBindingNativeCase::NORMAL, {}, start) ;
	ScanOptions options ;	// 端末内のDriver Storeと署名索引だけを検索します
	options.useDefaultProviders		   = false ;
	options.enabledProviderIds		   = {std::wstring{DRIVER_STORE_PROVIDER_ID},
										  std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
	constexpr OperationId OPERATION_ID = 853672U ;	// 通常workerで検索一回だけを依頼します
	// Worker開始と検索の受付を同じ入力で確認します
	const bool accepted = bound.worker && bound.worker->requestScan( OPERATION_ID, options) ;
	DRIVERCRATE_EXPECT( context, accepted) ;
	// 検索の受付が成立した場合だけ終端イベントを待ちます
	if( !accepted) {
		return ;
	}

	const auto scanned = waitEvent( *bound.worker, WorkerEventKind::SCAN_COMPLETED,
								   OPERATION_ID) ;	// 空の取得計画を外部へ発行しない通常終端です
	bound.worker->stop() ;
	const auto native = bound.observeAfterStop() ;	// Workerと全低位borrowの終了後に読みます
	DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded) ;
	// 終端通知を受けた場合にだけ元照合結果・権限・表示を個別に確認します
	if( scanned) {
		const auto references = std::ranges::count_if(
			scanned->scanResult.candidates, isReadOnlyReference) ;	// UIへ発行した元参照だけです
		DRIVERCRATE_EXPECT( context, !scanned->preparationPlan && scanned->preparationError == 0U) ;
		DRIVERCRATE_EXPECT( context, scanned->indexPreparation.authorityError == E_ACCESSDENIED &&
										scanned->indexPreparation.plannedTargets == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   scanned->indexSummary.matchedRelations == 2U && references == 1) ;
		DRIVERCRATE_EXPECT(
			context, std::ranges::all_of( scanned->scanResult.candidates, []( const auto &candidate) {
				return candidate.inspectionTargetIdentity.empty() ;
			})) ;
		std::cout << "WIX_CONSUMER_SCAN case=worker-empty-plan matches="
				  << scanned->indexSummary.matchedRelations
				  << " targets=" << scanned->indexPreparation.plannedTargets
				  << " readOnlyReferences=" << references << '\n' ;
	}

	DRIVERCRATE_EXPECT( context, sends == 0U && native.stages == 0U && native.installs == 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保存済みDMを通常スキャンと選択済み取得の境界へ渡します
 * @param[in,out] context 共通の試験集計です
 * @param[in] validStore 元証拠と投影が一致する署名済み索引です
 * @param[in] invalidStore 元証拠を欠く追加欄と同じ本文を持つ署名済み索引です
 * @param[in] nowUtc 両領域の有効期間内の試験時刻です
 * @param[in] expiry DMだけが失効する試験時刻です
 * @param[in] baseZip 本文の人工ZIPです。低位署名fakeにも同じbyteを使います
 * @param[in] baseDigest 元本文全体の展開後hashです
 * @param[in] modelsDigest 元DM全体の展開後hashです
 */
//------------------------------------------------------------------------------
void runScopedModelsConsumerScan(
	TestContext &context, const std::shared_ptr<SignedIndexStore> &validStore,
	const std::shared_ptr<SignedIndexStore> &invalidStore, const std::chrono::sys_seconds nowUtc,
	const std::chrono::sys_seconds expiry, const std::string_view baseZip,
	const IndexManifestSha256 &baseDigest, const IndexManifestSha256 &modelsDigest)
{
	// 元署名証拠と同じWindows 10の正常観測点
	constexpr WindowsHostPlatform WIN10{10U, 0U, 19045U, 9U, 1U, 0U} ;
	// 同じOSでも元証拠のビルドに達しない対照
	constexpr WindowsHostPlatform LOWER_BUILD{10U, 0U, 19044U, 9U, 1U, 0U} ;
	// Windows 11で別のOS条件になる対照
	constexpr WindowsHostPlatform WIN11{10U, 0U, 26100U, 9U, 1U, 0U} ;
	// 取得承認後にのみ通信へ達したことを確認する偽接続エラー
	constexpr NativeError		  CONNECT_FAILED =
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WINHTTP_CANNOT_CONNECT)) ;
	// 承認から取得までに実環境が変わった場合の期待診断
	constexpr NativeError STALE_HOST =
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)) ;
	// 承認後に元の取得期限へ達した場合の期待診断
	constexpr NativeError EXPIRED_CLAIM =
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
	static thread_local unsigned bodyReads ;	// WinHTTP ABIのfakeコールバックが同threadで加算します
	/** @brief 原索引から導出しない端末と取得の対照です */
	struct ScanCase {
		/// ログに記録する固定入力名です
		std::string_view		   name ;
		/// スキャン開始時に観測する元tupleです
		WindowsHostPlatform		   host ;
		/// 旧本文とDMが通常取得計画に出る独立した期待値です
		bool					   baseTarget ;
		/// 同じ端末で公式Modelsの取得対象が成立することを期待する場合はtrue
		bool					   modelsTarget ;
		/// 選択済み取得まで試す場合の期待HRESULTです
		std::optional<NativeError> acquisitionError{} ;
	} ;
	// 実索引の計算を使わず固定する、対象成立と取得拒否の対照
	constexpr std::array cases{ScanCase{"hardware", WIN10, true, true, CONNECT_FAILED},
							   ScanCase{"compatible-only", WIN10, true, false},
							   ScanCase{"lower-build", LOWER_BUILD, true, false},
							   ScanCase{"other-os", WIN11, false, false},
							   ScanCase{"expired-at-scan", WIN10, true, false},
							   ScanCase{"malformed-models", WIN10, true, false},
							   ScanCase{"stale-at-claim", WIN10, true, true, STALE_HOST},
							   ScanCase{"expired-at-claim", WIN10, true, true, EXPIRED_CLAIM}} ;
	// 同じ元本文を各例の独立した端末スキャンで再認証します
	for( const auto &test : cases) {
		// 元証拠の期限ちょうどに検索する対照かを示します
		const bool expiredScan = test.name == "expired-at-scan" ;
		// 専用欄が壊れた署名済み圧縮物を読む対照かを示します
		const bool malformed = test.name == "malformed-models" ;
		// 完全Hardware ID欄に一致せずCompatible IDだけに現れる対照かを示します
		const bool compatibleOnly = test.name == "compatible-only" ;
		bodyReads				  = 0U ;
		// 対象OSや現在時刻だけを変えて同じ実検索・取得判定を呼ぶ試験環境
		ServerP4Harness run{malformed ? invalidStore : validStore, expiredScan ? expiry : nowUtc,
							baseZip, test.name, test.host} ;
		// 掲載されたNet ClassGUIDを列挙とpropertyの両方で観測します
		run.native.network = true ;
		run.native.distributionDevices.push_back(
			{compatibleOnly ? L"TESTBUS\\UNRELATED_0001" : L"testbus\\synth_0001", L"fixture.inf",
			 L"Models.NTamd64", L"1.0.0.0", L"{4d36e972-e325-11ce-bfc1-08002be10318}", L"Net"}) ;
		// 公式IDを機器のCompatible IDにだけ置き、完全Hardware IDと区別されることを確認します
		if( compatibleOnly) {
			run.native.opaqueCompatibleId = L"TESTBUS\\SYNTH_0001" ;
		}

		// 取得権限を通った場合も、元CABの代わりに人工ZIP本文を渡さずレスポンス前で停止します
		run.services.httpTransport = [transport = run.services.httpTransport, clock = run.clock]() {
			// ページ・配布応答を本物の通信なしに観測する試験用トランスポート
			auto fake	= transport() ;
			fake.utcNow = [clock] {
				return static_cast<std::uint64_t>( clock->time_since_epoch().count()) ;
			} ;
			fake.receiveResponse = []( HINTERNET, LPVOID) -> BOOL {
				SetLastError( ERROR_WINHTTP_CANNOT_CONNECT) ;
				return FALSE ;
			} ;
			fake.readData = []( HINTERNET, LPVOID, DWORD, LPDWORD) -> BOOL {
				++bodyReads ;
				SetLastError( ERROR_INVALID_FUNCTION) ;
				return FALSE ;
			} ;
			return fake ;
		} ;

		const auto plan = run.plan( context, 853370U) ;	// 通常の端末列挙・参照行と取得計画です
		// 実検索で保持した、索引読み取りと端末内照合の集計
		const auto scan =
			signed_index_candidate_binding_detail::Access::cachedSummaryForFixture( *run.provider) ;
		// 専用欄の原証拠を有効と見なせるケースの独立期待値
		const bool		  hasModels = !expiredScan && !malformed ;
		// 旧本文の一行と有効な場合の専用行を合計した期待件数
		const std::size_t expectedRecords = hasModels ? 2U : 1U ;
		// 通常候補と公式Models候補の期待成立数
		const std::size_t expectedTargets =
			static_cast<std::size_t>( test.baseTarget) + static_cast<std::size_t>( test.modelsTarget) ;
		DRIVERCRATE_EXPECT( context, scan.storeStatus == IndexStoreStatus::SNAPSHOT_READY &&
										scan.totalRecords == expectedRecords &&
										scan.processedRecords == expectedRecords &&
										scan.resolverCalls == (hasModels ? 3U : 1U) &&
										scan.error == 0U) ;
		DRIVERCRATE_EXPECT(
			context,
			scan.supplementStatus == (expiredScan ? IndexAssetSupplementStatus::EXPIRED
												  : IndexAssetSupplementStatus::BYTE_VALIDATED) &&
				(expiredScan ? !scan.supplementRecordsStatus
							 : scan.supplementRecordsStatus ==
								   (malformed ? IndexRecordsStatus::INVALID_EVIDENCE
											  : IndexRecordsStatus::SCHEMA_VALIDATED))) ;
		// 実画面の候補から索引の取得前参照だけを数えた件数
		const auto references =
			std::ranges::count_if( run.displayedCandidates, []( const auto &item) {
				return item.identity.starts_with( L"index-reference-") ;
			}) ;
		DRIVERCRATE_EXPECT( context, plan.targets.size() == expectedTargets &&
										static_cast<std::size_t>( references) == expectedTargets &&
										run.lookup && run.state.sends == 0U && bodyReads == 0U &&
										run.native.stages == 0U && run.native.installs == 0U) ;
		// 実検索の照合結果が保持されなかった場合は、その詳細を参照しません
		if( !run.lookup) {
			continue ;
		}

		// 同じ検索で実候補照合に使った署名済みの索引スナップショット
		const auto &snapshot = run.lookup->snapshot() ;
		// 通常本文と専用欄から消費者向けに解決した実レコード列
		const auto	records = snapshot.consumerRecords() ;
		DRIVERCRATE_EXPECT( context, snapshot.schemaReceipt().records().size() == 1U &&
										snapshot.schemaReceipt().indexSha256() == baseDigest &&
										records.size() == expectedRecords) ;
		// 期待分母と一致した場合だけ候補の添字へ進みます
		if( records.size() != expectedRecords) {
			continue ;
		}

		// 通常本文の原ハッシュを計画の取得対象と比較する格納先
		std::wstring baseHash ;
		DRIVERCRATE_EXPECT( context,
						   records[0U].recordId == "unchanged-base" &&
							   records[0U].recordSchemaVersion == 2U &&
							   computeBytesSha256( records[0U].originalBytes, baseHash) == 0U) ;
		// 実計画が同じ通常レコードを保持するか確認する位置
		const auto base =
			std::ranges::find( plan.targets, baseHash, &OfficialPreparationTarget::releaseIdentity) ;
		DRIVERCRATE_EXPECT( context, (base != plan.targets.end()) == test.baseTarget) ;
		// 専用行がない対照では通常本文の照合までで終了します
		if( !hasModels) {
			continue ;
		}

		// 公式範囲の証拠付きとして受理された二番目のレコード
		const auto	&models = records[1U] ;
		// 取得対象ハッシュの確認に使う、同じ元レコードのバイト範囲
		const auto	 region = snapshot.consumerRecordRegion( 1U) ;
		// 公式Modelsの元レコードの実SHA-256を受け取る文字列
		std::wstring modelsHash ;
		DRIVERCRATE_EXPECT( context,
						   models.recordId == "scoped-models" && models.recordSchemaVersion == 6U &&
							   models.scopedModelsEvidence && region.indexSha256 == modelsDigest &&
							   region.indexSha256 != baseDigest && region.expiresAtUtc == expiry &&
							   region.sources.size() == 1U &&
							   region.sources.front().sourceId == "catalog-source" &&
							   computeBytesSha256( models.originalBytes, modelsHash) == 0U) ;
		// 同じ公式Models行のハッシュから署名済みの取得対象へ解決した位置
		const auto scoped = std::ranges::find( plan.targets, modelsHash,
											  &OfficialPreparationTarget::releaseIdentity) ;
		// 実検索で得た公式Models行と端末の照合関係
		const auto relation = std::ranges::find_if( run.lookup->relations(), []( const auto &item) {
			return item.recordIndex == 1U && item.state == IndexRecordMatchState::MATCHED ;
		}) ;
		// 同じ二番目の掲載IDへの端末一致とhostによる取得許可を独立に確認します
		DRIVERCRATE_EXPECT(
			context, (scoped != plan.targets.end()) == test.modelsTarget &&
						 (relation != run.lookup->relations().end()) == !compatibleOnly &&
						 (compatibleOnly || (relation->publicIdIndex == 1U &&
											 relation->deviceProof && relation->deviceIdentity))) ;
		// 取得対象があり、かつ取得中の動作を検査するケースだけを次へ進めます
		if( scoped == plan.targets.end() || !test.acquisitionError) {
			continue ;
		}

		// 元取得対象を選ぶ候補が通常画面に表示された位置
		const auto reference = std::ranges::find( run.displayedCandidates, scoped->identity,
												 &UpdateCandidate::preparationTargetIdentity) ;
		DRIVERCRATE_EXPECT(
			context, scoped->deviceCount == 1U && reference != run.displayedCandidates.end() &&
						 !reference->installable && relation != run.lookup->relations().end() &&
						 relation->deviceIdentity &&
						 reference->deviceIdentity == *relation->deviceIdentity) ;
		// 選択は維持したまま、取得の直前に元host又は元時刻を変更します
		if( test.acquisitionError == STALE_HOST) {
			run.state.platform = LOWER_BUILD ;
		}
		// 元期限へ時刻を進めた後は選択済み取得も停止することを確認します
		else if( test.acquisitionError == EXPIRED_CLAIM) {
			*run.clock = expiry ;
		}

		// 実計画から承認と取得を開始する一操作の試験用状態
		OfficialPreparationSession preparation ;
		DRIVERCRATE_EXPECT( context, preparation.initialize( plan) == OfficialPreparationError::NONE) ;
		// 同じscan・計画・制限値に結び付いた明示取得の承認
		OfficialPreparationApproval approval{
			853371U, plan.scanSessionId, plan.planId, plan.limits, {}} ;
		// 計画上の全対象を走査し、選んだ公式Modelsだけに取得意思を付けます
		for( const auto &target : plan.targets) {
			approval.decisions.push_back(
				{target, target.identity == scoped->identity, false, false, false}) ;
		}

		// 借用中の試験文脈で通常の取得入口を実行した結果
		const auto acquired = executeOfficialPreparation(
			preparation, approval,
			[&]( const OfficialPreparationTask &task, const PreparationCancellation &cancel) {
				return run.session.acquireForInspection( preparation, task, run.services, cancel) ;
			},
			[] { return false ; }, []( const OfficialPreparationProgress &) {}) ;
		// 同じ承認済み操作について保持された項目ごとの診断
		const auto summary = run.session.preparationSummary( approval.operationId) ;
		DRIVERCRATE_EXPECT( context,
						   acquired.approvalError == OfficialPreparationError::NONE &&
							   acquired.controlError == 0U && summary.items.size() == 1U &&
							   summary.items.front().targetIdentity == scoped->identity &&
							   summary.items.front().acquisitionError == *test.acquisitionError &&
							   !summary.items.front().inputBound &&
							   summary.items.front().acceptedInfCount == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   run.state.sends == (test.acquisitionError == CONNECT_FAILED ? 1U : 0U) &&
							   bodyReads == 0U && run.native.stages == 0U &&
							   run.native.installs == 0U && run.native.opens == run.native.closes) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 認証済みAWS原レコードを通常のscanと取得承認に渡します
 * @param[in,out] context 共通試験集計です
 * @param[in] store 原manifestと索引を保存した隔離storeです
 * @param[in] nowUtc 原期限内に固定した試験時計です
 * @param[in] zip hash照合済みの保存ZIPです
 * @param[in] signatureZip 本文前停止を維持したまま既署名fakeを初期化する人工ZIPです
 * @note 実取得先へ接続せず、確認後のfake応答は本文前で停止します
 */
//------------------------------------------------------------------------------
void runSavedAwsConsumerPlan( TestContext &context, std::shared_ptr<SignedIndexStore> store,
							 const std::chrono::sys_seconds nowUtc, const std::string_view zip,
							 const std::string_view signatureZip)
{
	/** @brief 元recordと独立した期待値を持つ観測対照です */
	struct HostCase {
		/// ログに残す固定入力名です
		std::string_view	name ;
		/// 低位fakeが観測する完全OS tupleです
		WindowsHostPlatform platform ;
		/// 元recordを一件計画に出す条件です
		bool				targetExpected ;
	} ;
	// 正常とOS・architectureの各対照です
	constexpr std::array hosts{
		HostCase{"server-2025-x64", {10U, 0U, 26100U, 9U, 3U, 0U}, true},
		HostCase{"server-2022-x64", {10U, 0U, 20348U, 9U, 3U, 0U}, false},
		HostCase{"client-26100-x64", {10U, 0U, 26100U, 9U, 1U, 0U}, false},
		HostCase{"server-2025-arm64", {10U, 0U, 26100U, 12U, 3U, 0U}, false}} ;
	// 元公式条件の完全表示文です。計画から期待値を生成しません
	constexpr std::wstring_view prereq =
		L"Confirm the device is an Amazon EC2 Nitro System EBS NVMe device and the official AWS "
		L"driver applies to this instance.\r\n" ;
	static thread_local unsigned bodyReads ;	// 低位関数ポインターが同threadで本文要求を数えます
	// 同じ原索引を異なるhost観測へ独立して結びます
	for( const auto &host : hosts) {
		// 他のhostの観測を引き継ぎません
		bodyReads = 0U ;
		ServerP4Harness run{
			store,		   nowUtc, zip,			host.name,
			host.platform, 1U,	   signatureZip} ;	// 保存ZIPはHTTP本文、人工ZIPは未到達の署名用です
		// 原配布key IDを製品の独立取得policyで検査します
		run.services.beginHostAcquisition = {} ;
		// 属性と列挙へ同じSCSIAdapter ClassGUIDを返します
		run.native.storage = true ;
		run.native.distributionDevices.push_back(
			{L"PCI\\VEN_1D0F&DEV_0061", L"AWSNVMe.inf", L"AWSNVME.NTamd64.10.0", L"1.8.2.53",
			 L"{4D36E97B-E325-11CE-BFC1-08002BE10318}", L"SCSIAdapter"}) ;
		run.services.httpTransport = [transport = run.services.httpTransport, nowUtc]() {
			auto fake	= transport() ;	// DNS、open、sendを含む既完全表です
			fake.utcNow = [nowUtc]() {
				return static_cast<std::uint64_t>( nowUtc.time_since_epoch().count()) ;
			} ; // grant発行と同じ試験時計です
			fake.receiveResponse = []( HINTERNET, LPVOID) -> BOOL {
				SetLastError( ERROR_WINHTTP_CANNOT_CONNECT) ;
				return FALSE ;
			} ; // 確認済みでsendへ進んでも原ZIPを内容検査へ渡しません
			fake.readData = []( HINTERNET, LPVOID, DWORD, LPDWORD) -> BOOL {
				++bodyReads ;
				SetLastError( ERROR_INVALID_FUNCTION) ;
				return FALSE ;
			} ;
			return fake ;
		} ;
		const auto plan = run.plan( context, 853350U) ;	// 通常のscan、認証lookup、計画です
		const auto references =
			std::ranges::count_if( run.displayedCandidates, []( const auto &item) {
				return item.identity.starts_with( L"index-reference-") ;
			}) ; // 通常表示の未取得参照です
		const std::size_t expectedTargets = host.targetExpected ? 1U : 0U ;	// 固定観測別の件数です
		DRIVERCRATE_EXPECT( context, plan.targets.size() == expectedTargets &&
										static_cast<std::size_t>( references) == expectedTargets &&
										run.state.sends == 0U && bodyReads == 0U &&
										run.native.stages == 0U && run.native.installs == 0U) ;
		std::cout << "AWS_SAVED_PLAN host=" << host.name << " targets=" << plan.targets.size()
				  << " references=" << references << " sends=" << run.state.sends << '\n' ;
		// 計画のない観測やfixture失敗を承認試験へ渡しません
		if( !host.targetExpected || plan.targets.size() != 1U) {
			continue ;
		}

		const auto &target = plan.targets.front() ;	// 通常計画が組み立てた完全snapshotです
		DRIVERCRATE_EXPECT(
			context, target.providerId == SIGNED_INDEX_PROVIDER_ID &&
						 target.releaseIdentity ==
							 L"55ebc323f1f440bcef95d2985403460af31c4d593c9340b13c642ece84e4239c" &&
						 target.terms == OfficialPreparationTerms::CONFIRMED_NO_CONSENT &&
						 target.requiresPrerequisiteConfirmation &&
						 target.prerequisiteText == prereq) ;
		OfficialPreparationSession preparation ;	// 通常承認と取得予約の所有者です
		DRIVERCRATE_EXPECT( context, preparation.initialize( plan) == OfficialPreparationError::NONE) ;
		// 元planの選択だけを保持する本人承認です
		OfficialPreparationApproval approval{853351U,
											 plan.scanSessionId,
											 plan.planId,
											 plan.limits,
											 {{target, true, false, false, false}}} ;
		unsigned					dispatches{} ;	// 承認後にだけ呼ばれる取得入口を数えます
		// 条件確認だけを変え、同じ通常承認入口を使います
		const auto					execute = [&]() {
			 return executeOfficialPreparation(
				 preparation, approval,
				 [&]( const OfficialPreparationTask &task, const PreparationCancellation &cancel) {
					 ++dispatches ;
					 return run.session.acquireForInspection( preparation, task, run.services,
																			 cancel) ;
				 },
				 [] { return false ; }, []( const OfficialPreparationProgress &) {}) ;
		} ;
		const auto unconfirmed = execute() ;	// 同元選択でNitro確認だけがない操作です
		DRIVERCRATE_EXPECT(
			context, unconfirmed.approvalError == OfficialPreparationError::INVALID_APPROVAL &&
						 dispatches == 0U && run.state.sends == 0U && bodyReads == 0U) ;
		++approval.operationId ;
		// 同元選択の新しい明示確認です
		approval.decisions.front().prerequisitesConfirmed = true ;
		const auto confirmed							  = execute() ;					// 同じ経路の確認済み結果です
		const auto summary = run.session.preparationSummary( approval.operationId) ;	// 元取得結果です
		// 期待する応答停止の元HRESULTです
		const auto error =
			summary.items.empty() ? NativeError{} : summary.items.front().acquisitionError ;
		DRIVERCRATE_EXPECT( context, confirmed.approvalError == OfficialPreparationError::NONE &&
										dispatches == 1U && run.state.sends == 1U &&
										bodyReads == 0U && summary.items.size() == 1U &&
										error == static_cast<NativeError>( HRESULT_FROM_WIN32(
													 ERROR_WINHTTP_CANNOT_CONNECT)) &&
										run.native.stages == 0U && run.native.installs == 0U) ;
		std::cout << "AWS_SAVED_APPROVAL unconfirmed="
				  << static_cast<unsigned>( unconfirmed.approvalError)
				  << " confirmed=" << static_cast<unsigned>( confirmed.approvalError)
				  << " dispatches=" << dispatches << " fakeSends=" << run.state.sends
				  << " bodyReads=" << bodyReads << " acquisitionError=" << error << '\n' ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 保存した公式応答を、端末の実照合・明示同意・取得検査へ渡します
 * @param[in,out] context 有限assertionの集計です
 * @param[in] store RAM鍵で認証した隔離索引です
 * @param[in] now 元候補期限内の同じUTCです
 * @param[in] bodies 元配布ページ、規約文書、ZIPです。HTTP代役だけへ渡します
 * @param[in] device 認証済みINFに結ぶ架空端末です
 * @param[in] retained 元ZIPを一件目で保護し二件目で再利用する独立計画です
 */
//------------------------------------------------------------------------------
void runSavedArchiveTermsConsumer( TestContext &context, std::shared_ptr<SignedIndexStore> store,
								  const std::chrono::sys_seconds		 now,
								  const std::array<std::string_view, 3> &bodies,
								  const DistributionBindingDevice &device, const bool retained)
{
	// 正常文書と承認後の差し替えを、独立した通常スキャンから確認します
	for( const bool changed : {false, true}) {
		const driver_package_signature_detail::OriginalInfMetadata originalInf{
			L"ena.inf", L"c5621773ad2c97d1ae05190293df1a630142458f6e3e82c0627284c71894ed9c",
			L"ena.cat"} ;	// 開発時にWindows署名と全依存を照合した元INFの固定値です
		// 保存済みの偽応答と元INFを使い、実通信なしにServerの照合を実行する試験環境
		ServerP4Harness run{
			store, now, bodies[2],	"saved-archive-terms", {10U, 0U, 26100U, 9U, 3U, 0U},
			1U,	   {},	originalInf} ;
		run.services.beginHostAcquisition = {} ;
		run.native.distributionDevices.push_back( device) ;
		run.native.originalIntelArchive = true ;
		run.native.originalInfs.push_back( originalInf) ;
		std::function<std::size_t()> sends ;	// このケースの同じfake HTTPだけを数えます
		run.services.httpTransport =
			archiveTermsConsumerTransport( bodies, now, changed, retained, sends) ;
		auto	   plan = run.plan( context, 853380U) ;	// 本体に先行する規約だけを表示へ結びます
		const auto targetCount = retained ? 2U : 1U ;	// 原期限の異なる行は個別承認を必要とします
		std::cout << "ARCHIVE_TERMS_PLAN targets=" << plan.targets.size() << " sends=" << sends()
				  << '\n' ;
		DRIVERCRATE_EXPECT( context,
						   plan.targets.size() == targetCount && sends() == targetCount * 2U) ;
		// 必要な元規約と対象が表示できたケースだけを承認します
		if( plan.targets.size() != targetCount) {
			continue ;
		}

		const auto target = plan.targets.front() ;	// 次計画から除外する元取得対象です
		DRIVERCRATE_EXPECT( context, target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED &&
										!target.eulaText.empty() &&
										target.eulaRevision == L"April 18, 2008") ;
		OfficialPreparationSession preparation ;	// 同意を消費する同じ状態機械です
		DRIVERCRATE_EXPECT( context, preparation.initialize( plan) == OfficialPreparationError::NONE) ;
		OfficialPreparationApproval approval{
			853381U,
			plan.scanSessionId,
			plan.planId,
			plan.limits,
			{{target, true, false, false, false}}} ;	// 元選択だけを持つ初回入力です
		// 二対象の計画でも、初回は別対象を未選択として渡します
		if( retained) {
			approval.decisions.push_back( {plan.targets.back(), false, false, false, false}) ;
		}

		const auto execute = [&] {
			return executeOfficialPreparation(
				preparation, approval,
				[&]( const OfficialPreparationTask &task, const PreparationCancellation &cancel) {
					return run.session.acquireForInspection( preparation, task, run.services,
															cancel) ;
				},
				[] { return false ; }, []( const OfficialPreparationProgress &) {}) ;
		} ; // 同じfixtureを選択・同意の違いだけで同期実行します
		const auto declined = execute() ;	// 同意がなければ追加の二応答も取得しません
		DRIVERCRATE_EXPECT( context,
						   declined.approvalError == OfficialPreparationError::INVALID_APPROVAL &&
							   sends() == targetCount * 2U) ;
		++approval.operationId ;
		approval.decisions.front().eulaAccepted			  = true ;
		approval.decisions.front().prerequisitesConfirmed = target.requiresPrerequisiteConfirmation ;
		const auto accepted = execute() ;	// 元本文と元対象に対する明示同意です
		const auto summary =
			// 元取得とZIP検査を別に確認します
			run.session.preparationSummary( approval.operationId) ;
		const bool firstChanged = changed && !retained ;	// 再利用の対照では二件目だけを変えます
		DRIVERCRATE_EXPECT( context, accepted.approvalError == OfficialPreparationError::NONE &&
										summary.items.size() == 1U &&
										sends() == targetCount * 2U + (firstChanged ? 2U : 3U) &&
										run.native.installs == 0U) ;
		// 規約ポリシーで停止した場合と、本体を実検査した場合を区別します
		if( summary.items.size() != 1U) {
			continue ;
		}

		const auto &item = summary.items.front() ;	// 同じ準備操作の非機密結果です
		std::cout << "ARCHIVE_TERMS_CONSUMER changed=" << firstChanged << " sends=" << sends()
				  << " acquisitionError=" << item.acquisitionError
				  << " contentError=" << item.contentError << '\n' ;
		DRIVERCRATE_EXPECT( context, firstChanged
										? item.acquisitionError != 0U && !item.inputBound
										: item.acquisitionError == 0U && item.contentError == 0U &&
											  item.inputBound && item.acceptedInfCount == 1U &&
											  !item.reusedOwnedBody) ;
		// 一件目の元ZIPが確保された対照だけを、同scanの独立した次の承認へ進めます
		if( !retained || !item.inputBound) {
			continue ;
		}

		plan.targets.erase( plan.targets.begin()) ;
		++plan.planId ;
		// 次の同意を試せるよう、一対象の計画が保持され取得セッションが初期化されたことを示します
		const bool nextReady = run.session.retainPreparationPlan( plan, run.services) &&
							   plan.targets.size() == 1U &&
							   preparation.initialize( plan) == OfficialPreparationError::NONE ;
		DRIVERCRATE_EXPECT( context, nextReady) ;
		// 元同意を再利用せず、確定した次計画だけを新しい操作へ渡します
		if( !nextReady) {
			continue ;
		}

		++approval.operationId ;
		approval.planId	   = plan.planId ;
		approval.decisions = {{plan.targets.front(), true, true, false,
							   plan.targets.front().requiresPrerequisiteConfirmation}} ;
		const auto local   = execute() ;	// 同じZIPを取得せずに別レコードで再検査します
		// 既に取得した元配布の再検査で、無通信だったことを確認する個別結果
		const auto localSummary = run.session.preparationSummary( approval.operationId) ;
		DRIVERCRATE_EXPECT( context, local.approvalError == OfficialPreparationError::NONE &&
										localSummary.items.size() == 1U && sends() == 9U &&
										run.native.installs == 0U) ;
		// 変更対照は再利用を承認せず、正常対照は元ZIPから独立の内容検査へ到達します
		if( localSummary.items.size() == 1U) {
			const auto &localItem = localSummary.items.front() ;	// 別承認に属する原結果です
			std::cout << "ARCHIVE_TERMS_REUSE changed=" << changed << " sends=" << sends()
					  << " acquisitionError=" << localItem.acquisitionError
					  << " contentError=" << localItem.contentError
					  << " reused=" << localItem.reusedOwnedBody << '\n' ;
			DRIVERCRATE_EXPECT( context,
							   changed ? localItem.acquisitionError != 0U &&
											 !localItem.inputBound && !localItem.reusedOwnedBody
									   : localItem.acquisitionError == 0U &&
											 localItem.contentError == 0U && localItem.inputBound &&
											 localItem.acceptedInfCount == 1U &&
											 localItem.reusedOwnedBody) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 正規Client最低build条件の実scan・取得と同context拒否を一入力ずつ確認します
 * @param[in,out] context 独立期待のassertion集計先です
 * @param[in] store RAM実署名・通常codecと隔離commitを通した索引です
 * @param[in] nowUtc 原人工索引の有効時刻です
 * @param[in] zip 選択recordのhash/sizeと一致する人工原archiveです
 * @param[in] caseId 事前固定した一意入力IDです
 * @param[in] platform 初回host六fieldの独立literalです
 * @param[in] expectedTargets 事前固定した通常取得計画の件数です
 * @param[in] changedBuild action時の一field差です。旧分母の既定26100を保持します
 * @param[in] planOnly trueは通常計画までの対照で、取得到達へ換算しません
 * @note 成功candidate/reference/lookupを合成せず、完全低位fakeだけを使います
 */
//------------------------------------------------------------------------------
void runClientMinimumBuildConsumerCase( TestContext						&context,
									   std::shared_ptr<SignedIndexStore> store,
									   const std::chrono::sys_seconds	 nowUtc,
									   const std::string_view zip, const std::string_view caseId,
									   const WindowsHostPlatform platform,
									   const std::size_t		 expectedTargets,
									   const unsigned			 changedBuild = 26100U,
									   const bool				 planOnly	  = false)
{
	const auto		beforeFailures = context.failureCount() ;	// 原失敗はcaseごとに消しません
	// 取得前と同じ元候補を保持して再試行する対照かを示します
	const bool		retained = caseId == "R01_RETAINED_CHANGED_HOST" ;
	// 現在OSの個別対照と署名済み索引を接続する試験環境
	ServerP4Harness run{std::move( store), nowUtc, zip, caseId, platform, retained ? 2U : 1U} ;
	bool			action{} ;	// 初回原hostと取得以降のfaultを分離します
	run.services.hostPlatform = [&]() {
		++run.state.callbacks ;
		++run.state.phaseCalls ;
		// OS観測の成功を前提に、Windowsの元ビルドと診断を保持する初期値
		WindowsHostPlatformObservation value{WindowsHostObservationState::OBSERVED, platform,
											 WindowsHostErrorDomain::NTSTATUS,
											 WindowsHostObservationStage::VERSION, 0U} ;
		// 初回未観測からlegacy成功tupleを補完しません
		if( caseId == "L04_FULLHOST_MISSING") {
			return WindowsHostPlatformObservation{} ;
		}

		const bool freshFault =
			action &&
			(caseId == "A01_FRESH_BUILD" || caseId == "A02_FRESH_PRODUCT" ||
			 caseId == "A03_FRESH_NATIVE_FAILURE" ||
			 (caseId == "A05_DIRECT_AFTER_PAYLOAD" && run.state.sends != 0U) ||
			 (caseId == "A06_AUDIT_CHANGED_HOST" && run.state.phase == 1U) ||
			 (caseId == "A07_FINAL_PAIR_CHANGED_HOST" && run.state.phase == 2U &&
			  run.state.phaseCalls == 3U) ||
			 (retained && run.state.phase == 3U)) ;	// 固定phaseの観測だけに一faultを与えます
		// 正例と未到達phaseは元literal値を返します
		if( !freshFault) {
			return value ;
		}

		// 原NTSTATUSのdomain/bitsをlocal HRESULTと分けます
		if( caseId == "A03_FRESH_NATIVE_FAILURE") {
			return WindowsHostPlatformObservation{WindowsHostObservationState::API_FAILED,
												  std::nullopt, WindowsHostErrorDomain::NTSTATUS,
												  WindowsHostObservationStage::VERSION,
												  0xc0000001U} ;
		}

		// 同base buildのclient→Server差もSTALEとして扱います
		if( caseId == "A02_FRESH_PRODUCT") {
			value.value->productType = 3U ;
		} else { // 他のhost負例は元build一fieldだけを変えます
			value.value->buildNumber = changedBuild ;
		}

		return value ;
	} ;
	signed_index_candidate_binding_detail::Access::observePublication(
		[]( const signed_index_candidate_binding_detail::PublicationDiagnostic &value,
		   void																  *raw) noexcept {
			// 実stage3通知だけをtoken発行として観測します
			if( value.stage == 3U) {
				++static_cast<ServerP4Observation *>( raw)->minted ;
			}
		},
		&run.state) ;
	const auto resetPublication = std::unique_ptr<void, void ( *)( void *)>{
		&run.state, []( void *) {
			signed_index_candidate_binding_detail::Access::observePublication( nullptr, nullptr) ;
		}} ; // 全正常/例外経路で私有callback借用を解除します
	auto	   plan = run.plan( context, 853341U) ;	// 通常native-owned scanと元factoryです
	const auto referenceCount =
		std::ranges::count_if( run.displayedCandidates, []( const auto &candidate) {
			return candidate.identity.starts_with( L"index-reference-") ;
		}) ; // 未取得の表示参照だけを数えます
	DRIVERCRATE_EXPECT( context, plan.targets.size() == expectedTargets &&
									static_cast<std::size_t>( referenceCount) == expectedTargets &&
									run.state.sends == 0U && run.state.minted == 0U) ;
	std::cout << "CLIENT_BUILD_SCAN case=" << caseId << " targets=" << plan.targets.size()
			  << " references=" << referenceCount << " sends=" << run.state.sends
			  << " callbacks=" << run.state.callbacks << '\n' ;
	// 対象外でも他recordのindex/参照/計画は使用可能です
	if( caseId.ends_with( "OTHER_NONE") && run.lookup && !plan.targets.empty()) {
		// 最低ビルドの条件が異なる二つのレコードを読んだ索引の実内容
		const auto records = run.lookup->snapshot().schemaReceipt().records() ;
		DRIVERCRATE_EXPECT( context, records.size() == 2U) ;
		std::wstring oldHash ;	// 実認証済み旧rawから得た独立SHAです
		// 最低ビルドを持たない旧レコードが同じ索引に残ることを確認する位置
		const auto	 old = std::ranges::find_if(
			  records, []( const auto &record) { return record.recordId == "legacy-none" ; }) ;
		DRIVERCRATE_EXPECT( context, old != records.end() &&
										computeBytesSha256( old->originalBytes, oldHash) == 0U &&
										plan.targets.front().releaseIdentity == oldHash &&
										old->acquisitionDescriptor &&
										old->acquisitionDescriptor->prerequisites.items.empty()) ;
	}

	// 計画不成立のcaseはterms/payload/input/token/Providerへ進めません
	if( expectedTargets == 0U || plan.targets.size() != expectedTargets) {
		DRIVERCRATE_EXPECT( context, run.native.installs == 0U && run.native.stages == 0U) ;
		std::cout << "CLIENT_BUILD_CASE case=" << caseId
				  << " acquired=0 input=0 token=" << run.state.minted
				  << " provider=" << run.native.installs
				  << " failures=" << context.failureCount() - beforeFailures << '\n' ;
		return ;
	}

	// これらは通常表示/計画の対照に留め、取得成功へ換算しません
	if( planOnly || caseId == "L03_ABOVE26201" || caseId == "L09_EXISTING_SERVER" ||
	   caseId == "L05_MALFORMED_GUID_OTHER_NONE" || caseId == "L06_UNKNOWN_RESERVED_OTHER_NONE") {
		std::cout << "CLIENT_BUILD_CASE case=" << caseId
				  << " planOnly=1 sends=0 token=0 provider=0 failures="
				  << context.failureCount() - beforeFailures << '\n' ;
		return ;
	}

	DRIVERCRATE_EXPECT( context, run.adapter && run.lookup) ;
	// 元lookup欠損を後段拒否の成功として数えません
	if( !run.adapter || !run.lookup) {
		throw std::runtime_error(
			"Client minimum-build authenticated acquisition prerequisite missing") ;
	}

	// 承認前の通信呼出し回数。早期拒否による通信ゼロを差分で確認します
	const auto beforeActionCallbacks = run.state.callbacks ;
	// 元が非constの独立lookup copyだけへ一byteのrecord hash不一致を与えます
	if( caseId == "A04_OWNER_HASH_FIRST") {
		auto relations = run.lookup->relations() ;	// 元認証snapshotの原byteは変更しません
		DRIVERCRATE_EXPECT( context, !relations.empty()) ;
		// 有効な元relationがないfixtureは狙った拒否へ数えません
		if( relations.empty()) {
			throw std::runtime_error( "Client minimum-build owner hash premise missing") ;
		}

		const_cast<IndexRecordRelation &>( relations.front()).recordSha256[0] ^= 1U ;
	}

	action = true ;
	OfficialPreparationSession preparation ;	// 実承認/予約/入力所有のownerです
	const auto				   execute = [&]( const OfficialPreparationPlan &selectedPlan,
							 const OperationId operation, const std::size_t selected) {
		DRIVERCRATE_EXPECT( context,
										   preparation.initialize( selectedPlan) == OfficialPreparationError::NONE) ;
		// 選んだ操作と計画にだけ用いる一時的な明示取得承認
		OfficialPreparationApproval approval{
			operation, selectedPlan.scanSessionId, selectedPlan.planId, selectedPlan.limits, {}} ;
		// 元計画の各選択/非選択を本人の明示承認へ結びます
		for( std::size_t index = 0U; index < selectedPlan.targets.size(); ++index) {
			approval.decisions.push_back(
				{selectedPlan.targets[index], index == selected, false, false, false}) ;
		}

		return executeOfficialPreparation(
			preparation, approval,
			[&]( const OfficialPreparationTask &task, const PreparationCancellation &cancel) {
				return run.session.acquireForInspection( preparation, task, run.services, cancel) ;
			},
			[] { return false ; }, []( const OfficialPreparationProgress &) {}) ;
	} ;
	// 同じ計画への最初の承認で通常の取得を実行した結果
	const auto acquired = execute( plan, 3401U, 0U) ;
	// 最初の操作の取得・検査診断を項目ごとに確認する要約
	const auto summary = run.session.preparationSummary( 3401U) ;
	// 取得後に検査へ引き継ぐ、元計画の取得対象と内容の結合
	const auto input = signed_index_candidate_binding_detail::Access::inspectionInputForFixture(
		run.session, plan.targets.front().identity) ;
	DRIVERCRATE_EXPECT( context, acquired.approvalError == OfficialPreparationError::NONE &&
									acquired.controlError == 0U && summary.items.size() == 1U) ;
	// 最初の項目で実際に記録された取得側の診断値。結果なしは0
	const auto acquisitionError =
		summary.items.empty() ? 0U
							  : static_cast<std::uint32_t>( summary.items.front().acquisitionError) ;
	// 最初の項目で実際に記録された内容検査側の診断値。結果なしは0
	const auto contentError =
		summary.items.empty() ? 0U : static_cast<std::uint32_t>( summary.items.front().contentError) ;
	std::cout << "CLIENT_BUILD_ACQUIRE case=" << caseId << " sends=" << run.state.sends
			  << " input=" << static_cast<bool>( input) << " acquisitionError=" << acquisitionError
			  << " contentError=" << contentError << " callbacks=" << run.state.callbacks << '\n' ;
	// 元OSまたは承認の照合で、ファイル取得前に停止する対照かを示します
	const bool earlyFault = caseId == "A01_FRESH_BUILD" || caseId == "A02_FRESH_PRODUCT" ||
							caseId == "A03_FRESH_NATIVE_FAILURE" ||
							caseId == "A04_OWNER_HASH_FIRST" ;
	// 元純粋/host拒否をsend後の内容拒否へ読み替えません
	if( earlyFault || caseId == "A05_DIRECT_AFTER_PAYLOAD") {
		// 各早期拒否の原因が区別できることを照合する期待診断
		const auto expected =
			caseId == "A04_OWNER_HASH_FIRST" ? static_cast<NativeError>( E_ACCESSDENIED)
			: caseId == "A03_FRESH_NATIVE_FAILURE"
				? static_cast<NativeError>( E_NOTIMPL)
				: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)) ;
		DRIVERCRATE_EXPECT( context, !input && run.state.sends == (earlyFault ? 0U : 1U) &&
										run.state.minted == 0U &&
										(earlyFault ? acquisitionError : contentError) ==
											static_cast<std::uint32_t>( expected)) ;
		// 純粋record hash拒否はhost callbackを消費しません
		if( caseId == "A04_OWNER_HASH_FIRST") {
			DRIVERCRATE_EXPECT( context, run.state.callbacks == beforeActionCallbacks) ;
		}
	} else { // 正常取得の原byte/内容合格を確認してから監査します
		DRIVERCRATE_EXPECT( context, input && input->byteCount == zip.size() &&
										run.state.sends == 1U && acquisitionError == 0U &&
										contentError == 0U &&
										summary.items.front().acceptedInfCount == 1U) ;
		run.state.phase		 = 1U ;
		run.state.phaseCalls = 0U ;
		// 取得結果から公式候補へ昇格させる実監査の報告
		const auto					 reports = run.provider->preparationAuditReports( acquired) ;
		std::vector<UpdateCandidate> candidates ;	// 実監査出力だけを保持します
		// 実発行された候補以外を補完しません
		for( const auto &report : reports) {
			candidates.insert( candidates.end(), report.publishedCandidates.begin(),
							  report.publishedCandidates.end()) ;
		}

		// 取得後の監査までにOS条件が変化する対照かを示します
		const bool auditFault = caseId == "A06_AUDIT_CHANGED_HOST" ;
		DRIVERCRATE_EXPECT( context, candidates.size() == (auditFault ? 0U : 1U) &&
										run.state.minted == (auditFault ? 0U : 1U)) ;
		std::cout << "CLIENT_BUILD_AUDIT case=" << caseId << " reports=" << reports.size()
				  << " candidates=" << candidates.size() << " token=" << run.state.minted
				  << " callbacks=" << run.state.callbacks << '\n' ;
		// Bは全純粋関係確認後、同host再観測の拒否でinputを発行しません
		if( retained && input && candidates.size() == 1U) {
			// 後続操作で同じ配布を選び直す試験用の計画コピー
			auto next = plan ;
			next.targets.erase( next.targets.begin()) ;
			++next.planId ;
			DRIVERCRATE_EXPECT( context, run.session.retainPreparationPlan( next, run.services)) ;
			run.state.phase		 = 3U ;
			run.state.phaseCalls = 0U ;
			// 別操作IDで保持候補の同じ取得を承認した結果
			const auto second = execute( next, 3402U, 0U) ;
			// 後続操作で通信や適用がどう扱われたかを確認する診断
			const auto secondSummary = run.session.preparationSummary( 3402U) ;
			// 別操作に引き継いだ元配布と検査結果の結合
			const auto secondInput =
				signed_index_candidate_binding_detail::Access::inspectionInputForFixture(
					run.session, next.targets.front().identity) ;
			DRIVERCRATE_EXPECT( context,
							   second.approvalError == OfficialPreparationError::NONE &&
								   second.controlError == 0U && secondSummary.items.size() == 1U &&
								   secondSummary.items.front().reusedOwnedBody && !secondInput &&
								   run.state.sends == 1U && run.state.phaseCalls == 1U &&
								   secondSummary.items.front().contentError ==
									   HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)) ;
			std::cout
				<< "CLIENT_BUILD_RETAINED case=" << caseId
				<< " items=" << secondSummary.items.size()
				<< " input=" << static_cast<bool>( secondInput) << " sends=" << run.state.sends
				<< " phaseCalls=" << run.state.phaseCalls
				<< " approval=" << static_cast<unsigned>( second.approvalError)
				<< " control=" << static_cast<std::uint32_t>( second.controlError) << " reused="
				<< (!secondSummary.items.empty() && secondSummary.items.front().reusedOwnedBody)
				<< " acquisitionError="
				<< (secondSummary.items.empty()
						? 0U
						: static_cast<std::uint32_t>( secondSummary.items.front().acquisitionError))
				<< " contentError="
				<< (secondSummary.items.empty()
						? 0U
						: static_cast<std::uint32_t>( secondSummary.items.front().contentError))
				<< '\n' ;
		}

		// 正候補成立後、最終pairの第三host境界だけを変化させます
		if( caseId == "A07_FINAL_PAIR_CHANGED_HOST" && candidates.size() == 1U) {
			run.state.phase		 = 2U ;
			run.state.phaseCalls = 0U ;
			// 監査で昇格した元配布一件だけを導入へ渡す選択集合
			const std::array selected{candidates.front().identity} ;
			DRIVERCRATE_EXPECT( context, run.provider->beginInstallOperation(
											3403U, plan.scanSessionId, selected) == 0U) ;
			// 偽Providerで同じscanの選択が適用直前まで通ったかを確認する結果
			const auto installed = run.provider->install( plan.scanSessionId, selected, 0U,
														 []( const ProviderProgress &) {}) ;
			DRIVERCRATE_EXPECT( context, !installed.succeeded &&
											installed.installError ==
												HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) &&
											run.state.phaseCalls == 3U &&
											run.native.installs == 0U) ;
			std::cout << "CLIENT_BUILD_FINAL case=" << caseId
					  << " error=" << static_cast<std::uint32_t>( installed.installError)
					  << " phaseCalls=" << run.state.phaseCalls
					  << " provider=" << run.native.installs << '\n' ;
		}
	}

	// 純粋record不正を新global latchにせず、原host失敗だけを不可逆に保持します
	if( caseId.starts_with( "A") || retained) {
		// 最初の照合文脈に対する現在OSの導入可否
		const auto gate = run.adapter->hostDecision( run.original.context) ;
		// 同じ拒否状態を再現できるかを確認する対照ごとの期待区分
		const auto expectedState =
			caseId == "A04_OWNER_HASH_FIRST"	   ? IndexHostGateState::ALLOW_UNVERIFIED
			: caseId == "A03_FRESH_NATIVE_FAILURE" ? IndexHostGateState::UNKNOWN
												   : IndexHostGateState::STALE ;
		DRIVERCRATE_EXPECT( context,
						   gate && gate->state == expectedState &&
							   gate->observation.domain == WindowsHostErrorDomain::NTSTATUS &&
							   gate->observation.rawBits ==
								   (caseId == "A03_FRESH_NATIVE_FAILURE" ? 0xc0000001U : 0U)) ;
	}

	DRIVERCRATE_EXPECT( context, run.native.installs == 0U && run.native.stages == 0U &&
									run.native.opens == run.native.closes) ;
	std::cout << "CLIENT_BUILD_CASE case=" << caseId << " sends=" << run.state.sends
			  << " token=" << run.state.minted << " provider=" << run.native.installs
			  << " failures=" << context.failureCount() - beforeFailures << '\n' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非空真正fixtureを元取得/監査/最終拒否へ通す一caseです
 * @param[in,out] context 共通assertion集計です
 * @param[in] store 元RAM署名codecで保存した隔離storeです
 * @param[in] nowUtc 独立fixture UTCです
 * @param[in] zip 原recordへhash/sizeを結んだ実人工archiveです
 * @param[in] caseId 固定matrixの一意IDです
 * @param[in] platform 元六fieldの独立literalです
 * @note pure22とは別に通常所有経路を通し、候補/成功DTOを注入しません
 */
//------------------------------------------------------------------------------
void runServerP4PipelineCase( TestContext &context, std::shared_ptr<SignedIndexStore> store,
							 const std::chrono::sys_seconds nowUtc, const std::string_view zip,
							 const std::string_view caseId, const WindowsHostPlatform platform)
{
	const auto		failures = context.failureCount() ;						// このcase以前の失敗を消しません
	ServerP4Harness run{std::move( store), nowUtc, zip, caseId, platform} ;	// 同threadの真ownerです
	// 公開Classが合う正常inventoryをClass負例の前提にします
	if( caseId == "P4_C04_CLASS_PIPELINE") {
		// 申告Netとnative inventoryだけを一致させ、実INFはPortsです
		run.native.network = true ;
	}

	// 誤kindにも正当なnative positiveを与えて内容比較へ進めます
	if( caseId == "P4_C02_WRONG_TYPED_KIND_PIPELINE") {
		run.native.opaqueCompatibleId =
			L"TESTBUS\\SYNTH_0001" ;	// 誤kindにも実native positiveを与えます
	}

	const bool retained = caseId == "P4_C14_RETAINED_NONEMPTY_SUCCESS" ||
						  caseId == "P4_C15_RETAINED_BAD_TARGET_HASH" ||
						  caseId == "P4_C16_RETAINED_TARGET_EXPIRED" ||
						  caseId == "P4_D17_RETAINED_FRESH_FAILURE" ||
						  // 別active Bです
						  caseId == "P4_D18_RETAINED_MODELS_THEN_HOST_CHANGE" ;
	const bool finalCase = caseId.starts_with( "P4_D07_") || caseId.starts_with( "P4_D08_") ||
						   caseId.starts_with( "P4_D09_") || caseId.starts_with( "P4_D10_") ||
						   caseId.starts_with( "P4_D11_") || caseId.starts_with( "P4_D13_") ||
						   caseId.starts_with( "P4_D14_") || caseId.starts_with( "P4_D15_") ||
						   // 正候補が必須の最終負例です
						   caseId.starts_with( "P4_D16_") ;
	const bool hostCase = caseId.starts_with( "P4_D") ;			// 分類期待は後段literal表へ固定します
	std::optional<IndexHostGateResult> observedHostRefusal ;	// 原domain/bitsをrawへ分離保存します
	std::size_t						   recoveredCandidates{} ;	// 正当な新scanの実候補だけです
	const bool						   client =
		// 元三条件不要です
		caseId == "P4_C20_OLD_CLIENT10" || caseId == "P4_C21_OLD_CLIENT11" ;
	signed_index_candidate_binding_detail::Access::observePublication(
		[]( const signed_index_candidate_binding_detail::PublicationDiagnostic &value,
		   void																  *raw) noexcept {
			// READY前3という実通知だけを数え、候補結果を書き換えません
			if( value.stage == 3U) {
				++static_cast<ServerP4Observation *>( raw)->minted ;
			}
		},
		&run.state) ;
	OfficialPreparationSession preparation ;	// 同scanの複数操作でも原予約/高水位を保持します
	std::optional<OfficialPreparationApproval>
			   approvedSnapshot ;	// 実行へ渡した元承認だけを保持します
	const auto execute = [&]( const OfficialPreparationPlan &plan, const OperationId operation,
							 const bool onlyFirst) {
		DRIVERCRATE_EXPECT( context, preparation.initialize( plan) == OfficialPreparationError::NONE) ;
		OfficialPreparationApproval approval{operation,
											 plan.scanSessionId,
											 plan.planId,
											 plan.limits,
											 {}} ;	// 元全targetを表示済みとして明示します
		// 全元targetの選択/非選択を明示します
		for( std::size_t index = 0U; index < plan.targets.size(); ++index) {
			approval.decisions.push_back(
				{plan.targets[index], !onlyFirst || index == 0U, false, false, false}) ;
		}

		approvedSnapshot = approval ;
		return executeOfficialPreparation(
			preparation, approval,
			[&]( const OfficialPreparationTask &task, const PreparationCancellation &cancel) {
				// 既plan/承認/active task成立後だけB一faultを与えます
				if( run.state.phase == 3U && caseId == "P4_C15_RETAINED_BAD_TARGET_HASH") {
					auto relations = run.lookup->relations() ;	// 元が非constの独立copyだけです
					// 新Bだけを独立lookup copy内から探します
					for( const auto &relation : relations) {
						// B以外の正常relationは変更しません
						if( relation.recordId == "metadata-retained") {
							const_cast<IndexRecordRelation &>( relation).recordSha256[0] ^= 1U ;
						}
					}
				}

				// B原expiryだけをactive task成立後に越えます
				if( run.state.phase == 3U && caseId == "P4_C16_RETAINED_TARGET_EXPIRED") {
					*run.clock = nowUtc + std::chrono::minutes{1} ;	// Bだけの原期限ちょうどです
				}

				return run.session.acquireForInspection( preparation, task, run.services, cancel) ;
			},
			[] { return false ; }, []( const OfficialPreparationProgress &) {}) ;
	} ; // 戻り値は実sessionの原終端だけで、成功値を合成しません
	const auto candidatesFrom = []( const std::vector<OfficialPreparationAuditReport> &reports) {
		std::vector<UpdateCandidate> result ;	// 実監査が発行した候補だけです
		// 実監査の発行集合だけを外へ複写します
		for( const auto &report : reports) {
			result.insert( result.end(), report.publishedCandidates.begin(),
						  report.publishedCandidates.end()) ;
		}

		return result ;
	} ;
	OfficialPreparationPlan plan = run.plan( context, 85305U) ;	// 新native-owned三IDです
	DRIVERCRATE_EXPECT( context, run.adapter && run.lookup) ;
	// generic Serverは取得計画前の拒否だけを期待します
	if( caseId == "P4_C17_GENERIC_SERVER") {
		DRIVERCRATE_EXPECT( context, plan.targets.empty() && run.state.sends == 0U &&
										run.state.callbacks == 1U && run.native.rankCalls == 0U &&
										run.state.minted == 0U) ;
		std::cout << "P4_PIPELINE case=" << caseId << " targets=0 sends=" << run.state.sends
				  << " candidates=0 tokens=0 provider=" << run.native.installs << '\n' ;
		signed_index_candidate_binding_detail::Access::observePublication( nullptr, nullptr) ;
		return ;
	}

	DRIVERCRATE_EXPECT( context, plan.targets.size() == (retained ? 2U : 1U)) ;
	// 正常認証/元計画がないcaseを後段拒否合格にしません
	if( plan.targets.size() != (retained ? 2U : 1U) || !run.lookup || !run.adapter) {
		throw std::runtime_error( "P4 authenticated pipeline prerequisite missing") ;
	}

	// 同一INFへ実positiveとなる二recordの前提を確認します
	if( caseId == "P4_C12_SHARED_AMBIGUOUS_RECORDS") {
		std::set<std::string> records ;	// 同native deviceへ実positiveとなった原二recordです
		// 原lookupで実positiveとなったrecordだけを数えます
		for( const auto &relation : run.lookup->relations()) {
			// 未確認関係から二つの正常前提を合成しません
			if( relation.deviceIdentity && (relation.positiveProof || relation.deviceProof ||
										   relation.state == IndexRecordMatchState::MATCHED)) {
				records.insert( relation.recordId) ;
			}
		}

		const std::set<std::string> expectedRecords{"metadata",
													"metadata-ambiguous"} ;	// 元二record literalです
		DRIVERCRATE_EXPECT( context,
						   records == expectedRecords && plan.targets.front().deviceCount == 1U) ;
	}

	// 同payloadの異productからhost3 recordだけが選ばれることを確認します
	if( caseId == "P4_C13_SHARED_OTHER_PRODUCT") {
		DRIVERCRATE_EXPECT( context, run.lookup->snapshot().schemaReceipt().records().size() == 2U &&
										plan.targets.size() == 1U &&
										plan.targets.front().deviceCount == 1U) ;
		const auto &record = run.lookup->snapshot()
								 .schemaReceipt()
								 .records()
								 .front() ;	// 第一recordだけがproduct3です
		std::wstring hash ;					// 新scope helperと独立した原raw byteのSHAです
		DRIVERCRATE_EXPECT( context,
						   computeBytesSha256( record.originalBytes, hash) == 0U &&
							   record.originalBytes.find( "target-product-type=3") !=
								   record.originalBytes.npos &&
							   plan.targets.front().releaseIdentity == hash &&
							   run.lookup->snapshot().schemaReceipt().sources().size() == 1U) ;
	}

	const auto acquired = execute( plan, 1402U, retained) ;	// 実TRANSFER/実byte/原内容を通します
	DRIVERCRATE_EXPECT( context, acquired.approvalError == OfficialPreparationError::NONE &&
									acquired.controlError == 0U && run.state.sends == 1U) ;
	const auto acquiredSummary =
		// 原sealと内容の非機密結果です
		run.session.preparationSummary( 1402U) ;
	DRIVERCRATE_EXPECT( context, acquiredSummary.items.size() == 1U &&
									acquiredSummary.items.front().acquisitionError == 0U &&
									acquiredSummary.items.front().inputBound &&
									acquiredSummary.items.front().infCount == 1U) ;
	const auto input = signed_index_candidate_binding_detail::Access::inspectionInputForFixture(
		run.session, plan.targets.front().identity) ;	// 既所有入力を読み取るだけです
	DRIVERCRATE_EXPECT(
		context, input && input->byteCount == zip.size() &&
					 !signed_index_candidate_binding_detail::Access::inspectionInputForFixture(
						 run.session, L"wrong-target")) ;
	const auto beforeAuditCallbacks = run.state.callbacks ;	// 純粋拒否より前の独立基準です
	std::vector<std::pair<std::string, IndexManifestSha256>>
		originalRecordBytes ;	// 全原byte/hashを後続へ保持します
	// 全原raw/hashを後続作用の前に保存します
	for( const auto &record : run.lookup->snapshot().schemaReceipt().records()) {
		originalRecordBytes.emplace_back( record.originalBytes, record.recordSha256) ;
	}

	const bool diagnostic =
		caseId == "P4_C06_CAT_REJECT" || caseId == "P4_C08_CHANGED_SEALED_BYTE" ||
		caseId == "P4_C10_EXPIRED_NATIVE_LEASE" || caseId == "P4_C12_SHARED_AMBIGUOUS_RECORDS" ||
		caseId == "P4_C14_RETAINED_NONEMPTY_SUCCESS" ||
		// 原不一致の六caseだけを数値観測します
		caseId == "P4_D05_BEFORE_TOKEN_CHANGED_SUITE" ;
	// 元summaryの所有copyだけを読み、対象名やhashは出さずA/B一致boolへ限定します
	const auto emitSummary = [&]( const std::string_view			phaseLabel,
								 const IndexPreparationSummary &summary) {
		// 許可した六case以外へ診断出力を追加しません
		if( !diagnostic) {
			return ;
		}

		std::cout << "P4_DIAG_SUMMARY case=" << caseId << " phase=" << phaseLabel
				  << " items=" << summary.items.size() << " callbacks=" << run.state.callbacks
				  << " phaseCalls=" << run.state.phaseCalls << " minted=" << run.state.minted
				  << " rank=" << run.native.rankCalls
				  << " signatureRejectedCalls=" << run.signatures->receipt().rejectedCalls << '\n' ;
		// 各既取得itemを原ordinalのまま読み、新しい取得やhost観測を呼びません
		for( std::size_t ordinal = 0U; ordinal < summary.items.size(); ++ordinal) {
			const auto &item = summary.items[ordinal] ;	// 同snapshot内だけの非所有参照です
			std::cout << "P4_DIAG_ITEM case=" << caseId << " phase=" << phaseLabel
					  << " item=" << ordinal
					  << " targetA=" << (item.targetIdentity == plan.targets.front().identity)
					  << " targetB="
					  << (plan.targets.size() == 2U &&
						  item.targetIdentity == plan.targets[1U].identity)
					  << " acquisition=" << static_cast<unsigned>( item.acquisition)
					  << " acquisitionError=" << static_cast<std::uint32_t>( item.acquisitionError)
					  << " content=" << static_cast<unsigned>( item.content)
					  << " contentError=" << static_cast<std::uint32_t>( item.contentError)
					  << " firstInf=" << static_cast<std::uint32_t>( item.firstInfRejection)
					  << " signatureRejected=" << item.signatureRejectedInfCount
					  << " accepted=" << item.acceptedInfCount << " infCount=" << item.infCount
					  << " inputBound=" << item.inputBound << " reused=" << item.reusedOwnedBody
					  << '\n' ;
		}
	} ;
	// 既reportと元拒否票をconstで読み、判定・callback・候補を変更しません
	const auto emitReports = [&]( const std::string_view								   phaseLabel,
								 const std::span<const OfficialPreparationAuditReport> values,
								 const unsigned										   baseline) {
		// 許可した六case以外の既処理を変えません
		if( !diagnostic) {
			return ;
		}

		const auto host =
			// 再観測しない元拒否票です
			run.adapter->hostDecision( run.original.context) ;
		std::cout << "P4_DIAG_AUDIT case=" << caseId << " phase=" << phaseLabel
				  << " reports=" << values.size() << " beforeCallbacks=" << baseline
				  << " afterCallbacks=" << run.state.callbacks
				  << " phaseCalls=" << run.state.phaseCalls << " minted=" << run.state.minted
				  << " rank=" << run.native.rankCalls << " hostPresent=" << host.has_value()
				  << " hostState=" << (host ? static_cast<unsigned>( host->state) : 0U)
				  << " hostError=" << (host ? static_cast<std::uint32_t>( host->error) : 0U) << '\n' ;
		// 各reportを元ordinalとA/B一致だけへ投影し、生identityを出しません
		for( std::size_t ordinal = 0U; ordinal < values.size(); ++ordinal) {
			const auto &value = values[ordinal] ;	// 今回返った非機密reportだけです
			std::cout << "P4_DIAG_REPORT case=" << caseId << " phase=" << phaseLabel
					  << " item=" << ordinal
					  << " targetA=" << (value.targetIdentity == plan.targets.front().identity)
					  << " targetB="
					  << (plan.targets.size() == 2U &&
						  value.targetIdentity == plan.targets[1U].identity)
					  << " content=" << static_cast<unsigned>( value.content)
					  << " contentError=" << static_cast<std::uint32_t>( value.contentError)
					  << " firstContent=" << static_cast<std::uint32_t>( value.firstContentRejection)
					  << " accepted=" << value.acceptedInfCount
					  << " applicability=" << static_cast<unsigned>( value.applicability)
					  << " applicabilityError="
					  << static_cast<std::uint32_t>( value.applicabilityError)
					  << " firstPair=" << static_cast<std::uint32_t>( value.firstPairError)
					  << " applicablePairs=" << value.applicablePairCount
					  << " publication=" << static_cast<unsigned>( value.publication.state)
					  << " examined=" << value.publication.examinedPairCount
					  << " excluded=" << value.publication.excludedPairCount << " publicationError="
					  << static_cast<std::uint32_t>( value.publication.firstError)
					  << " published=" << value.publishedCandidates.size() << '\n' ;
		}
	} ;
	emitSummary( "acquired", acquiredSummary) ;

	// 自作所有archiveの一byteだけをseal後に変更します
	if( caseId == "P4_C08_CHANGED_SEALED_BYTE" && input) {
		std::fstream file{std::filesystem::path{input->inspectionPath},
						  std::ios::in | std::ios::out |
							  std::ios::binary} ;	// 自作stageの同owned byteだけです
		char		 byte{} ;						// 原一byteを変える負例です
		file.read( &byte, 1) ;
		const bool read = file.good() ;	// 保護拒否を破壊成功へ数えません
		file.clear() ;
		file.seekp( 0) ;
		byte ^= 1 ;
		file.write( &byte, 1) ;
		file.flush() ;
		DRIVERCRATE_EXPECT( context, read && file.good()) ;
		// 所有保護のwrite拒否を変造成功へ数えません
		if( !read || !file.good()) {
			throw std::runtime_error(
				"P4 sealed-byte mutation blocked; intended phase not demonstrated") ;
		}
	}

	// 元が非constの負例copyだけでrecordIdを変えます
	if( caseId == "P4_C09_WRONG_RECORD_ID") {
		auto relations = run.lookup->relations() ;	// 元が非constの独立lookupだけです
		DRIVERCRATE_EXPECT( context, !relations.empty()) ;
		const_cast<IndexRecordRelation &>( relations.front()).recordId = "wrong-record" ;
	}

	// 実再列挙により原native leaseだけを失効させます
	if( caseId == "P4_C10_EXPIRED_NATIVE_LEASE") {
		const auto recaptured =
			signed_index_candidate_binding_detail::Access::driverStoreFixture( *run.provider)
				.scan( 85306U, {}, []( const ProviderProgress &) {}) ;	// 原leaseだけを失効します
		DRIVERCRATE_EXPECT( context, recaptured.succeeded) ;
	}

	// 当該原attestation期限ちょうどで監査します
	if( caseId == "P4_C11_EXPIRED_RECORD") {
		*run.clock = nowUtc + std::chrono::minutes{1} ;	// 当該原attestation期限だけです
	}

	run.state.phase		 = 1U ;
	run.state.phaseCalls = 0U ;
	// 元auditを同じ位置で一回だけ呼び、例外時も同じ例外をそのまま再送します
	auto reports = [&]() {
		try {
			return run.provider->preparationAuditReports( acquired) ;
		} catch( ...) {
			// D05の未返却reportを作らず、元local counterだけを例外の前に保存します
			if( diagnostic) {
				emitReports( "throw", {}, beforeAuditCallbacks) ;
			}

			throw ;
		}
	}() ;
	auto candidates = candidatesFrom( reports) ;	// 同元tokenからの通常候補です
	emitReports( "audit", reports, beforeAuditCallbacks) ;
	// 元単一INF/deviceのrank合格と、host拒否後の無候補終端を独立に照合します
	if( caseId == "P4_D05_BEFORE_TOKEN_CHANGED_SUITE" || caseId == "P4_D06_PREPUBLICATION_ARM64") {
		DRIVERCRATE_EXPECT(
			context,
			reports.size() == 1U &&
				reports.front().applicability == CandidateAuditGateState::PASSED &&
				reports.front().applicabilityError == 0U &&
				reports.front().examinedPairCount == 1U &&
				reports.front().applicablePairCount == 1U &&
				reports.front().failedPairCount == 0U &&
				reports.front().publication.state ==
					(caseId == "P4_D05_BEFORE_TOKEN_CHANGED_SUITE"
						 ? OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES
						 : OfficialPreparationCandidatePublicationState::FAILURE) &&
				reports.front().publication.examinedPairCount == 1U &&
				reports.front().publication.excludedPairCount == 1U &&
				reports.front().publication.firstError ==
					HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) &&
				reports.front().publication.publishedCount == 0U &&
				reports.front().publishedCandidates.empty()) ;
		auto audited = acquired ;	// 元操作結果を改変せず、実返却reportだけを通常通知へ結合します
		audited.auditReports = reports ;
		DRIVERCRATE_EXPECT( context, approvedSnapshot &&
										validatePreparationAuditReports( audited, *approvedSnapshot,
																		run.displayedCandidates)) ;
	}

	const bool pureRefusal = caseId == "P4_C08_CHANGED_SEALED_BYTE" ||
							 caseId == "P4_C09_WRONG_RECORD_ID" ||
							 caseId == "P4_C10_EXPIRED_NATIVE_LEASE" ||
							 // 全て観測前の拒否です
							 caseId == "P4_C11_EXPIRED_RECORD" ;
	// 純粋拒否はhost callbackを消費せず原codeを返す必要があります
	if( pureRefusal) {
		const auto expected = caseId == "P4_C08_CHANGED_SEALED_BYTE" ? TRUST_E_BAD_DIGEST
							  : caseId == "P4_C11_EXPIRED_RECORD"
								  ? HRESULT_FROM_WIN32( ERROR_TIMEOUT)
								  : E_ACCESSDENIED ;	// 元実装の固定codeです
		DRIVERCRATE_EXPECT( context,
						   run.state.callbacks == beforeAuditCallbacks && reports.size() == 1U &&
							   reports.front().contentError == expected && candidates.empty() &&
							   run.state.minted == 0U && run.native.rankCalls == 0U &&
							   run.adapter->hostDecision( run.original.context)->state ==
								   IndexHostGateState::ALLOW_UNVERIFIED) ;
		// 取得旧contextを再開始しても所有元を新scanから補いません
		if( caseId == "P4_C10_EXPIRED_NATIVE_LEASE") {
			DRIVERCRATE_EXPECT(
				context, signed_index_acquisition_detail::Access::beginHostFixture(
							 *run.adapter, run.lookup, run.original.context, run.original,
							 run.services.hostPlatform, nowUtc) == E_ACCESSDENIED &&
							 run.state.callbacks == beforeAuditCallbacks && run.state.sends == 1U) ;
		}
	}

	const bool contentMismatch = caseId.starts_with( "P4_C01_") || caseId.starts_with( "P4_C02_") ||
								 caseId.starts_with( "P4_C03_") || caseId.starts_with( "P4_C04_") ||
								 // 全元内容成立後のidentity比較です
								 caseId.starts_with( "P4_C05_") ;
	// 内容の正常前提と原identity不一致を独立に確認します
	if( contentMismatch || caseId == "P4_C12_SHARED_AMBIGUOUS_RECORDS") {
		DRIVERCRATE_EXPECT( context, reports.size() == 1U &&
										reports.front().acceptedInfCount == 1U &&
										reports.front().contentError == 0U && candidates.empty() &&
										run.native.rankCalls == 0U && run.state.minted == 0U) ;
		// 二つの完全一致を先頭へ丸めない元拒否を確認します
		if( caseId == "P4_C12_SHARED_AMBIGUOUS_RECORDS") {
			DRIVERCRATE_EXPECT( context,
							   reports.size() == 1U && reports.front().firstPairError ==
														   HRESULT_FROM_WIN32( ERROR_DUP_NAME)) ;
		} else { // 別のreader失敗を内容不一致成功へ換算しません
			DRIVERCRATE_EXPECT( context, reports.front().firstPairError == 0U &&
											reports.front().applicablePairCount == 0U) ;
		}
	}

	// 署名又はSYS欠損は候補/rank/tokenへ進めません
	if( caseId == "P4_C06_CAT_REJECT" || caseId == "P4_C07_MISSING_SYS") {
		DRIVERCRATE_EXPECT( context, candidates.empty() && run.state.minted == 0U &&
										run.native.rankCalls == 0U &&
										acquiredSummary.items.front().acceptedInfCount == 0U) ;
		// 全member原hashを拒否する人工署名APIの元Win32 errorを保持します
		if( caseId == "P4_C06_CAT_REJECT") {
			DRIVERCRATE_EXPECT( context,
							   acquiredSummary.items.front().signatureRejectedInfCount == 1U &&
								   acquiredSummary.items.front().firstInfRejection ==
									   HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) &&
								   run.signatures->receipt().rejectedCalls != 0U) ;
		} else { // 元referenced SYS欠損だけを拒否します
			DRIVERCRATE_EXPECT( context, acquiredSummary.items.front().firstInfRejection ==
											HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)) ;
		}
	}

	const bool initiallyQualified = caseId.starts_with( "P4_A_") || client || retained ||
									finalCase ||
									// 独立matrixの正候補前提です
									caseId == "P4_C13_SHARED_OTHER_PRODUCT" ;
	// 最終負例又はretainedのAには実正候補が必要です
	if( initiallyQualified) {
		DRIVERCRATE_EXPECT( context, candidates.size() == 1U && candidates.front().installable &&
										run.state.minted == 1U && run.native.rankCalls != 0U) ;
	}

	// 旧clientには新Server callback/三条件を追加しません
	if( client) {
		DRIVERCRATE_EXPECT( context, run.state.callbacks == beforeAuditCallbacks &&
										run.lookup->snapshot()
											.schemaReceipt()
											.records()
											.front()
											.acquisitionDescriptor->prerequisites.items.empty()) ;
	}

	// Aのcommit後だけ新Bを原予算の次操作へ進めます
	if( retained) {
		const auto				history = candidates ;	// Aの既commit表示/履歴は元byteのまま残します
		OfficialPreparationPlan next	= plan ;		// 原Bだけの新active operationです
		next.targets.erase( next.targets.begin()) ;
		++next.planId ;
		DRIVERCRATE_EXPECT( context, run.session.retainPreparationPlan( next, run.services) &&
										next.targets.size() == 1U) ;
		run.state.phase			 = 3U ;
		run.state.retainedTarget = true ;
		run.state.phaseCalls	 = 0U ;
		const auto beforeB		 = run.state.callbacks ;					// B純粋拒否はここからcallback0です
		const auto local		 = execute( next, 1403U, false) ;			// 原A byteの再取得を行いません
		const auto summary		 = run.session.preparationSummary( 1403U) ;	// Bの実通常内容です
		emitSummary( "retained", summary) ;
		// 元LOCAL操作の制御結果だけを数値表示し、taskやclaimを再発行しません
		if( diagnostic) {
			std::cout << "P4_DIAG_LOCAL case=" << caseId
					  << " approval=" << static_cast<unsigned>( local.approvalError)
					  << " control=" << static_cast<std::uint32_t>( local.controlError)
					  << " items=" << local.items.size() << " history=" << history.size() << '\n' ;
		}

		DRIVERCRATE_EXPECT( context, run.state.sends == 1U && local.items.size() == 1U &&
										summary.items.size() == 1U && history.size() == 1U) ;
		// B固有のhash/期限拒否はLOCALとhostより先に成立します
		if( caseId == "P4_C15_RETAINED_BAD_TARGET_HASH" ||
		   caseId == "P4_C16_RETAINED_TARGET_EXPIRED") {
			const auto expected = caseId == "P4_C15_RETAINED_BAD_TARGET_HASH"
									  ? E_ACCESSDENIED
									  : HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;	// B原拒否です
			DRIVERCRATE_EXPECT(
				context,
				run.state.callbacks == beforeB &&
					summary.items.front().acquisitionError == expected &&
					!summary.items.front().reusedOwnedBody && !summary.items.front().inputBound &&
					!signed_index_candidate_binding_detail::Access::inspectionInputForFixture(
						run.session, next.targets.front().identity)) ;
			candidates.clear() ;
		}
		// LOCAL成功後/B bind前のhost拒否です
		else if( caseId == "P4_D17_RETAINED_FRESH_FAILURE") {
			DRIVERCRATE_EXPECT(
				context,
				run.state.phaseCalls == 1U && summary.items.front().reusedOwnedBody &&
					!summary.items.front().inputBound &&
					summary.items.front().contentError == E_NOTIMPL &&
					!signed_index_candidate_binding_detail::Access::inspectionInputForFixture(
						run.session, next.targets.front().identity)) ;
			candidates.clear() ;
		} else { // 正常BもAの内容合格やrecordShaを複写しません
			DRIVERCRATE_EXPECT( context, summary.items.front().reusedOwnedBody &&
											summary.items.front().inputBound &&
											summary.items.front().acceptedInfCount == 1U &&
											summary.items.front().contentError == 0U) ;
			run.state.phase		 = 1U ;
			run.state.phaseCalls = 0U ;
			reports				 = run.provider->preparationAuditReports( local) ;
			candidates			 = candidatesFrom( reports) ;
			emitReports( "retained-audit", reports, beforeB) ;
			DRIVERCRATE_EXPECT( context,
							   candidates.size() ==
								   (caseId == "P4_C14_RETAINED_NONEMPTY_SUCCESS" ? 1U : 0U)) ;
		}

		// 既A routeでも同contextのhost拒否を迂回できません
		if( caseId == "P4_D17_RETAINED_FRESH_FAILURE" ||
		   caseId == "P4_D18_RETAINED_MODELS_THEN_HOST_CHANGE") {
			const std::array oldSelection{	// 元A履歴を再利用してもhost拒否を迂回しません
										  history.front().identity} ;
			DRIVERCRATE_EXPECT( context, run.provider->beginInstallOperation(
											1501U, plan.scanSessionId, oldSelection) == 0U) ;
			const auto oldAttempt =
				run.provider->install( plan.scanSessionId, oldSelection, 0U,
									  []( const ProviderProgress &) {}) ;	// 原routeも使用不能です
			DRIVERCRATE_EXPECT( context,
							   !oldAttempt.succeeded &&
								   oldAttempt.installError ==
									   (caseId == "P4_D17_RETAINED_FRESH_FAILURE"
											? E_NOTIMPL
											: HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)) &&
								   run.native.installs == 0U && history.front().installable) ;
		}
	}

	// 最終負例は実正候補を得た後だけ実行します
	if( finalCase && candidates.size() == 1U) {
		ServerP4ModelsState sdk ;	// D16だけが低位SDK節選択を切替えます
		std::unique_ptr<official_inf_models_native_detail::ScopedFixture>
			modelScope ;	// scope外は元SDKです
		// D16だけが不変INFのSDK Models応答を切替えます
		if( caseId == "P4_D16_FINAL_MODELS_MISMATCH") {
			DRIVERCRATE_EXPECT( context, !run.native.sourceInfs.empty()) ;
			// 正候補の実INF path欠測を最終拒否合格にしません
			if( run.native.sourceInfs.empty()) {
				throw std::runtime_error( "P4 final Models positive premise missing") ;
			}

			serverP4ModelsContract( context, run.native.sourceInfs.front(), sdk) ;
			sdk.other	   = true ;
			serverP4Models = &sdk ;
			modelScope = official_inf_models_native_detail::Access::create( {&serverP4ActualModels}) ;
			DRIVERCRATE_EXPECT( context, modelScope != nullptr) ;
		}

		run.state.phase		 = 2U ;
		run.state.phaseCalls = 0U ;
		const std::array selected{candidates.front().identity} ;	// 実ownerの唯一候補だけです
		DRIVERCRATE_EXPECT( context, run.provider->beginInstallOperation( 1500U, plan.scanSessionId,
																		selected) == 0U) ;
		const auto installed =
			run.provider->install( plan.scanSessionId, selected, 0U,
								  []( const ProviderProgress &) {}) ;	// 実最終指定入口です
		const auto expected =
			caseId == "P4_D16_FINAL_MODELS_MISMATCH" ? E_ACCESSDENIED
			: caseId == "P4_D07_FINAL_CHANGED_BUILD" || caseId == "P4_D14_FINAL_KNOWN_PRODUCT4"
				? HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)
				: E_NOTIMPL ;	// 独立原契約codeです
		DRIVERCRATE_EXPECT( context, !installed.succeeded && installed.installError == expected &&
										run.native.installs == 0U &&
										run.state.phaseCalls ==
											(caseId == "P4_D16_FINAL_MODELS_MISMATCH" ? 2U : 3U)) ;
		// 最終の実SDK出力だけが局所内容拒否を起こしたことを確認します
		if( modelScope) {
			DRIVERCRATE_EXPECT( context,
							   sdk.contractValid && sdk.queries > 0U && sdk.reads > 0U &&
								   run.adapter->hostDecision( run.original.context)->state ==
									   IndexHostGateState::ALLOW_UNVERIFIED) ;
			modelScope.reset() ;
			serverP4Models		= nullptr ;
			observedHostRefusal = run.adapter->hostDecision(
				run.original.context) ;	// 内容不一致はALLOW原hostを変えません
		}

		// 拒否したoperationに使用可能候補を返しません
		candidates.clear() ;
	}

	// host拒否の分類/原domain/bitsを独立literalへ照合します
	if( hostCase && caseId != "P4_D16_FINAL_MODELS_MISMATCH") {
		const auto gate =
			// 同contextの原拒否診断です
			run.adapter->hostDecision( run.original.context) ;
		observedHostRefusal = gate ;
		const bool unknown =
			caseId == "P4_D02_AUDIT_WIN32_FAILURE" || caseId == "P4_D03_AUDIT_NTSTATUS_FAILURE" ||
			caseId == "P4_D08_FINAL_WIN32_FAILURE" || caseId == "P4_D09_FINAL_NTSTATUS_FAILURE" ||
			caseId == "P4_D10_FINAL_UNOBSERVED" || caseId == "P4_D11_FINAL_OBSERVER_THROW" ||
			caseId == "P4_D13_FINAL_UNKNOWN_LATCH_SEQUENCE" ||
			caseId == "P4_D15_FINAL_BUILD_UNKNOWN" ||
			// 新helperから期待を生成しません
			caseId == "P4_D17_RETAINED_FRESH_FAILURE" ;
		const auto domain =
			caseId == "P4_D02_AUDIT_WIN32_FAILURE" || caseId == "P4_D08_FINAL_WIN32_FAILURE"
				? WindowsHostErrorDomain::WIN32_CODE
			: caseId == "P4_D10_FINAL_UNOBSERVED" || caseId == "P4_D11_FINAL_OBSERVER_THROW"
				? WindowsHostErrorDomain::NONE
				: WindowsHostErrorDomain::NTSTATUS ;	// 原code domainです
		const std::uint32_t bits = domain == WindowsHostErrorDomain::WIN32_CODE ? 126U
								   : caseId == "P4_D03_AUDIT_NTSTATUS_FAILURE" ||
										   caseId == "P4_D09_FINAL_NTSTATUS_FAILURE" ||
										   caseId == "P4_D13_FINAL_UNKNOWN_LATCH_SEQUENCE" ||
										   caseId == "P4_D17_RETAINED_FRESH_FAILURE"
									   ? 0xc0000001U
									   : 0U ;	// 変換HRESULTを原statusと呼びません
		DRIVERCRATE_EXPECT(
			context, gate &&
						 gate->state ==
							 (unknown ? IndexHostGateState::UNKNOWN : IndexHostGateState::STALE) &&
						 gate->error ==
							 (unknown ? E_NOTIMPL : HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)) &&
						 gate->observation.domain == domain && gate->observation.rawBits == bits &&
						 candidates.empty()) ;
		// Models後/Windows rank前の到達を実counterで区別します
		if( caseId == "P4_D04_AFTER_MODELS_CHANGED_PRODUCT") {
			DRIVERCRATE_EXPECT( context, run.state.phaseCalls == 2U && run.native.rankCalls == 0U &&
											run.state.minted == 0U) ;
		}

		// rank後/token前の到達を実counterで区別します
		if( caseId == "P4_D05_BEFORE_TOKEN_CHANGED_SUITE") {
			DRIVERCRATE_EXPECT( context, run.state.phaseCalls == 3U && run.native.rankCalls > 0U &&
											run.state.minted == 0U) ;
		}

		// 新token発行後のrollbackを発行未試行と区別します
		if( caseId == "P4_D06_PREPUBLICATION_ARM64") {
			DRIVERCRATE_EXPECT( context, run.state.phaseCalls == 4U && run.state.minted == 1U &&
											candidates.empty()) ;
		}

		const auto beforeLater = run.state.callbacks ;	// 後続matchingで原拒否を消しません
		run.state.recover	   = true ;
		run.adapter->invalidate() ;
		DRIVERCRATE_EXPECT(
			context, signed_index_acquisition_detail::Access::beginHostFixture(
						 *run.adapter, run.lookup, run.original.context, run.original,
						 run.services.hostPlatform, nowUtc) == gate->error &&
						 run.adapter->begin( run.lookup, run.original.context,
											IndexTargetOs::WINDOWS_SERVER, nowUtc) == gate->error &&
						 run.state.callbacks == beforeLater &&
						 run.adapter->hostDecision( run.original.context)->error == gate->error) ;
		// 正当な新native-owned contextだけが候補へ回復します
		if( caseId == "P4_D12_AUDIT_STALE_LATCH_SEQUENCE" ||
		   caseId == "P4_D13_FINAL_UNKNOWN_LATCH_SEQUENCE") {
			run.session.invalidate() ;
			const auto freshPlan =
				// 同管理で先行計画より大きいIDを発行します
				run.plan( context, 85307U, 2U) ;
			DRIVERCRATE_EXPECT( context, freshPlan.targets.size() == 1U &&
											freshPlan.scanSessionId != plan.scanSessionId &&
											freshPlan.planId > plan.planId) ;
			run.state.phase					= 0U ;
			run.state.phaseCalls			= 0U ;
			const auto signatureBeforeFresh = run.signatures->receipt() ;	// 元展開rootと拒否件数です
			const auto fresh =
				// 元期限/同一payloadで新正当操作です
				execute( freshPlan, 1600U, false) ;
			const auto signatureAfterFresh = run.signatures->receipt() ;	// 新展開直後の照合件数です
			DRIVERCRATE_EXPECT( context, signatureBeforeFresh.inspectionRoots == 1U &&
											signatureAfterFresh.inspectionRoots == 2U &&
											signatureAfterFresh.rejectedCalls ==
												signatureBeforeFresh.rejectedCalls) ;
			run.state.phase		 = 1U ;
			run.state.phaseCalls = 0U ;
			const auto recovered =
				// 実新owner由来です
				candidatesFrom( run.provider->preparationAuditReports( fresh)) ;
			recoveredCandidates = recovered.size() ;
			DRIVERCRATE_EXPECT( context, recovered.size() == 1U && recovered.front().installable &&
											run.native.installs == 0U) ;
		}
	}

	DRIVERCRATE_EXPECT( context, run.native.stages == 0U && run.native.installs == 0U &&
									run.native.opens == run.native.closes) ;
	const auto originals =
		// 元wireをtyped scopeで書換えません
		run.lookup->snapshot().schemaReceipt().records() ;
	DRIVERCRATE_EXPECT( context, originals.size() == originalRecordBytes.size()) ;
	// 新typed処理で元wire/raw/hashを変更していないことを確認します
	for( std::size_t index = 0U; index < originals.size(); ++index) {
		DRIVERCRATE_EXPECT( context,
						   originals[index].originalBytes == originalRecordBytes[index].first &&
							   originals[index].recordSha256 == originalRecordBytes[index].second) ;
	}

	std::cout << "P4_PIPELINE case=" << caseId << " sends=" << run.state.sends
			  << " callbacks=" << run.state.callbacks << " phase=" << run.state.phase
			  << " phaseCalls=" << run.state.phaseCalls << " minted=" << run.state.minted
			  << " returnedCandidates=" << candidates.size()
			  << " rankCalls=" << run.native.rankCalls << " provider=" << run.native.installs
			  << " recoveredCandidates=" << recoveredCandidates << " hostState="
			  << (observedHostRefusal ? static_cast<unsigned>( observedHostRefusal->state) : 0U)
			  << " localErrorBits="
			  << (observedHostRefusal ? static_cast<std::uint32_t>( observedHostRefusal->error) : 0U)
			  << " nativeDomain="
			  << (observedHostRefusal
					  ? static_cast<unsigned>( observedHostRefusal->observation.domain)
					  : 0U)
			  << " nativeRawBits="
			  << (observedHostRefusal ? observedHostRefusal->observation.rawBits : 0U)
			  << " failures=" << context.failureCount() - failures << '\n' ;
	signed_index_candidate_binding_detail::Access::observePublication( nullptr, nullptr) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既WUA/Storeの保護/結果を新Server条件から隔離して確認します
 * @param[in,out] context 共通assertionです
 * @param[in] store 原client fixtureの隔離storeです
 * @param[in] nowUtc 独立fixture UTCです
 * @param[in] zip 原人工archiveです
 * @note 両native専用scanではhost callback/三LOCALを要求せず完全fakeだけを実行します
 */
//------------------------------------------------------------------------------
void runServerP4NativeIsolationCases( TestContext &context, std::shared_ptr<SignedIndexStore> store,
									 const std::chrono::sys_seconds nowUtc,
									 const std::string_view			zip)
{
	// 元matrix C22/C23だけを通常worker/同意/復旧境界へ結びます
	for( const bool localStore : {false, true}) {
		std::atomic<unsigned> hostCalls{} ;									// 新Server observerの不要な呼出しを検出します
		auto clock = std::make_shared<std::chrono::sys_seconds>( nowUtc) ;	// 同fixtureだけのUTCです
		auto services =
			// 実HTTPには進みません
			makeServerP4PipelineServices( store, clock, zip, [] {}) ;
		services.hostPlatform = [&]() -> WindowsHostPlatformObservation {
			++hostCalls ;
			throw std::runtime_error( "P4 native-only path must not observe external index host") ;
		} ;
		auto borrowed =
			std::make_shared<NativeFixtureState *>( nullptr) ;	// 同worker寿命だけの観測です
		auto bound = makeSignedIndexBindingWorker(
			services, zip, false, false, false, SignedIndexBindingNativeCase::NORMAL, {},
			[borrowed]() {
				*borrowed = activeNative ;
				// このP4 fixtureだけ実OS依存観測を閉じます
				if( activeNative) {
					activeNative->p4ExplicitClientContext = true ;
				}
			},
			{}, false, SignedIndexBindingBatchFault::NONE, localStore) ;	// 既完全表を使います
		OperationController controller ;									// 元同意と保護を省略しません
		ScanOptions			options ;										// 署名索引Providerは明示無効です
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {
			 std::wstring{localStore ? DRIVER_STORE_PROVIDER_ID : WINDOWS_UPDATE_PROVIDER_ID}} ;
		const auto started = controller.beginScan() ;	// 通常UIと同じ受付です
		DRIVERCRATE_EXPECT( context, started.accepted &&
										bound.worker->requestScan( started.operationId, options)) ;
		const auto scanned = waitEvent( *bound.worker, WorkerEventKind::SCAN_COMPLETED,
									   started.operationId) ;	// 真終端です
		DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded && hostCalls == 0U) ;
		// 元scan終端欠測をnative専用経路の成功へ数えません
		if( !scanned) {
			bound.worker->stop() ;
			throw std::runtime_error( "P4 native isolation scan not observed") ;
		}

		const auto candidate =
			std::ranges::find_if( scanned->scanResult.candidates, [&]( const auto &value) {
				return value.installable && !value.current &&
					   value.providerId ==
						   (localStore ? DRIVER_STORE_PROVIDER_ID : WINDOWS_UPDATE_PROVIDER_ID) ;
			}) ; // 手製の成功候補を追加しません
		DRIVERCRATE_EXPECT( context,
						   candidate != scanned->scanResult.candidates.end() &&
							   controller.completeScan( started.operationId, scanned->scanResult)) ;
		// 元native正候補がない場合は指定導入へ進めません
		if( candidate == scanned->scanResult.candidates.end()) {
			bound.worker->stop() ;
			throw std::runtime_error( "P4 native isolation candidate missing") ;
		}

		const std::array selected{candidate->identity} ;	// 元正候補一件だけです
		DRIVERCRATE_EXPECT( context,
						   !controller
								   .beginInstall( scanned->scanResult.scanSessionId, selected,
												 InstallConfirmation::NOT_CONFIRMED)
								   .accepted &&
							   bound.observe().restoreBegins == 0U) ;
		const auto install =
			controller.beginInstall( scanned->scanResult.scanSessionId, selected,
									InstallConfirmation::CONFIRMED) ;	// fake本人同意です
		DRIVERCRATE_EXPECT( context,
						   install.accepted &&
							   bound.worker->requestInstall(
								   install.operationId, scanned->scanResult.scanSessionId, selected,
								   nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
		const auto completed = waitEvent( *bound.worker, WorkerEventKind::INSTALL_COMPLETED,
										 install.operationId) ;	// fake保護/既executorです
		DRIVERCRATE_EXPECT(
			context,
			completed && completed->installResult.succeeded && hostCalls == 0U &&
				bound.observe().restoreBegins == 1U && bound.observe().restoreCompletes == 1U &&
				*borrowed &&
				(localStore ? (*borrowed)->installs == 1U && (*borrowed)->managedInstalls == 0U
							: (*borrowed)->installs == 0U && (*borrowed)->managedInstalls == 1U)) ;
		bound.worker->stop() ;
		DRIVERCRATE_EXPECT( context, bound.allNativeHandlesClosed()) ;
		std::cout << "P4_NATIVE case="
				  << (localStore ? "P4_C23_DRIVER_STORE_PROTECTED" : "P4_C22_WUA_PROTECTED")
				  << " hostCallbacks=" << hostCalls << " restore=" << bound.observe().restoreBegins
				  << " provider="
				  << (localStore ? (*borrowed)->installs : (*borrowed)->managedInstalls) << '\n' ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 認可を発行しない実identity比較へ二十二の独立literalを渡します
 * @param[in,out] context 共通assertion集計です
 * @note 認証/取得/候補/Provider到達の試験とは別の純粋比較分母です
 */
//------------------------------------------------------------------------------
void runServerP4PureIdentityCases( TestContext &context)
{
	IndexDistributionRecord base ;	// 認証能力を持たない比較入力だけです
	base.recordSha256.fill( 0xbbU) ;
	base.packageEvidence.size.value = 1234U ;
	IndexManifestSha256 outer ;	// outerとINFとrecordを異なるliteralへ固定します
	outer.fill( 0xaaU) ;
	base.packageEvidence.publishedHash.sha256  = outer ;
	base.packageEvidence.calculatedHash.sha256 = outer ;
	IndexManifestSha256 infHash ;	// 原INFの独立比較材料です
	infHash.fill( 0xccU) ;
	base.publishedIdentityEvidence.state				 = IndexEvidenceState::PUBLISHED ;
	base.publishedIdentityEvidence.kind					 = IndexIdentityEvidenceKind::INF ;
	base.publishedIdentityEvidence.classGuid			 = "{4d36e978-e325-11ce-bfc1-08002be10318}" ;
	base.publishedIdentityEvidence.nestedArchiveIdentity = "nested/driver.zip" ;
	base.publishedIdentityEvidence.infIdentity			 = "drivers/fixture.inf" ;
	base.publishedIdentityEvidence.modelSection			 = "Models.NTamd64" ;
	base.publishedIdentityEvidence.evidenceSha256		 = infHash ;
	base.publishedIdentityEvidence.pnpIds				 = {
		   {IndexPnpIdKind::HARDWARE, "TESTBUS\\SYNTH_0001"},
		   {IndexPnpIdKind::COMPATIBLE, "TESTBUS\\P4_COMPAT_0001"}} ;
	CommonDriverPackageInspection inspected ;	// 外側の所有結果を比較するだけです
	inspected.archiveSha256 = std::wstring( 64U, L'a') ;
	inspected.archiveBytes	= 1234U ;
	IndexedDriverArchiveHint sealed{std::wstring( 64U, L'1'), std::wstring( 64U, L'b'),
									std::wstring( 64U, L'a'),
									1234U} ;	// 元sealの値比較だけでauthorityではありません
	CommonInfInspection		 member ;			// 実fileを所有しない純粋比較用memberです
	member.nestedArchivePath = L"nested\\driver.zip" ;
	member.infRelativePath	 = L"drivers\\fixture.inf" ;
	OfficialInfPublishedIdentity observed{std::wstring( 64U, L'c'),
										  L"{4d36e978-e325-11ce-bfc1-08002be10318}",
										  {{L"Models.NTamd64",
											{L"TESTBUS\\SYNTH_0001"},
											{L"TESTBUS\\P4_COMPAT_0001"}}}} ;	// SDK観測の値だけです
	// 原matrixのB01..B22を毎回独立copyへ一faultだけ適用します
	for( unsigned id = 1U; id <= 22U; ++id) {
		auto record	 = base ;		// 認可を持たない独立入力です
		auto archive = inspected ;	// 原outer期待です
		auto hint	 = sealed ;		// 原record結合です
		auto inf	 = member ;		// 同nested/INF位置です
		auto actual	 = observed ;	// 同Models/全typed IDです
		// case/順序の等値と原pathのslashだけを正例へ認めます
		if( id == 2U) {
			actual.classGuid						  = L"{4D36E978-E325-11CE-BFC1-08002BE10318}" ;
			actual.models.front().modelSection		  = L"models.ntAMD64" ;
			actual.models.front().hardwareIds.front() = L"testbus\\synth_0001" ;
			std::ranges::reverse( record.publishedIdentityEvidence.pnpIds) ;
		}
		// native/public separator以外を正規化しません
		else if( id == 3U) {
			inf.nestedArchivePath = L"nested/driver.zip" ;
			inf.infRelativePath	  = L"drivers/fixture.inf" ;
		}
		// 同文字列でも元kind違いを拒否します
		else if( id == 4U) {
			record.publishedIdentityEvidence.pnpIds.back().kind = IndexPnpIdKind::HARDWARE ;
		}
		// subsetを完全一致へしません
		else if( id == 5U) {
			actual.models.front().compatibleIds.clear() ;
		}
		// 追加IDも拒否します
		else if( id == 6U) {
			actual.models.front().compatibleIds.push_back( L"TESTBUS\\EXTRA") ;
		}
		// 同一IDの重複を除去して救済しません
		else if( id == 7U) {
			actual.models.front().hardwareIds.push_back( L"TESTBUS\\SYNTH_0001") ;
		}
		// 別Modelsをgenericへ読み替えません
		else if( id == 8U) {
			actual.models.front().modelSection = L"Models.Other" ;
		}
		// 同じ元節でも複数なら一意ではありません
		else if( id == 9U) {
			actual.models.push_back( actual.models.front()) ;
		}
		// 未観測は成功ではありません
		else if( id == 10U) {
			actual.models.clear() ;
		}
		// Classだけの差です
		else if( id == 11U) {
			actual.classGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
		}
		// INF原byte hashだけの差です
		else if( id == 12U) {
			actual.infSha256.assign( 64U, L'd') ;
		}
		// nested archiveだけの差です
		else if( id == 13U) {
			inf.nestedArchivePath = L"nested\\other.zip" ;
		}
		// INF memberだけの差です
		else if( id == 14U) {
			inf.infRelativePath = L"drivers\\other.inf" ;
		}
		// memberのcaseは原identityとして保持します
		else if( id == 15U) {
			inf.infRelativePath = L"drivers\\Fixture.inf" ;
		}
		// 同sealの外側hashとの差です
		else if( id == 16U) {
			archive.archiveSha256.assign( 64U, L'd') ;
		}
		// 同sealの外側sizeとの差です
		else if( id == 17U) {
			++archive.archiveBytes ;
		}
		// published outer hashだけの差です
		else if( id == 18U) {
			record.packageEvidence.publishedHash.sha256->fill( 0xddU) ;
		}
		// calculated outer hashだけの差です
		else if( id == 19U) {
			record.packageEvidence.calculatedHash.sha256->fill( 0xddU) ;
		}
		// UNKNOWN outerでは元record hashが必須です
		else if( id == 20U) {
			record.packageEvidence.size.value.reset() ;
			record.packageEvidence.publishedHash.sha256.reset() ;
			record.packageEvidence.calculatedHash.sha256.reset() ;
			hint.recordSha256.assign( 64U, L'd') ;
		}
		// 未公表のidentityは適合ではありません
		else if( id == 21U) {
			record.publishedIdentityEvidence.state = IndexEvidenceState::UNKNOWN ;
		}
		// 同hashのCATALOG申告でもINF根拠とは別です
		else if( id == 22U) {
			record.publishedIdentityEvidence.kind = IndexIdentityEvidenceKind::CATALOG ;
		}

		const bool expected = id <= 3U ;	// 実helperと独立した固定真偽です
		DRIVERCRATE_EXPECT( context, matchesIndexPublishedInf( record, archive, hint, inf, actual) ==
										expected) ;
		std::cout << "P4_PURE B" << id << " expected=" << expected << '\n' ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元二空ZIPが直接input/retained bind後に通常内容拒否となる期待を確認します
 * @param[in,out] context 共通assertion集計先です
 * @param[in] summary 完全fake通常scanが返した内容結果です
 * @param[in] retained 二件目も新LOCAL/retained bindから通常INF0拒否へ到達する期待です
 * @note 旧E_NOTIMPL fenceを合格へ残さず、非空の内容成功とは別に確認します
 */
//------------------------------------------------------------------------------
void assertServerP3InspectionFence( TestContext &context, const IndexPreparationSummary &summary,
								   const bool retained)
{
	DRIVERCRATE_EXPECT( context, summary.items.size() == (retained ? 2U : 1U)) ;
	// 元取得/直接bindの到達を保ち、空containerを有効driverへ読み替えません
	for( std::size_t index = 0U; index < summary.items.size(); ++index) {
		const auto &item = summary.items[index] ;	// 各元結果を独立に照合します
		DRIVERCRATE_EXPECT(
			context, item.acquisitionError == 0U && item.inputBound &&
						 item.contentError == HRESULT_FROM_WIN32( ERROR_TOO_MANY_OPEN_FILES) &&
						 item.acceptedInfCount == 0U && item.parsedInfCount == 0U &&
						 item.infCount == 0U && item.inventoryFileCount == 0U &&
						 item.content == IndexedDriverInspectionState::INSPECTION_FAILED &&
						 item.reusedOwnedBody == (retained && index + 1U == summary.items.size())) ;
	}

	// 最後の結果のrouteを原取得と区別します
	if( !summary.items.empty()) {
		DRIVERCRATE_EXPECT( context, summary.items.back().reusedOwnedBody == retained) ;
	}
}
#endif

} // namespace drivercrate::test
