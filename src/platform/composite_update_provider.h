//------------------------------------------------------------------------------
/**
 * @file composite_update_provider.h
 * @brief 複合update provider定義。
 * @version 01.10.02
 * @date 2026/09/01
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます。
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください。
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIXのPnP監査境界保持責務を反映。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel Ethernet Provider責務を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetへrank監査境界を固定。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernet監査reportを接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh PCL6表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  NVIDIA WinOF-2表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  ASIX AX88179A表示検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後候補のinstall routingを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの取得後監査を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Operation進捗通知追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  NVIDIA公式catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Dell公式PC catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider registryと状態報告追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  同一版取得元group追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Lenovo公式PC catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  HP公式PC catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  VAIO公式PC catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Dell PowerEdge catalog統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Intel Wireless local ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Prolific serial local ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH serial local ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH CH342／CH343系ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Silicon Labs CP210x ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用署名済みINF ZIP統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  AMD表示専用Provider統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS段階Provider統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASUS監査／install routing追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  ASRock表示専用Provider統合追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Local release観測失効接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Provider release差分・保存接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  段階別計測根拠とscan snapshotの統合を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Intel Ethernet Windows 11表示検索を接続。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  非機密な自動探索hint snapshotを保持。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  固定root自動探索registrationを保持。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  通常scan取消しを自動探索resolverへ結合。
 * Ver.01.05.00 Shunji Ogawa  2026/09/15  通常scanの共通自動探索結果を保持。
 * Ver.01.06.00 Shunji Ogawa  2026/09/15  自動探索payloadの準備取得状態を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/15  自動探索payloadのPnP観測状態を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * Ver.01.09.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  必要構成を持つ元索引選択の復旧前検査を結合。
 * Ver.01.10.01 Shunji Ogawa  2026/10/13  Field説明を完全な宣言開始前へ配置。
 * Ver.01.10.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 組み込みProviderの検索・取得・導入を同じregistryで管理し、旧sessionを拒否します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_acquisition.h"
#include "platform/official_delegated_package_inspection.h"
#include "platform/official_discovery_eula.h"
#include "platform/official_discovery_inventory.h"
#include "platform/official_discovery_package.h"
#include "platform/official_discovery_provider_adapter.h"
#include "platform/official_discovery_record_adapter.h"
#include "platform/official_download_workspace.h"
#include "platform/official_http_client.h"
#include "platform/official_release_discovery_provider.h"
#include "platform/official_release_local_probe.h"
#include "platform/official_release_observation_store.h"
#include "platform/official_serial_provider.h"
#include "platform/metadata_search_runner.h"

#include "core/official_preparation_operation.h"
#include "core/official_discovery.h"
#include "core/provider_registry.h"
#include "platform/signed_index_scan.h"
#include "core/scan_measurement.h"
#include "core/update_provider.h"
#include "platform/amd_update_provider.h"
#include "platform/asix_update_provider.h"
#include "platform/asrock_update_provider.h"
#include "platform/asus_update_provider.h"
#include "platform/broadcom_update_provider.h"
#include "platform/dell_server_update_provider.h"
#include "platform/dell_update_provider.h"
#include "platform/driver_store_provider.h"
#include "platform/hp_update_provider.h"
#include "platform/intel_wireless_package_provider.h"
#include "platform/lenovo_update_provider.h"
#include "platform/nvidia_update_provider.h"
#include "platform/nvidia_winof2_update_provider.h"
#include "platform/vaio_update_provider.h"
#include "platform/windows_update_provider.h"

#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// Provider class定義。
//------------------------------------------------------------------------------

/**
 * @brief network update と local driver 履歴を取得元を保ったまま統合する Provider である。
 */
class CompositeUpdateProvider final : public IUpdateProvider, public IIndexScanInventory {
public:
	/** @brief 同じComposite inventory scanの秘密resolverをworkerへ貸します。
	 * @param[in] operationId 正のworker operation。
	 * @param[out] context 元Driver Store発行context。拒否時空です。
	 * @param[out] present 全present opaque。拒否時空です。
	 * @return 実列挙stateをweak所有するcallback。追加I/Oや導入を行いません。
	 */
	[[nodiscard]] std::unique_ptr<IndexPublicIdResolver> indexScanInventory(
		OperationId operationId, IndexLookupContext &context,
		std::vector<std::wstring> &present) override ;
	/**
	 * @brief WUA、Driver Store、公式vendor catalogをregistryへ登録する。
	 * 異なるProvider interfaceを型消去した共通dispatchへ登録する。
	 */
	CompositeUpdateProvider() ;

	/**
     * @brief 保持中の Provider と scan session を解放する。
     */
	~CompositeUpdateProvider() override = default ;

	/**
	 * @brief 同じscanのregistry entryが保持した配布情報から取得計画を集約する。
	 * 既存の取得付きscanを二重取得対象へ加えず、registryの任意callbackだけを使用する。
	 * @param[in] scanSessionId 現在有効なaggregate検索session。
	 * @param[in] planId workerが発行した新計画ID。
	 * @return 未承認対象の計画。対象なし／旧sessionの場合はnullopt。 登録済み保持情報を集約した未承認計画。対象がなければnullopt。
	 */
	[[nodiscard]] std::optional<OfficialPreparationPlan> preparationPlan(
		ScanSessionId scanSessionId, std::uint64_t planId) override ;

	/**
	 * @brief 現在scanで有効なregistryの取得callbackへ承認済みtaskを渡す。
	 * 既存registryの有効な取得callbackだけへ渡し、別のメーカー分岐や任意URLを使わない。
	 * @param[in] task workerがclaimした計画対象。 Workerが承認・claimした計画対象。
	 * @param[in] cancellation 空または協調取消し照会。
	 * @return 検査用取得の結果。未対応・別sessionは拒否する。 対象Providerの取得結果。旧session・未対応は拒否。
	 */
	[[nodiscard]] OfficialPreparationTransferResult acquireForInspection(
		const OfficialPreparationTask &task, const PreparationCancellation &cancellation) override ;

	/**
	 * @brief 取得成功対象だけの非機密監査結果をregistry経由で集約する。
	 * 全reportを既存scanへ照合し、成功時だけ追加候補のdevice／Provider routingを一括反映する。
	 * @param[in] result 同一scanの確定した取得結果。 同じworkerが確定した取得結果。
	 * @return 既存行の監査と全監査合格時の追加候補。別session、未取得は含めない。 取得成功対象の非機密reportと追加候補集合。旧結果は空。
	 */
	[[nodiscard]] std::vector<OfficialPreparationAuditReport> preparationAuditReports(
		const OfficialPreparationOperationResult &result) override ;

	/**
	 * @brief 既存installの候補routingを保ち、取得準備用の保持情報だけを失効させる。
	 */
	void invalidatePreparation() noexcept override ;

	/**
	 * @brief Provider sessionと私有routing tableの複製構築をコンパイル時に禁止します。
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです。
	 * @note 削除宣言だけで関数本体やresource操作はありません。
	 */
	CompositeUpdateProvider( const CompositeUpdateProvider &other) = delete ;
	/**
	 * @brief Provider sessionと私有routing tableの複製代入をコンパイル時に禁止します。
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです。
	 * @return 宣言された自己参照型です。削除宣言なので戻り値を生成しません。
	 * @note 削除宣言だけで関数本体やresource操作はありません。
	 */
	CompositeUpdateProvider &operator=( const CompositeUpdateProvider &other) = delete ;
	/**
	 * @brief Provider sessionと私有routing tableの移動構築をコンパイル時に禁止します。
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです。
	 * @note 削除宣言だけで関数本体やresource操作はありません。
	 */
	CompositeUpdateProvider( CompositeUpdateProvider &&other) = delete ;
	/**
	 * @brief Provider sessionと私有routing tableの移動代入をコンパイル時に禁止します。
	 * @param[in] other 実行可能な呼出しを持たず、借用・変更・所有権移動を行わない元objectです。
	 * @return 宣言された自己参照型です。削除宣言なので戻り値を生成しません。
	 * @note 削除宣言だけで関数本体やresource操作はありません。
	 */
	CompositeUpdateProvider &operator=( CompositeUpdateProvider &&other) = delete ;

	/**
	 * @brief WUA、local Driver Store、公式vendor catalogを検索して候補へ統合する。
	 * WUA、local Driver Store、公式vendorを検索し、取得元を保持した候補へ統合する。 注記:一方だけが失敗した場合は、取得できた候補を警告付き成功として返す。
	 * @param[in] scanSessionId 呼出し側が割り当てた 0 ではない session ID。 呼出し側が割り当てた 0 ではないsession ID。
	 * @param[in] options 有効にする組み込みProvider ID集合。 有効なProviderを指定するscan条件。
	 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
	 * @return 各Providerの候補と集約した成否を含むscan結果。
	 * @note 一方だけが失敗した場合は、取得できた候補を警告付き成功として返す。
	 */
	[[nodiscard]] ScanResult scan( ScanSessionId scanSessionId, const ScanOptions &options,
								  const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief 通常scanの一操作限定取消しを公式自動探索へ渡す。
	 * @param[in] scanSessionId 呼出し側が割り当てた0ではないsession ID。
	 * @param[in] options 選択Providerと一scan承認の不変snapshot。
	 * @param[in] cancellation 同期scan実行中だけ借用する非blocking取消し照会。
	 * @param[in] progressCallback 確定した段階と完了率の通知先。
	 * @return 各Providerの候補と取消しを含む有限結果。
	 */
	[[nodiscard]] ScanResult scanWithCancellation(
		ScanSessionId scanSessionId, const ScanOptions &options,
		const ProviderScanCancellation &cancellation,
		const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief 直前の通常scanで共通自動探索が生成した非機密summaryを参照する。
	 * @return 現在scanにsummaryがあれば次scanまたは失効まで有効な借用pointer。なければnullptr。
	 * @note UI、永続logまたは診断保存へdevice identityをそのまま渡しません。
	 */
	[[nodiscard]] const OfficialDiscoverySummary *officialDiscoverySummary() const noexcept ;

	/**
	 * @brief 専用callbackと現在属性だけで情報検索し、旧routingを再使用不能にする。
	 * @param[in] scanSessionId 専用contextと一致するsession。
	 * @param[in] request 明示した専用Provider集合と今回の回線許可。
	 * @param[in,out] execution 同期実行中だけ借用する有限予算。
	 * @param[in] progressCallback 確定した全体進捗の通知先。
	 * @return 表示専用の部分結果と用途付きsummary。
	 */
	[[nodiscard]] ScanResult					  scanMetadataOnly(
							 ScanSessionId scanSessionId, const MetadataSearchRequest &request,
							 MetadataSearchExecutionContext &execution,
							 const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief 選択 identity を取得元 Provider へ振り分けて download/install する。
	 * 選択identityを取得元Providerへ振り分けてdownload/installする。
	 * @param[in] scanSessionId 選択元の aggregate scan session ID。 選択元のaggregate scan session ID。
	 * @param[in] identities UI に提示済みの opaque identity 群。 UIに提示済みのopaque identity群。
	 * @param[in] parentWindowNative Windows dialog の親 HWND を整数表現で渡す値。 Windows dialogの親HWNDを整数表現で渡す値
	 *                   。
	 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
	 * @return 元の選択順へ集約した update ごとの実行結果。
	 */
	[[nodiscard]] InstallResult install( ScanSessionId					scanSessionId,
										std::span<const std::wstring>	identities,
										std::uintptr_t					parentWindowNative,
										const ProviderProgressCallback &progressCallback) override ;

private:
	friend class ProviderWorker ;
	/** @brief 元必要role selectionを復旧開始前にread-onlyで一括確認します。
	 * @param[in] session 元通常scanです。
	 * @param[in] identities 通常画面の明示選択です。
	 * @return 元全byte/期限/状態一致0、不足はHRESULTです。
	 */
	[[nodiscard]] NativeError preflightRequiredSignedIndexInstall(
		ScanSessionId session, std::span<const std::wstring> identities) const ;
	friend struct signed_index_candidate_binding_detail::Access ;
	/** @brief 同workerの索引ownerと固定serviceを一回scanへ借用結合します。
	 * @param[in,out] session Workerが寿命を所有する元索引session。
	 * @param[in] services Worker開始前に固定した依存。
	 * @param[in] operationId 今回通常scan操作。
	 * @param[in] cancellation 同期処理だけへ限定する停止照会。
	 */
	void bindSignedIndexSession( SignedIndexScanSession						 &session,
								const provider_worker_index_detail::Services &services,
								OperationId									  operationId,
								ProviderScanCancellation cancellation) noexcept ;
	/** @brief 元索引targetへ非導入参照を結合して通常候補routingへ原子的に加えます。
	 * @param[in] plan 同lookupから発行した準備計画。
	 * @param[in,out] result 同scanでUIへ発行する結果。
	 */
	void finishSignedIndexScanPublication( const OfficialPreparationPlan &plan, ScanResult &result) ;
	/// Workerが終端まで所有する同sessionへの借用。
	SignedIndexScanSession						 *signedIndexSession_{} ;
	/// Worker生成時に固定したserviceへの借用。
	const provider_worker_index_detail::Services *signedIndexServices_{} ;
	/// 今回の通常scan操作ID。
	OperationId									  signedIndexOperation_{} ;
	/// 同scanの取消し照会。
	ProviderScanCancellation					  signedIndexCancellation_ ;
	/// 同registry callbackが一回生成した非機密索引summary。
	IndexScanSummary							  signedIndexSummary_ ;
	/**
     * @brief Aggregate scan内でProviderを実行する段階を表す。
     */
	enum class ProviderPhase {
		/// Local device inventoryを先に構築する。
		INVENTORY,
		/// Windows Update等の管理serviceへ問い合わせる。
		MANAGED_SERVICE,
		/// Local snapshotを公式vendor catalogへ照合する。
		OFFICIAL_CATALOG,
	} ;

	/**
	 * @brief 組み込みProviderの異なるscan呼出しをregistry内の共通署名へ結合する。
	 */
	using RegistryScanFunction = std::function<ScanResult(
		ScanSessionId, const ScanOptions &, std::span<const OfficialCatalogDevice>,
		const LocalHardwareIdMatcher &, const ProviderProgressCallback &)> ;
	/**
	 * @brief Registryに保持したProviderへ、sessionと選択集合を引き渡す導入callback。
	 */
	using RegistryInstallFunction =
		std::function<InstallResult( ScanSessionId, std::span<const std::wstring>, std::uintptr_t,
									const ProviderProgressCallback &)> ;

	/**
     * @brief 一つの組み込みProviderとsession routing状態を保持する。
     */
	struct RegisteredProvider {
		/// Stable ID、表示名、capability、既定状態。
		ProviderDescriptor		descriptor ;
		/// Aggregate scan内の実行順序。
		ProviderPhase			phase{} ;
		/// Provider固有scanを呼び出す関数。
		RegistryScanFunction	scan ;
		/// Provider固有installを呼び出す関数。
		RegistryInstallFunction install ;
		/// 保持metadataの対象化。未対応は空function。
		std::function<std::vector<OfficialPreparationTarget>( ScanSessionId, std::uint64_t)>
								   preparationTargets ;
		/// noexceptな保持情報失効処理。
		std::function<void()>	   invalidatePreparation ;
		/// 承認済み対象の取得。未対応は空。
		PreparationAcquireFunction acquireForInspection ;
		/// 同じ取得対象の監査表示。未接続は空callback。
		std::function<std::optional<OfficialPreparationAuditReport>( ScanSessionId,
																	std::wstring_view)>
			preparationAuditReport ;
		/// 前回観測と現在環境のworker内設定。
		std::function<void( std::span<const LocalOfficialReleaseObservation>,
						   const OfficialReleaseEnvironmentFingerprints &)>
			configureReleaseObservations ;
		/// 成立scanが生成した今回観測の参照。
		std::function<std::span<const LocalOfficialReleaseObservation>()> releaseObservations ;
		/// 接続済みProviderのworker内計測根拠。未対応は空function。
		std::function<const ProviderMeasurementEvidence &()>			  measurementEvidence ;
		/// Metadata専用の非取得経路。能力のない登録は空であり通常scanへfallbackしない。
		MetadataProviderScan											  metadataScan ;
		/// 現在sessionで候補検索を有効にした状態。
		bool															  enabledForSession{} ;
	} ;

	/**
	 * @brief 一つの自動探索payloadについて取得と内容検査のworker内状態を所有する。
	 * @note 取得成功は導入権限へ変換せず、installerは専用監査未接続の状態を保持します。
	 */
	struct OfficialDiscoveryPreparedPayload {
		/// 既存準備計画へ公開したURL非保持対象snapshot。
		OfficialPreparationTarget						  target ;
		/// 同じpayloadをrecord証拠、route、deviceへ戻す実行group。
		OfficialDiscoveryPackageGroup					  group ;
		/// Scan時の公開metadataとpayload方式を保持するURL非保持descriptor。
		OfficialRecordPayloadDescriptor					  descriptor ;
		/// 同じpackageとdevice順へ結合した既存の非選択表示行ID集合。
		std::vector<std::wstring>						  candidateIdentities ;
		/// EULA必須対象の完全一致snapshot。同意不要なら空です。
		OfficialDiscoveryEulaPackage					  eulaPackage ;
		/// 取得層が返したURL非保持の取得結果。
		OfficialAcquisitionResult						  acquisition ;
		/// 共通INF検査へ渡したURL非保持の入力snapshot。
		DelegatedOfficialPackageInput					  packageInput ;
		/// 共通INF内容検査のworker内結果。
		CommonDriverPackageInspection					  packageInspection ;
		/// 内容合格INFとdeviceのread-only PnP観測結果。
		std::vector<DelegatedOfficialDeviceApplicability> applicability ;
		/// 取得後の入力変換または内容検査診断値。
		NativeError										  inspectionError{} ;
		/// Device別PnP観測の全体診断値。
		NativeError										  applicabilityError{} ;
		/// EULA snapshotを同意sessionへ結合した対象ならtrue。
		bool											  eulaRequired{} ;
		/// 同じ計画対象への二重取得を拒否する一回試行状態。
		bool											  attempted{} ;
	} ;

	/**
	 * @brief Aggregate routing、表示候補、端末内release観測contextを失効させる。
	 * Candidate routing、表示snapshot、前回release観測のmemory copyを同時に破棄し、次scanへ持ち越さない。
	 */
	void invalidateScanSession() noexcept ;

	/**
	 * @brief 公式catalog snapshotへ端末内bindingと環境失効条件を設定する。
	 * 端末固有keyをworker内だけで使用し、OSまたは全device集合が変わった前回観測を保護stateから除外する。失敗時も公式検索は継続し、再利用だけを無効化する。
	 * @param[in,out] devices 現在scanの非機密device snapshot。
	 * @note Stateまたはfingerprint生成失敗は公式検索を止めず、前回観測だけを使用不能にする。
	 */
	void prepareLocalReleaseObservationContext( std::span<OfficialCatalogDevice> devices) ;

	// Callbackを保持する全Providerの破棄までbinding所有者を生存させる。
	/// Local deviceとDriver Storeの所有者。
	DriverStoreProvider				 driverStoreProvider_ ;
	/// AMD公式Web表示情報を扱うprovider。
	AmdUpdateProvider				 amdUpdateProvider_ ;
	/// AX88179Aの検索・取得とPnP監査境界を扱う。
	AsixUpdateProvider				 asixUpdateProvider_ ;
	/// ASRock公式Web表示情報を扱うprovider。
	AsrockUpdateProvider			 asrockUpdateProvider_ ;
	/// NetXtreme-Eの検索・取得・内容／PnP監査を扱う。
	BroadcomUpdateProvider			 broadcomUpdateProvider_ ;
	/// Intel Wi-Fiの公式配布情報だけを扱う。
	OfficialReleaseDiscoveryProvider intelWifiOfficialProvider_{OfficialReleaseFamily::INTEL_WIFI} ;
	/// Windows 11向けIntel Ethernetの公式配布情報だけを扱う。
	OfficialReleaseDiscoveryProvider intelEthernetWindows11OfficialProvider_{
		OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11} ;
	/// Server検索、取得、監査、指定INF導入を扱う。
	OfficialReleaseDiscoveryProvider intelEthernetServerOfficialProvider_ ;
	/// Ricoh PCL6の公式配布情報だけを扱う。
	OfficialReleaseDiscoveryProvider ricohUniversalPrintProvider_{
		OfficialReleaseFamily::RICOH_UNIVERSAL_PCL6} ;
	/// Wacom統合driver配布情報だけを扱う。
	OfficialReleaseDiscoveryProvider wacomWindowsProvider_{
		OfficialReleaseFamily::WACOM_WINDOWS_TABLET} ;
	/// 限定製品の配布情報を扱う。
	OfficialReleaseDiscoveryProvider focusriteScarlett2i2Provider_{
		OfficialReleaseFamily::FOCUSRITE_SCARLETT2I2_SECOND_GEN} ;
	/// ASUS公式監査済みINFを扱うprovider。
	AsusUpdateProvider			   asusUpdateProvider_ ;
	/// 公式DCHU ZIPの明示取得と監査。
	OfficialSerialProvider		   prolificOfficialProvider_{OfficialSerialFamily::PROLIFIC} ;
	/// 公式CP210x ZIPの明示取得と監査。
	OfficialSerialProvider		   siliconLabsOfficialProvider_{OfficialSerialFamily::SILICON_LABS} ;
	/// 公式CH341SER ZIPの明示取得と固定hash監査。
	OfficialSerialProvider		   wchOfficialProvider_{OfficialSerialFamily::WCH_CH341} ;
	/// 公式CH343SER ZIPの明示取得と固定hash監査。
	OfficialSerialProvider		   wchMultiOfficialProvider_{OfficialSerialFamily::WCH_CH343} ;
	/// PowerEdge公式catalog provider。
	DellServerUpdateProvider	   dellServerUpdateProvider_ ;
	/// Dell公式PC catalogを扱うprovider。
	DellUpdateProvider			   dellUpdateProvider_ ;
	/// HP公式SoftPaq catalogを扱うprovider。
	HpUpdateProvider			   hpUpdateProvider_ ;
	/// 取得元未証明の利用者選択driver-only ZIPを扱うProvider。
	UserSelectedInfPackageProvider genericSignedInfPackageProvider_ ;
	/// 利用者選択Intel INF ZIP。
	UserSelectedInfPackageProvider intelWirelessPackageProvider_ ;
	/// 利用者選択Prolific INF ZIP。
	UserSelectedInfPackageProvider prolificSerialPackageProvider_ ;
	/// 利用者選択Silicon Labs CP210x INF ZIP。
	UserSelectedInfPackageProvider siliconLabsSerialPackageProvider_ ;
	/// 利用者選択WCH INF ZIP。
	UserSelectedInfPackageProvider wchSerialPackageProvider_ ;
	/// 利用者選択WCH CH342／CH343系INF ZIP。
	UserSelectedInfPackageProvider wchMultiSerialPackageProvider_ ;
	/// Lenovo公式PC catalogを扱うprovider。
	LenovoUpdateProvider		   lenovoUpdateProvider_ ;
	/// NVIDIA公式catalogを扱うprovider。
	NvidiaUpdateProvider		   nvidiaUpdateProvider_ ;
	/// NVIDIA Networking表示情報を扱うprovider。
	NvidiaWinof2UpdateProvider	   nvidiaWinof2UpdateProvider_ ;
	/// VAIO Global公式catalogを扱うprovider。
	VaioUpdateProvider			   vaioUpdateProvider_ ;
	/// Network updateを扱うWUA provider。
	WindowsUpdateProvider		   windowsUpdateProvider_ ;
	/// 固定公式rootのmetadataだけをcacheなしで取得するworker所有client。
	OfficialHttpClient			   officialDiscoveryHttpClient_{false} ;
	/// 自動探索で解決した秘密recordとURL非保持package参照のsession所有者。
	OfficialDiscoveryRecordAdapterSession		  officialDiscoveryRecordSession_ ;
	/// Provider正本、固定source、matcher、resolverを結合した自動探索registration。
	std::vector<OfficialDiscoveryRegistration>	  officialDiscoveryRegistrations_ ;
	/// 現在の通常scanだけから固定root resolverへ渡す取消し照会。
	ProviderScanCancellation					  officialDiscoveryCancellation_ ;
	/// 現在の通常scanへ結合したURL非保持の自動探索summary。
	std::optional<OfficialDiscoverySummary>		  officialDiscoverySummary_ ;
	/// 同一EULAを一回だけ表示・判断する現在scan限定session。
	OfficialDiscoveryEulaSession				  officialDiscoveryEulaSession_ ;
	/// 自動探索で取得可能になった最大4 payloadのworker内状態。
	std::vector<OfficialDiscoveryPreparedPayload> officialDiscoveryPreparedPayloads_ ;
	/// EULA group順で一回判断を記録済みならtrueとなる固定長状態。
	std::vector<bool>							  officialDiscoveryAcceptedEulaGroups_ ;
	/// 一recordの複数payloadへgrantを発行するclaim済み秘密record索引。
	std::unordered_map<std::uint64_t, ResolvedOfficialDistributionRecord>
												   officialDiscoveryClaimedRecords_ ;
	/// 自動探索payloadを一scanの有限予算で取得するledger。
	std::unique_ptr<OfficialAcquisitionSession>	   officialDiscoveryAcquisitionSession_ ;
	/// 取得fileを候補監査終了まで所有する保護workspace。
	std::unique_ptr<OfficialDownloadWorkspace>	   officialDiscoveryWorkspace_ ;
	/// Workerが今回発行した準備計画ID。対象公開前は0です。
	std::uint64_t								   officialDiscoveryPreparationPlanId_{} ;
	/// 同じscan内で再使用しない次のrecord限定grant ID。
	std::uint64_t								   nextOfficialDiscoveryGrantId_{1U} ;
	/// Process中に再使用しない自動探索inventory世代の高水位。
	std::uint64_t								   latestOfficialDiscoveryInventoryGeneration_{} ;
	/// 管理者保護された前回release観測と端末固有key。
	OfficialReleaseObservationStore				   releaseObservationStore_ ;
	/// 現在OSとdevice集合へ一致し、X6-04のProvider差分確認へ渡せる前回観測。
	std::vector<LocalOfficialReleaseObservation>   reusableReleaseObservations_ ;
	/// 現在のOSとdevice集合の失効用hash。
	OfficialReleaseEnvironmentFingerprints		   releaseEnvironmentFingerprints_ ;
	/// Scan/install dispatchの登録順正本。
	std::vector<RegisteredProvider>				   providerRegistry_ ;
	/// 候補とProvider ID。
	std::unordered_map<std::wstring, std::wstring> identityProviders_ ;
	/// 候補とdeviceの対応。
	std::unordered_map<std::wstring, std::wstring> identityDevices_ ;
	/// 現在scanでUIへ発行した候補snapshot。
	std::vector<UpdateCandidate>				   displayedCandidates_ ;
	/// 現在scanの完全なpresent inventoryから作ったraw ID非保持hint。
	std::vector<OfficialDiscoveryDeviceHint>	   officialDiscoveryHints_ ;
	/// 現在有効なaggregate scan session ID。
	ScanSessionId								   scanSessionId_{} ;
	/// 現在の権限用途。表示専用sessionから準備・導入を受理しない。
	ScanPurpose									   scanPurpose_{ScanPurpose::STANDARD} ;
} ;

} // namespace drivercrate
