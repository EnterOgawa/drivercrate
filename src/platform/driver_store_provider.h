//------------------------------------------------------------------------------
/**
 * @file driver_store_provider.h
 * @brief Driver Store provider定義
 * @version 01.37.00
 * @date 2026/09/01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Binding指定INF導入を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Operation進捗通知追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通scan条件対応
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  検証済み外部INF導入境界追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  PnP rank非退行監査追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  端末内binding生成境界追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Local inventory計測参照を追加
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  現在版を要求しない単一INF適合観測を追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  同scan秘密属性の公表ID専用resolverを追加
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  明示初回状態と実登録INFの同scan共有所有を追加
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続
 * Ver.01.04.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足
 * Ver.01.05.00 Shunji Ogawa  2026/10/13  元Class観測とINF/native Classの私有binding保存を追加
 * Ver.01.06.00 Shunji Ogawa  2026/10/13  私有issuer限定の必要構成再検査と指定実行を追加
 * Ver.01.07.00 Shunji Ogawa  2026/10/13  同issuerの元node選択節から必要構成を発行
 * Ver.01.07.01 Shunji Ogawa  2026/10/15  必要roleの登録byte保持期間を計画終端へ明示
 * Ver.01.08.00 Shunji Ogawa  2026/10/15  非通信開発検査へ必要INF bindingの数値段階を追加
 * Ver.01.08.01 Shunji Ogawa  2026/10/28  索引proofを明示選択batchの終端まで私有scopeで保持
 * Ver.01.09.00 Shunji Ogawa  2026/10/28  選択対象の導入後実観測と現在行の自動更新を接続
 * Ver.01.10.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続
 * Ver.01.11.00 Shunji Ogawa  2026/11/09  導入後の一回fresh候補再評価と元表示保持を接続
 * Ver.01.12.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続
 * Ver.01.13.00 Shunji Ogawa  2026/11/10  最新実確認の選択表示と日内復元保護の実在再利用を接続
 * Ver.01.13.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.13.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.13.03 Shunji Ogawa  2026/11/13  元適用性errorへ固定失敗leafとcode由来だけを接続
 * Ver.01.14.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.15.00 Shunji Ogawa  2026/11/17  MTD同operationと原期限再照合を宣言
 * Ver.01.16.00 Shunji Ogawa  2026/11/17  必要子の同親operationに限定した所有観測を宣言
 * Ver.01.17.00 Shunji Ogawa  2026/11/19  独自クラスの一意な互換nodeを読み取りで元Models行へ照合
 * Ver.01.18.00 Shunji Ogawa  2026/11/19  実ドライバー行のクラス登録読取りと診断を追加
 * Ver.01.19.00 Shunji Ogawa  2026/11/19  独自クラスの選択行専用の順位監査結果を保持
 * Ver.01.20.00 Shunji Ogawa  2026/11/19  独自クラスの配置先照合に元共通閉包を渡す
 * Ver.01.21.00 Shunji Ogawa  2026/11/19  独自クラスの元選択と導入直前の再検証を結合
 * Ver.01.22.00 Shunji Ogawa  2026/11/20  公式索引が指定するHardware IDを導入時の端末再観測へ結合
 * Ver.01.23.00 Shunji Ogawa  2026/11/20  公式索引の元権限を登録と指定導入の直前に確認
 * Ver.01.24.00 Shunji Ogawa  2026/11/20  公式ファームウェア群を同じ端末の現在属性から再観測
 * Ver.01.25.00 Shunji Ogawa  2026/11/20  元の群を登録と指定適用の直前に確認する資格を保持
 * Ver.01.26.00 Shunji Ogawa  2026/11/21  標準シリアルページの固定証拠を端末の元選択に保持
 * Ver.01.27.00 Shunji Ogawa  2026/11/22  公式Models専用行のWindows選択と現在HardwareIdsを読取
 * Ver.01.28.00 Shunji Ogawa  2026/11/22  公式Modelsの一意な選択行と元閉包の必要関係を返す
 * Ver.01.29.00 Shunji Ogawa  2026/11/22  公式Modelsの取得物・選択行と実作用を私有計画へ結合
 * Ver.01.30.00 Shunji Ogawa  2026/11/22  公式Modelsの私有計画を既存トークンに固定して再照合
 * Ver.01.31.00 Shunji Ogawa  2026/11/22  公式Modelsの登録前承認と登録済み閉包の再照合を接続
 * Ver.01.32.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの上位フィルター元値を端末資格へ結合
 * Ver.01.33.00 Shunji Ogawa  2026/11/22  元端末の現在状態と完全Hardware IDを配布前に再照合
 * Ver.01.33.01 Shunji Ogawa  2026/11/22  指定適用と補助サービスの反映確認の契約を明記
 * Ver.01.34.00 Shunji Ogawa  2026/11/23  指定適用から自動起動型の事後観測を返す経路を追加
 * Ver.01.35.00 Shunji Ogawa  2026/11/23  同一Windows互換ノードの同梱INF委譲を読取り確認
 * Ver.01.36.00 Shunji Ogawa  2026/11/23  起動サービスと設定の独立確認を指定適用から返す
 * Ver.01.37.00 Shunji Ogawa  2026/11/23  WiXの署名付きModels対象を単一起動の選択に結合
 * </pre>
 *
 * @note 現在のPnP deviceとlocal Driver Storeの互換driver providerを定義します。Hardware IDとdevice instance IDは
 *       worker thread内だけに保持します。INF pathもUIまたはlogへ渡しません
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_driver_rank.h"
#include "core/official_release_observation.h"
#include "core/scan_measurement_types.h"
#include "core/update_provider.h"
#include "platform/official_catalog_device.h"
#include "platform/official_file_verifier.h"
#include "platform/official_inf_install_binding.h"
#include "platform/driver_store_inventory_transport.h"
#include "platform/mtd_handler_internal.h"
#include "platform/signed_index_record_lookup.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;
struct OfficialDriverClosure ;
struct OfficialInfPackage ;
struct OfficialInfScopedModelMatch ;
enum class OfficialInfSelectedModelRole ;
struct CommonInfInspection ;
struct CollectorDriverPackageContent ;
struct IndexDistributionRecord ;
struct IndexedDriverArchiveHint ;
struct RequiredInfBindingDiagnostic ;
class RequiredDriverComponentPlan ;
struct DeclarativeInfInstallQualification ;
struct ScopedInfInstallQualification ;
class StorageInfQualification ;
class MtdSharedFileOperation ;
struct MtdQueueResult ;
class SignedIndexCandidateBindingSession ;

/**
 * @brief 署名付きWiXレコードと同じ機器の照合で許可された元Models範囲です
 * @note 呼出し中だけ元値を借用します。構築だけでは資格を発行しません
 */
struct OfficialStorageInfModelScope {
	/// 署名レコードが指定する現在OSの元Models節です
	std::wstring_view			  modelsSection ;
	/// 同節の元レコードと同じ選択機器が共有する完全Hardware IDです
	std::span<const std::wstring> hardwareIds ;
} ;

//------------------------------------------------------------------------------
// Provider class定義
//------------------------------------------------------------------------------

/**
 * @brief SetupAPI で local driver inventory と指定版の導入を提供する Provider である
 */
class DriverStoreProvider final : public IUpdateProvider {
public:
	/**
     * @brief 現在 thread に所属する空の Driver Store Provider を作成する
     */
	DriverStoreProvider() = default ;
	/**
	 * @brief 元同scanの選択scopeと未処理所有を当該操作へ結びます
	 * @param[in] operationId 当該新操作です
	 * @param[in] session 未失効の元scanです
	 * @param[in] identities 元表示の選択candidate subsetです
	 * @return 元scopeの全件照合成功0、それ以外は拒否HRESULTです
	 */
	[[nodiscard]] NativeError beginInstallOperation(
		OperationId operationId, ScanSessionId session,
		std::span<const std::wstring> identities) override ;
	/**
	 * @brief 元同scanの選択scopeと未処理所有を当該操作へ結びます
	 * @param[in] operationId 当該新操作です
	 * @param[in] session 未失効の元scanです
	 * @return 当該操作の原未消費subsetです。不明な操作は空です
	 */
	[[nodiscard]] std::optional<InstallRetentionSummary> finishInstallOperation(
		OperationId operationId, ScanSessionId session) override ;
	/**
	 * @brief Compositeで検証した元device subsetを当該操作へ拘束します
	 * @param[in] operationId 新しいInstall操作です
	 * @param[in] session 未失効の元scanです
	 * @param[in] devices 元発行の一意なdevice subsetです
	 * @param[in] allowEmpty WUAだけの操作にnative実行scopeを作らず元ownerを保持する内部指定です
	 * @return 成功0、stale/不明/重複は失敗です。native変更は行いません
	 */
	[[nodiscard]] NativeError bindInstallDevices( OperationId operationId, ScanSessionId session,
												 std::span<const std::wstring> devices,
												 bool						   allowEmpty = false) ;
	/**
	 * @brief 実Provider入口を通った当該操作だけを消費対象へ記録します
	 */
	void					  markInstallEntered() noexcept ;

	/**
	 * @brief 現在属性の非通信内部試験用API表を所有copyする
	 * @param[in] transport 完全なSetupAPI代替表。欠損をnative呼出しで補完しない
	 * @note このinstanceはscanCurrentInventory専用。通常scanと導入sessionを発行しない
	 */
	explicit DriverStoreProvider( DriverStoreInventoryTransport transport) noexcept ;

	/**
     * @brief scan session と秘密性のある native metadata を解放する
     */
	~DriverStoreProvider() override = default ;

	// Native scan sessionを単独所有するためcopy/moveを禁止する
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	DriverStoreProvider( const DriverStoreProvider &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	DriverStoreProvider &operator=( const DriverStoreProvider &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	DriverStoreProvider( DriverStoreProvider &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
	 */
	DriverStoreProvider		&operator=( DriverStoreProvider &&) = delete ;

	/**
	 * @brief 現在の PnP device と compatible Driver Store 履歴を列挙する
	 * 現在の PnP device と compatible Driver Store履歴を列挙する。 注記: network 通信、download、およびsystem state の変更は
	 * 行わない
	 * @param[in] scanSessionId 呼出し側が割り当てた 0 ではない session ID。 呼出し側が割り当てた 0 ではないsession ID
	 * @param[in] options Aggregate Provider以外では既定値を使用するscan設定。 複合Providerで検証済みのscan条件
	 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先
	 * @return 現在版と切替可能な local driver 候補を含む scan 結果
	 * @note network 通信、download、および system state の変更は行わない
	 */
	[[nodiscard]] ScanResult scan( ScanSessionId scanSessionId, const ScanOptions &options,
								  const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief 履歴・native照合map・install targetを生成せず現在属性だけを列挙する
	 * @param[in] scanSessionId 専用contextと一致するworker session
	 * @param[in,out] execution 同期呼出し中だけ借用する取消し・期限context
	 * @param[in] progressCallback 確定した列挙件数の通知先
	 * @return 表示専用の現在行。途中停止では検証済み行と不完全な計測を保持
	 */
	[[nodiscard]] ScanResult scanCurrentInventory( ScanSessionId					  scanSessionId,
												  MetadataSearchExecutionContext &execution,
												  const ProviderProgressCallback &progressCallback) ;

	/**
	 * @brief 現在属性scanへ索引専用の秘密ID captureだけを追加します
	 * @param[in] scanSessionId 専用contextと一致する正のsession
	 * @param[in,out] execution 同期呼出し中だけ借用する停止context
	 * @param[in] progressCallback 確定進捗の通知先
	 * @return 表示専用の現在行と独立した秘密resolver state
	 * @note 完全transport内だけで実行し、履歴・install session・native fallbackを発行しません
	 */
	[[nodiscard]] ScanResult scanCurrentIndexInventory(
		ScanSessionId scanSessionId, MetadataSearchExecutionContext &execution,
		const ProviderProgressCallback &progressCallback) ;

	/**
	 * @brief 同scanの秘密snapshotをweak所有するread-only resolverを発行します
	 * @param[in] operationId 結合する正のworker operation
	 * @param[out] context 発行時だけsessionと単調inventory世代を返します。拒否時は空です
	 * @param[out] present 全観測opaque集合。拒否時は空です。生IDは含みません
	 * @return 所有threadの有効snapshotだけがcallbackを持ちます。拒否時はnullptrです
	 * @note Workerで同期呼出しし再入しません。新scan・install・Provider破棄で旧callbackは失効します。不完全snapshotのcallbackも発行できま
	 *       すが、resolveのcompletedはfalseです
	 */
	[[nodiscard]] std::unique_ptr<IndexPublicIdResolver> makeIndexPublicIdResolver(
		std::uint64_t operationId, IndexLookupContext &context,
		std::vector<std::wstring> &present) const ;

	/**
	 * @brief 同じスキャンの対象一台が現在も同じ公式ファームウェア群に属するか調べます
	 * @param[in] origin 凍結した元索引照合の操作・スキャン・インベントリ世代です
	 * @param[in] deviceIdentity 元スキャンが保持する端末の匿名識別子です
	 * @param[in] record 同じ選択に結ぶ認証済みの公式配布レコードです
	 * @param[in] expectedGroup 元の確認対象になった公式群の位置です
	 * @return 同じ群が一意なら0、変化・競合なら再確認を表すHRESULT、観測失敗なら元のエラーです
	 * @note 所有workerから同期で読み取ります。生ID、承認、取得や導入の権限は返しません
	 */
	[[nodiscard]] NativeError reobserveIndexFirmwareGroup( IndexLookupContext  origin,
														  const std::wstring &deviceIdentity,
														  const IndexDistributionRecord &record,
														  std::size_t expectedGroup) const ;

	/**
	 * @brief 選んだ元端末が現在も存在し、同じ完全Hardware IDを持つかを調べる
	 * @param[in] origin 凍結済みの元照合と操作・スキャン・インベントリの文脈です
	 * @param[in] deviceIdentity 元スキャンの端末一台を指す匿名識別子です
	 * @param[in] requiredHardwareId 元署名の選択行にある完全Hardware IDです
	 * @return 現在の同一端末に完全一致した場合は0、元観測の失敗又は不一致はHRESULTです
	 * @note 所有workerで同期して読み取り、比較値を外部に返しません
	 */
	[[nodiscard]] NativeError reobserveIndexHardwareId( IndexLookupContext  origin,
													   const std::wstring &deviceIdentity,
													   std::wstring_view requiredHardwareId) const ;

	/**
	 * @brief 直前のscanで実際に観測したlocal inventory計測を取得する
	 * @return Providerが所有する計測値への参照。次のscan、installまたは失効まで有効である
	 * @note 生のdevice識別子を含まず、呼出し元はworker thread内でだけ参照する
	 */
	[[nodiscard]] const DeviceInventoryMeasurement &inventoryMeasurement() const noexcept ;

	/**
	 * @brief 元scanの対象だけを同worker内で導入後にread-only照会する関数を作ります
	 * @param[in] session 元scan sessionです。導入権限を延長しません
	 * @param[in] devices 同scanの選択済みopaque device集合です
	 * @return 同workerのinstall呼出し内だけで一回使用する読取関数。生IDをUIへ渡しません
	 * @note 対象instanceとAPI表を一時所有し、期待mapはProviderから借用します。同owner thread・Provider生存中の同期呼出しだけが有効です
	 *       captured sessionと現在scanの不一致では期待mapを使いません。全PnP scan/再検出/候補発行は行いません
	 */
	[[nodiscard]] std::function<std::vector<PostInstallDeviceObservation>()>
											  capturePostInstallObservations( ScanSessionId				   session,
																			 std::span<const std::wstring> devices) const ;

	/**
	 * @brief 選択された local driver node を再照合して device へ導入する
	 * 選択された local driver node を再照合して deviceへ導入する。 注記: scan 時の INF path を直接信用せず、実行直前に全 metadata を再照合
	 * する
	 * @param[in] scanSessionId 選択元の Driver Store scan session ID
	 * @param[in] identities UI に提示済みの opaque identity 群
	 * @param[in] parentWindowNative device installer の親 HWND を整数表現で渡す値。 device installer の親 HWNDを整数
	 *                   表現で渡す値
	 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先
	 * @return 選択候補ごとの導入結果
	 * @note scan 時の INF path を直接信用せず、実行直前に全 metadata を再照合する
	 */
	[[nodiscard]] InstallResult				  install( ScanSessionId					  scanSessionId,
													  std::span<const std::wstring>	  identities,
													  std::uintptr_t				  parentWindowNative,
													  const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief WUA の Hardware ID と一致する local device の opaque identity を取得する
	 * @param[in] hardwareId WUA が返した Hardware ID。外部へ公開しない
	 * @return 現在の scan で一致する device identity。曖昧または未検出なら `std::nullopt`
	 */
	[[nodiscard]] std::optional<std::wstring> deviceIdentityForHardwareId(
		std::wstring_view hardwareId) const ;

	/**
	 * @brief 公式catalog snapshotへ端末内限定binding fingerprintを付与する
	 * 公式catalog snapshotへ端末内bindingを付与する
	 * Opaque identityをworker内mapでnative IDへ解決し、全件成功した場合だけfingerprintを反映する。生IDは返さない
	 * @param[in] secret 管理者保護stateから読み取った端末固有HMAC key。 管理者保護stateの端末固有HMAC key
	 * @param[in,out] devices 現在scanのopaque identityを持つ非機密snapshot。 現在scanの公式catalog用snapshot
	 * @return 全deviceへ付与できた場合は0、session、identity、CNG失敗時はHRESULT。 全deviceへ付与できた場合は0、入力またはCNG失敗時は
	 *         HRESULT
	 * @note Native device instance IDは本関数から返さず、network、UI、logへ渡さない
	 */
	[[nodiscard]] NativeError attachLocalOfficialBindingFingerprints(
		const LocalOfficialBindingSecret &secret, std::span<OfficialCatalogDevice> devices) const ;

	/**
	 * @brief G11-Cで分離した一つのINFを現在deviceのrankとread-onlyで比較する
	 * G11-Cで分離した一INFのPnP具体性とrankを監査する
	 * 現在driverと単一候補INFのWindows rankをread-onlyで取得し、ID具体性とrankが退行しない場合だけApplicableとする
	 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID
	 * @param[in] deviceIdentity UIへ提示済みのopaque device identity
	 * @param[in] workspace Candidate driver閉包を所有する保護workspace。 Candidate閉包を所有する保護workspace
	 * @param[in] package G11-Cで構造を検証した一つのINF package。 G11-Cで構造検証した一INF package
	 * @param[out] audit PnP ID文字列を含まない具体性とrankの監査結果。 PnP ID文字列を含まない監査結果
	 * @param[out] diagnostic 同失敗だけの任意診断です。null可、成功時は空です
 * @return 拒否を含む監査判定の生成時は0、入力またはSetupAPI失敗時はHRESULT。 拒否を含む監査判定の生成時は0、処理失敗時はHRESULT
	 * @note 戻り値0だけでinstallを許可せず、auditのApplicableを別途確認する
	 * @note Driver Storeへのstage、driver選択、installまたはdevice state変更を行わない
	 */
	[[nodiscard]] NativeError auditOfficialInfRank(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		OfficialDriverRankAudit &audit, InfFailureDiagnostic *diagnostic = nullptr) const ;

	/**
	 * @brief 現在版を要求せず単一INFのWindows compatible nodeを観測する
	 * @param[in] scanSessionId 現在inventoryのsession
	 * @param[in] deviceIdentity 当該sessionのopaque device identity
	 * @param[in] workspace 検証済みINF閉包の所有領域
	 * @param[in] package 内容と署名を検証したINF
	 * @param[out] candidateRank 一致nodeの最小Windows rank。非適用・失敗時は空
	 * @param[out] diagnostic 同失敗だけの任意診断です。null可、成功時は空です
 * @return 全列挙完了時0、入力・SetupAPI・有限上限違反時はHRESULT
	 * @note 空結果とAPI失敗を区別する。現在driverとの順位比較や導入許可は発行しない
	 * Workerから呼び、staging、driver選択、installを行わない
	 */
	[[nodiscard]] NativeError observeInfCandidateRank(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		std::optional<std::uint32_t> &candidateRank,
		InfFailureDiagnostic		 *diagnostic = nullptr) const ;

	/**
	 * @brief 同じ署名付きストレージ候補の一意な選択から、同梱INFへの空導入を確認する
	 * @param[in] scanSessionId 元の検索セッション
	 * @param[in] deviceIdentity 同セッションが所有する端末の不透明ID
	 * @param[in] inspection 元CAT署名と閉包を確認したストレージINFの検査結果
	 * @param[in] modelsSection 同じ署名レコードの現在OS用Models節
	 * @param[in] requiredHardwareId 同じ元レコードに結ぶ完全Hardware ID
	 * @param[in] observedRank 同じ元INFについて直前に観測したWindowsの順位
	 * @param[out] delegated 委譲宣言、実選択、同梱署名がすべて一致した場合true。失敗と通常選択はfalse
	 * @return 読取り成功0、元閉包、端末選択、同梱INFの不一致または読取り失敗はHRESULT
	 * @note 読取り専用。元端末の識別情報や導入資格を渡さない
	 */
	[[nodiscard]] NativeError observeStorageInboxNullDriver(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const CommonInfInspection &inspection, const std::wstring &modelsSection,
		std::wstring_view requiredHardwareId, std::uint32_t observedRank, bool &delegated) const ;

	/**
	 * @brief 端末の一意な互換nodeを元Models行に照合し、実ドライバーのクラス作用と順位を確認する
	 * @param[in] scanSessionId 端末の現在の検索セッション
	 * @param[in] deviceIdentity 同セッションに属する非公開端末識別子
	 * @param[in] workspace 端末内容検査の保護領域
	 * @param[in] package 同領域で確認した独自クラスの元INF
	 * @param[in] expectedSha256 元Modelsの全IDと照合済みのINFハッシュ
	 * @param[in] modelsSection 照合済みの現在OS用Models節
	 * @param[out] role Windowsが選んだ元行の作用。失敗時は未評価
	 * @param[out] rankAudit 実ドライバーの元行と端末の順位証拠。空サービスまたは失敗では空
	 * @param[in,out] diagnostic 指定導入の作用照会の失敗段階を保持する任意の診断
	 * @param[out] qualification 任意の出力先。評価済みの実ドライバーの元選択だけを保持する
	 * @return 一意な選択と作用を確認した場合0、対象なし・曖昧・変更・入力不正はHRESULT
	 * @note 元nodeと生IDは内部だけに保持する。導入用の資格や操作は伴わない
	 */
	[[nodiscard]] NativeError observeDeclarativeInfModelRole(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		std::wstring_view expectedSha256, const std::wstring &modelsSection,
		OfficialInfSelectedModelRole &role, std::optional<OfficialDriverRankAudit> &rankAudit,
		InfFailureDiagnostic									  *diagnostic,
		std::shared_ptr<const DeclarativeInfInstallQualification> *qualification = nullptr) const ;

	/**
	 * @brief 一意のWindows選択行、保護INFと現在HardwareIdsが同じ公式対象を示すか確認します
	 * @param[in] scanSessionId 現在のスキャンです
	 * @param[in] deviceIdentity 同スキャンが所有する端末の不透明IDです
	 * @param[in] workspace 元配布物のINFを保持する保護領域です
	 * @param[in] closure 公式Modelsの証拠付き基本INFと全参照を保持した内容検査結果です
	 * @param[in] modelsSection 同署名レコードが使用する元Models節です
	 * @param[out] selected 確認した公式ID・元行番号・基本導入節です
	 * @param[out] selectedRelations 同じ選択の実導入節と必要関係です
	 * @param[out] rankAudit 同じnodeと端末の状態から確認した順位です
	 * @return 全読取りが成立した場合0、変更・不一致・API失敗は元HRESULTです
	 * @note 失敗時は全出力を空にします。登録、導入、導入資格の発行は行いません
	 */
	[[nodiscard]] NativeError observeScopedInfModel(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialDriverClosure &closure,
		std::wstring_view modelsSection, OfficialInfScopedModelMatch &selected,
		OfficialInfPackage					   &selectedRelations,
		std::optional<OfficialDriverRankAudit> &rankAudit) const ;

	/**
	 * @brief 監査済み公式INFを現在device状態と一意なWindows nodeへ拘束する
	 * 監査済み公式INFを現在状態と一意なWindows nodeへ拘束する
	 * 現在状態と候補nodeを再取得し、全照合成功後だけ単調増加tokenへ秘密metadataをcommitする。OS状態は変更しない
	 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID
	 * @param[in] deviceIdentity UIへ提示済みのopaque device identity
	 * @param[in] workspace Candidate driver閉包を所有する保護workspace。 Candidate閉包を所有する保護workspace
	 * @param[in] package G11-Cで構造を検証した一つのINF package。 内容監査済みの一INF package
	 * @param[in] expectedCurrentProvider Scan結果に固定した現在Provider表示名。 Scan時の現在Provider名
	 * @param[in] expectedCurrentVersion Scan結果に固定した現在version。 Scan時の現在version
	 * @param[in] expectedCurrentDate Scan結果に固定した現在のYYYY/MM/DD日付。 Scan時の現在日付
	 * @param[in] expectedRankAudit 発行前に合格したPnP具体性とrank監査結果。 直前に合格したrank監査結果
	 * @param[out] binding 成功時の一scan限定opaque binding。失敗時は空値。 成功時の非機密opaque binding
	 * @param[out] diagnostic 任意の元拒否位置です。実行判定に使用しません
	 * @param[in] requiredHardwareId 再観測した端末のHardwareIdsに必要な元公開ID。空は追加条件なし
	 * @param[in] requiresFirmwareAuthorization 公式群への元承認をWindows変更直前に再確認する場合trueです
	 * @return 発行成功時は0、入力、状態変更、一意性またはSetupAPI失敗時はHRESULT。 Binding発行時は0、状態変更、曖昧性またはSetupAPI失敗時は
	 *         HRESULT
	 * @note 生のinstance ID、PnP ID、INF path、sectionはDriver Store内だけに保持する
	 */
	[[nodiscard]] NativeError createOfficialInfInstallBinding(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		std::wstring_view expectedCurrentProvider, std::wstring_view expectedCurrentVersion,
		std::wstring_view expectedCurrentDate, const OfficialDriverRankAudit &expectedRankAudit,
		OfficialInfInstallBinding &binding, RequiredInfBindingDiagnostic *diagnostic = nullptr,
		std::wstring_view requiredHardwareId = {}, bool requiresFirmwareAuthorization = false) ;

	/**
	 * @brief 公式INF導入bindingと現在のdeviceおよびWindows nodeを再照合する
	 * 公式INF導入bindingと現在状態を再照合する
	 * 発行時の現在INF、版、日付、PnP状態と候補section、版、日付、rankを再取得値へ比較する。OS状態は変更しない
	 * @param[in] scanSessionId Bindingを発行した現在session ID。 Binding発行元のscan session ID
	 * @param[in] deviceIdentity Bindingに対応するopaque device identity。 Bindingに対応するopaque device ID
	 * @param[in] workspace 再検証済みcandidate閉包を所有する保護workspace。 再検証済みcandidateの保護workspace
	 * @param[in] package 再検証済みの一つのINF package。 再検証済みの一INF package
	 * @param[in] binding Provider workerが保持した非機密binding。 Provider workerが保持する非機密binding
	 * @return 全記録が一致する場合は0、失効、変更またはSetupAPI失敗時はHRESULT。 全記録一致時は0、失効、変更またはSetupAPI失敗時はHRESULT
	 * @note 本関数はDriver Storeへのstage、driver選択、installを行わない
	 */
	[[nodiscard]] NativeError revalidateOfficialInfInstallBinding(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		const OfficialInfInstallBinding &binding) const ;

	/**
	 * @brief 指定scanに属する一つの公式INF導入bindingを明示的に破棄する
	 * 現在sessionと所有workerを照合し、他候補のbindingを維持したまま未発行候補の秘密記録だけを破棄する
	 * @param[in] scanSessionId Bindingを発行したscan session ID
	 * @param[in] token Driver Storeが発行した0ではないopaque token。 Driver Storeが発行したopaque token
	 * @return 一件を破棄した場合true。別session、別workerまたは未登録ならfalse。 一件を破棄した場合true。不一致または未登録ならfalse
	 * @note 他Providerが同じscanで保持するbindingは変更しない
	 */
	bool discardOfficialInfInstallBinding( ScanSessionId scanSessionId,
										  std::uint64_t token) noexcept ;

	/**
	 * @brief 指定scanに属する全公式INF導入bindingを明示的に失効させる
	 * 指定scanの公式INF導入bindingを明示的に失効させる
	 * 現在sessionと所有workerが一致する場合だけ全tokenを破棄する。旧sessionから現在bindingを失効させない
	 * @param[in] scanSessionId Bindingを発行したscan session ID
	 * @note 旧sessionまたは所有worker以外からの要求では現在bindingを変更しない
	 */
	void invalidateOfficialInfInstallBindings( ScanSessionId scanSessionId) noexcept ;

	/**
	 * @brief Bindingで固定した監査済み公式INFをstagingして指定deviceへ導入する
	 * Bindingを再検証後、SetupCopyOEMInfWが返した登録先INFから一意なnodeを再構築する。導入直前にも現在状態を確認し、DiInstallDeviceへ非nullの
	 * DriverInfoDataとFlags 0を渡す
	 * @param[in] scanSessionId Bindingを発行した現在scan session ID。 Bindingを発行した現在session
	 * @param[in] deviceIdentity Bindingに対応するopaque device identity。 対象のopaque device identity
	 * @param[in] workspace 再検証済みcandidate閉包を所有する保護workspace。 再検証済みINF閉包の保護workspace
	 * @param[in] package 再検証済みの一つのINF package。 再検証済みの一INF package
	 * @param[in] binding Provider workerが保持する一scan限定binding。 Providerが保持する一scan限定binding
	 * @param[in] parentWindowNative Windows導入dialogの親Window値。 Installer親HWNDの整数表現
	 * @param[out] rebootRequired 導入完了に再起動が必要な場合はtrue
	 * @return Stagingと指定device導入の成功時は0、それ以外はHRESULT
	 * @note Windowsが返した登録先INFだけを再照合し、登録済みpackageを自動削除しない
	 */
	[[nodiscard]] NativeError installBoundOfficialInf( ScanSessionId		scanSessionId,
													  std::wstring_view deviceIdentity,
													  const OfficialDownloadWorkspace &workspace,
													  const OfficialInfPackage		  &package,
													  const OfficialInfInstallBinding &binding,
													  std::uintptr_t parentWindowNative,
													  bool			&rebootRequired) const ;

	/**
	 * @brief 検証済み外部INFを現在scanの一つのopaque deviceへ導入する
	 * 検証済み外部INFを現在scanの一deviceへ導入する
	 * 指定INF一件だけからcompatible listを構築し、Providerとversionが一意なnodeだけを対象deviceへ導入する
	 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID
	 * @param[in] deviceIdentity UIへ提示済みのopaque device identity。 対象のopaque device identity
	 * @param[in] infPath Providerが再検証した保護workspace内INF絶対path。 再検証済みINFの保護workspace絶対path
	 * @param[in] expectedProvider Scan時に検証したINF Provider表示名。 Scan時のINF Provider表示名
	 * @param[in] expectedVersion Scan時に検証した4要素numeric driver version。 Scan時の4要素numeric version
	 * @param[in] parentWindowNative Device installerの親HWNDを整数表現で渡す値。 Installer親HWNDの整数表現
	 * @param[out] rebootRequired 完了に再起動が必要な場合は`true`
	 * @return 導入成功時は0、session、再照合またはWindows API失敗時はHRESULT。 対象nodeの再照合と導入成功時は0、それ以外はHRESULT
	 * @pre 呼出し側はINF、CAT、全参照fileの署名とPnP適用性を直前に再検証する
	 */
	[[nodiscard]] NativeError installVerifiedExternalInf(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity, std::wstring_view infPath,
		std::wstring_view expectedProvider, std::wstring_view expectedVersion,
		std::uintptr_t parentWindowNative, bool &rebootRequired) const ;

	/**
	 * @brief 元scanのpresent deviceを公式installer専用の秘密guardへ固定します
	 * @param[in] session 元scan sessionです
	 * @param[in] device 元表示のopaque deviceです
	 * @param[in] provider 元現在行のproviderです。native再観測へ完全一致を要求します
	 * @param[in] version 元現在行の版です
	 * @param[in] date 元現在行の日付です
	 * @param[out] token 全原状態一致時だけ非zero guardです。失敗時0です
	 * @return 同worker/native x64/present/原現在状態確認0、拒否は元HRESULTです
	 * @note 標準INFのWindows rank合格を発行しません
	 */
	[[nodiscard]] NativeError createOfficialInstallerDeviceBinding(
		ScanSessionId session, std::wstring_view device, std::wstring_view provider,
		std::wstring_view version, std::wstring_view date, std::uint64_t &token) ;
	/**
	 * @brief 元installer guardを変更直前のpresent/全秘密状態へ再照合します
	 * @param[in] session 元scanです
	 * @param[in] device 元opaque deviceです
	 * @param[in] token 未使用の同issuer guardです
	 * @return 全native状態一致0、それ以外は元HRESULTです
	 */
	[[nodiscard]] NativeError revalidateOfficialInstallerDeviceBinding( ScanSessionId	 session,
																	   std::wstring_view device,
																	   std::uint64_t token) const ;
	/**
	 * @brief 明示選択済みguardを一回だけ消費します
	 * @param[in] session 元scanです
	 * @param[in] device 元opaque deviceです
	 * @param[in] token 元未使用guardです
	 * @return 全再照合成功0、再使用/変化は元HRESULTです
	 */
	[[nodiscard]] NativeError consumeOfficialInstallerDeviceBinding( ScanSessionId	  session,
																	std::wstring_view device,
																	std::uint64_t	  token) ;
	/**
	 * @brief 同issuerの未公開installer guardだけをrollbackします
	 * @param[in] session 元scanです
	 * @param[in] token 当該issuerの元guardです
	 * @return 元sessionのguardを除去した場合trueです
	 */
	bool discardOfficialInstallerDeviceBinding( ScanSessionId session, std::uint64_t token) noexcept ;

private:
	/**
	 * @brief 原deviceの未処理Uまたは当該実行Sへの所属を照合します
	 * @param[in] device 元opaque deviceです
	 * @return 未消費または当該scopeへ予約済みだけtrueです
	 */
	[[nodiscard]] bool ownsInstallDevice( std::wstring_view device) const noexcept ;
	friend class SignedIndexCandidateBindingSession ;
	friend class CompositeUpdateProvider ;
	friend class DriverStoreBindingProbe ;
	friend class RequiredChildBindingProbe ;
	friend class ScopedInfQualificationProbe ;
	struct ScopedInfObservation ;
	/**
	 * @brief 公式Modelsで実選択を確認した端末状態を内部結果として保持します
	 * @param[in] session 現在のworkerのスキャンです
	 * @param[in] device 元のスキャンに属する端末の不透明IDです
	 * @param[in] workspace 元INFを保持する管理者保護領域です
	 * @param[in] closure 同じ元INFとModels証拠を含む全閉包です
	 * @param[in] modelsSection 署名済み元レコードのModels節です
	 * @param[out] observed 同じ端末の完全観測と元行・実選択の関係です。失敗時は空です
	 * @return 同じ端末と実選択が成立した場合0、その他はHRESULTです
	 */
	[[nodiscard]] NativeError observeScopedInfModelState( ScanSessionId					  session,
														 std::wstring_view				  device,
														 const OfficialDownloadWorkspace &workspace,
														 const OfficialDriverClosure	 &closure,
														 std::wstring_view	   modelsSection,
														 ScopedInfObservation &observed) const ;
	/**
	 * @brief 同じ署名レコードと取得物・端末・元選択から不変の私有計画を作ります
	 * @param[in] session 同じ索引取得のスキャンです
	 * @param[in] device 元の承認が指定した端末の不透明IDです
	 * @param[in] content 元取得と全検査に結び付いた閉包の不変所有者です
	 * @param[in] hint 取得側が認証して固定した索引、元レコード、元配布物の値です
	 * @param[in] original 同じ索引領域に含まれる署名済み原レコードです
	 * @param[out] qualification 全検査成功時だけ元選択と作用を保持する私有計画です
	 * @return 同じ端末と元選択・作用の確認に成功した場合0です
	 * @pre 呼出し側で同じ元索引の認証、元取得許可、期限と元CABを確認します
	 * @note 読取り専用です。Driver Storeの登録や導入トークン発行は行いません
	 */
	[[nodiscard]] NativeError buildScopedInfInstallQualification(
		ScanSessionId session, std::wstring_view device,
		const std::shared_ptr<const CollectorDriverPackageContent> &content,
		const IndexedDriverArchiveHint &hint, const IndexDistributionRecord &original,
		std::shared_ptr<const ScopedInfInstallQualification> &qualification) const ;
	/**
	 * @brief 元の私有計画を同じ所有者、現端末の選択、元ファイルと作用へ照合します
	 * @param[in] session 元計画を発行した現在のスキャンです
	 * @param[in] device 同じ承認済み端末の不透明IDです
	 * @param[in] content 元取得結果の不変所有者です
	 * @param[in] hint 元署名領域と同じレコード・配布物の値です
	 * @param[in] original 現在も同じ索引に含まれる認証済み元レコードです
	 * @param[in] qualification 元選択を確認して発行した私有計画です
	 * @return 所有者・元記録・現端末・実選択作用が一致した場合0です
	 * @pre 呼出し側で同じ元索引の認証、元取得許可、期限と元CABを確認します
	 */
	[[nodiscard]] NativeError revalidateScopedInfInstallQualification(
		ScanSessionId session, std::wstring_view device,
		const std::shared_ptr<const CollectorDriverPackageContent> &content,
		const IndexedDriverArchiveHint &hint, const IndexDistributionRecord &original,
		const std::shared_ptr<const ScopedInfInstallQualification> &qualification) const ;
	/**
	 * @brief 私有計画と同じ端末の元観測とファイル作用が生きているかを確かめます
	 * @param[in] qualification この発行元が保持した元計画です
	 * @param[out] current 一致時だけ元計画と同じ現観測です
	 * @return 現在の端末・元行・選択作用が変化していない場合0です
	 * @note 元署名領域・取得許可・期限の有効性は別に確認します
	 */
	[[nodiscard]] NativeError reobserveScopedInfInstallQualification(
		const ScopedInfInstallQualification &qualification, ScopedInfObservation &current) const ;
	/**
	 * @brief 同じ公式Modelsの計画と現在状態から既存の一scanトークンを発行します
	 * @param[in] session 元計画を発行したスキャンです
	 * @param[in] device 同じ端末の不透明IDです
	 * @param[in] qualification 同じ元署名・端末・ファイル作用を確認した私有計画です
	 * @param[in] expectedCurrentProvider 固定した現在の提供元です
	 * @param[in] expectedCurrentVersion 固定した現在のバージョンです
	 * @param[in] expectedCurrentDate 固定した現在の日付です
	 * @param[out] binding 同じ計画のトークンです。失敗時は空です
	 * @return 同じ端末・選択・作用が成立したとき0です
	 * @pre 呼出し側で同じ元署名領域・取得許可と期限を確認します
	 */
	[[nodiscard]] NativeError createScopedInfInstallBinding(
		ScanSessionId session, std::wstring_view device,
		const std::shared_ptr<const ScopedInfInstallQualification> &qualification,
		std::wstring_view expectedCurrentProvider, std::wstring_view expectedCurrentVersion,
		std::wstring_view expectedCurrentDate, OfficialInfInstallBinding &binding) ;
	/**
	 * @brief 元トークンの端末が現在の導入操作の元索引選択に予約済みか確認します
	 * @param[in] qualification トークンに保持した公式範囲の元計画です
	 * @return 同じ所有者、スキャン、実操作、選択済み端末の場合trueです
	 */
	[[nodiscard]] bool ownsActiveScopedInfInstall(
		const ScopedInfInstallQualification &qualification) const noexcept ;
	friend struct ScopedInfInstallQualification ;
	/** @brief 一つの選択subsetだけを借用し、終了時も未処理ownerを保持します
	 * @note Snapshotを強所有せず、新scan/明示失効を妨げません。同workerのstack上だけで使用します
	 */
	class IndexInstallProofScope final {
	public:
		/**
		 * @brief 同workerの検証済みProviderと元世代だけを借用します
		 * @param[in] owner 借用Provider。nullは開始拒否で、終了時に何も変更しません
		 * @param[in] generation ownerが保持した正の元inventory世代。null ownerでは0です
		 * @param[in] operation 当該予約済みの新操作です
		 */
		IndexInstallProofScope( DriverStoreProvider *owner, std::uint64_t generation,
							   OperationId operation) noexcept ;
		/**
		 * @brief 当該Sの借用だけを終了し、未処理Uの元proofを保持します
		 */
		~IndexInstallProofScope() ;
		/**
		 * @brief 一batchの終了責任を複製しません
		 */
		IndexInstallProofScope( const IndexInstallProofScope &) = delete ;
		/**
		 * @brief 一batchの終了責任を代入しません
		 */
		IndexInstallProofScope &operator=( const IndexInstallProofScope &) = delete ;
		/**
		 * @brief 終了責任をstack上の元scopeから移動しません
		 */
		IndexInstallProofScope( IndexInstallProofScope &&) = delete ;
		/**
		 * @brief 終了責任を別scopeへ移動代入しません
		 */
		IndexInstallProofScope &operator=( IndexInstallProofScope &&) = delete ;
		/**
		 * @brief 元同worker/scanのscope開始が成立したか確認します
		 * @return 開始した元scopeだけtrueです
		 */
		[[nodiscard]] bool		active() const noexcept ;

	private:
		/// 同期中だけ借用し、scopeより長く生存する元Providerです。拒否時nullです
		DriverStoreProvider *owner_{} ;
		/// 旧scope終了で新scan世代を解放しないための元世代です
		std::uint64_t		 generation_{} ;
		/// 当該scopeだけのInstall操作です
		OperationId			 operation_{} ;
	} ;
	/**
	 * @brief 全選択事前検証後だけ新resolverを閉じ、元proofの解放を一batch終端へ延期します
	 * @param[in] origin 元factoryの原contextです
	 * @param[in] operation 当該予約済み新操作です
	 * @param[in] devices 元Uの一意な選択subsetです
	 * @return 同worker/scanの一回scope。不一致/閉鎖済みはinactiveです
	 * @note 新取得・proof・導入許可を発行せず、各deviceの直前再検証は別に必須です
	 */
	[[nodiscard]] IndexInstallProofScope beginIndexInstallProofScope(
		IndexLookupContext origin, OperationId operation,
		std::span<const std::wstring> devices) noexcept ;
	/**
	 * @brief 原lookup完了後の再factory/全体再列挙を不可逆に閉じます
	 * @param[in] origin 元完全contextです
	 * @return 同じ原ownerへ適用した場合trueです
	 */
	[[nodiscard]] bool		  sealIndexLookup( IndexLookupContext origin) noexcept ;
	/**
	 * @brief 元スキャンの未処理又は実行中の端末一台から現在のHardwareIdsを読み取る
	 * @param[in] origin 凍結済みの元照合の文脈です
	 * @param[in] deviceIdentity 元スキャンの端末一台を指す匿名識別子です
	 * @param[in] requirePresent Windowsの現在present属性を必須にする場合trueです
	 * @param[out] hardwareIds 比較用に正規化した現在の完全値です。失敗時は空です
	 * @return 全値の読取りに成功した場合0、所有・状態又は読取りの不成立はHRESULTです
	 * @note 所有workerで同期し、現端末の生属性を公開DTOに渡しません
	 */
	[[nodiscard]] NativeError readRetainedIndexHardwareIds(
		IndexLookupContext origin, const std::wstring &deviceIdentity, bool requirePresent,
		std::vector<std::wstring> &hardwareIds) const ;
	/**
	 * @brief 未処理または当該実行中subsetへの結合を検証します
	 * @param[in] origin 元contextです
	 * @param[in] operation 明示操作です
	 * @param[in] devices 元一意subsetです
	 * @param[in] executing trueは当該scopeのS、falseは未処理Uです
	 * @return 完全一致だけtrueです。新しい権限を作りません
	 */
	[[nodiscard]] bool		  validateRetainedIndexSelection( IndexLookupContext			   origin,
															 OperationId				   operation,
															 std::span<const std::wstring> devices,
															 bool executing) const noexcept ;
	/**
	 * @brief 既workerに拘束した当該操作を同期参照します
	 * @return 未予約は0です。値だけでは導入許可になりません
	 */
	[[nodiscard]] OperationId activeInstallOperation() const noexcept
	{
		return activeInstallOperation_ ;
	}
	/**
	 * @brief 検証済み役割計画を単一親の私有bindingへ固定します
	 * @param[in] session 元scan sessionです
	 * @param[in] identity 元選択親のopaque identityです
	 * @param[in] inspection 同byte/CAT検証済み閉包です
	 * @param[out] plan 同deviceの私有node選択から生成した不変関係です。失敗時は空です
	 * @param[in] provider 元現在行のproviderです
	 * @param[in] version 元現在行のversionです
	 * @param[in] date 元現在行の日付です
	 * @param[in] audit 元baseのWindows rank監査です
	 * @param[out] binding 全照合成功時だけ発行する元親bindingです
	 * @param[out] diagnosticStage 任意の非所有数値診断先です。nullなら採取せず権限判定へ使いません
	 * @param[in] requiredHardwareId 元親の再観測HardwareIdsに必要な公開ID。空は追加条件なし
	 * @param[in] requiresFirmwareAuthorization 親端末の公式群を各登録と適用の直前に再確認する場合trueです
	 * @return 成功0、関係/適用性/元状態の拒否はHRESULTです
	 */
	[[nodiscard]] NativeError createRequiredInfInstallBinding(
		ScanSessionId session, std::wstring_view identity, const CommonInfInspection &inspection,
		std::shared_ptr<const RequiredDriverComponentPlan> &plan, std::wstring_view provider,
		std::wstring_view version, std::wstring_view date, const OfficialDriverRankAudit &audit,
		OfficialInfInstallBinding &binding, RequiredInfBindingDiagnostic *diagnosticStage = nullptr,
		std::wstring_view requiredHardwareId = {}, bool requiresFirmwareAuthorization = false) ;
	/**
	 * @brief app独立検査と私有native選択の全storage作用を同issuerへ資格化します
	 * @param[in] session 元scanです
	 * @param[in] identity 元選択deviceのopaqueです
	 * @param[in] inspection ADMIN原archiveの独立内容検査です
	 * @param[out] plan 全作用と必要importを固定した不変計画です。失敗時空です
	 * @param[in] provider 元現在providerです
	 * @param[in] version 元現在versionです
	 * @param[in] date 元現在日付です
	 * @param[in] audit 元全Windows rankです
	 * @param[out] binding 全原値/元選択成立時だけの同issuer tokenです
	 * @param[out] diagnostic 任意の非秘密な最初の固定拒否です
	 * @param[in] requiredHardwareId 元ストレージ端末の再観測HardwareIdsに必要な公開ID。空は追加条件なし
	 * @param[in] requiresFirmwareAuthorization 端末の公式群をストレージの変更直前に再確認する場合trueです
	 * @param[in] modelScope 私有WiXの元Modelsと同機器の完全ID範囲。通常のストレージはnullです
	 * @return 全storage資格/現在state/一意node成立0、その他は原HRESULTです
	 * @note 署名索引の内部選択経路だけが呼び、公開bool/JSON/collectorから資格を作りません
	 */
	[[nodiscard]] NativeError createStorageInfInstallBinding(
		ScanSessionId session, std::wstring_view identity, const CommonInfInspection &inspection,
		std::shared_ptr<const RequiredDriverComponentPlan> &plan, std::wstring_view provider,
		std::wstring_view version, std::wstring_view date, const OfficialDriverRankAudit &audit,
		OfficialInfInstallBinding &binding, RequiredInfBindingDiagnostic *diagnostic = nullptr,
		std::wstring_view requiredHardwareId = {}, bool requiresFirmwareAuthorization = false,
		const OfficialStorageInfModelScope *modelScope = nullptr) ;
	/**
	 * @brief 元親と全必要役割を変更前にread-onlyで再検証します
	 * @param[in] session 元scanです
	 * @param[in] identity 元親opaqueです
	 * @param[in] inspection 元保護閉包です
	 * @param[in] plan 元私有関係です
	 * @param[in] binding 元親bindingです
	 * @param[in,out] diagnosticStage null可の最初の固定拒否段階です
	 * @return 全byte/関係/元状態一致0、失効/未確認はHRESULTです
	 */
	[[nodiscard]] NativeError revalidateRequiredInfInstallBinding(
		ScanSessionId session, std::wstring_view identity, const CommonInfInspection &inspection,
		const std::shared_ptr<const RequiredDriverComponentPlan> &plan,
		const OfficialInfInstallBinding							 &binding,
		RequiredInfBindingDiagnostic							 *diagnosticStage = nullptr) const ;
	/**
	 * @brief 必要役割をstageし指定親と一意な必要SWC子だけを導入します
	 * @param[in] session 元scanです
	 * @param[in] identity 元選択親です
	 * @param[in] inspection 元検証済み閉包です
	 * @param[in] plan 元私有関係です
	 * @param[in] binding 元親bindingです
	 * @param[in] parentWindowNative 明示操作の親windowです
	 * @param[out] roles 登録と指定導入の実結果、必要な補助サービスの反映確認を役割別に保持します
	 * @param[out] imports 必要nullの原ordinal/登録結果です。部分失敗と未実行を保持します
	 * @param[out] rebootRequired 実APIが返した再起動要否です
	 * @param[in] authorizationCheck 同原署名recordと実UTCを同期再検証する。HDC、MTD、メディアチェンジャー、共有補助サービスとCatalog対象では必須
	 * @return 指定API完了かつ必須作用の未確認なしは0、未反映または未確認はS_FALSE、API失敗はHRESULTです
	 * @note 必要roleの元/登録INF/rootを変更非共有で計画終端まで保持します。Extension反映をbase API成功から推測しません。全device導入APIを呼びません
	 */
	[[nodiscard]] NativeError installBoundRequiredInfPlan(
		ScanSessionId session, std::wstring_view identity, const CommonInfInspection &inspection,
		const std::shared_ptr<const RequiredDriverComponentPlan> &plan,
		const OfficialInfInstallBinding &binding, std::uintptr_t parentWindowNative,
		std::vector<DriverPlanRoleExecutionResult> &roles,
		std::vector<RequiredInfStageResult> &imports, bool &rebootRequired,
		const std::function<NativeError()> &authorizationCheck = {}) ;
	struct OfficialCandidateNodeState ;
	/**
	 * @brief 標準入口または私有計画入口で確認したbase nodeを発行します
	 * @param[in] scanSessionId 元scanです
	 * @param[in] deviceIdentity 元opaqueです
	 * @param[in] workspace 検証済み閉包です
	 * @param[in] package 検証済み一INFです
	 * @param[in] expectedCurrentProvider 元現在providerです
	 * @param[in] expectedCurrentVersion 元現在versionです
	 * @param[in] expectedCurrentDate 元現在日付です
	 * @param[in] expectedRankAudit 元Windows rankです
	 * @param[out] binding 同状態の一意nodeだけです
	 * @param[out] diagnostic 任意の元拒否位置です。実行判定に使用しません
	 * @param[in] storageQualification 同issuerの全原作用資格です。通常入口はnullで、用途だけでは発行しません
	 * @param[in] declarativeQualification 独自クラスの実選択とクラス状態を固定した私有観測
	 * @param[in] requiredHardwareId 発行時の端末HardwareIdsに必要な元公開ID。空は追加条件なし
	 * @param[in] requiresFirmwareAuthorization 同端末と元承認の現在群を直前に再確認する場合trueです
	 * @param[in] scopedQualification 公式Modelsの同じ元選択・端末・作用を保持する私有計画です
	 * @param[in] storageModel WiX用に同じ元Modelsで確認した候補節と全ID。通常のストレージはnullです
	 * @return 一意性/全状態一致0、それ以外はHRESULTです
	 */
	[[nodiscard]] NativeError createOfficialInfInstallBindingImpl(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		std::wstring_view expectedCurrentProvider, std::wstring_view expectedCurrentVersion,
		std::wstring_view expectedCurrentDate, const OfficialDriverRankAudit &expectedRankAudit,
		OfficialInfInstallBinding &binding, RequiredInfBindingDiagnostic *diagnostic = nullptr,
		const StorageInfQualification							 *storageQualification = nullptr,
		std::shared_ptr<const DeclarativeInfInstallQualification> declarativeQualification = {},
		std::wstring_view requiredHardwareId = {}, bool requiresFirmwareAuthorization = false,
		std::shared_ptr<const ScopedInfInstallQualification> scopedQualification = {},
		const OfficialCandidateNodeState					*storageModel		 = nullptr) ;
	/**
	 * @brief 同保護INFのbyteを再確認して一度だけstoreへimportします
	 * @param[in] workspace 元保護領域です
	 * @param[in] package 同byte検証済みINFです
	 * @param[out] stagedInfPath 検証済み登録root直下の秘密pathです
	 * @param[in] storageQualification 同原workspace/全作用に結ぶ私有資格です。nullは既通常policyだけです
	 * @param[in] declarativeQualification 独自クラスの元選択に結ぶ私有資格
	 * @param[in] authorizationCheck 登録前に実UTCと元選択を再検証する任意の同期処理
	 * @param[in] scopedQualification 公式Modelsの専用トークンに保持した元計画です
	 * @return stageと元/登録byte一致0、それ以外はHRESULTです
	 */
	[[nodiscard]] NativeError stageOfficialInfPackage(
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		std::wstring &stagedInfPath, const StorageInfQualification *storageQualification = nullptr,
		const DeclarativeInfInstallQualification *declarativeQualification = nullptr,
		const std::function<NativeError()>		 *authorizationCheck	   = nullptr,
		const ScopedInfInstallQualification		 *scopedQualification	   = nullptr) const ;
	/**
	 * @brief 私有前提を満たした指定一deviceの元実装を実行します
	 * @param[in] scanSessionId 元scanです
	 * @param[in] deviceIdentity 元opaqueです
	 * @param[in] workspace 元保護閉包です
	 * @param[in] package 元検証済みINFです
	 * @param[in] binding 元一意nodeです
	 * @param[in] parentWindowNative 明示操作の親windowです
	 * @param[out] rebootRequired 実APIの再起動値です
	 * @param[out] diagnosticMissing 非nullは同期中だけ借用する出力です。FALSE/LastError0の観測だけtrueです
	 * @param[in,out] mtdFiles 同意/復旧後かつstage前に準備したMTD共有先です。旧経路はnullです
	 * @param[out] mtdResult MTDのcopy部分作用です。旧経路はnullです
	 * @param[in] authorizationCheck 同原署名recordと実UTCの同期再検証です。MTD・Catalog対象・独自クラスで必須です
	 * @param[in] declarativeSource 独自クラスの署名確認済み元閉包です。従来経路はnullです
	 * @param[in] wifiSource 同じ選択端末へフィルター置換を要求した元内容です。この経路以外はnullです
	 * @param[out] storageReflection 自動起動補助または単一起動の事後観測。指定適用成功時に記録し、他の経路はnull
	 * @return stage/指定API完了0、それ以外はHRESULTです
	 * @note FALSE/LastError0では内部ERROR_INVALID_DATAを返し、実Windowsの同error観測と区別します
	 */
	[[nodiscard]] NativeError installBoundOfficialInfImpl(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		const OfficialInfInstallBinding &binding, std::uintptr_t parentWindowNative,
		bool &rebootRequired, bool *diagnosticMissing = nullptr,
		MtdSharedFileOperation *mtdFiles = nullptr, MtdQueueResult *mtdResult = nullptr,
		const std::function<NativeError()> *authorizationCheck = nullptr,
		const CommonInfInspection		   *declarativeSource  = nullptr,
		const CommonInfInspection		   *wifiSource		   = nullptr,
		DriverStorageReflectionResult	   *storageReflection  = nullptr) const ;
	/**
	 * @brief 通常scanと現在属性専用scanが共有する有界present列挙
	 * @param[in] scanSessionId 呼出側が発行した非ゼロsession
	 * @param[in] progressCallback 同期の進捗通知先
	 * @param[in,out] execution Nullは通常履歴検索、非nullは表示専用
	 * @param[in] captureIndexIds 同scanの索引照合用秘密属性を保持する場合true
	 * @return 列挙結果。専用modeではinstall sessionを発行しない
	 */
	[[nodiscard]] ScanResult scanInventory( ScanSessionId				   scanSessionId,
										   const ProviderProgressCallback &progressCallback,
										   MetadataSearchExecutionContext *execution,
										   bool							   captureIndexIds = false) ;
	/** @brief 索引専用の同scan秘密属性と必要属性の完了軸です */
	struct IndexInventoryState ;
	/** @brief 秘密stateを外へ公開しないweak所有callbackです */
	class IndexInventoryResolver ;
	/**
     * @brief scan 時に照合し、worker thread 内だけで保持する導入対象 metadata である
     */
	struct InstallTarget {
		/// SetupAPI再列挙に使用する秘密のdevice instance ID
		std::wstring  deviceInstanceId ;
		/// Driver Store内で照合するINF file名
		std::wstring  infFileName ;
		/// 選択driver nodeのINF install section名
		std::wstring  sectionName ;
		/// Candidate再照合に使用するdriver provider名
		std::wstring  providerName ;
		/// SP_DRVINFO_DATAのpacked driver version
		std::uint64_t driverVersion{} ;
		/// FILETIMEを64-bit値にしたdriver日付
		std::uint64_t driverDateTicks{} ;
	} ;

	/**
	 * @brief 成功した指定対象だけを実事後照合用へ保持します
	 * @param[in] instance Worker内だけの元instanceです
	 * @param[in] inf 指定済みの実INFです
	 * @param[in] provider 指定nodeのproviderです
	 * @param[in] version 指定nodeのpacked版です
	 * @note 確保失敗は読取証明を省き、実導入結果を変更しません
	 */
	void rememberInstalledObservationTarget( std::wstring_view instance, std::wstring_view inf,
											std::wstring_view provider,
											std::uint64_t	  version) const noexcept ;
	/// 同一install内だけの実指定対象。実行能力は含みません
	mutable std::unordered_map<std::wstring, InstallTarget> installedObservationTargets_ ;

	/**
     * @brief Binding発行時の現在deviceとdriver状態をworker内だけで保持する
     */
	struct OfficialDeviceState {
		/// SetupAPI再open用の秘密device instance ID
		std::wstring					   deviceInstanceId ;
		/// 発行時のsetup class名
		std::wstring					   deviceClass ;
		/// 具体性順の秘密Hardware ID群
		std::vector<std::wstring>		   hardwareIds ;
		/// 具体性順の秘密Compatible ID群
		std::vector<std::wstring>		   compatibleIds ;
		/// 現在driver選択に使われた秘密PnP ID
		std::wstring					   matchingDeviceId ;
		/// 現在driverの秘密INF file名
		std::wstring					   currentInfFileName ;
		/// 現在driverのProvider表示名
		std::wstring					   currentProvider ;
		/// 現在driverの原文version
		std::wstring					   currentVersion ;
		/// 現在driverのYYYY/MM/DD日付
		std::wstring					   currentDate ;
		/// 現在driverのpacked version。Native NO_DRIVERでは比較へ使用しません
		std::uint64_t					   currentPackedVersion{} ;
		/// Nativeの全未導入根拠へ結合する初回modeです。空版から設定しません
		bool							   noDriver{} ;
		/// 元Class propertyの正式不存在/値を保持します
		DevicePropertyReadStatus		   classRead ;
		/// 元ClassGUID propertyの読取状態です
		DevicePropertyReadStatus		   classGuidRead ;
		/// 元ClassGUID propertyの値。不存在時は空です
		std::wstring					   observedClassGuid ;
		/// 一覧構築前の元device ClassGUIDです
		std::wstring					   nativeClassGuid ;
		/// 元Class観測の方式。INF Classで上書きしません
		OfficialDriverRankDeviceClassState classState{
			OfficialDriverRankDeviceClassState::KNOWN_CLASS} ;
		/// 元nodeのstatus/problemです。変更直前の差を拒否します
		DeviceNodeObservation	 node ;
		/// 元driver keyの読取方式です
		DevicePropertyReadStatus driverKeyRead ;
		/// 元Matching IDの読取方式です
		DevicePropertyReadStatus matchingRead ;
		/// 元driver key値です。Worker内だけで保持します
		std::wstring			 driverKey ;
	} ;

	/**
     * @brief Binding発行時の一意なcandidate Windows nodeをworker内だけで保持する
     */
	struct OfficialCandidateNodeState {
		/// 保護workspace内の秘密INF絶対path
		std::wstring			  infPath ;
		/// Windows nodeが選択した秘密install section名
		std::wstring			  sectionName ;
		/// 単一起動のWiX選択が一致した元の現在OS用Models節
		std::wstring			  modelsSection ;
		/// 上記元行と同じWindowsノードのHardware IDと元順の全Compatible ID
		std::vector<std::wstring> modelIds ;
		/// Windows nodeのProvider表示名
		std::wstring			  provider ;
		/// Windows nodeの4要素version
		std::wstring			  version ;
		/// Windows nodeのYYYY/MM/DD日付
		std::wstring			  date ;
		/// Windows nodeのpacked version
		std::uint64_t			  packedVersion{} ;
		/// Windows nodeのFILETIME日付
		std::uint64_t			  dateTicks{} ;
		/// Windows nodeのfull rank
		std::uint32_t			  rank{} ;
		/// 同じ検査済みINFのWindows ClassGUIDです
		std::wstring			  infClassGuid ;
		/// Windowsの単一INF一覧が返した候補ClassGUIDです
		std::wstring			  classGuid ;
	} ;

	/**
     * @brief Opaque tokenへ対応する一scan限定の秘密binding記録である
     */
	struct OfficialInfInstallBindingRecord {
		/// 記録を有効とするscan session ID
		ScanSessionId											  scanSessionId{} ;
		/// Provider間照合用のopaque device identity
		std::wstring											  deviceIdentity ;
		/// 発行時の秘密device状態
		OfficialDeviceState										  device ;
		/// 発行時の一意なcandidate node
		OfficialCandidateNodeState								  candidate ;
		/// 発行時の具体性とrank監査結果
		OfficialDriverRankAudit									  rankAudit ;
		/// 自己媒体Portsの端末選択に結ぶWindows標準ページの元証拠
		std::optional<WindowsSystemFileTrust>					  serialPropertyPage ;
		/// 同byte関係を同issuer tokenへ固定します。公開metadataは導入権限になりません
		std::shared_ptr<const RequiredDriverComponentPlan>		  requiredPlan ;
		/// 仮想Wi-Fiバスへ置換する元選択でだけ保持する同端末の型・状態・全バイトです
		std::optional<MtdHandlerProperty>						  wifiBusUpperFilters ;
		/// 同issuerが同原archive/全作用/元deviceへ結んだprivate storage資格です
		std::shared_ptr<const StorageInfQualification>			  storageQualification ;
		/// 元署名Modelsの実選択と端末・クラスの原観測
		std::shared_ptr<const DeclarativeInfInstallQualification> declarativeQualification ;
		/// 公式範囲に対する同端末・元署名・用途確認済みの元計画です
		std::shared_ptr<const ScopedInfInstallQualification>	  scopedQualification ;
		/// 必要SWCだけの元選択親instanceです。指定子の直前にread-onlyで再照合します
		std::wstring											  requiredParentInstance ;
		/// 公式対象がある場合に現在端末のHardwareIdsへ要求する元IDです
		std::wstring											  requiredHardwareId ;
		/// 元承認のファームウェア群を登録・適用に入る直前にも再確認します
		bool													  requiresFirmwareAuthorization{} ;
	} ;
	/** @brief base後に実取得した子自身の同期観測です */
	struct RequiredChildObservation ;
	/** @brief 同じ元計画から実列挙した一子だけの同期中proofです */
	struct RequiredChildProof {
		/// 元scanと同じsessionです
		ScanSessionId					   session{} ;
		/// 同期操作中だけ有効な元operationです
		OperationId						   operation{} ;
		/// 同issuerが保持する元親bindingです
		std::uint64_t					   parentBindingToken{} ;
		/// 元不変計画内のcomponent位置です
		std::size_t						   roleIndex{} ;
		/// 同同期scope内で借用する元内容検査です
		const CommonInfInspection		  *inspection{} ;
		/// 同issuer親bindingが保持する不変計画です
		const RequiredDriverComponentPlan *plan{} ;
		/// 元内容検査の当該component packageです
		const OfficialInfPackage		  *package{} ;
		/// 同実子の全native状態と一意node/rankを借用します
		const RequiredChildObservation	  *observation{} ;
		/// 元選択親のopaque identityです
		std::wstring_view				   parentIdentity ;
		/// 同scopeだけの導出子identityです
		std::wstring_view				   childIdentity ;
		/// 実列挙で確認した元親instanceです
		std::wstring_view				   parentInstance ;
		/// 実列挙で確認した一意な子instanceです
		std::wstring_view				   childInstance ;
	} ;
	/**
	 * @brief 元deviceまたは同active親に結ぶ一時的な必要子を照合します
	 * @param[in] device 同bindingのopaque identityです
	 * @param[in] workspace 元byteを所有する同じ保護領域です
	 * @param[in] package 元計画で選択された同じpackageです
	 * @return 元deviceまたは同scopeで全項一致した必要子ならtrueです
	 * @note 新しいscan候補や外部から指定可能な子権限を発行しません
	 */
	[[nodiscard]] bool		  ownsBindingDevice( std::wstring_view				 device,
												const OfficialDownloadWorkspace &workspace,
												const OfficialInfPackage		&package) const noexcept ;
	/**
	 * @brief 同issuer元記録から全import内容とdevice別選択関係を再構築します
	 * @param[in] inspection 同保護元byteと全CAT/memberの検査所有者です
	 * @param[in] record 同session/device/元INFに固定した私有binding記録です
	 * @param[out] plan 成功時だけ同原順の不変内容計画です。失敗時は空です
	 * @param[out] diagnosticStage 任意の数値段階です。生ID・path・節名を含みません
	 * @return 元byteと選択節/role関係確認0、その他は元HRESULTです
	 * @note Worker内read-only処理です。単独の導入許可を発行しません
	 */
	[[nodiscard]] NativeError buildRequiredInfComponentPlan(
		const CommonInfInspection &inspection, const OfficialInfInstallBindingRecord &record,
		std::shared_ptr<const RequiredDriverComponentPlan> &plan,
		RequiredInfBindingDiagnostic					   *diagnosticStage = nullptr) const ;
	/**
	 * @brief 同原計画と元deviceのService propertyをprivate storage資格へ結びます
	 * @param[in] inspection 元ADMIN保護archiveの内容です
	 * @param[in] record 実測した同issuerの元device/native選択です
	 * @param[in] plan 全作用/依存/必要importの元不変計画です
	 * @param[out] qualification 全原値成立時だけの同device資格です。失敗時空です
	 * @return 全型/元所有/現service観測成立0、その他は原HRESULTです
	 * @note 旧serviceのbinary/hash/configと提案新値との一致を要求しません
	 */
	[[nodiscard]] NativeError buildStorageInfQualification(
		const CommonInfInspection &inspection, const OfficialInfInstallBindingRecord &record,
		const RequiredDriverComponentPlan			   &plan,
		std::shared_ptr<const StorageInfQualification> &qualification) const ;
	/** @brief 標準INF rankと別に保存する公式installerの元秘密device guardです */
	struct OfficialInstallerDeviceBindingRecord {
		/// Guardを発行した元scanです
		ScanSessionId		session{} ;
		/// 元表示のopaque deviceです
		std::wstring		identity ;
		/// 全native present/current観測へ結合した元秘密状態です
		OfficialDeviceState device ;
		/// 明示引継ぎの直前に一度だけtrueへ変更します
		bool				consumed{} ;
	} ;

	/** @brief 同保護INFの実byteに結合した一scanの登録先を保持します */
	struct StagedOfficialInf {
		/// 元保護INFの完全SHA-256。別閉包や改変へ登録先を転用しません
		std::wstring sourceSha256 ;
		/// 検証済みWindows INF root直下の実登録先です。通常UIへ渡しません
		std::wstring path ;
	} ;

	/**
	 * @brief scan で照合済みの Driver Store 候補を再列挙して導入する
	 * @param[in] target worker 内に保持した対象 metadata
	 * @param[in] parentWindowNative device installer UI の親 HWND
	 * @param[out] rebootRequired 完了に再起動が必要な場合は `true`
	 * @return 成功時は 0、失敗時は HRESULT bit pattern
	 */
	[[nodiscard]] NativeError						installTarget( const InstallTarget &target,
																  std::uintptr_t	   parentWindowNative,
																  bool				  &rebootRequired) const ;

	/**
	 * @brief scan session と秘密性のある device metadata を失効させる
	 */
	void											invalidateScanSession() noexcept ;

	/// Identity別の秘密metadata
	std::unordered_map<std::wstring, InstallTarget> installTargets_ ;
	/// Hardware ID照合表
	std::unordered_map<std::wstring, std::wstring>	hardwareToDevice_ ;
	/// Opaque device identityからSetupAPI再open用instance IDへ戻すworker内限定表
	std::unordered_map<std::wstring, std::wstring>	deviceInstances_ ;
	/// Opaque tokenから秘密device状態とcandidate nodeへ解決する一scan限定表
	std::unordered_map<std::uint64_t, OfficialInfInstallBindingRecord> officialInfInstallBindings_ ;
	/// 元親の同期中だけ借用する一子proofです。外部へ公開しません
	const RequiredChildProof										  *activeRequiredChild_{} ;
	/// 同issuerの単調tokenへ結合した最大4096のinstaller専用guardです
	std::unordered_map<std::uint64_t, OfficialInstallerDeviceBindingRecord>
																officialInstallerBindings_ ;
	/// 同元INFだけを一回stageするscan内cache。各指定導入前にroot/byte/nodeを再検証します
	mutable std::unordered_map<std::wstring, StagedOfficialInf> stagedOfficialInfs_ ;
	/// 再利用しない次のopaque token
	std::uint64_t												nextOfficialBindingToken_{1U} ;
	/// Installを許可する現在のscan session ID
	ScanSessionId												scanSessionId_{} ;
	/// Providerを所有するworker thread ID
	std::uint32_t												ownerThreadId_{} ;
	/// 直前のscanの列挙数、属性欠損、上限終端だけを持つ非機密計測値
	DeviceInventoryMeasurement									inventoryMeasurement_ ;
	/// 内部fixtureだけの現在属性I/O。空は既定Windows API
	std::optional<DriverStoreInventoryTransport>				testInventoryTransport_ ;
	/// 同workerだけが所有する凍結済み秘密属性。失効時に解放します
	mutable std::shared_ptr<const IndexInventoryState>			indexInventory_ ;
	/// 全選択検証後の一batchだけ元proofを生存させる私有所有。新resolverには使いません
	mutable std::shared_ptr<const IndexInventoryState>			installProofInventory_ ;
	/// 失敗scanも消費し、新scanやinstall失効で再利用しないinventory世代
	std::uint64_t												indexInventoryGeneration_{} ;
	/// 原scanからまだ消費していないopaque deviceだけです
	std::unordered_set<std::wstring>							pendingIndexDevices_ ;
	/// 一度だけ発行した原lookup contextです
	mutable IndexLookupContext									issuedIndexContext_ ;
	/// 一回scopeへ移した選択subsetです
	std::vector<std::wstring>									activeIndexDevices_ ;
	/// 今回だけの選択deviceで、native IDを外へ出しません
	std::vector<std::wstring>									activeInstallDevices_ ;
	/// 現operationです。0は未予約です
	OperationId													activeInstallOperation_{} ;
	/// 同scanで受理した最後の操作です。再受理しません
	OperationId													lastAcceptedInstallOperation_{} ;
	/// 実Provider入口へ渡した場合trueです
	bool														installEntered_{} ;
} ;

} // namespace drivercrate
