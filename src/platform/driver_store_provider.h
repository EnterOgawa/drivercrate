//------------------------------------------------------------------------------
/**
 * @file driver_store_provider.h
 * @brief Driver Store provider定義。
 * @version 01.08.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Binding指定INF導入を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Operation進捗通知追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  共通scan条件対応。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  検証済み外部INF導入境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  PnP rank非退行監査追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  端末内binding生成境界追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Local inventory計測参照を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  現在版を要求しない単一INF適合観測を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  同scan秘密属性の公表ID専用resolverを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  明示初回状態と実登録INFの同scan共有所有を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * Ver.01.05.00 Shunji Ogawa  2026/10/13  元Class観測とINF/native Classの私有binding保存を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/13  私有issuer限定の必要構成再検査と指定実行を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/13  同issuerの元node選択節から必要構成を発行。
 * Ver.01.07.01 Shunji Ogawa  2026/10/15  必要roleの登録byte保持期間を計画終端へ明示。
 * Ver.01.08.00 Shunji Ogawa  2026/10/15  非通信開発検査へ必要INF bindingの数値段階を追加。
 * </pre>
 *
 * @note 現在のPnP deviceとlocal Driver Storeの互換driver providerを定義します。Hardware IDとdevice instance IDは
 *       worker thread内だけに保持します。INF pathもUIまたはlogへ渡しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_driver_rank.h"
#include "core/official_release_observation.h"
#include "core/scan_measurement_types.h"
#include "core/update_provider.h"
#include "platform/official_catalog_device.h"
#include "platform/official_inf_install_binding.h"
#include "platform/driver_store_inventory_transport.h"
#include "platform/signed_index_record_lookup.h"

#include <cstdint>
#include <memory>
#include <span>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;
struct OfficialInfPackage ;
struct CommonInfInspection ;
struct RequiredInfBindingDiagnostic ;
class RequiredDriverComponentPlan ;
class SignedIndexCandidateBindingSession ;

//------------------------------------------------------------------------------
// Provider class定義。
//------------------------------------------------------------------------------

/**
 * @brief SetupAPI で local driver inventory と指定版の導入を提供する Provider である。
 */
class DriverStoreProvider final : public IUpdateProvider {
public:
	/**
     * @brief 現在 thread に所属する空の Driver Store Provider を作成する。
     */
	DriverStoreProvider() = default ;

	/**
	 * @brief 現在属性の非通信内部試験用API表を所有copyする。
	 * @param[in] transport 完全なSetupAPI代替表。欠損をnative呼出しで補完しない。
	 * @note このinstanceはscanCurrentInventory専用。通常scanと導入sessionを発行しない。
	 */
	explicit DriverStoreProvider( DriverStoreInventoryTransport transport) noexcept ;

	/**
     * @brief scan session と秘密性のある native metadata を解放する。
     */
	~DriverStoreProvider() override = default ;

	// Native scan sessionを単独所有するためcopy/moveを禁止する。
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	DriverStoreProvider( const DriverStoreProvider &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	DriverStoreProvider &operator=( const DriverStoreProvider &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	DriverStoreProvider( DriverStoreProvider &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	DriverStoreProvider		&operator=( DriverStoreProvider &&) = delete ;

	/**
	 * @brief 現在の PnP device と compatible Driver Store 履歴を列挙する。
	 * 現在の PnP device と compatible Driver Store履歴を列挙する。 注記: network 通信、download、およびsystem state の変更は
	 * 行わない。
	 * @param[in] scanSessionId 呼出し側が割り当てた 0 ではない session ID。 呼出し側が割り当てた 0 ではないsession ID。
	 * @param[in] options Aggregate Provider以外では既定値を使用するscan設定。 複合Providerで検証済みのscan条件。
	 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
	 * @return 現在版と切替可能な local driver 候補を含む scan 結果。
	 * @note network 通信、download、および system state の変更は行わない。
	 */
	[[nodiscard]] ScanResult scan( ScanSessionId scanSessionId, const ScanOptions &options,
								  const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief 履歴・native照合map・install targetを生成せず現在属性だけを列挙する。
	 * @param[in] scanSessionId 専用contextと一致するworker session。
	 * @param[in,out] execution 同期呼出し中だけ借用する取消し・期限context。
	 * @param[in] progressCallback 確定した列挙件数の通知先。
	 * @return 表示専用の現在行。途中停止では検証済み行と不完全な計測を保持。
	 */
	[[nodiscard]] ScanResult scanCurrentInventory( ScanSessionId					  scanSessionId,
												  MetadataSearchExecutionContext &execution,
												  const ProviderProgressCallback &progressCallback) ;

	/** @brief 現在属性scanへ索引専用の秘密ID captureだけを追加します。
	 * @param[in] scanSessionId 専用contextと一致する正のsession。
	 * @param[in,out] execution 同期呼出し中だけ借用する停止context。
	 * @param[in] progressCallback 確定進捗の通知先。
	 * @return 表示専用の現在行と独立した秘密resolver state。
	 * @note 完全transport内だけで実行し、履歴・install session・native fallbackを発行しません。
	 */
	[[nodiscard]] ScanResult scanCurrentIndexInventory(
		ScanSessionId scanSessionId, MetadataSearchExecutionContext &execution,
		const ProviderProgressCallback &progressCallback) ;

	/** @brief 同scanの秘密snapshotをweak所有するread-only resolverを発行します。
	 * @param[in] operationId 結合する正のworker operation。
	 * @param[out] context 発行時だけsessionと単調inventory世代を返します。拒否時は空です。
	 * @param[out] present 全観測opaque集合。拒否時は空です。生IDは含みません。
	 * @return 所有threadの有効snapshotだけがcallbackを持ちます。拒否時はnullptrです。
	 * @note Workerで同期呼出しし再入しません。新scan・install・Provider破棄で旧callbackは失効します。
	 * 不完全snapshotのcallbackも発行できますが、resolveのcompletedはfalseです。
	 */
	[[nodiscard]] std::unique_ptr<IndexPublicIdResolver> makeIndexPublicIdResolver(
		std::uint64_t operationId, IndexLookupContext &context,
		std::vector<std::wstring> &present) const ;

	/**
	 * @brief 直前のscanで実際に観測したlocal inventory計測を取得する。
	 * @return Providerが所有する計測値への参照。次のscan、installまたは失効まで有効である。
	 * @note 生のdevice識別子を含まず、呼出し元はworker thread内でだけ参照する。
	 */
	[[nodiscard]] const DeviceInventoryMeasurement &inventoryMeasurement() const noexcept ;

	/**
	 * @brief 選択された local driver node を再照合して device へ導入する。
	 * 選択された local driver node を再照合して deviceへ導入する。 注記: scan 時の INF path を直接信用せず、実行直前に全 metadata を再照合
	 * する。
	 * @param[in] scanSessionId 選択元の Driver Store scan session ID。
	 * @param[in] identities UI に提示済みの opaque identity 群。
	 * @param[in] parentWindowNative device installer の親 HWND を整数表現で渡す値。 device installer の親 HWNDを整数
	 *                   表現で渡す値。
	 * @param[in] progressCallback 段階、処理件数、および全体完了率の通知先。
	 * @return 選択候補ごとの導入結果。
	 * @note scan 時の INF path を直接信用せず、実行直前に全 metadata を再照合する。
	 */
	[[nodiscard]] InstallResult						install( ScanSessionId					scanSessionId,
															std::span<const std::wstring>	identities,
															std::uintptr_t					parentWindowNative,
															const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief WUA の Hardware ID と一致する local device の opaque identity を取得する。
	 * @param[in] hardwareId WUA が返した Hardware ID。外部へ公開しない。
	 * @return 現在の scan で一致する device identity。曖昧または未検出なら `std::nullopt`。
	 */
	[[nodiscard]] std::optional<std::wstring>		deviceIdentityForHardwareId(
			  std::wstring_view hardwareId) const ;

	/**
	 * @brief 公式catalog snapshotへ端末内限定binding fingerprintを付与する。
	 * 公式catalog snapshotへ端末内bindingを付与する。
	 * Opaque identityをworker内mapでnative IDへ解決し、全件成功した場合だけfingerprintを反映する。生IDは返さない。
	 * @param[in] secret 管理者保護stateから読み取った端末固有HMAC key。 管理者保護stateの端末固有HMAC key。
	 * @param[in,out] devices 現在scanのopaque identityを持つ非機密snapshot。 現在scanの公式catalog用snapshot。
	 * @return 全deviceへ付与できた場合は0、session、identity、CNG失敗時はHRESULT。 全deviceへ付与できた場合は0、入力またはCNG失敗時は
	 *         HRESULT。
	 * @note Native device instance IDは本関数から返さず、network、UI、logへ渡さない。
	 */
	[[nodiscard]] NativeError attachLocalOfficialBindingFingerprints(
		const LocalOfficialBindingSecret &secret, std::span<OfficialCatalogDevice> devices) const ;

	/**
	 * @brief G11-Cで分離した一つのINFを現在deviceのrankとread-onlyで比較する。
	 * G11-Cで分離した一INFのPnP具体性とrankを監査する。
	 * 現在driverと単一候補INFのWindows rankをread-onlyで取得し、ID具体性とrankが退行しない場合だけApplicableとする。
	 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID。
	 * @param[in] deviceIdentity UIへ提示済みのopaque device identity。
	 * @param[in] workspace Candidate driver閉包を所有する保護workspace。 Candidate閉包を所有する保護workspace。
	 * @param[in] package G11-Cで構造を検証した一つのINF package。 G11-Cで構造検証した一INF package。
	 * @param[out] audit PnP ID文字列を含まない具体性とrankの監査結果。 PnP ID文字列を含まない監査結果。
	 * @return 拒否を含む監査判定の生成時は0、入力またはSetupAPI失敗時はHRESULT。 拒否を含む監査判定の生成時は0、処理失敗時はHRESULT。
	 * @note 戻り値0だけでinstallを許可せず、auditのApplicableを別途確認する。
	 * @note Driver Storeへのstage、driver選択、installまたはdevice state変更を行わない。
	 */
	[[nodiscard]] NativeError auditOfficialInfRank( ScanSessionId					scanSessionId,
												   std::wstring_view				deviceIdentity,
												   const OfficialDownloadWorkspace &workspace,
												   const OfficialInfPackage		   &package,
												   OfficialDriverRankAudit		   &audit) const ;

	/**
	 * @brief 現在版を要求せず単一INFのWindows compatible nodeを観測する。
	 * @param[in] scanSessionId 現在inventoryのsession。
	 * @param[in] deviceIdentity 当該sessionのopaque device identity。
	 * @param[in] workspace 検証済みINF閉包の所有領域。
	 * @param[in] package 内容と署名を検証したINF。
	 * @param[out] candidateRank 一致nodeの最小Windows rank。非適用・失敗時は空。
	 * @return 全列挙完了時0、入力・SetupAPI・有限上限違反時はHRESULT。
	 * @note 空結果とAPI失敗を区別する。現在driverとの順位比較や導入許可は発行しない。
	 * Workerから呼び、staging、driver選択、installを行わない。
	 */
	[[nodiscard]] NativeError observeInfCandidateRank(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		std::optional<std::uint32_t> &candidateRank) const ;

	/**
	 * @brief 監査済み公式INFを現在device状態と一意なWindows nodeへ拘束する。
	 * 監査済み公式INFを現在状態と一意なWindows nodeへ拘束する。
	 * 現在状態と候補nodeを再取得し、全照合成功後だけ単調増加tokenへ秘密metadataをcommitする。OS状態は変更しない。
	 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID。
	 * @param[in] deviceIdentity UIへ提示済みのopaque device identity。
	 * @param[in] workspace Candidate driver閉包を所有する保護workspace。 Candidate閉包を所有する保護workspace。
	 * @param[in] package G11-Cで構造を検証した一つのINF package。 内容監査済みの一INF package。
	 * @param[in] expectedCurrentProvider Scan結果に固定した現在Provider表示名。 Scan時の現在Provider名。
	 * @param[in] expectedCurrentVersion Scan結果に固定した現在version。 Scan時の現在version。
	 * @param[in] expectedCurrentDate Scan結果に固定した現在のYYYY/MM/DD日付。 Scan時の現在日付。
	 * @param[in] expectedRankAudit 発行前に合格したPnP具体性とrank監査結果。 直前に合格したrank監査結果。
	 * @param[out] binding 成功時の一scan限定opaque binding。失敗時は空値。 成功時の非機密opaque binding。
	 * @return 発行成功時は0、入力、状態変更、一意性またはSetupAPI失敗時はHRESULT。 Binding発行時は0、状態変更、曖昧性またはSetupAPI失敗時は
	 *         HRESULT。
	 * @note 生のinstance ID、PnP ID、INF path、sectionはDriver Store内だけに保持する。
	 */
	[[nodiscard]] NativeError createOfficialInfInstallBinding(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		std::wstring_view expectedCurrentProvider, std::wstring_view expectedCurrentVersion,
		std::wstring_view expectedCurrentDate, const OfficialDriverRankAudit &expectedRankAudit,
		OfficialInfInstallBinding &binding) ;

	/**
	 * @brief 公式INF導入bindingと現在のdeviceおよびWindows nodeを再照合する。
	 * 公式INF導入bindingと現在状態を再照合する。
	 * 発行時の現在INF、版、日付、PnP状態と候補section、版、日付、rankを再取得値へ比較する。OS状態は変更しない。
	 * @param[in] scanSessionId Bindingを発行した現在session ID。 Binding発行元のscan session ID。
	 * @param[in] deviceIdentity Bindingに対応するopaque device identity。 Bindingに対応するopaque device ID。
	 * @param[in] workspace 再検証済みcandidate閉包を所有する保護workspace。 再検証済みcandidateの保護workspace。
	 * @param[in] package 再検証済みの一つのINF package。 再検証済みの一INF package。
	 * @param[in] binding Provider workerが保持した非機密binding。 Provider workerが保持する非機密binding。
	 * @return 全記録が一致する場合は0、失効、変更またはSetupAPI失敗時はHRESULT。 全記録一致時は0、失効、変更またはSetupAPI失敗時はHRESULT。
	 * @note 本関数はDriver Storeへのstage、driver選択、installを行わない。
	 */
	[[nodiscard]] NativeError revalidateOfficialInfInstallBinding(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		const OfficialInfInstallBinding &binding) const ;

	/**
	 * @brief 指定scanに属する一つの公式INF導入bindingを明示的に破棄する。
	 * 現在sessionと所有workerを照合し、他候補のbindingを維持したまま未発行候補の秘密記録だけを破棄する。
	 * @param[in] scanSessionId Bindingを発行したscan session ID。
	 * @param[in] token Driver Storeが発行した0ではないopaque token。 Driver Storeが発行したopaque token。
	 * @return 一件を破棄した場合true。別session、別workerまたは未登録ならfalse。 一件を破棄した場合true。不一致または未登録ならfalse。
	 * @note 他Providerが同じscanで保持するbindingは変更しない。
	 */
	bool discardOfficialInfInstallBinding( ScanSessionId scanSessionId,
										  std::uint64_t token) noexcept ;

	/**
	 * @brief 指定scanに属する全公式INF導入bindingを明示的に失効させる。
	 * 指定scanの公式INF導入bindingを明示的に失効させる。
	 * 現在sessionと所有workerが一致する場合だけ全tokenを破棄する。旧sessionから現在bindingを失効させない。
	 * @param[in] scanSessionId Bindingを発行したscan session ID。
	 * @note 旧sessionまたは所有worker以外からの要求では現在bindingを変更しない。
	 */
	void invalidateOfficialInfInstallBindings( ScanSessionId scanSessionId) noexcept ;

	/**
	 * @brief Bindingで固定した監査済み公式INFをstagingして指定deviceへ導入する。
	 * Bindingを再検証後、SetupCopyOEMInfWが返した登録先INFから一意なnodeを再構築する。導入直前にも現在状態を確認し、DiInstallDeviceへ非nullの
	 * DriverInfoDataとFlags 0を渡す。
	 * @param[in] scanSessionId Bindingを発行した現在scan session ID。 Bindingを発行した現在session。
	 * @param[in] deviceIdentity Bindingに対応するopaque device identity。 対象のopaque device identity。
	 * @param[in] workspace 再検証済みcandidate閉包を所有する保護workspace。 再検証済みINF閉包の保護workspace。
	 * @param[in] package 再検証済みの一つのINF package。 再検証済みの一INF package。
	 * @param[in] binding Provider workerが保持する一scan限定binding。 Providerが保持する一scan限定binding。
	 * @param[in] parentWindowNative Windows導入dialogの親Window値。 Installer親HWNDの整数表現。
	 * @param[out] rebootRequired 導入完了に再起動が必要な場合はtrue。
	 * @return Stagingと指定device導入の成功時は0、それ以外はHRESULT。
	 * @note Windowsが返した登録先INFだけを再照合し、登録済みpackageを自動削除しない。
	 */
	[[nodiscard]] NativeError installBoundOfficialInf( ScanSessionId		scanSessionId,
													  std::wstring_view deviceIdentity,
													  const OfficialDownloadWorkspace &workspace,
													  const OfficialInfPackage		  &package,
													  const OfficialInfInstallBinding &binding,
													  std::uintptr_t parentWindowNative,
													  bool			&rebootRequired) const ;

	/**
	 * @brief 検証済み外部INFを現在scanの一つのopaque deviceへ導入する。
	 * 検証済み外部INFを現在scanの一deviceへ導入する。
	 * 指定INF一件だけからcompatible listを構築し、Providerとversionが一意なnodeだけを対象deviceへ導入する。
	 * @param[in] scanSessionId Device inventoryを作成した現在session ID。 Device inventoryの現在session ID。
	 * @param[in] deviceIdentity UIへ提示済みのopaque device identity。 対象のopaque device identity。
	 * @param[in] infPath Providerが再検証した保護workspace内INF絶対path。 再検証済みINFの保護workspace絶対path。
	 * @param[in] expectedProvider Scan時に検証したINF Provider表示名。 Scan時のINF Provider表示名。
	 * @param[in] expectedVersion Scan時に検証した4要素numeric driver version。 Scan時の4要素numeric version。
	 * @param[in] parentWindowNative Device installerの親HWNDを整数表現で渡す値。 Installer親HWNDの整数表現。
	 * @param[out] rebootRequired 完了に再起動が必要な場合は`true`。
	 * @return 導入成功時は0、session、再照合またはWindows API失敗時はHRESULT。 対象nodeの再照合と導入成功時は0、それ以外はHRESULT。
	 * @pre 呼出し側はINF、CAT、全参照fileの署名とPnP適用性を直前に再検証する。
	 */
	[[nodiscard]] NativeError installVerifiedExternalInf(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity, std::wstring_view infPath,
		std::wstring_view expectedProvider, std::wstring_view expectedVersion,
		std::uintptr_t parentWindowNative, bool &rebootRequired) const ;

	/** @brief 元scanのpresent deviceを公式installer専用の秘密guardへ固定します。
	 * @param[in] session 元scan sessionです。
	 * @param[in] device 元表示のopaque deviceです。
	 * @param[in] provider 元現在行のproviderです。native再観測へ完全一致を要求します。
	 * @param[in] version 元現在行の版です。
	 * @param[in] date 元現在行の日付です。
	 * @param[out] token 全原状態一致時だけ非zero guardです。失敗時0です。
	 * @return 同worker/native x64/present/原現在状態確認0、拒否は元HRESULTです。
	 * @note 標準INFのWindows rank合格を発行しません。
	 */
	[[nodiscard]] NativeError createOfficialInstallerDeviceBinding(
		ScanSessionId session, std::wstring_view device, std::wstring_view provider,
		std::wstring_view version, std::wstring_view date, std::uint64_t &token) ;
	/** @brief 元installer guardを変更直前のpresent/全秘密状態へ再照合します。
	 * @param[in] session 元scanです。
	 * @param[in] device 元opaque deviceです。
	 * @param[in] token 未使用の同issuer guardです。
	 * @return 全native状態一致0、それ以外は元HRESULTです。
	 */
	[[nodiscard]] NativeError revalidateOfficialInstallerDeviceBinding( ScanSessionId	 session,
																	   std::wstring_view device,
																	   std::uint64_t token) const ;
	/** @brief 明示選択済みguardを一回だけ消費します。
	 * @param[in] session 元scanです。
	 * @param[in] device 元opaque deviceです。
	 * @param[in] token 元未使用guardです。
	 * @return 全再照合成功0、再使用/変化は元HRESULTです。
	 */
	[[nodiscard]] NativeError consumeOfficialInstallerDeviceBinding( ScanSessionId	  session,
																	std::wstring_view device,
																	std::uint64_t	  token) ;
	/** @brief 同issuerの未公開installer guardだけをrollbackします。
	 * @param[in] session 元scanです。
	 * @param[in] token 当該issuerの元guardです。
	 * @return 元sessionのguardを除去した場合trueです。
	 */
	bool discardOfficialInstallerDeviceBinding( ScanSessionId session, std::uint64_t token) noexcept ;

private:
	friend class SignedIndexCandidateBindingSession ;
	friend class DriverStoreBindingProbe ;
	/** @brief 検証済み役割計画を単一親の私有bindingへ固定します。
	 * @param[in] session 元scan sessionです。
	 * @param[in] identity 元選択親のopaque identityです。
	 * @param[in] inspection 同byte/CAT検証済み閉包です。
	 * @param[out] plan 同deviceの私有node選択から生成した不変関係です。失敗時は空です。
	 * @param[in] provider 元現在行のproviderです。
	 * @param[in] version 元現在行のversionです。
	 * @param[in] date 元現在行の日付です。
	 * @param[in] audit 元baseのWindows rank監査です。
	 * @param[out] binding 全照合成功時だけ発行する元親bindingです。
	 * @param[out] diagnosticStage 任意の非所有数値診断先です。nullなら採取せず権限判定へ使いません。
	 * @return 成功0、関係/適用性/元状態の拒否はHRESULTです。
	 */
	[[nodiscard]] NativeError createRequiredInfInstallBinding(
		ScanSessionId session, std::wstring_view identity, const CommonInfInspection &inspection,
		std::shared_ptr<const RequiredDriverComponentPlan> &plan, std::wstring_view provider,
		std::wstring_view version, std::wstring_view date, const OfficialDriverRankAudit &audit,
		OfficialInfInstallBinding	 &binding,
		RequiredInfBindingDiagnostic *diagnosticStage = nullptr) ;
	/** @brief 元親と全必要役割を変更前にread-onlyで再検証します。
	 * @param[in] session 元scanです。
	 * @param[in] identity 元親opaqueです。
	 * @param[in] inspection 元保護閉包です。
	 * @param[in] plan 元私有関係です。
	 * @param[in] binding 元親bindingです。
	 * @return 全byte/関係/元状態一致0、失効/未確認はHRESULTです。
	 */
	[[nodiscard]] NativeError revalidateRequiredInfInstallBinding(
		ScanSessionId session, std::wstring_view identity, const CommonInfInspection &inspection,
		const std::shared_ptr<const RequiredDriverComponentPlan> &plan,
		const OfficialInfInstallBinding							 &binding) const ;
	/** @brief 必要役割をstageし指定親と一意な必要SWC子だけを導入します。
	 * @param[in] session 元scanです。
	 * @param[in] identity 元選択親です。
	 * @param[in] inspection 元検証済み閉包です。
	 * @param[in] plan 元私有関係です。
	 * @param[in] binding 元親bindingです。
	 * @param[in] parentWindowNative 明示操作の親windowです。
	 * @param[out] roles 実際のstage/指定導入/Windows反映待ちを役割別に保持します。
	 * @param[out] rebootRequired 実APIが返した再起動要否です。
	 * @return 全指定API完了0、反映待ちS_FALSE、部分失敗はHRESULTです。
	 * @note 必要roleの元/登録INF/rootを変更非共有で計画終端まで保持します。
	 * Extension反映をbase API成功から推測しません。全device導入APIを呼びません。
	 */
	[[nodiscard]] NativeError installBoundRequiredInfPlan(
		ScanSessionId session, std::wstring_view identity, const CommonInfInspection &inspection,
		const std::shared_ptr<const RequiredDriverComponentPlan> &plan,
		const OfficialInfInstallBinding &binding, std::uintptr_t parentWindowNative,
		std::vector<DriverPlanRoleExecutionResult> &roles, bool &rebootRequired) ;
	/** @brief 標準入口または私有計画入口で確認したbase nodeを発行します。
	 * @param[in] scanSessionId 元scanです。
	 * @param[in] deviceIdentity 元opaqueです。
	 * @param[in] workspace 検証済み閉包です。
	 * @param[in] package 検証済み一INFです。
	 * @param[in] expectedCurrentProvider 元現在providerです。
	 * @param[in] expectedCurrentVersion 元現在versionです。
	 * @param[in] expectedCurrentDate 元現在日付です。
	 * @param[in] expectedRankAudit 元Windows rankです。
	 * @param[out] binding 同状態の一意nodeだけです。
	 * @return 一意性/全状態一致0、それ以外はHRESULTです。
	 */
	[[nodiscard]] NativeError createOfficialInfInstallBindingImpl(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		std::wstring_view expectedCurrentProvider, std::wstring_view expectedCurrentVersion,
		std::wstring_view expectedCurrentDate, const OfficialDriverRankAudit &expectedRankAudit,
		OfficialInfInstallBinding &binding) ;
	/** @brief 同保護INFのbyteを再確認して一度だけstoreへimportします。
	 * @param[in] workspace 元保護領域です。
	 * @param[in] package 同byte検証済みINFです。
	 * @param[out] stagedInfPath 検証済み登録root直下の秘密pathです。
	 * @return stageと元/登録byte一致0、それ以外はHRESULTです。
	 */
	[[nodiscard]] NativeError stageOfficialInfPackage( const OfficialDownloadWorkspace &workspace,
													  const OfficialInfPackage		  &package,
													  std::wstring &stagedInfPath) const ;
	/** @brief 私有前提を満たした指定一deviceの元実装を実行します。
	 * @param[in] scanSessionId 元scanです。
	 * @param[in] deviceIdentity 元opaqueです。
	 * @param[in] workspace 元保護閉包です。
	 * @param[in] package 元検証済みINFです。
	 * @param[in] binding 元一意nodeです。
	 * @param[in] parentWindowNative 明示操作の親windowです。
	 * @param[out] rebootRequired 実APIの再起動値です。
	 * @param[out] diagnosticMissing 非nullは同期中だけ借用する出力です。FALSE/LastError0の観測だけtrueです。
	 * @return stage/指定API完了0、それ以外はHRESULTです。
	 * @note FALSE/LastError0では内部ERROR_INVALID_DATAを返し、実Windowsの同error観測と区別します。
	 */
	[[nodiscard]] NativeError installBoundOfficialInfImpl(
		ScanSessionId scanSessionId, std::wstring_view deviceIdentity,
		const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
		const OfficialInfInstallBinding &binding, std::uintptr_t parentWindowNative,
		bool &rebootRequired, bool *diagnosticMissing = nullptr) const ;
	/**
	 * @brief 通常scanと現在属性専用scanが共有する有界present列挙。
	 * @param[in] scanSessionId 呼出側が発行した非ゼロsession。
	 * @param[in] progressCallback 同期の進捗通知先。
	 * @param[in,out] execution Nullは通常履歴検索、非nullは表示専用。
	 * @param[in] captureIndexIds 同scanの索引照合用秘密属性を保持する場合true。
	 * @return 列挙結果。専用modeではinstall sessionを発行しない。
	 */
	[[nodiscard]] ScanResult scanInventory( ScanSessionId				   scanSessionId,
										   const ProviderProgressCallback &progressCallback,
										   MetadataSearchExecutionContext *execution,
										   bool							   captureIndexIds = false) ;
	/** @brief 索引専用の同scan秘密属性と必要属性の完了軸です。 */
	struct IndexInventoryState ;
	/** @brief 秘密stateを外へ公開しないweak所有callbackです。 */
	class IndexInventoryResolver ;
	/**
     * @brief scan 時に照合し、worker thread 内だけで保持する導入対象 metadata である。
     */
	struct InstallTarget {
		/// SetupAPI再列挙に使用する秘密のdevice instance ID。
		std::wstring  deviceInstanceId ;
		/// Driver Store内で照合するINF file名。
		std::wstring  infFileName ;
		/// 選択driver nodeのINF install section名。
		std::wstring  sectionName ;
		/// Candidate再照合に使用するdriver provider名。
		std::wstring  providerName ;
		/// SP_DRVINFO_DATAのpacked driver version。
		std::uint64_t driverVersion{} ;
		/// FILETIMEを64-bit値にしたdriver日付。
		std::uint64_t driverDateTicks{} ;
	} ;

	/**
     * @brief Binding発行時の現在deviceとdriver状態をworker内だけで保持する。
     */
	struct OfficialDeviceState {
		/// SetupAPI再open用の秘密device instance ID。
		std::wstring					   deviceInstanceId ;
		/// 発行時のsetup class名。
		std::wstring					   deviceClass ;
		/// 具体性順の秘密Hardware ID群。
		std::vector<std::wstring>		   hardwareIds ;
		/// 具体性順の秘密Compatible ID群。
		std::vector<std::wstring>		   compatibleIds ;
		/// 現在driver選択に使われた秘密PnP ID。
		std::wstring					   matchingDeviceId ;
		/// 現在driverの秘密INF file名。
		std::wstring					   currentInfFileName ;
		/// 現在driverのProvider表示名。
		std::wstring					   currentProvider ;
		/// 現在driverの原文version。
		std::wstring					   currentVersion ;
		/// 現在driverのYYYY/MM/DD日付。
		std::wstring					   currentDate ;
		/// 現在driverのpacked version。Native NO_DRIVERでは比較へ使用しません。
		std::uint64_t					   currentPackedVersion{} ;
		/// Nativeの全未導入根拠へ結合する初回modeです。空版から設定しません。
		bool							   noDriver{} ;
		/// 元Class propertyの正式不存在/値を保持します。
		DevicePropertyReadStatus		   classRead ;
		/// 元ClassGUID propertyの読取状態です。
		DevicePropertyReadStatus		   classGuidRead ;
		/// 元ClassGUID propertyの値。不存在時は空です。
		std::wstring					   observedClassGuid ;
		/// 一覧構築前の元device ClassGUIDです。
		std::wstring					   nativeClassGuid ;
		/// 元Class観測の方式。INF Classで上書きしません。
		OfficialDriverRankDeviceClassState classState{
			OfficialDriverRankDeviceClassState::KNOWN_CLASS} ;
		/// 元nodeのstatus/problemです。変更直前の差を拒否します。
		DeviceNodeObservation	 node ;
		/// 元driver keyの読取方式です。
		DevicePropertyReadStatus driverKeyRead ;
		/// 元Matching IDの読取方式です。
		DevicePropertyReadStatus matchingRead ;
		/// 元driver key値です。Worker内だけで保持します。
		std::wstring			 driverKey ;
	} ;

	/**
     * @brief Binding発行時の一意なcandidate Windows nodeをworker内だけで保持する。
     */
	struct OfficialCandidateNodeState {
		/// 保護workspace内の秘密INF絶対path。
		std::wstring  infPath ;
		/// Windows nodeが選択した秘密install section名。
		std::wstring  sectionName ;
		/// Windows nodeのProvider表示名。
		std::wstring  provider ;
		/// Windows nodeの4要素version。
		std::wstring  version ;
		/// Windows nodeのYYYY/MM/DD日付。
		std::wstring  date ;
		/// Windows nodeのpacked version。
		std::uint64_t packedVersion{} ;
		/// Windows nodeのFILETIME日付。
		std::uint64_t dateTicks{} ;
		/// Windows nodeのfull rank。
		std::uint32_t rank{} ;
		/// 同じ検査済みINFのWindows ClassGUIDです。
		std::wstring  infClassGuid ;
		/// Windowsの単一INF一覧が返した候補ClassGUIDです。
		std::wstring  classGuid ;
	} ;

	/**
     * @brief Opaque tokenへ対応する一scan限定の秘密binding記録である。
     */
	struct OfficialInfInstallBindingRecord {
		/// 記録を有効とするscan session ID。
		ScanSessionId									   scanSessionId{} ;
		/// Provider間照合用のopaque device identity。
		std::wstring									   deviceIdentity ;
		/// 発行時の秘密device状態。
		OfficialDeviceState								   device ;
		/// 発行時の一意なcandidate node。
		OfficialCandidateNodeState						   candidate ;
		/// 発行時の具体性とrank監査結果。
		OfficialDriverRankAudit							   rankAudit ;
		/// 同byte関係を同issuer tokenへ固定します。公開metadataは導入権限になりません。
		std::shared_ptr<const RequiredDriverComponentPlan> requiredPlan ;
		/// 必要SWCだけの元選択親instanceです。指定子の直前にread-onlyで再照合します。
		std::wstring									   requiredParentInstance ;
	} ;
	/** @brief 同issuer元記録から全import内容とdevice別選択関係を再構築します。
	 * @param[in] inspection 同保護元byteと全CAT/memberの検査所有者です。
	 * @param[in] record 同session/device/元INFに固定した私有binding記録です。
	 * @param[out] plan 成功時だけ同原順の不変内容計画です。失敗時は空です。
	 * @param[out] diagnosticStage 任意の数値段階です。生ID・path・節名を含みません。
	 * @return 元byteと選択節/role関係確認0、その他は元HRESULTです。
	 * @note Worker内read-only処理です。単独の導入許可を発行しません。
	 */
	[[nodiscard]] NativeError buildRequiredInfComponentPlan(
		const CommonInfInspection &inspection, const OfficialInfInstallBindingRecord &record,
		std::shared_ptr<const RequiredDriverComponentPlan> &plan,
		RequiredInfBindingDiagnostic					   *diagnosticStage = nullptr) const ;
	/** @brief 標準INF rankと別に保存する公式installerの元秘密device guardです。 */
	struct OfficialInstallerDeviceBindingRecord {
		/// Guardを発行した元scanです。
		ScanSessionId		session{} ;
		/// 元表示のopaque deviceです。
		std::wstring		identity ;
		/// 全native present/current観測へ結合した元秘密状態です。
		OfficialDeviceState device ;
		/// 明示引継ぎの直前に一度だけtrueへ変更します。
		bool				consumed{} ;
	} ;

	/** @brief 同保護INFの実byteに結合した一scanの登録先を保持します。 */
	struct StagedOfficialInf {
		/// 元保護INFの完全SHA-256。別閉包や改変へ登録先を転用しません。
		std::wstring sourceSha256 ;
		/// 検証済みWindows INF root直下の実登録先です。通常UIへ渡しません。
		std::wstring path ;
	} ;

	/**
	 * @brief scan で照合済みの Driver Store 候補を再列挙して導入する。
	 * @param[in] target worker 内に保持した対象 metadata。
	 * @param[in] parentWindowNative device installer UI の親 HWND。
	 * @param[out] rebootRequired 完了に再起動が必要な場合は `true`。
	 * @return 成功時は 0、失敗時は HRESULT bit pattern。
	 */
	[[nodiscard]] NativeError						installTarget( const InstallTarget &target,
																  std::uintptr_t	   parentWindowNative,
																  bool				  &rebootRequired) const ;

	/**
	 * @brief scan session と秘密性のある device metadata を失効させる。
	 */
	void											invalidateScanSession() noexcept ;

	/// Identity別の秘密metadata。
	std::unordered_map<std::wstring, InstallTarget> installTargets_ ;
	/// Hardware ID照合表。
	std::unordered_map<std::wstring, std::wstring>	hardwareToDevice_ ;
	/// Opaque device identityからSetupAPI再open用instance IDへ戻すworker内限定表。
	std::unordered_map<std::wstring, std::wstring>	deviceInstances_ ;
	/// Opaque tokenから秘密device状態とcandidate nodeへ解決する一scan限定表。
	std::unordered_map<std::uint64_t, OfficialInfInstallBindingRecord> officialInfInstallBindings_ ;
	/// 同issuerの単調tokenへ結合した最大4096のinstaller専用guardです。
	std::unordered_map<std::uint64_t, OfficialInstallerDeviceBindingRecord>
																officialInstallerBindings_ ;
	/// 同元INFだけを一回stageするscan内cache。各指定導入前にroot/byte/nodeを再検証します。
	mutable std::unordered_map<std::wstring, StagedOfficialInf> stagedOfficialInfs_ ;
	/// 再利用しない次のopaque token。
	std::uint64_t												nextOfficialBindingToken_{1U} ;
	/// Installを許可する現在のscan session ID。
	ScanSessionId												scanSessionId_{} ;
	/// Providerを所有するworker thread ID。
	std::uint32_t												ownerThreadId_{} ;
	/// 直前のscanの列挙数、属性欠損、上限終端だけを持つ非機密計測値。
	DeviceInventoryMeasurement									inventoryMeasurement_ ;
	/// 内部fixtureだけの現在属性I/O。空は既定Windows API。
	std::optional<DriverStoreInventoryTransport>				testInventoryTransport_ ;
	/// 同workerだけが所有する凍結済み秘密属性。失効時に解放します。
	mutable std::shared_ptr<const IndexInventoryState>			indexInventory_ ;
	/// 失敗scanも消費し、新scanやinstall失効で再利用しないinventory世代。
	std::uint64_t												indexInventoryGeneration_{} ;
} ;

} // namespace drivercrate
