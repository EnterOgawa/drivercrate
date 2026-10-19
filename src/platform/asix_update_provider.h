//------------------------------------------------------------------------------
/**
 * @file asix_update_provider.h
 * @brief ASIX AX88179A公式検索・取得準備Provider定義。
 * @version 01.00.01
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  取得後監査結果と一回report契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  検索候補とPnP監査境界の保持契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  同意後の検査用取得と保持物の寿命を定義。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  取得準備snapshotと失効境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測型の直接includeを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測差分を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/10/13  観測field説明を完全な宣言開始前へ配置。
 * </pre>
 *
 * @note 固定製品pageと端末内表示名を照合し、Windows client x64配布情報だけを表示します。Hardware IDを送信せず、取得準備snapshotをworker
 *       threadとscan sessionへ拘束します。監査合格候補の明示選択後、復旧保護とbinding再照合を経て指定導入します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_preparation.h"
#include "core/official_preparation_audit.h"
#include "core/official_preparation_operation.h"
#include "platform/official_acquisition.h"
#include "platform/official_bound_preparation.h"
#include "platform/official_catalog_provider.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package_audit.h"
#include "platform/official_http_client.h"
#include "platform/official_release_local_probe.h"
#include "platform/official_release_metadata.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/**
 * @brief 検証済み固定page取得だけを差し替える内部試験境界。
 * @param[in] scanSessionId 0ではないscan session。
 * @param[out] html 成功時の固定製品page本文。失敗時の内容は使用しない。
 * @return 成功時は0、取得を開始または完了できない場合はnative error。
 */
using AsixProductPageReader =
	std::function<NativeError( ScanSessionId scanSessionId, std::wstring &html)> ;

/**
 * @brief 検証済み固定Terms page取得だけを差し替える内部試験境界。
 * @param[in] scanSessionId 製品pageと同じ0ではないscan session。
 * @param[out] html 成功時の固定Terms page本文。失敗時の内容は使用しない。
 * @return 成功時は0、取得を開始または完了できない場合はnative error。
 */
using AsixTermsPageReader =
	std::function<NativeError( ScanSessionId scanSessionId, std::wstring &html)> ;

/**
 * @brief 検証済み配布情報とlocal deviceから非機密の前回差分だけを返す境界。
 * @param[in] device 今回の候補に対応する非機密device snapshot。
 * @param[in] release ASIX parserが作成したworker内専用metadata。
 * @return 観測成立時の差分。未設定または一件でも検証できない場合は空。
 */
using AsixReleaseObservationEvaluator = std::function<std::optional<ReleaseObservationDifference>(
	const OfficialCatalogDevice &device, const OfficialReleaseRecord &release)> ;

/**
 * @brief Local device表示がASIX AX88179AのNet deviceに限定されるか確認する。
 * 通信要否だけを判定し、PnP適用性または最新版を保証しない。
 * @param[in] device 端末内だけで参照する非機密device snapshot。 端末内だけで参照する非機密snapshot。
 * @return Net class、ASIX表示、AX88179A tokenが全て一致する場合true。 Net class、ASIX表示、AX88179A tokenが一致する場合true。
 * @note 通信要否を決めるprobeであり、Hardware IDまたはpackage適用性の確認ではない。
 */
[[nodiscard]] bool		 isAsixAx88179aDevice( const OfficialCatalogDevice &device) noexcept ;

/**
 * @brief Local probeと固定page readerを使いASIX表示専用候補を作る。
 * 対象deviceがない場合は通信せず、URLを候補DTOへ渡さない。
 * @param[in] scanSessionId 0ではないscan session。 0ではない検索session。
 * @param[in] devices 最大4096件の非機密snapshot。
 * @param[in] windowsServer 実OSがWindows Serverの場合true。 実OSがServerの場合true。
 * @param[in] windowsBuild 実OSのmajor build番号。0は判定不能。
 * @param[in] reader Worker内で固定公式pageを取得する差替え境界。 固定公式pageの取得境界。
 * @param[in] progressCallback 確定した処理件数と進捗の通知先。 確定した進捗通知先。
 * @param[in] observationEvaluator 任意の端末内release観測評価境界。
 * @return 表示候補または対象外・通信失敗・metadata拒否。
 */
[[nodiscard]] ScanResult scanAsixAx88179aProductPage(
	ScanSessionId scanSessionId, std::span<const OfficialCatalogDevice> devices, bool windowsServer,
	std::uint32_t windowsBuild, const AsixProductPageReader &reader,
	const ProviderProgressCallback		  &progressCallback,
	const AsixReleaseObservationEvaluator &observationEvaluator = {}) ;

/**
 * @brief ASIXのTerms結合済み配布情報を一つの未承認取得対象へ変換する。
 * 公表概算sizeを予約量へ使わず、8 MiBと本文・前提確認を固定する。
 * @param[in] release Workerだけが所有する二page結合済み配布情報。 Worker内の二page結合済み配布情報。
 * @param[in] scanSessionId 配布情報を取得した検索session。
 * @param[in] planId Workerが発行した新しい計画ID。
 * @param[in] deviceCount 同じ配布物に関係するdevice数。1～4096。 同じ配布物に関係する1～4096件のdevice数。
 * @return 本文同意と取得前提確認が必要な一対象。不整合時は空。 全対象deviceを集約した未承認一対象。不整合時は空。
 */
[[nodiscard]] std::vector<OfficialPreparationTarget> makeAsixPreparationTargets(
	const OfficialReleaseRecord &release, ScanSessionId scanSessionId, std::uint64_t planId,
	std::uint32_t deviceCount) ;

/** @brief ASIX AX88179Aの固定公式pageを検索し、明示同意後の検査用取得を行うProvider。 */
class AsixUpdateProvider final : public IOfficialCatalogProvider {
public:
	/** @brief 取得根拠を持たないASIX Providerを作成する。 */
	AsixUpdateProvider() = default ;

	/**
	 * @brief 同じworkerのDriver Store rank監査境界を保持するASIX Providerを作成する。
	 * CallbackをProvider寿命へ固定する。未設定時は取得計画を発行しない。
	 * @param[in] rankAuditor 取得後にだけ使用するWindows標準PnP／rank監査callback。 同じworkerのDriver Store rank監査
	 *                   callback。
	 * @note Callbackが空の場合は取得計画を発行しない。
	 */
	explicit AsixUpdateProvider( OfficialInfRankAuditor rankAuditor) ;
	/**
	 * @brief ASIX監査・候補発行・指定導入に使うworker境界を固定する。
	 * 同じworkerのcallbackだけを所有し、構築時にはOS操作を行わない。
	 * @param[in] rankAuditor 内容合格後のWindows PnP／rank監査。 Windows PnP／rank監査境界。
	 * @param[in] binder 現在driverと対象nodeの固定境界。 現在driverとnodeの固定境界。
	 * @param[in] releaser 未commit／失効tokenの非throw破棄境界。 Tokenの非throw破棄境界。
	 * @param[in] installer 固定bindingによる再照合・指定導入境界。 Binding再検証と指定導入境界。
	 */
	AsixUpdateProvider( OfficialInfRankAuditor rankAuditor, OfficialInfInstallBinder binder,
					   OfficialInfInstallBindingReleaser releaser,
					   OfficialBoundInfInstaller		 installer) ;
	/**
	 * @brief 所有workerでroutingとtokenをINF閉包より先に解放する。
	 */
	~AsixUpdateProvider() override ;

	// OfficialHttpClientのsource sessionを単独所有するためcopy／moveを禁止する。
	/** @brief 公式source sessionの単独所有を保つためコピー構築を禁止します。 */
	AsixUpdateProvider( const AsixUpdateProvider &) = delete ;
	/** @brief 公式source sessionの単独所有を保つためコピー代入を禁止します。
	 * @return 削除された関数のため戻り値はありません。
	 */
	AsixUpdateProvider &operator=( const AsixUpdateProvider &) = delete ;
	/** @brief 公式source sessionのthread所有を保つため移動構築を禁止します。 */
	AsixUpdateProvider( AsixUpdateProvider &&) = delete ;
	/** @brief 公式source sessionのthread所有を保つため移動代入を禁止します。
	 * @return 削除された関数のため戻り値はありません。
	 */
	AsixUpdateProvider &operator=( AsixUpdateProvider &&) = delete ;

	/**
	 * @brief 今回scanへ使用する前回観測と現在環境fingerprintを設定する。
	 * Worker内へ所有copyを作り、ASIX live metadataとの差分だけへ使用する。
	 * @param[in] previous 現在OS／device構成へ事前照合済みの観測。最大4,096件。 現在環境へ事前照合済みの前回観測。
	 * @param[in] environment 現在OSとdevice集合の端末内fingerprint。
	 */
	void				configureReleaseObservationContext(
					   std::span<const LocalOfficialReleaseObservation> previous,
					   const OfficialReleaseEnvironmentFingerprints	   &environment) ;

	/**
	 * @brief 直前の成立したscanで生成した今回観測を参照する。
	 * Compositeのatomic統合保存だけが参照し、配布IDとHMACをUIへ渡さない。
	 * @return 次scanまたは明示失効まで有効な非所有span。 直前の成功scanで生成した観測の非所有span。
	 */
	[[nodiscard]] std::span<const LocalOfficialReleaseObservation> releaseObservations()
		const noexcept ;

	/**
	 * @brief 差替えreaderから二pageを同じscanへ結合し、取得準備snapshotを保持する。
	 * 両page確認後に観測・候補・完了進捗へ進み、失敗時は旧準備も失効する。
	 * @param[in] scanSessionId 0ではないscan session。 二pageに共通する0ではない検索session。
	 * @param[in] devices 外部送信しない現在device snapshot。 外部送信しないdevice snapshot。
	 * @param[in] windowsServer 実OSがWindows Serverの場合true。 実OSがServerの場合true。
	 * @param[in] windowsBuild 実OSのmajor build番号。0は判定不能。
	 * @param[in] productReader 固定製品pageの取得境界。 固定製品pageの同期取得境界。
	 * @param[in] termsReader 同じsource sessionに属する固定Terms pageの取得境界。 同じsource sessionの固定Terms取得境界。
	 * @param[in] progressCallback 確定済み段階の通知先。 確定した進捗通知先。
	 * @param[in] observationEvaluator Terms結合済みrecordを評価する任意の端末内境界。 Terms結合済みrecordの端末内評価境界。
	 * @return 二page結合が成立した表示候補またはProvider別失敗状態。
	 * @note Worker専用。Source evidenceの照合は実readerを接続する呼出し側が行う。
	 */
	[[nodiscard]] ScanResult scanWithPreparedPageReaders(
		ScanSessionId scanSessionId, std::span<const OfficialCatalogDevice> devices,
		bool windowsServer, std::uint32_t windowsBuild, const AsixProductPageReader &productReader,
		const AsixTermsPageReader &termsReader, const ProviderProgressCallback &progressCallback,
		const AsixReleaseObservationEvaluator &observationEvaluator = {}) ;

	/**
	 * @brief 同じscanで保持した配布情報から未承認の取得対象を返す。
	 * 旧scan、別thread、同じまたは小さいplan IDから対象を復活させない。
	 * @param[in] scanSessionId 有効な検索session。 計画を要求する検索session。
	 * @param[in] planId 同じProvider instanceで単調増加する計画ID。
	 * @return 全対象deviceを一配布物へ集約した一対象。不一致時は空。 保持情報と一致する一つの未承認対象。不一致時は空。
	 * @note Worker専用。旧session、別thread、同じまたは小さいplan IDを拒否する。
	 */
	[[nodiscard]] std::vector<OfficialPreparationTarget> preparationTargets(
		ScanSessionId scanSessionId, std::uint64_t planId) ;

	/**
	 * @brief 承認済みASIX配布物を同じscanで一回だけ検査用に取得する。
	 * 両pageを再確認し、一回だけ保護workspaceへ取得する。取得成功後だけ監査し、監査の拒否・失敗では確定済みの取得結果と実受信量を書き換えない。
	 * @param[in] task 共通workerが本文同意・前提確認を照合してclaimした対象。 Workerが本文同意・前提確認後にclaimした固定対象。
	 * @param[in] cancellation 空または協調取消し照会。取消しでも試行は消費する。
	 * @return 取得の終端状態。内容・署名・適用性監査や導入許可を含めない。 共通取得の終端状態、元診断値、実byte数。導入許可ではない。
	 * @note 同じworker thread、scan、plan、両pageの公式取得根拠を必須とする。
	 * @note 取得成功後の監査結果は別に保持し、この戻り値の取得成功を書き換えない。
	 */
	[[nodiscard]] OfficialPreparationTransferResult acquireForInspection(
		const OfficialPreparationTask &task, const PreparationCancellation &cancellation) ;

	/**
	 * @brief 同一scanのASIX取得後監査を既存候補行の非機密reportへ変換する。
	 * 取得成功と独立した監査結果を一回だけ表示と候補へ変換する。現在版は書き換えず、binding付きroutingを候補と同時に固定する。
	 * @param[in] scanSessionId 現在保持している検索session。
	 * @param[in] targetIdentity 承認済み取得計画内のopaque対象ID。
	 * @return 同じ取得成功対象の監査report。未取得・旧session・再照会はnullopt。 監査reportと未選択候補。不一致または再照会はnullopt。
	 * @note 監査合格時はbinding付き未選択候補を一回だけ発行する。
	 */
	[[nodiscard]] std::optional<OfficialPreparationAuditReport> preparationAuditReport(
		ScanSessionId scanSessionId, std::wstring_view targetIdentity) ;

	/**
	 * @brief 対象deviceがある場合だけ固定ASIX製品pageとTermsを取得する。
	 * 固定URLだけを取得し、取得根拠がない結果を成功として返さない。
	 * @param[in] scanSessionId 0ではないscan session。 0ではない検索session。
	 * @param[in] devices 外部送信しない現在device snapshot。 外部送信しないdevice snapshot。
	 * @param[in] hardwareIdMatcher 使用しない。公式pageにPnP ID対応表がない。 使用しないlocal照合関数。
	 * @param[in] progressCallback 確定済み段階の通知先。 確定した進捗通知先。
	 * @return 非選択・非推奨の公式配布情報。Payloadを取得しない。 表示候補またはProvider別失敗状態。
	 */
	[[nodiscard]] ScanResult	scan( ScanSessionId							scanSessionId,
									 std::span<const OfficialCatalogDevice> devices,
									 const LocalHardwareIdMatcher		   &hardwareIdMatcher,
									 const ProviderProgressCallback		   &progressCallback) override ;

	/**
	 * @brief 復旧保護後のASIX発行候補を再監査して指定INF導入へ渡す。
	 * 同一scanの公開候補だけを再検証し、成否・例外で保持物を失効する。
	 * @param[in] scanSessionId 候補を発行した現在session。
	 * @param[in] identities 利用者が選択したopaque候補ID。 明示選択された候補identity群。
	 * @param[in] parentWindowNative Windows導入dialogの親Window。 導入dialogの親Window値。
	 * @param[in] progressCallback 確定段階と候補処理の通知先。 確定段階の通知先。
	 * @return 保持物の再検証と導入を区別した個別結果。 再検証とinstallを分離した候補別の結果。
	 * @note 成否・例外で保持物を失効する。別threadでは状態を変更せず拒否する。
	 */
	[[nodiscard]] InstallResult install( ScanSessionId					scanSessionId,
										std::span<const std::wstring>	identities,
										std::uintptr_t					parentWindowNative,
										const ProviderProgressCallback &progressCallback) override ;

	/**
	 * @brief 保持中のsource session、配布情報、準備計画を同時に失効させる。
	 * 所有workerだけが旧取得根拠と計画を同時に破棄する。別threadは拒否する。
	 * @note 成功scanを保持している間は所有worker thread以外から状態を変更しない。
	 */
	void						invalidateScanSession() noexcept ;

private:
	/**
	 * @brief 固定製品pageを取得して新しい公式source sessionを開始する。
	 * Scanと取得直前再確認で同じ固定起点と用途を使用する。
	 * @param[in] session 今回のscan session。 今回の検索session。
	 * @param[out] html 成功時の製品page本文。失敗時は使用しない。
	 * @return 取得根拠を確認できた場合0。それ以外はnative error。 公式取得根拠が成立した場合0。それ以外はnative error。
	 */
	[[nodiscard]] NativeError readProductPage( ScanSessionId session, std::wstring &html) ;

	/**
	 * @brief 同じsource sessionで固定Termsを取得する。
	 * Sessionを再開始せず、製品pageの根拠を維持して固定Termsを取得する。
	 * @param[in] session 製品pageと同じscan session。 製品pageと同じ検索session。
	 * @param[out] html 成功時のTerms本文。失敗時は使用しない。
	 * @return 両pageの取得根拠を確認できた場合0。それ以外はnative error。 両pageの公式取得根拠が成立した場合0。それ以外はnative error。
	 */
	[[nodiscard]] NativeError readTermsPage( ScanSessionId session, std::wstring &html) ;

	/**
	 * @brief 新scanまたは失効時に監査閉包、取得物、検索snapshotの順で破棄する。Plan ID高水位と構築時callbackは維持する。
	 */
	void					  resetPreparedSnapshot() noexcept ;

	/// Workerが所有する固定pageの取得根拠。
	OfficialHttpClient		  httpClient_ ;
	/// 同じworker内のWindows標準PnP／rank監査。
	OfficialInfRankAuditor	  rankAuditor_ ;
	/// Compositeが現在環境へ照合済みの前回観測。Provider外またはnetworkへ渡さない。
	std::vector<LocalOfficialReleaseObservation> previousReleaseObservations_ ;
	/// 現在OS／device集合の端末内fingerprint。
	OfficialReleaseEnvironmentFingerprints		 observationEnvironment_ ;
	/// 直前の成功scanで生成し、Compositeが一括保存する今回観測。
	std::vector<LocalOfficialReleaseObservation> currentReleaseObservations_ ;
	/// 二page結合後にworkerだけが保持する配布情報。
	OfficialReleaseRecord						 retainedRelease_ ;
	/// 成功scanの候補順で保持し、取得後の候補identityとPnP監査対象を一対一に拘束する。
	std::vector<OfficialCatalogDevice>			 retainedDevices_ ;
	/// retainedDevices_と同じindexへ対応する、scan結果から複写したopaque候補identity。
	std::vector<std::wstring>					 retainedCandidateIdentities_ ;
	/// 保持情報の検索session。0は情報なし。
	ScanSessionId								 retainedSessionId_{} ;
	/// 一配布物に関係する表示候補数。PnP監査数ではない。
	std::uint32_t								 retainedDeviceCount_{} ;
	/// 検索時のclient build。取得直前の実OS照合に使う。
	std::uint32_t								 retainedWindowsBuild_{} ;
	/// 成功scanを保持するworker thread。0は未保持。
	std::uint32_t								 ownerThreadId_{} ;
	/// Instance寿命中に最後に発行した単調計画ID。
	std::uint64_t								 preparedPlanId_{} ;
	/// 同意fieldを含む直前計画対象。
	std::optional<OfficialPreparationTarget>	 preparedTarget_ ;
	/// 取消し・失敗を含め、一度受理した取得を再実行しない。
	bool										 acquisitionAttempted_{} ;
	/// 保護された取得fileの単独所有者。
	std::unique_ptr<OfficialDownloadWorkspace>	 workspace_ ;
	/// 一file限定の取得予算。
	std::unique_ptr<OfficialAcquisitionSession>	 acquisitionSession_ ;
	/// 内容監査と分離したworker内限定の取得結果。
	OfficialAcquisitionResult					 acquisition_ ;
	/// 取得成功と独立して保持する、署名済みINF閉包と端末内PnP／rank監査結果。
	OfficialDriverPackageAudit					 preparedAudit_ ;
	/// Windows nodeを一scanへ固定する境界。
	OfficialInfInstallBinder					 bindingCreator_ ;
	/// 非throwの個別token解放境界。
	OfficialInfInstallBindingReleaser			 bindingReleaser_ ;
	/// Binding再検証と指定導入境界。
	OfficialBoundInfInstaller					 boundInstaller_ ;
	/// 一回発行した候補IDとINF／bindingの対応。
	BoundPreparedInstallTargets					 installTargets_ ;
	/// Reportとroutingを一括発行済みの場合true。
	bool										 candidatesPublished_{} ;
	/// trueの場合は同じ対象の監査reportを再発行しない。
	bool										 auditReportResolved_{} ;
} ;

} // namespace drivercrate
