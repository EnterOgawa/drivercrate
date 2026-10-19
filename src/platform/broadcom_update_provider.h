//------------------------------------------------------------------------------
/**
 * @file broadcom_update_provider.h
 * @brief Broadcom NetXtreme-E公式配布情報Provider契約。
 * @version 01.00.01
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Broadcom監査reportを共通集約へ移行。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  共通INF導入executorへ型と処理を移設。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  前回release差分接続を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  導入再検証の共通executor契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査済みINFの導入契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの取得後監査を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  新規作成。
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
 * @note 検索と承認済みZIP取得の境界を持ち、取得を適用性や導入成功へ変換しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_driver_rank.h"
#include "core/official_preparation_operation.h"
#include "platform/broadcom_catalog_parser.h"
#include "platform/official_acquisition.h"
#include "platform/official_catalog_provider.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package_audit.h"
#include "platform/official_http_client.h"
#include "platform/official_prepared_install.h"
#include "platform/official_release_local_probe.h"
#include "platform/official_release_metadata.h"
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

/** @brief Broadcom互換名からProvider非依存のINF導入関数を参照する。 */
using BroadcomVerifiedInfInstaller = PreparedVerifiedInfInstaller ;

/** @brief Broadcom互換名からProvider非依存のINF閉包再検証関数を参照する。 */
using BroadcomInfReverifier = PreparedInfReverifier ;

/** @brief Broadcom互換名からProvider非依存の候補routingを参照する。 */
using BroadcomPreparedInstallTarget = PreparedInfInstallTarget ;

/** @brief Broadcom互換名からProvider非依存の非所有worker contextを参照する。 */
using BroadcomPreparedInstallContext = PreparedInfInstallContext ;

/**
 * @brief Broadcom固定policyで発行済み候補を共通INF導入executorへ渡す。
 * Broadcomの固定Provider／resourceだけを共通executorへ渡す薄いwrapper。Session保持物の失効は所有するProviderが結果確定後に行う。
 * @param[in] context 同じworker呼出し中だけ有効な取得物・閉包・routing。 同じworkerが所有する取得物・閉包・routing。
 * @param[in] identities 利用者が一device一候補で明示選択したopaque ID群。 明示選択された監査合格候補ID群。
 * @param[in] reverifier 本番では共通INF閉包再検証だけを渡す必須関数。 保持INF閉包の共通再検証。
 * @param[in] rankAuditor 現在PnP／rankを再取得する必須関数。 現在PnP／rankの再監査。
 * @param[in] installer 再検証合格INFだけを導入する必須関数。 再検証合格INFのWindows標準導入境界。
 * @param[in] parentWindowNative Windows導入dialogの親Window値。
 * @param[in] progressCallback 確定した外側file検証・候補処理の進捗通知先。 確定した処理段階の通知先。
 * @return downloadとinstallを分離した入力順の個別結果。 入力順の外側ZIP再検証、INF／rank再監査および導入結果。
 * @note Provider IDとpayload resourceは本wrapperが固定する。UI入力からsourceEvidenceConfirmed、policyまたはroutingを構
 *       成してはならない。
 * @note 本関数は保持物を解放しない。呼出し側が結果または例外の確定後にsessionを失効させる。
 */
[[nodiscard]] InstallResult executeBroadcomPreparedInstall(
	const BroadcomPreparedInstallContext &context, std::span<const std::wstring> identities,
	const BroadcomInfReverifier &reverifier, const OfficialInfRankAuditor &rankAuditor,
	const BroadcomVerifiedInfInstaller &installer, std::uintptr_t parentWindowNative,
	const ProviderProgressCallback &progressCallback) ;

/** @brief Path・ID・本文を含まない、取得後監査のworker内集計である。 */
struct BroadcomPreparedAuditSummary {
	/// 署名を含む内容監査の件数と結果。
	OfficialDriverPackageAuditSummary  content ;
	/// 同一scanのPnP／rank監査結果。
	OfficialDriverApplicabilitySummary applicability ;
} ;

/**
 * @brief 非機密device表示値がNetXtreme-E配布情報の参照対象か確認する。
 * 端末内のNet class・メーカー・系列表示名を照合する。N210TPへの適用保証には使わない。
 * @param[in] device 現在deviceの非機密snapshot。
 * @return Net classと審査済み系列表示名が一致すればtrue。 定義した検査に適合する場合true。不一致はfalse。
 * @note 表示専用の関連付けであり、adapter型番やPnP適用性の合格ではない。
 */
[[nodiscard]] bool broadcomNetxtremeEDevice( const OfficialCatalogDevice &device) noexcept ;

/**
 * @brief 検証済み配布metadataから非選択・非推奨の表示専用行を作る。
 * 配布情報だけの非選択・導入不可行を作る。配布版をINF版へ転用しない。
 * @param[in] session 0ではない有効なscan session ID。 0でない検索session。
 * @param[in] ordinal Session内で一意な候補連番。 表示候補の0始まり連番。
 * @param[in] device Local系列照合が成立したdevice。 現在deviceの非機密snapshot。
 * @param[in] release 当該scanで製品・document情報を結合済みのrecord。 製品record。出力時の部分値は呼出し側が失敗時に破棄する。
 * @return 内容／適用性監査待ちでinstallを禁止した表示DTO。 適用性・内容未監査の表示専用候補。
 * @note 呼出し側で取得元根拠を確認する。INF版、日付、byte数を推測しない。
 */
[[nodiscard]] UpdateCandidate makeBroadcomDiscoveryCandidate( ScanSessionId				  session,
															 std::size_t				  ordinal,
															 const OfficialCatalogDevice &device,
															 const BroadcomDriverRelease &release) ;

/**
 * @brief NetXtreme-Eの公開Windows配布情報だけを検索する組み込みProviderである。
 * @note 既定OFF。明示承認後に全監査合格候補だけをSetupAPI導入へ接続する。
 */
class BroadcomUpdateProvider  final : public IOfficialCatalogProvider {
public:
	 /** @brief 取得根拠とcallbackを既定状態で所有するProviderを構築します。 */
	 BroadcomUpdateProvider() = default ;
	 /**
	 * @brief 同じworkerのDriver Store適用性監査へ接続する。
	 * 監査callbackを保持する。未設定の場合は取得を導入可能と判定しない。
	 * @param[in] rankAuditor 所有するcallback。空なら適用性監査を拒否する。 同じworkerのDriver Store監査を所有するcallback。
	 */
	 explicit BroadcomUpdateProvider( OfficialInfRankAuditor rankAuditor) ;
	 /**
	 * @brief Driver Storeの監査と導入境界へ接続する。
	 * 二つの境界を同じworker所有Providerへ固定し、Networkへdevice情報を渡さない。
	 * @param[in] rankAuditor 現在PnPと候補INFのG11-D監査関数。 Driver Store内のPnP／rank監査callback。
	 * @param[in] installer 再検証済みINFのWindows標準導入関数。 再検証済みINFだけを導入するcallback。
	 */
	 BroadcomUpdateProvider( OfficialInfRankAuditor		 rankAuditor,
							BroadcomVerifiedInfInstaller installer) ;
	 /** @brief Providerの所有状態を破棄します。 */
	 ~BroadcomUpdateProvider() override = default ;

	 /**
	 * @brief 今回scanへ使用する前回観測と現在環境fingerprintを設定する。
	 * Worker内へ所有copyを作り、Broadcom live metadataとの差分だけへ使用する。
	 * @param[in] previous 現在OS／device構成へ事前照合済みの観測。最大4,096件。 現在環境へ事前照合済みの前回観測。
	 * @param[in] environment 現在OSとdevice集合の端末内fingerprint。
	 */
	 void configureReleaseObservationContext(
		 std::span<const LocalOfficialReleaseObservation> previous,
		 const OfficialReleaseEnvironmentFingerprints	 &environment) ;

	 /**
	 * @brief 直前の成立したscanで生成した今回観測を参照する。
	 * Compositeのatomic統合保存だけが参照し、HMACとhashをUIへ渡さない。
	 * @return 次scanまたは明示失効まで有効な非所有span。 直前の成功scanで生成した観測の非所有span。
	 */
	 [[nodiscard]] std::span<const LocalOfficialReleaseObservation> releaseObservations()
		 const noexcept ;

	 // Source sessionを単独所有するためcopy/moveを禁止する。
	 /** @brief 公式source sessionの単独所有を保つためコピー構築を禁止します。 */
	 BroadcomUpdateProvider( const BroadcomUpdateProvider &) = delete ;
	 /** @brief 公式source sessionの単独所有を保つためコピー代入を禁止します。
	 * @return 削除された関数のため戻り値はありません。
	 */
	 BroadcomUpdateProvider &operator=( const BroadcomUpdateProvider &) = delete ;
	 /** @brief 公式source sessionのthread所有を保つため移動構築を禁止します。 */
	 BroadcomUpdateProvider( BroadcomUpdateProvider &&) = delete ;
	 /** @brief 公式source sessionのthread所有を保つため移動代入を禁止します。
	 * @return 削除された関数のため戻り値はありません。
	 */
	 BroadcomUpdateProvider		&operator=( BroadcomUpdateProvider &&) = delete ;

	 /**
	 * @brief 対象系列が存在する場合だけ固定公開JSONを取得する。
	 * 固定公式JSONをworkerで同期取得する。表示候補と別に本文付き配布情報を保持し、scanではZIPを取得しない。
	 * @param[in] scanSessionId 0ではない操作内session ID。 検索または要求元のsession ID。
	 * @param[in] devices 最大4096件の現在device。 最大4096件の非機密device情報。
	 * @param[in] hardwareIdMatcher 未使用。配布情報だけでPnP IDを推測しない。 本検索では未使用のPnP照合境界。
	 * @param[in] progressCallback 実際に終了した段階の通知先。必須。 検索の確定段階通知先。直接install拒否時は呼ばない。
	 * @return 表示候補、対象外、候補なし、通信失敗、metadata拒否を区別した結果。 表示候補と検索結果。本文解析が未対応なら取得対象は発行しない。
	 */
	 [[nodiscard]] ScanResult	 scan( ScanSessionId							 scanSessionId,
									  std::span<const OfficialCatalogDevice> devices,
									  const LocalHardwareIdMatcher			&hardwareIdMatcher,
									  const ProviderProgressCallback		&progressCallback) override ;

	 /**
	 * @brief 明示選択した監査済み候補を再検証してWindows標準APIで導入する。
	 * Provider所有sessionと公式取得根拠を確認して共通executorへ渡し、結果または例外の確定後に保持物を失効させる。
	 * @param[in] scanSessionId 候補を発行した検索session ID。
	 * @param[in] identities UIへ発行済みのopaque候補ID群。 利用者が明示選択した監査合格候補ID群。
	 * @param[in] parentWindowNative Windows導入dialogの親Window値。
	 * @param[in] progressCallback 再検証と個別導入の確定進捗通知先。 外側ZIP再検証と候補別導入の確定進捗通知先。
	 * @return 外側取得物、INF、PnP／rankと個別導入を分離した結果。 入力順の再検証、downloadおよびinstall個別結果。
	 */
	 [[nodiscard]] InstallResult install( ScanSessionId					 scanSessionId,
										 std::span<const std::wstring>	 identities,
										 std::uintptr_t					 parentWindowNative,
										 const ProviderProgressCallback &progressCallback) override ;

	 /**
	 * @brief 同じscanの保持配布物から一対象を作り、後続task照合用に固定する。
	 * 旧session・取得済みへの対象再発行を拒否し、有効な計画だけを後続照合用に保存する。
	 * @param[in] scanSessionId 保持情報の検索session。 対象を発行する検索session。
	 * @param[in] planId workerが発行する新しい計画ID。 Workerの新しい計画ID。
	 * @return 一対象または空。取得試行後は新scanまで再発行しない。 現在の配布物を表す一対象または空。
	 */
	 [[nodiscard]] std::vector<OfficialPreparationTarget> preparationTargets(
		 ScanSessionId scanSessionId, std::uint64_t planId) ;

	 /**
	 * @brief workerがclaimした対象を公式再確認後に一度だけ取得する。
	 * 同じ配布物を一度だけ取得する。保持物は次scan開始またはinstall結果確定時に解放する。
	 * @param[in] task 承認済み計画の照合token。UIからURLを受け取らない。 Workerがclaimした一度限りの固定対象。
	 * @param[in] cancellation 協調取消し照会。空は取消し信号なし。 空または協調取消し照会。
	 * @return 検査用取得の結果。監査結果は別集計へ保持し、導入許可は発行しない。 検査用取得の結果。監査と導入の成功は含めない。
	 * @note 取得成功後に同期の内容・PnP監査を行う。取消しは監査の項目間で反映する。
	 */
	 [[nodiscard]] OfficialPreparationTransferResult acquireForInspection(
		 const OfficialPreparationTask &task, const PreparationCancellation &cancellation) ;

	 /**
	 * @brief 同一scanで取得後に実行した監査の集計だけを返す。
	 * 監査所有物をUIへ公開せず、現在workerで実行した集計だけを返す。
	 * @param[in] scanSessionId 保持している検索session。 保持監査の検索session。
	 * @return 内容・適用性の集計。旧sessionまたは未取得・未監査はnullopt。 非機密の内容・適用性集計。旧session・未監査はnullopt。
	 * @note Worker thread内専用。UIは専用reportを使用し、本集計自体を導入許可にしない。
	 */
	 [[nodiscard]] std::optional<BroadcomPreparedAuditSummary> preparationAuditSummary(
		 ScanSessionId scanSessionId) const ;

	 /**
	 * @brief 保持監査を同じ取得対象の非機密表示へ変換する。
	 * 全監査合格時だけ候補IDと保持INFのroutingを一度作る。未取得、旧session、別threadまたは再発行要求には候補を返さない。
	 * @param[in] scanSessionId 現在の検索session。
	 * @param[in] targetIdentity 承認した計画内のopaque対象ID。 承認した計画対象のopaque ID。
	 * @return 同じ取得成功対象のreport。旧session・別対象・未取得ならnullopt。 既存表示監査と新しい選択候補を持つ非機密report。不一致はnullopt。
	 */
	 [[nodiscard]] std::optional<OfficialPreparationAuditReport> preparationAuditReport(
		 ScanSessionId scanSessionId, std::wstring_view targetIdentity) ;

	 /**
	 * @brief Provider workerで保持配布情報と自分のworkspaceだけを解放し、次scanへ持ち越さない。
	 */
	 void invalidatePreparation() noexcept ;

private:
	 /**
	 * @brief 固定製品とdocumentを再確認し、同一配布物の共通recordを返す。
	 * 固定製品JSONと同じdocumentを再確認する。変更後の配布物へ承認を転用しない。
	 * @param[out] current 成功時の再取得metadata。失敗時は空。 成功時の再取得配布情報。
	 * @param[out] rejected 内容・根拠の不一致時true。通信失敗はfalse。 公式recordまたは根拠の不一致時true。
	 * @return 成功時0。失敗時は元の通信または検証HRESULT。
	 */
	 [[nodiscard]] NativeError			refreshPreparedRelease( OfficialReleaseRecord &current,
															   bool					 &rejected) ;
	 /// 同じworker内のWindows標準PnP／rank監査。
	 OfficialInfRankAuditor				rankAuditor_ ;
	 /// 再検証後だけ呼ぶWindows標準導入境界。
	 BroadcomVerifiedInfInstaller		installer_ ;
	 /// 同じscanで系列照合した非機密device群。
	 std::vector<OfficialCatalogDevice> retainedDevices_ ;
	 /// 署名済み閉包と適用性をworker内で単独所有する。
	 OfficialDriverPackageAudit			preparedAudit_ ;
	 /// 当該scanの公式metadata取得根拠を所有する。
	 OfficialHttpClient					httpClient_ ;
	 /// 選択した製品recordとdocumentの結合。
	 BroadcomDriverRelease				retainedDocument_ ;
	 /// URLと本文をworker内だけに保持する。
	 OfficialReleaseRecord				retainedRelease_ ;
	 /// Compositeが現在環境へ照合済みの前回観測。Provider外またはnetworkへ渡さない。
	 std::vector<LocalOfficialReleaseObservation>					 previousReleaseObservations_ ;
	 /// 現在OS／device集合の端末内fingerprint。
	 OfficialReleaseEnvironmentFingerprints							 observationEnvironment_ ;
	 /// 直前の成功scanで生成し、Compositeが一括保存する今回観測。
	 std::vector<LocalOfficialReleaseObservation>					 currentReleaseObservations_ ;
	 /// 0は検索情報なし。
	 ScanSessionId													 retainedSessionId_{} ;
	 /// 同一配布物に関係するdevice数。適用数ではない。
	 std::uint32_t													 retainedDeviceCount_{} ;
	 /// 最後に発行した計画ID。0は計画なし。
	 std::uint64_t													 preparedPlanId_{} ;
	 /// 承認との全field照合用snapshot。
	 std::optional<OfficialPreparationTarget>						 preparedTarget_ ;
	 /// trueなら新scanまで追加の取得taskを拒否する。
	 bool															 acquisitionAttempted_{} ;
	 /// trueなら監査済み候補とroutingを一度発行済み。
	 bool															 candidatesPublished_{} ;
	 /// UIへ発行した候補IDと保持中の監査済みINF／deviceを結ぶrouting表。
	 std::unordered_map<std::wstring, BroadcomPreparedInstallTarget> installTargets_ ;
	 /// 成功ZIPを次scanまで所有する保護領域。
	 std::unique_ptr<OfficialDownloadWorkspace>						 workspace_ ;
	 /// 一配布物の有限取得ledger。
	 std::unique_ptr<OfficialAcquisitionSession>					 acquisitionSession_ ;
	 /// 後続の内容監査用。Path・hashをUIへ渡さない。
	 OfficialAcquisitionResult										 acquisition_ ;
	 /// 現在の保持sessionを所有するworker thread ID。
	 std::uint32_t													 ownerThreadId_{} ;
} ;

/**
 * @brief 解析済みBroadcom配布物からURLを含まない未承認対象を作る。
 * 公開URLをUIへ渡さず、一配布物を同型device数だけ重複取得しない。
 * @param[in] release 公式由来を別途確認したworker所有record。 同一scanの公式配布情報。
 * @param[in] scanSessionId 0でない検索session。
 * @param[in] planId 0でない計画ID。
 * @param[in] deviceCount 関連device数。1～4096。 配布物に関係するdevice数。1～4096。
 * @return 本文付きの一対象。不完全recordは空。 未承認の一対象。不完全なrecordは空。
 */
[[nodiscard]] std::vector<OfficialPreparationTarget> makeBroadcomPreparationTargets(
	const OfficialReleaseRecord &release, ScanSessionId scanSessionId, std::uint64_t planId,
	std::uint32_t deviceCount) ;

/**
 * @brief Broadcomの同一scan取得物を内容監査と端末内PnP監査へ接続する。
 * 固定Net profileで監査し、署名合格INFだけを端末内で照合する。導入許可は発行しない。
 * @param[in] scanSessionId 保持deviceと取得結果に共通の検索session。
 * @param[in] acquisition 公式由来を確認し、workerが所有している取得結果。 同じworkerが所有する公式取得結果。
 * @param[in] expectedSha256 公開hash。未公開なら空。実測hashで代替記入しない。 公開hash。未公開は空。
 * @param[in] devices 同じscanで系列照合したdevice群。IDはnetworkへ渡さない。 同一scanで系列照合済みのdevice群。
 * @param[in] rankAuditor 同じworkerのDriver Store照合callback。 Windows標準PnP／rank監査。
 * @param[in] cancellation 空または協調取消し照会。
 * @param[out] audit 内容と適用性の独立した結果。導入候補は作らない。 内容・適用性の結果と単独所有閉包。
 * @return 全体処理成功時0。入力・内容・全体処理失敗時はHRESULT。 全体処理成功時0、拒否・失敗時はHRESULT。
 */
[[nodiscard]] NativeError auditBroadcomPreparedPackage(
	ScanSessionId scanSessionId, const OfficialAcquisitionResult &acquisition,
	std::wstring_view expectedSha256, std::span<const OfficialCatalogDevice> devices,
	const OfficialInfRankAuditor &rankAuditor, const PreparationCancellation &cancellation,
	OfficialDriverPackageAudit &audit) ;

/**
 * @brief Broadcom監査集計を既存表示行へ変換する。導入権限を付加しない。
 * Broadcom対象系列と既存候補IDを確定してから、固定profileの共通helperへ集約を委譲する。候補発行と導入routingは変更しない。
 * @param[in] session 保持している0でない検索session。 検索時の有効session。
 * @param[in] targetIdentity 取得を承認済みのopaque計画対象ID。 同じ取得対象のopaque ID。
 * @param[in] devices 検索時と同じ順序の系列照合device。最大4096件。 検索時と同じ順序の非機密snapshot。
 * @param[in] audit 同じ取得物の内容・PnP監査結果。所有物は参照中のみ利用する。 保持物の監査結果。Path等は出力しない。
 * @return 非機密report。不正な件数または入力には例外で全体拒否する。 既存候補の表示用report。不正入力は例外。
 * @note Broadcom対象と既存候補IDを確定後に共通集約へ委譲し、表示状態だけを生成する。
 */
[[nodiscard]] OfficialPreparationAuditReport makeBroadcomPreparationAuditReport(
	ScanSessionId session, std::wstring_view targetIdentity,
	std::span<const OfficialCatalogDevice> devices, const OfficialDriverPackageAudit &audit) ;

/**
 * @brief Broadcom監査合格INF／device組合せを明示版付き候補へ変換する。
 * INFの明示値だけを表示へ渡し、候補を推奨または初期選択へ昇格しない。
 * @param[in] session 同じ取得・監査を所有する0でないscan session。 取得・監査と同じ検索session。
 * @param[in] acquisition 同じ公式取得層が固定したsize／hashとopaque取得identity。 共通取得層が固定した外側ZIPのidentity。
 * @param[in] devices 検索時と同じ非機密device snapshot群。
 * @param[in] audit 内容・PnP／rank監査済みの保持結果。 内容・PnP／rank監査結果と保持閉包。
 * @return 同device／同版を重複排除した、初期未選択の全監査合格候補。 同device／同版を重複排除した全監査合格候補。
 * @throws std::logic_error 同一scan、取得identityまたは監査保持構造が矛盾する場合。
 * @note INFのversion／dateだけを使用し、Web配布版やURLから値を推測しない。
 */
[[nodiscard]] std::vector<UpdateCandidate> makeBroadcomPreparedCandidates(
	ScanSessionId session, const OfficialAcquisitionResult &acquisition,
	std::span<const OfficialCatalogDevice> devices, const OfficialDriverPackageAudit &audit) ;

} // namespace drivercrate
