//------------------------------------------------------------------------------
/**
 * @file official_release_discovery_provider.h
 * @brief 共通公式検索と限定系列の取得・監査・指定導入契約。
 * @version 01.00.03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  Read-only live検索の非cache構築を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel監査reportを共通集約へ移行。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  File責務を指定INF導入まで更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel指定導入のOS・session拘束を明示。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel指定導入adapterの試験境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel候補公開の決定的試験境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel Ethernet指定導入境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Driver Store bindingと保持routing境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得後監査契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Rank監査と検索行対応の保持境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  取得成功後の監査結果を独立保持。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  非機密監査reportの取得境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  前回release差分接続を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得計画とworker実行を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報と検索接続を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  共通metadata計測根拠を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.00.02 Shunji Ogawa  2026/10/13  観測field説明を完全な宣言開始前へ配置。
 * Ver.01.00.03   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 初回検索行は表示専用です。Intel Ethernetだけは承認後の取得・監査・候補発行を行います。取得後監査をProvider内へ保持し、既存行、候補発行状態と未選択候補を返します
 *       。Intel Ethernetだけは監査合格後の保持bindingを指定導入境界へ接続します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_preparation_operation.h"
#include "core/scan_measurement.h"
#include "platform/official_acquisition.h"
#include "platform/official_bound_preparation.h"
#include "platform/official_catalog_provider.h"
#include "platform/official_driver_package_audit.h"
#include "platform/official_inf_install_binding.h"
#include "platform/official_prepared_install.h"
#include "platform/official_release_local_probe.h"
#include "platform/official_release_metadata.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace drivercrate {
/**
 * @brief Metadata取得だけを差し替える内部試験境界。成功時は指定familyの解析済み情報を返す。
 */
using OfficialReleaseMetadataReader = std::function<NativeError(
	OfficialReleaseFamily, ScanSessionId, OfficialReleaseRecord &, bool &)> ;

/**
 * @brief Live metadataとlocal bindingを結合し、UIへ渡せる差分だけを返す内部試験境界。
 */
using OfficialReleaseObservationEvaluator =
	std::function<std::optional<ReleaseObservationDifference>( const OfficialCatalogDevice &,
															  const OfficialReleaseRecord &)> ;

/** @brief Intelの既存契約名を共通binding付き型へ対応付ける。 */
using IntelEthernetPreparedInstallTarget = BoundPreparedInstallTarget ;
/** @brief Intel候補のrouting型。既存呼出側の契約名を維持する。 */
using IntelEthernetPreparedInstallTargets = BoundPreparedInstallTargets ;
/** @brief Intel導入context。固定profileは専用wrapperが選択する。 */
using IntelEthernetPreparedInstallContext = BoundPreparedInstallContext ;

/**
 * @brief Intel Ethernet保持routingを共通再監査と指定device導入へ接続する。
 * Intel固有routingを共通executor用に検証し、選択候補を一つの保持bindingへ解決する。保持物の失効は呼出し側が全終端で行う。
 * @param[in] context Provider workerが呼出し中だけ所有する取得物、監査閉包およびrouting。 Provider所有の取得物、監査閉包およびbinding
 *                   routing。
 * @param[in] identities 利用者が選択した発行済み候補ID群。
 * @param[in] reverifier 外側hash確認後にINF閉包を再検証するcallback。 INF閉包の再検証callback。
 * @param[in] rankAuditor 指定deviceとINFの現在PnP／rankを再監査するcallback。 現在PnP／rankの再監査callback。
 * @param[in] boundInstaller 保持bindingで指定deviceへ導入するcallback。 保持bindingによる指定device導入callback。
 * @param[in] parentWindowNative Windows導入dialogの親Window値。
 * @param[in] progressCallback 確定済み段階と候補数を通知するcallback。 確定済み段階と候補数の通知先。
 * @return Downloadとinstallを分離した入力順の個別結果。
 * @note 本関数はrouting、binding、取得物を失効させない。Providerが全終端で破棄する。
 */
[[nodiscard]] InstallResult executeIntelEthernetPreparedInstall(
	const IntelEthernetPreparedInstallContext &context, std::span<const std::wstring> identities,
	const PreparedInfReverifier &reverifier, const OfficialInfRankAuditor &rankAuditor,
	const OfficialBoundInfInstaller &boundInstaller, std::uintptr_t parentWindowNative,
	const ProviderProgressCallback &progressCallback) ;

/**
 * @brief Local系列照合と一回のmetadata検索で表示専用行を作る。
 * 対象なしでは通信しない。同型deviceを一台へ集約せず、payload取得、適用性判定、導入を行わない。
 * @param[in] family 組み込み検索系列。 共通検索の組み込み系列。
 * @param[in] session 0ではないscan session。 0ではない検索session。
 * @param[in] devices 最大4096件の非機密snapshot。同型でもidentityは個別。
 * @param[in] windowsServer 実OSがServerならtrue。系列別OS境界に使用する。 実OSがServerの場合true。
 * @param[in] reader Worker内の取得境界。成功時には当該sessionの公式取得根拠を要求する。 同sessionの公式根拠を要求するmetadata取得境界。
 * @param[in] progress 実際に終了した段階を通知する関数。 確定した進捗の通知先。
 * @param[in] windowsBuild 実OSのmajor build番号。client系列では使用せず、既定値は0。 実OSのmajor build。0は不明。
 * @param[in] observationEvaluator 今回観測と前回差分を返す任意callback。
 * @param[out] measurementEvidence 指定時は同じsessionの対象・query・record根拠。失敗時も段階を保持する。
 * @param[in,out] execution 指定時は専用情報検索。Package identityと観測保存を生成しない。
 * @return 配布情報の表示行または対象外・通信失敗・metadata拒否。 表示候補または対象外・通信失敗・metadata拒否。
 * @note 内部の差替え境界であり、readerをUI／pluginから登録しない。
 */
[[nodiscard]] ScanResult scanOfficialReleaseMetadata(
	OfficialReleaseFamily family, ScanSessionId session,
	std::span<const OfficialCatalogDevice> devices, bool windowsServer,
	const OfficialReleaseMetadataReader &reader, const ProviderProgressCallback &progress,
	std::uint32_t							   windowsBuild			= 0U,
	const OfficialReleaseObservationEvaluator &observationEvaluator = {},
	ProviderMeasurementEvidence				  *measurementEvidence	= nullptr,
	MetadataSearchExecutionContext			  *execution			= nullptr) ;

/**
 * @brief 専用HTTPを一回の呼出し内だけ所有し、準備状態を保持せず情報検索する。
 * @param[in] family 固定した審査済み系列。
 * @param[in] session Contextと一致するsession。
 * @param[in] devices 最大4096件の現在属性だけのsnapshot。
 * @param[in] windowsServer Workerが固定した実OS区分。
 * @param[in] windowsBuild Workerが固定した実OS build。
 * @param[in,out] execution 同期呼出し中だけ借用する専用予算。
 * @param[in] progress 確定進捗の通知先。
 * @param[out] evidence 同じ呼出し内のT/Q/RとURLなし取得根拠。
 * @return 全行表示専用の結果。部分停止でも確定行を保持する。
 * @note 通常Provider scan、準備plan、取得、rank、snapshot保存を呼ばない。
 */
[[nodiscard]] ScanResult			   scanOfficialMetadataOnly( OfficialReleaseFamily				   family,
																ScanSessionId						   session,
																std::span<const OfficialCatalogDevice> devices,
																bool windowsServer, std::uint32_t windowsBuild,
																MetadataSearchExecutionContext &execution,
																const ProviderProgressCallback &progress,
																ProviderMeasurementEvidence	   &evidence) ;

/** @brief 固定pageの解析結果だけを既存catalog interfaceへ接続する。 */
class OfficialReleaseDiscoveryProvider final : public IOfficialCatalogProvider {
public:
	/**
	 * @brief 検索系列を固定し、取得後rank callbackを持たないProviderを作る。
	 * Source sessionを作らず、検索系列だけを固定する。監査callbackは空にする。
	 * @param[in] family 組み込み系列。変更せず、未知値はscan時に拒否する。 Instanceの検索系列。
	 */
	explicit OfficialReleaseDiscoveryProvider( OfficialReleaseFamily family) noexcept ;

	/**
	 * @brief 検索系列と取得後の端末内PnP／rank監査境界を固定する。
	 * Callbackを外部登録可能にせず、Composite構築時のDriver Store境界へ固定する。
	 * @param[in] family 組み込み系列。Intel Ethernet以外へ監査能力を波及させない。 Instanceの検索系列。
	 * @param[in] rankAuditor 所有するDriver Store監査callback。空なら後続監査を拒否する。 Worker内で所有する端末内PnP／rank監査
	 *                   callback。
	 */
	OfficialReleaseDiscoveryProvider( OfficialReleaseFamily	family,
									 OfficialInfRankAuditor rankAuditor) noexcept ;

	/**
	 * @brief Intel Ethernetの監査、binding発行、破棄および指定導入境界を固定する。
	 * 全境界をComposite構築時のDriver Storeへ固定し、device情報をnetworkへ渡さない。falseは明示実行するread-only live検証だけが指定する。
	 * @param[in] family 組み込み系列。Intel Ethernet以外へ導入準備能力を波及させない。 Instanceの検索系列。
	 * @param[in] rankAuditor 所有するDriver Store監査callback。 Worker内のPnP／rank監査callback。
	 * @param[in] bindingCreator 監査合格INFをWindows nodeへ拘束するcallback。 一意なWindows nodeのbinding発行
	 *                   callback。
	 * @param[in] bindingReleaser 未発行または失効候補のtokenを個別破棄するcallback。 未使用tokenの個別破棄callback。
	 * @param[in] boundInstaller Bindingを再検証してstaging・指定導入するcallback。 Bindingを再検証する指定導入callback。
	 * @param[in] useCatalogCache trueなら通常の公式catalog cacheを利用する。
	 * @note 空callbackでは選択候補を発行せず、取得後監査reportだけを返す。
	 */
	OfficialReleaseDiscoveryProvider( OfficialReleaseFamily			   family,
									 OfficialInfRankAuditor			   rankAuditor,
									 OfficialInfInstallBinder		   bindingCreator,
									 OfficialInfInstallBindingReleaser bindingReleaser,
									 OfficialBoundInfInstaller		   boundInstaller,
									 bool useCatalogCache = true) noexcept ;
	/** @brief Workerが所有する取得fileと公式HTTP根拠を解放する。 */
	~OfficialReleaseDiscoveryProvider() override ;

	/**
	 * @brief 今回scanへ使用する前回観測と現在環境fingerprintを設定する。
	 * Worker内へ所有copyを作り、次scanの差分評価だけへ使用する。Fingerprintと観測をnetworkまたはUIへ渡さない。
	 * @param[in] previous 現在OS／device構成へ事前照合済みの観測。最大4,096件。 現在環境へ事前照合済みの前回観測。
	 * @param[in] environment 現在OSとdevice集合の端末内fingerprint。
	 * @note 設定値はworker内へcopyし、network requestまたはUIへ渡さない。
	 */
	void configureReleaseObservationContext(
		std::span<const LocalOfficialReleaseObservation> previous,
		const OfficialReleaseEnvironmentFingerprints	&environment) ;

	/**
	 * @brief 直前の成立したscanで生成した今回観測を参照する。
	 * Compositeのatomic統合保存に限って参照し、UIまたはlogへ渡さない。
	 * @return 次scanまたは明示失効まで有効な非所有span。 直前の成功scanで生成した観測の非所有span。
	 */
	[[nodiscard]] std::span<const LocalOfficialReleaseObservation> releaseObservations()
		const noexcept ;

	/**
	 * @brief 直前の共通公式metadata検索で得た対象・情報record根拠を取得する。
	 * @return Provider所有のworker内根拠への参照。次の失効まで有効である。
	 */
	[[nodiscard]] const ProviderMeasurementEvidence		&measurementEvidence() const noexcept ;

	/**
	 * @brief 同じscanで保持した配布情報から未承認の取得対象を返す。
	 * 旧scanや失効済み情報から新しい取得対象を復活させない。
	 * @param[in] scanSessionId 有効な検索session。 計画を要求する検索session。
	 * @param[in] planId 新しい計画のID。 workerが発行した新計画ID。
	 * @return 一配布物の対象または空。Intel Ethernetは本文同意と取得前提確認を必須とする。 保持情報と一致する未承認対象または空。
	 * @note Worker専用。Wi-Fiは従来どおり未解決で取得不可。旧計画や再取得は拒否する。
	 */
	[[nodiscard]] std::vector<OfficialPreparationTarget> preparationTargets(
		ScanSessionId scanSessionId, std::uint64_t planId) ;

	/**
	 * @brief 承認済みIntel Ethernet ZIPを一回だけ検査用に取得する。
	 * 同一thread・scan・plan・対象と実OSを確認し、一配布物を有限量だけ取得する。取得成功時だけ監査し、その拒否・取消し・例外で取得結果を書き換えない。自動retryせず、次
	 * scanまで取得結果と監査結果をworker内で別々に所有する。
	 * @param[in] task Workerがclaimした固定対象。任意URLや未承認tokenを受け付けない。 Workerが承認sessionでclaimした今回の固定対象。
	 * @param[in] cancellation 空または協調取消し照会。導入処理は呼ばない。
	 * @return 再確認と共通取得の終端状態。内容監査・適用性・導入結果を含めない。 取得終端状態、診断値、byte数。監査合格・導入許可は含めない。
	 * @note 同一worker／scan限定。呼出し元が前提確認と許諾同意を検証してからclaimする。
	 */
	[[nodiscard]] OfficialPreparationTransferResult acquireForInspection(
		const OfficialPreparationTask &task, const PreparationCancellation &cancellation) ;

	/**
	 * @brief 保持監査を同じ取得対象と既存候補行の非機密表示へ変換する。
	 * 全監査合格組合せを現在deviceとWindows nodeへ再拘束し、未選択候補とworker内routingを同時に一度だけcommitする。個別binding失敗は当該組合せだけを
	 * 除外し、構造矛盾では全新規候補を破棄する。
	 * @param[in] scanSessionId 現在保持している検索session。
	 * @param[in] targetIdentity 承認済み取得計画内のopaque対象ID。
	 * @return 同じ取得成功対象の監査report。未取得・旧session・別対象はnullopt。 既存監査行、候補発行状態および発行候補。不一致はnullopt。
	 * @note 全監査合格時だけ候補とroutingを一括発行し、同じ対象への再発行を拒否する。
	 */
	[[nodiscard]] std::optional<OfficialPreparationAuditReport> preparationAuditReport(
		ScanSessionId scanSessionId, std::wstring_view targetIdentity) ;

	/**
	 * @brief HTTPの検索根拠と配布情報を同時に失効させ、他の操作へ引き継がない。
	 */
	void invalidatePreparation() noexcept ;

	// 公式source sessionの所有権を複製しない。
	/** @brief 公式source sessionの単独所有を保つためコピー構築を禁止します。 */
	OfficialReleaseDiscoveryProvider( const OfficialReleaseDiscoveryProvider &) = delete ;
	/** @brief 公式source sessionの単独所有を保つためコピー代入を禁止します。
	 * @return 削除された関数のため戻り値はありません。
	 */
	OfficialReleaseDiscoveryProvider &operator=( const OfficialReleaseDiscoveryProvider &) = delete ;
	/** @brief 公式source sessionのthread所有を保つため移動構築を禁止します。 */
	OfficialReleaseDiscoveryProvider( OfficialReleaseDiscoveryProvider &&) = delete ;
	/** @brief 公式source sessionのthread所有を保つため移動代入を禁止します。
	 * @return 削除された関数のため戻り値はありません。
	 */
	OfficialReleaseDiscoveryProvider &operator=( OfficialReleaseDiscoveryProvider &&) = delete ;

	/**
	 * @brief 対象deviceがある場合だけ公式metadataを取得する。
	 * 実OSを確認し、公式HTTPだけをreaderとしてworkerで接続する。Intel Ethernetの成立結果は、取得後監査のため候補順のdevice対応をworker内へ保持する。
	 * @param[in] scanSessionId 0ではないsession。 当該検索session。
	 * @param[in] devices 外部送信しない現在device snapshot。 現在deviceの非機密snapshot。
	 * @param[in] hardwareIdMatcher 未使用。配布pageにPnP IDはない。 未使用。PageにPnP IDはない。
	 * @param[in] progressCallback 確定済み段階の通知先。 確定済み進捗の通知先。
	 * @return 非選択・非推奨の表示情報。Payloadを取得しない。 共通の表示専用検索結果。
	 */
	[[nodiscard]] ScanResult		  scan( ScanSessionId						  scanSessionId,
										   std::span<const OfficialCatalogDevice> devices,
										   const LocalHardwareIdMatcher			 &hardwareIdMatcher,
										   const ProviderProgressCallback		 &progressCallback) override ;

	/**
	 * @brief Intel Ethernetの公開済み監査合格候補を指定deviceへ導入する。
	 * Intel Server 2025の公開済み候補だけを共通executorへ渡す。保持bindingは候補とINFの完全一致で専用導入境界へ解決し、成否または例外の確定後に全保持物を失効
	 * させる。
	 * @param[in] scanSessionId 候補を発行した現在scan session。 候補を発行した現在session。
	 * @param[in] identities 利用者が明示選択した候補ID群。 利用者が選択した候補ID群。
	 * @param[in] parentWindowNative Windows導入dialogの親Window値。 Installer親HWNDの整数表現。
	 * @param[in] progressCallback 外側file再検証と候補処理の確定進捗通知先。 外側file再検証と候補処理の進捗通知先。
	 * @return Downloadとinstallを分離した入力順の個別結果。
	 * @note 対象外系列、未公開候補、旧sessionおよび不完全な保持物はfail-closedで拒否する。
	 */
	[[nodiscard]] InstallResult		  install( ScanSessionId					  scanSessionId,
											  std::span<const std::wstring>	  identities,
											  std::uintptr_t				  parentWindowNative,
											  const ProviderProgressCallback &progressCallback) override ;

private:
	/**
	 * @brief 次scanやinstall開始時に監査閉包、取得物、検索行対応の順で解放する。前回release観測の設定は維持する。
	 */
	void										 resetPreparedDownload() noexcept ;

	/// Instance寿命中の検索系列。
	const OfficialReleaseFamily					 family_ ;
	/// Worker内で所有する端末内PnP／rank監査境界。
	OfficialInfRankAuditor						 rankAuditor_ ;
	/// 一意なWindows nodeのbinding発行境界。
	OfficialInfInstallBinder					 bindingCreator_ ;
	/// 未使用tokenの個別破棄境界。
	OfficialInfInstallBindingReleaser			 bindingReleaser_ ;
	/// Binding再検証・staging・指定device導入境界。
	OfficialBoundInfInstaller					 boundInstaller_ ;
	/// Workerが所有する当該scanのsource取得根拠。
	OfficialHttpClient							 http_ ;
	/// 次scan／install開始までworkerだけが保持する情報。
	OfficialReleaseRecord						 retainedRelease_ ;
	/// Intel Ethernetの検索候補順に保持する、Hardware IDを含まないdevice snapshot。
	std::vector<OfficialCatalogDevice>			 retainedDevices_ ;
	/// `retainedDevices_`と同じindexに対応する、表示済みopaque candidate ID。
	std::vector<std::wstring>					 retainedCandidateIdentities_ ;
	/// Compositeが現在環境へ照合済みの前回観測。Provider外またはnetworkへ渡さない。
	std::vector<LocalOfficialReleaseObservation> previousReleaseObservations_ ;
	/// 現在OS／device集合の端末内fingerprint。
	OfficialReleaseEnvironmentFingerprints		 observationEnvironment_ ;
	/// 直前の成功scanで生成し、Compositeが一括保存する今回観測。
	std::vector<LocalOfficialReleaseObservation> currentReleaseObservations_ ;
	/// 共通検索の対象・query・record根拠。
	ProviderMeasurementEvidence					 measurementEvidence_ ;
	/// 保持情報の検索session。0は情報なし。
	ScanSessionId								 retainedSessionId_{} ;
	/// 同じ配布情報に関係したdevice数。PnP判定数ではない。
	std::uint32_t								 retainedDeviceCount_{} ;
	/// 成功scanを保持するworker thread。0は未保持。
	std::uint32_t								 ownerThreadId_{} ;
	/// 同じscanで最後に発行した計画ID。0は未計画。
	std::uint64_t								 preparedPlanId_{} ;
	/// 全同意fieldを照合する固定対象。
	std::optional<OfficialPreparationTarget>	 preparedTarget_ ;
	/// 失敗・取消しも含め、一度開始したら再取得しない。
	bool										 acquisitionAttempted_{} ;
	/// 取得fileを所有する保護領域。
	std::unique_ptr<OfficialDownloadWorkspace>	 workspace_ ;
	/// 一file限定の取得ledger。
	std::unique_ptr<OfficialAcquisitionSession>	 acquisitionSession_ ;
	/// 監査結果と分離したworker専用の取得結果。
	OfficialAcquisitionResult					 acquisition_ ;
	/// 取得成功と独立して保持する、署名済みINF閉包と端末内PnP／rank監査結果。
	OfficialDriverPackageAudit					 preparedAudit_ ;
	/// 発行候補IDから保持INFとDriver Store tokenへ解決するworker内限定routing。
	IntelEthernetPreparedInstallTargets			 installTargets_ ;
	/// trueの場合は同じ取得対象へ候補を再発行しない。
	bool										 candidatesPublished_{} ;
	/// trueの場合は候補0件を含むreportを再発行しない。
	bool										 publicationResolved_{} ;
} ;

/**
 * @brief 解析済みIntel metadataを非機密の未承認対象へ変換する。
 * Ethernetは許諾全文と取得前提確認を要求し、Wi-Fiは未解決のまま保持する。
 * @param[in] release workerだけが所有する解析情報。公式由来の根拠は呼出し側が保持する。 worker内の解析済み配布情報。
 * @param[in] scanSessionId 情報を取得した検索session。 配布情報の検索session。
 * @param[in] planId workerが発行した新計画ID。 新計画の単調ID。
 * @param[in] deviceCount 同じ配布物に関係するdevice数。1～4096。 同じ配布情報に関係する1～4096件のdevice数。
 * @return 一対象または空。Ethernetは取得前提確認を要求し、Wi-FiはUnresolvedを維持する。 Intel Wi-FiまたはEthernetの未承認一対象。未結合は空。
 */
[[nodiscard]] std::vector<OfficialPreparationTarget> makeReleasePreparationTargets(
	const OfficialReleaseRecord &release, ScanSessionId scanSessionId, std::uint64_t planId,
	std::uint32_t deviceCount) ;

/**
 * @brief Intel Ethernetの同一scan取得物を内容監査と端末内PnP監査へ接続する。
 * Server 2025向け固定Net profileで全INFを監査し、署名合格INFだけを端末内で照合する。製品名一致だけでは適用や導入を許可しない。
 * @param[in] scanSessionId 保持deviceと取得結果に共通の検索session。
 * @param[in] acquisition 公式由来と公開hashを確認し、workerが所有する取得結果。 同じworkerが所有する公開hash確認済み取得結果。
 * @param[in] expectedSha256 公式metadataの公開SHA-256。空または実測値の代用を拒否する。 公式metadataに掲載された公開SHA-256。
 * @param[in] devices 同じscanでIntel Ethernet系列へ照合したdevice群。 同一scanで系列照合済みのdevice群。
 * @param[in] rankAuditor 同じworkerのDriver Store照合callback。 Windows標準PnP／rank監査。
 * @param[in] cancellation 空または協調取消し照会。
 * @param[out] audit 内容と適用性の独立した結果。導入候補は作らない。 内容・適用性の結果と単独所有閉包。
 * @return 全体処理成功時0。入力・内容・全体処理失敗時はHRESULT。 全体処理成功時0、拒否・失敗時はHRESULT。
 * @note 製品名は対象範囲の事前確認に限り、適用性はPnP／rank監査を正本とする。
 */
[[nodiscard]] NativeError auditIntelEthernetPreparedPackage(
	ScanSessionId scanSessionId, const OfficialAcquisitionResult &acquisition,
	std::wstring_view expectedSha256, std::span<const OfficialCatalogDevice> devices,
	const OfficialInfRankAuditor &rankAuditor, const PreparationCancellation &cancellation,
	OfficialDriverPackageAudit &audit) ;

/**
 * @brief Intel Ethernet監査を検索時の既存候補行へ反映する非機密reportを作る。
 * Intel対象系列と既知非対応OEMだけを確認してから、固定profileの共通helperへ集約を委譲する。候補発行とinstall準備状態の昇格は行わない。
 * @param[in] session 保持している0ではない検索session。 監査対象を取得した検索session。
 * @param[in] targetIdentity 利用者が取得を承認したopaque対象ID。
 * @param[in] devices 検索候補順に保持した非機密device snapshot。 検索候補順の非機密device snapshot。
 * @param[in] candidateIdentities devicesと同じ順序の既存opaque候補ID。 devicesと同じ順序の既存候補ID。
 * @param[in] audit 同じ取得物の内容・PnP／rank監査結果。 同一取得物の内容・PnP／rank監査結果。
 * @return 既存候補の監査fieldを持つ、候補発行前の非機密report。 既存行の監査fieldだけを更新する非機密report。
 * @throws std::logic_error session、件数、identityまたは監査保持構造が矛盾する場合。
 * @note Intel対象確認後に共通集約へ委譲する。候補追加はProvider methodが別に実行する。
 */
[[nodiscard]] OfficialPreparationAuditReport makeIntelEthernetPreparationAuditReport(
	ScanSessionId session, std::wstring_view targetIdentity,
	std::span<const OfficialCatalogDevice> devices,
	std::span<const std::wstring> candidateIdentities, const OfficialDriverPackageAudit &audit) ;

/**
 * @brief Intel Ethernet監査合格組合せから候補と導入routingを同時に構成する。
 * 個別の版不明、既知非対応、重複、binding失敗は除外する。構造矛盾では今回発行した全tokenと候補を破棄し、例外をworker境界へ漏らさない。
 * @param[in] session 候補を発行する0ではない検索session。 候補を発行する検索session。
 * @param[in] acquisitionId 同じ取得成功物の0ではないopaque ID。 検証済み外側取得物のopaque ID。
 * @param[in] maximumDownloadBytes 検証済み外側取得物のbyte数。1以上。
 * @param[in] devices 同じscanで保持する一意な非機密device snapshot。 同じscanで保持する非機密device snapshot。
 * @param[in] audit 内容とPnP／rank監査に合格した保持構造。
 * @param[in] bindingCreator 一意なWindows nodeのbindingを発行するcallback。 Windows nodeのbinding発行callback。
 * @param[in] bindingReleaser 未commit tokenを個別破棄するcallback。 未commit tokenの破棄callback。
 * @param[in,out] report 候補発行前の合格report。発行結果と候補を反映する。 合格reportへ発行集計と候補を反映する。
 * @param[out] installTargets 全件成功時だけ候補ID別routingを返す。失敗時は空。 成功時だけ返す候補ID別routing。
 * @note 個別の版不明、既知非対応、重複、binding失敗は除外し、構造矛盾では全件破棄する。
 */
void publishIntelEthernetPreparedCandidates(
	ScanSessionId session, std::uint64_t acquisitionId, std::uint64_t maximumDownloadBytes,
	std::span<const OfficialCatalogDevice> devices, const OfficialDriverPackageAudit &audit,
	const OfficialInfInstallBinder			&bindingCreator,
	const OfficialInfInstallBindingReleaser &bindingReleaser,
	OfficialPreparationAuditReport			&report,
	IntelEthernetPreparedInstallTargets		&installTargets) noexcept ;
} // namespace drivercrate
