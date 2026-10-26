//------------------------------------------------------------------------------
/**
 * @file official_release_metadata.h
 * @brief 公式配布情報の共通契約。
 * @version 01.03.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Focusrite Scarlett 2i2検索契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Wacom Windows配布情報検索契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Ricoh Universal Print検索契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  ASIX配布IDのRelease観測契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測生成契約を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Intel Ethernet Server検索を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Broadcomの選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文と取得再確認の境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報と検索接続を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Intel Ethernet Windows 11 record系列を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  収集用Intel配布coreを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/26  公開SHA-512を独立fieldとして保持。
 * </pre>
 *
 * @note Worker内の配布情報を表し、未確認の版・容量・許諾を補完しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/collector_parser_control.h"

#include "core/official_release_observation.h"
#include "core/update_types.h"
#include "platform/official_catalog_device.h"
#include "platform/official_http_client.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {
class MetadataSearchExecutionContext ;
/** @brief 共通配布情報へ接続した組み込み系列。未知値は拒否する。 */
enum class OfficialReleaseFamily {
	/// 未初期化。既定系列として扱わない。
	UNKNOWN,
	/// PL2303GのDCHU INF配布行。
	PROLIFIC_DCHU,
	/// Wi-Fi IT管理者向けdriver-only配布。
	INTEL_WIFI,
	/// Windows Server 2025向けEthernet driver-only配布。
	INTEL_ETHERNET_SERVER2025,
	/// Intel record 727998のWindows 11向けEthernet driver-only配布。
	INTEL_ETHERNET_WINDOWS11,
	/// 二文書を専用parserで結合する公開Windows Drivers配布。
	BROADCOM_NET_XTREME_E,
	/// AX88179AのWindows client x64配布行。
	ASIX_AX88179A,
	/// Windows x64向け従来型PCL6 Universal Print配布行。
	RICOH_UNIVERSAL_PCL6,
	/// Windows 10／11 x64対応のWacom統合driver配布欄。
	WACOM_WINDOWS_TABLET,
	/// Scarlett 2i2 2nd GenのWindows driver配布欄。
	FOCUSRITE_SCARLETT2I2_SECOND_GEN,
	/// CP210xの公開Universal Windows ZIP。情報検索では内容を取得しない。
	SILICON_LABS_CP210X,
	/// CH340／CH341の公開ZIP。表示tokenの照合は適用性判定ではない。
	WCH_CH341,
	/// CH343の情報検索。CH342等への表示probe拡大を含めない。
	WCH_CH343,
} ;

/** @brief 配布元の使用許諾情報。利用者の同意状態ではない。 */
enum class OfficialReleaseLicense {
	/// 許諾条件とその識別子の確認が必要。
	UNRESOLVED,
	/// Pageがdownload前の許諾同意を要求する。
	ACCEPTANCE_BEFORE_DOWNLOAD,
	/// Providerがdownload前の同意不要を確認した。現行parserは生成しない。
	CONFIRMED_NO_CONSENT,
} ;

/** @brief 固定起点とbranchを選ぶ定義。Registryや取得許可を複製しない。 */
struct OfficialSourceDefinition {
	/// 組み込みの系列境界。
	OfficialReleaseFamily family{OfficialReleaseFamily::UNKNOWN} ;
	/// Registryへの参照key。表示名とcapabilityはregistryが正本。
	std::wstring_view	  providerId ;
	/// 公式source policyと一致する永続stable ID。
	std::wstring_view	  sourceId ;
	/// Parser系列を示す永続stable ID。
	std::wstring_view	  familyId ;
	/// 公式pageが公開する製品またはdownloadのstable key。
	std::wstring_view	  productKey ;
	/// 配布系列の識別子。Payloadの不変identityではない。
	std::wstring_view	  branch ;
	/// 既存内容監査の参照先ID。今回の導入関数は選択しない。
	std::wstring_view	  profileId ;
	/// Workerの固定GET起点。Device情報を付加しない。
	std::wstring_view	  landingUrl ;
	/// UIへ渡せる固定公式host名。URLまたはpathを含めない。
	std::wstring_view	  displayOrigin ;
	/// 一回の応答body上限byte数。
	std::uint64_t		  maximumMetadataBytes{} ;
	/// 観測比較へ使用する内容・適用性policyの単調revision。0は未定義。
	std::uint32_t		  observationPolicyRevision{} ;
	/// 二文書系列の固定補助JSON。空の場合はlandingだけを読む。
	std::wstring_view	  metadataUrl ;
} ;

/** @brief Payload取得前のworker内専用record。UIやlogへ直接渡してはならない。 */
struct OfficialReleaseRecord {
	/// Parserを選択した系列。
	OfficialReleaseFamily		 family{OfficialReleaseFamily::UNKNOWN} ;
	/// 公式sourceが明示したstable release key。File名を持たないendpoint系列だけが設定する。
	std::wstring				 releaseKey ;
	/// 公式配布行が明示したbasename。保存pathには使用しない。
	std::wstring				 fileName ;
	/// 明示された配布版。空は不明でありINF版ではない。
	std::wstring				 packageVersion ;
	/// 公表概算。実測byte数や上限の根拠にはしない。
	std::wstring				 displaySize ;
	/// 公式pageが明示した公開日。形式不明または欠落時は空。
	std::wstring				 publishedDate ;
	/// 正確な公表byte数。不明なら空。
	std::optional<std::uint64_t> publishedSizeBytes ;
	/// 公表hash。不明なら空。実測値を代入しない。
	std::wstring				 publishedSha256 ;
	/// Parserが確認したURL。取得許可ではなくworker内だけに保持。
	std::wstring				 downloadUrl ;
	/// 必要な許諾確認。
	OfficialReleaseLicense		 license{OfficialReleaseLicense::UNRESOLVED} ;
	/// 同意対象の改訂識別子。不明なら空であり承認に使えない。
	std::wstring				 eulaRevision ;
	/// 使用した組み込みparser契約。0は未解析。
	std::uint32_t				 parserRevision{} ;
	/// Providerが当該配布物へ結合したplain text全文。未確認は空。
	std::wstring				 eulaText ;
	/// 公表SHA-512。未掲載は空。SHA-256や実測file identityへ代入しない。
	std::wstring				 publishedSha512 ;

	/**
     * @brief 取得直前の公式再確認と保持snapshotを全fieldで比較する。
     * @param[in] other 同じ固定起点から再取得した配布情報。
     * @return 全field一致時true。同一URLでもhashや本文変更があればfalse。
     */
	bool						 operator==( const OfficialReleaseRecord &other) const = default ;
} ;

/** @brief 一つのdeviceについて生成した今回観測と前回との差である。 */
struct OfficialReleaseObservationEvaluation {
	/// 永続化前にcore検証済みの今回観測。
	LocalOfficialReleaseObservation observation ;
	/// UIへ渡せる非機密差分。取得・監査・導入の許可ではない。
	ReleaseObservationDifference	difference{ReleaseObservationDifference::INVALID} ;
} ;

/**
 * @brief 系列に対応する固定検索定義を返す。
 * 許可hostとcapabilityはsource policy／registryへ委譲する。
 * @param[in] family 組み込み系列。 組み込みの系列識別子。
 * @return Process寿命中有効な非所有定義。未知値はnullptr。 Process寿命中有効な非所有pointer。未知値はnullptr。
 */
[[nodiscard]] const OfficialSourceDefinition *officialSourceDefinition(
	OfficialReleaseFamily family) noexcept ;

/**
 * @brief 系列の配布情報を参照すべきdeviceか端末内だけで判断する。
 * 系列別のclass、GUID、manufacturer、model表示境界を確認する。いずれの系列も現在版不明だけを理由に除外しない。
 * @param[in] family 対象の組み込み系列。 探索系列。
 * @param[in] device 非機密snapshot。生IDを含めない。 呼出し中だけ参照する非機密snapshot。
 * @return 系列表示名と矛盾しないclassならtrue。不明な現在版は除外条件にしない。 系列参照の対象ならtrue。適用性を意味しない。
 * @note 適用性、最新性、更新必要性、導入可能性の判定ではない。
 */
[[nodiscard]] bool officialReleaseDeviceMatches( OfficialReleaseFamily		 family,
												const OfficialCatalogDevice &device) noexcept ;

/**
 * @brief 系列の固定公式pageと実OSの組合せが一致するか判定する。
 * 系列が明示するClient／Server範囲だけを許可する。Server専用または列挙型のServer系列では不明buildをfail-closedにする。
 * @param[in] family 対象の組み込み系列。 固定公式pageの系列。
 * @param[in] windowsServer 実OSがWindows Serverの場合true。 実OSがServerの場合true。
 * @param[in] windowsBuild 実OSのmajor build番号。判定不能時は0。 判定済みmajor build。0は不明。
 * @return 当該系列が明示するOS境界と一致する場合true。 系列と実OSの固定境界が一致する場合true。
 */
[[nodiscard]] bool officialReleaseOperatingSystemMatches( OfficialReleaseFamily family,
														 bool				   windowsServer,
														 std::uint32_t windowsBuild) noexcept ;

/**
 * @brief Live metadataと端末内device bindingから今回のrelease観測を作る。
 * 表示名やURLからidentityを推測せず、組み込みsource定義とlocal bindingだけを結合する。SHA-256のhex表記だけをlowercaseへ正規化し、一致結果を
 * payload取得または導入許可へ変換しない。
 * @param[in] family 組み込み系列。Releaseとsource定義へ完全一致させる。 組み込みの公式配布系列。
 * @param[in] release 同じscanで取得・解析済みの公式metadata。 Live取得・解析済みの公式metadata。
 * @param[in] device Local probeでHMAC bindingを付与した現在device。 Local HMAC binding付きの現在device。
 * @param[in] operatingSystemFingerprint 現在OS／x64条件の端末内fingerprint。 現在OS条件の端末内fingerprint。
 * @param[in] deviceConfigurationFingerprint 現在device集合の端末内fingerprint。 現在device集合のfingerprint。
 * @param[in] observedFileTime Live metadataを確認したUTC FILETIME値。 Live metadata確認時刻のUTC FILETIME値。
 * @param[in] previous 現在環境へ事前照合済みの前回観測。最大4,096件。 現在環境へ事前照合済みの前回観測集合。
 * @param[out] evaluation 成功時の今回観測と差分。失敗時は初期値。 成功時の今回観測と前回差分。
 * @return 全入力と一意な前回対応を検証できた場合true。
 * @note 前回一致でもpayload、EULA、署名、INF、PnP、rankの許可を返さない。
 */
[[nodiscard]] bool evaluateOfficialReleaseObservation(
	OfficialReleaseFamily family, const OfficialReleaseRecord &release,
	const OfficialCatalogDevice &device, std::wstring_view operatingSystemFingerprint,
	std::wstring_view deviceConfigurationFingerprint, std::uint64_t observedFileTime,
	std::span<const LocalOfficialReleaseObservation> previous,
	OfficialReleaseObservationEvaluation			&evaluation) ;

/**
 * @brief 既存の系列別parserから共通の配布情報を作成する。
 * 既存parserを再利用する。公表情報の欠落をfile名等から推測しない。
 * @param[in] family 使用する組み込みparser。 組み込みparser選択。
 * @param[in] html 上限付き公式page本文。取得元証明は別途必要。 有限長の公式metadata本文。
 * @param[out] record 成功時のworker内情報。失敗時は初期値。 成功時の共通情報。失敗時は初期値。
 * @return 既存parserの必須条件を満たした場合true。 系列別必須metadataが整合すればtrue。
 */
[[nodiscard]] bool parseOfficialReleaseRecord( OfficialReleaseFamily family, std::wstring_view html,
											  OfficialReleaseRecord &record) ;

/**
 * @brief 共通HTTPと公式landing取得根拠で配布情報だけを取得する。
 * 固定landingをworkerで同期取得し、同sessionの根拠を確認する。Payload取得と同意操作を行わない。
 * @param[in] family 検索定義を選ぶ組み込み系列。 固定検索定義の系列。
 * @param[in] session 0ではないscan session。
 * @param[in,out] http Workerが所有するHTTP client。以前のsource sessionは失効する。 Workerが所有するclient。以前の根拠は失効。
 * @param[out] record 成功時の配布情報。失敗時は初期値。 成功時の解析結果。失敗時は初期値。
 * @param[out] metadataRejected 取得後の解析・取得根拠検証が失敗した場合true。 取得後の解析・根拠拒否でtrue。
 * @param[in,out] execution 指定時は同じmetadata専用予算。解析前後にも停止を確認する。
 * @return 成功時0。失敗時は元の通信errorまたは不正入力・metadataのHRESULT。 成功時0。失敗は通信または検証のHRESULT。
 * @note 同期処理なのでUI threadでは呼ばない。PayloadとEULA同意を扱わない。
 */
[[nodiscard]] NativeError readOfficialReleaseMetadata(
	OfficialReleaseFamily family, ScanSessionId session, OfficialHttpClient &http,
	OfficialReleaseRecord &record, bool &metadataRejected,
	MetadataSearchExecutionContext *execution = nullptr) ;
/**
 * @brief 727998だけを同じ配布変換と必須制御で解析します。
 * @param[in] html 同一GET本文。
 * @param[out] record 旧fingerprintと互換のfield。
 * @param[in,out] context 元制御。
 * @return 配布非採用はfalse。停止・障害は上位へ伝播します。
 */
[[nodiscard]] bool parseIntelCollectorReleaseRecord( std::wstring_view		html,
													OfficialReleaseRecord  &record,
													CollectorParserContext &context) ;
} // namespace drivercrate
