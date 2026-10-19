//------------------------------------------------------------------------------
/**
 * @file collector_inspection_acquisition.h
 * @brief 外部台帳の一recordを生存検査取得へ接続する収集専用境界。
 * @version 01.00.02
 * @date 2026/10/06
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  台帳起点の一回検査取得境界を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.00.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 同期収集workerで所有し、公開JSONから取得証拠を復元しない。
 * @see docs/adr/0280-collector-scoped-inspection-acquisition.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/official_acquisition.h"
#include <string>
#include <string_view>

namespace drivercrate {
inline constexpr std::wstring_view COLLECTOR_INSPECTION_PROVIDER_ID =
	L"collector-inspection" ;	// 既存workspaceの24文字内で製品Providerに登録しない収集scope。
inline constexpr std::uint64_t COLLECTOR_INSPECTION_MAXIMUM_BYTES =
	32ULL * 1024ULL * 1024ULL ;	// 一record・一sessionのpayload予算。

/** @brief 保守担当が一次資料で確認した一公式起点と対象の定義。
 * @note 認証結果ではない。任意Web応答や端末情報から起点を作らない。
 */
struct CollectorInspectionSource {
	/// 手動調査済みの絶対HTTPS起点。Query・fragment・認証は許可しない。
	std::wstring rootUrl ;
	/// 起点の小文字ASCII exact DNS host。Suffix指定は許可しない。
	std::wstring rootHost ;
	/// 起点hrefから再解決するexact HTTPS配布URL。
	std::wstring payloadUrl ;
	/// 今回の一recordだけに許可する小文字ASCII exact配布host。
	std::wstring payloadHost ;
	/// 一意なanchorで確認する原href。最大480文字、entity・queryは扱わない。
	std::wstring href ;
} ;
/** @brief 定義のexact URLとhref解決を非通信で照合する。
 * @param[in] source 保守担当の一record定義。
 * @return 有限・exact host・href解決が一致する場合true。公式性の認定ではない。
 */
[[nodiscard]] bool validateCollectorInspectionSource( const CollectorInspectionSource &source) ;
/** @brief 静的HTMLの有効な一意anchorを確認する。
 * @param[in] html 実本文またはfixture。最大2 Mi UTF-16 code unit。
 * @param[in] source 非通信検査を通る対象定義。
 * @return 対象hrefが一意な有効anchorである場合true。権限は発行しない。
 * @note Comment・script・style・template・noscript内を根拠にしない。
 */
[[nodiscard]] bool verifyCollectorInspectionLink( std::wstring_view				  html,
												 const CollectorInspectionSource &source) ;

/** @brief 実HTTP起点とpayloadを一回scopeに限定する収集adapter。
 * @note 初回試行後は再使用不可。導入・日次予約・同意を代行しない。
 */
class CollectorInspectionAcquisition final : private IOfficialAcquisitionTransport {
public:
	/** @brief Cacheなしの実HTTPを作る。構築だけでは通信しない。 */
	CollectorInspectionAcquisition() ;
	/** @brief 非通信fixtureの低位HTTP表を所有する。
	 * @param[in] transport Native関数を使用しない完全な試験I/O表。
	 * @note 通常collector設定から指定しない。
	 */
	explicit CollectorInspectionAcquisition( OfficialHttpTransport transport) ;
	/** @brief 内部scopeを解放する。取得領域はcallerが所有する。 */
	~CollectorInspectionAcquisition() = default ;
	/**
	 * @brief 一回取得の使用状態とHTTP境界の二重管理を防ぐため、コピー構築を禁止する。
	 */
	CollectorInspectionAcquisition( const CollectorInspectionAcquisition &) = delete ;
	/**
	 * @brief 一回取得の使用状態とHTTP境界を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	CollectorInspectionAcquisition &operator=( const CollectorInspectionAcquisition &) = delete ;
	/** @brief 実起点本文の確認後、一payloadを共通保護sessionへ取得する。
	 * @param[in] scanSessionId 同じsessionに固定した0でないID。
	 * @param[in] source 手動調査済みの対象定義。成功boolは含めない。
	 * @param[in,out] session 初期化済みの有限元取得session。
	 * @param[in,out] workspace 同じID・収集scopeの空保護領域。
	 * @param[in,out] costReader 実OSまたは試験回線照会。
	 * @param[in] cancellation 空または非blocking取消し関数。
	 * @param[out] result 共通取得結果。失敗時に旧成功を残さない。
	 * @return 全固定成功0、起点・回線・共通検証拒否のHRESULT。
	 * @note 同期COM内で直列に使用し、制限付き／不明回線を自動承認しない。
	 */
	[[nodiscard]] NativeError		acquire( ScanSessionId					 scanSessionId,
											const CollectorInspectionSource &source,
											OfficialAcquisitionSession		&session,
											OfficialDownloadWorkspace		&workspace,
											IOfficialNetworkCostReader		&costReader,
											const HttpCancellationCallback	&cancellation,
											OfficialAcquisitionResult		&result) ;
	/** @brief 同じ実HTTP二段のprivate完了を観測する。
	 * @return Private起点確認とpayload保存が両方成功した場合true。
	 * @note このboolで封印証拠の再照合を代替しない。
	 */
	[[nodiscard]] bool				sourceVerified() const noexcept ;

private:
	friend class OfficialAcquisitionSession ;
	/** @brief 同じprivate scopeへ共通sessionの要求を完全一致させる。
	 * @param[in] scanSessionId 元取得sessionのID。
	 * @param[in] request adapter自身が生成した要求。
	 * @return 起点確認後・payload未取得の同じ要求の場合true。
	 */
	[[nodiscard]] bool		  matches( ScanSessionId						scanSessionId,
									  const OfficialAcquisitionRequest &request) const noexcept ;
	/**
	 * @copydoc drivercrate::IOfficialAcquisitionTransport::download
	 * @note 起点確認後の同じ一payloadだけを受け付ける。
	 */
	[[nodiscard]] NativeError download(
		std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
		HANDLE outputFile, const HttpDownloadProgressCallback &progressCallback,
		const HttpCancellationCallback &cancellationCallback) override ;
	/**
	 * @copydoc drivercrate::IOfficialAcquisitionTransport::downloadDelegated
	 * @note このadapterは別grant経路を受理しない。
	 */
	[[nodiscard]] NativeError downloadDelegated(
		OfficialDelegatedGetRequest &request, HANDLE outputFile,
		const HttpDownloadProgressCallback &progressCallback,
		const HttpCancellationCallback	   &cancellationCallback,
		OfficialPublicDestinationEvidence  &destinationEvidence) override ;
	/**
	 * @copydoc drivercrate::IOfficialAcquisitionTransport::hasSourceEvidence
	 * @note 同じ起点とpayloadの実取得状態を照合する。
	 */
	[[nodiscard]] bool hasSourceEvidence( ScanSessionId scanSessionId, std::wstring_view providerId,
										 std::wstring_view resourceId) const noexcept override ;
	/// Cacheなしの同じHTTP client。
	OfficialHttpClient http_ ;
	/// 一試行で固定する定義。外部の成功結果を取り込まない。
	CollectorInspectionSource source_ ;
	/// 同じ元取得session ID。未開始時0。
	ScanSessionId			  scanSessionId_{} ;
	/// 初回試行の成否にかかわらずtrue。
	bool					  used_{} ;
	/// 実起点の有効anchor確認だけでtrue。
	bool					  rootVerified_{} ;
	/// Payload開始前にtrueとし再送を拒否する。
	bool					  payloadAttempted_{} ;
	/// 同じ共通HTTPの全保存成功時だけtrue。
	bool					  payloadVerified_{} ;
} ;
} // namespace drivercrate
