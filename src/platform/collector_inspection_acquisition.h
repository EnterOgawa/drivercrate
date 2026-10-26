//------------------------------------------------------------------------------
/**
 * @file collector_inspection_acquisition.h
 * @brief 外部台帳の一recordを生存検査取得へ接続する収集専用境界。
 * @version 01.03.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/10/23  原page観測と取得上限・公開hash・確認本文の固定を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/23  同run専用の不変PAGE証拠と有限借用scopeを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/25  原byteを維持した限定末尾診断コメントの比較digestを追加。
 * </pre>
 *
 * @note 同期収集workerで所有し、公開JSONから取得証拠を復元しない。
 * @see docs/adr/0280-collector-scoped-inspection-acquisition.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/official_acquisition.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

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

/** @brief 原PAGEの厳密末尾診断コメントだけを区別する比較SHA-256を計算します。
 * @param[in] raw 1 byte以上2 MiB以下の原本文です。呼出し中に不変とします。
 * @param[out] sha256 成功時は小文字64桁、失敗時は空です。原本文hashとは別の値です。
 * @return 成功0、入力不正またはCNG失敗のHRESULTです。
 * @note ADR0399の完全末尾書式と実HTML終端だけを除外し、その他は全rawをhashします。
 *       本文・原観測を変更せず、公式性や権限を発行しません。
 */
[[nodiscard]] NativeError computeCollectorPageContentSha256( std::string_view raw,
															std::wstring	&sha256) ;

class CollectorRegistryJobProtectedCaller ;
class CollectorRegistryJobTestAccess ;
class CollectorRegistryJobRunner ;
class CollectorRunPageScope ;
struct CollectorRunPageLifetime ;

/** @brief 同じ実PAGEを親run内だけで再確認する不変証拠です。
 * @note 外部構築・JSON復元・保存cache復元はなく、grantや別jobの成功を保持しません。
 */
class CollectorRunPageProof final {
public:
	/** @brief 私有生成値の所有権移動だけを許します。
	 * @param[in,out] other 既に私有生成された一証拠です。
	 */
	CollectorRunPageProof( CollectorRunPageProof &&other) noexcept = default ;
	/** @brief 元本文と所有境界の暗黙複写を禁止します。
	 * @param[in] other 複写しない元証拠です。
	 */
	CollectorRunPageProof( const CollectorRunPageProof &other) = delete ;

private:
	friend class CollectorRunPageScope ;
	friend class CollectorInspectionAcquisition ;
	friend class CollectorRegistryJobProtectedCaller ;
	friend class CollectorRegistryJobTestAccess ;
	/** @brief 実HTTPの完全本文だけを不変所有へ移します。
	 * @param[in] lifetime 元runの生存と全bindingです。
	 * @param[in] source 元exact起点です。payload/grantは保存しません。
	 * @param[in] raw 同HTTPの原byteです。
	 * @param[in] html 同原byteから厳密復号した本文です。
	 * @param[in] observation 同原byte/hash/最終URL/UTCです。
	 * @param[in] transfer 同低位I/Oが発行したCOMPLETEです。
	 */
	CollectorRunPageProof( const std::shared_ptr<CollectorRunPageLifetime> &lifetime,
						  const CollectorInspectionSource &source, std::vector<std::byte> raw,
						  std::wstring html, CollectorInspectionPageObservation observation,
						  CollectorHttpTransferObservation transfer) ;
	/// 別run・終了・破棄後の借用を拒否する元scopeです。
	std::weak_ptr<CollectorRunPageLifetime> lifetime_ ;
	/// 原入力の起点URLです。
	std::wstring							rootUrl_ ;
	/// 原入力のexact起点hostです。
	std::wstring							rootHost_ ;
	/// 同じ実取得のBOMを含む原本文です。
	std::vector<std::byte>					raw_ ;
	/// 同じ原本文の厳密UTF-8復号結果です。
	std::wstring							html_ ;
	/// 原本文hash・実最終URL・時刻です。
	CollectorInspectionPageObservation		observation_ ;
	/// 同じ実PAGEの完全転送観測です。
	CollectorHttpTransferObservation		transfer_ ;
} ;

/** @brief 保護parent専用の同run最大32entry/raw32MiB境界です。
 * @note ctorは将来callerが固定するrun/lease/child/全入力hash/plan/期限を受けます。
 *       本型自体はnative admissionや子監督の実検証を代行しません。直列worker専用です。
 */
class CollectorRunPageScope final {
public:
	/** @brief 残る借用を失効し、所有本文を解放します。 */
	~CollectorRunPageScope() ;
	/** @brief Run所有権の複写を禁止します。
	 * @param[in] other 複写しないscopeです。
	 */
	CollectorRunPageScope( const CollectorRunPageScope &other) = delete ;
	/** @brief Run所有権の上書きを禁止します。
	 * @param[in] other 代入しないscopeです。
	 * @return 呼出し不能です。
	 */
	CollectorRunPageScope &operator=( const CollectorRunPageScope &other) = delete ;

private:
	friend class CollectorRegistryJobProtectedCaller ;
	friend class CollectorRegistryJobTestAccess ;
	friend class CollectorInspectionAcquisition ;
	/** @brief 将来parentが実検証して固定する全bindingから有限scopeを作ります。
	 * @param[in] runId 親が所有する空でないrun識別子です。
	 * @param[in] parentLease 元writer leaseの0でないidentityです。
	 * @param[in] childProcess 元監督childの0でないprocess identityです。
	 * @param[in] inputHashes 全固定入力の順序付きSHA-256です。1～32個です。
	 * @param[in] planHash 固定planの小文字SHA-256です。
	 * @param[in] deadline 延長しない単調期限です。
	 * @param[in] cancellation 子停止等を確認する非blocking関数です。
	 * @param[in] now 空は実steady clock、試験だけ完全fake時計です。
	 */
	CollectorRunPageScope( std::wstring runId, std::uint64_t parentLease, std::uint64_t childProcess,
						  std::vector<std::wstring> inputHashes, std::wstring planHash,
						  std::chrono::steady_clock::time_point					 deadline,
						  HttpCancellationCallback								 cancellation,
						  std::function<std::chrono::steady_clock::time_point()> now = {}) ;
	/** @brief 終了後の借用を永久拒否し、cacheを破棄します。 */
	void													   finish() noexcept ;
	/** @brief 生存・単調時計・取消しを同じrunへ確認します。
	 * @return 継続時true、停止時は全proofを失効してfalseです。
	 */
	[[nodiscard]] bool										   checkpoint() noexcept ;
	/** @brief 先行予約前に同runの完全PAGEだけを検索します。
	 * @param[in] source 今回のexact起点です。
	 * @return 同scope/期限内の共有不変証拠、未取得または停止時はnullです。
	 */
	[[nodiscard]] std::shared_ptr<const CollectorRunPageProof> find(
		const CollectorInspectionSource &source) noexcept ;
	/** @brief 借用証拠の全bindingと当該起点を再確認します。
	 * @param[in] proof 借用する私有証拠です。
	 * @param[in] source 今回のexact起点です。
	 * @return 同じ生存scopeと完全PAGEの場合だけtrueです。
	 */
	[[nodiscard]] bool accepts( const CollectorRunPageProof	   &proof,
							   const CollectorInspectionSource &source) noexcept ;
	/** @brief 同HTTPの完全本文を有限cacheへ保存します。
	 * @param[in] source 原起点です。
	 * @param[in] raw 実原本文です。
	 * @param[in] html 同じ復号本文です。
	 * @param[in] observation 同原byteのhash/URL/UTCです。
	 * @param[in] transfer 同低位HTTPが発行した完全観測です。
	 * @return 所有済み不変証拠。停止/上限/重複/未完時nullです。
	 */
	[[nodiscard]] std::shared_ptr<const CollectorRunPageProof> retain(
		const CollectorInspectionSource &source, std::vector<std::byte> raw, std::wstring html,
		CollectorInspectionPageObservation observation, CollectorHttpTransferObservation transfer) ;
	/// 全bindingと一方向の生存状態です。
	std::shared_ptr<CollectorRunPageLifetime>				  lifetime_ ;
	/// 同runだけの不変本文です。退避・復活しません。
	std::vector<std::shared_ptr<const CollectorRunPageProof>> pages_ ;
	/// 所有raw合計byteです。32MiBを超えません。
	std::uint64_t											  rawBytes_{} ;
} ;

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
	 * @param[in] maximumBytes 今回だけの1～32MiB上限です。既定は従来上限です。
	 * @param[in] publishedSha256 空または実byteへ比較する小文字SHA-256です。
	 * @param[in] expectedPageContentSha256 空または手動確認の比較digestです。不一致時はpayloadを開始しません。
	 * @return 全固定成功0、起点・回線・共通検証拒否のHRESULT。
	 * @note 同期COM内で直列に使用し、制限付き／不明回線を自動承認しない。
	 */
	[[nodiscard]] NativeError		acquire(
			  ScanSessionId scanSessionId, const CollectorInspectionSource &source,
			  OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
			  IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
			  OfficialAcquisitionResult &result,
			  std::uint64_t				 maximumBytes = COLLECTOR_INSPECTION_MAXIMUM_BYTES,
			  std::wstring_view publishedSha256 = {}, std::wstring_view expectedPageContentSha256 = {}) ;
	/** @brief 同じ実起点GETの成功観測を同期借用します。
	 * @return 次の破棄まで有効な原byte観測です。入力JSONから復元しません。
	 */
	[[nodiscard]] const CollectorInspectionPageObservation &pageObservation() const noexcept ;
	/** @brief 同じ実PAGE転送を借用します。
	 * @return 共有時も元PAGEの原観測です。
	 */
	[[nodiscard]] const CollectorHttpTransferObservation   &pageTransfer() const noexcept ;
	/** @brief 今回の実payload転送を借用します。
	 * @return 未送信・失敗でも実数とUNKNOWNを保持します。
	 */
	[[nodiscard]] const CollectorHttpTransferObservation   &payloadTransfer() const noexcept ;
	/** @brief 同runのPAGEを借用した事実を返します。
	 * @return trueなら今回のPAGE増分は0要求/0byteです。
	 */
	[[nodiscard]] bool										pageReusedInRun() const noexcept ;
	/** @brief 同じ実HTTP二段のprivate完了を観測する。
	 * @return Private起点確認とpayload保存が両方成功した場合true。
	 * @note このboolで封印証拠の再照合を代替しない。
	 */
	[[nodiscard]] bool										sourceVerified() const noexcept ;

private:
	friend class OfficialAcquisitionSession ;
	friend class CollectorRegistryJobRunner ;
	/** @brief 私有runの実PAGEを確定し、一jobだけ取得します。
	 * @copydoc acquire
	 * @param[in,out] scope 元parentの生存runです。
	 * @param[in] proof nullなら新PAGE、非nullなら同runの完全本文だけを借用します。
	 */
	[[nodiscard]] NativeError acquireWithRunPage(
		ScanSessionId scanSessionId, const CollectorInspectionSource &source,
		OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
		IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
		OfficialAcquisitionResult &result, std::uint64_t maximumBytes,
		std::wstring_view publishedSha256, std::wstring_view expectedPageContentSha256,
		CollectorRunPageScope &scope, const CollectorRunPageProof *proof) ;
	/** @brief 通常一回取得と私有run取得の共通境界です。
	 * @copydoc acquireWithRunPage
	 * @note scope=nullは従来一回入口で、proofは必ずnullです。
	 */
	[[nodiscard]] NativeError acquireCore(
		ScanSessionId scanSessionId, const CollectorInspectionSource &source,
		OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
		IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
		OfficialAcquisitionResult &result, std::uint64_t maximumBytes,
		std::wstring_view publishedSha256, std::wstring_view expectedPageContentSha256,
		CollectorRunPageScope *scope, const CollectorRunPageProof *proof) ;
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
	CollectorInspectionSource		   source_ ;
	/// 同じ実起点GETが所有する観測です。Anchor不一致時も本文取得の事実を保持します。
	CollectorInspectionPageObservation pageObservation_ ;
	/// 低位I/Oだけが生成した原PAGE転送です。
	CollectorHttpTransferObservation   pageTransfer_ ;
	/// 同jobのpayload転送です。別jobから貸しません。
	CollectorHttpTransferObservation   payloadTransfer_ ;
	/// 元完全PAGEを借用した今回の事実です。
	bool							   pageReusedInRun_{} ;
	/// 今回の保守jobが固定したpayload容量上限です。
	std::uint64_t					   maximumBytes_{} ;
	/// 実byteと比較する今回の公開hashです。空は未公開です。
	std::wstring					   publishedSha256_ ;
	/// 同じ元取得session ID。未開始時0。
	ScanSessionId					   scanSessionId_{} ;
	/// 初回試行の成否にかかわらずtrue。
	bool							   used_{} ;
	/// 実起点の有効anchor確認だけでtrue。
	bool							   rootVerified_{} ;
	/// Payload開始前にtrueとし再送を拒否する。
	bool							   payloadAttempted_{} ;
	/// 同じ共通HTTPの全保存成功時だけtrue。
	bool							   payloadVerified_{} ;
} ;
} // namespace drivercrate
