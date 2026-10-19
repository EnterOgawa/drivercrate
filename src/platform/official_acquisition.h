//------------------------------------------------------------------------------
/**
 * @file official_acquisition.h
 * @brief 公式fileの検査用取得境界定義。
 * @version 01.05.01
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Record限定grantの保護取得variantを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  公開SHA-512の任意検証値と独立した結果を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/06  成功sessionだけが発行する非永続取得証拠を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/06  収集adapter限定のprivate取得scopeを共通化。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.05.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * </pre>
 *
 * @note 公式由来を確認したfileを候補化せず保護workspaceへ取得し、容量予算、network cost、取消し、size、SHA-256をfail-closedで検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"
#include "core/official_download_delegation.h"
#include "platform/official_http_client.h"

#include <Windows.h>

#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;
class CollectorInspectionAcquisition ;

//------------------------------------------------------------------------------
// 公式file取得状態定義。
//------------------------------------------------------------------------------

/**
 * @brief Machine-wide networkの課金またはdata制限状態を表す。
 */
enum class OfficialNetworkCostKind {
	/// Cost API失敗またはOSがcostを判定できない。
	UNKNOWN,
	/// 使用量課金またはdata上限がない。
	UNRESTRICTED,
	/// Fixed、Variable、data limitまたはroaming状態である。
	RESTRICTED,
} ;

/**
 * @brief 一つの公式file取得が到達した監査前状態を表す。
 */
enum class OfficialAcquisitionState {
	/// 取得処理を開始していない。
	NOT_STARTED,
	/// RestrictedまたはUnknown networkへの同意待ち。
	AWAITING_NETWORK_CONSENT,
	/// 公式由来、容量、size、hashを検証して固定した。
	ACQUIRED_FOR_INSPECTION,
	/// 利用者の取消しによりpartial fileを破棄した。
	CANCELLED,
	/// 入力、予算、disk、根拠またはmetadataを拒否した。
	REJECTED,
	/// NetworkまたはWindows API処理が失敗した。
	FAILURE,
} ;

/**
 * @brief 一つのscan sessionへ適用する検査用取得の有限予算を表す。
 */
struct OfficialAcquisitionLimits {
	/// 一fileに許可する絶対上限byte数。
	std::uint64_t maximumFileBytes{} ;
	/// 一Providerの成功取得累計上限byte数。
	std::uint64_t maximumProviderBytes{} ;
	/// Scan session全体の成功取得上限byte数。
	std::uint64_t maximumSessionBytes{} ;
	/// 取得後もvolumeへ残す空き容量byte数。
	std::uint64_t minimumFreeBytes{} ;
	/// 一Providerの成功取得file数上限。
	std::uint32_t maximumProviderFiles{} ;
	/// Scan session全体の成功取得file数上限。
	std::uint32_t maximumSessionFiles{} ;
} ;

/**
 * @brief 公式payload一fileを検査用に取得する入力を表す。
 *
 * @note URLとfile名は本呼出し中だけ参照し、result、UIまたはlogへ複写しない。
 */
struct OfficialAcquisitionRequest {
	/// 登録済み公式payloadの絶対HTTPS URL。
	std::wstring_view			   url ;
	/// 組み込み公式network Provider ID。
	std::wstring_view			   providerId ;
	/// Payload用途の組み込みresource ID。
	std::wstring_view			   resourceId ;
	/// Providerが固定した安全な相対file名。
	std::wstring_view			   workspaceFileName ;
	/// Provider ADRが許可する取得上限byte数。
	std::uint64_t				   maximumFileBytes{} ;
	/// 公開exact size。未公開時はnullopt。
	std::optional<std::uint64_t>   publishedSize ;
	/// 公開64桁SHA-256。未公開時は空。
	std::wstring_view			   publishedSha256 ;
	/// 公開128桁SHA-512。未公開時は空。
	std::wstring_view			   publishedSha512 ;
	/// trueなら今回だけRestricted／Unknownを許可する。
	bool						   restrictedNetworkApproved{} ;
	/// Record限定経路でsessionより長く生存する未使用grant。固定URL経路ではnullptrです。
	RecordScopedDownloadGrant	  *delegatedGrant{} ;
	/// Record限定経路で利用者が選択したopaque grant ID。固定URL経路では0です。
	std::uint64_t				   delegatedGrantId{} ;
	/// Record限定経路でfile作成後のclaim直前UTC秒を返すworker時計。
	std::function<std::uint64_t()> delegatedUtcNow ;
} ;

/**
 * @brief 公式fileをsystem監査へ渡す前の取得結果を表す。
 *
 * @note `inspectionPath`と`sha256`はworker内だけに保持し、UIまたは永続logへ渡さない。
 * `ACQUIRED_FOR_INSPECTION`はcandidate、適用可能、推奨またはinstall可能を意味しない。
 */
struct OfficialAcquisitionResult {
	/// 到達状態。
	OfficialAcquisitionState	state{OfficialAcquisitionState::NOT_STARTED} ;
	/// 取得処理の失敗理由。成功時は0。
	NativeError					error{} ;
	/// Cost照会失敗理由。照会成功時は0。
	NativeError					networkCostError{} ;
	/// Cost分類。
	OfficialNetworkCostKind		networkCost{OfficialNetworkCostKind::UNKNOWN} ;
	/// 成功取得を所有するscan session ID。
	ScanSessionId				scanSessionId{} ;
	/// Session内で1から単調増加する成功取得ID。
	std::uint64_t				acquisitionId{} ;
	/// 取得元の組み込みProvider stable ID。
	std::wstring				providerId ;
	/// 取得時に検証したpayload resource ID。
	std::wstring				resourceId ;
	/// 保護workspace内の内部専用絶対path。
	std::wstring				inspectionPath ;
	/// 固定したfileの実byte数。
	std::uint64_t				byteCount{} ;
	/// 固定したfileの64桁小文字SHA-256。
	std::wstring				sha256 ;
	/// 公開sizeがあり完全一致した場合true。
	bool						publishedSizeVerified{} ;
	/// 公開SHA-256があり完全一致した場合true。
	bool						publishedSha256Verified{} ;
	/// 公開SHA-512があり完全一致した場合true。
	bool						publishedSha512Verified{} ;
	/// Record限定grant経由で取得した場合true。
	bool						delegatedRecord{} ;
	/// Live公式起点と署名監視PCattestationを明示して区別します。取得権限ではありません。
	OfficialDownloadGrantOrigin recordOrigin{OfficialDownloadGrantOrigin::LIVE_OFFICIAL_NETWORK} ;
	/// Record限定経路で結合したopaque record証拠ID。固定URL経路では0です。
	std::uint64_t				recordEvidenceId{} ;
	/// Record限定経路で消費したopaque grant ID。固定URL経路では0です。
	std::uint64_t				downloadGrantId{} ;
	/// RootからURLを再解決した回数。固定URL経路では0です。
	std::uint32_t				grantReresolutionCount{} ;
	/// 全hopでpublicと確認したDNS address数。固定URL経路では0です。
	std::uint32_t				validatedDestinationAddressCount{} ;
	/// Record限定経路で全hopをlocal解決できた場合true。
	bool						destinationLocallyResolved{} ;
} ;

/**
 * @brief 同じ生存sessionと元workspaceへ結合した非複写の取得証拠。
 * @note 既定値は無効。JSONや公開結果から構築できず、INF署名・適用性・導入許可を表さない。
 * @see docs/adr/0273-session-sealed-acquired-file-evidence.md
 */
class OfficialAcquiredFileEvidence final {
public:
	/** @brief 無効な空証拠を作る。 */
	OfficialAcquiredFileEvidence() = default ;
	/** @brief 弱いissuer参照と非秘密metadataを解放する。 */
	~OfficialAcquiredFileEvidence() = default ;
	/**
	 * @brief 取得権限と区別する証拠の暗黙複写を禁止する。
	 * @param[in] other 複写を許可しない元証拠。
	 */
	OfficialAcquiredFileEvidence( const OfficialAcquiredFileEvidence &other) = delete ;
	/**
	 * @brief 証拠の複写代入を禁止する。
	 * @param[in] other 複写を許可しない元証拠。
	 * @return 本演算子は呼出し不能であり、値を返さない。
	 */
	OfficialAcquiredFileEvidence &operator=( const OfficialAcquiredFileEvidence &other) = delete ;
	/**
	 * @brief 証拠の所有を移し、移動元issuerを空にする。
	 * @param[in,out] other 移動後は再照合できない元証拠。
	 */
	OfficialAcquiredFileEvidence( OfficialAcquiredFileEvidence &&other) noexcept = default ;
	/**
	 * @brief 元証拠を解放して所有を移す。
	 * @param[in,out] other 自身とは異なる移動元証拠。
	 * @return 移動先の自身。
	 * @pre 自己moveは行わない。
	 */
	OfficialAcquiredFileEvidence &operator=( OfficialAcquiredFileEvidence &&other) noexcept =
		default ;
	/**
	 * @brief 発行時の取得metadataを同期借用する。認証の再確認ではない。
	 * @return 次のmove／代入／破棄まで有効なread-only値。既定時は空。
	 * @note 実pathはworker内だけで利用し、UI／log／永続JSONへ渡さない。
	 */
	[[nodiscard]] const OfficialAcquisitionResult		&observation() const noexcept ;
	/**
	 * @brief 発行時のstable record fingerprintを同期借用する。
	 * @return 固定resource経路では全zero。Record経路では発行時に固定した値。
	 * @note この値だけで公式性を認定せず、sessionの再照合を必須とする。
	 */
	[[nodiscard]] const OfficialStableRecordFingerprint &recordFingerprint() const noexcept ;
	/**
	 * @brief 所有issuerの生存だけを観測する。公式性や元byteの再確認ではない。
	 * @return 同じissuerが生存中ならtrue、既定・move元・session終了後はfalse。
	 * @note 本値で検証を代替せず、verifyAcquiredFileを必須とする。
	 */
	[[nodiscard]] bool									 issuerAlive() const noexcept ;

private:
	friend class SignedIndexAcquisitionAdapter ;
	/// 原索引grantの独立issuer。公開取得結果から再構築できません。
	std::weak_ptr<const std::byte> signedIndexIssuer_ ;
	friend class OfficialAcquisitionSession ;
	/// 所有sessionの私有issuerへの弱参照。失効・別issuerを拒否する。
	std::weak_ptr<const std::byte>	issuer_ ;
	/// 発行時に私有成功記録から複写したworker限定metadata。
	OfficialAcquisitionResult		observation_ ;
	/// 元workspaceの保護file相対名。外部公開・永続化しない。
	std::wstring					workspaceFileName_ ;
	/// Record限定成功時だけ固定したstable fingerprint。
	OfficialStableRecordFingerprint recordFingerprint_ ;
} ;

/**
 * @brief 検査用file取得が利用する公式source transport境界である。
 */
class IOfficialAcquisitionTransport {
public:
	/**
	 * @brief 多態的な破棄に必要な基底destructorです。
	 * @note この既定本体は操作を開始せず、派生objectのresource解放は各実装が担当します。
	 */
	virtual ~IOfficialAcquisitionTransport() = default ;

	/**
     * @brief 公式source policyを使用して一fileを保存する。
     * @param[in] url 登録済み公式payloadの絶対HTTPS URL。
     * @param[in] resourceId Payload用途の組み込みresource ID。
     * @param[in] maximumBytes 受信を許可する有限byte数。
     * @param[in] outputFile 書込み可能な所有外file handle。
     * @param[in] progressCallback 確定済み受信進捗の通知先。
     * @param[in] cancellationCallback 取消し状態を返す非blocking関数。
     * @return 保存と公式取得根拠記録の成功時は0、失敗時はHRESULT bit pattern。
     */
	[[nodiscard]] virtual NativeError download(
		std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
		HANDLE outputFile, const HttpDownloadProgressCallback &progressCallback,
		const HttpCancellationCallback &cancellationCallback) = 0 ;

	/**
	 * @brief Record限定GETをURL非保持requestから一fileへ保存します。
	 * @param[in,out] request Claim済みgrantと秘密URLを所有する一回request。
	 * @param[in] outputFile 書込み可能な所有外file handle。
	 * @param[in] progressCallback 確定済み受信進捗の通知先。
	 * @param[in] cancellationCallback 取消し状態を返す非blocking関数。
	 * @param[out] destinationEvidence 成功時のURL非保持public宛先根拠。
	 * @return 保存とgrant終端成功時は0、失敗時はHRESULT bit pattern。
	 */
	[[nodiscard]] virtual NativeError downloadDelegated(
		OfficialDelegatedGetRequest &request, HANDLE outputFile,
		const HttpDownloadProgressCallback &progressCallback,
		const HttpCancellationCallback	   &cancellationCallback,
		OfficialPublicDestinationEvidence  &destinationEvidence) = 0 ;

	/**
     * @brief 指定sessionとresourceに有効な公式取得根拠があるか確認する。
     * @param[in] scanSessionId 照合するscan session ID。
     * @param[in] providerId 照合する組み込みProvider ID。
     * @param[in] resourceId 照合するpayload resource ID。
     * @return 取得根拠ledger全体と指定resourceが有効な場合は`true`。
     */
	[[nodiscard]] virtual bool hasSourceEvidence( ScanSessionId	   scanSessionId,
												 std::wstring_view providerId,
												 std::wstring_view resourceId) const noexcept = 0 ;
} ;

/**
 * @brief `OfficialHttpClient`を検査用file取得transportへ接続するadapterである。
 */
class OfficialHttpAcquisitionTransport final : public IOfficialAcquisitionTransport {
public:
	/**
	 * @brief 呼出し側が所有するHTTP clientへの非所有参照を保持する。
	 * HTTP client adapterを初期化する。
	 * Source sessionを所有せず、呼出し側clientへ全処理を委譲する。
	 * @param[in,out] client Adapterより長く有効なsource session開始済みclient。 Adapterより長く有効なHTTP client。
	 */
	explicit OfficialHttpAcquisitionTransport( OfficialHttpClient &client) noexcept ;

	/**
	 * @brief 公式HTTP sourceから検査対象fileを取得する。
	 * 任意hostを受け取らずHTTP clientの組み込みsource policyを使用する。
	 * @param[in] url 登録済み公式payloadの絶対HTTPS URL。
	 * @param[in] resourceId Payload用途resource ID。
	 * @param[in] maximumBytes 受信上限byte数。
	 * @param[in] outputFile 書込み可能な所有外file handle。
	 * @param[in] progressCallback 確定済み受信進捗の通知先。
	 * @param[in] cancellationCallback 取消し状態の確認先。
	 * @return 保存と取得根拠記録の成功時は0、失敗時はHRESULT。
	 * @see drivercrate::IOfficialAcquisitionTransport::download
	 */
	[[nodiscard]] NativeError download(
		std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
		HANDLE outputFile, const HttpDownloadProgressCallback &progressCallback,
		const HttpCancellationCallback &cancellationCallback) override ;

	/**
	 * @brief Record限定GETを共通HTTP clientへ委譲します。
	 * @param[in,out] request Claim済みgrantと秘密URLを所有する一回request。
	 * @param[in] outputFile 書込み可能な所有外file handle。
	 * @param[in] progressCallback 確定済み受信進捗の通知先。
	 * @param[in] cancellationCallback 取消し状態の確認先。
	 * @param[out] destinationEvidence 成功時のURL非保持public宛先根拠。
	 * @return 保存とgrant終端成功時は0、失敗時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError downloadDelegated(
		OfficialDelegatedGetRequest &request, HANDLE outputFile,
		const HttpDownloadProgressCallback &progressCallback,
		const HttpCancellationCallback	   &cancellationCallback,
		OfficialPublicDestinationEvidence  &destinationEvidence) override ;

	/**
	 * @brief HTTP clientの公式取得根拠を照合する。
	 * Adapter独自の根拠を生成せずHTTP clientのledgerを正本にする。
	 * @param[in] scanSessionId 照合するscan session ID。
	 * @param[in] providerId 照合する組み込みProvider ID。
	 * @param[in] resourceId 照合するpayload resource ID。
	 * @return Ledger全体と指定resourceが有効な場合は`true`。
	 * @see drivercrate::IOfficialAcquisitionTransport::hasSourceEvidence
	 */
	[[nodiscard]] bool hasSourceEvidence( ScanSessionId scanSessionId, std::wstring_view providerId,
										 std::wstring_view resourceId) const noexcept override ;

private:
	/// 呼出し側がsource session単位で所有するHTTP client。
	OfficialHttpClient &client_ ;
} ;

/**
 * @brief Machine-wide network costを取得する差替え可能な境界である。
 */
class IOfficialNetworkCostReader {
public:
	/**
	 * @brief 多態的な破棄に必要な基底destructorです。
	 * @note この既定本体は操作を開始せず、派生objectのresource解放は各実装が担当します。
	 */
	virtual ~IOfficialNetworkCostReader() = default ;

	/**
     * @brief 現在のmachine-wide network costを取得する。
     * @param[out] cost 成功時のcost分類。失敗時はUnknown。
     * @return 照会成功時は0、COMまたはOS処理失敗時はHRESULT bit pattern。
     */
	[[nodiscard]] virtual NativeError read( OfficialNetworkCostKind &cost) noexcept = 0 ;
} ;

/**
 * @brief Windows Network List Managerからnetwork costを取得する。
 */
class WindowsOfficialNetworkCostReader final : public IOfficialNetworkCostReader {
public:
	/**
	 * @brief Machine-wide network costを取得する。
	 * 呼出し済みCOM apartment内でNetwork List Managerを使用し、network設定を変更しない。
	 * @param[out] cost 成功時のcost分類。失敗時はUnknown。
	 * @return 照会成功時は0、COMまたはNLM失敗時はHRESULT。
	 * @see drivercrate::IOfficialNetworkCostReader::read
	 */
	[[nodiscard]] NativeError read( OfficialNetworkCostKind &cost) noexcept override ;
} ;

/**
 * @brief 一つのscan sessionで検査用公式fileと容量予算を管理する。
 *
 * @note Provider worker threadだけで直列利用する。取得fileを候補またはinstall対象へ昇格しない。
 */
class OfficialAcquisitionSession final {
public:
	/**
	 * @brief 外部resourceを取得しない空の初期状態を作成します。
	 */
	OfficialAcquisitionSession() = default ;
	/**
	 * @brief 所有する取得session内のmemberを破棄します。
	 * @note 標準memberを解放し、新たなnetwork取得や導入を開始しません。
	 */
	~OfficialAcquisitionSession() = default ;

	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialAcquisitionSession( const OfficialAcquisitionSession &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialAcquisitionSession &operator=( const OfficialAcquisitionSession &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialAcquisitionSession( OfficialAcquisitionSession &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	OfficialAcquisitionSession &operator=( OfficialAcquisitionSession &&) = delete ;

	/**
	 * @brief 空のscan session取得ledgerを有限予算付きで開始する。
	 * 検査用取得sessionを有限予算付きで開始する。
	 * File上限、Provider上限、session上限の包含関係も検証する。
	 * @param[in] scanSessionId 0ではないscan session ID。
	 * @param[in] limits ApplicationとProvider群へ適用する有限上限。 Session全体へ固定する有限予算。
	 * @return 開始成功時は0、再初期化または不正上限時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError	initialize( ScanSessionId					scanSessionId,
										   const OfficialAcquisitionLimits &limits) noexcept ;

	/**
	 * @brief 公式payloadを保護workspaceへ取得して検査対象として固定する。
	 * 公式payloadを取得して検査対象として固定する。
	 * 予算予約、cost、disk、取消し、source根拠、size、SHA-256を順に検証し、成功fileだけをledgerへ計上する。
	 * @param[in] request 公式取得元、公開metadata、今回のnetwork同意。 取得元、上限、公開metadata、network同意。
	 * @param[in,out] workspace 成功fileを所有し、失敗fileを削除する保護領域。 成功fileを所有する保護workspace。
	 * @param[in,out] transport 公式source取得と根拠照合を行う境界。 公式source取得と根拠照合境界。
	 * @param[in,out] costReader Machine-wide network cost照会境界。
	 * @param[in] progressCallback 確定済み受信進捗の通知先。
	 * @param[in] cancellationCallback 空または取消し状態を返す非blocking関数。 空または取消し状態の確認先。
	 * @param[out] result 成功または失敗の監査前状態。URLを含まない。 URLを含まない監査前取得状態。
	 * @return `ACQUIRED_FOR_INSPECTION`到達時は0、それ以外はHRESULT bit pattern。 検査対象固定成功時は0、それ以外はHRESULT。
	 */
	[[nodiscard]] NativeError	acquire( const OfficialAcquisitionRequest   &request,
										OfficialDownloadWorkspace		   &workspace,
										IOfficialAcquisitionTransport	   &transport,
										IOfficialNetworkCostReader		   &costReader,
										const HttpDownloadProgressCallback &progressCallback,
										const HttpCancellationCallback	   &cancellationCallback,
										OfficialAcquisitionResult		   &result) ;

	/**
	 * @brief 最後の成功取得から、元byteを再確認して封印証拠を発行する。
	 * @param[in] workspace 当該取得を今も所有する元workspace。
	 * @param[in] acquisitionId このsessionの最後の成功取得ID。
	 * @param[out] evidence 成功時だけ有効な証拠。失敗時は空。
	 * @return 発行成功0、失効・再入・入力不一致・実byte不一致・例外のHRESULT。
	 * @note 同期worker専用。公開取得結果・bool・JSONを認証入力にしない。
	 */
	[[nodiscard]] NativeError	bindAcquiredFile( const OfficialDownloadWorkspace &workspace,
												 std::uint64_t					  acquisitionId,
												 OfficialAcquiredFileEvidence	 &evidence) const ;
	/**
	 * @brief 封印証拠のissuerと元workspace／原byteを再照合する。
	 * @param[in] evidence 本sessionが発行した改変不能な取得証拠。
	 * @param[in] workspace 元取得を所有し続ける保護領域。
	 * @return 再照合成功0、失効・再入・位置／byte差・例外のHRESULT。
	 * @note 取得・削除・修復・署名認定を行わない。次の成功取得後も発行済みの元証拠だけを照合できる。
	 */
	[[nodiscard]] NativeError	verifyAcquiredFile( const OfficialAcquiredFileEvidence &evidence,
												   const OfficialDownloadWorkspace &workspace) const ;

private:
	/**
     * @brief 一つのProviderが成功取得で消費した容量を保持する。
     */
	struct ProviderUsage {
		/// 組み込みProvider stable ID。
		std::wstring  providerId ;
		/// 成功取得fileの実byte数累計。
		std::uint64_t bytes{} ;
		/// 成功取得file数。
		std::uint32_t files{} ;
	} ;
	friend class CollectorInspectionAcquisition ;
	/** @brief 通常policyと収集private scopeを分けて共通取得する。
	 * @param[in] request 通常またはadapter自身の有限要求。
	 * @param[in,out] workspace 元fileを所有する保護領域。
	 * @param[in,out] transport 同じ公式取得または非通信試験の境界。
	 * @param[in,out] costReader 回線照会。
	 * @param[in] progressCallback 確定byte進捗。
	 * @param[in] cancellationCallback 取消し。
	 * @param[out] result 共通結果。
	 * @param[in] collector Nullは従来policy、非nullは同じ具体adapter。
	 * @return 全固定成功0、拒否HRESULT。
	 * @note 公開boolからscopeを作らず、adapterの私有状態を再照合する。
	 */
	[[nodiscard]] NativeError				 acquireCore( const OfficialAcquisitionRequest	&request,
														 OfficialDownloadWorkspace			&workspace,
														 IOfficialAcquisitionTransport		&transport,
														 IOfficialNetworkCostReader			&costReader,
														 const HttpDownloadProgressCallback &progressCallback,
														 const HttpCancellationCallback		&cancellationCallback,
														 OfficialAcquisitionResult			&result,
														 const CollectorInspectionAcquisition *collector) ;

	/// Provider別の成功取得容量ledger。
	std::vector<ProviderUsage>				 providerUsage_ ;
	/// 生存sessionだけが所有する私有issuer。証拠は弱参照なのでsession終了で失効する。
	std::shared_ptr<const std::byte>		 evidenceIssuer_ ;
	/// 発行対象を最後の成功一件へ限定する私有取得記録。公開結果とは独立所有する。
	std::optional<OfficialAcquisitionResult> lastAcquiredResult_ ;
	/// 最後の成功fileの元相対名。Path再結合用で、外部公開しない。
	std::wstring							 lastAcquiredFileName_ ;
	/// 最後の成功のrecord限定fingerprint。固定resource経路では全zero。
	OfficialStableRecordFingerprint			 lastRecordFingerprint_ ;
	/// 最後の成功が索引grantのときだけ保持する元adapterの弱issuer。
	std::weak_ptr<const std::byte>			 lastSignedIndexIssuer_ ;
	/// 初期化時に固定した有限予算。
	OfficialAcquisitionLimits				 limits_ ;
	/// このobjectが所有するscan session ID。
	ScanSessionId							 scanSessionId_{} ;
	/// 成功取得fileのsession累計byte数。
	std::uint64_t							 sessionBytes_{} ;
	/// 次の成功取得へ割り当てる連番。
	std::uint64_t							 nextAcquisitionId_{1U} ;
	/// 成功取得fileのsession累計数。
	std::uint32_t							 sessionFiles_{} ;
	/// trueの場合は再入取得を拒否する。
	bool									 acquiring_{} ;
} ;

} // namespace drivercrate
