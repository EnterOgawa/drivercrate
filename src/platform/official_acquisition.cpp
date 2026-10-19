//------------------------------------------------------------------------------
/**
 * @file official_acquisition.cpp
 * @brief 公式fileの検査用取得境界実装。
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
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  公開SHA-512の事前検証・必須照合・独立結果を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/06  私有成功記録・issuerと原byte再確認の封印証拠を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/06  収集adapterの一回scopeを通常取得と分離。
 * Ver.01.05.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.05.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * </pre>
 *
 * @note Provider worker threadで公式fileを直列取得し、成功fileだけをsession容量へ計上します。取得物を実行、候補化またはUIへ公開しません。
 */
//------------------------------------------------------------------------------

#include "platform/official_acquisition.h"
#include "platform/collector_inspection_acquisition.h"

#include "core/official_download_delegation.h"
#include "core/official_source_policy.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <netlistmgr.h>
#include <wrl/client.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace drivercrate {
namespace {

// 成功記録のallocation完了後のcommitを例外なしに保つ型の前提。
static_assert( std::is_nothrow_move_assignable_v<OfficialAcquisitionResult>) ;
// Optional成功記録のcommitが旧記録を破壊して例外を出さない前提。
static_assert( std::is_nothrow_move_assignable_v<std::optional<OfficialAcquisitionResult>>) ;

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr DWORD NETWORK_COST_LEVEL_MASK	 = 0x0000ffffU ;	// NLM cost levelを抽出するmask。
constexpr DWORD RESTRICTED_NETWORK_FLAGS =					// 利用者確認を要求するNLM cost flag集合。
	static_cast<DWORD>( NLM_CONNECTION_COST_OVERDATALIMIT) |
	static_cast<DWORD>( NLM_CONNECTION_COST_ROAMING) |
	static_cast<DWORD>( NLM_CONNECTION_COST_APPROACHINGDATALIMIT) ;

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/**
 * @brief HANDLEを一度だけCloseHandleする所有wrapperである。
 */
class FileHandle final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief File handleのownershipを取得する。
     *
     * 呼出し側からhandleのCloseHandle責務を移す。
     *
     * @param[in] value 所有する有効またはINVALID_HANDLE_VALUE。
     */
	//------------------------------------------------------------------------------
	explicit FileHandle( const HANDLE value) noexcept : value_( value)
	{
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 所有中のfile handleを閉じる。
     *
     * 明示closeされていない有効handleだけをbest-effortで閉じる。
     */
	//------------------------------------------------------------------------------
	~FileHandle()
	{
		// 有効な所有handleだけを解放する。
		if( value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
			static_cast<void>( CloseHandle( value_)) ;
		}
	}

	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	FileHandle( const FileHandle &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	FileHandle &operator=( const FileHandle &) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	FileHandle( FileHandle &&) = delete ;
	/**
	 * @brief 所有状態の移動をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	FileHandle			&operator=( FileHandle &&) = delete ;

	//------------------------------------------------------------------------------
	/**
     * @brief 所有中のfile handleを参照する。
     *
     * Ownershipを移さずWin32 API呼出し中だけ値を貸し出す。
     * @return 所有中のHANDLE。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] HANDLE get() const noexcept
	{
		return value_ ;
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 所有中のfile handleを閉じる。
     *
     * CloseHandle前に所有値を無効化し、失敗時も重複closeを防ぐ。
     * @return Close成功または既に空なら0、失敗時はHRESULT。
     */
	//------------------------------------------------------------------------------
	[[nodiscard]] NativeError close() noexcept
	{
		// 所有する有効handleがなければcloseを重ねて呼ばない。
		if( value_ == nullptr || value_ == INVALID_HANDLE_VALUE) {
			return 0 ;
		}

		const HANDLE closing = value_ ;	// 今回だけCloseHandleへ渡す所有handle。
		value_				 = INVALID_HANDLE_VALUE ;
		return CloseHandle( closing) != FALSE
				   ? static_cast<NativeError>( 0)
				   : static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

private:
	/// Close前だけ所有するfile handle。
	HANDLE value_{INVALID_HANDLE_VALUE} ;
} ;

/**
 * @brief Scope終了時に取得中flagを必ず解除する。
 */
class AcquiringGuard final {
public:
	//------------------------------------------------------------------------------
	/**
     * @brief 解除対象flagへの参照を保持する。
     *
     * 呼出し側がtrueに設定済みの再入防止flagを借用する。
     *
     * @param[in,out] acquiring Scope終了時にfalseへ戻すflag。
     */
	//------------------------------------------------------------------------------
	explicit AcquiringGuard( bool &acquiring) noexcept : acquiring_( acquiring)
	{
	}

	//------------------------------------------------------------------------------
	/**
     * @brief 取得中flagを解除する。
     *
     * 全return経路と例外経路で再入防止状態を解除する。
     */
	//------------------------------------------------------------------------------
	~AcquiringGuard()
	{
		acquiring_ = false ;
	}

	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	AcquiringGuard( const AcquiringGuard &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	AcquiringGuard &operator=( const AcquiringGuard &) = delete ;

private:
	/// 呼出し元sessionが所有する再入防止flag。
	bool &acquiring_ ;
} ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief NativeErrorへWin32 errorを変換する。
 *
 * OS診断値をProvider共通の32-bit errorとして保持する。
 *
 * @param[in] error Win32 APIが返したerror code。
 * @return HRESULT_FROM_WIN32で変換したbit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開hashが指定桁ASCII hexか確認する。
 *
 * Separator、prefix、空白またはUnicodeを許可しない。
 *
 * @param[in] value 公開metadataから得たhash表示値。
 * @param[in] characters Algorithmで固定する64または128桁。
 * @return 指定桁ASCII hexだけなら`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidPublishedHash( const std::wstring_view value,
										const std::size_t		characters) noexcept
{
	// Algorithmの固定桁数に合わない期待値を拒否する。
	if( value.size() != characters) {
		return false ;
	}

	return std::all_of( value.begin(), value.end(), []( const wchar_t character) {
		return (character >= L'0' && character <= L'9') ||
			   (character >= L'a' && character <= L'f') || (character >= L'A' && character <= L'F') ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの公開hash ASCII hexを大小文字を除いて比較する。
 *
 * Hex表記差だけを許可し、記号除去や部分一致は行わない。
 *
 * @param[in] left 検証済み64または128桁の公開hash。
 * @param[in] right 検証済み64または128桁の公開hash。
 * @return 大小文字を除く全桁一致時は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool publishedHashEqual( const std::wstring_view left,
									  const std::wstring_view right) noexcept
{
	// 長さの異なるhash文字列を一致とみなさない。
	if( left.size() != right.size()) {
		return false ;
	}

	return std::equal(
		left.begin(), left.end(), right.begin(), []( const wchar_t first, const wchar_t second) {
			const wchar_t normalizedFirst =
				static_cast<wchar_t>( first >= L'A' && first <= L'F' ? first - L'A' + L'a' : first) ;
			const wchar_t normalizedSecond = static_cast<wchar_t>(
				second >= L'A' && second <= L'F' ? second - L'A' + L'a' : second) ;
			return normalizedFirst == normalizedSecond ;
		}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 使用済み量へ予約量を加えても上限内か確認する。
 *
 * 加算前の減算比較によりunsigned overflowを防止する。
 *
 * @param[in] used 既に成功取得へ計上したbyte数。
 * @param[in] planned 今回取得前に予約するbyte数。
 * @param[in] limit 累計へ許可する有限上限byte数。
 * @return Overflowせず上限内へ収まる場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool fitsByteLimit( const std::uint64_t used, const std::uint64_t planned,
								 const std::uint64_t limit) noexcept
{
	return used <= limit && planned <= limit - used ;
}

//------------------------------------------------------------------------------
/**
 * @brief 取消しcallbackを例外境界付きで確認する。
 *
 * 取得処理から任意のcallback例外を漏らさない。
 *
 * @param[in] callback 空または取消し状態を返す非blocking関数。
 * @param[out] cancelled Callbackがtrueを返した場合true。
 * @return 確認成功時は0、callback例外時はE_UNEXPECTED。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError queryCancellation( const HttpCancellationCallback &callback,
											bool						   &cancelled) noexcept
{
	cancelled = false ;
	// 任意の取消しcallbackが未指定なら取消し照会を省略する。
	if( !callback) {
		return 0 ;
	}

	try {
		cancelled = callback() ;
		return 0 ;
	} catch( ...) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 失敗したworkspace fileを直ちに破棄する。
 *
 * Partial fileを残すcleanup失敗を元の処理失敗より優先する。
 *
 * @param[in,out] workspace 対象fileを所有する保護workspace。
 * @param[in] name `createFile`へ渡した相対path。
 * @param[in] primaryError 破棄前に確定した失敗理由。
 * @return 破棄失敗時はそのHRESULT、それ以外はprimaryError。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError discardFailedFile( OfficialDownloadWorkspace &workspace,
											const std::wstring_view	   name,
											const NativeError		   primaryError)
{
	try {
		const NativeError discardError = workspace.discardFile( name) ;	// Partial file削除結果。
		return discardError != 0 ? discardError : primaryError ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		// Cleanup境界から型不明例外を漏らさず、destructorの再試行対象を維持する。
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Network cost分類値が定義内か確認する。
 *
 * Fakeを含む境界から未定義値が入った場合は取得を拒否する。
 *
 * @param[in] cost Cost readerが返した分類。
 * @return 定義済み列挙値の場合は`true`。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidNetworkCost( const OfficialNetworkCostKind cost) noexcept
{
	return cost == OfficialNetworkCostKind::UNKNOWN ||
		   cost == OfficialNetworkCostKind::UNRESTRICTED ||
		   cost == OfficialNetworkCostKind::RESTRICTED ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialHttpAcquisitionTransport::OfficialHttpAcquisitionTransport(
	OfficialHttpClient &client) noexcept
	: client_( client)
{
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpAcquisitionTransport::download(
	const std::wstring_view url, const std::wstring_view resourceId,
	const std::uint64_t maximumBytes, const HANDLE outputFile,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback	   &cancellationCallback)
{
	return client_.downloadForSource( url, resourceId, maximumBytes, outputFile, progressCallback,
									 cancellationCallback) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialHttpAcquisitionTransport::downloadDelegated(
	OfficialDelegatedGetRequest &request, const HANDLE outputFile,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback	   &cancellationCallback,
	OfficialPublicDestinationEvidence  &destinationEvidence)
{
	return client_.downloadDelegatedGet( request, outputFile, progressCallback, cancellationCallback,
										destinationEvidence) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool OfficialHttpAcquisitionTransport::hasSourceEvidence(
	const ScanSessionId scanSessionId, const std::wstring_view providerId,
	const std::wstring_view resourceId) const noexcept
{
	return client_.hasSourceEvidence( scanSessionId, providerId, resourceId) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError WindowsOfficialNetworkCostReader::read( OfficialNetworkCostKind &cost) noexcept
{
	cost = OfficialNetworkCostKind::UNKNOWN ;
	Microsoft::WRL::ComPtr<INetworkListManager> manager ;	// NLM COM entry point。
	HRESULT result = CoCreateInstance( __uuidof( NetworkListManager), nullptr, CLSCTX_ALL,
									  // NLM生成結果。
									  IID_PPV_ARGS( &manager)) ;
	// 失敗の診断値を共通の表現へ保ったまま返し、未完了の結果で後続処理を進めない。
	if( FAILED( result)) {
		return static_cast<NativeError>( result) ;
	}

	Microsoft::WRL::ComPtr<INetworkCostManager> costManager ;	// Cost照会interface。
	result = manager.As( &costManager) ;
	// 失敗の診断値を共通の表現へ保ったまま返し、未完了の結果で後続処理を進めない。
	if( FAILED( result)) {
		return static_cast<NativeError>( result) ;
	}

	DWORD rawCost{} ;	// NLM_CONNECTION_COSTのlevelとflag集合。
	result = costManager->GetCost( &rawCost, nullptr) ;
	// 失敗の診断値を共通の表現へ保ったまま返し、未完了の結果で後続処理を進めない。
	if( FAILED( result)) {
		return static_cast<NativeError>( result) ;
	}

	const DWORD costLevel  = rawCost & NETWORK_COST_LEVEL_MASK ;	// 下位16-bitのcost level。
	const bool	restricted =										// 課金、data上限またはroamingを伴う場合true。
		costLevel == static_cast<DWORD>( NLM_CONNECTION_COST_FIXED) ||
		costLevel == static_cast<DWORD>( NLM_CONNECTION_COST_VARIABLE) ||
		(rawCost & RESTRICTED_NETWORK_FLAGS) != 0U ;
	// 制限付きの接続費用を明示同意が必要な区分にする。
	if( restricted) {
		cost = OfficialNetworkCostKind::RESTRICTED ;
	}
	// 無制限が明示された接続だけを無制限区分にする。
	else if( costLevel == static_cast<DWORD>( NLM_CONNECTION_COST_UNRESTRICTED)) {
		cost = OfficialNetworkCostKind::UNRESTRICTED ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialAcquisitionSession::initialize( const ScanSessionId				scanSessionId,
												   const OfficialAcquisitionLimits &limits) noexcept
{
	// 多重sessionや不正な件数・byte予算の関係を開始前に拒否する。
	if( scanSessionId_ != 0U || acquiring_ || scanSessionId == 0U || limits.maximumFileBytes == 0U ||
	   limits.maximumProviderBytes == 0U || limits.maximumSessionBytes == 0U ||
	   limits.maximumProviderFiles == 0U || limits.maximumSessionFiles == 0U ||
	   limits.maximumFileBytes > limits.maximumProviderBytes ||
	   limits.maximumProviderBytes > limits.maximumSessionBytes ||
	   limits.maximumProviderFiles > limits.maximumSessionFiles) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		evidenceIssuer_ = std::make_shared<const std::byte>( std::byte{}) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		// issuerを作れないsessionを開始済みにしない。
		return E_UNEXPECTED ;
	}

	limits_		   = limits ;
	scanSessionId_ = scanSessionId ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError OfficialAcquisitionSession::acquire(
	const OfficialAcquisitionRequest &request, OfficialDownloadWorkspace &workspace,
	IOfficialAcquisitionTransport &transport, IOfficialNetworkCostReader &costReader,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback &cancellationCallback, OfficialAcquisitionResult &result)
{
	return acquireCore( request, workspace, transport, costReader, progressCallback,
					   cancellationCallback, result, nullptr) ;
}

/** @see OfficialAcquisitionSession 宣言側の契約を正本とする。 */
NativeError OfficialAcquisitionSession::acquireCore(
	const OfficialAcquisitionRequest &request, OfficialDownloadWorkspace &workspace,
	IOfficialAcquisitionTransport &transport, IOfficialNetworkCostReader &costReader,
	const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback &cancellationCallback, OfficialAcquisitionResult &result,
	const CollectorInspectionAcquisition *collector)
{
	result = {} ;
	// sessionなし、または別取得の実行中に新しい取得を開始しない。
	if( scanSessionId_ == 0U || acquiring_) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		return result.error ;
	}

	acquiring_ = true ;
	AcquiringGuard acquiringGuard( acquiring_) ;	// 全終了経路で再入防止flagを解除するguard。

	const bool	   delegatedSource =
		request.delegatedGrant != nullptr ;	// Record限定grantを唯一の取得権限にする場合true。
	const bool fixedSource =				// 従来の固定payload要求だけを持つ場合true。
		!delegatedSource && !request.url.empty() && request.delegatedGrantId == 0U &&
		!request.delegatedUtcNow ;
	const bool delegatedShape =	// Record限定要求に固定URL経路の権限値が混在しない場合true。
		delegatedSource && request.url.empty() && request.providerId.empty() &&
		request.resourceId.empty() && request.maximumFileBytes == 0U &&
		!request.publishedSize.has_value() && request.publishedSha256.empty() &&
		request.publishedSha512.empty() && request.delegatedGrantId != 0U &&
		request.delegatedUtcNow ;
	// 固定URLまたはRecord限定のどちらか一方だけを受理し、保存名と通知先を共通検証する。
	if( (!fixedSource && !delegatedShape) || request.workspaceFileName.empty() ||
	   !progressCallback) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result.error ;
	}

	std::wstring_view providerId = request.providerId ;	// Grantまたは固定要求が拘束するProvider ID。
	std::wstring_view resourceId = request.resourceId ;	// Grantまたは固定要求が拘束するpayload ID。
	std::uint64_t	  maximumFileBytes =				// 今回のpayload受信上限。
		request.maximumFileBytes ;
	std::optional<std::uint64_t> publishedSize =	// 公式recordのexact size。
		request.publishedSize ;
	std::wstring_view publishedSha256 =	// 公式recordの公開SHA-256。
		request.publishedSha256 ;
	std::wstring_view publishedSha512 = request.publishedSha512 ;		// 公式公開SHA-512。
	const RecordScopedDownloadGrantMetadata *grantMetadata = nullptr ;	// Record限定取得のbinding。
	// Record限定取得では公開要求値を信用せず、未使用grantから権限と検証値を導出する。
	if( delegatedSource) {
		grantMetadata = &request.delegatedGrant->metadata() ;
		const RecordScopedDownloadGrantPayloadView payload =
			// Grantが固定したURL非保持payload view。
			request.delegatedGrant->payloadView() ;
		// 現在sessionの未使用GET grantだけをfile予算とsource policyへ接続する。
		if( grantMetadata->state != OfficialDownloadGrantState::GRANT_ISSUED ||
		   grantMetadata->scanSessionId != scanSessionId_ ||
		   grantMetadata->grantId != request.delegatedGrantId ||
		   grantMetadata->method != OfficialDownloadGrantMethod::GET) {
			result.state = OfficialAcquisitionState::REJECTED ;
			result.error = static_cast<NativeError>( E_ACCESSDENIED) ;
			return result.error ;
		}

		providerId		 = grantMetadata->providerId ;
		resourceId		 = payload.resourceId ;
		maximumFileBytes = payload.maximumBytes ;
		publishedSize	 = payload.publishedSizeBytes ;
		publishedSha256	 = payload.publishedSha256 ;
		publishedSha512	 = payload.publishedSha512 ;
	}

	const OfficialSourcePolicy *const policy =
		// Providerの組み込みpolicy。
		officialSourcePolicyForProvider( providerId) ;
	const OfficialSourceResourcePolicy *const resource =
		policy == nullptr
			? nullptr
			: findOfficialSourceResource( *policy, resourceId) ;	// 取得対象resource policy。
	const bool validHash =											// 公開hashが空または各algorithmの厳密なhexならtrue。
		(publishedSha256.empty() || isValidPublishedHash( publishedSha256, 64U)) &&
		(publishedSha512.empty() || isValidPublishedHash( publishedSha512, 128U)) ;
	const bool collectorScope =
		collector != nullptr &&
		static_cast<const IOfficialAcquisitionTransport *>( collector) == &transport &&
		// 同じ具体adapterの私有scopeだけ。
		collector->matches( scanSessionId_, request) ;
	const bool signedIndexOrigin =
		delegatedSource &&
		grantMetadata->origin ==
			OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION ;	// 索引由来の明示分類。
	const bool signedIndexScope =
		signedIndexOrigin && request.delegatedGrant->validateSignedIndexAuthority( scanSessionId_) ==
								 0 ;	// 私有封印の再照合。
	// 取得先、固定resource、保存名、上限、期待size・hash、通知先を事前検証する。
	if( providerId.empty() || resourceId.empty() || maximumFileBytes == 0U ||
	   maximumFileBytes > limits_.maximumFileBytes || !validHash ||
	   (publishedSize.has_value() && (*publishedSize == 0U || *publishedSize > maximumFileBytes)) ||
	   (collector != nullptr ? !collectorScope
		: signedIndexOrigin
			? !signedIndexScope
			: resource == nullptr || resource->kind != OfficialSourceResourceKind::PAYLOAD)) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result.error ;
	}

	bool		cancelled{} ;	// 現在確認時点で利用者が取消しを要求した場合true。
	NativeError cancellationError =
		// Preflight取消し確認結果。
		queryCancellation( cancellationCallback, cancelled) ;
	// 取消しと取消し照会失敗を区別し、取得開始前に返す。
	if( cancellationError != 0 || cancelled) {
		result.state =
			cancelled ? OfficialAcquisitionState::CANCELLED : OfficialAcquisitionState::FAILURE ;
		result.error = cancelled ? nativeErrorFromWin32( ERROR_CANCELLED) : cancellationError ;
		return result.error ;
	}

	OfficialNetworkCostKind networkCost = OfficialNetworkCostKind::UNKNOWN ;	// 現在cost分類。
	NativeError networkCostError = costReader.read( networkCost) ;				// Machine-wide cost照会結果。
	// 定義外の通信費用区分を無制限とみなさず不明へ落とす。
	if( !isValidNetworkCost( networkCost)) {
		networkCost		 = OfficialNetworkCostKind::UNKNOWN ;
		networkCostError = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	result.networkCost		= networkCost ;
	result.networkCostError = networkCostError ;
	// 通信費用が無制限と確認できない場合は明示同意を要求する。
	if( (networkCostError != 0 || networkCost != OfficialNetworkCostKind::UNRESTRICTED) &&
	   !request.restrictedNetworkApproved) {
		result.state = OfficialAcquisitionState::AWAITING_NETWORK_CONSENT ;
		result.error = static_cast<NativeError>( E_ACCESSDENIED) ;
		return result.error ;
	}

	ProviderUsage *providerUsage = nullptr ;	// 今回Providerの成功取得累計entry。
	// usageは既存Provider entryからstable ID完全一致で検索する。
	for( ProviderUsage &usage : providerUsage_) {
		// 要求Providerの既存利用量を探して予算検査へ使う。
		if( usage.providerId == providerId) {
			providerUsage = &usage ;
			break ;
		}
	}

	// 初めて取得するProviderには独立した利用量記録を作る。
	if( providerUsage == nullptr) {
		try {
			providerUsage_.push_back( ProviderUsage{.providerId = std::wstring( providerId)}) ;
			providerUsage = &providerUsage_.back() ;
		} catch( const std::bad_alloc &) {
			result.state = OfficialAcquisitionState::FAILURE ;
			result.error = static_cast<NativeError>( E_OUTOFMEMORY) ;
			return result.error ;
		}
	}

	const std::uint64_t plannedBytes =	// 公開sizeまたはProvider上限による予約byte数。
		publishedSize.value_or( maximumFileBytes) ;
	// Provider別とsession全体のfile数・byte予算を取得前に守る。
	if( providerUsage->files >= limits_.maximumProviderFiles ||
	   sessionFiles_ >= limits_.maximumSessionFiles ||
	   !fitsByteLimit( providerUsage->bytes, plannedBytes, limits_.maximumProviderBytes) ||
	   !fitsByteLimit( sessionBytes_, plannedBytes, limits_.maximumSessionBytes)) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = nativeErrorFromWin32( ERROR_BUFFER_OVERFLOW) ;
		return result.error ;
	}

	std::uint64_t	  availableBytes{} ;											// Workspace volumeで利用可能な現在byte数。
	const NativeError diskError = workspace.queryAvailableBytes( availableBytes) ;	// 照会結果。
	// 空き容量の取得失敗時は容量を推測してdownloadしない。
	if( diskError != 0) {
		result.state = OfficialAcquisitionState::FAILURE ;
		result.error = diskError ;
		return result.error ;
	}

	// 取得予定量を保存しても最低空き容量が残ることを要求する。
	if( limits_.minimumFreeBytes > availableBytes ||
	   plannedBytes > availableBytes - limits_.minimumFreeBytes) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = nativeErrorFromWin32( ERROR_DISK_FULL) ;
		return result.error ;
	}

	cancellationError =
		// File作成前の取消し確認結果。
		queryCancellation( cancellationCallback, cancelled) ;
	// 容量確認後も取消しを再照会し、取消し済みのfileを作成しない。
	if( cancellationError != 0 || cancelled) {
		result.state =
			cancelled ? OfficialAcquisitionState::CANCELLED : OfficialAcquisitionState::FAILURE ;
		result.error = cancelled ? nativeErrorFromWin32( ERROR_CANCELLED) : cancellationError ;
		return result.error ;
	}

	HANDLE		createdFile = INVALID_HANDLE_VALUE ;	// Workspaceからownershipを受け取るfile handle。
	NativeError createError{} ;							// CREATE_NEWとworkspace追跡の処理結果。
	try {
		createError = workspace.createFile( request.workspaceFileName, createdFile) ;
	} catch( const std::bad_alloc &) {
		createError = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		// Workspace境界の型不明例外をworkerへ漏らさず、scope cleanupへ委ねる。
		createError = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	// 保護workspaceの出力fileを作れなければ取得を中止する。
	if( createError != 0) {
		result.state = OfficialAcquisitionState::FAILURE ;
		result.error = createError ;
		return result.error ;
	}

	FileHandle					file( createdFile) ;		// 全return経路でhandleを閉じる所有wrapper。
	OfficialDelegatedGetRequest delegatedRequest ;			// Record限定grantと秘密URLの一回取得所有者。
	OfficialPublicDestinationEvidence destinationEvidence ;	// URL非保持のpublic宛先根拠。
	NativeError						  operationError{} ;	// 公式source取得と根拠記録結果。
	try {
		// Record限定経路はfile作成後の時刻でclaimし、秘密URLを共通HTTP境界だけへ渡す。
		if( delegatedSource) {
			const std::uint64_t nowUtcSeconds =
				// Claim直前のworker UTC秒。
				request.delegatedUtcNow() ;
			operationError =
				delegatedRequest.prepare( *request.delegatedGrant, scanSessionId_,
										 request.delegatedGrantId, nowUtcSeconds, plannedBytes) ;
			// Claimが成功したrequestだけをRecord限定downloadへ渡す。
			if( operationError == 0) {
				operationError =
					transport.downloadDelegated( delegatedRequest, file.get(), progressCallback,
												cancellationCallback, destinationEvidence) ;
			}
		}
		// 固定URL経路は従来どおり組み込みpayload resourceへ限定する。
		else {
			operationError = transport.download( request.url, resourceId, plannedBytes, file.get(),
												progressCallback, cancellationCallback) ;
		}
	} catch( const std::bad_alloc &) {
		operationError = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		// 差替えtransportの例外をworker境界へ漏らさず、partial fileを必ず破棄する。
		operationError = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	LARGE_INTEGER fileSize{} ;	// Download完了後の実file byte数。
	// 取得が成功した場合に実file sizeを確認し、照会失敗を保持する。
	if( operationError == 0 && GetFileSizeEx( file.get(), &fileSize) == FALSE) {
		operationError = nativeErrorFromWin32( GetLastError()) ;
	}

	const NativeError closeError = file.close() ;	// Hash計算前のfile close結果。
	// 先行取得失敗がない場合だけclose失敗を最終診断へ反映する。
	if( operationError == 0 && closeError != 0) {
		operationError = closeError ;
	}

	// 取得失敗または取消し時は部分fileを破棄して状態を区別する。
	if( operationError != 0) {
		result.state = operationError == nativeErrorFromWin32( ERROR_CANCELLED)
						   ? OfficialAcquisitionState::CANCELLED
						   : OfficialAcquisitionState::FAILURE ;
		result.error = discardFailedFile( workspace, request.workspaceFileName, operationError) ;
		return result.error ;
	}

	// 空または計画量超過の取得fileを破棄する。
	if( fileSize.QuadPart <= 0 || static_cast<std::uint64_t>( fileSize.QuadPart) > plannedBytes) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = discardFailedFile( workspace, request.workspaceFileName,
										 nativeErrorFromWin32( ERROR_FILE_TOO_LARGE)) ;
		return result.error ;
	}

	const std::uint64_t actualBytes =	// 正で上限内と確認した取得file byte数。
		static_cast<std::uint64_t>( fileSize.QuadPart) ;
	// 公開sizeがある場合は実byte数の完全一致を要求する。
	if( publishedSize.has_value() && actualBytes != *publishedSize) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = discardFailedFile( workspace, request.workspaceFileName,
										 nativeErrorFromWin32( ERROR_BAD_LENGTH)) ;
		return result.error ;
	}

	const bool sourceEvidenceValid =	// 取得variantごとに要求する公式source根拠が揃う場合true。
		delegatedSource
			? grantMetadata != nullptr &&
				  grantMetadata->state == OfficialDownloadGrantState::CONSUMED &&
				  grantMetadata->outcome == OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION &&
				  destinationEvidence.locallyResolved && destinationEvidence.addressCount != 0U &&
				  (!signedIndexOrigin ||
				   request.delegatedGrant->validateSignedIndexAuthority( scanSessionId_) == 0)
			: transport.hasSourceEvidence( scanSessionId_, providerId, resourceId) ;
	// session・Provider・resourceに結び付く取得証拠がないfileを破棄する。
	if( !sourceEvidenceValid) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = discardFailedFile( workspace, request.workspaceFileName,
										 static_cast<NativeError>( E_ACCESSDENIED)) ;
		return result.error ;
	}

	std::wstring inspectionPath ;	// 後続system監査だけに渡す保護workspace path。
	try {
		inspectionPath = workspace.path( request.workspaceFileName) ;
	} catch( const std::bad_alloc &) {
		result.state = OfficialAcquisitionState::FAILURE ;
		result.error = discardFailedFile( workspace, request.workspaceFileName,
										 static_cast<NativeError>( E_OUTOFMEMORY)) ;
		return result.error ;
	}

	// 検査対象pathを解決できない内部不整合では取得fileを破棄する。
	if( inspectionPath.empty()) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = discardFailedFile( workspace, request.workspaceFileName,
										 static_cast<NativeError>( E_UNEXPECTED)) ;
		return result.error ;
	}

	std::wstring	  actualSha256 ;	// 取得直後に固定する64桁小文字SHA-256。
	const NativeError hashError =
		// Local hash計算結果。
		computeFileSha256( inspectionPath, actualSha256) ;
	// 実fileのhashを取得できなければ検査対象として保持しない。
	if( hashError != 0) {
		result.state = OfficialAcquisitionState::FAILURE ;
		result.error = discardFailedFile( workspace, request.workspaceFileName, hashError) ;
		return result.error ;
	}

	// 公開SHA-256と実fileの不一致を検出したら取得fileを破棄する。
	if( !publishedSha256.empty() && !publishedHashEqual( publishedSha256, actualSha256)) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = discardFailedFile( workspace, request.workspaceFileName,
										 nativeErrorFromWin32( ERROR_CRC)) ;
		return result.error ;
	}

	// 公開SHA-512はSHA-256と独立に必須照合し、片方の成功で不一致を隠さない。
	if( !publishedSha512.empty()) {
		std::wstring	  actualSha512 ;	// 取得fileの一時SHA-512。
		const NativeError sha512Error =
			// 共通stream計算。
			computeFileSha512( inspectionPath, actualSha512) ;
		// 計算失敗と公開値不一致のどちらもfileを破棄する。
		if( sha512Error != 0 || !publishedHashEqual( publishedSha512, actualSha512)) {
			result.state = sha512Error != 0 ? OfficialAcquisitionState::FAILURE
											: OfficialAcquisitionState::REJECTED ;
			result.error =
				discardFailedFile( workspace, request.workspaceFileName,
								  sha512Error != 0 ? sha512Error : nativeErrorFromWin32( ERROR_CRC)) ;
			return result.error ;
		}
	}

	try {
		OfficialAcquisitionResult completed ;	// Allocation成功後だけ公開する完成結果。
		completed.state					  = OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ;
		completed.networkCostError		  = networkCostError ;
		completed.networkCost			  = networkCost ;
		completed.scanSessionId			  = scanSessionId_ ;
		completed.acquisitionId			  = nextAcquisitionId_ ;
		completed.providerId			  = providerId ;
		completed.resourceId			  = resourceId ;
		completed.inspectionPath		  = inspectionPath ;
		completed.byteCount				  = actualBytes ;
		completed.sha256				  = std::move( actualSha256) ;
		completed.publishedSizeVerified	  = publishedSize.has_value() ;
		completed.publishedSha256Verified = !publishedSha256.empty() ;
		completed.publishedSha512Verified = !publishedSha512.empty() ;
		// Record限定取得ではURLなしの結合証拠だけを後続監査へ渡す。
		if( delegatedSource) {
			completed.delegatedRecord				   = true ;
			completed.recordOrigin					   = grantMetadata->origin ;
			completed.recordEvidenceId				   = grantMetadata->recordEvidenceId ;
			completed.downloadGrantId				   = grantMetadata->grantId ;
			completed.grantReresolutionCount		   = grantMetadata->reresolutionCount ;
			completed.validatedDestinationAddressCount = destinationEvidence.addressCount ;
			completed.destinationLocallyResolved	   = destinationEvidence.locallyResolved ;
		}

		OfficialAcquisitionResult retained = completed ;	// 公開結果の変更から独立した私有成功記録。
		std::wstring fileName( request.workspaceFileName) ;	// Allocationをcommit前に完了する。
		OfficialStableRecordFingerprint fingerprint ;		// 固定resourceは全zeroを維持する。
		// 取得前に固定したrecordと成功grantの同じfingerprintを保存する。
		if( delegatedSource) {
			fingerprint = grantMetadata->recordFingerprint ;
		}

		result				   = std::move( completed) ;
		lastAcquiredResult_	   = std::move( retained) ;
		lastAcquiredFileName_  = std::move( fileName) ;
		lastRecordFingerprint_ = fingerprint ;
		lastSignedIndexIssuer_ = signedIndexOrigin ? request.delegatedGrant->signedIndexIssuer_
												   : std::weak_ptr<const std::byte>{} ;
		// 結果構築が完了したfileだけを成功予算と単調増加IDへ反映する。
		providerUsage->bytes += actualBytes ;
		++providerUsage->files ;
		sessionBytes_ += actualBytes ;
		++sessionFiles_ ;
		++nextAcquisitionId_ ;
	} catch( const std::bad_alloc &) {
		result		 = {} ;
		result.state = OfficialAcquisitionState::FAILURE ;
		result.error = discardFailedFile( workspace, request.workspaceFileName,
										 static_cast<NativeError>( E_OUTOFMEMORY)) ;
		return result.error ;
	}

	return 0 ;
}

/** @see OfficialAcquiredFileEvidence 宣言側の契約を正本とする。 */
const OfficialAcquisitionResult &OfficialAcquiredFileEvidence::observation() const noexcept
{
	return observation_ ;
}

/** @see OfficialAcquiredFileEvidence 宣言側の契約を正本とする。 */
const OfficialStableRecordFingerprint &OfficialAcquiredFileEvidence::recordFingerprint()
	const noexcept
{
	return recordFingerprint_ ;
}

/** @see OfficialAcquiredFileEvidence 宣言側の契約を正本とする。 */
bool OfficialAcquiredFileEvidence::issuerAlive() const noexcept
{
	return !issuer_.expired() ;
}

/** @see OfficialAcquisitionSession 宣言側の契約を正本とする。 */
NativeError OfficialAcquisitionSession::bindAcquiredFile(
	const OfficialDownloadWorkspace &workspace, const std::uint64_t acquisitionId,
	OfficialAcquiredFileEvidence &evidence) const
{
	evidence = {} ;
	// 再入中や私有記録にない公開IDからは証拠を作らない。
	if( acquiring_ || !evidenceIssuer_ || !lastAcquiredResult_.has_value() || acquisitionId == 0U ||
	   lastAcquiredResult_->acquisitionId != acquisitionId) {
		return E_ACCESSDENIED ;
	}

	try {
		OfficialAcquiredFileEvidence bound ;	// 発行成功まで局所所有する非複写証拠。
		bound.issuer_			 = evidenceIssuer_ ;
		bound.observation_		 = *lastAcquiredResult_ ;
		bound.workspaceFileName_ = lastAcquiredFileName_ ;
		bound.recordFingerprint_ = lastRecordFingerprint_ ;
		bound.signedIndexIssuer_ = lastSignedIndexIssuer_ ;
		const auto error = verifyAcquiredFile( bound, workspace) ;	// 元位置と実byteを再照合する。
		// 不完全な証拠は出力へ移さない。
		if( error != 0) {
			return error ;
		}

		evidence = std::move( bound) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		// issuerや元pathの不明な例外を証拠発行成功へ弱めない。
		return E_UNEXPECTED ;
	}
}

/** @see OfficialAcquisitionSession 宣言側の契約を正本とする。 */
NativeError OfficialAcquisitionSession::verifyAcquiredFile(
	const OfficialAcquiredFileEvidence &evidence, const OfficialDownloadWorkspace &workspace) const
{
	// 生存issuerの同一性は、数値session IDの一致とは別に必須とする。
	if( acquiring_ || !evidenceIssuer_ || evidence.issuer_.lock() != evidenceIssuer_ ||
	   evidence.observation_.scanSessionId != scanSessionId_ ||
	   evidence.observation_.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   evidence.observation_.error != 0 || evidence.observation_.acquisitionId == 0U) {
		return E_ACCESSDENIED ;
	}

	try {
		// 別workspaceや元相対名の付替えは同hashであっても許可しない。
		if( workspace.path( evidence.workspaceFileName_) != evidence.observation_.inspectionPath) {
			return E_ACCESSDENIED ;
		}

		const HANDLE opened =
			CreateFileW( evidence.observation_.inspectionPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
						nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
						nullptr) ;	// 原byte照合中の既存writerと差替えを拒否する。
		// 有効handleを取得できない元診断を保持する。
		if( opened == INVALID_HANDLE_VALUE) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		FileHandle				   file( opened) ;	// 原byte照合が終わるまでleafを固定する同期所有者。
		BY_HANDLE_FILE_INFORMATION information{} ;	// 通常disk fileとleaf種別の実観測。
		// 属性照会不能を旧hashで補完しない。
		if( !GetFileInformationByHandle( file.get(), &information)) {
			return nativeErrorFromWin32( GetLastError()) ;
		}

		// 親directoryの認証は後続archive adapterで行い、ここでもleaf再解釈を許可しない。
		if( GetFileType( file.get()) != FILE_TYPE_DISK ||
		   (information.dwFileAttributes &
			(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
			return E_ACCESSDENIED ;
		}

		const auto error =
			verifyOfficialFileMetadata( evidence.observation_.inspectionPath,
									   {evidence.observation_.byteCount,
										evidence.observation_.sha256}) ;	// 共通CNG照合を共有する。
		const auto closeError = file.close() ;								// 先行診断がない場合だけclose失敗を返す。
		return error != 0 ? error : closeError ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		// 元fileの照合不能を旧成功記録で補完しない。
		return E_UNEXPECTED ;
	}
}

} // namespace drivercrate
