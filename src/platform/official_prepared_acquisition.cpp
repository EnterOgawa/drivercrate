//------------------------------------------------------------------------------
/**
 * @file official_prepared_acquisition.cpp
 * @brief 承認済み配布物の再確認と共通取得。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  ASIX配布IDと算出許諾本文識別子を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  配布物の再確認付き取得を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Snapshot変更・本文不一致・取消しではpayloadを取得せず、既存の公式監査境界を維持します。
 */
//------------------------------------------------------------------------------

#include "platform/official_prepared_acquisition.h"
#include "core/official_preparation.h"
#include "core/official_source_policy.h"
#include "platform/official_download_workspace.h"
#include <Windows.h>
#include <array>
#include <bcrypt.h>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
namespace drivercrate {
namespace {
//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view ASIX_DOWNLOAD_PREFIX =
	L"https://www.asix.com.tw/en/support/download/file/" ;	// ASIXの固定配布endpoint。
constexpr std::wstring_view COMPUTED_REVISION_PREFIX =
	L"DriverCrate content SHA-256: " ;							// Vendor公表revisionと区別する表示prefix。
constexpr std::size_t SHA256_BYTES					  = 32U ;	// SHA-256 digestの固定byte数。
constexpr std::size_t MAXIMUM_PREPARED_URL_CHARACTERS = 512U ;	// 取得前に許可するURL文字数上限。

//------------------------------------------------------------------------------
/**
 * @brief URLはUI側の値を使わず、取得元定義と既存取得policyへ委ねる。
 *
 * @param[in] task Claim済みの対象token。
 * @param[in] expected workerが固定した対象snapshot。
 * @param[in] retained 同じ対象の公式配布情報。
 * @return 全snapshotと許諾条件が整合する場合true。
 */
//------------------------------------------------------------------------------
bool				  matchesPreparedRelease( const OfficialPreparationTask	 &task,
											 const OfficialPreparationTarget &expected,
											 const OfficialReleaseRecord	 &retained) noexcept
{
	const OfficialSourceDefinition *const source =
		// 組み込み定義への非所有参照。
		officialSourceDefinition( retained.family) ;
	// 未結合の対象や別sourceへの承認転用を拒否する。
	if( task.operationId == 0 || task.scanSessionId == 0 || task.planId == 0 ||
	   task.target != expected || source == nullptr || expected.providerId != source->providerId ||
	   expected.resourceId != OFFICIAL_PAYLOAD_RESOURCE_ID || expected.maximumBytes == 0 ||
	   expected.parserRevision == 0 || expected.parserRevision != retained.parserRevision ||
	   expected.identity.empty() || expected.releaseIdentity.empty() ||
	   retained.downloadUrl.empty() || !validPreparedReleaseIdentity( retained)) {
		return false ;
	}

	// 同意必須の準備要求では、保持した EULA の内容と revision の一致を必須とする。
	if( expected.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED) {
		return retained.license == OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD &&
			   !expected.eulaRevision.empty() && expected.eulaRevision == retained.eulaRevision &&
			   expected.eulaText == retained.eulaText &&
			   validPreparationEulaText( expected.eulaText) ;
	}

	return expected.terms == OfficialPreparationTerms::CONFIRMED_NO_CONSENT &&
		   retained.license == OfficialReleaseLicense::CONFIRMED_NO_CONSENT &&
		   expected.eulaRevision.empty() && retained.eulaRevision.empty() &&
		   expected.eulaText.empty() && retained.eulaText.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief Path・hashをUI結果へ含めず、取得を内容監査や導入成功へ昇格させない。
 *
 * @param[in] error 共通取得層の戻り値。
 * @param[in] task 上限を固定した承認済みtask。
 * @param[in] acquisition 共通取得層が返したworker専用結果。
 * @return 取得状態と診断値。矛盾する成功は拒否する。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult acquisitionTransferResult(
	const NativeError error, const OfficialPreparationTask &task,
	const OfficialAcquisitionResult &acquisition)
{
	// 戻り値と取得結果の状態・size・session・取得元が矛盾する結果は拒否する。
	if( error != acquisition.error ||
	   (error == 0 &&
		(acquisition.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
		 acquisition.byteCount == 0 || acquisition.byteCount > task.target.maximumBytes ||
		 acquisition.scanSessionId != task.scanSessionId ||
		 acquisition.providerId != task.target.providerId ||
		 acquisition.resourceId != task.target.resourceId))) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_UNEXPECTED), 0} ;
	}

	// 取得成功は内容監査待ちとして返し、導入成功へ昇格させない。
	if( error == 0) {
		return {OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION, 0, acquisition.byteCount} ;
	}

	// 失敗を表すはずの診断値が正数なら内部契約の不整合として拒否する。
	if( error > 0) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_UNEXPECTED), 0} ;
	}

	// 取得失敗の種類を同意待ち・取消し・拒否・実行失敗へ分けて返す。
	switch( acquisition.state) {
		// 通信同意待ちは、内容監査へ進めず利用者の判断待ちとして返す。
		case OfficialAcquisitionState::AWAITING_NETWORK_CONSENT:
			return {OfficialPreparationItemState::AWAITING_NETWORK_CONSENT, error, 0} ;
		// 取得の中止を、準備処理の中止結果へ引き継ぐ。
		case OfficialAcquisitionState::CANCELLED:
			return {OfficialPreparationItemState::CANCELLED, error, 0} ;
		// 取得境界で拒否された内容を、準備済みへ昇格させない。
		case OfficialAcquisitionState::REJECTED:
			return {OfficialPreparationItemState::REJECTED, error, 0} ;
		// 取得失敗の診断値を、準備処理の失敗結果へ保持する。
		case OfficialAcquisitionState::FAILURE:
			return {OfficialPreparationItemState::FAILURE, error, 0} ;
		// 想定外の取得状態から、監査待ちまたは成功状態を作らない。
		default:
			return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_UNEXPECTED),
					0} ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_prepared_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool validPreparedReleaseIdentity( const OfficialReleaseRecord &release) noexcept
{
	// 未定義系列をfile名だけで取得可能にしない。
	if( release.family == OfficialReleaseFamily::UNKNOWN) {
		return false ;
	}

	// 既存系列のfile名必須条件を維持する。
	if( release.family != OfficialReleaseFamily::ASIX_AX88179A) {
		return !release.fileName.empty() ;
	}

	// File名偽装、空IDまたは固定endpointとIDの不一致を拒否する。
	if( !release.fileName.empty() || release.releaseKey.empty() ||
	   release.downloadUrl.size() > MAXIMUM_PREPARED_URL_CHARACTERS ||
	   release.downloadUrl.size() != ASIX_DOWNLOAD_PREFIX.size() + release.releaseKey.size() ||
	   !release.downloadUrl.starts_with( ASIX_DOWNLOAD_PREFIX) ||
	   release.downloadUrl.substr( ASIX_DOWNLOAD_PREFIX.size()) != release.releaseKey) {
		return false ;
	}

	// 配布IDの各文字をASCII数字だけに限定し、URL構造や表示値をIDとして受理しない。
	for( const wchar_t character : release.releaseKey) {
		// 公式 page の識別値には十進数字以外を許可しない。
		if( character < L'0' || character > L'9') {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_prepared_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError makeComputedEulaRevision( const std::wstring_view eulaText,
									 std::wstring			&revision) noexcept
{
	revision.clear() ;
	// 不完全または変換API上限外の本文を拒否する。
	if( !validPreparationEulaText( eulaText) ||
	   eulaText.size() > static_cast<std::size_t>( std::numeric_limits<int>::max())) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const int utf8Size = WideCharToMultiByte(
			CP_UTF8, WC_ERR_INVALID_CHARS, eulaText.data(), static_cast<int>( eulaText.size()),
			nullptr, 0, nullptr, nullptr) ;	// 終端NULを含まないUTF-8必要byte数。
		// 本文の UTF-8 必要量を計算できなければ識別 hash を作らない。
		if( utf8Size <= 0) {
			const DWORD error = GetLastError() ;	// 必要量計算失敗時の元のWin32診断値。
			return static_cast<NativeError>(
				HRESULT_FROM_WIN32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error)) ;
		}

		std::vector<UCHAR> utf8( static_cast<std::size_t>( utf8Size)) ;	// Hash対象の正確なUTF-8本文。
		// Win32変換APIのchar bufferへ、同じ記憶域をbyte列として渡す境界。
		const int		   converted = WideCharToMultiByte(
			 CP_UTF8, WC_ERR_INVALID_CHARS, eulaText.data(), static_cast<int>( eulaText.size()),
			 reinterpret_cast<char *>( utf8.data()), utf8Size, nullptr, nullptr) ;	// 変換結果byte数。
		// 本文全体を予定した byte 数へ変換できなければ識別値を返さない。
		if( converted != utf8Size) {
			const DWORD error = GetLastError() ;	// 変換失敗時の元のWin32診断値。
			return static_cast<NativeError>(
				HRESULT_FROM_WIN32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error)) ;
		}

		BCRYPT_ALG_HANDLE rawAlgorithm{} ;	// 成功時にBCryptCloseAlgorithmProviderするhandle。
		const NTSTATUS	  openStatus = BCryptOpenAlgorithmProvider(
			   &rawAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) ;	// SHA-256 Provider開始結果。
		// Hash algorithm の初期化失敗は NTSTATUS を保持して返す。
		if( !BCRYPT_SUCCESS( openStatus)) {
			return static_cast<NativeError>( HRESULT_FROM_NT( openStatus)) ;
		}

		// BCrypt algorithm handleへ第二引数0を渡して全return経路で閉じる。
		const auto closeAlgorithm = []( void *const value) noexcept {
			static_cast<void>(
				BCryptCloseAlgorithmProvider( static_cast<BCRYPT_ALG_HANDLE>( value), 0)) ;
		} ;
		// CNG algorithm handleの終了を保証する所有wrapper。
		const std::unique_ptr<void, decltype( closeAlgorithm)> algorithm( rawAlgorithm,
																		closeAlgorithm) ;
		std::array<UCHAR, SHA256_BYTES> digest{} ;	// CNGが設定するSHA-256 digest。
		const NTSTATUS					hashStatus =
			BCryptHash( static_cast<BCRYPT_ALG_HANDLE>( algorithm.get()), nullptr, 0, utf8.data(),
					   static_cast<ULONG>( utf8.size()), digest.data(),
					   // 一回の本文hash結果。
					   static_cast<ULONG>( digest.size())) ;
		// 本文 hash の計算に失敗した場合は revision 識別値を生成しない。
		if( !BCRYPT_SUCCESS( hashStatus)) {
			return static_cast<NativeError>( HRESULT_FROM_NT( hashStatus)) ;
		}

		constexpr std::array<wchar_t, 16> HEX_DIGITS{L'0', L'1', L'2', L'3', L'4', L'5',
													 L'6', L'7', L'8', L'9', L'a', L'b',
													 L'c', L'd', L'e', L'f'} ;	// 小文字hex変換表。
		std::wstring computed( COMPUTED_REVISION_PREFIX) ;						// 成功時だけ出力へ移す一時識別子。
		computed.reserve( COMPUTED_REVISION_PREFIX.size() + digest.size() * 2U) ;
		// 全digest byteを固定64桁の小文字hexへ変換する。
		for( const UCHAR value : digest) {
			computed.push_back( HEX_DIGITS[value >> 4U]) ;
			computed.push_back( HEX_DIGITS[value & 0x0fU]) ;
		}

		revision = std::move( computed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		revision.clear() ;
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		revision.clear() ;
		// Exceptionをworker境界へ漏らさない。
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_prepared_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult revalidateAndAcquireRelease(
	const OfficialPreparationTask &task, const OfficialPreparationTarget &expected,
	const OfficialReleaseRecord &retained, const PreparedReleaseRefresh &refresh,
	const PreparedReleaseAcquire &acquire, const PreparationCancellation &cancellation,
	OfficialAcquisitionResult &acquisition)
{
	acquisition = {} ;
	// 取得 callback の欠落と保持 release の不一致を実取得前に拒否する。
	if( !refresh || !acquire || !matchesPreparedRelease( task, expected, retained)) {
		return {OfficialPreparationItemState::REJECTED, static_cast<NativeError>( E_INVALIDARG), 0} ;
	}

	try {
		// Metadata の再取得前に取消し要求を受けた場合は network 処理へ進まない。
		if( cancellation && cancellation()) {
			return {OfficialPreparationItemState::CANCELLED,
					static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)), 0} ;
		}

		OfficialReleaseRecord current ;									// 固定公式起点の再確認結果。UIへ渡さない。
		bool				  rejected{} ;								// 公式取得根拠またはparserで拒否された場合true。
		const NativeError	  refreshed = refresh( current, rejected) ;	// 元の再確認診断値。
		// Metadata 再取得の失敗と形式拒否を区別して通知する。
		if( refreshed != 0 || rejected) {
			return {rejected ? OfficialPreparationItemState::REJECTED
							 : OfficialPreparationItemState::FAILURE,
					refreshed < 0
						? refreshed
						: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)),
					0} ;
		}

		// 公開 metadata が保持時点から変わった場合は新しい配布先へ追従しない。
		if( current != retained) {
			return {OfficialPreparationItemState::REJECTED,
					static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)), 0} ;
		}

		// Metadata 照合後も取消しを再確認し、不要になった payload 取得を避ける。
		if( cancellation && cancellation()) {
			return {OfficialPreparationItemState::CANCELLED,
					static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)), 0} ;
		}

		const OfficialAcquisitionRequest request{
			.url					   = retained.downloadUrl,
			.providerId				   = expected.providerId,
			.resourceId				   = expected.resourceId,
			.workspaceFileName		   = L"prepared.zip",
			.maximumFileBytes		   = expected.maximumBytes,
			.publishedSize			   = retained.publishedSizeBytes,
			.publishedSha256		   = retained.publishedSha256,
			.restrictedNetworkApproved = task.restrictedNetworkApproved} ;			// UIのpathを使わない。
		const NativeError error = acquire( request, cancellation, acquisition) ;	// 共通取得結果。
		return acquisitionTransferResult( error, task, acquisition) ;
	} catch( ...) {
		// 例外をworker境界へ漏らさず、取得許可や自動retryとして扱わない。
		acquisition = {} ;
		return {OfficialPreparationItemState::FAILURE, static_cast<NativeError>( E_UNEXPECTED), 0} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_prepared_acquisition.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationTransferResult acquirePreparedRelease(
	const OfficialPreparationTask &task, const OfficialPreparationTarget &expected,
	const OfficialReleaseRecord &retained, const PreparedReleaseRefresh &refresh,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialAcquisitionTransport &transport, IOfficialNetworkCostReader &costReader,
	const PreparationCancellation &cancellation, OfficialAcquisitionResult &acquisition)
{
	const PreparedReleaseAcquire acquire =	// URL、hash、disk等の検証を共通取得層へ一元化する。
		[&session, &workspace, &transport, &costReader]( const OfficialAcquisitionRequest &request,
														const PreparationCancellation	 &cancelled,
														OfficialAcquisitionResult		 &output) {
			// Byte単位はUIへ通知せず、外側executorが対象の確定件数を更新する。
			const HttpDownloadProgressCallback progress = []( std::uint64_t, std::uint64_t) {} ;
			return session.acquire( request, workspace, transport, costReader, progress, cancelled,
								   output) ;
		} ;
	return revalidateAndAcquireRelease( task, expected, retained, refresh, acquire, cancellation,
									   acquisition) ;
}

} // namespace drivercrate
