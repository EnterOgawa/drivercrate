//------------------------------------------------------------------------------
/**
 * @file official_download_grant.cpp
 * @brief 型付き公式配布recordの検証と短命download grantを実装します。
 * @version 01.12.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Record正規形、SHA-256と一回使用状態を実装。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Claim済みURLのHTTP request所有権移動を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  各HTTP hop開始前の期限再検証を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/20  Archive record表現上限と内容検査予算を分離。
 * Ver.01.04.00 Shunji Ogawa  2026/09/20  公式driver分類をrecord fingerprintへ追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/23  任意SHA-512の正規化・grant所有・再解決結合を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/23  取得専用形式と有限profileの検証・変換を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/23  開発sourceのrecordを非実行取得専用型へ限定。
 * Ver.01.08.00 Shunji Ogawa  2026/09/28  通常証跡と分離した収集専用の共通検証・射影を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/09/28  収集専用の公開形状・制御文字・UTF-8境界を補修。
 * Ver.01.10.00 Shunji Ogawa  2026/09/29  収集専用のCNG失敗probeと通常hash維持を接続。
 * Ver.01.11.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.11.01 Shunji Ogawa  2026/10/12  正規形の型と取得境界識別引数の説明を補足。
 * Ver.01.12.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * </pre>
 *
 * @note URLは正規形と非機密metadataへ含めず、grantの秘密所有領域だけへ移動します。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "platform/official_download_grant.h"
#include "platform/official_collector_public_text.h"

#include "core/official_source_policy.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------

constexpr std::size_t	   MAXIMUM_STABLE_ID_CHARACTERS	   = 64U ;		// 組み込みstable ID上限。
constexpr std::size_t	   MAXIMUM_ROUTE_CHARACTERS		   = 256U ;		// 型付きroute ID上限。
constexpr std::size_t	   MAXIMUM_RECORD_KEY_CHARACTERS   = 512U ;		// 公開record key上限。
constexpr std::size_t	   MAXIMUM_DISPLAY_TEXT_CHARACTERS = 4'096U ;	// 一つの公開表示field上限。
constexpr std::size_t	   MAXIMUM_EULA_CHARACTERS		   = 65'536U ;	// 同意本文上限。
constexpr std::size_t	   MAXIMUM_DEPENDENCY_CHARACTERS   = 512U ;		// 一依存識別子上限。
constexpr std::size_t	   MAXIMUM_DEPENDENCIES			   = 32U ;		// 一recordの依存件数上限。
constexpr std::size_t	   MAXIMUM_PAYLOADS				   = 32U ;		// 一recordのpayload操作上限。
constexpr std::size_t	   MAXIMUM_FILE_NAME_CHARACTERS	   = 260U ;		// 公開basename上限。
constexpr std::size_t	   MAXIMUM_PUBLISHER_CHARACTERS	   = 512U ;		// Publisher表示上限。
constexpr std::size_t	   MAXIMUM_CONTENT_TYPE_CHARACTERS = 128U ;		// Content-Type上限。
constexpr std::size_t	   MAXIMUM_URL_CHARACTERS		   = 8'192U ;	// 秘密URL上限。
	// ADR 0152の共通内容検査payload上限。
constexpr std::uint64_t	   MAXIMUM_PAYLOAD_BYTES		  = 128ULL * 1'024ULL * 1'024ULL ;
constexpr std::uint64_t	   MAXIMUM_GRANT_LIFETIME_SECONDS = 15ULL * 60ULL ;	// Grant寿命上限。
constexpr std::uint64_t	   REQUEST_DEADLINE_SLACK_SECONDS = 30ULL ;			// Request開始安全余裕。
constexpr std::size_t	   SHA256_CHARACTERS			  = 64U ;			// SHA-256 hex文字数。
constexpr std::string_view FINGERPRINT_DOMAIN =
	"drivercrate.official-distribution-record.v2" ;	// 分類を含む正規形の用途分離label。

constexpr NativeError INVALID_ARGUMENT = static_cast<NativeError>( E_INVALIDARG) ;	// 入力違反。
constexpr NativeError OUT_OF_MEMORY = static_cast<NativeError>( E_OUTOFMEMORY) ;	// Allocation失敗。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief Win32 errorをHRESULT bit patternへ変換します。
 * @param[in] error 変換するWin32 error code。
 * @return NativeErrorで保持するHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromWin32( const DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief CNGのNTSTATUSをHRESULT bit patternへ変換します。
 * @param[in] status BCrypt APIが返したNTSTATUS。
 * @return NativeErrorで保持するHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError nativeErrorFromNt( const NTSTATUS status) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_NT( status)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief UTF-16値が有限で表示可能なplain textか検証します。
 * @param[in] value 検証する文字列。
 * @param[in] maximumCharacters 許可するUTF-16 code unit数。
 * @param[in] allowEmpty 空文字列を許可する場合true。
 * @param[in] allowLineBreaks Tab、CR、LFを許可する場合true。
 * @return 上限、制御文字、surrogate pairを全て満たす場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidText( const std::wstring_view value, const std::size_t maximumCharacters,
							   const bool allowEmpty, const bool allowLineBreaks) noexcept
{
	// 必須値の欠落と有限上限超過を先に拒否する。
	if( (!allowEmpty && value.empty()) || value.size() > maximumCharacters) {
		return false ;
	}

	// indexで全UTF-16 code unitを検査し、surrogate pairの二文字を一組で進める。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		const wchar_t character = value[index] ;	// 今回検査するUTF-16 code unit。
		// EULA本文だけで許可する表示可能な空白か示す。
		const bool	  permittedWhitespace =
			allowLineBreaks && (character == L'\t' || character == L'\r' || character == L'\n') ;
		// NULと表示不能controlをrecord fieldへ保持しない。
		if( character == L'\0' || (character < L' ' && !permittedWhitespace)) {
			return false ;
		}

		const auto codeUnit = static_cast<std::uint16_t>( character) ;	// Surrogate判定用の値。
		// High surrogateは直後のlow surrogateと組になる場合だけ受理する。
		if( codeUnit >= 0xd800U && codeUnit <= 0xdbffU) {
			// 末尾high surrogateまたは別種code unitとの組を拒否する。
			if( index + 1U >= value.size()) {
				return false ;
			}

			const auto low = static_cast<std::uint16_t>( value[index + 1U]) ;	// Pair後半。
			// Unicode low surrogate範囲外を不正pairとして拒否する。
			if( low < 0xdc00U || low > 0xdfffU) {
				return false ;
			}

			++index ;
			continue ;
		}

		// Pair前半を持たないlow surrogateを拒否する。
		if( codeUnit >= 0xdc00U && codeUnit <= 0xdfffU) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Stable IDが限定ASCII構文を満たすか検証します。
 * @param[in] value Provider、policy、resourceまたはparserのstable ID。
 * @return 小文字英数字で始まり、小文字英数字、dot、hyphenだけならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isStableId( const std::wstring_view value) noexcept
{
	// 空IDと長すぎるIDを照合へ使用しない。
	if( value.empty() || value.size() > MAXIMUM_STABLE_ID_CHARACTERS) {
		return false ;
	}

	// 各文字をASCII stable ID集合へ限定する。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		const wchar_t character = value[index] ;							// 今回検査するASCII候補。
		const bool	  lowercase = character >= L'a' && character <= L'z' ;	// 小文字範囲。
		const bool	  decimal	= character >= L'0' && character <= L'9' ;	// 数字範囲。
		// 先頭以外で許可する二つのseparatorか示す。
		const bool	  separator = index != 0U && (character == L'-' || character == L'.') ;
		// 大文字、空白、先頭separator、path記号をstable IDへ許可しない。
		if( !lowercase && !decimal && !separator) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開SHA-256／SHA-512文字列表現を検証します。
 * @param[in] value 空または固定桁ASCII hexの公開hash。
 * @param[in] characters 呼出元が固定する64または128桁。
 * @return 空、または大文字小文字を問わない指定桁hexの場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isOptionalHash( const std::wstring_view value,
								  const std::size_t		  characters) noexcept
{
	// 公開hash欠落は明示的な未指定として受理する。
	if( value.empty()) {
		return true ;
	}

	// 指定algorithmと異なる桁数を拒否する。
	if( value.size() != characters) {
		return false ;
	}

	// 全桁をASCII hexへ限定する。
	for( const wchar_t character : value) {
		const bool decimal = character >= L'0' && character <= L'9' ;	// 数字範囲。
		const bool lower   = character >= L'a' && character <= L'f' ;	// 小文字hex範囲。
		const bool upper   = character >= L'A' && character <= L'F' ;	// 大文字hex範囲。
		// Hex集合外を公開hashとして受理しない。
		if( !decimal && !lower && !upper) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つの検証済み公開hash表記を大文字小文字を除いて比較します。
 * @param[in] left 比較する一つ目の空または64／128桁hex。
 * @param[in] right 比較する二つ目の空または64／128桁hex。
 * @return 同じbyte列の表記である場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool samePublishedHash( const std::wstring_view left,
									 const std::wstring_view right) noexcept
{
	// 桁数が異なる値は正規化後も一致しない。
	if( left.size() != right.size()) {
		return false ;
	}

	// 全桁をASCII小文字へ写像して比較する。
	for( std::size_t index = 0U; index < left.size(); ++index) {
		const wchar_t leftValue	 = left[index] >= L'A' && left[index] <= L'F'
									   ? static_cast<wchar_t>( left[index] - L'A' + L'a')
									   : left[index] ;	// 一つ目の正規化hex。
		const wchar_t rightValue = right[index] >= L'A' && right[index] <= L'F'
									   ? static_cast<wchar_t>( right[index] - L'A' + L'a')
									   : right[index] ;	// 二つ目の正規化hex。
		// 一桁でも異なる場合は別hashとして終了する。
		if( leftValue != rightValue) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式表示file名が一つのbasenameとして安全か検証します。
 * @param[in] value Recordが明示した表示file名。
 * @return 有限なbasenameで、path・wildcard・末尾dot／spaceを含まない場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeDisplayFileName( const std::wstring_view value) noexcept
{
	// 表示名自体のplain text契約を満たさない値を拒否する。
	if( !isValidText( value, MAXIMUM_FILE_NAME_CHARACTERS, false, false) || value == L"." ||
	   value == L"..") {
		return false ;
	}

	// Windows pathへ解釈可能なseparator、drive、wildcard等を表示basenameから除外する。
	if( value.find_first_of( L"\\/:*?\"<>|") != std::wstring_view::npos) {
		return false ;
	}

	// Windowsがbasename末尾から暗黙除去するdotとspaceを拒否する。
	return value.back() != L'.' && value.back() != L' ' ;
}

//------------------------------------------------------------------------------
/**
 * @brief Content-Typeがparameterを含まない限定ASCII media typeか検証します。
 * @param[in] value Provider parserが選択した期待content type。
 * @return 一つのslashを持つ小文字ASCII media typeの場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isContentType( const std::wstring_view value) noexcept
{
	// 空値、上限超過またはslashを持たない値を拒否する。
	const std::size_t slash = value.find( L'/') ;	// Typeとsubtypeのseparator位置。
	// Type／subtypeの境界が一つだけ存在する場合に限って文字検査へ進む。
	if( value.empty() || value.size() > MAXIMUM_CONTENT_TYPE_CHARACTERS || slash == 0U ||
	   slash == std::wstring_view::npos || slash + 1U >= value.size() ||
	   value.find( L'/', slash + 1U) != std::wstring_view::npos) {
		return false ;
	}

	// Typeとsubtypeを小文字ASCII tokenの安全な部分集合へ限定する。
	for( const wchar_t character : value) {
		const bool lowercase = character >= L'a' && character <= L'z' ;	// 小文字範囲。
		const bool decimal	 = character >= L'0' && character <= L'9' ;	// 数字範囲。
		// Media typeの安全な区切りとsuffix文字か示す。
		const bool punctuation =
			character == L'/' || character == L'.' || character == L'+' || character == L'-' ;
		// Parameter、空白、大文字または制御文字を期待値へ含めない。
		if( !lowercase && !decimal && !punctuation) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Record architectureが定義済みのWindows x64か確認します。
 * @param[in] value 検証するarchitecture。
 * @return Windows x64の場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isKnownArchitecture( const OfficialDistributionArchitecture value) noexcept
{
	// 定義外enumをfail-closedにし、x64だけを許可する。
	switch( value) {
		// DriverCrate初期版の唯一の対象architectureを受理する。
		case OfficialDistributionArchitecture::WINDOWS_X64:
			return true ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief Payload方式が定義済みか確認します。
 * @param[in] value 検証するpayload方式。
 * @return 定義済み値の場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isKnownPayloadKind( const OfficialDistributionPayloadKind value) noexcept
{
	// 定義済みの内容検査方式または明示未対応だけを許可する。
	switch( value) {
		// 共通INF検査へ渡す方式を受理する。
		case OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE:
			return true ;
		// 公式installer監査へ渡す方式を受理する。
		case OfficialDistributionPayloadKind::OFFICIAL_INSTALLER:
			return true ;
		// 未対応として保持する明示方式を受理する。
		case OfficialDistributionPayloadKind::UNSUPPORTED:
			return true ;
		// 内容検査・導入とは独立した取得専用方式を受理する。
		case OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE:
			return true ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 利用条件区分とEULA fieldの組合せを検証します。
 * @param[in] record 検証する配布record。
 * @return 同意不要または同意必須のfield関係が成立する場合true。
 */
//------------------------------------------------------------------------------
template <typename Record> [[nodiscard]] bool hasValidTerms( const Record &record) noexcept
{
	// 条件区分ごとにEULA fieldの必須・禁止関係を固定する。
	switch( record.terms) {
		// 同意不要recordに未提示EULAを混在させない。
		case OfficialDistributionTerms::CONFIRMED_NO_CONSENT:
			return record.eulaRevision.empty() && record.eulaText.empty() ;
		// 同意必須recordはrevisionと有限plain text全文を両方要求する。
		case OfficialDistributionTerms::ACCEPTANCE_REQUIRED:
			return isValidText( record.eulaRevision, MAXIMUM_DISPLAY_TEXT_CHARACTERS, false,
							   false) &&
				   isValidText( record.eulaText, MAXIMUM_EULA_CHARACTERS, false, true) ;
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二payloadのURLと期限を除くstable fieldが全て同じか比較します。
 * @param[in] left 比較する一つ目のpayload。
 * @param[in] right 比較する二つ目のpayload。
 * @return Stable fieldが全一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sameStablePayload( const OfficialDistributionPayloadRecord &left,
									 const OfficialDistributionPayloadRecord &right) noexcept
{
	return left.resourceId == right.resourceId && left.kind == right.kind &&
		   left.fileDisplayName == right.fileDisplayName &&
		   left.publishedSizeBytes == right.publishedSizeBytes &&
		   samePublishedHash( left.publishedSha256, right.publishedSha256) &&
		   samePublishedHash( left.publishedSha512, right.publishedSha512) &&
		   left.publisher == right.publisher &&
		   left.expectedContentType == right.expectedContentType &&
		   (left.kind != OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE ||
			left.maximumBytes == right.maximumBytes) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一payloadの有限fieldとsource policy結合を検証します。
 * @param[in] payload 検証するpayload行。
 * @param[in] policy Record rootと同じ組み込みsource policy。
 * @param[in] expectedOrdinal Vector内の0起点位置。
 * @return 全条件を満たす場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isValidPayload( const OfficialDistributionPayloadRecord &payload,
								  const OfficialSourcePolicy			  &policy,
								  const std::size_t						   expectedOrdinal) noexcept
{
	const OfficialSourceResourcePolicy *const resource =
		// Payload用途policy。
		findOfficialSourceResource( policy, payload.resourceId) ;
	// 未登録resourceまたはpayload以外の用途へdownload grantを結合しない。
	if( resource == nullptr || resource->kind != OfficialSourceResourceKind::PAYLOAD) {
		return false ;
	}

	// Ordinal、方式、表示basenameと期待応答形式を全て明示させる。
	if( expectedOrdinal > std::numeric_limits<std::uint32_t>::max() ||
	   payload.payloadOrdinal != static_cast<std::uint32_t>( expectedOrdinal) ||
	   !isKnownPayloadKind( payload.kind) || !isSafeDisplayFileName( payload.fileDisplayName) ||
	   !isContentType( payload.expectedContentType)) {
		return false ;
	}

	// 取得専用は明示profileと公開hash・宣言形式を必須にする。
	if( payload.kind == OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE &&
	   officialDownloadOnlyFormat( payload) == OfficialDownloadOnlyFormat::UNKNOWN) {
		return false ;
	}

	// ADR 0180のarchive表現上限。実取得ledgerと内容検査の128 MiBは独立して維持する。
	const auto representationMaximum =
		payload.kind == OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE
			? officialDownloadOnlyMaximumBytes( OfficialDownloadOnlyProfile::LARGE_2_GIB)
		: payload.kind == OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE
			? 4U * MAXIMUM_PAYLOAD_BYTES
			: MAXIMUM_PAYLOAD_BYTES ;
	// 表現上限を取得許可へ読み替えず、公開exact sizeがあれば内包させる。
	if( payload.maximumBytes == 0U || payload.maximumBytes > representationMaximum ||
	   (payload.publishedSizeBytes && *payload.publishedSizeBytes > payload.maximumBytes)) {
		return false ;
	}

	// 公開hashとpublisherの文字列契約を検証する。Publisher欠落は方式別監査へ残す。
	if( !isOptionalHash( payload.publishedSha256, SHA256_CHARACTERS) ||
	   !isOptionalHash( payload.publishedSha512, 128U) ||
	   !isValidText( payload.publisher, MAXIMUM_PUBLISHER_CHARACTERS, true, false)) {
		return false ;
	}

	// 秘密URLは存在と有限長だけをここで確認し、scheme／host／pathはHTTP境界へ委譲する。
	const std::wstring_view target = payload.targetUrl.view() ;	// 検証中だけ借用する秘密値。
	// 空、過大または埋込みNULの秘密URLを後続HTTP検査へ渡さない。
	if( target.empty() || target.size() > MAXIMUM_URL_CHARACTERS ||
	   target.find( L'\0') != target.npos) {
		return false ;
	}

	// 認識済み外部expiryは0を有効なUTC時刻として扱わない。
	if( payload.externalExpiryUtcSeconds && *payload.externalExpiryUtcSeconds == 0U) {
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 起点検証後のrecord共通fieldとpayload policyを検証します。
 * @tparam Record 通常recordまたは収集専用候補。
 * @param[in] record 検証する型付きrecord。
 * @param[in] policy 検証済み起点の組み込みpolicy。
 * @param[in] minimumUtcSeconds 起点本文検証UTC秒。
 * @return Stable fingerprint計算前の全構造が有効ならtrue。
 */
//------------------------------------------------------------------------------
template <typename Record>
[[nodiscard]] bool hasValidRecordFields( const Record &record, const OfficialSourcePolicy &policy,
										const std::uint64_t minimumUtcSeconds) noexcept
{
	// Record ID、parser、route、公開製品・OS、x64と解決時刻を必須にする。
	if( record.recordEvidenceId == 0U || !isStableId( record.parserId) ||
	   record.parserRevision == 0U ||
	   !isValidText( record.recordRoute, MAXIMUM_ROUTE_CHARACTERS, false, false) ||
	   !isValidText( record.recordKey, MAXIMUM_RECORD_KEY_CHARACTERS, false, false) ||
	   !isValidText( record.productFamily, MAXIMUM_DISPLAY_TEXT_CHARACTERS, false, false) ||
	   !isValidText( record.operatingSystem, MAXIMUM_DISPLAY_TEXT_CHARACTERS, false, false) ||
	   !isKnownArchitecture( record.architecture) || minimumUtcSeconds == 0U ||
	   record.resolvedUtcSeconds < minimumUtcSeconds) {
		return false ;
	}

	// 任意表示fieldも上限・plain textを満たし、利用条件の欠落や混在を拒否する。
	if( !isValidText( record.packageVersion, MAXIMUM_DISPLAY_TEXT_CHARACTERS, true, false) ||
	   !isValidText( record.driverCategory, MAXIMUM_DISPLAY_TEXT_CHARACTERS, true, false) ||
	   !isValidText( record.publishedDate, MAXIMUM_DISPLAY_TEXT_CHARACTERS, true, false) ||
	   !hasValidTerms( record)) {
		return false ;
	}

	// 依存とpayloadは空または上限超過の集合を受理しない。
	if( record.dependencies.size() > MAXIMUM_DEPENDENCIES || record.payloads.empty() ||
	   record.payloads.size() > MAXIMUM_PAYLOADS) {
		return false ;
	}

	// 依存を順に検査し、同じ識別子を二重に保持しない。
	for( std::size_t index = 0U; index < record.dependencies.size(); ++index) {
		const std::wstring_view dependency = record.dependencies[index] ;	// 今回の依存識別子。
		// 空・過大・制御文字を含む依存を受理しない。
		if( !isValidText( dependency, MAXIMUM_DEPENDENCY_CHARACTERS, false, false)) {
			return false ;
		}

		// 前方に同じ依存がある場合は曖昧な二重宣言として拒否する。
		for( std::size_t previous = 0U; previous < index; ++previous) {
			// Exact同一の依存識別子を重複として拒否する。
			if( record.dependencies[previous] == dependency) {
				return false ;
			}
		}
	}

	// 全payloadをpolicyと有限上限へ照合する。
	for( std::size_t index = 0U; index < record.payloads.size(); ++index) {
		const OfficialDistributionPayloadRecord &payload = record.payloads[index] ;	// 今回の行。
		// 一行でも不正ならrecord全体からgrantを発行しない。
		if( !isValidPayload( payload, policy, index) ||
		   (policy.providerId == INTEL_DOWNLOAD_DEVELOPMENT_PROVIDER_ID &&
			payload.kind != OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE)) {
			return false ;
		}

		// 先行行とstable fieldまたは完全URLが重なる曖昧なpayload操作を拒否する。
		for( std::size_t previous = 0U; previous < index; ++previous) {
			const OfficialDistributionPayloadRecord &earlier =
				record.payloads[previous] ;	// 比較する先行行。
			// 区別不能なstable行または同じ秘密targetの二重claimを許可しない。
			if( sameStablePayload( earlier, payload) ||
			   earlier.targetUrl.view() == payload.targetUrl.view()) {
				return false ;
			}
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通常配布recordの証拠と共通fieldを従来条件で検証します。
 * @param[in] record 検証する通常record。
 * @return 通常取得境界で有効ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasValidRecordStructure( const OfficialDistributionRecord &record) noexcept
{
	// 通常evidenceの検証を収集用に緩めない。
	if( !isValidOfficialSourceEvidence( record.rootEvidence)) {
		return false ;
	}

	const OfficialSourcePolicy *const policy =
		// 組み込みpolicy。
		findOfficialSourcePolicy( record.rootEvidence.policyId) ;
	const OfficialSourceResourcePolicy *const rootResource =
		policy == nullptr
			? nullptr
			: findOfficialSourceResource( *policy, record.rootEvidence.resourceId) ;	// 起点用途。
	// 起点用途と非cacheのnetwork証明を維持する。
	if( policy == nullptr || rootResource == nullptr ||
	   (rootResource->kind != OfficialSourceResourceKind::LANDING_PAGE &&
		rootResource->kind != OfficialSourceResourceKind::METADATA) ||
	   record.rootEvidence.acquisition != MeasurementAcquisition::NETWORK_BODY ||
	   record.rootEvidence.cachePermitted || !record.rootEvidence.originValidatedUtcSeconds) {
		return false ;
	}

	return hasValidRecordFields( record, *policy, *record.rootEvidence.originValidatedUtcSeconds) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 32-bit整数をlittle-endianでcanonical bufferへ追加します。
 * @param[in] value 追加する値。
 * @param[in,out] output 末尾へ4 byteを追加するbuffer。
 */
//------------------------------------------------------------------------------
void appendUint32( const std::uint32_t value, std::vector<std::byte> &output)
{
	// 下位byteから固定4回だけ追加する。
	for( std::uint32_t shift = 0U; shift < 32U; shift += 8U) {
		output.push_back( static_cast<std::byte>( (value >> shift) & 0xffU)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 64-bit整数をlittle-endianでcanonical bufferへ追加します。
 * @param[in] value 追加する値。
 * @param[in,out] output 末尾へ8 byteを追加するbuffer。
 */
//------------------------------------------------------------------------------
void appendUint64( const std::uint64_t value, std::vector<std::byte> &output)
{
	// 下位byteから固定8回だけ追加する。
	for( std::uint32_t shift = 0U; shift < 64U; shift += 8U) {
		output.push_back( static_cast<std::byte>( (value >> shift) & 0xffU)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 一つのbyte値をcanonical bufferへ追加します。
 * @param[in] value 追加する値。
 * @param[in,out] output 末尾へ一byteを追加するbuffer。
 */
//------------------------------------------------------------------------------
void appendByte( const std::uint8_t value, std::vector<std::byte> &output)
{
	output.push_back( static_cast<std::byte>( value)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ASCII用途分離labelを長さ付きでcanonical bufferへ追加します。
 * @param[in] value 組み込みASCII label。
 * @param[in,out] output 末尾へ長さとbyte列を追加するbuffer。
 */
//------------------------------------------------------------------------------
void appendAscii( const std::string_view value, std::vector<std::byte> &output)
{
	appendUint32( static_cast<std::uint32_t>( value.size()), output) ;
	// ASCII labelを一byteずつ固定順序で追加する。
	for( const char character : value) {
		output.push_back( static_cast<std::byte>( static_cast<unsigned char>( character))) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief UTF-16値を長さ付きlittle-endianでcanonical bufferへ追加します。
 * @param[in] value 構造検証済みのUTF-16文字列。
 * @param[in,out] output 末尾へcode unit数と各2 byteを追加するbuffer。
 */
//------------------------------------------------------------------------------
void appendUtf16( const std::wstring_view value, std::vector<std::byte> &output)
{
	appendUint32( static_cast<std::uint32_t>( value.size()), output) ;
	// 各UTF-16 code unitをCPU endianに依存しない順序で追加する。
	for( const wchar_t character : value) {
		const auto codeUnit = static_cast<std::uint16_t>( character) ;	// 今回のcode unit。
		appendByte( static_cast<std::uint8_t>( codeUnit & 0xffU), output) ;
		appendByte( static_cast<std::uint8_t>( (codeUnit >> 8U) & 0xffU), output) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 公開hash表記を小文字正規形でcanonical bufferへ追加します。
 * @param[in] value 構造検証済みの空または64／128桁hex。
 * @param[in,out] output 末尾へ正規化したUTF-16値を追加するbuffer。
 */
//------------------------------------------------------------------------------
void appendPublishedHash( const std::wstring_view value, std::vector<std::byte> &output)
{
	std::wstring normalized( value) ;	// 大文字hexだけを小文字へ揃える一時値。
	// 全桁を確認し、大文字A～Fだけを対応する小文字へ変換する。
	for( wchar_t &character : normalized) {
		// ASCII大文字hexだけを小文字へ正規化する。
		if( character >= L'A' && character <= L'F') {
			character = static_cast<wchar_t>( character - L'A' + L'a') ;
		}
	}

	appendUtf16( normalized, output) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 任意の64-bit値をpresence付きでcanonical bufferへ追加します。
 * @param[in] value Recordが明示した任意値。
 * @param[in,out] output 末尾へpresenceと存在時の値を追加するbuffer。
 */
//------------------------------------------------------------------------------
void appendOptionalUint64( const std::optional<std::uint64_t> value, std::vector<std::byte> &output)
{
	appendByte( value ? 1U : 0U, output) ;
	// 値が存在する場合だけ固定8 byteを追加し、欠落と0を区別する。
	if( value) {
		appendUint64( *value, output) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief RecordのURL・期限・session時刻を除くstable fieldを正規化します。
 * @tparam Record 検証済み公式配布recordまたは同じstable fieldを持つ署名索引recordの型。
 * @param[in] record 構造検証済みの型付きrecord。
 * @param[in] providerId 正規形へ結合する取得元Providerのstable ID。
 * @param[in] policyId 正規形へ結合する検証済み取得policyのstable ID。
 * @param[in] resourceId 正規形へ結合するpayload用途のstable resource ID。
 * @param[out] output Stable fieldを固定順序で保持するbyte列。
 */
//------------------------------------------------------------------------------
template <typename Record>
void makeCanonicalRecord( const Record &record, const std::wstring_view providerId,
						 const std::wstring_view policyId, const std::wstring_view resourceId,
						 std::vector<std::byte> &output)
{
	output.clear() ;
	appendAscii( FINGERPRINT_DOMAIN, output) ;
	appendUtf16( providerId, output) ;
	appendUtf16( policyId, output) ;
	appendUtf16( resourceId, output) ;
	appendUtf16( record.parserId, output) ;
	appendUint32( record.parserRevision, output) ;
	appendUtf16( record.recordRoute, output) ;
	appendUtf16( record.recordKey, output) ;
	appendUtf16( record.productFamily, output) ;
	appendUtf16( record.driverCategory, output) ;
	appendUtf16( record.operatingSystem, output) ;
	appendUint32( static_cast<std::uint32_t>( record.architecture), output) ;
	appendUtf16( record.packageVersion, output) ;
	appendUtf16( record.publishedDate, output) ;
	appendUint32( static_cast<std::uint32_t>( record.terms), output) ;
	appendUtf16( record.eulaRevision, output) ;
	appendUtf16( record.eulaText, output) ;
	appendUint32( static_cast<std::uint32_t>( record.dependencies.size()), output) ;
	// 依存をrecordの明示順で追加し、暗黙sortを行わない。
	for( const std::wstring &dependency : record.dependencies) {
		appendUtf16( dependency, output) ;
	}

	appendUint32( static_cast<std::uint32_t>( record.payloads.size()), output) ;
	// Payload stable fieldをordinal順で追加し、秘密URL・外部expiry・local上限を除外する。
	for( const OfficialDistributionPayloadRecord &payload : record.payloads) {
		appendUtf16( payload.resourceId, output) ;
		appendUint32( payload.payloadOrdinal, output) ;
		appendUint32( static_cast<std::uint32_t>( payload.kind), output) ;
		appendUtf16( payload.fileDisplayName, output) ;
		appendOptionalUint64( payload.publishedSizeBytes, output) ;
		appendPublishedHash( payload.publishedSha256, output) ;
		appendUtf16( payload.publisher, output) ;
		appendUtf16( payload.expectedContentType, output) ;
	}

	// SHA-512未指定recordの旧canonical表現を保持し、追加値だけ別domainへ結合する。
	if( std::ranges::any_of( record.payloads,
						   []( const auto &payload) { return !payload.publishedSha512.empty() ; })) {
		appendAscii( "published-sha512-v1", output) ;
		appendUint32( static_cast<std::uint32_t>( record.payloads.size()), output) ;
		// Ordinal順の空値も含め、hashがどのpayloadに属するか固定する。
		for( const auto &payload : record.payloads) {
			appendPublishedHash( payload.publishedSha512, output) ;
		}
	}

	// 取得専用profileだけ明示予算を固定し、旧型のlocal上限除外は維持する。
	if( std::ranges::any_of( record.payloads, []( const auto &payload) {
		   return payload.kind == OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE ;
	   })) {
		appendAscii( "download-only-profile-v1", output) ;
		appendUint32( static_cast<std::uint32_t>( record.payloads.size()), output) ;
		// 全ordinalの位置を保持して取得専用だけbyte上限を結合する。
		for( const auto &payload : record.payloads) {
			appendUint64( payload.kind == OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE
							 ? payload.maximumBytes
							 : 0U,
						 output) ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Canonical byte列のSHA-256をCNGで計算します。
 * @param[in] input 一byte以上の正規形。
 * @param[out] digest 成功時の32 byte SHA-256。失敗時は全zeroです。
 * @param[in] probe 収集診断の失敗専用通知。通常recordとgrantではnullです。
 * @return 成功時は0、不正sizeまたはCNG失敗時はHRESULT bit pattern。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError hashBytes( const std::span<const std::byte>  input,
									OfficialStableRecordFingerprint	 &digest,
									const OfficialCollectorHashProbe *probe = nullptr) noexcept
{
	digest = {} ;
	// 空入力またはCNGの32-bit byte数上限を超える入力を拒否する。
	if( input.empty() || input.size() > std::numeric_limits<ULONG>::max()) {
		return INVALID_ARGUMENT ;
	}

	BCRYPT_ALG_HANDLE rawAlgorithm{} ;	// BCryptCloseAlgorithmProvider対象handle。
	// SHA-256 algorithm providerを開始した結果。
	const NTSTATUS	  openStatus =
		BCryptOpenAlgorithmProvider( &rawAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) ;
	// Algorithm providerを開けない場合は元NTSTATUSを保持して終了する。
	if( !BCRYPT_SUCCESS( openStatus)) {
		return nativeErrorFromNt( openStatus) ;
	}

	// BCrypt algorithm handleを第二引数0で閉じるdeleter。
	const auto closeAlgorithm = []( void *const value) noexcept {
		static_cast<void>( BCryptCloseAlgorithmProvider( static_cast<BCRYPT_ALG_HANDLE>( value), 0)) ;
	} ;
	// Scope終了時にalgorithm handleを一回だけ閉じる所有wrapper。
	const std::unique_ptr<void, decltype( closeAlgorithm)> algorithm( rawAlgorithm, closeAlgorithm) ;
	// 失敗専用probeにも正常APIと同じhandle回収を適用します。
	if( probe != nullptr && *probe) {
		try {
			const auto status = static_cast<NTSTATUS>( (*probe)()) ;	// 元失敗値だけを受け取る。
			// 成功値はdigestを発行せず、この後の実CNGへ進みます。
			if( !BCRYPT_SUCCESS( status)) {
				return nativeErrorFromNt( status) ;
			}
		} catch( const std::bad_alloc &) {
			return OUT_OF_MEMORY ;
		} catch( ...) {
			return static_cast<NativeError>( E_FAIL) ;
		}
	}

	auto *const inputBytes = reinterpret_cast<PUCHAR>(
		const_cast<std::byte *>( input.data())) ;	// BCrypt宣言へ貸し出すread-only入力。
	auto *const digestBytes =
		reinterpret_cast<PUCHAR>( digest.bytes.data()) ;	// 固定32 byteの出力先。
	// Canonical record全体を一回でSHA-256へ入力した結果。
	const NTSTATUS hashStatus = BCryptHash( static_cast<BCRYPT_ALG_HANDLE>( algorithm.get()), nullptr,
										   0, inputBytes, static_cast<ULONG>( input.size()),
										   digestBytes, static_cast<ULONG>( digest.bytes.size())) ;
	// Hash失敗時は部分digestを公開せず全zeroへ戻す。
	if( !BCRYPT_SUCCESS( hashStatus)) {
		digest = {} ;
		return nativeErrorFromNt( hashStatus) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのroot source evidenceが全fieldで一致するか比較します。
 * @param[in] left 比較する一つ目の証拠。
 * @param[in] right 比較する二つ目の証拠。
 * @return URL非保持の全fieldが一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sameSourceEvidence( const OfficialSourceEvidence &left,
									  const OfficialSourceEvidence &right) noexcept
{
	return left.scanSessionId == right.scanSessionId && left.acquisitionId == right.acquisitionId &&
		   left.providerId == right.providerId && left.policyId == right.policyId &&
		   left.resourceId == right.resourceId && left.redirectCount == right.redirectCount &&
		   left.originPolicyIndices == right.originPolicyIndices &&
		   left.acquisition == right.acquisition &&
		   left.bodyAcquiredUtcSeconds == right.bodyAcquiredUtcSeconds &&
		   left.originValidatedUtcSeconds == right.originValidatedUtcSeconds &&
		   left.cachePermitted == right.cachePermitted ;
}

//------------------------------------------------------------------------------
/**
 * @brief 二つのrecord evidenceが全bindingで一致するか比較します。
 * @param[in] left Recordから再計算した証拠。
 * @param[in] right Grant発行要求が指定した証拠。
 * @return Root、ID、parser、fingerprint、件数、時刻が一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sameRecordEvidence( const OfficialDistributionRecordEvidence &left,
									  const OfficialDistributionRecordEvidence &right) noexcept
{
	return sameSourceEvidence( left.rootEvidence, right.rootEvidence) &&
		   left.recordEvidenceId == right.recordEvidenceId &&
		   left.parserRevision == right.parserRevision &&
		   left.stableFingerprint.bytes == right.stableFingerprint.bytes &&
		   left.payloadCount == right.payloadCount &&
		   left.resolvedUtcSeconds == right.resolvedUtcSeconds ;
}

//------------------------------------------------------------------------------
/**
 * @brief Claim前に許可する終端結果か確認します。
 * @param[in] value 検証する結果状態。
 * @return Claim前に確定できる拒否・取消し・失敗ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isPreAcquisitionOutcome( const OfficialDownloadGrantState value) noexcept
{
	// Claim前に成立し得る拒否、取消し、失敗だけを選別する。
	switch( value) {
		// Request開始前の期限切れを保持する。
		case OfficialDownloadGrantState::GRANT_EXPIRED:
			return true ;
		// 宛先検証の拒否を保持する。
		case OfficialDownloadGrantState::TARGET_REJECTED:
			return true ;
		// 再解決recordのstable変更を保持する。
		case OfficialDownloadGrantState::RECORD_CHANGED:
			return true ;
		// 利用者またはshutdown取消しを保持する。
		case OfficialDownloadGrantState::CANCELLED:
			return true ;
		// Root再解決等の具体的失敗を保持する。
		case OfficialDownloadGrantState::FAILED:
			return true ;
		// その他はclaim前の終端結果として使用しない。
		default:
			return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Claim後に許可する終端結果か確認します。
 * @param[in] value 検証する結果状態。
 * @return 取得成功または取得中の拒否・取消し・失敗ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isAcquisitionOutcome( const OfficialDownloadGrantState value) noexcept
{
	// Claim後に成立し得る取得結果だけを選別する。
	switch( value) {
		// 保護workspaceへ固定した取得成功を保持する。
		case OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION:
			return true ;
		// Redirect開始前の期限切れを保持する。
		case OfficialDownloadGrantState::GRANT_EXPIRED:
			return true ;
		// Hopまたは応答内容の拒否を保持する。
		case OfficialDownloadGrantState::TARGET_REJECTED:
			return true ;
		// 利用者またはshutdown取消しを保持する。
		case OfficialDownloadGrantState::CANCELLED:
			return true ;
		// HTTP、I/O、budget、hash等の失敗を保持する。
		case OfficialDownloadGrantState::FAILED:
			return true ;
		// その他は取得試行の終端結果として使用しない。
		default:
			return false ;
	}
}

/**
 * @brief Basenameと期待応答型が一致する取得専用形式を返します。
 * @param[in] name 公開basename。
 * @param[in] contentType Parserが明示した期待型。
 * @return 宣言上のZIP／EXE形式。不整合はUNKNOWN。
 */
[[nodiscard]] OfficialDownloadOnlyFormat downloadOnlyFormat(
	const std::wstring_view name, const std::wstring_view contentType) noexcept
{
	// Pathや短い不完全拡張子を形式として採用しない。
	if( !isSafeDisplayFileName( name) || name.size() <= 4U) {
		return OfficialDownloadOnlyFormat::UNKNOWN ;
	}

	std::array<wchar_t, 4U> extension{} ;	// ASCII小文字の最終拡張子。
	// 固定四文字だけを正規化し、filename本文を改変しない。
	for( std::size_t index = 0U; index < extension.size(); ++index) {
		const wchar_t character = name[name.size() - extension.size() + index] ;	// 元文字。
		extension[index]		= character >= L'A' && character <= L'Z'
									  ? static_cast<wchar_t>( character - L'A' + L'a')
									  : character ;
	}

	const std::wstring_view suffix( extension.data(), extension.size()) ;	// Stack上だけの借用。
	// ZIP表示にはZIP応答契約を要求する。
	if( suffix == L".zip" && contentType == L"application/zip") {
		return OfficialDownloadOnlyFormat::ZIP ;
	}

	// EXEは実行せずbinary応答として扱う。
	if( suffix == L".exe" && contentType == L"application/octet-stream") {
		return OfficialDownloadOnlyFormat::WINDOWS_EXE ;
	}

	return OfficialDownloadOnlyFormat::UNKNOWN ;
}

/**
 * @brief 取得専用metadataを既存公開hash規則と有限profileで検証します。
 * @param[in] payload 形式判定対象。
 * @param[in] maximum 明示profileの解決済みbyte上限。
 * @return 構文・容量・hashが揃う宣言形式。不正時UNKNOWN。
 */
[[nodiscard]] OfficialDownloadOnlyFormat validatedDownloadOnlyFormat(
	const OfficialDistributionPayloadRecord &payload, const std::uint64_t maximum) noexcept
{
	// Hashの欠落、構文不正とexact size超過を取得開始前に拒否する。
	if( maximum == 0U || (payload.publishedSha256.empty() && payload.publishedSha512.empty()) ||
	   !isOptionalHash( payload.publishedSha256, 64U) ||
	   !isOptionalHash( payload.publishedSha512, 128U) ||
	   (payload.publishedSizeBytes &&
		(*payload.publishedSizeBytes == 0U || *payload.publishedSizeBytes > maximum))) {
		return OfficialDownloadOnlyFormat::UNKNOWN ;
	}

	return downloadOnlyFormat( payload.fileDisplayName, payload.expectedContentType) ;
}

} // namespace

/** @see official_download_grant.h */
std::uint64_t officialDownloadOnlyMaximumBytes( const OfficialDownloadOnlyProfile profile) noexcept
{
	// 列挙された三つだけを許可し、任意数値castを予算へ流用しない。
	switch( profile) {
		// 既知の有限profileはenumのbyte数そのものを返す。
		case OfficialDownloadOnlyProfile::STANDARD_128_MIB:
		// 明示拡張枠も同じ有限解決を使う。
		case OfficialDownloadOnlyProfile::EXTENDED_512_MIB:
		// 大容量枠も取得専用以外の予算へ流用しない。
		case OfficialDownloadOnlyProfile::LARGE_2_GIB:
			return static_cast<std::uint64_t>( profile) ;
		// 未指定を自動拡大しない。
		case OfficialDownloadOnlyProfile::DISABLED:
			return 0U ;
	}

	return 0U ;
}

/** @see official_download_grant.h */
OfficialDownloadOnlyFormat officialDownloadOnlyFormat(
	const OfficialDistributionPayloadRecord &payload) noexcept
{
	// 旧installerやarchiveの認可へ取得専用の契約を流用しない。
	if( payload.kind != OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE) {
		return OfficialDownloadOnlyFormat::UNKNOWN ;
	}

	return validatedDownloadOnlyFormat(
		payload, officialDownloadOnlyMaximumBytes(
					 static_cast<OfficialDownloadOnlyProfile>( payload.maximumBytes))) ;
}

/** @see official_download_grant.h */
bool setOfficialDownloadOnlyProfile( OfficialDistributionPayloadRecord &payload,
									const OfficialDownloadOnlyProfile  profile) noexcept
{
	const auto maximum = officialDownloadOnlyMaximumBytes( profile) ;		// 明示有限予算。
	const auto format  = validatedDownloadOnlyFormat( payload, maximum) ;	// 宣言形式。
	// 元の型と配布形式が対応する場合だけ取得専用へ変更する。
	if( !((payload.kind == OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE &&
		  format == OfficialDownloadOnlyFormat::ZIP) ||
		 (payload.kind == OfficialDistributionPayloadKind::OFFICIAL_INSTALLER &&
		  format == OfficialDownloadOnlyFormat::WINDOWS_EXE))) {
		return false ;
	}

	payload.kind		 = OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE ;
	payload.maximumBytes = maximum ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError validateOfficialDistributionRecord(
	const OfficialDistributionRecord &record, OfficialDistributionRecordEvidence &evidence) noexcept
{
	evidence = {} ;
	// 構造または起点証拠が不正なrecordからfingerprintを作らない。
	if( !hasValidRecordStructure( record)) {
		return INVALID_ARGUMENT ;
	}

	try {
		std::vector<std::byte> canonical ;	// URLを含まない長さ付きstable field正規形。
		canonical.reserve( 4'096U) ;
		makeCanonicalRecord( record, record.rootEvidence.providerId, record.rootEvidence.policyId,
							record.rootEvidence.resourceId, canonical) ;

		OfficialStableRecordFingerprint fingerprint ;										// CNGが計算するrecord SHA-256。
		const NativeError				hashError = hashBytes( canonical, fingerprint) ;	// CNG結果。
		SecureZeroMemory( canonical.data(), canonical.size()) ;
		// SHA-256計算失敗時は部分的な証拠を公開しない。
		if( hashError != 0) {
			return hashError ;
		}

		OfficialDistributionRecordEvidence validated ;	// 全成功後にcommitする証拠。
		validated.rootEvidence		 = record.rootEvidence ;
		validated.recordEvidenceId	 = record.recordEvidenceId ;
		validated.parserRevision	 = record.parserRevision ;
		validated.stableFingerprint	 = fingerprint ;
		validated.payloadCount		 = static_cast<std::uint32_t>( record.payloads.size()) ;
		validated.resolvedUtcSeconds = record.resolvedUtcSeconds ;
		evidence					 = std::move( validated) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return OUT_OF_MEMORY ;
	} catch( ...) {
		// Worker境界へ未知例外を漏らさず、入力内容を診断へ含めない。
		return static_cast<NativeError>( E_FAIL) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 保存可能な公開文字列のUTF-8 byte数とURL非混入を確認します。
 * @param[in] value 確認する公開値。
 * @param[in] maximumBytes 射影内のfield別byte上限。
 * @return 有効なUTF-16で上限内、URL形状でない場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSafeCollectorText( const std::wstring_view value,
									   const std::size_t	   maximumBytes) noexcept
{
	return isOfficialCollectorPublicText( value, maximumBytes) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 親に渡す全公開fieldをbyte上限とURL非混入へ照合します。
 * @param[in] record 共通構造検証済みの収集候補。
 * @return 射影可能な場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasSafeCollectorProjectionFields(
	const OfficialCollectorRecordCandidate &record) noexcept
{
	constexpr std::size_t KEY_BYTES		= 256U ;	// 公開keyの新上限。
	constexpr std::size_t DISPLAY_BYTES = 1'024U ;	// 公開表示の新上限。
	// Record本文を複写する全公開fieldの実UTF-8 byte数を確認する。
	if( !isSafeCollectorText( record.parserId, KEY_BYTES) ||
	   !isSafeCollectorText( record.recordRoute, KEY_BYTES) ||
	   !isSafeCollectorText( record.recordKey, KEY_BYTES) ||
	   !isSafeCollectorText( record.productFamily, DISPLAY_BYTES) ||
	   !isSafeCollectorText( record.driverCategory, DISPLAY_BYTES) ||
	   !isSafeCollectorText( record.operatingSystem, DISPLAY_BYTES) ||
	   !isSafeCollectorText( record.packageVersion, DISPLAY_BYTES) ||
	   !isOfficialCollectorPublicText( record.publishedDate, DISPLAY_BYTES,
									  OfficialCollectorPublicTextKind::DATE) ||
	   !isSafeCollectorText( record.eulaRevision, KEY_BYTES)) {
		return false ;
	}

	// 依存集合の各値を保存可能な公開keyに限定する。
	for( const std::wstring &dependency : record.dependencies) {
		// 一つでも持出し不可なら全射影を拒否します。
		if( !isSafeCollectorText( dependency, KEY_BYTES)) {
			return false ;
		}
	}

	// Payload metadataだけを保存するため、全fieldを独立に確認する。
	for( const OfficialDistributionPayloadRecord &payload : record.payloads) {
		// PayloadのURLは検査対象でなくworker内に保持し、公開値だけを確認します。
		if( !isSafeCollectorText( payload.resourceId, KEY_BYTES) ||
		   !isSafeCollectorText( payload.fileDisplayName, DISPLAY_BYTES) ||
		   !isSafeCollectorText( payload.publishedSha256, KEY_BYTES) ||
		   !isSafeCollectorText( payload.publishedSha512, KEY_BYTES) ||
		   !isSafeCollectorText( payload.publisher, DISPLAY_BYTES) ||
		   !isOfficialCollectorPublicText( payload.expectedContentType, DISPLAY_BYTES,
										  OfficialCollectorPublicTextKind::CONTENT_TYPE)) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError projectOfficialCollectorRecord( const OfficialCollectorRecordCandidate &candidate,
										   const std::wstring_view				   policyId,
										   const std::wstring_view				   resourceId,
										   const std::uint64_t bodyValidatedUtcSeconds,
										   OfficialCollectorRecordProjection &projection) noexcept
{
	return projectOfficialCollectorRecordWithHashProbe( candidate, policyId, resourceId,
													   bodyValidatedUtcSeconds, projection, {}) ;
}

/** @see official_download_grant.h */
NativeError projectOfficialCollectorRecordWithHashProbe(
	const OfficialCollectorRecordCandidate &candidate, const std::wstring_view policyId,
	const std::wstring_view resourceId, const std::uint64_t bodyValidatedUtcSeconds,
	OfficialCollectorRecordProjection &projection, const OfficialCollectorHashProbe &probe) noexcept
{
	projection								 = {} ;
	const OfficialSourcePolicy *const policy = findOfficialSourcePolicy( policyId) ;	// 組み込み起点。
	const OfficialSourceResourcePolicy *const rootResource =
		policy == nullptr ? nullptr
						  : findOfficialSourceResource( *policy, resourceId) ;	// 登録済み用途。
	// 未登録またはpayload用途を同一本文のmetadataとして受理しない。
	if( policy == nullptr || rootResource == nullptr ||
	   (rootResource->kind != OfficialSourceResourceKind::LANDING_PAGE &&
		rootResource->kind != OfficialSourceResourceKind::METADATA) ||
	   !hasValidRecordFields( candidate, *policy, bodyValidatedUtcSeconds) ||
	   !hasSafeCollectorProjectionFields( candidate)) {
		return INVALID_ARGUMENT ;
	}

	try {
		std::vector<std::byte> canonical ;	// EULA本文を含むworker内限定の正規形。
		canonical.reserve( 4'096U) ;
		makeCanonicalRecord( candidate, policy->providerId, policy->id, resourceId, canonical) ;
		OfficialStableRecordFingerprint fingerprint ;								// 通常recordと同じ不透明な指紋。
		const NativeError hashError = hashBytes( canonical, fingerprint, &probe) ;	// CNG結果。
		SecureZeroMemory( canonical.data(), canonical.size()) ;
		// Hash APIの失敗から仮の指紋を発行しません。
		if( hashError != 0) {
			return hashError ;
		}

		OfficialCollectorRecordProjection result ;	// 全検証後だけ親用出力へcommitする。
		result.stableFingerprint = fingerprint ;
		result.parserId			 = candidate.parserId ;
		result.parserRevision	 = candidate.parserRevision ;
		result.recordRoute		 = candidate.recordRoute ;
		result.recordKey		 = candidate.recordKey ;
		result.productFamily	 = candidate.productFamily ;
		result.driverCategory	 = candidate.driverCategory ;
		result.operatingSystem	 = candidate.operatingSystem ;
		result.architecture		 = candidate.architecture ;
		result.packageVersion	 = candidate.packageVersion ;
		result.publishedDate	 = candidate.publishedDate ;
		result.terms			 = candidate.terms ;
		result.eulaRevision		 = candidate.eulaRevision ;
		result.dependencies		 = candidate.dependencies ;
		result.payloads.reserve( candidate.payloads.size()) ;
		// 秘密URLを除く公開fieldだけを所有値へ複写します。
		for( const OfficialDistributionPayloadRecord &payload : candidate.payloads) {
			result.payloads.push_back( OfficialCollectorPayloadProjection{
				.resourceId			 = payload.resourceId,
				.payloadOrdinal		 = payload.payloadOrdinal,
				.kind				 = payload.kind,
				.fileDisplayName	 = payload.fileDisplayName,
				.publishedSizeBytes	 = payload.publishedSizeBytes,
				.publishedSha256	 = payload.publishedSha256,
				.publishedSha512	 = payload.publishedSha512,
				.publisher			 = payload.publisher,
				.expectedContentType = payload.expectedContentType}) ;
		}

		projection = std::move( result) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return OUT_OF_MEMORY ;
	} catch( ...) {
		return static_cast<NativeError>( E_FAIL) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
RecordScopedDownloadGrant::RecordScopedDownloadGrant( RecordScopedDownloadGrant &&other) noexcept
{
	moveFrom( other) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
RecordScopedDownloadGrant::~RecordScopedDownloadGrant() noexcept
{
	targetUrl_.clear() ;
	SecureZeroMemory( targetFingerprint_.bytes.data(), targetFingerprint_.bytes.size()) ;
	targetFingerprintPresent_ = false ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
RecordScopedDownloadGrant &RecordScopedDownloadGrant::operator=(
	RecordScopedDownloadGrant &&other) noexcept
{
	// 自己移動では有効grantと秘密URLを維持する。
	if( this != &other) {
		targetUrl_.clear() ;
		SecureZeroMemory( targetFingerprint_.bytes.data(), targetFingerprint_.bytes.size()) ;
		targetFingerprintPresent_ = false ;
		moveFrom( other) ;
	}

	return *this ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError RecordScopedDownloadGrant::issue( OfficialDistributionRecord				  &record,
											 const OfficialDistributionRecordEvidence &evidence,
											 const std::uint32_t payloadOrdinal,
											 const std::uint64_t grantId,
											 const std::uint64_t issuedUtcSeconds,
											 const std::uint32_t reresolutionCount)
{
	// 一objectから複数grantを発行せず、消費済みobjectの再利用も拒否する。
	if( metadata_.state != OfficialDownloadGrantState::NOT_REQUESTED || !targetUrl_.empty()) {
		return nativeErrorFromWin32( ERROR_ALREADY_EXISTS) ;
	}

	OfficialDistributionRecordEvidence currentEvidence ;	// 現在recordから再計算する証拠。
	const NativeError				   validationError =
		// Record再検証結果。
		validateOfficialDistributionRecord( record, currentEvidence) ;
	// Record検証失敗をgrant発行で補完しない。
	if( validationError != 0) {
		return validationError ;
	}

	// 発行要求が別snapshotの証拠、範囲外payload、0 IDまたは0時刻を指定した場合は拒否する。
	if( !sameRecordEvidence( currentEvidence, evidence)) {
		return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
	}

	// Payload範囲、grant ID、発行時刻と再解決回数の有限条件を満たさない入力を拒否する。
	if( payloadOrdinal >= record.payloads.size() || grantId == 0U || issuedUtcSeconds == 0U ||
	   reresolutionCount > 1U) {
		return INVALID_ARGUMENT ;
	}

	OfficialDistributionPayloadRecord &payload = record.payloads[payloadOrdinal] ;	// 発行対象行。
	// 現在の内容検査で扱えない方式へ取得権限を発行しない。
	if( payload.kind == OfficialDistributionPayloadKind::UNSUPPORTED) {
		return static_cast<NativeError>( E_NOTIMPL) ;
	}

	// 15分加算のoverflowを時刻として丸めず、異常な発行値を拒否する。
	if( issuedUtcSeconds >
	   std::numeric_limits<std::uint64_t>::max() - MAXIMUM_GRANT_LIFETIME_SECONDS) {
		return INVALID_ARGUMENT ;
	}

	const std::uint64_t internalExpiry =
		issuedUtcSeconds + MAXIMUM_GRANT_LIFETIME_SECONDS ;	// Applicationの絶対上限。
	const std::uint64_t notAfter = payload.externalExpiryUtcSeconds
									   ? std::min( internalExpiry, *payload.externalExpiryUtcSeconds)
									   : internalExpiry ;	// 外部expiryを認識した場合の短い方。
	// 発行時点で30秒の開始余裕を持たないgrantを作らない。
	if( notAfter <= issuedUtcSeconds ||
	   notAfter - issuedUtcSeconds < REQUEST_DEADLINE_SLACK_SECONDS) {
		return nativeErrorFromWin32( ERROR_TIMEOUT) ;
	}

	try {
		RecordScopedDownloadGrant pending ;								// 全field準備後にcommitする未公開grant。
		const std::wstring_view	  target = payload.targetUrl.view() ;	// 発行前の秘密URL view。
		const NativeError		  targetHashError =
			hashBytes( std::as_bytes( std::span( target.data(), target.size())),
					  pending.targetFingerprint_) ;	// 同じ拒否URLへの再発行を防ぐSHA-256結果。
		// Target fingerprintを作れない場合はURLを移動せず発行を中止する。
		if( targetHashError != 0) {
			return targetHashError ;
		}

		pending.targetFingerprintPresent_		= true ;
		pending.metadata_.scanSessionId			= evidence.rootEvidence.scanSessionId ;
		pending.metadata_.grantId				= grantId ;
		pending.metadata_.recordEvidenceId		= evidence.recordEvidenceId ;
		pending.metadata_.providerId			= evidence.rootEvidence.providerId ;
		pending.metadata_.policyId				= evidence.rootEvidence.policyId ;
		pending.metadata_.rootResourceId		= evidence.rootEvidence.resourceId ;
		pending.metadata_.recordFingerprint		= evidence.stableFingerprint ;
		pending.metadata_.payloadOrdinal		= payloadOrdinal ;
		pending.metadata_.method				= OfficialDownloadGrantMethod::GET ;
		pending.metadata_.state					= OfficialDownloadGrantState::GRANT_ISSUED ;
		pending.metadata_.outcome				= OfficialDownloadGrantState::NOT_REQUESTED ;
		pending.metadata_.error					= 0 ;
		pending.metadata_.issuedUtcSeconds		= issuedUtcSeconds ;
		pending.metadata_.expiresUtcSeconds		= notAfter ;
		pending.metadata_.externalExpiryPresent = payload.externalExpiryUtcSeconds.has_value() ;
		pending.metadata_.maximumBytes			= payload.maximumBytes ;
		pending.metadata_.reresolutionCount		= reresolutionCount ;
		pending.resourceId_						= payload.resourceId ;
		pending.kind_							= payload.kind ;
		pending.fileDisplayName_				= payload.fileDisplayName ;
		pending.publishedSizeBytes_				= payload.publishedSizeBytes ;
		pending.publishedSha256_				= payload.publishedSha256 ;
		pending.publishedSha512_				= payload.publishedSha512 ;
		pending.publisher_						= payload.publisher ;
		pending.expectedContentType_			= payload.expectedContentType ;
		pending.targetUrl_						= std::move( payload.targetUrl) ;
		*this									= std::move( pending) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return OUT_OF_MEMORY ;
	} catch( ...) {
		// 秘密URLを移動する前の文字列copy例外だけを一般失敗として閉じる。
		return static_cast<NativeError>( E_FAIL) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError RecordScopedDownloadGrant::claim( const ScanSessionId scanSessionId,
											 const std::uint64_t grantId,
											 const std::uint64_t nowUtcSeconds) noexcept
{
	// 共有snapshotが残っていても元adapter失効後の索引grantは開始しない。
	if( metadata_.origin == OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
	   validateSignedIndexAuthority( scanSessionId) != 0) {
		consume( OfficialDownloadGrantState::TARGET_REJECTED, E_ACCESSDENIED) ;
		return E_ACCESSDENIED ;
	}

	// 未発行、取得中または消費済みgrantを二重claimしない。
	if( metadata_.state != OfficialDownloadGrantState::GRANT_ISSUED) {
		return nativeErrorFromWin32( ERROR_INVALID_STATE) ;
	}

	// 別sessionまたは別grant IDの要求で有効grantを横取りしない。
	if( scanSessionId == 0U || grantId == 0U || scanSessionId != metadata_.scanSessionId ||
	   grantId != metadata_.grantId) {
		return nativeErrorFromWin32( ERROR_REVISION_MISMATCH) ;
	}

	// 0の現在時刻は期限切れへ読み替えず、内部入力失敗としてgrantを消費する。
	if( nowUtcSeconds == 0U) {
		consume( OfficialDownloadGrantState::FAILED, INVALID_ARGUMENT) ;
		return INVALID_ARGUMENT ;
	}

	// Request直前に30秒の安全余裕がないgrantを消費し、秘密URLを再利用不能にする。
	if( metadata_.expiresUtcSeconds <= nowUtcSeconds ||
	   metadata_.expiresUtcSeconds - nowUtcSeconds < REQUEST_DEADLINE_SLACK_SECONDS) {
		const NativeError timeout = nativeErrorFromWin32( ERROR_TIMEOUT) ;	// 期限切れ診断。
		consume( OfficialDownloadGrantState::GRANT_EXPIRED, timeout) ;
		return timeout ;
	}

	// 秘密URLが失われた不整合grantを取得処理へ渡さない。
	if( targetUrl_.empty()) {
		const NativeError invalid = nativeErrorFromWin32( ERROR_INVALID_DATA) ;	// 内部不整合診断。
		consume( OfficialDownloadGrantState::FAILED, invalid) ;
		return invalid ;
	}

	metadata_.state = OfficialDownloadGrantState::ACQUIRING ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError RecordScopedDownloadGrant::finishBeforeAcquisition(
	const OfficialDownloadGrantState outcome, const NativeError error) noexcept
{
	// 発行済みgrantだけをclaim前の終端へ進め、結果区分と非zero診断を必須にする。
	if( metadata_.state != OfficialDownloadGrantState::GRANT_ISSUED ||
	   !isPreAcquisitionOutcome( outcome) || error == 0) {
		return nativeErrorFromWin32( ERROR_INVALID_STATE) ;
	}

	consume( outcome, error) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError RecordScopedDownloadGrant::finishAcquisition( const OfficialDownloadGrantState outcome,
														 const NativeError error) noexcept
{
	// 成功時だけ診断0を要求する判定。
	const bool success = outcome == OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION ;
	// Claim済みgrantだけを終端へ進め、成功と失敗の診断値を混同しない。
	if( metadata_.state != OfficialDownloadGrantState::ACQUIRING || !isAcquisitionOutcome( outcome) ||
	   (success && error != 0) || (!success && error == 0)) {
		return nativeErrorFromWin32( ERROR_INVALID_STATE) ;
	}

	consume( outcome, error) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
const RecordScopedDownloadGrantMetadata &RecordScopedDownloadGrant::metadata() const noexcept
{
	return metadata_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
RecordScopedDownloadGrantPayloadView RecordScopedDownloadGrant::payloadView() const noexcept
{
	const std::wstring_view target = metadata_.state == OfficialDownloadGrantState::ACQUIRING
										 ? targetUrl_.view()
										 : std::wstring_view{} ;	// Claim中だけ公開する秘密URL view。
	return {.targetUrl			 = target,
			.resourceId			 = resourceId_,
			.kind				 = kind_,
			.fileDisplayName	 = fileDisplayName_,
			.publishedSizeBytes	 = publishedSizeBytes_,
			.publishedSha256	 = publishedSha256_,
			.publishedSha512	 = publishedSha512_,
			.publisher			 = publisher_,
			.expectedContentType = expectedContentType_,
			.maximumBytes		 = metadata_.maximumBytes} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
SecretOfficialUrl RecordScopedDownloadGrant::takeTargetUrlForHttp() noexcept
{
	// Claim済みの未移動URLだけをHTTP requestに一回移す。
	if( metadata_.state != OfficialDownloadGrantState::ACQUIRING || targetUrl_.empty()) {
		return {} ;
	}

	return std::move( targetUrl_) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError RecordScopedDownloadGrant::validateRequestStartDeadline(
	const std::uint64_t nowUtcSeconds) const noexcept
{
	// 各hopで元adapterの失効を再確認し、数値session一致だけでは開始しない。
	if( metadata_.origin == OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
	   validateSignedIndexAuthority( metadata_.scanSessionId) != 0) {
		return E_ACCESSDENIED ;
	}

	// Claim済みgrantと有効な時計だけをrequest開始判定へ使用する。
	if( metadata_.state != OfficialDownloadGrantState::ACQUIRING || nowUtcSeconds == 0U) {
		return INVALID_ARGUMENT ;
	}

	// 各hop開始時に30秒未満しか残らないgrantを新しい通信へ使用しない。
	if( metadata_.expiresUtcSeconds <= nowUtcSeconds ||
	   metadata_.expiresUtcSeconds - nowUtcSeconds < REQUEST_DEADLINE_SLACK_SECONDS) {
		return nativeErrorFromWin32( ERROR_TIMEOUT) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError RecordScopedDownloadGrant::compareConsumedTarget( const std::wstring_view candidate,
															 bool &sameTarget) const noexcept
{
	sameTarget = false ;
	// 終端済みgrantの有効なsession内fingerprintだけを再解決照合へ使用する。
	if( metadata_.state != OfficialDownloadGrantState::CONSUMED || !targetFingerprintPresent_ ||
	   candidate.empty()) {
		return INVALID_ARGUMENT ;
	}

	OfficialStableRecordFingerprint candidateFingerprint ;	// 再解決URLの一時照合値。
	const NativeError				hashError =
		hashBytes( std::as_bytes( std::span( candidate.data(), candidate.size())),
				  candidateFingerprint) ;	// 秘密URLをcopyしないSHA-256結果。
	// Hash失敗時は比較値を使用せず診断を返す。
	if( hashError != 0) {
		return hashError ;
	}

	sameTarget = targetFingerprint_.bytes == candidateFingerprint.bytes ;
	SecureZeroMemory( candidateFingerprint.bytes.data(), candidateFingerprint.bytes.size()) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
void RecordScopedDownloadGrant::consume( const OfficialDownloadGrantState outcome,
										const NativeError				 error) noexcept
{
	targetUrl_.clear() ;
	metadata_.state = OfficialDownloadGrantState::CONSUMED ;
	signedIndexRoute_.clear() ;
	metadata_.outcome = outcome ;
	metadata_.error	  = error ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_download_grant.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
void RecordScopedDownloadGrant::moveFrom( RecordScopedDownloadGrant &other) noexcept
{
	signedIndexIssuer_			= std::move( other.signedIndexIssuer_) ;
	signedIndexAcquisitionOpen_ = std::move( other.signedIndexAcquisitionOpen_) ;
	signedIndexLookup_			= std::move( other.signedIndexLookup_) ;
	signedIndexRelationIndex_	= std::exchange( other.signedIndexRelationIndex_, 0U) ;
	signedIndexRoute_			= std::move( other.signedIndexRoute_) ;
	metadata_					= std::move( other.metadata_) ;
	targetUrl_					= std::move( other.targetUrl_) ;
	resourceId_					= std::move( other.resourceId_) ;
	kind_						= other.kind_ ;
	fileDisplayName_			= std::move( other.fileDisplayName_) ;
	publishedSizeBytes_			= other.publishedSizeBytes_ ;
	publishedSha256_			= std::move( other.publishedSha256_) ;
	publishedSha512_			= std::move( other.publishedSha512_) ;
	publisher_					= std::move( other.publisher_) ;
	expectedContentType_		= std::move( other.expectedContentType_) ;
	targetFingerprint_			= other.targetFingerprint_ ;
	targetFingerprintPresent_	= std::exchange( other.targetFingerprintPresent_, false) ;
	SecureZeroMemory( other.targetFingerprint_.bytes.data(), other.targetFingerprint_.bytes.size()) ;
	other.metadata_ = {} ;
	other.kind_		= OfficialDistributionPayloadKind::UNSUPPORTED ;
	other.publishedSizeBytes_.reset() ;
}

} // namespace drivercrate
