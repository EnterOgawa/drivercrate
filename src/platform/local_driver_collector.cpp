//------------------------------------------------------------------------------
/**
 * @file local_driver_collector.cpp
 * @brief 公式metadataを有限manifestから収集し、非公開checkpointへ保存します。
 * @version 01.17.00
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/24  有限収集・ASUS／Intel接続・checkpointを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/25  保護state storeへ読書きとlockを結合。
 * Ver.01.02.00 Shunji Ogawa  2026/09/25  run契約結合・日跨ぎ再開・試験入口を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/25  v3のmetadata再検証と本文・射影結合を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/25  未昇格回収・source待機・空と減少の保留を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/27  v2登録済みrootへの旧収集mode混用を拒否。
 * Ver.01.06.00 Shunji Ogawa  2026/09/27  全旧契約の非変更検査とrequest待機引継ぎを追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/27  公式GET経路と恒久request keyの生成を共用。
 * Ver.01.08.00 Shunji Ogawa  2026/09/28  全対象job準備用のkey付きtarget builderを追加。
 * Ver.01.08.01 Shunji Ogawa  2026/10/02  AI依存を撤去し非AI共通処理と試験を維持。
 * Ver.01.09.00 Shunji Ogawa  2026/10/03  旧storeの非変更待機export準備を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/14  待機を維持した明示200原byte返却を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/10/15  保護本文と日次receipt・due前検査を追加。
 * Ver.01.11.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.11.02   Shunji Ogawa  2026/10/16 target key生成の入出力と失敗時契約を明記。
 * Ver.01.12.00   Shunji Ogawa  2026/10/17 全旧requestの射影と保護monitor原点参照の検査を追加。
 * Ver.01.13.00   Shunji Ogawa  2026/10/17 原日次receiptと既存headの非変更照合を追加。
 * Ver.01.14.00 Shunji Ogawa  2026/10/25  同run新200からの明示grant取得と中断待機を追加。
 * Ver.01.15.00 Shunji Ogawa  2026/10/25  元errorを維持し呼出し内の拒否区間を返却。
 * Ver.01.16.00 Shunji Ogawa  2026/10/25  明示失敗の完全200原本文と原receipt診断を分離。
 * Ver.01.17.00 Shunji Ogawa  2026/10/26 新metadataと全公開algorithmを同run取得へ結合。
 * </pre>
 *
 * @note 明示日次本体取得も同writerで実行し、原page/pathは通常logへ出力しません。
 */
//------------------------------------------------------------------------------

#include "platform/local_driver_collector.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/asus_network_record_adapter.h"
#include "platform/intel_ethernet_windows11_record_adapter.h"
#include "platform/official_record_utilities.h"
#include "platform/local_collector_state_store.h"
#include "platform/local_collector_legacy.h"
#include "platform/official_file_verifier.h"
#include "platform/official_release_metadata.h"
#include "platform/official_download_workspace.h"

#include <Windows.h>
#include <wincrypt.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

/**
 * @brief JSON配列をWinRT参照で保持する。要素数と各要素のschema検証は利用側で行う。
 */
using JsonArray = winrt::Windows::Data::Json::JsonArray ;
/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using JsonObject = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON値をWinRT参照で保持する。所有byteの検証と型判定はreader側で行う。
 */
using JsonValue = winrt::Windows::Data::Json::JsonValue ;
/**
 * @brief JSON値の実種別を表し、schemaで要求する型との一致を検査する。
 */
using JsonValueType = winrt::Windows::Data::Json::JsonValueType ;

// 一manifestに許可する最大byte数を固定する。
constexpr std::uintmax_t				 MAXIMUM_MANIFEST_BYTES = 256U * 1024U ;
// 一checkpointに許可する最大byte数を固定する。
constexpr std::uintmax_t				 MAXIMUM_STATE_BYTES = 1024U * 1024U ;
// 一回の通信試行へ渡す公開target数を固定する。
constexpr std::size_t					 MAXIMUM_TARGETS = 32U ;
// 前回成功からの再確認間隔を秒で固定する。
constexpr std::uint64_t					 SECONDS_PER_DAY = 86400U ;
// 一回の収集処理へ許可する単調時間予算を固定する。
constexpr auto							 RUN_BUDGET = std::chrono::hours( 1) ;

/**
 * @brief 有限の通常fileだけをbyte列として読みます。
 * @param[in] path 通常fileの入力path。同期呼出し中だけ借用する。
 * @param[in] maximum 事前file sizeに許可する最大byte数。
 * @return 事前sizeと一致しNULを含まない非空byte。属性・size・読取り違反時はnullopt。
 */
[[nodiscard]] std::optional<std::string> readSmallFile( const std::filesystem::path &path,
													   const std::uintmax_t			maximum)
{
	// 元のAPI診断。
	std::error_code error ;
	// 取得対象fileの実byte数。
	const auto		size = std::filesystem::file_size( path, error) ;
	// Win32 file属性。
	const DWORD		attributes = GetFileAttributesW( path.c_str()) ;
	// 元の失敗を成功として扱わず、この段階を停止する。
	if( error || size == 0U || size > maximum || attributes == INVALID_FILE_ATTRIBUTES ||
	   (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U) {
		return std::nullopt ;
	}

	// 今回のfileを検証中だけ保持する。
	std::ifstream file( path, std::ios::binary) ;
	// 操作対象のfileとworkspaceを限定する。
	if( !file) {
		return std::nullopt ;
	}

	// 検証する実byte列。
	std::string bytes( std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}) ;
	// 入力と出力を有限上限内へ制限する。
	if( bytes.size() != size || bytes.find( '\0') != std::string::npos) {
		return std::nullopt ;
	}

	return bytes ;
}

/**
 * @brief UTF-8本文の検証済みJSON objectだけを返します。
 * @param[in] bytes UTF-8 JSON本文の借用view。
 * @return 解析成功時のJSON object。例外を含む解析失敗はnullopt。
 */
[[nodiscard]] std::optional<JsonObject> parseObject( const std::string_view bytes)
{
	try {
		return JsonObject::Parse( winrt::to_hstring( bytes)) ;
	} catch( ...) {
		return std::nullopt ;
	}
}

/**
 * @brief 公開名からURL、PnP ID、制御文字を拒否します。
 * @param[in] value 検査対象のUTF-16 view。同期呼出し中だけ借用する。
 * @param[in] maximum 許可する最大UTF-16 code unit数。
 * @param[in] allowEmpty 空文字列を許可する場合true。
 * @return 当該公開文字・長さの全条件を満たす場合true。禁止文字・長さ違反はfalse。
 */
[[nodiscard]] bool publicText( const std::wstring_view value, const std::size_t maximum,
							  const bool allowEmpty = false)
{
	// 入力と出力を有限上限内へ制限する。
	if( value.size() > maximum || (value.empty() && !allowEmpty) ||
	   value.find( L"://") != value.npos || value.find( L'\\') != value.npos) {
		return false ;
	}

	// 秘密ID照合用の大文字表現。
	std::wstring upper( value) ;
	// 有限集合の各要素を順に検証し、件数と順序を保持する。
	for( wchar_t &letter : upper) {
		// 外部へ渡す公開名から秘密値と不正文字を除外する。
		if( letter < L' ' || letter == 127) {
			return false ;
		}

		// 外部へ渡す公開名から秘密値と不正文字を除外する。
		if( letter >= L'a' && letter <= L'z') {
			letter = static_cast<wchar_t>( letter - L'a' + L'A') ;
		}
	}

	// 有限集合の各要素を順に検証し、件数と順序を保持する。
	for( const std::wstring_view privatePrefix :
		{L"VEN_", L"DEV_", L"VID_", L"PID_", L"PCI_", L"USB_"}) {
		// 外部へ渡す公開名から秘密値と不正文字を除外する。
		if( upper.find( privatePrefix) != upper.npos) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief 公開名のmanifest fieldを有限ASCIIへ制限します。
 * @param[in] value 検査対象のUTF-16 view。同期呼出し中だけ借用する。
 * @param[in] maximum 許可する最大UTF-16 code unit数。
 * @param[in] allowEmpty 空文字列を許可する場合true。
 * @return 当該公開文字・長さの全条件を満たす場合true。禁止文字・長さ違反はfalse。
 */
[[nodiscard]] bool asciiName( const std::wstring_view value, const std::size_t maximum,
							 const bool allowEmpty = false)
{
	// 入力と出力を有限上限内へ制限する。
	if( !publicText( value, maximum, allowEmpty)) {
		return false ;
	}

	// 有限集合の各要素を順に検証し、件数と順序を保持する。
	for( const wchar_t character : value) {
		// 外部へ渡す公開名から秘密値と不正文字を除外する。
		if( character > 126 || character == L'/' || character == L':' || character == L'|') {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief 状態file名へ使うSHA-256と日付の文字集合を固定します。
 * @param[in] value 検査対象のUTF-16 view。同期呼出し中だけ借用する。
 * @return 64桁の大小ASCII hexならtrue。それ以外はfalse。
 */
[[nodiscard]] bool hashName( const std::wstring_view value)
{
	// 入力と出力を有限上限内へ制限する。
	if( value.size() != 64U) {
		return false ;
	}

	return std::all_of( value.begin(), value.end(), []( const wchar_t ch) {
		return (ch >= L'0' && ch <= L'9') || (ch >= L'A' && ch <= L'F') ||
			   (ch >= L'a' && ch <= L'f') ;
	}) ;
}

/**
 * @brief 文字列日付をpath delimiterのない固定数字へ制限します。
 * @param[in] value 検査対象のUTF-16 view。同期呼出し中だけ借用する。
 * @return 8桁のASCII数字ならtrue。それ以外はfalse。暦日の実在は判定しない。
 */
[[nodiscard]] bool dayName( const std::wstring_view value)
{
	return value.size() == 8U && std::all_of( value.begin(), value.end(), []( const wchar_t ch) {
			   return ch >= L'0' && ch <= L'9' ;
		   }) ;
}

/**
 * @brief 内部文字列をASCII hash keyへ射影します。
 * @param[in,out] target 同期呼出し中だけ借用する対象。source、publicModel、operatingSystem、categoryを読み、
 *                      keySha256をHash計算成功時は小文字64桁hex、Hash計算失敗時は空へ更新する。
 * @return 元公開fieldからSHA-256 keyを生成できた場合true。Hash計算失敗時はfalse。
 * @note Hash計算前の文字列変換例外は伝播し、その場合はkeySha256を変更しない。
 */
[[nodiscard]] bool makeTargetKey( LocalCollectorTarget &target)
{
	// target同一性のcanonical入力。
	const std::string fields = winrt::to_string( winrt::hstring( target.source)) + "\n" +
							   winrt::to_string( winrt::hstring( target.publicModel)) + "\n" +
							   winrt::to_string( winrt::hstring( target.operatingSystem)) + "\n" +
							   winrt::to_string( winrt::hstring( target.category)) + "\n" ;
	return computeBytesSha256( fields, target.keySha256) == 0 ;
}

/**
 * @brief JSON string propertyを型・上限付きで読みます。
 * @param[in] object 同じCOM apartmentで借用する元JSON object。
 * @param[in] name 取得するfieldのUTF-16名。同期中だけ借用する。
 * @param[in] maximum 許可する最大UTF-16 code unit数。
 * @return 型・長さが一致する所有文字列。欠損、型違反、過大値、例外時はnullopt。
 */
[[nodiscard]] std::optional<std::wstring> stringField( const JsonObject		 &object,
													  const std::wstring_view name,
													  const std::size_t		  maximum)
{
	try {
		// 型付きJSON field。
		const auto value = object.GetNamedValue( winrt::hstring( name)) ;
		// 保存済みJSONの必須fieldを検査する。
		if( value.ValueType() != JsonValueType::String) {
			return std::nullopt ;
		}

		// 復号した公開文字列。
		std::wstring text( value.GetString().c_str()) ;
		// 入力と出力を有限上限内へ制限する。
		if( text.size() > maximum) {
			return std::nullopt ;
		}

		return text ;
	} catch( ...) {
		return std::nullopt ;
	}
}

/**
 * @brief JSON数値を精度が維持できる範囲で整数へ読みます。
 * @param[in] object 同じCOM apartmentで借用する元JSON object。
 * @param[in] name 取得するfieldのUTF-16名。同期中だけ借用する。
 * @return 0～2の53乗未満の正確な整数。欠損、型・値域違反、例外時はnullopt。
 */
[[nodiscard]] std::optional<std::uint64_t> numberField( const JsonObject		  &object,
													   const std::wstring_view name)
{
	try {
		// 型付きJSON field。
		const auto value = object.GetNamedValue( winrt::hstring( name)) ;
		// 保存済みJSONの必須fieldを検査する。
		if( value.ValueType() != JsonValueType::Number) {
			return std::nullopt ;
		}

		// 精度確認前のJSON数値。
		const double number = value.GetNumber() ;
		// 保存済みJSONの必須fieldを検査する。
		if( !std::isfinite( number) || number < 0.0 || number > 9007199254740991.0 ||
		   std::floor( number) != number) {
			return std::nullopt ;
		}

		return static_cast<std::uint64_t>( number) ;
	} catch( ...) {
		return std::nullopt ;
	}
}

/**
 * @brief 永続化に許可したstring fieldを挿入します。
 * @param[in,out] object 挿入先のJSON object。既存の同名fieldは置き換える。
 * @param[in] name 固定fieldの非null、NUL終端UTF-16名。同期中だけ借用する。
 * @param[in] value 保存するUnicode文字列の借用view。JSON値へcopyする。
 */
void putString( JsonObject &object, const wchar_t *name, const std::wstring_view value)
{
	object.Insert( name, JsonValue::CreateStringValue( winrt::hstring( value))) ;
}

/**
 * @brief 永続化するuint64をJSONの整数精度内で挿入します。
 * @param[in,out] object 挿入先のJSON object。既存の同名fieldは置き換える。
 * @param[in] name 固定fieldの非null、NUL終端UTF-16名。同期中だけ借用する。
 * @param[in] value 2の53乗未満であることを呼出し側が検査済みの整数。
 */
void putNumber( JsonObject &object, const wchar_t *name, const std::uint64_t value)
{
	object.Insert( name, JsonValue::CreateNumberValue( static_cast<double>( value))) ;
}

/**
 * @brief 状態名の保存表現を固定します。
 * @param[in] state 保存名へ変換する対象状態。
 * @return 固定literalの非所有view。未知enumはINVALID。
 */
[[nodiscard]] std::wstring_view stateName( const LocalCollectorTargetState state)
{
	// 定義された状態だけを固定名へ変換する。
	switch( state) {
		// 未開始のtargetは次の実行へ残す。
		case LocalCollectorTargetState::PENDING:
			return L"PENDING" ;
		// 試行中のtargetは再開時に未完了として扱う。
		case LocalCollectorTargetState::IN_PROGRESS:
			return L"IN_PROGRESS" ;
		// 公式recordが変化したtargetを記録する。
		case LocalCollectorTargetState::UPDATED:
			return L"UPDATED" ;
		// 公式recordが前回と同じtargetを記録する。
		case LocalCollectorTargetState::UNCHANGED:
			return L"UNCHANGED" ;
		// 完全な空応答を確認した場合だけ空として記録する。
		case LocalCollectorTargetState::NO_RECORDS:
			return L"NO_RECORDS" ;
		// 失敗を配布なしへ変換せず保存する。
		case LocalCollectorTargetState::FAILED:
			return L"ERROR" ;
		// 未確認の結果を成功へ昇格せず保持する。
		case LocalCollectorTargetState::HELD:
			return L"HELD" ;
		// 期限または予算により今回未実施のtargetを記録する。
		case LocalCollectorTargetState::DEFERRED:
			return L"DEFERRED" ;
	}

	return L"INVALID" ;
}

/**
 * @brief 未知状態を成功へ変換せず拒否します。
 * @param[in] name 固定保存名の借用view。
 * @return 完全一致する定義済み状態。未知名はnullopt。
 */
[[nodiscard]] std::optional<LocalCollectorTargetState> parseState( const std::wstring_view name)
{
	// 有限集合の各要素を順に検証し、件数と順序を保持する。
	for( const auto candidate :
		{LocalCollectorTargetState::PENDING, LocalCollectorTargetState::IN_PROGRESS,
		 LocalCollectorTargetState::UPDATED, LocalCollectorTargetState::UNCHANGED,
		 LocalCollectorTargetState::NO_RECORDS, LocalCollectorTargetState::FAILED,
		 LocalCollectorTargetState::DEFERRED, LocalCollectorTargetState::HELD}) {
		// 保存状態の形式と遷移を確認し、不明な値を拒否する。
		if( stateName( candidate) == name) {
			return candidate ;
		}
	}

	return std::nullopt ;
}

/**
 * @brief 永続化と結合hashに同じrecord表現を使用します。
 * @param[in] values 既に有限上限を検査した公開record集合。元順序で借用する。
 * @return 全recordを元順序で保持する所有JSON配列。
 */
[[nodiscard]] JsonArray encodeRecords( const std::vector<LocalCollectorRecord> &values)
{
	JsonArray records ;	// 有限公開fieldの配列。
	// 元順序を変えずcanonical field順で固定する。
	for( const auto &record : values) {
		JsonObject item ;	// 一recordの公開射影。
		putString( item, L"fingerprint", record.fingerprint) ;
		putString( item, L"displayTitle", record.displayTitle) ;
		putString( item, L"driverCategory", record.driverCategory) ;
		putString( item, L"operatingSystem", record.operatingSystem) ;
		putString( item, L"packageVersion", record.packageVersion) ;
		putString( item, L"publishedDate", record.publishedDate) ;
		records.Append( item) ;
	}

	return records ;
}

/** @brief 元200のrequest・本文・時刻とrecord射影の厳密byteを返します。
 * @param[in] target 元fetchの結合値と型付きrecords。
 * @return Hashとreceiptへ共用するJSON原byte。
 */
[[nodiscard]] std::string projectionBytes( const LocalCollectorTargetResult &target)
{
	JsonObject body ;	// URL・生本文を保持しない結合対象。
	putString( body, L"requestBindingSha256", target.requestBindingSha256) ;
	putString( body, L"bodySha256", target.bodySha256) ;
	putNumber( body, L"lastFetchedAt", target.lastFetchedAt) ;
	body.Insert( L"records", encodeRecords( target.records)) ;
	return winrt::to_string( body.Stringify()) ;
}

/** @brief 200の原本文と射影を同じrequestへ結合します。
 * @param[in] target 同じ元fetchとrequestの型付きrecord射影。
 * @return Canonical射影のSHA-256。Hash失敗は空です。
 */
[[nodiscard]] std::wstring projectionHash( const LocalCollectorTargetResult &target)
{
	std::wstring hash ;	// Canonical射影の指紋。
	// Hash失敗を一致と見なさない。
	if( computeBytesSha256( projectionBytes( target), hash) != 0) {
		return {} ;
	}

	return hash ;
}

/** @brief 有限原byteをbase64へ可逆変換します。
 * @param[in] bytes 用途上限内の原byte。切り詰めません。
 * @param[in] maximumBytes 通常512KiB、失敗診断だけ実request上限2MiBです。
 * @return 改行なしbase64。失敗時は空です。
 */
[[nodiscard]] std::wstring bodyBase64( const std::string_view bytes,
									  const std::uint64_t	 maximumBytes = 512U * 1024U)
{
	// 空本文・SDK容量外を保存用の正例にしません。
	if( maximumBytes == 0U || maximumBytes > 2U * 1024U * 1024U || bytes.empty() ||
	   bytes.size() > maximumBytes) {
		return {} ;
	}

	DWORD			size{} ;	// SDKが数える終端込み容量。
	// Win32変換APIのbyte viewでのみ型を変換します。
	const auto	   *raw	  = reinterpret_cast<const BYTE *>( bytes.data()) ;
	constexpr DWORD FLAGS = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF ;	// 原byte維持。
	// 短い変換・不完全な変換は保存しません。
	if( !CryptBinaryToStringW( raw, static_cast<DWORD>( bytes.size()), FLAGS, nullptr, &size)) {
		return {} ;
	}

	std::wstring encoded( size, L'\0') ;	// 有限な保存buffer。
	// 実変換の失敗を成功にしません。
	if( !CryptBinaryToStringW( raw, static_cast<DWORD>( bytes.size()), FLAGS, encoded.data(), &size)) {
		return {} ;
	}

	encoded.resize( size) ;
	// SDK終端だけをJSON文字列から外します。
	if( !encoded.empty() && encoded.back() == L'\0') {
		encoded.pop_back() ;
	}

	return encoded ;
}

/** @brief 保護store内のbase64を原byteへ戻しcanonical性を検証します。
 * @param[in] encoded 最大700KiBのcanonical base64。
 * @return 最大512KiBの原byte。欠損・不正形式はnulloptです。
 */
[[nodiscard]] std::optional<std::string> decodeBody( const std::wstring &encoded)
{
	DWORD size{} ;	// 終端を含めない復号byte数。
	// 空・過大・SDK変換失敗を旧200として扱いません。
	if( encoded.empty() || encoded.size() > 700U * 1024U ||
	   !CryptStringToBinaryW( encoded.c_str(), static_cast<DWORD>( encoded.size()),
							 CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr) ||
	   size == 0U || size > 512U * 1024U) {
		return std::nullopt ;
	}

	std::string decoded( size, '\0') ;	// 原byteだけを持つ所有buffer。
	// Win32 byte出力の境界でだけ借用文字列の型を変換します。
	if( !CryptStringToBinaryW( encoded.c_str(), static_cast<DWORD>( encoded.size()),
							 CRYPT_STRING_BASE64, reinterpret_cast<BYTE *>( decoded.data()), &size,
							 nullptr, nullptr) ||
	   size != decoded.size() || bodyBase64( decoded) != encoded) {
		return std::nullopt ;
	}

	return decoded ;
}

/**
 * @brief runを秘密非保持のJSON本文へ変換します。
 * @param[in] run 保存対象の今回run。同期中だけ借用する。
 * @return 永続envelopeへ渡すUTF-8 JSON原byte。
 */
[[nodiscard]] std::string encodeRun( const LocalCollectorRun &run)
{
	// 永続化する許可fieldのJSON本文。
	JsonObject body ;
	putString( body, L"schema", L"dc-collector-run-v4") ;
	putString( body, L"manifestSha256", run.manifestSha256) ;
	putString( body, L"contractSha256", run.contractSha256) ;
	putString( body, L"day", run.day) ;
	body.Insert( L"complete", JsonValue::CreateBooleanValue( run.complete)) ;
	// 元manifest順序を維持したtarget結果配列を保持する。
	JsonArray targets ;
	// 有限集合の各要素を順に検証し、件数と順序を保持する。
	for( const LocalCollectorTargetResult &target : run.targets) {
		// 今回検査するtarget行。
		JsonObject row ;
		putString( row, L"keySha256", target.keySha256) ;
		putString( row, L"source", target.source) ;
		putString( row, L"publicModel", target.publicModel) ;
		putString( row, L"operatingSystem", target.operatingSystem) ;
		putString( row, L"category", target.category) ;
		putString( row, L"state", stateName( target.state)) ;
		putNumber( row, L"lastSuccessfulValidationAt", target.lastSuccessfulValidationAt) ;
		putNumber( row, L"lastAttemptAt", target.lastAttemptAt) ;
		putNumber( row, L"error", target.error) ;
		putNumber( row, L"lastFetchedAt", target.lastFetchedAt) ;
		putNumber( row, L"lastHttpStatus", target.lastHttpStatus) ;
		putString( row, L"requestBindingSha256", target.requestBindingSha256) ;
		putString( row, L"bodySha256", target.bodySha256) ;
		putString( row, L"projectionSha256", target.projectionSha256) ;
		putString( row, L"entityTag", target.entityTag) ;
		putNumber( row, L"nextAttemptAt", target.nextAttemptAt) ;
		putString( row, L"holdReason", target.holdReason) ;
		putNumber( row, L"observedRecordCount", target.observedRecordCount) ;
		row.Insert( L"records", encodeRecords( target.records)) ;
		// 日次modeで検証した元200だけを既存保護storeへ追加保存します。
		if( !target.retainedMetadataBytes.empty()) {
			putString( row, L"retainedBodyBytesBase64", bodyBase64( target.retainedMetadataBytes)) ;
		}

		targets.Append( row) ;
	}

	body.Insert( L"targets", targets) ;
	return winrt::to_string( body.Stringify()) ;
}

/**
 * @brief 保存済みrunのschema、target、値域をすべて照合します。
 * @param[in] bytes 保存run本文のUTF-8 byte view。
 * @return 全schema・値域・完了条件が成立するrun。拒否または解析例外時はnullopt。
 */
[[nodiscard]] std::optional<LocalCollectorRun> decodeRun( const std::string_view bytes)
{
	// 検証対象の公式・JSON root。
	const auto root = parseObject( bytes) ;
	// 入力と出力を有限上限内へ制限する。
	if( !root || root->Size() != 6U ||
	   stringField( *root, L"schema", 32U) != L"dc-collector-run-v4") {
		return std::nullopt ;
	}

	// 実byte SHA-256。
	const auto hash = stringField( *root, L"manifestSha256", 64U) ;
	// 収集実装と固定設定の実byte結合。
	const auto contract = stringField( *root, L"contractSha256", 64U) ;
	// JST日付。
	const auto day = stringField( *root, L"day", 8U) ;
	// 実byteの指紋と保存済みの結合を確認する。
	if( !hash || !hashName( *hash) || !contract || !hashName( *contract) || !day || !dayName( *day)) {
		return std::nullopt ;
	}

	// pointer昇格済みかを区別するrun終端flag。
	bool complete{} ;
	try {
		// Boolean以外の完了表現を拒否する。
		const auto value = root->GetNamedValue( L"complete") ;
		// 保存状態の型を固定する。
		if( value.ValueType() != JsonValueType::Boolean) {
			return std::nullopt ;
		}

		complete = value.GetBoolean() ;
	} catch( ...) {
		return std::nullopt ;
	}

	// 日付とmanifestに固定した収集run。
	LocalCollectorRun run{
		.manifestSha256 = *hash, .contractSha256 = *contract, .day = *day, .complete = complete} ;
	try {
		// JSONから読み取った有限配列。
		const auto values = root->GetNamedValue( L"targets") ;
		// この段階の入力条件を満たさない値を採用しない。
		if( values.ValueType() != JsonValueType::Array) {
			return std::nullopt ;
		}

		// 有限のtarget配列。
		const JsonArray rows = values.GetArray() ;
		// 入力と出力を有限上限内へ制限する。
		if( rows.Size() == 0U || rows.Size() > MAXIMUM_TARGETS) {
			return std::nullopt ;
		}

		// 有限集合の各要素を順に検証し、件数と順序を保持する。
		for( const auto &item : rows) {
			// この段階の入力条件を満たさない値を採用しない。
			if( item.ValueType() != JsonValueType::Object) {
				return std::nullopt ;
			}

			// 今回検査するtarget行。
			const JsonObject row = item.GetObject() ;
			// manifestから再計算するtarget key。
			const auto		 key = stringField( row, L"keySha256", 64U) ;
			// 組み込み公式source識別子。
			const auto		 source = stringField( row, L"source", 32U) ;
			// 公開製品model。
			const auto		 model = stringField( row, L"publicModel", 128U) ;
			// 公開OS条件。
			const auto		 os = stringField( row, L"operatingSystem", 32U) ;
			// 公式driver分類。
			const auto		 category = stringField( row, L"category", 32U) ;
			// 保存済み状態名。
			const auto		 stateText = stringField( row, L"state", 32U) ;
			// 検証済み状態。
			const auto		 state = stateText ? parseState( *stateText) : std::nullopt ;
			// 最後の成功確認時刻。
			const auto		 success = numberField( row, L"lastSuccessfulValidationAt") ;
			// 今回の試行時刻。
			const auto		 attempt = numberField( row, L"lastAttemptAt") ;
			// 元のAPI診断。
			const auto		 error	 = numberField( row, L"error") ;
			const auto		 fetched = numberField( row, L"lastFetchedAt") ;	// 200受信時刻。
			const auto		 status	 = numberField( row, L"lastHttpStatus") ;	// 今回HTTP状態。
			const auto		 binding =
				// 固定request結合。
				stringField( row, L"requestBindingSha256", 64U) ;
			const auto bodyHash	  = stringField( row, L"bodySha256", 64U) ;			// 元本文指紋。
			const auto projection = stringField( row, L"projectionSha256", 64U) ;	// 射影指紋。
			const auto tag		  = stringField( row, L"entityTag", 256U) ;			// 限定ETag。
			// 元の失敗を成功として扱わず、この段階を停止する。
			const auto next		= numberField( row, L"nextAttemptAt") ;			// 次回試行期限。
			const auto reason	= stringField( row, L"holdReason", 32U) ;		// 固定保留理由。
			const auto observed = numberField( row, L"observedRecordCount") ;	// 今回件数。
			// 欠損と未知状態を成功へ補完しない。
			if( (row.Size() != 19U && row.Size() != 20U) ||
			   (row.Size() == 20U && !row.HasKey( L"retainedBodyBytesBase64")) || !key ||
			   !hashName( *key) || !source || !model || !os || !category || !state || !success ||
			   !attempt || !error || *error > std::numeric_limits<std::uint32_t>::max() ||
			   !fetched || !status || *status > 599U || !binding ||
			   (!binding->empty() && !hashName( *binding)) || !bodyHash ||
			   (!bodyHash->empty() && !hashName( *bodyHash)) || !projection ||
			   (!projection->empty() && !hashName( *projection)) || !tag ||
			   (!tag->empty() && !isCollectorEntityTag( *tag)) || *fetched > *success || !next ||
			   *next > 253402300799ULL || !observed || *observed > 16U || !reason ||
			   (*reason != L"NONE" && *reason != L"RETRY_AFTER" && *reason != L"EMPTY_RESPONSE" &&
				*reason != L"RECORD_DECREASE") ||
			   (*state == LocalCollectorTargetState::HELD && *reason == L"NONE")) {
				return std::nullopt ;
			}

			// 今回のtarget別保存結果。
			LocalCollectorTargetResult result{.keySha256				  = *key,
											  .source					  = *source,
											  .publicModel				  = *model,
											  .operatingSystem			  = *os,
											  .category					  = *category,
											  .state					  = *state,
											  .lastSuccessfulValidationAt = *success,
											  .lastAttemptAt			  = *attempt,
											  .error		  = static_cast<std::uint32_t>( *error),
											  .lastFetchedAt  = *fetched,
											  .lastHttpStatus = static_cast<std::uint32_t>( *status),
											  .requestBindingSha256 = *binding,
											  .bodySha256			= *bodyHash,
											  .projectionSha256		= *projection,
											  .entityTag			= *tag} ;
			// 今回の保存済みrecord配列の型を検証する。
			const auto				   recordValue = row.GetNamedValue( L"records") ;
			// 公式recordの出典と許可fieldを照合する。
			if( recordValue.ValueType() != JsonValueType::Array) {
				return std::nullopt ;
			}

			// 今回の有限公式record集合。
			const JsonArray records = recordValue.GetArray() ;
			// 入力と出力を有限上限内へ制限する。
			if( records.Size() > 16U) {
				return std::nullopt ;
			}

			// 有限集合の各要素を順に検証し、件数と順序を保持する。
			for( const auto &recordValueItem : records) {
				// 公式recordの出典と許可fieldを照合する。
				if( recordValueItem.ValueType() != JsonValueType::Object) {
					return std::nullopt ;
				}

				// 今回検証する公式配布record。
				const JsonObject record = recordValueItem.GetObject() ;
				// 公式recordのstable指紋。
				const auto		 fingerprint = stringField( record, L"fingerprint", 64U) ;
				// 公開配布行の表示名を保持する。
				const auto		 title = stringField( record, L"displayTitle", 512U) ;
				// 公式recordに記載されたdriver分類。
				const auto		 recordCategory = stringField( record, L"driverCategory", 128U) ;
				// 公式recordに記載されたOS条件。
				const auto		 recordOs = stringField( record, L"operatingSystem", 128U) ;
				// 配布元が明示したpackage版を保持する。
				const auto		 version = stringField( record, L"packageVersion", 128U) ;
				// 公式recordに記載された公開日。
				const auto		 date = stringField( record, L"publishedDate", 128U) ;
				// 実byteの指紋と保存済みの結合を確認する。
				if( record.Size() != 6U || !fingerprint || !hashName( *fingerprint) || !title ||
				   !recordCategory || !recordOs || !version || !date ||
				   !publicText( *title, 512U, true) || !publicText( *recordCategory, 128U, true) ||
				   !publicText( *recordOs, 128U, true) || !publicText( *version, 128U, true) ||
				   !publicText( *date, 128U, true)) {
					return std::nullopt ;
				}

				result.records.push_back(
					{*fingerprint, *title, *recordCategory, *recordOs, *version, *date}) ;
			}

			// 旧19fieldはそのまま読み、追加本文の欠損・改変は成功へ補完しません。
			if( row.HasKey( L"retainedBodyBytesBase64")) {
				const auto encoded =
					// 保護本文。
					stringField( row, L"retainedBodyBytesBase64", 700U * 1024U) ;
				const auto	 raw = encoded ? decodeBody( *encoded) : std::nullopt ;	// 原byte。
				std::wstring actual ;												// 元200に一致するhash。
				// 元200hashとrecord/request/fetch結合の両方を検証します。
				if( !raw || computeBytesSha256( *raw, actual) != 0 || actual != result.bodySha256 ||
				   projectionHash( result) != result.projectionSha256 ||
				   result.lastFetchedAt == 0U) {
					return std::nullopt ;
				}

				result.retainedMetadataBytes = *raw ;
			}

			run.targets.push_back( std::move( result)) ;
			run.targets.back().nextAttemptAt	   = *next ;
			run.targets.back().holdReason		   = *reason ;
			run.targets.back().observedRecordCount = static_cast<std::uint32_t>( *observed) ;
		}
	} catch( ...) {
		return std::nullopt ;
	}

	// 未完了targetを含むrunを完了と偽装させない。
	if( run.complete && std::any_of( run.targets.begin(), run.targets.end(), []( const auto &target) {
		   return target.state == LocalCollectorTargetState::PENDING ||
				  target.state == LocalCollectorTargetState::IN_PROGRESS ;
	   })) {
		return std::nullopt ;
	}

	return run ;
}

/**
 * @brief 本文hash付きの単一file envelopeへ保存します。
 * @param[in,out] store 同じworkerが排他を保持する保護store。
 * @param[in] path 保護storeからの許可相対名。同期中だけ借用する。
 * @param[in] body 最大1 MiBの保存本文。同期中だけ借用する。
 * @return 実hash生成とstore.writeの両方が成功した場合true。それ以外はfalse。
 */
[[nodiscard]] bool saveEnvelope( LocalCollectorStateStore &store, const std::filesystem::path &path,
								const std::string_view body)
{
	// 実byte SHA-256。
	std::wstring hash ;
	// 実byteの指紋と保存済みの結合を確認する。
	if( body.size() > MAXIMUM_STATE_BYTES || computeBytesSha256( body, hash) != 0) {
		return false ;
	}

	// hash付き状態envelope。
	JsonObject wrapper ;
	putString( wrapper, L"schema", L"dc-collector-envelope-v1") ;
	putString( wrapper, L"sha256", hash) ;
	wrapper.Insert( L"body", JsonValue::CreateStringValue( winrt::to_hstring( body))) ;
	// 検証する実byte列。
	const std::string bytes = winrt::to_string( wrapper.Stringify()) ;
	return store.write( path, bytes) == ERROR_SUCCESS ;
}

/**
 * @brief 原byte SHAを検証してからcheckpoint本文を返します。
 * @param[in,out] store 同じworkerが排他を保持する保護store。
 * @param[in] path 保護storeからの許可相対名。同期中だけ借用する。
 * @return Envelopeと原byte SHA-256を検証した所有本文。欠損、I/O、構造、hash違反はnullopt。
 */
[[nodiscard]] std::optional<std::string> loadEnvelope( LocalCollectorStateStore	  &store,
													  const std::filesystem::path &path)
{
	// 検証する実byte列。
	std::string bytes ;
	// 初回欠損と読取り失敗を分ける。
	bool		found{} ;
	// ownerとACLを確認した同じhandleからだけ本文を受け取る。
	if( store.read( path, bytes, found) != ERROR_SUCCESS || !found) {
		return std::nullopt ;
	}

	// hash付き状態envelope。
	const auto wrapper = parseObject( bytes) ;
	// 入力と出力を有限上限内へ制限する。
	if( !wrapper || wrapper->Size() != 3U ||
	   stringField( *wrapper, L"schema", 32U) != L"dc-collector-envelope-v1") {
		return std::nullopt ;
	}

	// 実byte SHA-256。
	const auto hash = stringField( *wrapper, L"sha256", 64U) ;
	// 永続化する許可fieldのJSON本文。
	const auto body = stringField( *wrapper, L"body", MAXIMUM_STATE_BYTES) ;
	// 実byteの指紋と保存済みの結合を確認する。
	if( !hash || !body || !hashName( *hash)) {
		return std::nullopt ;
	}

	// hash照合後のUTF-8本文。
	const std::string utf8Body = winrt::to_string( winrt::hstring( *body)) ;
	// 再計算した実byte SHA-256。
	std::wstring	  actual ;
	// 実byteの指紋と保存済みの結合を確認する。
	if( computeBytesSha256( utf8Body, actual) != 0 || actual != *hash) {
		return std::nullopt ;
	}

	return utf8Body ;
}

/** @brief 保護storeの日次世代headを非変更で検証します。
 * @param[in,out] store Lock取得済みの既存store。
 * @param[out] generation 欠損時3、存在時は最大の予約済み運用世代。
 * @param[out] receiptHash 直前receiptのhash。初回は空です。
 * @return 不正headやI/O失敗はfalse。巻戻りのために欠損扱いしません。
 */
[[nodiscard]] bool loadDailyGeneration( LocalCollectorStateStore &store, std::uint64_t &generation,
									   std::wstring &receiptHash)
{
	generation = 3U ;
	receiptHash.clear() ;
	std::string raw ;		// 存在の確認。本文は同じ保護storeで再検証します。
	bool		found{} ;	// 初回欠損だけを許します。
	// 読取拒否を初回へ読み替えません。
	if( store.read( L"current/daily-generation-v1.json", raw, found) != ERROR_SUCCESS) {
		return false ;
	}

	// 初回世代は受入用1..3の次から始めます。
	if( !found) {
		return true ;
	}

	const auto body =
		// Hash検証済み原byte。
		loadEnvelope( store, L"current/daily-generation-v1.json") ;
	const auto value = body ? parseObject( *body) : std::nullopt ;	// 厳密head。
	// 旧headの任意schemaを採用しません。
	if( !value || value->Size() != 3U ||
	   stringField( *value, L"schema", 40U) != L"dc-collector-daily-generation-v1") {
		return false ;
	}

	const auto saved = numberField( *value, L"generation") ;			// JSONで厳密に表せる整数だけ。
	const auto hash	 = stringField( *value, L"receiptSha256", 64U) ;	// 前回receipt hash。
	// オーバーフロー・不正hash・受入世代との混同を拒否します。
	if( !saved || *saved < 4U || *saved > 9007199254740991ULL || !hash || !hashName( *hash)) {
		return false ;
	}

	generation	= *saved ;
	receiptHash = *hash ;
	return true ;
}

/**
 * @brief state rootを現在workspaceのwork/state配下へ制限します。
 * @param[in] candidate Local state root候補。同期中だけ借用する。
 * @return 現在repositoryのwork/state直下へ字句的に限定した絶対path。条件不成立はnullopt。実handle検査はstore側が行う。
 */
[[nodiscard]] std::optional<std::filesystem::path> checkedStateRoot(
	const std::filesystem::path &candidate)
{
	// 元のAPI診断。
	std::error_code error ;
	// 現在workspaceの正規path。
	const auto		repository =
		std::filesystem::absolute( std::filesystem::current_path()).lexically_normal() ;
	// 操作対象のfileとworkspaceを限定する。
	if( !std::filesystem::exists( repository / L"docs" / L"adr" /
								L"0209-local-first-recurring-driver-collector.md")) {
		return std::nullopt ;
	}

	// stateを置く許可root。
	const auto base = repository / L"work" / L"state" ;

	// reparseを解決せず残し、state storeの実handle検査で拒否する。
	const auto selected = std::filesystem::absolute( candidate, error).lexically_normal() ;
	// 元の失敗を成功として扱わず、この段階を停止する。
	if( error || selected.parent_path() != base || selected.filename().empty()) {
		return std::nullopt ;
	}

	return selected ;
}

/**
 * @brief JST日付と同じ日のrun filenameだけを生成します。
 * @return 現在の固定JST日付YYYYMMDD。時刻変換・表記失敗時は空。
 */
[[nodiscard]] std::wstring currentDay()
{
	// 今回のUTC秒。
	const auto now = std::chrono::system_clock::now() + std::chrono::hours( 9) ;
	// JST日付計算用の時刻。
	const auto time = std::chrono::system_clock::to_time_t( now) ;
	// UTC変換後の暦日。
	std::tm	   date{} ;
	// この段階の入力条件を満たさない値を採用しない。
	if( gmtime_s( &date, &time) != 0) {
		return {} ;
	}

	// 固定長日付表現。
	wchar_t buffer[9]{} ;
	// この段階の入力条件を満たさない値を採用しない。
	if( wcsftime( buffer, 9U, L"%Y%m%d", &date) != 8U) {
		return {} ;
	}

	return buffer ;
}

/**
 * @brief UTC秒を整数精度内で返します。
 * @return 正のUnix epoch秒。時計値が0以下なら0。
 */
[[nodiscard]] std::uint64_t nowSeconds()
{
	// Unix epoch秒。
	const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
		std::chrono::system_clock::now().time_since_epoch()) ;
	return seconds.count() > 0 ? static_cast<std::uint64_t>( seconds.count()) : 0U ;
}

/**
 * @brief 実binaryと固定設定の変更を前回runから分離します。
 * @return 現在EXEと固定収集設定を結合した完全SHA-256。Module取得・hash失敗はnullopt。
 */
[[nodiscard]] std::optional<std::wstring> collectorContractSha256()
{
	// Win32の最大拡張path長まで有限bufferを許す。
	std::wstring module( 32768U, L'\0') ;
	// 実際に稼働中のEXEだけを結合する。
	const DWORD	 length =
		GetModuleFileNameW( nullptr, module.data(), static_cast<DWORD>( module.size())) ;
	// 切り詰められたpathをhash対象にしない。
	if( length == 0U || length >= module.size()) {
		return std::nullopt ;
	}

	module.resize( length) ;
	// parserとsource policyを静的に含むEXEの指紋。
	std::wstring binaryHash ;
	// file取得失敗を未変更と扱わない。
	if( computeFileSha256( module, binaryHash) != 0 || !hashName( binaryHash)) {
		return std::nullopt ;
	}

	// run結果に影響する固定設定をEXE指紋に結合する。
	const std::string contract = "dc-collector-contract-v4|fresh=86400|budget=3600|"
								 "max-targets=32|projection=v1|binary=" +
								 winrt::to_string( winrt::hstring( binaryHash)) ;
	// pathと状態本文へ使う完全な収集契約SHA。
	std::wstring contractHash ;
	// 不完全な契約指紋を再開keyに使用しない。
	if( computeBytesSha256( contract, contractHash) != 0 || !hashName( contractHash)) {
		return std::nullopt ;
	}

	return contractHash ;
}

/**
 * @brief SHAを省略せず、旧schemaと重ならない完全なrun名を作ります。
 * @param[in] day 検査済みの8桁JST日付。
 * @param[in] manifestSha256 検査済みの元manifest完全SHA-256。
 * @param[in] contractSha256 検査済みの収集契約完全SHA-256。
 * @return runs直下の完全相対名。Fileの作成や存在確認は行わない。
 */
[[nodiscard]] std::filesystem::path runFilePath( const std::wstring &day,
												const std::wstring &manifestSha256,
												const std::wstring &contractSha256)
{
	return std::filesystem::path( L"runs") /
		   (day + L"-" + manifestSha256 + L"-" + contractSha256 + L".json") ;
}

/**
 * @brief 同じmanifestと収集契約の確定pointer名です。
 * @param[in] manifestSha256 検査済みの元manifest完全SHA-256。
 * @param[in] contractSha256 検査済みの収集契約完全SHA-256。
 * @return current直下の完全相対名。Fileの作成や存在確認は行わない。
 */
[[nodiscard]] std::filesystem::path pointerFilePath( const std::wstring &manifestSha256,
													const std::wstring &contractSha256)
{
	return std::filesystem::path( L"current") / (manifestSha256 + L"-" + contractSha256 + L".json") ;
}

/**
 * @brief 前世代pointerが参照する完全なrunだけを読みます。
 * @param[in,out] store 同じworkerが排他を保持する保護store。
 * @param[in] manifestSha256 今回と一致を必須とする元manifest hash。
 * @param[in] contractSha256 今回と一致を必須とする収集契約hash。
 * @return Pointer、本文hash、scope、完了条件が一致する前run。欠損や違反時はnullopt。
 */
[[nodiscard]] std::optional<LocalCollectorRun> loadPrevious( LocalCollectorStateStore &store,
															const std::wstring &manifestSha256,
															const std::wstring &contractSha256)
{
	// 永続化する許可fieldのJSON本文。
	const auto body = loadEnvelope( store, pointerFilePath( manifestSha256, contractSha256)) ;
	// 最後に確定した世代のpointer。
	const auto pointer = body ? parseObject( *body) : std::nullopt ;
	// 入力と出力を有限上限内へ制限する。
	if( !pointer || pointer->Size() != 5U ||
	   stringField( *pointer, L"schema", 32U) != L"dc-collector-current-v4") {
		return std::nullopt ;
	}

	// JST日付。
	const auto day = stringField( *pointer, L"day", 8U) ;
	// 実byte SHA-256。
	const auto hash = stringField( *pointer, L"manifestSha256", 64U) ;
	// pointerとrunの収集契約を一致させる。
	const auto contract = stringField( *pointer, L"contractSha256", 64U) ;
	// 確定runの実byte SHA-256。
	const auto runHash = stringField( *pointer, L"runSha256", 64U) ;
	// 実byteの指紋と保存済みの結合を確認する。
	if( !day || !dayName( *day) || !hash || *hash != manifestSha256 || !hashName( *hash) ||
	   !contract || *contract != contractSha256 || !hashName( *contract) || !runHash ||
	   !hashName( *runHash)) {
		return std::nullopt ;
	}

	// hash照合した前世代本文を保持する。
	const auto	 saved = loadEnvelope( store, runFilePath( *day, *hash, *contract)) ;
	// 再計算した実byte SHA-256。
	std::wstring actual ;
	// 実byteの指紋と保存済みの結合を確認する。
	if( !saved || computeBytesSha256( *saved, actual) != 0 || actual != *runHash) {
		return std::nullopt ;
	}

	// 直近の検証済みrun。
	const auto previous = decodeRun( *saved) ;
	// 実byteの指紋と保存済みの結合を確認する。
	if( !previous || !previous->complete || previous->day != *day ||
	   previous->manifestSha256 != *hash || previous->contractSha256 != *contract) {
		return std::nullopt ;
	}

	return previous ;
}

/** @brief 同じ保護rootの全manifest・binaryへ適用するsource待機です。 */
struct SourceCooldown {
	/// 最後に429／503を受けたUTC。
	std::uint64_t observedAt{} ;
	/// 次回照会可能UTC。欠損は0。
	std::uint64_t nextAttemptAt{} ;
	/// 不明な待機指定を自動解除しない場合true。
	bool		  needsReview{} ;
	/// 元の429または503。欠損は0。
	std::uint32_t status{} ;
} ;

/** @brief URL非保持のsource別台帳名を作ります。
 * @param[in] source 固定manifest source。
 * @return current直下のcooldown名。計算失敗時は空。
 */
[[nodiscard]] std::filesystem::path cooldownPath( const std::wstring &source)
{
	std::wstring hash ;	// 公開sourceの完全hash。
	// 不完全なkeyに書き込まない。
	if( computeBytesSha256( winrt::to_string( winrt::hstring( source)), hash) != 0) {
		return {} ;
	}

	return std::filesystem::path( L"current") / (L"cooldown-" + hash + L".json") ;
}

/** @brief 存在する待機台帳は形式とsourceまで検証します。
 * @param[in,out] store Lock取得済みの保護store。
 * @param[in] source 固定source名。
 * @param[out] cooldown 欠損時は待機なし、失敗時は初期値。
 * @return 欠損または完全検証成功ならtrue。
 */
[[nodiscard]] bool loadCooldown( LocalCollectorStateStore &store, const std::wstring &source,
								SourceCooldown &cooldown)
{
	cooldown		 = {} ;
	const auto	path = cooldownPath( source) ;	// source別の独立台帳。
	std::string bytes ;							// 存在確認用の保護読取り。
	bool		found{} ;						// 欠損と破損を区別する。
	// 読取り失敗を待機なしにしない。
	if( path.empty() || store.read( path, bytes, found) != ERROR_SUCCESS) {
		return false ;
	}

	// 初回欠損はHTTP可能。
	if( !found) {
		return true ;
	}

	const auto body	  = loadEnvelope( store, path) ;				// 同じlock下のhash検証。
	const auto object = body ? parseObject( *body) : std::nullopt ;	// 有限JSON。
	// 旧・未知schemaを無視して再送しない。
	if( !object || object->Size() != 6U ||
	   stringField( *object, L"schema", 32U) != L"dc-collector-cooldown-v1" ||
	   stringField( *object, L"source", 64U) != source) {
		return false ;
	}

	const auto observed = numberField( *object, L"observedAt") ;	// 失敗受信時刻。
	const auto next		= numberField( *object, L"nextAttemptAt") ;	// 絶対期限。
	const auto status	= numberField( *object, L"status") ;		// 元HTTP状態。
	// 未来方向への期限と既知HTTP拒否だけを保存する。
	if( !observed || *observed == 0U || !next || *next < *observed || *next > 253402300799ULL ||
	   !status || (*status != 429U && *status != 503U)) {
		return false ;
	}

	try {
		const auto review = object->GetNamedValue( L"needsReview") ;	// 厳密Boolean。
		// 型を暗黙変換しない。
		if( review.ValueType() != JsonValueType::Boolean) {
			return false ;
		}

		cooldown = {*observed, *next, review.GetBoolean(), static_cast<std::uint32_t>( *status)} ;
	} catch( ...) {
		return false ;
	}

	return true ;
}

/** @brief Source待機をtarget checkpointより先に確定します。
 * @param[in,out] store Lock取得済みstore。
 * @param[in] source 固定source名。
 * @param[in] cooldown 有限UTCと非機密な失敗観測。
 * @return 完全な永続化に成功した場合true。
 */
[[nodiscard]] bool saveCooldown( LocalCollectorStateStore &store, const std::wstring &source,
								const SourceCooldown &cooldown)
{
	JsonObject body ;	// 原headerは含めない。
	putString( body, L"schema", L"dc-collector-cooldown-v1") ;
	putString( body, L"source", source) ;
	putNumber( body, L"observedAt", cooldown.observedAt) ;
	putNumber( body, L"nextAttemptAt", cooldown.nextAttemptAt) ;
	putNumber( body, L"status", cooldown.status) ;
	body.Insert( L"needsReview", JsonValue::CreateBooleanValue( cooldown.needsReview)) ;
	return saveEnvelope( store, cooldownPath( source), winrt::to_string( body.Stringify())) ;
}

/** @brief 生存する新200の一recordから、明示同意と有限予算の範囲だけを取得します。
 * @param[in,out] record 同runの型付き公式record。成功時に秘密URLを消費します。
 * @param[in,out] client 同recordの新200証拠を所有するcache無効client。
 * @param[in] request 明示同意/予算と保護callerの非置換commitです。
 * @param[in] clock 元runの現在UTC秒です。
 * @param[in] cancelled 元runの単調期限または同意失効を確認します。
 * @param[in] fixtureCost 非nullは非通信fixtureの回線照会です。
 * @return 取得/封印/新archive commit成功0、元失敗のbit patternです。
 */
[[nodiscard]] std::uint32_t acquireTargetPayload( OfficialDistributionRecord			  &record,
												 OfficialHttpClient					  &client,
												 const LocalCollectorPayloadRequest	  &request,
												 const std::function<std::uint64_t()> &clock,
												 const HttpCancellationCallback		  &cancelled,
												 IOfficialNetworkCostReader			  *fixtureCost)
{
	const auto	 now = clock() ;	// Grant発行前の原時計です。
	std::wstring termsHash ;		// PAGE全体と区別する抽出全文です。
	// 欠同意/変更/不明時刻やmetadata不足からpayload権限を作りません。
	if( !request.termsAccepted || now == 0U || now >= request.consentNotAfter ||
	   request.consentNotAfter - now > SECONDS_PER_DAY || !request.commitArchive ||
	   request.termsRevision != record.eulaRevision ||
	   computeBytesSha256( winrt::to_string( winrt::hstring{record.eulaText}), termsHash) != 0 ||
	   termsHash != request.termsTextSha256 || record.payloads.size() != 1U ||
	   record.terms != OfficialDistributionTerms::ACCEPTANCE_REQUIRED) {
		return ERROR_ACCESS_DENIED ;
	}

	auto &payload = record.payloads.front() ;	// 同recordの一payloadだけです。
	// 公表hash/sizeを期待値で上書きせず、上限だけを今回予算へ狭めます。
	if( payload.kind != OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE ||
	   request.payloadUrl != payload.targetUrl.view() ||
	   request.fileName != payload.fileDisplayName ||
	   request.packageVersion != record.packageVersion ||
	   request.publishedSizeBytes != payload.publishedSizeBytes ||
	   (payload.publishedSha256.empty() && payload.publishedSha512.empty()) ||
	   CompareStringOrdinal( payload.publishedSha256.c_str(), -1, request.publishedSha256.c_str(),
							-1, TRUE) != CSTR_EQUAL ||
	   CompareStringOrdinal( payload.publishedSha512.c_str(), -1, request.publishedSha512.c_str(),
							-1, TRUE) != CSTR_EQUAL ||
	   request.maximumBytes == 0U || request.maximumBytes > 128U * 1024U * 1024U ||
	   (payload.publishedSizeBytes && *payload.publishedSizeBytes > request.maximumBytes)) {
		return ERROR_INVALID_DATA ;
	}

	payload.maximumBytes = std::min( payload.maximumBytes, request.maximumBytes) ;
	OfficialDistributionRecordEvidence evidence ;	// 狭めた同recordの再検証です。
	RecordScopedDownloadGrant		   grant ;		// 一回の私有recordだけから発行します。
	OfficialAcquisitionSession		   session ;	// 別日次counterを作らない揮発性取得予算です。
	OfficialDownloadWorkspace		   workspace ;	// 失敗partialを既存RAIIで回収します。
	const OfficialAcquisitionLimits	   limits{payload.maximumBytes,
											  payload.maximumBytes,
											  payload.maximumBytes,
											  64U * 1024U * 1024U,
											  1U,
											  1U} ;	// 一file/一sessionです。
	NativeError						   error =
		// 原authority再検証です。
		validateOfficialDistributionRecord( record, evidence) ;
	// 元失敗がある段階以後のgrant/取得を開始しません。
	if( error == 0) {
		error = grant.issue( record, evidence, 0U, 1U, now, 0U) ;
	}

	// 一回の承認予算だけを同sessionへ設定します。
	if( error == 0) {
		error = session.initialize( evidence.rootEvidence.scanSessionId, limits) ;
	}

	// 取得先は共通の管理者保護workspaceだけです。
	if( error == 0) {
		error = workspace.initialize( L"native-daily-payload", evidence.rootEvidence.scanSessionId) ;
	}

	WindowsOfficialNetworkCostReader osCost ;				// 通常は既存OS costを使用します。
	OfficialHttpAcquisitionTransport transport( client) ;	// 同じ新200 clientを借用します。
	OfficialAcquisitionResult		 acquired ;				// 公開authorityや導入許可ではありません。
	// 公式起点/CDN/size/hashと進捗は既存共通取得器で検証します。
	if( error == 0) {
		error = acquireGrantedOfficialPayload( session, workspace, transport,
											  fixtureCost != nullptr ? *fixtureCost : osCost, grant,
											  clock, false, cancelled, acquired) ;
	}

	// 本体取得後に失効した同意や単調期限をcommitへ進めません。
	if( error == 0 && cancelled()) {
		error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	}

	// 保護callerが封印と実byteを再照合してatomic非置換保存します。
	if( error == 0 && ((!request.publishedSha256.empty() && !acquired.publishedSha256Verified) ||
					  (!request.publishedSha512.empty() && !acquired.publishedSha512Verified) ||
					  (request.publishedSizeBytes && !acquired.publishedSizeVerified))) {
		error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	}

	// 全掲載algorithmの実byte検証を完了した結果だけを保存sinkへ渡します。
	if( error == 0) {
		error = request.commitArchive( session, workspace, acquired) ;
	}

	// 保存中に期限が尽きたarchiveは孤立原byteとして保持し、成功receiptを発行しません。
	if( error == 0 && cancelled()) {
		error = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
	}

	return static_cast<std::uint32_t>( error) ;
}

/** @brief 公式adapterを一targetだけ呼び、明示時だけ同recordの本体を取得します。
 * @param[in] target 検証済みの固定公式target。
 * @param[out] projected 成功時だけの公開metadata射影。
 * @param[out] failureStage 最初に拒否した区間。成功時はNONEで、永続化しません。
 * @param[in] transport nullなら実HTTP、非nullなら非通信fixture。
 * @param[in] previous 同じtargetの最後の保存済み公開射影。
 * @param[in] contract 実binaryと固定収集条件の指紋。
 * @param[out] http 元HTTP statusと200本文hash、待機診断。
 * @param[out] binding 組込みURLを含む元requestの非秘密指紋。
 * @param[out] raw 非null時だけ完全新200原byte。失敗診断以外へ失敗本文を公開しません。
 * @param[in] payload 明示日次同意/予算。通常metadataはnullです。
 * @param[in] clock 元runの現在UTCです。
 * @param[in] cancelled 同じrunの延長しない単調期限です。
 * @param[in] fixtureCost 非通信fixtureのcostです。通常はnullです。
 * @return 全配布検証成功0、失敗は元診断。
 * @note Worker内で有限HTTPを待機し、明示時だけ同runの取得grantを消費します。端末ID/導入は扱いません。
 */
[[nodiscard]] std::uint32_t resolveTarget(
	const LocalCollectorTarget &target, std::vector<LocalCollectorRecord> &projected,
	LocalCollectorFailureStage &failureStage, const OfficialHttpTransport *transport,
	const LocalCollectorTargetResult &previous, const std::wstring &contract,
	CollectorHttpObservation &http, std::wstring &binding, std::string *raw,
	const LocalCollectorPayloadRequest *payload, const std::function<std::uint64_t()> &clock,
	const HttpCancellationCallback &cancelled, IOfficialNetworkCostReader *fixtureCost)
{
	projected.clear() ;
	http		 = {} ;
	failureStage = LocalCollectorFailureStage::REQUEST_SESSION ;
	// 通常はcache無効の公式HTTP client。fixtureだけ既存の保護境界へfake応答を渡す。
	std::unique_ptr<OfficialHttpClient> client =
		transport == nullptr ? std::make_unique<OfficialHttpClient>( false)
							 : std::make_unique<OfficialHttpClient>( *transport) ;
	AsusSupportPageRequest asusRequest ;				// 公開modelから再構築した公式要求。
	std::wstring		   url, provider, resource ;	// 今回の固定request。保存しない。
	std::uint64_t		   maximumBytes{} ;				// 公式本文上限。
	// 公開targetと組み込み公式sourceの対応を確認する。
	if( target.source == L"ASUS_CATALOG") {
		// 公開条件を通常経路と同じcanonical起点へ変換する。
		if( !makeAsusPublicModelSupportPageRequest( target.publicModel, target.operatingSystem,
												  asusRequest)) {
			return ERROR_INVALID_DATA ;
		}

		url			 = asusRequest.pageUrl ;
		provider	 = ASUS_PROVIDER_ID ;
		resource	 = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID ;
		maximumBytes = 8U * 1024U * 1024U ;
	}
	// 公開targetと組み込み公式sourceの対応を確認する。
	else if( target.source == L"INTEL_ETHERNET_WINDOWS11") {
		// 組み込み公式起点定義。
		const auto *definition =
			officialSourceDefinition( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;
		// この段階の入力条件を満たさない値を採用しない。
		if( definition == nullptr) {
			return ERROR_INVALID_DATA ;
		}

		url			 = definition->landingUrl ;
		provider	 = definition->providerId ;
		resource	 = OFFICIAL_LANDING_RESOURCE_ID ;
		maximumBytes = definition->maximumMetadataBytes ;
	} else {
		return ERROR_INVALID_PARAMETER ;
	}

	JsonObject requestIdentity ;	// 秘密URLをhash入力内に限定する。
	putString( requestIdentity, L"target", target.keySha256) ;
	putString( requestIdentity, L"contract", contract) ;
	putString( requestIdentity, L"provider", provider) ;
	putString( requestIdentity, L"resource", resource) ;
	putString( requestIdentity, L"url", url) ;
	// 同じ固定requestとbinaryの場合にだけvalidatorを利用する。
	if( computeBytesSha256( winrt::to_string( requestIdentity.Stringify()), binding) != 0) {
		return ERROR_INVALID_DATA ;
	}

	// 明示本体は新200を要求し、通常metadataだけが同request/binaryのvalidatorを利用します。
	const bool reusable = payload == nullptr && previous.requestBindingSha256 == binding &&
						  !previous.records.empty() && hashName( previous.bodySha256) &&
						  hashName( previous.projectionSha256) && previous.lastFetchedAt != 0U &&
						  previous.lastFetchedAt <= previous.lastSuccessfulValidationAt &&
						  isCollectorEntityTag( previous.entityTag) &&
						  // 結合再確認。
						  projectionHash( previous) == previous.projectionSha256 ;
	NativeError error = client->beginSourceSession( 1U, provider) ;	// 公式session開始。
	// Session拒否時はHTTPを行わない。
	if( error != 0) {
		return static_cast<std::uint32_t>( error) ;
	}

	std::wstring html ;	// 200本文だけを一時保持する。
	failureStage = LocalCollectorFailureStage::METADATA ;
	error		 = client->getCollectorMetadataForSource(
		   url, resource, maximumBytes,
		   reusable ? std::wstring_view( previous.entityTag) : std::wstring_view{}, html, http, raw) ;
	// 失敗後に同じ要求を自動再試行しない。
	if( error != 0) {
		return static_cast<std::uint32_t>( error) ;
	}

	failureStage = LocalCollectorFailureStage::EVIDENCE ;
	// 304で既存parserや取得evidenceを合成しない。
	if( http.status == 304U) {
		// 保存済み射影だけを再確認し、通常取得証拠へ変換しない。
		if( !reusable || !html.empty() || !client->sourceEvidence().empty()) {	// 収集専用の再確認。
			return ERROR_INVALID_DATA ;
		}

		// 304から新しい私有recordや本体取得を復元しません。
		if( payload != nullptr) {
			return ERROR_INVALID_DATA ;
		}

		projected	 = previous.records ;
		failureStage = LocalCollectorFailureStage::NONE ;
		return 0U ;
	}

	const auto evidence = client->sourceEvidence() ;	// 今回の実200取得証拠。
	// 未取得の本文を公式adapterへ渡さない。
	if( evidence.size() != 1U || !evidence.front().bodyAcquiredUtcSeconds) {
		return ERROR_INVALID_DATA ;
	}

	const auto resolved =
		// 解析時刻。
		std::max( nowSeconds(), *evidence.front().bodyAcquiredUtcSeconds) ;
	std::vector<OfficialDistributionRecord> records ;	// 検証済み配布record。
	failureStage = LocalCollectorFailureStage::PARSE ;
	// 同じ公式parser・adapterを使用し、取得済みrawを再取得しない。
	if( target.source == L"ASUS_CATALOG") {
		std::vector<AsusDriverPageEntry> entries ;		// 有限配布行。
		AsusNetworkRecordObservation	 observation ;	// 既存parser診断。
		// Model・OS・分類と通常record検証を維持する。
		if( !parseAsusDriverPageHtml( html, asusRequest.model, asusRequest.osName, entries,
									target.category, &observation.catalog)) {
			return ERROR_INVALID_DATA ;
		}

		// 構造確認済みでもcategory未掲載・全行対象外をdriverなしと断定しない。
		if( entries.empty()) {
			return ERROR_NO_MORE_ITEMS ;
		}

		failureStage = LocalCollectorFailureStage::ADAPT ;
		// 有効entryには通常の公式record検証を適用する。
		if( !adaptAsusNetworkDistributionRecords( entries, asusRequest,
												AsusNetworkRecordTarget::CATALOG, evidence.front(),
												resolved, records, target.category)) {
			return ERROR_INVALID_DATA ;
		}
	} else {
		OfficialReleaseRecord	   release ;	// 固定Intel page解析結果。
		OfficialDistributionRecord record ;		// 同じpage根拠に拘束するrecord。
		// 既存の版・公開hash・許諾本文検証を維持する。
		if( !parseOfficialReleaseRecord( OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11, html,
									   release)) {
			return ERROR_INVALID_DATA ;
		}

		failureStage = LocalCollectorFailureStage::ADAPT ;
		// 同じ解析結果と取得証拠を通常の公式recordへ変換する。
		if( !adaptIntelEthernetWindows11DistributionRecord( std::move( release), evidence.front(), 1U,
														  resolved, record)) {
			return ERROR_INVALID_DATA ;
		}

		records.push_back( std::move( record)) ;
	}

	failureStage = LocalCollectorFailureStage::RECORD_VALIDATION ;
	// 入力と出力を有限上限内へ制限する。
	if( records.empty() || records.size() > 16U) {
		return ERROR_INVALID_DATA ;
	}

	// 有限集合の各要素を順に検証し、件数と順序を保持する。
	for( const OfficialDistributionRecord &record : records) {
		// 公式recordのURL非保持根拠を保持する。
		OfficialDistributionRecordEvidence recordEvidence ;
		// 公式recordの出典と許可fieldを照合する。
		if( validateOfficialDistributionRecord( record, recordEvidence) != 0 ||
		   record.architecture != OfficialDistributionArchitecture::WINDOWS_X64 ||
		   (target.source == L"ASUS_CATALOG" &&
			!record.recordKey.starts_with( target.publicModel + L"|")) ||
		   !publicText( record.productFamily, 512U, true) ||
		   !publicText( record.driverCategory, 128U, true) ||
		   !publicText( record.operatingSystem, 128U, true) ||
		   !publicText( record.packageVersion, 128U, true) ||
		   !publicText( record.publishedDate, 128U, true)) {
			projected.clear() ;
			return ERROR_INVALID_DATA ;
		}

		// 公式recordのstable指紋。
		const std::string fingerprint = officialRecordFingerprint( recordEvidence) ;
		projected.push_back( {std::wstring( fingerprint.begin(), fingerprint.end()),
							 record.productFamily, record.driverCategory, record.operatingSystem,
							 record.packageVersion, record.publishedDate}) ;
	}

	std::sort( projected.begin(), projected.end(), []( const auto &left, const auto &right) {
		return left.fingerprint < right.fingerprint ;
	}) ;
	// 通常metadata-onlyには取得grantを発行しません。
	if( payload != nullptr) {
		failureStage = LocalCollectorFailureStage::PAYLOAD ;
		const auto payloadError =
			acquireTargetPayload( records.front(), *client, *payload, clock, cancelled,
								 fixtureCost) ;	// 元取得/保存診断です。
		// 拒否時だけ区間を残し、元errorを変更しない。
		if( payloadError != 0U) {
			return payloadError ;
		}
	}

	failureStage = LocalCollectorFailureStage::NONE ;
	return 0U ;
}

} // namespace

/** @see local_driver_collector.h */
bool loadLocalCollectorManifest( const std::filesystem::path		  &path,
								std::vector<LocalCollectorTarget> &targets, std::wstring &sha256)
{
	targets.clear() ;
	sha256.clear() ;
	// 検証する実byte列。
	const auto bytes = readSmallFile( path, MAXIMUM_MANIFEST_BYTES) ;
	// 検証対象の公式・JSON root。
	const auto root = bytes ? parseObject( *bytes) : std::nullopt ;
	// 実byteの指紋と保存済みの結合を確認する。
	if( !root || root->Size() != 2U ||
	   stringField( *root, L"schema", 32U) != L"dc-collector-targets-v1" ||
	   computeBytesSha256( *bytes, sha256) != 0) {
		return false ;
	}

	try {
		// JSONから読み取った有限配列。
		const auto values = root->GetNamedValue( L"targets") ;
		// この段階の入力条件を満たさない値を採用しない。
		if( values.ValueType() != JsonValueType::Array) {
			return false ;
		}

		// 有限のtarget配列。
		const JsonArray rows = values.GetArray() ;
		// 入力と出力を有限上限内へ制限する。
		if( rows.Size() == 0U || rows.Size() > MAXIMUM_TARGETS) {
			return false ;
		}

		// 重複target拒否用key集合。
		std::set<std::wstring> seen ;
		// 有限集合の各要素を順に検証し、件数と順序を保持する。
		for( const auto &item : rows) {
			// この段階の入力条件を満たさない値を採用しない。
			if( item.ValueType() != JsonValueType::Object) {
				return false ;
			}

			// 今回検査するtarget行。
			const JsonObject row = item.GetObject() ;
			// 組み込み公式source識別子。
			const auto		 source = stringField( row, L"source", 32U) ;
			// 公開製品model。
			const auto		 model = stringField( row, L"publicModel", 128U) ;
			// 公開OS条件。
			const auto		 os = stringField( row, L"operatingSystem", 32U) ;
			// 公式driver分類。
			const auto		 category = stringField( row, L"category", 32U) ;
			// 入力と出力を有限上限内へ制限する。
			if( row.Size() != 4U || !source || !model || !os || !category) {
				return false ;
			}

			// 今回確認する公開target。
			LocalCollectorTarget   target{*source, *model, *os, *category} ;
			// 公開modelから作った公式page要求。
			AsusSupportPageRequest request ;
			// ASUS公式pageの照合結果。
			const bool			   asus = *source == L"ASUS_CATALOG" && asciiName( *category, 32U) &&
							  makeAsusPublicModelSupportPageRequest( *model, *os, request) ;
			// Intel固定起点の照合結果。
			const bool intel = *source == L"INTEL_ETHERNET_WINDOWS11" && model->empty() &&
							   category->empty() && *os == L"Windows 11 64-bit" ;
			// 実byteの指紋と保存済みの結合を確認する。
			if( (!asus && !intel) || !makeTargetKey( target) ||
			   !seen.insert( target.keySha256).second) {
				return false ;
			}

			targets.push_back( std::move( target)) ;
		}
	} catch( ...) {
		targets.clear() ;
		return false ;
	}

	return true ;
}

/** @see local_driver_collector.h */
bool decodeLocalCollectorPayloadApproval( const std::string_view		   raw,
										 LocalCollectorPayloadRequest &request)
{
	request = {} ;
	try {
		// 保存診断を公式authorityへ復元せず、有限の明示期待値だけを読みます。
		if( raw.empty() || raw.size() > MAXIMUM_STATE_BYTES) {
			return false ;
		}

		const auto release = JsonObject::Parse( winrt::to_hstring( raw)) ;	// 原保存解析です。
		const auto schema  = release.GetNamedString( L"schema") ;			// 未知schemaへfallbackしません。
		// v1へ追加されたSHA-512を黙って除外しません。
		if( (schema != L"dc-saved-release-analysis-v1" &&
			schema != L"dc-saved-release-analysis-v2") ||
		   release.GetNamedString( L"source") != L"INTEL_ETHERNET_WINDOWS11" ||
		   (schema == L"dc-saved-release-analysis-v2") != release.HasKey( L"publishedSha512")) {
			return false ;
		}

		LocalCollectorPayloadRequest parsed ;	// 全検査成功後だけcallerへ移します。
		parsed.termsRevision   = release.GetNamedString( L"termsRevision") ;
		parsed.termsTextSha256 = release.GetNamedString( L"termsTextSha256") ;
		parsed.publishedSha256 = release.GetNamedString( L"publishedSha256") ;
		parsed.publishedSha512 = release.GetNamedString( L"publishedSha512", L"") ;
		parsed.payloadUrl	   = release.GetNamedString( L"payloadUrl") ;
		parsed.fileName		   = release.GetNamedString( L"fileName") ;
		parsed.packageVersion  = release.GetNamedString( L"packageVersion") ;
		std::wstring termsHash ;	// 同じ抽出全文のSHA-256です。
		// 片方不正/全欠測/空metadata/全文矛盾を取得要求へ渡しません。
		if( parsed.termsRevision.empty() || !hashName( parsed.termsTextSha256) ||
		   parsed.payloadUrl.empty() || parsed.fileName.empty() || parsed.packageVersion.empty() ||
		   (parsed.publishedSha256.empty() && parsed.publishedSha512.empty()) ||
		   (!parsed.publishedSha256.empty() && !hashName( parsed.publishedSha256)) ||
		   (schema == L"dc-saved-release-analysis-v2" &&
			(parsed.publishedSha512.size() != 128U ||
			 !hashName( parsed.publishedSha512.substr( 0U, 64U)) ||
			 !hashName( parsed.publishedSha512.substr( 64U)))) ||
		   computeBytesSha256( winrt::to_string( release.GetNamedString( L"termsText")), termsHash) !=
			   0 ||
		   termsHash != parsed.termsTextSha256) {
			return false ;
		}

		// 概算からexactを捏造せず、明示された正整数だけを保持します。
		if( release.HasKey( L"publishedSizeBytes")) {
			const auto exact = release.GetNamedNumber( L"publishedSizeBytes") ;	// 公表exact値です。
			// 0・小数・過大を未知へ変換しません。
			if( !(exact > 0.0 && exact <= 134217728.0) ||
			   exact != static_cast<std::uint64_t>( exact)) {
				return false ;
			}

			parsed.publishedSizeBytes = static_cast<std::uint64_t>( exact) ;
		}

		request = std::move( parsed) ;
		return true ;
	} catch( ...) {
		request = {} ;
		// 構文/型/容量失敗を呼出し側の明示拒否へ返します。
		return false ;
	}
}

/** @see local_driver_collector.h */
int runLocalDriverCollector( const std::filesystem::path				&stateRoot,
							const std::vector<LocalCollectorTarget> &targets,
							const std::wstring &manifestSha256, const bool dryRun,
							LocalCollectorRun &run, const bool retainMetadata, const bool dailyMode,
							const LocalCollectorPayloadRequest *payload)
{
	return runLocalDriverCollectorWithHooks( stateRoot, targets, manifestSha256, dryRun, {}, run,
											retainMetadata, dailyMode, payload) ;
}

/** @see local_driver_collector.h */
int runLocalDriverCollectorWithHooks( const std::filesystem::path			 &stateRoot,
									 const std::vector<LocalCollectorTarget> &targets,
									 const std::wstring &manifestSha256, const bool dryRun,
									 const LocalCollectorTestHooks &hooks, LocalCollectorRun &run,
									 const bool retainMetadata, const bool dailyMode,
									 const LocalCollectorPayloadRequest *payload)
{
	run = {} ;
	const auto approvalNow =
		payload == nullptr
			? 0U
			: (hooks.utcSeconds ? hooks.utcSeconds()
								: nowSeconds()) ;	// 通常metadataの元時計照会順を変えません。
	// 欠同意/失効/未知時計/予算不足はwriterやPAGEの新試行より前に拒否します。
	if( payload != nullptr &&
	   (!dailyMode || !payload->termsAccepted || payload->termsRevision.empty() ||
		!hashName( payload->termsTextSha256) ||
		(payload->publishedSha256.empty() && payload->publishedSha512.empty()) ||
		(!payload->publishedSha256.empty() && !hashName( payload->publishedSha256)) ||
		(!payload->publishedSha512.empty() &&
		 (payload->publishedSha512.size() != 128U ||
		  !hashName( payload->publishedSha512.substr( 0U, 64U)) ||
		  !hashName( payload->publishedSha512.substr( 64U)))) ||
		payload->payloadUrl.empty() || payload->fileName.empty() ||
		payload->packageVersion.empty() ||
		(payload->publishedSizeBytes && (*payload->publishedSizeBytes == 0U ||
										 *payload->publishedSizeBytes > payload->maximumBytes)) ||
		!payload->commitArchive || payload->maximumBytes == 0U ||
		payload->maximumBytes > 128U * 1024U * 1024U || approvalNow == 0U ||
		approvalNow >= payload->consentNotAfter ||
		payload->consentNotAfter - approvalNow > SECONDS_PER_DAY)) {
		run.stateError = ERROR_ACCESS_DENIED ;
		return 2 ;
	}

	// 検証対象の公式・JSON root。
	const auto root = checkedStateRoot( stateRoot) ;
	// 実byteの指紋と保存済みの結合を確認する。
	if( !root || targets.empty() || targets.size() > MAXIMUM_TARGETS || !hashName( manifestSha256)) {
		return 2 ;
	}

	// 日次運用と明示本体取得の対象をIntel一件に固定します。
	if( dailyMode &&
	   (targets.size() != 1U || targets.front().source != L"INTEL_ETHERNET_WINDOWS11")) {
		return 2 ;
	}

	// JST日付と実binaryに結合した収集契約。
	const std::wstring day = hooks.jstDay ? hooks.jstDay() : currentDay() ;
	// parser・policyと有限設定が同じ場合だけrunを再開する。
	const auto		   contract = collectorContractSha256() ;
	// この段階の入力条件を満たさない値を採用しない。
	if( !dayName( day) || !contract) {
		return 2 ;
	}

	run.manifestSha256 = manifestSha256 ;
	run.contractSha256 = *contract ;
	run.day			   = day ;
	// 有限集合の各要素を順に検証し、件数と順序を保持する。
	for( const LocalCollectorTarget &target : targets) {
		run.targets.push_back( {.keySha256		= target.keySha256,
							   .source			= target.source,
							   .publicModel		= target.publicModel,
							   .operatingSystem = target.operatingSystem,
							   .category		= target.category}) ;
	}

	// 通信と内容更新の前に既存台帳全体の権限を確認する。
	LocalCollectorStateStore store ;
	run.stateError = store.initialize( *root, !dryRun) ;
	// 既存ACLを修復せず元errorを表示用DTOへ残す。
	if( run.stateError != ERROR_SUCCESS) {
		return 2 ;
	}

	// 検証だけではdirectory、lock、checkpointを作成しない。
	if( dryRun) {
		return 0 ;
	}

	// v2登録済みの共通台帳を旧CLIの更新経路で変更しない。
	if( (run.stateError = rejectLocalCollectorCampaignMode( store)) != ERROR_SUCCESS) {
		return 2 ;
	}

	// 版を含む確定pointerは旧v1と共存し、改訂前のrunを流用しない。
	const auto pointerPath = pointerFilePath( manifestSha256, *contract) ;
	// storeの元errorを保持して拒否を返す。
	const auto stateFailure = [&run, &store]() {
		run.stateError =
			store.lastError() == ERROR_SUCCESS ? ERROR_INVALID_DATA : store.lastError() ;
		return 2 ;
	} ;
	// pointer欠損は初回だけ許し、存在する破損pointerを無視しない。
	std::string pointerBytes ;
	// 前世代pointerの存在を読取りAPIで判定する。
	bool		pointerFound{} ;
	// 失敗したreadを初回欠損に変換しない。
	if( store.read( pointerPath, pointerBytes, pointerFound) != ERROR_SUCCESS) {
		return stateFailure() ;
	}

	// 存在した前世代は本文とrun hashまで再検証する。
	const auto previous = pointerFound ? loadPrevious( store, manifestSha256, *contract)
									   : std::optional<LocalCollectorRun>{} ;
	// 破損した確定pointerを無視して新runを開始しない。
	if( pointerFound && !previous) {
		return stateFailure() ;
	}

	// 検証済みrun名だけを有限列挙する。旧v1と別契約のrunは選ばない。
	std::vector<std::wstring> names ;
	// ACL検証済みの子directoryからだけ候補を得る。
	if( store.listRunNames( names) != ERROR_SUCCESS) {
		return stateFailure() ;
	}

	// 完全な二つのSHAを含む同一契約だけを選別する。
	const std::wstring				 suffix = L"-" + manifestSha256 + L"-" + *contract + L".json" ;
	// 再開できる未完了runは最大一つ。
	std::optional<LocalCollectorRun> unfinished ;
	// 今日完了済みのrunも再実行しない。
	std::optional<LocalCollectorRun> sameDay ;
	// Pointerより新しい完了本文。未昇格は同時に一件だけ認める。
	std::optional<LocalCollectorRun> uncommitted ;
	// bounded storeの全file名を検証する。
	for( const std::wstring &name : names) {
		// 旧schema・他manifest・他binaryは候補外とする。
		if( name.size() != 8U + suffix.size() || !name.ends_with( suffix)) {
			continue ;
		}

		// filenameの日付もrun本文へ照合する。
		const std::wstring savedDay = name.substr( 0U, 8U) ;
		// 時計後退時に未来のrunを飛ばさない。
		if( !dayName( savedDay) || savedDay > day) {
			return stateFailure() ;
		}

		// 原byte envelope検証済みの本文だけをdecodeする。
		const auto saved = loadEnvelope( store, std::filesystem::path( L"runs") / name) ;
		// schema・値域・完了状態を検査する。
		const auto candidate = saved ? decodeRun( *saved) : std::nullopt ;
		// filename、manifest、契約、母数に矛盾があれば停止する。
		if( !candidate || candidate->manifestSha256 != manifestSha256 ||
		   candidate->contractSha256 != *contract || candidate->day != savedDay ||
		   candidate->targets.size() != targets.size()) {
			return stateFailure() ;
		}

		// targetの順序と公開条件をmanifestに結合する。
		for( std::size_t index = 0U; index < targets.size(); ++index) {
			// 保存済みtarget。
			const auto &old = candidate->targets[index] ;
			// 今回のmanifest target。
			const auto &wanted = targets[index] ;
			// 同じhashでも公開条件が異なる状態を混ぜない。
			if( old.keySha256 != wanted.keySha256 || old.source != wanted.source ||
			   old.publicModel != wanted.publicModel ||
			   old.operatingSystem != wanted.operatingSystem || old.category != wanted.category) {
				return stateFailure() ;
			}
		}

		// 未完了runだけを日跨ぎ再開の対象にする。
		if( !candidate->complete) {
			// 複数の未完了runは自動選択しない。
			if( unfinished) {
				return stateFailure() ;
			}

			unfinished = *candidate ;
		} else {
			// 完了本文保存とpointer更新の間で止まったrunを日付に依らず回収する。
			if( !previous || savedDay > previous->day) {
				// 複数未昇格を勝手に並べ替えない。
				if( uncommitted) {
					return stateFailure() ;
				}

				uncommitted = *candidate ;
			}

			// 今日の確定runは再通信しない。
			if( savedDay == day) {
				sameDay = *candidate ;
			}
		}
	}

	// pointerが新しいのに古い未完了runがある矛盾を拒否する。
	if( unfinished && (uncommitted || sameDay || (previous && previous->day >= unfinished->day))) {
		return stateFailure() ;
	}

	// 未昇格完了runは再通信せずpointer確定だけを行う。
	if( uncommitted) {
		run					 = *uncommitted ;
		run.reusedCheckpoint = true ;
		run.recoveredCommit	 = true ;
	}
	// 同一契約の未完了runを先に回収する。
	else if( unfinished) {
		run					  = *unfinished ;
		run.reusedCheckpoint  = true ;
		run.resumedEarlierDay = run.day != day ;
	}
	// 同日完了済みは保存結果をそのまま返す。
	else if( sameDay) {
		run					 = *sameDay ;
		run.reusedCheckpoint = true ;
		// 確定pointerが当日runより未来を指す場合は停止する。
		if( previous && previous->day > run.day) {
			return stateFailure() ;
		}
	}
	// 新日付のrunでは直近成功recordだけを継承する。
	else if( previous) {
		// 時計後退を理由に旧成功記録を上書きしない。
		if( previous->day >= day) {
			return stateFailure() ;
		}

		// 公開target keyが同じ場合だけ旧成功recordを継承する。
		for( LocalCollectorTargetResult &target : run.targets) {
			// manifest順序を変更してもkeyで対応づける。
			for( const LocalCollectorTargetResult &old : previous->targets) {
				// 別製品の同名recordを流用しない。
				if( old.keySha256 == target.keySha256) {
					target.records					  = old.records ;
					target.lastSuccessfulValidationAt = old.lastSuccessfulValidationAt ;
					target.lastFetchedAt			  = old.lastFetchedAt ;
					target.requestBindingSha256		  = old.requestBindingSha256 ;
					target.bodySha256				  = old.bodySha256 ;
					target.projectionSha256			  = old.projectionSha256 ;
					target.entityTag				  = old.entityTag ;
					target.retainedMetadataBytes	  = old.retainedMetadataBytes ;
					target.nextAttemptAt			  = old.nextAttemptAt ;
					target.holdReason				  = old.holdReason ;
					break ;
				}
			}
		}
	}

	// 新しい日次runの作成前に、別binary/manifestの既存待機も非変更検証します。
	if( dailyMode && !run.reusedCheckpoint) {
		const auto now = hooks.utcSeconds ? hooks.utcSeconds() : nowSeconds() ;	// 信頼するUTC秒。
		CollectorLegacySnapshot snapshot ;										// 既存root全契約の待機。
		std::wstring			reason ;										// 固定診断。通常logへ元本文を渡しません。
		// 破損・旧未回収・時計後退は、新しいrunや通信へ進めません。
		if( now == 0U || now > 253402214399ULL ||
		   (run.stateError = inspectLocalCollectorLegacy( store, now * 1000U, snapshot, reason)) !=
			   0U) {
			return 2 ;
		}

		LocalCollectorRequest request ;	// 全契約を跨いで共用する恒久request key。
		// 保存targetの任意keyを待機除外に利用しません。
		if( !makeLocalCollectorRequest( targets.front(), request)) {
			return stateFailure() ;
		}

		bool review{} ;	// 元の要確認を自動解除しません。
		// 当該requestまたはsource全体の最大期限を引き継ぎます。
		for( const auto &wait : snapshot.waits) {
			// 無関係な製品の期限だけは対象外です。
			if( wait.group == request.group &&
			   (wait.requestKey.empty() || wait.requestKey == request.requestKey)) {
				run.dailyNotBefore = std::max( run.dailyNotBefore, (wait.notBefore + 999U) / 1000U) ;
				review |= wait.review ;
			}
		}

		// due前のHOLDは当日のDEFERRED runを作らず、同日due後の再開を可能にします。
		if( review || run.dailyNotBefore > now) {
			run.dailyHeld					  = true ;
			run.targets.front().nextAttemptAt = run.dailyNotBefore ;
			return 3 ;
		}
	}

	// 再開時も元の日付でcheckpointを更新する。
	const auto runPath = runFilePath( run.day, manifestSha256, *contract) ;
	// これが成功するまで最初のnetwork requestを開始しない。
	if( !run.reusedCheckpoint && !saveEnvelope( store, runPath, encodeRun( run))) {
		return stateFailure() ;
	}

	// 試験専用の永続化直後停止。本番ではcallbackを持たない。
	const auto stopAt = [&hooks, &run]( LocalCollectorCheckpoint point, std::size_t index) {
		// 中断理由を明示し、既存checkpointを破棄しない。
		if( hooks.stopAfterCheckpoint && hooks.stopAfterCheckpoint( point, index)) {
			run.stateError = ERROR_OPERATION_ABORTED ;
			return true ;
		}

		return false ;
	} ;
	// 初期run保存後からの再開を試験できるようにする。
	if( !run.reusedCheckpoint && stopAt( LocalCollectorCheckpoint::RUN_STARTED, targets.size())) {
		return 2 ;
	}

	// 経過予算を測る開始時刻。
	const auto steadyNow = [&hooks]() {
		return hooks.steadyNow ? hooks.steadyNow() : std::chrono::steady_clock::now() ;
	} ;
	// 成功時刻と鮮度は注入したUTC時計へ揃える。
	const auto utcNow = [&hooks]() { return hooks.utcSeconds ? hooks.utcSeconds() : nowSeconds() ; } ;
	// 単調時間は一回の呼出しの有限予算へ使う。
	const auto started = steadyNow() ;
	// 部分失敗の集計状態。
	bool	   failed{} ;
	// 有限集合の各要素を順に検証し、件数と順序を保持する。
	for( std::size_t index = 0U; index < targets.size(); ++index) {
		// 今回のtarget別保存結果。
		LocalCollectorTargetResult &result = run.targets[index] ;
		// 本体試行の途中/不確定を再起動から再送せず、先払い待機を保持して閉じます。
		if( payload != nullptr && run.reusedCheckpoint &&
		   result.state == LocalCollectorTargetState::IN_PROGRESS) {
			result.state = LocalCollectorTargetState::FAILED ;
			result.error = ERROR_OPERATION_ABORTED ;
			result.entityTag.clear() ;
			failed = true ;
			// 中断前checkpointの最大待機を短縮しません。
			if( !saveEnvelope( store, runPath, encodeRun( run))) {
				return stateFailure() ;
			}

			continue ;
		}

		// 保存状態の形式と遷移を確認し、不明な値を拒否する。
		if( result.state != LocalCollectorTargetState::PENDING &&
		   result.state != LocalCollectorTargetState::IN_PROGRESS) {
			failed |= result.state == LocalCollectorTargetState::FAILED ||
					  result.state == LocalCollectorTargetState::HELD ;
			continue ;
		}

		// 今回のUTC秒。
		const std::uint64_t now = utcNow() ;
		// この段階の入力条件を満たさない値を採用しない。
		if( now == 0U || now > 253402214399ULL) {
			return stateFailure() ;
		}

		SourceCooldown cooldown ;	// 他manifestで確定した待機も毎target直前に読む。
		// 待機台帳の破損や時計後退を無視して通信しない。
		if( !loadCooldown( store, result.source, cooldown) || cooldown.observedAt > now ||
		   result.lastSuccessfulValidationAt > now) {
			return stateFailure() ;
		}

		result.nextAttemptAt = std::max( result.nextAttemptAt, cooldown.nextAttemptAt) ;

		// 不正な待機指定は無限再送せず要確認状態を維持する。
		if( cooldown.needsReview) {
			result.state	  = LocalCollectorTargetState::HELD ;
			result.holdReason = L"RETRY_AFTER" ;
			failed			  = true ;
		}
		// 時間予算やsource／target期限を超えて通信しない。
		else if( steadyNow() - started > RUN_BUDGET || result.nextAttemptAt > now) {
			result.state = LocalCollectorTargetState::DEFERRED ;
		}
		// この段階の入力条件を満たさない値を採用しない。
		else if( result.lastSuccessfulValidationAt != 0U &&
				now >= result.lastSuccessfulValidationAt &&
				now - result.lastSuccessfulValidationAt < SECONDS_PER_DAY) {
			result.state = LocalCollectorTargetState::DEFERRED ;
		} else {
			result.state			   = LocalCollectorTargetState::IN_PROGRESS ;
			result.lastAttemptAt	   = now ;
			result.holdReason		   = L"NONE" ;
			result.observedRecordCount = 0U ;
			// 未完了/不確定ではrunの最大時間と24hを先払いして再送を防ぎます。
			if( payload != nullptr) {
				result.nextAttemptAt = now + SECONDS_PER_DAY + 3600U ;
			}

			// 操作対象のfileとworkspaceを限定する。
			if( !saveEnvelope( store, runPath, encodeRun( run))) {
				return stateFailure() ;
			}

			// HTTP開始直前に中断したtargetは再開時も未完了として扱う。
			if( stopAt( LocalCollectorCheckpoint::TARGET_STARTED, index)) {
				return 2 ;
			}

			// 新しい公式配布record射影。
			std::vector<LocalCollectorRecord> fresh ;
			CollectorHttpObservation		  http ;	// 200と304を区別する応答。
			std::wstring					  binding ;	// 再構築した固定request指紋。
			std::string raw ;							// 同HTTPの完全新200だけ。成功と失敗診断を分離します。
			result.attemptedThisInvocation = true ;
			// 元のAPI診断。
			const HttpCancellationCallback cancelled = [&]() {
				const auto current = utcNow() ;	// 同意期限と元時計を再確認します。
				return steadyNow() - started > RUN_BUDGET || current < now ||
					   (payload != nullptr && current >= payload->consentNotAfter) ;
			} ; // 元runのdeadlineを取得開始で再起点化しません。
			const std::uint32_t error =	// 同じPAGEと本体の最初の拒否値です。
				resolveTarget( targets[index], fresh, result.failureStageThisInvocation,
							  hooks.httpTransport, result, *contract, http, binding,
							  (retainMetadata || dailyMode) ? &raw : nullptr, payload, utcNow,
							  cancelled, hooks.networkCostReader) ;
			result.payloadAcquiredThisInvocation = payload != nullptr && error == 0U ;
			result.lastHttpStatus				 = http.status ;
			result.error						 = error ;
			// 明示本体取得の同呼出しだけに、成功checkpointと別の完全200診断を返します。
			if( payload != nullptr && error != 0U && http.status == 200U && !raw.empty()) {
				result.failedMetadataBytesThisInvocation = std::move( raw) ;
				result.failedBodySha256ThisInvocation	 = http.bodySha256 ;
			}

			const auto observedAt = utcNow() ;	// 応答完了後を待機期限の起点にする。
			// 時計後退・overflowで待機期限を短縮しない。
			if( observedAt < now || observedAt > 253402214399ULL) {
				return stateFailure() ;
			}

			result.observedRecordCount = static_cast<std::uint32_t>( fresh.size()) ;
			result.nextAttemptAt	   = observedAt + SECONDS_PER_DAY ;
			// Source単位の失敗はtarget保存より先に別manifestへも見える形で確定する。
			if( http.status == 429U || http.status == 503U) {
				cooldown = {observedAt,
							std::max( result.nextAttemptAt,
									 std::max( observedAt + http.retryAfterDelaySeconds,
											  http.retryAfterUtcSeconds)),
							http.retryAfterNeedsReview, http.status} ;
				// 型の最大UTCを超す指定を短縮せず要確認へ送る。
				if( cooldown.nextAttemptAt > 253402300799ULL) {
					cooldown.nextAttemptAt = 253402300799ULL ;
					cooldown.needsReview   = true ;
				}

				// 保存不能なら後続targetへ進めない。
				if( !saveCooldown( store, result.source, cooldown)) {
					return stateFailure() ;
				}

				result.nextAttemptAt = cooldown.nextAttemptAt ;
			}

			// 元の失敗を成功として扱わず、この段階を停止する。
			if( cooldown.needsReview || error == ERROR_NO_MORE_ITEMS ||
			   (error == 0U && fresh.size() < result.records.size())) {
				result.state = LocalCollectorTargetState::HELD ;
				result.holdReason =
					cooldown.needsReview
						? L"RETRY_AFTER"
						: (error == ERROR_NO_MORE_ITEMS ? L"EMPTY_RESPONSE" : L"RECORD_DECREASE") ;
				result.entityTag.clear() ;
				failed = true ;
			}
			// 通常の通信・schema失敗でも旧成功を維持する。
			else if( error != 0U) {
				result.state = LocalCollectorTargetState::FAILED ;
				result.entityTag.clear() ;
				failed = true ;
			} else {
				result.state   = fresh == result.records ? LocalCollectorTargetState::UNCHANGED
														 : LocalCollectorTargetState::UPDATED ;
				result.records = std::move( fresh) ;
				result.lastSuccessfulValidationAt = observedAt ;
				// 不明時刻で成功recordを確定しない。
				if( result.lastSuccessfulValidationAt < now) {
					return stateFailure() ;
				}

				// 実200のみが本文hashと受信時刻を更新する。
				if( http.status == 200U) {
					// 日次の保護本文とreceiptの有限容量を超す新200を保存しません。
					if( dailyMode && (raw.empty() || raw.size() > 512U * 1024U)) {
						return stateFailure() ;
					}

					result.lastFetchedAt		 = result.lastSuccessfulValidationAt ;
					result.bodySha256			 = http.bodySha256 ;
					result.retainedMetadataBytes = dailyMode ? raw : std::string{} ;
					result.rawMetadataBytes		 = std::move( raw) ;
				}

				result.requestBindingSha256 = binding ;
				result.entityTag			= http.entityTag ;
				result.projectionSha256		= projectionHash( result) ;
				// 不完全な射影hashを成功checkpointへ保存しない。
				if( !hashName( result.projectionSha256)) {
					return stateFailure() ;
				}
			}
		}

		// 操作対象のfileとworkspaceを限定する。
		if( !saveEnvelope( store, runPath, encodeRun( run))) {
			return stateFailure() ;
		}

		// 保存したterminal結果を再開後に再通信させない。
		if( stopAt( LocalCollectorCheckpoint::TARGET_SAVED, index)) {
			return 2 ;
		}
	}

	// 全target処理後のrun本文。
	run.complete = true ;
	// 全件terminalの本文をpointerより先に永続化する。
	const std::string complete = encodeRun( run) ;
	// 確定runの実byte SHA-256。
	std::wstring	  runHash ;
	// 実byteの指紋と保存済みの結合を確認する。
	if( computeBytesSha256( complete, runHash) != 0 || !saveEnvelope( store, runPath, complete)) {
		return stateFailure() ;
	}

	// 初回・旧pointerありの両方でcommit窓の中断を再現する。
	if( stopAt( LocalCollectorCheckpoint::RUN_COMPLETED, targets.size())) {
		return 2 ;
	}

	// 最後に確定した世代のpointer。
	JsonObject pointer ;
	putString( pointer, L"schema", L"dc-collector-current-v4") ;
	putString( pointer, L"day", run.day) ;
	putString( pointer, L"manifestSha256", manifestSha256) ;
	putString( pointer, L"contractSha256", *contract) ;
	putString( pointer, L"runSha256", runHash) ;
	// 操作対象のfileとworkspaceを限定する。
	if( !saveEnvelope( store, pointerPath, winrt::to_string( pointer.Stringify()))) {
		return stateFailure() ;
	}

	// 今回実観測が成功した時だけ運用世代を保護store内で単調に予約します。
	if( dailyMode && !failed && run.targets.front().attemptedThisInvocation) {
		std::uint64_t previousGeneration{} ;	// 受入用上限と分離する永続head。
		// 破損head・最大値では新しい署名入力を発行しません。
		if( !loadDailyGeneration( store, previousGeneration, run.dailyPreviousReceiptSha256) ||
		   previousGeneration >= 9007199254740991ULL) {
			return stateFailure() ;
		}

		run.dailyGeneration = previousGeneration + 1U ;
		std::string	 receipt ;		// 発行予定の厳密byteを先に検証します。
		std::wstring receiptHash ;	// 保存headと新規出力を同じbyteへ結合します。
		// 原本文欠損や改変から新世代を作りません。
		if( !makeLocalCollectorDailyReceipt( run, receipt) ||
		   computeBytesSha256( receipt, receiptHash) != 0) {
			return stateFailure() ;
		}

		JsonObject head ;	// 既存lock下の一file原子的head。
		putString( head, L"schema", L"dc-collector-daily-generation-v1") ;
		putNumber( head, L"generation", run.dailyGeneration) ;
		putString( head, L"receiptSha256", receiptHash) ;
		// 出力失敗時も世代を巻き戻さず、次回は新しい実観測を要求します。
		if( !saveEnvelope( store, L"current/daily-generation-v1.json",
						 winrt::to_string( head.Stringify()))) {
			return stateFailure() ;
		}
	}

	return failed ? 1 : 0 ;
}

/** @see local_driver_collector.h */
bool makeLocalCollectorDailyReceipt( const LocalCollectorRun &run, std::string &bytes)
{
	bytes.clear() ;
	// 日次の固定対象と元収集契約だけを受け付けます。
	if( run.targets.size() != 1U || !hashName( run.manifestSha256) || !hashName( run.contractSha256) ||
	   run.targets.front().source != L"INTEL_ETHERNET_WINDOWS11") {
		return false ;
	}

	const auto &target = run.targets.front() ;	// 同runの所有targetだけを借用します。
	const bool	observed =
		target.attemptedThisInvocation && run.complete && target.error == 0U &&
		(target.state == LocalCollectorTargetState::UPDATED ||
		 target.state == LocalCollectorTargetState::UNCHANGED) &&
		(target.lastHttpStatus == 200U || target.lastHttpStatus == 304U) ;	// 今回の実HTTP成功。
	std::wstring actual ;													// 原200本文の再計算hash。
	// 実観測receiptの本文欠損とhash/射影不一致を拒否します。
	if( observed &&
	   (target.retainedMetadataBytes.empty() || target.lastFetchedAt == 0U ||
		target.lastFetchedAt > target.lastSuccessfulValidationAt ||
		computeBytesSha256( target.retainedMetadataBytes, actual) != 0 ||
		actual != target.bodySha256 || projectionHash( target) != target.projectionSha256)) {
		return false ;
	}

	const std::wstring outcome =
		run.dailyHeld
			? L"HOLD"
			: (!target.attemptedThisInvocation
				   ? L"NO_NETWORK"
				   : (observed ? (target.lastHttpStatus == 200U ? L"NEW_200" : L"REVALIDATED_304")
							   : L"FAILED")) ;	// 観測を捏造しません。
	JsonObject receipt ;						// 元本文は明示fileだけに保存しstdoutへ出しません。
	putString( receipt, L"schema", L"dc-collector-daily-receipt-v1") ;
	putString( receipt, L"outcome", outcome) ;
	putNumber( receipt, L"generation", run.dailyGeneration) ;
	putString( receipt, L"previousReceiptSha256", run.dailyPreviousReceiptSha256) ;
	putString( receipt, L"manifestSha256", run.manifestSha256) ;
	putString( receipt, L"contractSha256", run.contractSha256) ;
	putString( receipt, L"day", run.day) ;
	putString( receipt, L"source", target.source) ;
	putNumber( receipt, L"httpStatus", target.attemptedThisInvocation ? target.lastHttpStatus : 0U) ;
	putNumber( receipt, L"lastFetchedAt", target.lastFetchedAt) ;
	putNumber( receipt, L"lastSuccessfulValidationAt", target.lastSuccessfulValidationAt) ;
	putNumber( receipt, L"lastAttemptAt",
			  target.attemptedThisInvocation ? target.lastAttemptAt : 0U) ;
	putNumber( receipt, L"notBefore", std::max( run.dailyNotBefore, target.nextAttemptAt)) ;
	putString( receipt, L"requestBindingSha256", target.requestBindingSha256) ;
	putString( receipt, L"bodySha256", target.bodySha256) ;
	putString( receipt, L"projectionSha256", target.projectionSha256) ;
	putString( receipt, L"bodyBytesBase64", bodyBase64( target.retainedMetadataBytes)) ;
	putString( receipt, L"projectionBytesBase64",
			  observed ? bodyBase64( projectionBytes( target)) : L"") ;
	receipt.Insert( L"records", encodeRecords( target.records)) ;
	putNumber( receipt, L"error", target.error) ;
	putNumber( receipt, L"stateError", run.stateError) ;
	bytes = winrt::to_string( receipt.Stringify()) ;
	// 保存先と同じ有限上限を守ります。
	if( bytes.size() > MAXIMUM_STATE_BYTES) {
		bytes.clear() ;
		return false ;
	}

	return true ;
}

/** @see local_driver_collector.h */
bool makeLocalCollectorFailedPageDiagnostic( const LocalCollectorRun &run,
											const std::string_view	 receiptBytes,
											const int collectorCode, std::string &bytes)
{
	bytes.clear() ;
	// 成功、state不明、再開、複数対象を同HTTPの失敗資料へ読み替えません。
	if( collectorCode != 1 || !run.complete || run.stateError != 0U || run.targets.size() != 1U ||
	   receiptBytes.empty() || receiptBytes.size() > MAXIMUM_STATE_BYTES) {
		return false ;
	}

	const auto &target	   = run.targets.front() ;	// 同呼出しの失敗だけを借用します。
	const auto *definition = officialSourceDefinition(
		OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;	// 実requestの有限上限です。
	const auto stage =
		// 元の拒否区間です。
		static_cast<std::uint32_t>( target.failureStageThisInvocation) ;
	// 元APIが完全200本文を返した後の失敗だけを認め、未知stageや旧成功は拒否します。
	if( definition == nullptr || target.source != L"INTEL_ETHERNET_WINDOWS11" ||
	   !target.attemptedThisInvocation || target.lastHttpStatus != 200U || target.error == 0U ||
	   (target.state != LocalCollectorTargetState::FAILED &&
		target.state != LocalCollectorTargetState::HELD) ||
	   stage < static_cast<std::uint32_t>( LocalCollectorFailureStage::EVIDENCE) ||
	   stage > static_cast<std::uint32_t>( LocalCollectorFailureStage::PAYLOAD) ||
	   target.failedMetadataBytesThisInvocation.empty() ||
	   target.failedMetadataBytesThisInvocation.size() > definition->maximumMetadataBytes ||
	   !hashName( target.failedBodySha256ThisInvocation)) {
		return false ;
	}

	std::string	 expectedReceipt ;	// 同runの原receipt以外へ失敗本文を結びません。
	std::wstring receiptHash ;		// 元receipt全byteの指紋です。
	std::wstring bodyHash ;			// 保存直前の原byte再hashです。
	// 旧receipt・改変本文・不完全なhashを診断保存成功へ変換しません。
	if( !makeLocalCollectorDailyReceipt( run, expectedReceipt) || expectedReceipt != receiptBytes ||
	   computeBytesSha256( receiptBytes, receiptHash) != 0 ||
	   computeCollectorMetadataSha256( target.failedMetadataBytesThisInvocation, bodyHash) != 0 ||
	   bodyHash != target.failedBodySha256ThisInvocation) {
		return false ;
	}

	const auto encoded =
		bodyBase64( target.failedMetadataBytesThisInvocation,
				   definition->maximumMetadataBytes) ;	// 切り詰めず全原byteを可逆保存します。
	// SDK変換失敗を空の本文資料へ置換しません。
	if( encoded.empty()) {
		return false ;
	}

	JsonObject diagnostic ;	// 成功metadata・URL・grantを含まない別schemaです。
	putString( diagnostic, L"schema", L"dc-collector-failed-page-diagnostic-v1") ;
	putString( diagnostic, L"receiptSha256", receiptHash) ;
	putString( diagnostic, L"manifestSha256", run.manifestSha256) ;
	putString( diagnostic, L"contractSha256", run.contractSha256) ;
	putString( diagnostic, L"source", target.source) ;
	putNumber( diagnostic, L"collectorCode", static_cast<std::uint32_t>( collectorCode)) ;
	putNumber( diagnostic, L"error", target.error) ;
	putNumber( diagnostic, L"failureStage", stage) ;
	putNumber( diagnostic, L"httpStatus", target.lastHttpStatus) ;
	putNumber( diagnostic, L"lastAttemptAt", target.lastAttemptAt) ;
	putNumber( diagnostic, L"notBefore", std::max( run.dailyNotBefore, target.nextAttemptAt)) ;
	putString( diagnostic, L"bodySha256", bodyHash) ;
	putNumber( diagnostic, L"bodySize", target.failedMetadataBytesThisInvocation.size()) ;
	putString( diagnostic, L"bodyBytesBase64", encoded) ;
	bytes = winrt::to_string( diagnostic.Stringify()) ;
	// 最大2MiBのbase64と固定metadataを含む診断専用の3MiB上限です。
	if( bytes.size() > 3U * 1024U * 1024U) {
		bytes.clear() ;
		return false ;
	}

	return true ;
}

/** @see local_driver_collector.h */
std::uint32_t verifyLocalCollectorDailyReservation( const std::filesystem::path &stateRoot,
												   const std::wstring		   &manifestSha256,
												   const std::string_view		receiptBytes,
												   const LocalCollectorReservationMode mode,
												   LocalCollectorReservationFacts	  &facts,
												   const LocalCollectorTestHooks &hooks) noexcept
{
	facts		 = {} ;
	facts.reason = L"DAILY_RESERVATION_RECEIPT" ;
	try {
		const auto root	 = checkedStateRoot( stateRoot) ;	// 固定workspace内の既存rootだけ。
		const auto value = receiptBytes.size() <= MAXIMUM_STATE_BYTES
							   ? parseObject( receiptBytes)
							   : std::nullopt ;	// 最大原byteを先に検査する。
		// 定義外用途、欠損・重複key・未知field・非canonical原byteを拒否する。
		if( !root || !stateRoot.is_absolute() || stateRoot != stateRoot.lexically_normal() ||
		   (mode != LocalCollectorReservationMode::FRESH_INPUT &&
			mode != LocalCollectorReservationMode::LEGACY_FENCE) ||
		   receiptBytes.empty() || receiptBytes.size() > MAXIMUM_STATE_BYTES || !value ||
		   value->Size() != 21U || winrt::to_string( value->Stringify()) != receiptBytes) {
			return ERROR_INVALID_DATA ;
		}

		const auto generation = numberField( *value, L"generation") ;					// 実予約世代。
		const auto contract	  = stringField( *value, L"contractSha256", 64U) ;			// 原契約。
		const auto day		  = stringField( *value, L"day", 8U) ;						// 保存runの日付。
		const auto previous	  = stringField( *value, L"previousReceiptSha256", 64U) ;	// 原鎖。
		const auto fetched	  = numberField( *value, L"lastFetchedAt") ;				// 原200の時刻。
		const auto validated  = numberField( *value, L"lastSuccessfulValidationAt") ;	// 今回成功。
		const auto attempted  = numberField( *value, L"lastAttemptAt") ;				// 今回試行。
		const auto notBefore  = numberField( *value, L"notBefore") ;					// 次回due。
		const auto status	  = numberField( *value, L"httpStatus") ;					// 実HTTP区分。
		const auto now		  = hooks.utcSeconds ? hooks.utcSeconds() : nowSeconds() ;	// 信頼時計。
		// callerのpinから新予約を作らず、原成功の固定fieldを要求する。
		if( !generation || *generation < 4U || *generation > 9007199254740991ULL || !contract ||
		   !hashName( *contract) || !day || !dayName( *day) || !previous ||
		   ((*generation == 4U) ? !previous->empty() : !hashName( *previous)) ||
		   stringField( *value, L"schema", 40U) != L"dc-collector-daily-receipt-v1" ||
		   stringField( *value, L"source", 40U) != L"INTEL_ETHERNET_WINDOWS11" ||
		   !hashName( manifestSha256) ||
		   stringField( *value, L"manifestSha256", 64U) != manifestSha256 ||
		   numberField( *value, L"error") != 0U || numberField( *value, L"stateError") != 0U ||
		   !status || (*status != 200U && *status != 304U) ||
		   stringField( *value, L"outcome", 20U) !=
			   (*status == 200U ? L"NEW_200" : L"REVALIDATED_304")) {
			facts.reason = L"DAILY_RESERVATION_BINDING" ;
			return ERROR_INVALID_DATA ;
		}

		// legacyも未来観測・壊れた順序を許さず、現在期限だけを要求しない。
		if( now == 0U || now > 4102444799ULL || !fetched || !validated || !attempted || !notBefore ||
		   *fetched == 0U || *attempted == 0U || *attempted > *validated || *validated > now ||
		   *validated > 4102444799ULL - SECONDS_PER_DAY || *fetched > *validated ||
		   *notBefore != *validated + SECONDS_PER_DAY ||
		   (*status == 200U ? *fetched != *validated : *fetched >= *attempted) ||
		   (mode == LocalCollectorReservationMode::FRESH_INPUT && now >= *notBefore)) {
			facts.reason = L"DAILY_RESERVATION_TIME" ;
			return ERROR_INVALID_DATA ;
		}

		// freshだけは実行binaryの現在契約を要求する。
		if( mode == LocalCollectorReservationMode::FRESH_INPUT &&
		   collectorContractSha256() != contract) {
			facts.reason = L"DAILY_RESERVATION_CONTRACT" ;
			return ERROR_INVALID_DATA ;
		}

		LocalCollectorStateStore store ;	// 作成しない既存writer lockの所有者。
		facts.reason = L"DAILY_RESERVATION_STORE" ;
		DWORD code	 = store.initializeExistingWriter( *root) ;	// 欠損から初期化しない。
		// 旧CLIが理解しないcampaign状態を無視しない。
		if( code != ERROR_SUCCESS ||
		   (code = rejectLocalCollectorCampaignMode( store)) != ERROR_SUCCESS) {
			return code ;
		}

		std::vector<std::wstring> currentNames ;	// 上位campaignへの未知委譲を拒否する。
		std::vector<std::wstring> runNames ;		// 同じ有限storeの全run名。
		// 既存legacy検査が上位へ委譲する名前をこの専用入口へ混用しない。
		if( (code = store.listCurrentNames( currentNames)) != ERROR_SUCCESS ||
		   (code = store.listRunNames( runNames)) != ERROR_SUCCESS) {
			return code ;
		}

		// 全有限名を確認し、理解しないcampaign部分を無視しない。
		for( const auto &names : {currentNames, runNames}) {
			// 旧予約だけを完全照合できる名前へ限定する。
			for( const auto &name : names) {
				// 上位契約を部分的な旧成功へ縮小しない。
				if( name.starts_with( L"campaign-")) {
					return ERROR_INVALID_DATA ;
				}
			}
		}

		CollectorLegacySnapshot snapshot ;	// 全有限store検証の非機密結果。
		std::wstring			reason ;	// 既存validatorの内部固定理由。
		// 未知file・破損run・未来時計を既存の有限validatorで拒否する。
		if( (code = inspectLocalCollectorLegacy( store, now * 1000U, snapshot, reason)) !=
		   ERROR_SUCCESS) {
			return code ;
		}

		std::uint64_t headGeneration{} ;	// 既存headの世代。
		std::wstring  headHash ;			// 既存headの原receipt hash。
		std::wstring  receiptHash ;			// 全byteから再計算するhash。
		facts.reason = L"DAILY_RESERVATION_HEAD" ;
		// 欠損headを世代3からの新予約へ変換しない。
		if( !loadDailyGeneration( store, headGeneration, headHash) || headGeneration != *generation ||
		   computeBytesSha256( receiptBytes, receiptHash) != 0 || receiptHash != headHash) {
			return ERROR_INVALID_DATA ;
		}

		const auto rawRun =
			// 原run。
			loadEnvelope( store, runFilePath( *day, manifestSha256, *contract)) ;
		auto run	 = rawRun ? decodeRun( *rawRun) : std::nullopt ;	// 完全な型付き保存状態。
		facts.reason = L"DAILY_RESERVATION_RECEIPT" ;
		// 保存runが持たない自己申告の本文・時刻・recordを採用しない。
		if( !run || !run->complete || run->targets.size() != 1U || run->day != *day ||
		   run->manifestSha256 != manifestSha256 || run->contractSha256 != *contract) {
			return ERROR_INVALID_DATA ;
		}

		run->dailyGeneration						 = *generation ;
		run->dailyPreviousReceiptSha256				 = *previous ;
		run->targets.front().attemptedThisInvocation = true ;
		std::string reconstructed ;	// 既存writerと同じserializerによる原byte。
		// 原status/body/projection/records/fetched/validatedを全byteで結合する。
		if( !makeLocalCollectorDailyReceipt( *run, reconstructed) || reconstructed != receiptBytes) {
			return ERROR_INVALID_DATA ;
		}

		facts.generation	= *generation ;
		facts.receiptSha256 = std::move( receiptHash) ;
		facts.reason.clear() ;
		return ERROR_SUCCESS ;
	} catch( ...) {
		facts		 = {} ;
		facts.reason = L"DAILY_RESERVATION_RECEIPT" ;
		return ERROR_INVALID_DATA ;
	}
}
namespace {
/** @brief 公開targetの旧・新identityへ共用する非通信公式経路を組み立てます。
 * @param[in] target 旧公開target。
 * @param[out] url メモリ内だけで使用する公式URL。
 * @param[out] provider 組み込みprovider。
 * @param[out] resource 組み込みresource。
 * @return 公開fieldと元keyが成立した場合true。
 */
[[nodiscard]] bool legacyRoute( const LocalCollectorTarget &target, std::wstring &url,
							   std::wstring &provider, std::wstring &resource)
{
	auto checked = target ;	// 元公開fieldからkeyを再計算する。
	// 任意保存keyを公式requestへ昇格しない。
	if( !makeTargetKey( checked) || checked.keySha256 != target.keySha256) {
		return false ;
	}

	// ASUSの公開model／OSを通常のresolverで検証する。
	if( target.source == L"ASUS_CATALOG") {
		AsusSupportPageRequest request ;	// 通信しない公開起点構築。
		// 旧分類も有限の公開ASCIIに限定する。
		if( !asciiName( target.category, 32U) ||
		   !makeAsusPublicModelSupportPageRequest( target.publicModel, target.operatingSystem,
												  request)) {
			return false ;
		}

		url		 = request.pageUrl ;
		provider = ASUS_PROVIDER_ID ;
		resource = OFFICIAL_PRIMARY_METADATA_RESOURCE_ID ;
		return true ;
	}

	// Intelは旧v4が使用した一つの公式入口だけを扱う。
	if( target.source != L"INTEL_ETHERNET_WINDOWS11" || !target.publicModel.empty() ||
	   !target.category.empty() || target.operatingSystem != L"Windows 11 64-bit") {
		return false ;
	}

	const auto *definition = officialSourceDefinition(
		OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;	// 組み込み公式起点。
	// 未登録定義をURL直書きで代替しない。
	if( definition == nullptr) {
		return false ;
	}

	url		 = definition->landingUrl ;
	provider = definition->providerId ;
	resource = OFFICIAL_LANDING_RESOURCE_ID ;
	return true ;
}

/** @brief 検証済みUTC秒からJST日付を非通信で作ります。
 * @param[in] utc 正数のUTC秒。
 * @return 固定8桁日付。
 */
[[nodiscard]] std::wstring legacyDay( const std::uint64_t utc)
{
	const auto date = std::chrono::year_month_day(
		std::chrono::floor<std::chrono::days>( std::chrono::sys_seconds( std::chrono::seconds( utc)) +
											  // 元試行日のJST。
											  std::chrono::hours( 9))) ;
	const auto month = static_cast<unsigned>( date.month()) ;	// 固定二桁の月。
	const auto day	 = static_cast<unsigned>( date.day()) ;		// 固定二桁の日。
	return std::to_wstring( static_cast<int>( date.year())) + (month < 10U ? L"0" : L"") +
		   std::to_wstring( month) + (day < 10U ? L"0" : L"") + std::to_wstring( day) ;
}

/** @brief 旧保存日を実在する暦日として照合します。
 * @param[in] value 旧YYYYMMDD。
 * @return 有限の実在日付ならtrue。
 */
bool validLegacyDay( const std::wstring &value)
{
	// 数字以外を整数変換へ渡さない。
	if( !dayName( value)) {
		return false ;
	}

	const int  year	 = std::stoi( value.substr( 0U, 4U)) ;							// 元公開年。
	const auto month = static_cast<unsigned>( std::stoi( value.substr( 4U, 2U))) ;	// 元公開月。
	const auto date	 = static_cast<unsigned>( std::stoi( value.substr( 6U, 2U))) ;	// 元公開日。
	return year >= 1970 && year <= 2099 &&
		   std::chrono::year_month_day( std::chrono::year( year), std::chrono::month( month),
									   std::chrono::day( date))
			   .ok() ;
}
} // namespace

/** @see local_collector_legacy.h */
bool makeLocalCollectorRequest( const LocalCollectorTarget &target, LocalCollectorRequest &request)
{
	request = {} ;
	try {
		LocalCollectorRequest result ;	// 出力は全検証後にだけ更新する。
		// 登録source以外を恒久requestへ取り込まない。
		if( !legacyRoute( target, result.url, result.provider, result.resource)) {
			return false ;
		}

		result.source = target.source ;
		result.accept =
			L"application/json, application/xml, text/xml, application/octet-stream, */*" ;
		JsonObject identity ;	// Artifact・category・製品参照を含めないrequest同一性。
		putString( identity, L"schema", L"collector-request-v1") ;
		putString( identity, L"method", L"GET") ;
		putString( identity, L"source", target.source) ;
		putString( identity, L"provider", result.provider) ;
		putString( identity, L"resource", result.resource) ;
		putString( identity, L"url", result.url) ;
		putString( identity, L"locale", L"en-US") ;
		putString( identity, L"os", target.operatingSystem) ;
		putString( identity, L"accept", result.accept) ;
		// Hash計算失敗で空keyを返さない。
		if( computeBytesSha256( winrt::to_string( identity.Stringify()), result.requestKey) != 0) {
			return false ;
		}

		result.group = target.source == L"ASUS_CATALOG" ? L"asus" : L"intel" ;
		request		 = std::move( result) ;
		return true ;
	} catch( ...) {
		return false ;
	}
}

/** @see local_collector_legacy.h */
bool makeLocalCollectorTarget( const std::wstring_view source, const std::wstring_view publicModel,
							  const std::wstring_view operatingSystem,
							  const std::wstring_view category, LocalCollectorTarget &target)
{
	target = {} ;
	try {
		LocalCollectorTarget result ;	// 旧keyを単一builderで計算する。
		result.source		   = source ;
		result.publicModel	   = publicModel ;
		result.operatingSystem = operatingSystem ;
		result.category		   = category ;
		LocalCollectorRequest request ;	// 公式経路で公開fieldを再検査する。
		// 公開fieldと旧keyを同じ非AI経路で検証できないtargetは登録しない。
		if( !makeTargetKey( result) || !makeLocalCollectorRequest( result, request)) {
			return false ;
		}

		target = std::move( result) ;
		return true ;
	} catch( ...) {
		return false ;
	}
}

/** @see local_collector_legacy.h */
bool makeLocalCollectorRequestKey( const LocalCollectorTarget &target, std::wstring &group,
								  std::wstring &requestKey)
{
	group.clear() ;
	requestKey.clear() ;
	LocalCollectorRequest request ;	// 共通builderだけがcanonicalを定義する。
	// 失敗時に前回のkeyを残さない。
	if( !makeLocalCollectorRequest( target, request)) {
		return false ;
	}

	group	   = std::move( request.group) ;
	requestKey = std::move( request.requestKey) ;
	return true ;
}

/** @see local_collector_legacy.h */
DWORD inspectLocalCollectorLegacy( LocalCollectorStateStore &store, const std::uint64_t utcMillis,
								  CollectorLegacySnapshot &snapshot, std::wstring &reason)
{
	snapshot = {} ;
	reason	 = L"LEGACY_CONTRACT_UNKNOWN" ;
	try {
		// 使用量と観測時計を有限な通常範囲で検査する。
		if( utcMillis < 1000U || utcMillis > 4102444799999ULL || !store.isWritable()) {
			return ERROR_INVALID_PARAMETER ;
		}

		std::vector<std::wstring> current ;										// 全契約のpointerとsource待機。
		std::vector<std::wstring> runs ;										// 全契約の完了・未完了履歴。
		DWORD					  error = store.listCurrentNames( current) ;	// 元I/O code。
		// 部分列挙から旧履歴の欠損を無視しない。
		if( error != 0U || (error = store.listRunNames( runs)) != 0U) {
			return error ;
		}

		CollectorLegacySnapshot result ;	// 全検証後だけcallerへ渡す。
		bool retainedHistory{} ;			// 既発行の保護本文がある時は日次head欠損を初回扱いしません。
		std::map<std::wstring, CollectorLegacyWait>
											 waits ;		// 公開request／groupごとに最大値を保持する。
		std::map<std::wstring, std::wstring> tips ;			// Manifest／contract組の確定JST日。
		std::set<std::wstring>				 matchedTips ;	// 参照先runが実在したpointer集合。
		std::map<std::wstring, std::string>	 hashes ;		// 相対名の固定順と実byte hashだけを保持する。
		std::uint64_t						 totalBytes{} ;	// 有限台帳の総読取り量。
		// Digestには旧run・pointer・cooldownの実保存byteを使用する。
		const auto							 recordFile = [&]( const std::filesystem::path &path) {
			  std::string bytes ;										// 一fileの原byte。
			  bool		  found{} ;										// 読取り途中の消失を拒否する。
			  const DWORD readError = store.read( path, bytes, found) ;	// ACLを再検証する同じhandle。
			  // 元I/Oを例外の形式errorへ潰さない。
			  if( readError != 0U) {
				  throw readError ;
			  }

			  // 上限を越える台帳を全量メモリへ取り込まない。
			  if( !found || totalBytes > 5ULL * 1024U * 1024U * 1024U - bytes.size()) {
				  throw DWORD{ERROR_INVALID_DATA} ;
			  }

			  totalBytes += bytes.size() ;
			  std::wstring hash ;	// 実保存byteの指紋。
			  // Hash失敗を登録済みdigestへ混ぜない。
			  if( computeBytesSha256( bytes, hash) != 0) {
				  throw DWORD{ERROR_INVALID_DATA} ;
			  }

			  hashes.emplace( path.generic_wstring(), winrt::to_string( hash)) ;
		} ;
		// Source cooldownはtargetが現在scope外でも必ず検査する。
		for( const std::wstring source : {L"ASUS_CATALOG", L"INTEL_ETHERNET_WINDOWS11"}) {
			SourceCooldown cooldown ;	// 旧schemaを通常decoderで検査する。
			// 未知sourceや破損待機は未存在へ変換しない。
			if( !loadCooldown( store, source, cooldown)) {
				return store.lastError() != 0U ? store.lastError() : ERROR_INVALID_DATA ;
			}

			// 存在するsource待機だけを引き継ぐ。
			if( cooldown.observedAt != 0U) {
				// 未来の観測は実測時刻として扱わない。
				if( cooldown.observedAt > utcMillis / 1000U) {
					return ERROR_INVALID_DATA ;
				}

				const std::wstring group =
					// 固定group対応。
					source == L"ASUS_CATALOG" ? L"asus" : L"intel" ;
				waits[L"g-" + group] = {group,
										{},
										cooldown.observedAt * 1000U,
										cooldown.nextAttemptAt * 1000U,
										cooldown.needsReview ||
											cooldown.nextAttemptAt > 4102444799ULL} ;
				recordFile( cooldownPath( source)) ;
			}
		}

		// 各契約の確定pointerを現在のmanifestで絞らず読む。
		for( const auto &name : current) {
			// 明示採用したlocal原点を、portable許可へ変換せず完全な固定fieldで検査する。
			if( name == L"collector-monitor-origin-v1.json") {
				std::string bytes ;		// 保護storeからだけ読むlocal参照。
				bool		found{} ;	// 欠損を新規原点としない。
				const DWORD code = store.read( std::filesystem::path( L"current") / name, bytes,
											  found) ;	// 元I/O結果。
				// 不完全なbindingを履歴なしへ読み替えない。
				if( code != ERROR_SUCCESS || !found) {
					return code != ERROR_SUCCESS ? code : ERROR_INVALID_DATA ;
				}

				const JsonObject origin =
					// 固定schema。
					JsonObject::Parse( winrt::to_hstring( bytes)) ;
				// identityと絶対参照の欠損・余剰を拒否する。
				if( origin.Size() != 7U ||
				   origin.GetNamedString( L"schema", L"") != L"dc-collector-monitor-origin-v1") {
					return ERROR_INVALID_DATA ;
				}

				// 三つのrootは別々の実identityと正規local参照を必要とする。
				for( const std::wstring prefix : {L"native", L"workspace", L"monitor"}) {
					const std::wstring identity =
						// 実体hash。
						origin.GetNamedString( prefix + L"Identity", L"").c_str() ;
					const std::filesystem::path root(
						// 非公開local参照。
						origin.GetNamedString( prefix + L"Root", L"").c_str()) ;
					// 壊れた参照を完全旧検証のdigestへ混ぜない。
					if( !hashName( identity) || !root.is_absolute() ||
					   root != root.lexically_normal() || root.native().size() > 32767U) {
						return ERROR_INVALID_DATA ;
					}
				}

				recordFile( std::filesystem::path( L"current") / name) ;
				continue ;
			}

			// 日次headも同じ保護storeで検証し、旧待機の検証対象から脱落させません。
			if( name == L"daily-generation-v1.json") {
				std::uint64_t generation{} ;	// 完全検証後だけの最大予約世代。
				std::wstring  receiptHash ;		// 完全検証後だけのreceipt hash。
				// 壊れた運用headを初回扱いにしません。
				if( !loadDailyGeneration( store, generation, receiptHash) || generation < 4U) {
					return ERROR_INVALID_DATA ;
				}

				recordFile( std::filesystem::path( L"current") / name) ;
				continue ;
			}

			// Campaignの既知prefixは上位監督が厳密に照合する。
			if( name.starts_with( L"campaign-") || name == L"collector-campaign-mode-v1.json") {
				continue ;
			}

			const auto path = std::filesystem::path( L"current") / name ;	// 任意階層へ進まない。
			// Cooldownは先に固定二sourceで検証済みのものだけを許可する。
			if( name.starts_with( L"cooldown-")) {
				// 未知sourceの待機を捨てて移行しない。
				if( !hashes.contains( path.generic_wstring())) {
					return ERROR_INVALID_DATA ;
				}

				continue ;
			}

			// 旧pointerは完全二hashの固定名である。
			if( name.size() != 134U || name[64U] != L'-' || !name.ends_with( L".json")) {
				return ERROR_INVALID_DATA ;
			}

			const auto manifest = name.substr( 0U, 64U) ;	// 旧manifestの完全hash。
			const auto contract = name.substr( 65U, 64U) ;	// 旧artifact契約の完全hash。
			const auto previous =
				// Pointerからrunのhashまで照合する。
				loadPrevious( store, manifest, contract) ;
			// 不正pointerを未確定runの新規登録へ変換しない。
			if( !previous) {
				return store.lastError() != 0U ? store.lastError() : ERROR_INVALID_DATA ;
			}

			const auto pointerBody =
				// 重複fieldを失ったparse結果は認めない。
				loadEnvelope( store, path) ;
			// 元保存形式と同じcanonical表現だけを登録する。
			if( !pointerBody ||
			   winrt::to_string( JsonObject::Parse( winrt::to_hstring( *pointerBody)).Stringify()) !=
				   *pointerBody) {
				return ERROR_INVALID_DATA ;
			}

			tips.emplace( manifest + L"-" + contract, previous->day) ;
			recordFile( path) ;
		}

		// 正常履歴と未昇格・未完了を全旧runで検査する。
		for( const auto &name : runs) {
			// v1／v2履歴の検査は上位監督へ残す。
			if( name.starts_with( L"campaign-")) {
				continue ;
			}

			const auto path = std::filesystem::path( L"runs") / name ;	// 旧runの有限名。
			const auto body = loadEnvelope( store, path) ;				// 既存envelope・hash検査。
			const auto run = body ? decodeRun( *body) : std::nullopt ;	// 全target・recordの旧schema。
			// 元fieldと保存名が結合したcanonical runだけを取り込む。
			if( !run || runFilePath( run->day, run->manifestSha256, run->contractSha256) != path ||
			   encodeRun( *run) != *body || !validLegacyDay( run->day) ||
			   run->day > legacyDay( utcMillis / 1000U)) {
				return store.lastError() != 0U ? store.lastError() : ERROR_INVALID_DATA ;
			}

			const auto pair =
				run->manifestSha256 + L"-" + run->contractSha256 ;	// 全旧契約を分離する。
			// Pointerなし・未完了・未昇格は旧処理での回収が必要である。
			if( !run->complete || !tips.contains( pair) || tips.at( pair) < run->day) {
				reason = L"LEGACY_RECOVERY_REQUIRED" ;
				return ERROR_RETRY ;
			}

			// 確定pointerに対応するrunの実在を記録する。
			if( tips.at( pair) == run->day) {
				matchedTips.insert( pair) ;
			}

			result.lastUsedDay = std::max( result.lastUsedDay, run->day) ;
			std::set<std::wstring> targets ;	// 同じrun内の重複targetを拒否する。
			// 現在の収集scope外を含む全targetの待機を集約する。
			for( const auto &target : run->targets) {
				retainedHistory |= !target.retainedMetadataBytes.empty() ;
				LocalCollectorTarget input{target.source, target.publicModel,
										   target.operatingSystem, target.category,
										   target.keySha256} ;	// 元公開条件。
				std::wstring		 group ;					// 固定source group。
				std::wstring		 key ;						// 旧artifactやcategoryに依存しないrequest。
				// 旧key・公開値・将来時刻の矛盾を拒否する。
				if( !targets.insert( target.keySha256).second ||
				   !makeLocalCollectorRequestKey( input, group, key) ||
				   target.lastAttemptAt > utcMillis / 1000U ||
				   target.lastSuccessfulValidationAt > utcMillis / 1000U) {
					return ERROR_INVALID_DATA ;
				}

				// 日跨ぎ試行の使用日も開始日とは別に保持する。
				LocalCollectorRequest projected ;	// 同じbuilderによるactual URLとgroup。
				// 異なるhash算法だけで非共有を証明せず、元requestを全件再構築する。
				if( !makeLocalCollectorRequest( input, projected)) {
					return ERROR_INVALID_DATA ;
				}

				// 複数契約やcategoryで同じrequestが重複しても一つの作用域へ統合する。
				if( std::none_of( result.requests.begin(), result.requests.end(),
								[&projected]( const auto &entry) {
									return entry.requestKey == projected.requestKey ;
								})) {
					result.requests.push_back( std::move( projected)) ;
				}

				// 日跨ぎ試行の使用日も開始日とは別に保持する。
				if( target.lastAttemptAt != 0U) {
					result.lastUsedDay =
						std::max( result.lastUsedDay, legacyDay( target.lastAttemptAt)) ;
				}

				std::wstring url ;		// 元cache bindingを再計算するメモリ内URL。
				std::wstring provider ;	// 旧requestの固定配布主体。
				std::wstring resource ;	// 旧requestの固定用途。
				// 同じ公開起点からだけ旧bindingを検証する。
				if( !legacyRoute( input, url, provider, resource)) {
					return ERROR_INVALID_DATA ;
				}

				JsonObject identity ;	// 旧requestBindingの元式を変更しない。
				putString( identity, L"target", input.keySha256) ;
				putString( identity, L"contract", run->contractSha256) ;
				putString( identity, L"provider", provider) ;
				putString( identity, L"resource", resource) ;
				putString( identity, L"url", url) ;
				std::wstring binding ;	// 元契約の再計算hash。
				// 未成功の空bindingは許すが、存在するbindingは完全一致させる。
				if( computeBytesSha256( winrt::to_string( identity.Stringify()), binding) != 0 ||
				   (!target.requestBindingSha256.empty() &&
					target.requestBindingSha256 != binding)) {
					return ERROR_INVALID_DATA ;
				}

				// 旧成功recordは元本文・元契約の射影hashまで確認する。
				if( !target.records.empty() &&
				   (target.lastFetchedAt == 0U || target.lastSuccessfulValidationAt == 0U ||
					target.requestBindingSha256 != binding || !hashName( target.bodySha256) ||
					projectionHash( target) != target.projectionSha256)) {
					return ERROR_INVALID_DATA ;
				}

				// 空集合へ成功時刻を貼り付けた旧状態は採用しない。
				if( target.records.empty() &&
				   (target.lastSuccessfulValidationAt != 0U || target.lastFetchedAt != 0U ||
					!target.bodySha256.empty() || !target.projectionSha256.empty())) {
					return ERROR_INVALID_DATA ;
				}

				// 限流応答に必要なsource待機の消失を拒否する。
				if( (target.lastHttpStatus == 429U || target.lastHttpStatus == 503U) &&
				   !waits.contains( L"g-" + group)) {
					return ERROR_INVALID_DATA ;
				}

				auto &request = waits[L"r-" + key] ;	// 同じrequestの複数category・契約を統合する。
				request.group = group ;
				request.requestKey = key ;
				request.observed   = std::max( {request.observed, target.lastAttemptAt * 1000U,
											   target.lastSuccessfulValidationAt * 1000U}) ;
				request.notBefore =
					std::max( {request.notBefore, target.nextAttemptAt * 1000U,
							  target.lastSuccessfulValidationAt == 0U
								  ? 0U
								  : (target.lastSuccessfulValidationAt + 86400U) * 1000U}) ;
				request.review = request.review || target.holdReason == L"RETRY_AFTER" ||
								 request.notBefore > 4102444799999ULL ;
				// 403は同source全体の要確認を保持する。
				if( target.lastHttpStatus == 403U) {
					auto &source	= waits[L"g-" + group] ;	// 未存在ならgroupだけを追加する。
					source.group	= group ;
					source.observed = std::max( source.observed, target.lastAttemptAt * 1000U) ;
					source.review	= true ;
				}

				// 待機集合の増大を固定上限で停止する。
				if( std::count_if( waits.begin(), waits.end(), []( const auto &entry) {
					   return !entry.second.requestKey.empty() ;
				   }) > 300) {
					reason = L"STATE_CAPACITY" ;
					return ERROR_TOO_MANY_NAMES ;
				}
			}

			recordFile( path) ;
		}

		// 既発行runを残したhead消失から世代4へ巻き戻しません。
		if( retainedHistory && std::find( current.begin(), current.end(),
										L"daily-generation-v1.json") == current.end()) {
			return ERROR_INVALID_DATA ;
		}

		// 参照run欠損を旧fileなしとして登録しない。
		if( matchedTips.size() != tips.size()) {
			return ERROR_INVALID_DATA ;
		}

		std::string digestInput{
			"collector-legacy-v1\n"} ;	// 空履歴もschema付きの非空正規列へ固定する。
		// File名はstoreのASCII限定で区切りとの衝突がない。
		for( const auto &[name, hash] : hashes) {
			digestInput += winrt::to_string( name) + "\n" + hash + "\n" ;
		}

		// 空集合も通常のSHA-256へ固定する。
		if( computeBytesSha256( digestInput, result.digest) != 0) {
			return ERROR_INVALID_DATA ;
		}

		result.fileCount = static_cast<std::uint32_t>( hashes.size()) ;
		// 順序を固定した待機だけをcallerへ返す。
		for( const auto &[key, wait] : waits) {
			result.waits.push_back( wait) ;
		}

		snapshot = std::move( result) ;
		reason.clear() ;
		return ERROR_SUCCESS ;
	} catch( const DWORD error) {
		return error ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_legacy.h */
DWORD prepareLocalCollectorLegacyExport( const std::filesystem::path &candidate,
										const std::uint64_t			 utcMillis,
										CollectorLegacySnapshot		&snapshot,
										std::string					&bytes) noexcept
{
	snapshot = {} ;
	bytes.clear() ;
	try {
		const auto root = checkedStateRoot( candidate) ;	// workspace内の固定一階層。
		// 未存在storeを初期化して待機なしの履歴を作らない。
		if( !root || !candidate.is_absolute() || candidate != candidate.lexically_normal()) {
			return ERROR_INVALID_PARAMETER ;
		}

		// 必須の旧階層とlockを先に確認し、欠損からの新規作成を拒否する。
		for( const auto &relative : {L"", L"runs", L"current", L"collector.lock"}) {
			const auto	path	   = *root / relative ;						// 固定名の通常directoryまたはlock。
			const DWORD attributes = GetFileAttributesW( path.c_str()) ;	// 欠損の元診断。
			// 未存在・アクセス拒否を空の旧snapshotへ変換しない。
			if( attributes == INVALID_FILE_ATTRIBUTES) {
				return GetLastError() ;
			}

			const bool directory = std::wstring_view( relative) != L"collector.lock" ;	// 期待種別。
			// Junction・file/directory入替えはstoreを開く前にも止める。
			if( (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
			   ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) != directory) {
				return ERROR_INVALID_DATA ;
			}
		}

		LocalCollectorStateStore store ;				// 既存の私有ACLと一writer lockを保持する。
		DWORD code = store.initialize( *root, true) ;	// ACLを変更しない既存rootの初期化。
		// Campaignへ移行済みのstoreを旧v4待機だけで出力しない。
		if( code != ERROR_SUCCESS ||
		   (code = rejectLocalCollectorCampaignMode( store)) != ERROR_SUCCESS) {
			return code ;
		}

		std::vector<std::wstring> current ;	// 既存prefixを見落とさない全有限名。
		std::vector<std::wstring> runs ;	// Campaignの未登録履歴も拒否する。
		// 部分列挙を完全な旧検証へ進めない。
		if( (code = store.listCurrentNames( current)) != ERROR_SUCCESS ||
		   (code = store.listRunNames( runs)) != ERROR_SUCCESS) {
			return code ;
		}

		// 旧検査が上位監督へ委譲するprefixは、この出力入口では対象外にする。
		for( const auto &names : {current, runs}) {
			// 全保存名を確認し、旧待機だけへの部分exportを拒否する。
			for( const auto &name : names) {
				// 新監督のbyteを無視して旧schemaへ縮小しない。
				if( name.starts_with( L"campaign-")) {
					return ERROR_INVALID_DATA ;
				}
			}
		}

		CollectorLegacySnapshot result ;	// 全旧run・pointer・source待機の非変更結果。
		std::wstring			reason ;	// 旧validatorの固定理由。stdoutへ秘密を渡さない。
		code = inspectLocalCollectorLegacy( store, utcMillis, result, reason) ;
		// 未回収・未昇格・破損の旧履歴をそのまま持ち出さない。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		JsonObject document ;	// 同じ待機をmillisecond整数のまま保持する公開情報。
		putString( document, L"schema", L"dc-collector-legacy-wait-export-v1") ;
		putNumber( document, L"observedAtUtcMillis", utcMillis) ;
		putString( document, L"legacyDigest", result.digest) ;
		putNumber( document, L"legacyFileCount", result.fileCount) ;
		putString( document, L"lastUsedDay", result.lastUsedDay) ;
		JsonArray waits ;	// 元groupとrequestの順序・期限を変更しない。
		// 検証済み旧待機だけをURLなしの公開fieldへ投影する。
		for( const auto &wait : result.waits) {
			JsonObject row ;	// 一つの恒久requestまたはsource待機。
			putString( row, L"group", wait.group) ;
			putString( row, L"requestKey", wait.requestKey) ;
			putNumber( row, L"observed", wait.observed) ;
			putNumber( row, L"notBefore", wait.notBefore) ;
			row.Insert( L"review", JsonValue::CreateBooleanValue( wait.review)) ;
			waits.Append( row) ;
		}

		document.Insert( L"waits", waits) ;
		std::string encoded = winrt::to_string( document.Stringify()) ;	// 有限UTF-8の所有byte。
		encoded += '\n' ;
		// 旧待機集合の既存上限に加えて、出力byteも有限にする。
		if( encoded.size() > MAXIMUM_STATE_BYTES) {
			return ERROR_FILE_TOO_LARGE ;
		}

		snapshot = std::move( result) ;
		bytes	 = std::move( encoded) ;
		return ERROR_SUCCESS ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}

} // namespace drivercrate
