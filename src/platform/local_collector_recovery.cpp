//------------------------------------------------------------------------------
/**
 * @file local_collector_recovery.cpp
 * @brief 固定更新前後像と応答先行のv2監督を実装します。
 * @version 01.29.03
 * @date 2026/09/29
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  応答先行回収と固定commitを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  日次回収の二重前進と待機容量の誤分類を補修。
 * Ver.01.02.00 Shunji Ogawa  2026/09/27  初回容量・旧削除分類を補修し保存枠検査を共用。
 * Ver.01.03.00 Shunji Ogawa  2026/09/27  予約判定をreadinessと共用し有限deadlineを返す。
 * Ver.01.04.00 Shunji Ogawa  2026/09/27  v3応答・二version回収・制御予約結合を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/28  Dispatch同値に予約modeを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/28  v3登録・旧root回収・世代別inventoryを追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/28  射影予約と四role中断回収・容量を接続。
 * Ver.01.07.01 Shunji Ogawa  2026/09/28  元inputのscopeを予約へ結合。
 * Ver.01.08.00 Shunji Ogawa  2026/09/29  旧gateを維持した新世代専用readinessを追加。
 * Ver.01.09.00 Shunji Ogawa  2026/09/29  初回親prepareと保存前の元予約再照合を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/09/29  中断CACHEを共通有限codecへ接続。
 * Ver.01.11.00 Shunji Ogawa  2026/09/29  予約前履歴根拠と親の応答・CACHE候補を結合。
 * Ver.01.12.00 Shunji Ogawa  2026/09/30  登録履歴と四role更新前後像の非変更検証を追加。
 * Ver.01.13.00 Shunji Ogawa  2026/09/30  初回v4原byte保存・四role成功commitと回復を接続。
 * Ver.01.14.00 Shunji Ogawa  2026/09/30  固定完了intent・対象shard／summary／pointerと回復を追加。
 * Ver.01.15.00 Shunji Ogawa  2026/09/30  初回完了の全inventoryを有限読取りと履歴contextへ接続。
 * Ver.01.16.00 Shunji Ogawa  2026/09/30  全完了世代をCACHE鎖・元日精算と非変更再結合。
 * Ver.01.17.00 Shunji Ogawa  2026/09/30  全完了検査を通常inventory・最新完了再読込みへ接続。
 * Ver.01.18.00 Shunji Ogawa  2026/09/30  明示次回開始と未応答末尾・所有履歴予約を接続。
 * Ver.01.19.00 Shunji Ogawa  2026/09/30  次世代所有結果の履歴保存・精算済み末尾完了を接続。
 * Ver.01.20.00 Shunji Ogawa  2026/09/30  更新前全履歴から未登録v4・準備prefixを非再送回復。
 * Ver.01.21.00 Shunji Ogawa  2026/09/30  登録commitの論理前像検査と反映suffix回復を追加。
 * Ver.01.22.00 Shunji Ogawa  2026/10/01  元成功を保持した欠測中断と保存v2の全prefix復旧を追加。
 * Ver.01.22.01 Shunji Ogawa  2026/10/01  検査済み登録commitの元acceptedとroot監督時計を分離。
 * Ver.01.23.00 Shunji Ogawa  2026/10/01  最後の部分開始予約を共通検査と非再送中断へ接続。
 * Ver.01.23.01 Shunji Ogawa  2026/10/01  二prefix証明後だけROOTより先行した共有時計を受入。
 * Ver.01.23.02 Shunji Ogawa  2026/10/01  開始prefixと先行精算の注釈を実装へ整合。
 * Ver.01.24.00 Shunji Ogawa  2026/10/01  全完了inventoryへ日次切替の有限prefix検査と回復を接続。
 * Ver.01.24.01 Shunji Ogawa  2026/10/01  証跡なし全完了と既存日次切替回復の注釈を一致。
 * Ver.01.24.02 Shunji Ogawa  2026/10/01  日次先行検査でも世代容量超過の元68を保持。
 * Ver.01.25.00 Shunji Ogawa  2026/10/01  未完了末尾の固定完了prefix検査と不足suffix復旧を接続。
 * Ver.01.26.00 Shunji Ogawa  2026/10/01  原raw容量拒否と部分計数を非変更診断へ接続。
 * Ver.01.27.00 Shunji Ogawa  2026/10/02  全raw先払いと完了rootの封印導出を追加。
 * Ver.01.28.00 Shunji Ogawa  2026/10/02  元共有値／CACHE由来と私有同時再検査を追加。
 * Ver.01.29.00 Shunji Ogawa  2026/10/02  HTTP発行の実所有と初期化前freeze検査を追加。
 * Ver.01.29.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.29.02   Shunji Ogawa  2026/10/16 保存応答の省略可能な観測出力と失敗時契約を明記。
 * Ver.01.29.03 Shunji Ogawa  2026/10/24  必須解析の型・有限所有buffer・失敗制御を明示。
 * </pre>
 *
 * @note HTTP、cacheの品質昇格、summary公開は実行しません。
 */
//------------------------------------------------------------------------------
#include "local_collector_recovery.h"
#include "local_collector_completed_inventory.h"
#include "local_collector_projected_input.h"
#include "local_collector_projected_start.h"
#include "local_collector_projected_response.h"
#include "local_collector_projected_cache.h"
#include "local_collector_http_observation.h"
#include "local_collector_legacy.h"
#include "local_collector_state_store.h"
#include "official_file_verifier.h"

#include <objbase.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <set>
#include <utility>

namespace drivercrate {
namespace {
/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using Object = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON配列をWinRT参照で保持する。要素数と各要素のschema検証は利用側で行う。
 */
using Array = winrt::Windows::Data::Json::JsonArray ;
/**
 * @brief JSON値をWinRT参照で保持する。所有byteの検証と型判定はreader側で行う。
 */
using Value = winrt::Windows::Data::Json::JsonValue ;
// 永続先は組み込みの有限名だけを使う。
constexpr auto			ROOT = L"current/campaign-root-v2.json" ;
// 旧APIの混用を止めるmode marker。
constexpr auto			MODE = L"current/collector-campaign-mode-v1.json" ;
// 既存v1と共用する日次予算。
constexpr auto			BUDGET = L"current/campaign-budget-v1.json" ;
// Manifest独立のrequest待機表。
constexpr auto			CONTROL = L"current/campaign-controls-v1.json" ;
// 予算の片側欠損を検出するmarker。
constexpr auto			BUDGET_MARKER = L"current/campaign-budget-marker-v1.json" ;
// 待機表の片側欠損を検出するmarker。
constexpr auto			CONTROL_MARKER = L"current/campaign-controls-marker-v1.json" ;
// 最新の完了世代だけを指す固定名です。
constexpr auto			FINISH_POINTER = L"current/campaign-current-v2.json" ;
// 通常の実行時計は2100年未満に限定する。
constexpr std::uint64_t LAST_UTC = 4102444799999ULL ;
// 未知結果にも適用する24時間のmillisecond。
constexpr std::uint64_t DAY = 86400000ULL ;

/** @brief 不変条件違反を数値errorとして止めます。
 * @param[in] ok 継続可能条件。
 * @param[in] code 失敗時の数値code。
 */
void					require( const bool ok, const DWORD code = ERROR_INVALID_DATA)
{
	// 既知のcodeを例外経由でも保持する。
	if( !ok) {
		throw code ;
	}
}

/** @brief 成否APIの元I/O errorを保持します。
 * @param[in] code 元API結果。
 */
void io( const DWORD code)
{
	require( code == 0U, code) ;
}

/** @brief 専用codecの第一HRESULT／容量／OOMを元数値で保持します。
 * @param[in] result 専用codecの確定結果。成功値は注入しません。
 */
void projectedCodec( const collector_projected_json::Result result)
{
	// 不成立だけを監督の第一errorへ渡します。
	if( result.status != collector_projected_json::Status::OK) {
		throw result.error != 0 ? static_cast<DWORD>( result.error)
		: result.status == collector_projected_json::Status::OUT_OF_MEMORY
			? static_cast<DWORD>( E_OUTOFMEMORY)
		: result.status == collector_projected_json::Status::SIZE_LIMIT ? ERROR_TOO_MANY_NAMES
																		: ERROR_INVALID_DATA ;
	}
}

/** @brief 有限保存byteのSHAを計算します。
 * @param[in] bytes 元byte列。
 * @return 小文字の完全SHA-256。
 */
std::wstring sha( const std::string_view bytes)
{
	std::wstring result ;	// 端末情報を持たない内容指紋。
	io( computeBytesSha256( bytes, result)) ;
	std::transform( result.begin(), result.end(), result.begin(), []( wchar_t c) {
		return c >= L'A' && c <= L'F' ? static_cast<wchar_t>( c + (L'a' - L'A')) : c ;
	}) ;
	return result ;
}

/** @brief 小文字SHAだけを認めます。
 * @param[in] value 候補。
 * @return 完全hashならtrue。
 */
bool hash( const std::wstring_view value)
{
	return value.size() == 64U && std::all_of( value.begin(), value.end(), []( wchar_t c) {
			   return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ;
		   }) ;
}

/** @brief UTCを固定JST日へ変換します。
 * @param[in] millis 有限UTC millisecond。
 * @return YYYYMMDD。
 */
std::wstring day( const std::uint64_t millis)
{
	require( millis >= 1000U && millis <= LAST_UTC) ;
	const auto date = std::chrono::year_month_day( std::chrono::floor<std::chrono::days>(
		std::chrono::sys_time<std::chrono::milliseconds>( std::chrono::milliseconds( millis)) +
		// 地域設定によらないJST日。
		std::chrono::hours( 9))) ;
	wchar_t	   result[9]{} ;	// 固定長の公開日付。
	swprintf_s( result, L"%04d%02u%02u", int( date.year()), unsigned( date.month()),
			   unsigned( date.day())) ;
	return result ;
}

/** @brief JSONへ有限文字列を入れます。
 * @param[in,out] object 保存object。
 * @param[in] key 固定field。
 * @param[in] value 保存値。
 */
void put( const Object &object, const wchar_t *key, const std::wstring_view value)
{
	object.Insert( key, Value::CreateStringValue( winrt::hstring( value))) ;
}

/** @brief JSONへ正確な整数を入れます。
 * @param[in,out] object 保存object。
 * @param[in] key 固定field。
 * @param[in] value 2の53乗未満。
 */
void put( const Object &object, const wchar_t *key, const std::uint64_t value)
{
	require( value < 9007199254740992ULL) ;
	object.Insert( key, Value::CreateNumberValue( static_cast<double>( value))) ;
}

/** @brief 数値fieldを厳格に読みます。
 * @param[in] object 型検証対象。
 * @param[in] key 固定field。
 * @return 有限非負整数。
 */
std::uint64_t number( const Object &object, const wchar_t *key)
{
	const double value = object.GetNamedNumber( key) ;	// JSON numberの正確性を確認する。
	require( std::isfinite( value) && value >= 0 && value < 9007199254740992.0 &&
			std::floor( value) == value) ;
	return static_cast<std::uint64_t>( value) ;
}

/** @brief JSON文字列を有限で読みます。
 * @param[in] object 型検証対象。
 * @param[in] key 固定field。
 * @return UTF-16値。
 */
std::wstring str( const Object &object, const wchar_t *key)
{
	return std::wstring( object.GetNamedString( key)) ;
}

/** @brief CanonicalなUTF-8を作ります。
 * @param[in] object 元object。
 * @return 保存本文。
 */
std::string bytes( const Object &object)
{
	return winrt::to_string( object.Stringify()) ;
}

/** @brief 重複fieldや別表現を許さずcanonical JSONを読みます。
 * @param[in] body 最大768 KiBの本文。
 * @return 有効object。
 */
Object json( const std::string_view body)
{
	require( body.size() <= 768U * 1024U && body.find( '\0') == std::string_view::npos) ;
	const auto object = Object::Parse( winrt::to_hstring( body)) ;	// WinRTによる型付きparse。
	require( bytes( object) == body) ;
	return object ;
}

/** @brief Objectのfield集合を厳密に照合します。
 * @param[in] object 型検証対象。
 * @param[in] names 固定field集合。
 */
void fields( const Object &object, const std::initializer_list<const wchar_t *> names)
{
	require( object.Size() == names.size()) ;
	// 未知field・欠損を部分成功へしない。
	for( const auto name : names) {
		require( object.HasKey( name)) ;
	}
}

/** @brief Schema付きobjectを作ります。
 * @param[in] schema 組み込みschema。
 * @return 新規object。
 */
Object make( const wchar_t *schema)
{
	Object object ; /* 固定schemaの開始点。 */
	put( object, L"schema", schema) ;
	return object ;
}

/** @brief Hash envelopeを保護handleから読みます。
 * @param[in,out] store 借用store。
 * @param[in] path 固定相対名。
 * @return 欠損nulloptまたは検証済み本文。
 */
std::optional<std::string> read( LocalCollectorStateStore &store, const std::filesystem::path &path)
{
	std::string data ;		// 同じ検証済みhandleからのbyte。
	bool		found{} ;	// 欠損とI/O errorを区別する。
	io( store.read( path, data, found)) ;
	// 未存在を内容破損に置き換えない。
	if( !found) {
		return std::nullopt ;
	}

	const auto envelope = Object::Parse( winrt::to_hstring( data)) ;	// 既存v1 envelopeを維持する。
	fields( envelope, {L"schema", L"body", L"sha256"}) ;
	const auto body = winrt::to_string( envelope.GetNamedString( L"body")) ;	// Hash対象は元本文byte。
	require( str( envelope, L"schema") == L"collector-campaign-envelope-v1" &&
			body.size() <= 768U * 1024U && sha( body) == str( envelope, L"sha256")) ;
	return body ;
}

/** @brief 必須envelopeを読みます。
 * @param[in,out] store 借用store。
 * @param[in] path 固定相対名。
 * @return 必須本文。
 */
std::string required( LocalCollectorStateStore &store, const std::filesystem::path &path)
{
	const auto body = read( store, path) ; /* 欠損を新規へ戻さない。 */
	require( body.has_value()) ;
	return *body ;
}

/** @brief 閉包のraw byteを有限に読み、終了時に全存在・hashを再照合する読取り専用部品です。 */
struct RegisteredHistoryReader {
	/// 全末尾・旧完了prefix・元時刻から再導出した四本文。全raw再照合後だけ返します。
	std::optional<std::array<std::string, 4U>>					 finishBodies ;
	/// 全完了起動だけが証明した一件の日次intent。全再照合後だけ監督へ返します。
	std::string													 dayRollIntent ;
	/// 同じ日次intentと三準備像の固定名。未知fileを許可する一般集合ではありません。
	std::set<std::wstring>										 dayRollNames ;
	/// 元PENDINGと最後の予約の二prefixが全末尾検査で証明された場合だけtrueです。
	bool														 partialStartVerified{} ;
	/// 全像と物理prefixを検査済みの登録commit一操作。論理前像の時計区別だけに使います。
	std::optional<std::wstring>									 registeredOperation ;
	/// 呼出し中だけ借用する保護store。保存・lease変更をしません。
	LocalCollectorStateStore									&store ;
	/// 不在名も含む最初の実byte指紋。最大6000名。
	std::map<std::filesystem::path, std::optional<std::wstring>> identities ;
	/// 最終再読取りも含めた累積raw byte。最大64 MiB。
	std::size_t													 total{} ;
	/// 封印入口だけは保護handleの確保・読込みより先に64 MiB残量を課金します。
	bool														 prepay{} ;
	/// 初回rawの同handle byte量。封印入口だけが保持します。
	std::map<std::filesystem::path, std::uint64_t>				 rawSizes ;
	/// 任意の部分計数出力。path／本文を持たず制御判断へ使用しません。
	CollectorHistoryReadDiagnostics								*diagnostics{} ;

	/// 応答の固定五件または日次の固定三件だけの検査専用前像。物理raw照合を省略しません。
	std::map<std::filesystem::path, std::optional<std::string>>	 beforeView ;

	/** @brief 保護storeをこの呼出し中だけ借用します。
	 * @param[in,out] source 読取り対象。呼出しwriter threadだけで使用します。
	 * @param[out] observation 任意の部分観測。呼出し全体で借用します。
	 * @param[in] prepayRaw 封印専用の場合true。従来入口の後課金は変更しません。
	 */
	explicit RegisteredHistoryReader( LocalCollectorStateStore		 &source,
									 CollectorHistoryReadDiagnostics *observation = nullptr,
									 const bool						  prepayRaw	  = false)
		: store( source), prepay( prepayRaw), diagnostics( observation)
	{
	}
	/** @brief 固定名を読み、変更・累積上限・元I/O errorを検査します。
	 * @param[in] name hashから作った固定相対名。
	 * @return 存在時の元byte、不在時nullopt。
	 */
	std::optional<std::string> raw( const std::filesystem::path &name)
	{
		std::string data ;		// 同じ保護handleからの実byte。
		bool		found{} ;	// 不在とI/O失敗を区別します。
		// 封印入口だけはReadFile／確保前に累積残量を渡します。
		if( prepay) {
			std::uint64_t remaining = 64U * 1024U * 1024U - total ;			// 同じ有限枠です。
			const auto error = store.read( name, data, found, remaining) ;	// 元I/Oを先に保持します。
			total			 = 64U * 1024U * 1024U - static_cast<std::size_t>( remaining) ;
			// 失敗I/Oでも先払い済み量を払い戻しません。
			if( diagnostics) {
				diagnostics->chargedBytes = total ;
			}

			io( error) ;
		} else {
			io( store.read( name, data, found)) ;
		}

		// 成功I/O後の実量だけを通知し、元容量判定を変更しません。
		if( diagnostics) {
			diagnostics->attemptedBytes = data.size() ;
			++diagnostics->readCalls ;
			// 拒否される同じpredicateで記録し、code68から逆算しません。
			if( !prepay && data.size() > 64U * 1024U * 1024U - total) {
				diagnostics->capacity = CollectorHistoryCapacity::RAW_BYTES ;
			}
		}

		// 旧入口のpost-read課金・診断分母を維持します。
		if( !prepay) {
			require( data.size() <= 64U * 1024U * 1024U - total, ERROR_TOO_MANY_NAMES) ;
			total += data.size() ;
		}

		// 未指定のcallerには計数保存を追加しません。
		if( diagnostics) {
			diagnostics->chargedBytes = total ;
		}

		const auto identity =
			found ? std::optional<std::wstring>( sha( data)) : std::nullopt ;	// 不在も固定します。
		const auto previous = identities.find( name) ;							// 最初の観測との照合位置。
		// 再読取りで変わったfileを縮退成功へしません。
		if( previous != identities.end()) {
			require( previous->second == identity) ;
		} else {
			// 初回identity登録を拒否する元容量箇所だけを区別します。
			if( diagnostics && identities.size() >= 6000U) {
				diagnostics->capacity = CollectorHistoryCapacity::REFERENCE_NAMES ;
			}

			require( identities.size() < 6000U, ERROR_TOO_MANY_NAMES) ;
			identities.emplace( name, identity) ;
			// 同じ初回handleのsizeと実hashだけを封印へ結合します。
			if( prepay && found) {
				rawSizes.emplace( name, static_cast<std::uint64_t>( data.size())) ;
			}

			// 登録済み名だけを数え、不在も元検査と同様に保持します。
			if( diagnostics) {
				diagnostics->referencedNames = identities.size() ;
			}
		}

		return found ? std::optional<std::string>( std::move( data)) : std::nullopt ;
	}
	/** @brief 既存hash envelopeの元本文を独立検証します。
	 * @param[in] name 固定相対名。
	 * @return 存在時の検証済み本文、不在時nullopt。
	 */
	std::optional<std::string> physicalBody( const std::filesystem::path &name)
	{
		const auto data = raw( name) ;	// 外側hashと存在を固定します。
		// 欠損を新規の成功値へ補完しません。
		if( !data) {
			return std::nullopt ;
		}

		const auto envelope = Object::Parse( winrt::to_hstring( *data)) ;	// 旧外側codecを維持します。
		fields( envelope, {L"schema", L"body", L"sha256"}) ;
		const auto value = winrt::to_string( envelope.GetNamedString( L"body")) ;	// 元hash対象。
		require( str( envelope, L"schema") == L"collector-campaign-envelope-v1" &&
				value.size() <= 768U * 1024U && sha( value) == str( envelope, L"sha256")) ;
		return value ;
	}
	/** @brief 物理raw検査後だけ固定した検査専用前像を解釈します。
	 * @param[in] name 固定相対名。任意pathをビューへ登録する入口ではありません。
	 * @return ビューがあれば検査専用前値、それ以外は物理本文。不在はnullopt。
	 */
	std::optional<std::string> body( const std::filesystem::path &name)
	{
		const auto physical	 = physicalBody( name) ;	// 論理前像があっても物理I/Oとhashを検査します。
		const auto projected = beforeView.find( name) ;	// 最大五件の固定解釈だけ。
		return projected == beforeView.end() ? physical : projected->second ;
	}
	/** @brief 必須保存物の欠損を拒否します。
	 * @param[in] name 固定相対名。
	 * @return 元本文。
	 */
	std::string mandatory( const std::filesystem::path &name)
	{
		const auto value = body( name) ;	// hashと存在の独立検査。
		require( value.has_value()) ;
		return *value ;
	}
	/// 完了検査時だけ固定するcurrent／runsの全保存名。未使用時nullです。
	std::optional<std::array<std::vector<std::wstring>, 2U>> names ;

	/** @brief 完了検査の全保存名を最初の非変更列挙へ固定します。 */
	void													 captureNames()
	{
		require( !names) ;
		names.emplace() ;
		io( store.listCurrentNames( (*names)[0])) ;
		io( store.listRunNames( (*names)[1])) ;
	}
	/** @brief 公開直前に全参照rawと、固定した全保存名を再確認します。 */
	void recheck()
	{
		// 最終照合開始と成功完了は別であり、開始だけを記録します。
		if( diagnostics) {
			diagnostics->recheckStarted = true ;
		}

		// 欠損を含む同じ有限集合だけを再読取りします。新規名は追加しません。
		for( const auto &entry : identities) {
			(void)raw( entry.first) ;
		}

		// 完了検査中の未参照file追加・消失も成功contextへ混入させません。
		if( names) {
			std::array<std::vector<std::wstring>, 2U> current ;	// 同じ保護列挙の終了時の全名。
			io( store.listCurrentNames( current[0])) ;
			io( store.listRunNames( current[1])) ;
			require( current == *names) ;
		}
	}
} ;

/** @brief 全semantic検査済みrawから有限inventory／sealを導出します。
 * @param[in] reader 元raw identityと全保存名を持つ先払いreader。
 * @param[in] rootBody 元ROOT本文。
 * @param[in] sources 再検査したsource契約。
 * @param[in] utc 検査UTC。元時刻を更新しません。
 * @param[in] operations 全閉包検査済み操作数。
 * @param[in] budgetBody 元予算本文。
 * @param[in] controlBody 元制御本文。
 * @return 最終再照合前の値。単体DTOは検査証明ではありません。
 */
CollectorCompletedRootEvidence makeCompletedRootEvidence(
	const RegisteredHistoryReader &reader, const std::string &rootBody,
	const std::span<const CollectorCampaignSource> sources, const std::uint64_t utc,
	const std::size_t operations, const std::string &budgetBody, const std::string &controlBody)
{
	require( reader.prepay && reader.names && !sources.empty() && sources.size() <= 20U) ;
	CollectorCompletedRootEvidence result ;					// 元rawだけから導出する候補です。
	const auto					   root = json( rootBody) ;	// 元ROOTの登録を保持します。
	result.rootSha256					= sha( rootBody) ;
	result.rootKey						= str( root, L"rootKey") ;
	result.rootUtcMillis				= number( root, L"lastUtcMillis") ;
	result.budgetBody					= budgetBody ;
	result.controlBody					= controlBody ;
	result.inspectedUtcMillis			= utc ;
	result.generations					= root.GetNamedArray( L"generations").Size() ;
	result.operations					= operations ;
	// current／runsの固定role順で全存在fileを検査します。
	for( std::size_t directory = 0U; directory < reader.names->size(); ++directory) {
		const std::wstring prefix = directory == 0U ? L"current/" : L"runs/" ;	// 固定directoryです。
		// 未参照fileを封印へ混入させません。
		for( const auto &name : (*reader.names)[directory]) {
			const std::filesystem::path path = prefix + name ;		// 保護列挙済みbasenameだけです。
			const auto identity = reader.identities.find( path) ;	// Semantic参照の存在です。
			const auto size		= reader.rawSizes.find( path) ;		// 同じ初回handleのsizeです。
			require( identity != reader.identities.end() && identity->second &&
					size != reader.rawSizes.end()) ;
			require( size->second <= 64U * 1024U * 1024U - result.fileBytes, ERROR_TOO_MANY_NAMES) ;
			result.fileBytes += size->second ;
			result.files.push_back( {path.generic_wstring(), *identity->second, size->second}) ;
		}
	}

	require( !result.files.empty() && result.files.size() == reader.rawSizes.size() &&
				result.files.size() <= 8192U,
			ERROR_TOO_MANY_NAMES) ;
	// 全fileを最大512行の独立shardへ順序を保って結合します。
	for( std::size_t first = 0U; first < result.files.size(); first += 512U) {
		Object shard = make( L"collector-completed-root-inventory-v1") ;	// 固定schemaです。
		put( shard, L"rootKey", result.rootKey) ;
		put( shard, L"root", result.rootSha256) ;
		put( shard, L"ordinal", result.shards.size()) ;
		put( shard, L"fileCount", result.files.size()) ;
		Array rows ;	// このshardに含める元raw identityです。
		// 最後の残行も一回ずつ結合し、空shardを作りません。
		for( std::size_t index = first; index < std::min( first + 512U, result.files.size());
			++index) {
			Object row ;	// 一つの実rawの全fieldです。
			put( row, L"name", result.files[index].name) ;
			put( row, L"bytes", result.files[index].bytes) ;
			put( row, L"sha256", result.files[index].sha256) ;
			rows.Append( row) ;
		}

		shard.Insert( L"files", rows) ;
		const auto body = bytes( shard) ;	// 本文全byteのhash対象です。
		require( body.size() <= 256U * 1024U && result.shards.size() < 16U, ERROR_TOO_MANY_NAMES) ;
		result.shards.push_back( {body, sha( body)}) ;
	}

	Array											contracts ;		// 実検査に使った全sourceの順序です。
	std::set<std::pair<std::wstring, std::wstring>> sourceKeys ;	// 重複を拒否する完全keyです。
	// 名前だけでなく契約の全fieldを封印へ結合します。
	for( const auto &source : sources) {
		require( !source.sourceId.empty() && source.sourceId.size() <= 128U &&
				!source.resourceId.empty() && source.resourceId.size() <= 128U &&
				!source.rateLimitGroup.empty() && source.rateLimitGroup.size() <= 128U &&
				!source.parserRevision.empty() && source.parserRevision.size() <= 128U &&
				source.maximumResponseBytes > 0U &&
				source.maximumResponseBytes <= 8U * 1024U * 1024U &&
				sourceKeys.emplace( source.sourceId, source.resourceId).second) ;
		Object row ;	// Sourceの全契約です。
		put( row, L"sourceId", source.sourceId) ;
		put( row, L"resourceId", source.resourceId) ;
		put( row, L"rateLimitGroup", source.rateLimitGroup) ;
		put( row, L"parserRevision", source.parserRevision) ;
		put( row, L"maximumResponseBytes", source.maximumResponseBytes) ;
		contracts.Append( row) ;
	}

	const auto sourceBody = winrt::to_string( contracts.Stringify()) ;	// 元契約の全byteです。
	require( sourceBody.size() <= 16U * 1024U, ERROR_TOO_MANY_NAMES) ;
	Object seal = make( L"collector-completed-root-seal-v1") ;	// 新区間sealとは別schemaです。
	put( seal, L"rootKey", result.rootKey) ;
	put( seal, L"root", result.rootSha256) ;
	put( seal, L"rootUtc", number( root, L"lastUtcMillis")) ;
	put( seal, L"inspectedUtc", utc) ;
	put( seal, L"sources", sha( sourceBody)) ;
	put( seal, L"budget", sha( budgetBody)) ;
	put( seal, L"control", sha( controlBody)) ;
	put( seal, L"cacheInventory",
		sha( winrt::to_string( root.GetNamedArray( L"cacheInventory").Stringify()))) ;
	put( seal, L"generations", result.generations) ;
	put( seal, L"operations", result.operations) ;
	put( seal, L"fileCount", result.files.size()) ;
	put( seal, L"fileBytes", result.fileBytes) ;
	Array shardHashes ;	// 元ordinal順の全shard hashです。
	// 全shardを一つの封印へ閉じます。
	for( const auto &shard : result.shards) {
		shardHashes.Append( Value::CreateStringValue( shard.sha256)) ;
	}

	seal.Insert( L"inventory", shardHashes) ;
	result.seal = bytes( seal) ;
	require( result.seal.size() <= 16U * 1024U, ERROR_TOO_MANY_NAMES) ;
	result.sealSha256 = sha( result.seal) ;
	return result ;
}

/** @brief 同一hash envelopeをatomic保存します。
 * @param[in,out] store 借用store。
 * @param[in] path 固定相対名。
 * @param[in] body 元schemaの本文。
 * @param[in] immutable trueでは同内容の再利用だけを許します。
 */
void save( LocalCollectorStateStore &store, const std::filesystem::path &path,
		  const std::string_view body, const bool immutable = false)
{
	require( body.size() <= 768U * 1024U) ;
	// Immutableの既存byteは同一の場合だけ再利用する。
	if( immutable) {
		const auto old = read( store, path) ;	// 欠損だけが作成可能。
		// 既存immutable本文は完全一致の場合だけ再利用する。
		if( old) {
			require( *old == body) ;
			return ;
		}
	}

	const auto envelope = make( L"collector-campaign-envelope-v1") ;	// 共通envelope。
	put( envelope, L"body", winrt::to_hstring( body)) ;
	put( envelope, L"sha256", sha( body)) ;
	io( store.write( path, bytes( envelope))) ;
	require( required( store, path) == body) ;
}

/** @brief Hashからgeneration固有の固定名を作ります。
 * @param[in] prefix 組み込みprefix。
 * @param[in] key 検証済みhash。
 * @return 固定相対名。
 */
std::filesystem::path path( const wchar_t *prefix, const std::wstring_view key)
{
	require( hash( key)) ;
	return std::wstring( prefix) + std::wstring( key) + L".json" ;
}

/** @brief 固定公開入力を保存し、再parseして一致を確認します。
 * @param[in] input Caller固定入力。
 * @param[in] startDay Generation開始日。
 * @param[out] manifest 検証済み共有job。
 * @return Canonical input。
 */
Object encodeInput( const CollectorRecoveryInput &input, const std::wstring_view startDay,
				   CollectorCampaignManifest &manifest)
{
	require( hash( input.artifactSha256) &&
			parseCollectorCampaignManifest( input.manifestBytes, input.sources, manifest)) ;
	require( input.requestKeys.size() == manifest.jobs.size() &&
			input.cacheBindings.size() == manifest.jobs.size()) ;
	const auto result = make( L"collector-campaign-input-v2") ;	// 元manifest byteを保持する。
	put( result, L"day", startDay) ;
	put( result, L"artifact", input.artifactSha256) ;
	put( result, L"manifest", winrt::to_hstring( input.manifestBytes)) ;
	put( result, L"manifestSha256", manifest.manifestSha256) ;
	Array sources ;	// 呼出し側の固定registry全体。
	// 取得許可ではなく元inputの再解釈に必要な契約だけを保存する。
	for( const auto &source : input.sources) {
		Object row ;	// 一つの固定source。
		put( row, L"source", source.sourceId) ;
		put( row, L"resource", source.resourceId) ;
		put( row, L"group", source.rateLimitGroup) ;
		put( row, L"parser", source.parserRevision) ;
		put( row, L"maximum", source.maximumResponseBytes) ;
		sources.Append( row) ;
	}

	result.Insert( L"sources", sources) ;
	Array bindings ;	// 固定job順の非機密結合。
	// Public requestとcacheの結合を分けて保存する。
	for( std::size_t index = 0; index < manifest.jobs.size(); ++index) {
		require( hash( input.requestKeys[index]) && hash( input.cacheBindings[index])) ;
		Object row ;	// 一つの重複除去job。
		put( row, L"job", manifest.jobs[index].key) ;
		put( row, L"request", input.requestKeys[index]) ;
		put( row, L"cache", input.cacheBindings[index]) ;
		put( row, L"batch",
			static_cast<std::uint64_t>( *std::min_element( manifest.jobs[index].targetIndices.begin(),
														 manifest.jobs[index].targetIndices.end()) /
									   32U)) ;
		bindings.Append( row) ;
	}

	result.Insert( L"bindings", bindings) ;
	return result ;
}

/** @brief 保存inputを元registryで再parseします。
 * @param[in] object 保存input。
 * @param[out] manifest 元共有job。
 * @return 保存時と同じ型付き入力。
 */
CollectorRecoveryInput decodeInput( const Object &object, CollectorCampaignManifest &manifest)
{
	fields( object, {L"schema", L"day", L"artifact", L"manifest", L"manifestSha256", L"sources",
					L"bindings"}) ;
	require( str( object, L"schema") == L"collector-campaign-input-v2") ;
	CollectorRecoveryInput input ;	// URLを含まない元入力。
	input.manifestBytes	 = winrt::to_string( object.GetNamedString( L"manifest")) ;
	input.artifactSha256 = str( object, L"artifact") ;
	const auto sources	 = object.GetNamedArray( L"sources") ;	// 有限registry。
	require( sources.Size() <= 64U) ;
	// 保存sourceは新しい許可ではなく旧応答の照合だけに使う。
	for( const auto &value : sources) {
		const auto row = value.GetObject() ;	// 一つの組み込み契約像。
		fields( row, {L"source", L"resource", L"group", L"parser", L"maximum"}) ;
		input.sources.push_back( {str( row, L"source"), str( row, L"resource"), str( row, L"group"),
								 str( row, L"parser"), number( row, L"maximum")}) ;
	}

	const auto bindings = object.GetNamedArray( L"bindings") ;	// 固定job順。
	require( bindings.Size() <= 300U) ;
	// 復号後にjob・batchも再計算して比較する。
	for( const auto &value : bindings) {
		const auto row = value.GetObject() ;	// 非機密request結合。
		fields( row, {L"job", L"request", L"cache", L"batch"}) ;
		input.requestKeys.push_back( str( row, L"request")) ;
		input.cacheBindings.push_back( str( row, L"cache")) ;
	}

	require( bytes( encodeInput( input, str( object, L"day"), manifest)) == bytes( object)) ;
	return input ;
}

/** @brief 元日付・manifest・artifactへgenerationを結合します。
 * @param[in] input 固定input。
 * @return 完全SHA。
 */
std::wstring generation( const Object &input)
{
	return sha( "schema-v2\n" + winrt::to_string( str( input, L"day")) + "\n" +
			   winrt::to_string( str( input, L"manifestSha256")) + "\n" +
			   winrt::to_string( str( input, L"artifact")) + "\n") ;
}

/** @brief 元jobの一つだけの応答slotを作ります。
 * @param[in] generationKey 固定generation。
 * @param[in] job 元job。
 * @return 完全SHA。
 */
std::wstring operation( const std::wstring_view generationKey, const std::wstring_view job)
{
	return sha( "response-v2\n" + winrt::to_string( generationKey) + "\n" + winrt::to_string( job) +
			   "\n") ;
}

/** @brief Inputと同順の初期job状態を作ります。
 * @param[in] key 固定generation。
 * @param[in] manifest 元共有job。
 * @param[in] projected 新形式の初期stateを作る場合true。
 * @return Canonical state。
 */
Object initialJobs( const std::wstring_view key, const CollectorCampaignManifest &manifest,
				   const bool projected = false)
{
	const auto result = make( projected ? L"collector-campaign-state-v3"
									   : L"collector-campaign-state-v2") ;	// 最大300job。
	put( result, L"generation", key) ;
	Array rows ;	// 固定job順の保存行。
	// 未予約だけを初期化し、既存状態をここへ戻さない。
	for( const auto &job : manifest.jobs) {
		Object row ;	// 一つのjob状態。
		put( row, L"job", job.key) ;
		put( row, L"state", L"PENDING") ;
		put( row, L"started", 0ULL) ;
		put( row, L"response", L"") ;
		put( row, L"operation", L"") ;
		put( row, L"reason", L"") ;
		// 新世代では未予約をnull intentで明示する。
		if( projected) {
			row.Insert( L"intent", Value::CreateNullValue()) ;
		}

		rows.Append( row) ;
	}

	result.Insert( L"jobs", rows) ;
	return result ;
}

/** @brief Stateの有限値と元job順を照合します。
 * @param[in] state 検査するstate。
 * @param[in] key 元generation。
 * @param[in] manifest 元共有job。
 * @param[in] projected 新形式の予約と中断stateを検査する場合true。
 * @param[in] allowV4 新世代のv4保存／回復または登録履歴検査の場合true。
 */
void validateJobs( const Object &state, const std::wstring_view key,
				  const CollectorCampaignManifest &manifest, const bool projected = false,
				  const bool allowV4 = false)
{
	fields( state, {L"schema", L"generation", L"jobs"}) ;
	require( str( state, L"schema") ==
				(projected ? L"collector-campaign-state-v3" : L"collector-campaign-state-v2") &&
			str( state, L"generation") == key) ;
	const auto rows = state.GetNamedArray( L"jobs") ;	// 元順序を固定する。
	require( rows.Size() == manifest.jobs.size()) ;
	// 未知terminalや欠損responseを拒否する。
	for( std::uint32_t index = 0; index < rows.Size(); ++index) {
		const auto row = rows.GetObjectAt( index) ;	// 元jobへの保存結果。
		// 新形式のintentを旧stateへ混入させない。
		if( projected) {
			fields( row,
				   {L"job", L"state", L"started", L"response", L"operation", L"reason", L"intent"}) ;
		} else {
			fields( row, {L"job", L"state", L"started", L"response", L"operation", L"reason"}) ;
		}

		const auto stateName = str( row, L"state") ;	// 固定enum文字列。
		// V4専用codecと四role回復が対応する有限終端だけを許します。
		const bool v4Terminal = projected && allowV4 &&
								(stateName == L"FETCHED" || stateName == L"FAILED" ||
								 // 専用保存／読取りの有限終端。
								 stateName == L"HELD") ;
		require( !projected || stateName == L"PENDING" || stateName == L"DEFERRED" ||
				stateName == L"RUNNING" || stateName == L"INTERRUPTED" || v4Terminal) ;
		// 新開始intentの内容照合は元inputを所有するStateで行う。
		if( projected) {
			const bool absent =
				row.GetNamedValue( L"intent").ValueType() ==
				winrt::Windows::Data::Json::JsonValueType::Null ;	// 予約前二窓だけ欠測可。
			require( stateName == L"INTERRUPTED" ||
					((stateName == L"RUNNING" || v4Terminal) ? !absent : absent)) ;
		}

		require( str( row, L"job") == manifest.jobs[index].key &&
				number( row, L"started") <= LAST_UTC) ;
		const bool terminal = v4Terminal || stateName == L"OBSERVED" || stateName == L"FAILED" ||
							  // 応答済み状態。
							  stateName == L"HELD" || stateName == L"INTERRUPTED" ;
		require( terminal || stateName == L"PENDING" || stateName == L"RUNNING" ||
				stateName == L"DEFERRED") ;
		require( terminal ? hash( str( row, L"response")) &&
							   str( row, L"operation") == operation( key, manifest.jobs[index].key)
						 : str( row, L"response").empty() && str( row, L"operation").empty()) ;
		require( (stateName == L"PENDING" || stateName == L"DEFERRED")
					? number( row, L"started") == 0U
					: number( row, L"started") >= 1000U) ;
		const auto reason = str( row, L"reason") ;	// 任意文字列を保存しない。
		require( stateName == L"DEFERRED" ? reason == L"DAY_CLOSED" || reason == L"INPUT_CHANGED" ||
											   reason == L"ARTIFACT_CHANGED"
										 : reason.empty()) ;
	}
}
} // namespace

/** @brief 固定error domainを保存名へ変換します。
 * @param[in] domain 元分類。
 * @return 固定名。未知値は拒否します。
 */
std::wstring_view ioDomainName( CollectorIoErrorDomain domain)
{
	// Domainを原数値の意味と同じ有限表現へ対応させる。
	switch( domain) {
		// 成功だけに使う。
		case CollectorIoErrorDomain::NONE:
			return L"NONE" ;
		// Win32 APIの原値。
		case CollectorIoErrorDomain::WIN32_ERROR:
			return L"WIN32" ;
		// Winsock APIの原値。
		case CollectorIoErrorDomain::WINSOCK_ERROR:
			return L"WINSOCK" ;
		// HRESULTの原bit pattern。
		case CollectorIoErrorDomain::HRESULT_ERROR:
			return L"HRESULT" ;
		// HTTP status拒否。
		case CollectorIoErrorDomain::HTTP:
			return L"HTTP" ;
		// 固定parser拒否。
		case CollectorIoErrorDomain::PARSER:
			return L"PARSER" ;
	}

	require( false) ;
	return L"" ;
}
/** @brief 保存domainを未知値へ丸めず復号します。
 * @param[in] name 固定保存名。
 * @return 元分類。
 */
CollectorIoErrorDomain ioDomain( std::wstring_view name)
{
	// 保存可能な固定enumだけを探索し、未知名を成功へしない。
	for( unsigned value = 0U; value <= static_cast<unsigned>( CollectorIoErrorDomain::PARSER);
		++value) {
		const auto domain = static_cast<CollectorIoErrorDomain>( value) ;	// 有限ordinal。
		// 完全一致だけを復号する。
		if( ioDomainName( domain) == name) {
			return domain ;
		}
	}

	require( false) ;
	return CollectorIoErrorDomain::NONE ;
}
/** @brief 同じ三期限の式を予約と回収で共有します。
 * @param[in] started 秒境界の元予約UTC。
 * @param[in] first 当日の最初の予約秒。未予約0。
 * @param[in] batchFirst 同batchの最初の予約秒。未予約0。
 * @return 元予約から延長しない最小UTC。
 */
std::uint64_t reservationDeadline( std::uint64_t started, std::uint64_t first,
								  std::uint64_t batchFirst)
{
	return std::min( {started + 120000U, (first == 0U ? started : first * 1000U) + 14400000U,
					 (batchFirst == 0U ? started : batchFirst * 1000U) + 3600000U}) ;
}

/** @see local_collector_recovery.h */
DWORD checkCollectorRecoveryCapacity( const CollectorStoreUsage &usage,
									 const std::size_t			jobCount) noexcept
{
	// Manifestの上限を越える入力から容量を計算しない。
	if( jobCount > 300U) {
		return ERROR_INVALID_PARAMETER ;
	}

	// 応答・六前後像と固定保存物・atomic一時枠。
	const auto extra = jobCount * 7U + 8U ;
	// 既存byteと加算してoverflowさせず、残容量と比較する。
	const auto extraBytes = static_cast<std::uint64_t>( extra) * 2U * 1024U * 1024U ;
	// Entryとbyteを独立に満たす場合だけ許可する。
	if( usage.runEntries > 4096U - extra || usage.currentEntries > 4096U - 8U ||
	   usage.bytes > 5ULL * 1024U * 1024U * 1024U - extraBytes) {
		return ERROR_TOO_MANY_NAMES ;
	}

	return ERROR_SUCCESS ;
}

/** @see local_collector_recovery.h */
DWORD checkCollectorProjectedRecoveryCapacity( const CollectorStoreUsage &usage,
											  const std::size_t			 jobCount,
											  const std::size_t			 requestCount) noexcept
{
	// 乗算前に全入力を有限にする。
	if( jobCount > 300U || requestCount > jobCount) {
		return ERROR_INVALID_PARAMETER ;
	}

	const auto extraRuns	= 9U * jobCount + 13U ;	// Atomic一枠も含む。
	const auto extraCurrent = requestCount + 13U ;	// CACHEと固定file。
	const auto extraBytes	= 7ULL * jobCount * 2U * 1024U * 1024U +
							(2ULL * jobCount + requestCount) * 64U * 1024U +
							50ULL * 1024U * 1024U ;	// ADR第8節。
	// 差分比較により既存使用量のoverflowを避ける。
	if( usage.runEntries > 4096U - extraRuns || usage.currentEntries > 4096U - extraCurrent ||
	   usage.bytes > 5ULL * 1024U * 1024U * 1024U - extraBytes) {
		return ERROR_TOO_MANY_NAMES ;
	}

	return ERROR_SUCCESS ;
}

/** @see local_collector_recovery.h */
DWORD checkCollectorProjectedCompletionCapacity( const CollectorStoreUsage &usage,
												const std::size_t		   jobCount,
												const std::size_t		   requestCount) noexcept
{
	// 不正な入力の分類を使用量によって変えません。
	if( jobCount > 300U || requestCount > jobCount) {
		return ERROR_INVALID_PARAMETER ;
	}

	// 追加枠は差分比較し、使用量の加算overflowを避けます。
	if( usage.runEntries > 4096U - 3U || usage.currentEntries > 4096U - 2U ||
	   usage.bytes > 5ULL * 1024U * 1024U * 1024U - 10ULL * 1024U * 1024U) {
		return ERROR_TOO_MANY_NAMES ;
	}

	auto charged = usage ;	// 完了三run・pointerとatomic一枠を保守的に先払いします。
	charged.runEntries += 3U ;
	charged.currentEntries += 2U ;
	charged.bytes += 10ULL * 1024U * 1024U ;
	return checkCollectorProjectedRecoveryCapacity( charged, jobCount, requestCount) ;
}

/** @brief Storeと固定更新の単独所有状態です。 */
struct LocalCollectorRecovery::State {
	/** @brief 初回の登録／CACHE不在を検査した監督内だけの値です。成功履歴の型ではありません。 */
	struct InitialProjectedHistory {
		/// 所有rootの内部key。
		std::wstring root ;
		/// 元generation。
		std::wstring generation ;
		/// 元入力の実hash。
		std::wstring input ;
		/// 元request。
		std::wstring request ;
		/// 元cache binding。
		std::wstring binding ;
		/// 元job scope。
		std::wstring scope ;
		/** @brief 元identityの全field一致を確認します。
		 * @param[in] other 再検査した値。
		 * @return 全field一致の場合true。
		 */
		bool		 operator==( const InitialProjectedHistory &other) const = default ;
	} ;
	/// 同じGを持つ他監督やaddress再利用と区別するprocess内identity。
	std::shared_ptr<const std::byte>		   projectedOwner{std::make_shared<const std::byte>()} ;
	/// 初回prepareの失敗時に追加確保せずswapする固定理由。
	std::wstring							   projectedFailureReason{L"STATE_ERROR"} ;
	/// 借用した単一writer。
	LocalCollectorStateStore				  *store{} ;
	/// 全完了履歴の非変更再導出中だけ借用する有限reader。通常監督ではnullです。
	RegisteredHistoryReader					  *historyReader{} ;
	/// 初回の拒否code。
	DWORD									   error{} ;
	/// 非機密の固定拒否理由。
	std::wstring							   reason ;
	/// Rootの検証済み保存像。
	Object									   root{nullptr} ;
	/// Active generationの固定input。
	Object									   input{nullptr} ;
	/// Active generationのjob状態。
	Object									   jobs{nullptr} ;
	/// 未登録準備中の固定日次切替intent。
	Object									   pendingRoll{nullptr} ;
	/// 通常起動の全履歴再照合が完了した、元末尾完了intentと三生成物だけです。
	std::optional<std::array<std::string, 4U>> pendingFinish ;
	/// 元manifestの共有job。
	CollectorCampaignManifest				   manifest ;
	/// 元公開requestとcache結合。
	CollectorRecoveryInput					   definition ;
	/// 読込み中generationの保存version。旧2、新3だけを認めます。
	std::uint32_t							   storageVersion{2U} ;
	/// 専用入口を旧reserve／acceptから区別します。
	bool									   projectedRequested{} ;
	/// 完了prefixと精算済み行を含む未完了末尾を持つ次回世代。初回受領へ流用しません。
	bool									   nextProjected{} ;
	/// RUNNING再起動や入力変更では履歴受領接続まで新規dispatchを止めます。
	bool									   nextDispatchEnabled{} ;
	/// 保存sourceから権限を作らない現在の組み込みsource所有値。
	std::vector<CollectorCampaignSource>	   projectedSources ;
	/// Active generation。
	std::wstring							   key ;
	/// 回収時も別に検査する現在UTC。
	std::uint64_t							   now{} ;
	/// 初期化時の単調時計。
	std::uint64_t							   initialSteady{} ;
	/// 同一process内で後退を拒否する最新単調時刻。
	std::uint64_t							   lastSteady{} ;
	/// 各groupの直近process内完了時刻。
	std::map<std::wstring, std::uint64_t>	   completedSteady ;
	/// 制御付き予約のprocess内正本。予約前に四枠を確保します。
	std::array<std::optional<CollectorRecoveryDispatch>, 4>					  controlledBindings ;
	/// 予約前に確保し、予約成立後だけ固定四枠へ保持する初回根拠。
	std::array<std::shared_ptr<const InitialProjectedHistory>, 4>			  projectedHistories ;
	/// 元dispatchと同じ四slotが予約前に確保する変更不能な登録履歴。
	std::array<std::shared_ptr<const CollectorRegisteredProjectedHistory>, 4> nextHistories ;
	/// Fixtureの有限保存後停止。
	std::function<bool( CollectorRecoveryCheckpoint)>						  stop ;

	/** @brief 共通検査の本文読取りを非変更時だけ有限readerへ経由させます。
	 * @param[in,out] source このStateと同じ保護store。
	 * @param[in] name 固定相対名。
	 * @return 検証済み本文または不在nullopt。通常側の読取り契約は変えません。
	 */
	std::optional<std::string> read( LocalCollectorStateStore	&source,
									const std::filesystem::path &name)
	{
		require( &source == store) ;
		return historyReader ? historyReader->body( name) : drivercrate::read( source, name) ;
	}

	/** @brief 共通検査の必須本文を同じ非変更読取り境界で取得します。
	 * @param[in,out] source このStateと同じ保護store。
	 * @param[in] name 固定相対名。
	 * @return 元本文。欠損は履歴なしへ変換せず拒否します。
	 */
	std::string required( LocalCollectorStateStore &source, const std::filesystem::path &name)
	{
		const auto value = read( source, name) ;	// 不在を含めて終了時照合へ固定します。
		require( value.has_value()) ;
		return *value ;
	}

	/** @brief 予約と非変更照会の候補選択を一箇所で行います。
	 * @param[in] budget 現在の日次予算。
	 * @param[in] controls 現在の恒久待機表。
	 * @param[in] utcMillis 検証済みUTC。
	 * @param[in] steadyMillis 検証済み単調時計。
	 * @return 固定順の候補、または有限待機分類。状態は変更しません。
	 */
	CollectorRecoveryReadiness selectJob( const CollectorBudgetSnapshot &budget,
										 const CollectorWaitSnapshot   &controls,
										 const std::uint64_t			utcMillis,
										 const std::uint64_t			steadyMillis) const
	{
		CollectorRecoveryReadiness result ;	// HTTP許可ではない選択結果。
		result.reason = L"WAIT_OR_TERMINAL" ;
		// 日跨ぎ後の新予約は元generationへ加えない。
		if( budget.day != day( utcMillis) || str( input, L"day") != day( utcMillis)) {
			result.reason = L"DAY_CLOSED" ;
			return result ;
		}

		std::size_t			   active{} ;		// 未閉鎖予約の総数。
		std::uint64_t		   charged{} ;		// 日次の先払いを含む共通消費。
		std::uint64_t		   first{} ;		// 当日の最初の予約UTC秒。
		std::set<std::wstring> activeGroups ;	// 同group並行送信を禁止する。
		// 全契約を同じ予算枠として数える。
		for( const auto &row : budget.reservations) {
			charged += row.charged ;
			first = first == 0U ? row.started : std::min( first, row.started) ;
			// 終端予約はslotを占有しない。
			if( row.phase == 0U) {
				++active ;
				activeGroups.insert( row.group) ;
			}
		}

		// 満杯slotは回収通知を待つ。数値APIの旧理由は維持する。
		if( active >= 4U) {
			result.kind	  = CollectorRecoveryReadinessKind::ACTIVE_WAIT ;
			result.reason = L"BUDGET_WAIT" ;
			return result ;
		}

		const auto	  rows = jobs.GetNamedArray( L"jobs") ;	// 元順序の保存状態。
		bool		  pending{} ;							// 全job終端と長期延期を区別する。
		std::uint64_t shortestWait{} ;						// 進めるjobの最短2秒間隔。
		// 固定順で最初の実行可能jobを探す。未対応条件で分母を削らない。
		for( std::size_t index = 0; index < manifest.jobs.size(); ++index) {
			const auto row = rows.GetObjectAt( static_cast<std::uint32_t>( index)) ;	// 保存済みjob。
			// 予約済みjobの再送を選択しない。
			if( str( row, L"state") != L"PENDING") {
				continue ;
			}

			pending = true ;
			// 回数と経過時間の枠は応答精算で増えない。
			if( budget.reservations.size() >= 1200U ||
			   (first != 0U && utcMillis / 1000U >= first + 14400U)) {
				result.reason = L"BUDGET_WAIT" ;
				return result ;
			}

			const auto &job		= manifest.jobs[index] ;			// 元入力の有限上限。
			const auto &request = definition.requestKeys[index] ;	// Artifact独立の恒久key。
			// 同group枠と日次本文枠を先に確認する。
			if( activeGroups.contains( job.source.rateLimitGroup) ||
			   charged + job.source.maximumResponseBytes > 1024ULL * 1024U * 1024U) {
				continue ;
			}

			bool blocked{} ;	// 長期延期または未回収の開始intent。
			// Groupとrequestの両方の待機を満たす必要がある。
			for( const auto &controlKey : {L"g-" + job.source.rateLimitGroup, L"r-" + request}) {
				const auto found = controls.controls.find( controlKey) ;	// 未登録は待機なし。
				// 復旧や要確認を短時間waitとして反復しない。
				if( found != controls.controls.end() &&
				   (found->second.review || found->second.notBefore > utcMillis ||
					found->second.started != 0U)) {
					blocked = true ;
				}
			}

			// 一方でも保留なら当jobを選択しない。
			if( blocked) {
				continue ;
			}

			const auto batch =
				*std::min_element( job.targetIndices.begin(), job.targetIndices.end()) /
				32U ;						// 固定batch。
			std::uint64_t batchBytes{} ;	// 当generation・同batchの先払い込みbyte。
			std::uint64_t batchFirst{} ;	// 同batchの最初のUTC秒。
			// 元jobと同じbatchだけを合算する。
			for( const auto &reservation : budget.reservations) {
				// 別generationは日次枠だけで既に合算済み。
				if( reservation.campaign != key) {
					continue ;
				}

				const auto found =
					std::find_if( manifest.jobs.begin(), manifest.jobs.end(), [&]( const auto &item) {
						return item.key == reservation.job ;
					}) ; // 元job照合。
				require( found != manifest.jobs.end()) ;
				// 最小対象indexが同じbatchへ属するものだけを数える。
				if( *std::min_element( found->targetIndices.begin(), found->targetIndices.end()) /
					   32U ==
				   batch) {
					batchBytes += reservation.charged ;
					batchFirst = batchFirst == 0U ? reservation.started
												  : std::min( batchFirst, reservation.started) ;
				}
			}

			// Batchのbyte・経過枠を超えるjobは短期待機では進めない。
			if( batchBytes + job.source.maximumResponseBytes > 256ULL * 1024U * 1024U ||
			   (batchFirst != 0U && utcMillis / 1000U >= batchFirst + 3600U)) {
				continue ;
			}

			const auto group =
				// UTC完了時刻。
				controls.controls.find( L"g-" + job.source.rateLimitGroup) ;
			const auto steady =
				// Process内完了時刻。
				completedSteady.find( job.source.rateLimitGroup) ;
			const auto baseline =
				// 再開時も待つ。
				steady == completedSteady.end() ? initialSteady : steady->second ;
			std::uint64_t interval{} ;	// 二clockの大きい残待機。
			// 完了観測があるgroupだけに二秒間隔を適用する。
			if( group != controls.controls.end() && group->second.completed != 0U) {
				require( utcMillis >= group->second.completed && steadyMillis >= baseline) ;
				const auto utcElapsed = utcMillis - group->second.completed ;	// overflowしない差分。
				const auto steadyElapsed = steadyMillis - baseline ;			// 単調時計側の差分。
				interval				 = std::max( utcElapsed < 2000U ? 2000U - utcElapsed : 0U,
									steadyElapsed < 2000U ? 2000U - steadyElapsed : 0U) ;
			}

			// 実行可能になる最短間隔を通知待ちへ返す。
			if( interval != 0U) {
				shortestWait = shortestWait == 0U ? interval : std::min( shortestWait, interval) ;
				continue ;
			}

			const auto started		 = utcMillis / 1000U * 1000U ;	// 秒予約から延長しない。
			result.deadlineUtcMillis = reservationDeadline( started, first, batchFirst) ;
			require( result.deadlineUtcMillis > utcMillis && result.deadlineUtcMillis <= LAST_UTC) ;
			require( steadyMillis <= std::numeric_limits<std::uint64_t>::max() -
										(result.deadlineUtcMillis - utcMillis)) ;
			result.kind		= CollectorRecoveryReadinessKind::READY ;
			result.jobIndex = index ;
			result.reason.clear() ;
			return result ;
		}

		// Clock待ちがあればworker通知と同時に有限時間でも起床できる。
		if( shortestWait != 0U) {
			result.kind		  = CollectorRecoveryReadinessKind::INTERVAL_WAIT ;
			result.waitMillis = shortestWait ;
		}
		// 残る実行中jobを回収するまで全体終了としない。
		else if( active != 0U) {
			result.kind = CollectorRecoveryReadinessKind::ACTIVE_WAIT ;
		}
		// PENDINGも実行中もない場合だけjob終端とする。
		else if( !pending) {
			result.kind = CollectorRecoveryReadinessKind::TERMINAL ;
		}

		return result ;
	}

	/** @brief Fixtureで指定された保存窓だけを停止します。
	 * @param[in] checkpoint 保存済み段階。
	 */
	void checkpoint( const CollectorRecoveryCheckpoint checkpoint)
	{
		require( !stop || !stop( checkpoint), ERROR_OPERATION_ABORTED) ;
	}

	/** @brief 必須共有予算を非変更で読みます。
	 * @return 検証済みsnapshot。
	 */
	CollectorBudgetSnapshot budget()
	{
		CollectorBudgetSnapshot value ;	// Phaseを暗黙変更しない。
		require( required( *store, BUDGET_MARKER) == "collector-campaign-budget-root-v1") ;
		require( parseCollectorBudgetSnapshot( required( *store, BUDGET), value) &&
				value.lastUtc <= now / 1000U) ;
		return value ;
	}

	/** @brief 必須共有待機を非変更で読みます。
	 * @return 検証済みsnapshot。
	 */
	CollectorWaitSnapshot controls()
	{
		CollectorWaitSnapshot value ;	// 開始intentを消さない。
		require( required( *store, CONTROL_MARKER) == "collector-campaign-controls-root-v1") ;
		require( parseCollectorWaitSnapshot( required( *store, CONTROL), value) &&
				value.lastUtc <= now) ;
		return value ;
	}

	/** @brief Rootへ現在の監督時計を保存します。 */
	void saveRoot()
	{
		put( root, L"lastUtcMillis", std::max( number( root, L"lastUtcMillis"), now)) ;
		save( *store, ROOT, bytes( root)) ;
	}

	/** @brief 読込み中世代にだけ許されたstate名を返します。
	 * @return 固定versionと検証済みGからなる相対名。
	 */
	std::filesystem::path statePath() const
	{
		return path( storageVersion == 3U ? L"current/campaign-state-v3-"
										 : L"current/campaign-state-v2-",
					key) ;
	}

	/** @brief 元inputを世代別codecで復号して所有入力を確定します。
	 * @param[in] object canonical検査済み入力。
	 * @param[in] version 登録された保存version。
	 */
	void adoptInput( const Object &object, const std::uint32_t version)
	{
		require( version == 2U || version == 3U) ;
		storageVersion = version ;
		input		   = object ;
		// 旧Gとbindingの解釈は元codecへ任せる。
		if( version == 2U) {
			definition = decodeInput( input, manifest) ;
			key		   = generation( input) ;
			return ;
		}

		CollectorProjectedCampaignDefinition decoded ;	// 元公開manifestとregistry。
		CollectorProjectedCampaignIdentity	 identity ;	// 全jobを再構築した新G。
		require( parseCollectorProjectedCampaignIdentity( bytes( input), decoded, identity)) ;
		definition				  = {} ;
		definition.manifestBytes  = std::move( decoded.manifestBytes) ;
		definition.sources		  = std::move( decoded.sources) ;
		definition.artifactSha256 = std::move( decoded.artifactSha256) ;
		require(
			parseCollectorCampaignManifest( definition.manifestBytes, definition.sources, manifest)) ;
		// Workerへ渡す元bindingも保存された任意値からコピーしない。
		for( const auto &job : identity.jobs) {
			definition.requestKeys.push_back( job.requestKey) ;
			definition.cacheBindings.push_back( job.cacheBinding) ;
		}

		key = std::move( identity.generationKey) ;
	}

	/** @brief 専用markerへ入力実byteと必須応答versionを結合します。
	 * @param[in] inputHash 検証済みinputの実byte SHA-256。
	 * @return 固定fieldのcanonical marker。
	 */
	std::string projectedMarker( const std::wstring &inputHash) const
	{
		const auto marker = make( L"collector-campaign-generation-v3") ;	// 新世代専用。
		put( marker, L"profile", L"METADATA_PROJECTION_V1") ;
		put( marker, L"generation", key) ;
		put( marker, L"inputHash", inputHash) ;
		put( marker, L"responseVersion", 4ULL) ;
		return bytes( marker) ;
	}

	/** @brief 元generationの入力・marker・stateを同時に確認します。
	 * @param[in] generationKey 登録簿のhash。
	 * @param[in] inputHash 登録簿のinput hash。
	 * @param[in] version 登録簿が指定する2または3。
	 */
	void loadGeneration( const std::wstring &generationKey, const std::wstring &inputHash,
						const std::uint32_t version = 2U)
	{
		require( version == 2U || version == 3U) ;
		const auto savedInput = json( required(
			*store, path( version == 3U ? L"runs/campaign-input-v3-" : L"runs/campaign-input-v2-",
						 generationKey))) ;	// 世代別保存名。
		adoptInput( savedInput, version) ;
		require( key == generationKey && sha( bytes( input)) == inputHash &&
				str( input, L"day") <= day( now)) ;
		// 新markerは旧文字列markerへ変換せず全byteで照合する。
		if( version == 3U) {
			require( required( *store, path( L"runs/campaign-marker-v3-", key)) ==
					projectedMarker( inputHash)) ;
		} else {
			require( required( *store, path( L"runs/campaign-marker-v2-", key)) ==
					"collector-campaign-generation-v2\n" + winrt::to_string( key) + "\n" +
						winrt::to_string( inputHash)) ;
		}

		jobs = json( required( *store, statePath())) ;
		validateJobs( jobs, key, manifest, version == 3U, version == 3U) ;
		validateIntents( jobs) ;
	}

	/** @brief 元inputから全開始intentを再構築してstateへ結合します。
	 * @param[in] state 検査する保存state。
	 */
	void validateIntents( const Object &state)
	{
		// 旧stateの受理条件は変更しない。
		if( storageVersion != 3U) {
			return ;
		}

		CollectorProjectedCampaignDefinition source ;	// 元保存定義。
		CollectorProjectedCampaignIdentity	 identity ;	// 再構築scope。
		require( parseCollectorProjectedCampaignIdentity( bytes( input), source, identity)) ;
		const auto rows = state.GetNamedArray( L"jobs") ;	// 固定順。
		// 非nullの開始intentは再起動時計ではなく元二時計のまま照合する。
		for( std::uint32_t index = 0U; index < rows.Size(); ++index) {
			const auto row = rows.GetObjectAt( index) ;	// 元job。
			// 早期予約窓はintentを推測で生成しない。
			if( row.GetNamedValue( L"intent").ValueType() ==
			   winrt::Windows::Data::Json::JsonValueType::Null) {
				continue ;
			}

			CollectorRecoveryDispatch dispatch ;	// 送信権を持たない再照合値。
			require( parseCollectorProjectedStart( identity, bytes( row.GetNamedObject( L"intent")),
												 dispatch) &&
					dispatch.jobIndex == index &&
					dispatch.startedUtcMillis == number( row, L"started")) ;
		}
	}

	/** @brief 本文から共通予算を再符号化します。
	 * @param[in] value 型付き予算。
	 * @return 検証済みcanonical本文。
	 */
	std::string budgetBytes( const CollectorBudgetSnapshot &value)
	{
		std::string body ; /* 共通codecを再利用する。 */
		require( encodeCollectorBudgetSnapshot( value, body)) ;
		return body ;
	}

	/** @brief 共通待機を再符号化します。
	 * @param[in] value 型付き待機。
	 * @return 検証済みcanonical本文。
	 */
	std::string controlBytes( const CollectorWaitSnapshot &value)
	{
		// 初回旧待機統合も予約時と同じ容量区分で停止する。
		const auto groups =
			std::count_if( value.controls.begin(), value.controls.end(),
						  []( const auto &entry) { return entry.second.request.empty() ; }) ;
		require( groups <= 20 && value.controls.size() - static_cast<std::size_t>( groups) <= 300U,
				ERROR_TOO_MANY_NAMES) ;
		std::string body ; /* 共通codecを再利用する。 */
		require( encodeCollectorWaitSnapshot( value, body)) ;
		return body ;
	}

	/** @brief 元予約に結合した応答を固定表現にします。
	 * @param[in] index 元job index。
	 * @param[in] response 元応答。
	 * @param[in] started 元予約の開始。
	 * @param[in] interrupted 応答欠損を初めて回収する場合true。
	 * @param[in] observed 新modeだけの確定観測。旧v2はnullです。
	 * @return 非機密の固定応答intent。
	 */
	Object responseObject( const std::size_t index, const CollectorRecoveryResponse &response,
						  const std::uint64_t started, const bool interrupted,
						  const CollectorIoSnapshot *observed = nullptr)
	{
		require( index < manifest.jobs.size()) ;
		const auto &job = manifest.jobs[index] ;	// 元予約に結合した固定job。
		require( started >= 1000U && started <= response.finishedUtcMillis &&
				response.finishedUtcMillis <= response.acceptedUtcMillis &&
				response.acceptedUtcMillis <= now) ;
		require( response.receivedBytes <= job.source.maximumResponseBytes &&
				(response.bytesKnown || response.receivedBytes == 0U)) ;
		require( response.status == 0U || (response.status >= 100U && response.status <= 599U)) ;
		require( !response.sentRequests || *response.sentRequests <= 1U) ;
		require( response.status == 0U || response.sentRequests == 1U) ;
		require( response.retryAfterUtcMillis <= 253402300799999ULL) ;
		require( response.errorDomain == L"NONE" || response.errorDomain == L"WIN32" ||
				response.errorDomain == L"HTTP" || response.errorDomain == L"PARSER" ||
				(observed &&
				 (response.errorDomain == L"WINSOCK" || response.errorDomain == L"HRESULT"))) ;
		require( response.bodySha256.empty() || hash( response.bodySha256)) ;
		require( response.projectionSha256.empty() || hash( response.projectionSha256)) ;
		require( response.state == CollectorCampaignJobState::OBSERVED ||
				response.state == CollectorCampaignJobState::FAILED ||
				response.state == CollectorCampaignJobState::HELD) ;
		const bool success =
			// 品質適合ではなくmetadata結果。
			response.state == CollectorCampaignJobState::OBSERVED ;
		require( !success || ((response.status == 200U || response.status == 304U) &&
							 response.error == 0U && response.errorDomain == L"NONE" &&
							 !response.needsReview && !response.challenge && response.bytesKnown &&
							 hash( response.bodySha256) && hash( response.projectionSha256))) ;
		require( !interrupted ||
				(!response.sentRequests && !response.bytesKnown && response.status == 0U &&
				 response.error == 0U && response.errorDomain == L"NONE" && !response.needsReview &&
				 !response.challenge && response.retryAfterUtcMillis == 0U &&
				 response.bodySha256.empty() && response.projectionSha256.empty())) ;
		const auto result =
			make( observed ? L"collector-campaign-response-v3"
						  : L"collector-campaign-response-v2") ;	// 元入力と時刻を固定する。
		put( result, L"generation", key) ;
		put( result, L"job", job.key) ;
		put( result, L"source", job.source.sourceId) ;
		put( result, L"request", definition.requestKeys[index]) ;
		put( result, L"cache", definition.cacheBindings[index]) ;
		put( result, L"day", str( input, L"day")) ;
		put( result, L"maximum", job.source.maximumResponseBytes) ;
		put( result, L"started", started) ;
		put( result, L"finished", response.finishedUtcMillis) ;
		put( result, L"accepted", response.acceptedUtcMillis) ;
		put( result, L"state",
			interrupted											? L"INTERRUPTED"
			: success											? L"OBSERVED"
			: response.state == CollectorCampaignJobState::HELD ? L"HELD"
																: L"FAILED") ;
		result.Insert( L"bytes",
					  response.bytesKnown
						  ? Value::CreateNumberValue( static_cast<double>( response.receivedBytes))
						  : Value::CreateNullValue()) ;
		result.Insert( L"sends", response.sentRequests
									? Value::CreateNumberValue( *response.sentRequests)
									: Value::CreateNullValue()) ;
		put( result, L"status", response.status) ;
		put( result, L"error", response.error) ;
		put( result, L"errorDomain", response.errorDomain) ;
		put( result, L"retryAfter", response.retryAfterUtcMillis) ;
		result.Insert( L"review", Value::CreateBooleanValue( response.needsReview)) ;
		result.Insert( L"challenge", Value::CreateBooleanValue( response.challenge)) ;
		put( result, L"body", response.bodySha256) ;
		put( result, L"projection", response.projectionSha256) ;
		// 新観測を落とした応答を同じ成功判定へ渡さない。
		if( observed) {
			require( !interrupted && observed->sealed && observed->elapsedMillis &&
					observed->finishedUtcMillis == response.finishedUtcMillis) ;
			require( observed->cause != CollectorIoCause::NONE &&
					observed->cause != CollectorIoCause::CLOCK) ;
			require( response.sentRequests && *response.sentRequests == observed->sends &&
					observed->sends <= 1U) ;
			require( observed->bytesKnown == response.bytesKnown &&
					observed->lowerBytes <= job.source.maximumResponseBytes) ;
			require( !observed->bytesKnown || observed->lowerBytes == response.receivedBytes) ;
			require( observed->sends != 0U || (response.status == 0U && observed->lowerBytes == 0U)) ;
			require( !observed->headerUtcMillis ||
					(observed->sends == 1U && *observed->headerUtcMillis >= started &&
					 *observed->headerUtcMillis <= response.finishedUtcMillis)) ;
			require( ioDomainName( observed->error.domain) == response.errorDomain &&
					observed->error.code == response.error &&
					observed->error.stage == observed->stage) ;
			require( observed->deadlineUtcMillis > started &&
					observed->deadlineUtcMillis <= started + 120000U) ;
			require( !success || observed->cause == CollectorIoCause::COMPLETE) ;
			// 正常終了は期限・原error・native回収がすべて成立した場合だけ。
			if( observed->cause == CollectorIoCause::COMPLETE) {
				require( observed->nativeReleased && !observed->native && observed->bytesKnown &&
						(response.status == 200U || response.status == 304U) &&
						(response.status != 304U || observed->lowerBytes == 0U) &&
						response.error == 0U && response.errorDomain == L"NONE" &&
						observed->stage == CollectorIoStage::COMPLETE && observed->sends == 1U &&
						response.finishedUtcMillis < observed->deadlineUtcMillis) ;
			} else {
				require( !success && response.errorDomain != L"NONE") ;
			}

			// 外部停止の受理を欠測へ変換しない。
			if( observed->cause == CollectorIoCause::CANCELLED ||
			   observed->cause == CollectorIoCause::SHARED_STOP) {
				require( observed->stopElapsedMillis.has_value()) ;
			}

			std::string ioBody ;	// 固定4 KiB codec。
			require( encodeCollectorHttpObservation( *observed, operation( key, job.key), ioBody)) ;
			result.Insert( L"io", json( ioBody)) ;
		}

		return result ;
	}

	/** @brief 保存応答の型・元入力・時刻を再計算して検査します。
	 * @param[in] index 元job index。
	 * @param[in] object 保存応答。
	 * @param[out] observed 同期呼出し中だけ借用する任意出力。省略またはnullptrなら書き込まない。
	 *                     全検査成功後にv3の復号観測、v2なら既定構築したsnapshotを代入する。
	 * @return 元の型付き観測。
	 * @note 検査拒否や復号中の例外は伝播し、observedの参照先を更新しない。
	 */
	CollectorRecoveryResponse decodeResponse( const std::size_t index, const Object &object,
											 CollectorIoSnapshot *observed = nullptr)
	{
		CollectorRecoveryResponse result ;							// 任意fieldを再出力へ引き継がない。
		const auto				  state = str( object, L"state") ;	// 固定結果。
		result.state					= state == L"OBSERVED" ? CollectorCampaignJobState::OBSERVED
										  : state == L"HELD"   ? CollectorCampaignJobState::HELD
															   : CollectorCampaignJobState::FAILED ;
		require( state == L"OBSERVED" || state == L"HELD" || state == L"FAILED" ||
				state == L"INTERRUPTED") ;
		result.finishedUtcMillis = number( object, L"finished") ;
		result.acceptedUtcMillis = number( object, L"accepted") ;
		result.bytesKnown		 = object.GetNamedValue( L"bytes").ValueType() !=
							winrt::Windows::Data::Json::JsonValueType::Null ;
		// 未知を数値0へ変換しない。
		if( result.bytesKnown) {
			result.receivedBytes = number( object, L"bytes") ;
		}

		// 実送信の欠測は予約数から推定しない。
		if( object.GetNamedValue( L"sends").ValueType() !=
		   winrt::Windows::Data::Json::JsonValueType::Null) {
			require( number( object, L"sends") <= 1U) ;
			result.sentRequests = static_cast<std::uint32_t>( number( object, L"sends")) ;
		}

		require( number( object, L"status") <= 599U && number( object, L"error") <= MAXDWORD) ;
		result.status			   = static_cast<std::uint32_t>( number( object, L"status")) ;
		result.error			   = static_cast<std::uint32_t>( number( object, L"error")) ;
		result.errorDomain		   = str( object, L"errorDomain") ;
		result.retryAfterUtcMillis = number( object, L"retryAfter") ;
		result.needsReview		   = object.GetNamedBoolean( L"review") ;
		result.challenge		   = object.GetNamedBoolean( L"challenge") ;
		result.bodySha256		   = str( object, L"body") ;
		result.projectionSha256	   = str( object, L"projection") ;

		const auto schema = str( object, L"schema") ;	// 保存名との照合は読込み入口でも行う。
		require( schema == L"collector-campaign-response-v2" ||
				schema == L"collector-campaign-response-v3") ;
		CollectorIoSnapshot decoded ;	// 外側応答を元観測へ再結合する。
		const bool			controlled =
			// 新fieldの寛容化を防ぐ。
			schema == L"collector-campaign-response-v3" ;
		// 新versionだけに固定I/O codecを使う。
		if( controlled) {
			require( result.sentRequests && decodeCollectorHttpObservation(
											   bytes( object.GetNamedObject( L"io")),
											   operation( key, manifest.jobs[index].key), decoded)) ;
			decoded.sends			  = *result.sentRequests ;
			decoded.bytesKnown		  = result.bytesKnown ;
			decoded.finishedUtcMillis = result.finishedUtcMillis ;
			decoded.error			  = {ioDomain( result.errorDomain), result.error, decoded.stage} ;
		}

		require( bytes( responseObject( index, result, number( object, L"started"),
									 state == L"INTERRUPTED", controlled ? &decoded : nullptr)) ==
				bytes( object)) ;
		// 呼出し側が必要な場合だけ確定観測を返す。
		if( observed) {
			*observed = decoded ;
		}

		return result ;
	}

	/** @brief 固定roleから更新先を導出します。
	 * @param[in] commit 検証対象commit。
	 * @param[in] role 有限role。
	 * @return 組み込み相対名。
	 */
	std::filesystem::path destination( const Object &commit, const std::wstring &role)
	{
		// 任意pathをjournalから受け付けない。
		if( role == L"CONTROL") {
			return CONTROL ;
		}

		// 予算roleは共有budget一件に限定する。
		if( role == L"BUDGET") {
			return BUDGET ;
		}

		// Job roleは元generationのstateだけに限定する。
		if( role == L"JOB") {
			return path( str( commit, L"kind") == L"PROJECTED_RESPONSE_V1"
							? L"current/campaign-state-v3-"
							: L"current/campaign-state-v2-",
						str( commit, L"generation")) ;
		}

		// CACHE名は元jobの登録requestからだけ導出する。
		if( role == L"CACHE") {
			require( str( commit, L"kind") == L"PROJECTED_RESPONSE_V1" && storageVersion == 3U) ;
			const auto found =
				std::find_if( manifest.jobs.begin(), manifest.jobs.end(), [&]( const auto &job) {
					return job.key == str( commit, L"job") ;
				}) ; // 元job。
			require( found != manifest.jobs.end()) ;
			return path( L"current/campaign-cache-v1-",
						definition.requestKeys[static_cast<std::size_t>(
							std::distance( manifest.jobs.begin(), found))]) ;
		}

		require( role == L"ARCHIVE" && str( commit, L"oldDay").size() == 8U) ;
		return L"runs/campaign-budget-" + str( commit, L"oldDay") + L".json" ;
	}

	/** @brief 更新前後像の固定名を作ります。
	 * @param[in] operationKey 元操作hash。
	 * @param[in] role 有限role。
	 * @param[in] before 更新前像ならtrue。
	 * @param[in] projected 新四roleのeffect v2ならtrue。
	 * @return 組み込み相対名。
	 */
	std::filesystem::path effectPath( const std::wstring &operationKey, const std::wstring &role,
									 const bool before, const bool projected = false)
	{
		require( hash( operationKey) && (role == L"CONTROL" || role == L"JOB" || role == L"BUDGET" ||
									   (projected ? role == L"CACHE" : role == L"ARCHIVE"))) ;
		auto suffix = role ;	// Storeの小文字ASCII名契約を維持する。
		std::transform( suffix.begin(), suffix.end(), suffix.begin(),
					   []( wchar_t c) { return static_cast<wchar_t>( c + (L'a' - L'A')) ; }) ;
		return std::wstring( projected ? L"runs/campaign-effect-v2-" : L"runs/campaign-effect-v1-") +
			   operationKey + (before ? L"-before-" : L"-") + suffix + L".json" ;
	}

	/** @brief 三versionの候補を読み、併存・世代別schemaを拒否します。
     * @param[in] operationKey 元G／jobの操作key。
     * @return 存在する一件の元本文。両欠損はnullopt。
     */
	std::optional<std::string> storedResponse( const std::wstring &operationKey)
	{
		const auto old =
			// 旧専用名。
			read( *store, path( L"runs/campaign-response-v2-", operationKey)) ;
		const auto current =
			// 新専用名。
			read( *store, path( L"runs/campaign-response-v3-", operationKey)) ;
		const auto projected =
			// 元v4の本文byte。
			read( *store, path( L"runs/campaign-response-v4-", operationKey)) ;
		require( static_cast<unsigned>( old.has_value()) +
					static_cast<unsigned>( current.has_value()) +
					static_cast<unsigned>( projected.has_value()) <=
				1U) ;
		// 保存名とschemaが異なる本文を受理しない。
		if( old) {
			require( str( json( *old), L"schema") == L"collector-campaign-response-v2") ;
		}

		// 新versionも自動変換せず元schemaを要求する。
		if( current) {
			require( str( json( *current), L"schema") == L"collector-campaign-response-v3") ;
		}

		// 新世代の実観測はv4だけ。旧v2は欠測INTERRUPTEDを維持します。
		if( storageVersion == 3U) {
			require( !current && (!old || str( json( *old), L"state") == L"INTERRUPTED")) ;
		} else {
			require( !projected) ;
		}

		// V4は元envelopeを専用codecで検査し、旧canonical再符号化を行いません。
		if( projected) {
			const auto found =
				std::find_if( manifest.jobs.begin(), manifest.jobs.end(), [&]( const auto &job) {
					return operation( key, job.key) == operationKey ;
				}) ; // 固定job。
			require( found != manifest.jobs.end()) ;
			(void)decodeSavedProjected(
				static_cast<std::size_t>( std::distance( manifest.jobs.begin(), found)), *projected) ;
			return projected ;
		}

		return current ? current : old ;
	}

	/** @brief 新世代の元v4 envelopeを元入力scopeへ独立照合します。
	 * @param[in] index 元jobの有限index。
	 * @param[in] body 外側hash検査済みの原response byte。
	 * @return 元byteを所有する専用codec結果。304成功は拒否します。
	 */
	CollectorProjectedResponseBytes decodeSavedProjected( const std::size_t	index,
														 const std::string &body)
	{
		require( storageVersion == 3U && index < manifest.jobs.size()) ;
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
				   campaign ;					// 保存入力からの照合専用。
		const auto inputBody = bytes( input) ;	// 元入力byte。
		require( prepareCollectorProjectedCampaign( inputBody, sha( inputBody), key,
												  definition.artifactSha256, definition.sources,
												  campaign) &&
				campaign && campaign->job( index)) ;
		std::string raw ;		// Stringifyを通さない元envelope。
		bool		found{} ;	// 欠損を空応答へ補完しません。
		const auto	name = path( L"runs/campaign-response-v4-",
								// 元raw専用名。
								operation( key, manifest.jobs[index].key)) ;
		// 非変更inventoryの専用v4 decodeも累積読取り／終了時照合から除外しません。
		if( historyReader) {
			auto saved = historyReader->raw( name) ;	// 専用codecへ元envelopeを移します。
			found	   = saved.has_value() ;
			// 欠損時に空rawを成功値へしません。
			if( saved) {
				raw = std::move( *saved) ;
			}
		} else {
			io( store->read( name, raw, found)) ;
		}

		require( found) ;
		CollectorProjectedResponseBytes result ;	// 独立hash検査後だけ返します。
		projectedCodec(
			decodeCollectorProjectedResponse( campaign->job( index)->value(), raw, result).result) ;
		require( result.response == body && result.value.accepted <= now &&
				result.value.state != CollectorMetadataOutcome::REVALIDATED) ;
		return result ;
	}

	/** @brief 次回回復のv4またはcanonical v2欠測中断だけを独立検査します。
	 * @param[in] index 元jobの有限index。
	 * @param[in] body 保存済み応答の元byte。v4は再符号化しません。
	 * @return v4の独立decode、v2中断ならnullopt。未知形式は拒否します。
	 */
	std::optional<CollectorProjectedResponseBytes> decodeNextRecoveryResponse(
		const std::size_t index, const std::string &body)
	{
		const auto object = json( body) ;	// schema識別だけの所有値。
		// 元v4は既存の専用envelope検証を維持します。
		if( str( object, L"schema") == L"collector-campaign-response-v4") {
			return decodeSavedProjected( index, body) ;
		}

		require( storageVersion == 3U &&
				str( object, L"schema") == L"collector-campaign-response-v2" &&
				str( object, L"state") == L"INTERRUPTED" && bytes( object) == body) ;
		(void)decodeResponse( index, object) ;
		return std::nullopt ;
	}

	/** @brief 元応答と検査済み更新前値からCACHE本文を再導出します。
	 * @param[in] index 元job。
	 * @param[in] response 元response object。V4のhash対象には使いません。
	 * @param[in] projected 独立decode済みv4、旧中断ならnull。
	 * @param[in] before 検査済み元CACHE本文。初回／新requestだけnull。
	 * @return 専用codecのcanonical CACHE本文。
	 */
	std::string initialResponseCache( const std::size_t index, const Object &response,
									 const CollectorProjectedResponseBytes *projected,
									 const std::optional<std::string>	   &before = std::nullopt)
	{
		// 中断形は元codecと初回byteを維持し、次回だけ検査済み前像を渡します。
		if( !projected) {
			require( !before || root.GetNamedArray( L"generations").Size() > 1U) ;
			return interruptedCache( index, response, before) ;
		}

		CollectorProjectedCampaignDefinition decoded ;	// scopeを保存入力から再構築します。
		CollectorProjectedCampaignIdentity	 identity ;	// 元G／job。
		require( parseCollectorProjectedCampaignIdentity( bytes( input), decoded, identity) &&
				identity.generationKey == key && index < identity.jobs.size()) ;
		CollectorProjectedCache prior ;	// 元CACHEのcanonical全fieldを検査します。
		// 更新前値がある場合だけ同じ有限codecで解決します。
		if( before) {
			projectedCodec( decodeCollectorProjectedCache( *before, prior)) ;
		}

		CollectorProjectedCache cache ;	// 元応答と元CACHEだけから導出します。
		projectedCodec( deriveCollectorProjectedCache( identity.jobs[index], projected->envelope,
													 before ? &prior : nullptr, cache)) ;
		std::string result ;	// 元metadataに結合した有限CACHE。
		projectedCodec( encodeCollectorProjectedCache( cache, result)) ;
		return result ;
	}
	/** @brief 更新前予算から元三期限を再計算します。
     * @param[in] index 元job。
     * @param[in] started 元秒予約UTC。
     * @param[in] budget 更新前予算。後の予約で期限を延長しません。
     * @return 元期限。
     */
	std::uint64_t originalDeadline( std::size_t index, std::uint64_t started,
								   const CollectorBudgetSnapshot &budget)
	{
		const auto &job	  = manifest.jobs[index] ;	// 元対象のbatch。
		const auto	batch = *std::min_element( job.targetIndices.begin(), job.targetIndices.end()) /
						   32U ;		// 固定batch。
		std::uint64_t first{} ;			// 当日の元先頭予約。
		std::uint64_t batchFirst{} ;	// 同batchの元先頭予約。
		// 元予算内の有限予約だけから期限を再導出する。
		for( const auto &reservation : budget.reservations) {
			first = first == 0U ? reservation.started : std::min( first, reservation.started) ;
			// 他generationを同batchへ加えない。
			if( reservation.campaign != key) {
				continue ;
			}

			const auto found =
				std::find_if( manifest.jobs.begin(), manifest.jobs.end(), [&]( const auto &item) {
					return item.key == reservation.job ;
				}) ; // 元job。
			require( found != manifest.jobs.end()) ;
			// 同じ固定batchの先頭だけを採る。
			if( *std::min_element( found->targetIndices.begin(), found->targetIndices.end()) / 32U ==
			   batch) {
				batchFirst = batchFirst == 0U ? reservation.started
											  : std::min( batchFirst, reservation.started) ;
			}
		}

		return reservationDeadline( started, first, batchFirst) ;
	}

	/** @brief 元PENDINGと最後の予約を二種類の開始CONTROL prefixへ結合します。
	 * @param[in] index 元入力のjob index。
	 * @param[in] row 元PENDING行。開始intentは欠損のまま保持します。
	 * @param[in] budget 全検査対象と同じ元予算。
	 * @param[in] control 元CONTROL。旧待機または同じ開始済み値だけを認めます。
	 * @throws DWORD 不正行・非最終予約・最大量／group／時計／待機の不一致。
	 */
	void validatePartialProjectedStart( const std::size_t index, const Object &row,
									   const CollectorBudgetSnapshot &budget,
									   const CollectorWaitSnapshot	 &control)
	{
		require( storageVersion == 3U && index < manifest.jobs.size() &&
				str( row, L"state") == L"PENDING" && number( row, L"started") == 0U &&
				row.GetNamedValue( L"intent").ValueType() ==
					winrt::Windows::Data::Json::JsonValueType::Null &&
				str( row, L"response").empty() && str( row, L"operation").empty() &&
				!budget.reservations.empty() && budget.day == str( input, L"day")) ;
		const auto &job		 = manifest.jobs[index] ;			// 元の上限とgroup。
		const auto &reserved = budget.reservations.back() ;		// 保存途中は最後の一予約だけ。
		const auto	started	 = reserved.started * 1000U ;		// 秒予約とCONTROLのミリ秒を分けます。
		const auto &request	 = definition.requestKeys[index] ;	// 元公開scopeのrequest。
		require( reserved.campaign == key && reserved.job == job.key && reserved.phase == 0U &&
				reserved.group == job.source.rateLimitGroup &&
				reserved.maximum == job.source.maximumResponseBytes &&
				reserved.charged == reserved.maximum && budget.lastUtc == reserved.started &&
				started <= now && control.lastUtc <= started + 999U) ;
		const auto current = control.controls.find( L"r-" + request) ;					// 新requestだけ不在。
		const auto group = control.controls.find( L"g-" + job.source.rateLimitGroup) ;	// 元共有待機。
		// 開始済みprefixは一保存のrequest／group／最高時計が一致する場合だけです。
		if( current != control.controls.end()) {
			require( current->second.group == job.source.rateLimitGroup &&
					current->second.request == request && !current->second.review &&
					current->second.notBefore <= started + 999U) ;
			// JOB保存前の開始値を元予約へ厳格に再結合します。
			if( current->second.started != 0U) {
				require( current->second.generation == key && current->second.job == job.key &&
						current->second.started == started && current->second.observed >= started &&
						current->second.observed == control.lastUtc &&
						group != control.controls.end() &&
						group->second.observed == control.lastUtc) ;
			}
		}

		// 元待機を消すために部分開始を使用しません。
		if( group != control.controls.end()) {
			require( !group->second.review && group->second.notBefore <= started + 999U) ;
		}

		// 同groupの別予約は元選択規則でも開始できないため、保存途中へ読み替えません。
		for( const auto &entry : budget.reservations) {
			require( entry.phase != 0U || entry.group != reserved.group ||
					(entry.campaign == key && entry.job == job.key)) ;
		}

		// 当request以外の同group開始値を残した不正prefixを拒否します。
		for( const auto &[name, entry] : control.controls) {
			require( entry.started == 0U || entry.group != reserved.group ||
					name == L"r-" + request) ;
		}
	}

	/** @brief 日次切替の元時刻・旧予算を固定したintentを作ります。
	 * @param[in] oldBody 閉鎖済み旧予算のcanonical本文。
	 * @param[in] accepted 初回準備の固定UTC millisecond。
	 * @return 同じ旧予算と新日へ結合したimmutable intent。
	 */
	Object rollIntent( const std::string &oldBody, const std::uint64_t accepted)
	{
		CollectorBudgetSnapshot prior ;	// 旧予算の元schema。
		require( parseCollectorBudgetSnapshot( oldBody, prior) && accepted <= now &&
				prior.day < day( accepted)) ;
		const auto result = make( L"collector-campaign-day-roll-v2") ;	// 任意更新先を含まない。
		put( result, L"rootKey", str( root, L"rootKey")) ;
		put( result, L"oldDay", prior.day) ;
		put( result, L"newDay", day( accepted)) ;
		put( result, L"accepted", accepted) ;
		put( result, L"budgetHash", sha( oldBody)) ;
		put( result, L"operation",
			sha( "day-roll-v2\n" + winrt::to_string( str( root, L"rootKey")) + "\n" +
				winrt::to_string( prior.day) + "\n" + winrt::to_string( day( accepted)) + "\n" +
				winrt::to_string( sha( oldBody)))) ;
		return result ;
	}

	/** @brief 全完了起動の日次一切替を非変更検査し、固定三前像だけを履歴readerへ結合します。
	 * @param[in,out] reader 同じ有限raw／全名再照合を所有する読取り部品。
	 * @throws DWORD 元I/O、形式・保存順不一致13、有限上限68。
	 * @note 任意pathや旧予算DTOを受け取らず、物理台帳は変更しません。
	 */
	void prepareProjectedDayRollView( RegisteredHistoryReader &reader)
	{
		require( store && historyReader == &reader && reader.beforeView.empty() &&
				str( root, L"schema") == L"collector-campaign-root-v3" &&
				str( root, L"activeGeneration").empty()) ;
		const auto generations = root.GetNamedArray( L"generations") ;	// 完了登録だけを対象にします。
		require( generations.Size() > 0U) ;
		require( generations.Size() <= 300U, ERROR_TOO_MANY_NAMES) ;
		require( std::all_of( generations.begin(), generations.end(), []( const auto &entry) {
			const auto row = entry.GetObject() ;	// 元登録の保存版と完了hash。
			return number( row, L"storageVersion") == 3U && hash( str( row, L"summaryHash")) ;
		})) ;
		const bool registered =
			root.GetNamedValue( L"commit").ValueType() !=
			winrt::Windows::Data::Json::JsonValueType::Null ;		// 登録後は全像が必須です。
		const auto archives = root.GetNamedArray( L"archives") ;	// 完了済み操作を再準備しません。
		std::set<std::wstring> completedRolls ;						// 元順序の登録は全履歴coreでさらに検証します。
		// 最大300の登録済み切替だけを一覧から除外します。
		for( const auto &entry : archives) {
			completedRolls.insert( str( entry.GetObject(), L"operation")) ;
		}

		std::vector<std::wstring> names ;	// 未登録一件を有限runs一覧から選びます。
		io( store->listRunNames( names)) ;
		require( names.size() <= 6000U, ERROR_TOO_MANY_NAMES) ;
		Object intent{nullptr} ;	// 全登録外の切替は一つだけです。
		// 未登録と登録commitの一intentを読み、他のcampaign名は通常検査へ残します。
		for( const auto &name : names) {
			// 切替以外の保存物をこの例外へ含めません。
			if( !name.starts_with( L"campaign-day-roll-v2-")) {
				continue ;
			}

			const auto body =
				// 元rawへ拘束。
				reader.mandatory( std::filesystem::path( L"runs") / name) ;
			const auto candidate = json( body) ;					// 全fieldはrollIntentとの完全一致で検査します。
			const auto op		 = str( candidate, L"operation") ;	// 固定名に使う元hash。
			require( hash( op) && name == L"campaign-day-roll-v2-" + op + L".json") ;
			// 登録済み旧切替の内容は後段のarchive閉包へ渡します。
			if( completedRolls.contains( op)) {
				continue ;
			}

			require( !intent) ;
			intent				 = candidate ;
			reader.dayRollIntent = body ;
		}

		// 証跡のない通常全完了は日次変更せず、元検査を続けます。
		if( !intent) {
			require( !registered) ;
			return ;
		}

		require( archives.Size() < 300U, ERROR_TOO_MANY_NAMES) ;
		const auto op			  = str( intent, L"operation") ;	// 一意に証明する元操作。
		const auto physicalBudget = reader.physicalBody( BUDGET) ;	// 登録前だけは現値が元前像です。
		require( physicalBudget.has_value()) ;
		const auto budgetBefore =
			// 固定前像。
			reader.physicalBody( effectPath( op, L"BUDGET", true)) ;
		const auto oldBody = registered ? budgetBefore : physicalBudget ;	// 推測で前像を作りません。
		require( oldBody.has_value()) ;
		CollectorBudgetSnapshot oldBudget ;	// 全予約を元日のまま保持します。
		CollectorWaitSnapshot	control ;	// 旧待機・reviewを変更しません。
		require( parseCollectorBudgetSnapshot( *oldBody, oldBudget) &&
				budgetBytes( oldBudget) == *oldBody &&
				parseCollectorWaitSnapshot( reader.mandatory( CONTROL), control) &&
				std::all_of( oldBudget.reservations.begin(), oldBudget.reservations.end(),
							[]( const auto &entry) { return entry.phase != 0U ; }) &&
				std::all_of( control.controls.begin(), control.controls.end(),
							[]( const auto &entry) { return entry.second.started == 0U ; })) ;
		const auto accepted = number( intent, L"accepted") ;	// 現在UTCへ延長しない元時刻。
		require( accepted >= oldBudget.lastUtc * 1000U && accepted >= control.lastUtc &&
				(registered ? accepted <= number( root, L"lastUtcMillis")
							: accepted >= number( root, L"lastUtcMillis")) &&
				bytes( rollIntent( *oldBody, accepted)) == reader.dayRollIntent) ;
		const auto newBody =
			// 固定空予算。
			budgetBytes( {str( intent, L"newDay"), accepted / 1000U, {}}) ;
		const auto archiveName =
			L"runs/campaign-budget-" + oldBudget.day + L".json" ;	// 元日に限定。
		const auto physicalArchive =
			// 不在beforeを真の不在で検査。
			reader.physicalBody( archiveName) ;
		const std::array<std::filesystem::path, 3U> effects{effectPath( op, L"ARCHIVE", false),
															effectPath( op, L"BUDGET", true),
															// 実addEffectの保存順を保持します。
															effectPath( op, L"BUDGET", false)} ;
		const std::array<std::string, 3U>			expected{*oldBody, *oldBody,
													 newBody} ;	// 共通再導出の三像。
		bool										missing{} ;	// 未登録の準備は連続prefixだけです。
		// 三像を最後まで検査し、欠損後の保存や改変を共有更新前に拒否します。
		for( std::size_t index = 0U; index < effects.size(); ++index) {
			const auto body = reader.physicalBody( effects[index]) ;	// 不在もraw再照合へ入れます。
			require( body ? !missing && *body == expected[index] : !registered) ;
			missing = missing || !body ;
			reader.dayRollNames.insert( effects[index].generic_wstring()) ;
		}

		require( !reader.physicalBody( effectPath( op, L"ARCHIVE", true))) ;
		// 登録後だけ固定二roleと物理反映順を検査し、最大三前像を解釈します。
		if( registered) {
			const auto commit = root.GetNamedObject( L"commit") ;	// 他kind／余剰fieldを拒否します。
			fields( commit, {L"kind", L"operation", L"generation", L"job", L"response", L"accepted",
							L"oldDay", L"newDay", L"effects"}) ;
			require( str( commit, L"kind") == L"DAY_ROLL" && str( commit, L"operation") == op &&
					str( commit, L"generation").empty() && str( commit, L"job").empty() &&
					str( commit, L"response").empty() && number( commit, L"accepted") == accepted &&
					str( commit, L"oldDay") == oldBudget.day &&
					str( commit, L"newDay") == str( intent, L"newDay")) ;
			const auto descriptors = commit.GetNamedArray( L"effects") ;	// ARCHIVE→BUDGETだけ。
			require( descriptors.Size() == 2U) ;
			// 保存像hashと二role順を全て検査します。
			for( std::uint32_t index = 0U; index < 2U; ++index) {
				const auto row = descriptors.GetObjectAt( index) ;	// 一つの固定role。
				fields( row, {L"role", L"before", L"after"}) ;
				require( str( row, L"role") == (index == 0U ? L"ARCHIVE" : L"BUDGET") &&
						str( row, L"before") == (index == 0U ? L"" : sha( *oldBody)) &&
						str( row, L"after") == sha( index == 0U ? *oldBody : newBody)) ;
			}

			const bool archiveApplied =
				physicalArchive && *physicalArchive == *oldBody ;	// 最初の反映。
			const bool budgetApplied = *physicalBudget == newBody ;	// 前の反映なしでは許可しません。
			require( (archiveApplied || !physicalArchive) &&
					(budgetApplied ? archiveApplied : *physicalBudget == *oldBody)) ;
			auto beforeRoot = json( bytes( root)) ;	// 元監督時計を巻戻さずcommitだけnullへ解釈。
			beforeRoot.Insert( L"commit", Value::CreateNullValue()) ;
			reader.beforeView.emplace( ROOT, bytes( beforeRoot)) ;
			reader.beforeView.emplace( BUDGET, *oldBody) ;
			reader.beforeView.emplace( archiveName, std::nullopt) ;
		} else {
			require( !physicalArchive && *physicalBudget == *oldBody) ;
		}

		reader.dayRollNames.insert( path( L"runs/campaign-day-roll-v2-", op).generic_wstring()) ;
	}

	/** @brief 元応答と更新前像から三つの更新後本文を再計算します。
	 * @param[in] index 元job index。
	 * @param[in] response 元応答intent。
	 * @param[in] before CONTROL／JOB／BUDGETの更新前本文。
	 * @param[in] projected 元専用codecで検査したv4。新保存／回復と履歴検査だけ非nullです。
	 * @return 同順序の更新後本文。
	 */
	std::array<std::string, 3> derive( const std::size_t index, const Object &response,
									  const std::array<std::string, 3>		&before,
									  const CollectorProjectedResponseBytes *projected = nullptr)
	{
		CollectorIoSnapshot		  ioObservation ;	// 新versionだけの固定観測。
		CollectorRecoveryResponse observation ;		// 元I/Oから待機／精算の必要値だけを作ります。
		// V4は元canonical byteを保持し、旧Object再符号化でhashを変えません。
		if( projected) {
			const auto &value = projected->value ;	// 専用codecの検査済み値。
			require( storageVersion == 3U && value.generation == key &&
					value.job == manifest.jobs[index].key &&
					value.request == definition.requestKeys[index] &&
					value.cache == definition.cacheBindings[index] &&
					str( response, L"schema") == L"collector-campaign-response-v4") ;
			observation.state				= value.state == CollectorMetadataOutcome::FETCHED
												  ? CollectorCampaignJobState::OBSERVED
											  : value.state == CollectorMetadataOutcome::HELD
												  ? CollectorCampaignJobState::HELD
												  : CollectorCampaignJobState::FAILED ;
			observation.finishedUtcMillis	= value.finished ;
			observation.acceptedUtcMillis	= value.accepted ;
			observation.bytesKnown			= value.bytes.has_value() ;
			observation.receivedBytes		= value.bytes.value_or( 0U) ;
			observation.status				= value.status ;
			observation.retryAfterUtcMillis = value.retryAfter ;
			observation.needsReview			= value.review ;
			observation.challenge			= value.challenge ;
			ioObservation					= value.io ;
		} else {
			observation = decodeResponse( index, response, &ioObservation) ;
		}

		CollectorWaitSnapshot	control ;	// 固定更新前control。
		CollectorBudgetSnapshot value ;		// 固定更新前budget。
		require( parseCollectorWaitSnapshot( before[0], control) &&
				parseCollectorBudgetSnapshot( before[2], value)) ;
		const auto state = json( before[1]) ;	// 固定更新前job表。
		validateJobs( state, key, manifest, storageVersion == 3U, storageVersion == 3U) ;
		validateIntents( state) ;
		const auto row = state.GetNamedArray( L"jobs").GetObjectAt(
			// 元job一行。
			static_cast<std::uint32_t>( index)) ;
		const auto &job = manifest.jobs[index] ;	// 元入力契約。
		const auto	reservation =
			std::find_if( value.reservations.begin(), value.reservations.end(), [&]( const auto &r) {
				return r.campaign == key && r.job == job.key ;
			}) ; // 元予約だけを精算する。
		require( reservation != value.reservations.end() && reservation->phase == 0U &&
				reservation->group == job.source.rateLimitGroup &&
				reservation->maximum == job.source.maximumResponseBytes &&
				(!projected || reservation->charged == reservation->maximum) &&
				reservation->started * 1000U == number( response, L"started") &&
				value.day == str( input, L"day")) ;
		// 保存観測の期限は現在のclockではなく元更新前予算へ結合する。
		if( projected || str( response, L"schema") == L"collector-campaign-response-v3") {
			require( ioObservation.deadlineUtcMillis ==
					originalDeadline( index, number( response, L"started"), value)) ;
		}

		const bool interrupted =
			// 中断だけに開始intent欠損を限定する。
			str( response, L"state") == L"INTERRUPTED" ;
		const bool pending = str( row, L"state") == L"PENDING" ;	// 予算保存直後の窓。
		// 新世代は観測なし回復だけをこの導出へ渡す。
		if( storageVersion == 3U && !projected) {
			require( interrupted && str( response, L"schema") == L"collector-campaign-response-v2") ;
			// 元PENDINGの歴史的前像も、実保存順の二prefixと同じ条件で再検査します。
			if( pending && root.GetNamedArray( L"generations").Size() > 1U &&
			   str( root.GetNamedArray( L"generations").GetObjectAt( 0U), L"generation") != key) {
				validatePartialProjectedStart( index, row, value, control) ;
			}

			// 保存された期限を元予算の三期限へ再結合する。
			if( !pending) {
				require( number( row.GetNamedObject( L"intent"), L"deadlineUtc") ==
						originalDeadline( index, number( response, L"started"), value)) ;
			}
		}

		require( (pending && interrupted) ||
				(str( row, L"state") == L"RUNNING" &&
				 number( row, L"started") == number( response, L"started"))) ;
		// 元開始intentの二時計を同じv4観測へ結合します。
		if( projected) {
			CollectorProjectedCampaignDefinition decoded ;	// 元入力を再構築します。
			CollectorProjectedCampaignIdentity	 identity ;	// 元scopeとG。
			CollectorRecoveryDispatch			 start ;	// 同一予約の全field。
			require( parseCollectorProjectedCampaignIdentity( bytes( input), decoded, identity) &&
					parseCollectorProjectedStart( identity, bytes( row.GetNamedObject( L"intent")),
												 start) &&
					start.jobIndex == index && start.startedUtcMillis == projected->value.started &&
					start.deadlineUtcMillis == ioObservation.deadlineUtcMillis &&
					projected->value.finished >= start.anchorUtcMillis &&
					ioObservation.elapsedMillis &&
					(!ioObservation.headerUtcMillis ||
					 *ioObservation.headerUtcMillis >= start.anchorUtcMillis) &&
					(ioObservation.cause != CollectorIoCause::COMPLETE ||
					 *ioObservation.elapsedMillis <
						 start.deadlineSteadyMillis - start.anchorSteadyMillis)) ;
		}

		const auto request =
			CollectorWaitRequest{job.source.rateLimitGroup, definition.requestKeys[index], key,
								 job.key} ;	// 元要求identity。
		const auto wait = CollectorWaitObservation{
			observation.state == CollectorCampaignJobState::OBSERVED, observation.status,
			observation.retryAfterUtcMillis, observation.needsReview,
			observation.challenge} ;			// 待機への必要観測。
		CollectorWaitSnapshot afterControl ;	// 元finished起点だけの更新後待機。
		require( prepareCollectorWaitSettlement(
			control, request, wait, number( response, L"started"), observation.finishedUtcMillis,
			observation.acceptedUtcMillis, now, pending && interrupted, afterControl)) ;
		reservation->phase = interrupted ? 2U : 1U ;
		reservation->charged =
			observation.bytesKnown ? observation.receivedBytes : reservation->maximum ;
		value.lastUtc = std::max( value.lastUtc, observation.acceptedUtcMillis / 1000U) ;
		put( row, L"state", str( response, L"state")) ;
		put( row, L"started", number( response, L"started")) ;
		put( row, L"response", projected ? projected->responseSha256 : sha( bytes( response))) ;
		put( row, L"operation", operation( key, job.key)) ;
		validateJobs( state, key, manifest, storageVersion == 3U, storageVersion == 3U) ;
		validateIntents( state) ;
		return {controlBytes( afterControl), bytes( state), budgetBytes( value)} ;
	}

	/** @brief 元中断と検査済み前像から成功履歴を保持した無効CACHEを導出します。
	 * @param[in] index 元job。
	 * @param[in] response 元の欠測中断。
	 * @param[in] before 全履歴検査済みCACHE。初回／新requestだけnullです。
	 * @return 初回byteまたは元成功履歴を保持した有限本文。validatorは持ちません。
	 */
	std::string interruptedCache( std::size_t index, const Object &response,
								 const std::optional<std::string> &before = std::nullopt)
	{
		require( storageVersion == 3U && str( response, L"state") == L"INTERRUPTED") ;
		(void)decodeResponse( index, response) ;
		CollectorProjectedCache prior ;	// 元全CACHE閉包の検査済み前像。
		// 次回の成功sliceを欠測で消去しません。
		if( before) {
			projectedCodec( decodeCollectorProjectedCache( *before, prior)) ;
		}

		CollectorProjectedCache cache ;	// 現attemptは中断、旧成功は保持します。
		// 中断だけの型導出。
		const auto				made = makeInterruptedCollectorCache(
			 definition.requestKeys[index], definition.cacheBindings[index],
			 {key, operation( key, manifest.jobs[index].key), sha( bytes( response))},
			 before ? &prior : nullptr, cache) ;
		require( made.status == collector_projected_json::Status::OK,
				made.error != 0 ? static_cast<DWORD>( made.error) : ERROR_INVALID_DATA) ;
		std::string result ;	// 旧中断形と同一byteの本文。
		// 旧byte互換の有限符号化。
		const auto	encoded = encodeCollectorProjectedCache( cache, result) ;
		require( encoded.status == collector_projected_json::Status::OK,
				encoded.error != 0 ? static_cast<DWORD>( encoded.error) : ERROR_INVALID_DATA) ;
		// 初回中断の旧小容量契約は広げません。前像ありは既存有限codecで制限します。
		if( !before) {
			require( result.size() <= 4096U) ;
		}

		return result ;
	}

	/** @brief CACHE登録を照合し、初回保存の前倒しを拒否します。
	 * @param[in] request 元request key。
	 * @return 登録hash。未登録は空文字列。
	 */
	std::wstring registeredCache( const std::wstring &request)
	{
		const auto rows = root.GetNamedArray( L"cacheInventory") ;	// 最大300件。
		require( rows.Size() <= 300U) ;
		std::set<std::wstring> seen ;	// 重複登録を拒否。
		std::wstring		   result ;	// 未登録を欠損hashと区別する。
		// 全登録を検証してから該当hashを返す。
		for( const auto &entry : rows) {
			const auto row = entry.GetObject() ;	// 任意pathを持たない。
			fields( row, {L"request", L"hash"}) ;
			require( hash( str( row, L"request")) && hash( str( row, L"hash")) &&
					seen.insert( str( row, L"request")).second) ;
			// 同じrequestの登録だけを返す。
			if( str( row, L"request") == request) {
				result = str( row, L"hash") ;
			}
		}

		return result ;
	}

	/** @brief 保存根拠とprocess内正本を非変更照合し、初回だけのidentityを返します。
	 * @param[in] index 元入力のjob index。
	 * @param[in] scope 元inputから再構築済みのscope hash。
	 * @return 初回登録とCACHE／応答／effect欠損を確認した値。
	 * @throws DWORD 元I/O／hashまたは関係拒否。回復・補完・書込みはしません。
	 */
	InitialProjectedHistory inspectInitialProjectedHistory( std::size_t		   index,
														   const std::wstring &scope)
	{
		require( projectedRequested && storageVersion == 3U && store && store->isWritable() &&
				index < manifest.jobs.size() && hash( scope)) ;
		require( required( *store, ROOT) == bytes( root) &&
				str( root, L"schema") == L"collector-campaign-root-v3" &&
				str( root, L"activeGeneration") == key && !pendingRoll &&
				root.GetNamedValue( L"commit").ValueType() ==
					winrt::Windows::Data::Json::JsonValueType::Null) ;
		const auto mode = make( L"collector-campaign-mode-v1") ;	// 元rootと結合した固定marker。
		put( mode, L"rootKey", str( root, L"rootKey")) ;
		require( required( *store, MODE) == bytes( mode)) ;
		const auto inputBytes = bytes( input) ;		// 元登録の正本。
		const auto inputHash  = sha( inputBytes) ;	// 保存名ではなく本文の実hash。
		require( required( *store, path( L"runs/campaign-input-v3-", key)) == inputBytes &&
				required( *store, path( L"runs/campaign-marker-v3-", key)) ==
					projectedMarker( inputHash) &&
				required( *store, statePath()) == bytes( jobs)) ;
		std::size_t matches{} ;											// 一つの登録世代だけを要求します。
		const auto	generations = root.GetNamedArray( L"generations") ;	// 有限登録だけを走査します。
		require( generations.Size() <= 300U) ;
		// 元登録簿の固定最大300件を確認し、重複した現世代を受け入れません。
		for( const auto &entry : generations) {
			const auto row = entry.GetObject() ;	// 初期化時の検査済みrootと同じ行。
			// 今回の世代を元入力hashと保存版へ結合します。
			if( str( row, L"generation") == key) {
				require( str( row, L"inputHash") == inputHash &&
						number( row, L"storageVersion") == 3U && str( row, L"summaryHash").empty()) ;
				++matches ;
			}
		}

		require( matches == 1U) ;
		const auto &request = definition.requestKeys[index] ;	// 元一要求の不在を確認します。
		require( registeredCache( request).empty() &&
				!read( *store, path( L"current/campaign-cache-v1-", request))) ;
		const auto op =
			// 固定された元操作名だけを調べます。
			operation( key, manifest.jobs[index].key) ;
		require( !storedResponse( op) && !read( *store, path( L"runs/campaign-response-v4-", op))) ;
		// 初回なので、応答先行保存や準備途中の四roleを全て拒否します。
		for( const auto role : {L"CONTROL", L"CACHE", L"JOB", L"BUDGET"}) {
			require( !read( *store, effectPath( op, role, true, true)) &&
					!read( *store, effectPath( op, role, false, true))) ;
		}

		return {str( root, L"rootKey"),			 key,  inputHash, request,
				definition.cacheBindings[index], scope} ;
	}

	/** @brief 更新前後像を固定roleへ準備します。
	 * @param[in,out] commit 元操作identity。
	 * @param[in] role 有限role。
	 * @param[in] before 元の本文。初回archive／初回または新request CACHEだけ欠損可。
	 * @param[in] after 更新後の元schema本文。
	 */
	void addEffect( const Object &commit, const std::wstring &role,
				   const std::optional<std::string> &before, const std::string &after)
	{
		// 変更なしは適用prefixの判定から除く。
		if( before && *before == after) {
			return ;
		}

		const auto operationKey = str( commit, L"operation") ;							// 決定的な操作identity。
		const bool projected	= str( commit, L"kind") == L"PROJECTED_RESPONSE_V1" ;	// 保存版分離。
		// 更新前像は登録後の型付き再導出に必須。
		if( before) {
			save( *store, effectPath( operationKey, role, true, projected), *before, true) ;
			// 前像だけの準備中断も元応答から回復する。
			if( projected) {
				checkpoint( CollectorRecoveryCheckpoint::PROJECTED_BEFORE_EFFECT) ;
			}

			// 日次前像だけの未登録停止も、全完了の新経路から検査します。
			if( projectedRequested && str( commit, L"kind") == L"DAY_ROLL" &&
			   str( root, L"schema") == L"collector-campaign-root-v3" &&
			   root.GetNamedArray( L"generations").Size() > 0U) {
				checkpoint( CollectorRecoveryCheckpoint::DAY_ROLL_EFFECT) ;
			}
		}

		save( *store, effectPath( operationKey, role, false, projected), after, true) ;
		// 準備途中の各effect保存も再開試験の停止点にする。
		if( projected) {
			checkpoint( CollectorRecoveryCheckpoint::PROJECTED_EFFECT) ;
		}

		// 全完了からの日次準備窓だけを追加し、旧callerの停止集合は変えません。
		if( projectedRequested && str( commit, L"kind") == L"DAY_ROLL" &&
		   str( root, L"schema") == L"collector-campaign-root-v3" &&
		   root.GetNamedArray( L"generations").Size() > 0U) {
			checkpoint( CollectorRecoveryCheckpoint::DAY_ROLL_EFFECT) ;
		}

		Object row ;	// 任意pathなしのdescriptor。
		put( row, L"role", role) ;
		put( row, L"before", before ? sha( *before) : L"") ;
		put( row, L"after", sha( after)) ;
		commit.GetNamedArray( L"effects").Append( row) ;
	}

	/** @brief 登録v4／canonical v2中断commitから固定五件の論理前像を作る非変更検査です。
	 * @param[in,out] reader 同じ全履歴検査の有限reader。物理rawを最後に再照合します。
	 * @param[in] sources 現在の組み込みsource契約。保存値から通信許可を作りません。
	 * @return 全検査へ結合する元操作hashと、真の新CACHEならtrue。
	 * @throws DWORD 元I/O／codec／関係error。物理保存物を変更しません。
	 */
	std::pair<std::wstring, bool> prepareRegisteredCommitView(
		RegisteredHistoryReader &reader, const std::span<const CollectorCampaignSource> sources)
	{
		require( store && historyReader == &reader && reader.beforeView.empty() &&
				!reader.registeredOperation) ;
		const auto registrations = root.GetNamedArray( L"generations") ;	// 元順序の登録済み末尾だけ。
		require( registrations.Size() > 1U && registrations.Size() <= 300U) ;
		const auto tail = registrations.GetObjectAt( registrations.Size() - 1U) ;	// 未完了の元登録。
		require( number( tail, L"storageVersion") == 3U && str( tail, L"summaryHash").empty() &&
				str( tail, L"generation") == str( root, L"activeGeneration")) ;
		loadGeneration( str( tail, L"generation"), str( tail, L"inputHash"), 3U) ;
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
			campaign ;	// 保存入力を現sourceへ再結合。
		require( prepareCollectorProjectedCampaign( bytes( input), str( tail, L"inputHash"), key,
												  definition.artifactSha256, sources, campaign)) ;
		const auto commit = root.GetNamedObject( L"commit") ;	// 日次／旧応答commitへ流用しません。
		fields( commit, {L"kind", L"operation", L"generation", L"job", L"response", L"accepted",
						L"oldDay", L"newDay", L"effects"}) ;
		const auto op = str( commit, L"operation") ;	// 固定元応答と全像のname key。
		require( str( commit, L"kind") == L"PROJECTED_RESPONSE_V1" &&
				str( commit, L"generation") == key && str( commit, L"oldDay").empty() &&
				str( commit, L"newDay").empty() && hash( op) && hash( str( commit, L"response")) &&
				number( commit, L"accepted") <= now) ;
		const auto found =
			std::find_if( manifest.jobs.begin(), manifest.jobs.end(), [&]( const auto &job) {
				return job.key == str( commit, L"job") ;
			}) ; // 登録した元input以外のjobを認めません。
		require( found != manifest.jobs.end() && op == operation( key, found->key)) ;
		const auto index =
			// 元固定index。
			static_cast<std::size_t>( std::distance( manifest.jobs.begin(), found)) ;
		const auto descriptors = commit.GetNamedArray( L"effects") ;	// 元四roleに限定します。
		const std::array<std::wstring, 4U> roles{L"CONTROL", L"CACHE", L"JOB",
												 L"BUDGET"} ;	// 物理反映順。
		require( descriptors.Size() == roles.size()) ;
		std::array<std::optional<std::string>, 4U> before ;	// 新requestのCACHE前像だけnullです。
		std::array<std::string, 4U> after ;					// 独立導出との全byte照合が必要な保存後像。
		// 登録順と全前後像を検査してから、物理台帳のprefixを検査します。
		for( std::size_t role = 0U; role < roles.size(); ++role) {
			const auto descriptor =
				// 元一role。
				descriptors.GetObjectAt( static_cast<std::uint32_t>( role)) ;
			fields( descriptor, {L"role", L"before", L"after"}) ;
			require( str( descriptor, L"role") == roles[role] && hash( str( descriptor, L"after")) &&
					(str( descriptor, L"before").empty() || hash( str( descriptor, L"before")))) ;
			before[role] = reader.physicalBody( effectPath( op, roles[role], true, true)) ;
			after[role]	 = reader.mandatory( effectPath( op, roles[role], false, true)) ;
			require( (before[role] ? sha( *before[role]) : L"") == str( descriptor, L"before") &&
					sha( after[role]) == str( descriptor, L"after") &&
					(!before[role] || *before[role] != after[role])) ;
		}

		require( before[0] && before[2] && before[3] &&
				registeredCache( definition.requestKeys[index]) ==
					(before[1] ? sha( *before[1]) : L"")) ;
		const auto response = storedResponse( op) ;	// 元v4／固定中断以外の代用・併存を拒否します。
		require( response.has_value()) ;
		const auto decoded =
			// 元予約scopeまたは固定中断codec。
			decodeNextRecoveryResponse( index, *response) ;
		require( (decoded ? decoded->responseSha256 : sha( *response)) == str( commit, L"response") &&
				number( json( *response), L"accepted") == number( commit, L"accepted")) ;
		const auto derived = derive( index, json( *response), {*before[0], *before[2], *before[3]},
									decoded ? &*decoded : nullptr) ;	// 元I/Oと三台帳。
		require( derived[0] == after[0] && derived[1] == after[2] && derived[2] == after[3] &&
				initialResponseCache( index, json( *response), decoded ? &*decoded : nullptr,
									 before[1]) == after[1]) ;
		bool seenBefore{} ;	// 反映済みprefixの後に反映済み像を挿入させません。
		// 全現在値が元前像か元後像の固定prefixでなければ、論理ビューも作りません。
		for( std::size_t role = 0U; role < roles.size(); ++role) {
			const auto name = destination( commit, roles[role]) ;		// 組み込みの固定destinationのみ。
			const auto current = reader.physicalBody( name) ;			// 欠損も元I/Oとともに固定します。
			const bool applied = current && *current == after[role] ;	// hashではなく全byte照合。
			require( applied ? !seenBefore : current == before[role]) ;
			seenBefore = seenBefore || !applied ;
			reader.beforeView.emplace( name, before[role]) ;
		}

		const auto logicalRoot = json( bytes( root)) ;	// 物理rootとaliasしない検査専用copy。
		logicalRoot.Insert( L"commit", Value::CreateNullValue()) ;
		reader.beforeView.emplace( ROOT, bytes( logicalRoot)) ;
		require( reader.beforeView.size() == 5U) ;
		reader.registeredOperation = op ;
		return {op, !before[1]} ;
	}

	/** @brief 登録済みcommitの全像を検証してprefixだけを適用します。 */
	void applyCommit()
	{
		const auto commit = root.GetNamedObject( L"commit") ;	// 一つだけの固定commit。
		fields( commit, {L"kind", L"operation", L"generation", L"job", L"response", L"accepted",
						L"oldDay", L"newDay", L"effects"}) ;
		const auto kind		 = str( commit, L"kind") ;				// 世代別応答または日次切替。
		const bool projected = kind == L"PROJECTED_RESPONSE_V1" ;	// 新世代だけの四role。
		require( !projected || storageVersion == 3U) ;
		const auto operationKey = str( commit, L"operation") ;	// 全effect名へ結合する。
		require( hash( operationKey) && number( commit, L"accepted") <= now) ;
		const auto descriptors = commit.GetNamedArray( L"effects") ;	// 固定順の旧最大三／新四role。
		require( descriptors.Size() >= 1U && descriptors.Size() <= (projected ? 4U : 3U)) ;
		std::vector<std::optional<std::string>> before ;	// 元schemaの更新前像。
		std::vector<std::string>				after ;		// 元schemaの更新後像。
		std::vector<std::wstring>				roles ;		// descriptorと同順の有限role。
		// 全effectを読むまで共有fileを一つも変更しない。
		for( const auto &entry : descriptors) {
			const auto row = entry.GetObject() ;	// 不明fieldを拒否する。
			fields( row, {L"role", L"before", L"after"}) ;
			const auto role = str( row, L"role") ;	// destination関数でも制限する。
			require( hash( str( row, L"after")) &&
					(str( row, L"before").empty() || hash( str( row, L"before")))) ;
			std::optional<std::string> prior ;	// 初回archive以外は必須。
			// 初回archive以外では元像の存在とhashを必須とする。
			if( !str( row, L"before").empty()) {
				prior = required( *store, effectPath( operationKey, role, true, projected)) ;
				require( sha( *prior) == str( row, L"before")) ;
			}

			const auto next =
				// 登録後欠損は修復しない。
				required( *store, effectPath( operationKey, role, false, projected)) ;
			require( sha( next) == str( row, L"after") && (!prior || *prior != next)) ;
			before.push_back( prior) ;
			after.push_back( next) ;
			roles.push_back( role) ;
		}

		// 元応答から更新後を再導出し、hashだけのpatch権限にしない。
		if( kind == L"RESPONSE" || projected) {
			require( projected == (storageVersion == 3U)) ;
			require( str( commit, L"generation") == key && str( commit, L"oldDay").empty() &&
					str( commit, L"newDay").empty()) ;
			const auto jobRole	  = projected ? 2U : 1U ;	// CACHEの後にJOBを反映。
			const auto budgetRole = projected ? 3U : 2U ;	// 予算精算は最後。
			require( roles ==
						(projected
							 ? std::vector<std::wstring>{L"CONTROL", L"CACHE", L"JOB", L"BUDGET"}
							 : std::vector<std::wstring>{L"CONTROL", L"JOB", L"BUDGET"}) &&
					before[0] && before[jobRole] && before[budgetRole]) ;
			const auto found =
				std::find_if( manifest.jobs.begin(), manifest.jobs.end(), [&]( const auto &job) {
					return job.key == str( commit, L"job") ;
				}) ; // 元固定job。
			require( found != manifest.jobs.end() && operationKey == operation( key, found->key)) ;
			const auto index = static_cast<std::size_t>(
				// 固定順index。
				std::distance( manifest.jobs.begin(), found)) ;
			const auto stored = storedResponse( operationKey) ;	// 二versionから必須一件。
			require( stored.has_value()) ;
			const auto response =
				// V4の元hashを変えません。
				Object::Parse( winrt::to_hstring( *stored)) ;
			const auto decoded = str( response, L"schema") == L"collector-campaign-response-v4"
									 ? std::optional<CollectorProjectedResponseBytes>(
										   decodeSavedProjected( index, *stored))
									 : std::nullopt ;	// 元専用codecだけから値を取得します。
			require( (decoded ? decoded->responseSha256 : sha( bytes( response))) ==
						str( commit, L"response") &&
					number( response, L"accepted") == number( commit, L"accepted")) ;
			const auto expected =
				derive( index, response, {*before[0], *before[jobRole], *before[budgetRole]},
					   decoded ? &*decoded : nullptr) ;	// 元像だけ。
			require( expected[0] == after[0] && expected[1] == after[jobRole] &&
					expected[2] == after[budgetRole]) ;
			// 元CACHE登録と更新前像を結合し、初回の欠損条件も維持します。
			if( projected) {
				require( !before[1] || root.GetNamedArray( L"generations").Size() > 1U) ;
				require( registeredCache( definition.requestKeys[index]) ==
							(before[1] ? sha( *before[1]) : L"") &&
						read( *store, effectPath( operationKey, L"CACHE", true, true)) == before[1] &&
						after[1] == initialResponseCache( index, response,
														 decoded ? &*decoded : nullptr, before[1])) ;
			}
		} else {
			require( kind == L"DAY_ROLL" && str( commit, L"generation").empty() &&
					str( commit, L"job").empty() && str( commit, L"response").empty()) ;
			require( roles == std::vector<std::wstring>{L"ARCHIVE", L"BUDGET"} && !before[0] &&
					before[1]) ;
			CollectorBudgetSnapshot oldBudget ;	// 閉鎖済み旧日だけをarchiveする。
			CollectorBudgetSnapshot newBudget ;	// 固定新日の空予算。
			require( parseCollectorBudgetSnapshot( *before[1], oldBudget) &&
					parseCollectorBudgetSnapshot( after[1], newBudget)) ;
			require( after[0] == *before[1] && oldBudget.day == str( commit, L"oldDay") &&
					newBudget.day == str( commit, L"newDay") && oldBudget.day < newBudget.day &&
					newBudget.reservations.empty() &&
					newBudget.lastUtc == number( commit, L"accepted") / 1000U &&
					day( number( commit, L"accepted")) == newBudget.day) ;
			require( std::all_of( oldBudget.reservations.begin(), oldBudget.reservations.end(),
								[]( const auto &r) { return r.phase != 0U ; })) ;
			require( operationKey ==
					sha( "day-roll-v2\n" + winrt::to_string( str( root, L"rootKey")) + "\n" +
						winrt::to_string( oldBudget.day) + "\n" + winrt::to_string( newBudget.day) +
						"\n" + winrt::to_string( sha( *before[1])))) ;
			require( required( *store, path( L"runs/campaign-day-roll-v2-", operationKey)) ==
					bytes( rollIntent( *before[1], number( commit, L"accepted")))) ;
		}

		bool			  seenBefore{} ;	// 更新後は先頭から連続しなければならない。
		std::vector<bool> done ;			// 完全なprefix検査後だけ保存を始める。
		// 一つでも未知の現在値があれば変更せずに停止する。
		for( std::size_t index = 0; index < roles.size(); ++index) {
			const auto current =
				// 元schema本文で比較する。
				read( *store, destination( commit, roles[index])) ;
			const bool applied = current && *current == after[index] ;	// 内容完全一致を要求する。
			require( applied ? !seenBefore : current == before[index]) ;
			seenBefore = seenBefore || !applied ;
			done.push_back( applied) ;
		}

		// 元の保存順序を維持して未反映のsuffixだけを保存する。
		for( std::size_t index = 0; index < roles.size(); ++index) {
			// 更新前のままのsuffixだけを順にatomic保存する。
			if( !done[index]) {
				save( *store, destination( commit, roles[index]), after[index],
					 roles[index] == L"ARCHIVE") ;
				checkpoint( CollectorRecoveryCheckpoint::APPLIED) ;
			}
		}

		// 新archiveを登録するのは全roleの反映後だけ。
		if( kind == L"DAY_ROLL") {
			Object archive ;	// 閉鎖済みdayと本文hashだけ。
			put( archive, L"day", str( commit, L"oldDay")) ;
			put( archive, L"hash", sha( after[0])) ;
			put( archive, L"operation", operationKey) ;
			root.GetNamedArray( L"archives").Append( archive) ;
		} else {
			jobs = json( required( *store, statePath())) ;
			// 四roleの全反映後だけCACHE登録とcommit解除を同じrootへ保存する。
			if( projected) {
				Object row ;	// 現在の登録hash。
				put( row, L"request", str( json( after[1]), L"request")) ;
				put( row, L"hash", sha( after[1])) ;
				const auto inventory = root.GetNamedArray( L"cacheInventory") ;	// 元登録順。
				bool	   replaced{} ;											// 同requestの元hashだけを一回置き換えます。
				// 最大300登録を走査し、新request以外の重複登録を防ぎます。
				for( std::uint32_t index = 0U; index < inventory.Size(); ++index) {
					// 元検証済みCACHEの登録位置だけを維持します。
					if( str( inventory.GetObjectAt( index), L"request") == str( row, L"request")) {
						require( before[1] && !replaced &&
								str( inventory.GetObjectAt( index), L"hash") == sha( *before[1])) ;
						inventory.SetAt( index, row) ;
						replaced = true ;
					}
				}

				// 真の新requestだけ登録を追加します。
				if( !replaced) {
					require( !before[1] && inventory.Size() < 300U, ERROR_TOO_MANY_NAMES) ;
					inventory.Append( row) ;
				}
			}
		}

		root.Insert( L"commit", Value::CreateNullValue()) ;
		saveRoot() ;
		checkpoint( CollectorRecoveryCheckpoint::COMPLETED) ;
		pendingRoll = nullptr ;
	}

	/** @brief 元応答の一回だけの固定更新を準備します。
	 * @param[in] index 元job index。
	 * @param[in] response 検証する元intent。V4のhash対象には使いません。
	 * @param[in] projectedResponse 独立decode済みv4。旧中断／旧応答ならnull。
	 * @param[in] beforeCache 全履歴検査済み元CACHE本文。初回／新requestだけnull。
	 */
	void commitResponse( const std::size_t index, const Object &response,
						const CollectorProjectedResponseBytes *projectedResponse = nullptr,
						const std::optional<std::string>	  &beforeCache		 = std::nullopt)
	{
		std::array<std::string, 3> before{required( *store, CONTROL), required( *store, statePath()),
										  // 保存順と同じ三つの元像。
										  required( *store, BUDGET)} ;
		const auto				   after =
			// 共有更新前に全型を検査。
			derive( index, response, before, projectedResponse) ;
		Object	   commit ;								// 任意pathを持たない固定commit。
		const bool projected = storageVersion == 3U ;	// 旧commitへ新stateを渡さない。
		put( commit, L"kind", projected ? L"PROJECTED_RESPONSE_V1" : L"RESPONSE") ;
		put( commit, L"operation", operation( key, manifest.jobs[index].key)) ;
		put( commit, L"generation", key) ;
		put( commit, L"job", manifest.jobs[index].key) ;
		put( commit, L"response",
			projectedResponse ? projectedResponse->responseSha256 : sha( bytes( response))) ;
		put( commit, L"accepted", number( response, L"accepted")) ;
		put( commit, L"oldDay", L"") ;
		put( commit, L"newDay", L"") ;
		commit.Insert( L"effects", Array()) ;
		// 元登録とCACHE前像を全role保存前に照合します。
		if( projected) {
			require( !beforeCache || root.GetNamedArray( L"generations").Size() > 1U) ;
			const auto savedBeforeCache =
				read( *store, effectPath( str( commit, L"operation"), L"CACHE", true,
										true)) ;	// 全履歴検査済み準備像だけを再利用します。
			require( registeredCache( definition.requestKeys[index]) ==
						(beforeCache ? sha( *beforeCache) : L"") &&
					read( *store, destination( commit, L"CACHE")) == beforeCache &&
					(!savedBeforeCache || savedBeforeCache == beforeCache)) ;
			const auto cache =
				// 先に全導出。
				initialResponseCache( index, response, projectedResponse, beforeCache) ;
			addEffect( commit, L"CONTROL", before[0], after[0]) ;
			addEffect( commit, L"CACHE", beforeCache, cache) ;
			addEffect( commit, L"JOB", before[1], after[1]) ;
			addEffect( commit, L"BUDGET", before[2], after[2]) ;
		} else {
			const std::array<std::wstring, 3> roles{L"CONTROL", L"JOB",
													L"BUDGET"} ;	// 順序をcallerから受けない。
			// 未登録の部分effectは同内容の場合だけ再利用する。
			for( std::size_t role = 0; role < roles.size(); ++role) {
				addEffect( commit, roles[role], before[role], after[role]) ;
			}
		}

		checkpoint( CollectorRecoveryCheckpoint::EFFECTS) ;
		root.Insert( L"commit", commit) ;
		saveRoot() ;
		checkpoint( CollectorRecoveryCheckpoint::REGISTERED) ;
		applyCommit() ;
	}

	/** @brief 完了済み応答を全tableの旧hashではなく必要条件で照合します。
	 * @param[in] index 元job index。
	 * @param[in] response 元の固定応答。
	 * @param[in] projectedResponse 独立decode済みv4。旧応答ならnull。
	 */
	void verifyTerminal( const std::size_t index, const Object &response,
						const CollectorProjectedResponseBytes *projectedResponse = nullptr)
	{
		const auto op		 = operation( key, manifest.jobs[index].key) ;	// 元jobの操作key。
		const bool projected = storageVersion == 3U ;						// 世代別immutable像。
		const std::array<std::string, 3> before{
			required( *store, effectPath( op, L"CONTROL", true, projected)),
			required( *store, effectPath( op, L"JOB", true, projected)),
			// 固定元像。
			required( *store, effectPath( op, L"BUDGET", true, projected))} ;
		const auto expected =
			// 元像だけの再導出。
			derive( index, response, before, projectedResponse) ;
		const std::array<std::wstring, 3> roles{L"CONTROL", L"JOB", L"BUDGET"} ;	// 有限の保存順。
		// 完了後もimmutable前後像の導出を検査する。
		for( std::size_t role = 0U; role < roles.size(); ++role) {
			require( required( *store, effectPath( op, roles[role], false, projected)) ==
					expected[role]) ;
		}

		// 現profileはrequest重複なし・単一世代なので最新CACHEもこの応答に一致する。
		if( projected) {
			const auto cache =
				// 初回の元導出。
				initialResponseCache( index, response, projectedResponse) ;
			require( !read( *store, effectPath( op, L"CACHE", true, true)) &&
					required( *store, effectPath( op, L"CACHE", false, true)) == cache &&
					required( *store, path( L"current/campaign-cache-v1-",
										  definition.requestKeys[index])) == cache &&
					registeredCache( definition.requestKeys[index]) == sha( cache)) ;
		}

		CollectorRecoveryResponse observation ;	// 元I/Oに結合した最低条件だけを比較します。
		// V4は専用codecで検査した値から取り出します。
		if( projectedResponse) {
			observation.finishedUtcMillis	= projectedResponse->value.finished ;
			observation.bytesKnown			= projectedResponse->value.bytes.has_value() ;
			observation.receivedBytes		= projectedResponse->value.bytes.value_or( 0U) ;
			observation.status				= projectedResponse->value.status ;
			observation.retryAfterUtcMillis = projectedResponse->value.retryAfter ;
			observation.needsReview			= projectedResponse->value.review ;
			observation.challenge			= projectedResponse->value.challenge ;
		} else {
			observation = decodeResponse( index, response) ;
		}

		const auto row =
			// 完了行。
			jobs.GetNamedArray( L"jobs").GetObjectAt( static_cast<std::uint32_t>( index)) ;
		// Terminalの開始intentを保存後に別の正当なintentへ差替えることも拒否する。
		if( projected) {
			require( bytes( row) == bytes( json( expected[1])
											.GetNamedArray( L"jobs")
											.GetObjectAt( static_cast<std::uint32_t>( index)))) ;
		}

		const auto value = budget() ;	// Active generationは日次切替前に回収する。
		const auto found =
			std::find_if( value.reservations.begin(), value.reservations.end(), [&]( const auto &r) {
				return r.campaign == key && r.job == manifest.jobs[index].key ;
			}) ; // 元予約。
		require( found != value.reservations.end() &&
				found->phase == (str( response, L"state") == L"INTERRUPTED" ? 2U : 1U) &&
				found->charged ==
					(observation.bytesKnown ? observation.receivedBytes : found->maximum) &&
				found->started * 1000U == number( response, L"started") &&
				found->maximum == manifest.jobs[index].source.maximumResponseBytes &&
				found->group == manifest.jobs[index].source.rateLimitGroup &&
				value.day == str( input, L"day")) ;
		require( str( row, L"state") == str( response, L"state") &&
				str( row, L"response") == (projectedResponse ? projectedResponse->responseSha256
															: sha( bytes( response))) &&
				str( row, L"operation") == operation( key, manifest.jobs[index].key) &&
				number( row, L"started") == number( response, L"started")) ;
		const auto table = controls() ;	// 後続jobによる正当な更新を認める。
		const auto request =
			// 対象要求の最低待機。
			table.controls.find( L"r-" + definition.requestKeys[index]) ;
		const auto group = table.controls.find(
			L"g-" + manifest.jobs[index].source.rateLimitGroup) ;	// 共有group待機。
		require( request != table.controls.end() && group != table.controls.end() &&
				request->second.group == group->second.group && request->second.started == 0U &&
				request->second.notBefore >= observation.finishedUtcMillis + DAY &&
				group->second.completed >= observation.finishedUtcMillis) ;
		require( !observation.needsReview || request->second.review) ;
		// 限流とアクセス拒否を成功回収時に解除しない。
		if( observation.status == 429U || observation.status == 503U) {
			require( group->second.notBefore >= std::max( observation.finishedUtcMillis + DAY,
														observation.retryAfterUtcMillis) &&
					(!observation.needsReview || group->second.review)) ;
		}

		require( !(observation.status == 403U || observation.challenge) || group->second.review) ;
	}

	/** @brief 更新前全履歴検査後だけ未登録v4／canonical v2中断一件を非再送で精算します。
	 * @throws DWORD 元I/O／codec error、有限容量、保存後停止の第一error。
	 * @note 応答なし・登録commit・反映途中・日次／完了窓の回復は行いません。
	 */
	void recoverPreparedNextResponses()
	{
		require( nextProjected && storageVersion == 3U &&
				root.GetNamedValue( L"commit").ValueType() ==
					winrt::Windows::Data::Json::JsonValueType::Null) ;
		std::optional<std::size_t>
				   pending ;								// 一件の元RUNNING／部分開始応答だけ。外部からindexを受けません。
		const auto rows = jobs.GetNamedArray( L"jobs") ;	// 全履歴検査済みの元末尾。
		// 既に精算済みの応答を再保存・再精算しません。
		for( std::size_t index = 0U; index < manifest.jobs.size(); ++index) {
			// 全検査済みの元予約と応答の組だけを選び、欠測を新たに生成しません。
			if( (str( rows.GetObjectAt( static_cast<std::uint32_t>( index)), L"state") == L"RUNNING" ||
				str( rows.GetObjectAt( static_cast<std::uint32_t>( index)), L"state") == L"PENDING") &&
			   storedResponse( operation( key, manifest.jobs[index].key))) {
				require( !pending) ;
				pending = index ;
			}
		}

		// 応答なしの再読込みは従来の非変更待機を維持します。
		if( !pending) {
			return ;
		}

		std::shared_ptr<const CollectorPreparedProjectedCampaign>
			campaign ;	// 保存入力を現sourceへ再結合します。
		require( prepareCollectorProjectedCampaign( bytes( input), sha( bytes( input)), key,
												  definition.artifactSha256, projectedSources,
												  campaign)) ;
		std::shared_ptr<const CollectorRegisteredProjectedHistory>
			history ;	// 全閉包検査済みの更新前値だけ。
		io( LocalCollectorRecovery::inspectProjectedHistoryCore(
			*store, campaign->job( *pending), projectedSources, now, sha( bytes( root)), history, {},
			true, nullptr, true, false, true)) ;
		std::optional<std::string> beforeCache ;	// 真の新requestだけ不在を保持します。
		// 登録hashへ一致する変更不能contextからcanonical前像を再導出します。
		if( history) {
			beforeCache.emplace() ;
			projectedCodec( encodeCollectorProjectedCache( history->cache(), *beforeCache)) ;
			require( sha( *beforeCache) == history->cacheHash()) ;
		}

		const auto response =
			// 元byteの再読取り。
			storedResponse( operation( key, manifest.jobs[*pending].key)) ;
		require( response.has_value()) ;
		const auto decoded =
			// 取得／初回中断時のfinished／acceptedを維持します。
			decodeNextRecoveryResponse( *pending, *response) ;
		CollectorStoreUsage usage ;	// 残留stagingも含む保存前の有限予算。
		io( store->inspectUsage( usage)) ;
		io( checkCollectorProjectedRecoveryCapacity( usage, manifest.jobs.size(),
												   definition.requestKeys.size())) ;
		commitResponse( *pending, json( *response), decoded ? &*decoded : nullptr, beforeCache) ;
		std::shared_ptr<const CollectorRegisteredProjectedHistory>
			verified ;	// 完了後も同じ閉包判定で検査します。
		io( LocalCollectorRecovery::inspectProjectedHistoryCore( *store, nullptr, projectedSources,
															   now, sha( bytes( root)), verified, {},
															   true, nullptr, false, false, true)) ;
	}

	/** @brief 保存応答を先に固定job順で回収し、その後だけ欠損を中断にします。 */
	void recoverResponses()
	{
		// 一巡目は全保存応答を先に反映する。
		for( std::size_t index = 0; index < manifest.jobs.size(); ++index) {
			const auto response =
				// 保存済みintent。
				storedResponse( operation( key, manifest.jobs[index].key)) ;
			const auto row = jobs.GetNamedArray( L"jobs").GetObjectAt(
				// 現状態。
				static_cast<std::uint32_t>( index)) ;
			const bool terminal = !str( row, L"response").empty() ;	// 固定結果の有無。
			// 保存済み応答を欠損中断より先に処理する。
			if( response) {
				const auto object =
					// 元bodyを再符号化しません。
					Object::Parse( winrt::to_hstring( *response)) ;
				const auto decoded = str( object, L"schema") == L"collector-campaign-response-v4"
										 ? std::optional<CollectorProjectedResponseBytes>(
											   decodeSavedProjected( index, *response))
										 : std::nullopt ;	// 旧応答は従来codecへ残します。
				// 完了済みなら再精算せず元応答との一致だけを検査する。
				if( terminal) {
					verifyTerminal( index, object, decoded ? &*decoded : nullptr) ;
				} else {
					commitResponse( index, object, decoded ? &*decoded : nullptr) ;
				}
			} else {
				require( !terminal) ;
			}
		}

		const auto value = budget() ;	// 応答回収後の残予約だけを確認する。
		// 予約一件に対して一度だけ中断intentを生成する。
		for( const auto &reservation : value.reservations) {
			// 既に閉鎖した予約を中断へ変更しない。
			if( reservation.phase != 0U) {
				// 閉鎖済み当generation予約にはterminal応答が必須。
				if( reservation.campaign == key) {
					const auto rows = jobs.GetNamedArray( L"jobs") ;	// 回収済みの固定表。
					require( std::any_of( rows.begin(), rows.end(), [&]( const auto &entry) {
						const auto row = entry.GetObject() ;	// 元jobの終端証拠。
						return str( row, L"job") == reservation.job &&
							   !str( row, L"response").empty() ;
					})) ;
				}

				continue ;
			}

			require( reservation.campaign == key) ;
			const auto found =
				std::find_if( manifest.jobs.begin(), manifest.jobs.end(), [&]( const auto &job) {
					return job.key == reservation.job ;
				}) ; // 入力にない予約を拒否する。
			require( found != manifest.jobs.end()) ;
			const auto index =
				// 元job順。
				static_cast<std::size_t>( std::distance( manifest.jobs.begin(), found)) ;
			CollectorRecoveryResponse observation ;	// byte／送信数は未知のまま。
			observation.finishedUtcMillis = now ;
			observation.acceptedUtcMillis = now ;
			const auto response = responseObject( index, observation, reservation.started * 1000U,
												 true) ;	// 初回回収時刻だけを固定する。
			save( *store, path( L"runs/campaign-response-v2-", operation( key, reservation.job)),
				 bytes( response), true) ;
			checkpoint( CollectorRecoveryCheckpoint::RESPONSE) ;
			commitResponse( index, response) ;
		}

		const auto table = controls() ;	// 不明な開始intentを新規許可へ変換しない。
		// 残る開始intentは一件も新規許可へ持ち越さない。
		for( const auto &[name, row] : table.controls) {
			require( row.started == 0U) ;
		}

		// 予約欠損RUNNINGを勝手に中断として再構築しない。
		for( const auto &entry : jobs.GetNamedArray( L"jobs")) {
			require( str( entry.GetObject(), L"state") != L"RUNNING") ;
		}
	}

	/** @brief 旧v1の閉鎖状態を保ち、登録可能file集合を固定します。
	 * @param[in] value 登録前の共通予算。欠損ならnullopt。
	 * @return 不変にする相対名と実byte hash。
	 */
	Array legacyV1( const std::optional<CollectorBudgetSnapshot> &value)
	{
		Array					  result ;	// 登録する旧v1 fileだけの有限集合。
		std::vector<std::wstring> current ;	// 保護されたcurrent名。
		std::vector<std::wstring> runs ;	// 保護されたrun名。
		io( store->listCurrentNames( current)) ;
		io( store->listRunNames( runs)) ;
		std::map<std::wstring, CollectorBudgetSnapshot> budgets ;	// 旧日も照合する保存予算。
		// 既存の日次予算がある場合だけ元dayで照合集合へ入れる。
		if( value) {
			budgets.emplace( value->day, *value) ;
		}

		std::set<std::wstring>	  expected ;	// 旧markerの片側欠損を拒否する。
		std::vector<std::wstring> selected ;	// 実byteを固定する相対名。
		// 旧archiveは閉鎖予約だけを持つ必要がある。
		for( const auto &name : runs) {
			// 旧v4履歴は専用decoder側が確認する。
			if( !name.starts_with( L"campaign-")) {
				continue ;
			}

			require( name.starts_with( L"campaign-budget-") && name.size() == 29U) ;
			CollectorBudgetSnapshot prior ;	// 旧日予算。
			require( parseCollectorBudgetSnapshot(
						required( *store, std::filesystem::path( L"runs") / name), prior) &&
					name == L"campaign-budget-" + prior.day + L".json" &&
					prior.lastUtc <= now / 1000U && budgets.emplace( prior.day, prior).second) ;
			selected.push_back( L"runs/" + name) ;
		}

		// Phase 0の旧coreはv2へ暗黙移行しない。
		for( const auto &[date, prior] : budgets) {
			// 各旧予約のphaseを独立して確認する。
			for( const auto &reservation : prior.reservations) {
				// 未閉鎖の旧予約は旧coreによる回収を要求する。
				if( reservation.phase == 0U) {
					reason = L"CORE_V1_RECOVERY_REQUIRED" ;
					throw DWORD( ERROR_RETRY) ;
				}
			}
		}

		// 旧v1 stateの型・marker・閉鎖予約を確認する。
		for( const auto &name : current) {
			// 旧v4 pointerやsource待機は別の全契約検査に任せる。
			if( !name.starts_with( L"campaign-")) {
				continue ;
			}

			// 共有budgetとcontrolは今後更新されるため不変集合から除外する。
			if( name == L"campaign-budget-v1.json" || name == L"campaign-controls-v1.json") {
				continue ;
			}

			// 共有台帳のmarkerは不変集合へ含める。
			if( name == L"campaign-budget-marker-v1.json" ||
			   name == L"campaign-controls-marker-v1.json") {
				selected.push_back( L"current/" + name) ;
				continue ;
			}

			// 旧campaign markerは対応stateを読むときに検証する。
			if( name.starts_with( L"campaign-marker-v1-")) {
				continue ;
			}

			require( name.size() == 81U && name.starts_with( L"campaign-v1-") &&
					name.ends_with( L".json")) ;
			const auto oldKey = name.substr( 12U, 64U) ;	// 完全keyだけの旧保存名。
			require( hash( oldKey)) ;
			const auto state =
				// 元v1 schema。
				json( required( *store, std::filesystem::path( L"current") / name)) ;
			fields( state, {L"schema", L"key", L"jobs", L"targets"}) ;
			require( str( state, L"schema") == L"collector-campaign-state-v1" &&
					str( state, L"key") == oldKey) ;
			const auto marker = L"campaign-marker-v1-" + oldKey + L".json" ;	// 対となる元marker。
			require( required( *store, std::filesystem::path( L"current") / marker) ==
					"collector-campaign-identity-v1\n" + winrt::to_string( oldKey)) ;
			expected.insert( marker) ;
			selected.push_back( L"current/" + name) ;
			selected.push_back( L"current/" + marker) ;
			const auto rows	   = state.GetNamedArray( L"jobs") ;	// 最大300job。
			const auto targets = state.GetNamedArray( L"targets") ;	// 最大300固定対象。
			require( rows.Size() > 0U && rows.Size() <= 300U && targets.Size() > 0U &&
					targets.Size() <= 300U && value.has_value()) ;
			std::set<std::wstring> keys ;	// 重複jobを認めない。
			// 全旧jobの型と閉鎖予約を一件ずつ確認する。
			for( const auto &entry : rows) {
				const auto row = entry.GetObject() ;	// 旧v1の保存観測。
				fields( row, {L"key", L"state", L"started", L"finished", L"bytes", L"status",
							 L"error", L"body", L"projection"}) ;
				require( hash( str( row, L"key")) && keys.insert( str( row, L"key")).second &&
						number( row, L"state") <= 5U && number( row, L"error") <= MAXDWORD) ;
				// 未予約と実行中の旧jobは移行前に回収する。
				if( number( row, L"state") <= 1U) {
					reason = L"CORE_V1_RECOVERY_REQUIRED" ;
					throw DWORD( ERROR_RETRY) ;
				}

				require( number( row, L"started") > 0U &&
						number( row, L"started") <= number( row, L"finished") &&
						number( row, L"finished") <= now / 1000U) ;
				std::size_t matches{} ;	// 一つの予約日にだけ存在する元予約。
				// Currentと全archiveの予算を同じ予約identityで調べる。
				for( const auto &[date, prior] : budgets) {
					// 予約日を跨いだ同じ元jobの重複も数える。
					for( const auto &r : prior.reservations) {
						// 別のcampaignやjobの予約はこの行へ結合しない。
						if( r.campaign != oldKey || r.job != str( row, L"key")) {
							continue ;
						}

						++matches ;
						require( r.started == number( row, L"started") &&
								number( row, L"bytes") <= r.maximum &&
								r.phase == (number( row, L"state") == 5U ? 2U : 1U) &&
								r.charged == (number( row, L"state") == 5U ? r.maximum
																		  : number( row, L"bytes"))) ;
					}
				}

				require( matches == 1U) ;
				const auto status = number( row, L"status") ;	// 有限HTTP観測。
				require( status == 0U || (status >= 100U && status <= 599U)) ;
				require( (str( row, L"body").empty() || hash( str( row, L"body"))) &&
						(str( row, L"projection").empty() || hash( str( row, L"projection")))) ;
			}

			// 製品反映が未完了の旧coreを登録済みとしない。
			for( const auto &entry : targets) {
				const auto stateValue = entry.GetNumber() ;	// 旧反映済みenumだけ。
				require( std::isfinite( stateValue) && std::floor( stateValue) == stateValue &&
							stateValue >= 1.0 && stateValue <= 4.0,
						ERROR_RETRY) ;
			}
		}

		// 旧markerだけが残るrootを新規としない。
		for( const auto &name : current) {
			// 旧marker単独の残留を拒否する。
			if( name.starts_with( L"campaign-marker-v1-")) {
				require( expected.contains( name)) ;
			}
		}

		std::sort( selected.begin(), selected.end()) ;
		// Digestはenvelopeを含む実byteを固定する。
		for( const auto &name : selected) {
			// Envelopeを含む元fileの実byte。
			std::string raw ;
			bool		found{} ;	// 同じ保護handleから読む。
			io( store->read( name, raw, found)) ;
			require( found) ;
			Object row ;	// 相対名は旧の固定patternだけ。
			put( row, L"name", name) ;
			put( row, L"hash", sha( raw)) ;
			result.Append( row) ;
		}

		return result ;
	}

	/** @brief 旧全契約のdigestと追加・消失・改変を検査します。
	 * @param[in] legacy 全旧v4観測。
	 * @param[in] savedV1 登録済みv1 file集合。
	 * @return Rootへ固定する複合digest。
	 */
	std::wstring legacyDigest( const CollectorLegacySnapshot &legacy, const Array &savedV1)
	{
		std::string inputBytes =
			// 旧v4全manifest／artifactを含む。
			winrt::to_string( legacy.digest) + "\n" ;
		std::set<std::wstring> names ;	// 重複登録を拒否する。
		require( savedV1.Size() <= 4096U) ;
		// 登録済みの各実fileを毎回同じ保護handleから照合する。
		for( const auto &entry : savedV1) {
			const auto row = entry.GetObject() ;	// 型検査済みの相対名とhash。
			fields( row, {L"name", L"hash"}) ;
			const auto name = str( row, L"name") ;	// 新規pathへ書く用途には使わない。
			require( (name.starts_with( L"current/campaign-") ||
					 name.starts_with( L"runs/campaign-budget-")) &&
					names.insert( name).second && hash( str( row, L"hash"))) ;
			// 登録時hashと照合する原byte。
			std::string raw ;
			bool		found{} ;	// 不変byteの確認。
			io( store->read( name, raw, found)) ;
			require( found && sha( raw) == str( row, L"hash")) ;
			inputBytes +=
				winrt::to_string( name) + "\n" + winrt::to_string( str( row, L"hash")) + "\n" ;
		}

		return sha( inputBytes) ;
	}

	/** @brief 初回登録を全検査後だけ行います。
	 * @param[in] legacy 旧v4全履歴。
	 */
	void enroll( const CollectorLegacySnapshot &legacy)
	{
		const auto budgetBody	 = read( *store, BUDGET) ;			// 登録前の共通予算。
		const auto budgetMarker	 = read( *store, BUDGET_MARKER) ;	// 片側欠損を拒否する。
		const auto controlBody	 = read( *store, CONTROL) ;			// 登録前の独立待機。
		const auto controlMarker = read( *store, CONTROL_MARKER) ;	// 片側欠損を拒否する。
		require( budgetBody.has_value() == budgetMarker.has_value() &&
				controlBody.has_value() == controlMarker.has_value()) ;
		std::optional<CollectorBudgetSnapshot> oldBudget ;	// 旧予算を新規へ戻さない。
		// 既存予算は空の新予算へ置換せず共有codecで読む。
		if( budgetBody) {
			oldBudget = budget() ;
		}

		CollectorWaitSnapshot table{now, {}} ;	// 履歴なしの場合だけ初期化する。
		// 既存の待機期限と要確認条件を保持する。
		if( controlBody) {
			table = controls() ;
		}

		// 開始intentは元v1で先に回収が必要。
		for( const auto &[name, row] : table.controls) {
			// 応答未回収の開始intentがあれば登録前に止める。
			if( row.started != 0U) {
				reason = L"CORE_V1_RECOVERY_REQUIRED" ;
				throw DWORD( ERROR_RETRY) ;
			}
		}

		const auto priorFiles = legacyV1( oldBudget) ;	// 全旧契約を非変更で検証する。
		require( oldBudget || priorFiles.Size() == 0U ||
				(priorFiles.Size() == 1U && controlMarker.has_value())) ;
		// 元観測値から最大待機とreviewを統合する。
		for( const auto &wait : legacy.waits) {
			auto &group	   = table.controls[L"g-" + wait.group] ;	// Requestのgroup欠損を作らない。
			group.group	   = wait.group ;
			group.observed = std::max( {group.observed, wait.observed, now}) ;
			auto &row =
				wait.requestKey.empty()
					? group
					: table.controls[L"r-" + wait.requestKey] ;	// 公開requestだけを統合する。
			require( row.group.empty() || row.group == wait.group) ;
			row.group	  = wait.group ;
			row.request	  = wait.requestKey ;
			row.observed  = std::max( {row.observed, wait.observed, now}) ;
			row.notBefore = std::max( row.notBefore, wait.notBefore) ;
			row.review	  = row.review || wait.review ;
		}

		table.lastUtc		  = std::max( table.lastUtc, now) ;
		const auto newControl = controlBytes( table) ;	// 保存前に全上限を確認する。
		const auto newBudget  = budgetBytes( oldBudget.value_or(
			 CollectorBudgetSnapshot{day( now), now / 1000U, {}})) ;	// 旧予算の日付を変えない。
		// 端末名やuser情報を含まない新rootのGUID。
		GUID	   guid{} ;
		wchar_t	   guidText[40]{} ;	// 端末情報なしのroot identity。
		require( SUCCEEDED( CoCreateGuid( &guid)) && StringFromGUID2( guid, guidText, 40) != 0) ;
		root = make( projectedRequested ? L"collector-campaign-root-v3"
									   : L"collector-campaign-root-v2") ;
		put( root, L"rootKey", sha( winrt::to_string( guidText))) ;
		put( root, L"lastUtcMillis", now) ;
		put( root, L"legacyDigest", legacyDigest( legacy, priorFiles)) ;
		put( root, L"legacyFileCount",
			static_cast<std::uint64_t>( legacy.fileCount) + priorFiles.Size()) ;
		put( root, L"legacyLastUsedDay", legacy.lastUsedDay) ;
		root.Insert( L"legacyFiles", priorFiles) ;
		root.Insert( L"generations", Array()) ;
		root.Insert( L"archives", Array()) ;
		put( root, L"activeGeneration", L"") ;
		root.Insert( L"commit", Value::CreateNullValue()) ;
		// 初回rootは旧rootを移行した履歴を持たない。
		if( projectedRequested) {
			root.Insert( L"upgradeFrom", Value::CreateNullValue()) ;
			root.Insert( L"cacheInventory", Array()) ;
		}

		const auto mode = make( L"collector-campaign-mode-v1") ;	// Immutableのv1混用拒否marker。
		put( mode, L"rootKey", str( root, L"rootKey")) ;
		// 全検査後、初回登録だけを固定順に保存する。途中登録は次回拒否する。
		save( *store, MODE, bytes( mode), true) ;
		// 両側欠損を検証済みの初回だけbudget markerを作る。
		if( !budgetMarker) {
			save( *store, BUDGET_MARKER, "collector-campaign-budget-root-v1", true) ;
		}

		// 旧budgetが存在する場合は一切置換しない。
		if( !budgetBody) {
			save( *store, BUDGET, newBudget) ;
		}

		// 初回だけcontrol markerを作成する。
		if( !controlMarker) {
			save( *store, CONTROL_MARKER, "collector-campaign-controls-root-v1", true) ;
		}

		save( *store, CONTROL, newControl) ;
		saveRoot() ;
		checkpoint( CollectorRecoveryCheckpoint::ROOT_ENROLLED) ;
	}

	/** @brief 回収済みでactive世代がない旧rootを同じ物理入口へ移行します。 */
	void upgradeRoot()
	{
		require( str( root, L"schema") == L"collector-campaign-root-v2" &&
				str( root, L"activeGeneration").empty() &&
				root.GetNamedValue( L"commit").ValueType() ==
					winrt::Windows::Data::Json::JsonValueType::Null) ;
		const auto before = required( *store, ROOT) ;	// 実保存本文のhashへ移行を結合する。
		require( before == bytes( root)) ;
		checkpoint( CollectorRecoveryCheckpoint::BEFORE_ROOT_UPGRADE) ;
		put( root, L"schema", L"collector-campaign-root-v3") ;
		put( root, L"upgradeFrom", sha( before)) ;
		root.Insert( L"cacheInventory", Array()) ;
		// 旧登録が将来複数世代になっても保存versionを付け替えない。
		for( const auto &entry : root.GetNamedArray( L"generations")) {
			put( entry.GetObject(), L"storageVersion", 2ULL) ;
		}

		saveRoot() ;
		checkpoint( CollectorRecoveryCheckpoint::ROOT_UPGRADED) ;
	}

	/** @brief 全終端と元応答から完了の四本文を非変更で再導出します。
	 * @param[in] closedUtc 元intentへ固定する完了UTC。再起動時も変更しません。
	 * @param[in] verifiedOperations 全CACHE閉包で検査した元操作集合。通常初回保存はnull。
	 * @param[in] closing 現在末尾を完了する場合true。履歴の元時刻検査には使いません。
	 * @return intent、対象shard、summary、pointerの順のcanonical本文。
	 * @throws DWORD 元I/O／codec error、未終端1237または容量68。
	 */
	std::array<std::string, 4U> completionBodies(
		const std::uint64_t closedUtc, const std::set<std::wstring> *verifiedOperations = nullptr,
		const bool closing = false)
	{
		// 保存先の不在は元の形式拒否で止め、照合APIへ無効な参照を渡しません。
		if( store == nullptr) {
			throw static_cast<DWORD>( ERROR_INVALID_DATA) ;
		}

		require( storageVersion == 3U && str( root, L"schema") == L"collector-campaign-root-v3" &&
				(verifiedOperations || root.GetNamedArray( L"generations").Size() == 1U) &&
				!pendingRoll &&
				root.GetNamedValue( L"commit").ValueType() ==
					winrt::Windows::Data::Json::JsonValueType::Null &&
				(verifiedOperations && !closing ? closedUtc <= number( root, L"lastUtcMillis")
												: closedUtc >= number( root, L"lastUtcMillis")) &&
				closedUtc <= now && day( closedUtc) >= str( input, L"day")) ;
		const auto inputHash = sha( bytes( input)) ;	// 正本inputと保存像を再照合します。
		require( required( *store, path( L"runs/campaign-input-v3-", key)) == bytes( input) &&
				required( *store, path( L"runs/campaign-marker-v3-", key)) ==
					projectedMarker( inputHash) &&
				required( *store, statePath()) == bytes( jobs)) ;
		validateJobs( jobs, key, manifest, true, true) ;
		validateIntents( jobs) ;
		auto reservations = budget() ;	// 通常初回は当日、完了履歴は元日の精算先へ結合します。
		// 過去日の終端を現在日の空予算へ読み替えません。登録全archiveは呼出し側で検証済みです。
		if( verifiedOperations && reservations.day != str( input, L"day")) {
			require( parseCollectorBudgetSnapshot(
						required( *store, L"runs/campaign-budget-" + str( input, L"day") + L".json"),
						reservations) &&
					reservations.day == str( input, L"day")) ;
		}

		require( std::all_of( reservations.reservations.begin(), reservations.reservations.end(),
							[&]( const auto &row) {
								return row.phase != 0U ||
									   (verifiedOperations && row.campaign != key) ;
							})) ;
		// 未解放のprocess予約から先に完了を報告しません。
		for( const auto &binding : controlledBindings) {
			require( !binding) ;
		}

		// 独立controlの開始intentも全て閉じている必要があります。
		for( const auto &[name, control] : controls().controls) {
			require( control.started == 0U || (verifiedOperations && control.generation != key)) ;
		}

		// 全jobの独立検査済み応答を所有し、中断はnullのまま保持します。
		std::vector<std::optional<CollectorProjectedResponseBytes>> responses( manifest.jobs.size()) ;
		// 固定終端順の件数です。成功数やpayload取得数ではありません。
		std::map<std::wstring, std::uint64_t>						outcomes{{L"FETCHED", 0U},
																			 {L"HELD", 0U},
																			 {L"FAILED", 0U},
																			 {L"INTERRUPTED", 0U},
																			 {L"DEFERRED", 0U}} ;
		const auto rows = jobs.GetNamedArray( L"jobs") ;	// 元job順を維持します。
		// 全jobの元応答と四role精算を検査してから集計します。
		for( std::size_t index = 0U; index < manifest.jobs.size(); ++index) {
			const auto row	= rows.GetObjectAt( static_cast<std::uint32_t>( index)) ;	// 同順の終端。
			const auto name = str( row, L"state") ;										// 固定分類だけを数えます。
			require( name != L"PENDING" && name != L"RUNNING", ERROR_RETRY) ;
			require( outcomes.contains( name)) ;
			++outcomes.at( name) ;
			const auto response =
				// 元応答slot。
				storedResponse( operation( key, manifest.jobs[index].key)) ;
			// 未予約の延期には応答や予算を捏造しません。
			if( name == L"DEFERRED") {
				require( !response &&
						std::none_of( reservations.reservations.begin(),
									 reservations.reservations.end(), [&]( const auto &item) {
										 return item.campaign == key &&
												item.job == manifest.jobs[index].key ;
									 })) ;
				continue ;
			}

			require( response.has_value()) ;
			// 元応答・全四role・精算先・CACHE鎖を検査済みの操作だけを旧集計へ渡します。
			if( verifiedOperations) {
				require( verifiedOperations->contains( operation( key, manifest.jobs[index].key))) ;
			}

			const auto object =
				// 原v4 byteを再hashしません。
				Object::Parse( winrt::to_hstring( *response)) ;
			// 専用v4だけがmetadataを持ち、中断v2は未知のまま残します。
			if( str( object, L"schema") == L"collector-campaign-response-v4") {
				responses[index] = decodeSavedProjected( index, *response) ;
				require( responses[index]->value.accepted <= closedUtc) ;
				// 通常初回保存は従来の現CACHE照合を維持します。旧終端は閉包検査結果へ結合済みです。
				if( !verifiedOperations) {
					verifyTerminal( index, object, &*responses[index]) ;
				}
			} else {
				require( name == L"INTERRUPTED" && number( object, L"accepted") <= closedUtc) ;
				// 初回の中断も、過去CACHE鎖がない通常保存側では元検査を省略しません。
				if( !verifiedOperations) {
					verifyTerminal( index, object) ;
				}
			}
		}

		const auto shard = make( L"collector-campaign-targets-v1") ;	// 分母を減らさない一shard。
		put( shard, L"generation", key) ;
		put( shard, L"inputHash", inputHash) ;
		Array		  targets ;			// 最大300対象を元順序で保持します。
		std::uint64_t matched{} ;		// metadata MATCH対象数。実device適合数ではありません。
		std::uint64_t noMatch{} ;		// 全jobが明示NO_MATCHの対象数。
		std::uint64_t unknown{} ;		// 部分・失敗・不足の対象数。
		std::uint64_t unsupported{} ;	// jobのない対象数。
		std::uint64_t references{} ;	// 各対象内で重複除去したrecord参照の合計。
		// 元対象と全beneficiary jobを再照合し、成功recordを保留から借用しません。
		for( std::size_t index = 0U; index < manifest.targets.size(); ++index) {
			Object target ;	// 公開IDと元indexだけを保存します。
			put( target, L"index", static_cast<std::uint64_t>( index)) ;
			put( target, L"id", manifest.targets[index].id) ;
			Array jobsForTarget ;							// 元job index集合。応答hashは元stateに結合済みです。
			bool  allNoMatch = true ;						// 不足が一件でもあれば明示不適合へ変換しません。
			std::set<std::array<std::byte, 32U>> records ;	// 同対象のstable fingerprint集合。
			// 固定job順で対象をbeneficiaryに持つ結果だけ集約します。
			for( std::size_t jobIndex = 0U; jobIndex < manifest.jobs.size(); ++jobIndex) {
				const auto &indices =
					manifest.jobs[jobIndex].targetIndices ;	// 元共有jobの対象集合。
				// 他対象の結果を成功の根拠にしません。
				if( std::find( indices.begin(), indices.end(), index) == indices.end()) {
					continue ;
				}

				jobsForTarget.Append( Value::CreateNumberValue( static_cast<double>( jobIndex))) ;
				bool hasNoMatch = false ;	// 当job内の採用済み明示矛盾だけでtrueにします。
				// v2中断・保留・失敗のmetadataを採用しません。
				if( responses[jobIndex] && responses[jobIndex]->value.metadata.outcome ==
											  CollectorMetadataOutcome::FETCHED) {
					const auto &metadata =
						responses[jobIndex]->value.metadata ;	// 独立codec検査済み。
					// 元target／sliceと採用sliceの結合を維持します。
					for( const auto &edge : metadata.edges) {
						// 当edgeと同じ元sliceの採用だけを使用します。
						const bool accepted = std::any_of(
							metadata.slices.begin(), metadata.slices.end(), [&]( const auto &slice) {
								return slice.scope.key == edge.sliceKey &&
									   slice.disposition == CollectorMetadataDisposition::ACCEPTED ;
							}) ;
						// 当targetの採用されたsliceだけを集約します。
						if( edge.target.index != index || !accepted) {
							continue ;
						}

						hasNoMatch = edge.state == CollectorProjectedTargetState::NO_MATCH ;
						// MATCH record参照は元metadata検証済みfingerprintからだけ数えます。
						if( edge.state == CollectorProjectedTargetState::MATCH) {
							// 各target内の重複参照を排除します。
							for( const auto &fingerprint : edge.recordFingerprints) {
								records.insert( fingerprint.bytes) ;
							}
						}
					}
				}

				allNoMatch = allNoMatch && hasNoMatch ;
			}

			const auto state = jobsForTarget.Size() == 0U ? L"UNSUPPORTED"
							   : !records.empty()		  ? L"MATCH"
							   : allNoMatch				  ? L"NO_MATCH"
														  : L"UNKNOWN" ;	// 固定優先順。
			matched += !records.empty() ? 1U : 0U ;
			unsupported += jobsForTarget.Size() == 0U ? 1U : 0U ;
			noMatch += jobsForTarget.Size() != 0U && records.empty() && allNoMatch ? 1U : 0U ;
			unknown += jobsForTarget.Size() != 0U && records.empty() && !allNoMatch ? 1U : 0U ;
			references += records.size() ;
			target.Insert( L"jobs", jobsForTarget) ;
			put( target, L"metadataState", state) ;
			put( target, L"matchedRecords", static_cast<std::uint64_t>( records.size())) ;
			targets.Append( target) ;
		}

		shard.Insert( L"targets", targets) ;
		const auto shardBody = bytes( shard) ;								// Summaryはこの本文hashへ結合します。
		const auto summary	 = make( L"collector-campaign-summary-v1") ;	// 全件成功ではない完了。
		put( summary, L"generation", key) ;
		put( summary, L"inputHash", inputHash) ;
		put( summary, L"stateHash", sha( bytes( jobs))) ;
		put( summary, L"closedUtcMillis", closedUtc) ;
		put( summary, L"targetShardHash", sha( shardBody)) ;
		put( summary, L"targetCount", static_cast<std::uint64_t>( manifest.targets.size())) ;
		put( summary, L"jobCount", static_cast<std::uint64_t>( manifest.jobs.size())) ;
		put( summary, L"metadataMatchedTargets", matched) ;
		put( summary, L"metadataNoMatchTargets", noMatch) ;
		put( summary, L"metadataUnknownTargets", unknown) ;
		put( summary, L"unsupportedTargets", unsupported) ;
		put( summary, L"matchedRecordReferences", references) ;
		Array counts ;	// 五終端を0件も含めて保持します。
		// 固定map順の全分類を出力し、失敗を分母から除外しません。
		for( const auto &[name, count] : outcomes) {
			Object outcome ;	// 元job状態別の件数だけを保存します。
			put( outcome, L"state", name) ;
			put( outcome, L"count", count) ;
			counts.Append( outcome) ;
		}

		summary.Insert( L"jobOutcomes", counts) ;
		summary.Insert( L"researchOnly", Value::CreateBooleanValue( true)) ;
		summary.Insert( L"publishable", Value::CreateBooleanValue( false)) ;
		summary.Insert( L"downloadEligible", Value::CreateBooleanValue( false)) ;
		const auto summaryBody = bytes( summary) ;							// pointerとrootが同じhashを参照します。
		const auto pointer	   = make( L"collector-campaign-current-v2") ;	// 完了世代専用の固定形。
		put( pointer, L"generation", key) ;
		put( pointer, L"summaryHash", sha( summaryBody)) ;
		const auto pointerBody = bytes( pointer) ;						// 任意pathや配布URLを持ちません。
		const auto intent = make( L"collector-campaign-finish-v1") ;	// 元時刻と全像を固定します。
		put( intent, L"rootKey", str( root, L"rootKey")) ;
		put( intent, L"generation", key) ;
		put( intent, L"inputHash", inputHash) ;
		put( intent, L"stateHash", sha( bytes( jobs))) ;
		put( intent, L"closedUtcMillis", closedUtc) ;
		put( intent, L"targetShardHash", sha( shardBody)) ;
		put( intent, L"summaryHash", sha( summaryBody)) ;
		put( intent, L"pointerHash", sha( pointerBody)) ;
		std::array<std::string, 4U> result{bytes( intent), shardBody, summaryBody,
										   pointerBody} ;	// 固定保存順。
		// 既存本文上限を完了記録だけで拡張しません。
		for( const auto &body : result) {
			require( body.size() <= 768U * 1024U, ERROR_TOO_MANY_NAMES) ;
		}

		return result ;
	}

	/** @brief 完了intentと全生成物の固定prefixを非変更検査します。
	 * @return intent未保存ならnullopt。保存済みなら元時刻から再導出した四本文。
	 */
	std::optional<std::array<std::string, 4U>> inspectCompletion()
	{
		const auto registration = root.GetNamedArray( L"generations").GetObjectAt( 0U) ;	// 現一世代。
		const auto summaryHash	= str( registration, L"summaryHash") ;						// 空だけが未確定です。
		const auto intentBody =
			// 最初の保存物。
			read( *store, path( L"runs/campaign-finish-v1-", key)) ;
		const std::array<std::filesystem::path, 3U> names{
			path( L"runs/campaign-targets-v1-", key), path( L"runs/campaign-summary-v1-", key),
			FINISH_POINTER} ;	// 組み込み保存順だけを許します。
		// Intentのない生成物やroot完了登録を許可しません。
		if( !intentBody) {
			require( summaryHash.empty() && str( root, L"activeGeneration") == key) ;
			// 登録もない片側生成物を自動修復しません。
			for( const auto &name : names) {
				require( !read( *store, name)) ;
			}

			return std::nullopt ;
		}

		const auto intent = json( *intentBody) ;								// 任意追加fieldも再導出一致で拒否します。
		auto result = completionBodies( number( intent, L"closedUtcMillis")) ;	// 元時刻を固定します。
		require( result[0] == *intentBody &&
				(summaryHash.empty() ? str( root, L"activeGeneration") == key
									 : hash( summaryHash) && summaryHash == sha( result[2]) &&
										   str( root, L"activeGeneration").empty())) ;
		bool missing = false ;	// 保存済み像は常に先頭から連続している必要があります。
		// 全prefix検査を済ませてから、後続の回復が書き込みます。
		for( std::size_t index = 0U; index < names.size(); ++index) {
			const auto body = read( *store, names[index]) ;	// 欠損と異なる像を区別します。
			// 登録前の末尾欠損だけが準備中として許されます。
			if( !body) {
				require( summaryHash.empty()) ;
				missing = true ;
			} else {
				require( !missing && *body == result[index + 1U]) ;
			}
		}

		return result ;
	}

	/** @brief 初回完了の不足suffixを元像から保存し、最後にrootを確定します。 */
	void finishGeneration()
	{
		auto	   saved		= inspectCompletion() ;										// 書込み前に全像と逆順を検査します。
		const auto registration = root.GetNamedArray( L"generations").GetObjectAt( 0U) ;	// 現一世代。
		// 完了済みは何も再保存しません。
		if( !str( registration, L"summaryHash").empty()) {
			return ;
		}

		const auto bodies = saved ? std::move( *saved) : completionBodies( now) ;	// 再起動も元時刻。
		CollectorStoreUsage usage ;													// 残留stagingを含めた完了の現物保存枠。
		io( store->inspectUsage( usage)) ;
		require( usage.runEntries <= 4096U - 3U && usage.currentEntries <= 4096U - 2U &&
					usage.bytes <= 5ULL * 1024U * 1024U * 1024U - 10ULL * 1024U * 1024U,
				ERROR_TOO_MANY_NAMES) ;
		save( *store, path( L"runs/campaign-finish-v1-", key), bodies[0], true) ;
		checkpoint( CollectorRecoveryCheckpoint::FINISH_INTENT) ;
		const std::array<std::filesystem::path, 3U> names{
			path( L"runs/campaign-targets-v1-", key), path( L"runs/campaign-summary-v1-", key),
			FINISH_POINTER} ;	// 固定順でsuffixだけを作成します。
		const std::array<CollectorRecoveryCheckpoint, 3U> points{
			CollectorRecoveryCheckpoint::FINISH_SHARD, CollectorRecoveryCheckpoint::FINISH_SUMMARY,
			CollectorRecoveryCheckpoint::FINISH_POINTER} ;	// 各atomic保存窓の試験用観測。
		// 既に検査済みのprefixはimmutable一致で保持します。
		for( std::size_t index = 0U; index < names.size(); ++index) {
			save( *store, names[index], bodies[index + 1U], true) ;
			checkpoint( points[index]) ;
		}

		(void)inspectCompletion() ;
		put( registration, L"summaryHash", sha( bodies[2])) ;
		put( root, L"activeGeneration", L"") ;
		put( root, L"lastUtcMillis", number( json( bodies[0]), L"closedUtcMillis")) ;
		// 回復時計ではなく元intentの時計を確定し、同じ呼出しから新世代を始めません。
		save( *store, ROOT, bytes( root)) ;
		checkpoint( CollectorRecoveryCheckpoint::FINISH_REGISTERED) ;
	}

	/** @brief 全履歴検査済み末尾完了の不足suffixを保存し、最後に元時刻で登録します。
	 * @param[in] bodies 元closedUtcMillisから独立再導出したintent・shard・summary・pointer。
	 * @throws DWORD 保存前の容量拒否・元I/O／checkpoint error。第一失敗後は再保存しません。
	 */
	void saveNextCompletion( const std::array<std::string, 4U> &bodies)
	{
		const auto rows	  = root.GetNamedArray( L"generations") ;			// 検査済みの元登録順。
		const auto tail	  = rows.GetObjectAt( rows.Size() - 1U) ;			// 未登録の最後だけ。
		const auto closed = number( json( bodies[0]), L"closedUtcMillis") ;	// 復旧UTCではありません。
		require( rows.Size() > 1U && nextProjected && str( tail, L"generation") == key &&
				str( tail, L"summaryHash").empty() && str( root, L"activeGeneration") == key &&
				required( *store, ROOT) == bytes( root)) ;
		CollectorStoreUsage usage ;	// Atomic stagingも含む従来の有限保存枠です。
		io( store->inspectUsage( usage)) ;
		require( usage.runEntries <= 4096U - 3U && usage.currentEntries <= 4096U - 2U &&
					usage.bytes <= 5ULL * 1024U * 1024U * 1024U - 10ULL * 1024U * 1024U,
				ERROR_TOO_MANY_NAMES) ;
		const std::array<std::filesystem::path, 4U> names{
			path( L"runs/campaign-finish-v1-", key), path( L"runs/campaign-targets-v1-", key),
			// 実保存順を保ちます。
			path( L"runs/campaign-summary-v1-", key), FINISH_POINTER} ;
		const std::array<CollectorRecoveryCheckpoint, 4U> points{
			CollectorRecoveryCheckpoint::FINISH_INTENT, CollectorRecoveryCheckpoint::FINISH_SHARD,
			CollectorRecoveryCheckpoint::FINISH_SUMMARY,
			CollectorRecoveryCheckpoint::FINISH_POINTER} ;	// 書込んだ窓だけ通知します。
		// 既存prefixを再保存せず、不足像と未反映pointerだけを元byteで保存します。
		for( std::size_t index = 0U; index < names.size(); ++index) {
			const auto existing = read( *store, names[index]) ;	// 原I/Oを保持し、同値は非変更です。
			// 一致済みのimmutable像もpointerも書込みません。
			if( existing && *existing == bodies[index]) {
				continue ;
			}

			require( !existing || index == 3U) ;
			save( *store, names[index], bodies[index], index != 3U) ;
			checkpoint( points[index]) ;
		}

		// ROOTの確定より先に全保存像の元byteを再確認します。
		for( std::size_t index = 0U; index < names.size(); ++index) {
			require( required( *store, names[index]) == bodies[index]) ;
		}

		put( tail, L"summaryHash", sha( bodies[2])) ;
		put( root, L"activeGeneration", L"") ;
		put( root, L"lastUtcMillis", closed) ;
		save( *store, ROOT, bytes( root)) ;
		checkpoint( CollectorRecoveryCheckpoint::FINISH_REGISTERED) ;
		nextProjected		= false ;
		nextDispatchEnabled = false ;
	}

	/** @brief 元応答から未登録四role準備prefixを再導出して非変更検査します。
	 * @param[in,out] reader 更新前全履歴と同じ有限raw読取り。
	 * @param[in] index 元RUNNINGまたは部分開始行の有限index。
	 * @param[in,out] expected 一致した元応答と準備像だけを加える固定名集合。
	 * @param[in] allowPrepared 通常起動の未登録応答回復だけがtrueです。
	 * @return 保存v4／canonical v2中断があればtrue、不在ならfalse。未知形式・穴は拒否します。
	 */
	bool inspectPreparedNextResponse( RegisteredHistoryReader &reader, const std::size_t index,
									 std::set<std::wstring> &expected, const bool allowPrepared)
	{
		const auto op		= operation( key, manifest.jobs[index].key) ;	// 元入力の一応答slot。
		const auto response = storedResponse( op) ;							// 併存拒否と独立v4 decodeを有限readerへ含めます。
		// 応答なしを成功や中断へ補完しません。未知effectは全名検査で拒否します。
		if( !response) {
			return false ;
		}

		require( allowPrepared) ;
		const auto decoded =
			// 元envelopeを再符号化しません。
			decodeNextRecoveryResponse( index, *response) ;
		// 登録commitの監督時計は元acceptedより新しくても、検査済み同一操作だけを復旧します。
		require( number( json( *response), L"accepted") >= number( root, L"lastUtcMillis") ||
				(reader.registeredOperation && *reader.registeredOperation == op)) ;
		const std::array<std::string, 3U> before{reader.mandatory( CONTROL),
												 reader.mandatory( statePath()),
												 // 物理台帳は未反映値だけ。
												 reader.mandatory( BUDGET)} ;
		const auto						  after =
			// 元予約・二時計・期限も再照合。
			derive( index, json( *response), before, decoded ? &*decoded : nullptr) ;
		const auto &request = definition.requestKeys[index] ;	// 元scopeのrequestだけを選びます。
		const auto	beforeCache =
			// 全閉包検査済み前値。
			reader.body( path( L"current/campaign-cache-v1-", request)) ;
		require( registeredCache( request) == (beforeCache ? sha( *beforeCache) : L"")) ;
		const auto afterCache =
			initialResponseCache( index, json( *response), decoded ? &*decoded : nullptr,
								 beforeCache) ;	// 元slice最終化済み値。
		const std::array<std::wstring, 4U>				 roles{L"CONTROL", L"CACHE", L"JOB",
												   L"BUDGET"} ;	// 固定適用順。
		const std::array<std::optional<std::string>, 4U> beforeRoles{
			before[0], beforeCache, before[1], before[2]} ;	// 新requestだけCACHE前像なし。
		const std::array<std::string, 4U> afterRoles{after[0], afterCache, after[1],
													 after[2]} ;	// 同じ再導出結果。
		bool							  gap{} ;					// 保存順の欠損後に像を許可しません。
		// 最大八像を既存addEffectと同じ保存順・省略条件で検査します。
		for( std::size_t role = 0U; role < roles.size(); ++role) {
			const bool unchanged =
				beforeRoles[role] && *beforeRoles[role] == afterRoles[role] ;	// 不変roleは保存なし。
			// 更新前像、更新後像の順を保持して連続prefixだけを許します。
			for( unsigned image = 0U; image < 2U; ++image) {
				const auto name =
					// Caller名は受け取りません。
					effectPath( op, roles[role], image == 0U, true) ;
				const auto value  = reader.body( name) ;	// 不在も終了時再照合します。
				const auto wanted = image == 0U
										? beforeRoles[role]
										: std::optional<std::string>(
											  afterRoles[role]) ;	// 実元値または独立再導出値。
				// 省略すべき像が存在した場合は後続の順序にも関係なく拒否します。
				if( unchanged || !wanted) {
					require( !value) ;
					continue ;
				}

				// 存在する像はprefix内かつcanonical全byte一致が必須です。
				if( value) {
					require( !gap && *value == *wanted) ;
					expected.insert( name.generic_wstring()) ;
				} else {
					gap = true ;
				}
			}
		}

		expected.insert(
			path( decoded ? L"runs/campaign-response-v4-" : L"runs/campaign-response-v2-", op)
				.generic_wstring()) ;
		return true ;
	}

	/** @brief 未完了末尾を元予約・精算済み閉包へ非変更で結合します。
	 * @param[in,out] reader 全完了prefixと同じ有限raw読取り。
	 * @param[in] sources 現組み込みsource契約。
	 * @param[in,out] expected 元入力・marker・stateと検証済み元操作の固定名を加える集合。
	 * @param[in] verifiedOperations 全CACHE閉包の検査済み元操作集合。
	 * @param[in,out] completedOperations 末尾の精算済み元操作を一回追加します。
	 * @param[in] allowPrepared 通常起動だけ未登録v4と四role準備prefixを別検査します。
	 * @param[in] allowPartialStart 起動／明示中断だけ単一PENDINGの最後の予約を認めます。
	 * @param[in] allowFinish 通常起動だけ末尾完了intentを後続の全prefix検査へ渡します。
	 * @throws DWORD 元I/O／codec errorまたは関係拒否。
	 */
	void inspectActiveProjectedTail( RegisteredHistoryReader						  &reader,
									const std::span<const CollectorCampaignSource> sources,
									std::set<std::wstring>						  &expected,
									const std::set<std::wstring> &verifiedOperations,
									std::set<std::wstring>		 &completedOperations,
									const bool allowPrepared, const bool allowPartialStart,
									const bool allowFinish)
	{
		const auto rows = root.GetNamedArray( L"generations") ;	// 検査済みの元登録順。
		require( rows.Size() > 1U) ;
		const auto tail = rows.GetObjectAt( rows.Size() - 1U) ;	// 未完了は末尾だけ。
		require( str( tail, L"generation") == str( root, L"activeGeneration") &&
				number( tail, L"storageVersion") == 3U && str( tail, L"summaryHash").empty()) ;
		loadGeneration( str( tail, L"generation"), str( tail, L"inputHash"), 3U) ;
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
			campaign ;	// 元sourceへ再結合する入力。
		require( prepareCollectorProjectedCampaign( bytes( input), str( tail, L"inputHash"), key,
												  definition.artifactSha256, sources, campaign)) ;
		const auto reservations = budget() ;	// 同日共有予算。旧精算もprefix側で再検査する。
		const auto control		= controls() ;	// 永続開始intentと待機を区別する。
		require( reservations.day == str( input, L"day")) ;
		std::set<std::wstring> runningJobs ;					// 未精算の元job集合。
		std::set<std::wstring> runningRequests ;				// controlの逆照合用。
		std::set<std::wstring> settledJobs ;					// 元閉包へ結合した精算済みjob。
		std::size_t preparedCount{} ;							// 単一writerの未登録応答一件だけを回復対象にします。
		std::size_t partialCount{} ;							// 単一writerの開始保存途中は一件だけ。
		const auto	jobsRows = jobs.GetNamedArray( L"jobs") ;	// 元job順を保持する。
		// 最大300行の末尾stateを、元予約または検査済み精算へ結合します。
		for( std::size_t index = 0U; index < manifest.jobs.size(); ++index) {
			const auto	row	 = jobsRows.GetObjectAt( static_cast<std::uint32_t>( index)) ;	// 元一行。
			const auto &job	 = manifest.jobs[index] ;										// 元groupと上限。
			const auto	name = str( row, L"state") ;										// 未予約・稼働・精算済みの有限状態。
			require( name == L"PENDING" || name == L"DEFERRED" || name == L"RUNNING" ||
					name == L"FETCHED" || name == L"HELD" || name == L"FAILED" ||
					name == L"INTERRUPTED") ;
			const auto matching = [&]( const auto &reservation) {
				return reservation.campaign == key && reservation.job == job.key ;
			} ; // 現世代の元jobだけを選ぶ同期述語。
			const auto reserved =
				std::find_if( reservations.reservations.begin(), reservations.reservations.end(),
							 matching) ;	// 同じ予算の元予約。
			// 専用復旧検査だけが最後のPENDING予約を元保存順へ結合します。
			if( name == L"PENDING" || name == L"DEFERRED") {
				// 真の未予約行には応答や開始像を作りません。
				if( reserved == reservations.reservations.end()) {
					continue ;
				}

				require( allowPartialStart && name == L"PENDING" && ++partialCount <= 1U) ;
				validatePartialProjectedStart( index, row, reservations, control) ;
				reader.partialStartVerified = true ;
				runningJobs.insert( job.key) ;
				const auto &request = definition.requestKeys[index] ;			// 元の部分開始だけ。
				const auto	current = control.controls.find( L"r-" + request) ;	// 不在prefixも保持。
				// 開始CONTROL保存済みの場合だけ逆照合対象へ加えます。
				if( current != control.controls.end() && current->second.started != 0U) {
					runningRequests.insert( request) ;
				}

				// 中断保存後の準備prefixも全履歴・同一元予約の検査を省略しません。
				if( inspectPreparedNextResponse( reader, index, expected, allowPrepared)) {
					require( ++preparedCount <= 1U) ;
				}

				continue ;
			}

			// 精算済み行は元応答・全前後像を検証したCACHE閉包だけへ結合します。
			if( name != L"RUNNING") {
				const auto op = operation( key, job.key) ;	// 元の一操作。
				require( reserved != reservations.reservations.end() && reserved->phase != 0U &&
						verifiedOperations.contains( op) && completedOperations.insert( op).second &&
						settledJobs.insert( job.key).second) ;
				expected.insert( path( L"runs/campaign-response-v2-", op).generic_wstring()) ;
				expected.insert( path( L"runs/campaign-response-v4-", op).generic_wstring()) ;
				// 元閉包で検証した四roleの固定名だけを許します。
				for( const auto role : {L"CONTROL", L"JOB", L"BUDGET", L"CACHE"}) {
					expected.insert( effectPath( op, role, true, true).generic_wstring()) ;
					expected.insert( effectPath( op, role, false, true).generic_wstring()) ;
				}

				continue ;
			}

			const auto	started = number( row, L"started") ;				// 元秒境界の開始UTC。
			const auto &request = definition.requestKeys[index] ;			// 再構築した元request。
			const auto	current = control.controls.find( L"r-" + request) ;	// 元開始control。
			require( reserved != reservations.reservations.end() && reserved->phase == 0U &&
					reserved->group == job.source.rateLimitGroup &&
					reserved->started * 1000U == started &&
					reserved->maximum == job.source.maximumResponseBytes &&
					reserved->charged == reserved->maximum && started <= now &&
					current != control.controls.end() && current->second.generation == key &&
					current->second.job == job.key && current->second.request == request &&
					current->second.group == job.source.rateLimitGroup &&
					current->second.started == started && current->second.observed >= started &&
					runningJobs.insert( job.key).second && runningRequests.insert( request).second) ;
			// 全履歴検査後の共有更新は一件だけ。応答なしの他予約は非変更で残します。
			if( inspectPreparedNextResponse( reader, index, expected, allowPrepared)) {
				require( ++preparedCount <= 1U) ;
			}
		}

		// 末尾以外の未精算や、元jobのない予約を許可しない。
		for( const auto &reservation : reservations.reservations) {
			// 旧閉鎖済みの予約は全CACHE／完了prefixの検査へ残す。
			if( reservation.phase == 0U || reservation.campaign == key) {
				require( reservation.campaign == key &&
						(reservation.phase == 0U ? runningJobs.contains( reservation.job)
												 : settledJobs.contains( reservation.job))) ;
			}
		}

		// 取り残された開始controlを別requestの正当な予約へ読み替えない。
		for( const auto &[name, row] : control.controls) {
			// 開始値0の旧待機・groupは完了prefix側で検査する。
			if( row.started != 0U) {
				require( row.generation == key && runningJobs.contains( row.job) &&
						runningRequests.contains( row.request) && name == L"r-" + row.request) ;
			}
		}

		expected.insert( path( L"runs/campaign-input-v3-", key).generic_wstring()) ;
		expected.insert( path( L"runs/campaign-marker-v3-", key).generic_wstring()) ;
		expected.insert( statePath().generic_wstring()) ;
		require( allowFinish || !reader.body( path( L"runs/campaign-finish-v1-", key))) ;
	}

	/** @brief 全CACHE閉包の検査後に全完了世代と元日精算を非変更で再結合します。
	 * @param[in,out] reader 呼出し全体で共有する有限raw読取り。保存は行いません。
	 * @param[in] sources 現組み込みsource契約。保存sourceから権限を作りません。
	 * @param[in] verifiedOperations 全登録CACHEの検査済み元操作集合。外部から受け取りません。
	 * @param[in] allowActive 内部入口だけが未完了末尾を予約と精算の別検査へ結合します。
	 * @param[in] allowPrepared 通常起動だけが元応答・未登録準備prefixを認めます。
	 * @param[in] allowPartialStart 起動／明示中断の二開始prefixだけを追加検査します。
	 * @param[in] allowFinish 通常起動だけ末尾完了の固定連続prefixを追加検査します。
	 * @throws DWORD 元I/O／codec error、不完全登録13、有限容量68。
	 * @note 保存を行いません。公開入口は全完了だけ、内部入口は未完了末尾を別検査へ結合します。
	 */
	void inspectCompletedHistory( RegisteredHistoryReader					   &reader,
								 const std::span<const CollectorCampaignSource> sources,
								 const std::set<std::wstring>				   &verifiedOperations,
								 const bool allowActive = false, const bool allowPrepared = false,
								 const bool allowPartialStart = false,
								 const bool allowFinish		  = false)
	{
		require( store && historyReader == &reader && reader.names &&
				(allowActive || str( root, L"activeGeneration").empty()) && !pendingRoll &&
				root.GetNamedValue( L"commit").ValueType() ==
					winrt::Windows::Data::Json::JsonValueType::Null) ;
		std::set<std::wstring> expected{
			ROOT,		   MODE,		   BUDGET,		  CONTROL,
			BUDGET_MARKER, CONTROL_MARKER, FINISH_POINTER} ;	// 全完了の固定必須名。
		std::set<std::wstring> legacyNames ;					// 凍結legacyの重複／実raw変更を拒否します。
		std::set<std::wstring> completedOperations ;			// 末尾精算と完了prefixを一対一に結合します。
		// 日次専用検査で証明したintentと三準備像だけを許可名へ結合します。
		expected.insert( reader.dayRollNames.begin(), reader.dayRollNames.end()) ;
		// 登録commitから検査した固定destinationだけは、論理不在でも物理名を許します。
		for( const auto &[name, value] : reader.beforeView) {
			(void)value ;
			expected.insert( name.generic_wstring()) ;
		}

		// 未完了末尾は旧集計へ加えず、同じreaderで元予約／精算済み閉包へ結合します。
		if( allowActive && !str( root, L"activeGeneration").empty()) {
			inspectActiveProjectedTail( reader, sources, expected, verifiedOperations,
									   completedOperations, allowPrepared, allowPartialStart,
									   allowFinish) ;
		}

		// Rootに凍結された旧fileも同じreaderへ入れ、未知pathや自己宣言hashだけで受理しません。
		for( const auto &entry : root.GetNamedArray( L"legacyFiles")) {
			const auto row = entry.GetObject() ;	// 既存登録の固定pathと原raw hash。
			fields( row, {L"name", L"hash"}) ;
			const auto name = str( row, L"name") ;	// 保護storeの読取り専用相対名。
			require( (name.starts_with( L"current/campaign-") ||
					 name.starts_with( L"runs/campaign-budget-")) &&
					hash( str( row, L"hash")) && legacyNames.insert( name).second) ;
			const auto raw = reader.raw( name) ;	// 外側byteを登録hashへ照合します。
			require( raw && sha( *raw) == str( row, L"hash")) ;
			expected.insert( name) ;
		}

		const auto currentBudget = budget() ;	// 現在予算も閉じていることを先に検査します。
		require( allowActive ||
				std::all_of( currentBudget.reservations.begin(), currentBudget.reservations.end(),
							[]( const auto &reservation) { return reservation.phase != 0U ; })) ;
		// process内予約とは別に、保存共有controlの開始intent残留を拒否します。
		for( const auto &[name, control] : controls().controls) {
			require( allowActive || control.started == 0U) ;
		}

		const auto archives = root.GetNamedArray( L"archives") ;	// 最大300の検査済み登録順。
		std::set<std::wstring> rolls ;								// 一切替を別日に二重登録しません。
		// 各元日archiveと切替の二roleを原時刻で再導出し、次の日付へ連続結合します。
		for( std::uint32_t index = 0U; index < archives.Size(); ++index) {
			const auto registration = archives.GetObjectAt( index) ;				// 型は入口で検査済み。
			const auto date			= str( registration, L"day") ;					// 固定8桁名。
			const auto op			= str( registration, L"operation") ;			// 元切替hash。
			const auto archiveName	= L"runs/campaign-budget-" + date + L".json" ;	// 元日精算先。
			const auto body			= reader.mandatory( archiveName) ;				// 登録hashとの全byte結合。
			CollectorBudgetSnapshot prior ;											// 未精算予約や別日をarchiveへ閉じ込めません。
			require( sha( body) == str( registration, L"hash") &&
					parseCollectorBudgetSnapshot( body, prior) && prior.day == date &&
					std::all_of( prior.reservations.begin(), prior.reservations.end(),
								[]( const auto &reservation) { return reservation.phase != 0U ; }) &&
					rolls.insert( op).second) ;
			const auto intentName = path( L"runs/campaign-day-roll-v2-", op) ;	// 固定元intent。
			const auto intentBody = reader.mandatory( intentName) ;				// 任意現在時計へ延長しません。
			const auto intent	  = json( intentBody) ;							// 共通導出結果との完全照合用。
			const auto accepted	  = number( intent, L"accepted") ;				// 元切替時刻。
			require( accepted >= prior.lastUtc * 1000U &&
					accepted <= number( root, L"lastUtcMillis") &&
					bytes( rollIntent( body, accepted)) == intentBody &&
					str( intent, L"operation") == op &&
					str( intent, L"newDay") == (index + 1U < archives.Size()
												   ? str( archives.GetObjectAt( index + 1U), L"day")
												   : currentBudget.day)) ;
			const std::array<std::filesystem::path, 3U> effects{effectPath( op, L"BUDGET", true),
																effectPath( op, L"ARCHIVE", false),
																// 既存day-rollの固定保存順。
																effectPath( op, L"BUDGET", false)} ;
			require( reader.mandatory( effects[0]) == body && reader.mandatory( effects[1]) == body &&
					reader.mandatory( effects[2]) ==
						budgetBytes( {str( intent, L"newDay"), accepted / 1000U, {}})) ;
			expected.insert( archiveName) ;
			expected.insert( intentName.generic_wstring()) ;
			// 二roleの有限三像だけを許可名へ追加します。
			for( const auto &name : effects) {
				expected.insert( name.generic_wstring()) ;
			}
		}

		std::uint64_t previousClosed{} ;	// 登録順の完了時計を後退させません。
		std::string	  latestPointer ;		// 現pointerは最後の完了世代だけを参照します。
		// 最大300世代を元登録順に検査し、各集計は現在CACHEではなく元応答から再導出します。
		for( const auto &entry : root.GetNamedArray( L"generations")) {
			const auto registration = entry.GetObject() ;	// 全完了・保存版3を入口で検査済み。
			// 未完了末尾は上の元予約／精算検査を使い、完了像を捏造しません。
			if( str( registration, L"summaryHash").empty()) {
				require( allowActive &&
						str( registration, L"generation") == str( root, L"activeGeneration")) ;
				continue ;
			}

			const auto g = str( registration, L"generation") ;	// 登録済み元G。
			loadGeneration( g, str( registration, L"inputHash"), 3U) ;
			std::shared_ptr<const CollectorPreparedProjectedCampaign>
				campaign ;	// source再結合の所有入力。
			require( prepareCollectorProjectedCampaign( bytes( input), str( registration, L"inputHash"),
													  g, definition.artifactSha256, sources,
													  campaign)) ;
			expected.insert( path( L"runs/campaign-input-v3-", g).generic_wstring()) ;
			expected.insert( path( L"runs/campaign-marker-v3-", g).generic_wstring()) ;
			expected.insert( statePath().generic_wstring()) ;
			const auto finishName = path( L"runs/campaign-finish-v1-", g) ;				// 元完了時刻の正本。
			const auto intentBody = reader.mandatory( finishName) ;						// 欠損は回復しません。
			const auto closed	  = number( json( intentBody), L"closedUtcMillis") ;	// 元完了時計。
			require( closed >= previousClosed) ;
			const auto bodies	 = completionBodies( closed, &verifiedOperations) ;	// 共通固定集計。
			const auto shardName = path( L"runs/campaign-targets-v1-", g) ;			// 全target分母。
			const auto summaryName = path( L"runs/campaign-summary-v1-", g) ;		// 旧成功数も不変です。
			require( intentBody == bodies[0] && reader.mandatory( shardName) == bodies[1] &&
					reader.mandatory( summaryName) == bodies[2] &&
					sha( bodies[2]) == str( registration, L"summaryHash")) ;
			previousClosed = closed ;
			latestPointer  = bodies[3] ;
			expected.insert( finishName.generic_wstring()) ;
			expected.insert( shardName.generic_wstring()) ;
			expected.insert( summaryName.generic_wstring()) ;
			// 検査済み終端操作の元応答と四roleだけを許可名へ結合します。延期には像を作りません。
			for( std::size_t index = 0U; index < manifest.jobs.size(); ++index) {
				const auto op  = operation( g, manifest.jobs[index].key) ;	// 元jobの有限操作。
				const auto row = jobs.GetNamedArray( L"jobs").GetObjectAt(
					// 元終端。
					static_cast<std::uint32_t>( index)) ;
				// 未予約延期の余剰応答／effectも未知名として拒否します。
				if( str( row, L"state") == L"DEFERRED") {
					continue ;
				}

				require( completedOperations.insert( op).second && verifiedOperations.contains( op)) ;
				expected.insert( path( L"runs/campaign-response-v2-", op).generic_wstring()) ;
				expected.insert( path( L"runs/campaign-response-v4-", op).generic_wstring()) ;
				// 初回の不在before-CACHEも固定する閉包検査を済ませてから全role名を許します。
				for( const auto role : {L"CONTROL", L"JOB", L"BUDGET", L"CACHE"}) {
					expected.insert( effectPath( op, role, true, true).generic_wstring()) ;
					expected.insert( effectPath( op, role, false, true).generic_wstring()) ;
				}
			}
		}

		require( completedOperations == verifiedOperations && !latestPointer.empty()) ;
		// 全末尾と旧履歴を検査してから、元完了時刻の固定prefixだけを導出します。
		if( allowFinish) {
			const auto rows = root.GetNamedArray( L"generations") ;	// 元登録順です。
			const auto tail = rows.GetObjectAt( rows.Size() - 1U) ;	// 未完了末尾だけを選びます。
			require( rows.Size() > 1U && str( tail, L"summaryHash").empty() &&
					str( tail, L"generation") == str( root, L"activeGeneration")) ;
			loadGeneration( str( tail, L"generation"), str( tail, L"inputHash"), 3U) ;
			const auto finishName = path( L"runs/campaign-finish-v1-", key) ;			// 固定元intent。
			const auto intentBody = reader.mandatory( finishName) ;						// 不在を補完しません。
			const auto closed	  = number( json( intentBody), L"closedUtcMillis") ;	// 元完了UTC。
			require( closed >= previousClosed) ;
			const auto bodies =
				// 全終端と元精算。
				completionBodies( closed, &verifiedOperations, true) ;
			const auto reservations = budget() ;	// Iteratorは同じ所有snapshotへ結合します。
			require( bodies[0] == intentBody &&
					std::all_of( reservations.reservations.begin(), reservations.reservations.end(),
								[]( const auto &row) { return row.phase != 0U ; })) ;
			// 完了保存中は共有CONTROLの開始残留も一件も許可しません。
			for( const auto &[name, row] : controls().controls) {
				require( row.started == 0U) ;
			}

			const std::array<std::filesystem::path, 2U> names{
				path( L"runs/campaign-targets-v1-", key),
				// 保存済み二像だけを許します。
				path( L"runs/campaign-summary-v1-", key)} ;
			bool gap{} ;	// 欠損後に保存物がある逆順を拒否します。
			// 先行の元intentと連続prefixを全byteで結合します。
			for( std::size_t index = 0U; index < names.size(); ++index) {
				const auto body = reader.body( names[index]) ;	// 原I/O・不在も再照合します。
				// 不在suffixは作成せず、取得済み像は元導出値に限ります。
				if( body) {
					require( !gap && *body == bodies[index + 1U]) ;
					expected.insert( names[index].generic_wstring()) ;
				} else {
					gap = true ;
				}
			}

			const auto pointer = reader.mandatory( FINISH_POINTER) ;	// 元旧値または保存順の新値だけ。
			require( pointer == latestPointer || (!gap && pointer == bodies[3])) ;
			expected.insert( finishName.generic_wstring()) ;
			reader.finishBodies = bodies ;
		} else {
			require( reader.mandatory( FINISH_POINTER) == latestPointer) ;
		}

		// 全CACHE登録は上の閉包で検査済みです。固定現在名だけを許可集合へ加えます。
		for( const auto &entry : root.GetNamedArray( L"cacheInventory")) {
			expected.insert( path( L"current/campaign-cache-v1-", str( entry.GetObject(), L"request"))
								.generic_wstring()) ;
		}

		// 最初に固定したcurrent／runs全名を登録・証明済み集合へ照合します。終了時に再列挙します。
		for( std::size_t directory = 0U; directory < 2U; ++directory) {
			const auto prefix = directory == 0U ? L"current/" : L"runs/" ;	// 二固定directoryだけ。
			// campaignの未知名／orphanを参照なしとして無視しません。
			for( const auto &name : (*reader.names)[directory]) {
				// 無関係な通常store資産へこのinventoryの所有権を広げません。
				if( name.starts_with( L"campaign-") || name == L"collector-campaign-mode-v1.json") {
					require( expected.contains( std::wstring( prefix) + name)) ;
				}
			}
		}
	}

	/** @brief 登録簿と全保存名を照合し、未知やorphanを拒否します。
	 * @param[in] sources 通常全完了検査に使う現在の組み込みsource契約。
	 * @param[in] allowPrepared 通常initializeだけが未登録応答と登録commitの論理前像検査を許可します。
	 * @return 全完了を有限coreで再検査した場合true。初回稼働／保存窓の場合false。
	 */
	bool inventory( const std::span<const CollectorCampaignSource> sources,
				   const bool									  allowPrepared = false)
	{
		const auto registeredGenerations =
			// 完了済みの登録順を保ちます。
			root.GetNamedArray( L"generations") ;
		// 全登録が完了済みの場合だけ共有coreへ渡し、稼働・保存途中へ制限を流用しません。
		if( str( root, L"schema") == L"collector-campaign-root-v3" &&
		   registeredGenerations.Size() > 0U &&
		   std::all_of( registeredGenerations.begin(), registeredGenerations.end(),
					   []( const auto &entry) {
						   const auto row = entry.GetObject() ;	// 空summaryは従来回復へ残します。
						   return !str( row, L"summaryHash").empty() ;
					   })) {
			require( projectedRequested) ;
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
						unused ;		// 通常検査はcontext・送信許可を発行しません。
			std::string verifiedRoll ;	// 全履歴と全raw再照合が成功した元intentだけです。
			io( LocalCollectorRecovery::inspectProjectedHistoryCore(
				*store, nullptr, sources, now, sha( bytes( root)), unused, {}, false, nullptr, false,
				false, false, allowPrepared, allowPrepared ? &verifiedRoll : nullptr)) ;
			// 全再照合成功前の候補を保存権限として監督へ保持しません。
			if( !verifiedRoll.empty()) {
				pendingRoll = json( verifiedRoll) ;
			}

			const auto latest = registeredGenerations.GetObjectAt(
				// 全proofと最新pointerを検査済みの最後のG。
				registeredGenerations.Size() - 1U) ;
			loadGeneration( str( latest, L"generation"), str( latest, L"inputHash"), 3U) ;
			CollectorStoreUsage usage ;	// 残留stagingを含む通常storeの使用量も省略しません。
			io( store->inspectUsage( usage)) ;
			return true ;
		}

		// 完了prefixと未完了末尾だけを内部の共通有限coreで検査します。
		if( projectedRequested && registeredGenerations.Size() > 1U &&
		   std::any_of(
			   registeredGenerations.begin(), registeredGenerations.end(),
			   []( const auto &entry) { return !str( entry.GetObject(), L"summaryHash").empty() ; })) {
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
					   unused ;	// 送信許可を発行しない。
			const auto tail = registeredGenerations.GetObjectAt( registeredGenerations.Size() -
																1U) ;	// 検査済み末尾。
			const bool finishing =
				allowPrepared &&
				read( *store, path( L"runs/campaign-finish-v1-", str( tail, L"generation")))
					.has_value() ;										// 証拠の存在だけで許可しません。
			std::optional<std::array<std::string, 4U>> verifiedFinish ;	// 全再照合後だけの値。
			io( LocalCollectorRecovery::inspectProjectedHistoryCore(
				*store, nullptr, sources, now, sha( bytes( root)), unused, {}, true, nullptr,
				allowPrepared && !finishing, allowPrepared && !finishing,
				allowPrepared && !finishing, false, nullptr, finishing,
				finishing ? &verifiedFinish : nullptr)) ;
			pendingFinish = std::move( verifiedFinish) ;
			loadGeneration( str( tail, L"generation"), str( tail, L"inputHash"), 3U) ;
			nextProjected = true ;
			CollectorStoreUsage usage ;	// 残留stagingも除外しない。
			io( store->inspectUsage( usage)) ;
			return false ;
		}

		std::set<std::wstring> expected{ROOT,	 MODE,			BUDGET,
										CONTROL, BUDGET_MARKER, CONTROL_MARKER} ;	// 共有の必須名。
		std::set<std::wstring> rollOperations ;										// 完了済みと登録済みの切替。
		// 凍結した旧v1だけを許す。
		for( const auto &entry : root.GetNamedArray( L"legacyFiles")) {
			expected.insert( str( entry.GetObject(), L"name")) ;
		}

		const auto generations =
			// 現経路は未完了または完了済みの初回一件に限定します。
			root.GetNamedArray( L"generations") ;
		require( generations.Size() <= 1U) ;
		std::set<std::wstring> keys ;	// 登録の重複を拒否する。
		// 全登録のinput／state／markerを非変更で検査する。
		for( const auto &entry : generations) {
			const auto row			 = entry.GetObject() ;	// 登録一行。
			const bool projectedRoot = str( root, L"schema") ==
									   L"collector-campaign-root-v3" ;	// Root schemaが分岐を決める。
			// Root v2へ新保存名だけを混入させない。
			if( projectedRoot) {
				fields( row, {L"generation", L"inputHash", L"summaryHash", L"storageVersion"}) ;
				require( number( row, L"storageVersion") == 2U ||
						number( row, L"storageVersion") == 3U) ;
			} else {
				fields( row, {L"generation", L"inputHash", L"summaryHash"}) ;
			}

			const auto version = projectedRoot
									 ? static_cast<std::uint32_t>( number( row, L"storageVersion"))
									 : 2U ;					// 検査済み版。
			const auto g	   = str( row, L"generation") ;	// 保存nameにも使う検証済みhash。
			require( hash( g) && hash( str( row, L"inputHash")) && keys.insert( g).second &&
					(str( row, L"summaryHash").empty() ||
					 (version == 3U && hash( str( row, L"summaryHash"))))) ;
			loadGeneration( g, str( row, L"inputHash"), version) ;
			expected.insert(
				path( version == 3U ? L"runs/campaign-input-v3-" : L"runs/campaign-input-v2-", g)
					.generic_wstring()) ;
			expected.insert(
				path( version == 3U ? L"runs/campaign-marker-v3-" : L"runs/campaign-marker-v2-", g)
					.generic_wstring()) ;
			expected.insert( statePath().generic_wstring()) ;
			// 未登録準備effectだけは同じjobの固定名で保持できる。
			for( const auto &job : manifest.jobs) {
				const auto op = operation( g, job.key) ;	// 元jobの有限保存slot。
				expected.insert( path( L"runs/campaign-response-v2-", op).generic_wstring()) ;
				// 新世代の実観測旧v3保存名は認めない。
				if( version == 2U) {
					expected.insert( path( L"runs/campaign-response-v3-", op).generic_wstring()) ;
				} else {
					expected.insert( path( L"runs/campaign-response-v4-", op).generic_wstring()) ;
				}

				const auto response = storedResponse( op) ;	// 併存・schemaも検査する。
				// 応答に許された三roleの前後像だけを一覧へ加える。
				for( const auto role : {L"CONTROL", L"JOB", L"BUDGET"}) {
					// 新effectは応答が先に保存されている場合だけ許す。
					if( version == 2U || response) {
						expected.insert(
							effectPath( op, role, true, version == 3U).generic_wstring()) ;
						expected.insert(
							effectPath( op, role, false, version == 3U).generic_wstring()) ;
					}
				}

				// 中断用CACHEは初回欠損前像のみ。前像fileがあれば未知名として拒否する。
				if( version == 3U && response) {
					expected.insert( effectPath( op, L"CACHE", false, true).generic_wstring()) ;
				}
			}
		}

		// 現CACHEは登録済みか、active四roleの一件だけを許す。
		if( str( root, L"schema") == L"collector-campaign-root-v3") {
			(void)registeredCache( L"") ;
			// 全CACHE登録を元job・元応答・現在fileの三者へ照合する。
			for( const auto &entry : root.GetNamedArray( L"cacheInventory")) {
				const auto row	   = entry.GetObject() ;		// 型はregisteredCacheが検査済み。
				const auto request = str( row, L"request") ;	// 登録された元jobへ逆照合。
				require( storageVersion == 3U &&
						std::find( definition.requestKeys.begin(), definition.requestKeys.end(),
								  request) != definition.requestKeys.end()) ;
				const auto name = path( L"current/campaign-cache-v1-", request) ;	// 固定名。
				require( sha( required( *store, name)) == str( row, L"hash")) ;
				const auto index = static_cast<std::size_t>(
					std::distance( definition.requestKeys.begin(),
								  std::find( definition.requestKeys.begin(),
											// 元一job。
											definition.requestKeys.end(), request))) ;
				const auto response =
					// 登録元。
					storedResponse( operation( key, manifest.jobs[index].key)) ;
				require( response.has_value()) ;
				const auto object =
					// 専用応答の原hashは維持。
					Object::Parse( winrt::to_hstring( *response)) ;
				const auto decoded = str( object, L"schema") == L"collector-campaign-response-v4"
										 ? std::optional<CollectorProjectedResponseBytes>(
											   decodeSavedProjected( index, *response))
										 : std::nullopt ;	// 現profileは初回一操作だけ。
				require(
					required( *store, name) ==
						initialResponseCache( index, object, decoded ? &*decoded : nullptr) &&
					str( jobs.GetNamedArray( L"jobs").GetObjectAt( static_cast<std::uint32_t>( index)),
						L"state") == str( object, L"state")) ;
				expected.insert( name.generic_wstring()) ;
			}

			// 反映途中のCACHEだけは後で全prefixを照合する。
			if( root.GetNamedValue( L"commit").ValueType() !=
				   winrt::Windows::Data::Json::JsonValueType::Null &&
			   str( root.GetNamedObject( L"commit"), L"kind") == L"PROJECTED_RESPONSE_V1") {
				expected.insert(
					destination( root.GetNamedObject( L"commit"), L"CACHE").generic_wstring()) ;
			}
		}

		require( generations.Size() == 0U
					? str( root, L"activeGeneration").empty()
					: key == str( root, L"activeGeneration") ||
						  (storageVersion == 3U && str( root, L"activeGeneration").empty() &&
						   hash( str( generations.GetObjectAt( 0U), L"summaryHash")))) ;
		// 初回完了は元intent／全像／順序と終端まで検査してから名前を許可します。
		if( generations.Size() == 1U && storageVersion == 3U && inspectCompletion()) {
			expected.insert( path( L"runs/campaign-finish-v1-", key).generic_wstring()) ;
			expected.insert( path( L"runs/campaign-targets-v1-", key).generic_wstring()) ;
			expected.insert( path( L"runs/campaign-summary-v1-", key).generic_wstring()) ;
			expected.insert( FINISH_POINTER) ;
		}

		// 完了した日次切替のeffectも永久に登録して消失を検出する。
		for( const auto &entry : root.GetNamedArray( L"archives")) {
			const auto archive = entry.GetObject() ;	// 完了した固定archive。
			fields( archive, {L"day", L"hash", L"operation"}) ;
			rollOperations.insert( str( archive, L"operation")) ;
			const auto name =
				L"runs/campaign-budget-" + str( archive, L"day") + L".json" ;	// 有限日付の固定名。
			CollectorBudgetSnapshot prior ;										// 元dayと閉鎖状態を確認する。
			// 登録済み旧日archiveのcanonical本文。
			const auto				body = required( *store, name) ;
			require( sha( body) == str( archive, L"hash") &&
					parseCollectorBudgetSnapshot( body, prior) && prior.day == str( archive, L"day")) ;
			require( std::all_of( prior.reservations.begin(), prior.reservations.end(),
								[]( const auto &r) { return r.phase != 0U ; })) ;
			expected.insert( name) ;
			// 日次切替の二roleの更新後像を保持する。
			for( const auto role : {L"ARCHIVE", L"BUDGET"}) {
				expected.insert(
					effectPath( str( archive, L"operation"), role, false).generic_wstring()) ;
			}

			expected.insert(
				effectPath( str( archive, L"operation"), L"BUDGET", true).generic_wstring()) ;
			const auto intentName = path( L"runs/campaign-day-roll-v2-",
										 // 完了後も元intentを検査する。
										 str( archive, L"operation")) ;
			// 完了後も保持した最初の切替intent。
			const auto intent = json( required( *store, intentName)) ;
			require( bytes( intent) == bytes( rollIntent( body, number( intent, L"accepted")))) ;
			expected.insert( intentName.generic_wstring()) ;
		}

		// 登録途中の日次切替は現在値のprefixを後で照合する。
		if( root.GetNamedValue( L"commit").ValueType() !=
		   winrt::Windows::Data::Json::JsonValueType::Null) {
			const auto commit = root.GetNamedObject( L"commit") ;	// Active commit一つだけ。
			// 日次commitの未完了archiveと固定effect名を登録集合へ加える。
			if( str( commit, L"kind") == L"DAY_ROLL") {
				rollOperations.insert( str( commit, L"operation")) ;
				expected.insert( path( L"runs/campaign-day-roll-v2-", str( commit, L"operation"))
									.generic_wstring()) ;
				expected.insert( destination( commit, L"ARCHIVE").generic_wstring()) ;
				// Activeな日次切替だけは二roleの準備fileを許す。
				for( const auto role : {L"ARCHIVE", L"BUDGET"}) {
					expected.insert(
						effectPath( str( commit, L"operation"), role, false).generic_wstring()) ;
				}

				expected.insert(
					effectPath( str( commit, L"operation"), L"BUDGET", true).generic_wstring()) ;
			}
		}

		std::vector<std::wstring> preparedNames ;	// 登録前intentも固定内容からだけ回収する。
		io( store->listRunNames( preparedNames)) ;
		// 未登録の切替intentを有限一覧から一つだけ探す。
		for( const auto &name : preparedNames) {
			// 他の保存fileは通常の登録検査へ残す。
			if( !name.starts_with( L"campaign-day-roll-v2-")) {
				continue ;
			}

			const auto intent = json( required( *store, std::filesystem::path( L"runs") /
														  name)) ;	// 元時刻を現在で置換しない。
			// 元旧予算と新日に結合する操作key。
			const auto op = str( intent, L"operation") ;
			// 完了またはactive登録済みのintentは再準備しない。
			if( rollOperations.contains( op)) {
				continue ;
			}

			require( !pendingRoll && str( root, L"activeGeneration").empty() &&
					name == L"campaign-day-roll-v2-" + op + L".json") ;
			require( bytes( intent) ==
					bytes( rollIntent( required( *store, BUDGET), number( intent, L"accepted")))) ;
			pendingRoll = intent ;
			expected.insert( L"runs/" + name) ;
			// 元intentへ結合した二roleの更新後像だけを許す。
			for( const auto role : {L"ARCHIVE", L"BUDGET"}) {
				expected.insert( effectPath( op, role, false).generic_wstring()) ;
			}

			expected.insert( effectPath( op, L"BUDGET", true).generic_wstring()) ;
		}

		// 未登録generationや未知campaign prefixを無視しない。
		for( const auto directory : {L"current", L"runs"}) {
			std::vector<std::wstring> names ;	// 固定directoryの保護一覧。
			io( std::wstring_view( directory) == L"current" ? store->listCurrentNames( names)
														  : store->listRunNames( names)) ;
			// 新旧campaignの全保存名を登録集合と比較する。
			for( const auto &name : names) {
				// 未知campaign名とorphanを旧履歴なしとして無視しない。
				if( name.starts_with( L"campaign-") || name == L"collector-campaign-mode-v1.json") {
					require( expected.contains( std::wstring( directory) + L"/" + name)) ;
				}
			}
		}

		CollectorStoreUsage usage ;	// 残留stagingも容量から除外しない。
		io( store->inspectUsage( usage)) ;
		return false ;
	}

	/** @brief 閉鎖済み旧予算だけを固定二段階で新日へ移します。 */
	void rollDay()
	{
		const auto value = budget() ;	// 応答・中断回収後の旧予算。
		// 同日予算は再作成もarchiveも行わない。
		if( value.day == day( now)) {
			return ;
		}

		require( value.day < day( now) && str( root, L"activeGeneration").empty()) ;
		require( std::all_of( value.reservations.begin(), value.reservations.end(),
							[]( const auto &r) { return r.phase != 0U ; })) ;
		const auto before = budgetBytes( value) ;	// Archiveとbefore像で完全一致する。
		const auto intent =
			pendingRoll ? pendingRoll : rollIntent( before, now) ;	// 初回準備時刻へ固定する。
		// 次世代の日次切替も共有archive上限を、最初の保存前に確認します。
		if( projectedRequested && root.GetNamedArray( L"generations").Size() > 0U) {
			require( root.GetNamedArray( L"archives").Size() < 300U, ERROR_TOO_MANY_NAMES) ;
		}

		save( *store, path( L"runs/campaign-day-roll-v2-", str( intent, L"operation")), bytes( intent),
			 true) ;
		// 旧callerには追加しない、全完了からの日次intent停止点です。
		if( projectedRequested && str( root, L"schema") == L"collector-campaign-root-v3" &&
		   root.GetNamedArray( L"generations").Size() > 0U) {
			checkpoint( CollectorRecoveryCheckpoint::DAY_ROLL_INTENT) ;
		}

		const auto after = budgetBytes( {str( intent, L"newDay"),
										number( intent, L"accepted") / 1000U,
										{}}) ;	// 固定した新日の空予算。
		Object	   commit ;						// 日次切替専用の固定操作。
		put( commit, L"kind", L"DAY_ROLL") ;
		put( commit, L"operation", str( intent, L"operation")) ;
		put( commit, L"generation", L"") ;
		put( commit, L"job", L"") ;
		put( commit, L"response", L"") ;
		put( commit, L"accepted", number( intent, L"accepted")) ;
		put( commit, L"oldDay", value.day) ;
		put( commit, L"newDay", str( intent, L"newDay")) ;
		commit.Insert( L"effects", Array()) ;
		require( !read( *store, destination( commit, L"ARCHIVE"))) ;
		addEffect( commit, L"ARCHIVE", std::nullopt, before) ;
		addEffect( commit, L"BUDGET", before, after) ;
		checkpoint( CollectorRecoveryCheckpoint::EFFECTS) ;
		root.Insert( L"commit", commit) ;
		saveRoot() ;
		checkpoint( CollectorRecoveryCheckpoint::REGISTERED) ;
		applyCommit() ;
	}

	/** @brief 固定input一式を登録してからrootへ載せます。
	 * @param[in] incoming 新しい公開入力。
	 */
	void createGeneration( const Object &incoming)
	{
		const auto count = root.GetNamedArray( L"generations").Size() ;	// 有限登録数。
		require( count < 300U, ERROR_TOO_MANY_NAMES) ;
		require( count == 0U || (nextProjected && str( root, L"activeGeneration").empty())) ;
		adoptInput( incoming, projectedRequested ? 3U : 2U) ;
		const auto inputHash = sha( bytes( input)) ;	// 元入力実byteへ結合する。
		jobs				 = initialJobs( key, manifest, projectedRequested) ;
		// 最大300 jobの応答・前後像を先に容量予約する。
		CollectorStoreUsage usage ;	// 残留stagingも含む現物容量。
		io( store->inspectUsage( usage)) ;
		io( projectedRequested ? checkCollectorProjectedCompletionCapacity(
									usage, manifest.jobs.size(), manifest.jobs.size())
							  : checkCollectorRecoveryCapacity( usage, manifest.jobs.size())) ;
		save(
			*store,
			path( projectedRequested ? L"runs/campaign-input-v3-" : L"runs/campaign-input-v2-", key),
			bytes( input), true) ;
		// 未登録の部分generationは送信せず、再起動時のinventoryが拒否する。
		if( projectedRequested) {
			checkpoint( CollectorRecoveryCheckpoint::PROJECTED_INPUT) ;
			save( *store, path( L"runs/campaign-marker-v3-", key), projectedMarker( inputHash), true) ;
			checkpoint( CollectorRecoveryCheckpoint::PROJECTED_MARKER) ;
		} else {
			save( *store, path( L"runs/campaign-marker-v2-", key),
				 "collector-campaign-generation-v2\n" + winrt::to_string( key) + "\n" +
					 winrt::to_string( inputHash),
				 true) ;
		}

		save( *store, statePath(), bytes( jobs), true) ;
		// 初期state保存後もrootへの登録前は不完全登録である。
		if( projectedRequested) {
			checkpoint( CollectorRecoveryCheckpoint::PROJECTED_STATE) ;
		}

		Object row ;	// 登録前の片側欠損は自動修復しない。
		put( row, L"generation", key) ;
		put( row, L"inputHash", inputHash) ;
		put( row, L"summaryHash", L"") ;
		// 新rootでは旧世代を作る場合にも保存versionを明記する。
		if( str( root, L"schema") == L"collector-campaign-root-v3") {
			put( row, L"storageVersion", static_cast<std::uint64_t>( storageVersion)) ;
		}

		root.GetNamedArray( L"generations").Append( row) ;
		put( root, L"activeGeneration", key) ;
		saveRoot() ;
		// Root登録後は同じinputから新世代を作らず再読込できる。
		if( projectedRequested) {
			checkpoint( CollectorRecoveryCheckpoint::PROJECTED_REGISTERED) ;
		}
	}
} ;

/** @see local_collector_recovery.h */
LocalCollectorRecovery::LocalCollectorRecovery() : state_( std::make_unique<State>())
{
}

/** @see local_collector_recovery.h */
LocalCollectorRecovery::~LocalCollectorRecovery()
{
	// Writer lockは監督storeが保持したまま借用だけを返す。
	if( state_->store) {
		state_->store->releaseWaitLedger( state_.get()) ;
		state_->store->releaseCampaign( state_.get()) ;
	}
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::initialize( LocalCollectorStateStore	  &store,
										 const CollectorRecoveryInput &input,
										 const std::uint64_t		   utcMillis,
										 const std::uint64_t		   steadyMillis,
										 std::function<bool( CollectorRecoveryCheckpoint)> stop)
{
	return initializeForMode( store, input, nullptr, utcMillis, steadyMillis, std::move( stop)) ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::initializeProjected(
	LocalCollectorStateStore &store, const CollectorProjectedCampaignDefinition &input,
	const std::uint64_t utcMillis, const std::uint64_t steadyMillis,
	std::function<bool( CollectorRecoveryCheckpoint)> stop)
{
	return initializeForMode( store, {}, &input, utcMillis, steadyMillis, std::move( stop)) ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::initializeForMode(
	LocalCollectorStateStore &store, const CollectorRecoveryInput &input,
	const CollectorProjectedCampaignDefinition *projected, const std::uint64_t utcMillis,
	const std::uint64_t steadyMillis, std::function<bool( CollectorRecoveryCheckpoint)> stop)
{
	// 初回の失敗を消して同じobjectから新規登録しない。
	if( state_->error != 0U) {
		return state_->error ;
	}

	try {
		require( !state_->store, ERROR_BUSY) ;
		require( store.isWritable(), ERROR_INVALID_PARAMETER) ;
		io( store.checkHttpSupervisor()) ;
		state_->now				   = utcMillis ;
		state_->initialSteady	   = steadyMillis ;
		state_->lastSteady		   = steadyMillis ;
		state_->stop			   = std::move( stop) ;
		state_->projectedRequested = projected != nullptr ;
		// 現sourceの所有値を保存sourceと区別し、再読込み・予約まで寿命を保つ。
		if( projected) {
			state_->projectedSources = projected->sources ;
		}

		CollectorCampaignManifest checked ;				// Caller入力を保存前に全件検査する。
		Object					  incoming{nullptr} ;	// 未予約jobの入力変更検査にも使う。
		// 新callerから任意request／scope hashを受け取らない。
		if( projected) {
			CollectorProjectedCampaignIdentity identity ;	// 同じ日付で全jobを固定する。
			require( makeCollectorProjectedCampaignIdentity( *projected, day( utcMillis), identity)) ;
			incoming = json( identity.canonicalInput) ;
		} else {
			incoming = encodeInput( input, day( utcMillis), checked) ;
		}

		const auto parent = (std::filesystem::current_path() / L"work/state")
								.lexically_normal() ;						// 専用workspace境界。
		const auto relative = store.root().lexically_relative( parent) ;	// 親とroot自身を拒否する。
		require( !relative.empty() && relative != L"." &&
				!std::any_of( relative.begin(), relative.end(),
							 []( const auto &part) { return part == L".." ; })) ;
		io( store.borrowCampaign( state_.get())) ;
		const auto waitLease =
			// 独立旧台帳との同時更新を止める。
			store.borrowWaitLedger( state_.get()) ;
		// 待機借用が失敗したら先に得たcampaign借用を返す。
		if( waitLease != 0U) {
			store.releaseCampaign( state_.get()) ;
			throw waitLease ;
		}

		state_->store		= &store ;
		const auto mode		= read( store, MODE) ;	// 初回登録の片側欠損を拒否する。
		const auto rootBody = read( store, ROOT) ;	// 必須root本文。
		bool	   initialV3Upgrade{} ;				// b2bの未予約rootだけに空CACHE登録簿を追加する。
		require( mode.has_value() == rootBody.has_value()) ;
		CollectorLegacySnapshot legacy ;	// 全旧manifest／artifactを非変更で検査する。
		// 初回の回収必要と、登録後の旧集合変更は区別する。
		const auto				legacyError =
			inspectLocalCollectorLegacy( store, utcMillis, legacy, state_->reason) ;
		// 既存rootでは旧形式の欠損・改変・未昇格追加も登録集合の変更である。
		if( rootBody && (legacyError == ERROR_INVALID_DATA || legacyError == ERROR_RETRY)) {
			state_->reason = L"LEGACY_STATE_CHANGED" ;
			throw DWORD{ERROR_INVALID_DATA} ;
		}

		io( legacyError) ;
		// 新規rootだけを全検査後に登録する。
		if( !rootBody) {
			state_->enroll( legacy) ;
		} else {
			state_->root = json( *rootBody) ;
			const bool rootV3 =
				// 同じ物理入口。
				str( state_->root, L"schema") == L"collector-campaign-root-v3" ;
			// 世代情報を省略した新rootを旧rootとして解釈しない。
			if( rootV3) {
				initialV3Upgrade = !state_->root.HasKey( L"cacheInventory") ;
				// 旧初期v3だけの互換。稼働済みなら全検査後に拒否する。
				if( initialV3Upgrade) {
					state_->root.Insert( L"cacheInventory", Array()) ;
				}

				fields( state_->root, {L"schema", L"rootKey", L"lastUtcMillis", L"legacyDigest",
									  L"legacyFileCount", L"legacyLastUsedDay", L"legacyFiles",
									  L"generations", L"archives", L"activeGeneration", L"commit",
									  L"upgradeFrom", L"cacheInventory"}) ;
				require( state_->root.GetNamedValue( L"upgradeFrom").ValueType() ==
							winrt::Windows::Data::Json::JsonValueType::Null ||
						hash( str( state_->root, L"upgradeFrom"))) ;
			} else {
				fields( state_->root, {L"schema", L"rootKey", L"lastUtcMillis", L"legacyDigest",
									  L"legacyFileCount", L"legacyLastUsedDay", L"legacyFiles",
									  L"generations", L"archives", L"activeGeneration", L"commit"}) ;
			}

			const auto marker = json( *mode) ;	// Immutableのmode登録。
			fields( marker, {L"schema", L"rootKey"}) ;
			require( (rootV3 || str( state_->root, L"schema") == L"collector-campaign-root-v2") &&
					hash( str( state_->root, L"rootKey")) &&
					str( marker, L"schema") == L"collector-campaign-mode-v1" &&
					str( marker, L"rootKey") == str( state_->root, L"rootKey") &&
					number( state_->root, L"lastUtcMillis") <= utcMillis) ;
			state_->reason = L"LEGACY_STATE_CHANGED" ;
			require( str( state_->root, L"legacyDigest") ==
						state_->legacyDigest( legacy, state_->root.GetNamedArray( L"legacyFiles")) &&
					number( state_->root, L"legacyFileCount") ==
						legacy.fileCount + state_->root.GetNamedArray( L"legacyFiles").Size() &&
					str( state_->root, L"legacyLastUsedDay") == legacy.lastUsedDay) ;
			state_->reason.clear() ;
		}

		const bool completedInventory = state_->inventory(
			projected ? std::span<const CollectorCampaignSource>( projected->sources)
					  : std::span<const CollectorCampaignSource>{},
			projected != nullptr) ;	// 元応答準備窓は全履歴を先行検査。
		(void)state_->budget() ;
		(void)state_->controls() ;
		// 新世代を旧callerから回収・送信しない。
		if( state_->storageVersion == 3U) {
			require( projected != nullptr) ;
		}

		// 完了を再保存せず、日次証跡がある一切替の回復だけを許します。新入力は登録しません。
		if( completedInventory) {
			// 証跡が検査された一切替だけを確定し、新世代や現在日への追加切替は始めません。
			if( state_->pendingRoll) {
				CollectorStoreUsage usage ;	// 復旧再中断の残留stagingも含む保存容量です。
				io( store.inspectUsage( usage)) ;
				io( checkCollectorProjectedCompletionCapacity(
					usage, state_->manifest.jobs.size(), state_->definition.requestKeys.size())) ;
				const bool registered = state_->root.GetNamedValue( L"commit").ValueType() !=
										winrt::Windows::Data::Json::JsonValueType::
											Null ;	// 全像と物理prefixは検査済みです。
				// 登録済みなら未反映suffixだけ、未登録なら元intentの不足準備だけを保存します。
				if( registered) {
					state_->applyCommit() ;
				} else {
					state_->rollDay() ;
				}

				std::shared_ptr<const CollectorRegisteredProjectedHistory>
					verified ;	// 通常の全完了再検査。
				io( inspectProjectedHistoryCore( store, nullptr, state_->projectedSources, utcMillis,
											   sha( bytes( state_->root)), verified, {})) ;
				// 後日再開は固定された新日まで。追加切替は別の明示入口へ残します。
				if( state_->budget().day != day( utcMillis)) {
					state_->reason = L"DAY_ROLL_CONTINUE" ;
					return ERROR_RETRY ;
				}
			}

			state_->reason = L"GENERATION_COMPLETE" ;
			return ERROR_SUCCESS ;
		}

		// 未完了末尾の再読込みを初回CACHE回復へ渡しません。
		if( state_->nextProjected) {
			// 元完了prefixは全履歴・全raw再照合済み。不足suffixだけで元ROOT確定へ進みます。
			if( state_->pendingFinish) {
				state_->saveNextCompletion( *state_->pendingFinish) ;
				std::shared_ptr<const CollectorRegisteredProjectedHistory>
					verified ;	// 通常全完了検査。
				io( inspectProjectedHistoryCore( store, nullptr, state_->projectedSources, utcMillis,
											   sha( bytes( state_->root)), verified, {})) ;
				state_->reason = L"GENERATION_COMPLETE" ;
				return ERROR_SUCCESS ;
			}

			// 登録commitは論理前像の全履歴検査済み。実prefixを再検査してsuffixだけを保存します。
			if( state_->root.GetNamedValue( L"commit").ValueType() !=
			   winrt::Windows::Data::Json::JsonValueType::Null) {
				state_->applyCommit() ;
				std::shared_ptr<const CollectorRegisteredProjectedHistory>
					verified ;	// 物理確定後の同じ全閉包判定。
				io( inspectProjectedHistoryCore( store, nullptr, state_->projectedSources, utcMillis,
											   sha( bytes( state_->root)), verified, {}, true,
											   nullptr, false, false, true)) ;
			} else {
				// 初回の欠測中断生成へ流用しません。
				state_->recoverPreparedNextResponses() ;
			}

			const auto rows =
				// 元末尾の予約・稼働・精算済み行。
				state_->jobs.GetNamedArray( L"jobs") ;
			const auto budget = state_->budget() ;	// 部分開始もphase0のまま送信を抑止します。
			state_->nextDispatchEnabled =
				bytes( state_->input) == bytes( incoming) &&
				std::none_of( budget.reservations.begin(), budget.reservations.end(),
							 []( const auto &entry) { return entry.phase == 0U ; }) &&
				std::none_of( rows.begin(), rows.end(), []( const auto &entry) {
					return str( entry.GetObject(), L"state") == L"RUNNING" ;
				}) ;
			state_->reason = state_->nextDispatchEnabled ? L"NEXT_GENERATION_READY"
														 : L"HISTORY_ACCEPTANCE_PENDING" ;
			return state_->nextDispatchEnabled ? ERROR_SUCCESS : ERROR_RETRY ;
		}

		// 固定完了intentは通常回収やroot時計更新より先に元時刻で確定します。
		if( state_->storageVersion == 3U && !state_->key.empty() &&
		   read( store, path( L"runs/campaign-finish-v1-", state_->key))) {
			state_->finishGeneration() ;
			state_->reason = L"GENERATION_COMPLETE" ;
			return ERROR_SUCCESS ;
		}

		// 初期登録時代のrootだけを非破壊で補完する。稼働済みの欠損を隠さない。
		if( initialV3Upgrade) {
			require( projected && state_->root.GetNamedValue( L"commit").ValueType() ==
									 winrt::Windows::Data::Json::JsonValueType::Null) ;
			const auto currentBudget = state_->budget() ;	// 新予約はまだ発行しない。
			require( std::none_of(
				currentBudget.reservations.begin(), currentBudget.reservations.end(),
				[&]( const auto &row) { return row.campaign == state_->key || row.phase == 0U ; })) ;
			// 開始intentの取り残しを予約なしへ書き換えない。
			for( const auto &[name, row] : state_->controls().controls) {
				require( row.started == 0U) ;
			}

			// 全jobが未予約で、未登録の応答もない場合に限る。
			for( const auto &job : state_->manifest.jobs) {
				require( !state_->storedResponse( operation( state_->key, job.key))) ;
			}

			// 初期rootではRUNNING／終端行も存在しない。
			if( state_->jobs) {
				// 互換対象の全行が未予約であることを確認する。
				for( const auto &entry : state_->jobs.GetNamedArray( L"jobs")) {
					const auto name = str( entry.GetObject(), L"state") ;	// 未予約の二状態のみ。
					require( name == L"PENDING" || name == L"DEFERRED") ;
				}
			}
		}

		// 他の共有更新より先に登録済みcommitを回収する。
		if( state_->root.GetNamedValue( L"commit").ValueType() !=
		   winrt::Windows::Data::Json::JsonValueType::Null) {
			// 登録済み日次intentの回収と、新しい日次切替を同じ入口で重ねない。
			const bool recoveredDay =
				str( state_->root.GetNamedObject( L"commit"), L"kind") == L"DAY_ROLL" ;
			state_->applyCommit() ;
			// 後日再開でも初回acceptedの固定新日へ一度だけ進める。
			if( recoveredDay && state_->budget().day != day( utcMillis)) {
				state_->reason = L"DAY_ROLL_CONTINUE" ;
				return ERROR_RETRY ;
			}
		}

		// 既存generationを回収し、この呼出しから別世代を始めない。
		if( !state_->key.empty()) {
			state_->recoverResponses() ;
			// 旧応答と未完了予約だけを元codecで回収する。
			if( state_->storageVersion == 2U) {
				// 集計待ちの旧世代を新世代へ誤登録せず、そのまま返す。
				if( projected) {
					state_->saveRoot() ;
					state_->reason = L"LEGACY_GENERATION_PENDING" ;
					return ERROR_RETRY ;
				}
			}

			std::wstring defer ;	// 未予約だけを非再送terminalへ閉じる。
			// 開始JST日が変わった未予約jobは追加送信しない。
			if( str( state_->input, L"day") != day( utcMillis)) {
				defer = L"DAY_CLOSED" ;
			}

			// 入力変更では旧分母を維持する。日付変更の理由を優先する。
			if( defer.empty() &&
			   str( state_->input, L"manifestSha256") != str( incoming, L"manifestSha256")) {
				defer = L"INPUT_CHANGED" ;
			}

			// 同日・同manifestのartifactや固定binding変更では旧入力を閉じる。
			if( defer.empty() && (str( state_->input, L"artifact") != str( incoming, L"artifact") ||
								 bytes( state_->input) != bytes( incoming))) {
				defer = L"ARTIFACT_CHANGED" ;
			}

			// 継続不能理由がある場合だけ未予約の終端処理を行う。
			if( !defer.empty()) {
				// 応答済みや実行済みjobをDEFERREDへ上書きしない。
				for( const auto &entry : state_->jobs.GetNamedArray( L"jobs")) {
					const auto row = entry.GetObject() ;	// 未予約だけを変更する。
					// 予算未予約のPENDINGだけを非再送終端にする。
					if( str( row, L"state") == L"PENDING") {
						put( row, L"state", L"DEFERRED") ;
						put( row, L"reason", defer) ;
					}
				}

				save( store, state_->statePath(), bytes( state_->jobs)) ;
				state_->reason = defer ;
			}

			state_->saveRoot() ;
			// Summary接続はb2dへ残し、旧generationを閉じた呼出しから新規を始めない。
			return ERROR_SUCCESS ;
		}

		// Active世代がないrootに開始予約だけが残る矛盾を新登録で覆い隠さない。
		if( projected) {
			const auto priorBudget = state_->budget() ;	// 未閉鎖予約があれば回収主体が欠損している。
			require( std::all_of( priorBudget.reservations.begin(), priorBudget.reservations.end(),
								[]( const auto &row) { return row.phase != 0U ; })) ;
			// 独立待機にも取り残された開始intentがないことを要求する。
			for( const auto &[name, row] : state_->controls().controls) {
				require( row.started == 0U) ;
			}
		}

		// 旧v4の同日使用量を0として新HTTPの予算へ転用しない。
		if( !legacy.lastUsedDay.empty() && day( utcMillis) <= legacy.lastUsedDay) {
			state_->reason = L"LEGACY_DAY_USAGE_UNKNOWN" ;
			state_->saveRoot() ;
			return ERROR_RETRY ;
		}

		state_->rollDay() ;
		// 複数日経過した準備intentは一回の固定切替で止め、次入口で次日へ進む。
		if( state_->budget().day != day( utcMillis)) {
			state_->reason = L"DAY_ROLL_CONTINUE" ;
			return ERROR_RETRY ;
		}

		// 旧履歴・待機・日次intentを回収した空active rootだけを移行する。
		if( projected && str( state_->root, L"schema") == L"collector-campaign-root-v2") {
			state_->upgradeRoot() ;
		}

		state_->createGeneration( incoming) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		state_->error = code ;
	} catch( const std::bad_alloc &) {
		state_->error = static_cast<DWORD>( E_OUTOFMEMORY) ;
	} catch( const winrt::hresult_error &error) {
		state_->error = static_cast<DWORD>( error.code().value) ;
	} catch( ...) {
		state_->error = ERROR_INVALID_DATA ;
	}

	// OOMの第一数値を返す前に、新しい理由文字列を確保しません。
	if( state_->error == static_cast<DWORD>( E_OUTOFMEMORY)) {
		state_->reason.swap( state_->projectedFailureReason) ;
		return state_->error ;
	}

	// 元I/O codeは数値で保持し、理由だけ未設定時に補う。
	if( state_->reason.empty()) {
		state_->reason = state_->error == ERROR_TOO_MANY_NAMES ? L"STATE_CAPACITY" : L"STATE_ERROR" ;
	}

	return state_->error ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::beginNextProjected( const CollectorProjectedCampaignDefinition &input,
												 const std::uint64_t utcMillis,
												 const std::uint64_t steadyMillis)
{
	// 第一errorを消して次の世代へ進まない。
	if( state_->error != 0U) {
		return state_->error ;
	}

	try {
		require( state_->store && state_->projectedRequested && !state_->nextProjected &&
					state_->storageVersion == 3U && !state_->key.empty(),
				ERROR_INVALID_PARAMETER) ;
		require( utcMillis >= state_->now && utcMillis <= LAST_UTC &&
				steadyMillis >= state_->lastSteady) ;
		CollectorProjectedCampaignIdentity identity ;	// 新定義と実日付から再構築する元入力。
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
			prepared ;	// 保存前の全source／scope照合。
		require( makeCollectorProjectedCampaignIdentity( input, day( utcMillis), identity) &&
				prepareCollectorProjectedCampaign( identity.canonicalInput, identity.inputSha256,
												  identity.generationKey, input.artifactSha256,
												  input.sources, prepared)) ;
		std::shared_ptr<const CollectorRegisteredProjectedHistory>
			unused ;	// 全完了検査だけを共有する。
		io( inspectProjectedHistoryCore( *state_->store, nullptr, input.sources, utcMillis,
									   sha( bytes( state_->root)), unused, {})) ;
		const auto registrations =
			// 全完了・最大300件。
			state_->root.GetNamedArray( L"generations") ;
		// 同じGの再登録は全byte不変の待機とし、rootやbudgetを更新しない。
		if( std::any_of( registrations.begin(), registrations.end(), [&]( const auto &entry) {
			   return str( entry.GetObject(), L"generation") == identity.generationKey ;
		   })) {
			state_->reason = L"GENERATION_ALREADY_COMPLETE" ;
			return ERROR_RETRY ;
		}

		require( registrations.Size() < 300U, ERROR_TOO_MANY_NAMES) ;
		CollectorStoreUsage usage ;	// 日次切替より前に追加保存枠を検査する。
		io( state_->store->inspectUsage( usage)) ;
		io( checkCollectorProjectedCompletionCapacity( usage, prepared->jobCount(),
													 prepared->jobCount())) ;
		const auto legacyDay =
			// 未計測旧予算の同日迂回をしない。
			str( state_->root, L"legacyLastUsedDay") ;
		// 旧v4の使用量が不明な日は新世代を開始しない。
		if( !legacyDay.empty() && day( utcMillis) <= legacyDay) {
			state_->reason = L"LEGACY_DAY_USAGE_UNKNOWN" ;
			return ERROR_RETRY ;
		}

		state_->now				 = utcMillis ;
		state_->lastSteady		 = steadyMillis ;
		state_->projectedSources = input.sources ;
		state_->rollDay() ;
		require( state_->budget().day == day( utcMillis)) ;
		state_->nextProjected = true ;
		state_->createGeneration( json( identity.canonicalInput)) ;
		// 新世代も登録直後に同じ有限coreへ結合し、旧proofを省略しない。
		io( inspectProjectedHistoryCore( *state_->store, nullptr, state_->projectedSources, utcMillis,
									   sha( bytes( state_->root)), unused, {}, true)) ;
		state_->nextDispatchEnabled = true ;
		state_->reason				= L"NEXT_GENERATION_READY" ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		state_->error = code ;
	} catch( const std::bad_alloc &) {
		state_->error = static_cast<DWORD>( E_OUTOFMEMORY) ;
	} catch( const winrt::hresult_error &error) {
		state_->error = static_cast<DWORD>( error.code().value) ;
	} catch( ...) {
		state_->error = ERROR_INVALID_DATA ;
	}

	state_->nextDispatchEnabled = false ;
	state_->reason.swap( state_->projectedFailureReason) ;
	return state_->error ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::recoverNextProjectedReservations( const std::uint64_t utcMillis,
															   const std::uint64_t steadyMillis)
{
	// 第一errorを消して欠測の再生成を行いません。
	if( state_->error != 0U) {
		return state_->error ;
	}

	try {
		require( state_->store && state_->projectedRequested && state_->nextProjected &&
					state_->storageVersion == 3U,
				ERROR_NOT_SUPPORTED) ;
		// 同processが所有する実行枠を再起動中断へ読み替えません。
		require( std::none_of( state_->controlledBindings.begin(), state_->controlledBindings.end(),
							 []( const auto &binding) { return binding.has_value() ; }),
				ERROR_BUSY) ;
		require( utcMillis >= state_->now && utcMillis <= LAST_UTC &&
				steadyMillis >= state_->lastSteady &&
				required( *state_->store, ROOT) == bytes( state_->root) &&
				required( *state_->store, state_->statePath()) == bytes( state_->jobs)) ;
		std::shared_ptr<const CollectorRegisteredProjectedHistory> unused ;	// 保存前の全閉包検査。
		std::set<std::wstring> operations ;									// 元保存操作だけを先行加算します。
		io( inspectProjectedHistoryCore( *state_->store, nullptr, state_->projectedSources, utcMillis,
									   sha( bytes( state_->root)), unused, {}, true, &operations,
									   false, false, true)) ;
		std::vector<std::pair<std::size_t, std::uint64_t>>
				   pending ;	// 元indexと予算の開始UTCだけの計画。
		const auto reservations =
			// 全検査済み元予約。PENDINGから開始時刻を補完しません。
			state_->budget() ;
		std::size_t newRequests{} ;	// 真の未登録CACHEの将来追加数。
		// 全未精算枠を調べ、一件目の保存前に全体容量を検査します。
		for( std::size_t index = 0U; index < state_->manifest.jobs.size(); ++index) {
			const auto reserved =
				std::find_if( reservations.reservations.begin(), reservations.reservations.end(),
							 [&]( const auto &entry) {
								 return entry.campaign == state_->key &&
										entry.job == state_->manifest.jobs[index].key &&
										entry.phase == 0U ;
							 }) ; // 全履歴で元RUNNINGまたは単一部分開始へ結合済みの予約だけ。
			// 未予約・精算済みを中断へ変換しません。
			if( reserved != reservations.reservations.end()) {
				require( !state_->storedResponse(
					operation( state_->key, state_->manifest.jobs[index].key))) ;
				pending.emplace_back( index, reserved->started * 1000U) ;
				newRequests +=
					state_->registeredCache( state_->definition.requestKeys[index]).empty() ? 1U
																						   : 0U ;
			}
		}

		std::stable_sort(
			pending.begin(), pending.end(), [&]( const auto &first, const auto &second) {
				const auto rows =
					// 同期検査済み元状態だけを参照します。
					state_->jobs.GetNamedArray( L"jobs") ;
				return str( rows.GetObjectAt( static_cast<std::uint32_t>( first.first)), L"state") ==
						   L"PENDING" &&
					   str( rows.GetObjectAt( static_cast<std::uint32_t>( second.first)), L"state") !=
						   L"PENDING" ;
			}) ; // 部分開始を先に閉じ、他精算による最高時計更新で元prefixを失わないようにします。
		require( operations.size() + pending.size() <= 300U &&
					state_->root.GetNamedArray( L"cacheInventory").Size() + newRequests <= 300U,
				ERROR_TOO_MANY_NAMES) ;
		CollectorStoreUsage usage ;	// 残留stagingを含む既存有限保存枠。
		io( state_->store->inspectUsage( usage)) ;
		io( checkCollectorProjectedRecoveryCapacity( usage, state_->manifest.jobs.size(),
												   state_->definition.requestKeys.size())) ;
		state_->now		   = utcMillis ;
		state_->lastSteady = steadyMillis ;
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
			campaign ;	// 同じ元sourceを再構築します。
		require( prepareCollectorProjectedCampaign( bytes( state_->input), sha( bytes( state_->input)),
												  state_->key, state_->definition.artifactSha256,
												  state_->projectedSources, campaign)) ;
		// 部分開始を先に、残りは元job順で保存し、他slotの未応答と過去証跡を毎回再検査します。
		for( const auto &[index, started] : pending) {
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
				history ;	// 最新の検査済みCACHE前像。
			io( inspectProjectedHistoryCore(
				*state_->store, campaign->job( index), state_->projectedSources, utcMillis,
				sha( bytes( state_->root)), history, {}, true, nullptr, false, false, true)) ;
			std::optional<std::string> beforeCache ;	// 新requestだけ元の不在を維持します。
			// 閉包から生成した変更不能contextだけを前像へ使用します。
			if( history) {
				beforeCache.emplace() ;
				projectedCodec( encodeCollectorProjectedCache( history->cache(), *beforeCache)) ;
				require( sha( *beforeCache) == history->cacheHash()) ;
			}

			const auto op = operation( state_->key, state_->manifest.jobs[index].key) ;	// 元一予約。
			require( !state_->storedResponse( op)) ;
			CollectorRecoveryResponse observation ;	// 送信数・受信量を未知のまま固定します。
			observation.finishedUtcMillis = utcMillis ;
			observation.acceptedUtcMillis = utcMillis ;
			const auto response			  = state_->responseObject( index, observation, started,
																   true) ;	// 元開始時計を保持します。
			save( *state_->store, path( L"runs/campaign-response-v2-", op), bytes( response), true) ;
			state_->checkpoint( CollectorRecoveryCheckpoint::RESPONSE) ;
			state_->commitResponse( index, response, nullptr, beforeCache) ;
			io( inspectProjectedHistoryCore( *state_->store, nullptr, state_->projectedSources,
										   utcMillis, sha( bytes( state_->root)), unused, {}, true,
										   nullptr, false, false, true)) ;
		}

		state_->nextDispatchEnabled = false ;
		state_->reason =
			pending.empty() ? L"NEXT_RESERVATIONS_SETTLED" : L"NEXT_RESERVATIONS_INTERRUPTED" ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		state_->error = code ;
	} catch( const std::bad_alloc &) {
		state_->error = static_cast<DWORD>( E_OUTOFMEMORY) ;
	} catch( const winrt::hresult_error &error) {
		state_->error = static_cast<DWORD>( error.code().value) ;
	} catch( ...) {
		state_->error = ERROR_INVALID_DATA ;
	}

	state_->nextDispatchEnabled = false ;
	state_->reason.swap( state_->projectedFailureReason) ;
	return state_->error ;
}

/** @see local_collector_recovery.h */
bool sameCollectorRecoveryDispatch( const CollectorRecoveryDispatch &first,
								   const CollectorRecoveryDispatch &second) noexcept
{
	return first.mode == second.mode && first.jobIndex == second.jobIndex &&
		   first.generationKey == second.generationKey &&
		   first.startedUtcMillis == second.startedUtcMillis && first.jobKey == second.jobKey &&
		   first.requestKey == second.requestKey && first.cacheBinding == second.cacheBinding &&
		   first.scopeSha256 == second.scopeSha256 &&
		   first.source.sourceId == second.source.sourceId &&
		   first.source.resourceId == second.source.resourceId &&
		   first.source.rateLimitGroup == second.source.rateLimitGroup &&
		   first.source.parserRevision == second.source.parserRevision &&
		   first.source.maximumResponseBytes == second.source.maximumResponseBytes &&
		   first.anchorUtcMillis == second.anchorUtcMillis &&
		   first.anchorSteadyMillis == second.anchorSteadyMillis &&
		   first.deadlineUtcMillis == second.deadlineUtcMillis &&
		   first.deadlineSteadyMillis == second.deadlineSteadyMillis ;
}
/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::reserve( std::uint64_t utcMillis, std::uint64_t steadyMillis,
									  CollectorRecoveryDispatch &dispatch)
{
	return reserveForMode( utcMillis, steadyMillis, dispatch, false) ;
}
/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::reserveControlled( std::uint64_t utcMillis, std::uint64_t steadyMillis,
												CollectorRecoveryDispatch &dispatch)
{
	return reserveForMode( utcMillis, steadyMillis, dispatch, true) ;
}
/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::reserveProjected( std::uint64_t utcMillis, std::uint64_t steadyMillis,
											   CollectorRecoveryDispatch &dispatch)
{
	return reserveForMode( utcMillis, steadyMillis, dispatch, true, true) ;
}
/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::acquireHttpActivity(
	std::shared_ptr<const CollectorStoreHttpLease> &lease) noexcept
{
	lease.reset() ;
	// 所有登録で元監督の第一errorを隠しません。
	if( state_->error != ERROR_SUCCESS) {
		return state_->error ;
	}

	// 借用未成立の監督からHTTP所有を作りません。
	if( !state_->store) {
		return ERROR_INVALID_PARAMETER ;
	}

	return state_->store->acquireHttpActivity( state_.get(), lease) ;
}
/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::reserveForMode( std::uint64_t utcMillis, std::uint64_t steadyMillis,
											 CollectorRecoveryDispatch &dispatch, bool controlled,
											 bool projected)
{
	dispatch = {} ;
	// 最初の保存errorを保持する。
	if( state_->error != 0U) {
		return state_->error ;
	}

	try {
		// 専用入口と登録版が完全一致した場合だけ許可する。
		require( projected == state_->projectedRequested &&
					state_->storageVersion == (projected ? 3U : 2U),
				ERROR_INVALID_PARAMETER) ;
		require( state_->store && !state_->key.empty(), ERROR_INVALID_PARAMETER) ;
		require( !state_->nextProjected || state_->nextDispatchEnabled, ERROR_RETRY) ;
		require( utcMillis >= state_->now && utcMillis <= LAST_UTC &&
				steadyMillis >= state_->lastSteady) ;
		state_->lastSteady	= steadyMillis ;
		state_->now			= utcMillis ;
		auto	   budget	= state_->budget() ;	// 保存直前の共通予算。
		auto	   controls = state_->controls() ;	// 元の恒久待機。
		const auto selected =
			// 共通選択。
			state_->selectJob( budget, controls, utcMillis, steadyMillis) ;
		// 非変更照会と同じ理由で予約を止める。
		if( selected.kind != CollectorRecoveryReadinessKind::READY) {
			state_->reason = selected.reason ;
			return ERROR_RETRY ;
		}

		const auto	index	= *selected.jobIndex ;						// READYでだけ存在する固定index。
		const auto &job		= state_->manifest.jobs[index] ;			// 元job上限。
		const auto &request = state_->definition.requestKeys[index] ;	// 元request hash。
		const auto	row		= state_->jobs.GetNamedArray( L"jobs").GetObjectAt(
			 // 更新対象の一job。
			 static_cast<std::uint32_t>( index)) ;
		const auto started	 = utcMillis / 1000U * 1000U ;				// 既存秒予約に一致。
		const auto remaining = selected.deadlineUtcMillis - utcMillis ;	// 保存時間も含む残枠。
		require( steadyMillis <= std::numeric_limits<std::uint64_t>::max() - remaining) ;
		const auto liveSlot =
			std::find_if( state_->controlledBindings.begin(), state_->controlledBindings.end(),
						 []( const auto &entry) { return !entry ; }) ;	// 事前確保四枠。
		require( !controlled || liveSlot != state_->controlledBindings.end(), ERROR_RETRY) ;
		CollectorRecoveryDispatch prepared ;	// 文字列確保は永続予約より前に済ませる。
		prepared.jobIndex			  = index ;
		prepared.generationKey		  = state_->key ;
		prepared.startedUtcMillis	  = started ;
		prepared.jobKey				  = job.key ;
		prepared.requestKey			  = request ;
		prepared.cacheBinding		  = state_->definition.cacheBindings[index] ;
		prepared.source				  = job.source ;
		prepared.anchorUtcMillis	  = utcMillis ;
		prepared.anchorSteadyMillis	  = steadyMillis ;
		prepared.deadlineUtcMillis	  = selected.deadlineUtcMillis ;
		prepared.deadlineSteadyMillis = steadyMillis + remaining ;
		Object intent{nullptr} ;	// 全検証・確保を永続予約より前に行う。
		std::shared_ptr<const State::InitialProjectedHistory>
			history ;	// 書込み前に確保する所有根拠。
		std::shared_ptr<const CollectorRegisteredProjectedHistory>
			registeredHistory ;	// 四slotに所有する元登録履歴。
		// 射影予約のscopeと二時計を元inputへ再結合する。
		if( projected) {
			prepared.mode = CollectorRecoveryDispatch::Mode::PROJECTED ;
			CollectorProjectedCampaignDefinition source ;	// 元定義。
			CollectorProjectedCampaignIdentity	 identity ;	// 全scope再構築。
			std::string							 encoded ;	// 専用開始intent。
			require(
				parseCollectorProjectedCampaignIdentity( bytes( state_->input), source, identity) &&
				index < identity.jobs.size()) ;
			prepared.scopeSha256 = identity.jobs[index].scopeSha256 ;
			require( encodeCollectorProjectedStart( identity, prepared, encoded)) ;
			intent = json( encoded) ;
			CollectorStoreUsage usage ;	// 既存fileを返金しない保存枠検査。
			io( state_->store->inspectUsage( usage)) ;
			io( checkCollectorProjectedCompletionCapacity( usage, state_->manifest.jobs.size(),
														 state_->manifest.jobs.size())) ;
			// 次回予約は完了prefixと末尾を全検査してから元requestのcontextを所有する。
			if( state_->nextProjected) {
				std::shared_ptr<const CollectorPreparedProjectedCampaign>
					campaign ;	// 保存元入力から再構築する全scope。
				require( prepareCollectorProjectedCampaign(
					bytes( state_->input), sha( bytes( state_->input)), state_->key,
					state_->definition.artifactSha256, state_->projectedSources, campaign)) ;
				std::set<std::wstring> operations ;	// 全requestの再導出済み保存操作。
				io( inspectProjectedHistoryCore(
					*state_->store, campaign->job( index), state_->projectedSources, utcMillis,
					sha( bytes( state_->root)), registeredHistory, {}, true, &operations)) ;
				std::size_t running{} ;		// 既に送信枠を予約した将来の保存操作数。
				std::size_t newRequests{} ;	// まだ登録されていない稼働requestの将来CACHE数。
				// 最大300元jobを走査し、未受領枠も全体上限へ先行加算します。
				for( std::size_t jobIndex = 0U; jobIndex < state_->manifest.jobs.size();
					++jobIndex) {
					// 精算済み操作は閉包集合に含まれるため二重加算しません。
					if( str( state_->jobs.GetNamedArray( L"jobs").GetObjectAt(
							   static_cast<std::uint32_t>( jobIndex)),
						   L"state") == L"RUNNING") {
						++running ;
						newRequests +=
							state_->registeredCache( state_->definition.requestKeys[jobIndex])
									.empty()
								? 1U
								: 0U ;
					}
				}

				require(
					operations.size() + running < 300U &&
						(registeredHistory ||
						 state_->root.GetNamedArray( L"cacheInventory").Size() + newRequests < 300U),
					ERROR_TOO_MANY_NAMES) ;
			} else {
				history = std::make_shared<const State::InitialProjectedHistory>(
					state_->inspectInitialProjectedHistory( index, prepared.scopeSha256)) ;
			}
		}

		auto live = controlled ? std::optional<CollectorRecoveryDispatch>( prepared)
							   : std::nullopt ;	// 結合のcopy確保も保存前に行う。
		budget.reservations.push_back( {state_->key, job.key, job.source.rateLimitGroup,
									   started / 1000U, job.source.maximumResponseBytes,
									   job.source.maximumResponseBytes, 0U}) ;
		budget.lastUtc = utcMillis / 1000U ;
		auto &g	   = controls.controls[L"g-" + job.source.rateLimitGroup] ;	// Groupの元待機を保持。
		g.group	   = job.source.rateLimitGroup ;
		g.observed = utcMillis ;
		auto &r	   = controls.controls[L"r-" + request] ;	// Requestだけへ開始intentを結合。
		require( r.group.empty() || r.group == job.source.rateLimitGroup) ;
		r.group				   = job.source.rateLimitGroup ;
		r.request			   = request ;
		r.observed			   = utcMillis ;
		r.generation		   = state_->key ;
		r.job				   = job.key ;
		r.started			   = started ;
		controls.lastUtc	   = utcMillis ;
		const auto controlBody = state_->controlBytes( controls) ;	// 保存前の容量・型確認。
		save( *state_->store, BUDGET, state_->budgetBytes( budget)) ;
		state_->checkpoint( CollectorRecoveryCheckpoint::RESERVED) ;
		save( *state_->store, CONTROL, controlBody) ;
		state_->checkpoint( CollectorRecoveryCheckpoint::STARTED) ;
		put( row, L"state", L"RUNNING") ;
		put( row, L"started", started) ;
		// 永続開始intentなしのRUNNINGは発行しない。
		if( projected) {
			row.Insert( L"intent", intent) ;
		}

		save( *state_->store, state_->statePath(), bytes( state_->jobs)) ;
		state_->checkpoint( CollectorRecoveryCheckpoint::RUNNING) ;
		state_->saveRoot() ;
		state_->reason.clear() ;
		// 保存完了後だけ制御予約を登録し、旧acceptを拒否する。
		if( controlled) {
			*liveSlot = std::move( live) ;
			// 初回根拠は同じ四枠へ保存完了後だけ移します。
			if( projected) {
				const auto slot					 = static_cast<std::size_t>( std::distance(
					 // 元dispatchと同じslot。
					 state_->controlledBindings.begin(), liveSlot)) ;
				state_->projectedHistories[slot] = std::move( history) ;
				state_->nextHistories[slot]		 = std::move( registeredHistory) ;
			}
		}

		dispatch = std::move( prepared) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		state_->error = code ;
	} catch( const std::bad_alloc &) {
		state_->error = projected ? static_cast<DWORD>( E_OUTOFMEMORY) : ERROR_INVALID_DATA ;
	} catch( const winrt::hresult_error &error) {
		state_->error = projected ? static_cast<DWORD>( error.code().value) : ERROR_INVALID_DATA ;
	} catch( ...) {
		state_->error = ERROR_INVALID_DATA ;
	}

	// 射影予約のOOM後も新たな文字列を確保せず第一errorを保持します。
	if( projected && state_->error != ERROR_TOO_MANY_NAMES) {
		state_->reason.swap( state_->projectedFailureReason) ;
		return state_->error ;
	}

	state_->reason = state_->error == ERROR_TOO_MANY_NAMES ? L"STATE_CAPACITY" : L"STATE_ERROR" ;
	return state_->error ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::readiness( const std::uint64_t			utcMillis,
										const std::uint64_t			steadyMillis,
										CollectorRecoveryReadiness &readiness) const
{
	return readinessForMode( utcMillis, steadyMillis, readiness, false) ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::readinessProjected( std::uint64_t				 utcMillis,
												 std::uint64_t				 steadyMillis,
												 CollectorRecoveryReadiness &readiness) const
{
	return readinessForMode( utcMillis, steadyMillis, readiness, true) ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::readinessForMode( std::uint64_t utcMillis, std::uint64_t steadyMillis,
											   CollectorRecoveryReadiness &readiness,
											   bool						   projected) const
{
	readiness = {} ;
	// 保存失敗後は非変更照会でも新予約候補を返さない。
	if( state_->error != 0U) {
		return state_->error ;
	}

	try {
		// 元予約と同じ世代gateを守り、旧入口を新世代へ流用しません。
		require( projected == state_->projectedRequested &&
					state_->storageVersion == (projected ? 3U : 2U),
				ERROR_INVALID_PARAMETER) ;
		require( state_->store && !state_->key.empty(), ERROR_INVALID_PARAMETER) ;
		require( !state_->nextProjected || state_->nextDispatchEnabled, ERROR_RETRY) ;
		require( utcMillis >= state_->now && utcMillis <= LAST_UTC &&
				steadyMillis >= state_->lastSteady) ;
		readiness =
			state_->selectJob( state_->budget(), state_->controls(), utcMillis, steadyMillis) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::accept( std::size_t					  jobIndex,
									 const CollectorRecoveryResponse &response,
									 std::uint64_t utcMillis, std::uint64_t steadyMillis)
{
	return acceptForMode( jobIndex, response, utcMillis, steadyMillis, nullptr, nullptr) ;
}
/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::acceptControlled( const CollectorRecoveryDispatch &binding,
											   const CollectorRecoveryResponse &response,
											   const CollectorIoSnapshot	   &observation,
											   std::uint64_t utcMillis, std::uint64_t steadyMillis)
{
	return acceptForMode( binding.jobIndex, response, utcMillis, steadyMillis, &observation,
						 &binding) ;
}
/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::acceptForMode( std::size_t						 jobIndex,
											const CollectorRecoveryResponse &response,
											std::uint64_t utcMillis, std::uint64_t steadyMillis,
											const CollectorIoSnapshot		*observation,
											const CollectorRecoveryDispatch *binding)
{
	// 保存失敗後は新応答を追加せず最初のerrorを返す。
	if( state_->error != 0U) {
		return state_->error ;
	}

	try {
		// 新profileを旧三role保存へ渡す迂回を拒否する。
		require( !state_->projectedRequested && state_->storageVersion == 2U,
				ERROR_INVALID_PARAMETER) ;
		require( state_->store && !state_->key.empty() && jobIndex < state_->manifest.jobs.size(),
				ERROR_INVALID_PARAMETER) ;
		require( utcMillis >= state_->now && utcMillis <= LAST_UTC &&
				steadyMillis >= state_->lastSteady) ;
		state_->lastSteady = steadyMillis ;
		state_->now		   = utcMillis ;
		const auto row	   = state_->jobs.GetNamedArray( L"jobs").GetObjectAt(
			// 元予約job。
			static_cast<std::uint32_t>( jobIndex)) ;
		require( str( row, L"state") == L"RUNNING") ;

		const auto live = std::find_if( state_->controlledBindings.begin(),
									   state_->controlledBindings.end(), [&]( const auto &entry) {
										   return entry && entry->jobIndex == jobIndex ;
									   }) ; // 元processの予約。
		// 制御予約を旧acceptへ渡して観測を捨てることを禁止する。
		if( observation) {
			// 観測付き応答に必須の元予約がなければ同じ形式errorで停止します。
			if( binding == nullptr) {
				throw static_cast<DWORD>( ERROR_INVALID_DATA) ;
			}

			require( live != state_->controlledBindings.end() &&
					sameCollectorRecoveryDispatch( **live, *binding)) ;
			require( observation->deadlineUtcMillis == binding->deadlineUtcMillis &&
					observation->finishedUtcMillis &&
					*observation->finishedUtcMillis >= binding->anchorUtcMillis &&
					observation->elapsedMillis && steadyMillis >= binding->anchorSteadyMillis &&
					*observation->elapsedMillis <= steadyMillis - binding->anchorSteadyMillis) ;
			require( !observation->headerUtcMillis ||
					*observation->headerUtcMillis >= binding->anchorUtcMillis) ;
			require( observation->cause != CollectorIoCause::COMPLETE ||
					*observation->elapsedMillis <
						binding->deadlineSteadyMillis - binding->anchorSteadyMillis) ;
		} else {
			require( !binding && live == state_->controlledBindings.end()) ;
		}

		const auto object =
			state_->responseObject( jobIndex, response, number( row, L"started"), false,
								   observation) ;	// 元時刻・byte・観測の固定intent。

		// 共有更新の型導出を保存前にも確認する。
		(void)state_->derive(
			jobIndex, object,
			{required( *state_->store, CONTROL),
			 required( *state_->store, path( L"current/campaign-state-v2-", state_->key)),
			 required( *state_->store, BUDGET)}) ;
		const auto op =
			// 元一件の応答slot。
			operation( state_->key, state_->manifest.jobs[jobIndex].key) ;
		require( !state_->storedResponse( op)) ;
		save( *state_->store,
			 path( observation ? L"runs/campaign-response-v3-" : L"runs/campaign-response-v2-", op),
			 bytes( object), true) ;
		state_->checkpoint( CollectorRecoveryCheckpoint::RESPONSE) ;
		state_->commitResponse( jobIndex, object) ;
		state_->completedSteady[state_->manifest.jobs[jobIndex].source.rateLimitGroup] =
			steadyMillis ;
		// 精算完了後だけprocess内の予約正本を解放する。
		if( live != state_->controlledBindings.end()) {
			live->reset() ;
		}

		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		state_->error = code ;
	} catch( ...) {
		state_->error = ERROR_INVALID_DATA ;
	}

	state_->reason = L"STATE_ERROR" ;
	return state_->error ;
}

/** @see local_collector_recovery.h */
const std::shared_ptr<const std::byte> &LocalCollectorRecovery::projectedOwnerToken() const noexcept
{
	return state_->projectedOwner ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::inspectRegisteredProjectedHistory(
	LocalCollectorStateStore &store, const CollectorPreparedProjectedJob &job,
	const std::span<const CollectorCampaignSource> sources, const std::uint64_t utcMillis,
	std::shared_ptr<const CollectorRegisteredProjectedHistory>	   &history,
	const std::function<std::int32_t( CollectorProjectedHashStage)> &probe,
	CollectorHistoryReadDiagnostics								   *diagnostics)
{
	return inspectProjectedHistoryCore( store, &job, sources, utcMillis, L"", history, probe, false,
									   nullptr, false, false, false, false, nullptr, false, nullptr,
									   diagnostics) ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::inspectCompletedRootInventory(
	LocalCollectorStateStore &store, const std::span<const CollectorCampaignSource> sources,
	const std::uint64_t										utcMillis,
	std::shared_ptr<const CollectorCompletedRootInventory> &inventory,
	const std::function<DWORD()> &beforeFinalRecheck, CollectorHistoryReadDiagnostics *diagnostics)
{
	return inspectCompletedRootInventoryBound( store, sources, utcMillis, inventory,
											  beforeFinalRecheck, diagnostics, {}) ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::inspectCompletedRootInventoryBound(
	LocalCollectorStateStore &store, const std::span<const CollectorCampaignSource> sources,
	const std::uint64_t										utcMillis,
	std::shared_ptr<const CollectorCompletedRootInventory> &inventory,
	const std::function<DWORD()> &beforeFinalRecheck, CollectorHistoryReadDiagnostics *diagnostics,
	const std::function<DWORD( const CollectorCompletedRootEvidence &,
							  const std::function<DWORD()> &)> &couple)
{
	inventory.reset() ;
	// 借用拒否時にも前回の部分観測を返しません。
	if( diagnostics) {
		*diagnostics = {} ;
	}

	std::byte  borrower{} ;										// この同期呼出しだけの非再利用借用tokenです。
	const auto borrowed = store.borrowCampaign( &borrower) ;	// 既存監督／worker能力と併存しません。
	// 非writerと借用競合の元errorを維持します。
	if( borrowed != ERROR_SUCCESS) {
		return borrowed ;
	}

	std::shared_ptr<const CollectorRegisteredProjectedHistory>
			   history ;	// 要求contextは発行しません。
	const auto error = inspectProjectedHistoryCore( store, nullptr, sources, utcMillis, L"", history,
												   {}, false, nullptr, false, false, false, false,
												   nullptr, false, nullptr, diagnostics, &inventory,
												   beforeFinalRecheck, couple) ;	// 第一errorです。
	store.releaseCampaign( &borrower) ;
	return error ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::inspectProjectedHistoryCore(
	LocalCollectorStateStore &store, const CollectorPreparedProjectedJob *job,
	const std::span<const CollectorCampaignSource> sources, const std::uint64_t utcMillis,
	const std::wstring_view											expectedRoot,
	std::shared_ptr<const CollectorRegisteredProjectedHistory>	   &history,
	const std::function<std::int32_t( CollectorProjectedHashStage)> &probe, const bool allowActive,
	std::set<std::wstring> *verifiedOperations, const bool allowPrepared, const bool allowCommit,
	const bool allowPartialStart, const bool allowDayRoll, std::string *verifiedDayRoll,
	const bool allowFinish, std::optional<std::array<std::string, 4U>> *verifiedFinish,
	CollectorHistoryReadDiagnostics							   *diagnostics,
	std::shared_ptr<const CollectorCompletedRootInventory>	   *completedInventory,
	const std::function<DWORD()>							   &beforeFinalRecheck,
	const std::function<DWORD( const CollectorCompletedRootEvidence &,
							  const std::function<DWORD()> &)> &couple)
{
	// 失敗後に旧封印contextをfresh根拠へ流用しません。
	if( completedInventory) {
		completedInventory->reset() ;
	}

	// 前回の部分観測を新しい成功や拒否根拠へ流用しません。
	if( diagnostics) {
		*diagnostics = {} ;
	}

	// 失敗時に旧完了候補を新しい保存権限へ転用しません。
	if( verifiedFinish) {
		verifiedFinish->reset() ;
	}

	// 失敗時に旧intentを新たな日次保存権限へ流用しません。
	if( verifiedDayRoll) {
		verifiedDayRoll->clear() ;
	}

	// 失敗後に旧検査済み集合を新しい保存権限へ流用しません。
	if( verifiedOperations) {
		verifiedOperations->clear() ;
	}

	const auto previousOutput =
		// 入力job／sourceが旧出力を借用していても寿命を保ちます。
		std::move( history) ;
	(void)previousOutput ;
	try {
		require( utcMillis >= 1000U && utcMillis <= LAST_UTC) ;
		require( !allowPrepared || allowActive) ;
		require( !allowPartialStart || allowActive) ;
		require( !allowCommit || (allowActive && allowPrepared && !job && !expectedRoot.empty())) ;
		require( !allowDayRoll || (!job && !expectedRoot.empty() && !allowActive && !allowPrepared &&
								  !allowCommit && !allowPartialStart)) ;
		require( !verifiedDayRoll || allowDayRoll) ;
		require( !allowFinish || (allowActive && !job && !expectedRoot.empty() && !allowPrepared &&
								 !allowCommit && !allowPartialStart && !allowDayRoll)) ;
		require( !verifiedFinish || allowFinish) ;
		RegisteredHistoryReader reader( store, diagnostics,
									   completedInventory != nullptr) ;	// 封印だけ先払いします。
		State					scratch ;								// Lease・process予約を持たない導出用の所有入力。
		scratch.now				= utcMillis ;
		const auto physicalRoot = reader.physicalBody( ROOT) ;	// 元登録hashは物理本文へ結合します。
		require( physicalRoot && (expectedRoot.empty() || sha( *physicalRoot) == expectedRoot)) ;
		scratch.root = json( *physicalRoot) ;
		// 日次例外は通常全完了inventoryだけ。既存の四role応答例外とは混用しません。
		if( allowDayRoll) {
			scratch.store		  = &store ;
			scratch.historyReader = &reader ;
			scratch.prepareProjectedDayRollView( reader) ;
		}

		std::optional<std::pair<std::wstring, bool>>
			committed ;	// 元操作と新CACHE追加だけを上限へ結合します。
		// 通常起動の登録v4 commitだけを、物理書換えなしの固定五前像へ解釈します。
		if( allowCommit && scratch.root.GetNamedValue( L"commit").ValueType() !=
							  winrt::Windows::Data::Json::JsonValueType::Null) {
			scratch.store		  = &store ;
			scratch.historyReader = &reader ;
			committed			  = scratch.prepareRegisteredCommitView( reader, sources) ;
		}

		const auto rootBody = reader.mandatory( ROOT) ;	// 検査専用前像または元物理本文。
		scratch.root		= json( rootBody) ;
		fields( scratch.root,
			   {L"schema", L"rootKey", L"lastUtcMillis", L"legacyDigest", L"legacyFileCount",
				L"legacyLastUsedDay", L"legacyFiles", L"generations", L"archives",
				L"activeGeneration", L"commit", L"upgradeFrom", L"cacheInventory"}) ;
		const auto mode = json( reader.mandatory( MODE)) ;	// 同じstoreのmodeとrootKey。
		fields( mode, {L"schema", L"rootKey"}) ;
		require( str( scratch.root, L"schema") == L"collector-campaign-root-v3" &&
				hash( str( scratch.root, L"rootKey")) &&
				str( mode, L"schema") == L"collector-campaign-mode-v1" &&
				str( mode, L"rootKey") == str( scratch.root, L"rootKey") &&
				number( scratch.root, L"lastUtcMillis") >= 1000U &&
				number( scratch.root, L"lastUtcMillis") <= utcMillis &&
				scratch.root.GetNamedValue( L"commit").ValueType() ==
					winrt::Windows::Data::Json::JsonValueType::Null) ;
		require( hash( str( scratch.root, L"legacyDigest")) &&
				number( scratch.root, L"legacyFileCount") <= 18000U &&
				scratch.root.GetNamedArray( L"legacyFiles").Size() <= 18000U &&
				(scratch.root.GetNamedValue( L"upgradeFrom").ValueType() ==
					 winrt::Windows::Data::Json::JsonValueType::Null ||
				 hash( str( scratch.root, L"upgradeFrom")))) ;
		std::map<std::wstring, Object> registrations ;	// 有限・一意な元世代登録。
		const auto					   generationRows =
			// 登録簿だけを検査します。
			scratch.root.GetNamedArray( L"generations") ;
		require( generationRows.Size() <= 300U, ERROR_TOO_MANY_NAMES) ;
		bool completed = false ;	// 完了登録があれば全CACHEと全世代の非変更検査を要求します。
		// 未参照の登録でも未知保存版・重複・不正summaryは拒否します。
		for( const auto &entry : generationRows) {
			const auto row = entry.GetObject() ;	// 元登録一行。
			fields( row, {L"generation", L"inputHash", L"summaryHash", L"storageVersion"}) ;
			require(
				hash( str( row, L"generation")) && hash( str( row, L"inputHash")) &&
				(str( row, L"summaryHash").empty() ||
				 (number( row, L"storageVersion") == 3U && hash( str( row, L"summaryHash")))) &&
				(number( row, L"storageVersion") == 2U || number( row, L"storageVersion") == 3U) &&
				registrations.emplace( str( row, L"generation"), row).second) ;
			completed = completed || !str( row, L"summaryHash").empty() ;
			// 完了保存中は読取り入口で回復せず、通常回復後の独立検査を要求します。
			if( str( row, L"summaryHash").empty() && !allowFinish) {
				require( !reader.body( path( L"runs/campaign-finish-v1-", str( row, L"generation")))) ;
			}
		}

		require( job || completed) ;
		// 公開読取りは全完了だけ。内部入口は完了prefix＋一つの未完了末尾を別検査へ結合します。
		if( completed) {
			const auto active =
				// 末尾以外の稼働を拒否する。
				str( scratch.root, L"activeGeneration") ;
			require( active.empty() || (allowActive && hash( active) && generationRows.Size() > 1U)) ;
			// 全登録を元順序で検査し、間に未完了を挟まない。
			for( std::uint32_t index = 0U; index < generationRows.Size(); ++index) {
				const auto row = generationRows.GetObjectAt( index) ;	// 元登録順の一行。
				const bool tail =
					!active.empty() && index + 1U == generationRows.Size() ;	// 稼働末尾だけ。
				require( number( row, L"storageVersion") == 3U &&
						(tail
							 ? str( row, L"summaryHash").empty() && str( row, L"generation") == active
							 : !str( row, L"summaryHash").empty())) ;
			}

			reader.captureNames() ;
			scratch.store		  = &store ;
			scratch.historyReader = &reader ;
		} else {
			require( registrations.contains( str( scratch.root, L"activeGeneration")) &&
					!reader.body( FINISH_POINTER)) ;
		}

		std::map<std::wstring, std::wstring> inventory ;	// 登録CACHEのrequestと実本文hash。
		const auto							 cacheRows =
			// 未登録を初回へ変換しません。
			scratch.root.GetNamedArray( L"cacheInventory") ;
		require( cacheRows.Size() <= 300U, ERROR_TOO_MANY_NAMES) ;
		// 全登録keyを検査し、二重登録や不正path用hashを拒否します。
		for( const auto &entry : cacheRows) {
			const auto row = entry.GetObject() ;	// 一つのCACHE登録。
			fields( row, {L"request", L"hash"}) ;
			require( hash( str( row, L"request")) && hash( str( row, L"hash")) &&
					inventory.emplace( str( row, L"request"), str( row, L"hash")).second) ;
		}

		const auto registered =
			job ? inventory.find( job->value().requestKey)
				: inventory.end() ;	// 通常検査は要求requestを作らず全登録を検査します。
		require( !job || registered != inventory.end() || allowActive) ;
		require( reader.mandatory( BUDGET_MARKER) == "collector-campaign-budget-root-v1" &&
				reader.mandatory( CONTROL_MARKER) == "collector-campaign-controls-root-v1") ;
		CollectorBudgetSnapshot currentBudget ;							// 当日共有予算は元I/Oの精算先へ再結合します。
		CollectorWaitSnapshot	currentControl ;						// 完了結果から後退していない共有待機。
		const auto currentBudgetBody  = reader.mandatory( BUDGET) ;		// 終了時にもraw再照合します。
		const auto currentControlBody = reader.mandatory( CONTROL) ;	// 現時刻へ期限を延長しません。
		require( parseCollectorBudgetSnapshot( currentBudgetBody, currentBudget) &&
				parseCollectorWaitSnapshot( currentControlBody, currentControl) &&
				currentBudget.lastUtc <= utcMillis / 1000U && currentControl.lastUtc <= utcMillis) ;
		const bool sharedClockAhead =
			currentBudget.lastUtc > number( scratch.root, L"lastUtcMillis") / 1000U ||
			currentControl.lastUtc >
				// ROOT保存前の先行は後段で証明します。
				number( scratch.root, L"lastUtcMillis") ;
		// 通常callerでは従来の上限を維持し、専用flagだけで時計先行を確定許可しません。
		if( completed) {
			require( !sharedClockAhead || allowPartialStart) ;
		}

		std::map<std::wstring, std::wstring> archives ;	// 参照日の固定archive登録だけを所有します。
		const auto							 archiveRows =
			// 後続の全日次受入とは区別します。
			scratch.root.GetNamedArray( L"archives") ;
		require( archiveRows.Size() <= 300U, ERROR_TOO_MANY_NAMES) ;
		// 日付をpathへ入れる前に形式と一意性を検査します。
		for( const auto &entry : archiveRows) {
			const auto row = entry.GetObject() ;	// 日次登録の一行。
			fields( row, {L"day", L"hash", L"operation"}) ;
			const auto date = str( row, L"day") ;	// 固定8桁の公開日。
			require( date.size() == 8U &&
					std::all_of( date.begin(), date.end(),
								[]( wchar_t c) { return c >= L'0' && c <= L'9' ; }) &&
					date <= day( utcMillis) && hash( str( row, L"hash")) &&
					hash( str( row, L"operation")) &&
					archives.emplace( date, str( row, L"hash")).second) ;
		}

		std::set<std::wstring>
				   allVerified ;	// 呼出し全体で最大300操作。旧完了集計への内部証明だけです。
		// 同じreader／root／精算先を借用する同期検査。request単位で読取り予算をリセットしません。
		const auto inspectCache = [&]( const std::wstring &request)
			-> std::shared_ptr<const CollectorRegisteredProjectedHistory> {
			const auto cacheRegistration = inventory.find( request) ;	// 全登録検査済みの一request。
			require( cacheRegistration != inventory.end()) ;
			const auto cacheBody = reader.mandatory(
				// 原hash照合用の最新本文。
				path( L"current/campaign-cache-v1-", request)) ;
			CollectorProjectedCache latest ;	// 参照閉包の検査までは出力へ公開しません。
			const auto				decodedCache =
				// 全field検査。
				decodeCollectorProjectedCache( cacheBody, latest) ;
			require( decodedCache.status == collector_projected_json::Status::OK,
					decodedCache.error != 0 ? static_cast<DWORD>( decodedCache.error)
											: ERROR_INVALID_DATA) ;
			require( latest.request == request && sha( cacheBody) == cacheRegistration->second) ;

			/** @brief 元登録・全四role・元応答を所有する一操作の検証値です。 */
			struct Node {
				/// 元G／O／応答hash。
				CollectorCacheAttempt									  attempt ;
				/// 検証した元canonical input。
				std::string												  input ;
				/// 組み込みsourceと元artifactへ結合した全job。
				std::shared_ptr<const CollectorPreparedProjectedCampaign> campaign ;
				/// 元job index。
				std::size_t												  index{} ;
				/// 専用codecで保持したv4。中断時はnull。
				std::optional<CollectorProjectedResponseBytes>			  response ;
				/// 旧欠測中断のcanonical本文。V4時は空。
				std::string												  interrupted ;
				/// 元RUNNINGの開始intent。旧予算保存窓では空。
				std::string												  intent ;
				/// 元予約開始UTC。
				std::uint64_t											  started{} ;
				/// 元親受領UTC。
				std::uint64_t											  accepted{} ;
				/// 更新前のCACHE。初回はnull。
				std::optional<std::string>								  before ;
				/// 更新前の型付きCACHE。
				std::optional<CollectorProjectedCache>					  beforeValue ;
				/// 再計算と比較するCACHE更新後像。
				std::string												  after ;
				/// 全参照を閉包へ加える更新後CACHE値。
				CollectorProjectedCache									  afterValue ;
			} ;
			std::vector<CollectorCacheAttempt>			  pending ;	// 最大300操作の有限閉包。
			std::map<std::wstring, CollectorCacheAttempt> claims ;	// 同Oへ別G／応答を結合しません。
			std::map<std::wstring, Node> nodes ;					// 全immutable根拠を所有して再計算します。
			// 呼出し中だけpendingとclaimsを借用し、重複を排除して全参照を追加します。
			const auto					 add = [&]( const CollectorCacheAttempt &attempt) {
				  require( hash( attempt.generation) && hash( attempt.operation) &&
										  hash( attempt.response)) ;
				  const auto found = claims.find( attempt.operation) ;	// 既存の同操作宣言。
				  // 同じ操作への相反する参照を拒否します。
				  if( found != claims.end()) {
					  require( found->second.generation == attempt.generation &&
											  found->second.response == attempt.response) ;
					  return ;
				  }

				  require( pending.size() < 300U, ERROR_TOO_MANY_NAMES) ;
				  claims.emplace( attempt.operation, attempt) ;
				  pending.push_back( attempt) ;
			} ;
			// CACHE内のattemptだけでなく全成功参照を同じ閉包へ結合する同期lambdaです。
			const auto addCache = [&]( const CollectorProjectedCache &value) {
				require( value.request == latest.request) ;
				add( value.attempt) ;
				// Sliceの保存順を保ち全参照を検査します。
				for( const auto &slice : value.slices) {
					add( {slice.generation, slice.operation, slice.response}) ;
				}

				// 元200の参照を単なる文字列として受理しません。
				if( value.original200) {
					add( {value.original200->generation, value.original200->operation,
						 value.original200->response}) ;
				}

				// 最後の検証参照も欠損・改変を拒否します。
				if( value.validated) {
					add( {value.validated->generation, value.validated->operation,
						 value.validated->response}) ;
				}
			} ;
			addCache( latest) ;
			// 全参照と更新前CACHEを固定名からたどります。追加込み最大300操作で終了します。
			for( std::size_t cursor = 0U; cursor < pending.size(); ++cursor) {
				Node node ;	// Vector拡張に影響されない元参照を所有します。
				node.attempt = pending[cursor] ;
				const auto registration =
					// Rootに登録された元世代。
					registrations.find( node.attempt.generation) ;
				require( registration != registrations.end() &&
						number( registration->second, L"storageVersion") == 3U) ;
				node.input =
					reader.mandatory( path( L"runs/campaign-input-v3-", node.attempt.generation)) ;
				scratch.adoptInput( json( node.input), 3U) ;
				require( scratch.key == node.attempt.generation &&
						sha( node.input) == str( registration->second, L"inputHash") &&
						str( scratch.input, L"day") <= day( utcMillis) &&
						prepareCollectorProjectedCampaign(
							node.input, str( registration->second, L"inputHash"), scratch.key,
							scratch.definition.artifactSha256, sources, node.campaign) &&
						reader.mandatory( path( L"runs/campaign-marker-v3-", scratch.key)) ==
							scratch.projectedMarker( str( registration->second, L"inputHash"))) ;
				const auto currentState = json(
					// 後続jobの更新を許し元行は保持します。
					reader.mandatory( scratch.statePath())) ;
				validateJobs( currentState, scratch.key, scratch.manifest, true, true) ;
				scratch.validateIntents( currentState) ;
				const auto manifestJob = std::find_if(
					scratch.manifest.jobs.begin(), scratch.manifest.jobs.end(),
					[&]( const auto &entry) {
						return operation( scratch.key, entry.key) == node.attempt.operation ;
					}) ; // 現呼出し中の元G／Oだけへ解決します。
				require( manifestJob != scratch.manifest.jobs.end()) ;
				node.index = static_cast<std::size_t>( manifestJob - scratch.manifest.jobs.begin()) ;
				const auto *oldJob =
					// 元の全scopeを持つ変更不能入力。
					node.campaign->job( node.index) ;
				require( oldJob && oldJob->value().requestKey == latest.request) ;
				const auto v2 = reader.raw(
					// 併存も固定します。
					path( L"runs/campaign-response-v2-", node.attempt.operation)) ;
				const auto v3 = reader.raw( path( L"runs/campaign-response-v3-",
												node.attempt.operation)) ;	// 新世代へ変換しません。
				const auto v4 = reader.raw(
					// 専用元byte。
					path( L"runs/campaign-response-v4-", node.attempt.operation)) ;
				require( !v3 && (v2.has_value() != v4.has_value())) ;
				Object response ;	// 導出関数へ渡すfield観測。V4のhashは元byteを使います。
				// V4は専用canonical codecで独立read-backします。
				if( v4) {
					node.response.emplace() ;
					const auto result = decodeCollectorProjectedResponse(
						// 原hash error。
						oldJob->value(), *v4, *node.response, probe) ;
					require( result.result.status == collector_projected_json::Status::OK,
							result.result.error != 0 ? static_cast<DWORD>( result.result.error)
													 : ERROR_INVALID_DATA) ;
					require( node.response->responseSha256 == node.attempt.response &&
							node.response->value.generation == scratch.key &&
							node.response->value.state != CollectorMetadataOutcome::REVALIDATED) ;
					response = Object::Parse( winrt::to_hstring( node.response->response)) ;
				} else {
					node.interrupted = reader.mandatory(
						path( L"runs/campaign-response-v2-", node.attempt.operation)) ;
					response = json( node.interrupted) ;
					require( str( response, L"state") == L"INTERRUPTED" &&
							sha( node.interrupted) == node.attempt.response) ;
				}

				node.started  = number( response, L"started") ;
				node.accepted = number( response, L"accepted") ;
				require( node.accepted <= utcMillis &&
						node.accepted <= number( scratch.root, L"lastUtcMillis")) ;
				const auto &op = node.attempt.operation ;	// Hash検査済みの固定effect名。
				const std::array<std::string, 3> before = {
					reader.mandatory( scratch.effectPath( op, L"CONTROL", true, true)),
					reader.mandatory( scratch.effectPath( op, L"JOB", true, true)),
					// 全更新前像。
					reader.mandatory( scratch.effectPath( op, L"BUDGET", true, true))} ;
				const auto derived =
					scratch.derive( node.index, response, before,
								   node.response ? &*node.response : nullptr) ;	// 共通精算core。
				CollectorWaitSnapshot
					settledControl ;	// 元更新後の待機が現在値から消えていないか検査します。
				require( parseCollectorWaitSnapshot( derived[0], settledControl) &&
						currentControl.lastUtc >= settledControl.lastUtc) ;
				// 当requestとgroupだけを現在共有台帳へ再結合します。他jobの正当な前進を許します。
				for( const auto &controlKey :
					{L"r-" + latest.request, L"g-" + manifestJob->source.rateLimitGroup}) {
					const auto oldControl =
						// 元精算後の当該行。
						settledControl.controls.find( controlKey) ;
					const auto savedControl =
						// 現在の同じ行。
						currentControl.controls.find( controlKey) ;
					require( oldControl != settledControl.controls.end() &&
							savedControl != currentControl.controls.end() &&
							oldControl->second.group == savedControl->second.group &&
							oldControl->second.request == savedControl->second.request &&
							savedControl->second.observed >= oldControl->second.observed &&
							savedControl->second.completed >= oldControl->second.completed &&
							savedControl->second.notBefore >= oldControl->second.notBefore &&
							(!oldControl->second.review || savedControl->second.review)) ;
				}

				// 同じ原I/Oと未精算予約から三roleを再計算し全byteで比較します。
				for( std::size_t role = 0U; role < 3U; ++role) {
					const std::array<std::wstring, 3> roles = {L"CONTROL", L"JOB",
															   L"BUDGET"} ;	// 旧固定role順。
					require( reader.mandatory( scratch.effectPath( op, roles[role], false, true)) ==
							derived[role]) ;
				}

				const auto afterState = json( derived[1]) ;	// 元terminal行を現在表へ再結合します。
				require( bytes( currentState.GetNamedArray( L"jobs").GetObjectAt(
							static_cast<std::uint32_t>( node.index))) ==
						bytes( afterState.GetNamedArray( L"jobs").GetObjectAt(
							static_cast<std::uint32_t>( node.index)))) ;
				const auto beforeRow = json( before[1]).GetNamedArray( L"jobs").GetObjectAt(
					// 元開始行。
					static_cast<std::uint32_t>( node.index)) ;
				// 中断の予約保存窓だけはintent不在を保持します。
				if( beforeRow.GetNamedValue( L"intent").ValueType() !=
				   winrt::Windows::Data::Json::JsonValueType::Null) {
					node.intent = bytes( beforeRow.GetNamedObject( L"intent")) ;
				}

				CollectorBudgetSnapshot
					settled ;	// 元更新後予算と現共有／archiveの予約を比較します。
				require( parseCollectorBudgetSnapshot( derived[2], settled)) ;
				CollectorBudgetSnapshot destination = currentBudget ;	// 同じ日の精算先。
				// 過去日は登録された元日付のarchiveへ解決します。
				if( destination.day != settled.day) {
					const auto archived = archives.find( settled.day) ;	// 元日付の登録hash。
					require( archived != archives.end()) ;
					const auto body =
						// 固定8桁名。
						reader.mandatory( L"runs/campaign-budget-" + settled.day + L".json") ;
					require( sha( body) == archived->second &&
							parseCollectorBudgetSnapshot( body, destination) &&
							destination.day == settled.day) ;
				}

				const auto originalReservation = std::find_if(
					settled.reservations.begin(), settled.reservations.end(), [&]( const auto &r) {
						return r.campaign == scratch.key && r.job == manifestJob->key ;
					}) ; // 元更新後の一件。
				const auto savedReservation =
					std::find_if( destination.reservations.begin(), destination.reservations.end(),
								 [&]( const auto &r) {
									 return r.campaign == scratch.key && r.job == manifestJob->key ;
								 }) ; // 現精算先の同じ一件。
				require( originalReservation != settled.reservations.end() &&
						savedReservation != destination.reservations.end() &&
						originalReservation->group == savedReservation->group &&
						originalReservation->phase == savedReservation->phase &&
						originalReservation->started == savedReservation->started &&
						originalReservation->maximum == savedReservation->maximum &&
						originalReservation->charged == savedReservation->charged) ;
				node.before = reader.body( scratch.effectPath( op, L"CACHE", true, true)) ;
				// 前回値の全参照もbinding差を理由に省略しません。
				if( node.before) {
					node.beforeValue.emplace() ;
					const auto result =
						// 前回全field。
						decodeCollectorProjectedCache( *node.before, *node.beforeValue) ;
					require( result.status == collector_projected_json::Status::OK,
							result.error != 0 ? static_cast<DWORD>( result.error)
											  : ERROR_INVALID_DATA) ;
					addCache( *node.beforeValue) ;
				}

				node.after = reader.mandatory( scratch.effectPath( op, L"CACHE", false, true)) ;
				const auto result =
					// 更新後全参照。
					decodeCollectorProjectedCache( node.after, node.afterValue) ;
				require( result.status == collector_projected_json::Status::OK,
						result.error != 0 ? static_cast<DWORD>( result.error) : ERROR_INVALID_DATA) ;
				require( node.afterValue.binding == oldJob->value().cacheBinding &&
						node.afterValue.attempt.operation == op &&
						node.afterValue.attempt.generation == scratch.key &&
						node.afterValue.attempt.response == node.attempt.response) ;
				addCache( node.afterValue) ;
				nodes.emplace( op, std::move( node)) ;
			}

			std::vector<const Node *>
				candidates ;	// 元受領時刻順の有限候補。等時刻の依存順は下で解決します。
			// Map所有値の安定pointerを有限に並べます。
			for( const auto &entry : nodes) {
				candidates.push_back( &entry.second) ;
			}

			std::sort( candidates.begin(), candidates.end(), []( const Node *a, const Node *b) {
				return a->accepted < b->accepted ||
					   (a->accepted == b->accepted && a->attempt.operation < b->attempt.operation) ;
			}) ;
			std::set<std::wstring>	  verified ;	// 再計算済み前回だけをCACHE更新の根拠にします。
			std::vector<const Node *> ordered ;		// 再計算が完了した依存順。最大300件。
			// 毎回一操作以上が前進する最大300巡回で、等時刻の正当な前後と循環を区別します。
			while( verified.size() < nodes.size()) {
				const auto previousSize = verified.size() ;	// 循環で停止せず反復することを防ぎます。
				// 旧値が検証済みになった操作だけを再計算します。一巡は最大300操作です。
				for( const auto *node : candidates) {
					// 検証済み操作を二度適用しません。
					if( verified.contains( node->attempt.operation)) {
						continue ;
					}

					// 更新前像は前回attemptの完全な更新後像でなければ拒否します。
					if( node->beforeValue) {
						const auto prior =
							// 元の直前更新。
							nodes.find( node->beforeValue->attempt.operation) ;
						require( prior != nodes.end() && prior->second.after == *node->before &&
								prior->second.accepted <= node->started) ;
						// 等時刻でも元更新の検証を先に行います。循環は巡回末尾で拒否します。
						if( !verified.contains( prior->first)) {
							continue ;
						}
					}

					CollectorProjectedCache
								recomputed ;	// 元応答と検査済み前回値だけから導出します。
					const auto *basis =
						node->beforeValue ? &*node->beforeValue : nullptr ;	// 初回だけnull。
					// 全履歴検査後の元応答によるCACHE導出結果。
					const auto result =
						node->response ? deriveCollectorProjectedCache(
											 node->campaign->job( node->index)->value(),
											 node->response->envelope, basis, recomputed, probe)
									   : makeInterruptedCollectorCache(
											 latest.request,
											 node->campaign->job( node->index)->value().cacheBinding,
											 node->attempt, basis, recomputed) ;
					require( result.status == collector_projected_json::Status::OK,
							result.error != 0 ? static_cast<DWORD>( result.error)
											  : ERROR_INVALID_DATA) ;
					std::string body ;	// 同じ有限codecのcanonical更新後像。
					const auto	encoded =
						// 全byte照合用。
						encodeCollectorProjectedCache( recomputed, body) ;
					require( encoded.status == collector_projected_json::Status::OK,
							encoded.error != 0 ? static_cast<DWORD>( encoded.error)
											   : ERROR_INVALID_DATA) ;
					require( body == node->after) ;
					verified.insert( node->attempt.operation) ;
					ordered.push_back( node) ;
				}

				require( verified.size() > previousSize) ;
			}

			require( nodes.at( latest.attempt.operation).after == cacheBody) ;
			// 同期呼出し中だけnodesを借用して直接参照の元成功200を厳格に解決します。
			const auto original = [&]( const CollectorProjectedOriginal200 &ref)
				-> const CollectorProjectedResponse & {
				const auto &node = nodes.at( ref.operation) ;	// 閉包へ追加済みの元操作。
				require( node.response.has_value()) ;
				const auto &value = node.response->value ;	// 元codecで検査済みの成功候補。
				require( node.attempt.generation == ref.generation &&
						node.attempt.response == ref.response &&
						value.state == CollectorMetadataOutcome::FETCHED && value.status == 200U &&
						value.cacheDecision.action == CollectorProjectedCacheAction::REPLACE &&
						value.projection == ref.projection && value.body == ref.body &&
						value.io.headerUtcMillis && *value.io.headerUtcMillis == ref.headerUtc) ;
				return value ;
			} ;
			// 再計算済み全CACHEの元200・検証・sliceの具体的な採用事実を検査します。
			for( const auto *node : ordered) {
				const auto &value = node->afterValue ;	// 全更新後像。
				// 元200は完全200と元headerへ結合します。
				if( value.original200) {
					(void)original( *value.original200) ;
				}

				// 現入口は304成功を受け付けず、validatedは元200と同じ参照です。
				if( value.validated) {
					require( value.original200 &&
							value.validated->generation == value.original200->generation &&
							value.validated->operation == value.original200->operation &&
							value.validated->response == value.original200->response &&
							value.validated->projection == value.original200->projection &&
							value.validated->headerUtc == value.original200->headerUtc) ;
				}

				// Sliceごとの最後の成功参照を実metadataのACCEPTEDへ結合します。
				for( const auto &slice : value.slices) {
					const auto &source =
						// 別bindingでも元内容を検査します。
						nodes.at( slice.operation) ;
					require( source.response && source.attempt.generation == slice.generation &&
							source.attempt.response == slice.response &&
							source.response->value.projection == slice.projection &&
							source.response->value.state == CollectorMetadataOutcome::FETCHED &&
							source.response->value.status == 200U &&
							source.accepted <= node->accepted) ;
					const auto found = std::find_if( source.response->value.metadata.slices.begin(),
													source.response->value.metadata.slices.end(),
													[&]( const auto &entry) {
														return entry.scope.key == slice.slice ;
													}) ; // 元sliceの採用事実を同期検査します。
					require( found != source.response->value.metadata.slices.end() &&
							found->disposition == CollectorMetadataDisposition::ACCEPTED) ;
				}
			}

			std::vector<CollectorProjectedHistoryEvidence>
				evidence ;	// 最大16成功sliceの全元byteを所有します。
			// 最新CACHEの保存順を維持して既存最終化coreへ渡せる所有値を作ります。
			for( const auto &slice : latest.slices) {
				const auto &node = nodes.at( slice.operation) ;	// 全閉包検証済みの元成功。
				evidence.push_back( {node.campaign, node.index, slice.generation, slice.operation,
									slice.response, slice.projection, slice.slice, node.input,
									node.intent, node.response->envelope}) ;
			}

			// 全参照検査済みの元操作だけを完了集計の再導出へ共有します。request跨ぎ重複は拒否します。
			for( const auto &[op, node] : nodes) {
				require( allVerified.size() < 300U, ERROR_TOO_MANY_NAMES) ;
				require( allVerified.insert( op).second) ;
			}

			return std::make_shared<const CollectorRegisteredProjectedHistory>(
				CollectorRegisteredProjectedHistory::ConstructionKey{}, std::move( latest),
				std::move( evidence), sha( rootBody), cacheRegistration->second, nodes.size()) ;
		} ;

		std::vector<CollectorCompletedCacheReference> cacheReferences ;		// 同じ閉包検査の元参照です。
		std::shared_ptr<const CollectorRegisteredProjectedHistory> result ;	// 公開前の所有候補。
		// 全完了時だけ他requestも検証します。従来の未完了入口は参照閉包の契約を維持します。
		if( completed) {
			// 最大300登録を同じreaderで順次検証し、全request合計の操作上限も保持します。
			for( const auto &[request, cacheHash] : inventory) {
				auto candidate = inspectCache( request) ;	// 同じ有限readerで順次再導出します。
				// 完了根拠だけが最新登録と検査済みbindingを所有します。
				if( completedInventory) {
					cacheReferences.push_back( {request, cacheHash, candidate->cache().binding}) ;
				}

				// 呼出し対象のcontextだけを保持し、他requestの成功を混入させません。
				if( job && registered != inventory.end() && request == registered->first) {
					result = std::move( candidate) ;
				}
			}
		} else {
			result = inspectCache( registered->first) ;
		}

		// 全完了世代の元集計・日次切替・全保存名を同じ検査済みCACHE鎖へ再結合します。
		if( completed) {
			scratch.inspectCompletedHistory( reader, sources, allVerified, allowActive,
											allowPrepared, allowPartialStart, allowFinish) ;
			require( !sharedClockAhead || reader.partialStartVerified) ;
		}

		// 登録中の一操作と新CACHEを加えても全体の有限上限を超えないことを先に確認します。
		if( committed) {
			require( !allVerified.contains( committed->first) && allVerified.size() < 300U &&
						(!committed->second || cacheRows.Size() < 300U),
					ERROR_TOO_MANY_NAMES) ;
		}

		std::optional<CollectorCompletedRootEvidence> evidence ;	// 全raw再照合前の候補です。
		bool coupledRecheck = false ;								// 私有結合時だけ一回の同期再照合成功を保持します。
		require( !couple || completedInventory) ;
		// 回復例外を持たない全完了rootだけから実raw封印を導出します。
		if( completedInventory) {
			require( !job && completed && !allowActive && !allowPrepared && !allowCommit &&
					!allowPartialStart && !allowDayRoll && !allowFinish) ;
			evidence =
				makeCompletedRootEvidence( reader, rootBody, sources, utcMillis, allVerified.size(),
										  currentBudgetBody, currentControlBody) ;
			evidence->caches = std::move( cacheReferences) ;
			// Fixtureの成功値は受け取らず、後続全raw再照合を必ず実行します。
			if( beforeFinalRecheck) {
				io( beforeFinalRecheck()) ;
			}

			// 私有結合監督は共有借用中にこの元readerを一回だけ再検査します。
			if( couple) {
				const std::function<DWORD()> recheck = [&reader, &coupledRecheck]() -> DWORD {
					try {
						require( !coupledRecheck, ERROR_BUSY) ;
						reader.recheck() ;
						coupledRecheck = true ;
						return ERROR_SUCCESS ;
					} catch( const DWORD code) {
						return code ;
					} catch( const std::bad_alloc &) {
						return static_cast<DWORD>( E_OUTOFMEMORY) ;
					} catch( const winrt::hresult_error &error) {
						return static_cast<DWORD>( error.code().value) ;
					} catch( ...) {
						return ERROR_INVALID_DATA ;
					}
				} ; // Readerと完了flagはこの同期couple呼出しより長く存続します。
				io( couple( *evidence, recheck)) ;
				require( coupledRecheck) ;
			}
		}

		// 従来入口は同じ最終検査を行い、私有結合時は成功済み再検査を二重課金しません。
		if( !coupledRecheck) {
			reader.recheck() ;
		}

		// Contextの構築keyは全raw／全名の再照合成功後だけ使用します。
		if( completedInventory) {
			*completedInventory = std::make_shared<const CollectorCompletedRootInventory>(
				CollectorCompletedRootInventory::ConstructionKey{}, std::move( *evidence)) ;
		}

		// 保存権限は全元履歴・全raw・全名の再照合成功後に限って返します。
		if( verifiedFinish) {
			require( reader.finishBodies.has_value()) ;
			*verifiedFinish = std::move( reader.finishBodies) ;
		}

		// 全元履歴・全raw・全名が一致した場合だけ、固定intentを通常監督へ返します。
		if( verifiedDayRoll) {
			*verifiedDayRoll = reader.dayRollIntent ;
		}

		// 全rawと全名の再照合後だけ、内部完了入口へ操作集合を移します。
		if( verifiedOperations) {
			*verifiedOperations = std::move( allVerified) ;
		}

		history = std::move( result) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( const std::bad_alloc &) {
		return static_cast<DWORD>( E_OUTOFMEMORY) ;
	} catch( const winrt::hresult_error &error) {
		return static_cast<DWORD>( error.code().value) ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::prepareInitialProjected(
	LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
	std::uint64_t steadyMillis, CollectorProjectedResponseBytes &prepared,
	const std::function<std::int32_t( CollectorProjectedHashStage)> &probe)
{
	prepared = {} ;
	CollectorProjectedPreparedUpdate update ;	// 共通親入口だけで応答とCACHEを検査します。
	const auto error = prepareInitialProjectedUpdate( executor, slot, utcMillis, steadyMillis,
													 update, probe) ;	// 第一error。
	// 旧callerへは従来の応答だけを返します。
	if( error == ERROR_SUCCESS) {
		prepared = std::move( update.response) ;
	}

	return error ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::prepareInitialProjectedUpdate(
	LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
	std::uint64_t steadyMillis, CollectorProjectedPreparedUpdate &prepared,
	const std::function<std::int32_t( CollectorProjectedHashStage)> &probe)
{
	return prepareProjectedUpdateForMode( executor, slot, utcMillis, steadyMillis, prepared, probe,
										 false) ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::prepareNextProjectedUpdate(
	LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
	std::uint64_t steadyMillis, CollectorProjectedPreparedUpdate &prepared,
	const std::function<std::int32_t( CollectorProjectedHashStage)> &probe)
{
	return prepareProjectedUpdateForMode( executor, slot, utcMillis, steadyMillis, prepared, probe,
										 true) ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::prepareProjectedUpdateForMode(
	LocalCollectorProjectedExecutor &executor, std::size_t slot, std::uint64_t utcMillis,
	std::uint64_t steadyMillis, CollectorProjectedPreparedUpdate &prepared,
	const std::function<std::int32_t( CollectorProjectedHashStage)> &probe, const bool next)
{
	prepared = {} ;
	// 最初の失敗後はcodecもhashも再試行しません。
	if( state_->error != 0U) {
		executor.failPreparation( state_->error) ;
		return state_->error ;
	}

	try {
		// 初回と次世代の受領を明示入口で分けます。
		require( state_->nextProjected == next, ERROR_NOT_SUPPORTED) ;
		const CollectorPreparedProjectedCampaign *campaign{} ;	// Executorが保持する元入力だけ。
		const CollectorProjectedWorkerResult	 *worker{} ;	// 全join後の元const観測だけ。
		io( executor.takeInitialPreparation( state_->projectedOwner, slot, campaign, worker)) ;
		require( state_->projectedRequested && state_->storageVersion == 3U && state_->store &&
				state_->store->isWritable() && !state_->key.empty() && campaign && worker) ;
		require( utcMillis >= state_->now && utcMillis <= LAST_UTC &&
				steadyMillis >= state_->lastSteady) ;
		state_->now			= utcMillis ;
		state_->lastSteady	= steadyMillis ;
		const auto &binding = worker->binding ;	// 元予約の全field。
		require( campaign->generationKey() == state_->key && binding.generationKey == state_->key &&
				binding.mode == CollectorRecoveryDispatch::Mode::PROJECTED &&
				binding.jobIndex < state_->manifest.jobs.size() &&
				campaign->jobCount() == state_->manifest.jobs.size()) ;
		const auto index = binding.jobIndex ;	// 元入力index。slot番号とは区別します。
		const auto live	 = std::find_if( state_->controlledBindings.begin(),
										state_->controlledBindings.end(), [&]( const auto &entry) {
											return entry && entry->jobIndex == index ;
										}) ; // Process内の予約正本。
		require( live != state_->controlledBindings.end() &&
				sameCollectorRecoveryDispatch( **live, binding)) ;
		const auto liveIndex = static_cast<std::size_t>(
			// 元予約に対応する履歴slot。
			std::distance( state_->controlledBindings.begin(), live)) ;
		const auto *job = campaign->job( index) ;	// 元prepared scopeだけを使います。
		// 元prepared jobの不在を同じ形式拒否へ返し、後続codecへ参照を渡しません。
		if( job == nullptr) {
			throw static_cast<DWORD>( ERROR_INVALID_DATA) ;
		}

		std::shared_ptr<const CollectorRegisteredProjectedHistory> history ;	// 全閉包検査後の値。
		// 次世代は現在の全履歴と予約前の同CACHEhashを再照合します。
		if( next) {
			io( inspectProjectedHistoryCore( *state_->store, job, state_->projectedSources, utcMillis,
										   sha( bytes( state_->root)), history, probe, true)) ;
			const auto &reserved = state_->nextHistories[liveIndex] ;	// 予約前の所有正本。
			require( static_cast<bool>( history) == static_cast<bool>( reserved) &&
					(!history || history->cacheHash() == reserved->cacheHash())) ;
		} else {
			const auto &initial = state_->projectedHistories[liveIndex] ;	// 初回専用の欠損証明。
			require( initial &&
					*initial == state_->inspectInitialProjectedHistory( index, binding.scopeSha256)) ;
		}

		const auto &observed = worker->io ;	// 原時刻と単調経過を別々に照合します。
		require(
			observed.sealed && observed.nativeReleased && observed.finishedUtcMillis &&
			observed.elapsedMillis && observed.deadlineUtcMillis == binding.deadlineUtcMillis &&
			*observed.finishedUtcMillis >= binding.anchorUtcMillis &&
			*observed.finishedUtcMillis <= utcMillis &&
			steadyMillis >= binding.anchorSteadyMillis &&
			*observed.elapsedMillis <= steadyMillis - binding.anchorSteadyMillis &&
			(!observed.headerUtcMillis || *observed.headerUtcMillis >= binding.anchorUtcMillis)) ;
		require( observed.cause != CollectorIoCause::COMPLETE ||
				*observed.elapsedMillis <
					binding.deadlineSteadyMillis - binding.anchorSteadyMillis) ;

		// 保存rootとprocess内正本の両方を使い、自己一貫した差替えも受け入れません。
		require( required( *state_->store, ROOT) == bytes( state_->root) &&
				state_->root.GetNamedValue( L"commit").ValueType() ==
					winrt::Windows::Data::Json::JsonValueType::Null &&
				!state_->pendingRoll && str( state_->root, L"activeGeneration") == state_->key) ;
		const auto inputBytes = bytes( state_->input) ;	// 元登録入力の正確なbyte。
		require( required( *state_->store, path( L"runs/campaign-input-v3-", state_->key)) ==
					inputBytes &&
				campaign->inputSha256() == sha( inputBytes) &&
				required( *state_->store, path( L"runs/campaign-marker-v3-", state_->key)) ==
					state_->projectedMarker( campaign->inputSha256()) &&
				required( *state_->store, state_->statePath()) == bytes( state_->jobs)) ;
		CollectorProjectedCampaignDefinition definition ;	// 任意保存jobから直接権限を作りません。
		CollectorProjectedCampaignIdentity	 identity ;		// 元manifestからscopeを全再構築。
		require( parseCollectorProjectedCampaignIdentity( inputBytes, definition, identity) &&
				identity.generationKey == state_->key &&
				identity.inputSha256 == campaign->inputSha256()) ;
		const auto row = state_->jobs.GetNamedArray( L"jobs").GetObjectAt(
			// 保存中の元一行。
			static_cast<std::uint32_t>( index)) ;
		CollectorRecoveryDispatch stored ;	// Intentからの送信権を持たない比較値。
		require(
			str( row, L"state") == L"RUNNING" &&
			number( row, L"started") == binding.startedUtcMillis &&
			parseCollectorProjectedStart( identity, bytes( row.GetNamedObject( L"intent")), stored) &&
			sameCollectorRecoveryDispatch( stored, binding)) ;

		const auto budget	   = state_->budget() ;	// 同じ保護handleで読む未精算予算。
		const auto reservation = std::find_if(
			budget.reservations.begin(), budget.reservations.end(), [&]( const auto &value) {
				return value.campaign == state_->key && value.job == binding.jobKey ;
			}) ; // 元一予約。
		require( reservation != budget.reservations.end() && reservation->phase == 0U &&
				reservation->group == binding.source.rateLimitGroup &&
				reservation->started * 1000U == binding.startedUtcMillis &&
				reservation->maximum == binding.source.maximumResponseBytes &&
				reservation->charged == reservation->maximum &&
				state_->originalDeadline( index, binding.startedUtcMillis, budget) ==
					binding.deadlineUtcMillis) ;
		const auto controls = state_->controls() ;	// 同じGETの開始intentを検査します。
		const auto request =
			// 永続request待機表。
			controls.controls.find( L"r-" + binding.requestKey) ;
		require(
			request != controls.controls.end() && request->second.request == binding.requestKey &&
			request->second.group == binding.source.rateLimitGroup &&
			request->second.generation == state_->key && request->second.job == binding.jobKey &&
			request->second.started == binding.startedUtcMillis &&
			request->second.observed == binding.anchorUtcMillis) ;
		const auto operationKey = operation( state_->key, binding.jobKey) ;	// 固定保存slot。
		require( !state_->storedResponse( operationKey) &&
				!read( *state_->store, path( L"runs/campaign-response-v4-", operationKey))) ;
		// Codecの元HRESULTとOOMは32bitのまま伝播します。
		const auto codec = []( collector_projected_json::Result result) {
			// 正常以外だけを第一errorへ渡します。
			if( result.status != collector_projected_json::Status::OK) {
				const DWORD code =
					result.error != 0 ? static_cast<DWORD>( result.error)
					: result.status == collector_projected_json::Status::OUT_OF_MEMORY
						? static_cast<DWORD>( E_OUTOFMEMORY)
					: result.status == collector_projected_json::Status::SIZE_LIMIT
						? ERROR_TOO_MANY_NAMES
						: ERROR_INVALID_DATA ;	// 元数値を優先。
				throw code ;
			}
		} ;
		CollectorProjectedHistoryFinalization finalized ;	// 全検査済み成功sliceだけを渡します。
		const auto							  slices =
			   history ? std::span<const CollectorProjectedHistoryEvidence>( history->slices())
					   // 初回／新requestは空。
											   : std::span<const CollectorProjectedHistoryEvidence>{} ;
		codec( finalizeCollectorProjectedHistory( *job, *worker, utcMillis, slices, finalized)) ;
		CollectorProjectedResponseBytes encoded ;	// 元errorを保った有限生成。
		codec( encodeCollectorProjectedResponseWithFallback( job->value(), finalized.response,
														   encoded, probe)
				  .result) ;
		CollectorProjectedResponseBytes readback ;	// 同じbyteを独立CNGで再検査。
		codec( decodeCollectorProjectedResponse( job->value(), encoded.envelope, readback, probe)
				  .result) ;
		require( readback.envelope == encoded.envelope &&
				readback.responseSha256 == encoded.responseSha256 &&
				readback.value.generation == state_->key && readback.value.job == binding.jobKey &&
				readback.value.accepted == utcMillis) ;
		CollectorProjectedCache cache ;	// 同じ元v4からだけ導出し、保存は行いません。
		codec( deriveCollectorProjectedCache( job->value(), readback.envelope,
											history ? &history->cache() : nullptr, cache, probe)) ;
		CollectorProjectedPreparedUpdate update ;	// 全検査後にまとめて出力へ移します。
		codec( encodeCollectorProjectedCache( cache, update.cache)) ;
		update.cacheSha256 = sha( update.cache) ;
		update.response	   = std::move( readback) ;
		prepared		   = std::move( update) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		state_->error = code ;
	} catch( const std::bad_alloc &) {
		state_->error = static_cast<DWORD>( E_OUTOFMEMORY) ;
	} catch( const winrt::hresult_error &error) {
		state_->error = static_cast<DWORD>( error.code().value) ;
	} catch( ...) {
		state_->error = ERROR_INVALID_DATA ;
	}

	// OOM後にも文字列確保をせず、第一errorと停止を必ず伝えます。
	state_->reason.swap( state_->projectedFailureReason) ;
	executor.failPreparation( state_->error) ;
	return state_->error ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::acceptInitialProjected(
	LocalCollectorProjectedExecutor &executor, const std::size_t slot,
	const std::uint64_t utcMillis, const std::uint64_t steadyMillis,
	const std::function<std::int32_t( CollectorProjectedHashStage)> &probe)
{
	return acceptProjectedForMode( executor, slot, utcMillis, steadyMillis, probe, false) ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::acceptNextProjected(
	LocalCollectorProjectedExecutor &executor, const std::size_t slot,
	const std::uint64_t utcMillis, const std::uint64_t steadyMillis,
	const std::function<std::int32_t( CollectorProjectedHashStage)> &probe)
{
	return acceptProjectedForMode( executor, slot, utcMillis, steadyMillis, probe, true) ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::acceptProjectedForMode(
	LocalCollectorProjectedExecutor &executor, const std::size_t slot,
	const std::uint64_t utcMillis, const std::uint64_t steadyMillis,
	const std::function<std::int32_t( CollectorProjectedHashStage)> &probe, const bool next)
{
	CollectorProjectedPreparedUpdate update ;	// 元executorから一回だけ生成する非保存候補。
	const auto						 error =
		prepareProjectedUpdateForMode( executor, slot, utcMillis, steadyMillis, update, probe,
									  next) ;	// 全join・所有予約・原I/Oを共通入口で検査します。
	// 第一準備errorでは保存を一切始めません。
	if( error != 0U) {
		return error ;
	}

	try {
		const auto *worker = executor.result( slot) ;	// 全join後の元所有値だけ。
		// 全join後も結果がないslotは元の形式errorで止めます。
		if( worker == nullptr) {
			throw static_cast<DWORD>( ERROR_INVALID_DATA) ;
		}

		const auto &binding = worker->binding ;	// 同じ予約の全field。
		const auto	live =
			std::find_if( state_->controlledBindings.begin(), state_->controlledBindings.end(),
						 [&]( const auto &entry) {
							 return entry && sameCollectorRecoveryDispatch( *entry, binding) ;
						 }) ; // 未精算の予約正本。
		require( live != state_->controlledBindings.end()) ;
		const auto liveIndex = static_cast<std::size_t>(
			// 根拠と同じ有限slot。
			std::distance( state_->controlledBindings.begin(), live)) ;
		std::optional<std::string> beforeCache ;	// 保存権限ではなく再検証済みのcanonical前像。
		// 次世代は保存直前にも全履歴を検査し同requestの予約前値へ結合します。
		if( next) {
			std::shared_ptr<const CollectorPreparedProjectedCampaign>
				campaign ;	// 保存入力を元sourceへ再結合。
			require( prepareCollectorProjectedCampaign(
				bytes( state_->input), sha( bytes( state_->input)), state_->key,
				state_->definition.artifactSha256, state_->projectedSources, campaign)) ;
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
				history ;	// 同じ所有jobの根拠。
			io( inspectProjectedHistoryCore( *state_->store, campaign->job( binding.jobIndex),
										   state_->projectedSources, utcMillis,
										   sha( bytes( state_->root)), history, probe, true)) ;
			const auto &reserved = state_->nextHistories[liveIndex] ;	// 同じ予約前CACHE。
			require( static_cast<bool>( history) == static_cast<bool>( reserved) &&
					(!history || history->cacheHash() == reserved->cacheHash())) ;
			// 登録された元値だけを更新前像へ符号化します。真の新requestは欠損を維持します。
			if( history) {
				beforeCache.emplace() ;
				projectedCodec( encodeCollectorProjectedCache( history->cache(), *beforeCache)) ;
				require( sha( *beforeCache) == history->cacheHash()) ;
			}
		} else {
			require(
				state_->projectedHistories[liveIndex] &&
				*state_->projectedHistories[liveIndex] ==
					state_->inspectInitialProjectedHistory( binding.jobIndex, binding.scopeSha256)) ;
		}

		const auto object =
			// hash再符号化なし。
			Object::Parse( winrt::to_hstring( update.response.response)) ;
		(void)state_->derive( binding.jobIndex, object,
							 {required( *state_->store, CONTROL),
							  required( *state_->store, state_->statePath()),
							  required( *state_->store, BUDGET)},
							 &update.response) ;	// 全共有更新を保存前に導出。
		require( state_->initialResponseCache( binding.jobIndex, object, &update.response,
											 beforeCache) == update.cache &&
				sha( update.cache) == update.cacheSha256) ;
		const auto completed =
			state_->completedSteady.try_emplace( binding.source.rateLimitGroup, 0U)
				.first ;	// 保存後のmap確保を避けます。
		const auto	name = path( L"runs/campaign-response-v4-",
								// callerのpathを受けません。
								operation( state_->key, binding.jobKey)) ;
		std::string prior ;		// immutable原envelopeの先行存在を拒否します。
		bool		found{} ;	// 欠損だけに初回作成を許します。
		io( state_->store->read( name, prior, found)) ;
		require( !found) ;
		// 専用codecの元byteを保存します。
		io( state_->store->write( name, update.response.envelope)) ;
		const auto saved = state_->decodeSavedProjected( binding.jobIndex,
														update.response.response) ;	// 原byte読戻し。
		require( saved.envelope == update.response.envelope &&
				saved.responseSha256 == update.response.responseSha256) ;
		state_->checkpoint( CollectorRecoveryCheckpoint::RESPONSE) ;
		// 四role・登録・回復と同じ導出。
		state_->commitResponse( binding.jobIndex, object, &saved, beforeCache) ;
		completed->second = steadyMillis ;
		// rootの完了後だけ予約と初回根拠を解放します。
		live->reset() ;
		state_->projectedHistories[liveIndex].reset() ;
		state_->nextHistories[liveIndex].reset() ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		state_->error = code ;
	} catch( const std::bad_alloc &) {
		state_->error = static_cast<DWORD>( E_OUTOFMEMORY) ;
	} catch( const winrt::hresult_error &nativeFailure) {
		state_->error = static_cast<DWORD>( nativeFailure.code().value) ;
	} catch( ...) {
		state_->error = ERROR_INVALID_DATA ;
	}

	// OOM後に追加確保しません。
	state_->reason.swap( state_->projectedFailureReason) ;
	executor.failPreparation( state_->error) ;
	return state_->error ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::finishInitialProjected( const std::uint64_t utcMillis,
													 const std::uint64_t steadyMillis)
{
	// 最初の保存失敗後は次の書込みを行いません。
	if( state_->error != 0U) {
		return state_->error ;
	}

	try {
		require( state_->store && state_->projectedRequested && state_->storageVersion == 3U &&
					!state_->key.empty(),
				ERROR_INVALID_PARAMETER) ;
		// 末尾完了は履歴受領と四role更新の接続後だけ扱い、初回完了へ流用しない。
		require( !state_->nextProjected, ERROR_NOT_SUPPORTED) ;
		require( utcMillis >= state_->now && utcMillis <= LAST_UTC &&
				steadyMillis >= state_->lastSteady &&
				required( *state_->store, ROOT) == bytes( state_->root)) ;
		// 未終端は保存や回復をせず、通常の継続待ちとして返します。
		if( terminalJobs() != state_->manifest.jobs.size()) {
			state_->reason = L"GENERATION_NOT_TERMINAL" ;
			return ERROR_RETRY ;
		}

		state_->now		   = utcMillis ;
		state_->lastSteady = steadyMillis ;
		// 全完了は同じ有限coreで再検査し、元完了時刻の再保存はしません。
		if( !state_->inventory( state_->definition.sources)) {
			state_->finishGeneration() ;
		}

		state_->reason = L"GENERATION_COMPLETE" ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		state_->error = code ;
	} catch( const std::bad_alloc &) {
		state_->error = static_cast<DWORD>( E_OUTOFMEMORY) ;
	} catch( const winrt::hresult_error &error) {
		state_->error = static_cast<DWORD>( error.code().value) ;
	} catch( ...) {
		state_->error = ERROR_INVALID_DATA ;
	}

	// 失敗後に理由文字列を追加確保せず、元数値を保持します。
	state_->reason.swap( state_->projectedFailureReason) ;
	return state_->error ;
}

/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::finishNextProjected( const std::uint64_t utcMillis,
												  const std::uint64_t steadyMillis)
{
	// 最初の失敗後に不足像を自作して保存しません。
	if( state_->error != 0U) {
		return state_->error ;
	}

	try {
		require( state_->store && state_->projectedRequested && state_->storageVersion == 3U &&
					state_->root.GetNamedArray( L"generations").Size() > 1U,
				ERROR_NOT_SUPPORTED) ;
		require( utcMillis >= state_->now && utcMillis <= LAST_UTC &&
				steadyMillis >= state_->lastSteady &&
				required( *state_->store, ROOT) == bytes( state_->root)) ;
		// 未終端では全保存像を変更せず次の通常収集へ戻します。
		if( terminalJobs() != state_->manifest.jobs.size()) {
			state_->reason = L"GENERATION_NOT_TERMINAL" ;
			return ERROR_RETRY ;
		}

		state_->now		   = utcMillis ;
		state_->lastSteady = steadyMillis ;
		std::shared_ptr<const CollectorRegisteredProjectedHistory>
							   unused ;		// 完了入口はcontextを発行しません。
		std::set<std::wstring> operations ;	// 全閉包再導出済みの元操作だけ。
		io( inspectProjectedHistoryCore( *state_->store, nullptr, state_->projectedSources, utcMillis,
									   sha( bytes( state_->root)), unused, {}, true, &operations)) ;
		const auto registrations = state_->root.GetNamedArray( L"generations") ;	// 元の登録順。
		const auto tail = registrations.GetObjectAt( registrations.Size() - 1U) ;	// 最後だけを完了。
		// 既完了は元時刻と全fileを保持し、再保存せず成功を返します。
		if( !str( tail, L"summaryHash").empty()) {
			state_->reason = L"GENERATION_COMPLETE" ;
			return ERROR_SUCCESS ;
		}

		require( state_->nextProjected && str( tail, L"generation") == state_->key &&
				str( state_->root, L"activeGeneration") == state_->key) ;
		const auto bodies =
			// 元応答による集計。
			state_->completionBodies( utcMillis, &operations, true) ;
		state_->saveNextCompletion( bodies) ;
		state_->reason = L"GENERATION_COMPLETE" ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		state_->error = code ;
	} catch( const std::bad_alloc &) {
		state_->error = static_cast<DWORD>( E_OUTOFMEMORY) ;
	} catch( const winrt::hresult_error &error) {
		state_->error = static_cast<DWORD>( error.code().value) ;
	} catch( ...) {
		state_->error = ERROR_INVALID_DATA ;
	}

	state_->reason.swap( state_->projectedFailureReason) ;
	return state_->error ;
}

/** @see local_collector_recovery.h */
std::size_t LocalCollectorRecovery::terminalJobs() const noexcept
{
	// 初期化失敗から空参照をdereferenceしない。
	if( !state_->jobs) {
		return 0U ;
	}

	try {
		std::size_t result{} ;	// 製品成功数ではなく非再送job数。
		// 固定job順で非再送状態だけを数える。
		for( const auto &entry : state_->jobs.GetNamedArray( L"jobs")) {
			const auto state = str( entry.GetObject(), L"state") ; /* 有限enum。 */
			// 未予約と実行中はterminal件数に含めない。
			if( state != L"PENDING" && state != L"RUNNING") {
				++result ;
			}
		}

		return result ;
	} catch( ...) {
		return 0U ;
	}
}

/** @see local_collector_recovery.h */
const std::wstring &LocalCollectorRecovery::generationKey() const noexcept
{
	return state_->key ;
}
/** @see local_collector_recovery.h */
DWORD LocalCollectorRecovery::lastError() const noexcept
{
	return state_->error ;
}
/** @see local_collector_recovery.h */
const std::wstring &LocalCollectorRecovery::reason() const noexcept
{
	return state_->reason ;
}
} // namespace drivercrate
