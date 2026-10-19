//------------------------------------------------------------------------------
/**
 * @file local_collector_campaign.cpp
 * @brief 有限manifestと保護台帳で共有収集jobの予約・回収を実装します。
 * @version 01.04.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  共有job・予算予約・中断回収を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  監督所有storeの単一借用入口を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/27  共通予算の非変更読込みと精算準備を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/27  復旧監督用の共通controlと固定精算を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  共有job keyの再照合入口を追加。
 * Ver.01.04.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 単一監督threadから使用します。通信・取得grant・導入を実行しません。
 * @see docs/adr/0214-multi-source-collector-campaign.md
 */
//------------------------------------------------------------------------------

#include "platform/local_collector_campaign.h"
#include "platform/local_collector_state_store.h"
#include "platform/official_file_verifier.h"

#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>

namespace drivercrate {
namespace {

/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using JsonObject = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON配列をWinRT参照で保持する。要素数と各要素のschema検証は利用側で行う。
 */
using JsonArray = winrt::Windows::Data::Json::JsonArray ;
/**
 * @brief JSON値をWinRT参照で保持する。所有byteの検証と型判定はreader側で行う。
 */
using JsonValue = winrt::Windows::Data::Json::JsonValue ;
/**
 * @brief JSON値の実種別を表し、schemaで要求する型との一致を検査する。
 */
using JsonValueType = winrt::Windows::Data::Json::JsonValueType ;

// 保護storeの2 MiB envelope内に収める本文上限。
constexpr std::size_t	MAXIMUM_BODY = 768U * 1024U ;
// 共有rootに許可する日次の実要求数。
constexpr std::uint64_t DAILY_REQUESTS = 1200U ;
// 日次の応答予約と実受信byteの共通上限。
constexpr std::uint64_t DAILY_BYTES = 1024U * 1024U * 1024U ;
// 初回予約からの有限wall時間を秒で指定する。
constexpr std::uint64_t DAILY_SECONDS = 14400U ;
// 一応答に許可する通常metadata上限。
constexpr std::uint64_t RESPONSE_BYTES = 8U * 1024U * 1024U ;

/**
 * @brief 小文字SHA-256文字列だけを識別子として受理します。
 * @param[in] value 検査する有限文字列。
 * @return 64桁の小文字16進hashならtrue。
 */
[[nodiscard]] bool		isHash( const std::wstring_view value)
{
	return value.size() == 64U && std::all_of( value.begin(), value.end(), []( const wchar_t ch) {
			   return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ;
		   }) ;
}

/**
 * @brief 有限ASCII tokenだけをsourceや公開識別子へ使います。
 * @param[in] value 検査する公開識別子。
 * @return 96文字以内の許可tokenならtrue。
 */
[[nodiscard]] bool isToken( const std::wstring_view value)
{
	return !value.empty() && value.size() <= 96U &&
		   std::all_of( value.begin(), value.end(), []( const wchar_t ch) {
			   return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'z') ||
					  (ch >= L'A' && ch <= L'Z') || ch == L'-' || ch == L'_' || ch == L'.' ;
		   }) ;
}

/**
 * @brief NFCと空白が確定した公開labelから端末IDとURLを拒否します。
 * @param[in] value 検査する公開表示名。
 * @return 公開labelの文字・正規化条件に一致する場合true。
 */
[[nodiscard]] bool isPublicLabel( const std::wstring_view value)
{
	// 制御文字と非公開の識別形式を正規化前に除く。
	if( value.empty() || value.size() > 256U || value.front() == L' ' || value.back() == L' ' ||
	   value.find( L"  ") != value.npos || value.find( L"://") != value.npos ||
	   value.find( L'\\') != value.npos ||
	   !std::all_of( value.begin(), value.end(),
					[]( const wchar_t ch) { return ch >= 32 && ch != 127 ; })) {
		return false ;
	}

	// Windows NFCへの変換を比較する有限buffer。
	wchar_t	  normalized[512]{} ;
	// 元のUTF-16列を正規化した長さ。
	const int length = NormalizeString( NormalizationC, value.data(), static_cast<int>( value.size()),
									   normalized, 512) ;
	// 変換失敗やNFC不一致を暗黙補正しない。
	if( length <= 0 || std::wstring_view( normalized, static_cast<std::size_t>( length)) != value) {
		return false ;
	}

	// 生PnP IDのprefixを大文字比較する公開列の複製。
	std::wstring upper( value) ;
	std::transform( upper.begin(), upper.end(), upper.begin(), []( const wchar_t ch) {
		return ch >= L'a' && ch <= L'z' ? static_cast<wchar_t>( ch - L'a' + L'A') : ch ;
	}) ;
	// 端末固有の識別形式を検索語と保存labelへ入れない。
	for( const std::wstring_view prefix : {L"VEN_", L"DEV_", L"VID_", L"PID_", L"PCI#", L"USB#"}) {
		// 公開の製品type codeとは区別し、生IDだけを拒否する。
		if( upper.find( prefix) != upper.npos) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief 有効UTC秒に対するJST日付を一意に返します。
 * @param[in] utc 1970年起点のUTC秒。
 * @return 有効時はYYYYMMDD、不正時は空。
 */
[[nodiscard]] std::wstring dayFor( const std::uint64_t utc)
{
	// 1970より前や2100以降はJSON精度と時計契約の外として拒否する。
	if( utc == 0U || utc > 4102444799ULL) {
		return {} ;
	}

	// JSTはDSTを持たず、UTCから九時間進めた暦日である。
	const auto date = std::chrono::year_month_day( std::chrono::floor<std::chrono::days>(
		std::chrono::sys_seconds( std::chrono::seconds( utc)) + std::chrono::hours( 9))) ;
	// 月日を固定二桁へ整える。
	const auto month = static_cast<unsigned>( date.month()) ;
	// 固定二桁の日。
	const auto day = static_cast<unsigned>( date.day()) ;
	return std::to_wstring( static_cast<int>( date.year())) + (month < 10U ? L"0" : L"") +
		   std::to_wstring( month) + (day < 10U ? L"0" : L"") + std::to_wstring( day) ;
}

/**
 * @brief WinRTが黙って上書きする重複JSON keyをlexical走査で拒否します。
 * @param[in] bytes 文法検証済みの有限UTF-8 JSON。
 * @return 復号したkeyの重複と深さ超過がない場合true。
 */
[[nodiscard]] bool uniqueKeys( const std::string_view bytes)
{
	// Object／arrayの有限深さを保持し、objectの復号済みkeyを比較する。
	std::vector<std::set<std::wstring>> scopes ;
	// JSON全体を一回だけ走査するbyte位置。
	for( std::size_t offset = 0U; offset < bytes.size(); ++offset) {
		// Objectとarrayの境界はstring外でだけ処理する。
		if( bytes[offset] == '{' || bytes[offset] == '[') {
			scopes.emplace_back() ;
			// 入力の深い再帰をmetadata契約へ持ち込まない。
			if( scopes.size() > 16U) {
				return false ;
			}

			continue ;
		}

		// 閉じたscopeを解除して親objectのkey集合へ戻る。
		if( bytes[offset] == '}' || bytes[offset] == ']') {
			// 不均衡な構文を受理しない。
			if( scopes.empty()) {
				return false ;
			}

			scopes.pop_back() ;
			continue ;
		}

		// String内の括弧やcolonを構文の境界として扱わない。
		if( bytes[offset] == '"') {
			// Escapeを含むstring tokenの開始位置。
			const auto begin = offset++ ;
			// Escapeの次のbyteは終端引用符として扱わない。
			while( offset < bytes.size() && bytes[offset] != '"') {
				// JSON stringのescapeを一組として飛ばす。
				if( bytes[offset] == '\\') {
					++offset ;
				}

				++offset ;
			}

			// 終端を欠くstringは拒否する。
			if( offset >= bytes.size()) {
				return false ;
			}

			// Keyを示すcolonまでの空白だけを飛ばす。
			auto after = offset + 1U ;
			// 文法の空白を有限入力の終端まで調べる。
			while( after < bytes.size() && (bytes[after] == ' ' || bytes[after] == '\r' ||
										   bytes[after] == '\n' || bytes[after] == '\t')) {
				++after ;
			}

			// Colonが続くtokenだけをobjectのkeyとして復号する。
			if( after < bytes.size() && bytes[after] == ':') {
				// 一つの復号済みJSON key。
				const auto key =
					JsonValue::Parse( winrt::to_hstring( bytes.substr( begin, offset - begin + 1U)))
						.GetString() ;
				// Escaped表記の重複も同じkeyとして拒否する。
				if( scopes.empty() || !scopes.back().insert( std::wstring( key)).second) {
					return false ;
				}
			}
		}
	}

	return scopes.empty() ;
}

/**
 * @brief 有限JSON objectを型と重複key検査で読みます。
 * @param[in] bytes 最大768 KiBのUTF-8本文。
 * @return 形式を検証したJSON object。不正入力は例外。
 */
[[nodiscard]] JsonObject objectFrom( const std::string_view bytes)
{
	// NUL、BOM、過大入力をparserへ渡さない。
	if( bytes.empty() || bytes.size() > MAXIMUM_BODY || bytes.find( '\0') != bytes.npos ||
	   bytes.starts_with( "\xef\xbb\xbf")) {
		throw std::invalid_argument( "campaign JSON") ;
	}

	// WinRTで文法を先に検証し、重複を追加で確認する。
	const auto object = JsonObject::Parse( winrt::to_hstring( bytes)) ;
	// 同名fieldの上書きを受理しない。
	if( !uniqueKeys( bytes)) {
		throw std::invalid_argument( "duplicate JSON key") ;
	}

	return object ;
}

/**
 * @brief Objectの許可fieldと件数を完全一致で確認します。
 * @param[in] object 検査するJSON object。
 * @param[in] names 必須かつ許可するfield名。
 */
void fields( const JsonObject &object, const std::initializer_list<std::wstring_view> names)
{
	// 未知fieldや欠損fieldを同じ境界で拒否する。
	if( object.Size() != names.size() ||
	   !std::all_of( names.begin(), names.end(),
					[&]( const auto name) { return object.HasKey( winrt::hstring( name)) ; })) {
		throw std::invalid_argument( "campaign fields") ;
	}
}

/**
 * @brief String fieldを有限UTF-16列として取り出します。
 * @param[in] object 入力JSON object。
 * @param[in] name 必須field名。
 * @return 256文字以内のstring。欠損・型不正は例外。
 */
[[nodiscard]] std::wstring textField( const JsonObject &object, const wchar_t *name)
{
	// String以外はSDKの型検査により拒否する。
	const std::wstring text( object.GetNamedString( name)) ;
	// 保存labelとhashの最大長を越える値を拒否する。
	if( text.size() > 256U) {
		throw std::invalid_argument( "campaign text") ;
	}

	return text ;
}

/**
 * @brief JSON numberの非負整数だけを精度内で返します。
 * @param[in] object 入力JSON object。
 * @param[in] name 必須field名。
 * @return 精度内の非負整数。不正値は例外。
 */
[[nodiscard]] std::uint64_t numberField( const JsonObject &object, const wchar_t *name)
{
	// WinRTが検査したnumberを整数精度で再検査する。
	const double value = object.GetNamedNumber( name) ;
	// 不正な浮動小数や精度喪失を保存数値へ変換しない。
	if( !std::isfinite( value) || value < 0.0 || value > 9007199254740991.0 ||
	   std::floor( value) != value) {
		throw std::invalid_argument( "campaign number") ;
	}

	return static_cast<std::uint64_t>( value) ;
}

/**
 * @brief 公開stringだけをcanonical JSON fieldへ追加します。
 * @param[in,out] object 書込み先JSON object。
 * @param[in] name 固定field名。
 * @param[in] text 保存許可された有限string。
 */
void putText( JsonObject &object, const wchar_t *name, const std::wstring_view text)
{
	object.Insert( name, JsonValue::CreateStringValue( winrt::hstring( text))) ;
}

/**
 * @brief 上限が検査済みの整数をJSONへ追加します。
 * @param[in,out] object 書込み先JSON object。
 * @param[in] name 固定field名。
 * @param[in] value JSON精度内の検証済み整数。
 */
void putNumber( JsonObject &object, const wchar_t *name, const std::uint64_t value)
{
	object.Insert( name, JsonValue::CreateNumberValue( static_cast<double>( value))) ;
}

/**
 * @brief 検証済みbyte列を小文字SHA-256へ変換します。
 * @param[in] bytes 有限のhash計算対象。
 * @return 小文字SHA-256。計算失敗は例外。
 */
[[nodiscard]] std::wstring hashOf( const std::string_view bytes)
{
	// APIが返す計算hash。
	std::wstring hash ;
	// Hash API失敗を空identityとして扱わない。
	if( computeBytesSha256( bytes, hash) != 0) {
		throw std::runtime_error( "campaign hash") ;
	}

	std::transform( hash.begin(), hash.end(), hash.begin(), []( const wchar_t ch) {
		return ch >= L'A' && ch <= L'F' ? static_cast<wchar_t>( ch - L'A' + L'a') : ch ;
	}) ;
	return hash ;
}

/**
 * @brief 共有jobのcanonical identityを製品参照と分離して符号化します。
 * @param[in] job 検証済み公開requestと組み込み契約。
 * @return 共有判定に使う有限UTF-8 JSON。
 */
[[nodiscard]] std::string jobIdentity( const CollectorCampaignJob &job)
{
	// 組み込み契約と公開requestだけを結合する。
	JsonObject object ;
	putText( object, L"source", job.source.sourceId) ;
	putText( object, L"resource", job.source.resourceId) ;
	putText( object, L"group", job.source.rateLimitGroup) ;
	putText( object, L"parser", job.source.parserRevision) ;
	putNumber( object, L"maximumBytes", job.source.maximumResponseBytes) ;
	putText( object, L"locator", job.publicLocator) ;
	putText( object, L"locale", job.locale) ;
	putNumber( object, L"page", job.page) ;
	putText( object, L"os", L"WINDOWS_11_X64") ;
	return winrt::to_string( object.Stringify()) ;
}

/**
 * @brief 保存対象のjob状態を有限の整数へ制限します。
 * @param[in] state Narrowing前のJSON整数。
 * @return 定義済み状態の範囲内ならtrue。
 */
[[nodiscard]] bool validState( const std::uint64_t state)
{
	return state <= static_cast<std::uint64_t>( CollectorCampaignJobState::INTERRUPTED) ;
}

/**
 * @brief 製品の依存job状態から再開可能な集約結果を導きます。
 * @param[in] manifest 固定製品と共有job。
 * @param[in] observations Manifest jobと同順の観測集合。
 * @param[in] target 範囲確認済みの製品index。
 * @return 当該製品の現在集約状態。
 */
[[nodiscard]] CollectorCampaignTargetState targetState(
	const CollectorCampaignManifest					&manifest,
	const std::vector<CollectorCampaignObservation> &observations, const std::size_t target)
{
	// 依存の有無と未完了／失敗／保留を独立して集計する。
	bool referenced{} ;
	// 未完了の依存が一つでもあればterminalへ反映しない。
	bool pending{} ;
	// 失敗を他jobの成功で隠さない。
	bool failed{} ;
	// 要確認を成功へ変換しない。
	bool held{} ;
	// 有限job集合で当該targetの依存だけを調べる。
	for( std::size_t index = 0U; index < manifest.jobs.size(); ++index) {
		// 当該公開製品へ対応するrequest参照だけを集約する。
		if( std::find( manifest.jobs[index].targetIndices.begin(),
					 manifest.jobs[index].targetIndices.end(),
					 target) != manifest.jobs[index].targetIndices.end()) {
			referenced = true ;
			pending = pending || observations[index].state == CollectorCampaignJobState::PENDING ||
					  observations[index].state == CollectorCampaignJobState::RUNNING ;
			failed = failed || observations[index].state == CollectorCampaignJobState::FAILED ||
					 observations[index].state == CollectorCampaignJobState::INTERRUPTED ;
			held = held || observations[index].state == CollectorCampaignJobState::HELD ;
		}
	}

	return !referenced ? CollectorCampaignTargetState::UNSUPPORTED
		   : pending   ? CollectorCampaignTargetState::PENDING
		   : failed	   ? CollectorCampaignTargetState::FAILED
		   : held	   ? CollectorCampaignTargetState::HELD
					   : CollectorCampaignTargetState::OBSERVED ;
}

/** @brief v1の内部予約名を共通typed予約へ対応させます。 */
using Reservation = CollectorBudgetReservation ;

/** @brief v1と非変更読込みで同じcodec・数値検査を使用します。 */
using Budget = CollectorBudgetSnapshot ;

/**
 * @brief 日次台帳をcanonical fieldだけで保存します。
 * @param[in] budget 有限日次予約台帳。
 * @return 許可fieldだけを持つUTF-8本文。
 */
[[nodiscard]] std::string encodeBudget( const Budget &budget)
{
	// 保存する予算の有限object。
	JsonObject object ;
	putText( object, L"schema", L"collector-campaign-budget-v1") ;
	putText( object, L"day", budget.day) ;
	putNumber( object, L"lastUtc", budget.lastUtc) ;
	// 日次に最大1200の予約だけを保持する。
	JsonArray rows ;
	// 予約を固定順序のまま符号化する。
	for( const auto &reservation : budget.reservations) {
		// 一つの先払い予約。
		JsonObject row ;
		putText( row, L"campaign", reservation.campaign) ;
		putText( row, L"job", reservation.job) ;
		putText( row, L"group", reservation.group) ;
		putNumber( row, L"started", reservation.started) ;
		putNumber( row, L"maximum", reservation.maximum) ;
		putNumber( row, L"charged", reservation.charged) ;
		putNumber( row, L"phase", reservation.phase) ;
		rows.Append( row) ;
	}

	object.Insert( L"reservations", rows) ;
	return winrt::to_string( object.Stringify()) ;
}

/**
 * @brief Budgetの合計・重複・時計・予約状態を復号時に検査します。
 * @param[in] bytes Hash確認済みの有限保存本文。
 * @return 検査済みtyped budget。不整合は例外。
 */
[[nodiscard]] Budget decodeBudget( const std::string_view bytes)
{
	// Hash検査後の有限object。
	const auto object = objectFrom( bytes) ;
	fields( object, {L"schema", L"day", L"lastUtc", L"reservations"}) ;
	// 復号するtyped budget。
	Budget budget ;
	budget.day	   = textField( object, L"day") ;
	budget.lastUtc = numberField( object, L"lastUtc") ;
	// 未知schemaと時計矛盾を拒否する。
	if( textField( object, L"schema") != L"collector-campaign-budget-v1" || budget.day.size() != 8U ||
	   !std::all_of( budget.day.begin(), budget.day.end(),
					[]( const wchar_t ch) { return ch >= L'0' && ch <= L'9' ; }) ||
	   dayFor( budget.lastUtc).empty() || dayFor( budget.lastUtc) < budget.day) {
		throw std::invalid_argument( "budget header") ;
	}

	// 日次の有限予約配列。
	const auto rows = object.GetNamedArray( L"reservations") ;
	// 一日のrequest上限を超える保存状態を拒否する。
	if( rows.Size() > DAILY_REQUESTS) {
		throw std::invalid_argument( "budget count") ;
	}

	// Reservation identityの二重計上検出。
	std::set<std::pair<std::wstring, std::wstring>> identities ;
	// Byte合計を上限内で検証する。
	std::uint64_t									bytesTotal{} ;
	// 保存順序と時刻の単調性を検証する。
	std::uint64_t									previousUtc{} ;
	// 全予約を同じtyped規則で読み取る。
	for( const auto &value : rows) {
		// 一予約のfieldを追加fieldなしで読む。
		const auto row = value.GetObject() ;
		fields( row, {L"campaign", L"job", L"group", L"started", L"maximum", L"charged", L"phase"}) ;
		// 数値のnarrowing前に状態を検査する。
		const auto	phase = numberField( row, L"phase") ;
		// 同じpublic identityと数値を復号する。
		Reservation reservation{textField( row, L"campaign"),	  textField( row, L"job"),
								textField( row, L"group"),		  numberField( row, L"started"),
								numberField( row, L"maximum"),	  numberField( row, L"charged"),
								static_cast<std::uint32_t>( phase)} ;
		// 不正状態・日時・重複・byte overflowを保存台帳から除く。
		if( phase > 2U || !isHash( reservation.campaign) || !isHash( reservation.job) ||
		   !isToken( reservation.group) || reservation.maximum == 0U ||
		   reservation.maximum > RESPONSE_BYTES || reservation.charged > reservation.maximum ||
		   (phase != 1U && reservation.charged != reservation.maximum) ||
		   dayFor( reservation.started) != budget.day || reservation.started < previousUtc ||
		   reservation.started > budget.lastUtc || reservation.charged > DAILY_BYTES - bytesTotal ||
		   !identities.insert( {reservation.campaign, reservation.job}).second) {
			throw std::invalid_argument( "budget reservation") ;
		}

		previousUtc = reservation.started ;
		bytesTotal += reservation.charged ;
		budget.reservations.push_back( std::move( reservation)) ;
	}

	// 正規encodeとの一致で不明な保存表現を拒否する。
	if( encodeBudget( budget) != bytes) {
		throw std::invalid_argument( "budget canonical") ;
	}

	return budget ;
}

/**
 * @brief Hash envelopeから有限本文を読み取ります。
 * @param[in,out] store Writerが保持するACL検証済みstore。
 * @param[in] path 固定二階層内の相対JSON名。
 * @param[out] body 成功時だけ本文。失敗時は空。
 * @param[out] found 読み取ったfileが存在する場合true。
 * @return 欠損または成功0、拒否・I/O失敗はWin32 code。
 */
[[nodiscard]] DWORD readEnvelope( LocalCollectorStateStore &store, const std::filesystem::path &path,
								 std::string &body, bool &found)
{
	// 保護handleから読む元envelope。
	std::string bytes ;
	// 欠損と拒否を区別する元I/O code。
	const DWORD error = store.read( path, bytes, found) ;
	body.clear() ;
	// 欠損時には本文を合成しない。
	if( error != 0U || !found) {
		return error ;
	}

	try {
		// 外側の許可fieldだけを取り出す。
		const auto envelope = objectFrom( bytes) ;
		fields( envelope, {L"schema", L"sha256", L"body"}) ;
		// 内側のUTF-8本文はStringとして取り出す。
		body = winrt::to_string( envelope.GetNamedString( L"body")) ;
		// Unknown schema、過大本文、hash不一致は通信前拒否。
		if( textField( envelope, L"schema") != L"collector-campaign-envelope-v1" ||
		   body.size() > MAXIMUM_BODY || hashOf( body) != textField( envelope, L"sha256")) {
			body.clear() ;
			return ERROR_INVALID_DATA ;
		}

		return ERROR_SUCCESS ;
	} catch( ...) {
		body.clear() ;
		return ERROR_INVALID_DATA ;
	}
}

/**
 * @brief Canonical本文をhash envelopeと共に保護storeへ保存します。
 * @param[in,out] store ACL検証済みstore。
 * @param[in] path 固定二階層内の相対JSON名。
 * @param[in] body 最大768 KiBの許可field本文。
 * @return 保存成功0、過大13または元Win32 code。
 */
[[nodiscard]] DWORD writeEnvelope( LocalCollectorStateStore	  &store,
								  const std::filesystem::path &path, const std::string_view body)
{
	// Bodyとescape後のenvelopeを両方有限にする。
	if( body.size() > MAXIMUM_BODY) {
		return ERROR_INVALID_DATA ;
	}

	// 外側のhashとschemaだけを追加する。
	JsonObject envelope ;
	putText( envelope, L"schema", L"collector-campaign-envelope-v1") ;
	putText( envelope, L"sha256", hashOf( body)) ;
	envelope.Insert( L"body", JsonValue::CreateStringValue( winrt::to_hstring( body))) ;
	return store.write( path, winrt::to_string( envelope.Stringify())) ;
}

} // namespace

/** @see local_collector_campaign.h */
bool parseCollectorBudgetSnapshot( const std::string_view bytes, CollectorBudgetSnapshot &snapshot)
{
	snapshot = {} ;
	try {
		snapshot = decodeBudget( bytes) ;
		return true ;
	} catch( ...) {
		snapshot = {} ;
		return false ;
	}
}

/** @see local_collector_campaign.h */
bool encodeCollectorBudgetSnapshot( const CollectorBudgetSnapshot &snapshot, std::string &bytes)
{
	bytes.clear() ;
	try {
		// JSONを作る前に、typed callerの過大配列・長大文字列を拒否する。
		if( snapshot.reservations.size() > DAILY_REQUESTS || snapshot.day.size() != 8U ||
		   dayFor( snapshot.lastUtc).empty()) {
			return false ;
		}

		// 最大1200予約の文字fieldを有限にしてから共通decoderへ渡す。
		for( const auto &reservation : snapshot.reservations) {
			// 保存形式で許可しないidentityやgroupをJSON化しない。
			if( !isHash( reservation.campaign) || !isHash( reservation.job) ||
			   !isToken( reservation.group)) {
				return false ;
			}
		}

		// 同じcanonical decoderで、callerが作ったtyped値も保存前に検査する。
		const auto encoded = encodeBudget( snapshot) ;
		// 復号検査を通した同じ保存形式だけを出力へ返す。
		const auto checked = decodeBudget( encoded) ;
		bytes			   = encodeBudget( checked) ;
		return true ;
	} catch( ...) {
		return false ;
	}
}

/** @brief writer借用と読込み時の時計を非変更snapshotに保持します。 */
struct LocalCollectorBudgetLedger::State {
	/// 外部監督が所有し、本stateより長く存続するstore。
	LocalCollectorStateStore *store{} ;
	/// 共通codecで確認した読込み時点の予算。
	CollectorBudgetSnapshot	  budget ;
	/// read時の検査時計。更新後本文にはそのまま使いません。
	std::uint64_t			  readUtc{} ;
	/// 予算本文とmarkerが存在した場合true。
	bool					  found{} ;
	/// 非変更読込みが最後まで成立した場合true。
	bool					  initialized{} ;
	/// 初回の失敗code。後続操作で上書きしません。
	DWORD					  error{} ;

	/** @brief 本stateが取得した借用だけを解放します。 */
	~State()
	{
		// 別coreが使用中のstoreへ本stateの解放を作用させない。
		if( store != nullptr) {
			store->releaseCampaign( this) ;
		}
	}
} ;

/** @see local_collector_campaign.h */
LocalCollectorBudgetLedger::LocalCollectorBudgetLedger() : state_( std::make_unique<State>())
{
}

/** @see local_collector_campaign.h */
LocalCollectorBudgetLedger::~LocalCollectorBudgetLedger() = default ;

/** @see local_collector_campaign.h */
DWORD LocalCollectorBudgetLedger::initializeBorrowed( LocalCollectorStateStore &store,
													 const std::uint64_t	   utcSeconds)
{
	// 最初の拒否を後続の再初期化で解除しない。
	if( state_->error != 0U) {
		return state_->error ;
	}

	// 未初期化・二重初期化・不正時計を読込み前に拒否する。
	if( !store.isWritable() || state_->store != nullptr || state_->initialized ||
	   dayFor( utcSeconds).empty()) {
		return state_->error = ERROR_INVALID_PARAMETER ;
	}

	try {
		// 同じworkspaceの専用rootだけを監督の借用対象にする。
		const auto parent	= (std::filesystem::current_path() / L"work/state").lexically_normal() ;
		const auto relative = store.root().lexically_relative( parent) ;	// 親への脱出を検査する。
		// workspace外・親自身へ操作を拡張しない。
		if( relative.empty() || relative == L"." ||
		   std::any_of( relative.begin(), relative.end(),
					   []( const auto &part) { return part == L".." ; })) {
			return state_->error = ERROR_INVALID_NAME ;
		}

		// v1 coreと同じ借用枠を保持し、暗黙の中断処理と共存させない。
		if( (state_->error = store.borrowCampaign( state_.get())) != 0U) {
			return state_->error ;
		}

		state_->store = &store ;
		std::string marker ;		// 予算を作成済みか確認する固定本文。
		std::string body ;			// 元のcanonical budget本文。
		bool		hasMarker{} ;	// 初回欠損と片側欠損を区別する。
		bool		found{} ;		// 予算本文の存在。
		// Markerと本文はhash・owner・ACLの同じ境界で読む。
		if( (state_->error = readEnvelope( store, L"current/campaign-budget-marker-v1.json", marker,
										 hasMarker)) != 0U ||
		   (state_->error = readEnvelope( store, L"current/campaign-budget-v1.json", body, found)) !=
			   0U) {
			return state_->error ;
		}

		// 台帳の片側欠損や未知markerを新予算へ置き換えない。
		if( found != hasMarker || (hasMarker && marker != "collector-campaign-budget-root-v1")) {
			return state_->error = ERROR_INVALID_DATA ;
		}

		// 既存予約とclockを読むだけでphaseやlastUtcを変えない。
		if( found) {
			state_->budget = decodeBudget( body) ;
			// 過去へ戻した監督時計は受け入れない。
			if( utcSeconds < state_->budget.lastUtc) {
				return state_->error = ERROR_INVALID_DATA ;
			}
		} else {
			std::vector<std::wstring> current ;	// 予算に依存する既存登録を探す。
			std::vector<std::wstring> runs ;	// 旧archiveと新generationの保存名。
			// 両directoryを保護handle境界で全件列挙する。
			if( (state_->error = store.listCurrentNames( current)) != 0U ||
			   (state_->error = store.listRunNames( runs)) != 0U) {
				return state_->error ;
			}

			// 予算に依存する任意のcampaign履歴を、現在manifestで絞らず検査する。
			const auto needsBudget = []( const std::wstring &name) {
				return name.starts_with( L"campaign-") && !name.starts_with( L"campaign-controls-") ;
			} ;
			// 履歴・v2登録があるrootの予算両側消失も初回に戻さない。
			if( std::any_of( current.begin(), current.end(), needsBudget) ||
			   std::any_of( runs.begin(), runs.end(), needsBudget) ||
			   std::find( current.begin(), current.end(), L"collector-campaign-mode-v1.json") !=
				   current.end()) {
				return state_->error = ERROR_INVALID_DATA ;
			}
		}

		state_->found		= found ;
		state_->readUtc		= utcSeconds ;
		state_->initialized = true ;
		return ERROR_SUCCESS ;
	} catch( ...) {
		return state_->error = ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_campaign.h */
bool LocalCollectorBudgetLedger::hasSnapshot() const noexcept
{
	return state_->initialized && state_->found && state_->error == 0U ;
}

/** @see local_collector_campaign.h */
const CollectorBudgetSnapshot &LocalCollectorBudgetLedger::snapshot() const noexcept
{
	return state_->budget ;
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorBudgetLedger::prepareSettlement( const std::wstring_view			 campaign,
													const std::wstring_view			 job,
													const CollectorBudgetSettlement &settlement,
													CollectorBudgetPreparedUpdate	&prepared)
{
	prepared = {} ;
	// 既存のI/O拒否を形式errorで上書きしない。
	if( state_->error != 0U) {
		return state_->error ;
	}

	// 未存在予算・未初期化・不正identityには精算を作らない。
	if( !hasSnapshot() || !isHash( campaign) || !isHash( job)) {
		return state_->error = ERROR_INVALID_DATA ;
	}

	try {
		std::string currentBody ;	// 準備時点でも読込み済みsnapshotとの一致を要求する。
		std::string marker ;		// 登録の片側欠損を精算準備で無視しない。
		bool		found{} ;		// 欠損は元予算を復活させる理由にしない。
		bool		hasMarker{} ;	// 同じmarker本文を保存時にも確認する。
		// 別の共有更新があった場合は古いsnapshotから更新後本文を作らない。
		if( (state_->error = readEnvelope( *state_->store, L"current/campaign-budget-v1.json",
										 currentBody, found)) != 0U ||
		   (state_->error = readEnvelope( *state_->store, L"current/campaign-budget-marker-v1.json",
										 marker, hasMarker)) != 0U) {
			return state_->error ;
		}

		// 予算と登録を非変更で再確認し、未知の保存変更を拒否する。
		if( !found || !hasMarker || marker != "collector-campaign-budget-root-v1" ||
		   currentBody != encodeBudget( state_->budget)) {
			return state_->error = ERROR_INVALID_DATA ;
		}

		// Snapshotは保持し、更新後は別のtyped複製で計算する。
		auto	   after = state_->budget ;
		// 元予約へ完全一致する一件だけを精算対象にする。
		const auto reservation = std::find_if(
			after.reservations.begin(), after.reservations.end(),
			[&]( const auto &row) { return row.campaign == campaign && row.job == job ; }) ;
		// 固定時刻・課金条件と未閉鎖予約を照合する。
		if( reservation == after.reservations.end() || reservation->phase != 0U ||
		   dayFor( settlement.finishedUtcSeconds).empty() ||
		   dayFor( settlement.acceptedUtcSeconds).empty() ||
		   settlement.finishedUtcSeconds < reservation->started ||
		   settlement.acceptedUtcSeconds < settlement.finishedUtcSeconds ||
		   settlement.acceptedUtcSeconds > state_->readUtc ||
		   settlement.receivedBytes > reservation->maximum ||
		   (!settlement.bytesKnown && settlement.receivedBytes != 0U) ||
		   (settlement.interrupted && settlement.bytesKnown)) {
			return state_->error = ERROR_INVALID_DATA ;
		}

		reservation->phase = settlement.interrupted ? 2U : 1U ;
		reservation->charged =
			settlement.bytesKnown ? settlement.receivedBytes : reservation->maximum ;
		after.lastUtc = std::max( after.lastUtc, settlement.acceptedUtcSeconds) ;
		// 現在の回収時計を固定精算本文へ混ぜない。
		const auto	beforeBody = encodeBudget( state_->budget) ;
		std::string afterBody ;	// 同じcodecで更新後値を再検証する。
		// 更新後の日時・上限・phaseもv1契約を維持する。
		if( !encodeCollectorBudgetSnapshot( after, afterBody)) {
			return state_->error = ERROR_INVALID_DATA ;
		}

		prepared = {beforeBody, afterBody, hashOf( beforeBody), hashOf( afterBody)} ;
		return ERROR_SUCCESS ;
	} catch( ...) {
		return state_->error = ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorBudgetLedger::lastError() const noexcept
{
	return state_->error ;
}

/** @see local_collector_campaign.h */
bool parseCollectorCampaignManifest( const std::string_view						   bytes,
									const std::span<const CollectorCampaignSource> sources,
									CollectorCampaignManifest					  &manifest)
{
	manifest = {} ;
	try {
		// Manifestの非通信256 KiB上限。
		if( bytes.size() > 256U * 1024U || sources.size() > 64U) {
			return false ;
		}

		// Source registryはcallerが固定し、manifestには許可値を持たせない。
		std::map<std::pair<std::wstring, std::wstring>, CollectorCampaignSource> registry ;
		// Registryの内部矛盾と同じsourceのgroup分割を拒否する。
		std::map<std::wstring, std::wstring>									 groups ;
		// 有限descriptorを先に検証する。
		for( const auto &source : sources) {
			// Source fieldと上限が固定範囲外なら全入力を拒否する。
			if( !isToken( source.sourceId) || !isToken( source.resourceId) ||
			   !isToken( source.rateLimitGroup) || !isToken( source.parserRevision) ||
			   source.maximumResponseBytes == 0U || source.maximumResponseBytes > RESPONSE_BYTES ||
			   !registry.emplace( std::make_pair( source.sourceId, source.resourceId), source)
					.second) {
				return false ;
			}

			// 同一sourceの複数resourceではgroupを統一する。
			if( groups.contains( source.sourceId) &&
			   groups.at( source.sourceId) != source.rateLimitGroup) {
				return false ;
			}

			groups[source.sourceId] = source.rateLimitGroup ;
			// Source数をメーカー横断の有限枠へ制限する。
			if( groups.size() > 20U) {
				return false ;
			}
		}

		// 完全な実行manifest object。
		const auto root = objectFrom( bytes) ;
		fields( root, {L"schema", L"campaignId", L"planSha256", L"os", L"targets", L"jobs"}) ;
		// 評価plan schemaや未知OSを実行条件にしない。
		if( textField( root, L"schema") != L"collector-campaign-manifest-v1" ||
		   textField( root, L"os") != L"WINDOWS_11_X64") {
			return false ;
		}

		// 全入力検査が済むまでcaller出力を変更しない。
		CollectorCampaignManifest result ;
		result.campaignId	  = textField( root, L"campaignId") ;
		result.planSha256	  = textField( root, L"planSha256") ;
		result.manifestSha256 = hashOf( bytes) ;
		// Path等に転用できない有限識別子だけを保持する。
		if( !isToken( result.campaignId) || !isHash( result.planSha256)) {
			return false ;
		}

		// 固定300製品以下の入力配列。
		const auto targets = root.GetNamedArray( L"targets") ;
		// 空集合や過大集合を拒否する。
		if( targets.Size() == 0U || targets.Size() > 300U) {
			return false ;
		}

		// 公開IDから固定indexへ解決する。
		std::map<std::wstring, std::size_t> indices ;
		// 同一公開製品をOS等で水増ししない。
		std::set<std::wstring>				products ;
		// Makerごとの上限を共有する。
		std::map<std::wstring, std::size_t> makers ;
		// 有限集合の公開製品条件を固定順で取り出す。
		for( const auto &value : targets) {
			// 一targetの有限field。
			const auto row = value.GetObject() ;
			fields( row, {L"id", L"maker", L"model", L"kind", L"purpose"}) ;
			// Typeの持つ五つの公開値だけを読む。
			CollectorCampaignTarget		 target{textField( row, L"id"), textField( row, L"maker"),
											textField( row, L"model"), textField( row, L"kind"),
											textField( row, L"purpose")} ;
			// 製品種別を評価planで使用した有限集合へ制限する。
			const std::set<std::wstring> kinds{
				L"PRINT_SCAN_DEVICE", L"OEM_SYSTEM",	 L"DOCK",		  L"NETWORK_ADAPTER",
				L"MAINBOARD",		  L"BRIDGE_CHIP",	 L"AUDIO_DEVICE", L"TABLET_DEVICE",
				L"ADAPTER",			  L"GRAPHICS_DEVICE"} ;
			// Public identityの欠損・重複と秘密値を拒否する。
			if( !isToken( target.id) || !isPublicLabel( target.maker) ||
			   !isPublicLabel( target.model) || !isPublicLabel( target.purpose) ||
			   !kinds.contains( target.kind) ||
			   !indices.emplace( target.id, result.targets.size()).second ||
			   !products.insert( target.maker + L"\n" + target.model + L"\n" + target.kind).second ||
			   ++makers[target.maker] > 64U || makers.size() > 20U) {
				return false ;
			}

			result.targets.push_back( std::move( target)) ;
		}

		// 個別request入力の有限配列。
		const auto jobs = root.GetNamedArray( L"jobs") ;
		// 入力側も最大300のjobに制限する。
		if( jobs.Size() > 300U) {
			return false ;
		}

		// Shared keyから既存jobを探す。
		std::map<std::wstring, std::size_t> jobIndices ;
		// 最大3000の製品参照edgeを計数する。
		std::size_t							edges{} ;
		// 同じpublic requestだけを共有し、target参照を結合する。
		for( const auto &value : jobs) {
			// 一metadata jobの入力条件。
			const auto row = value.GetObject() ;
			fields( row, {L"source", L"resource", L"locator", L"locale", L"page", L"targets"}) ;
			// 組み込みdescriptorとの完全一致を探す。
			const auto source =
				registry.find( {textField( row, L"source"), textField( row, L"resource")}) ;
			// 未登録sourceやresourceに許可値を合成しない。
			if( source == registry.end()) {
				return false ;
			}

			// 共有jobの公開request identity。
			CollectorCampaignJob job ;
			job.source		  = source->second ;
			job.publicLocator = textField( row, L"locator") ;
			job.locale		  = textField( row, L"locale") ;
			// Narrowing前に有限page番号を検査する。
			const auto page = numberField( row, L"page") ;
			// Public locatorにはURLを受け取らない。
			if( !isPublicLabel( job.publicLocator) || !isToken( job.locale) || page == 0U ||
			   page > 10U) {
				return false ;
			}

			job.page = static_cast<std::uint32_t>( page) ;
			job.key	 = hashOf( jobIdentity( job)) ;
			// Jobの参照先を固定製品集合で照合する。
			const auto references = row.GetNamedArray( L"targets") ;
			// Product参照がないrequestを実行条件に入れない。
			if( references.Size() == 0U || references.Size() > 300U) {
				return false ;
			}

			// 重複参照を同一行内で検出する。
			std::set<std::size_t> rowIndices ;
			// 全参照を公開IDから固定indexへ解決する。
			for( const auto &reference : references) {
				// SDKによるString型検査後の公開ID。
				const std::wstring id( reference.GetString()) ;
				// 未知targetと参照上限超過を拒否する。
				if( !indices.contains( id) || !rowIndices.insert( indices.at( id)).second ||
				   ++edges > 3000U) {
					return false ;
				}

				job.targetIndices.push_back( indices.at( id)) ;
			}

			// 同一jobの重複行はrequestを増やさず参照だけを統合する。
			if( jobIndices.contains( job.key)) {
				// 既存jobの参照集合。
				auto &existing = result.jobs[jobIndices.at( job.key)].targetIndices ;
				// 追加行の参照を重複なしで結合する。
				for( const auto index : job.targetIndices) {
					// 別入力行での同じ参照は一つとして保持する。
					if( std::find( existing.begin(), existing.end(), index) == existing.end()) {
						existing.push_back( index) ;
					}
				}
			} else {
				jobIndices[job.key] = result.jobs.size() ;
				result.jobs.push_back( std::move( job)) ;
			}
		}

		manifest = std::move( result) ;
		return true ;
	} catch( ...) {
		manifest = {} ;
		return false ;
	}
}

/** @see local_collector_campaign.h */
bool makeCollectorCampaignJobKey( const CollectorCampaignJob &job, std::wstring &key)
{
	key.clear() ;
	try {
		key = hashOf( jobIdentity( job)) ;
		return true ;
	} catch( ...) {
		key.clear() ;
		return false ;
	}
}

/** @brief 保護storeと実行中campaignを単一writerとして所有します。 */
struct LocalCollectorCampaign::State {
	/// 旧root入口だけが所有するwriter store。
	std::unique_ptr<LocalCollectorStateStore>		 ownedStore ;
	/// 監督またはownedStoreが所有する借用store。core破棄まで存続します。
	LocalCollectorStateStore						*store{} ;
	/// 非通信parserで検証した固定manifest。
	CollectorCampaignManifest						 manifest ;
	/// 全実artifactとmanifestに結合した保存identity。
	std::wstring									 key ;
	/// Campaign本文のcurrent相対path。
	std::filesystem::path							 path ;
	/// 全campaignへ共通する今の日次予算。
	Budget											 budget ;
	/// Manifest jobと同じ順序の観測。
	std::vector<CollectorCampaignObservation>		 observations ;
	/// Manifest targetと同じ順序の反映状態。
	std::vector<CollectorCampaignTargetState>		 targets ;
	/// 直近の元I/O error。失敗後は新dispatchを拒否する。
	DWORD											 error{} ;
	/// 初期化成功後だけ操作を受理する。
	bool											 initialized{} ;
	/// Fixture専用の有限中断callback。
	std::function<bool( CollectorCampaignCheckpoint)> stop ;

	/** @brief 保存するcampaign本文をcanonical fieldへ射影します。
	 * @return 有限UTF-8本文。
	 */
	[[nodiscard]] std::string						 encode() const
	{
		// 元manifestはhashで結合し、任意入力本文を保存しない。
		JsonObject object ;
		putText( object, L"schema", L"collector-campaign-state-v1") ;
		putText( object, L"key", key) ;
		// Fixed job observationsだけを保存する。
		JsonArray rows ;
		// Job identityと結果を同じ順序で符号化する。
		for( std::size_t index = 0U; index < observations.size(); ++index) {
			// 一jobの有限結果。
			JsonObject	row ;
			// 対応するtyped observation。
			const auto &observation = observations[index] ;
			putText( row, L"key", manifest.jobs[index].key) ;
			putNumber( row, L"state", static_cast<std::uint64_t>( observation.state)) ;
			putNumber( row, L"started", observation.startedUtc) ;
			putNumber( row, L"finished", observation.finishedUtc) ;
			putNumber( row, L"bytes", observation.receivedBytes) ;
			putNumber( row, L"status", observation.httpStatus) ;
			putNumber( row, L"error", observation.error) ;
			putText( row, L"body", observation.bodySha256) ;
			putText( row, L"projection", observation.projectionSha256) ;
			rows.Append( row) ;
		}

		object.Insert( L"jobs", rows) ;
		// Targetの反映済み状態だけを固定順で保存する。
		JsonArray values ;
		// 二重反映防止のterminal状態を保持する。
		for( const auto state : targets) {
			values.Append( JsonValue::CreateNumberValue( static_cast<double>( state))) ;
		}

		object.Insert( L"targets", values) ;
		return winrt::to_string( object.Stringify()) ;
	}

	/** @brief Canonicalなcampaign本文をmanifestと照合して復号します。
	 * @param[in] bytes Hash検査済み本文。
	 */
	void decode( const std::string_view bytes)
	{
		// 許可fieldだけを持つ保存object。
		const auto object = objectFrom( bytes) ;
		fields( object, {L"schema", L"key", L"jobs", L"targets"}) ;
		// 別manifest／契約の保存結果を混ぜない。
		if( textField( object, L"schema") != L"collector-campaign-state-v1" ||
		   textField( object, L"key") != key) {
			throw std::invalid_argument( "campaign binding") ;
		}

		// 固定順で読むjob観測。
		const auto rows = object.GetNamedArray( L"jobs") ;
		// 固定順で読むtarget状態。
		const auto values = object.GetNamedArray( L"targets") ;
		// 保存側の集合を縮小・拡大しない。
		if( rows.Size() != observations.size() || values.Size() != targets.size()) {
			throw std::invalid_argument( "campaign count") ;
		}

		// 全jobを契約keyと型付き数値で検証する。
		for( std::size_t index = 0U; index < observations.size(); ++index) {
			// 一つの保存行。
			const auto row = rows.GetAt( static_cast<std::uint32_t>( index)).GetObject() ;
			fields( row, {L"key", L"state", L"started", L"finished", L"bytes", L"status", L"error",
						 L"body", L"projection"}) ;
			// Narrowing前の状態値。
			const auto state = numberField( row, L"state") ;
			// Narrowing前のHTTP status。
			const auto status = numberField( row, L"status") ;
			// Narrowing前の元error。
			const auto code = numberField( row, L"error") ;
			// Job identityと有限の数値状態を先に確認する。
			if( textField( row, L"key") != manifest.jobs[index].key || !validState( state) ||
			   status > 599U || (status != 0U && status < 100U) || code > MAXDWORD) {
				throw std::invalid_argument( "observation type") ;
			}

			// 検証後に型へ変換する一結果。
			CollectorCampaignObservation observation ;
			observation.state			 = static_cast<CollectorCampaignJobState>( state) ;
			observation.startedUtc		 = numberField( row, L"started") ;
			observation.finishedUtc		 = numberField( row, L"finished") ;
			observation.receivedBytes	 = numberField( row, L"bytes") ;
			observation.httpStatus		 = static_cast<std::uint32_t>( status) ;
			observation.error			 = static_cast<std::uint32_t>( code) ;
			observation.bodySha256		 = textField( row, L"body") ;
			observation.projectionSha256 = textField( row, L"projection") ;
			// 観測stateに固有の整合条件を検査する。
			if( !validObservation( observation, manifest.jobs[index].source.maximumResponseBytes)) {
				throw std::invalid_argument( "observation state") ;
			}

			observations[index] = std::move( observation) ;
		}

		// Terminal targetは現在の依存結果と一致していなければ拒否する。
		for( std::size_t index = 0U; index < targets.size(); ++index) {
			// 元の浮動値を整数状態として検証する。
			const double state = values.GetAt( static_cast<std::uint32_t>( index)).GetNumber() ;
			// Unknownな状態を整数へcastしない。
			if( !std::isfinite( state) || state < 0.0 || state > 4.0 || std::floor( state) != state) {
				throw std::invalid_argument( "target state") ;
			}

			targets[index] =
				static_cast<CollectorCampaignTargetState>( static_cast<std::uint32_t>( state)) ;
			// 未反映PENDING以外は現在jobからの集約と完全一致を要求する。
			if( targets[index] != CollectorCampaignTargetState::PENDING &&
			   targets[index] != targetState( manifest, observations, index)) {
				throw std::invalid_argument( "target binding") ;
			}
		}

		// 重複key以外の非canonical保存表現も拒否する。
		if( encode() != bytes) {
			throw std::invalid_argument( "campaign canonical") ;
		}
	}

	/** @brief 観測の状態別predicateを保存と完了で共用します。
	 * @param[in] observation 確認する結果。
	 * @param[in] maximum 応答の固定byte上限。
	 * @return 状態別の欠損／数値／hashが整合する場合true。
	 */
	[[nodiscard]] static bool validObservation( const CollectorCampaignObservation &observation,
											   const std::uint64_t				   maximum)
	{
		// Byte／statusの上限を全状態で検査する。
		if( observation.receivedBytes > maximum || observation.httpStatus > 599U ||
		   (observation.httpStatus != 0U && observation.httpStatus < 100U)) {
			return false ;
		}

		// 未試行を成功観測へ見せない。
		if( observation.state == CollectorCampaignJobState::PENDING) {
			return observation.startedUtc == 0U && observation.finishedUtc == 0U &&
				   observation.receivedBytes == 0U && observation.httpStatus == 0U &&
				   observation.error == 0U && observation.bodySha256.empty() &&
				   observation.projectionSha256.empty() ;
		}

		// 開始していない結果や日時不正を拒否する。
		if( dayFor( observation.startedUtc).empty()) {
			return false ;
		}

		// 実行中は開始時刻だけを保存する。
		if( observation.state == CollectorCampaignJobState::RUNNING) {
			return observation.finishedUtc == 0U && observation.receivedBytes == 0U &&
				   observation.httpStatus == 0U && observation.error == 0U &&
				   observation.bodySha256.empty() && observation.projectionSha256.empty() ;
		}

		// 完了時刻を同じUTC系列で確認する。
		if( dayFor( observation.finishedUtc).empty() ||
		   observation.finishedUtc < observation.startedUtc) {
			return false ;
		}

		// 正常結果には二つの独立hashと実応答が必要である。
		if( observation.state == CollectorCampaignJobState::OBSERVED) {
			return observation.error == 0U && observation.receivedBytes != 0U &&
				   observation.httpStatus >= 200U && observation.httpStatus < 300U &&
				   isHash( observation.bodySha256) && isHash( observation.projectionSha256) ;
		}

		return observation.error != 0U && observation.bodySha256.empty() &&
			   observation.projectionSha256.empty() &&
			   (observation.state == CollectorCampaignJobState::FAILED ||
				observation.state == CollectorCampaignJobState::HELD ||
				(observation.state == CollectorCampaignJobState::INTERRUPTED &&
				 observation.receivedBytes == 0U && observation.httpStatus == 0U &&
				 observation.error == ERROR_OPERATION_ABORTED)) ;
	}

	/** @brief 日次予算を同rootの固定fileへ保存します。
	 * @return 元Win32 code。
	 */
	[[nodiscard]] DWORD saveBudget()
	{
		return error =
				   writeEnvelope( *store, L"current/campaign-budget-v1.json", encodeBudget( budget)) ;
	}

	/** @brief 一campaign本文を現在世代へ保存します。
	 * @return 元Win32 code。
	 */
	[[nodiscard]] DWORD saveCampaign()
	{
		return error = writeEnvelope( *store, path, encode()) ;
	}

	/** @brief 日跨ぎの予算を保守的に閉じ、旧日を保存して新日へ移ります。
	 * @param[in] utc 信頼する現在UTC秒。
	 * @return 変更保存成功0、日時不正またはI/O code。
	 */
	[[nodiscard]] DWORD advanceDay( const std::uint64_t utc)
	{
		// 時計の巻戻しは予算更新前に拒否する。
		if( dayFor( utc).empty() || utc < budget.lastUtc) {
			return error = ERROR_INVALID_DATA ;
		}

		// 同一日は台帳世代を変えない。
		if( dayFor( utc) == budget.day) {
			budget.lastUtc = utc ;
			return ERROR_SUCCESS ;
		}

		// 新日に跨ぐ未確定予約はmaximumを維持して閉じる。
		for( auto &reservation : budget.reservations) {
			// 別campaignの未完了も旧日から新日へ予算を持ち越さない。
			if( reservation.phase == 0U) {
				reservation.phase = 2U ;
			}
		}

		// Archive前に旧currentの閉鎖を確定する。
		if( saveBudget() != 0U) {
			return error ;
		}

		// 旧日を既存の保護runsへimmutable保存する。
		const auto archivePath =
			std::filesystem::path( L"runs") / (L"campaign-budget-" + budget.day + L".json") ;
		// 旧日に確定したcanonical本文。
		const auto	body = encodeBudget( budget) ;
		// 再開時の既存archiveを検証する。
		std::string existing ;
		// Archiveの欠損を正常な初回と区別する。
		bool		found{} ;
		// 同一archiveの内容を変えず、commit窓再開を受け入れる。
		if( (error = readEnvelope( *store, archivePath, existing, found)) != 0U ||
		   (found && existing != body)) {
			return error = error != 0U ? error : ERROR_INVALID_DATA ;
		}

		// 新規archiveだけを作成する。
		if( !found && (error = writeEnvelope( *store, archivePath, body)) != 0U) {
			return error ;
		}

		budget = {dayFor( utc), utc, {}} ;
		return saveBudget() ;
	}
} ;

/** @see local_collector_campaign.h */
LocalCollectorCampaign::LocalCollectorCampaign() : state_( std::make_unique<State>())
{
}
/** @see local_collector_campaign.h */
LocalCollectorCampaign::~LocalCollectorCampaign()
{
	// 借用coreを破棄しても監督のwriter lockを解放しない。
	if( state_->store != nullptr) {
		state_->store->releaseCampaign( state_.get()) ;
	}
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorCampaign::initialize( const std::filesystem::path	 &root,
										 const CollectorCampaignManifest &manifest,
										 const std::wstring_view		  contractSha256,
										 const std::uint64_t			  utcSeconds,
										 std::function<bool( CollectorCampaignCheckpoint)> stop)
{
	// 一coreからwriterや借用先を途中で差し替えない。
	if( state_->store != nullptr || state_->ownedStore || state_->initialized) {
		return state_->error = ERROR_BUSY ;
	}

	try {
		// 入力とrootの境界を作成前に検査する。
		const auto absolute = std::filesystem::absolute( root).lexically_normal() ;
		// 専用state以外の領域へ書き込まないための固定親。
		const auto parent = (std::filesystem::current_path() / L"work/state").lexically_normal() ;
		// root自身と親方向のpathを拒否する相対値。
		const auto relative = absolute.lexically_relative( parent) ;
		// 許可外pathではwriterもdirectoryも作成しない。
		if( relative.empty() || relative == L"." ||
		   std::any_of( relative.begin(), relative.end(),
					   []( const auto &part) { return part == L".." ; })) {
			return state_->error = ERROR_INVALID_NAME ;
		}

		// 不正manifestから保護directoryを作成しない。
		if( !isHash( manifest.manifestSha256) || !isHash( manifest.planSha256) ||
		   !isHash( contractSha256) || !isToken( manifest.campaignId) || manifest.targets.empty() ||
		   manifest.targets.size() > 300U || manifest.jobs.size() > 300U ||
		   dayFor( utcSeconds).empty()) {
			return state_->error = ERROR_INVALID_DATA ;
		}

		// 入力後のjob改変をstore作成前にも検査する。
		for( const auto &job : manifest.jobs) {
			// source上限とtarget参照が有効な共有jobだけを受け入れる。
			if( !isHash( job.key) || job.key != hashOf( jobIdentity( job)) ||
			   job.source.maximumResponseBytes == 0U ||
			   job.source.maximumResponseBytes > RESPONSE_BYTES || job.targetIndices.empty() ||
			   std::any_of( job.targetIndices.begin(), job.targetIndices.end(),
						   [&]( const auto index) { return index >= manifest.targets.size() ; })) {
				return state_->error = ERROR_INVALID_DATA ;
			}
		}

		state_->ownedStore = std::make_unique<LocalCollectorStateStore>() ;
		// root入口の所有権だけを確定して共通借用入口へ渡す。
		const DWORD error = state_->ownedStore->initialize( absolute, true) ;
		// writer取得失敗を有効な借用へ変換しない。
		if( error != ERROR_SUCCESS) {
			return state_->error = error ;
		}

		return initializeBorrowed( *state_->ownedStore, manifest, contractSha256, utcSeconds,
								  std::move( stop)) ;
	} catch( ...) {
		return state_->error = ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorCampaign::initializeBorrowed(
	LocalCollectorStateStore &store, const CollectorCampaignManifest &manifest,
	const std::wstring_view contractSha256, const std::uint64_t utcSeconds,
	std::function<bool( CollectorCampaignCheckpoint)> stop)
{
	try {
		// 未初期化やread-only検査からwriter操作を開始しない。
		if( !store.isWritable()) {
			return state_->error = ERROR_INVALID_PARAMETER ;
		}

		// 未初期化objectの一回目だけを受け入れる。
		if( state_->initialized || state_->store != nullptr || !isHash( manifest.manifestSha256) ||
		   !isHash( manifest.planSha256) || !isHash( contractSha256) ||
		   !isToken( manifest.campaignId) || manifest.targets.empty() ||
		   manifest.targets.size() > 300U || manifest.jobs.size() > 300U ||
		   dayFor( utcSeconds).empty()) {
			return state_->error = ERROR_INVALID_DATA ;
		}

		// v2登録済みrootの応答を、v1の他campaign自動中断で失わせない。
		if( (state_->error = rejectLocalCollectorCampaignMode( store)) != 0U) {
			return state_->error ;
		}

		// Workspace内の絶対pathだけへ保護stateを作る。
		const auto absolute = store.root() ;
		// Stateの固定親。reparseはstoreがhandleから検証する。
		const auto parent = (std::filesystem::current_path() / L"work/state").lexically_normal() ;
		// root自身や外部pathを対象にしない。
		const auto relative = absolute.lexically_relative( parent) ;
		// 相対親方向を含むrootを拒否する。
		if( relative.empty() || relative == L"." ||
		   std::any_of( relative.begin(), relative.end(),
					   []( const auto &part) { return part == L".." ; })) {
			return state_->error = ERROR_INVALID_NAME ;
		}

		// Typed入力でもjob keyと参照indexを再確認する。
		for( const auto &job : manifest.jobs) {
			// Manifest後の改変と予算上限拡張を拒否する。
			if( !isHash( job.key) || job.key != hashOf( jobIdentity( job)) ||
			   job.source.maximumResponseBytes == 0U ||
			   job.source.maximumResponseBytes > RESPONSE_BYTES || job.targetIndices.empty() ||
			   std::any_of( job.targetIndices.begin(), job.targetIndices.end(),
						   [&]( const auto index) { return index >= manifest.targets.size() ; })) {
				return state_->error = ERROR_INVALID_DATA ;
			}
		}

		state_->manifest = manifest ;
		state_->key		 = hashOf( winrt::to_string( winrt::hstring( manifest.manifestSha256)) + "\n" +
								  winrt::to_string( winrt::hstring( contractSha256)) + "\n") ;
		state_->path =
			std::filesystem::path( L"current") / (L"campaign-v1-" + state_->key + L".json") ;
		state_->observations.resize( manifest.jobs.size()) ;
		state_->targets.resize( manifest.targets.size(), CollectorCampaignTargetState::PENDING) ;
		state_->stop = std::move( stop) ;
		// 一つの監督だけが同じstoreからcampaign予算を操作する。
		if( (state_->error = store.borrowCampaign( state_.get())) != 0U) {
			return state_->error ;
		}

		state_->store = &store ;

		// Hash envelopeの有限本文。
		std::string body ;
		// 初回と既存台帳を区別する。
		bool		found{} ;
		// 台帳欠損時の予算復活を防ぐ、同rootのimmutable marker。
		std::string marker ;
		// Markerがすでに作成されたrootかを確認する。
		bool		hasMarker{} ;
		// Markerも通常stateと同じACL・hash境界で読む。
		if( (state_->error = readEnvelope( *state_->store, L"current/campaign-budget-marker-v1.json",
										 marker, hasMarker)) != 0U ||
		   (hasMarker && marker != "collector-campaign-budget-root-v1")) {
			return state_->error = state_->error != 0U ? state_->error : ERROR_INVALID_DATA ;
		}

		// 全campaign共通予算をmanifestとは独立に読む。
		if( (state_->error = readEnvelope( *state_->store, L"current/campaign-budget-v1.json", body,
										 found)) != 0U) {
			return state_->error ;
		}

		// 既存budgetを検査し、時計の巻戻しを拒否する。
		if( found) {
			// 予算本文だけが残った不完全なrootを新規扱いしない。
			if( !hasMarker) {
				return state_->error = ERROR_INVALID_DATA ;
			}

			state_->budget = decodeBudget( body) ;
			// 別契約の起動でも時計は共通台帳に従う。
			if( utcSeconds < state_->budget.lastUtc) {
				return state_->error = ERROR_INVALID_DATA ;
			}
		} else {
			// 作成済みrootからbudgetだけ失われても課金を戻さない。
			if( hasMarker) {
				return state_->error = ERROR_INVALID_DATA ;
			}

			state_->budget = {dayFor( utcSeconds), utcSeconds, {}} ;
			// Budgetが失われた既存campaignを初回と誤認しない。
			std::string existing ;
			// 自campaign本文の欠損確認。
			bool		hasCampaign{} ;
			// 自campaignが存在するのに共通budgetがない状態を拒否する。
			if( (state_->error =
					readEnvelope( *state_->store, state_->path, existing, hasCampaign)) != 0U ||
			   hasCampaign) {
				return state_->error = state_->error != 0U ? state_->error : ERROR_INVALID_DATA ;
			}

			// 初回markerをbudgetより先に保存し、中断窓をfail-closedにする。
			if( (state_->error =
					writeEnvelope( *state_->store, L"current/campaign-budget-marker-v1.json",
								  "collector-campaign-budget-root-v1")) != 0U ||
			   state_->saveBudget() != 0U) {
				return state_->error ;
			}
		}

		// 一campaignの既存結果を同じ保護handle契約で読む。
		if( (state_->error = readEnvelope( *state_->store, state_->path, body, found)) != 0U) {
			return state_->error ;
		}

		// 日次台帳に履歴が残らなくても、本文欠損を初回として再送しない。
		const auto identityPath =
			std::filesystem::path( L"current") / (L"campaign-marker-v1-" + state_->key + L".json") ;
		// Manifestとartifactへ結合したimmutable識別本文。
		const auto identity =
			"collector-campaign-identity-v1\n" + winrt::to_string( winrt::hstring( state_->key)) ;
		// 本文とmarkerの存在を独立した保護readで照合する。
		bool hasIdentity{} ;
		// 未存在だけを新規とし、片方だけの保存は自動修復しない。
		if( (state_->error = readEnvelope( *state_->store, identityPath, marker, hasIdentity)) !=
			   0U ||
		   found != hasIdentity || (hasIdentity && marker != identity)) {
			return state_->error = state_->error != 0U ? state_->error : ERROR_INVALID_DATA ;
		}

		// 初回本文より先にmarkerを保存し、中断後の新規扱いを抑止する。
		if( !hasIdentity &&
		   (state_->error = writeEnvelope( *state_->store, identityPath, identity)) != 0U) {
			return state_->error ;
		}

		// 既存結果の型・key・集合・状態を照合する。
		if( found) {
			state_->decode( body) ;
		}

		// 旧processが別campaignの予約を残していてもin-flight枠を永久占有させない。
		for( auto &reservation : state_->budget.reservations) {
			// 未確定byteは最大予約量を保ち、他campaignの結果は推測しない。
			if( reservation.campaign != state_->key && reservation.phase == 0U) {
				reservation.phase = 2U ;
			}
		}

		// 中断予約により結果または先払いを回収する。
		for( std::size_t index = 0U; index < manifest.jobs.size(); ++index) {
			// 対応するjobの保存観測。
			auto &observation = state_->observations[index] ;
			// 保存結果より前へ時計を戻して再開しない。
			if( observation.finishedUtc > utcSeconds || observation.startedUtc > utcSeconds) {
				return state_->error = ERROR_INVALID_DATA ;
			}

			// 旧日の予約が必要なjobはそのimmutable台帳を読む。
			Budget	archive ;
			// 現日台帳を通常の照合先とする。
			Budget *ledger = &state_->budget ;
			// 開始日が旧current日より前ならarchiveを参照する。
			if( observation.startedUtc != 0U &&
			   dayFor( observation.startedUtc) < state_->budget.day) {
				// 旧日予算は存在を必須とする。
				bool hasArchive{} ;
				// Jobが参照する旧日だけを有限に読む。
				if( (state_->error = readEnvelope(
						*state_->store,
						std::filesystem::path( L"runs") /
							(L"campaign-budget-" + dayFor( observation.startedUtc) + L".json"),
						body, hasArchive)) != 0U ||
				   !hasArchive) {
					return state_->error = state_->error != 0U ? state_->error : ERROR_INVALID_DATA ;
				}

				archive = decodeBudget( body) ;
				ledger	= &archive ;
			}

			// Manifestから予約の対応を一意に探す。
			auto reservation = std::find_if(
				ledger->reservations.begin(), ledger->reservations.end(), [&]( const auto &entry) {
					return entry.campaign == state_->key && entry.job == manifest.jobs[index].key ;
				}) ;
			// 開始済みjobに予約がないと通信前に拒否する。
			if( reservation == ledger->reservations.end()) {
				// 未通信jobだけは予約なしを許可する。
				if( observation.state != CollectorCampaignJobState::PENDING) {
					return state_->error = ERROR_INVALID_DATA ;
				}

				continue ;
			}

			// 保存jobと組み込みsource契約の予約が一致しているか確認する。
			if( reservation->group != manifest.jobs[index].source.rateLimitGroup ||
			   reservation->maximum != manifest.jobs[index].source.maximumResponseBytes ||
			   (observation.startedUtc != 0U && observation.startedUtc != reservation->started)) {
				return state_->error = ERROR_INVALID_DATA ;
			}

			// 未確定または予約直後の中断を再送せず確定する。
			if( observation.state == CollectorCampaignJobState::PENDING ||
			   observation.state == CollectorCampaignJobState::RUNNING) {
				// 結果閉鎖済みなのにjobが未完了なら矛盾である。
				if( reservation->phase == 1U) {
					return state_->error = ERROR_INVALID_DATA ;
				}

				observation.state		= CollectorCampaignJobState::INTERRUPTED ;
				observation.startedUtc	= reservation->started ;
				observation.finishedUtc = utcSeconds ;
				observation.error		= ERROR_OPERATION_ABORTED ;
				reservation->phase		= 2U ;
				continue ;
			}

			// 結果だけ確定した保存窓では実byteへ閉じる。
			if( reservation->phase == 0U) {
				// Job結果だけ保存した中断窓から実受信byteで予約を閉じる。
				reservation->phase	 = 1U ;
				reservation->charged = observation.receivedBytes ;
			}

			// 完了済み二台帳の課金不一致を拒否する。
			if( reservation->phase == 1U && reservation->charged != observation.receivedBytes) {
				// 閉鎖済みbyteとjob結果が矛盾した場合は拒否する。
				return state_->error = ERROR_INVALID_DATA ;
			}
		}

		// 結果回収後のbudgetを先払いと整合した状態へ保存する。
		if( state_->saveCampaign() != 0U || state_->saveBudget() != 0U ||
		   state_->advanceDay( utcSeconds) != 0U) {
			return state_->error ;
		}

		state_->initialized = true ;
		return ERROR_SUCCESS ;
	} catch( ...) {
		return state_->error = ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_campaign.h */
CollectorCampaignDispatchResult LocalCollectorCampaign::reserve( const std::uint64_t utcSeconds,
																CollectorCampaignDispatch &dispatch)
{
	dispatch = {} ;
	// 初期化拒否・先行I/O失敗後は通信許可を返さない。
	if( !state_->initialized || state_->error != 0U) {
		return CollectorCampaignDispatchResult::REJECTED ;
	}

	// 同じprocessでのRUNNING jobを日跨ぎで再送しない。
	if( dayFor( utcSeconds) != state_->budget.day &&
	   std::any_of( state_->observations.begin(), state_->observations.end(), []( const auto &row) {
		   return row.state == CollectorCampaignJobState::RUNNING ;
	   })) {
		return CollectorCampaignDispatchResult::WAIT ;
	}

	// 共通budgetの日時を先に確認する。
	if( state_->advanceDay( utcSeconds) != 0U) {
		return CollectorCampaignDispatchResult::REJECTED ;
	}

	// 現在in-flightのrequest数。
	const auto active =
		std::count_if( state_->budget.reservations.begin(), state_->budget.reservations.end(),
					  []( const auto &row) { return row.phase == 0U ; }) ;
	// Pendingがなければ実行中と全terminalを区別する。
	const bool pending =
		std::any_of( state_->observations.begin(), state_->observations.end(), []( const auto &row) {
			return row.state == CollectorCampaignJobState::PENDING ;
		}) ;
	// Terminalだけの集合には新予約を作らない。
	if( !pending && active == 0) {
		return CollectorCampaignDispatchResult::COMPLETE ;
	}

	// 実行中のrequestも監督へ返したwall期限で取消し対象にする。
	if( !state_->budget.reservations.empty() &&
	   utcSeconds - state_->budget.reservations.front().started >= DAILY_SECONDS) {
		return CollectorCampaignDispatchResult::BUDGET_EXHAUSTED ;
	}

	// 全体の同時request数は四つに制限する。
	if( active >= 4 || !pending) {
		return CollectorCampaignDispatchResult::WAIT ;
	}

	// 全campaignからの課金byteを合算する。
	std::uint64_t charged{} ;
	// 日次の予約・受信済みbyteを一つの総量へ集計する。
	for( const auto &reservation : state_->budget.reservations) {
		charged += reservation.charged ;
	}

	// 要求数・初回からの時間を日次全体で確認する。
	if( state_->budget.reservations.size() >= DAILY_REQUESTS ||
	   (!state_->budget.reservations.empty() &&
		utcSeconds - state_->budget.reservations.front().started >= DAILY_SECONDS)) {
		return CollectorCampaignDispatchResult::BUDGET_EXHAUSTED ;
	}

	// Byte待ちとsource開始間隔待ちを区別する。
	bool byteBlocked{} ;
	// Manifestの固定順から開始できるjobを選ぶ。
	for( std::size_t index = 0U; index < state_->manifest.jobs.size(); ++index) {
		// 未開始jobだけをdispatch対象にする。
		if( state_->observations[index].state != CollectorCampaignJobState::PENDING) {
			continue ;
		}

		// 借用する組み込みrequest条件。
		const auto &job = state_->manifest.jobs[index] ;
		// 全日台帳から同groupの開始間隔とin-flightを確認する。
		const bool	busy =
			std::any_of( state_->budget.reservations.begin(), state_->budget.reservations.end(),
						[&]( const auto &entry) {
							return entry.group == job.source.rateLimitGroup &&
								   (entry.phase == 0U || utcSeconds - entry.started < 2U) ;
						}) ;
		// 応答上限を予約できなければHTTP前に止める。
		if( job.source.maximumResponseBytes > DAILY_BYTES - charged) {
			byteBlocked = true ;
			continue ;
		}

		// 同groupの許可枠が空くまで別sourceだけを探す。
		if( busy) {
			continue ;
		}

		state_->budget.reservations.push_back( {state_->key, job.key, job.source.rateLimitGroup,
											   utcSeconds, job.source.maximumResponseBytes,
											   job.source.maximumResponseBytes, 0U}) ;
		// Budget予約を先に確定して保存窓での二重通信を防ぐ。
		if( state_->saveBudget() != 0U) {
			return CollectorCampaignDispatchResult::REJECTED ;
		}

		// 非通信fixtureだけが予約直後の中断を差し込む。
		if( state_->stop && state_->stop( CollectorCampaignCheckpoint::BUDGET_RESERVED)) {
			state_->error = ERROR_OPERATION_ABORTED ;
			return CollectorCampaignDispatchResult::REJECTED ;
		}

		state_->observations[index].state	   = CollectorCampaignJobState::RUNNING ;
		state_->observations[index].startedUtc = utcSeconds ;
		// Executorへ返す前にjob開始を保存する。
		if( state_->saveCampaign() != 0U) {
			return CollectorCampaignDispatchResult::REJECTED ;
		}

		dispatch = {index, job.key, job.source.maximumResponseBytes,
					state_->budget.reservations.front().started + DAILY_SECONDS} ;
		return CollectorCampaignDispatchResult::READY ;
	}

	return byteBlocked ? CollectorCampaignDispatchResult::BUDGET_EXHAUSTED
					   : CollectorCampaignDispatchResult::WAIT ;
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorCampaign::finish( const std::wstring_view			 jobKey,
									 const CollectorCampaignObservation &observation,
									 const std::uint64_t				 utcSeconds)
{
	// Stateエラー後は結果で失敗を上書きしない。
	if( !state_->initialized || state_->error != 0U) {
		return state_->error = state_->error != 0U ? state_->error : ERROR_INVALID_DATA ;
	}

	// 完了時刻は予算の時計と一貫している必要がある。
	if( dayFor( utcSeconds).empty() || utcSeconds < state_->budget.lastUtc) {
		return state_->error = ERROR_INVALID_DATA ;
	}

	// 完了の対象を元のjob keyで解決する。
	const auto found = std::find_if( state_->manifest.jobs.begin(), state_->manifest.jobs.end(),
									[&]( const auto &job) { return job.key == jobKey ; }) ;
	// 未知jobに完了状態を追加しない。
	if( found == state_->manifest.jobs.end()) {
		return state_->error = ERROR_INVALID_DATA ;
	}

	// 固定job配列へのindex。
	const auto index = static_cast<std::size_t>( found - state_->manifest.jobs.begin()) ;
	// Caller値から元の開始時刻と今回の完了時刻を確定する。
	auto	   completed  = observation ;
	completed.startedUtc  = state_->observations[index].startedUtc ;
	completed.finishedUtc = utcSeconds ;
	// RUNNING一件の有限結果だけを一回受理する。
	if( state_->observations[index].state != CollectorCampaignJobState::RUNNING ||
	   (completed.state != CollectorCampaignJobState::OBSERVED &&
		completed.state != CollectorCampaignJobState::FAILED &&
		completed.state != CollectorCampaignJobState::HELD) ||
	   !State::validObservation( completed, found->source.maximumResponseBytes)) {
		return state_->error = ERROR_INVALID_DATA ;
	}

	// 先払い予約を必ず一件へ結合する。
	auto reservation = std::find_if(
		state_->budget.reservations.begin(), state_->budget.reservations.end(),
		[&]( const auto &entry) { return entry.campaign == state_->key && entry.job == jobKey ; }) ;
	// 保存budgetとの結合が欠ける完了は拒否する。
	if( reservation == state_->budget.reservations.end() || reservation->phase != 0U) {
		return state_->error = ERROR_INVALID_DATA ;
	}

	state_->observations[index] = std::move( completed) ;
	// Observationを先に保存し、budgetだけ成功した状態を作らない。
	if( state_->saveCampaign() != 0U) {
		return state_->error ;
	}

	// 非通信fixtureで結果保存直後の中断を観測する。
	if( state_->stop && state_->stop( CollectorCampaignCheckpoint::OBSERVATION_SAVED)) {
		return state_->error = ERROR_OPERATION_ABORTED ;
	}

	reservation->phase	 = 1U ;
	reservation->charged = state_->observations[index].receivedBytes ;
	// 日跨ぎの完了でも時計の最高値を保ち、旧日の予約groupは維持する。
	state_->budget.lastUtc = utcSeconds ;
	return state_->saveBudget() ;
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorCampaign::applyResults( std::size_t &applied)
{
	applied = 0U ;
	// 初期化失敗後の反映は拒否する。
	if( !state_->initialized || state_->error != 0U) {
		return state_->error = state_->error != 0U ? state_->error : ERROR_INVALID_DATA ;
	}

	// 固定順で最大32製品だけをterminalへ反映する。
	for( std::size_t index = 0U; index < state_->targets.size() && applied < 32U; ++index) {
		// 反映済み製品を再計上しない。
		if( state_->targets[index] != CollectorCampaignTargetState::PENDING) {
			continue ;
		}

		// 現在のjob依存から集約する。
		const auto result = targetState( state_->manifest, state_->observations, index) ;
		// 未完了依存をterminalへ昇格しない。
		if( result != CollectorCampaignTargetState::PENDING) {
			state_->targets[index] = result ;
			++applied ;
		}
	}

	return applied == 0U ? ERROR_SUCCESS : state_->saveCampaign() ;
}

/** @see local_collector_campaign.h */
const std::vector<CollectorCampaignObservation> &LocalCollectorCampaign::observations()
	const noexcept
{
	return state_->observations ;
}

/** @see local_collector_campaign.h */
const std::vector<CollectorCampaignTargetState> &LocalCollectorCampaign::targetStates()
	const noexcept
{
	return state_->targets ;
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorCampaign::lastError() const noexcept
{
	return state_->error ;
}

/** @brief Manifest独立の待機と開始intentを一つの台帳へ結合します。 */
struct LocalCollectorWaitLedger::State {
	/** @brief v1待機とv2監督で同じ型とcodecを使います。 */
	using Control = CollectorWaitControl ;

	/// 台帳より長く存続する監督store。
	LocalCollectorStateStore			 *store{} ;
	/// 最大20 group・300 requestの制御集合。
	std::map<std::wstring, Control>		  controls ;
	/// 稼働中に観測したgroup完了の単調millisecond。
	std::map<std::wstring, std::uint64_t> completedSteady ;
	/// 保存台帳のUTC最高値。
	std::uint64_t						  lastUtc{} ;
	/// 保存を伴わないcheckも含む現在processのUTC最高値。
	std::uint64_t						  clockUtc{} ;
	/// 単調時計の最高値。
	std::uint64_t						  lastSteady{} ;
	/// 起動時に旧完了groupへ適用する保守的な二秒基準。
	std::uint64_t						  initialSteady{} ;
	/// 単一監督のthread identity。OSのthread IDは保存しません。
	DWORD								  ownerThread{} ;
	/// 初期化を完全に終えた場合true。
	bool								  ready{} ;
	/// 失敗後に操作を受け入れない元code。
	DWORD								  error{} ;

	/** @brief Controlを未知fieldなしのcanonical JSONへ符号化します。
     * @return 有限の非機密本文。
     */
	[[nodiscard]] std::string			  encode() const
	{
		// 登録とcontrol更新を同じatomic replaceへ結合する。
		JsonObject object ;
		putText( object, L"schema", L"collector-campaign-controls-v1") ;
		putNumber( object, L"lastUtcMillis", lastUtc) ;
		// 固定key順で最大320 entryを保存する。
		JsonArray rows ;
		// 原URL・Retry-After文字列・EULAを射影へ含めない。
		for( const auto &entry : controls) {
			// 同じkeyに属する一control。
			const auto &control = entry.second ;
			// 許可fieldだけを持つ保存行。
			JsonObject	row ;
			putText( row, L"key", entry.first) ;
			putText( row, L"group", control.group) ;
			putText( row, L"request", control.request) ;
			putNumber( row, L"observed", control.observed) ;
			putNumber( row, L"notBefore", control.notBefore) ;
			putNumber( row, L"completed", control.completed) ;
			row.Insert( L"needsReview", JsonValue::CreateBooleanValue( control.review)) ;
			putText( row, L"generation", control.generation) ;
			putText( row, L"job", control.job) ;
			putNumber( row, L"started", control.started) ;
			rows.Append( row) ;
		}

		object.Insert( L"controls", rows) ;
		return winrt::to_string( object.Stringify()) ;
	}

	/** @brief 保存controlのkey・時計・開始結合を検証します。
     * @param[in] bytes Hash検査済み本文。
     */
	void decode( const std::string_view bytes)
	{
		// 完全一致のfieldを持つcontrol台帳だけを読む。
		const auto object = objectFrom( bytes) ;
		fields( object, {L"schema", L"lastUtcMillis", L"controls"}) ;
		// 保存された最高時刻を精度内の整数で読む。
		const auto savedUtc = numberField( object, L"lastUtcMillis") ;
		// 未知schemaと時計巻戻しを拒否する。
		if( textField( object, L"schema") != L"collector-campaign-controls-v1" ||
		   dayFor( savedUtc / 1000U).empty() || savedUtc < lastUtc) {
			throw std::invalid_argument( "wait ledger header") ;
		}

		// 最大320行を一回の更新で扱う。
		const auto rows = object.GetNamedArray( L"controls") ;
		// 保存集合自体が予算を超える場合は読む前に拒否する。
		if( rows.Size() > 320U) {
			throw std::invalid_argument( "wait control count") ;
		}

		// 全行を検証した後だけ更新する一時集合。
		std::map<std::wstring, Control> pending ;
		// Source groupの個数を独立に数える。
		std::size_t						groupCount{} ;
		// Request hashの個数を独立に数える。
		std::size_t						requestCount{} ;
		// 全controlの状態・hash・重複を固定順で調べる。
		for( const auto &value : rows) {
			// 一controlの有限保存行。
			const auto row = value.GetObject() ;
			fields( row, {L"key", L"group", L"request", L"observed", L"notBefore", L"completed",
						 L"needsReview", L"generation", L"job", L"started"}) ;
			// Hash入力となる完全key。
			const auto key = textField( row, L"key") ;
			// Requestとgroupの状態を別々に復号する。
			Control	   control ;
			control.group	   = textField( row, L"group") ;
			control.request	   = textField( row, L"request") ;
			control.observed   = numberField( row, L"observed") ;
			control.notBefore  = numberField( row, L"notBefore") ;
			control.completed  = numberField( row, L"completed") ;
			control.review	   = row.GetNamedBoolean( L"needsReview") ;
			control.generation = textField( row, L"generation") ;
			control.job		   = textField( row, L"job") ;
			control.started	   = numberField( row, L"started") ;
			// 期限は旧sourceが許可した9999年の上限まで保持する。
			if( !isToken( control.group) || control.observed == 0U || control.observed > savedUtc ||
			   control.completed > control.observed || control.notBefore > 253402300799999ULL ||
			   (control.notBefore > 4102444799999ULL && !control.review) ||
			   (!control.request.empty() && !isHash( control.request)) ||
			   key != (control.request.empty() ? L"g-" + control.group : L"r-" + control.request) ||
			   !pending.emplace( key, control).second) {
				throw std::invalid_argument( "wait control binding") ;
			}

			// 開始中のrequestだけが二つの元予約hashを保持する。
			if( (control.started == 0U && (!control.generation.empty() || !control.job.empty())) ||
			   (control.started != 0U &&
				(control.request.empty() || control.started > control.observed ||
				 !isHash( control.generation) || !isHash( control.job)))) {
				throw std::invalid_argument( "wait start intent") ;
			}

			// Group controlとrequest controlの上限を個別に確認する。
			if( control.request.empty()) {
				++groupCount ;
			} else {
				++requestCount ;
			}
		}

		// 一つのrequestの所属groupが消失しても新規扱いしない。
		for( const auto &entry : pending) {
			// Request行には同じgroup行が必須である。
			if( !entry.second.request.empty() && !pending.contains( L"g-" + entry.second.group)) {
				throw std::invalid_argument( "wait group missing") ;
			}
		}

		// 上限を超える新sourceを暗黙追加しない。
		if( groupCount > 20U || requestCount > 300U) {
			throw std::invalid_argument( "wait control limits") ;
		}

		controls = std::move( pending) ;
		lastUtc	 = savedUtc ;
		// 正規表現以外の保存byteを拒否する。
		if( encode() != bytes) {
			throw std::invalid_argument( "wait canonical") ;
		}
	}

	/** @brief 登録済み台帳の消失・変更を毎操作の前に照合します。
     * @return 検証成功0、欠損13またはI/O error。
     */
	[[nodiscard]] DWORD load()
	{
		// 保護handleから読む原本文。
		std::string body ;
		// 欠損と初回を同じ意味で扱わない存在flag。
		bool		found{} ;
		// 初期化後のmarker欠損を初回へ戻さない。
		if( (error = readEnvelope( *store, L"current/campaign-controls-marker-v1.json", body,
								 found)) != 0U ||
		   !found || body != "collector-campaign-controls-root-v1") {
			return error = error != 0U ? error : ERROR_INVALID_DATA ;
		}

		// 台帳だけが消えても待機を復活させない。
		if( (error = readEnvelope( *store, L"current/campaign-controls-v1.json", body, found)) !=
			   0U ||
		   !found) {
			return error = error != 0U ? error : ERROR_INVALID_DATA ;
		}

		decode( body) ;
		return ERROR_SUCCESS ;
	}

	/** @brief 制御の登録と更新を同じ保護fileへ保存します。
     * @return 保存成功0、上限13またはI/O error。
     */
	[[nodiscard]] DWORD save()
	{
		// 最大320 entryを永続化前にも確認する。
		if( controls.size() > 320U) {
			return error = ERROR_INVALID_DATA ;
		}

		// encodeとdecodeの同じ境界で個別上限・不整合を確認する。
		const auto body = encode() ;
		decode( body) ;
		return error = writeEnvelope( *store, L"current/campaign-controls-v1.json", body) ;
	}

	/** @brief 巻戻しと別threadからの操作を通信前に拒否します。
     * @param[in] utc UTC millisecond。
     * @param[in] steady 同じprocessの単調millisecond。
     * @return 二時計が前進している場合true。
     */
	[[nodiscard]] bool clockValid( const std::uint64_t utc, const std::uint64_t steady)
	{
		// 最初の保存失敗や拒否のcodeを後続操作で上書きしない。
		if( error != 0U) {
			return false ;
		}

		// UTC範囲はcoreの1970～2099年契約へ限定する。
		if( !ready || ownerThread != GetCurrentThreadId() || dayFor( utc / 1000U).empty() ||
		   utc > 4102444799999ULL || utc < lastUtc || utc < clockUtc || steady < lastSteady) {
			error = ERROR_INVALID_DATA ;
			return false ;
		}

		clockUtc   = utc ;
		lastSteady = steady ;
		return true ;
	}

	/** @brief 元予約の完全identityを確認します。
     * @param[in] request Callerが固定した非機密identity。
     * @return Groupと三hashが有限形式に一致した場合true。
     */
	[[nodiscard]] static bool requestValid( const CollectorWaitRequest &request)
	{
		return isToken( request.group) && isHash( request.requestKey) &&
			   isHash( request.generationKey) && isHash( request.jobKey) ;
	}

	/** @brief 旧source待機を形式変更せず同じstoreから読みます。
     * @param[in] group 組み込みgroup。
     * @param[in,out] control 期限と要確認だけを最大値で結合するgroup control。
     * @return 検証成功0、形式不正13またはI/O error。
     */
	[[nodiscard]] DWORD mergeLegacy( const std::wstring &group, Control &control)
	{
		// 初期二sourceの既存file名だけを再構成する。
		const std::wstring source = group == L"asus"	? L"ASUS_CATALOG"
									: group == L"intel" ? L"INTEL_ETHERNET_WINDOWS11"
														: L"" ;
		// 旧source対応がないgroupには仮のURLや待機を生成しない。
		if( source.empty()) {
			return ERROR_SUCCESS ;
		}

		// 旧collectorと同じ小文字SHA名。
		const auto path =
			std::filesystem::path( L"current") /
			(L"cooldown-" + hashOf( winrt::to_string( winrt::hstring( source))) + L".json") ;
		// 同じwriter下で読む旧envelope。
		std::string bytes ;
		// 初回欠損だけを待機なしとする。
		bool		found{} ;
		// I/O拒否を待機なしへ変換しない。
		if( (error = store->read( path, bytes, found)) != 0U || !found) {
			return error ;
		}

		// 旧schemaのhash envelopeを完全一致で検証する。
		const auto envelope = objectFrom( bytes) ;
		fields( envelope, {L"schema", L"body", L"sha256"}) ;
		// 旧bodyを有限UTF-8で取り出す。
		const auto body = winrt::to_string( envelope.GetNamedString( L"body")) ;
		// 原bodyのhash検査を省略しない。
		if( textField( envelope, L"schema") != L"dc-collector-envelope-v1" ||
		   hashOf( body) != textField( envelope, L"sha256")) {
			return error = ERROR_INVALID_DATA ;
		}

		// 生headerを持たない旧source control。
		const auto object = objectFrom( body) ;
		fields( object,
			   {L"schema", L"source", L"observedAt", L"nextAttemptAt", L"status", L"needsReview"}) ;
		// 旧台帳のUTC秒を精度内で読む。
		const auto observed = numberField( object, L"observedAt") ;
		// 旧台帳の絶対待機UTC秒。
		const auto next = numberField( object, L"nextAttemptAt") ;
		// 旧台帳が保存する二種類のHTTP拒否。
		const auto status = numberField( object, L"status") ;
		// 旧source・schema・期限の整合を検査する。
		if( textField( object, L"schema") != L"dc-collector-cooldown-v1" ||
		   textField( object, L"source") != source || observed == 0U || next < observed ||
		   next > 253402300799ULL || (status != 429U && status != 503U) ||
		   observed > clockUtc / 1000U) {
			return error = ERROR_INVALID_DATA ;
		}

		control.notBefore = std::max( control.notBefore, next * 1000U) ;
		control.review =
			control.review || object.GetNamedBoolean( L"needsReview") || next > 4102444799ULL ;
		return ERROR_SUCCESS ;
	}

	/** @brief 同じgroupに開始intentがあるか確認します。
     * @param[in] group 固定group。
     * @return 未回収開始intentが一つでもあればtrue。
     */
	[[nodiscard]] bool activeGroup( const std::wstring &group) const
	{
		return std::any_of( controls.begin(), controls.end(), [&]( const auto &entry) {
			return entry.second.group == group && entry.second.started != 0U ;
		}) ;
	}
} ;

/** @see local_collector_campaign.h */
LocalCollectorWaitLedger::LocalCollectorWaitLedger() : state_( std::make_unique<State>())
{
}

/** @see local_collector_campaign.h */
LocalCollectorWaitLedger::~LocalCollectorWaitLedger()
{
	// 待機台帳の借用解除でwriterやcore借用を解放しない。
	if( state_->store != nullptr) {
		state_->store->releaseWaitLedger( state_.get()) ;
	}
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorWaitLedger::initialize( LocalCollectorStateStore &store,
										   const std::uint64_t		 utcMillis,
										   const std::uint64_t		 steadyMillis)
{
	try {
		// 一instanceの初期化や借用先を途中で置き換えない。
		if( state_->store != nullptr || !store.isWritable()) {
			return state_->error = state_->store != nullptr ? ERROR_BUSY : ERROR_INVALID_PARAMETER ;
		}

		// Workspaceの専用store内にだけcontrolを作る。
		const auto parent = (std::filesystem::current_path() / L"work/state").lexically_normal() ;
		// root自身と親方向を除く相対値。
		const auto relative = store.root().lexically_relative( parent) ;
		// 公開clock契約と専用rootを台帳作成前に確認する。
		if( relative.empty() || relative == L"." ||
		   std::any_of( relative.begin(), relative.end(),
					   []( const auto &part) { return part == L".." ; }) ||
		   dayFor( utcMillis / 1000U).empty() || utcMillis > 4102444799999ULL) {
			return state_->error = ERROR_INVALID_DATA ;
		}

		// 一つの待機監督だけをstoreへ結合する。
		if( (state_->error = store.borrowWaitLedger( state_.get())) != 0U) {
			return state_->error ;
		}

		state_->store		  = &store ;
		state_->ownerThread	  = GetCurrentThreadId() ;
		state_->clockUtc	  = utcMillis ;
		state_->lastSteady	  = steadyMillis ;
		state_->initialSteady = steadyMillis ;
		// Markerと台帳の存在を独立に照合する。
		std::string marker ;
		// Markerだけが消えても初回としない。
		bool		hasMarker{} ;
		// 読み取った保存本文。
		std::string body ;
		// 本文だけが消えても初回としない。
		bool		hasBody{} ;
		// 片側欠損と未知markerを通信前に拒否する。
		if( (state_->error = readEnvelope( store, L"current/campaign-controls-marker-v1.json", marker,
										 hasMarker)) != 0U ||
		   (state_->error =
				readEnvelope( store, L"current/campaign-controls-v1.json", body, hasBody)) != 0U ||
		   hasMarker != hasBody || (hasMarker && marker != "collector-campaign-controls-root-v1")) {
			return state_->error = state_->error != 0U ? state_->error : ERROR_INVALID_DATA ;
		}

		// 既存controlを新たな空台帳で置き換えない。
		if( hasBody) {
			state_->decode( body) ;
			// 台帳より前のclockで起動しない。
			if( utcMillis < state_->lastUtc) {
				return state_->error = ERROR_INVALID_DATA ;
			}
		} else {
			state_->lastUtc = utcMillis ;
			// Marker先行の保存窓は片側欠損の明示拒否として残す。
			if( (state_->error = writeEnvelope( store, L"current/campaign-controls-marker-v1.json",
											  "collector-campaign-controls-root-v1")) != 0U ||
			   state_->save() != 0U) {
				return state_->error ;
			}
		}

		state_->ready = true ;
		return ERROR_SUCCESS ;
	} catch( ...) {
		return state_->error = ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorWaitLedger::check( const CollectorWaitRequest &request,
									  const std::uint64_t		  utcMillis,
									  const std::uint64_t		  steadyMillis,
									  CollectorWaitDecision		 &decision)
{
	decision = CollectorWaitDecision::NEEDS_REVIEW ;
	try {
		// 別thread・不正identity・時計巻戻しの操作を拒否する。
		if( !state_->clockValid( utcMillis, steadyMillis) || !State::requestValid( request)) {
			return state_->error = state_->error != 0U ? state_->error : ERROR_INVALID_DATA ;
		}

		// 保存controlを失った場合に許可を返さない。
		if( state_->load() != 0U) {
			return state_->error ;
		}

		// Groupの保存済み最大待機を原値のまま扱う。
		State::Control group ;
		// 未登録groupだけは新しい空制御へできる。
		const auto	   saved = state_->controls.find( L"g-" + request.group) ;
		// 既存groupの待機・完了時刻を維持する。
		if( saved != state_->controls.end()) {
			group = saved->second ;
		}

		// 新sourceと旧source待機を最大期限・要確認で結合する。
		if( state_->mergeLegacy( request.group, group) != 0U) {
			return state_->error ;
		}

		// 旧sourceの最大期限とreviewを新台帳へ取り込み、旧file消失で解除しない。
		if( (saved == state_->controls.end() && (group.notBefore != 0U || group.review)) ||
		   (saved != state_->controls.end() &&
			(group.notBefore != saved->second.notBefore || group.review != saved->second.review))) {
			group.group								= request.group ;
			group.observed							= utcMillis ;
			state_->controls[L"g-" + request.group] = group ;
			state_->lastUtc							= utcMillis ;
			// 取り込み失敗を開始可能と扱わない。
			if( state_->save() != 0U) {
				return state_->error ;
			}
		}

		// 同じ公開requestの待機をartifactが変わっても使用する。
		const auto row = state_->controls.find( L"r-" + request.requestKey) ;
		// 同じrequestを別groupとして再登録して待機を抜けない。
		if( row != state_->controls.end() && row->second.group != request.group) {
			return state_->error = ERROR_INVALID_DATA ;
		}

		// 未回収開始intentは期限の経過だけで解除しない。
		if( state_->activeGroup( request.group)) {
			decision = CollectorWaitDecision::RECOVERY_REQUIRED ;
			return ERROR_SUCCESS ;
		}

		// Reviewは過去の成功や時計経過から自動解除しない。
		if( group.review || (row != state_->controls.end() && row->second.review)) {
			decision = CollectorWaitDecision::NEEDS_REVIEW ;
			return ERROR_SUCCESS ;
		}

		// Group完了後の実時間間隔は同じprocessの単調時計でも確認する。
		const auto finished = state_->completedSteady.find( request.group) ;
		// 再起動直後には旧完了groupだけへ保守的な二秒待機を置く。
		const auto steadyBase =
			finished == state_->completedSteady.end() ? state_->initialSteady : finished->second ;
		// UTCと単調時計の双方で最小二秒と待機期限を守る。
		if( utcMillis < group.notBefore ||
		   (row != state_->controls.end() && utcMillis < row->second.notBefore) ||
		   (group.completed != 0U &&
			(utcMillis < group.completed || utcMillis - group.completed < 2000U ||
			 steadyMillis - steadyBase < 2000U))) {
			decision = CollectorWaitDecision::WAIT ;
			return ERROR_SUCCESS ;
		}

		decision = CollectorWaitDecision::READY ;
		return ERROR_SUCCESS ;
	} catch( ...) {
		return state_->error = ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorWaitLedger::begin( const CollectorWaitRequest &request,
									  const std::uint64_t		  utcMillis,
									  const std::uint64_t		  steadyMillis)
{
	try {
		// 開始可否の再計算結果だけを開始intentへ変換する。
		CollectorWaitDecision decision{} ;
		// 別group進行は許すが、未回収・待機・reviewを開始しない。
		if( check( request, utcMillis, steadyMillis, decision) != 0U) {
			return state_->error ;
		}

		// 通常待機は台帳errorにせず後の監督判断へ返す。
		if( decision != CollectorWaitDecision::READY) {
			return ERROR_RETRY ;
		}

		// 新規のgroup controlにも公開groupを保持する。
		auto &group	   = state_->controls[L"g-" + request.group] ;
		group.group	   = request.group ;
		group.observed = utcMillis ;
		// 開始保存時に旧最大期限を失わない。
		if( state_->mergeLegacy( request.group, group) != 0U) {
			return state_->error ;
		}

		// 一つの公開requestに元予約の開始identityを結合する。
		auto &control	   = state_->controls[L"r-" + request.requestKey] ;
		control.group	   = request.group ;
		control.request	   = request.requestKey ;
		control.observed   = utcMillis ;
		control.generation = request.generationKey ;
		control.job		   = request.jobKey ;
		control.started	   = utcMillis ;
		state_->lastUtc	   = utcMillis ;
		return state_->save() ;
	} catch( ...) {
		return state_->error = ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorWaitLedger::finish( const CollectorWaitRequest	  &request,
									   const CollectorWaitObservation &observation,
									   const std::uint64_t			   utcMillis,
									   const std::uint64_t			   steadyMillis)
{
	try {
		// 不明なstatus・期限・clockから待機更新を作らない。
		if( !state_->clockValid( utcMillis, steadyMillis) || !State::requestValid( request) ||
		   observation.status > 599U || (observation.status != 0U && observation.status < 100U) ||
		   observation.retryAfterUtcMillis > 253402300799999ULL ||
		   (observation.successful && (observation.status != 200U && observation.status != 304U)) ||
		   (observation.successful && (observation.needsReview || observation.challenge))) {
			return state_->error = state_->error != 0U ? state_->error : ERROR_INVALID_DATA ;
		}

		// 完了直前も欠損や保存改変を確認する。
		if( state_->load() != 0U) {
			return state_->error ;
		}

		// 別generationの完了が同じrequestを上書きしない。
		const auto row = state_->controls.find( L"r-" + request.requestKey) ;
		// 保存開始intentへの一致は応答観測より先に検査する。
		if( row == state_->controls.end() || row->second.group != request.group ||
		   row->second.started == 0U || row->second.generation != request.generationKey ||
		   row->second.job != request.jobKey || utcMillis < row->second.started) {
			return state_->error = ERROR_INVALID_DATA ;
		}

		// Requestとgroupへ同じ完了時刻を反映する。
		auto &control = row->second ;
		// Requestが持つgroupはdecodeで存在確認済みである。
		auto &group		 = state_->controls.at( L"g-" + request.group) ;
		control.observed = utcMillis ;
		group.observed	 = utcMillis ;
		group.completed	 = utcMillis ;
		// 正常鮮度も失敗待機もrequestへ最低24時間を保持する。
		control.notBefore = std::max( control.notBefore, utcMillis + 86400000U) ;
		control.review	  = control.review || observation.needsReview ;
		// 明示Retry-AfterとHTTP限流をgroup全体へ結合する。
		if( observation.status == 429U || observation.status == 503U) {
			group.notBefore =
				std::max( {group.notBefore, utcMillis + 86400000U, observation.retryAfterUtcMillis}) ;
			group.review = group.review || observation.needsReview ||
						   observation.retryAfterUtcMillis > 4102444799999ULL ;
		}

		// Challengeと403は時計が進んでも自動解除しない。
		if( observation.status == 403U || observation.challenge) {
			group.review = true ;
		}

		control.generation.clear() ;
		control.job.clear() ;
		control.started = 0U ;
		state_->lastUtc = utcMillis ;
		// 待機を永続化するまで同groupの間隔基準を解放しない。
		if( state_->save() != 0U) {
			return state_->error ;
		}

		state_->completedSteady[request.group] = steadyMillis ;
		return ERROR_SUCCESS ;
	} catch( ...) {
		return state_->error = ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorWaitLedger::recoverInterrupted( const CollectorWaitRequest &request,
												   const std::uint64_t		   utcMillis,
												   const std::uint64_t		   steadyMillis)
{
	// 応答が保存されていない場合だけ未知失敗の24時間待機へ閉じる。
	return finish( request, {}, utcMillis, steadyMillis) ;
}

/** @see local_collector_campaign.h */
DWORD LocalCollectorWaitLedger::lastError() const noexcept
{
	return state_->error ;
}

/** @see local_collector_campaign.h */
bool parseCollectorWaitSnapshot( const std::string_view bytes, CollectorWaitSnapshot &snapshot)
{
	snapshot = {} ;
	try {
		LocalCollectorWaitLedger::State decoded ;	// 既存と同じ一つのdecoder。
		decoded.decode( bytes) ;
		snapshot = {decoded.lastUtc, std::move( decoded.controls)} ;
		return true ;
	} catch( ...) {
		return false ;
	}
}

/** @see local_collector_campaign.h */
bool encodeCollectorWaitSnapshot( const CollectorWaitSnapshot &snapshot, std::string &bytes)
{
	bytes.clear() ;
	try {
		// 過大typed入力をJSON化する前に拒否する。
		if( snapshot.controls.size() > 320U) {
			return false ;
		}

		// 文字列も単一controlの有限形式に限定する。
		for( const auto &[key, row] : snapshot.controls) {
			// 組み込みtokenと完全hash以外を保存しない。
			if( !isToken( row.group) || key.size() > 98U ||
			   (!row.request.empty() && !isHash( row.request)) ||
			   (!row.generation.empty() && !isHash( row.generation)) ||
			   (!row.job.empty() && !isHash( row.job))) {
				return false ;
			}
		}

		LocalCollectorWaitLedger::State encoded ;	// v1と同じ保存表現。
		encoded.lastUtc						 = snapshot.lastUtc ;
		encoded.controls					 = snapshot.controls ;
		const auto						body = encoded.encode() ;	// 型矛盾も同じdecoderで拒否する。
		LocalCollectorWaitLedger::State checked ;					// 復号検査用の独立状態。
		checked.decode( body) ;
		bytes = body ;
		return true ;
	} catch( ...) {
		return false ;
	}
}

/** @see local_collector_campaign.h */
bool prepareCollectorWaitSettlement( const CollectorWaitSnapshot	   &before,
									const CollectorWaitRequest	   &request,
									const CollectorWaitObservation &observation,
									const std::uint64_t started, const std::uint64_t finished,
									const std::uint64_t accepted, const std::uint64_t now,
									const bool missingStart, CollectorWaitSnapshot &after)
{
	after = {} ;
	std::string checked ;	// Typed入力にも通常保存と同じ検査を要求する。
	// 元応答の時刻と現在時計を別々に検査する。
	if( !encodeCollectorWaitSnapshot( before, checked) || !isToken( request.group) ||
	   !isHash( request.requestKey) || !isHash( request.generationKey) || !isHash( request.jobKey) ||
	   dayFor( started / 1000U).empty() || started > finished || finished > accepted ||
	   accepted > now || now < before.lastUtc || now > 4102444799999ULL ||
	   observation.status > 599U || (observation.status != 0U && observation.status < 100U) ||
	   observation.retryAfterUtcMillis > 253402300799999ULL ||
	   (observation.successful && (observation.status != 200U && observation.status != 304U)) ||
	   (observation.successful && (observation.needsReview || observation.challenge)) ||
	   (missingStart && (observation.successful || observation.status != 0U ||
						 observation.retryAfterUtcMillis != 0U || observation.needsReview ||
						 observation.challenge))) {
		return false ;
	}

	auto	   pending = before ;												// 元tableを変更しない更新後の複製。
	const auto row	   = pending.controls.find( L"r-" + request.requestKey) ;	// 元開始intent。
	// 完了済みや別予約の開始intentを上書きしない。
	if( row != pending.controls.end() &&
	   (row->second.group != request.group ||
		(row->second.started != 0U &&
		 (row->second.generation != request.generationKey || row->second.job != request.jobKey ||
		  row->second.started != started)))) {
		return false ;
	}

	// 実応答には開始intentを必須とする。
	if( !missingStart && (row == pending.controls.end() || row->second.started == 0U)) {
		return false ;
	}

	// 別requestが同groupで実行中なら中断intentを捏造しない。
	for( const auto &[key, control] : pending.controls) {
		// 元要求以外の稼働枠を消さない。
		if( key != L"r-" + request.requestKey && control.group == request.group &&
		   control.started != 0U) {
			return false ;
		}
	}

	auto &group		 = pending.controls[L"g-" + request.group] ;		// Groupの旧期限を保持する。
	auto &control	 = pending.controls[L"r-" + request.requestKey] ;	// 中断予約だけなら新規に作る。
	group.group		 = request.group ;
	control.group	 = request.group ;
	control.request	 = request.requestKey ;
	pending.lastUtc	 = std::max( before.lastUtc, accepted) ;
	group.observed	 = pending.lastUtc ;
	control.observed = pending.lastUtc ;
	group.completed	 = std::max( group.completed, finished) ;
	control.notBefore = std::max( control.notBefore, finished + 86400000U) ;
	control.review =
		control.review || observation.needsReview || control.notBefore > 4102444799999ULL ;
	// Retry-Afterはgroup全体へ最大値で結合する。
	if( observation.status == 429U || observation.status == 503U) {
		group.notBefore =
			std::max( {group.notBefore, finished + 86400000U, observation.retryAfterUtcMillis}) ;
		group.review =
			group.review || observation.needsReview || group.notBefore > 4102444799999ULL ;
	}

	group.review = group.review || observation.status == 403U || observation.challenge ;
	control.generation.clear() ;
	control.job.clear() ;
	control.started = 0U ;
	// Table上限・key・group欠損は保存前にも同じcodecで検査する。
	if( !encodeCollectorWaitSnapshot( pending, checked)) {
		return false ;
	}

	after = std::move( pending) ;
	return true ;
}

} // namespace drivercrate
