//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_input.cpp
 * @brief 元manifestの全scopeから専用v3入力identityを非保存で構築します。
 * @version 01.02.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  全共有jobの非保存v3入力と専用Gを実装。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  保存入力の全再構築・非canonical拒否を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  元保存入力から変更不能jobを一括準備。
 * Ver.01.02.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 新root／予約の保存入口は後続です。秘密URLやEULAを扱いません。
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_projected_input.h"

#include "platform/official_file_verifier.h"

#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <tuple>
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

/// 既存storeの本文上限を越えるidentityを予約へ渡さない。
constexpr std::size_t MAXIMUM_INPUT_BYTES = 768U * 1024U ;

/**
 * @brief SHA-256の小文字ASCII固定表現です。
 * @param[in] value 検査対象のUTF-16 view。同期呼出し中だけ借用する。
 * @return 64桁小文字ASCII hexの場合true。それ以外はfalse。
 */
[[nodiscard]] bool	  hashName( const std::wstring_view value) noexcept
{
	return value.size() == 64U && std::all_of( value.begin(), value.end(), []( const wchar_t ch) {
			   return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ;
		   }) ;
}

/**
 * @brief 元日付を暦日に検証し、文字列の丸めを避けます。
 * @param[in] value 検査対象のUTF-16 view。同期呼出し中だけ借用する。
 * @return 1970年から2099年の実在するYYYYMMDDならtrue。表記・暦日違反はfalse。
 */
[[nodiscard]] bool validDay( const std::wstring_view value) noexcept
{
	// 固定8文字以外を数値化しない。
	if( value.size() != 8U || !std::all_of( value.begin(), value.end(), []( const wchar_t ch) {
		   return ch >= L'0' && ch <= L'9' ;
	   })) {
		return false ;
	}

	std::uint32_t year{} ;	// 四桁の元年。
	std::uint32_t month{} ;	// 二桁の元月。
	std::uint32_t day{} ;	// 二桁の元日。
	// C++ localeや例外を介さず8桁だけを解釈する。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		auto *part = index < 4U ? &year : index < 6U ? &month : &day ;	// 現在の要素。
		*part	   = *part * 10U + static_cast<std::uint32_t>( value[index] - L'0') ;
	}

	return year >= 1970U && year <= 2099U &&
		   std::chrono::year_month_day( std::chrono::year( static_cast<int>( year)),
									   std::chrono::month( month), std::chrono::day( day))
			   .ok() ;
}

/**
 * @brief Canonical JSONへ有限Unicode stringを追加します。
 * @param[in,out] object 挿入先のJSON object。既存の同名fieldは置き換える。
 * @param[in] name 固定fieldの非null、NUL終端UTF-16名。同期中だけ借用する。
 * @param[in] value 保存するUnicode文字列の借用view。JSON値へcopyする。
 */
void putText( JsonObject &object, const wchar_t *name, const std::wstring_view value)
{
	object.Insert( name, JsonValue::CreateStringValue( winrt::hstring( value))) ;
}

/**
 * @brief 53bitを越えない検査済み整数を追加します。
 * @param[in,out] object 挿入先のJSON object。既存の同名fieldは置き換える。
 * @param[in] name 固定fieldの非null、NUL終端UTF-16名。同期中だけ借用する。
 * @param[in] value 2の53乗未満であることを呼出し側が検査済みの整数。
 */
void putNumber( JsonObject &object, const wchar_t *name, const std::uint64_t value)
{
	object.Insert( name, JsonValue::CreateNumberValue( static_cast<double>( value))) ;
}

/**
 * @brief 元manifestとsource registryを再解釈可能な所有行へ符号化します。
 * @param[in] sources 元registry全件の借用集合。入力順は変更しない。
 * @return Source/resource順へ並べた所有JSON配列。
 */
JsonArray sourcesObject( const std::vector<CollectorCampaignSource> &sources)
{
	std::vector<CollectorCampaignSource> ordered = sources ;	// 入力列挙順だけの世代差を作らない。
	std::sort( ordered.begin(), ordered.end(), []( const auto &left, const auto &right) {
		return std::tie( left.sourceId, left.resourceId) <
			   std::tie( right.sourceId, right.resourceId) ;
	}) ;
	JsonArray values ;	// 正規化済みsource全件。
	// 未使用sourceも元の組み込みregistryを再検証できるよう保持する。
	for( const auto &source : ordered) {
		JsonObject row ;	// 一つの組み込み契約像。
		putText( row, L"source", source.sourceId) ;
		putText( row, L"resource", source.resourceId) ;
		putText( row, L"group", source.rateLimitGroup) ;
		putText( row, L"parser", source.parserRevision) ;
		putNumber( row, L"maximum", source.maximumResponseBytes) ;
		values.Append( row) ;
	}

	return values ;
}

/**
 * @brief 全対象scopeの暗号学的結合とparser版を一job行へ符号化します。
 * @param[in] job 今回の固定scopeとsource条件。同期呼出し中だけ借用する。
 * @return 全scopeとparser条件を保持する所有JSON object。
 */
JsonObject jobObject( const CollectorProjectedJobInput &job)
{
	JsonObject row ;	// 元共有jobと同順の一行。
	putText( row, L"job", job.jobKey) ;
	putText( row, L"request", job.requestKey) ;
	putText( row, L"cache", job.cacheBinding) ;
	putText( row, L"scope", job.scopeSha256) ;
	putText( row, L"source", job.source.sourceId) ;
	putText( row, L"resource", job.source.resourceId) ;
	putText( row, L"group", job.source.rateLimitGroup) ;
	putText( row, L"provider", job.providerId) ;
	putText( row, L"policy", job.policyId) ;
	putText( row, L"sourceParser", job.source.parserRevision) ;
	putText( row, L"recordParser", job.recordParser) ;
	putText( row, L"identityParser", job.identityParser) ;
	putText( row, L"matchingRule", job.matchingRule) ;
	putText( row, L"locator", job.publicLocator) ;
	putText( row, L"locale", job.locale) ;
	putNumber( row, L"page", job.page) ;
	putNumber( row, L"maximum", job.source.maximumResponseBytes) ;
	putNumber( row, L"targets", job.targets.size()) ;
	JsonArray slices ;	// 新scopeの一つ以上16個以下のslice key。
	// 全sliceをjob固有の順序で入力へ結合する。
	for( const auto &slice : job.slices) {
		slices.Append( JsonValue::CreateStringValue( winrt::hstring( slice.key))) ;
	}

	row.Insert( L"slices", slices) ;
	return row ;
}

} // namespace

/** @see local_collector_projected_input.h */
bool makeCollectorProjectedCampaignIdentity( const CollectorProjectedCampaignDefinition &definition,
											const std::wstring_view						startDay,
											CollectorProjectedCampaignIdentity		   &identity)
{
	identity = {} ;
	try {
		// 無効な日・元artifact・過大manifestを保存用identityへ変換しない。
		if( !validDay( startDay) || !hashName( definition.artifactSha256) ||
		   definition.manifestBytes.empty() || definition.manifestBytes.size() > 256U * 1024U ||
		   definition.manifestBytes.find( '\0') != std::string::npos) {
			return false ;
		}

		CollectorCampaignManifest manifest ;	// 元manifestを組み込みregistryで全件解析する。
		// 元共有jobが空なら永続予約を作れない。
		if( !parseCollectorCampaignManifest( definition.manifestBytes, definition.sources,
										   manifest) ||
		   manifest.jobs.empty()) {
			return false ;
		}

		CollectorProjectedCampaignIdentity result ;	// 全検査後だけcallerへ返す。
		result.jobs.reserve( manifest.jobs.size()) ;
		JsonArray jobs ;	// 元job順の全scope binding。
		// すべてのjobの公式経路を検査し、一つの未知sourceも見逃さない。
		for( std::size_t index = 0U; index < manifest.jobs.size(); ++index) {
			CollectorProjectedJobInput job ;	// 現jobの全公開target。
			// 初回失敗で部分世代を返さない。
			if( !makeCollectorProjectedJobInput( manifest, index, definition.artifactSha256, job)) {
				return false ;
			}

			jobs.Append( jobObject( job)) ;
			result.jobs.push_back( std::move( job)) ;
		}

		JsonObject root ;	// v2入力と名前・G導出を共有しない専用schema。
		putText( root, L"schema", L"collector-campaign-input-v3") ;
		putText( root, L"profile", L"METADATA_PROJECTION_V1") ;
		putText( root, L"day", startDay) ;
		putText( root, L"artifact", definition.artifactSha256) ;
		root.Insert( L"manifest",
					JsonValue::CreateStringValue( winrt::to_hstring( definition.manifestBytes))) ;
		putText( root, L"manifestSha256", manifest.manifestSha256) ;
		root.Insert( L"sources", sourcesObject( definition.sources)) ;
		root.Insert( L"jobs", jobs) ;
		// 実保存候補byte。
		result.canonicalInput = winrt::to_string( root.Stringify()) ;
		// 旧storeの本文上限を超える場合、切詰めず全体拒否する。
		if( result.canonicalInput.empty() || result.canonicalInput.size() > MAXIMUM_INPUT_BYTES ||
		   computeBytesSha256( result.canonicalInput, result.inputSha256) != 0U ||
		   !hashName( result.inputSha256)) {
			return false ;
		}

		const auto generationInput = "schema-v3\n" +
									 winrt::to_string( winrt::hstring( result.inputSha256)) +
									 "\n" ;	// ADR 0220の専用G domain。
		// 元v2のday・manifest・artifact直結算法へfallbackしない。
		if( computeBytesSha256( generationInput, result.generationKey) != 0U ||
		   !hashName( result.generationKey)) {
			return false ;
		}

		identity = std::move( result) ;
		return true ;
	} catch( ...) {
		identity = {} ;
		return false ;
	}
}

/** @see local_collector_projected_input.h */
bool parseCollectorProjectedCampaignIdentity( const std::string_view				   canonicalInput,
											 CollectorProjectedCampaignDefinition &definition,
											 CollectorProjectedCampaignIdentity	  &identity)
{
	definition = {} ;
	identity   = {} ;
	try {
		// Parseの前に保存本文の有限境界を確認する。
		if( canonicalInput.empty() || canonicalInput.size() > MAXIMUM_INPUT_BYTES ||
		   canonicalInput.find( '\0') != std::string_view::npos) {
			return false ;
		}

		const auto root = JsonObject::Parse( winrt::to_hstring( canonicalInput)) ;	// 元保存像。
		CollectorProjectedCampaignDefinition decoded ;								// 全照合後だけ公開する入力。
		decoded.manifestBytes  = winrt::to_string( root.GetNamedString( L"manifest")) ;
		decoded.artifactSha256 = root.GetNamedString( L"artifact") ;
		const auto sources	   = root.GetNamedArray( L"sources") ;	// 有限registry。
		// 無制限の保存配列を展開しない。
		if( sources.Size() == 0U || sources.Size() > 64U) {
			return false ;
		}

		// 残りのfieldと順序はbuilderの全再符号化で検査する。
		for( const auto &value : sources) {
			const auto row	   = value.GetObject() ;				// 組み込み契約の保存像。
			const auto maximum = row.GetNamedNumber( L"maximum") ;	// 狭小化前の元数値。
			// 公式metadata本文の範囲外や小数を整数へ丸めない。
			if( !std::isfinite( maximum) || maximum < 1.0 || maximum > 8.0 * 1024.0 * 1024.0 ||
			   std::floor( maximum) != maximum) {
				return false ;
			}

			decoded.sources.push_back( {std::wstring( row.GetNamedString( L"source")),
									   std::wstring( row.GetNamedString( L"resource")),
									   std::wstring( row.GetNamedString( L"group")),
									   std::wstring( row.GetNamedString( L"parser")),
									   static_cast<std::uint64_t>( maximum)}) ;
		}

		CollectorProjectedCampaignIdentity rebuilt ;	// 全scope・revisionを元定義で再計算する。
		// 未知・重複・欠損propertyも最終実byte比較で拒否する。
		if( !makeCollectorProjectedCampaignIdentity(
			   decoded, std::wstring_view( root.GetNamedString( L"day")), rebuilt) ||
		   rebuilt.canonicalInput != canonicalInput) {
			return false ;
		}

		definition = std::move( decoded) ;
		identity   = std::move( rebuilt) ;
		return true ;
	} catch( ...) {
		definition = {} ;
		identity   = {} ;
		return false ;
	}
}

/** @see local_collector_projected_input.h */
bool prepareCollectorProjectedCampaign(
	const std::string_view canonicalInput, const std::wstring_view expectedInputSha256,
	const std::wstring_view expectedGenerationKey, const std::wstring_view currentArtifactSha256,
	const std::span<const CollectorCampaignSource>			   builtInSources,
	std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	prepared.reset() ;
	try {
		// 元保存入力の全再構築に失敗した場合、部分jobを返さない。
		CollectorProjectedCampaignDefinition decoded ;	// 保存内の公開定義。
		CollectorProjectedCampaignIdentity	 rebuilt ;	// 元manifestから再計算した全job。
		// 元入力・現artifact・固定registryの基本結合を全て確認する。
		if( !hashName( expectedInputSha256) || !hashName( expectedGenerationKey) ||
		   !hashName( currentArtifactSha256) || builtInSources.empty() ||
		   !parseCollectorProjectedCampaignIdentity( canonicalInput, decoded, rebuilt) ||
		   rebuilt.inputSha256 != expectedInputSha256 ||
		   rebuilt.generationKey != expectedGenerationKey ||
		   decoded.artifactSha256 != currentArtifactSha256 ||
		   decoded.sources.size() != builtInSources.size()) {
			return false ;
		}

		// 保存されたregistryだけを新しい通信許可へ使わない。
		for( const auto &source : decoded.sources) {
			std::size_t matches{} ;	// 組み込み側の完全一致件数。
			// Source IDだけが同じでresourceや上限が違う場合を拒否する。
			for( const auto &builtIn : builtInSources) {
				// 同一sourceの全resource／parser／予算を揃える。
				if( source.sourceId == builtIn.sourceId && source.resourceId == builtIn.resourceId &&
				   source.rateLimitGroup == builtIn.rateLimitGroup &&
				   source.parserRevision == builtIn.parserRevision &&
				   source.maximumResponseBytes == builtIn.maximumResponseBytes) {
					++matches ;
				}
			}

			// 重複・差替えたsourceで準備を続けない。
			if( matches != 1U) {
				return false ;
			}
		}

		std::vector<CollectorPreparedProjectedJob> jobs ;	// 元入力順の所有job。
		jobs.reserve( rebuilt.jobs.size()) ;
		// 旧aggregateを変更不能型のprivate所有値へ移す。
		for( auto &job : rebuilt.jobs) {
			jobs.push_back( CollectorPreparedProjectedJob( std::move( job))) ;
		}

		prepared.reset( new CollectorPreparedProjectedCampaign(
			std::move( jobs), std::move( rebuilt.inputSha256), std::move( rebuilt.generationKey))) ;
		return true ;
	} catch( ...) {
		prepared.reset() ;
		return false ;
	}
}
} // namespace drivercrate
