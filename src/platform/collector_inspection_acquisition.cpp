//------------------------------------------------------------------------------
/**
 * @file collector_inspection_acquisition.cpp
 * @brief 台帳起点の実HTML確認と一回payload取得の共通接続。
 * @version 01.07.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  外部定義の静的導線と共通生存取得を接続。
 * Ver.01.01.00 Shunji Ogawa  2026/10/23  同原page観測と明示予算・公開hash・確認本文固定を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/23  実完全PAGEの同run有限共有とjob別再確認を追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/23  重複照会中の停止を未取得へ読み替えない保持条件へ修正。
 * Ver.01.03.00 Shunji Ogawa  2026/10/25  原byteと原SHAを維持した限定末尾診断コメント比較を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/11/04  定義候補を同native metadataへ結ぶ取得を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/11/04  通常resolver・Catalog row/OS・現在EULAの同native照合を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/11/05  NVIDIA同APIの原release再照合と規約未対応拒否を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/11/05  独立静的規約の原文書・公式リンクと既存同意を共通接続。
 * </pre>
 *
 * @note 同期収集worker専用。公開bool・研究hashで公式取得根拠を復元しない。
 * @see docs/adr/0280-collector-scoped-inspection-acquisition.md
 */
//------------------------------------------------------------------------------
#include "platform/collector_inspection_acquisition.h"
#include "platform/collector_definition_request.h"
#include "platform/nvidia_collector_metadata.h"
#include "core/official_source_policy.h"
#include "platform/official_static_record_parser.h"
#include "platform/official_file_verifier.h"
#include "platform/official_release_metadata.h"
#include "platform/official_html_terms.h"
#include "platform/signed_index_acquisition_descriptor_internal.h"
#include <algorithm>
#include <array>
#include <utility>
#include <wincrypt.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>

namespace drivercrate {

/** @brief 私有scopeだけが作る全bindingと一方向の失効状態です。 */
struct CollectorRunPageLifetime {
	/// 元parentの固定run識別子です。
	std::wstring										   runId ;
	/// 将来callerが検証して固定する元native leaseです。
	std::uint64_t										   parentLease{} ;
	/// 将来callerが監督する元child identityです。
	std::uint64_t										   childProcess{} ;
	/// 元runの全固定入力hashを順序付きで保持します。
	std::vector<std::wstring>							   inputHashes ;
	/// 元runの固定plan hashです。
	std::wstring										   planHash ;
	/// 延長しない単調期限です。
	std::chrono::steady_clock::time_point				   deadline ;
	/// 停止したchild等の親照会です。
	HttpCancellationCallback							   cancellation ;
	/// 空は実時計、非空は専用fixture時計です。
	std::function<std::chrono::steady_clock::time_point()> now ;
	/// 最後の確認単調時刻です。時計後退を拒否します。
	std::chrono::steady_clock::time_point				   lastNow{} ;
	/// 一度falseになれば再開しない元scopeの生存です。
	bool												   active{} ;
} ;

/** @see collector_inspection_acquisition.h */
CollectorRunPageProof::CollectorRunPageProof(
	const std::shared_ptr<CollectorRunPageLifetime> &lifetime,
	const CollectorInspectionSource &source, std::vector<std::byte> raw, std::wstring html,
	CollectorInspectionPageObservation observation, CollectorHttpTransferObservation transfer)
	: lifetime_( lifetime), rootUrl_( source.rootUrl), rootHost_( source.rootHost),
	  raw_( std::move( raw)), html_( std::move( html)), observation_( std::move( observation)),
	  transfer_( std::move( transfer))
{
}

/** @see collector_inspection_acquisition.h */
CollectorRunPageScope::CollectorRunPageScope(
	std::wstring runId, std::uint64_t parentLease, std::uint64_t childProcess,
	std::vector<std::wstring> inputHashes, std::wstring planHash,
	std::chrono::steady_clock::time_point deadline, HttpCancellationCallback cancellation,
	std::function<std::chrono::steady_clock::time_point()> now)
	: lifetime_( std::make_shared<CollectorRunPageLifetime>())
{
	// 全結合値を同じ私有lifetimeへ一度だけ所有させます。
	lifetime_->runId		= std::move( runId) ;
	lifetime_->parentLease	= parentLease ;
	lifetime_->childProcess = childProcess ;
	lifetime_->inputHashes	= std::move( inputHashes) ;
	lifetime_->planHash		= std::move( planHash) ;
	lifetime_->deadline		= deadline ;
	lifetime_->cancellation = std::move( cancellation) ;
	lifetime_->now			= std::move( now) ;
	// Hash群の要素は順序付きで固定し、欠損した入力を暗黙補完しません。
	const auto hashValid = []( std::wstring_view hash) {
		return hash.size() == 64U &&
			   hash.find_first_not_of( L"0123456789abcdef") == std::wstring_view::npos ;
	} ;
	lifetime_->active = !lifetime_->runId.empty() && lifetime_->runId.size() <= 128U &&
						parentLease != 0U && childProcess != 0U &&
						!lifetime_->inputHashes.empty() && lifetime_->inputHashes.size() <= 32U &&
						hashValid( lifetime_->planHash) &&
						std::ranges::all_of( lifetime_->inputHashes, hashValid) ;
}

/** @see collector_inspection_acquisition.h */
CollectorRunPageScope::~CollectorRunPageScope()
{
	finish() ;
}

/** @see collector_inspection_acquisition.h */
void CollectorRunPageScope::finish() noexcept
{
	lifetime_->active = false ;
	pages_.clear() ;
	rawBytes_ = 0U ;
}

/** @see collector_inspection_acquisition.h */
bool CollectorRunPageScope::checkpoint() noexcept
{
	try {
		const auto now = lifetime_->now ? lifetime_->now()
										: std::chrono::steady_clock::now() ;	// 元単調時計です。
		// 終了・期限・子停止・時計後退はいずれも同runの全借用を失効します。
		if( !lifetime_->active || now < lifetime_->lastNow || now >= lifetime_->deadline ||
		   (lifetime_->cancellation && lifetime_->cancellation())) {
			finish() ;
			return false ;
		}

		lifetime_->lastNow = now ;
		return true ;
	} catch( ...) {
		// 取消し/時計の障害を生存証明へ変えません。
		finish() ;
		return false ;
	}
}

/** @see collector_inspection_acquisition.h */
std::shared_ptr<const CollectorRunPageProof> CollectorRunPageScope::find(
	const CollectorInspectionSource &source) noexcept
{
	// 停止後に保存済み本文から新しい権限を作りません。
	if( !checkpoint()) {
		return {} ;
	}

	// 同じrunの有限集合からexact起点だけを検索します。
	for( const auto &page : pages_) {
		// Payloadの一致や別jobの成功はcache keyへ使いません。
		if( page->rootUrl_ == source.rootUrl && page->rootHost_ == source.rootHost) {
			return page ;
		}
	}

	return {} ;
}

/** @see collector_inspection_acquisition.h */
bool CollectorRunPageScope::accepts( const CollectorRunPageProof		&proof,
									const CollectorInspectionSource &source) noexcept
{
	return checkpoint() && proof.lifetime_.lock() == lifetime_ &&
		   proof.rootUrl_ == source.rootUrl && proof.rootHost_ == source.rootHost &&
		   proof.transfer_.completion() == CollectorHttpTransferCompletion::COMPLETE &&
		   std::ranges::any_of( pages_, [&proof]( const auto &page) { return page.get() == &proof ; }) ;
}

/** @see collector_inspection_acquisition.h */
std::shared_ptr<const CollectorRunPageProof> CollectorRunPageScope::retain(
	const CollectorInspectionSource &source, std::vector<std::byte> raw, std::wstring html,
	CollectorInspectionPageObservation observation, CollectorHttpTransferObservation transfer)
{
	constexpr std::uint64_t MAX_RAW_BYTES = 32ULL * 1024ULL * 1024ULL ;	// 同runの保有限度です。
	// 同実HTTP完全終端と有限容量だけを保持し、過大集合を一部だけ保存しません。
	if( !checkpoint() || pages_.size() >= 32U || raw.empty() || raw.size() > 2U * 1024U * 1024U ||
	   raw.size() > MAX_RAW_BYTES - rawBytes_ || html.empty() || observation.httpStatus != 200U ||
	   observation.bodyBytes != raw.size() || observation.bodySha256.size() != 64U ||
	   transfer.stage() != CollectorHttpTransferStage::PAGE ||
	   transfer.completion() != CollectorHttpTransferCompletion::COMPLETE ||
	   transfer.bodyBytesRead() != raw.size() ||
	   std::ranges::any_of( pages_, [&source]( const auto &page) {
		   return page->rootUrl_ == source.rootUrl && page->rootHost_ == source.rootHost ;
	   })) {
		return {} ;
	}

	const auto proof = std::make_shared<const CollectorRunPageProof>(
		CollectorRunPageProof( lifetime_, source, std::move( raw), std::move( html),
							  // 同run不変所有です。
							  std::move( observation), std::move( transfer))) ;
	pages_.push_back( proof) ;
	rawBytes_ += proof->raw_.size() ;
	return proof ;
}

namespace {
/** @brief URLとhrefの有限な未解釈文字を確認する。
 * @param[in] value 台帳のURLまたはhref。
 * @param[in] maximum 文字数上限。
 * @return 空・制御・認証query・entity・fragment等がない場合true。
 */
bool plainInspectionValue( std::wstring_view value, std::size_t maximum)
{
	return !value.empty() && value.size() <= maximum &&
		   value.find_first_of( L"?#@<>&\"'\\") == std::wstring_view::npos &&
		   value.find( L"..") == std::wstring_view::npos &&
		   std::ranges::none_of(
			   value, []( wchar_t character) { return character <= L' ' || character == L'\x7f' ; }) ;
}

/** @brief Exact hostだけの小文字ASCII集合を確認する。
 * @param[in] host 台帳host。
 * @return Suffix・大文字・制御・IP literalを含まないDNS形の場合true。
 */
bool exactInspectionHost( std::wstring_view host)
{
	return host.size() <= 253U && host.find( L'.') != std::wstring_view::npos &&
		   !host.starts_with( L'.') && !host.ends_with( L'.') &&
		   std::ranges::all_of( host, []( wchar_t character) {
			   return (character >= L'a' && character <= L'z') ||
					  (character >= L'0' && character <= L'9') || character == L'-' ||
					  character == L'.' ;
		   }) ;
}

/** @brief 定義hrefを起点URLから有限な文字列規則で解決する。
 * @param[in] source 事前文字検査済みの定義。
 * @return 絶対href、root相対、page相対だけの解決値。
 * @note Dot segment・query・entity・scheme相対の補完は行わない。
 */
std::wstring resolvedInspectionHref( const CollectorInspectionSource &source)
{
	// 明示絶対HTTPSを別schemeへ補完しない。
	if( source.href.starts_with( L"https://")) {
		return source.href ;
	}

	// Root相対は同じ起点originだけへ解決する。
	if( source.href.starts_with( L"/")) {
		return L"https://" + source.rootHost + source.href ;
	}

	return source.rootUrl.substr( 0U, source.rootUrl.rfind( L'/') + 1U) + source.href ;
}
/** @brief 対象href markerが別属性の引用符内でないことを確認する。
 * @param[in] tag 引用符終端を確認した原anchor開始tag。
 * @param[in] marker 空白とhrefの正確な属性token。
 * @return 引用符外の一意属性だけならtrue。
 */
bool inspectionMarkerIsAttribute( std::wstring_view tag, std::wstring_view marker)
{
	wchar_t		quote{} ;	// 0は属性値外。
	std::size_t matches{} ;	// 属性値内の偽markerを数えない。
	// 有限tag全体を走査し、属性tokenの文脈を確認する。
	for( std::size_t index = 0U; index < tag.size(); ++index) {
		// Markerが属性値の外にある時だけ有効とする。
		if( quote == 0U && tag.substr( index).starts_with( marker)) {
			++matches ;
		}

		// 同じ引用符だけが属性値を閉じる。
		if( quote != 0U && tag[index] == quote) {
			quote = 0U ;
		}
		// 別引用符の開始は属性値外だけで認める。
		else if( quote == 0U && (tag[index] == L'"' || tag[index] == L'\'')) {
			quote = tag[index] ;
		}
	}

	return quote == 0U && matches == 1U ;
}
} // namespace

/** @see collector_inspection_acquisition.h */
bool validateCollectorInspectionSource( const CollectorInspectionSource &source)
{
	const std::array<std::wstring_view, 1U> rootHosts{source.rootHost} ;		// Exact起点host。
	const std::array<std::wstring_view, 1U> payloadHosts{source.payloadHost} ;	// Record限定委譲先。
	return exactInspectionHost( source.rootHost) && exactInspectionHost( source.payloadHost) &&
		   plainInspectionValue( source.rootUrl, 8192U) &&
		   plainInspectionValue( source.payloadUrl, 8192U) &&
		   plainInspectionValue( source.href, 480U) && !source.href.starts_with( L"//") &&
		   source.rootUrl.starts_with( L"https://" + source.rootHost + L"/") &&
		   source.payloadUrl.starts_with( L"https://" + source.payloadHost + L"/") &&
		   validateOfficialHttpsUrl( source.rootUrl, rootHosts) == 0 &&
		   validateOfficialHttpsUrl( source.payloadUrl, payloadHosts) == 0 &&
		   resolvedInspectionHref( source) == source.payloadUrl ;
}

namespace {
/** @brief 同じ有限HTML走査で一意anchorまたは実末尾終了tagを確認します。
 * @param[in] html 原文字順を維持した本文です。
 * @param[in] href 空でない場合は対象anchor、空の場合は末尾終了tagを検査します。
 * @return 完全な有限走査と当該条件が成立する場合trueです。
 * @note Comment・属性文字列・非表示要素内の偽tagを根拠にしません。
 */
bool inspectCollectorHtml( std::wstring_view html, std::wstring_view href)
{
	// 台帳の不正形・過大／NUL本文を走査前に拒否する。
	if( html.empty() || html.size() > 2U * 1024U * 1024U ||
	   html.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	std::wstring lower( html) ;	// TagのASCII caseだけを走査用に統一する。
	// 原属性値はhtmlから読み、大小文字を勝手に変換しない。
	for( auto &character : lower) {
		// Tag比較用のASCII大文字だけを小文字へ揃える。
		if( character >= L'A' && character <= L'Z') {
			character = static_cast<wchar_t>( character - L'A' + L'a') ;
		}
	}

	const std::wstring marker = L" href=\"" + std::wstring( href) + L"\"" ;	// 対象の原属性。
	std::size_t		   offset{} ;											// 最後に処理したtag末尾。最大8192tagで終了する。
	std::size_t		   tagCount{} ;											// Commentを含む有限走査数。
	std::size_t		   matches{} ;											// 二件以上なら曖昧として拒否する。
	bool			   terminal{} ;											// 実tagとして確認した固定末尾だけでtrueです。
	// 全開始tagを走査し、対象anchorまたは末尾位置を確認します。
	while( (offset = lower.find( L'<', offset)) != std::wstring::npos) {
		// 過大tag集合を一部分だけ検査して成功にしない。
		if( ++tagCount > 8192U) {
			return false ;
		}

		// Comment内markupを配布根拠にしない。
		if( lower.compare( offset, 4U, L"<!--") == 0) {
			const auto end = lower.find( L"-->", offset + 4U) ;	// Commentの有限終端。
			// 未終端comment以降を有効HTMLとみなさない。
			if( end == std::wstring::npos) {
				return false ;
			}

			offset = end + 3U ;
			continue ;
		}

		std::size_t end = offset + 1U ;	// 引用符内の偽tagを読み飛ばす有限走査。
		wchar_t		quote{} ;			// 0は属性値外、単／二重引用符を独立に扱う。
		// 最大4096文字で引用符外のtag終端まで進める。
		for( ; end < lower.size() && end - offset <= 4096U; ++end) {
			const wchar_t character = lower[end] ;	// 現在tagの文字。
			// 同じ引用符だけが属性値を閉じる。
			if( quote != 0U && character == quote) {
				quote = 0U ;
			}
			// 別引用符の開始を属性値外だけで認める。
			else if( quote == 0U && (character == L'\"' || character == L'\'')) {
				quote = character ;
			}
			// 引用符外の終端だけをtag末尾とする。
			else if( quote == 0U && character == L'>') {
				break ;
			}
		}

		// 未終端・過大tagは別parserへfallbackしない。
		if( end >= lower.size() || end - offset > 4096U) {
			return false ;
		}

		const auto	 tag = std::wstring_view( lower).substr( offset, end - offset + 1U) ;	// Tagだけ。
		std::wstring suppressed ;															// 非実行・非表示要素の開始だけで設定する。
		// Script等の開始tagは大小文字以外を推測補正しない。
		for( const auto name :
			{L"script", L"style", L"template", L"noscript", L"textarea", L"iframe", L"xmp",
			 L"title", L"plaintext", L"noembed", L"noframes", L"svg", L"math"}) {
			const std::wstring prefix = L"<" + std::wstring( name) ;	// 要素境界を確認するprefix。
			// 別名要素を同じ非表示要素と誤認しない。
			if( tag.starts_with( prefix) && tag.size() > prefix.size() &&
			   std::wstring_view( L">/ \t\n\r\f").find( tag[prefix.size()]) !=
				   std::wstring_view::npos) {
				suppressed = name ;
				break ;
			}
		}

		// 非表示内容内の偽anchorや引用符をtag走査へ戻さない。
		if( !suppressed.empty()) {
			const auto close = lower.find( L"</" + suppressed + L">", end + 1U) ;	// 有限close。
			// 未終端またはnested templateを独自に推測しない。
			if( close == std::wstring::npos || (href.empty() && suppressed == L"plaintext") ||
			   ((suppressed == L"template" || suppressed == L"svg" || suppressed == L"math") &&
				lower.find( L"<" + suppressed, end + 1U) < close)) {
				return false ;
			}

			offset = close + suppressed.size() + 3U ;
			continue ;
		}

		// 元HTML終端と同じ位置の実body終了tagだけを比較境界にします。
		if( href.empty() && html.ends_with( L"</body>\n</html>") && offset + 15U == html.size() &&
		   tag == L"</body>") {
			terminal = true ;
		}

		// 直前bodyと連続する実html終了tagを必要とします。
		if( href.empty() && offset + 7U == html.size() && tag == L"</html>") {
			return terminal ;
		}

		// 有効anchorだけを属性parserへ渡す。終了tag・他要素は根拠にしない。
		if( !href.empty() && suppressed.empty() &&
		   (tag.starts_with( L"<a ") || tag.starts_with( L"<a\n"))) {
			std::wstring actualHref ;											// 同じtagの原属性値です。
			const auto	 original = html.substr( offset, end - offset + 1U) ;	// Case未変更の原tag。
			// 同じ原hrefの一意属性だけを配布根拠にする。
			if( tag.find( L"href") != std::wstring_view::npos &&
			   tag.find( L"href", tag.find( L"href") + 4U) == std::wstring_view::npos &&
			   inspectionMarkerIsAttribute( original, marker) &&
			   extractUniqueOfficialHtmlAttribute( original, marker, L"href", 480U, actualHref) &&
			   actualHref == href && ++matches > 1U) {
				return false ;
			}
		}

		offset = end + 1U ;
	}

	return !href.empty() && matches == 1U ;
}
} // namespace

/** @see collector_inspection_acquisition.h */
bool verifyCollectorInspectionLink( std::wstring_view html, const CollectorInspectionSource &source)
{
	return validateCollectorInspectionSource( source) && inspectCollectorHtml( html, source.href) ;
}

/** @see collector_inspection_acquisition.h */
NativeError computeCollectorPageContentSha256( const std::string_view raw, std::wstring &sha256)
{
	sha256.clear() ;
	// 原PAGEの有限容量を越える入力から比較値を発行しません。
	if( raw.empty() || raw.size() > 2U * 1024U * 1024U) {
		return E_INVALIDARG ;
	}

	constexpr std::string_view MARKER =
		"<!-- WP Fastest Cache file was created in " ;	// 唯一の除外候補です。
	const auto start   = raw.find( MARKER) ;			// 一件以外は全rawを比較します。
	auto	   content = raw ;							// 不明な形式では元byte全体を保持します。
	// EOF直結・一件・固定桁の既知診断だけを詳しく確認します。
	if( start != std::string_view::npos && raw.find( MARKER, start + 1U) == std::string_view::npos &&
	   raw.size() - start == MARKER.size() + 50U) {
		const auto value  = raw.substr( start + MARKER.size()) ;	// 固定50byteの診断値です。
		bool	   digits = true ;									// 秒数の可変部はASCII数字14桁だけです。
		// 全14桁を確認し、指数表記や任意文字列を除去しません。
		for( std::size_t index = 2U; index < 16U; ++index) {
			digits = digits && value[index] >= '0' && value[index] <= '9' ;
		}

		const auto stamp = value.substr( 29U, 17U) ;	// 実観測とは独立した診断日時です。
		// 日時の数字を全て確認し、書式不明は全rawへ戻します。
		for( const auto index : {0U, 1U, 3U, 4U, 6U, 7U, 9U, 10U, 12U, 13U, 15U, 16U}) {
			digits = digits && stamp[index] >= '0' && stamp[index] <= '9' ;
		}

		// 生成日時は書式だけを検査し、実観測時刻や期限へ使用しません。
		if( digits && value.starts_with( "0.") && value.substr( 16U, 13U) == " seconds, on " &&
		   value.ends_with( " -->") && stamp[2U] == '-' && stamp[5U] == '-' && stamp[8U] == ' ' &&
		   stamp[11U] == ':' && stamp[14U] == ':') {
			const auto number = [stamp]( const std::size_t at) {
				return static_cast<unsigned>( (stamp[at] - '0') * 10 + stamp[at + 1U] - '0') ;
			} ; // 検証済み二桁だけを読む短期借用です。
			const std::chrono::year_month_day date{
				std::chrono::year{2000 + static_cast<int>( number( 6U))},
				std::chrono::month{number( 3U)},
				std::chrono::day{number( 0U)}} ;	// 診断書式だけの検査です。
			std::wstring prefix ;					// ASCII tag走査用だけのbyte対応文字列です。
			prefix.reserve( start) ;
			// 再encodeせず、ASCII tagの位置を原byteへ対応させます。
			for( const unsigned char character : raw.substr( 0U, start)) {
				prefix.push_back( static_cast<wchar_t>( character)) ;
			}

			// 実HTML終端の外側にある既知書式だけを比較digestから除外します。
			if( date.ok() && number( 9U) < 24U && number( 12U) < 60U && number( 15U) < 60U &&
			   inspectCollectorHtml( prefix, {})) {
				content = raw.substr( 0U, start) ;
			}
		}
	}

	return computeCollectorMetadataSha256( content, sha256) ;
}

/** @see collector_inspection_acquisition.h */
CollectorInspectionAcquisition::CollectorInspectionAcquisition() : http_( false)
{
}
/** @see collector_inspection_acquisition.h */
CollectorInspectionAcquisition::CollectorInspectionAcquisition( OfficialHttpTransport transport)
	: http_( std::move( transport))
{
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::readDefinitionMetadata(
	const std::wstring_view url, const std::wstring_view host, const bool modelJson,
	std::vector<std::byte> &raw, std::wstring &text,
	CollectorInspectionPageObservation &observation, CollectorHttpTransferObservation &transfer,
	const HttpCancellationCallback &cancellation)
{
	std::wstring finalUrl ;	// 同じHTTPが確定した公開URLです。
	return http_.getCollectorInspectionPage( url, host, cancellation, text, finalUrl, &observation,
											&transfer, &raw, modelJson) ;
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::acquire(
	ScanSessionId scanSessionId, const CollectorInspectionSource &source,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
	OfficialAcquisitionResult &result, const std::uint64_t maximumBytes,
	const std::wstring_view publishedSha256, const std::wstring_view expectedPageContentSha256)
{
	return acquireCore( scanSessionId, source, session, workspace, costReader, cancellation, result,
					   maximumBytes, publishedSha256, expectedPageContentSha256, nullptr, nullptr) ;
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::acquireWithRunPage(
	ScanSessionId scanSessionId, const CollectorInspectionSource &source,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
	OfficialAcquisitionResult &result, std::uint64_t maximumBytes,
	std::wstring_view publishedSha256, std::wstring_view expectedPageContentSha256,
	CollectorRunPageScope &scope, const CollectorRunPageProof *proof)
{
	// 元parentの生存照会を全HTTP hopと本文の取消しへ接続します。
	const auto stop = [&scope, &cancellation]() {
		return !scope.checkpoint() || (cancellation && cancellation()) ;
	} ;
	return acquireCore( scanSessionId, source, session, workspace, costReader, stop, result,
					   maximumBytes, publishedSha256, expectedPageContentSha256, &scope, proof) ;
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::acquireCore(
	ScanSessionId scanSessionId, const CollectorInspectionSource &source,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
	OfficialAcquisitionResult &result, std::uint64_t maximumBytes,
	std::wstring_view publishedSha256, std::wstring_view expectedPageContentSha256,
	CollectorRunPageScope *scope, const CollectorRunPageProof *proof)
{
	result			  = {} ;
	const bool reused = std::exchange( used_, true) ;	// 初回拒否も一回scopeを消費する。
	// 再試行・別session・任意URL形は実起点GET前に止める。
	if( reused || scanSessionId == 0U || scanSessionId != session.scanSessionId_ ||
	   !validateCollectorInspectionSource( source) || maximumBytes == 0U ||
	   maximumBytes > COLLECTOR_INSPECTION_MAXIMUM_BYTES ||
	   (scope == nullptr && proof != nullptr) || (scope != nullptr && !scope->checkpoint()) ||
	   (!publishedSha256.empty() &&
		(publishedSha256.size() != 64U ||
		 publishedSha256.find_first_not_of( L"0123456789abcdef") != std::wstring_view::npos)) ||
	   (!expectedPageContentSha256.empty() &&
		(expectedPageContentSha256.size() != 64U ||
		 expectedPageContentSha256.find_first_not_of( L"0123456789abcdef") !=
			 std::wstring_view::npos))) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = E_INVALIDARG ;
		return result.error ;
	}

	scanSessionId_	 = scanSessionId ;
	source_			 = source ;
	maximumBytes_	 = maximumBytes ;
	publishedSha256_ = publishedSha256 ;
	// 親が既存proofを渡さなかった場合も同PAGEを二度取得しません。
	if( scope != nullptr && proof == nullptr && scope->find( source_)) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = E_ACCESSDENIED ;
		return result.error ;
	}

	result.networkCostError = costReader.read( result.networkCost) ;
	// 起点本文にも制限付き・不明回線の自動同意を適用しない。
	if( result.networkCostError != 0 ||
	   result.networkCost != OfficialNetworkCostKind::UNRESTRICTED) {
		result.state = OfficialAcquisitionState::AWAITING_NETWORK_CONSENT ;
		result.error = E_ACCESSDENIED ;
		return result.error ;
	}

	std::wstring html ;				// 同scopeの実起点本文。結果JSONへ出さない。
	std::wstring finalUrl ;			// 実最終responseの相対href base。永続化しない。
	std::wstring contentSha256 ;	// 同HTTPの原SHAとは別の比較値です。
	NativeError	 error{} ;			// 元HTTPと借用拒否を後段parserから分離します。
	// 借用証拠の期限・元run・全bindingを再確認し、無効時は新GETへfallbackしません。
	if( proof != nullptr) {
		// 別scope/終了済み証拠ではpayloadも起点も送信しません。
		if( !scope->accepts( *proof, source_)) {
			result.state = OfficialAcquisitionState::REJECTED ;
			result.error = E_ACCESSDENIED ;
			return result.error ;
		}

		html			 = proof->html_ ;
		pageObservation_ = proof->observation_ ;
		pageTransfer_	 = proof->transfer_ ;
		finalUrl		 = proof->observation_.finalUrl ;
		pageReusedInRun_ = true ;
		// 同じ生存proofの原byteから毎jobの比較値を再確認します。
		error = computeCollectorPageContentSha256(
			{reinterpret_cast<const char *>( proof->raw_.data()), proof->raw_.size()},
			contentSha256) ;
	} else {
		std::vector<std::byte> raw ;	// 同HTTP比較と私有runが原本文を所有します。
		error =
			http_.getCollectorInspectionPage( source_.rootUrl, source_.rootHost, cancellation, html,
											 finalUrl, &pageObservation_, &pageTransfer_, &raw) ;
		std::shared_ptr<const CollectorRunPageProof>
			retained ;	// 比較失敗でも元完全PAGEをscopeへ残します。
		// PAGE自体が完全なら、後続anchor/hash/CAT失敗と独立して他jobへ保持します。
		if( error == 0 && scope != nullptr) {
			retained =
				scope->retain( source_, std::move( raw), html, pageObservation_, pageTransfer_) ;
			// 保持拒否を比較成功として扱いません。
			if( !retained) {
				error = E_ACCESSDENIED ;
			}
		}

		// 同HTTPのbyteを文字aliasで借用し、再encodeせず比較します。
		if( error == 0) {
			const auto &actual = retained ? retained->raw_ : raw ;	// 同じ完全PAGEの所有領域です。
			error			   = computeCollectorPageContentSha256(
				 {reinterpret_cast<const char *>( actual.data()), actual.size()}, contentSha256) ;
		}
	}

	auto resolvedSource	   = source_ ;	// 台帳を変更せず、実最終URLでだけhrefを再解決する。
	resolvedSource.rootUrl = finalUrl ;
	// 旧本文への手動確認を変更後pageへ移し替えません。
	if( error == 0 && !expectedPageContentSha256.empty() &&
	   contentSha256 != expectedPageContentSha256) {
		error = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
	}

	// 起点取得に成功しても、対象linkが有効anchorでなければ取得しない。
	if( error == 0 && !verifyCollectorInspectionLink( html, resolvedSource)) {
		error = HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
	}

	// 元HTTP／parser失敗をpackage不適合に変換しない。
	if( error != 0) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = error ;
		return error ;
	}

	rootVerified_ = true ;
	const OfficialAcquisitionRequest request{
		.url			   = source_.payloadUrl,
		.providerId		   = COLLECTOR_INSPECTION_PROVIDER_ID,
		.resourceId		   = OFFICIAL_PAYLOAD_RESOURCE_ID,
		.workspaceFileName = L"inspection.zip",
		.maximumFileBytes  = maximumBytes_,
		.publishedSha256   = publishedSha256_} ;	// 公開hashは共通実byte検証でだけ使用する。
	return session.acquireCore(
		request, workspace, *this, costReader, []( std::uint64_t, std::uint64_t) {}, cancellation,
		result, this) ;
}

/** @see collector_inspection_acquisition.h */
bool CollectorInspectionAcquisition::matches(
	ScanSessionId scanSessionId, const OfficialAcquisitionRequest &request) const noexcept
{
	return used_ && rootVerified_ && !payloadAttempted_ && scanSessionId == scanSessionId_ &&
		   request.url == source_.payloadUrl &&
		   request.providerId == COLLECTOR_INSPECTION_PROVIDER_ID &&
		   request.resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID &&
		   request.workspaceFileName == L"inspection.zip" &&
		   request.maximumFileBytes == maximumBytes_ && !request.publishedSize &&
		   request.publishedSha256 == publishedSha256_ &&
		   request.publishedSha512 == publishedSha512_ && !request.restrictedNetworkApproved &&
		   request.delegatedGrant == nullptr && request.delegatedGrantId == 0U &&
		   !request.delegatedUtcNow ;
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::download(
	std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
	HANDLE outputFile, const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback &cancellationCallback)
{
	// 同じ実起点からの唯一payload以外は送信しない。
	if( !rootVerified_ || payloadAttempted_ || url != source_.payloadUrl ||
	   resourceId != OFFICIAL_PAYLOAD_RESOURCE_ID || maximumBytes == 0U ||
	   maximumBytes > maximumBytes_) {
		return E_ACCESSDENIED ;
	}

	payloadAttempted_ = true ;
	const std::array<std::wstring_view, 1U> hosts{source_.payloadHost} ;	// 当該recordだけの委譲先。
	std::vector<std::uint32_t>				origins ;						// 同一origin内二redirectまで。
	const bool resolved = !definitionCdn_.empty() ;							// 同一scopeだけが解決した秘密値です。
	const std::function<NativeError()> checkpoint = [&]() {
		return definitionCheckpoint( cancellationCallback) ;
	} ; // 同時計/取消しです。
	const auto error = http_.downloadToFile(
		resolved ? definitionCdn_.view() : url, hosts, resolved ? 0U : 2U, maximumBytes, outputFile,
		progressCallback, cancellationCallback, origins, true, &payloadTransfer_,
		resolved ? &checkpoint : nullptr) ;	// 同じ実保存観測です。
	payloadVerified_ = error == 0 && !origins.empty() ;
	return error ;
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::downloadDelegated(
	OfficialDelegatedGetRequest &, HANDLE, const HttpDownloadProgressCallback &,
	const HttpCancellationCallback &, OfficialPublicDestinationEvidence &destinationEvidence)
{
	destinationEvidence = {} ;
	return E_ACCESSDENIED ;
}

/** @see collector_inspection_acquisition.h */
bool CollectorInspectionAcquisition::hasSourceEvidence( ScanSessionId	 scanSessionId,
													   std::wstring_view providerId,
													   std::wstring_view resourceId) const noexcept
{
	return sourceVerified() && scanSessionId == scanSessionId_ &&
		   providerId == COLLECTOR_INSPECTION_PROVIDER_ID &&
		   resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID ;
}

/** @see collector_inspection_acquisition.h */
bool CollectorInspectionAcquisition::sourceVerified() const noexcept
{
	return used_ && rootVerified_ && payloadAttempted_ && payloadVerified_ ;
}

/** @see collector_inspection_acquisition.h */
const CollectorInspectionPageObservation &CollectorInspectionAcquisition::pageObservation()
	const noexcept
{
	return pageObservation_ ;
}

/** @see collector_inspection_acquisition.h */
const CollectorHttpTransferObservation &CollectorInspectionAcquisition::pageTransfer()
	const noexcept
{
	return pageTransfer_ ;
}
/** @see collector_inspection_acquisition.h */
const CollectorHttpTransferObservation &CollectorInspectionAcquisition::payloadTransfer()
	const noexcept
{
	return payloadTransfer_ ;
}
/** @see collector_inspection_acquisition.h */
bool CollectorInspectionAcquisition::pageReusedInRun() const noexcept
{
	return pageReusedInRun_ ;
}

/** @see collector_inspection_acquisition.h */
std::uint64_t CollectorInspectionAcquisition::definitionUtcNow() const
{
	// 試験用I/O表だけに偽時計を許し、欠損を実時計で補いません。
	if( http_.testTransport_) {
		return http_.testTransport_->utcNow ? http_.testTransport_->utcNow() : 0U ;
	}

	const auto now = std::chrono::duration_cast<std::chrono::seconds>(
						 std::chrono::system_clock::now().time_since_epoch())
						 .count() ;	// 現実UTC秒です。
	return now > 0 ? static_cast<std::uint64_t>( now) : 0U ;
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::definitionCheckpoint(
	const HttpCancellationCallback &cancellation) const
{
	// 取消し関数の例外をネットワーク成功へ変換しません。
	try {
		// 実送信直前にも同じworkerの協調停止を確認します。
		if( cancellation && cancellation()) {
			return HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
		}
	} catch( ...) {
		return E_UNEXPECTED ;
	}

	const auto now = definitionUtcNow() ;	// Metadata開始と同じ時計です。
	// 無効時計と後退を期限余裕だけで救済しません。
	if( now == 0U || now < definitionIssuedUtc_) {
		return E_INVALIDARG ;
	}

	// 元token失効と30秒未満の余裕は送信前に止めます。
	if( now >= definitionDeadlineUtc_ || definitionDeadlineUtc_ - now < 30U) {
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	return 0 ;
}

namespace {
/** @brief 公開cache versionだけを旧相対href解決へ正確に結びます。
 * @param[in] source 同一page/候補URLの未認証値です。
 * @return 同じhrefを解決したURL。不正文法は空です。
 */
std::wstring definitionPublicHref( CollectorInspectionSource source)
{
	const auto query = source.href.find( L'?') ;	// 原hrefのquery開始位置です。
	// Query無しの旧検査をそのまま再利用します。
	if( query == std::wstring::npos) {
		return resolvedInspectionHref( source) ;
	}

	const auto suffix = source.href.substr( query) ;	// 公開cache keyだけを有限保存します。
	// 任意queryやfragmentを取得能力へ広げません。
	if( !suffix.starts_with( L"?v=") || suffix.size() <= 3U || suffix.size() > 131U ||
	   suffix.find_first_not_of( L"0123456789abcdefABCDEF", 3U) != std::wstring::npos ||
	   !source.payloadUrl.ends_with( suffix)) {
		return {} ;
	}

	source.href.resize( query) ;
	source.payloadUrl.resize( source.payloadUrl.size() - suffix.size()) ;
	const auto base = resolvedInspectionHref( source) ;	// 旧path検査結果です。
	return base.empty() ? std::wstring{} : base + suffix ;
}

/** @brief 公開model APIの同一model/path/hash一件を再確認します。
 * @param[in] text 同じnative HTTPで全受信したJSONです。
 * @param[in] plan 同じ公開model/pathです。
 * @param[in] digest 原metadataへ比較する小文字SHA-256です。
 * @return 同じfileの一意な公開行だけならtrueです。
 */
bool definitionModelMatches( std::wstring_view text, const OfficialAnonymousCdnPlan &plan,
							std::wstring_view digest)
{
	using namespace winrt::Windows::Data::Json ;
	JsonObject root ;	// 生JSONから同期解析した一文書だけです。
	// Parser例外・欠損は外側acquireのHRESULTへ戻します。
	if( !JsonObject::TryParse( text, root) || root.GetNamedString( L"Status", L"") != L"SUCCESS") {
		return false ;
	}

	const auto result = root.GetNamedObject( L"Result") ;	// 公開modelの結果です。
	// 別modelの同pathだけを借用しません。
	if( result.GetNamedString( L"Model", L"") != plan.model) {
		return false ;
	}

	const auto groups = result.GetNamedArray( L"Obj") ;	// 有限の分類一覧です。
	// 公式JSONであっても任意に大きい集合は受理しません。
	if( groups.Size() > 256U) {
		return false ;
	}

	std::size_t total{} ;	// 全分類共同のfile数です。
	std::size_t matches{} ;	// 同pathの一意性をhashと別に確認します。
	// 公開file以外のExeModule/command等は参照しません。
	for( const auto &group : groups) {
		const auto files = group.GetObject().GetNamedArray( L"Files") ;	// 原の配布行です。
		// 各分類と全分類に共同上限を課します。
		if( files.Size() > 512U || total > 2048U - files.Size()) {
			return false ;
		}

		total += files.Size() ;
		// 同じpathの異なるhashや重複も成功にしません。
		for( const auto &value : files) {
			const auto file = value.GetObject() ;	// 同じ配布objectです。
			const auto path = file.GetNamedObject( L"DownloadUrl")
								  .GetNamedString( L"Global", L"") ;	// 原公開pathです。
			// 対象外の配布行をdriver本体へ選びません。
			if( path != plan.path) {
				continue ;
			}

			std::wstring published( file.GetNamedString( L"sha256", L"")) ;	// 原同fileのhashです。
			std::ranges::transform( published, published.begin(), []( wchar_t c) {
				return c >= L'A' && c <= L'F' ? static_cast<wchar_t>( c + (L'a' - L'A')) : c ;
			}) ; // Hash文字だけをcase変換します。
			// 原hashが欠損または相違する場合は取得しません。
			if( published != digest || ++matches != 1U) {
				return false ;
			}
		}
	}

	return matches == 1U ;
}

/** @brief 同一GUID一件だけの正規Catalog download queryをnativeで生成します。
 * @param[in] id 小文字の公開update GUID。
 * @return 正常時の固定endpoint URL。不正GUIDは空です。
 */
std::wstring definitionCatalogDownloadUrl( std::wstring_view id)
{
	// GUIDの区切り位置も検査し、任意JSONや追加updateを受け取りません。
	if( id.size() != 36U) {
		return {} ;
	}

	// 公開GUIDの36文字を一度だけ検証します。
	for( std::size_t index = 0U; index < id.size(); ++index) {
		const bool separator =
			// 固定位置です。
			index == 8U || index == 13U || index == 18U || index == 23U ;
		// 区切り以外のhyphenや非hexを拒否します。
		if( (separator && id[index] != L'-') ||
		   (!separator &&
			std::wstring_view{L"0123456789abcdef"}.find( id[index]) == std::wstring_view::npos)) {
			return {} ;
		}
	}

	const std::wstring body = L"[{\"size\":0,\"languages\":\"\",\"uidInfo\":\"" + std::wstring( id) +
							  L"\",\"updateID\":\"" + std::wstring( id) +
							  L"\"}]" ;	// 同じGUID一件だけです。
	std::wstring url =
		L"https://www.catalog.update.microsoft.com/DownloadDialog.aspx?updateIDs=" ;	// 固定起点です。
	// ASCII JSONのpercent encodingです。
	constexpr std::wstring_view digits = L"0123456789ABCDEF" ;
	// 固定ASCII JSONだけをurllibのquote_plusと同じ一意表現へ変換します。
	for( const wchar_t character : body) {
		// Unreservedだけをそのまま保持します。
		if( (character >= L'a' && character <= L'z') || (character >= L'A' && character <= L'Z') ||
		   (character >= L'0' && character <= L'9') || character == L'-' || character == L'_' ||
		   character == L'.' || character == L'~') {
			url.push_back( character) ;
		} else {
			url.push_back( L'%') ;
			url.push_back( digits[static_cast<std::size_t>( (character >> 4U) & 15U)]) ;
			url.push_back( digits[static_cast<std::size_t>( character & 15U)]) ;
		}
	}

	return url ;
}
} // namespace

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::acquireDefinition(
	ScanSessionId scanSessionId, const CollectorDefinitionRequest &definition,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
	OfficialAcquisitionResult &result, CollectorDefinitionMetadataObservation &metadata,
	CollectorDefinitionPublicMetadata *confirmed)
try {
	result	 = {} ;
	metadata = {} ;
	// 未認証hintを成功metadataとして返しません。
	if( confirmed != nullptr) {
		*confirmed = {} ;
	}

	const auto			   &source	= definition.source ;					// 外側callerの未認証候補です。
	constexpr std::uint64_t maximum = 2ULL * 1024ULL * 1024ULL * 1024ULL ;	// 定義取得の有限枠です。
	const std::array<std::wstring_view, 1U> roots{source.rootHost} ;		// 今回のexact起点hostです。
	const std::array<std::wstring_view, 1U> payloads{
		source.payloadHost} ;	// 今回の明示配布hostです。
	// 不正/再使用/session不一致はmetadata要求前に拒否します。
	if( std::exchange( used_, true) || scanSessionId == 0U ||
	   scanSessionId != session.scanSessionId_ || definition.maximumBytes == 0U ||
	   definition.maximumBytes > maximum || !exactInspectionHost( source.rootHost) ||
	   !exactInspectionHost( source.payloadHost) ||
	   validateOfficialHttpsUrl( source.rootUrl, roots) != 0 ||
	   validateOfficialHttpsUrl( source.payloadUrl, payloads) != 0) {
		return E_INVALIDARG ;
	}

	scanSessionId_	 = scanSessionId ;
	source_			 = source ;
	maximumBytes_	 = definition.maximumBytes ;
	publishedSha256_ = definition.publishedSha256 ;
	publishedSha512_ = definition.publishedSha512 ;
	// 公表hash hintの文法自体をHTTP前に固定します。
	if( !publishedSha256_.empty() &&
	   (publishedSha256_.size() != 64U ||
		publishedSha256_.find_first_not_of( L"0123456789abcdef") != std::wstring::npos)) {
		return E_INVALIDARG ;
	}

	// 公表SHA-512にも算法固有の有限文法を課します。
	if( !publishedSha512_.empty() &&
	   (publishedSha512_.size() != 128U ||
		publishedSha512_.find_first_not_of( L"0123456789abcdef") != std::wstring::npos)) {
		return E_INVALIDARG ;
	}

	result.networkCostError = costReader.read( result.networkCost) ;
	// 未知/従量制回線へ定義のcopyだけで同意を発行しません。
	if( result.networkCostError != 0 ||
	   result.networkCost != OfficialNetworkCostKind::UNRESTRICTED) {
		result.state = OfficialAcquisitionState::AWAITING_NETWORK_CONSENT ;
		result.error = E_ACCESSDENIED ;
		return result.error ;
	}

	std::wstring html ;				// 同native I/Oが所有する現在本文です。
	std::wstring eulaRevision ;		// 同取得parserだけが確認する現在の必須revisionです。
	std::wstring eulaTextSha256 ;	// 同parser全文からだけ計算します。
	std::wstring finalUrl ;			// 相対anchorの同一origin baseです。
	std::optional<CollectorDefinitionStaticTermsObservation>
									   staticTerms ;	// 成功時だけcommitする独立観測です。
	CollectorInspectionPageObservation apiPage ;		// NVIDIAの原API観測をdetailsで上書きしません。
	// 個々のmetadata失敗も実数を保持し、成功JSONから観測を復元しません。
	const auto						   fetch = [&]( std::wstring_view url) {
		// 同じ元I/OのHRESULTを他のmetadata分類で上書きしません。
		const NativeError error = http_.getCollectorInspectionPage(
			url, source.rootHost, cancellation, html, finalUrl, &pageObservation_, &pageTransfer_) ;
		metadata.requests += pageTransfer_.attemptedRequests() ;
		metadata.bodyBytes += pageTransfer_.bodyBytesRead() ;
		metadata.httpStatus = pageTransfer_.terminalStatus() ;
		return error ;
	} ;
	NativeError error{} ;	// 元HTTPと内容拒否を混同しない結果です。
	// 公開page形式は同じ実anchorを再確認してからpayloadへ進みます。
	if( definition.protocol == CollectorDefinitionProtocol::PUBLIC_LINK) {
		// 汎用anchorには公表hash parserがないため、hintを公表根拠へ昇格させません。
		if( !publishedSha256_.empty() || !publishedSha512_.empty()) {
			return E_INVALIDARG ;
		}

		error			 = fetch( source.rootUrl) ;
		auto resolved	 = source ;	// 実最終URLにだけ相対hrefを結びます。
		resolved.rootUrl = finalUrl ;
		// URLの一致と実HTML anchorを別々に検査します。
		if( error == 0 && (source.href.empty() || source.href.size() > 480U ||
						  definitionPublicHref( resolved) != source.payloadUrl ||
						  !inspectCollectorHtml( html, source.href))) {
			error = HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
		}
	}
	// Catalog形式は同じ検索/update GUID/公表URL/hashを実原本文へ再結合します。
	else if( definition.protocol == CollectorDefinitionProtocol::CATALOG_SEARCH) {
		constexpr std::wstring_view origin =
			L"https://www.catalog.update.microsoft.com/" ;	// 閉protocol起点です。
		const auto &id = definition.catalogUpdateId ;		// 同検索が選んだ公開GUIDです。
		const auto	downloadUrl =
			// nativeが同一GUID一件だけへ固定します。
			definitionCatalogDownloadUrl( id) ;
		// 別起点・別update・自由endpointをmetadataへ渡しません。
		if( source.rootHost != L"www.catalog.update.microsoft.com" || id.size() != 36U ||
		   id.find_first_not_of( L"0123456789abcdef-") != std::wstring::npos ||
		   !definition.catalogSearchUrl.starts_with( std::wstring( origin) + L"Search.aspx?q=") ||
		   definition.catalogDetailsUrl !=
			   std::wstring( origin) + L"ScopedViewInline.aspx?updateid=" + id ||
		   downloadUrl.empty() || definition.catalogDownloadUrl != downloadUrl ||
		   publishedSha256_.empty() || !publishedSha512_.empty()) {
			return E_INVALIDARG ;
		}

		error = fetch( definition.catalogSearchUrl) ;
		// 同じ検索に存在しないGUIDを後段の公式domainだけで救済しません。
		if( error == 0 && html.find( L"id=\"" + id + L"_R") == std::wstring::npos) {
			error = HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
		}

		// 通常callerのfamily条件を同検索行へ再照合し、Python選択をauthorityにしません。
		if( error == 0 && !definition.catalogRequiredTitleTerms.empty()) {
			const auto start = html.find( L"id=\"" + id + L"_R") ;	// 同GUIDの原row開始です。
			const auto end	 = html.find( L"</tr>", start) ;		// 別rowのtitleを借用しません。
			// 不完全または過大rowは推測で受理しません。
			if( end == std::wstring::npos || end - start > 65536U ||
			   definition.catalogRequiredTitleTerms.size() > 16U) {
				error = E_INVALIDARG ;
			} else {
				std::wstring row = html.substr( start, end - start) ;	// 同じrowだけです。
				std::ranges::transform( row, row.begin(), []( wchar_t c) {
					return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c + L'a' - L'A') : c ;
				}) ;
				// 元登録の全公開termが同じrowに存在する場合だけ継続します。
				for( const auto &term : definition.catalogRequiredTitleTerms) {
					std::wstring lower = term ;	// 原termは書き換えません。
					std::ranges::transform( lower, lower.begin(), []( wchar_t c) {
						return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c + L'a' - L'A') : c ;
					}) ;
					// 別familyや空termで全体を許可しません。
					if( lower.empty() || lower.size() > 128U ||
					   row.find( lower) == std::wstring::npos) {
						error = E_INVALIDARG ;
					}
				}
			}
		}

		// 検索成功だけではArchitecture/OSや内容の成功へ昇格しません。
		if( error == 0) {
			error = fetch( definition.catalogDetailsUrl) ;
		}

		// 原detailsの明示x64だけをmetadata条件とし、OS装飾は通常INF検査へ残します。
		if( error == 0 && html.find( L"AMD64") == std::wstring::npos &&
		   html.find( L"x64") == std::wstring::npos) {
			error = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		// 宣言OSは同detailsの明示値だけを使い、現在PC適用性と区別します。
		if( error == 0 && !definition.catalogTargetOs.empty()) {
			const bool windows10 = html.find( L"Windows 10") != std::wstring::npos ;	// 原宣言です。
			const bool windows11 = html.find( L"Windows 11") != std::wstring::npos ;	// 原宣言です。
			const bool later =
				windows10 && html.find( L"and later") != std::wstring::npos ;	// 継承宣言だけです。
			bool matches{} ;													// 未知を対応成功にしません。
			// 元OS集合との共通部分だけをmetadata条件とします。
			for( const auto &os : definition.catalogTargetOs) {
				matches = matches || (os == L"WINDOWS_10" && windows10) ||
						  (os == L"WINDOWS_11" && (windows11 || later)) ;
			}

			// OS装飾の最終判定はこの後の通常INF/Modelsへ残します。
			if( !matches) {
				error = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}
		}

		// 同じupdateの原download bodyを次に確認します。
		if( error == 0) {
			error = fetch( downloadUrl) ;
		}

		std::array<BYTE, 32U> hash{} ;	// 比較hintを原base64文法へ一意に戻します。
		// 同じ二桁のhexだけをbyteへ変換します。
		for( std::size_t index = 0U; index < hash.size(); ++index) {
			const auto digit = []( wchar_t value) {
				return value <= L'9' ? value - L'0' : value - L'a' + 10 ;
			} ; // 検証済みhexです。
			hash[index] = static_cast<BYTE>( digit( publishedSha256_[index * 2U]) * 16 +
											digit( publishedSha256_[index * 2U + 1U])) ;
		}

		std::array<wchar_t, 45U> encoded{} ;						// SHA-256のbase64とNULです。
		DWORD encodedSize = static_cast<DWORD>( encoded.size()) ;	// Windows APIへの有限容量です。
		// 失敗時のGetLastErrorを別の比較errorで上書きしません。
		if( error == 0 && !CryptBinaryToStringW( hash.data(), static_cast<DWORD>( hash.size()),
											   CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
											   encoded.data(), &encodedSize)) {
			error = HRESULT_FROM_WIN32( GetLastError()) ;
		}

		// 一つの原fileへURL/hashを同時に結び、複数fileの曖昧選択は保留します。
		if( error == 0 && (html.find( L"downloadInformation[0].files[0].url = '" + source.payloadUrl +
									L"';") == std::wstring::npos ||
						  html.find( L"downloadInformation[0].files[0].sha256 = '" +
									std::wstring( encoded.data()) + L"';") == std::wstring::npos ||
						  html.find( L"downloadInformation[0].files[1].") != std::wstring::npos)) {
			error = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
		}
	}
	// Intel形式は既存の同Ethernet parserを同run本文へ適用します。
	else if( definition.protocol == CollectorDefinitionProtocol::INTEL_RELEASE) {
		// 別vendor/product parserへの代用や任意配布hostを許しません。
		if( source.rootHost != L"www.intel.com" ||
		   source.payloadHost != L"downloadmirror.intel.com") {
			return E_INVALIDARG ;
		}

		error = fetch( source.rootUrl) ;
		OfficialReleaseRecord release ;	// 原同pageが明示した配布行だけです。
		// Page解析失敗と候補URL/hash変更は未知/HOLDへ戻します。
		if( error == 0 && !parseOfficialReleaseRecord(
							 OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11, html, release)) {
			error = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
		}

		// 原digestの算法と値を維持し、hexのcaseだけを共通形へ合わせます。
		if( error == 0) {
			const auto lowerHash = []( std::wstring &value) {
				std::ranges::transform( value, value.begin(), []( wchar_t c) {
					return c >= L'A' && c <= L'F' ? static_cast<wchar_t>( c + (L'a' - L'A')) : c ;
				}) ; // 有限のhex case変換です。
			} ; // 元公開値以外は作りません。
			lowerHash( release.publishedSha256) ;
			lowerHash( release.publishedSha512) ;
			// 未認証hintが存在する場合も同じ実pageへ完全照合します。
			if( release.downloadUrl != source.payloadUrl ||
			   (!publishedSha256_.empty() && publishedSha256_ != release.publishedSha256) ||
			   (!publishedSha512_.empty() && publishedSha512_ != release.publishedSha512)) {
				error = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
			}
		}

		// 未公表の算法は空のまま保持し、実測hashを代入しません。
		if( error == 0) {
			publishedSha256_ = std::move( release.publishedSha256) ;
			publishedSha512_ = std::move( release.publishedSha512) ;
			// 明示した必須EULAは、現在parserの原revision/全文をpayload前に再確認します。
			if( !definition.expectedEulaRevision.empty()) {
				eulaRevision = release.eulaRevision ;
				// 本文不在を旧同意で救済しません。
				if( eulaRevision.empty() || release.eulaText.empty() ||
				   definition.expectedEulaTextSha256.size() != 64U) {
					error = E_ACCESSDENIED ;
				} else {
					error = computeDriverContainerSha256( winrt::to_string( release.eulaText),
														 eulaTextSha256) ;
					// 同じrevision名でも全文の変更を自動承認しません。
					if( error == 0 && (eulaRevision != definition.expectedEulaRevision ||
									  eulaTextSha256 != definition.expectedEulaTextSha256)) {
						error = E_ACCESSDENIED ;
					}
				}
			}
		}
	}
	// NVIDIAの同API・原releaseを再確認し、未対応規約ではpayloadを開始しません。
	else if( definition.protocol == CollectorDefinitionProtocol::NVIDIA_DRIVER_JSON) {
		NvidiaCollectorLookup lookup ;	// 端末情報を含まない登録公開queryだけです。
		// 公表のないhashや別起点をNVIDIAの公式metadataへ混ぜません。
		if( source.rootHost != L"gfwsl.geforce.com" ||
		   !parseNvidiaCollectorLookupUrl( source.rootUrl, lookup) || !publishedSha256_.empty() ||
		   !publishedSha512_.empty() || definition.nvidiaDownloadId.empty() ||
		   definition.nvidiaVersion.empty()) {
			return E_INVALIDARG ;
		}

		error = fetch( source.rootUrl) ;
		NvidiaDriverEntry release ;	// 同run原APIの現在releaseです。
		// 変更後metadataから旧payloadへのfallbackを行いません。
		if( error == 0 && (selectNvidiaCollectorRelease( html, source.rootUrl, release) !=
							  NvidiaCollectorMetadataStatus::SELECTED ||
						  release.id != definition.nvidiaDownloadId ||
						  release.version != definition.nvidiaVersion ||
						  release.downloadUrl != source.payloadUrl)) {
			error = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
		}

		// 規約宣言なしの旧入力は従来どおり未対応HOLDへ残します。
		if( error == 0) {
			// 必須規約のない入力から配布page/文書取得へ進みません。
			if( definition.staticTermsJson.empty()) {
				error = E_NOTIMPL ;
			} else {
				apiPage = pageObservation_ ;
				error	= http_.getCollectorInspectionPage( release.detailsUrl, L"www.nvidia.com",
														   cancellation, html, finalUrl,
														   &pageObservation_, &pageTransfer_) ;
				metadata.requests += pageTransfer_.attemptedRequests() ;
				metadata.bodyBytes += pageTransfer_.bodyBytesRead() ;
				metadata.httpStatus = pageTransfer_.terminalStatus() ;
				// 同APIが発行した完全details URLだけを公開sourceへ再結合します。
				if( error == 0 && finalUrl != release.detailsUrl) {
					error = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
				}

				// APIで確認したpayloadを保持し、公開配布pageとAPI観測を分離します。
				if( error == 0) {
					source_.rootUrl	 = release.detailsUrl ;
					source_.rootHost = L"www.nvidia.com" ;
				}
			}
		}
	}
	// Model形式は公開行を再確認してからsession内だけで匿名CDNを解決します。
	else if( definition.protocol == CollectorDefinitionProtocol::MODEL_CDN) {
		const auto &plan = definition.anonymousCdn ;	// 任意HTTP workflowではない公開文脈です。
		// Canonical URL/host/hashを固定し、秘密query付き入力や別modelを拒否します。
		if( !validAsusAnonymousCdnPlan( plan) || source.rootHost != L"www.asus.com" ||
		   source.payloadHost != L"dlcdnta.asus.com" ||
		   source.payloadUrl != asusAnonymousCdnCanonicalUrl( plan) || publishedSha256_.empty() ||
		   !publishedSha512_.empty()) {
			return E_INVALIDARG ;
		}

		std::wstring model = plan.model ;	// URLの公開modelだけをASCII lowercaseへ変換します。
		std::ranges::transform( model, model.begin(), []( wchar_t c) {
			return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c + (L'a' - L'A')) : c ;
		}) ; // 原modelの意味は変更しません。
		// 公開pageの同modelをAPI queryへ結びます。
		if( source.rootUrl !=
		   L"https://www.asus.com/supportonly/" + model + L"/helpdesk_download/") {
			return E_INVALIDARG ;
		}

		definitionIssuedUtc_ = definitionUtcNow() ;
		// 不正時計や期限加算overflowを接続前に拒否します。
		if( definitionIssuedUtc_ == 0U || definitionIssuedUtc_ > UINT64_MAX - 900U) {
			return E_INVALIDARG ;
		}

		definitionDeadlineUtc_ = definitionIssuedUtc_ + 900U ;
		const std::wstring api =
			L"https://www.asus.com/support/webapi/ProductV2/GetPDBIOS?website=global&model=" +
			model + L"&pdhashedid=&pdid=99999&cpu=&siteID=www&sitelang=" ;	// 固定query builderです。
		error = http_.getCollectorInspectionPage( api, source.rootHost, cancellation, html, finalUrl,
												 &pageObservation_, &pageTransfer_, nullptr, true) ;
		metadata.requests += pageTransfer_.attemptedRequests() ;
		metadata.bodyBytes += pageTransfer_.bodyBytesRead() ;
		metadata.httpStatus = pageTransfer_.terminalStatus() ;
		// 同一modelの原path/hashがなければTokenHQへ進みません。
		if( error == 0 && !definitionModelMatches( html, plan, publishedSha256_)) {
			error = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
		}

		OfficialEmptyJsonQueryPost		   post ;			// 固定Origin/Referer/二段encodingだけです。
		OfficialAnonymousCdnResolution	   resolved ;		// 秘密queryはこのscope以外へ保存しません。
		OfficialAuxiliaryHttpObservation   auxiliary ;		// 同じPOSTだけの非秘密実数です。
		std::uint32_t					   addresses{} ;	// 同じ補助宛先の全公開DNS結果です。
		const std::function<NativeError()> checkpoint = [&]() {
			return definitionCheckpoint( cancellation) ;
		} ; // 同時計/停止です。
		// 公開metadata成功時だけbuilderと一回POSTへ進みます。
		if( error == 0) {
			error = makeAsusAnonymousCdnPost( plan, post) ;
		}

		// Form/単独canonical GETへのfallbackを追加しません。
		if( error == 0) {
			error = http_.postEmptyJsonQuery(
				post, checkpoint, cancellation,
				[&]( std::wstring_view body) {
					return parseAsusAnonymousCdnResponse( body, plan, resolved) ;
				},
				auxiliary, addresses) ;
			metadata.requests += auxiliary.requests ;
			metadata.bodyBytes += auxiliary.bodyBytes ;
			metadata.httpStatus = auxiliary.httpStatus ;
		}

		// Parser結果も同canonical URL/epochへ再結合します。
		if( error == 0 && !matchesAsusAnonymousCdnTarget( plan, resolved.target.view(),
														resolved.expiresUtcSeconds)) {
			error = E_ACCESSDENIED ;
		}

		// Token期限を延長せず15分枠との小さい方でGETを制限します。
		if( error == 0) {
			definitionDeadlineUtc_ = std::min( definitionDeadlineUtc_, resolved.expiresUtcSeconds) ;
			error				   = checkpoint() ;
		}

		// 秘密URL所有権を同一取得adapterだけへ移します。
		if( error == 0) {
			definitionCdn_ = std::move( resolved.target) ;
		}
	}
	// 未知protocolは旧static取得へfallbackしません。
	else {
		error = E_NOTIMPL ;
	}

	// 独立規約はprotocol非依存の実公式anchorと元全文snapshotへ結び、旧Intel埋込み契約を変更しません。
	if( error == 0 && !definition.staticTermsJson.empty()) {
		const auto terms = signed_index_acquisition::readTermsValue(
			definition.staticTermsJson) ;	// 共通の閉schemaです。
		// 不明規約や別profileを独立文書として扱いません。
		if( terms.state != IndexTermsState::ACCEPTANCE_REQUIRED ||
		   terms.revisionKind != IndexTermsRevisionKind::VENDOR_LITERAL || !terms.textDocument ||
		   !terms.textDocument->htmlExtraction ||
		   terms.textDocument->htmlExtraction->profile != "STATIC_HTML_SECTION_V1" ||
		   pageObservation_.finalUrl != source_.rootUrl) {
			error = E_ACCESSDENIED ;
		}

		// NVIDIA driver APIからApp用や任意規約への転用を許可しません。
		if( error == 0 && definition.protocol == CollectorDefinitionProtocol::NVIDIA_DRIVER_JSON &&
		   terms.textDocument->url != "https://www.nvidia.com/en-us/drivers/nvidia-license/") {
			error = E_ACCESSDENIED ;
		}

		// 実配布pageの実anchorだけが規約文書の取得先originを委譲できます。
		if( error == 0 && !hasStaticHtmlDocumentLink( html, terms.textDocument->url)) {
			error = E_ACCESSDENIED ;
		}

		CollectorInspectionPageObservation documentPage ;	// 原規約だけの同I/O観測です。
		CollectorHttpTransferObservation documentTransfer ;	// 元配布pageの転送観測を上書きしません。
		std::wstring					 documentHtml ;		// 通常logへ渡さない完全原文書です。
		std::wstring					 documentFinal ;	// 別origin redirectの成功へ読み替えません。
		std::wstring					 fullText ;			// 元snapshotへ完全一致した場合だけ使用します。
		// 元API/公式リンクの成立後だけ、同取消し・応答上限の規約GETへ進みます。
		if( error == 0) {
			const auto		  &url	 = terms.textDocument->url ;	// codec確認済みのASCII HTTPSです。
			const auto		   slash = url.find( '/', 8U) ;			// exact hostだけを取得制約へ渡します。
			const std::wstring host( url.begin() + 8, url.begin() +
														 // query/認証なしです。
														 static_cast<std::ptrdiff_t>( slash)) ;
			error = http_.getCollectorInspectionPage( winrt::to_hstring( url), host, cancellation,
													 documentHtml, documentFinal, &documentPage,
													 &documentTransfer) ;
			metadata.requests += documentTransfer.attemptedRequests() ;
			metadata.bodyBytes += documentTransfer.bodyBytesRead() ;
			metadata.httpStatus = documentTransfer.terminalStatus() ;
			// 最終URLも同じ文書へ一致させ、別文書を同意へ流用しません。
			if( error == 0 && documentFinal != winrt::to_hstring( url)) {
				error = E_ACCESSDENIED ;
			}
		}

		// 旧原section/全文hashと公開revisionに一致しない改変を自動同意しません。
		if( error == 0) {
			error = verifyStaticHtmlTerms( documentHtml, *terms.textDocument->htmlExtraction,
										  winrt::to_string( source_.payloadUrl),
										  winrt::to_hstring( terms.revision), fullText) ;
		}

		// 完全照合後だけ現在のprovenanceを別JSONへ写し、元templateは不変に保ちます。
		if( error == 0) {
			using Value	 = winrt::Windows::Data::Json::JsonValue ;	// 同期私有宣言の文字列だけです。
			auto current = winrt::Windows::Data::Json::JsonObject::Parse(
				// 元宣言の独立値です。
				winrt::to_hstring( definition.staticTermsJson)) ;
			current.Insert( L"evidenceUrl", Value::CreateStringValue( documentFinal)) ;
			current.Insert( L"evidenceSha256", Value::CreateStringValue( documentPage.bodySha256)) ;
			auto document =
				// 現在の規約原byteの観測だけです。
				current.GetNamedObject( L"textDocument") ;
			document.Insert( L"sha256", Value::CreateStringValue( documentPage.bodySha256)) ;
			document.Insert( L"sizeBytes",
							Value::CreateNumberValue( static_cast<double>( documentPage.bodyBytes))) ;
			auto extraction =
				// 同じ元section/全文hashを維持します。
				document.GetNamedObject( L"htmlExtraction") ;
			extraction.Insert( L"bindingEvidenceUrl", Value::CreateStringValue( source_.rootUrl)) ;
			extraction.Insert( L"bindingEvidenceSha256",
							  Value::CreateStringValue( pageObservation_.bodySha256)) ;
			extraction.Insert(
				L"bindingEvidenceSizeBytes",
				Value::CreateNumberValue( static_cast<double>( pageObservation_.bodyBytes))) ;
			eulaRevision = winrt::to_hstring( terms.revision) ;
			error		 = computeDriverContainerSha256( winrt::to_string( fullText), eulaTextSha256) ;
			staticTerms	 = CollectorDefinitionStaticTermsObservation{
				 winrt::to_string( current.Stringify()), apiPage, documentPage} ;
		}
	}

	// 実metadataが不成立ならpayload取得の権限状態を作りません。
	if( error != 0) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = error ;
		return error ;
	}

	rootVerified_ = true ;
	const OfficialAcquisitionRequest request{
		.url			   = source_.payloadUrl,
		.providerId		   = COLLECTOR_INSPECTION_PROVIDER_ID,
		.resourceId		   = OFFICIAL_PAYLOAD_RESOURCE_ID,
		.workspaceFileName = L"inspection.zip",
		.maximumFileBytes  = maximumBytes_,
		.publishedSha256   = publishedSha256_,
		.publishedSha512   = publishedSha512_} ;	// 同実metadataにだけ結んだ共通要求です。
	// 同じ封印issuerが実byte/hashを検証した結果だけです。
	const auto acquired = session.acquireCore(
		request, workspace, *this, costReader, []( std::uint64_t, std::uint64_t) {}, cancellation,
		result, this) ;
	// 秘密値は失敗でも同一取得の終了とともに消去します。
	definitionCdn_.clear() ;
	// 非秘密metadataも同取得成功後だけcommitします。取得証拠は別途sessionへ結びます。
	if( acquired == 0 && confirmed != nullptr) {
		*confirmed = {source_,		publishedSha256_, publishedSha512_,
					  eulaRevision, eulaTextSha256,	  std::move( staticTerms)} ;
	}

	return acquired ;
} catch( const std::bad_alloc &) {
	definitionCdn_.clear() ;
	result.error = E_OUTOFMEMORY ;
	return result.error ;
} catch( ...) {
	definitionCdn_.clear() ;
	result.error = E_FAIL ;
	return result.error ;
}
} // namespace drivercrate
