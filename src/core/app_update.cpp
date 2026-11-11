//------------------------------------------------------------------------------
/**
 * @file app_update.cpp
 * @brief App版比較と24時間の非通信policyを実装します。
 * @version 01.00.01
 * @date 2026/11/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/11  App専用の通知付き更新を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note URLは固定repo/tag/assetからだけ生成します。
 * @see docs/adr/0481-app-inno-setup-and-update-checks.md
 */
//------------------------------------------------------------------------------
#include "core/app_update.h"
#include <limits>

namespace drivercrate {
//------------------------------------------------------------------------------
/**
 * @brief ASCIIのcanonical三要素版をoverflowなしで読みます。
 * @param[in] text ASCIIの三要素版です。text.size() byteのviewを呼出し中だけ借用し、NUL終端を要求せず保持しません。
 * @return 全て成立した値。不正はnulloptです。
 */
//------------------------------------------------------------------------------
std::optional<AppVersion> parseAppVersion( const std::string_view text) noexcept
{
	AppVersion	result ;		// 一致した三要素だけを返します。
	std::size_t position{} ;	// 次に読むASCII位置です。
	// 有限三要素を各16bitへ制限します。
	for( std::size_t component{}; component < result.parts.size(); ++component) {
		const auto	  begin = position ;	// 先頭0と空要素の判定位置です。
		std::uint32_t value{} ;				// overflow前に上限を検査します。
		// 十進数字だけを各要素の終端まで読みます。
		while( position < text.size() && text[position] >= '0' && text[position] <= '9') {
			const auto digit = static_cast<unsigned>( text[position] - '0') ;	// ASCIIの一桁です。
			// 乗算前に16bitの範囲へ閉じます。
			if( value > (65535U - digit) / 10U) {
				return std::nullopt ;
			}

			value = value * 10U + digit ;
			++position ;
		}

		// 欠損とcanonicalでない先頭0を拒否します。
		if( position == begin || (position - begin > 1U && text[begin] == '0')) {
			return std::nullopt ;
		}

		result.parts[component] = static_cast<std::uint16_t>( value) ;
		// 最後以外には区切りをちょうど一個要求します。
		if( component + 1U < result.parts.size()) {
			// 不足要素やsuffixを補完しません。
			if( position >= text.size() || text[position++] != '.') {
				return std::nullopt ;
			}
		}
	}

	// 全入力の一致だけを返します。
	if( position != text.size()) {
		return std::nullopt ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief canonicalな三要素版を表示と固定tag用に作ります。
 * @param[in] version 表示する版。
 * @return major.minor.patchのASCII文字列。
 */
//------------------------------------------------------------------------------
std::string formatAppVersion( const AppVersion &version)
{
	return std::to_string( version.parts[0]) + "." + std::to_string( version.parts[1]) + "." +
		   std::to_string( version.parts[2]) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 正しい版・size/hashだけをSetup取得へ渡します。
 * @param[in] release 検査対象の宣言。
 * @return sizeとhashが正しい場合はtrue。
 */
//------------------------------------------------------------------------------
bool validAppUpdateRelease( const AppUpdateRelease &release) noexcept
{
	// 取得上限と正確なdigest長を先に要求します。
	if( release.sizeBytes == 0U || release.sizeBytes > APP_UPDATE_MAX_BYTES ||
	   release.sha256.size() != 64U) {
		return false ;
	}

	// 小文字のhex以外をURL取得の宣言として扱いません。
	for( const char digit : release.sha256) {
		// 正規化済みのASCIIだけを受理します。
		if( !((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f'))) {
			return false ;
		}
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 公式repoと正確asset名だけの起点を組み立てます。
 * @param[in] release 正しい版・size/hashを持つ宣言。
 * @return 成立時の固定HTTPS URL。不正時は空文字列です。
 */
//------------------------------------------------------------------------------
std::wstring appUpdateAssetUrl( const AppUpdateRelease &release)
{
	// 任意宣言からのURL組立てを拒否します。
	if( !validAppUpdateRelease( release)) {
		return {} ;
	}

	const auto version = formatAppVersion( release.version) ;	// ASCIIのcanonical版です。
	return L"https://github.com/EnterOgawa/drivercrate/releases/download/v" +
		   std::wstring( version.begin(), version.end()) + L"/DriverCrateSetup-windows-x64.exe" ;
}
//------------------------------------------------------------------------------
/**
 * @brief 初回または24h期限の到来を照会します。
 * @param[in] nowMilliseconds 現在の単調millisecond。
 * @return 期限に達している場合はtrue。
 */
//------------------------------------------------------------------------------
bool AppUpdateSchedule::due( const std::uint64_t nowMilliseconds) noexcept
{
	// 時計逆行を即時確認にせず、新しい24hへ送り直します。
	if( scheduled_ && nowMilliseconds < lastNow_) {
		attempted( nowMilliseconds) ;
	}

	lastNow_ = nowMilliseconds ;
	return !scheduled_ || nowMilliseconds >= nextDue_ ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実際に受理した一回から次の24hを予約します。
 * @param[in] nowMilliseconds 受理時の単調millisecond。
 */
//------------------------------------------------------------------------------
void AppUpdateSchedule::attempted( const std::uint64_t nowMilliseconds) noexcept
{
	scheduled_ = true ;
	lastNow_   = nowMilliseconds ;
	nextDue_ = nowMilliseconds > std::numeric_limits<std::uint64_t>::max() - APP_UPDATE_INTERVAL_MS
				   ? std::numeric_limits<std::uint64_t>::max()
				   : nowMilliseconds + APP_UPDATE_INTERVAL_MS ;
}
}
