//------------------------------------------------------------------------------
/**
 * @file official_collector_public_text.cpp
 * @brief 収集専用の公開文字列形状とUTF-8上限を検証します。
 * @version 01.01.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  metadata専用公開値境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  公開値の内側走査へ明示制御を伝播。
 * </pre>
 */
//------------------------------------------------------------------------------

#include "platform/official_collector_public_text.h"

#include <array>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

/**
 * @brief ASCII大小文字に依存せず端末識別子形状を見つけます。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] value 有限の公開field。
 * @return PnP識別子のmarkerを含む場合true。
 */
[[nodiscard]] bool hasDeviceMarker( CollectorParserContext *control, const std::wstring_view value)
{
	collectorParserCheckpoint( control) ;
	constexpr std::array<std::wstring_view, 5U> MARKERS{L"VEN_", L"DEV_", L"VID_", L"PID_",
														L"SUBSYS_"} ;	// 固定形状。
	// 最大1,024文字の各位置で有限markerだけを比較します。
	for( std::size_t offset = 0U; offset < value.size(); ++offset) {
		collectorParserStep( control) ;
		// 一致した一形状だけで公開候補を拒否します。
		for( const auto marker : MARKERS) {
			collectorParserStep( control) ;
			// 残りが短い場合は後続のmarkerを試します。
			if( marker.size() > value.size() - offset) {
				continue ;
			}

			bool equal = true ;	// 現在の形状比較。
			// ASCIIだけを大文字化し、Unicode正規化を追加しません。
			for( std::size_t index = 0U; index < marker.size(); ++index) {
				collectorParserStep( control) ;
				wchar_t ch = value[offset + index] ;	// 元の一文字。
				// 英小文字だけを有限に変換します。
				if( ch >= L'a' && ch <= L'z') {
					ch = static_cast<wchar_t>( ch - L'a' + L'A') ;
				}

				equal = equal && ch == marker[index] ;
			}

			// 端末ID形状はsource由来でも公開表示へ保存しません。
			if( equal) {
				return true ;
			}
		}
	}

	return false ;
}

/**
 * @brief Slashを含むfieldの文法を限定します。
 * @param[in] value 有限field。
 * @param[in,out] control 新経路の制御。旧wrapperだけnull。
 * @param[in] kind Field別文法。
 * @return Slashなし、または指定文法で許される場合true。
 */
[[nodiscard]] bool validSlash( CollectorParserContext *control, const std::wstring_view value,
							  const OfficialCollectorPublicTextKind kind)
{
	collectorParserCheckpoint( control) ;
	const auto slash = collectorParserFind( control, value, L'/') ;	// 最初の区切り。
	// Slashなしは一般文字検査へ委譲します。
	if( slash == value.npos) {
		return true ;
	}

	// 日付に限り二つの固定区切りとASCII数字を許します。
	if( kind == OfficialCollectorPublicTextKind::DATE) {
		// 実在日付の意味検査は元parserが行います。
		if( value.size() != 10U || value[4] != L'/' || value[7] != L'/') {
			return false ;
		}

		// 区切り以外にpath文字を認めません。
		for( std::size_t index = 0U; index < value.size(); ++index) {
			collectorParserStep( control) ;
			// ASCII数字だけを受理します。
			if( index != 4U && index != 7U && (value[index] < L'0' || value[index] > L'9')) {
				return false ;
			}
		}

		return true ;
	}

	// MIMEは空でない二tokenの間の一つだけを許します。
	if( kind != OfficialCollectorPublicTextKind::CONTENT_TYPE || slash == 0U ||
	   slash + 1U == value.size() ||
	   collectorParserFind( control, value, L'/', slash + 1U) != value.npos) {
		return false ;
	}

	// Dot segmentや相対pathをMIMEの例外文法へ潜り込ませません。
	if( value.front() < L'a' || value.front() > L'z' ||
	   !((value[slash + 1U] >= L'a' && value[slash + 1U] <= L'z') ||
		 (value[slash + 1U] >= L'0' && value[slash + 1U] <= L'9'))) {
		return false ;
	}

	// MIME tokenの有限ASCII集合以外をpathとして通しません。
	for( const wchar_t ch : value) {
		collectorParserStep( control) ;
		// 通常recordのMIME構文検証と同じ文字集合です。
		if( !((ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9') || ch == L'/' || ch == L'.' ||
			 ch == L'+' || ch == L'-')) {
			return false ;
		}
	}

	return true ;
}

} // namespace

//------------------------------------------------------------------------------
// 公開関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 公開fieldの同じ形状・文字数検証を共有します。
 * @param[in,out] control 新経路の制御。旧経路だけnull。
 * @param[in] value 公開値。
 * @param[in] maximumBytes UTF-8上限。
 * @param[in] kind Slash文法。
 * @return 公開契約の成立。
 */
static bool isOfficialCollectorPublicTextCore( CollectorParserContext			   *control,
											  const std::wstring_view				value,
											  const std::size_t						maximumBytes,
											  const OfficialCollectorPublicTextKind kind)
{
	collectorParserCheckpoint( control) ;
	// 不正な契約や最小byte数で既に上限外の値は走査しません。
	if( maximumBytes == 0U || maximumBytes > 1'024U || value.size() > maximumBytes ||
	   !validSlash( control, value, kind) || hasDeviceMarker( control, value)) {
		return false ;
	}

	std::size_t bytes = 0U ;	// 正規UTF-8に必要なbyte数。
	// UTF-16を一方向に検証し、allocationなしでbyte数を算出します。
	for( std::size_t index = 0U; index < value.size(); ++index) {
		collectorParserStep( control) ;
		const wchar_t ch = value[index] ;	// 現在のcode unit。
		// 不可視制御・markup・path／query形状を拒否します。
		if( ch < L' ' || (ch >= 0x7f && ch <= 0x9f) || ch == L'\\' || ch == L':' || ch == L'?' ||
		   ch == L'#' || ch == L'=' || ch == L'<' || ch == L'>' || (ch >= 0xdc00 && ch <= 0xdfff)) {
			return false ;
		}

		// 高位surrogateは必ず低位surrogateと対にします。
		if( ch >= 0xd800 && ch <= 0xdbff) {
			++index ;
			// 不完全なUnicodeは公開しません。
			if( index == value.size() || value[index] < 0xdc00 || value[index] > 0xdfff) {
				return false ;
			}

			bytes += 4U ;
		} else {
			bytes += ch <= 0x7f ? 1U : (ch <= 0x7ff ? 2U : 3U) ;
		}
	}

	return bytes <= maximumBytes ;
}

/** @see official_collector_public_text.h */
bool isOfficialCollectorPublicText( std::wstring_view value, std::size_t maximumBytes,
								   OfficialCollectorPublicTextKind kind) noexcept
{
	return isOfficialCollectorPublicTextCore( nullptr, value, maximumBytes, kind) ;
}

/** @see official_collector_public_text.h */
bool isOfficialCollectorPublicTextForCollector( std::wstring_view value, std::size_t maximumBytes,
											   OfficialCollectorPublicTextKind kind,
											   CollectorParserContext		  &context)
{
	return isOfficialCollectorPublicTextCore( &context, value, maximumBytes, kind) ;
}
} // namespace drivercrate
