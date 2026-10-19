//------------------------------------------------------------------------------
/**
 * @file intel_wireless_page_parser_tests.cpp
 * @brief Intel Wireless page parser単体試験実装。
 * @version 01.00.00
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 公式pageの必須表示を一般化した架空fixtureで、欠落、重複、別host、version不整合を候補化前に拒否することを確認します。
 */
//------------------------------------------------------------------------------

#include "intel_wireless_page_parser_tests.h"

#include "platform/intel_wireless_page_parser.h"
#include "test_framework.h"

#include <string>
#include <string_view>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 試験data定義。
//------------------------------------------------------------------------------

constexpr std::wstring_view VALID_PAGE =
	LR"(<html><body><p>Intel requires an accepted license agreement</p>)"
	LR"(<p>This download includes drivers-only distribution packages for Wi-Fi version 24.60.0</p>)"
	LR"(<h2>Available Downloads</h2>)"
	LR"(<a href="https://downloadmirror.intel.com/123456/WiFi-24.60.0-Driver64-Win10-Win11.zip">)"
	LR"(Download WiFi-24.60.0-Driver64-Win10-Win11.zip</a>)"
	LR"(<span>Windows 11*, Windows 10, 64-bit*</span>)"
	LR"(<span>Size: 42.7 MB</span><span>SHA256: )"
	LR"(0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</span>)"
	LR"(<h2>Detailed Description</h2><p>Drivers only:</p></body></html>)" ;

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 正常なIntel Wireless pageを検証する。
 *
 * Driver-only x64 ZIPのversion、URL、size、hash、EULAを一つの整合した探索metadataとして取得する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidPage( TestContext &context)
{
	IntelWirelessPageMetadata metadata ;	// Parserが設定する探索区分B metadata。
	DRIVERCRATE_EXPECT( context, parseIntelWirelessDownloadPage( VALID_PAGE, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.version == L"24.60.0") ;
	DRIVERCRATE_EXPECT( context, metadata.fileName == L"WiFi-24.60.0-Driver64-Win10-Win11.zip") ;
	DRIVERCRATE_EXPECT(
		context,
		metadata.downloadUrl ==
			L"https://downloadmirror.intel.com/123456/WiFi-24.60.0-Driver64-Win10-Win11.zip") ;
	DRIVERCRATE_EXPECT( context, metadata.displaySize == L"42.7 MB") ;
	DRIVERCRATE_EXPECT( context,
					   metadata.sha256 ==
						   L"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") ;
	DRIVERCRATE_EXPECT( context, metadata.requiresEula) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 欠落とversion不整合を拒否する。
 *
 * Hash、EULAまたは紹介文versionが一致しないpageを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testMissingAndMismatchedMetadata( TestContext &context)
{
	IntelWirelessPageMetadata metadata ;					// 失敗時に空へ戻される出力。
	std::wstring			  missingHash( VALID_PAGE) ;	// SHA256 labelを欠落させるfixture。
	missingHash.replace( missingHash.find( L"SHA256:"), 7U, L"Digest:") ;
	DRIVERCRATE_EXPECT( context, !parseIntelWirelessDownloadPage( missingHash, metadata)) ;
	DRIVERCRATE_EXPECT( context, metadata.downloadUrl.empty()) ;

	std::wstring wrongVersion( VALID_PAGE) ;	// 紹介文だけを別versionにしたfixture。
	wrongVersion.replace( wrongVersion.find( L"version 24.60.0"),
						 std::wstring_view( L"version 24.60.0").size(), L"version 24.50.0") ;
	DRIVERCRATE_EXPECT( context, !parseIntelWirelessDownloadPage( wrongVersion, metadata)) ;

	std::wstring missingEula( VALID_PAGE) ;	// 明示同意表示を欠落させるfixture。
	missingEula.replace( missingEula.find( L"accepted license agreement"), 26U,
						L"download information only") ;
	DRIVERCRATE_EXPECT( context, !parseIntelWirelessDownloadPage( missingEula, metadata)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief URL hostと候補一意性を検証する。
 *
 * 類似別host、複数ZIP anchor、x86 basenameを拒否する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testUrlAndUniquenessRejections( TestContext &context)
{
	IntelWirelessPageMetadata metadata ;				// 各negative fixtureの出力。
	std::wstring			  wrongHost( VALID_PAGE) ;	// Intel以外の類似download URL。
	wrongHost.replace( wrongHost.find( L"downloadmirror.intel.com"),
					  std::wstring_view( L"downloadmirror.intel.com").size(),
					  L"downloadmirror.example.com") ;
	DRIVERCRATE_EXPECT( context, !parseIntelWirelessDownloadPage( wrongHost, metadata)) ;

	std::wstring	  duplicate( VALID_PAGE) ;							// 同じpayload anchorを二件持つ曖昧fixture。
	const std::size_t anchor	= duplicate.find( L"<a href=") ;		// 複製するanchor開始位置。
	const std::size_t anchorEnd = duplicate.find( L"</a>", anchor) ;	// Anchor終了位置。
	DRIVERCRATE_EXPECT( context, anchor != std::wstring::npos) ;
	DRIVERCRATE_EXPECT( context, anchorEnd != std::wstring::npos) ;
	// anchorの両端を取得できた場合にだけ複製し、重複候補の拒否を検証する。
	if( anchor != std::wstring::npos && anchorEnd != std::wstring::npos) {
		duplicate.insert( anchorEnd + 4U, duplicate.substr( anchor, anchorEnd + 4U - anchor)) ;
		DRIVERCRATE_EXPECT( context, !parseIntelWirelessDownloadPage( duplicate, metadata)) ;
	}

	std::wstring x86File( VALID_PAGE) ;	// Filename中のx64 markerをx86へ変更するfixture。
	std::size_t	 position{} ;			// 次に置換するDriver64 marker位置。
	// Page内の全Filename表記を置換し、一部一致による受理を防ぐ。
	while( (position = x86File.find( L"Driver64", position)) != std::wstring::npos) {
		x86File.replace( position, 8U, L"Driver32") ;
		position += 8U ;
	}

	DRIVERCRATE_EXPECT( context, !parseIntelWirelessDownloadPage( x86File, metadata)) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/intel_wireless_page_parser_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runIntelWirelessPageParserTests( TestContext &context)
{
	testValidPage( context) ;
	testMissingAndMismatchedMetadata( context) ;
	testUrlAndUniquenessRejections( context) ;
}

} // namespace drivercrate::test
