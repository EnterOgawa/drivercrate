//------------------------------------------------------------------------------
/**
 * @file official_discovery_eula_tests.cpp
 * @brief 公式自動探索EULA groupと短命同意tokenの単体試験実装。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  EULA完全一致groupの非通信試験を追加。
 * </pre>
 *
 * @note 架空Provider、package、EULAだけを使用し、network、file、driver APIを呼びません。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#include "official_discovery_eula_tests.h"

#include "platform/official_discovery_eula.h"
#include "test_framework.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

/**
 * @brief SHA-256 byte列を比較用の小文字hexへ変換する。
 * @param[in] hash 32 byteのdigest。
 * @return 64文字の小文字hex。
 */
[[nodiscard]] std::wstring hashText( const std::array<std::byte, 32U> &hash)
{
	constexpr std::wstring_view DIGITS = L"0123456789abcdef" ;	// Hex一桁の固定表。
	std::wstring				result ;						// 比較用の64文字出力。
	result.reserve( hash.size() * 2U) ;
	// Digest順を維持して各byteを上位・下位nibbleへ分ける。
	for( const std::byte value : hash) {
		const auto number = std::to_integer<unsigned int>( value) ;	// 0～255の比較用値。
		result.push_back( DIGITS[(number >> 4U) & 0x0fU]) ;
		result.push_back( DIGITS[number & 0x0fU]) ;
	}

	return result ;
}

/**
 * @brief 同一Provider・revision・本文だけを一groupへまとめることを検証する。
 * @param[in,out] context Assertion集計先。
 */
void testExactGrouping( TestContext &context)
{
	const OfficialDiscoveryBinding binding{
		.operationId = 10U, .scanSessionId = 20U, .inventoryGeneration = 30U} ;	// 開始binding。
	const std::vector<OfficialDiscoveryEulaPackage> packages{
		{.packageIdentity = L"package-a",
		 .providerId	  = L"provider-a",
		 .eulaRevision	  = L"revision-1",
		 .eulaText		  = L"abc",
		 .maximumBytes	  = 10U},
		{.packageIdentity = L"package-b",
		 .providerId	  = L"provider-a",
		 .eulaRevision	  = L"revision-1",
		 .eulaText		  = L"abc",
		 .maximumBytes	  = 20U},
		{.packageIdentity = L"package-c",
		 .providerId	  = L"provider-b",
		 .eulaRevision	  = L"revision-1",
		 .eulaText		  = L"abc",
		 .maximumBytes	  = 30U},
		{.packageIdentity = L"package-d",
		 .providerId	  = L"provider-a",
		 .eulaRevision	  = L"revision-1",
		 .eulaText		  = L"abcd",
		 .maximumBytes	  = 40U}} ;			// Providerまたは本文が異なる四payload。
	OfficialDiscoveryEulaSession session ;	// Worker thread直列利用を再現する所有session。
	DRIVERCRATE_EXPECT( context, session.beginSession( binding, packages) == 0) ;
	const auto groups = session.groups() ;	// 次のsession開始までの借用group集合。
	DRIVERCRATE_EXPECT( context, groups.size() == 3U) ;
	// 先頭二packageだけが同じ完全一致keyへまとめられる。
	if( groups.size() == 3U) {
		DRIVERCRATE_EXPECT( context, groups[0].packageIdentities.size() == 2U) ;
		DRIVERCRATE_EXPECT( context, groups[0].packageIdentities[0] == L"package-a") ;
		DRIVERCRATE_EXPECT( context, groups[0].packageIdentities[1] == L"package-b") ;
		DRIVERCRATE_EXPECT( context, groups[0].maximumTotalBytes == 30U) ;
		DRIVERCRATE_EXPECT( context,
						   hashText( groups[0].eulaTextSha256) ==
							   L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") ;
		DRIVERCRATE_EXPECT( context, groups[1].providerId == L"provider-b") ;
		DRIVERCRATE_EXPECT( context, groups[2].eulaText == L"abcd") ;
	}
}

/**
 * @brief 許可tokenを同じbindingと不変packageだけへ使用できることを検証する。
 * @param[in,out] context Assertion集計先。
 */
void testDecisionBinding( TestContext &context)
{
	const OfficialDiscoveryBinding binding{
		.operationId = 100U, .scanSessionId = 200U, .inventoryGeneration = 300U} ;	// 現在binding。
	const OfficialDiscoveryEulaPackage package{.packageIdentity = L"package-a",
											   .providerId		= L"provider-a",
											   .eulaRevision	= L"revision-1",
											   .eulaText		= L"Fixture terms.",
											   .maximumBytes =
												   1024U} ;	// 許可対象の変更不可snapshot。
	OfficialDiscoveryEulaSession	   session ;			// 一回限り判断を所有するsession。
	DRIVERCRATE_EXPECT( context, session.beginSession( binding, {&package, 1U}) == 0) ;
	const auto groups = session.groups() ;	// Token取得用の借用span。
	DRIVERCRATE_EXPECT( context, groups.size() == 1U) ;
	// Groupを作れない場合は範囲外参照を避け、後続試験を行わない。
	if( groups.size() != 1U) {
		return ;
	}

	const OfficialDiscoveryEulaGroupToken token = groups[0].token ;	// 利用者へ表示したgroup token。
	DRIVERCRATE_EXPECT( context, !session.isPackageAccepted( binding, token, package)) ;
	DRIVERCRATE_EXPECT( context, session.recordDecision( binding, token, true) == 0) ;
	DRIVERCRATE_EXPECT( context, session.isPackageAccepted( binding, token, package)) ;
	DRIVERCRATE_EXPECT( context, session.recordDecision( binding, token, false) != 0) ;

	OfficialDiscoveryEulaPackage changed = package ;	// 本文差替え拒否fixture。
	changed.eulaText += L" Changed." ;
	DRIVERCRATE_EXPECT( context, !session.isPackageAccepted( binding, token, changed)) ;
	changed = package ;
	changed.maximumBytes++ ;
	DRIVERCRATE_EXPECT( context, !session.isPackageAccepted( binding, token, changed)) ;

	OfficialDiscoveryBinding stale = binding ;	// 別inventoryへのtoken流用fixture。
	++stale.inventoryGeneration ;
	DRIVERCRATE_EXPECT( context, !session.isPackageAccepted( stale, token, package)) ;
	session.invalidate() ;
	DRIVERCRATE_EXPECT( context, !session.isPackageAccepted( binding, token, package)) ;
	DRIVERCRATE_EXPECT( context, !isOfficialDiscoveryBindingValid( session.activeBinding())) ;
}

/**
 * @brief 拒否、重複、不完全EULA、旧session tokenをfail-closedで扱うことを検証する。
 * @param[in,out] context Assertion集計先。
 */
void testRejectionAndStaleSession( TestContext &context)
{
	const OfficialDiscoveryBinding first{
		.operationId = 1U, .scanSessionId = 1U, .inventoryGeneration = 1U} ;	// 最初のsession。
	const OfficialDiscoveryEulaPackage package{.packageIdentity = L"package-a",
											   .providerId		= L"provider-a",
											   .eulaRevision	= L"revision-1",
											   .eulaText		= L"Fixture terms.",
											   .maximumBytes	= 1024U} ;	// 基準snapshot。
	OfficialDiscoveryEulaSession	   session ;							// 複数sessionの逆行拒否を保持する所有object。
	DRIVERCRATE_EXPECT( context, session.beginSession( first, {&package, 1U}) == 0) ;
	const OfficialDiscoveryEulaGroupToken oldToken = session.groups()[0].token ;	// 旧token。
	DRIVERCRATE_EXPECT( context, session.recordDecision( first, oldToken, false) == 0) ;
	DRIVERCRATE_EXPECT( context, !session.isPackageAccepted( first, oldToken, package)) ;

	const OfficialDiscoveryBinding second{
		.operationId = 2U, .scanSessionId = 2U, .inventoryGeneration = 2U} ;	// 新しいsession。
	DRIVERCRATE_EXPECT( context, session.beginSession( second, {&package, 1U}) == 0) ;
	DRIVERCRATE_EXPECT( context, session.recordDecision( second, oldToken, true) != 0) ;
	DRIVERCRATE_EXPECT( context, session.beginSession( first, {&package, 1U}) != 0) ;

	OfficialDiscoveryEulaPackage missingRevision = package ;	// 空revision拒否fixture。
	missingRevision.eulaRevision.clear() ;
	const OfficialDiscoveryBinding third{
		.operationId = 3U, .scanSessionId = 3U, .inventoryGeneration = 3U} ;	// 不正入力用binding。
	DRIVERCRATE_EXPECT( context, session.beginSession( third, {&missingRevision, 1U}) != 0) ;

	const std::array duplicate{package, package} ;	// 同じpackage IDの二重対象化fixture。
	const OfficialDiscoveryBinding fourth{
		.operationId = 4U, .scanSessionId = 4U, .inventoryGeneration = 4U} ;	// 重複入力用binding。
	DRIVERCRATE_EXPECT( context, session.beginSession( fourth, duplicate) != 0) ;
	DRIVERCRATE_EXPECT( context, session.groups().empty()) ;
}

} // namespace

/** @see official_discovery_eula_tests.h */
void runOfficialDiscoveryEulaTests( TestContext &context)
{
	testExactGrouping( context) ;
	testDecisionBinding( context) ;
	testRejectionAndStaleSession( context) ;
}

} // namespace drivercrate::test
