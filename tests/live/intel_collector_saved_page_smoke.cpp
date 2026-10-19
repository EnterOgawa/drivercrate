//------------------------------------------------------------------------------
/**
 * @file intel_collector_saved_page_smoke.cpp
 * @brief 保存済みIntel／ASUS本文を解析する非通信の限定smoke。
 * @version 01.02.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  保存UTF-8本文のread-only限定検証を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  ASUS保存本文と公開射影・有限読取を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  保存ASUSの公開target三状態を限定検証。
 * </pre>
 * @note 入力fileを読むだけでGET・取得・導入・製品候補生成を行いません。
 */
//------------------------------------------------------------------------------

#include "platform/intel_ethernet_windows11_record_adapter.h"
#include "platform/asus_catalog_parser.h"
#include "platform/asus_network_record_adapter.h"
#include "platform/asus_collector_target_assessment.h"
#include "core/official_source_policy.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

/**
 * @brief ASUS保存本文からLAN行と公開射影だけを検証します。
 * @param[in] html 読取専用の保存本文。公式GET証拠ではありません。
 * @return 保存資料の7行が4候補・2hash未掲載・1公開形状拒否に分かれれば0。
 */
int inspectAsus( const std::wstring_view html)
{
	drivercrate::AsusCollectorPageResult page ;								// 同一storeの有限解析結果。
	drivercrate::AsusSupportPageRequest	 request ;							// 保存資料のmodelから作る架空要求。
	std::vector<drivercrate::OfficialCollectorRecordCandidate> candidates ;	// 取得権限なしの候補。
	// 保存資料のmodelは実機targetの一致確認を代替しません。
	if( !drivercrate::parseAsusCollectorDriverPageHtml( html, L"ProArt X870E-CREATOR WIFI",
													  L"Windows 11 64-bit", L"LAN",
													  128ULL * 1024ULL * 1024ULL, page) ||
	   !drivercrate::makeAsusPublicModelSupportPageRequest( L"PROART X870E-CREATOR WIFI",
														   L"Windows 11 64-bit", request) ||
	   !drivercrate::adaptAsusCollectorNetworkRecordCandidates( page, request, 1U, candidates)) {
		std::wcerr << L"ASUS saved body rejected\n" ;
		return 9 ;
	}

	std::size_t projected = 0U ;	// URLを含まない公開射影の成立数。
	// 全行のpublic fieldも新しい共通検査へ通します。
	for( const auto &candidate : candidates) {
		drivercrate::OfficialCollectorRecordProjection projection ;	// 一候補の公開field。
		// 一件でも共通検証に失敗した場合は集計を成功にしません。
		if( drivercrate::projectOfficialCollectorRecord(
			   candidate, drivercrate::ASUS_OFFICIAL_SOURCE_POLICY_ID,
			   drivercrate::OFFICIAL_PRIMARY_METADATA_RESOURCE_ID, 1U, projection) != 0) {
			std::wcerr << L"ASUS public projection rejected\n" ;
			return 10 ;
		}

		++projected ;
	}

	constexpr std::array<drivercrate::AsusCollectorTargetQuery, 3U> ASUS_TARGETS{{
		{L"saved-board", L"ASUS", L"ProArt X870E-CREATOR WIFI", L"MAINBOARD", L"LAN",
		 L"Windows 11 64-bit", L"x64", L""},
		{L"saved-chip", L"ASUS", L"ProArt X870E-CREATOR WIFI", L"MAINBOARD", L"LAN",
		 L"Windows 11 64-bit", L"x64", L"Marvell"},
		{L"saved-other", L"ASUS", L"ProArt X870E-CREATOR WIFI D4", L"MAINBOARD", L"LAN",
		 L"Windows 11 64-bit", L"x64", L""},
	}} ; // 一致、chip欠測、別revisionの公開条件。
	std::vector<drivercrate::AsusCollectorTargetAssessment>			assessed ;	// 非機密の一時照合。
	// 保存本文の一時候補を対象別に評価し、実端末適合へ読み替えません。
	if( !drivercrate::inspectAsusCollectorTargets( page, candidates, ASUS_TARGETS, assessed) ||
	   assessed.size() != ASUS_TARGETS.size()) {
		std::wcerr << L"ASUS saved target assessment rejected\n" ;
		return 12 ;
	}

	std::wcout << L"asus-seen=" << page.seen << L" candidates=" << candidates.size()
			   << L" projections=" << projected << L" slice=" << static_cast<int>( page.sliceStatus)
			   << L'\n' ;
	// 除外行を取得成功へ混ぜず、数値理由の分母を表示します。
	for( std::size_t index = 0U; index < std::size( page.reasonCounts); ++index) {
		std::wcout << L"row-reason-" << index << L"=" << page.reasonCounts[index] << L'\n' ;
	}

	return page.targetModelMatches &&
				   page.sliceStatus == drivercrate::AsusCollectorSliceStatus::PARTIAL_REJECTED &&
				   page.seen == 7U && candidates.size() == 4U && projected == 4U &&
				   assessed[0].state == drivercrate::AsusCollectorTargetState::MATCH &&
				   assessed[0].candidateOrdinals.size() == 4U &&
				   assessed[1].state == drivercrate::AsusCollectorTargetState::UNKNOWN &&
				   assessed[1].reason == drivercrate::AsusCollectorTargetReason::CHIP_UNKNOWN &&
				   assessed[2].state == drivercrate::AsusCollectorTargetState::NO_MATCH &&
				   assessed[2].reason == drivercrate::AsusCollectorTargetReason::PRODUCT_CONFLICT &&
				   page.reasonCounts[static_cast<std::size_t>(
					   drivercrate::AsusCollectorRowReason::ACCEPTED)] == 4U &&
				   page.reasonCounts[static_cast<std::size_t>(
					   drivercrate::AsusCollectorRowReason::HASH_NOT_PUBLISHED)] == 2U &&
				   page.reasonCounts[static_cast<std::size_t>(
					   drivercrate::AsusCollectorRowReason::REJECTED_ROW)] == 1U
			   ? 0
			   : 11 ;
}

/**
 * @brief 保存本文の位置を受け、公式証拠なしの解析結果を確認します。
 * @param[in] argc 引数数。
 * @param[in] argv 旧Intel path一つ、または--asusと保存path。
 * @return 限定smokeの終了code。
 */
int wmain( const int argc, const wchar_t *const argv[])
{
	const bool asus =
		// 明示mode。
		argc == 3 && argv[1] != nullptr && std::wstring_view{argv[1]} == L"--asus" ;
	// 入力を暗黙の最新fileやnetworkから選びません。
	if( (!asus && argc != 2) || argv[1] == nullptr || (asus && argv[2] == nullptr)) {
		std::wcerr << L"usage: drivercrate_intel_collector_saved_smoke [--asus] <saved-html>\n" ;
		return 2 ;
	}

	std::ifstream input( std::filesystem::path{argv[asus ? 2 : 1]},
						std::ios::binary | std::ios::ate) ;	// 読取専用。
	// 保存資料がない場合は測定済みと記録しません。
	if( !input) {
		std::wcerr << L"saved body not readable\n" ;
		return 3 ;
	}

	const auto length = input.tellg() ;	// Allocation前に確認する長さ。
	// 有限長を確認してからbufferを確保します。
	if( length <= 0 || length > 8U * 1024U * 1024U) {
		std::wcerr << L"saved body size or read failure\n" ;
		return 4 ;
	}

	std::string bytes( static_cast<std::size_t>( length), '\0') ;	// 有限のUTF-8原本。
	input.seekg( 0) ;
	// 短い読み込みや読み取り途中の増加を成功としません。
	if( !input.read( bytes.data(), static_cast<std::streamsize>( bytes.size())) ||
	   input.peek() != std::char_traits<char>::eof() || input.bad()) {
		return 4 ;
	}

	const int units = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
										  static_cast<int>( bytes.size()), nullptr,
										  0) ;	// 不正UTF-8拒否後の必要長。
	// 変換失敗から空文字列を推測生成しません。
	if( units <= 0 || units > 4 * 1024 * 1024) {
		std::wcerr << L"saved body UTF-8 rejection\n" ;
		return 5 ;
	}

	std::wstring html( static_cast<std::size_t>( units), L'\0') ;	// Parserへ渡すUTF-16本文。
	// 実際の変換長と事前長が違う本文を拒否します。
	if( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
						   static_cast<int>( bytes.size()), html.data(), units) != units) {
		std::wcerr << L"saved body conversion mismatch\n" ;
		return 6 ;
	}

	// 明示されたASUS modeだけを別sourceの保存fixtureへ接続します。
	if( asus) {
		return inspectAsus( html) ;
	}

	constexpr std::array<drivercrate::IntelCollectorTargetQuery, 1U> TARGETS{
		{{L"saved-e610-xt2", L"Intel", L"Intel® Ethernet Network Adapter E610-XT2",
		  L"NETWORK_ADAPTER", L"Ethernet", L"Windows 11", L"x64", L""}}} ;	// 一件の公開名対照。
	drivercrate::IntelCollectorMetadataAssessment result ;					// GET出典を持たない一時評価。
	// 保存本文のparse失敗と入力契約失敗を区別します。
	if( !drivercrate::inspectIntelCollectorMetadataPage( html, TARGETS, 1U, result)) {
		std::wcerr << L"collector input rejected\n" ;
		return 7 ;
	}

	// 対象を省略した結果を表示のために参照しません。
	if( result.targets.size() != TARGETS.size()) {
		std::wcerr << L"collector target count mismatch\n" ;
		return 8 ;
	}

	std::wcout << L"release=" << result.releaseParsed << L" candidate="
			   << result.candidate.has_value() << L" identity-status="
			   << static_cast<int>( result.identity.status) << L" products="
			   << result.identity.products.size() << L" target-state="
			   << static_cast<int>( result.targets[0].state) << L" target-reason="
			   << static_cast<int>( result.targets[0].reason) << L'\n' ;
	// 合成fixtureからの期待を保存資料へ黙って流用せず、実際のparse結果をgateにします。
	return result.releaseParsed && result.candidate &&
				   result.identity.status == drivercrate::IntelCollectorIdentityStatus::ACCEPTED &&
				   result.identity.products.size() == 63U &&
				   result.targets[0].state == drivercrate::IntelCollectorTargetState::MATCH &&
				   result.targets[0].candidateOrdinal == 0U
			   ? 0
			   : 8 ;
}
