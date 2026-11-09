//------------------------------------------------------------------------------
/**
 * @file pending_reference_version_tests.cpp
 * @brief 取得前の版比較とsession/現在観測不足の非導入回帰。
 * @version 01.00.00
 * @date 2026/11/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  新版/同版/旧版/不明と元選択境界を確認。
 * </pre>
 * @note 全deviceと版は架空です。Windows適合・導入許可・networkを使用しません。
 * @see docs/adr/0428-newer-index-reference-confirmation.md
 */
//------------------------------------------------------------------------------
#include "core/pending_reference_version.h"
#include "core/candidate_audit.h"
#include "core/provider_registry.h"
#include <array>
#include <cstdio>
#include <string_view>

namespace {
unsigned assertions{} ;	// 固定期待の分母です。
unsigned failures{} ;	// 失敗を後続成功で隠しません。
/** @brief 固定期待を数値だけで集計します。
 * @param[in] value 実際の期待成立値。
 */
void	 expect( const bool value)
{
	++assertions ;
	// 任意の文字列本文を出力しません。
	if( !value) {
		++failures ;
		std::printf( "FAIL assertion=%u\n", assertions) ;
	}
}
/** @brief 有効な登録済み現在行と同deviceの非導入参照を作ります。
 * @return 架空の二行。私有導入tokenを持ちません。
 */
std::array<drivercrate::UpdateCandidate, 2U> sample()
{
	using namespace drivercrate ;
	std::array<UpdateCandidate, 2U> rows ;				// 架空の同scan snapshotです。
	auto						   &current = rows[0] ;	// 一意な現在行です。
	current.identity						= L"fixture-current" ;
	current.deviceIdentity					= L"fixture-device" ;
	current.providerId						= DRIVER_STORE_PROVIDER_ID ;
	current.discoveryBasis					= CandidateDiscoveryBasis::LOCAL_INVENTORY ;
	current.current							= true ;
	current.version							= L"1.2.3.4" ;
	current.deviceClassGuid					= L"{4d36e96c-e325-11ce-bfc1-08002be10318}" ;
	current.deviceObservation.emplace() ;
	auto &observed			  = *current.deviceObservation ;	// 同sessionへ結合する観測です。
	observed.scanSessionId	  = 8U ;
	observed.deviceIdentity	  = current.deviceIdentity ;
	observed.node.read.state  = DevicePropertyReadState::VALUE ;
	observed.node.statusFlags = 0U ;
	observed.driverKey.state  = DevicePropertyReadState::VALUE ;
	observed.version.state	  = DevicePropertyReadState::VALUE ;
	observed.driverPresence	  = DeviceDriverPresence::REGISTERED ;
	auto &reference			  = rows[1] ;	// 記述済みの取得前形状だけです。
	reference.identity		  = L"fixture-reference" ;
	reference.deviceIdentity  = current.deviceIdentity ;
	reference.deviceClassGuid = current.deviceClassGuid ;
	reference.providerId	  = SIGNED_INDEX_PROVIDER_ID ;
	reference.discoveryBasis  = CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
	reference.version		  = L"1.2.3.5" ;
	reference.preparationTargetIdentity = L"fixture-target" ;
	reference.audit.sourceOrigin		= CandidateAuditGateState::PASSED ;
	return rows ;
}
/** @brief 十三個の不足と正当な新版/同版/旧版を同じ純粋入口へ通します。 */
void run()
{
	using namespace drivercrate ;
	auto rows = sample() ;	// 元target/sessionと非導入flagを保持します。
	expect( isCandidateDetailsValid( rows[0], 8U) && isCandidateDetailsValid( rows[1], 8U)) ;
	expect( classifyPendingReferenceVersion( rows[1], rows, 8U) == PendingReferenceVersion::NEWER) ;
	expect( !rows[1].installable && !rows[1].recommended && rows[1].action == DriverAction::NONE &&
		   rows[1].packageIdentity.empty() &&
		   rows[1].preparationTargetIdentity == L"fixture-target") ;
	rows[1].version = L"1.2.3.4" ;
	expect( classifyPendingReferenceVersion( rows[1], rows, 8U) == PendingReferenceVersion::SAME) ;
	rows[1].version = L"1.2.2.65535" ;
	expect( classifyPendingReferenceVersion( rows[1], rows, 8U) == PendingReferenceVersion::OLDER) ;
	// 毎回独立した元snapshotへ一つだけ不足を加えます。
	for( unsigned mode{}; mode < 15U; ++mode) {
		rows = sample() ;
		// 各固定不足はUNKNOWNへ保持し、別driverや新しいsessionで補いません。
		switch( mode) {
			// 現在版欠損。
			case 0U:
				rows[0].version.clear() ;
				break ;

			// 公表版欠損。
			case 1U:
				rows[1].version.clear() ;
				break ;

			// 現在版の読取り未確認。
			case 2U:
				rows[0].deviceObservation->version.state = DevicePropertyReadState::NOT_READ ;
				break ;

			// 登録状態未知。
			case 3U:
				rows[0].deviceObservation->driverKey.state = DevicePropertyReadState::NOT_READ ;
				rows[0].deviceObservation->driverPresence  = DeviceDriverPresence::UNKNOWN ;
				break ;

			// 初回観測を通常更新に変換しません。
			case 4U:
				rows[0].deviceObservation->node.statusFlags = 0x400U ;
				rows[0].deviceObservation->node.problemCode = 28U ;
				rows[0].deviceObservation->driverPresence	= DeviceDriverPresence::NOT_INSTALLED ;
				break ;

			// 旧session。
			case 5U:
				rows[0].deviceObservation->scanSessionId = 7U ;
				break ;

			// 別device。
			case 6U:
				rows[0].deviceObservation->deviceIdentity = L"other-fixture-device" ;
				break ;

			// Class不足。
			case 7U:
				rows[1].deviceClassGuid.clear() ;
				break ;

			// 元target不足。
			case 8U:
				rows[1].preparationTargetIdentity.clear() ;
				break ;

			// 私有記述を経ない他Provider。
			case 9U:
				rows[1].providerId = DRIVER_STORE_PROVIDER_ID ;
				break ;

			// 実候補の別actionを参照比較へ混ぜません。
			case 10U:
				rows[1].installable = true ;
				break ;

			// 不正な現在版。
			case 11U:
				rows[0].version = L"bundle-1.2.3.4" ;
				break ;

			// 取得済み参照。
			case 12U:
				rows[1].audit.inspectionDownload = CandidateAuditGateState::PASSED ;
				break ;

			// 取得元根拠不足。
			case 13U:
				rows[1].audit.sourceOrigin = CandidateAuditGateState::PENDING ;
				break ;

			// 終端失効後の参照。
			default:
				rows[1].preparationTargetIdentity.clear() ;
				break ;
		}

		expect( classifyPendingReferenceVersion( rows[1], rows, 8U) ==
			   PendingReferenceVersion::UNKNOWN) ;
	}

	rows = sample() ;
	const std::array duplicated{rows[0], rows[0], rows[1]} ;	// 複数現在行を拒否します。
	expect( classifyPendingReferenceVersion( rows[1], duplicated, 8U) ==
		   PendingReferenceVersion::UNKNOWN) ;
	expect( classifyPendingReferenceVersion( rows[1], rows, 0U) == PendingReferenceVersion::UNKNOWN) ;
	// 省略・overflow・suffixを正規版へ補完しません。
	for( const std::wstring_view version :
		{L"", L"1.2.3", L"1.2.3.4.5", L"1.2.3.65536", L"1..3.4", L"1.2.3.4x", L"-1.2.3.4"}) {
		expect( !parseFourPartDriverVersion( version)) ;
	}

	expect( parseFourPartDriverVersion( L"65535.65535.65535.65535") == UINT64_MAX) ;
}
}
/** @brief 非通信の有限比較回帰だけを実行します。
 * @return 全期待成立0。それ以外1。
 */
int main()
{
	run() ;
	std::printf( "assertions=%u failures=%u\n", assertions, failures) ;
	return failures == 0U ? 0 : 1 ;
}
