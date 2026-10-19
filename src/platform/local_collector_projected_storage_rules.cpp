//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_storage_rules.cpp
 * @brief 旧世代へ新応答を混入させない固定許可表を実装します。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  旧応答との排他と新終端の形状検査を追加。
 * </pre>
 *
 * @note File I/Oを行わず、既存保存回復の受理条件を変更しません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#include "local_collector_projected_storage_rules.h"
#include "platform/local_collector_projected_json.h"

namespace drivercrate {
/** @see local_collector_projected_storage_rules.h */
CollectorStoredResponseVersion collectorStoredResponseVersion( bool v2, bool v3, bool v4) noexcept
{
	// どの二版の併存も拒否し、新しい版を暗黙に優先しない。
	if( (v2 && v3) || (v2 && v4) || (v3 && v4)) {
		return CollectorStoredResponseVersion::CONFLICT ;
	}

	return v2	? CollectorStoredResponseVersion::V2
		   : v3 ? CollectorStoredResponseVersion::V3
		   : v4 ? CollectorStoredResponseVersion::V4
				: CollectorStoredResponseVersion::ABSENT ;
}
/** @see local_collector_projected_storage_rules.h */
std::optional<std::wstring> collectorResponseFileName( CollectorStoredResponseVersion version,
													  std::wstring_view				 operation)
{
	// Oをpath fragmentとして扱う前に固定hexだけへ制限する。
	if( !collector_projected_json::isHash( operation)) {
		return std::nullopt ;
	}

	std::wstring_view prefix ;	// 有限版に対応した組み込み保存名。
	// 存在判定のABSENT／CONFLICTを保存版へ読み替えない。
	switch( version) {
		// 旧非制御応答と欠測中断。
		case CollectorStoredResponseVersion::V2:
			prefix = L"runs/campaign-response-v2-" ;
			break ;

		// 旧制御I/O応答。
		case CollectorStoredResponseVersion::V3:
			prefix = L"runs/campaign-response-v3-" ;
			break ;

		// 新射影応答。
		case CollectorStoredResponseVersion::V4:
			prefix = L"runs/campaign-response-v4-" ;
			break ;

		// 未知版を含め保存名を発行しない。
		default:
			return std::nullopt ;
	}

	return std::wstring( prefix) + std::wstring( operation) + L".json" ;
}
/** @see local_collector_projected_storage_rules.h */
bool collectorResponseVersionAllowed( std::uint32_t					storageVersion,
									 CollectorStoredResponseVersion version,
									 std::wstring_view state, bool hasObservation) noexcept
{
	const bool oldTerminal =
		// 旧集合。
		state == L"OBSERVED" || state == L"FAILED" || state == L"HELD" ;
	// 登録v2は旧応答だけを許し、v3ではI/O欠測を認めない。
	if( storageVersion == 2U) {
		return (version == CollectorStoredResponseVersion::V2 && !hasObservation &&
				(oldTerminal || state == L"INTERRUPTED")) ||
			   (version == CollectorStoredResponseVersion::V3 && hasObservation && oldTerminal) ;
	}

	// 新世代の元観測はv4だけで、欠測中断だけは旧v2名を維持する。
	if( storageVersion == 3U) {
		return (version == CollectorStoredResponseVersion::V2 && !hasObservation &&
				state == L"INTERRUPTED") ||
			   (version == CollectorStoredResponseVersion::V4 && hasObservation &&
				(state == L"FETCHED" || state == L"REVALIDATED" || state == L"FAILED" ||
				 state == L"HELD")) ;
	}

	return false ;
}
/** @see local_collector_projected_storage_rules.h */
bool collectorProjectedStateShapeAllowed( std::wstring_view state, bool hasIntent,
										 CollectorStoredResponseVersion version,
										 std::wstring_view				responseSha256,
										 std::wstring_view				operation) noexcept
{
	const bool absent = version == CollectorStoredResponseVersion::ABSENT &&
						// 非終端の一貫した欠測。
						responseSha256.empty() && operation.empty() ;
	// 予約前二状態にはintentや応答を保持しない。
	if( state == L"PENDING" || state == L"DEFERRED") {
		return !hasIntent && absent ;
	}

	// 実行中は元intentだけを持ち、完了応答を混ぜない。
	if( state == L"RUNNING") {
		return hasIntent && absent ;
	}

	// 全終端に実hashと元Oを要求する。空や大文字で補完しない。
	if( !collector_projected_json::isHash( responseSha256) ||
	   !collector_projected_json::isHash( operation)) {
		return false ;
	}

	// Intent保存前の中断も存在するため、中断だけはintent欠測を維持する。
	if( state == L"INTERRUPTED") {
		return version == CollectorStoredResponseVersion::V2 ;
	}

	return hasIntent && version == CollectorStoredResponseVersion::V4 &&
		   (state == L"FETCHED" || state == L"REVALIDATED" || state == L"FAILED" ||
			state == L"HELD") ;
}
} // namespace drivercrate
