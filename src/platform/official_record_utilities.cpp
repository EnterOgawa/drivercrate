//------------------------------------------------------------------------------
/**
 * @file official_record_utilities.cpp
 * @brief 公式recordの指紋表記とgrant限定取得の共通実装。
 * @version 01.00.01
 * @date 2026/10/02
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  旧AI adapterの非AI共通処理を移設。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note Fingerprint byte列と既存grant・容量・進捗検証を維持し、推論や導入は行いません。
 * @see docs/adr/0224-remove-ai-and-local-index-distribution.md
 */
//------------------------------------------------------------------------------

#include "platform/official_record_utilities.h"

#include <cstddef>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// 公式record共通処理。
//------------------------------------------------------------------------------
/**
 * @brief 既存grant限定取得と進捗一致を同じ同期境界で検証します。
 * @param[in,out] session 呼出しthreadが所有する有限取得session。
 * @param[in,out] workspace 保護保存先。共通取得器が失敗時のfile回収を担当します。
 * @param[in,out] transport 同期取得に使うHTTP境界。
 * @param[in,out] costReader 回線costの照会境界。
 * @param[in,out] grant 同じsessionへ発行済みの一回取得権限。
 * @param[in] utcClock 共通grantが要求する現在UTC秒の照会。同期呼出し中だけ借用します。
 * @param[in] networkApproved 制限／不明回線への今回の明示同意。
 * @param[in] cancellation 非blocking取消し照会。
 * @param[out] result URL非保持の取得結果。拒否時も状態とHRESULTを設定します。
 * @param[in] downloadOnlyProfile 取得専用型だけに要求する明示profile。既定は無効。
 * @return 共通取得と進捗identity一致時0、それ以外は元のHRESULT。
 * @note 型とprofile不一致は回線照会・grant消費・network開始前に拒否します。
 * @warning 成功は検査用byte取得だけであり、実行・内容合格・導入許可ではありません。
 */
//------------------------------------------------------------------------------
NativeError acquireGrantedOfficialPayload(
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialAcquisitionTransport &transport, IOfficialNetworkCostReader &costReader,
	RecordScopedDownloadGrant &grant, const std::function<std::uint64_t()> &utcClock,
	const bool networkApproved, const HttpCancellationCallback &cancellation,
	OfficialAcquisitionResult &result, const OfficialDownloadOnlyProfile downloadOnlyProfile)
{
	const auto payload = grant.payloadView() ;	// Grant所有の型・上限だけを借用する。
	const bool downloadOnly =
		// 取得専用。
		payload.kind == OfficialDistributionPayloadKind::DOWNLOAD_ONLY_FILE ;
	const auto explicitMaximum =
		// 明示予算。
		officialDownloadOnlyMaximumBytes( downloadOnlyProfile) ;
	// 型と明示profileの不一致はcost照会・grant消費・network開始前に拒否する。
	if( (downloadOnly && (explicitMaximum == 0U || explicitMaximum != payload.maximumBytes)) ||
	   (!downloadOnly && (payload.kind != OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE ||
						  downloadOnlyProfile != OfficialDownloadOnlyProfile::DISABLED))) {
		result		 = {} ;
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = static_cast<NativeError>( E_INVALIDARG) ;
		return result.error ;
	}

	std::uint64_t					   completed = 0U ;	// 最後に通知された確定受信byte数。
	std::uint64_t					   announced = 0U ;	// 応答の総byte数。0は未通知。
	const HttpDownloadProgressCallback progress =
		[&completed, &announced]( const std::uint64_t bytes, const std::uint64_t total) {
			completed = bytes ;
			announced = total ;
		} ; // 同期取得中だけ有効なstack上の数値集計先を借用する。
	const OfficialAcquisitionRequest request{.workspaceFileName =
												 downloadOnly ? L"payload.bin" : L"payload.zip",
											 .restrictedNetworkApproved = networkApproved,
											 .delegatedGrant			= &grant,
											 .delegatedGrantId			= grant.metadata().grantId,
											 .delegatedUtcNow = utcClock} ;	// 既存grantだけの要求。
	const NativeError				 error =
		session.acquire( request, workspace, transport, costReader, progress, cancellation,
						result) ;	// 非空callbackで共通validatorへ渡す。
	// 元の失敗値と回線同意待ちはそのまま呼出し側へ保持する。
	if( error != 0) {
		return error ;
	}

	// 成功結果と実通知が一致しなければ持出しへ進めない。
	if( result.state != OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   completed != result.byteCount || (announced != 0U && announced != result.byteCount)) {
		result.state = OfficialAcquisitionState::FAILURE ;
		result.error = static_cast<NativeError>( E_UNEXPECTED) ;
		return result.error ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非機密record fingerprintを小文字hexへ変換します。
 * @param[in] evidence 検証済みrecord証拠。呼出し中だけ借用します。
 * @return 元byte順を維持した固定64文字のfingerprint。
 * @note Record検証は行わず、与えられたSHA-256 byte列を表記します。
 */
//------------------------------------------------------------------------------
std::string officialRecordFingerprint( const OfficialDistributionRecordEvidence &evidence)
{
	constexpr std::string_view digits = "0123456789abcdef" ;	// 正規hex文字集合。
	std::string				   result ;							// 固定64文字の所有結果。
	result.reserve( 64U) ;
	// SHA-256の全byteを元順序のまま表記する。
	for( const auto value : evidence.stableFingerprint.bytes) {
		const auto byte = std::to_integer<unsigned>( value) ;	// unsignedへの明示変換。
		result.push_back( digits[byte >> 4U]) ;
		result.push_back( digits[byte & 15U]) ;
	}

	return result ;
}

} // namespace drivercrate
