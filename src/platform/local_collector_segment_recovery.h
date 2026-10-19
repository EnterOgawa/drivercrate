//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_recovery.h
 * @brief 回復候補byteの有限結合検査を能力発行から分離します。
 * @version 01.00.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  全像とintent／ROOT／元head記録の非保存decoderを追加。
 * </pre>
 *
 * @note 借用byteだけの検査です。実file由来・旧根拠・回復予約・通信許可は発行しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_segment_switch.h"
#include <Windows.h>
#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace drivercrate {
/** @brief 呼出し中だけ借用する固定回復入力です。任意pathやhash証明ではありません。 */
struct CollectorSegmentRecoveryBytes {
	/// 同じintentの固定envelopeです。最大2 MiB、本文16 KiBです。
	std::string_view				  intent ;
	/// 同intentの元head保持記録です。未保存だけは空です。
	std::string_view				  activation ;
	/// 専用初期ROOTのenvelopeです。本文16 KiBです。
	std::string_view				  root ;
	/// 親の現在headです。最大2 MiB、本文256 KiBです。
	std::string_view				  head ;
	/// 予算／group／全64requestの元順序です。空像を補完しません。
	std::array<std::string_view, 66U> images ;
} ;
/** @brief 全byte結合後だけの所有値です。実handle・保存能力を持ちません。 */
struct CollectorSegmentRecoveryState {
	/// 全66本文から既存coreで再導出し、元intentと一致したdraftです。
	CollectorSegmentSwitchDraft	  draft ;
	/// 全像のcodecと未精算0を検査した値です。旧実台帳との一致証明ではありません。
	CollectorSharedLedgerSnapshot carried ;
	/// 現在headまたは元保持記録から取り出し、元intent本文hashへ結合したrawです。
	std::string					  oldHeadRaw ;
	/// 固定17fieldから再導出した初期ROOT本文の実CNG hashです。
	std::wstring				  initialRootSha256 ;
	/// 記録未保存0／記録保存1／登録head2／最終head3です。失敗時は0です。
	std::size_t					  saved{} ;
} ;
/** @brief 初回区間切替の四保存状態を有限byteから非変更で検査します。
 * @param[in] bytes 同期呼出し中に生存し、変更されない全借用rawです。
 * @param[out] state 成功時だけの所有値です。全失敗時は空です。
 * @return 成功0、内容13、有限枠68、未対応ordinal50、確保8、第一CNG errorです。
 * @pre 入力の借用領域と出力の所有領域をaliasさせないでください。
 * @note 保存・時計採取・実file読取り・HTTP・能力発行を行いません。旧全rawの実照合は別入口です。
 */
[[nodiscard]] DWORD decodeCollectorSegmentRecovery( const CollectorSegmentRecoveryBytes &bytes,
												   CollectorSegmentRecoveryState &state) noexcept ;
} // namespace drivercrate
