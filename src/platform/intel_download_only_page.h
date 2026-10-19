//------------------------------------------------------------------------------
/**
 * @file intel_download_only_page.h
 * @brief Intel共通heroから非実行取得recordを構築します。
 * @version 01.01.00
 * @date 2026/09/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/23  取得専用の公式起点とparser契約を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加。
 * </pre>
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_download_grant.h"

namespace drivercrate {

/// 検証済み公式moduleの同一origin相対path。任意scriptへ一般化しません。
inline constexpr std::wstring_view INTEL_DOWNLOAD_BEHAVIOR_PATH =
	L"/etc.clientlibs/intel/clientlibs/bundles/resources/js/downloadcenter.components.content.dcPageLicenseModal.script.d5fff54a.bundle.js" ;
/// 非実行で固定照合する原byteのSHA-256です。
inline constexpr std::wstring_view INTEL_DOWNLOAD_BEHAVIOR_SHA256 =
	L"4e2534009f94d0dd77c2a8254d0b120afed9934afe7d11236e0ac0138d5cc359" ;

/** @brief 共通HTTPでfresh取得した既知moduleの観測です。 */
struct IntelDownloadBehaviorObservation {
	/// 同一sessionのmetadata GET根拠です。
	OfficialSourceEvidence evidence ;
	/// 共通SHA-256計算で得た原byteのdigestです。
	std::wstring		   sha256 ;
	/// 応答の原byte数です。
	std::uint64_t		   byteCount{} ;
} ;

/** @brief 開発評価用の明示公式起点です。 */
enum class IntelDownloadOnlySource {
	/// Intel Wireless Bluetooth公式配布pageです。
	BLUETOOTH,
	/// Intel Arc Graphics公式配布pageです。
	ARC_GRAPHICS
} ;

/** @brief Payload URLを含まない固定公式起点です。 */
struct IntelDownloadOnlySourceDefinition {
	/// 起点pageの固定HTTPS URLです。
	std::wstring_view landingUrl ;
	/// 公式policy内の起点用途です。
	std::wstring_view resourceId ;
	/// 公開製品系列です。実機適合判定には使いません。
	std::wstring_view productFamily ;
	/// 公式recordの公開keyです。
	std::wstring_view recordKey ;
} ;

/**
 * @brief 明示sourceの固定起点だけを返します。
 * @param[in] source 明示評価source。
 * @return 既知sourceの定義。未知enumはnullptr。
 */
[[nodiscard]] const IntelDownloadOnlySourceDefinition *intelDownloadOnlySourceDefinition(
	IntelDownloadOnlySource source) noexcept ;

/**
 * @brief 同一HTML内の単一download heroとEULAを取得専用recordへ結合します。
 * @param[in] source 明示した固定起点。
 * @param[in] html 同じ公式GET応答。2 Mi文字以下。
 * @param[in] rootEvidence そのGETの公式根拠。
 * @param[in] profile 呼出元が明示した有限取得上限。
 * @param[in] resolvedUtcSeconds 解決時刻。
 * @param[out] record 全検証成功時だけ公開する取得専用record。
 * @param[in] behavior 空raw欄の独立判定に必要なfresh module観測。既定では許可しません。
 * @param[out] failureStage 非秘密の拒否段階。成功時0。
 * @return 一意な配布・hash・EULA・公式根拠を結合できた場合true。
 * @note 内容検査・署名確認・実機適合・installer実行は行いません。
 */
[[nodiscard]] bool parseIntelDownloadOnlyPage(
	IntelDownloadOnlySource source, std::wstring_view html,
	const OfficialSourceEvidence &rootEvidence, OfficialDownloadOnlyProfile profile,
	std::uint64_t resolvedUtcSeconds, OfficialDistributionRecord &record,
	std::uint32_t &failureStage, const IntelDownloadBehaviorObservation *behavior = nullptr) ;
} // namespace drivercrate
