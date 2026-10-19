//------------------------------------------------------------------------------
/**
 * @file nvidia_winof2_catalog_parser.h
 * @brief NVIDIA Networking WinOF-2公式metadata parser定義。
 * @version 01.00.00
 * @date 2026/09/06
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note NVIDIA公式pageから委譲されたWinOF-2 JSONだけを有限な表示情報へ変換します。Package版をINF driver版へ転用せず、payload取得または
 *       installを許可しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief 実Windows OSから固定Download Center選択値へ変換した結果。 */
struct NvidiaWinof2OsSelection {
	/// Download Centerへ送る公開distribution名。
	std::wstring distribution ;
	/// 実buildを含む公式OS選択肢の完全一致値。
	std::wstring osLabel ;
} ;

/** @brief 検証済みcurrent WinOF-2配布情報。 */
struct NvidiaWinof2Release {
	/// Download Centerのcurrent package版。
	std::wstring packageVersion ;
	/// 版とx64を含む固定形式のEXE名。
	std::wstring fileName ;
	/// 公開概算size。byte上限には使用しない。
	std::wstring displaySize ;
	/// Download Centerが提示した小文字SHA-256。
	std::wstring sha256 ;
	/// 検証済み公式payload URL。UIへ渡さない。
	std::wstring downloadUrl ;
	/// 同じ版のNVIDIA Release Notes URL。
	std::wstring releaseNotesUrl ;
	/// 同じ版のNVIDIA User Manual URL。
	std::wstring userManualUrl ;
} ;

/**
 * @brief NVIDIA WinOF-2製品pageが固定Download Centerを委譲しているか確認する。
 * Iframe先だけを独立した公式originとして扱わず、委譲を毎scan確認する。
 * @param[in] html NVIDIA公式hostから取得したUTF-16 HTML。
 * @return 製品名、対象系列、iframe URLが一意に存在する場合true。 製品名、系列説明、固定iframe URLが各一件の場合true。
 */
[[nodiscard]] bool parseNvidiaWinof2LandingPage( std::wstring_view html) noexcept ;

/**
 * @brief Download Centerのversion応答から唯一のcurrent版を選ぶ。
 * ArchiveまたはLTS注釈付き版をlatestの代替として選択しない。
 * @param[in] json 固定`get_versions` POSTのUTF-16 JSON。 `get_versions`のUTF-16 JSON。
 * @param[out] version 成功時のcurrent package版。失敗時は空。
 * @return Latestがversionsとcurrent一覧の双方に一度だけ存在する場合true。 Latestがversionsとcurrent一覧に一度ずつ存在する場合true。
 */
[[nodiscard]] bool parseNvidiaWinof2Versions( std::wstring_view json, std::wstring &version) ;

/**
 * @brief Download Centerのstringまたはstring array応答を有限listへ変換する。
 * 一件時と複数件時のPHP JSON型差だけを吸収し、他型へfallbackしない。
 * @param[in] json 固定action POSTのUTF-16 JSON。
 * @param[out] values 成功時の重複しない非空値。失敗時は空。 成功時の重複しない選択肢。
 * @return Root型、件数、各値が契約内の場合true。 Stringまたはstring array全体が有限schemaを満たす場合true。
 */
[[nodiscard]] bool parseNvidiaWinof2StringList( std::wstring_view		  json,
											   std::vector<std::wstring> &values) ;

/**
 * @brief 実Windows buildをDownload Centerの明示OS選択肢へ対応付ける。
 * Client／Server同一buildをproduct typeで分離し、未知buildを拒否する。
 * @param[in] windowsServer 実OSがWindows Serverの場合true。 実OSがServerの場合true。
 * @param[in] windowsBuild 実OSのmajor build番号。0は判定不能。 実OSのmajor build。0は不明。
 * @param[out] selection 成功時の固定distributionとOS label。失敗時は空。 成功時の公開distributionとOS label。
 * @return 2026-09-06時点のcurrent版が明示するOS buildの場合true。 Current版が明示する既知buildの場合true。
 */
[[nodiscard]] bool selectNvidiaWinof2Os( bool windowsServer, std::uint32_t windowsBuild,
										NvidiaWinof2OsSelection &selection) ;

/**
 * @brief Download Centerの最終応答から一つのx64 WinOF Driverを解析する。
 * URL、file名、版、hashを同一応答内で結合し、部分結果を返さない。
 * @param[in] json 固定`get_download_info` POSTのUTF-16 JSON。 `get_download_info`のUTF-16 JSON。
 * @param[in] expectedVersion 同一scanのversion応答で選んだcurrent版。 同一scanで選んだcurrent版。
 * @param[out] release 成功時の配布情報。失敗時は初期値。 成功時の所有配布情報。
 * @return File、size、SHA-256、payload URL、二つの文書URLが整合する場合true。 一つのx64 EXE、SHA-256、二文書URLが整合する場合true。
 */
[[nodiscard]] bool parseNvidiaWinof2DownloadInfo( std::wstring_view	  json,
												 std::wstring_view	  expectedVersion,
												 NvidiaWinof2Release &release) ;

} // namespace drivercrate
