//------------------------------------------------------------------------------
/**
 * @file signed_index_wix_content.h
 * @brief 署名索引のWiX内容証拠を同じ元配布の実ファイルへ照合する
 * @version 01.01.00
 * @date 2026/11/23
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/23  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/23  保護された元規約の再照合と本文取得を追加
 * </pre>
 *
 * @note 所有workerで同期検査する。保護領域の所有だけを引き渡し、規約同意や導入許可を発行しない
 * @see docs/adr/0572-signed-wix-burn-driver-content.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/official_preparation_operation.h"
#include "core/update_types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace drivercrate {

struct DriverArchiveInput ;
struct IndexDistributionRecord ;
struct OfficialWixDriverContent ;
struct WindowsHostPlatform ;

/** @brief 同じ保護取得物の元規約から得た一言語の表示用本文です */
struct WixTermsDocument {
	/// 署名索引に宣言された元言語タグです
	std::wstring locale ;
	/// 読み取り専用の表示にだけ使うUnicode本文です
	std::wstring body ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 封印済みWiX配布をv8索引の元規約、INFのModelsとドライバー閉包へ照合する
 * @param[in] original 検証済み署名索引から借用する同一v8レコード
 * @param[in] input 同じ配布の保護された元EXEと取得ハッシュ。呼出し中に所有者を保持する
 * @param[in] platform 同スキャンのWindowsクライアントの完全な元観測
 * @param[in] cancellation 同操作の協調取消し。空の場合は取消しを要求しない
 * @param[out] content 全照合が成功した場合だけ移す二つの保護領域と検査結果。失敗時は空
 * @param[out] retainedBytes 二つの領域で保持する実ファイルの合計byte数。元EXEは含まず失敗時は0
 * @return 成功時0、取消し、入出力、信頼又は内容の照合が不成立の場合はHRESULT
 * @throws ... 取消し関数から送出された元例外
 * @pre 呼出workerがCOMを初期化し、元索引と元取得の有効性を確認する
 * @note 通常Windows署名検証を使い、EXEやMSIを実行せず、端末適用性、規約同意や導入許可を発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectSignedIndexWixContent( const IndexDistributionRecord &original,
													   const DriverArchiveInput		 &input,
													   const WindowsHostPlatform	 &platform,
													   const PreparationCancellation &cancellation,
													   OfficialWixDriverContent		 &content,
													   std::uint64_t &retainedBytes) ;

//------------------------------------------------------------------------------
/**
 * @brief 同じWiX保護領域の各言語の元規約を再照合し、表示用の全文を作る
 * @param[in] original 同じ取得と検査に対応する認証済み元v8レコードです
 * @param[in] content 元署名とINFを確認済みの所有内容です。同期呼出しの間は解放できません
 * @param[in] cancellation 同操作の協調取消しです。空の場合は取消しを要求しません
 * @param[out] documents 元の言語順で全件を返します。一件でも失敗した場合は空です
 * @return 全原バイトと本文の確認成功0、失敗時は元I/O、形式、信頼又は取消しのHRESULT
 * @throws ... 取消し関数が送出する元例外
 * @note 表示に使う文字列だけを返します。元期限・機器の確定と同意は呼出し側で別に行います
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSignedIndexWixTerms( const IndexDistributionRecord	 &original,
												  const OfficialWixDriverContent &content,
												  const PreparationCancellation	 &cancellation,
												  std::vector<WixTermsDocument>	 &documents) ;

} // namespace drivercrate
