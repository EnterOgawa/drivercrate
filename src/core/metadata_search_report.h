//------------------------------------------------------------------------------
/**
 * @file metadata_search_report.h
 * @brief 情報検索専用の明示実行引数と非機密report定義。
 * @version 01.00.00
 * @date 2026/09/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  情報検索専用の非機密出力契約を追加。
 * </pre>
 *
 * @note 任意の端末表示値・URL・path・EULA本文を出力しない。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

// 完全構築したreportだけを公開する際のbyte上限。
inline constexpr std::size_t METADATA_SEARCH_REPORT_MAXIMUM_BYTES = 1024U * 1024U ;

/** @brief Test専用入口の引数を外部処理前に分類する。 */
enum class MetadataSearchCommandKind {
	/// 未知、重複または未指定集合を拒否する。
	REJECTED,
	/// 条件表示のみ。Workerとcacheを生成しない。
	DESCRIBE,
	/// 指定した集合で一回だけ情報検索する。
	RUN,
} ;

/** @brief 認識済みの用途と今回の明示集合を所有する。 */
struct MetadataSearchCommand {
	/// 引数全体の判定。既定は拒否。
	MetadataSearchCommandKind kind{MetadataSearchCommandKind::REJECTED} ;
	/// RUNだけが使う今回限りの条件。
	MetadataSearchRequest	  request ;
} ;

/**
 * @brief 実行file名を除く全引数を副作用なしで解析する。
 * @param[in] arguments 呼出し中だけ借用する入力。Provider IDは完全一致で照合。
 * @return 引数なし・describe、明示run、または拒否。拒否時は要求を空にする。
 * @note 許容する入力は固定flagと登録IDだけ。任意URL／file／cache消去flagを持たない。
 */
[[nodiscard]] MetadataSearchCommand parseMetadataSearchArguments(
	std::span<const std::wstring_view> arguments) noexcept ;

/**
 * @brief Workerを生成せず、固定予算と選択可能な登録IDをASCIIで構築する。
 * @param[out] description 成功時だけ置き換える完全な条件表示。
 * @return 上限内で全条件を構築できた場合true。
 */
[[nodiscard]] bool buildMetadataSearchDescription( std::string &description) noexcept ;

/**
 * @brief 公開結果を開始条件へ再照合し、専用schema revision 1へ変換する。
 * @param[in] operationId Controllerが発行した非ゼロ操作ID。
 * @param[in] applicationVersion CMake生成値。結果contextと完全一致を要求。
 * @param[in] request Workerへ渡した要求。結果の自己申告から補完しない。
 * @param[in] result 同一操作の全snapshot。失敗・取消しも整合時に保持する。
 * @param[out] report 成功時だけ更新する完全なASCII report。失敗時は変更しない。
 * @return 固定ID、enum、件数、消費、容量の全検証に成功した場合true。
 * @note Providerは正本registry順で出力し、入力配列を並べ替えない。
 */
[[nodiscard]] bool buildMetadataSearchReport( OperationId				  operationId,
											 std::wstring_view			  applicationVersion,
											 const MetadataSearchRequest &request,
											 const ScanResult			 &result,
											 std::string				 &report) noexcept ;

} // namespace drivercrate
