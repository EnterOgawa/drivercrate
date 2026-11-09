//------------------------------------------------------------------------------
/**
 * @file official_mapped_file.h
 * @brief 通常入力fileの固定読取りと所有一時fileの有界mappingを定義する。
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  固定handleと私有file-backed mappingを追加。
 * </pre>
 *
 * @note 全mappingの寿命は所有handle内に限定し、入力は変更せず、出力は自身の新規fileだけを削除する。
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace drivercrate {
class OfficialDownloadWorkspace ;

/** @brief 固定入力または所有一時出力のmappingとhandleを単独所有する。 */
class OfficialMappedFile final {
public:
	/** @brief 未取得の空ownerを作る。 */
	OfficialMappedFile() noexcept ;
	/** @brief viewとhandleを閉じ、所有一時fileだけを回収する。 */
	~OfficialMappedFile() ;
	/** @brief mappingの複写所有を禁止する。 */
	OfficialMappedFile( const OfficialMappedFile &) = delete ;
	/** @brief 所有handleの複写代入を禁止する。 */
	OfficialMappedFile &operator=( const OfficialMappedFile &) = delete ;
	/** @brief 借用spanのownerを移動しない。 */
	OfficialMappedFile( OfficialMappedFile &&) = delete ;
	/** @brief 借用spanのownerを移動代入しない。 */
	OfficialMappedFile		 &operator=( OfficialMappedFile &&) = delete ;
	/**
	 * @brief 非reparse通常fileをwrite/delete共有なしで固定し、read-only viewを作る。
	 * @param[in] path local絶対path。先祖directoryも固定する。
	 * @param[in] maximumBytes 空でない入力の有限上限。
	 * @return 全取得成功0、失敗時は空ownerと元HRESULT。
	 */
	[[nodiscard]] NativeError open( std::wstring_view path, std::uint64_t maximumBytes) ;
	/**
	 * @brief 所有workspaceの新規fileだけへ有限なread/write viewを作る。
	 * @param[in,out] workspace 本ownerより長く生存する保護file所有者。
	 * @param[in] name 所有者が生成した安全な相対名。
	 * @param[in] bytes 共同quotaへ予約済みの正のfile byte数。
	 * @param[in] maximumBytes 一mappingの有限上限。
	 * @return 容量照会・新規file・view取得成功0、失敗時は元HRESULT。
	 */
	[[nodiscard]] NativeError create( OfficialDownloadWorkspace &workspace, std::wstring_view name,
									 std::uint64_t bytes, std::uint64_t maximumBytes) ;
	/** @brief 同期中だけ有効なread-only viewを返す。
	 * @return owner終了またはcloseまで有効な借用byte列。
	 */
	[[nodiscard]] std::span<const std::byte> bytes() const noexcept ;
	/** @brief 出力mappingだけの書込みviewを返す。
	 * @return create成功時だけ非空。入力ownerでは空。
	 */
	[[nodiscard]] std::span<std::byte>		 writableBytes() noexcept ;
	/** @brief 全resourceを解放し、所有一時fileだけを削除する。
	 * @return 最初の解放失敗のHRESULT。既に空なら0。
	 */
	[[nodiscard]] NativeError				 close() noexcept ;

private:
	/// Resourceと所有file名を外部へ公開しない実装。
	struct State ;
	/// 最後まで単独所有する実装。空なら未取得。
	std::unique_ptr<State> state_ ;
} ;
} // namespace drivercrate
