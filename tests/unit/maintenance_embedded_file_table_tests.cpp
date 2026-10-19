//------------------------------------------------------------------------------
/**
 * @file maintenance_embedded_file_table_tests.cpp
 * @brief 保守専用PE内表の架空境界回帰実装。
 * @version 01.00.00
 * @date 2026/10/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  架空PE内表の回帰を追加。
 * </pre>
 *
 * @note 原tableとdataを独立に構築します。架空CATの形状成功を署名成功と扱いません。
 */
//------------------------------------------------------------------------------

#include "maintenance_embedded_file_table_tests.h"

#include "platform/maintenance_embedded_file_table.h"
#include "test_framework.h"

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {

constexpr std::size_t	   TABLE_OFFSET = 0x240U ;						// Section先頭とは異なる架空表位置。
constexpr std::size_t	   BLOB_OFFSET	= TABLE_OFFSET + 3U * 264U ;	// 三項目の直後。
constexpr std::string_view INF_TEXT =
	"; fictional\r\n[Version]\r\nSignature=\"$Windows NT$\"\r\n" ;	// 生IDなしの架空INF。

/**
 * @brief 十分なfixture範囲へ独立little-endian値を書く。
 * @param[in,out] raw 呼出し側が確保した所有byte。
 * @param[in] offset 確保済みのfield先頭。
 * @param[in] value uint32の期待値。
 * @param[in] count 既定4、uint16 fieldなら2。
 */
void writeInteger( std::vector<std::byte> &raw, const std::size_t offset, const std::uint32_t value,
				  const std::size_t count = 4U)
{
	// 期待fieldを製品readerに依存せず構築する。
	for( std::size_t index = 0U; index < count; ++index) {
		raw[offset + index] = static_cast<std::byte>( (value >> (index * 8U)) & 0xffU) ;
	}
}

/**
 * @brief Fixtureへ終端NULを除くASCII textをコピーする。
 * @param[in,out] raw 十分なzero初期化fixture。
 * @param[in] offset コピー先の有効範囲。
 * @param[in] text 原構造markerまたは架空file名。
 */
void writeText( std::vector<std::byte> &raw, const std::size_t offset, const std::string_view text)
{
	// 架空textをbyteとしてのみ配置する。
	for( std::size_t index = 0U; index < text.size(); ++index) {
		raw[offset + index] = static_cast<std::byte>( text[index]) ;
	}
}

/**
 * @brief 固定offset・section名へ依存しない最小PE32+表を作る。
 * @return 架空CAT・INF・SYSを持つreadonly dataの原byte。
 */
std::vector<std::byte> fixture()
{
	std::vector<std::byte> raw( 0x1000U) ;	// 完全zeroで始める原PE範囲。
	writeText( raw, 0U, "MZ") ;
	writeInteger( raw, 60U, 0x80U) ;
	writeText( raw, 0x80U, "PE") ;
	writeInteger( raw, 0x84U, 0x8664U, 2U) ;
	writeInteger( raw, 0x86U, 1U, 2U) ;
	writeInteger( raw, 0x94U, 240U, 2U) ;
	writeInteger( raw, 0x98U, 0x20bU, 2U) ;
	writeInteger( raw, 0x98U + 60U, 0x200U) ;
	writeInteger( raw, 0x98U + 108U, 16U) ;
	writeText( raw, 0x188U, ".custom") ;
	writeInteger( raw, 0x188U + 16U, 0xe00U) ;
	writeInteger( raw, 0x188U + 20U, 0x200U) ;
	writeInteger( raw, 0x188U + 36U, 0x40000040U) ;
	writeText( raw, TABLE_OFFSET, "fictional.cat") ;
	writeInteger( raw, TABLE_OFFSET + 260U, 5U) ;
	writeText( raw, TABLE_OFFSET + 264U, "fictional.INF") ;
	writeInteger( raw, TABLE_OFFSET + 264U + 260U, static_cast<std::uint32_t>( INF_TEXT.size())) ;
	writeText( raw, TABLE_OFFSET + 528U, "fictional.sys") ;
	writeInteger( raw, TABLE_OFFSET + 528U + 260U, 88U) ;
	raw[BLOB_OFFSET]	  = std::byte{0x30} ;
	raw[BLOB_OFFSET + 1U] = std::byte{0x82} ;
	raw[BLOB_OFFSET + 3U] = std::byte{1} ;
	writeText( raw, BLOB_OFFSET + 8U, INF_TEXT) ;
	const std::size_t sys =
		BLOB_OFFSET + 8U + (INF_TEXT.size() + 3U) / 4U * 4U ;	// 独立計算のSYS先頭。
	writeText( raw, sys, "MZ") ;
	writeInteger( raw, sys + 60U, 64U) ;
	writeText( raw, sys + 64U, "PE") ;
	return raw ;
}

/**
 * @brief 拒否時に直前成功の範囲も残らないことを検証する。
 * @param[in,out] context 共通集計の所有者。
 * @param[in] raw 架空破損入力。
 */
void expectRejected( TestContext &context, const std::vector<std::byte> &raw)
{
	MaintenanceEmbeddedFileTable layout ;	// 失敗で消えるべき架空旧結果。
	layout.tableOffset = 123U ;
	layout.blobOffset  = 456U ;
	layout.blobBytes   = 789U ;
	layout.files.push_back( {"stale.inf", 12U, 34U}) ;
	DRIVERCRATE_EXPECT( context, inspectMaintenanceEmbeddedFileTable( raw, layout) != 0) ;
	DRIVERCRATE_EXPECT( context, layout.tableOffset == 0U && layout.blobOffset == 0U &&
									layout.blobBytes == 0U && layout.files.empty()) ;
}

} // namespace

void runMaintenanceEmbeddedFileTableTests( TestContext &context)
{
	const std::vector<std::byte> valid = fixture() ;	// 架空の正例。CAT trustは含まない。
	MaintenanceEmbeddedFileTable layout ;				// 構造だけの結果。
	DRIVERCRATE_EXPECT( context, inspectMaintenanceEmbeddedFileTable( valid, layout) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   layout.tableOffset == TABLE_OFFSET && layout.blobOffset == BLOB_OFFSET) ;
	DRIVERCRATE_EXPECT( context, layout.files.size() == 3U) ;
	// 正例契約が成立した場合だけ範囲の独立期待値を照合する。
	if( layout.files.size() == 3U) {
		DRIVERCRATE_EXPECT( context,
						   layout.files[0].offset == BLOB_OFFSET && layout.files[0].bytes == 5U) ;
		DRIVERCRATE_EXPECT( context, layout.files[1].offset == BLOB_OFFSET + 8U &&
										layout.files[1].bytes == INF_TEXT.size()) ;
		DRIVERCRATE_EXPECT( context, layout.files[2].offset ==
										BLOB_OFFSET + 8U + (INF_TEXT.size() + 3U) / 4U * 4U) ;
	}

	// Header／dataの全切断位置を有限に検査し、必要原byte欠損を受理しない。
	for( std::size_t length = 0U; length < BLOB_OFFSET + 8U + (INF_TEXT.size() + 3U) / 4U * 4U + 88U;
		++length) {
		expectRejected( context, std::vector<std::byte>( valid.begin(), valid.begin() + length)) ;
	}

	std::vector<std::byte> changed = valid ;	// 各拒否で原正例からやり直す所有fixture。
	writeInteger( changed, 0x84U, 0xaa64U, 2U) ;
	expectRejected( context, changed) ;
	changed = valid ;
	writeInteger( changed, 0x98U, 0x10bU, 2U) ;
	expectRejected( context, changed) ;
	// Executable／writable／未初期化sectionをdata表として扱わない。
	for( const std::uint32_t flags : std::array{0x60000040U, 0xc0000040U, 0x40000000U}) {
		changed = valid ;
		writeInteger( changed, 0x188U + 36U, flags) ;
		expectRejected( context, changed) ;
	}

	// 危険な隣接項目をskipしてINFから部分表を受理しない。
	for( const std::string_view name :
		std::array{std::string_view( "../fake.cat"), std::string_view( "CON.cat"),
				   std::string_view( "fake.ps1"), std::string_view( "fake.bin"),
				   std::string_view( "fictional.inf")}) {
		changed = valid ;
		// 名fieldを再初期化し、意図した不正項目だけを置く。
		for( std::size_t index = 0U; index < 260U; ++index) {
			changed[TABLE_OFFSET + index] = std::byte{} ;
		}

		writeText( changed, TABLE_OFFSET, name) ;
		expectRejected( context, changed) ;
	}

	changed					  = valid ;
	changed[BLOB_OFFSET + 5U] = std::byte{1} ;
	expectRejected( context, changed) ;
	changed					  = valid ;
	changed[BLOB_OFFSET + 3U] = std::byte{2} ;
	expectRejected( context, changed) ;
	changed = valid ;
	writeInteger( changed, TABLE_OFFSET + 260U, 0xffffffffU) ;
	expectRejected( context, changed) ;
	changed = valid ;
	writeInteger( changed, TABLE_OFFSET + 528U + 260U, 0U) ;
	expectRejected( context, changed) ;
	changed = valid ;
	writeInteger( changed, 0x98U + 144U, 0x280U) ;
	writeInteger( changed, 0x98U + 148U, 8U) ;
	expectRejected( context, changed) ;
	changed = valid ;
	writeInteger( changed, 0x86U, 97U, 2U) ;
	expectRejected( context, changed) ;
	changed = valid ;
	writeInteger( changed, 0x188U + 16U, 0xffffffffU) ;
	expectRejected( context, changed) ;
	changed = valid ;
	// 第二の同形表を同sectionへ配置し、曖昧入力を拒否する。
	for( std::size_t index = 0U; index < 792U; ++index) {
		changed[0xb00U + index] = valid[TABLE_OFFSET + index] ;
	}

	expectRejected( context, changed) ;
}

} // namespace drivercrate::test
