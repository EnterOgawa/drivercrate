//------------------------------------------------------------------------------
/**
 * @file live_search_diagnostics.cpp
 * @brief Locale非依存のlive検索診断出力。
 * @version 01.00.00
 * @date 2026/09/08
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 固定ASCII recordを有限領域で構築し、出力失敗を呼出し側へ返します。
 */
//------------------------------------------------------------------------------

#include "live_search_diagnostics.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <ostream>
#include <streambuf>
#include <string_view>
#include <system_error>

namespace drivercrate::test {

//------------------------------------------------------------------------------
/**
 * @see tests/support/live_search_diagnostics.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool writeLiveSearchDiagnostics( std::ostream				&output,
								const LiveSearchDiagnostics &diagnostics) noexcept
{
	bool succeeded{} ;	// 全byte受理と明示flushの双方が成功した場合だけtrue。
	try {
		// 既に失敗したstreamへ再出力せず、呼出し側に終了判断を返す。
		if( !output.good() || output.rdbuf() == nullptr) {
			return false ;
		}

		std::array<char, 512> record{} ;	// 固定labelと最大整数を含むrecord構築領域。
		std::size_t			  used{} ;		// 有効ASCII byte数。record.size()以下を維持する。
		// 固定labelだけを残領域へ追加し、上限超過を呼出し側へ返す。
		const auto			  appendText = [&record, &used]( const std::string_view text) {
			   // 診断recordの残り容量を超える文字列を追加しない。
			   if( text.size() > record.size() - used) {
				   return false ;
			   }

			   std::copy( text.begin(), text.end(), record.data() + used) ;
			   used += text.size() ;
			   return true ;
		   } ;
		// Localeを参照せず件数とHTTP statusを10進へ変換する。
		const auto appendNumber = [&record, &used]( const std::size_t number) {
			const auto result = std::to_chars( record.data() + used, record.data() + record.size(),
											  number) ;	// 未確定領域への有限変換結果。
			// 数値のASCII変換に失敗した場合は不完全な診断recordを出力しない。
			if( result.ec != std::errc{}) {
				return false ;
			}

			used = static_cast<std::size_t>( result.ptr - record.data()) ;
			return true ;
		} ;
		// 32-bit bit patternを符号拡張せず固定8桁へ変換する。
		const auto				   errorBits = static_cast<std::uint32_t>( diagnostics.error) ;
		std::array<char, 8>		   errorHex{} ;							// 先行zeroを含む固定長のerror表示。
		constexpr std::string_view HEX_DIGITS = "0123456789ABCDEF" ;	// Locale非依存の16進文字。
		// 上位nibbleから8桁だけを生成し、0および負数のbit patternを維持する。
		for( std::size_t index = 0; index < errorHex.size(); ++index) {
			// 現在の16進桁に対応する、32-bit範囲内の右shift量。
			const auto shift = static_cast<unsigned>( (errorHex.size() - index - 1U) * 4U) ;
			// 固定8桁の範囲から取り出す現在の4-bit値。
			errorHex[index] = HEX_DIGITS[(errorBits >> shift) & 0xFU] ;
		}

		// HTTP失敗由来かつ共通clientの受理するstatus範囲だけをHTTPとして表示する。
		const auto httpStatus = static_cast<unsigned>( HRESULT_CODE( diagnostics.error)) ;
		const bool hasHttpStatus =
			FAILED( diagnostics.error) && HRESULT_FACILITY( diagnostics.error) == FACILITY_HTTP &&
			httpStatus >= 100U && httpStatus <= 599U ;	// 取得前の失敗からstatusを推測しない。

		// 完全なrecordを構築できなければ部分recordを出力しない。
		if( !appendText( "Official search diagnostics: error=0x") ||
		   !appendText( std::string_view( errorHex.data(), errorHex.size())) ||
		   !appendText( " http_status=") ||
		   !(hasHttpStatus ? appendNumber( httpStatus) : appendText( "none")) ||
		   !appendText( " metadata_reads=") || !appendNumber( diagnostics.metadataReads) ||
		   !appendText( " metadata_rejected=") ||
		   !appendText( diagnostics.metadataRejected ? "1" : "0") || !appendText( " candidates=") ||
		   !appendNumber( diagnostics.candidates) || !appendText( " landing_evidence=") ||
		   !appendText( diagnostics.landingEvidence ? "1" : "0") ||
		   !appendText( " payload_evidence=") ||
		   !appendText( diagnostics.payloadEvidence ? "1" : "0") || !appendText( "\n")) {
			return false ;
		}

		// Sentryによるunitbufの暗黙flushを避け、例外を捕捉できるscopeで一回ずつI/Oする。
		std::streambuf *const buffer = output.rdbuf() ;				// Outputに接続された非nullの借用buffer。
		const auto count = static_cast<std::streamsize>( used) ;	// 512 byte以下の確定record長。
		succeeded		 = buffer->sputn( record.data(), count) == count && buffer->pubsync() == 0 ;
	} catch( ...) {
		// 例外の本文を出力せず、下段でstreamの失敗状態とfalseの両方へ変換する。
	}

	// 出力失敗をstream状態へ反映し、exception maskによる再送出も境界内で処理する。
	if( !succeeded) {
		try {
			output.setstate( std::ios::badbit) ;
		} catch( ...) {
			// Badbitを設定した結果のexception maskによる再送出も呼出し境界で終える。
			return false ;
		}
	}

	return succeeded ;
}

} // namespace drivercrate::test
