//------------------------------------------------------------------------------
/**
 * @file live_search_diagnostics_tests.cpp
 * @brief Live検索のASCII出力とstream失敗試験。
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
 * @note 合成値とfake sinkで検証し、network・端末情報・実driverへ接続しません。
 */
//------------------------------------------------------------------------------

#include "live_search_diagnostics_tests.h"

#include "support/live_search_diagnostics.h"
#include "test_framework.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <ios>
#include <limits>
#include <locale>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部型定義。                                                               //
//------------------------------------------------------------------------------

/** @brief 出力先の故障位置と通知方法。 */
enum class SinkFailure {
	/// 全byteの書込みとflushが成功する。
	NONE,
	/// 一部だけを受理し、残りを書き込めない。
	SHORT_WRITE,
	/// 全byte受理後にflush失敗を返す。
	FLUSH_FAILURE,
	/// 最初の書込みで例外を投げる。
	WRITE_EXCEPTION,
	/// 全byte受理後にflush例外を投げる。
	FLUSH_EXCEPTION,
} ;

/** @brief 再試行回数と部分出力を観測できる、networkを使わないsink。 */
class DiagnosticBuffer final : public std::streambuf {
public:
	/**
     * @brief 本sinkの固定故障modeを指定する。
     * @param[in] failure 以後の書込み／flushで使用する故障種別。 書込みまたはflushの故障種別。
     * Fake sinkの故障modeを固定する。
     * 外部resourceを所有せず、以後の呼出しだけを観測する。
     */
	//------------------------------------------------------------------------------
	explicit DiagnosticBuffer( const SinkFailure failure) : failure_( failure)
	{
	}

	/// 故障までに受理したbyte列。
	std::string bytes ;
	/// xsputnへ到達した回数。
	std::size_t writeCount{} ;
	/// syncへ到達した回数。
	std::size_t flushCount{} ;

protected:
	/**
     * @brief 指定modeに従ってbyte列を一部または全部受理する。
     * @param[in] data count byteを指す借用領域。 count byteの借用領域。
     * @param[in] count 要求されたbyte数。負数は受理しない。 要求byte数。
     * @return 受理したbyte数。WriteExceptionは例外で通知する。 受理byte数。故障modeにより例外を投げる。
     * Fake sinkの書込みを観測する。
     * 部分書込み後の再試行や出力成功の誤判定を検出する。
     */
	//------------------------------------------------------------------------------
	std::streamsize xsputn( const char *data, const std::streamsize count) override
	{
		++writeCount ;
		// 例外型の書込み障害を注入して診断出力の失敗処理を検証する。
		if( failure_ == SinkFailure::WRITE_EXCEPTION) {
			throw std::runtime_error( "Synthetic write failure.") ;
		}

		// 正の書込み要求がない場合はbufferへ追加しない。
		if( count <= 0) {
			return 0 ;
		}

		const std::streamsize accepted =
			// 実際の受理byte数。
			failure_ == SinkFailure::SHORT_WRITE ? count / 2 : count ;
		bytes.append( data, static_cast<std::size_t>( accepted)) ;
		return accepted ;
	}

	/**
     * @brief Flush結果と呼出し回数を観測する。
     * @return 成功時0、故障時-1。FlushExceptionは例外で通知する。 成功時0、故障時-1。故障modeにより例外を投げる。
     * Fake sinkのflushを観測する。
     * 全byte受理後もflush成功が必要であることを検証する。
     */
	//------------------------------------------------------------------------------
	int sync() override
	{
		++flushCount ;
		// flush時の例外を注入して終了段階の失敗処理を検証する。
		if( failure_ == SinkFailure::FLUSH_EXCEPTION) {
			throw std::runtime_error( "Synthetic flush failure.") ;
		}

		return failure_ == SinkFailure::FLUSH_FAILURE ? -1 : 0 ;
	}

private:
	/// 構築後に変更しない故障設定。
	const SinkFailure failure_ ;
} ;

/** @brief 数字区切りlocaleが診断へ混入しないことを試験する非所有facet。 */
class DiagnosticPunctuation final : public std::numpunct<char> {
public:
	/**
     * @brief 呼出しscopeが所有するfacetを構築する。
     * refs=1なのでlocaleは解放せず、testのscopeが寿命を管理する。
     */
	//------------------------------------------------------------------------------
	DiagnosticPunctuation() : std::numpunct<char>( static_cast<std::size_t>( 1))
	{
	}

protected:
	/**
     * @brief 試験用の桁区切り間隔を返す。
     * Formatted整数出力を誤使用した場合に差を生じさせる。
     * @return 一桁ごとに区切る指定。
     */
	//------------------------------------------------------------------------------
	std::string do_grouping() const override
	{
		return "\1" ;
	}

	/**
     * @brief 試験用の桁区切り文字を返す。
     * 診断にlocale依存の文字が混入する場合を検出する。
     * @return ASCII underscore。
     */
	//------------------------------------------------------------------------------
	char do_thousands_sep() const override
	{
		return '_' ;
	}
} ;

//------------------------------------------------------------------------------
// 内部試験関数定義。                                                         //
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief HTTPとtransportの区別およびflag保存を検証する。
 *
 * 生32-bit値の保存とHTTP status範囲を合成入力で検証する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testStatusRecords( TestContext &context)
{
	struct StatusCase {
		NativeError		 error ;		// Helperへ渡す元の32-bit値。
		std::string_view errorText ;	// 期待する固定8桁error。
		std::string_view httpStatus ;	// 期待するHTTP分類。未知はnone。
	} ;
	const std::array cases{
		StatusCase{HTTP_E_STATUS_FORBIDDEN, "80190193", "403"},
		StatusCase{HTTP_E_STATUS_PROXY_AUTH_REQ, "80190197", "407"},
		StatusCase{HTTP_E_STATUS_NOT_FOUND, "80190194", "404"},
		StatusCase{static_cast<NativeError>( 0x801901ADU), "801901AD", "429"},
		StatusCase{static_cast<NativeError>( 0x80190257U), "80190257", "599"},
		StatusCase{static_cast<NativeError>( 0x80190064U), "80190064", "100"},
		StatusCase{static_cast<NativeError>( 0x80072F78U), "80072F78", "none"},
		StatusCase{S_OK, "00000000", "none"},
		StatusCase{E_ACCESSDENIED, "80070005", "none"},
		StatusCase{static_cast<NativeError>( 0x00190193U), "00190193", "none"},
		StatusCase{static_cast<NativeError>( 0x80190063U), "80190063", "none"},
		StatusCase{static_cast<NativeError>( 0x80190258U), "80190258", "none"},
	} ; // 有効status、transport、非失敗値と範囲外statusの合成例。

	// 全ケースで各値を保存し、system messageやロケールを必要としないことを確認する。 //
	for( const StatusCase &entry : cases) {
		std::ostringstream			output ;	// Recordをnetworkなしで受理するsink。
		const LiveSearchDiagnostics diagnostics{
			entry.error, 7U, true, 2U, true, true} ;	// 意図的に全boolをtrueとした観測値。
		DRIVERCRATE_EXPECT( context, writeLiveSearchDiagnostics( output, diagnostics)) ;
		const std::string expected =
			"Official search diagnostics: error=0x" + std::string( entry.errorText) +
			" http_status=" + std::string( entry.httpStatus) +
			" metadata_reads=7 metadata_rejected=1 candidates=2 landing_evidence=1 "
			"payload_evidence=1\n" ;	// 全項目を切り詰めず保存する期待record。
		DRIVERCRATE_EXPECT( context, output.str() == expected) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Localeとstream設定から独立した最大件数の診断を確認する。
 *
 * Facetの寿命をstreamより長くし、数字区切りとformat設定を注入する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testLocaleAndLimits( TestContext &context)
{
	DiagnosticPunctuation punctuation ;									// Localeが削除しないstack所有facet。
	const std::locale locale( std::locale::classic(), &punctuation) ;	// Outputより長寿命のlocale。
	DiagnosticBuffer  buffer( SinkFailure::NONE) ;						// 一回のwriteとflushを観測する正常sink。
	std::ostream	  output( &buffer) ;								// Bufferを所有しない出力stream。
	output.imbue( locale) ;
	output.setf( std::ios::hex, std::ios::basefield) ;
	output.setf( std::ios::boolalpha | std::ios::showbase | std::ios::unitbuf) ;
	output.width( 1000) ;
	output.fill( '*') ;
	output.exceptions( std::ios::badbit | std::ios::failbit) ;
	const auto	   flags		 = output.flags() ;								// Helper呼出し前のformat flag。
	const auto	   mask			 = output.exceptions() ;						// Helper呼出し前の例外設定。
	constexpr auto MAXIMUM_COUNT = std::numeric_limits<std::size_t>::max() ;	// x64最大件数。
	const LiveSearchDiagnostics diagnostics{0,	   MAXIMUM_COUNT, false, MAXIMUM_COUNT,
											false, false} ;	// 全bool falseと最大値の組合せ。
	DRIVERCRATE_EXPECT( context, writeLiveSearchDiagnostics( output, diagnostics)) ;
	DRIVERCRATE_EXPECT( context, buffer.writeCount == 1U && buffer.flushCount == 1U) ;
	DRIVERCRATE_EXPECT( context, buffer.bytes.find( "metadata_reads=18446744073709551615 ") !=
									std::string::npos) ;
	DRIVERCRATE_EXPECT( context,
					   buffer.bytes.find( "candidates=18446744073709551615 ") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context, buffer.bytes.find( "http_status=none") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context, buffer.bytes.find( "metadata_rejected=0") != std::string::npos) ;
	DRIVERCRATE_EXPECT( context, buffer.bytes.find( "landing_evidence=0 payload_evidence=0\n") !=
									std::string::npos) ;
	DRIVERCRATE_EXPECT( context, buffer.bytes.size() <= 512U) ;
	DRIVERCRATE_EXPECT( context, output.getloc() == locale && output.flags() == flags &&
									output.exceptions() == mask && output.width() == 1000 &&
									output.fill() == '*') ;
	// Labelと値がASCII printableおよび末尾改行だけであることを全byteで確認する。 //
	DRIVERCRATE_EXPECT( context, std::all_of( buffer.bytes.begin(), buffer.bytes.end(),
											[]( const unsigned char byte) {
												return byte == '\n' ||
													   (byte >= 0x20U && byte <= 0x7EU) ;
											})) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 出力失敗を成功とせず自動再試行しないことを確認する。
 *
 * 部分write、flush失敗と例外をmaskの有無にかかわらずfalseへ変換する。
 *
 * @param[in,out] context Assertion集計先。
 */
//------------------------------------------------------------------------------
void testFailedSinks( TestContext &context)
{
	const LiveSearchDiagnostics diagnostics{
		HTTP_E_STATUS_FORBIDDEN, 1U, false, 0U, false, false} ;	// Network拒否を表す非機密の合成値。
	// 出力を途中で止める四種類の故障設定。
	const std::array failures{SinkFailure::SHORT_WRITE, SinkFailure::FLUSH_FAILURE,
							  SinkFailure::WRITE_EXCEPTION, SinkFailure::FLUSH_EXCEPTION} ;
	// 故障位置の全組合せで、完全出力またはflushを偽って成功としない。        //
	for( const SinkFailure failure : failures) {
		// Streamが例外を投げる設定でも呼出し境界から漏らさないことを確認する。 //
		for( const bool throws : {false, true}) {
			DiagnosticBuffer buffer( failure) ;	// 今回の故障modeに固定したsink。
			std::ostream	 output( &buffer) ;	// Fake sinkを借用するstream。
			output.setf( std::ios::unitbuf) ;
			// 例外経路の試験ではstreamの失敗を例外として通知させる。
			if( throws) {
				output.exceptions( std::ios::badbit | std::ios::failbit) ;
			}

			const auto mask = output.exceptions() ;	// 呼出し後も保持すべき例外設定。
			DRIVERCRATE_EXPECT( context, !writeLiveSearchDiagnostics( output, diagnostics)) ;
			DRIVERCRATE_EXPECT( context, buffer.writeCount == 1U) ;
			const bool failsOnWrite = failure == SinkFailure::SHORT_WRITE ||
									  // Flushに到達しない故障かどうか。
									  failure == SinkFailure::WRITE_EXCEPTION ;
			DRIVERCRATE_EXPECT( context, buffer.flushCount == (failsOnWrite ? 0U : 1U)) ;
			DRIVERCRATE_EXPECT( context, !output.good() && output.exceptions() == mask) ;
			// 短い書込みでは行末まで保存されていないことを確認する。
			if( failure == SinkFailure::SHORT_WRITE) {
				DRIVERCRATE_EXPECT( context, !buffer.bytes.empty() && buffer.bytes.back() != '\n') ;
			}

			// 書込み前の例外では出力bufferが空のままであることを確認する。
			if( failure == SinkFailure::WRITE_EXCEPTION) {
				DRIVERCRATE_EXPECT( context, buffer.bytes.empty()) ;
			}
		}
	}

	DiagnosticBuffer buffer( SinkFailure::NONE) ;	// 初期stream失敗なら一度も呼ばれないsink。
	std::ostream	 output( &buffer) ;				// 既存の失敗状態を維持する試験対象。
	output.setstate( std::ios::failbit) ;
	DRIVERCRATE_EXPECT( context, !writeLiveSearchDiagnostics( output, diagnostics)) ;
	DRIVERCRATE_EXPECT( context, buffer.writeCount == 0U && buffer.flushCount == 0U &&
									buffer.bytes.empty() && output.fail()) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/live_search_diagnostics_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runLiveSearchDiagnosticsTests( TestContext &context)
{
	testStatusRecords( context) ;
	testLocaleAndLimits( context) ;
	testFailedSinks( context) ;
}

} // namespace drivercrate::test
