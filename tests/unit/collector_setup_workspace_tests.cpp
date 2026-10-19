//------------------------------------------------------------------------------
/**
 * @file collector_setup_workspace_tests.cpp
 * @brief 非通信workspaceのcomponent境界と保存済みAPI診断を決定的に検査します。
 * @version 01.01.00
 * @date 2026/10/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/17 component比較と明示fake診断の回帰を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/17 nativeの有限proxy環境保持を値非出力で検証。
 * </pre>
 *
 * @note 内部helperを同一TUで検査し、製品CLIに故障注入を追加しません。
 * @see docs/adr/0356-collector-workspace-boundary-repairs.md
 */
//------------------------------------------------------------------------------

// 内部境界だけを検査する独立targetであり、製品targetへこのTUはlinkしない。
#include "platform/collector_setup_workspace.cpp"

#include <array>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace drivercrate {
namespace {

/** @brief 固定stageの例外を要求し、実API故障を発生させません。
 * @param[in] operation 明示fake戻り値または意味拒否を検査する同期処理。
 * @param[in] stage 期待する固定stage。
 * @return 期待した例外を受け取った場合true。
 */
bool catchesStage( const std::function<void()> &operation, const std::string_view stage)
{
	try {
		operation() ;
	} catch( const std::runtime_error &error) {
		return error.what() == stage ;
	}

	return false ;
}

/** @brief 非重複とAPI診断の固定入力を一度ずつ検査します。
 * @return 全検査成功時0、失敗時1。
 */
int workspaceChecks()
{
	std::size_t					   failures{} ;						// 固定期待と異なる件数。
	const fs::path				   first	= L"D:\\Fixture\\foo" ;	// 実fileには触れない比較入力。
	const std::array<fs::path, 4U> overlaps = {first, L"d:\\fixture\\FOO", L"D:\\Fixture",
											   L"D:\\Fixture\\foo\\child"} ;	// 同一と両方向親子。
	// 全比較は順序も反転し、一方の祖先だけを見落とさない。
	for( const fs::path &other : overlaps) {
		failures += !pathsOverlap( first, other) || !pathsOverlap( other, first) ;
	}

	const fs::path separate = L"D:\\Fixture\\foo-other" ;	// 似たprefixの兄弟。
	failures += pathsOverlap( first, separate) || pathsOverlap( separate, first) ;
	// 各lambdaは即時同期実行し、fakeのthread errorをhelperへ直接渡す。
	failures += !catchesStage(
		[] {
			SetLastError( ERROR_ACCESS_DENIED) ;
			requireBool( FALSE, "TEST_BOOL") ;
		},
		"TEST_BOOL") ;
	failures += !catchesStage(
		[] {
			SetLastError( ERROR_INVALID_DATA) ;
			requireStatus( ERROR_SHARING_VIOLATION, "TEST_DWORD") ;
		},
		"TEST_DWORD") ;
	failures += !catchesStage(
		[] {
			SetLastError( ERROR_INVALID_HANDLE) ;
			requireTokenSizeQuery( FALSE) ;
		},
		"WORKSPACE_TOKEN_SIZE_QUERY") ;
	failures += !catchesStage(
		[] {
			SetLastError( ERROR_ACCESS_DENIED) ;
			requireTokenSizeQuery( TRUE) ;
		},
		"WORKSPACE_TOKEN_SIZE_QUERY_RESULT") ;
	failures += !catchesStage(
		[] {
			SetLastError( ERROR_ACCESS_DENIED) ;
			require( false, "TEST_SEMANTIC") ;
		},
		"TEST_SEMANTIC") ;
	SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
	requireTokenSizeQuery( FALSE) ;
	requireBool( TRUE, "TEST_BOOL_SUCCESS") ;
	requireStatus( ERROR_SUCCESS, "TEST_DWORD_SUCCESS") ;
	std::wstring environment ;	// 本番と同じhelperで生成する非出力の環境block。
	appendProxyEnvironment( environment) ;
	// 呼出し元が設定した四種だけを比較し、値やcredentialをstdoutへ出さない。
	for( const auto name : {L"HTTPS_PROXY", L"HTTP_PROXY", L"ALL_PROXY", L"NO_PROXY"}) {
		std::array<wchar_t, 4096U> value{} ;	// 本番と同じ有限容量の一設定。
		SetLastError( ERROR_SUCCESS) ;
		const DWORD length = GetEnvironmentVariableW( name, value.data(),
													 // 親processの設定だけを照会する。
													 static_cast<DWORD>( value.size())) ;
		const DWORD error =
			// 未設定と実失敗を区別する。
			length == 0U ? GetLastError() : ERROR_SUCCESS ;
		const std::wstring prefix = std::wstring( name) + L"=" ;	// 比較する固定環境名。
		// 設定済み値はbyte相当の完全一致、未設定は欠損のままであることを要求する。
		if( length > 0U && length < value.size()) {
			failures += environment.find( prefix + value.data() + L'\0') == std::wstring::npos ;
		} else {
			failures +=
				error != ERROR_ENVVAR_NOT_FOUND || environment.find( prefix) != std::wstring::npos ;
		}
	}

	std::printf( "WORKSPACE_UNIT fake_only=1 cases=17 failures=%zu\n", failures) ;
	return failures == 0U ? 0 : 1 ;
}
} // namespace
} // namespace drivercrate

/** @brief 非通信の固定helper試験を実行します。
 * @return 全検査成功時0、失敗時1。
 */
int main()
{
	return drivercrate::workspaceChecks() ;
}
