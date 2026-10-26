//------------------------------------------------------------------------------
/**
 * @file collector_setup_bootstrap_main.cpp
 * @brief 固定resource閉包を検査して保護stagingの既存setupへ委譲します。
 * @version 01.02.01
 * @date 2026/10/26
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/20 raw RCDATA閉包と既存setupへの固定委譲を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/23 v7の83file閉包を既存固定委譲へ追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理。
 * Ver.01.02.00 Shunji Ogawa  2026/10/26 既知参考六file付きの84resource閉包を追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/26 resourceと引数欠損の拒否を解析可能な制御フローへ明示。
 * </pre>
 *
 * @note stagingと部分配置は保持します。署名認証や収集開始は行いません。
 * @see docs/adr/0387-collector-embedded-bootstrap-and-local-index.md
 */
//------------------------------------------------------------------------------
#include "platform/collector_setup_workspace.h"
#include "platform/official_file_verifier.h"
#include "collector_setup_bootstrap_table.h"

#include <Windows.h>
#include <winrt/base.h>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
namespace {

/** @brief 拒否条件を副作用前の固定stageへ変換します。
 * @param[in] valid 成立が必要な条件。
 * @param[in] stage 個人情報を含まない固定stage。
 * @throws std::runtime_error 条件不成立。
 */
void requireEmbedded( const bool valid, const char *stage)
{
	// 欠損や未知を完成へ読み替えない。
	if( !valid) {
		throw std::runtime_error( stage) ;
	}
}

/** @brief Win32 resource列挙callbackの有限な検査状態です。 */
struct ResourceInventory {
	/// 名前とneutral言語の検査に一つでも失敗した場合false。
	bool		valid{true} ;
	/// 固定RCDATA名の実列挙件数。
	std::size_t count{} ;
	/// 現在の名前に含まれた実言語件数。
	std::size_t languages{} ;
} ;

/** @brief 固定resourceにneutral一言語だけが存在することを確認します。
 * @param[in] module 列挙元module。
 * @param[in] type RT_RCDATA。
 * @param[in] name 列挙対象の固定整数ID。
 * @param[in] language 実resource言語。
 * @param[in] parameter 同期呼出し中に借用するResourceInventory。
 * @return 列挙を続ける場合TRUE。
 * @note callbackから例外を送出しません。
 */
BOOL CALLBACK inspectLanguage( HMODULE module, LPCWSTR type, LPCWSTR name, WORD language,
							  LONG_PTR parameter) noexcept
{
	static_cast<void>( module) ;
	static_cast<void>( type) ;
	static_cast<void>( name) ;
	// Win32の整数context境界で、呼出し期間中生存する実stateへ戻す。
	auto &state = *reinterpret_cast<ResourceInventory *>( parameter) ;
	++state.languages ;
	state.valid = state.valid && language == MAKELANGID( LANG_NEUTRAL, SUBLANG_NEUTRAL) &&
				  state.languages == 1U ;
	return TRUE ;
}

/** @brief 未知のRCDATA名と重複言語を実resource集合から拒否します。
 * @param[in] module 列挙元module。
 * @param[in] type RT_RCDATA。
 * @param[in] name 実resource名。
 * @param[in] parameter 同期呼出し中に借用するResourceInventory。
 * @return 列挙を続ける場合TRUE。
 * @note callbackから例外を送出しません。
 */
BOOL CALLBACK inspectResource( HMODULE module, LPCWSTR type, LPWSTR name,
							  LONG_PTR parameter) noexcept
{
	// EnumResourceNamesの整数contextを元の同期stateへ戻す。
	auto &state = *reinterpret_cast<ResourceInventory *>( parameter) ;
	++state.count ;
	const auto id = reinterpret_cast<ULONG_PTR>( name) ;	// MAKEINTRESOURCEのWin32整数表現。
	bool	   found{} ;									// compile時tableに存在する名前だけを許可する。
	// 固定table内の一意ID全件を照合し、未知のresource名を拒否する。
	for( const auto &row : EMBEDDED_RESOURCES) {
		found = found || (IS_INTRESOURCE( name) && row.resourceId == id) ;
	}

	state.languages = 0U ;
	state.valid		= state.valid && found ;
	const BOOL enumerated =
		// 実言語集合。
		EnumResourceLanguagesW( module, type, name, inspectLanguage, parameter) ;
	state.valid = state.valid && enumerated != FALSE && state.languages == 1U ;
	return TRUE ;
}

/** @brief 全実resourceをcompile時閉包へ照合して借用byte一覧を返します。
 * @return 呼出しprocessのmodule生存中だけ有効な検査済みpayload。
 * @throws std::exception 欠損・未知・言語・size・hash拒否。
 */
std::vector<CollectorSetupEmbeddedFile> inspectEmbedded()
{
	const HMODULE	  module = GetModuleHandleW( nullptr) ;	// 自己EXEだけを検査する。
	ResourceInventory state ;								// 全callback終了まで生存する有限state。
	// resource callbackのWin32整数contextへ借用stateを渡す。
	const BOOL		  enumerated =
		EnumResourceNamesW( module, RT_RCDATA, inspectResource,
						   reinterpret_cast<LONG_PTR>( &state)) ;	// 未知名/言語を含む実集合。
	requireEmbedded( enumerated != FALSE && state.valid &&
						state.count == EMBEDDED_RESOURCES.size() &&
						(state.count == 78U || state.count == 84U),
					"EMBEDDED_RESOURCE_SET") ;
	std::vector<CollectorSetupEmbeddedFile> files ;		// 検査済みresourceの借用集合。
	std::uint64_t							total{} ;	// 最大64MiB内で加算する。
	std::set<std::wstring> paths ;						// Windowsで衝突する大小文字差も含む一意な固定相対名。
	std::uint16_t		   expectedId = 4000U ;			// generatorと同じ連番ID。
	// 固定順の全payloadを検査し、一件でも違えば保存と子起動を行わない。
	for( const auto &row : EMBEDDED_RESOURCES) {
		std::wstring folded ;	// ASCIIだけの相対名を比較専用に大小文字統一する。
		requireEmbedded( !row.path.empty() && row.path.size() <= 160U && row.path.back() != L'/' &&
							row.path.find( L"//") == std::wstring_view::npos &&
							row.resourceId == expectedId++,
						"EMBEDDED_TABLE_ID") ;
		// 固定相対名の文字を走査し、separatorはslash一種類だけへ限定する。
		for( const wchar_t letter : row.path) {
			const bool upper = letter >= L'A' && letter <= L'Z' ;	// 固定ASCII英字の大文字。
			requireEmbedded( upper || (letter >= L'a' && letter <= L'z') ||
								(letter >= L'0' && letter <= L'9') || letter == L'_' ||
								letter == L'-' || letter == L'.' || letter == L'/',
							"EMBEDDED_TABLE_PATH") ;
			folded.push_back( upper ? static_cast<wchar_t>( letter + (L'a' - L'A')) : letter) ;
		}

		const std::filesystem::path relative( row.path) ;	// 読取り前に絶対名を拒否する。
		requireEmbedded( !relative.is_absolute() && !relative.has_root_path() &&
							paths.insert( folded).second,
						"EMBEDDED_TABLE_PATH") ;
		// 空名・dot参照・Windows末尾dot正規化を全componentで拒否する。
		for( const auto &part : relative) {
			requireEmbedded( !part.empty() && part != L"." && part != L".." &&
								part.native().back() != L'.',
							"EMBEDDED_TABLE_COMPONENT") ;
		}

		const HRSRC resource = FindResourceExW( module, RT_RCDATA, MAKEINTRESOURCEW( row.resourceId),
											   // 固定ID/言語。
											   MAKELANGID( LANG_NEUTRAL, SUBLANG_NEUTRAL)) ;
		// 欠損resourceは同じsize検査stageで拒否し、Win32 APIへ渡さない。
		if( resource == nullptr) {
			throw std::runtime_error( "EMBEDDED_RESOURCE_SIZE") ;
		}

		requireEmbedded( row.bytes > 0U && row.bytes <= 67108864U && total <= 67108864U - row.bytes,
						"EMBEDDED_RESOURCE_SIZE") ;
		total += row.bytes ;
		const DWORD	  bytes	 = SizeofResource( module, resource) ;	// 実resource byte数。
		const HGLOBAL loaded = LoadResource( module, resource) ;	// 自己moduleの借用resource。
		const void	 *data =
			// module終了まで不変。
			loaded == nullptr ? nullptr : LockResource( loaded) ;
		// 読込み不能は同じload検査stageで拒否し、非nullのbyteだけを借用する。
		if( data == nullptr) {
			throw std::runtime_error( "EMBEDDED_RESOURCE_LOAD") ;
		}

		requireEmbedded( bytes == row.bytes, "EMBEDDED_RESOURCE_LOAD") ;
		const std::string_view raw( static_cast<const char *>( data),
								   bytes) ;	// 実byteを所有せず借用する。
		std::wstring		   digest ;		// 共通CNG処理の実hash。
		requireEmbedded( computeDriverContainerSha256( raw, digest) == 0 && digest == row.sha256,
						"EMBEDDED_RESOURCE_HASH") ;
		files.push_back( {row.path, raw, row.sha256}) ;
	}

	std::printf( "SETUP_EMBEDDED_COMPLETE files=%zu bytes=%llu child_started=0 network=0\n",
				files.size(), static_cast<unsigned long long>( total)) ;
	return files ;
}
} // namespace
} // namespace drivercrate

/** @brief 閉じたCLIを先に検査して固定setupへだけ委譲します。
 * @param[in] count 引数数。
 * @param[in] args 操作と任意の新規配置先・明示--yes。
 * @return 成功0、拒否2、取消し3、その他の内部setup終了値は元bit列。
 * @note 例外はこのprocess境界内で拒否へ変換します。
 */
int wmain( const int count, wchar_t *args[])
{
	try {
		winrt::init_apartment() ;
		// 引数配列の欠損を同じstageで拒否し、mode判定で参照しない。
		if( args == nullptr) {
			throw std::runtime_error( "EMBEDDED_ARGUMENTS") ;
		}

		drivercrate::requireEmbedded( count >= 1 && count <= 4, "EMBEDDED_ARGUMENTS") ;
		const std::wstring_view mode  = count > 1 ? args[1] : L"--install" ;	// 公開された二mode。
		const bool				check = mode == L"--check-embedded" ;			// 非変更で子起動0。
		const bool				yes	  = (count == 4 && std::wstring_view( args[3]) == L"--yes") ||
						 (count == 3 && std::wstring_view( args[2]) == L"--yes") ;	// 明示同意だけ。
		drivercrate::requireEmbedded( (check && count == 2) ||
										 (mode == L"--install" && (count <= 3 || yes)),
									 "EMBEDDED_MODE") ;
		const std::filesystem::path target =
			count > 2 && std::wstring_view( args[2]) != L"--yes"
				? std::filesystem::path( args[2])
				: std::filesystem::path{} ;	// 内部setupの既存境界へ渡す。
		drivercrate::requireEmbedded(
			target.empty() || (target.is_absolute() && target.native().front() != L'\\' &&
							   target.native().find_first_of( L"\"\r\n") == std::wstring::npos),
			"EMBEDDED_INSTALL_PATH") ;
		const auto files = drivercrate::inspectEmbedded() ;	// 副作用前の全実resource検査。
		// checkではstagingも子も作らず終了する。
		if( check) {
			return 0 ;
		}

		return drivercrate::runCollectorSetupEmbedded( files, target, yes) ;
	} catch( const std::filesystem::filesystem_error &error) {
		std::printf( "SETUP_EMBEDDED_REJECTED filesystem_error=%d stagingRetained=true\n",
					error.code().value()) ;
	} catch( const winrt::hresult_error &error) {
		std::printf( "SETUP_EMBEDDED_REJECTED hresult=%08x\n",
					static_cast<unsigned int>( error.code().value)) ;
	} catch( const std::exception &error) {
		std::printf( "SETUP_EMBEDDED_REJECTED stage=%s\n", error.what()) ;
	} catch( ...) {
		std::printf( "SETUP_EMBEDDED_REJECTED stage=UNKNOWN\n") ;
	}

	return 2 ;
}
