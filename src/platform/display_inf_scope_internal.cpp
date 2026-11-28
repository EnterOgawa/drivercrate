//------------------------------------------------------------------------------
/**
 * @file display_inf_scope_internal.cpp
 * @brief 現用INFからDisplay補助サービスとイベント源への静的作用を読み取る
 * @version 01.06.00
 * @date 2026/11/27
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/27  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/27  旧新の必須子と候補の限定作用を照合
 * Ver.01.02.00 Shunji Ogawa  2026/11/27  Display変更前に元操作と再観測後の承認を照合
 * Ver.01.03.00 Shunji Ogawa  2026/11/27  Type 1処理のPnP到達範囲と選択親を照合
 * Ver.01.04.00 Shunji Ogawa  2026/11/27  Type 1の元書式で参照位置と旧マーカー消失を照合
 * Ver.01.05.00 Shunji Ogawa  2026/11/27  WindowsのType 1実行記録を同じ導入と必須子の観測へ結合
 * Ver.01.06.00 Shunji Ogawa  2026/11/27  同じ必須子の共有コピーを全件再読取りして元内容と照合
 * </pre>
 *
 * @note SetupAPIは読取りだけに使う。外部INFを追加読込みせず、実行可能コードの作用は推測しない
 * @see docs/adr/0605-validate-selected-display-auxiliary-service-declaration.md
 */
//------------------------------------------------------------------------------
#include "platform/display_inf_scope_internal.h"

#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/storage_inf_effects_internal.h"
#include <Windows.h>
#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <functional>
#include <new>
#include <optional>
#include <set>
#include <span>
#include <utility>

namespace drivercrate {
namespace {
constexpr UINT		  MAX_SECTIONS = 16'384U ;	// 一つのHINFで列挙する節数の上限
constexpr LONG		  MAX_ROWS	   = 131'072L ;	// 一つのHINFで読み取る全行数の上限
constexpr std::size_t MAX_INCLUDES = 256U ;		// 外部INF葉名を保持する件数の上限
// SetupAPIの展開済み一欄を格納する上限です。終端を含みます
constexpr DWORD		  MAX_FIELD = 4096U ;
// 元DIRID 13を再確認する際の一INFの最大バイト数です
constexpr DWORD		  MAX_RAW_BYTES = 32U * 1024U * 1024U ;

//------------------------------------------------------------------------------
/**
 * @brief 元Win32エラーをNativeErrorに写す
 * @param[in] error 元APIが返したWin32診断
 * @return 拒否を表すHRESULT。診断値なしの場合は不正データ
 */
//------------------------------------------------------------------------------
NativeError			  infError( DWORD error)
{
	return static_cast<NativeError>(
		HRESULT_FROM_WIN32( error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsの大文字小文字を区別しない元名比較を行う
 * @param[in] left 有限な比較元の値
 * @param[in] right 有限な同種別の値
 * @return 大小文字以外が完全一致する場合true
 */
//------------------------------------------------------------------------------
bool same( std::wstring_view left, std::wstring_view right)
{
	return left.size() == right.size() &&
		   (left.empty() ||
			CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								 static_cast<int>( right.size()), TRUE) == CSTR_EQUAL) ;
}

//------------------------------------------------------------------------------
/**
 * @brief キー区切り以外の接頭辞一致を排除して対象配下かを調べる
 * @param[in] key 一つの完全レジストリキー
 * @param[in] parent 照合する完全親キー
 * @return 同じキー又は区切り付き子キーであればtrue
 */
//------------------------------------------------------------------------------
bool withinKey( std::wstring_view key, std::wstring_view parent)
{
	return same( key, parent) || (key.size() > parent.size() && key[parent.size()] == L'\\' &&
								 same( key.substr( 0U, parent.size()), parent)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開済みの必須識別名が完全な有限文字列かを調べる
 * @param[in] value 名称として使う一つの元欄
 * @return 非空で制御文字と未解決トークンのない場合true
 */
//------------------------------------------------------------------------------
bool validName( std::wstring_view value)
{
	return !value.empty() && value.size() < MAX_FIELD && value.find( L'%') == value.npos &&
		   std::ranges::none_of( value, []( wchar_t ch) { return ch < L' ' || ch == L'\x7f' ; }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Include先を検索先の推測を要しない単独INF葉名に限定する
 * @param[in] name SetupAPIで展開した元Include欄
 * @return 一つの有限かつパスを含まないINF葉名であればtrue
 */
//------------------------------------------------------------------------------
bool includeLeaf( std::wstring_view name)
{
	return validName( name) && name.size() > 4U && name.size() <= 255U &&
		   same( name.substr( name.size() - 4U), L".inf") &&
		   name.find_first_of( L"\\/:*?\"<>|") == name.npos && name.front() != L' ' ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択行の一欄をWindowsの展開後の完全な文字列で読み取る
 * @param[in,out] line 同じHINFが生存する間に借用する行カーソル
 * @param[in] field 0はキー。1からは通常の元欄
 * @param[out] value 成功時の完全な欄。空文字も保持する
 * @return 読取り成功は0。欄欠損と元API失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readField( INFCONTEXT &line, DWORD field, std::wstring &value)
{
	std::array<wchar_t, MAX_FIELD> buffer{} ;	// 展開及び終端を受け取る有限領域
	DWORD						   used{} ;		// 元APIが報告する終端込みの文字数
	// 読み取れない欄を空文字と解釈しない
	if( !SetupGetStringFieldW( &line, field, buffer.data(), MAX_FIELD, &used)) {
		return infError( GetLastError()) ;
	}

	// 元APIの長さと最初の終端を照合する
	if( used == 0U || used > MAX_FIELD || buffer[used - 1U] != L'\0' ||
	   std::find( buffer.begin(), buffer.begin() + used - 1U, L'\0') != buffer.begin() + used - 1U) {
		return infError( ERROR_INVALID_DATA) ;
	}

	value.assign( buffer.data(), used - 1U) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 末尾と先頭のINFの空白を取り除き原文字列のviewを返す
 * @param[in] source 呼出し中に借用する物理行又は元欄
 * @return 同じ元範囲内の空白を除いたview
 */
//------------------------------------------------------------------------------
std::wstring_view trim( std::wstring_view source)
{
	const auto start = source.find_first_not_of( L" \t\r") ;	// 内容を持つ最初の位置
	// 空白だけの原行を空行として扱う
	if( start == source.npos) {
		return {} ;
	}

	return source.substr( start, source.find_last_not_of( L" \t\r") - start + 1U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 引用符外のコメントを省き物理行の元本文に絞る
 * @param[in] line 呼出し中に借用する元物理行
 * @return 同じ範囲内の本文
 */
//------------------------------------------------------------------------------
std::wstring_view withoutComment( std::wstring_view line)
{
	bool quoted{} ;	// 今の一文字が引用符内にあるかを追跡する
	// 行内の引用を追い、引用外の最初のコメントで止める
	for( std::size_t index = 0U; index < line.size(); ++index) {
		// 隣接引用符も一回ずつ処理し、引用符内のセミコロンを保持する
		if( line[index] == L'"') {
			quoted = !quoted ;
		}
		// 引用外に現れたコメント以降を値に含めない
		else if( line[index] == L';' && !quoted) {
			return trim( line.substr( 0U, index)) ;
		}
	}

	return trim( line) ;
}

//------------------------------------------------------------------------------
/**
 * @brief REG_SZの明示ゼロを全桁で照合する
 * @param[in] value SetupAPIで展開した元DWORDフラグ欄
 * @return 全桁から十進又は十六進のゼロを確認した場合true
 */
//------------------------------------------------------------------------------
bool zeroFlags( std::wstring_view value)
{
	// REG_SZのflagsに許す明示十六進prefixだけを取り除く
	if( value.starts_with( L"0x") || value.starts_with( L"0X")) {
		value.remove_prefix( 2U) ;
	}

	return !value.empty() && std::ranges::all_of( value, []( wchar_t ch) { return ch == L'0' ; }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開前の同一行がDIRID 13だけの明示五欄かを照合する
 * @param[in] raw コメントを持たない継続なしの元物理行
 * @return 元データが一つのDIRID 13トークンの場合true
 */
//------------------------------------------------------------------------------
bool exactPackageRoot( std::wstring_view raw)
{
	bool		quoted{} ;	// 区切りを数える際の引用状態
	std::size_t commas{} ;	// 引用外の元欄区切り数
	std::size_t last{} ;	// 最終元欄を開始する位置
	// 元行を最後まで走査し、引用内にあるカンマを欄区切りとしない
	for( std::size_t index = 0U; index < raw.size(); ++index) {
		// 引用符内の元カンマと、通常の欄の区切りを区別する
		if( raw[index] == L'"') {
			quoted = !quoted ;
		}
		// 引用外の区切りだけでフィールドの開始位置を更新する
		else if( raw[index] == L',' && !quoted) {
			++commas ;
			last = index + 1U ;
		}
	}

	const auto value = trim( raw.substr( last)) ;	// 展開前の最後の元欄
	return !quoted && commas == 4U && (value == L"%13%" || value == L"\"%13%\"") ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定したINFから元バイトを取得しINFの文字コードで復元する
 * @param[in] file 呼出し元が書込みと削除を共有せずに開いた元INF
 * @param[out] value 成功時の元文字列。欠損や未知の文字列は拒否する
 * @return 全バイトを読み取った場合0、元診断又は不正データはHRESULT
 */
//------------------------------------------------------------------------------
NativeError readRawInf( HANDLE file, std::wstring &value)
{
	LARGE_INTEGER size{} ;	// 固定した同じ元INFのバイト数
	// 過大又は読取不能な元ファイルから由来を確定しない
	if( !GetFileSizeEx( file, &size)) {
		return infError( GetLastError()) ;
	}

	// 上限を確認してから長さをDWORDへ変換する
	if( size.QuadPart <= 0 || size.QuadPart > MAX_RAW_BYTES) {
		return infError( ERROR_INVALID_DATA) ;
	}

	const auto	bytes = static_cast<DWORD>( size.QuadPart) ;	// 上限を確認した元バイト数
	std::string source( bytes, '\0') ;							// 同一ハンドルから得る元バイト列
	DWORD		read{} ;										// ReadFileが返す完全な取得バイト数
	// 失敗や短い読取を同じ元ファイルの証拠にしない
	if( !ReadFile( file, source.data(), bytes, &read, nullptr)) {
		return infError( GetLastError()) ;
	}

	// 成功値も固定したファイルの全長へ照合する
	if( read != bytes) {
		return infError( ERROR_HANDLE_EOF) ;
	}

	// UTF-16LEでは一コード単位ずつ読み、バッファの整列に依存しない
	if( source.starts_with( "\xff\xfe")) {
		// BOMの後ろに不完全なUTF-16があれば由来判定へ進まない
		if( bytes % 2U != 0U) {
			return infError( ERROR_INVALID_DATA) ;
		}

		value.reserve( bytes / 2U - 1U) ;
		// BOM以降の全コード単位を元順序で復元する
		for( DWORD index = 2U; index < bytes; index += 2U) {
			const auto low	= static_cast<unsigned char>( source[index]) ;		// 元下位バイト
			const auto high = static_cast<unsigned char>( source[index + 1U]) ;	// 元上位バイト
			value.push_back( static_cast<wchar_t>( low | high << 8U)) ;
		}
	} else {
		const bool	utf8	 = source.starts_with( "\xef\xbb\xbf") ;	// 明示UTF-8 BOMの有無
		const UINT	page	 = utf8 ? CP_UTF8 : CP_ACP ;				// Windowsの元文字コード
		const DWORD skip	 = utf8 ? 3U : 0U ;							// BOMを元本文に含めない
		const auto	length	 = static_cast<int>( bytes - skip) ;		// 先に上限を確認した変換元長
		const int	required = MultiByteToWideChar( page, MB_ERR_INVALID_CHARS, source.data() + skip,
												   length, nullptr, 0) ;	// 完全変換に必要な文字数
		// 前半だけの文字変換を認めない
		if( required <= 0) {
			return infError( GetLastError()) ;
		}

		value.resize( static_cast<std::size_t>( required)) ;
		// サイズ計算と実変換は同一の元バイトと文字コードで行う
		if( MultiByteToWideChar( page, MB_ERR_INVALID_CHARS, source.data() + skip, length,
							   value.data(), required) != required) {
			return infError( GetLastError()) ;
		}
	}

	return value.find( L'\0') == value.npos ? 0 : infError( ERROR_INVALID_DATA) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択した一行の元データを節名、元行番号、節の全行数に結合する
 * @param[in] text 固定INFから読んだ展開前の元テキスト
 * @param[in] section SetupAPIが参照した同じINFのレジストリ節
 * @param[in] row SetupAPIで照合済みの0起点行番号
 * @param[in] expected SetupAPIが計数した同じ節の全行数
 * @return 元の一意な節の同じ元行がDIRID 13だけの場合true
 * @note 継続や複数定義がある元レジストリ節に子固有の印は付けない
 */
//------------------------------------------------------------------------------
bool matchRawRow( std::wstring_view text, std::wstring_view section, LONG row, LONG expected)
{
	bool reached{} ;	// 同名の元節を一度読み始めたか
	bool inside{} ;		// 現在の物理行が同名の元節にあるか
	bool continued{} ;	// 直前の元物理行が次の行へ継続するか
	bool matched{} ;	// 同一元行で明示DIRID 13が見つかったか
	LONG count{} ;		// 同名の元節で確認した行数
	// 元テキスト末尾まで読み、対象節の複数定義と全行数を確認する
	while( !text.empty()) {
		const auto end	= text.find( L'\n') ;						// 次の元物理行の境界
		const auto line = withoutComment( text.substr( 0U, end)) ;	// 原コメント除外後の一行
		text.remove_prefix( end == text.npos ? text.size() : end + 1U) ;
		// 空行又はコメントだけなら物理的な継続先を待つ
		if( line.empty()) {
			continue ;
		}

		// 節を始めるのは継続中でない行の完全な見出しだけ
		if( !continued && line.starts_with( L"[") && line.ends_with( L"]")) {
			inside = same( trim( line.substr( 1U, line.size() - 2U)), section) ;
			// 同じ節が再定義されていれば元行番号の一対一対応を確定しない
			if( inside && std::exchange( reached, true)) {
				return false ;
			}

			continue ;
		}

		continued = line.ends_with( L"\\") ;
		// 対象節の外での継続と本文は元行番号に数えない
		if( !inside) {
			continue ;
		}

		// 対象節は継続なしの同じ全行数と同一の元行番号を要求する
		if( continued || count >= expected) {
			return false ;
		}

		// Windowsが照合した一行の原データだけを証拠にする
		if( count == row) {
			matched = exactPackageRoot( line) ;
		}

		++count ;
	}

	return matched && count == expected ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元HINFと書込みを拒否したファイルハンドルを所持する
 */
//------------------------------------------------------------------------------
struct InfReadHandles {
	/// 元INFの書込みと削除を共有しない固定ハンドル
	HANDLE file{INVALID_HANDLE_VALUE} ;
	/// 同じ元INFのインストール操作をしないSetupAPIハンドル
	HINF   inf{INVALID_HANDLE_VALUE} ;

	/**
	 * @brief 有効なSetupAPIとファイルのハンドルを逆順に解放する
	 */
	~InfReadHandles()
	{
		// 開けた場合だけ元INFの解析ハンドルを閉じる
		if( inf != INVALID_HANDLE_VALUE) {
			SetupCloseInfFile( inf) ;
		}

		// 固定を保ったファイルを最後に閉じる
		if( file != INVALID_HANDLE_VALUE) {
			CloseHandle( file) ;
		}
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief SetupAPIが返した節名のWindows規則による順序を提供する
 */
//------------------------------------------------------------------------------
struct SectionOrder {
	/**
	 * @brief 二つの終端付き節名を大文字小文字を区別せずに並べる
	 * @param[in] left 元の節名
	 * @param[in] right 別に読んだ節名
	 * @return Windowsの順序でleftが先の場合true
	 */
	bool operator()( const std::wstring &left, const std::wstring &right) const
	{
		return CompareStringOrdinal( left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_LESS_THAN ;
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief レジストリ節の文法と作用を区別する
 */
//------------------------------------------------------------------------------
enum class RegistryAction {
	/// AddReg節。明示条件により追加、更新、削除
	ADD,
	/// DelReg節。指定キー又は値の削除
	REMOVE,
	/// BitReg節。既存値のビット変更
	BIT,
	/// Ini2Reg節。別欄のrootとsubkeyへの転記
	IMPORT,
	/// 外部から指定され得る全INF内の無キー行
	POTENTIAL,
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じINF内で子の唯一の元レジストリ行を追跡する
 */
//------------------------------------------------------------------------------
struct ChildRow {
	/// 元レジストリ節。候補なしの場合は空
	std::wstring section ;
	/// 同じ元節での0起点行番号
	LONG		 row{} ;
	/// 同じ元節の完全行数
	LONG		 count{} ;
	/// SetupAPIによる元DIRID 13の展開値
	std::wstring expanded ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 一つの固定済みHINFの対象作用と到達範囲を集める
 */
//------------------------------------------------------------------------------
class DisplayInfReader {
public:
	/**
	 * @brief 一INFの読み取り範囲と比較対象を固定する
	 * @param[in] inf 呼出し元がこのインスタンスより長く保持する読取HINF
	 * @param[in] target このインスタンスより長く保持する比較対象
	 * @param[in] whole 外部参照又は拡張として全節を読み取る場合true
	 */
	DisplayInfReader( HINF inf, const OfficialDisplayAuxiliaryService &target, bool whole)
		: inf_( inf), target_( target), whole_( whole),
		  serviceKey_( L"SYSTEM\\CurrentControlSet\\Services\\" + target.serviceName),
		  eventKey_( L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" +
					target.eventSource)
	{
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 実選択節と付随節、又は全INFを宣言ごとに調べる
	 * @param[in] section 実選択節。全INFモードでは空
	 * @param[in] file 元DIRIDの根拠に使う固定ファイルハンドル
	 * @param[in] path 固定ファイルと同じ登録INFの絶対位置
	 * @param[out] output 成功時に同じINFの全観測を移す
	 * @return 読取成功は0、元診断又は不正データはHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError read( std::wstring_view section, HANDLE file, const std::wstring &path,
					 DisplayInfUse &output)
	{
		// Windowsが選んだ実節を持たない外部INFは広い範囲で調べる
		if( whole_) {
			const auto error = readWhole() ;	// 全節の読み取り結果
			// 全節の読み取りに失敗した場合は観測を引き渡さない
			if( error != 0) {
				return error ;
			}
		} else {
			const auto error = readSelected( section) ;	// 正確な起点からの到達範囲の読取状態
			// 選択節と到達先の読取りが成功した場合だけ元値まで検証する
			if( error != 0) {
				return error ;
			}

			// 同名のサービス宣言、イベント作用、他INFを持つINFには印を付けない
			if( !child_.section.empty() && !use_.serviceDeclaration && !use_.applicationEvent &&
			   use_.includeFiles.empty()) {
				std::wstring raw ;									// 同一INFのバイトから復元した元文字列
				const auto	 rawError = readRawInf( file, raw) ;	// 元ファイルの完全読取り結果
				// 元値を検証できない場合は読取り失敗として保持する
				if( rawError != 0) {
					return rawError ;
				}

				use_.scopedChildRegistration =
					matchRawRow( raw, child_.section, child_.row, child_.count) &&
					!hasNamedDirectoryToken() && exactStoreRoot( path, child_.expanded) ;
			}
		}

		output = std::move( use_) ;
		return 0 ;
	}

private:
	//------------------------------------------------------------------------------
	/**
	 * @brief 元DIRID 13の展開値を同じ元INFの実Storeルートへ照合する
	 * @param[in] path 読み取った元INFの絶対位置
	 * @param[in] expanded 同じ元DIRID 13をSetupAPIが展開した値
	 * @return 未設定の点又は同じINFのStoreルートと完全一致した場合true
	 * @note 点は展開前の元%13%を別途確認した行でだけ許容する
	 */
	//------------------------------------------------------------------------------
	static bool exactStoreRoot( const std::wstring &path, std::wstring_view expanded)
	{
		// 公開又はStore登録がない元INFではSetupAPIは点を返す
		if( expanded == L".") {
			return true ;
		}

		std::array<wchar_t, MAX_PATH> storeInf{} ;	// SetupAPIの正式なStore内INF位置
		// 他INFの絶対位置へ展開された値を同じ元パッケージの根拠にしない
		if( !SetupGetInfDriverStoreLocationW( path.c_str(), nullptr, nullptr, storeInf.data(),
											static_cast<DWORD>( storeInf.size()), nullptr)) {
			return false ;
		}

		const std::wstring_view location{storeInf.data()} ;		// 同じ登録のStore内元INF
		const auto separator = location.find_last_of( L'\\') ;	// Store内の元INFファイル名を除く位置
		return separator != location.npos && same( expanded, location.substr( 0U, separator)) ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief DIRID 13と同じ表記の文字列定義がないことを確認する
	 * @return 名前付き定義の存在又は不明な列挙の場合true
	 */
	//------------------------------------------------------------------------------
	bool hasNamedDirectoryToken() const
	{
		std::array<wchar_t, MAX_FIELD> section{} ;	// 一つの元節名を終端込みで受け取る
		// 全節から言語別も含む文字列定義を調べ、上限又は列挙終端で止める
		for( UINT index = 0U; index <= MAX_SECTIONS; ++index) {
			// 正常な全節列挙ができなければDIRIDだけとは判断しない
			if( !SetupEnumInfSectionsW( inf_, index, section.data(), MAX_FIELD, nullptr)) {
				return GetLastError() != ERROR_NO_MORE_ITEMS ;
			}

			// 文字列表以外の同名欄はDIRIDの置換証拠にならない
			if( !stringsSection( section.data())) {
				continue ;
			}

			INFCONTEXT line{} ;	// 元文字列表で数値名を探すためのカーソル
			// 数値名が存在する又は欄を確実に照会できない場合は保守的に扱う
			if( SetupFindFirstLineW( inf_, section.data(), L"13", &line) ||
			   GetLastError() != ERROR_LINE_NOT_FOUND) {
				return true ;
			}
		}

		return true ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 文字列定義節かどうかを確認する
	 * @param[in] section SetupAPIが返す元節名
	 * @return 無装飾又は言語付きの文字列節の場合true
	 */
	//------------------------------------------------------------------------------
	static bool stringsSection( std::wstring_view section)
	{
		return same( section, L"Strings") || same( section.substr( 0U, 8U), L"Strings.") ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 同じHINFの全節を外部の選択に依存せずに調べる
	 * @return 列挙終端まで読んで0、予算超過又は元診断はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readWhole()
	{
		std::array<wchar_t, MAX_FIELD> section{} ;	// 同じHINFの元節名の受取領域
		// 外部から指定され得る節を全て調べて列挙終端を確認する
		for( UINT index = 0U; index <= MAX_SECTIONS; ++index) {
			// 正常な列挙の終端と読取り失敗を区別する
			if( !SetupEnumInfSectionsW( inf_, index, section.data(), MAX_FIELD, nullptr)) {
				const auto error = GetLastError() ;	// 元列挙診断
				return error == ERROR_NO_MORE_ITEMS ? 0 : infError( error) ;
			}

			// 有限予算の先に読めなかった節がある場合は結果を渡さない
			if( index == MAX_SECTIONS) {
				return infError( ERROR_BUFFER_OVERFLOW) ;
			}

			const std::wstring name{section.data()} ;	// 元節の同期所有名
			// 文字列定義をディレクティブとして解釈しない
			if( stringsSection( name)) {
				continue ;
			}

			const auto error = readSection( name) ;	// 同じ元節を読んだ結果
			// 参照の欠損と未読行を全INFの陰性にしない
			if( error != 0) {
				return error ;
			}
		}

		return infError( ERROR_BUFFER_OVERFLOW) ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 実節と既存の付随節を起点にローカル参照を走査する
	 * @param[in] section Windowsが選んだ正確な実DDInstall節
	 * @return 全ての元起点と到達先の読取りは0、損失や上限超過はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readSelected( std::wstring_view section)
	{
		const std::wstring name{section} ;						// 元実起点の終端付き名
		auto			   error = queueSection( name, false) ;	// 実起点の存在確認を兼ねた登録結果
		// 元実選択の不在を未導入や作用なしに縮約しない
		if( error != 0) {
			return error ;
		}

		bool rootIncludes{} ;	// 同じDDInstallが共同で読み込む外部INFの有無
		error = readIncludes( name, rootIncludes) ;
		// 実起点にある外部参照が読めなければ付随節のNeedsを処理しない
		if( error != 0U) {
			return error ;
		}

		constexpr std::wstring_view companions[]{
			L".Services", L".HW",	   L".Interfaces",		 L".CoInstallers",
			L".Wdf",	  L".Filters", L".Components",		 L".Software",
			L".Events",	  L".COM",	   L".LogConfigOverride"} ;	// 同じ実起点のWindows既知付随節
		// 同じ装飾を保った元起点の付随節を追加する。不在は許容する
		for( const auto suffix : companions) {
			std::wstring companion{name} ;	// 元実起点と付随節接尾辞を結んだ完全名
			companion.append( suffix) ;
			error = queueSection( companion, true) ;
			// 目標外の装飾へ付け替えず同じ元節の読取診断を保持する
			if( error != 0) {
				return error ;
			}
		}

		// 新しく見つけた節を末尾に積んで全ローカル参照の終端まで読めるようにする
		for( std::size_t index = 0U; index < pending_.size(); ++index) {
			const auto current =
				pending_[index] ;	// 追加参照でベクターが再配置されても有効な同期所有名
			error = readSection( current, rootIncludes) ;
			// 一部だけ読めた元HINFを作用なしの証拠に使わない
			if( error != 0) {
				return error ;
			}
		}

		return 0 ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 同じHINFの参照節を一度だけ後続読み取りへ登録する
	 * @param[in] name SetupAPIから読み取った元節名
	 * @param[in] mayBeAbsent 付随節又はIncludeで解決し得る節の場合true
	 * @return 元節が登録又は正式に省略された場合0、その他はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError queueSection( const std::wstring &name, bool mayBeAbsent)
	{
		// 名称の欠損と表示用の文字列節を元参照として通さない
		if( !validName( name) || stringsSection( name)) {
			return infError( ERROR_INVALID_DATA) ;
		}

		// 到達済み参照を再び展開しない。循環のある元INFも有限に読む
		if( visited_.contains( name)) {
			return 0 ;
		}

		// 元のローカル節が欠損しているときだけ外部解決又は付随節の省略を認める
		if( SetupGetLineCountW( inf_, name.c_str()) < 0L) {
			const auto error = GetLastError() ;	// 元節の不在又は読取り診断
			return mayBeAbsent && error == ERROR_SECTION_NOT_FOUND ? 0 : infError( error) ;
		}

		// 到達先を途中で切り捨てずに予算超過を返す
		if( pending_.size() == MAX_SECTIONS) {
			return infError( ERROR_BUFFER_OVERFLOW) ;
		}

		visited_.insert( name) ;
		pending_.push_back( name) ;
		return 0 ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 同じ節のIncludeを元順序で取り込む
	 * @param[in] section 元Includeが属し得る同じHINFの節
	 * @param[out] includes 同じ節に一つ以上のIncludeが明示されていればtrue
	 * @return 正式な不在又は全元Includeの読取りは0、その他はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readIncludes( const std::wstring &section, bool &includes)
	{
		INFCONTEXT line{} ;	// 元Includeの検索カーソル
		// 指示がない節から外部参照の許可を作らない
		if( !SetupFindFirstLineW( inf_, section.c_str(), L"Include", &line)) {
			const auto error = GetLastError() ;	// 元Include検索結果
			return error == ERROR_LINE_NOT_FOUND ? 0 : infError( error) ;
		}

		// 同じ節にある全Include行の終端を確認し、元順序を保つ
		do {
			const auto fields = SetupGetFieldCount( &line) ;	// 現在のInclude元欄数
			// 空のIncludeから外部参照先を作り出さない
			if( fields == 0U || fields > MAX_INCLUDES) {
				return infError( ERROR_INVALID_DATA) ;
			}

			// 現在行の各Include名を一欄ずつ確認する
			for( DWORD index = 1U; index <= fields; ++index) {
				std::wstring leaf ;										// 同じ行が指定した外部INFの元葉名
				const auto	 error = readField( line, index, leaf) ;	// 元欄の完全読取結果
				// 未読、パス、短縮先の可能性がある不正名を外部検索へ渡さない
				if( error != 0 || !includeLeaf( leaf)) {
					return error != 0 ? error : infError( ERROR_INVALID_DATA) ;
				}

				// 同じ外部INFは表記差を含めて最初の元葉名だけ保持する
				if( std::ranges::none_of( use_.includeFiles,
										[&]( const auto &known) { return same( leaf, known) ; })) {
					// 読み切れない外部参照を成功扱いしない
					if( use_.includeFiles.size() == MAX_INCLUDES) {
						return infError( ERROR_BUFFER_OVERFLOW) ;
					}

					use_.includeFiles.push_back( std::move( leaf)) ;
				}
			}
		} while( SetupFindNextMatchLineW( &line, L"Include", &line)) ;

		const auto error = GetLastError() ;	// 元Include列挙が終わった理由
		includes		 = true ;
		return error == ERROR_LINE_NOT_FOUND ? 0 : infError( error) ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 元行数を読み取り予算へ算入する
	 * @param[in] count 一つの元節について確認済みの非負行数
	 * @return 元行数を加算した場合true、予算を超過する場合false
	 */
	//------------------------------------------------------------------------------
	bool addRows( LONG count)
	{
		// 元読取りを一部だけで打ち切って成功を作らない
		if( count > MAX_ROWS - rows_) {
			return false ;
		}

		rows_ += count ;
		return true ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 指定節の元行を読み取り証拠とローカル参照を集める
	 * @param[in] section 実選択から到達した又は全INF内の元節名
	 * @param[in] rootIncludes 選択元DDInstallが同じ処理で外部INFを明示する場合true
	 * @return 全元行を読み取った場合0、元診断や予算超過はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readSection( const std::wstring &section, bool rootIncludes = false)
	{
		const auto count = SetupGetLineCountW( inf_, section.c_str()) ;	// 同じ節の元行数
		// 予備照会した節を消失又は破損で開けない場合は観測を成立させない
		if( count < 0L || !addRows( count)) {
			return infError( count < 0L ? GetLastError() : ERROR_BUFFER_OVERFLOW) ;
		}

		// 空の節には外部指示や作用がない
		if( count == 0L) {
			return 0 ;
		}

		bool includes = rootIncludes ;						// 実DDInstallまたは同じ節が外部参照を明示しているか
		auto error	  = readIncludes( section, includes) ;	// 局所にない参照を外部へ渡せるかの読取結果
		// Include読取り不備のまま局所グラフを完成させない
		if( error != 0) {
			return error ;
		}

		// 選択元の全ディレクティブと外部INFの元無キー行を調べる
		for( LONG index = 0L; index < count; ++index) {
			INFCONTEXT line{} ;	// 同じ元節の0起点行を借用する
			// 途中の行が失われた場合に次の行で読み取りを補わない
			if( !SetupGetLineByIndexW( inf_, section.c_str(), static_cast<DWORD>( index), &line)) {
				return infError( GetLastError()) ;
			}

			std::wstring key ;	// キー付きの場合の元指示名
			error = readField( line, 0U, key) ;
			// 元行にキーがない場合をSetupAPIの所定の診断で確認する
			if( error == infError( ERROR_INVALID_PARAMETER)) {
				error =
					whole_ ? readRegistryRow( line, RegistryAction::POTENTIAL, section, index, count)
						   : 0 ;
			}
			// 展開済みのキーを取得できた行をディレクティブとして照合する
			else if( error == 0) {
				error = readDirective( line, key, includes) ;
			}

			// 欠けた元宣言や未読の該当欄をままにしない
			if( error != 0) {
				return error ;
			}
		}

		return 0 ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 対象への作用を持ち得るWindowsディレクティブを処理する
	 * @param[in,out] line 同じHINFの元指示行
	 * @param[in] key 取得済みの元指示名
	 * @param[in] includes 同じ節に外部INFの元宣言がある場合true
	 * @return 読取り成功は0、該当宣言の失敗はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readDirective( INFCONTEXT &line, std::wstring_view key, bool includes)
	{
		// サービス宣言とイベント源の登録を元行の独立した欄で調べる
		if( same( key, L"AddService") || same( key, L"DelService")) {
			return readService( line, same( key, L"AddService"), includes) ;
		}

		// 同じHINF及び既に列挙される外部INFの元Needs参照を処理する
		if( same( key, L"Needs")) {
			return readReferences( line, RegistryAction::POTENTIAL, includes) ;
		}

		// 各レジストリ指示は作用を保ったまま同じ元データ節へ到達する
		if( same( key, L"AddReg")) {
			return readReferences( line, RegistryAction::ADD, includes) ;
		}
		// 対象レジストリを削除できる節も共用判定に含める
		else if( same( key, L"DelReg")) {
			return readReferences( line, RegistryAction::REMOVE, includes) ;
		}
		// 対象値のビット操作を独立した変更として判定する
		else if( same( key, L"BitReg")) {
			return readReferences( line, RegistryAction::BIT, includes) ;
		}
		// INIからの取込みも対象キーへの書込みとして調べる
		else if( same( key, L"Ini2Reg")) {
			return readReferences( line, RegistryAction::IMPORT, includes) ;
		}

		// 付随節内でレジストリ指示に達し得る元行の節参照を辿る
		if( same( key, L"AddInterface")) {
			return readNamedSection( line, 3U, true, includes) ;
		}
		// 子登録、フィルターなどの実行時に参照される節も辿る
		else if( same( key, L"AddComponent") || same( key, L"AddSoftware") ||
				same( key, L"AddComServer") || same( key, L"AddFilter")) {
			return readNamedSection( line, 3U, false, includes) ;
		}
		// フレームワークのサービス節は第2フィールドから辿る
		else if( same( key, L"KmdfService") || same( key, L"UmdfService")) {
			return readNamedSection( line, 2U, false, includes) ;
		}

		return 0 ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 一つの指定欄を読んで同じHINFにある元節を辿る
	 * @param[in,out] line 元指示行のカーソル
	 * @param[in] index 元節参照を持つ1起点欄番号
	 * @param[in] optional 省略欄又は明示的な空欄を認める場合true
	 * @param[in] includes 元節が外部INFで解決し得る場合true
	 * @return 参照の読取成功は0。元欄欠損又は元API失敗はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readNamedSection( INFCONTEXT &line, DWORD index, bool optional, bool includes)
	{
		// 任意欄の省略と必須欄の欠損を分ける
		if( SetupGetFieldCount( &line) < index) {
			return optional ? 0 : infError( ERROR_INVALID_DATA) ;
		}

		std::wstring section ;									// 元指示行から読んだ正確な参照節
		const auto	 error = readField( line, index, section) ;	// 参照節欄の読取り状態
		// 正当な任意空欄は新しい参照を作らない
		if( error != 0 || (optional && section.empty())) {
			return error ;
		}

		// 全INFモードでも参照の元字句と不在を確認する。行は全節列挙で読む
		if( whole_) {
			return validName( section) ? 0 : infError( ERROR_INVALID_DATA) ;
		}

		return queueSection( section, includes) ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 元AddServiceとDelServiceの対象名及びイベント源を独立して比較する
	 * @param[in,out] line 元サービス指示の行カーソル
	 * @param[in] add AddServiceの場合true。DelServiceの場合false
	 * @param[in] includes 元節が外部INFで解決し得る場合true
	 * @return 元欄読取りは0、必須欄又は参照の異常はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readService( INFCONTEXT &line, bool add, bool includes)
	{
		const auto	 fields = SetupGetFieldCount( &line) ;		// 元サービス指示の全欄数
		std::wstring service ;									// 同じ行の元サービス名。null serviceの明示空欄を許す
		auto		 error = readField( line, 1U, service) ;	// 元サービス名の読取り状態
		// 読めない名前や未解決名を対象外の確定に使わない
		if( error != 0 || (!service.empty() && !validName( service))) {
			return error != 0 ? error : infError( ERROR_INVALID_DATA) ;
		}

		use_.serviceDeclaration = use_.serviceDeclaration || same( service, target_.serviceName) ;
		// 削除時はイベントの種別と名前が別の欄で明示され得る
		if( !add) {
			return service.empty() || fields > 4U ? infError( ERROR_INVALID_DATA)
												  : readApplicationEvent( line, service, 3U, fields) ;
		}

		// 明示null service関連付けにはサービス導入節がない
		if( service.empty()) {
			int flags{} ;	// Windowsが読むnull serviceの関連付けフラグ
			// 作用を持つフラグや未知欄を正式な空サービスに縮約しない
			if( fields < 2U || fields > 6U || !SetupGetIntField( &line, 2U, &flags) ||
			   flags != SPSVCINST_ASSOCSERVICE) {
				return infError( ERROR_INVALID_DATA) ;
			}

			// Windows同梱INFの末尾空欄を、実サービス節・イベント源の指定と区別する
			for( DWORD index = 3U; index <= fields; ++index) {
				std::wstring value ;	// 省略と同じ明示空欄かを確認する
				error = readField( line, index, value) ;
				// 空でない導入節や元行の読取失敗を許容しない
				if( error != 0U || !value.empty()) {
					return error != 0U ? error : infError( ERROR_INVALID_DATA) ;
				}
			}

			return 0U ;
		}

		// 元サービス節が未読なら配下のレジストリ作用を否定しない
		error = readNamedSection( line, 3U, false, includes) ;
		// 読取に失敗した行と既知のフィールド範囲を超える行を打ち切る
		if( error != 0 || fields > 6U) {
			return error != 0 ? error : infError( ERROR_INVALID_DATA) ;
		}

		error = readNamedSection( line, 4U, true, includes) ;
		return error != 0 ? error : readApplicationEvent( line, service, 5U, fields) ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 元AddService又はDelServiceが指定するApplicationのイベント源を照合する
	 * @param[in,out] line 同じサービス元指示の行カーソル
	 * @param[in] service 同じ行の明示元サービス名。元イベント源を省略した場合に使う
	 * @param[in] logField 元イベントログ種別の1起点欄番号
	 * @param[in] fields 同じ行の全欄数
	 * @return 読取成功は0、未知の元イベント源はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readApplicationEvent( INFCONTEXT &line, std::wstring_view service, DWORD logField,
									 DWORD fields)
	{
		// Applicationの判定に必要な元log種別が省略された場合は既定のSystem
		if( fields < logField) {
			return 0 ;
		}

		std::wstring logType ;										// 元AddServiceのログ種別。空は既定System
		auto		 error = readField( line, logField, logType) ;	// 元イベントログ種別欄の読取結果
		// 別のlogへの明示登録も未読と区別する
		if( error != 0 || (!logType.empty() && !validName( logType))) {
			return error != 0 ? error : infError( ERROR_INVALID_DATA) ;
		}

		// 他のイベントログは対象のApplication登録ではない
		if( !same( logType, L"Application")) {
			return 0 ;
		}

		std::wstring eventName ;	// 明示イベント源。省略又は空は元サービス名
		// イベント源欄を持つ場合は元の展開名を読む
		if( fields > logField) {
			error = readField( line, logField + 1U, eventName) ;
			// 不明な元名を既定の元サービス名で補完しない
			if( error != 0 || (!eventName.empty() && !validName( eventName))) {
				return error != 0 ? error : infError( ERROR_INVALID_DATA) ;
			}
		}

		use_.applicationEvent = use_.applicationEvent ||
								same( eventName.empty() ? service : eventName, target_.eventSource) ;
		return 0 ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 一欄ずつ元Needs又はレジストリデータ節参照を処理する
	 * @param[in,out] line 元指示行のカーソル
	 * @param[in] action 参照先の種類。POTENTIALの場合はNeeds節
	 * @param[in] includes 元節が外部INFで解決し得る場合true
	 * @return 全参照の読取りは0、異常又は予算超過はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readReferences( INFCONTEXT &line, RegistryAction action, bool includes)
	{
		const auto fields = SetupGetFieldCount( &line) ;	// 同じ指示にある元参照の個数
		// 元参照ゼロ又は過大な参照数から陰性を成功として返さない
		if( fields == 0U || fields > MAX_SECTIONS) {
			return infError( ERROR_INVALID_DATA) ;
		}

		// 元欄を順に処理して、繰り返すレジストリ作用も別の作用として読む
		for( DWORD index = 1U; index <= fields; ++index) {
			std::wstring name ;										// 元指示行の正確な一参照
			auto		 error = readField( line, index, name) ;	// 元参照欄の読取結果
			// 空参照と文字列定義節を元作用の参照先へ使わない
			if( error != 0 || !validName( name) || stringsSection( name)) {
				return error != 0 ? error : infError( ERROR_INVALID_DATA) ;
			}

			// Needsの元節と型付きレジストリデータ節の処理を分ける
			if( action == RegistryAction::POTENTIAL) {
				error = whole_ ? 0 : queueSection( name, includes) ;
			} else {
				error = readRegistrySection( name, action, includes) ;
			}

			// 同じ一欄の読取失敗を後方の成功参照で上書きしない
			if( error != 0) {
				return error ;
			}
		}

		return 0 ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 選択したレジストリ作用の元データ節を調べる
	 * @param[in] section 元指示が指定した正確な節名
	 * @param[in] action 元指示が定める作用種別
	 * @param[in] includes 元節が外部INFで解決し得る場合true
	 * @return 全元行を読んだ場合0、未読や不正な元行はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readRegistrySection( const std::wstring &section, RegistryAction action,
									bool includes)
	{
		const auto count = SetupGetLineCountW( inf_, section.c_str()) ;	// 元レジストリデータ行数
		// 外部INFの指定がある場合は、元ローカル欠損を外部列挙へ保留する
		if( count < 0L) {
			const auto error = GetLastError() ;	// 同じ元節の診断
			return includes && error == ERROR_SECTION_NOT_FOUND ? 0 : infError( error) ;
		}

		// 参照の重複や多重経路を含めた読み取り総数に上限を設ける
		if( !addRows( count)) {
			return infError( ERROR_BUFFER_OVERFLOW) ;
		}

		// 同じ元データ節内のすべての作用を評価する
		for( LONG index = 0L; index < count; ++index) {
			INFCONTEXT line{} ;	// 元レジストリデータを一行ずつ借用する
			// 途中の元レジストリ行が読めなければ対象作用を確定しない
			if( !SetupGetLineByIndexW( inf_, section.c_str(), static_cast<DWORD>( index), &line)) {
				return infError( GetLastError()) ;
			}

			const auto error =
				// 作用の読取結果
				readRegistryRow( line, action, section, index, count) ;
			// 不完全な行を別行の完全な結果で補わない
			if( error != 0) {
				return error ;
			}
		}

		return 0 ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief HKLM元パスの制御セット表記と区切りを比較用に揃える
	 * @param[in] source 展開したレジストリの完全な元相対キー
	 * @return 同じ一元パスを保守的に比較する正規表記
	 */
	//------------------------------------------------------------------------------
	static std::wstring registryKey( std::wstring_view source)
	{
		std::wstring key ;	// 比較用に余分な区切りだけを取り除く元キー表記
		// パスを全長比較するため区切りの繰り返しを一つに揃える
		for( const auto ch : source) {
			// 元要素境界を保持し、余分な先頭区切りを除く
			if( ch != L'\\' || (!key.empty() && key.back() != L'\\')) {
				key.push_back( ch) ;
			}
		}

		// 末尾区切りがあっても対象ルートとの比較を落とさない
		if( key.ends_with( L"\\")) {
			key.pop_back() ;
		}

		constexpr std::wstring_view prefix =
			L"SYSTEM\\ControlSet" ;	// 明示数値制御セット名の元接頭辞
		// 明示制御セットを識別する接頭辞直後の3桁分の参照
		const auto digits = std::wstring_view{key}.substr( std::min( key.size(), prefix.size()), 3U) ;
		// 現行か不明な明示制御セットも対象作用の可能性として扱う
		if( same( std::wstring_view{key}.substr( 0U, prefix.size()), prefix) && digits.size() == 3U &&
		   std::ranges::all_of( digits, []( wchar_t ch) { return ch >= L'0' && ch <= L'9' ; }) &&
		   (key.size() == prefix.size() + 3U || key[prefix.size() + 3U] == L'\\')) {
			key.replace( 7U, 13U, L"CurrentControlSet") ;
		}

		return key ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 元レジストリ行がサービス又はイベント源のキーへ触れるかを調べる
	 * @param[in,out] line 元欄を取得する同一HINFのカーソル
	 * @param[in] action 元参照から得たレジストリ作用種別
	 * @param[in] section 元データ節名
	 * @param[in] index 元データ節の0起点行番号
	 * @param[in] count 元データ節の完全行数
	 * @return 対象への作用を記録又は非該当を確認して0、読取り失敗はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readRegistryRow( INFCONTEXT &line, RegistryAction action,
								const std::wstring &section, LONG index, LONG count)
	{
		const DWORD	 rootField = action == RegistryAction::IMPORT ? 4U : 1U ;	// 元指示ごとのroot欄
		const auto	 fields	   = SetupGetFieldCount( &line) ;					// 現在の元レジストリ行の完全欄数
		std::wstring root ;														// 同じ元行の絶対又は相対レジストリroot
		const auto	 rootError = readField( line, rootField, root) ;			// 元rootの完全読取結果
		// 全節探索の無キー行はレジストリ行と判明した場合だけ解釈する
		if( action == RegistryAction::POTENTIAL && (rootError != 0 || !same( root, L"HKLM"))) {
			return 0 ;
		}

		// 型付き参照で未解決又は未知のrootは陰性とみなさない
		if( rootError != 0 ||
		   (!same( root, L"HKLM") && !same( root, L"HKR") && !same( root, L"HKCR") &&
			!same( root, L"HKCU") && !same( root, L"HKU") && !same( root, L"HKCC"))) {
			return rootError != 0 ? rootError : infError( ERROR_INVALID_DATA) ;
		}

		// サービス節及びイベント節自体の相対作用は親指示の一致で表現する
		if( !same( root, L"HKLM")) {
			return 0 ;
		}

		std::wstring rawKey ;	// 展開済み元絶対パスのsubkey。子専用印ではこの厳密表記を使う
		// 省略subkeyは明示されたルートのままとする
		if( fields > rootField) {
			const auto error = readField( line, rootField + 1U, rawKey) ;	// 元の絶対subkeyの読取結果
			// 未知の絶対位置を対象外に短絡しない
			if( error != 0 || (!rawKey.empty() && !validName( rawKey))) {
				return error != 0 ? error : infError( ERROR_INVALID_DATA) ;
			}
		}

		const auto key	   = registryKey( rawKey) ;			// 比較用に区切りと制御セットを揃えた元キー
		bool	   service = withinKey( key, serviceKey_) ;	// 同じ補助サービスのキー配下を示す
		bool	   event   = withinKey( key, eventKey_) ;	// 同じイベント源のキー配下を示す
		// 祖先キーの一括削除はその配下にある対象にも影響する
		if( !service && !event &&
		   (key.empty() || withinKey( serviceKey_, key) || withinKey( eventKey_, key))) {
			bool	   deletes{} ;											// 元行が祖先キーの削除に使える場合を示す
			const auto error = deletesKey( line, fields, action, deletes) ;	// 元行の削除欄の読取結果
			// 元削除作用が不明な場合に対象キーの存続を仮定しない
			if( error != 0) {
				return error ;
			}

			service = deletes && (key.empty() || withinKey( serviceKey_, key)) ;
			event	= deletes && (key.empty() || withinKey( eventKey_, key)) ;
		}

		use_.applicationEvent = use_.applicationEvent || event ;
		// イベント又は対象外キーを子サービスの限定書込みに数えない
		if( !service) {
			return 0 ;
		}

		const bool first = !std::exchange( use_.serviceRegistry, true) ;	// 元サービスへの最初の行か
		// 比較用に生成した別表記、他の書込み、削除を子の限定登録へ使わない
		if( !first || whole_ || action != RegistryAction::ADD || fields != 5U ||
		   !same( rawKey, serviceKey_)) {
			child_ = {} ;
			return 0 ;
		}

		return readChildRow( line, section, index, count) ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 元レジストリ行がキーそのものの削除かどうかを調べる
	 * @param[in,out] line 型付き又は全INFの元レジストリ行
	 * @param[in] fields 元行の全欄数
	 * @param[in] action 元参照が供給するレジストリ作用種別
	 * @param[out] deletes 対象の祖先キーを削除し得る場合true
	 * @return 判定できた場合0、原フラグや対象欄が未読の場合はHRESULT
	 */
	//------------------------------------------------------------------------------
	static NativeError deletesKey( INFCONTEXT &line, DWORD fields, RegistryAction action,
								  bool &deletes)
	{
		// ビット変更やINI転記では祖先を削除しない
		if( action == RegistryAction::BIT || action == RegistryAction::IMPORT) {
			return 0 ;
		}

		std::wstring value ;	// 元値名。省略又は空は保守的にキー全体の可能性とする
		// 元の値名から値限定の削除と区別する
		if( fields >= 3U) {
			const auto error = readField( line, 3U, value) ;	// 削除対象の元値欄の読取結果
			// 読めない値名を既定値にもキー全体にも仮定しない
			if( error != 0 || !value.empty()) {
				return error ;
			}
		}

		// 削除指示由来と外部呼出しの可能性がある行は対象全体を保守的に見る
		if( action != RegistryAction::ADD) {
			deletes = true ;
			return 0 ;
		}

		// 明示フラグなしのAddRegは祖先自体を削除しない
		if( fields < 4U) {
			return 0 ;
		}

		std::wstring flags ;								// AddRegの元フラグ欄。明示空は既定の追加
		const auto	 error = readField( line, 4U, flags) ;	// 元フラグの完全読取り結果
		// 安全な既定値と未読を区別する
		if( error != 0 || flags.empty()) {
			return error ;
		}

		int valueFlags{} ;	// SetupAPIが元フラグ欄から解釈するDWORD
		// 不明な削除ビットから対象キーの存続を推測しない
		if( !SetupGetIntField( &line, 4U, &valueFlags)) {
			return infError( ERROR_INVALID_DATA) ;
		}

		deletes = (static_cast<DWORD>( valueFlags) & FLG_ADDREG_DELVAL) != 0U ;
		return 0 ;
	}

	//------------------------------------------------------------------------------
	/**
	 * @brief 唯一のサービスキー作用をREG_SZの限定候補として保持する
	 * @param[in,out] line 同じAddReg行を借用する元カーソル
	 * @param[in] section 同じ元レジストリ行の節名
	 * @param[in] index 同じ元節の0起点元行
	 * @param[in] count 同じ元節で確認した全行数
	 * @return 読取成功は0。元作用の必須データが読めない場合はHRESULT
	 */
	//------------------------------------------------------------------------------
	NativeError readChildRow( INFCONTEXT &line, const std::wstring &section, LONG index, LONG count)
	{
		std::wstring value ;									// 同じキーに書込む元の値名
		std::wstring flags ;									// 数値と全桁を照合する展開済み元フラグ欄
		std::wstring data ;										// SetupAPIが展開した元データ。点は元バイトと別に照合する
		const auto	 valueError = readField( line, 3U, value) ;	// 元値名の読み取り状態
		const auto	 flagsError = readField( line, 4U, flags) ;	// 元フラグの読み取り状態
		const auto	 dataError	= readField( line, 5U, data) ;	// 元データの読み取り状態
		// 影響が判明した元子候補に未読欄があれば結果を返さない
		if( valueError != 0 || flagsError != 0 || dataError != 0) {
			return valueError != 0 ? valueError : flagsError != 0 ? flagsError : dataError ;
		}

		// 明示された単一の値名、置換なしのREG_SZ、空でない展開値だけを保持する
		if( !same( value, L"CheckRegistration") || !zeroFlags( flags) || data.empty()) {
			return 0 ;
		}

		const auto security = section + L".security" ;	// 同じ元レジストリ節への追加保護指示
		// 同じ作用に追加の保護変更があれば子の限定書込みとはみなさない
		if( SetupGetLineCountW( inf_, security.c_str()) >= 0L) {
			return 0 ;
		}

		const auto error = GetLastError() ;	// 同じ元追加保護節の不在又は読取り診断
		// 正式な不在を確認した元行だけを再読取りへ渡す
		if( error != ERROR_SECTION_NOT_FOUND) {
			return infError( error) ;
		}

		child_ = {section, index, count, std::move( data)} ;
		return 0 ;
	}

	/// 呼出し元が固定した読取専用HINFを借用する
	HINF								   inf_ ;
	/// 同じ導入計画から取得した比較対象を同期中だけ借用する
	const OfficialDisplayAuxiliaryService &target_ ;
	/// 保守的な全INFの調査ならtrue。実選択の完全節があるときfalse
	const bool							   whole_ ;
	/// 対象補助サービスのHKLMからの完全キー
	const std::wstring					   serviceKey_ ;
	/// 対象ApplicationソースのHKLMからの完全キー
	const std::wstring					   eventKey_ ;
	/// ローカルの指示参照で追加済みの節名
	std::set<std::wstring, SectionOrder>   visited_ ;
	/// 起点と後から見つけたローカルの指示節を挿入順に所有する
	std::vector<std::wstring>			   pending_ ;
	/// 同じHINFの読取り予算の消費済み行数
	LONG								   rows_{} ;
	/// 同じHINFで唯一の子用候補行。後段で元バイトへ照合する
	ChildRow							   child_ ;
	/// 読取り成功時だけ呼出し元へ移す観測
	DisplayInfUse						   use_ ;
} ;
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 登録済みINFの対象サービスとイベント源への作用を読取専用で調べる
 * @param[in] path 呼出し元が確認した元登録INFの絶対パス
 * @param[in] actualSection Windowsが記録した実DDInstall節。空の場合は全節を調べる
 * @param[in] target 照合する元サービス名とApplicationイベント源
 * @param[out] result 成功時の観測と外部INF参照。読取失敗時は空
 * @return 有限範囲内の読取成功は0、構文・元API・予算の失敗はHRESULT
 * @note 外部INFの解決、署名、親子関係及び導入の可否は呼出し元の責務
 */
//------------------------------------------------------------------------------
NativeError inspectRegisteredDisplayInfUse( const std::wstring					 &path,
										   std::wstring_view					  actualSection,
										   const OfficialDisplayAuxiliaryService &target,
										   DisplayInfUse						 &result)
{
	result = {} ;
	// 絶対位置と同じ元選択の比較対象が揃う場合だけ登録INFを開く
	if( path.size() < 7U || path[1U] != L':' || path[2U] != L'\\' || path.find( L'\0') != path.npos ||
	   !same( std::wstring_view{path}.substr( path.size() - 4U), L".inf") ||
	   !validName( target.serviceName) ||
	   target.serviceName.find_first_of( L"\\/") != target.serviceName.npos ||
	   !validName( target.eventSource) ||
	   target.eventSource.find_first_of( L"\\/") != target.eventSource.npos) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		InfReadHandles handles ;	// 同じ元ファイルへの固定と読取HINFの局所所有
		handles.file =
			CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr) ;
		// 登録元のパスが消失又は別用途で開かれた場合は読取りを中止する
		if( handles.file == INVALID_HANDLE_VALUE) {
			return infError( GetLastError()) ;
		}

		handles.inf = SetupOpenInfFileW( path.c_str(), nullptr,
										INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr) ;
		// 現在の元データを開かなければ作用を確定しない
		if( handles.inf == INVALID_HANDLE_VALUE) {
			return infError( GetLastError()) ;
		}

		DisplayInfReader reader( handles.inf, target,
								// 同じ元INFだけを調べる
								actualSection.empty()) ;
		return reader.read( actualSection, handles.file, path, result) ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 現用子の主IDが同じ親の旧新宣言一件と候補の選択済み子INF一件へ結び付くか確認する
 * @param[in] workspace 署名検査済みの候補INFを所有する保護領域
 * @param[in] parent 現用親の署名済み選択節から得たComponentIDs
 * @param[in] packages 候補の選択済み親と同じ閉包の選択済み子
 * @param[in] id 現用子の唯一の主Hardware ID
 * @param[in] target 同じ候補Displayが宣言する補助サービス
 * @param[out] selectedChild 指定時に一意な選択済み子を借用で返す。失敗時はnullを設定する
 * @return 元親子と限定一値を確認した場合0、曖昧・読取失敗・範囲外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyDisplayPeerCandidateChild( const OfficialDownloadWorkspace &workspace,
											std::span<const OfficialInfComponentReference> parent,
											std::span<const OfficialInfPackage>			   packages,
											const std::wstring							  &id,
											const OfficialDisplayAuxiliaryService		  &target,
											const OfficialInfPackage **selectedChild)
{
	// 途中で失敗するときは借用先を返さない
	if( selectedChild) {
		*selectedChild = nullptr ;
	}

	// 元親または一意な現用子IDのない入力を候補子へ変換しない
	if( packages.empty() || id.empty()) {
		return infError( ERROR_INVALID_PARAMETER) ;
	}

	// 同じ現用子の主IDを大小無視で照合する。借用IDは同期中だけ使う
	const auto sameId = [&id]( const std::wstring &value) {
		return CompareStringOrdinal( value.c_str(), -1, id.c_str(), -1, TRUE) == CSTR_EQUAL ;
	} ;
	// 両方の親が明示している一件の元AddComponentを照合する
	const auto usesId = [&sameId]( const OfficialInfComponentReference &relation) {
		return std::ranges::any_of( relation.hardwareIds, sameId) ;
	} ;
	const auto &base = packages.front() ;	// 同じ候補の実選択済み親
	// 親が宣言しない、または複数の元子に割り当てるIDを同じ子と判断しない
	if( std::ranges::count_if( parent, usesId) != 1 ||
	   std::ranges::count_if( base.requiredComponents, usesId) != 1) {
		return infError( ERROR_NOT_SUPPORTED) ;
	}

	const auto oldRelation = std::ranges::find_if( parent, usesId) ;	// 現用親の元子名
	const auto newRelation =
		// 候補親の元子名
		std::ranges::find_if( base.requiredComponents, usesId) ;
	// 名前の変わった子を同じWindows登録へ更新するとは判断しない
	if( !same( oldRelation->name, newRelation->name)) {
		return infError( ERROR_NOT_SUPPORTED) ;
	}

	const OfficialInfPackage *child = nullptr ;	// 直接必要な候補子の一意な選択
	// 元CopyINFと同じ親AddComponentに属する実選択済み子に限定する
	for( const auto &package : packages.subspan( 1U)) {
		// 同梱されただけの別役割や別の子を現用子へ結び付けない
		if( package.role != DriverPlanRole::DRIVER_COMPONENT ||
		   package.selectedInstallSection.empty() ||
		   !std::ranges::any_of( package.hardwareIds, sameId) ||
		   std::ranges::none_of( base.activeRequiredInfPaths, [&package]( const auto &path) {
			   return same( path, package.infRelativePath) ;
		   })) {
			continue ;
		}

		// 読取順で対象を決めず、曖昧な元子は拒否する
		if( child != nullptr) {
			return infError( ERROR_DUP_NAME) ;
		}

		child = &package ;
	}

	// 子の実選択と同じサービスキー内の一値だけを両方確認する
	if( child == nullptr) {
		return infError( ERROR_NOT_FOUND) ;
	}

	DisplayInfUse scope ;	// 候補子の限定書込みの確認結果
	const auto	  error = inspectRegisteredDisplayInfUse( workspace.path( child->infRelativePath),
														 child->selectedInstallSection, target,
														 scope) ;	// 同じ署名済み子の作用結果
	// 同じ子の実節から限定作用を読み取れた場合だけ、選択済み子の参照も返す
	if( error == 0U && scope.scopedChildRegistration && selectedChild) {
		*selectedChild = child ;
	}

	return error != 0U ? error : scope.scopedChildRegistration ? 0U : infError( ERROR_NOT_SUPPORTED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Displayの登録・適用前に同じ操作と最新の署名承認を確かめる
 * @param[in] ownsOperation 元の操作と親が現在も有効かを返す同期操作
 * @param[in] reobserve 現用所有、内容と登録元の不在を再照合する同期読取り
 * @param[in] authorize 元署名レコードと実UTCを同期で確認する操作
 * @return 全項成立時0、各照会の最初の失敗またはE_ACCESSDENIED
 * @note 同期の観測だけを行う。各読取後の操作入れ替わりから変更を許可しない
 */
//------------------------------------------------------------------------------
NativeError verifyDisplayMutationBoundary( const std::function<bool()>		 &ownsOperation,
										  const std::function<NativeError()> &reobserve,
										  const std::function<NativeError()> &authorize)
{
	// 不足する確認や別の操作を、旧確認の有効な再利用にしない
	if( !ownsOperation || !reobserve || !authorize || !ownsOperation()) {
		return E_ACCESSDENIED ;
	}

	const auto observed = reobserve() ;	// 元状態、付随参照と現用所有の再読取結果
	// 現用所有が変化した場合は署名の再照合が成立しても進めない
	if( observed != 0U || !ownsOperation()) {
		return observed != 0U ? observed : E_ACCESSDENIED ;
	}

	const auto authorized = authorize() ;	// 時間のかかる再観測後の現時点の承認
	return authorized != 0U ? authorized : ownsOperation() ? 0U : E_ACCESSDENIED ;
}

namespace {
constexpr std::wstring_view SOFTWARE_COMPONENT_GUID =
	L"{5c4c3332-344d-483c-8739-259e934c9cc8}" ;	// 子の正式クラス
constexpr std::wstring_view DISPLAY_GUID =
	L"{4d36e968-e325-11ce-bfc1-08002be10318}" ;	// 親の正式クラス

//------------------------------------------------------------------------------
/**
 * @brief 同じ実行物が参照するHardware IDの接頭辞への一致を確認する
 * @param[in] value Windowsの最初のHardware ID又はクラス登録の一致ID
 * @param[in] families 元実行物に由来するASCII接頭辞の集合
 * @return 元接頭辞と大文字・小文字を除いて一致する場合true
 */
//------------------------------------------------------------------------------
bool matchesType1Family( std::wstring_view value, std::span<const std::wstring_view> families)
{
	return std::ranges::any_of( families, [value]( const auto prefix) {
		return same( value.substr( 0U, prefix.size()), prefix) ;
	}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実行物が読むANSI属性で現在機器の最初のHardware IDを取得する
 * @param[in] node 同じ現在ツリーの機器
 * @param[out] id 最初のID又はWindowsが明示した不在。失敗時は空
 * @return 読取りまたは正式不在で0、型・形式・照会失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readFirstType1HardwareId( DEVINST node, std::wstring &id)
{
	id.clear() ;
	std::array<char, 16U * 1024U> bytes{} ;										// ANSIの全IDと終端を含む上限
	ULONG						  length = static_cast<ULONG>( bytes.size()) ;	// APIが返す元バイト長
	ULONG						  type{} ;										// 同じ元Hardware ID属性の型
	const auto					  read = CM_Get_DevNode_Registry_PropertyA(
		   node, CM_DRP_HARDWAREID, &type, bytes.data(), &length, 0U) ;	// 元実行物と同じ符号化の診断
	// 正式不在だけを一致し得るHardware IDがない場合に数える
	if( read == CR_NO_SUCH_VALUE) {
		return 0U ;
	}

	// 元診断を失わず、途中までのリストを現在の全元値として採用しない
	if( read != CR_SUCCESS || type != REG_MULTI_SZ || length == 0U || length > bytes.size() ||
	   bytes[length - 1U] != '\0' || (length > 1U && bytes[length - 2U] != '\0')) {
		return read != CR_SUCCESS ? infError( CM_MapCrToWin32Err( read, ERROR_GEN_FAILURE))
								  : infError( ERROR_INVALID_DATA) ;
	}

	const auto end =
		// 同じ元値の最初の終端
		std::find( bytes.cbegin(), bytes.cbegin() + length, '\0') ;
	const auto chars =
		// 最初のIDのANSI長。上限は元配列と同じ
		static_cast<int>( end - bytes.cbegin()) ;
	// Windowsが返した正式な空リストには該当IDがない
	if( chars == 0) {
		return 0U ;
	}

	id.resize( static_cast<std::size_t>( chars)) ;
	const auto decoded = MultiByteToWideChar( CP_ACP, MB_ERR_INVALID_CHARS, bytes.data(), chars,
											 // 実行物と同じANSI属性のUTF-16表記
											 id.data(), chars) ;
	// 変換に失敗した値は非該当として扱わない
	if( decoded <= 0) {
		id.clear() ;
		return infError( GetLastError()) ;
	}

	id.resize( static_cast<std::size_t>( decoded)) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ現在機器の完全IDとクラスのDriver属性を取得する
 * @param[in] node 現在の一機器
 * @param[out] instance Windowsの完全インスタンスID。失敗時は呼出側で破棄する
 * @param[out] driver WindowsのDriver属性。失敗時は呼出側で破棄する
 * @return 二つの元値を完全に読んで0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readType1NodeRegistration( DEVINST node, std::wstring &instance, std::wstring &driver)
{
	std::array<wchar_t, MAX_DEVICE_ID_LEN> id{} ;	// Windowsの完全インスタンスIDの上限
	const auto							   identity =
		// 同じ機器の照会
		CM_Get_Device_IDW( node, id.data(), static_cast<ULONG>( id.size()), 0U) ;
	// 現在機器の元IDを名前やクラスから推測しない
	if( identity != CR_SUCCESS || id.front() == L'\0' || std::ranges::find( id, L'\0') == id.end()) {
		return identity != CR_SUCCESS ? infError( CM_MapCrToWin32Err( identity, ERROR_GEN_FAILURE))
									  : infError( ERROR_INVALID_DATA) ;
	}

	std::array<wchar_t, 128U> raw{} ;										// クラスGUIDと登録番号を含むDriver値の上限
	ULONG					  bytes = static_cast<ULONG>( sizeof( raw)) ;	// 元バイトの長さと終端
	ULONG					  type{} ;										// Windowsの元値の型
	const auto read = CM_Get_DevNode_Registry_PropertyW( node, CM_DRP_DRIVER, &type, raw.data(),
														&bytes, 0U) ;	// 現用登録の相対名
	// 不明な元クラス登録、型や境界の異常を根拠に採用しない
	if( read != CR_SUCCESS || type != REG_SZ || bytes <= sizeof( wchar_t) || bytes > sizeof( raw) ||
	   bytes % sizeof( wchar_t) != 0U) {
		return read != CR_SUCCESS ? infError( CM_MapCrToWin32Err( read, ERROR_GEN_FAILURE))
								  : infError( ERROR_INVALID_DATA) ;
	}

	const auto end = raw.cbegin() + bytes / sizeof( wchar_t) - 1U ;	// 元値の一つの終端位置
	// 過剰なNULや欠けた終端を別登録へ解決しない
	if( std::find( raw.cbegin(), end + 1U, L'\0') != end) {
		return infError( ERROR_INVALID_DATA) ;
	}

	instance.assign( id.data()) ;
	driver.assign( raw.cbegin(), end) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現用Driver属性から同じクラスの四桁の登録名を切り出す
 * @param[in] driver Windowsが返した完全なDriver属性
 * @param[in] guid 検証する正式クラスGUID
 * @return 同じクラスの正しい登録名。異常時は空
 */
//------------------------------------------------------------------------------
std::wstring_view type1RegistrySlot( std::wstring_view driver, std::wstring_view guid)
{
	// 他クラス、サブキー又は異なる形式の登録を正規の番号に変換しない
	if( driver.size() != guid.size() + 5U || !same( driver.substr( 0U, guid.size()), guid) ||
	   driver[guid.size()] != L'\\') {
		return {} ;
	}

	const auto slot = driver.substr( guid.size() + 1U) ;	// 同じクラスの直接子の名前
	return std::ranges::all_of( slot,
							   []( const wchar_t digit) { return digit >= L'0' && digit <= L'9' ; })
			   ? slot
			   : std::wstring_view{} ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 現在のルートから全機器を走査し実行物が読む対象の元親子を観測する
 * @param[in] families 静的検査で固定した元Hardware ID接頭辞
 * @param[out] topology 一巡した現在ツリーと対象の完全観測。失敗時は空
 * @return 正式なルート、終端と全親子の読取り成功で0、その他はHRESULT
 * @note PnPを読み取るだけで変更を行わない。実行範囲の判定は別に行う
 */
//------------------------------------------------------------------------------
NativeError readDisplayType1Topology( std::span<const std::wstring_view> families,
									 DisplayType1Topology			   &topology)
{
	topology						= {} ;
	constexpr std::size_t MAX_NODES = 4096U ;	// 現在のPnPツリーを一巡する上限
	// 元実行物の検索条件を空の集合で代用しない
	if( families.empty() ||
	   std::ranges::any_of( families, []( const auto prefix) { return prefix.empty() ; })) {
		return E_INVALIDARG ;
	}

	try {
		DEVINST	   root{} ;	// Windowsが示す現在ツリーの正式ルート
		const auto located =
			// 同じ読み取りの元診断
			CM_Locate_DevNodeW( &root, nullptr, CM_LOCATE_DEVNODE_NORMAL) ;
		// 見つからないツリーを対象のないツリーへ変換しない
		if( located != CR_SUCCESS) {
			return infError( CM_MapCrToWin32Err( located, ERROR_GEN_FAILURE)) ;
		}

		DisplayType1Topology made ;				// 全枝の終端を確認した場合だけ返す
		std::vector<DEVINST> pending{root} ;	// 次に読む現在ノード
		std::set<DEVINST>	 visited ;			// 同じ機器を複数回解釈しない走査集合
		// 各実ノードを一度だけ読み、全部の子と隣接枝の終端を確認する
		while( !pending.empty()) {
			const auto node = pending.back() ;	// 読み取り対象の一ノード
			pending.pop_back() ;
			// 循環、重複又は容量超過では部分集合を発行しない
			if( visited.size() == MAX_NODES || !visited.insert( node).second) {
				return infError( ERROR_INVALID_DATA) ;
			}

			std::wstring id ;											// 同じ機器が持つ最初のHardware ID
			auto		 error = readFirstType1HardwareId( node, id) ;	// 正式不在も区別する元診断
			// 未読値を非該当として次の機器へ進めない
			if( error != 0U) {
				return error ;
			}

			// 実行物の検索条件に該当する全機器から親とクラス登録を読む
			if( matchesType1Family( id, families)) {
				DEVINST	   parent{} ;									// 同じ現在機器の直接の親
				const auto found = CM_Get_Parent( &parent, node, 0U) ;	// 現用親の元診断
				// 直接の親が不明な場合は別機器を元親へ割り当てない
				if( found != CR_SUCCESS) {
					return infError( CM_MapCrToWin32Err( found, ERROR_GEN_FAILURE)) ;
				}

				DisplayType1DevicePath path ;	// 同じ対象の正式な子と親の登録
				path.firstHardwareId = std::move( id) ;
				error = readType1NodeRegistration( node, path.childInstance, path.childDriver) ;
				// 実在する子に対応する親だけを読み取る
				if( error == 0U) {
					error =
						readType1NodeRegistration( parent, path.parentInstance, path.parentDriver) ;
				}

				// 属性未確認の対象の作用を両方確認した場合へ読み替えない
				if( error != 0U) {
					return error ;
				}

				made.paths.push_back( std::move( path)) ;
			}

			DEVINST	   connected{} ;									// 次の枝の正式な元ノード
			const auto child = CM_Get_Child( &connected, node, 0U) ;	// このノードの最初の子の読取り
			// 子がある場合だけ次の読み取りに含める
			if( child == CR_SUCCESS) {
				pending.push_back( connected) ;
			}
			// 正式終端以外を、子が存在しないという結果へ補完しない
			else if( child != CR_NO_SUCH_DEVNODE) {
				return infError( CM_MapCrToWin32Err( child, ERROR_GEN_FAILURE)) ;
			}

			// ルートの子孫だけを読み、各枝に属する同じ階層の次の機器を追う
			if( node != root) {
				const auto sibling = CM_Get_Sibling( &connected, node, 0U) ;	// 同じ親の次の機器
				// 存在する後続を走査に加える
				if( sibling == CR_SUCCESS) {
					pending.push_back( connected) ;
				}
				// 読取り失敗を同じ親の枝の終端へ読み替えない
				else if( sibling != CR_NO_SUCH_DEVNODE) {
					return infError( CM_MapCrToWin32Err( sibling, ERROR_GEN_FAILURE)) ;
				}
			}
		}

		std::ranges::sort( made.paths, {}, &DisplayType1DevicePath::childInstance) ;
		made.scannedNodes = visited.size() ;
		topology		  = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief クラス登録と全検索対象を一意な選択親と署名付き現用子へ結ぶ
 * @param[in] classes Windowsの現在クラス登録の読み取り結果
 * @param[in] topology 現在ツリーの検索対象
 * @param[in] families 検査済み実行物の検索接頭辞
 * @param[in] parentInstance 署名候補の選択親の完全ID
 * @param[in] childInstance 現用の署名付き必須子の完全ID
 * @param[in] childHardwareId 同じ現用子の確認済み主Hardware ID
 * @param[in] childStoreInf 同じ現用子の署名済みStore INF絶対位置
 * @param[out] parentDriver 成功時だけ同じDisplay親のクラス登録名。失敗時は空
 * @return 一つの対象がすべての元情報に一致して0、未確定や共用はHRESULT
 */
//------------------------------------------------------------------------------
NativeError verifyDisplayType1ParentBinding(
	const DisplayType1ClassSnapshot &classes, const DisplayType1Topology &topology,
	std::span<const std::wstring_view> families, std::wstring_view parentInstance,
	std::wstring_view childInstance, std::wstring_view childHardwareId,
	std::wstring_view childStoreInf, std::wstring &parentDriver)
{
	parentDriver.clear() ;
	const auto slash = childStoreInf.find_last_of( L'\\') ;	// 署名元INFが実際に属する親との境界
	// 不明な親子、署名元又は未読の母集合を一台への作用と判断しない
	if( classes.controlSet.empty() || topology.scannedNodes == 0U || families.empty() ||
	   parentInstance.empty() || childInstance.empty() || same( parentInstance, childInstance) ||
	   childHardwareId.empty() || slash == childStoreInf.npos) {
		return E_INVALIDARG ;
	}

	// 読取済みの現在PnPで他の到達先がある場合や必要子がいない場合は保留する
	if( topology.paths.size() != 1U) {
		return infError( ERROR_SHARING_VIOLATION) ;
	}

	const auto &path = topology.paths.front() ;	// 実行物が到達する一件
	const auto	childSlot =
		// 子が実際に使うクラス登録名
		type1RegistrySlot( path.childDriver, SOFTWARE_COMPONENT_GUID) ;
	// 現在の直接親と子を、署名付き元選択の完全IDと元クラスへ結ぶ
	if( childSlot.empty() || type1RegistrySlot( path.parentDriver, DISPLAY_GUID).empty() ||
	   !same( path.childInstance, childInstance) || !same( path.parentInstance, parentInstance) ||
	   !same( path.firstHardwareId, childHardwareId)) {
		return infError( ERROR_RETRY) ;
	}

	const DisplayType1ClassRegistration *selected = nullptr ;	// 該当する一つの現用クラス登録
	// 非presentの残留登録も元実行物の走査対象に入るため、全クラス登録を確認する
	for( const auto &row : classes.registrations) {
		// Windowsの正式不在だけを該当登録なしと扱う
		if( !row.matchingId) {
			continue ;
		}

		// ANSIへの変換で別のIDに見える可能性がある元値を除外の根拠にしない
		if( !std::ranges::all_of( *row.matchingId, []( const wchar_t value) {
			   return value >= L'!' && value <= L'~' ;
		   })) {
			return infError( ERROR_INVALID_DATA) ;
		}

		// 元実行物が使う接頭辞に該当する全登録を数える
		if( matchesType1Family( *row.matchingId, families)) {
			// 複数の登録や別のスロットを同じ現用子へ束ねない
			if( selected || row.slot != childSlot || !same( *row.matchingId, childHardwareId)) {
				return infError( ERROR_SHARING_VIOLATION) ;
			}

			selected = &row ;
		}
	}

	// 該当登録が正式に存在し、同じ元Storeパッケージの親を示す場合だけ採用する
	if( !selected || !selected->storePath) {
		return infError( ERROR_NOT_FOUND) ;
	}

	std::wstring_view registeredStore =
		*selected->storePath ;	// 元クラスが登録したStoreパッケージ位置
	// 終端の一つの区切りを除いた同じディレクトリ名を比較する
	if( registeredStore.ends_with( L'\\')) {
		registeredStore.remove_suffix( 1U) ;
	}

	// 別のパッケージや旧パスから同じ子の作用を承認しない
	if( !same( registeredStore, childStoreInf.substr( 0U, slash))) {
		return infError( ERROR_RETRY) ;
	}

	parentDriver = path.parentDriver ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 観測した型付き参照と旧マーカーを同じ署名済み子の結果へ照合する
 * @param[in] registry 同じ選択親から保護付きで取得した全対象値
 * @param[in] nativePath 同じ子の正規Driver Store内に属する64ビット元ファイルの全位置
 * @param[in] wow64Path 同じ子の正規Driver Store内に属する32ビット元ファイルの全位置
 * @return REG_SZの両位置が一致して対象旧値が不在ならtrue。欠損・別の位置・型はfalse
 * @note REG_SZの終端NUL一つの有無を許容する。Windowsの実行記録や適用完了は別に確認する
 */
//------------------------------------------------------------------------------
bool matchesDisplayType1ReflectedRegistry( const DisplayType1RegistrySnapshot &registry,
										  std::wstring_view					  nativePath,
										  std::wstring_view					  wow64Path) noexcept
{
	const auto matches = []( const std::optional<DisplayType1RegistryValue> &field,
							std::wstring_view								expected) noexcept {
		// 空の位置、別型及びUTF-16の途中までのデータを同じ参照に読み替えない
		if( !field || field->type != REG_SZ || expected.empty() || expected.size() >= MAX_PATH ||
		   expected.find( L'\0') != expected.npos || field->bytes.size() % sizeof( wchar_t) != 0U) {
			return false ;
		}

		const auto count = field->bytes.size() / sizeof( wchar_t) ;	// Windowsが保存した文字数
		// 終端なし又は終端一つの元値だけを読んで完全位置と比較する
		if( count != expected.size() && count != expected.size() + 1U) {
			return false ;
		}

		std::array<wchar_t, MAX_PATH> buffer{} ;	// 元バイトを非整列参照せずに読む
		std::memcpy( buffer.data(), field->bytes.data(), field->bytes.size()) ;
		return buffer[expected.size()] == L'\0' && same( {buffer.data(), expected.size()}, expected) ;
	} ; // 実行物の書込み時の終端有無を許容する非実行の値照合

	return matches( registry.openClDriverName, nativePath) &&
		   matches( registry.openClDriverNameWow, wow64Path) && !registry.parentCheckRegistration &&
		   !registry.copyToVmOverwrite && !registry.copyToVmOverwriteWow64 &&
		   !registry.serviceCheckRegistration && !registry.softwareCheckRegistration ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ選択の全共有宛先で保護、二度の事後観測と元内容を照合する
 * @param[in] copies 署名検査済みの子の元コピー行、Windows宛先、元ファイル証拠
 * @param[in] before 同じ順で導入前に得た宛先の保護付き観測
 * @param[in] read 正規の共有宛先だけを同期で読む処理
 * @return 全宛先が元内容と一致する場合0、安定した不在または内容差はS_FALSE、他は元HRESULT
 * @note 二回の読取りは変化の検出用。旧内容の保持からコピーの省略理由を推測しない
 */
//------------------------------------------------------------------------------
NativeError verifyDisplayType1SharedCopies(
	std::span<const OfficialSoftwareComponentSharedCopy> copies,
	std::span<const ProtectedExecutableSnapshot> before, const DisplayType1SharedFileRead &read)
{
	// 同じ選択の元証拠と導入前の観測がそろう場合にだけ読む
	if( !read || copies.empty() || copies.size() != before.size()) {
		return E_INVALIDARG ;
	}

	try {
		std::vector<ProtectedExecutableSnapshot> first( copies.size()) ;	// 全共有先の一回目の証拠
		// 元の選択と同じ順で各共有宛先を一度ずつ読取る
		for( std::size_t index = 0U; index < copies.size(); ++index) {
			const auto &copy = copies[index] ;	// 同じ宛先と署名付き元内容
			// 元宣言と導入前の保護が確定している正規親の直接配置に限る
			if( (copy.dirid != 10 && copy.dirid != 11) || copy.target.empty() || copy.bytes == 0U ||
			   copy.sha256.size() != 64U || before[index].directorySecurity.empty()) {
				return E_INVALIDARG ;
			}

			const auto error = read( copy.target, copy.dirid == 10, first[index]) ;	// 元読取診断
			// 読取失敗と保護済みの正式な不在を区別する
			if( error != 0U) {
				return error ;
			}

			// 導入前から親の保護が変化した場合は同じ宛先の証拠にしない
			if( first[index].directorySecurity != before[index].directorySecurity) {
				return infError( ERROR_RETRY) ;
			}
		}

		bool complete = true ;	// 安定した全宛先が元内容と一致する場合にだけ維持
		// 全件を再度読み、途中交換を検出してから元配布の全サイズとハッシュに照合する
		for( std::size_t index = 0U; index < copies.size(); ++index) {
			const auto				   &copy = copies[index] ;					// 先の一回と同じ共有宛先
			ProtectedExecutableSnapshot fresh ;									// 二回目の同じ宛先の保護と実内容
			const auto error = read( copy.target, copy.dirid == 10, fresh) ;	// 二回目の元診断
			// 二度目だけの読取失敗も元コードのまま保持する
			if( error != 0U) {
				return error ;
			}

			// 元バイトが同じでもファイルIDや保護が途中で変われば確定しない
			if( fresh != first[index]) {
				return infError( ERROR_RETRY) ;
			}

			complete = complete && fresh.existing && fresh.existing->bytes == copy.bytes &&
					   same( fresh.existing->sha256, copy.sha256) ;
		}

		return complete ? S_OK : S_FALSE ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief レビュー済みType 1の記録コマンドが同じ署名済み元実行物と引数を指すか判定する
 * @param[in] command Windowsの開始イベントから得た有界の元コマンド
 * @param[in] source 同じ署名済み実行物の正規Store内の完全位置
 * @param[in] arguments 同じ元INFから得た順序付きの単純引数
 * @return Windowsが記録した引用符付き元実行物と単純引数が完全一致する場合true
 * @note 実行、環境展開、ファイル名推測は行わない
 */
//------------------------------------------------------------------------------
bool matchesDisplayType1RecordedCommand( std::wstring_view command, std::wstring_view source,
										std::span<const std::wstring> arguments) noexcept
{
	// 確認したWindowsの書式と完全パスの長さに結び付け、余分な実行構文を採用しない
	if( source.empty() || source.size() >= MAX_PATH || arguments.empty() || command.size() > 4096U ||
	   !command.starts_with( L'"') || command.size() <= source.size() + 1U ||
	   command[source.size() + 1U] != L'"' || !same( command.substr( 1U, source.size()), source)) {
		return false ;
	}

	command.remove_prefix( source.size() + 2U) ;
	// 同じ位置と順序にある元引数の全体を比較する
	for( const auto &argument : arguments) {
		// 引用、改行やメタ構文を要する未確認の引数にはこの観測規則を適用しない
		if( argument.empty() ||
		   !std::ranges::all_of( argument,
								[]( const wchar_t value) {
									return (value >= L'a' && value <= L'z') ||
										   (value >= L'A' && value <= L'Z') ||
										   (value >= L'0' && value <= L'9') || value == L'-' ||
										   value == L'_' ;
								}) ||
		   !command.starts_with( L' ') || !command.substr( 1U).starts_with( argument)) {
			return false ;
		}

		command.remove_prefix( argument.size() + 1U) ;
	}

	return command.empty() ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同じ導入以後の実行記録を選択子と署名済み元実行物の事後事実へ結び付ける
 * @param[in] observation 同じ導入の変更前位置と署名・選択・現在値を同期中だけ借用する
 * @param[in] events 同じチャネル世代の対象イベント。昇順で同期中だけ借用する
 * @return 実行と反映の状態。重複起動、別対象の同名実行、未確認の順序や欠損はUNCONFIRMED
 * @note 元コマンドを実行せず、Windowsの設定、再試行、ドライバーを変更しない
 */
//------------------------------------------------------------------------------
DisplayType1InstallResult classifyDisplayType1Install(
	const DisplayType1InstallObservation	 &observation,
	std::span<const DisplayType1InstallEvent> events) noexcept
{
	// 取得の完全性と同じ親子への署名付き元条件が分からない場合は結果を推定しない
	if( !observation.streamIntact || observation.afterRecord == 0U || observation.software.empty() ||
	   observation.binary.empty() || observation.arguments.empty() ||
	   observation.childInstance.empty() || events.size() > 512U) {
		return {} ;
	}

	DisplayType1InstallResult result{DisplayType1InstallState::WAITING, 0U} ;	// 現位置までの判定
	const DisplayType1InstallEvent *start = nullptr ;							// 同じ操作で起動した一件を同期中だけ借用する
	std::uint64_t					previous{} ;								// 取得順の重複や巻き戻りを拒否するための直前位置
	// 過去を除外し、同じソフトウェアの開始と終了を取得順のまま照合する
	for( const auto &event : events) {
		// 欠損の疑いがある順序や不正なレコード位置を成功へ変換しない
		if( event.record <= previous) {
			return {} ;
		}

		previous = event.record ;
		// 元変更より前と明示的に別のソフトウェアだけを除外する
		if( event.record <= observation.afterRecord || !same( event.software, observation.software)) {
			continue ;
		}

		// 開始は対象の正式位置・引数・有効な実行コンテキストの一件に限定する
		if( event.kind == DisplayType1EventKind::STARTED) {
			// 同名の旧実行物、別起動や再試行と今回の完了を合成しない
			if( start || event.process == 0U || event.thread == 0U || event.error != 0U ||
			   !event.childInstance.empty() ||
			   !matchesDisplayType1RecordedCommand( event.command, observation.binary,
												   observation.arguments)) {
				return {} ;
			}

			start = &event ;
			continue ;
		}

		// 同じ実行コンテキストと明示子を伴う一つの終端だけを関連付ける
		if( !start || result.state != DisplayType1InstallState::WAITING ||
		   event.process != start->process || event.thread != start->thread ||
		   !same( event.childInstance, observation.childInstance) || !event.command.empty()) {
			return {} ;
		}

		// 終了、失敗、延期をそれぞれ元記録の意味に対応させる
		switch( event.kind) {
			// 開始は元コマンドの検査をすでに通過している
			case DisplayType1EventKind::STARTED:
				return {} ;
			// 既存の構成を使う通知は、同じ機器での今回の反映を示さない
			case DisplayType1EventKind::NOT_CONFIGURED:
				return {} ;
			// 完了だけでは反映判定を発行せず、端末の事後状態を合わせる
			case DisplayType1EventKind::COMPLETED:
				// 正常終了と原失敗値が競合する記録は終端に使わない
				if( event.error != 0U) {
					return {} ;
				}

				result.state = observation.childApplied && observation.registryReflected &&
									   observation.sharedFilesVerified
								   ? DisplayType1InstallState::REFLECTED
								   : DisplayType1InstallState::REFLECTION_PENDING ;
				break ;

			// Windowsが示した同じ子の失敗を元値のまま維持する
			case DisplayType1EventKind::FAILED:
				result = {DisplayType1InstallState::FAILED, event.error} ;
				break ;

			// Windows側が行う再試行の通知であり、アプリから再実行しない
			case DisplayType1EventKind::RETRY_PENDING:
				result = {DisplayType1InstallState::RETRY_PENDING, event.error} ;
				break ;

			// 読取り範囲外の段階を終端と誤認しない
			default:
				return {} ;
		}
	}

	return result ;
}

} // namespace drivercrate
