//------------------------------------------------------------------------------
/**
 * @file system_inf_effects_internal.cpp
 * @brief 選択SYSTEM原文の閉じた作用を二相で検査します
 * @version 01.00.00
 * @date 2026/11/13
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/13  新規作成
 * </pre>
 *
 * @note 全原文/参照/実file確認後だけ私有tupleを返し、導入/registry/SCM変更を行いません
 * @see docs/adr/0491-typed-system-needs-effects-and-complete-selection-qualification.md
 */
//------------------------------------------------------------------------------
#include "platform/system_inf_effects_internal.h"
#include <Windows.h>
#include <Aclapi.h>
#include <Sddl.h>
#include <combaseapi.h>
#include <ks.h>
#include <ksmedia.h>
#include <strmif.h>
#include <ksproxy.h>
#include <uuids.h>
#undef INTERFACE
#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <utility>

namespace drivercrate {
namespace {
/** @brief 同同期の二相検査と閉じたfirst-errorだけを所有します */
struct EffectState {
	/// 同NativeLoaderの完全な限定操作です
	const SystemInfEffectApi	 &api ;
	/// 元全参照と所有scopeです
	std::vector<SystemInfSection> sections ;
	/// 全行と実体の検査が済むまで公開しない結果です
	SystemInfEffects			  result ;
	/// 最初の閉じた拒否地点です
	std::uint32_t				  stage{} ;
	/// 固定型/件数だけの補足です
	std::uint32_t				  observed{} ;
	/// 元graphと共有する参照辺の消費です。既読targetでも増加させます
	std::size_t					  references{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief Windowsのordinal規則で有限な名前だけを同値化します
 * @param[in] left 同期中借用する第一値です
 * @param[in] right 同期中借用する第二値です
 * @return 両値全体がcase-insensitiveに一致する場合trueです
 */
//------------------------------------------------------------------------------
bool same( std::wstring_view left, std::wstring_view right)
{
	return left.size() == right.size() && left.size() <= 4096U &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原値を比較だけに用いるASCII小文字へ変換します
 * @param[in] value 有限な原値です。呼出し元の値は変更しません
 * @return ASCIIだけを小文字化した所有copyです
 */
//------------------------------------------------------------------------------
std::wstring folded( std::wstring_view value)
{
	std::wstring result{value} ;	// 原byteと比較値を分離します
	// ASCII以外のregistry文字を独自正規化しません
	for( auto &c : result) {
		c = c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c - L'A' + L'a') : c ;
	}

	return result ;
}
//------------------------------------------------------------------------------
/**
 * @brief 十進/0x十六進の全桁をUINT64へoverflowなく読みます
 * @param[in] text 空でない原数値です。空白/符号を補完しません
 * @param[out] value 成功時だけの全値です。失敗時0です
 * @return 全桁と上限が成立する場合trueです
 */
//------------------------------------------------------------------------------
bool scalar( std::wstring_view text, std::uint64_t &value)
{
	value		   = 0U ;
	const bool hex = text.size() > 2U && text[0] == L'0' &&
					 (text[1] == L'x' ||
					  // 元field/型の全消費を確認する局所位置又は閉じた分類です
					  text[1] == L'X') ;
	const auto			digits = hex ? text.substr( 2U) : text ;	// 接頭辞以外は全て読む値です
	const std::uint64_t base =
		hex ? 16U : 10U ;	// この同期だけで保持する元値です。許可の代用にしません
	// 空/過長を既定0へ変換しません
	if( digits.empty() || digits.size() > 20U) {
		return false ;
	}

	// 末尾まで検査し、途中まで読めた数値を使用しません
	for( const auto c : digits) {
		const auto digit =
			c >= L'0' && c <= L'9'
				? static_cast<unsigned>(
					  c - L'0')	// 元field/型の全消費を確認する局所位置又は閉じた分類です
			: c >= L'a' && c <= L'f' ? static_cast<unsigned>( c - L'a' + 10)
			: c >= L'A' && c <= L'F' ? static_cast<unsigned>( c - L'A' + 10)
									 : 16U ;
		// 乗算前にoverflowを拒否します
		if( digit >= base || value > (std::numeric_limits<std::uint64_t>::max() - digit) / base) {
			value = 0U ;
			return false ;
		}

		value = value * base + digit ;
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 波括弧付きGUIDの全38文字を厳密に確認します
 * @param[in] value 元SYSTEM原文の値です
 * @return 固定区切りとASCII hexだけの場合trueです
 */
//------------------------------------------------------------------------------
bool guid( std::wstring_view value)
{
	// 部分GUIDや末尾文字を補完しません
	if( value.size() != 38U || value.front() != L'{' || value.back() != L'}') {
		return false ;
	}

	// 全桁を固定位置へ照合します
	for( std::size_t i = 1U; i < 37U; ++i) {
		const auto c = value[i] ;	// 一元文字です
		// 区切りだけはhyphenを必要とします
		if( i == 9U || i == 14U || i == 19U || i == 24U) {
			// 別記号を同値化しません
			if( c != L'-') {
				return false ;
			}
		}
		// 後続の別型/文脈だけを判定し、未確認を既定へ変換しません
		else if( !((c >= L'0' && c <= L'9') ||
				  (c >= L'a' && c <= L'f') ||	// 不明/不一致の元値を成功や別scopeへ補完しません
				  (c >= L'A' && c <= L'F'))) {
			return false ;
		}
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 厳密な原GUIDだけをSDKの標準identityへ照合します
 * @param[in] value 全38文字を所有する原GUIDです
 * @param[in] expected Windows SDKが定義する標準identityです
 * @return 全桁とGUID値が一致する場合trueです
 */
//------------------------------------------------------------------------------
bool sdkGuid( std::wstring_view value, const GUID &expected)
{
	GUID parsed{} ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
	return guid( value) && SUCCEEDED( IIDFromString( std::wstring{value}.c_str(), &parsed)) &&
		   IsEqualGUID( parsed, expected) ;
}
//------------------------------------------------------------------------------
/**
 * @brief service/節/単一module用の有限な原名を確認します
 * @param[in] value 原名です。pathや空白を許しません
 * @param[in] maximum 許す最大文字数です
 * @return ASCIIの英数字/underscore/dot/hyphenだけの場合trueです
 */
//------------------------------------------------------------------------------
bool simpleName( std::wstring_view value, std::size_t maximum)
{
	return !value.empty() && value.size() <= maximum && value != L"." && value != L".." &&
		   std::ranges::all_of( value, []( wchar_t c) {
			   return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
					  (c >= L'0' && c <= L'9') || c == L'_' || c == L'.' || c == L'-' ;
		   }) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 非実行の表示文字列を有限/制御文字なしへ限定します
 * @param[in] value 原表示値です
 * @return 非空/最大254文字/制御文字なしの場合trueです
 */
//------------------------------------------------------------------------------
bool displayText( std::wstring_view value)
{
	return !value.empty() && value.size() <= 254U &&
		   std::ranges::none_of( value, []( wchar_t c) { return c < L' ' || c == 0x7f ; }) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同検査の最初の固定拒否を保持します
 * @param[in,out] state 同期中だけ有効な二相検査です
 * @param[in] stage 固定された拒否区分です
 * @param[in] observed 型/件数の補足です。任意文字列を含みません
 * @return ERROR_NOT_SUPPORTEDのHRESULTです
 */
//------------------------------------------------------------------------------
NativeError rejected( EffectState &state, SystemInfDiagnosticStage stage,
					 std::uint32_t observed = 0U)
{
	// 後段の欠測で元拒否を上書きしません
	if( state.stage == 0U) {
		state.stage	   = static_cast<std::uint32_t>( stage) ;
		state.observed = observed ;
	}

	return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同document/節/文脈/所有者を一意のpendingへ追加します
 * @param[in,out] state 既読節と共有予算を持つ検査です
 * @param[in] source 元参照の所有documentです
 * @param[in] name 同原文の正確な節名です
 * @param[in] context 追加する参照の型です
 * @param[in] owner 同原文のservice/interface所有先です
 * @return 一意追加/共有済み0、不正/容量のHRESULTです
 */
//------------------------------------------------------------------------------
NativeError appendSection( EffectState &state, const SystemInfSection &source,
						  std::wstring_view name, SystemInfContext context, std::wstring_view owner)
{
	// 共有済みtargetでも元参照辺を省略して上限を回避しません
	if( state.references >= 4096U) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	++state.references ;
	// 空/境界外/未展開tokenを別節へ補完しません
	if( name.empty() || name.size() > 254U ||
	   name.find_first_of( L"\\/:%\r\n\0", 0U, 7U) != name.npos) {
		return rejected( state, SystemInfDiagnosticStage::REFERENCE) ;
	}

	SystemInfSection target{source.document, std::wstring{name}, context,
							context == SystemInfContext::REGISTRY ||
									context == SystemInfContext::PROPERTY
								? source.context
								: context,
							std::wstring{owner}} ;	// 元scopeをdata参照へ保存します
	const auto		 present = std::ranges::find_if(
		  state.sections,
		  [&]( const auto &old) {	// 独立した条件又は到達件数です。別条件の成功を借用しません
			  return old.document == target.document && same( old.name, target.name) &&
					 old.context == target.context && old.scope == target.scope &&
					 same( old.owner, target.owner) ;
		  }) ;
	// 元共有参照の再走査を止めます
	if( present != state.sections.end()) {
		return 0U ;
	}

	// 元1024節の共有上限を追加前に保ちます
	if( state.sections.size() >= 1024U) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	state.sections.push_back( std::move( target)) ;
	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 全行を先に列挙しservice/interface/frameworkの参照を原順で追加します
 * @param[in,out] state 元全seedと完全readerを持つ検査です
 * @return 全列挙0、元読取又は不正/容量のHRESULTです
 */
//------------------------------------------------------------------------------
NativeError collectEffects( EffectState &state)
{
	// 追加した前方参照まで処理し、宣言順へ成功を依存させません
	for( std::size_t i = 0U; i < state.sections.size(); ++i) {
		const auto				  source = state.sections[i] ;				// vector再配置から独立した元参照です
		std::vector<SystemInfRow> rows ;									// 元節全行を所有します
		auto					  error = state.api.read( source, rows) ;	// 同documentだけを読みます
		// 途中読取を部分集合の成功へ変換しません
		if( error != 0U) {
			// 元の不正/不一致又は不足を成功へ補完しません
			if( state.stage == 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				state.stage	   = static_cast<std::uint32_t>( SystemInfDiagnosticStage::READ) ;
				state.observed = static_cast<std::uint32_t>( source.context) ;
			}

			return error ;
		}

		// 全行で共有する上限を減算前に確認します
		if( state.result.effects.size() > 4096U ||
		   rows.size() > 4096U - state.result.effects.size()) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 全fieldを保持し、明示data行も落としません
		for( auto &row : rows) {
			// 既field容量を型の追加で広げません
			if( row.values.size() > 64U) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			state.result.effects.push_back( {source, row}) ;
			// Data行はdirective名として再解釈しません
			if( source.context == SystemInfContext::REGISTRY ||
			   source.context == SystemInfContext::PROPERTY) {
				continue ;
			}

			const auto key = folded( row.key) ;	// 比較専用の固定keyです
			// 元AddReg/AddPropertyの全参照を列挙します
			if( key == L"addreg" || key == L"addproperty") {
				// 空参照は無作用としません
				if( row.values.empty()) {
					return rejected( state, SystemInfDiagnosticStage::DATA_REFERENCE) ;
				}

				// 各data節を同原文・同親scopeへ結びます
				for( const auto &name : row.values) {
					error = appendSection( state, source, name,
										  key == L"addreg" ? SystemInfContext::REGISTRY
														   : SystemInfContext::PROPERTY,
										  source.owner) ;
					// 不正節名の後続参照へ進みません
					if( error != 0U) {
						return error ;
					}
				}
			}
			// 後続の別型/文脈だけを判定し、未確認を既定へ変換しません
			else if( key == L"addservice" || key == L"addinterface" ||
					key == L"kmdfservice" ||	// 不明/不一致の元値を成功や別scopeへ補完しません
					key == L"umdfservice" || key == L"companionconfiguration") {
				const bool three = key == L"addservice" || key == L"addinterface" ;	// 元参照位置です
				const auto field = three ? 2U : 1U ;								// 0起点で元第三/第二fieldだけです
				// 必須fieldと任意第四field以外を切り捨てません
				if( row.values.size() < field + 1U || row.values.size() > (three ? 4U : 2U)) {
					return rejected( state, SystemInfDiagnosticStage::DECLARATION) ;
				}

				const auto context =
					key == L"addservice"
						? SystemInfContext::SERVICE	// 同原文/操作へ結ぶ検査又は結果の所有値です
					: key == L"addinterface" ? SystemInfContext::INTERFACE
					: key == L"kmdfservice"	 ? SystemInfContext::KMDF
					: key == L"umdfservice"	 ? SystemInfContext::UMDF
											 : SystemInfContext::COMPANION ;
				const auto owner = key == L"addinterface" ? row.values[0] + L"|" + row.values[1]
														  : row.values[0] ;	// 型別の所有先です
				error			 = appendSection( state, source, row.values[field], context, owner) ;
				// 元参照を読めない状態を標準serviceへ補完しません
				if( error != 0U) {
					return error ;
				}

				// AddServiceだけは第四fieldをevent-logとして同serviceへ結びます
				if( key == L"addservice" && row.values.size() == 4U && !row.values[3].empty()) {
					error = appendSection( state, source, row.values[3], SystemInfContext::EVENT_LOG,
										  row.values[0]) ;
					// event-log不足を無作用にしません
					if( error != 0U) {
						return error ;
					}
				}
			}
		}
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同原節の一意な単一fieldを取得します
 * @param[in] state 列挙済みの全原行です
 * @param[in] section 同原document/文脈の参照です
 * @param[in] key 必須の固定keyです
 * @return 一意かつ単一fieldの場合だけ非所有view、それ以外は空です
 */
//------------------------------------------------------------------------------
std::wstring_view oneField( const EffectState &state, const SystemInfSection &section,
						   std::wstring_view key)
{
	const SystemInfRow *found = nullptr ;	// 全列挙期間中だけ借用します
	// 重複や余分fieldを先頭値へ縮約しません
	for( const auto &effect : state.result.effects) {
		// 同原document/節/文脈の指定keyだけを対象にします
		if( effect.source == section && same( effect.row.key, key)) {
			// 重複を正常値として返しません
			if( found || effect.row.values.size() != 1U) {
				return {} ;
			}

			found = &effect.row ;
		}
	}

	return found ? std::wstring_view{found->values.front()} : std::wstring_view{} ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同原文のservice名又はframework名の明示宣言を探します
 * @param[in] state 全列挙済みの作用です
 * @param[in] document 元document identityです
 * @param[in] key 固定directive名です
 * @param[in] name 元service名です
 * @return 一意な宣言の場合だけ非所有pointerです
 */
//------------------------------------------------------------------------------
const SystemInfEffect *declaration( const EffectState &state, std::uint64_t document,
								   std::wstring_view key, std::wstring_view name)
{
	const SystemInfEffect *found = nullptr ;	// 同同期の列挙済み原行だけです
	// 別documentや同名二宣言を一件へ縮約しません
	for( const auto &effect : state.result.effects) {
		// 正確な元directiveの先頭fieldを照合します
		if( effect.source.document == document && same( effect.row.key, key) &&
		   !effect.row.values.empty() && same( effect.row.values[0], name)) {
			// 重複は一意関係の証明に使いません
			if( found) {
				return nullptr ;
			}

			found = &effect ;
		}
	}

	return found ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同原宣言が参照した型付き節を一意に取得します
 * @param[in] state 列挙済みの全節です
 * @param[in] source 元宣言行です
 * @param[in] context 必要な参照先文脈です
 * @param[in] field 0起点の元節名fieldです
 * @return 同document/節/型/所有者の参照、なければnullptrです
 */
//------------------------------------------------------------------------------
const SystemInfSection *referenced( const EffectState &state, const SystemInfEffect &source,
								   SystemInfContext context, std::size_t field)
{
	// 欠損fieldから節名を推測しません
	if( field >= source.row.values.size()) {
		return nullptr ;
	}

	const auto				owner = context == SystemInfContext::INTERFACE
										? source.row.values[0] + L"|" + source.row.values[1]
										: source.row.values[0] ;	// 元宣言の所有先です
	const SystemInfSection *found = nullptr ;						// 一意な全tupleだけを返します
	// 同名の別所有者と別scopeを先頭一致で借りません
	for( const auto &section : state.sections) {
		// 元document/節/型/scope/所有者の全てを要求します
		if( section.document == source.source.document &&
		   same( section.name, source.row.values[field]) && section.context == context &&
		   section.scope == context && same( section.owner, owner)) {
			// 複数の受理候補を一意と扱いません
			if( found) {
				return nullptr ;
			}

			found = &section ;
		}
	}

	return found ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同SYSTEMが宣言したmodule参照を実file/CAT/SDへ接続します
 * @param[in,out] state 全原作用と完全な限定操作です
 * @param[in] document 元document identityです
 * @param[in] value 元module/ServiceBinary値です。任意引数を除きません
 * @param[in] role 同じ拒否へ保持する閉じたmodule用途です
 * @return 実体成立0、元検査errorです
 */
//------------------------------------------------------------------------------
NativeError verifyModule( EffectState &state, std::uint64_t document, std::wstring_view value,
						 SystemInfModuleRole role)
{
	// 同じfileの参照も全graphの有限辺数へ計上します
	if( state.references >= 4096U) {
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	++state.references ;
	// 元値の欠落を実Windows名へ補完しません
	if( value.empty() || value.size() > 254U) {
		return rejected( state, SystemInfDiagnosticStage::MODULE) ;
	}

	const auto error = state.api.module( document, value) ;	// 直後に保持した元API又は検査errorです
	// 原API errorを維持して閉じた元役割だけをfirst-errorへ残します
	if( error != 0U && state.stage == 0U) {
		state.stage	   = static_cast<std::uint32_t>( SystemInfDiagnosticStage::MODULE) ;
		state.observed = static_cast<std::uint32_t>( role) ;
	}

	return error ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元framework versionの全数値要素を確認します
 * @param[in] value 同SYSTEM原文の展開済みversionです
 * @return 二又は三要素が16bit非負整数の場合trueです
 */
//------------------------------------------------------------------------------
bool frameworkVersion( std::wstring_view value)
{
	std::size_t count{} ;	// 元versionの要素数です
	// 全要素を読み、prefixだけの一致を使いません
	while( !value.empty()) {
		const auto	  dot = value.find( L'.') ;	// 次の明示区切りです
		std::uint64_t part{} ;					// 同要素だけの数値です
		// 空/過長/余分な要素を拒否します
		if( ++count > 3U || !scalar( value.substr( 0U, dot), part) || part > 65535U) {
			return false ;
		}

		// 最後まで消費した場合だけ終わります
		if( dot == value.npos) {
			return count >= 2U ;
		}

		value.remove_prefix( dot + 1U) ;
	}

	return false ;
}
//------------------------------------------------------------------------------
/**
 * @brief service/framework/interfaceの閉じた全fieldと実体関係を確認します
 * @param[in,out] state 全列挙済みの二相検査です
 * @return 全構造/実体成立0、元error又は固定型拒否です
 */
//------------------------------------------------------------------------------
NativeError verifyStructures( EffectState &state)
{
	std::set<std::wstring> declared ;	// 同doc/型/名前の重複を参照前に拒否します
	// 宣言順にかかわらず、重複を不存在のSCM fallbackへ変換しません
	for( const auto &effect : state.result.effects) {
		const auto key = folded( effect.row.key) ;	// 固定directive分類です
		// 所有関係を定義する全named宣言を対象にします
		if( key == L"addservice" || key == L"kmdfservice" || key == L"umdfservice" ||
		   key == L"companionconfiguration") {
			// 名前欠落又は同名二宣言は別の成功源で救済しません
			if( effect.row.values.empty() ||
			   !declared
					.insert( std::to_wstring( effect.source.document) + L"|" + key + L"|" +
							folded( effect.row.values[0]))
					.second) {
				return rejected( state, SystemInfDiagnosticStage::DECLARATION) ;
			}
		}
	}

	// 全宣言を読む前にregistryの前方参照を承認しません
	for( const auto &effect : state.result.effects) {
		const auto &row		= effect.row ;				// 同原key/全fieldです
		const auto	key		= folded( row.key) ;		// 比較用だけです
		const auto	context = effect.source.context ;	// 同原作用の型です
		const auto &v		= row.values ;				// 原順の同期借用です
		// data節は後段の型付きvalidatorが全行確認します
		if( context == SystemInfContext::REGISTRY || context == SystemInfContext::PROPERTY) {
			continue ;
		}

		// graphが独立検証した元Include/Needsは空fieldを救済しません
		if( key == L"include" || key == L"needs") {
			// 明示した全参照が有限名であることを保持します
			if( v.empty() || std::ranges::any_of( v, []( const auto &name) {
				   return name.empty() || name.size() > 254U ||
						  name.find_first_of( L"\\/:%") != name.npos ;
			   })) {
				return rejected( state, SystemInfDiagnosticStage::REFERENCE) ;
			}

			continue ;
		}

		// 元CopyFilesはNativeLoaderの実source/target/hash/CATへも必ず接続します
		if( key == L"copyfiles") {
			// 空copyを無作用へ変換しません
			if( v.empty() || v.size() > 4096U - state.references) {
				return rejected( state, SystemInfDiagnosticStage::COPY_REFERENCE) ;
			}

			// 既読copyも元参照辺を消費します
			state.references += v.size() ;
			state.result.copySections.push_back( effect.source) ;
			continue ;
		}

		// registry/property参照は既列挙を必要とし、許可の代替にしません
		if( key == L"addreg" || key == L"addproperty") {
			continue ;
		}

		// device情報優先だけを一値booleanへ限定します
		if( key == L"preferdeviceinfo") {
			// 別文脈や別値を未知の正常値にしません
			if( context != SystemInfContext::DEVICE || v.size() != 1U || v[0] != L"1") {
				return rejected( state, SystemInfDiagnosticStage::DEVICE_PREFERENCE) ;
			}

			continue ;
		}

		// 全AddServiceを同原service-installへ結びます
		if( key == L"addservice") {
			std::uint64_t flags{} ;	// 元associated-service flagです
			const auto	  section =
				referenced( state, effect, SystemInfContext::SERVICE,
						   2U) ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			// 欠損/多義/未知flagで別serviceへ進みません
			if( context != SystemInfContext::SERVICES || !section || v.size() < 3U ||
			   v.size() > 4U || !simpleName( v[0], 31U) || !scalar( v[1], flags) ||
			   (flags != 0U && flags != 2U)) {
				return rejected( state, SystemInfDiagnosticStage::SERVICE) ;
			}

			std::uint64_t type{} ;													// 元kernel型です
			std::uint64_t start{} ;													// 元開始方式です
			std::uint64_t control{} ;												// 元error controlです
			const auto	  binary = oneField( state, *section, L"ServiceBinary") ;	// 同原moduleです
			// 必須fieldの一意性/数値を全て要求します
			if( !scalar( oneField( state, *section, L"ServiceType"), type) || type != 1U ||
			   !scalar( oneField( state, *section, L"StartType"), start) || start != 3U ||
			   !scalar( oneField( state, *section, L"ErrorControl"), control) || control != 1U ||
			   !folded( binary).ends_with( L".sys")) {
				return rejected( state, SystemInfDiagnosticStage::SERVICE) ;
			}

			const auto error =
				verifyModule( state, effect.source.document, binary,
							 SystemInfModuleRole::SERVICE_SYS) ;	// 現提供/CATへ結合します
			// 宣言だけでkernel実体を承認しません
			if( error != 0U) {
				return error ;
			}

			continue ;
		}

		// interfaceは元GUID/referenceと同documentの節だけを使用します
		if( key == L"addinterface") {
			std::uint64_t flags{} ;	// 元任意flagです
			// 異文脈/不正GUID/余分flagを拒否します
			if( context != SystemInfContext::INTERFACES || v.size() < 3U || v.size() > 4U ||
			   !guid( v[0]) || (!v[1].empty() && !simpleName( v[1], 254U)) ||
			   (v.size() == 4U && (!scalar( v[3], flags) || flags != 0U))) {
				return rejected( state, SystemInfDiagnosticStage::INTERFACE) ;
			}

			continue ;
		}

		// frameworkは同原二fieldとlibrary versionへ結びます
		if( key == L"kmdfservice" || key == L"umdfservice") {
			const bool kernel = key == L"kmdfservice" ;	// 型を混ぜません
			const auto section =
				referenced(	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
					state, effect, kernel ? SystemInfContext::KMDF : SystemInfContext::UMDF, 1U) ;
			// 任意serviceや別frameworkを型の不足で救済しません
			if( context != SystemInfContext::FRAMEWORK || v.size() != 2U || !simpleName( v[0], 31U) ||
			   !section ||
			   !frameworkVersion( oneField(
				   state, *section, kernel ? L"KmdfLibraryVersion" : L"UmdfLibraryVersion"))) {
				return rejected( state, SystemInfDiagnosticStage::FRAMEWORK) ;
			}

			// KMDFのbinary再宣言がない場合だけ正確な既存serviceを照会します
			if( kernel && !declaration( state, effect.source.document, L"AddService", v[0])) {
				SystemServiceEvidence service ;	// 安定field/元SDだけの結果です
				auto				  error =
					// 直後に保持した元API又は検査errorです
					state.api.service( v[0], service) ;
				// 元の不正/不一致又は不足を成功へ補完しません
				if( error != 0U &&
				   state.stage == 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
					state.stage =
						static_cast<std::uint32_t>( SystemInfDiagnosticStage::SERVICE_SNAPSHOT) ;
					state.observed = 1U ;
				}

				// 名前/型/元binaryを別のinbox serviceへ補完しません
				if( error != 0U || !same( service.name, v[0]) || service.type != 1U ||
				   service.start != 3U || service.security.empty() ||
				   validateSystemServiceEvidence( service) != 0U) {
					return error != 0U
							   ? error
							   : rejected( state, SystemInfDiagnosticStage::SERVICE_SNAPSHOT) ;
				}

				std::wstring module =
					service.binary ;	// 元configは変更せず実file位置を別に解決します
				constexpr std::wstring_view RELATIVE_DRIVER =
					L"System32\\drivers\\" ;	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
				// 元の不正/不一致又は不足を成功へ補完しません
				if( module.size() >
					   RELATIVE_DRIVER.size() &&	// 不明/不一致の元値を成功や別scopeへ補完しません
				   same( std::wstring_view{module}.substr( 0U, RELATIVE_DRIVER.size()),
						RELATIVE_DRIVER)) {
					const auto leaf = std::wstring_view{module}.substr(
						// 元所有scopeへ結ぶ位置です。任意探索へ使いません
						RELATIVE_DRIVER.size()) ;
					// 元の不正/不一致又は不足を成功へ補完しません
					if( !simpleName( leaf, 254U) ||
					   !folded( leaf).ends_with(
						   L".sys")) {	// 不明/不一致の元値を成功や別scopeへ補完しません
						return rejected( state, SystemInfDiagnosticStage::SERVICE_SNAPSHOT) ;
					}

					module = L"%12%\\" + std::wstring{leaf} ;
				}

				error = verifyModule( state, effect.source.document, module,
									 SystemInfModuleRole::EXISTING_SERVICE) ;
				// 保護されたservice名だけを実fileの証拠にしません
				if( error != 0U) {
					return error ;
				}

				const auto old =
					std::ranges::find( state.result.services,
									  service.name,	// 同原文/操作へ結ぶ検査又は結果の所有値です
									  &SystemServiceEvidence::name) ;
				// 同名の異なるconfigを別成功へ置換しません
				if( old != state.result.services.end() && *old != service) {
					return HRESULT_FROM_WIN32( ERROR_RETRY) ;
				}

				// 重複照会の結果は一つの原tupleへ束縛します
				if( old == state.result.services.end()) {
					state.result.services.push_back( std::move( service)) ;
				}
			}

			// Secure companion以外のUMDFを今回の追加型へ含めません
			if( !kernel) {
				std::uint64_t identity{} ;	// 原Windows限定identityです
				const auto	  binary =
					oneField( state, *section,
							 L"ServiceBinary") ;	// この同期/fixtureが所有する資源又は原状態です
				// 既知型/identityと原UMDF実体を全て必要とします
				if( !same( oneField( state, *section, L"ServiceType"), L"SecureCompanion") ||
				   !scalar( oneField( state, *section, L"TrustletIdentity"), identity) ||
				   identity != 4096U || !folded( binary).ends_with( L".dll") ||
				   folded( binary).find( L"\\umdf\\") == std::wstring::npos) {
					return rejected( state, SystemInfDiagnosticStage::SECURE_COMPANION) ;
				}

				const auto error = verifyModule( state, effect.source.document,
												binary,	// 直後に保持した元API又は検査errorです
												SystemInfModuleRole::UMDF_DLL) ;
				// 未提供/署名不明をframework名で救済しません
				if( error != 0U) {
					return error ;
				}
			}

			continue ;
		}

		// companionの親KMDFと子UMDFを同原文へ閉じます
		if( key == L"companionconfiguration") {
			const auto section =
				referenced( state, effect, SystemInfContext::COMPANION,
						   1U) ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			// 孤立した設定から任意serviceを追加しません
			if( context != SystemInfContext::FRAMEWORK || v.size() != 2U || !section ||
			   !declaration( state, effect.source.document, L"KmdfService", v[0])) {
				return rejected( state, SystemInfDiagnosticStage::COMPANION) ;
			}

			const auto child = oneField( state, *section, L"CompanionServices") ;	// 現型は一子です
			// 別doc/未宣言/未知子を標準companionへしません
			if( !simpleName( child, 31U) ||
			   !declaration( state, effect.source.document, L"UmdfService", child)) {
				return rejected( state, SystemInfDiagnosticStage::COMPANION) ;
			}

			// 子serviceへの辺も既graphと同じ上限へ計上します
			if( state.references >= 4096U) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			++state.references ;
			continue ;
		}

		const bool serviceField =	// 元field/型の全消費を確認する局所位置又は閉じた分類です
			context == SystemInfContext::SERVICE &&
			(key == L"displayname" || key == L"servicetype" || key == L"starttype" ||
			 key == L"errorcontrol" || key == L"servicebinary") ;
		const bool kernelField = context == SystemInfContext::KMDF &&
								 // 元field/型の全消費を確認する局所位置又は閉じた分類です
								 key == L"kmdflibraryversion" ;
		const bool userField =
			context ==
				SystemInfContext::UMDF &&	// 元field/型の全消費を確認する局所位置又は閉じた分類です
			(key == L"umdflibraryversion" || key == L"servicebinary" || key == L"servicetype" ||
			 key == L"trustletidentity") ;
		const bool companionField =	// 元field/型の全消費を確認する局所位置又は閉じた分類です
			context == SystemInfContext::COMPANION && key == L"companionservices" ;
		// 全scalar fieldの一意性と型を親宣言検査後も維持します
		if( (serviceField || kernelField || userField || companionField) && v.size() == 1U &&
		   !oneField( state, effect.source, row.key).empty()) {
			continue ;
		}

		return rejected( state, SystemInfDiagnosticStage::DIRECTIVE,
						static_cast<std::uint32_t>( context)) ;
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原registry pathを空成分を許さず分離します
 * @param[in] path 元subkeyです。正規化で別位置へ移しません
 * @return 元順の成分です。不正時は空です
 */
//------------------------------------------------------------------------------
std::vector<std::wstring> pathParts( std::wstring_view path)
{
	std::vector<std::wstring> result ;	// 比較専用の有限成分です
	// 全pathを消費してからscopeを選びます
	while( !path.empty()) {
		const auto slash = path.find( L'\\') ;			// 次の元区切りです
		const auto part	 = path.substr( 0U, slash) ;	// 一成分だけです
		// 空/親/制御文字/過長を解決して受理しません
		if( part.empty() || part == L"." || part == L".." || !displayText( part) ||
		   part.find( L'/') != part.npos) {
			return {} ;
		}

		result.emplace_back( part) ;
		// 最後まで読んだ場合だけ正常終了します
		if( slash == path.npos) {
			return result ;
		}

		path.remove_prefix( slash + 1U) ;
	}

	return {} ;
}
//------------------------------------------------------------------------------
/**
 * @brief 非実行表示値にprogram参照を混ぜないことを確認します
 * @param[in] value 原の有限表示値です
 * @return 制御/未展開token/実行形式参照がない場合trueです
 */
//------------------------------------------------------------------------------
bool dataText( std::wstring_view value)
{
	const auto lower = folded( value) ;	// 原値を変更しない比較copyです
	return displayText( value) && value.find( L'%') == value.npos &&
		   lower.find( L".exe") == lower.npos && lower.find( L".dll") == lower.npos &&
		   lower.find( L".sys") == lower.npos && lower.find( L".com") == lower.npos ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元module pathの最後の名だけを関係比較へ使います
 * @param[in] value 未変更の原module値です
 * @return 元basenameのviewです。位置/署名の検査は別のmodule callbackが必須です
 */
//------------------------------------------------------------------------------
std::wstring_view moduleName( std::wstring_view value)
{
	const auto slash = value.find_last_of( L"\\/") ;	// 原区切りの位置です
	return slash == value.npos ? value : value.substr( slash + 1U) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同原serviceの明示binaryと参照moduleを比較します
 * @param[in] state 全列挙済み作用です
 * @param[in] document 元document identityです
 * @param[in] service 元service名です。空なら同docの全関連serviceから一意に探します
 * @param[in] module 同原文の参照moduleです
 * @return 同原serviceの一意な実binaryと一致する場合trueです
 */
//------------------------------------------------------------------------------
bool serviceModule( const EffectState &state, std::uint64_t document, std::wstring_view service,
				   std::wstring_view module)
{
	std::size_t matches{} ;	// 同docでの一意性だけです
	// 原AddServiceが実際に所有するservice-installだけへ照合します
	for( const auto &effect : state.result.effects) {
		// 別documentや別serviceのbinaryを借りません
		if( effect.source.document == document && same( effect.row.key, L"AddService") &&
		   !effect.row.values.empty() && (service.empty() || same( effect.row.values[0], service))) {
			const auto section =
				referenced( state, effect, SystemInfContext::SERVICE,
						   2U) ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			// 参照先まで一意で同moduleの場合だけ数えます
			if( section &&
			   same( moduleName( oneField( state, *section, L"ServiceBinary")), moduleName( module))) {
				++matches ;
			}
		}
	}

	return matches == 1U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 標準event-channelのSDDLデータを正確な六ACE policyへ照合します
 * @param[in] text 同SYSTEM原文のChannelAccess値です
 * @return 元SD構文/六ACE policy成立0、元API又は閉じたpolicy拒否のHRESULTです
 * @note Descriptorは読取/解放だけで適用しません。通常INF .securityの許可ではありません
 */
//------------------------------------------------------------------------------
NativeError channelSecurity( const std::wstring &text)
{
	constexpr std::wstring_view PREFIX =
		L"O:BAG:SYD:" ;	// この閉じた作用型だけが使用する固定scopeです
	const std::array<std::pair<std::wstring_view, std::uint64_t>, 6U> tokens{
		{{L"SY", 0xf0007U},
		 {L"BA", 7U},
		 {L"BO", 3U},
		 {L"SO", 5U},
		 {L"S-1-5-33", 2U},
		 {L"S-1-5-32-573", 1U}}} ;	// このdata型だけの全構文です
	// 変換APIのnull終端prefix受理を全原値の受理へしません
	if( !text.starts_with( PREFIX) || text.find( L'\0') != text.npos) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	std::wstring_view remaining{text.data() + PREFIX.size(),
								// 元全長又は共同予算の有限件数です
								text.size() - PREFIX.size()} ;
	// 元順の六ACEを全消費し、追加scope/flag/条件/余白を認めません
	for( const auto &[sid, mask] : tokens) {
		const auto end =
			// 元field/型の全消費を確認する局所位置又は閉じた分類です
			remaining.find( L')') ;
		const auto entry =
			// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			remaining.substr( 0U, end) ;
		const auto separator =
			// 元field/型の全消費を確認する局所位置又は閉じた分類です
			entry.find( L";;;", 4U) ;
		std::uint64_t actual{} ;	// 実操作から得た観測値です。独立期待とは分けます
		// 数値mask以外の権限名や未知SIDを補完しません
		if( end == remaining.npos || !entry.starts_with( L"(A;;") || separator == entry.npos ||
		   !scalar( entry.substr( 4U, separator - 4U), actual) || actual != mask ||
		   entry.substr( separator + 3U) != sid) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		remaining.remove_prefix( end + 1U) ;
	}

	// 正しい六ACEの後に任意textを残しません
	if( !remaining.empty()) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	PSECURITY_DESCRIPTOR raw{} ;	// 変換APIが返す局所所有SDです
	// 原構文の失敗を別のSDへ変換しません
	if( !ConvertStringSecurityDescriptorToSecurityDescriptorW( text.c_str(), SDDL_REVISION_1, &raw,
															 nullptr)) {
		const auto error = GetLastError() ;	// 直後の元値だけです
		return error ? static_cast<NativeError>( HRESULT_FROM_WIN32( error)) : E_UNEXPECTED ;
	}

	const std::unique_ptr<void, decltype( &LocalFree)> descriptor{raw,
																 &LocalFree} ;	// 同同期で解放します
	PSID											  owner{} ;					// 元SD内の非所有SIDです
	PSID											  group{} ;					// 元SD内の非所有SIDです
	BOOL											  defaulted{} ;				// 既定化の有無です
	BOOL											  present{} ;				// DACLの実在です
	PACL											  acl{} ;					// 元順の非所有DACLです
	SECURITY_DESCRIPTOR_CONTROL						  control{} ;				// 余分な制御を認めません
	DWORD											  revision{} ;				// SD APIの元revisionです
	// null/absolute/追加controlを標準channel policyへしません
	if( !IsValidSecurityDescriptor( raw) || !GetSecurityDescriptorOwner( raw, &owner, &defaulted) ||
	   !owner || !IsValidSid( owner) || !GetSecurityDescriptorGroup( raw, &group, &defaulted) ||
	   !group || !IsValidSid( group) ||
	   !GetSecurityDescriptorDacl( raw, &present, &acl, &defaulted) ||
	   !GetSecurityDescriptorControl( raw, &control, &revision) || !present || !acl ||
	   !IsValidAcl( acl) || control != (SE_SELF_RELATIVE | SE_DACL_PRESENT) || acl->AceCount != 6U) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	const std::array<std::pair<const wchar_t *, DWORD>, 6U> expected{
		{{L"S-1-5-18", 0xf0007U},
		 {L"S-1-5-32-544", 7U},
		 {L"S-1-5-32-551", 3U},
		 {L"S-1-5-32-549", 5U},
		 {L"S-1-5-33", 2U},
		 {L"S-1-5-32-573", 1U}}} ;	// 標準channelだけのprincipal/maskです
	// 元ACE順/型/flag/SID/maskを全件確認します
	for( DWORD i = 0U; i < expected.size(); ++i) {
		void *entry{} ;	// 一ACEの借用です
		PSID  sid{} ;	// 固定principalの局所所有です
		// 読取不能/別principalをpolicyへ補完しません
		if( !GetAce( acl, i, &entry) || !ConvertStringSidToSidW( expected[i].first, &sid)) {
			const auto error = GetLastError() ;	// 直後に保持した元API又は検査errorです
			return error ? static_cast<NativeError>( HRESULT_FROM_WIN32( error)) : E_UNEXPECTED ;
		}

		const std::unique_ptr<void, decltype( &LocalFree)> expectedSid{
			sid, &LocalFree} ;	// このACEで解放します
		const auto ace =
			// 型確認前はheaderだけ読みます
			static_cast<const ACCESS_ALLOWED_ACE *>( entry) ;
		// 通常ALLOW以外/追加flag/違うmaskを認めません
		if( ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags != 0U ||
		   ace->Header.AceSize != sizeof( ACCESS_ALLOWED_ACE) - sizeof( DWORD) + GetLengthSid( sid) ||
		   ace->Mask != expected[i].second || !EqualSid( const_cast<DWORD *>( &ace->SidStart), sid) ||
		   (i == 0U && !EqualSid( group, sid)) || (i == 1U && !EqualSid( owner, sid))) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元registry行の型/field数と有限scalarを取得します
 * @param[in] row 同原文の全fieldです
 * @param[out] flags 元DWORD flagです。空は元REG_SZ既定です
 * @param[out] value 単一scalar型の場合の全値です。それ以外0です
 * @return 最低四fieldとflag/scalarの完全解析が成立する場合trueです
 */
//------------------------------------------------------------------------------
bool registryType( const SystemInfRow &row, std::uint64_t &flags, std::uint64_t &value)
{
	flags		  = 0U ;
	value		  = 0U ;
	const auto &v = row.values ;	// 全原fieldを借用します
	// field欠落やflag不正を既定へ変換しません
	if( v.size() < 3U ||
	   (v.size() >= 4U && !v[3].empty() && (!scalar( v[3], flags) || flags > 0xffffffffULL))) {
		return false ;
	}

	// DWORD/QWORDはdata全桁を確認します
	if( flags == 0x10001U || flags == 0xb0001U) {
		return v.size() == 5U && scalar( v[4], value) &&
			   (flags != 0x10001U || value <= 0xffffffffULL) ;
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同SYSTEM原文のETW行を閉じたchannel/publisher/logger型へ分離します
 * @param[in,out] state 全原行/実module操作です
 * @param[in] effect 同serviceのevent-logから来た一registry行です
 * @param[in] flags 完全解析済みflagです
 * @param[in] number 完全解析済みscalar値です
 * @return 既知型/実体成立0、元error又は固定型拒否です
 */
//------------------------------------------------------------------------------
NativeError eventRegistry( EffectState &state, const SystemInfEffect &effect, std::uint64_t flags,
						  std::uint64_t number)
{
	const auto &v = effect.row.values ;	// 元五fieldだけです
	// ETW以外のroot/文脈/field数をここへ流用しません
	if( effect.source.scope != SystemInfContext::EVENT_LOG || v.size() != 5U ||
	   !same( v[0], L"HKLM")) {
		return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
	}

	const auto					path	= folded( v[1]) ;	// 位置の比較用です
	const auto					key		= folded( v[2]) ;	// 固定値名だけです
	constexpr std::wstring_view CHANNEL =					// この閉じた作用型だけが使用する固定scopeです
		L"software\\microsoft\\windows\\currentversion\\winevt\\channels\\" ;
	constexpr std::wstring_view PUBLISHER =	// この閉じた作用型だけが使用する固定scopeです
		L"software\\microsoft\\windows\\currentversion\\winevt\\publishers\\" ;
	constexpr std::wstring_view LOGGER =	// この閉じた作用型だけが使用する固定scopeです
		L"system\\currentcontrolset\\control\\wmi\\autologger\\eventlog-system\\" ;
	// Channelは標準二種類の同publisherだけです
	if( path.starts_with( CHANNEL)) {
		const auto channel = std::wstring_view{path}.substr( CHANNEL.size()) ;	// 元channel suffixです
		const bool operational =
			// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
			channel.ends_with( L"/operational") ;
		const bool analytic =
			// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
			channel.ends_with( L"/analytic") ;
		// 別path/不明channelを許しません
		if( channel.find( L'\\') != channel.npos || (!operational && !analytic)) {
			return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
		}

		// ChannelAccessだけは既知SDDLデータの全構造を確認します
		if( key == L"channelaccess" && flags == 0U) {
			return channelSecurity( v[4]) ;
		}

		// 元GUID/boolean/enumを個別に確認します
		if( (key == L"owningpublisher" && flags == 0U && guid( v[4])) ||
		   (key == L"enabled" && flags == 0x10001U && number <= 1U) ||
		   (key == L"isolation" && flags == 0x10001U && number == 1U) ||
		   (key == L"type" && flags == 0x10001U && number == (operational ? 1U : 2U))) {
			return 0U ;
		}

		return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
	}

	// Publisherの全dataは同service/原SYSへ結びます
	if( path.starts_with( PUBLISHER)) {
		const auto tail = std::wstring_view{v[1]}.substr( PUBLISHER.size()) ;	// 元caseのGUIDです
		// GUID以外のpublisherは追加しません
		if( tail.size() < 38U || !guid( tail.substr( 0U, 38U))) {
			return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
		}

		const auto suffix = folded( tail.substr( 38U)) ;	// 固定後続位置です
		// 原publisher表示名だけを非実行dataとして扱います
		if( suffix.empty() && key.empty() && flags == 0U && dataText( v[4])) {
			return 0U ;
		}

		// Message/Resourceは同serviceの提供SYSだけです
		if( suffix.empty() && (key == L"resourcefilename" || key == L"messagefilename") &&
		   flags == 0x20000U &&
		   serviceModule( state, effect.source.document, effect.source.owner, v[4])) {
			return verifyModule( state, effect.source.document, v[4],
								SystemInfModuleRole::EVENT_RESOURCE) ;
		}

		// 二channelのCountを元宣言へ固定します
		if( suffix == L"\\channelreferences" && key == L"count" && flags == 0x10001U &&
		   number == 2U) {
			return 0U ;
		}

		// 連番二件の名前/Id/flag以外を追加しません
		if( suffix == L"\\channelreferences\\0" || suffix == L"\\channelreferences\\1") {
			const auto index = suffix.back() == L'0' ? 0U : 1U ;	// 元連番だけです
			// 既知のdata/数値型だけを必要とします
			if( (key.empty() && flags == 0U && displayText( v[4])) ||
			   (key == L"id" && flags == 0x10001U && number == 16U + index) ||
			   (key == L"flags" && flags == 0x10001U && number == 0U)) {
				return 0U ;
			}
		}

		return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
	}

	// WMIは同SYSTEMの標準EventLog-Systemだけへ限定します
	if( path.starts_with( LOGGER) && guid( std::wstring_view{v[1]}.substr( LOGGER.size()))) {
		// QWORDをDWORDや符号付き値へ切り詰めません
		if( ((key == L"matchanykeyword" || key == L"matchallkeyword") && flags == 0xb0001U) ||
		   (key == L"loggername" && flags == 0U && v[4] == L"EventLog-System") ||
		   ((key == L"enabled" || key == L"enableproperty") && flags == 0x10001U && number == 1U) ||
		   (key == L"enablelevel" && flags == 0x10001U && number <= 255U)) {
			return 0U ;
		}
	}

	return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 全SYSTEM registry行を元scope/閉型/実moduleへ結びます
 * @param[in,out] state 全原行と共有registry予算を持つ検査です
 * @param[in] effect 同原document/文脈の一行です
 * @return 閉型成立0、元API又は固定型拒否です
 */
//------------------------------------------------------------------------------
NativeError verifyRegistry( EffectState &state, const SystemInfEffect &effect)
{
	const auto				   &v				 = effect.row.values ;	// 全fieldを原順で参照します
	constexpr std::wstring_view COMPACT_CATEGORY =						// この閉じた作用型だけが使用する固定scopeです
		L"system\\currentcontrolset\\control\\mediacategories\\" ;
	// SYSTEM媒体Nameの原4field表示型だけを、flagsの失敗fallbackと分離します
	if( v.size() == 4U && effect.source.scope == SystemInfContext::DEVICE && same( v[0], L"HKLM") &&
	   folded( v[1]).starts_with( COMPACT_CATEGORY) &&
	   guid( std::wstring_view{v[1]}.substr( COMPACT_CATEGORY.size())) && same( v[2], L"Name")) {
		const auto first =
			v[3].empty() ? L'\0'
						 : v[3].front() ;	// 元field/型の全消費を確認する局所位置又は閉じた分類です
		std::uint64_t numeric{} ;			// この同期/fixtureが所有する資源又は原状態です
		// 元の不正/不一致又は不足を成功へ補完しません
		if( !dataText( v[3]) || (first >= L'0' && first <= L'9') || first == L'+' ||
		   first == L'-' ||	// 不明/不一致の元値を成功や別scopeへ補完しません
		   first == L' ' || scalar( v[3], numeric) || std::ranges::all_of( v[3], []( wchar_t c) {
			   return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
					  (c >= L'A' && c <= L'F') ;
		   })) {
			return rejected( state, SystemInfDiagnosticStage::REGISTRY) ;
		}

		return 0U ;
	}

	std::uint64_t flags{} ;		// 元flagの全値です
	std::uint64_t number{} ;	// 元scalarの全値です
	// 不正flag/型の行を別contextへ再解釈しません
	if( !registryType( effect.row, flags, number)) {
		return rejected( state, SystemInfDiagnosticStage::REGISTRY) ;
	}

	const auto scope = effect.source.scope ;	// data参照の親scopeです
	const auto root	 = folded( v[0]) ;			// rootは閉じた値だけです
	const auto key	 = folded( v[2]) ;			// 元値名の比較用です
	const auto path	 = folded( v[1]) ;			// 元subkeyの比較用です
	// event-logだけは専用publisher/channel型を全行要求します
	if( scope == SystemInfContext::EVENT_LOG) {
		return eventRegistry( state, effect, flags, number) ;
	}

	// HKRは元相対文脈をglobal keyへ置き換えません
	if( root == L"hkr") {
		const bool loaderName =
			// 独立した条件又は到達件数です。別条件の成功を借用しません
			same( v[2], L"DevLoader") ;
		const bool streamName =
			// 独立した条件又は到達件数です。別条件の成功を借用しません
			same( v[2], L"NTMPDriver") ;
		const bool powerName = same(
			v[2], L"D3ColdSupported") ;	// 独立した条件又は到達件数です。別条件の成功を借用しません
		const bool filterName =
			// 独立した条件又は到達件数です。別条件の成功を借用しません
			same( v[2], L"LowerFilters") ;
		// 標準streamのloader情報は元device software scopeだけです
		if( loaderName) {
			return scope == SystemInfContext::DEVICE && path.empty() && v.size() == 5U &&
						   flags == 0U && v[4] == L"*ntkern"
					   ? 0U
					   : rejected( state, SystemInfDiagnosticStage::STREAM_MODULE) ;
		}

		// SYS dataを無作用にせず、同service/実fileへ結びます
		if( streamName) {
			// 単一basenameと原service関係を必要とします
			if( scope != SystemInfContext::DEVICE || !path.empty() || v.size() != 5U ||
			   flags != 0U || !simpleName( v[4], 254U) || !folded( v[4]).ends_with( L".sys") ||
			   !serviceModule( state, effect.source.document, {}, v[4])) {
				return rejected( state, SystemInfDiagnosticStage::STREAM_MODULE) ;
			}

			return verifyModule( state, effect.source.document, v[4],
								SystemInfModuleRole::STREAM_SYS) ;
		}

		// 標準hardware power値をbooleanへ限定します
		if( powerName) {
			return scope == SystemInfContext::HARDWARE &&
						   (v[1].size() == 36U ? guid( L"{" + v[1] + L"}") : guid( v[1])) &&
						   v.size() == 5U && flags == 0x10001U && number <= 1U
					   ? 0U
					   : rejected( state, SystemInfDiagnosticStage::HARDWARE) ;
		}

		// LowerFiltersは同原KMDF serviceの単一MULTI_SZだけです
		if( filterName) {
			// append/複数値/別serviceを標準filterへ追加しません
			if( scope != SystemInfContext::HARDWARE || !path.empty() || v.size() != 5U ||
			   flags != 0x10000U ||
			   !declaration( state, effect.source.document, L"KmdfService", v[4])) {
				return rejected( state, SystemInfDiagnosticStage::HARDWARE) ;
			}

			return 0U ;
		}

		// interfaceの相対dataは同GUID/referenceに閉じます
		if( scope == SystemInfContext::INTERFACE) {
			// 別subkeyをinterfaceのglobal登録へ読み替えません
			if( !path.empty() || effect.source.owner.empty()) {
				return rejected( state, SystemInfDiagnosticStage::INTERFACE_DATA) ;
			}

			// 元四値の削除だけを既定値/新規値と分けて確認します
			if( flags == 4U && v.size() == 4U &&
			   (key == L"camerapostprocessingpluginclsid" || key == L"cameradevicemftclsid" ||
				key == L"cameradevicemftclsidchain" || key == L"customcapturesourceclsid")) {
				return 0U ;
			}

			// CLSID/表示/RTCの元型以外は受理しません
			if( v.size() == 5U && ((key == L"clsid" && flags == 0U && guid( v[4])) ||
								  (key == L"friendlyname" && flags == 0U && dataText( v[4])) ||
								  (key == L"rtcflags" && flags == 0x10001U && number == 0x10U))) {
				const GUID proxy{STATIC_CLSID_Proxy} ;	// SDKのKS proxy以外を追加しません
				return key != L"clsid" || sdkGuid( v[4], proxy)
						   ? 0U
						   : rejected( state, SystemInfDiagnosticStage::INTERFACE_DATA) ;
			}

			return rejected( state, SystemInfDiagnosticStage::INTERFACE_DATA) ;
		}

		// 旧DDInstall/HW HKRは元parserの全制限を維持します
		if( scope == SystemInfContext::DEVICE || scope == SystemInfContext::HARDWARE) {
			return state.api.legacyRegistry( effect, false) ;
		}

		return rejected( state, SystemInfDiagnosticStage::REGISTRY) ;
	}

	// global媒体作用をservice/interface等へ移植しません
	if( scope != SystemInfContext::DEVICE) {
		return rejected( state, SystemInfDiagnosticStage::REGISTRY) ;
	}

	// 媒体HKCRはcategory/CLSIDの記述だけです
	if( root == L"hkcr") {
		const auto parts = pathParts( v[1]) ;	// 元GUID階層を全消費します
		// 型/flags/余分階層/COM server登録を拒否します
		if( v.size() != 5U || flags != 0U || parts.empty() || !same( parts[0], L"CLSID")) {
			return rejected( state, SystemInfDiagnosticStage::COM_METADATA) ;
		}

		// 元CLSID表示名以外を追加しません
		if( parts.size() == 2U && guid( parts[1]) && key.empty() && dataText( v[4])) {
			return 0U ;
		}

		// 同category/filter GUIDのdataだけを確認します
		if( parts.size() == 4U && guid( parts[1]) && same( parts[2], L"Instance") && guid( parts[3]) &&
		   ((key == L"clsid" && guid( v[4]) && same( v[4], parts[3])) ||
			(key == L"friendlyname" && dataText( v[4])))) {
			return 0U ;
		}

		return rejected( state, SystemInfDiagnosticStage::COM_METADATA) ;
	}

	// 未知global rootを署名だけで許可しません
	if( root != L"hklm") {
		return rejected( state, SystemInfDiagnosticStage::REGISTRY) ;
	}

	constexpr std::wstring_view CATEGORY =
		L"system\\currentcontrolset\\control\\mediacategories\\" ;	// この閉じた作用型だけが使用する固定scopeです
	constexpr std::wstring_view INTERFACE =							// この閉じた作用型だけが使用する固定scopeです
		L"system\\currentcontrolset\\control\\mediainterfaces\\" ;
	constexpr std::wstring_view RUNONCE =
		L"software\\microsoft\\windows\\currentversion\\runonce" ;	// この閉じた作用型だけが使用する固定scopeです
	const bool category =											// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
		path.starts_with( CATEGORY) && guid( std::wstring_view{v[1]}.substr( CATEGORY.size())) ;
	const bool mediaInterface =	// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
		path.starts_with( INTERFACE) && guid( std::wstring_view{v[1]}.substr( INTERFACE.size())) ;
	// 既媒体binary/SWENUMの構文と実helperを元validatorへ委譲します
	if( category || mediaInterface || path == RUNONCE) {
		const auto error = state.api.legacyRegistry( effect, true) ;	// 全field/原helperの既検査です
		// 正常な元RunOnceだけから遅延登録factを発行します
		if( error == 0U && path == RUNONCE) {
			state.result.delayedRegistration = true ;
		}

		return error ;
	}

	const auto parts = pathParts( v[1]) ;	// 追加媒体scopeだけの全成分です
	// PropertyPagesはGUID二段と表示dataに限定します
	if( parts.size() == 7U && same( parts[0], L"SYSTEM") && same( parts[1], L"CurrentControlSet") &&
	   same( parts[2], L"Control") &&
	   (same( parts[3], L"MediaSets") || same( parts[3], L"MediaCategories")) && guid( parts[4]) &&
	   same( parts[5], L"PropertyPages") && guid( parts[6]) && v.size() == 5U && key.empty() &&
	   flags == 0U && (v[4].empty() || dataText( v[4]))) {
		return 0U ;
	}

	constexpr std::wstring_view RESOURCES =	// この閉じた作用型だけが使用する固定scopeです
		L"system\\currentcontrolset\\control\\mediaresources\\msvideo\\" ;
	constexpr std::wstring_view DRIVERS =	// この閉じた作用型だけが使用する固定scopeです
		L"software\\microsoft\\windows nt\\currentversion\\drivers32" ;
	constexpr std::wstring_view DESCRIPTIONS =	// この閉じた作用型だけが使用する固定scopeです
		L"software\\microsoft\\windows nt\\currentversion\\drivers.desc" ;
	// VfWは三つの原登録位置と実Windows DLLだけです
	if( v.size() == 5U && flags == 0U) {
		// device別の表示名は実行文字列を含めません
		if( path == std::wstring{RESOURCES} + L"msvideo.vfwwdm" &&
		   (key == L"description" || key == L"friendlyname") && dataText( v[4])) {
			return 0U ;
		}

		const bool resourceDriver =	// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
			path == std::wstring{RESOURCES} + L"msvideo.vfwwdm" && key == L"driver" ;
		const bool driverAlias =
			// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
			path == DRIVERS && key == L"msvideo8" ;
		// Windows module名以外のpath/引数を受理しません
		if( (resourceDriver || driverAlias) && same( v[4], L"vfwwdm32.dll")) {
			return verifyModule( state, effect.source.document, v[4], SystemInfModuleRole::VFW_DLL) ;
		}

		// 同DLLの説明は実fileの代わりにしません
		if( path == DESCRIPTIONS && key == L"vfwwdm32.dll" && dataText( v[4])) {
			return verifyModule( state, effect.source.document, v[2], SystemInfModuleRole::VFW_DLL) ;
		}
	}

	return rejected( state, SystemInfDiagnosticStage::VFW) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 個別registry成功後にETW/媒体module/companionの全関係を確認します
 * @param[in,out] state 同原文の全列挙済み作用です
 * @return 関係完備0、欠損/重複/別所有者の固定拒否です
 */
//------------------------------------------------------------------------------
NativeError verifyRelations( EffectState &state)
{
	std::map<std::wstring, std::vector<const SystemInfEffect *>>
									 events ;			// 同doc/service別のETW集合です
	std::map<std::wstring, unsigned> mediaModules ;		// 同doc/DLLの三者登録bitです
	std::map<std::wstring, unsigned> mediaInstances ;	// 同docのcategory登録二値を全消費します
	// 同期中の全原rowだけを関係集合へ追加します
	for( const auto &effect : state.result.effects) {
		// 全UMDFが同原companion関係へ一回だけ接続することを必要とします
		if( same( effect.row.key, L"UmdfService")) {
			std::size_t linked{} ;	// 元子serviceへの関係数です
			// 宣言順に依存せず全親を調べます
			for( const auto &parent : state.result.effects) {
				// 同docの元companionだけを候補にします
				if( parent.source.document == effect.source.document &&
				   same( parent.row.key, L"CompanionConfiguration")) {
					const auto section = referenced(
						state, parent, SystemInfContext::COMPANION,
						1U) ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
					linked += section && same( oneField( state, *section, L"CompanionServices"),
											  effect.row.values[0])
								  ? 1U
								  : 0U ;
				}
			}

			// 孤立又は複数親を先頭へ縮約しません
			if( linked != 1U) {
				return rejected( state, SystemInfDiagnosticStage::COMPANION) ;
			}
		}

		// data行以外をregistry関係へ数えません
		if( effect.source.context != SystemInfContext::REGISTRY) {
			continue ;
		}

		const auto &v = effect.row.values ;	// 既全field検査済みの元dataです
		// 元の不正/不一致又は不足を成功へ補完しません
		if( v.size() == 5U &&
		   same( v[0], L"HKCR")) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			const auto parts =
				// 元field/型の全消費を確認する局所位置又は閉じた分類です
				pathParts( v[1]) ;
			// 元の不正/不一致又は不足を成功へ補完しません
			if( parts.size() == 4U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				const bool category =
					sdkGuid( parts[3],
							KSCATEGORY_TVTUNER) ||	// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
					sdkGuid( parts[3], KSCATEGORY_TVAUDIO) ||
					sdkGuid( parts[3], KSCATEGORY_CROSSBAR) ||
					sdkGuid( parts[3], KSCATEGORY_ENCODER) ||
					sdkGuid( parts[3], KSCATEGORY_MULTIPLEXER) ;
				// 元の不正/不一致又は不足を成功へ補完しません
				if( !sdkGuid( parts[1], CLSID_ActiveMovieCategories) ||
				   !category) {	// 不明/不一致の元値を成功や別scopeへ補完しません
					return rejected( state, SystemInfDiagnosticStage::COM_METADATA) ;
				}

				const unsigned bit =
					same( v[2], L"CLSID")
						? 1U
						: 2U ;	// 元field/型の全消費を確認する局所位置又は閉じた分類です
				auto &bits =	// 元field/型の全消費を確認する局所位置又は閉じた分類です
					mediaInstances[std::to_wstring( effect.source.document) + L"|" + folded( v[1])] ;
				// 元の不正/不一致又は不足を成功へ補完しません
				if( (bits & bit) != 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
					return rejected( state, SystemInfDiagnosticStage::COM_METADATA) ;
				}

				bits |= bit ;
			}
		}

		// ETWは同event-log owner単位で全26行を必要とします
		if( effect.source.scope == SystemInfContext::EVENT_LOG) {
			events[std::to_wstring( effect.source.document) + L"|" + folded( effect.source.owner)]
				.push_back( &effect) ;
		}

		// VfW三者のmodule関係を記述名だけで成立させません
		if( v.size() == 5U && same( v[0], L"HKLM")) {
			const auto	 path = folded( v[1]) ;	// 元位置です
			unsigned	 bit{} ;				// 三つの閉じた登録役割です
			std::wstring module ;				// 元basenameだけです
			// resource driverの元moduleです
			if( path.starts_with( L"system\\currentcontrolset\\control\\mediaresources\\msvideo\\") &&
			   same( v[2], L"Driver")) {
				bit	   = 1U ;
				module = folded( v[4]) ;
			}
			// 後続の別型/文脈だけを判定し、未確認を既定へ変換しません
			else if(
				path ==
				L"software\\microsoft\\windows nt\\currentversion\\drivers32") {	// 不明/不一致の元値を成功や別scopeへ補完しません
				bit	   = 2U ;
				module = folded( v[4]) ;
			}
			// 後続の別型/文脈だけを判定し、未確認を既定へ変換しません
			else if(
				path ==
				L"software\\microsoft\\windows nt\\currentversion\\drivers.desc") {	// 不明/不一致の元値を成功や別scopeへ補完しません
				bit	   = 4U ;
				module = folded( v[2]) ;
			}

			// 同じ元役割を二行の別定義へしません
			if( bit != 0U) {
				auto &bits =
					mediaModules[std::to_wstring( effect.source.document) + L"|" +
								 module] ;	// 元field/型の全消費を確認する局所位置又は閉じた分類です
				// 同一moduleの同役割重複を拒否します
				if( (bits & bit) != 0U) {
					return rejected( state, SystemInfDiagnosticStage::VFW) ;
				}

				bits |= bit ;
			}
		}
	}

	// 一つの元category登録にはCLSID/FriendlyNameの両方を必要とします
	for( const auto &[name, bits] : mediaInstances) {
		static_cast<void>( name) ;
		// 元の不正/不一致又は不足を成功へ補完しません
		if( bits != 3U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			return rejected( state, SystemInfDiagnosticStage::COM_METADATA) ;
		}
	}

	// 全moduleが三者の原登録へ結ばれることを確認します
	for( const auto &[name, bits] : mediaModules) {
		// 私有名は一般logへ出しません
		static_cast<void>( name) ;
		// 一つの正しい登録で他の不足を隠しません
		if( bits != 7U) {
			return rejected( state, SystemInfDiagnosticStage::VFW) ;
		}
	}

	// 同publisher/channelとserviceの全関係を一括検査します
	for( const auto &[owner, rows] : events) {
		// 元serviceは私有のまま保持します
		static_cast<void>( owner) ;
		// 元参考型の全26行以外へ拡大しません
		if( rows.size() != 26U) {
			return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER,
							static_cast<std::uint32_t>( rows.size())) ;
		}

		std::map<std::wstring, std::wstring> values ;			// 同owner内の位置/値名を一意にします
		std::set<std::wstring>				 publishers ;		// 元publisher GUIDだけです
		std::map<std::wstring, std::wstring> channels ;			// 元channel名と所有publisherです
		std::map<std::wstring, std::wstring> references ;		// 元0/1参照とchannel名です
		std::wstring						 publisherName ;	// 元publisherの表示名です
		// 全元行から関係を取り、別ownerへ借りません
		for( const auto row : rows) {
			const auto &v =
				row->row.values ;				// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			const auto path = folded( v[1]) ;	// 元所有scopeへ結ぶ位置です。任意探索へ使いません
			const auto key =
				// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
				folded( v[2]) ;
			// 同位置の重複値を後勝ちにしません
			if( !values.emplace( path + L"|" + key, v[4]).second) {
				return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
			}

			const auto marker = path.find( L"\\publishers\\") ;	// 検査済み固定prefixの位置です
			// 全publisher参照のGUIDを一つへ結びます
			if( marker != path.npos) {
				const auto tail =
					std::wstring_view{v[1]}.substr( marker + 12U) ;	// 元GUIDからのsuffixです
				publishers.insert( folded( tail.substr( 0U, 38U))) ;
				// 元publisherの表示名とchannel prefixを結びます
				if( tail.size() == 38U && key.empty()) {
					publisherName = folded( v[4]) ;
				}

				// 同連番参照だけを保持します
				if( key.empty() && tail.size() > 38U) {
					references.emplace( path.substr( path.size() - 1U), folded( v[4])) ;
				}
			}

			// channelのOwningPublisherが全参照と一致する必要があります
			if( key == L"owningpublisher") {
				const auto start = path.find( L"\\channels\\") + 10U ;	// 既知channel prefix後です
				channels.emplace( path.substr( start), folded( v[4])) ;
			}

			// Autologgerも同publisher GUIDに閉じます
			if( path.starts_with(
				   L"system\\currentcontrolset\\control\\wmi\\autologger\\eventlog-system\\")) {
				publishers.insert( path.substr( path.size() - 38U)) ;
			}
		}

		// 欠損/孤立/別publisher/別channelを拒否します
		if( publishers.size() != 1U || channels.size() != 2U || references.size() != 2U ||
		   publisherName.empty()) {
			return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
		}

		// 二つの標準channel名とその連番を完全に照合します
		for( unsigned index = 0U; index < 2U; ++index) {
			const auto name =
				publisherName +
				(index == 0U ? L"/operational" : L"/analytic") ;	// 同元publisherからだけです
			const auto channel =
				// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
				channels.find( name) ;
			const auto reference = references.find( std::to_wstring(
				index)) ;	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
			// 同ownerの全リンクが閉じている場合だけ許可します
			if( channel == channels.end() || channel->second != *publishers.begin() ||
			   reference == references.end() || reference->second != name) {
				return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
			}
		}

		const auto		   publisher   = *publishers.begin() ;	// 同ownerで一つと確認したGUIDです
		const std::wstring channelRoot =						// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
			L"software\\microsoft\\windows\\currentversion\\winevt\\channels\\" ;
		const std::wstring publisherRoot =	// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
			L"software\\microsoft\\windows\\currentversion\\winevt\\publishers\\" + publisher ;
		const std::wstring loggerRoot =	// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
			L"system\\currentcontrolset\\control\\wmi\\autologger\\eventlog-system\\" + publisher ;
		std::set<std::wstring> expected ;	// 必須26位置そのものを全列挙します
		// channelの欠落を第三channelの同数補充で隠しません
		for( unsigned index = 0U; index < 2U; ++index) {
			const auto channel =	// 同原文の標準媒体/ETW作用へ結ぶ固定の役割です
				channelRoot + publisherName + (index == 0U ? L"/operational" : L"/analytic") ;
			// 一channelに必要な全五keyです
			for( const auto key :
				{L"owningpublisher", L"enabled", L"isolation", L"channelaccess", L"type"}) {
				expected.insert( channel + L"|" + key) ;
			}

			const auto reference =	// 同期借用又は所有する元入力の全値です。先頭値へ縮約しません
				publisherRoot + L"\\channelreferences\\" + std::to_wstring( index) ;
			// 各連番の名前/Id/Flagsも欠落を認めません
			for( const auto key : {L"", L"id", L"flags"}) {
				expected.insert( reference + L"|" + key) ;
			}
		}

		// 同publisher本体の全三keyです
		for( const auto key : {L"", L"resourcefilename", L"messagefilename"}) {
			expected.insert( publisherRoot + L"|" + key) ;
		}

		expected.insert( publisherRoot + L"\\channelreferences|count") ;
		// 同publisherの全WMI logger dataです
		for( const auto key : {L"enabled", L"enablelevel", L"loggername", L"matchanykeyword",
							  L"matchallkeyword", L"enableproperty"}) {
			expected.insert( loggerRoot + L"|" + key) ;
		}

		// 数だけでなく全path/key集合の一致を必要とします
		if( expected.size() != values.size() || std::ranges::any_of( values, [&]( const auto &entry) {
			   return !expected.contains( entry.first) ;
		   })) {
			return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
		}
	}

	return 0U ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同SYSTEM全参照を列挙後に型と実file/関係へ照合します
 * @param[in] seeds 同元graphで検証済みのSYSTEM選択節/文脈です
 * @param[in] api 同期中有効な全read/module/legacy/service操作です
 * @param[out] result 全成立時だけの不変作用です。失敗時は空です
 * @param[out] stage 最初の固定拒否地点です。任意本文を含みません
 * @param[out] observed 固定型/件数の補足です。GUID/値の転記はしません
 * @return 全成立0、元API error又は限定型の拒否HRESULTです
 * @note 一同期最大1024節/4096行/64 fieldで、registry/SCM/driverを変更しません
 */
//------------------------------------------------------------------------------
NativeError inspectSystemInfEffects( std::span<const SystemInfSection> seeds,
									const SystemInfEffectApi &api, SystemInfEffects &result,
									std::uint32_t &stage, std::uint32_t &observed)
{
	result	 = {} ;
	stage	 = 0U ;
	observed = 0U ;
	// 不足操作を実nativeへfallbackしません
	if( !api.read || !api.module || !api.legacyRegistry || !api.service || !api.registryRows ||
	   *api.registryRows > 4096U || api.graphReferences > 4096U || seeds.size() > 1024U) {
		return E_INVALIDARG ;
	}

	EffectState state{api} ;	// 一同期の所有検査です
	state.references = api.graphReferences ;
	// 元seedも同document/文脈/所有者の一意性へ結びます
	for( const auto &seed : seeds) {
		const auto found = std::ranges::find_if(
			state.sections,
			[&]( const auto &old) {	// この同期だけで保持する元値です。許可の代用にしません
				return old.document == seed.document && same( old.name, seed.name) &&
					   old.context == seed.context && old.scope == seed.scope &&
					   same( old.owner, seed.owner) ;
			}) ;
		// 同じ元参照を二度読んで予算を増やしません
		if( found == state.sections.end()) {
			state.sections.push_back( seed) ;
		}
	}

	auto error = collectEffects( state) ;	// 全前方参照を先に列挙します
	// 列挙不成立なら型/実体の一部成功を返しません
	if( error == 0U) {
		error = verifyStructures( state) ;
	}

	// 全構造が成立してから各data行を検査します
	if( error == 0U) {
		// 全原rowを元scopeへ結び、未知を省略しません
		for( const auto &effect : state.result.effects) {
			// registryは補助interfaceを含む共同予算です
			if( effect.source.context == SystemInfContext::REGISTRY) {
				// 増加前の上限を守ります
				if( *api.registryRows >= 4096U) {
					error = HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
					break ;
				}

				error = verifyRegistry( state, effect) ;
				// 型/親scopeと有限行位置だけを残し、原値名や本文を公開しません
				if( error != 0U &&
				   state.stage == static_cast<std::uint32_t>( SystemInfDiagnosticStage::REGISTRY) &&
				   state.observed == 0U) {
					state.observed = (static_cast<std::uint32_t>( effect.source.scope) << 16U) |
									 (effect.row.ordinal + 1U) ;
				}

				// 一失敗で部分dataの成功を閉じます
				if( error != 0U || *api.registryRows >= 4096U) {
					error =
						error != 0U
							? error
							: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
					break ;
				}

				++*api.registryRows ;
			}
			// 後続の別型/文脈だけを判定し、未確認を既定へ変換しません
			else if( effect.source.context ==
					SystemInfContext::PROPERTY) {	// 不明/不一致の元値を成功や別scopeへ補完しません
				const auto &v = effect.row.values ;	// 元五fieldだけです
				// GenericDriverInstalled boolean以外のpropertyを追加しません
				if( effect.source.scope != SystemInfContext::DEVICE || v.size() != 5U ||
				   !same( v[0], L"GenericDriverInstalled") || !v[1].empty() || !v[2].empty() ||
				   !v[3].empty() || v[4] != L"1") {
					error = rejected( state, SystemInfDiagnosticStage::PROPERTY) ;
					break ;
				}
			}
		}
	}

	// 全原dataの成立後にだけ相互関係を完結させます
	if( error == 0U) {
		error = verifyRelations( state) ;
	}

	stage	 = state.stage ;
	observed = state.observed ;
	// 全行/型/実体/関係が成立した結果だけを公開します
	if( error == 0U) {
		state.result.references = state.references ;
		result					= std::move( state.result) ;
	}

	return error ;
}
//------------------------------------------------------------------------------
/**
 * @brief 正確な既存kernel serviceの安定configと保守主体だけの変更権限を確認します
 * @param[in] name 同原SYSTEM文脈で検証された最大31文字のservice名です
 * @param[out] evidence 全成立時だけの安定config/SDです。失敗時は空です
 * @return 読取/保護成立0、元SCM/SD error又は不正/未知権限のHRESULTです
 * @note QUERY_CONFIG/READ_CONTROLだけで開き、SCM/registry/driverを変更しません
 */
//------------------------------------------------------------------------------
NativeError readSystemServiceEvidence( std::wstring_view name, SystemServiceEvidence &evidence)
{
	evidence = {} ;
	// 正確な一service以外を探索しません
	if( !simpleName( name, 31U)) {
		return E_INVALIDARG ;
	}

	const auto closeService = []( SC_HANDLE handle) {	// この同期/fixtureが所有する資源又は原状態です
		// 元の不正/不一致又は不足を成功へ補完しません
		if( handle) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			CloseServiceHandle( handle) ;
		}
	} ;
	const std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, decltype( closeService)> manager{
		// この同期/fixtureが所有する資源又は原状態です
		OpenSCManagerW( nullptr, nullptr, SC_MANAGER_CONNECT), closeService} ;
	// 元読取errorだけを返します
	if( !manager) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	const std::wstring serviceName{name} ;	// 終端を所有する全原名です
	const std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, decltype( closeService)> service{
		// この同期/fixtureが所有する資源又は原状態です
		OpenServiceW( manager.get(), serviceName.c_str(), SERVICE_QUERY_CONFIG | READ_CONTROL),
		closeService} ;
	// 別service/別権限で再試行しません
	if( !service) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	DWORD	   required{} ;	// 元APIが要求する全config容量です
	const auto initial = QueryServiceConfigW(
		// 同原文/操作へ結ぶ検査又は結果の所有値です
		service.get(), nullptr, 0U, &required) ;
	const auto sizingError = GetLastError() ;	// 直後に保持した元API又は検査errorです
	// 通常の有限size応答だけを採用します
	if( initial || sizingError != ERROR_INSUFFICIENT_BUFFER ||
	   required < sizeof( QUERY_SERVICE_CONFIGW) || required > 65536U) {
		return HRESULT_FROM_WIN32( !initial && sizingError != ERROR_INSUFFICIENT_BUFFER
									  ? sizingError
									  : ERROR_INVALID_DATA) ;
	}

	std::vector<std::byte> buffer( required) ;	// 同同期で安定fieldへ移すだけの所有領域です
	auto				   config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(
		  // この同期/fixtureが所有する資源又は原状態です
		  buffer.data()) ;
	// Config読取の元errorを保持します
	if( !QueryServiceConfigW( service.get(), config, required, &required)) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	SystemServiceEvidence result ;	// 全成立前は呼出し元へ出しません
	result.name			= serviceName ;
	result.type			= config->dwServiceType ;
	result.start		= config->dwStartType ;
	result.errorControl = config->dwErrorControl ;
	result.tag			= config->dwTagId ;
	const auto text		= [&]( const wchar_t *value, std::wstring &out) {
		out.clear() ;
		// null optional値は空値として保持します
		if( !value) {
			return true ;
		}

		const auto start = reinterpret_cast<std::uintptr_t>(
			value) ;	// 元field/型の全消費を確認する局所位置又は閉じた分類です
		const auto first = reinterpret_cast<std::uintptr_t>(
			// 元field/型の全消費を確認する局所位置又は閉じた分類です
			buffer.data()) ;
		const auto last = first + buffer.size() ;	// 直後に保持した元API又は検査errorです
		// 元応答外のpointerや未終端を読取りません
		if( start < first || start >= last || start % alignof( wchar_t) != 0U) {
			return false ;
		}

		const auto capacity = (last - start) / sizeof( wchar_t) ;	// 元全長又は共同予算の有限件数です
		const auto end		= std::find( value, value + capacity,
											L'\0') ;	// 元field/型の全消費を確認する局所位置又は閉じた分類です
		// 最大4096文字を超すservice設定を追加型へしません
		if( end == value + capacity || end - value > 4096) {
			return false ;
		}

		out.assign( value, end) ;
		return true ;
	} ; // 同config内の全null終端値を同期copyします
	// Raw pointer/paddingを私有tupleへ保存しません
	if( !text( config->lpBinaryPathName, result.binary) ||
	   !text( config->lpLoadOrderGroup, result.group) ||
	   !text( config->lpServiceStartName, result.account) ||
	   !text( config->lpDisplayName, result.display) || result.type != SERVICE_KERNEL_DRIVER ||
	   result.start != SERVICE_DEMAND_START || result.binary.empty()) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	const wchar_t *dependency = config->lpDependencies ;	// 元MULTI_SZ全体を借用します
	// 個々の依存値も元順/全消費で保持します
	while( dependency) {
		std::wstring item ;	// この同期だけで保持する元値です。許可の代用にしません
		// 元buffer内の終端を各回確認します
		if( !text( dependency, item)) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		// 空終端を確認してからだけ終了します
		if( item.empty()) {
			const auto end = reinterpret_cast<std::uintptr_t>( buffer.data()) +
							 // 元field/型の全消費を確認する局所位置又は閉じた分類です
							 buffer.size() ;
			// 最初から空のMULTI_SZにも二NULを要求します
			if( result.dependencies.empty() &&
			   (reinterpret_cast<std::uintptr_t>( dependency + 1U) + sizeof( wchar_t) > end ||
				dependency[1] != L'\0')) {
				return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
			}

			break ;
		}

		// 元の不正/不一致又は不足を成功へ補完しません
		if( result.dependencies.size() >= 64U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		dependency += item.size() + 1U ;
		result.dependencies.push_back( std::move( item)) ;
	}

	PSECURITY_DESCRIPTOR raw{} ;							// この同期だけで保持する元値です。許可の代用にしません
	PSID				 owner{} ;							// 元権限/署名の照合中だけ使う証拠です
	PSID				 group{} ;							// 元権限/署名の照合中だけ使う証拠です
	PACL				 acl{} ;							// 元権限/署名の照合中だけ使う証拠です
	const auto			 securityError = GetSecurityInfo(	// 直後に保持した元API又は検査errorです
		  service.get(), SE_SERVICE,
		  OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
		  &group, &acl, nullptr, &raw) ;
	const std::unique_ptr<void, decltype( &LocalFree)> descriptor{
		raw, &LocalFree} ;	// 元権限/署名の照合中だけ使う証拠です
	// 元SDの取得不能/null/不正を保護済みへ補完しません
	if( securityError != ERROR_SUCCESS || !raw || !IsValidSecurityDescriptor( raw) || !owner ||
	   !IsValidSid( owner) || !group || !IsValidSid( group) || !acl || !IsValidAcl( acl)) {
		return HRESULT_FROM_WIN32( securityError ? securityError : ERROR_ACCESS_DENIED) ;
	}

	SECURITY_DESCRIPTOR_CONTROL control{} ;		// 元権限/署名の照合中だけ使う証拠です
	DWORD						revision{} ;	// この同期だけで保持する元値です。許可の代用にしません
	// GetSecurityInfoのself-relative全長だけを保存します
	if( !GetSecurityDescriptorControl( raw, &control, &revision) ||
	   (control & SE_SELF_RELATIVE) == 0U) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR) ;
	}

	const auto length = GetSecurityDescriptorLength( raw) ;	// 元全長又は共同予算の有限件数です
	// bufferの余剰/paddingを比較へ含めません
	if( length == 0U || length > 65536U) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR) ;
	}

	const auto bytes = static_cast<const std::byte *>( raw) ;	// 元全長又は共同予算の有限件数です
	result.security.assign( bytes, bytes + length) ;
	const auto validated =
		// 同原文/操作へ結ぶ検査又は結果の所有値です
		validateSystemServiceEvidence( result) ;
	// 元の不正/不一致又は不足を成功へ補完しません
	if( validated != 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
		return validated ;
	}

	evidence = std::move( result) ;
	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実SCMと内部fixtureが共有する安定config/元SDの閉じた安全条件を確認します
 * @param[in] evidence 全長を所有する原configとself-relative SDです
 * @return 型/全byte境界/保守主体限定変更が成立0、不正又は未知権限のHRESULTです
 * @note 任意serviceを探索せず、SDを適用しません
 */
//------------------------------------------------------------------------------
NativeError validateSystemServiceEvidence( const SystemServiceEvidence &evidence)
{
	// 同期所有した有限configとSDだけを検証します
	if( !simpleName( evidence.name, 31U) || evidence.type != SERVICE_KERNEL_DRIVER ||
	   evidence.start != SERVICE_DEMAND_START || evidence.binary.empty() ||
	   evidence.binary.size() > 4096U || evidence.binary.find( L'\0') != evidence.binary.npos ||
	   evidence.dependencies.size() > 64U ||
	   evidence.security.size() < sizeof( SECURITY_DESCRIPTOR_RELATIVE) ||
	   evidence.security.size() > 65536U) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	const auto stableText =
		[]( std::wstring_view value) {	// この同期だけで保持する元値です。許可の代用にしません
			return value.size() <= 4096U && value.find( L'\0') == value.npos &&
				   std::ranges::none_of( value, []( wchar_t c) { return c < L' ' || c == 0x7f ; }) ;
		} ;
	// fixtureも実SCMと同じ全長/終端後tail拒否を通します
	if( !stableText( evidence.binary) || !stableText( evidence.group) ||
	   !stableText( evidence.account) || !stableText( evidence.display) ||
	   std::ranges::any_of( evidence.dependencies, [&]( const auto &value) {
		   return value.empty() || !stableText( value) ;
	   })) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	const auto raw = const_cast<std::byte *>(
		// この同期だけで保持する元値です。許可の代用にしません
		evidence.security.data()) ;
	const auto relative = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE *>(
		raw) ;	// 元権限/署名の照合中だけ使う証拠です
	// 未検証offsetをWindowsのpointer ABIへ渡しません
	if( relative->Revision != SECURITY_DESCRIPTOR_REVISION ||
	   (relative->Control & (SE_SELF_RELATIVE | SE_DACL_PRESENT)) !=
		   (SE_SELF_RELATIVE | SE_DACL_PRESENT) ||
	   relative->Sacl != 0U || relative->Sbz1 != 0U ||
	   (relative->Control & ~(SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_OWNER_DEFAULTED |
							  SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED | SE_DACL_AUTO_INHERIT_REQ |
							  SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED)) != 0U) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR) ;
	}

	const auto boundedSid = [&]( DWORD offset) -> PSID {
		// SID headerと全SubAuthorityが元vector内にある場合だけ借用します
		if( offset < sizeof( SECURITY_DESCRIPTOR_RELATIVE) || offset % 4U != 0U ||
		   offset > evidence.security.size() - 8U) {
			return nullptr ;
		}

		auto	   sid	 = raw + offset ;	// 元権限/署名の照合中だけ使う証拠です
		const auto count = reinterpret_cast<const SID *>( sid)
							   ->SubAuthorityCount ;	// 元全長又は共同予算の有限件数です
		// IsValidSidより先に全長を確認します
		if( count > SID_MAX_SUB_AUTHORITIES || 8U + 4U * count > evidence.security.size() - offset ||
		   !IsValidSid( sid)) {
			return nullptr ;
		}

		return sid ;
	} ; // 元SD内だけを確認する非所有借用です
	PSID owner = boundedSid( relative->Owner) ;	// 元権限/署名の照合中だけ使う証拠です
	PSID group = boundedSid( relative->Group) ;	// 元権限/署名の照合中だけ使う証拠です
	// null owner/group/DACLを既定主体へ補完しません
	if( !owner || !group || relative->Dacl < sizeof( SECURITY_DESCRIPTOR_RELATIVE) ||
	   relative->Dacl % 4U != 0U || relative->Dacl > evidence.security.size() - sizeof( ACL)) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR) ;
	}

	const auto acl =
		reinterpret_cast<const ACL *>( raw + relative->Dacl) ;	// 元権限/署名の照合中だけ使う証拠です
	// 元ACL全体の境界を確認してからWindows validatorへ渡します
	if( acl->AclSize < sizeof( ACL) || acl->AclSize > evidence.security.size() - relative->Dacl ||
	   !IsValidAcl( const_cast<ACL *>( acl)) || !IsValidSecurityDescriptor( raw) ||
	   GetSecurityDescriptorLength( raw) != evidence.security.size()) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR) ;
	}

	const std::array<std::pair<DWORD, DWORD>, 3U> ranges{
		{{relative->Owner,
		  GetLengthSid( owner)},	// この同期だけで保持する元値です。許可の代用にしません
		 {relative->Group, GetLengthSid( group)},
		 {relative->Dacl, acl->AclSize}}} ;
	// 同owner/group SIDの完全共有以外の領域重複を拒否します
	for( std::size_t i = 0U; i < ranges.size(); ++i) {
		// 同元文脈の全対象を有限な共同予算内で確認します
		for( std::size_t j = i + 1U; j < ranges.size();
			++j) {	// 同原文の全対象を共有上限内で消費します
			const auto [left, leftBytes] =
				ranges[i] ;	// この同期だけで保持する元値です。許可の代用にしません
			const auto [right, rightBytes] =
				ranges[j] ;	// この同期だけで保持する元値です。許可の代用にしません
			// 元の不正/不一致又は不足を成功へ補完しません
			if( left < right + rightBytes &&
			   right < left + leftBytes &&	// 不明/不一致の元値を成功や別scopeへ補完しません
			   !(j == 1U && left == right && leftBytes == rightBytes)) {
				return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR) ;
			}
		}
	}

	std::array<BYTE, SECURITY_MAX_SID_SIZE> admin{} ;		// 元権限/署名の照合中だけ使う証拠です
	std::array<BYTE, SECURITY_MAX_SID_SIZE> system{} ;		// 元権限/署名の照合中だけ使う証拠です
	DWORD adminSize	 = static_cast<DWORD>( admin.size()) ;	// 元全長又は共同予算の有限件数です
	DWORD systemSize = static_cast<DWORD>( system.size()) ;	// 元全長又は共同予算の有限件数です
	PSID  installerRaw{} ;									// この同期/fixtureが所有する資源又は原状態です
	// 既Windows保守主体以外のwriteを認めません
	if( !CreateWellKnownSid( WinBuiltinAdministratorsSid, nullptr, admin.data(), &adminSize) ||
	   !CreateWellKnownSid( WinLocalSystemSid, nullptr, system.data(), &systemSize) ||
	   !ConvertStringSidToSidW( L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
							   &installerRaw)) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	const std::unique_ptr<void, decltype( &LocalFree)> installer{
		installerRaw, &LocalFree} ;			// この同期/fixtureが所有する資源又は原状態です
	const auto trusted = [&]( PSID sid) {	// 元権限/署名の照合中だけ使う証拠です
		return sid && IsValidSid( sid) &&
			   (EqualSid( sid, admin.data()) || EqualSid( sid, system.data()) ||
				EqualSid( sid, installer.get())) ;
	} ;
	// ownerの暗黙WRITE_DACも保守主体に限定します
	if( !trusted( owner)) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_OWNER) ;
	}

	GENERIC_MAPPING mapping{STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG |
								SERVICE_QUERY_STATUS |	// 元権限/署名の照合中だけ使う証拠です
								SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS,
							STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG,
							STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP |
								SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL,
							SERVICE_ALL_ACCESS} ;
	constexpr DWORD WRITES = SERVICE_CHANGE_CONFIG | WRITE_DAC | WRITE_OWNER |
							 DELETE ;	// 元権限/署名の照合中だけ使う証拠です
	// 全ACEを読み、不明な種類や権限付与を省略しません
	for( DWORD i = 0U; i < acl->AceCount; ++i) {
		void *entry{} ;
		// 読取不能の元errorを保持します
		if( !GetAce( const_cast<ACL *>( acl), i, &entry)) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		const auto header =
			// 元権限/署名の照合中だけ使う証拠です
			static_cast<const ACE_HEADER *>( entry) ;
		// object/callback/条件付は通常ACEへ縮約しません
		if( (header->AceType != ACCESS_ALLOWED_ACE_TYPE &&
			header->AceType != ACCESS_DENIED_ACE_TYPE) ||
		   header->AceSize < offsetof( ACCESS_ALLOWED_ACE, SidStart) + GetSidLengthRequired( 0U)) {
			return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		}

		const auto ace =
			// 元権限/署名の照合中だけ使う証拠です
			static_cast<const ACCESS_ALLOWED_ACE *>( entry) ;
		auto	   sid = const_cast<DWORD *>( &ace->SidStart) ;	// 元権限/署名の照合中だけ使う証拠です
		const auto available = header->AceSize -
							   // 元全長又は共同予算の有限件数です
							   offsetof( ACCESS_ALLOWED_ACE, SidStart) ;
		// IsValidSid前にSID headerと全SubAuthorityをACE境界へ閉じます
		if( (header->AceFlags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
								 NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE | INHERITED_ACE)) !=
			   0U ||
		   available < 8U ||
		   reinterpret_cast<const SID *>( sid)->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES ||
		   8U + 4U * reinterpret_cast<const SID *>( sid)->SubAuthorityCount != available) {
			return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		}

		DWORD mask = ace->Mask ;	// 元権限/署名の照合中だけ使う証拠です
		MapGenericMask( &mask, &mapping) ;
		// SID境界と全適用allowを確認します。denyをallowの証拠にしません
		if( (mask & ~SERVICE_ALL_ACCESS) != 0U || !IsValidSid( sid) ||
		   GetLengthSid( sid) != header->AceSize - offsetof( ACCESS_ALLOWED_ACE, SidStart) ||
		   (header->AceType == ACCESS_ALLOWED_ACE_TYPE &&
			(header->AceFlags & INHERIT_ONLY_ACE) == 0U && (mask & WRITES) != 0U &&
			!trusted( sid))) {
			return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		}
	}

	return 0U ;
}
} // namespace drivercrate
