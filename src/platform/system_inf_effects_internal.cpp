//------------------------------------------------------------------------------
/**
 * @file system_inf_effects_internal.cpp
 * @brief 選択SYSTEM原文の閉じた作用を二相で検査します
 * @version 01.13.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.02.00 Shunji Ogawa  2026/11/20  収集で選択したWindows標準SDバスのサービスと相対設定を検査
 * Ver.01.03.00 Shunji Ogawa  2026/11/20  収集で選択した標準Portsサービス・上位フィルター・イベント資源の所有先を検査
 * Ver.01.04.00 Shunji Ogawa  2026/11/20  収集で選択した標準NVMeの起動サービス、PCIのHW設定、電源作用を検査
 * Ver.01.05.00 Shunji Ogawa  2026/11/21  収集で選択した標準AHCIの起動サービス、レジストリ、除外IDと電源作用を検査
 * Ver.01.05.01 Shunji Ogawa  2026/11/21  ストレージサービスの開始種別を用途別に検査
 * Ver.01.06.00 Shunji Ogawa  2026/11/22  正規仮想Wi-Fiバスサービスの設定とStore上の実体を検査
 * Ver.01.07.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの選択節と上位フィルターの全作用を照合
 * Ver.01.08.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの現在の表示名と説明を同じ同梱INFに結合
 * Ver.01.09.00 Shunji Ogawa  2026/11/22  ストレージ補助サービスの実状態と監査を含むSCM構成を読取
 * Ver.01.10.00 Shunji Ogawa  2026/11/23  同梱NVMeと署名済みストレージの電源値域・AC/DC既定値を共通検査
 * Ver.01.11.00 Shunji Ogawa  2026/11/23  現用同梱NVMeとPCIの原作用と電源宣言を照合
 * Ver.01.12.00 Shunji Ogawa  2026/11/24  Serenumの元作用と現在の要求時サービス設定を照合
 * Ver.01.13.00 Shunji Ogawa  2026/11/24  正規WinUSBの元作用と要求時サービス実体を照合
 * </pre>
 *
 * @note 全原文/参照/実file確認後だけ私有tupleを返し、導入/registry/SCM変更を行いません
 * @see docs/adr/0491-typed-system-needs-effects-and-complete-selection-qualification.md
 */
//------------------------------------------------------------------------------
#include "platform/system_inf_effects_internal.h"
#include "platform/inf_dependency_native.h"
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
#include <cstddef>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <type_traits>
#include <utility>

namespace drivercrate {
namespace {
constexpr std::wstring_view NVME_INSTALL_SECTION =
	L"Stornvme_Inst" ;	// 収集で照合する標準NVMeの基本節です
// 同じ基本節から原順で到達する4つの電源設定です
constexpr std::array<std::wstring_view, 4U> NVME_POWER_SECTIONS{
	L"NVMePowerSetting1", L"NVMePowerSetting2", L"NVMePowerSetting3", L"NVMePowerSetting4"} ;
constexpr std::wstring_view AHCI_INSTALL_SECTION =
	L"msahci_Inst" ;	// 収集で照合する標準AHCIの基本節です
// 同じAHCI基本節から原順で到達する2つの電源設定です
constexpr std::array<std::wstring_view, 2U> AHCI_POWER_SECTIONS{L"AhciPowerSetting1",
																L"AhciPowerSetting2"} ;
constexpr auto WIFI_BUS_SERVICE = L"vwifibus" ;	// 正規同梱INFが宣言する固定サービス名です
constexpr auto WIFI_BUS_DISPLAY =
	L"@netvwifibus.inf,%vwifibus_ServiceDisplayName%;Virtual Wireless Bus Driver" ;	// 展開前の原表示名です
constexpr auto WIFI_BUS_DESCRIPTION =
	L"@netvwifibus.inf,%vwifibus_ServiceDesc%;Implements bus functionality for Virtual Wireless" ;	// 展開前の原説明です

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
			   source.context == SystemInfContext::PROPERTY ||
			   source.context == SystemInfContext::POWER_SETTING) {
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
			// 標準ストレージの基本節と種類ごとの原順の参照だけを電源設定へ接続します
			else if( key == L"addpowersetting") {
				// 同じ元文書・基本節に結ぶ参照列を種類ごとに分けます
				const bool nvme = source.document == state.api.storNvmeInboxDocument &&
								  state.api.storNvmeInboxDocument != 0U &&
								  same( source.name, NVME_INSTALL_SECTION) &&
								  std::ranges::equal( row.values, NVME_POWER_SECTIONS, same) ;
				// 標準AHCIのWindows文書に結び付く現在の作用かを判定する
				const bool ahci = source.document == state.api.storAhciInboxDocument &&
								  state.api.storAhciInboxDocument != 0U &&
								  same( source.name, AHCI_INSTALL_SECTION) &&
								  std::ranges::equal( row.values, AHCI_POWER_SECTIONS, same) ;
				// 別文書や別節にある同名設定を調べません
				if( source.context != SystemInfContext::DEVICE || !(nvme || ahci)) {
					return rejected( state, SystemInfDiagnosticStage::POWER_SETTING) ;
				}

				// 電源設定の親に元基本節を保存し、同じ文書だけを読みます
				for( const auto &name : row.values) {
					error = appendSection( state, source, name, SystemInfContext::POWER_SETTING,
										  source.name) ;
					// 一部の電源設定だけが成立した結果を返しません
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
 * @brief 仮想Wi-Fiバスの登録文字列とSCMの展開値を同じ元INFの一意な値へ照合します
 * @param[in] expected 検証済み同梱INFの選択サービス節が返した展開済み文字列です
 * @param[in] effective 同一サービスについてWindowsのSCMが返した文字列です
 * @param[in] registered 同じ設定の展開前の全登録文字列です
 * @param[in] indirect 同梱INFの当該フィールドに固有の既知参照と英語の予備表示です
 * @return 展開値が同じで、登録文字列がその直接値又は既知参照と完全一致する場合trueです
 * @note 登録文字列をパスとして解決せず、任意の間接資源をロードしません
 */
//------------------------------------------------------------------------------
bool matchesWifiBusServiceText( std::wstring_view expected, std::wstring_view effective,
							   std::wstring_view registered, std::wstring_view indirect)
{
	return displayText( expected) && !expected.starts_with( L'@') && effective == expected &&
		   (registered == expected || registered == indirect) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同梱仮想Wi-Fiバスの登録済みサービスを原SYSTEM文書と実ファイルへ結びます
 * @param[in,out] state 同じ文書の実体検査、SCM読取、再照合用の原設定を保持する状態です
 * @param[in] section 検証済み同梱INFの選択サービス節です
 * @return 原設定と同じStore上の実体を確認した場合0、未登録、不一致、権限または実体の不成立はHRESULTです
 * @note 表示名と説明の展開前後を含め、設定の全値を終端で比較します
 */
//------------------------------------------------------------------------------
NativeError verifyWifiBusServiceSnapshot( EffectState &state, const SystemInfSection &section)
{
	SystemServiceEvidence service ;	// 現在の設定、登録値と保護されたセキュリティ記述子です
	const auto			  readError =
		// 同名の登録済みサービスだけです
		state.api.service( WIFI_BUS_SERVICE, service) ;
	// 読取失敗と元INFからの設定差を区別します
	if( readError != 0U || !same( service.name, WIFI_BUS_SERVICE) ||
	   service.type != SERVICE_KERNEL_DRIVER || service.start != SERVICE_DEMAND_START ||
	   service.errorControl != SERVICE_ERROR_NORMAL || service.tag != 0U ||
	   !service.group.empty() || !service.dependencies.empty() || !service.account.empty() ||
	   service.binary.starts_with( L"%13%") || validateSystemServiceEvidence( service) != 0U ||
	   !matchesWifiBusServiceText( oneField( state, section, L"DisplayName"), service.display,
								  service.rawDisplay, WIFI_BUS_DISPLAY) ||
	   !matchesWifiBusServiceText( oneField( state, section, L"Description"), service.description,
								  service.rawDescription, WIFI_BUS_DESCRIPTION)) {
		// 設定が元の証拠と異なる場合の固定診断です
		const auto rejectedError = rejected( state, SystemInfDiagnosticStage::SERVICE_SNAPSHOT) ;
		return readError != 0U ? readError : rejectedError ;
	}

	const auto moduleError =
		verifyModule( state, state.api.wifiBusInboxDocument, service.binary,
					 SystemInfModuleRole::EXISTING_SERVICE) ;	// 現登録位置を元SYSと照合します
	// 元ファイルの実証に成功した設定だけを終了時の再観測へ渡します
	if( moduleError == 0U) {
		state.result.services.push_back( std::move( service)) ;
	}

	return moduleError ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同梱Serenumサービスの現在値を署名済み原文の既知条件へ照合する
 * @param[in,out] state 固定した同梱文書と同期SCM読取、終端照合用の証拠を保持する
 * @return 元設定と現在の保護ファイルが一致すれば0。取得・読取・設定差は元HRESULT
 * @note OSが割り当てたtagも保持し、終了時は元観測の全設定を比較する
 */
//------------------------------------------------------------------------------
NativeError verifySerialEnumeratorServiceSnapshot( EffectState &state)
{
	SystemServiceEvidence service ;										// 同じWindowsの元SCM設定と保護記述子
	const auto readError = state.api.service( L"Serenum", service) ;	// 元設定の読み取り結果
	// 正規のサービス名・カーネル型・要求時開始・元グループを開いた同じ設定で照合する
	if( readError != 0U || !same( service.name, L"Serenum") ||
	   service.type != SERVICE_KERNEL_DRIVER || service.start != SERVICE_DEMAND_START ||
	   service.errorControl != SERVICE_ERROR_NORMAL || !same( service.group, L"PNP Filter") ||
	   !service.dependencies.empty() || !service.account.empty() ||
	   validateSystemServiceEvidence( service) != 0U) {
		const auto rejectedError =
			// 設定不一致
			rejected( state, SystemInfDiagnosticStage::SERVICE_SNAPSHOT) ;
		return readError != 0U ? readError : rejectedError ;
	}

	const auto moduleError =
		verifyModule( state, state.api.msPortsInboxDocument, service.binary,
					 SystemInfModuleRole::EXISTING_SERVICE) ;	// 現登録パスと元SYSの同一性
	// 配備済みの正規元SYSを確認した場合だけ、設定を終端再照合へ渡す
	if( moduleError == 0U) {
		state.result.services.push_back( std::move( service)) ;
	}

	return moduleError ;
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
		const bool	ports =
			state.api.msPortsInboxDocument != 0U &&
			effect.source.document ==
				state.api.msPortsInboxDocument ;	// 事前に選択節と全行を照合したPorts原文です
		const bool nvme = state.api.storNvmeInboxDocument != 0U &&
						  effect.source.document ==
							  state.api.storNvmeInboxDocument ;	// 同じNVMe選択の全作用を照合済みです
		const bool ahci = state.api.storAhciInboxDocument != 0U &&
						  effect.source.document ==
							  state.api.storAhciInboxDocument ;	// 同じAHCI選択の全作用を照合済みです
		const bool wifiBus = state.api.wifiBusInboxDocument != 0U &&
							 // 元INBOX文書の作用だけです
							 effect.source.document == state.api.wifiBusInboxDocument ;
		const bool winUsb = state.api.winUsbInboxDocument != 0U &&
							effect.source.document ==
								state.api.winUsbInboxDocument ;	// 同梱WinUSBの全作用を照合済みです
		// data節は後段の型付きvalidatorが全行確認します
		if( context == SystemInfContext::REGISTRY || context == SystemInfContext::PROPERTY) {
			continue ;
		}

		// 専用電源作用では、署名済み標準ストレージの元参照と全行の検査を必要とします
		if( key == L"addpowersetting" || context == SystemInfContext::POWER_SETTING) {
			// 別文書の同名節・directiveを通常の宣言へ移しません
			if( !(nvme || ahci)) {
				return rejected( state, SystemInfDiagnosticStage::POWER_SETTING) ;
			}

			continue ;
		}

		// AHCIの除外IDは基本節の原集合を照合してから、参照先を作らず保存します
		if( ahci && context == SystemInfContext::DEVICE && key == L"excludeid") {
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
			const bool wifiDeclaration =
				wifiBus && same( effect.source.name, L"VWiFiBus.Services") && v.size() == 3U &&
				same( v[0], L"vwifibus") && v[1].empty() &&
				// 原文書が参照する唯一の明示サービスです
				same( v[2], L"vwifibus_Service_Inst") ;
			// 欠損/多義/未知flagで別serviceへ進みません
			if( context != SystemInfContext::SERVICES || !section || v.size() < 3U ||
			   v.size() > 4U || !simpleName( v[0], 31U) || (wifiBus && !wifiDeclaration) ||
			   (!scalar( v[1], flags) && !wifiDeclaration &&
				!(ports && same( v[0], L"Serenum") && v[1].empty())) ||
			   (flags != 0U && flags != 2U)) {
				return rejected( state, SystemInfDiagnosticStage::SERVICE) ;
			}

			std::uint64_t		type{} ;	// 元kernel型です
			std::uint64_t		start{} ;	// 元開始方式です
			std::uint64_t		control{} ;	// 元error controlです
			const std::uint64_t startType =
				nvme || ahci ? SERVICE_BOOT_START
							 : SERVICE_DEMAND_START ;	// 署名済み標準ストレージの起動時動作です
			const std::uint64_t errorControl =
				nvme || ahci ? SERVICE_ERROR_CRITICAL
				: ports && same( v[0], L"Serial")
					? SERVICE_ERROR_IGNORE
					: SERVICE_ERROR_NORMAL ;									// 照合済み原作用の起動エラー動作です
			const auto binary = oneField( state, *section, L"ServiceBinary") ;	// 同原moduleです
			// 必須fieldの一意性/数値を全て要求します
			if( !scalar( oneField( state, *section, L"ServiceType"), type) || type != 1U ||
			   !scalar( oneField( state, *section, L"StartType"), start) || start != startType ||
			   !scalar( oneField( state, *section, L"ErrorControl"), control) ||
			   control != errorControl || !folded( binary).ends_with( L".sys")) {
				return rejected( state, SystemInfDiagnosticStage::SERVICE) ;
			}

			const auto error =
				verifyModule( state, effect.source.document, binary,
							 SystemInfModuleRole::SERVICE_SYS) ;	// 現提供/CATへ結合します
			// 宣言だけでkernel実体を承認しません
			if( error != 0U) {
				return error ;
			}

			// 宣言に加えて、既存サービスが同じ実体と保護設定を使用することを確認します
			if( wifiDeclaration) {
				const auto snapshotError =
					// 終端再照合へ渡す原値です
					verifyWifiBusServiceSnapshot( state, *section) ;
				// 設定や実体の差を導入許可へ読み替えません
				if( snapshotError != 0U) {
					return snapshotError ;
				}
			}

			// 混在媒体が選んだWindows側Serenumでは、元宣言と現在のSCM設定を両方確認する
			if( ports && state.api.serialEnumeratorOnly) {
				const auto snapshotError =
					// 同文書の現在値
					verifySerialEnumeratorServiceSnapshot( state) ;
				// 一時読取りや設定差があれば元の診断を返す
				if( snapshotError != 0U) {
					return snapshotError ;
				}
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
			 key == L"errorcontrol" || key == L"servicebinary" ||
			 ((wifiBus || winUsb) && key == L"description") ||
			 (key == L"loadordergroup" &&
			  (nvme || ahci || ports ||
			   (state.api.sdBusInboxDocument != 0U &&
				effect.source.document == state.api.sdBusInboxDocument)))) ;
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
/** @brief 署名済みWindows INFの固定field列に続く一つの値またはbyte列の型です */
enum class InboxTail {
	/// 固定fieldで終わり、末尾の空fieldも追加できません
	NONE,
	/// DIRID 12のサービスSYSを後続の同document実体検査へ結びます
	SERVICE_BINARY,
	/// 仮想Wi-Fiバスの元Storeを参照するSYSです。正確な位置はmodule検査が確認します
	WIFI_BUS_BINARY,
	/// ローカライズ済み表示はスロット番号の書式一つを含みます
	SLOT_FORMAT,
	/// 選択HWに含まれる全32bitの符号なし値です
	HARDWARE_DWORD,
	/// REG_BINARYを有限なコマンド番号とフラグの組として読みます
	COMMAND_BYTES,
	/// ローカライズ済みサービス表示名を制御文字や実行参照を含まないdataとして読みます
	DISPLAY_NAME,
	/// 元の表示名と説明を間接資源参照を含まない展開済み文字列として読みます
	DIRECT_DISPLAY_TEXT,
	/// 一つのREG_EXPAND_SZ全体を後段でSerialの二つの実イベント資源へ結びます
	SERIAL_EVENT_FILES,
	/// Windowsのエラー・警告・情報のうち一つ以上を表すDWORDです
	EVENT_TYPES,
	/// NVMeのPCIデバイス別REG_MULTI_SZ追記で指定する初期値です
	NVME_DEVICE_OVERRIDE,
} ;
/** @brief 元directiveまたは無名registry行の全fieldと末尾型です */
struct InboxRowRule {
	/// REGISTRY data行では空です
	std::wstring_view						 key ;
	/// 原順の有限fieldです。空文字列は明示空fieldです
	std::initializer_list<std::wstring_view> fields ;
	/// 固定fieldの後に必要な値の型です
	InboxTail								 tail{InboxTail::NONE} ;
	/// SERVICE_BINARYのSYS basename又はNVME_DEVICE_OVERRIDEの期待値です
	std::wstring_view						 argument{} ;
	/// この型を共有する原行の必要数です
	std::size_t								 count{1U} ;
} ;
/** @brief 選択節と参照先をHKRの所有scopeおよび全作用に結びます */
struct InboxSectionRule {
	/// 同じ署名済みWindows INF内の節名です
	std::wstring_view					name ;
	/// 元選択または参照から伝播した節の型です
	SystemInfContext					context ;
	/// 同じHKRでもサービス、イベントログ、デバイスの所有先を区別します
	SystemInfContext					scope ;
	/// 成立に必要な一意の全行です
	std::initializer_list<InboxRowRule> rows ;
	/// サービスとそのイベントログで必要な元AddServiceの名前です。他の節は空です
	std::wstring_view					owner{} ;
	/// POWER_SETTINGで必要な固有の設定GUIDです。他の節は空です
	std::wstring_view					powerSettingGuid{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief SDコマンド番号とフラグのREG_BINARYを元順に検査します
 * @param[in] fields HKRの4つの宣言fieldに続く原byte列です
 * @return 有限な2桁hex対で、同じ6bitコマンドのフラグに矛盾がない場合trueです
 * @note 同値の再掲を含む原値はWindows同梱INFの行に保存し、ローカルのテーブルへ置換しません
 */
//------------------------------------------------------------------------------
bool sdBusCommandTable( std::span<const std::wstring> fields)
{
	// 元64field予算から先頭4fieldを除いた最大30対までを完全に読み取ります
	if( fields.empty() || fields.size() > 60U || fields.size() % 2U != 0U) {
		return false ;
	}

	std::array<std::optional<std::uint64_t>, 64U> flagsByCommand{} ;	// SDコマンド番号は6bitです
	// プレフィックスなし2桁のhex byteだけを共有数値処理で解釈します
	const auto octet = []( const std::wstring &field, std::uint64_t &value) {
		return field.size() == 2U && scalar( L"0x" + field, value) ;
	} ;
	// Windows同梱表には同じコマンド・同じフラグの再掲があるため、異なる値の再定義を区別します
	for( std::size_t index = 0U; index < fields.size(); index += 2U) {
		std::uint64_t command{} ;	// 元表にある6bitのSDコマンド番号です
		std::uint64_t flags{} ;		// 原文のフラグbyteを同一コマンド間で比較します
		// 一方のbyteの欠測、余計な桁、不正なコマンド番号を拒否します
		if( !octet( fields[index], command) || command >= flagsByCommand.size() ||
		   !octet( fields[index + 1U], flags)) {
			return false ;
		}

		auto &seen = flagsByCommand[static_cast<std::size_t>( command)] ;	// 同じ表内の先行設定です
		// 同じ番号に異なるフラグがある場合はどちらかを採用しません
		if( seen && *seen != flags) {
			return false ;
		}

		seen = flags ;
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief NVMeのデバイス別追記をPCI vendor/device、revisionの固定形式と一つの設定値へ限定します
 * @param[in] field 同原REG_MULTI_SZ_APPENDの唯一のデータです
 * @param[in] setting 元値名で決まる十進数の期待値です
 * @return 入力の全長とhexの各桁、元設定値まで成立した場合trueです
 */
//------------------------------------------------------------------------------
bool nvmeDeviceOverride( std::wstring_view field, std::wstring_view setting)
{
	constexpr std::size_t PCI_LENGTH = 24U ;	// VEN_の4桁、DEV_の4桁、REV_の二文字を含む範囲です
	// 完全なPCI指定と空白一つに続く設定値だけが原データです
	if( field.size() != PCI_LENGTH + 1U + setting.size() || field[PCI_LENGTH] != L' ' ||
	   field.substr( PCI_LENGTH + 1U) != setting || !same( field.substr( 0U, 4U), L"VEN_") ||
	   !same( field.substr( 8U, 5U), L"&DEV_") || !same( field.substr( 17U, 7U), L"&REV_??")) {
		return false ;
	}

	// 区切りや符号を含まない4桁の16進値を各識別子に必要とします
	const auto hex4 = []( std::wstring_view text) {
		return std::ranges::all_of( text, []( wchar_t c) {
			return (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F') || (c >= L'a' && c <= L'f') ;
		}) ;
	} ;
	return hex4( field.substr( 4U, 4U)) && hex4( field.substr( 13U, 4U)) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 選択されたWindows INFの行を空field、型、参照するSYSとデータ長まで照合します
 * @param[in] row 同じ署名原文から列挙した全fieldです
 * @param[in] rule 同じ選択節と所有scopeに許す一つの行です
 * @return 一行の文法が成立した場合trueです。イベントの二参照と全実ファイルは後段で検査します
 */
//------------------------------------------------------------------------------
bool inboxRowMatches( const SystemInfRow &row, const InboxRowRule &rule)
{
	const auto prefix = rule.fields.size() ;						// この行で固定された先頭field数です
	const auto tail	  = rule.tail == InboxTail::NONE ? 0U : 1U ;	// 固定長の末尾に必要なfield数です
	// 不正なdirective、余分なfield、打ち切られたテーブルは読み進めません
	if( row.values.size() < prefix ||
	   (rule.tail != InboxTail::COMMAND_BYTES && row.values.size() != prefix + tail) ||
	   !(rule.key.empty() ? row.key.empty() : same( row.key, rule.key))) {
		return false ;
	}

	std::size_t index{} ;	// 原field番号を保って、明示空欄も一件として比較します
	// 型と操作flagの数値は全桁、名前や節はWindowsの名前比較で照合します
	for( const auto expected : rule.fields) {
		const bool registryName =
			// HKRの値名は数字で始まっても文字列です
			rule.key.empty() && index == 2U ;
		const auto	 &actual = row.values[index++] ;	// この位置以外の値を代用しません
		std::uint64_t wanted{} ;						// 固定fieldが数値の場合の期待値です
		std::uint64_t number{} ;						// 元fieldの完全な数値です
		// DWORDの表記差だけは値で比較し、符号や末尾の余分な字句を拒否します
		if( !registryName && scalar( expected, wanted)) {
			// 異なる操作flagや値を既定値へ補いません
			if( !scalar( actual, number) || number != wanted) {
				return false ;
			}
		}
		// 明示空欄の位置を保存し、別名や別のパラメータを拒否します
		else if( !(expected.empty() ? actual.empty() : same( actual, expected))) {
			return false ;
		}
	}

	// %12%をSetupAPIが展開した場合も単一のdrivers配下の同SYSだけを実体検査へ渡します
	if( rule.tail == InboxTail::SERVICE_BINARY) {
		const auto &value = row.values.back() ;				// module callbackが再び検査する同じ原fieldです
		const auto	file  = std::wstring{rule.argument} ;	// 元サービスに対応する単一のSYS名です
		return same( value, L"%12%\\" + file) ||
			   (validInfDependencyPath( value, true) &&
				folded( value).ends_with( L"\\system32\\drivers\\" + file)) ;
	}

	// SetupAPIによるDIRID 13の展開を許し、正確な元StoreとCATはmodule検査で照合します
	if( rule.tail == InboxTail::WIFI_BUS_BINARY) {
		const auto &value = row.values.back() ;	// 同じ元サービスの単一module指定です
		return same( value, L"%13%\\vwifibus.sys") ||
			   (validInfDependencyPath( value, true) && folded( value).ends_with( L"\\vwifibus.sys")) ;
	}

	// 国別のスロット表示文の中で、一つの無符号引数だけが展開できます
	if( rule.tail == InboxTail::SLOT_FORMAT) {
		constexpr std::wstring_view SLOT  = L"%1!u!" ;			// Windowsのスロット番号の挿入書式です
		const auto				   &value = row.values.back() ;	// INFのローカライズ済み表示文です
		const auto slot = value.find( SLOT) ;					// 追加の%書式は残りの表示文の検査で拒否します
		return displayText( value) && slot != value.npos &&
			   dataText( value.substr( 0U, slot) + value.substr( slot + SLOT.size())) ;
	}

	// 新しいWindowsで同じHW設定の値が変わっても、型と範囲を満たす原DWORDはそのまま保存します
	if( rule.tail == InboxTail::HARDWARE_DWORD) {
		std::uint64_t number{} ;	// 切り詰めずに評価する一つのHW設定です
		return scalar( row.values.back(), number) && number <= 0xffffffffULL ;
	}

	// コマンド表の原バイトを保持して、1バイトずつ組の構造を確かめます
	if( rule.tail == InboxTail::COMMAND_BYTES) {
		return sdBusCommandTable( std::span{row.values}.subspan( prefix)) ;
	}

	// Windowsの言語によって変わる表示名を固定文字列にしません
	if( rule.tail == InboxTail::DISPLAY_NAME) {
		return dataText( row.values.back()) ;
	}

	// 直接表示だけを宣言する元サービスに間接の表示資源参照を追加しません
	if( rule.tail == InboxTail::DIRECT_DISPLAY_TEXT) {
		const auto &value = row.values.back() ;	// 元サービスが指定する展開済みの一値です
		return dataText( value) && !value.starts_with( L'@') ;
	}

	// REG_EXPAND_SZは最大254文字の二ファイルと一つの区切りまでを元の一fieldに保存します
	if( rule.tail == InboxTail::SERIAL_EVENT_FILES) {
		return !row.values.back().empty() && row.values.back().size() <= 509U ;
	}

	// Systemログのエラー、警告、情報のbit以外はイベント型として採用しません
	if( rule.tail == InboxTail::EVENT_TYPES) {
		std::uint64_t types{} ;	// 切り詰めず原fieldから読むイベント型のマスクです
		return scalar( row.values.back(), types) && types != 0U &&
			   types <= (EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE) ;
	}

	// デバイス別のNVMe既定値は一つの固定形式のREG_MULTI_SZ追記だけを許します
	if( rule.tail == InboxTail::NVME_DEVICE_OVERRIDE) {
		return nvmeDeviceOverride( row.values.back(), rule.argument) ;
	}

	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief 署名済みINFから取得した電源設定のローカライズ文字列を検査します
 * @param[in] value SetupAPIの展開済みの表示名、説明又は単位です
 * @return 有限で読み取れる文字列の場合trueです。未解決tokenや間接資源は拒否します
 */
//------------------------------------------------------------------------------
bool powerText( std::wstring_view value)
{
	return dataText( value) && value.front() != L'@' && std::ranges::any_of( value, []( wchar_t c) {
			   return c != L' ' && c != L'\u00A0' && c != L'\u3000' ;
		   }) ;
}

constexpr std::wstring_view DISK_POWER_SUBGROUP =
	L"{0012EE47-9041-4B5D-9B77-535FBA8B1442}" ;	// ディスク電源のサブグループです
constexpr std::array<std::wstring_view, 3U> DISK_POWER_PLANS{
	L"{8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C}", L"{381B4222-F694-41F0-9685-FF5BB260DF2E}",
	L"{A1841308-3541-4FAB-BC81-F71556F20B4A}"} ;	// 高パフォーマンス、バランス、省電力の元GUIDです

constexpr std::array<std::wstring_view, 3U> RANGED_POWER_PROPERTIES{
	L"Subgroup", L"Setting", L"ValueRange"} ;	// 一節に各一行必要な値域宣言
constexpr std::size_t RANGED_POWER_ROW_COUNT =
	// 三宣言と六つの既定値
	RANGED_POWER_PROPERTIES.size() + DISK_POWER_PLANS.size() * 2U ;

//------------------------------------------------------------------------------
/**
 * @brief 一節の電源値域と三プランのAC/DC既定値を検査します
 * @param[in] rows 同じ署名節から読んだ完全な行です。nullや未知キーは不正です
 * @param[out] result 全九行の成立時にだけ保持する元の型付き値です
 * @return 正式な範囲、許容する表示構文、六組の既定値がすべて成立した場合trueです
 * @note 文書の署名、現在端末の所有や導入資格は呼出し側が別に照合します
 */
//------------------------------------------------------------------------------
bool parseRangedStoragePowerSetting( std::span<const SystemInfRow *const> rows,
									RangedStoragePowerSetting			&result)
{
	// 欠けた既定値や余分な作用行を有効な一設定へ縮約しません
	if( rows.size() != RANGED_POWER_ROW_COUNT) {
		return false ;
	}

	std::array<const SystemInfRow *, RANGED_POWER_PROPERTIES.size()>
		declarations{} ;	// 元宣言の一意行
	// 許容したキーだけを各一回見つけ、既定値は範囲を確定してから照合します
	for( const auto *row : rows) {
		// 不在の行を既定の設定へ置き換えません
		if( !row) {
			return false ;
		}

		// 既定値は後段でプランとAC/DCの組に結びます
		if( same( row->key, L"Default")) {
			continue ;
		}

		const auto property = std::ranges::find_if( RANGED_POWER_PROPERTIES, [&]( auto key) {
			return same( key, row->key) ;
		}) ; // この節で解釈できる唯一のキー
		// 離散値や未分類のキーを値域形式へ変換しません
		if( property == RANGED_POWER_PROPERTIES.end()) {
			return false ;
		}

		auto &slot = declarations[static_cast<std::size_t>(
			property - RANGED_POWER_PROPERTIES.begin())] ;	// 同キーの元行を保持する位置
		// 重複行から先頭や後続の値を任意に採用しません
		if( slot) {
			return false ;
		}

		slot = row ;
	}

	// 節、設定、値域を別の参照から補完しません
	if( std::ranges::any_of( declarations, []( const auto *row) { return row == nullptr ; })) {
		return false ;
	}

	const auto	  &subgroup = declarations[0]->values ;						// 既存サブグループの唯一のGUID
	const auto	  &setting	= declarations[1]->values ;						// 設定GUIDと元の表示欄
	const auto	  &range	= declarations[2]->values ;						// 下限、上限、増分、任意の単位
	std::uint64_t  attributes{} ;											// 非表示属性の原値
	std::uint64_t  minimum{} ;												// 切り詰めない下限
	std::uint64_t  maximum{} ;												// 切り詰めない上限
	std::uint64_t  increment{} ;											// 切り詰めない増分
	constexpr auto MAX_DWORD = std::numeric_limits<std::uint32_t>::max() ;	// Windows値域の型上限
	// 既存サブグループ、非実行の表示値、追加の非表示属性1とDWORD値域だけを扱います
	if( subgroup.size() != 1U || !guid( subgroup.front()) || setting.empty() || setting.size() > 5U ||
	   !guid( setting.front()) ||
	   (setting.size() >= 2U && !setting[1].empty() && !powerText( setting[1])) ||
	   (setting.size() >= 3U && !setting[2].empty() && !powerText( setting[2])) ||
	   (setting.size() >= 4U && !setting[3].empty()) ||
	   (setting.size() == 5U && (!scalar( setting[4], attributes) || attributes != 1U)) ||
	   range.size() < 3U || range.size() > 4U ||
	   (range.size() == 4U && !range[3].empty() && !powerText( range[3])) ||
	   !scalar( range[0], minimum) || !scalar( range[1], maximum) || maximum < minimum ||
	   maximum > MAX_DWORD || !scalar( range[2], increment) || increment == 0U ||
	   increment > MAX_DWORD) {
		return false ;
	}

	RangedStoragePowerSetting					   made ;	// 全値を検査するまで外へ返さない結果
	std::array<bool, DISK_POWER_PLANS.size() * 2U> seen{} ;	// 各プランのACとDCの占有状態
	// 既定値を原GUIDとAC/DCの組に分け、開始値からの増分へ照合します
	for( const auto *row : rows) {
		// 検査済みの三宣言を既定値として扱いません
		if( !same( row->key, L"Default")) {
			continue ;
		}

		const auto	 &values = row->values ;	// プラン、AC/DC、既定値の全欄
		std::uint64_t powerSource{} ;			// AC0又はDC1
		std::uint64_t initial{} ;				// 切り詰めない元既定値
		// 範囲外、非整列又はAC/DC以外の値を拒みます
		if( values.size() != 3U || !scalar( values[1], powerSource) || powerSource > 1U ||
		   !scalar( values[2], initial) || initial < minimum || initial > maximum ||
		   (initial - minimum) % increment != 0U) {
			return false ;
		}

		const auto plan = std::ranges::find_if( DISK_POWER_PLANS, [&]( auto id) {
			return same( id, values[0]) ;
		}) ; // 同じGUIDの標準電源プラン
		// PCの任意プランを標準プランの既定値に流用しません
		if( plan == DISK_POWER_PLANS.end()) {
			return false ;
		}

		const auto slot = static_cast<std::size_t>( plan - DISK_POWER_PLANS.begin()) * 2U +
						  // プランに対応するAC/DCの位置
						  static_cast<std::size_t>( powerSource) ;
		// 同じ組の再定義を他の組の不足へ振り替えません
		if( seen[slot]) {
			return false ;
		}

		seen[slot]			= true ;
		made.defaults[slot] = static_cast<std::uint32_t>( initial) ;
	}

	made.subgroup	 = subgroup.front() ;
	made.setting	 = setting.front() ;
	made.displayName = setting.size() >= 2U ? setting[1] : L"" ;
	made.description = setting.size() >= 3U ? setting[2] : L"" ;
	made.unitLabel	 = range.size() == 4U ? range[3] : L"" ;
	// 属性欄の省略を明示値へ置き換えません
	if( setting.size() == 5U) {
		made.attributes = static_cast<std::uint32_t>( attributes) ;
	}

	made.minimum   = static_cast<std::uint32_t>( minimum) ;
	made.maximum   = static_cast<std::uint32_t>( maximum) ;
	made.increment = static_cast<std::uint32_t>( increment) ;
	result		   = std::move( made) ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief NVMeの各電源設定を、所有元の全行、既知GUID、値域、全プラン初期値に結びます
 * @param[in,out] state 元作用と最初の有限診断を所有する同期状態です
 * @param[in] section 同じNVMe基本節が参照した一つの電源設定節です
 * @param[in] settingGuid 設定節に結合した元プロファイルの設定GUIDです
 * @return 全九行と6つの初期値が成立すると0、欠落・重複・未知作用は専用の拒否です
 * @note 読み出した元表示と初期値は変更せず、Windows電源設定も変更しません
 */
//------------------------------------------------------------------------------
NativeError verifyNvmePowerSetting( EffectState &state, const SystemInfSection &section,
								   std::wstring_view settingGuid)
{
	constexpr auto STAGE = SystemInfDiagnosticStage::POWER_SETTING ;	// 元本文を含まない拒否位置です
	std::array<const SystemInfRow *, 3U + DISK_POWER_PLANS.size() * 2U>
		rows{} ;	// 三宣言と全AC/DC初期値です
	// 先頭三宣言と全初期値を元行位置のまま照合します
	for( const auto &effect : state.result.effects) {
		// 同名の他節、別文書、別所有先から初期値を借りません
		if( effect.source != section) {
			continue ;
		}

		const auto ordinal = effect.row.ordinal ;	// 元節内の0起点の位置です
		// 予期しない追加行や重複する行位置を先頭の値へ縮約しません
		if( ordinal >= rows.size() || rows[ordinal]) {
			return rejected( state, STAGE) ;
		}

		rows[ordinal] = &effect.row ;
	}

	RangedStoragePowerSetting power ;	// 同一節を共通構文で読んだ型付き値
	// Windows同梱NVMeの元順、GUID、表示欄、属性と既知の範囲は従来どおり照合します
	if( !parseRangedStoragePowerSetting( rows, power) ||
	   !same( rows[0]->key, RANGED_POWER_PROPERTIES[0]) ||
	   !same( rows[1]->key, RANGED_POWER_PROPERTIES[1]) ||
	   !same( rows[2]->key, RANGED_POWER_PROPERTIES[2]) ||
	   !same( power.subgroup, DISK_POWER_SUBGROUP) || !same( power.setting, settingGuid) ||
	   power.displayName.empty() || power.description.empty() || power.unitLabel.empty() ||
	   power.attributes != 1U || power.minimum != 0U || power.maximum != 60000U ||
	   power.increment != 1U) {
		return rejected( state, STAGE) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief AHCIの離散値又は時間範囲と3プランのAC/DC初期値を元順で照合します
 * @param[in,out] state 元作用と最初の有限診断を保持します
 * @param[in] section 同じAHCI基本節から到達した元電源設定です
 * @param[in] settingGuid 同じ電源設定だけに対応する固有GUIDです
 * @return 全原行の成立で0、欠落・重複・別の設定は拒否HRESULTです
 */
//------------------------------------------------------------------------------
NativeError verifyAhciPowerSetting( EffectState &state, const SystemInfSection &section,
								   std::wstring_view settingGuid)
{
	using Text = std::wstring_view ;
	constexpr std::array<Text, 4U> INDICES{L"0", L"1", L"2", L"3"} ;	// 選択肢の元番号です
	constexpr std::array<Text, 4U> MODES{L"0", L"1", L"3",
										 L"2"} ;	// Active、HIPM、両方、DIPMのDWORDです
	// 高パフォーマンス、バランス、省電力の順に並ぶAC/DC初期値です
	constexpr std::array<Text, 6U> MODE_DEFAULTS{L"0", L"1", L"1", L"1", L"2", L"2"} ;
	// 標準AHCIが指定するACとDCの時間初期値
	constexpr std::array<Text, 6U> TIME_DEFAULTS{L"0", L"0", L"100", L"100", L"100", L"100"} ;
	constexpr auto STAGE = SystemInfDiagnosticStage::POWER_SETTING ;	// 固定の拒否位置です
	const bool	   selectable =
		// 離散値を持つ最初の設定です
		same( section.name, AHCI_POWER_SECTIONS[0]) ;
	const auto	defaultStart = selectable ? 2U + INDICES.size() : 3U ;		// 最初のDefault行の位置です
	const auto &defaults	 = selectable ? MODE_DEFAULTS : TIME_DEFAULTS ;	// この設定の全初期値です
	std::array<const SystemInfRow *, 2U + INDICES.size() + MODE_DEFAULTS.size()>
			   rows{} ;	// 大きい方の元行数を上限とします
	const auto activeRows =
		std::span{rows}.first( defaultStart + defaults.size()) ;	// 元設定で必要な全行です
	// 原位置を失った値や別設定の行から補いません
	for( const auto &effect : state.result.effects) {
		// 同じ元参照の全行だけを集めます
		if( effect.source != section) {
			continue ;
		}

		const auto ordinal = effect.row.ordinal ;	// 同じ元設定における行位置です
		// 重複や所定範囲外の行を設定値に取り込みません
		if( ordinal >= activeRows.size() || activeRows[ordinal]) {
			return rejected( state, STAGE) ;
		}

		activeRows[ordinal] = &effect.row ;
	}

	// 全行が揃い、先頭に正規ディスク設定の宣言がある場合に限ります
	if( std::ranges::any_of( activeRows, []( const auto *row) { return row == nullptr ; }) ||
	   !inboxRowMatches( *rows[0], {L"Subgroup", {DISK_POWER_SUBGROUP}}) ||
	   !same( rows[1]->key, L"Setting") || rows[1]->values.size() != 5U) {
		return rejected( state, STAGE) ;
	}

	const auto &setting = rows[1]->values ;	// GUID、表示、説明、予約欄と隠し属性です
	// 別の設定や間接資源を定義せず、予約欄と属性も元値に限定します
	if( !powerText( setting[1]) || !powerText( setting[2]) ||
	   !inboxRowMatches( *rows[1], {L"Setting", {settingGuid, setting[1], setting[2], L"", L"1"}})) {
		return rejected( state, STAGE) ;
	}

	// 二つの設定で値域の型を入れ替えません
	if( selectable) {
		// 選択番号ごとに異なるDWORDを結び、表示は元ローカライズ文字列を保持します
		for( std::size_t i = 0U; i < INDICES.size(); ++i) {
			const auto &row = *rows[i + 2U] ;	// 同設定の選択肢です
			const auto &v	= row.values ;		// 選択番号からDWORDまでの全fieldです
			// 同じ番号に期待する元値と異なる型や値を拒否します
			if( v.size() != 5U || !powerText( v[1]) || !powerText( v[2]) ||
			   !inboxRowMatches( row, {L"Value", {INDICES[i], v[1], v[2], L"0x10001", MODES[i]}})) {
				return rejected( state, STAGE) ;
			}
		}
	} else {
		const auto &range = rows[2]->values ;	// 0から300000ミリ秒を1刻みで扱う元範囲です
		// 数値の上下限や刻みを拡張せず、表示用の単位だけを元文字列のまま保ちます
		if( range.size() != 4U || !powerText( range[3]) ||
		   !inboxRowMatches( *rows[2], {L"ValueRange", {L"0", L"300000", L"1", range[3]}})) {
			return rejected( state, STAGE) ;
		}
	}

	// 各プランのAC0とDC1を、その設定の元初期値へ個別に照合します
	for( std::size_t i = 0U; i < defaults.size(); ++i) {
		// 同じ組の重複、別プラン、別電源状態又は別初期値で元行を埋めません
		if( !inboxRowMatches(
			   *rows[defaultStart + i],
			   {L"Default", {DISK_POWER_PLANS[i / 2U], i % 2U == 0U ? L"0" : L"1", defaults[i]}})) {
			return rejected( state, STAGE) ;
		}
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 一つのWindows同梱文書の選択節、参照元の所有者、一意な全作用を照合します
 * @param[in,out] state 同期中に列挙した原節と各行の検査結果です
 * @param[in] document INBOX署名・Storeと同CATを確認した元文書の非零IDです
 * @param[in] rules 元選択で必要な全節と各節の全行です。この同期中だけ借用します
 * @param[in] requireOrder 行順に作用する設定では各行の元位置も照合します
 * @return 全集合の一致で0、欠落・重複・余分な節や行、異なる所有先は拒否HRESULTです
 */
//------------------------------------------------------------------------------
NativeError verifyInboxSections( EffectState &state, std::uint64_t document,
								std::span<const InboxSectionRule> rules, bool requireOrder = false)
{
	const auto count = std::ranges::count( state.sections, document,
										  &SystemInfSection::document) ;	// 同原文の到達節数です
	// 無作用に見える追加節も別経路の選択として拒否します
	if( static_cast<std::size_t>( count) != rules.size()) {
		return rejected( state, SystemInfDiagnosticStage::REFERENCE) ;
	}

	// 各節を型と所有者まで確認してから、同じ元節の行だけを照合します
	for( const auto &rule : rules) {
		const auto section = std::ranges::find_if( state.sections, [&]( const auto &source) {
			return source.document == document && source.context == rule.context &&
				   source.scope == rule.scope && same( source.name, rule.name) &&
				   (rule.owner.empty() ? source.owner.empty() : same( source.owner, rule.owner)) ;
		}) ; // 同じ署名文書の節だけを同期参照します
		// 別の所有先や文脈にある同名節から補いません
		if( section == state.sections.end()) {
			return rejected( state, SystemInfDiagnosticStage::REFERENCE) ;
		}

		// 標準ストレージの電源設定は全行に対してプラン別の初期値を照合します
		if( !rule.powerSettingGuid.empty()) {
			// 文書に結び付く標準AHCIまたは通常の作用検査結果
			const auto error = document == state.api.storAhciInboxDocument
								   ? verifyAhciPowerSetting( state, *section, rule.powerSettingGuid)
								   : verifyNvmePowerSetting( state, *section, rule.powerSettingGuid) ;
			// 一部の電源設定だけを成功へ残しません
			if( error != 0U) {
				return error ;
			}

			continue ;
		}

		const auto	stage	 = rule.context == SystemInfContext::REGISTRY
								   ? SystemInfDiagnosticStage::REGISTRY
								   : SystemInfDiagnosticStage::DIRECTIVE ;	// 失敗した作用の区分です
		const auto	rowCount = std::ranges::count( state.result.effects, *section,
												  &SystemInfEffect::source) ;	// 元節の全行数です
		std::size_t expectedRows{} ;											// 元節に必要な各型の行数を合計します
		// 複数行を持つ型にも必要な件数を課します
		for( const auto &rowRule : rule.rows) {
			expectedRows += rowRule.count ;
		}

		// 追加のdirectiveやデータを元行に混ぜて通過させません
		if( static_cast<std::size_t>( rowCount) != expectedRows) {
			return rejected( state, stage, static_cast<std::uint32_t>( rule.scope)) ;
		}

		std::size_t ordinal{} ;	// 行順を照合するプロファイルの期待位置です
		// 行順を保持し、期待する各作用の件数を同じ節内で確かめます
		for( const auto &rowRule : rule.rows) {
			const auto matches =
				std::ranges::count_if( state.result.effects, [&]( const auto &effect) {
					return effect.source == *section &&
						   (!requireOrder || (effect.row.ordinal >= ordinal &&
											  effect.row.ordinal - ordinal < rowRule.count)) &&
						   inboxRowMatches( effect.row, rowRule) ;
				}) ; // 他の正しい行の重複で欠落を埋めません
			// 型、参照、flags、全fieldのどれかが異なる行も拒否します
			if( static_cast<std::size_t>( matches) != rowRule.count) {
				return rejected( state, stage, static_cast<std::uint32_t>( rule.scope)) ;
			}

			ordinal += rowRule.count ;
		}
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 収集で到達したSDバスの三選択節とその参照先の全作用を同じ原文内で検査します
 * @param[in,out] state 原文の全行、共有予算、最初の固定拒否を所有する検査です
 * @return 該当文書がない場合または完全一致で0、欠落・重複・追加・異なる所有先は拒否HRESULTです
 * @note ServiceBinaryの実ファイルと元CopyFilesは既存検査へ引き継ぎ、SCMを照会しません
 */
//------------------------------------------------------------------------------
NativeError verifySdBusEffects( EffectState &state)
{
	const auto document = state.api.sdBusInboxDocument ;	// 元INBOX署名とStoreが結んだ収集専用IDです
	// 端末や他の文書を単独で検査したときはSDバスの作用を要求しません
	if( document == 0U || std::ranges::find( state.sections, document, &SystemInfSection::document) ==
							 state.sections.end()) {
		return 0U ;
	}

	using Context = SystemInfContext ;
	// 選択三節と到達する五節の全fieldです。入れ子の初期化リストをこの呼出し中だけ保持します
	const InboxSectionRule SECTIONS[] = {
		{L"SDHostIntelCherryTrail",
		 Context::DEVICE,
		 Context::DEVICE,
		 {{L"CopyFiles", {L"CSCopyFiles"}}, {L"AddReg", {L"SDBUSReg"}}}},
		{L"SDHostIntelCherryTrail.HW",
		 Context::HARDWARE,
		 Context::HARDWARE,
		 {{L"AddReg", {L"SDBUSLocationReg"}}, {L"AddReg", {L"SDHostIntelCherryTrail.HW.addreg"}}}},
		{L"SDHostIntelCherryTrail.Services",
		 Context::SERVICES,
		 Context::SERVICES,
		 {{L"AddService", {L"sdbus", L"2", L"sdbus_Service_Inst"}}}},
		{L"sdbus_Service_Inst",
		 Context::SERVICE,
		 Context::SERVICE,
		 {{L"ServiceType", {L"1"}},
		  {L"StartType", {L"3"}},
		  {L"ErrorControl", {L"1"}},
		  {L"ServiceBinary", {}, InboxTail::SERVICE_BINARY, L"sdbus.sys"},
		  {L"LoadOrderGroup", {L"System Bus Extender"}},
		  {L"AddReg", {L"SDBUSServiceReg"}}},
		 L"sdbus"},
		{L"SDBUSReg",
		 Context::REGISTRY,
		 Context::DEVICE,
		 {{{}, {L"HKR", L"", L"Driver", L"", L"sdbus.sys"}}}},
		{L"SDBUSLocationReg",
		 Context::REGISTRY,
		 Context::HARDWARE,
		 {{{}, {L"HKR", L"", L"UINumberDescFormat", L""}, InboxTail::SLOT_FORMAT}}},
		{L"SDHostIntelCherryTrail.HW.addreg",
		 Context::REGISTRY,
		 Context::HARDWARE,
		 {{{}, {L"HKR", L"", L"CompatType", L"0x10001"}, InboxTail::HARDWARE_DWORD},
		  {{}, {L"HKR", L"", L"HostRevision", L"0x10001"}, InboxTail::HARDWARE_DWORD},
		  {{}, {L"HKR", L"", L"FunctionBlockIndex", L"0x10001"}, InboxTail::HARDWARE_DWORD},
		  {{}, {L"HKR", L"", L"OverrideFlags", L"0x10001"}, InboxTail::HARDWARE_DWORD}}},
		{L"SDBUSServiceReg",
		 Context::REGISTRY,
		 Context::SERVICE,
		 {{{}, {L"HKR", L"", L"BootFlags", L"0x10003", L"8"}},
		  {{}, {L"HKR", L"Parameters", L"SdCmdFlags", L"1"}, InboxTail::COMMAND_BYTES},
		  {{}, {L"HKR", L"Parameters", L"SdAppCmdFlags", L"1"}, InboxTail::COMMAND_BYTES}},
		 L"sdbus"},
	} ;

	return verifyInboxSections( state, document, SECTIONS) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 収集で到達した標準Portsの基本、HW、Servicesと各サービス所有の全作用を照合します
 * @param[in,out] state 元署名済み文書からの選択と型付き全行を保持する検査です
 * @return 元選択の全作用が一意なら0、欠落・追加・異なる作用や所有先は拒否HRESULTです
 * @pre msPortsInboxDocumentは収集の元Ports選択で確認した正規Windows INFの非零IDです
 * @note CopyFilesはSerial.NTだけが所有します。SerenumはHW上位フィルターのサービスです
 */
//------------------------------------------------------------------------------
NativeError verifyMsPortsEffects( EffectState &state)
{
	using Context = SystemInfContext ;
	const InboxSectionRule serenumService{
		L"Serenum_Service_Inst",
		Context::SERVICE,
		Context::SERVICE,
		{{L"DisplayName", {}, InboxTail::DISPLAY_NAME},
		 {L"ServiceType", {L"1"}},
		 {L"StartType", {L"3"}},
		 {L"ErrorControl", {L"1"}},
		 {L"ServiceBinary", {}, InboxTail::SERVICE_BINARY, L"serenum.sys"},
		 {L"LoadOrderGroup", {L"PNP Filter"}}},
		L"Serenum"} ;	// 両経路が参照する同じ元サービス節
	// 元の自前媒体を確認した収集選択では、SerialEnumeratorの三節だけに絞る
	if( state.api.serialEnumeratorOnly) {
		const InboxSectionRule sections[]{
			{L"SerialEnumerator.NT",
			 Context::DEVICE,
			 Context::DEVICE,
			 {{L"CopyFiles", {L"SerialEnumerator.NT.Copy"}}}},
			{L"SerialEnumerator.NT.Services",
			 Context::SERVICES,
			 Context::SERVICES,
			 {{L"AddService", {L"Serenum", L"", L"Serenum_Service_Inst"}}}},
			serenumService,
		} ; // 元基本節と元Servicesから到達する三つの正確な作用
		return verifyInboxSections( state, state.api.msPortsInboxDocument, sections) ;
	}

	// 選択三節とそこから到達する五節の行を、サービス名とイベントログの所有先に結びます
	const InboxSectionRule SECTIONS[] = {
		{L"Serial.NT", Context::DEVICE, Context::DEVICE, {{L"CopyFiles", {L"Serial.NT.Copy"}}}},
		{L"ComPort.NT.HW",
		 Context::HARDWARE,
		 Context::HARDWARE,
		 {{L"AddReg", {L"ComPort.NT.HW.AddReg"}}}},
		{L"ComPort.NT.Services",
		 Context::SERVICES,
		 Context::SERVICES,
		 {{L"AddService", {L"Serial", L"2", L"Serial_Service_Inst", L"Serial_EventLog_Inst"}},
		  {L"AddService", {L"Serenum", L"", L"Serenum_Service_Inst"}}}},
		{L"Serial_Service_Inst",
		 Context::SERVICE,
		 Context::SERVICE,
		 {{L"DisplayName", {}, InboxTail::DISPLAY_NAME},
		  {L"ServiceType", {L"1"}},
		  {L"StartType", {L"3"}},
		  {L"ErrorControl", {L"0"}},
		  {L"ServiceBinary", {}, InboxTail::SERVICE_BINARY, L"serial.sys"},
		  {L"LoadOrderGroup", {L"Extended base"}}},
		 L"Serial"},
		serenumService,
		{L"ComPort.NT.HW.AddReg",
		 Context::REGISTRY,
		 Context::HARDWARE,
		 {{{}, {L"HKR", L"", L"UpperFilters", L"0x10000", L"Serenum"}}}},
		{L"Serial_EventLog_Inst",
		 Context::EVENT_LOG,
		 Context::EVENT_LOG,
		 {{L"AddReg", {L"Serial_EventLog_AddReg"}}},
		 L"Serial"},
		{L"Serial_EventLog_AddReg",
		 Context::REGISTRY,
		 Context::EVENT_LOG,
		 {{{}, {L"HKR", L"", L"EventMessageFile", L"0x20000"}, InboxTail::SERIAL_EVENT_FILES},
		  {{}, {L"HKR", L"", L"TypesSupported", L"0x10001"}, InboxTail::EVENT_TYPES}},
		 L"Serial"},
	} ;
	return verifyInboxSections( state, state.api.msPortsInboxDocument, SECTIONS) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 選択された標準NVMeとPCIの各原文を、到達節・所有者・全作用へ結びます
 * @param[in,out] state 同じ選択で原署名とStoreを確認した両文書の同期状態です
 * @return NVMe選択が無い場合又は全作用の照合で0、不足や未知の作用は拒否HRESULTです
 * @note 署名済み同文書でも選択外のIntel節、PCIサービス又は別のHW設定を含めません
 */
//------------------------------------------------------------------------------
NativeError verifyNvmeInboxEffects( EffectState &state)
{
	const auto nvme = state.api.storNvmeInboxDocument ;	// NVMe選択の原署名・Store・CATに結ぶIDです
	// 未指定時は通常の型条件を維持します
	if( nvme == 0U) {
		return 0U ;
	}

	using Context						= SystemInfContext ;	// 原節とHKRの文脈です
	constexpr std::wstring_view SERVICE = L"stornvme" ;			// 元AddServiceと相対HKRを結ぶ所有者です
	constexpr std::wstring_view OVERRIDES =
		L"nvme_registry_device_specific_values" ;	// サービス所有のPCIデバイス別追記です
	constexpr std::wstring_view MSI =
		L"Interrupt Management\\MessageSignaledInterruptProperties" ;	// デバイスHWのMSI設定です
	constexpr std::wstring_view AFFINITY =
		L"Interrupt Management\\Affinity Policy" ;	// デバイスHWの割り込み分配設定です
	const InboxSectionRule nvmeSections[]{
		{NVME_INSTALL_SECTION,
		 Context::DEVICE,
		 Context::DEVICE,
		 {{L"CopyFiles", {L"Stornvme_copyfiles"}},
		  {L"AddPowerSetting",
		   {NVME_POWER_SECTIONS[0], NVME_POWER_SECTIONS[1], NVME_POWER_SECTIONS[2],
			NVME_POWER_SECTIONS[3]}}}},
		{L"Stornvme_Inst.HW",
		 Context::HARDWARE,
		 Context::HARDWARE,
		 {{L"AddReg", {L"Stornvme_Inst_HW_AddReg"}},
		  {L"Include", {L"pci.inf"}},
		  {L"Needs", {L"PciForceSBR.HW"}}}},
		{L"Stornvme_Inst.Services",
		 Context::SERVICES,
		 Context::SERVICES,
		 {{L"AddService", {SERVICE, L"2", L"Stornvme_Service_Inst", L"Stornvme_EventLog_Inst"}}}},
		{L"Stornvme_Service_Inst",
		 Context::SERVICE,
		 Context::SERVICE,
		 {{L"DisplayName", {}, InboxTail::DISPLAY_NAME},
		  {L"ServiceType", {L"1"}},
		  {L"StartType", {L"0"}},
		  {L"ErrorControl", {L"3"}},
		  {L"ServiceBinary", {}, InboxTail::SERVICE_BINARY, L"stornvme.sys"},
		  {L"LoadOrderGroup", {L"SCSI Miniport"}},
		  {L"AddReg", {L"nvme_registry_values"}},
		  {L"AddReg", {OVERRIDES}}},
		 SERVICE},
		{L"Stornvme_EventLog_Inst",
		 Context::EVENT_LOG,
		 Context::EVENT_LOG,
		 {{L"AddReg", {L"Stornvme_EventLog_AddReg"}}},
		 SERVICE},
		{L"Stornvme_EventLog_AddReg",
		 Context::REGISTRY,
		 Context::EVENT_LOG,
		 {{{},
		   {L"HKR", L"", L"EventMessageFile", L"0x20000", L"%SystemRoot%\\System32\\IoLogMsg.dll"}},
		  {{}, {L"HKR", L"", L"TypesSupported", L"0x10001", L"7"}}},
		 SERVICE},
		{L"Stornvme_Inst_HW_AddReg",
		 Context::REGISTRY,
		 Context::HARDWARE,
		 {{{}, {L"HKR", L"Interrupt Management", L"0x00000010"}},
		  {{}, {L"HKR", MSI, L"0x00000010"}},
		  {{}, {L"HKR", AFFINITY, L"0x00000010"}},
		  {{}, {L"HKR", MSI, L"MSISupported", L"0x10001", L"1"}},
		  {{}, {L"HKR", MSI, L"MessageNumberLimit", L"0x10001", L"2048"}},
		  {{}, {L"HKR", AFFINITY, L"DevicePolicy", L"0x10001", L"5"}},
		  {{}, {L"HKR", AFFINITY, L"DevicePriority", L"0x10001", L"3"}},
		  {{}, {L"HKR", AFFINITY, L"GroupPolicy", L"0x10001", L"1"}},
		  {{}, {L"HKR", L"DMA Management", L"RemappingSupported", L"0x10001", L"1"}},
		  {{}, {L"HKR", L"DMA Management", L"RemappingFlags", L"0x10001", L"1"}}}},
		{L"nvme_registry_values",
		 Context::REGISTRY,
		 Context::SERVICE,
		 {{{}, {L"HKR", L"Parameters\\PnpInterface", L"5", L"0x10001", L"1"}},
		  {{}, {L"HKR", L"Parameters", L"BusType", L"0x10001", L"0x11"}},
		  {{}, {L"HKR", L"Parameters", L"IoTimeoutValue", L"0x10001", L"10"}},
		  {{}, {L"HKR", L"Parameters", L"StorageSupportedFeatures", L"0x10001", L"3"}}},
		 SERVICE},
		{OVERRIDES,
		 Context::REGISTRY,
		 Context::SERVICE,
		 {{{},
		   {L"HKR", L"Parameters\\Device", L"IoStripeAlignment", L"0x10008"},
		   InboxTail::NVME_DEVICE_OVERRIDE,
		   L"128",
		   5U},
		  {{},
		   {L"HKR", L"Parameters\\Device", L"DisableF0TimestampSync", L"0x10008"},
		   InboxTail::NVME_DEVICE_OVERRIDE,
		   L"1"}},
		 SERVICE},
		{NVME_POWER_SECTIONS[0],
		 Context::POWER_SETTING,
		 Context::POWER_SETTING,
		 {},
		 NVME_INSTALL_SECTION,
		 L"{FC95AF4D-40E7-4B6D-835A-56D131DBC80E}"},
		{NVME_POWER_SECTIONS[1],
		 Context::POWER_SETTING,
		 Context::POWER_SETTING,
		 {},
		 NVME_INSTALL_SECTION,
		 L"{D639518A-E56D-4345-8AF2-B9F32FB26109}"},
		{NVME_POWER_SECTIONS[2],
		 Context::POWER_SETTING,
		 Context::POWER_SETTING,
		 {},
		 NVME_INSTALL_SECTION,
		 L"{DBC9E238-6DE9-49E3-92CD-8C2B4946B472}"},
		{NVME_POWER_SECTIONS[3],
		 Context::POWER_SETTING,
		 Context::POWER_SETTING,
		 {},
		 NVME_INSTALL_SECTION,
		 L"{D3D55EFD-C1FF-424E-9DC3-441BE7833010}"},
	} ; // 選択節とそこから同じ文書内で明示参照した全節です
	const InboxSectionRule pciSections[]{
		{L"PciForceSBR.HW",
		 Context::HARDWARE,
		 Context::HARDWARE,
		 {{L"AddReg", {L"PciForceSBR.RegHW"}}}},
		{L"PciForceSBR.RegHW",
		 Context::REGISTRY,
		 Context::HARDWARE,
		 {{{}, {L"HKR", L"e5b3b5ac-9725-4f78-963f-03dfb1d828c7", L"ForceSBR", L"0x10001", L"1"}}}},
	} ; // PCI側は指定したHWの1作用のみを検査します

	const auto nvmeError =
		// NVMeの元全作用を検査します
		verifyInboxSections( state, nvme, nvmeSections) ;
	// 片方だけの署名済み文書では選択全体を承認しません
	if( nvmeError != 0U) {
		return nvmeError ;
	}

	const auto pciError = verifyInboxSections( state, state.api.pciNvmeInboxDocument,
											  pciSections) ;	// PCIの元作用を検査します
	// 別PCI節や元値不一致を同名のHWとして扱いません
	if( pciError != 0U) {
		return pciError ;
	}

	std::set<std::wstring> devices ;	// 同一PCI指定を複数の原行の代わりにしません
	std::wstring_view	   unit ;		// 四つの範囲が共有する元ローカライズ済みミリ秒単位です
	// 各行の型を確認した後、デバイス別追記と電源設定間の関係を検査します
	for( const auto &effect : state.result.effects) {
		// 他の署名文書からデバイスや電源設定を取り込みません
		if( effect.source.document != nvme) {
			continue ;
		}

		// 各原REG_MULTI_SZ行のPCI指定を一意にします
		if( same( effect.source.name, OVERRIDES)) {
			const auto &value = effect.row.values[4] ;	// 型検査済みのPCI指定と設定値です
			// 既存のPCI指定の重複で別対象を満たしたことにしません
			if( !devices.insert( folded( value.substr( 0U, value.find( L' ')))).second) {
				return rejected( state, SystemInfDiagnosticStage::REGISTRY) ;
			}
		}

		// 同じミリ秒の範囲を表す四つの電源設定は元単位を共有します
		if( effect.source.context == Context::POWER_SETTING && same( effect.row.key, L"ValueRange")) {
			const auto &current = effect.row.values[3] ;	// 読取済みの元単位です
			// 異なる単位を同じ意味の範囲として扱いません
			if( !unit.empty() && unit != current) {
				return rejected( state, SystemInfDiagnosticStage::POWER_SETTING) ;
			}

			unit = current ;
		}
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief PCI IDが同一又はアンパサンドで区切る同じ枝にあるかを確認します
 * @param[in] left 照合中だけ借用する元PnP IDです
 * @param[in] right 照合中だけ借用するもう一方の元PnP IDです
 * @return 大文字小文字を除いて同一か、片方が相手の区切り位置まで一致する場合trueです
 */
//------------------------------------------------------------------------------
bool sameHardwareIdBranch( std::wstring_view left, std::wstring_view right)
{
	// 部分一致を一方向にそろえ、元値を変更せずに比較します
	if( left.size() > right.size()) {
		std::swap( left, right) ;
	}

	return same( left, right.substr( 0U, left.size())) &&
		   (left.size() == right.size() || right[left.size()] == L'&') ;
}
//------------------------------------------------------------------------------
/**
 * @brief 署名済みmshdc.infのAHCI選択を元全節と読み出した全作用へ結びます
 * @param[in,out] state 収集で確認した原文IDと到達した全作用を保持します
 * @return 選択された全作用の成立で0、欠落・余分又は別の作用は拒否HRESULTです
 * @note 配布元IDと競合しない既知の21除外ID、サービス所有の相対設定と固有の共有追記を照合します
 */
//------------------------------------------------------------------------------
NativeError verifyAhciInboxEffects( EffectState &state)
{
	const auto ahci = state.api.storAhciInboxDocument ;	// 原署名・Store・CATを確認済みのIDです
	// 元文書が確定した収集だけで専用検査を有効にします
	if( ahci == 0U) {
		return 0U ;
	}

	const auto ids = state.api.ahciHardwareIds ;	// 収集rootの元署名が覆うPnP ID全体を借用します
	// 元配布の一部や空集合では除外との競合がないことを確認できません
	if( ids.empty() || ids.size() > 4096U || std::ranges::any_of( ids, []( const auto &id) {
		   return id.empty() || id.size() > 256U || id.find( wchar_t{}) != id.npos ;
	   })) {
		return rejected( state, SystemInfDiagnosticStage::REFERENCE) ;
	}

	using Context						= SystemInfContext ;
	constexpr std::wstring_view SERVICE = L"storahci" ;				// 元サービスと全相対設定の所有者です
	constexpr std::wstring_view DEVICE	= L"Parameters\\Device" ;	// サービスの機種別設定の位置です
	constexpr std::wstring_view APPEND	= L"0x10008" ;				// REG_MULTI_SZ追記だけを認めます
	constexpr std::wstring_view DWORD_TYPE = L"0x10001" ;			// 符号なしの単一DWORDです
	constexpr std::wstring_view MSI =
		L"Interrupt Management\\MessageSignaledInterruptProperties" ;	// デバイスHWのMSI設定です
	constexpr std::wstring_view AFFINITY =
		L"Interrupt Management\\Affinity Policy" ;	// デバイスHWの割り込み分配設定です
	const InboxSectionRule sections[]{
		{AHCI_INSTALL_SECTION,
		 Context::DEVICE,
		 Context::DEVICE,
		 {{L"CopyFiles", {L"storahci_copyfiles"}},
		  {L"AddPowerSetting", {AHCI_POWER_SECTIONS[0], AHCI_POWER_SECTIONS[1]}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2653&SUBSYS_0F001179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2653&SUBSYS_0F101179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_27C5&SUBSYS_0F001179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_27C5&SUBSYS_0F101179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_27C5&SUBSYS_0F031179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_27C5&SUBSYS_0F131179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_27C5&SUBSYS_FF011179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_0F031179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_0F131179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF011179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF021179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF031179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF041179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF111179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF121179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF131179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF141179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF311179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF321179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF331179"}},
		  {L"ExcludeId", {L"PCI\\VEN_8086&DEV_2829&SUBSYS_FF341179"}}}},
		{L"msahci_Inst.HW",
		 Context::HARDWARE,
		 Context::HARDWARE,
		 {{L"AddReg", {L"msahci_Inst_HW_AddReg"}}}},
		{L"msahci_Inst.Services",
		 Context::SERVICES,
		 Context::SERVICES,
		 {{L"AddService",
		   {SERVICE, L"2", L"msahci_Service_Inst_Client", L"storahci_EventLog_Inst"}}}},
		{L"msahci_Service_Inst_Client",
		 Context::SERVICE,
		 Context::SERVICE,
		 {{L"DisplayName", {}, InboxTail::DISPLAY_NAME},
		  {L"ServiceType", {L"1"}},
		  {L"StartType", {L"0"}},
		  {L"ErrorControl", {L"3"}},
		  {L"ServiceBinary", {}, InboxTail::SERVICE_BINARY, L"storahci.sys"},
		  {L"LoadOrderGroup", {L"SCSI Miniport"}},
		  {L"AddReg", {L"storahci_general_values"}},
		  {L"AddReg", {L"device_specific_values"}},
		  {L"AddReg", {L"client_sku_values"}}},
		 SERVICE},
		{L"msahci_Inst_HW_AddReg",
		 Context::REGISTRY,
		 Context::HARDWARE,
		 {{{}, {L"HKR", L"Interrupt Management", L"0x00000010"}},
		  {{}, {L"HKR", MSI, L"0x00000010"}},
		  {{}, {L"HKR", AFFINITY, L"0x00000010"}},
		  {{}, {L"HKR", MSI, L"MSISupported", DWORD_TYPE, L"1"}},
		  {{}, {L"HKR", MSI, L"MessageNumberLimit", DWORD_TYPE, L"8"}},
		  {{}, {L"HKR", AFFINITY, L"DevicePolicy", DWORD_TYPE, L"5"}},
		  {{}, {L"HKR", AFFINITY, L"DevicePriority", DWORD_TYPE, L"3"}},
		  {{}, {L"HKR", AFFINITY, L"GroupPolicy", DWORD_TYPE, L"1"}},
		  {{}, {L"HKR", L"StorPort", L"EnableIdlePowerManagement", DWORD_TYPE, L"1"}},
		  {{}, {L"HKR", L"DMA Management", L"RemappingSupported", DWORD_TYPE, L"1"}},
		  {{}, {L"HKR", L"DMA Management", L"RemappingFlags", DWORD_TYPE, L"1"}}}},
		{L"storahci_general_values",
		 Context::REGISTRY,
		 Context::SERVICE,
		 {{{},
		   {L"HKLM", L"SYSTEM\\CurrentControlSet\\Control\\Compatibility\\Driver\\storahci.sys",
			L"Shims", APPEND, L"Srbshim"}},
		  {{}, {L"HKR", L"Parameters\\PnpInterface", L"5", DWORD_TYPE, L"1"}},
		  {{}, {L"HKR", L"Parameters", L"BusType", DWORD_TYPE, L"11"}},
		  {{}, {L"HKR", L"Parameters", L"IoTimeoutValue", DWORD_TYPE, L"30"}},
		  {{}, {L"HKR", L"Parameters", L"BusyRetryCount", DWORD_TYPE, L"240"}},
		  {{}, {L"HKR", L"Parameters", L"BusyPauseTimeInMs", DWORD_TYPE, L"500"}}},
		 SERVICE},
		{L"device_specific_values",
		 Context::REGISTRY,
		 Context::SERVICE,
		 {{{}, {L"HKR", DEVICE, L"ResetInInit", APPEND, L"VEN_1106&DEV_6287&REV_*"}},
		  {{}, {L"HKR", DEVICE, L"SingleIO", APPEND, L"VEN_1106&DEV_6287&REV_00"}},
		  {{}, {L"HKR", DEVICE, L"SingleIO", APPEND, L"VEN_1106&DEV_6287&REV_10"}},
		  {{}, {L"HKR", DEVICE, L"SingleIO", APPEND, L"VEN_1106&DEV_6287&REV_20"}},
		  {{}, {L"HKR", DEVICE, L"IgnoreHotPlug", APPEND, L"VEN_1002&DEV_4380&REV_*"}},
		  {{},
		   {L"HKR", DEVICE, L"NeverNonQueuedErrorRecovery", APPEND, L"VEN_1002&DEV_4380&REV_*"}},
		  {{}, {L"HKR", DEVICE, L"EnableCLOReset", APPEND, L"VEN_1002&DEV_4391&REV_*"}},
		  {{}, {L"HKR", DEVICE, L"ExpectedMsiMessageCount", APPEND, L"VEN_1022&DEV_7801&REV_00 8"}},
		  {{}, {L"HKR", DEVICE, L"NoFUACommand", APPEND, L"HTE*"}},
		  {{}, {L"HKR", DEVICE, L"NoFUACommand", APPEND, L"Hitachi*"}},
		  {{}, {L"HKR", DEVICE, L"NoFUACommand", APPEND, L"HTS*"}},
		  {{}, {L"HKR", DEVICE, L"NoFUACommand", APPEND, L"HDS*"}},
		  {{}, {L"HKR", DEVICE, L"NoFUACommand", APPEND, L"HDT*"}},
		  {{}, {L"HKR", DEVICE, L"NeedSetTransferModeCommand", APPEND, L"MCBQE64GBMPP*"}},
		  {{}, {L"HKR", DEVICE, L"NoLPM", APPEND, L"WD740ADFD?00NLR1*"}},
		  {{}, {L"HKR", DEVICE, L"NoLPM", APPEND, L"WDC WD740ADFD?00NLR1*"}},
		  {{}, {L"HKR", DEVICE, L"NoLPM", APPEND, L"Maxtor 6V???E0*"}},
		  {{}, {L"HKR", DEVICE, L"NoLPM", APPEND, L"Maxtor 6V???F0*"}},
		  {{}, {L"HKR", DEVICE, L"NoLPM", APPEND, L"Maxtor 7V???E0*"}},
		  {{}, {L"HKR", DEVICE, L"NoLPM", APPEND, L"Maxtor 7V???F0*"}},
		  {{}, {L"HKR", DEVICE, L"NoLPM", APPEND, L"SanDisk SSD P4*"}},
		  {{}, {L"HKR", DEVICE, L"NoIdleD3", APPEND, L"INTEL SSD?C??????A4"}},
		  {{}, {L"HKR", DEVICE, L"NoIdleD3", APPEND, L"INTEL SSD?C??????A4?"}},
		  {{}, {L"HKR", DEVICE, L"NoIdleD3", APPEND, L"INTEL SSD?C??????A4??"}},
		  {{}, {L"HKR", DEVICE, L"NoIdleD3", APPEND, L"INTEL SSD?C??????A5"}},
		  {{}, {L"HKR", DEVICE, L"NoIdleD3", APPEND, L"INTEL SSD?C??????A5?"}},
		  {{}, {L"HKR", DEVICE, L"NoIdleD3", APPEND, L"INTEL SSD?C??????A5??"}},
		  {{}, {L"HKR", DEVICE, L"PRDTSplit", APPEND, L"VEN_1022&DEV_43B5&REV_*"}},
		  {{}, {L"HKR", DEVICE, L"PRDTSplit", APPEND, L"VEN_1022&DEV_43B6&REV_*"}},
		  {{}, {L"HKR", DEVICE, L"PRDTSplit", APPEND, L"VEN_1022&DEV_43B7&REV_*"}},
		  {{}, {L"HKR", DEVICE, L"PRDTSplit", APPEND, L"VEN_1022&DEV_43B8&REV_*"}},
		  {{}, {L"HKR", DEVICE, L"PRDTSplit", APPEND, L"VEN_1022&DEV_43C8&REV_*"}}},
		 SERVICE},
		{L"client_sku_values",
		 Context::REGISTRY,
		 Context::SERVICE,
		 {{{}, {L"HKR", L"Parameters", L"IoLatencyCap", DWORD_TYPE, L"500"}}},
		 SERVICE},
		{L"storahci_EventLog_Inst",
		 Context::EVENT_LOG,
		 Context::EVENT_LOG,
		 {{L"AddReg", {L"storahci_EventLog_AddReg"}}},
		 SERVICE},
		{L"storahci_EventLog_AddReg",
		 Context::REGISTRY,
		 Context::EVENT_LOG,
		 {{{},
		   {L"HKR", L"", L"EventMessageFile", L"0x20000", L"%SystemRoot%\\System32\\IoLogMsg.dll"}},
		  {{}, {L"HKR", L"", L"TypesSupported", DWORD_TYPE, L"7"}}},
		 SERVICE},
		{AHCI_POWER_SECTIONS[0],
		 Context::POWER_SETTING,
		 Context::POWER_SETTING,
		 {},
		 AHCI_INSTALL_SECTION,
		 L"{0B2D69D7-A2A1-449C-9680-F91C70521C60}"},
		{AHCI_POWER_SECTIONS[1],
		 Context::POWER_SETTING,
		 Context::POWER_SETTING,
		 {},
		 AHCI_INSTALL_SECTION,
		 L"{DAB60367-53FE-4FBC-825E-521D069D2456}"},
	} ; // 元選択節の全作用と、その節が到達する参照先です

	const auto error =
		// 元行の全fieldを確認します
		verifyInboxSections( state, ahci, sections, true) ;
	// 不正又は欠落した除外からIDを取り出しません
	if( error != 0U) {
		return error ;
	}

	// 全除外を元配布の各IDへ照合し、同じ機器に重なる先祖・子孫の指定も保留します
	for( const auto &effect : state.result.effects) {
		// 検査済みの同文書、基本節、単一IDの元行だけを読み出します
		if( effect.source.document == ahci && effect.source.context == Context::DEVICE &&
		   same( effect.row.key, L"ExcludeId") && std::ranges::any_of( ids, [&]( const auto &id) {
			   return sameHardwareIdBranch( id, effect.row.values.front()) ;
		   })) {
			return rejected( state, SystemInfDiagnosticStage::DIRECTIVE) ;
		}
	}

	return 0U ;
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
 * @brief Serialのイベント資源を、許されたWindows相対位置を変えずにmodule検査へ渡します
 * @param[in] value REG_EXPAND_SZの区切り間にある元文字列全体です
 * @param[in] expected %SystemRoot%から始まる固定のシステム資源名です
 * @return 成立時は元の一資源を借用します。不正な位置や環境変数の場合は空です
 * @note SetupAPIは原INFの二重%を一重へ戻します。返却値の%を再度解釈せず、絶対位置のWindows所有はmodule側で検査します
 */
//------------------------------------------------------------------------------
std::wstring_view serialEventResource( std::wstring_view value, std::wstring_view expected)
{
	constexpr std::wstring_view ROOT = L"%SystemRoot%" ;	// SetupAPIから返る展開用の一変数です
	const auto suffix = expected.substr( ROOT.size()) ;		// 役割ごとのSystem32からの完全な位置です
	// 正式な一重%の変数と完全な後続位置だけを、環境変数の探索なしで渡します
	if( same( value, expected)) {
		return value ;
	}

	// 既に解決済みのDOS絶対位置は他のrootへ差し替えず、そのまま実体検査へ渡します
	return value.size() > suffix.size() && validInfDependencyPath( value, true) &&
				   same( value.substr( value.size() - suffix.size()), suffix)
			   ? value
			   : std::wstring_view{} ;
}
//------------------------------------------------------------------------------
/**
 * @brief 選択PortsのHWフィルターとSerialイベントログを、同原サービスと実ファイルへ結びます
 * @param[in,out] state 全作用と同じ原文のmodule検査、共有参照予算です
 * @param[in] effect Windows標準Portsのprofileでscope、所有者、型、全fieldを確認したHKR行です
 * @return 同文書の関係と全資源の確認で0、未知の参照または最初の実体検査errorです
 * @note 元のREG_EXPAND_SZを保存し、二つの参照だけを個別に検査します。registryやSCMを変更しません
 */
//------------------------------------------------------------------------------
NativeError verifyMsPortsRegistry( EffectState &state, const SystemInfEffect &effect)
{
	const auto &values = effect.row.values ;	// 元選択で型を照合済みの五fieldです
	// HWの単一UpperFiltersは同じ文書が明示宣言したSerenumを指定しなければなりません
	if( effect.source.scope == SystemInfContext::HARDWARE) {
		return declaration( state, effect.source.document, L"AddService", values[4])
				   ? 0U
				   : rejected( state, SystemInfDiagnosticStage::HARDWARE) ;
	}

	// TypesSupportedの元DWORDと有効bitは全行の型検査で消費しています
	if( same( values[2], L"TypesSupported")) {
		return 0U ;
	}

	const std::wstring_view data	= values[4] ;			// このイベントログのREG_EXPAND_SZ全体です
	const auto				divider = data.find( L';') ;	// 固定DLLと同サービスSYSの間の一区切りです
	// 追加、欠落、空の資源を正しい二ファイルに縮約しません
	if( divider == data.npos || divider == 0U || divider + 1U == data.size() ||
	   data.find( L';', divider + 1U) != data.npos) {
		return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
	}

	const std::array resources{
		serialEventResource( data.substr( 0U, divider), L"%SystemRoot%\\System32\\IoLogMsg.dll"),
		serialEventResource(
			data.substr( divider + 1U),
			L"%SystemRoot%\\System32\\drivers\\serial.sys")} ;	// Windows共通メッセージとSerial固有のメッセージの順です
	// Serialの元AddServiceが宣言する実体と、第二資源のSYS名を結びます
	if( resources[0].empty() || resources[1].empty() ||
	   !serviceModule( state, effect.source.document, effect.source.owner, resources[1])) {
		return rejected( state, SystemInfDiagnosticStage::EVENT_PUBLISHER) ;
	}

	// 両方の実体の署名・原位置を同文書で検査し、最初の不足と参照予算を保持します
	for( const auto path : resources) {
		const auto error =
			verifyModule( state, effect.source.document, path,
						 SystemInfModuleRole::EVENT_RESOURCE) ;	// 対応する元APIの結果です
		// 片方の成立でメッセージファイル列全体を認定しません
		if( error != 0U) {
			return error ;
		}
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 正規仮想Wi-Fiバスの選択節を限定し、上位フィルターの置換を識別する
 * @param[in,out] state 元の到達節、各行と診断を保持する同期検査です
 * @return 全作用の一致または対象なしで0、余分な節・作用・不一致は拒否HRESULTです
 * @note 実コピー元、サービス構成と端末のフィルター値は別途検査します
 */
//------------------------------------------------------------------------------
NativeError verifyWifiBusEffects( EffectState &state)
{
	const auto document = state.api.wifiBusInboxDocument ;	// 同梱と署名を確認した元文書です
	// 仮想Wi-Fiバスを選択しない経路には既存規則を適用します
	if( document == 0U) {
		return 0U ;
	}

	using Context = SystemInfContext ;
	// 同原文書に到達した節名を選択し、型と全行は規則との比較で検査します
	const auto reached = [&]( std::wstring_view name) {
		return std::ranges::any_of( state.sections, [&]( const auto &section) {
			return section.document == document && same( section.name, name) ;
		}) ;
	} ;
	const bool modernBase = reached( L"VWiFiBus") ;							// 現行の基本節を選んだ場合です
	const bool legacyHw = reached( L"VWiFiBus.PnPFilterRegistration.HW") ;	// 旧HW節に到達した場合です
	const InboxSectionRule required[] = {
		{modernBase ? L"VWiFiBus" : L"VWiFiBus.CopyFiles",
		 Context::DEVICE,
		 Context::DEVICE,
		 {{L"CopyFiles", {L"VWiFiBus.CopyFilesInternal", L"CopyKMDriver"}}}},
		{legacyHw ? L"VWiFiBus.PnPFilterRegistration.HW" : L"VWiFiBus.HW",
		 Context::HARDWARE,
		 Context::HARDWARE,
		 {{L"AddReg", {L"PnPFilterRegistration"}}}},
		{L"PnPFilterRegistration",
		 Context::REGISTRY,
		 Context::HARDWARE,
		 {{L"", {L"HKR", L"", L"UpperFilters", L"0x00010000", L"vwifibus"}}}},
		{L"VWiFiBus.Services",
		 Context::SERVICES,
		 Context::SERVICES,
		 {{L"AddService", {L"vwifibus", L"", L"vwifibus_Service_Inst"}}}},
		{L"vwifibus_Service_Inst",
		 Context::SERVICE,
		 Context::SERVICE,
		 {{L"DisplayName", {}, InboxTail::DISPLAY_NAME},
		  {L"ServiceType", {L"1"}},
		  {L"StartType", {L"3"}},
		  {L"ErrorControl", {L"1"}},
		  {L"ServiceBinary", {}, InboxTail::WIFI_BUS_BINARY},
		  {L"Description", {}, InboxTail::DISPLAY_NAME}},
		 L"vwifibus"},
	} ; // 各元節とその所有先に必要な全行です
	const InboxSectionRule legacyWrapper{
		L"VWiFiBus.PnPFilterRegistration",
		Context::HARDWARE,
		Context::HARDWARE,
		{{L"Needs", {L"VWiFiBus.PnPFilterRegistration.HW"}}}} ;	// 旧名は同じ文書のHW節に委譲します
	const InboxSectionRule interfaces{
		L"VWiFiBus.Interfaces", Context::INTERFACES, Context::INTERFACES, {}} ;	// 元の空付随節です
	std::vector<InboxSectionRule> rules{										// 各元ルールの行にはこの検査中だけ借用します
										std::begin( required), std::end( required)} ;
	// 旧名からの到達も別のレジストリ作用へ転送しません
	if( reached( legacyWrapper.name)) {
		// 現行HW節と旧ラッパーの組み合わせでは所定の委譲先を欠いています
		if( !legacyHw) {
			return rejected( state, SystemInfDiagnosticStage::REFERENCE) ;
		}

		rules.push_back( legacyWrapper) ;
	}

	// 元選択からインターフェース付随節を参照した場合は空の実在を確認します
	if( reached( interfaces.name)) {
		rules.push_back( interfaces) ;
	}

	const auto error = verifyInboxSections( state, document, rules) ;	// 選択節と全作用の照合結果です
	// 上位フィルターの元行と所有先が確定した場合だけ文書を記録します
	if( error == 0U) {
		state.result.wifiBusFilterDocument = document ;
	}

	return error ;
}
//------------------------------------------------------------------------------
/**
 * @brief WinUSBを関連サービスとして使用する三選択節と全作用を同じ同梱INFへ結びます
 * @param[in,out] state 同期中に列挙した元の選択節、行及び固定診断を保持する検査です
 * @return 対象なし又は全作用一致で0、欠落・追加・別所有先では拒否HRESULTです
 * @note コピーとサービスSYSの実体はNativeLoaderが確認し、互換レジストリ値は同じサービスへ結びます
 */
//------------------------------------------------------------------------------
NativeError verifyWinUsbInboxEffects( EffectState &state)
{
	const auto document = state.api.winUsbInboxDocument ;	// 署名とStoreの同一性を確認した元文書です
	// 同梱WinUSBを選択しない経路には既存規則を適用します
	if( document == 0U) {
		return 0U ;
	}

	using Context				   = SystemInfContext ;
	const InboxSectionRule rules[] = {
		{L"WINUSB.NT",
		 Context::DEVICE,
		 Context::DEVICE,
		 {{L"CopyFiles", {L"WINUSB.CopyFiles"}}, {L"AddReg", {L"WINUSB.AddReg"}}}},
		{L"WINUSB.NT.HW", Context::HARDWARE, Context::HARDWARE, {}},
		{L"WINUSB.NT.Services",
		 Context::SERVICES,
		 Context::SERVICES,
		 {{L"AddService", {L"WINUSB", L"2", L"WINUSB.AddService"}}}},
		{L"WINUSB.AddService",
		 Context::SERVICE,
		 Context::SERVICE,
		 {{L"DisplayName", {}, InboxTail::DIRECT_DISPLAY_TEXT},
		  {L"Description", {}, InboxTail::DIRECT_DISPLAY_TEXT},
		  {L"ServiceType", {L"1"}},
		  {L"StartType", {L"3"}},
		  {L"ErrorControl", {L"1"}},
		  {L"ServiceBinary", {}, InboxTail::SERVICE_BINARY, L"winusb.sys"}},
		 L"WINUSB"},
		{L"WINUSB.AddReg",
		 Context::REGISTRY,
		 Context::DEVICE,
		 {{L"", {L"HKR", L"", L"DevLoader", L"", L"*ntkern"}},
		  {L"", {L"HKR", L"", L"NTMPDriver", L"", L"winusb.sys"}}}},
	} ; // 関連サービスの選択だけに必要な元節と全行です
	return verifyInboxSections( state, document, rules) ;
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
	// 仮想Wi-Fiバスの唯一の置換行と所有先は正規文書の全作用から検査済みです
	if( state.result.wifiBusFilterDocument != 0U &&
	   effect.source.document == state.result.wifiBusFilterDocument) {
		return 0U ;
	}

	// 署名済みSDバス文書では、同じ全行を所有scope、操作flag、全byteまで事前に照合しています
	if( state.api.sdBusInboxDocument != 0U &&
	   effect.source.document == state.api.sdBusInboxDocument) {
		return 0U ;
	}

	// 元Portsの全行と所有scopeを照合した後、上位フィルターとログの実参照だけを解決します
	if( state.api.msPortsInboxDocument != 0U &&
	   effect.source.document == state.api.msPortsInboxDocument) {
		return verifyMsPortsRegistry( state, effect) ;
	}

	// 専用プロファイルで文書・元節の全行と所有scopeを確認済みです
	const bool nvme = state.api.storNvmeInboxDocument != 0U &&
					  (effect.source.document == state.api.storNvmeInboxDocument ||
					   effect.source.document == state.api.pciNvmeInboxDocument) ;
	// 元文書で標準AHCIを選択した場合だけ専用検査する
	const bool ahci = state.api.storAhciInboxDocument != 0U &&
					  effect.source.document == state.api.storAhciInboxDocument ;
	// 元全registry行はストレージの各所有scopeの検査で成立済みです
	if( nvme || ahci) {
		// 元イベントログが指定する唯一のWindows資源は実ファイルへも結びます
		if( effect.source.scope == SystemInfContext::EVENT_LOG &&
		   same( effect.row.values[2], L"EventMessageFile")) {
			return verifyModule( state, effect.source.document, effect.row.values[4],
								SystemInfModuleRole::EVENT_RESOURCE) ;
		}

		return 0U ;
	}

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

		// ETWのHKLMは同event-log owner単位で全26行を要求します。PortsのHKRは元サービスに結合済みです
		if( effect.source.scope == SystemInfContext::EVENT_LOG && same( v[0], L"HKLM")) {
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
 * @brief 同じ署名文書の選択節が参照した範囲型の電源設定を読み取ります
 * @param[in] selected 同じ文書に属する元DDInstall又はHW節です
 * @param[in] api 元の署名文書だけを読む同期操作と累積参照数です
 * @param[out] settings すべての参照が成立した場合だけ元順で保持します。失敗時は空です
 * @return 元読取の成功0、未対応・重複設定・予算超過又は元読取のHRESULTです
 * @note 各参照は予算に数えます。同じ節の再参照は一件へまとめ、端末への作用は別に評価します
 */
//------------------------------------------------------------------------------
NativeError readSelectedRangedStoragePowerSettings( const SystemInfSection				  &selected,
												   const SystemInfEffectApi				  &api,
												   std::vector<RangedStoragePowerSetting> &settings)
{
	settings.clear() ;
	constexpr std::size_t MAXIMUM_REFERENCES = 4096U ;	// 元依存と同じ参照予算
	// 元文書の選択コンテキスト以外の節へ読取りを広げません
	if( !api.read || selected.document == 0U || selected.name.empty() || !selected.owner.empty() ||
	   selected.context != selected.scope ||
	   (selected.context != SystemInfContext::DEVICE &&
		selected.context != SystemInfContext::HARDWARE) ||
	   api.graphReferences > MAXIMUM_REFERENCES) {
		return E_INVALIDARG ;
	}

	std::vector<SystemInfRow> selectedRows ;								// 適用候補の同じ選択節だけを読む
	auto					  error = api.read( selected, selectedRows) ;	// 元APIの診断を保持します
	// 読めない原文を電源設定なしへ変換しません
	if( error != 0U) {
		return error ;
	}

	std::vector<RangedStoragePowerSetting> made ;	// 全成立前は呼出し元へ出さない結果
	auto references = api.graphReferences ;			// 確認済みの依存関係と今回の参照の合計
	// 元選択節の全AddPowerSettingから同じ文書内の参照先だけをたどります
	for( const auto &row : selectedRows) {
		// 他の作用は個別の検査へ渡し、この読取りの成功で承認しません
		if( !same( row.key, L"AddPowerSetting")) {
			continue ;
		}

		// 明示の空行を参照なしとして扱いません
		if( row.values.empty()) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		// 再参照も予算に含め、同一設定へ収束する節は一回だけ読みます
		for( const auto &name : row.values) {
			// 別の文書やpathへ参照を解釈しません
			if( !simpleName( name, 254U) || same( name, selected.name)) {
				return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
			}

			// 既存の全依存と今回の参照が同じ上限を超える場合は打ち切ります
			if( references == MAXIMUM_REFERENCES) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			++references ;
			// 同文書の同一節は重複した設定にしません
			if( std::ranges::any_of(
				   made, [&]( const auto &item) { return same( item.source.name, name) ; })) {
				continue ;
			}

			SystemInfSection source{selected.document, name, SystemInfContext::POWER_SETTING,
									selected.scope, selected.name} ;	// 同じ選択を所有元とする参照
			std::vector<SystemInfRow> rows ;							// 同じ節の原行
			error = api.read( source, rows) ;
			// 不在を空の既定値で補完しません
			if( error != 0U) {
				return error ;
			}

			std::array<const SystemInfRow *, RANGED_POWER_ROW_COUNT>
				ordered{} ;	// 節内の正確な元行位置
			// 既定値の不完全な節や未知行を読み捨てません
			if( rows.size() != ordered.size()) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			// 元行位置を一意に並べ、同じ位置を上書きしません
			for( const auto &settingRow : rows) {
				// 重複・過大な位置は元範囲の成立にしません
				if( settingRow.ordinal >= ordered.size() || ordered[settingRow.ordinal]) {
					return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
				}

				ordered[settingRow.ordinal] = &settingRow ;
			}

			RangedStoragePowerSetting power ;	// 一節からだけ読み取る候補
			// 異なる節から同じ設定GUIDを上書きする場合は保留します
			if( !parseRangedStoragePowerSetting( ordered, power) ||
			   std::ranges::any_of(
				   made, [&]( const auto &item) { return same( item.setting, power.setting) ; })) {
				return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
			}

			power.source = std::move( source) ;
			made.push_back( std::move( power)) ;
		}
	}

	settings = std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名確認済みの標準NVMeの実選択とPCI依存節を照合して電源宣言を読む
 * @param[in] api 元のNVMe・PCI文書の異なるIDと同じ原バイトに対する同期の行読取り
 * @param[out] settings 全到達節と四つの電源宣言が成立した時だけ保持する元値。失敗時は空
 * @return 元作用と電源宣言が一致すれば0、元読取りや範囲の不成立はHRESULT
 * @note 元の署名、Needsの所有先の一意性、コピー実体と現在の構成は呼出側で照合する
 */
//------------------------------------------------------------------------------
NativeError readVerifiedNvmeInboxPowerSettings( const SystemInfEffectApi				  &api,
											   std::vector<RangedStoragePowerSetting> &settings)
{
	settings.clear() ;
	const auto nvme = api.storNvmeInboxDocument ;	// 原署名を確認したNVMe文書
	const auto pci	= api.pciNvmeInboxDocument ;	// 別に原署名を確認したPCI文書
	// 同じ署名元と別の文書の役割を取り違えない
	if( !api.read || nvme == 0U || pci == 0U || nvme == pci || api.graphReferences > 4096U) {
		return E_INVALIDARG ;
	}

	using Context = SystemInfContext ;	// 選択節と依存節の実文脈
	const SystemInfSection selected{nvme,
									std::wstring( NVME_INSTALL_SECTION),
									Context::DEVICE,
									Context::DEVICE,
									{}} ;	// 対応する実DDInstall
	EffectState			   state{api} ;		// 元の選択節と到達する全行の一時所有
	state.references = api.graphReferences ;
	state.sections	 = {selected,
						{nvme, L"Stornvme_Inst.HW", Context::HARDWARE, Context::HARDWARE, {}},
						{nvme, L"Stornvme_Inst.Services", Context::SERVICES, Context::SERVICES, {}},
						{pci, L"PciForceSBR.HW", Context::HARDWARE, Context::HARDWARE, {}}} ;
	auto error		 = collectEffects( state) ;	// 選択と確定済み依存節からの全到達行
	// 収集と同じ原規則で参照の種類、所有先と全行を照合する
	if( error == 0U) {
		error = verifyNvmeInboxEffects( state) ;
	}

	// 元作用が成立した時だけ同じ署名元から型付きの電源宣言を取る
	return error == 0U ? readSelectedRangedStoragePowerSettings( selected, api, settings) : error ;
}

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

	const std::array nvmeDocuments{
		api.storNvmeInboxDocument,
		api.pciNvmeInboxDocument} ;	// 同じ選択を構成する別々の署名確認済み文書です
	// 片方のIDだけを有効にしたり、別の収集選択のIDを流用したりしません
	if( (nvmeDocuments[0] == 0U) != (nvmeDocuments[1] == 0U) ||
	   (nvmeDocuments[0] != 0U &&
		(nvmeDocuments[0] == nvmeDocuments[1] || std::ranges::any_of( nvmeDocuments, [&]( auto id) {
			 return id == api.sdBusInboxDocument || id == api.msPortsInboxDocument ;
		 })))) {
		return E_INVALIDARG ;
	}

	// AHCIの文書には別の収集プロファイルの証拠を流用しません
	if( api.storAhciInboxDocument != 0U &&
	   (api.storAhciInboxDocument == api.sdBusInboxDocument ||
		api.storAhciInboxDocument == api.msPortsInboxDocument ||
		std::ranges::find( nvmeDocuments, api.storAhciInboxDocument) != nvmeDocuments.end())) {
		return E_INVALIDARG ;
	}

	// 別の同梱INFに結んだ作用の許可を仮想Wi-Fiバスへ流用しません
	if( api.wifiBusInboxDocument != 0U &&
	   (api.wifiBusInboxDocument == api.sdBusInboxDocument ||
		api.wifiBusInboxDocument == api.msPortsInboxDocument ||
		api.wifiBusInboxDocument == api.storAhciInboxDocument ||
		std::ranges::find( nvmeDocuments, api.wifiBusInboxDocument) != nvmeDocuments.end())) {
		return E_INVALIDARG ;
	}

	// 別の同梱依存で確認した文書へWinUSB固有の作用を付与しません
	if( api.winUsbInboxDocument != 0U &&
	   (api.winUsbInboxDocument == api.sdBusInboxDocument ||
		api.winUsbInboxDocument == api.msPortsInboxDocument ||
		api.winUsbInboxDocument == api.storAhciInboxDocument ||
		api.winUsbInboxDocument == api.wifiBusInboxDocument ||
		std::ranges::find( nvmeDocuments, api.winUsbInboxDocument) != nvmeDocuments.end())) {
		return E_INVALIDARG ;
	}

	// 専用のシリアル列挙検査には同じ署名済みMS Ports文書が必要
	if( api.serialEnumeratorOnly && api.msPortsInboxDocument == 0U) {
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
	// 収集の限定型を使う前に、該当する原文の選択節・参照・作用の集合を照合します
	if( error == 0U) {
		error = verifySdBusEffects( state) ;
	}

	// 元Ports収集文書だけが、通常のサービス規則と異なるSerialとSerenumの作用を持てます
	if( error == 0U && api.msPortsInboxDocument != 0U) {
		error = verifyMsPortsEffects( state) ;
	}

	// 収集で確認したNVMeとPCIを同じ選択の全作用として確定します
	if( error == 0U) {
		error = verifyNvmeInboxEffects( state) ;
	}

	// 同じ署名済みAHCI文書の全作用を個別の原scopeへ固定します
	if( error == 0U) {
		error = verifyAhciInboxEffects( state) ;
	}

	// 仮想Wi-Fiバスは同じ文書で選択された元作用の集合だけを採用します
	if( error == 0U) {
		error = verifyWifiBusEffects( state) ;
	}

	// WinUSBの元文書にある同じ三節とその参照先を一組として確定します
	if( error == 0U) {
		error = verifyWinUsbInboxEffects( state) ;
	}

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

//------------------------------------------------------------------------------
/** @brief 既存SYSTEM、資格付き仮想Wi-Fiバスとstorageの現在サービス読取を区別します */
enum class ServiceEvidencePurpose {
	/// 旧SYSTEMのstart3/error1/31文字という限定範囲です
	SYSTEM,
	/// 同梱仮想Wi-Fiバスの説明と展開前の登録値も保持します
	WIFI_BUS,
	/// storageのstart0/1/3/error0..3/256文字という現kernel観測です
	STORAGE
} ;

//------------------------------------------------------------------------------
/**
 * @brief SCMの応答バッファ内に収まる一つの文字列を複製します
 * @param[in] buffer SCMが書き込んだ同期応答の所有領域です
 * @param[in] value 同応答が返した文字列位置です。nullは空値として扱います
 * @param[out] out 成功時は最大4096文字の全値、失敗時は空です
 * @return 範囲、整列と終端が成立する文字列又はnullの場合trueです
 */
//------------------------------------------------------------------------------
static bool copyServiceEvidenceText( std::span<const std::byte> buffer, const wchar_t *value,
									std::wstring &out)
{
	out.clear() ;
	// optionalなnull文字列は空として保持します
	if( !value) {
		return true ;
	}

	const auto start = reinterpret_cast<std::uintptr_t>( value) ;			// SCMの返した位置です
	const auto first = reinterpret_cast<std::uintptr_t>( buffer.data()) ;	// 応答の先頭位置です
	// Win32応答のポインターを参照する前に、その範囲と文字の整列を確認します
	if( start < first || start - first >= buffer.size() || start % alignof( wchar_t) != 0U) {
		return false ;
	}

	const auto capacity =
		(buffer.size() - (start - first)) / sizeof( wchar_t) ;	// 安全に読める文字数です
	const auto limit =
		value + (std::min)( capacity, std::size_t{4097U}) ;	// 許容する文字と終端の上限です
	const auto end = std::find( value, limit, L'\0') ;		// 完全値の終端です
	// 応答外又は許容上限を超えた文字列を切り詰めません
	if( end == limit) {
		return false ;
	}

	out.assign( value, end) ;
	return true ;
}
//------------------------------------------------------------------------------
/**
 * @brief SCM応答内のMULTI_SZを元順の文字列へ複製します
 * @param[in] buffer 同じSCM照会が書き込んだ領域です
 * @param[in] itemStart 元文字列位置です。nullは空集合です
 * @param[out] values 末尾まで読み取った値です。失敗時は作業値を破棄します
 * @return 全終端と上限の確認時0、不正又は容量超過時に対応するHRESULTです
 */
//------------------------------------------------------------------------------
static NativeError copyServiceEvidenceList( std::span<const std::byte> buffer,
										   const wchar_t			 *itemStart,
										   std::vector<std::wstring> &values)
{
	// 個々の値と最後の空終端を同じ応答範囲内で読みます
	while( itemStart) {
		std::wstring item ;	// 次の一値を完全に読んだ場合だけ追加します
		// 元応答内に終端がある場合だけ次の位置を計算します
		if( !copyServiceEvidenceText( buffer, itemStart, item)) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		// 空集合の場合も二重NULを確認してから完了します
		if( item.empty()) {
			const auto offset =
				reinterpret_cast<std::uintptr_t>( itemStart) -
				reinterpret_cast<std::uintptr_t>( buffer.data()) ;	// 検証済み停止位置です
			// 文字列応答から空集合の第二終端が欠けていれば拒否します
			if( values.empty() &&
			   (buffer.size() - offset < 2U * sizeof( wchar_t) || itemStart[1] != L'\0')) {
				return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
			}

			break ;
		}

		// 元集合を切り詰めずに拒否します
		if( values.size() >= 64U) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		itemStart += item.size() + 1U ;
		values.push_back( std::move( item)) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正確な一サービスの基本SCM構成を原値へ複製します
 * @param[in] service 開いた同一の構成照会ハンドルです
 * @param[in] expectedType 呼出し元が扱うカーネル又は補助サービスの固定型です
 * @param[in,out] result 元サービス名を持つ作業値です。失敗時は破棄します
 * @return 全基本構成の読取時0、元SCM診断又は不正構成のHRESULTです
 */
//------------------------------------------------------------------------------
static NativeError readServiceConfiguration( SC_HANDLE service, DWORD expectedType,
											SystemServiceEvidence &result)
{
	DWORD	   required{} ;															// 元APIが要求する全構成の受信容量です
	const auto initial = QueryServiceConfigW( service, nullptr, 0U, &required) ;	// 先に容量を得ます
	const auto sizingError = GetLastError() ;										// 容量照会の元診断です
	// 通常の有限な容量応答だけを採用します
	if( initial || sizingError != ERROR_INSUFFICIENT_BUFFER ||
	   required < sizeof( QUERY_SERVICE_CONFIGW) || required > 65536U) {
		return HRESULT_FROM_WIN32( !initial && sizingError != ERROR_INSUFFICIENT_BUFFER &&
										  sizingError != ERROR_SUCCESS
									  ? sizingError
									  : ERROR_INVALID_DATA) ;
	}

	std::vector<std::byte> buffer( required) ;	// 同期中だけ保持するSCM応答です
	// Windowsが応答先バッファ冒頭に構成型を置きます
	auto				  *config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>( buffer.data()) ;
	// 構成読取の元診断を保持します
	if( !QueryServiceConfigW( service, config, required, &required)) {
		const auto error = GetLastError() ;	// 失敗直後の元診断です
		return HRESULT_FROM_WIN32( error ? error : ERROR_INVALID_DATA) ;
	}

	result.type			= config->dwServiceType ;
	result.start		= config->dwStartType ;
	result.errorControl = config->dwErrorControl ;
	result.tag			= config->dwTagId ;
	// ポインターも文字列の一部も採用せず全原値を複製し、別型は拒否します
	if( !copyServiceEvidenceText( buffer, config->lpBinaryPathName, result.binary) ||
	   !copyServiceEvidenceText( buffer, config->lpLoadOrderGroup, result.group) ||
	   !copyServiceEvidenceText( buffer, config->lpServiceStartName, result.account) ||
	   !copyServiceEvidenceText( buffer, config->lpDisplayName, result.display) ||
	   result.type != expectedType || result.binary.empty()) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	return copyServiceEvidenceList( buffer, config->lpDependencies, result.dependencies) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 仮想Wi-FiバスのREG_SZを未展開のまま読み取ります
 * @param[in] key 固定サービスキーの読取専用ハンドルです
 * @param[in] name 呼出し元が選ぶ固定のDisplayName又はDescriptionです
 * @param[out] value 検査を通った場合に複製する、終端を除いた全登録値です
 * @return 完全な元値の読取で0、元のレジストリエラー又は不正データのHRESULTです
 */
//------------------------------------------------------------------------------
static NativeError readWifiBusRegistryText( HKEY key, const wchar_t *name, std::wstring &value)
{
	std::array<wchar_t, 4097U> buffer{} ;						// 最大4096文字と明示終端です
	DWORD					   type{} ;							// 登録値の元の種類です
	DWORD	   bytes = static_cast<DWORD>( sizeof( buffer)) ;	// 容量と実読取バイト数です
	const auto error = RegQueryValueExW( key, name, nullptr, &type,
										// Win32が文字バッファをバイトとして受け取ります
										reinterpret_cast<BYTE *>( buffer.data()), &bytes) ;
	// 不存在、容量超過、アクセス不良を別値で置換しません
	if( error != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( error) ;
	}

	// REG_SZ以外を変換せず、明示終端を含む完全なUTF-16単位だけを受理します
	if( type != REG_SZ || bytes < sizeof( wchar_t) || bytes > sizeof( buffer) ||
	   bytes % sizeof( wchar_t) != 0U) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	const auto end =
		// 元値で要求する末尾終端位置です
		buffer.begin() + bytes / sizeof( wchar_t) - 1U ;
	// 埋込み終端や欠落終端を取り除いて既知値に合わせません
	if( *end != L'\0' || std::find( buffer.begin(), end, L'\0') != end) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	value.assign( buffer.begin(), end) ;
	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 固定の仮想Wi-Fiバスについて表示名と説明の登録値、SCMの説明を取得します
 * @param[in] service 読み取り中の同じSCMサービスハンドルです
 * @param[in,out] evidence 既存構成へ追加する非公開の作業証拠です。失敗時は破棄します
 * @return 追加読取の成立時0、元SCM・registryエラー又は不正データのHRESULTです
 * @note Windowsの登録値を自前で展開せず、SCMの応答文字列を照合用に保持します
 */
//------------------------------------------------------------------------------
static NativeError readWifiBusServiceText( SC_HANDLE service, SystemServiceEvidence &evidence)
{
	HKEY	   key{} ;	// 仮想Wi-Fiバスに固定した登録キーです
	const auto opened = RegOpenKeyExW(
		HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vwifibus", REG_OPTION_OPEN_LINK,
		KEY_QUERY_VALUE, &key) ;	// 末端を別キーへ解決せず、二つの登録値だけを読みます
	// 元の固定キーを読めない場合はサービス証拠を発行しません
	if( opened != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( opened) ;
	}

	const std::unique_ptr<std::remove_pointer_t<HKEY>, decltype( &RegCloseKey)> registered{
		key, &RegCloseKey} ;	// 二つの値を同じキーから読む間だけ所有します
	auto error = readWifiBusRegistryText( registered.get(), L"DisplayName",
										 evidence.rawDisplay) ;	// 元表示名です
	// 表示名の元エラーを保ち、成功時だけ続けて説明を読みます
	if( error == 0U) {
		error = readWifiBusRegistryText( registered.get(), L"Description", evidence.rawDescription) ;
	}

	// 二つの登録値が揃わなければSCMの値だけを採用しません
	if( error != 0U) {
		return error ;
	}

	// 追加のSCM照会が未知の間接説明を展開する前に、既知の同梱参照へ限定します
	if( evidence.rawDescription.starts_with( L'@') &&
	   evidence.rawDescription != WIFI_BUS_DESCRIPTION) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	// QueryServiceConfig2Wが定める応答上限と構造体の整列を確保します
	alignas( SERVICE_DESCRIPTIONW) std::array<BYTE, 8192U> buffer{} ;
	DWORD required{} ;	// 容量不足時にSCMが返す必要バイト数です
	// 上限を超えて再取得せず、SCM照会失敗を保持します
	if( !QueryServiceConfig2W( service, SERVICE_CONFIG_DESCRIPTION, buffer.data(),
							 static_cast<DWORD>( buffer.size()), &required)) {
		const auto queryError = GetLastError() ;	// API失敗直後の元診断です
		return HRESULT_FROM_WIN32( queryError ? queryError : ERROR_INVALID_DATA) ;
	}

	SERVICE_DESCRIPTIONW config{} ;	// SCMが返した説明文字列へのポインターを持ちます
	std::memcpy( &config, buffer.data(), sizeof( config)) ;
	// 欠落や不正なポインターによる説明を成立と扱いません
	if( !copyServiceEvidenceText( std::as_bytes( std::span{buffer}), config.lpDescription,
								evidence.description) ||
	   evidence.description.empty()) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元用途ごとの条件で正確なサービスの安定構成とSDを読みます
 * @param[in] name SYSTEM最大31文字又はstorage最大256文字の元名です
 * @param[out] evidence 全成立時だけ原configとSDです。失敗時は空です
 * @param[in] purpose 元reader用途です。説明と登録値は仮想Wi-Fiバス用途でだけ取得します
 * @return 全読取/保護成立0、正式不存在又は元SCM/SD診断のHRESULTです
 * @note QUERY_CONFIG/READ_CONTROLだけで開き、SCM/registry/driverを変更しません
 */
//------------------------------------------------------------------------------
static NativeError readServiceEvidence( std::wstring_view name, SystemServiceEvidence &evidence,
									   const ServiceEvidencePurpose purpose)
{
	evidence = {} ;
	// 正確な一service以外を探索しません
	if( !simpleName( name, purpose == ServiceEvidencePurpose::STORAGE ? 256U : 31U)) {
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

	SystemServiceEvidence result ;	// 全成立前は呼出し元へ出しません
	result.name = serviceName ;
	const auto configError =
		// 元基本構成です
		readServiceConfiguration( service.get(), SERVICE_KERNEL_DRIVER, result) ;
	// 現行カーネルの型又は元構成が読めない場合は同じ診断で停止します
	if( configError != 0U) {
		return configError ;
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
		(purpose == ServiceEvidencePurpose::STORAGE ? validateStorageServiceEvidence( result)
													: validateSystemServiceEvidence( result)) ;
	// 元の不正/不一致又は不足を成功へ補完しません
	if( validated != 0U) {	// 不明/不一致の元値を成功や別scopeへ補完しません
		return validated ;
	}

	// 同梱文書と結合したサービスだけで展開前と展開後の文字列を追加します
	if( purpose == ServiceEvidencePurpose::WIFI_BUS) {
		const auto error = readWifiBusServiceText( service.get(), result) ;	// 追加の読取結果です
		// 全文字列を保持できない場合は元証拠を公開しません
		if( error != 0U) {
			return error ;
		}
	}

	evidence = std::move( result) ;
	return 0U ;
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
	return readServiceEvidence( name, evidence, ServiceEvidencePurpose::SYSTEM) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定の仮想Wi-Fiバスサービスの安定構成と表示名・説明の登録値を読み取ります
 * @param[out] evidence 全読取と保護の成立時だけの構成・SD・登録文字列です。失敗時は空です
 * @return 読取と保護の成立時0、元OSエラー又は不正構成のHRESULTです
 * @note 同梱文書と結合したサービスに使い、SCMと登録値を変更しません
 */
//------------------------------------------------------------------------------
NativeError readWifiBusServiceEvidence( SystemServiceEvidence &evidence)
{
	return readServiceEvidence( WIFI_BUS_SERVICE, evidence, ServiceEvidencePurpose::WIFI_BUS) ;
}

//------------------------------------------------------------------------------
/**
 * @brief exact storage serviceの原config/全SDだけを読取り専用で固定します
 * @param[in] name 同原選択又はDependenciesが示す最大256文字のservice名です
 * @param[out] evidence 全成立時だけ原値です。失敗/正式不存在時空です
 * @return 元読取/保護成立0、正式不存在又は元SCM/SDのHRESULTです
 * @note BOOT0/SYSTEM1/DEMAND3の原値を保持し、旧SYSTEM限定policyを変更しません
 */
//------------------------------------------------------------------------------
NativeError readStorageServiceEvidence( std::wstring_view name, SystemServiceEvidence &evidence)
{
	return readServiceEvidence( name, evidence, ServiceEvidencePurpose::STORAGE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief SCMの可変応答に含まれる配列を同じバッファへ閉じます
 * @tparam T SCMが定める配列の要素型です
 * @param[in] buffer 同期読取で所有する全応答領域です
 * @param[in] values SCMが返した配列位置です
 * @param[in] count SCMが返した要素数です
 * @return 整列と全要素範囲が成立する配列です。不成立又は件数0では空です
 */
//------------------------------------------------------------------------------
template <typename T>
static std::span<const T> boundedServiceConfigArray( std::span<const BYTE> buffer, const T *values,
													std::size_t count)
{
	const auto first = reinterpret_cast<std::uintptr_t>( buffer.data()) ;	// 同応答の先頭です
	const auto start = reinterpret_cast<std::uintptr_t>( values) ;			// SCMが返した参照位置です
	// 参照や乗算より先に、整列済みの全要素が同じバッファに収まることを確認します
	if( count == 0U || start < first || start - first >= buffer.size() || start % alignof( T) != 0U ||
	   count > (buffer.size() - (start - first)) / sizeof( T)) {
		return {} ;
	}

	return {values, count} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 補助サービスのトリガーを借用ポインターから元順の所有値へ移します
 * @param[in] buffer 同じトリガー照会の全応答領域です
 * @param[in] source SCMのトリガー応答の先頭構成です
 * @param[out] triggers 全トリガーの元作用とデータです。失敗時は作業値を破棄します
 * @return 全応答が成立時0、未知の予約値又は領域不正時はHRESULTです
 */
//------------------------------------------------------------------------------
static NativeError copyServiceTriggers( std::span<const BYTE>						buffer,
									   const SERVICE_TRIGGER_INFO				   &source,
									   std::vector<AuxiliaryStorageServiceTrigger> &triggers)
{
	const auto records =
		// 元配列です
		boundedServiceConfigArray( buffer, source.pTriggers, source.cTriggers) ;
	// 予約値又は元配列の不足を空集合に変換しません
	if( source.pReserved || records.size() != source.cTriggers) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	// 同じSCM応答の全トリガーを元順に保持します
	for( const auto &record : records) {
		AuxiliaryStorageServiceTrigger trigger ;	// 一つのトリガーを最後まで読む作業値です
		trigger.type   = record.dwTriggerType ;
		trigger.action = record.dwAction ;
		// サブタイプを省略していなければ同じバッファ内のGUIDだけを複製します
		if( record.pTriggerSubtype) {
			const auto guid =
				// 唯一の元GUIDです
				boundedServiceConfigArray( buffer, record.pTriggerSubtype, 1U) ;
			// 元GUIDの境界を確認できなければ不成立です
			if( guid.empty()) {
				return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
			}

			auto &subtype = trigger.subtype.emplace() ;	// 同GUIDの全バイトを所有します
			static_assert( sizeof( GUID) == 16U) ;
			std::ranges::copy( std::as_bytes( guid), subtype.begin()) ;
		}

		const auto data =
			// 元条件です
			boundedServiceConfigArray( buffer, record.pDataItems, record.cDataItems) ;
		// 元条件の一部を捨ててトリガーを受理しません
		if( data.size() != record.cDataItems) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		// 全条件の元種別とバイト列を同じ順序で記録します
		for( const auto &item : data) {
			const auto bytes = std::as_bytes(
				// 元条件値です
				boundedServiceConfigArray( buffer, item.pData, item.cbData)) ;
			// 一部のバイトだけで完全な条件を表現しません
			if( bytes.size() != item.cbData) {
				return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
			}

			trigger.data.push_back( {item.dwDataType, {bytes.begin(), bytes.end()}}) ;
		}

		triggers.push_back( std::move( trigger)) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 基本SCM構成以外で既存サービスに残る動作・権限・説明を読みます
 * @param[in] service 同じサービスの構成照会ハンドルです
 * @param[in,out] snapshot 基本構成を含む作業観測です。失敗時は破棄します
 * @return 全追加構成の読取時0、元SCM診断又は不正応答のHRESULTです
 */
//------------------------------------------------------------------------------
static NativeError readAuxiliaryStorageServiceOptions( SC_HANDLE						   service,
													  AuxiliaryStorageServiceSnapshot &snapshot)
{
	// SCMが規定する応答上限です
	alignas( std::max_align_t) std::array<BYTE, 8192U> buffer{} ;
	std::span<const BYTE> response ;	// この照会が返した応答だけを次の解析へ渡します
	const auto			  query = [&]( DWORD level, auto &value) -> NativeError {
		   DWORD required{} ;	// SCMが報告する当該応答容量です
		   buffer.fill( 0U) ;
		   // 元SCM診断を保持し、同じ照会を別の権限や大きい容量で再試行しません
		   if( !QueryServiceConfig2W( service, level, buffer.data(), static_cast<DWORD>( buffer.size()),
											&required)) {
			   const auto error = GetLastError() ;	// 失敗直後の元診断です
			   return HRESULT_FROM_WIN32( error ? error : ERROR_INVALID_DATA) ;
		   }

		   // 元APIが成功時にも容量を報告する場合、その範囲を越えて解析しません
		   if( required != 0U && (required < sizeof( value) || required > buffer.size())) {
			   return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		   }

		   response = std::span<const BYTE>{buffer}.first( required == 0U ? buffer.size() : required) ;
		   std::memcpy( &value, buffer.data(), sizeof( value)) ;
		   return 0U ;
	} ; // 同期中だけ応答バッファを借用します。参照付き応答は次回照会前に複製します

	SERVICE_DELAYED_AUTO_START_INFO delayed{} ;		// 遅延自動開始の元指定です
	SERVICE_FAILURE_ACTIONS_FLAG	failureFlag{} ;	// 非クラッシュ障害時の回復条件です
	SERVICE_SID_INFO				sid{} ;			// サービスSID種別です
	SERVICE_PRESHUTDOWN_INFO		preshutdown{} ;	// 前停止通知の元タイムアウトです
	SERVICE_PREFERRED_NODE_INFO		node{} ;		// 優先プロセッサーノードと指定の有無です
	SERVICE_LAUNCH_PROTECTED_INFO	launch{} ;		// SCMの起動保護種別です
	// ポインターを持たない各応答を別々の所有値へ読みます
	const std::array				errors{query( SERVICE_CONFIG_DELAYED_AUTO_START_INFO, delayed),
							   query( SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, failureFlag),
							   query( SERVICE_CONFIG_SERVICE_SID_INFO, sid),
							   query( SERVICE_CONFIG_PRESHUTDOWN_INFO, preshutdown),
							   query( SERVICE_CONFIG_LAUNCH_PROTECTED, launch)} ;
	const auto						failed = std::ranges::find_if(
		 errors, []( NativeError error) { return error != 0U ; }) ;	// 元順の最初の失敗です
	// 元設定の読取が失敗した場合に既定値を採用しません
	if( failed != errors.end()) {
		return *failed ;
	}

	snapshot.delayedAutoStart		  = delayed.fDelayedAutostart != FALSE ;
	snapshot.failureActionsOnNonCrash = failureFlag.fFailureActionsOnNonCrashFailures != FALSE ;
	snapshot.serviceSidType			  = sid.dwServiceSidType ;
	snapshot.preshutdownTimeout		  = preshutdown.dwPreshutdownTimeout ;
	snapshot.launchProtection		  = launch.dwLaunchProtected ;

	// 元INFが変更しない優先NUMAの任意照会は、Windowsの引数不対応も元状態として保持する
	snapshot.preferredNodeError = query( SERVICE_CONFIG_PREFERRED_NODE, node) ;
	// アクセス拒否や他のエラーを未設定へ読み替えない
	if( snapshot.preferredNodeError != 0U &&
	   snapshot.preferredNodeError !=
		   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER))) {
		return snapshot.preferredNodeError ;
	}

	// 未読値をノード0の明示設定として採用しない
	if( snapshot.preferredNodeError == 0U) {
		snapshot.preferredNode		 = node.usPreferredNode ;
		snapshot.preferredNodeDelete = node.fDelete != FALSE ;
	}

	SERVICE_DESCRIPTIONW description{} ;											// 受信した説明への応答内ポインターです
	auto				 error = query( SERVICE_CONFIG_DESCRIPTION, description) ;	// 同照会の診断です
	// 構成照会失敗又は範囲不正を設定のない状態に変換しません
	if( error != 0U || !copyServiceEvidenceText( std::as_bytes( response), description.lpDescription,
											   snapshot.config.description)) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	SERVICE_FAILURE_ACTIONSW failure{} ;	// 元の回復条件、メッセージ、コマンドと作用配列です
	error = query( SERVICE_CONFIG_FAILURE_ACTIONS, failure) ;
	// 失敗時は次の応答で置き換えません
	if( error != 0U) {
		return error ;
	}

	const auto actions = boundedServiceConfigArray( response, failure.lpsaActions,
												   failure.cActions) ;	// 元作用配列です
	// 再起動メッセージ、コマンド、全作用のどれかが欠けていれば観測を返しません
	if( actions.size() != failure.cActions ||
	   !copyServiceEvidenceText( std::as_bytes( response), failure.lpRebootMsg,
								snapshot.failureRebootMessage) ||
	   !copyServiceEvidenceText( std::as_bytes( response), failure.lpCommand,
								snapshot.failureCommand)) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	snapshot.failureResetSeconds = failure.dwResetPeriod ;
	// 元の回復処理順と待機時間を保持します
	for( const auto &action : actions) {
		snapshot.failureActions.push_back( {static_cast<std::uint32_t>( action.Type), action.Delay}) ;
	}

	SERVICE_REQUIRED_PRIVILEGES_INFOW privileges{} ;	// サービストークンに保持する特権の元集合です
	error = query( SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, privileges) ;
	// 一照会のバッファを再利用する前に全特権名を複製します
	if( error == 0U) {
		error = copyServiceEvidenceList( std::as_bytes( response), privileges.pmszRequiredPrivileges,
										snapshot.requiredPrivileges) ;
	}

	// 元の設定とエラーを次の照会で上書きしません
	if( error != 0U) {
		return error ;
	}

	SERVICE_TRIGGER_INFO trigger{} ;	// トリガー配列と各条件の参照を含む照会の先頭です
	error = query( SERVICE_CONFIG_TRIGGER_INFO, trigger) ;
	return error != 0U ? error : copyServiceTriggers( response, trigger, snapshot.triggers) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 補助サービスのSCM状態を許可判定に変換せず取得します
 * @param[in] service 同じサービスの状態照会ハンドルです
 * @param[out] status 全状態報告です。失敗時は作業値を破棄します
 * @return 停止、実行中又は一時停止の読取で0、遷移中又は不正・失敗時はHRESULTです
 */
//------------------------------------------------------------------------------
static NativeError readAuxiliaryStorageServiceStatus( SC_HANDLE						service,
													 AuxiliaryStorageServiceStatus &status)
{
	SERVICE_STATUS_PROCESS original{} ;	// SCMの固定長状態報告です
	DWORD				   required{} ;	// 容量不足時の元必要バイト数です
	// SCMに保持された状態だけを取得し、サービスへ制御要求や即時照会を送りません
	if( !QueryServiceStatusEx( service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE *>( &original),
							 sizeof( original), &required)) {
		const auto error = GetLastError() ;	// 失敗直後の元診断です
		return HRESULT_FROM_WIN32( error ? error : ERROR_INVALID_DATA) ;
	}

	// 遷移中の状態を確定観測として使えないため、終了を待たずに保留します
	if( original.dwCurrentState == SERVICE_START_PENDING ||
	   original.dwCurrentState == SERVICE_STOP_PENDING ||
	   original.dwCurrentState == SERVICE_CONTINUE_PENDING ||
	   original.dwCurrentState == SERVICE_PAUSE_PENDING) {
		return HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	// 別型又は未定義状態を既知のWin32サービスとして扱いません
	if( original.dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
	   (original.dwCurrentState != SERVICE_STOPPED && original.dwCurrentState != SERVICE_RUNNING &&
		original.dwCurrentState != SERVICE_PAUSED)) {
		return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
	}

	status = {original.dwServiceType,
			  original.dwCurrentState,
			  original.dwControlsAccepted,
			  original.dwWin32ExitCode,
			  original.dwServiceSpecificExitCode,
			  original.dwCheckPoint,
			  original.dwWaitHint,
			  original.dwProcessId,
			  original.dwServiceFlags} ;
	return 0U ;
}

/** @brief Windows SCMの接続又は照会ハンドルを所有する型です */
using ScopedServiceHandle =
	std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, decltype( &CloseServiceHandle)> ;

//------------------------------------------------------------------------------
/**
 * @brief 監査照会用の読み取りハンドルを同じ実効トークンの複製から取得します
 * @param[in] manager ローカルSCMの接続ハンドルです
 * @param[in] name 検証済みの同一サービス名です。終端を含みます
 * @param[out] result 成功時に所有を引き渡す保護照会ハンドルです
 * @return 照会ハンドル取得時0、特権不足又は元API診断のHRESULTです
 * @note 現在の権限を持つ処理スレッドだけで一時的に特権を有効にします
 */
//------------------------------------------------------------------------------
static NativeError openAuxiliaryStorageServiceSecurity( SC_HANDLE manager, const wchar_t *name,
													   ScopedServiceHandle &result)
{
	HANDLE		   original{} ;	// 現在のスレッドトークンです。偽装していなければ空です
	constexpr auto THREAD_TOKEN_RIGHTS =
		TOKEN_DUPLICATE | TOKEN_IMPERSONATE ;	// 複製と元への復帰に必要です
	// 既に偽装している場合に、プロセス権限へ切り替えて読取りません
	if( !OpenThreadToken( GetCurrentThread(), THREAD_TOKEN_RIGHTS, TRUE, &original)) {
		const auto error = GetLastError() ;	// 現在のトークンを取得できなかった元診断です
		// 元トークン不存在だけが同プロセストークンを実効主体として使えます
		if( error != ERROR_NO_TOKEN) {
			return HRESULT_FROM_WIN32( error ? error : ERROR_INVALID_DATA) ;
		}
	}

	const std::unique_ptr<void, decltype( &CloseHandle)> prior{original,
															  &CloseHandle} ;	// 復元まで保持します
	std::unique_ptr<void, decltype( &CloseHandle)>		process{nullptr,
															&CloseHandle} ;	// 必要時だけ所有します
	// 既存のスレッドトークンがなければプロセスの実効元を複製する権利だけを取得します
	if( !prior) {
		HANDLE rawProcess{} ;	// 複製元となるプロセストークンです
		// 現在のプロセス以外のトークンを使いません
		if( !OpenProcessToken( GetCurrentProcess(), TOKEN_DUPLICATE, &rawProcess)) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		process.reset( rawProcess) ;
	}

	HANDLE rawScoped{} ;	// この一照会だけで変更する実効トークンの複製です
	// 元トークンを変更せず、複製の特権調整とスレッド適用だけを許すハンドルを得ます
	if( !DuplicateTokenEx( prior ? prior.get() : process.get(),
						 TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE, nullptr,
						 SecurityImpersonation, TokenImpersonation, &rawScoped)) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	const std::unique_ptr<void, decltype( &CloseHandle)> scoped{
		rawScoped, &CloseHandle} ;	// 読取権取得まで所有します
	TOKEN_PRIVILEGES privileges{} ;	// 保持済みの監査特権一つだけを指定します
	privileges.PrivilegeCount			= 1U ;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED ;
	// 特権の識別子が確認できなければ権限を変更しません
	if( !LookupPrivilegeValueW( nullptr, SE_SECURITY_NAME, &privileges.Privileges[0].Luid)) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	SetLastError( ERROR_SUCCESS) ;
	const auto adjusted = AdjustTokenPrivileges( scoped.get(), FALSE, &privileges, 0U, nullptr,
												nullptr) ;	// 複製だけを変更します
	const auto adjustmentError = GetLastError() ;			// ERROR_NOT_ALL_ASSIGNEDも失敗として保持します
	// 実効主体が持たない特権を取得できたことにしません
	if( !adjusted || adjustmentError != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( adjustmentError ? adjustmentError : ERROR_PRIVILEGE_NOT_HELD) ;
	}

	// 偽装を開始できた場合だけ必要な照会ハンドルを開きます
	if( !SetThreadToken( nullptr, scoped.get())) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	const auto opened = OpenServiceW(
		manager, name, READ_CONTROL | ACCESS_SYSTEM_SECURITY) ;	// 監査と所有者・DACLに必要です
	const auto openError =
		opened ? ERROR_SUCCESS : GetLastError() ;	// 元診断をトークン復元より先に保持します
	// 開くときだけ特権が必要です。元のセキュリティコンテキストを復元できないまま処理しません
	if( !SetThreadToken( nullptr, prior.get())) {
		RaiseFailFastException( nullptr, nullptr, 0U) ;
	}

	// 元の不存在も最初の照会で既存だったサービスの変化として返します
	if( !opened) {
		return HRESULT_FROM_WIN32( openError ? openError : ERROR_INVALID_DATA) ;
	}

	result.reset( opened) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ補助サービスの所有者、グループ、DACL及び監査SACLを取得します
 * @param[in] service 監査を含む保護照会権を確認した同一サービスです
 * @param[out] security 元自己相対形式の記述子です。失敗時は作業値を破棄します
 * @return 完全な記述子の読取時0、元診断又は不正記述子のHRESULTです
 */
//------------------------------------------------------------------------------
static NativeError readAuxiliaryStorageServiceSecurity( SC_HANDLE			   service,
													   std::vector<std::byte> &security)
{
	alignas( SECURITY_DESCRIPTOR_RELATIVE) std::array<std::byte, 8192U>
				   buffer{} ;	// SCMの保護読取上限です
	DWORD		   required{} ;	// 容量不足時にSCMが返すサイズです
	constexpr auto SECURITY_PARTS = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
									DACL_SECURITY_INFORMATION |
									SACL_SECURITY_INFORMATION ;	// 取得する元記述子の部分です
	// 監査照会の失敗を元SACLの不存在へ変換しません
	if( !QueryServiceObjectSecurity( service, SECURITY_PARTS, buffer.data(),
								   static_cast<DWORD>( buffer.size()), &required)) {
		const auto error = GetLastError() ;	// 失敗直後の元診断です
		return HRESULT_FROM_WIN32( error ? error : ERROR_INVALID_SECURITY_DESCR) ;
	}

	SECURITY_DESCRIPTOR_CONTROL control{} ;		// 権限の保護と構造種別を持つビット集合です
	DWORD						revision{} ;	// Windowsの記述子形式の版です
	// SCMが生成した応答の構造と自己相対形式を確認します
	if( !IsValidSecurityDescriptor( buffer.data()) ||
	   !GetSecurityDescriptorControl( buffer.data(), &control, &revision) ||
	   (control & SE_SELF_RELATIVE) == 0U) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR) ;
	}

	const auto length = GetSecurityDescriptorLength( buffer.data()) ;	// 元記述子に用いた全長です
	// バッファ余剰を除き、元DACLと監査SACLの欠落又はNULL状態も記述子内で区別します
	if( length < sizeof( SECURITY_DESCRIPTOR_RELATIVE) || length > buffer.size()) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR) ;
	}

	security.assign( buffer.data(), buffer.data() + length) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元選択の正確な補助サービスについてSCMの構成・状態・保護を読取ります
 * @param[in] name 同選択が指定する最大256文字のサービス名です
 * @param[out] snapshot 全読取時の私有観測です。明示不存在又はエラー時は空です
 * @return 完全な読取又はSCMの明示不存在で0、その他は元診断又は不正応答のHRESULTです
 * @note 同期処理です。監査読取のハンドル取得だけで保持特権を一時使用します
 * @see docs/adr/0569-selected-storage-auxiliary-services.md
 */
//------------------------------------------------------------------------------
NativeError readAuxiliaryStorageServiceSnapshot(
	std::wstring_view name, std::optional<AuxiliaryStorageServiceSnapshot> &snapshot)
{
	snapshot.reset() ;
	// 正確な元名以外のサービス、パス又は表示名を探索しません
	if( !simpleName( name, 256U)) {
		return E_INVALIDARG ;
	}

	AuxiliaryStorageServiceSnapshot result ;	// 全読取を確認するまで非公開の作業値です
	result.config.name = name ;
	const ScopedServiceHandle manager{OpenSCManagerW( nullptr, nullptr, SC_MANAGER_CONNECT),
									  &CloseServiceHandle} ;	// ローカルSCMの接続だけを保持します
	// SCMの接続失敗はサービス不存在を示しません
	if( !manager) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	const ScopedServiceHandle service{OpenServiceW( manager.get(), result.config.name.c_str(),
												   SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS),
									  &CloseServiceHandle} ;	// 対象一件の構成・状態照会です
	// 最初の明示不存在だけを不存在の観測として採用します
	if( !service) {
		const auto error = GetLastError() ;	// SCMによる正確な元診断です
		return error == ERROR_SERVICE_DOES_NOT_EXIST
				   ? 0U
				   : HRESULT_FROM_WIN32( error ? error : ERROR_INVALID_DATA) ;
	}

	auto error = readAuxiliaryStorageServiceStatus(
		// 一連の読取を開始した時点の状態です
		service.get(), result.status) ;
	// 補助サービスと同じ型の安定状態が成立した場合だけ基本構成を読みます
	if( error == 0U) {
		error = readServiceConfiguration( service.get(), SERVICE_WIN32_OWN_PROCESS, result.config) ;
	}

	// 基本構成の後に残る既存サービスのオプションを読みます
	if( error == 0U) {
		error = readAuxiliaryStorageServiceOptions( service.get(), result) ;
	}

	// 元の同じサービスハンドルを保持したまま、監査照会用ハンドルを正確な元名から開きます
	if( error == 0U) {
		ScopedServiceHandle security{nullptr,
									 &CloseServiceHandle} ;	// 照会後すぐに閉じる監査用ハンドルです
		error = openAuxiliaryStorageServiceSecurity( manager.get(), result.config.name.c_str(),
													security) ;
		// 監査照会権を得て、元の権限へ復帰した場合だけ記述子を読みます
		if( error == 0U) {
			error = readAuxiliaryStorageServiceSecurity( security.get(), result.config.security) ;
		}
	}

	// 一部だけ読めた構成や保護を発行しません
	if( error != 0U) {
		return error ;
	}

	AuxiliaryStorageServiceStatus finalStatus ;	// 構成と監査読取後の独立した状態です
	error = readAuxiliaryStorageServiceStatus( service.get(), finalStatus) ;
	// 読取中に実行状態が変わった場合に同一観測を組み立てません
	if( error != 0U || result.status != finalStatus) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	snapshot = std::move( result) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元用途のkernel条件と保守主体限定の完全SDを検査します
 * @param[in] evidence 全長を所有する現在configとself-relative SDです
 * @param[in] purpose SYSTEMは旧start3/error1、storageはstart0/1/3/error0..3を要求します
 * @return 全型/範囲/SD/保守主体限定変更が成立0、不正又は未知権限はHRESULTです
 * @note 現configを適用せず、提案する新版configやdriver実行意味を認定しません
 */
//------------------------------------------------------------------------------
static NativeError validateServiceEvidence( const SystemServiceEvidence &evidence,
										   const ServiceEvidencePurpose purpose)
{
	// 同期所有した有限configとSDだけを検証します
	if( !simpleName( evidence.name, purpose == ServiceEvidencePurpose::STORAGE ? 256U : 31U) ||
	   evidence.type != SERVICE_KERNEL_DRIVER ||
	   (purpose == ServiceEvidencePurpose::SYSTEM
			? evidence.start != SERVICE_DEMAND_START
			: (evidence.start != SERVICE_BOOT_START && evidence.start != SERVICE_SYSTEM_START &&
			   evidence.start != SERVICE_DEMAND_START) ||
				  evidence.errorControl > 3U) ||
	   evidence.binary.empty() || evidence.binary.size() > 4096U ||
	   evidence.binary.find( L'\0') != evidence.binary.npos || evidence.dependencies.size() > 64U ||
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
	return validateServiceEvidence( evidence, ServiceEvidencePurpose::SYSTEM) ;
}

//------------------------------------------------------------------------------
/**
 * @brief storageだけのkernel1/Start0/1/3原configと保守主体限定SDを検査します
 * @param[in] evidence 同期所有する全原config/SDです
 * @return 全有限型/権限成立0、不明又は逸脱はHRESULTです
 * @note 現旧binary/configを提案新版へ一致させず、原値を書き換えません
 */
//------------------------------------------------------------------------------
NativeError validateStorageServiceEvidence( const SystemServiceEvidence &evidence)
{
	return validateServiceEvidence( evidence, ServiceEvidencePurpose::STORAGE) ;
}
} // namespace drivercrate
