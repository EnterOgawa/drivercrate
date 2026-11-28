//------------------------------------------------------------------------------
/**
 * @file storage_inf_effects_internal.cpp
 * @brief 元storage全作用を型/所有scopeと安定service観測へ結びます
 * @version 01.41.00
 * @date 2026/11/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/15  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/16  MTD serviceと元hardware propertyを限定検査
 * Ver.01.02.00 Shunji Ogawa  2026/11/21  メディアチェンジャーの作用とWindows起動グループ順序を検査
 * Ver.01.03.00 Shunji Ogawa  2026/11/21  HDCカーネルブートサービスと共有AutoLoggerの静的検査を追加
 * Ver.01.04.00 Shunji Ogawa  2026/11/21  HDCのAutoLoggerの現在値と保護状態を読み取る
 * Ver.01.05.00 Shunji Ogawa  2026/11/21  SCSI関連サービスの既存値保持付き文字列を検査
 * Ver.01.06.00 Shunji Ogawa  2026/11/21  HDCの単一IDEブートサービスと元SYSコピーを検査
 * Ver.01.07.00 Shunji Ogawa  2026/11/21  IDEブートグループの現在位置を読み取り確認
 * Ver.01.08.00 Shunji Ogawa  2026/11/22  選択SCSI基本節の順位指定を検査
 * Ver.01.09.00 Shunji Ogawa  2026/11/22  補助サービスの元宣言とSystemイベントを検査
 * Ver.01.10.00 Shunji Ogawa  2026/11/22  現在の補助サービスと実行ファイル・イベント登録を固定
 * Ver.01.11.00 Shunji Ogawa  2026/11/22  補助サービスの実行条件と保護を署名付き元宣言に照合
 * Ver.01.11.01 Shunji Ogawa  2026/11/23  端末構成の照会をSystem32の要求時起動補助サービスに限定
 * Ver.01.12.00 Shunji Ogawa  2026/11/23  トリアージ指定の共有AutoLoggerを署名付き選択機器節から検査
 * Ver.01.13.00 Shunji Ogawa  2026/11/23  共有ACPI・DMAと名前付きイベントを元ストレージ作用へ結合
 * Ver.01.14.00 Shunji Ogawa  2026/11/23  ACPIとAutoLoggerの現在位置・値・保護を同じ読取り規則で確認
 * Ver.01.15.00 Shunji Ogawa  2026/11/23  Systemの明示イベント源と現在カテゴリ値を保護付きで読取
 * Ver.01.16.00 Shunji Ogawa  2026/11/23  自動起動補助の現在SCM構成と保護付きのDriver Store EXEを照合
 * Ver.01.17.00 Shunji Ogawa  2026/11/23  現用登録の関連イベントと補助サービスを観測
 * Ver.01.18.00 Shunji Ogawa  2026/11/23  自動起動補助の現用登録と共有設定を一緒に再観測
 * Ver.01.19.00 Shunji Ogawa  2026/11/23  関連サービスを共有する全現用の観測を照合
 * Ver.01.20.00 Shunji Ogawa  2026/11/23  元選択に対応するWindowsの現用電源設定を保持
 * Ver.01.21.00 Shunji Ogawa  2026/11/23  現用署名元と候補の電源設定を現在観測へ照合
 * Ver.01.22.00 Shunji Ogawa  2026/11/23  補助サービスとイベントの共有先を元登録へ照合
 * Ver.01.23.00 Shunji Ogawa  2026/11/23  起動サービスと配置済みSYSを署名元へ照合
 * Ver.01.24.00 Shunji Ogawa  2026/11/23  元AutoLogger名でETW稼働状態を照会
 * Ver.01.25.00 Shunji Ogawa  2026/11/23  指定された自動起動と共有設定の適用後観測を照合
 * Ver.01.26.00 Shunji Ogawa  2026/11/23  旧起動構成と再起動要求が両方成立した場合を判定
 * Ver.01.27.00 Shunji Ogawa  2026/11/23  名前付きイベントの二資源をWindowsと選択元コピーへ結合
 * Ver.01.28.00 Shunji Ogawa  2026/11/23  名前付きイベント用DLLの現在配置と適用後を署名元へ照合
 * Ver.01.29.00 Shunji Ogawa  2026/11/23  単一ブートサービスの元電源、割込み、イベントを照合
 * Ver.01.30.00 Shunji Ogawa  2026/11/23  電源設定GUIDの直下と全サブグループを観測
 * Ver.01.30.01 Shunji Ogawa  2026/11/23  起動SYSの元パス照合を現用登録と共用
 * Ver.01.31.00 Shunji Ogawa  2026/11/23  単一起動の関連イベントを独立したキー監視で観測
 * Ver.01.32.00 Shunji Ogawa  2026/11/23  選択機器キーと関連サービスの局所値を保護付きで観測
 * Ver.01.33.00 Shunji Ogawa  2026/11/23  同じ制御セットのイベントと局所観測を再照合
 * Ver.01.34.00 Shunji Ogawa  2026/11/23  現用機器の電源宣言を全登録場所と照合
 * Ver.01.35.00 Shunji Ogawa  2026/11/23  新規作成と既存電源定義の変更を同じ元候補で判定
 * Ver.01.36.00 Shunji Ogawa  2026/11/23  単一ブートの配置・イベント・局所値の変更範囲を判定
 * Ver.01.37.00 Shunji Ogawa  2026/11/23  単一起動の適用後の元署名と実作用を照合
 * Ver.01.38.00 Shunji Ogawa  2026/11/27  DisplayのApplicationイベント源を元宣言へ照合
 * Ver.01.39.00 Shunji Ogawa  2026/11/27  Display補助の現用SCM構成を保護付き実EXEへ照合
 * Ver.01.40.00 Shunji Ogawa  2026/11/27  Display登録処理が読むSoftwareComponentクラスを観測
 * Ver.01.41.00 Shunji Ogawa  2026/11/27  選択DisplayのOpenCL登録値と共有の旧マーカーを観測
 * </pre>
 *
 * @note 既SYSTEM policyを変更せず、PACKAGEは同由来のまま扱います。実registry/SCM変更はありません
 */
//------------------------------------------------------------------------------
#include "platform/storage_inf_effects_internal.h"

#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/registered_driver_store_package_internal.h"
#include <Windows.h>
#include <evntrace.h>
#include <objbase.h>
#include <powrprof.h>
#include <sddl.h>
#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <set>
#include <tuple>
#include <type_traits>
#include <utility>

namespace drivercrate {
namespace {
// 未知作用を保留する固定HRESULTです
constexpr NativeError UNSUPPORTED =
	static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
// 元fieldの不正を返す固定HRESULTです
constexpr NativeError INVALID = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;

//------------------------------------------------------------------------------
/**
 * @brief 原値を変更せずWindows ordinal規則で同名を比較します
 * @param[in] left 同期借用する元値です
 * @param[in] right 独立に確認する元値です
 * @return 全長と文字が大小文字以外一致する場合trueです
 */
//------------------------------------------------------------------------------
bool				  same( std::wstring_view left, std::wstring_view right)
{
	return left.size() == right.size() && left.size() <= 4096U &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原UINT32の全桁を解釈し、符号/後続文字/overflowを拒否します
 * @param[in] text 元decimal又は0x hexadecimalです
 * @param[out] value 成功時だけ元数値です
 * @return 一つの有限整数だけならtrueです
 */
//------------------------------------------------------------------------------
bool integer( std::wstring_view text, std::uint32_t &value)
{
	// 原表記から選ぶ十進又は十六進の基数です
	unsigned radix = 10U ;
	// 明示hexだけを別基数へ解釈します
	if( text.size() > 2U && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) {
		text.remove_prefix( 2U) ;
		radix = 16U ;
	}

	// 空値を既定0へ補完しません
	if( text.empty() || text.size() > 10U) {
		return false ;
	}

	// 全桁の検査後だけ元UINT32へ移す一時整数です
	std::uint32_t parsed{} ;
	// 全fieldを消費して末尾悪値を省略しません
	for( const wchar_t character : text) {
		// 現在の原一文字を解釈した数字です
		const unsigned digit = character >= L'0' && character <= L'9'	? character - L'0'
							   : character >= L'a' && character <= L'f' ? character - L'a' + 10U
							   : character >= L'A' && character <= L'F' ? character - L'A' + 10U
																		: 16U ;
		// 追加文字やUINT32超過を縮約しません
		if( digit >= radix || parsed > (std::numeric_limits<std::uint32_t>::max() - digit) / radix) {
			return false ;
		}

		parsed = parsed * radix + digit ;
	}

	value = parsed ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原scopeを外部key/pathへ拡張しない有限相対名を確認します
 * @param[in] text 元subkey又はvalue名です。空は既定key/valueです
 * @return 既定又は安全な有限相対形ならtrueです
 */
//------------------------------------------------------------------------------
bool relative( std::wstring_view text)
{
	return text.size() <= 4096U && !text.starts_with( L"\\") && !text.ends_with( L"\\") &&
		   text.find( L"\\\\") == text.npos && text.find( L"..") == text.npos &&
		   std::ranges::none_of( text, []( wchar_t character) {
			   return character < L' ' || character > L'~' ||
					  std::wstring_view{L":/%\";<>|?*"}.find( character) != std::wstring_view::npos ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非実行scalarをcommand/module/保護service設定へ偽装させません
 * @param[in] value 同原行の通常REG_SZ dataです。vendorのkey/value名は渡しません
 * @return 有限で既知禁止marker/未解決tokenを持たない場合trueです
 */
//------------------------------------------------------------------------------
bool passive( std::wstring_view value)
{
	// 未展開tokenとcontrolを無作用dataへ変更しません
	if( value.size() > 4096U || value.find( L'%') != value.npos ||
	   std::ranges::any_of( value, []( wchar_t c) { return c < L' ' || c == 0x7f ; })) {
		return false ;
	}

	// 実行file参照の検査だけに使う比較用copyです
	std::wstring lowered{value} ;
	std::ranges::transform( lowered, lowered.begin(), []( wchar_t c) {
		return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>( c + L'a' - L'A') : c ;
	}) ;
	// 通常REG_SZを実program参照と分ける既知実行拡張子です
	constexpr std::array markers{L".exe", L".dll", L".bat", L".cmd", L".ps1", L".vbs", L".js"} ;
	std::wstring_view	 command{lowered} ;	// 元dataの先頭tokenだけを実program名へ比較します
	// 先頭の通常空白をprogram名の一部として拒否回避に使わせません
	while( command.starts_with( L' ')) {
		command.remove_prefix( 1U) ;
	}

	const bool quoted = command.starts_with( L'"') ;	// 引用符で囲んだprogram名も同じ境界で確認します
	// 原REG_SZの外側引用だけを取り出し、表示文言の部分語は検査しません
	if( quoted) {
		command.remove_prefix( 1U) ;
	}

	const auto end	 = command.find( quoted ? L'"' : L' ') ;	// 完全な先頭tokenの境界です
	command			 = command.substr( 0U, end) ;
	const auto slash = command.find_last_of( L"\\/") ;	// 明示pathも末尾program名を確認します
	command.remove_prefix( slash == command.npos ? 0U : slash + 1U) ;
	constexpr std::array<std::wstring_view, 8U> commands{
		L"cmd",		L"powershell", L"pwsh",	  L"rundll32", L"regsvr32",
		L"msiexec", L"wscript",	   L"cscript"} ;	// 拡張子省略で実行できる既知programです
	// commandという一般語やvendor名の部分一致を禁止条件にしません
	if( std::ranges::find( commands, command) != commands.end()) {
		return false ;
	}

	return std::ranges::none_of( markers, [&]( std::wstring_view marker) {
		auto position = lowered.find( marker) ;	// 同期借用data内の実行拡張子候補を全て確認します
		// .json等の単なる部分語をscript参照と読み替えません
		while( position != lowered.npos) {
			const auto tail = position + marker.size() ;	// 元file名の末尾又は引数境界です
			// 正確な実行拡張子と引数/登録区切りに一致する場合だけ参照とします
			if( tail == lowered.size() ||
			   std::wstring_view{L" \"',;:|&<>)"}.find( lowered[tail]) != std::wstring_view::npos) {
				return true ;
			}

			position = lowered.find( marker, tail) ;
		}

		return false ;
	}) ; // 元文字列の所有者はこの同期全体で生存します
}

/** @brief 同原節の文脈と元registry操作を併存させる有限queueです */
struct PendingSection {
	/// 元document/節/ownerです
	SystemInfSection section ;
	/// 元DelReg参照だけがtrueです
	bool			 deletion{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同所有元registry行を型とscopeで検査します
 * @param[in] effect 原全tupleです
 * @param[in] deletion 元参照がDelRegならtrueです
 * @param[in] service 元associated serviceとSYSコピーです
 * @param[in] api 同NativeLoaderのWindows resource検証です
 * @param[out] action 成功した原作用の限定型です
 * @param[in,out] timeout 正確な共有DWORDだけを原値のまま保持します
 * @param[in,out] deviceType 同MTD hardwareの元DWORDと重複状態です
 * @param[in,out] characteristics 同MTD hardwareの元DWORDと重複状態です
 * @return 型/scope/全field成立0、それ以外はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError registry( const SystemInfEffect &effect, bool deletion,
					 const SelectedStorageServiceFacts &service, const SystemInfEffectApi &api,
					 StorageInfAction &action, std::optional<std::uint32_t> &timeout,
					 std::optional<std::uint32_t> &deviceType,
					 std::optional<std::uint32_t> &characteristics)
{
	// 元AddReg/DelRegの省略を含む全fieldを同期借用します
	const auto &v = effect.row.values ;
	// fieldの省略を埋めず、余分fieldも捨てません
	if( v.size() < 3U || v.size() > 5U || !relative( v[1]) || !relative( v[2])) {
		return INVALID ;
	}

	// 既詳細へ表示する元storage変更範囲です
	const auto scope = effect.source.scope ;
	// MTDのdevice object propertyは文脈を変えて一般dataへ隠しません
	const bool mtdProperty = same( service.className, L"MTD") &&
							 (same( v[2], L"DeviceType") || same( v[2], L"DeviceCharacteristics")) ;
	// device objectの必須属性を削除する作用は未評価です
	if( mtdProperty && deletion) {
		return UNSUPPORTED ;
	}

	// DelRegは当該hardwareの三つの旧named値だけです
	if( deletion) {
		action = StorageInfAction::HARDWARE_VALUE_DELETE ;
		return v.size() == 3U && scope == SystemInfContext::HARDWARE && same( v[0], L"HKR") &&
					   same( v[1], L"ScsiPort") &&
					   (same( v[2], L"BusNumber") || same( v[2], L"LegacyInterfaceType") ||
						same( v[2], L"SlotNumber"))
				   ? 0U
				   : UNSUPPORTED ;
	}

	// 元API又は原宣言の全flag bitです
	std::uint32_t flags{} ;
	// flagsは第4fieldだけです。原3fieldの第3値をKEYONLYへ移しません
	if( v.size() >= 4U && !v[3].empty() && !integer( v[3], flags)) {
		return INVALID ;
	}

	// 第5fieldだけを参照する原scalarです。省略時空です
	const auto data = v.size() == 5U ? std::wstring_view{v[4]} : std::wstring_view{} ;
	// EventMessageFileだけは元System event-logの専用resource文法です
	if( scope == SystemInfContext::EVENT_LOG) {
		action = StorageInfAction::EVENT_RESOURCE ;
		// 別log又は任意rootへservice resourceを登録しません
		if( !same( v[0], L"HKR") || !v[1].empty() || v.size() != 5U ||
		   effect.source.owner != service.name) {
			return UNSUPPORTED ;
		}

		// System logのmaskは原DWORD1..7だけです
		if( same( v[2], L"TypesSupported")) {
			// 元event maskの全値です
			std::uint32_t types{} ;
			return flags == 0x10001U && integer( data, types) && types > 0U && types <= 7U
					   ? 0U
					   : UNSUPPORTED ;
		}

		// EXPAND_SZのresource listを任意DLL/commandへ流用しません
		if( !same( v[2], L"EventMessageFile") || flags != 0x20000U || data.empty() || !api.module) {
			return UNSUPPORTED ;
		}

		// 元resource list内の次の開始位置です
		std::size_t position{} ;
		// 同原文の全参照又は行数を上限と照合する数です
		std::size_t count{} ;
		// すべてのsemicolon区切りresourceを消費します
		while( position <= data.size()) {
			// 現在の元参照又はinstanceの正式終端位置です
			const auto end = data.find( L';', position) ;
			// 同原event resource listの一つの完全要素です
			const auto resource =
				data.substr( position, end == data.npos ? data.size() - position : end - position) ;
			// 空resource/過大listを先頭一fileで救済しません
			if( resource.empty() || ++count > 8U) {
				return UNSUPPORTED ;
			}

			// 同CATへ結合済みの元SYS resourceだけをWindows helperと区別します
			const auto systemRoot = std::wstring_view{L"%SystemRoot%"} ;
			// 同CATの元SYS完全宛先へ一致するresourceの分類です
			const bool sameSystemDriver =
				resource.size() > systemRoot.size() &&
				same( resource.substr( 0U, systemRoot.size()), systemRoot) &&
				resource.size() - systemRoot.size() < service.binaryTarget.size() &&
				same( resource.substr( systemRoot.size()),
					 std::wstring_view{service.binaryTarget}.substr(
						 service.binaryTarget.size() - (resource.size() - systemRoot.size()))) &&
				resource.substr( systemRoot.size()).size() > 18U &&
				same( resource.substr( systemRoot.size(), 18U), L"\\System32\\Drivers\\") ;
			// 同CATのSYS以外は限定Windows resourceの実trustを必須にします
			if( !same( resource, service.binary) && !same( resource, service.binaryTarget) &&
			   !sameSystemDriver) {
				// 原完全名を失わずleafを取り出す境界です
				const auto slash = resource.find_last_of( L'\\') ;
				// 同原resourceの末尾名だけです。名前自体をtrustへしません
				const auto leaf = resource.substr( slash == resource.npos ? 0U : slash + 1U) ;
				// IoLogMsg.dllの実file/trustは同NativeLoaderが確認します
				if( !same( leaf, L"IoLogMsg.dll")) {
					return UNSUPPORTED ;
				}

				// 下位検査の最初の診断を後続へ返す一時値です
				const auto error = api.module( effect.source.document, resource) ;
				// 名前だけでWindows helperを認定しません
				if( error != 0U) {
					return error ;
				}
			}

			// 原listの正式終端だけを認めます
			if( end == data.npos) {
				break ;
			}

			position = end + 1U ;
		}

		return 0U ;
	}

	// SCSIの選択機器節から関連サービスへ登録する既存値保持付きの文字列
	const bool preserveString = flags == 0x02U && v.size() == 5U && !v[2].empty() &&
								same( service.className, L"SCSIAdapter") &&
								scope == SystemInfContext::DEVICE && same( v[0], L"HKLM") ;
	// 既存値保持の単独フラグと元の型以外を通常データへ変換しない
	if( (flags != 0U && flags != 0x10001U && flags != 0x10U && !preserveString) ||
	   (flags == 0x10001U && v.size() != 5U) ||
	   (flags == 0x10U && (!v[2].empty() || v.size() < 4U || !data.empty()))) {
		return UNSUPPORTED ;
	}

	// 元DWORDの全桁を読んだ値です
	std::uint32_t number{} ;
	// DWORDの欠測/文字/overflowを値0へ変換しません
	if( flags == 0x10001U && !integer( data, number)) {
		return INVALID ;
	}

	// Windows device objectに作用するMTD属性を正確なHW scopeとDWORDへ限定します
	if( mtdProperty) {
		// DeviceTypeとCharacteristicsで許可値と保存先を分けます
		const bool type = same( v[2], L"DeviceType") ;
		// 先行行と重複する同属性を検出する保存先です
		auto	  &prior = type ? deviceType : characteristics ;
		// 対象外scope、重複、不正な型や値を通常のregistry dataへ落としません
		if( scope != SystemInfContext::HARDWARE || !same( v[0], L"HKR") || !v[1].empty() ||
		   v.size() != 5U || flags != 0x10001U || prior || number != (type ? 7U : 0x101U)) {
			return UNSUPPORTED ;
		}

		prior = number ;
		action =
			type ? StorageInfAction::MTD_DEVICE_TYPE : StorageInfAction::MTD_DEVICE_CHARACTERISTICS ;
		return 0U ;
	}

	// 正確な共有disk timeoutだけを既知global作用へ分類します
	if( same( v[0], L"HKLM") && same( v[1], L"SYSTEM\\CurrentControlSet\\Services\\disk") &&
	   same( v[2], L"TimeOutValue")) {
		// この1..255は共有disk専用で、Storport vendor parameterへ適用しません
		if( flags != 0x10001U || number < 1U || number > 255U ||
		   (scope != SystemInfContext::DEVICE && scope != SystemInfContext::HARDWARE &&
			scope != SystemInfContext::SERVICE)) {
			return UNSUPPORTED ;
		}

		action	= StorageInfAction::SHARED_DISK_TIMEOUT ;
		timeout = number ;
		return 0U ;
	}

	// 原HKR又はexact service Parametersの相対scopeです
	std::wstring_view subkey{v[1]} ;
	// 関連serviceだけの明示HKLM起点です
	const auto		  own = L"SYSTEM\\CurrentControlSet\\Services\\" + service.name + L"\\" ;
	// 明示HKLMはexact associated serviceのParametersだけへ制限します
	if( same( v[0], L"HKLM")) {
		// 明示HKLMの別serviceやservice本体への逸脱を拒否します
		if( subkey.size() <= own.size() || !same( subkey.substr( 0U, own.size()), own)) {
			return UNSUPPORTED ;
		}

		subkey.remove_prefix( own.size()) ;
		// exact serviceでもParameters外の作用を受理しません
		if( !same( subkey, L"Parameters") &&
		   !(subkey.size() > 11U && same( subkey.substr( 0U, 11U), L"Parameters\\"))) {
			return UNSUPPORTED ;
		}
	}
	// HKR/HKLM以外のrootをdevice相対へ補完しません
	else if( !same( v[0], L"HKR")) {
		return UNSUPPORTED ;
	}

	// service HKRをStart/ImagePath/security本体へ向けません
	if( scope == SystemInfContext::SERVICE &&
	   (effect.source.owner != service.name ||
		(!same( subkey, L"Parameters") &&
		 !(subkey.size() > 11U && same( subkey.substr( 0U, 11U), L"Parameters\\"))))) {
		return UNSUPPORTED ;
	}

	// device/hardware HKRとexact service data以外の文脈は未知として残します
	if( scope != SystemInfContext::DEVICE && scope != SystemInfContext::HARDWARE &&
	   scope != SystemInfContext::SERVICE) {
		return UNSUPPORTED ;
	}

	// 自device/HWのParametersもdriver固有dataであり、service本体の制御位置とは分けます
	const bool parameters = same( v[0], L"HKLM") || scope == SystemInfContext::SERVICE ||
							same( subkey, L"Parameters") ||
							(subkey.size() > 11U && same( subkey.substr( 0U, 11U), L"Parameters\\")) ;
	// device/HWの実制御位置として拒否する正確な作用名です
	constexpr std::array controls{
		L"UpperFilters", L"LowerFilters",  L"CoInstallers32", L"DeviceInterfaceGUIDs",
		L"ImagePath",	 L"StartOverride", L"Security",		  L"Run",
		L"RunOnce",		 L"Command",	   L"BootFlags"} ;
	// vendor Parametersの名前を実行作用と推測せず、実制御位置とdata型を区別します
	if( (!parameters &&
		std::ranges::any_of( controls,
							[&]( auto control) {
								return same( v[2], control) || same( subkey, control) ||
									   (subkey.size() > std::wstring_view{control}.size() &&
										same( subkey.substr( 0U, std::wstring_view{control}.size()),
											 control) &&
										subkey[std::wstring_view{control}.size()] == L'\\') ;
							})) ||
	   ((flags == 0U || preserveString) && !passive( data))) {
		return UNSUPPORTED ;
	}

	action = StorageInfAction::REGISTRY_VALUE ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief AutoLoggerの元GUIDを固定長の括弧付きASCII UUIDとして検査する
 * @param[in] guid レジストリのキー名またはGuid値を構成する元文字列
 * @return 全フィールドが正式な形で非零ならtrue
 */
//------------------------------------------------------------------------------
bool validAutoLoggerGuid( std::wstring_view guid)
{
	// 省略文字、追加文字、ProgIDを別のGUIDに読み替えない
	if( guid.size() != 38U || guid.front() != L'{' || guid.back() != L'}') {
		return false ;
	}

	bool nonzero{} ;	// 少なくとも一つの非零の16進桁があるかを保持する
	// 括弧間の全位置と全桁を確認する
	for( std::size_t index = 1U; index + 1U < guid.size(); ++index) {
		const auto c = guid[index] ;	// 現在の元文字
		// UUIDの区切り位置は固定で扱う
		if( index == 9U || index == 14U || index == 19U || index == 24U) {
			// 区切りの省略や置換を認めない
			if( c != L'-') {
				return false ;
			}

			continue ;
		}

		// ASCIIの16進桁だけを比較し、Unicodeや空白を解釈しない
		if( !((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'))) {
			return false ;
		}

		nonzero = nonzero || c != L'0' ;
	}

	return nonzero ;
}

/** @brief 一つのAutoLogger値の名前と保存先、各ログモードで確認した元DWORD */
struct AutoLoggerValue {
	/// 元値の正式名
	std::wstring_view name ;
	/// DWORDの保存先。FileNameとGuidは別の元フィールドを読む
	std::uint32_t StorageAutoLoggerEffects::*dword ;
	/// HDCのメモリバッファー設定で要求する元DWORD
	std::uint32_t							 expected ;
	/// トリアージダンプ追加を宣言する設定で要求する元DWORD
	std::uint32_t							 triageExpected ;
} ;

// 一つのメモリバッファーセッションとプロバイダーに必要な行の原順と型
constexpr std::array AUTOLOGGER_VALUES{
	AutoLoggerValue{L"LogFileMode", &StorageAutoLoggerEffects::logFileMode, 0x400U, 0x90000400U},
	AutoLoggerValue{L"FileName", nullptr, 0U, 0U},
	AutoLoggerValue{L"Guid", nullptr, 0U, 0U},
	AutoLoggerValue{L"Start", &StorageAutoLoggerEffects::start, 1U, 1U},
	AutoLoggerValue{L"BufferSize", &StorageAutoLoggerEffects::bufferSize, 999U, 5000U},
	AutoLoggerValue{L"EnableProperty", &StorageAutoLoggerEffects::enableProperty, 0U, 0U},
	AutoLoggerValue{L"Enabled", &StorageAutoLoggerEffects::enabled, 1U, 1U},
	AutoLoggerValue{L"EnableLevel", &StorageAutoLoggerEffects::enableLevel, 4U, 4U},
	AutoLoggerValue{L"EnableFlags", &StorageAutoLoggerEffects::enableFlags, 0xffffU, 0xffffU}} ;
constexpr std::size_t AUTOLOGGER_PROVIDER_FIRST = 5U ;	// 原行のプロバイダー値の開始位置

//------------------------------------------------------------------------------
/**
 * @brief 共有AutoLoggerの完全相対パスから単一の正式セッション名を取り出す
 * @param[in] path HKLM配下の元パス。返したビューの利用中も借用する
 * @return 正式な親と単一のASCIIセッション名が成立した場合にその名前、不正なら空
 */
//------------------------------------------------------------------------------
std::wstring_view	  autoLoggerSessionName( std::wstring_view path)
{
	// セッション直下以外のキーや別の親を共有設定に含めない
	constexpr std::wstring_view PREFIX{L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\"} ;
	// 空のセッション名と切り詰めを許さない
	if( path.size() <= PREFIX.size() || !same( path.substr( 0U, PREFIX.size()), PREFIX)) {
		return {} ;
	}

	const auto name = path.substr( PREFIX.size()) ;	// 一つのセッション名
	// 起点を変える文字や埋め込まれた区切りを許さない
	if( name.size() > 64U || !std::ranges::all_of( name, []( wchar_t c) {
		   return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
				  (c >= L'0' && c <= L'9') || c == L'_' || c == L'-' ;
	   })) {
		return {} ;
	}

	return name ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共有設定のセッションと直接子プロバイダーを確認して元セッション名を取り出す
 * @param[in] declared 選択HW節の元設定。返したビューの利用中も借用する
 * @return 共有位置、二つのGUID、直接親子関係が成立すれば終端付きセッション名のビュー、不正なら空
 */
//------------------------------------------------------------------------------
std::wstring_view validatedAutoLoggerSessionName( const StorageAutoLoggerEffects &declared)
{
	const auto session = autoLoggerSessionName( declared.sessionPath) ;	// 元パス末尾のセッション名
	const std::wstring_view provider{declared.providerPath} ;			// プロバイダーの元完全相対パス
	// 共有位置と元GUIDを照合し、単一の直接子以外を作用先に含めない
	if( session.empty() || !validAutoLoggerGuid( declared.sessionGuid) ||
	   !validAutoLoggerGuid( declared.providerGuid) ||
	   same( declared.sessionGuid, declared.providerGuid) ||
	   provider.size() != declared.sessionPath.size() + 39U ||
	   !same( provider.substr( 0U, declared.sessionPath.size()), declared.sessionPath) ||
	   provider[declared.sessionPath.size()] != L'\\' ||
	   !same( provider.substr( declared.sessionPath.size() + 1U), declared.providerGuid)) {
		return {} ;
	}

	return session ;
}

/**
 * @brief ETWの照会ヘッダーと二つの終端付き出力文字列を同じ記憶域に置く
 * @note 現在セッションを読み取る一回の照会だけが参照する
 */
struct AutoLoggerRuntimeQueryBuffer {
	/// ETWが設定と統計を返すヘッダー
	EVENT_TRACE_PROPERTIES	   properties{} ;
	/// セッション名の最大1024文字と終端
	std::array<wchar_t, 1025U> sessionName{} ;
	/// ログファイル名の最大1024文字と終端
	std::array<wchar_t, 1025U> logFileName{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 一つのHW AddReg節に閉じる共有AutoLoggerの全行を検査する
 * @param[in] pending 元HW参照と元操作を含む読み取り位置
 * @param[in] raw 同じ節から読み取った元順の全行
 * @param[in] triageDump トリアージ追加の元モードとバッファーの組を検査する場合true
 * @param[out] result 全行が成立した場合の型付き設定
 * @return 九つの元フィールド組と二つの識別子が成立すれば0、それ以外はHRESULT
 * @note 省略されたFileNameの型・値を補完せず、現在のレジストリは照会しない
 */
//------------------------------------------------------------------------------
NativeError inspectStorageAutoLogger( const PendingSection		  &pending,
									 std::span<const SystemInfRow> raw, bool triageDump,
									 StorageAutoLoggerEffects &result)
{
	// 他の文脈と混在した節や別の操作を共有設定に含めない
	if( pending.deletion || pending.section.scope != SystemInfContext::HARDWARE ||
	   !pending.section.owner.empty() || raw.size() != AUTOLOGGER_VALUES.size() ||
	   raw.front().values.size() != 5U) {
		return UNSUPPORTED ;
	}

	const std::wstring_view sessionPath{raw.front().values[1]} ;	// 元の完全相対パス
	// セッション直下以外のキーや別の親を共有設定に含めない
	if( autoLoggerSessionName( sessionPath).empty()) {
		return UNSUPPORTED ;
	}

	StorageAutoLoggerEffects made ;	// 全行が成立するまで外へ渡さない型付き原値
	made.sessionPath = sessionPath ;
	// 元行の数、順序、型、値を固定の組と一対一で照合する
	for( std::size_t index = 0U; index < raw.size(); ++index) {
		const auto &row		 = raw[index] ;					// 元の行位置とフィールド
		const auto &fields	 = row.values ;					// 省略と明示空を区別した元フィールド
		const auto &value	 = AUTOLOGGER_VALUES[index] ;	// 同じ行位置に必要な値名と型
		const bool	fileName = value.name == L"FileName" ;	// 型と値が省略された唯一の行
		// 同じ行位置にある正式な無名AddRegの全フィールド数を要求する
		if( row.ordinal != index || !row.key.empty() || fields.size() != (fileName ? 3U : 5U) ||
		   !same( fields[0], L"HKLM") || !same( fields[2], value.name)) {
			return UNSUPPORTED ;
		}

		const std::wstring_view path{fields[1]} ;	// 現在の行が指定した元キー
		// セッション側は同一キーと照合し、プロバイダー側はその直下に限定する
		if( index < AUTOLOGGER_PROVIDER_FIRST) {
			// セッション側の全行が同じ一つのキーを指定する必要がある
			if( !same( path, sessionPath)) {
				return UNSUPPORTED ;
			}
		}
		// プロバイダーの最初の元行でキーと識別子を確定する
		else if( made.providerPath.empty()) {
			// プロバイダーはセッション直下の非零GUIDキー一つだけを認める
			if( path.size() != sessionPath.size() + 39U ||
			   !same( path.substr( 0U, sessionPath.size()), sessionPath) ||
			   path[sessionPath.size()] != L'\\') {
				return UNSUPPORTED ;
			}

			const auto guid = path.substr( sessionPath.size() + 1U) ;	// 元プロバイダー識別子
			// セッションの自己参照や不正なGUIDキーを許さない
			if( !validAutoLoggerGuid( guid) || same( guid, made.sessionGuid)) {
				return UNSUPPORTED ;
			}

			made.providerPath = path ;
			made.providerGuid = guid ;
		}
		// 後続のプロバイダー設定も確定した一つのキーを使う
		else if( !same( path, made.providerPath)) {
			return UNSUPPORTED ;
		}

		// FileNameのフラグと値の省略を原行に保持する
		if( fileName) {
			continue ;
		}

		std::uint32_t flags{} ;	// 第4フィールドの明示した元フラグ
		// 既定や空のフラグを明示型として扱わない
		if( !integer( fields[3], flags)) {
			return INVALID ;
		}

		// 型ごとに正式な設定値だけを保持する
		if( value.dword) {
			std::uint32_t number{} ;	// 元DWORDの数値
			const auto	  expected =
				   triageDump ? value.triageExpected : value.expected ;	// 元モードに属する値
			// 他の起動、書き出し、フィルター設定に読み替えない
			if( flags != 0x10001U || !integer( fields[4], number) || number != expected) {
				return UNSUPPORTED ;
			}

			made.*value.dword = number ;
		} else {
			// セッションGUIDは明示REG_SZの非零GUIDのみを保持する
			if( flags != 0U || !validAutoLoggerGuid( fields[4])) {
				return UNSUPPORTED ;
			}

			made.sessionGuid = fields[4] ;
		}
	}

	result = std::move( made) ;
	return 0U ;
}

// 読取り専用レジストリハンドルの所有時だけ、スコープ終了で閉じる
constexpr auto CLOSE_AUTOLOGGER_KEY = []( HKEY key) { RegCloseKey( key) ; } ;
/** @brief レジストリの読み取りと通知だけに使うネイティブハンドルの所有型 */
using AutoLoggerRegistryKey =
	std::unique_ptr<std::remove_pointer_t<HKEY>, decltype( CLOSE_AUTOLOGGER_KEY)> ;

//------------------------------------------------------------------------------
/**
 * @brief Windowsの固定CurrentControlSetリンクから正式なControlSet名を取得する
 * @param[in] key リンクそのものを開いた読み取り専用ハンドル
 * @param[out] name 成功時の単一ControlSet名。失敗時は更新しない
 * @return 直接の正式リンクなら0、不正または読取失敗ならHRESULT
 */
//------------------------------------------------------------------------------
NativeError readAutoLoggerControlSet( HKEY key, std::wstring &name)
{
	// REG_LINKは終端を含まない元のWindowsオブジェクトパス
	constexpr std::wstring_view				PREFIX{L"\\Registry\\Machine\\SYSTEM\\ControlSet"} ;
	std::array<wchar_t, PREFIX.size() + 3U> target{} ;										// 許可するパスの有限長
	DWORD									bytes = static_cast<DWORD>( sizeof( target)) ;	// 元byte数
	DWORD									type{} ;										// Windowsが保存した元型
	// Windows APIへUTF-16の実体をbyte列として渡す
	const auto queried = RegQueryValueExW( key, L"SymbolicLinkValue", nullptr, &type,
										  reinterpret_cast<BYTE *>( target.data()), &bytes) ;
	// 標準のCurrentControlSet名が欠損した状態で他の親を採用しない
	if( queried != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( queried) ;
	}

	const std::wstring_view path{target.data(), target.size()} ;	// 終端を含まない元パス
	const auto				digits = path.substr( PREFIX.size()) ;	// 固定長の番号部分
	// 別hive、別のリンク階層、異なる型、埋め込み終端を拒否する
	if( type != REG_LINK || bytes != sizeof( target) ||
	   !same( path.substr( 0U, PREFIX.size()), PREFIX) || digits == L"000" ||
	   !std::ranges::all_of( digits, []( wchar_t c) { return c >= L'0' && c <= L'9' ; })) {
		return INVALID ;
	}

	name.assign( path.substr( PREFIX.size() - std::wstring_view{L"ControlSet"}.size())) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共有AutoLoggerの元の安全記述子を読み取り書込み主体を限定する
 * @param[in] key 同期中だけ借用するREAD_CONTROLの元ハンドル
 * @param[in] autoLoggerParent EventLogの正式SIDを許可するWindows AutoLogger親の場合true
 * @param[in,out] eventLogInheritance 元親で継承可能なEventLog権限。成功時に次の子向けへ更新する
 * @param[out] security 確認済みの元owner/group/DACL byte。失敗時は更新しない
 * @return 元owner/DACLが成立すれば0、非特権書込みまたは読取不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readAutoLoggerSecurity( HKEY key, bool autoLoggerParent, DWORD &eventLogInheritance,
								   std::vector<std::byte> &security)
{
	// 比較する所有者、グループおよびアクセス制御の項目
	constexpr SECURITY_INFORMATION PARTS =
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION ;
	DWORD	   bytes{} ;													// Windowsから取得する元記述子の必要長
	const auto sized = RegGetKeySecurity( key, PARTS, nullptr, &bytes) ;	// 長さ照会
	// 長さ照会が成立しない場合は元エラーを保持する
	if( sized != ERROR_INSUFFICIENT_BUFFER) {
		return sized == ERROR_SUCCESS ? INVALID : HRESULT_FROM_WIN32( sized) ;
	}

	// 異常な長さの記述子を再確保や部分読取りへ送らない
	if( bytes < sizeof( SECURITY_DESCRIPTOR_RELATIVE) || bytes > 16384U) {
		return INVALID ;
	}

	std::vector<std::byte> raw( bytes) ;										// Windowsが返す自己相対記述子の所有領域
	const auto queried = RegGetKeySecurity( key, PARTS, raw.data(), &bytes) ;	// 一回の再読取り
	// 不足、拡大、読取り失敗を既定のACLへ補完しない
	if( queried != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( queried) ;
	}

	PSID						owner{} ;		// 元記述子内のborrowed owner
	PACL						dacl{} ;		// 元記述子内のborrowed DACL
	BOOL						defaulted{} ;	// APIのowner/DACL元属性
	BOOL						present{} ;		// 明示DACLの実在
	SECURITY_DESCRIPTOR_CONTROL control{} ;		// Windowsの記述子形式
	DWORD						revision{} ;	// Windowsの記述子revision
	// 入力元は同期Win32が埋める自己相対記述子。元長と各標準validatorを確認する
	if( !GetSecurityDescriptorControl( raw.data(), &control, &revision) ||
	   (control & SE_SELF_RELATIVE) == 0U || !IsValidSecurityDescriptor( raw.data()) ||
	   GetSecurityDescriptorLength( raw.data()) != raw.size() ||
	   !GetSecurityDescriptorOwner( raw.data(), &owner, &defaulted) || !owner ||
	   !IsValidSid( owner) || !GetSecurityDescriptorDacl( raw.data(), &present, &dacl, &defaulted) ||
	   !present || !dacl || !IsValidAcl( dacl)) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR) ;
	}

	PSID installerRaw{} ;	// TrustedInstallerの固定SID
	// Windows保守主体の実SIDを数値で構成する
	if( !ConvertStringSidToSidW( L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
							   &installerRaw)) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	const std::unique_ptr<void, decltype( &LocalFree)> installer{installerRaw,
																&LocalFree} ;	// SIDの所有
	PSID eventLogRaw{} ;														// Windowsイベントログサービスの固定SID
	// Windowsが元親から継承を認めた場合だけ、子で同じサービスSIDも照合する
	if( (autoLoggerParent || eventLogInheritance != 0U) &&
	   !ConvertStringSidToSidW( L"S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122",
							   &eventLogRaw)) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	const std::unique_ptr<void, decltype( &LocalFree)> eventLog{eventLogRaw,
															   &LocalFree} ;	// SIDの所有
	const auto trusted = [&]( PSID sid) {										// 記述子または固定SIDを同期中だけ借用する
		return IsWellKnownSid( sid, WinBuiltinAdministratorsSid) ||
			   IsWellKnownSid( sid, WinLocalSystemSid) || EqualSid( sid, installer.get()) ;
	} ;
	// EventLogの例外を元ownerの暗黙の書込み能力へ広げない
	if( !trusted( owner)) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_OWNER) ;
	}

	GENERIC_MAPPING mapping{KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS} ;	// keyの権限写像
	// 作用、置換、権限記述子の変更につながる権限
	constexpr DWORD WRITES =
		KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER ;
	DWORD childEventLogRights{} ;	// このDACLで直接の子に継承できるEventLog権限
	// 現在の書込みと新しい子への継承を一件ずつ確認する
	for( DWORD index = 0U; index < dacl->AceCount; ++index) {
		void *entry{} ;	// 検査済みDACL内の一ACE
		// 読めないACEを省略しない
		if( !GetAce( dacl, index, &entry)) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		const auto header = static_cast<const ACE_HEADER *>( entry) ;	// 一ACEの元ヘッダー
		// 拡張/条件付きACEを一般allow又はdenyとして扱わない
		if( (header->AceType != ACCESS_ALLOWED_ACE_TYPE &&
			header->AceType != ACCESS_DENIED_ACE_TYPE) ||
		   header->AceSize < offsetof( ACCESS_ALLOWED_ACE, SidStart) + GetSidLengthRequired( 0U)) {
			return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		}

		const auto ace		 = static_cast<ACCESS_ALLOWED_ACE *>( entry) ;					// 通常ACEの共通Windows形
		PSID	   sid		 = &ace->SidStart ;												// 元ACEの可変長SIDを同期中だけ借用する
		const auto available = header->AceSize - offsetof( ACCESS_ALLOWED_ACE, SidStart) ;	// SID領域
		// Windows SIDの可変長全体を検査してから参照する
		if( GetSidLengthRequired( static_cast<SID *>( sid)->SubAuthorityCount) != available ||
		   !IsValidSid( sid)) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR) ;
		}

		DWORD mask = ace->Mask ;	// 保存された権限をkey固有の権限へ変換する
		MapGenericMask( &mask, &mapping) ;
		// Creator Ownerは親の既知ownerに支えられるWindowsの継承用プレースホルダー
		const bool creatorOwner = (header->AceFlags & CONTAINER_INHERIT_ACE) != 0U &&
								  IsWellKnownSid( sid, WinCreatorOwnerSid) != FALSE ;
		// 直前の正規親が許可した継承だけ認める
		const bool allowedEventLog =
			eventLog && EqualSid( sid, eventLog.get()) &&
			(autoLoggerParent ||
			 ((header->AceFlags & INHERITED_ACE) != 0U && (mask & ~eventLogInheritance) == 0U)) ;
		// EventLogの明示leaf権限や元親を超える書込みを持ち込まない
		if( (mask & ~static_cast<DWORD>( KEY_ALL_ACCESS)) != 0U ||
		   (header->AceType == ACCESS_ALLOWED_ACE_TYPE && (mask & WRITES) != 0U && !trusted( sid) &&
			!creatorOwner && !allowedEventLog)) {
			return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
		}

		// denyから後続子への許可を推測しない
		if( allowedEventLog && header->AceType == ACCESS_ALLOWED_ACE_TYPE &&
		   (header->AceFlags & CONTAINER_INHERIT_ACE) != 0U) {
			childEventLogRights |= mask ;
		}
	}

	eventLogInheritance = childEventLogRights ;
	security			= std::move( raw) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief リンクとして開いた固定キーが通常キーとして実在することを確認する
 * @param[in] parent 読み取り対象の正規親
 * @param[in] name 親の直接の子キー名
 * @param[in] direct 同じ子をREG_OPTION_OPEN_LINKで開いた通常キー。確認済みリンクならnull
 * @return 参照が通常キーとして成立すれば0、不明なリンクや元のエラーはHRESULT
 */
//------------------------------------------------------------------------------
NativeError requireOrdinaryAutoLoggerKey( HKEY parent, const wchar_t *name, HKEY direct)
{
	// 通常キーの予約値を先に読み、未知リンクのターゲットを開かない
	if( direct) {
		const auto queried =
			RegQueryValueExW( direct, L"SymbolicLinkValue", nullptr, nullptr, nullptr,
							 nullptr) ;	// 名前だけを照会する
		// 予約値の存在も読取り不能も通常キーとして扱わない
		if( queried != ERROR_FILE_NOT_FOUND) {
			return queried == ERROR_SUCCESS ? INVALID : HRESULT_FROM_WIN32( queried) ;
		}
	}

	HKEY	   raw{} ;	// 通常の名前解決で読める同じ位置
	// 通常の名前解決で同じ子を開いた結果
	const auto opened = RegOpenKeyExW( parent, name, 0U, KEY_READ | KEY_WOW64_64KEY, &raw) ;
	const AutoLoggerRegistryKey ordinary{raw} ;	// 通常openの確認用ハンドル
	// ターゲットを持たないリンクを正式な不存在へ変えない
	if( opened != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( opened) ;
	}

	// 標準リンクでは解決後のキーからリンク元の予約値が見えないことを確認する
	if( !direct) {
		const auto queried = RegQueryValueExW( raw, L"SymbolicLinkValue", nullptr, nullptr, nullptr,
											  nullptr) ;	// 解決先に予約値がないかを照会する
		// 値だけを持つ普通のキーを正式リンクに読み替えない
		if( queried != ERROR_FILE_NOT_FOUND) {
			return queried == ERROR_SUCCESS ? INVALID : HRESULT_FROM_WIN32( queried) ;
		}
	}

	return 0U ;
}

/** @brief 監視付きの固定階層で一つのキーが持つ例外 */
enum class StorageRegistryReadRole {
	/// 置換のない既存の通常キー
	ORDINARY,
	/// 読取り時点での正式不在を記録できる通常キー
	ABSENCE_ALLOWED,
	/// Windowsが現在の制御セットを示す正式なリンク
	CURRENT_CONTROL_SET,
	/// Windows EventLogの既定の継承を許可する標準親
	WINDOWS_EVENT_PARENT,
} ;

/** @brief 一回の階層読取りに共通する変更通知とWindowsの観測値 */
struct StorageRegistryReadState {
	/// 開いている親と葉の通知を集約する借用ハンドル
	HANDLE		 changed ;
	/// 正式CurrentControlSetリンクから読み取ったControlSet名
	std::wstring controlSet ;
	/// Windowsの標準親が次の子に継承するイベントログの権限
	DWORD		 eventLogInheritance{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Windowsの固定階層にある直接子を開き、保護と変更監視を確認する
 * @param[in] parent 確認済みの親ハンドル。最初のキーはHKLMを指定する
 * @param[in] name 親の直下にある一つのキー名
 * @param[in] role 正式不在、標準リンク、イベントログの標準親に限った読取り条件
 * @param[in,out] state 同期中の変更通知と現在制御セットの観測
 * @param[out] key 成功時は通知中も保持する通常キーまたは確認済みリンクのハンドル
 * @param[out] security 成功時には保護を検査した元owner、group、DACL
 * @param[in] notify 元キーの変更通知の対象。既定では名前、元値、保護
 * @param[in] watchSubtree trueの場合は当該キーの全配下も同じ通知で監視する
 * @return 成功時0。明示不在を許すキーではkeyを空に保つ。他の不成立は元HRESULT
 */
//------------------------------------------------------------------------------
NativeError readProtectedStorageKey( HKEY parent, const wchar_t *name, StorageRegistryReadRole role,
									StorageRegistryReadState &state, AutoLoggerRegistryKey &key,
									std::vector<std::byte> &security,
									DWORD					notify = REG_NOTIFY_CHANGE_NAME |
												   REG_NOTIFY_CHANGE_LAST_SET |
												   REG_NOTIFY_CHANGE_SECURITY,
									bool watchSubtree = false)
{
	HKEY	   raw{} ;	// 最初にリンクを辿らず開く同じ直接子
	const auto opened = RegOpenKeyExW( parent, name, REG_OPTION_OPEN_LINK,
									  KEY_READ | KEY_WOW64_64KEY, &raw) ;	// 元開く操作の結果
	// 正式親直下の明示不在だけを任意の葉の不在とする
	if( role == StorageRegistryReadRole::ABSENCE_ALLOWED && opened == ERROR_FILE_NOT_FOUND) {
		return 0U ;
	}

	// 保護や位置を確認できない親・リンク・葉は不在へ変更しない
	if( opened != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( opened) ;
	}

	key.reset( raw) ;
	const auto watched = RegNotifyChangeKeyValue( raw, watchSubtree ? TRUE : FALSE, notify,
												 state.changed, TRUE) ;	// 指定した範囲の変更通知
	// 通知が開始できなければ同時点の値と保護として採用できない
	if( watched != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( watched) ;
	}

	const bool currentLink =
		// 唯一許可するリンク
		role == StorageRegistryReadRole::CURRENT_CONTROL_SET ;
	// CurrentControlSetだけはWindowsの正式な直接リンクの元値を先に確認する
	if( currentLink) {
		const auto linked = readAutoLoggerControlSet( raw, state.controlSet) ;	// 元リンクの有限な対象
		// 未確認の制御セットから現在値を読み取らない
		if( linked != 0U) {
			return linked ;
		}
	}

	const auto ordinary = requireOrdinaryAutoLoggerKey(
		parent, name, currentLink ? nullptr : raw) ;	// 正式なキーの照会結果
	// 正式リンク以外の再解決や通常キーの照会失敗を採用しない
	if( ordinary != 0U) {
		return ordinary ;
	}

	return readAutoLoggerSecurity( raw, role == StorageRegistryReadRole::WINDOWS_EVENT_PARENT,
								  state.eventLogInheritance, security) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 読取り済みキーの任意の元DWORDを型と長さを保って取得する
 * @param[in] key 通常キーを保持する読取ハンドル
 * @param[in] name 観測する一つの値名
 * @param[out] result 実在する場合は元DWORD。正式不在と失敗時は空
 * @return 読取りまたは正式な値の不在を確認した場合0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readOptionalStorageDword( HKEY key, const wchar_t *name,
									 std::optional<std::uint32_t> &result)
{
	result.reset() ;
	DWORD	   value{} ;				// Windowsが返す元DWORD
	DWORD	   type{} ;					// レジストリに保存された型
	DWORD	   bytes = sizeof( value) ;	// 型付きの元値を受ける固定長
	// Windows APIへDWORDの格納先をbyte列として渡す
	const auto read =
		RegQueryValueExW( key, name, nullptr, &type, reinterpret_cast<BYTE *>( &value), &bytes) ;
	// 正式に値が不在の場合だけ空の成功を返す
	if( read == ERROR_FILE_NOT_FOUND) {
		return 0U ;
	}

	// 異なる長さ・型や拒否を既知値または不在へ変換しない
	if( read != ERROR_SUCCESS || type != REG_DWORD || bytes != sizeof( value)) {
		return read == ERROR_SUCCESS ? INVALID : HRESULT_FROM_WIN32( read) ;
	}

	result = value ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護の確認済みキーから展開前の任意の文字列を取得する
 * @param[in] key 読取り中の通常キー
 * @param[in] name 読み取る正式な値名
 * @param[out] result 確認済みの元文字列又は正式な不在。失敗時は空
 * @param[out] resultType 成功時の元型。正式不在と失敗時は0
 * @return 文字列又は正式な値の不在を読めた場合0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readOptionalStorageString( HKEY key, const wchar_t *name,
									  std::optional<std::wstring> &result,
									  std::uint32_t				  &resultType)
{
	result.reset() ;
	resultType = 0U ;
	DWORD	   type{} ;		// 展開前にWindowsが記録した元の文字列型
	DWORD	   bytes{} ;	// 文字列の終端を含む元byte数
	// 最初にREG_SZまたはREG_EXPAND_SZの元容量だけを調べる
	const auto sized = RegQueryValueExW( key, name, nullptr, &type, nullptr, &bytes) ;
	// 正式に値が不在の場合は読み取った空文字列へ変換しない
	if( sized == ERROR_FILE_NOT_FOUND) {
		return 0U ;
	}

	// 型の違い、上限超過、途中の照会エラーを切り詰めた表示値へ補完しない
	if( sized != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
	   bytes < sizeof( wchar_t) || bytes % sizeof( wchar_t) != 0U ||
	   bytes > 4096U * sizeof( wchar_t)) {
		return sized == ERROR_SUCCESS ? INVALID : HRESULT_FROM_WIN32( sized) ;
	}

	std::wstring value( bytes / sizeof( wchar_t), L'\0') ;	// 末尾終端を含む可変の元領域
	DWORD		 size		  = bytes ;						// 元サイズ確認に使う実読取り長
	const auto	 originalType = type ;						// 再読取りと比較する元型
	// Windows APIへ文字列の実体をbyte列として渡す
	const auto	 read =
		RegQueryValueExW( key, name, nullptr, &type, reinterpret_cast<BYTE *>( value.data()), &size) ;
	// 取得途中の変更や終端以降の追加文字を保持しない
	if( read != ERROR_SUCCESS || size != bytes || type != originalType ||
	   value.find( L'\0') != value.size() - 1U) {
		return read == ERROR_SUCCESS ? INVALID : HRESULT_FROM_WIN32( read) ;
	}

	value.pop_back() ;
	result	   = std::move( value) ;
	resultType = type ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護された電源キーを開き、存在と時刻を同じハンドルから取得する
 * @param[in] parent 同じ電源階層で保護を確認した親
 * @param[in] name 親の一つの直接子名
 * @param[in] role 必須の既存キーまたは正式な不在を許すキー
 * @param[in,out] state 現在制御セットの観測と関係する全キーの変更監視
 * @param[out] key 存在時に読取り完了まで保持するキー
 * @param[out] snapshot キーの存在、時刻と保護の作業結果
 * @return 保護付き読取り又は正式な不在で0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readStoragePowerKey( HKEY parent, const wchar_t *name, StorageRegistryReadRole role,
								StorageRegistryReadState &state, AutoLoggerRegistryKey &key,
								StoragePowerKeySnapshot &snapshot)
{
	// 通常キーの確認と変更通知を既存の保護付き読取りと共用する
	const auto opened = readProtectedStorageKey( parent, name, role, state, key, snapshot.security) ;
	// 正式不在と開く操作の失敗を別に保持する
	if( opened != 0U || !key) {
		return opened ;
	}

	FILETIME   lastWrite{} ;	// 同じ保持ハンドルの最終書込み時刻
	// 読み取ったキーの更新時刻が調べられない場合は元状態を確定しない
	const auto observed = RegQueryInfoKeyW( key.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
										   nullptr, nullptr, nullptr, nullptr, nullptr, &lastWrite) ;
	// 時刻の省略を正式なキー不在へ変換しない
	if( observed != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( observed) ;
	}

	snapshot.lastWrite =
		(static_cast<std::uint64_t>( lastWrite.dwHighDateTime) << 32U) | lastWrite.dwLowDateTime ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの元電源設定の現在定義・範囲と既定値を同じ制御セットから取得する
 * @param[in] root 正式なPowerSettingsの保護付き親
 * @param[in] setting 元選択でGUIDを検査済みの一つの電源設定
 * @param[in,out] state 同じ現在制御セットと全キーの変更通知
 * @param[in,out] keys サブグループから三つの既定値まで読取り終了まで保持する
 * @param[out] observed 全観測が成立するまで呼出元だけで保持する作業値
 * @return 各値の観測又は明示的な不在の観測で0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readOneStoragePowerSetting( HKEY root, const RangedStoragePowerSetting &setting,
									   StorageRegistryReadState				 &state,
									   std::array<AutoLoggerRegistryKey, 6U> &keys,
									   StoragePowerSettingSnapshot			 &observed)
{
	observed.subgroup = setting.subgroup ;
	observed.setting  = setting.setting ;
	// 括弧だけを除いた検査済みのサブグループと設定の直接子名
	const auto subgroup = setting.subgroup.substr( 1U, 36U) ;
	const auto leaf		= setting.setting.substr( 1U, 36U) ;	// 同じ設定GUIDのキー名
	// サブグループは元INFが参照した既存のWindows設定グループに限る
	auto error = readStoragePowerKey( root, subgroup.c_str(), StorageRegistryReadRole::ORDINARY,
									 state, keys[0U], observed.keys[0U]) ;
	// 存在や保護が不明なグループを電源設定の正式不在としない
	if( error != 0U) {
		return error ;
	}

	error =
		readStoragePowerKey( keys[0U].get(), leaf.c_str(), StorageRegistryReadRole::ABSENCE_ALLOWED,
							state, keys[1U], observed.keys[1U]) ;
	// 元設定がない場合は既定値も正式不在のまま保持する
	if( error != 0U || !keys[1U]) {
		return error ;
	}

	const std::array numbers{std::pair{L"ValueMin", &observed.minimum},
							 std::pair{L"ValueMax", &observed.maximum},
							 std::pair{L"ValueIncrement", &observed.increment},
							 std::pair{L"Attributes", &observed.attributes}} ;	// 同定義の元DWORD
	// 決められた範囲と元属性を、欠損を補わずそれぞれ読み取る
	for( const auto &[name, output] : numbers) {
		error = readOptionalStorageDword( keys[1U].get(), name, *output) ;
		// 値の違う型や参照エラーを既定値に変換しない
		if( error != 0U) {
			return error ;
		}
	}

	const std::array texts{
		std::pair{L"FriendlyName", &observed.displayName},
		std::pair{L"Description", &observed.description},
		std::pair{L"ValueUnits", &observed.unitLabel}} ;	// 定義が変更し得る元の表示値
	// 言語置換や資源展開を行わず、元定義の型と文字列を保持する
	for( const auto &[name, output] : texts) {
		error = readOptionalStorageString( keys[1U].get(), name, output->value, output->type) ;
		// 読み取れない表示のまま正確な現在状態として返さない
		if( error != 0U) {
			return error ;
		}
	}

	error = readStoragePowerKey( keys[1U].get(), L"DefaultPowerSchemeValues",
								StorageRegistryReadRole::ABSENCE_ALLOWED, state, keys[2U],
								observed.keys[2U]) ;
	// 定義の存在と既定値の存在を混同しない
	if( error != 0U || !keys[2U]) {
		return error ;
	}

	// 署名付きValueRangeの既定値配列と同じ三つのWindowsペルソナ順
	constexpr std::array PERSONAS{L"8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
								  L"381b4222-f694-41f0-9685-ff5bb260df2e",
								  L"a1841308-3541-4fab-bc81-f71556f20b4a"} ;
	// 既定値のAC/DCをペルソナごとに読み、正式不在を値0と区別する
	for( std::size_t index = 0U; index < PERSONAS.size(); ++index) {
		const auto keyIndex = index + 3U ;	// 同じ既定値親に属するペルソナの保持位置
		error				= readStoragePowerKey( keys[2U].get(), PERSONAS[index],
												  StorageRegistryReadRole::ABSENCE_ALLOWED, state, keys[keyIndex],
												  observed.keys[keyIndex]) ;
		// 開く操作の失敗を他のペルソナの結果で補わない
		if( error != 0U) {
			return error ;
		}

		// 正式に登録されていないペルソナでは両方の元値を空に保つ
		if( !keys[keyIndex]) {
			continue ;
		}

		error = readOptionalStorageDword( keys[keyIndex].get(), L"ACSettingIndex",
										 observed.defaults[index * 2U]) ;
		// 同じキーのDCも番地を固定して読む
		if( error == 0U) {
			error = readOptionalStorageDword( keys[keyIndex].get(), L"DCSettingIndex",
											 observed.defaults[index * 2U + 1U]) ;
		}

		// 片側が読めない場合は完全な観測として返さない
		if( error != 0U) {
			return error ;
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検査済みの電源設定GUIDのASCII大文字を小文字へ揃える
 * @param[in] guid 既に形を確認した括弧付きGUID
 * @return 比較と保管に使う括弧付き小文字GUID
 */
//------------------------------------------------------------------------------
std::wstring canonicalStoragePowerGuid( std::wstring guid)
{
	// ASCIIの16進桁だけを処理し、レジストリのキー構造は変えない
	for( auto &character : guid) {
		// 大文字表記の同じ設定を別の登録として扱わない
		if( character >= L'A' && character <= L'F') {
			character = static_cast<wchar_t>( character - L'A' + L'a') ;
		}
	}

	return guid ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsがサブグループとして扱うGUIDの一覧を有限に読み取る
 * @param[out] subgroups 確認済みのサブグループGUID。失敗時は呼出元で破棄する
 * @return 列挙が終端まで成立した場合0、元API失敗、不正や上限超過はHRESULT
 * @note 元位置の親の種類を確認する資料とし、設定GUIDの不在確認は別に行う
 */
//------------------------------------------------------------------------------
NativeError readKnownStoragePowerSubgroups( std::set<std::wstring> &subgroups)
{
	constexpr ULONG MAXIMUM_GROUPS = 4096U ;	// 一つの列挙で照合用に受け取る最大件数
	// システムのサブグループを順に確認し、終端、上限超過又はAPI失敗で終了する
	for( ULONG index = 0U; index <= MAXIMUM_GROUPS; ++index) {
		GUID	   id{} ;					// Windowsが返す一件の型付きサブグループ
		DWORD	   bytes = sizeof( id) ;	// APIに渡すGUIDの容量と実出力長
		// Win32のバイト出力へ同じサイズのGUID領域を渡し、成功後に長さを照合する
		const auto error = PowerEnumerate( nullptr, nullptr, nullptr, ACCESS_SUBGROUP, index,
										  reinterpret_cast<UCHAR *>( &id), &bytes) ;
		// 終端まで読めた場合だけ、既知の種別集合として使用する
		if( error == ERROR_NO_MORE_ITEMS) {
			return 0U ;
		}

		// 権限または読取りの失敗を一覧の終端と混同しない
		if( error != ERROR_SUCCESS) {
			return HRESULT_FROM_WIN32( error) ;
		}

		// 上限を超える親を途中まで読んで観測済みとしない
		if( index == MAXIMUM_GROUPS) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		std::array<wchar_t, 39U> name{} ;	// 既存の括弧付きGUID表記と終端
		// APIはGUIDの実バイトを書き出すため、完全な一値だけを表記に変換する
		if( bytes != sizeof( id) ||
		   StringFromGUID2( id, name.data(), static_cast<int>( name.size())) !=
			   static_cast<int>( name.size()) ||
		   !subgroups.insert( canonicalStoragePowerGuid( name.data())).second) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}
	}

	return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護と直接子の変更を監視中のキーから、直下のGUIDキーを名前順に列挙する
 * @param[in] parent 観測完了まで開いている通常キー
 * @param[in,out] remaining 全親で共有する残り子キー件数。GUID以外も数える
 * @param[out] guids 検査が完了した括弧付き小文字GUID。失敗時は呼出元で破棄する
 * @return 全直接子を列挙できた場合0、上限超過やWin32失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError collectStoragePowerGuidChildren( HKEY parent, std::size_t &remaining,
											std::vector<std::wstring> &guids)
{
	guids.clear() ;
	// 未列挙分があるまま確定せず、列挙終端か上限超過又は最初の失敗で止める
	for( DWORD index = 0U;; ++index) {
		std::array<wchar_t, 256U> name{} ;						// Windowsの一キー名上限と終端
		auto	   length = static_cast<DWORD>( name.size()) ;	// API入力は終端を含む容量
		const auto error  = RegEnumKeyExW( parent, index, name.data(), &length, nullptr, nullptr,
										  nullptr, nullptr) ;	// 終端を含まない一子の長さを取得
		// 上限ぴったりの場合も次の子がないことを確認する
		if( error == ERROR_NO_MORE_ITEMS) {
			break ;
		}

		// 一部の子を飛ばした列挙を正常としない
		if( error != ERROR_SUCCESS) {
			return HRESULT_FROM_WIN32( error) ;
		}

		// 対象外の子も列挙費用に含める
		if( remaining == 0U) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		--remaining ;
		// 名前が破損した観測から存在や不在を推定しない
		if( length == 0U || length >= name.size()) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		// 値一覧の補助キー等の名前をGUIDへ読み替えない
		if( length != 36U) {
			continue ;
		}

		std::wstring guid{L"{"} ;	// キー名に元INFと同じ括弧を付けて比較する
		guid.append( name.data(), length).push_back( L'}') ;
		// 全零のGUID名も親として列挙し、候補自身の非零条件は呼出元で維持する
		if( validAutoLoggerGuid( guid) || guid == L"{00000000-0000-0000-0000-000000000000}") {
			guids.push_back( canonicalStoragePowerGuid( std::move( guid))) ;
		}
	}

	std::ranges::sort( guids) ;
	// 大文字小文字を揃えた後の重複は一貫した列挙の結果としない
	return std::ranges::adjacent_find( guids) == guids.end() ? 0U : HRESULT_FROM_WIN32( ERROR_RETRY) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元の設定GUIDをPowerSettingsの直接子と各GUID親の直下から照合する
 * @param[in] root 保護と変更を監視中の同じPowerSettingsキー
 * @param[in,out] state 観測中の現在制御セットと共通の変更通知
 * @param[in,out] settings 元位置を確認済みの設定。各値に登録場所の作業結果を付ける
 * @param[in,out] handles 追加で開いた通常キーを最後の変更確認まで保持する
 * @return 全位置を観測できた場合0、上限、保護、開く操作や元位置との不整合はHRESULT
 * @note 途中失敗時の設定と保持ハンドルは呼出元で破棄する
 */
//------------------------------------------------------------------------------
NativeError readStoragePowerLocations( HKEY root, StorageRegistryReadState &state,
									  std::span<StoragePowerSettingSnapshot> settings,
									  std::vector<AutoLoggerRegistryKey>	&handles)
{
	std::size_t				  remaining = 4096U ;								// 直下と各GUID親の直接子を含む残り列挙枠
	std::vector<std::wstring> groups ;											// 保護付きで確認する同じルート直下のGUID名
	auto error = collectStoragePowerGuidChildren( root, remaining, groups) ;	// 全直接子の列挙
	// 親の集合を取得し切れない場合、正確な登録場所は返せない
	if( error != 0U) {
		return error ;
	}

	std::set<std::wstring> knownSubgroups ;	// 同じWindowsが実際にサブグループと区別する親
	error = readKnownStoragePowerSubgroups( knownSubgroups) ;
	// 親の種類が未確認のまま、候補の元位置を正式なサブグループとして扱わない
	if( error != 0U) {
		return error ;
	}

	std::map<std::wstring, StoragePowerSettingSnapshot *> requested ;	// 元順を保つ借用索引
	// 候補ごとに元サブグループを確認し、直接子のGUIDで探せるようにする
	for( auto &setting : settings) {
		const auto expected = canonicalStoragePowerGuid( setting.subgroup) ;	// 名前順で比較する元位置
		// 先に開いた元位置が列挙から欠落した場合は同時点の結果としない
		if( !std::ranges::binary_search( groups, expected)) {
			return HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}

		// 実在する直接子でも、サブグループなしの設定や種別不明のキーを親と認めない
		if( !knownSubgroups.contains( expected)) {
			return HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
		}

		setting.locations.emplace() ;
		requested.emplace( canonicalStoragePowerGuid( setting.setting), &setting) ;
	}

	std::vector<std::wstring> children ;	// 現在の一親から読む直接子のGUID
	std::vector<std::byte>	  security ;	// 保護判定用の再利用領域
	// 元サブグループを含む全GUID親を、順に同じ保護条件で読み取る
	for( const auto &group : groups) {
		const auto groupName = group.substr( 1U, 36U) ;	// 括弧のない正規の直接子名
		auto	  &groupKey	 = handles.emplace_back() ;	// 観測完了まで保持する親ハンドル
		error = readProtectedStorageKey( root, groupName.c_str(), StorageRegistryReadRole::ORDINARY,
										state, groupKey, security) ;
		// リンクや保護不明の親は配下を不在として扱えない
		if( error != 0U) {
			return error ;
		}

		const HKEY parent	 = groupKey.get() ;			// 保持容器が拡張されても有効な観測ハンドル
		const auto rootMatch = requested.find( group) ;	// サブグループに属さない定義等との同名
		// 直下で一致した名前を別位置の可能性として保持する
		if( rootMatch != requested.end()) {
			rootMatch->second->locations->rootMatch = true ;
		}

		error = collectStoragePowerGuidChildren( parent, remaining, children) ;
		// 一親の未確認でも全域の正式不在を返さない
		if( error != 0U) {
			return error ;
		}

		// 各GUID子を元設定の索引で照合し、一致したキーだけを開いて保護を確認する
		for( const auto &child : children) {
			const auto match = requested.find( child) ;	// 同じ設定に結ぶ作業値の位置
			// 別の定義は一致場所に含めない
			if( match == requested.end()) {
				continue ;
			}

			const auto name = child.substr( 1U, 36U) ;	// 列挙した同じ直接子だけを開く
			error = readProtectedStorageKey( parent, name.c_str(), StorageRegistryReadRole::ORDINARY,
											state, handles.emplace_back(), security) ;
			// 列挙後に消失したり置き換わったキーを正常な不在としない
			if( error != 0U) {
				return error ;
			}

			match->second->locations->matchingSubgroups.push_back( group) ;
		}
	}

	// 元位置の値と列挙結果の双方で、同じ設定の存在が一致することを確認する
	for( const auto &setting : settings) {
		const auto expected = canonicalStoragePowerGuid( setting.subgroup) ;	// 元宣言のサブグループ
		const auto present	= std::ranges::binary_search( setting.locations->matchingSubgroups,
														 expected) ;	// 全域で観測した元位置の存在
		// 途中で元位置の存在が変わった結果は採用しない
		if( present != setting.keys[1U].lastWrite.has_value()) {
			return HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共有AutoLoggerの実キー直下の値、数、元時刻を照合する
 * @param[in] key 読取りと変更通知を開始したセッションまたはプロバイダーのハンドル
 * @param[in] isProvider プロバイダーの実キーならtrue
 * @param[in,out] snapshot 検査済みの期待値を保持し、成功時には実GUIDの表記と実時刻を取得する
 * @return 元キーの完全な構造と型付き値が成立すれば0、不一致や読取失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError inspectCurrentAutoLoggerValues( HKEY key, bool isProvider,
										   StorageAutoLoggerSnapshot &snapshot)
{
	auto &observed = *snapshot.existing ;								// 確定前の型付き葉の作業値
	const std::span<const AutoLoggerValue> rules{AUTOLOGGER_VALUES} ;	// 元HW節と共用する規則
	const auto values = isProvider ? rules.subspan( AUTOLOGGER_PROVIDER_FIRST)
								   : rules.first( AUTOLOGGER_PROVIDER_FIRST) ;	// 今回の値の閉集合
	// 同一キーに本来ある名前と型だけを一度ずつ検証する
	for( const auto &rule : values) {
		DWORD type{} ;	// 生のレジストリ型
		// DWORDは正確な4 byteを要求し、別表記に読み替えない
		if( rule.dword) {
			DWORD	   value{} ;				// 元DWORDの読取り先
			DWORD	   bytes = sizeof( value) ;	// 応答の有限容量と元長
			// Windows APIへDWORDの実体をbyte列として渡す
			const auto queried = RegQueryValueExW( key, rule.name.data(), nullptr, &type,
												  reinterpret_cast<BYTE *>( &value), &bytes) ;
			// 欠落や取得不能を期待値で埋めない
			if( queried != ERROR_SUCCESS) {
				return HRESULT_FROM_WIN32( queried) ;
			}

			// 型、長さ、元値のいずれが異なっても採用しない
			if( type != REG_DWORD || bytes != sizeof( value) || value != observed.*rule.dword) {
				return INVALID ;
			}
		}
		// FileNameの許可範囲は正式な不存在または終端付きの明示空REG_SZ
		else if( rule.name == L"FileName") {
			wchar_t	   value{} ;				// 空REG_SZに必要な唯一のUTF-16終端
			DWORD	   bytes = sizeof( value) ;	// 応答の有限容量と元長
			// Windows APIへUTF-16終端の実体をbyte列として渡す
			const auto queried = RegQueryValueExW( key, rule.name.data(), nullptr, &type,
												  reinterpret_cast<BYTE *>( &value), &bytes) ;
			// 存在しない値だけを省略として扱う
			if( queried == ERROR_FILE_NOT_FOUND) {
				continue ;
			}

			// 読めない値やより長い実値を省略へ変えない
			if( queried != ERROR_SUCCESS) {
				return HRESULT_FROM_WIN32( queried) ;
			}

			// パス、展開型、非終端の表記は保持しない
			if( type != REG_SZ || bytes != sizeof( value) || value != L'\0') {
				return INVALID ;
			}

			snapshot.fileNamePresent = true ;
		} else {
			std::array<wchar_t, 39U> value{} ;							// 括弧付きGUIDと末尾の唯一のUTF-16終端
			DWORD	   bytes = static_cast<DWORD>( sizeof( value)) ;	// 応答の有限容量と元長
			// Windows APIへUTF-16の実体をbyte列として渡す
			const auto queried = RegQueryValueExW( key, rule.name.data(), nullptr, &type,
												  reinterpret_cast<BYTE *>( value.data()), &bytes) ;
			// 取得失敗した場合は既知GUIDで補完しない
			if( queried != ERROR_SUCCESS) {
				return HRESULT_FROM_WIN32( queried) ;
			}

			const std::wstring_view guid{value.data(), value.size() - 1U} ;	// 終端を除いた元表記
			// 元GUIDと同じ識別子で終端が実在するREG_SZだけを保持する
			if( type != REG_SZ || bytes != sizeof( value) || value.back() != L'\0' ||
			   !same( guid, observed.sessionGuid)) {
				return INVALID ;
			}

			observed.sessionGuid.assign( guid) ;
		}
	}

	DWORD	   children{} ;		// 実キーの直下の子数
	DWORD	   count{} ;		// 無名値も含む実キーの値数
	FILETIME   lastWrite{} ;	// Windowsが記録した元の最終書込み時刻
	// 閉集合の件数と元の最終書込み時刻を取得した結果
	const auto queried = RegQueryInfoKeyW( key, nullptr, nullptr, nullptr, &children, nullptr,
										  nullptr, &count, nullptr, nullptr, nullptr, &lastWrite) ;
	// 未確定の件数を閉集合に変換しない
	if( queried != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( queried) ;
	}

	// 意図しない子、無名値、追加のETW設定がないことを全数で確認する
	if( children != (isProvider ? 0U : 1U) ||
	   count != values.size() - (!isProvider && !snapshot.fileNamePresent ? 1U : 0U)) {
		return INVALID ;
	}

	snapshot.leafLastWrite[isProvider ? 1U : 0U] =
		(static_cast<std::uint64_t>( lastWrite.dwHighDateTime) << 32U) | lastWrite.dwLowDateTime ;
	return 0U ;
}

/** @brief 同じサービス所有のSystemイベント資源を原グラフへ結合する作業値 */
struct StorageEventGraphState {
	/// 元イベント資源リストの二番目に必要な同SYSの完全名
	std::wstring eventBinary ;
	/// 一つの元イベント資源リストを確認した場合にtrue
	bool		 resourcesFound{} ;
	/// 一つの元イベント種別値を確認した場合にtrue
	bool		 typesFound{} ;
} ;

/** @brief 自動起動補助を持つ選択でだけ認めるレジストリ行の原型と所有範囲 */
struct AutoStartRegistryRule {
	/// HKRまたは明示したHKLMです
	std::wstring_view			root ;
	/// 元レジストリの完全サブキーです
	std::wstring_view			subkey ;
	/// 元DWORDの値名です
	std::wstring_view			name ;
	/// 観測した元DWORDです
	std::uint32_t				value ;
	/// HKRを評価する機器またはサービスの元文脈です
	SystemInfContext			scope ;
	/// 一行の型付き作用です
	StorageInfAction			action ;
	/// 元節の行数と、この元行の位置です
	std::array<std::size_t, 2U> position ;
} ;

// 関連サービス内の機能2行、機器側DMAの2行、サービス側DMAの順に対を保持する
constexpr std::array AUTO_START_REGISTRY_RULES{
	AutoStartRegistryRule{L"HKR",
						  L"Parameters",
						  L"StorageSupportedFeatures",
						  1U,
						  SystemInfContext::SERVICE,
						  StorageInfAction::SERVICE_STORAGE_FEATURES,
						  {2U, 0U}},
	AutoStartRegistryRule{L"HKLM",
						  L"SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters",
						  L"StorageSupportedFeatures",
						  1U,
						  SystemInfContext::SERVICE,
						  StorageInfAction::SHARED_ACPI_STORAGE_FEATURES,
						  {2U, 1U}},
	AutoStartRegistryRule{L"HKR",
						  L"DMA Management",
						  L"RemappingSupported",
						  1U,
						  SystemInfContext::HARDWARE,
						  StorageInfAction::DEVICE_DMA_SUPPORT,
						  {2U, 0U}},
	AutoStartRegistryRule{L"HKR",
						  L"DMA Management",
						  L"RemappingFlags",
						  1U,
						  SystemInfContext::HARDWARE,
						  StorageInfAction::DEVICE_DMA_FLAGS,
						  {2U, 1U}},
	AutoStartRegistryRule{L"HKR",
						  L"Parameters",
						  L"DmaRemappingCompatible",
						  2U,
						  SystemInfContext::SERVICE,
						  StorageInfAction::SERVICE_DMA_COMPATIBILITY,
						  {1U, 0U}},
} ;

/** @brief 自動起動補助の共通グラフで型付き行の重複と必須の組を確認する作業値 */
struct AutoStartInfGraphState {
	/// 関連サービスとの対応を保った各レジストリ行の元節名。未検出なら空
	std::array<std::wstring, AUTO_START_REGISTRY_RULES.size()> registrySections ;
	/// 補助サービスがAddServiceの第6欄で明示したイベント源
	std::wstring_view										   auxiliaryEventName ;
	/// 同じ元選択で確認したイベント用DLLコピー。省略の場合はnull
	const SelectedStorageCopyFact							  *eventMessageCopy{} ;
	/// 関連サービスに属する元イベントと署名済み資源の確認状態
	StorageEventGraphState									   associatedEvent ;
	/// 補助イベントの種別値が一度だけ成立した状態
	bool													   namedTypesFound{} ;
	/// 補助イベントのカテゴリ数が一度だけ成立した状態
	bool													   namedCategoryFound{} ;
	/// 元コピーと一致する資源一覧が一度だけ成立した状態
	bool													   namedMessageFound{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 共有ACPIとDMAの元DWORDを署名付きの機器または関連サービスの作用へ分類する
 * @param[in] effect 元レジストリ節の文脈、所有者と一行の全欄
 * @param[in] serviceName 同じ選択に結び付いた関連ブートサービス
 * @param[in] deletion 元節がDelRegから参照された場合true
 * @param[in] count 元節の全行数
 * @param[in,out] sections 各元作用が属する節名。重複はエラーになる
 * @param[in,out] sharedAcpi 選択が別のWindows ACPIサービスへ指定する元DWORD
 * @param[in,out] action 確認した作用。その他の相対レジストリ行は未分類のまま返す
 * @return 元行が照合できる、または一般の相対レジストリ行なら0。それ以外はHRESULT
 * @note 現在のレジストリやサービスを読み書きしない
 */
//------------------------------------------------------------------------------
NativeError inspectAutoStartRegistry(
	const SystemInfEffect &effect, std::wstring_view serviceName, bool deletion, std::size_t count,
	std::array<std::wstring, AUTO_START_REGISTRY_RULES.size()> &sections,
	std::optional<std::uint32_t> &sharedAcpi, StorageInfAction &action)
{
	const auto &fields = effect.row.values ;	// 省略も含む全欄
	// 対象の元行は非削除の無名行に限り、値名と作用を同じ欄から読む
	if( deletion || !effect.row.key.empty() || fields.size() < 3U) {
		return UNSUPPORTED ;
	}

	const auto rule = std::ranges::find_if( AUTO_START_REGISTRY_RULES, [&]( const auto &entry) {
		return same( fields[2], entry.name) && same( fields[0], entry.root) ;
	}) ; // 同じ名前を持つ自サービスとACPIを元rootで分けた規則
	// 専用名の別rootと未知の共有作用は一般のレジストリデータに含めない
	if( rule == AUTO_START_REGISTRY_RULES.end()) {
		const std::wstring_view key{fields[1]} ;			// 元の相対サブキー
		const std::wstring_view dmaKey{L"DMA Management"} ;	// 機器側DMAを定義する専用サブキー
		return !same( fields[0], L"HKR") || same( key, dmaKey) ||
					   (key.size() > dmaKey.size() && key[dmaKey.size()] == L'\\' &&
						same( key.substr( 0U, dmaKey.size()), dmaKey)) ||
					   std::ranges::any_of(
						   AUTO_START_REGISTRY_RULES,
						   [&]( const auto &entry) { return same( fields[2], entry.name) ; })
				   ? UNSUPPORTED
				   : 0U ;
	}

	const auto index = static_cast<std::size_t>(
		rule - AUTO_START_REGISTRY_RULES.begin()) ;	// 同じ作用の重複を検出する位置
	const bool	  ownerMatches = rule->scope == SystemInfContext::SERVICE
									 ? same( effect.source.owner, serviceName)
									 : effect.source.owner.empty() ;	// 元文脈の所有先
	std::uint32_t flag{} ;												// DWORDの型を含む元のフラグ
	std::uint32_t value{} ;												// 省略や切捨てを行わない元DWORD
	// 宣言の文脈、パス、型、値を一組として確認し、別値や別機器への作用を認めない
	if( !sections[index].empty() || effect.source.scope != rule->scope || !ownerMatches ||
	   count != rule->position[0] || effect.row.ordinal != rule->position[1] ||
	   !same( fields[1], rule->subkey) || fields.size() != 5U || !integer( fields[3], flag) ||
	   flag != 0x10001U || !integer( fields[4], value) || value != rule->value) {
		return UNSUPPORTED ;
	}

	sections[index] = effect.source.name ;
	action			= rule->action ;
	// 共有ACPIの場合だけ元DWORDを端末の現在値との照合へ渡す
	if( action == StorageInfAction::SHARED_ACPI_STORAGE_FEATURES) {
		sharedAcpi = value ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自動起動補助の名前付きSystemイベントの元DWORDと任意の資源を照合する
 * @param[in] effect 同じ署名文書にある元イベントの行
 * @param[in] api 同じWindowsの既存資源を検証する操作
 * @param[in,out] automatic 名前付きイベント源と重複を確認する状態
 * @return 種別・カテゴリ・明示資源の元値が一意に成立すれば0、それ以外はHRESULT
 * @note 元の資源行省略を保持する。現在の設定から旧資源の残存は判定しない
 */
//------------------------------------------------------------------------------
NativeError inspectNamedStorageEventRow( const SystemInfEffect	 &effect,
										const SystemInfEffectApi &api,
										AutoStartInfGraphState	 &automatic)
{
	const auto	 &fields = effect.row.values ;	// イベント登録の全欄
	std::uint32_t type{} ;						// 元レジストリフラグ
	// 同じ名前付きイベントのルートに属する元の一値だけを扱う
	if( !effect.row.key.empty() || !same( effect.source.owner, automatic.auxiliaryEventName) ||
	   fields.size() != 5U || !same( fields[0], L"HKR") || !fields[1].empty() ||
	   !integer( fields[3], type)) {
		return UNSUPPORTED ;
	}

	// 同じ元コピーが存在するときだけ、二要素の展開可能文字列を許可する
	if( same( fields[2], L"EventMessageFile")) {
		const auto *copy = automatic.eventMessageCopy ;	// 同じ選択の元CATに属するDLL
		// 候補の元コピーがない行や別形式を許可しない
		if( !copy || automatic.namedMessageFound || type != 0x20000U || copy->dirid != 11 ||
		   copy->fields.size() != 1U) {
			return UNSUPPORTED ;
		}

		constexpr std::wstring_view windowsResource{
			L"%SystemRoot%\\System32\\IoLogMsg.dll"} ;	// 元Windowsイベント資源
		const auto expected = std::wstring{windowsResource} + L";%SystemRoot%\\System32\\" +
							  // 順序と全内容の一致を要求する二つの元パス
							  copy->fields.front() ;
		// 追加要素、別のファイル名や相対位置から資源を読み替えない
		if( !same( fields[4], expected)) {
			return UNSUPPORTED ;
		}

		const auto error =
			// 既存のWindows標準資源
			api.module( effect.source.document, windowsResource) ;
		automatic.namedMessageFound = error == 0U ;
		return error ;
	}

	std::uint32_t value{} ;	// 元DWORD
	// 種別とカテゴリは従来どおり元DWORDを要求する
	if( type != 0x10001U || !integer( fields[4], value)) {
		return UNSUPPORTED ;
	}

	// 種別マスクは元のSystemイベントの型で一度だけ保持する
	if( same( fields[2], L"TypesSupported") && value == 31U && !automatic.namedTypesFound) {
		automatic.namedTypesFound = true ;
		return 0U ;
	}

	// カテゴリ数は種別および省略された資源行と独立に確認する
	if( same( fields[2], L"CategoryCount") && value == 1U && !automatic.namedCategoryFound) {
		automatic.namedCategoryFound = true ;
		return 0U ;
	}

	return UNSUPPORTED ;
}

/** @brief HDCの必須作用を一度ずつ原グラフへ結合する作業値 */
struct HdcInfGraphState {
	/// 同CATのSYSに結ぶ一つの元直接コピー参照
	std::wstring		   directCopy ;
	/// 関連サービスが所有するイベント資源の確認状態
	StorageEventGraphState event ;
	/// 元の二節とIDEブートサービスに限定する場合にtrue
	bool				   legacyIde{} ;
	/// 一つの元コピー行を確認した場合にtrue
	bool				   copyFound{} ;
} ;

// HDCの一つのカーネルサービスに必須のスカラー宣言
constexpr std::array HDC_SERVICE_FIELDS{L"ServiceType", L"StartType", L"ErrorControl",
										L"ServiceBinary", L"LoadOrderGroup"} ;

//------------------------------------------------------------------------------
/**
 * @brief HDCの元節ごとに評価済みのディレクティブだけを選ぶ
 * @param[in] section 同じPACKAGEから読んだ元節と文脈
 * @param[in] row 元の全フィールドと順番
 * @param[in,out] hdc 順位とコピーの重複検出に用いる作業値
 * @param[in,out] score 一回だけ認める基本節の元順位
 * @return 閉じたHDC構成の作用として評価できる場合true
 */
//------------------------------------------------------------------------------
bool				 inspectHdcDirective( const SystemInfSection &section, const SystemInfRow &row,
										 HdcInfGraphState &hdc, std::optional<std::uint32_t> &score)
{
	const bool addReg = same( row.key, L"AddReg") ;	// 親文脈を保持する唯一のレジストリ参照
	// 基本節は単一SYSのコピーと元順位だけを持つ
	switch( section.context) {
		case SystemInfContext::DEVICE:
			// 同じドライバーの直接コピーは一回だけ許可する
			if( same( row.key, L"CopyFiles") && !hdc.copyFound && row.values.size() == 1U &&
			   same( row.values.front(), hdc.directCopy)) {
				hdc.copyFound = true ;
				return true ;
			}

			// 0x80の一つの原順位を確認し、フィールド表記は原行に保持する
			if( !hdc.legacyIde && same( row.key, L"FeatureScore") && !score &&
			   row.values.size() == 1U && same( row.values.front(), L"0x80")) {
				score = 0x80U ;
				return true ;
			}

			return false ;
		// ハードウェア節は元の設定データだけを参照する
		case SystemInfContext::HARDWARE:
			return !hdc.legacyIde && addReg ;
		// サービス節では関連サービス一つの宣言だけを読む
		case SystemInfContext::SERVICES:
			return same( row.key, L"AddService") ;
		// イベント節でレジストリの参照を一つに限定する
		case SystemInfContext::EVENT_LOG:
			return !hdc.legacyIde && addReg && row.ordinal == 0U && row.values.size() == 1U ;
		// サービス設定では既知のスカラー宣言と元設定データだけを許可する
		case SystemInfContext::SERVICE:
			return (!hdc.legacyIde &&
					(addReg || same( row.key, L"DisplayName") || same( row.key, L"Description"))) ||
				   std::ranges::any_of( HDC_SERVICE_FIELDS,
									   [&]( const auto key) { return same( row.key, key) ; }) ;
		// 他の付随節の作用を扱わない
		default:
			return false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Systemイベント登録を元のWindows資源と同CATのSYSに結合する
 * @param[in] effect 元イベントソース所有のレジストリ行
 * @param[in] owner 元AddServiceが所有するイベントソース名
 * @param[in] api 元Windows保護資源を検証する呼出元の操作
 * @param[in,out] event 同一所有者の二つのイベント登録の重複を保持する作業値
 * @return 二つのイベント設定とWindows資源に問題がなければ0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError inspectStorageEventRow( const SystemInfEffect &effect, std::wstring_view owner,
								   const SystemInfEffectApi &api, StorageEventGraphState &event)
{
	const auto	 &fields = effect.row.values ;	// 元のイベント設定行を全フィールドのまま借用する
	std::uint32_t flags{} ;						// 型と追加の作用を表す元フラグ
	// 同じサービスのSystemイベント登録以外を認めない
	if( effect.source.owner != owner || fields.size() != 5U || !same( fields[0], L"HKR") ||
	   !fields[1].empty() || !integer( fields[3], flags)) {
		return UNSUPPORTED ;
	}

	// EventLogの元種別値に必要な型と値を一度だけ確認する
	if( same( fields[2], L"TypesSupported")) {
		std::uint32_t types{} ;	// 元種別マスク
		// 不明な型、重複、異なる種別を既定値へ変更しない
		if( event.typesFound || flags != 0x10001U || !integer( fields[4], types) || types != 7U) {
			return UNSUPPORTED ;
		}

		event.typesFound = true ;
		return 0U ;
	}

	constexpr std::wstring_view windowsResource{
		L"%SystemRoot%\\System32\\IoLogMsg.dll"} ;	// 元リストの一番目
	const auto expected =
		std::wstring{windowsResource} + L";" + event.eventBinary ;	// 元リストと比較する完全形
	// Windows資源、同CATのSYSをこの順番の完全な二要素に限定する
	if( event.resourcesFound || !same( fields[2], L"EventMessageFile") || flags != 0x20000U ||
	   !same( fields[4], expected)) {
		return UNSUPPORTED ;
	}

	event.resourcesFound = true ;
	return api.module( effect.source.document, windowsResource) ;
}

/** @brief Windowsが解析した補助サービスの自己相対記述子を所有する型 */
using AuxiliaryServiceSecurityDescriptor = std::unique_ptr<void, decltype( &LocalFree)> ;

//------------------------------------------------------------------------------
/**
 * @brief 要求時起動サービスの元保護記述子を有限の権限と監査へ検査する
 * @param[in] text 元サービス設定の完全なSDDL。同期中だけ借用する
 * @param[out] verified null以外なら全検査成功時にだけ元記述子の所有を引き渡す
 * @return 予定したDACLと失敗監査だけなら0、それ以外はHRESULT
 * @note Windowsで記述子を解析する。サービスや権限は変更しない
 */
//------------------------------------------------------------------------------
NativeError inspectAuxiliaryServiceSecurity( const std::wstring				   &text,
											AuxiliaryServiceSecurityDescriptor *verified = nullptr)
{
	// 空値、過長やNUL以降の原宣言をWindowsが省略する入力を認めない
	if( text.empty() || text.size() > 4096U || text.find( L'\0') != text.npos) {
		return INVALID ;
	}

	PSECURITY_DESCRIPTOR raw{} ;	// Windowsが返す自己相対記述子
	// 構文不成立を既定セキュリティへ変更しない
	if( !ConvertStringSecurityDescriptorToSecurityDescriptorW( text.c_str(), SDDL_REVISION_1, &raw,
															 nullptr)) {
		const auto error = GetLastError() ;	// Windowsの元構文診断
		return error == ERROR_SUCCESS ? INVALID : HRESULT_FROM_WIN32( error) ;
	}

	AuxiliaryServiceSecurityDescriptor descriptor{raw, &LocalFree} ;	// 記述子の局所所有
	PSID						owner{} ;								// 元記述子に所有者を指定していないことを確認する借用値
	PSID						group{} ;								// 元記述子にグループを指定していないことを確認する借用値
	BOOL						defaulted{} ;							// Windowsが返す記述子の既定化フラグ
	BOOL						present{} ;								// 各ACLの実在を区別するフラグ
	PACL						dacl{} ;								// 元サービスの許可ACL
	PACL						sacl{} ;								// 元サービスの監査ACL
	SECURITY_DESCRIPTOR_CONTROL control{} ;								// 元の継承とACL存在を保持する制御値
	DWORD						revision{} ;							// Windowsが読むセキュリティ記述子版
	// 未指定のowner/group、空ACL、他の制御フラグを補わず拒否する
	if( !IsValidSecurityDescriptor( raw) || !GetSecurityDescriptorOwner( raw, &owner, &defaulted) ||
	   owner || !GetSecurityDescriptorGroup( raw, &group, &defaulted) || group ||
	   !GetSecurityDescriptorControl( raw, &control, &revision) ||
	   revision != SECURITY_DESCRIPTOR_REVISION ||
	   control !=
		   (SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT | SE_DACL_AUTO_INHERIT_REQ) ||
	   !GetSecurityDescriptorDacl( raw, &present, &dacl, &defaulted) || !present || !dacl ||
	   !IsValidAcl( dacl) || dacl->AceCount != 3U ||
	   !GetSecurityDescriptorSacl( raw, &present, &sacl, &defaulted) || !present || !sacl ||
	   !IsValidAcl( sacl) || sacl->AceCount != 1U) {
		return UNSUPPORTED ;
	}

	// 管理者、LocalSystem、対話利用者の三主体に限定する
	constexpr std::array principals{WinBuiltinAdministratorsSid, WinLocalSystemSid,
									WinInteractiveSid} ;
	// 対話利用者には照会と元のユーザー定義制御を保持する
	constexpr DWORD interactiveAccess = READ_CONTROL | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
										SERVICE_ENUMERATE_DEPENDENTS | SERVICE_INTERROGATE |
										SERVICE_USER_DEFINED_CONTROL ;
	// 元順の許可ACEだけを読み、起動、書換えなどの権限追加を拒否する
	for( DWORD index = 0U; index < principals.size(); ++index) {
		void *entry{} ;	// Windowsの有効なACLから一要素を同期借用する
		// 元要素を読めない場合はサービスの保護形を確定しない
		if( !GetAce( dacl, index, &entry) || !entry) {
			return INVALID ;
		}

		const auto *header = static_cast<const ACE_HEADER *>( entry) ;	// 識別と長さだけを読む元ACE
		// 既知型と大きさを確認してから型付きACEを読む
		if( header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0U ||
		   header->AceSize < sizeof( ACCESS_ALLOWED_ACE)) {
			return UNSUPPORTED ;
		}

		auto *const access = static_cast<ACCESS_ALLOWED_ACE *>( entry) ;	// Windowsが確定した許可ACE
		// 各主体と原マスクを同じ順序で保持する
		if( access->Mask != (index == 2U ? interactiveAccess : SERVICE_ALL_ACCESS) ||
		   !IsWellKnownSid( &access->SidStart, principals[index])) {
			return UNSUPPORTED ;
		}
	}

	void *entry{} ;	// 同じ元SACLから借用する唯一の監査ACE
	// 読み取れない監査や成功監査を元の失敗監査と混同しない
	if( !GetAce( sacl, 0U, &entry) || !entry) {
		return INVALID ;
	}

	const auto *header = static_cast<const ACE_HEADER *>( entry) ;	// 識別と長さだけを読む元ACE
	// Windowsが生成した元監査ACEの型とサイズを確認する
	if( header->AceType != SYSTEM_AUDIT_ACE_TYPE || header->AceFlags != FAILED_ACCESS_ACE_FLAG ||
	   header->AceSize < sizeof( SYSTEM_AUDIT_ACE)) {
		return UNSUPPORTED ;
	}

	auto *const audit = static_cast<SYSTEM_AUDIT_ACE *>( entry) ;	// Windowsが確定した監査ACE
	// 元の失敗監査と主体が成立する場合にだけ署名元の記述子を渡す
	if( audit->Mask != SERVICE_ALL_ACCESS || !IsWellKnownSid( &audit->SidStart, WinWorldSid)) {
		return UNSUPPORTED ;
	}

	// 現在の保護を照合する呼出元だけが解析済み記述子を保持する
	if( verified) {
		*verified = std::move( descriptor) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在のSCMコマンドが署名元の一つのSystem32実行ファイルを指すことを確認する
 * @param[in] current 引数を含めた現在のSCMの元文字列
 * @param[in] declared 登録とコピー先を照合済みのSystem32絶対パス
 * @return 同じ絶対パスか限定変数形で、曖昧な実行や引数がなければtrue
 */
//------------------------------------------------------------------------------
bool matchesAuxiliaryServiceBinary( std::wstring_view current, std::wstring_view declared)
{
	// 既にWindowsのSystem32へ確認したパスの構成だけを、許容する変数形の生成に使う
	const auto					leafStart = declared.find_last_of( L'\\') ;
	constexpr std::wstring_view system32{L"\\System32\\"} ;	// 元絶対パスに必要な親
	// ルートやファイル名の欠損、引用、別のパス解釈を持つ元宣言を許容しない
	if( declared.size() > 4096U || leafStart == declared.npos || leafStart <= system32.size() + 1U ||
	   declared.substr( 1U, 2U) != L":\\" || declared.find_first_of( L"%/\"") != declared.npos ||
	   std::ranges::any_of( declared, []( wchar_t c) { return c < L' ' || c == 0x7f ; })) {
		return false ;
	}

	// System32から末尾までの元表記を過不足なく確認する
	const auto tail = declared.substr( leafStart + 1U - system32.size()) ;
	const auto leaf = tail.substr( system32.size()) ;	// 同じ元実行ファイルのleaf
	// 元宣言が通常のドライブ文字とSystem32直下のEXEだけであることを確認する
	if( !((declared.front() >= L'A' && declared.front() <= L'Z') ||
		 (declared.front() >= L'a' && declared.front() <= L'z')) ||
	   !same( tail.substr( 0U, system32.size()), system32) || leaf.size() <= 4U ||
	   !isSafeOfficialArchiveMember( leaf, L'\\') || !same( leaf.substr( leaf.size() - 4U), L".exe")) {
		return false ;
	}

	// 先頭から末尾までを囲む一組の引用符だけを除く
	if( current.size() >= 2U && current.front() == L'"' && current.back() == L'"') {
		current.remove_prefix( 1U) ;
		current.remove_suffix( 1U) ;
	}
	// 変数展開後に空白を含む場合も、引用符なしで別の実行ファイルを選ばせない
	else if( declared.find( L' ') != declared.npos) {
		return false ;
	}

	constexpr std::wstring_view systemRoot{L"%SystemRoot%"} ;	// 許容する唯一の変数の元表記
	return same( current, declared) || (same( current.substr( 0U, systemRoot.size()), systemRoot) &&
									   same( current.substr( systemRoot.size()), tail)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自己相対記述子の参照先が記述子内にあることを確認する
 * @param[in] bytes SCMから得た同一の自己相対記述子の全バイト
 * @param[in] offset 記述子の先頭を起点とする元のDWORD位置
 * @param[in] minimum 参照先の長さ情報を安全に読むために必要な最小サイズ
 * @return 位置が指定され、範囲内なら参照先から末尾まで。失敗時は空
 */
//------------------------------------------------------------------------------
std::span<const std::byte> auxiliaryDescriptorComponent( std::span<const std::byte> bytes,
														DWORD offset, std::size_t minimum)
{
	// 未指定、元ヘッダーとの重なり、非整列、範囲外を借用ポインターへ変換しない
	if( offset < sizeof( SECURITY_DESCRIPTOR_RELATIVE) || offset % alignof( DWORD) != 0U ||
	   offset > bytes.size() || minimum > bytes.size() - offset) {
		return {} ;
	}

	return bytes.subspan( offset) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 自己相対記述子の一つのSIDを範囲内で検証する
 * @param[in] bytes 同じSCM記述子の全バイト。返したSIDの使用中だけ借用する
 * @param[in] offset 同じ記述子のowner又はgroupの元位置
 * @return 記述子内の有効なSIDの借用ポインター。不成立ならnull
 */
//------------------------------------------------------------------------------
PSID auxiliaryDescriptorSid( std::span<const std::byte> bytes, DWORD offset)
{
	// SIDの可変長を読む前に元の固定ヘッダーを確認する
	const auto sid = auxiliaryDescriptorComponent( bytes, offset, offsetof( SID, SubAuthority)) ;
	// SIDがなければSCMの既定主体を推測しない
	if( sid.empty()) {
		return nullptr ;
	}

	// 元SIDが持つ可変長の構成要素数
	const auto count = std::to_integer<UCHAR>( sid[offsetof( SID, SubAuthorityCount)]) ;
	// 元バッファ以外をSIDとして検査しない
	if( count > SID_MAX_SUB_AUTHORITIES || GetSidLengthRequired( count) > sid.size()) {
		return nullptr ;
	}

	auto *value = const_cast<std::byte *>( sid.data()) ;	// Windowsの読取りAPIへ渡す借用SID
	return IsValidSid( value) ? value : nullptr ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの現在ACLの全ACEを署名元の検査済みACLへ比較する
 * @param[in] bytes 同じSCM記述子の全バイト
 * @param[in] offset 同じ記述子内のDACL又はSACLの元位置
 * @param[in] declared 署名元SDDLから検査した同種のACLを同期借用する
 * @return 記述子内の有効なACLで、種類・フラグ・マスク・SIDを元順で一致できればtrue
 */
//------------------------------------------------------------------------------
bool matchesAuxiliaryServiceAcl( std::span<const std::byte> bytes, DWORD offset, PACL declared)
{
	const auto actual = auxiliaryDescriptorComponent( bytes, offset, sizeof( ACL)) ;	// 元ACLの位置
	// NULL ACLや記述子の外側への参照を認めない
	if( actual.empty()) {
		return false ;
	}

	ACL header{} ;	// 可変長ACLのサイズと要素数を持つ固定ヘッダー
	std::memcpy( &header, actual.data(), sizeof( header)) ;
	// 元ACLの範囲と要素数を確定してからACEを比較する
	if( header.AclSize < sizeof( header) || header.AclSize > actual.size() ||
	   header.AceCount != declared->AceCount) {
		return false ;
	}

	auto entries = actual.first( header.AclSize).subspan( sizeof( header)) ;	// 未比較の元領域
	// 型、マスク、SIDとフラグを保持する元ACEを同じ数と順で完全比較する
	for( DWORD index = 0U; index < declared->AceCount; ++index) {
		void *entry{} ;	// 検査済みの署名元ACLのACEを同期借用する
		// 元ACEを取得できない場合は別の権限設定で補わない
		if( !GetAce( declared, index, &entry) || !entry) {
			return false ;
		}

		const auto length = static_cast<const ACE_HEADER *>( entry)->AceSize ;	// 元ACEの全長
		// 署名元ACEの全長で現在の型、長さ、権限、主体を照合する
		if( length > entries.size() || std::memcmp( entries.data(), entry, length) != 0) {
			return false ;
		}

		entries = entries.subspan( length) ;
	}

	// 全ACEを範囲内で照合できた現在ACLの構造をWindowsで検証する
	return IsValidAcl( static_cast<PACL>(
			   static_cast<void *>( const_cast<std::byte *>( actual.data())))) != FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在の補助サービスの所有者と二つのACLを署名元の設定へ照合する
 * @param[in] bytes SCMが返した元の自己相対記述子。比較後も同じ全バイトを保持する
 * @param[in] sddl 同じ登録済みINFが宣言する元サービスのセキュリティ設定
 * @return 記述子の構造、所有者、グループ、許可と監査が成立すれば0、失敗時はHRESULT
 */
//------------------------------------------------------------------------------
NativeError matchAuxiliaryServiceSecurity( std::span<const std::byte> bytes,
										  const std::wstring		&sddl)
{
	AuxiliaryServiceSecurityDescriptor declared{nullptr, &LocalFree} ;		// 署名元SDDLの検査済み記述子
	const auto error = inspectAuxiliaryServiceSecurity( sddl, &declared) ;	// 元SDDLの検査結果
	// 検査済みの元SDDLと完全な現在観測が揃う場合にだけ比較する
	if( error != 0U || bytes.size() < sizeof( SECURITY_DESCRIPTOR_RELATIVE) || bytes.size() > 8192U) {
		return error != 0U ? error : INVALID ;
	}

	SECURITY_DESCRIPTOR_RELATIVE actual{} ;	// 現在の元制御フラグと各参照位置
	std::memcpy( &actual, bytes.data(), sizeof( actual)) ;
	// SCM側で変わり得るDACLの自動継承処理の記録ビットだけを比較から外す
	constexpr auto daclBookkeeping = SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED ;
	constexpr auto requiredControl =
		SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT ;	// 必須の記述子形式とACL
	// DACLとSACLの明示設定・自己相対形式を要求し、保護と監査の制御差は認めない
	if( actual.Revision != SECURITY_DESCRIPTOR_REVISION || actual.Sbz1 != 0U ||
	   (actual.Control & ~daclBookkeeping) != requiredControl) {
		return UNSUPPORTED ;
	}

	const auto owner = auxiliaryDescriptorSid( bytes, actual.Owner) ;	// 現在の所有者SID
	// 所有権を管理者又はLocalSystemへ限定し、現在のグループも有効なSIDを要求する
	if( !owner || !auxiliaryDescriptorSid( bytes, actual.Group) ||
	   (!IsWellKnownSid( owner, WinLocalSystemSid) &&
		!IsWellKnownSid( owner, WinBuiltinAdministratorsSid))) {
		return UNSUPPORTED ;
	}

	PACL dacl{} ;		// Windowsが解析済みの元DACL
	PACL sacl{} ;		// Windowsが解析済みの元SACL
	BOOL present{} ;	// 元記述子のACL存在を示す値
	BOOL defaulted{} ;	// 元記述子のACL既定化を示す値
	// 解析済みの両ACLを別々に取得して、現在の許可と監査とを照合する
	if( !GetSecurityDescriptorDacl( declared.get(), &present, &dacl, &defaulted) || !present ||
	   !dacl || !GetSecurityDescriptorSacl( declared.get(), &present, &sacl, &defaulted) ||
	   !present || !sacl || !matchesAuxiliaryServiceAcl( bytes, actual.Dacl, dacl) ||
	   !matchesAuxiliaryServiceAcl( bytes, actual.Sacl, sacl)) {
		return UNSUPPORTED ;
	}

	// 各参照先を範囲内に限定した元バイトを最後にWindowsで確認する
	auto *raw = const_cast<std::byte *>( bytes.data()) ;	// 読取りAPIだけに渡す同一の元記述子
	return IsValidSecurityDescriptor( raw) && GetSecurityDescriptorLength( raw) == bytes.size()
			   ? 0U
			   : INVALID ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 選択機器の元HW節にあるトリアージ指定付き共有AutoLoggerを読み取る
 * @param[in] hardware 署名と適用元を照合した同じ文書の選択HW節
 * @param[in] api 選択時の元文書読取と共用する節・レジストリ行の制限
 * @param[out] result 元値の全行を検査した設定。該当なしと失敗時は空
 * @return 元宣言の読取りと型の照合が成立した場合0、それ以外はHRESULT
 * @note 共有設定の現在値、所有や復旧は判定せず、導入資格を発行しない
 */
//------------------------------------------------------------------------------
NativeError readStorageTriageAutoLogger( const SystemInfSection					&hardware,
										const SystemInfEffectApi				&api,
										std::optional<StorageAutoLoggerEffects> &result)
{
	result.reset() ;
	// 元の機器設定から直接到達する同文書の無所有者参照だけを使う
	if( hardware.document == 0U || hardware.context != SystemInfContext::HARDWARE ||
	   hardware.scope != SystemInfContext::HARDWARE || !hardware.owner.empty() || !api.read ||
	   !api.registryRows) {
		return INVALID ;
	}

	std::vector<SystemInfRow> directives ;			// 元選択HW節の全宣言
	auto error = api.read( hardware, directives) ;	// 元節を読めなかった場合の診断
	// 読み取れない元節を共有設定なしへ変更しない
	if( error != 0U || directives.size() > 4096U) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	std::optional<StorageAutoLoggerEffects> made ;			// 全参照成立後にだけ結果へ渡す設定
	std::vector<std::wstring>				references ;	// 実際に読み取った同文書のAddReg節
	// 選択元に現れたすべての直接AddReg参照を元順で調べる
	for( const auto &directive : directives) {
		// 他の作用は共有AutoLoggerに分類しない
		if( !same( directive.key, L"AddReg")) {
			continue ;
		}

		// 空参照や読取り側の欄制限を超えた宣言を成功にしない
		if( directive.values.empty() || directive.values.size() > 64U) {
			return INVALID ;
		}

		// 一宣言が参照する全節を調べ、最初の共有設定だけで終了しない
		for( const auto &name : directive.values) {
			// 空名、過長、同じ元節を二度適用する参照を認めない
			if( name.empty() || name.size() > 255U ||
			   std::ranges::any_of( references, [&]( const auto &old) { return same( old, name) ; })) {
				return INVALID ;
			}

			// 元グラフで消費した辺と合わせて追加参照を制限する
			if( references.size() >= 1023U || api.graphReferences >= 4096U - references.size()) {
				return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			references.push_back( name) ;
			const PendingSection pending{
				{hardware.document, name, SystemInfContext::REGISTRY, hardware.scope, {}},
				false} ;					// 元HWの直接レジストリ参照
			std::vector<SystemInfRow> raw ;	// 一つの参照節の全行と元省略
			error = api.read( pending.section, raw) ;
			// 部分読取りと全レジストリ行の共通上限超過を拒否する
			if( error != 0U || *api.registryRows > 4096U || raw.size() > 4096U - *api.registryRows) {
				return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			*api.registryRows += raw.size() ;
			// 共有の絶対行を含む節は全行で型を照合し、相対レジストリ行とは混ぜない
			if( std::ranges::any_of( raw, []( const auto &row) {
				   return !row.values.empty() && same( row.values.front(), L"HKLM") ;
			   })) {
				// 一つの署名付き機器選択の結果に複数の共有セッションを含めない
				if( made) {
					return UNSUPPORTED ;
				}

				error = inspectStorageAutoLogger( pending, raw, true, made.emplace()) ;
				// 型や元値に不一致があれば、以前に読めた一部を返さない
				if( error != 0U) {
					return error ;
				}
			}
		}
	}

	result = std::move( made) ;
	return 0U ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 要求時起動と自動起動の補助に共通する現在の実行条件を照合する
 * @param[in] actual 同じサービスの構成、状態、追加設定と保護の安定した観測
 * @param[in] name 同じ補助サービスの署名付き登録から確認した元名
 * @param[in] start 同じ元宣言の開始方式
 * @param[in] errorControl 同じ元宣言の障害時制御
 * @param[in] group 元の起動順グループ。未指定は空
 * @return 共通の実行条件が成立すれば0、設定や状態が不一致ならHRESULT
 * @note 実行ファイルとセキュリティ記述子は各配置経路で別に検査する
 */
//------------------------------------------------------------------------------
NativeError matchAuxiliaryServiceExecution( const AuxiliaryStorageServiceSnapshot &actual,
										   std::wstring_view name, std::uint32_t start,
										   std::uint32_t errorControl, std::wstring_view group)
{
	const auto &config = actual.config ;	// SCMの基本構成を全項目のまま同期借用する
	// 一つのWin32サービスで元構成と同じ開始方式・エラー制御・依存の不存在を要求する
	if( name.empty() || !same( config.name, name) || config.type != SERVICE_WIN32_OWN_PROCESS ||
	   config.start != start || config.errorControl != errorControl || config.tag != 0U ||
	   (group.empty() ? !config.group.empty() : !same( config.group, group)) ||
	   !config.dependencies.empty()) {
		return UNSUPPORTED ;
	}

	// 元INFが省略したアカウントを同じ組み込みLocalSystemの既知表記だけへ結ぶ
	if( !same( config.account, L"LocalSystem") && !same( config.account, L".\\LocalSystem") &&
	   !same( config.account, L"NT AUTHORITY\\SYSTEM")) {
		return UNSUPPORTED ;
	}

	const auto &status = actual.status ;	// 元の実行状態と遷移の元数値を保持する
	// 処理中の状態や未完了の応答を示す数値を安定した停止・実行として扱わない
	if( status.state == SERVICE_START_PENDING || status.state == SERVICE_STOP_PENDING ||
	   status.state == SERVICE_PAUSE_PENDING || status.state == SERVICE_CONTINUE_PENDING ||
	   status.checkpoint != 0U || status.waitHint != 0U) {
		return HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	// 同じ型が安定して停止中又は実行中である場合だけ既存所有の照合へ進む
	if( status.type != SERVICE_WIN32_OWN_PROCESS ||
	   (status.state != SERVICE_STOPPED && status.state != SERVICE_RUNNING)) {
		return UNSUPPORTED ;
	}

	// 無作用の回復項目だけを許し、起動・再起動・コマンドや開始条件・特権の追加を拒む
	if( !actual.failureCommand.empty() || !actual.failureRebootMessage.empty() ||
	   std::ranges::any_of( actual.failureActions,
						   []( const auto &action) { return action.front() != SC_ACTION_NONE ; }) ||
	   !actual.triggers.empty() || actual.delayedAutoStart ||
	   actual.serviceSidType != SERVICE_SID_TYPE_NONE || !actual.requiredPrivileges.empty() ||
	   actual.launchProtection != SERVICE_LAUNCH_PROTECTED_NONE) {
		return UNSUPPORTED ;
	}

	// 優先NUMAの既知の照会非対応は元診断のまま保持し、その他の読取失敗は伝える
	if( actual.preferredNodeError != 0U &&
	   actual.preferredNodeError != HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER)) {
		return actual.preferredNodeError ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief ストレージ補助が指定した実行条件を元のグループなしで確認する
 * @param[in] actual 同じサービスの完全なSCM観測
 * @param[in] declared 同じ現用署名元に結び付いた補助サービス
 * @return 元実行条件が成立して0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError matchStorageAuxiliaryServiceExecution( const AuxiliaryStorageServiceSnapshot &actual,
												  const RegisteredStorageHelperEvidence &declared)
{
	return declared.type == SERVICE_WIN32_OWN_PROCESS
			   ? matchAuxiliaryServiceExecution( actual, declared.name, declared.start,
												declared.errorControl, {})
			   : UNSUPPORTED ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 現在のDisplay補助サービスの実行条件を署名付き現用INFの宣言へ照合する
 * @param[in] declaration 現用サービスのクラス、開始指定とグループまで照合済みの元宣言
 * @param[in] actual 同じSCMサービスの元構成と保護付き観測
 * @return 宣言の実行条件と現在構成が同じ場合0、失敗はHRESULT
 * @note SCMコマンドに対応するファイルとCATは呼出側が照合する
 */
//------------------------------------------------------------------------------
NativeError matchDisplayAuxiliaryServiceExecution(
	const OfficialDisplayAuxiliaryService &declaration,
	const AuxiliaryStorageServiceSnapshot &actual)
{
	// 元が省略した表示設定は現用名を用いる既知のSCM状態だけに結び付ける
	if( !same( actual.config.display, declaration.serviceName) ||
	   !actual.config.description.empty() || actual.config.security.empty() ||
	   (!declaration.loadOrderGroup.empty() && !same( declaration.loadOrderGroup, L"Event log"))) {
		return UNSUPPORTED ;
	}

	return matchAuxiliaryServiceExecution( actual, declaration.serviceName, SERVICE_AUTO_START,
										  SERVICE_ERROR_NORMAL, declaration.loadOrderGroup) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現用署名パッケージの実行ファイルと同じ補助サービスのSCM構成を照合する
 * @param[in] registered 同じ選択の公開名・実節・元署名を確認した現用パッケージ
 * @param[out] observation 同じ構成と実EXEの二度の完全観測。失敗時は空
 * @return 現用の元実行条件と正規ファイルが一致して0、それ以外はHRESULT
 * @note 読取専用。端末上の他デバイスとの共用や導入許可はここでは決めない
 */
//------------------------------------------------------------------------------
NativeError readRegisteredDisplayAuxiliaryService(
	const RegisteredDisplayAuxiliaryPackage &registered,
	DisplayAuxiliaryServiceObservation		&observation)
{
	observation = {} ;
	// 同じ現用元INFとCATが確認されていない実行パスを使わない
	if( !registered.storeFile.existing || !registered.catalogFile.existing ||
	   registered.executablePath.empty() || registered.executableSha256.size() != 64U) {
		return E_INVALIDARG ;
	}

	try {
		const auto read = [&registered]( DisplayAuxiliaryServiceObservation &result) {
			// 元INFと同じ名前のSCM登録を一件だけ照会する
			auto error =
				readDisplayAuxiliaryScmSnapshot( registered.declaration.serviceName, result.service) ;
			// 同名でも元の実行範囲や起動指定が異なる状態は選択外として扱う
			if( error == 0U) {
				error =
					matchDisplayAuxiliaryServiceExecution( registered.declaration, result.service) ;
			}

			// SCMが署名検査済みの完全位置を指定する場合だけ実ファイルを読む
			if( error == 0U) {
				error = readRegisteredDriverStoreExecutableSnapshot(
					result.service.config.binary, registered.executablePath, result.executable) ;
			}

			// 元CAT比較時の実バイトとの完全一致を要求する
			if( error == 0U && (!result.executable.existing ||
							   result.executable.existing->sha256 != registered.executableSha256)) {
				return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
			}

			return error ;
		} ; // 元署名の証拠を二度の同期読取の間だけ借用する

		DisplayAuxiliaryServiceObservation made ;					// 全照合前は外へ渡さない一回目の観測
		DisplayAuxiliaryServiceObservation fresh ;					// 設定と実体の入れ替わりを調べる二回目の観測
		auto							   error = read( made) ;	// 同じSCMと実ファイルの元診断
		// 一回目の失敗は別時点の成功で補完しない
		if( error == 0U) {
			error = read( fresh) ;
		}

		// 状態、構成、権限、実ファイル識別子と元byteを全て再比較する
		if( error != 0U || made != fresh) {
			return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}

		observation = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 要求時起動の補助サービスを署名元のSystem32宛先と明示された保護に照合する
 * @param[in] actual 確認済みの現在構成、状態、保護
 * @param[in] declared 署名付き元選択の実行条件、System32宛先と元SDDL
 * @return 実行条件と保護の一致時0、違いや観測の不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError matchRegisteredStorageAuxiliaryService( const AuxiliaryStorageServiceSnapshot &actual,
												   const RegisteredStorageHelperEvidence &declared)
{
	// 従来経路では元INFが同じSystem32直下に登録した要求時起動だけを照合する
	if( declared.start != SERVICE_DEMAND_START ||
	   !matchesAuxiliaryServiceBinary( actual.config.binary, declared.binary)) {
		return UNSUPPORTED ;
	}

	const auto error = matchStorageAuxiliaryServiceExecution( actual, declared) ;	// 共通の実行条件
	return error != 0U ? error
					   : matchAuxiliaryServiceSecurity( actual.config.security, declared.security) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ロード順の元文字列から対象ストレージグループの位置を確認する
 * @param[in] groups 終端を含む元の複数文字列
 * @param[out] order 正しい順序の位置。失敗時は空の値
 * @param[in] legacyIde IDEブートサービスのグループを確認する場合true
 * @return 完全かつ一意の順序が成立すれば0、それ以外は元診断
 */
//------------------------------------------------------------------------------
NativeError inspectStorageLoadOrder( const std::span<const wchar_t> groups, StorageLoadOrder &order,
									bool legacyIde)
{
	order = {} ;
	// 元の終端を追加せず、全長と二つのNULを検証する
	if( groups.size() < 3U || groups.size() > 16384U || groups.back() != L'\0' ||
	   groups[groups.size() - 2U] != L'\0') {
		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	const auto				   last = groups.end() - 1 ;	// 最後のNULは一覧全体の終端
	std::optional<std::size_t> miniport, deviceClass ;		// 完全な元一覧で見つけた位置
	std::optional<std::size_t> systemBusExtender ;			// IDEブートのグループ位置
	std::size_t				   precedingCharacters{} ;		// 対象グループより前の元文字列長
	std::size_t				   position{} ;					// 現在確認しているグループの順序
	// 先に必要な二つが見つかっても末尾まで確認する
	for( auto cursor = groups.begin(); cursor != last; ++position) {
		const auto end = std::find( cursor, last, L'\0') ;	// 現在の名前の終端
		// 一覧途中の空文字列や名前の切り詰めを拒否する
		if( end == last || end == cursor) {
			return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
		}

		// 現在のREG_MULTI_SZ項目の名前
		const std::wstring_view name{&*cursor, static_cast<std::size_t>( end - cursor)} ;
		// 現在の名前に対応する確認対象の位置
		auto				   *selected = legacyIde
											   ? (same( name, L"System Bus Extender") ? &systemBusExtender : nullptr)
											   : (same( name, L"SCSI Miniport") ? &miniport
												  : same( name, L"SCSI Class")  ? &deviceClass
																			   : nullptr) ;
		// 必要グループは大文字小文字を区別せず、重複なく保持する
		if( selected) {
			// 同じ名前が二度現れた一覧を拒否する
			if( *selected) {
				return HRESULT_FROM_WIN32( ERROR_DUP_NAME) ;
			}

			*selected = position ;
			// 対象の前を通過する順序変更も比較する
			if( legacyIde) {
				precedingCharacters = static_cast<std::size_t>( cursor - groups.begin()) ;
			}
		}

		cursor = end + 1 ;
	}

	// IDEでは関係する一つの起動グループの位置を保持する
	if( legacyIde) {
		// 起動グループが消えた場合は資格を作らない
		if( !systemBusExtender) {
			return UNSUPPORTED ;
		}

		try {
			order.precedingGroups.assign( groups.data(), precedingCharacters) ;
		} catch( const std::bad_alloc &) {
			return E_OUTOFMEMORY ;
		}

		order.systemBusExtender = systemBusExtender ;
		return 0U ;
	}

	// 不在や逆順を既定の順序で補完しない
	if( !miniport || !deviceClass || *miniport >= *deviceClass) {
		return UNSUPPORTED ;
	}

	order = {*miniport, *deviceClass, std::nullopt, {}} ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在のWindowsの固定レジストリ値から起動グループの順序を読む
 * @param[out] order 読み取りと検査に成功した位置
 * @param[in] legacyIde System Bus Extenderの位置を確認する場合true
 * @return 順序が成立すれば0、読み取りまたは順序の不成立はHRESULT
 * @note REG_MULTI_SZの終端を補完せず、キーとサービスに書き込まない
 */
//------------------------------------------------------------------------------
NativeError readStorageLoadOrder( StorageLoadOrder &order, bool legacyIde)
{
	order = {} ;
	HKEY	   key{} ;	// 固定されたWindowsの設定を照会するハンドル
	// Windowsのキーを読み取り専用で開いた結果
	const auto opened =
		RegOpenKeyExW( HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ServiceGroupOrder",
					  0U, KEY_QUERY_VALUE, &key) ;
	// 読み取れない設定から既定の順序を作らない
	if( opened != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( opened) ;
	}

	std::array<wchar_t, 16384U> groups{} ;	// 元の型と終端を保つ有限バッファー
	// APIが返す元文字列の長さ
	DWORD						bytes = sizeof( groups) ;
	// レジストリが返す元の型
	DWORD						type{} ;
	// 終端を補完せず読み取った結果
	const auto					read = RegQueryValueExW( key, L"List", nullptr, &type,
														reinterpret_cast<BYTE *>( groups.data()), &bytes) ;
	RegCloseKey( key) ;
	// 上限超過や読み取り失敗を部分的な許可へ変更しない
	if( read != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( read) ;
	}

	// 元型と長さを検証してから文字列を渡す
	if( type != REG_MULTI_SZ || bytes > sizeof( groups) || bytes % sizeof( wchar_t) != 0U) {
		return HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
	}

	return inspectStorageLoadOrder( {groups.data(), bytes / sizeof( wchar_t)}, order, legacyIde) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元選択のAutoLogger作用先を読み取り専用で調べる
 * @param[in] desired INFの選択HW節から検査済みの一セッションと一プロバイダー
 * @param[out] snapshot 両キーの正式不在または保護された完全な現在値。失敗時は空
 * @param[in] profile 選択が宣言した元ログモード
 * @return 読み取り成功0、保護、値、形、安定性の不成立または読取失敗はHRESULT
 * @note サービスへの所有結合は呼出元が確認する。レジストリ値やACLは変更しない
 */
//------------------------------------------------------------------------------
NativeError readStorageAutoLoggerSnapshot( const StorageAutoLoggerEffects &desired,
										  StorageAutoLoggerSnapshot		 &snapshot,
										  StorageAutoLoggerProfile		  profile)
{
	snapshot = {} ;
	const bool triage =
		// 元選択が指定した二つ目の組
		profile == StorageAutoLoggerProfile::TRIAGE_BUFFER ;
	// 呼出側の未知プロファイルをHDCの既定に置き換えない
	if( !triage && profile != StorageAutoLoggerProfile::MEMORY_BUFFER) {
		return INVALID ;
	}

	const auto session = validatedAutoLoggerSessionName( desired) ;	// 直接親子関係を確認した元の名前
	// 開く前に、元の共有位置と選択モードに対応する全DWORDを確認する
	if( session.empty() ||
	   std::ranges::any_of( AUTOLOGGER_VALUES, [&desired, triage]( const AutoLoggerValue &value) {
		   return value.dword &&
				  desired.*value.dword != (triage ? value.triageExpected : value.expected) ;
	   })) {
		return INVALID ;
	}

	try {
		// 開き続けた全キーの名前、値、権限の変更を一つの一時イベントへ集約する
		const std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype( &CloseHandle)> event{
			CreateEventW( nullptr, TRUE, FALSE, nullptr), &CloseHandle} ;
		// 通知を開始できない環境では観測を安定済みへ補完しない
		if( !event) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		StorageAutoLoggerSnapshot made ;	// 全キーの読取り成功まで公開しない元証拠
		// SYSTEMを起点に標準リンクとその正規の対象を独立して開く
		constexpr std::size_t	  SYSTEM_ROOT = 0U ;
		// 標準リンクから確認した実制御セットの位置
		constexpr std::size_t	  CONTROL_SET = 2U ;
		// 元INFが指定したセッションの位置
		constexpr std::size_t	  SESSION = 6U ;
		// 同セッションが持つプロバイダーの位置
		constexpr std::size_t	  PROVIDER = 7U ;
		// リンクとその実体を別々に開く読取り順
		const std::array		  names{
			 L"SYSTEM",		 L"CurrentControlSet",		  L"", L"Control", L"WMI", L"Autologger",
			 session.data(), desired.providerGuid.c_str()} ;
		std::array<AutoLoggerRegistryKey, names.size()> keys ;	// 変更通知終了まで開いたまま保持する
		StorageRegistryReadState state{event.get(), {}, 0U} ;	// 全元キーの観測状態
		constexpr std::array	 roles{
			StorageRegistryReadRole::ORDINARY,		  StorageRegistryReadRole::CURRENT_CONTROL_SET,
			StorageRegistryReadRole::ORDINARY,		  StorageRegistryReadRole::ORDINARY,
			StorageRegistryReadRole::ORDINARY,		  StorageRegistryReadRole::WINDOWS_EVENT_PARENT,
			StorageRegistryReadRole::ABSENCE_ALLOWED, StorageRegistryReadRole::ORDINARY,
		} ; // 正式不在はセッションだけ。存在するならプロバイダーを要求する
		// 正規の各直接子だけを順に読み、完全不在の場合は葉を開かない
		for( std::size_t index = 0U; index < names.size(); ++index) {
			const HKEY parent =
				index == SYSTEM_ROOT
					? HKEY_LOCAL_MACHINE
					: keys[index == CONTROL_SET ? SYSTEM_ROOT : index - 1U].get() ;	// 元の直接親
			const wchar_t *name =
				// 固定の子名
				index == CONTROL_SET ? state.controlSet.c_str() : names[index] ;
			const auto error =
				readProtectedStorageKey( parent, name, roles[index], state, keys[index],
										made.security[index]) ;	// 元保護・名前・読取り中の変更監視
			// 権限拒否、リンク異常、読取不能は不在としない
			if( error != 0U) {
				return error ;
			}

			// 正式不在のセッションにプロバイダーの親を補完しない
			if( !keys[index]) {
				break ;
			}
		}

		made.controlSet = std::move( state.controlSet) ;

		// 葉がある場合は既に両キーを開いてあり、その閉じた全値を照合する
		if( keys[SESSION]) {
			made.existing = desired ;
			// 元セッションのプロパティと子の閉集合を照合した結果
			const auto sessionRead =
				inspectCurrentAutoLoggerValues( keys[SESSION].get(), false, made) ;
			// セッションの値や子が不一致ならプロバイダーだけでは成立しない
			if( sessionRead != 0U) {
				return sessionRead ;
			}

			// 元プロバイダーの型付き設定を照合した結果
			const auto providerRead =
				inspectCurrentAutoLoggerValues( keys[PROVIDER].get(), true, made) ;
			// 同名の別設定を正式なプロバイダーとして採用しない
			if( providerRead != 0U) {
				return providerRead ;
			}
		}

		const auto changed = WaitForSingleObject( event.get(), 0U) ;	// 同一観測内の変更を確認
		// API失敗と読取中の変更を各元結果で拒否する
		if( changed != WAIT_TIMEOUT) {
			return HRESULT_FROM_WIN32( changed == WAIT_FAILED ? GetLastError() : ERROR_RETRY) ;
		}

		snapshot = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元AutoLoggerのセッション名で現在のETW稼働状態を読み取る
 * @param[in] declared INFの選択HW節から検査済みの一セッションと一プロバイダー
 * @param[out] present 照会成功ならtrue、ETWが元セッションの不在を返した場合はfalse。失敗時は変更しない
 * @return 稼働またはERROR_WMI_INSTANCE_NOT_FOUNDを確認できた場合0、引数不正やその他の照会失敗はHRESULT
 * @note セッション名で照会する。ETWの構成、セッション状態、レジストリは変更しない
 */
//------------------------------------------------------------------------------
NativeError readStorageAutoLoggerRuntimePresence( const StorageAutoLoggerEffects &declared,
												 bool							&present)
{
	const auto session = validatedAutoLoggerSessionName( declared) ;	// 直接親子関係を確認した元の名前
	// 元セッションに結び付けられない名前はETWへ渡さない
	if( session.empty()) {
		return INVALID ;
	}

	AutoLoggerRuntimeQueryBuffer buffer{} ;	// ETWが返すヘッダー、名前、パスの固定容量
	buffer.properties.Wnode.BufferSize = static_cast<ULONG>( sizeof( buffer)) ;
	buffer.properties.LoggerNameOffset =
		static_cast<ULONG>( offsetof( AutoLoggerRuntimeQueryBuffer, sessionName)) ;
	buffer.properties.LogFileNameOffset =
		static_cast<ULONG>( offsetof( AutoLoggerRuntimeQueryBuffer, logFileName)) ;
	// ハンドルと入力GUIDは零のままにして元セッション名だけで照会する
	const auto queried =
		ControlTraceW( 0U, session.data(), &buffer.properties, EVENT_TRACE_CONTROL_QUERY) ;
	// ETWが指定セッションの不在と明示した場合にだけ不在を採用する
	if( queried != ERROR_SUCCESS && queried != ERROR_WMI_INSTANCE_NOT_FOUND) {
		return HRESULT_FROM_WIN32( queried) ;
	}

	present = queried == ERROR_SUCCESS ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsの正規ACPI登録から共有ストレージ機能の現在DWORDを読み取る
 * @param[out] snapshot 正式の不在または現在DWORDと保護。失敗時は空
 * @return 保護と安定性を照合した読取り成功は0、値の型や読取りの不成立はHRESULT
 * @note 同じACPIサービスの正規SYSと現在構成は呼出元が別途確認する。レジストリは変更しない
 */
//------------------------------------------------------------------------------
NativeError readStorageAcpiSnapshot( StorageAcpiSnapshot &snapshot)
{
	snapshot = {} ;
	try {
		const std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype( &CloseHandle)> changed{
			// すべての親と葉の変更通知
			CreateEventW( nullptr, TRUE, FALSE, nullptr), &CloseHandle} ;
		// 安定性を検査できない場合は観測を採用しない
		if( !changed) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		StorageAcpiSnapshot		 made ;							// 正式の不在と元値を保護の証拠と一緒に保持する
		StorageRegistryReadState state{changed.get(), {}, 0U} ;	// 同期中の現在制御セット
		constexpr std::size_t	 CONTROL_SET = 2U ;				// リンクを解決したSYSTEM直下の実名の位置
		// 元制御セットとACPIのParametersへ向かう各キー名
		constexpr std::array	 names{L"SYSTEM", L"CurrentControlSet", L"", L"Services",
								   L"ACPI",	  L"Parameters"} ;
		constexpr std::array	 roles{
			StorageRegistryReadRole::ORDINARY,
			StorageRegistryReadRole::CURRENT_CONTROL_SET,
			StorageRegistryReadRole::ORDINARY,
			StorageRegistryReadRole::ORDINARY,
			StorageRegistryReadRole::ORDINARY,
			StorageRegistryReadRole::ABSENCE_ALLOWED} ;			// ACPI本体の不在をParametersの不在へ変えない
		std::array<AutoLoggerRegistryKey, names.size()> keys ;	// 観測中はすべての親を保持する
		// 既知のSYSTEMから、他サービスへのリンクを辿らず一階層ずつ読む
		for( std::size_t index = 0U; index < names.size(); ++index) {
			const HKEY parent =
				index == 0U ? HKEY_LOCAL_MACHINE
							: keys[index == CONTROL_SET ? 0U : index - 1U].get() ;	// 元の直接親
			const wchar_t *name =
				// 元の正規子名
				index == CONTROL_SET ? state.controlSet.c_str() : names[index] ;
			const auto error =
				readProtectedStorageKey( parent, name, roles[index], state, keys[index],
										made.security[index]) ;	// 元位置、保護、安定性の結果
			// 権限不一致やリンク異常を正式不在として扱わない
			if( error != 0U) {
				return error ;
			}
		}

		made.controlSet = std::move( state.controlSet) ;
		// 葉がある場合も、該当する元値だけを型と元長を含めて照合する
		if( const auto key = keys.back().get() ; key) {
			made.parametersPresent = true ;
			const auto valueRead   = readOptionalStorageDword(
				  key, L"StorageSupportedFeatures",
				  made.storageSupportedFeatures) ;	// 元DWORDか正式な値不在を保持する
			// 読取り失敗を観測済みの不在として返さない
			if( valueRead != 0U) {
				return valueRead ;
			}

			FILETIME   lastWrite{} ;	// ACPI Parametersの最終書込み時刻
			const auto observed =
				RegQueryInfoKeyW( key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
								 nullptr, nullptr, nullptr, &lastWrite) ;	// 保持した元キーの観測
			// 時刻が取得できない状態を安定した既知の構成へ変更しない
			if( observed != ERROR_SUCCESS) {
				return HRESULT_FROM_WIN32( observed) ;
			}

			made.parametersLastWrite =
				(static_cast<std::uint64_t>( lastWrite.dwHighDateTime) << 32U) |
				lastWrite.dwLowDateTime ;
		}

		const auto wait = WaitForSingleObject( changed.get(), 0U) ;	// 観測中に通知された変更
		// 観測中の変更や通知照会の失敗を元の診断値で止める
		if( wait != WAIT_TIMEOUT) {
			return HRESULT_FROM_WIN32( wait == WAIT_FAILED ? GetLastError() : ERROR_RETRY) ;
		}

		snapshot = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

namespace {
// 自動解放と独立監視配列の既定構築に使うイベントの閉鎖処理
constexpr auto CLOSE_REGISTRY_CHANGE_EVENT = []( HANDLE event) { CloseHandle( event) ; } ;
/** @brief 親の監視が完了するまで独立したイベントを保持する所有型 */
using StorageRegistryChangeEvent =
	std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype( CLOSE_REGISTRY_CHANGE_EVENT)> ;

//------------------------------------------------------------------------------
/**
 * @brief 署名付き元選択が指定した電源設定の現在定義と全既定値を読み取る
 * @param[in] settings 識別子を検査済みの同じ選択の電源定義
 * @param[in] includeLocations 全登録場所を独立監視と同じ制御セットで取得する場合true
 * @param[out] snapshot 成功時は同じ制御セットの保護と現在値。失敗時は空
 * @return 正式不在又は元値の観測に成功して0、保護や読取りの不成立はHRESULT
 * @note 定義から電源プランへの変更を実行せず、元選択の導入資格を発行しない
 */
//------------------------------------------------------------------------------
NativeError readStoragePowerSettingsSnapshotImpl(
	std::span<const RangedStoragePowerSetting> settings, bool includeLocations,
	StoragePowerSettingsSnapshot &snapshot)
{
	snapshot							   = {} ;
	constexpr std::size_t MAXIMUM_SETTINGS = 4096U ;	// 元選択と同じ参照上限
	// 自動起動ストレージの元選択に対応する有限個の定義だけを観測する
	if( settings.empty() || settings.size() > MAXIMUM_SETTINGS) {
		return E_INVALIDARG ;
	}

	// 元の署名付き選択と同じく設定GUIDを一意にし、相対キーの混入を拒否する
	for( std::size_t index = 0U; index < settings.size(); ++index) {
		const auto &setting = settings[index] ;	// 固定位置へ対応付ける前に確認する元設定
		// 不明GUIDや再定義で観測対象を増やさない
		if( !validAutoLoggerGuid( setting.subgroup) || !validAutoLoggerGuid( setting.setting) ||
		   std::ranges::any_of( settings.first( index), [&]( const auto &earlier) {
			   return same( earlier.setting, setting.setting) ;
		   })) {
			return E_INVALIDARG ;
		}
	}

	try {
		const StorageRegistryChangeEvent changed{	// 各対象枝を開く保護付き読取りの通知
												 CreateEventW( nullptr, TRUE, FALSE, nullptr)} ;
		// 同時点の値と保護を保持できない状態を観測済みとしない
		if( !changed) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		StoragePowerSettingsSnapshot made ;							// 全読取りが成立するまで保持する現在値
		StorageRegistryReadState	 state{changed.get(), {}, 0U} ;	// 正式な制御セットと通知
		constexpr std::size_t		 CONTROL_SET = 2U ;				// SYSTEM直下に解決した実キーの位置
		constexpr std::array		 names{
			L"SYSTEM", L"CurrentControlSet", L"", L"Control",
			L"Power",  L"PowerSettings"} ;										// Windowsの固定階層を一段ずつ確認する
		std::array<StorageRegistryChangeEvent, names.size()> parentChanges ;	// 固定親の独立監視
		std::array<AutoLoggerRegistryKey, names.size()>		 roots ;			// 最後の通知確認まで保持する
		// 唯一の標準リンクを解決し、各親を固定して元の保護を読む
		for( std::size_t index = 0U; index < roots.size(); ++index) {
			const HKEY parent =
				index == 0U ? HKEY_LOCAL_MACHINE
							: roots[index == CONTROL_SET ? 0U : index - 1U].get() ;	// 元の直接親
			const wchar_t *name = index == CONTROL_SET
									  ? state.controlSet.c_str()
									  : names[index] ;	// 同じ制御セットに解決した直接子名
			const auto	   role = index == 1U
									  ? StorageRegistryReadRole::CURRENT_CONTROL_SET
									  : StorageRegistryReadRole::ORDINARY ;	// 標準リンクだけを認める
			// 後続キーの監視登録で先の固定親の通知が消えないよう分離する
			if( includeLocations) {
				parentChanges[index].reset( CreateEventW( nullptr, TRUE, FALSE, nullptr)) ;
				// 独立した監視が一つでも作れなければ全登録場所を確定しない
				if( !parentChanges[index]) {
					return HRESULT_FROM_WIN32( GetLastError()) ;
				}

				state.changed = parentChanges[index].get() ;
			}

			const bool watchSubtree =
				includeLocations && index + 1U == roots.size() ;	// 配下の変更も監視する起点
			// 最後の固定親は定義、既定値、名前と保護の途中変更も監視する
			const auto error = readProtectedStorageKey(
				parent, name, role, state, roots[index], made.parents[index],
				REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
				watchSubtree) ;
			// 保護された親の不成立を設定の正式不在へ置き換えない
			if( error != 0U) {
				return error ;
			}
		}

		state.changed = changed.get() ;
		std::vector<std::array<AutoLoggerRegistryKey, 6U>> keys(
			// 各枝の通知を保持
			settings.size()) ;
		made.settings.resize( settings.size()) ;
		// 同じ制御セットの全設定を元選択順に読み、最初の失敗で止める
		for( std::size_t index = 0U; index < settings.size(); ++index) {
			const auto error =
				readOneStoragePowerSetting( roots.back().get(), settings[index], state, keys[index],
										   made.settings[index]) ;	// 設定と全既定値の読取り
			// 一部の定義の成功を完全な現在値として公開しない
			if( error != 0U) {
				return error ;
			}
		}

		std::vector<AutoLoggerRegistryKey> locationKeys ;	// 追加した親と一致キーを閉じずに保持する
		// 元位置の値に同じ制御セットでの全登録場所を追加する
		if( includeLocations) {
			const auto error = readStoragePowerLocations( roots.back().get(), state, made.settings,
														 locationKeys) ;	// 全GUIDの所在
			// 部分一覧と既存値の組を観測成功として公開しない
			if( error != 0U) {
				return error ;
			}

			// 固定親と全配下の独立したイベントを最後まで確認する
			for( const auto &parentChange : parentChanges) {
				const auto wait = WaitForSingleObject( parentChange.get(), 0U) ;	// 保持中の通知
				// 専用イベントの通知や読めない待機結果を不在に置き換えない
				if( wait != WAIT_TIMEOUT) {
					return HRESULT_FROM_WIN32( wait == WAIT_FAILED ? GetLastError() : ERROR_RETRY) ;
				}
			}
		}

		const auto wait = WaitForSingleObject( changed.get(), 0U) ;	// 読取り期間の変更通知
		// 元の値または保護の途中変更を再観測用の正常値として公開しない
		if( wait != WAIT_TIMEOUT) {
			return HRESULT_FROM_WIN32( wait == WAIT_FAILED ? GetLastError() : ERROR_RETRY) ;
		}

		made.controlSet = std::move( state.controlSet) ;
		snapshot		= std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 元選択が指定した電源設定の登録定義と六つの既定値を読み取る
 * @param[in] settings 元INFの署名付き選択節から検査した電源設定の一覧
 * @param[out] snapshot 同じ現在制御セットの値と保護。失敗時は空
 * @return 同じ保護付きの位置で正式不在又は値を観測できれば0、失敗はHRESULT
 * @note 現在の電源プランやレジストリを変更しない。導入資格や元配布の所有は別に判断する
 */
//------------------------------------------------------------------------------
NativeError readStoragePowerSettingsSnapshot( std::span<const RangedStoragePowerSetting> settings,
											 StoragePowerSettingsSnapshot			   &snapshot)
{
	return readStoragePowerSettingsSnapshotImpl( settings, false, snapshot) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元位置の電源定義と既定値に加え、同じ設定GUIDの直下とサブグループを読み取る
 * @param[in] settings 元INFの署名付き選択節から検査した電源設定の一覧
 * @param[out] snapshot 現在制御セットの値と保護に全登録場所を加えた観測。失敗時は空
 * @return 正式不在を含む保護付きの現在値と全登録場所の観測で0、不成立はHRESULT
 * @note PowerSettingsの直下にあるGUID形式のキーとその直接子に限定する
 * @note 読取り専用で、電源プラン、署名元の所有や端末への導入資格は別に扱う
 */
//------------------------------------------------------------------------------
NativeError readStoragePowerSettingsAndLocationsSnapshot(
	std::span<const RangedStoragePowerSetting> settings, StoragePowerSettingsSnapshot &snapshot)
{
	return readStoragePowerSettingsSnapshotImpl( settings, true, snapshot) ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 省略を含む元INFの表示文字列をWindowsが保持する現在値へ照合する
 * @param[in] actual 現在値を原型のまま読んだ観測
 * @param[in] declared 署名元で確認した展開済みの文字列
 * @return 定義した文字列と現在の値がそのまま一致するか、双方が省略であればtrue
 */
//------------------------------------------------------------------------------
bool matchesStoragePowerText( const StoragePowerTextSnapshot &actual,
							 std::wstring_view				 declared) noexcept
{
	// 省略を実在する空文字列へ置き換えない
	if( declared.empty() || !actual.value) {
		return declared.empty() && !actual.value ;
	}

	// 展開で意味が変わらない元文字列だけをそのまま比較する
	return (actual.type == REG_SZ ||
			(actual.type == REG_EXPAND_SZ && declared.find( L'%') == declared.npos)) &&
		   *actual.value == declared ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全域観測で同じ設定が元の一箇所だけにあるか、全域で不在かを確認する
 * @param[in] actual 元位置と、取得した場合は全登録場所の保護付き観測
 * @return 全域観測が一致する場合true。元位置だけの経路ではその照合に委ねる
 */
//------------------------------------------------------------------------------
bool matchesStoragePowerLocations( const StoragePowerSettingSnapshot &actual) noexcept
{
	// 元位置だけの読取りは従来の値と署名付き所有の照合へ渡す
	if( !actual.locations) {
		return true ;
	}

	const auto &places = *actual.locations ;	// 同じ設定GUIDの全登録場所
	// 直下で同名のキーがあれば元位置だけの設定に限定できない
	if( places.rootMatch) {
		return false ;
	}

	// 元位置に既存定義がある場合は、全域でもその一箇所だけを認める
	if( actual.keys[1U].lastWrite) {
		return places.matchingSubgroups.size() == 1U &&
			   same( places.matchingSubgroups.front(), actual.subgroup) ;
	}

	return places.matchingSubgroups.empty() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名付きの電源宣言を同じ現在設定の定義と全既定値へ照合する
 * @param[in] declared 選択節が参照した範囲・既定値・表示情報の原宣言
 * @param[in] actual 現在の保護付き同設定。元位置の不在も保持する
 * @return 同じ位置、定義、既定値と値の省略が成立した場合true
 */
//------------------------------------------------------------------------------
bool matchesStoragePowerDefinition( const RangedStoragePowerSetting	 &declared,
								   const StoragePowerSettingSnapshot &actual) noexcept
{
	// 別設定や保護付きキーの欠落を同じ所有先にしない
	if( !same( actual.subgroup, declared.subgroup) || !same( actual.setting, declared.setting) ||
	   !matchesStoragePowerLocations( actual) ||
	   !std::ranges::all_of(
		   actual.keys,
		   []( const auto &key) { return key.lastWrite.has_value() && !key.security.empty() ; }) ||
	   actual.minimum != declared.minimum || actual.maximum != declared.maximum ||
	   actual.increment != declared.increment || actual.attributes != declared.attributes ||
	   !matchesStoragePowerText( actual.displayName, declared.displayName) ||
	   !matchesStoragePowerText( actual.description, declared.description) ||
	   !matchesStoragePowerText( actual.unitLabel, declared.unitLabel)) {
		return false ;
	}

	// 既定値の不在と署名元の明示値0を区別する
	return std::equal( actual.defaults.begin(), actual.defaults.end(), declared.defaults.begin()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの現用登録から同じ設定GUIDの元宣言を探す
 * @param[in] registration 署名と元選択を検査済みの現在登録。未導入または未確認ではnull
 * @param[in] setting 候補の設定GUID。同じGUIDの別サブグループも照合へ渡す
 * @return 元宣言の借用ポインター。登録の未確認・不在または元宣言なしではnull
 */
//------------------------------------------------------------------------------
const RangedStoragePowerSetting *findRegisteredStoragePower(
	const RegisteredStoragePackageEvidence *registration, std::wstring_view setting) noexcept
{
	// 未確認や正式な未導入に既存の元宣言を補完しない
	if( !registration) {
		return nullptr ;
	}

	const auto &settings = registration->powerSettings ;	// 元署名の同一実選択に限定
	const auto	matched	 = std::ranges::find_if( settings, [&]( const auto &declared) {
		  return same( declared.setting, setting) ;
	  }) ; // GUIDの表記差を除いて比較する借用対象
	return matched == settings.end() ? nullptr : &*matched ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在値と選択機器・継続利用する機器の電源定義を一つずつ照合する
 * @param[in] candidate 候補が書く一つの定義と既定値
 * @param[in] observed 同じ位置の保護付き現在値
 * @param[in] device 選択と他の共有機器の署名元
 * @return 現在値と宣言から確認した変更の種別
 */
//------------------------------------------------------------------------------
StoragePowerChange classifyOneStoragePower( const RangedStoragePowerSetting		&candidate,
										   const StoragePowerSettingSnapshot	&observed,
										   const StorageAutomaticDeviceSnapshot &device) noexcept
{
	// 直下や別サブグループにもある定義は、正式な不在や変更不要へ置き換えない
	if( !matchesStoragePowerLocations( observed)) {
		return StoragePowerChange::UNVERIFIED ;
	}

	const auto *previous =
		// 選択機器の元宣言
		findRegisteredStoragePower( device.selected.package ? &*device.selected.package : nullptr,
								   candidate.setting) ;
	// 選択機器の宣言と異なる現用値を候補の値や他の機器の署名で補わない
	if( previous && !matchesStoragePowerDefinition( *previous, observed)) {
		return StoragePowerChange::UNVERIFIED ;
	}

	bool shared{} ;	// 選択していない機器が同じ既存定義を使うか
	// 確認した全機器の元宣言に対し、同じ定義の競合を見落とさない
	for( const auto &owner : device.owners) {
		const auto *declaration =
			// 他機器の元宣言
			findRegisteredStoragePower(
				owner.registered.package ? &*owner.registered.package : nullptr, candidate.setting) ;
		// 同じGUIDを定義する機器がある場合だけ、その元値と共有を確認する
		if( declaration) {
			// 候補適合ありの別機器も今回の指定導入では現用元を使い続ける
			if( !matchesStoragePowerDefinition( *declaration, observed)) {
				return StoragePowerChange::UNVERIFIED ;
			}

			shared = true ;
		}
	}

	// 元登録に裏付けられない既存定義は、候補と同値でも所有を確認できない
	if( !previous && !shared) {
		return observed.keys[1U].lastWrite ? StoragePowerChange::UNVERIFIED
										   : StoragePowerChange::CREATE ;
	}

	// 元定義と候補も一致する場合は同じ範囲と既定値を維持する
	if( matchesStoragePowerDefinition( candidate, observed)) {
		return StoragePowerChange::KEEP ;
	}

	return shared ? StoragePowerChange::UPDATE_SHARED : StoragePowerChange::UPDATE_SELECTED ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 候補の全電源定義を現在設定と全現用登録に照合して分類する
 * @param[in] candidate 元選択に結ぶ電源定義の一覧
 * @param[in] observed 同じ候補順に検査した現在値と保護
 * @param[in] device 選択機器と全present同サービス機器の署名付き元登録
 * @param[out] changes 全分類が完了した場合の候補順の一覧。失敗時は空
 * @return 分類の成功0。位置、観測、現用登録の不足や不一致はHRESULT
 * @note 使用中のプランの値は扱わず、候補を書き込む権限を発行しない
 */
//------------------------------------------------------------------------------
NativeError classifyStoragePowerChanges( std::span<const RangedStoragePowerSetting> candidate,
										const StoragePowerSettingsSnapshot		  &observed,
										const StorageAutomaticDeviceSnapshot	  &device,
										std::vector<StoragePowerChange>			  &changes)
{
	changes.clear() ;
	// 不完全な現用一覧や現在観測から未使用の設定だと推定しない
	if( candidate.empty() || observed.controlSet.empty() ||
	   candidate.size() != observed.settings.size() ||
	   std::ranges::any_of( device.owners,
						   []( const auto &owner) { return !owner.registered.package ; })) {
		return HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	try {
		std::vector<StoragePowerChange> made ;	// 全位置が成立するまで保持する分類
		made.reserve( candidate.size()) ;
		// 同じ署名候補順に比較し、別位置や保護不明の定義を混ぜない
		for( std::size_t index = 0U; index < candidate.size(); ++index) {
			const auto &target	= candidate[index] ;			// 元選択の同じ定義
			const auto &current = observed.settings[index] ;	// 同じ定義の現在値
			// 正式な親を確認した同じ設定枝だけを分類する
			if( !same( target.subgroup, current.subgroup) || !same( target.setting, current.setting) ||
			   !current.keys.front().lastWrite || current.keys.front().security.empty()) {
				return HRESULT_FROM_WIN32( ERROR_RETRY) ;
			}

			made.push_back( classifyOneStoragePower( target, current, device)) ;
		}

		changes = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ設定GUIDに対する選択機器と選択外機器の既知宣言を現在値に照合する
 * @param[in,out] snapshot 安定性を確認した局所観測、全電源所在と現用側の元証拠
 * @return 全ての既知宣言の分類で0、保護・所在または証拠の不足や矛盾はHRESULT
 * @note 未確認機器を消さない。照合は肯定的な証拠を保持するだけで、未使用を確定しない
 */
//------------------------------------------------------------------------------
NativeError classifySingleBootStoragePowerUse( StorageSingleBootSharingSnapshot &snapshot)
{
	snapshot.use.clear() ;
	// 二つの階層が分かれる前のSYSTEM・標準リンク・実制御セットだけを照合する
	constexpr std::size_t COMMON_PARENTS = 3U ;
	const auto			 &power			 = snapshot.power ;				// 同じ候補の現在定義と全所在
	const auto			 &registry		 = snapshot.device.registry ;	// 同じ選択機器の局所観測
	// 異なる制御セット、未確認の親や途中までの一覧を組み合わせない
	if( power.controlSet.empty() || power.controlSet != registry.controlSet ||
	   power.settings.empty() ||
	   !std::equal( power.parents.begin(), power.parents.begin() + COMMON_PARENTS,
				   registry.keySecurity.begin()) ||
	   std::any_of( power.parents.begin(), power.parents.begin() + COMMON_PARENTS,
				   []( const auto &protection) { return protection.empty() ; })) {
		return HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	try {
		const auto &installed = snapshot.device.installed.registered ;	// 署名付き現用元
		std::vector<StorageSingleBootPowerUse> made ;					// 全設定について照合するまで公開しない結果
		made.reserve( power.settings.size()) ;
		// 元候補順に、同GUIDの別サブグループも含めて元宣言を探す
		for( const auto &actual : power.settings) {
			// 設定値の正式な不在と全体の所在の未確認を区別する
			if( !actual.locations || !actual.keys.front().lastWrite ||
			   actual.keys.front().security.empty()) {
				return HRESULT_FROM_WIN32( ERROR_RETRY) ;
			}

			auto	   &use = made.emplace_back() ;	// 一つの同GUID指定と既知元の関係
			const auto *selected =
				findRegisteredStoragePower( installed ? &installed->package : nullptr,
										   actual.setting) ;	// 選択機器の同GUIDだけを借用する
			use.selectedDeclared = selected != nullptr ;
			use.selectedMatches	 = selected && matchesStoragePowerDefinition( *selected, actual) ;
			// 未確認は既知の他機器から除かず、元宣言との一致・相違を別々に数える
			for( const auto &peer : snapshot.peers) {
				// 失敗を元署名へ付け替えた矛盾する観測を受理しない
				if( peer.diagnostic == 0U ? peer.noDriver == peer.origin.has_value()
										 : peer.noDriver || peer.origin.has_value()) {
					return HRESULT_FROM_WIN32( ERROR_RETRY) ;
				}

				const auto *declared =
					findRegisteredStoragePower( peer.origin ? &*peer.origin : nullptr,
											   actual.setting) ;	// 同GUIDを持つ既知の宣言
				// 同じ設定を宣言していない、または未確認の機器には一致を与えない
				if( !declared) {
					continue ;
				}

				// 別位置や異なる現在値を正しい共有ユーザーに合算しない
				if( matchesStoragePowerDefinition( *declared, actual)) {
					++use.sharedMatches ;
				} else {
					++use.sharedConflicts ;
				}
			}
		}

		snapshot.use = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 確認した現在状態と署名付き宣言から一つの電源変更を分類する
 * @param[in] candidate 同じ署名付き選択の設定定義と既定値
 * @param[in] actual 保護付きレジストリから得た全所在と同じ位置の現在値
 * @param[in] use 選択機器と署名確認済みの他機器が宣言する同一GUIDの照合
 * @param[in] unknownPeers 署名元未確認のpresent機器がある場合true
 * @return 同じ元観測で確認した新規・維持・変更・未確認の種別
 */
//------------------------------------------------------------------------------
StoragePowerChange classifySingleBootPowerChange( const RangedStoragePowerSetting   &candidate,
												 const StoragePowerSettingSnapshot &actual,
												 const StorageSingleBootPowerUse   &use,
												 bool unknownPeers) noexcept
{
	// 既知の宣言との矛盾や、直下・別サブグループへの登録を上書きに使わない
	if( !matchesStoragePowerLocations( actual) || use.sharedConflicts != 0U ||
	   (use.selectedDeclared && !use.selectedMatches)) {
		return StoragePowerChange::UNVERIFIED ;
	}

	const bool hasClaim = use.selectedDeclared || use.sharedMatches != 0U ;	// 既知の同GUID元宣言
	// 全所在で正式に不在の場合は物理的な新規作成として扱う
	if( !actual.keys[1U].lastWrite) {
		// 設定と付随する子キーにも既存の保護や更新記録がないことを確認する
		const bool emptyKeys =
			std::all_of( actual.keys.begin() + 1, actual.keys.end(),
						[]( const auto &key) { return !key.lastWrite && key.security.empty() ; }) ;
		// 型付きの定義および既定値が残っていれば不在の観測と矛盾する
		const bool emptyValues =
			!actual.minimum && !actual.maximum && !actual.increment && !actual.attributes &&
			actual.displayName == StoragePowerTextSnapshot{} &&
			actual.description == StoragePowerTextSnapshot{} &&
			actual.unitLabel == StoragePowerTextSnapshot{} &&
			std::ranges::none_of( actual.defaults,
								 []( const auto &value) { return value.has_value() ; }) ;
		return !hasClaim && emptyKeys && emptyValues ? StoragePowerChange::CREATE
													 : StoragePowerChange::UNVERIFIED ;
	}

	// 同じ現在値の維持でも、対応する署名付き元宣言を一件以上要求する
	if( !hasClaim) {
		return StoragePowerChange::UNVERIFIED ;
	}

	// 署名付き現在値と候補の範囲・定義・全既定値が同じ場合だけ維持する
	if( matchesStoragePowerDefinition( candidate, actual)) {
		return StoragePowerChange::KEEP ;
	}

	// 他機器の既知の宣言への変更は、別の未確認機器がいても共有として扱う
	if( use.sharedMatches != 0U) {
		return StoragePowerChange::UPDATE_SHARED ;
	}

	return unknownPeers ? StoragePowerChange::UNVERIFIED : StoragePowerChange::UPDATE_SELECTED ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同じ候補の全電源設定の変更種別を正規の署名元と現在値から決める
 * @param[in] candidate 元INFと同じ順に検査済みの電源定義
 * @param[in,out] snapshot 同じ候補の全所在、値、元登録と合成観測。成功時に分類を格納
 * @return 同じ候補の全設定の分類で0、元観測または対応の不成立はHRESULT
 * @note 候補に書込資格を付与せず、不在と未確認機器を独立して保持する
 */
//------------------------------------------------------------------------------
NativeError classifySingleBootStoragePowerChanges(
	std::span<const RangedStoragePowerSetting> candidate,
	StorageSingleBootSharingSnapshot		  &snapshot)
{
	snapshot.powerChanges.clear() ;
	// 候補を別の電源設定の全所在観測へ付け替えない
	if( candidate.empty() || candidate.size() != snapshot.power.settings.size()) {
		return E_INVALIDARG ;
	}

	const auto read = classifySingleBootStoragePowerUse( snapshot) ;	// 同GUIDの既知宣言の再分類
	// 途中で失敗した元観測を成功した変更分類として使わない
	if( read != 0U) {
		return read ;
	}

	try {
		// 下の同期判定中だけ未確認機器の有無を参照する
		const bool unknownPeers = std::ranges::any_of( snapshot.peers, []( const auto &peer) {
			return peer.diagnostic != 0U ;
		}) ;									  // 未確認の元署名が一件でも残っている状態
		std::vector<StoragePowerChange> made ;	// 同じ候補順の全変更が揃うまで保持する
		made.reserve( candidate.size()) ;
		// 署名候補順に現在値、全所在と元機器の宣言を照らし合わせる
		for( std::size_t index = 0U; index < candidate.size(); ++index) {
			const auto &target = candidate[index] ;					// 同じ元候補が変更する一設定
			const auto &actual = snapshot.power.settings[index] ;	// 同じ位置の全域観測
			// 値やGUIDの一致だけで別のサブグループに対する承認としない
			if( !same( target.setting, actual.setting) || !same( target.subgroup, actual.subgroup)) {
				return HRESULT_FROM_WIN32( ERROR_RETRY) ;
			}

			made.push_back(
				classifySingleBootPowerChange( target, actual, snapshot.use[index], unknownPeers)) ;
		}

		snapshot.powerChanges = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 同じイベントソースの元値を展開せずに読み取る
 * @param[in] key 保持したSystemログソースの通常キー
 * @param[in,out] source 明示的不在又は元型と元値を保持する作業値
 * @param[in] namedSource 元六欄が指定した明示イベントのカテゴリ値も読む場合true
 * @return 読取り成功0、型・容量・読取の不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readStorageEventSourceValues( HKEY key, StorageEventSourceSnapshot &source,
										 bool namedSource)
{
	const auto message = readOptionalStorageString( key, L"EventMessageFile", source.messageFile,
												   source.messageFileType) ;	// 展開前の元資源
	// 元文字列の読取りに失敗した場合は他の元値を確認しない
	if( message != 0U) {
		return message ;
	}

	const auto types =
		// 元種別の照会結果
		readOptionalStorageDword( key, L"TypesSupported", source.typesSupported) ;
	// 従来経路の元値と元エラーを保持し、明示名でだけカテゴリ数を追加で読む
	if( types != 0U || !namedSource) {
		return types ;
	}

	return readOptionalStorageDword( key, L"CategoryCount", source.categoryCount) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正式なWindowsログ親と元選択から渡した一つまたは二つのイベント登録を読む
 * @tparam Source 葉名、実在、保護、時刻を保持する観測型
 * @tparam ReadValues 保護葉が開いた間だけ実行する値照合関数の型
 * @param[out] controlSet 成功時は同じWindowsが示す正式ControlSet名
 * @param[out] eventParents 同じWindowsログまでの親の元保護
 * @param[in,out] sources 検査済みの一つまたは二つの葉名と作業中の現在値
 * @param[in] logName 呼出側が用途別に固定したSystemまたはApplicationの終端付き親名
 * @param[in] readValues 同じ葉と位置を同期中だけ借用する型別値照合関数
 * @return 全読取り成功0、変更、型、保護またはWindowsの元エラーはHRESULT
 * @note 観測の作業値を失敗時に利用者や所有判定へ渡してはならない
 */
//------------------------------------------------------------------------------
template <class Source, class ReadValues>
NativeError readProtectedDriverEventSources( std::wstring						 &controlSet,
											std::span<std::vector<std::byte>, 6U> eventParents,
											std::span<Source> sources, const wchar_t *logName,
											ReadValues readValues)
{
	constexpr std::size_t MAX_EVENT_SOURCES = 2U ;	// 関連名と別の明示名まで
	// 元選択の宣言数だけを受理し、空の部分観測を返さない
	if( sources.empty() || sources.size() > MAX_EVENT_SOURCES) {
		return E_INVALIDARG ;
	}

	constexpr std::size_t CURRENT_LINK = 1U ;	// 正式なCurrentControlSetリンク
	constexpr std::size_t CONTROL_SET  = 2U ;	// リンクが指す同じSYSTEM直下の実キー
	// 元制御セットと用途別の固定ログへ向かう各キー名
	const std::array names{L"SYSTEM", L"CurrentControlSet", L"", L"Services", L"EventLog", logName} ;
	constexpr std::array roles{
		StorageRegistryReadRole::ORDINARY,
		StorageRegistryReadRole::CURRENT_CONTROL_SET,
		StorageRegistryReadRole::ORDINARY,
		StorageRegistryReadRole::ORDINARY,
		StorageRegistryReadRole::WINDOWS_EVENT_PARENT,
		StorageRegistryReadRole::WINDOWS_EVENT_PARENT,
	} ; // Windows EventLogの標準権限は専用親でだけ引き継ぐ
	std::array<StorageRegistryChangeEvent, roles.size() + MAX_EVENT_SOURCES>
			   changes ;															// 各親と葉に別の通知を保持する
	const auto watched = std::span{changes}.first( names.size() + sources.size()) ;	// 監視数
	// 後の通知登録で先の通知が消えないよう、実際に開く親と葉に別イベントを割り当てる
	for( auto &notification : watched) {
		notification.reset( CreateEventW( nullptr, TRUE, FALSE, nullptr)) ;
		// 一つでも監視できない場合は現在値を公開しない
		if( !notification) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}
	}

	std::array<AutoLoggerRegistryKey, roles.size()> parents ;	// 変更確認まで各正式親を保持する
	StorageRegistryReadState state{nullptr, {}, 0U} ;			// 共通の正式制御セットと継承権限
	// 同じWindowsログの親を一つずつ保護付きで読む
	for( std::size_t index = 0U; index < parents.size(); ++index) {
		const HKEY	   parent = index == 0U ? HKEY_LOCAL_MACHINE
											: parents[index == CONTROL_SET ? 0U : index - 1U]
											  .get() ;	// リンク対象も同じSYSTEM直下
		const wchar_t *name =
			// 元の直接子名
			index == CONTROL_SET ? state.controlSet.c_str() : names[index] ;
		const DWORD watch = REG_NOTIFY_CHANGE_SECURITY |
							(index == CURRENT_LINK ? REG_NOTIFY_CHANGE_LAST_SET
												   : REG_NOTIFY_CHANGE_NAME) ;	// 親の従来監視範囲
		state.changed = watched[index].get() ;
		const auto error =
			readProtectedStorageKey( parent, name, roles[index], state, parents[index],
									eventParents[index], watch) ;	// 読取りと保護の結果
		// 正式な親の異常を個別イベントの不在へ置き換えない
		if( error != 0U) {
			return error ;
		}
	}

	std::array<AutoLoggerRegistryKey, MAX_EVENT_SOURCES> leaves ;	// 各葉を変更確認まで保持する
	// 署名付き元選択が指定した葉だけを同じWindowsログ親から読む
	for( std::size_t index = 0U; index < sources.size(); ++index) {
		auto &source	  = sources[index] ;	// この登録の名前と現在値
		auto  leafState	  = state ;				// 同じ標準親から各葉に独立して継承する権限と通知
		leafState.changed = watched[names.size() + index].get() ;
		// 元イベントの葉と保護の照会結果
		auto error = readProtectedStorageKey( parents.back().get(), source.name.c_str(),
											 StorageRegistryReadRole::ABSENCE_ALLOWED, leafState,
											 leaves[index], source.security) ;
		// 権限不足やリンクの異常は正式な葉の不在にしない
		if( error != 0U) {
			return error ;
		}

		// 正式に不在の葉は値と保護を空に保つ
		if( !leaves[index]) {
			continue ;
		}

		const auto key = leaves[index].get() ;	// 保護を確認して保持した通常キー
		error		   = readValues( key, source, index) ;
		// 一方の元診断を別ソースの成功で上書きしない
		if( error != 0U) {
			return error ;
		}

		FILETIME   stamp{} ;	// 既存イベント源が記録した最終書込み時刻
		const auto stamped =
			RegQueryInfoKeyW( key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
							 nullptr, nullptr, nullptr, &stamp) ;	// 保持した同じ元キーの観測
		// 時刻なしの既存状態を再照合へ使わない
		if( stamped != ERROR_SUCCESS) {
			return HRESULT_FROM_WIN32( stamped) ;
		}

		source.lastWrite =
			(static_cast<std::uint64_t>( stamp.dwHighDateTime) << 32U) | stamp.dwLowDateTime ;
		source.present = true ;
	}

	// 正式不在を含む配置の変更と、保持中の値・保護を別通知で確認する
	for( const auto &notification : watched) {
		const auto notified = WaitForSingleObject( notification.get(), 0U) ;	// 独立監視の現在値
		// 元観測の値や保護の途中変更を成功として公開しない
		if( notified != WAIT_TIMEOUT) {
			return HRESULT_FROM_WIN32( notified == WAIT_FAILED ? GetLastError() : ERROR_RETRY) ;
		}
	}

	controlSet = std::move( state.controlSet) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief ストレージの元選択が参照するSystemイベントを既存値規則で読む
 * @param[out] controlSet 成功時は同じWindowsが示す正式ControlSet名
 * @param[out] eventParents Systemログまでの親の元保護
 * @param[in,out] sources 検査済みの一つまたは二つの葉名と作業中の現在値
 * @param[in] namedSource 補助サービスが明示した二番目のイベントのカテゴリ値も読む場合true
 * @return 全読取り成功0、変更、型、保護またはWindowsの元エラーはHRESULT
 */
//------------------------------------------------------------------------------
NativeError readStorageEventSources( std::wstring						 &controlSet,
									std::span<std::vector<std::byte>, 6U> eventParents,
									std::span<StorageEventSourceSnapshot> sources, bool namedSource)
{
	// 従来の明示名では元の二件の宣言を維持する
	if( namedSource && sources.size() != 2U) {
		return E_INVALIDARG ;
	}

	return readProtectedDriverEventSources(
		controlSet, eventParents, sources, L"System",
		[namedSource]( HKEY key, StorageEventSourceSnapshot &source, std::size_t index) {
			return readStorageEventSourceValues( key, source, namedSource && index == 1U) ;
		}) ; // 読取中だけ元設定を値で保持する
}

//------------------------------------------------------------------------------
/**
 * @brief Systemログ直下で解釈できる一つのイベント名を判定する
 * @param[in] name 同じ元INFの関連名または明示イベント名
 * @return 有限で相対の直接子名だけならtrue
 */
//------------------------------------------------------------------------------
bool isStorageEventSourceName( std::wstring_view name)
{
	return !name.empty() && name.size() <= 256U && relative( name) && name != L"." &&
		   name.find( L'\\') == name.npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護葉の展開前メッセージ型と元値を一件照合する
 * @param[in] key 変更通知中の同じApplicationイベント葉
 * @param[in] name 終端付きの固定EventMessageFileまたはCategoryMessageFile名
 * @param[in] expected 署名INFの展開前元値。空は同じ値の正式な不在を要求する
 * @return 同じ型と値または正式不在で0、その他は元診断または不一致のHRESULT
 */
//------------------------------------------------------------------------------
NativeError matchDisplayEventString( HKEY key, const wchar_t *name, std::wstring_view expected)
{
	std::optional<std::wstring> actual ;										// Windowsから取得した展開前の値
	std::uint32_t				type{} ;										// 展開前のREG_EXPAND_SZまたは不在の型
	const auto error = readOptionalStorageString( key, name, actual, type) ;	// 元の型と値を読む
	// 不正な型や不完全な元文字列を比較前に拒否する
	if( error != 0U) {
		return error ;
	}

	const bool matches = expected.empty() ? !actual && type == REG_NONE
										  : actual && type == REG_EXPAND_SZ &&
												// 原表記のまま照合する
												same( *actual, expected) ;
	return matches ? 0U : INVALID ;
}

//------------------------------------------------------------------------------
/**
 * @brief Applicationイベント源が現用INFの値だけを持つことを確認する
 * @param[in] key 元イベント源を保護付きで開いた通常キー
 * @param[in] declaration 現用署名元の一意な値名と型別の元値
 * @return 全値・子キー数が一致する場合0、読取または照合不成立はHRESULT
 * @note 読取り中の変更通知は呼出側の共通処理が確認する
 */
//------------------------------------------------------------------------------
NativeError matchDisplayApplicationEventValues( HKEY									  key,
											   const OfficialDisplayAuxiliaryService &declaration)
{
	DWORD	   subkeys{} ;	// 既存イベント源は直接の値だけを持つ
	DWORD	   values{} ;	// 追加や隠れた値を判定する既存件数
	const auto queried =
		RegQueryInfoKeyW( key, nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr, &values,
						 nullptr, nullptr, nullptr, nullptr) ;	// 全キーと値を数える
	// 取得失敗を子キーや値がない状態へ読み替えない
	if( queried != ERROR_SUCCESS) {
		return HRESULT_FROM_WIN32( queried) ;
	}

	const auto expected = 1U + (declaration.categoryMessageFile.empty() ? 0U : 1U) +
						  // 現用INFが宣言した全型付きの値数
						  declaration.eventValues.size() ;
	// 追加の値・子キーを同じ元宣言の登録として扱わない
	if( subkeys != 0U || values != expected) {
		return INVALID ;
	}

	// 元イベント説明の診断を先に保持し、後続値の診断で上書きしない
	auto error = matchDisplayEventString( key, L"EventMessageFile", declaration.messageFile) ;
	// 同じイベント説明ファイルへ結合した場合だけカテゴリ宣言も照合する
	if( error == 0U) {
		error =
			matchDisplayEventString( key, L"CategoryMessageFile", declaration.categoryMessageFile) ;
	}

	// 二つの説明先が一致しなければ数値だけの照合へ進めない
	if( error != 0U) {
		return error ;
	}

	// 元署名INFが明示した各DWORDについて型と全32bitの値を照合する
	for( const auto &[name, value] : declaration.eventValues) {
		std::optional<std::uint32_t> actual ;	// 取得した同名の元DWORD
		error = readOptionalStorageDword( key, name.c_str(), actual) ;
		// 読取の異常を不在や別の値へ置き換えない
		if( error != 0U || actual != value) {
			return error != 0U ? error : INVALID ;
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名付き元が指定した二つの直接Systemイベントを共通の保護経路で観測する
 * @param[in] relatedService 関連カーネルサービスと同じ既定のイベント名
 * @param[in] eventName 補助サービスが明示した別のイベント名
 * @param[out] snapshot 成功時の二つの現在観測。失敗時は空
 * @return 保護付き読取りの成功0、元名や現在値が不明ならHRESULT
 */
//------------------------------------------------------------------------------
NativeError readNamedStorageEventSources( std::wstring_view			 relatedService,
										 std::wstring_view			 eventName,
										 StorageSystemEventSnapshot &snapshot)
{
	snapshot = {} ;
	// どちらの名前も同じSystemログに属する別々の直接子に限る
	if( !isStorageEventSourceName( relatedService) || !isStorageEventSourceName( eventName) ||
	   same( relatedService, eventName)) {
		return INVALID ;
	}

	StorageSystemEventSnapshot made ;	// 読取と安定性が成立するまで公開しない
	made.events[0].name = relatedService ;
	made.events[1].name = eventName ;
	// 二つの関連イベントの同一制御セットでの照会結果
	const auto error =
		readStorageEventSources( made.controlSet, made.eventParents, made.events, true) ;
	// 一部の登録だけ読み取った状態を完全な現在観測へ昇格させない
	if( error != 0U) {
		return error ;
	}

	snapshot = std::move( made) ;
	return 0U ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 保護された既存Applicationイベント源の全値を現用INFの宣言へ照合する
 * @param[in] declaration 現用署名済みDisplay INFが指定した同名イベント源と元値
 * @param[out] snapshot 全値・型・保護と安定性が確認できた場合だけ保持。失敗時は空
 * @return 既存の名前と全登録が一致して0、不在・不一致・読取エラーはHRESULT
 * @note リソースDLLを読み込まず、登録を変更しない。デバイス所有の判定は呼出側で行う
 */
//------------------------------------------------------------------------------
NativeError readDisplayApplicationEventSnapshot( const OfficialDisplayAuxiliaryService &declaration,
												DisplayApplicationEventSnapshot		  &snapshot)
{
	snapshot = {} ;
	// 同一イベント源の一意な名前と有限の値集合に限定する
	if( !isStorageEventSourceName( declaration.eventSource) || declaration.messageFile.empty() ||
	   declaration.eventValues.size() > 8U) {
		return E_INVALIDARG ;
	}

	// 元DWORD名の重複を値件数に混ぜず、同じ名前を二重に比較しない
	for( const auto &entry : declaration.eventValues) {
		// 展開名や複数の同名値を有効なWindows値の集合に変えない
		if( entry.first.empty() || entry.first.size() > 64U ||
		   entry.first.find( L'\0') != entry.first.npos ||
		   std::ranges::count_if( declaration.eventValues, [&entry]( const auto &other) {
			   return same( entry.first, other.first) ;
		   }) != 1) {
			return E_INVALIDARG ;
		}
	}

	try {
		DisplayApplicationEventSnapshot made ;	// 検査と安定性が揃うまで非公開の観測
		made.name		 = declaration.eventSource ;
		const auto error = readProtectedDriverEventSources(
			made.controlSet, made.eventParents, std::span{&made, 1U}, L"Application",
			[&declaration]( HKEY key, const DisplayApplicationEventSnapshot &, std::size_t) {
				return matchDisplayApplicationEventValues( key, declaration) ;
			}) ; // 固定した元宣言を値検査の同期中だけ借用する
		// 現用の署名宣言に値があっても、イベント源の実在がなければ所有証拠にしない
		if( error != 0U || !made.present) {
			return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
		}

		snapshot = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief SoftwareComponentクラスの名前と値の安定した母集合を保護付きで取得する
 * @param[out] snapshot 全登録、元制御セットと保護。読取失敗時は空
 * @return 有界の登録を確定した場合0、それ以外はHRESULT
 * @note 同じクラスの元状態のみを読む。現在機器や署名の照合は呼出し側で行う
 */
//------------------------------------------------------------------------------
NativeError readDisplayType1ClassSnapshot( DisplayType1ClassSnapshot &snapshot)
{
	snapshot					   = {} ;
	constexpr std::size_t LINK	   = 1U ;		// 現行Windowsの正式なCurrentControlSetリンク
	constexpr std::size_t REAL	   = 2U ;		// 同じSYSTEM直下の実制御セット
	constexpr DWORD		  MAX_KEYS = 4096U ;	// 番号以外も含めた直接子上限
	constexpr std::array  names{
		 L"SYSTEM", L"CurrentControlSet",
		 L"",		L"Control",
		 L"Class",	L"{5c4c3332-344d-483c-8739-259e934c9cc8}"} ;	// Windowsの正式クラスまでの階層
	try {
		DisplayType1ClassSnapshot made ;							// 完全な母集合と変更なしの確認後だけ外へ渡す値
		std::array<AutoLoggerRegistryKey, names.size()> parents ;	// 元親を読取りの終端まで保持する
		std::array<StorageRegistryChangeEvent, names.size()>
										 watches ;			// 各元親とクラス配下の独立通知
		std::array<HANDLE, names.size()> events{} ;			// 観測完了時にまとめて照会する借用ハンドル
		StorageRegistryReadState state{nullptr, {}, 0U} ;	// 正式リンクとキーの保護を確認する一時状態
		// 元のリンクを確定してから同じ実制御セットにあるクラスを開く
		for( std::size_t index = 0U; index < names.size(); ++index) {
			watches[index].reset( CreateEventW( nullptr, TRUE, FALSE, nullptr)) ;
			// 変更を追えない読取りを安定した現在登録へ変換しない
			if( !watches[index]) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			events[index] = watches[index].get() ;
			state.changed = events[index] ;
			const HKEY parent =
				index == 0U ? HKEY_LOCAL_MACHINE
							: parents[index == REAL ? 0U : index - 1U].get() ;	// 同じWindowsの正規親
			const auto *name =
				// 元の直接子名
				index == REAL ? state.controlSet.c_str() : names[index] ;
			const auto role =
				index == LINK
					? StorageRegistryReadRole::CURRENT_CONTROL_SET
					: StorageRegistryReadRole::ORDINARY ;	// 正式リンク以外の再解決を認めない
			const bool watchSubtree =
				index + 1U == names.size() ;	// 最下層では各登録の変更も観測する
			const DWORD notify = REG_NOTIFY_CHANGE_SECURITY | REG_NOTIFY_CHANGE_NAME |
								 ((index == LINK || watchSubtree) ? REG_NOTIFY_CHANGE_LAST_SET
																  : 0U) ;	// 層ごとの観測範囲
			const auto error = readProtectedStorageKey( parent, name, role, state, parents[index],
													   made.parents[index], notify,
													   watchSubtree) ;	// 現用Windowsの親と元保護
			// 読めない親を空のクラスと判断しない
			if( error != 0U) {
				return error ;
			}
		}

		// 数え落としを防ぐため、対象外の名前も上限と列挙終端の確認に含める
		for( DWORD index = 0U; index <= MAX_KEYS; ++index) {
			std::array<wchar_t, 256U> name{} ;										// 直接子名と終端の上限
			auto					  length = static_cast<DWORD>( name.size()) ;	// 入力容量と実名長
			const auto				  listed =
				RegEnumKeyExW( parents.back().get(), index, name.data(), &length, nullptr, nullptr,
							  nullptr, nullptr) ;	// 同じクラスでの列挙診断
			// 正式な列挙終端を確認してから現在登録を確定する
			if( listed == ERROR_NO_MORE_ITEMS) {
				break ;
			}

			// 列挙失敗や上限到達を部分成功として返さない
			if( listed != ERROR_SUCCESS || index == MAX_KEYS || length == 0U ||
			   length >= name.size()) {
				return HRESULT_FROM_WIN32( listed != ERROR_SUCCESS ? listed : ERROR_BUFFER_OVERFLOW) ;
			}

			const std::wstring_view slot( name.data(), length) ;	// 実際に列挙した同じ子名
			// Windowsの番号付き登録だけを収める。クラス共通の子キーは登録と区別する
			if( slot.size() != 4U || !std::ranges::all_of( slot, []( const wchar_t digit) {
				   return digit >= L'0' && digit <= L'9' ;
			   })) {
				continue ;
			}

			DisplayType1ClassRegistration row ;	// 値と保護の確認が完了するまで保留する一登録
			row.slot = slot ;
			HKEY	   raw{} ;	// 既に配下を監視中のクラスにある直接子
			const auto opened =
				RegOpenKeyExW( parents.back().get(), row.slot.c_str(), REG_OPTION_OPEN_LINK,
							  KEY_READ | KEY_WOW64_64KEY, &raw) ;	// リンクを辿らず一件だけ開く
			// クラスが開けても各元登録の読取不能を不在にしない
			if( opened != ERROR_SUCCESS) {
				return HRESULT_FROM_WIN32( opened) ;
			}

			AutoLoggerRegistryKey child ;	// 同じクラス配下の元キーの保持
			child.reset( raw) ;
			auto error = requireOrdinaryAutoLoggerKey( parents.back().get(), row.slot.c_str(),
													  // 別のレジストリ位置へ転送するキーを拒否する
													  child.get()) ;
			// 通常の直接子だけで元のアクセス権を読む
			if( error == 0U) {
				error = readAutoLoggerSecurity( child.get(), false, state.eventLogInheritance,
											   row.security) ;
			}

			// 同じ登録の保護を確認できなければ元値を採用しない
			if( error != 0U) {
				return error ;
			}

			std::uint32_t idType{} ;	// MatchingDeviceIdの実型または不在
			std::uint32_t pathType{} ;	// DriverStorePathの実型または不在
			error =
				readOptionalStorageString( child.get(), L"MatchingDeviceId", row.matchingId, idType) ;
			// 同じ登録の元一致IDが読めた場合だけ実パスの型を確認する
			if( error == 0U) {
				error = readOptionalStorageString( child.get(), L"DriverStorePath", row.storePath,
												  pathType) ;
			}

			// 型が異なる元値や曖昧な展開を既知の登録へ変換しない
			if( error != 0U || (row.matchingId && idType != REG_SZ) ||
			   (row.storePath && pathType != REG_SZ)) {
				return error ? error : INVALID ;
			}

			made.registrations.push_back( std::move( row)) ;
		}

		const auto changed = WaitForMultipleObjects(
			// 全観測中に起きた変更
			static_cast<DWORD>( events.size()), events.data(), FALSE, 0U) ;
		// 途中変更や通知失敗から同一時点のクラス登録を発行しない
		if( changed != WAIT_TIMEOUT) {
			return HRESULT_FROM_WIN32( changed == WAIT_FAILED ? GetLastError() : ERROR_RETRY) ;
		}

		std::ranges::sort( made.registrations, {}, &DisplayType1ClassRegistration::slot) ;
		made.controlSet = std::move( state.controlSet) ;
		snapshot		= std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

namespace {
// 選択された親に要求するWindowsのDisplayクラスGUID
constexpr GUID DISPLAY_TYPE1_REGISTRY_CLASS{
	0x4d36e968, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}} ;
// 同じDisplayクラスGUIDを表すWindowsのレジストリキー名
constexpr std::wstring_view DISPLAY_TYPE1_REGISTRY_CLASS_NAME{
	L"{4d36e968-e325-11ce-bfc1-08002be10318}"} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ選択Displayに設定されたWindowsの相対Driverキー名を取得する
 * @param[in] devices 選択親を開いたWindowsデバイス情報集合
 * @param[in,out] parent 同じ集合に属する選択親をWindowsの照会へ同期で渡す
 * @param[out] driverKey 正式Displayクラスと4桁の直接子。失敗時は更新しない
 * @return 元Display登録の明示値で0、型・構文・読取りの不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readDisplayType1DriverKey( HDEVINFO devices, SP_DEVINFO_DATA &parent,
									  std::wstring &driverKey)
{
	constexpr std::wstring_view CLASS_NAME{
		DISPLAY_TYPE1_REGISTRY_CLASS_NAME} ;	// 相対パスの固定クラス部分
	constexpr std::size_t SLOT_LENGTH = 4U ;	// Windowsのクラス登録番号の十進桁数
	std::array<wchar_t, CLASS_NAME.size() + 1U + SLOT_LENGTH + 1U>
		  value{} ;	// 区切りと終端を含む元領域
	DWORD type{} ;	// SetupAPIが返すレジストリの元型
	DWORD bytes{} ;	// SetupAPIが実際に返した元全長
	// Windowsのプロパティ照会にUTF-16の領域をbyte列として渡す
	if( !SetupDiGetDeviceRegistryPropertyW( devices, &parent, SPDRP_DRIVER, &type,
										  reinterpret_cast<PBYTE>( value.data()),
										  static_cast<DWORD>( sizeof( value)), &bytes)) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	const std::wstring_view relative{value.data(), value.size() - 1U} ;	// 終端を除く元照会値
	const auto slot = relative.substr( CLASS_NAME.size() + 1U) ;		// 直接の登録番号だけを検証する
	// 別クラス、埋込み終端、追加の階層、文字や長さの違う登録番号を拒否する
	if( type != REG_SZ || bytes != sizeof( value) || value.back() != L'\0' ||
	   !same( relative.substr( 0U, CLASS_NAME.size()), CLASS_NAME) ||
	   relative[CLASS_NAME.size()] != L'\\' || !std::ranges::all_of( slot, []( const wchar_t digit) {
		   return digit >= L'0' && digit <= L'9' ;
	   })) {
		return INVALID ;
	}

	driverKey = relative ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護の確認済みキーで一つの固定値の実型と原バイトを読み取る
 * @param[in] key 同じ観測で保持した通常キー。正式に不在ならnull
 * @param[in] name 確認済み実行物が参照する一つの固定値名
 * @param[out] result 実在時は元型と全バイト。正式不在と失敗時は空
 * @return 正式不在または全元値で0、型や長さの途中変更・読取失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readDisplayType1RegistryValue( HKEY key, const wchar_t *name,
										  std::optional<DisplayType1RegistryValue> &result)
{
	result.reset() ;
	// 正式不在のキーに別の場所からの値を補完しない
	if( !key) {
		return 0U ;
	}

	constexpr DWORD MAX_BYTES = 8192U ;	// 型を問わず保持する元値の上限byte数
	DWORD			type{} ;			// 初回照会時にWindowsが返す保存型
	DWORD			required{} ;		// 変換前の元値の全byte数
	// 最初の照会で元型と長さ又は正式な不在を得る
	const auto		sized = RegQueryValueExW( key, name, nullptr, &type, nullptr, &required) ;
	// 直接値の正式不在だけを空の成功へ含める
	if( sized == ERROR_FILE_NOT_FOUND) {
		return 0U ;
	}

	// 失敗や上限超過を空の値へ変換しない
	if( sized != ERROR_SUCCESS || required > MAX_BYTES) {
		return HRESULT_FROM_WIN32( sized == ERROR_SUCCESS ? ERROR_BUFFER_OVERFLOW : sized) ;
	}

	DisplayType1RegistryValue made ;	// 型と全長を再確認してから返す元値
	made.bytes.resize( required) ;
	BYTE	   empty{} ;			// 元値がゼロ長でも二回目を長さ専用照会にしないための領域
	DWORD	   bytes = required ;	// APIの入力容量と実際に読んだbyte数
	DWORD	   currentType{} ;		// 再照会時のWindows保存型
	// Win32へbyte列の可変領域を渡し、値の全体を読取る
	const auto read = RegQueryValueExW(
		key, name, nullptr, &currentType,
		required == 0U ? &empty : reinterpret_cast<PBYTE>( made.bytes.data()), &bytes) ;
	// 照会途中の削除・変更を最初からの不在や整合済みの元値へ変換しない
	if( read != ERROR_SUCCESS || currentType != type || bytes != required) {
		return read == ERROR_SUCCESS ? HRESULT_FROM_WIN32( ERROR_RETRY) : HRESULT_FROM_WIN32( read) ;
	}

	made.type = type ;
	result	  = std::move( made) ;
	return 0U ;
}

/** @brief Type 1の固定の直接親と各キーに許す読取り条件 */
struct DisplayType1RegistryPath {
	/// 固定の直接子名。実制御セットと選択番号だけは観測時の元名を使う
	const wchar_t		   *name ;
	/// 同じ表の既読の親。ルートではHKLMを使う
	std::size_t				parent ;
	/// 正式なリンク又は正式不在を許す位置を別に指定する
	StorageRegistryReadRole role = StorageRegistryReadRole::ORDINARY ;
	/// 当該キーの直接値の変更も監視する場合true
	bool					watchValues{} ;
} ;
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 選択Displayの実Driverキーと共有二箇所のOpenCL Type 1対象値を読取る
 * @param[in] devices 選択親を開いたWindowsのデバイス情報集合。同期中だけ借用する
 * @param[in,out] parent 同じ情報集合に属する選択Displayのデバイス情報
 * @param[out] snapshot 保護、元型、元値と正式な不在。失敗時は空
 * @return 現在の相対Driverキーと各作用先を安定して読めた場合0、その他は元HRESULT
 * @note レジストリは読取り専用。元実行物、親子関係、他の作用、導入可否は確定しない
 */
//------------------------------------------------------------------------------
NativeError readDisplayType1RegistrySnapshot( HDEVINFO devices, SP_DEVINFO_DATA &parent,
											 DisplayType1RegistrySnapshot &snapshot)
{
	snapshot = {} ;
	// Windowsが選択親として扱う同じDisplayクラス以外からは観測しない
	if( !devices || devices == INVALID_HANDLE_VALUE || parent.cbSize != sizeof( parent) ||
	   !IsEqualGUID( parent.ClassGuid, DISPLAY_TYPE1_REGISTRY_CLASS)) {
		return E_INVALIDARG ;
	}

	try {
		DisplayType1RegistrySnapshot made ;	// 全キーと値を確認してから公開する作業結果
		auto						 error =
			// 実際の親から読む元結合
			readDisplayType1DriverKey( devices, parent, made.driverKey) ;
		// 現用の相対キーが不明なら別のDisplay登録番号を探索しない
		if( error != 0U) {
			return error ;
		}

		constexpr std::size_t ROOT = std::tuple_size_v<decltype( made.keySecurity)> ;	// HKLMの親指定
		constexpr std::size_t CONTROL_SET = 2U ;										// 正式リンクから読み取る同じ制御セット
		constexpr std::size_t SLOT		  = 6U ;										// 選択親のWindows相対Driverキーの登録番号
		constexpr auto		  OPTIONAL_KEY =
			StorageRegistryReadRole::ABSENCE_ALLOWED ;	// 正式不在も観測する枝
		const auto *slot =
			// 元番号
			made.driverKey.c_str() + DISPLAY_TYPE1_REGISTRY_CLASS_NAME.size() + 1U ;
		const std::array paths{
			DisplayType1RegistryPath{L"SYSTEM", ROOT},
			DisplayType1RegistryPath{L"CurrentControlSet", 0U,
									 StorageRegistryReadRole::CURRENT_CONTROL_SET, true},
			DisplayType1RegistryPath{nullptr, 0U},
			DisplayType1RegistryPath{L"Control", CONTROL_SET},
			DisplayType1RegistryPath{L"Class", 3U},
			DisplayType1RegistryPath{DISPLAY_TYPE1_REGISTRY_CLASS_NAME.data(), 4U},
			DisplayType1RegistryPath{slot, 5U, StorageRegistryReadRole::ORDINARY, true},
			DisplayType1RegistryPath{L"CopyToVMOverwrite", SLOT, OPTIONAL_KEY, true},
			DisplayType1RegistryPath{L"CopyToVMOverwriteWow64", SLOT, OPTIONAL_KEY, true},
			DisplayType1RegistryPath{L"Services", CONTROL_SET},
			DisplayType1RegistryPath{L"AMD External Events Utility", 9U, OPTIONAL_KEY, true},
			DisplayType1RegistryPath{L"SOFTWARE", ROOT},
			DisplayType1RegistryPath{L"AMD", 11U, OPTIONAL_KEY},
			DisplayType1RegistryPath{L"EEU", 12U, OPTIONAL_KEY, true},
		} ; // 元実行物が参照する直接階層とその保護を固定順で観測する
		static_assert( std::tuple_size_v<decltype( paths)> == ROOT) ;
		std::array<StorageRegistryChangeEvent, ROOT>
			watches ;	// 各キーへの独立した変更通知を所有する
		std::array<AutoLoggerRegistryKey, ROOT>
								 keys ;						// 通知確認まで元の全親と葉を開いたまま保持する
		std::array<HANDLE, ROOT> events{} ;					// 最後に一度に確認する作成済み通知
		std::size_t				 count{} ;					// 途中で親が正式不在の枝を除いた通知数
		StorageRegistryReadState state{nullptr, {}, 0U} ;	// 同じ正式リンクを解決する元状態
		// 各位置で監視を開始し、同じ固定木の保護と正式な葉の不在を確認する
		for( std::size_t index = 0U; index < paths.size(); ++index) {
			const auto &path	  = paths[index] ;	// 確認する一枝と許可した直下名
			const HKEY	keyParent = path.parent == ROOT ? HKEY_LOCAL_MACHINE
														: keys[path.parent].get() ;	// 保持した正規親
			// 保護を確認して正式に不在だった親の配下には別の位置を使わない
			if( !keyParent) {
				continue ;
			}

			watches[index].reset( CreateEventW( nullptr, TRUE, FALSE, nullptr)) ;
			// 途中変更を検出できない範囲を同じ観測として扱わない
			if( !watches[index]) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			state.changed	 = watches[index].get() ;
			events[count++]	 = state.changed ;
			const auto *name = index == CONTROL_SET ? state.controlSet.c_str()
													: path.name ;	// 同じリンクで解決した一名
			const DWORD filter =
				REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_SECURITY |
				(path.watchValues ? REG_NOTIFY_CHANGE_LAST_SET : 0U) ;	// 直接キーの監視範囲
			error = readProtectedStorageKey( keyParent, name, path.role, state, keys[index],
											made.keySecurity[index], filter) ;
			// 保護・解決・通知の異常を構成要素の不存在へ読み替えない
			if( error != 0U) {
				return error ;
			}
		}

		const std::array values{
			std::tuple{SLOT, L"OpenCLDriverName", &made.openClDriverName},
			std::tuple{SLOT, L"OpenCLDriverNameWow", &made.openClDriverNameWow},
			std::tuple{SLOT, L"CheckRegistration", &made.parentCheckRegistration},
			std::tuple{std::size_t{7U}, L"AMDOpenCL", &made.copyToVmOverwrite},
			std::tuple{std::size_t{8U}, L"AMDOpenCL", &made.copyToVmOverwriteWow64},
			std::tuple{std::size_t{10U}, L"CheckRegistration", &made.serviceCheckRegistration},
			std::tuple{std::size_t{13U}, L"CheckRegistration", &made.softwareCheckRegistration},
		} ; // 選択親と共有二箇所で実行物が対象とする元値だけを読む
		// 全位置の変更監視が有効な間に各値の元型と全byteを確認する
		for( const auto &[index, name, value] : values) {
			error = readDisplayType1RegistryValue( keys[index].get(), name, *value) ;
			// 一部の観測失敗を正式不在として返さない
			if( error != 0U) {
				return error ;
			}
		}

		std::wstring currentDriverKey ;	// 同じWindows機器から再取得する元結合
		error = readDisplayType1DriverKey( devices, parent, currentDriverKey) ;
		// 読取りの両端で親の登録位置が一致した場合だけ保持する
		if( error != 0U || !same( made.driverKey, currentDriverKey)) {
			return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}

		const auto changed = WaitForMultipleObjects( static_cast<DWORD>( count), events.data(), FALSE,
													0U) ;	// 全元キーの読取り途中の変更
		// 通知の変化や照会失敗を安定した現在レジストリ値へ変換しない
		if( changed != WAIT_TIMEOUT) {
			return HRESULT_FROM_WIN32( changed == WAIT_FAILED ? GetLastError() : ERROR_RETRY) ;
		}

		made.controlSet = std::move( state.controlSet) ;
		snapshot		= std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの関連ブートサービスが使うSystemイベントを保護付きで取得する
 * @param[in] serviceName 同じ署名付き元選択が示した直接の関連イベント名
 * @param[out] snapshot 正式制御セット、親保護と葉の現在値。読取り失敗時は空
 * @return 親と葉の観測で0、保護、形式、名前または読取りの不成立はHRESULT
 * @note 別のイベント葉を補完せず、署名元の所有や導入可否は決めない
 */
//------------------------------------------------------------------------------
NativeError readSingleBootStorageEventSnapshot( std::wstring_view			   serviceName,
											   StorageSingleBootEventSnapshot &snapshot)
{
	snapshot = {} ;
	// 元サービス名の範囲だけをイベントログの直接子名として扱う
	if( !isStorageEventSourceName( serviceName)) {
		return INVALID ;
	}

	try {
		StorageSingleBootEventSnapshot made ;	// すべての親とイベントを確認するまで保持する
		made.event.name = serviceName ;
		const auto error =
			readStorageEventSources( made.controlSet, made.eventParents, std::span{&made.event, 1U},
									false) ;	// 同じ制御セットの関連イベントの観測
		// 完全な現在観測だけを後続の元署名の照合へ渡す
		if( error == 0U) {
			snapshot = std::move( made) ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 署名付き選択が指定した関連サービスと名前付きのSystemイベントを読取専用で観測する
 * @param[in] selected 検証済みの元選択と六欄形式のAddServiceを持つ自動起動補助サービス
 * @param[out] snapshot 正式な不在と、存在する場合の元値・保護。失敗時は空
 * @return 二つの元イベントを観測できれば0、それ以外はHRESULT
 * @note 現在値から旧所有やファイルの信頼を推定せず、登録・起動は行わない
 */
//------------------------------------------------------------------------------
NativeError readNamedStorageEventSnapshot( const SelectedStorageServiceFacts &selected,
										  StorageSystemEventSnapshot		&snapshot)
{
	snapshot			  = {} ;
	const auto &auxiliary = selected.auxiliary ;	// 検査済みの別補助サービスの元宣言
	// 明示名が署名付きの六欄System宣言にあるときだけその葉を探す
	if( !auxiliary || auxiliary->start != SERVICE_AUTO_START || auxiliary->copy.dirid != 13 ||
	   auxiliary->addServiceFields.size() != 6U ||
	   !same( auxiliary->addServiceFields[4], L"System")) {
		return INVALID ;
	}

	return readNamedStorageEventSources( selected.name, auxiliary->addServiceFields[5], snapshot) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現用登録の署名付き関連サービスと明示イベントの現在値を保護付きで読む
 * @param[in] declared 同じ機器の登録INFと元CATに照合済みのイベント宣言
 * @param[out] snapshot 現用関連サービスと明示イベントの観測。失敗時は空
 * @return 保護付きで両方を読めた場合0、入力・保護・読取りの不成立はHRESULT
 * @note 元と同じ直接のイベント名だけを読み、登録や現在値を変更しない
 */
//------------------------------------------------------------------------------
NativeError readRegisteredNamedStorageEventSnapshot(
	const RegisteredStoragePackageEvidence &declared, StorageSystemEventSnapshot &snapshot)
{
	snapshot = {} ;
	// 現用関連名と同じ署名文書に属する二つの既知宣言だけを現在キーへ結ぶ
	if( !declared.eventReferences[0U] || !declared.eventReferences[1U] ||
	   !same( declared.installedService, declared.eventReferences[0U]->name) ||
	   !declared.eventReferences[1U]->categoryCount) {
		return INVALID ;
	}

	return readNamedStorageEventSources( declared.installedService,
										declared.eventReferences[1U]->name, snapshot) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元補助サービスとSystem32実行ファイル、同じ二つのSystemイベント登録を読み取る
 * @param[in] selected 署名済みINFから閉包を保持した一つの関連・補助サービスの選択
 * @param[out] snapshot 現在値を保持する。途中失敗は空を返す
 * @return 読取り成功0、権限・元位置・読取りに問題がある場合HRESULT
 * @note 端末を変更しない。同名の現在構成に導入権限や元配布の所有を認めない
 */
//------------------------------------------------------------------------------
NativeError readStorageAuxiliaryHostSnapshot( const SelectedStorageServiceFacts &selected,
											 StorageAuxiliaryHostSnapshot	   &snapshot)
{
	snapshot = {} ;
	// 別コンポーネントやレジストリの親を参照する名前を受け取らない
	if( !selected.auxiliary || selected.name.empty() || selected.auxiliary->name.empty() ||
	   !relative( selected.name) || !relative( selected.auxiliary->name) ||
	   selected.name.find( L'\\') != selected.name.npos ||
	   selected.auxiliary->name.find( L'\\') != selected.auxiliary->name.npos ||
	   same( selected.name, selected.auxiliary->name)) {
		return INVALID ;
	}

	StorageAuxiliaryHostSnapshot made ;	// 全読取りが確定する前の作業値
	auto error = readAuxiliaryStorageServiceSnapshot( selected.auxiliary->name,
													 made.service) ;	// 補助サービスの照会結果
	// 同名サービスの読取り失敗をSystem32ファイルの不存在で置き換えない
	if( error == 0U) {
		error = readSystem32ExecutableSnapshot( selected.auxiliary->copy.target, made.executable) ;
	}

	// 作用を持つ両イベントソースの状態を保護された親から観測する
	if( error == 0U) {
		made.events[0].name = selected.name ;
		made.events[1].name = selected.auxiliary->name ;
		error = readStorageEventSources( made.controlSet, made.eventParents, made.events, false) ;
	}

	// 全読取りが成功した場合に限り元観測を公開する
	if( error == 0U) {
		snapshot = std::move( made) ;
	}

	return error ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 署名付き選択または登録が指定した自動起動補助の現在構成とファイルを再観測する
 * @param[in] name CATに照合済みの補助サービス名
 * @param[in] leaf 同じ補助が直接参照する元EXEの名前
 * @param[in] errorControl 同じ元補助が宣言したエラー制御
 * @param[out] snapshot 正式不在または現在の保護付き構成とファイル。失敗時は空
 * @return 同じ構成とファイルを二度観測できれば0、失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readAutoStartStorageAuxiliarySnapshotImpl( std::wstring_view name,
													  std::wstring_view leaf,
													  std::uint32_t		errorControl,
													  StorageAutoStartAuxiliarySnapshot &snapshot)
{
	snapshot = {} ;
	StorageAutoStartAuxiliarySnapshot made ;								// 現在のSCMと実行ファイルが揃うまで非公開の観測
	auto error = readAuxiliaryStorageServiceSnapshot( name, made.service) ;	// 元SCMの照会結果
	// 正式不在とSCMの元失敗を区別する
	if( error != 0U) {
		return error ;
	}

	// サービスの正式不在時に別のパッケージや実行ファイルを探索しない
	if( made.service) {
		const auto &config = made.service->config ;	// 読み取った現在SCMの元値
		// 署名付き選択と異なる現在の開始方式や役割は既存の同じサービスにしない
		if( !same( config.name, name) || config.type != SERVICE_WIN32_OWN_PROCESS ||
		   config.start != SERVICE_AUTO_START || config.errorControl != errorControl) {
			return UNSUPPORTED ;
		}

		error = readDriverStoreExecutableSnapshot( config.binary, leaf, made.executablePath,
												  made.executable) ;
		// 既存サービスが指すEXEの不在や別位置はサービス不在にしない
		if( error != 0U) {
			return error ;
		}
	}

	std::optional<AuxiliaryStorageServiceSnapshot> freshService ;	// ファイル観測後の独立SCM読取り
	error = readAuxiliaryStorageServiceSnapshot( name, freshService) ;
	// 正式不在を含む構成・状態・保護の途中変更を採用しない
	if( error != 0U || freshService != made.service) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	// 実在するサービスでは同じSCMの元指示からファイルも再観測する
	if( freshService) {
		std::wstring				freshPath ;	// 二回目の正規配置先
		ProtectedExecutableSnapshot freshFile ;	// 二回目の親とEXEの全観測値
		error = readDriverStoreExecutableSnapshot( freshService->config.binary, leaf, freshPath,
												  freshFile) ;
		// 異なる識別子、時刻、保護、元バイトを同じ現在ファイルとして扱わない
		if( error != 0U || freshPath != made.executablePath || freshFile != made.executable) {
			return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}
	}

	snapshot = std::move( made) ;
	return 0U ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 元選択の自動起動補助の現在SCM構成とDriver Store内のファイルを読み取る
 * @param[in] selected 署名付きの元選択と直接コピーの補助EXE宣言
 * @param[out] snapshot 正式不在または保護を確認した現在構成と実ファイル。失敗時は空
 * @return 同じ端末の保護付き観測が成立すれば0、構成・位置・読取の不成立はHRESULT
 * @note 同じ現在ファイルと元登録の署名による所有照合は別工程。サービスの起動・変更は行わない
 */
//------------------------------------------------------------------------------
NativeError readAutoStartStorageAuxiliarySnapshot( const SelectedStorageServiceFacts &selected,
												  StorageAutoStartAuxiliarySnapshot &snapshot)
{
	snapshot			  = {} ;
	const auto &auxiliary = selected.auxiliary ;	// 署名付きの元選択から区別した補助サービス
	// 直接コピーの自動起動補助以外をDriver Store候補として検索しない
	if( !auxiliary || auxiliary->type != SERVICE_WIN32_OWN_PROCESS ||
	   auxiliary->start != SERVICE_AUTO_START || auxiliary->copy.dirid != 13 ||
	   auxiliary->addServiceFields.size() != 6U || auxiliary->name.empty() ||
	   same( auxiliary->name, selected.name) || auxiliary->copy.source.empty()) {
		return INVALID ;
	}

	return readAutoStartStorageAuxiliarySnapshotImpl( auxiliary->name, auxiliary->copy.source,
													 auxiliary->errorControl, snapshot) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現用の元CATが確認した補助サービスの現在SCM構成とEXEを読み取る
 * @param[in] declared 同じ機器の登録INFと元CATで照合済みの補助サービス
 * @param[out] snapshot 正式不在または同じ登録元に一致した現在観測。失敗時は空
 * @return 読取りと元位置・バイトの照合が成立すれば0、失敗はHRESULT
 * @note 実在する補助は保護付きで読み、起動・停止・構成変更は行わない
 */
//------------------------------------------------------------------------------
NativeError readRegisteredAutoStartStorageAuxiliarySnapshot(
	const RegisteredStorageHelperEvidence &declared, StorageAutoStartAuxiliarySnapshot &snapshot)
{
	snapshot			 = {} ;
	const auto separator = declared.storePath.rfind( L'\\') ;	// 実パッケージ親の直後の区切り
	// 同じ登録元の完全Pathと元ハッシュが揃う自動起動補助だけを読み取る
	if( declared.type != SERVICE_WIN32_OWN_PROCESS || declared.start != SERVICE_AUTO_START ||
	   declared.name.empty() || separator == declared.storePath.npos ||
	   separator + 1U == declared.storePath.size() || declared.sourceSha256.size() != 64U ||
	   !same( declared.binary, declared.storePath)) {
		return INVALID ;
	}

	// 元登録のパッケージから取り出した正確な元EXE名
	const auto leaf = std::wstring_view{declared.storePath}.substr( separator + 1U) ;
	StorageAutoStartAuxiliarySnapshot made ;	// 元位置とバイトの照合まで公開しない
	// 同じ登録済み補助の保護付き現在観測の成否
	const auto						  error =
		readAutoStartStorageAuxiliarySnapshotImpl( declared.name, leaf, declared.errorControl, made) ;
	// 他の登録位置や別ファイルを現用配布の正規補助に変換しない
	if( error != 0U ||
	   (made.service &&
		(!same( made.executablePath, declared.storePath) || !made.executable.existing ||
		 made.executable.existing->sha256 != declared.sourceSha256))) {
		return error != 0U ? error : INVALID ;
	}

	snapshot = std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現用と候補の重なる候補変更先を同じ制御セットと現在状態に結ぶ
 * @param[in] selected 同じ候補が宣言した署名付き補助構成
 * @param[in] host 個々の署名元から読み取った現用と候補の現在観測
 * @return 重なる現在状態が全部一致すれば0、読取り間の変化は再試行HRESULT
 * @note 新旧の別サービス名を同一視しない。共有所有や利用者の導入資格は発行しない
 */
//------------------------------------------------------------------------------
NativeError verifyStorageAutomaticHostCoherence( const SelectedStorageServiceFacts  &selected,
												const StorageAutomaticHostSnapshot &host) noexcept
{
	// 別の制御セットから得たイベントと共有設定を一つの状態に結合しない
	if( host.shared.acpi.controlSet.empty() ||
	   host.shared.acpi.controlSet != host.shared.autoLogger.controlSet ||
	   host.shared.acpi.controlSet != host.events.controlSet) {
		return HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	// 機器未指定または正式な初回の場合は、観測済みの共有先だけを照合する
	if( !host.device) {
		return 0U ;
	}

	// 選択機器と全所有機器の元観測を、候補と共通する変更先へそれぞれ照合する
	const auto verify = [&]( const StorageAutomaticRegistrationSnapshot &current) -> NativeError {
		// 正式に未導入の選択機器には現用のイベントと補助が存在しない
		if( !current.package) {
			return 0U ;
		}

		// 現用登録も候補の変更先と同じ制御セット・親の保護を観測していなければならない
		if( current.events.controlSet != host.events.controlSet ||
		   current.events.eventParents != host.events.eventParents) {
			return HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}

		// 別の元名で読んだ二組の有限な葉のうち、共通の名前だけは同じ現在値でなければならない
		for( const auto &oldSource : current.events.events) {
			// 関連サービスと明示イベントのいずれの共通名も見落とさない
			for( const auto &targetSource : host.events.events) {
				// Windowsが同じ葉へ解決する名前の違いを除き、保護と原型まで比較する
				if( same( oldSource.name, targetSource.name) &&
				   std::tie( oldSource.present, oldSource.messageFile, oldSource.messageFileType,
							oldSource.typesSupported, oldSource.categoryCount, oldSource.security,
							oldSource.lastWrite) !=
					   std::tie( targetSource.present, targetSource.messageFile,
								targetSource.messageFileType, targetSource.typesSupported,
								targetSource.categoryCount, targetSource.security,
								targetSource.lastWrite)) {
					return HRESULT_FROM_WIN32( ERROR_RETRY) ;
				}
			}
		}

		// 同じ補助名ならSCMの構成・状態・実ファイルと保護も同一でなければならない
		if( !selected.auxiliary || !current.package->helper ||
		   (same( selected.auxiliary->name, current.package->helper->name) &&
			current.auxiliary != host.auxiliary)) {
			return HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}

		return 0U ;
	} ;

	// 選択機器の共通箇所が異なる場合は他の機器の一致で補わない
	const auto selectedResult = verify( host.device->selected) ;
	// 選択機器の観測が成立した場合だけ共有機器へ進む
	if( selectedResult != 0U) {
		return selectedResult ;
	}

	// どの機器の共通イベントや補助の状態も、一部欠落や別観測で置き換えない
	for( const auto &owner : host.device->owners) {
		const auto error = verify( owner.registered) ;	// 一つの元登録と共有先の照合
		// 一致しない元登録を候補へ結合しない
		if( !owner.registered.package || error != 0U) {
			return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}
	}

	return 0U ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 自動起動補助の現在構成を署名付き現用登録と同じ実ファイルに照合する
 * @param[in] declared 現用機器の元補助と元CATの照合証拠
 * @param[in] actual 候補と同名の現在補助の元構成と保護付きファイル
 * @return 元構成、元位置と現在ファイルの署名元が揃えばtrue
 * @note SCMの保護は現在観測に保持する。既定ACLの設定や導入の許可は行わない
 */
//------------------------------------------------------------------------------
bool matchesAutomaticStorageHelper( const RegisteredStorageHelperEvidence   &declared,
								   const StorageAutoStartAuxiliarySnapshot &actual)
{
	// 現在ファイルを別パッケージの同一ハッシュや元宣言のない場所で補わない
	if( !actual.service || !actual.executable.existing || declared.start != SERVICE_AUTO_START ||
	   !declared.security.empty() || !same( declared.storePath, actual.executablePath) ||
	   !same( declared.binary, actual.executablePath) || declared.sourceSha256.size() != 64U ||
	   declared.deployedSha256 != declared.sourceSha256 ||
	   actual.executable.existing->sha256 != declared.sourceSha256 ||
	   actual.service->config.security.empty()) {
		return false ;
	}

	// 元が表示名を省略した場合はSCMのサービス名が表示名になる
	const auto &display = declared.display.empty() ? declared.name : declared.display ;
	return actual.service->config.display == display &&
		   actual.service->config.description == declared.description &&
		   matchStorageAuxiliaryServiceExecution( *actual.service, declared) == 0U ;
}

/** @brief 一つの共有先について比較した現用登録の状態 */
struct StorageServiceClaims {
	/// 選択機器の元登録がこの名前を宣言する
	bool selected{} ;
	/// 選択外の機器の元登録もこの名前を宣言する
	bool peer{} ;
	/// 確認した宣言がすべて現在値と整合する
	bool match{true} ;
	/// 少なくとも一つの照合元が現在イベント資源の元ファイルを裏付ける
	bool ownsEventResource{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 現用登録と候補の変更先の一致から、一つのサービスまたはイベントを分類する
 * @param[in] claims 選択機器と他機器の署名付き元宣言を照合した結果
 * @param[in] exists 保護付き現在観測が実在を示す場合true
 * @param[in] maintains 候補が現在の定義と同じ値を指定する場合true
 * @return 確認した新規、維持、変更の種別。現用の帰属が未確認の場合はUNVERIFIED
 */
//------------------------------------------------------------------------------
StorageServiceChange classifyStorageServiceTarget( const StorageServiceClaims &claims, bool exists,
												  bool maintains) noexcept
{
	// 宣言が現物に結び付かない状態や残存物を所有確認済みにしない
	if( !claims.match || exists != (claims.selected || claims.peer)) {
		return StorageServiceChange::UNVERIFIED ;
	}

	// 現用宣言と同じ保存先が正式不在の場合だけ新規として扱う
	if( !exists) {
		return StorageServiceChange::CREATE ;
	}

	// 一致する定義でも既存値の観測と署名付き元登録の確認後に維持と判定する
	if( maintains) {
		return StorageServiceChange::KEEP ;
	}

	return claims.peer ? StorageServiceChange::UPDATE_SHARED
					   : StorageServiceChange::UPDATE_SELECTED ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じサービスを使用する機器の署名元を現在の起動サービスとSYSへ照合する
 * @param[in] registration 同名サービスを使用する機器の元登録
 * @param[in] selected 同じ配置先を持つ署名付き更新候補
 * @param[in] actual 同名SCMの現在構成。不在では空
 * @param[in] deployed 同じ時点に確認した正規SYSの現在配置。不在では空
 * @return 元サービスの構成、宛先、保護付き現物と元CATの全ハッシュが一致した場合true
 */
//------------------------------------------------------------------------------
bool matchesRegisteredStorageBoot(
	const RegisteredStoragePackageEvidence &registration,
	const SelectedStorageServiceFacts &selected, const std::optional<SystemServiceEvidence> &actual,
	const std::optional<ProtectedExecutableEvidence> &deployed) noexcept
{
	const auto &declared = registration.bootService ;	// 署名と元コピーで確認したカーネルサービス
	return declared && actual && deployed && !deployed->security.empty() &&
		   registration.driverSha256.size() == 64U &&
		   deployed->sha256 == registration.driverSha256 &&
		   same( actual->name, registration.installedService) &&
		   same( declared->binary, selected.binaryTarget) &&
		   matchesStorageBootImage( actual->binary, declared->binary) &&
		   declared->type == SERVICE_KERNEL_DRIVER && declared->start == SERVICE_BOOT_START &&
		   actual->type == declared->type && actual->start == declared->start &&
		   actual->errorControl == declared->errorControl && same( actual->group, declared->group) &&
		   actual->dependencies.empty() && !actual->security.empty() ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 更新先の起動サービスを保護付きSCM・SYSと元署名に照合する
 * @param[in] selected 元INFの署名、選択、コピーの検査を終えた候補
 * @param[in] device 現用・候補サービスに結ぶ完全な機器観測
 * @param[in] boot 元候補の同名サービスと同じSYS配置先の現在観測
 * @return 照合した変更の種別。元観測や所有が一致しない場合はUNVERIFIED
 * @note 導入直前の全状態の再照合と復旧同意は別工程。サービスを起動・変更しない
 */
//------------------------------------------------------------------------------
StorageServiceChange classifyStorageAutomaticBoot( const SelectedStorageServiceFacts	   &selected,
												  const StorageAutomaticDeviceSnapshot &device,
												  const StorageAutomaticBootSnapshot &boot) noexcept
{
	const auto &actual	 = boot.related.evidence ;		// 候補と同じ名前の現在SCM
	const auto &deployed = boot.destination.existing ;	// 現在のSYS配置と完全ハッシュ
	// 片側だけ残る場合も、ファイルやサービスの新規配置として扱わない
	if( !same( boot.related.name, selected.name) || selected.binarySha256.size() != 64U ||
	   !selected.group || boot.destination.directorySecurity.empty() ||
	   actual.has_value() != deployed.has_value()) {
		return StorageServiceChange::UNVERIFIED ;
	}

	StorageServiceClaims claims ;	// 現在SYSの配布元に結び付く機器の集計
	// 別名の現用がある場合も、同名の既存サービスの所有へ流用しない
	if( const auto &owner = device.selected.package ;
	   owner && same( owner->installedService, selected.name)) {
		claims.selected = true ;
		claims.match	= matchesRegisteredStorageBoot( *owner, selected, actual, deployed) ;
	}

	// 同サービスを使用している他の全機器を元配布へ照合する
	for( const auto &peer : device.owners) {
		const auto &owner = peer.registered.package ;	// 現用機器の元署名
		// 完全な機器一覧の一部を照合不能のまま省略しない
		if( !owner) {
			return StorageServiceChange::UNVERIFIED ;
		}

		// 同じ候補が更新する起動サービスの機器だけを所有者として数える
		if( same( owner->installedService, selected.name)) {
			claims.peer = true ;
			claims.match =
				claims.match && matchesRegisteredStorageBoot( *owner, selected, actual, deployed) ;
		}
	}

	const bool maintains = actual && deployed && deployed->sha256 == selected.binarySha256 &&
						   actual->type == selected.type && actual->start == selected.start &&
						   actual->errorControl == selected.errorControl &&
						   // 候補が指定する同じ実行条件とSYS
						   same( actual->group, *selected.group) ;
	return classifyStorageServiceTarget( claims, actual.has_value(), maintains) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元候補が名前付きイベントに使うSystem32のDLLを保護付きで読む
 * @param[in] selected コピー先と元バイトを照合済みの選択
 * @param[out] resource 元候補がDLLを指定した場合の観測。省略や失敗時は空
 * @return 観測または元の省略を確認した場合0、それ以外はHRESULT
 * @note 同名の既存DLLを元配布の所有と見なさない。DLLをロードせず変更しない
 */
//------------------------------------------------------------------------------
NativeError readStorageAutomaticEventResource(
	const SelectedStorageServiceFacts					 &selected,
	std::optional<StorageAutomaticEventResourceSnapshot> &resource)
{
	resource.reset() ;
	// コピーを指定しない選択には候補資源の書込み先を作らない
	if( !selected.auxiliary || !selected.auxiliary->eventMessageCopy) {
		return 0U ;
	}

	const auto &copy = *selected.auxiliary->eventMessageCopy ;	// 同じ署名付き選択の元コピー
	// 調べる先は元のSystem32コピーが指定した場所に限定する
	if( copy.dirid != 11 || copy.fields.size() != 1U || copy.sha256.size() != 64U ||
	   copy.bytes == 0U) {
		return INVALID ;
	}

	StorageAutomaticEventResourceSnapshot observed ;	// 完全な保護付き現在値だけを公開する
	const auto							  error = readSystem32StorageEventResourceSnapshot(
		   copy.target, observed.destination) ;	// 元イベント資源の配置照会
	// 読取り失敗を正式なファイル不存在に置き換えない
	if( error == 0U) {
		resource = std::move( observed) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 候補の補助サービスと二つのイベントの変更を署名付き現用登録へ照合する
 * @param[in] selected 元閉包に結ぶ検証済みの自動起動補助付き選択
 * @param[in] infSha256 同じ選択を保持する署名付きINFの完全SHA-256
 * @param[in] catalogSha256 元INFと同じ閉包の署名付きCATの完全SHA-256
 * @param[in,out] host 候補変更先と同じ現用機器群。失敗時は分類を空にする
 * @return 全分類の完了0。未確定の使用中状態または入力の不成立はHRESULT
 * @note 元宣言が省略するイベント資源は現在値を保持する。適用後の残存は別に確認する
 */
//------------------------------------------------------------------------------
NativeError classifyStorageAutomaticServiceChanges( const SelectedStorageServiceFacts &selected,
												   std::wstring_view				  infSha256,
												   std::wstring_view				  catalogSha256,
												   StorageAutomaticHostSnapshot		 &host)
{
	host.serviceChanges.reset() ;
	const auto &helper = selected.auxiliary ;	// 元の自動起動補助
	// 元署名が明示したイベント資源の複写元。省略ならnull
	const auto *resource =
		helper && helper->eventMessageCopy ? &*helper->eventMessageCopy : nullptr ;
	// 再分類に失敗した場合に旧観測の所有判定を残さない
	if( host.eventResource) {
		host.eventResource->change = StorageServiceChange::UNVERIFIED ;
	}

	// 同一の元選択、署名元、候補の二つの保護付きイベント、現用機器を揃える
	if( !host.device || !helper || helper->addServiceFields.size() != 6U ||
	   infSha256.size() != 64U || catalogSha256.size() != 64U ||
	   !same( selected.name, host.events.events[0U].name) ||
	   !same( helper->addServiceFields[5U], host.events.events[1U].name) ||
	   host.auxiliary.service.has_value() != host.auxiliary.executable.existing.has_value() ||
	   (resource != nullptr) != host.eventResource.has_value() ||
	   std::ranges::any_of( host.device->owners,
						   []( const auto &owner) { return !owner.registered.package ; })) {
		return HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	try {
		const auto slash = selected.binaryTarget.rfind( L'\\') ;	// 関連SYS名の先頭を区切る位置
		// 元グラフが照合した関連SYSの通常名がなければ同じイベント資源にしない
		if( slash == selected.binaryTarget.npos || slash + 1U == selected.binaryTarget.size()) {
			return INVALID ;
		}

		std::array<RegisteredStorageEventReference, 2U> desired ;	// 検査済みの二つの書込み定義
		desired[0U].name = selected.name ;
		desired[0U].messageFile =
			L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\drivers" +
			selected.binaryTarget.substr( slash) ;
		desired[0U].typesSupported = 7U ;
		desired[1U].name		   = helper->addServiceFields[5U] ;
		desired[1U].typesSupported = 31U ;
		desired[1U].categoryCount  = 1U ;
		// 元候補がDLLを指定したときだけ、明示イベントが書き込む資源の元値を追加する
		if( resource) {
			// 保護付き配置先と一意な元ファイルがそろわない場合は分類しない
			if( resource->dirid != 11 || resource->fields.size() != 1U ||
			   resource->sha256.size() != 64U || resource->bytes == 0U ||
			   host.eventResource->destination.directorySecurity.empty()) {
				return INVALID ;
			}

			desired[1U].messageFile =
				L"%SystemRoot%\\System32\\IoLogMsg.dll;%SystemRoot%\\System32\\" +
				resource->fields.front() ;
		}

		StorageServiceClaims				 helperClaims ;		// 現在の補助と同じ名前の署名元
		std::array<StorageServiceClaims, 2U> eventClaims{} ;	// 各同名イベントの元宣言と資源
		StorageServiceClaims				 fileClaims ;		// 同じ配置先を使う署名付きイベントと現物
		const auto *file = resource && host.eventResource->destination.existing
							   ? &*host.eventResource->destination.existing
							   : nullptr ;	// 保護付き配置先の実DLL
		bool		sameHelperSource{} ;	// 現在の補助と候補が同じ署名付き実選択か
		// 候補と同じ名前の作用だけについて、一つの現用機器の証拠を記録する
		const auto	observe = [&]( const StorageAutomaticRegistrationSnapshot &registration,
								  bool										  peer) {
			 const auto &package = *registration.package ;	// 同じ機器に現在登録された元署名
			 // 別名の旧補助サービスを更新候補と同じSCM対象に数えない
			 if( package.helper && same( package.helper->name, helper->name)) {
				 (peer ? helperClaims.peer : helperClaims.selected) = true ;
				 helperClaims.match									= helperClaims.match &&
									  matchesAutomaticStorageHelper( *package.helper, host.auxiliary) ;
				 sameHelperSource =
					 sameHelperSource ||
					 (package.infSha256 == infSha256 && package.catalogSha256 == catalogSha256 &&
					  same( package.installedSection, selected.selectedInstallSection) &&
					  package.helper->sourceSha256 == helper->copy.sha256) ;
			 }

			 const auto &named =
				 package.eventReferences[1U] ;	// 同じ署名付き登録が直接指定する名前付きイベント
			 // 署名元のイベント宣言とその実際の現在値が同じDLLを使う場合だけ配置の所有を調べる
			 if( resource && named && same( named->resourceLeaf, resource->fields.front())) {
				 const auto &actual = registration.events.events[1U] ;	// 同じ元署名に結ぶ現在イベント
				 // 選択機器が使う別のイベント源はこの候補の書換え対象に含めない
				 const bool	 shared = peer || !same( named->name, desired[1U].name) ;
				 (shared ? fileClaims.peer : fileClaims.selected) = true ;
				 fileClaims.match = fileClaims.match && file && !file->security.empty() &&
									!actual.security.empty() && !named->messageFile.empty() &&
									file->sha256 == named->resourceSha256 &&
									file->bytes == named->resourceBytes &&
									named->deployedResource == host.eventResource->destination &&
									matchesRegisteredStorageEvent( *named, actual) ;
			 }

			 // 既定と明示のどちらの元イベントも名前が同じ変更先へ照合する
			 for( const auto &declared : package.eventReferences) {
				 // 未宣言のイベントから現在値の所有を推測しない
				 if( !declared) {
					 continue ;
				 }

				 // 元宣言と候補名が一致する現在のイベントだけを対象とする
				 for( std::size_t index = 0U; index < desired.size(); ++index) {
					 // 異なるSystemイベントの所有根拠は使わない
					 if( !same( declared->name, desired[index].name)) {
						 continue ;
					 }

					 const auto &actual = host.events.events[index] ;	// 候補と同名の現在観測
					 auto		&claims = eventClaims[index] ;			// 同じイベントを使う署名元の集計
					 (peer ? claims.peer : claims.selected) = true ;
					 claims.match = claims.match && !actual.security.empty() &&
									matchesRegisteredStorageEvent( *declared, actual, true) ;
					 claims.ownsEventResource =
						 claims.ownsEventResource ||
						 (!declared->messageFile.empty() &&
						  (index == 0U ||
						   (!declared->resourceLeaf.empty() &&
							declared->resourceSha256.size() == 64U && declared->deployedResource &&
							declared->deployedResource->existing &&
							declared->deployedResource->existing->sha256 ==
								declared->resourceSha256 &&
							declared->deployedResource->existing->bytes ==
								declared->resourceBytes)) &&
						  matchesRegisteredStorageEvent( *declared, actual)) ;
				 }
			 }
		} ;

		// 現用がない選択機器は署名元がない独立した観測として扱う
		if( host.device->selected.package) {
			observe( host.device->selected, false) ;
		}

		// 選択候補と現用の関連サービスを共有する全機器について確認する
		for( const auto &owner : host.device->owners) {
			observe( owner.registered, true) ;
		}

		auto &changes = host.serviceChanges.emplace() ;	// 一つの候補から確認した三つの分類
		changes[0U] = classifyStorageServiceTarget( helperClaims, host.auxiliary.service.has_value(),
												   sameHelperSource) ;
		// 候補が明示する値だけの互換性と、現在資源の裏付けを区別する
		for( std::size_t index = 0U; index < desired.size(); ++index) {
			auto	   &claims	= eventClaims[index] ;			// 書かれない資源も現在の根拠を要求する
			const auto &actual	= host.events.events[index] ;	// 現在の値と実在の観測
			claims.match		= claims.match && (!actual.messageFile || claims.ownsEventResource) ;
			changes[index + 1U] = classifyStorageServiceTarget(
				claims, actual.present,
				matchesRegisteredStorageEvent( desired[index], actual, true)) ;
		}

		// 確認済みの元宣言を持つ現物だけを維持または変更として扱う
		if( resource) {
			// 元INFが資源を省略する機器でも、同じイベントが実際に使うDLLへの書換えに影響する
			if( (fileClaims.selected || fileClaims.peer) && eventClaims[1U].peer &&
			   matchesRegisteredStorageEvent( desired[1U], host.events.events[1U])) {
				fileClaims.peer = true ;
			}

			host.eventResource->change = classifyStorageServiceTarget(
				fileClaims, file != nullptr,
				file && file->sha256 == resource->sha256 && file->bytes == resource->bytes) ;
		}

		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 自動起動型の元選択が設定する作用を適用後の値へ照合する
 * @param[in] intended 同じ選択の署名確認済み作用と適用前のACPI観測
 * @param[in] current 同じ機器の元INF・CAT・SYS・EXEを照合済みの適用後観測
 * @param[in] rebootRequired 同じ指定適用APIがWindowsの再起動を要求した場合true
 * @return 元選択と共有設定の反映は0、署名済みの旧起動構成だけが残る再起動要求はS_FALSE、他の相違はHRESULT
 * @note 保護確認済みの現在値だけを読む。旧資源、他機器と実際の起動の確認は別に行う
 */
//------------------------------------------------------------------------------
NativeError verifyAppliedAutomaticStorageEffects( const StorageInfEffects			&intended,
												 const StorageAutomaticHostSnapshot &current,
												 bool rebootRequired) noexcept
{
	// 同じ署名付き元選択と新しい作用の読取りが全部そろうまで反映を確認しない
	if( !intended.automaticHost || !intended.service.auxiliary ||
	   !intended.sharedAcpiStorageFeatures || !intended.autoLogger ||
	   intended.powerSettings.empty() || !current.device || !current.device->selected.package ||
	   !current.boot || !current.autoLoggerRuntimePresent.has_value()) {
		return INVALID ;
	}

	const auto &registration = current.device->selected ;		// 同じ機器から読んだ現在の署名付き登録
	const auto &package		 = *registration.package ;			// 配置ファイルとサービス宣言を結んだ元配布
	const auto &before		 = intended.automaticHost->shared ;	// 当該操作の適用前の制御セットとACPI
	// 同じ制御セットのACPIと共有定義だけを、新しい登録の反映へ結び付ける
	if( !same( current.shared.acpi.controlSet, before.acpi.controlSet) ||
	   current.shared.acpiService != before.acpiService ||
	   current.shared.acpi.storageSupportedFeatures != intended.sharedAcpiStorageFeatures ||
	   current.shared.autoLogger.existing != intended.autoLogger ||
	   current.shared.acpi.controlSet != current.power.controlSet ||
	   package.powerSettings.size() != intended.powerSettings.size() ||
	   current.power.settings.size() != intended.powerSettings.size() ||
	   verifyStorageAutomaticHostCoherence( intended.service, current) != 0U) {
		return HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	const bool bootApplied =
		matchesRegisteredStorageBoot( package, intended.service, current.boot->related.evidence,
									 current.boot->destination.existing) ;	// 新登録の正規起動構成
	const auto &oldBoot = intended.automaticHost->boot ;					// 使用中の旧署名元に結び付けた配置
	// 同じ旧構成と保護付き実ファイルに限って再起動の残存根拠になる
	const bool	bootRetained = rebootRequired && oldBoot && oldBoot->related.evidence &&
							  oldBoot->destination.existing &&
							  (oldBoot->change == StorageServiceChange::UPDATE_SELECTED ||
							   oldBoot->change == StorageServiceChange::UPDATE_SHARED) &&
							  current.boot->related == oldBoot->related &&
							  current.boot->destination == oldBoot->destination ;
	// 新しい起動構成または署名付き旧構成の残存に限り、新しい補助と共有値の照合へ進む
	if( !same( package.installedService, intended.service.name) || (!bootApplied && !bootRetained) ||
	   !package.helper || !matchesAutomaticStorageHelper( *package.helper, registration.auxiliary)) {
		return HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	const auto &copy = intended.service.auxiliary->eventMessageCopy ;	// 同じ元選択が書く明示資源
	// 適用後の元登録と保護付きSystem32の現物を、同じ元選択のDLLに照合する
	if( copy) {
		const auto &registered	   = package.eventReferences[1U] ;				// 適用後の登録が宣言した同じ資源
		const auto &placement	   = current.eventResource ;					// 元候補が指定した配置先の現在観測
		const auto &beforeResource = intended.automaticHost->eventResource ;	// 導入前の配置先の保護
		const auto &oldEvents =
			intended.automaticHost->events ;	// 導入前の名前付きイベントと親の保護
		// 未配置、別バイト、保護不明や元登録との差を操作成功だけで反映済みにしない
		if( copy->fields.size() != 1U || !registered ||
		   !same( registered->resourceLeaf, copy->fields.front()) ||
		   registered->resourceSha256 != copy->sha256 || registered->resourceBytes != copy->bytes ||
		   !placement || placement->destination.directorySecurity.empty() ||
		   !placement->destination.existing ||
		   registered->deployedResource != placement->destination || !beforeResource ||
		   beforeResource->destination.directorySecurity !=
			   placement->destination.directorySecurity ||
		   oldEvents.eventParents != current.events.eventParents ||
		   (oldEvents.events[1U].present &&
			oldEvents.events[1U].security != current.events.events[1U].security) ||
		   placement->destination.existing->security.empty() ||
		   placement->destination.existing->sha256 != copy->sha256 ||
		   placement->destination.existing->bytes != copy->bytes) {
			return HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}
	}

	// 元INFが書く二つのイベントを両方確認し、省略した資源の扱いは別の保持判定へ残す
	for( std::size_t index = 0U; index < package.eventReferences.size(); ++index) {
		const auto &expected = package.eventReferences[index] ;		// 同じ元選択の型付き宣言
		const auto &event	 = registration.events.events[index] ;	// 同じ名前の現在値と保護
		// 元宣言があっても現在の登録または保護が未確認なら反映とは扱わない
		if( !expected || event.security.empty() ||
		   !matchesRegisteredStorageEvent( *expected, event, true)) {
			return HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}
	}

	// 署名付きの各電源定義と全既定値を実観測へ照合する
	for( std::size_t index = 0U; index < intended.powerSettings.size(); ++index) {
		const auto &expected = intended.powerSettings[index] ;	// 元宣言の定義と既定値
		const auto &observed = current.power.settings[index] ;	// 同じ枝の保護付き現在値
		// 別々の読取りで割り当てた文書IDに依存せず、同じ現在値を両方の元定義に照合する
		if( !matchesStoragePowerDefinition( expected, observed) ||
		   !matchesStoragePowerDefinition( package.powerSettings[index], observed)) {
			return HRESULT_FROM_WIN32( ERROR_RETRY) ;
		}
	}

	return bootApplied ? 0U : static_cast<NativeError>( S_FALSE) ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 同一の元文書に属する基本、機器、サービスの開始節を一回ずつ照合する
 * @param[in] seeds NativeLoaderが確定した元選択
 * @param[in] service 同じ元INFとSYSから読み取った選択節
 * @return 同じ元選択の三節だけならtrue
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasSelectedStorageSeeds( const std::span<const SystemInfSection> seeds,
										   const SelectedStorageServiceFacts	  &service)
{
	// 三節が成立しない選択や由来の欠けた読取りを先へ進めない
	if( seeds.size() != 3U || seeds.front().document == 0U) {
		return false ;
	}

	const auto		 document = seeds.front().document ;					// 三節に共通する署名文書
	const auto		 hardware = service.selectedInstallSection + L".HW" ;	// 同じ修飾を持つ機器節
	const std::array targets{
		std::pair{SystemInfContext::DEVICE, std::wstring_view{service.selectedInstallSection}},
		std::pair{SystemInfContext::HARDWARE, std::wstring_view{hardware}},
		std::pair{SystemInfContext::SERVICES, std::wstring_view{service.servicesSection}},
	} ; // 読取り中だけ借用する期待節と文脈
	// 期待節それぞれに別文書や別の作用先を持つ参照を混ぜない
	for( const auto &[context, name] : targets) {
		// 元節の空指定、欠落と順に依存しない重複を拒否する
		if( name.empty() || std::ranges::count_if( seeds, [&]( const auto &seed) {
							   return seed.document == document && seed.context == context &&
									  seed.scope == context && seed.owner.empty() &&
									  same( seed.name, name) ;
						   }) != 1) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元の割込みと関連サービスの局所レジストリだけを対象に選ぶ
 * @param[in] effect 所有文脈と元AddReg行の全フィールド
 * @param[in] deletion DelRegから到達したときtrue
 * @return 次の共通レジストリ型検査へ渡せる元作用ならtrue
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSingleBootLocalRegistry( const SystemInfEffect &effect, const bool deletion)
{
	const auto &fields = effect.row.values ;	// 原順と省略状態を保つ元フィールド
	// 削除、他のレジストリルート、省略された対象名は受理しない
	if( deletion || fields.size() < 3U || !same( fields[0], L"HKR")) {
		return false ;
	}

	const auto	 &subkey = fields[1] ;	// 機器か関連サービスへの相対位置
	const auto	 &value	 = fields[2] ;	// 第3欄は常に元の値名
	std::uint32_t flags{} ;				// 5欄の行が明示した元の型
	const bool	  dword =
		// 明示DWORDの行
		fields.size() == 5U && integer( fields[3], flags) && flags == 0x10001U ;
	// 関連サービスには元PnPインターフェイスとバス種別のDWORDを確認する
	if( effect.source.scope == SystemInfContext::SERVICE) {
		return dword && ((same( subkey, L"Parameters\\PnpInterface") && same( value, L"5")) ||
						 (same( subkey, L"Parameters") && same( value, L"BusType"))) ;
	}

	const bool message = same(
		subkey, L"Interrupt Management\\MessageSignaledInterruptProperties") ;	// 同じ機器のMSI設定
	const bool affinity =
		// 同じ機器の割込み先
		same( subkey, L"Interrupt Management\\Affinity Policy") ;
	// 元の3欄の値名を4欄のKEYONLYへ読み替えず、5欄の行は元DWORDの型を要求する
	return effect.source.scope == SystemInfContext::HARDWARE &&
		   ((fields.size() == 3U && same( value, L"0x00000010") &&
			 (message || affinity || same( subkey, L"Interrupt Management"))) ||
			(dword &&
			 ((message && (same( value, L"MSISupported") || same( value, L"MessageNumberLimit"))) ||
			  (affinity && (same( value, L"DevicePolicy") || same( value, L"DevicePriority") ||
							same( value, L"GroupPolicy")))))) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsが同じPnP機器に返したハードウェアキーハンドルの正規名を照合する
 * @param[in] key SetupAPIのDIREG_DEVで開いた読取り専用ハンドル
 * @param[in] instanceId 同じ情報集合の完全インスタンス識別
 * @param[in] controlSet 正式CurrentControlSetリンクが示す実制御セット
 * @return 同じ機器のDevice Parametersに一致して0、未確認または元読取り失敗はHRESULT
 * @note 正規名は取得したハンドルの検査だけに使い、キーを開く入力や診断には使わない
 */
//------------------------------------------------------------------------------
NativeError verifySingleBootHardwareKey( HKEY key, std::wstring_view instanceId,
										std::wstring_view controlSet)
{
	using QueryKey	   = LONG( NTAPI *)( HANDLE, ULONG, void *, ULONG, ULONG *) ;	// Native APIのABI
	const auto module  = GetModuleHandleW( L"ntdll.dll") ;							// Windowsがロード済みのシステムDLL
	const auto address = module ? GetProcAddress( module, "NtQueryKey") : nullptr ;	// 文書化済み入口
	// ハンドル名を照会できない場合は解決先が同じ機器と判断しない
	if( !address) {
		return HRESULT_FROM_WIN32( ERROR_PROC_NOT_FOUND) ;
	}

	const auto query = std::bit_cast<QueryKey>( address) ;	// Windows境界だけで元ABIと同じ型にする
	constexpr ULONG KEY_NAME_INFORMATION = 3U ;				// KEY_INFORMATION_CLASSの正規名照会
	struct {
		/// 終端を含まないWindows名のバイト数
		ULONG					   nameBytes ;
		/// 名を保持する有限UTF-16領域
		std::array<wchar_t, 1024U> name ;
	} value{} ; // KEY_NAME_INFORMATIONの応答領域
	constexpr ULONG PREFIX_BYTES = offsetof( decltype( value), name) ;	// 名の手前のバイト長
	ULONG			returned{} ;										// APIが実際に返した構造体のバイト数
	const auto		status =
		// ハンドル名の元NTSTATUS
		query( key, KEY_NAME_INFORMATION, &value, sizeof( value), &returned) ;
	// バッファーの再確保や部分名で対象を推定しない
	if( status != 0) {
		return HRESULT_FROM_NT( status) ;
	}

	// 応答のUTF-16長とヘッダーを確認してから保持領域を参照する
	if( returned < PREFIX_BYTES || returned > sizeof( value) || value.nameBytes == 0U ||
	   value.nameBytes != returned - PREFIX_BYTES || value.nameBytes % sizeof( wchar_t) != 0U) {
		return INVALID ;
	}

	std::wstring expected{L"\\REGISTRY\\MACHINE\\SYSTEM\\"} ;	// 比較専用の正規位置
	expected.append( controlSet)
		.append( L"\\Enum\\")
		.append( instanceId)
		.append( L"\\Device Parameters") ;
	return same( {value.name.data(), value.nameBytes / sizeof( wchar_t)}, expected)
			   ? 0U
			   : HRESULT_FROM_WIN32( ERROR_RETRY) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元選択の対象キーが持つ一つの型付き値を展開せず読み取る
 * @param[in] key 保護と位置の確認済みキー。正式な親の不在はnull
 * @param[in] name 同じ元作用が指定した値名
 * @param[in] expectedType 元作用から確定したREG_SZまたはREG_DWORD
 * @param[in,out] result 同じ元行に対応する作業値。失敗時は使用しない
 * @return 型と完全値または正式な不在の確認で0、相違や読取り失敗はHRESULT
 * @note 空の元値と正式な不在を別に保持し、設定を書き換えない
 */
//------------------------------------------------------------------------------
NativeError readSingleBootRegistryValue( HKEY key, const wchar_t *name, DWORD expectedType,
										StorageSingleBootRegistryValue &result)
{
	// 正式に不在のキーからは値を探索しない
	if( !key) {
		return 0U ;
	}

	DWORD	   type{} ;		// Windowsが返す元のレジストリ型
	DWORD	   required{} ;	// 元値の全バイト。終端の情報を含む
	const auto sized =
		// 同じ型と元サイズを保持する最初の応答
		RegQueryValueExW( key, name, nullptr, &type, nullptr, &required) ;
	// 既知キー内の値の正式不在だけを成功へ含める
	if( sized == ERROR_FILE_NOT_FOUND) {
		return 0U ;
	}

	// 比較できない型や長さを元値の不存在にしない
	if( sized != ERROR_SUCCESS || type != expectedType || required > 4096U ||
	   (type == REG_DWORD && required != sizeof( DWORD)) ||
	   (type == REG_SZ && required % sizeof( wchar_t) != 0U)) {
		return sized == ERROR_SUCCESS ? INVALID : HRESULT_FROM_WIN32( sized) ;
	}

	std::vector<std::byte> data( required) ;	// 生の値だけを保持する有限領域
	DWORD				   bytes = required ;	// 二度目の応答の全バイト数
	// Win32境界に生バイト領域を渡し、二度の照会で型と長さを照合する
	const auto			   read = RegQueryValueExW( key, name, nullptr, &type,
												   reinterpret_cast<BYTE *>( data.data()), &bytes) ;	// 元診断
	// 途中の削除や別型への変更を既知値に置き換えない
	if( read != ERROR_SUCCESS || type != expectedType || bytes != required) {
		return read == ERROR_SUCCESS ? INVALID : HRESULT_FROM_WIN32( read) ;
	}

	result.type	 = type ;
	result.bytes = std::move( data) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通の上限内で元PACKAGEの選択作用をすべて読み取って型と所有範囲を検査する
 * @param[in] seeds NativeLoaderが確定した元選択のPACKAGE節
 * @param[in] api 元INFの全行とWindows資源を読み取る操作
 * @param[in] service 選択された関連サービスと元SYSの非権限事実
 * @param[in,out] made 全作用と型付き原値を保持する作業結果
 * @param[out] stage 元値を含まない固定診断
 * @param[in,out] hdc HDCの必須作用の作業値。既存のストレージ検査ではnull
 * @param[in,out] automatic 自動起動補助を含む元作用の作業値。他の経路ではnull
 * @param[in,out] singleBoot 補助のないブートサービスの関連Systemイベント。他の経路ではnull
 * @return 全選択作用が検査できた場合は0、未対応の作用や読取不成立はHRESULT
 */
//------------------------------------------------------------------------------
NativeError inspectStorageInfGraph( std::span<const SystemInfSection>  seeds,
								   const SystemInfEffectApi			 &api,
								   const SelectedStorageServiceFacts &service,
								   StorageInfEffects &made, std::uint32_t &stage,
								   HdcInfGraphState		  *hdc,
								   AutoStartInfGraphState *automatic  = nullptr,
								   StorageEventGraphState *singleBoot = nullptr)
{
	// 元document/文脈/所有者/操作を併存させる有限参照queueです
	std::vector<PendingSection> queue ;
	// 全graphと追加作用で共有する元辺数です
	std::size_t					references = api.graphReferences ;
	const auto append = [&]( SystemInfSection section, bool deletion) -> NativeError {
		// 対象の元文書の作用を保つ経路では同じ原節の多重実行を拒否する
		if( (hdc || automatic || singleBoot) && std::ranges::any_of( queue, [&]( const auto &old) {
			   return old.section.document == section.document &&
					  same( old.section.name, section.name) ;
		   })) {
			return UNSUPPORTED ;
		}

		// 同document/文脈/所有者と操作だけを一度ずつ評価します
		if( std::ranges::any_of( queue, [&]( const auto &old) {
			   return old.section == section && old.deletion == deletion ;
		   })) {
			return 0U ;
		}

		// 元graphと一つの有限節/参照上限を共有します
		if( queue.size() >= 1024U || ++references > 4096U || section.document == 0U ||
		   section.name.empty() || section.name.size() > 255U) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		queue.push_back( {std::move( section), deletion}) ;
		return 0U ;
	} ;
	// 同NativeLoaderの確定PACKAGE seedだけを出発点にします
	for( const auto &seed : seeds) {
		// 下位検査の最初の診断を後続へ返す一時値です
		const auto error = append( seed, false) ;
		// 部分seed集合を全作用へ昇格しません
		if( error != 0U) {
			return error ;
		}
	}

	// 全作用とregistryが共有する累積行数です
	std::size_t			   rows{} ;
	// 全graphの関連service宣言数です
	std::size_t			   associated{} ;
	std::size_t			   auxiliaryDeclarations{} ;	// 元補助サービスの宣言数
	StorageEventGraphState auxiliaryEvent ;				// 補助サービス所有のSystemイベント
	// 元の補助サービスで使うイベント資源を同CATの関連SYSへ結ぶ
	if( service.auxiliary) {
		const auto slash = service.binaryTarget.rfind( L'\\') ;	// 関連SYSのファイル名境界
		// 実パスとWindows資源検証がない場合はイベント登録を受け入れない
		if( slash == service.binaryTarget.npos || !api.module) {
			return UNSUPPORTED ;
		}

		auxiliaryEvent.eventBinary =
			L"%SystemRoot%\\System32\\drivers" + service.binaryTarget.substr( slash) ;
		// 自動起動補助の経路で同じ資源を要求するのは関連サービスのイベントだけ
		if( automatic) {
			automatic->associatedEvent.eventBinary = auxiliaryEvent.eventBinary ;
		}
	}

	// 原参照の全行を上限内で型と所有先へ分類します
	for( std::size_t index = 0U; index < queue.size(); ++index) {
		// 同原順queueから取り出す文脈/所有者/操作です
		const auto	pending = queue[index] ;
		// 元補助サービスと同documentに属する参照だけをその所有文脈として扱う
		const auto *auxiliary = service.auxiliary &&
										pending.section.document == seeds.front().document &&
										same( pending.section.owner, service.auxiliary->name)
									? &*service.auxiliary
									: nullptr ;
		const bool	namedEvent =
			automatic && pending.section.document == seeds.front().document &&
			pending.section.scope == SystemInfContext::EVENT_LOG &&
			same( pending.section.owner,
				 automatic->auxiliaryEventName) ;	// 元6欄の独立したSystemイベント源
		// 同原文又はSDの全byteを取得する一時所有です
		std::vector<SystemInfRow> raw ;
		stage = 14002U ;
		// 下位検査の最初の診断を後続へ返す一時値です
		auto error = api.read( pending.section, raw) ;
		// 読取失敗を空節成功へ変換しません
		if( error != 0U || raw.size() > 4096U - rows) {
			return error != 0U
					   ? error
					   : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW)) ;
		}

		rows += raw.size() ;
		// 元の機器節から達する絶対行を含む節は、一組の共有設定として検査する
		const bool autoLogger =
			(hdc || (automatic && pending.section.scope == SystemInfContext::HARDWARE)) &&
			pending.section.context == SystemInfContext::REGISTRY &&
			std::ranges::any_of( raw, []( const auto &row) {
				return !row.values.empty() && same( row.values.front(), L"HKLM") ;
			}) ;
		// 混在したregistry節や二つ以上の共有セッションを許可しない
		if( autoLogger) {
			stage = 14014U ;
			// 共有の行上限と元のセッション数を満たした全行だけを検査する
			if( made.autoLogger || *api.registryRows > 4096U ||
			   raw.size() > 4096U - *api.registryRows) {
				return made.autoLogger ? UNSUPPORTED : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
			}

			error = inspectStorageAutoLogger( pending, raw, automatic != nullptr,
											 made.autoLogger.emplace()) ;
			// 未対応の共有作用を通常のストレージデータへ流さない
			if( error != 0U) {
				return error ;
			}
		}

		// HDCの関連サービスの全行を独立に読んだ元事実と照合する
		if( hdc && pending.section.context == SystemInfContext::SERVICE &&
		   (!std::ranges::equal( raw, service.directives,
								[]( const auto &row, const auto &original) {
									return row.ordinal == original.ordinal &&
										   row.key == original.key && row.values == original.fields ;
								}) ||
			!std::ranges::all_of( HDC_SERVICE_FIELDS, [&]( const auto key) {
				return std::ranges::count_if(
						   raw, [&]( const auto &row) { return same( row.key, key) ; }) == 1 ;
			}))) {
			stage = 14013U ;
			return INVALID ;
		}

		// 自動起動の関係ではAddRegの参照も独立に確認した元サービス行へ照合する
		if( (automatic || singleBoot) && pending.section.context == SystemInfContext::SERVICE) {
			const auto &expected =
				auxiliary ? auxiliary->directives : service.directives ;	// 一つの元サービス節の事実
			// 省略・順序・元節の一致がなければ参照元の所有を成立させない
			if( !same( pending.section.name,
					 auxiliary ? auxiliary->installSection : service.installSection) ||
			   !std::ranges::equal( raw, expected, []( const auto &row, const auto &original) {
				   return row.ordinal == original.ordinal && row.key == original.key &&
						  row.values == original.fields ;
			   })) {
				stage = 14006U ;
				return INVALID ;
			}
		}

		// 原ordinal/全fieldを一度ずつ保持します
		for( std::size_t ordinal = 0U; ordinal < raw.size(); ++ordinal) {
			// 同原節の一行を完全fieldで読むcursor又は所有値です
			const auto		&row = raw[ordinal] ;
			// 元rowの全fieldと元文脈を併存させるtupleです
			SystemInfEffect	 effect{pending.section, row} ;
			// 原操作を無作用へ置換せず保持する限定型です
			StorageInfAction action{StorageInfAction::DECLARATION} ;
			stage = 14003U ;
			// readerの全行/fieldが不完全な場合はnativeへ進めません
			if( row.ordinal != ordinal || row.values.size() > 64U) {
				return INVALID ;
			}

			// registry dataのHKRは原参照文脈を保持します
			if( pending.section.context == SystemInfContext::REGISTRY) {
				stage = 14004U ;
				// 旧registry BootFlagsをmodern directive又はWindows非互換へ読み替えません
				if( pending.section.scope == SystemInfContext::SERVICE && row.values.size() >= 3U &&
				   same( row.values[2], L"BootFlags") && row.values[1].empty()) {
					stage = 14009U ;
					return UNSUPPORTED ;
				}

				// registry全体の共同上限を別節の残量で回避しません
				if( *api.registryRows >= 4096U) {
					return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
				}

				++*api.registryRows ;
				// HDCのレジストリ行は正確な無名行だけを許可する
				if( (hdc || singleBoot) && !row.key.empty()) {
					return INVALID ;
				}

				// 共有設定とイベント値は一般のデバイス相対値と区別する
				if( autoLogger) {
					action = StorageInfAction::AUTOLOGGER_VALUE ;
				}
				// イベント資源は元リストと同じ順序で検査する
				else if( hdc && pending.section.scope == SystemInfContext::EVENT_LOG) {
					stage  = 14015U ;
					action = StorageInfAction::EVENT_RESOURCE ;
					error  = inspectStorageEventRow( effect, service.name, api, hdc->event) ;
				}
				// 単一サービスの関連イベントもWindows資源と同じCATのSYSだけを使う
				else if( singleBoot && pending.section.scope == SystemInfContext::EVENT_LOG) {
					stage  = 14015U ;
					action = StorageInfAction::EVENT_RESOURCE ;
					error  = pending.deletion
								 ? UNSUPPORTED
								 : inspectStorageEventRow( effect, service.name, api, *singleBoot) ;
				}
				// 自動起動補助のイベントでは明示名と関連サービスの既定名を分ける
				else if( automatic && pending.section.scope == SystemInfContext::EVENT_LOG) {
					stage  = 14019U ;
					action = StorageInfAction::EVENT_RESOURCE ;
					// 元登録は削除や名前付き行へ読み替えない
					if( pending.deletion || !row.key.empty()) {
						return UNSUPPORTED ;
					}

					error = namedEvent ? inspectNamedStorageEventRow( effect, api, *automatic)
									   : inspectStorageEventRow( effect, service.name, api,
																automatic->associatedEvent) ;
				}
				// 補助イベントは所有者、正確な二行、同SYS資源を個別に確認する
				else if( auxiliary && pending.section.scope == SystemInfContext::EVENT_LOG) {
					action = StorageInfAction::EVENT_RESOURCE ;
					error =
						row.key.empty() && !pending.deletion
							? inspectStorageEventRow( effect, auxiliary->name, api, auxiliaryEvent)
							: UNSUPPORTED ;
				} else {
					// 単一ブートサービスの局所作用は同機器と関連サービスの既知位置だけを読む
					if( singleBoot && !isSingleBootLocalRegistry( effect, pending.deletion)) {
						return UNSUPPORTED ;
					}

					// 共有ACPIとDMAは一般の相対レジストリ値より先に所有と型を確認する
					if( automatic) {
						stage = 14018U ;
						error = inspectAutoStartRegistry( effect, service.name, pending.deletion,
														 raw.size(), automatic->registrySections,
														 made.sharedAcpiStorageFeatures, action) ;
						// 専用の作用や型・所有の不一致を一般値の検査へ渡さない
						if( error != 0U || action != StorageInfAction::DECLARATION) {
							// 型付き作用と元行の組を他の元作用と同じ順番で保持する
							if( error != 0U) {
								return error ;
							}

							made.effects.push_back( {std::move( effect), action}) ;
							continue ;
						}
					}

					error = registry( effect, pending.deletion, service, api, action,
									 made.sharedDiskTimeout, made.mtdDeviceType,
									 made.mtdDeviceCharacteristics) ;
				}
			}
			// 補助サービスの設定行を同じ元節の全欄に照合する
			else if( auxiliary && pending.section.context == SystemInfContext::SERVICE) {
				stage = 14006U ;
				// 元service節で読み取った同一位置の宣言です
				const auto original = std::ranges::find( auxiliary->directives, row.ordinal,
														&StorageServiceDirective::ordinal) ;
				// 他の設定節や元宣言と一致しない行を受け入れない
				if( original == auxiliary->directives.end() || original->key != row.key ||
				   original->fields != row.values ||
				   !same( pending.section.name, auxiliary->installSection)) {
					return INVALID ;
				}

				// この要求時起動の補助サービスが使用する限定スカラーです
				constexpr std::array allowed{L"ServiceType",   L"StartType",   L"ErrorControl",
											 L"ServiceBinary", L"DisplayName", L"Description",
											 L"Security"} ;
				// 任意のアカウント、登録、トリガー、開始動作を追加できないようにする
				if( row.values.size() != 1U ||
				   std::ranges::none_of( allowed, [&]( auto key) { return same( row.key, key) ; })) {
					return UNSUPPORTED ;
				}

				// 保護記述子の型と元権限の不一致は、文字列の存在だけで成立にしない
				if( same( row.key, L"Security")) {
					error = row.values.front() == auxiliary->security
								? inspectAuxiliaryServiceSecurity( auxiliary->security)
								: INVALID ;
				}
			}
			// 補助Systemイベントは一つのAddReg参照だけを持つ
			else if( (auxiliary || automatic || singleBoot) &&
					pending.section.context == SystemInfContext::EVENT_LOG &&
					(!same( row.key, L"AddReg") || row.ordinal != 0U || row.values.size() != 1U)) {
				return UNSUPPORTED ;
			}
			// 同じPACKAGEのHDCでは入れ子参照や新たなディレクティブへ拡張しない
			else if( hdc && !inspectHdcDirective( pending.section, row, *hdc, made.featureScore)) {
				stage = 14013U ;
				return UNSUPPORTED ;
			}
			// 元順位は基本節のコピーやレジストリ登録と区別する
			else if( hdc && same( row.key, L"FeatureScore")) {
				action = StorageInfAction::FEATURE_SCORE ;
			}
			// 選択されたSCSI基本節の元順位を後段の再照合へ保持する
			else if( same( row.key, L"FeatureScore")) {
				// 同じ元基本節の一回の順位宣言だけを保持する
				if( pending.section.context != SystemInfContext::DEVICE ||
				   pending.section.document != seeds.front().document ||
				   !same( pending.section.name, service.selectedInstallSection) ||
				   !same( service.className, L"SCSIAdapter") || made.featureScore ||
				   row.values.size() != 1U || !same( row.values.front(), L"0x80")) {
					return UNSUPPORTED ;
				}

				made.featureScore = 0x80U ;
				action			  = StorageInfAction::FEATURE_SCORE ;
			}
			// 電源設定は署名付き元基本節の範囲設定に限って一組として保持する
			else if( (automatic || singleBoot) && same( row.key, L"AddPowerSetting")) {
				stage = static_cast<std::uint32_t>( SystemInfDiagnosticStage::POWER_SETTING) ;
				// 機器節や別元の作用を選択基本節の設定へ昇格させない
				if( pending.section.context != SystemInfContext::DEVICE ||
				   pending.section.document != seeds.front().document ||
				   !same( pending.section.name, service.selectedInstallSection) ||
				   row.values.empty()) {
					return UNSUPPORTED ;
				}

				action = StorageInfAction::POWER_SETTINGS ;
			}
			// 元AddReg/DelRegの全参照を操作別に保持します
			else if( same( row.key, L"AddReg") || same( row.key, L"DelReg")) {
				// 自動起動補助の元レジストリは関連サービス・機器・イベントだけから参照する
				if( (automatic || singleBoot) &&
				   (same( row.key, L"DelReg") ||
					(pending.section.context != SystemInfContext::SERVICE &&
					 pending.section.context != SystemInfContext::HARDWARE &&
					 pending.section.context != SystemInfContext::EVENT_LOG))) {
					return UNSUPPORTED ;
				}

				// 元参照の全fieldからだけregistry節を追加します
				if( row.values.empty()) {
					return INVALID ;
				}

				// 原順の全参照節を親の所有文脈でqueueへ追加します
				for( const auto &name : row.values) {
					// 元参照の所有文脈を継承した次の節です
					SystemInfSection target{pending.section.document, name,
											SystemInfContext::REGISTRY, pending.section.context,
											pending.section.owner} ;
					error = append( std::move( target), same( row.key, L"DelReg")) ;
					// 一参照の欠損を後続の正常節で救済しません
					if( error != 0U) {
						return error ;
					}
				}
			}
			// 元Include/Needsは同NativeLoaderの全graph検査を正本にします
			else if( same( row.key, L"Include") || same( row.key, L"Needs")) {
				// 参照自体は同NativeLoaderの全graph/CAT/Store/全作用検査が正本です
				error = row.values.empty() || automatic || singleBoot ? INVALID : 0U ;
			}
			// 関連serviceの元宣言は全graphで一つだけとします
			else if( pending.section.context == SystemInfContext::SERVICES &&
					same( row.key, L"AddService")) {
				stage = 14005U ;
				// HDCはWindowsの節名照合を用い、読み取った節名自体は原作用に保持する
				const bool sameSection = hdc || service.auxiliary
											 ? same( pending.section.name, service.servicesSection)
											 : pending.section.name == service.servicesSection ;
				// 同じ元節と行の補助サービス宣言だけを関連サービスから区別する
				const bool helper = service.auxiliary &&
									row.ordinal == service.auxiliary->addServiceOrdinal &&
									row.values == service.auxiliary->addServiceFields &&
									pending.section.document == seeds.front().document ;
				// 全graphで元の一行ずつだけを認める
				if( !sameSection ||
				   (helper ? ++auxiliaryDeclarations != 1U
						   : (++associated != 1U || row.values != service.addServiceFields ||
							  row.ordinal != service.addServiceOrdinal))) {
					return UNSUPPORTED ;
				}

				const auto &owner =
					helper ? service.auxiliary->name : service.name ;	// 元の作用所有者
				const auto &install = helper ? service.auxiliary->installSection
											 : service.installSection ;	// 元の設定節
				error = append( {pending.section.document, install, SystemInfContext::SERVICE,
								SystemInfContext::SERVICE, owner},
							   false) ;
				// 原4fieldのevent-logを別service所有へ移しません
				if( error == 0U && row.values.size() == 4U && !row.values[3].empty()) {
					error =
						append( {pending.section.document, row.values[3],
								SystemInfContext::EVENT_LOG, SystemInfContext::EVENT_LOG, owner},
							   false) ;
				}
				// 六欄のイベントは構成の所有者を流用せず、元宣言の明示した源を使う
				else if( error == 0U && automatic && helper && row.values.size() == 6U) {
					error = append( {pending.section.document, row.values[3],
									SystemInfContext::EVENT_LOG, SystemInfContext::EVENT_LOG,
									std::wstring{automatic->auxiliaryEventName}},
								   false) ;
				}
			}
			// service-installの全行を元factsと一対一に照合します
			else if( pending.section.context == SystemInfContext::SERVICE) {
				stage = 14006U ;
				// 元資格又は元原文から保持した比較値です
				const auto original = std::ranges::find( service.directives, row.ordinal,
														&StorageServiceDirective::ordinal) ;
				// 元factsとの全field一致と限定directiveを同時に要求します
				if( original == service.directives.end() || original->key != row.key ||
				   original->fields != row.values || pending.section.owner != service.name) {
					return INVALID ;
				}

				// 元service-installで評価済みの有限directive集合です
				constexpr std::array allowed{L"ServiceType",   L"StartType",	  L"ErrorControl",
											 L"ServiceBinary", L"LoadOrderGroup", L"Dependencies",
											 L"BootFlags",	   L"DisplayName",	  L"Description"} ;
				// 未知service作用又は不正表示値を原設定から除外しません
				if( std::ranges::none_of( allowed, [&]( auto key) { return same( row.key, key) ; }) ||
				   ((same( row.key, L"DisplayName") || same( row.key, L"Description")) &&
					(row.values.size() != 1U || row.values.front().size() > 4096U ||
					 row.values.front().find( L'%') != std::wstring::npos ||
					 std::ranges::any_of( row.values.front(),
										 []( wchar_t c) { return c < L' ' || c == 0x7f ; })))) {
					return UNSUPPORTED ;
				}
			}
			// deviceのcopy/import宣言は同原閉包の別検査へ結びます
			else if( pending.section.context == SystemInfContext::DEVICE &&
					(same( row.key, L"CopyFiles") || same( row.key, L"CopyINF"))) {
				// コピー元/全CATと全import分類は別の同原計画で必須です
				error = row.values.empty() ? INVALID : 0U ;
			} else {
				// 未知directiveをdata又はSYSTEM許可へ変換しません
				return UNSUPPORTED ;
			}

			// 後続の成功で原失敗を消しません
			if( error != 0U) {
				return error ;
			}

			made.effects.push_back( {std::move( effect), action}) ;
		}
	}

	stage = 14007U ;
	// 空Servicesを有効なminiportにしません
	if( associated != 1U) {
		return UNSUPPORTED ;
	}

	// 認めた補助サービスの宣言とSystemイベント登録が同じgraphに揃うことを要求する
	if( service.auxiliary &&
	   (auxiliaryDeclarations != 1U ||
		(!automatic && (!auxiliaryEvent.resourcesFound || !auxiliaryEvent.typesFound)))) {
		return UNSUPPORTED ;
	}

	// 片方だけのイベント登録を完全な作用として返さない
	if( singleBoot && (!singleBoot->resourcesFound || !singleBoot->typesFound)) {
		stage = 14015U ;
		return UNSUPPORTED ;
	}

	// 元の共有作用は一方だけ存在する状態を完全な選択として渡さない
	if( automatic) {
		const auto &sections =
			automatic->registrySections ;	// 自サービス／ACPI、機器DMA2行、サービスDMAの順
		// 既存の二つの作用に加え、DMAは全行成立または原文で一切省略の場合に限る
		if( sections[0].empty() || sections[0] != sections[1] || sections[2] != sections[3] ||
		   sections[2].empty() != sections[4].empty() || !made.autoLogger || !made.featureScore ||
		   made.powerSettings.empty()) {
			stage = 14018U ;
			return UNSUPPORTED ;
		}

		// 関連サービスの資源、補助イベントのDWORDと候補側資源の対を独立に要求する
		if( !automatic->associatedEvent.typesFound || !automatic->associatedEvent.resourcesFound ||
		   !automatic->namedTypesFound || !automatic->namedCategoryFound ||
		   automatic->namedMessageFound != (automatic->eventMessageCopy != nullptr)) {
			stage = 14019U ;
			return UNSUPPORTED ;
		}
	}

	return 0U ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 元PACKAGEの全選択作用を原文脈/所有scope/有限型へ検査します
 * @param[in] seeds 同NativeLoaderのPACKAGE到達節です
 * @param[in] api 同原byte readerとWindows helper検証です
 * @param[in] service 同原選択と一意SYSコピーのfactsです
 * @param[in] readService 同完全backendのexact service読取です
 * @param[in] osBuild 現在の実OS buildです
 * @param[out] result 全成立時だけ原結果です。失敗時空です
 * @param[out] stage 最初の固定拒否数値です
 * @return 全成立0、それ以外は元HRESULTです
 * @note PACKAGE由来、BOOT/SYSTEM原値と全fieldを保持し、OSを変更しません
 */
//------------------------------------------------------------------------------
NativeError inspectStorageInfEffects( std::span<const SystemInfSection>	seeds,
									 const SystemInfEffectApi		   &api,
									 const SelectedStorageServiceFacts &service,
									 const StorageServiceReadFunction  &readService,
									 std::uint32_t osBuild, StorageInfEffects &result,
									 std::uint32_t &stage)
{
	result = {} ;
	stage  = 14001U ;
	// 同原選択から固定した正式対だけでservice型を選びます
	const bool mtd = same( service.className, L"MTD") &&
					 same( service.classGuid, L"{4d36e970-e325-11ce-bfc1-08002be10318}") ;
	// 旧SCSIの正式対とMTDの正式対を混同しません
	const bool scsi = same( service.className, L"SCSIAdapter") &&
					  same( service.classGuid, L"{4d36e97b-e325-11ce-bfc1-08002be10318}") ;
	// 正式メディアチェンジャーの一意なクラス対
	const bool changer = same( service.className, L"MediumChanger") &&
						 same( service.classGuid, L"{ce5939ae-ebde-11d0-b181-0000f8753ec4}") ;
	// 原service型/開始/error/groupを閉構成へ限定します。BOOTをDEMANDへ変えません
	if( (!mtd && !scsi && !changer) || seeds.empty() || !api.read || !api.registryRows ||
	   !readService || service.flags != 2U || service.type != 1U || service.errorControl > 3U ||
	   (service.start != 0U && service.start != 1U && service.start != 3U) ||
	   service.name.empty() || service.name.size() > 256U || !relative( service.name) ||
	   service.name.find( L'\\') != service.name.npos ||
	   (mtd && (service.start != 3U || service.bootFlags ||
				(service.group && !same( *service.group, L"SD / MMC")))) ||
	   (scsi && (service.start == 0U || service.start == 1U) &&
		(!service.group || !same( *service.group, L"SCSI Miniport"))) ||
	   (scsi && service.group && !same( *service.group, L"SCSI Miniport")) ||
	   (changer && (service.start != SERVICE_SYSTEM_START || service.errorControl != 1U ||
					service.bootFlags || !service.group || !same( *service.group, L"SCSI Class") ||
					!service.dependencies || service.dependencies->size() != 1U ||
					!same( service.dependencies->front(), L"+SCSI Miniport"))) ||
	   (service.bootFlags && (osBuild < 25398U || (*service.bootFlags & ~0xffU) != 0U))) {
		return UNSUPPORTED ;
	}

	// 端末で評価する補助サービスを元のSystem32配置と要求時起動に限定する
	if( service.auxiliary &&
	   (!scsi || service.start != SERVICE_BOOT_START ||
		service.auxiliary->type != SERVICE_WIN32_OWN_PROCESS ||
		service.auxiliary->start != SERVICE_DEMAND_START || service.auxiliary->copy.dirid != 11 ||
		service.auxiliary->errorControl != SERVICE_ERROR_NORMAL ||
		service.auxiliary->addServiceFields.size() != 4U ||
		same( service.auxiliary->name, service.name))) {
		return UNSUPPORTED ;
	}

	// 全条件が成立するまで公開しない構築中の元値
	StorageInfEffects made ;
	made.service = service ;
	// 共通の原作用検査結果を現サービスの読み取り前に確定する
	const auto graphError = inspectStorageInfGraph( seeds, api, service, made, stage, nullptr) ;
	// 元PACKAGEの失敗後に現サービスを照会しない
	if( graphError != 0U) {
		return graphError ;
	}

	const auto observe = [&]( std::wstring_view name, bool required) -> NativeError {
		// 重複依存の原順はfactsへ保持し、同service観測だけを共有します
		if( std::ranges::any_of( made.services,
							   [&]( const auto &old) { return same( old.name, name) ; })) {
			return 0U ;
		}

		// associatedを含む全必要serviceで一つの32件上限を守ります
		if( made.services.size() >= 32U) {
			return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
		}

		// 当該exact serviceの明示不存在又は全現configです
		StorageServiceSnapshot snapshot ;
		snapshot.name = name ;
		// 当該exact serviceから読み取る原configと完全SDです
		SystemServiceEvidence evidence ;
		// 下位検査の最初の診断を後続へ返す一時値です
		auto				  error = readService( name, evidence) ;
		// associatedの明示不存在は新service用の正当な観測です
		if( error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SERVICE_DOES_NOT_EXIST)) &&
		   !required) {
			made.services.push_back( std::move( snapshot)) ;
			return 0U ;
		}

		// 依存不存在、欠損callback、未知config/権限を補完しません
		if( error != 0U || !same( evidence.name, name) ||
		   validateStorageServiceEvidence( evidence) != 0U) {
			return error != 0U ? error : UNSUPPORTED ;
		}

		// 外部依存は名前/配置/SDだけで受理せず、元Windows kernelの実trustへ結びます
		if( required) {
			// Windows実体検証がない依存を名前/SDだけで充足しません
			if( !api.module) {
				return UNSUPPORTED ;
			}

			error = api.module( seeds.front().document, evidence.binary) ;
			// 依存binaryの実trust失敗をassociated serviceの成功で救済しません
			if( error != 0U) {
				return error ;
			}
		}

		snapshot.evidence = std::move( evidence) ;
		made.services.push_back( std::move( snapshot)) ;
		return 0U ;
	} ;
	// 下位検査の最初の診断を後続へ返す一時値です
	auto error = observe( service.name, false) ;
	// 元associated観測の失敗を依存の成功で消しません
	if( error != 0U) {
		return error ;
	}

	// 明示空と不在をfactsへ保ったまま、全依存を原順で確認します
	if( service.dependencies && !changer) {
		// 明示依存を元順で全件確認し、先頭依存だけを採用しません
		for( const auto &dependency : *service.dependencies) {
			// 明示空の一fieldだけを依存なしとして扱います
			if( dependency.empty() && service.dependencies->size() == 1U) {
				continue ;
			}

			stage = 14008U ;
			// 未観測のgroup/外部依存を名前から充足しません
			if( dependency.empty() || dependency.size() > 256U || !relative( dependency) ||
			   dependency.starts_with( L"+") || dependency.find( L'\\') != dependency.npos ||
			   same( dependency, service.name)) {
				return UNSUPPORTED ;
			}

			error = observe( dependency, true) ;
			// 一依存の未資格状態を後続成功で上書きしません
			if( error != 0U) {
				return error ;
			}
		}
	}

	stage  = 0U ;
	result = std::move( made) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元HDCのカーネルブートサービス、順位、イベント、共有AutoLoggerの閉じた作用を検査する
 * @param[in] seeds 一つの署名検証済みPACKAGEの基本節、HW節、Services節
 * @param[in] api 同INFの全フィールド読取とWindows保護イベント資源の検証
 * @param[in] service 同選択と単一の署名済みSYSコピーに結合した元事実
 * @param[in] osBuild 同じNativeLoaderが観測したWindowsのビルド番号
 * @param[out] result 完全に検査した元行と型付き結果。失敗時は空
 * @param[out] stage 元値を含まない固定診断。成功時は0
 * @return 全作用成立時は0、未対応の作用や読取不成立はHRESULT
 * @note 現端末のサービス、起動順、AutoLoggerの読み取りや導入資格の発行には接続しない
 */
//------------------------------------------------------------------------------
NativeError inspectHdcInfContentEffects( std::span<const SystemInfSection>  seeds,
										const SystemInfEffectApi		  &api,
										const SelectedStorageServiceFacts &service,
										std::uint32_t osBuild, StorageInfEffects &result,
										std::uint32_t &stage)
{
	result				 = {} ;
	stage				 = 14012U ;
	const bool legacyIde = service.group &&
						   // 起動グループに基づく元の構成
						   same( *service.group, L"System Bus Extender") ;
	// 正式HDCクラスのBOOTカーネルサービス一つと元宣言を検査する
	if( !same( service.className, L"HDC") ||
	   !same( service.classGuid, L"{4d36e96a-e325-11ce-bfc1-08002be10318}") || osBuild == 0U ||
	   seeds.size() != (legacyIde ? 2U : 3U) || !api.read || !api.registryRows ||
	   (!legacyIde && (!api.module || !service.group || !same( *service.group, L"SCSI Miniport"))) ||
	   service.name.empty() || service.name.size() > 256U || !relative( service.name) ||
	   service.name.find( L'\\') != service.name.npos || service.flags != 2U ||
	   service.type != SERVICE_KERNEL_DRIVER || service.start != SERVICE_BOOT_START ||
	   service.errorControl != SERVICE_ERROR_NORMAL || service.dependencies || service.bootFlags ||
	   service.selectedInstallSection.empty() ||
	   service.addServiceFields.size() != (legacyIde ? 3U : 4U) ||
	   service.addServiceFields[0] != service.name || service.installSection.empty() ||
	   service.addServiceFields[2] != service.installSection ||
	   (!legacyIde && service.addServiceFields[3].empty())) {
		return UNSUPPORTED ;
	}

	// 同じパッケージの基本節と二つの正確な付随節だけを調べる
	const std::array sections{
		std::pair{SystemInfContext::DEVICE, service.selectedInstallSection},
		std::pair{SystemInfContext::HARDWARE, service.selectedInstallSection + L".HW"},
		std::pair{SystemInfContext::SERVICES, service.selectedInstallSection + L".Services"}} ;
	const auto document = seeds.front().document ;	// すべての作用に共通するPACKAGE文書ID
	// 参照や重複で不足している元節を補わない
	if( document == 0U || !same( service.servicesSection, sections.back().second) ||
	   !std::ranges::all_of( sections, [&]( const auto &section) {
		   return std::ranges::count_if( seeds, [&]( const auto &seed) {
					  return seed.document == document && seed.context == section.first &&
							 seed.scope == seed.context && seed.owner.empty() &&
							 same( seed.name, section.second) ;
				  }) == (legacyIde && section.first == SystemInfContext::HARDWARE ? 0 : 1) ;
	   })) {
		return UNSUPPORTED ;
	}

	const auto separator  = service.binarySource.find_last_of( L'\\') ;	// 元コピーの末尾名との境界
	const auto binaryName = std::wstring_view{service.binarySource}.substr(
		// 同CATのSYSの元末尾名
		separator == service.binarySource.npos ? 0U : separator + 1U) ;
	const auto targetTail = L"\\System32\\drivers\\" + std::wstring{binaryName} ;	// 同SYSの宛先末尾
	// 直接コピーとイベントリソースを同じ変更されていないシステムドライバーに限定する
	if( binaryName.size() < 5U || !relative( binaryName) ||
	   !same( binaryName.substr( binaryName.size() - 4U), L".sys") ||
	   !same( service.binary, service.binaryTarget) ||
	   service.binaryTarget.size() <= targetTail.size() ||
	   !same( std::wstring_view{service.binaryTarget}.substr( service.binaryTarget.size() -
															targetTail.size()),
			 targetTail)) {
		return UNSUPPORTED ;
	}

	HdcInfGraphState hdc ;	// 元のコピーとイベントリソースが指す同SYSと必須作用の観測
	hdc.directCopy		  = L"@" + std::wstring{binaryName} ;
	hdc.event.eventBinary = L"%SystemRoot%" + targetTail ;
	hdc.legacyIde		  = legacyIde ;
	StorageInfEffects made ;	// 全作用が成立するまで公開しない非権限の元結果
	made.service = service ;
	const auto error =
		// 最初の元診断
		inspectStorageInfGraph( seeds, api, service, made, stage, &hdc) ;
	// 不成立の作用を後続の検査結果で上書きしない
	if( error != 0U) {
		return error ;
	}

	// 必須の作用が実際に原グラフに全部存在した場合だけ結果を返す
	if( !hdc.copyFound || (!legacyIde && (!hdc.event.resourcesFound || !hdc.event.typesFound ||
										 !made.featureScore || !made.autoLogger))) {
		stage = 14016U ;
		return UNSUPPORTED ;
	}

	stage  = 0U ;
	result = std::move( made) ;
	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 自動起動補助サービスを含む一つの署名付きストレージ選択の元作用を検査する
 * @param[in] seeds 元の署名付き基本節・機器節・Services節の完全な集合
 * @param[in] api 署名文書の全行とWindowsのイベント資源を読み取る操作
 * @param[in] service 元選択と閉包に結び付いたサービス事実
 * @param[out] result 全作用が成立した場合だけ返す型付きの元事実。失敗時は空
 * @param[out] stage 失敗時に示す固定診断番号。成功時は0
 * @return 元作用が成立すれば0、それ以外はHRESULT
 * @note 端末のサービスや共有設定を変更せず、選択の導入資格も発行しない
 */
//------------------------------------------------------------------------------
NativeError inspectAutoStartStorageInfContentEffects( std::span<const SystemInfSection>	seeds,
													 const SystemInfEffectApi		   &api,
													 const SelectedStorageServiceFacts &service,
													 StorageInfEffects				   &result,
													 std::uint32_t					   &stage)
{
	result				  = {} ;
	stage				  = 14001U ;
	const auto &auxiliary = service.auxiliary ;	// 元選択と同じ署名済みEXEを使うサービス
	// 一つのSCSI選択、関連ブートサービスと自動起動の補助サービスの組だけを扱う
	if( !api.read || !api.registryRows || !api.module || seeds.size() != 3U ||
	   !same( service.className, L"SCSIAdapter") ||
	   !same( service.classGuid, L"{4d36e97b-e325-11ce-bfc1-08002be10318}") || service.flags != 2U ||
	   service.type != SERVICE_KERNEL_DRIVER || service.start != SERVICE_BOOT_START ||
	   service.name.empty() || same( service.name, L"ACPI") || !service.group ||
	   !same( *service.group, L"SCSI Miniport") || service.bootFlags || service.dependencies ||
	   service.addServiceFields.size() != 4U || !auxiliary ||
	   auxiliary->start != SERVICE_AUTO_START || auxiliary->copy.dirid != 13 ||
	   auxiliary->type != SERVICE_WIN32_OWN_PROCESS ||
	   auxiliary->errorControl != SERVICE_ERROR_NORMAL || auxiliary->name.empty() ||
	   same( service.name, auxiliary->name) || !auxiliary->security.empty() ||
	   auxiliary->addServiceFields.size() != 6U ||
	   !same( auxiliary->addServiceFields[4], L"System")) {
		return UNSUPPORTED ;
	}

	AutoStartInfGraphState automatic ;	// 名前付きイベントと共有作用の元行を照合する状態
	automatic.auxiliaryEventName = auxiliary->addServiceFields[5] ;
	automatic.eventMessageCopy =
		auxiliary->eventMessageCopy ? &*auxiliary->eventMessageCopy : nullptr ;
	// 構成名とは別のイベント源を一意のSystemキーへ結ぶ
	if( automatic.auxiliaryEventName.empty() || automatic.auxiliaryEventName.size() > 256U ||
	   !relative( automatic.auxiliaryEventName) ||
	   automatic.auxiliaryEventName.find( L'\\') != std::wstring_view::npos ||
	   same( automatic.auxiliaryEventName, service.name)) {
		return UNSUPPORTED ;
	}

	// 署名文書の他節や別文書から設定を借用しない
	if( !hasSelectedStorageSeeds( seeds, service)) {
		return UNSUPPORTED ;
	}

	StorageInfEffects made ;	// すべての原作用を確認するまで呼出元に返さない
	made.service = service ;
	const SystemInfSection selected{seeds.front().document,
									service.selectedInstallSection,
									SystemInfContext::DEVICE,
									SystemInfContext::DEVICE,
									{}} ;	// 同じ署名文書のDDInstall
	stage	   = static_cast<std::uint32_t>( SystemInfDiagnosticStage::POWER_SETTING) ;
	auto error = readSelectedRangedStoragePowerSettings( selected, api,
														made.powerSettings) ;	// 既存の元電源検査
	// 電源設定の原参照が不成立なら残りの作用へ進まない
	if( error != 0U) {
		return error ;
	}

	error = inspectStorageInfGraph( seeds, api, service, made, stage, nullptr, &automatic) ;
	// 設定の一部のみ成立した結果を端末側の検査に渡さない
	if( error != 0U) {
		return error ;
	}

	result = std::move( made) ;
	stage  = 0U ;
	return 0U ;
}
//------------------------------------------------------------------------------
/**
 * @brief 単一ブートサービスの元電源、局所レジストリ、イベントを同じ署名付き選択で照合する
 * @param[in] seeds 同じ元INFの基本節、機器節、サービス節
 * @param[in] api 元INFの行とWindowsイベント資源を読み取る操作
 * @param[in] service 同じ選択とAMD64の元SYSに結び付いたサービスの事実
 * @param[out] result 全作用を確認できた場合だけ返す元事実。失敗時は空
 * @param[out] stage 最初の失敗の固定診断。成功時は0
 * @return 成功0、元の宣言、参照、形式、資源が不成立の場合はHRESULT
 * @note 元作用だけを検査し、現在の電源の所有、端末の適用性、導入資格は呼出側で別に検査する
 */
//------------------------------------------------------------------------------
NativeError inspectSingleBootStorageInfContentEffects( std::span<const SystemInfSection>	 seeds,
													  const SystemInfEffectApi			&api,
													  const SelectedStorageServiceFacts &service,
													  StorageInfEffects					&result,
													  std::uint32_t						&stage)
{
	result = {} ;
	stage  = 14001U ;
	// 関連ブートサービスの同じ元SYSとイベントだけを扱い、補助や別の起動形を流用しない
	if( !api.read || !api.registryRows || !api.module || !same( service.className, L"SCSIAdapter") ||
	   !same( service.classGuid, L"{4d36e97b-e325-11ce-bfc1-08002be10318}") || service.auxiliary ||
	   service.flags != 2U || service.type != SERVICE_KERNEL_DRIVER ||
	   service.start != SERVICE_BOOT_START || service.errorControl != SERVICE_ERROR_NORMAL ||
	   service.name.empty() || service.name.size() > 256U || !relative( service.name) ||
	   service.name.find( L'\\') != service.name.npos || same( service.name, L"ACPI") ||
	   !service.group || !same( *service.group, L"SCSI Miniport") || service.bootFlags ||
	   service.dependencies || service.addServiceFields.size() != 4U ||
	   !hasSelectedStorageSeeds( seeds, service)) {
		return UNSUPPORTED ;
	}

	const auto slash = service.binaryTarget.rfind( L'\\') ;	// 同CATに属する元SYSの配置名境界
	// 保護されたSYSの配置を元イベントで参照するファイル名へ結ぶ
	if( slash == service.binaryTarget.npos || slash + 1U == service.binaryTarget.size()) {
		return UNSUPPORTED ;
	}

	StorageEventGraphState event ;	// 関連サービスの元Systemイベントを照合する作業値
	event.eventBinary = L"%SystemRoot%\\System32\\drivers" + service.binaryTarget.substr( slash) ;
	StorageInfEffects made ;	// 全原作用が成立するまで保持する内容用の事実
	made.service = service ;
	const SystemInfSection selected{seeds.front().document,
									service.selectedInstallSection,
									SystemInfContext::DEVICE,
									SystemInfContext::DEVICE,
									{}} ;	// 同じ元基本節の電源作用
	stage = static_cast<std::uint32_t>( SystemInfDiagnosticStage::POWER_SETTING) ;
	const auto power =
		// 元電源設定
		readSelectedRangedStoragePowerSettings( selected, api, made.powerSettings) ;
	// 電源定義を読めない宣言を局所作用の成功で救済しない
	if( power != 0U || made.powerSettings.empty()) {
		return power != 0U ? power : UNSUPPORTED ;
	}

	const auto effects = inspectStorageInfGraph( seeds, api, service, made, stage, nullptr, nullptr,
												&event) ;	// 同じ元署名文書の全作用
	// 一部の追加だけを検査済みとして渡さない
	if( effects != 0U) {
		return effects ;
	}

	// 元グラフが一意と確認した展開前のイベント資源値を、同じ選択に保持する
	const auto resource = std::ranges::find_if( made.effects, []( const auto &effect) {
		return effect.action == StorageInfAction::EVENT_RESOURCE &&
			   same( effect.original.row.values[2U], L"EventMessageFile") ;
	}) ;
	// 元作用にない資源を配置先の名前から構成しない
	if( resource == made.effects.end()) {
		stage = 14015U ;
		return UNSUPPORTED ;
	}

	auto &eventReference = made.singleBootEvent.emplace() ;	// 検証した同じ元値だけを保持する
	eventReference.name	 = service.name ;
	eventReference.installSection = service.addServiceFields[3U] ;
	eventReference.messageFile	  = resource->original.row.values[4U] ;
	eventReference.typesSupported = 7U ;
	// 同じ元選択から得た関連サービスのDWORDだけを元登録との比較用に保持する
	for( const auto &effect : made.effects) {
		const auto &entry = effect.original ;	// 同じ元グラフの行と所有者
		// 機器局所値やイベントをサービス局所値へ含めない
		if( effect.action != StorageInfAction::REGISTRY_VALUE ||
		   entry.source.scope != SystemInfContext::SERVICE) {
			continue ;
		}

		const auto	 &fields = entry.row.values ;	// 型付き検査済みの元欄
		std::uint32_t value{} ;						// 元の数値をDWORDのまま保持する
		// 同じ名前へ複数行が作用する候補や値の欠落を順序で解消しない
		if( !integer( fields[4U], value) ||
		   std::ranges::any_of( made.singleBootRegistryValues, [&]( const auto &old) {
			   return same( old.subkey, fields[1U]) && same( old.name, fields[2U]) ;
		   })) {
			stage = 14004U ;
			return INVALID ;
		}

		made.singleBootRegistryValues.push_back( {fields[1U], fields[2U], value}) ;
	}

	result = std::move( made) ;
	stage  = 0U ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名付きの同一選択が変更する機器と関連サービスのレジストリ値を読む
 * @param[in] devices 同じ選択機器を開いたWindows情報集合
 * @param[in,out] device その集合に属する機器情報。SetupAPIへ同期で借用する
 * @param[in] instanceId 同じ機器の確認済み完全識別。外部へ出さない
 * @param[in] effects 同じINF選択の起動サービスと検査済み作用
 * @param[out] snapshot 位置、保護、元型と値。失敗時は空
 * @return 全位置で正式不在または安定した元値が得られれば0、失敗はHRESULT
 * @note 読取り専用。元機器の登録再照合、サービスの所有と導入可否は呼出側で確認する
 */
//------------------------------------------------------------------------------
NativeError readSingleBootStorageRegistrySnapshot( HDEVINFO devices, SP_DEVINFO_DATA &device,
												  std::wstring_view					 instanceId,
												  const StorageInfEffects			&effects,
												  StorageSingleBootRegistrySnapshot &snapshot)
{
	snapshot			= {} ;
	const auto &service = effects.service ;	// 同じ署名付き元選択が指定する関連サービス
	// 選択機器の実識別と同じ元作用の有限集合だけを受け入れる
	if( !devices || devices == INVALID_HANDLE_VALUE || instanceId.empty() ||
	   instanceId.size() > 512U || instanceId.find( L'\0') != instanceId.npos ||
	   !isStorageEventSourceName( service.name) || service.auxiliary ||
	   service.type != SERVICE_KERNEL_DRIVER || service.start != SERVICE_BOOT_START ||
	   effects.effects.size() > 4096U) {
		return E_INVALIDARG ;
	}

	try {
		StorageSingleBootRegistrySnapshot made ;				// 観測が成立するまで公開しない現在局所値
		constexpr std::size_t			  CURRENT_LINK = 1U ;	// 正式CurrentControlSet
		constexpr std::size_t CONTROL_SET = 2U ;				// 同じリンクから解決したSYSTEM直下の制御セット
		// SetupAPIでのみ開く当該機器のHKR
		constexpr std::size_t HARDWARE = StorageSingleBootRegistrySnapshot::HARDWARE_KEY_INDEX ;
		// 実制御セットと機器キーを除く各固定位置の直接子名
		const std::array	  names{L"SYSTEM",
								L"CurrentControlSet",
								L"",
								L"Services",
								service.name.c_str(),
								L"Parameters",
								L"PnpInterface",
								L"",
								L"Interrupt Management",
								L"MessageSignaledInterruptProperties",
								L"Affinity Policy"} ;
		// CurrentControlSetと機器キーを除き、各名前は保持中の直接親からだけ解決する
		constexpr std::array<std::size_t, 11U> parents{0U, 0U, 0U, 2U, 3U, 4U, 5U, 0U, 7U, 8U, 8U} ;
		std::array<StorageRegistryChangeEvent, names.size()> changes ;	// 各キーの独立通知
		std::array<AutoLoggerRegistryKey, names.size()>		 keys ;		// 最終確認まで親と葉を保持
		StorageRegistryReadState state{nullptr, {}, 0U} ;				// 同じ正式制御セットを作る作業値
		// 必須親を順に開き、不在キーの配下は存在しないまま保持する
		for( std::size_t index = 0U; index < names.size(); ++index) {
			// 保持した直接の親。機器キーは別入口
			const HKEY parent = index == 0U ? HKEY_LOCAL_MACHINE : keys[parents[index]].get() ;
			// 確認した親が不在なら別の位置にある同名キーを探索しない
			if( index != HARDWARE && !parent) {
				continue ;
			}

			changes[index].reset( CreateEventW( nullptr, TRUE, FALSE, nullptr)) ;
			// 通知なしのキーを安定観測として扱わない
			if( !changes[index]) {
				return HRESULT_FROM_WIN32( GetLastError()) ;
			}

			state.changed = changes[index].get() ;
			// Windowsが現在機器から解決したハンドルだけを機器の起点にする
			if( index == HARDWARE) {
				const HKEY raw = SetupDiOpenDevRegKey( devices, &device, DICS_FLAG_GLOBAL, 0U,
													  DIREG_DEV, KEY_READ) ;	// 機器の読み取りだけ
				// 機器自身のキーが不明の場合は値の正式不在を発行しない
				if( raw == INVALID_HANDLE_VALUE) {
					return HRESULT_FROM_WIN32( GetLastError()) ;
				}

				keys[index].reset( raw) ;
				// 機器自身の読み取り中の変更通知
				const auto watch =
					RegNotifyChangeKeyValue( raw, FALSE,
											REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET |
												REG_NOTIFY_CHANGE_SECURITY,
											state.changed, TRUE) ;
				// 正式な親の変更や保護の途中変化を監視できることを要求する
				if( watch != ERROR_SUCCESS) {
					return HRESULT_FROM_WIN32( watch) ;
				}

				// 正規名の照合結果
				const auto identity =
					verifySingleBootHardwareKey( raw, instanceId, state.controlSet) ;
				// 別の機器または保護登録への参照を収容しない
				if( identity != 0U) {
					return identity ;
				}

				const auto security = readAutoLoggerSecurity( raw, false, state.eventLogInheritance,
															 made.keySecurity[index]) ;	// 元の保護
				// 不明な所有者やDACLを正式なハードウェアキーの観測へ使わない
				if( security != 0U) {
					return security ;
				}

				continue ;
			}

			// 実制御セットまたは元の固定子名
			const auto name = index == CONTROL_SET ? state.controlSet.c_str() : names[index] ;
			// 公式リンクと正式不在が認められる位置を分ける
			const auto role = index == CURRENT_LINK
								  ? StorageRegistryReadRole::CURRENT_CONTROL_SET
								  : (index < 4U ? StorageRegistryReadRole::ORDINARY
												: StorageRegistryReadRole::ABSENCE_ALLOWED) ;
			// 既存の直接子と保護を確認し、正式リンク以外は解決させない
			const auto error =
				readProtectedStorageKey( parent, name, role, state, keys[index],
										made.keySecurity[index]) ;	// 同じ直接子の元診断
			// 読取り失敗と既知親の直下の正式不在を区別する
			if( error != 0U) {
				return error ;
			}
		}

		constexpr std::array targets{
			std::pair{L"Parameters", 5U},
			std::pair{L"Parameters\\PnpInterface", 6U},
			std::pair{L"Interrupt Management", 8U},
			std::pair{L"Interrupt Management\\MessageSignaledInterruptProperties", 9U},
			std::pair{L"Interrupt Management\\Affinity Policy", 10U},
		} ; // 検査済み元AddRegが指す固定の局所位置
		// 署名付き候補の元順で、実際に変更する値だけを照会する
		for( std::size_t index = 0U; index < effects.effects.size(); ++index) {
			const auto &effect = effects.effects[index] ;	// 一作用の元文書、位置と各欄
			// 電源、イベントその他の宣言から別の値名を組み立てない
			if( effect.action != StorageInfAction::REGISTRY_VALUE) {
				continue ;
			}

			const auto &entry = effect.original ;	// 同じ検査済みの無名AddReg行
			// 別の関連サービスの作用や型・位置の未対応を拒否する
			if( !isSingleBootLocalRegistry( entry, false) || made.values.size() >= 10U ||
			   (entry.source.scope == SystemInfContext::SERVICE &&
				!same( entry.source.owner, service.name))) {
				return INVALID ;
			}

			const auto &fields = entry.row.values ;	// 省略を保つ元の名前・型・値
			const auto	target = std::ranges::find_if( targets, [&]( const auto &possible) {
				 return same( possible.first, fields[1]) ;
			 }) ; // 既知キー同士の対応だけを同期中に照合する
			// 大小文字違いを含む重複や既知でない位置を観測に混ぜない
			if( target == targets.end() || std::ranges::any_of( made.values, [&]( const auto &old) {
				   // 先行して確認した同じ文脈の名前
				   const auto &prior = effects.effects[old.effectIndex].original.row.values ;
				   return same( prior[1], fields[1]) && same( prior[2], fields[2]) ;
			   })) {
				return INVALID ;
			}

			auto &value		  = made.values.emplace_back() ;	// 同じ元順に対応する現在の値
			value.effectIndex = index ;
			const auto error =
				readSingleBootRegistryValue( keys[target->second].get(), fields[2].c_str(),
											// 元値の診断
											fields.size() == 3U ? REG_SZ : REG_DWORD, value) ;
			// 値の正しい型と全バイトが成立しなければ部分観測は返さない
			if( error != 0U) {
				return error ;
			}
		}

		const auto identity = verifySingleBootHardwareKey( keys[HARDWARE].get(), instanceId,
														  state.controlSet) ;	// 同じ機器の終端観測
		// 元作用がない状態や機器キーの途中変更を有効な局所値にしない
		if( identity != 0U || made.values.empty()) {
			return identity != 0U ? identity : INVALID ;
		}

		// 不在のキーについても保護した各親で名前の変更を最後まで確認する
		for( const auto &change : changes) {
			// 正式に不在の親配下には監視対象が存在しない
			if( !change) {
				continue ;
			}

			const auto wait = WaitForSingleObject( change.get(), 0U) ;	// 同じ読取り中の通知
			// 途中変更を値の既知状態や正式不在に置き換えない
			if( wait != WAIT_TIMEOUT) {
				return HRESULT_FROM_WIN32( wait == WAIT_FAILED ? GetLastError() : ERROR_RETRY) ;
			}
		}

		made.controlSet = std::move( state.controlSet) ;
		snapshot		= std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 前後の機器登録照合中に行う二回の観測を、同じ現在状態として比較する
 * @param[in] read 機器と元作用を二回だけ同期利用する読取り
 * @param[out] snapshot 両回の全観測が一致した場合の完全な現在状態。失敗時は空
 * @return 各観測と制御セット・元値の一致で0、変更時はERROR_RETRY、個別失敗は元HRESULT
 * @note SCMとレジストリの各不在は独立した値として保持し、一方で他方を補わない
 */
//------------------------------------------------------------------------------
NativeError readStableSingleBootDeviceSnapshot(
	const std::function<NativeError( StorageSingleBootDeviceSnapshot &)> &read,
	StorageSingleBootDeviceSnapshot										&snapshot)
{
	snapshot = {} ;
	// 読取り未指定の対象に完成した現在状態を発行しない
	if( !read) {
		return E_INVALIDARG ;
	}

	StorageSingleBootDeviceSnapshot made ;					// 二度目の照合まで公開しない全観測
	auto							error = read( made) ;	// 前観測で同じ対象を読む操作の元診断
	// 保護不明や読取り失敗を不在の成功へ変換しない
	if( error != 0U) {
		return error ;
	}

	const auto &registry = made.registry ;	// 同じ候補から照会した局所キーと制御セット
	// 局所値とイベントが共有するSYSTEMからServicesまでの保護を同期中だけ参照する
	const auto	matchesEvent = [&]( const StorageSingleBootEventSnapshot &event) {
		 return registry.controlSet == event.controlSet &&
				std::equal( registry.keySecurity.begin(),
						   registry.keySecurity.begin() +
							   StorageSingleBootRegistrySnapshot::SERVICE_KEY_INDEX,
						   event.eventParents.begin()) ;
	} ;

	const auto &current	  = made.installed.registered ;	// 署名確認済みの現用元。正式な未導入では空
	const auto &candidate = made.candidateService ;		// 独立に確認した候補関連サービス
	// 現用と候補が別名のときだけ追加のイベント源を照合する
	const bool	otherExpected = current && !same( current->package.installedService, candidate.name) ;
	// 同じ制御セットの元親と、現用・候補それぞれの元名に結び付いた観測だけを比較する
	if( registry.controlSet.empty() || !same( made.candidateEvent.event.name, candidate.name) ||
	   !matchesEvent( made.candidateEvent) ||
	   made.otherInstalledEvent.has_value() != otherExpected ||
	   (made.otherInstalledEvent &&
		(!matchesEvent( *made.otherInstalledEvent) ||
		 !same( made.otherInstalledEvent->event.name, current->package.installedService)))) {
		return HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	StorageSingleBootDeviceSnapshot fresh ;	// 独立した後観測。現在値と正式な不在を両方比較する
	error = read( fresh) ;
	// 同じ登録に見えても値・保護・サービス構成が変わった状態は公開しない
	if( error != 0U || fresh != made) {
		return error != 0U ? error : HRESULT_FROM_WIN32( ERROR_RETRY) ;
	}

	snapshot = std::move( made) ;
	return 0U ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 署名付き元AddRegに対する現在の一つの局所値の一致を調べる
 * @param[in] fields 元AddRegの値欄。同じ選択で型と所在を検査済み
 * @param[in] observed 同じ機器または関連サービスから読んだ完全値
 * @param[in] dword 元が指定するDWORD値。空文字列の行では未使用
 * @return 元の書込値と同じ型と完全バイトならtrue
 */
//------------------------------------------------------------------------------
bool matchesSingleBootRegistryValue( std::span<const std::wstring>		  fields,
									const StorageSingleBootRegistryValue &observed,
									std::uint32_t						  dword) noexcept
{
	// 正式不在と、存在する元型の値を区別する
	if( !observed.bytes) {
		return false ;
	}

	// 名前付き三欄は空のREG_SZを表す。バイトなしや終端以降の値は同一にしない
	if( fields.size() == 3U) {
		const std::array<std::byte, sizeof( wchar_t)> empty{} ;	// 空文字列を格納する元終端
		return observed.type == REG_SZ && std::ranges::equal( *observed.bytes, empty) ;
	}

	const auto bytes = std::as_bytes( std::span{&dword, 1U}) ;	// 同じWindowsのDWORDの全バイト
	return observed.type == REG_DWORD && std::ranges::equal( *observed.bytes, bytes) ;
}

//------------------------------------------------------------------------------
/**
 * @brief サービスの局所値を全現用元の署名付き宣言に照合して分類する
 * @param[in] fields 同じ候補の五欄のAddReg
 * @param[in] observed 候補が書き込む一つの局所値の現在観測
 * @param[in] desired 署名付き候補が指定するDWORD
 * @param[in] owners 同じサービスの検証済み全現用元。同期中だけ借用する
 * @param[in] shared 選択外の機器が同じサービスを利用する場合true
 * @return 比較できた局所値の関係。実値の元が裏付けられない場合はUNVERIFIED
 */
//------------------------------------------------------------------------------
StorageServiceChange classifySingleBootServiceValue(
	std::span<const std::wstring> fields, const StorageSingleBootRegistryValue &observed,
	std::uint32_t desired, std::span<const RegisteredStoragePackageEvidence *const> owners,
	bool shared) noexcept
{
	// 選択機器と選択外機器の同じ値名を元署名で照合する
	for( const auto *owner : owners) {
		const auto &values = owner->bootRegistryValues ;	// 現用元で確認したサービス局所値
		const auto	prior  = std::ranges::find_if( values, [&]( const auto &entry) {
			  return same( entry.subkey, fields[1U]) && same( entry.name, fields[2U]) ;
		  }) ; // 呼出中だけ元サブキーと値名を照合する
		// 既存値を候補と同値というだけで元署名の証拠にしない
		if( prior == values.end()
			   ? observed.bytes.has_value()
			   : !matchesSingleBootRegistryValue( fields, observed, prior->value)) {
			return StorageServiceChange::UNVERIFIED ;
		}
	}

	// 同じ型と値の再登録は共有サービスの変更に数えない
	if( matchesSingleBootRegistryValue( fields, observed, desired)) {
		return StorageServiceChange::KEEP ;
	}

	// 共有サービスに新しく値を足す場合も、選択外の機器への変更となる
	if( shared) {
		return StorageServiceChange::UPDATE_SHARED ;
	}

	return observed.bytes ? StorageServiceChange::UPDATE_SELECTED : StorageServiceChange::CREATE ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 一つの署名付き候補と同じ機器の現在観測から変更範囲を確定する
 * @param[in] intended 元SYSと全作用を照合済みの同じ候補
 * @param[in] snapshot 同じ選択に結ぶ現在の配置、局所値と全present機器の元登録
 * @param[out] changes 起動・イベント・局所値の分類。失敗時は初期値
 * @return 全分類が成立すれば0。元観測の不足や関係の矛盾があればHRESULT
 * @note 同名の所属だけから別サービスによる同じSYSの参照を否定しない。書込みは行わない
 */
//------------------------------------------------------------------------------
NativeError classifySingleBootStorageChanges( const StorageInfEffects				&intended,
											 const StorageSingleBootSharingSnapshot &snapshot,
											 StorageSingleBootChanges				&changes)
{
	changes				 = {} ;
	const auto &selected = intended.service ;					// 同じ署名選択が書く関連サービス
	const auto &device	 = snapshot.device ;					// 選択機器の現用元と候補の局所観測
	const auto &actual	 = device.candidateService.evidence ;	// 同じ名前の現在SCM
	const auto &deployed = snapshot.destination.existing ;		// 同じ正規宛先の現在SYS
	const auto &event	 = device.candidateEvent.event ;		// 同じ名前のイベント現在値
	const auto &roster	 = snapshot.candidateServiceDevices ;	// 同名サービスを使うpresent機器
	// 選択と候補の現在観測を名前・元設定・保護が成立しないデータへ持ち替えない
	if( !intended.singleBootEvent || selected.auxiliary || selected.binarySha256.size() != 64U ||
	   !selected.group || snapshot.destination.directorySecurity.empty() ||
	   !same( device.candidateService.name, selected.name) || !same( event.name, selected.name) ||
	   !same( intended.singleBootEvent->name, selected.name)) {
		return INVALID ;
	}

	try {
		StorageSingleBootChanges made ;							// 同じ選択のすべてを確認するまで公開しない
		const auto &registered = device.installed.registered ;	// 同じ選択機器の署名付き元
		// 選択機器の現用サービスが候補と同じ場合にだけ共有の分母へ含める
		const bool	selectedUses =
			registered && same( registered->package.installedService, selected.name) ;
		// 同名サービスキーの現在保護。正式な不在では空
		const bool serviceKey =
			!device.registry.keySecurity[StorageSingleBootRegistrySnapshot::SERVICE_KEY_INDEX]
				 .empty() ;
		std::vector<const RegisteredStoragePackageEvidence *>
			owners ;	// 保持中の同名サービスの元だけを借用する
		// 選択機器が同じサービスを使う場合だけ既存サービスの現用元として扱う
		if( selectedUses) {
			owners.push_back( &registered->package) ;
		}

		// 同名所属の選択外機器ごとに署名付き元を確認する。未確認の所属は件数に残る
		for( const auto &peer : snapshot.peers) {
			// 現在の所属が同じでも別名の出自資料は使用しない
			if( peer.diagnostic == 0U && peer.origin && same( peer.service, selected.name) &&
			   same( peer.origin->installedService, selected.name) &&
			   std::ranges::binary_search( roster, peer.instance)) {
				owners.push_back( &*peer.origin) ;
			}
		}

		const bool shared = roster.size() > (selectedUses ? 1U : 0U) ;	// 選択外の現用機器が存在する
		// 起動の三つの配置と同名の現用機器をすべて確認した正式不在
		const bool serviceAbsent =
			!actual && !deployed && !serviceKey && owners.empty() && roster.empty() ;
		const bool newTarget = serviceAbsent && !event.present && event.security.empty() &&
							   !event.messageFile && event.messageFileType == REG_NONE &&
							   !event.typesSupported && !event.categoryCount &&
							   // 各位置を独立に確認した正式不在
							   event.lastWrite == 0U ;
		// 既存配置は対象サービスの全現用元と同じ構成・同じ実SYSに結ぶ
		const bool owned =
			actual && deployed && serviceKey && !owners.empty() && owners.size() == roster.size() &&
			std::ranges::all_of( owners, [&]( const auto *owner) {
				return matchesRegisteredStorageBoot( *owner, selected, actual, deployed) ;
			}) ;
		// 完全な不在か、署名付き全現用元の一致を確認した場合だけ変更種別を進める
		if( newTarget) {
			made.boot  = StorageServiceChange::CREATE ;
			made.event = StorageServiceChange::CREATE ;
		}
		// 既存サービスと配置を全署名元に帰属させた場合だけ同じ元値を照合する
		else if( owned) {
			const bool description = std::ranges::any_of( selected.directives, []( const auto &row) {
				return same( row.key, L"DisplayName") || same( row.key, L"Description") ;
			}) ; // この観測では元説明の書込みを裏付けない
			const bool sameBinary =
				// 引き続き使用するSYS
				deployed->sha256 == selected.binarySha256 ;
			// 保持すべき共有名の説明は元が書かない場合だけ既存の構成比較を使う
			if( !description) {
				// 起動構成と正規SYSの全値を候補の元宣言と比較する
				const bool keepsBoot = sameBinary && actual->type == selected.type &&
									   actual->start == selected.start &&
									   actual->errorControl == selected.errorControl &&
									   same( actual->group, *selected.group) ;
				// 別名サービスの参照や同じ実ファイルへの別経路が不明なら異なるSYSを上書きしない
				made.boot = keepsBoot	 ? StorageServiceChange::KEEP
							: shared	 ? StorageServiceChange::UPDATE_SHARED
							: sameBinary ? StorageServiceChange::UPDATE_SELECTED
										 : StorageServiceChange::UNVERIFIED ;
			}

			// 全元署名のイベント宣言と実値が揃う場合だけ維持・更新を分類する
			if( event.lastWrite != 0U && !event.security.empty() &&
			   std::ranges::all_of( owners, [&]( const auto *owner) {
				   const auto &prior = owner->eventReferences.front() ;	// 一つの関連イベント元宣言
				   return prior && matchesRegisteredStorageEvent( *prior, event) ;
			   })) {
				made.event = matchesRegisteredStorageEvent( *intended.singleBootEvent, event)
								 ? StorageServiceChange::KEEP
							 : shared ? StorageServiceChange::UPDATE_SHARED
									  : StorageServiceChange::UPDATE_SELECTED ;
			}
		}

		std::size_t index{} ;	// 候補と観測の両方に存在する局所値の順番
		// 元の作用配列から、機器固有とサービス共有の値を元順で分類する
		for( std::size_t effectIndex = 0U; effectIndex < intended.effects.size(); ++effectIndex) {
			const auto &effect = intended.effects[effectIndex] ;	// 同じ候補の元節と元行
			// イベント・サービス宣言などは局所値の確認へ混ぜない
			if( effect.action != StorageInfAction::REGISTRY_VALUE) {
				continue ;
			}

			const auto &entry = effect.original ;	// 同じ候補が変更する局所値の元行
			// 署名付き元に対応しない観測や未確認の位置は変更に使わない
			if( index == device.registry.values.size() ||
			   device.registry.values[index].effectIndex != effectIndex ||
			   !isSingleBootLocalRegistry( entry, false)) {
				return INVALID ;
			}

			const auto	 &observed = device.registry.values[index++] ;	// 完全な値または正式な不在
			const auto	 &fields   = entry.row.values ;					// 型・値名の原欄
			std::uint32_t desired{} ;									// 元がDWORDを指定する場合の値
			// 型や値の矛盾を正式な不在へ置換しない
			if( (fields.size() == 5U && !integer( fields[4U], desired)) ||
			   observed.type !=
				   (observed.bytes ? (fields.size() == 3U ? REG_SZ : REG_DWORD) : REG_NONE)) {
				return INVALID ;
			}

			// 機器の局所値だけは同じ機器の読み取りから独立して分類する
			if( entry.source.scope == SystemInfContext::HARDWARE) {
				made.registry.push_back( !observed.bytes ? StorageServiceChange::CREATE
										: matchesSingleBootRegistryValue( fields, observed, desired)
											? StorageServiceChange::KEEP
											: StorageServiceChange::UPDATE_SELECTED) ;
			} else {
				// サービスの局所値は全現用元の証拠、または正式な新規の配置に限る
				made.registry.push_back(
					same( entry.source.owner, selected.name) &&
							(owned || (newTarget && !observed.bytes))
						? classifySingleBootServiceValue( fields, observed, desired, owners, shared)
						: StorageServiceChange::UNVERIFIED) ;
			}
		}

		// 取り残した観測を同じ署名付き元の結果へ含めない
		if( index != device.registry.values.size()) {
			return INVALID ;
		}

		changes = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	}
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief 二つのサービス所属の差が同じ選択機器一件だけであることを確認する
 * @param[in] without 選択機器を含まない正規化済み所属の昇順
 * @param[in] with 選択機器を含む正規化済み所属の昇順
 * @param[in] selected 両一覧と同じ表記の選択機器の識別
 * @return 選択機器だけを除くと同じ所属ならtrue
 */
//------------------------------------------------------------------------------
bool matchesSingleBootRosterWithoutSelection( std::span<const std::wstring> without,
											 std::span<const std::wstring> with,
											 std::wstring_view			   selected) noexcept
{
	const auto member = std::ranges::lower_bound( with, selected) ;	// 昇順の同じ機器の位置
	// 選択機器の消失だけを認め、他の追加や削除を同じ所属へ合算しない
	if( member == with.end() || *member != selected || with.size() - 1U != without.size() ||
	   std::ranges::binary_search( without, selected)) {
		return false ;
	}

	const auto prefix = static_cast<std::size_t>( member - with.begin()) ;	// 選択機器より前の件数
	return std::ranges::equal( without.first( prefix), with.first( prefix)) &&
		   std::ranges::equal( without.subspan( prefix), with.subspan( prefix + 1U)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名付き局所AddRegの全作用と適用後に独立して読んだ値を照合する
 * @param[in] intended 同じ元選択の作用配列とサービス名
 * @param[in] before 適用前の保護付き局所値と各値の変更種別
 * @param[in] after 同じ候補と機器の適用後の保護付き局所値
 * @return 元作用順と型付き値がすべて一致し、以前のキー保護と維持値が保たれればtrue
 */
//------------------------------------------------------------------------------
bool matchesAppliedSingleBootRegistry( const StorageInfEffects				  &intended,
									  const StorageSingleBootInstallScope	  &before,
									  const StorageSingleBootRegistrySnapshot &after)
{
	const auto &prior	= before.observed.device.registry ;	// 同じ作用が触れる適用前の局所状態
	const auto &changes = before.changes.registry ;			// 元作用ごとに確定した許容範囲
	// 同じ制御セットと同じ元作用に結ばれた前後の全値を比較する
	if( after.controlSet.empty() || after.controlSet != prior.controlSet || prior.values.empty() ||
	   prior.values.size() != after.values.size() || changes.size() != after.values.size() ||
	   after.keySecurity[StorageSingleBootRegistrySnapshot::SERVICE_KEY_INDEX].empty() ||
	   prior.keySecurity[StorageSingleBootRegistrySnapshot::HARDWARE_KEY_INDEX].empty()) {
		return false ;
	}

	// 元の保護を別の主体へ変更せず、正式に不在のキーは新規の保護を認める
	if( !std::ranges::equal(
		   prior.keySecurity, after.keySecurity,
		   []( const auto &old, const auto &current) { return old.empty() || old == current ; })) {
		return false ;
	}

	std::size_t index{} ;	// 元行の位置とは別に進める局所値の観測順
	// 署名付き作用を元順に確認し、局所値一件ずつを観測の位置と値へ結ぶ
	for( std::size_t effectIndex = 0U; effectIndex < intended.effects.size(); ++effectIndex) {
		const auto &effect = intended.effects[effectIndex] ;	// 元作用とその所在
		// 電源・イベントを局所値の確認へ重複して含めない
		if( effect.action != StorageInfAction::REGISTRY_VALUE) {
			continue ;
		}

		const auto &entry = effect.original ;	// 署名付き元AddReg行
		// 元作用と同じ配列位置を指す全値と所有を要求する
		if( index == after.values.size() || prior.values[index].effectIndex != effectIndex ||
		   after.values[index].effectIndex != effectIndex ||
		   !isSingleBootLocalRegistry( entry, false) ||
		   (entry.source.scope == SystemInfContext::SERVICE &&
			!same( entry.source.owner, intended.service.name))) {
			return false ;
		}

		const auto	 &fields = entry.row.values ;		// 元の型と値を保持する欄
		const auto	 &value	 = after.values[index] ;	// 適用後に読んだ型と完全バイト
		const auto	  change = changes[index] ;			// 同じ元値の適用前の変更分類
		std::uint32_t desired{} ;						// 元が五欄で指定したDWORD値
		// 作用先と型付き値の一致を要求し、維持の承認を値変更へ読み替えない
		if( (fields.size() == 5U && !integer( fields[4U], desired)) ||
		   !matchesSingleBootRegistryValue( fields, value, desired) ||
		   (change != StorageServiceChange::CREATE &&
			change != StorageServiceChange::UPDATE_SELECTED &&
			(change != StorageServiceChange::KEEP || value != prior.values[index]))) {
			return false ;
		}

		++index ;
	}

	return index == after.values.size() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名付き電源定義と全所在を同じ制御セットの現在定義に照合する
 * @param[in] intended 同じ選択が指定する電源定義の元順
 * @param[in] registered 適用後の実登録から確認した署名付き電源定義の元順
 * @param[in] before 適用前の保護付き定義と変更種別
 * @param[in] after 適用後の正式制御セットと全設定の保護付き観測
 * @return 全定義、位置、元保護と維持する型付き値が成立すればtrue
 */
//------------------------------------------------------------------------------
bool matchesAppliedSingleBootPower( std::span<const RangedStoragePowerSetting> intended,
								   std::span<const RangedStoragePowerSetting> registered,
								   const StorageSingleBootSharingSnapshot	 &before,
								   const StoragePowerSettingsSnapshot		 &after)
{
	const auto &prior = before.power ;	// 同じ選択の作用先と適用前の保護
	// 同じ制御セットの保護と、署名付き元順のすべての定義を要求する
	if( after.controlSet.empty() || after.controlSet != prior.controlSet ||
	   after.parents != prior.parents ||
	   std::ranges::any_of( after.parents,
						   []( const auto &protection) { return protection.empty() ; }) ||
	   intended.empty() || registered.size() != intended.size() ||
	   prior.settings.size() != intended.size() || after.settings.size() != intended.size() ||
	   before.powerChanges.size() != intended.size()) {
		return false ;
	}

	// 同じ順に全登録場所と設定値を確認し、一件でも欠ければ反映と判定しない
	for( std::size_t index = 0U; index < intended.size(); ++index) {
		const auto &current = after.settings[index] ;		// 同設定の適用後の全所在と型付き値
		const auto &old		= prior.settings[index] ;		// 同設定で適用前に観測した値と保護
		const auto	change	= before.powerChanges[index] ;	// 同設定の許容された変更種別
		// 全所在の一意性は必須で、既存のキーの保護は適用前と同じものを要求する
		if( !current.locations || !matchesStoragePowerDefinition( intended[index], current) ||
		   !matchesStoragePowerDefinition( registered[index], current) ||
		   !std::ranges::equal( old.keys, current.keys, []( const auto &priorKey, const auto &key) {
			   return priorKey.security.empty() || priorKey.security == key.security ;
		   })) {
			return false ;
		}

		// 維持の承認では同じ値の元型と保護付きの全所在も保存する
		if( change != StoragePowerChange::CREATE && change != StoragePowerChange::UPDATE_SELECTED &&
		   (change != StoragePowerChange::KEEP ||
			!matchesStoragePowerDefinition( intended[index], old) ||
			old.locations != current.locations || old.displayName != current.displayName ||
			old.description != current.description || old.unitLabel != current.unitLabel)) {
			return false ;
		}
	}

	return true ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 適用後の実登録と全作用を署名付き単一起動選択および適用前の保護へ照合する
 * @param[in] intended 同じ署名付き選択の元構成と全作用
 * @param[in] before 指定適用前に確認した同じ選択の現在観測と変更種別
 * @param[in] after 同じ機器と候補を独立して読み取った適用後の現在観測
 * @param[in] publishedInf 登録直後に元閉包と照合した公開INF名
 * @param[in] infSha256 元INFの完全SHA-256
 * @param[in] catalogSha256 元CATの完全SHA-256
 * @param[in] selectedInstance 同じ選択機器の正規化済み識別。所属一覧と同じ表記
 * @param[in] retained 旧関連サービスが別名の場合の独立した適用後の観測
 * @return 実登録・元バイト・作用・保護・所属がすべて成立すれば0、不一致はHRESULT
 * @note 観測を比較する。再起動後の確認待ちと、端末からの読取りは呼出側が扱う
 */
//------------------------------------------------------------------------------
NativeError verifyAppliedSingleBootStorageEffects(
	const StorageInfEffects &intended, const StorageSingleBootInstallScope &before,
	const StorageSingleBootSharingSnapshot &after, std::wstring_view publishedInf,
	std::wstring_view infSha256, std::wstring_view catalogSha256,
	std::wstring_view											   selectedInstance,
	const std::optional<StorageSingleBootRetainedServiceSnapshot> &retained)
{
	const auto &selected	 = intended.service ;			// 元署名と選択節に結ばれた起動サービス
	const auto &desiredEvent = intended.singleBootEvent ;	// 同じ関連名の元Systemイベント
	// 適用先を確定できない元選択、公開名とハッシュから反映を推定しない
	if( !desiredEvent || desiredEvent->messageFile.empty() || selected.auxiliary ||
	   !selected.group || selected.binaryBytes == 0U || selected.binarySha256.size() != 64U ||
	   infSha256.size() != 64U || catalogSha256.size() != 64U || publishedInf.empty() ||
	   selectedInstance.empty() || !same( desiredEvent->name, selected.name)) {
		return E_INVALIDARG ;
	}

	const auto			 &previous	= before.observed ;						// 指定適用前に同じ元選択で固定した全観測
	const auto			 &installed = after.device.installed.registered ;	// 選択機器から読んだ実登録
	constexpr NativeError RETRY		= HRESULT_FROM_WIN32( ERROR_RETRY) ;	// 反映の観測が元作用と不一致
	// API成功やパッケージの存在だけで同じ選択機器への割当てと扱わない
	if( !installed || !same( installed->package.publishedInf, publishedInf) ||
	   !same( installed->package.installedSection, selected.selectedInstallSection) ||
	   !same( installed->package.installedService, selected.name)) {
		return RETRY ;
	}

	const auto &package = installed->package ;	// 同じ公開INFとDriver Storeから確認した元署名
	const auto &attribute =
		after.device.installed.sectionExtension ;	// Windowsが実機器から返した節装飾
	// 正式な属性の不在は元登録の装飾なしに対応する
	const std::wstring_view extension =
		attribute ? std::wstring_view{*attribute} : std::wstring_view{} ;
	const std::wstring_view section = package.installedSection ;	// 元基本節と装飾を結んだ実節
	const auto basicLength = package.installedBasicSection.size() ;	// 実節内の元基本節の長さ
	// 合成後の節名だけでなく、実機器が保持する基本節と装飾も同じ登録に結ぶ
	if( basicLength == 0U || basicLength > section.size() ||
	   !same( section.substr( 0U, basicLength), package.installedBasicSection) ||
	   section.substr( basicLength) != package.installedSectionExtension ||
	   extension != package.installedSectionExtension) {
		return RETRY ;
	}

	const auto &source = installed->source ;			// 同じCATへ照合したDriver Storeの元SYS
	const auto &copy   = after.destination.existing ;	// 同じ元選択が指定した正規配置での実SYS
	// 元または実SYSが正式に不在の場合は、誤ったハッシュを読めた場合と区別する
	if( !source.existing || !copy) {
		return RETRY ;
	}

	// INF、CAT、元SYSと実SYSの全ハッシュ・バイト数が候補と一致した場合だけ構成へ進む
	if( package.infSha256 != infSha256 || package.catalogSha256 != catalogSha256 ||
	   package.driverSha256 != selected.binarySha256 ||
	   source.existing->sha256 != selected.binarySha256 ||
	   source.existing->bytes != selected.binaryBytes || copy->sha256 != selected.binarySha256 ||
	   copy->bytes != selected.binaryBytes) {
		return TRUST_E_BAD_DIGEST ;
	}

	const auto &boot	   = package.bootService ;				// 実登録の署名付き元宣言
	const auto &service	   = after.device.candidateService ;	// 候補名による独立した現在SCM照会
	const auto &oldService = previous.device.candidateService ;	// 同名SCMの適用前の保護付き観測
	const auto &oldCopy	   = previous.destination.existing ;	// 候補のSYS配置先にあったファイル
	const auto &event	   = after.device.candidateEvent ;		// 同じ制御セットでの現在イベント
	const auto &oldEvent   = previous.device.candidateEvent ;	// 同名イベント源の適用前の元値
	// 元の起動構成、独立して確認した現在値、維持する保護を同じ配置に結ぶ
	if( !boot || boot->type != selected.type || boot->start != selected.start ||
	   boot->errorControl != selected.errorControl || !same( boot->group, *selected.group) ||
	   !same( service.name, selected.name) || !same( oldService.name, selected.name) ||
	   !matchesRegisteredStorageBoot( package, selected, service.evidence, copy) ||
	   installed->service != *service.evidence || installed->deployed != after.destination ||
	   source.directorySecurity.empty() || source.repositorySecurity.empty() ||
	   source.existing->security.empty() || after.destination.directorySecurity.empty() ||
	   previous.destination.directorySecurity != after.destination.directorySecurity ||
	   (oldService.evidence && oldService.evidence->security != service.evidence->security) ||
	   (oldCopy && oldCopy->security != copy->security) ||
	   (before.changes.boot == StorageServiceChange::KEEP
			? service != oldService || !oldCopy || oldCopy->sha256 != copy->sha256 ||
				  oldCopy->bytes != copy->bytes
			: before.changes.boot != StorageServiceChange::CREATE &&
				  before.changes.boot != StorageServiceChange::UPDATE_SELECTED)) {
		return RETRY ;
	}

	const auto &registeredEvent = package.eventReferences.front() ;	// 実登録の元イベント宣言
	const auto &registry = after.device.registry ;					// 同じ制御セットと同じ機器の保護付き局所観測
	constexpr std::size_t COMMON_POWER_PARENTS = 3U ;				// 局所キーと電源が共有する親階層
	// 適用後の各観測を同じ保護へ結び、署名付きイベントと維持する元値を照合する
	if( registry.controlSet != after.power.controlSet || registry.controlSet != event.controlSet ||
	   event.controlSet != oldEvent.controlSet || event.eventParents != oldEvent.eventParents ||
	   std::ranges::any_of( event.eventParents, []( const auto &acl) { return acl.empty() ; }) ||
	   !std::equal( event.eventParents.begin(),
				   event.eventParents.begin() +
					   StorageSingleBootRegistrySnapshot::SERVICE_KEY_INDEX,
				   registry.keySecurity.begin()) ||
	   !std::equal( after.power.parents.begin(), after.power.parents.begin() + COMMON_POWER_PARENTS,
				   registry.keySecurity.begin()) ||
	   !registeredEvent || !matchesRegisteredStorageEvent( *registeredEvent, event.event) ||
	   !matchesRegisteredStorageEvent( *desiredEvent, event.event) ||
	   event.event.categoryCount != desiredEvent->categoryCount || event.event.security.empty() ||
	   event.event.lastWrite == 0U ||
	   (oldEvent.event.present && oldEvent.event.security != event.event.security) ||
	   (before.changes.event == StorageServiceChange::KEEP
			? !oldEvent.event.present || oldEvent.event.messageFile != event.event.messageFile ||
				  oldEvent.event.messageFileType != event.event.messageFileType ||
				  oldEvent.event.typesSupported != event.event.typesSupported ||
				  oldEvent.event.categoryCount != event.event.categoryCount
			: before.changes.event != StorageServiceChange::CREATE &&
				  before.changes.event != StorageServiceChange::UPDATE_SELECTED) ||
	   !matchesAppliedSingleBootRegistry( intended, before, registry) ||
	   !matchesAppliedSingleBootPower( intended.powerSettings, package.powerSettings, previous,
									  after.power)) {
		return RETRY ;
	}

	const auto &oldMembers = previous.candidateServiceDevices ;	// 候補側の適用前の完全所属
	const auto &newMembers = after.candidateServiceDevices ;	// 同じ候補側の適用後の完全所属
	// 選択機器以外の観測を変えず、候補に選択機器だけが加わったことを要求する
	if( after.peers != previous.peers || after.device.otherInstalledEvent ||
	   !after.otherInstalledServiceDevices.empty() ||
	   (std::ranges::binary_search( oldMembers, selectedInstance)
			? oldMembers != newMembers
			: !matchesSingleBootRosterWithoutSelection( oldMembers, newMembers, selectedInstance))) {
		return RETRY ;
	}

	const auto &oldInstalled  = previous.device.installed.registered ;	// 同じ機器の署名付き旧登録
	const auto &previousEvent = previous.device.otherInstalledEvent ;	// 別名の旧関連イベント
	// 旧関連サービスが候補と別名なら選択機器の所属は切り替わる
	const bool	switched =
		oldInstalled && !same( oldInstalled->package.installedService, selected.name) ;
	// 旧登録が別名だったときだけ旧構成の独立読取りを必須とする
	if( retained.has_value() != switched) {
		return RETRY ;
	}

	// 旧構成と各保護を維持し、元の完全所属から選択機器だけが離れたことを確認する
	if( retained &&
	   (!previousEvent || retained->event != *previousEvent ||
		retained->event.controlSet != registry.controlSet ||
		retained->event.eventParents != event.eventParents ||
		!same( retained->service.name, oldInstalled->package.installedService) ||
		!retained->service.evidence || *retained->service.evidence != oldInstalled->service ||
		!retained->destination.existing || retained->destination != oldInstalled->deployed ||
		!matchesSingleBootRosterWithoutSelection(
			retained->devices, previous.otherInstalledServiceDevices, selectedInstance))) {
		return RETRY ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新登録の確認が不成立の場合に再起動後の確認待ちの根拠を照合する
 * @param[in] before 指定適用前に確認した同じ選択の全観測
 * @param[in] newReadError 新登録の観測が返した非0の元診断
 * @param[in] rebootRequired Windowsの指定適用が再起動を要求した場合true
 * @param[in] readBefore 必要な場合に一回だけ同じ機器と旧状態を独立に安定観測する読取り
 * @return 再起動要求と全旧状態の一致が成立した場合は再起動後の確認待ち、その他は未確認と診断
 * @note 署名や保護の読取り失敗を再起動要求で補わない。再起動は実行しない
 */
//------------------------------------------------------------------------------
DriverStorageReflectionResult resolveUnconfirmedSingleBootStorageReflection(
	const StorageSingleBootSharingSnapshot &before, NativeError newReadError, bool rebootRequired,
	const std::function<NativeError( StorageSingleBootSharingSnapshot &)> &readBefore)
{
	// この経路は新登録の読取り不成立時だけ使用する
	if( newReadError == 0U) {
		return {DriverStorageReflectionState::UNCONFIRMED, E_INVALIDARG} ;
	}

	constexpr NativeError RETRY =
		// 旧状態に留まった可能性がある失敗
		HRESULT_FROM_WIN32( ERROR_RETRY) ;
	constexpr NativeError NOT_FOUND = HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;	// 新登録の正式な不在
	// 署名や読取りの元診断を、再起動後の確認待ちで上書きしない
	if( !rebootRequired || (newReadError != RETRY &&
						   (newReadError != NOT_FOUND || before.device.installed.registered))) {
		return {DriverStorageReflectionState::UNCONFIRMED, newReadError} ;
	}

	// 読取り操作がなければ旧状態が保持されたことを確認できない
	if( !readBefore) {
		return {DriverStorageReflectionState::UNCONFIRMED, E_INVALIDARG} ;
	}

	try {
		StorageSingleBootSharingSnapshot unchanged ;	// 旧登録と全作用先を確認した独立観測
		const auto error = readBefore( unchanged) ;		// 旧登録を安定観測できたかの元診断
		// 再読取りに失敗した場合は旧配置が維持されたことを推定しない
		if( error != 0U) {
			return {DriverStorageReflectionState::UNCONFIRMED, error} ;
		}

		return unchanged == before
				   ? DriverStorageReflectionResult{DriverStorageReflectionState::RESTART_CHECK, 0U}
				   : DriverStorageReflectionResult{DriverStorageReflectionState::UNCONFIRMED,
												   RETRY} ;
	} catch( const std::bad_alloc &) {
		return {DriverStorageReflectionState::UNCONFIRMED, E_OUTOFMEMORY} ;
	}
}

} // namespace drivercrate
