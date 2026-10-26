//------------------------------------------------------------------------------
/**
 * @file collector_user_task.cpp
 * @brief 現在userの日次収集Taskを保護取引と実COMで管理します。
 * @version 01.01.03
 * @date 2026/10/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23 新user Taskの登録と所有解除を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/23 登録XML表現差と初回未確定解除を限定処理。
 * Ver.01.00.02 Shunji Ogawa  2026/10/23 Enabled既定行省略を原byte両pinだけで照合。
 * Ver.01.01.00 Shunji Ogawa  2026/10/23 別名の汎用日次Task契約と所有schemaを追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理。
 * Ver.01.01.02 Shunji Ogawa  2026/10/24 root直下distribution Actionへ完全な保護親検査を指定。
 * Ver.01.01.03 Shunji Ogawa  2026/10/24 未登録Taskの正常不存在を所有記録なしで確認。
 * </pre>
 *
 * @note 旧Task名は照会しません。同じuserと管理者の同時改変からの隔離は保証しません。
 * @see docs/adr/0394-collector-user-task-install-lifecycle.md
 */
//------------------------------------------------------------------------------
#include "collector_user_task.h"
#include "collector_setup_workspace.h"
#include "local_driver_collector.h"
#include "official_file_verifier.h"
#include "com_raii.h"

#include <Windows.h>
#include <sddl.h>
#include <taskschd.h>
#include <wrl/client.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
namespace fs = std::filesystem ;
/** @brief 有限metadataのJSON objectです。 */
using Json = winrt::Windows::Data::Json::JsonObject ;
/** @brief 有限metadataのJSON値です。 */
using Value = winrt::Windows::Data::Json::JsonValue ;
/** @brief OS handleの単独所有です。 */
using Handle = std::unique_ptr<void, decltype( &CloseHandle)> ;
/** @brief LocalAlloc領域の単独所有です。 */
using Memory = std::unique_ptr<void, decltype( &LocalFree)> ;
// 導入後にだけ作る端末固有metadata。seedへ入れない。
constexpr std::wstring_view PLAN_FILE = L"collector-user-task-plan.json" ;
// 原XMLとSDDLを結合する新schemaだけのreceipt。
constexpr std::wstring_view OWNER_FILE = L"collector-user-task-ownership.json" ;

/** @brief 意味拒否を個人情報のない固定stageへ変換します。
 * @param[in] condition 必須条件。
 * @param[in] stage 固定診断名。
 * @throws std::runtime_error 不成立。
 */
void						require( const bool condition, const char *stage)
{
	// 不明な所有や状態を成功へ変換しない。
	if( !condition) {
		throw std::runtime_error( stage) ;
	}
}

/** @brief 正値警告も含めS_OK以外を拒否します。
 * @param[in] result 元HRESULT。
 * @param[in] stage 固定診断名。
 * @throws std::runtime_error S_OK以外。元HRESULTは診断へ保持します。
 */
void exactOk( const HRESULT result, const char *stage)
{
	// Taskの部分成功を有効登録や不存在の証明へ転換しない。
	if( result != S_OK) {
		std::printf( "SETUP_USER_TASK_ERROR stage=%s hresult=%08lx state=UNKNOWN retained=1\n",
					stage, static_cast<unsigned long>( result)) ;
		throw std::runtime_error( stage) ;
	}
}

/** @brief UTF-8原byteの共通SHA-256を返します。
 * @param[in] bytes 有限入力。
 * @return 小文字64桁hash。
 * @throws std::exception hash失敗。
 */
std::wstring hash( const std::string_view bytes)
{
	std::wstring result ;	// 共通検証器が所有出力を作る。
	require( computeBytesSha256( bytes, result) == 0U, "USER_TASK_HASH") ;
	return result ;
}

/** @brief 小文字SHA-256の閉形式を検査します。
 * @param[in] value 検査するpin。
 * @return 小文字hex64桁だけならtrue。
 */
bool validHash( const std::wstring_view value)
{
	return value.size() == 64U && std::all_of( value.begin(), value.end(),
											  // 一文字ずつhex範囲を検査する。
											  []( const wchar_t ch) {
												  return (ch >= L'0' && ch <= L'9') ||
														 (ch >= L'a' && ch <= L'f') ;
											  }) ;
}

/** @brief 取引に依存しないidentityを完全一致で照合します。
 * @param[in] first 一方のidentity。
 * @param[in] second もう一方のidentity。
 * @return SID/root/manifest/導出名の全一致。
 */
bool sameIdentity( const CollectorUserTaskPlan &first, const CollectorUserTaskPlan &second)
{
	return CompareStringOrdinal( first.root.c_str(), -1, second.root.c_str(), -1, TRUE) ==
			   CSTR_EQUAL &&
		   first.sid == second.sid && first.manifest == second.manifest &&
		   first.path == second.path && first.distributionDaily == second.distributionDaily ;
}

/** @brief 取引nonceと初回日時を含めて照合します。
 * @param[in] first 先行plan。
 * @param[in] second 所有receiptのplan。
 * @return 全fieldの一致。
 */
bool samePlan( const CollectorUserTaskPlan &first, const CollectorUserTaskPlan &second)
{
	return sameIdentity( first, second) && first.nonce == second.nonce &&
		   first.boundary == second.boundary && first.previousOwnership == second.previousOwnership ;
}

/** @brief 修復で残る旧所有receiptの全fieldを新planへ結合します。
 * @param[in] owner 既に保護検査した同じ配置の旧所有記録。
 * @return 全fieldの小文字SHA-256。
 * @throws std::exception hash失敗。
 * @note 新planと旧receiptの途中状態だけを識別し、旧Taskをadoptする許可にしません。
 */
std::wstring ownershipFingerprint( const CollectorUserTaskOwnership &owner)
{
	const auto &plan = owner.plan ;	// 一世代前のhash文字列までを含め、再帰しない。
	return hash( winrt::to_string( plan.root + L"\n" + plan.sid + L"\n" + plan.manifest + L"\n" +
								 plan.path + L"\n" + plan.nonce + L"\n" + plan.boundary + L"\n" +
								 plan.previousOwnership + L"\n" + owner.enabledXml + L"\n" +
								 owner.disabledXml + L"\n" + owner.sddl)) ;
}

/** @brief planの固定取引形式を検査します。
 * @param[in] plan 保護読取りまたは新規取引。
 * @throws std::exception nonce、日時またはidentity不正。
 */
void validatePlan( const CollectorUserTaskPlan &plan)
{
	require( sameIdentity( plan, collectorUserTaskIdentity( plan.root, plan.sid, plan.manifest,
														 plan.distributionDaily)),
			"USER_TASK_PLAN_IDENTITY") ;
	GUID nonce{} ;	// GUID以外をDescriptionへ取り込まない。
	require( plan.nonce.size() == 38U && CLSIDFromString( plan.nonce.c_str(), &nonce) == S_OK,
			"USER_TASK_PLAN_NONCE") ;
	require( plan.boundary.size() == 19U &&
				plan.boundary.substr( 10U) ==
					(plan.distributionDaily ? L"T17:00:00" : L"T15:00:00") &&
				plan.boundary[4] == L'-' && plan.boundary[7] == L'-',
			"USER_TASK_PLAN_BOUNDARY") ;
	require( plan.previousOwnership.empty() || validHash( plan.previousOwnership),
			"USER_TASK_PREDECESSOR_HASH") ;
}

/** @brief 全定義と非実行状態を要求します。
 * @param[in] snapshot 読戻ししたTask。
 * @throws std::exception 契約不一致または実行中・不明。
 */
void validateSnapshot( const CollectorUserTaskSnapshot &snapshot)
{
	const bool omitted = !snapshot.omittedEnabledPins.empty() ;	// 検証候補は実原hashと混同しない。
	require( snapshot.exists && snapshot.contractMatches && validHash( snapshot.xml) &&
				validHash( snapshot.sddl),
			"USER_TASK_CONTRACT") ;
	require( snapshot.instances == 0U && snapshot.state == (snapshot.enabled ? 3U : 1U),
			"USER_TASK_RUNNING_OR_UNKNOWN") ;
	// 有効既定値省略では両pinを偽の実原hashとして格納しない。
	if( omitted) {
		require( snapshot.enabled && snapshot.enabledXml.empty() && snapshot.disabledXml.empty() &&
					snapshot.omittedEnabledPins.size() <= 32U,
				"USER_TASK_OMITTED_ENABLED") ;
		// 有限な候補対の全hash形式を検査する。
		for( const auto &pins : snapshot.omittedEnabledPins) {
			require( validHash( pins.first) && validHash( pins.second), "USER_TASK_OMITTED_PIN") ;
		}
	} else {
		require( validHash( snapshot.enabledXml) && validHash( snapshot.disabledXml) &&
					snapshot.xml == (snapshot.enabled ? snapshot.enabledXml : snapshot.disabledXml),
				"USER_TASK_ENABLED_XML") ;
	}
}

/** @brief 所有receiptの原byte pinを現在の実Taskへ結合します。
 * @param[in] snapshot 読戻ししたTask。
 * @param[in] owner 保護receipt。
 * @throws std::exception 改変、所有不明または実行中。
 */
void validateOwned( const CollectorUserTaskSnapshot	&snapshot,
				   const CollectorUserTaskOwnership &owner)
{
	validateSnapshot( snapshot) ;
	const bool paired =
		std::any_of( snapshot.omittedEnabledPins.begin(), snapshot.omittedEnabledPins.end(),
					// 同じ挿入位置・書式の一対が両方とも一致する場合だけ所有とする。
					[&owner]( const auto &pins) {
						return pins.first == owner.enabledXml && pins.second == owner.disabledXml ;
					}) ;
	require(
		((snapshot.enabledXml == owner.enabledXml && snapshot.disabledXml == owner.disabledXml) ||
		 paired) &&
			snapshot.sddl == owner.sddl,
		"USER_TASK_OWNERSHIP_CHANGED") ;
}

/** @brief 所有disabled取引だけを削除して正常不存在を確認します。
 * @param[in] plan 照合済み取引。
 * @param[in] snapshot 直前の照合済みdisabled状態。
 * @param[in] backend 同期操作。
 * @throws std::exception 途中改変、APIまたは不存在確認失敗。
 */
void reclaimDisabled( const CollectorUserTaskPlan &plan, const CollectorUserTaskSnapshot &snapshot,
					 const CollectorUserTaskBackend &backend)
{
	validateSnapshot( snapshot) ;
	require( !snapshot.enabled, "USER_TASK_RECOVERY_ENABLED") ;
	const auto current = backend.read( plan) ;	// 削除直前にもnonceと原pinを再確認する。
	validateOwned( current, {plan, snapshot.enabledXml, snapshot.disabledXml, snapshot.sddl}) ;
	require( !current.enabled, "USER_TASK_RECOVERY_CHANGED") ;
	exactOk( backend.remove( plan), "USER_TASK_RECOVERY_DELETE") ;
	require( !backend.read( plan).exists, "USER_TASK_RECOVERY_ABSENCE") ;
}

/** @brief Task XMLの文字列値をescapeします。
 * @param[in] input root、SIDまたはnonceの所有文字列。
 * @return XML textとして同じ文字列を表す値。
 */
std::wstring escape( const std::wstring_view input)
{
	std::wstring result ;	// XML用の有限所有出力。
	// pathのUnicodeと空白をそのまま維持し、markupだけをescapeする。
	for( const wchar_t ch : input) {
		result += ch == L'&'	? L"&amp;"
				  : ch == L'<'	? L"&lt;"
				  : ch == L'>'	? L"&gt;"
				  : ch == L'\"' ? L"&quot;"
								: std::wstring( 1U, ch) ;
	}

	return result ;
}

/** @brief Taskの明示三principal descriptorを固定します。
 * @param[in] plan 現在user SIDを含む取引。
 * @return Windowsが出力するowner/group/DACLの原SDDL。
 * @throws std::exception descriptor変換失敗。
 */
std::wstring taskSddl( const CollectorUserTaskPlan &plan)
{
	const std::wstring text = L"O:" + plan.sid + L"G:" + plan.sid + L"D:P(A;;GA;;;" + plan.sid +
							  L")(A;;GA;;;SY)(A;;GA;;;BA)" ;	// 固定三principal。
	PSECURITY_DESCRIPTOR raw{} ;								// LocalAllocのdescriptor。
	winrt::check_bool( ConvertStringSecurityDescriptorToSecurityDescriptorW(
		text.c_str(), SDDL_REVISION_1, &raw, nullptr)) ;
	const Memory descriptor( raw, &LocalFree) ;	// 変換元の所有領域。
	LPWSTR		 converted{} ;					// Windowsが生成する同じdescriptorのSDDL。
	winrt::check_bool( ConvertSecurityDescriptorToStringSecurityDescriptorW(
		descriptor.get(), SDDL_REVISION_1, 7U, &converted, nullptr)) ;
	const Memory owner( converted, &LocalFree) ;	// 原SDDLの寿命を固定する。
	return converted ;
}

/** @brief 実native --onceへ直接つながる固定XMLを作ります。
 * @param[in] plan 新user Taskの固定取引。
 * @param[in] enabled 期待するEnabled値。
 * @return Task Scheduler schema1.2の全定義。
 */
std::wstring definitionXml( const CollectorUserTaskPlan &plan, const bool enabled)
{
	const std::wstring root = escape( plan.root) ;	// XML escape後の同じroot。
	const std::wstring action =
		plan.distributionDaily
			? root + L"\\DriverCrateCollectorSetup.exe</Command><Arguments>--distribution-daily"
			: root + L"\\bin\\DriverCrateCollector.exe</Command><Arguments>--once &quot;" + root +
				  L"\\config\\targets.json&quot; &quot;" + root +
				  L"\\work\\state\\collector&quot;" ;	// 固定二契約だけです。
	return L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
		   L"<RegistrationInfo><SecurityDescriptor>" +
		   escape( taskSddl( plan)) +
		   L"</SecurityDescriptor><Description>DriverCrate collector transaction " +
		   escape( plan.nonce) + L"</Description><URI>" + escape( plan.path) +
		   L"</URI></RegistrationInfo>"
		   L"<Triggers><CalendarTrigger><StartBoundary>" +
		   plan.boundary +
		   L"</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval>"
		   L"</ScheduleByDay></CalendarTrigger></Triggers><Principals><Principal id=\"Collector\">"
		   L"<UserId>" +
		   escape( plan.sid) +
		   L"</UserId><LogonType>InteractiveToken</LogonType>"
		   L"<RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings>"
		   L"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
		   L"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
		   L"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
		   L"<AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable>"
		   L"<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
		   L"<IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle>"
		   L"</IdleSettings><AllowStartOnDemand>false</AllowStartOnDemand><Enabled>" +
		   std::wstring( enabled ? L"true" : L"false") +
		   L"</Enabled><Hidden>false</Hidden>"
		   L"<RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun>"
		   L"<ExecutionTimeLimit>PT1H10M</ExecutionTimeLimit><Priority>7</Priority></Settings>"
		   L"<Actions Context=\"Collector\"><Exec><Command>" +
		   action + L"</Arguments><WorkingDirectory>" + root +
		   L"</WorkingDirectory></Exec></Actions></Task>" ;
}

/** @brief 固定Task契約で使用する完全pathだけを受け付けます。
 * @param[in] path 検査済みTask namespace内の完全path。
 * @return 採用定義の既知要素ならtrue。
 */
bool knownXmlPath( const std::wstring_view path)
{
	constexpr auto PATHS = std::to_array<std::wstring_view>(
		{L"/Task",
		 L"/Task/RegistrationInfo",
		 L"/Task/RegistrationInfo/SecurityDescriptor",
		 L"/Task/RegistrationInfo/Description",
		 L"/Task/RegistrationInfo/URI",
		 L"/Task/Principals",
		 L"/Task/Principals/Principal",
		 L"/Task/Principals/Principal/UserId",
		 L"/Task/Principals/Principal/LogonType",
		 L"/Task/Principals/Principal/RunLevel",
		 L"/Task/Triggers",
		 L"/Task/Triggers/CalendarTrigger",
		 L"/Task/Triggers/CalendarTrigger/StartBoundary",
		 L"/Task/Triggers/CalendarTrigger/Enabled",
		 L"/Task/Triggers/CalendarTrigger/ScheduleByDay",
		 L"/Task/Triggers/CalendarTrigger/ScheduleByDay/DaysInterval",
		 L"/Task/Settings",
		 L"/Task/Settings/MultipleInstancesPolicy",
		 L"/Task/Settings/DisallowStartIfOnBatteries",
		 L"/Task/Settings/StopIfGoingOnBatteries",
		 L"/Task/Settings/AllowHardTerminate",
		 L"/Task/Settings/StartWhenAvailable",
		 L"/Task/Settings/RunOnlyIfNetworkAvailable",
		 L"/Task/Settings/IdleSettings",
		 L"/Task/Settings/IdleSettings/StopOnIdleEnd",
		 L"/Task/Settings/IdleSettings/RestartOnIdle",
		 L"/Task/Settings/AllowStartOnDemand",
		 L"/Task/Settings/Enabled",
		 L"/Task/Settings/Hidden",
		 L"/Task/Settings/RunOnlyIfIdle",
		 L"/Task/Settings/WakeToRun",
		 L"/Task/Settings/ExecutionTimeLimit",
		 L"/Task/Settings/Priority",
		 L"/Task/Actions",
		 L"/Task/Actions/Exec",
		 L"/Task/Actions/Exec/Command",
		 L"/Task/Actions/Exec/Arguments",
		 L"/Task/Actions/Exec/WorkingDirectory"}) ;	// 閉じた契約。
	return std::find( PATHS.begin(), PATHS.end(), path) != PATHS.end() ;
}

/** @brief xs:allと採用済み既定値だけを限定して比較用構造へ変換します。
 * @param[in] node DOMが所有する現在node。
 * @param[in,out] result 比較用の有限出力。
 * @param[in] depth 最大32の再帰深さ。
 * @param[in] parentPath 検査済みTask namespace内の親の完全path。
 * @throws std::exception 未知node、深さまたは容量超過。
 * @note これは初回/plan回収の契約比較だけです。所有receiptは原XML全byteをhashします。
 */
void xmlShape( const winrt::Windows::Data::Xml::Dom::IXmlNode &node, std::wstring &result,
			  const std::size_t depth, const std::wstring &parentPath)
{
	using NodeType = winrt::Windows::Data::Xml::Dom::NodeType ;	// OS DOMの型区分。
	require( depth <= 32U && result.size() <= 131072U, "USER_TASK_XML_LIMIT") ;
	// Elementの全属性と全子nodeを閉じて比較する。
	if( node.NodeType() == NodeType::ElementNode) {
		const std::wstring name( node.NodeName()) ;				// prefixの暗黙補正は行わない。
		const std::wstring path = parentPath + L"/" + name ;	// namespace検査と一体の完全path。
		require( winrt::unbox_value_or<winrt::hstring>( node.NamespaceUri(), L"") ==
						L"http://schemas.microsoft.com/windows/2004/02/mit/task" &&
					knownXmlPath( path),
				"USER_TASK_XML_ELEMENT") ;
		std::vector<std::wstring> attributes ;				// 順序に意味を持たないXML属性だけを整列する。
		const auto				  map = node.Attributes() ;	// DOMが所有する属性集合。
		// 全属性値を長さ付きで保存し、unknown属性を無視しない。
		for( std::uint32_t index = 0U; index < map.Length(); ++index) {
			const auto		   item = map.Item( index) ;			// 今回の属性node。
			const std::wstring attributeName( item.NodeName()) ;	// 採用した無prefix属性だけ。
			require(
				(path == L"/Task" && (attributeName == L"version" || attributeName == L"xmlns")) ||
					(path == L"/Task/Principals/Principal" && attributeName == L"id") ||
					(path == L"/Task/Actions" && attributeName == L"Context"),
				"USER_TASK_XML_ATTRIBUTE") ;
			const std::wstring value(
				winrt::unbox_value<winrt::hstring>( item.NodeValue())) ;	// 原値。
			attributes.push_back( attributeName + L":" + std::to_wstring( value.size()) + L":" +
								 value) ;
		}

		std::wstring element = L"<" + name ;	// 既定値省略が成立するまで呼出し元へ追加しない。
		std::sort( attributes.begin(), attributes.end()) ;
		// 全属性を同じ順に連結して値の相違を保持する。
		for( const auto &attribute : attributes) {
			element += L"|" + attribute ;
		}

		element += L">" ;
		const auto				  children = node.ChildNodes() ;	// DOMが所有する子集合。
		std::vector<std::wstring> names ;							// 省略処理より先に全子要素の重複を拒否する。
		// 既定値二重指定も、省略で隠す前に全子要素から検出する。
		for( std::uint32_t index = 0U; index < children.Length(); ++index) {
			const auto child = children.Item( index) ;	// 省略前の元node。
			// text以外の重複検査はelementだけに行い、未知nodeは再帰で拒否する。
			if( child.NodeType() == NodeType::ElementNode) {
				const std::wstring childName( child.NodeName()) ;	// この親の一意な要素名。
				require( std::find( names.begin(), names.end(), childName) == names.end(),
						"USER_TASK_XML_DUPLICATE") ;
				names.push_back( childName) ;
			}
		}

		// 省略対象Enabledも元sequence内の位置を先に確認し、順序違反を省略で隠さない。
		if( path == L"/Task/Triggers/CalendarTrigger") {
			require( names == std::vector<std::wstring>{L"StartBoundary", L"Enabled",
													   L"ScheduleByDay"} ||
						names == std::vector<std::wstring>{L"StartBoundary", L"ScheduleByDay"},
					"USER_TASK_XML_TRIGGER_SEQUENCE") ;
		}

		std::vector<std::wstring> values ;	// sequenceの位置を維持する子構造。
		// 全子nodeのnamespace・属性・重複を検査してから既定値を省略する。
		for( std::uint32_t index = 0U; index < children.Length(); ++index) {
			std::wstring value ;	// 一つの子の有限構造。
			xmlShape( children.Item( index), value, depth + 1U, path) ;
			// 空白と採用既定値を除いた子だけを比較する。
			if( !value.empty()) {
				values.push_back( std::move( value)) ;
			}
		}

		const std::wstring text( node.InnerText()) ;	// leafの完全一致だけに既定値規則を適用する。
		const bool		   defaultValue =
			(path == L"/Task/Principals/Principal/RunLevel" && text == L"LeastPrivilege") ||
			(path == L"/Task/Triggers/CalendarTrigger/Enabled" && text == L"true") ||
			(path == L"/Task/Settings/Enabled" && text == L"true") ||
			(path == L"/Task/Settings/Priority" && text == L"7") ||
			((path == L"/Task/Settings/Hidden" || path == L"/Task/Settings/RunOnlyIfIdle" ||
			  path == L"/Task/Settings/RunOnlyIfNetworkAvailable" ||
			  path == L"/Task/Settings/StartWhenAvailable" ||
			  path == L"/Task/Settings/WakeToRun") &&
			 // この九path以外は省略同値にしない。
			 text == L"false") ;
		// 検査済みの属性なしleafだけを省略と同値にする。
		if( defaultValue && attributes.empty() && names.empty()) {
			return ;
		}

		// Microsoft schemaでxs:allの既知完全pathだけを順序非依存にする。
		if( path == L"/Task" || path == L"/Task/RegistrationInfo" ||
		   path == L"/Task/Principals/Principal" || path == L"/Task/Settings" ||
		   path == L"/Task/Settings/IdleSettings" ||
		   path == L"/Task/Triggers/CalendarTrigger/ScheduleByDay") {
			std::sort( values.begin(), values.end()) ;
		}

		// sequence親では元の子順序のまま比較へ連結する。
		for( const auto &value : values) {
			element += value ;
		}

		result += element + L"</" + name + L">" ;
		return ;
	}

	require( node.NodeType() == NodeType::TextNode, "USER_TASK_XML_NODE") ;
	const std::wstring value( winrt::unbox_value<winrt::hstring>( node.NodeValue())) ;	// 原text。
	// indentationだけのtextを除き、path内空白とUnicodeは維持する。
	if( std::all_of( value.begin(), value.end(), []( const wchar_t ch) {
		   return ch == L' ' || ch == L'\r' || ch == L'\n' || ch == L'\t' ;
	   })) {
		return ;
	}

	result += std::to_wstring( value.size()) + L":" + value ;
}

/** @brief 外部entityを禁止した有限XMLの全構造を比較用にします。
 * @param[in] xml Schedulerが返した有限XML。
 * @return 全node/属性/値の構造。
 * @throws std::exception parseまたは閉形式不一致。
 */
std::wstring shape( const std::wstring_view xml)
{
	require( !xml.empty() && xml.size() <= 65536U, "USER_TASK_XML_LIMIT") ;
	winrt::Windows::Data::Xml::Dom::XmlLoadSettings settings ;	// DTD/外部entityは不許可。
	settings.ProhibitDtd( true) ;
	settings.ResolveExternals( false) ;
	winrt::Windows::Data::Xml::Dom::XmlDocument document ;	// 一読取りだけのDOM。
	document.LoadXml( winrt::hstring( xml), settings) ;
	const auto children = document.ChildNodes() ;	// root外の未知comment/PIも黙認しない。
	// 通常のXML宣言とroot以外は、空白textだけを許す。
	for( std::uint32_t index = 0U; index < children.Length(); ++index) {
		const auto child = children.Item( index) ;	// DOMが所有する文書直下node。
		// XML宣言と単一rootはparserの妥当性検査に従う。
		if( child.NodeType() == winrt::Windows::Data::Xml::Dom::NodeType::ElementNode ||
		   (child.NodeType() ==
				winrt::Windows::Data::Xml::Dom::NodeType::ProcessingInstructionNode &&
			child.NodeName() == L"xml")) {
			continue ;
		}

		std::wstring whitespace ;	// 意味のある文書直下textや未知nodeは拒否する。
		xmlShape( child, whitespace, 0U, L"") ;
		require( whitespace.empty(), "USER_TASK_XML_DOCUMENT_NODE") ;
	}

	std::wstring result ;	// 全構造を所有する。
	xmlShape( document.DocumentElement(), result, 0U, L"") ;
	return result ;
}

/** @brief 原XMLのSettings/Enabled一か所だけを切替えた両pinを作ります。
 * @param[in] xml Schedulerの原XML。
 * @param[in] enabled 実Enabled。
 * @return true/false原byteの両hash。
 * @throws std::exception 一意なSettings/Enabledでない場合。
 */
std::pair<std::wstring, std::wstring> xmlPins( const std::wstring &xml, const bool enabled)
{
	const auto		   settings = xml.find( L"<Settings>") ;			// 他のEnabledには触らない。
	const auto		   end		= xml.find( L"</Settings>", settings) ;	// Settings区間の終端。
	const std::wstring source =
		enabled ? L"<Enabled>true</Enabled>"
				: L"<Enabled>false</Enabled>" ;			// 実属性と一致する一か所だけを置換する。
	const auto position = xml.find( source, settings) ;	// 原byte内の対象位置。
	require( settings != std::wstring::npos && end != std::wstring::npos && position < end &&
				xml.find( L"<Enabled>", position + source.size()) >= end,
			"USER_TASK_XML_ENABLED") ;
	std::wstring on	 = xml ;	// Enabled以外の全byteを保持する。
	std::wstring off = xml ;	// Enabled以外の全byteを保持する。
	on.replace( position, source.size(), L"<Enabled>true</Enabled>") ;
	off.replace( position, source.size(), L"<Enabled>false</Enabled>") ;
	return {hash( winrt::to_string( on)), hash( winrt::to_string( off))} ;
}

/** @brief 検査済みSettingsの直接子行だけから省略Enabledの有限検証対を作ります。
 * @param[in] xml 全DOM契約の検査を先に通った実原XML。
 * @return 同じ一行だけを挿入したtrue/false hash対。最大32です。
 * @throws std::exception 省略でない、未知書式、容量または候補上限超過。
 * @note 挿入候補を外部へ書かず、残る全原byteをそのままhashします。
 */
std::vector<std::pair<std::wstring, std::wstring>> omittedXmlPins( const std::wstring &xml)
{
	const auto start = xml.find( L"<Settings>") ;			// DOMで検査済みの一意な親。
	const auto end	 = xml.find( L"</Settings>", start) ;	// 他のEnabledへは触れない。
	require( start != std::wstring::npos && end != std::wstring::npos &&
				xml.find( L"<Enabled", start) >= end,
			"USER_TASK_XML_OMISSION") ;
	std::vector<std::size_t> positions ;	// 既知直接子の行頭だけを候補にする。
	std::wstring			 indentation ;	// 最初の直接子から取得した限定書式。
	std::wstring			 eol ;			// CRLFまたはLFだけを許す。
	// 閉集合の直接子を一度ずつ検査し、別階層や未知nodeを候補にしない。
	for( const auto name : std::to_array<std::wstring_view>(
			{L"MultipleInstancesPolicy", L"DisallowStartIfOnBatteries", L"StopIfGoingOnBatteries",
			 L"AllowHardTerminate", L"StartWhenAvailable", L"RunOnlyIfNetworkAvailable",
			 L"IdleSettings", L"AllowStartOnDemand", L"Hidden", L"RunOnlyIfIdle", L"WakeToRun",
			 L"ExecutionTimeLimit", L"Priority"})) {
		const auto position = xml.find( L"<" + std::wstring( name) + L">", start) ;	// 対象tag。
		// OSが省略した既定値は挿入位置を提供しない。
		if( position >= end) {
			continue ;
		}

		const auto newline = xml.rfind( L'\n', position) ;	// 既存行境界。
		require( newline != std::wstring::npos && newline > start, "USER_TASK_XML_LINE") ;
		const auto		   lineStart = newline + 1U ;								// 残byteを分割する一意なoffset。
		const auto		   prefix = xml.substr( lineStart, position - lineStart) ;	// 原indentation。
		const std::wstring ending =
			newline > 0U && xml[newline - 1U] == L'\r' ? L"\r\n" : L"\n" ;	// 原EOL。
		require( !prefix.empty() && prefix.size() <= 16U &&
					std::all_of( prefix.begin(), prefix.end(),
								[]( const wchar_t ch) { return ch == L' ' || ch == L'\t' ; }),
				"USER_TASK_XML_INDENT") ;
		// 一つの既存直接子書式だけを採用し、混在や未知形式を補正しない。
		if( positions.empty()) {
			indentation = prefix ;
			eol			= ending ;
		}

		require( prefix == indentation && ending == eol, "USER_TASK_XML_LINE_FORMAT") ;
		positions.push_back( lineStart) ;
	}

	require( !positions.empty() && positions.size() <= 32U, "USER_TASK_XML_CANDIDATE_LIMIT") ;
	std::vector<std::pair<std::wstring, std::wstring>> result ;	// 最大十三個の候補対。
	// 各候補の同じslotに一行だけ挿入し、全残byteは再出力も正規化もしない。
	for( const auto position : positions) {
		std::wstring on	 = xml ;	// 実原XMLとは別の検証候補。
		std::wstring off = xml ;	// 同じslotと書式を使用する。
		on.insert( position, indentation + L"<Enabled>true</Enabled>" + eol) ;
		off.insert( position, indentation + L"<Enabled>false</Enabled>" + eol) ;
		require( on.size() <= 65536U && off.size() <= 65536U, "USER_TASK_XML_LIMIT") ;
		result.emplace_back( hash( winrt::to_string( on)), hash( winrt::to_string( off))) ;
	}

	return result ;
}

/** @brief 現在process user SIDを文字列へ固定します。
 * @return 実token userのSID。
 * @throws std::exception token照会または変換失敗。
 */
std::wstring currentSid()
{
	HANDLE raw{} ;	// tokenの所有権を受け取る。
	winrt::check_bool( OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &raw)) ;
	const Handle token( raw, &CloseHandle) ;	// tokenを一度だけ閉じる。
	DWORD		 size{} ;						// TOKEN_USERの必要容量。
	const BOOL	 queried =
		// 元結果。
		GetTokenInformation( token.get(), TokenUser, nullptr, 0U, &size) ;
	const DWORD error = GetLastError() ;	// 元の容量照会結果を保持する。
	require( queried == FALSE && error == ERROR_INSUFFICIENT_BUFFER && size > 0U && size <= 65536U,
			"USER_TASK_TOKEN_SIZE") ;
	std::vector<std::byte> bytes( size) ;	// SIDを含む所有buffer。
	winrt::check_bool( GetTokenInformation( token.get(), TokenUser, bytes.data(), size, &size)) ;
	// OSが返したTOKEN_USERの可変長bufferからSIDだけを借用する。
	PSID   sid = reinterpret_cast<const TOKEN_USER *>( bytes.data())->User.Sid ;
	LPWSTR text{} ;	// LocalAllocのSID文字列。
	winrt::check_bool( ConvertSidToStringSidW( sid, &text)) ;
	const Memory owner( text, &LocalFree) ;	// SID文字列の寿命。
	return text ;
}

/** @brief 現在local時刻をFILETIMEの比較単位で取得します。
 * @param[in] time local壁時計のSYSTEMTIME。
 * @return 100ns単位のlocal壁時計値。UTC変換は行いません。
 * @throws std::exception 不正日時。
 */
std::uint64_t wallTime( const SYSTEMTIME &time)
{
	FILETIME file{} ;	// 同じlocal壁時計を整数比較へ移す。
	winrt::check_bool( SystemTimeToFileTime( &time, &file)) ;
	return (static_cast<std::uint64_t>( file.dwHighDateTime) << 32U) | file.dwLowDateTime ;
}

/** @brief 境界文字列を契約で使うlocal15:00または17:00に限定します。
 * @param[in] text planの初回境界。
 * @return 100ns単位のlocal壁時計値。
 * @throws std::exception 日時不正。
 */
std::uint64_t boundaryTime( const std::wstring &text)
{
	require( text.size() == 19U &&
				(text.substr( 10U) == L"T15:00:00" || text.substr( 10U) == L"T17:00:00"),
			"USER_TASK_BOUNDARY") ;
	SYSTEMTIME	 time{} ;	// planで許可する日付と固定15時。
	unsigned int year{} ;	// 四桁年の一時出力。
	unsigned int month{} ;	// 二桁月の一時出力。
	unsigned int day{} ;	// 二桁日の一時出力。
	require( swscanf_s( text.c_str(), L"%4u-%2u-%2u", &year, &month, &day) == 3 && year >= 2020U &&
				year <= 9999U && month >= 1U && month <= 12U && day >= 1U && day <= 31U,
			"USER_TASK_BOUNDARY_DATE") ;
	time.wYear	= static_cast<WORD>( year) ;
	time.wMonth = static_cast<WORD>( month) ;
	time.wDay	= static_cast<WORD>( day) ;
	time.wHour	= text[12] == L'7' ? 17U : 15U ;
	return wallTime( time) ;
}

/** @brief 新規nonceと最低5分先のlocal15時を一回固定します。
 * @param[in] identity 同じuser/root/manifest。
 * @return 新しい先行plan。
 * @throws std::exception GUIDまたは日時失敗。
 */
CollectorUserTaskPlan freshPlan( const CollectorUserTaskPlan &identity)
{
	auto result = identity ;	// identityを変えず取引だけを更新する。
	GUID guid{} ;				// 推測可能なTask名と別の所有nonce。
	exactOk( CoCreateGuid( &guid), "USER_TASK_NONCE") ;
	std::array<wchar_t, 40> nonce{} ;	// GUIDの固定文字数。
	require( StringFromGUID2( guid, nonce.data(), static_cast<int>( nonce.size())) > 0,
			"USER_TASK_NONCE_TEXT") ;
	result.nonce = nonce.data() ;
	SYSTEMTIME now{} ;	// localの現在時刻。
	GetLocalTime( &now) ;
	result.boundary = collectorUserTaskFirstBoundary(
		wallTime( now) - (result.distributionDaily ? 72000000000ULL : 0ULL)) ;
	// 新Taskだけを17時へずらし、既存15時Taskの時刻を変更しません。
	if( result.distributionDaily) {
		result.boundary.replace( 11U, 2U, L"17") ;
	}

	return result ;
}

/** @brief planの全fieldを閉じたJSONへ保存します。
 * @param[in] plan 検査済み取引。
 * @return schemaを含む8fieldのobject。
 */
Json planJson( const CollectorUserTaskPlan &plan)
{
	Json json ;	// 所有する有限object。
	json.SetNamedValue( L"schema", Value::CreateStringValue(
									  plan.distributionDaily ? L"dc-collector-user-task-plan-v2"
															 : L"dc-collector-user-task-plan-v1")) ;
	json.SetNamedValue( L"packageRoot", Value::CreateStringValue( plan.root)) ;
	json.SetNamedValue( L"principalSid", Value::CreateStringValue( plan.sid)) ;
	json.SetNamedValue( L"packageManifestSha256", Value::CreateStringValue( plan.manifest)) ;
	json.SetNamedValue( L"taskPath", Value::CreateStringValue( plan.path)) ;
	json.SetNamedValue( L"transactionNonce", Value::CreateStringValue( plan.nonce)) ;
	json.SetNamedValue( L"startBoundary", Value::CreateStringValue( plan.boundary)) ;
	json.SetNamedValue( L"previousOwnershipSha256",
					   Value::CreateStringValue( plan.previousOwnership)) ;
	return json ;
}

/** @brief 未知fieldを拒否して保護planを読みます。
 * @param[in] json 保護fileのJSON。
 * @return 完全検査済み取引。
 * @throws std::exception schemaまたは値不正。
 */
CollectorUserTaskPlan parsePlan( const Json &json)
{
	const bool daily =
		// 明示新版です。
		json.GetNamedString( L"schema") == L"dc-collector-user-task-plan-v2" ;
	require( json.Size() == 8U &&
				(daily || json.GetNamedString( L"schema") == L"dc-collector-user-task-plan-v1"),
			"USER_TASK_PLAN_SCHEMA") ;
	CollectorUserTaskPlan plan{std::wstring( json.GetNamedString( L"packageRoot")),
							   std::wstring( json.GetNamedString( L"principalSid")),
							   std::wstring( json.GetNamedString( L"packageManifestSha256")),
							   std::wstring( json.GetNamedString( L"taskPath")),
							   std::wstring( json.GetNamedString( L"transactionNonce")),
							   // schemaの固定fieldだけを受理する。
							   std::wstring( json.GetNamedString( L"startBoundary")),
							   std::wstring( json.GetNamedString( L"previousOwnershipSha256")),
							   daily} ;
	validatePlan( plan) ;
	static_cast<void>( boundaryTime( plan.boundary)) ;
	return plan ;
}

/** @brief 正常なfile不存在だけをfalseにします。
 * @param[in] path 固定metadata path。
 * @return 存在すればtrue。
 * @throws std::exception 存在不明のOS失敗。
 */
bool present( const fs::path &path)
{
	const DWORD attributes = GetFileAttributesW( path.c_str()) ;	// 元属性結果。
	// 不存在以外のerrorは保存して拒否する。
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		const DWORD error = GetLastError() ;	// 元Win32 error。
		require( error == ERROR_FILE_NOT_FOUND, "USER_TASK_METADATA_ACCESS") ;
		return false ;
	}

	return true ;
}

/** @brief 旧admin receiptの混在をTask接続前に拒否します。
 * @param[in] root 現行receipt-v3の導入先。
 * @throws std::exception 旧receipt存在または存在不明。
 */
void rejectLegacyReceipts( const fs::path &root)
{
	require( !present( root / L"collector-task-Daily229.json") &&
				!present( root / L"collector-task-Smoke229.json"),
			"USER_TASK_LEGACY_RECEIPT_MIXED") ;
}

/** @brief 接続済みCOMと固定rootから実backendを構築します。
 * @param[in] root 保護root。
 * @param[in] service 呼出し期間だけ生存する同じapartmentのservice。
 * @param[in] folder root Task folder。
 * @param[in] verifyPackage 全byte再検査。
 * @param[in] daily trueなら別所有の汎用日次Taskのbackendを作ります。
 * @return 同期呼出し中だけ借用するcallback集合。
 */
CollectorUserTaskBackend realBackend( const fs::path &root, ITaskService *service,
									 ITaskFolder				 *folder,
									 const std::function<void()> &verifyPackage, const bool daily)
{
	const std::wstring		 planFile  = daily ? L"collector-distribution-task-plan.json"
											   : std::wstring( PLAN_FILE) ;	// 所有fileを分離します。
	const std::wstring		 ownerFile = daily ? L"collector-distribution-task-ownership.json"
											   : std::wstring( OWNER_FILE) ;	// 旧receiptを使いません。
	CollectorUserTaskBackend backend ;											// 入力から任意path/nameを採用しない。
	// 固定新planの保護読取りだけを行う。
	backend.loadPlan = [root, planFile]() -> std::optional<CollectorUserTaskPlan> {
		// 初回だけは正常不存在を許す。
		if( !present( root / planFile)) {
			return std::nullopt ;
		}

		return parseCollectorUserTaskPlan( readCollectorSetupProtectedMetadata( root / planFile)) ;
	} ;
	// 新schemaの全pinと埋込みplanを閉じて読む。
	backend.loadOwnership = [root, ownerFile,
							 daily]() -> std::optional<CollectorUserTaskOwnership> {
		// 未完了取引では所有receiptがまだない場合がある。
		if( !present( root / ownerFile)) {
			return std::nullopt ;
		}

		const auto json = Json::Parse(
			// 原JSON。
			winrt::to_hstring( readCollectorSetupProtectedMetadata( root / ownerFile))) ;
		require( json.Size() == 5U && json.GetNamedString( L"schema") ==
										 (daily ? L"dc-collector-user-task-ownership-v2"
												: L"dc-collector-user-task-ownership-v1"),
				"USER_TASK_OWNER_SCHEMA") ;
		CollectorUserTaskOwnership owner{
			parsePlan( json.GetNamedObject( L"plan")),
			std::wstring( json.GetNamedString( L"enabledTaskXmlSha256")),
			std::wstring( json.GetNamedString( L"disabledTaskXmlSha256")),
			// 新取引のpinだけ。
			std::wstring( json.GetNamedString( L"taskSddlSha256"))} ;
		require( validHash( owner.enabledXml) && validHash( owner.disabledXml) &&
					validHash( owner.sddl),
				"USER_TASK_OWNER_HASH") ;
		return owner ;
	} ;
	backend.freshPlan = freshPlan ;
	// atomic保存後の全byte読戻しを既存保護境界へ委譲する。
	backend.savePlan = [root, planFile]( const CollectorUserTaskPlan &plan) {
		writeCollectorSetupProtectedMetadata( root / planFile, serializeCollectorUserTaskPlan( plan),
											 present( root / planFile)) ;
	} ;
	// 登録後の原XML/SDDL pinをflush・読戻ししてからenableを許す。
	backend.saveOwnership = [root, ownerFile, daily]( const CollectorUserTaskOwnership &owner) {
		Json json ;	// 新所有schemaの固定5field。
		json.SetNamedValue(
			L"schema", Value::CreateStringValue( daily ? L"dc-collector-user-task-ownership-v2"
													  : L"dc-collector-user-task-ownership-v1")) ;
		json.SetNamedValue( L"plan", planJson( owner.plan)) ;
		json.SetNamedValue( L"enabledTaskXmlSha256", Value::CreateStringValue( owner.enabledXml)) ;
		json.SetNamedValue( L"disabledTaskXmlSha256", Value::CreateStringValue( owner.disabledXml)) ;
		json.SetNamedValue( L"taskSddlSha256", Value::CreateStringValue( owner.sddl)) ;
		writeCollectorSetupProtectedMetadata( root / ownerFile, winrt::to_string( json.Stringify()),
											 present( root / ownerFile)) ;
	} ;
	// XML全構造は初回契約用、原byte pinは所有確認用として分けて確認する。
	backend.read = [service, folder]( const CollectorUserTaskPlan &plan) {
		Microsoft::WRL::ComPtr<IRegisteredTask> task ;									// 同じapartmentの一件だけ。
		const HRESULT found = folder->GetTask( UniqueBstr( plan.path).get(), &task) ;	// 元COM結果。
		// ERROR_FILE_NOT_FOUNDだけを正常不存在とする。
		if( found == HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND)) {
			return CollectorUserTaskSnapshot{} ;
		}

		exactOk( found, "USER_TASK_GET") ;
		UniqueBstr									   xml ;		// Schedulerの原XML。
		UniqueBstr									   sddl ;		// owner/group/DACLの原SDDL。
		UniqueBstr									   path ;		// 実Task path。
		VARIANT_BOOL								   enabled{} ;	// 実Enabled。
		TASK_STATE									   state{} ;	// 実行中/queued/unknownを保持する。
		Microsoft::WRL::ComPtr<IRunningTaskCollection> instances ;	// 現在userのinstance。
		LONG										   count{} ;	// 非負の実instance数。
		exactOk( task->get_Xml( xml.put()), "USER_TASK_XML") ;
		exactOk( task->GetSecurityDescriptor( 7, sddl.put()), "USER_TASK_SDDL") ;
		exactOk( task->get_Path( path.put()), "USER_TASK_PATH") ;
		exactOk( task->get_Enabled( &enabled), "USER_TASK_ENABLED") ;
		exactOk( task->get_State( &state), "USER_TASK_STATE") ;
		exactOk( task->GetInstances( 0, &instances), "USER_TASK_INSTANCES") ;
		exactOk( instances->get_Count( &count), "USER_TASK_INSTANCE_COUNT") ;
		require( count >= 0, "USER_TASK_INSTANCE_NEGATIVE") ;
		const std::wstring rawXml( xml.get(), SysStringLen( xml.get())) ;		// 原byteをhashまで保持する。
		const std::wstring rawSddl( sddl.get(), SysStringLen( sddl.get())) ;	// 原SDDL。
		const bool		   on = enabled != VARIANT_FALSE ;						// Enabledの実値。
		Microsoft::WRL::ComPtr<ITaskDefinition> expected ;						// OS parserで正規化する期待定義。
		exactOk( service->NewTask( 0U, &expected), "USER_TASK_EXPECTED") ;
		exactOk( expected->put_XmlText( UniqueBstr( definitionXml( plan, on)).get()),
				"USER_TASK_EXPECTED_XML") ;
		UniqueBstr expectedXml ;	// OSが展開した既定値を含む期待XML。
		exactOk( expected->get_XmlText( expectedXml.put()), "USER_TASK_EXPECTED_READ") ;
		const bool matches =
			std::wstring_view( path.get(), SysStringLen( path.get())) == plan.path &&
			collectorUserTaskXmlMatches(
				rawXml, std::wstring_view( expectedXml.get(), SysStringLen( expectedXml.get()))) &&
			isCollectorUserTaskSddlAllowed( rawSddl,
										   plan.sid) ;	// 初回だけ閉じたOS rights mappingを許す。
		require( matches, "USER_TASK_CONTRACT") ;
		require( state == (on ? TASK_STATE_READY : TASK_STATE_DISABLED) && count == 0,
				"USER_TASK_RUNNING_OR_UNKNOWN") ;
		auto snapshot = collectorUserTaskXmlSnapshot(
			rawXml, std::wstring_view( expectedXml.get(), SysStringLen( expectedXml.get())),
			on) ;	// 検査後だけ候補生成。
		snapshot.state	   = static_cast<std::uint32_t>( state) ;
		snapshot.instances = static_cast<std::uint32_t>( count) ;
		snapshot.sddl	   = hash( winrt::to_string( rawSddl)) ;
		return snapshot ;
	} ;
	// 明示三ACEへのprincipal ACE自動追加を抑止し、更新もregistration実行もしない。
	backend.createDisabled = [service, folder]( const CollectorUserTaskPlan &plan) {
		Microsoft::WRL::ComPtr<ITaskDefinition> definition ;	// disabledの一件。
		exactOk( service->NewTask( 0U, &definition), "USER_TASK_NEW") ;
		exactOk( definition->put_XmlText( UniqueBstr( definitionXml( plan, false)).get()),
				"USER_TASK_DEFINITION") ;
		VARIANT			 user{} ;				// BSTRはsidOwnerのscopeで借用する。
		const UniqueBstr sidOwner( plan.sid) ;	// 現在user以外は渡さない。
		user.vt		 = VT_BSTR ;
		user.bstrVal = sidOwner.get() ;
		VARIANT			 empty{} ;						// passwordを保存しない。
		VARIANT			 descriptor{} ;					// 明示三principal SDDLを借用する。
		const UniqueBstr sddlOwner( taskSddl( plan)) ;	// Registerの間だけ生存する。
		descriptor.vt	   = VT_BSTR ;
		descriptor.bstrVal = sddlOwner.get() ;
		Microsoft::WRL::ComPtr<IRegisteredTask> created ;	// 登録の返却参照。
		return static_cast<std::int32_t>( folder->RegisterTaskDefinition(
			UniqueBstr( plan.path).get(), definition.Get(),
			TASK_CREATE | TASK_IGNORE_REGISTRATION_TRIGGERS | TASK_DONT_ADD_PRINCIPAL_ACE, user,
			empty, TASK_LOGON_INTERACTIVE_TOKEN, descriptor, &created)) ;
	} ;
	// enable/disableだけを行い、即時実行や停止を追加しない。
	backend.setEnabled = [folder]( const CollectorUserTaskPlan &plan, const bool enabled) {
		Microsoft::WRL::ComPtr<IRegisteredTask> task ;	// 変更直前の一件。
		exactOk( folder->GetTask( UniqueBstr( plan.path).get(), &task), "USER_TASK_CHANGE_GET") ;
		return static_cast<std::int32_t>( task->put_Enabled( enabled ? VARIANT_TRUE : VARIANT_FALSE)) ;
	} ;
	// 同じ導出path一件だけを削除する。
	backend.remove = [folder]( const CollectorUserTaskPlan &plan) {
		return static_cast<std::int32_t>( folder->DeleteTask( UniqueBstr( plan.path).get(), 0)) ;
	} ;
	// local壁時計で初回の最小余裕を再確認する。
	backend.future = []( const CollectorUserTaskPlan &plan) {
		SYSTEMTIME now{} ;	// 現在のlocal壁時計。
		GetLocalTime( &now) ;
		return boundaryTime( plan.boundary) >= wallTime( now) + 3000000000ULL ;
	} ;
	backend.verifyPackage = [root, verifyPackage]() {
		rejectLegacyReceipts( root) ;
		verifyPackage() ;
	} ;
	// 編集可能なconfigは登録/修復だけで検査し、解除時に修正・削除しない。
	backend.verifyConfiguration = [root, daily]() {
		// 汎用日次は別の保護同意を必須とし、metadata設定から同意を推測しません。
		if( daily) {
			const auto consent = Json::Parse( winrt::to_hstring( readCollectorSetupProtectedMetadata(
				root / L"collector-distribution-daily-consent.json"))) ;	// 固定schemaです。
			require( consent.Size() == 8U &&
						consent.GetNamedString( L"schema") ==
							L"dc-collector-distribution-daily-consent-v1" &&
						consent.GetNamedBoolean( L"inspectionDownloads") &&
						consent.GetNamedString( L"scope") ==
							L"ACTIVE_STATIC_ZIP_CAB_INF_32JOBS_64REQUESTS_32MIB_600S_24H" &&
						consent.GetNamedBoolean( L"daily"),
					"DISTRIBUTION_DAILY_CONSENT_REQUIRED") ;
			return ;
		}

		withCollectorSetupProtectedFile( root / L"config/targets.json", [&]() {
			std::vector<LocalCollectorTarget> targets ;	// native parserの既存1～32対象。
			std::wstring					  digest ;	// 設定の原hash。stateへ保存しない。
			require( loadLocalCollectorManifest( root / L"config/targets.json", targets, digest),
					"USER_TASK_CONFIG") ;
		}) ;
	} ;
	return backend ;
}

/** @brief 新user Task操作に必要なCOMだけへ接続します。
 * @param[in] root 保護root。
 * @param[in] manifest 固定元hash。
 * @param[in] verifyPackage package再検査。
 * @param[in] remove 解除ならtrue。
 * @param[in] daily trueなら別所有の汎用日次Taskを扱います。
 * @return 解除件数。登録なら0。
 * @throws std::exception 保護、混在、COMまたはpolicy失敗。
 */
std::size_t installedOperation( const fs::path &root, const std::wstring_view manifest,
							   const std::function<void()> &verifyPackage, const bool remove,
							   const bool daily)
{
	std::size_t removed{} ;	// 不存在確認後だけ更新する。
	// 全操作中rootと祖先を固定し、旧Taskサービス照会へ分岐しない。
	withCollectorSetupProtectedRoot( root, [&]() {
		rejectLegacyReceipts( root) ;
		const auto installed = Json::Parse( winrt::to_hstring( readCollectorSetupProtectedMetadata(
			root / L"install-receipt.json"))) ;	// 配置receiptも同じ三principalで固定する。
		require( installed.Size() == 3U &&
					installed.GetNamedString( L"schema") == L"dc-collector-install-receipt-v3" &&
					installed.GetNamedString( L"packageManifestSha256") == manifest,
				"USER_TASK_INSTALL_RECEIPT") ;
		// 唯一Actionの実EXEと対応する保護親を、全Task操作中write/delete共有せず保持する。
		withCollectorSetupProtectedFile(
			root / (daily ? L"DriverCrateCollectorSetup.exe" : L"bin/DriverCrateCollector.exe"),
			[&]() {
				verifyPackage() ;
				const auto identity =
					// 現在user/rootのみ。
					collectorUserTaskIdentity( root, currentSid(), manifest, daily) ;
				Microsoft::WRL::ComPtr<ITaskService> service ;	// 呼出しapartment内だけの接続。
				exactOk( CoCreateInstance( CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
										 IID_PPV_ARGS( &service)),
						"USER_TASK_SERVICE") ;
				VARIANT empty{} ;	// local現在identityの既定接続。
				exactOk( service->Connect( empty, empty, empty, empty), "USER_TASK_CONNECT") ;
				Microsoft::WRL::ComPtr<ITaskFolder> folder ;	// Scheduler rootだけを使う。
				exactOk( service->GetFolder( UniqueBstr( L"\\").get(), &folder), "USER_TASK_FOLDER") ;
				const auto backend =
					// scope内借用。
					realBackend( root, service.Get(), folder.Get(), verifyPackage, daily) ;
				// 現行配置receiptだけが呼ぶ二操作をdispatchする。
				if( remove) {
					removed = removeCollectorUserTask( identity, backend) ;
				} else {
					ensureCollectorUserTask( identity, backend) ;
				}
			},
			daily) ;
	}) ;
	return removed ;
}
} // namespace

CollectorUserTaskPlan collectorUserTaskIdentity( const fs::path &root, const std::wstring_view sid,
												const std::wstring_view manifest,
												const bool				distributionDaily)
{
	std::wstring path = root.native() ;	// 入力の同じ絶対root。
	std::replace( path.begin(), path.end(), L'/', L'\\') ;
	require( path.size() >= 4U && path.size() <= 2048U && path[1] == L':' && path[2] == L'\\' &&
				path.back() != L'\\' && path.find( L':', 2U) == std::wstring::npos &&
				path.find_first_of( L"%\"\r\n\t") == std::wstring::npos &&
				path.find( L'\0') == std::wstring::npos,
			"USER_TASK_ROOT") ;
	// DOS aliasや相対componentで別のTask名を作らせない。
	for( const auto &part : fs::path( path).relative_path()) {
		require( !part.empty() && part != L"." && part != L".." && part.native().back() != L' ' &&
					part.native().back() != L'.',
				"USER_TASK_ROOT_COMPONENT") ;
	}

	std::wstring upper( path.size(), L'\0') ;	// Unicodeのordinal大小文字を固定する。
	require( LCMapStringEx( LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE, path.data(),
						  static_cast<int>( path.size()), upper.data(),
						  static_cast<int>( upper.size()), nullptr, nullptr,
						  0U) == static_cast<int>( upper.size()),
			"USER_TASK_ROOT_CASE") ;
	PSID raw{} ;	// OSのSID parserが確保する領域。
	winrt::check_bool( ConvertStringSidToSidW( std::wstring( sid).c_str(), &raw)) ;
	const Memory owner( raw, &LocalFree) ;	// SIDの形式をOSで照合する。
	require( IsValidSid( raw) && (sid.starts_with( L"S-1-5-21-") || sid.starts_with( L"S-1-12-1-")) &&
				validHash( manifest),
			"USER_TASK_IDENTITY") ;
	const std::wstring name = L"\\DriverCrate.Collector.Daily." +
							  // manifestで名前を変えない。
							  hash( winrt::to_string( std::wstring( sid) + L"\n" + upper)) ;
	return {path,
			std::wstring( sid),
			std::wstring( manifest),
			distributionDaily ? name + L"-Distribution" : name,
			{},
			{},
			{},
			distributionDaily} ;
}

std::wstring collectorUserTaskXml( const CollectorUserTaskPlan &plan, const bool enabled)
{
	validatePlan( plan) ;
	return definitionXml( plan, enabled) ;
}

std::string serializeCollectorUserTaskPlan( const CollectorUserTaskPlan &plan)
{
	validatePlan( plan) ;
	return winrt::to_string( planJson( plan).Stringify()) ;
}

CollectorUserTaskPlan parseCollectorUserTaskPlan( const std::string_view bytes)
{
	require( !bytes.empty() && bytes.size() <= 65536U, "USER_TASK_PLAN_LIMIT") ;
	return parsePlan( Json::Parse( winrt::to_hstring( bytes))) ;
}

bool collectorUserTaskXmlMatches( const std::wstring_view actual, const std::wstring_view expected)
{
	return shape( actual) == shape( expected) ;
}

CollectorUserTaskSnapshot collectorUserTaskXmlSnapshot( const std::wstring_view actual,
													   const std::wstring_view expected,
													   const bool			   enabled)
{
	require( collectorUserTaskXmlMatches( actual, expected), "USER_TASK_CONTRACT") ;
	const std::wstring raw( actual) ;								// 全DOM契約の後だけ原byteを候補へ使う。
	const auto		   start = raw.find( L"<Settings>") ;			// 完全一致tagの限定形式。
	const auto		   end	 = raw.find( L"</Settings>", start) ;	// 一意なSettingsの終端。
	require( start != std::wstring::npos && end != std::wstring::npos, "USER_TASK_XML_SETTINGS") ;
	CollectorUserTaskSnapshot snapshot ;	// OS状態とSDDLは呼出し側が実観測を設定する。
	snapshot.exists			 = true ;
	snapshot.contractMatches = true ;
	snapshot.enabled		 = enabled ;
	snapshot.xml			 = hash( winrt::to_string( raw)) ;
	// true省略だけが候補を持ち、falseや別markupを補正しない。
	if( raw.find( L"<Enabled", start) >= end) {
		require( enabled, "USER_TASK_XML_ENABLED") ;
		snapshot.omittedEnabledPins = omittedXmlPins( raw) ;
	} else {
		const auto pins		 = xmlPins( raw, enabled) ;	// API値と明示XMLが一致する原両pin。
		snapshot.enabledXml	 = pins.first ;
		snapshot.disabledXml = pins.second ;
	}

	return snapshot ;
}

std::wstring collectorUserTaskFirstBoundary( const std::uint64_t localFileTime)
{
	const FILETIME input{static_cast<DWORD>( localFileTime),
						 // local壁時計。
						 static_cast<DWORD>( localFileTime >> 32U)} ;
	SYSTEMTIME	   now{} ;	// 日付と時刻の変換結果。
	winrt::check_bool( FileTimeToSystemTime( &input, &now)) ;
	require( now.wYear >= 2020U && now.wYear <= 9998U, "USER_TASK_FIRST_BOUNDARY_RANGE") ;
	SYSTEMTIME due		= now ;	// 今日の固定15時候補。
	due.wHour			= 15U ;
	due.wMinute			= 0U ;
	due.wSecond			= 0U ;
	due.wMilliseconds	= 0U ;
	std::uint64_t value = wallTime( due) ;	// 100ns単位のlocal壁時計。
	// 5分未満なら翌暦日の15時へ一度だけ送る。
	if( value < localFileTime + 3000000000ULL) {
		value += 864000000000ULL ;
	}

	const FILETIME file{static_cast<DWORD>( value),
						// 次回の日付。
						static_cast<DWORD>( value >> 32U)} ;
	winrt::check_bool( FileTimeToSystemTime( &file, &due)) ;
	std::array<wchar_t, 32> boundary{} ;	// 固定ISO日時の容量。
	require( swprintf_s( boundary.data(), boundary.size(), L"%04u-%02u-%02uT15:00:00", due.wYear,
					   due.wMonth, due.wDay) == 19,
			"USER_TASK_BOUNDARY_TEXT") ;
	return boundary.data() ;
}

bool isCollectorUserTaskSddlAllowed( const std::wstring_view sddl, const std::wstring_view sid)
{
	// 初回でも有限なowner/group/DACL以外を受け付けない。
	if( sddl.empty() || sddl.size() > 16384U) {
		return false ;
	}

	PSID rawUser{} ;	// 比較用の現在user SID。
	// 無効なSIDはpolicy不成立として返す。
	if( !ConvertStringSidToSidW( std::wstring( sid).c_str(), &rawUser)) {
		return false ;
	}

	const Memory		 user( rawUser, &LocalFree) ;	// SIDの単独所有。
	PSECURITY_DESCRIPTOR raw{} ;						// 原SDDLのdescriptor。
	// 不正descriptorを暗黙修正して受理しない。
	if( !ConvertStringSecurityDescriptorToSecurityDescriptorW( std::wstring( sddl).c_str(),
															 SDDL_REVISION_1, &raw, nullptr)) {
		return false ;
	}

	const Memory				descriptor( raw, &LocalFree) ;	// OS領域を全終了経路で解放する。
	PSID						owner{} ;						// descriptor内の借用owner。
	PSID						group{} ;						// descriptor内の借用group。
	PACL						acl{} ;							// descriptor内の借用DACL。
	BOOL						defaulted{} ;					// OSの既定flag。
	BOOL						presentDacl{} ;					// NULL DACLを明示拒否する。
	SECURITY_DESCRIPTOR_CONTROL control{} ;						// protected bitを検査する。
	DWORD						revision{} ;					// OSのdescriptor revision。
	// owner/groupも同じuserに限定し、service/別userを許さない。
	if( !GetSecurityDescriptorOwner( raw, &owner, &defaulted) || !owner ||
	   !GetSecurityDescriptorGroup( raw, &group, &defaulted) || !group ||
	   !EqualSid( owner, rawUser) || !EqualSid( group, rawUser) ||
	   !GetSecurityDescriptorDacl( raw, &presentDacl, &acl, &defaulted) || !presentDacl || !acl ||
	   !IsValidAcl( acl) || acl->AceCount != 3U ||
	   !GetSecurityDescriptorControl( raw, &control, &revision) ||
	   (control & SE_DACL_PROTECTED) == 0U) {
		return false ;
	}

	bool hasUser{} ;	// current userの一意なACE。
	bool hasSystem{} ;	// SYSTEMの一意なACE。
	bool hasAdmin{} ;	// Administratorsの一意なACE。
	// 三ACEだけを検査し、Denyや未知形式でfull rightsを補正しない。
	for( DWORD index = 0U; index < 3U; ++index) {
		void *rawAce{} ;	// ACLが所有する可変長ACE。
		// 不明ACEを安全な許可へ変換しない。
		if( !GetAce( acl, index, &rawAce)) {
			return false ;
		}

		const auto *ace = static_cast<const ACCESS_ALLOWED_ACE *>( rawAce) ;	// Win32 ABI境界。
		// Task SchedulerがGAをfile/task full accessへmappingする二表現だけを許す。
		if( ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags != 0U ||
		   ace->Header.AceSize < sizeof( ACCESS_ALLOWED_ACE) ||
		   (ace->Mask != GENERIC_ALL && ace->Mask != FILE_ALL_ACCESS)) {
			return false ;
		}

		PSID principal = const_cast<DWORD *>( &ace->SidStart) ;	// API可変長SIDを借用する。
		// SIDの未検証参照や余分なprincipalを拒否する。
		if( !IsValidSid( principal)) {
			return false ;
		}

		const bool isUser	= EqualSid( principal, rawUser) != FALSE ;					// current user一致。
		const bool isSystem = IsWellKnownSid( principal, WinLocalSystemSid) != FALSE ;	// SYSTEM一致。
		const bool isAdmin =
			// 管理者一致。
			IsWellKnownSid( principal, WinBuiltinAdministratorsSid) != FALSE ;
		// 重複ACEも余分なprincipalも閉じた三集合には含めない。
		if( (isUser && hasUser) || (isSystem && hasSystem) || (isAdmin && hasAdmin) ||
		   (!isUser && !isSystem && !isAdmin)) {
			return false ;
		}

		hasUser |= isUser ;
		hasSystem |= isSystem ;
		hasAdmin |= isAdmin ;
	}

	return hasUser && hasSystem && hasAdmin ;
}

void ensureCollectorUserTask( const CollectorUserTaskPlan	&identity,
							 const CollectorUserTaskBackend &backend)
{
	backend.verifyPackage() ;
	backend.verifyConfiguration() ;
	auto	   plan		 = backend.loadPlan() ;			// 先行取引がある場合だけ未完了回収を許す。
	auto	   owner	 = backend.loadOwnership() ;	// 初回は正常不存在。
	const bool priorPlan = plan.has_value() ;			// 同じ呼出しで新規保存したplanとの区別。
	bool	   pendingReplacement{} ;					// 新plan保存後・新receipt保存前の途中取引。
	// 所有receiptだけの不整合はadoptせず保持する。
	require( !owner || plan.has_value(), "USER_TASK_ORPHAN_RECEIPT") ;
	// 保存済みplanは現在のroot/SID/manifest/導出名へ厳密に結合する。
	if( plan) {
		validatePlan( *plan) ;
		require( sameIdentity( *plan, identity), "USER_TASK_PLAN_BINDING") ;
		// 新planと旧receiptの途中状態は、先行保存した全field hashの一致だけを許す。
		if( owner) {
			validatePlan( owner->plan) ;
			require( sameIdentity( owner->plan, identity) && validHash( owner->enabledXml) &&
						validHash( owner->disabledXml) && validHash( owner->sddl),
					"USER_TASK_RECEIPT_IDENTITY") ;
			pendingReplacement = !samePlan( *plan, owner->plan) ;
			require( !pendingReplacement ||
						(plan->nonce != owner->plan.nonce &&
						 plan->previousOwnership == ownershipFingerprint( *owner)),
					"USER_TASK_RECEIPT_BINDING") ;
		}
	} else {
		plan = backend.freshPlan( identity) ;
		validatePlan( *plan) ;
		require( sameIdentity( *plan, identity), "USER_TASK_FRESH_BINDING") ;
		backend.savePlan( *plan) ;
	}

	const auto previousOwner = owner ;	// 旧receiptを破棄せず新planへ結合する。
	// 旧receiptを新Taskへ転用せず、plan nonceに一致するdisabled契約だけを回収する。
	if( pendingReplacement) {
		owner.reset() ;
	}

	auto snapshot = backend.read( *plan) ;	// 最初のTask照会も先行plan保存後。
	// 同一版の有効Taskだけを冪等成功とする。
	if( snapshot.exists && owner) {
		validateOwned( snapshot, *owner) ;
		// 既に有効なら設定やstateを一切copyしない。
		if( snapshot.enabled) {
			return ;
		}
	}

	// receipt未保存の回収は既存planと完全契約のdisabled Taskだけに限定する。
	if( snapshot.exists && !owner) {
		require( priorPlan, "USER_TASK_NAME_COLLISION") ;
		reclaimDisabled( *plan, snapshot, backend) ;
		snapshot = {} ;
	}

	// 古いdisabled取引はcatch-upを許さず一回だけ回収する。
	if( snapshot.exists && !backend.future( *plan)) {
		reclaimDisabled( *plan, snapshot, backend) ;
		snapshot = {} ;
	}

	// 欠損または回収済みだけに新しい未来取引を一回作る。
	if( !snapshot.exists) {
		// 初回は既に作ったnonceを維持し、保存済み取引だけを更新する。
		if( priorPlan && (!pendingReplacement || !backend.future( *plan))) {
			plan					= backend.freshPlan( identity) ;
			plan->previousOwnership = previousOwner ? ownershipFingerprint( *previousOwner) : L"" ;
			require( !previousOwner || plan->nonce != previousOwner->plan.nonce,
					"USER_TASK_REPAIR_NONCE_REUSE") ;
			validatePlan( *plan) ;
			require( sameIdentity( *plan, identity), "USER_TASK_REPAIR_BINDING") ;
			backend.savePlan( *plan) ;
		}

		require( backend.future( *plan), "USER_TASK_CREATE_FUTURE") ;
		require( !backend.read( *plan).exists, "USER_TASK_CREATE_COLLISION") ;
		exactOk( backend.createDisabled( *plan), "USER_TASK_REGISTER") ;
		snapshot = backend.read( *plan) ;
		validateSnapshot( snapshot) ;
		require( !snapshot.enabled, "USER_TASK_CREATED_ENABLED") ;
		const CollectorUserTaskOwnership created{
			*plan, snapshot.enabledXml, snapshot.disabledXml,
			snapshot.sddl} ;	// 読戻した原pinだけを所有証明にする。
		try {
			backend.saveOwnership( created) ;
			const auto readback = backend.loadOwnership() ;	// 保存後もschema/ACL/全pinを読む。
			require( readback && samePlan( readback->plan, *plan) &&
						readback->enabledXml == created.enabledXml &&
						readback->disabledXml == created.disabledXml &&
						readback->sddl == created.sddl,
					"USER_TASK_RECEIPT_READBACK") ;
		} catch( ...) {
			const auto original = std::current_exception() ;	// 元の保存失敗を保持する。
			try {
				reclaimDisabled( *plan, snapshot, backend) ;
			} catch( const std::exception &error) {
				std::printf( "SETUP_USER_TASK_RECOVERY stage=%s state=UNKNOWN retained=1\n",
							error.what()) ;
			} catch( const winrt::hresult_error &error) {
				std::printf( "SETUP_USER_TASK_RECOVERY hresult=%08x state=UNKNOWN retained=1\n",
							static_cast<unsigned int>( error.code().value)) ;
			} catch( ...) {
				std::printf( "SETUP_USER_TASK_RECOVERY stage=exception state=UNKNOWN retained=1\n") ;
			}

			std::rethrow_exception( original) ;
		}

		owner = created ;
	}

	require( owner.has_value(), "USER_TASK_ENABLE_OWNERSHIP") ;
	backend.verifyPackage() ;
	backend.verifyConfiguration() ;
	validateOwned( backend.read( *plan), *owner) ;
	require( backend.future( *plan), "USER_TASK_ENABLE_FUTURE") ;
	exactOk( backend.setEnabled( *plan, true), "USER_TASK_ENABLE") ;
	const auto enabled = backend.read( *plan) ;	// S_OKだけで成功にしない。
	validateOwned( enabled, *owner) ;
	require( enabled.enabled, "USER_TASK_ENABLE_READBACK") ;
}

std::size_t removeCollectorUserTask( const CollectorUserTaskPlan	   &identity,
									const CollectorUserTaskBackend &backend)
{
	backend.verifyPackage() ;
	const auto plan	 = backend.loadPlan() ;			// 新user取引だけを読む。
	const auto owner = backend.loadOwnership() ;	// 新schemaだけの所有pin。
	// 未opt-inまたはplan保存前の失敗では、固定名の正常不存在だけを確認します。
	if( !plan) {
		require( !owner, "USER_TASK_UNINSTALL_ORPHAN_OWNER") ;
		require( !backend.read( identity).exists, "USER_TASK_UNINSTALL_UNOWNED_TASK") ;
		return 0U ;
	}

	require( sameIdentity( *plan, identity), "USER_TASK_UNINSTALL_OWNERSHIP") ;
	validatePlan( *plan) ;
	// 初回の未確定取引だけは、保護planの全契約からdisabled回収を認める。
	if( !owner) {
		require( plan->previousOwnership.empty(), "USER_TASK_UNINSTALL_PREDECESSOR_MISSING") ;
		const auto pending = backend.read( *plan) ;	// API拒否や不明を不存在へ変換しない。
		// 正常不存在なら所有receiptを後付けせず、呼出し元のfile解除へ進む。
		if( !pending.exists) {
			return 0U ;
		}

		validateSnapshot( pending) ;
		require( !pending.enabled, "USER_TASK_UNINSTALL_PENDING_ENABLED") ;
		backend.verifyPackage() ;
		reclaimDisabled( *plan, pending, backend) ;
		return 1U ;
	}

	require( samePlan( *plan, owner->plan), "USER_TASK_UNINSTALL_OWNERSHIP") ;
	auto snapshot = backend.read( *plan) ;	// Task不存在もAPIで正常確認する。
	// 前回のdelete後失敗は同じreceiptから再開できる。
	if( !snapshot.exists) {
		return 0U ;
	}

	validateOwned( snapshot, *owner) ;
	backend.verifyPackage() ;
	snapshot = backend.read( *plan) ;
	validateOwned( snapshot, *owner) ;
	// 実行中を強制停止せず、次回の自然実行だけを抑止する。
	if( snapshot.enabled) {
		exactOk( backend.setEnabled( *plan, false), "USER_TASK_DISABLE") ;
	}

	const auto disabled = backend.read( *plan) ;	// 無効化後にも全pinと非実行を確認する。
	validateOwned( disabled, *owner) ;
	require( !disabled.enabled, "USER_TASK_DISABLE_READBACK") ;
	exactOk( backend.remove( *plan), "USER_TASK_DELETE") ;
	require( !backend.read( *plan).exists, "USER_TASK_DELETE_ABSENCE") ;
	return 1U ;
}

void ensureInstalledCollectorUserTask( const fs::path &root, const std::wstring_view manifest,
									  const std::function<void()> &verifyPackage,
									  const bool				   distributionDaily)
{
	static_cast<void>( installedOperation( root, manifest, verifyPackage, false, distributionDaily)) ;
	std::printf( "SETUP_USER_TASK_COMPLETE registered=1 enabled=1 run=0 network=0\n") ;
}

std::size_t removeInstalledCollectorUserTask( const fs::path &root, const std::wstring_view manifest,
											 const std::function<void()> &verifyPackage,
											 const bool					  distributionDaily)
{
	return installedOperation( root, manifest, verifyPackage, true, distributionDaily) ;
}
} // namespace drivercrate
