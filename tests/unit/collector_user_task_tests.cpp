//------------------------------------------------------------------------------
/**
 * @file collector_user_task_tests.cpp
 * @brief 新user Taskの登録・失敗保持・修復・解除をfakeだけで検査します。
 * @version 01.01.02
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23 U01-U32の有限fake集合を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/23 登録XML差と初回pending解除のU33-U36を追加。
 * Ver.01.00.02 Shunji Ogawa  2026/10/23 有効既定値省略と両pin所有回帰U37-U40を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/23 別日次の所有・17時・共存・解除readbackを追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/24 未登録の正常不存在と未所有/孤立/不明拒否を追加。
 * Ver.01.01.02 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * </pre>
 *
 * @note 実Task、HTTP、driver、復元、運用stateに触れません。fake状態はmemoryだけです。
 * @see docs/adr/0394-collector-user-task-install-lifecycle.md
 */
//------------------------------------------------------------------------------
#include <memory>
#include "platform/collector_user_task.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/base.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using namespace drivercrate ;
// 架空user SIDだけを使用し、実tokenを照会しない。
constexpr std::wstring_view FAKE_SID = L"S-1-5-21-111-222-333-1001" ;

/** @brief 不一致をテスト失敗へ変換します。
 * @param[in] condition 期待条件。
 * @param[in] reason 入力情報を含まない固定理由。
 * @throws std::runtime_error 不一致。
 */
void						check( const bool condition, const char *reason)
{
	// 最初の不一致を実行caseへ返す。
	if( !condition) {
		throw std::runtime_error( reason) ;
	}
}

/** @brief local壁時計の初回境界をOS変換だけで検査します。
 * @param[in] year 入力年。
 * @param[in] month 入力月。
 * @param[in] day 入力日。
 * @param[in] hour 入力時。
 * @param[in] minute 入力分。
 * @param[in] second 入力秒。
 * @param[in] milliseconds 入力ミリ秒。
 * @param[in] expected 固定した次回15時。
 * @throws std::exception 変換または期待不一致。
 */
void checkBoundary( const WORD year, const WORD month, const WORD day, const WORD hour,
				   const WORD minute, const WORD second, const WORD milliseconds,
				   const std::wstring_view expected)
{
	const SYSTEMTIME input{year, month,	 0U,	 day,
						   hour, minute, second, milliseconds} ;	// 架空local日時。
	FILETIME		 value{} ;										// 100ns単位へのOS変換だけを使う。
	winrt::check_bool( SystemTimeToFileTime( &input, &value)) ;
	const std::uint64_t local = (static_cast<std::uint64_t>( value.dwHighDateTime) << 32U) |
								value.dwLowDateTime ;	// Taskや実clockを使わない固定値。
	check( collectorUserTaskFirstBoundary( local) == expected, "five-minute-boundary") ;
}

/** @brief 一つのfake取引と失敗注入を所有します。 */
struct Fake {
	/// 対象root/SID/manifestの固定identity。
	CollectorUserTaskPlan identity =
		collectorUserTaskIdentity( L"D:\\fixture\\収集 A & B", FAKE_SID, std::wstring( 64U, L'a')) ;
	/// 保存済みplan。
	std::optional<CollectorUserTaskPlan>	  plan ;
	/// 保存済み所有receipt。
	std::optional<CollectorUserTaskOwnership> owner ;
	/// 実Taskに代わるmemory snapshot。
	CollectorUserTaskSnapshot				  task ;
	/// Task Descriptionの実nonceを表すmemory値。
	std::wstring							  taskNonce ;
	/// 同じ呼出し期間だけFakeを借用する操作。
	CollectorUserTaskBackend				  backend ;
	/// 元の順序を保持するイベント。
	std::vector<std::string>				  events ;
	/// 作成APIの元HRESULT。
	std::int32_t							  createResult{} ;
	/// enable/disableの元HRESULT。
	std::int32_t							  changeResult{} ;
	/// 削除APIの元HRESULT。
	std::int32_t							  deleteResult{} ;
	/// 初回境界の最小余裕。
	bool									  future = true ;
	/// native入力検査拒否。
	bool									  badConfig{} ;
	/// plan保存失敗。
	bool									  failPlan{} ;
	/// receipt保存/flush失敗。
	bool									  failOwner{} ;
	/// receipt保存後の読戻し不明。
	bool									  ownerReadbackFailure{} ;
	/// 作成後のTask読戻し不明。
	bool									  postCreateReadFailure{} ;
	/// enable後のpin改変。
	bool									  corruptEnabledPin{} ;
	/// API成功でもEnabledが変わらない状態。
	bool									  ignoreChange{} ;
	/// delete後も存在する状態。
	bool									  ignoreDelete{} ;
	/// 次のreadを不明にする。
	bool									  failRead{} ;
	/// 全操作の新Task読取り数。
	std::size_t								  reads{} ;
	/// 作成回数。
	std::size_t								  creates{} ;
	/// enable/disable回数。
	std::size_t								  changes{} ;
	/// 削除回数。
	std::size_t								  deletes{} ;
	/// 新規取引生成回数。
	std::size_t								  transactions{} ;
	/// programはpolicyから削除できないことを表すsentinel。
	std::string								  program = "program-bytes" ;
	/// 修復で保持する既存config。
	std::string								  config = "config-original" ;
	/// 修復で保持する待機履歴。
	std::string								  state = "cooldown-original" ;

	/** @brief memoryだけのfake操作を構築します。 */
	Fake()
	{
		// 各callbackはこのFakeの生存中だけ同期で呼ぶ。
		backend.loadPlan = [this]() {
			events.emplace_back( "load-plan") ;
			return plan ;
		} ;
		backend.loadOwnership = [this]() {
			check( !ownerReadbackFailure || !owner, "owner-readback") ;
			events.emplace_back( "load-owner") ;
			return owner ;
		} ;
		backend.freshPlan = [this]( const CollectorUserTaskPlan &source) {
			auto result = source ;	// 取引部分以外は変えない。
			++transactions ;
			std::array<wchar_t, 40> nonce{} ;	// 取引ごとに異なる架空GUID。
			check( swprintf_s( nonce.data(), nonce.size(), L"{11111111-2222-3333-4444-%012zu}",
							 transactions) == 38,
				  "fake-guid") ;
			result.nonce = nonce.data() ;
			result.boundary =
				result.distributionDaily ? L"2050-10-24T17:00:00" : L"2050-10-24T15:00:00" ;
			future = true ;
			events.emplace_back( "fresh") ;
			return result ;
		} ;
		backend.savePlan = [this]( const CollectorUserTaskPlan &value) {
			check( !failPlan, "plan-save") ;
			plan = parseCollectorUserTaskPlan( serializeCollectorUserTaskPlan( value)) ;
			events.emplace_back( "plan-flushed") ;
		} ;
		backend.saveOwnership = [this]( const CollectorUserTaskOwnership &value) {
			check( !failOwner, "owner-flush") ;
			owner = value ;
			events.emplace_back( "owner-flushed") ;
		} ;
		backend.read = [this]( const CollectorUserTaskPlan &value) {
			check( value.path == identity.path, "unexpected-task-name") ;
			++reads ;
			check( !failRead && !(postCreateReadFailure && creates > 0U), "read-unknown") ;
			events.emplace_back( "read") ;
			auto snapshot			 = task ;	// Task側nonceを今回のplanへ照合する。
			snapshot.contractMatches = snapshot.contractMatches && taskNonce == value.nonce ;
			return snapshot ;
		} ;
		backend.createDisabled = [this]( const CollectorUserTaskPlan &value) {
			check( plan && plan->nonce == value.nonce && !task.exists, "plan-before-create") ;
			++creates ;
			taskNonce = value.nonce ;
			task	  = {true,
						 true,
						 false,
						 1U,
						 0U,
						 std::wstring( 64U, L'd'),
						 std::wstring( 64U, L'e'),
						 std::wstring( 64U, L'd'),
						 std::wstring( 64U, L'f')} ;
			events.emplace_back( "create-disabled") ;
			return createResult ;
		} ;
		backend.setEnabled = [this]( const CollectorUserTaskPlan &, const bool enabled) {
			check( owner.has_value(), "owner-before-enable") ;
			++changes ;
			events.emplace_back( enabled ? "enable" : "disable") ;
			// 注入された失敗では元状態を保持する。
			if( changeResult == 0 && !ignoreChange) {
				task.enabled = enabled ;
				task.state	 = enabled ? 3U : 1U ;
				task.xml	 = enabled ? task.enabledXml : task.disabledXml ;
				// enable後の原pin変更を再読戻しで検出する。
				if( enabled && corruptEnabledPin) {
					task.sddl = std::wstring( 64U, L'b') ;
				}
			}

			return changeResult ;
		} ;
		backend.remove = [this]( const CollectorUserTaskPlan &) {
			check( task.exists && !task.enabled, "delete-before-disable") ;
			++deletes ;
			events.emplace_back( "delete") ;
			// 不存在確認に失敗する状態も独立に注入する。
			if( deleteResult == 0 && !ignoreDelete) {
				task = {} ;
			}

			return deleteResult ;
		} ;
		backend.future		  = [this]( const CollectorUserTaskPlan &) { return future ; } ;
		backend.verifyPackage = [this]() { events.emplace_back( "verify") ; } ;
		// 登録時だけ既存native入力検査の失敗を注入する。
		backend.verifyConfiguration = [this]() { check( !badConfig, "config-rejected") ; } ;
	}

	/** @brief 通常登録をmemoryだけで完了します。 */
	void install()
	{
		ensureCollectorUserTask( identity, backend) ;
	}

	/** @brief 通常解除をmemoryだけで完了します。
     * @return 今回の削除数。
     */
	std::size_t uninstall()
	{
		return removeCollectorUserTask( identity, backend) ;
	}

	/** @brief 部分取引のdisabled状態を作ります。 */
	void disabledTransaction()
	{
		install() ;
		static_cast<void>( backend.setEnabled( *plan, false)) ;
		creates = changes = deletes = reads = 0U ;
		events.clear() ;
	}
} ;

/** @brief 非成功とprogram/config/stateの保持を要求します。
 * @param[in,out] fake 確認するmemory状態。
 * @param[in] operation 同期借用操作。
 * @throws std::runtime_error 拒否しないか保持違反。
 */
void rejects( Fake &fake, const std::function<void()> &operation)
{
	bool rejected{} ;	// 元失敗を合格へ換算しないための観測値。
	try {
		operation() ;
	} catch( const std::exception &) {
		rejected = true ;
	} catch( const winrt::hresult_error &) {
		rejected = true ;
	}

	check( rejected, "expected-rejection") ;
	check( fake.program == "program-bytes" && fake.config == "config-original" &&
			  fake.state == "cooldown-original",
		  "data-preservation") ;
}

/** @brief XML比較の不一致または閉形式拒否を要求します。
 * @param[in] actual 一変異の架空XML。
 * @param[in] expected 独立した固定契約。
 * @throws std::runtime_error 拒否されない場合。
 */
void checkXmlRejected( const std::wstring &actual, const std::wstring &expected)
{
	bool rejected{} ;	// falseと不正XMLのexceptionを同じ拒否結果として数える。
	try {
		rejected = !collectorUserTaskXmlMatches( actual, expected) ;
	} catch( const std::exception &) {
		rejected = true ;
	} catch( const winrt::hresult_error &) {
		rejected = true ;
	}

	check( rejected, "xml-contract-rejection") ;
}

/** @brief 一意なfixture文字列だけを置換します。
 * @param[in,out] xml 所有する架空XML。
 * @param[in] before 一か所だけ存在する原文。
 * @param[in] after 置換先。
 * @throws std::runtime_error fixtureの対象不一致。
 */
void replaceXml( std::wstring &xml, const std::wstring &before, const std::wstring &after)
{
	const auto position = xml.find( before) ;	// 元fixture内の一意な対象。
	check( position != std::wstring::npos &&
			  xml.find( before, position + before.size()) == std::wstring::npos,
		  "fixture-unique-replacement") ;
	xml.replace( position, before.size(), after) ;
}

/** @brief 属性なし要素の完全なfixture断片を借用せず返します。
 * @param[in] xml 架空XML。
 * @param[in] name 一意な要素名。
 * @return 開始・終了tagを含む所有文字列。
 * @throws std::runtime_error 対象がない場合。
 */
std::wstring xmlElement( const std::wstring &xml, const std::wstring &name)
{
	const auto start = xml.find( L"<" + name + L">") ;			// 属性なし要素だけのfixture helper。
	const auto end	 = xml.find( L"</" + name + L">", start) ;	// 同じ一意要素の終端。
	check( start != std::wstring::npos && end != std::wstring::npos, "fixture-element") ;
	return xml.substr( start, end + name.size() + 3U - start) ;
}

/** @brief 保存済み登録XMLの省略・順序差を架空identityで再現します。
 * @param[in] expected 架空planから作った固定定義。
 * @return 登録後に観測した同じ構造の匿名fixture。
 * @throws std::runtime_error fixtureの構築不一致。
 * @note 実root、SID、nonceやTask APIは使用しません。
 */
std::wstring registeredXmlFixture( const std::wstring &expected)
{
	std::wstring xml = expected ;	// 値を固定の実端末情報から複写しない。
	// 観測された八既定値の省略だけを独立に再現する。
	for( const auto value : std::array<std::wstring_view, 8>{
			L"<RunLevel>LeastPrivilege</RunLevel>", L"<Hidden>false</Hidden>",
			L"<Priority>7</Priority>", L"<RunOnlyIfIdle>false</RunOnlyIfIdle>",
			L"<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>",
			L"<StartWhenAvailable>false</StartWhenAvailable>", L"<WakeToRun>false</WakeToRun>",
			L"<Enabled>true</Enabled>"}) {
		replaceXml( xml, std::wstring( value), L"") ;
	}

	const auto	 settings  = xmlElement( xml, L"Settings") ;	// 登録後の実順序を独立に指定する。
	std::wstring reordered = L"<Settings>" ;					// sequenceでないSettingsだけを組み替える。
	// 実登録で残った八要素の順序を再現する。
	for( const auto name : std::array<std::wstring_view, 8>{
			L"AllowHardTerminate", L"AllowStartOnDemand", L"DisallowStartIfOnBatteries",
			L"StopIfGoingOnBatteries", L"Enabled", L"ExecutionTimeLimit",
			L"MultipleInstancesPolicy", L"IdleSettings"}) {
		reordered += xmlElement( settings, std::wstring( name)) ;
	}

	replaceXml( xml, settings, reordered + L"</Settings>") ;
	const auto triggers = xmlElement( xml, L"Triggers") ;	// Task直下のxs:all順序差。
	replaceXml( xml, triggers, L"") ;
	replaceXml( xml, L"</Settings>", L"</Settings>" + triggers) ;
	return xml ;
}

/** @brief 匿名の実登録順序へSettings直接子行のCRLF書式を付けます。
 * @param[in] plan 架空の固定取引。
 * @return 明示false行を持つdisabled原XMLの匿名版。
 * @throws std::exception fixture構築不一致。
 */
std::wstring disabledLineFixture( const CollectorUserTaskPlan &plan)
{
	auto	   xml = registeredXmlFixture( collectorUserTaskXml( plan, false)) ;	// 値は架空planだけ。
	const auto settings = xmlElement( xml, L"Settings") ;							// 観測済み順序を独立に固定する。
	std::wstring lines	= L"<Settings>\r\n" ;										// OSが返した直接子の書式。
	// 各既知直接子を原内容のまま一行へ置く。
	for( const auto name : std::array<std::wstring_view, 8>{
			L"AllowHardTerminate", L"AllowStartOnDemand", L"DisallowStartIfOnBatteries",
			L"StopIfGoingOnBatteries", L"Enabled", L"ExecutionTimeLimit",
			L"MultipleInstancesPolicy", L"IdleSettings"}) {
		lines += L"    " + xmlElement( settings, std::wstring( name)) + L"\r\n" ;
	}

	replaceXml( xml, settings, lines + L"  </Settings>") ;
	return L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" + xml ;
}

/** @brief 検証候補と独立に共通hash APIで原byteの期待hashを作ります。
 * @param[in] text 架空XML原文。
 * @return UTF-8全byteのSHA-256。
 * @throws std::exception hash失敗。
 */
std::wstring fixtureHash( const std::wstring &text)
{
	std::wstring result ;	// 実原文を直接hashし、候補生成の出力を期待値にしない。
	check( computeBytesSha256( winrt::to_string( text), result) == 0U, "fixture-hash") ;
	return result ;
}

/** @brief 実原XML helperの結果へ架空OS状態だけを結合します。
 * @param[in] xml 匿名の原XML。
 * @param[in] plan 架空取引。
 * @param[in] enabled 架空API値。
 * @return 実hash処理を通ったmemory snapshot。
 * @throws std::exception XML契約またはpin拒否。
 */
CollectorUserTaskSnapshot lineSnapshot( const std::wstring &xml, const CollectorUserTaskPlan &plan,
									   const bool enabled)
{
	auto result	 = collectorUserTaskXmlSnapshot( xml, collectorUserTaskXml( plan, enabled),
												enabled) ;	// 製品helper。
	result.state = enabled ? 3U : 1U ;
	result.sddl	 = std::wstring( 64U, L'f') ;
	return result ;
}

/** @brief 固定U番号一件の正常・失敗境界を検査します。
 * @param[in] number 1～40のcase番号。
 * @throws std::exception 期待不一致。
 */
void runCase( const std::size_t number)
{
	const auto fakeOwner = std::make_unique<Fake>() ;	// 大きなfixtureを元scopeだけで所有します。
	auto	  &fake		 = *fakeOwner ;					// 各caseで独立したmemory状態。
	// 事前固定したU01-U40を一度ずつ実行する。
	switch( number) {
		// disabled→所有保存→enabled→読戻しの順序。
		case 1U: {
			fake.install() ;
			check( fake.task.enabled && fake.creates == 1U && fake.changes == 1U, "normal-enabled") ;
			const auto flushed =
				// 保存位置。
				std::find( fake.events.begin(), fake.events.end(), "owner-flushed") ;
			const auto enable =
				// 有効化位置。
				std::find( fake.events.begin(), fake.events.end(), "enable") ;
			check( flushed < enable && enable < fake.events.end() - 1, "readback-order") ;
			break ;
		}
		// pathの大小文字、Unicode、空白、SID/rootの名前結合。
		case 2U: {
			const auto same	 = collectorUserTaskIdentity( L"d:\\FIXTURE\\収集 a & b", FAKE_SID,
														 fake.identity.manifest) ;	// 同じroot。
			const auto other = collectorUserTaskIdentity( L"D:\\fixture\\other", FAKE_SID,
														 fake.identity.manifest) ;	// 別root。
			check( same.path == fake.identity.path && other.path != same.path, "derived-name") ;
			fake.install() ;
			const auto xml = collectorUserTaskXml( *fake.plan, false) ;	// 固定Actionの非通信出力。
			check( xml.find( L"\\bin\\DriverCrateCollector.exe") != std::wstring::npos &&
					  xml.find( L"--once &quot;") != std::wstring::npos &&
					  xml.find( L"\\config\\targets.json&quot; &quot;") != std::wstring::npos &&
					  xml.find( L"\\work\\state\\collector&quot;") != std::wstring::npos &&
					  xml.find( L"<WorkingDirectory>" + fake.plan->root.substr( 0U, 10U)) !=
						  std::wstring::npos &&
					  xml.find( L"&amp;") != std::wstring::npos,
				  "native-action") ;
			bool invalid{} ;	// Schedulerの環境変数展開を拒否する。
			try {
				static_cast<void>( collectorUserTaskIdentity( L"D:\\fixture\\%TEMP%", FAKE_SID,
															fake.identity.manifest)) ;
			} catch( const std::exception &) {
				invalid = true ;
			}

			check( invalid, "environment-path") ;
			// well-known service主体は現在user Taskのidentityに使わない。
			for( const auto sid :
				std::array<std::wstring_view, 3>{L"S-1-5-18", L"S-1-5-19", L"S-1-5-20"}) {
				bool rejected{} ;	// SID形式が正しくてもservice主体は拒否する。
				try {
					static_cast<void>(
						collectorUserTaskIdentity( fake.identity.root, sid, fake.identity.manifest)) ;
				} catch( const std::exception &) {
					rejected = true ;
				}

				check( rejected, "service-principal-rejected") ;
			}

			break ;
		}
		// 未来15時、唯一daily、全実行設定。
		case 3U: {
			fake.install() ;
			const auto xml = collectorUserTaskXml( *fake.plan, false) ;	// nativeへ渡す同じXML。
			const std::array<std::wstring_view, 12> required{
				L"T15:00:00",
				L"<DaysInterval>1</DaysInterval>",
				L"<MultipleInstancesPolicy>IgnoreNew",
				L"<StartWhenAvailable>false",
				L"<RunOnlyIfIdle>false",
				L"<WakeToRun>false",
				L"<DisallowStartIfOnBatteries>false",
				L"<StopIfGoingOnBatteries>false",
				L"<ExecutionTimeLimit>PT1H10M",
				L"<AllowHardTerminate>false",
				L"<LogonType>InteractiveToken",
				L"<RunLevel>LeastPrivilege"} ;	// 採用契約の固定集合。
			// 全固定設定を一度ずつ確認する。
			for( const auto value : required) {
				check( xml.find( value) != std::wstring::npos, "daily-contract") ;
			}

			check( xml.find( L"LogonTrigger") == std::wstring::npos &&
					  xml.find( L"RegistrationTrigger") == std::wstring::npos,
				  "no-immediate-trigger") ;
			const std::wstring sddl = L"O:" + std::wstring( FAKE_SID) + L"G:" +
									  std::wstring( FAKE_SID) + L"D:P(A;;GA;;;" +
									  // 初回の三principal。
									  std::wstring( FAKE_SID) + L")(A;;GA;;;SY)(A;;GA;;;BA)" ;
			check( isCollectorUserTaskSddlAllowed( sddl, FAKE_SID), "initial-ga-policy") ;
			std::wstring mapped = sddl ;	// OSのfile/task full access mappingだけを変更する。
			std::size_t	 position{} ;		// 置換済み位置から次を探す有限cursor。
			// 固定三GAをFAに置き換え、他の権利は許可しない。
			while( (position = mapped.find( L"GA", position)) != std::wstring::npos) {
				mapped.replace( position, 2U, L"FA") ;
				position += 2U ;
			}

			check( isCollectorUserTaskSddlAllowed( mapped, FAKE_SID) &&
					  !isCollectorUserTaskSddlAllowed( mapped + L"(A;;FA;;;BU)", FAKE_SID),
				  "mapped-policy-closed") ;
			checkBoundary( 2026U, 10U, 23U, 14U, 54U, 59U, 0U, L"2026-10-23T15:00:00") ;
			checkBoundary( 2026U, 10U, 23U, 14U, 55U, 0U, 0U, L"2026-10-23T15:00:00") ;
			checkBoundary( 2026U, 10U, 23U, 14U, 55U, 0U, 1U, L"2026-10-24T15:00:00") ;
			checkBoundary( 2026U, 12U, 31U, 16U, 0U, 0U, 0U, L"2027-01-01T15:00:00") ;
			checkBoundary( 2028U, 2U, 28U, 16U, 0U, 0U, 0U, L"2028-02-29T15:00:00") ;
			check( collectorUserTaskXmlMatches( xml, xml), "xml-complete-contract") ;
			// 一つのfield/要素だけを変え、全構造比較が見逃さないことを確認する。
			for( const auto &change : std::array<std::pair<std::wstring, std::wstring>, 5>{
					std::pair{std::wstring( FAKE_SID), std::wstring( L"S-1-5-21-999-888-777-1001")},
					std::pair{std::wstring( L"InteractiveToken"), std::wstring( L"S4U")},
					std::pair{
						std::wstring( L"</Actions>"),
						std::wstring( L"<Exec><Command>unexpected</Command></Exec></Actions>")},
					std::pair{std::wstring( L"<StartWhenAvailable>false"),
							  std::wstring( L"<StartWhenAvailable>true")},
					std::pair{fake.plan->nonce,
							  std::wstring( L"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}")}}) {
				std::wstring changed		  = xml ;							// 原XMLから一変異だけを作る。
				const auto	 mutationPosition = changed.find( change.first) ;	// 元の必須field位置。
				check( mutationPosition != std::wstring::npos, "xml-mutation-source") ;
				changed.replace( mutationPosition, change.first.size(), change.second) ;
				checkXmlRejected( changed, xml) ;
			}

			rejects( fake, [&]() {
				static_cast<void>( collectorUserTaskXmlMatches(
					L"<!DOCTYPE Task [<!ENTITY x 'blocked'>]>" + xml, xml)) ;
			}) ;
			break ;
		}
		// native入力拒否ではTaskを作らない。
		case 4U: {
			fake.badConfig = true ;
			rejects( fake, [&]() { fake.install() ; }) ;
			check( fake.creates == 0U, "config-create-zero") ;
			const auto planFailureOwner =
				std::make_unique<Fake>() ;				// 大きなfixtureを元scopeだけで所有します。
			auto &planFailure	 = *planFailureOwner ;	// 先行plan保存失敗はTask照会/作成前に止める。
			planFailure.failPlan = true ;
			rejects( planFailure, [&]() { planFailure.install() ; }) ;
			check( planFailure.creates == 0U && planFailure.reads == 0U, "plan-before-task") ;
			break ;
		}

		// 同意前の呼出し側がmoduleへ到達しない境界をfakeに固定する。
		case 5U: {
			const bool consent = false ;	// UI取消し/同意なしを表す呼出し側の固定条件。
			// 明示同意が成立したときだけ製品もmoduleへ進む。
			if( consent) {
				fake.install() ;
			}

			check( fake.reads == 0U && fake.creates == 0U, "cancel-no-dispatch") ;
			break ;
		}
		// 旧版のdispatchは新user backendを使わない。
		case 6U: {
			const bool v6 = false ;	// v1-v5の従来配置を表す固定呼出し条件。
			// 最新v6だけを新しいmoduleへdispatchする。
			if( v6) {
				fake.install() ;
			}

			check( fake.reads == 0U && fake.changes == 0U, "legacy-no-dispatch") ;
			break ;
		}
		// 同名既存Taskをadopt/変更しない。
		case 7U:
			fake.task.exists = true ;
			rejects( fake, [&]() { fake.install() ; }) ;
			check( fake.creates + fake.changes + fake.deletes == 0U, "collision-no-change") ;
			break ;

		// 元COM拒否は保持する。
		case 8U:
			fake.createResult = static_cast<std::int32_t>( 0x80070005U) ;
			rejects( fake, [&]() { fake.install() ; }) ;
			check( fake.changes == 0U, "denied-no-enable") ;
			break ;

		// 正値のScheduler警告も成功ではない。
		case 9U:
			fake.createResult = 0x0004131c ;
			rejects( fake, [&]() { fake.install() ; }) ;
			check( fake.task.exists && !fake.task.enabled && fake.changes == 0U, "warning-retained") ;
			break ;

		// 作成後のUNKNOWNを削除の根拠にしない。
		case 10U:
			fake.postCreateReadFailure = true ;
			rejects( fake, [&]() { fake.install() ; }) ;
			check( fake.deletes == 0U && fake.changes == 0U, "unknown-retained") ;
			break ;

		// receipt保存/flush失敗で同じdisabled取引だけを回収する。
		case 11U: {
			// 保存/読戻し失敗と、回収read/deleteの不明を独立に注入する。
			for( std::size_t variant = 0U; variant < 4U; ++variant) {
				const auto receiptFailureOwner =
					std::make_unique<Fake>() ;						// 大きなfixtureを元scopeだけで所有します。
				auto &receiptFailure	 = *receiptFailureOwner ;	// 取引の副作用を変異間で混ぜない。
				receiptFailure.failOwner = variant != 1U ;
				receiptFailure.ownerReadbackFailure = variant == 1U ;
				// 原保存失敗の後だけ、回収用のreadを不明にする。
				if( variant == 2U) {
					const auto save =
						receiptFailure.backend.saveOwnership ;	// 同じfake寿命内の保存。
					receiptFailure.backend.saveOwnership =
						[&receiptFailure, save]( const CollectorUserTaskOwnership &value) {
							receiptFailure.failRead = true ;
							save( value) ;
						} ;
				}

				// 回収DeleteTaskの元HRESULTも成功にしない。
				if( variant == 3U) {
					receiptFailure.deleteResult = static_cast<std::int32_t>( 0x80070005U) ;
				}

				rejects( receiptFailure, [&]() { receiptFailure.install() ; }) ;
				check( receiptFailure.changes == 0U && receiptFailure.task.exists == (variant >= 2U),
					  "receipt-recovery-boundary") ;
			}

			break ;
		}

		// enable失敗は所有receiptとdisabled Taskを保持する。
		case 12U:
			fake.changeResult = static_cast<std::int32_t>( 0x80070005U) ;
			rejects( fake, [&]() { fake.install() ; }) ;
			check( fake.owner && !fake.task.enabled && fake.deletes == 0U, "enable-retained") ;
			break ;

		// 最終SDDL/原XML改変を成功へ変換しない。
		case 13U: {
			// SDDL改変、S_OKでもdisabled、XML改変を別の最終読戻しで拒否する。
			for( std::size_t variant = 0U; variant < 3U; ++variant) {
				const auto finalFailureOwner =
					std::make_unique<Fake>() ;				// 大きなfixtureを元scopeだけで所有します。
				auto &finalFailure = *finalFailureOwner ;	// 元のreceiptを保持して非成功にする。
				finalFailure.corruptEnabledPin = variant == 0U ;
				finalFailure.ignoreChange	   = variant == 1U ;
				// 有効化自体は成功し、最終XMLだけが違う状態を作る。
				if( variant == 2U) {
					const auto change = finalFailure.backend.setEnabled ;	// 元の同期操作。
					finalFailure.backend.setEnabled = [&finalFailure,
													   change]( const CollectorUserTaskPlan &plan,
															   const bool enabled) {
						const auto result	  = change( plan, enabled) ;	// 元HRESULTを維持する。
						finalFailure.task.xml = std::wstring( 64U, L'b') ;
						return result ;
					} ;
				}

				rejects( finalFailure, [&]() { finalFailure.install() ; }) ;
				check( finalFailure.task.exists && finalFailure.owner && finalFailure.deletes == 0U,
					  "final-pin-retained") ;
			}

			break ;
		}

		// 完全一致enabledは冪等。
		case 14U:
			fake.install() ;
			fake.creates = fake.changes = 0U ;
			fake.install() ;
			check( fake.creates + fake.changes == 0U, "idempotent") ;
			break ;

		// 欠損Taskは新取引だけを有限登録する。
		case 15U: {
			fake.install() ;
			fake.task	 = {} ;
			fake.creates = 0U ;
			fake.install() ;
			check( fake.creates == 1U && fake.task.enabled && fake.transactions == 2U,
				  "missing-repair") ;
			// 新planと旧receiptが残る三つの途中状態も同じ有限caseで確認する。
			for( std::size_t variant = 0U; variant < 3U; ++variant) {
				const auto partialOwner =
					std::make_unique<Fake>() ;	// 大きなfixtureを元scopeだけで所有します。
				auto &partial = *partialOwner ;	// 変異ごとに独立した既存同一版を作る。
				partial.install() ;
				partial.task = {} ;
				const auto create =
					partial.backend.createDisabled ;	// 同じ寿命内で元のfakeを保持する。
				// Registerの元失敗を注入する。
				if( variant == 0U) {
					partial.createResult = static_cast<std::int32_t>( 0x80070005U) ;
				}
				// 新receiptの保存失敗を注入する。
				else if( variant == 1U) {
					partial.failOwner = true ;
				} else {
					partial.backend.createDisabled =
						[]( const CollectorUserTaskPlan &) -> std::int32_t {
						throw std::runtime_error( "interrupted-before-create") ;
					} ;
				}

				rejects( partial, [&]() { partial.install() ; }) ;
				check( partial.plan->nonce != partial.owner->plan.nonce &&
						  !partial.plan->previousOwnership.empty(),
					  "predecessor-bound-before-create") ;
				partial.createResult		   = 0 ;
				partial.failOwner			   = false ;
				partial.backend.createDisabled = create ;
				partial.install() ;
				check( partial.task.enabled && partial.plan->nonce == partial.owner->plan.nonce,
					  "partial-repair-recovered") ;
			}

			break ;
		}

		// 同じplan/nonceのdisabled取引を回収してから再登録する。
		case 16U:
			fake.disabledTransaction() ;
			fake.owner.reset() ;
			fake.install() ;
			check( fake.deletes == 1U && fake.creates == 1U && fake.task.enabled,
				  "pending-recovery") ;
			break ;

		// nonce/SID/root/manifest不一致を変更前に拒否する。
		case 17U: {
			fake.install() ;
			fake.owner->plan.nonce = L"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}" ;
			fake.changes		   = 0U ;
			rejects( fake, [&]() { fake.install() ; }) ;
			check( fake.changes == 0U, "nonce-no-change") ;
			// 実plan codecへ未知schema/field・不正hash・不正nonceを渡して拒否を確認する。
			for( std::size_t variant = 0U; variant < 4U; ++variant) {
				const auto original =
					// 実writerと同じ原byte。
					serializeCollectorUserTaskPlan( *fake.plan) ;
				auto json = winrt::Windows::Data::Json::JsonObject::Parse(
					// 一変異だけのobject。
					winrt::to_hstring( original)) ;
				// 未採用schemaを受け付けない。
				if( variant == 0U) {
					json.SetNamedValue(
						L"schema",
						winrt::Windows::Data::Json::JsonValue::CreateStringValue( L"unknown")) ;
				}
				// 任意command等の追加fieldを受け付けない。
				else if( variant == 1U) {
					json.SetNamedValue(
						L"unknown", winrt::Windows::Data::Json::JsonValue::CreateStringValue( L"x")) ;
				}
				// 不正な前receipt hashを閉形式で拒否する。
				else if( variant == 2U) {
					json.SetNamedValue(
						L"previousOwnershipSha256",
						winrt::Windows::Data::Json::JsonValue::CreateStringValue( L"bad-hash")) ;
				} else {
					json.SetNamedValue(
						L"transactionNonce",
						winrt::Windows::Data::Json::JsonValue::CreateStringValue( L"not-guid")) ;
				}

				rejects( fake, [&]() {
					static_cast<void>(
						parseCollectorUserTaskPlan( winrt::to_string( json.Stringify()))) ;
				}) ;
			}

			rejects( fake, [&]() {
				static_cast<void>( parseCollectorUserTaskPlan( std::string( 65537U, 'x'))) ;
			}) ;
			const auto changedOwner =
				std::make_unique<Fake>() ;	// 大きなfixtureを元scopeだけで所有します。
			auto &changed = *changedOwner ;	// 正しい形式の偽hashでも前receiptとの結合を許さない。
			changed.install() ;
			changed.task	  = {} ;
			changed.failOwner = true ;
			rejects( changed, [&]() { changed.install() ; }) ;
			changed.plan->previousOwnership = std::wstring( 64U, L'b') ;
			changed.failOwner				= false ;
			changed.reads					= 0U ;
			rejects( changed, [&]() { changed.install() ; }) ;
			check( changed.reads == 0U, "changed-predecessor-before-task-read") ;
			break ;
		}

		// disabled日時越えは次の未来取引一回だけで修復する。
		case 18U:
			fake.disabledTransaction() ;
			fake.future = false ;
			fake.install() ;
			check( fake.deletes == 1U && fake.creates == 1U && fake.transactions == 2U,
				  "expired-finite-repair") ;
			break ;

		// 正常解除はdisable/read/delete/absenceの順。
		case 19U:
			fake.install() ;
			fake.events.clear() ;
			check( fake.uninstall() == 1U && !fake.task.exists, "normal-uninstall") ;
			check( std::find( fake.events.begin(), fake.events.end(), "disable") <
					  std::find( fake.events.begin(), fake.events.end(), "delete"),
				  "uninstall-order") ;
			break ;

		// 前回削除後の失敗は同じreceiptで不存在を再確認できる。
		case 20U:
			fake.install() ;
			fake.task = {} ;
			check( fake.uninstall() == 0U, "already-absent") ;
			break ;

		// receipt欠損はprogram削除の許可ではない。
		case 21U:
			fake.install() ;
			fake.owner.reset() ;
			rejects( fake, [&]() { static_cast<void>( fake.uninstall()) ; }) ;
			check( fake.task.exists, "missing-owner-retained") ;
			break ;

		// XML/SDDL/root/manifestの改変拒否を独立fakeで全部検査する。
		case 22U: {
			// 固定四変異を有限に実施し、一件でも見逃したらcaseを失敗にする。
			for( std::size_t variant = 0U; variant < 4U; ++variant) {
				const auto changedOwner =
					std::make_unique<Fake>() ;	// 大きなfixtureを元scopeだけで所有します。
				auto &changed = *changedOwner ;	// 変異間で作用を混ぜない。
				changed.install() ;
				// 各caseで一つの所有pinまたはidentityだけを変更する。
				if( variant == 0U) {
					changed.task.enabledXml = std::wstring( 64U, L'b') ;
					changed.task.xml		= changed.task.enabledXml ;
				}
				// 原SDDLの改変を検出する。
				else if( variant == 1U) {
					changed.task.sddl = std::wstring( 64U, L'b') ;
				}
				// 別rootのplanを現在配置へ流用しない。
				else if( variant == 2U) {
					changed.plan->root += L"x" ;
				} else {
					changed.plan->manifest = std::wstring( 64U, L'b') ;
				}

				rejects( changed, [&]() { static_cast<void>( changed.uninstall()) ; }) ;
				check( changed.deletes == 0U, "changed-no-delete") ;
			}

			break ;
		}
		// running、queued、実instanceを全部保持する。
		case 23U: {
			// 固定三状態を同じ拒否契約で確認する。
			for( const auto state : std::array<std::uint32_t, 3>{4U, 2U, 3U}) {
				const auto activeOwner =
					std::make_unique<Fake>() ;	// 大きなfixtureを元scopeだけで所有します。
				auto &active = *activeOwner ;	// 独立memory状態。
				active.install() ;
				active.task.state	  = state ;
				active.task.instances = state == 3U ? 1U : 0U ;
				rejects( active, [&]() { static_cast<void>( active.uninstall()) ; }) ;
				check( active.deletes == 0U, "running-no-stop-or-delete") ;
			}

			break ;
		}
		// 権限/状態不明は不存在へ変換しない。
		case 24U:
			fake.install() ;
			fake.failRead = true ;
			rejects( fake, [&]() { static_cast<void>( fake.uninstall()) ; }) ;
			check( fake.deletes == 0U, "read-denied-retained") ;
			break ;

		// disable失敗ではdeleteしない。
		case 25U: {
			// 正値警告とS_OKでも無効化されない読戻しを拒否する。
			for( std::size_t variant = 0U; variant < 2U; ++variant) {
				const auto disableFailureOwner =
					std::make_unique<Fake>() ;					// 大きなfixtureを元scopeだけで所有します。
				auto &disableFailure = *disableFailureOwner ;	// 各変異のprogram/dataを保持する。
				disableFailure.install() ;
				disableFailure.changeResult = variant == 0U ? 1 : 0 ;
				disableFailure.ignoreChange = variant == 1U ;
				rejects( disableFailure, [&]() { static_cast<void>( disableFailure.uninstall()) ; }) ;
				check( disableFailure.deletes == 0U, "disable-warning-or-readback") ;
			}

			break ;
		}

		// delete失敗/不存在読戻し失敗は非成功でreceiptを保持する。
		case 26U: {
			// Deleteの失敗、残存、最終不存在readの不明を区別して非成功にする。
			for( std::size_t variant = 0U; variant < 3U; ++variant) {
				const auto deleteFailureOwner =
					std::make_unique<Fake>() ;				// 大きなfixtureを元scopeだけで所有します。
				auto &deleteFailure = *deleteFailureOwner ;	// receipt/programは全変異で保持する。
				deleteFailure.install() ;
				deleteFailure.deleteResult =
					variant == 0U ? static_cast<std::int32_t>( 0x80070005U) : 0 ;
				deleteFailure.ignoreDelete = variant == 1U ;
				// 削除後の不明を、正常不存在に読み替えない。
				if( variant == 2U) {
					const auto remove = deleteFailure.backend.remove ;	// 同じfakeの元Delete。
					deleteFailure.backend.remove = [&deleteFailure,
													remove]( const CollectorUserTaskPlan &plan) {
						const auto result	   = remove( plan) ;	// 元HRESULT。
						deleteFailure.failRead = true ;
						return result ;
					} ;
				}

				rejects( deleteFailure, [&]() { static_cast<void>( deleteFailure.uninstall()) ; }) ;
				check( deleteFailure.owner && !deleteFailure.task.enabled,
					  "delete-unknown-retained") ;
			}

			break ;
		}

		// disabled再実行は同じpinから解除でき、program削除権限はpolicy外。
		case 27U:
			fake.disabledTransaction() ;
			check( fake.uninstall() == 1U && fake.changes == 0U && fake.program == "program-bytes",
				  "disabled-retry-order") ;
			break ;

		// backendが受け取るのは新導出名だけ。旧Task read/changeなし。
		case 28U:
			fake.install() ;
			static_cast<void>( fake.uninstall()) ;
			check( fake.reads > 0U &&
					  fake.identity.path.starts_with( L"\\DriverCrate.Collector.Daily."),
				  "new-only") ;
			break ;

		// 旧receipt混在の事前拒否をverify境界に注入し、Task read0を要求する。
		case 29U:
			fake.backend.verifyPackage = []() { throw std::runtime_error( "legacy-receipt-mixed") ; } ;
			rejects( fake, [&]() { fake.install() ; }) ;
			check( fake.reads == 0U, "mixed-before-task") ;
			break ;

		// 旧admin schemaは新所有証明にならない。
		case 30U:
			fake.disabledTransaction() ;
			fake.owner.reset() ;
			fake.backend.loadOwnership = []() -> std::optional<CollectorUserTaskOwnership> {
				throw std::runtime_error( "legacy-schema-rejected") ;
			} ;
			rejects( fake, [&]() { static_cast<void>( fake.uninstall()) ; }) ;
			check( fake.deletes == 0U && fake.reads == 0U, "admin-not-new-owner") ;
			break ;

		// 登録後の匿名構造差だけを許し、各既定値の非既定・重複を拒否する。
		case 33U: {
			fake.install() ;
			const auto expected = collectorUserTaskXml( *fake.plan, false) ;	// 固定の架空取引。
			const auto actual	= registeredXmlFixture( expected) ;				// 保存済み実構造の匿名版。
			check( collectorUserTaskXmlMatches( actual, expected), "registered-os-shape") ;
			check( collectorUserTaskXmlMatches(
					  L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" + actual, expected),
				  "registered-declaration-and-formatting") ;
			check( expected.find( L"<SecurityDescriptor>O:" + std::wstring( FAKE_SID)) !=
					  std::wstring::npos,
				  "expected-explicit-three-principal-sddl") ;
			// 観測差に加え、残る複数子xs:all親の順序非依存も独立に確認する。
			for( const auto &entry : std::array<std::pair<std::wstring, std::wstring>, 3>{
					std::pair{L"RegistrationInfo", L"SecurityDescriptor"},
					std::pair{L"Principal", L"UserId"},
					std::pair{L"IdleSettings", L"StopOnIdleEnd"}}) {
				auto	   reordered = expected ;								// 値・属性・子集合を変えず一要素を末尾へ動かす。
				const auto element	 = xmlElement( reordered, entry.second) ;	// 移動する一意の子。
				replaceXml( reordered, element, L"") ;
				replaceXml( reordered, L"</" + entry.first + L">",
						   element + L"</" + entry.first + L">") ;
				check( collectorUserTaskXmlMatches( reordered, expected), "known-xs-all-order") ;
			}

			// 八pathをそれぞれ単独で省略・非既定・重複へ変え、分母を固定する。
			for( const auto &entry : std::array<std::pair<std::wstring, std::wstring>, 8>{
					std::pair{L"<RunLevel>LeastPrivilege</RunLevel>",
							  L"<RunLevel>HighestAvailable</RunLevel>"},
					std::pair{L"<Hidden>false</Hidden>", L"<Hidden>true</Hidden>"},
					std::pair{L"<Priority>7</Priority>", L"<Priority>8</Priority>"},
					std::pair{L"<RunOnlyIfIdle>false</RunOnlyIfIdle>",
							  L"<RunOnlyIfIdle>true</RunOnlyIfIdle>"},
					std::pair{L"<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>",
							  L"<RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>"},
					std::pair{L"<StartWhenAvailable>false</StartWhenAvailable>",
							  L"<StartWhenAvailable>true</StartWhenAvailable>"},
					std::pair{L"<WakeToRun>false</WakeToRun>", L"<WakeToRun>true</WakeToRun>"},
					std::pair{L"<Enabled>true</Enabled>", L"<Enabled>false</Enabled>"}}) {
				auto omitted = expected ;	// 単独省略は同値。
				replaceXml( omitted, entry.first, L"") ;
				check( collectorUserTaskXmlMatches( omitted, expected), "single-default-omission") ;
				auto changed = expected ;	// 非既定値は同値でない。
				replaceXml( changed, entry.first, entry.second) ;
				checkXmlRejected( changed, expected) ;
				auto duplicate = expected ;	// 同じ既定値を二つとも省略させない。
				replaceXml( duplicate, entry.first, entry.first + entry.first) ;
				checkXmlRejected( duplicate, expected) ;
			}

			// 未知node/属性/namespace、追加Action/triggerとsequence改変を独立に拒否する。
			for( const auto &entry : std::array<std::pair<std::wstring, std::wstring>, 9>{
					std::pair{L"</Settings>", L"<Unknown>false</Unknown></Settings>"},
					std::pair{L"<Hidden>", L"<Hidden unknown=\"1\">"},
					std::pair{L"<Hidden>", L"<Hidden xmlns=\"urn:unknown\">"},
					std::pair{L"</Actions>", L"<Exec><Command>extra</Command></Exec></Actions>"},
					std::pair{L"</Triggers>",
							  xmlElement( expected, L"CalendarTrigger") + L"</Triggers>"},
					std::pair{xmlElement( expected, L"StartBoundary") + L"<Enabled>true</Enabled>" +
								  xmlElement( expected, L"ScheduleByDay"),
							  xmlElement( expected, L"ScheduleByDay") + L"<Enabled>true</Enabled>" +
								  xmlElement( expected, L"StartBoundary")},
					std::pair{L"</Settings>", L"<Enabled>false</Enabled></Settings>"},
					std::pair{L"<IdleSettings>", L"<IdleSettings><!--unknown-->"},
					std::pair{L"<SecurityDescriptor>", L"<SecurityDescriptor unknown=\"x\">"}}) {
				auto changed = expected ;	// 一変異ずつ完全契約へ照合する。
				replaceXml( changed, entry.first, entry.second) ;
				checkXmlRejected( changed, expected) ;
			}

			const auto command	= xmlElement( expected, L"Command") ;	// Execはsequenceを維持する。
			auto	   reversed = expected ;							// 引数をcommandより前へ動かす。
			replaceXml( reversed, command, L"") ;
			replaceXml( reversed, L"</Arguments>", L"</Arguments>" + command) ;
			checkXmlRejected( reversed, expected) ;
			checkXmlRejected( L"<!--unknown-->" + expected, expected) ;
			checkXmlRejected( L"<?unexpected blocked?>" + expected, expected) ;
			break ;
		}

		// 初回pendingだけは所有receiptを捏造せず通常解除と正常不存在へ進む。
		case 34U: {
			fake.disabledTransaction() ;
			fake.owner.reset() ;
			check( fake.uninstall() == 1U && !fake.task.exists && !fake.owner &&
					  fake.changes == 0U && fake.creates == 0U,
				  "pending-normal-uninstall") ;
			check( fake.uninstall() == 0U && !fake.owner, "pending-already-absent") ;
			break ;
		}

		// plan不在、前所有結合、別identity、enabled/実行中/未知契約は回収しない。
		case 35U: {
			// 固定十変異を独立した初回pendingから検査する。
			for( std::size_t variant = 0U; variant < 10U; ++variant) {
				const auto pendingOwner =
					std::make_unique<Fake>() ;	// 大きなfixtureを元scopeだけで所有します。
				auto &pending = *pendingOwner ;	// 各変異を他の作用から隔離する。
				pending.disabledTransaction() ;
				pending.owner.reset() ;
				// plan不在をTask名だけで補わない。
				if( variant == 0U) {
					pending.plan.reset() ;
				}
				// 前所有receiptを失った修復取引は拒否する。
				else if( variant == 1U) {
					pending.plan->previousOwnership = std::wstring( 64U, L'a') ;
				}
				// 現在rootと異なるidentityは拒否する。
				else if( variant == 2U) {
					pending.plan->root += L"x" ;
				}
				// nonceの閉形式をTask照会前に確認する。
				else if( variant == 3U) {
					pending.plan->nonce = L"invalid" ;
				}
				// ownerなしのenabled Taskは一切変更しない。
				else if( variant == 4U) {
					pending.task.enabled = true ;
					pending.task.state	 = 3U ;
					pending.task.xml	 = pending.task.enabledXml ;
				}
				// runningのTaskを強制停止しない。
				else if( variant == 5U) {
					pending.task.state = 4U ;
				}
				// queuedも非実行とは扱わない。
				else if( variant == 6U) {
					pending.task.state = 2U ;
				}
				// stateだけで実instanceを無視しない。
				else if( variant == 7U) {
					pending.task.instances = 1U ;
				}
				// 設定またはSDDLの不一致を削除しない。
				else if( variant == 8U) {
					pending.task.contractMatches = false ;
				} else {
					pending.taskNonce = L"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}" ;
				}

				rejects( pending, [&]() {
					static_cast<void>( pending.uninstall()) ;
					pending.program.clear() ;
				}) ;
				check( pending.deletes == 0U && pending.changes == 0U && pending.task.exists,
					  "unsafe-pending-retained") ;
			}

			break ;
		}

		// 再読・package・原pin・delete・不存在の各失敗ではprogram削除へ進まない。
		case 36U: {
			// 固定八変異を各pendingの通常解除へ一度ずつ注入する。
			for( std::size_t variant = 0U; variant < 8U; ++variant) {
				const auto pendingOwner =
					std::make_unique<Fake>() ;	// 大きなfixtureを元scopeだけで所有します。
				auto &pending = *pendingOwner ;	// 実Taskを使わない独立した初回取引。
				pending.disabledTransaction() ;
				pending.owner.reset() ;
				// 初回照会拒否は正常不存在にしない。
				if( variant == 0U) {
					pending.failRead = true ;
				}
				// packageの二回目の再検査拒否を保持する。
				else if( variant == 1U) {
					pending.backend.verifyPackage = [&pending]() {
						check( pending.reads == 0U, "package-recheck-failed") ;
					} ;
				}
				// 削除直前の原pin変更・読戻し拒否を保持する。
				else if( variant == 2U || variant == 3U) {
					const auto read		 = pending.backend.read ;	// 同じFakeの元同期操作。
					pending.backend.read = [&pending, read,
											variant]( const CollectorUserTaskPlan &plan) {
						auto snapshot = read( plan) ;	// 最初のpinを変えず二回目だけ変異する。
						// 削除直前だけ競合または取得拒否を再現する。
						if( pending.reads == 2U) {
							check( variant != 3U, "final-read-denied") ;
							snapshot.sddl = std::wstring( 64U, L'b') ;
						}

						return snapshot ;
					} ;
				}
				// Delete APIの失敗はそのまま非成功にする。
				else if( variant == 4U) {
					pending.deleteResult = static_cast<std::int32_t>( 0x80070005U) ;
				}
				// S_OKでも残存ならprogramを保持する。
				else if( variant == 5U) {
					pending.ignoreDelete = true ;
				}
				// 削除後の不存在確認拒否も非成功にする。
				else if( variant == 6U) {
					const auto remove	   = pending.backend.remove ;	// 元のmemory Delete。
					pending.backend.remove = [&pending, remove]( const CollectorUserTaskPlan &plan) {
						const auto result = remove( plan) ;	// 元のAPI結果。
						pending.failRead  = true ;
						return result ;
					} ;
				} else {
					pending.deleteResult = 1 ;
				}

				rejects( pending, [&]() {
					static_cast<void>( pending.uninstall()) ;
					pending.program.clear() ;
				}) ;
				check( !pending.owner && pending.changes == 0U && pending.creates == 0U,
					  "pending-failure-no-adopt-enable") ;
			}

			break ;
		}

		// Task plan/receiptはseed/export payloadでなく、policyにexport操作がない。
		case 31U:
			fake.install() ;
			check( fake.plan && fake.owner && fake.config == "config-original" &&
					  fake.state == "cooldown-original",
				  "metadata-local-only") ;
			break ;

		// 登録修復を繰返してもconfig/stateの原byteは保持する。
		case 32U:
			fake.disabledTransaction() ;
			fake.install() ;
			fake.task = {} ;
			fake.install() ;
			check( fake.config == "config-original" && fake.state == "cooldown-original" &&
					  fake.program == "program-bytes",
				  "repair-byte-preservation") ;
			fake.badConfig = true ;
			check( fake.uninstall() == 1U && fake.config == "config-original",
				  "invalid-config-uninstall-retained") ;
			break ;

		// 原byte両hashを保った有効省略を、登録読戻し・冪等・通常解除まで確認する。
		case 37U: {
			const auto create = fake.backend.createDisabled ;	// 元fakeの取引とイベントは保持する。
			fake.backend.createDisabled = [&]( const CollectorUserTaskPlan &plan) {
				const auto result = create( plan) ;	// 証明されたdisabled原文で置き換える。
				fake.task		  = lineSnapshot( disabledLineFixture( plan), plan, false) ;
				return result ;
			} ;
			fake.backend.setEnabled = [&]( const CollectorUserTaskPlan &plan, const bool enabled) {
				++fake.changes ;
				fake.events.emplace_back( enabled ? "enable" : "disable") ;
				auto raw = disabledLineFixture( plan) ;	// disable後は元原byteへ戻るOS挙動。
				// trueだけを省略し、他の全byteはそのまま保持する。
				if( enabled) {
					replaceXml( raw, L"    <Enabled>false</Enabled>\r\n", L"") ;
				}

				fake.task = lineSnapshot( raw, plan, enabled) ;
				return 0 ;
			} ;
			fake.install() ;
			const auto off = disabledLineFixture( *fake.plan) ;	// 独立した明示原文。
			auto	   on  = off ;								// 期待する明示true hashだけを原文から直接作る。
			replaceXml( on, L"<Enabled>false</Enabled>", L"<Enabled>true</Enabled>") ;
			check( fake.owner->enabledXml == fixtureHash( on) &&
					  fake.owner->disabledXml == fixtureHash( off),
				  "original-owner-pair") ;
			check( fake.task.xml != fake.owner->enabledXml && fake.task.enabledXml.empty() &&
					  fake.task.disabledXml.empty() && fake.task.omittedEnabledPins.size() == 7U,
				  "actual-versus-seven-witnesses") ;
			fake.install() ;
			check( fake.creates == 1U && fake.changes == 1U, "omitted-idempotent-nochange") ;
			check( fake.uninstall() == 1U && fake.changes == 2U && fake.deletes == 1U &&
					  !fake.task.exists,
				  "omitted-normal-uninstall") ;
			break ;
		}

		// 全残byte・片pin・候補対・SDDLの改変は最初の変更前に拒否する。
		case 38U: {
			// 固定七変異はそれぞれ正常owned省略snapshotから検査する。
			for( std::size_t variant = 0U; variant < 7U; ++variant) {
				const auto changedOwner =
					std::make_unique<Fake>() ;	// 大きなfixtureを元scopeだけで所有します。
				auto &changed = *changedOwner ;	// 他の変異の作用を混ぜない。
				changed.install() ;
				const auto off		= disabledLineFixture( *changed.plan) ;			// 原disabled証拠。
				const auto disabled = lineSnapshot( off, *changed.plan, false) ;	// 元両pin。
				changed.owner		= CollectorUserTaskOwnership{*changed.plan, disabled.enabledXml,
															 disabled.disabledXml, disabled.sddl} ;
				auto raw			= off ;	// 省略だけなら同じownerと一致する。
				replaceXml( raw, L"    <Enabled>false</Enabled>\r\n", L"") ;
				// 意味が同じでも残byteの一文字変更を許さない。
				if( variant == 0U) {
					raw += L"\r\n" ;
				}

				changed.task = lineSnapshot( raw, *changed.plan, true) ;
				// 一方のowner hashだけが違っても拒否する。
				if( variant == 1U) {
					changed.owner->enabledXml = std::wstring( 64U, L'b') ;
				}

				// disabled側だけの改変も有効時から拒否する。
				if( variant == 2U) {
					changed.owner->disabledXml = std::wstring( 64U, L'b') ;
				}

				// 原SDDLの変化は意味上の同権限でも許可しない。
				if( variant == 3U) {
					changed.task.sddl = std::wstring( 64U, L'b') ;
				}

				// 別slotの片方ずつを集めて一対へ偽装できない。
				if( variant == 4U) {
					changed.owner->enabledXml  = changed.task.omittedEnabledPins[0].first ;
					changed.owner->disabledXml = changed.task.omittedEnabledPins[1].second ;
				}

				// 候補上限をfake境界から超過させても受理しない。
				if( variant == 5U) {
					changed.task.omittedEnabledPins.resize( 33U, changed.task.omittedEnabledPins[0]) ;
				}

				// 省略の検証候補を実原XML hashとして報告できない。
				if( variant == 6U) {
					changed.task.enabledXml = changed.owner->enabledXml ;
				}

				const auto changes = changed.changes ;	// 拒否前の変更数。
				rejects( changed, [&]() { static_cast<void>( changed.uninstall()) ; }) ;
				check( changed.changes == changes && changed.deletes == 0U && changed.task.exists,
					  "omitted-tamper-nochange") ;
			}

			break ;
		}

		// false省略・API矛盾・未知XML・未知書式は候補生成で修復しない。
		case 39U: {
			fake.install() ;
			const auto off		= disabledLineFixture( *fake.plan) ;		// 匿名原文。
			const auto expected = collectorUserTaskXml( *fake.plan, true) ;	// 独立期待。
			auto	   omitted	= off ;										// 既定trueを省略した正例。
			replaceXml( omitted, L"    <Enabled>false</Enabled>\r\n", L"") ;
			check( collectorUserTaskXmlMatches( omitted, expected), "ninth-default-equivalent") ;
			// 固定十一変異を同じDOMとpin helperへ直接渡す。
			for( std::size_t variant = 0U; variant < 11U; ++variant) {
				auto raw	 = omitted ;	// 各変異は元正例から作る。
				bool enabled = true ;		// 実APIの独立観測値。
				// falseが省略されたと推測しない。
				if( variant == 0U) {
					enabled = false ;
				}

				// 明示falseとAPI trueの矛盾を拒否する。
				if( variant == 1U) {
					raw = off ;
				}

				// 明示trueとAPI falseの矛盾を拒否する。
				if( variant == 2U) {
					raw = off ;
					replaceXml( raw, L"<Enabled>false</Enabled>", L"<Enabled>true</Enabled>") ;
					enabled = false ;
				}

				// 重複は既定値を省略する前に拒否する。
				if( variant == 3U) {
					replaceXml( raw, L"</Settings>",
							   L"<Enabled>true</Enabled><Enabled>true</Enabled></Settings>") ;
				}

				// 未知要素をsafeな候補へ補正しない。
				if( variant == 4U) {
					replaceXml( raw, L"</Settings>", L"<Unknown>false</Unknown></Settings>") ;
				}

				// 実XML容量と候補容量は従前上限に従う。
				if( variant == 5U) {
					raw.append( 65536U, L' ') ;
				}

				// 行境界なしの書式は有限挿入対象にしない。
				if( variant == 6U) {
					raw.erase( std::remove( raw.begin(), raw.end(), L'\n'), raw.end()) ;
				}

				// 直接子indentationの混在を補正しない。
				if( variant == 7U) {
					replaceXml( raw, L"    <ExecutionTimeLimit>", L"\t<ExecutionTimeLimit>") ;
				}

				// DTDは候補より先にDOMで拒否する。
				if( variant == 8U) {
					replaceXml( raw, L"<Task version",
							   L"<!DOCTYPE Task [<!ENTITY x 'blocked'>]><Task version") ;
				}

				// 非既定値の追加を既定省略へ転換しない。
				if( variant == 9U) {
					replaceXml( raw, L"</Settings>", L"<Enabled>unknown</Enabled></Settings>") ;
				}

				// 候補一行追加で上限超過する場合も拒否する。
				if( variant == 10U) {
					raw.append( 65536U - raw.size(), L' ') ;
				}

				rejects( fake, [&]() {
					static_cast<void>( collectorUserTaskXmlSnapshot( raw, expected, enabled)) ;
				}) ;
			}

			break ;
		}

		// 有効所有一致後もdisabled実原pinが違えばDeleteへ進まない。
		case 40U: {
			fake.install() ;
			const auto off		= disabledLineFixture( *fake.plan) ;		// 初回disabled原XML。
			const auto disabled = lineSnapshot( off, *fake.plan, false) ;	// 所有する原両pin。
			fake.owner			= CollectorUserTaskOwnership{*fake.plan, disabled.enabledXml,
													 disabled.disabledXml, disabled.sddl} ;
			auto raw			= off ;	// 実enabledの省略形。
			replaceXml( raw, L"    <Enabled>false</Enabled>\r\n", L"") ;
			fake.task				= lineSnapshot( raw, *fake.plan, true) ;
			fake.backend.setEnabled = [&]( const CollectorUserTaskPlan &plan, const bool enabled) {
				check( !enabled, "uninstall-disable-only") ;
				++fake.changes ;
				fake.task = lineSnapshot( off + L"\r\n", plan, false) ;
				return 0 ;
			} ;
			rejects( fake, [&]() { static_cast<void>( fake.uninstall()) ; }) ;
			check( fake.deletes == 0U && fake.task.exists && !fake.task.enabled,
				  "disabled-raw-repin-rejection") ;
			break ;
		}

		// 新日次Taskは別identity/Action/schemaで有効readbackまで同じ取引を通します。
		case 41U: {
			const auto old = fake.identity ;	// 既存native identityを比較用に保持します。
			fake.identity  = collectorUserTaskIdentity( old.root, old.sid, old.manifest, true) ;
			check( fake.identity.path == old.path + L"-Distribution", "daily-distinct-owner") ;
			fake.install() ;
			const auto xml = collectorUserTaskXml( *fake.plan, true) ;	// 実登録はしません。
			check(
				xml.find(
					L"DriverCrateCollectorSetup.exe</Command><Arguments>--distribution-daily</Arguments>") !=
						std::wstring::npos &&
					xml.find( L"--once") == std::wstring::npos &&
					fake.plan->boundary.ends_with( L"T17:00:00"),
				"daily-fixed-action-hour") ;
			check( parseCollectorUserTaskPlan( serializeCollectorUserTaskPlan( *fake.plan))
						  .distributionDaily &&
					  fake.task.enabled,
				  "daily-v2-readback") ;
			fake.install() ;
			check( fake.creates == 1U && fake.uninstall() == 1U && !fake.task.exists,
				  "daily-idempotent-uninstall") ;
			break ;
		}
		// 新所有Taskの削除確認失敗では管理file削除側へ成功を返しません。
		case 42U: {
			fake.identity = collectorUserTaskIdentity( fake.identity.root, fake.identity.sid,
													  fake.identity.manifest, true) ;
			fake.install() ;
			fake.backend.remove = []( const CollectorUserTaskPlan &) -> std::int32_t {
				return 0 ;
			} ; // 不存在readbackを偽装しません。
			rejects( fake, [&]() { static_cast<void>( fake.uninstall()) ; }) ;
			check( fake.task.exists, "daily-retain-on-delete-readback") ;
			break ;
		}
		// 新旧Taskは別fakeの所有を交差させず共存します。
		case 43U: {
			const auto dailyOwner =
				std::make_unique<Fake>() ;	// 大きなfixtureを元scopeだけで所有します。
			auto &daily	   = *dailyOwner ;	// 実Schedulerを使わない別所有状態です。
			daily.identity = collectorUserTaskIdentity( daily.identity.root, daily.identity.sid,
													   daily.identity.manifest, true) ;
			fake.install() ;
			daily.install() ;
			check( fake.task.enabled && daily.task.enabled &&
					  fake.plan->boundary.ends_with( L"T15:00:00") &&
					  daily.plan->boundary.ends_with( L"T17:00:00"),
				  "daily-coexists-native") ;
			check( daily.uninstall() == 1U && fake.task.exists && fake.task.enabled,
				  "daily-removes-own-only") ;
			break ;
		}
		// 未登録の二用途は固定名の正常不存在を確認し、取引やTaskを作りません。
		case 44U: {
			// nativeとdistributionの両identityを同じ未登録境界で確認します。
			for( const bool daily : {false, true}) {
				const auto unregisteredOwner =
					std::make_unique<Fake>() ;				// 大きなfixtureを元scopeだけで所有します。
				auto &unregistered = *unregisteredOwner ;	// planとownerがない正常な初期状態です。
				unregistered.identity =
					collectorUserTaskIdentity( unregistered.identity.root, unregistered.identity.sid,
											  unregistered.identity.manifest, daily) ;
				check( unregistered.uninstall() == 0U && unregistered.reads == 1U &&
						  unregistered.creates == 0U && unregistered.changes == 0U &&
						  unregistered.deletes == 0U && !unregistered.plan && !unregistered.owner,
					  "unregistered-normal-absence") ;
			}

			break ;
		}
		// planが消えた所有receiptは孤立として照会・変更前に拒否します。
		case 45U: {
			fake.install() ;
			fake.plan.reset() ;
			const auto reads = fake.reads ;	// 拒否前のTask照会回数です。
			rejects( fake, [&]() { static_cast<void>( fake.uninstall()) ; }) ;
			check( fake.reads == reads && fake.deletes == 0U && fake.task.enabled,
				  "orphan-owner-retained") ;
			break ;
		}
		// 記録なしの同名Taskを所有と推定せず、そのまま保持します。
		case 46U: {
			fake.task.exists  = true ;
			fake.task.enabled = true ;
			rejects( fake, [&]() { static_cast<void>( fake.uninstall()) ; }) ;
			check( fake.reads == 1U && fake.changes == 0U && fake.deletes == 0U &&
					  fake.task.exists && fake.task.enabled,
				  "unowned-name-retained") ;
			break ;
		}
		// 不存在照会の失敗を正常不存在へ変換しません。
		case 47U: {
			fake.failRead = true ;
			rejects( fake, [&]() { static_cast<void>( fake.uninstall()) ; }) ;
			check( fake.reads == 1U && fake.changes == 0U && fake.deletes == 0U,
				  "unregistered-unknown-retained") ;
			break ;
		}
		// 有限集合以外は試験の誤呼出しとして拒否する。
		default:
			throw std::runtime_error( "invalid-case") ;
	}
}
} // namespace

/** @brief 有限47caseをfakeだけで実行します。
 * @return 全成功0、不一致1。
 * @note 実Task APIのcallbackを構築・呼出しません。
 */
int main()
{
	winrt::init_apartment() ;
	std::size_t failed{} ;	// 失敗を分母から除外しない。
	// 全U01-U47を一度ずつ実行し、最初の失敗でも残りを確認する。
	for( std::size_t number = 1U; number <= 47U; ++number) {
		try {
			runCase( number) ;
			std::printf( "U%02zu PASS fake=1 task_api=0 http=0\n", number) ;
		} catch( const std::exception &error) {
			++failed ;
			std::printf( "U%02zu FAIL reason=%s\n", number, error.what()) ;
		} catch( const winrt::hresult_error &error) {
			++failed ;
			std::printf( "U%02zu FAIL hresult=%08x\n", number,
						static_cast<unsigned int>( error.code().value)) ;
		}
	}

	std::printf( "USER_TASK_FAKE_RESULT cases=47 failed=%zu real_tasks=0 http=0\n", failed) ;
	winrt::uninit_apartment() ;
	return failed == 0U ? 0 : 1 ;
}
