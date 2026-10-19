//------------------------------------------------------------------------------
/**
 * @file signed_index_candidate_binding_tests.h
 * @brief 通常本体の真署名索引候補とfake指定導入試験を宣言します。
 * @version 01.15.00
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  同workerの索引候補と指定導入の内部境界を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/12  全低位fakeを持つ内部unit構成へ試験宣言を限定。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  実UIへ同workerと二deviceの固定低位fixtureを共有。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  明示初回・共有・登録path拒否の完全低位条件を宣言。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  実CAT memberと低位署名期待hashの不一致条件を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/13  Class未確定初回の完全低位正常・拒否条件を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/13  必要構成のstageと親子指定APIの低位条件を宣言。
 * Ver.01.07.00 Shunji Ogawa  2026/10/13  元detail節/完全path/全import拒否条件とpartial意味を定義。
 * Ver.01.08.00 Shunji Ogawa  2026/10/13  必要service EXE署名/改変と子曖昧/親停止の低位条件を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  選択依存の拒否/文脈差/改変と独立低位観測を宣言。
 * Ver.01.10.00 Shunji Ogawa  2026/10/14  取得commandのnative部分根拠と二node非一意を宣言。
 * Ver.01.11.00 Shunji Ogawa  2026/10/15  R04の全present再列挙なしを独立低位counterで観測。
 * Ver.01.12.00 Shunji Ogawa  2026/10/15  低位署名scope開始時の同worker観測登録を共有。
 * Ver.01.13.00 Shunji Ogawa  2026/10/15  登録Extensionの変更権限probeと解放確認を共有。
 * Ver.01.14.00 Shunji Ogawa  2026/10/15  fake復旧前の有限同期とjoin後の低位観測を共有。
 * Ver.01.15.00 Shunji Ogawa  2026/10/16  索引通信結果の可視導線と同版publicationの画面受入を追加。
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once
#include <Windows.h>
#include "platform/provider_worker_index_internal.h"
#include "test_framework.h"
#include <chrono>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
namespace drivercrate::test {
// 製品構成と独立取得targetには候補／導入fixtureの入口を宣言しない。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
/** @brief 成功DTOを作らず原低位APIだけへ与える有限な状態変更です。 */
enum class SignedIndexBindingNativeCase {
	/// Extension登録後のbase stageと指定API内で実一byte書換を試みます。
	EXTENSION_REGISTERED_WRITE_PROBE,
	/// 同地点でDELETE権限のopenだけを試み、実削除は行いません。
	EXTENSION_REGISTERED_DELETE_PROBE,
	/// 現在版が候補と同版でも指定base APIを省略しないことを確認します。
	EXTENSION_BASE_ALREADY_CURRENT,
	/// 他nodeのCompatible読取失敗を保持し、DriverStoreだけが既知positive根拠を発行します。
	INDEX_VERIFIED_PARTIAL,
	/// 一つの公表IDを二つのpresent nodeへexact一致させ取得候補を拒否します。
	INDEX_NON_UNIQUE,
	/// SYSTEM同名INFを二か所に観測する曖昧入力です。
	DEPENDENCY_AMBIGUOUS,
	/// SYSTEM署名の独立検査を拒否します。
	DEPENDENCY_SIGNATURE_REJECTED,
	/// SYSTEM既存宛先byteを対応Storeと異ならせます。
	DEPENDENCY_PAYLOAD_CHANGED,
	/// 同runの終了OS文脈を変化させます。
	DEPENDENCY_CONTEXT_CHANGED,
	/// 同runの終了native architectureだけを変化させます。
	DEPENDENCY_ARCHITECTURE_CHANGED,
	/// 同runの終了client/serverだけを変化させます。
	DEPENDENCY_SERVER_CHANGED,
	/// 同runの終了OS minor versionだけを変化させます。
	DEPENDENCY_OS_CHANGED,
	/// 公表後の同保護component INF実byteを変更します。
	DEPENDENCY_PACKAGE_CHANGED,
	/// 同元署名検査後のCAT/署名者arrayに有限NULがない応答です。
	DEPENDENCY_SIGNER_UNTERMINATED,
	/// 同元署名検査後の署名者名だけを空にします。
	DEPENDENCY_SIGNER_EMPTY,
	/// 同元rootの終端署名応答だけ全非NULにします。
	DEPENDENCY_SIGNER_RECHECK_UNTERMINATED,
	/// 同元rootの終端署名応答だけ署名者空にします。
	DEPENDENCY_SIGNER_RECHECK_EMPTY,
	/// OS観測を未充足にします。
	DEPENDENCY_NOT_OBSERVED,
	/// 既知現在driverの通常指定導入です。
	NORMAL,
	/// 必要roleの二番目stageだけを拒否します。
	REQUIRED_STAGE_PARTIAL,
	/// 必要roleの選択base APIだけを拒否します。
	REQUIRED_BASE_FAILURE,
	/// base指定APIのFALSEとGetLastError欠落を返し、成功への換算を拒否します。
	REQUIRED_BASE_DIAGNOSTIC_MISSING,
	/// 元親へ結合した必要SWC子APIだけを拒否します。
	REQUIRED_CHILD_FAILURE,
	/// 必要SWC子がWindowsへまだ列挙されない状態です。
	REQUIRED_CHILD_PENDING,
	/// 同SWC IDの子が元選択親に属さない状態です。
	REQUIRED_WRONG_PARENT,
	/// 同ID/同親のpresent必要子を二つ返し、一意選択を拒否します。
	REQUIRED_CHILD_AMBIGUOUS,
	/// 基本指定API後の元親でDN_STARTEDだけを欠かします。
	REQUIRED_PARENT_NOT_STARTED,
	/// 原サービスEXE byteを変えず完全署名期待hashだけを不一致にします。
	SERVICE_EXE_MEMBER_FAILURE,
	/// 原EXE実hashを保ったまま別INF ownerへ結び、CAT member照合で拒否します。
	SERVICE_EXE_OTHER_OWNER,
	/// 公表後に同保護閉包のサービスEXE実byteだけを変更します。
	SERVICE_EXE_HASH_CHANGED,
	/// 二deviceとも成功する共有指定導入です。
	SHARED_SUCCESS,
	/// 元compatible nodeの基本名を空にします。
	SECTION_EMPTY,
	/// 元compatible nodeの基本名を安全な節文法外にします。
	SECTION_INVALID,
	/// Modelsにはあるが実節がない基本名を返します。
	SECTION_MISSING_FALLBACK,
	/// 同名INFを別の完全pathへ返します。
	SECTION_OTHER_INF,
	/// 同deviceでWindowsが返す別Models基本名を選びます。
	SECTION_OTHER_MODEL,
	/// 基本名ではなく装飾済み節を誤って返します。
	SECTION_DECORATED,
	/// 別architectureのModels基本名だけを返します。
	SECTION_OTHER_OS,
	/// 固定SectionName配列を範囲内NULなしへ変更します。
	SECTION_UNTERMINATED,
	/// static detailを書込んでも可変IDの全取得をFALSEで拒否します。
	SECTION_DETAIL_INCOMPLETE,
	/// 固定INF完全path配列を範囲内NULなしへ変更します。
	SECTION_INF_UNTERMINATED,
	/// 公表後に元compatible nodeの基本名だけを変更します。
	SECTION_CHANGED,
	/// 二deviceの異なる元基本名を同共有取得物へ結び両方成功します。
	SHARED_SECTION_SUCCESS,
	/// import-only CATの原member hashだけを拒否します。
	IMPORT_MEMBER_FAILURE,
	/// 公表後に同保護閉包のimport-only INF実byteを変更します。
	IMPORT_HASH_CHANGED,
	/// Present/Code28/全現在属性欠損/installed node空です。
	INITIAL,
	/// 現在nodeがあるのに版だけ欠損しています。
	BLANK_CURRENT,
	/// Code28/属性欠損に反してinstalled nodeが存在します。
	CONTRADICTORY_NODE,
	/// 公表後に現在driverが追加されます。
	DRIVER_ADDED,
	/// 公表後にpresent状態を失います。
	DISAPPEARED,
	/// Driver key読取が元ACCESS_DENIEDで失敗します。
	PROPERTY_FAILURE,
	/// 候補rank読取が元NOT_FOUNDで失敗します。
	MISSING_RANK,
	/// 正常byteをINF登録root外へ返します。
	STAGE_EXTERNAL,
	/// 登録root内の返却byteを変更します。
	STAGE_CHANGED,
	/// 登録後の指定node版を変更します。
	STAGE_WRONG_NODE,
	/// 登録後の候補rankを変更します。
	STAGE_WRONG_RANK,
	/// Stage返却長を終端と矛盾させます。
	STAGE_BAD_LENGTH,
	/// 復旧終了だけ元ACCESS_DENIEDで失敗します。
	RESTORE_END_FAILURE,
	/// 二番目INFだけWindows互換nodeがありません。
	MULTI_NONAPPLICABLE,
	/// 二番目INFだけWindows観測が失敗します。
	MULTI_UNKNOWN,
	/// 全INFにWindows互換nodeがありません。
	MULTI_ALL_NONAPPLICABLE,
	/// 原installer署名だけを拒否します。
	INSTALLER_SIGNATURE_FAILURE,
	/// 実CAT memberの元byteと完全署名fixture期待hashだけを異ならせます。
	CAB_MEMBER_FAILURE,
	/// 原signerだけを期待publisherと異ならせます。
	INSTALLER_PUBLISHER_FAILURE,
	/// 原CreateProcessWだけをACCESS_DENIEDで拒否します。
	INSTALLER_LAUNCH_FAILURE,
	/// 正式Class不存在と完全な未導入証拠を返します。
	INITIAL_CLASS_MISSING,
	/// 正式Unknown名/GUIDと完全な未導入証拠を返します。
	INITIAL_CLASS_UNKNOWN,
	/// Scan後のClass読取だけをACCESS_DENIEDで拒否します。
	CLASS_PROPERTY_FAILURE,
	/// Scan後のClassだけを不正なUINT32型へ変更します。
	CLASS_PROPERTY_INVALID,
	/// Scan後のClass必要長だけを有限上限超過へ変更します。
	CLASS_PROPERTY_LIMIT,
	/// Scan後のClassを正式不存在でなく空文字へ変更します。
	CLASS_PROPERTY_EMPTY,
	/// Scan後の既知Class名と未知GUIDを矛盾させます。
	CLASS_CONTRADICTORY,
	/// Scan後のCode28だけを別の問題へ変更します。
	INITIAL_NOT_CODE28,
	/// Scan後にdriver keyだけを存在させます。
	INITIAL_DRIVER_KEY_PRESENT,
	/// Scan後のinstalled-only一覧に実nodeを返します。
	INITIAL_INSTALLED_NODE,
	/// Scan後のinstalled-only列挙だけをACCESS_DENIEDで拒否します。
	INITIAL_ENUMERATION_FAILURE,
	/// Scan後に原PnP IDだけを別の人工IDへ変更します。
	INITIAL_PNP_CHANGED,
	/// 元実INF読取の返却Class名を内容Classと異ならせます。
	INF_CLASS_MISMATCH,
	/// 元単一INF一覧の返却ClassGUIDを実INFと異ならせます。
	NATIVE_CLASS_MISMATCH,
	/// 公表後の元Class観測だけを既知Classへ変更します。
	INITIAL_CLASS_CHANGED,
	/// 公表後に既知現在driverを追加します。
	INITIAL_DRIVER_ADDED,
	/// 公表後にpresent属性だけを失います。
	INITIAL_DISAPPEARED,
	/// Class未確定初回の復旧終了だけを拒否します。
	INITIAL_RESTORE_END_FAILURE,
	/// Class未確定の二device共有で二番目指定導入だけ失敗します。
	INITIAL_SHARED_PARTIAL,
	/// Scan後の元Classを候補と異なる既知Netへ変更します。
	KNOWN_CLASS_MISMATCH,
	/// Scan後のClassGUID読取だけをACCESS_DENIEDで拒否します。
	CLASS_GUID_FAILURE,
	/// Class未確定の発行時状態をstage直後だけ変更します。
	INITIAL_CLASS_AFTER_STAGE,
	/// 原record/INFと同じ1.0.0.0を現在版へ返す通常deviceです。初回条件ではありません。
	NORMAL_SAME_VERSION,
} ;
/** @brief 元workerの低位callを同operation終端後だけ読み取る有限観測です。 */
struct SignedIndexBindingObservation {
	/// 指定INFのfake stage回数。
	std::uint32_t							 stages{} ;
	/// 非null指定driverのfake DiInstallDevice回数。
	std::uint32_t							 installs{} ;
	/// Fake Windows検索handle生成数。
	std::uint32_t							 opens{} ;
	/// 同handleの解放数。
	std::uint32_t							 closes{} ;
	/// 復旧fake開始数。
	std::uint32_t							 restoreBegins{} ;
	/// 復旧fake終了数。
	std::uint32_t							 restoreCompletes{} ;
	/// 元stageのexact INF path、指定node、provider、版、flagsを一致させた場合trueです。
	bool									 specifiedBindingMatches{} ;
	/// 同workerの署名wrapper呼出し数。停止前だけ観測します。
	driver_package_signature_detail::Receipt signature ;
	/// 各元deviceの指定導入call数です。未選択deviceの0を別観測します。
	std::array<std::uint32_t, 2U>			 deviceInstalls{} ;
	/// 空pathとinstalled-only flagsを低位fakeで照合した現在node照会回数です。
	std::uint32_t							 installedOnlyQueries{} ;
	/// Windowsの完全rankを同元compatible nodeへ照会した低位call数です。
	std::uint32_t							 rankCalls{} ;
	/// 同元PACKAGE必要INFへの独立署名観測回数です。
	std::uint32_t							 dependencyPackageObservations{} ;
	/// SYSTEM必要節の実payloadと既存宛先の全CAT検査回数です。
	std::uint32_t							 dependencySystemEffectChecks{} ;
	/// SYSTEM必要INFをstageしようとした低位call数です。正常SYSTEMでは0を要求します。
	std::uint32_t							 dependencySystemStageCalls{} ;
	/// 完全低位表のOS versionへ到達した呼出し数です。
	std::uint32_t							 dependencyVersionCalls{} ;
	/// PACKAGE/SYSTEMを問わず依存INF署名へ到達した呼出し数です。
	std::uint32_t							 dependencyInfCalls{} ;
	/// 依存CATの独立署名へ到達した呼出し数です。
	std::uint32_t							 dependencyCatalogCalls{} ;
	/// 完全低位表の隔離Windows起点照会回数です。
	std::uint32_t							 dependencyWindowsDirectoryCalls{} ;
	/// SYSTEM INFの対応Storeを独立に再照会した回数です。
	std::uint32_t							 dependencyDriverStoreCalls{} ;
	/// 元署名応答のCAT/署名者のarray内有限NULと非空条件が全callで成立した場合trueです。
	bool									 dependencySignerResponsesValid{true} ;
	/// PACKAGE署名応答のCAT終端/署名者終端/非空二条件を各bitへ記録します。
	std::uint32_t							 dependencySignerMask{} ;
	/// 指定device再確認と分ける全present inventory開始数です。自動全scanの増分を確認します。
	std::uint32_t							 allPresentInventoryOpens{} ;
	/// 登録Extensionへの変更権限openを試みた回数です。
	std::uint32_t							 registeredExtensionProbes{} ;
	/// 実file共有規則が変更権限openを拒否した回数です。
	std::uint32_t							 registeredExtensionBlocked{} ;
	/// 最後の変更権限openの元Windows診断です。
	DWORD									 registeredExtensionError{} ;
	/// 各probe前後の登録INF全byte hashが一致した場合trueです。
	bool									 registeredExtensionBytesUnchanged{true} ;
	/// 元base現在版が候補1.0.0.0と同版に固定された場合trueです。
	bool									 baseInitiallySameVersion{} ;
} ;
/** @brief 完全installer低位表の非機密観測です。 */
struct SignedIndexInstallerObservation {
	/// 実processを作らない低位fake呼出し数です。
	std::uint32_t launches{} ;
	/// 同process/thread二handleのfake解放数です。
	std::uint32_t closes{} ;
	/// 全原byte・policy・exact command条件を満たした場合trueです。
	bool		  valid{true} ;
} ;
/** @brief 完全低位fakeと実command queueを所有する内部fixtureです。 */
struct SignedIndexBindingWorker {
	/// 同worker終端後だけ読む完全installer低位観測です。
	std::function<SignedIndexInstallerObservation()> observeInstaller ;
	/// Windowと同じ実worker。停止後は署名receiptを参照しません。
	std::unique_ptr<ProviderWorker>					 worker ;
	/// 同operation終端後かつworker停止前の同期観測関数。
	std::function<SignedIndexBindingObservation()>	 observe ;
	/// Workerをstop/joinした後だけ読む低位counterです。破棄済み署名scopeを参照しません。
	std::function<SignedIndexBindingObservation()>	 observeAfterStop ;
	/// Worker停止後に全固定集合と登録INFの変更非共有handle解放を確認します。署名pointerを参照しません。
	std::function<bool()>							 allNativeHandlesClosed ;
	/// 結果DTOに触れず、選択後の原native状態だけを変更します。
	std::function<void()>							 changeNativeState ;
} ;
/** @brief 二deviceまでの固定低位Windows境界を実workerへ結びます。
 * @param[in] services 真署名隔離store・完全HTTP・固定UTCの所有callbackです。
 * @param[in] zip 全member hashを固定する非空原ZIPです。欠損CAT負例は期待表だけを完全にします。
 * @param[in] partial 二record/二deviceを作ります。共有正常条件以外では二番目指定導入だけを失敗させます。
 * @param[in] restoreFailure 復旧開始を拒否しProviderへ到達させません。
 * @param[in] stagingFailure SetupCopyOEMInfWだけを元ERROR_ACCESS_DENIEDで拒否します。
 * @param[in] nativeCase 元Windows property/node/rank/登録先へ与える有限状態です。
 * @param[in] installerPayload 原実byteを完全署名/起動fakeで確認する架空EXE/MSIです。
 * @param[in] observeWorkerStart 低位署名scope開始時の同期観測です。空は何もしません。
 * Worker停止まで所有し、callback自身が借用stateの寿命を保持します。署名検証の返却値を変更しません。
 * @param[in] beforeRestore fake復旧開始直前の有限な同期callbackです。空は何もしません。
 * 同workerだけが呼び、callbackは借用状態を所有します。例外はfake復旧失敗へ変換します。
 * @return 実workerと非機密call観測。Native成功fallbackはありません。
 */
[[nodiscard]] SignedIndexBindingWorker makeSignedIndexBindingWorker(
	provider_worker_index_detail::Services services, std::string_view zip, bool partial = false,
	bool restoreFailure = false, bool stagingFailure = false,
	SignedIndexBindingNativeCase nativeCase = SignedIndexBindingNativeCase::NORMAL,
	std::string_view installerPayload = {}, std::function<void()> observeWorkerStart = {},
	std::function<void()> beforeRestore = {}) ;
/** @brief 真署名reload・実HTTP fake・正常ZIPを通常本体へ接続します。
 * @param[in,out] context Assertion正本です。
 * @param[in] services 真署名store・固定UTC・完全HTTPの依存です。
 * @param[in] zip 非空INF/SYS/CATの実原containerです。
 * @param[in] network Net classの固定fixtureならtrueです。
 */
void runSignedIndexCandidateBindingTests( TestContext						   &context,
										 provider_worker_index_detail::Services services,
										 std::string_view zip, bool network = false) ;
/** @brief 既存完全fake HTTPを新正常候補fixtureへ結合します。
 * @param[in,out] context Assertion正本です。
 * @param[in] store 実commit/reload済み隔離索引storeです。
 * @param[in] nowUtc 固定信頼UTCです。
 * @param[in] zip 実原containerです。
 * @param[in] network Net classの固定fixtureならtrueです。
 */
void runNormalSignedIndexCandidateBindingTests( TestContext						&context,
											   std::shared_ptr<SignedIndexStore> store,
											   std::chrono::sys_seconds			 nowUtc,
											   const std::string &zip, bool network = false) ;
#endif	// defined(DRIVERCRATE_INTERNAL_INDEX_TESTS)
}
