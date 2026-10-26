//------------------------------------------------------------------------------
/**
 * @file collector_user_task.h
 * @brief 現在userの収集Task一件と保護所有取引の契約を定義します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23 新user Taskの登録・修復・解除を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/23 XML限定同値比較と初回pending解除契約を明記。
 * Ver.01.00.02 Shunji Ogawa  2026/10/23 有効既定値の省略と原byte検証候補を分離。
 * Ver.01.01.00 Shunji Ogawa  2026/10/23 別名の汎用日次Task契約と所有schemaを追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/24 現行配置receipt-v3だけの解除契約を明記。
 * Ver.01.01.02 Shunji Ogawa  2026/10/24 未登録Taskは固定名の正常不存在だけを確認。
 * </pre>
 *
 * @note setupだけが使用します。旧管理者Task、Run、Stop、HTTPを扱いません。
 * @see docs/adr/0394-collector-user-task-install-lifecycle.md
 */
//------------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {

/** @brief 保護された先行planへ保存する一取引の固定identityです。 */
struct CollectorUserTaskPlan {
	/// 検査済み実pathの表記を保持する絶対package root。
	std::wstring root ;
	/// 現在processのWindows user SID。
	std::wstring sid ;
	/// 導入元manifestの小文字SHA-256。
	std::wstring manifest ;
	/// SIDとrootから固定導出したScheduler root内の一件。
	std::wstring path ;
	/// TaskのDescriptionにも結合する新規取引GUID。
	std::wstring nonce ;
	/// local時刻の初回15:00。登録時に最低5分先です。
	std::wstring boundary ;
	/// 修復で置き換える旧所有receipt全fieldのhash。初回は空です。
	std::wstring previousOwnership ;
	/// v2専用の汎用検査取得Task。既存v1のnative Actionはfalseです。
	bool		 distributionDaily{} ;
} ;

/** @brief 原XMLとSDDLの変更を拒否する所有receiptのpinです。 */
struct CollectorUserTaskOwnership {
	/// 先行planと完全一致する取引。
	CollectorUserTaskPlan plan ;
	/// Settings/Enabledだけをtrueにした原XMLのhash。
	std::wstring		  enabledXml ;
	/// Settings/Enabledだけをfalseにした原XMLのhash。
	std::wstring		  disabledXml ;
	/// owner/group/DACLの原SDDL hash。
	std::wstring		  sddl ;
} ;

/** @brief 一回の読戻しで得るTaskと非実行状態です。 */
struct CollectorUserTaskSnapshot {
	/// 正常なfile不存在だけがfalseです。
	bool											   exists{} ;
	/// nonce、principal、全定義とSDDL policyが期待値に一致した場合true。
	bool											   contractMatches{} ;
	/// 実TaskのEnabled値。
	bool											   enabled{} ;
	/// Task Schedulerの状態値。disabled1、ready3だけを非実行として受理。
	std::uint32_t									   state{} ;
	/// 現在user Taskの実行instance数。
	std::uint32_t									   instances{} ;
	/// 現在の原XML hash。
	std::wstring									   xml ;
	/// 明示Enabledだけをtrueへ変えた原XML hash。省略時は空です。
	std::wstring									   enabledXml ;
	/// 明示Enabledだけをfalseへ変えた原XML hash。省略時は空です。
	std::wstring									   disabledXml ;
	/// 原SDDL hash。
	std::wstring									   sddl ;
	/// 実Enabled=trueの省略時だけの明示true/false検証hash対。最大32で実原hashとは別です。
	std::vector<std::pair<std::wstring, std::wstring>> omittedEnabledPins ;
} ;

/** @brief 実COMとdefault fakeに共通する同期操作です。 */
struct CollectorUserTaskBackend {
	/// 固定新planだけを保護読取りします。
	std::function<std::optional<CollectorUserTaskPlan>()>					loadPlan ;
	/// 固定新所有receiptだけを保護読取りします。
	std::function<std::optional<CollectorUserTaskOwnership>()>				loadOwnership ;
	/// 新規nonceと未来15:00を持つ取引を一回作ります。
	std::function<CollectorUserTaskPlan( const CollectorUserTaskPlan &)>		freshPlan ;
	/// planをflush・保護読戻ししてから戻ります。
	std::function<void( const CollectorUserTaskPlan &)>						savePlan ;
	/// 所有receiptをflush・保護読戻ししてから戻ります。
	std::function<void( const CollectorUserTaskOwnership &)>					saveOwnership ;
	/// 与えた新名一件だけの実定義と状態を読みます。
	std::function<CollectorUserTaskSnapshot( const CollectorUserTaskPlan &)> read ;
	/// CREATEとIGNORE_REGISTRATION_TRIGGERSでdisabled作成し、元HRESULTを返します。
	std::function<std::int32_t( const CollectorUserTaskPlan &)>				createDisabled ;
	/// 同じ新名のEnabledだけを変更し、元HRESULTを返します。
	std::function<std::int32_t( const CollectorUserTaskPlan &, bool)>		setEnabled ;
	/// 同じ新名だけをDeleteTask(0)へ渡し、元HRESULTを返します。
	std::function<std::int32_t( const CollectorUserTaskPlan &)>				remove ;
	/// 初回境界が現在から最低5分未来ならtrueです。
	std::function<bool( const CollectorUserTaskPlan &)>						future ;
	/// packageの非通信再検査です。状態を書き換えません。
	std::function<void()>													verifyPackage ;
	/// 登録/修復だけで既存native config parserを非通信で呼びます。
	std::function<void()>													verifyConfiguration ;
} ;

/**
 * @brief SIDとrootから任意名を受け付けない新Task identityを作ります。
 * @param[in] root 検査済み絶対root。環境変数展開を含むpathは拒否します。
 * @param[in] sid 現在user SID。
 * @param[in] manifest 小文字SHA-256。
 * @param[in] distributionDaily trueなら別名/別Action/17時のv2汎用収集契約です。
 * @return nonceと境界が空のidentity。
 * @throws std::exception path、SIDまたはhashの不正。
 */
[[nodiscard]] CollectorUserTaskPlan collectorUserTaskIdentity( const std::filesystem::path &root,
															  std::wstring_view			   sid,
															  std::wstring_view			   manifest,
															  bool distributionDaily = false) ;

/**
 * @brief 固定native Actionと日次設定のXMLを非通信で構築します。
 * @param[in] plan 検査済み先行取引。
 * @param[in] enabled 期待する有効値。
 * @return 唯一Action/triggerを持つ固定XML。OSへの登録は行いません。
 * @throws std::exception plan不正。
 */
[[nodiscard]] std::wstring collectorUserTaskXml( const CollectorUserTaskPlan &plan, bool enabled) ;

/**
 * @brief local壁時計値から最低5分未来の初回15時を選びます。
 * @param[in] localFileTime local SYSTEMTIMEをSystemTimeToFileTimeで表した100ns値。
 * @return timezoneを含まないlocal YYYY-MM-DDT15:00:00。
 * @throws std::exception 日時範囲外またはOS変換失敗。
 */
[[nodiscard]] std::wstring collectorUserTaskFirstBoundary( std::uint64_t localFileTime) ;

/**
 * @brief 先行planの閉schemaを有限UTF-8 JSONへ変換します。
 * @param[in] plan 検査する固定取引。
 * @return 保護metadata writerへ渡す原byte。
 * @throws std::exception identity、nonce、境界またはhash不正。
 */
[[nodiscard]] std::string  serializeCollectorUserTaskPlan( const CollectorUserTaskPlan &plan) ;

/**
 * @brief 未知schema/fieldと不正な前receipt hashを拒否してplanを読みます。
 * @param[in] bytes 65536byte以下のUTF-8原byte。
 * @return 閉schemaと全fieldを検査した取引。
 * @throws std::exception 容量、JSON、schemaまたは値の不正。
 */
[[nodiscard]] CollectorUserTaskPlan		parseCollectorUserTaskPlan( std::string_view bytes) ;

/**
 * @brief XML全構造を、既知xs:allと採用済み九既定値だけ同値として比較します。
 * @param[in] actual Schedulerの原XML。
 * @param[in] expected OS parserが展開した固定期待XML。
 * @return 限定同値規則を適用した全構造が一致すればtrue。
 * @throws std::exception 容量、DTD、重複、未知要素/属性/namespaceまたは不正XML。
 * @note 初回契約の検査だけです。所有確認は原XML全byteのhashも要求します。
 */
[[nodiscard]] bool						collectorUserTaskXmlMatches( std::wstring_view actual,
																	std::wstring_view expected) ;

/**
 * @brief 全XML契約を先に検査し、実原hashとEnabledだけの検証候補を分けて作ります。
 * @param[in] actual Schedulerの実原XML。65536文字以下。
 * @param[in] expected 独立した固定期待XML。
 * @param[in] enabled APIで得た実Enabled。
 * @return XMLの読戻し証拠。状態、instance、SDDLは呼出し側が実取得値を設定します。
 * @throws std::exception XML不正、契約不一致、API値不一致または未知省略書式。
 * @note 省略候補をTaskやreceiptへ保存しません。所有は同じ候補対と保護owner両pinの一致が必須です。
 */
[[nodiscard]] CollectorUserTaskSnapshot collectorUserTaskXmlSnapshot( std::wstring_view actual,
																	 std::wstring_view expected,
																	 bool			   enabled) ;

/**
 * @brief 初回SDDLを同じ三principalの閉じたfull-access policyで検査します。
 * @param[in] sddl Schedulerの原owner/group/DACL。
 * @param[in] sid 現在process user SID。
 * @return owner/group一致、protected三ACE、GAまたはWindowsのFILE_ALL_ACCESSだけならtrue。
 * @note 登録後の所有照合はこのpredicateへ戻さず原SDDL hashを使います。
 */
[[nodiscard]] bool isCollectorUserTaskSddlAllowed( std::wstring_view sddl, std::wstring_view sid) ;

/**
 * @brief 有効readbackまで登録し、同一manifestだけの有限修復を行います。
 * @param[in] identity 現在userと検査済みroot/manifestのidentity。
 * @param[in] backend 呼出し期間だけ借用する実またはfake操作。
 * @throws std::exception 衝突、警告HRESULT、所有不明、部分失敗。program/dataを保持します。
 * @note 正常enabledは冪等です。設定やstateのcopy、Run、Stopは行いません。
 */
void			   ensureCollectorUserTask( const CollectorUserTaskPlan	  &identity,
										   const CollectorUserTaskBackend &backend) ;

/**
 * @brief 所有Taskの非実行・削除・正常不存在をfile削除前に確認します。
 * @param[in] identity 現在userとroot/manifest。
 * @param[in] backend 同期借用操作。
 * @return 今回削除した件数0または1。
 * @throws std::exception 所有不明、running/queued、APIまたは読戻し失敗。
 * @note 所有receiptがない初回planは、前所有結合が空で全契約一致のdisabled取引だけ回収します。
 *       plan/receiptが共にない場合は固定名の正常不存在だけを確認し、存在/不明を変更しません。
 */
[[nodiscard]] std::size_t removeCollectorUserTask( const CollectorUserTaskPlan	 &identity,
												  const CollectorUserTaskBackend &backend) ;

/**
 * @brief 保護root上で新user Taskを実登録・修復して有効状態を確認します。
 * @param[in] root 検査済み現行v7導入先。
 * @param[in] manifest 元manifest hash。
 * @param[in] verifyPackage package全byteの同期再検査。
 * @param[in] distributionDaily trueなら別所有のv7汎用日次Taskを扱います。
 * @throws std::exception 保護、入力、COM、所有または登録失敗。
 */
void ensureInstalledCollectorUserTask( const std::filesystem::path &root, std::wstring_view manifest,
									  const std::function<void()> &verifyPackage,
									  bool						   distributionDaily = false) ;

/**
 * @brief 現行配置receiptの所有user Taskだけを実解除します。
 * @param[in] root 検査済み導入先。
 * @param[in] manifest 元manifest hash。
 * @param[in] verifyPackage package全byteの同期再検査。
 * @param[in] distributionDaily trueなら別所有のv7汎用日次Taskを解除します。
 * @return 正常不存在を確認した削除件数。
 * @throws std::exception 旧admin receipt混在、所有または解除失敗。
 */
[[nodiscard]] std::size_t removeInstalledCollectorUserTask(
	const std::filesystem::path &root, std::wstring_view manifest,
	const std::function<void()> &verifyPackage, bool distributionDaily = false) ;

} // namespace drivercrate
