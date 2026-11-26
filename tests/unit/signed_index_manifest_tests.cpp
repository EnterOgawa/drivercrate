//------------------------------------------------------------------------------
/**
 * @file signed_index_manifest_tests.cpp
 * @brief 非永続CNG RSA鍵の実署名でmanifest認証の拒否境界を検査します
 * @version 01.65.01
 * @date 2026/10/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/11  同RAM鍵から実GZip assetの別group検査を追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  同helperで配布recordとUNKNOWN・原hash拒否を追加
 * Ver.01.03.00 Shunji Ogawa  2026/10/11  隔離diskの実DPAPI・原子head・世代拒否を追加
 * Ver.01.04.00 Shunji Ogawa  2026/10/11  実保存snapshotから有限公開ID照合の独立groupを追加
 * Ver.01.05.00 Shunji Ogawa  2026/10/11  実Driver Store秘密属性resolverへ保存snapshotを接続
 * Ver.01.06.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続
 * Ver.01.07.00 Shunji Ogawa  2026/10/12  同RAM署名と隔離storeでv2取得descriptor codecを検査
 * Ver.01.08.00 Shunji Ogawa  2026/10/12  真署名索引から共通取得・検査と拒否の内部fixtureを追加
 * Ver.01.09.00 Shunji Ogawa  2026/10/12  私有batch集約と通常workerの非空INF取得fixtureを追加
 * Ver.01.10.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続
 * Ver.01.10.01 Shunji Ogawa  2026/10/12  二通常classへ真正recordを結ぶfixture宣言を説明
 * Ver.01.10.02 Shunji Ogawa  2026/10/14  共通HTML追加後の現reader policy3へ既存期待値を追従
 * Ver.01.11.00 Shunji Ogawa  2026/10/14  同v2署名snapshotへnative部分positive準備の正負を接続
 * Ver.01.11.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける
 * Ver.01.11.02 Shunji Ogawa  2026/10/16  製品固定公開pinとmanifest-only取得拒否を追加
 * Ver.01.12.00 Shunji Ogawa  2026/10/19  旧headの認証移動と世代/中断/拒否回帰を追加
 * Ver.01.13.00 Shunji Ogawa  2026/10/23 実producer原byteをRAM認証/保存/通常workerへ接続
 * Ver.01.13.01 Shunji Ogawa  2026/10/24 現行仕様へ限定し旧版専用の入口・移動を整理
 * Ver.01.14.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合
 * Ver.01.15.00 Shunji Ogawa  2026/10/24  同公開集合の追加native recordを未照合のまま検査
 * Ver.01.16.00 Shunji Ogawa  2026/10/24  原Intel archiveと原期限のhistorical通常app試験を追加
 * Ver.01.16.01 Shunji Ogawa  2026/10/24  新規配布8日上限の秒境界を検証
 * Ver.01.16.02 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示
 * Ver.01.17.00 Shunji Ogawa  2026/10/26 新metadata生成索引の原byteを通常reader/候補adapterへ接続
 * Ver.01.18.00 Shunji Ogawa  2026/10/27  現codec拒否の履歴下限保持とfresh置換を検査
 * Ver.01.18.01 Shunji Ogawa  2026/10/27  追加履歴fixtureを独立stackへ分離
 * Ver.01.18.02 Shunji Ogawa  2026/11/03  通常公開IDと署名済み参照データの境界を更新
 * Ver.01.19.00 Shunji Ogawa  2026/11/03  内容検査INF参照版の通常worker接続を確認
 * Ver.01.20.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.21.00 Shunji Ogawa  2026/11/03  明示非実行formatを元grant/record/hintへ結合
 * Ver.01.22.00 Shunji Ogawa  2026/11/03  匿名CDNの同record二要求と有限予約を接続
 * Ver.01.23.00 Shunji Ogawa  2026/11/03  拡大recordと有限保持quotaを通常経路へ整合
 * Ver.01.24.00 Shunji Ogawa  2026/11/05  独立規約の通常consumerと同意snapshotを有限確認
 * Ver.01.25.00 Shunji Ogawa  2026/11/06  Windows管理driver DATAの通常索引fixtureを追加
 * Ver.01.26.00 Shunji Ogawa  2026/11/06  同INF代替Modelsの通常意図解決と厳密負例を追加
 * Ver.01.27.00 Shunji Ogawa  2026/11/07  全体容量・所有stateと有限進行の契約へ整合
 * Ver.01.28.00 Shunji Ogawa  2026/11/08  同内容候補の表示集約と元一件選択を保持
 * Ver.01.28.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.28.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.28.03 Shunji Ogawa  2026/11/12  外側tupleの取得予約と開始拒否の原理由を接続
 * Ver.01.28.04 Shunji Ogawa  2026/11/12  共通匿名診断revision正本への期待を接続
 * Ver.01.29.00 Shunji Ogawa  2026/11/16  storage通常選択と完全native表の正負・原結果を検証
 * Ver.01.30.00 Shunji Ogawa  2026/11/16  原flags省略MTD二DLLの通常署名経路を検証
 * Ver.01.31.00 Shunji Ogawa  2026/11/17  実recordと同ClockのMTD境界別失効を検証
 * Ver.01.32.00 Shunji Ogawa  2026/11/17  既存祖先と配置親の権限差を有限fakeで検査
 * Ver.01.33.00 Shunji Ogawa  2026/11/18  P3同scan fullhost観測と取得直前拒否を接続
 * Ver.01.33.01 Shunji Ogawa  2026/11/18  Server hostと元正常client recordのOS不一致だけを分離
 * Ver.01.34.00 Shunji Ogawa  2026/11/18  P4七十九入力の実原byte/型付き条件と真署名storeを固定
 * Ver.01.35.00 Shunji Ogawa  2026/11/19  正規Client26200条件の限定consumer入力を真署名索引へ固定
 * Ver.01.36.00 Shunji Ogawa  2026/11/19  24H2最低26100の独立回帰と旧条件を接続
 * Ver.01.36.01 Shunji Ogawa  2026/11/19  Serverの曖昧な候補を同一INFの実Models二節で検証
 * Ver.01.37.00 Shunji Ogawa  2026/11/19  実署名に結合した追加欄と旧GZipの共存を検証
 * Ver.01.38.00 Shunji Ogawa  2026/11/19  追加欄の元識別表記と共通証拠の拒否境界を検証
 * Ver.01.39.00 Shunji Ogawa  2026/11/19  保存原取得に基づく追加索引と旧本文を照合
 * Ver.01.40.00 Shunji Ogawa  2026/11/19  追加欄付き候補の全行期限と旧索引からの振分けを検証
 * Ver.01.41.00 Shunji Ogawa  2026/11/19  保存AWS原索引の認証と元期限を通常取得計画へ結合
 * Ver.01.42.00 Shunji Ogawa  2026/11/19  独自クラスの二つのModels行と元期限を人工署名索引に固定
 * Ver.01.43.00 Shunji Ogawa  2026/11/20  私有Catalog対象の保存と旧公開本文の拒否を検査
 * Ver.01.44.00 Shunji Ogawa  2026/11/20  Catalog対象の異名衝突と元詳細再観測を検査
 * Ver.01.45.00 Shunji Ogawa  2026/11/20  Catalog対象の元Models位置と対象外IDを検査
 * Ver.01.46.00 Shunji Ogawa  2026/11/20  端末用追加欄の元領域と期限・競合を実署名で検査
 * Ver.01.47.00 Shunji Ogawa  2026/11/20  本文とCatalog追加欄の通常スキャン用に原配布物と期限を署名
 * Ver.01.48.00 Shunji Ogawa  2026/11/20  機種別配布条件の私有索引と端末での保留を検査
 * Ver.01.49.00 Shunji Ogawa  2026/11/20  署名済み機種別条件の型番と端末HardwareIdsを検証
 * Ver.01.50.00 Shunji Ogawa  2026/11/20  機種別取得の署名済み元ZIPとINF閉包を追加
 * Ver.01.51.00 Shunji Ogawa  2026/11/20  必須ファームウェア群の私有索引と対象・競合を検査
 * Ver.01.52.00 Shunji Ogawa  2026/11/20  同じファームウェア版を持つ別群を通常照合の署名済み入力へ追加
 * Ver.01.52.01 Shunji Ogawa  2026/11/20  端末別の確認対象と取得保留に使う署名済み入力を明示
 * Ver.01.52.02 Shunji Ogawa  2026/11/20  機種別の署名済み配布物を取得と非通信再検査の試験に接続
 * Ver.01.53.00 Shunji Ogawa  2026/11/21  メディアチェンジャーの署名索引と導入資格を通常操作で検証
 * Ver.01.54.00 Shunji Ogawa  2026/11/21  HDCの通常署名索引と登録後の期限および起動順を検証
 * Ver.01.55.00 Shunji Ogawa  2026/11/22  汎用PnP IDをCatalogの完全対象として照合
 * Ver.01.56.00 Shunji Ogawa  2026/11/22  収集専用Models証拠の容量・対象・公開経路拒否を検証
 * Ver.01.57.00 Shunji Ogawa  2026/11/22  署名済みModels欄の原本文・期限・排他境界を検証
 * Ver.01.58.00 Shunji Ogawa  2026/11/22  実署名のModels専用欄で元証拠とレコードの結合を検証
 * Ver.01.59.00 Shunji Ogawa  2026/11/22  実署名の私有規約証拠と元ZIP・規約の結合を検証
 * Ver.01.60.00 Shunji Ogawa  2026/11/22  保存した私有索引をRAM署名し元ZIPと規約を通常端末試験へ接続
 * Ver.01.61.00 Shunji Ogawa  2026/11/22  同じ配布物を使う二台の機器確認を個別に検証
 * Ver.01.62.00 Shunji Ogawa  2026/11/22  公式ZIPの完全Hardware IDと別名の確認条件を検証
 * Ver.01.63.00 Shunji Ogawa  2026/11/23  WiX規約付き配布の私有署名索引と旧経路の拒否を検証
 * Ver.01.64.00 Shunji Ogawa  2026/11/23  署名済みWiX行と端末の完全Hardware IDを通常スキャンで検証
 * Ver.01.65.00 Shunji Ogawa  2026/11/23  署名済みWiXの原配布ハッシュを通常ワーカーの取得試験へ接続
 * Ver.01.65.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 *
 * @note 秘密鍵はCNG handleのRAM内だけにあり、public blob以外をexportしません
 * Test材料を製品libraryのtrustへ配置せず、製品store・実device・導入を呼びません
 * 明示Intel原archive modeだけは標準Windows署名APIを実行し、証明書読取通信を許可します
 * 保存試験は自作の隔離directoryだけへ実DPAPIとfile APIを使います
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#include "signed_index_manifest_tests.h"
#include "core/operation_controller.h"
#include "platform/local_scan_diagnostics.h"
#include "signed_index_candidate_binding_tests.h"
#include "metadata_inventory_tests.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/driver_package_signature_internal.h"
#include "platform/common_driver_package.h"
#include "platform/com_raii.h"
#include "platform/official_gzip.h"

#include <array>
#include <algorithm>
#include <chrono>
#include <format>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <tuple>
#include <vector>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winioctl.h>
#include <bcrypt.h>
#include <miniz.h>

#include "platform/signed_index_asset_bytes.h"
#include "platform/signed_index_codec_internal.h"
#include "platform/signed_index_manifest_internal.h"
#include "platform/signed_index_records.h"
#include "platform/signed_index_scan.h"
#include "platform/signed_index_record_lookup.h"
#include "platform/signed_index_store_internal.h"
#include "platform/signed_index_json_internal.h"
#include "platform/signed_index_acquisition_adapter.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "platform/index_distribution_trust.h"
#include "local_index_acceptance.h"
#include "test_framework.h"

namespace drivercrate::test {
//------------------------------------------------------------------------------
/**
 * @brief 生成した同一原recordを通常取得候補adapterと完全fake terms HTTPへ通します
 * @param[in,out] context 共通assertion集計先です
 * @param[in] lookup 原manifest/GZipの隔離認証・保存・再読取から得たlookupです
 * @param[in] nowUtc 原発行と同じ信頼UTCです
 * @param[in] body 原recordがpinした人工許諾bodyです。実本文を渡しません
 */
//------------------------------------------------------------------------------
void runMetadataBoundAdapterFixtureTests( TestContext								   &context,
										 std::shared_ptr<const SignedIndexRecordLookup> lookup,
										 std::chrono::sys_seconds nowUtc, const std::string &body) ;

//------------------------------------------------------------------------------
/**
 * @brief 真署名隔離storeを実worker取得fixtureへ渡します
 * @param[in,out] context 共通assertion所有者
 * @param[in] store 実原byte再認証する隔離store
 * @param[in] nowUtc 固定信頼UTC
 * @param[in] zip 文法上有効なINF・参照fileを含む非空原ZIP
 * @param[in] recordCount 元署名recordの有限件数
 * @param[in] skip 完了不一致を先行させる関係数
 */
//------------------------------------------------------------------------------
void runNormalIndexWorkerAcquisitionTests( TestContext					   &context,
										  std::shared_ptr<SignedIndexStore> store,
										  std::chrono::sys_seconds nowUtc, const std::string &zip,
										  std::size_t recordCount, std::size_t skip) ;
//------------------------------------------------------------------------------
/**
 * @brief 真署名lookupを既存完全fake HTTPの取得・seal・共通検査へ渡します
 * @param[in,out] context 共通assertion集計先
 * @param[in] lookup 真署名・隔離reloadから構築した不変lookup
 * @param[in] nowUtc 固定信頼UTC
 * @param[in] scenario 0は通常、1は計算hash不一致、2はsize不一致、3は保留、4はCDN、6は未知hash／sizeです
 */
//------------------------------------------------------------------------------
void runSignedIndexAcquisitionAdapterTests( TestContext									 &context,
										   std::shared_ptr<const SignedIndexRecordLookup> lookup,
										   std::chrono::sys_seconds nowUtc, unsigned scenario) ;
//------------------------------------------------------------------------------
/**
 * @brief 人工再署名recordを元native所有とhost境界の独立期待へ渡します
 * @param[in,out] context 共通assertion集計先です
 * @param[in] snapshot 元CNG/hash/codec/storeを通った人工snapshotです
 * @param[in] nowUtc 人工信頼UTCです
 * @param[in] caseId 固定入力IDです
 * @param[in] platform 独立literalの全六fieldです
 * @param[in] initialExpected 初回分類の固定期待です
 * @param[in] targetExpected 未検査取得targetを作れる期待です
 * @param[in] legacyEnum 旧Server enumだけを試す指定です
 */
//------------------------------------------------------------------------------
void runServerHostIndexFixtureCase( TestContext										&context,
								   std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
								   std::chrono::sys_seconds nowUtc, std::string_view caseId,
								   WindowsHostPlatform platform, IndexHostGateState initialExpected,
								   bool targetExpected, bool legacyEnum) ;
//------------------------------------------------------------------------------
/**
 * @brief 原scanから実claim/dispatchとServer内容HOLDを非通信fakeで確認します
 * @param[in,out] context 共通assertionです
 * @param[in] store 再署名して保存/reloadした原人工storeです
 * @param[in] nowUtc 人工信頼UTCです
 * @param[in] caseId 固定scan境界の一意IDです
 */
//------------------------------------------------------------------------------
void runServerHostScanFixtureCase( TestContext &context, std::shared_ptr<SignedIndexStore> store,
								  std::chrono::sys_seconds nowUtc, std::string_view caseId) ;
//------------------------------------------------------------------------------
/**
 * @brief 非空真正fixtureを元取得/監査/最終拒否へ通す一caseです
 * @param[in,out] context 共通assertion集計です
 * @param[in] store 元RAM署名codecで保存した隔離storeです
 * @param[in] nowUtc 独立fixture UTCです
 * @param[in] zip 原recordへhash/sizeを結んだ実人工archiveです
 * @param[in] caseId 固定matrixの一意IDです
 * @param[in] platform 元六fieldの独立literalです
 * @note pure22とは別に通常所有経路を通し、候補/成功DTOを注入しません
 */
//------------------------------------------------------------------------------
void runServerP4PipelineCase( TestContext &context, std::shared_ptr<SignedIndexStore> store,
							 std::chrono::sys_seconds nowUtc, std::string_view zip,
							 std::string_view caseId, WindowsHostPlatform platform) ;
//------------------------------------------------------------------------------
/**
 * @brief 認証済みAWS原レコードを通常のscanと取得承認に渡します
 * @param[in,out] context 共通試験集計です
 * @param[in] store 原manifestと索引を保存した隔離storeです
 * @param[in] nowUtc 原期限内に固定した試験時計です
 * @param[in] zip hash照合済みの保存ZIPです
 * @param[in] signatureZip 本文前停止を維持したまま既署名fakeを初期化する人工ZIPです
 */
//------------------------------------------------------------------------------
void runSavedAwsConsumerPlan( TestContext &context, std::shared_ptr<SignedIndexStore> store,
							 std::chrono::sys_seconds nowUtc, std::string_view zip,
							 std::string_view signatureZip) ;

//------------------------------------------------------------------------------
/**
 * @brief 認証済みの保存候補を通常のスキャンと同意・取得検査へ接続します
 * @param[in,out] context 共通試験集計です
 * @param[in] store 元索引を保持するRAM署名対応の隔離storeです
 * @param[in] now 元候補期限内の試験時計です
 * @param[in] bodies 元GET順の保存応答です
 * @param[in] device 同じ原INFに結ぶ架空端末です
 * @param[in] retained 元ZIPの一度の取得と独立した次操作での再利用を検査します
 */
//------------------------------------------------------------------------------
void runSavedArchiveTermsConsumer( TestContext &context, std::shared_ptr<SignedIndexStore> store,
								  std::chrono::sys_seconds				 now,
								  const std::array<std::string_view, 3> &bodies,
								  const DistributionBindingDevice &device, bool retained) ;
//------------------------------------------------------------------------------
/**
 * @brief 本文とCatalog追加欄を通常スキャンの端末照合・取得と期限境界で検証します
 * @param[in,out] context 共通の試験集計です
 * @param[in] store 両欄の署名済み原転送byteを再読できる隔離ストアです
 * @param[in] nowUtc 両欄が使用できる開始時刻です
 * @param[in] expiry 別行の期限で決まる追加欄全体の原期限です
 * @param[in] baseZip 本文の元レコードが参照する人工ZIPです
 * @param[in] catalogZip 対象付きレコードが参照する人工ZIPです
 * @param[in] baseDigest 本文の展開前に用意した元JSONのSHA-256です
 * @param[in] supplementDigest 追加欄の元JSON全体のSHA-256です
 */
//------------------------------------------------------------------------------
void runCatalogSupplementConsumerScan( TestContext &context, std::shared_ptr<SignedIndexStore> store,
									  std::chrono::sys_seconds nowUtc,
									  std::chrono::sys_seconds expiry, std::string_view baseZip,
									  std::string_view			 catalogZip,
									  const IndexManifestSha256 &baseDigest,
									  const IndexManifestSha256 &supplementDigest) ;
//------------------------------------------------------------------------------
/**
 * @brief 同じ署名索引から通常スキャンと承認済みWiX検査取得の境界を検証します
 * @param[in,out] context 共通の試験集計です
 * @param[in] store 本文とWiXの元追加欄を保持する隔離ストアです
 * @param[in] nowUtc 両領域の有効期間内に固定する時計です
 * @param[in] expiry 追加欄の原期限と同値の拒否を検査する時刻です
 * @param[in] baseZip 既存の低位署名fakeを初期化する本文用の人工ZIPです
 * @param[in] payload 追加欄の実SHA-256に結び、転送試験に使用する非実行の人工バイト列です
 */
//------------------------------------------------------------------------------
void runWixSupplementConsumerScan( TestContext &context, std::shared_ptr<SignedIndexStore> store,
								  std::chrono::sys_seconds nowUtc, std::chrono::sys_seconds expiry,
								  std::string_view baseZip, std::string_view payload) ;
//------------------------------------------------------------------------------
/**
 * @brief 保存済みDMを通常スキャンと選択済み取得の境界へ渡します
 * @param[in,out] context 共通の試験集計です
 * @param[in] validStore 元証拠と投影が一致する署名済み索引です
 * @param[in] invalidStore 元証拠を欠く追加欄と同じ本文を持つ署名済み索引です
 * @param[in] nowUtc 両領域の有効期間内の試験時刻です
 * @param[in] expiry DMだけが失効する試験時刻です
 * @param[in] baseZip 本文の人工ZIPです。低位署名fakeにも同じbyteを使います
 * @param[in] baseDigest 元本文全体の展開後hashです
 * @param[in] modelsDigest 元DM全体の展開後hashです
 */
//------------------------------------------------------------------------------
void runScopedModelsConsumerScan( TestContext							 &context,
								 const std::shared_ptr<SignedIndexStore> &validStore,
								 const std::shared_ptr<SignedIndexStore> &invalidStore,
								 std::chrono::sys_seconds nowUtc, std::chrono::sys_seconds expiry,
								 std::string_view baseZip, const IndexManifestSha256 &baseDigest,
								 const IndexManifestSha256 &modelsDigest) ;
//------------------------------------------------------------------------------
/**
 * @brief 機種別レコードを同じ端末の通常スキャンと取得計画へ渡します
 * @param[in,out] context 共通の試験集計です
 * @param[in] store 本文と機種別追加欄を再認証する隔離ストアです
 * @param[in] unrecognizedStore 別の配布元が同じ型番を示す対照ストアです
 * @param[in] nowUtc 両欄の有効時刻です
 * @param[in] expiry 機種別追加欄の元期限です
 * @param[in] baseZip 本文の元レコードが参照する人工ZIPです
 * @param[in] scopedZip 機種別追加欄の元レコードが参照する別の人工ZIPです
 */
//------------------------------------------------------------------------------
void runPlatformDeviceConsumerScan( TestContext &context, std::shared_ptr<SignedIndexStore> store,
								   std::shared_ptr<SignedIndexStore> unrecognizedStore,
								   std::chrono::sys_seconds nowUtc, std::chrono::sys_seconds expiry,
								   std::string_view baseZip, std::string_view scopedZip) ;
//------------------------------------------------------------------------------
/**
 * @brief 通常スキャンの端末別確認と、現在のファームウェア群に応じた取得・保留を検証します
 * @param[in,out] context 元スキャンの確認結果を集計します
 * @param[in] store RAM内の試験鍵で確定した本文と機器別追加行です
 * @param[in] nowUtc 両領域が有効な試験時刻です
 * @param[in] baseZip 同じ索引の従来行が参照する試験ZIPです
 * @param[in] scopedZip ファームウェア条件がある元レコードに結合した試験ZIPです
 * @note 端末と通信を試験用の応答へ置き換えます
 */
//------------------------------------------------------------------------------
void runPlatformFirmwareConsumerHold( TestContext &context, std::shared_ptr<SignedIndexStore> store,
									 std::chrono::sys_seconds nowUtc, std::string_view baseZip,
									 std::string_view scopedZip) ;
//------------------------------------------------------------------------------
/**
 * @brief 正規Client最低build条件の実scan・取得と同context拒否を一入力ずつ確認します
 * @param[in,out] context 独立期待のassertion集計先です
 * @param[in] store RAM実署名・通常codecと隔離commitを通した索引です
 * @param[in] nowUtc 原人工索引の有効時刻です
 * @param[in] zip 選択recordのhash/sizeと一致する人工原archiveです
 * @param[in] caseId 事前固定した一意入力IDです
 * @param[in] platform 初回host六fieldの独立literalです
 * @param[in] expectedTargets 事前固定した通常取得計画の件数です
 * @param[in] changedBuild action時の一field差です。旧分母の既定26100を保持します
 * @param[in] planOnly trueは通常計画までの対照で、取得到達へ換算しません
 * @note 成功candidate/reference/lookupを合成せず、完全低位fakeだけを使います
 */
//------------------------------------------------------------------------------
void runClientMinimumBuildConsumerCase( TestContext						&context,
									   std::shared_ptr<SignedIndexStore> store,
									   std::chrono::sys_seconds nowUtc, std::string_view zip,
									   std::string_view caseId, WindowsHostPlatform platform,
									   std::size_t expectedTargets, unsigned changedBuild,
									   bool planOnly) ;
//------------------------------------------------------------------------------
/**
 * @brief 認可を発行しない実identity比較へ二十二の独立literalを渡します
 * @param[in,out] context 共通assertion集計です
 * @note 認証/取得/候補/Provider到達の試験とは別の純粋比較分母です
 */
//------------------------------------------------------------------------------
void runServerP4PureIdentityCases( TestContext &context) ;
//------------------------------------------------------------------------------
/**
 * @brief 既WUA/Storeの保護/結果を新Server条件から隔離して確認します
 * @param[in,out] context 共通assertionです
 * @param[in] store 原client fixtureの隔離storeです
 * @param[in] nowUtc 独立fixture UTCです
 * @param[in] zip 原人工archiveです
 * @note 両native専用scanではhost callback/三LOCALを要求せず完全fakeだけを実行します
 */
//------------------------------------------------------------------------------
void runServerP4NativeIsolationCases( TestContext &context, std::shared_ptr<SignedIndexStore> store,
									 std::chrono::sys_seconds nowUtc, std::string_view zip) ;
namespace {

// 固定検査UTC。OS時計を使わず期限境界を決定的に検査する
const std::chrono::sys_seconds NOW =
	std::chrono::sys_days{std::chrono::year{2026} / 10 / 11} + std::chrono::hours{6} ;
// 架空assetの固定digest。実asset検証を実行したことにはしない
constexpr std::string_view ASSET_HASH =
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ;

//------------------------------------------------------------------------------
/**
 * @brief API失敗をfixture成功へ変換せずunit processへ通知します
 * @param[in] status 元NTSTATUS
 */
//------------------------------------------------------------------------------
void checkNative( const NTSTATUS status)
{
	// 秘密materialを含まない固定説明だけでfixture生成失敗を通知する
	if( status < 0) {
		throw std::runtime_error( "CNG RAM fixture API failed") ;
	}
}

/** @brief 鍵生成・署名に使うCNG resourceをRAM内だけで単独所有します */
class RamKey final {
public:
	/**
	 * @brief 取得前のownerを作ります
	 */
	RamKey() = default ;
	/**
	 * @brief 秘密鍵を含むCNG handleとalgorithmを全経路で解放します
	 */
	~RamKey() noexcept
	{
		// 鍵をalgorithmより先に回収し、秘密鍵を永続化しない
		if( key_ != nullptr) {
			static_cast<void>( BCryptDestroyKey( key_)) ;
		}

		// SHA algorithmも途中のfixture失敗で残さない
		if( sha_ != nullptr) {
			static_cast<void>( BCryptCloseAlgorithmProvider( sha_, 0U)) ;
		}

		// RSA algorithmは最後に回収する
		if( rsa_ != nullptr) {
			static_cast<void>( BCryptCloseAlgorithmProvider( rsa_, 0U)) ;
		}
	}
	/**
	 * @brief 単独所有のためコピー構築を禁止します
	 */
	RamKey( const RamKey &) = delete ;
	/**
	 * @brief 単独所有のためコピー代入を禁止します
	 */
	RamKey &operator=( const RamKey &) = delete ;

	/**
	 * @brief 名前を持たない非永続RSA鍵を一回生成します
	 * @param[in] bits FixtureのRSA bit長
	 * @note Public blobだけをexportします。秘密鍵exportやNCrypt永続storeを使いません
	 */
	void	generate( const ULONG bits)
	{
		checkNative( BCryptOpenAlgorithmProvider( &rsa_, BCRYPT_RSA_ALGORITHM, nullptr, 0U)) ;
		checkNative( BCryptGenerateKeyPair( rsa_, &key_, bits, 0U)) ;
		checkNative( BCryptFinalizeKeyPair( key_, 0U)) ;
		checkNative( BCryptOpenAlgorithmProvider( &sha_, BCRYPT_SHA256_ALGORITHM, nullptr, 0U)) ;
		ULONG bytes{} ;	// Public blob容量。Private blobを要求しない
		checkNative( BCryptExportKey( key_, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0U, &bytes, 0U)) ;
		publicBlob.resize( bytes) ;
		checkNative( BCryptExportKey( key_, nullptr, BCRYPT_RSAPUBLIC_BLOB, publicBlob.data(), bytes,
									&bytes, 0U)) ;
		publicBlob.resize( bytes) ;
	}

	/**
	 * @brief Test側の独立CNG hashで原byteをSHA-256へ結合します
	 * @param[in] bytes 原byte
	 * @return 実CNG digest
	 */
	[[nodiscard]] IndexManifestSha256 digest( const std::string_view bytes) const
	{
		std::vector<std::uint8_t> input( bytes.begin(), bytes.end()) ;	// CNG境界だけの所有copy
		IndexManifestSha256		  hash{} ;								// 固定32byte出力
		checkNative( BCryptHash( sha_, nullptr, 0U, input.data(), static_cast<ULONG>( input.size()),
							   hash.data(), static_cast<ULONG>( hash.size()))) ;
		return hash ;
	}

	/**
	 * @brief 原byteをRAM内private keyで実RSA-PSS署名します
	 * @param[in] bytes 署名対象。再整形しません
	 * @param[in] saltBytes 固定32または拒否fixture用の別salt長
	 * @return 原byteに対する実署名
	 */
	[[nodiscard]] std::vector<std::uint8_t> sign( const std::string_view bytes,
												 const ULONG			saltBytes = 32U) const
	{
		IndexManifestSha256		hash = digest( bytes) ;							// 製品hash APIに依存しない署名対象
		BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, saltBytes} ;	// Native PSS設定
		ULONG					size{} ;										// Key長に由来する実署名長
		checkNative( BCryptSignHash( key_, &padding, hash.data(), static_cast<ULONG>( hash.size()),
								   nullptr, 0U, &size, BCRYPT_PAD_PSS)) ;
		std::vector<std::uint8_t> signature( size) ;	// Secret keyとは別の署名byte
		checkNative( BCryptSignHash( key_, &padding, hash.data(), static_cast<ULONG>( hash.size()),
								   signature.data(), size, &size, BCRYPT_PAD_PSS)) ;
		signature.resize( size) ;
		return signature ;
	}
	/// Test verifierへ渡すpublic blobだけの所有値
	std::vector<std::uint8_t> publicBlob ;

private:
	/// RAMだけのRSA algorithm
	BCRYPT_ALG_HANDLE rsa_{} ;
	/// RAMだけの秘密鍵handle。Exportや保存をしません
	BCRYPT_KEY_HANDLE key_{} ;
	/// RAMだけのSHA-256 algorithm
	BCRYPT_ALG_HANDLE sha_{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief Test側で正規base64を作ります
 * @param[in] bytes 原byte
 * @return 標準alphabetと正規paddingのASCII
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string encodeBase64( const std::span<const std::uint8_t> bytes)
{
	constexpr std::string_view ALPHABET =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ;	// 標準alphabet
	std::string encoded ;														// Test専用所有base64
	// 原byteを三byteずつ走査し、末尾だけをpaddingする
	for( std::size_t offset = 0U; offset < bytes.size(); offset += 3U) {
		const unsigned first = bytes[offset] ;	// 必須第一byte
		const unsigned second =
			offset + 1U < bytes.size() ? bytes[offset + 1U] : 0U ;						// 欠けたbyteはpaddingで表す
		const unsigned third = offset + 2U < bytes.size() ? bytes[offset + 2U] : 0U ;	// 最終byte
		encoded.push_back( ALPHABET[first >> 2U]) ;
		encoded.push_back( ALPHABET[((first & 3U) << 4U) | (second >> 4U)]) ;
		encoded.push_back(
			offset + 1U < bytes.size() ? ALPHABET[((second & 15U) << 2U) | (third >> 6U)] : '=') ;
		encoded.push_back( offset + 2U < bytes.size() ? ALPHABET[third & 63U] : '=') ;
	}

	return encoded ;
}

//------------------------------------------------------------------------------
/**
 * @brief UTF-8原byteをtest側base64へ変換します
 * @param[in] bytes 原UTF-8
 * @return 原byteのbase64
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string encodeText( const std::string_view bytes)
{
	const std::vector<std::uint8_t> input( bytes.begin(),
										  // Const pointer castを使わないcopy
										  bytes.end()) ;
	return encodeBase64( input) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 人工manifest原byteを作ります。Field順は製品契約として固定しません
 * @return 全必須値を持つ架空manifest
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string manifest()
{
	return "{\"schema\":\"driver-index-manifest-v1\",\"repository\":\"EnterOgawa/drivercrate\","
		   "\"channel\":\"driver-index\",\"keyId\":\"fixture-main\",\"generation\":7,\"assetGeneration\":7,"
		   "\"publishedAtUtc\":\"2026-10-11T05:00:00Z\",\"expiresAtUtc\":\"2026-10-25T05:00:00Z\","
		   "\"asset\":{\"tag\":\"index-v1-20261011-" +
		   std::string{ASSET_HASH} +
		   "\",\"name\":\"index.json.gz\",\"compression\":\"gzip\",\"sizeBytes\":123,\"sha256\":\"" +
		   std::string{ASSET_HASH} +
		   "\"},\"quality\":{\"sourceCount\":1,\"recordCount\":3,"
		   "\"metadataOnlyCount\":1,\"contentInspectedCount\":1,\"unconfirmedCount\":1}}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一箇所だけを意図した値へ変える拒否fixtureを作ります
 * @param[in] bytes 元fixture
 * @param[in] before 必ず存在する元断片
 * @param[in] after 変更断片
 * @return 一箇所を変更した所有原byte
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string replaced( std::string bytes, const std::string_view before,
								   const std::string_view after)
{
	const std::size_t position = bytes.find( before) ;	// 意図した唯一の変更位置
	// Test生成不成立をcodec拒否の合格へ読み替えない
	if( position == std::string::npos) {
		throw std::runtime_error( "fixture replacement not found") ;
	}

	bytes.replace( position, before.size(), after) ;
	return bytes ;
}

//------------------------------------------------------------------------------
/**
 * @brief Testで署名済み原byteを有限envelopeへ包みます
 * @param[in] raw 元manifest
 * @param[in] signature 元署名
 * @param[in] keyId 外側ID
 * @return 署名対象を再serializationしない外側JSON
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string envelope( const std::string_view			   raw,
								   const std::span<const std::uint8_t> signature,
								   const std::string_view			   keyId = "fixture-main")
{
	return "{\"schema\":\"driver-index-envelope-v1\",\"keyId\":\"" + std::string{keyId} +
		   "\",\"manifestBytesBase64\":\"" + encodeText( raw) + "\",\"signatureBase64\":\"" +
		   encodeBase64( signature) + "\"}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一拒否ケースで理由と認証receiptの不在を確認します
 * @param[in,out] context 集計先
 * @param[in] result 実native検査結果
 * @param[in] expected 固定拒否理由
 */
//------------------------------------------------------------------------------
void expectRejected( TestContext &context, const SignedIndexManifestResult &result,
					const SignedIndexManifestStatus expected)
{
	DRIVERCRATE_EXPECT( context, result.status == expected) ;
	DRIVERCRATE_EXPECT( context, !result.manifest.has_value()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正RSA整数の値域とCNGの厳格な拒否区分を独立して照合します
 * @param[in,out] context 共通集計先
 * @param[in] result 実CNG認証の結果
 * @param[in] signature 署名とみなして入力した384byte整数
 * @param[in] blob Trustへ使った既知の正常3072bit public blob
 * @note 値域外は元INVALID_PARAMETER、値域内の不一致はINVALID_SIGNATUREを要求します
 */
//------------------------------------------------------------------------------
void expectSignatureIntegerRejected( TestContext &context, const SignedIndexManifestResult &result,
									const std::span<const std::uint8_t> signature,
									const std::span<const std::uint8_t> blob)
{
	constexpr std::size_t MODULUS_OFFSET =
		// 既知blobの指数65537の直後です
		sizeof( BCRYPT_RSAKEY_BLOB) + 3U ;
	// Fixture前提が崩れた場合は値域判定を推測しません
	if( signature.size() != 384U || blob.size() != MODULUS_OFFSET + 384U) {
		throw std::runtime_error( "RSA integer fixture shape failed") ;
	}

	const auto modulus = blob.subspan( MODULUS_OFFSET, 384U) ;	// 独立したtrust public modulusです
	const bool outside =
		!std::lexicographical_compare( signature.begin(), signature.end(), modulus.begin(),
									  // Big-endian整数s>=nです
									  modulus.end()) ;
	const auto expected =
		outside ? SignedIndexManifestStatus::CRYPTO_FAILURE
				: SignedIndexManifestStatus::INVALID_SIGNATURE ;	// 暗号verifierの区分は変更しません
	constexpr NTSTATUS INVALID_PARAMETER_STATUS =
		// 値域外入力のCNG診断です
		static_cast<NTSTATUS>( 0xC000000DU) ;
	constexpr NTSTATUS INVALID_SIGNATURE_STATUS =
		// 値域内不一致のCNG診断です
		static_cast<NTSTATUS>( 0xC000A000U) ;
	const NativeError expectedError = static_cast<NativeError>(
		HRESULT_FROM_NT( outside ? INVALID_PARAMETER_STATUS
								: INVALID_SIGNATURE_STATUS)) ;	// 任意crypto errorへ広げません
	std::cout << "RSA rejected integer range outside: " << outside
			  << ", status: " << static_cast<unsigned>( result.status)
			  << ", error: " << static_cast<std::uint32_t>( result.error) << '\n' ;
	expectRejected( context, result, expected) ;
	DRIVERCRATE_EXPECT( context, result.error == expectedError) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの署名し直した不正manifestを実CNG経路へ渡します
 * @param[in,out] context 集計先
 * @param[in] key RAM内署名鍵
 * @param[in] trust 内部test専用公開鍵集合
 * @param[in] raw 不正schemaまたは意味を持つ原byte
 * @param[in] expected 固定拒否理由
 */
//------------------------------------------------------------------------------
void rejectManifest( TestContext &context, const RamKey &key,
					const std::span<const signed_index_detail::TrustKey> trust,
					const std::string_view raw, const SignedIndexManifestStatus expected)
{
	const auto signedBytes = key.sign( raw) ;	// 不正内容にも正しい実署名を付けて意味層を検査する
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( envelope( raw, signedBytes), NOW,
																  std::nullopt, trust),
				   expected) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 実CNG署名・JSON・base64・期限・世代の正例と拒否を固定時刻で検査します
 * @param[in,out] context 共通unit assertion集計先
 */
//------------------------------------------------------------------------------
void runSignedIndexManifestTests( TestContext &context)
{
	static_assert( !std::is_default_constructible_v<AuthenticatedIndexManifest>) ;
	static_assert( !std::is_constructible_v<AuthenticatedIndexManifest, IndexManifestData>) ;
	const int firstAssertion = context.assertionCount() ;	// このgroupだけの実行件数
	const int firstFailure	 = context.failureCount() ;		// このgroupだけの失敗件数
	RamKey	  mainKey ;										// 秘密鍵はCNG handleのRAMだけ
	RamKey	  otherKey ;									// 別の信頼済み3072bit鍵
	RamKey	  smallKey ;									// 2048bit拒否用だけのRAM鍵
	mainKey.generate( 3072U) ;
	otherKey.generate( 3072U) ;
	smallKey.generate( 2048U) ;
	// 公開byteだけの非owning viewをRAM内の独立SHA実装へ渡します
	const auto				   productDigest = mainKey.digest( std::string_view{
		reinterpret_cast<const char *>( index_distribution_trust::PUBLIC_BLOB.data()),
		index_distribution_trust::PUBLIC_BLOB.size()}) ;
	std::string				   productFingerprint ;			// 所有する小文字hex表現だけです
	constexpr std::string_view HEX = "0123456789abcdef" ;	// 公開digestの表示用です
	// 全32byteを省略せずfingerprintへ結合します
	for( const auto byte : productDigest) {
		productFingerprint += HEX[byte >> 4U] ;
		productFingerprint += HEX[byte & 15U] ;
	}

	DRIVERCRATE_EXPECT( context,
					   index_distribution_trust::PUBLIC_BLOB.size() == 411U &&
						   productFingerprint == index_distribution_trust::PUBLIC_FINGERPRINT) ;
	DRIVERCRATE_EXPECT( context, index_distribution_trust::TRUST_KEYS.size() == 1U &&
									index_distribution_trust::ACQUISITION_KEYS.size() == 1U &&
									index_distribution_trust::ACQUISITION_POLICY_REVISION == 1U &&
									index_distribution_trust::KEY_ID ==
										"distribution-index-" + productFingerprint.substr( 0U, 32U)) ;
	DRIVERCRATE_EXPECT( context, signed_index_detail::productTrustAvailable() &&
									(local_index_profile::ENABLED ||
									 (local_index_profile::TRUST_KEYS.empty() &&
									  local_index_profile::ACQUISITION_KEYS.empty()))) ;
	const std::array<signed_index_detail::TrustKey, 2U> trust{
		{{"fixture-main", mainKey.publicBlob},
		 {"fixture-other", otherKey.publicBlob}}} ;					// Test targetだけの有限公開鍵集合
	const std::string raw			 = manifest() ;					// 人工原manifest
	const auto		  signature		 = mainKey.sign( raw) ;			// 実RSA-PSS salt32署名
	const std::string signedEnvelope = envelope( raw, signature) ;	// 原byteを保つ正例
	const auto		  accepted		 = signed_index_detail::authenticateWithTrustKeys(
		 signedEnvelope, NOW, std::nullopt, trust) ;	// 実CNG正例
	DRIVERCRATE_EXPECT( context, accepted.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	DRIVERCRATE_EXPECT( context, accepted.error == 0) ;
	DRIVERCRATE_EXPECT( context, accepted.manifest.has_value()) ;
	// 正例不成立時は認証receiptを参照せず、このgroupを失敗として終了する
	if( !accepted.manifest.has_value()) {
		return ;
	}

	const auto &data = accepted.manifest->data() ;	// 書換え不可の認証値
	DRIVERCRATE_EXPECT( context, data.manifestBytes == raw) ;
	DRIVERCRATE_EXPECT( context, data.manifestSha256 == mainKey.digest( raw)) ;
	DRIVERCRATE_EXPECT( context, data.generation == 7U && data.assetGeneration == 7U) ;
	DRIVERCRATE_EXPECT( context, data.asset.sizeBytes == 123U && data.asset.name == "index.json.gz") ;
	DRIVERCRATE_EXPECT( context,
					   data.quality.unconfirmedCount == 1U && data.quality.recordCount == 3U) ;
	DRIVERCRATE_EXPECT( context, data.expiresAtUtc - data.publishedAtUtc == std::chrono::days{14}) ;
	expectRejected( context, authenticateSignedIndexManifest( signedEnvelope, NOW, std::nullopt),
				   SignedIndexManifestStatus::UNKNOWN_KEY) ;
	// 既存RAM署名を製品公開keyIdへ変えても真署名成功にはなりません
	const auto productRaw =
		// 他fieldは不変です
		replaced( raw, "fixture-main", index_distribution_trust::KEY_ID) ;
	const auto productEnvelope = envelope( productRaw, mainKey.sign( productRaw),
										  index_distribution_trust::KEY_ID) ;	// RAM署名だけです
	const auto productRejected =
		// 実選択境界です
		authenticateSignedIndexManifest( productEnvelope, NOW, std::nullopt) ;
	DRIVERCRATE_EXPECT( context,
					   (productRejected.status == SignedIndexManifestStatus::UNKNOWN_KEY) ==
							   local_index_profile::ENABLED &&
						   productRejected.status != SignedIndexManifestStatus::AUTHENTICATED &&
						   !productRejected.manifest) ;
	std::cout << "P3 native public pin/trust: local=" << local_index_profile::ENABLED
			  << ", localTrust=" << local_index_profile::TRUST_KEYS.size()
			  << ", localAcquisition=" << local_index_profile::ACQUISITION_KEYS.size()
			  << ", production signature UNCONFIRMED\n" ;

	const IndexManifestHighWater highWater{data.generation,
										   data.manifestSha256} ;	// 副作用なく照合する固定state
	const auto same = signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, highWater,
																	 trust) ;	// 同世代同原byteの正例
	DRIVERCRATE_EXPECT( context, same.status == SignedIndexManifestStatus::AUTHENTICATED &&
									same.manifest.has_value()) ;
	DRIVERCRATE_EXPECT( context, highWater.generation == 7U &&
									highWater.manifestSha256 == data.manifestSha256) ;

	const std::string alternate = replaced( raw, "\"schema\":\"driver-index-manifest-v1\",",
										   "") ;	// Field順を変える正例の本体
	// Schemaを最後のfieldへ移し、標準空白も含めて署名対象の原byteを変える
	const std::string reordered = "\n " + alternate.substr( 0U, alternate.size() - 1U) +
								  ", \"schema\" : \"driver-index-manifest-v1\" }\r\n" ;
	const auto reorderedResult = signed_index_detail::authenticateWithTrustKeys(
		envelope( reordered, mainKey.sign( reordered)), NOW, std::nullopt,
		trust) ;	// 原byteを再整形しない正例
	DRIVERCRATE_EXPECT( context, reorderedResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	DRIVERCRATE_EXPECT( context, reorderedResult.manifest.has_value() &&
									reorderedResult.manifest->data().manifestBytes == reordered) ;
	const std::string escaped = replaced( raw, "EnterOgawa/drivercrate",
										 "EnterOgawa\\/drivercrate") ;	// 標準slash escape正例
	// 標準escapeを含む原byteの独立した認証結果
	const auto		  escapedResult = signed_index_detail::authenticateWithTrustKeys(
		   envelope( escaped, mainKey.sign( escaped)), NOW, std::nullopt, trust) ;
	DRIVERCRATE_EXPECT( context, escapedResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   envelope( reordered, mainKey.sign( reordered)), NOW, highWater, trust),
				   SignedIndexManifestStatus::GENERATION_CONFLICT) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   signedEnvelope, NOW, IndexManifestHighWater{8U, data.manifestSha256}, trust),
				   SignedIndexManifestStatus::GENERATION_ROLLBACK) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   signedEnvelope, NOW, IndexManifestHighWater{0U, data.manifestSha256}, trust),
				   SignedIndexManifestStatus::INVALID_HIGH_WATER) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   signedEnvelope, NOW, IndexManifestHighWater{7U, {}}, trust),
				   SignedIndexManifestStatus::INVALID_HIGH_WATER) ;
	const std::string restored =
		replaced( replaced( raw, "\"generation\":7", "\"generation\":8"), "\"assetGeneration\":7",
				 "\"assetGeneration\":3") ;	// 新manifestが旧assetを参照する正例
	// 新しい世代で旧assetを参照した場合のmanifest認証結果
	const auto restoredResult = signed_index_detail::authenticateWithTrustKeys(
		envelope( restored, mainKey.sign( restored)), NOW, highWater, trust) ;
	DRIVERCRATE_EXPECT( context, restoredResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	DRIVERCRATE_EXPECT( context, restoredResult.manifest.has_value() &&
									restoredResult.manifest->data().assetGeneration == 3U) ;
	const std::string otherRaw =
		// 別の既知IDの正例
		replaced( raw, "fixture-main", "fixture-other") ;
	// 内部固定集合の別鍵で署名した場合の独立結果
	const auto otherResult = signed_index_detail::authenticateWithTrustKeys(
		envelope( otherRaw, otherKey.sign( otherRaw), "fixture-other"), NOW, std::nullopt, trust) ;
	DRIVERCRATE_EXPECT( context, otherResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	const auto wrongKeySignature = otherKey.sign( raw) ;	// 別鍵の原署名を再試行・補正せず保持します
	expectSignatureIntegerRejected( context,
								   signed_index_detail::authenticateWithTrustKeys(
									   envelope( raw, wrongKeySignature), NOW, std::nullopt, trust),
								   wrongKeySignature, mainKey.publicBlob) ;
	const std::vector<std::uint8_t> outsideSignature(
		384U, 255U) ;	// 任意3072bit modulus以上の決定的整数です
	expectSignatureIntegerRejected( context,
								   signed_index_detail::authenticateWithTrustKeys(
									   envelope( raw, outsideSignature), NOW, std::nullopt, trust),
								   outsideSignature, mainKey.publicBlob) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   envelope( raw, signature, "unknown-key"), NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::UNKNOWN_KEY) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   envelope( raw, mainKey.sign( raw, 20U)), NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_SIGNATURE) ;
	auto changedSignature = signature ;	// 一byteだけ改変する署名copy
	changedSignature[0] ^= 1U ;
	expectSignatureIntegerRejected( context,
								   signed_index_detail::authenticateWithTrustKeys(
									   envelope( raw, changedSignature), NOW, std::nullopt, trust),
								   changedSignature, mainKey.publicBlob) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( envelope( raw + " ", signature),
																  NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_SIGNATURE) ;
	changedSignature.pop_back() ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( envelope( raw, changedSignature),
																  NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_SIGNATURE) ;

	const std::array<signed_index_detail::TrustKey, 1U> smallTrust{
		{{"fixture-main", smallKey.publicBlob}}} ;	// 不許可2048bit
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt,
																  smallTrust),
				   SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	const std::array<signed_index_detail::TrustKey, 2U> duplicateTrust{
		{{"fixture-main", mainKey.publicBlob},
		 {"fixture-main", otherKey.publicBlob}}} ;	// 曖昧な内部集合
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt,
																  duplicateTrust),
				   SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	std::vector<std::uint8_t> invalidBlob		 = mainKey.publicBlob ;	// 内部公開blobの拒否fixture
	invalidBlob[sizeof( BCRYPT_RSAKEY_BLOB) + 2U] = 3U ;
	std::array<signed_index_detail::TrustKey, 1U> invalidTrust{
		{{"fixture-main", invalidBlob}}} ;	// 65537以外
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt,
																  invalidTrust),
				   SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	invalidBlob = mainKey.publicBlob ;
	invalidBlob.push_back( 0U) ;
	invalidTrust[0].rsaPublicBlob = invalidBlob ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt,
																  invalidTrust),
				   SignedIndexManifestStatus::INVALID_TRUST_KEY) ;
	invalidBlob = mainKey.publicBlob ;
	BCRYPT_RSAKEY_BLOB privateHeader{} ;	// Public blobにprivate flagを偽装する拒否fixture
	std::memcpy( &privateHeader, invalidBlob.data(), sizeof( privateHeader)) ;
	privateHeader.cbPrime1 = 1U ;
	std::memcpy( invalidBlob.data(), &privateHeader, sizeof( privateHeader)) ;
	invalidTrust[0].rsaPublicBlob = invalidBlob ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt,
																  invalidTrust),
				   SignedIndexManifestStatus::INVALID_TRUST_KEY) ;

	// 署名が成立した不正manifestを意味層まで渡し、固定条件を一つずつ拒否する
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "EnterOgawa/drivercrate", "OtherOwner/drivercrate"),
				   SignedIndexManifestStatus::REPOSITORY_MISMATCH) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"channel\":\"driver-index\"", "\"channel\":\"research\""),
				   SignedIndexManifestStatus::CHANNEL_MISMATCH) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "fixture-main", "fixture-other"),
				   SignedIndexManifestStatus::KEY_MISMATCH) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "driver-index-manifest-v1", "research-index-v3"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-11T05:00:00Z", "2026-10-11T07:00:00Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-25T05:00:00Z", "2026-10-25T05:00:01Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-25T05:00:00Z", "2026-10-11T06:00:00Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-25T05:00:00Z", "2026-10-11T05:00:00Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-11T05:00:00Z", "2026-02-30T05:00:00Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-11T05:00:00Z", "2026-10-11T25:00:00Z"),
				   SignedIndexManifestStatus::INVALID_TIME) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "2026-10-11T05:00:00Z", "2026-10-11T05:00:00+00"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope, std::nullopt,
																  std::nullopt, trust),
				   SignedIndexManifestStatus::TIME_UNAVAILABLE) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"assetGeneration\":7", "\"assetGeneration\":8"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"generation\":0"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"generation\":7.0"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"generation\":7e0"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"generation\":-7"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"generation\":07"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"generation\":7", "\"generation\":18446744073709551616"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"generation\":7", "\"generation\":true"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "index.json.gz", "other.json.gz"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"compression\":\"gzip\"", "\"compression\":\"zip\""),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"sizeBytes\":123", "\"sizeBytes\":33554433"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"sizeBytes\":123", "\"sizeBytes\":0"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "index-v1-20261011-", "index-v1-20260230-"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"sha256\":\"012", "\"sha256\":\"112"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"sha256\":\"0123456789abcdef", "\"sha256\":\"0123456789abcdeF"),
				   SignedIndexManifestStatus::INVALID_ASSET) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"unconfirmedCount\":1", "\"unconfirmedCount\":2"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"recordCount\":3", "\"recordCount\":0"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, "{", SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, raw + "{}",
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"generation\":7", "\"generation\":7,\"generation\":7"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"generation\":7", "\"generation\":7,\"genera\\u0074ion\":7"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"sizeBytes\":123", "\"sizeBytes\":123,\"sizeBytes\":123"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"recordCount\":3", "\"recordCount\":3,\"recordCount\":3"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "\"generation\":7", "\"extra\":1"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "driver-index-manifest-v1", "driver-index-manifest-v1\\q"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "driver-index-manifest-v1", "\\uD800"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, replaced( raw, "driver-index-manifest-v1", "\\uDC00"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, raw + std::string{"\xc0\xaf", 2U},
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust, std::string{"\xef\xbb\xbf", 3U} + raw,
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;
	rejectManifest( context, mainKey, trust,
				   replaced( raw, "\"generation\":7", "\"generation\":null"),
				   SignedIndexManifestStatus::INVALID_MANIFEST) ;

	// 外側は署名対象外でもschema・重複・自己提示keyを厳密に拒否する
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( "{}", NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_ENVELOPE) ;
	expectRejected(
		context,
		signed_index_detail::authenticateWithTrustKeys(
			replaced( signedEnvelope, "fixture-main", "fixture-main\",\"keyId\":\"fixture-main"),
			NOW, std::nullopt, trust),
		SignedIndexManifestStatus::INVALID_ENVELOPE) ;
	expectRejected(
		context,
		signed_index_detail::authenticateWithTrustKeys(
			replaced( signedEnvelope, "\"keyId\":", "\"publicKey\":"), NOW, std::nullopt, trust),
		SignedIndexManifestStatus::INVALID_ENVELOPE) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   replaced( signedEnvelope, "driver-index-envelope-v1", "research-v3"), NOW,
					   std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_ENVELOPE) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( signedEnvelope + "\xff", NOW,
																  std::nullopt, trust),
				   SignedIndexManifestStatus::INVALID_ENVELOPE) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( "", NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::ENVELOPE_SIZE_LIMIT) ;
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys(
					   std::string( INDEX_ENVELOPE_MAX_BYTES + 1U, ' '), NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::ENVELOPE_SIZE_LIMIT) ;
	const std::string oversizedRaw( INDEX_MANIFEST_MAX_BYTES + 1U,
								   ' ') ;	// 外側枠内でもdecoded上限を超えるfixture
	expectRejected( context,
				   signed_index_detail::authenticateWithTrustKeys( envelope( oversizedRaw, signature),
																  NOW, std::nullopt, trust),
				   SignedIndexManifestStatus::MANIFEST_SIZE_LIMIT) ;

	constexpr std::array<std::string_view, 10U> BAD_BASE64{
		"A",	"AAA",	"A===", "AA=A", "AA-_",
		"AA A", "AB==", "AAB=", "====", "AA==AAAA"} ;	// 文法・padding・padbit拒否
	// 各不正base64だけを外側へ差し込み、native codecのdecode拒否を確認する
	for( const auto bad : BAD_BASE64) {
		const std::string invalid =
			// 署名は元のまま保持する
			replaced( signedEnvelope, encodeText( raw), bad) ;
		expectRejected(
			context,
			signed_index_detail::authenticateWithTrustKeys( invalid, NOW, std::nullopt, trust),
			SignedIndexManifestStatus::INVALID_BASE64) ;
	}

	const std::string maxGeneration = replaced(
		raw, "\"generation\":7", "\"generation\":18446744073709551615") ;	// uint64_t上限の正例
	// 整数上限を丸めず受理した場合の独立結果
	const auto maxResult = signed_index_detail::authenticateWithTrustKeys(
		envelope( maxGeneration, mainKey.sign( maxGeneration)), NOW, std::nullopt, trust) ;
	DRIVERCRATE_EXPECT( context, maxResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	const std::string maxManifest =
		raw + std::string( INDEX_MANIFEST_MAX_BYTES - raw.size(), ' ') ;	// 原byte上限ちょうどの正例
	// 原manifestの独立byte上限を満たす場合の結果
	const auto maxManifestResult = signed_index_detail::authenticateWithTrustKeys(
		envelope( maxManifest, mainKey.sign( maxManifest)), NOW, std::nullopt, trust) ;
	DRIVERCRATE_EXPECT( context,
					   maxManifestResult.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	const std::string maxEnvelope =
		signedEnvelope +
		// 外側上限ちょうど
		std::string( INDEX_ENVELOPE_MAX_BYTES - signedEnvelope.size(), ' ') ;
	DRIVERCRATE_EXPECT( context, signed_index_detail::authenticateWithTrustKeys( maxEnvelope, NOW,
																			   std::nullopt, trust)
										.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	std::cout << "Signed index manifest assertions: " << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
}

namespace {

//------------------------------------------------------------------------------
/**
 * @brief 架空原byteをminizで実圧縮し、CRC／ISIZEを持つ単一GZipを作ります
 * @param[in] raw 架空の不変原byte。最大128MiB+1で、混在IDの合法fixtureも扱います
 * @return 実Deflateを持つ単一member。失敗時はtest processへ例外を通知します
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> assetGzip( const std::string_view raw)
{
	// 元fixtureも展開上限+1の独立拒否試験までに限定します
	if( raw.size() > INDEX_ASSET_EXPANDED_MAX_BYTES + 1U) {
		throw std::runtime_error( "synthetic gzip raw limit") ;
	}

	const std::size_t capacity = mz_compressBound(
		// 同文字反復を仮定しない有限圧縮上限です
		static_cast<mz_ulong>( raw.size())) ;
	std::vector<unsigned char> packed( capacity) ;						// Zlib containerの一時所有値
	mz_ulong	packedSize = static_cast<mz_ulong>( packed.size()) ;	// 実圧縮長の格納先
	// 原char byteをminizの読取り型へ借用するtest compressor境界です
	const auto *input = reinterpret_cast<const unsigned char *>( raw.data()) ;
	const int	compressed =
		mz_compress2( packed.data(), &packedSize, input, static_cast<mz_ulong>( raw.size()),
					 MZ_BEST_COMPRESSION) ;	// 実miniz結果
	// 生成失敗を検査対象の拒否と混同しない
	if( compressed != MZ_OK || packedSize < 6U) {
		throw std::runtime_error( "synthetic gzip compression failed") ;
	}

	std::vector<std::byte> gzip{std::byte{0x1f}, std::byte{0x8b}, std::byte{8}, std::byte{0},
								std::byte{0},	 std::byte{0},	  std::byte{0}, std::byte{0},
								std::byte{0},	 std::byte{0xff}} ;	// GZip固定header
	// Zlibのheader二byteとAdler四byteを除いた実raw Deflateだけを移す
	for( std::size_t offset = 2U; offset < packedSize - 4U; ++offset) {
		gzip.push_back( static_cast<std::byte>( packed[offset])) ;
	}

	const std::uint32_t crc = static_cast<std::uint32_t>(
		// 原展開byteの独立CRC32
		mz_crc32( MZ_CRC32_INIT, input, raw.size())) ;
	// CRC32と実原byte数を一値ずつtrailerのlittle endianへ欠落なく追加する
	for( const std::uint32_t value : {crc, static_cast<std::uint32_t>( raw.size())}) {
		// 固定四byteだけを下位側から順に追加する
		for( unsigned shift = 0U; shift < 32U; shift += 8U) {
			gzip.push_back( static_cast<std::byte>( (value >> shift) & 0xffU)) ;
		}
	}

	return gzip ;
}

//------------------------------------------------------------------------------
/**
 * @brief 有効なoptional commentで人工containerを正確な有限長へ広げます
 * @param[in] gzip 実Deflate／CRC／ISIZEを持つ人工member
 * @param[in] sizeBytes 必須の正確なcontainer長。元より大きく最大32MiBです
 * @return 単一memberを維持し、comment以外の原byteを変えないcontainer
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> padAssetGzip( std::vector<std::byte> gzip,
												  const std::size_t		 sizeBytes)
{
	// 境界fixtureの生成失敗をnative検査の合格にしない
	if( sizeBytes <= gzip.size() || sizeBytes > INDEX_ASSET_MAX_BYTES) {
		throw std::runtime_error( "synthetic gzip padding failed") ;
	}

	const std::size_t padding = sizeBytes - gzip.size() ;	// FCOMMENTを含む増加byte数
	gzip[3] |= std::byte{0x10} ;
	gzip.insert( gzip.begin() + 10, padding, std::byte{0x70}) ;
	gzip[10U + padding - 1U] = std::byte{0} ;
	return gzip ;
}

//------------------------------------------------------------------------------
/**
 * @brief Byte列を原byteのままtest hash／署名helperへ借用します
 * @param[in] bytes 呼出し中不変の架空byte
 * @return 元byteに対するchar view。正規化やcopyをしません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string_view assetText( const std::span<const std::byte> bytes)
{
	// Object representationを読取り専用charへ渡すtest hash境界です
	return {reinterpret_cast<const char *>( bytes.data()), bytes.size()} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実圧縮byteを署名に結合し、前段実CNG認証からだけmanifestを取得します
 * @param[in] key RAM内秘密鍵。Public blob以外のexportは行いません
 * @param[in] compressed 架空の原転送byte
 * @param[in] olderAsset 新manifestが旧asset世代を参照する正例の指定
 * @param[in] signedQuality Record試験の署名集計。空は旧byte fixtureの集計を維持します
 * @param[out] originalEnvelope 非null時は、認証に用いた同じ署名入りenvelopeを返します
 * @return 前段が実RSA-PSSとschema／期限を認証したreceipt
 */
//------------------------------------------------------------------------------
[[nodiscard]] AuthenticatedIndexManifest assetManifest( const RamKey					   &key,
													   const std::span<const std::byte> compressed,
													   const bool			  olderAsset	= false,
													   const std::string_view signedQuality = {},
													   std::string *originalEnvelope = nullptr)
{
	const auto hash = key.digest( assetText( compressed)) ;	// Test側の独立実CNG圧縮digest
	constexpr std::string_view HEX = "0123456789abcdef" ;	// 固定ASCII小文字表
	std::string				   hex ;						// 署名対象のasset digest文字列
	// 固定32byteを一byteずつ完全な64桁へ変換する
	for( const auto byte : hash) {
		hex.push_back( HEX[byte >> 4U]) ;
		hex.push_back( HEX[byte & 15U]) ;
	}

	std::string raw = replaced( manifest(), ASSET_HASH, hex) ;	// 固定tag末尾への実digest結合
	raw				= replaced( std::move( raw), ASSET_HASH, hex) ;
	raw				= replaced( std::move( raw), "\"sizeBytes\":123",
							   "\"sizeBytes\":" + std::to_string( compressed.size())) ;
	// 新record groupだけの集計を署名し、既存byte groupの件数を変更しない
	if( !signedQuality.empty()) {
		raw = replaced(
			std::move( raw),
			"{\"sourceCount\":1,\"recordCount\":3,\"metadataOnlyCount\":1,\"contentInspectedCount\":1,\"unconfirmedCount\":1}",
			signedQuality) ;
	}

	// 旧assetの再参照はmanifest世代だけを増やし、asset世代を補正しない
	if( olderAsset) {
		raw = replaced( std::move( raw), "\"generation\":7", "\"generation\":8") ;
	}

	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;				// Test targetだけのRAM public trust
	auto signedEnvelope = envelope( raw, key.sign( raw)) ;	// 同一の署名byteを認証と保存へ渡します
	// 元の実署名を試験用公開鍵へ結び付けた認証の結果
	auto result =
		signed_index_detail::authenticateWithTrustKeys( signedEnvelope, NOW, std::nullopt, trust) ;
	// 前段不成立をasset検査の拒否へ読み替えない
	if( result.status != SignedIndexManifestStatus::AUTHENTICATED || !result.manifest) {
		throw std::runtime_error( "synthetic asset manifest authentication failed") ;
	}

	// 保存試験だけへ実認証に使った原envelopeの所有を移します
	if( originalEnvelope) {
		*originalEnvelope = std::move( signedEnvelope) ;
	}

	return std::move( result.manifest.value()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 拒否理由・元HRESULT・成功receipt不在を別々に確認します
 * @param[in,out] context Assertion集計先
 * @param[in] result 実byte API結果
 * @param[in] expected 期待する独立拒否区分
 * @param[in] error 保持されるべきAPI元HRESULT。入力拒否は0です
 */
//------------------------------------------------------------------------------
void expectAssetRejected( TestContext &context, const IndexAssetBytesResult &result,
						 const IndexAssetBytesStatus expected, const NativeError error = 0)
{
	DRIVERCRATE_EXPECT( context, result.status == expected) ;
	DRIVERCRATE_EXPECT( context, result.error == error) ;
	DRIVERCRATE_EXPECT( context, !result.receipt.has_value()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正GZipにも実hash／署名を付け直し、GZip層そのものの拒否を確認します
 * @param[in,out] context Assertion集計先
 * @param[in] key Test専用RAM秘密鍵
 * @param[in] compressed 不正header／stream／trailerを持つ架空原byte
 * @param[in] expected 独立拒否区分
 * @param[in] error 既存gzip APIの元HRESULT
 */
//------------------------------------------------------------------------------
void rejectSignedGzip( TestContext &context, const RamKey &key,
					  const std::span<const std::byte> compressed,
					  const IndexAssetBytesStatus expected, const NativeError error)
{
	const auto authenticated = assetManifest( key, compressed) ;	// 各改変byteへの実署名と前段認証
	expectAssetRejected( context, authenticateIndexAssetBytes( authenticated, compressed, NOW),
						expected, error) ;
}

//------------------------------------------------------------------------------
/**
 * @brief GZipに試験用追加欄だけを挿入します
 * @param[in] gzip 既存展開byteに対応する原GZipです
 * @param[in] extra XLENと区別する試験用の追加欄本体です
 * @return 元Deflateと追加欄を含む署名用の試験byteです
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> assetWithExtra( std::vector<std::byte>		  gzip,
													const std::vector<std::byte> &extra)
{
	const auto size = extra.size() ;	// RFC欄の独立長です
	// GZipの16ビット長に収まらない試験入力を生成しません
	if( size > 65535U) {
		throw std::runtime_error( "synthetic gzip extra length invalid") ;
	}

	gzip[3] |= std::byte{4} ;
	gzip.insert( gzip.begin() + 10,
				{static_cast<std::byte>( size & 0xffU), static_cast<std::byte>( size >> 8U)}) ;
	gzip.insert( gzip.begin() + 12, extra.begin(), extra.end()) ;
	return gzip ;
}

//------------------------------------------------------------------------------
/**
 * @brief 追加欄を旧展開hashとasset世代、追加欄の期限へ結合します
 * @param[in] key 独立hashを計算する試験用RAM鍵です
 * @param[in] legacy 旧領域の展開byteです
 * @param[in] nested 追加欄の展開byteに対応するGZipです
 * @param[in] expiry 追加欄だけに署名するUTC期限です
 * @param[in] assetGeneration 元資産の世代です。既存の人工索引は7を使用します
 * @return 試験用GZipのXLENに格納する追加欄です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> assetSupplementFrame( const RamKey					&key,
														  const std::string_view		 legacy,
														  const std::vector<std::byte>	&nested,
														  const std::chrono::sys_seconds expiry,
														  const std::uint64_t assetGeneration = 7U)
{
	const auto writeInteger = []( std::vector<std::byte> &out, std::uint64_t value,
								 const unsigned width) {
		// 指定幅の整数を下位バイトから順に書き、追加欄の転送形式を再現します
		for( unsigned index{}; index < width; ++index) {
			out.push_back( static_cast<std::byte>( value & 0xffU)) ;
			value >>= 8U ;
		}
	} ; // 製品側の読取りとは独立した試験用little endian生成です
	std::vector<std::byte> extra{std::byte{'D'}, std::byte{'C'}} ;	// 正規subfieldです
	writeInteger( extra, 49U + nested.size(), 2U) ;
	extra.push_back( std::byte{1}) ;
	writeInteger( extra, assetGeneration, 8U) ;
	// 本文のSHA-256の全バイトを原順で追加欄へ結び付けます
	for( const auto digest : key.digest( legacy)) {
		extra.push_back( std::byte{digest}) ;
	}

	writeInteger( extra, static_cast<std::uint64_t>( expiry.time_since_epoch().count()), 8U) ;
	extra.insert( extra.end(), nested.begin(), nested.end()) ;
	return extra ;
}

//------------------------------------------------------------------------------
/**
 * @brief Raw RSA-PSSと同じ転送byteを用いて追加欄の境界を検査します
 * @param[in,out] context 共通集計先です
 * @param[in] key 試験用RAM鍵です
 */
//------------------------------------------------------------------------------
void testIndexAssetSupplement( TestContext &context, const RamKey &key)
{
	using Status					= IndexAssetSupplementStatus ;
	constexpr std::string_view BASE = "{\"legacy\":true}" ;	// 元の展開byte比較用です
	constexpr std::string_view SUPPLEMENT =
		"{\"candidate\":\"bounded\"}" ;						// 内容意味を持たない試験入力です
	const auto expiry = NOW + std::chrono::seconds{60} ;	// 明示した追加欄だけの期限です
	const auto raw	  = assetGzip( BASE) ;					// 旧readerが読む単一memberです
	const auto frame  = [&]( std::string_view legacy, const std::vector<std::byte> &nested) {
		 return assetSupplementFrame( key, legacy, nested, expiry) ;
	} ; // 同一asset世代の別実署名にも使用します
	const auto expected = frame( BASE, assetGzip( SUPPLEMENT)) ;	// 正規の追加欄です
	const auto complete = assetWithExtra( raw, expected) ;			// 元Deflateを変更しません
	const auto manifest = assetManifest( key, complete, true) ;		// manifest 8、asset 7の復帰です
	// 元の署名が指す同一圧縮バイトを認証した結果
	const auto authenticated = authenticateIndexAssetBytes( manifest, complete, NOW) ;
	DRIVERCRATE_EXPECT( context,
					   authenticated.receipt && authenticated.receipt->hasSupplementFrame()) ;
	// 元転送物の確認に失敗した場合に追加欄の詳細を参照しません
	if( !authenticated.receipt) {
		return ;
	}

	const auto &asset = *authenticated.receipt ;	// 実署名とhashを通ったbyte receiptです
	DRIVERCRATE_EXPECT( context, assetText( asset.expandedBytes()) == BASE &&
									asset.expandedSha256() == key.digest( BASE) &&
									manifest.data().generation == 8U &&
									manifest.data().assetGeneration == 7U) ;
	const auto live = asset.readSupplement( NOW) ;	// 有効期限内の展開です
	DRIVERCRATE_EXPECT( context, live.status == Status::BYTE_VALIDATED && live.error == 0U &&
									live.expiresAtUtc == expiry &&
									assetText( live.expanded) == SUPPLEMENT) ;
	// 同じ認証結果を期限境界、公開前、現在時刻不明で読み直し、理由を照合します
	for( const auto &[time, status] :
		{std::pair{std::optional{expiry}, Status::EXPIRED},
		 std::pair{std::optional{manifest.data().publishedAtUtc - std::chrono::seconds{1}},
				   Status::NOT_YET_VALID},
		 std::pair{std::optional<std::chrono::sys_seconds>{}, Status::TIME_UNAVAILABLE}}) {
		const auto result = asset.readSupplement( time) ;	// 現在時刻の再確認結果です
		DRIVERCRATE_EXPECT( context, result.status == status && result.expanded.empty()) ;
	}

	auto mutated = complete ;	// 旧manifestを使った同長改変です
	mutated[16] ^= std::byte{1} ;
	expectAssetRejected( context, authenticateIndexAssetBytes( manifest, mutated, NOW),
						IndexAssetBytesStatus::HASH_MISMATCH) ;

	const auto check = [&]( const std::vector<std::byte> &gzip, const Status wanted) {
		const auto signedAsset = assetManifest( key, gzip) ;						// 各原byte自身のRSA-PSS署名です
		const auto result = authenticateIndexAssetBytes( signedAsset, gzip, NOW) ;	// 旧展開は独立です
		DRIVERCRATE_EXPECT( context, result.receipt.has_value()) ;
		// 署名認証を通った対照だけを使って追加欄の境界結果を確認します
		if( result.receipt) {
			const auto extra = result.receipt->readSupplement( NOW) ;	// 判定境界ごとの結果です
			DRIVERCRATE_EXPECT( context, extra.status == wanted && extra.expanded.empty()) ;
		}
	} ;
	check( raw, Status::ABSENT) ;
	auto foreign = std::vector{std::byte{'A'}, std::byte{'p'}, std::byte{2}, std::byte{0},
							   std::byte{'D'}, std::byte{'C'}} ;	// 他欄の本文にある同じ文字です
	foreign.insert( foreign.end(), expected.begin(), expected.end()) ;
	check( assetWithExtra( raw, foreign), Status::ABSENT) ;
	// 追加欄の版、世代、原hashとフラグをそれぞれ変え、固有の診断を確認します
	for( const auto &[offset, status] :
		{std::pair{4U, Status::INVALID_FRAME}, std::pair{5U, Status::BINDING_MISMATCH},
		 std::pair{13U, Status::BINDING_MISMATCH}, std::pair{56U, Status::GZIP_REJECTED}}) {
		auto altered = expected ;	// 版、世代、旧hash、内側flagを一つずつ変更します
		altered[offset] ^= std::byte{1} ;
		check( assetWithExtra( raw, altered), status) ;
	}

	auto duplicate = expected ;	// 一個目の長さを維持し、重複subfieldを加えます
	duplicate.insert( duplicate.end(), expected.begin(), expected.end()) ;
	check( assetWithExtra( raw, duplicate), Status::INVALID_FRAME) ;
	auto badCrc = expected ;	// 内側GZipのCRCだけを壊します
	badCrc[badCrc.size() - 8U] ^= std::byte{1} ;
	check( assetWithExtra( raw, badCrc), Status::GZIP_REJECTED) ;
	check( assetWithExtra( raw, frame( BASE, assetGzip( std::string( 40000U, 's')))),
		  Status::EXPANSION_LIMIT) ;
	const std::string oversizedBase( 8000U, 'o') ;	// 追加欄の量で旧展開倍率を満たす対照です
	check( assetWithExtra( assetGzip( oversizedBase), frame( oversizedBase, assetGzip( SUPPLEMENT))),
		  Status::EXPANSION_LIMIT) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実署名からModels専用欄を展開し、従来本文とDCの読取りを照合します
 * @param[in,out] context 共通集計先です
 * @param[in] key 試験用RAM鍵です
 */
//------------------------------------------------------------------------------
void testIndexAssetScopedModels( TestContext &context, const RamKey &key)
{
	using Status					= IndexAssetSupplementStatus ;
	constexpr std::string_view BASE = " {\"legacy\":true}\n" ;	// 空白を含む旧本文です
	constexpr std::string_view MODELS =
		"{\"scopedModels\":true}\n" ;							// 運搬だけを検査する人工データです
	const auto expiry	  = NOW + std::chrono::seconds{60} ;	// Manifestより先に来る元期限です
	const auto baseHash	  = key.digest( BASE) ;					// 本文の期待値は独立CNGで算出します
	const auto modelsHash = key.digest( MODELS) ;				// 専用欄の展開hashです
	const auto plain	  = assetGzip( BASE) ;					// 追加欄を入れる前の圧縮本文です
	const auto nested	  = assetGzip( MODELS) ;				// 追加flagのない単一memberです
	// 従来欄のfixture生成で同じ固定形式と元本文hashを組み立てます
	const auto modelsFrame = [&]( const std::string_view base, const std::vector<std::byte> &gzip,
								 const std::chrono::sys_seconds frameExpiry) {
		auto frame =
			// 識別子の二文字目だけを変えます
			assetSupplementFrame( key, base, gzip, frameExpiry) ;
		frame[1] = std::byte{'M'} ;
		return frame ;
	} ;
	const auto dm		= modelsFrame( BASE, nested, expiry) ;					// 有効な専用欄です
	const auto dc		= assetSupplementFrame( key, BASE, nested, expiry) ;	// 同じ内容の従来欄です
	const auto gzip		= assetWithExtra( plain, dm) ;							// 本文のDeflateとtrailerをそのまま保持します
	const auto manifest = assetManifest( key, gzip, true) ;						// manifest世代8がasset世代7を参照します
	const auto result =
		// 実署名から認証した原byteです
		authenticateIndexAssetBytes( manifest, gzip, NOW) ;
	DRIVERCRATE_EXPECT( context,
					   result.status == IndexAssetBytesStatus::BYTE_VALIDATED && result.receipt) ;
	// 署名と転送内容がそろった場合だけ専用欄の詳細を確認します
	if( !result.receipt) {
		// 認証不成立の場合は後続のreceipt検査を続けません
		return ;
	}

	const auto			  &asset = *result.receipt ;	// 同じ本文を従来と専用の読取りで借用します
	std::vector<std::byte> legacy ;						// 追加欄を受け取らない共通gzipの本文出力です
	DRIVERCRATE_EXPECT( context,
					   decompressOfficialGzip( gzip, INDEX_ASSET_EXPANDED_MAX_BYTES, legacy) == 0U &&
						   assetText( legacy) == BASE) ;
	DRIVERCRATE_EXPECT(
		context, assetText( asset.expandedBytes()) == BASE && asset.expandedSha256() == baseHash &&
					 manifest.data().generation == 8U && manifest.data().assetGeneration == 7U) ;
	DRIVERCRATE_EXPECT( context, !asset.hasSupplementFrame() &&
									asset.readSupplement( NOW).status == Status::ABSENT &&
									asset.hasScopedModelsFrame()) ;
	const auto live = asset.readScopedModels( expiry - std::chrono::seconds{1}) ;	// 元期限直前です
	DRIVERCRATE_EXPECT( context, live.status == Status::BYTE_VALIDATED && live.error == 0U &&
									live.expiresAtUtc == expiry &&
									assetText( live.expanded) == MODELS &&
									live.expandedSha256 == modelsHash) ;
	// 拒否時は部分展開や部分hashも残さないことを確認します
	const auto checkUnavailable = [&]( const IndexAssetSupplementResult &read, const Status wanted) {
		DRIVERCRATE_EXPECT( context, read.status == wanted && read.expanded.empty() &&
										read.expandedSha256 == IndexManifestSha256{}) ;
	} ;
	checkUnavailable( asset.readScopedModels( expiry), Status::EXPIRED) ;
	checkUnavailable( asset.readScopedModels( std::nullopt), Status::TIME_UNAVAILABLE) ;
	checkUnavailable(
		asset.readScopedModels( manifest.data().publishedAtUtc - std::chrono::seconds{1}),
		Status::NOT_YET_VALID) ;
	const auto baseAfterExpiry =
		// 従来本文はまだ有効です
		authenticateIndexAssetBytes( manifest, gzip, expiry) ;
	DRIVERCRATE_EXPECT( context, baseAfterExpiry.receipt &&
									assetText( baseAfterExpiry.receipt->expandedBytes()) == BASE &&
									baseAfterExpiry.receipt->expandedSha256() == baseHash) ;
	const auto manifestExpiry = manifest.data().expiresAtUtc ;	// 元期限より早いmanifestの対照です
	const auto later =
		// Manifestより後まで有効な欄を作ります
		assetWithExtra( plain, modelsFrame( BASE, nested, manifestExpiry + std::chrono::seconds{1})) ;
	const auto laterAsset =
		// 失効前の認証receiptを保持した状態で時刻だけを進めます
		authenticateIndexAssetBytes( assetManifest( key, later), later, NOW) ;
	DRIVERCRATE_EXPECT( context, laterAsset.receipt.has_value()) ;
	// マニフェストの方が早く失効する対照で、有効時刻の境界を確認します
	if( laterAsset.receipt) {
		// Manifestが先に失効する場合も直前と境界を区別します
		DRIVERCRATE_EXPECT(
			context,
			laterAsset.receipt->readScopedModels( manifestExpiry - std::chrono::seconds{1}).status ==
				Status::BYTE_VALIDATED) ;
		checkUnavailable( laterAsset.receipt->readScopedModels( manifestExpiry), Status::EXPIRED) ;
	}

	expectAssetRejected(
		context,
		authenticateIndexAssetBytes( manifest, std::span{gzip}.first( gzip.size() - 1U), NOW),
		IndexAssetBytesStatus::SIZE_MISMATCH) ;
	auto tampered = gzip ;	// 元の署名は維持し、内側CRCの圧縮byteだけを変更します
	tampered[12U + dm.size() - 8U] ^= std::byte{1} ;
	expectAssetRejected( context, authenticateIndexAssetBytes( manifest, tampered, NOW),
						IndexAssetBytesStatus::HASH_MISMATCH) ;
	auto corruptBase = gzip ;	// 外側CRCが不正なら正しいDMがあっても本文を発行しません
	corruptBase[corruptBase.size() - 8U] ^= std::byte{1} ;
	rejectSignedGzip( context, key, corruptBase, IndexAssetBytesStatus::GZIP_REJECTED,
					 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC))) ;

	// 認証できる本文と両読取りの結果を、各欄の対照で同時に確認します
	const auto check = [&]( const std::vector<std::byte> &compressed, const Status wantedModels,
						   const Status wantedLegacy = Status::ABSENT) {
		const auto signedAsset = assetManifest( key, compressed) ;	// 各対照の全圧縮byteを署名します
		const auto checked =
			// 本文の認証結果です
			authenticateIndexAssetBytes( signedAsset, compressed, NOW) ;
		DRIVERCRATE_EXPECT( context, checked.status == IndexAssetBytesStatus::BYTE_VALIDATED &&
										checked.receipt) ;
		// 元本文の認証に失敗した場合は専用欄の読み取りを中断します
		if( !checked.receipt) {
			// 本文が不成立の場合は結果を借用しません
			return ;
		}

		DRIVERCRATE_EXPECT( context, assetText( checked.receipt->expandedBytes()) == BASE &&
										checked.receipt->expandedSha256() == baseHash) ;
		DRIVERCRATE_EXPECT(
			context, checked.receipt->hasScopedModelsFrame() == (wantedModels != Status::ABSENT) &&
						 checked.receipt->hasSupplementFrame() == (wantedLegacy != Status::ABSENT)) ;
		checkUnavailable( checked.receipt->readScopedModels( NOW), wantedModels) ;
		const auto old = checked.receipt->readSupplement( NOW) ;	// 既存DCの読み取り結果です
		// 従来の追加欄が存在する入力では、元データと期限も確認します
		if( wantedLegacy == Status::BYTE_VALIDATED) {
			// DCが単独のときは同じ追加データと元期限を読み出します
			DRIVERCRATE_EXPECT( context, old.status == wantedLegacy && old.error == 0U &&
											old.expiresAtUtc == expiry &&
											assetText( old.expanded) == MODELS &&
											old.expandedSha256 == modelsHash) ;
		} else {
			checkUnavailable( old, wantedLegacy) ;
		}
	} ;
	check( plain, Status::ABSENT) ;
	check( assetWithExtra( plain, dc), Status::ABSENT, Status::BYTE_VALIDATED) ;
	auto unknown = dm ;	// 同じ本文を持つ未予約識別子は無視します
	unknown[1]	 = std::byte{'X'} ;
	check( assetWithExtra( plain, unknown), Status::ABSENT) ;
	// 追加欄の長さ、版、世代、本文ハッシュを個別に変えて拒否位置を確認します
	for( const auto &[offset, wanted] :
		{std::pair{2U, Status::INVALID_FRAME}, std::pair{4U, Status::INVALID_FRAME},
		 std::pair{5U, Status::BINDING_MISMATCH}, std::pair{13U, Status::BINDING_MISMATCH}}) {
		// 欄のLEN、版、asset世代、展開本文hashの一項目だけを変更します
		auto wrong = dm ;	// 各対照は正規欄の新しいコピーです
		wrong[offset] ^= std::byte{1} ;
		check( assetWithExtra( plain, wrong), wanted) ;
	}

	check( assetWithExtra( plain, {std::byte{'D'}, std::byte{'M'}}), Status::INVALID_FRAME) ;
	check( tampered, Status::GZIP_REJECTED) ;
	check(
		assetWithExtra( plain, modelsFrame( BASE, padAssetGzip( nested, nested.size() + 2U), expiry)),
		Status::GZIP_REJECTED) ;
	check( assetWithExtra( plain, modelsFrame( BASE, assetGzip( std::string( 40000U, 's')), expiry)),
		  Status::EXPANSION_LIMIT) ;
	auto dmBeforeDc = dm ;	// 各欄は元のLENを保持するためXLENに二領域あります
	dmBeforeDc.insert( dmBeforeDc.end(), dc.begin(), dc.end()) ;
	check( assetWithExtra( plain, dmBeforeDc), Status::INVALID_FRAME) ;
	auto dcBeforeDm = dc ;	// 旧readerも先頭DCとXLENの不一致を拒否します
	dcBeforeDm.insert( dcBeforeDm.end(), dm.begin(), dm.end()) ;
	check( assetWithExtra( plain, dcBeforeDm), Status::ABSENT, Status::INVALID_FRAME) ;

	const std::string oversizedBase( 8000U, 'o') ;				// DMの圧縮量を含めた場合だけ倍率内に収まります
	const auto		  baseOnly = assetGzip( oversizedBase) ;	// 専用欄を除く実圧縮量の対照です
	const auto		  withDm =
		// 同じ本文とDMです
		assetWithExtra( baseOnly, modelsFrame( oversizedBase, nested, expiry)) ;
	DRIVERCRATE_EXPECT(
		context, oversizedBase.size() > baseOnly.size() * INDEX_ASSET_MAX_COMPRESSION_RATIO &&
					 oversizedBase.size() <= withDm.size() * INDEX_ASSET_MAX_COMPRESSION_RATIO) ;
	const auto tooLarge = static_cast<NativeError>(
		// 既存gzipの上限診断です
		HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
	rejectSignedGzip( context, key, baseOnly, IndexAssetBytesStatus::EXPANSION_LIMIT, tooLarge) ;
	rejectSignedGzip( context, key, withDm, IndexAssetBytesStatus::EXPANSION_LIMIT, tooLarge) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 前段の実CNG認証から実GZip assetのsize／hash／期限／展開上限を検査します
 * @param[in,out] context 共通unit assertion集計先
 * @note 実128MiB境界の人工原byteを使い、record schemaや実deviceのcoverageを測りません
 */
//------------------------------------------------------------------------------
void runSignedIndexAssetBytesTests( TestContext &context)
{
	static_assert( !std::is_default_constructible_v<AuthenticatedIndexAssetBytes>) ;
	static_assert( !std::is_constructible_v<AuthenticatedIndexAssetBytes, IndexManifestData>) ;
	static_assert(
		!std::is_constructible_v<AuthenticatedIndexAssetBytes, AuthenticatedIndexManifest,
								 std::vector<std::byte>, IndexManifestSha256, std::uint64_t>) ;
	const int firstAssertion = context.assertionCount() ;	// 新groupだけの実assertion数
	const int firstFailure	 = context.failureCount() ;		// 新groupだけの実失敗数
	RamKey	  key ;											// Test専用のRAM内3072bit鍵。旧manifest groupを変更しません
	key.generate( 3072U) ;
	testIndexAssetSupplement( context, key) ;
	testIndexAssetScopedModels( context, key) ;
	constexpr std::string_view RAW =
		"  {\"fixture\":true,\"schema\":\"not-an-index\"}\n" ;	// 架空の非索引JSON
	const auto gzip			 = assetGzip( RAW) ;				// 実圧縮された小さい正例
	const auto authenticated = assetManifest( key, gzip) ;		// 本当の前段認証receipt
	auto movedFromManifest	 = authenticated ;					// Move後の根拠欠損を実native APIで再現する独立copy
	const auto movedManifest = std::move( movedFromManifest) ;	// 成功値を持つmove先
	DRIVERCRATE_EXPECT( context,
					   authenticateIndexAssetBytes( movedManifest, gzip, NOW).receipt.has_value()) ;
	const auto movedFromResult =
		// Move元の実検査結果
		authenticateIndexAssetBytes( movedFromManifest, gzip, NOW) ;
	expectAssetRejected( context, movedFromResult,
						IndexAssetBytesStatus::INCOMPLETE_MANIFEST_RECEIPT) ;
	std::cout << "Moved-from asset receipt generated: " << movedFromResult.receipt.has_value()
			  << ", manifest bytes retained: " << !movedFromManifest.data().manifestBytes.empty()
			  << '\n' ;
	const auto accepted =
		// Native byte正例
		authenticateIndexAssetBytes( authenticated, gzip, NOW) ;
	DRIVERCRATE_EXPECT( context, accepted.status == IndexAssetBytesStatus::BYTE_VALIDATED) ;
	DRIVERCRATE_EXPECT( context, accepted.error == 0) ;
	DRIVERCRATE_EXPECT( context, accepted.receipt.has_value()) ;
	// 正例が不成立なら未生成receiptを参照しない
	if( !accepted.receipt) {
		return ;
	}

	const auto &receipt = accepted.receipt.value() ;	// 書換えできない検査結果
	DRIVERCRATE_EXPECT( context, assetText( receipt.expandedBytes()) == RAW) ;
	DRIVERCRATE_EXPECT( context, receipt.expandedSha256() == key.digest( RAW)) ;
	DRIVERCRATE_EXPECT( context, receipt.manifest().data().manifestSha256 ==
									authenticated.data().manifestSha256) ;
	DRIVERCRATE_EXPECT( context, receipt.manifest().data().manifestBytes ==
									authenticated.data().manifestBytes) ;
	DRIVERCRATE_EXPECT( context,
					   receipt.manifest().data().asset.sha256 == key.digest( assetText( gzip))) ;
	DRIVERCRATE_EXPECT( context, receipt.manifest().data().asset.sizeBytes == gzip.size()) ;
	DRIVERCRATE_EXPECT( context, receipt.expandedSha256() != receipt.manifest().data().asset.sha256) ;
	DRIVERCRATE_EXPECT( context,
					   receipt.expandedSha256() != receipt.manifest().data().manifestSha256) ;
	DRIVERCRATE_EXPECT( context, receipt.bytePolicyVersion() == 1U) ;
	DRIVERCRATE_EXPECT( context, receipt.maximumExpandedBytes() == gzip.size() * 128ULL) ;
	DRIVERCRATE_EXPECT( context, receipt.manifest().data().keyId == "fixture-main" &&
									receipt.manifest().data().asset.name == "index.json.gz") ;

	expectAssetRejected( context, authenticateIndexAssetBytes( authenticated, gzip, std::nullopt),
						IndexAssetBytesStatus::TIME_UNAVAILABLE) ;
	expectAssetRejected(
		context,
		authenticateIndexAssetBytes( authenticated, gzip,
									authenticated.data().publishedAtUtc - std::chrono::seconds{1}),
		IndexAssetBytesStatus::NOT_YET_VALID) ;
	expectAssetRejected(
		context,
		authenticateIndexAssetBytes( authenticated, gzip, authenticated.data().expiresAtUtc),
		IndexAssetBytesStatus::EXPIRED) ;
	expectAssetRejected(
		context,
		authenticateIndexAssetBytes( authenticated, gzip,
									authenticated.data().expiresAtUtc + std::chrono::seconds{1}),
		IndexAssetBytesStatus::EXPIRED) ;
	DRIVERCRATE_EXPECT( context, authenticateIndexAssetBytes( authenticated, gzip,
															authenticated.data().publishedAtUtc)
									.receipt.has_value()) ;
	DRIVERCRATE_EXPECT( context, authenticateIndexAssetBytes( authenticated, gzip,
															authenticated.data().expiresAtUtc -
																std::chrono::seconds{1})
									.receipt.has_value()) ;
	expectAssetRejected( context, authenticateIndexAssetBytes( authenticated, {}, NOW),
						IndexAssetBytesStatus::COMPRESSED_SIZE_LIMIT) ;
	expectAssetRejected(
		context,
		authenticateIndexAssetBytes( authenticated, std::span{gzip}.first( gzip.size() - 1U), NOW),
		IndexAssetBytesStatus::SIZE_MISMATCH) ;
	auto altered = gzip ;	// 認証後の同長改変をGZip処理前に拒否する
	altered[10] ^= std::byte{1} ;
	expectAssetRejected( context, authenticateIndexAssetBytes( authenticated, altered, NOW),
						IndexAssetBytesStatus::HASH_MISMATCH) ;
	const auto old = assetManifest( key, gzip, true) ;	// 新manifest8から旧asset7を再参照する
	const auto oldAccepted =
		// 旧asset参照のnative正例
		authenticateIndexAssetBytes( old, gzip, NOW) ;
	DRIVERCRATE_EXPECT( context, oldAccepted.receipt.has_value() &&
									oldAccepted.receipt->manifest().data().generation == 8U &&
									oldAccepted.receipt->manifest().data().assetGeneration == 7U) ;

	const NativeError invalid =
		// 元GZip形式診断値
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	const NativeError crcError =
		// 元CRC診断値
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	const NativeError limit =
		// 元展開枠診断値
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
	auto badCrc = gzip ;	// 実署名を付け直すCRC改変
	badCrc[badCrc.size() - 8U] ^= std::byte{1} ;
	rejectSignedGzip( context, key, badCrc, IndexAssetBytesStatus::GZIP_REJECTED, crcError) ;
	auto badSize = gzip ;	// 宣言ISIZEだけを一byte変更し、実出力量不一致を検査する
	badSize[badSize.size() - 4U] ^= std::byte{1} ;
	rejectSignedGzip( context, key, badSize, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	auto members = gzip ;	// 単一member限定の拒否fixture
	members.insert( members.end(), gzip.begin(), gzip.end()) ;
	rejectSignedGzip( context, key, members, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	auto trailing = gzip ;	// Trailer前にDeflate未消費byteを残す
	trailing.insert( trailing.end() - 8, std::byte{0x42}) ;
	rejectSignedGzip( context, key, trailing, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	auto appended = gzip ;	// Container末尾の余剰byteも成功にしない
	appended.push_back( std::byte{0x42}) ;
	const auto appendedManifest = assetManifest( key, appended) ;	// 余剰byteまで署名する
	const auto appendedResult =
		// 実拒否
		authenticateIndexAssetBytes( appendedManifest, appended, NOW) ;
	DRIVERCRATE_EXPECT( context, appendedResult.status != IndexAssetBytesStatus::BYTE_VALIDATED) ;
	DRIVERCRATE_EXPECT( context, !appendedResult.receipt) ;
	auto badHeader = gzip ;	// 予約flagは既存GZip契約のまま拒否する
	badHeader[3]   = std::byte{0xe0} ;
	rejectSignedGzip( context, key, badHeader, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	auto badMagic = gzip ;	// GZip以外へ暗黙fallbackしない
	badMagic[0]	  = std::byte{0} ;
	rejectSignedGzip( context, key, badMagic, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	auto noName = gzip ;	// Optional nameのNULを持たないheader
	noName[3]	= std::byte{8} ;
	std::fill( noName.begin() + 10, noName.end() - 8, std::byte{0x61}) ;
	rejectSignedGzip( context, key, noName, IndexAssetBytesStatus::GZIP_REJECTED, invalid) ;
	const std::array<std::byte, 1U> shortGzip{
		std::byte{0x1f}} ;	// Size署名が成立してもGZip最小構造未満
	rejectSignedGzip( context, key, shortGzip, IndexAssetBytesStatus::GZIP_REJECTED,
					 static_cast<NativeError>( E_INVALIDARG)) ;

	const std::string ratioRaw( 4096U * 128U, 'r') ;	// Container4096byteの128倍ちょうど
	const auto		  ratioGzip =
		// 有効なcommentで正確な転送長を固定する
		padAssetGzip( assetGzip( ratioRaw), 4096U) ;
	const auto ratioManifest = assetManifest( key, ratioGzip) ;	// 比率境界への実認証
	const auto ratioAccepted =
		// 正確な倍率正例
		authenticateIndexAssetBytes( ratioManifest, ratioGzip, NOW) ;
	DRIVERCRATE_EXPECT( context,
					   ratioAccepted.receipt &&
						   ratioAccepted.receipt->expandedBytes().size() == ratioRaw.size()) ;
	const std::string ratioOver( ratioRaw.size() + 1U, 'r') ;					// 比率上限より実原byteが一byte多い
	const auto ratioOverGzip = padAssetGzip( assetGzip( ratioOver), 4096U) ;	// 実圧縮した超過原byte
	rejectSignedGzip( context, key, ratioOverGzip, IndexAssetBytesStatus::EXPANSION_LIMIT, limit) ;
	{
		const auto maximumCompressed = padAssetGzip(
			gzip, static_cast<std::size_t>( INDEX_ASSET_MAX_BYTES)) ;	// 実32MiBの正確なcontainer
		const auto maximumManifest =
			// 32MiB実hashを署名する
			assetManifest( key, maximumCompressed) ;
		const auto maximumAccepted = authenticateIndexAssetBytes( maximumManifest, maximumCompressed,
																 NOW) ;	// 圧縮量上限正例
		DRIVERCRATE_EXPECT(
			context,
			maximumAccepted.receipt && assetText( maximumAccepted.receipt->expandedBytes()) == RAW &&
				maximumAccepted.receipt->maximumExpandedBytes() == INDEX_ASSET_EXPANDED_MAX_BYTES) ;
		auto oversized = maximumCompressed ;	// 一byte追加で圧縮絶対枠を超える
		oversized.push_back( std::byte{}) ;
		expectAssetRejected( context, authenticateIndexAssetBytes( maximumManifest, oversized, NOW),
							IndexAssetBytesStatus::COMPRESSED_SIZE_LIMIT) ;
	}

	{
		const std::string absoluteRaw( static_cast<std::size_t>( INDEX_ASSET_EXPANDED_MAX_BYTES),
									  'a') ;	// 実128MiBの人工原byte
		const auto		  absoluteGzip = padAssetGzip(
			   // 倍率枠と絶対枠が一致する実圧縮入力
			   assetGzip( absoluteRaw), 1024U * 1024U) ;
		const auto absoluteManifest = assetManifest( key, absoluteGzip) ;	// 実assetへのCNG署名認証
		const auto absoluteAccepted = authenticateIndexAssetBytes(
			absoluteManifest, absoluteGzip, NOW) ;	// 縮小policyでない実128MiB展開
		DRIVERCRATE_EXPECT( context, absoluteAccepted.receipt &&
										absoluteAccepted.receipt->expandedBytes().size() ==
											INDEX_ASSET_EXPANDED_MAX_BYTES) ;
		DRIVERCRATE_EXPECT( context,
						   absoluteAccepted.receipt &&
							   assetText( absoluteAccepted.receipt->expandedBytes()) == absoluteRaw) ;
	}

	{
		const std::string absoluteOver(
			static_cast<std::size_t>( INDEX_ASSET_EXPANDED_MAX_BYTES + 1U),
			'a') ;	// 実128MiB+1原byte
		const auto absoluteOverGzip = padAssetGzip(
			// 比率は許可し絶対128MiBだけを超える
			assetGzip( absoluteOver), 1024U * 1024U + 1U) ;
		rejectSignedGzip( context, key, absoluteOverGzip, IndexAssetBytesStatus::EXPANSION_LIMIT,
						 limit) ;
	}

	std::cout << "Signed index asset byte assertions: " << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
}

namespace {

// 人工hash値は出典やpackageの実検証を表さず、元申告の型付き保持だけを検査する
constexpr std::string_view RECORD_CLAIM_HASH =
	"1111111111111111111111111111111111111111111111111111111111111111" ;
// 原出典byteの元申告。Record原byte hashと混同しない
constexpr std::string_view RECORD_EVIDENCE_HASH =
	"2222222222222222222222222222222222222222222222222222222222222222" ;

//------------------------------------------------------------------------------
/**
 * @brief Test側の独立CNG原hashを小文字hexへ表現します
 * @param[in] key 既存RAM鍵helper。秘密materialをexportしません
 * @param[in] raw 元byte
 * @return 実原bytehashの小文字64桁
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string recordDigest( const RamKey &key, const std::string_view raw)
{
	const auto				   hash = key.digest( raw) ;	// 同じRAM helperの独立実CNG digest
	constexpr std::string_view HEX	= "0123456789abcdef" ;	// 固定hex表
	std::string				   result ;						// Test専用の所有表現
	// 全32byteを原値どおり二桁へ表現する
	for( const auto byte : hash) {
		result.push_back( HEX[byte >> 4U]) ;
		result.push_back( HEX[byte & 15U]) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原record byteだけをentryへ結びます
 * @param[in] key 既存RAM helper
 * @param[in] raw 原UTF-8
 * @param[in] hashOverride Hash取り違え用の明示digest。空は実原hashです
 * @return 原byteを再整形しないbase64 entry
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string recordEntry( const RamKey &key, const std::string_view raw,
									  const std::string_view hashOverride = {})
{
	return "{\"recordBytesBase64\":\"" + encodeText( raw) + "\",\"recordSha256\":\"" +
		   (hashOverride.empty() ? recordDigest( key, raw) : std::string{hashOverride}) + "\"}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空sourceの公開申告またはUNKNOWNを作ります
 * @param[in] id 架空のASCII identity
 * @param[in] unknown 元公式性未確認を保持する指定
 * @return 通信しないtestだけのsource JSON
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string recordSource( const std::string_view id	  = "fixture-source",
									   const bool			  unknown = false)
{
	const std::string evidence =
		unknown
			? R"json({"state":"UNKNOWN","kind":"UNKNOWN","evidenceUrl":"","evidenceSha256":"","reason":"source not verified"})json"
			: R"json({"state":"PUBLISHED","kind":"OFFICIAL_PAGE","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
				  std::string{RECORD_EVIDENCE_HASH} +
				  R"json(","reason":""})json" ;	// 元申告または明示UNKNOWN
	return "{\"sourceId\":\"" + std::string{id} +
		   "\",\"officialOrigin\":\"https://vendor.example/\",\"distributionPage\":\"https://vendor.example/support\"," +
		   "\"officialEvidence\":" + evidence + "}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示既知のtext条件を作ります
 * @param[in] value 固定架空値。Quoteを含みません
 * @return Test用KNOWN JSON
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string recordKnown( const std::string_view value)
{
	return "{\"state\":\"KNOWN\",\"value\":\"" + std::string{value} + "\",\"reason\":\"\"}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空recordの完全な型付き元申告を作ります
 * @param[in] id Source内の架空identity
 * @param[in] identityPublished PnP evidenceの元申告を持つ指定。FalseではUNKNOWNを保持します
 * @param[in] stage 発行側の段階
 * @param[in] source 存在するか拒否用の架空source ID
 * @return Test専用の元record byte
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string distributionRecord( const std::string_view id				  = "metadata",
											 const bool				identityPublished = true,
											 const std::string_view stage  = "METADATA_ONLY",
											 const std::string_view source = "fixture-source")
{
	constexpr std::string_view UNKNOWN =
		R"json({"state":"UNKNOWN","value":"","reason":"not supplied"})json" ;	// 欠損を補完しない条件
	constexpr std::string_view UNKNOWN_HASH =
		// 未知hash
		R"json({"state":"UNKNOWN","sha256":"","evidenceUrl":"","evidenceSha256":"","reason":"not inspected"})json" ;
	const std::string hash =
		R"json({"state":"KNOWN","sha256":")json" + std::string{RECORD_CLAIM_HASH} +
		R"json(","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} + R"json(","reason":""})json" ;	// 型だけを確認する元申告
	const std::string identity =
		identityPublished
			? R"json({"state":"PUBLISHED","kind":"INF","pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}],"classGuid":"{11111111-2222-3333-4444-555555555555}","nestedArchiveIdentity":"","infIdentity":"drivers/fixture.inf","modelSection":"Fixture.NTamd64","evidenceUrl":"https://vendor.example/fixture.inf","evidenceSha256":")json" +
				  std::string{RECORD_EVIDENCE_HASH} + R"json(","reason":""})json"
			// 元公開identityか不足理由
			: R"json({"state":"UNKNOWN","kind":"UNKNOWN","pnpIds":[],"classGuid":"","nestedArchiveIdentity":"","infIdentity":"","modelSection":"","evidenceUrl":"","evidenceSha256":"","reason":"public INF identity missing"})json" ;
	return "{\"schema\":\"driver-index-record-v1\",\"sourceId\":\"" + std::string{source} +
		   "\",\"recordId\":\"" + std::string{id} + "\",\"product\":\"Synthetic fixture\"," +
		   "\"targetOs\":" +
		   (identityPublished ? recordKnown( "WINDOWS_11") : std::string{UNKNOWN}) +
		   ",\"architecture\":" + (identityPublished ? recordKnown( "X64") : std::string{UNKNOWN}) +
		   ",\"driverKind\":" +
		   (identityPublished ? recordKnown( "NORMAL_DRIVER") : std::string{UNKNOWN}) +
		   ",\"version\":" + (identityPublished ? recordKnown( "1.2.3.4") : std::string{UNKNOWN}) +
		   ",\"publishedDate\":" +
		   (identityPublished ? recordKnown( "2026-10-01") : std::string{UNKNOWN}) +
		   ",\"acquisition\":" +
		   (identityPublished ? recordKnown( "STANDARD_INF_ARCHIVE") : std::string{UNKNOWN}) +
		   ",\"packageEvidence\":{\"publishedHash\":" +
		   (identityPublished ? hash : std::string{UNKNOWN_HASH}) +
		   ",\"calculatedHash\":" + (identityPublished ? hash : std::string{UNKNOWN_HASH}) +
		   ",\"size\":" +
		   (identityPublished
				? std::string{R"json({"state":"KNOWN","valueBytes":1234,"reason":""})json"}
				: std::
					  string{R"json({"state":"UNKNOWN","valueBytes":0,"reason":"not inspected"})json"}) +
		   "},\"lastSuccessfulObservationUtc\":" +
		   (identityPublished ? recordKnown( "2026-10-10T03:00:00Z") : std::string{UNKNOWN}) +
		   ",\"inspectionStage\":\"" + std::string{stage} +
		   "\",\"publishedIdentityEvidence\":" + identity + "}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元sourceとentryを配布indexへ包みます
 * @param[in] sources 配列内の架空source JSON
 * @param[in] entries 配列内の原record entry JSON
 * @return 元順序を保持する配布index
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string distributionIndex( const std::string_view sources,
											const std::string_view entries)
{
	return "{\"schema\":\"driver-index-records-v1\",\"assetGeneration\":7,\"sources\":[" +
		   std::string{sources} + "],\"records\":[" + std::string{entries} + "]}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実qualityを前段fixtureの署名fieldへ渡す表現を作ります
 * @param[in] quality 署名する架空集計
 * @return 全5fieldを持つ集計JSON
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string recordQuality( const IndexManifestQuality &quality)
{
	return "{\"sourceCount\":" + std::to_string( quality.sourceCount) +
		   ",\"recordCount\":" + std::to_string( quality.recordCount) +
		   ",\"metadataOnlyCount\":" + std::to_string( quality.metadataOnlyCount) +
		   ",\"contentInspectedCount\":" + std::to_string( quality.contentInspectedCount) +
		   ",\"unconfirmedCount\":" + std::to_string( quality.unconfirmedCount) + "}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実署名と実GZipを通してからだけbyte receiptを作ります
 * @param[in] key 既存RAM鍵helper
 * @param[in] index 原index byte
 * @param[in] quality 前段に署名する集計
 * @return 前段の実認証byte receipt。生成不成立は例外にします
 */
//------------------------------------------------------------------------------
[[nodiscard]] AuthenticatedIndexAssetBytes recordBytes( const RamKey				 &key,
													   const std::string_view	  index,
													   const IndexManifestQuality quality = {
														   1U, 3U, 1U, 1U, 1U})
{
	auto			  gzip	  = assetGzip( index) ;				// 既存helperによる実圧縮
	const std::size_t minimum = (index.size() + 127U) / 128U ;	// 実比率上限を満たすcontainer量
	// 圧縮率の高い人工byteでも既存の128倍policyを変更しない
	if( gzip.size() < minimum) {
		gzip = padAssetGzip( std::move( gzip), minimum) ;
	}

	const auto manifestReceipt =
		// 実CNG認証
		assetManifest( key, gzip, false, recordQuality( quality)) ;
	auto result = authenticateIndexAssetBytes( manifestReceipt, gzip, NOW) ;	// 実GZip／原hash検査
	// Fixture生成失敗を新codec拒否の合格へ読み替えない
	if( result.status != IndexAssetBytesStatus::BYTE_VALIDATED || !result.receipt) {
		throw std::runtime_error( "record fixture byte authentication failed") ;
	}

	return std::move( *result.receipt) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一人工indexを全前段からnative codecへ渡します
 * @param[in] key 既存RAM helper
 * @param[in] index 元byte
 * @param[in] quality 署名集計
 * @return 実codecの結果
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexRecordsResult readRecordFixture( const RamKey &key, const std::string_view index,
												   const IndexManifestQuality quality = {1U, 3U, 1U,
																						 1U, 1U})
{
	const auto bytes = recordBytes( key, index, quality) ;	// 全前段を成功した認証receipt
	return readSignedIndexRecords( bytes, NOW) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一拒否の理由・元診断・receipt不在を独立に確認します
 * @param[in,out] context 集計先
 * @param[in] result 実codec結果
 * @param[in] status 期待拒否区分
 */
//------------------------------------------------------------------------------
void expectRecordsRejected( TestContext &context, const IndexRecordsResult &result,
						   const IndexRecordsStatus status)
{
	DRIVERCRATE_EXPECT( context, result.status == status) ;
	DRIVERCRATE_EXPECT( context, result.error == 0) ;
	DRIVERCRATE_EXPECT( context, !result.receipt) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正indexにも実署名を付け、新schema層そのものの拒否を確認します
 * @param[in,out] context 集計先
 * @param[in] key 既存RAM helper
 * @param[in] index 不正な元index byte
 * @param[in] status 期待拒否区分
 * @param[in] quality 署名集計
 */
//------------------------------------------------------------------------------
void rejectRecordIndex( TestContext &context, const RamKey &key, const std::string_view index,
					   const IndexRecordsStatus	  status,
					   const IndexManifestQuality quality = {1U, 3U, 1U, 1U, 1U})
{
	expectRecordsRejected( context, readRecordFixture( key, index, quality), status) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正recordにも正しい原hashを結び、record schema層の拒否を確認します
 * @param[in,out] context 集計先
 * @param[in] key 既存RAM helper
 * @param[in] raw 不正record原byte
 * @param[in] status 期待拒否区分
 */
//------------------------------------------------------------------------------
void rejectDistributionRecord( TestContext &context, const RamKey &key, const std::string_view raw,
							  const IndexRecordsStatus status)
{
	rejectRecordIndex( context, key, distributionIndex( recordSource(), recordEntry( key, raw)),
					  status, {1U, 1U, 1U, 0U, 0U}) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通readerの実container深さを固定test再帰で確認します
 * @param[in,out] reader 借用test reader
 * @param[in] containers 残る固定container数。Test callerは最大9だけを渡します
 */
//------------------------------------------------------------------------------
void readDepthFixture( signed_index_json::Reader<IndexRecordsStatus> &reader,
					  const unsigned								 containers)
{
	// 最深の一文字値だけで再帰を終える
	if( containers == 0U) {
		static_cast<void>( reader.text( 1U)) ;
		return ;
	}

	constexpr std::array<std::string_view, 1U> FIELDS{"x"} ;	// 固定一field
	// Readerと残container数を同期借用する有限test handler
	reader.object( FIELDS, [&]( const std::size_t) { readDepthFixture( reader, containers - 1U) ; }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 静的取得descriptorの完全な人工元申告を作ります
 * @param[in] unknown 取得情報だけを明示UNKNOWNへする指定
 * @param[in] rich 規約全文と具体的条件を含む入れ子の正例を作る指定
 * @return 通信や同意を行わない全13fieldの人工JSON
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string descriptorFixture( const bool unknown = false, const bool rich = false)
{
	const std::string evidence{RECORD_EVIDENCE_HASH} ;	// 元出典byteの架空申告
	const std::string terms =
		rich
			? R"json({"state":"ACCEPTANCE_REQUIRED","reason":"","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
				  evidence +
				  R"json(","revisionKind":"VENDOR_LITERAL","revision":"Original 1.0","textDocument":{"url":"https://vendor.example/terms.txt","sha256":")json" +
				  evidence +
				  R"json(","sizeBytes":123,"contentType":"text/plain; charset=utf-8"}})json"
			: R"json({"state":"CONFIRMED_NO_CONSENT","reason":"","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
				  evidence +
				  R"json(","revisionKind":"NONE","revision":"","textDocument":null})json" ;	// 元規約の別状態
	const std::string prerequisites =
		rich
			? R"json({"state":"KNOWN","reason":"","items":[{"kind":"LOCAL_CHECK","description":"Check a specific prerequisite","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
				  evidence + R"json("}]})json"
			: R"json({"state":"KNOWN","reason":"","items":[]})json" ;	// 明示空集合か個別条件
	// UNKNOWNは取得URLやattestationを補完せず、独立した未知理由も保持する
	if( unknown) {
		return R"json({"schema":"driver-index-acquisition-v1","state":"UNKNOWN","reason":"static route not supplied","payloadUrl":"","fileName":"","format":"UNKNOWN","expectedContentType":"","maximumBytes":0,"route":[],"terms":{"state":"UNKNOWN","reason":"terms not supplied","evidenceUrl":"","evidenceSha256":"","revisionKind":"NONE","revision":"","textDocument":null},"prerequisites":{"state":"UNKNOWN","reason":"prerequisites not supplied","items":[]},"publisher":{"state":"UNKNOWN","value":"","reason":"publisher not supplied"},"attestation":null})json" ;
	}

	return R"json({"schema":"driver-index-acquisition-v1","state":"KNOWN","reason":"","payloadUrl":"https://vendor.example/fixture.zip","fileName":"Fixture 1.2 (x64).zip","format":"ZIP","expectedContentType":"application/zip","maximumBytes":134217728,"route":[{"url":"https://vendor.example/fixture.zip","kind":"OFFICIAL_PAYLOAD_LINK","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
		   evidence + R"json("}],"terms":)json" + terms + R"json(,"prerequisites":)json" +
		   prerequisites +
		   R"json(,"publisher":{"state":"KNOWN","value":"Synthetic publisher","reason":""},"attestation":{"kind":"COLLECTOR_VERIFIED_OFFICIAL_ROUTE","policyRevision":1,"checkedAtUtc":"2026-10-10T03:00:00Z","validUntilUtc":"2026-10-12T03:00:00Z","authorityMethod":"OFFICIAL_SITE_CONTROL_AND_LINK","authorityEvidenceUrl":"https://vendor.example/support","authorityEvidenceSha256":")json" +
		   evidence + R"json("}})json" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 通信なしのv2 resource descriptorを元親identityへ結ぶ
 * @param[in] rootHash 人工payloadの実hash
 * @param[in] bytes 人工payloadの実byte数
 * @return raw内容を検査済みとしない人工計画
 */
//------------------------------------------------------------------------------
std::string resourceDescriptorFixture( const std::string_view rootHash, const std::uint64_t bytes)
{
	auto value = replaced( descriptorFixture(), "driver-index-acquisition-v1",
						  "driver-index-acquisition-v2") ;	// 新wireだけを明示
	value =
		replaced( std::move( value), "\"format\":\"ZIP\"", "\"format\":\"PE_RESOURCE_CONTAINER\"") ;
	const std::string hash( 64U, 'a') ;	// 未検査childの人工期待値
	const std::string tuple =
		// 型付き人工resource
		R"json({"type":{"kind":"STRING","value":"TEST"},"name":{"kind":"ID","value":1},"language":{"kind":"ID","value":1033}})json" ;
	const std::string outer = "{\"resource\":" + tuple +
							  ",\"offset\":0,\"length\":1,\"sha256\":\"" + hash +
							  "\"}" ;	// 原親の有界範囲
	const std::string inf = "{\"role\":\"INF\",\"basename\":\"fixture.inf\",\"resource\":" + tuple +
							",\"offset\":0,\"length\":1,\"sha256\":\"" + hash + "\"}" ;	// 原INF role
	const std::string cat =
		"{\"role\":\"CATALOG\",\"basename\":\"fixture.cat\",\"resource\":" + tuple +
		",\"offset\":1,\"length\":1,\"sha256\":\"" + hash + "\"}" ;	// 原CAT role
	value.pop_back() ;
	value +=
		",\"payloadPlan\":{\"retrieval\":{\"kind\":\"STATIC_URL\"},\"content\":{\"kind\":\"PE_RESOURCE_RANGES_V1\",\"root\":{\"bytes\":" +
		std::to_string( bytes) + ",\"sha256\":\"" + std::string( rootHash) +
		"\"},\"archive\":" + outer +
		",\"member\":{\"path\":\"inner.exe\",\"bytes\":2,\"sha256\":\"" + hash + "\"},\"files\":[" +
		inf + "," + cat + "],\"selectedInf\":\"fixture.inf\"}}}" ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 匿名CDNの公開locatorを有限resource descriptorへ結ぶ
 * @param[in] rootHash 人工payloadの実hash
 * @param[in] bytes 人工payloadの実byte数
 * @return 実HTTPや実CAT成功を持たない人工wire
 */
//------------------------------------------------------------------------------
std::string anonymousDescriptorFixture( const std::string_view rootHash, const std::uint64_t bytes)
{
	auto value = resourceDescriptorFixture( rootHash, bytes) ;	// 既存の同じcontent plan
	value	   = replaced( std::move( value), "OFFICIAL_PAYLOAD_LINK",
						  "OFFICIAL_CDN_LINK") ;	// 別originへの元公式CDN導線
	value	   = replaced(
		 std::move( value), R"json({"kind":"STATIC_URL"})json",
		 R"json({"kind":"ANONYMOUS_CDN_TOKEN_V1","model":"G614FR","path":"/pub/ASUS/fixture.exe","systemCode":"asus"})json") ;
	// 元sourceと証拠pageだけを公式起点へ揃え、擬似native receiptは作らない
	while( value.find( "vendor.example") != std::string::npos) {
		value = replaced( std::move( value), "vendor.example", "www.asus.com") ;
	}

	// Payloadと一hopだけを完全なpublic canonicalへ結ぶ
	while( value.find( "https://www.asus.com/fixture.zip") != std::string::npos) {
		value = replaced( std::move( value), "https://www.asus.com/fixture.zip",
						 "https://dlcdnta.asus.com/pub/ASUS/fixture.exe?model=G614FR") ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief Descriptorをschemaより先に置くv2原recordを作ります
 * @param[in] descriptor 全13fieldの人工元取得情報
 * @param[in] raw 旧14fieldの人工record。欠損を補いません
 * @return 原field順を明示した15fieldの人工record
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string descriptorRecord( const std::string_view descriptor,
										   std::string			  raw = distributionRecord())
{
	raw = replaced( std::move( raw), "driver-index-record-v1", "driver-index-record-v2") ;
	return "{\"acquisitionDescriptor\":" + std::string{descriptor} + "," + raw.substr( 1U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Sourcesとrecordsをouter schemaより先に置くv2原indexを作ります
 * @param[in] sources 人工source集合
 * @param[in] entries 原byteと実hashに結合した人工entry集合
 * @return Outer field順を固定しない全4fieldの人工index
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string descriptorIndex( const std::string_view sources,
										  const std::string_view entries)
{
	return "{\"sources\":[" + std::string{sources} + "],\"records\":[" + std::string{entries} +
		   "],\"assetGeneration\":7,\"schema\":\"driver-index-records-v2\"}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 架空の元INF根拠にWindows Serverの三条件を追加します
 * @param[in] base 条件追加前の原レコードです
 * @param[in] release Serverの正規版名です
 * @param[in] product 2又は3のproduct型です
 * @param[in] fault 正常時は空、対照の場合は一つの故障名です
 * @return 元INF根拠と条件を保持する試験用JSONです
 */
//------------------------------------------------------------------------------
std::string serverHostRaw( std::string base, std::string_view release, std::string_view product,
						  std::string_view fault) ;

//------------------------------------------------------------------------------
/**
 * @brief 本文と対象付き追加欄を同じ署名と隔離ストアに保存し、通常の端末スキャンへ渡します
 * @param[in,out] context 共通の試験集計です
 * @param[in] key 人工索引の原byteだけを署名するRAM内の鍵です
 */
//------------------------------------------------------------------------------
void		testCatalogSupplementConsumer( TestContext &context, const RamKey &key) ;

//------------------------------------------------------------------------------
/**
 * @brief 通常の署名候補試験で使用する人工INF閉包のZIPを作ります
 * @param[in] network trueでNetの別Classと別identityを選びます
 * @param[out] infBytes 非null時は人工INFの全元byteです
 * @param[in] nestedMembers 内側に追加する一段ZIPの元nameです
 * @param[in] includeFlat trueで外側にINF閉包を含めます
 * @param[in] managed 人工INFの特定内容を選択します
 * @param[in] models 人工INFのModels装飾を選択します
 * @param[in] originalInf 非空時は指定した人工INFへ置換します
 * @return Minizで生成した原ZIPです
 */
//------------------------------------------------------------------------------
std::string normalWorkerDriverZip( bool network, std::string *infBytes,
								  std::span<const std::string_view> nestedMembers, bool includeFlat,
								  unsigned managed, unsigned models, std::string_view originalInf) ;

//------------------------------------------------------------------------------
/**
 * @brief 実署名を通した専用欄で元証拠と投影の一致、期限、旧文法の拒否を確認します
 * @param[in,out] context 共通の試験集計です
 * @param[in] key 原証拠と圧縮索引を独立にhashするRAM内の試験鍵です
 * @param[in] proof 収集専用の人工元証拠です
 * @param[in] source 同じ人工Catalog起点の取得元です
 * @param[in] catalogDescriptor 同じ人工Catalog起点と元期限の取得記述です
 */
//------------------------------------------------------------------------------
void testScopedModelsRecords( TestContext &context, const RamKey &key, const std::string &proof,
							 const std::string_view source, const std::string &catalogDescriptor)
{
	using Status	  = IndexRecordsStatus ;
	using Transport	  = IndexAssetSupplementStatus ;
	const auto expiry = std::chrono::sys_days{std::chrono::year{2026} / 10 / 12} +
						std::chrono::hours{3} ;			// 取得記述の元期限です
	const auto proofHash = recordDigest( key, proof) ;	// 独立した元証拠の実SHA-256です
	// 元Catalog配布がCABを指す公式Models行に使う取得条件
	auto descriptor = replaced( catalogDescriptor, "\"format\":\"ZIP\"", "\"format\":\"CABINET\"") ;
	descriptor = replaced( std::move( descriptor), "application/zip", "application/octet-stream") ;
	descriptor = replaced( std::move( descriptor), "/fixture.zip", "/fixture.cab") ;
	descriptor = replaced( std::move( descriptor), "/fixture.zip", "/fixture.cab") ;
	descriptor = replaced( std::move( descriptor), "(x64).zip", "(x64).cab") ;

	// 署名済みの一致証拠を端末側の候補へ解決する二つの架空対象ID
	constexpr std::string_view TARGET_IDS =
		R"json([{"kind":"HARDWARE","value":"testbus\\Other"},{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json" ;
	// 元配布、取得条件、通常本文との違いを確認する専用レコード
	auto row =
		descriptorRecord( descriptor, distributionRecord( "scoped-models", true, "CONTENT_INSPECTED",
														"catalog-source")) ;
	// 公表hashと実測hash、内包位置とINF、Unicode節と選択OSを元証拠へ揃えます
	row = replaced( std::move( row), RECORD_CLAIM_HASH, RECORD_EVIDENCE_HASH) ;
	row = replaced( std::move( row), RECORD_CLAIM_HASH, RECORD_EVIDENCE_HASH) ;
	row = replaced( std::move( row), R"("valueBytes":1234)", R"("valueBytes":489361)") ;
	row = replaced( std::move( row), R"("nestedArchiveIdentity":"")",
				   R"("nestedArchiveIdentity":"driver.cab")") ;
	row = replaced( std::move( row), "drivers/fixture.inf", "amd64/fixture.inf") ;
	row = replaced( std::move( row), "{11111111-2222-3333-4444-555555555555}",
				   "{4d36e972-e325-11ce-bfc1-08002be10318}") ;
	row = replaced( std::move( row), "Fixture.NTamd64", R"(Fixture\u65e5.NTamd64)") ;
	row = replaced( std::move( row), "WINDOWS_11", "WINDOWS_10") ;
	row = replaced( std::move( row), R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
				   TARGET_IDS) ;
	row = replaced( std::move( row), "driver-index-record-v2", "driver-index-record-v6") ;
	row.insert( 1U, "\"scopedModelsEvidenceSha256\":\"" + proofHash + "\",") ;

	std::string baseInf ;	// 同端末へ表示する従来本文用の別INFです
	// 専用欄の影響を受けず保持される架空の通常配布物
	const auto	baseZip		   = normalWorkerDriverZip( true, &baseInf, {}, true, 0U, 0U, {}) ;
	const auto	baseDescriptor = replaced( descriptorFixture(), "2026-10-12T03:00:00Z",
										  "2026-10-13T03:00:00Z") ;	// DM失効後も本文は有効です
	// 専用欄が付いても通常経路で読める、本体側の独立レコード
	auto		baseRow = descriptorRecord(
		   baseDescriptor, distributionRecord( "unchanged-base", true, "CONTENT_INSPECTED")) ;
	const auto baseZipHash = recordDigest( key, baseZip) ;	// 従来の本文と人工ZIPを結びます
	baseRow				   = replaced( std::move( baseRow), RECORD_CLAIM_HASH, baseZipHash) ;
	baseRow				   = replaced( std::move( baseRow), RECORD_CLAIM_HASH, baseZipHash) ;
	baseRow				   = replaced( std::move( baseRow), R"("valueBytes":1234)",
									  R"("valueBytes":)" + std::to_string( baseZip.size())) ;
	baseRow				   = replaced( std::move( baseRow), "drivers/fixture.inf", "fixture.inf") ;
	baseRow				   = replaced( std::move( baseRow), "{11111111-2222-3333-4444-555555555555}",
									  "{4d36e972-e325-11ce-bfc1-08002be10318}") ;
	baseRow				   = replaced( std::move( baseRow), "Fixture.NTamd64", "Models.NTamd64") ;
	baseRow				   = replaced( std::move( baseRow), "WINDOWS_11", "WINDOWS_10") ;
	baseRow				   = replaced( std::move( baseRow),
									  "fixture.inf\",\"evidenceSha256\":\"" + std::string{RECORD_EVIDENCE_HASH},
									  "fixture.inf\",\"evidenceSha256\":\"" + recordDigest( key, baseInf)) ;
	// 追加欄への結合に使う従来本文の元UTF-8
	const auto baseIndex = descriptorIndex( recordSource(), recordEntry( key, baseRow)) ;
	const auto baseGzip	 = assetGzip( baseIndex) ;	// DMとDCで全く同じ圧縮本文を使います
	// 原証拠の包み直しと申告hashの改変を個別に試せる形にする。引数は同期組立て中だけ借りる
	const auto proofEntry = []( const std::string_view raw, const std::string_view hash) {
		return "{\"evidenceBytesBase64\":\"" + encodeText( raw) + "\",\"evidenceSha256\":\"" +
			   std::string{hash} + "\"}" ;
	} ;
	// 元レコードhashは入力ごとに再計算し、原証拠との意味照合まで届けます
	const auto modelsIndex = [&]( const std::string_view raw, const std::string_view proofs) {
		// 同じ配布行を公式Models専用欄の本文へ投影した元UTF-8
		auto index = replaced( descriptorIndex( source, recordEntry( key, raw)),
							  "driver-index-records-v2", "driver-index-records-scoped-models-v1") ;
		index.pop_back() ;
		return index + ",\"proofs\":[" + std::string{proofs} + "]}" ;
	} ;
	// 旧本文だけを集計した実署名を作り、各追加欄の元圧縮byteまで認証させます
	const auto readBase = [&]( const std::string_view additional, const bool scoped,
							  std::shared_ptr<SignedIndexStore> *const store = nullptr) {
		// 従来本文のハッシュと元期限に結び付く専用欄の転送バイト
		auto frame = assetSupplementFrame( key, baseIndex, assetGzip( additional), expiry) ;
		// DMの正負例を作る際だけ、従来のDCとは異なる識別子へ切り替えます
		if( scoped) {
			frame[1] = std::byte{'M'} ;
		}

		const auto	gzip = assetWithExtra( baseGzip, frame) ;	// 元Deflateと追加欄は同一署名の対象です
		std::string outer ;										// 保存する場合だけ元envelopeも保持します
		// 本体と専用欄を同じ転送物として照合する試験用マニフェスト
		const auto	manifest = assetManifest( key, gzip, false, recordQuality( {1U, 1U, 0U, 1U, 0U}),
											 store ? &outer : nullptr) ;
		// 同じ署名が指定した圧縮物を端末と同じ入口で認証した結果
		const auto	bytes = authenticateIndexAssetBytes( manifest, gzip, NOW) ;
		// 人工入力の署名やbyte codecの失敗を、元証拠照合の期待拒否に数えません
		if( !bytes.receipt) {
			throw std::runtime_error( "scoped models fixture byte authentication failed") ;
		}

		// 追加欄を分けて通常本文だけを読んだ結果
		auto base = readSignedIndexRecords( *bytes.receipt, NOW) ;
		// 元証拠照合の前に本文が独立して成立したことを確認します
		if( !base.receipt || base.receipt->records().size() != 1U ||
		   base.receipt->records().front().originalBytes != baseRow) {
			throw std::runtime_error( "scoped models fixture base schema rejected") ;
		}

		// 通常スキャンには署名済みの元転送byteを保護ストアから渡します
		if( store) {
			// 他の試験鍵や実配布鍵を参照せずに認証する、一つの試験公開鍵
			const std::array<signed_index_detail::TrustKey, 1U> trust{
				{{"fixture-main", key.publicBlob}}} ;
			// 同じ試験鍵で候補の再読取りを行う隔離ストア
			auto opened = signed_index_store_detail::Access::createIsolated( trust) ;
			// 署名済みの元本文を隔離ストアに保存できなければ比較を続けません
			if( !opened.store || !opened.store->commit( *base.receipt, outer, gzip, NOW).snapshot) {
				throw std::runtime_error( "scoped models isolated commit") ;
			}

			const auto reload = opened.store->reload( NOW) ;	// 元署名と元転送byteを再認証します
			DRIVERCRATE_EXPECT(
				context, reload.status == IndexStoreStatus::SNAPSHOT_READY && reload.snapshot &&
							 reload.snapshot->originalEnvelope() == outer &&
							 std::ranges::equal( reload.snapshot->originalGzip(), gzip) &&
							 reload.snapshot->schemaReceipt().assetBytes().hasScopedModelsFrame() &&
							 reload.snapshot->consumerRecords().size() == 1U) ;
			*store = std::move( opened.store) ;
		}

		return std::move( *base.receipt) ;
	} ;
	const auto entry = proofEntry( proof, proofHash) ;	// 元証拠と一致する正規の包みです
	const auto extra = modelsIndex( row, entry) ;		// 同じ元証拠を指す一つの投影です
	std::shared_ptr<SignedIndexStore>
			   validStore ;									// 正規の元署名と元圧縮byteを保護ストアへ保存します
	const auto base = readBase( extra, true, &validStore) ;	// 専用欄より先に旧本文を検査します
	// 境界の直前に元証拠と公式範囲の両方を読んだ結果
	const auto live = readSignedIndexScopedModels( base, expiry - std::chrono::seconds{1}) ;
	DRIVERCRATE_EXPECT( context,
					   live.contents.transportStatus == Transport::BYTE_VALIDATED &&
						   live.contents.status == Status::SCHEMA_VALIDATED &&
						   live.contents.error == 0U && live.contents.sources.size() == 1U &&
						   live.contents.records.size() == 1U &&
						   live.expandedSha256 == key.digest( extra) && live.expiresAtUtc == expiry) ;
	// 認証済みレコードの付帯証拠と、元Modelsから導いた対象の両方を確認します
	if( live.contents.records.size() == 1U) {
		const auto &record	 = live.contents.records.front() ;	// v6の型付き投影です
		const auto &evidence = record.scopedModelsEvidence ;	// 同じ行へ結合した原証拠です
		const auto &scope	 = record.catalogHardwareScope ;	// 原証拠から導いたCatalog条件です
		// 専用欄から端末側へ投影されることを期待する二つの元ID
		const std::vector<std::string> projected{R"(testbus\Other)", R"(TESTBUS\SYNTH_0001)"} ;
		// 大小文字と順序の差があっても完全な集合として照合する公式側の元ID
		const std::vector<std::string> official{R"(testbus\synth_0001)", R"(TESTBUS\OTHER)"} ;
		const std::vector<std::size_t> positions{0U, 1U} ;	// 公開ID配列での位置です
		DRIVERCRATE_EXPECT(
			context, record.recordSchemaVersion == 6U && record.originalBytes == row &&
						 record.recordSha256 == key.digest( row) &&
						 record.scopedModelsEvidenceSha256 == key.digest( proof) &&
						 record.publishedIdentityEvidence.modelSection == "Fixture日.NTamd64") ;
		DRIVERCRATE_EXPECT(
			context, evidence && evidence->originalBytes == proof &&
						 evidence->evidenceSha256 == key.digest( proof) &&
						 evidence->models.sections.size() == 2U &&
						 evidence->models.sections.front().matches.size() == 2U &&
						 evidence->models.sections.front().matches.front().modelRow == 4097U &&
						 evidence->models.sections.front().matches.back().modelRow == 16383U) ;
		DRIVERCRATE_EXPECT( context, scope && scope->hardwareIds == projected &&
										scope->hardwareIdIndices == positions &&
										scope->packageHardwareIds == official) ;
	}

	const auto expired = readSignedIndexScopedModels( base, expiry) ;	// 期限ちょうどで失効します
	// 期限境界に達した時点での通常本文の読取り結果
	const auto legacy = readSignedIndexRecords( base.assetBytes(), expiry) ;
	DRIVERCRATE_EXPECT( context, expired.contents.transportStatus == Transport::EXPIRED &&
									expired.contents.records.empty() &&
									expired.contents.sources.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   legacy.receipt && legacy.receipt->records().size() == 1U &&
						   legacy.receipt->records().front().originalBytes == baseRow &&
						   assetText( legacy.receipt->assetBytes().expandedBytes()) == baseIndex) ;

	// 全て同じ本文と正しい外側署名を使い、拒否時に元証拠や投影を渡さないことを確かめます
	const auto reject = [&]( const std::string_view additional, const Status expected) {
		// 同じ署名の専用追加欄を既存読取り機構へ渡した結果
		const auto parsed = readSignedIndexScopedModels( readBase( additional, true), NOW) ;
		DRIVERCRATE_EXPECT( context,
						   parsed.contents.transportStatus == Transport::BYTE_VALIDATED &&
							   parsed.contents.status == expected && parsed.contents.error == 0U &&
							   parsed.contents.sources.empty() && parsed.contents.records.empty()) ;
	} ;
	const auto substitute = proof + ' ' ;	// 文法は同じで原byteだけを変えた証拠です
	reject( modelsIndex( row, {}), Status::INVALID_EVIDENCE) ;
	reject( modelsIndex( row, proofEntry( substitute, recordDigest( key, substitute))),
		   Status::INVALID_EVIDENCE) ;
	reject( modelsIndex( row, proofEntry( substitute, proofHash)), Status::RECORD_HASH_MISMATCH) ;
	// 元証拠と一致しない投影を一項目ずつ差し替え、各行自身のhashは作り直します
	for( const auto &invalid :
		{replaced(
			 row, TARGET_IDS,
			 R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},{"kind":"HARDWARE","value":"testbus\\Other"}])json"),
		 replaced( row, R"(testbus\\Other)", R"(TESTBUS\\OTHER)"),
		 replaced( row, R"("kind":"HARDWARE")", R"("kind":"COMPATIBLE")"),
		 replaced( row, "amd64/fixture.inf", "amd64/other.inf"),
		 replaced( row, R"("valueBytes":489361)", R"("valueBytes":489362)"),
		 replaced( row, R"(Fixture\u65e5.NTamd64)", "NoTargets.NTamd64"),
		 replaced( row, "WINDOWS_10", "WINDOWS_11"),
		 replaced( row, "\"format\":\"CABINET\"", "\"format\":\"ZIP\"")}) {
		reject( modelsIndex( invalid, entry), Status::INVALID_EVIDENCE) ;
	}

	// 従来の本文とDCの文法に同じv6レコードを混ぜた場合も拒否します
	const auto inBase = readRecordFixture( key, extra, {1U, 1U, 0U, 1U, 0U}) ;
	expectRecordsRejected( context, inBase, Status::INVALID_RECORD) ;
	// 元専用レコードを旧DC欄へ移した際の用途不一致を確認する認証結果
	const auto inDc =
		readBase( replaced( descriptorIndex( source, recordEntry( key, row)), "driver-index-records-v2",
						  "driver-index-records-supplement-v1"),
				 false) ;
	// 旧追加欄の読み取りへ専用レコードを渡した負例の結果
	const auto old = readSignedIndexSupplementRecords( inDc, NOW) ;
	DRIVERCRATE_EXPECT( context, old.transportStatus == Transport::BYTE_VALIDATED &&
									old.status == Status::INVALID_RECORD && old.records.empty()) ;
	DRIVERCRATE_EXPECT( context, readSignedIndexConsumerSupplement( inDc, NOW).contents.status ==
									Status::INVALID_RECORD) ;
	DRIVERCRATE_EXPECT( context, readSignedIndexSupplementRecords( base, NOW).transportStatus ==
									Transport::ABSENT) ;

	std::shared_ptr<SignedIndexStore> invalidStore ;	// 外側の実署名が有効な証拠欠損例です
	static_cast<void>( readBase( modelsIndex( row, {}), true, &invalidStore)) ;
	runScopedModelsConsumerScan( context, validStore, invalidStore, NOW, expiry, baseZip,
								key.digest( baseIndex), key.digest( extra)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実署名の追加欄で元INFの識別表記と元期限を保持し、旧索引との共通検査を確認します
 * @param[in,out] context 共通試験集計です
 * @param[in] key 実署名に使うRAM内試験鍵です
 * @note 元INFから抜き出した識別表記を架空の取得証拠へ組み合わせます
 */
//------------------------------------------------------------------------------
void testIndexSupplementRecords( TestContext &context, const RamKey &key)
{
	using Status = IndexRecordsStatus ;
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// 元OS条件の読取りに必要な試験用MTAです
	const auto		   expiry = std::chrono::sys_days{std::chrono::year{2026} / 10 / 12} +
						std::chrono::hours{3} ;		// 架空の内容検査期限です
	const auto descriptor = descriptorFixture() ;	// 取得元の内容検査に対応する架空証拠です
	const auto source	  = recordSource() ;		// 両欄で元申告が一致する取得元です
	const auto legacy =
		descriptorRecord( descriptor, replaced( distributionRecord( "legacy"), "drivers/fixture.inf",
											  "drivers/legacy.inf")) ;	// 旧本文にある別INFの対照です
	const auto amdDescriptor = replaced(
		descriptor, "\"items\":[]",
		R"json("items":[{"kind":"LOCAL_CHECK","description":"DriverCrate:client-min-build=26100;catalog-update-id=bc41fadb-7443-489b-8f8a-ab5665af9707","evidenceUrl":"https://www.catalog.update.microsoft.com/ScopedViewInline.aspx","evidenceSha256":")json" +
			std::string{RECORD_EVIDENCE_HASH} +
			R"json("}])json") ;	// 元のWindows 11適用条件を持つ架空証拠です
	auto amd	 = descriptorRecord( amdDescriptor,
									// 元GUID付きIDを含む架空recordです
									distributionRecord( "amd", true, "CONTENT_INSPECTED")) ;
	amd			 = replaced( std::move( amd), "Fixture.NTamd64", "AMD.ntamd64.10.0...16299") ;
	amd			 = replaced( std::move( amd), R"(TESTBUS\\SYNTH_0001)",
							R"({54cb850d-a731-8590-0628-1992592bd448}\\rcbottom)") ;
	auto printer = descriptorRecord(
		descriptor, distributionRecord( "printer", true,
									   "CONTENT_INSPECTED")) ;	// 元Models節名と型付きIDを入れます
	printer = replaced( std::move( printer), "Fixture.NTamd64", "Tally Dascom.NTamd64") ;
	printer = replaced(
		std::move( printer), R"json({"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"})json",
		R"json({"kind":"HARDWARE","value":"USBPRINT\\Tally_Dascom2600+0D64"},{"kind":"COMPATIBLE","value":"Tally_Dascom_2600+0D64"})json") ;
	const IndexManifestQuality baseQuality{1U, 1U, 1U, 0U, 0U} ;	// 旧本文の署名用件数です
	const auto index = [&]( const std::string_view extraSource, const std::string_view entries) {
		return replaced( descriptorIndex( extraSource, entries), "driver-index-records-v2",
						"driver-index-records-supplement-v1") ;
	} ; // 追加欄のschemaを明示します
	// RAM鍵と入力の借用は同行の旧本文と追加欄の認証が完了するまでです
	const auto readBase = [&]( const std::string_view baseRecord, const IndexManifestQuality quality,
							  const std::string_view		 additional,
							  const std::chrono::sys_seconds frameExpiry) {
		const auto baseIndex = descriptorIndex( source, recordEntry( key, baseRecord)) ;	// 旧本文です
		const auto gzip		 = assetWithExtra(
			 assetGzip( baseIndex), assetSupplementFrame( key, baseIndex, assetGzip( additional),
															frameExpiry)) ;	// 両欄を同じ実署名へ結びます
		const auto manifest =
			// 旧本文の件数です
			assetManifest( key, gzip, false, recordQuality( quality)) ;
		const auto bytes =
			// 同じ原圧縮hashを確認します
			authenticateIndexAssetBytes( manifest, gzip, NOW) ;
		// 認証失敗を追加欄の意味検査の合格へ読み替えません
		if( !bytes.receipt) {
			throw std::runtime_error( "supplement fixture byte authentication failed") ;
		}

		auto base =
			// 追加欄を使わず旧本文を検査します
			readSignedIndexRecords( *bytes.receipt, NOW) ;
		// 追加欄の判定に進む前に旧本文の原byteとhashを確認します
		if( !base.receipt || base.receipt->records().size() != 1U ||
		   base.receipt->records().front().originalBytes != baseRecord ||
		   base.receipt->records().front().recordSha256 != key.digest( baseRecord)) {
			throw std::runtime_error( "supplement changed verified base records") ;
		}

		return std::move( *base.receipt) ;
	} ;
	// 既存公開readerへ渡す旧本文receiptは各呼出しで所有します
	const auto read = [&]( const std::string_view		 additional,
						  const std::chrono::sys_seconds frameExpiry,
						  const std::chrono::sys_seconds readTime) {
		return readSignedIndexSupplementRecords(
			readBase( legacy, baseQuality, additional, frameExpiry), readTime) ;
	} ;
	const std::string archiveHash{RECORD_CLAIM_HASH} ;	// 配布された架空ZIPの実測値です
	const std::string pageHash{RECORD_EVIDENCE_HASH} ;	// 配布ページと文書の架空元ハッシュです
	const std::string memberHash( 64U, 'e') ;			// 架空メンバーを元ZIPから区別する値です
	const std::string terms =
		// 元配布ページと規約文書を区別した私有追加欄の架空規約です
		R"json("terms":{"state":"ACCEPTANCE_REQUIRED","reason":"","evidenceUrl":"https://terms.example/legal/","evidenceSha256":")json" +
		pageHash +
		R"json(","revisionKind":"VENDOR_LITERAL","revision":"Original 1.0","textDocument":{"url":"https://terms.example/legal/","sha256":")json" +
		pageHash +
		R"json(","sizeBytes":512,"contentType":"text/html; charset=utf-8","htmlExtraction":{"profile":"STATIC_HTML_SECTION_V1","selector":{"tag":"div","attribute":"id","value":"license"},"documentSha256":")json" +
		pageHash + R"json(","documentSizeBytes":349,"textSha256":")json" + pageHash +
		R"json(","textSizeBytes":128,"bindingEvidenceUrl":"https://vendor.example/support","bindingEvidenceSha256":")json" +
		pageHash +
		R"json(","bindingEvidenceSizeBytes":256}},"archiveNotice":{"archiveSizeBytes":1234,"archiveSha256":")json" +
		archiveHash +
		R"json(","memberPath":"docs\\license.txt","memberSizeBytes":100,"memberSha256":")json" +
		memberHash +
		R"json(","statementOffset":6,"statement":"License applies at http://terms.example/legal/.","originalDocumentUrl":"http://terms.example/legal/"}})json" ;
	const auto termsBegin = descriptor.find( "\"terms\":") ;			// 既存架空記述子の規約欄です
	const auto termsEnd	  = descriptor.find( ",\"prerequisites\"") ;	// 次の項目の開始位置です
	const auto archiveDescriptor =
		replaced( descriptor, descriptor.substr( termsBegin, termsEnd - termsBegin),
				 terms) ;	// 取得方式と期限は既存架空記述子から維持します
	auto archiveRow = descriptorRecord(
		archiveDescriptor, distributionRecord( "archive-notice", true,
											  "CONTENT_INSPECTED")) ;	// 元内容検査付きの架空配布です
	const auto measuredBegin =
		// 実測の根拠部分だけを置き換えます
		archiveRow.find( "\"calculatedHash\":") ;
	const auto measuredEnd = archiveRow.find( ",\"size\"") ;	// 架空元ZIPのサイズは維持します
	archiveRow			   = replaced(
		archiveRow, archiveRow.substr( measuredBegin, measuredEnd - measuredBegin),
		R"json("calculatedHash":{"state":"KNOWN","sha256":")json" + archiveHash +
			R"json(","evidenceUrl":"https://vendor.example/fixture.zip","evidenceSha256":")json" +
			archiveHash + R"json(","reason":""})json") ;
	const auto privateIndex =
		// 署名対象の私有欄だけです
		index( source, recordEntry( key, archiveRow)) ;
	const auto archiveNoticeBase =
		// 同署名資産の旧本文です
		readBase( legacy, baseQuality, privateIndex, expiry) ;
	const auto native =
		// 元行を変更せず所有します
		readSignedIndexConsumerSupplement( archiveNoticeBase, NOW) ;
	DRIVERCRATE_EXPECT( context, native.contents.status == Status::SCHEMA_VALIDATED &&
									native.contents.records.size() == 1U) ;
	// 私有証拠は他の欄へ移さず、型付き証拠と元バイトを保持します
	if( native.contents.records.size() == 1U) {
		const auto &record = native.contents.records.front() ;	// 署名済みの原レコードです
		DRIVERCRATE_EXPECT(
			context, record.originalBytes == archiveRow &&
						 signed_index_detail::indexRecordNeedsSupplement( record) &&
						 record.acquisitionDescriptor &&
						 record.acquisitionDescriptor->terms.archiveNotice &&
						 record.acquisitionDescriptor->terms.archiveNotice->memberPath ==
							 R"(docs\license.txt)" &&
						 record.acquisitionDescriptor->terms.archiveNotice->statementOffset == 6U) ;
	}

	const auto publicRead =
		// 旧公開入口です
		readSignedIndexSupplementRecords( archiveNoticeBase, NOW) ;
	DRIVERCRATE_EXPECT( context, publicRead.status == Status::INVALID_SUPPLEMENT_PURPOSE &&
									publicRead.records.empty()) ;
	const auto baseOnly =
		readRecordFixture( key, descriptorIndex( source, recordEntry( key, archiveRow)),
						  {1U, 1U, 0U, 1U, 0U}) ;	// 私有証拠を旧本文に入れた対照です
	DRIVERCRATE_EXPECT( context, baseOnly.status == Status::INVALID_EVIDENCE && !baseOnly.receipt) ;

	const std::array invalidArchiveRows{
		replaced( archiveRow, "\"archiveSha256\":\"" + archiveHash,
				 "\"archiveSha256\":\"" + memberHash),
		replaced( archiveRow, "\"archiveSizeBytes\":1234", "\"archiveSizeBytes\":1235"),
		replaced( archiveRow, "\"bindingEvidenceSha256\":\"" + pageHash,
				 "\"bindingEvidenceSha256\":\"" + memberHash),
		replaced( archiveRow, "\"authorityEvidenceSha256\":\"" + pageHash,
				 "\"authorityEvidenceSha256\":\"" + memberHash),
		replaced( archiveRow, R"("memberPath":"docs\\license.txt")",
				 R"("memberPath":"..\\license.txt")"),
		replaced( archiveRow, "\"statementOffset\":6", "\"statementOffset\":100"),
		replaced( archiveRow, "legal/.\"", "legal/elsewhere.\""),
		replaced( archiveRow, "License applies at ",
				 "Copied http://another.example/ license applies at "),
		replaced( archiveRow, "\"originalDocumentUrl\":\"http://terms.example/legal/",
				 "\"originalDocumentUrl\":\"https://terms.example/legal/"),
		replaced( archiveRow, "\"format\":\"ZIP\"", "\"format\":\"CABINET\""),
		replaced( archiveRow, "\"state\":\"ACCEPTANCE_REQUIRED\"",
				 "\"state\":\"CONFIRMED_NO_CONSENT\"")} ;	// それぞれ独立の差し替えです
	// 署名とハッシュを架空入力に対して作り直し、証拠結合の検査だけで拒否を確認します
	for( const auto &invalid : invalidArchiveRows) {
		const auto rejectedArchive = readSignedIndexConsumerSupplement(
			readBase( legacy, baseQuality, index( source, recordEntry( key, invalid)), expiry),
			NOW) ;	// 運搬署名が揃っても不一致の行を返しません
		DRIVERCRATE_EXPECT( context, rejectedArchive.contents.status == Status::INVALID_EVIDENCE &&
										rejectedArchive.contents.records.empty()) ;
	}

	// 二つの元INF表記を同じ実署名で受け渡す追加欄の原文
	const auto extra	= index( source, recordEntry( key, amd) + "," + recordEntry( key, printer)) ;
	const auto accepted = read( extra, expiry, NOW) ;	// 旧件数の署名と別に新2件が成立します
	DRIVERCRATE_EXPECT( context,
					   accepted.transportStatus == IndexAssetSupplementStatus::BYTE_VALIDATED &&
						   accepted.status == Status::SCHEMA_VALIDATED && accepted.error == 0 &&
						   accepted.sources.size() == 1U && accepted.records.size() == 2U) ;
	// 二つのレコードを取得できた場合だけ元クラスとパスを個別に照合します
	if( accepted.records.size() == 2U) {
		const auto &amdRecord	  = accepted.records[0] ;	// 元GUIDを保存したtyped recordです
		const auto &printerRecord = accepted.records[1] ;	// 多様な元表記を保存したtyped recordです
		// 二番目のレコードから元INF識別表記を参照します
		const auto &printerIdentity = printerRecord.publishedIdentityEvidence ;
		DRIVERCRATE_EXPECT( context, amdRecord.originalBytes == amd &&
										amdRecord.recordSha256 == key.digest( amd) &&
										amdRecord.publishedIdentityEvidence.modelSection ==
											"AMD.ntamd64.10.0...16299" &&
										amdRecord.publishedIdentityEvidence.pnpIds.front().value ==
											R"({54cb850d-a731-8590-0628-1992592bd448}\rcbottom)") ;
		DRIVERCRATE_EXPECT(
			context, printerRecord.originalBytes == printer &&
						 printerRecord.recordSha256 == key.digest( printer) &&
						 printerIdentity.modelSection == "Tally Dascom.NTamd64" &&
						 printerIdentity.pnpIds.size() == 2U &&
						 printerIdentity.pnpIds[0].kind == IndexPnpIdKind::HARDWARE &&
						 printerIdentity.pnpIds[0].value == R"(USBPRINT\Tally_Dascom2600+0D64)" &&
						 printerIdentity.pnpIds[1].kind == IndexPnpIdKind::COMPATIBLE &&
						 printerIdentity.pnpIds[1].value == "Tally_Dascom_2600+0D64") ;
	}

	// 両形式の元レコードを順に旧本文へ混ぜ、追加欄の用途が区別されることを確認します
	for( const auto &extended : {amd, printer}) {
		const auto old =
			readRecordFixture( key, descriptorIndex( source, recordEntry( key, extended)),
							  {1U, 1U, 0U, 1U, 0U}) ;	// 同じ元識別子は旧索引内で引き続き拒否されます
		DRIVERCRATE_EXPECT( context, old.status == Status::INVALID_EVIDENCE && !old.receipt) ;
	}

	const auto reject = [&]( const std::string_view additional, const Status status,
							const std::chrono::sys_seconds frameExpiry) {
		const auto result =
			// 実署名後の意味検査だけを確認します
			read( additional, frameExpiry, NOW) ;
		DRIVERCRATE_EXPECT( context,
						   result.transportStatus == IndexAssetSupplementStatus::BYTE_VALIDATED &&
							   result.status == status && result.sources.empty() &&
							   result.records.empty()) ;
	} ;
	reject( descriptorIndex( source, recordEntry( key, amd)), Status::INVALID_INDEX, expiry) ;
	reject( extra, Status::SUPPLEMENT_EXPIRY_MISMATCH, expiry + std::chrono::seconds{1}) ;
	reject( index( source, recordEntry( key, legacy)), Status::DUPLICATE_RECORD, expiry) ;
	reject(
		index( replaced( source, RECORD_EVIDENCE_HASH, std::string( 64U, 'a')), recordEntry( key, amd)),
		Status::DUPLICATE_SOURCE, expiry) ;
	reject( index( {}, recordEntry( key, amd)), Status::MISSING_SOURCE, expiry) ;
	reject( index( source, recordEntry( key, replaced( printer, "Tally Dascom.NTamd64",
												   "Tally Dascom].NTamd64"))),
		   Status::INVALID_EVIDENCE, expiry) ;
	reject( index( source, recordEntry( key, replaced( printer, "Tally_Dascom_2600+0D64",
												   "Tally Dascom_2600+0D64"))),
		   Status::INVALID_EVIDENCE, expiry) ;
	reject( index( source, recordEntry( key, replaced( amd, "CONTENT_INSPECTED", "METADATA_ONLY"))),
		   Status::INVALID_SUPPLEMENT_PURPOSE, expiry) ;
	reject( index( source, recordEntry( key, replaced( amd, "WINDOWS_11", "WINDOWS_10"))),
		   Status::INVALID_SUPPLEMENT_PURPOSE, expiry) ;
	reject( index( source, recordEntry( key, amd, recordDigest( key, amd + " "))),
		   Status::RECORD_HASH_MISMATCH, expiry) ;

	// 架空取得元をCatalog起点へ揃えます。テストから通信は行いません
	const auto catalogOrigin = []( std::string raw) {
		// 取得元と記述に現れる旧起点を全て同じ起点へ置き換えます
		while( raw.find( "vendor.example") != raw.npos) {
			raw = replaced( std::move( raw), "vendor.example", "www.catalog.update.microsoft.com") ;
		}

		return raw ;
	} ;
	const auto catalogSource = catalogOrigin( recordSource( "catalog-source")) ;	// 同起点の元申告です
	const std::string scope =
		R"json(,"catalogHardwareScope":{"detailsUrl":"https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=bc41fadb-7443-489b-8f8a-ab5665af9707","detailsSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} +
		// 二行に分かれた公式表です
		R"json(","observedAtUtc":"2026-10-10T02:00:00Z","packageHardwareIds":["testbus\\synth_0001","TESTBUS\\OTHER"]}})json" ;
	// 元配布や元INFの人工証拠として使用する固定ハッシュ表記
	const std::string sha{RECORD_EVIDENCE_HASH} ;
	// 元の節順・行順・大小文字・空白を保持する収集専用の証拠です
	const auto		  proof =
		std::string{R"json({ "archiveBytes":489361,"archiveSha256":")json"} + sha +
		R"json(","schema":"driver-index-collector-scoped-models-v1",
		"nestedArchiveIdentity":"driver.cab","infIdentity":"amd64/fixture.inf",
		"infSha256":")json" +
		sha + R"json(","catalogIdentity":"amd64/FIXTURE.CAT","catalogSha256":")json" + sha +
		R"json(","classGuid":"{4d36e972-e325-11ce-bfc1-08002be10318}","catalogDetailsBytes":39155,
		"modelsPlatform":{"majorVersion":10,"minorVersion":0,"buildNumber":19045,
		"processorArchitecture":9,"productType":1,"suiteMask":0},
		"sections":[{"modelSection":"Fixture\u65e5.NTamd64","modelRows":16383,"idFields":65535,
		"orderedRowsSha256":")json" +
		sha + R"json(","matches":[
		{"modelRow":4097,"hardwareId":"testbus\\Other","installBase":"Base.Ndi"},
		{"modelRow":16383,"hardwareId":"TESTBUS\\SYNTH_0001","installBase":"Second.Ndi"}]},
		{"modelSection":"NoTargets.NTamd64","modelRows":1,"idFields":1,"orderedRowsSha256":")json" +
		sha + R"json(","matches":[]}])json" + scope ;
	testScopedModelsRecords( context, key, proof, catalogSource, catalogOrigin( descriptor)) ;
	// 借用した試験鍵で与えた原文と同じ値をハッシュし、証拠だけを読む同期処理
	const auto readProof = [&]( const std::string &rawProof) {
		return signed_index_detail::decodeCollectorScopedModelsEvidence( rawProof,
																		key.digest( rawProof)) ;
	} ;
	// 元証拠を厳格な共通codecで読み込んだ結果
	const auto decodedProof = readProof( proof) ;
	DRIVERCRATE_EXPECT( context,
					   decodedProof.status == Status::SCHEMA_VALIDATED && decodedProof.data) ;
	// 証拠の読取りが成立した場合だけ内部のModelsと元参照を確認します
	if( decodedProof.data) {
		// 検証済みの元証拠。読み取った結果を保持する間だけ借用します
		const auto &evidence = *decodedProof.data ;
		DRIVERCRATE_EXPECT( context, evidence.originalBytes == proof &&
										evidence.evidenceSha256 == key.digest( proof) &&
										evidence.archiveBytes == 489361U &&
										evidence.nestedArchiveIdentity == "driver.cab" &&
										evidence.catalogIdentity == "amd64/FIXTURE.CAT" &&
										evidence.models.platform ==
											OfficialInfModelsPlatform{.buildNumber = 19045U} &&
										evidence.models.sections.size() == 2U) ;
		// 期待した二つの元節が得られた場合だけ、それぞれの行情報へ進みます
		if( evidence.models.sections.size() == 2U) {
			// 元行の上限等号と、順序を保持した一致を確認する先頭の節
			const auto &first = evidence.models.sections.front() ;
			DRIVERCRATE_EXPECT( context, first.modelSection == L"Fixture日.NTamd64" &&
											first.matches.size() == 2U &&
											first.matches.front().modelRow == 4097U &&
											first.matches.front().hardwareId == L"testbus\\Other" &&
											first.matches.front().installBase == L"Base.Ndi" &&
											first.matches.back().modelRow == 16383U &&
											evidence.models.sections.back().matches.empty()) ;
		}
	}

	// 見た目のデータは同じまま、原UTF-8に余白を加えたハッシュ不一致対照
	const auto differentRaw = proof + ' ' ;
	// 原バイトが異なる証拠を、変更前のハッシュと照合した拒否結果
	const auto rawMismatch =
		signed_index_detail::decodeCollectorScopedModelsEvidence( differentRaw, key.digest( proof)) ;
	DRIVERCRATE_EXPECT( context,
					   rawMismatch.status == Status::RECORD_HASH_MISMATCH && !rawMismatch.data) ;
	// 元証拠を個別上限と同じバイト数にする等号対照
	const auto fullProof = proof + std::string( INDEX_RECORD_MAX_BYTES - proof.size(), ' ') ;
	DRIVERCRATE_EXPECT( context, readProof( fullProof).data.has_value()) ;
	DRIVERCRATE_EXPECT( context, readProof( fullProof + ' ').status == Status::RECORD_SIZE_LIMIT) ;

	// 元行数、ID数、行位置などの制約を一つずつ崩して拒否を確かめます
	for( const auto &invalidProof :
		{replaced( proof, "\"modelRows\":16383", "\"modelRows\":16384"),
		 replaced( proof, "\"idFields\":65535", "\"idFields\":65536"),
		 replaced( proof, "\"modelRow\":4097", "\"modelRow\":0"),
		 replaced( proof, "\"modelRow\":16383", "\"modelRow\":4096"),
		 replaced( proof, "\"modelRow\":16383", "\"modelRow\":16384"),
		 replaced( proof, "testbus\\\\Other", "TESTBUS\\\\SYNTH_0001"),
		 replaced( proof, "testbus\\\\Other", "TESTBUS\\\\COMPATIBLE_ONLY"),
		 replaced( proof, "NoTargets.NTamd64", "fixture\\u65e5.ntamd64"),
		 replaced( proof, "amd64/FIXTURE.CAT", "amd64-other/FIXTURE.CAT"),
		 replaced( proof, "\"buildNumber\":19045", "\"buildNumber\":17763"),
		 replaced( proof, "\"productType\":1", "\"productType\":1,\"productType\":1")}) {
		DRIVERCRATE_EXPECT( context, !readProof( invalidProof).data) ;
	}

	// 署名済みtransportと既存の未署名追加欄は収集専用の原証拠を受け付けません
	const auto proofEntry = recordEntry( key, proof) ;
	// 本来収集専用の元証拠が公開用途に混ざる追加欄の対照入力
	const auto privateAsPublic = index( source, recordEntry( key, amd) + "," + proofEntry) ;
	// 公開の読取りで収集専用の証拠を含む追加欄を拒否することを確認します
	const auto privateConsumer = readSignedIndexConsumerSupplement(
		readBase( legacy, baseQuality, privateAsPublic, expiry), NOW) ;
	DRIVERCRATE_EXPECT( context, privateConsumer.contents.transportStatus ==
										IndexAssetSupplementStatus::BYTE_VALIDATED &&
									privateConsumer.contents.status != Status::SCHEMA_VALIDATED &&
									privateConsumer.contents.records.empty()) ;
	// 同じ証拠を追加欄から通常本文へ移す用途不一致の対照
	const auto privateBase =
		readRecordFixture( key, descriptorIndex( source, proofEntry), {1U, 1U, 0U, 1U, 0U}) ;
	DRIVERCRATE_EXPECT( context, !privateBase.receipt) ;
	// 正式公開とは別に、同じ証拠を局所の候補として読めるかを確認する結果
	const auto pendingProof = signed_index_detail::decodePendingCollectorSupplement(
		std::as_bytes( std::span{proof}), expiry, NOW) ;
	DRIVERCRATE_EXPECT( context, !pendingProof.data) ;

	const auto catalogRow = [&]( const std::string_view id, const std::string_view acquisition) {
		auto record = catalogOrigin( descriptorRecord(
			acquisition, distributionRecord( id, true, "CONTENT_INSPECTED",
											"catalog-source"))) ;	// 同sourceへの元行です
		record = replaced( std::move( record), "driver-index-record-v2", "driver-index-record-v3") ;
		record.pop_back() ;
		return record + scope ;
	} ; // 元の全Modelsはそのまま保持します
	constexpr std::string_view CATALOG_MODELS_IDS =
		// 元Modelsの全IDです
		R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},{"kind":"COMPATIBLE","value":"TESTBUS\\COMPAT"}])json" ;
	const auto catalogA = replaced( catalogRow( "catalog-a", amdDescriptor),
								   R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
								   CATALOG_MODELS_IDS) ;	// 同詳細の最低buildも保持します
	auto	   catalogB = replaced( catalogRow( "catalog-b", descriptor), R"(TESTBUS\\SYNTH_0001)",
								   R"(TESTBUS\\OTHER)") ;	// 別Models側に属する対象です
	catalogB			= replaced( std::move( catalogB), "Fixture.NTamd64", "Other.NTamd64") ;
	const auto pending	= [&]( const std::string_view entries, const std::string_view sourceBytes) {
		 const auto raw = replaced( index( sourceBytes, entries), R"("assetGeneration":7)",
								   R"("assetGeneration":1)") ;	// 私有候補の固定世代です
		 return signed_index_detail::decodePendingCollectorSupplement(
			 std::as_bytes( std::span{raw.data(), raw.size()}), expiry, NOW) ;
	} ; // 公開経路から独立した原候補の再読を使います
	const auto catalogEntries =
		// 別々の元Models行です
		recordEntry( key, catalogA) + "," + recordEntry( key, catalogB) ;
	const auto catalog = pending( catalogEntries, catalogSource) ;	// 同じ公式表を二行で再読します
	DRIVERCRATE_EXPECT( context, catalog.status == Status::SCHEMA_VALIDATED && catalog.data &&
									catalog.data->records.size() == 2U) ;
	// 元表記、元byte、行ごとに導いた照合範囲を確認します
	if( catalog.data && catalog.data->records.size() == 2U) {
		const auto &first  = catalog.data->records.front() ;	// 元Modelsの初行です
		const auto &second = catalog.data->records.back() ;		// 別Modelsの行です
		DRIVERCRATE_EXPECT(
			context,
			first.recordSchemaVersion == 3U && first.originalBytes == catalogA &&
				second.originalBytes == catalogB && second.recordSha256 == key.digest( catalogB) &&
				signed_index_detail::indexRecordNeedsSupplement( first) &&
				first.catalogHardwareScope && second.catalogHardwareScope &&
				first.catalogHardwareScope->packageHardwareIds ==
					(std::vector<std::string>{R"(testbus\synth_0001)", R"(TESTBUS\OTHER)"}) &&
				first.catalogHardwareScope->hardwareIds ==
					std::vector<std::string>{R"(TESTBUS\SYNTH_0001)"} &&
				first.catalogHardwareScope->hardwareIdIndices == std::vector<std::size_t>{0U} &&
				isIndexLookupIdEligible( first, 0U) && !isIndexLookupIdEligible( first, 1U) &&
				!isIndexLookupIdEligible( first, 2U) &&
				second.catalogHardwareScope->hardwareIds ==
					std::vector<std::string>{R"(TESTBUS\OTHER)"}) ;
	}

	// RAM鍵を借り、同行の正規性を保った二つの別名を同じ私有候補で再読します
	const auto pendingPair = [&]( const std::string_view first, const std::string_view second) {
		return pending( recordEntry( key, first) + "," + recordEntry( key, second), catalogSource) ;
	} ;
	// 汎用PnP IDを元Modelsに結び、先頭記号を含めた完全一致として読み戻す
	const auto genericScope = replaced( catalogA, R"(testbus\\synth_0001)", "*tst0001") ;
	// 公式表と同じ汎用PnP IDをHardware種別で持つ元Models行
	const auto genericModel = replaced( genericScope, R"(TESTBUS\\SYNTH_0001)", "*TST0001") ;
	// 同じ公式表を共有する別Models行
	const auto genericOther = replaced( catalogB, R"(testbus\\synth_0001)", "*tst0001") ;
	// 両行を一緒に読んだ候補の結果
	const auto generic = pendingPair( genericModel, genericOther) ;
	DRIVERCRATE_EXPECT( context, generic.status == Status::SCHEMA_VALIDATED && generic.data &&
									generic.data->records.size() == 2U) ;
	// 両行が成立したときに汎用IDの完全一致位置を確認する
	if( generic.data && generic.data->records.size() == 2U) {
		const auto &first = generic.data->records.front() ;	// 汎用PnP IDを含む元レコード
		DRIVERCRATE_EXPECT( context, first.catalogHardwareScope &&
										first.catalogHardwareScope->hardwareIds ==
											std::vector<std::string>{"*TST0001"} &&
										isIndexLookupIdEligible( first, 0U)) ;
	}

	// 不正な記号配置の対象宣言では候補を返さない
	for( const auto invalidId : {"*", "**tst0001", "*tst0001*", R"(testbus\\*synth_0001)"}) {
		// 不正IDに差し替えた元行と正常な別行を一緒に検査する
		const auto rejected =
			pendingPair( replaced( genericModel, "*tst0001", invalidId), genericOther) ;
		DRIVERCRATE_EXPECT( context, rejected.status == Status::INVALID_EVIDENCE && !rejected.data) ;
	}

	const auto catalogAlias =
		replaced( catalogA, "\"recordId\":\"catalog-a\"",
				 "\"recordId\":\"catalog-a-alias\"") ;	// 同じModelsの別recordです
	const auto orderedAlias = replaced(
		replaced( catalogAlias, "Fixture.NTamd64", "fixture.ntamd64"), CATALOG_MODELS_IDS,
		// 元ID番号を取り違える対照です
		R"json([{"kind":"COMPATIBLE","value":"TESTBUS\\COMPAT"},{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json") ;
	const auto reordered =
		// 元順を入れ替えた単独行
		pending( recordEntry( key, orderedAlias), catalogSource) ;
	DRIVERCRATE_EXPECT( context, reordered.data && reordered.data->records.size() == 1U) ;
	// 先頭のCompatible IDが候補位置にならず、元Hardware IDの位置を保持する
	if( reordered.data && reordered.data->records.size() == 1U) {
		const auto &row = reordered.data->records.front() ;	// 既存codecで読み戻した元行
		DRIVERCRATE_EXPECT( context, row.originalBytes == orderedAlias && row.catalogHardwareScope &&
										row.catalogHardwareScope->hardwareIdIndices ==
											std::vector<std::size_t>{1U} &&
										!isIndexLookupIdEligible( row, 0U) &&
										isIndexLookupIdEligible( row, 1U)) ;
	}

	const auto kindAlias = replaced( catalogAlias, R"("COMPATIBLE")",
									R"("HARDWARE")") ;	// 同じIDの種別だけを変えます
	const auto changedTable =
		replaced( catalogB, R"(testbus\\synth_0001)",
				 R"(testbus\\synth_0002)") ;	// B行の対象は残し、全体の公式表だけ変えます
	const auto changedUpdate = replaced( catalogB, "updateid=bc41fadb",
										"updateid=ac41fadb") ;	// 同じ配布物の別更新です
	// 同じ配布物を指す四つの矛盾を各々単独で確認し、元行の一部も返しません
	for( const auto &alias : {orderedAlias, kindAlias, changedTable, changedUpdate}) {
		const auto conflict = pendingPair( catalogA, alias) ;	// 両行の検査済み証拠を比較します
		DRIVERCRATE_EXPECT( context, conflict.status == Status::CATALOG_SCOPE_CONFLICT &&
										conflict.error == 0 && !conflict.data) ;
	}

	const auto reversedConflict = pendingPair( orderedAlias, catalogA) ;	// 先にある別名を優先しません
	DRIVERCRATE_EXPECT( context, reversedConflict.status == Status::CATALOG_SCOPE_CONFLICT &&
									reversedConflict.error == 0 && !reversedConflict.data) ;

	constexpr std::string_view FRESH_DETAILS_HASH =
		"3333333333333333333333333333333333333333333333333333333333333333" ;	// 再観測の原応答hashです
	const std::string originalDetailsHash =
		"\"detailsSha256\":\"" + std::string{RECORD_EVIDENCE_HASH} ;	// 旧原応答だけの欄です
	const auto staleFloor =
		replaced( replaced( catalogAlias, originalDetailsHash,
						  "\"detailsSha256\":\"" + std::string{FRESH_DETAILS_HASH}),
				 "2026-10-10T02:00:00Z", "2026-10-10T02:15:00Z") ;	// 最低buildの原hashだけが旧値です
	const auto mismatchedFloor =
		// 同行で照合します
		pending( recordEntry( key, staleFloor), catalogSource) ;
	DRIVERCRATE_EXPECT( context, mismatchedFloor.status == Status::INVALID_SUPPLEMENT_PURPOSE &&
									!mismatchedFloor.data) ;
	auto refreshed = replaced( staleFloor,
							  "ScopedViewInline.aspx\",\"evidenceSha256\":\"" +
								  std::string{RECORD_EVIDENCE_HASH},
							  "ScopedViewInline.aspx\",\"evidenceSha256\":\"" +
								  std::string{FRESH_DETAILS_HASH}) ;	// 同行の原応答を一致させます
	refreshed	   = replaced( std::move( refreshed), "Fixture.NTamd64", "fixture.ntamd64") ;
	refreshed	   = replaced(
		 std::move( refreshed), CATALOG_MODELS_IDS,
		 // 元IDの順序と種別は同じです
		 R"json([{"kind":"HARDWARE","value":"testbus\\synth_0001"},{"kind":"COMPATIBLE","value":"testbus\\compat"}])json") ;
	refreshed = replaced(
		std::move( refreshed), R"(["testbus\\synth_0001","TESTBUS\\OTHER"])",
		R"(["testbus\\other","TESTBUS\\SYNTH_0001"])") ;	// 公式表の順序と大文字小文字だけを変えます
	const auto reobserved =
		// 旧原byteと再観測原byteの両方を確認します
		pendingPair( catalogA, refreshed) ;
	DRIVERCRATE_EXPECT( context, reobserved.status == Status::SCHEMA_VALIDATED &&
									reobserved.error == 0 && reobserved.data &&
									reobserved.data->records.size() == 2U) ;
	// 同じ対象でも各行のSHA・元時刻・ID表記をそれぞれ保持します
	if( reobserved.data && reobserved.data->records.size() == 2U) {
		const auto &original = reobserved.data->records.front() ;	// 先に観測した原行です
		const auto &latest	 = reobserved.data->records.back() ;	// 再観測した原行です
		DRIVERCRATE_EXPECT( context, original.originalBytes == catalogA &&
										original.recordSha256 == key.digest( catalogA) &&
										latest.originalBytes == refreshed &&
										latest.recordSha256 == key.digest( refreshed)) ;
		DRIVERCRATE_EXPECT(
			context,
			original.catalogHardwareScope && latest.catalogHardwareScope &&
				original.catalogHardwareScope->detailsSha256 ==
					signed_index_json::decodeHash( RECORD_EVIDENCE_HASH, Status::INVALID_EVIDENCE) &&
				latest.catalogHardwareScope->detailsSha256 ==
					signed_index_json::decodeHash( FRESH_DETAILS_HASH, Status::INVALID_EVIDENCE) &&
				latest.catalogHardwareScope->observedAtUtc ==
					original.catalogHardwareScope->observedAtUtc + std::chrono::minutes{15} &&
				latest.catalogHardwareScope->packageHardwareIds ==
					(std::vector<std::string>{R"(testbus\other)", R"(TESTBUS\SYNTH_0001)"})) ;
	}

	auto legacyAlias =
		descriptorRecord( descriptor,
						 // 別sourceの旧本文です
						 distributionRecord( "legacy-alias", true, "CONTENT_INSPECTED")) ;
	legacyAlias = replaced( std::move( legacyAlias), "Fixture.NTamd64", "Legacy.NTamd64") ;
	legacyAlias = replaced( std::move( legacyAlias), "1.2.3.4", "9.8.7.6") ;
	const auto oneCatalogRow =
		// 最低buildなしの対象行です
		index( catalogSource, recordEntry( key, catalogB)) ;
	// 旧receiptが所有する元byteと追加欄の検査値を同じ呼出しで借用します
	const auto readMixed = [&]( const std::string_view baseRecord,
							   const std::string_view additional) {
		// 同じGZipの両欄を保持する実署名済みの旧本文receiptです
		const auto	base  = readBase( baseRecord, {1U, 1U, 0U, 1U, 0U}, additional, expiry) ;
		const auto &asset = base.assetBytes() ;	// 両欄を認証済みの運搬結果です
		return signed_index_detail::decodeIndexSupplementRecordsData(
			asset.manifest().data(), base.sources(), base.records(), asset.readSupplement( NOW),
			NOW) ;
	} ;
	const auto mixed =
		// 別source、record、Models、版でも同じ物理証拠です
		readSignedIndexConsumerSupplement(
			readBase( legacyAlias, {1U, 1U, 0U, 1U, 0U}, oneCatalogRow, expiry), NOW) ;
	DRIVERCRATE_EXPECT( context, mixed.contents.transportStatus ==
										IndexAssetSupplementStatus::BYTE_VALIDATED &&
									mixed.contents.status == Status::CATALOG_SCOPE_CONFLICT &&
									mixed.contents.error == 0 && mixed.contents.sources.empty() &&
									mixed.contents.records.empty() &&
									mixed.expandedSha256 == IndexManifestSha256{} &&
									mixed.expiresAtUtc == std::chrono::sys_seconds{}) ;
	const std::string otherHash( 64U, '4') ;	// 取得物又はINFの別証拠です
	// 同じ出典とrecord名でも物理証拠の各境界を一つずつ変えた場合は両欄が成立します
	for( const auto &distinct :
		{replaced( replaced( legacyAlias, RECORD_CLAIM_HASH, otherHash), RECORD_CLAIM_HASH,
				  otherHash),
		 replaced( legacyAlias, R"("nestedArchiveIdentity":"")",
				  R"("nestedArchiveIdentity":"nested.zip")"),
		 replaced( legacyAlias, "drivers/fixture.inf", "drivers/other.inf"),
		 replaced( legacyAlias,
				  "fixture.inf\",\"evidenceSha256\":\"" + std::string{RECORD_EVIDENCE_HASH},
				  "fixture.inf\",\"evidenceSha256\":\"" + otherHash),
		 replaced( legacyAlias, "WINDOWS_11", "WINDOWS_10")}) {
		const auto acceptedMixed =
			// 追加欄から原対象行を取り出します
			readMixed( distinct, oneCatalogRow) ;
		DRIVERCRATE_EXPECT(
			context, acceptedMixed.transportStatus == IndexAssetSupplementStatus::BYTE_VALIDATED &&
						 acceptedMixed.status == Status::SCHEMA_VALIDATED &&
						 acceptedMixed.error == 0 && acceptedMixed.sources.size() == 1U &&
						 acceptedMixed.records.size() == 1U &&
						 acceptedMixed.records.front().originalBytes == catalogB &&
						 acceptedMixed.records.front().recordSha256 == key.digest( catalogB)) ;
	}

	const auto serverScope =
		index( catalogSource,
			  recordEntry( key, catalogOrigin( serverHostRaw( catalogB, "WINDOWS_SERVER_2025", "3",
														   {})))) ;	// 同物理配布物のServer対象です
	// 明示された別のServer版・productだけを別の適用範囲として保持します
	for( const auto &[release, product, fault, expected] :
		std::array{std::tuple{"WINDOWS_SERVER_2022", "3", "", Status::SCHEMA_VALIDATED},
				   std::tuple{"WINDOWS_SERVER_2025", "2", "", Status::SCHEMA_VALIDATED},
				   std::tuple{"WINDOWS_SERVER_2025", "3", "", Status::CATALOG_SCOPE_CONFLICT},
				   std::tuple{"WINDOWS_SERVER_2022", "3", "LEGACY_ENUM_GENERIC_SERVER",
							  Status::CATALOG_SCOPE_CONFLICT}}) {
		const auto result = readMixed( serverHostRaw( legacyAlias, release, product, fault),
									  serverScope) ;	// 旧本文と比較します
		DRIVERCRATE_EXPECT( context, result.status == expected && result.error == 0) ;
	}

	const auto publicCatalog =
		readRecordFixture( key, descriptorIndex( catalogSource, recordEntry( key, catalogA)),
						  {1U, 1U, 0U, 1U, 0U}) ;	// 旧本文です
	DRIVERCRATE_EXPECT( context,
					   publicCatalog.status == Status::INVALID_RECORD && !publicCatalog.receipt) ;
	// 意味を変えない空白を含む元取得元です
	const auto rawCatalogSource = replaced( catalogSource, R"({"sourceId":)", R"({ "sourceId": )") ;
	// 末尾改行まで含めてSHA-256を比較する元領域です
	const auto rawCatalogIndex = index( rawCatalogSource, catalogEntries) + "\n" ;
	const auto catalogBase =
		// 同じ実署名の比較入力です
		readBase( legacy, baseQuality, rawCatalogIndex, expiry) ;
	const auto publicSupplement =
		// 旧公開用の拒否を確認します
		readSignedIndexSupplementRecords( catalogBase, NOW) ;
	DRIVERCRATE_EXPECT(
		context, publicSupplement.transportStatus == IndexAssetSupplementStatus::BYTE_VALIDATED &&
					 publicSupplement.status == Status::INVALID_SUPPLEMENT_PURPOSE &&
					 publicSupplement.sources.empty() && publicSupplement.records.empty()) ;

	// 同じ実署名から展開元領域と各行の元byte・hashを受け取ります
	const auto consumer = readSignedIndexConsumerSupplement( catalogBase, NOW) ;
	DRIVERCRATE_EXPECT( context, consumer.contents.transportStatus ==
										IndexAssetSupplementStatus::BYTE_VALIDATED &&
									consumer.contents.status == Status::SCHEMA_VALIDATED &&
									consumer.contents.error == 0 &&
									consumer.expandedSha256 == key.digest( rawCatalogIndex) &&
									consumer.expandedSha256 != catalogBase.indexSha256() &&
									consumer.expiresAtUtc == expiry) ;
	DRIVERCRATE_EXPECT( context,
					   consumer.contents.sources.size() == 1U &&
						   consumer.contents.sources.front().originalBytes == rawCatalogSource &&
						   consumer.contents.records.size() == 2U &&
						   consumer.contents.records.front().originalBytes == catalogA &&
						   consumer.contents.records.front().recordSha256 == key.digest( catalogA) &&
						   consumer.contents.records.front().catalogHardwareScope &&
						   consumer.contents.records.back().originalBytes == catalogB &&
						   consumer.contents.records.back().recordSha256 == key.digest( catalogB) &&
						   consumer.contents.records.back().catalogHardwareScope) ;

	// 期限の一秒前まで同じ元領域を読み取り、期限に達すると旧本文だけが読めます
	const auto reread =
		readSignedIndexConsumerSupplement( catalogBase, expiry - std::chrono::seconds{1}) ;
	DRIVERCRATE_EXPECT( context, reread.contents.status == Status::SCHEMA_VALIDATED &&
									reread.expandedSha256 == consumer.expandedSha256 &&
									reread.expiresAtUtc == consumer.expiresAtUtc) ;
	const auto expiredConsumer =
		// 期限ちょうどの判定です
		readSignedIndexConsumerSupplement( catalogBase, expiry) ;
	DRIVERCRATE_EXPECT( context, expiredConsumer.contents.transportStatus ==
										IndexAssetSupplementStatus::EXPIRED &&
									expiredConsumer.contents.status != Status::SCHEMA_VALIDATED &&
									expiredConsumer.contents.sources.empty() &&
									expiredConsumer.contents.records.empty() &&
									expiredConsumer.expandedSha256 == IndexManifestSha256{} &&
									expiredConsumer.expiresAtUtc == std::chrono::sys_seconds{}) ;
	const auto remainingBase =
		// 同時刻に再読した旧本文です
		readSignedIndexRecords( catalogBase.assetBytes(), expiry) ;
	DRIVERCRATE_EXPECT(
		context, remainingBase.status == Status::SCHEMA_VALIDATED && remainingBase.receipt &&
					 remainingBase.receipt->records().size() == 1U &&
					 remainingBase.receipt->records().front().originalBytes == legacy &&
					 remainingBase.receipt->records().front().recordSha256 == key.digest( legacy) &&
					 remainingBase.receipt->indexSha256() == catalogBase.indexSha256()) ;

	// 追加欄の取得元IDを旧本文と同じにし、異なる出典の組を実署名で検査します
	const auto sourceConflict =
		index( replaced( catalogSource, "catalog-source", "fixture-source"),
			  recordEntry( key, replaced( catalogA, "catalog-source", "fixture-source"))) ;
	// 異なる元取得元が同じIDを持つ対照の拒否です
	const auto conflictingConsumer = readSignedIndexConsumerSupplement(
		readBase( legacy, baseQuality, sourceConflict, expiry), NOW) ;
	DRIVERCRATE_EXPECT( context,
					   conflictingConsumer.contents.transportStatus ==
							   IndexAssetSupplementStatus::BYTE_VALIDATED &&
						   conflictingConsumer.contents.status == Status::DUPLICATE_SOURCE &&
						   conflictingConsumer.contents.error == 0 &&
						   conflictingConsumer.contents.sources.empty() &&
						   conflictingConsumer.contents.records.empty() &&
						   conflictingConsumer.expandedSha256 == IndexManifestSha256{} &&
						   conflictingConsumer.expiresAtUtc == std::chrono::sys_seconds{}) ;

	// 配布条件を失った別形式や対象が成立しない元行を私有再読時に拒否します
	for( const auto &raw :
		{replaced( catalogA, "driver-index-record-v3", "driver-index-record-v2"),
		 replaced( catalogA, R"("HARDWARE")", R"("COMPATIBLE")"),
		 replaced( catalogA, R"(TESTBUS\\SYNTH_0001)", R"(TESTBUS\\UNKNOWN)"),
		 replaced( catalogA, R"(TESTBUS\\OTHER)", R"(TESTBUS\\SYNTH_0001)"),
		 replaced( catalogA, "2026-10-10T02:00:00Z", "2026-10-10T03:00:01Z"),
		 replaced( catalogA, "2026-10-10T02:00:00Z", "2026-10-01T02:00:00Z"),
		 replaced( catalogA, "?updateid=", "?other="),
		 replaced( catalogA, "updateid=bc41fadb", "updateid=ac41fadb"),
		 replaced( catalogA, R"(["testbus\\synth_0001","TESTBUS\\OTHER"])", "[]")}) {
		DRIVERCRATE_EXPECT( context, !pending( recordEntry( key, raw), catalogSource).data) ;
	}

	const auto expired = read( extra, expiry, expiry) ;	// 元期限ちょうどにはレコードを返しません
	DRIVERCRATE_EXPECT( context, expired.transportStatus == IndexAssetSupplementStatus::EXPIRED &&
									expired.records.empty()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief WiXの原取得と内容証拠を私有追加欄だけで読み戻し、旧経路と別名の回避を検査します
 * @param[in,out] context 共通試験集計です
 * @param[in] key 人工索引だけを署名するRAM内試験鍵です
 * @note 人工の原行と実RSA署名を使用し、通信や配布物の実行は行いません
 */
//------------------------------------------------------------------------------
void testWixContentSupplement( TestContext &context, const RamKey &key)
{
	using Status	  = IndexRecordsStatus ;
	const auto expiry = std::chrono::sys_days{std::chrono::year{2026} / 10 / 12} +
						std::chrono::hours{3} ;			// 元配布の有効期限です
	const std::string pageHash{RECORD_EVIDENCE_HASH} ;	// 元ページの人工SHA-256です
	const std::string payload =
		std::string{"MZ"} + std::string( 1232U, 'Q') ;		// 署名行の1234バイトに対応する非実行データです
	const auto archiveHash = recordDigest( key, payload) ;	// 転送する全バイトの独立CNG SHA-256です
	const std::string infHash( 64U, 'a') ;					// 署名付き元INFの人工SHA-256です
	// WiX検査と引継ぎ可否を照合するために同じ配布ハッシュへ結ぶ人工規約
	const std::string terms =
		R"json({"state":"ACCEPTANCE_REQUIRED","reason":"",)json"
		R"json("evidenceUrl":"https://vendor.example/download/fixture.exe","evidenceSha256":")json" +
		archiveHash +
		R"json(","revisionKind":"WIX_RTF_SHA256","revision":"","textDocument":null})json" ;
	// 公式アンカーだけを取得routeへ持たせ、元の転送先は閉じた内容証拠へ結びます
	const std::string descriptor =
		R"json({"schema":"driver-index-acquisition-v1","state":"KNOWN","reason":"",)json"
		R"json("payloadUrl":"https://vendor.example/download/fixture.exe","fileName":"fixture.exe",)json"
		R"json("format":"WIX_BURN_V3","expectedContentType":"application/octet-stream","maximumBytes":134217728,)json"
		R"json("route":[{"url":"https://vendor.example/download/fixture.exe","kind":"OFFICIAL_PAYLOAD_LINK",)json"
		R"json("evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
		pageHash + R"json("}],"terms":)json" + terms +
		R"json(,"prerequisites":{"state":"KNOWN","reason":"","items":[]},)json"
		R"json("publisher":{"state":"KNOWN","value":"Synthetic CAT publisher","reason":""},)json"
		R"json("attestation":{"kind":"COLLECTOR_VERIFIED_OFFICIAL_ROUTE","policyRevision":1,)json"
		R"json("checkedAtUtc":"2026-10-10T03:00:00Z","validUntilUtc":"2026-10-12T03:00:00Z",)json"
		R"json("authorityMethod":"OFFICIAL_SITE_CONTROL_AND_LINK",)json"
		R"json("authorityEvidenceUrl":"https://vendor.example/support","authorityEvidenceSha256":")json" +
		pageHash + R"json("}})json" ;
	constexpr std::string_view PACKAGES =
		// 二つの元MSIを元順序のまま示します
		R"json([{"id":"Fixture64","cabinetMember":"a1","filePath":"msi\\fixture64.msi",)json"
		R"json("installCondition":"SelectFixture AND VersionNT64","architecture":"AMD64","language":1033},)json"
		R"json({"id":"Fixture32","cabinetMember":"a2","filePath":"msi\\fixture32.msi",)json"
		R"json("installCondition":"SelectFixture AND NOT VersionNT64","architecture":"X86","language":1033}])json" ;
	const std::string licenses =
		// 元RTFの言語、サイズとSHA-256を保持します
		R"json([{"id":"FixtureEnglish","cabinetMember":"u1","filePath":"locales\\en-US\\license.rtf",)json"
		R"json("locale":"en-US","sizeBytes":120,"sha256":")json" +
		std::string( 64U, 'b') +
		R"json("},{"id":"FixtureJapanese","cabinetMember":"u2","filePath":"locales\\ja-JP\\license.rtf",)json"
		R"json("locale":"ja-JP","sizeBytes":121,"sha256":")json" +
		std::string( 64U, 'c') + R"json("}])json" ;
	const std::string driverFiles =
		// 同じ一つのINFと参照閉包を元CABメンバーへ結びます
		R"json([{"cabinetMember":"CatFile","targetName":"fixture.cat","sizeBytes":50,"sha256":")json" +
		std::string( 64U, 'd') +
		R"json("},{"cabinetMember":"InfFile","targetName":"fixture.inf","sizeBytes":30,"sha256":")json" +
		infHash +
		R"json("},{"cabinetMember":"SysFile","targetName":"fixture.sys","sizeBytes":140,"sha256":")json" +
		std::string( 64U, 'e') + R"json("}])json" ;
	// 同じWiX配布のページと実ファイルのハッシュを固定する人工の元証拠
	const std::string proof =
		R"json(,"wixContentEvidence":{"pageUrl":"https://vendor.example/support","pageSha256":")json" +
		pageHash +
		R"json(","observedAtUtc":"2026-10-10T02:00:00Z",)json"
		R"json("downloadUrl":"https://cdn.vendor.example/download/fixture.exe",)json"
		R"json("acceptedPublishers":["Synthetic publisher"],"packages":)json" +
		std::string{PACKAGES} + R"json(,"licenses":)json" + licenses +
		R"json(,"streamName":"FixtureCab","driverFiles":)json" + driverFiles + "}" ;

	// 計算hashとINFの原URLを元アンカーへ結び、元ページの証拠と区別します
	auto common = replaced( distributionRecord( "wix-v8", true, "CONTENT_INSPECTED"),
						   "drivers/fixture.inf", "fixture.inf") ;
	common		= replaced( std::move( common), RECORD_CLAIM_HASH, archiveHash) ;
	common		= replaced( std::move( common), RECORD_CLAIM_HASH, archiveHash) ;
	common		= replaced(
		 std::move( common),
		 R"json("calculatedHash":{"state":"KNOWN","sha256":")json" + archiveHash +
			 R"json(","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
			 pageHash,
		 R"json("calculatedHash":{"state":"KNOWN","sha256":")json" + archiveHash +
			 R"json(","evidenceUrl":"https://vendor.example/download/fixture.exe","evidenceSha256":")json" +
			 archiveHash) ;
	common = replaced(
		std::move( common),
		R"json("evidenceUrl":"https://vendor.example/fixture.inf","evidenceSha256":")json" +
			pageHash,
		R"json("evidenceUrl":"https://vendor.example/download/fixture.exe","evidenceSha256":")json" +
			infHash) ;
	const auto legacyWithWixFormat =
		// 根拠を欠く旧スキーマです
		descriptorRecord( descriptor, common) ;
	// 従来のレコードをWiXの元証拠が使える版へ変換した人工レコード
	auto row = replaced( legacyWithWixFormat, "driver-index-record-v2", "driver-index-record-v8") ;
	row.pop_back() ;
	row += proof + "}\n" ;
	const auto				   source = recordSource() ;		// 同じ公式ページを出典とする架空取得元です
	const IndexManifestQuality quality{1U, 1U, 0U, 1U, 0U} ;	// 署名対象となる旧本文の件数です
	const auto				   weakAlias = descriptorRecord(
		descriptorFixture(),
		replaced( common, "\"recordId\":\"wix-v8\"",
								 "\"recordId\":\"weak-wix-alias\"")) ;	// 配布物とINFの原hashは同じです
	// 同じ追加欄を検査するため通常経路で独立に読める対照レコード
	auto			  otherBase = descriptorRecord( descriptorFixture(),
												   distributionRecord( "other-v2", true, "CONTENT_INSPECTED")) ;
	const std::string otherHash( 64U, 'f') ;	// 無関係な旧本文向けの別配布物です
	otherBase = replaced( std::move( otherBase), RECORD_CLAIM_HASH, otherHash) ;
	otherBase = replaced( std::move( otherBase), RECORD_CLAIM_HASH, otherHash) ;

	// 入力する元レコードと正しい出典を既存追加欄の文法へ包みます
	const auto supplemental = [&]( const std::string_view entries) {
		return replaced( descriptorIndex( source, entries), "driver-index-records-v2",
						"driver-index-records-supplement-v1") ;
	} ;
	// 保留候補が持つ局所世代1で元証拠と期限を読みます
	const auto pending = [&]( const std::string_view entries, const std::chrono::sys_seconds now) {
		const auto raw = replaced( supplemental( entries), R"("assetGeneration":7)",
								  R"("assetGeneration":1)") ;	// 保留候補の元展開byteです
		return signed_index_detail::decodePendingCollectorSupplement( std::as_bytes( std::span{raw}),
																	 expiry, now) ;
	} ;
	// 各ケースの旧本文と追加欄を同じ実署名と転送byteへ結びます
	const auto signedBase = [&]( const std::string_view base, const std::string_view extra,
								std::shared_ptr<SignedIndexStore> *const store = nullptr) {
		const auto baseIndex =
			// 署名する旧本文です
			descriptorIndex( source, recordEntry( key, base)) ;
		// 署名済みの元本文と追加欄を同じ転送物へ結び付ける圧縮内容
		const auto gzip = assetWithExtra(
			assetGzip( baseIndex), assetSupplementFrame( key, baseIndex, assetGzip( extra), expiry)) ;
		std::string outer ;	// 隔離ストアへ元署名入りenvelopeを保存します
		// 同じ圧縮バイトの署名と件数を検査できる試験用マニフェスト
		const auto	manifest = assetManifest( key, gzip, false, recordQuality( quality), &outer) ;
		const auto	asset =
			// 同じ圧縮byteを認証します
			authenticateIndexAssetBytes( manifest, gzip, NOW) ;
		// 前段不成立を新しい内容検査での拒否と取り違えません
		if( !asset.receipt) {
			throw std::runtime_error( "WiX supplement fixture asset authentication failed") ;
		}

		auto verified = readSignedIndexRecords( *asset.receipt, NOW) ;	// 旧本文の原領域です
		// 旧本文は追加欄にかかわらず同じ元レコードとして読めることを要求します
		if( !verified.receipt || verified.receipt->records().size() != 1U ||
		   verified.receipt->records().front().originalBytes != base ||
		   verified.receipt->records().front().recordSha256 != key.digest( base)) {
			throw std::runtime_error( "WiX supplement fixture changed authenticated base records") ;
		}

		// 通常スキャン用の例だけ、同じ署名と同じ圧縮原byteを隔離ストアへ保存します
		if( store != nullptr) {
			const std::array<signed_index_detail::TrustKey, 1U> trust{
				{{"fixture-main", key.publicBlob}}} ;	// 人工鍵の公開部だけを渡します
			auto opened =
				// 私有ストアです
				signed_index_store_detail::Access::createIsolated( trust) ;
			// 保存失敗を後段の端末照合拒否と取り違えません
			if( !opened.store ||
			   !opened.store->commit( *verified.receipt, outer, gzip, NOW).snapshot) {
				throw std::runtime_error( "WiX supplement scan isolated commit") ;
			}

			*store = std::move( opened.store) ;
		}

		return std::move( *verified.receipt) ;
	} ;

	const auto entry = recordEntry( key, row) ;	// 原行末尾の改行も元SHA-256へ結びます
	const auto local = pending( entry, NOW) ;	// 通常の未署名保留候補です
	DRIVERCRATE_EXPECT( context, local.status == Status::SCHEMA_VALIDATED && local.data &&
									local.data->records.size() == 1U &&
									local.data->records.front().originalBytes == row &&
									local.data->records.front().recordSchemaVersion == 8U) ;
	const auto extra = supplemental( entry) ;			// 同じ原行を持つ追加欄です
	const auto base	 = signedBase( otherBase, extra) ;	// 旧本文には別配布物だけを含めます
	// 私有で確認した元証拠を公開向けの消費者入口へ渡した結果
	const auto consumer = readSignedIndexConsumerSupplement( base, NOW) ;
	DRIVERCRATE_EXPECT(
		context,
		consumer.contents.transportStatus == IndexAssetSupplementStatus::BYTE_VALIDATED &&
			consumer.contents.status == Status::SCHEMA_VALIDATED &&
			consumer.expandedSha256 == key.digest( extra) && consumer.expiresAtUtc == expiry &&
			consumer.contents.sources.size() == 1U && consumer.contents.records.size() == 1U &&
			consumer.contents.records.front().originalBytes == row &&
			consumer.contents.records.front().recordSchemaVersion == 8U &&
			consumer.contents.records.front().recordSha256 == key.digest( row) &&
			signed_index_detail::indexRecordNeedsSupplement( consumer.contents.records.front())) ;

	const auto publicRead = readSignedIndexSupplementRecords( base, NOW) ;	// 現行公開互換の入口です
	DRIVERCRATE_EXPECT( context,
					   publicRead.transportStatus == IndexAssetSupplementStatus::BYTE_VALIDATED &&
						   publicRead.status == Status::INVALID_SUPPLEMENT_PURPOSE &&
						   publicRead.records.empty() && publicRead.sources.empty()) ;
	rejectRecordIndex( context, key, descriptorIndex( source, entry), Status::INVALID_RECORD,
					  quality) ;
	// 同じ内容の配布に弱い別名経路が混ざる場合の署名読取り結果
	const auto mixed = readSignedIndexConsumerSupplement( signedBase( weakAlias, extra), NOW) ;
	DRIVERCRATE_EXPECT( context, mixed.contents.transportStatus ==
										IndexAssetSupplementStatus::BYTE_VALIDATED &&
									mixed.contents.status != Status::SCHEMA_VALIDATED &&
									mixed.contents.error == 0 && mixed.contents.records.empty() &&
									mixed.contents.sources.empty()) ;
	// 同じ弱い別名を局所の保存候補へ混ぜた対照の読取り結果
	const auto mixedPending = pending( recordEntry( key, weakAlias) + "," + entry, NOW) ;
	DRIVERCRATE_EXPECT( context, mixedPending.status != Status::SCHEMA_VALIDATED &&
									mixedPending.error == 0 && !mixedPending.data) ;

	// 元行を改変してから実hashを付け直し、各結合と役割の不一致を両読取り入口で拒否します
	for( const auto &invalid :
		{replaced( row, "cdn.vendor.example/download/fixture.exe",
				  "cdn.vendor.example/other/fixture.exe"),
		 replaced( row, "cdn.vendor.example/download/fixture.exe",
				  "vendor.example/download/fixture.exe"),
		 replaced( row, terms, replaced( terms, archiveHash, pageHash)),
		 replaced( row, PACKAGES, "[]"),
		 replaced( row, "\"id\":\"Fixture32\"", "\"id\":\"Fixture64\""),
		 replaced( row, licenses, "[]"),
		 replaced( row, "\"locale\":\"ja-JP\"", "\"locale\":\"en-US\""),
		 replaced( row, "\"targetName\":\"fixture.inf\"", "\"targetName\":\"other.inf\""),
		 replaced( row, "\"streamName\":\"FixtureCab\"",
				  "\"streamName\":\"FixtureCab\",\"unknownRole\":null"),
		 replaced( row, "2026-10-10T02:00:00Z", "2026-10-10T04:00:00Z"), legacyWithWixFormat}) {
		const auto invalidEntry = recordEntry( key, invalid) ;	// 改変した元行に正しい元hashを付けます
		// 壊した元証拠を局所追加候補として読んだ診断
		const auto pendingRead = pending( invalidEntry, NOW) ;
		DRIVERCRATE_EXPECT( context, pendingRead.status != Status::SCHEMA_VALIDATED &&
										pendingRead.error == 0 && !pendingRead.data) ;
		// 同じ破損証拠を通常の署名認証と追加欄経由で読んだ診断
		const auto authenticatedRead = readSignedIndexConsumerSupplement(
			signedBase( otherBase, supplemental( invalidEntry)), NOW) ;
		DRIVERCRATE_EXPECT( context,
						   authenticatedRead.contents.transportStatus ==
								   IndexAssetSupplementStatus::BYTE_VALIDATED &&
							   authenticatedRead.contents.status != Status::SCHEMA_VALIDATED &&
							   authenticatedRead.contents.error == 0 &&
							   authenticatedRead.contents.records.empty() &&
							   authenticatedRead.contents.sources.empty()) ;
	}

	// 元期限ちょうどで新しい有効期限や内容証拠を発行しません
	const auto expired = readSignedIndexConsumerSupplement( base, expiry) ;
	DRIVERCRATE_EXPECT( context,
					   expired.contents.transportStatus == IndexAssetSupplementStatus::EXPIRED &&
						   expired.contents.records.empty() && expired.contents.sources.empty() &&
						   expired.expandedSha256 == IndexManifestSha256{} &&
						   expired.expiresAtUtc == std::chrono::sys_seconds{} &&
						   !pending( entry, expiry).data) ;

	// 既存の模擬端末と同じクラス・Models節を本文とWiXの対照に使います
	const auto atPorts = []( std::string raw) {
		raw = replaced( std::move( raw), "{11111111-2222-3333-4444-555555555555}",
					   "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
		return replaced( std::move( raw), "Fixture.NTamd64", "Models.NTamd64") ;
	} ;
	auto scanRow =
		replaced( atPorts( row), R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
				 // 同じ値のCompatible役割とワイルドカード表記も署名対象の原順で保持します
				 R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},)json"
				 R"json({"kind":"COMPATIBLE","value":"TESTBUS\\SYNTH_0001"},)json"
				 R"json({"kind":"HARDWARE","value":"TESTBUS\\SYNTH_*"}])json") ;
	// 公式公表ハッシュのない配布を使い、転送後に収集側の計算ハッシュを独立に検査します
	scanRow = replaced(
		std::move( scanRow),
		R"json("publishedHash":{"state":"KNOWN","sha256":")json" + archiveHash +
			R"json(","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
			pageHash + R"json(","reason":""})json",
		R"json("publishedHash":{"state":"UNKNOWN","sha256":"","evidenceUrl":"","evidenceSha256":"","reason":"not published"})json") ;
	const auto scanExtra = supplemental( recordEntry( key, scanRow)) ;	// 端末照合用の元追加欄です
	const auto scanBase	 = replaced( atPorts( otherBase), "2026-10-12T03:00:00Z",
									"2026-10-13T03:00:00Z") ;				// 追加欄の失効後も有効な本文です
	std::shared_ptr<SignedIndexStore> scanStore ;							// 通常入口が署名から再読する隔離ストアです
	const auto scanReceipt = signedBase( scanBase, scanExtra, &scanStore) ;	// 実署名と同じ原byteです
	const auto scanSupplement =
		// 三つの元IDを保持した真正行を通常入口の入力にします
		readSignedIndexConsumerSupplement( scanReceipt, NOW) ;
	DRIVERCRATE_EXPECT(
		context,
		scanSupplement.contents.status == Status::SCHEMA_VALIDATED &&
			scanSupplement.contents.records.size() == 1U &&
			scanSupplement.contents.records.front().originalBytes == scanRow &&
			scanSupplement.contents.records.front().publishedIdentityEvidence.pnpIds.size() == 3U) ;
	const auto baseZip = normalWorkerDriverZip( false, nullptr, {}, true, 0U, 0U,
											   {}) ;	// 低位fake初期化用の既存人工閉包です
	runWixSupplementConsumerScan( context, std::move( scanStore), NOW, expiry, baseZip, payload) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 機種別配布表と必須ファームウェアの原証拠、全Models、配布物の競合を私有索引で検査します
 * @param[in,out] context 共通試験集計です
 * @param[in] key 人工索引だけを署名するRAM内試験鍵です
 * @note 端末用の読み取りでは同梱の従来行を保持し、通常照合では公式の配布元を確認します
 */
//------------------------------------------------------------------------------
void testPlatformDeviceSupplement( TestContext &context, const RamKey &key)
{
	using Status   = IndexRecordsStatus ;
	using Vendor   = IndexPlatformMachineVendor ;
	const auto mtm = parseIndexPlatformMachine( L" lenovo\t", L" 7dh4cto1ww\t") ;	// 完全な型番です
	DRIVERCRATE_EXPECT( context, mtm.vendor == Vendor::LENOVO && mtm.machineType == "7DH4") ;
	const auto machineType = parseIndexPlatformMachine( L"LENOVO", L"\tz9z1 ") ;	// 四文字型番です
	DRIVERCRATE_EXPECT( context,
					   machineType.vendor == Vendor::LENOVO && machineType.machineType == "Z9Z1") ;
	const auto otherVendor =
		// 別の製造元です
		parseIndexPlatformMachine( L"Synthetic Manufacturer", L"Z9Z1") ;
	DRIVERCRATE_EXPECT( context,
					   otherVendor.vendor == Vendor::OTHER && otherVendor.machineType.empty()) ;
	const auto noVendor = parseIndexPlatformMachine( L"\t ", L"Z9Z1") ;	// 製造元が不明です
	DRIVERCRATE_EXPECT( context, noVendor.vendor == Vendor::UNKNOWN && noVendor.machineType.empty()) ;
	// 不完全MTM、型番以外の表記、区切り・非ASCII・中間NULを型番へ縮めません
	for( const std::wstring_view product :
		{std::wstring_view{}, std::wstring_view{L"7DH4C"}, std::wstring_view{L"7DH4CTO1W"},
		 std::wstring_view{L"7DH4CTO1WWW"}, std::wstring_view{L"ThinkSystem 7DH4"},
		 std::wstring_view{L"7DH4-TO1WW"}, std::wstring_view{L"7ＤH4CTO1WW"},
		 std::wstring_view{L"7DH4\0TO1WW", 10U}}) {
		const auto invalid = parseIndexPlatformMachine( L"LENOVO", product) ;	// 型番だけが不明です
		DRIVERCRATE_EXPECT( context,
						   invalid.vendor == Vendor::LENOVO && invalid.machineType.empty()) ;
	}

	const ComApartment apartment( COINIT_MULTITHREADED) ;	// 原Server条件の試験用MTAです
	const auto		   expiry = std::chrono::sys_days{std::chrono::year{2026} / 10 / 12} +
						std::chrono::hours{3} ;	// 既存取得記述の原期限です
	constexpr std::string_view MODELS =
		// 架空INFの元順序に、対象Hardwareと対象外Hardware・Compatibleを混在させます
		R"json([{"kind":"HARDWARE","value":"PCI\\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF"},{"kind":"COMPATIBLE","value":"PCI\\VEN_FFFF&DEV_0001&SUBSYS_3333FFFF"},{"kind":"HARDWARE","value":"PCI\\VEN_FFFF&DEV_0001&SUBSYS_4444FFFF"},{"kind":"HARDWARE","value":"PCI\\VEN_FFFF&DEV_0001&SUBSYS_2222FFFF&REV_01"}])json" ;
	constexpr std::string_view TARGETS =
		// 元Modelsと逆順にし、表の元の大文字小文字も残します
		R"json(["pci\\ven_ffff&dev_0001&subsys_2222ffff&rev_01","PCI\\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF"])json" ;
	const std::string scope =
		R"json(,"platformDeviceScope":{"pageUrl":"https://vendor.example/support","pageSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} +
		R"json(","observedAtUtc":"2026-10-10T02:00:00Z","model":"Synthetic Server R1","machineTypes":["Z9Z2","Z9Z1"],"packageHardwareIds":)json" +
		std::string{TARGETS} + "}" ;		// 配布表、導線、取得元の原URLと原hashは同じです
	const auto source = recordSource() ;	// 公式配布表に結合する架空取得元です
	const auto client =
		replaced( descriptorRecord( descriptorFixture(),
								  distributionRecord( "platform-scoped", true, "CONTENT_INSPECTED")),
				 R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
				 MODELS) ;	// 同じ人工INFです
	const auto weak =
		// 元Server条件付きのv2です
		serverHostRaw( client, "WINDOWS_SERVER_2022", "3", {}) ;
	// 元v2に対象条件だけを追加し、元Modelsと取得記述を保持します
	const auto scoped = [&]( std::string row) {
		row = replaced( std::move( row), "driver-index-record-v2", "driver-index-record-v4") ;
		row.pop_back() ;
		return row + scope + "}\n" ;
	} ;
	const auto row = scoped( weak) ;	// 末尾改行も署名された原行の一部です
	// 元行と取得元を補足の原領域へ包みます
	const auto supplemental = []( const std::string_view sources, const std::string_view entries) {
		return replaced( descriptorIndex( sources, entries), "driver-index-records-v2",
						"driver-index-records-supplement-v1") ;
	} ;
	// 局所世代1の私有候補に元行を包み、共通検査だけを行います
	const auto pending = [&]( const std::string_view entries, const std::string_view sources) {
		const auto raw = replaced( supplemental( sources, entries), R"("assetGeneration":7)",
								  R"("assetGeneration":1)") ;	// 私有候補の固定世代です
		return signed_index_detail::decodePendingCollectorSupplement(
			std::as_bytes( std::span{raw.data(), raw.size()}), expiry, NOW) ;
	} ;
	const auto accepted = pending( recordEntry( key, row), source) ;	// 同じ全Modelsから対象を導きます
	DRIVERCRATE_EXPECT( context, accepted.status == Status::SCHEMA_VALIDATED && accepted.data &&
									accepted.data->records.size() == 1U) ;
	// 全Modelsと原配布条件の並びをそれぞれ保持し、元Models上の対象位置を確認します
	if( accepted.data && accepted.data->records.size() == 1U) {
		const auto &record		= accepted.data->records.front() ;	// 保存後の原行です
		const auto &deviceScope = record.platformDeviceScope ;		// 配布表の型付き条件です
		DRIVERCRATE_EXPECT( context, record.recordSchemaVersion == 4U &&
										record.originalBytes == row &&
										record.recordSha256 == key.digest( row) &&
										record.publishedIdentityEvidence.pnpIds.size() == 4U &&
										signed_index_detail::indexRecordNeedsSupplement( record)) ;
		DRIVERCRATE_EXPECT(
			context,
			deviceScope && deviceScope->pageUrl == "https://vendor.example/support" &&
				deviceScope->pageSha256 ==
					signed_index_json::decodeHash( RECORD_EVIDENCE_HASH, Status::INVALID_EVIDENCE) &&
				deviceScope->observedAtUtc == NOW - std::chrono::hours{28} &&
				deviceScope->model == "Synthetic Server R1" &&
				deviceScope->machineTypes == (std::vector<std::string>{"Z9Z2", "Z9Z1"}) &&
				deviceScope->packageHardwareIds ==
					(std::vector<std::string>{R"(pci\ven_ffff&dev_0001&subsys_2222ffff&rev_01)",
											  R"(PCI\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF)"}) &&
				deviceScope->hardwareIdIndices == (std::vector<std::size_t>{0U, 3U})) ;
		// 取得根拠を一切変えず、機種条件の違いだけで共有対象を分けます
		if( deviceScope) {
			auto reordered = record ;	// 同じ型番集合を別順序で示します
			std::ranges::reverse( reordered.platformDeviceScope->machineTypes) ;
			auto narrower = record ;	// 一方だけの別型番を許可しません
			std::erase( narrower.platformDeviceScope->machineTypes, "Z9Z1") ;
			auto unscoped = record ;	// 機種別と無条件を同じ共有組へ入れません
			unscoped.platformDeviceScope.reset() ;
			DRIVERCRATE_EXPECT( context, matchesSharedIndexPayloadEvidence( record, reordered) &&
											!matchesSharedIndexPayloadEvidence( record, narrower) &&
											!matchesSharedIndexPayloadEvidence( record, unscoped)) ;
		}
	}

	// 旧本文では正しい元条件と原hashを持つv4でも認識できません
	rejectRecordIndex( context, key, descriptorIndex( source, recordEntry( key, row)),
					  Status::INVALID_RECORD, {1U, 1U, 0U, 1U, 0U}) ;
	const std::string differentHash( 64U, 'a') ;	// 別の元応答を示す正常なSHA-256表記です
	// 元行を作り直して正しい行hashを付け、配布条件そのものの不成立だけを検査します
	for( const auto &invalid :
		{scoped( client), scoped( serverHostRaw( client, "WINDOWS_SERVER_2022", "3", "MISSING_SUITE")),
		 replaced( row, R"("machineTypes":["Z9Z2","Z9Z1"])", R"("machineTypes":[])"),
		 replaced( row, "Z9Z1", "Z9Z2"), replaced( row, "Z9Z1", "z9z1"), replaced( row, TARGETS, "[]"),
		 replaced(
			 row, TARGETS,
			 R"json(["pci\\ven_ffff&dev_0001&subsys_1111ffff","PCI\\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF"])json"),
		 replaced( row, "subsys_2222ffff&rev_01", "subsys_3333ffff"),
		 replaced( row, "subsys_2222ffff&rev_01", "subsys_5555ffff"),
		 replaced( row, "&subsys_2222ffff&rev_01", ""),
		 replaced( row, R"("pageUrl":"https://vendor.example/support")",
				  R"("pageUrl":"https://vendor.example/other-table")"),
		 replaced( row, "\"pageSha256\":\"" + std::string{RECORD_EVIDENCE_HASH},
				  "\"pageSha256\":\"" + differentHash),
		 replaced( row, "\"authorityEvidenceSha256\":\"" + std::string{RECORD_EVIDENCE_HASH},
				  "\"authorityEvidenceSha256\":\"" + differentHash),
		 replaced( row, "COLLECTOR_VERIFIED_OFFICIAL_ROUTE", "MANUAL_VERIFIED_OFFICIAL_ROUTE"),
		 replaced( row, "OFFICIAL_PAYLOAD_LINK", "OFFICIAL_CDN_LINK"),
		 replaced( row, "2026-10-10T02:00:00Z", "2026-10-10T03:00:01Z"),
		 replaced( row, "2026-10-10T02:00:00Z", "2026-10-04T02:59:59Z")}) {
		const auto result = pending( recordEntry( key, invalid), source) ;	// 私有候補でも失敗します
		DRIVERCRATE_EXPECT( context, result.status == Status::INVALID_EVIDENCE && !result.data) ;
	}

	// 取得元の原本文hashだけを変えた場合も同行の条件は成立しません
	const auto wrongSource =
		pending( recordEntry( key, row), replaced( source, RECORD_EVIDENCE_HASH, differentHash)) ;
	DRIVERCRATE_EXPECT( context,
					   wrongSource.status == Status::INVALID_EVIDENCE && !wrongSource.data) ;
	// 旧wireへ対象条件を載せる場合、またはv4から対象条件を落とす場合は項目集合が違います
	for( const auto &wrongSchema :
		{replaced( row, "driver-index-record-v4", "driver-index-record-v2"),
		 replaced( weak, "driver-index-record-v2", "driver-index-record-v4")}) {
		const auto result = pending( recordEntry( key, wrongSchema), source) ;	// 閉じた項目集合です
		DRIVERCRATE_EXPECT( context, result.status == Status::INVALID_RECORD && !result.data) ;
	}

	const auto alias		= replaced( weak, "\"recordId\":\"platform-scoped\"",
									   "\"recordId\":\"platform-alias\"") ;	// 同じ配布物・INFのv2別名です
	const auto changedTypes = replaced( scoped( alias), "Z9Z1", "Z9Z3") ;	// 同版の別対象です
	const auto changedIds	= replaced( scoped( alias), "subsys_2222ffff&rev_01",
									   "subsys_4444ffff") ;	// 元Models内の別対象です
	const auto changedModel =
		// 別の対象機種です
		replaced( scoped( alias), "Synthetic Server R1", "Synthetic Server R2") ;
	const auto differentModels =
		// 元ModelsのID列の差です
		replaced( scoped( alias), "SUBSYS_3333FFFF", "SUBSYS_5555FFFF") ;
	// 入力順にかかわらず一部の行も返さず、条件の取り違えと弱い別名を拒否します
	for( const auto &other : {alias, changedTypes, changedIds, changedModel, differentModels}) {
		// 同じ衝突を両順で確認し、先頭・末尾の優先規則による上書きを防ぎます
		for( const auto &entries : {recordEntry( key, row) + "," + recordEntry( key, other),
								   recordEntry( key, other) + "," + recordEntry( key, row)}) {
			const auto result = pending( entries, source) ;	// 同一補足内の組です
			DRIVERCRATE_EXPECT( context, result.status == Status::PLATFORM_DEVICE_SCOPE_CONFLICT &&
											result.error == 0 && !result.data) ;
		}
	}

	// 対象の元の順序と大文字小文字だけを変えます
	const auto reorderedTargets = replaced(
		replaced( scoped( alias), R"(["Z9Z2","Z9Z1"])", R"(["Z9Z1","Z9Z2"])"), TARGETS,
		R"json(["pci\\ven_ffff&dev_0001&subsys_1111ffff","PCI\\VEN_FFFF&DEV_0001&SUBSYS_2222FFFF&REV_01"])json") ;
	// 比較では同じ対象になり、保存する元行は別々に保持します
	const auto sameTargets =
		pending( recordEntry( key, row) + "," + recordEntry( key, reorderedTargets), source) ;
	DRIVERCRATE_EXPECT( context,
					   sameTargets.status == Status::SCHEMA_VALIDATED && sameTargets.data &&
						   sameTargets.data->records.size() == 2U &&
						   sameTargets.data->records.back().originalBytes == reorderedTargets) ;

	// 既存Catalogの起点に結ぶときだけ、同じ原行の全URLを書き換えます
	const auto catalogOrigin = []( std::string raw) {
		// 架空の起点が残らないところまで各URLを一度ずつ置き換えます
		while( raw.find( "vendor.example") != raw.npos) {
			raw = replaced( std::move( raw), "vendor.example", "www.catalog.update.microsoft.com") ;
		}

		return raw ;
	} ;
	const auto catalogSource = catalogOrigin( recordSource( "catalog-platform")) ;	// v3の取得元です
	auto	   catalog		 = catalogOrigin(
		replaced( alias, "\"sourceId\":\"fixture-source\"",
							 "\"sourceId\":\"catalog-platform\"")) ;	// 同じServer版と物理配布物です
	catalog = replaced( std::move( catalog), "driver-index-record-v2", "driver-index-record-v3") ;
	catalog.pop_back() ;
	catalog +=
		R"json(,"catalogHardwareScope":{"detailsUrl":"https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=11111111-2222-4333-8444-555555555555","detailsSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} +
		R"json(","observedAtUtc":"2026-10-10T02:00:00Z","packageHardwareIds":)json" +
		std::string{TARGETS} + "}}" ;
	// 同じ配布物に異種の対象条件を併記した場合も保留します
	const auto overlappingCatalog = pending( recordEntry( key, row) + "," + recordEntry( key, catalog),
											source + "," + catalogSource) ;
	DRIVERCRATE_EXPECT( context,
					   overlappingCatalog.status == Status::PLATFORM_DEVICE_SCOPE_CONFLICT &&
						   !overlappingCatalog.data) ;

	// 旧本文と追加欄を同一GZipの認証済み領域へ結び、両欄の組を検査します
	const auto signedBase = [&]( const std::string_view base, const std::string_view extra,
								std::shared_ptr<SignedIndexStore> *const store = nullptr) {
		const auto baseIndex = descriptorIndex( source, recordEntry( key, base)) ;	// 本文の元領域です
		// 同じ認証対象に本文と補足の圧縮原byteを入れます
		const auto gzip = assetWithExtra(
			assetGzip( baseIndex), assetSupplementFrame( key, baseIndex, assetGzip( extra), expiry)) ;
		std::string outer ;	// 保存する場合は同じ署名入りenvelopeを使います
		const auto	manifest = assetManifest( key, gzip, false, recordQuality( {1U, 1U, 0U, 1U, 0U}),
											 &outer) ;							// 集計は本文一件分です
		const auto bytes = authenticateIndexAssetBytes( manifest, gzip, NOW) ;	// 実認証した原圧縮です
		// fixture生成の失敗を競合検査の成功に数えません
		if( !bytes.receipt) {
			throw std::runtime_error( "platform fixture authentication failed") ;
		}

		auto baseResult = readSignedIndexRecords( *bytes.receipt, NOW) ;	// 本文を単独で読み戻します
		// 本文自体は追加欄の有無にかかわらず元byteと原hashを保持します
		if( !baseResult.receipt || baseResult.receipt->records().size() != 1U ||
		   baseResult.receipt->records().front().originalBytes != base ||
		   baseResult.receipt->records().front().recordSha256 != key.digest( base)) {
			throw std::runtime_error( "platform fixture changed signed base records") ;
		}

		// 通常スキャンでは元署名と圧縮byteを隔離ストアから再読み取りします
		if( store != nullptr) {
			const std::array<signed_index_detail::TrustKey, 1U> trust{
				{{"fixture-main", key.publicBlob}}} ;	// この人工鍵の公開部だけです
			auto opened =
				// この例の所有ストアです
				signed_index_store_detail::Access::createIsolated( trust) ;
			// 保存の失敗を端末側で期待した拒否と取り違えません
			if( !opened.store ||
			   !opened.store->commit( *baseResult.receipt, outer, gzip, NOW).snapshot) {
				throw std::runtime_error( "platform scan isolated commit") ;
			}

			*store = std::move( opened.store) ;
		}

		return std::move( *baseResult.receipt) ;
	} ;
	const auto onlyScoped =
		// 制限付きv4を一件だけ入れます
		supplemental( source, recordEntry( key, row)) ;
	// 同一exact版と汎用Serverでは本文を経由した条件の回避を拒否します
	for( const auto &base :
		{alias,
		 replaced( serverHostRaw( client, "WINDOWS_SERVER_2022", "3", "LEGACY_ENUM_GENERIC_SERVER"),
				  "\"recordId\":\"platform-scoped\"", "\"recordId\":\"generic-alias\"")}) {
		// 運搬認証の結果を保ったまま両欄の意味が衝突します
		const auto result = readSignedIndexConsumerSupplement( signedBase( base, onlyScoped), NOW) ;
		DRIVERCRATE_EXPECT( context,
						   result.contents.transportStatus ==
								   IndexAssetSupplementStatus::BYTE_VALIDATED &&
							   result.contents.status == Status::PLATFORM_DEVICE_SCOPE_CONFLICT &&
							   result.contents.records.empty()) ;
	}

	const auto otherServer = replaced( alias, "WINDOWS_SERVER_2022",
									  "WINDOWS_SERVER_2025") ;	// 同じ物理配布物の別exact範囲です
	// 旧公開リーダーでは物理配布物が衝突しなくてもv4を拒否します
	const auto publicResult =
		readSignedIndexSupplementRecords( signedBase( otherServer, onlyScoped), NOW) ;
	DRIVERCRATE_EXPECT( context,
					   publicResult.transportStatus == IndexAssetSupplementStatus::BYTE_VALIDATED &&
						   publicResult.status == Status::INVALID_SUPPLEMENT_PURPOSE &&
						   publicResult.records.empty() && publicResult.sources.empty()) ;
	const auto oldRow = replaced(
		replaced( otherServer, "\"recordId\":\"platform-alias\"", "\"recordId\":\"other-v2\""),
		"drivers/fixture.inf", "drivers/other-v2.inf") ;	// 既存の無条件v2です
	const auto otherCatalog = replaced( catalog, "drivers/fixture.inf",
									   "drivers/other-v3.inf") ;	// 既存Catalog条件のv3です
	const auto extra		= supplemental( source + "," + catalogSource,
										   recordEntry( key, row) + "," + recordEntry( key, oldRow) + "," +
											   // 両形式の従来行も同じ追加欄へ入れます
											   recordEntry( key, otherCatalog)) ;
	// 両欄の検査後、通常の端末リーダーへ渡す行と元補足領域を確認します
	const auto result = readSignedIndexConsumerSupplement( signedBase( otherServer, extra), NOW) ;
	DRIVERCRATE_EXPECT( context, result.contents.status == Status::SCHEMA_VALIDATED &&
									result.contents.transportStatus ==
										IndexAssetSupplementStatus::BYTE_VALIDATED &&
									result.expandedSha256 == key.digest( extra) &&
									result.expiresAtUtc == expiry &&
									result.contents.records.size() == 3U &&
									result.contents.records[0U].originalBytes == row &&
									result.contents.records[0U].recordSchemaVersion == 4U &&
									result.contents.records[0U].recordSha256 == key.digest( row) &&
									result.contents.records[1U].originalBytes == oldRow &&
									result.contents.records[1U].recordSchemaVersion == 2U &&
									result.contents.records.back().originalBytes == otherCatalog &&
									result.contents.records.back().recordSchemaVersion == 3U) ;

	// 公式配布物を選ぶ前に利用者が確認することを示す架空の案内
	constexpr std::string_view ARCHIVE_CONFIRM = "Verify the standalone device and backup software" ;
	const std::string		   archiveConfirmation =
		R"json({"kind":"USER_CONFIRMATION","description":")json" + std::string{ARCHIVE_CONFIRM} +
		R"json(","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} + R"json("})json" ;	// 元ページに結ぶ機器ごとの確認です
	const std::string archiveScope =
		R"json(,"archiveHardwareScope":{"pageUrl":"https://vendor.example/support","pageSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} +
		R"json(","observedAtUtc":"2026-10-10T02:00:00Z","hardwareIds":)json" +
		std::string{TARGETS} + "}" ;	// 元Models内の完全Hardware IDだけを対象にします
	// 配布表の証拠を確認する形式にした、弱い元レコードからの対照
	auto archiveRecord = replaced( weak, "driver-index-record-v2", "driver-index-record-v7") ;
	archiveRecord	   = replaced( std::move( archiveRecord), R"("items":[)",
								  "\"items\":[" + archiveConfirmation + ",") ;
	// 元INFと三つのローカル条件を同じ取得ZIP内のINFへ結びます
	while( archiveRecord.find( "https://vendor.example/fixture.inf") != archiveRecord.npos) {
		archiveRecord = replaced( std::move( archiveRecord), "https://vendor.example/fixture.inf",
								 "https://vendor.example/fixture.zip") ;
	}

	archiveRecord = replaced(
		std::move( archiveRecord),
		R"json("calculatedHash":{"state":"KNOWN","sha256":")json" + std::string{RECORD_CLAIM_HASH} +
			R"json(","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
			std::string{RECORD_EVIDENCE_HASH},
		R"json("calculatedHash":{"state":"KNOWN","sha256":")json" + std::string{RECORD_CLAIM_HASH} +
			R"json(","evidenceUrl":"https://vendor.example/fixture.zip","evidenceSha256":")json" +
			std::string{RECORD_CLAIM_HASH}) ;
	archiveRecord.pop_back() ;
	archiveRecord += archiveScope + "}" ;
	const auto archiveExtra =
		// 元署名領域です
		supplemental( source, recordEntry( key, archiveRecord)) ;
	const auto archiveBase =
		// 別の明示Server版は重なりません
		signedBase( otherServer, archiveExtra) ;
	// 配布表と明示したファームウェア条件を含む署名追加欄の読取り結果
	const auto archiveAccepted = readSignedIndexConsumerSupplement( archiveBase, NOW) ;
	DRIVERCRATE_EXPECT( context, archiveAccepted.contents.status == Status::SCHEMA_VALIDATED &&
									archiveAccepted.expandedSha256 == key.digest( archiveExtra) &&
									archiveAccepted.expiresAtUtc == expiry &&
									archiveAccepted.contents.records.size() == 1U) ;
	// 元Modelsを全て保持し、完全Hardware IDの一致位置だけを別に導きます
	if( archiveAccepted.contents.records.size() == 1U) {
		const auto &archive = archiveAccepted.contents.records.front() ;	// 元行です
		DRIVERCRATE_EXPECT( context, archive.recordSchemaVersion == 7U &&
										isIndexHardwareScoped( archive) &&
										archive.recordSha256 == key.digest( archiveRecord) &&
										archive.publishedIdentityEvidence.pnpIds.size() == 4U &&
										archive.archiveHardwareScope &&
										archive.archiveHardwareScope->hardwareIdIndices ==
											(std::vector<std::size_t>{0U, 3U})) ;
		DRIVERCRATE_EXPECT( context, isIndexLookupIdEligible( archive, 0U) &&
										!isIndexLookupIdEligible( archive, 1U) &&
										!isIndexLookupIdEligible( archive, 2U) &&
										isIndexLookupIdEligible( archive, 3U) &&
										!isIndexLookupIdEligible( archive, 4U)) ;
	}

	DRIVERCRATE_EXPECT( context, readSignedIndexSupplementRecords( archiveBase, NOW).status ==
									Status::INVALID_SUPPLEMENT_PURPOSE) ;
	rejectRecordIndex( context, key, descriptorIndex( source, recordEntry( key, archiveRecord)),
					  Status::INVALID_RECORD, {1U, 1U, 0U, 1U, 0U}) ;
	const auto weakArchiveAlias =
		readSignedIndexConsumerSupplement( signedBase( alias, archiveExtra),
										  NOW) ;	// 同じServer版で確認が欠落します
	DRIVERCRATE_EXPECT( context, weakArchiveAlias.contents.status ==
										Status::ARCHIVE_HARDWARE_SCOPE_CONFLICT &&
									weakArchiveAlias.contents.records.empty()) ;
	const auto archiveAlias =
		// 別の元行です
		replaced( archiveRecord, "platform-scoped", "archive-alias") ;
	// 対象と機器確認のいずれかが異なる別名、他の専用対象方式との重複を拒否します
	for( const auto &other :
		{replaced( archiveAlias, ARCHIVE_CONFIRM, "Other device conditions"),
		 replaced( archiveAlias, "subsys_2222ffff&rev_01", "subsys_4444ffff"), scoped( alias)}) {
		const auto conflict =
			pending( recordEntry( key, other) + "," + recordEntry( key, archiveRecord),
					source) ;	// 競合する元行を両方含めます
		DRIVERCRATE_EXPECT( context, conflict.status == Status::ARCHIVE_HARDWARE_SCOPE_CONFLICT &&
										!conflict.data) ;
	}

	// Compatibleのみの一致、頁の確認欠落、元配布への根拠不一致を拒否します
	for( const auto &invalidArchive :
		{replaced( archiveRecord, "subsys_2222ffff&rev_01", "subsys_3333ffff"),
		 replaced( archiveRecord, archiveConfirmation + ",", ""),
		 replaced( archiveRecord, archiveConfirmation,
				  replaced( archiveConfirmation, "vendor.example/support", "vendor.example/other")),
		 replaced( archiveRecord,
				  "\"authorityEvidenceSha256\":\"" + std::string{RECORD_EVIDENCE_HASH},
				  "\"authorityEvidenceSha256\":\"" + differentHash)}) {
		const auto denied =
			// 元行hashは再計算します
			pending( recordEntry( key, invalidArchive), source) ;
		DRIVERCRATE_EXPECT( context, denied.status == Status::INVALID_EVIDENCE && !denied.data) ;
	}

	constexpr std::string_view FIRST_IDS = R"(["1111FFFF","2222FFFF"])" ;	// 元Modelsの対象群です
	constexpr std::string_view FIRST_GROUP =
		// 元Modelsに二つのHardware IDがある元条件です
		R"({"subsystemIds":["1111FFFF","2222FFFF"],"versionLabel":"R1.2_rc-1","evidenceUrl":"https://vendor.example/firmware/r1"})" ;
	constexpr std::string_view SECOND_GROUP =
		// Compatibleだけが一致する元条件です
		R"({"subsystemIds":["3333FFFF","5555FFFF"],"versionLabel":"R2.3","evidenceUrl":"https://vendor.example/firmware/r2"})" ;
	const auto groups =
		"[" + std::string{FIRST_GROUP} + "," + std::string{SECOND_GROUP} + "]" ;	// 公式の二群です
	// 元v4行の配布表と順序を借用し、追加欄だけに置けるv5を作ります
	const auto withFirmware = []( std::string raw, const std::string_view firmwareGroups) {
		raw = replaced( std::move( raw), "driver-index-record-v4", "driver-index-record-v5") ;
		return replaced( std::move( raw), "}}\n",
						"},\"platformFirmwareGroups\":" + std::string{firmwareGroups} + "}\n") ;
	} ;
	// 同じ正式配布表にある二群の原証拠を、実署名と私有候補の双方で検証します
	{
		const auto firmwareRow = withFirmware( row, groups) ;	// 元Modelsの全IDと二群を持つ原行です
		const auto firmwareExtra =
			// v5追加欄です
			supplemental( source, recordEntry( key, firmwareRow)) ;
		const auto firmwareBase = signedBase( otherServer, firmwareExtra) ;	// 本文と同じ実署名です
		const auto privateFirmware =
			// 端末用の読取結果です
			readSignedIndexConsumerSupplement( firmwareBase, NOW) ;
		DRIVERCRATE_EXPECT( context,
						   privateFirmware.contents.status == Status::SCHEMA_VALIDATED &&
							   privateFirmware.contents.transportStatus ==
								   IndexAssetSupplementStatus::BYTE_VALIDATED &&
							   privateFirmware.expandedSha256 == key.digest( firmwareExtra) &&
							   privateFirmware.expiresAtUtc == expiry &&
							   privateFirmware.contents.records.size() == 1U) ;
		// 利用可能な全元行で、有効な所属だけを抽出して元Modelsを保持します
		if( privateFirmware.contents.records.size() == 1U) {
			const auto &record	 = privateFirmware.contents.records.front() ;	// 実認証した元v5行です
			const auto &models	 = record.publishedIdentityEvidence.pnpIds ;	// 元順序と種別です
			const auto &firmware = record.platformFirmwareGroups ;				// 対象のない群も含む公式条件です
			const auto &deviceScope = record.platformDeviceScope ;				// v4と共通の型付き配布条件です
			DRIVERCRATE_EXPECT(
				context, record.recordSchemaVersion == 5U && record.originalBytes == firmwareRow &&
							 record.recordSha256 == key.digest( firmwareRow) &&
							 signed_index_detail::indexRecordNeedsSupplement( record) &&
							 signed_index_detail::isInspectedIndexAcquisition( record, NOW)) ;
			DRIVERCRATE_EXPECT(
				context,
				deviceScope && deviceScope->pageUrl == "https://vendor.example/support" &&
					deviceScope->pageSha256 ==
						signed_index_json::decodeHash( RECORD_EVIDENCE_HASH,
													  Status::INVALID_EVIDENCE) &&
					deviceScope->observedAtUtc == NOW - std::chrono::hours{28} &&
					deviceScope->model == "Synthetic Server R1" &&
					deviceScope->machineTypes == (std::vector<std::string>{"Z9Z2", "Z9Z1"}) &&
					deviceScope->hardwareIdIndices == (std::vector<std::size_t>{0U, 3U})) ;
			DRIVERCRATE_EXPECT(
				context, models.size() == 4U && models[0U].kind == IndexPnpIdKind::HARDWARE &&
							 models[0U].value == R"(PCI\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF)" &&
							 models[1U].kind == IndexPnpIdKind::COMPATIBLE &&
							 models[1U].value == R"(PCI\VEN_FFFF&DEV_0001&SUBSYS_3333FFFF)" &&
							 models[2U].kind == IndexPnpIdKind::HARDWARE &&
							 models[2U].value == R"(PCI\VEN_FFFF&DEV_0001&SUBSYS_4444FFFF)" &&
							 models[3U].kind == IndexPnpIdKind::HARDWARE &&
							 models[3U].value == R"(PCI\VEN_FFFF&DEV_0001&SUBSYS_2222FFFF&REV_01)") ;
			DRIVERCRATE_EXPECT(
				context, firmware.size() == 2U &&
							 firmware[0U].subsystemIds ==
								 (std::vector<std::string>{"1111FFFF", "2222FFFF"}) &&
							 firmware[0U].versionLabel == "R1.2_rc-1" &&
							 firmware[0U].evidenceUrl == "https://vendor.example/firmware/r1" &&
							 firmware[1U].subsystemIds ==
								 (std::vector<std::string>{"3333FFFF", "5555FFFF"}) &&
							 firmware[1U].versionLabel == "R2.3" &&
							 firmware[1U].evidenceUrl == "https://vendor.example/firmware/r2") ;
		}

		// 正しい原行と追加欄の原byteでも公開用の入口では受理しません
		rejectRecordIndex( context, key, descriptorIndex( source, recordEntry( key, firmwareRow)),
						  Status::INVALID_RECORD, {1U, 1U, 0U, 1U, 0U}) ;
		const auto publicFirmware =
			// 公開用の読取結果です
			readSignedIndexSupplementRecords( firmwareBase, NOW) ;
		DRIVERCRATE_EXPECT(
			context, publicFirmware.transportStatus == IndexAssetSupplementStatus::BYTE_VALIDATED &&
						 publicFirmware.status == Status::INVALID_SUPPLEMENT_PURPOSE &&
						 publicFirmware.records.empty() && publicFirmware.sources.empty()) ;

		// 同じ鍵と私有候補を借用し、変えた原行の正しいhashを付けてから理由を確認します
		const auto rejectFirmware = [&]( const std::string_view invalid, const Status status) {
			const auto rejected =
				// 候補全体を拒否します
				pending( recordEntry( key, invalid), source) ;
			DRIVERCRATE_EXPECT( context, rejected.status == status && !rejected.data) ;
		} ;
		// 必須項目の欠落、旧wireへの混入、未知の群項目は文法の拒否です
		for( const auto &invalid :
			{replaced( firmwareRow, "driver-index-record-v5", "driver-index-record-v4"),
			 replaced( row, "driver-index-record-v4", "driver-index-record-v5"),
			 replaced( firmwareRow, scope, ""),
			 replaced( firmwareRow, "\"versionLabel\"", "\"requiredVersion\""),
			 replaced( firmwareRow, "R1.2_rc-1", std::string( 129U, 'V'))}) {
			rejectFirmware( invalid, Status::INVALID_RECORD) ;
		}

		// 群そのもの、全Modelsからの導出、従来の同一配布表への結合を分けて変えます
		for( const auto &invalid :
			{withFirmware( row, "[]"), withFirmware( row, replaced( groups, FIRST_IDS, "[]")),
			 withFirmware( row, replaced( groups, "5555FFFF", "1111FFFF")),
			 withFirmware( row, replaced( groups, "5555FFFF", "3333FFFF")),
			 withFirmware( row, replaced( groups, "5555FFFF", "5555ffff")),
			 withFirmware( row, replaced( groups, "5555FFFF", "5555FFF")),
			 withFirmware( row, replaced( groups, "5555FFFF", "5555FGFF")),
			 withFirmware( row, replaced( groups, "R1.2_rc-1", "")),
			 withFirmware( row, replaced( groups, "R1.2_rc-1", "R1.2+rc")),
			 withFirmware( row, replaced( groups, FIRST_IDS, R"(["6666FFFF","7777FFFF"])")),
			 replaced( firmwareRow, TARGETS,
					  R"json(["PCI\\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF"])json"),
			 replaced( firmwareRow, TARGETS,
					  R"json(["PCI\\VEN_FFFF&DEV_0001&SUBSYS_3333FFFF"])json"),
			 replaced(
				 firmwareRow, TARGETS,
				 R"json(["PCI\\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF","PCI\\VEN_FFFF&DEV_0001&SUBSYS_2222FFFF&REV_01","PCI\\VEN_FFFF&DEV_0001&SUBSYS_4444FFFF"])json"),
			 replaced( firmwareRow, "&subsys_2222ffff&rev_01", "&subsys_2222ffff&rev_0"),
			 replaced( firmwareRow, R"("pageUrl":"https://vendor.example/support")",
					  R"("pageUrl":"https://vendor.example/other-table")"),
			 replaced( firmwareRow, "\"pageSha256\":\"" + std::string{RECORD_EVIDENCE_HASH},
					  "\"pageSha256\":\"" + differentHash)}) {
			rejectFirmware( invalid, Status::INVALID_EVIDENCE) ;
		}

		rejectFirmware( replaced( firmwareRow, "https://vendor.example/firmware/r1",
								"http://vendor.example/firmware/r1"),
					   Status::INVALID_URL) ;

		std::string manyIds{	// 閉じ括弧を除いた先頭群です
							FIRST_IDS.substr( 0U, FIRST_IDS.size() - 1U)} ;
		// 元二IDに30件の未一致IDを加え、群の32件上限まで埋めます
		for( unsigned index = 0U; index < 30U; ++index) {
			manyIds += ",\"" + std::to_string( 10'000'000U + index) + "\"" ;
		}

		// 借用期間が固定の群literalを値で保持し、各追加群に異なる架空IDを割り当てます
		const auto extraGroup = [group = SECOND_GROUP]( const unsigned index) {
			return replaced( std::string{group}, R"("3333FFFF","5555FFFF")",
							"\"" + std::to_string( 20'000'000U + index) + "\"") ;
		} ;
		std::string manyGroups{groups.substr( 0U, groups.size() - 1U)} ;	// 閉じ括弧を除いた元二群です
		// 元二群に14群を加え、行の16群上限まで埋めます
		for( unsigned index = 0U; index < 14U; ++index) {
			manyGroups += "," + extraGroup( index) ;
		}

		// 32 ID、16群、128文字の全上限で対象が元の二件のままになることを確認します
		const auto cappedGroups = replaced( manyGroups + "]", FIRST_IDS, manyIds + "]") ;
		const auto capped =
			// 三つの上限をすべて満たす原行です
			withFirmware( row, replaced( cappedGroups, "R1.2_rc-1", std::string( 128U, 'V'))) ;
		DRIVERCRATE_EXPECT( context, pending( recordEntry( key, capped), source).status ==
										Status::SCHEMA_VALIDATED) ;
		// 各上限の次の一件だけを足して計数の拒否を確認します
		rejectFirmware( withFirmware( row, replaced( groups, FIRST_IDS, manyIds + R"(,"10000030"])")),
					   Status::COUNT_LIMIT) ;
		rejectFirmware( withFirmware( row, manyGroups + "," + extraGroup( 14U) + "]"),
					   Status::COUNT_LIMIT) ;

		// 旧経路と群の割当・版・根拠が異なる別名を入力順に依存せず拒否します
		for( const auto &other :
			{alias, scoped( alias),
			 withFirmware( scoped( alias), replaced( groups, "R1.2_rc-1", "R1.3")),
			 withFirmware( scoped( alias), replaced( groups, "https://vendor.example/firmware/r1",
												  "https://vendor.example/firmware/revised-r1")),
			 withFirmware( scoped( alias),
						  replaced( replaced( groups, FIRST_IDS, R"(["1111FFFF","5555FFFF"])"),
								   R"(["3333FFFF","5555FFFF"])", R"(["3333FFFF","2222FFFF"])"))}) {
			// 先頭と末尾による優先を許さず、衝突時には一行も保持しません
			for( const auto &entries :
				{recordEntry( key, firmwareRow) + "," + recordEntry( key, other),
				 recordEntry( key, other) + "," + recordEntry( key, firmwareRow)}) {
				const auto conflict = pending( entries, source) ;	// 同じ追加欄内の別名です
				DRIVERCRATE_EXPECT( context,
								   conflict.status == Status::PLATFORM_DEVICE_SCOPE_CONFLICT &&
									   conflict.error == 0 && !conflict.data) ;
			}
		}

		// 同じ旧経路を本文へ移しても元ファームウェア条件の迂回を拒否します
		const auto oldAlias =
			readSignedIndexConsumerSupplement( signedBase( alias, firmwareExtra), NOW) ;
		DRIVERCRATE_EXPECT( context,
						   oldAlias.contents.transportStatus ==
								   IndexAssetSupplementStatus::BYTE_VALIDATED &&
							   oldAlias.contents.status == Status::PLATFORM_DEVICE_SCOPE_CONFLICT &&
							   oldAlias.contents.records.empty()) ;
		// 群の並びと群内のIDの並びだけを逆にした元行です
		const auto reorderedFirmware = withFirmware(
			reorderedTargets,
			"[" + std::string{SECOND_GROUP} + "," +
				replaced( std::string{FIRST_GROUP}, FIRST_IDS, R"(["2222FFFF","1111FFFF"])") + "]") ;
		// 群の意味が同じ別名はそれぞれの原行を保持します
		const auto sameFirmware = pending(
			recordEntry( key, firmwareRow) + "," + recordEntry( key, reorderedFirmware), source) ;
		DRIVERCRATE_EXPECT(
			context, sameFirmware.status == Status::SCHEMA_VALIDATED && sameFirmware.data &&
						 sameFirmware.data->records.size() == 2U &&
						 sameFirmware.data->records.back().originalBytes == reorderedFirmware) ;
	}

	std::string baseInf ;	// 本文の原ZIPへ入れた人工INFです
	const auto	baseZip =
		// 本文の原ZIPです
		normalWorkerDriverZip( false, &baseInf, {}, true, 0U, 0U, {}) ;
	const auto scopedInf = replaced(
		baseInf, R"(%Device%=Install,TESTBUS\SYNTH_0001)",
		"%Device%=Install,PCI\\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF,PCI\\VEN_FFFF&DEV_0001&SUBSYS_3333FFFF\r\n"
		"%Device%=Install,PCI\\VEN_FFFF&DEV_0001&SUBSYS_4444FFFF\r\n"
		"%Device%=Install,PCI\\VEN_FFFF&DEV_0001&SUBSYS_2222FFFF&REV_01") ;	// 機種別行の全Modelsです
	const auto scopedZip = normalWorkerDriverZip( false, nullptr, {}, true, 0U, 0U,
												 scopedInf) ;	// 本文と区別する原配布物です
	// 通常スキャンに載せる行だけを模擬端末のPorts ClassとModels節に揃えます
	const auto atPorts = []( std::string raw) {
		raw = replaced( std::move( raw), "{11111111-2222-3333-4444-555555555555}",
					   "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
		return replaced( std::move( raw), "Fixture.NTamd64", "Models.NTamd64") ;
	} ;
	// 各人工原配布物とそのINFの実byteを、型番による許可判定とは独立に署名行へ結びます
	const auto bindZip = [&]( std::string raw, const std::string_view zip,
							 const std::string_view inf) {
		const auto hash	  = recordDigest( key, zip) ;	// 発行・実計算の両申告は同じ原byteです
		raw				  = replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
		raw				  = replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
		raw				  = replaced( std::move( raw), "\"valueBytes\":1234",
									 "\"valueBytes\":" + std::to_string( zip.size())) ;
		raw				  = replaced( std::move( raw), "drivers/fixture.inf", "fixture.inf") ;
		const auto before = "fixture.inf\",\"evidenceSha256\":\"" +
							std::string{RECORD_EVIDENCE_HASH} ;	// 人工の旧INF根拠です
		const auto actual = "fixture.inf\",\"evidenceSha256\":\"" +
							// 人工ZIP内の実INF根拠です
							recordDigest( key, inf) ;
		// 元Modelsの根拠と三つのServer条件を同じINFの実ハッシュへ結びます
		for( unsigned occurrence{}; occurrence < 4U; ++occurrence) {
			raw = replaced( std::move( raw), before, actual) ;
		}

		return raw ;
	} ;
	// 型番条件なしのWindows Server 2022向け本文を用意します
	auto baseline = serverHostRaw(
		descriptorRecord( descriptorFixture(),
						 distributionRecord( "platform-baseline", true, "CONTENT_INSPECTED")),
		"WINDOWS_SERVER_2022", "3", {}) ;
	baseline = bindZip( atPorts( std::move( baseline)), baseZip, baseInf) ;
	// 追加欄の期限ちょうどでも本文の取得記述は有効です
	baseline = replaced( std::move( baseline), "2026-10-12T03:00:00Z", "2026-10-13T03:00:00Z") ;
	const auto scopedRecord = bindZip( atPorts( row), scopedZip, scopedInf) ;	// 機種別の原署名対象です
	// 本文と区別し、追加欄の取得元と配布表の全URLに同じホストを設定します
	const auto scopedAt = [&]( const std::string_view hostname, const std::string &platformRow) {
		const auto extraOrigin = [&]( std::string raw) {
			// 元の架空ホストへの申告が残らないまで置き換えます
			while( raw.find( "vendor.example") != raw.npos) {
				raw = replaced( std::move( raw), "vendor.example", hostname) ;
			}

			return replaced( std::move( raw), "\"sourceId\":\"fixture-source\"",
							"\"sourceId\":\"platform-scope-source\"") ;
		} ;
		return supplemental( extraOrigin( source), recordEntry( key, extraOrigin( platformRow))) ;
	} ;
	std::shared_ptr<SignedIndexStore> lenovo ;			// 実ホスト名と元表が一致する人工署名索引です
	std::shared_ptr<SignedIndexStore> unrecognized ;	// ホスト名が似る別の配布元です
	static_cast<void>(
		signedBase( baseline, scopedAt( "windows-server.lenovo.com", scopedRecord), &lenovo)) ;
	static_cast<void>( signedBase(
		baseline, scopedAt( "windows-server.lenovo.com.example", scopedRecord), &unrecognized)) ;
	runPlatformDeviceConsumerScan( context, std::move( lenovo), std::move( unrecognized), NOW, expiry,
								  baseZip, scopedZip) ;
	constexpr std::string_view SCAN_TARGETS =
		// 元Modelsの別群IDも公式の配布対象へ含めます
		R"json(["pci\\ven_ffff&dev_0001&subsys_2222ffff&rev_01","PCI\\VEN_FFFF&DEV_0001&SUBSYS_1111FFFF","PCI\\VEN_FFFF&DEV_0001&SUBSYS_4444FFFF"])json" ;
	constexpr std::string_view SCAN_SECOND_GROUP =
		// 表示上の必須版が同じでも、端末別の確認と同一端末での競合を区別します
		R"json({"subsystemIds":["3333FFFF","4444FFFF","5555FFFF"],"versionLabel":"R1.2_rc-1","evidenceUrl":"https://vendor.example/firmware/r2"})json" ;
	const auto scanGroups = "[" + std::string{FIRST_GROUP} + "," + std::string{SCAN_SECOND_GROUP} +
							"]" ;	// 公式の二群です
	const auto firmwareRecord = withFirmware( replaced( scopedRecord, TARGETS, SCAN_TARGETS),
											 scanGroups) ;	// 通常workerの原署名対象です
	std::shared_ptr<SignedIndexStore> firmwareStore ;		// 同じ配布物に二群を持つ隔離索引です
	static_cast<void>( signedBase( baseline, scopedAt( "windows-server.lenovo.com", firmwareRecord),
								 &firmwareStore)) ;
	runPlatformFirmwareConsumerHold( context, std::move( firmwareStore), NOW, baseZip, scopedZip) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定人工JSONの一objectへ欠損・未知・重複fieldを作ります
 * @param[in] raw 完全に既知の人工JSON。製品parserとして使用しません
 * @param[in] key 対象objectまたは一要素object配列の固定field名。空はrootです
 * @param[in] mutation 0は先頭field欠損、1は未知field、2は先頭field重複です
 * @return 元の残りbyteを維持した不正fixture
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string mutateDescriptorObject( std::string raw, const std::string_view key,
												 const unsigned mutation)
{
	const std::size_t anchor =
		// 固定field位置
		key.empty() ? 0U : raw.find( "\"" + std::string{key} + "\":") ;
	const std::size_t start = raw.find( '{', anchor) ;	// 完全fixture内の対象object開始
	// 不正なtest材料を空の拒否成功として扱わない
	if( anchor == std::string::npos || start == std::string::npos) {
		throw std::runtime_error( "descriptor mutation anchor missing") ;
	}

	std::size_t end = start + 1U ;	// 先頭memberの終端だけを有限走査する
	unsigned	depth{} ;			// 入れ子object・arrayの対応
	bool		quoted{} ;			// Stringの内部commaをmember境界にしない
	bool		escaped{} ;			// Quote escapeは一byteだけに作用する
	// 既知fixtureの先頭memberを最後のbyteまでに一度だけ走査する
	for( ; end < raw.size(); ++end) {
		const char character = raw[end] ;	// 現在の人工byte
		// String内部ではescapeされたquoteやcommaを保持する
		if( quoted) {
			// Escapeの直後一byteだけはdelimiterにしない
			if( escaped) {
				escaped = false ;
			}
			// 次byteのescapeを保持する
			else if( character == '\\') {
				escaped = true ;
			}
			// 完全quoteでだけstringを閉じる
			else if( character == '"') {
				quoted = false ;
			}
		}
		// String開始を区別する
		else if( character == '"') {
			quoted = true ;
		}
		// 先頭値の入れ子を維持する
		else if( character == '{' || character == '[') {
			++depth ;
		}
		// 同じmemberの入れ子だけを閉じる
		else if( (character == '}' || character == ']') && depth > 0U) {
			--depth ;
		}
		// 対象objectの最初のmember境界で有限走査を終える
		else if( depth == 0U && (character == ',' || character == '}')) {
			break ;
		}
	}

	const std::string member = raw.substr( start + 1U, end - start - 1U) ;	// 完全な先頭member
	// 欠損だけは元memberとそのcommaを除き、残りbyteを維持する
	if( mutation == 0U) {
		raw.erase( start + 1U, end - start) ;
	} else {
		raw.insert( start + 1U, mutation == 1U ? "\"codecUnknown\":null," : member + ",") ;
	}

	return raw ;
}

//------------------------------------------------------------------------------
/**
 * @brief 静的人工route hopを一つ作ります
 * @param[in] url 原の架空URL
 * @param[in] kind 固定元申告種別
 * @param[in] evidence 元の架空根拠URL
 * @return 出典hashへ結合した四fieldの人工JSON
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string descriptorHop( const std::string_view url, const std::string_view kind,
										const std::string_view evidence)
{
	return "{\"url\":\"" + std::string{url} + "\",\"kind\":\"" + std::string{kind} +
		   "\",\"evidenceUrl\":\"" + std::string{evidence} + "\",\"evidenceSha256\":\"" +
		   std::string{RECORD_EVIDENCE_HASH} + "\"}" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 完全fixtureのrouteだけを別の有限集合へ置き換えます
 * @param[in] descriptor 全13fieldの完全人工fixture
 * @param[in] hops 人工hop配列の本文
 * @return 残りbyteを維持した人工descriptor
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string descriptorRoute( std::string descriptor, const std::string_view hops)
{
	const std::size_t begin = descriptor.find( "\"route\":[") ;			// 固定人工fieldの開始
	const std::size_t end	= descriptor.find( "],\"terms\":", begin) ;	// 固定人工routeの終端
	// Mutationの失敗を製品codecの拒否成功にしない
	if( begin == std::string::npos || end == std::string::npos) {
		throw std::runtime_error( "descriptor route fixture missing") ;
	}

	descriptor.replace( begin, end + 1U - begin, "\"route\":[" + std::string{hops} + "]") ;
	return descriptor ;
}

//------------------------------------------------------------------------------
/**
 * @brief 真RAM署名と原GZipからv2 codecの正例・拒否・旧v1互換を検査します
 * @param[in,out] context 旧record groupと別の集計先
 * @note 実HTTP・EULA全文取得・grant・実device・導入は実行しません
 */
//------------------------------------------------------------------------------
void runDescriptorCodecChecks( TestContext &context)
{
	const int firstAssertion = context.assertionCount() ;	// 新codec groupだけの開始件数
	const int firstFailure	 = context.failureCount() ;		// 新codec groupだけの開始失敗
	RamKey	  key ;											// 既存CNG helperの秘密鍵はRAMだけに保持する
	key.generate( 3072U) ;
	const std::string descriptor = descriptorFixture() ;			// 一payloadの完全元申告
	const std::string raw		 = descriptorRecord( descriptor) ;	// Descriptorがschemaより先の原byte
	const std::string index =
		// Outer schemaも最後に置く
		descriptorIndex( recordSource(), recordEntry( key, raw)) ;
	const auto read =
		// 真署名・実GZip・原hash検査
		readRecordFixture( key, index, {1U, 1U, 1U, 0U, 0U}) ;
	DRIVERCRATE_EXPECT( context,
					   read.status == IndexRecordsStatus::SCHEMA_VALIDATED && read.receipt) ;
	// 正例生成失敗時は後のtyped assertionを空の成功へ変換しない
	if( !read.receipt) {
		throw std::runtime_error( "descriptor positive fixture rejected") ;
	}

	const auto resourceDescriptor =
		// 人工親byteへ結んだ新wire
		resourceDescriptorFixture( RECORD_CLAIM_HASH, 1234U) ;
	const auto resourceRecord = [&]( const std::string &descriptorValue) {
		return descriptorRecord( descriptorValue, replaced( distributionRecord(),
														  "\"infIdentity\":\"drivers/fixture.inf\"",
														  "\"infIdentity\":\"fixture.inf\"")) ;
	} ; // flat inventoryの原INFだけを参照する
	const auto resourceRead = readRecordFixture(
		key, descriptorIndex( recordSource(), recordEntry( key, resourceRecord( resourceDescriptor))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 通常codec全層の新wire
	DRIVERCRATE_EXPECT(
		context,
		resourceRead.receipt &&
			resourceRead.receipt->records()[0].acquisitionDescriptor->schemaVersion == 2U &&
			resourceRead.receipt->records()[0].acquisitionDescriptor->resourceContent.has_value()) ;
	std::string asusSource = recordSource() ;	// 同じ人工sourceの公式起点だけを揃える
	// Source内のorigin/pageを一貫した同値へ置換する
	while( asusSource.find( "vendor.example") != std::string::npos) {
		asusSource = replaced( std::move( asusSource), "vendor.example", "www.asus.com") ;
	}

	const auto dynamicDescriptor =
		// 新閉wire
		anonymousDescriptorFixture( RECORD_CLAIM_HASH, 1234U) ;
	const auto dynamicRead = readRecordFixture(
		key, descriptorIndex( asusSource, recordEntry( key, resourceRecord( dynamicDescriptor))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 通常署名codec
	DRIVERCRATE_EXPECT(
		context,
		dynamicRead.receipt &&
			dynamicRead.receipt->records()[0].acquisitionDescriptor->anonymousCdn.has_value()) ;
	const std::array dynamicBad{
		replaced( dynamicDescriptor, "\"model\":\"G614FR\"", "\"model\":\"wrong\""),
		replaced( dynamicDescriptor, "\"systemCode\":\"asus\"", "\"systemCode\":\"rog\""),
		replaced(
			dynamicDescriptor,
			"\"kind\":\"ANONYMOUS_CDN_TOKEN_V1\",\"model\":\"G614FR\",\"path\":\"/pub/ASUS/fixture.exe\",\"systemCode\":\"asus\"",
			"\"kind\":\"STATIC_URL\""),
		replaced( dynamicDescriptor, "?model=G614FR", "?model=G614FR&model=G614FR"),
		replaced(
			dynamicDescriptor, "?model=G614FR",
			"?model=G614FR&Signature=untrusted")} ;	// 元model/path/queryとstatic policyを緩めない拒否
	// 不正wireを指定したときに別producerやstaticへfallbackしない
	for( const auto &bad : dynamicBad) {
		const auto rejected = readRecordFixture(
			key, descriptorIndex( asusSource, recordEntry( key, resourceRecord( bad))),
			{1U, 1U, 1U, 0U, 0U}) ;	// 原不正byte
		DRIVERCRATE_EXPECT( context, !rejected.receipt) ;
	}

	const auto foreignSource = readRecordFixture(
		key, descriptorIndex( recordSource(), recordEntry( key, resourceRecord( dynamicDescriptor))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 同hostだけの自己申告を拒否
	DRIVERCRATE_EXPECT( context, !foreignSource.receipt) ;
	const std::array resourceBad{
		replaced( resourceDescriptor, "driver-index-acquisition-v2", "driver-index-acquisition-v1"),
		replaced( resourceDescriptor, "STATIC_URL", "DYNAMIC_UNSUPPORTED"),
		replaced( resourceDescriptor, "\"bytes\":1234", "\"bytes\":1235"),
		replaced( resourceDescriptor, "\"offset\":0", "\"offset\":null"),
		replaced( resourceDescriptor, "\"value\":1033", "\"value\":\"1033\""),
		replaced( resourceDescriptor, "\"selectedInf\":\"fixture.inf\"",
				 "\"selectedInf\":\"wrong.inf\""),
		mutateDescriptorObject( resourceDescriptor, "payloadPlan", 0U),
		mutateDescriptorObject( resourceDescriptor, "payloadPlan", 1U),
		mutateDescriptorObject(
			resourceDescriptor, "payloadPlan",
			2U)} ;	// 旧schema混入/未知取得/親不一致/null/原型/選択不一致/閉field境界
	// 各失敗を正常申告へ補完せず元byteを通常readerへ渡す
	for( const auto &bad : resourceBad) {
		const auto rejected = readRecordFixture(
			key, descriptorIndex( recordSource(), recordEntry( key, resourceRecord( bad))),
			{1U, 1U, 1U, 0U, 0U}) ;	// 同じ認証fixtureの原不正byte
		DRIVERCRATE_EXPECT( context, !rejected.receipt &&
										rejected.status != IndexRecordsStatus::SCHEMA_VALIDATED) ;
	}

	const auto &record = read.receipt->records()[0] ;		// Receipt寿命へ結合した所有record
	const auto &value  = *record.acquisitionDescriptor ;	// 全13fieldの型付き元申告
	DRIVERCRATE_EXPECT( context, record.recordSchemaVersion == 2U && record.originalBytes == raw &&
									read.receipt->schemaPolicyVersion() ==
										INDEX_RECORD_READER_POLICY_VERSION &&
									record.acquisitionDescriptorUnavailableReason.empty()) ;
	DRIVERCRATE_EXPECT(
		context,
		value.state == IndexDescriptorState::KNOWN && value.reason.empty() &&
			value.payloadUrl == "https://vendor.example/fixture.zip" &&
			value.fileName == "Fixture 1.2 (x64).zip" && value.format == IndexPayloadFormat::ZIP &&
			value.expectedContentType == "application/zip" && value.maximumBytes == 134217728U) ;
	DRIVERCRATE_EXPECT( context, value.route.size() == 1U &&
									value.route[0].kind == IndexRouteKind::OFFICIAL_PAYLOAD_LINK &&
									value.route[0].evidenceUrl ==
										read.receipt->sources()[0].distributionPage) ;
	DRIVERCRATE_EXPECT( context, value.terms.state == IndexTermsState::CONFIRMED_NO_CONSENT &&
									value.terms.revisionKind == IndexTermsRevisionKind::NONE &&
									!value.terms.textDocument &&
									value.prerequisites.state == IndexDescriptorState::KNOWN &&
									value.prerequisites.items.empty()) ;
	DRIVERCRATE_EXPECT( context, value.publisher.value == "Synthetic publisher" &&
									value.attestation && value.attestation->policyRevision == 1U &&
									value.attestation->authorityMethod ==
										IndexAuthorityMethod::OFFICIAL_SITE_CONTROL_AND_LINK) ;
	DRIVERCRATE_EXPECT( context, record.packageEvidence.publishedHash.sha256 ==
										record.packageEvidence.calculatedHash.sha256 &&
									record.packageEvidence.publishedHash.evidenceSha256 !=
										record.packageEvidence.publishedHash.sha256) ;
	// 同じ元textでも異なる空白の原byteとhashを独立に保持する
	const auto spaced = readRecordFixture(
		key, descriptorIndex( recordSource(), recordEntry( key, " \n" + raw + "\t")),
		{1U, 1U, 1U, 0U, 0U}) ;
	DRIVERCRATE_EXPECT( context,
					   spaced.receipt &&
						   spaced.receipt->records()[0].recordSha256 != record.recordSha256 &&
						   spaced.receipt->records()[0].originalBytes == " \n" + raw + "\t") ;
	const auto unknown = readRecordFixture(
		key,
		descriptorIndex( recordSource(),
						recordEntry( key, descriptorRecord( descriptorFixture( true)))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 明示UNKNOWNを保持する正例
	DRIVERCRATE_EXPECT(
		context, unknown.receipt &&
					 unknown.receipt->records()[0].acquisitionDescriptor->reason ==
						 "static route not supplied" &&
					 unknown.receipt->records()[0].acquisitionDescriptor->terms.reason ==
						 "terms not supplied" &&
					 unknown.receipt->records()[0].acquisitionDescriptor->prerequisites.reason ==
						 "prerequisites not supplied" &&
					 unknown.receipt->records()[0].acquisitionDescriptor->publisher.reason ==
						 "publisher not supplied" &&
					 !unknown.receipt->records()[0].acquisitionDescriptor->attestation) ;
	const std::string legacy = distributionRecord( "legacy") ;	// 元14fieldの旧record
	const auto		  mixed	 = readRecordFixture(
		key,
		descriptorIndex( recordSource(), recordEntry( key, raw) + "," + recordEntry( key, legacy)),
		{1U, 2U, 2U, 0U, 0U}) ;	// v2 outer内の旧record
	DRIVERCRATE_EXPECT(
		context, mixed.receipt && mixed.receipt->records()[1].recordSchemaVersion == 1U &&
					 !mixed.receipt->records()[1].acquisitionDescriptor &&
					 !mixed.receipt->records()[1].acquisitionDescriptorUnavailableReason.empty()) ;
	rejectRecordIndex( context, key, distributionIndex( recordSource(), recordEntry( key, raw)),
					  IndexRecordsStatus::INVALID_RECORD, {1U, 1U, 1U, 0U, 0U}) ;
	// 同じrawでも申告hashを別原byteから取った場合はschemaより前で拒否する
	rejectRecordIndex(
		context, key,
		descriptorIndex( recordSource(), recordEntry( key, raw, recordDigest( key, raw + " "))),
		IndexRecordsStatus::RECORD_HASH_MISMATCH, {1U, 1U, 1U, 0U, 0U}) ;
	const std::string rich =
		// 全nestedobjectを含む正例
		descriptorRecord( descriptorFixture( false, true)) ;
	const auto richRead =
		readRecordFixture( key, descriptorIndex( recordSource(), recordEntry( key, rich)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 本文取得や条件確認は実施しない
	DRIVERCRATE_EXPECT(
		context,
		richRead.receipt &&
			richRead.receipt->records()[0].acquisitionDescriptor->terms.textDocument &&
			richRead.receipt->records()[0].acquisitionDescriptor->terms.revision ==
				"Original 1.0" &&
			richRead.receipt->records()[0].acquisitionDescriptor->prerequisites.items[0].kind ==
				IndexPrerequisiteKind::LOCAL_CHECK) ;
	constexpr std::array<std::string_view, 22U> OBJECTS{"",
														"acquisitionDescriptor",
														"route",
														"terms",
														"textDocument",
														"prerequisites",
														"items",
														"publisher",
														"attestation",
														"targetOs",
														"architecture",
														"driverKind",
														"version",
														"publishedDate",
														"acquisition",
														"packageEvidence",
														"publishedHash",
														"calculatedHash",
														"size",
														"lastSuccessfulObservationUtc",
														"publishedIdentityEvidence",
														"pnpIds"} ;	// 全record入れ子の固定集合
	// 全nestedobjectの欠損・未知・重複を三通りずつ真署名と正しい原hashで拒否確認する
	for( const auto object : OBJECTS) {
		// 同じfixtureを有限三種類だけ改変し、既存strict規則を全objectで確認する
		for( unsigned mutation = 0U; mutation < 3U; ++mutation) {
			const std::string changed =
				// 原byte改変を正しくhashへ結ぶ
				mutateDescriptorObject( rich, object, mutation) ;
			rejectRecordIndex( context, key,
							  descriptorIndex( recordSource(), recordEntry( key, changed)),
							  IndexRecordsStatus::INVALID_RECORD, {1U, 1U, 1U, 0U, 0U}) ;
		}
	}

	constexpr std::array<std::string_view, 3U> INDEX_OBJECTS{
		"", "sources", "officialEvidence"} ;	// Outerとsourceの全object
	// Outerの入れ子も三種類ずつ拒否し、schema順序で不正objectを補完しない
	for( const auto object : INDEX_OBJECTS) {
		// 固定三改変を実署名indexに通す
		for( unsigned mutation = 0U; mutation < 3U; ++mutation) {
			rejectRecordIndex( context, key, mutateDescriptorObject( index, object, mutation),
							  IndexRecordsStatus::INVALID_INDEX, {1U, 1U, 1U, 0U, 0U}) ;
		}
	}

	// Sourceとrecordの対応を失った先頭route証拠は型が正しくても拒否する
	const std::array<std::pair<std::string, std::string>, 24U> invalidEvidence{
		{{"\"maximumBytes\":134217728", "\"maximumBytes\":0"},
		 {"\"maximumBytes\":134217728", "\"maximumBytes\":2147483649"},
		 {"\"format\":\"ZIP\"", "\"format\":\"UNKNOWN\""},
		 {"\"format\":\"ZIP\"", "\"format\":\"WINDOWS_EXE\""},
		 {"\"reason\":\"\",\"payloadUrl\"", "\"reason\":\"contradictory\",\"payloadUrl\""},
		 {"\"fileName\":\"Fixture 1.2 (x64).zip\"", "\"fileName\":\"CON .v2.zip\""},
		 {"\"fileName\":\"Fixture 1.2 (x64).zip\"", "\"fileName\":\"../fixture.zip\""},
		 {"\"expectedContentType\":\"application/zip\"",
		  "\"expectedContentType\":\"application/zip;token=x\""},
		 {"\"kind\":\"OFFICIAL_PAYLOAD_LINK\"", "\"kind\":\"HTTP_REDIRECT\""},
		 {"\"evidenceUrl\":\"https://vendor.example/support\"",
		  "\"evidenceUrl\":\"https://vendor.example/other\""},
		 {"\"policyRevision\":1", "\"policyRevision\":2"},
		 {"\"kind\":\"COLLECTOR_VERIFIED_OFFICIAL_ROUTE\"", "\"kind\":\"SELF_APPROVED\""},
		 {"2026-10-10T03:00:00Z", "2026-10-11T05:00:01Z"},
		 {"2026-10-12T03:00:00Z", "2026-10-11T05:00:00Z"},
		 {"2026-10-12T03:00:00Z", "2026-10-25T05:00:01Z"},
		 {"2026-10-12T03:00:00Z", "2026-10-18T03:00:01Z"},
		 {"2026-10-10T03:00:00Z", "2026-02-30T03:00:00Z"},
		 {"\"textDocument\":null", "\"textDocument\":{}"},
		 {"\"revisionKind\":\"NONE\"", "\"revisionKind\":\"VENDOR_LITERAL\""},
		 {"\"state\":\"CONFIRMED_NO_CONSENT\"", "\"state\":\"UNKNOWN\""},
		 {"\"prerequisites\":{\"state\":\"KNOWN\",\"reason\":\"\"",
		  "\"prerequisites\":{\"state\":\"UNKNOWN\",\"reason\":\"\""},
		 {"\"publisher\":{\"state\":\"KNOWN\"", "\"publisher\":{\"state\":\"UNKNOWN\""},
		 {"\"format\":\"ZIP\"", "\"format\":\"RAR\""},
		 {"\"payloadUrl\":\"https://vendor.example/fixture.zip\"",
		  "\"payloadUrl\":\"https://vendor.example/other.zip\""}}} ;	// 構造不正と意味不正を別に期待する固定改変表
	// 意味不整合の固定24条件を型が正しい署名recordで確認する
	for( std::size_t indexCase = 0U; indexCase < invalidEvidence.size(); ++indexCase) {
		const auto &change = invalidEvidence[indexCase] ;	// 同期借用する元/改変literal
		const auto	status = indexCase == 17U
								 ? IndexRecordsStatus::INVALID_RECORD
								 : IndexRecordsStatus::INVALID_EVIDENCE ;	// 空objectだけは文法拒否
		rejectRecordIndex(
			context, key,
			descriptorIndex( recordSource(),
							recordEntry( key, descriptorRecord( replaced( descriptor, change.first,
																	   change.second)))),
			status, {1U, 1U, 1U, 0U, 0U}) ;
	}

	constexpr std::array<std::string_view, 17U> BAD_URLS{
		"http://vendor.example/fixture.zip",	   "https://user@vendor.example/fixture.zip",
		"https://127.0.0.1/fixture.zip",		   "https://[::1]/fixture.zip",
		"https://vendor.local/fixture.zip",		   "https://vendor.internal/fixture.zip",
		"https://localhost.example/fixture.zip",   "https://vendor.lan/fixture.zip",
		"https://-vendor.example/fixture.zip",	   "https://vendor..example/fixture.zip",
		"https://vendor.example:444/fixture.zip",  "https://vendor.example/fixture.zip#x",
		"https://vendor.example/fixture.zip?id=7", "https://vendor.example/a%0d.zip",
		"https://vendor.example/a%255c.zip",	   "https://vendor.example/a%2.zip",
		"https://vendor.example/a b.zip"} ;	// DNSやHTTPを呼ばない固定拒否集合
	// Payloadとrouteの両方に同じ不正原URLを置き、queryやprivate構文を拒否する
	for( const auto url : BAD_URLS) {
		std::string changed = descriptor ;	// この条件だけの人工元byte
		// 同じ原payload URLの二参照を共に改変する
		for( unsigned occurrence = 0U; occurrence < 2U; ++occurrence) {
			changed = replaced( std::move( changed), "https://vendor.example/fixture.zip", url) ;
		}

		rejectRecordIndex(
			context, key,
			descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( changed))),
			IndexRecordsStatus::INVALID_URL, {1U, 1U, 1U, 0U, 0U}) ;
	}

	// 初回PAGEの閉じた数値queryは原URLを変えず保持する
	const std::string sourceQuery = replaced(
		replaced( recordSource(), "\"distributionPage\":\"https://vendor.example/support\"",
				 "\"distributionPage\":\"https://vendor.example/support?id=7\""),
		"\"evidenceUrl\":\"https://vendor.example/support\"",
		"\"evidenceUrl\":\"https://vendor.example/support?id=7\"") ;	// 元pageと公式出典を一致させる
	const std::string queryDescriptor = replaced(
		descriptor, "\"evidenceUrl\":\"https://vendor.example/support\"",
		"\"evidenceUrl\":\"https://vendor.example/support?id=7\"") ;	// 先頭routeの同source根拠
	const auto queryRead = readRecordFixture(
		key, descriptorIndex( sourceQuery, recordEntry( key, descriptorRecord( queryDescriptor))),
		{1U, 1U, 1U, 0U, 0U}) ;	// PAGEだけの正例
	DRIVERCRATE_EXPECT( context,
					   queryRead.receipt && queryRead.receipt->sources()[0].distributionPage ==
												"https://vendor.example/support?id=7") ;
	rejectRecordIndex( context, key, distributionIndex( sourceQuery, recordEntry( key, legacy)),
					  IndexRecordsStatus::INVALID_URL, {1U, 1U, 1U, 0U, 0U}) ;
	// 未登録CDNの元申告は専用Providerを増やさず共通codecで保持する
	std::string cdn = descriptor ;	// 公式pageに結合する別originの元申告
	// 二つのpayload参照だけをexact CDN URLへ結ぶ
	for( unsigned occurrence = 0U; occurrence < 2U; ++occurrence) {
		cdn = replaced( std::move( cdn), "https://vendor.example/fixture.zip",
					   "https://new-cdn.example/fixture.zip") ;
	}

	rejectRecordIndex( context, key,
					  descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( cdn))),
					  IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	cdn				   = replaced( std::move( cdn), "OFFICIAL_PAYLOAD_LINK", "OFFICIAL_CDN_LINK") ;
	const auto cdnRead = readRecordFixture(
		key, descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( cdn))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 元attestationを実公式性へ昇格しない
	DRIVERCRATE_EXPECT( context,
					   cdnRead.receipt &&
						   cdnRead.receipt->records()[0].acquisitionDescriptor->route[0].kind ==
							   IndexRouteKind::OFFICIAL_CDN_LINK) ;
	rejectRecordIndex( context, key,
					  descriptorIndex( recordSource( "fixture-source", true), recordEntry( key, raw)),
					  IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	const auto capacity = readRecordFixture(
		key,
		descriptorIndex( recordSource(), recordEntry( key, replaced( raw, "\"valueBytes\":1234",
																  "\"valueBytes\":134217729"))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 元size超過は後段容量保留でありrecordを消さない
	DRIVERCRATE_EXPECT( context,
					   capacity.receipt &&
						   capacity.receipt->records()[0].packageEvidence.size.value == 134217729U) ;
	const auto missingSize = readRecordFixture(
		key,
		descriptorIndex(
			recordSource(),
			recordEntry(
				key,
				replaced(
					raw, R"json({"state":"KNOWN","valueBytes":1234,"reason":""})json",
					R"json({"state":"UNKNOWN","valueBytes":0,"reason":"size not supplied"})json"))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 推測sizeで補完しない
	DRIVERCRATE_EXPECT( context, missingSize.receipt &&
									!missingSize.receipt->records()[0].packageEvidence.size.value &&
									missingSize.receipt->records()[0].packageEvidence.size.reason ==
										"size not supplied") ;
	const auto unknownConditions = readRecordFixture(
		key,
		descriptorIndex(
			recordSource(),
			recordEntry( key,
						descriptorRecord( descriptor, distributionRecord( "unknown-target", false)))),
		{1U, 1U, 1U, 0U, 0U}) ;	// Descriptorの形式から未知条件を補わない
	DRIVERCRATE_EXPECT( context, unknownConditions.receipt &&
									!unknownConditions.receipt->records()[0].targetOs.value &&
									!unknownConditions.receipt->records()[0].architecture.value &&
									!unknownConditions.receipt->records()[0].driverKind.value &&
									!unknownConditions.receipt->records()[0].acquisition.value) ;
	// 公開revisionと算出予定revisionをwire上で別々に保持する
	const std::string computed =
		replaced( replaced( rich, "VENDOR_LITERAL", "COMPUTED_UTF8_SHA256"), "Original 1.0",
				 "") ;	// 本文の取得やrevision計算は行わない
	const auto computedRead =
		readRecordFixture( key, descriptorIndex( recordSource(), recordEntry( key, computed)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 元revisionの由来を保持する読取り
	DRIVERCRATE_EXPECT(
		context,
		computedRead.receipt &&
			computedRead.receipt->records()[0].acquisitionDescriptor->terms.revisionKind ==
				IndexTermsRevisionKind::COMPUTED_UTF8_SHA256 &&
			computedRead.receipt->records()[0].acquisitionDescriptor->terms.revision.empty()) ;
	const auto oldObservationBytes =
		// 元確認は更新せず原assetを保持する
		recordBytes( key, index, {1U, 1U, 1U, 0U, 0U}) ;
	const auto expiredIndividual = readSignedIndexRecords(
		oldObservationBytes, NOW + std::chrono::days{3}) ;	// Manifest内で個別attestationだけ期限切れ
	DRIVERCRATE_EXPECT( context, expiredIndividual.receipt &&
									expiredIndividual.receipt->records()[0]
											.acquisitionDescriptor->attestation->validUntilUtc <
										NOW + std::chrono::days{3}) ;
	const auto exactSevenDays = readRecordFixture(
		key,
		descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( replaced(
															 descriptor, "2026-10-12T03:00:00Z",
															 "2026-10-17T03:00:00Z")))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 7日の構造境界は有効
	DRIVERCRATE_EXPECT( context, exactSevenDays.receipt.has_value()) ;
	const auto exactEightDays = readRecordFixture(
		key,
		descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( replaced(
															 descriptor, "2026-10-12T03:00:00Z",
															 "2026-10-18T03:00:00Z")))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 8日ちょうどと8日1秒の拒否を分けます
	DRIVERCRATE_EXPECT( context, exactEightDays.receipt.has_value()) ;
	constexpr std::array<std::pair<std::string_view, IndexPayloadFormat>, 4U> FORMATS{
		{{"CABINET", IndexPayloadFormat::CABINET},
		 {"SEVEN_ZIP_SFX", IndexPayloadFormat::SEVEN_ZIP_SFX},
		 {"WINDOWS_EXE", IndexPayloadFormat::WINDOWS_EXE},
		 {"WINDOWS_MSI", IndexPayloadFormat::WINDOWS_MSI}}} ;	// 申告形式だけを保持し実行はしない
	// Archiveとinstallerを別方式に結び、全既知形式のtyped値を確認する
	for( const auto &format : FORMATS) {
		std::string typed = descriptorRecord(
			replaced( descriptor, "\"format\":\"ZIP\"",
					 "\"format\":\"" + std::string{format.first} + "\"")) ;	// 元申告形式だけの変更
		// EXEとMSIだけは元方式をinstallerへ結ぶ
		if( format.second == IndexPayloadFormat::WINDOWS_EXE ||
		   format.second == IndexPayloadFormat::WINDOWS_MSI) {
			typed = replaced( std::move( typed), "STANDARD_INF_ARCHIVE", "OFFICIAL_INSTALLER") ;
		}

		// 非実行SFXは新有限入力上限ちょうども元archive方式のまま受理します
		if( format.second == IndexPayloadFormat::SEVEN_ZIP_SFX) {
			typed = replaced( std::move( typed), "\"maximumBytes\":134217728",
							 "\"maximumBytes\":2147483648") ;
		}

		const auto acceptedFormat =
			readRecordFixture( key, descriptorIndex( recordSource(), recordEntry( key, typed)),
							  {1U, 1U, 1U, 0U, 0U}) ;	// 実byteや起動許可とは別の型検査
		DRIVERCRATE_EXPECT( context,
						   acceptedFormat.receipt &&
							   acceptedFormat.receipt->records()[0].acquisitionDescriptor->format ==
								   format.second) ;
	}

	const std::array<std::string, 6U> hopUrls{
		"https://vendor.example/fixture.zip",
		"https://vendor.example/step.zip",
		"https://new-cdn.example/one.zip",
		"https://new-cdn.example/two.zip",
		"https://new-cdn.example/three.zip",
		"https://new-cdn.example/four.zip"} ;	// 有限6hopの原URL
	std::string hops ;							// Exact routeの元順序を保持する人工配列
	// 最大5redirectの正例を明示し、以後の根拠を直前URLへ完全結合する
	for( std::size_t hop = 0U; hop < hopUrls.size(); ++hop) {
		// 二件目以後だけcommaを加える
		if( hop != 0U) {
			hops += "," ;
		}

		hops += descriptorHop( hopUrls[hop], hop == 0U ? "OFFICIAL_PAYLOAD_LINK" : "HTTP_REDIRECT",
							  hop == 0U ? "https://vendor.example/support" : hopUrls[hop - 1U]) ;
	}

	const auto sixHops = readRecordFixture(
		key,
		descriptorIndex( recordSource(),
						recordEntry( key, descriptorRecord( descriptorRoute( descriptor, hops)))),
		{1U, 1U, 1U, 0U, 0U}) ;	// OriginからCDNへ一方向だけの正例
	DRIVERCRATE_EXPECT( context,
					   sixHops.receipt &&
						   sixHops.receipt->records()[0].acquisitionDescriptor->route.size() == 6U) ;
	rejectRecordIndex(
		context, key,
		descriptorIndex(
			recordSource(),
			recordEntry( key, descriptorRecord( descriptorRoute(
								 descriptor, hops + "," +
												 descriptorHop( "https://new-cdn.example/five.zip",
															   "HTTP_REDIRECT", hopUrls.back()))))),
		IndexRecordsStatus::COUNT_LIMIT, {1U, 1U, 1U, 0U, 0U}) ;
	const std::string				  firstHop = descriptorHop( hopUrls[0], "OFFICIAL_PAYLOAD_LINK",
															   "https://vendor.example/support") ;	// 先頭の完全根拠
	const std::array<std::string, 4U> BAD_ROUTES{
		firstHop + "," + descriptorHop( hopUrls[0], "HTTP_REDIRECT", hopUrls[0]),
		firstHop + "," +
			descriptorHop( hopUrls[1], "HTTP_REDIRECT", "https://vendor.example/wrong.zip"),
		firstHop + "," + descriptorHop( hopUrls[1], "OFFICIAL_CDN_LINK", hopUrls[0]),
		firstHop + "," + descriptorHop( hopUrls[2], "HTTP_REDIRECT", hopUrls[0]) + "," +
			descriptorHop( hopUrls[1], "HTTP_REDIRECT",
						  hopUrls[2])} ;	// 循環・根拠不整合・redirect種別違反・CDN逆戻り
	// 同じpayloadの元route不整合だけを四条件で拒否する
	for( const auto &route : BAD_ROUTES) {
		rejectRecordIndex(
			context, key,
			descriptorIndex( recordSource(),
							recordEntry( key, descriptorRecord( descriptorRoute( descriptor, route)))),
			IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	}

	const std::string item =
		R"json({"kind":"USER_CONFIRMATION","description":"Confirm a specific prerequisite","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} + R"json("})json" ;	// 独立同意にしない具体的条件
	std::string items ;											// 最大16件の元条件集合
	// 明示16件だけを生成し、全件で終了する
	for( unsigned itemIndex = 0U; itemIndex < 16U; ++itemIndex) {
		// 二件目以後だけcommaを追加する
		if( itemIndex > 0U) {
			items += "," ;
		}

		items += item ;
	}

	const std::string sixteen =
		// 上限の完全人工申告
		replaced( descriptor, "\"items\":[]", "\"items\":[" + items + "]") ;
	const auto sixteenRead = readRecordFixture(
		key, descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( sixteen))),
		{1U, 1U, 1U, 0U, 0U}) ;	// 条件確認は未実施
	DRIVERCRATE_EXPECT(
		context,
		sixteenRead.receipt &&
			sixteenRead.receipt->records()[0].acquisitionDescriptor->prerequisites.items.size() ==
				16U) ;
	rejectRecordIndex(
		context, key,
		descriptorIndex(
			recordSource(),
			recordEntry( key, descriptorRecord( replaced( descriptor, "\"items\":[]",
													   "\"items\":[" + items + "," + item + "]")))),
		IndexRecordsStatus::COUNT_LIMIT, {1U, 1U, 1U, 0U, 0U}) ;
	const std::string emptyAttestation =
		descriptor.substr( 0U, descriptor.find( "\"attestation\":")) +
		"\"attestation\":null}" ;	// 既知descriptorの必須元証拠を欠損させる
	rejectRecordIndex(
		context, key,
		descriptorIndex( recordSource(), recordEntry( key, descriptorRecord( emptyAttestation))),
		IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	rejectRecordIndex(
		context, key,
		descriptorIndex(
			recordSource(),
			recordEntry( key, descriptorRecord( replaced(
								 descriptorFixture( true), "\"payloadUrl\":\"\"",
								 "\"payloadUrl\":\"https://vendor.example/fixture.zip\"")))),
		IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	const std::string schemaFirst =
		"{\"schema\":\"driver-index-record-v2\"," +
		replaced( raw.substr( 1U), "\"schema\":\"driver-index-record-v2\",",
				 "") ;	// Record schemaを先頭へ移した別の元byte
	const auto schemaFirstRead =
		readRecordFixture( key, descriptorIndex( recordSource(), recordEntry( key, schemaFirst)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 元順序が別でも全15fieldを要求する
	DRIVERCRATE_EXPECT(
		context, schemaFirstRead.receipt &&
					 schemaFirstRead.receipt->records()[0].originalBytes == schemaFirst &&
					 schemaFirstRead.receipt->records()[0].recordSha256 != record.recordSha256) ;
	std::cout << "Signed index descriptor codec assertions: "
			  << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同RAM helperで厳格配布schema・原hash・UNKNOWN・有限上限を検査します
 * @param[in,out] context 共通unit assertion集計先
 * @note 架空の公開IDだけを使用し、公式性・端末適合・導入の実績を作りません
 */
//------------------------------------------------------------------------------
void runSignedIndexRecordsTests( TestContext &context)
{
	static_assert( !std::is_default_constructible_v<IndexRecordsSchemaReceipt>) ;
	static_assert(
		!std::is_constructible_v<IndexRecordsSchemaReceipt, AuthenticatedIndexAssetBytes,
								 std::vector<IndexRecordSource>,
								 std::vector<IndexDistributionRecord>, IndexManifestQuality>) ;
	const int firstAssertion = context.assertionCount() ;	// このgroupだけの実件数
	const int firstFailure	 = context.failureCount() ;		// このgroupだけの実失敗
	RamKey	  key ;											// 既存helperのRAM鍵。再実装・秘密鍵永続化をしない
	key.generate( 3072U) ;
	testIndexSupplementRecords( context, key) ;
	testWixContentSupplement( context, key) ;
	testPlatformDeviceSupplement( context, key) ;
	testCatalogSupplementConsumer( context, key) ;
	const std::string metadata = distributionRecord() ;	// 架空の公開identityを持つ元申告
	const std::string content =
		// 発行側内容検査申告
		distributionRecord( "content", true, "CONTENT_INSPECTED") ;
	const std::string unknown =
		// 明示UNKNOWNを残すrecord
		distributionRecord( "unconfirmed", false, "UNCONFIRMED") ;
	const std::string entries = recordEntry( key, metadata) + "," + recordEntry( key, content) + "," +
								// 三段階が一件ずつの人工集合
								recordEntry( key, unknown) ;
	const std::string index	   = distributionIndex( recordSource(), entries) ;	// 原配布index
	auto			  bytes	   = recordBytes( key, index) ;						// 全前段を通した必須入力
	const auto		  accepted = readSignedIndexRecords( bytes, NOW) ;			// 実native正例
	DRIVERCRATE_EXPECT( context, accepted.status == IndexRecordsStatus::SCHEMA_VALIDATED) ;
	DRIVERCRATE_EXPECT( context, accepted.error == 0) ;
	DRIVERCRATE_EXPECT( context, accepted.receipt.has_value()) ;
	// 正例生成不成立でreceiptを参照しない
	if( !accepted.receipt) {
		return ;
	}

	const auto &receipt = *accepted.receipt ;	// 原byteと元申告だけを持つ不変receipt
	DRIVERCRATE_EXPECT( context, receipt.sources().size() == 1U && receipt.records().size() == 3U) ;
	DRIVERCRATE_EXPECT( context, receipt.indexSha256() == key.digest( index)) ;
	DRIVERCRATE_EXPECT( context, assetText( receipt.assetBytes().expandedBytes()) == index) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].originalBytes == metadata) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].recordSha256 == key.digest( metadata)) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].recordSha256 != receipt.indexSha256()) ;
	DRIVERCRATE_EXPECT( context, receipt.assetBytes().manifest().data().asset.sha256 !=
									receipt.indexSha256()) ;
	DRIVERCRATE_EXPECT( context, receipt.assetBytes().manifest().data().manifestSha256 !=
									receipt.indexSha256()) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].publishedIdentityEvidence.pnpIds[0].value ==
									"TESTBUS\\SYNTH_0001") ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].publishedIdentityEvidence.infIdentity ==
									"drivers/fixture.inf") ;
	DRIVERCRATE_EXPECT( context,
					   receipt.records()[0].publishedIdentityEvidence.evidenceSha256 ==
						   signed_index_json::decodeHash( RECORD_EVIDENCE_HASH,
														 IndexRecordsStatus::INVALID_EVIDENCE)) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[0].packageEvidence.publishedHash.sha256 ==
									receipt.records()[0].packageEvidence.calculatedHash.sha256) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[2].publishedIdentityEvidence.state ==
									IndexEvidenceState::UNKNOWN) ;
	DRIVERCRATE_EXPECT( context, receipt.records()[2].publishedIdentityEvidence.reason ==
									"public INF identity missing") ;
	DRIVERCRATE_EXPECT( context, !receipt.records()[2].targetOs.value &&
									receipt.records()[2].targetOs.reason == "not supplied") ;
	DRIVERCRATE_EXPECT( context, !receipt.records()[2].packageEvidence.calculatedHash.sha256 &&
									receipt.records()[2].packageEvidence.calculatedHash.reason ==
										"not inspected") ;
	DRIVERCRATE_EXPECT( context, receipt.actualQuality().sourceCount == 1U &&
									receipt.actualQuality().recordCount == 3U &&
									receipt.actualQuality().metadataOnlyCount == 1U &&
									receipt.actualQuality().contentInspectedCount == 1U &&
									receipt.actualQuality().unconfirmedCount == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   receipt.schemaPolicyVersion() == INDEX_RECORD_READER_POLICY_VERSION) ;

	expectRecordsRejected( context, readSignedIndexRecords( bytes, std::nullopt),
						  IndexRecordsStatus::TIME_UNAVAILABLE) ;
	expectRecordsRejected( context,
						  readSignedIndexRecords( bytes, bytes.manifest().data().publishedAtUtc -
															std::chrono::seconds{1}),
						  IndexRecordsStatus::NOT_YET_VALID) ;
	expectRecordsRejected( context,
						  readSignedIndexRecords( bytes, bytes.manifest().data().expiresAtUtc),
						  IndexRecordsStatus::EXPIRED) ;
	DRIVERCRATE_EXPECT(
		context,
		readSignedIndexRecords( bytes, bytes.manifest().data().publishedAtUtc).receipt.has_value()) ;
	DRIVERCRATE_EXPECT( context, readSignedIndexRecords( bytes, bytes.manifest().data().expiresAtUtc -
																  std::chrono::seconds{1})
									.receipt.has_value()) ;
	auto moved = std::move( bytes) ;	// 認証byteを持つmove先
	expectRecordsRejected( context, readSignedIndexRecords( bytes, NOW),
						  IndexRecordsStatus::INCOMPLETE_BYTE_RECEIPT) ;
	DRIVERCRATE_EXPECT( context, readSignedIndexRecords( moved, NOW).receipt.has_value()) ;

	const std::string shifted = replaced( metadata, "\"schema\":\"driver-index-record-v1\",",
										 "") ;	// Field順を変える元record
	const std::string reordered =
		"\n " + shifted.substr( 0U, shifted.size() - 1U) +
		", \"schema\" : \"driver-index-record-v1\" }\r\n" ;	// 再serializationしない原byte
	const std::string singleIndex = "\n " +
									distributionIndex( recordSource(), recordEntry( key, reordered)) +
									"\n" ;	// 原空白を持つindex
	const auto reorderedResult =
		// 順序・空白正例
		readRecordFixture( key, singleIndex, {1U, 1U, 1U, 0U, 0U}) ;
	DRIVERCRATE_EXPECT( context,
					   reorderedResult.receipt &&
						   reorderedResult.receipt->records()[0].originalBytes == reordered) ;
	DRIVERCRATE_EXPECT( context, reorderedResult.receipt &&
									reorderedResult.receipt->records()[0].recordSha256 ==
										key.digest( reordered)) ;
	DRIVERCRATE_EXPECT( context, reorderedResult.receipt &&
									reorderedResult.receipt->records()[0].recordSha256 !=
										key.digest( metadata)) ;
	const std::string escaped =
		// 標準escape原byte
		replaced( metadata, "Synthetic fixture", "Synthetic \\u0066ixture") ;
	const auto escapedResult =
		readRecordFixture( key, distributionIndex( recordSource(), recordEntry( key, escaped)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 解除だけを行う正例
	DRIVERCRATE_EXPECT( context,
					   escapedResult.receipt &&
						   escapedResult.receipt->records()[0].originalBytes == escaped &&
						   escapedResult.receipt->records()[0].product == "Synthetic fixture") ;
	const auto unknownSource = readRecordFixture(
		key, distributionIndex( recordSource( "fixture-source", true), recordEntry( key, unknown)),
		{1U, 1U, 0U, 0U, 1U}) ;	// 元公式性もUNKNOWNに残す正例
	DRIVERCRATE_EXPECT( context, unknownSource.receipt &&
									unknownSource.receipt->sources()[0].officialEvidence.state ==
										IndexEvidenceState::UNKNOWN &&
									unknownSource.receipt->sources()[0].officialEvidence.reason ==
										"source not verified") ;
	const auto metadataUnknown = readRecordFixture(
		key,
		distributionIndex( recordSource( "fixture-source", true),
						  recordEntry( key, replaced( unknown, "\"inspectionStage\":\"UNCONFIRMED\"",
													"\"inspectionStage\":\"METADATA_ONLY\""))),
		{1U, 1U, 1U, 0U, 0U}) ;	// UNKNOWNと検査段階を独立に保持する正例
	DRIVERCRATE_EXPECT( context, metadataUnknown.status == IndexRecordsStatus::SCHEMA_VALIDATED &&
									metadataUnknown.receipt.has_value()) ;
	DRIVERCRATE_EXPECT( context,
					   metadataUnknown.receipt &&
						   metadataUnknown.receipt->records()[0].inspectionStage ==
							   IndexInspectionStage::METADATA_ONLY &&
						   metadataUnknown.receipt->actualQuality().metadataOnlyCount == 1U &&
						   metadataUnknown.receipt->actualQuality().unconfirmedCount == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   metadataUnknown.receipt &&
						   metadataUnknown.receipt->records()[0].publishedIdentityEvidence.state ==
							   IndexEvidenceState::UNKNOWN &&
						   metadataUnknown.receipt->records()[0].publishedIdentityEvidence.reason ==
							   "public INF identity missing" &&
						   !metadataUnknown.receipt->records()[0].targetOs.value &&
						   metadataUnknown.receipt->records()[0].targetOs.reason == "not supplied") ;

	rejectRecordIndex(
		context, key,
		distributionIndex( recordSource(), recordEntry( key, metadata, recordDigest( key, index))),
		IndexRecordsStatus::RECORD_HASH_MISMATCH, {1U, 1U, 1U, 0U, 0U}) ;
	rejectRecordIndex(
		context, key,
		distributionIndex(
			recordSource(),
			recordEntry( key, metadata, recordDigest( key, assetText( assetGzip( index))))),
		IndexRecordsStatus::RECORD_HASH_MISMATCH, {1U, 1U, 1U, 0U, 0U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::QUALITY_MISMATCH,
					  {2U, 3U, 1U, 1U, 1U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::QUALITY_MISMATCH,
					  {1U, 4U, 2U, 1U, 1U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::QUALITY_MISMATCH,
					  {1U, 3U, 2U, 0U, 1U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::QUALITY_MISMATCH,
					  {1U, 3U, 0U, 1U, 2U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::QUALITY_MISMATCH,
					  {1U, 3U, 1U, 2U, 0U}) ;
	rejectRecordIndex( context, key,
					  replaced( index, "\"assetGeneration\":7", "\"assetGeneration\":8"),
					  IndexRecordsStatus::ASSET_GENERATION_MISMATCH) ;
	rejectRecordIndex(
		context, key,
		replaced( index, "\"assetGeneration\":7", "\"assetGeneration\":7,\"assetGeneration\":7"),
		IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key,
					  replaced( index, "\"assetGeneration\":7",
							   "\"assetGeneration\":7,\"assetGenera\\u0074ion\":7"),
					  IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key,
					  replaced( index, "\"assetGeneration\":7", "\"assetGeneration\":7,\"other\":0"),
					  IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key, replaced( index, "driver-index-records-v1", "research-v3"),
					  IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key, replaced( index, "\"sources\":[", "\"sources\":{"),
					  IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key, index + "{}", IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key, index + "\xff", IndexRecordsStatus::INVALID_INDEX) ;
	rejectRecordIndex( context, key, "\xef\xbb\xbf" + index, IndexRecordsStatus::INVALID_INDEX) ;
	constexpr std::array<std::string_view, 6U> BAD_NUMBERS{
		"NaN", "Infinity", "7.0", "7e0", "-7", "18446744073709551616"} ;	// 非整数／非有限拒否
	// 各不正数値を署名済みindexの同じfieldへ一つずつ渡す
	for( const auto number : BAD_NUMBERS) {
		rejectRecordIndex(
			context, key,
			replaced( index, "\"assetGeneration\":7", "\"assetGeneration\":" + std::string{number}),
			IndexRecordsStatus::INVALID_INDEX) ;
	}

	rejectRecordIndex( context, key,
					  distributionIndex( recordSource() + "," + recordSource(), entries),
					  IndexRecordsStatus::DUPLICATE_SOURCE) ;
	rejectRecordIndex( context, key,
					  distributionIndex( recordSource(), recordEntry( key, metadata) + "," +
															recordEntry( key, metadata)),
					  IndexRecordsStatus::DUPLICATE_RECORD) ;
	rejectRecordIndex( context, key, distributionIndex( "", entries),
					  IndexRecordsStatus::MISSING_SOURCE) ;
	rejectRecordIndex(
		context, key,
		distributionIndex( recordSource(),
						  recordEntry( key, distributionRecord( "metadata", true, "METADATA_ONLY",
															  "missing-source"))),
		IndexRecordsStatus::MISSING_SOURCE) ;
	rejectRecordIndex(
		context, key,
		distributionIndex( recordSource() + "," + recordSource( "unreferenced"), entries),
		IndexRecordsStatus::UNREFERENCED_SOURCE) ;
	const std::string otherSourceRecord = distributionRecord(
		"metadata", true, "METADATA_ONLY", "other-source") ;	// 別sourceの同record ID
	// 別sourceの同名recordを独立identityとして受理した実結果
	const auto separateIdentities = readRecordFixture(
		key,
		distributionIndex( recordSource() + "," + recordSource( "other-source"),
						  recordEntry( key, metadata) + "," + recordEntry( key, otherSourceRecord)),
		{2U, 2U, 2U, 0U, 0U}) ;
	DRIVERCRATE_EXPECT( context, separateIdentities.receipt &&
									separateIdentities.receipt->records().size() == 2U) ;

	constexpr std::array<std::string_view, 10U> BAD_BASE64{
		"",		"A",	"A===", "AA=A", "AA-_",
		"AA A", "AB==", "AAB=", "====", "AA==AAAA"} ;	// 全厳格base64拒否
	// 正しいhash申告を残し、base64文法だけを個別に拒否する
	for( const auto encoded : BAD_BASE64) {
		const std::string entry = "{\"recordBytesBase64\":\"" + std::string{encoded} +
								  "\",\"recordSha256\":\"" + recordDigest( key, metadata) +
								  "\"}" ;	// 文法だけ不正なentry
		rejectRecordIndex( context, key, distributionIndex( recordSource(), entry),
						  IndexRecordsStatus::INVALID_BASE64, {1U, 1U, 1U, 0U, 0U}) ;
	}

	rejectRecordIndex(
		context, key,
		distributionIndex( recordSource(), replaced( recordEntry( key, metadata), "\"recordSha256\":",
												   "\"recordSha256\":\"abc\",\"recordSha256\":")),
		IndexRecordsStatus::INVALID_INDEX, {1U, 1U, 1U, 0U, 0U}) ;
	rejectDistributionRecord( context, key, metadata + "\xff", IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key, "\xef\xbb\xbf" + metadata,
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "Synthetic fixture", std::string{"\xc0\xaf", 2U}),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"recordId\":\"metadata\"",
									  "\"recordId\":\"metadata\",\"recordId\":\"metadata\""),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"recordId\":\"metadata\"",
									  "\"recordId\":\"metadata\",\"record\\u0049d\":\"metadata\""),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord(
		context, key,
		replaced( metadata, "\"recordId\":\"metadata\"", "\"recordId\":\"metadata\",\"other\":true"),
		IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key, replaced( metadata, "\"recordId\":\"metadata\",", ""),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "driver-index-record-v1", "research-v3"),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"value\":\"X64\"", "\"value\":null"),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"value\":\"X64\"", "\"value\":\"ARM64\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"state\":\"KNOWN\",\"value\":\"X64\"",
									  "\"state\":\"UNKNOWN\",\"value\":\"X64\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"value\":\"X64\",\"reason\":\"\"",
									  "\"value\":\"X64\",\"reason\":\"not known\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key, replaced( metadata, "2026-10-01", "2026-02-30"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "2026-10-10T03:00:00Z", "2026-10-11T05:00:01Z"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "2026-10-10T03:00:00Z", "2026-10-10T25:00:00Z"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"valueBytes\":1234", "\"valueBytes\":0"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"valueBytes\":1234", "\"valueBytes\":1234.0"),
							 IndexRecordsStatus::INVALID_RECORD) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"sha256\":\"111", "\"sha256\":\"311"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord(
		context, key,
		replaced(
			content,
			"\"calculatedHash\":" + std::string{R"json({"state":"KNOWN","sha256":")json"} +
				std::string{RECORD_CLAIM_HASH} +
				R"json(","evidenceUrl":"https://vendor.example/support","evidenceSha256":")json" +
				std::string{RECORD_EVIDENCE_HASH} + R"json(","reason":""})json",
			R"json("calculatedHash":{"state":"UNKNOWN","sha256":"","evidenceUrl":"","evidenceSha256":"","reason":"not inspected"})json"),
		IndexRecordsStatus::INVALID_EVIDENCE) ;

	rejectDistributionRecord(
		context, key,
		replaced( metadata, R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json", "[]"),
		IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "{11111111-2222-3333-4444-555555555555}", ""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "{11111111-2222-3333-4444-555555555555}",
									  "{00000000-0000-0000-0000-000000000000}"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "drivers/fixture.inf", "../fixture.inf"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "drivers/fixture.inf", "/fixture.inf"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	// flatは明示空、nestedは一段memberです。同じ現行10fieldを全値codecで読みます
	for( const std::string_view selector : {"", "release+driver/package (x64).zip",
										   "release/inner.CAB", "release/static-driver.exe"}) {
		const auto nested = replaced( metadata, "\"nestedArchiveIdentity\":\"\"",
									 "\"nestedArchiveIdentity\":\"" + std::string{selector} +
										 "\"") ;	// 元fieldを欠損補完しません
		const auto read =
			readRecordFixture( key, distributionIndex( recordSource(), recordEntry( key, nested)),
							  {1U, 1U, 1U, 0U, 0U}) ;	// 真RAM署名から共通codecへ渡します
		DRIVERCRATE_EXPECT(
			context,
			read.receipt &&
				read.receipt->records().front().publishedIdentityEvidence.nestedArchiveIdentity ==
					selector) ;
	}

	constexpr std::array<std::string_view, 16U> BAD_MEMBERS{
		"../inner.zip",	 "/inner.zip",	"a//inner.zip",	   "a/./inner.zip", "a/../inner.zip",
		"a/inner.zip/",	 "C:inner.zip", "a/inner.zip:ads", "a/CON.zip",		"nul.zip",
		"a/COM1.zip",	 "a/LPT9.zip",	"a./inner.zip",	   "a /inner.zip",	"a/inner.zip.",
		"a\\\\inner.zip"} ;	// nativeと同じ拒否文法です。非実行nested SFXは上の正例へ含めます
	// 各unsafe memberを同じ共通codecへ一度ずつ渡します
	for( const auto member : BAD_MEMBERS) {
		rejectDistributionRecord(
			context, key,
			replaced( metadata, "\"nestedArchiveIdentity\":\"\"",
					 "\"nestedArchiveIdentity\":\"" + std::string{member} + "\""),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	// 欠損/未知/重複/null selectorをflatの別表現として受理しません
	for( const std::string_view replacement :
		{"", "\"nestedSelector\":\"\",",
		 "\"nestedArchiveIdentity\":\"\",\"nestedArchiveIdentity\":\"\",",
		 "\"nestedArchiveIdentity\":null,"}) {
		rejectDistributionRecord( context, key,
								 replaced( metadata, "\"nestedArchiveIdentity\":\"\",", replacement),
								 IndexRecordsStatus::INVALID_RECORD) ;
	}

	rejectDistributionRecord( context, key,
							 replaced( unknown, "\"nestedArchiveIdentity\":\"\"",
									  "\"nestedArchiveIdentity\":\"inner.zip\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	// INF memberも共通文法へ一致させ、通常名と予約名を同じ規則で扱います
	const auto plusInf =
		replaced( metadata, "drivers/fixture.inf",
				 "driver+release/fixture (x64).inf") ;	// 公開memberの文字を正規化しません
	DRIVERCRATE_EXPECT(
		context,
		readRecordFixture( key, distributionIndex( recordSource(), recordEntry( key, plusInf)),
						  {1U, 1U, 1U, 0U, 0U})
			.receipt.has_value()) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "drivers/fixture.inf", "drivers/NUL.inf"),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key, replaced( metadata, "Fixture.NTamd64", ""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	const auto lowerId = replaced( metadata, "TESTBUS", "testbus") ;	// 原caseのまま保持する正例です
	const auto lowerRead =
		readRecordFixture( key, distributionIndex( recordSource(), recordEntry( key, lowerId)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 同じstrict codecです
	DRIVERCRATE_EXPECT( context, lowerRead.receipt &&
									lowerRead.receipt->records().front().originalBytes == lowerId &&
									lowerRead.receipt->records()
										.front()
										.publishedIdentityEvidence.pnpIds.front()
										.value.starts_with( "testbus")) ;
	// kind付き等価集合でalias重複を拒否し、別ID欠損を件数だけで隠させません
	rejectDistributionRecord(
		context, key,
		replaced(
			metadata, R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
			R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},{"kind":"HARDWARE","value":"testbus\\synth_0001"}])json"),
		IndexRecordsStatus::INVALID_EVIDENCE) ;
	// nativeが未対応のUnicode memberをcodecだけで受理しません
	DRIVERCRATE_EXPECT( context, !isSafeOfficialArchiveMember( L"release/\u03a9.zip", L'/') &&
									!isSafeOfficialArchiveMember( L"release\\\u03a9.zip", L'\\')) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"nestedArchiveIdentity\":\"\"",
									  "\"nestedArchiveIdentity\":\"release/\u03a9.zip\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( metadata, "\"kind\":\"HARDWARE\"", "\"kind\":\"INSTANCE\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord(
		context, key,
		replaced(
			metadata, R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
			R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json"),
		IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectRecordIndex(
		context, key,
		distributionIndex( recordSource( "fixture-source", true), recordEntry( key, metadata)),
		IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	rejectRecordIndex( context, key,
					  distributionIndex( replaced( recordSource(), "\"sourceId\":\"fixture-source\"",
												 "\"sourceId\":\"bad/source\""),
										recordEntry( key, metadata)),
					  IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	rejectRecordIndex(
		context, key,
		distributionIndex( replaced( recordSource(),
								   "\"evidenceUrl\":\"https://vendor.example/support\"",
								   "\"evidenceUrl\":\"https://vendor.example/other\""),
						  recordEntry( key, metadata)),
		IndexRecordsStatus::INVALID_EVIDENCE, {1U, 1U, 1U, 0U, 0U}) ;
	constexpr std::array<std::string_view, 8U> BAD_URLS{
		"http://vendor.example/fixture.inf",
		"https://127.0.0.1/fixture.inf",
		"https://[::1]/fixture.inf",
		"https://localhost/fixture.inf",
		"https://vendor.local/fixture.inf",
		"https://user@vendor.example/fixture.inf",
		"https://vendor.example/fixture.inf?token=synthetic",
		"https://vendor.example/fixture.inf#part"} ;	// 未対応形式と不正URL
	// 公開証拠URL文法の違反を元署名付きrecordへ一つずつ入れる
	for( const auto url : BAD_URLS) {
		rejectDistributionRecord( context, key,
								 replaced( metadata, "https://vendor.example/fixture.inf", url),
								 IndexRecordsStatus::INVALID_URL) ;
	}

	rejectDistributionRecord( context, key, replaced( unknown, "public INF identity missing", ""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	rejectDistributionRecord( context, key,
							 replaced( unknown, "\"classGuid\":\"\"",
									  "\"classGuid\":\"{11111111-2222-3333-4444-555555555555}\""),
							 IndexRecordsStatus::INVALID_EVIDENCE) ;
	const std::string deepRecord =
		replaced( metadata, "\"value\":\"X64\"",
				 "\"value\":[[[[[[[[[\"X64\"]]]]]]]]]") ;	// 固定schemaより深い誤型
	rejectDistributionRecord( context, key, deepRecord, IndexRecordsStatus::INVALID_RECORD) ;

	const std::string exactRecord =
		metadata + std::string( INDEX_RECORD_MAX_BYTES - metadata.size(), ' ') ;	// 原512KiB境界
	const auto exactRecordResult =
		readRecordFixture( key, distributionIndex( recordSource(), recordEntry( key, exactRecord)),
						  {1U, 1U, 1U, 0U, 0U}) ;	// 縮小policyでない正例
	DRIVERCRATE_EXPECT( context, exactRecordResult.receipt &&
									exactRecordResult.receipt->records()[0].originalBytes.size() ==
										INDEX_RECORD_MAX_BYTES) ;
	rejectDistributionRecord( context, key, exactRecord + " ",
							 IndexRecordsStatus::RECORD_SIZE_LIMIT) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::COUNT_LIMIT,
					  {INDEX_RECORD_SOURCE_MAX_COUNT + 1U, 3U, 1U, 1U, 1U}) ;
	rejectRecordIndex( context, key, index, IndexRecordsStatus::COUNT_LIMIT,
					  {1U, INDEX_RECORD_MAX_COUNT + 1U, INDEX_RECORD_MAX_COUNT - 1U, 1U, 1U}) ;
	std::string ids ;	// 件数境界を検査する一意な架空公開ID配列
	// 件数上限まで異なる架空IDを順に作り、端末actual IDを一切読まない
	for( std::size_t count = 0U; count < INDEX_RECORD_PNP_MAX_COUNT; ++count) {
		// 後続要素だけのcommaを追加する
		if( count != 0U) {
			ids += "," ;
		}

		ids += R"json({"kind":"HARDWARE","value":"TESTBUS\\SYNTH_)json" + std::to_string( count) +
			   R"json("})json" ;
	}

	const std::string maximumIds =
		replaced( metadata, R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
				 "[" + ids + "]") ;	// ID件数上限ちょうど
	DRIVERCRATE_EXPECT(
		context,
		readRecordFixture( key, distributionIndex( recordSource(), recordEntry( key, maximumIds)),
						  {1U, 1U, 1U, 0U, 0U})
			.receipt.has_value()) ;
	rejectDistributionRecord(
		context, key,
		replaced( metadata, R"json([{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
				 "[" + ids + R"json(,{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_OVER"}])json"),
		IndexRecordsStatus::COUNT_LIMIT) ;
	std::string sources ;	// 実source配列の件数超過fixture
	// 件数上限の一つ先まで一意sourceを作り、配列上限そのものの拒否を確認する
	for( std::size_t count = 0U; count <= INDEX_RECORD_SOURCE_MAX_COUNT; ++count) {
		// 後続sourceだけのdelimiterを追加する
		if( count != 0U) {
			sources += "," ;
		}

		sources += recordSource( "source-" + std::to_string( count), true) ;
	}

	rejectRecordIndex( context, key, distributionIndex( sources, entries),
					  IndexRecordsStatus::COUNT_LIMIT) ;

	std::string depth = "\"x\"" ;	// 実container深さを測る固定一文字
	// 深さ8ちょうどまで一field objectを作る
	for( unsigned count = 0U; count < 8U; ++count) {
		depth = "{\"x\":" + depth + "}" ;
	}

	bool depthAccepted{} ;	// 共通readerの実境界正例
	try {
		signed_index_json::Reader<IndexRecordsStatus> reader(
			depth, IndexRecordsStatus::INVALID_INDEX) ;	// 共通文法
		readDepthFixture( reader, 8U) ;
		reader.finish() ;
		depthAccepted = true ;
	} catch( const signed_index_json::Failure<IndexRecordsStatus> &) {
		depthAccepted = false ;
	}

	DRIVERCRATE_EXPECT( context, depthAccepted) ;
	bool depthRejected{} ;	// 実深さ9の拒否
	try {
		const std::string tooDeep = "{\"x\":" + depth + "}" ;	// 一container超過
		signed_index_json::Reader<IndexRecordsStatus> reader(
			tooDeep, IndexRecordsStatus::INVALID_INDEX) ;	// 同じ固定policy
		readDepthFixture( reader, 9U) ;
		reader.finish() ;
	} catch( const signed_index_json::Failure<IndexRecordsStatus> &failure) {
		depthRejected = failure.status == IndexRecordsStatus::INVALID_INDEX ;
	}

	DRIVERCRATE_EXPECT( context, depthRejected) ;

	{
		std::string largeEntries ;	// 原record合計64MiBちょうどを持つ有限index
		largeEntries.reserve( 90U * 1024U * 1024U) ;
		// 各512KiBの一意record128件を作り、合計64MiBの境界へ達する
		for( std::size_t count = 0U; count < INDEX_RECORD_TOTAL_MAX_BYTES / INDEX_RECORD_MAX_BYTES;
			++count) {
			// 後続entryだけのcommaを追加する
			if( count != 0U) {
				largeEntries += "," ;
			}

			std::string raw =
				// 一意の人工record原byte
				distributionRecord( "total-" + std::to_string( count)) ;
			raw.append( INDEX_RECORD_MAX_BYTES - raw.size(), ' ') ;
			largeEntries += recordEntry( key, raw) ;
		}

		const std::string largeIndex =
			// 実約85MiBの配布index
			distributionIndex( recordSource(), largeEntries) ;
		const auto totalAccepted =
			// 実合計境界正例
			readRecordFixture( key, largeIndex, {1U, 128U, 128U, 0U, 0U}) ;
		DRIVERCRATE_EXPECT( context, totalAccepted.receipt &&
										totalAccepted.receipt->records().size() == 128U) ;
		DRIVERCRATE_EXPECT( context,
						   totalAccepted.receipt &&
							   totalAccepted.receipt->records()[0].originalBytes.size() ==
								   INDEX_RECORD_MAX_BYTES &&
							   totalAccepted.receipt->records()[127U].originalBytes.size() ==
								   INDEX_RECORD_MAX_BYTES) ;
		rejectRecordIndex(
			context, key,
			distributionIndex( recordSource(), largeEntries + "," + recordEntry( key, " ")),
			IndexRecordsStatus::TOTAL_RECORD_SIZE_LIMIT, {1U, 129U, 129U, 0U, 0U}) ;
	}
	std::cout << "Signed index record schema assertions: "
			  << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
	runDescriptorCodecChecks( context) ;
}

namespace {

/** @brief 保存試験の原envelope／gzipと前段manifestを一つに所有します */
struct StoreInputs {
	/// 実RSA-PSS認証を通った前段manifest
	AuthenticatedIndexManifest manifest ;
	/// Original-byte認証で使った原外側byte
	std::string				   envelope ;
	/// 実hash／GZip検査する原転送byte
	std::vector<std::byte>	   gzip ;
} ;

/** @brief 原入力と保存前schema receiptを所有する架空fixtureです */
struct StoreFixture {
	/// 実署名と実原gzipを持つ前段入力
	StoreInputs				  inputs ;
	/// 保存前まで全検査した不変receipt
	IndexRecordsSchemaReceipt receipt ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 実署名付き保存入力を作り、製品の暗号を迂回しません
 * @param[in] key 同じRAM内署名鍵
 * @param[in] index 原配布index byte
 * @param[in] generation 新manifest世代
 * @param[in] assetGeneration 原asset世代
 * @param[in] nowUtc Fixtureの検査時刻
 * @param[in] publication 署名発行のUTC表記
 * @param[in] expiry 署名期限のUTC表記
 * @param[in] padBytes 実gzip containerをこのbyte長へ拡大する指定。0は通常です
 * @param[in] quality 実record集合へ署名する元集計。既存fixtureの既定件数は維持します
 * @return 実CNG認証から取得した入力。生成不成立は例外です
 */
//------------------------------------------------------------------------------
[[nodiscard]] StoreInputs makeStoreInputs(
	const RamKey &key, const std::string_view index, const std::uint64_t generation = 7U,
	const std::uint64_t assetGeneration = 7U, const std::chrono::sys_seconds nowUtc = NOW,
	const std::string_view publication = "2026-10-11T05:00:00Z",
	const std::string_view expiry = "2026-10-25T05:00:00Z", const std::size_t padBytes = 0U,
	const IndexManifestQuality quality = {1U, 1U, 1U, 0U, 0U})
{
	auto gzip = assetGzip( index) ;	// 実GZipを独立helperで生成します
	// 実圧縮上限の正例だけでcontainer長を拡大します
	if( padBytes > gzip.size()) {
		gzip = padAssetGzip( std::move( gzip), padBytes) ;
	}

	const auto initial =
		// 共通asset hashの実署名です
		assetManifest( key, gzip, false, recordQuality( quality)) ;
	std::string raw =
		replaced( initial.data().manifestBytes, "\"generation\":7",
				 "\"generation\":" + std::to_string( generation)) ;	// Manifest世代を独立指定します
	raw						   = replaced( std::move( raw), "\"assetGeneration\":7",
										  "\"assetGeneration\":" + std::to_string( assetGeneration)) ;
	raw						   = replaced( std::move( raw), "2026-10-11T05:00:00Z", publication) ;
	raw						   = replaced( std::move( raw), "2026-10-25T05:00:00Z", expiry) ;
	std::string signedEnvelope = envelope( raw, key.sign( raw)) ;	// PSSは実RAM秘密鍵で行います
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;	// Unit public materialだけです
	auto result = signed_index_detail::authenticateWithTrustKeys(
		signedEnvelope, nowUtc, std::nullopt, trust) ;	// 製品と同じ実verifierです
	// Fixture生成を検証済み入力と誤認しません
	if( !result.manifest) {
		throw std::runtime_error( "store input manifest authentication failed") ;
	}

	return {std::move( *result.manifest), std::move( signedEnvelope), std::move( gzip)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 完全保存前receiptを実前段からだけ作ります
 * @param[in] key RAM内署名鍵
 * @param[in] generation Manifest世代
 * @param[in] assetGeneration 原asset世代
 * @param[in] nowUtc 現在の検査UTC
 * @param[in] publication 署名発行UTC
 * @param[in] expiry 署名期限UTC
 * @param[in] padBytes 実圧縮上限を測るcontainer長。通常は0です
 * @return 全前段が成功した人工入力とreceipt
 */
//------------------------------------------------------------------------------
[[nodiscard]] StoreFixture makeStoreFixture(
	const RamKey &key, const std::uint64_t generation = 7U,
	const std::uint64_t assetGeneration = 7U, const std::chrono::sys_seconds nowUtc = NOW,
	const std::string_view publication = "2026-10-11T05:00:00Z",
	const std::string_view expiry = "2026-10-25T05:00:00Z", const std::size_t padBytes = 0U)
{
	const auto index =
		replaced( distributionIndex( recordSource(), recordEntry( key, distributionRecord())),
				 "\"assetGeneration\":7",
				 "\"assetGeneration\":" +
					 // 架空recordの元観測は変えません
					 std::to_string( assetGeneration)) ;
	auto inputs = makeStoreInputs( key, index, generation, assetGeneration, nowUtc, publication,
								  expiry, padBytes) ;	// 実署名です
	auto bytes =
		// 実gzipの完全hashです
		authenticateIndexAssetBytes( inputs.manifest, inputs.gzip, nowUtc) ;
	// 前段生成の障害をstoreの拒否成功へ変換しません
	if( !bytes.receipt) {
		throw std::runtime_error( "store gzip fixture failed") ;
	}

	auto records = readSignedIndexRecords( *bytes.receipt, nowUtc) ;	// 実原recordとschemaです
	// Schema生成に失敗した場合は試験自体を失敗させます
	if( !records.receipt) {
		throw std::runtime_error( "store record fixture failed") ;
	}

	return {std::move( inputs), std::move( *records.receipt)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保存結果の拒否とsnapshot不在を独立して確認します
 * @param[in,out] context 共通集計先
 * @param[in] result 実store結果
 * @param[in] expected 期待拒否区分
 * @param[in] commit 期待する実commit区分
 */
//------------------------------------------------------------------------------
void expectStoreRejected(
	TestContext &context, const IndexStoreResult &result, const IndexStoreStatus expected,
	const IndexStoreCommitDisposition commit = IndexStoreCommitDisposition::NO_CHANGE)
{
	// 拒否区分の不一致だけを非機密の数値診断で残します
	if( result.status != expected) {
		std::cout << "Store rejection mismatch expected: " << static_cast<unsigned>( expected)
				  << ", actual: " << static_cast<unsigned>( result.status)
				  << ", error: " << static_cast<std::uint32_t>( result.error) << '\n' ;
	}

	DRIVERCRATE_EXPECT( context, result.status == expected) ;
	DRIVERCRATE_EXPECT( context, result.commit == commit) ;
	DRIVERCRATE_EXPECT( context, !result.snapshot) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実保存済みheadのreloadから世代を確認します
 * @param[in,out] context 共通集計先
 * @param[in,out] store 自作隔離store
 * @param[in] generation 期待する世代
 * @param[in] nowUtc 現在の信頼UTC
 */
//------------------------------------------------------------------------------
void expectStoredGeneration( TestContext &context, SignedIndexStore &store,
							const std::uint64_t			   generation,
							const std::chrono::sys_seconds nowUtc = NOW)
{
	const auto result = store.reload( nowUtc) ;	// 実diskの全原入力を再認証します
	DRIVERCRATE_EXPECT( context,
					   result.status == IndexStoreStatus::SNAPSHOT_READY && result.snapshot) ;
	DRIVERCRATE_EXPECT( context, result.persistedGeneration == generation) ;
	DRIVERCRATE_EXPECT(
		context, result.snapshot &&
					 result.snapshot->schemaReceipt().assetBytes().manifest().data().generation ==
						 generation) ;
}

/** @brief Testの実file handleを例外時も閉じます */
class StoreTestFile final {
public:
	/**
	 * @brief APIが返したhandleを単独所有します
	 * @param[in] handle API結果
	 */
	explicit StoreTestFile( const HANDLE handle) : handle_( handle)
	{
		// 取得不能を空byteの試験成功へ変換しません
		if( handle_ == INVALID_HANDLE_VALUE) {
			throw std::runtime_error( "isolated file API failed") ;
		}
	}
	/**
	 * @brief 所有handleを解放します
	 */
	~StoreTestFile() noexcept
	{
		CloseHandle( handle_) ;
	}
	/**
	 * @brief 単独所有のcopyを禁止します
	 */
	StoreTestFile( const StoreTestFile &) = delete ;
	/**
	 * @brief 単独所有の代入を禁止します
	 */
	StoreTestFile		&operator=( const StoreTestFile &) = delete ;
	/**
	 * @brief I/O中だけ実handleを借用します
	 * @return このownerの寿命まで有効なhandle
	 */
	[[nodiscard]] HANDLE get() const noexcept
	{
		return handle_ ;
	}

private:
	/// Scopeへ単独所有した実file handle
	HANDLE handle_ ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 改変試験だけで隔離fileの実byteを読みます
 * @param[in] path Isolated capabilityから得たheadまたはstageのpath
 * @return 完全な実disk byte
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> readStoreTestFile( const std::filesystem::path &path)
{
	const StoreTestFile file{CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
										 OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
										 nullptr)} ;	// Test内の実ownerです
	LARGE_INTEGER		size{} ;						// 同じfileの実長です
	// Test helperも有限実長なしに確保しません
	if( !GetFileSizeEx( file.get(), &size) || size.QuadPart <= 0 ||
	   size.QuadPart > 34LL * 1024LL * 1024LL) {
		throw std::runtime_error( "isolated read size failed") ;
	}

	std::vector<std::byte> bytes( static_cast<std::size_t>( size.QuadPart)) ;	// 有限な実byteです
	DWORD				   count{} ;											// 実read長です
	// 部分readをoriginal-byte比較へ使いません
	if( !ReadFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &count, nullptr) ||
	   count != bytes.size()) {
		throw std::runtime_error( "isolated read failed") ;
	}

	return bytes ;
}

//------------------------------------------------------------------------------
/**
 * @brief 隔離した既存headだけを試験byteで上書きします
 * @param[in] path Isolated capabilityから得た既存head path
 * @param[in] bytes 34MiB以内の人工byte
 */
//------------------------------------------------------------------------------
void writeStoreTestFile( const std::filesystem::path &path, const std::span<const std::byte> bytes)
{
	const StoreTestFile file{CreateFileW( path.c_str(), GENERIC_WRITE, 0U, nullptr, OPEN_EXISTING,
										 FILE_FLAG_OPEN_REPARSE_POINT,
										 nullptr)} ;	// Testだけの同file書込みです
	DWORD				count{} ;						// 実write長です
	// Fixture上書きが不完全なら検査自体を失敗させます
	if( bytes.size() > 34U * 1024U * 1024U ||
	   !WriteFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &count, nullptr) ||
	   count != bytes.size() || !SetEndOfFile( file.get()) || !FlushFileBuffers( file.get())) {
		throw std::runtime_error( "isolated write failed") ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Testの独立wire整数をpaddingなしで追加します
 * @param[in,out] bytes 人工wire
 * @param[in] value 値
 * @param[in] count 幅4または8byte
 */
//------------------------------------------------------------------------------
void appendStoreTestInteger( std::vector<std::byte> &bytes, const std::uint64_t value,
							const unsigned count)
{
	// 指定の有限byteだけをlittle-endianで書きます
	for( unsigned index = 0U; index < count; ++index) {
		bytes.push_back( static_cast<std::byte>( (value >> (index * 8U)) & 255U)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Test独立hashで改変wireの末尾digestを再計算します
 * @param[in] key RAM helperの独立CNG hash
 * @param[in,out] plain 最後の32byteがdigestの有限wire
 */
//------------------------------------------------------------------------------
void refreshStorePlainDigest( const RamKey &key, std::vector<std::byte> &plain)
{
	const auto hash = key.digest(
		// 製品wire codecを使いません
		assetText( std::span{plain}.first( plain.size() - 32U))) ;
	std::memcpy( plain.data() + plain.size() - 32U, hash.data(), hash.size()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 不正schemaも実署名・DPAPIへ通せる有限wireをtest側で構成します
 * @param[in] key RAM helperの独立hash
 * @param[in] inputs 実署名された人工入力
 * @param[in] index 元index byte
 * @return 正しいplain digestを持つwire。Snapshot成功を注入しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<std::byte> makeStorePlain( const RamKey &key, const StoreInputs &inputs,
													const std::string_view index)
{
	const auto			  &data = inputs.manifest.data() ;	// 実署名に結合した値です
	std::vector<std::byte> bytes ;							// 人工wireの所有byteです
	// 固定magicだけを追加します
	for( const char value : std::string_view{"DCIDXSTR01"}) {
		bytes.push_back( static_cast<std::byte>( value)) ;
	}

	appendStoreTestInteger( bytes, 1U, 4U) ;
	appendStoreTestInteger( bytes, 1U, 4U) ;
	appendStoreTestInteger( bytes, 1U, 4U) ;
	appendStoreTestInteger( bytes, data.generation, 8U) ;
	appendStoreTestInteger(
		bytes, static_cast<std::uint64_t>( data.publishedAtUtc.time_since_epoch().count()), 8U) ;
	appendStoreTestInteger( bytes, inputs.envelope.size(), 8U) ;
	appendStoreTestInteger( bytes, inputs.gzip.size(), 8U) ;
	// 独立原manifest／index hashを別fieldへ追加します
	for( const auto &hash : {data.manifestSha256, key.digest( index)}) {
		// 固定32byteを原値どおり保存します
		for( const auto value : hash) {
			bytes.push_back( static_cast<std::byte>( value)) ;
		}
	}

	// 原envelope byteを補正せず追加します
	for( const char value : inputs.envelope) {
		bytes.push_back( static_cast<std::byte>( value)) ;
	}

	bytes.insert( bytes.end(), inputs.gzip.begin(), inputs.gzip.end()) ;
	bytes.resize( bytes.size() + 32U) ;
	refreshStorePlainDigest( key, bytes) ;
	return bytes ;
}

/** @brief Test側のOS descriptorを例外時も回収します */
struct StoreTestLocalCloser {
	/**
	 * @brief OSが割り当てたdescriptorを返します
	 * @param[in] value LocalFree可能な領域
	 */
	void operator()( void *value) const noexcept
	{
		LocalFree( value) ;
	}
} ;

/** @brief 隔離file／rootだけのDACLを広げ、原DACLへ戻すownerです */
class StoreTestDacl final {
public:
	/**
	 * @brief 元DACLを保持してEveryoneを許す不正profileを設定します
	 * @param[in] path 自作isolated capabilityのfileまたはroot
	 * @param[in] directory Directory handleを開く場合true
	 */
	StoreTestDacl( const std::filesystem::path &path, const bool directory)
		: file_( CreateFileW( path.c_str(), READ_CONTROL | WRITE_DAC,
							FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
							FILE_FLAG_OPEN_REPARSE_POINT |
								(directory ? FILE_FLAG_BACKUP_SEMANTICS : 0U),
							nullptr))
	{
		PSECURITY_DESCRIPTOR raw{} ;	// OSが返す原descriptorです
		const DWORD			 code =
			GetSecurityInfo( file_.get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
							nullptr, nullptr, nullptr, &raw) ;	// 原保護を保存します
		original_.reset( raw) ;
		// 元の保護を回収できなければDACLを変更しません
		if( code != ERROR_SUCCESS) {
			throw std::runtime_error( "isolated original DACL failed") ;
		}

		PSECURITY_DESCRIPTOR wide{} ;	// 不正profileのOS descriptorです
		// Test fixtureもOSの有効なdescriptorだけを使います
		if( !ConvertStringSecurityDescriptorToSecurityDescriptorW( L"D:P(A;;FA;;;WD)",
																 SDDL_REVISION_1, &wide, nullptr)) {
			throw std::runtime_error( "isolated wide DACL failed") ;
		}

		const std::unique_ptr<void, StoreTestLocalCloser> owner{
			wide} ;			// 不正profileもscopeで返します
		PACL acl{} ;		// OS descriptorへ借用するDACLです
		BOOL present{} ;	// API返却の存在flagです
		BOOL defaulted{} ;	// API返却のdefaulted flagです
		// 実security変更が成立しなければ拒否試験自体を失敗させます
		if( !GetSecurityDescriptorDacl( wide, &present, &acl, &defaulted) || !present ||
		   SetSecurityInfo( file_.get(), SE_FILE_OBJECT,
						   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
						   nullptr, acl, nullptr) != ERROR_SUCCESS) {
			throw std::runtime_error( "isolated DACL write failed") ;
		}
	}
	/**
	 * @brief 例外時も自作rootの原DACLへの復帰を試みます
	 */
	~StoreTestDacl() noexcept
	{
		static_cast<void>( restore()) ;
	}
	/**
	 * @brief 保護の二重復帰ownerを作りません
	 */
	StoreTestDacl( const StoreTestDacl &) = delete ;
	/**
	 * @brief 復帰ownerの代入を禁止します
	 */
	StoreTestDacl	   &operator=( const StoreTestDacl &) = delete ;
	/**
	 * @brief 同じ実handleで原DACLへ戻し、元API結果を報告します
	 * @return 全復帰成功0、元のWin32 error
	 */
	[[nodiscard]] DWORD restore() noexcept
	{
		PACL acl{} ;		// 保存descriptor内の原DACLです
		BOOL present{} ;	// 有効DACLの存在flagです
		BOOL defaulted{} ;	// API返却のdefaulted flagです
		// 元descriptor不成立を成功へ変換しません
		if( !GetSecurityDescriptorDacl( original_.get(), &present, &acl, &defaulted) || !present) {
			return ERROR_INVALID_DATA ;
		}

		return SetSecurityInfo( file_.get(), SE_FILE_OBJECT,
							   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
							   nullptr, nullptr, acl, nullptr) ;
	}

private:
	/// DACL操作を同じfile／rootへ固定するowner
	StoreTestFile								file_ ;
	/// 復帰のためにだけ所有する元OS descriptor
	std::unique_ptr<void, StoreTestLocalCloser> original_ ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 自作のstage directoryへだけ実junctionを設定します
 * @param[in] stage 自作isolated root内の空directory
 * @param[in] target 同じisolated root。外部targetへ誘導しません
 * @return 実FSCTL設定成功の場合true。権限の変更は行いません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool createStoreTestJunction( const std::filesystem::path &stage,
										   const std::filesystem::path &target)
{
	const StoreTestFile file{CreateFileW( stage.c_str(), GENERIC_WRITE, 0U, nullptr, OPEN_EXISTING,
										 FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
										 nullptr)} ;	// Reparse自身を開きます
	const std::wstring	substitute =
		L"\\??\\" + target.native() ;				// Mount-point namespaceだけの内部targetです
	const std::wstring print = target.native() ;	// 同じrootの表示nameです
	const std::size_t  pathBytes =
		(substitute.size() + print.size() + 2U) * sizeof( wchar_t) ;	// 二つの終端を含む実byte数です
	// USHORT fieldとOS reparse枠を超えるfixtureを作りません
	if( pathBytes > 4096U) {
		throw std::runtime_error( "isolated junction size failed") ;
	}

	std::vector<std::byte> bytes ;	// PaddingなしのWin32 reparse inputです
	appendStoreTestInteger( bytes, IO_REPARSE_TAG_MOUNT_POINT, 4U) ;
	appendStoreTestInteger( bytes, 8U + pathBytes, 2U) ;
	appendStoreTestInteger( bytes, 0U, 2U) ;
	appendStoreTestInteger( bytes, 0U, 2U) ;
	appendStoreTestInteger( bytes, substitute.size() * sizeof( wchar_t), 2U) ;
	appendStoreTestInteger( bytes, (substitute.size() + 1U) * sizeof( wchar_t), 2U) ;
	appendStoreTestInteger( bytes, print.size() * sizeof( wchar_t), 2U) ;
	// 有限二文字列をUTF-16 code unitの原値どおり追加します
	for( const auto &text : {substitute, print}) {
		// Code unitごとにlittle-endianへ結合します
		for( const wchar_t value : text) {
			appendStoreTestInteger( bytes, static_cast<std::uint16_t>( value), 2U) ;
		}

		appendStoreTestInteger( bytes, 0U, 2U) ;
	}

	DWORD returned{} ;	// 同期FSCTLの実返却byte数です
	return DeviceIoControl( file.get(), FSCTL_SET_REPARSE_POINT, bytes.data(),
						   static_cast<DWORD>( bytes.size()), nullptr, 0U, &returned,
						   nullptr) != FALSE ;
}

//------------------------------------------------------------------------------
/**
 * @brief 旧record拒否時の履歴下限保持と現schemaへの正規更新を隔離storeで検査します
 * @param[in,out] context 元の実行順序へassertionと失敗を累積する集計先です
 * @param[in] key 呼出し元が試験中だけ所有するRAM署名鍵です
 * @param[in] trust keyの公開blobを借用する非永続trustです
 * @param[in] first 同世代衝突を検査する元の正規fixtureです
 * @param[in] descriptorRaw 呼出し元が所有する現schema recordです
 * @param[in] descriptorReceipt descriptorInputsの現schema認証receiptです
 * @param[in] descriptorInputs 正規世代8の署名済み試験入力です
 * @note 全引数は同期呼出し中だけ借用します。製品root・実鍵・通信は扱いません
 */
//------------------------------------------------------------------------------
void runSignedIndexHistoryFloorFixture( TestContext &context, const RamKey &key,
									   const std::span<const signed_index_detail::TrustKey> trust,
									   const StoreFixture &first, const std::string &descriptorRaw,
									   const IndexRecordsSchemaReceipt &descriptorReceipt,
									   const StoreInputs			   &descriptorInputs)
{
	using signed_index_store_detail::Access ;
	const int historyStart	 = context.assertionCount() ;		// 下限専用認証の独立集計です
	const int historyFailure = context.failureCount() ;			// 元groupの失敗を除去しません
	auto	  historyStore	 = Access::createIsolated( trust) ;	// 製品rootを扱わない自作保護storeです
	// 隔離rootを生成できない場合は残件を成功へ数えません
	if( !historyStore.store) {
		throw std::runtime_error( "history floor fixture failed") ;
	}

	const auto oldRaw =
		// 旧九fieldの原recordです
		replaced( descriptorRaw, ",\"nestedArchiveIdentity\":\"\"", "") ;
	const auto oldIndex =
		// 元hashも旧byteへ結合します
		descriptorIndex( recordSource(), recordEntry( key, oldRaw)) ;
	const auto oldInputs =
		// 現codecを通さず実署名/assetを作ります
		makeStoreInputs( key, oldIndex) ;
	const auto oldBytes = authenticateIndexAssetBytes( oldInputs.manifest, oldInputs.gzip,
													  NOW) ;	// 共通byte認証は成功です
	DRIVERCRATE_EXPECT( context, oldBytes.receipt.has_value()) ;
	// Byte fixtureの失敗を旧record拒否の成功へ変換しません
	if( !oldBytes.receipt) {
		throw std::runtime_error( "history asset fixture failed") ;
	}

	const auto oldRecords =
		// 旧codec/補完を追加しません
		readSignedIndexRecords( *oldBytes.receipt, NOW) ;
	DRIVERCRATE_EXPECT( context, !oldRecords.receipt &&
									oldRecords.status == IndexRecordsStatus::INVALID_RECORD) ;
	const auto oldPlain =
		// 正しいDPAPI内に履歴原byteを置きます
		makeStorePlain( key, oldInputs, oldIndex) ;
	DRIVERCRATE_EXPECT( context, Access::replacePlain( *historyStore.store, oldPlain) == 0) ;
	const auto historyHead =
		// この自作rootだけを比較します
		Access::isolatedRoot( *historyStore.store) / L"head.bin" ;
	const auto historyCipher = readStoreTestFile( historyHead) ;	// Commit点前の原暗号byteです
	auto	   historyOpened =
		// 通常openと同じ下限認証を通します
		Access::reopenIsolated( *historyStore.store) ;
	DRIVERCRATE_EXPECT( context, historyOpened.error == 0 && historyOpened.store) ;
	// Open失敗のまま別の既存ownerだけで成功させません
	if( !historyOpened.store) {
		throw std::runtime_error( "history floor reopen failed") ;
	}

	const auto historyReload =
		// 下限7を認証し、現在snapshotは拒否します
		historyOpened.store->reload( NOW) ;
	expectStoreRejected( context, historyReload, IndexStoreStatus::RECORDS_REJECTED) ;
	DRIVERCRATE_EXPECT( context,
					   historyReload.persistedGeneration == 7U &&
						   historyReload.recordsStatus == IndexRecordsStatus::INVALID_RECORD) ;
	const auto historyConflict =
		historyOpened.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip,
									NOW) ;	// 同世代の別manifestで旧不適合を救済しません
	expectStoreRejected( context, historyConflict, IndexStoreStatus::MANIFEST_REJECTED) ;
	DRIVERCRATE_EXPECT( context, historyConflict.manifestStatus ==
										SignedIndexManifestStatus::GENERATION_CONFLICT &&
									historyConflict.persistedGeneration == 7U) ;
	const auto lowerHistory	   = makeStoreFixture( key, 6U, 6U) ;	// 現在有効でも下限未満です
	const auto historyRollback = historyOpened.store->commit(
		lowerHistory.receipt, lowerHistory.inputs.envelope, lowerHistory.inputs.gzip,
		NOW) ;	// 旧record拒否を下限resetに使いません
	expectStoreRejected( context, historyRollback, IndexStoreStatus::MANIFEST_REJECTED) ;
	DRIVERCRATE_EXPECT( context, historyRollback.persistedGeneration == 7U &&
									historyRollback.manifestStatus ==
										SignedIndexManifestStatus::GENERATION_ROLLBACK) ;
	const auto invalidFreshIndex = replaced( oldIndex, "\"assetGeneration\":7",
											"\"assetGeneration\":8") ;	// N+1も欠損fieldを残します
	const auto invalidFreshInputs =
		// 署名正常は現schema成功を意味しません
		makeStoreInputs( key, invalidFreshIndex, 8U, 8U) ;
	const auto invalidFresh = historyOpened.store->commit(
		descriptorReceipt, invalidFreshInputs.envelope, invalidFreshInputs.gzip,
		NOW) ;	// 正しいreceiptの原byteとは不一致です
	expectStoreRejected( context, invalidFresh, IndexStoreStatus::STATE_REJECTED) ;
	const auto invalidFreshBytes =
		authenticateIndexAssetBytes( invalidFreshInputs.manifest, invalidFreshInputs.gzip,
									NOW) ;	// 同じfresh byteのcodec拒否も独立確認します
	DRIVERCRATE_EXPECT( context,
					   invalidFreshBytes.receipt &&
						   !readSignedIndexRecords( *invalidFreshBytes.receipt, NOW).receipt) ;
	DRIVERCRATE_EXPECT( context, readStoreTestFile( historyHead) == historyCipher) ;
	const auto historyAdvance = historyOpened.store->commit(
		descriptorReceipt, descriptorInputs.envelope, descriptorInputs.gzip,
		NOW) ;	// 同root/下限7から現在有効8へ正規commitします
	DRIVERCRATE_EXPECT( context,
					   historyAdvance.snapshot && historyAdvance.persistedGeneration == 8U &&
						   historyAdvance.commit == IndexStoreCommitDisposition::COMMITTED) ;
	expectStoredGeneration( context, *historyStore.store, 8U) ;
	const auto currentCipher = readStoreTestFile( historyHead) ;	// 新headは以後下げません
	const auto historySame	 = historyOpened.store->commit(
		  descriptorReceipt, descriptorInputs.envelope, descriptorInputs.gzip,
		  NOW) ;	// 保存済み全schemaでNO_CHANGEを確認します
	DRIVERCRATE_EXPECT( context, historySame.snapshot && historySame.persistedGeneration == 8U &&
									historySame.commit == IndexStoreCommitDisposition::NO_CHANGE &&
									readStoreTestFile( historyHead) == currentCipher) ;
	std::cout << "Signed index history floor assertions: "
			  << context.assertionCount() - historyStart
			  << ", failures: " << context.failureCount() - historyFailure << '\n' ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同RAM鍵と実隔離diskで保護原子head・世代・期限・障害を検査します
 * @param[in,out] context 共通unit assertion集計先
 * @note 製品store、network、実端末適合、実導入、process再起動は実行しません
 */
//------------------------------------------------------------------------------
void runSignedIndexStoreTests( TestContext &context)
{
	// 各戻り値とtemporaryを短命なfactory内で生成し、元の検証期間はheapで所有する
	const auto ownResult = []( auto make) { return std::make_unique<decltype( make())>( make()) ; } ;

	using signed_index_store_detail::Access ;
	using signed_index_store_detail::Fault ;
	static_assert( !std::is_default_constructible_v<AuthenticatedIndexSnapshot>) ;
	static_assert( !std::is_constructible_v<AuthenticatedIndexSnapshot, IndexRecordsSchemaReceipt,
										   std::string, std::vector<std::byte>>) ;
	static_assert( std::is_nothrow_move_constructible_v<AuthenticatedIndexSnapshot>) ;
	const int firstAssertion = context.assertionCount() ;	// この保存groupだけの実件数です
	const int firstFailure	 = context.failureCount() ;		// この保存groupだけの失敗です
	RamKey	  key ;											// 署名秘密鍵はRAMのCNG handleだけです
	key.generate( 3072U) ;
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;	// 製品には配置しません
	const auto firstOwner =
		// 同じ元結果を単独所有する
		ownResult( [&] { return makeStoreFixture( key) ; }) ;
	const auto &first = *firstOwner ;	// 世代7、原asset7、旧成功観測です
	const auto	newerOwner =
		// 同じ元結果を単独所有する
		ownResult( [&] { return makeStoreFixture( key, 8U, 8U) ; }) ;
	const auto &newer = *newerOwner ;	// Manifestと原assetを両方増やす正例です
	const auto	restored =
		// 新manifestだけが旧固定assetを参照します
		makeStoreFixture( key, 9U, 7U) ;
	auto opened = Access::createIsolated( trust) ;	// 実保護temp rootとgenesisです
	DRIVERCRATE_EXPECT( context, opened.error == 0 && opened.store) ;
	// 保護fixtureを用意できない場合は残りを空の成功にしません
	if( !opened.store) {
		throw std::runtime_error( "isolated index store creation failed") ;
	}

	auto &store = *opened.store ;	// Fixture寿命に結合する実storeです
	// 製品二ACEと隔離三ACEをRAM内で交差検査し、製品rootを作成しません
	for( const bool directory : {false, true}) {
		const auto product = Access::protectionSddl( store, directory, true) ;	// 実製品生成規則です
		const auto fixture =
			// 実隔離生成規則です
			Access::protectionSddl( store, directory, false) ;
		DRIVERCRATE_EXPECT( context, Access::acceptsProtectionSddl( store, product, directory, true)) ;
		DRIVERCRATE_EXPECT( context,
						   Access::acceptsProtectionSddl( store, fixture, directory, false)) ;
		DRIVERCRATE_EXPECT( context,
						   !Access::acceptsProtectionSddl( store, fixture, directory, true)) ;
		DRIVERCRATE_EXPECT( context,
						   !Access::acceptsProtectionSddl( store, product, directory, false)) ;
		DRIVERCRATE_EXPECT( context,
						   !Access::acceptsProtectionSddl( store, product, !directory, true)) ;
		const auto userOwner = fixture.substr( 0U, fixture.find( L"D:")) +
							   // 二ACEでもuser ownerを拒否します
							   product.substr( 4U) ;
		DRIVERCRATE_EXPECT( context,
						   !Access::acceptsProtectionSddl( store, userOwner, directory, true)) ;
		auto systemOwner = product ;	// SYSTEM ownerだけは製品既存profileとして認めます
		systemOwner.replace( 0U, 4U, L"O:SY") ;
		DRIVERCRATE_EXPECT( context,
						   Access::acceptsProtectionSddl( store, systemOwner, directory, true)) ;
		auto unprotected = product ;	// 同principalでも継承停止欠損を拒否します
		unprotected.replace( 4U, 3U, L"D:") ;
		DRIVERCRATE_EXPECT( context,
						   !Access::acceptsProtectionSddl( store, unprotected, directory, true)) ;
	}

	const auto root = Access::isolatedRoot( store) ;	// 任意pathを作る能力はありません
	const auto head = root / L"head.bin" ;				// 実ciphertext比較対象です
	const auto emptyOwner =
		// 同じ元結果を単独所有する
		ownResult( [&] { return store.reload( NOW) ; }) ;
	const auto &empty = *emptyOwner ;	// 実genesis headを再読取りします
	DRIVERCRATE_EXPECT( context, empty.status == IndexStoreStatus::EMPTY_STORE &&
									empty.persistedGeneration == 0U && !empty.snapshot) ;
	const auto	acceptedOwner = ownResult( [&] {
		 return store.commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW) ;
	 }) ;										// 同じ元結果を単独所有する
	const auto &accepted	  = *acceptedOwner ;	// 実一head commitです
	DRIVERCRATE_EXPECT( context, accepted.status == IndexStoreStatus::SNAPSHOT_READY &&
									accepted.snapshot &&
									accepted.commit == IndexStoreCommitDisposition::COMMITTED) ;
	DRIVERCRATE_EXPECT(
		context, accepted.snapshot &&
					 accepted.snapshot->originalEnvelope() == first.inputs.envelope &&
					 std::ranges::equal( accepted.snapshot->originalGzip(), first.inputs.gzip)) ;
	DRIVERCRATE_EXPECT( context, accepted.snapshot &&
									accepted.snapshot->storePolicyVersion() == 1U &&
									accepted.snapshot->schemaReceipt().indexSha256() ==
										first.receipt.indexSha256()) ;
	expectStoredGeneration( context, store, 7U) ;
	auto reopened = Access::reopenIsolated( store) ;	// 別に初期化した実handleで既存headを検証します
	DRIVERCRATE_EXPECT( context, reopened.error == 0 && reopened.store) ;
	// 別ownerの再open不成立を試験成功へ読み替えません
	if( !reopened.store) {
		throw std::runtime_error( "isolated index reopen failed") ;
	}

	expectStoredGeneration( context, *reopened.store, 7U) ;
	const auto	original  = readStoreTestFile( head) ;	// 初回成功後の実暗号byteです
	const auto	sameOwner = ownResult( [&] {
		 return store.commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW) ;
	 }) ;								// 同じ元結果を単独所有する
	const auto &same	  = *sameOwner ;	// 同世代同原manifestは再利用です
	DRIVERCRATE_EXPECT( context, same.status == IndexStoreStatus::SNAPSHOT_READY &&
									same.commit == IndexStoreCommitDisposition::NO_CHANGE) ;
	DRIVERCRATE_EXPECT( context, original == readStoreTestFile( head)) ;
	const auto resignedOwner =
		// 同じ元結果を単独所有する
		ownResult( [&] { return makeStoreFixture( key) ; }) ;
	const auto &resigned		  = *resignedOwner ;	// 同じ原manifestへ別のPSS署名を生成します
	const auto	sameOriginalOwner = ownResult( [&] {
		 return store.commit( resigned.receipt, resigned.inputs.envelope, resigned.inputs.gzip, NOW) ;
	 }) ;												// 同じ元結果を単独所有する
	const auto &sameOriginal	  = *sameOriginalOwner ;	// 元manifest identityで再利用します
	DRIVERCRATE_EXPECT( context,
					   sameOriginal.snapshot &&
						   sameOriginal.snapshot->originalEnvelope() == first.inputs.envelope) ;
	DRIVERCRATE_EXPECT( context, original == readStoreTestFile( head)) ;
	std::string conflictRaw =
		// 同意味でも異なる原byteです
		first.inputs.manifest.data().manifestBytes + " " ;
	const auto conflictEnvelope =
		// 正しい実署名を付けます
		envelope( conflictRaw, key.sign( conflictRaw)) ;
	auto conflictManifest = signed_index_detail::authenticateWithTrustKeys(
		conflictEnvelope, NOW, std::nullopt, trust) ;	// 保存前の世代scalarなしで作ります
	auto conflictBytes = authenticateIndexAssetBytes( *conflictManifest.manifest, first.inputs.gzip,
													 NOW) ;	// 全asset byteは正当です
	auto conflictRecords =
		// 全schemaも正当です
		readSignedIndexRecords( *conflictBytes.receipt, NOW) ;
	const auto	conflictOwner = ownResult( [&] {
		 return store.commit( *conflictRecords.receipt, conflictEnvelope, first.inputs.gzip, NOW) ;
	 }) ;										// 同じ元結果を単独所有する
	const auto &conflict	  = *conflictOwner ;	// 最新headで原byte差を拒否します
	expectStoreRejected( context, conflict, IndexStoreStatus::MANIFEST_REJECTED) ;
	DRIVERCRATE_EXPECT( context,
					   conflict.manifestStatus == SignedIndexManifestStatus::GENERATION_CONFLICT &&
						   conflict.persistedGeneration == 7U) ;
	DRIVERCRATE_EXPECT( context, original == readStoreTestFile( head)) ;
	// 全commit前診断で旧headの実ciphertextとhighwaterを保持します
	for( const Fault fault : {Fault::BEFORE_PROTECT, Fault::BEFORE_STAGE, Fault::PARTIAL_WRITE,
							 Fault::BEFORE_FLUSH, Fault::BEFORE_REPLACE}) {
		const auto failed =
			Access::commitWithFault( store, newer.receipt, newer.inputs.envelope, newer.inputs.gzip,
									NOW, fault) ;	// 同じ実I/O経路の拒否点です
		expectStoreRejected( context, failed,
							fault == Fault::BEFORE_PROTECT ? IndexStoreStatus::PROTECTION_FAILURE
														   : IndexStoreStatus::IO_FAILURE) ;
		DRIVERCRATE_EXPECT( context, failed.persistedGeneration == 7U && failed.error != 0) ;
		DRIVERCRATE_EXPECT( context, original == readStoreTestFile( head)) ;
		expectStoredGeneration( context, store, 7U) ;
	}

	{
		const auto held = Access::holdLock( store) ;	// 実share0の競合writer能力です
		DRIVERCRATE_EXPECT( context, static_cast<bool>( held)) ;
		expectStoreRejected(
			context,
			reopened.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW),
			IndexStoreStatus::BUSY) ;
		expectStoreRejected( context, store.reload( NOW), IndexStoreStatus::BUSY) ;
	}
	{
		const StoreTestFile denyDelete{
			CreateFileW( head.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
						OPEN_EXISTING, 0U, nullptr)} ;	// 旧headのrenameを実OSで拒否します
		const auto	failedRenameOwner = ownResult( [&] {
			 return store.commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW) ;
		 }) ;												// 同じ元結果を単独所有する
		const auto &failedRename	  = *failedRenameOwner ;	// Flush後のMoveFileEx失敗です
		expectStoreRejected( context, failedRename, IndexStoreStatus::COMMIT_UNCERTAIN,
							IndexStoreCommitDisposition::UNKNOWN) ;
		DRIVERCRATE_EXPECT( context, !failedRename.persistedGeneration && failedRename.error != 0) ;
	}
	expectStoredGeneration( context, store, 7U) ;
	DRIVERCRATE_EXPECT( context, original == readStoreTestFile( head)) ;
	const auto	advancedOwner = ownResult( [&] {
		 return reopened.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW) ;
	 }) ;										// 同じ元結果を単独所有する
	const auto &advanced	  = *advancedOwner ;	// 別ownerから先に世代8を確定します
	DRIVERCRATE_EXPECT( context, advanced.snapshot &&
									advanced.commit == IndexStoreCommitDisposition::COMMITTED) ;
	const auto	lowerOwner = ownResult( [&] {
		 return store.commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW) ;
	 }) ;								  // 同じ元結果を単独所有する
	const auto &lower	   = *lowerOwner ;	// 古いreceiptは最新head再読取りで拒否します
	expectStoreRejected( context, lower, IndexStoreStatus::MANIFEST_REJECTED) ;
	DRIVERCRATE_EXPECT( context,
					   lower.manifestStatus == SignedIndexManifestStatus::GENERATION_ROLLBACK &&
						   lower.persistedGeneration == 8U) ;
	const auto movedTarget		= first.receipt ;			// Copy後のmove元／先を独立検査します
	auto	   movedSource		= movedTarget ;				// Storeへ渡す不完全化対象です
	auto	   movedDestination = std::move( movedSource) ;	// 正当な原入力を所有します
	expectStoreRejected( context,
						store.commit( movedSource, first.inputs.envelope, first.inputs.gzip, NOW),
						IndexStoreStatus::INVALID_INPUT) ;
	DRIVERCRATE_EXPECT( context, movedDestination.indexSha256() == first.receipt.indexSha256()) ;
	const auto	restoredResultOwner = ownResult( [&] {
		 return store.commit( restored.receipt, restored.inputs.envelope, restored.inputs.gzip, NOW) ;
	 }) ;													// 同じ元結果を単独所有する
	const auto &restoredResult		= *restoredResultOwner ;	// 新世代9が旧固定asset7を参照します
	DRIVERCRATE_EXPECT( context,
					   restoredResult.snapshot && restoredResult.persistedGeneration == 9U) ;
	DRIVERCRATE_EXPECT( context, restoredResult.snapshot && restoredResult.snapshot->schemaReceipt()
																   .assetBytes()
																   .manifest()
																   .data()
																   .assetGeneration == 7U) ;
	DRIVERCRATE_EXPECT(
		context,
		restoredResult.snapshot &&
			restoredResult.snapshot->schemaReceipt().indexSha256() == first.receipt.indexSha256() &&
			std::ranges::equal( restoredResult.snapshot->originalGzip(), first.inputs.gzip)) ;
	DRIVERCRATE_EXPECT( context,
					   restoredResult.snapshot &&
						   restoredResult.snapshot->schemaReceipt()
								   .records()[0]
								   .lastSuccessfulObservationUtc.value ==
							   first.receipt.records()[0].lastSuccessfulObservationUtc.value) ;
	const auto stable = readStoreTestFile( head) ;	// 世代9の実保存byteです
	expectStoreRejected( context,
						store.commit( restored.receipt, restored.inputs.envelope,
									 restored.inputs.gzip, std::nullopt),
						IndexStoreStatus::TIME_UNAVAILABLE) ;
	const auto clockMissing =
		// 履歴highwaterは回収するがservableにしません
		store.reload( std::nullopt) ;
	expectStoreRejected( context, clockMissing, IndexStoreStatus::TIME_UNAVAILABLE) ;
	DRIVERCRATE_EXPECT( context, clockMissing.persistedGeneration == 9U) ;
	const auto future = NOW + std::chrono::days{15} ;	// 旧headが明確に期限切れになる固定時刻です
	const auto expiredOwner =
		// 同じ元結果を単独所有する
		ownResult( [&] { return store.reload( future) ; }) ;
	const auto &expired = *expiredOwner ;	// Historical署名は正常でも現在期限が不成立です
	expectStoreRejected( context, expired, IndexStoreStatus::EXPIRED) ;
	DRIVERCRATE_EXPECT( context,
					   expired.persistedGeneration == 9U && stable == readStoreTestFile( head)) ;
	const auto earlyOwner = ownResult(
		[&] { return store.reload( NOW - std::chrono::hours{2}) ; }) ;	// 同じ元結果を単独所有する
	const auto &early = *earlyOwner ;									// 発行前は候補へ渡しません
	expectStoreRejected( context, early, IndexStoreStatus::NOT_YET_VALID) ;
	DRIVERCRATE_EXPECT( context, early.persistedGeneration == 9U) ;
	const auto	freshOwner = ownResult( [&] {
		 return makeStoreFixture( key, 10U, 10U, future, "2026-10-26T05:00:00Z",
								 "2026-11-01T05:00:00Z") ;
	 }) ;								  // 同じ元結果を単独所有する
	const auto &fresh	   = *freshOwner ;	// 期限切れheadを新manifestだけで進めます
	// 期限切れheadを最新の有効manifestで置換した実結果です
	const auto	freshResultOwner = ownResult( [&] {
		 return store.commit( fresh.receipt, fresh.inputs.envelope, fresh.inputs.gzip, future) ;
	 }) ;											  // 同じ元結果を単独所有する
	const auto &freshResult		 = *freshResultOwner ;	// 元所有者と同じscopeだけで結果を借用する
	DRIVERCRATE_EXPECT( context, freshResult.snapshot && freshResult.persistedGeneration == 10U) ;
	const auto	freshLowerOwner = ownResult( [&] {
		 return makeStoreFixture( key, 8U, 7U, future, "2026-10-26T05:00:00Z",
								 "2026-11-01T05:00:00Z") ;
	 }) ;											// 同じ元結果を単独所有する
	const auto &freshLower		= *freshLowerOwner ;	// 有効期限だけ新しいrollbackです
	// 時計が進んでもhighwaterを下げない実拒否結果です
	const auto	expiredRollbackOwner = ownResult( [&] {
		 return store.commit( freshLower.receipt, freshLower.inputs.envelope, freshLower.inputs.gzip,
							 future) ;
	 }) ;												 // 同じ元結果を単独所有する
	const auto &expiredRollback = *expiredRollbackOwner ;	// 元所有者と同じscopeだけで結果を借用する
	expectStoreRejected( context, expiredRollback, IndexStoreStatus::MANIFEST_REJECTED) ;
	DRIVERCRATE_EXPECT( context, expiredRollback.manifestStatus ==
										SignedIndexManifestStatus::GENERATION_ROLLBACK &&
									expiredRollback.persistedGeneration == 10U) ;
	// 各commit後診断はheadを実advanceし、snapshotだけを発行しません
	for( const Fault fault :
		{Fault::AFTER_REPLACE, Fault::READBACK, Fault::AFTER_COMMIT_ALLOCATION}) {
		auto		local = Access::createIsolated( trust) ;	// 各診断を独立した実diskで検査します
		const auto	savedOwner = ownResult( [&] {
			 return local.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip,
										NOW) ;
		 }) ;								  // 同じ元結果を単独所有する
		const auto &saved	   = *savedOwner ;	// 旧成功stateです
		DRIVERCRATE_EXPECT( context, saved.snapshot.has_value()) ;
		// Commit後の障害でもadvanceを維持する実結果です
		const auto failed = Access::commitWithFault(
			*local.store, newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW, fault) ;
		expectStoreRejected( context, failed, IndexStoreStatus::COMMITTED_NO_SNAPSHOT,
							IndexStoreCommitDisposition::COMMITTED) ;
		DRIVERCRATE_EXPECT( context, failed.persistedGeneration == 8U && failed.error != 0) ;
		expectStoredGeneration( context, *local.store, 8U) ;
		expectStoreRejected(
			context,
			local.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW),
			IndexStoreStatus::MANIFEST_REJECTED) ;
	}

	{
		auto		local = Access::createIsolated( trust) ;	// 改変群だけの独立rootです
		// 改変前に確定した実成功stateです
		const auto	savedOwner = ownResult( [&] {
			 return local.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip,
										NOW) ;
		 }) ;								  // 同じ元結果を単独所有する
		const auto &saved	   = *savedOwner ;	// 元所有者と同じscopeだけで結果を借用する
		DRIVERCRATE_EXPECT( context, saved.snapshot.has_value()) ;
		const auto localHead =
			// 改変は自作rootへ限定します
			Access::isolatedRoot( *local.store) / L"head.bin" ;
		const auto originalCipher = readStoreTestFile( localHead) ;	// 元成功ciphertextです
		std::vector<std::byte> plain ;								// 実DPAPIが返す所有plainです
		DRIVERCRATE_EXPECT( context, Access::readPlain( *local.store, plain) == 0) ;
		const auto originalPlain = plain ;	// 元成功wireを保持します
		// Plainの各独立境界を正しいDPAPI保護の内側で改変します
		for( const std::size_t offset : {0U, 10U, 14U, 18U, 22U, 30U, 38U, 46U, 54U, 86U, 118U}) {
			plain = originalPlain ;
			plain[offset] ^= std::byte{1U} ;
			refreshStorePlainDigest( key, plain) ;
			DRIVERCRATE_EXPECT( context, Access::replacePlain( *local.store, plain) == 0) ;
			const auto rejectedOwner =
				// 同じ元結果を単独所有する
				ownResult( [&] { return local.store->reload( NOW) ; }) ;
			const auto &rejected = *rejectedOwner ;	// Wire／署名／世代等の実拒否です
			expectStoreRejected( context, rejected, IndexStoreStatus::STATE_REJECTED) ;
			DRIVERCRATE_EXPECT( context, !rejected.persistedGeneration) ;
		}

		plain = originalPlain ;
		// 原gzip末尾を改変します
		plain[plain.size() - 33U] ^= std::byte{1U} ;
		refreshStorePlainDigest( key, plain) ;
		DRIVERCRATE_EXPECT( context, Access::replacePlain( *local.store, plain) == 0) ;
		const auto badGzipOwner =
			// 同じ元結果を単独所有する
			ownResult( [&] { return local.store->reload( NOW) ; }) ;
		const auto &badGzip = *badGzipOwner ;	// DPAPIが正常でも原gzip hashで拒否します
		expectStoreRejected( context, badGzip, IndexStoreStatus::STATE_REJECTED) ;
		DRIVERCRATE_EXPECT( context, badGzip.assetStatus == IndexAssetBytesStatus::HASH_MISMATCH) ;
		const auto badIndex = replaced(
			distributionIndex( recordSource(), recordEntry( key, distributionRecord())),
			"driver-index-records-v1", "invalid-records-schema") ;			// 正しい署名でも不正schemaです
		const auto badInputs = makeStoreInputs( key, badIndex) ;			// 実署名と圧縮hashは成立します
		const auto badPlain	 = makeStorePlain( key, badInputs, badIndex) ;	// Plain整合性も成立します
		DRIVERCRATE_EXPECT( context, Access::replacePlain( *local.store, badPlain) == 0) ;
		const auto badRecordsOwner =
			// 同じ元結果を単独所有する
			ownResult( [&] { return local.store->reload( NOW) ; }) ;
		const auto &badRecords = *badRecordsOwner ;	// 最後のschema再認証で拒否します
		expectStoreRejected( context, badRecords, IndexStoreStatus::RECORDS_REJECTED) ;
		DRIVERCRATE_EXPECT( context, badRecords.recordsStatus == IndexRecordsStatus::INVALID_INDEX) ;
		DRIVERCRATE_EXPECT( context, badRecords.persistedGeneration == 7U) ;
		DRIVERCRATE_EXPECT( context, Access::replacePlain( *local.store, originalPlain) == 0) ;
		expectStoredGeneration( context, *local.store, 7U) ;
		const auto validCipher = readStoreTestFile( localHead) ;	// 実再保護後の正常byteです
		auto	   corrupted   = validCipher ;						// DPAPI integrity自体の改変です
		corrupted[corrupted.size() / 2U] ^= std::byte{1U} ;
		writeStoreTestFile( localHead, corrupted) ;
		const auto dpapiRejectedOwner =
			// 同じ元結果を単独所有する
			ownResult( [&] { return local.store->reload( NOW) ; }) ;
		const auto &dpapiRejected = *dpapiRejectedOwner ;	// 実DPAPIまたはplain検査での拒否です
		DRIVERCRATE_EXPECT( context, (dpapiRejected.status == IndexStoreStatus::PROTECTION_FAILURE ||
									 dpapiRejected.status == IndexStoreStatus::STATE_REJECTED) &&
										!dpapiRejected.snapshot) ;
		DRIVERCRATE_EXPECT( context, !dpapiRejected.persistedGeneration) ;
		writeStoreTestFile( localHead, validCipher) ;
		auto other = Access::createIsolated( trust) ;	// 同じmachineでもroot identityが異なります
		const auto otherHead =
			// 別の自作rootです
			Access::isolatedRoot( *other.store) / L"head.bin" ;
		writeStoreTestFile( otherHead, validCipher) ;
		expectStoreRejected( context, other.store->reload( NOW),
							IndexStoreStatus::PROTECTION_FAILURE) ;
		std::vector<std::byte> oversized( 33U * 1024U * 1024U + 1U) ;	// 実disk上限の一byte超過です
		writeStoreTestFile( localHead, oversized) ;
		expectStoreRejected( context, local.store->reload( NOW), IndexStoreStatus::STATE_REJECTED) ;
		writeStoreTestFile( localHead, originalCipher) ;
		expectStoredGeneration( context, *local.store, 7U) ;
		DRIVERCRATE_EXPECT( context, DeleteFileW( localHead.c_str()) !=
										FALSE) ;	// established headだけを意図的に欠損させます
		expectStoreRejected( context, local.store->reload( NOW), IndexStoreStatus::STATE_REJECTED) ;
		expectStoreRejected(
			context,
			local.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW),
			IndexStoreStatus::STATE_REJECTED) ;
		const auto missingReopen =
			// 初期化し直さないことを確認します
			Access::reopenIsolated( *local.store) ;
		DRIVERCRATE_EXPECT( context, !missingReopen.store && missingReopen.error != 0) ;
		DRIVERCRATE_EXPECT( context, !std::filesystem::exists( localHead)) ;
	}
	{
		auto		local = Access::createIsolated( trust) ;	// 属性・ACL・hard link検査用の実rootです
		// 属性を変更する前に保存した実成功stateです
		const auto	savedOwner = ownResult( [&] {
			 return local.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip,
										NOW) ;
		 }) ;								  // 同じ元結果を単独所有する
		const auto &saved	   = *savedOwner ;	// 元所有者と同じscopeだけで結果を借用する
		DRIVERCRATE_EXPECT( context, saved.snapshot.has_value()) ;
		const auto localRoot = Access::isolatedRoot( *local.store) ;	// 自作rootだけへ限定します
		const auto localHead = localRoot / L"head.bin" ;				// 単一linkを要求するfileです
		const auto link		 = localRoot / L"extra-link.bin" ;			// 一時hard linkの明示名です
		DRIVERCRATE_EXPECT( context,
						   CreateHardLinkW( link.c_str(), localHead.c_str(), nullptr) != FALSE) ;
		expectStoreRejected( context, local.store->reload( NOW),
							IndexStoreStatus::PROTECTION_FAILURE) ;
		DRIVERCRATE_EXPECT( context, DeleteFileW( link.c_str()) != FALSE) ;
		expectStoredGeneration( context, *local.store, 7U) ;
		{
			StoreTestDacl wide{localHead, false} ;	// 実headの不正Everyone allowを拒否します
			expectStoreRejected( context, local.store->reload( NOW),
								IndexStoreStatus::PROTECTION_FAILURE) ;
			DRIVERCRATE_EXPECT( context, wide.restore() == ERROR_SUCCESS) ;
		}
		expectStoredGeneration( context, *local.store, 7U) ;
		{
			StoreTestDacl wide{localRoot, true} ;	// 実rootの不正ACLも再確認して拒否します
			expectStoreRejected( context, local.store->reload( NOW),
								IndexStoreStatus::PROTECTION_FAILURE) ;
			DRIVERCRATE_EXPECT( context, wide.restore() == ERROR_SUCCESS) ;
		}
		expectStoredGeneration( context, *local.store, 7U) ;
		const auto stage = localRoot / L"head.stage" ;	// 部分stageはauthorityにしません
		DRIVERCRATE_EXPECT( context, CreateDirectoryW( stage.c_str(), nullptr) != FALSE) ;
		expectStoreRejected(
			context,
			local.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW),
			IndexStoreStatus::PROTECTION_FAILURE) ;
		DRIVERCRATE_EXPECT( context, RemoveDirectoryW( stage.c_str()) != FALSE) ;
		expectStoredGeneration( context, *local.store, 7U) ;
		DRIVERCRATE_EXPECT( context, CreateDirectoryW( stage.c_str(), nullptr) != FALSE) ;
		DRIVERCRATE_EXPECT( context, createStoreTestJunction( stage, localRoot)) ;
		expectStoreRejected(
			context,
			local.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW),
			IndexStoreStatus::PROTECTION_FAILURE) ;
		DRIVERCRATE_EXPECT( context, RemoveDirectoryW( stage.c_str()) !=
										FALSE) ;	// Junction自身だけを外し、targetを削除しません
		expectStoredGeneration( context, *local.store, 7U) ;
		const auto renamedRoot =
			localRoot.parent_path() /
			(localRoot.filename().native() + L"-renamed") ;	// 明示した自作rootのrename試験です
		DRIVERCRATE_EXPECT( context,
						   MoveFileExW( localRoot.c_str(), renamedRoot.c_str(), 0U) == FALSE) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::exists( localRoot) &&
										!std::filesystem::exists( renamedRoot)) ;
		const auto lockPath = localRoot / L"store.lock" ;	// 永続markerの欠損拒否です
		DRIVERCRATE_EXPECT( context, DeleteFileW( lockPath.c_str()) != FALSE) ;
		expectStoreRejected( context, local.store->reload( NOW), IndexStoreStatus::STATE_REJECTED) ;
		expectStoreRejected(
			context,
			local.store->commit( newer.receipt, newer.inputs.envelope, newer.inputs.gzip, NOW),
			IndexStoreStatus::STATE_REJECTED) ;
	}
	{
		auto local = Access::createIsolated( {}) ;	// 製品と同じempty trustの別隔離stateです
		expectStoreRejected(
			context,
			local.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW),
			IndexStoreStatus::MANIFEST_REJECTED) ;
		const auto stillEmptyOwner =
			// 同じ元結果を単独所有する
			ownResult( [&] { return local.store->reload( NOW) ; }) ;
		const auto &stillEmpty = *stillEmptyOwner ;	// Test鍵の自己信頼でgenesisを進めません
		DRIVERCRATE_EXPECT( context, stillEmpty.status == IndexStoreStatus::EMPTY_STORE &&
										stillEmpty.persistedGeneration == 0U) ;
	}
	{
		const auto	maximumOwner = ownResult( [&] {
			 return makeStoreFixture( key, 7U, 7U, NOW, "2026-10-11T05:00:00Z",
									 "2026-10-25T05:00:00Z",
									 // 実32MiB gzip境界です
									 static_cast<std::size_t>( INDEX_ASSET_MAX_BYTES)) ;
		 }) ;									  // 同じ元結果を単独所有する
		const auto &maximum		 = *maximumOwner ;					// 元所有者と同じscopeだけで結果を借用する
		auto		local		 = Access::createIsolated( trust) ;	// 通常と同じ実policyで保存します
		// 実上限gzipを一headへ保護保存した結果です
		const auto	savedOwner = ownResult( [&] {
			 return local.store->commit( maximum.receipt, maximum.inputs.envelope,
										maximum.inputs.gzip, NOW) ;
		 }) ;								  // 同じ元結果を単独所有する
		const auto &saved	   = *savedOwner ;	// 元所有者と同じscopeだけで結果を借用する
		DRIVERCRATE_EXPECT( context, saved.snapshot && saved.snapshot->originalGzip().size() ==
														  INDEX_ASSET_MAX_BYTES) ;
		const auto loadedOwner =
			// 同じ元結果を単独所有する
			ownResult( [&] { return local.store->reload( NOW) ; }) ;
		const auto &loaded = *loadedOwner ;	// 実上限原byteをDPAPIから再認証します
		DRIVERCRATE_EXPECT( context,
						   loaded.snapshot && std::ranges::equal( loaded.snapshot->originalGzip(),
																 maximum.inputs.gzip)) ;
	}
	std::cout << "Signed index protected store assertions: "
			  << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
	const int descriptorStoreStart	 = context.assertionCount() ;	// 旧store groupと別の有限集計
	const int descriptorStoreFailure = context.failureCount() ;		// 新groupだけの失敗開始値
	auto	  descriptorStore = Access::createIsolated( trust) ;	// 新たな自作隔離rootだけを使用する
	// 隔離fixtureの生成失敗を再認証成功にしない
	if( !descriptorStore.store) {
		throw std::runtime_error( "descriptor store fixture failed") ;
	}

	const std::string legacyIndex = distributionIndex(
		// 全14fieldの旧原asset
		recordSource(), recordEntry( key, distributionRecord())) ;
	const auto legacyPlain =
		// 既存helperで旧head1を明示構成する
		makeStorePlain( key, first.inputs, legacyIndex) ;
	DRIVERCRATE_EXPECT( context, legacyPlain.size() > 22U && legacyPlain[18U] == std::byte{1U} &&
									legacyPlain[19U] == std::byte{0U} &&
									legacyPlain[20U] == std::byte{0U} &&
									legacyPlain[21U] == std::byte{0U}) ;
	DRIVERCRATE_EXPECT( context, Access::replacePlain( *descriptorStore.store, legacyPlain) == 0) ;
	const auto legacyReload =
		// 実DPAPIから旧headの全原入力を現codecで再認証する
		descriptorStore.store->reload( NOW) ;
	DRIVERCRATE_EXPECT(
		context,
		legacyReload.snapshot &&
			legacyReload.snapshot->schemaReceipt().schemaPolicyVersion() ==
				INDEX_RECORD_READER_POLICY_VERSION &&
			legacyReload.snapshot->schemaReceipt().records()[0].recordSchemaVersion == 1U &&
			!legacyReload.snapshot->schemaReceipt().records()[0].acquisitionDescriptor &&
			legacyReload.persistedGeneration == 7U) ;
	const std::string descriptorRaw =
		// 原byteを維持するv2 record
		descriptorRecord( descriptorFixture()) ;
	const std::string descriptorAsset =
		// 別固定世代8のv2原byte
		replaced( descriptorIndex( recordSource(), recordEntry( key, descriptorRaw)),
				 "\"assetGeneration\":7", "\"assetGeneration\":8") ;
	const auto descriptorInputs =
		// 新manifestと新固定assetへ結ぶ
		makeStoreInputs( key, descriptorAsset, 8U, 8U) ;
	const auto descriptorBytes = authenticateIndexAssetBytes(
		descriptorInputs.manifest, descriptorInputs.gzip, NOW) ;	// 実GZipとhash検査
	// 前段生成失敗は取得codecの拒否成功にしない
	if( !descriptorBytes.receipt) {
		throw std::runtime_error( "descriptor store byte fixture rejected") ;
	}

	const auto descriptorRecords =
		// 型付き元申告の全検査
		readSignedIndexRecords( *descriptorBytes.receipt, NOW) ;
	// Schema fixtureの不成立では保存を開始しない
	if( !descriptorRecords.receipt) {
		throw std::runtime_error( "descriptor store record fixture rejected") ;
	}

	const auto	descriptorSavedOwner = ownResult( [&] {
		 return descriptorStore.store->commit( *descriptorRecords.receipt, descriptorInputs.envelope,
											  descriptorInputs.gzip, NOW) ;
	 }) ;													  // 同じ元結果を単独所有する
	const auto &descriptorSaved		 = *descriptorSavedOwner ;	// 実一head transactionを再利用する
	DRIVERCRATE_EXPECT( context,
					   descriptorSaved.snapshot && descriptorSaved.persistedGeneration == 8U) ;
	std::vector<std::byte> descriptorPlain ;	// 実headの保存wire互換値だけを検査する有限所有byte
	DRIVERCRATE_EXPECT( context, Access::readPlain( *descriptorStore.store, descriptorPlain) == 0 &&
									descriptorPlain.size() > 22U &&
									descriptorPlain[18U] == std::byte{1U}) ;
	const auto descriptorReload =
		// 保存した原byteからv2を実再認証する
		descriptorStore.store->reload( NOW) ;
	DRIVERCRATE_EXPECT(
		context,
		descriptorReload.snapshot &&
			descriptorReload.snapshot->schemaReceipt().schemaPolicyVersion() ==
				INDEX_RECORD_READER_POLICY_VERSION &&
			descriptorReload.snapshot->schemaReceipt().records()[0].recordSchemaVersion == 2U &&
			descriptorReload.snapshot->schemaReceipt().records()[0].originalBytes ==
				descriptorRaw &&
			descriptorReload.snapshot->schemaReceipt().records()[0].acquisitionDescriptor &&
			descriptorReload.snapshot->originalEnvelope() == descriptorInputs.envelope) ;
	expectStoreRejected(
		context,
		descriptorStore.store->commit( first.receipt, first.inputs.envelope, first.inputs.gzip, NOW),
		IndexStoreStatus::MANIFEST_REJECTED) ;
	std::cout << "Signed index descriptor store assertions: "
			  << context.assertionCount() - descriptorStoreStart
			  << ", failures: " << context.failureCount() - descriptorStoreFailure << '\n' ;
	// 追加fixtureの一時値を独立stackへ分け、元のassertion順序を維持します
	runSignedIndexHistoryFloorFixture( context, key, trust, first, descriptorRaw,
									  *descriptorRecords.receipt, descriptorInputs) ;
}

namespace {

//------------------------------------------------------------------------------
/**
 * @brief 固定domain名だけを借りた人工RAM署名の完全fixtureを作ります
 * @param[in] key 永続化しないRAM署名鍵です
 * @param[in] local 検証用IDへ署名する場合trueです
 * @param[in] generation Manifest世代です
 * @param[in] assetGeneration 原asset世代です
 * @return 架空の署名/byte/schema receiptです。製品鍵の署名ではありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] StoreFixture makeDomainStoreFixture( const RamKey &key, const bool local,
												  const std::uint64_t generation	  = 7U,
												  const std::uint64_t assetGeneration = 7U)
{
	auto	   first = makeStoreFixture( key, generation, assetGeneration) ;	// 元の全schema正例です
	const auto id =
		local ? "fixture-local" : index_distribution_trust::KEY_ID ;	// 実署名後の分類を検査します
	const auto raw	 = replaced( first.inputs.manifest.data().manifestBytes, "fixture-main",
								id) ;						// 原manifestだけを人工再署名します
	auto	   outer = envelope( raw, key.sign( raw), id) ;	// 署名materialは人工RAM鍵です
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{id, key.publicBlob}}} ;	// 実製品の固定鍵を置換しません
	auto manifest = signed_index_detail::authenticateWithTrustKeys( outer, NOW, std::nullopt,
																   trust) ;	// 実CNG認証です
	// 人工fixtureの不成立をdomain拒否の成功にしません
	if( !manifest.manifest) {
		throw std::runtime_error( "domain manifest fixture failed") ;
	}

	auto asset = authenticateIndexAssetBytes( *manifest.manifest, first.inputs.gzip,
											 NOW) ;	// 原gzipを検証します
	// 前段が不成立の場合は残りのtestへ進みません
	if( !asset.receipt) {
		throw std::runtime_error( "domain asset fixture failed") ;
	}

	auto records = readSignedIndexRecords( *asset.receipt, NOW) ;	// 原全schemaを検証します
	// Schema拒否をdomain成功へ換算しません
	if( !records.receipt) {
		throw std::runtime_error( "domain records fixture failed") ;
	}

	return {{std::move( *manifest.manifest), std::move( outer), std::move( first.inputs.gzip)},
			std::move( *records.receipt)} ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 実署名/DPAPIの隔離rootで用途別trust・世代下限・未知root拒否を検査します
 * @param[in,out] context 共通unit assertion集計先です
 * @note 固定ProgramData/実鍵/実通信へアクセスしません
 */
//------------------------------------------------------------------------------
void runSignedIndexStoreDomainTests( TestContext &context)
{
	using signed_index_store_detail::Access ;
	using signed_index_store_detail::NamespaceLeaf ;
	const int initialAssertions = context.assertionCount() ;	// 現行domainだけの分母です
	RamKey	  key ;												// 人工署名鍵はRAMだけです
	key.generate( 3072U) ;
	const std::array<signed_index_detail::TrustKey, 1U> productionTrust{
		{{index_distribution_trust::KEY_ID, key.publicBlob}}} ;	// 通常側はlocal鍵を持ちません
	const std::array<signed_index_detail::TrustKey, 1U> localTrust{
		{{"fixture-local", key.publicBlob}}} ;	// 固定製品trustを変更しません
	auto parent = Access::createIsolated( {}) ;	// 自作sandboxだけを所有します
	// Fixture作成不能を空成功へ変換しません
	if( !parent.store) {
		throw std::runtime_error( "domain parent failed") ;
	}

	auto production = Access::openNamespaceIsolated( *parent.store, NamespaceLeaf::DISTRIBUTION,
													productionTrust) ;	// 現行配布domainです
	auto local		= Access::openNamespaceIsolated( *parent.store, NamespaceLeaf::LOCAL,
													localTrust) ;	// 独立local domainです
	// 両rootを作れない場合は後続の検査へ進みません
	if( !production.store || !local.store) {
		throw std::runtime_error( "domain creation failed") ;
	}

	const auto distributionFixture = makeDomainStoreFixture( key, false) ;	// 真署名IDだけを使います
	const auto localFixture		   = makeDomainStoreFixture( key, true) ;	// 同世代で別trustです
	DRIVERCRATE_EXPECT( context, production.store
									->commit( distributionFixture.receipt,
											 distributionFixture.inputs.envelope,
											 distributionFixture.inputs.gzip, NOW)
									.snapshot.has_value()) ;
	DRIVERCRATE_EXPECT( context, local.store
									->commit( localFixture.receipt, localFixture.inputs.envelope,
											 localFixture.inputs.gzip, NOW)
									.snapshot.has_value()) ;
	const auto productionPath = Access::isolatedRoot( *production.store) ;			// 自作rootだけです
	const auto localPath	  = Access::isolatedRoot( *local.store) ;				// 独立rootの同世代です
	const auto productionHead = readStoreTestFile( productionPath / L"head.bin") ;	// 原暗号byteです
	const auto localHead	  = readStoreTestFile( localPath / L"head.bin") ;		// 原byteを保持します
	DRIVERCRATE_EXPECT( context, productionPath != localPath) ;
	DRIVERCRATE_EXPECT( context, !production.store
									 ->commit( localFixture.receipt, localFixture.inputs.envelope,
											  localFixture.inputs.gzip, NOW)
									 .snapshot) ;
	DRIVERCRATE_EXPECT( context, !local.store
									 ->commit( distributionFixture.receipt,
											  distributionFixture.inputs.envelope,
											  distributionFixture.inputs.gzip, NOW)
									 .snapshot) ;
	const auto lower	= makeDomainStoreFixture( key, false, 6U, 6U) ;	// 原high-water未満です
	const auto rollback = production.store->commit( lower.receipt, lower.inputs.envelope,
												   lower.inputs.gzip, NOW) ;	// 自動resetしません
	DRIVERCRATE_EXPECT( context,
					   rollback.manifestStatus == SignedIndexManifestStatus::GENERATION_ROLLBACK &&
						   rollback.persistedGeneration == 7U) ;
	const auto expired =
		// 失効でもfloorを保持します
		production.store->reload( NOW + std::chrono::days{15}) ;
	DRIVERCRATE_EXPECT( context, expired.status == IndexStoreStatus::EXPIRED &&
									expired.persistedGeneration == 7U && !expired.snapshot) ;
	// 未知共用rootの存在を発見したら、両domainの再open/操作を拒否します
	auto unknown = Access::openNamespaceIsolated( *parent.store, NamespaceLeaf::LEGACY,
												 {}) ;	// 旧形式を認証しません
	DRIVERCRATE_EXPECT( context, unknown.store != nullptr) ;
	DRIVERCRATE_EXPECT( context, Access::openNamespaceIsolated(
									*parent.store, NamespaceLeaf::DISTRIBUTION, productionTrust)
										.error == ERROR_REVISION_MISMATCH) ;
	DRIVERCRATE_EXPECT(
		context,
		Access::openNamespaceIsolated( *parent.store, NamespaceLeaf::LOCAL, localTrust).error ==
			ERROR_REVISION_MISMATCH) ;
	DRIVERCRATE_EXPECT( context, production.store->reload( NOW).error == ERROR_REVISION_MISMATCH) ;
	DRIVERCRATE_EXPECT( context, local.store->reload( NOW).error == ERROR_REVISION_MISMATCH) ;
	DRIVERCRATE_EXPECT( context, readStoreTestFile( productionPath / L"head.bin") == productionHead &&
									readStoreTestFile( localPath / L"head.bin") == localHead) ;
	std::cout << "Signed index store domain assertions: "
			  << context.assertionCount() - initialAssertions << '\n' ;
}

namespace {

//------------------------------------------------------------------------------
/**
 * @brief 文法上有効なINF・SYS・未署名CATの非空ZIPをRAMだけで作ります
 * @param[in] network trueではNetwork class、falseでは元fixtureの通常classを使う
 * @param[out] infBytes 非null時は同ZIPへ入れた原INF byteを返します
 * @param[in] nestedMembers 同じ一段inner ZIPを置く有限なouter member名です
 * @param[in] includeFlat trueはouter直下にも同じINF閉包を含めます
 * @param[in] managed 0は旧fixture、1はdriver DATA、2..7はforeign/app/MSI/選択自動起動のscope負例です
 * @param[in] models 0は旧単一Models、1は二OS装飾、2は別Manufacturer行で両装飾が実選択されます
 * @param[in] originalInf 非空なら同じ三memberのZIPへ指定した人工INFの全byteを入れます
 * @return Minizが生成した有限原byte。CAT拒否を正常署名へ変更しません
 */
//------------------------------------------------------------------------------
std::string normalWorkerDriverZip( const bool network = false, std::string *const infBytes = nullptr,
								  const std::span<const std::string_view> nestedMembers = {},
								  const bool includeFlat = true, const unsigned managed = 0U,
								  const unsigned		 models		 = 0U,
								  const std::string_view originalInf = {})
{
	std::string inf =
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Ports\r\n"
		"ClassGuid={4d36e978-e325-11ce-bfc1-08002be10318}\r\nProvider=%Vendor%\r\n"
		"DriverVer=10/11/2026,1.0.0.0\r\nCatalogFile=fixture.cat\r\n"
		"[Manufacturer]\r\n%Vendor%=Models,NTamd64\r\n[Models.NTamd64]\r\n"
		"%Device%=Install,TESTBUS\\SYNTH_0001\r\n[Install]\r\nCopyFiles=Files\r\n"
		"[Files]\r\nfixture.sys\r\n[DestinationDirs]\r\nFiles=12\r\n"
		"[SourceDisksNames]\r\n1=\"fixture\"\r\n[SourceDisksFiles]\r\nfixture.sys=1\r\n"
		"[Strings]\r\nVendor=\"Fixture Vendor\"\r\nDevice=\"Fixture Device\"\r\n" ;	// 架空IDだけです
	mz_zip_archive archive{} ;														// MinizのRAM writer。全経路でendします
	// 特定のModels・サービスを宣言する独立fixtureも同じZIP構築と元CAT・SYSを使います
	if( !originalInf.empty()) {
		inf.assign( originalInf) ;
	}

	// Writerの初期化不成立は試験材料の生成失敗です
	// 一般Netも同じ静的基本INF policyへ渡します
	if( network) {
		inf = replaced( std::move( inf), "Class=Ports", "Class=Net") ;
		inf = replaced( std::move( inf), "4d36e978", "4d36e972") ;
	}

	// 元INFにだけ標準OS装飾を追加し、archive/record hashは変更後の全byteへ結びます
	if( models != 0U) {
		inf = replaced(
			std::move( inf), "%Vendor%=Models,NTamd64\r\n[Models.NTamd64]\r\n",
			models == 2U
				? "%Vendor%=Models,NTamd64.10.0...17134\r\n%Vendor%=Models,NTamd64.10.0...26200\r\n[Models.NTamd64.10.0...17134]\r\n%Device%=Install,TESTBUS\\SYNTH_0001\r\n[Models.NTamd64.10.0...26200]\r\n"
				: "%Vendor%=Models,NTamd64.10.0...17134,NTamd64.10.0...26200\r\n[Models.NTamd64.10.0...17134]\r\n%Device%=Install,TESTBUS\\SYNTH_0001\r\n[Models.NTamd64.10.0...26200]\r\n") ;
	}

	// 新scopeだけを元通常fixtureの同source/関連kernel/Type1/受動BATへ結びます
	if( managed != 0U) {
		inf = replaced( std::move( inf), "CopyFiles=Files\r\n",
					   "CopyFiles=Files,Programs\r\nCopyINF=importonly.inf\r\n") ;
		inf +=
			"; windows-managed-scope-fixture\r\n"
			"[Install.Services]\r\nAddService=FixtureKernel,2,KernelService\r\nAddService=FixtureHelper,0,HelperService\r\n"
			"[KernelService]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=%12%\\fixture.sys\r\n"
			"[HelperService]\r\nServiceType=16\r\nStartType=2\r\nErrorControl=1\r\nServiceBinary=%13%\\fixture.exe --data fixture.bat\r\n"
			"[DestinationDirs]\r\nPrograms=13\r\n[Programs]\r\nfixture.exe\r\nfixture.bat\r\n"
			"[SourceDisksFiles]\r\nfixture.exe=1\r\nfixture.bat=1\r\n"
			"[Install.Software]\r\nAddSoftware=RelatedDeviceHelper,0,RelatedSoftware\r\n"
			"[RelatedSoftware]\r\nSoftwareType=1\r\nSoftwareBinary=%13%\\fixture.exe\r\nSoftwareVersion=1.0.0.0\r\n"
			"SoftwareArguments=--device <<DeviceInstanceID>>, --driver\r\n"
			"[Install.HW]\r\nAddReg=PassiveReg\r\n"
			"[PassiveReg]\r\nHKR,,Opaque,0x00010000" ;
		// 選択registryの324 fieldsを全値解析へ流用せず、先頭metadataだけを確認します
		for( unsigned field = 0U; field < 320U; ++field) {
			inf += ",\"opaque\"" ;
		}

		inf += "\r\n" ;
		// scope負例は元INF/ZIP/署名indexを新しい原byteへ固定し、後からDTOを書換えません
		if( managed >= 2U) {
			inf += "; scope-fixture-reject\r\n" ;
		}

		// 外部directoryコピーを通常driver用DATAへ読み替えません
		if( managed == 2U) {
			inf = replaced( std::move( inf), "Programs=13", "Programs=16422") ;
		}

		// 同元EXEでもdevice文脈を失う独立app宣言を負例にします
		if( managed == 3U) {
			inf = replaced( std::move( inf), "--device <<DeviceInstanceID>>",
						   "--standalone-application") ;
		}

		// 独立MSIは実行せず、同元コピーがあっても本Windows-only scopeでは追加しません
		if( managed == 4U) {
			inf = replaced( std::move( inf), "[Programs]\r\nfixture.exe",
						   "[Programs]\r\nfixture.exe\r\nfixture.msi") ;
			inf = replaced( std::move( inf), "fixture.exe=1", "fixture.exe=1\r\nfixture.msi=1") ;
			inf = replaced( std::move( inf), "SoftwareBinary=%13%\\fixture.exe",
						   "SoftwareBinary=%13%\\fixture.msi") ;
		}

		// 選択DDInstall/関連service/softwareの自動起動登録を同元signed-index経路で拒否します
		if( managed >= 5U && managed <= 7U) {
			const std::string anchor = managed == 5U   ? "CopyFiles=Files,Programs"
									   : managed == 6U ? "[HelperService]"
													   : "[RelatedSoftware]" ;	// 各正式到達文脈です
			inf = replaced( std::move( inf), anchor, anchor + "\r\nAddReg=AutorunReg") ;
			inf += "[AutorunReg]\r\nHKLM,\"Software\\Microsoft\\Windows\\CurrentVersion\\" ;
			inf += managed == 6U ? "RunOnce" : "Run" ;
			inf += "\",Fixture,0,\"foreign.exe\"\r\n" ;
		}
	}

	// ZIP生成開始失敗を非空正常fixtureへ換算しません
	if( infBytes != nullptr) {
		*infBytes = inf ;
	}

	// 要求された同原INF byteを返し、別文字列からhashを推測しません
	if( !mz_zip_writer_init_heap( &archive, 0U, 0U)) {
		throw std::runtime_error( "worker ZIP initialization failed") ;
	}

	const std::string sys =
		"fictional nonexecuting system driver bytes" ;				// 実driver binaryではありません
	const std::string cat = "fictional unsigned catalog bytes" ;	// Windows署名合格を偽装しません
	// 一基本driverと同元stage内容だけの小fixtureです。別deviceを導入しません
	if( managed != 0U) {
		// 同元CopyINFで全内容だけをstageする独立deviceの人工INFです
		constexpr std::string_view IMPORT =
			"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=SoftwareDevice\r\n"
			"ClassGuid={62f9c741-b25a-46ce-b54c-9bccce08b6f2}\r\nProvider=Fixture Vendor\r\n"
			"DriverVer=10/11/2026,1.0.0.0\r\nCatalogFile=importonly.cat\r\n"
			"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
			"Device=Import,TESTBUS\\SYNTH_IMPORT_ONLY\r\n[Import]\r\nCopyFiles=Files\r\n"
			"[Files]\r\nimportonly.sys\r\n[DestinationDirs]\r\nFiles=12\r\n"
			"[SourceDisksNames]\r\n1=fixture\r\n[SourceDisksFiles]\r\nimportonly.sys=1\r\n" ;
		constexpr std::string_view DATA =
			"opaque fixture data; never executed" ;	// 実programではありません
		const std::array names{"fixture.exe", "fixture.bat", "importonly.inf", "importonly.sys",
							   "importonly.cat"} ;	// 全原参照です
		const std::array<std::string_view, 5U> bodies{DATA, DATA, IMPORT, sys,
													  cat} ;	// 原byteを完全期待hashへ結びます
		// 全新memberを既存ZIP writerへ有限追加します
		for( std::size_t index = 0U; index < names.size(); ++index) {
			// 原writer失敗を部分材料の正常化で隠しません
			if( !mz_zip_writer_add_mem( &archive, names[index], bodies[index].data(),
									  bodies[index].size(), MZ_NO_COMPRESSION)) {
				mz_zip_writer_end( &archive) ;
				throw std::runtime_error( "managed scope fixture ZIP members") ;
			}
		}

		// MSI負例も元sourceが実在する条件だけを使用します
		if( managed == 4U && !mz_zip_writer_add_mem( &archive, "fixture.msi", DATA.data(),
												   DATA.size(), MZ_NO_COMPRESSION)) {
			mz_zip_writer_end( &archive) ;
			throw std::runtime_error( "managed scope MSI fixture") ;
		}
	}

	// 三つの原memberを全て追加できた場合だけ非空ZIPを完成させます
	if( includeFlat && (!mz_zip_writer_add_mem( &archive, "fixture.inf", inf.data(), inf.size(),
											  MZ_NO_COMPRESSION) ||
					   !mz_zip_writer_add_mem( &archive, "fixture.sys", sys.data(), sys.size(),
											  MZ_NO_COMPRESSION) ||
					   !mz_zip_writer_add_mem( &archive, "fixture.cat", cat.data(), cat.size(),
											  MZ_NO_COMPRESSION))) {
		mz_zip_writer_end( &archive) ;
		throw std::runtime_error( "worker ZIP members failed") ;
	}

	// 各innerは同じ完全原INF閉包を持ち、member名だけを変えた取り違え回帰です
	for( const auto member : nestedMembers) {
		const auto inner = normalWorkerDriverZip( network) ;	// 子呼出しはnestedなしのflat一段です
		// 明示flatだけをouterへ加え、nested-onlyにflatを混入させません
		if( !mz_zip_writer_add_mem( &archive, std::string{member}.c_str(), inner.data(), inner.size(),
								  MZ_NO_COMPRESSION)) {
			mz_zip_writer_end( &archive) ;
			throw std::runtime_error( "worker nested ZIP failed") ;
		}
	}

	void	   *memory{} ;	// Finalizeが発行したheap。mz_freeへ返します
	std::size_t bytes{} ;	// 有限fixtureの実原byte長
	// 正規container生成不成立を内容拒否fixtureの合格へ補完しません
	if( !mz_zip_writer_finalize_heap_archive( &archive, &memory, &bytes)) {
		mz_zip_writer_end( &archive) ;
		throw std::runtime_error( "worker ZIP finalization failed") ;
	}

	const std::unique_ptr<void, decltype( &mz_free)> owner{memory, &mz_free} ;	// 原heapのRAII
	mz_zip_writer_end( &archive) ;
	return {static_cast<const char *>( owner.get()), bytes} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 本文と対象付き追加欄を同じ署名と隔離ストアに保存し、通常の端末スキャンへ渡します
 * @param[in,out] context 共通の試験集計です
 * @param[in] key 人工索引の原byteだけを署名するRAM内の鍵です
 */
//------------------------------------------------------------------------------
void testCatalogSupplementConsumer( TestContext &context, const RamKey &key)
{
	std::string catalogInf ;												// 補足レコードが指定する人工ZIP内の原INFです
	const auto	catalogZip = normalWorkerDriverZip( false, &catalogInf) ;	// 既存のPorts用閉包です
	const auto	baseInf =
		// 本文用の別INFです
		replaced( catalogInf, "Fixture Device", "Base fixture device") ;
	const auto baseZip =
		// 本文は別の原配布物です
		normalWorkerDriverZip( false, nullptr, {}, true, 0U, 0U, baseInf) ;
	// 各レコードは実際の配布物とそのINFの原byteに結びます
	const auto record = [&]( std::string_view id, std::string_view source, std::string_view zip,
							std::string_view inf) {
		auto row =
			descriptorRecord( descriptorFixture(), distributionRecord( id, true, "CONTENT_INSPECTED",
																	 source)) ;	// 一件の人工原行です
		const auto hash = recordDigest( key, zip) ;								// 発行側計算・公表の両申告に同じ原byteを使います
		row				= replaced( std::move( row), RECORD_CLAIM_HASH, hash) ;
		row				= replaced( std::move( row), RECORD_CLAIM_HASH, hash) ;
		row				= replaced( std::move( row), "\"valueBytes\":1234",
								   "\"valueBytes\":" + std::to_string( zip.size())) ;
		row				= replaced( std::move( row), "drivers/fixture.inf", "fixture.inf") ;
		row				= replaced( std::move( row), "{11111111-2222-3333-4444-555555555555}",
								   "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
		row				= replaced( std::move( row), "Fixture.NTamd64", "Models.NTamd64") ;
		return replaced( std::move( row),
						"fixture.inf\",\"evidenceSha256\":\"" + std::string{RECORD_EVIDENCE_HASH},
						"fixture.inf\",\"evidenceSha256\":\"" + recordDigest( key, inf)) ;
	} ;
	// Catalog側の元レコードと起点の全申告を同じ取得元へ結びます
	const auto atCatalog = []( std::string raw) {
		// 同一原行内にある各URLを一度ずつ同じ架空のCatalog配布へ移します
		while( raw.find( "vendor.example") != raw.npos) {
			raw = replaced( std::move( raw), "vendor.example", "www.catalog.update.microsoft.com") ;
		}

		return raw ;
	} ;
	const auto base =
		// 旧本文の一件です
		record( "fixture-base", "fixture-source", baseZip, baseInf) ;
	auto catalog = atCatalog(
		// 追加欄の対象行です
		record( "fixture-catalog", "catalog-source", catalogZip, catalogInf)) ;
	catalog = replaced( std::move( catalog), "driver-index-record-v2", "driver-index-record-v3") ;
	catalog.pop_back() ;
	catalog +=
		R"json(,"catalogHardwareScope":{"detailsUrl":"https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=11111111-2222-4333-8444-555555555555","detailsSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} +
		R"json(","observedAtUtc":"2026-10-10T02:00:00Z","packageHardwareIds":["testbus\\synth_0001"]}})json" ;
	const auto expiry = NOW + std::chrono::minutes{1} ;	// 追加欄のうち最も短い元期限です
	const auto early =
		replaced( atCatalog( record( "fixture-short", "catalog-source", baseZip, baseInf)),
				 "2026-10-12T03:00:00Z",
				 "2026-10-11T06:01:00Z") ;	// この対象条件のない行だけが追加欄の期限を決めます
	const auto baseIndex =
		// 署名集計は本文一件だけです
		descriptorIndex( recordSource(), recordEntry( key, base)) ;
	const auto supplemental =
		replaced( descriptorIndex( atCatalog( recordSource( "catalog-source")),
								 recordEntry( key, early) + "," + recordEntry( key, catalog)),
				 "driver-index-records-v2",
				 "driver-index-records-supplement-v1") ;	// 非対象行を先頭に置きます
	const auto	gzip = assetWithExtra( assetGzip( baseIndex),
									  assetSupplementFrame( key, baseIndex, assetGzip( supplemental),
														   expiry)) ;	// 同一の認証対象です
	std::string outer ;													// 隔離ストアが再検証する元の署名入りenvelopeです
	const auto	manifest = assetManifest( key, gzip, false, recordQuality( {1U, 1U, 0U, 1U, 0U}),
										 &outer) ;	// RAM鍵による実署名です
	const auto	bytes =
		// 保存前に同じ原転送byteを検査します
		authenticateIndexAssetBytes( manifest, gzip, NOW) ;
	// 元assetの認証が成立しない場合は端末照合へ進みません
	if( !bytes.receipt) {
		throw std::runtime_error( "catalog scan signed asset") ;
	}

	const auto schema = readSignedIndexRecords( *bytes.receipt, NOW) ;	// 本文専用の保存receiptです
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;									// RAM鍵の公開部だけを隔離環境に渡します
	auto opened = signed_index_store_detail::Access::createIsolated( trust) ;	// この試験のストアです
	// 保存前の失敗をスキャンが観測した拒否として数えません
	if( !schema.receipt || !opened.store ||
	   !opened.store->commit( *schema.receipt, outer, gzip, NOW).snapshot) {
		throw std::runtime_error( "catalog scan isolated commit") ;
	}

	const auto reload = opened.store->reload( NOW) ;	// 元envelopeと両欄を含むGZipを再認証します
	DRIVERCRATE_EXPECT(
		context, reload.status == IndexStoreStatus::SNAPSHOT_READY && reload.snapshot &&
					 reload.snapshot->originalEnvelope() == outer &&
					 std::ranges::equal( reload.snapshot->originalGzip(), gzip) &&
					 reload.snapshot->schemaReceipt().records().size() == 1U &&
					 reload.snapshot->schemaReceipt().records().front().originalBytes == base &&
					 reload.snapshot->consumerRecords().size() == 1U) ;
	runCatalogSupplementConsumerScan(
		context, std::shared_ptr<SignedIndexStore>{std::move( opened.store)}, NOW, expiry, baseZip,
		catalogZip, key.digest( baseIndex), key.digest( supplemental)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保存前から実署名・gzip・schema・commit／reloadを通したlookup入力を作ります
 * @param[in] key 既存RAM内秘密鍵。永続保存しません
 * @param[in] record 架空の原record byte
 * @param[in] recordCount 有限batch境界用件数。通常は1です
 * @param[out] storeOut 指定時だけ実reload済み隔離store所有を返します。nullptr可です
 * @param[in] generation 真署名manifestの人工世代。asset世代7は変更しません
 * @param[in] recordRows 非空時は各元recordをそのまま使います。件数はrecordCountへ一致させます
 * @param[in] sourceOverride 非空時だけ人工sourceの全元byteを使います。既定は元vendor source
 * @return Reloadが発行した真のconst snapshotの共有所有
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::shared_ptr<const AuthenticatedIndexSnapshot> lookupSnapshot(
	const RamKey &key, const std::string_view record, const std::size_t recordCount = 1U,
	std::shared_ptr<SignedIndexStore> *const storeOut = nullptr,
	const std::uint64_t generation = 9U, const std::span<const std::string> recordRows = {},
	const std::string_view sourceOverride = {})
{
	std::string	  entries ;			// 有限batch試験の原entry群
	std::uint64_t metadataCount{} ;	// 原fixture行の段階だけを数えます
	std::uint64_t contentCount{} ;	// 内容検査申告をmetadataへ戻しません
	// 別record集合の件数不一致を暗黙に切り捨てません
	if( !recordRows.empty() && recordRows.size() != recordCount) {
		throw std::runtime_error( "lookup exact record count failed") ;
	}

	// 指定した架空record件数だけ一意identityを生成し、全件で終了する
	for( std::size_t recordIndex = 0U; recordIndex < recordCount; ++recordIndex) {
		// 後続entryだけにcommaを追加する
		if( recordIndex != 0U) {
			entries += "," ;
		}

		const auto raw = !recordRows.empty() ? recordRows[recordIndex]
						 : recordIndex == 0U
							 ? std::string{record}
							 : replaced( std::string{record}, "\"recordId\":\"metadata\"",
										"\"recordId\":\"batch-" + std::to_string( recordIndex) +
											"\"") ;	// 原recordを一意化
		entries += recordEntry( key, raw) ;
		metadataCount += raw.find( "\"inspectionStage\":\"METADATA_ONLY\"") != std::string::npos ;
		contentCount += raw.find( "\"inspectionStage\":\"CONTENT_INSPECTED\"") != std::string::npos ;
	}

	const auto source =
		// 明示sourceだけ使用
		sourceOverride.empty() ? recordSource() : std::string{sourceOverride} ;
	const auto index = record.find( "driver-index-record-v2") == std::string_view::npos
						   ? distributionIndex( source, entries)
						   : descriptorIndex( source, entries) ;	// Wire版ごとの原index
	auto	   inputs =
		makeStoreInputs( key, index, generation, 7U, NOW, "2026-10-11T05:00:00Z",
						"2026-10-25T05:00:00Z", (index.size() + 127U) / 128U,
						{1U, static_cast<std::uint64_t>( recordCount), metadataCount, contentCount,
						 static_cast<std::uint64_t>( recordCount) - metadataCount -
							 contentCount}) ;	// 原行と一致する段階別quality
	const auto bytes =
		// 実gzip検査
		authenticateIndexAssetBytes( inputs.manifest, inputs.gzip, NOW) ;
	// Test入力生成の不成立を拒否試験の成功にしない
	if( !bytes.receipt) {
		throw std::runtime_error( "lookup gzip fixture failed") ;
	}

	const auto records = readSignedIndexRecords( *bytes.receipt, NOW) ;	// 実schema読取り
	// 元recordを検査していないsnapshotは作れない
	if( !records.receipt) {
		throw std::runtime_error( "lookup record fixture failed") ;
	}

	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{"fixture-main", key.publicBlob}}} ;									// Test public trustだけを隔離rootへ渡す
	auto opened = signed_index_store_detail::Access::createIsolated( trust) ;	// 実保護root
	// Storeの生成失敗をfixture successへ変換しない
	if( !opened.store) {
		throw std::runtime_error( "lookup isolated store failed") ;
	}

	const auto committed =
		// 実commit
		opened.store->commit( *records.receipt, inputs.envelope, inputs.gzip, NOW) ;
	// 原子保存なしのschema receiptをlookup入力に使わない
	if( !committed.snapshot) {
		throw std::runtime_error( "lookup commit failed") ;
	}

	auto loaded = opened.store->reload( NOW) ;	// 保存原byteから再認証する
	// Reload成功からだけconst所有snapshotを発行する
	if( !loaded.snapshot) {
		throw std::runtime_error( "lookup reload failed") ;
	}

	// 内部worker fixtureだけが同じ実storeの再認証を継続します
	if( storeOut != nullptr) {
		*storeOut = std::shared_ptr<SignedIndexStore>{std::move( opened.store)} ;
	}

	return std::make_shared<const AuthenticatedIndexSnapshot>( std::move( *loaded.snapshot)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 独立した三markerのraw材料を既fixtureへ結び、通常認証前の申告を作ります
 * @param[in] base 同意不要又は明示termsを持つ元人工v2 recordです
 * @param[in] release exact版のliteralです
 * @param[in] product 2又は3のliteralです
 * @param[in] fault 一つだけ壊す固定IDです。空は正常です
 * @return 新scope helperを使わない元JSONです。client不一致負例は元baseを保持し、署名と成功能力は含みません
 */
//------------------------------------------------------------------------------
std::string serverHostRaw( std::string base, const std::string_view release,
						  const std::string_view product, const std::string_view fault = {})
{
	// 正常client recordとのOS不一致だけを試し、Server条件という二つ目のfaultを加えません
	if( fault == "SERVER3_HOST_CLIENT_RECORD_SAME26100") {
		return base ;
	}

	const std::array descriptions{
		"DriverCrate:target-os=" + std::string{release},
		"DriverCrate:target-product-type=" + std::string{product},
		std::string{"DriverCrate:models-observed-suite=0"}} ;	// 独立wire literalです
	std::vector<std::string> items ;							// 条件だけを独立に故障させます
	// 各条件の出典は同じ原PUBLISHED/INFだけです
	for( std::size_t index = 0U; index < descriptions.size(); ++index) {
		// 当該必須markerだけの欠落を作ります
		if( (fault == "MISSING_RELEASE" && index == 0U) ||
		   (fault == "MISSING_PRODUCT" && index == 1U) ||
		   (fault == "MISSING_SUITE" && index == 2U)) {
			continue ;
		}

		auto description = descriptions[index] ;	// 原条件literalです
		// generic/未知版をexactへ広げません
		if( index == 0U && fault == "GENERIC_RELEASE_MARKER") {
			description = "DriverCrate:target-os=WINDOWS_SERVER" ;
		}

		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		if( index == 0U && fault == "UNKNOWN_RELEASE_MARKER") {
			description = "DriverCrate:target-os=WINDOWS_SERVER_2040" ;
		}

		const auto url	= index == 0U && fault == "OTHER_INF_URL"
							  ? "https://vendor.example/other.inf"
							  : "https://vendor.example/fixture.inf" ;	// 同hash別URL負例です
		const auto hash = index == 0U && fault == "OTHER_INF_HASH"
							  ? std::string( 64U, 'b')
							  : std::string{RECORD_EVIDENCE_HASH} ;	// 同URL別hash負例です
		const auto item = "{\"kind\":\"LOCAL_CHECK\",\"description\":\"" + description +
						  "\",\"evidenceUrl\":\"" + url + "\",\"evidenceSha256\":\"" + hash +
						  "\"}" ;	// 完全な独立rawです
		items.push_back( item) ;
		// 同じ値でも二回あれば拒否する入力です
		if( (fault == "DUPLICATE_RELEASE" && index == 0U) ||
		   (fault == "DUPLICATE_PRODUCT" && index == 1U) ||
		   (fault == "DUPLICATE_SUITE" && index == 2U)) {
			items.push_back( item) ;
		}
	}

	// 未登録LOCAL又は分離不能firmwareを同意で通しません
	if( fault == "EXTRA_LOCAL" || fault == "INSEPARABLE_FIRMWARE") {
		items.push_back(
			"{\"kind\":\"" +
			std::string{fault == "EXTRA_LOCAL" ? "LOCAL_CHECK" : "INSEPARABLE_FIRMWARE"} +
			"\",\"description\":\"Future condition\",\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
			std::string{RECORD_EVIDENCE_HASH} + "\"}") ;
	}

	std::string conditions ;	// 元順序を保持します
	// 固定件数だけをJSON配列へ結びます
	for( const auto &item : items) {
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		if( !conditions.empty()) {
			conditions += "," ;
		}

		conditions += item ;
	}

	const std::string empty =
		"\"prerequisites\":{\"state\":\"KNOWN\",\"reason\":\"\",\"items\":[]}" ;	// 元fixtureのliteralです
	base = replaced( std::move( base), empty,
					"\"prerequisites\":{\"state\":\"KNOWN\",\"reason\":\"\",\"items\":[" +
						conditions + "]}") ;
	base = replaced( std::move( base), "\"value\":\"WINDOWS_11\"", "\"value\":\"WINDOWS_SERVER\"") ;

	// UNKNOWN/generic旧rawは空条件のままで新marker成功へ補完しません
	if( fault == "UNKNOWN_PREREQUISITES" || fault == "LEGACY_ENUM_GENERIC_SERVER") {
		base = replaced(
			std::move( base),
			"\"prerequisites\":{\"state\":\"KNOWN\",\"reason\":\"\",\"items\":[" + conditions +
				"]}",
			fault == "UNKNOWN_PREREQUISITES"
				? "\"prerequisites\":{\"state\":\"UNKNOWN\",\"reason\":\"not supplied\",\"items\":[]}"
				: empty) ;
	}

	// 方式と容器を独立に保った既codec正常installerです
	if( fault == "SERVER_INSTALLER") {
		base = replaced( std::move( base), "STANDARD_INF_ARCHIVE", "OFFICIAL_INSTALLER") ;
		base = replaced( std::move( base), "\"format\":\"ZIP\"", "\"format\":\"WINDOWS_EXE\"") ;
	}

	return base ;
}

//------------------------------------------------------------------------------
/**
 * @brief 16正常scopeと31拒否、context/actionの独立raw入力を再署名して接続します
 * @param[in,out] context 共通assertion集計先です
 * @param[in] key このtestだけの既RAM鍵です
 * @param[in] base 人工22byte ZIPへ結合した元v2 recordです
 * @note 新observer/helperから期待値や権限を生成しません
 */
//------------------------------------------------------------------------------
void testServerHostIndexRecords( TestContext &context, const RamKey &key, const std::string &base)
{
	const std::array releases{"WINDOWS_SERVER_2016", "WINDOWS_SERVER_2019", "WINDOWS_SERVER_2022",
							  "WINDOWS_SERVER_2025"} ;			// 独立正式literalです
	const std::array builds{14393U, 17763U, 20348U, 26100U} ;	// UBRや範囲ではありません
	// 非0suiteも未検査取得まで進め、適合成功へ計上しません
	for( std::size_t index = 0U; index < releases.size(); ++index) {
		// product2/3を互いにunionしません
		for( const auto product : std::array<std::uint8_t, 2U>{2U, 3U}) {
			// 原suite0観測markerをhost必須0へ読み替えません
			for( const auto suite : std::array<std::uint16_t, 2U>{0U, 256U}) {
				const auto id = "SERVER_" + std::string{releases[index] + 15U} + "_P" +
								std::to_string( product) + "_S" +
								// 全16入力の一意IDです
								std::to_string( suite) ;
				const auto raw = serverHostRaw( base, releases[index],
											   // 署名前の原申告です
											   std::to_string( product)) ;
				runServerHostIndexFixtureCase( context, lookupSnapshot( key, raw), NOW, id,
											  {10U, 0U, builds[index], 9U, product, suite},
											  IndexHostGateState::ALLOW_UNVERIFIED, true, false) ;
			}
		}
	}

	const std::array<std::string_view, 31U> refusals{
		"CLIENT1_HOST_SERVER3_RECORD_SAME26100",
		"SERVER3_HOST_CLIENT_RECORD_SAME26100",
		"HOST2_RECORD3",
		"HOST3_RECORD2",
		"HOST2016_RECORD2025",
		"HOST2019_RECORD2025",
		"HOST2022_RECORD2025",
		"MISSING_RELEASE",
		"MISSING_PRODUCT",
		"MISSING_SUITE",
		"DUPLICATE_RELEASE",
		"DUPLICATE_PRODUCT",
		"DUPLICATE_SUITE",
		"GENERIC_RELEASE_MARKER",
		"UNKNOWN_RELEASE_MARKER",
		"EXTRA_LOCAL",
		"OTHER_INF_URL",
		"OTHER_INF_HASH",
		"SERVER_INSTALLER",
		"BUILD0",
		"PRODUCT0",
		"ARCH_UNKNOWN",
		"UNSUPPORTED_SERVER_BUILD22000",
		"UNSUPPORTED_ARM64",
		"UNSUPPORTED_X86",
		"UNSUPPORTED_PRODUCT4",
		"UNSUPPORTED_VERSION6_1",
		"INSEPARABLE_FIRMWARE",
		"UNKNOWN_PREREQUISITES",
		"LEGACY_ENUM_SERVER_WITH_MARKERS",
		"LEGACY_ENUM_GENERIC_SERVER"} ;	// 元31を省略しません
	// 一case一つの独立故障だけを認証前に与えます
	for( const auto id : refusals) {
		WindowsHostPlatform host{10U, 0U, 26100U, 9U, 3U, 256U} ;	// 元正常host literalです
		IndexHostGateState	expected =
			IndexHostGateState::ALLOW_UNVERIFIED ;	// record拒否と初回観測拒否を分けます
		// 同buildでもclient/server/productを取り違えません
		if( id == "CLIENT1_HOST_SERVER3_RECORD_SAME26100") {
			host.productType = 1U ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "HOST2_RECORD3") {
			host.productType = 2U ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "HOST2016_RECORD2025") {
			host.buildNumber = 14393U ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "HOST2019_RECORD2025") {
			host.buildNumber = 17763U ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "HOST2022_RECORD2025") {
			host.buildNumber = 20348U ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "BUILD0") {
			host.buildNumber = 0U ;
			expected		 = IndexHostGateState::UNKNOWN ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "PRODUCT0") {
			host.productType = 0U ;
			expected		 = IndexHostGateState::UNKNOWN ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "ARCH_UNKNOWN") {
			host.nativeArchitecture = 0xFFFFU ;
			expected				= IndexHostGateState::UNKNOWN ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "UNSUPPORTED_SERVER_BUILD22000") {
			host.buildNumber = 22000U ;
			expected		 = IndexHostGateState::UNSUPPORTED ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "UNSUPPORTED_ARM64") {
			host.nativeArchitecture = 12U ;
			expected				= IndexHostGateState::UNSUPPORTED ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "UNSUPPORTED_X86") {
			host.nativeArchitecture = 0U ;
			expected				= IndexHostGateState::UNSUPPORTED ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "UNSUPPORTED_PRODUCT4") {
			host.productType = 4U ;
			expected		 = IndexHostGateState::UNSUPPORTED ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( id == "UNSUPPORTED_VERSION6_1") {
			host.majorVersion = 6U ;
			host.minorVersion = 1U ;
			expected		  = IndexHostGateState::UNSUPPORTED ;
		}

		const auto raw =
			serverHostRaw( base, "WINDOWS_SERVER_2025", id == "HOST3_RECORD2" ? "2" : "3",
						  id) ;								// 他product policyを借りません
		const auto snapshot = lookupSnapshot( key, raw) ;	// 同じ既署名builderで通常認証します
		// 元正常client/空条件を独立literalへ照合し、拒否原因をOS不一致だけにします
		if( id == "SERVER3_HOST_CLIENT_RECORD_SAME26100") {
			DRIVERCRATE_EXPECT(
				context,
				raw == base &&
					raw.find(
						"\"targetOs\":{\"state\":\"KNOWN\",\"value\":\"WINDOWS_11\",\"reason\":\"\"}") !=
						raw.npos &&
					raw.find(
						"\"prerequisites\":{\"state\":\"KNOWN\",\"reason\":\"\",\"items\":[]}") !=
						raw.npos &&
					raw.find( "\"kind\":\"LOCAL_CHECK\"") == raw.npos) ;
			const WindowsHostPlatform expectedHost{10U, 0U, 26100U,
												   9U,	3U, 256U} ;	// 元Server hostだけが不一致です
			DRIVERCRATE_EXPECT( context, host == expectedHost && snapshot &&
											snapshot->schemaReceipt().records().size() == 1U) ;
			// 前提不成立を元負例の合格へ変換せず、同じ正規recordの型付き条件も確認します
			if( snapshot && snapshot->schemaReceipt().records().size() == 1U) {
				const auto &record =
					// 原byteを保持した実codec結果です
					snapshot->schemaReceipt().records().front() ;
				DRIVERCRATE_EXPECT( context,
								   record.originalBytes == base &&
									   record.targetOs.value == IndexTargetOs::WINDOWS_11 &&
									   record.architecture.value == IndexArchitecture::X64 &&
									   record.driverKind.value == IndexDriverKind::NORMAL_DRIVER &&
									   record.acquisition.value ==
										   IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
									   record.acquisitionDescriptor) ;
				// 元取得条件を新scope helperで作り直さず、正常clientのliteral期待へ照合します
				if( record.acquisitionDescriptor) {
					const auto &descriptor =
						*record.acquisitionDescriptor ;	// 元rawと署名へ結ぶ同一descriptorです
					DRIVERCRATE_EXPECT( context, descriptor.state == IndexDescriptorState::KNOWN &&
													descriptor.format == IndexPayloadFormat::ZIP &&
													descriptor.terms.state ==
														IndexTermsState::CONFIRMED_NO_CONSENT &&
													descriptor.prerequisites.state ==
														IndexDescriptorState::KNOWN &&
													descriptor.prerequisites.items.empty()) ;
				}
			}
		}

		runServerHostIndexFixtureCase( context, snapshot, NOW, id, host, expected, false,
									  id.starts_with( "LEGACY_ENUM_")) ;
	}

	const std::array<std::string_view, 19U> actions{
		"WRONG_OPERATION",
		"WRONG_SCAN",
		"WRONG_INVENTORY",
		"CHANGED_RECORD_HASH",
		"EXPIRED_ISSUER_OR_RECORD",
		"CHANGED_MAJOR",
		"CHANGED_MINOR",
		"CHANGED_BUILD",
		"CHANGED_ARCH",
		"CHANGED_PRODUCT",
		"CHANGED_ACTUAL_SUITE",
		"FRESH_WIN32_FAILURE",
		"FRESH_NTSTATUS_FAILURE",
		"UNCHANGED_NONZERO_SUITE",
		"OLD_CLIENT10",
		"OLD_CLIENT11",
		"STALE_CONTEXT_CANNOT_REAUTHORIZE_AFTER_MATCHING_OBSERVATION",
		"UNKNOWN_CONTEXT_CANNOT_REAUTHORIZE_AFTER_MATCHING_OBSERVATION",
		"SAME_CONTEXT_INITIAL_SNAPSHOT_REPLACEMENT_REJECTED"} ;	// 他5入口はterms一・download/retained二・dispatch二です
	// 原context、原期限、初回値と再観測の違いを固定します
	for( const auto id : actions) {
		const bool client = id == "OLD_CLIENT10" ||
							// 既client経路もfullhost正例として残します
							id == "OLD_CLIENT11" ;
		auto raw =
			client ? base
				   : serverHostRaw( base, "WINDOWS_SERVER_2025", "3") ;	// 元raw材料から独立生成します
		// 旧Win10 recordだけ宣言literalを変更して再署名します
		if( id == "OLD_CLIENT10") {
			raw = replaced( std::move( raw), "WINDOWS_11", "WINDOWS_10") ;
		}

		runServerHostIndexFixtureCase( context, lookupSnapshot( key, raw), NOW, id,
									  {10U, 0U, id == "OLD_CLIENT10" ? 19045U : 26100U, 9U,
									   static_cast<std::uint8_t>( client ? 1U : 3U), 256U},
									  IndexHostGateState::ALLOW_UNVERIFIED, true, false) ;
	}

	const auto termsBase = descriptorRecord( replaced(
		descriptorFixture( false, true),
		"\"items\":[{\"kind\":\"LOCAL_CHECK\",\"description\":\"Check a specific prerequisite\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
			std::string{RECORD_EVIDENCE_HASH} + "\"}]",
		"\"items\":[]")) ;	// 元rich termsだけを保持します
	const auto termsRaw =
		// HTTP前の変化だけを試します
		serverHostRaw( termsBase, "WINDOWS_SERVER_2025", "3") ;
	runServerHostIndexFixtureCase( context, lookupSnapshot( key, termsRaw), NOW,
								  "TERMS_HOST_CHANGE_BEFORE_GET", {10U, 0U, 26100U, 9U, 3U, 256U},
								  IndexHostGateState::ALLOW_UNVERIFIED, true, false) ;
	// 四つの実scan入口も原byteを再認証してからだけ渡します
	for( const std::string_view id :
		{"DOWNLOADED_SERVER_P4_PENDING", "RETAINED_SERVER_P4_PENDING",
		 "HOST_CHANGE_AFTER_CLAIM_BEFORE_DISPATCH", "OBSERVER_FAILURE_BEFORE_DISPATCH"}) {
		const auto raw =
			// 同一の人工22byte payloadです
			serverHostRaw( base, "WINDOWS_SERVER_2025", "3") ;
		std::vector<std::string> rows{raw} ;	// download一又はretained二recordだけです
		// 取得policyは同一で原時刻窓だけ異なる別recordです。借用適合を作りません
		if( id == "RETAINED_SERVER_P4_PENDING") {
			auto second = replaced( raw, "\"recordId\":\"metadata\"",
								   "\"recordId\":\"metadata-retained\"") ;	// 別原recordです
			second		= replaced( std::move( second), "\"checkedAtUtc\":\"2026-10-10T03:00:00Z\"",
								   "\"checkedAtUtc\":\"2026-10-10T04:00:00Z\"") ;
			rows.push_back( std::move( second)) ;
		}

		std::shared_ptr<SignedIndexStore> store ;	// 自作隔離rootだけを保持します
		static_cast<void>( lookupSnapshot( key, raw, rows.size(), &store, 9U, rows)) ;
		runServerHostScanFixtureCase( context, std::move( store), NOW, id) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元正常containerからP4の型付きIDを持つ人工ZIPを作ります
 * @param[out] infBytes 同ZIPの原INF全byteです
 * @param[in] missingSys trueでは参照SYSだけをcontainerから除きます
 * @param[in] ambiguousModels trueでは同じIDを持つ同じbaseの標準AMD64二節を別Manufacturer行で参照します
 * @return CRCを含めMinizで新規作成した全archiveです
 * @note 元client fixtureのbyteやhelper既定値を変更しません
 */
//------------------------------------------------------------------------------
std::string serverP4DriverZip( std::string &infBytes, const bool missingSys,
							  const bool ambiguousModels)
{
	static_cast<void>( normalWorkerDriverZip( false, &infBytes)) ;
	infBytes = replaced( std::move( infBytes), "%Device%=Install,TESTBUS\\SYNTH_0001\r\n",
						"%Device%=Install,TESTBUS\\SYNTH_0001,TESTBUS\\P4_COMPAT_0001\r\n") ;
	infBytes +=
		"[Models.Other]\r\n%Device%=Install,TESTBUS\\SYNTH_0001,TESTBUS\\P4_COMPAT_0001\r\n" ;
	// 同じ署名済みINFで実際に二節が選択される入力だけを曖昧判定に渡します
	if( ambiguousModels) {
		infBytes = replaced( std::move( infBytes), "%Vendor%=Models,NTamd64\r\n",
							"%Vendor%=Models,NTamd64\r\nFixtureAlternate=Models,NTamd64.10.0\r\n") ;
		infBytes = replaced( std::move( infBytes), "[Models.Other]", "[Models.NTamd64.10.0]") ;
	}

	const std::array names{"fixture.inf", "fixture.sys", "fixture.cat"} ;	// 固定三memberです
	const std::array<std::string_view, 3U> bodies{
		infBytes, "fictional nonexecuting system driver bytes",
		"fictional unsigned catalog bytes"} ;	// 全原byteです
	mz_zip_archive archive{} ;					// 同threadのRAM writerです
	// RAM writer生成失敗を正常fixtureへ読み替えません
	if( !mz_zip_writer_init_heap( &archive, 0U, 0U)) {
		throw std::runtime_error( "P4 archive initialization") ;
	}

	// 原三memberだけをCRC付きwriterへ渡します
	for( std::size_t index = 0U; index < names.size(); ++index) {
		// SYS以外の内容を壊さない一faultです
		if( index == 1U && missingSys) {
			continue ;
		}

		// 一member書込み失敗なら原writerを閉じて材料失敗にします
		if( !mz_zip_writer_add_mem( &archive, names[index], bodies[index].data(),
								  bodies[index].size(), MZ_NO_COMPRESSION)) {
			mz_zip_writer_end( &archive) ;
			throw std::runtime_error( "P4 archive member") ;
		}
	}

	void	   *memory{} ;	// Minizが発行する一時bufferです
	std::size_t bytes{} ;	// 全container原byte長です
	// 全container確定失敗を部分fixtureの成功にしません
	if( !mz_zip_writer_finalize_heap_archive( &archive, &memory, &bytes)) {
		mz_zip_writer_end( &archive) ;
		throw std::runtime_error( "P4 archive finalization") ;
	}

	const std::string result{static_cast<const char *>( memory), bytes} ;	// 原byteを所有します
	mz_free( memory) ;
	mz_zip_writer_end( &archive) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 独立raw/hash/条件をRAM署名し、P4の全有限入力へ接続します
 * @param[in,out] context 共通assertionです
 * @param[in] key 元testだけのRAM署名鍵です
 * @note 予定件数を実到達へ換算せず、各caseの実counterと元case IDを別に出します
 */
//------------------------------------------------------------------------------
void testServerP4Connections( TestContext &context, const RamKey &key)
{
	runServerP4PureIdentityCases( context) ;
	const auto run = [&]( const std::string_view id, const std::string_view release,
						 const std::string_view product, const WindowsHostPlatform host) {
		const bool client =
			// 旧条件を保持します
			id == "P4_C20_OLD_CLIENT10" || id == "P4_C21_OLD_CLIENT11" ;
		const bool	ambiguousModels = id == "P4_C12_SHARED_AMBIGUOUS_RECORDS" ;	// 同一INFの二節です
		std::string inf ;														// 新helperから期待を生成せず原byteのhashだけを得ます
		const auto	zip = client ? normalWorkerDriverZip( false, &inf)
								 : serverP4DriverZip( inf,
													 // 一faultだけの実containerです
													 id == "P4_C07_MISSING_SYS", ambiguousModels) ;
		auto raw = descriptorRecord( descriptorFixture()) ;	// 原client schema/field順を維持します
		// 別Modelsの同一候補への結合は、双方の内容検査済み証拠を要求します
		if( ambiguousModels) {
			raw = replaced( std::move( raw), "\"inspectionStage\":\"METADATA_ONLY\"",
						   "\"inspectionStage\":\"CONTENT_INSPECTED\"") ;
		}

		const auto outerHash = recordDigest( key, zip) ;	// 本来別の二outer claimを同原byteへ結びます
		raw					 = replaced( std::move( raw), RECORD_CLAIM_HASH, outerHash) ;
		raw					 = replaced( std::move( raw), RECORD_CLAIM_HASH, outerHash) ;
		raw					 = replaced( std::move( raw), "\"valueBytes\":1234",
										"\"valueBytes\":" + std::to_string( zip.size())) ;
		raw					 = replaced( std::move( raw), "drivers/fixture.inf", "fixture.inf") ;
		raw					 = replaced( std::move( raw), "{11111111-2222-3333-4444-555555555555}",
						id == "P4_C04_CLASS_PIPELINE" ? "{4d36e972-e325-11ce-bfc1-08002be10318}"
																	  : "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
		raw					 = replaced( std::move( raw), "Fixture.NTamd64",
						id == "P4_C01_WRONG_MODELS_PIPELINE" ? "Models.Other" : "Models.NTamd64") ;
		// 新Server fixtureだけへ全typed IDの原申告を固定します
		if( !client) {
			raw = replaced(
				std::move( raw),
				R"json("pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
				R"json("pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},{"kind":"COMPATIBLE","value":"TESTBUS\\P4_COMPAT_0001"}])json") ;
			// 元一IDのkindだけを実INFから異なる申告へ変えます
			if( id == "P4_C02_WRONG_TYPED_KIND_PIPELINE") {
				raw = replaced( std::move( raw),
							   R"json({"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"})json",
							   R"json({"kind":"COMPATIBLE","value":"TESTBUS\\SYNTH_0001"})json") ;
			}

			// 追加ID一件だけを宣言し部分集合の救済を拒否させます
			if( id == "P4_C03_EXTRA_ID_PIPELINE") {
				raw = replaced(
					std::move( raw), R"json("value":"TESTBUS\\P4_COMPAT_0001"}])json",
					R"json("value":"TESTBUS\\P4_COMPAT_0001"},{"kind":"HARDWARE","value":"TESTBUS\\P4_EXTRA_0001"}])json") ;
			}

			raw = serverHostRaw( std::move( raw), release, product,
								id == "P4_C17_GENERIC_SERVER" ? "MISSING_RELEASE" : "") ;
		}
		// 同buildのclientをServerへしません
		else if( id == "P4_C20_OLD_CLIENT10") {
			raw = replaced( std::move( raw), "WINDOWS_11", "WINDOWS_10") ;
		}

		// 元legacy generic rawは新三条件へ補完しません
		if( id == "P4_C17_GENERIC_SERVER") {
			const auto start = raw.find( "\"prerequisites\":") ;		// 固定自作JSONだけです
			const auto end	 = raw.find( ",\"publisher\":", start) ;	// 元objectの完全境界です
			// 自作raw object境界の欠損を黙って補いません
			if( start == raw.npos || end == raw.npos) {
				throw std::runtime_error( "P4 generic raw fixture boundary") ;
			}

			raw.replace( start, end - start,
						R"json("prerequisites":{"state":"KNOWN","reason":"","items":[]})json") ;
		}

		const auto infHash = id == "P4_C05_INF_HASH_PIPELINE"
								 ? std::string( 64U, 'e')
								 : recordDigest( key, inf) ;	// 実INFと意図した一hash faultです
		const auto anchor =
			"\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
			std::string{RECORD_EVIDENCE_HASH} ;	// LOCAL/INFだけで非LOCALを更新しません
		// 署名する前の原四根拠だけです
		while( raw.find( anchor) != raw.npos) {
			raw = replaced(
				std::move( raw), anchor,
				"\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
					infHash) ;
		}

		// このcaseだけ原attestationを一分後に失効させます
		if( id == "P4_C11_EXPIRED_RECORD") {
			raw = replaced( std::move( raw), "2026-10-12T03:00:00Z", "2026-10-11T06:01:00Z") ;
		}

		std::vector<std::string> rows{raw} ;	// 一つの原family/sourceでrecordを別に保持します
		const bool				 retained =
			id == "P4_C14_RETAINED_NONEMPTY_SUCCESS" || id == "P4_C15_RETAINED_BAD_TARGET_HASH" ||
			id == "P4_C16_RETAINED_TARGET_EXPIRED" || id == "P4_D17_RETAINED_FRESH_FAILURE" ||
			// 独立B windowです
			id == "P4_D18_RETAINED_MODELS_THEN_HOST_CHANGE" ;
		// 元matrixで指定した共有又はretained二recordだけを作ります
		if( retained || ambiguousModels || id == "P4_C13_SHARED_OTHER_PRODUCT") {
			auto second = replaced(
				raw, "\"recordId\":\"metadata\"",
				ambiguousModels ? "\"recordId\":\"metadata-ambiguous\""
								: "\"recordId\":\"metadata-retained\"") ;	// 実distinct recordです
			// 同一INFの別Models節を参照し、同じ節のID違いだけで曖昧性を作りません
			if( ambiguousModels) {
				second = replaced( std::move( second), "\"modelSection\":\"Models.NTamd64\"",
								  "\"modelSection\":\"Models.NTamd64.10.0\"") ;
			}

			// strict shared taskとretained bodyを分ける原時刻差です
			if( retained) {
				second = replaced( std::move( second), "\"checkedAtUtc\":\"2026-10-10T03:00:00Z\"",
								  "\"checkedAtUtc\":\"2026-10-10T04:00:00Z\"") ;
			}

			// 同payloadでもproduct2のscopeを借りません
			if( id == "P4_C13_SHARED_OTHER_PRODUCT") {
				second =
					replaced( std::move( second), "target-product-type=3", "target-product-type=2") ;
			}

			// Bだけ短い原expiryを署名します
			if( id == "P4_C16_RETAINED_TARGET_EXPIRED") {
				second =
					replaced( std::move( second), "2026-10-12T03:00:00Z", "2026-10-11T06:01:00Z") ;
			}

			rows.push_back( std::move( second)) ;
		}

		std::shared_ptr<SignedIndexStore> store ;	// 真CNG/hash/codec/保存/reloadを通します
		const auto						  authenticated =
			// 成功DTOの直接構築をしません
			lookupSnapshot( key, raw, rows.size(), &store, 9U, rows) ;
		DRIVERCRATE_EXPECT( context, authenticated && store &&
										authenticated->schemaReceipt().sources().size() == 1U) ;
		runServerP4PipelineCase( context, std::move( store), NOW, zip, id, host) ;
	} ;
	const std::array releases{"WINDOWS_SERVER_2016", "WINDOWS_SERVER_2019", "WINDOWS_SERVER_2022",
							  "WINDOWS_SERVER_2025"} ;			// 独立版literalです
	const std::array builds{14393U, 17763U, 20348U, 26100U} ;	// UBRを使いません
	// 四つのexact版を独立containerへ結びます
	for( std::size_t index = 0U; index < releases.size(); ++index) {
		// DCとServerを別record/host入力で確認します
		for( const auto product : std::array<std::uint8_t, 2U>{2U, 3U}) {
			// 観測suite0と実host非0を別々の入力へ固定します
			for( const auto suite : std::array<std::uint16_t, 2U>{0U, 256U}) {
				const auto id = "P4_A_SERVER" + std::string{releases[index] + 15U} + "_P" +
								std::to_string( product) + "_S" +
								// 全16 scopeのIDです
								std::to_string( suite) ;
				run( id, releases[index], std::to_string( product),
					{10U, 0U, builds[index], 9U, product, suite}) ;
			}
		}
	}

	const std::array<std::string_view, 37U> cases{
		"P4_C01_WRONG_MODELS_PIPELINE",
		"P4_C02_WRONG_TYPED_KIND_PIPELINE",
		"P4_C03_EXTRA_ID_PIPELINE",
		"P4_C04_CLASS_PIPELINE",
		"P4_C05_INF_HASH_PIPELINE",
		"P4_C06_CAT_REJECT",
		"P4_C07_MISSING_SYS",
		"P4_C08_CHANGED_SEALED_BYTE",
		"P4_C09_WRONG_RECORD_ID",
		"P4_C10_EXPIRED_NATIVE_LEASE",
		"P4_C11_EXPIRED_RECORD",
		"P4_C12_SHARED_AMBIGUOUS_RECORDS",
		"P4_C13_SHARED_OTHER_PRODUCT",
		"P4_C14_RETAINED_NONEMPTY_SUCCESS",
		"P4_C15_RETAINED_BAD_TARGET_HASH",
		"P4_C16_RETAINED_TARGET_EXPIRED",
		"P4_C17_GENERIC_SERVER",
		"P4_C20_OLD_CLIENT10",
		"P4_C21_OLD_CLIENT11",
		"P4_D01_AUDIT_CHANGED_BUILD",
		"P4_D02_AUDIT_WIN32_FAILURE",
		"P4_D03_AUDIT_NTSTATUS_FAILURE",
		"P4_D04_AFTER_MODELS_CHANGED_PRODUCT",
		"P4_D05_BEFORE_TOKEN_CHANGED_SUITE",
		"P4_D06_PREPUBLICATION_ARM64",
		"P4_D07_FINAL_CHANGED_BUILD",
		"P4_D08_FINAL_WIN32_FAILURE",
		"P4_D09_FINAL_NTSTATUS_FAILURE",
		"P4_D10_FINAL_UNOBSERVED",
		"P4_D11_FINAL_OBSERVER_THROW",
		"P4_D12_AUDIT_STALE_LATCH_SEQUENCE",
		"P4_D13_FINAL_UNKNOWN_LATCH_SEQUENCE",
		"P4_D14_FINAL_KNOWN_PRODUCT4",
		"P4_D15_FINAL_BUILD_UNKNOWN",
		"P4_D16_FINAL_MODELS_MISMATCH",
		"P4_D17_RETAINED_FRESH_FAILURE",
		"P4_D18_RETAINED_MODELS_THEN_HOST_CHANGE"} ;	// 移行2/native隔離2は別既入口です
	// 各独立IDを別の認証store/ownerへ渡します
	for( const auto id : cases) {
		const bool client =
			// 旧client literalです
			id == "P4_C20_OLD_CLIENT10" || id == "P4_C21_OLD_CLIENT11" ;
		run( id, "WINDOWS_SERVER_2025", "3",
			client ? WindowsHostPlatform{10U, 0U, id == "P4_C20_OLD_CLIENT10" ? 19045U : 26100U, 9U,
										 1U, 0U}
				   : WindowsHostPlatform{10U, 0U, 26100U, 9U, 3U, 256U}) ;
	}

	std::string clientInf ;												// 元の旧client containerを変更しません
	const auto	clientZip = normalWorkerDriverZip( false, &clientInf) ;	// native隔離fixtureだけです
	auto		clientRaw = descriptorRecord( descriptorFixture()) ;	// 外部Server三条件はありません
	clientRaw = replaced( std::move( clientRaw), RECORD_CLAIM_HASH, recordDigest( key, clientZip)) ;
	clientRaw = replaced( std::move( clientRaw), RECORD_CLAIM_HASH, recordDigest( key, clientZip)) ;
	clientRaw = replaced( std::move( clientRaw), "\"valueBytes\":1234",
						 "\"valueBytes\":" + std::to_string( clientZip.size())) ;
	std::shared_ptr<SignedIndexStore>
		clientStore ;	// 取得を呼ばないnative専用caseでも原storeは正常です
	static_cast<void>( lookupSnapshot( key, clientRaw, 1U, &clientStore)) ;
	runServerP4NativeIsolationCases( context, std::move( clientStore), NOW, clientZip) ;
}

/** @brief Fake callbackの有限な正例・拒否モードです */
enum class LookupMode {
	/// 種別ごとに別のdeviceへ一意に結ぶ
	UNIQUE,
	/// 完了した空結果
	EMPTY,
	/// 同じ公開IDに同型deviceが複数ある未確定結果
	MULTIPLE,
	/// 未知opaque
	UNKNOWN,
	/// 同じopaqueの重複
	DUPLICATE,
	/// 部分inventory／未完了
	INCOMPLETE,
	/// 元HRESULT失敗
	FAILURE,
	/// 例外失敗
	THROWING,
	/// 確保例外
	ALLOCATION,
	/// 古いcontext
	STALE,
	/// 上限超過結果
	EXCESSIVE
} ;

/** @brief 実端末ID・networkを使わない同期read-only fixtureです */
class LookupResolver final : public IndexPublicIdResolver {
public:
	/// この試行だけの有限モード
	LookupMode							  mode{LookupMode::UNIQUE} ;
	/// 同workerのfixture呼出し件数
	mutable std::size_t					  calls{} ;
	/// Callbackへ到達した元種別を保持するfixture観測
	mutable std::vector<IndexPnpIdKind>	  kinds ;
	/// 公開ID・classの原申告が届いたことの観測
	mutable bool						  receivedOriginal{true} ;
	/**
	 * @brief 人工索引検索のmodeごとにopaque集合・不完全/失敗を返すfakeです
	 * @param[in] kind メーカー公表INF側identifierの元役割。native property指定ではありません
	 * @param[in] publishedId 元公開ASCII ID。端末actual IDではありません
	 * @param[in] classGuid 元申告ClassGUID
	 * @param[in] context 現在のworker context
	 * @param[in] present 現在の有限opaque集合。本呼出し中だけ借用します
	 * @return modeで指定した人工完了区分・元エラーと候補集合です
	 * @note kindと固定ID/ClassGUIDの受信値を記録し、mode別の人工集合を組み立てます。実Windows inventory・適合・rankは照会しません
	 */
	[[nodiscard]] IndexPublicIdResolution resolve(
		const IndexPnpIdKind kind, const std::string_view publishedId,
		const std::string_view classGuid, const IndexLookupContext context,
		const std::span<const std::wstring> present) const override
	{
		++calls ;
		kinds.push_back( kind) ;
		receivedOriginal = receivedOriginal && publishedId == "TESTBUS\\SYNTH_0001" &&
						   classGuid == "{11111111-2222-3333-4444-555555555555}" ;
		IndexPublicIdResolution result{context, true, 0, {}} ;	// 全inventory完了の架空結果
		// Fixtureモードごとに原結果だけを返し、共通adapter側の拒否を試す
		switch( mode) {
			// 元種別を区別し、共通recordを別deviceへ結ぶ
			case LookupMode::UNIQUE:
				result.devices.push_back( present[kind == IndexPnpIdKind::HARDWARE ? 0U : 1U]) ;
				break ;

			// 同型2台も元opaque集合全件を返す
			case LookupMode::MULTIPLE:
				result.devices.assign( present.begin(), present.end()) ;
				break ;

			// 未知opaqueを返し、adapterで拒否させる
			case LookupMode::UNKNOWN:
				result.devices = {L"unknown-opaque"} ;
				break ;

			// 重複を合法な非一意へまとめない
			case LookupMode::DUPLICATE:
				result.devices = {L"opaque-a", L"opaque-a"} ;
				break ;

			// 部分inventoryでは空結果も完了不一致にしない
			case LookupMode::INCOMPLETE:
				result.completed = false ;
				break ;

			// 元HRESULTを変更せず返す
			case LookupMode::FAILURE:
				result.error = static_cast<NativeError>( E_ACCESSDENIED) ;
				break ;

			// 非標準のfixture障害もcallback外へ漏らさない
			case LookupMode::THROWING:
				throw std::runtime_error( "synthetic resolver failure") ;
			// 確保障害を独立した元診断へ変換させる
			case LookupMode::ALLOCATION:
				throw std::bad_alloc{} ;
			// 不一致のinventory世代を返す
			case LookupMode::STALE:
				++result.context.inventoryGeneration ;
				break ;

			// Callback戻り枠を超過させる
			case LookupMode::EXCESSIVE:
				result.devices.resize( INDEX_LOOKUP_PRESENT_MAX + 1U, L"opaque-a") ;
				break ;

			// 全inventory完了かつmatchなし
			case LookupMode::EMPTY:
				break ;
		}

		return result ;
	}
} ;

//------------------------------------------------------------------------------
/**
 * @brief Lookup成立と各関係の区分を確認します
 * @param[in,out] context 共通assertion集計先
 * @param[in] result 実adapter結果
 * @param[in] state 期待する各関係区分
 * @param[in] reason 期待する各関係理由
 */
//------------------------------------------------------------------------------
void expectLookupRelations( TestContext &context, const IndexRecordLookupResult &result,
						   const IndexRecordMatchState state, const IndexRecordMatchReason reason)
{
	DRIVERCRATE_EXPECT( context,
					   result.status == IndexRecordLookupStatus::LOOKUP_READY && result.lookup) ;
	// 不成立結果を参照して試験の失敗を隠さない
	if( !result.lookup) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, !result.lookup->relations().empty()) ;
	// 有限関係を全件確認し、最初の結果だけでgroupを合格にしない
	for( const auto &relation : result.lookup->relations()) {
		DRIVERCRATE_EXPECT( context, relation.state == state && relation.reason == reason) ;
		DRIVERCRATE_EXPECT( context,
						   state == IndexRecordMatchState::MATCHED || !relation.deviceIdentity) ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 実署名・gzip・schema・隔離commit／reloadから公開ID照合seamを検査します
 * @param[in,out] context 共通unit assertion集計先
 * @note Fake resolverを使用し、実端末適合・通常worker／UI・取得導入へ接続しません
 */
//------------------------------------------------------------------------------
void runSignedIndexRecordLookupTests( TestContext &context)
{
	DRIVERCRATE_EXPECT( context,
					   INDEX_RECORD_MAX_BYTES == 524288U && INDEX_RECORD_PNP_MAX_COUNT == 4096U) ;
	std::uint64_t retained{} ;	// 転送量と独立した同scanの保持量
	DRIVERCRATE_EXPECT(
		context, tryRetainIndexedInspectionBytes( 2ULL * 1024ULL * 1024ULL * 1024ULL, retained) &&
					 retained == 2ULL * 1024ULL * 1024ULL * 1024ULL) ;
	DRIVERCRATE_EXPECT( context,
					   tryRetainIndexedInspectionBytes( 1024ULL * 1024ULL * 1024ULL, retained) &&
						   retained == 3ULL * 1024ULL * 1024ULL * 1024ULL) ;
	DRIVERCRATE_EXPECT( context, !tryRetainIndexedInspectionBytes( 1U, retained) &&
									retained == 3ULL * 1024ULL * 1024ULL * 1024ULL) ;
	DRIVERCRATE_EXPECT( context, tryRetainIndexedInspectionBytes( 0U, retained)) ;
	retained = UINT64_MAX ;
	DRIVERCRATE_EXPECT( context,
					   !tryRetainIndexedInspectionBytes( 1U, retained) && retained == UINT64_MAX) ;
	const int firstAssertion = context.assertionCount() ;	// 新groupの実件数だけを測る
	const int firstFailure	 = context.failureCount() ;		// 新groupの実失敗だけを測る
	RamKey	  key ;											// 非永続の既存RAM CNG鍵
	key.generate( 3072U) ;
	const std::string raw = replaced(
		distributionRecord(),
		R"json("pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
		// 同じ公表文字列でも種別は別
		R"json("pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},{"kind":"COMPATIBLE","value":"TESTBUS\\SYNTH_0001"}])json") ;
	// 真のcommit／reload snapshot
	auto							   snapshot = lookupSnapshot( key, raw) ;
	// 同workerの架空有限context
	const IndexLookupContext		   active{11U, 12U, 13U} ;
	const std::array<std::wstring, 2U> present{L"opaque-a", L"opaque-b"} ;	// Raw端末IDを含まない集合
	LookupResolver					   resolver ;							// この呼出し中だけ借用するfake
	const auto						   accepted =
		// 実入口
		lookupSignedIndexRecords( snapshot, active, active, present, {}, NOW, &resolver) ;
	expectLookupRelations( context, accepted, IndexRecordMatchState::MATCHED,
						  IndexRecordMatchReason::UNIQUE_RELATION) ;
	DRIVERCRATE_EXPECT( context, resolver.calls == 2U && resolver.receivedOriginal) ;
	DRIVERCRATE_EXPECT( context,
					   resolver.kinds == std::vector<IndexPnpIdKind>( {IndexPnpIdKind::HARDWARE,
																	  IndexPnpIdKind::COMPATIBLE})) ;
	DRIVERCRATE_EXPECT( context, accepted.lookup && accepted.lookup->relations().size() == 2U) ;
	// 正例不成立をdereferenceで隠さず、残り試験を中止する
	if( !accepted.lookup || accepted.lookup->relations().size() != 2U) {
		throw std::runtime_error( "lookup positive fixture failed") ;
	}

	// 同じ認証snapshotから独立lookupを一度作り、共有const所有へ明示移動します
	auto manifestOnlyLookup =
		lookupSignedIndexRecords( snapshot, active, active, present, {}, NOW, &resolver) ;
	// 正常lookup前提の不成立を取得拒否の正例へ変換しません
	if( !manifestOnlyLookup.lookup) {
		throw std::runtime_error( "manifest-only lookup prerequisite failed") ;
	}

	const auto manifestOnlyOwned = std::make_shared<const SignedIndexRecordLookup>(
		// 原lookupだけを共有所有します
		std::move( *manifestOnlyLookup.lookup)) ;
	SignedIndexAcquisitionAdapter
			   manifestOnlyAdapter ;	// RAM trust成功を取得認可に転用しない実境界です
	const auto manifestOnlyError =
		manifestOnlyAdapter.begin( manifestOnlyOwned, active, IndexTargetOs::WINDOWS_11,
								  NOW) ;	// 選択した取得集合にはRAM鍵を含みません
	DRIVERCRATE_EXPECT( context, manifestOnlyError == E_ACCESSDENIED) ;
	std::cout << "P3 native manifest-only RAM snapshot: acquisition refused at product begin\n" ;

	const auto &owned	 = accepted.lookup->snapshot() ;			// 共有const所有からの借用
	const auto &schema	 = owned.schemaReceipt() ;					// 原source／recordを読み取る
	const auto &manifest = schema.assetBytes().manifest().data() ;	// 原世代とhashを別々に確認する
	DRIVERCRATE_EXPECT( context, &owned == snapshot.get()) ;
	DRIVERCRATE_EXPECT( context, schema.sources().size() == 1U && schema.records().size() == 1U) ;
	DRIVERCRATE_EXPECT( context, schema.records()[0].originalBytes == raw) ;
	DRIVERCRATE_EXPECT( context, manifest.generation == 9U && manifest.assetGeneration == 7U) ;
	DRIVERCRATE_EXPECT( context,
					   schema.schemaPolicyVersion() == INDEX_RECORD_READER_POLICY_VERSION &&
						   schema.assetBytes().bytePolicyVersion() == 1U &&
						   owned.storePolicyVersion() == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   manifest.manifestSha256 ==
						   snapshot->schemaReceipt().assetBytes().manifest().data().manifestSha256) ;
	DRIVERCRATE_EXPECT( context,
					   manifest.asset.sha256 ==
						   snapshot->schemaReceipt().assetBytes().manifest().data().asset.sha256) ;
	DRIVERCRATE_EXPECT( context, schema.indexSha256() == snapshot->schemaReceipt().indexSha256()) ;
	DRIVERCRATE_EXPECT( context,
					   schema.records()[0].inspectionStage == IndexInspectionStage::METADATA_ONLY) ;
	DRIVERCRATE_EXPECT( context, accepted.lookup->relations()[0].deviceIdentity == L"opaque-a" &&
									accepted.lookup->relations()[1].deviceIdentity == L"opaque-b") ;
	// 同record複数deviceでも原source／record hashとcontextを全件保持する
	for( const auto &relation : accepted.lookup->relations()) {
		DRIVERCRATE_EXPECT( context, relation.context == active &&
										relation.recordSha256 == schema.records()[0].recordSha256 &&
										relation.sourceId == "fixture-source" &&
										relation.recordId == "metadata") ;
	}

	const std::array modes{LookupMode::EMPTY,	  LookupMode::MULTIPLE,	  LookupMode::UNKNOWN,
						   LookupMode::DUPLICATE, LookupMode::INCOMPLETE, LookupMode::FAILURE,
						   LookupMode::THROWING,  LookupMode::ALLOCATION, LookupMode::STALE,
						   LookupMode::EXCESSIVE} ;	// 独立の拒否試行
	const std::array reasons{IndexRecordMatchReason::NO_RELATION,
							 IndexRecordMatchReason::NON_UNIQUE_RELATION,
							 IndexRecordMatchReason::INVALID_OPAQUE_RESULT,
							 IndexRecordMatchReason::INVALID_OPAQUE_RESULT,
							 IndexRecordMatchReason::RESOLVER_INCOMPLETE,
							 IndexRecordMatchReason::RESOLVER_FAILED,
							 IndexRecordMatchReason::RESOLVER_EXCEPTION,
							 IndexRecordMatchReason::RESOLVER_EXCEPTION,
							 IndexRecordMatchReason::RESOLVER_CONTEXT_MISMATCH,
							 IndexRecordMatchReason::INVALID_OPAQUE_RESULT} ;	// 各理由
	// 有限モードを各一度実行し、各公開IDの元結果を確認する
	for( std::size_t modeIndex = 0U; modeIndex < modes.size(); ++modeIndex) {
		resolver.mode	  = modes[modeIndex] ;
		const auto result = lookupSignedIndexRecords( snapshot, active, active, present, {}, NOW,
													 &resolver) ;	// 同context試行
		expectLookupRelations( context, result,
							  modeIndex < 2U ? IndexRecordMatchState::UNMATCHED
											 : IndexRecordMatchState::UNDETERMINED,
							  reasons[modeIndex]) ;
		// 同型複数deviceは非一意のまま全opaqueを残す
		if( modes[modeIndex] == LookupMode::MULTIPLE) {
			DRIVERCRATE_EXPECT( context,
							   result.lookup &&
								   result.lookup->relations()[0].relatedDevices ==
									   std::vector<std::wstring>( {L"opaque-a", L"opaque-b"})) ;
		}

		// Callbackの元失敗HRESULTを保存する
		if( modes[modeIndex] == LookupMode::FAILURE) {
			DRIVERCRATE_EXPECT( context,
							   result.lookup && result.lookup->relations()[0].error ==
													static_cast<NativeError>( E_ACCESSDENIED)) ;
		}

		// 例外の型を規定した診断へ変換する
		if( modes[modeIndex] == LookupMode::THROWING || modes[modeIndex] == LookupMode::ALLOCATION) {
			DRIVERCRATE_EXPECT(
				context, result.lookup &&
							 result.lookup->relations()[0].error ==
								 static_cast<NativeError>( modes[modeIndex] == LookupMode::ALLOCATION
															  ? E_OUTOFMEMORY
															  : E_FAIL)) ;
		}
	}

	resolver.mode = LookupMode::UNIQUE ;
	expectLookupRelations(
		context, lookupSignedIndexRecords( snapshot, active, active, present, {}, NOW, nullptr),
		IndexRecordMatchState::UNDETERMINED, IndexRecordMatchReason::RESOLVER_UNAVAILABLE) ;
	// 一recordの全二IDが収まらない枠は、途中positive/未実行tupleをcommitしません
	for( const auto calls : {0U, 1U}) {
		const auto before = resolver.calls ;	// 未開始を実callback数でも照合します
		const auto partialBudget =
			lookupSignedIndexRecords( snapshot, active, active, present, {0U, 256U, calls}, NOW,
									 &resolver) ;	// 全record prefixだけを返します
		DRIVERCRATE_EXPECT( context, partialBudget.lookup &&
										partialBudget.lookup->relations().empty() &&
										partialBudget.lookup->progress().completedRecords == 0U &&
										partialBudget.lookup->progress().nextRecordOffset == 0U &&
										partialBudget.lookup->progress().stopReason ==
											IndexLookupStopReason::CALL_BUDGET &&
										resolver.calls == before) ;
	}

	const auto unknown =
		// Class・versionも元UNKNOWN
		lookupSnapshot( key, distributionRecord( "unknown", false)) ;
	const auto unknownResult = lookupSignedIndexRecords( unknown, active, active, present, {}, NOW,
														&resolver) ;	// 公開identity不明
	expectLookupRelations( context, unknownResult, IndexRecordMatchState::UNDETERMINED,
						  IndexRecordMatchReason::PUBLIC_IDENTITY_UNKNOWN) ;
	DRIVERCRATE_EXPECT(
		context, unknownResult.lookup &&
					 !unknownResult.lookup->snapshot().schemaReceipt().records()[0].version.value &&
					 unknownResult.lookup->snapshot().schemaReceipt().records()[0].version.reason ==
						 "not supplied" &&
					 unknownResult.lookup->snapshot()
							 .schemaReceipt()
							 .records()[0]
							 .publishedIdentityEvidence.reason == "public INF identity missing") ;
	const std::size_t beforeReject = resolver.calls ;	// 入力拒否でcallbackが走らないことの基準
	const std::array  staleContexts{IndexLookupContext{0U, 12U, 13U},
									IndexLookupContext{10U, 12U, 13U},
									IndexLookupContext{11U, 10U, 13U},
									IndexLookupContext{11U, 12U, 10U}} ;	// 不明・各stale field
	// 不明と各世代不一致を全て拒否する
	for( const auto stale : staleContexts) {
		const auto result = lookupSignedIndexRecords( snapshot, stale, active, present, {}, NOW,
													 &resolver) ;	// 不一致context
		DRIVERCRATE_EXPECT( context, result.status == IndexRecordLookupStatus::STALE_CONTEXT &&
										!result.lookup) ;
	}

	DRIVERCRATE_EXPECT( context, lookupSignedIndexRecords( snapshot, active, active, present, {},
														 std::nullopt, &resolver)
										.status == IndexRecordLookupStatus::TIME_UNAVAILABLE) ;
	DRIVERCRATE_EXPECT( context, lookupSignedIndexRecords(
									snapshot, active, active, present, {},
									manifest.publishedAtUtc - std::chrono::seconds{1}, &resolver)
										.status == IndexRecordLookupStatus::NOT_YET_VALID) ;
	DRIVERCRATE_EXPECT( context, lookupSignedIndexRecords( snapshot, active, active, present, {},
														 manifest.expiresAtUtc, &resolver)
										.status == IndexRecordLookupStatus::EXPIRED) ;
	DRIVERCRATE_EXPECT(
		context, lookupSignedIndexRecords( {}, active, active, present, {}, NOW, &resolver).status ==
					 IndexRecordLookupStatus::INCOMPLETE_SNAPSHOT) ;
	const std::array<std::wstring, 2U> duplicated{L"opaque-a", L"opaque-a"} ;	// 不正present
	const std::array<std::wstring, 1U> emptyIdentity{L""} ;						// 空opaqueはIDではない
	DRIVERCRATE_EXPECT(
		context,
		lookupSignedIndexRecords( snapshot, active, active, duplicated, {}, NOW, &resolver).status ==
			IndexRecordLookupStatus::INVALID_PRESENT_SET) ;
	DRIVERCRATE_EXPECT( context, lookupSignedIndexRecords( snapshot, active, active, emptyIdentity,
														 {}, NOW, &resolver)
										.status == IndexRecordLookupStatus::INVALID_PRESENT_SET) ;
	const std::vector<std::wstring> oversized( INDEX_LOOKUP_PRESENT_MAX + 1U,
											  L"opaque-a") ;	// 件数上限超過
	DRIVERCRATE_EXPECT(
		context,
		lookupSignedIndexRecords( snapshot, active, active, oversized, {}, NOW, &resolver).status ==
			IndexRecordLookupStatus::BUDGET_LIMIT) ;
	const std::array budgets{IndexLookupBudget{2U, 1U, 1U}, IndexLookupBudget{0U, 0U, 1U},
							 IndexLookupBudget{0U, 257U, 1U},
							 IndexLookupBudget{0U, 1U, 32769U}} ;	// 独立した有限枠拒否
	// Batch範囲と各上限を全て確認する
	for( const auto budget : budgets) {
		const auto result = lookupSignedIndexRecords( snapshot, active, active, present, budget, NOW,
													 &resolver) ;	// 枠外入力
		DRIVERCRATE_EXPECT( context, result.status == IndexRecordLookupStatus::BUDGET_LIMIT &&
										!result.lookup) ;
	}

	DRIVERCRATE_EXPECT( context, resolver.calls == beforeReject) ;
	const auto emptyBatch = lookupSignedIndexRecords(
		snapshot, active, active, present, {1U, 256U, 0U}, NOW, &resolver) ;	// 末尾の空batch
	DRIVERCRATE_EXPECT( context, emptyBatch.lookup && emptyBatch.lookup->relations().empty()) ;
	auto movedSource = *snapshot ;	// 真snapshotの正規copy。任意DTOではない
	auto movedTarget = std::make_shared<const AuthenticatedIndexSnapshot>(
		// 一度moveして所有する
		std::move( movedSource)) ;
	const auto movedInput = std::make_shared<const AuthenticatedIndexSnapshot>(
		// 必須byteのないmove元
		std::move( movedSource)) ;
	DRIVERCRATE_EXPECT(
		context,
		lookupSignedIndexRecords( movedInput, active, active, present, {}, NOW, &resolver).status ==
			IndexRecordLookupStatus::INCOMPLETE_SNAPSHOT) ;
	DRIVERCRATE_EXPECT(
		context,
		lookupSignedIndexRecords( movedTarget, active, active, present, {}, NOW, &resolver).status ==
			IndexRecordLookupStatus::LOOKUP_READY) ;
	const std::weak_ptr<const AuthenticatedIndexSnapshot> lifetime =
		snapshot ;	// 共有寿命を外から観測する
	const auto batchSnapshot =
		// Batch上限を超える全索引
		lookupSnapshot( key, distributionRecord(), 257U) ;
	const auto firstBatch = lookupSignedIndexRecords( batchSnapshot, active, active, present, {},
													 NOW, &resolver) ;	// 先頭256件
	const auto lastBatch =
		lookupSignedIndexRecords( batchSnapshot, active, active, present, {256U, 256U, 32768U}, NOW,
								 &resolver) ;	// 同索引の残り1件
	DRIVERCRATE_EXPECT( context,
					   firstBatch.lookup && firstBatch.lookup->relations().size() == 256U &&
						   lastBatch.lookup && lastBatch.lookup->relations().size() == 1U &&
						   lastBatch.lookup->relations()[0].recordIndex == 256U) ;
	DRIVERCRATE_EXPECT( context,
					   firstBatch.lookup && lastBatch.lookup &&
						   &firstBatch.lookup->snapshot() == &lastBatch.lookup->snapshot()) ;
	std::vector<std::wstring> maximumPresent ;	// 4096件の架空opaque集合
	// 最大件数まで一意opaqueを作り、実device列挙はしない
	for( std::size_t presentIndex = 0U; presentIndex < INDEX_LOOKUP_PRESENT_MAX; ++presentIndex) {
		maximumPresent.push_back( L"opaque-" + std::to_wstring( presentIndex)) ;
	}

	DRIVERCRATE_EXPECT( context, lookupSignedIndexRecords( snapshot, active, active, maximumPresent,
														 {}, NOW, &resolver)
										.status == IndexRecordLookupStatus::LOOKUP_READY) ;
	resolver.mode = LookupMode::MULTIPLE ;
	const auto retainedBoundary =
		lookupSignedIndexRecords( batchSnapshot, active, active, maximumPresent, {0U, 9U, 9U}, NOW,
								 &resolver) ;	// 4096opaqueを8回保持して32768境界へ到達する
	DRIVERCRATE_EXPECT(
		context,
		retainedBoundary.lookup && retainedBoundary.lookup->relations().size() == 8U &&
			retainedBoundary.lookup->relations()[7].relatedDevices.size() == 4096U &&
			retainedBoundary.lookup->relations()[7].state == IndexRecordMatchState::UNMATCHED &&
			retainedBoundary.lookup->progress().completedRecords == 8U &&
			retainedBoundary.lookup->progress().nextRecordOffset == 8U &&
			retainedBoundary.lookup->progress().stopReason ==
				IndexLookupStopReason::RETAINED_CAPACITY) ;
	resolver.mode = LookupMode::EMPTY ;
	expectLookupRelations(
		context, lookupSignedIndexRecords( snapshot, active, active, {}, {}, NOW, &resolver),
		IndexRecordMatchState::UNMATCHED, IndexRecordMatchReason::NO_RELATION) ;
	resolver.mode = LookupMode::INCOMPLETE ;
	expectLookupRelations(
		context, lookupSignedIndexRecords( snapshot, active, active, {}, {}, NOW, &resolver),
		IndexRecordMatchState::UNDETERMINED, IndexRecordMatchReason::RESOLVER_INCOMPLETE) ;
	snapshot.reset() ;
	DRIVERCRATE_EXPECT( context, !lifetime.expired() &&
									owned.schemaReceipt().records()[0].originalBytes == raw) ;
	std::cout << "Signed index record lookup assertions: "
			  << context.assertionCount() - firstAssertion
			  << ", failures: " << context.failureCount() - firstFailure << '\n' ;
	runDriverStoreIndexResolverTests( context, lookupSnapshot( key, raw), NOW) ;
	std::shared_ptr<SignedIndexStore> workerStore ;	// 真署名・commit済み隔離rootだけです
	static_cast<void>( lookupSnapshot( key, raw, 513U, &workerStore)) ;
	runWorkerSignedIndexScanTests( context, std::move( workerStore), NOW, 513U) ;

	const std::string zip =
		std::string{"PK\x05\x06", 4U} + std::string( 18U, '\0') ;	// 非実行の空ZIP22byte
	const std::string zipHash = recordDigest( key, zip) ;			// 同RAM helperで実byteへ結ぶ元申告hash
	const IndexLookupContext		   acquisitionContext{71U, 72U,
												  73U} ;		// 同worker・scan・inventory固定context
	LookupResolver					   acquisitionResolver ;	// 同じ既存resolverの一意opaque関係
	const std::array<std::wstring, 2U> acquisitionPresent{L"opaque-a",
														  L"opaque-b"} ;	// 人工presentだけ
	// 七つの元record条件を各真署名・隔離保存へ通し、有限件数で終了します
	for( unsigned scenario = 0U; scenario < 10U; ++scenario) {
		std::string acquisitionRaw =
			// 正常の静的ZIP元record
			descriptorRecord( descriptorFixture()) ;
		acquisitionRaw = replaced( std::move( acquisitionRaw), RECORD_CLAIM_HASH, zipHash) ;
		acquisitionRaw = replaced( std::move( acquisitionRaw), RECORD_CLAIM_HASH, zipHash) ;
		acquisitionRaw =
			replaced( std::move( acquisitionRaw), "\"valueBytes\":1234", "\"valueBytes\":22") ;
		// 両非実行formatは認証済みrecord→実adapter→同grant/hintを確認する。内容は人工ZIPなので合格にしない
		if( scenario == 7U || scenario == 8U || scenario == 9U) {
			auto nextDescriptor =
				scenario == 7U	 ? replaced( descriptorFixture(), "\"format\":\"ZIP\"",
											"\"format\":\"SEVEN_ZIP_SFX\"")
				: scenario == 9U ? anonymousDescriptorFixture( zipHash, 22U)
								 : resourceDescriptorFixture( zipHash, 22U) ;	// 独立した明示format
			acquisitionRaw = descriptorRecord( nextDescriptor) ;
			acquisitionRaw = replaced( std::move( acquisitionRaw), RECORD_CLAIM_HASH, zipHash) ;
			acquisitionRaw = replaced( std::move( acquisitionRaw), RECORD_CLAIM_HASH, zipHash) ;
			acquisitionRaw =
				replaced( std::move( acquisitionRaw), "\"valueBytes\":1234", "\"valueBytes\":22") ;
			// resource inventoryのflat原名へだけ結び、擬似nestedを作らない
			if( scenario == 8U || scenario == 9U) {
				acquisitionRaw =
					replaced( std::move( acquisitionRaw), "\"infIdentity\":\"drivers/fixture.inf\"",
							 "\"infIdentity\":\"fixture.inf\"") ;
			}
		}

		// 計算hashだけを変更し、メーカー公表hash検査とは独立した拒否を確認します
		if( scenario == 1U) {
			acquisitionRaw =
				replaced( std::move( acquisitionRaw),
						 "\"calculatedHash\":{\"state\":\"KNOWN\",\"sha256\":\"" + zipHash,
						 "\"calculatedHash\":{\"state\":\"KNOWN\",\"sha256\":\"" +
							 std::string{RECORD_CLAIM_HASH}) ;
			acquisitionRaw = replaced(
				std::move( acquisitionRaw),
				"\"publishedHash\":{\"state\":\"KNOWN\",\"sha256\":\"" + zipHash +
					"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
					std::string{RECORD_EVIDENCE_HASH} + "\",\"reason\":\"\"}",
				"\"publishedHash\":{\"state\":\"UNKNOWN\",\"sha256\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"not published\"}") ;
		}

		// 元size不一致を公表hash成功で隠しません
		if( scenario == 2U) {
			acquisitionRaw =
				replaced( std::move( acquisitionRaw), "\"valueBytes\":22", "\"valueBytes\":23") ;
		}

		// 同意必須と具体的条件は本sliceの取得正常へ補完しません
		if( scenario == 3U) {
			acquisitionRaw = descriptorRecord( descriptorFixture( false, true)) ;
		}

		// 未登録のCDNも原署名routeのexact URLだけで共通取得へ進めます
		if( scenario == 4U) {
			acquisitionRaw =
				replaced( std::move( acquisitionRaw), "https://vendor.example/fixture.zip",
						 "https://cdn.fixture.example/fixture.zip") ;
			acquisitionRaw =
				replaced( std::move( acquisitionRaw), "https://vendor.example/fixture.zip",
						 "https://cdn.fixture.example/fixture.zip") ;
			acquisitionRaw =
				replaced( std::move( acquisitionRaw), "OFFICIAL_PAYLOAD_LINK", "OFFICIAL_CDN_LINK") ;
		}

		// 旧v1の配布pageとhashだけではdescriptorを発行しません
		if( scenario == 5U) {
			acquisitionRaw = distributionRecord() ;
		}

		// 未知hashとsizeも固定上限内で取得し、公表検証済み値を架空に補完しません
		if( scenario == 6U) {
			const std::string knownHash =
				"{\"state\":\"KNOWN\",\"sha256\":\"" + zipHash +
				"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
				std::string{RECORD_EVIDENCE_HASH} + "\",\"reason\":\"\"}" ;	// 元known evidence
			const std::string unknownHash =
				// 欠損を維持するhash
				"{\"state\":\"UNKNOWN\",\"sha256\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"not published\"}" ;
			acquisitionRaw = replaced( std::move( acquisitionRaw), knownHash, unknownHash) ;
			acquisitionRaw = replaced( std::move( acquisitionRaw), knownHash, unknownHash) ;
			acquisitionRaw =
				replaced( std::move( acquisitionRaw),
						 "{\"state\":\"KNOWN\",\"valueBytes\":22,\"reason\":\"\"}",
						 "{\"state\":\"UNKNOWN\",\"valueBytes\":0,\"reason\":\"not inspected\"}") ;
		}

		// 正常v2の同原byteでnative私有証拠の準備正負を追加し、旧七scenarioを維持します
		if( scenario == 0U) {
			testServerHostIndexRecords( context, key, acquisitionRaw) ;
			testServerP4Connections( context, key) ;
			runNativePartialIndexPreparationTests( context, lookupSnapshot( key, acquisitionRaw),
												  NOW) ;
		}

		std::string sourceOverride ;	// 旧fixtureには元sourceを使う
		// 動的protocolの一つだけを同ASUS公式sourceへ結ぶ
		if( scenario == 9U) {
			sourceOverride = recordSource() ;
			// 原origin/pageを同じ公式値に保つ
			while( sourceOverride.find( "vendor.example") != std::string::npos) {
				sourceOverride =
					replaced( std::move( sourceOverride), "vendor.example", "www.asus.com") ;
			}
		}

		auto acquisitionLookup = lookupSignedIndexRecords(
			lookupSnapshot( key, acquisitionRaw, 1U, nullptr, 9U, {}, sourceOverride),
			acquisitionContext, acquisitionContext, acquisitionPresent, {}, NOW,
			&acquisitionResolver) ;	// 同じ非公開構築入口
		// Fixtureのlookup不成立を正常取得試験の成功にしません
		if( !acquisitionLookup.lookup) {
			throw std::runtime_error( "acquisition lookup fixture failed") ;
		}

		runSignedIndexAcquisitionAdapterTests(
			context,
			std::make_shared<const SignedIndexRecordLookup>( std::move( *acquisitionLookup.lookup)),
			NOW, scenario == 5U ? 3U : scenario) ;
	}

	std::string driverInf ;	// 同原ZIPのINF evidence hashへ結びます
	const auto	driverZip =
		// 非空INF・SYS・CATを含む実container
		normalWorkerDriverZip( false, &driverInf) ;
	const auto driverHash = recordDigest( key, driverZip) ;				// 原byteへ結ぶ公開申告の人工hash
	auto	   driverRaw  = descriptorRecord( descriptorFixture()) ;	// 既知の同意不要静的ZIP条件
	driverRaw			  = replaced( std::move( driverRaw), RECORD_CLAIM_HASH, driverHash) ;
	driverRaw			  = replaced( std::move( driverRaw), RECORD_CLAIM_HASH, driverHash) ;
	driverRaw			  = replaced( std::move( driverRaw), "\"valueBytes\":1234",
									 "\"valueBytes\":" + std::to_string( driverZip.size())) ;
	// 通常の選択INF検査も、架空ZIP内の実memberへ元locatorを一致させます
	driverRaw = replaced( std::move( driverRaw), "\"infIdentity\":\"drivers/fixture.inf\"",
						 "\"infIdentity\":\"fixture.inf\"") ;
	std::vector<std::string> independentRows ;	// 元の独立取得task分母258件です
	// 同payload複製に依存せず、異なる明示routeの取得/予算/取消しを確認します
	for( std::size_t ordinal = 0U; ordinal < 258U; ++ordinal) {
		auto	   row	 = replaced( driverRaw, "\"recordId\":\"metadata\"",
									"\"recordId\":\"independent-" + std::to_string( ordinal) +
										"\"") ;	// 原identityです
		const auto route = "https://vendor.example/fixture-" + std::to_string( ordinal) +
						   ".zip" ;	// 同じfake本体でも異なる原配布recordの固定取得先です
		// Payload/routeの全出現を同一の原URLへ揃えます
		while( row.find( "https://vendor.example/fixture.zip") != row.npos) {
			row = replaced( std::move( row), "https://vendor.example/fixture.zip", route) ;
		}

		independentRows.push_back( std::move( row)) ;
	}

	std::shared_ptr<SignedIndexStore> normalStore ;	// 同実store再認証をworker内へ借用します
	auto							  normalSnapshot =
		// Batch境界後の二正常対象
		lookupSnapshot( key, driverRaw, independentRows.size(), &normalStore, 9U, independentRows) ;
	runNormalIndexWorkerAcquisitionTests( context, normalStore, NOW, driverZip, 258U, 256U) ;
	runNormalIndexWorkerAcquisitionTests( context, normalStore, NOW, driverZip, 258U, 0U) ;
	// 正常本体fixtureは原native CAT拒否と分離し、同じ真署名storeを一recordへ限定します
	std::shared_ptr<SignedIndexStore> bindingStore ;	// 公開ClassGUIDまで実fixtureへ完全一致します
	// 元真正recordの公開classだけを人工Ports内容へ一致させる再署名用byte
	auto bindingRaw = replaced( driverRaw, "{11111111-2222-3333-4444-555555555555}",
							   "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
	bindingRaw		= replaced( std::move( bindingRaw), "Fixture.NTamd64", "Models.NTamd64") ;
	bindingRaw =
		replaced( std::move( bindingRaw),
				 "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
					 std::string{RECORD_EVIDENCE_HASH},
				 "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
					 recordDigest( key, driverInf)) ;
	// 内容検査正例だけへ独立copyを使い、後段のUNKNOWN hash試験の元段階を維持します
	const auto inspectedBindingRaw =
		replaced( bindingRaw, "\"inspectionStage\":\"METADATA_ONLY\"",
				 "\"inspectionStage\":\"CONTENT_INSPECTED\"") ;	// 全元byteはRAM鍵で再署名します
	static_cast<void>( lookupSnapshot( key, inspectedBindingRaw, 1U, &bindingStore)) ;
	runNormalSignedIndexCandidateBindingTests( context, bindingStore, NOW, driverZip) ;
	runSignedIndexDeclarativeClassBindingTests( context) ;
	std::string netInf ;											// 別classの原INFです
	const auto	netZip	= normalWorkerDriverZip( true, &netInf) ;	// 別classの非空通常INFです
	const auto	netHash = recordDigest( key, netZip) ;				// 真署名recordを実原byteへ固定します
	auto		netRaw =
		// Net内容のsize/hash/classを再署名へ結ぶ原record
		descriptorRecord( descriptorFixture()) ;
	netRaw = replaced( std::move( netRaw), RECORD_CLAIM_HASH, netHash) ;
	netRaw = replaced( std::move( netRaw), RECORD_CLAIM_HASH, netHash) ;
	netRaw = replaced( std::move( netRaw), "\"valueBytes\":1234",
					  "\"valueBytes\":" + std::to_string( netZip.size())) ;
	netRaw = replaced( std::move( netRaw), "{11111111-2222-3333-4444-555555555555}",
					  "{4d36e972-e325-11ce-bfc1-08002be10318}") ;
	std::shared_ptr<SignedIndexStore> netStore ;	// Portsとは別の隔離真正storeです
	netRaw = replaced( std::move( netRaw), "drivers/fixture.inf", "fixture.inf") ;
	netRaw = replaced( std::move( netRaw), "Fixture.NTamd64", "Models.NTamd64") ;
	netRaw =
		replaced( std::move( netRaw),
				 "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
					 std::string{RECORD_EVIDENCE_HASH},
				 "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
					 recordDigest( key, netInf)) ;
	static_cast<void>( lookupSnapshot( key, netRaw, 1U, &netStore)) ;
	runNormalSignedIndexCandidateBindingTests( context, netStore, NOW, netZip, true) ;

	// 同名同内容INFをflat/nested A/Bへ置き、Windows rankを別元recordへ流用させません
	const std::array<std::string_view, 1U> nestedA{"release+a/inner.zip"} ;	// 一段の原memberです
	const std::array<std::string_view, 2U> nestedBoth{
		"release+a/inner.zip", "release+b/inner.zip"} ;	// 同内容でも別memberです
	const auto onlyNested =
		// flat INFはありません
		normalWorkerDriverZip( false, nullptr, nestedA, false) ;
	const auto allMembers =
		// flatと二nestedを同outerへ固定します
		normalWorkerDriverZip( false, nullptr, nestedBoth) ;
	const auto exactRecord = [&]( const std::string &payload, const std::string_view selector,
								 const std::string_view id = "metadata") {
		auto	   value	 = bindingRaw ;						// 同原INF hash/Models/Class/公開IDへ修正済みです
		const auto outerHash = recordDigest( key, payload) ;	// 当該outerの原hashです
		value				 = replaced( std::move( value), driverHash, outerHash) ;
		value				 = replaced( std::move( value), driverHash, outerHash) ;
		value = replaced( std::move( value), "\"valueBytes\":" + std::to_string( driverZip.size()),
						 "\"valueBytes\":" + std::to_string( payload.size())) ;
		value = replaced( std::move( value), "\"nestedArchiveIdentity\":\"\"",
						 "\"nestedArchiveIdentity\":\"" + std::string{selector} + "\"") ;
		return replaced( std::move( value), "\"recordId\":\"metadata\"",
						"\"recordId\":\"" + std::string{id} + "\"") ;
	} ; // 元申告を作るだけで、権限や実観測を生成しません
	const auto identityStart = context.assertionCount() ;	// 有限な取り違え回帰の開始値です
	// 全21条件の原archiveと原recordを一回ずつ評価します
	for( unsigned scenario = 0U; scenario < 21U; ++scenario) {
		const auto			  &payload = scenario == 0U || scenario == 7U ? driverZip
										 : scenario == 1U || scenario == 6U || scenario == 8U
											 ? onlyNested
											 : allMembers ;	// 各caseの原archiveです
		const std::string_view selector =
			scenario == 1U || scenario == 3U || scenario == 7U	 ? nestedA.front()
			: scenario == 4U || scenario == 5U || scenario == 6U ? nestedBoth.back()
																 : "" ;	// flat/A/Bを区別します
		std::vector<std::string> rows{									// 原byteで署名する全recordです
									  exactRecord( payload, selector)} ;
		std::size_t				 expected = scenario <= 5U || scenario == 15U || scenario == 16U ||
										(scenario >= 17U && scenario <= 19U)
												? 1U
												: 0U ;	// 固定の期待候補数です
		std::size_t				 references = 1U ;		// class不一致以外は元参照を保持します
		// 同target/deviceの別recordを先頭参照へ丸めません
		if( scenario == 5U) {
			rows.push_back( exactRecord( payload, nestedA.front(), "second")) ;
			expected   = 2U ;
			references = 2U ;
		}

		// 同原hash/節でも別INF memberでは一致させません
		if( scenario == 9U) {
			rows.front() = replaced( std::move( rows.front()), "\"infIdentity\":\"fixture.inf\"",
									"\"infIdentity\":\"another/fixture.inf\"") ;
		}

		// 別INF原hashを通常内容合格で補完しません
		if( scenario == 10U) {
			rows.front() = replaced( std::move( rows.front()), recordDigest( key, driverInf),
									std::string( 64U, 'f')) ;
		}

		// 別Modelsのrank成功を元節へ借用しません
		if( scenario == 11U) {
			rows.front() = replaced( std::move( rows.front()), "Models.NTamd64", "Another.NTamd64") ;
		}

		// 一つの照合IDが合っても、公開全集合の差は元identity不一致です
		if( scenario == 12U) {
			rows.front() =
				replaced( std::move( rows.front()), "\"pnpIds\":[",
						 "\"pnpIds\":[{\"kind\":\"COMPATIBLE\",\"value\":\"TESTBUS\\\\ABSENT\"},") ;
		}

		// Class不一致をdriverなしや正常rankへ読み替えません
		if( scenario == 13U) {
			rows.front() = replaced( std::move( rows.front()), "4d36e978", "4d36e972") ;
			references	 = 0U ;
		}

		// 既知outer size矛盾は同取得のINF合格で補完しません
		if( scenario == 14U) {
			rows.front() = replaced( std::move( rows.front()),
									"\"valueBytes\":" + std::to_string( payload.size()),
									"\"valueBytes\":" + std::to_string( payload.size() + 1U)) ;
		}

		// UNKNOWN期待は当該原recordのprivate seal/hintに限って実outerへ結合します
		if( scenario == 15U || scenario == 16U) {
			const auto knownHash =
				"{\"state\":\"KNOWN\",\"sha256\":\"" + recordDigest( key, payload) +
				"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
				std::string{RECORD_EVIDENCE_HASH} + "\",\"reason\":\"\"}" ;	// 元期待です
			const std::string unknownHash =
				// 実取得の事実とは別です
				"{\"state\":\"UNKNOWN\",\"sha256\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"not supplied\"}" ;
			rows.front() = replaced( std::move( rows.front()), knownHash, unknownHash) ;
			rows.front() = replaced( std::move( rows.front()), knownHash, unknownHash) ;
			rows.front() =
				replaced( std::move( rows.front()),
						 "{\"state\":\"KNOWN\",\"valueBytes\":" + std::to_string( payload.size()) +
							 ",\"reason\":\"\"}",
						 "{\"state\":\"UNKNOWN\",\"valueBytes\":0,\"reason\":\"not supplied\"}") ;
			// 別原recordは共有せず、それぞれのprivate取得へ結びます
			if( scenario == 16U) {
				rows.push_back(
					replaced( rows.front(), "\"recordId\":\"metadata\"", "\"recordId\":\"second\"")) ;
				expected   = 2U ;
				references = 2U ;
			}
		}

		std::shared_ptr<SignedIndexStore> exactStore ;	// 当該caseの原recordだけを保存します
		// Windowsの意味で同じClass caseを別identity不一致にしません
		if( scenario == 17U) {
			rows.front() =
				replaced( std::move( rows.front()), "{4d36e978-e325-11ce-bfc1-08002be10318}",
						 "{4D36E978-E325-11CE-BFC1-08002BE10318}") ;
		}

		// 元Modelsのcaseだけを変えても同じ原HINFへ結びます
		if( scenario == 18U) {
			rows.front() = replaced( std::move( rows.front()), "Models.NTamd64", "MODELS.NTAMD64") ;
		}

		// 原PnP byteは保持し、resolver/binderの比較keyだけをcase非依存にします
		if( scenario == 19U) {
			rows.front() =
				replaced( std::move( rows.front()), "TESTBUS\\\\SYNTH_0001", "testbus\\\\synth_0001") ;
		}

		// memberは原archive caseもidentityなので、別表記へ丸めません
		if( scenario == 20U) {
			rows.front() = replaced( std::move( rows.front()), "\"infIdentity\":\"fixture.inf\"",
									"\"infIdentity\":\"FIXTURE.inf\"") ;
		}

		static_cast<void>( lookupSnapshot( key, rows.front(), rows.size(), &exactStore, 9U, rows)) ;
		std::cout << "INDEX_IDENTITY_CASE scenario=" << scenario << '\n' ;
		runNormalIndexIdentityBindingCase( context, exactStore, NOW, payload, references, expected,
										  scenario == 13U	? 0U
										  : scenario == 16U ? 2U
															: 1U) ;
	}

	std::cout << "INDEX_IDENTITY_CASES cases=21 assertions="
			  << context.assertionCount() - identityStart << " actualCatAccepted=0 realInstall=0\n" ;

	const auto aggregateStart	 = context.assertionCount() ;	// 全batch私有凍結groupの開始値
	const auto aggregateFailures = context.failureCount() ;		// 元失敗を消しません
	std::vector<SignedIndexRecordLookup> batches ;				// 正規入口でだけ構築した元batch
	// 同snapshotの二batchを個別に読み、global位置を保持する私有凍結へ渡します
	for( std::size_t offset = 0U; offset < 258U; offset += 256U) {
		auto batch = lookupSignedIndexRecords(
			normalSnapshot, acquisitionContext, acquisitionContext, acquisitionPresent,
			{offset, 256U, 32768U}, NOW, &acquisitionResolver) ;	// 元scanの全context
		// 前段の不成立を集約拒否試験の成功へ変更しません
		if( !batch.lookup) {
			throw std::runtime_error( "worker aggregate batch rejected") ;
		}

		batches.push_back( std::move( *batch.lookup)) ;
	}

	using AggregateAccess = signed_index_acquisition_detail::Access ;	// 固定私有batchだけの試験入口
	const auto aggregate  = AggregateAccess::freezeFixture(
		 normalSnapshot, acquisitionContext, batches, NOW) ;	// 同原snapshotだけを集約します
	DRIVERCRATE_EXPECT( context, aggregate.lookup && aggregate.lookup->relations().size() == 258U &&
									aggregate.lookup->relations()[256U].recordIndex == 256U &&
									&aggregate.lookup->snapshot() == normalSnapshot.get()) ;
	const auto otherSnapshot =
		// 同byteでも別commit/reload ownerです
		lookupSnapshot( key, driverRaw, 258U) ;
	DRIVERCRATE_EXPECT(
		context,
		!AggregateAccess::freezeFixture( otherSnapshot, acquisitionContext, batches, NOW).lookup) ;
	const auto newGeneration =
		// 署名世代だけが異なります
		lookupSnapshot( key, driverRaw, 258U, nullptr, 10U) ;
	DRIVERCRATE_EXPECT(
		context,
		newGeneration->schemaReceipt().assetBytes().manifest().data().generation == 10U &&
			!AggregateAccess::freezeFixture( newGeneration, acquisitionContext, batches, NOW)
				 .lookup) ;
	const auto otherRaw = replaced( driverRaw, "Synthetic fixture",
								   "Alternate fixture") ;	// 認証済み原record hashが異なります
	const auto otherHash =
		// 正規署名・保存・再読取を維持します
		lookupSnapshot( key, otherRaw, 258U) ;
	DRIVERCRATE_EXPECT(
		context,
		otherHash->schemaReceipt().records().front().recordSha256 !=
				normalSnapshot->schemaReceipt().records().front().recordSha256 &&
			!AggregateAccess::freezeFixture( otherHash, acquisitionContext, batches, NOW).lookup) ;
	auto otherContext = acquisitionContext ;	// 新取得operationへ原scan operationを書き換えません
	++otherContext.operationId ;
	DRIVERCRATE_EXPECT(
		context,
		!AggregateAccess::freezeFixture( normalSnapshot, otherContext, batches, NOW).lookup) ;
	otherContext = acquisitionContext ;
	++otherContext.scanSessionId ;
	DRIVERCRATE_EXPECT(
		context,
		!AggregateAccess::freezeFixture( normalSnapshot, otherContext, batches, NOW).lookup) ;
	otherContext = acquisitionContext ;
	++otherContext.inventoryGeneration ;
	DRIVERCRATE_EXPECT(
		context,
		!AggregateAccess::freezeFixture( normalSnapshot, otherContext, batches, NOW).lookup) ;
	DRIVERCRATE_EXPECT( context, !AggregateAccess::freezeFixture( normalSnapshot, acquisitionContext,
																batches, std::nullopt)
									 .lookup) ;
	DRIVERCRATE_EXPECT( context,
					   !AggregateAccess::freezeFixture( normalSnapshot, acquisitionContext, batches,
													   NOW + std::chrono::days{15})
							.lookup) ;
	// 私有構築済み同batch再使用も重複拒否します
	batches.push_back( batches.front()) ;
	DRIVERCRATE_EXPECT(
		context,
		!AggregateAccess::freezeFixture( normalSnapshot, acquisitionContext, batches, NOW).lookup) ;
	std::string manyIds ;	// 各recordで128個までの合法な公開IDを持つ原byte
	// 合法な有限最大128個を一意に生成し、batch保持枠と全batch枠を分けて検査します
	for( std::size_t index = 0U; index < 128U; ++index) {
		// JSON配列の先頭だけcommaを付けません
		if( index != 0U) {
			manyIds += "," ;
		}

		manyIds += R"json({"kind":"HARDWARE","value":"TESTBUS\\SYNTH_)json" +
				   std::to_string( index) + R"json("})json" ;
	}

	const auto wideRaw =
		replaced( driverRaw, R"json({"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"})json",
				 manyIds) ;	// 私有relationを直接編集しません
	const auto wideSnapshot =
		// 真署名・実schemaの原batchだけです
		lookupSnapshot( key, wideRaw, 257U) ;
	std::vector<SignedIndexRecordLookup> wideBatches ;	// 32768関係と128関係の二元batch
	// 正規lookupでだけ構築し、未知callback理由を維持したまま枠超過を確認します
	for( std::size_t offset = 0U; offset < 257U; offset += 256U) {
		auto batch = lookupSignedIndexRecords( wideSnapshot, acquisitionContext, acquisitionContext,
											  {}, {offset, 256U, 0U}, NOW,
											  nullptr) ;	// 未実行はUNKNOWNのままです
		// 材料生成の失敗を枠拒否の合格へ変更しません
		if( !batch.lookup) {
			throw std::runtime_error( "wide aggregate batch rejected") ;
		}

		wideBatches.push_back( std::move( *batch.lookup)) ;
	}

	// 連続した完全record prefixは保持し、末尾一recordを全scan完了へ混ぜません
	const auto partialPrefix = AggregateAccess::freezeFixture(
		wideSnapshot, acquisitionContext,
		std::span<const SignedIndexRecordLookup>{wideBatches}.first( 1U), NOW) ;	// 元prefixだけです
	DRIVERCRATE_EXPECT(
		context, partialPrefix.lookup &&
					 partialPrefix.lookup->progress().nextRecordOffset == 256U &&
					 partialPrefix.lookup->snapshot().schemaReceipt().records().size() == 257U &&
					 partialPrefix.lookup->relations().size() == 32768U) ;
	const auto exactSnapshot =
		// 同じ原recordでちょうど32768関係です
		lookupSnapshot( key, wideRaw, 256U) ;
	const auto exactBatch =
		lookupSignedIndexRecords( exactSnapshot, acquisitionContext, acquisitionContext, {},
								 {0U, 256U, 0U}, NOW, nullptr) ;	// 全recordのUNKNOWNを保持します
	DRIVERCRATE_EXPECT( context,
					   exactBatch.lookup && exactBatch.lookup->progress().completedRecords == 256U) ;
	// 正例生成の失敗を空prefixの正常凍結へ変換しません
	if( !exactBatch.lookup) {
		throw std::runtime_error( "exact aggregate fixture rejected") ;
	}

	const auto atLimit = AggregateAccess::freezeFixture( exactSnapshot, acquisitionContext,
														std::span{&*exactBatch.lookup, 1U},
														NOW) ;	// 全prefixかつ上限同値だけが正常です
	DRIVERCRATE_EXPECT( context, atLimit.lookup && atLimit.lookup->relations().size() == 32768U &&
									atLimit.lookup->relations().front().state ==
										IndexRecordMatchState::UNDETERMINED &&
									atLimit.lookup->relations().front().reason ==
										IndexRecordMatchReason::RESOLVER_UNAVAILABLE) ;
	const auto overLimit = AggregateAccess::freezeFixture(
		wideSnapshot, acquisitionContext, wideBatches, NOW) ;	// 全batchが上限を越える要求
	DRIVERCRATE_EXPECT( context, !overLimit.lookup &&
									overLimit.status == IndexRecordLookupStatus::BUDGET_LIMIT) ;
	std::cout << "Normal index aggregate assertions: " << context.assertionCount() - aggregateStart
			  << ", failures: " << context.failureCount() - aggregateFailures << '\n' ;
}

namespace {

//------------------------------------------------------------------------------
/**
 * @brief 所有済み試験ファイルを有限枠内で読み込みます
 * @param[in] path 試験呼出しが指定した読み取り専用ファイルです
 * @param[in] maximum 確保前に確認する最大byte数です
 * @return 読み取った原byteを保持します
 * @throws std::runtime_error 読取り失敗、空ファイル、サイズ変化又は上限超過です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string readDistributionFixture( const std::filesystem::path &path,
												  const std::uintmax_t		   maximum)
{
	const auto size = std::filesystem::file_size( path) ;	// 確保前に元ファイルを測ります
	// 空または個別上限を超える試験ファイルをメモリへ読み込みません
	if( size == 0U || size > maximum) {
		throw std::runtime_error( "distribution fixture byte limit") ;
	}

	std::ifstream input( path, std::ios::binary) ;					// 既存ファイルを読み取り専用で開きます
	std::string	  bytes( static_cast<std::size_t>( size), '\0') ;	// 原byteを保持します
	// 全バイトが得られなかったか、読取り中にサイズが変化した試験データを拒否します
	if( !input.read( bytes.data(), static_cast<std::streamsize>( size)) ||
	   std::filesystem::file_size( path) != size) {
		throw std::runtime_error( "distribution fixture read failed") ;
	}

	return bytes ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 保存AWS原索引の通常取得計画とNitro確認を隔離して検査します
 * @param[in,out] context 共通試験集計です
 * @param[in] manifestPath 保存済みの原manifestです
 * @param[in] gzipPath 原レコードを含む保存済み圧縮索引です
 * @param[in] archivePath 検査済みの保存ZIPです
 * @throws std::runtime_error 原byte、期限、認証、保存のいずれかが不成立です
 */
//------------------------------------------------------------------------------
void runSavedAwsConsumerPlanTests( TestContext &context, const std::filesystem::path &manifestPath,
								  const std::filesystem::path &gzipPath,
								  const std::filesystem::path &archivePath)
{
	constexpr auto now = std::chrono::sys_days{std::chrono::year{2026} / 11 / 19} +
						 std::chrono::seconds{0} ;	// 元有効窓内の固定試験UTCです
	constexpr auto expiry = std::chrono::sys_days{std::chrono::year{2026} / 11 / 25} +
							std::chrono::hours{1} + std::chrono::minutes{2} +
							std::chrono::seconds{32} ;	// 再発行せず元期限を使用します
	// 元manifestの全byteです
	const auto raw		  = readDistributionFixture( manifestPath, INDEX_MANIFEST_MAX_BYTES) ;
	const auto compressed = readDistributionFixture( gzipPath, 2924U) ;			// 元GZipの全byteです
	const auto zip		  = readDistributionFixture( archivePath, 317020U) ;	// 元ZIPの全byteです
	RamKey	   key ;															// 永続鍵を使用しない隔離試験用鍵です
	key.generate( 3072U) ;
	// 各保存元を独立に固定し、一つでも別byteなら認証へ進めません
	if( recordDigest( key, raw) !=
		   "0b56dfad10612a6c07f209865c872caca05baeb449a35c964e0289e02710ef3a" ||
	   compressed.size() != 2924U ||
	   recordDigest( key, compressed) !=
		   "bd5b90950708031f5f4ee810b29fa24617481cce78528dbfdda838716b4d44e3" ||
	   zip.size() != 317020U ||
	   recordDigest( key, zip) !=
		   "51d7850aa9370ce2f227853ae9ee7ccca538db567e3de155c384933f8ea7d882") {
		throw std::runtime_error( "saved AWS manifest, gzip or ZIP pin") ;
	}

	const auto keyId = index_distribution_trust::KEY_ID ;	// 保存manifestの元key IDです
	// 元key IDに対応する隔離試験の公開鍵だけです
	const std::array<signed_index_detail::TrustKey, 1U> trust{{{keyId, key.publicBlob}}} ;
	const auto outer = envelope( raw, key.sign( raw), keyId) ;	// 元manifestを書き換えません
	const auto auth	 = signed_index_detail::authenticateWithTrustKeys( outer, now, std::nullopt,
																	  trust) ;	// 通常の認証codecです
	// 元manifestの認証と期限を確認してからassetを開きます
	if( !auth.manifest || auth.manifest->data().expiresAtUtc != expiry) {
		throw std::runtime_error( "saved AWS manifest authentication or expiry") ;
	}

	const auto expired = signed_index_detail::authenticateWithTrustKeys(
		outer, expiry, std::nullopt, trust) ;	// 同manifestの元期限境界です
	DRIVERCRATE_EXPECT( context, !expired.manifest &&
									expired.status == SignedIndexManifestStatus::INVALID_TIME) ;
	const auto bytes = std::as_bytes( std::span{compressed}) ;						// 原GZipを再圧縮しません
	const auto asset = authenticateIndexAssetBytes( *auth.manifest, bytes, now) ;	// 元asset認証です
	// 未認証assetをrecord codecに渡しません
	if( !asset.receipt) {
		throw std::runtime_error( "saved AWS asset authentication") ;
	}

	const auto schema = readSignedIndexRecords( *asset.receipt, now) ;	// 通常の型付きrecordです
	// 一件の原レコードがない場合に別の出力を生成しません
	if( !schema.receipt || schema.receipt->records().size() != 1U) {
		throw std::runtime_error( "saved AWS record schema") ;
	}

	const auto &record = schema.receipt->records().front() ;	// 認証済みの元recordです
	// 元recordとattestationの元期限をそのまま照合します
	if( recordDigest( key, record.originalBytes) !=
		   "55ebc323f1f440bcef95d2985403460af31c4d593c9340b13c642ece84e4239c" ||
	   !record.acquisitionDescriptor || !record.acquisitionDescriptor->attestation ||
	   record.acquisitionDescriptor->attestation->validUntilUtc != expiry) {
		throw std::runtime_error( "saved AWS record pin or attestation expiry") ;
	}

	const auto &identities = record.publishedIdentityEvidence.pnpIds ;	// 元INFの全型付きIDです
	DRIVERCRATE_EXPECT( context, identities.size() == 6U &&
									std::ranges::all_of( identities, []( const auto &id) {
										return id.kind == IndexPnpIdKind::HARDWARE ;
									})) ;
	auto opened =
		// 製品storeから隔離します
		signed_index_store_detail::Access::createIsolated( trust) ;
	// 元経路でcommitされたsnapshotだけを通常scanへ渡します
	if( !opened.store || !opened.store->commit( *schema.receipt, outer, bytes, now).snapshot) {
		throw std::runtime_error( "saved AWS isolated index commit") ;
	}

	runSavedAwsConsumerPlan( context, std::shared_ptr<SignedIndexStore>{std::move( opened.store)},
							now, zip, normalWorkerDriverZip()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保存した元私有索引を試験用RAM鍵で認証し、元ZIPと規約を端末側へ渡します
 * @param[in,out] context 共通試験集計です
 * @param[in] manifestPath 元未署名manifestです
 * @param[in] gzipPath 私有追加欄を含む元GZipです
 * @param[in] archivePath 保存したZIPの原バイトです
 * @param[in] pagePath 同じ公式配布の元HTMLです
 * @param[in] termsPath 同じ公式規約の元HTMLです
 * @throws std::runtime_error 署名索引又は保存応答へ結ぶ根拠が不正です
 */
//------------------------------------------------------------------------------
void runSavedArchiveTermsConsumerTests( TestContext				   &context,
									   const std::filesystem::path &manifestPath,
									   const std::filesystem::path &gzipPath,
									   const std::filesystem::path &archivePath,
									   const std::filesystem::path &pagePath,
									   const std::filesystem::path &termsPath)
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// 元OSを観測する既存試験と同じapartmentです
	const auto		   now = std::chrono::floor<std::chrono::seconds>(
		// 元有効期限内だけで行います
		std::chrono::system_clock::now()) ;
	const auto raw =
		// 元manifestです
		readDistributionFixture( manifestPath, INDEX_MANIFEST_MAX_BYTES) ;
	const auto gzip	 = readDistributionFixture( gzipPath, INDEX_ASSET_MAX_BYTES) ;	// 元私有索引です
	const auto bytes = std::as_bytes( std::span{gzip}) ;							// 認証とstoreへ同じ原GZipを渡します
	RamKey	   key ;																// 永続化しない試験鍵です
	key.generate( 3072U) ;
	const auto keyId = index_distribution_trust::KEY_ID ;	// 元manifestの既存鍵IDです
	// この試験で生成した署名だけを受理する一つの公開鍵
	const std::array<signed_index_detail::TrustKey, 1U> trust{{{keyId, key.publicBlob}}} ;
	const auto outer = envelope( raw, key.sign( raw), keyId) ;	// 原バイトを同じ文法で認証します
	// 保存していた署名対象を現在時刻と試験鍵で認証した結果
	const auto manifest =
		signed_index_detail::authenticateWithTrustKeys( outer, now, std::nullopt, trust) ;
	// 元期限や署名文法の異なる入力を受け入れません
	if( !manifest.manifest) {
		throw std::runtime_error( "archive terms test manifest") ;
	}

	const auto asset =
		// 元圧縮の実ハッシュです
		authenticateIndexAssetBytes( *manifest.manifest, bytes, now) ;
	// 元gzipを認証できた場合だけレコードを読み取ります
	if( !asset.receipt) {
		throw std::runtime_error( "archive terms test asset") ;
	}

	const auto base = readSignedIndexRecords( *asset.receipt, now) ;	// 旧本文も既存文法で検査します
	// 旧本文が不成立の追加欄を使いません
	if( !base.receipt) {
		throw std::runtime_error( "archive terms test base") ;
	}

	const auto supplemental =
		// 署名済みの私有候補です
		readSignedIndexConsumerSupplement( *base.receipt, now) ;
	// この再生に結ぶ規約付き元行が一意であることを確認します
	if( supplemental.contents.status != IndexRecordsStatus::SCHEMA_VALIDATED ||
	   supplemental.contents.records.size() != 1U) {
		throw std::runtime_error( "archive terms test supplement") ;
	}

	const auto &record	 = supplemental.contents.records.front() ;						// 元候補の取得とINF証拠です
	const auto &identity = record.publishedIdentityEvidence ;							// 同じ元INFのModelsです
	const auto &terms	 = record.acquisitionDescriptor->terms ;						// 元配布と規約を照合する署名値です
	const auto page = readDistributionFixture( pagePath, 2U * 1024U * 1024U) ;			// 元公式配布ページです
	const auto document = readDistributionFixture( termsPath, 2U * 1024U * 1024U) ;		// 元公式規約です
	const auto zip		= readDistributionFixture( archivePath, 2U * 1024U * 1024U) ;	// 同じ元ZIPです
	// 元候補の根拠と異なるHTTP情報を正常対照に使いません
	if( !terms.archiveNotice || !terms.textDocument || !terms.textDocument->htmlExtraction ||
	   identity.pnpIds.empty() ||
	   key.digest( page) != terms.textDocument->htmlExtraction->bindingEvidenceSha256 ||
	   key.digest( document) != terms.textDocument->sha256 ||
	   key.digest( zip) != terms.archiveNotice->archiveSha256) {
		throw std::runtime_error( "archive terms test original bytes") ;
	}

	auto opened = signed_index_store_detail::Access::createIsolated( trust) ;	// 稼働先を変更しません
	// 通常storeで読み戻せる認証済みの原索引だけを使います
	if( !opened.store || !opened.store->commit( *base.receipt, outer, bytes, now).snapshot) {
		throw std::runtime_error( "archive terms test commit") ;
	}

	// 署名済みの元選択、版とクラスへ同じように照合する合成デバイス
	const DistributionBindingDevice device{winrt::to_hstring( identity.pnpIds.front().value).c_str(),
										   winrt::to_hstring( identity.infIdentity).c_str(),
										   winrt::to_hstring( identity.modelSection).c_str(),
										   winrt::to_hstring( record.version.value.value()).c_str(),
										   winrt::to_hstring( identity.classGuid).c_str(),
										   L"Net"} ;
	runSavedArchiveTermsConsumer( context,
								 std::shared_ptr<SignedIndexStore>{std::move( opened.store)}, now,
								 {page, document, zip}, device, false) ;

	const auto extra =
		// 原規約と原期限を保持する認証済み追加欄です
		asset.receipt->readSupplement( now) ;
	const auto &attestation	   = *record.acquisitionDescriptor->attestation ;	// 原時間範囲です
	const auto	timePrefix	   = std::string{"\"checkedAtUtc\":\""} ;			// 同名時刻を一件だけ置換します
	const auto	recordIdPrefix = std::string{"\"recordId\":\""} ;				// 同じ元UIDの再登録はしません
	// 同じ配布を別レコードとして表したときの元規約再利用を確認する対照
	const auto	alias = replaced(
		 replaced( record.originalBytes, recordIdPrefix + record.recordId + "\"",
				  recordIdPrefix + "fixture-archive-terms-reuse\""),
		 timePrefix + std::format( "{:%FT%TZ}", attestation.checkedAtUtc) + "\"",
		 timePrefix + std::format( "{:%FT%TZ}", attestation.checkedAtUtc + std::chrono::seconds{1}) +
			 "\"") ;
	const auto originalEntry = recordEntry( key, record.originalBytes) ;	// 元行のhashを変更しません
	const auto extraJson =
		replaced( std::string{assetText( extra.expanded)}, originalEntry,
				 originalEntry + "," + recordEntry( key, alias)) ;		// 別承認用の試験行だけを追加します
	const auto baseJson = assetText( asset.receipt->expandedBytes()) ;	// 原本文に手を加えません
	const auto aliasGzip =
		assetWithExtra( assetGzip( baseJson),
					   assetSupplementFrame( key, baseJson, assetGzip( extraJson), extra.expiresAtUtc,
											// 同じ期限の隔離試験用GZipです
											manifest.manifest->data().assetGeneration)) ;
	const auto originalDigest = recordDigest( key, gzip) ;	// 原manifestの固定参照です
	const auto aliasDigest =
		// 新しい試験入力だけのhashです
		recordDigest( key, assetText( aliasGzip)) ;
	const auto aliasRaw = replaced(
		replaced( replaced( raw, originalDigest, aliasDigest), originalDigest, aliasDigest),
		"\"sizeBytes\":" + std::to_string( gzip.size()),
		"\"sizeBytes\":" + std::to_string( aliasGzip.size())) ;					// tagと圧縮元組を実バイトへ結びます
	const auto aliasOuter = envelope( aliasRaw, key.sign( aliasRaw), keyId) ;	// 同じ試験RAM鍵です
	// 変更後の元レコードも同じ試験鍵へ結び付けたマニフェスト認証結果
	const auto aliasManifest =
		signed_index_detail::authenticateWithTrustKeys( aliasOuter, now, std::nullopt, trust) ;
	// 試験用の追加行も通常の署名・バイト検査を通してから読み込みます
	if( !aliasManifest.manifest) {
		throw std::runtime_error( "archive terms reuse manifest") ;
	}

	// 別名候補の復号へ渡す前に署名済みの元圧縮バイトを照合した結果
	const auto aliasAsset = authenticateIndexAssetBytes( *aliasManifest.manifest, aliasGzip, now) ;
	// 完全な元圧縮が確認できる場合だけ新しい隔離storeへ進みます
	if( !aliasAsset.receipt) {
		throw std::runtime_error( "archive terms reuse asset") ;
	}

	const auto aliasBase =
		// 本文は元一件を保持します
		readSignedIndexRecords( *aliasAsset.receipt, now) ;
	auto aliasStore =
		// 実稼働領域を使用しません
		signed_index_store_detail::Access::createIsolated( trust) ;
	// 異なる署名byteを元世代保全と衝突させないよう、独立した隔離storeへ保存します
	if( !aliasBase.receipt || !aliasStore.store ||
	   !aliasStore.store->commit( *aliasBase.receipt, aliasOuter, aliasGzip, now).snapshot) {
		throw std::runtime_error( "archive terms reuse commit") ;
	}

	runSavedArchiveTermsConsumer( context,
								 std::shared_ptr<SignedIndexStore>{std::move( aliasStore.store)},
								 now, {page, document, zip}, device, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元取得を保持した索引追加欄と、既存の展開内容および有効性を照合します
 * @param[in,out] context 共通試験集計です
 * @param[in] legacyGzipPath 追加欄を持たない元GZipです
 * @param[in] manifestPath 追加欄を含む実圧縮hashを持つ未署名原manifestです
 * @param[in] gzipPath 同manifestの追加欄付きGZipです
 * @note 署名と信頼鍵はRAM内の試験用です。追加欄が期限に達した時刻も独立に検査します
 */
//------------------------------------------------------------------------------
void runSignedIndexSupplementFixtureTests( TestContext				  &context,
										  const std::filesystem::path &legacyGzipPath,
										  const std::filesystem::path &manifestPath,
										  const std::filesystem::path &gzipPath)
{
	const ComApartment apartment( COINIT_MULTITHREADED) ;	// 元OS条件を解釈する試験用MTAです
	// 追加欄を含むファイルの通常領域と比較する基準の圧縮本文
	const auto		   legacyGzip = readDistributionFixture( legacyGzipPath, INDEX_ASSET_MAX_BYTES) ;
	// 試験で署名する元マニフェストの実バイト。個別上限内に限定します
	const auto		   raw = readDistributionFixture( manifestPath, INDEX_MANIFEST_MAX_BYTES) ;
	// 追加欄を含む試験用圧縮物の元バイト
	const auto		   compressed = readDistributionFixture( gzipPath, INDEX_ASSET_MAX_BYTES) ;
	// 署名対象の元期限を本番の読取りと同じ時点で評価するUTC秒
	const auto now = std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now()) ;
	RamKey	   key ;	// 鍵を永続化しない試験用署名器です
	key.generate( 3072U) ;
	const auto keyId = index_distribution_trust::KEY_ID ;	// manifestと同じ鍵IDを隔離して使います
	// この試験で生成した鍵の公開部分だけを登録した検証集合
	const std::array<signed_index_detail::TrustKey, 1U> trust{{{keyId, key.publicBlob}}} ;
	// 実ファイルの元マニフェストを試験鍵で署名し、端末側入口で認証した結果
	const auto manifest = signed_index_detail::authenticateWithTrustKeys(
		envelope( raw, key.sign( raw), keyId), now, std::nullopt, trust) ;
	// マニフェストの認証が成立しなければ元配布の照合を続けません
	if( !manifest.manifest) {
		throw std::runtime_error( "supplement fixture manifest authentication failed") ;
	}

	// 同マニフェストの元ハッシュと圧縮物の全バイトを照合した結果
	const auto asset =
		authenticateIndexAssetBytes( *manifest.manifest, std::as_bytes( std::span{compressed}), now) ;
	// 元転送物の認証が成立しなければ本文と追加欄を参照しません
	if( !asset.receipt) {
		throw std::runtime_error( "supplement fixture asset authentication failed") ;
	}

	std::vector<std::byte> legacy ;	// 旧GZipを別に展開します
	// 比較用の旧圧縮本文を共通上限内で展開した診断値
	const auto legacyError = decompressOfficialGzip( std::as_bytes( std::span{legacyGzip}),
													INDEX_ASSET_EXPANDED_MAX_BYTES, legacy) ;
	DRIVERCRATE_EXPECT( context, legacyError == 0 && !legacy.empty() &&
									assetText( legacy) == assetText( asset.receipt->expandedBytes())) ;
	const auto existing =
		// 旧本文の全recordを検査します
		readSignedIndexRecords( *asset.receipt, now) ;
	// 従来本文を確認できない場合は追加欄と旧本文を比較できません
	if( !existing.receipt) {
		throw std::runtime_error( "supplement fixture base record validation failed") ;
	}

	// 同じ署名済み本文と結び付いた追加欄の読取り結果
	const auto supplement = readSignedIndexSupplementRecords( *existing.receipt, now) ;
	const auto transport  = asset.receipt->readSupplement( now) ;	// 確認済み追加欄の原期限です
	std::cout << "SUPPLEMENT_FIXTURE transport=" << static_cast<int>( supplement.transportStatus)
			  << " status=" << static_cast<int>( supplement.status)
			  << " legacyRecords=" << existing.receipt->records().size()
			  << " extraSources=" << supplement.sources.size()
			  << " extraRecords=" << supplement.records.size()
			  << " extraExpiry=" << transport.expiresAtUtc.time_since_epoch().count() << '\n' ;
	DRIVERCRATE_EXPECT( context,
					   supplement.transportStatus == IndexAssetSupplementStatus::BYTE_VALIDATED &&
						   supplement.status == IndexRecordsStatus::SCHEMA_VALIDATED &&
						   !supplement.records.empty()) ;
	// 追加欄の各行について原文のハッシュを出力し、元取得物との照合に使います
	for( const auto &record : supplement.records) {
		std::cout << "SUPPLEMENT_FIXTURE recordSha256=" << recordDigest( key, record.originalBytes)
				  << " ids=" << record.publishedIdentityEvidence.pnpIds.size() << '\n' ;
		DRIVERCRATE_EXPECT( context, record.recordSha256 == key.digest( record.originalBytes)) ;
	}

	// 同じreceiptで元期限の到達を検査します
	if( transport.status == IndexAssetSupplementStatus::BYTE_VALIDATED &&
	   transport.expiresAtUtc < manifest.manifest->data().expiresAtUtc) {
		const auto deadline = transport.expiresAtUtc ;	// 旧本文はまだ有効です
		// 同じ認証済み本文に対し、追加欄の元期限と等しい時刻での読取り結果
		const auto expired = readSignedIndexSupplementRecords( *existing.receipt, deadline) ;
		DRIVERCRATE_EXPECT( context,
						   expired.transportStatus == IndexAssetSupplementStatus::EXPIRED &&
							   expired.records.empty() &&
							   readSignedIndexRecords( *asset.receipt, deadline).receipt) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 実producerの同一manifest/GZip原byteをRAM認証し通常照合へ渡します
 * @param[in,out] context 共通assertion集計先です
 * @param[in] manifestPath 原producerが保存した未署名manifestです
 * @param[in] gzipPath 同producerの原GZipです
 * @param[in] package 同runを生成した自己所有packageです
 * @param[in] nativeMerge trueだけ固定Intel一原recordを未照合のまま四record集合へ保持します
 * @param[in] metadataBound trueだけ新metadata一recordとpackage引数の人工terms原bodyを検査します
 * @note 秘密鍵はRAM限定です。製品trustへ登録せず、実導入/通信を行いません
 */
//------------------------------------------------------------------------------
void runDistributionApplicationFixtureTests( TestContext					&context,
											const std::filesystem::path &manifestPath,
											const std::filesystem::path &gzipPath,
											const std::filesystem::path &package,
											const bool nativeMerge, const bool metadataBound)
{
	const auto before = context.assertionCount() ;	// 一貫試験の元開始値です
	const auto raw =
		// 同producer原manifestです
		readDistributionFixture( manifestPath, INDEX_MANIFEST_MAX_BYTES) ;
	const auto compressed =
		// 同producer原GZipです
		readDistributionFixture( gzipPath, INDEX_ASSET_MAX_BYTES) ;
	const auto now = std::chrono::floor<std::chrono::seconds>(
		// 実runと同じ有限UTCです
		std::chrono::system_clock::now()) ;
	RamKey key ;	// 既存RAM-only fixture鍵です。永続storeを開きません
	key.generate( 3072U) ;
	const auto keyId = index_distribution_trust::KEY_ID ;	// 原producerの同keyIdです
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{keyId, key.publicBlob}}} ;	// Test隔離trustだけです
	const auto outer =
		// 原manifest byteをそのままRAM署名します
		envelope( raw, key.sign( raw), keyId) ;
	const auto manifest = signed_index_detail::authenticateWithTrustKeys(
		outer, now, std::nullopt, trust) ;	// 通常認証wrapperです
	DRIVERCRATE_EXPECT( context, manifest.manifest &&
									manifest.manifest->data().manifestBytes == raw &&
									manifest.status == SignedIndexManifestStatus::AUTHENTICATED) ;
	// 認証失敗で別の手書きmanifestへ置換しません
	if( !manifest.manifest) {
		throw std::runtime_error( "producer raw manifest authentication failed") ;
	}

	const IndexManifestHighWater newer{manifest.manifest->data().generation + 1U,
									   // 元より新しい保護headの有限値です
									   manifest.manifest->data().manifestSha256} ;
	const auto					 staleGeneration = signed_index_detail::authenticateWithTrustKeys(
		  outer, now, newer, trust) ;	// 原byteを再署名/変更しません
	DRIVERCRATE_EXPECT( context, !staleGeneration.manifest &&
									staleGeneration.status ==
										SignedIndexManifestStatus::GENERATION_ROLLBACK) ;

	const auto bytes = std::as_bytes(
		std::span<const char>{compressed.data(), compressed.size()}) ;	// 同原GZip viewです
	const auto asset =
		// 通常hash/GZip/CRCです
		authenticateIndexAssetBytes( *manifest.manifest, bytes, now) ;
	DRIVERCRATE_EXPECT( context, asset.receipt.has_value()) ;
	// 元asset認証なしにrecordを構成しません
	if( !asset.receipt) {
		throw std::runtime_error( "producer raw asset authentication failed") ;
	}

	std::string altered = compressed ;	// 原producer byteは保持し、拒否用copy一byteだけを変更します
	altered.back() ^= 1 ;
	const auto alteredBytes =
		// 不一致copyです
		std::as_bytes( std::span<const char>{altered.data(), altered.size()}) ;
	DRIVERCRATE_EXPECT( context,
					   !authenticateIndexAssetBytes( *manifest.manifest, alteredBytes, now).receipt) ;

	const auto records =
		// 通常record/quality codecです
		readSignedIndexRecords( *asset.receipt, now) ;
	DRIVERCRATE_EXPECT( context,
					   records.receipt &&
						   records.receipt->records().size() == (metadataBound ? 1U
																 : nativeMerge ? 4U
																			   : 3U) &&
						   records.receipt->actualQuality().sourceCount == (metadataBound ? 1U
																			: nativeMerge ? 3U
																						  : 2U) &&
						   records.receipt->actualQuality().contentInspectedCount ==
							   (metadataBound ? 1U
								: nativeMerge ? 4U
											  : 3U)) ;
	// 生成record失敗を別の手書きv2へ置換しません
	if( !records.receipt) {
		throw std::runtime_error( "producer raw records failed") ;
	}

	auto opened =
		// 自作保護rootだけです
		signed_index_store_detail::Access::createIsolated( trust) ;
	DRIVERCRATE_EXPECT( context, opened.store != nullptr) ;
	const auto committed =
		// 同原byteを原子保存します
		opened.store->commit( *records.receipt, outer, bytes, now) ;
	DRIVERCRATE_EXPECT( context, committed.snapshot.has_value()) ;
	auto reloaded = opened.store->reload( now) ;	// 通常保存原byteの再認証です
	DRIVERCRATE_EXPECT( context, reloaded.snapshot &&
									reloaded.snapshot->originalEnvelope() == outer &&
									reloaded.snapshot->originalGzip().size() == bytes.size() &&
									std::ranges::equal( reloaded.snapshot->originalGzip(), bytes)) ;
	auto snapshot = std::make_shared<const AuthenticatedIndexSnapshot>(
		// 同認証済保存ownerです
		std::move( *reloaded.snapshot)) ;
	const IndexLookupContext original{301U, 302U, 303U} ;	// 同scanの元contextです
	// 新metadata一recordを同じreader/原byte/通常adapterへ渡し、実端末/CAT成功を作りません
	if( metadataBound) {
		const std::array<std::wstring, 2U> present{
			L"artificial-device-a", L"artificial-device-b"} ;	// 公開ID由来の架空deviceです
		LookupResolver resolver ;								// 実inventoryへfallbackしない既存fakeです
		auto matched = lookupSignedIndexRecords( snapshot, original, original, present, {}, now,
												&resolver) ;	// 原認証recordだけです
		DRIVERCRATE_EXPECT( context, matched.lookup && !matched.lookup->relations().empty()) ;
		// 未照合を取得候補adapterの成功へ補完しません
		if( !matched.lookup || matched.lookup->relations().empty()) {
			throw std::runtime_error( "metadata bound lookup failed") ;
		}

		runMetadataBoundAdapterFixtureTests(
			context, std::make_shared<const SignedIndexRecordLookup>( std::move( *matched.lookup)),
			now,
			readDistributionFixture(
				package,
				4U * 1024U * 1024U)) ;	// 新二文書fixtureだけの入力枠です。製品上限は変えません
		std::cout
			<< "METADATA_BOUND_APPLICATION assertions=" << context.assertionCount() - before
			<< " rawManifestUnchanged=1 rawGzipUnchanged=1 ramFixtureSignature=1 realIndexSignature=0 actualCatAccepted=0 realDevice=0\n" ;
		return ;
	}

	auto changedContext = original ;	// 次scanの文脈だけを変更します
	++changedContext.scanSessionId ;
	DRIVERCRATE_EXPECT(
		context,
		lookupSignedIndexRecords( snapshot, original, changedContext, {}, {}, now, nullptr).status ==
			IndexRecordLookupStatus::STALE_CONTEXT) ;
	std::vector<DistributionBindingDevice> devices ;	// 公開IDは同実producer recordだけから読みます
	std::size_t unmatchedNative{} ;						// 固定追加recordを成功deviceへ数えない件数です
	// 生成元全三recordの原INF/Models/版を切り捨てず保持します
	for( const auto &record : records.receipt->records()) {
		// 追加Intel recordも同codec/storeに保持し、架空三deviceのIDへは変換しません
		if( nativeMerge && record.sourceId == "intel-ethernet-win11" &&
		   record.recordId == "intel-wired-31-2-2-win11") {
			++unmatchedNative ;
			continue ;
		}

		const auto &identity = record.publishedIdentityEvidence ;	// 同原INFから投影した公開値です
		DRIVERCRATE_EXPECT( context, identity.pnpIds.size() == 1U && !identity.infIdentity.empty() &&
										!identity.modelSection.empty() &&
										record.version.value.has_value()) ;
		const auto widen = []( const std::string_view value) {
			return std::wstring{value.begin(), value.end()} ;
		} ; // 架空ASCIIだけです
		devices.push_back( {widen( identity.pnpIds.front().value), widen( identity.infIdentity),
						   widen( identity.modelSection), widen( *record.version.value)}) ;
		std::cout << "DISTRIBUTION_AUTHENTICATED_RECORD inf=" << identity.infIdentity
				  << " models=" << identity.modelSection << " version=" << *record.version.value
				  << " originalBytes=" << record.originalBytes.size() << '\n' ;
	}

	// 追加modeはこの固定一recordだけが未照合で、元三deviceを減らしていません
	if( nativeMerge) {
		DRIVERCRATE_EXPECT( context, unmatchedNative == 1U && devices.size() == 3U) ;
	}

	const auto zipA	 = readDistributionFixture( package / L"fixture-payload.bin",
											   1048576U) ;	// 同runのA原archiveです
	const auto zipB	 = readDistributionFixture( package / L"fixture-payload-b.bin",
											   1048576U) ;	// 同runのB原archiveです
	auto	   store = std::shared_ptr<SignedIndexStore>{	// 全worker終端まで隔離rootを所有します
													 std::move( opened.store)} ;
	auto	   weeklyDevices = devices ;	// 同じ公開tupleを7日後にも検査し、原recordを変更しません
	runNormalDistributionApplicationTests( context, store, now, zipA, zipB, std::move( devices)) ;
	const auto baseAssertions = context.assertionCount() - before ;	// 従来153/154の分母です
	const auto weekNow		  = now + std::chrono::days{7} ;		// OS時計を変えない明示fixture時刻です
	// 週次公開preflightを満たす新規原byteだけが7日後の通常appを確認します
	if( weekNow < manifest.manifest->data().expiresAtUtc) {
		runNormalDistributionApplicationTests( context, store, weekNow, zipA, zipB,
											  std::move( weeklyDevices)) ;
		std::cout << "DISTRIBUTION_WEEKLY_APPLICATION days=7 originalExpiryUnchanged=1 assertions="
				  << context.assertionCount() - before - baseAssertions << '\n' ;
	}

	std::cout << "DISTRIBUTION_AUTHENTICATION assertions=" << baseAssertions
			  << " rawManifestUnchanged=1 rawGzipUnchanged=1 ramKeyOnly=1 actualCatAccepted=0\n" ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原Intel record/期限/実archiveを通常appへ明示historical replayします
 * @param[in,out] context 元assertion集計先です
 * @param[in] manifestPath 現producerで六原入力を元publication秒へ投影したmanifestです
 * @param[in] gzipPath 同producerの全22IDを持つ原GZip、負例3だけはID欠損copyです
 * @param[in] archivePath 元40477087Bのarchiveです。別byte/hashを拒否します
 * @param[in] termsPath 元173557BのHTTP規約documentです
 * @param[in] scenario 0正常、1誤byte、2同意欠落、3全ID tuple欠損です
 * @note RAM鍵/隔離storeとhistorical fake時計だけを使い、実現在UTCの失効拒否も確認します。Windows標準署名APIは実行し、証明書読取通信は未観測です。実
 *       device/導入/driver HTTPは0です
 */
//------------------------------------------------------------------------------
void runNativeIntelArchiveFixtureTests( TestContext				   &context,
									   const std::filesystem::path &manifestPath,
									   const std::filesystem::path &gzipPath,
									   const std::filesystem::path &archivePath,
									   const std::filesystem::path &termsPath,
									   const unsigned				scenario)
{
	const auto read = []( const std::filesystem::path &path, const std::uintmax_t maximum) {
		const auto size = std::filesystem::file_size( path) ;	// 確保前の有限原byte数です
		// 欠損/過大byteからfixture成功を作りません
		if( size == 0U || size > maximum) {
			throw std::runtime_error( "native Intel fixture size") ;
		}

		std::ifstream input{path, std::ios::binary} ;					// 元fileは読取りだけです
		std::string	  bytes( static_cast<std::size_t>( size), '\0') ;	// 原byteを所有します
		// 短読/長さ変化を成功へ補完しません
		if( !input.read( bytes.data(), static_cast<std::streamsize>( size)) ||
		   std::filesystem::file_size( path) != size) {
			throw std::runtime_error( "native Intel fixture read") ;
		}

		return bytes ;
	} ; // 原archive/原documentを変更しません
	const auto raw =
		// 元publication/期限を保持します
		read( manifestPath, INDEX_MANIFEST_MAX_BYTES) ;
	const auto	 compressed = read( gzipPath, INDEX_ASSET_MAX_BYTES) ;	// 同現producer byteです
	const auto	 archive	= read( archivePath, 134217728U) ;			// 元40MB archiveです
	const auto	 terms		= read( termsPath, 1048576U) ;				// 同規約bodyです
	std::wstring digest ;												// 元archiveを実byteで照合します
	DRIVERCRATE_EXPECT(
		context, archive.size() == 40477087U &&
					 computeDriverContainerSha256( archive, digest) == 0U &&
					 digest == L"2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5") ;
	// 元hash不一致を負例の合格へ取り込みません
	if( archive.size() != 40477087U ||
	   digest != L"2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5") {
		throw std::runtime_error( "original Intel archive pin") ;
	}

	const auto replayUtc = std::chrono::sys_seconds{
		std::chrono::seconds{1792341124}} ;	// 元publication秒だけの明示fake clockです
	const auto actualUtc = std::chrono::floor<std::chrono::seconds>(
		// OS時計は変更しません
		std::chrono::system_clock::now()) ;
	RamKey key ;	// 非永続RAM署名だけです
	key.generate( 3072U) ;
	const auto keyId = index_distribution_trust::KEY_ID ;	// 原recordを通常取得policyへ結びます
	const std::array<signed_index_detail::TrustKey, 1U> trust{
		{{keyId, key.publicBlob}}} ;							// 隔離test trustです
	const auto outer = envelope( raw, key.sign( raw), keyId) ;	// 原manifestを再serializationしません
	const auto authenticated = signed_index_detail::authenticateWithTrustKeys(
		outer, replayUtc, std::nullopt, trust) ;	// 明示historicalです
	DRIVERCRATE_EXPECT( context, authenticated.manifest.has_value()) ;
	// 認証不成立を以後の拒否成功へ数えません
	if( !authenticated.manifest) {
		throw std::runtime_error( "native Intel historical manifest") ;
	}

	const auto current = signed_index_detail::authenticateWithTrustKeys(
		outer, actualUtc, std::nullopt, trust) ;	// 実現在UTCの独立拒否です
	DRIVERCRATE_EXPECT( context, !current.manifest &&
									current.status == SignedIndexManifestStatus::INVALID_TIME) ;
	const auto expiry = signed_index_detail::authenticateWithTrustKeys(
		outer, authenticated.manifest->data().expiresAtUtc, std::nullopt,
		trust) ;	// 原期限秒ちょうどです
	DRIVERCRATE_EXPECT( context, !expiry.manifest &&
									expiry.status == SignedIndexManifestStatus::INVALID_TIME) ;
	const auto bytes = std::as_bytes(
		std::span<const char>{compressed.data(), compressed.size()}) ;	// 同原GZip viewです
	const auto asset = authenticateIndexAssetBytes( *authenticated.manifest, bytes,
												   replayUtc) ;	// 通常hash/GZip境界です
	DRIVERCRATE_EXPECT( context, asset.receipt.has_value()) ;
	// 原asset不成立を別indexへ置換しません
	if( !asset.receipt) {
		throw std::runtime_error( "native Intel original asset") ;
	}

	const auto records =
		// 現10field readerだけです
		readSignedIndexRecords( *asset.receipt, replayUtc) ;
	DRIVERCRATE_EXPECT( context, records.receipt && records.receipt->records().size() == 1U) ;
	// 元record不成立を手書きDTOへ補完しません
	if( !records.receipt || records.receipt->records().size() != 1U) {
		throw std::runtime_error( "native Intel original record") ;
	}

	const auto &record	 = records.receipt->records().front() ;	// 同認証原recordです
	const auto &identity = record.publishedIdentityEvidence ;	// 全tupleを元workerが後で比較します
	DRIVERCRATE_EXPECT( context, record.sourceId == "intel-ethernet-win11" &&
									record.recordId == "intel-wired-31-2-2-win11" &&
									identity.pnpIds.size() == (scenario == 3U ? 21U : 22U) &&
									identity.infIdentity == "PRO2500/Winx64/W11/e2fn.inf" &&
									identity.modelSection == "Intel.NTamd64.10.0.1..22000" &&
									record.version.value == "2.1.5.7") ;
	// 正常caseだけ全72INFの個別拒否を既存共通APIから保持します
	if( scenario == 0U) {
		ComApartment apartment{COINIT_MULTITHREADED} ;	// 同threadの実署名APIを所有します
		OfficialDownloadWorkspace	  workspace ;		// 原archiveの保護copyだけを所有します
		DriverArchiveInput			  input ;			// 実copyの原hash/sizeです
		OfficialDriverArchiveFormat	  format{} ;		// 元copyが確認した形式です
		CommonDriverPackageInspection inspection ;		// 全個別結果を保持します
		DRIVERCRATE_EXPECT( context,
						   SUCCEEDED( apartment.result()) &&
							   copyLocalDriverArchive( archivePath.native(), 385U, workspace, input,
													  format) == 0U &&
							   inspectCommonDriverPackage( input, format, inspection) == 0U &&
							   inspection.infs.size() == 72U) ;
		bool		selectedVerified{} ;	// 元一INFの実CAT/publisher/参照本体を確認します
		std::size_t refused{} ;				// 成功行から省略しない残15行です
		// 全元行のstate/errorを保存し、他INFの失敗を当該一件成功から独立させます
		for( const auto &inf : inspection.infs) {
			std::wcout << L"NATIVE_INTEL_INF path=" << inf.infRelativePath << L" state="
					   << static_cast<unsigned>( inf.state) << L" error=" << inf.error << L'\n' ;
			refused += inf.state != CommonInfInspectionState::VERIFIED ? 1U : 0U ;
			// 指定元e2fnだけを個別正例へ数えます
			if( inf.infRelativePath == L"PRO2500\\Winx64\\W11\\e2fn.inf" &&
			   inf.state == CommonInfInspectionState::VERIFIED && inf.workspace &&
			   inf.closure.packages.size() == 1U) {
				const auto	&package = inf.closure.packages.front() ;	// 同実閉包だけです
				std::wstring publisher ;								// 元CATの実Windows署名者です
				selectedVerified =
					reverifyCommonDriverInf( inf) == 0U &&
					readWindowsInfPackagePublisher( *inf.workspace, package, publisher) == 0U &&
					publisher == L"Microsoft Windows Hardware Compatibility Publisher" ;
				DRIVERCRATE_EXPECT( context, package.sourceFiles.size() == 2U) ;
				std::wcout << L"NATIVE_INTEL_SELECTED publisher=" << publisher
						   << L" referencedFiles=" << package.sourceFiles.size() << L" verified="
						   << selectedVerified << L'\n' ;
			}
		}

		DRIVERCRATE_EXPECT( context, selectedVerified && refused == 15U) ;
	}

	auto opened =
		// 製品storeを開きません
		signed_index_store_detail::Access::createIsolated( trust) ;
	DRIVERCRATE_EXPECT(
		context,
		opened.store && opened.store->commit( *records.receipt, outer, bytes, replayUtc).snapshot) ;
	const auto widen = []( const std::string_view text) {
		return std::wstring{text.begin(), text.end()} ;
	} ; // 原公開ASCIIだけです
	DistributionBindingDevice device{widen( identity.pnpIds.front().value),
									 widen( identity.infIdentity), widen( identity.modelSection),
									 // 明示fake local一deviceです
									 widen( *record.version.value)} ;
	auto					  store =
		std::shared_ptr<SignedIndexStore>{std::move( opened.store)} ;	// 全worker終端まで保持します
	// 元scopeを重複backendで上書きできないことを、実署名呼出し前に確認します
	{
		auto adapter =
			// 本threadだけです
			driver_package_signature_detail::Access::createNativeAdapter() ;
		DRIVERCRATE_EXPECT(
			context, adapter && !driver_package_signature_detail::Access::createNativeAdapter()) ;
	}

	runNormalNativeIntelArchiveCase( context, std::move( store), replayUtc, archive, terms,
									std::move( device), scenario) ;
	std::cout
		<< "NATIVE_INTEL_AUTHENTICATION originalExpiryPreserved=1 actualUtcExpired=1 ramKeyOnly=1 fakeHistoricalUtc=1792341124\n" ;
}
//------------------------------------------------------------------------------
/**
 * @brief 人工署名索引からWindows-only driver DATAの通常選択/保護導入経路を検査します
 * @param[in,out] context 有限assertion集計先です
 * @note 実CAB/実CAT検査Aと分ける人工fixture Bです。HTTP、復旧、NewDevは完全fakeです
 */
//------------------------------------------------------------------------------
void runWindowsManagedDriverPackageFixtureTests( TestContext &context)
{
	RamKey key ;	// この人工試験だけの非永続署名keyです
	key.generate( 3072U) ;
	const auto modelStart = context.assertionCount() ;	// 新しい共通選択群だけの分母です
	// 六条件を別の原署名record/隔離storeへ結び、成功状態を再利用しません
	for( unsigned scenario = 0U; scenario < 6U; ++scenario) {
		std::string inf ;	// 当該人工archiveの全原INF byteです
		const auto	zip = normalWorkerDriverZip( false, &inf, {}, true, 0U,
												// 両Modelsを持つ小人工INFの全原archiveです
												scenario == 1U ? 2U : 1U) ;
		auto		raw =
			// 原schemaに従う同意不要の人工recordです
			descriptorRecord( descriptorFixture()) ;
		const auto hash = recordDigest( key, zip) ;	// 全payloadの元byte hashです
		raw				= replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
		raw				= replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
		raw				= replaced( std::move( raw), "\"valueBytes\":1234",
								   "\"valueBytes\":" + std::to_string( zip.size())) ;
		raw				= replaced( std::move( raw), "{11111111-2222-3333-4444-555555555555}",
								   "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
		raw				= replaced( std::move( raw), "drivers/fixture.inf", "fixture.inf") ;
		raw = replaced( std::move( raw), "Fixture.NTamd64", "Models.NTamd64.10.0...17134") ;
		raw = replaced( std::move( raw), "\"version\":" + recordKnown( "1.2.3.4"),
					   "\"version\":" + recordKnown( "1.0.0.0")) ;
		raw = replaced(
			std::move( raw),
			"\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
				std::string{RECORD_EVIDENCE_HASH},
			"\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
				recordDigest( key, inf)) ;
		raw = replaced( std::move( raw), "\"inspectionStage\":\"METADATA_ONLY\"",
					   "\"inspectionStage\":\"CONTENT_INSPECTED\"") ;
		std::vector<std::string> rows{
			raw, replaced( raw, "\"recordId\":\"metadata\"",
						  "\"recordId\":\"second\"")} ;	// 両原recordを別byte/hashで認証します
		rows[1] = replaced( std::move( rows[1]), "Models.NTamd64.10.0...17134",
						   scenario == 2U ? "Models.NTamd64.10.0...19041"
										  : "Models.NTamd64.10.0...26200") ;
		// 同targetの別INFを当該選択集合へfallbackしません
		if( scenario == 3U) {
			rows[0] = replaced( std::move( rows[0]), "\"infIdentity\":\"fixture.inf\"",
							   "\"infIdentity\":\"other.inf\"") ;
		}

		std::shared_ptr<SignedIndexStore> store ;	// 元全recordの正規commit/reload所有者です
		const auto						  snapshot =
			lookupSnapshot( key, rows.front(), rows.size(), &store, 9U,
						   rows) ;									// 元二recordを正規署名/隔離保存/reloadした不変snapshotです
		const auto records = snapshot->schemaReceipt().records() ;	// 値比較負例だけの借用です
		// 元codec成功値だけを比較し、この変形copyから認証/Grantを発行しません
		if( scenario == 0U) {
			DRIVERCRATE_EXPECT( context, areEquivalentIndexModelChoices( records[0], records[1])) ;
			auto identical = records[0] ;	// 別recordでも同内容の表示だけは一つにできます
			identical.recordId += "-display-only" ;
			identical.product += " display alias" ;
			DRIVERCRATE_EXPECT( context, areIdenticalIndexDisplayChoices( records[0], identical)) ;
			DRIVERCRATE_EXPECT( context, !areIdenticalIndexDisplayChoices( records[0], records[1])) ;
			// 同version/targetでも残す内容・日付・取得元・不明を独立に変えます
			for( unsigned mutation = 0U; mutation < 10U; ++mutation) {
				auto changed = identical ;	// 権限を生成しない一field負例です
				// 既payload/policyとINF証拠の独立境界を省略しません
				switch( mutation) {
					// 別の取得元を共通Provider名だけでまとめません
					case 0U:
						changed.sourceId += "-other" ;
						break ;

					// 別payloadの同versionを残します
					case 1U:
						(*changed.packageEvidence.publishedHash.sha256)[0] ^= 1U ;
						break ;

					// 同payloadの別INFを残します
					case 2U:
						changed.publishedIdentityEvidence.infIdentity = "other.inf" ;
						break ;

					// 同名INFでも別byteを残します
					case 3U:
						(*changed.publishedIdentityEvidence.evidenceSha256)[0] ^= 1U ;
						break ;

					// 別Modelsは既私有選択groupの契約へ残します
					case 4U:
						changed.publishedIdentityEvidence.modelSection += "-other" ;
						break ;

					// 日付の差を空のUI日付で消しません
					case 5U:
						changed.publishedDate.value = "2026-11-01" ;
						break ;

					// バージョン不明を同一内容へ補完しません
					case 6U:
						changed.version.value.reset() ;
						break ;

					// 未知の内容証拠を別recordから補完しません
					case 7U:
						changed.publishedIdentityEvidence.evidenceSha256.reset() ;
						break ;

					// 全公表IDの部分集合を同じ構成にしません
					case 8U:
						changed.publishedIdentityEvidence.pnpIds.pop_back() ;
						break ;

					// 原期限差を統合で延長しません
					default:
						changed.acquisitionDescriptor->attestation->validUntilUtc +=
							std::chrono::seconds{1} ;
						break ;
				}

				DRIVERCRATE_EXPECT( context, !areIdenticalIndexDisplayChoices( records[0], changed)) ;
			}

			// 値比較だけの十七負例を原認証/通常workerの成功と分離して確認します
			for( unsigned mutation = 0U; mutation < 17U; ++mutation) {
				auto changed = records[1] ;	// 一field差の非authority値です
				// 同payloadだけでは統合できない独立境界を一つずつ変形します
				switch( mutation) {
					// 別root INF memberは同じdriver意図ではありません
					case 0U:
						changed.publishedIdentityEvidence.infIdentity = "other.inf" ;
						break ;

					// 別INF原byteを同内容として扱いません
					case 1U:
						(*changed.publishedIdentityEvidence.evidenceSha256)[0] ^= 1U ;
						break ;

					// 別Classを同Windows選択へ合併しません
					case 2U:
						changed.publishedIdentityEvidence.classGuid =
							"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
						break ;

					// 異版は同一INF代替表現へ統合しません
					case 3U:
						changed.version.value = "2.0.0.0" ;
						break ;

					// 別sourceの根拠を同じ私有集合へ流用しません
					case 4U:
						changed.sourceId += "-other" ;
						break ;

					// 外側hash差を同target名で補完しません
					case 5U:
						(*changed.packageEvidence.publishedHash.sha256)[0] ^= 1U ;
						break ;

					// 元size差も同じ配布物の根拠ではありません
					case 6U:
						++*changed.packageEvidence.size.value ;
						break ;

					// 規約根拠の差は別選択のままです
					case 7U:
						changed.acquisitionDescriptor->terms.evidenceUrl += "/other" ;
						break ;

					// 原期限を別recordから延長しません
					case 8U:
						changed.acquisitionDescriptor->attestation->validUntilUtc +=
							std::chrono::seconds{1} ;
						break ;

					// 別Models baseを同じOS装飾として扱いません
					case 9U:
						changed.publishedIdentityEvidence.modelSection =
							"Other.NTamd64.10.0...26200" ;
						break ;

					// ID部分集合を全ID一致にしません
					case 10U:
						changed.publishedIdentityEvidence.pnpIds.pop_back() ;
						break ;

					// ID種別差を値の文字列だけで統合しません
					case 11U:
						changed.publishedIdentityEvidence.pnpIds.front().kind =
							IndexPnpIdKind::COMPATIBLE ;
						break ;

					// 未知の装飾を任意の最新Windowsへ読み替えません
					case 12U:
						changed.publishedIdentityEvidence.modelSection =
							"Models.NTamd64.10.x...26200" ;
						break ;

					// 同Modelsの重複は元の曖昧な別参照として保持します
					case 13U:
						changed.publishedIdentityEvidence.modelSection =
							records[0].publishedIdentityEvidence.modelSection ;
						break ;

					// 取得route差を同payload申告で消しません
					case 14U:
						changed.acquisitionDescriptor->payloadUrl += "-other" ;
						break ;

					// 別nested memberの同basenameを混同しません
					case 15U:
						changed.publishedIdentityEvidence.nestedArchiveIdentity = "other.zip" ;
						break ;

					// 明示した取得上限の差もpolicy差です
					default:
						--changed.acquisitionDescriptor->maximumBytes ;
						break ;
				}

				DRIVERCRATE_EXPECT( context, !areEquivalentIndexModelChoices( records[0], changed)) ;
			}
		}

		std::cout << "MODEL_CHOICE_CASE scenario=" << scenario
				  << " originalRecords=2 primaryModels=17134 actualModels="
				  << (scenario == 1U ? "17134+26200" : "26200") << '\n' ;
		runNormalIndexIdentityBindingCase(
			context, store, NOW, zip, scenario == 3U ? 2U : 1U, scenario == 0U ? 1U : 0U, 1U,
			scenario == 0U ? PreparedInstallResolutionState::READY
						   : PreparedInstallResolutionState::NOT_READY,
			scenario == 4U	 ? 1U
			: scenario == 5U ? 2U
							 : 0U) ;
	}

	std::cout << "MODEL_CHOICE_CASES cases=6 pureNegativeCases=17 assertions="
			  << context.assertionCount() - modelStart << " realNetwork=0 install=0\n" ;
	// 正常/foreign/app/MSI/三つの正式到達autorunを各原ZIPと各元署名recordへ結びます
	for( unsigned mode = 1U; mode <= 7U; ++mode) {
		std::string inf ;	// 同ZIPの原INF byteです
		const auto	zip =
			// 小さい完全人工packageです
			normalWorkerDriverZip( false, &inf, {}, true, mode) ;
		const auto hash = recordDigest( key, zip) ;	// 元payloadと実取得byteの同一性です
		auto	   raw =
			// 同意を偽装せず既存人工規約状態を使います
			descriptorRecord( descriptorFixture()) ;
		raw = replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
		raw = replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
		raw = replaced( std::move( raw), "\"valueBytes\":1234",
					   "\"valueBytes\":" + std::to_string( zip.size())) ;
		raw = replaced( std::move( raw), "{11111111-2222-3333-4444-555555555555}",
					   "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
		raw = replaced( std::move( raw), "drivers/fixture.inf", "fixture.inf") ;
		raw = replaced( std::move( raw), "Fixture.NTamd64", "Models.NTamd64") ;
		raw = replaced(
			std::move( raw),
			"\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
				std::string{RECORD_EVIDENCE_HASH},
			"\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
				recordDigest( key, inf)) ;
		raw = replaced( std::move( raw), "\"inspectionStage\":\"METADATA_ONLY\"",
					   "\"inspectionStage\":\"CONTENT_INSPECTED\"") ;
		std::shared_ptr<SignedIndexStore> store ;	// 製品storeとは別の実署名/保存/reload所有者です
		static_cast<void>( lookupSnapshot( key, raw, 1U, &store)) ;
		std::cout << "WINDOWS_MANAGED_SOURCE mode=" << mode << " payloadBytes=" << zip.size()
				  << " actualVendorPackage=0\n" ;
		runNormalSignedIndexCandidateBindingTests( context, std::move( store), NOW, zip) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 二種類の元Models行と短い元期限を含む人工索引を署名し通常workerへ渡します
 * @param[in,out] context 候補と指定導入の実到達を検証する集計先です
 * @note 同じZIPと署名recordを使い、端末・登録先・時刻の各条件だけを変えます
 */
//------------------------------------------------------------------------------
void runSignedIndexDeclarativeClassBindingTests( TestContext &context)
{
	constexpr std::string_view inf =	// 実ドライバー行と空サービスを持つ同一の人工INFです
		"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=DCFixtureBridge\r\n"
		"ClassGuid={c054bd69-a76e-4caa-a915-e3ce9a285b62}\r\nProvider=Fixture Vendor\r\n"
		"DriverVer=10/11/2026,1.0.0.0\r\nCatalogFile=fixture.cat\r\n"
		"[Manufacturer]\r\nVendor=Models,NTamd64\r\n[Models.NTamd64]\r\n"
		"Kernel=Install,TESTBUS\\SYNTH_0001,TESTBUS\\SYNTH_COMPAT,TESTBUS\\SYNTH_FALLBACK\r\n"
		"Null=NoDriver,TESTBUS\\SYNTH_NULL\r\n"
		"[Install.NT]\r\nCopyFiles=DriverFiles\r\n"
		"[Install.NT.Services]\r\nAddService=FixtureKernel,2,KernelService\r\n"
		"[KernelService]\r\nServiceType=1\r\nStartType=3\r\nErrorControl=1\r\nServiceBinary=%12%\\fixture.sys\r\n"
		"[NoDriver.NT]\r\n[NoDriver.NT.Services]\r\nAddService=,2\r\n"
		"[DestinationDirs]\r\nDriverFiles=12\r\n[DriverFiles]\r\nfixture.sys\r\n"
		"[SourceDisksNames]\r\n1=fixture,,,\r\n[SourceDisksFiles]\r\nfixture.sys=1\r\n"
		"[ClassInstall32]\r\nAddReg=DisplayClass\r\n[DisplayClass]\r\n"
		"HKR,,,,%ClassLabel%\r\nHKR,,Icon,,-10\r\n[Strings]\r\nClassLabel=\"Fixture bridge devices\"\r\n" ;
	const auto zip =
		// 三memberの元byteです
		normalWorkerDriverZip( false, nullptr, {}, true, 0U, 0U, inf) ;
	RamKey key ;	// このfixtureだけの非永続CNG鍵です
	key.generate( 3072U) ;
	const auto hash = recordDigest( key, zip) ;	// 申告・計算の両方を同じ元byteに結びます
	auto	   raw	= descriptorRecord( descriptorFixture(),
									   distributionRecord( "declarative-bridge", true,
														  "CONTENT_INSPECTED")) ;	// 署名前の元recordです
	raw				= replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
	raw				= replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
	raw				= replaced( std::move( raw), "\"valueBytes\":1234",
							   "\"valueBytes\":" + std::to_string( zip.size())) ;
	raw				= replaced( std::move( raw), "{11111111-2222-3333-4444-555555555555}",
							   "{c054bd69-a76e-4caa-a915-e3ce9a285b62}") ;
	raw				= replaced( std::move( raw), "drivers/fixture.inf", "fixture.inf") ;
	raw				= replaced( std::move( raw), "Fixture.NTamd64", "Models.NTamd64") ;
	raw				= replaced( std::move( raw), "1.2.3.4", "1.0.0.0") ;
	raw				= replaced( std::move( raw), "2026-10-01", "2026-10-11") ;
	raw				= replaced( std::move( raw), "2026-10-12T03:00:00Z", "2026-10-11T06:04:00Z") ;
	raw				= replaced(
		std::move( raw), R"json("pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
		R"json("pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_NULL"},{"kind":"COMPATIBLE","value":"TESTBUS\\SYNTH_COMPAT"},{"kind":"COMPATIBLE","value":"TESTBUS\\SYNTH_FALLBACK"}])json") ;
	raw = replaced( std::move( raw),
				   "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
					   std::string{RECORD_EVIDENCE_HASH},
				   "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
					   recordDigest( key, inf)) ;
	std::shared_ptr<SignedIndexStore> store ;							// 通常reloadを行う隔離storeです
	const auto	snapshot = lookupSnapshot( key, raw, 1U, &store) ;		// 発行時と同じ記録を再認証します
	const auto &record = snapshot->schemaReceipt().records().front() ;	// 期限限界の独立した期待です
	DRIVERCRATE_EXPECT( context, record.acquisitionDescriptor &&
									record.acquisitionDescriptor->attestation &&
									record.acquisitionDescriptor->attestation->validUntilUtc ==
										NOW + std::chrono::minutes{4} &&
									record.publishedIdentityEvidence.pnpIds.size() == 4U) ;
	runNormalSignedIndexCandidateBindingTests( context, std::move( store), NOW, zip, false, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 従来のPorts通常署名candidateを同じfake指定導入経路で確認します
 * @param[in,out] context 隔離した有限assertionの集計先です
 * @note 実HTTP、実device導入、実復元の作成を行いません
 */
//------------------------------------------------------------------------------
void runSignedIndexNormalBindingControl( TestContext &context)
{
	// 人工索引のRAM限定署名鍵です
	RamKey key ;
	key.generate( 3072U) ;
	// 人工archiveに対応する原INF文字列です
	std::string inf ;
	// 同workerへ渡す人工driver archiveです
	const auto	zip = normalWorkerDriverZip( false, &inf) ;
	// 人工recordに固定するarchive digestです
	const auto	hash = recordDigest( key, zip) ;
	// 同人工descriptorから作る署名recordです
	auto		raw = descriptorRecord( descriptorFixture()) ;
	raw				= replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
	raw				= replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
	raw				= replaced( std::move( raw), "\"valueBytes\":1234",
							   "\"valueBytes\":" + std::to_string( zip.size())) ;
	raw				= replaced( std::move( raw), "{11111111-2222-3333-4444-555555555555}",
							   "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
	raw				= replaced( std::move( raw), "drivers/fixture.inf", "fixture.inf") ;
	raw				= replaced( std::move( raw), "Fixture.NTamd64", "Models.NTamd64") ;
	raw				= replaced( std::move( raw),
							   "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
								   std::string{RECORD_EVIDENCE_HASH},
							   "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
								   recordDigest( key, inf)) ;
	raw				= replaced( std::move( raw), "\"inspectionStage\":\"METADATA_ONLY\"",
							   "\"inspectionStage\":\"CONTENT_INSPECTED\"") ;
	// 人工署名索引の隔離storeです
	std::shared_ptr<SignedIndexStore> store ;
	static_cast<void>( lookupSnapshot( key, raw, 1U, &store)) ;
	runNormalSignedIndexCandidateBindingTests( context, store, NOW, zip) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正規Client最低build条件の通常scan・計画・取得とhost拒否を限定実行します
 * @param[in,out] context 独立literal条件と実owner経路のassertion集計先です
 * @param[in] minimumBuild 既26200又は追加26100の固定分母です
 * @param[in] prechange 旧sourceの26100項目拒否だけを別に確認する場合trueです
 * @note RAM署名・人工archive・完全native/HTTP fakeだけを使い、実導入を行いません
 */
//------------------------------------------------------------------------------
void runClientMinimumBuildConsumerTests( TestContext &context, const unsigned minimumBuild,
										const bool prechange)
{
	DRIVERCRATE_EXPECT( context, minimumBuild == 26100U || minimumBuild == 26200U) ;
	RamKey key ;	// 永続key/profileを使わない実RSA署名fixtureです
	key.generate( 3072U) ;
	std::string inf ;	// 実archiveへ格納した同一原INFです
	// 最低ビルドの有無を比較する、通常取得試験と同じ架空の配布ZIP
	const auto	zip = normalWorkerDriverZip( false, &inf) ;
	// 元INFの署名対象と同じ入力かを確認する実ハッシュ
	const auto	infHash	  = recordDigest( key, inf) ;
	auto		legacyZip = zip ;	// 別outer SHAの旧NONE対照を同索引へ残します
	DRIVERCRATE_EXPECT( context, legacyZip.size() >= 22U && legacyZip[legacyZip.size() - 2U] == 0 &&
									legacyZip.back() == 0) ;
	// ZIP EOCDの独立comment長です
	legacyZip[legacyZip.size() - 2U] = 6 ;
	// member/INF/CATの原byteは変更しません
	legacyZip += "legacy" ;
	const auto makeRaw = [&]( const std::string_view payload) {
		auto	   raw = descriptorRecord( descriptorFixture()) ;	// 元v2 codec fieldを保持します
		// 対照ごとの配布内容に対応する署名索引のハッシュ
		const auto sha = recordDigest( key, payload) ;
		raw			   = replaced( std::move( raw), RECORD_CLAIM_HASH, sha) ;
		raw			   = replaced( std::move( raw), RECORD_CLAIM_HASH, sha) ;
		raw			   = replaced( std::move( raw), "\"valueBytes\":1234",
								  "\"valueBytes\":" + std::to_string( payload.size())) ;
		raw			   = replaced( std::move( raw), "{11111111-2222-3333-4444-555555555555}",
								  "{4d36e978-e325-11ce-bfc1-08002be10318}") ;
		raw			   = replaced( std::move( raw), "drivers/fixture.inf", "fixture.inf") ;
		raw			   = replaced( std::move( raw), "Fixture.NTamd64", "Models.NTamd64") ;
		raw			   = replaced(
			   std::move( raw),
			   "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
				   std::string{RECORD_EVIDENCE_HASH},
			   "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
				   infHash) ;
		return replaced( std::move( raw), "\"inspectionStage\":\"METADATA_ONLY\"",
						"\"inspectionStage\":\"CONTENT_INSPECTED\"") ;
	} ; // 期待scopeはhelperから生成せず以下の独立wire literalに固定します
	// 配布行へ最低ビルドを明示し、現端末との照合を行う固定条件
	const std::string marker =
		std::string{
			R"json({"kind":"LOCAL_CHECK","description":"DriverCrate:client-min-build=)json"} +
		(minimumBuild == 26100U ? "26100" : "26200") +
		R"json(;catalog-update-id=01234567-89ab-cdef-0123-456789abcdef","evidenceUrl":"https://www.catalog.update.microsoft.com/ScopedViewInline.aspx","evidenceSha256":")json" +
		std::string{RECORD_EVIDENCE_HASH} + "\"}" ;
	// 現在の対象条件を明記した配布行の元UTF-8
	const auto floorRaw = replaced( makeRaw( zip), "\"items\":[]", "\"items\":[" + marker + "]") ;
	// 最低ビルドがなく旧経路を通る対照レコードの元UTF-8
	auto	   oldRaw =
		replaced( makeRaw( legacyZip), "\"recordId\":\"metadata\"", "\"recordId\":\"legacy-none\"") ;
	// 旧recordは別payloadの公式tupleで、同coreの弱いaliasを作りません
	while( oldRaw.find( "https://vendor.example/fixture.zip") != oldRaw.npos) {
		oldRaw = replaced( std::move( oldRaw), "https://vendor.example/fixture.zip",
						  "https://vendor.example/legacy.zip") ;
	}

	/** @brief 初回hostと計画の独立literal分母です */
	struct Input {
		/// 事前固定した入力IDです
		std::string_view id ;
		/// native base buildです
		unsigned		 build ;
		/// native product typeです
		unsigned		 product ;
		/// native architectureです
		unsigned		 arch ;
		/// 元計画の独立期待件数です
		std::size_t		 targets ;
	} ;
	// 実scanで照合するビルド境界と、表示・計画・取得の期待結果の対照一覧
	std::vector<Input> inputs{Input{"L01_LOW26100_OTHER_NONE", 26100U, 1U, 9U, 1U},
							  Input{"L02_EXACT26200", 26200U, 1U, 9U, 1U},
							  Input{"L03_ABOVE26201", 26201U, 1U, 9U, 1U},
							  Input{"L04_FULLHOST_MISSING", 26200U, 1U, 9U, 0U},
							  Input{"L05_MALFORMED_GUID_OTHER_NONE", 26200U, 1U, 9U, 1U},
							  Input{"L06_UNKNOWN_RESERVED_OTHER_NONE", 26200U, 1U, 9U, 1U},
							  Input{"L07_SERVER_HOST_CLIENT_RECORD", 26100U, 3U, 9U, 0U},
							  Input{"L08_ARM64", 26200U, 1U, 12U, 0U},
							  Input{"L09_EXISTING_SERVER", 26100U, 3U, 9U, 1U},
							  Input{"L10_OLD_NONE", 26100U, 1U, 9U, 1U},
							  Input{"A01_FRESH_BUILD", 26200U, 1U, 9U, 1U},
							  Input{"A02_FRESH_PRODUCT", 26200U, 1U, 9U, 1U},
							  Input{"A03_FRESH_NATIVE_FAILURE", 26200U, 1U, 9U, 1U},
							  Input{"A04_OWNER_HASH_FIRST", 26200U, 1U, 9U, 1U},
							  Input{"A05_DIRECT_AFTER_PAYLOAD", 26200U, 1U, 9U, 1U},
							  Input{"A06_AUDIT_CHANGED_HOST", 26200U, 1U, 9U, 1U},
							  Input{"A07_FINAL_PAIR_CHANGED_HOST", 26200U, 1U, 9U, 1U},
							  Input{"R01_RETAINED_CHANGED_HOST", 26200U, 1U, 9U, 2U}} ;
	// 新floorは既未到達retained caseを繰り返さず、到達可能な二十入口だけです
	if( minimumBuild == 26100U) {
		inputs = {{"N01_LOW26099_OTHER_NONE", 26099U, 1U, 9U, 1U},
				  {"N02_EXACT26100", 26100U, 1U, 9U, 1U},
				  {"N03_ABOVE26200", 26200U, 1U, 9U, 1U},
				  {"L04_FULLHOST_MISSING", 26100U, 1U, 9U, 0U},
				  {"L07_SERVER_HOST_CLIENT_RECORD", 26100U, 3U, 9U, 0U},
				  {"N06_DC", 26100U, 2U, 9U, 0U},
				  {"L08_ARM64", 26100U, 1U, 12U, 0U},
				  {"N08_X86", 26100U, 1U, 0U, 0U},
				  {"L05_MALFORMED_GUID_OTHER_NONE", 26100U, 1U, 9U, 1U},
				  {"L06_UNKNOWN_RESERVED_OTHER_NONE", 26100U, 1U, 9U, 1U},
				  {"A01_FRESH_BUILD", 26100U, 1U, 9U, 1U},
				  {"A02_FRESH_PRODUCT", 26100U, 1U, 9U, 1U},
				  {"A03_FRESH_NATIVE_FAILURE", 26100U, 1U, 9U, 1U},
				  {"A04_OWNER_HASH_FIRST", 26100U, 1U, 9U, 1U},
				  {"A05_DIRECT_AFTER_PAYLOAD", 26100U, 1U, 9U, 1U},
				  {"A06_AUDIT_CHANGED_HOST", 26100U, 1U, 9U, 1U},
				  {"A07_FINAL_PAIR_CHANGED_HOST", 26100U, 1U, 9U, 1U},
				  {"N18_EXISTING26200_OTHER_NONE", 26100U, 1U, 9U, 1U},
				  {"L09_EXISTING_SERVER", 26100U, 3U, 9U, 1U},
				  {"L10_OLD_NONE", 26100U, 1U, 9U, 1U}} ;
	}

	// 新実装で旧拒否を試したことにせず、製品変更前だけ実行する一分母です
	if( prechange) {
		inputs = {{"O01_UNSUPPORTED26100_OTHER_NONE", 26100U, 1U, 9U, 1U}} ;
	}

	// 各入力は新署名store/新native scanだけで独立して実行します
	for( const auto &input : inputs) {
		auto raw = floorRaw ;	// 変更は事前固定した一faultだけです
		// 非正規GUIDだけを壊し、v2 descriptor自体の読取りは維持します
		if( input.id == "L05_MALFORMED_GUID_OTHER_NONE") {
			raw = replaced( std::move( raw), "89ab-cdef", "89AB-cdef") ;
		}

		// 解釈できないreserved floorを旧NONEへ落としません
		if( input.id == "L06_UNKNOWN_RESERVED_OTHER_NONE") {
			raw = replaced( std::move( raw),
						   minimumBuild == 26100U ? "client-min-build=26100"
												  : "client-min-build=26200",
						   "client-min-build=26201") ;
		}

		// 既26200は新26100 hostでも対象外のまま、他のNONEを保持します
		if( input.id == "N18_EXISTING26200_OTHER_NONE") {
			raw = replaced( std::move( raw), "client-min-build=26100", "client-min-build=26200") ;
		}

		// 既Server三条件の通常正例は元生成fixtureを維持します
		if( input.id == "L09_EXISTING_SERVER") {
			raw = serverHostRaw( makeRaw( zip), "WINDOWS_SERVER_2025", "3") ;
			// 同じ元取得の期待ハッシュを置換して不一致を作る元文字列
			const auto anchor =
				"\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
				std::string{RECORD_EVIDENCE_HASH} ;
			// 三LOCALだけを同実INFの原hashへ結びます
			while( raw.find( anchor) != raw.npos) {
				raw = replaced(
					std::move( raw), anchor,
					"\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
						infHash) ;
			}
		}

		// 単独旧NONEの元wireは三LOCALも新scopeも追加しません
		if( input.id == "L10_OLD_NONE") {
			raw = makeRaw( zip) ;
		}

		std::vector<std::string> rows{raw} ;	// 実署名する全recordです
		// 対象外の一recordで同索引の旧record利用を阻害しないことを確認します
		if( input.id.ends_with( "OTHER_NONE")) {
			rows.push_back( oldRaw) ;
		}

		// 既retained fixture同様、原attestation時刻が異なる同payloadの二targetです
		if( input.id == "R01_RETAINED_CHANGED_HOST") {
			// 先の明示取得後も候補を保持することを確認する別レコード
			auto second =
				replaced( raw, "\"recordId\":\"metadata\"", "\"recordId\":\"metadata-retained\"") ;
			second = replaced( std::move( second), "\"checkedAtUtc\":\"2026-10-10T03:00:00Z\"",
							  "\"checkedAtUtc\":\"2026-10-10T04:00:00Z\"") ;
			rows.push_back( std::move( second)) ;
		}

		std::shared_ptr<SignedIndexStore> store ;	// 実署名/codec/commit/reloadの所有者です
		static_cast<void>( lookupSnapshot( key, raw, rows.size(), &store, 9U, rows)) ;
		runClientMinimumBuildConsumerCase(
			context, std::move( store), NOW, input.id.ends_with( "OTHER_NONE") ? legacyZip : zip,
			input.id,
			WindowsHostPlatform{10U, 0U, input.build, static_cast<std::uint16_t>( input.arch),
								static_cast<std::uint8_t>( input.product), 0U},
			input.targets, minimumBuild == 26100U ? 26099U : 26100U,
			minimumBuild == 26100U &&
				(prechange || input.id == "N01_LOW26099_OTHER_NONE" ||
				 input.id == "N03_ABOVE26200" || input.id == "N18_EXISTING26200_OTHER_NONE" ||
				 input.id == "L10_OLD_NONE")) ;
	}

	std::cout << "CLIENT_MINIMUM_BUILD_MATRIX floor=" << minimumBuild << " cases=" << inputs.size()
			  << " prechange=" << prechange
			  << " retainedDownstream=unqualified realNetwork=0 realInstall=0\n" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 真署名storage索引を通常選択と完全native fakeの候補資格へ接続します
 * @param[in,out] context 隔離した有限assertionの集計先です
 * @param[in] mtdFileOnly 新規所有workspaceのMTD file I/Oだけを選ぶ場合trueです
 * @param[in] mtdOperationOnly MTDの通常操作一件だけを選ぶ場合trueです
 * @note BOOT0/SYSTEM1/DEMAND3の元INFを使い、実通信・実導入・復元作成を行いません
 */
//------------------------------------------------------------------------------
void runSignedIndexStorageQualificationTests( TestContext &context, bool mtdFileOnly,
											 bool mtdOperationOnly)
{
	RamKey key ;	// 隔離したRAM鍵だけで元索引を再認証します
	key.generate( 3072U) ;
	// 同じ正式Classと原serviceを三つのWindows開始方式へ個別に結びます
	for( const unsigned start : {0U, 1U, 3U}) {
		// file fixtureは固定した一つの開始方式だけ実行します
		if( mtdFileOnly && start != 0U) {
			continue ;
		}

		// MTD操作fixtureはDEMAND開始だけ実行します
		if( mtdOperationOnly && start != 3U) {
			continue ;
		}

		std::string inf ;	// 同archiveへ固定する元本文です
		static_cast<void>( normalWorkerDriverZip( false, &inf)) ;
		inf = replaced( std::move( inf), "Class=Ports", "Class=SCSIAdapter") ;
		inf = replaced( std::move( inf), "4d36e978", "4d36e97b") ;
		inf += "[Install.Services]\r\nAddService=FixtureStorage,2,StorageService\r\n"
			   "[StorageService]\r\nServiceType=1\r\nStartType=" +
			   std::to_string( start) +
			   "\r\nErrorControl=1\r\nServiceBinary=%12%\\fixture.sys\r\n"
			   "LoadOrderGroup=SCSI Miniport\r\n; selected-storage-fixture\r\n" ;
		std::string		 sys( 1024U, '\0') ;	// WindowsのPE catalog digestも成立する非実行fixtureです
		// catalog digestが成立する人工PEのDOS headerです
		IMAGE_DOS_HEADER dos{} ;
		dos.e_magic	 = IMAGE_DOS_SIGNATURE ;
		dos.e_lfanew = 0x80 ;
		// AMD64 PE32+を有限に構成する非実行headerです
		IMAGE_NT_HEADERS64 pe{} ;
		pe.Signature					   = IMAGE_NT_SIGNATURE ;
		pe.FileHeader.Machine			   = IMAGE_FILE_MACHINE_AMD64 ;
		pe.FileHeader.NumberOfSections	   = 1U ;
		pe.FileHeader.SizeOfOptionalHeader = sizeof( IMAGE_OPTIONAL_HEADER64) ;
		pe.FileHeader.Characteristics =
			IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE ;
		pe.OptionalHeader.Magic						  = IMAGE_NT_OPTIONAL_HDR64_MAGIC ;
		pe.OptionalHeader.ImageBase					  = 0x140000000ULL ;
		pe.OptionalHeader.SectionAlignment			  = 4096U ;
		pe.OptionalHeader.FileAlignment				  = 512U ;
		pe.OptionalHeader.SizeOfHeaders				  = 512U ;
		pe.OptionalHeader.SizeOfImage				  = 8192U ;
		pe.OptionalHeader.MajorOperatingSystemVersion = 6U ;
		pe.OptionalHeader.MajorSubsystemVersion		  = 6U ;
		pe.OptionalHeader.Subsystem					  = IMAGE_SUBSYSTEM_NATIVE ;
		pe.OptionalHeader.NumberOfRvaAndSizes		  = 16U ;
		// 人工PEの有限raw data sectionです
		IMAGE_SECTION_HEADER section{} ;
		section.Name[0]			 = 'f' ;
		section.Misc.VirtualSize = 1U ;
		section.VirtualAddress	 = 4096U ;
		section.SizeOfRawData	 = 512U ;
		section.PointerToRawData = 512U ;
		section.Characteristics	 = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ ;
		std::memcpy( sys.data(), &dos, sizeof( dos)) ;
		std::memcpy( sys.data() + dos.e_lfanew, &pe, sizeof( pe)) ;
		std::memcpy( sys.data() + dos.e_lfanew + sizeof( pe), &section, sizeof( section)) ;
		// 元CAT member対応へ固定する人工非署名byteです
		const std::string cat = "nonexecuting unsigned fixture catalog" ;
		// 各caseは異なる原byteを再署名し、同じ通常workerへ渡します
		const auto		  run = [&]( std::string_view name, const std::string &source,
								const StorageBindingTestInput						   &expected = {},
								const std::vector<std::pair<std::string, std::string>> &extra = {},
								const std::string &binary = std::string{}, bool reference = false) {
			   mz_zip_archive archive{} ;	// 全memberを同一のRAM ZIPへ閉じます
			   // 全root/SYS/CATを原ZIPへ閉じられなければ素材作成を中止します
			   if( !mz_zip_writer_init_heap( &archive, 0U, 0U) ||
				  !mz_zip_writer_add_mem( &archive, "fixture.inf", source.data(), source.size(),
											 MZ_NO_COMPRESSION) ||
				  !mz_zip_writer_add_mem(
					  &archive, "fixture.sys", binary.empty() ? sys.data() : binary.data(),
					  binary.empty() ? sys.size() : binary.size(), MZ_NO_COMPRESSION) ||
				  !mz_zip_writer_add_mem( &archive, "fixture.cat", cat.data(), cat.size(),
											 MZ_NO_COMPRESSION)) {
				   mz_zip_writer_end( &archive) ;
				   throw std::runtime_error( "storage source fixture failed") ;
			   }

			   // 必要nullも同じ原ZIPの全byte/CATへ閉じます
			   for( const auto &[member, body] : extra) {
				   // 追加nullの原byteが入らない素材を正常caseへ渡しません
				   if( !mz_zip_writer_add_mem( &archive, member.c_str(), body.data(), body.size(),
												 MZ_NO_COMPRESSION)) {
					   mz_zip_writer_end( &archive) ;
					   throw std::runtime_error( "storage additional original member failed") ;
				   }
			   }

			   void	 *bytes{} ;	// minizの一時所有はcopy後に必ず解放します
			   // minizが確定した全archive byte数です
			   size_t size{} ;
			   // 原archiveの全byteを確定できなければ索引を署名しません
			   if( !mz_zip_writer_finalize_heap_archive( &archive, &bytes, &size)) {
				   mz_zip_writer_end( &archive) ;
				   throw std::runtime_error( "storage archive finalization failed") ;
			   }

			   // RAMへ確定した元archive全byteの所有copyです
			   const std::string zip( static_cast<const char *>( bytes), size) ;
			   mz_free( bytes) ;
			   mz_zip_writer_end( &archive) ;
			   const auto hash = recordDigest( key, zip) ;	// 原containerの完全hashです
			   // 同原文又はSDの全byteを取得する一時所有です
			   auto		  raw = descriptorRecord( descriptorFixture()) ;
			   raw			  = replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
			   raw			  = replaced( std::move( raw), RECORD_CLAIM_HASH, hash) ;
			   raw			  = replaced( std::move( raw), "\"valueBytes\":1234",
											 "\"valueBytes\":" + std::to_string( zip.size())) ;
			   raw = replaced( std::move( raw), "{11111111-2222-3333-4444-555555555555}",
							  source.find( "Class=MTD\r\n") != source.npos
									  ? "{4d36e970-e325-11ce-bfc1-08002be10318}"
								  : source.find( "Class=MediumChanger\r\n") != source.npos
									  ? "{ce5939ae-ebde-11d0-b181-0000f8753ec4}"
								  : source.find( "Class=HDC\r\n") != source.npos
									  ? "{4d36e96a-e325-11ce-bfc1-08002be10318}"
									  : "{4d36e97b-e325-11ce-bfc1-08002be10318}") ;
			   raw = replaced( std::move( raw), "drivers/fixture.inf", "fixture.inf") ;
			   raw = replaced( std::move( raw), "Fixture.NTamd64", "Models.NTamd64") ;
			   raw = replaced(
				   std::move( raw),
				   "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
					   std::string{RECORD_EVIDENCE_HASH},
				   "\"evidenceUrl\":\"https://vendor.example/fixture.inf\",\"evidenceSha256\":\"" +
					   recordDigest( key, source)) ;
			   // 別枝の元IDも索引の完全集合へ保持し、未選択IDを削除しません
			   if( source.find( "TESTBUS\\SYNTH_UNUSED") != source.npos) {
				   raw = replaced(
					   std::move( raw),
					   R"json("pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"}])json",
					   R"json("pnpIds":[{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_0001"},{"kind":"HARDWARE","value":"TESTBUS\\SYNTH_UNUSED"}])json") ;
			   }

			   raw = replaced( std::move( raw), "\"inspectionStage\":\"METADATA_ONLY\"",
								  "\"inspectionStage\":\"CONTENT_INSPECTED\"") ;
			   std::shared_ptr<SignedIndexStore> store ;	// production authorityを使いません
			   static_cast<void>( lookupSnapshot( key, raw, 1U, &store)) ;
			   std::cout << "STORAGE_SOURCE name=" << name << " start=" << start
						 << " originalBytes=" << zip.size() << '\n' ;
			   // c0と同じ通常意図の分母を有効PE素材で再確認します
			   if( reference) {
				   runNormalIndexIdentityBindingCase( context, store, NOW, zip, 1U, 1U, 1U,
														 PreparedInstallResolutionState::READY) ;
				   // 同有効素材の通常入口/collector型/用途書換え拒否を一度だけ独立確認します
				   if( start == 0U) {
					   runStorageAuthorizationBoundaryTests( context, zip) ;
				   }
			   }

			   runNormalStorageDriverBindingCase( context, store, NOW, zip, expected) ;
		} ;
		// 旧通常controlはMTD専用runと分けて実行します
		if( !mtdOperationOnly) {
			run( "A-standard", inf, {}, {}, {}, true) ;
		}

		// HDCの二選択節を公式IDの追加限定なしの署名済みModelsレコードへ結ぶ
		if( start == 0U && !mtdFileOnly && !mtdOperationOnly) {
			auto ide =
				// 元のブート開始を保持するINF
				replaced( inf, "Class=SCSIAdapter", "Class=HDC") ;
			ide = replaced( std::move( ide), "4d36e97b", "4d36e96a") ;
			ide = replaced( std::move( ide),
						   "CopyFiles=Files\r\n[Files]\r\nfixture.sys\r\n"
						   "[DestinationDirs]\r\nFiles=12\r\n",
						   "CopyFiles=@fixture.sys\r\n[DestinationDirs]\r\nDefaultDestDir=12\r\n") ;
			ide = replaced( std::move( ide), "LoadOrderGroup=SCSI Miniport",
						   "LoadOrderGroup=System Bus Extender") ;
			run( "hdc-ide-models", ide) ;
			run( "hdc-ide-models-expired-after-stage", ide,
				{.nativeCase	 = SignedIndexBindingNativeCase::STORAGE_RECORD_EXPIRES_AFTER_STAGE,
				 .installs		 = 0U,
				 .succeeded		 = false,
				 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT))}) ;
			run( "hdc-ide-preceding-order-changed-after-stage", ide,
				{.nativeCase	 = SignedIndexBindingNativeCase::STORAGE_LOAD_ORDER_AFTER_STAGE,
				 .installs		 = 0U,
				 .succeeded		 = false,
				 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY))}) ;
		}

		// 正式メディアチェンジャーはSYSTEM開始時の固定構成で通常経路を確認する
		if( start == 1U && !mtdFileOnly && !mtdOperationOnly) {
			auto changer = replaced( inf, "Class=SCSIAdapter",
									"Class=MediumChanger") ;	// 正式クラスへ変更する元INF
			changer		 = replaced( std::move( changer), "{4d36e97b-e325-11ce-bfc1-08002be10318}",
									"{ce5939ae-ebde-11d0-b181-0000f8753ec4}") ;
			changer = replaced( std::move( changer), "AddService=FixtureStorage,2,StorageService",
							   "AddService=FixtureStorage,2,StorageService,EventLog") ;
			changer = replaced( std::move( changer), "LoadOrderGroup=SCSI Miniport",
							   "LoadOrderGroup=SCSI Class\r\nDependencies=+SCSI Miniport") ;
			changer += "[ControlFlags]\r\nExcludeFromSelect=*\r\n"
					   "[EventLog]\r\nAddReg=EventLogRegistry\r\n[EventLogRegistry]\r\n"
					   "HKR,,EventMessageFile,0x00020000,\"%%SystemRoot%%\\System32\\IoLogMsg.dll;"
					   "%%SystemRoot%%\\System32\\drivers\\fixture.sys\"\r\n"
					   "HKR,,TypesSupported,0x00010001,7\r\n" ;
			run( "medium-changer", changer) ;
			run( "medium-changer-first-install", changer,
				{.nativeCase = SignedIndexBindingNativeCase::INITIAL_CLASS_UNKNOWN}) ;
			run( "medium-changer-existing-service", changer,
				{.nativeCase = SignedIndexBindingNativeCase::STORAGE_EXISTING_SERVICE}) ;
			run( "medium-changer-missing-order", changer,
				{.nativeCase	 = SignedIndexBindingNativeCase::STORAGE_LOAD_ORDER_MISSING,
				 .qualified		 = false,
				 .stages		 = 0U,
				 .installs		 = 0U,
				 .succeeded		 = false,
				 .rejectionError = static_cast<NativeError>( E_NOTIMPL),
				 .rejectionStage = 14011U}) ;
			run( "medium-changer-order-changed-after-stage", changer,
				{.nativeCase	 = SignedIndexBindingNativeCase::STORAGE_LOAD_ORDER_AFTER_STAGE,
				 .installs		 = 0U,
				 .succeeded		 = false,
				 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY))}) ;
			run( "medium-changer-expired-after-stage", changer,
				{.nativeCase	 = SignedIndexBindingNativeCase::STORAGE_RECORD_EXPIRES_AFTER_STAGE,
				 .installs		 = 0U,
				 .succeeded		 = false,
				 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT))}) ;
		}

		// file専用runでは署名操作分母を重複実行しません
		if( mtdFileOnly) {
			continue ;
		}

		// ErrorControlは0..3の元値を全開始方式に対して保持します
		if( !mtdOperationOnly) {
			// 旧service ErrorControlの各元値を維持します
			for( const auto errorControl : {0U, 2U, 3U}) {
				run( "A-error-control", replaced( inf, "ErrorControl=1",
												"ErrorControl=" + std::to_string( errorControl))) ;
			}
		}

		// 原optional groupだけを省略した独立素材です
		const auto noGroup = replaced( inf, "LoadOrderGroup=SCSI Miniport\r\n", "") ;
		// 初期製品の0/1 group必須と3省略可を明示的に区別します
		if( start == 3U) {
			// 旧通常group省略controlをMTD専用runから分けます
			if( !mtdOperationOnly) {
				run( "A-demand-group-omitted", noGroup) ;
			}

			// 元flagsを補わない二つのcopy-only DLLとMTD hardware作用です
			auto mtd = replaced( inf, "Class=SCSIAdapter", "Class=MTD") ;
			mtd		 = replaced( std::move( mtd), "4d36e97b", "4d36e970") ;
			mtd =
				replaced( std::move( mtd), "LoadOrderGroup=SCSI Miniport", "LoadOrderGroup=SD / MMC") ;
			mtd = replaced( std::move( mtd), "CopyFiles=Files\r\n", "CopyFiles=Files,SharedDlls\r\n") ;
			mtd += "[DestinationDirs]\r\nSharedDlls=11\r\n"
				   "[SharedDlls]\r\nfixture-a.dll\r\nfixture-b.dll\r\n"
				   "[SourceDisksFiles]\r\nfixture-a.dll=1\r\nfixture-b.dll=1\r\n"
				   "[Install.HW]\r\nAddReg=MtdHardware\r\n[MtdHardware]\r\n"
				   "HKR,,DeviceType,0x10001,7\r\n"
				   "HKR,,DeviceCharacteristics,0x10001,0x101\r\n" ;
			// 二件目DLLに固定する独立した原byteです
			auto secondDll	= sys ;
			secondDll[512U] = 'g' ;
			// 原INFに対応する二DLLの名前とbyteです
			const std::vector<std::pair<std::string, std::string>> mtdFiles{
				{"fixture-a.dll", sys}, {"fixture-b.dll", secondDll}} ;
			run( "M-raw-two-dll", mtd, {}, mtdFiles) ;
			// 復旧拒否後にstageと共有作用がない条件を検証します
			if( mtdOperationOnly) {
				run( "M-restore-reject", mtd,
					{.restoreFailure = true, .stages = 0U, .installs = 0U, .succeeded = false},
					mtdFiles) ;
				// 初回・同版・旧版の明示選択を分けて実行します
				for( const auto state : {SignedIndexBindingNativeCase::INITIAL,
										SignedIndexBindingNativeCase::NORMAL_SAME_VERSION,
										SignedIndexBindingNativeCase::STORAGE_OLDER}) {
					run( "M-device-state", mtd, {.nativeCase = state}, mtdFiles) ;
				}

				// 既存・混在・Store・競合・SYS遅延の各正例を固定します
				for( const auto scenario :
					{MtdFixtureScenario::BOTH_EXIST, MtdFixtureScenario::MIXED,
					 MtdFixtureScenario::STORE_SOURCE, MtdFixtureScenario::RACE_SAME,
					 MtdFixtureScenario::SYSTEM_DELAYED}) {
					run( "M-copy-positive", mtd, {.mtdScenario = scenario}, mtdFiles) ;
				}

				// 未知handlerと権限失敗を拒否条件として分けます
				for( const auto scenario :
					{MtdFixtureScenario::HANDLER_PRESENT, MtdFixtureScenario::HANDLER_DENIED,
					 MtdFixtureScenario::TABLE_EMPTY}) {
					run( "M-handler-reject", mtd,
						{.qualified	  = false,
						 .stages	  = 0U,
						 .installs	  = 0U,
						 .succeeded	  = false,
						 .mtdScenario = scenario},
						mtdFiles) ;
				}

				// 異byte、reparse、write、queue、期限等の負例と元errorを固定します
				for( const auto &[scenario, code] : std::array{
						std::pair{MtdFixtureScenario::FOREIGN_EXISTING, ERROR_CRC},
						std::pair{MtdFixtureScenario::BAD_DACL, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::BAD_OWNER, ERROR_INVALID_OWNER},
						std::pair{MtdFixtureScenario::ANCESTOR_DELETE_CHILD, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::ANCESTOR_DELETE, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::ANCESTOR_WRITE_DAC, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::ANCESTOR_WRITE_OWNER, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::ANCESTOR_WRITE_FILE, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::ANCESTOR_UNPROTECTED_CHILD,
								  ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::ANCESTOR_CHILD_WRITE, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::DESTINATION_PARENT_ADD_DIRECTORY,
								  ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::STORE_PARENT_ADD_DIRECTORY,
								  ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::EXISTING_WRITER, ERROR_SHARING_VIOLATION},
						std::pair{MtdFixtureScenario::REPARSE_TARGET, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::REPARSE_PARENT, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::HARDLINK_TARGET, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::READ_FAILURE, ERROR_READ_FAULT},
						std::pair{MtdFixtureScenario::RACE_DIFFERENT, ERROR_CRC},
						std::pair{MtdFixtureScenario::PARTIAL_WRITE, ERROR_WRITE_FAULT},
						std::pair{MtdFixtureScenario::TEMP_CREATE_FAILURE, ERROR_DISK_FULL},
						std::pair{MtdFixtureScenario::FLUSH_FAILURE, ERROR_WRITE_FAULT},
						std::pair{MtdFixtureScenario::RENAME_FAILURE, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::RENAME_VERIFY_FAILURE, ERROR_RETRY},
						std::pair{MtdFixtureScenario::HANDLER_AFTER_STAGE, ERROR_NOT_SUPPORTED},
						std::pair{MtdFixtureScenario::HW_AFTER_STAGE, ERROR_RETRY},
						std::pair{MtdFixtureScenario::SELECTED_NODE_CHANGED, ERROR_RETRY},
						std::pair{MtdFixtureScenario::PARAMS_CHANGED_AFTER_FILES, ERROR_RETRY},
						std::pair{MtdFixtureScenario::RANK_AFTER_COMMIT, ERROR_RETRY},
						std::pair{MtdFixtureScenario::EXPIRED_BEFORE_STAGE, ERROR_TIMEOUT},
						std::pair{MtdFixtureScenario::EXPIRED_BEFORE_FILE_DIF, ERROR_TIMEOUT},
						std::pair{MtdFixtureScenario::EXPIRED_BEFORE_SHARED, ERROR_TIMEOUT},
						std::pair{MtdFixtureScenario::EXPIRED_BEFORE_FIRST_RENAME, ERROR_TIMEOUT},
						std::pair{MtdFixtureScenario::EXPIRED_BEFORE_SECOND_RENAME, ERROR_TIMEOUT},
						std::pair{MtdFixtureScenario::EXPIRED_BEFORE_COMMIT, ERROR_TIMEOUT},
						std::pair{MtdFixtureScenario::EXPIRED_AFTER_COMMIT, ERROR_TIMEOUT},
						std::pair{MtdFixtureScenario::QUEUE_MISSING, ERROR_INVALID_DATA},
						std::pair{MtdFixtureScenario::QUEUE_DUPLICATE, ERROR_INVALID_DATA},
						std::pair{MtdFixtureScenario::QUEUE_EXTRA, ERROR_INVALID_DATA},
						std::pair{MtdFixtureScenario::QUEUE_DELETE, ERROR_INVALID_DATA},
						std::pair{MtdFixtureScenario::QUEUE_FLAGS, ERROR_INVALID_DATA},
						std::pair{MtdFixtureScenario::QUEUE_SOURCE, ERROR_NOT_FOUND},
						std::pair{MtdFixtureScenario::CONTROL_FLAGS, ERROR_INVALID_DATA},
						std::pair{MtdFixtureScenario::UNKNOWN_CALLBACK, ERROR_INVALID_DATA},
						std::pair{MtdFixtureScenario::DLL_DELAYED, ERROR_INVALID_DATA},
						std::pair{MtdFixtureScenario::INSTALL_FAILURE, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::POST_DIF_VERIFY_FAILURE, ERROR_ACCESS_DENIED},
						std::pair{MtdFixtureScenario::PARAM_CLEANUP_FAILURE,
								  ERROR_ACCESS_DENIED}}) {
					// 共有preflightで作用前に拒否すべきscenarioです
					const bool early =
						scenario == MtdFixtureScenario::FOREIGN_EXISTING ||
						scenario == MtdFixtureScenario::BAD_DACL ||
						scenario == MtdFixtureScenario::BAD_OWNER ||
						scenario == MtdFixtureScenario::ANCESTOR_DELETE_CHILD ||
						scenario == MtdFixtureScenario::ANCESTOR_DELETE ||
						scenario == MtdFixtureScenario::ANCESTOR_WRITE_DAC ||
						scenario == MtdFixtureScenario::ANCESTOR_WRITE_OWNER ||
						scenario == MtdFixtureScenario::ANCESTOR_WRITE_FILE ||
						scenario == MtdFixtureScenario::ANCESTOR_UNPROTECTED_CHILD ||
						scenario == MtdFixtureScenario::ANCESTOR_CHILD_WRITE ||
						scenario == MtdFixtureScenario::DESTINATION_PARENT_ADD_DIRECTORY ||
						scenario == MtdFixtureScenario::EXISTING_WRITER ||
						scenario == MtdFixtureScenario::REPARSE_TARGET ||
						scenario == MtdFixtureScenario::REPARSE_PARENT ||
						scenario == MtdFixtureScenario::HARDLINK_TARGET ||
						scenario == MtdFixtureScenario::READ_FAILURE ||
						scenario == MtdFixtureScenario::EXPIRED_BEFORE_STAGE ;
					// 選択DIFまで到達する失敗scenarioです
					const bool calledInstall =
						scenario == MtdFixtureScenario::INSTALL_FAILURE ||
						scenario == MtdFixtureScenario::POST_DIF_VERIFY_FAILURE ||
						scenario == MtdFixtureScenario::PARAM_CLEANUP_FAILURE ;
					run( "M-copy-reject", mtd,
						{.stages		 = early ? 0U : 1U,
						 .installs		 = calledInstall ? 1U : 0U,
						 .succeeded		 = false,
						 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( code)),
						 .mtdScenario	 = scenario},
						mtdFiles) ;
				}
			}
		} else {
			run( "C-boot-system-group-missing", noGroup,
				{.qualified = false,
				 .stages	= 0U,
				 .installs	= 0U,
				 .succeeded = false,
				 .rejectionError =
					 static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)),
				 .rejectionStage = 14001U}) ;
		}

		// 原差分matrixを一開始方式だけへ置き、同じ負例を無理由に重複実行しません
		if( start != 0U) {
			continue ;
		}

		// 同原索引/通常workerで固定拒否地点を確認する同期caseです
		const auto reject =
			[&]( std::string_view name, const std::string &source, std::uint32_t stage,
				NativeError error =
					static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))) {
				run( name, source,
					{.qualified		 = false,
					 .stages		 = 0U,
					 .installs		 = 0U,
					 .succeeded		 = false,
					 .rejectionError = error,
					 .rejectionStage = stage}) ;
			} ;
		// 不正な元fieldを要求する固定HRESULTです
		const auto invalid = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		reject( "C-service-type2", replaced( inf, "ServiceType=1", "ServiceType=2"), 14001U) ;
		reject( "C-start2", replaced( inf, "StartType=0", "StartType=2"), 14001U) ;
		reject( "C-start4", replaced( inf, "StartType=0", "StartType=4"), 14001U) ;
		reject( "C-error-control4", replaced( inf, "ErrorControl=1", "ErrorControl=4"), 9U, invalid) ;
		reject( "C-service-flags-unknown",
			   replaced( inf, "FixtureStorage,2,", "FixtureStorage,0x102,"), 14001U) ;
		reject( "C-wrong-group", replaced( inf, "SCSI Miniport", "File System"), 14001U) ;
		reject( "C-missing-start", replaced( inf, "StartType=0\r\n", ""), 9U, invalid) ;
		reject( "C-duplicate-tail-start", inf + "StartType=3\r\n", 9U, invalid) ;
		reject( "C-unknown-tail-directive", inf + "UnknownStorageAction=1\r\n", 14006U) ;
		reject( "C-unknown-bootflags", inf + "BootFlags=0x100\r\n", 14001U) ;
		run( "C-modern-bootflags", inf + "BootFlags=0xff\r\n") ;
		run( "C-display-and-description-data",
			inf +
				"DisplayName=Storage Command Adapter\r\nDescription=Security mode display text\r\n") ;
		run( "C-long-exact-service-name",
			replaced( inf, "FixtureStorage",
					 "FixtureStorageServiceNameLongerThanThirtyOneCharacters")) ;
		// 明示関連serviceのdata scopeであるという分類です
		const auto parameters = inf + "AddReg=OwnParameters\r\n[OwnParameters]\r\n"
									  "HKR,Parameters,CommandTimeout,0x10001,4096\r\n"
									  "HKR,Parameters,SecurityMode,0x10001,257\r\n" ;
		run( "E-vendor-opaque-parameters", parameters) ;
		reject(
			"E-other-service-scope",
			replaced(
				parameters, "HKR,Parameters,CommandTimeout",
				"HKLM,SYSTEM\\CurrentControlSet\\Services\\OtherStorage\\Parameters,CommandTimeout"),
			14004U) ;
		reject(
			"E-other-controlset",
			replaced(
				parameters, "HKR,Parameters,CommandTimeout",
				"HKLM,SYSTEM\\ControlSet002\\Services\\FixtureStorage\\Parameters,CommandTimeout"),
			14004U) ;
		reject( "E-startoverride-control",
			   replaced( parameters, "HKR,Parameters,CommandTimeout",
						"HKR,StartOverride,CommandTimeout"),
			   14004U) ;
		reject( "E-command-reference",
			   replaced( parameters, "HKR,Parameters,CommandTimeout,0x10001,4096",
						"HKR,Parameters,CommandTimeout,0,foreign.exe --run"),
			   14004U) ;
		// 元REG_SZの実program参照と通常の表示dataを独立に確認します
		reject( "E-command-without-extension",
			   replaced( parameters, "HKR,Parameters,CommandTimeout,0x10001,4096",
						"HKR,Parameters,CommandTimeout,0,cmd /c arbitrary-action"),
			   14004U) ;
		reject( "E-powershell-without-extension",
			   replaced( parameters, "HKR,Parameters,CommandTimeout,0x10001,4096",
						"HKR,Parameters,CommandTimeout,0,powershell -Command arbitrary-action"),
			   14004U) ;
		run( "E-ordinary-regsz-words",
			parameters + "HKR,Parameters,Label,0,Storage command security mode\r\n") ;
		run( "E-nonexecuting-json-name", parameters + "HKR,Parameters,DataFile,0,settings.json\r\n") ;
		run( "E-adapter-parameters-opaque-control-words",
			inf + "[Install.HW]\r\nAddReg=AdapterParameters\r\n"
				  "[AdapterParameters]\r\nHKR,Parameters\\Command,Security,0x10001,1\r\n") ;
		// 原共有disk DWORDだけを追加した独立素材です
		const auto shared =
			inf +
			"AddReg=SharedDisk\r\n[SharedDisk]\r\nHKLM,SYSTEM\\CurrentControlSet\\Services\\disk,TimeOutValue,0x10001,90\r\n" ;
		run( "E-shared-disk90", shared) ;
		reject( "E-shared-disk0", replaced( shared, "0x10001,90", "0x10001,0"), 14004U) ;
		reject( "E-shared-disk256", replaced( shared, "0x10001,90", "0x10001,256"), 14004U) ;
		reject( "E-unknown-shared-value", replaced( shared, "TimeOutValue", "UnknownDiskSetting"),
			   14004U) ;
		reject( "E-wrong-registry-type", replaced( shared, "0x10001,90", "0x10000,90"), 14004U) ;
		reject( "E-legacy-bootflags-specific",
			   inf + "AddReg=LegacyBoot\r\n[LegacyBoot]\r\nHKR,,BootFlags,0x10001,1\r\n", 14009U) ;
		// file/service作用を持たない元限定null INFです
		const std::string nullInf =
			"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=System\r\n"
			"ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\r\nProvider=Fixture Vendor\r\n"
			"DriverVer=10/11/2026,1.0.0.0\r\nCatalogFile=fixture.cat\r\n"
			"[Manufacturer]\r\nVendor=NullModels,NTamd64\r\n[NullModels.NTamd64]\r\n"
			"Device=NullInstall,TESTBUS\\SYNTH_NULL,SCSIEnclosure\r\n[NullInstall.NT]\r\n[NullInstall.NT.Services]\r\nAddService=,2\r\n" ;
		// 実選択CopyINFから一つの必要nullへ到達する原INFです
		const auto withNull =
			replaced( inf, "CopyFiles=Files\r\n", "CopyFiles=Files\r\nCopyINF=importonly.inf\r\n") ;
		run( "F-required-null-shared-cat", withNull, {.stages = 2U, .imports = 1U},
			{{"importonly.inf", nullInf}}) ;
		// 全潜在importと実選択登録を区別する二枝の原INFです
		const auto twoNulls =
			replaced(
				withNull, "%Device%=Install,TESTBUS\\SYNTH_0001\r\n",
				"%Device%=Install,TESTBUS\\SYNTH_0001\r\nOther=Unused,TESTBUS\\SYNTH_UNUSED\r\n") +
			"[Unused]\r\nCopyFiles=Files\r\nCopyINF=unselected.inf\r\n" ;
		run( "I-unselected-null-content-only", twoNulls, {.stages = 2U, .imports = 1U},
			{{"importonly.inf", nullInf},
			 {"unselected.inf",
			  replaced( nullInf, "TESTBUS\\SYNTH_NULL", "TESTBUS\\SYNTH_UNUSED_NULL")}}) ;
		// 元Areca作用の形を架空device/SYS/CATへ一般化した閉素材です
		const auto areca =
			replaced( replaced( withNull, "CopyINF=importonly.inf\r\n",
							  "CopyINF=importonly.inf\r\nAddReg=SharedDisk\r\n"),
					 "AddService=FixtureStorage,2,StorageService",
					 "AddService=FixtureStorage,2,StorageService,EventLog") +
			"AddReg=OwnParameters\r\n"
			"[SharedDisk]\r\nHKLM,SYSTEM\\CurrentControlSet\\Services\\disk,TimeOutValue,0x10001,90\r\n"
			"HKLM,SYSTEM\\CurrentControlSet\\Services\\FixtureStorage\\Parameters\\Device,MaximumSGList,0x10001,4096\r\n"
			"HKLM,SYSTEM\\CurrentControlSet\\Services\\FixtureStorage\\Parameters\\Device,NumberOfRequests,0x10001,257\r\n"
			"[OwnParameters]\r\nHKR,Parameters\\PnpInterface,5,0x10001,1\r\n"
			"HKR,Parameters\\PnpInterface,Thunderbolt,0x10001,1\r\n"
			"HKR,Parameters,BusType,0x10001,8\r\n"
			"HKR,Parameters\\Device,NbrLUNsperHBA,0x10001,512\r\n"
			"[Install.HW]\r\nInclude=pci.inf\r\nNeeds=PciIoSpaceNotRequired.HW\r\n"
			"AddReg=HardwareSettings\r\nDelReg=LegacyScsiPort\r\n"
			"[HardwareSettings]\r\nHKR,,RemovalPolicy,0x10001,3\r\n"
			"HKR,ScsiPort,NeedsSystemShutdownNotification,0x10001,1\r\n"
			"HKR,Interrupt Management,0x00000010\r\n"
			"HKR,Interrupt Management\\MessageSignaledInterruptProperties,0x00000010\r\n"
			"HKR,Interrupt Management\\MessageSignaledInterruptProperties,MSISupported,0x10001,1\r\n"
			"[LegacyScsiPort]\r\nHKR,ScsiPort,BusNumber\r\nHKR,ScsiPort,LegacyInterfaceType\r\nHKR,ScsiPort,SlotNumber\r\n"
			"[EventLog]\r\nAddReg=EventResources\r\n[EventResources]\r\n"
			"HKR,,EventMessageFile,0x20000,\"%%SystemRoot%%\\System32\\IoLogMsg.dll;%%SystemRoot%%\\System32\\Drivers\\fixture.sys\"\r\n"
			"HKR,,TypesSupported,0x10001,7\r\n" ;
		run( "B-areca-nonmsi", areca, {.stages = 2U, .imports = 1U, .arecaEquivalent = true},
			{{"importonly.inf", nullInf}}) ;
		run( "B-areca-msi-machine-forward",
			replaced( areca, "Include=pci.inf", "Include=machine.inf"),
			{.stages = 2U, .imports = 1U, .arecaEquivalent = true}, {{"importonly.inf", nullInf}}) ;
		// 新旧service設定と原byteが異なる正当な更新を同じ通常入口へ通します
		run( "G-existing-service-new-version", inf,
			{.nativeCase = SignedIndexBindingNativeCase::STORAGE_EXISTING_SERVICE}) ;
		run( "G-shared-service-second-adapter", inf,
			{.nativeCase = SignedIndexBindingNativeCase::STORAGE_SHARED_INITIAL}) ;
		run( "C-windows-dependency", inf + "Dependencies=InboxFixture\r\n") ;
		reject( "C-external-dependency-protected-but-not-windows",
			   inf + "Dependencies=ExternalFixture\r\n", 14008U,
			   static_cast<NativeError>( E_INVALIDARG)) ;
		reject( "C-group-dependency", inf + "Dependencies=+SCSI Miniport\r\n", 14008U) ;
		run( "C-empty-dependencies", inf + "Dependencies=\r\n") ;
		run( "C-old-os-without-modern-bootflags", inf,
			{.nativeCase = SignedIndexBindingNativeCase::STORAGE_OLD_BOOT_FLAGS_OS}) ;
		run( "C-modern-bootflags-old-os", inf + "BootFlags=1\r\n",
			{.nativeCase	 = SignedIndexBindingNativeCase::STORAGE_OLD_BOOT_FLAGS_OS,
			 .qualified		 = false,
			 .stages		 = 0U,
			 .installs		 = 0U,
			 .succeeded		 = false,
			 .rejectionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)),
			 .rejectionStage = 14001U}) ;
		run( "H-missing-storage-callback", inf,
			{.nativeCase	 = SignedIndexBindingNativeCase::STORAGE_SERVICE_CALLBACK_MISSING,
			 .qualified		 = false,
			 .stages		 = 0U,
			 .installs		 = 0U,
			 .succeeded		 = false,
			 .rejectionError = static_cast<NativeError>( E_NOTIMPL),
			 .rejectionStage = 14007U}) ;
		run( "I-file-exists-readback", withNull,
			{.nativeCase = SignedIndexBindingNativeCase::STORAGE_STAGE_EXISTS,
			 .stages	 = 2U,
			 .imports	 = 1U},
			{{"importonly.inf", nullInf}}) ;
		run( "I-null-stage-failure", withNull,
			{.stagingFailure = true,
			 .installs		 = 0U,
			 .imports		 = 1U,
			 .succeeded		 = false,
			 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED))},
			{{"importonly.inf", nullInf}}) ;
		run( "I-base-stage-after-null-failure", withNull,
			{.nativeCase	 = SignedIndexBindingNativeCase::REQUIRED_STAGE_PARTIAL,
			 .stages		 = 2U,
			 .installs		 = 0U,
			 .imports		 = 1U,
			 .succeeded		 = false,
			 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED))},
			{{"importonly.inf", nullInf}}) ;
		run( "J-install-native-error", withNull,
			{.nativeCase	 = SignedIndexBindingNativeCase::REQUIRED_BASE_FAILURE,
			 .stages		 = 2U,
			 .imports		 = 1U,
			 .succeeded		 = false,
			 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED))},
			{{"importonly.inf", nullInf}}) ;
		run( "J-install-diagnostic-missing", withNull,
			{.nativeCase	 = SignedIndexBindingNativeCase::REQUIRED_BASE_DIAGNOSTIC_MISSING,
			 .stages		 = 2U,
			 .imports		 = 1U,
			 .succeeded		 = false,
			 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA))},
			{{"importonly.inf", nullInf}}) ;
		run( "J-no-reboot", inf, {.noReboot = true}) ;
		run( "J-current-old-after-api-success", inf, {.reflectOwnInstall = false}) ;
		run( "H-restore-failure", inf,
			{.restoreFailure = true, .stages = 0U, .installs = 0U, .succeeded = false}) ;
		// 名前衝突/所有不明を他adapterの存在そのものと区別します
		for( const auto condition : {SignedIndexBindingNativeCase::STORAGE_SHARED_WRONG_SERVICE,
									SignedIndexBindingNativeCase::STORAGE_SHARED_INCOMPATIBLE,
									SignedIndexBindingNativeCase::STORAGE_SHARED_AMBIGUOUS}) {
			run( "G-shared-owner-negative", inf,
				{.nativeCase	 = condition,
				 .qualified		 = false,
				 .stages		 = 0U,
				 .installs		 = 0U,
				 .succeeded		 = false,
				 .rejectionError = static_cast<NativeError>( HRESULT_FROM_WIN32(
					 condition == SignedIndexBindingNativeCase::STORAGE_SHARED_WRONG_SERVICE
						 ? ERROR_NOT_SUPPORTED
					 : condition == SignedIndexBindingNativeCase::STORAGE_SHARED_INCOMPATIBLE
						 ? ERROR_NOT_FOUND
						 : ERROR_DUP_NAME)),
				 .rejectionStage = 14010U}) ;
		}

		run( "I-service-changed-before-stage", inf,
			{.nativeCase   = SignedIndexBindingNativeCase::STORAGE_SERVICE_CHANGED,
			 .changeNative = true,
			 .stages	   = 0U,
			 .installs	   = 0U,
			 .succeeded	   = false}) ;
		run( "I-service-changed-after-null-stage", withNull,
			{.nativeCase	 = SignedIndexBindingNativeCase::STORAGE_SERVICE_CHANGED_AFTER_STAGE,
			 .installs		 = 0U,
			 .imports		 = 1U,
			 .succeeded		 = false,
			 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY))},
			{{"importonly.inf", nullInf}}) ;
		run( "F-helper-trust-failure", areca,
			{.nativeCase	 = SignedIndexBindingNativeCase::STORAGE_HELPER_REJECTED,
			 .qualified		 = false,
			 .stages		 = 0U,
			 .installs		 = 0U,
			 .succeeded		 = false,
			 .rejectionError = static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED),
			 .rejectionStage = 14004U},
			{{"importonly.inf", nullInf}}) ;
		run( "I-helper-changed-after-null-stage", areca,
			{.nativeCase	 = SignedIndexBindingNativeCase::STORAGE_HELPER_CHANGED_AFTER_STAGE,
			 .installs		 = 0U,
			 .imports		 = 1U,
			 .succeeded		 = false,
			 .executionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_RETRY))},
			{{"importonly.inf", nullInf}}) ;
		// 現在Class不在/Unknownは元NO_DRIVERの全観測が成立する場合だけ通します
		run( "G-first-class-absent", inf,
			{.nativeCase = SignedIndexBindingNativeCase::INITIAL_CLASS_MISSING}) ;
		run( "G-first-class-unknown", inf,
			{.nativeCase = SignedIndexBindingNativeCase::INITIAL_CLASS_UNKNOWN}) ;
		run( "G-explicit-older-version", inf,
			{.nativeCase = SignedIndexBindingNativeCase::STORAGE_OLDER}) ;
		run( "G-unique-better-node-last", inf,
			{.nativeCase = SignedIndexBindingNativeCase::RANK_BEST_LAST}) ;
		run( "G-tied-best-node", inf,
			{.nativeCase	 = SignedIndexBindingNativeCase::RANK_BEST_TIED,
			 .qualified		 = false,
			 .stages		 = 0U,
			 .installs		 = 0U,
			 .succeeded		 = false,
			 .rejectionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_DUP_NAME)),
			 .rejectionStage = 0U}) ;
		run( "G-blank-version-is-not-first", inf,
			{.nativeCase	 = SignedIndexBindingNativeCase::BLANK_CURRENT,
			 .qualified		 = false,
			 .stages		 = 0U,
			 .installs		 = 0U,
			 .succeeded		 = false,
			 .rejectionError = 0U,
			 .rejectionStage = 0U}) ;
		// 元登録INFとnodeを別々に変え、null成功で後続拒否を隠しません
		for( const auto condition : {SignedIndexBindingNativeCase::STAGE_CHANGED,
									SignedIndexBindingNativeCase::STAGE_EXTERNAL,
									SignedIndexBindingNativeCase::STAGE_BAD_LENGTH}) {
			run( "I-registered-inf-invalid", withNull,
				{.nativeCase = condition, .installs = 0U, .imports = 1U, .succeeded = false},
				{{"importonly.inf", nullInf}}) ;
		}

		// 登録後の原node/rank変異だけを独立したcaseとして与えます
		for( const auto condition : {SignedIndexBindingNativeCase::STAGE_WRONG_NODE,
									SignedIndexBindingNativeCase::STAGE_WRONG_RANK,
									SignedIndexBindingNativeCase::RANK_STAGE_TIED}) {
			run( "I-registered-native-node-invalid", withNull,
				{.nativeCase = condition,
				 .stages	 = 2U,
				 .installs	 = 0U,
				 .imports	 = 1U,
				 .succeeded	 = false},
				{{"importonly.inf", nullInf}}) ;
		}

		reject( "E-key-subtree-delete",
			   inf + "[Install.HW]\r\nDelReg=Deletion\r\n[Deletion]\r\nHKR,ScsiPort,\r\n", 14004U) ;
		std::string x86 = sys ;	// 他architectureの有効PE digestと元署名を先に通します
		// 元転送又はarchitectureの独立した有限入力です
		const WORD	machine = IMAGE_FILE_MACHINE_I386 ;
		std::memcpy( x86.data() + dos.e_lfanew + offsetof( IMAGE_NT_HEADERS64, FileHeader.Machine),
					&machine, sizeof( machine)) ;
		run( "D-x86-binary", inf,
			{.qualified		 = false,
			 .stages		 = 0U,
			 .installs		 = 0U,
			 .succeeded		 = false,
			 .rejectionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BAD_EXE_FORMAT)),
			 .rejectionStage = 9U},
			{}, x86) ;
		run( "D-invalid-pe", inf,
			{.qualified		 = false,
			 .stages		 = 0U,
			 .installs		 = 0U,
			 .succeeded		 = false,
			 .rejectionError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_BAD_EXE_FORMAT)),
			 .rejectionStage = 9U},
			{}, "ordinary non-PE bytes") ;
		reject( "D-binary-not-selected-copy",
			   replaced( inf, "ServiceBinary=%12%\\fixture.sys", "ServiceBinary=%12%\\outside.sys"),
			   9U, static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))) ;
		run( "D-original-cat-mismatch", inf,
			{.nativeCase   = SignedIndexBindingNativeCase::CAB_MEMBER_FAILURE,
			 .qualified	   = false,
			 .stages	   = 0U,
			 .installs	   = 0U,
			 .succeeded	   = false,
			 .contentError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED))}) ;
		reject(
			"C-duplicate-associated-service",
			replaced(
				inf, "AddService=FixtureStorage,2,StorageService",
				"AddService=FixtureStorage,2,StorageService\r\nAddService=SecondStorage,2,StorageService"),
			9U, static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))) ;
		reject(
			"E-filter-setting",
			inf +
				"[Install.HW]\r\nAddReg=Filter\r\n[Filter]\r\nHKR,,UpperFilters,0,otherfilter\r\n",
			14004U) ;
		reject( "E-security-setting",
			   inf + "[Install.HW]\r\nAddReg=Acl\r\n[Acl]\r\nHKR,,Security,0,sddl-text\r\n",
			   14004U) ;
		reject( "E-extra-registry-field", parameters + "HKR,Parameters,TooMany,0x10001,1,extra\r\n",
			   14004U, invalid) ;
		reject( "E-unknown-registry-flag", parameters + "HKR,Parameters,UnknownFlag,0x10003,1\r\n",
			   14004U) ;
		reject( "F-unknown-device-action", inf + "[Install.HW]\r\nUnknownHardwareAction=1\r\n",
			   14003U) ;
		run( "J-target-absent-after-api", inf,
			{.nativeCase = SignedIndexBindingNativeCase::STORAGE_POST_ABSENT}) ;
		run( "J-target-read-failure-after-api", inf,
			{.nativeCase = SignedIndexBindingNativeCase::STORAGE_POST_READ_FAILURE}) ;
		run( "H-original-expired-before-stage", inf,
			{.nativeCase   = SignedIndexBindingNativeCase::STORAGE_EXPIRED,
			 .changeNative = true,
			 .stages	   = 0U,
			 .installs	   = 0U,
			 .succeeded	   = false}) ;
		run( "D-original-null-bytes-changed", withNull,
			{.nativeCase   = SignedIndexBindingNativeCase::IMPORT_HASH_CHANGED,
			 .changeNative = true,
			 .stages	   = 0U,
			 .installs	   = 0U,
			 .imports	   = 1U,
			 .succeeded	   = false},
			{{"importonly.inf", nullInf}}) ;
		// 全潜在importを後続base成功で救済しない内容負例です
		run( "F-required-null-named-service", withNull,
			{.qualified	   = false,
			 .stages	   = 0U,
			 .installs	   = 0U,
			 .succeeded	   = false,
			 .contentError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))},
			{{"importonly.inf",
			  replaced( nullInf, "AddService=,2", "AddService=UnexpectedService,2")}}) ;
		run( "F-required-null-extra-action", withNull,
			{.qualified	   = false,
			 .stages	   = 0U,
			 .installs	   = 0U,
			 .succeeded	   = false,
			 .contentError = static_cast<NativeError>( 0xe0000102U)},
			{{"importonly.inf",
			  nullInf +
				  "[NullInstall.NT.HW]\r\nAddReg=Extra\r\n[Extra]\r\nHKR,,unexpected,0x10001,1\r\n"}}) ;
		run( "F-missing-required-import", withNull,
			{.qualified	   = false,
			 .stages	   = 0U,
			 .installs	   = 0U,
			 .succeeded	   = false,
			 .contentError = static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_NOT_FOUND))}) ;
		reject( "F-missing-needs", inf + "[Install.HW]\r\nInclude=pci.inf\r\nNeeds=Missing.HW\r\n",
			   100U, static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))) ;
		reject( "F-package-needs-cycle",
			   replaced( inf, "CopyFiles=Files\r\n", "CopyFiles=Files\r\nNeeds=Cycle\r\n") +
				   "[Cycle]\r\nNeeds=Install\r\n",
			   100U, static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))) ;
		reject(
			"I-unknown-copy-flag",
			replaced( inf, "[Files]\r\nfixture.sys\r\n", "[Files]\r\nfixture.sys,,,0x80000000\r\n"),
			9U) ;
		reject( "I-copy-security-effect", inf + "[Files.security]\r\nD:P(A;;GA;;;SY)\r\n", 9U) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 真署名outer sizeから実UI共有承認/予算guardと匿名拒否へ有限接続します
 * @param[in,out] context assertion集計先です
 * @note 隔離RAM署名/保存と既fakeだけを使い、実HTTP/driver/restoreを呼びません
 */
//------------------------------------------------------------------------------
void runSignedIndexKnownSizeApprovalTests( TestContext &context)
{
	RamKey key ;	// 既RAM鍵だけで原record/manifestを署名します
	key.generate( 3072U) ;
	const IndexLookupContext			current{71U, 72U, 73U} ;			// 実端末へ接続しない元contextです
	const std::array<std::wstring, 2U>	present{L"opaque-a", L"opaque-b"} ;	// 異なる二deviceです
	const OfficialPreparationLimits		limits{2147483648ULL, 2147483648ULL, 2147483648ULL, 2U,
										   4U} ;	// 原fallback値です
	const std::array<std::uint64_t, 5U> sizes{58973U, 39157U, 101U, 103U,
											  107U} ;	// outerだけの元申告です
	std::vector<std::string>			rows ;			// 元署名を通す独立した五tupleです
	// 同一IDや共有payloadへ重複計上せず、五つの外側sizeを元recordへ固定します
	for( std::size_t index{}; index < sizes.size(); ++index) {
		auto raw = descriptorRecord( descriptorFixture()) ;	// 型認証済み標準archiveです
		raw = replaced( std::move( raw), "\"maximumBytes\":134217728", "\"maximumBytes\":2147483648") ;
		raw = replaced( std::move( raw), "\"valueBytes\":1234",
					   "\"valueBytes\":" + std::to_string( sizes[index])) ;
		raw = replaced( std::move( raw), "\"recordId\":\"metadata\"",
					   "\"recordId\":\"reservation-" + std::to_string( index) + "\"") ;
		// 先頭二参照は、元kindを既resolverの異なるopaque deviceへ結びます
		if( index == 1U) {
			raw = replaced( std::move( raw), "\"kind\":\"HARDWARE\"", "\"kind\":\"COMPATIBLE\"") ;
		}

		rows.push_back( std::move( raw)) ;
	}

	auto		   snapshot = lookupSnapshot( key, rows.front(), rows.size(), nullptr, 9U,
											 rows) ;	// 隔離commit/reloadの原署名です
	LookupResolver resolver ;							// 既public ID resolverだけを使います
	auto		   lookup = lookupSignedIndexRecords( snapshot, current, current, present, {}, NOW,
													 &resolver) ;	// 実lookupです
	DRIVERCRATE_EXPECT( context, lookup.lookup && lookup.lookup->relations().size() == 5U) ;
	// Fixture生成失敗から下位処理を開始しません
	if( !lookup.lookup) {
		return ;
	}

	auto owned = std::make_shared<const SignedIndexRecordLookup>(
		// immutable元tupleです
		std::move( *lookup.lookup)) ;
	SignedIndexAcquisitionAdapter adapter ;	// 実describe/bindingを使う既fixtureです
	DRIVERCRATE_EXPECT( context, signed_index_acquisition_detail::Access::beginFixture(
									adapter, owned, current, IndexTargetOs::WINDOWS_11, NOW) == 0) ;
	OfficialPreparationPlan plan{current.scanSessionId, 1U, limits, {}} ;	// 同scanだけの五targetです
	// 元署名のexact outer sizeが全targetへ使われ、再記述も同じ値を保つことを確認します
	for( std::size_t index{}; index < sizes.size(); ++index) {
		SignedIndexPreparationDescription description ;	// 元targetだけを受けます
		DRIVERCRATE_EXPECT( context,
						   adapter.describe( index, current, NOW, limits, description) == 0 &&
							   description.target) ;
		// 欠損targetを成功として後段へ渡しません
		if( !description.target) {
			return ;
		}

		DRIVERCRATE_EXPECT( context, description.target->maximumBytes == sizes[index]) ;
		plan.targets.push_back( *description.target) ;
		SignedIndexPreparationDescription repeated ;	// 共有bindingの元再検証です
		DRIVERCRATE_EXPECT( context, adapter.describe( index, current, NOW, limits, repeated) == 0 &&
										repeated.target == description.target) ;
	}

	SignedIndexAcquisitionAdapter oversized ;	// 元cap超過を再利用済みbindingで隠しません
	DRIVERCRATE_EXPECT( context,
					   signed_index_acquisition_detail::Access::beginFixture(
						   oversized, owned, current, IndexTargetOs::WINDOWS_11, NOW) == 0) ;
	auto smallLimits			 = limits ;	// 明示された小capは拡大しません
	smallLimits.maximumFileBytes = 64U ;
	SignedIndexPreparationDescription refused ;	// 拒否時はtargetなしです
	DRIVERCRATE_EXPECT( context, oversized.describe( 0U, current, NOW, smallLimits, refused) ==
										HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) &&
									!refused.target) ;
	std::vector<UpdateCandidate> candidates ;	// 実UIに渡す元参照と同じshapeです
	// 同deviceを二選択せず、当該五targetへ一対一に結ぶ非導入参照です
	for( std::size_t index{}; index < plan.targets.size(); ++index) {
		UpdateCandidate candidate ;	// 実driver identityを含みません
		candidate.identity		 = L"PRIVATE_SENTINEL_reference-" + std::to_wstring( index) ;
		candidate.deviceIdentity = index == 1U ? present[1] : present[0] ;
		candidate.providerId	 = SIGNED_INDEX_PROVIDER_ID ;
		candidate.discoveryBasis = CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
		candidate.preparationTargetIdentity = plan.targets[index].identity ;
		candidates.push_back( std::move( candidate)) ;
	}

	const std::array<std::size_t, 2U> selected{0U, 1U} ;	// 元二参照だけを明示します
	BeginResult						  budgetRejection ;		// 元UI表示と同じ結果を匿名sinkへ投影します
	OfficialPreparationApproval		  oldApproval ;			// 原2GiB予約の完全snapshotです
	// 全成功/警告付き成功の両方で、同じUI共有builderと実controllerを使います
	for( const auto outcome : {OutcomeCode::SUCCESS, OutcomeCode::SUCCEEDED_WITH_ERRORS}) {
		// 旧2GiB target二件と、署名sizeへ結んだ新targetを同じ境界へ渡します
		for( const bool legacy : {true, false}) {
			auto currentPlan = plan ;	// 同意/出典/原上限を変更しません
			// 旧sourceの予約値だけを再現し、guardの期待は維持します
			if( legacy) {
				// 未選択も含め元全targetの上限を旧値へ固定します
				for( auto &target : currentPlan.targets) {
					target.maximumBytes = 2147483648ULL ;
				}
			}

			OperationController controller ;						// 実workerを生成せずUI側の境界だけを確認します
			const auto			started = controller.beginScan() ;	// 新operation1の同scanです
			ScanResult			scan{.succeeded		= true,
									 .scanSessionId = current.scanSessionId,
									 .outcome		= outcome,
									 .state			= ProviderScanState::CANDIDATES_AVAILABLE,
									 .candidates	= candidates} ;	// 元参照はまだ非installableです
			DRIVERCRATE_EXPECT( context, controller.completeScan( started.operationId, scan)) ;
			DRIVERCRATE_EXPECT( context,
							   controller.setPreparationPlan( started.operationId, currentPlan)) ;
			auto approval = makeInstallPreparationApproval( controller.preparationPlan(),
														   controller.scanSessionId(), candidates,
														   selected) ;	// 実UIの共有builderです
			DRIVERCRATE_EXPECT( context, approval && approval->operationId == 0U &&
											approval->decisions.size() == 5U &&
											approval->installIntentIdentities.size() == 2U) ;
			// builderの失敗を手書きした正例へ置き換えません
			if( !approval) {
				return ;
			}

			DRIVERCRATE_EXPECT( context,
							   std::ranges::count( approval->decisions, true,
												  &OfficialPreparationDecision::acquire) == 2) ;
			const auto begin = controller.beginPreparation( *approval) ;	// 取得/導入は呼びません
			DRIVERCRATE_EXPECT( context, begin.accepted == !legacy) ;
			// 原budget guardを維持し、拒否後も元scan/未承認値を保持します
			if( legacy) {
				DRIVERCRATE_EXPECT( context,
								   begin.error == BeginError::INVALID_PREPARATION &&
									   begin.preparationError ==
										   OfficialPreparationError::BUDGET_EXCEEDED &&
									   begin.preparationStage == PreparationBeginStage::APPROVAL &&
									   approval->operationId == 0U &&
									   controller.state() == ApplicationState::SCAN_READY) ;
				budgetRejection = begin ;
				oldApproval		= *approval ;
			} else {
				DRIVERCRATE_EXPECT( context,
								   begin.preparationError == OfficialPreparationError::NONE &&
									   controller.state() == ApplicationState::PREPARING &&
									   approval->operationId != 0U) ;
			}
		}
	}

	// 完全snapshot/重複判断/同意漏れ/前提確認漏れ/再送の各原guardを独立確認します
	for( unsigned variant{}; variant < 5U; ++variant) {
		auto original = plan ;	// 他条件を変えず、拒否する一fieldだけを選びます
		// 同意漏れの試験だけは元planに同意必須の全文を設定します
		if( variant == 2U) {
			original.targets[0].terms		 = OfficialPreparationTerms::ACCEPTANCE_REQUIRED ;
			original.targets[0].eulaText	 = L"Fixture full terms" ;
			original.targets[0].eulaRevision = L"fixture-v1" ;
		}

		// 具体的な元条件を未確認のまま承認へ渡します
		if( variant == 3U) {
			original.targets[0].requiresPrerequisiteConfirmation = true ;
			original.targets[0].prerequisiteText				 = L"Fixture prerequisite" ;
		}

		OperationController controller ;						// 一失敗を他の計画の失敗へ重ねません
		const auto			started = controller.beginScan() ;	// 元sessionへだけ結びます
		ScanResult			scan{.succeeded		= true,
								 .scanSessionId = current.scanSessionId,
								 .outcome		= OutcomeCode::SUCCEEDED_WITH_ERRORS,
								 .candidates	= candidates} ;	// partialも正当に受理します
		DRIVERCRATE_EXPECT( context,
						   controller.completeScan( started.operationId, scan) &&
							   controller.setPreparationPlan( started.operationId, original)) ;
		auto approval =
			makeInstallPreparationApproval( controller.preparationPlan(), controller.scanSessionId(),
										   candidates, selected) ;	// UI共有処理を通します
		DRIVERCRATE_EXPECT( context, approval.has_value()) ;
		// Fixture不成立で実controllerを成功扱いにしません
		if( !approval) {
			return ;
		}

		// 元対象のbyte改変を同じtarget identityで通しません
		if( variant == 0U) {
			++approval->decisions[0].target.maximumBytes ;
		}

		// 一targetの重複/別targetの省略を合計件数一致で補完しません
		if( variant == 1U) {
			approval->decisions[1] = approval->decisions[0] ;
		}

		// 旧operationをfresh承認として再使用しません
		if( variant == 4U) {
			approval->operationId = 99U ;
		}

		const auto rejected = controller.beginPreparation( *approval) ;	// worker送信前の実判定です
		DRIVERCRATE_EXPECT(
			context,
			!rejected.accepted && rejected.error == BeginError::INVALID_PREPARATION &&
				(variant == 4U ? rejected.preparationStage == PreparationBeginStage::REPLAY &&
									 rejected.preparationError == OfficialPreparationError::NONE
							   : rejected.preparationStage == PreparationBeginStage::APPROVAL &&
									 rejected.preparationError ==
										 OfficialPreparationError::INVALID_APPROVAL)) ;
	}

	// 同じ配布を使う二台で、通常の共有と機器確認の個別結合を比較します
	for( const bool needsConfirmation : {false, true}) {
		auto raw = rows[0] ;	// 既存の一配布の署名前の行です
		// 具体的な機器確認だけを追加し、同じ配布物と根拠を維持します
		if( needsConfirmation) {
			raw = replaced(
				std::move( raw),
				"\"prerequisites\":{\"state\":\"KNOWN\",\"reason\":\"\",\"items\":[]}",
				"\"prerequisites\":{\"state\":\"KNOWN\",\"reason\":\"\",\"items\":[{\"kind\":"
				"\"USER_CONFIRMATION\",\"description\":\"Confirm the selected device\","
				"\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
					std::string{RECORD_EVIDENCE_HASH} + "\"}]}") ;
		}

		const std::array<std::string, 2U> sharedRows{
			raw, replaced( replaced( raw, "reservation-0", "shared-record"), "\"kind\":\"HARDWARE\"",
						  "\"kind\":\"COMPATIBLE\"")} ;	// 条件・出典・配布物を二台で同じにします
		auto sharedLookup = lookupSignedIndexRecords(
			lookupSnapshot( key, sharedRows[0], sharedRows.size(), nullptr, 9U, sharedRows), current,
			current, present, {}, NOW, &resolver) ;	// 既lookupで全件認証します
		DRIVERCRATE_EXPECT( context, sharedLookup.lookup.has_value()) ;
		// 元lookupなしを共有成功にしません
		if( !sharedLookup.lookup) {
			continue ;
		}

		SignedIndexAcquisitionAdapter shared ;	// 新たなcapやsourceを生成しません
		DRIVERCRATE_EXPECT( context, signed_index_acquisition_detail::Access::beginFixture(
										shared,
										std::make_shared<const SignedIndexRecordLookup>(
											std::move( *sharedLookup.lookup)),
										current, IndexTargetOs::WINDOWS_11, NOW) == 0) ;
		SignedIndexPreparationDescription first ;	// 原共有targetです
		SignedIndexPreparationDescription second ;	// 他deviceの同tupleです
		DRIVERCRATE_EXPECT(
			context, shared.describe( 0U, current, NOW, limits, first) == 0 &&
						 shared.describe( 1U, current, NOW, limits, second) == 0 && first.target &&
						 second.target && (first.target == second.target) == !needsConfirmation &&
						 first.target->maximumBytes == sizes[0] &&
						 second.target->maximumBytes == sizes[0] &&
						 first.target->requiresPrerequisiteConfirmation == needsConfirmation &&
						 second.target->requiresPrerequisiteConfirmation == needsConfirmation &&
						 first.target->deviceCount == (needsConfirmation ? 1U : 2U) &&
						 second.target->deviceCount == first.target->deviceCount) ;
	}

	std::vector<std::string> unknownRows ;	// 未知hash/sizeを既知小容量へ補完しません
	// 元五targetのouter証拠だけをUNKNOWNへ変更して真署名します
	for( std::size_t index{}; index < rows.size(); ++index) {
		auto	   raw = rows[index] ;	// 他の原条件は変更しません
		const auto known =
			"{\"state\":\"KNOWN\",\"sha256\":\"" + std::string{RECORD_CLAIM_HASH} +
			"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
			std::string{RECORD_EVIDENCE_HASH} + "\",\"reason\":\"\"}" ;	// 元hash二申告です
		const std::string unknown =
			// 元不足理由を保ちます
			"{\"state\":\"UNKNOWN\",\"sha256\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"not published\"}" ;
		raw = replaced( std::move( raw), known, unknown) ;
		raw = replaced( std::move( raw), known, unknown) ;
		raw = replaced( std::move( raw),
					   "{\"state\":\"KNOWN\",\"valueBytes\":" + std::to_string( sizes[index]) +
						   ",\"reason\":\"\"}",
					   "{\"state\":\"UNKNOWN\",\"valueBytes\":0,\"reason\":\"not inspected\"}") ;
		unknownRows.push_back( std::move( raw)) ;
	}

	auto unknownLookup = lookupSignedIndexRecords(
		lookupSnapshot( key, unknownRows[0], unknownRows.size(), nullptr, 9U, unknownRows), current,
		current, present, {}, NOW, &resolver) ;	// UNKNOWNも同codecを通します
	DRIVERCRATE_EXPECT( context, unknownLookup.lookup.has_value()) ;
	// 未知を正例へ読み替えず、元2GiBの二予約が拒否されることを確認します
	if( unknownLookup.lookup) {
		SignedIndexAcquisitionAdapter unknown ;	// 原capを使う別issuerです
		DRIVERCRATE_EXPECT( context, signed_index_acquisition_detail::Access::beginFixture(
										unknown,
										std::make_shared<const SignedIndexRecordLookup>(
											std::move( *unknownLookup.lookup)),
										current, IndexTargetOs::WINDOWS_11, NOW) == 0) ;
		OfficialPreparationPlan unknownPlan{
			current.scanSessionId, 1U, limits, {}} ;	// 保守的な元予約です
		// 元五targetを欠けなく取得して、二選択の同snapshotを作ります
		for( std::size_t index{}; index < sizes.size(); ++index) {
			SignedIndexPreparationDescription description ;	// UNKNOWNをexact sizeへしません
			DRIVERCRATE_EXPECT( context,
							   unknown.describe( index, current, NOW, limits, description) == 0 &&
								   description.target &&
								   description.target->maximumBytes == 2147483648ULL) ;
			// 欠損targetを架空の2GiBへ補完しません
			if( !description.target) {
				return ;
			}

			unknownPlan.targets.push_back( *description.target) ;
		}

		OperationController controller ;						// 実workerを開始しません
		const auto			started = controller.beginScan() ;	// 同じ元選択へだけ接続します
		ScanResult			scan{.succeeded		= true,
								 .scanSessionId = current.scanSessionId,
								 .outcome		= OutcomeCode::SUCCEEDED_WITH_ERRORS,
								 .candidates	= candidates} ;	// 部分成功を拒否理由にしません
		DRIVERCRATE_EXPECT( context,
						   controller.completeScan( started.operationId, scan) &&
							   controller.setPreparationPlan( started.operationId, unknownPlan)) ;
		auto approval =
			makeInstallPreparationApproval( controller.preparationPlan(), controller.scanSessionId(),
										   candidates, selected) ;	// 元target IDだけを対応させます
		DRIVERCRATE_EXPECT( context, approval.has_value()) ;
		// 未知の承認不成立を成功扱いにしません
		if( approval) {
			const auto rejected =
				// 二つの元capが累計超過です
				controller.beginPreparation( *approval) ;
			DRIVERCRATE_EXPECT( context, !rejected.accepted &&
											rejected.preparationError ==
												OfficialPreparationError::BUDGET_EXCEEDED &&
											controller.state() == ApplicationState::SCAN_READY) ;
		}
	}

	const auto folder =
		std::filesystem::absolute( std::filesystem::path{L"work/tmp"} /
								  (L"841-approval-" + std::to_wstring( GetCurrentProcessId()) +
								   L"-" + std::to_wstring( GetTickCount64())))
			.lexically_normal() ;	// 自己新規fixtureだけです
	DRIVERCRATE_EXPECT( context, std::filesystem::create_directory( folder)) ;
	LocalDiagnosticLog log ;	// 本番logを開きません
	local_diagnostic_detail::Access::startPaused( log, folder.native()) ;
	recordPreparationBeginRejectedDiagnostics( 1U, oldApproval, budgetRejection, &log) ;
	local_diagnostic_detail::Access::resume( log) ;
	DRIVERCRATE_EXPECT( context, local_diagnostic_detail::Access::drain( log)) ;
	log.stop() ;
	std::string rawLog ;	// fixture byteだけをprivacyと元理由へ照合します
	// 二slotだけを読み、原選択ID/URL/本文がないことを確認します
	for( const auto name : {L"scan-0.log", L"scan-1.log"}) {
		std::ifstream input( folder / L"log" / name, std::ios::binary) ;	// 私有fixtureの数値だけです
		rawLog.append( std::istreambuf_iterator<char>( input), std::istreambuf_iterator<char>()) ;
	}

	DRIVERCRATE_EXPECT( context,
					   rawLog.find( "event=preparation_begin_rejected") != std::string::npos &&
						   rawLog.find( "status=10 error=0 stage=3 outcome=7") != std::string::npos) ;
	DRIVERCRATE_EXPECT(
		context,
		rawLog.find(
			"requiredBytes=4294967296 providerLimitBytes=2147483648 sessionLimitBytes=2147483648") !=
				std::string::npos &&
			rawLog.find( "diagnosticRevision=" + std::to_string( LOCAL_DIAGNOSTIC_REVISION)) !=
				std::string::npos) ;
	DRIVERCRATE_EXPECT( context, rawLog.find( "PRIVATE_SENTINEL") == std::string::npos &&
									rawLog.find( "index-acquisition-") == std::string::npos &&
									rawLog.find( "https:") == std::string::npos) ;
	// 非recursiveの自己生成fileだけを回収します。未知の残りを無視しません
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( folder / L"log/scan-0.log") &&
									std::filesystem::remove( folder / L"log/scan-1.log") &&
									std::filesystem::remove( folder / L"log") &&
									std::filesystem::remove( folder)) ;

	// 実grant/HTTP cap/hash/sizeと失効leaseは既完全fakeで独立確認します
	for( const unsigned scenario : {0U, 1U, 2U, 6U}) {
		const std::string zip =
			std::string{"PK\x05\x06", 4U} + std::string( 18U, '\0') ;	// 有効な空ZIPです
		const auto zipHash = recordDigest( key, zip) ;					// 下位fixtureの元外側hashです
		auto	   raw	   = descriptorRecord( descriptorFixture()) ;	// 既private helperと同じ型です
		raw				   = replaced( std::move( raw), RECORD_CLAIM_HASH, zipHash) ;
		raw				   = replaced( std::move( raw), RECORD_CLAIM_HASH, zipHash) ;
		raw				   = replaced( std::move( raw), "\"valueBytes\":1234",
						  scenario == 2U ? "\"valueBytes\":23" : "\"valueBytes\":22") ;
		// 計算hashだけの原不一致を取得成功から補完しません
		if( scenario == 1U) {
			raw = replaced( std::move( raw),
						   "\"calculatedHash\":{\"state\":\"KNOWN\",\"sha256\":\"" + zipHash,
						   "\"calculatedHash\":{\"state\":\"KNOWN\",\"sha256\":\"" +
							   std::string{RECORD_CLAIM_HASH}) ;
			raw = replaced(
				std::move( raw),
				"\"publishedHash\":{\"state\":\"KNOWN\",\"sha256\":\"" + zipHash +
					"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
					std::string{RECORD_EVIDENCE_HASH} + "\",\"reason\":\"\"}",
				"\"publishedHash\":{\"state\":\"UNKNOWN\",\"sha256\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"not published\"}") ;
		}

		// 外側hash/sizeともUNKNOWNなら元capを保守的に維持します
		if( scenario == 6U) {
			const auto known =
				"{\"state\":\"KNOWN\",\"sha256\":\"" + zipHash +
				"\",\"evidenceUrl\":\"https://vendor.example/support\",\"evidenceSha256\":\"" +
				std::string{RECORD_EVIDENCE_HASH} + "\",\"reason\":\"\"}" ;	// 元既知tupleです
			const std::string unknown =
				// codecへそのまま渡します
				"{\"state\":\"UNKNOWN\",\"sha256\":\"\",\"evidenceUrl\":\"\",\"evidenceSha256\":\"\",\"reason\":\"not published\"}" ;
			raw = replaced( std::move( raw), known, unknown) ;
			raw = replaced( std::move( raw), known, unknown) ;
			raw =
				replaced( std::move( raw), "{\"state\":\"KNOWN\",\"valueBytes\":22,\"reason\":\"\"}",
						 "{\"state\":\"UNKNOWN\",\"valueBytes\":0,\"reason\":\"not inspected\"}") ;
		}

		auto original =
			lookupSignedIndexRecords( lookupSnapshot( key, raw), current, current, present, {}, NOW,
									 &resolver) ;	// 真署名の別recordです
		DRIVERCRATE_EXPECT( context, original.lookup.has_value()) ;
		// 私有lookupなしを下位fakeの正例にしません
		if( original.lookup) {
			runSignedIndexAcquisitionAdapterTests(
				context,
				std::make_shared<const SignedIndexRecordLookup>( std::move( *original.lookup)), NOW,
				scenario) ;
		}
	}
}

} // namespace drivercrate::test

#include "index_capacity_tests.cpp"
