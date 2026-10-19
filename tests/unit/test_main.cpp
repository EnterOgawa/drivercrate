//------------------------------------------------------------------------------
/**
 * @file test_main.cpp
 * @brief DriverCrate単体試験エントリーポイント。
 * @version 01.31.00
 * @date 2026/09/01
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  公式MSI stream試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  WinOF-2 driver閉包試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  WinOF-2内容・適用性監査試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  公式release端末内観測試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  公式release観測永続化試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Local probe試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Live検索ASCII診断試験を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  段階別計測の非通信試験を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索専用の型と拒否境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/14  非導入Local AIの有限境界試験を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  公式探索の固定評価集合fixtureを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  Record限定download grant試験を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  委譲取得と共通package検査の接続試験を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/15  公式record payload三方式のrouting試験を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/09/15  公式自動探索Core境界試験を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/09/15  公式自動探索固定root adapter試験を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/09/15  組み込み自動探索registration接続試験を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/09/15  自動探索EULA完全一致group試験を追加。
 * Ver.01.10.00 Shunji Ogawa  2026/09/20  保存graph評価core試験を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/09/20  保存graph入力・GPU接続と非導入検証を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/09/20  AI選択と公式検査用取得の接続試験を追加。
 * Ver.01.13.00 Shunji Ogawa  2026/09/21  目的照合offline再生codec試験を追加。
 * Ver.01.14.00 Shunji Ogawa  2026/09/22  静的HTML正規化試験を追加。
 * Ver.01.15.00 Shunji Ogawa  2026/09/22  Live HTML公式GETの非通信試験を追加。
 * Ver.01.16.00 Shunji Ogawa  2026/09/23  Intel EXE取得専用parser試験を追加。
 * Ver.01.17.00 Shunji Ogawa  2026/09/28  Intel製品identityの有限解析試験を追加。
 * Ver.01.17.01 Shunji Ogawa  2026/10/02  AI依存を撤去し非AI共通処理と試験を維持。
 * Ver.01.18.00 Shunji Ogawa  2026/10/05  保守専用PE内表の回帰を追加。
 * Ver.01.19.00 Shunji Ogawa  2026/10/05  索引hintと通常検査の非導入結合回帰を追加。
 * Ver.01.20.00 Shunji Ogawa  2026/10/11  原byte署名manifestの実CNG回帰を追加。
 * Ver.01.21.00 Shunji Ogawa  2026/10/11  固定GZip asset byteの別native回帰groupを追加。
 * Ver.01.22.00 Shunji Ogawa  2026/10/11  署名済み配布record schemaの独立回帰groupを追加。
 * Ver.01.23.00 Shunji Ogawa  2026/10/11  隔離diskの署名索引保護保存groupを追加。
 * Ver.01.24.00 Shunji Ogawa  2026/10/11  保存snapshot公開ID照合groupと限定実行を追加。
 * Ver.01.25.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.26.00 Shunji Ogawa  2026/10/12  変更module独立targetと通常全groupの分母を分離。
 * Ver.01.27.00 Shunji Ogawa  2026/10/15  公式policy groupの限定再現引数を追加。
 * Ver.01.27.01 Shunji Ogawa  2026/10/15  全体INF件数の正負再現groupを追加。
 * Ver.01.27.02 Shunji Ogawa  2026/10/16  RAM manifest認証groupの限定実行入口を追加。
 * Ver.01.28.00 Shunji Ogawa  2026/10/16  固定GitHub refreshの完全fake回帰入口を追加。
 * Ver.01.29.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * Ver.01.30.00 Shunji Ogawa  2026/10/17  署名索引のHTTP・実容量三group限定入口を追加。
 * Ver.01.31.00 Shunji Ogawa  2026/10/19  保護storeと認証移動の限定回帰入口を追加。
 * </pre>
 *
 * @note 全unit test groupを順に実行し、process終了codeを返します。
 */
//------------------------------------------------------------------------------

#include "amd_catalog_parser_tests.h"
#include "asix_catalog_parser_tests.h"
#include "asrock_catalog_parser_tests.h"
#include "asrock_system_identity_tests.h"
#include "asus_catalog_parser_tests.h"
#include "asus_system_identity_tests.h"
#include "broadcom_official_provider_tests.h"
#include "candidate_audit_tests.h"
#include "official_workflow_evaluation_tests.h"
#include "candidate_selection_tests.h"
#include "candidate_source_group_tests.h"
#include "dell_catalog_parser_tests.h"
#include "dell_server_catalog_parser_tests.h"
#include "hp_catalog_parser_tests.h"
#include "intel_ethernet_server_page_parser_tests.h"
#include "intel_collector_identity_parser_tests.h"
#include "intel_wireless_package_tests.h"
#include "intel_wireless_page_parser_tests.h"
#include "intel_download_only_page_tests.h"
#include "lenovo_catalog_parser_tests.h"
#include "live_search_diagnostics_tests.h"
#include "local_coverage_tests.h"
#include "metadata_search_tests.h"
#include "metadata_search_runner_tests.h"
#include "metadata_search_budget_tests.h"
#include "metadata_search_http_tests.h"
#include "metadata_inventory_tests.h"
#include "nvidia_catalog_parser_tests.h"
#include "nvidia_winof2_catalog_parser_tests.h"
#include "nvidia_winof2_driver_audit_tests.h"
#include "nvidia_winof2_driver_package_tests.h"
#include "official_acquisition_tests.h"
#include "official_delegated_package_inspection_tests.h"
#include "official_discovery_tests.h"
#include "official_discovery_eula_tests.h"
#include "official_discovery_provider_adapter_tests.h"
#include "official_discovery_record_adapter_tests.h"
#include "official_download_grant_tests.h"
#include "official_driver_closure_tests.h"
#include "official_driver_package_tests.h"
#include "official_driver_rank_tests.h"
#include "official_gzip_tests.h"
#include "official_msi_tests.h"
#include "official_preparation_operation_tests.h"
#include "official_preparation_tests.h"
#include "official_prepared_acquisition_tests.h"
#include "official_record_payload_routing_tests.h"
#include "official_release_local_probe_tests.h"
#include "official_release_metadata_tests.h"
#include "official_release_observation_store_tests.h"
#include "official_release_observation_tests.h"
#include "official_seven_zip_tests.h"
#include "official_sfx_tests.h"
#include "maintenance_embedded_file_table_tests.h"
#include "indexed_driver_package_inspection_tests.h"
#include "official_source_policy_tests.h"
#include "official_validation_tests.h"
#include "official_zip_tests.h"
#include "openpgp_signature_verifier_tests.h"
#include "signed_index_manifest_tests.h"
#include "signed_index_refresh_tests.h"
#include "operation_controller_tests.h"
#include "package_selection_tests.h"
#include "platform/com_raii.h"
#include "prepared_audit_display_tests.h"
#include "prolific_official_provider_tests.h"
#include "prolific_serial_package_tests.h"
#include "protected_install_tests.h"
#include "provider_preparation_worker_tests.h"
#include "provider_registry_tests.h"
#include "scan_measurement_diagnostics_tests.h"
#include "scan_measurement_tests.h"
#include "silicon_labs_official_provider_tests.h"
#include "silicon_labs_serial_package_tests.h"
#include "test_framework.h"
#include "user_selected_inf_package_provider_tests.h"
#include "vaio_catalog_parser_tests.h"
#include "wch_official_provider_tests.h"
#include "wch_serial_package_tests.h"
#include "windows_update_provider_tests.h"

#include <exception>
#include <iostream>
#include <string_view>

//------------------------------------------------------------------------------
/**
 * @brief 全 unit test group を実行して process result を返す。
 * @param[in] argc 引数数。限定group指定は2です。
 * @param[in] argv Process寿命の引数。限定指定以外は全groupを実行します。
 * @return 全 assertion 成功時は 0、それ以外は 1。
 */
//------------------------------------------------------------------------------
int main( const int argc, const char *const argv[])
{
	drivercrate::test::TestContext	context ;							// 全test groupのassertion集計先。
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// Test process全体のCOM MTA。
	// COMが初期化できないthreadでは検証対象を呼び出さず、初期化失敗として試験を終了する。
	if( FAILED( apartment.result())) {
		std::cerr << "COM initialization failed: " << apartment.result() << '\n' ;
		return 1 ;
	}

	try {
		// 独立targetは変更moduleだけを固定順に実行し、通常aggregateと分離します。
#if defined( DRIVERCRATE_INDEX_BINDING_STANDALONE)
		// 独立processの分母を未知optionで変更しません。
		if( argc != 1 || argv == nullptr) {
			return 2 ;
		}

		drivercrate::test::runSignedIndexRecordLookupTests( context) ;
		drivercrate::test::runOfficialPreparationTests( context) ;
		drivercrate::test::runOfficialPreparationOperationTests( context) ;
		drivercrate::test::runOfficialPreparedAcquisitionTests( context) ;
		drivercrate::test::runOfficialDriverRankTests( context) ;
		drivercrate::test::runCandidateAuditTests( context) ;
		// 通常aggregateは既存の全groupと限定optionをそのまま維持します。
#else
		// 実DPAPIの自作rootだけで旧store回帰と移動回帰を固定実行します。
		if( argc == 2 && std::string_view{argv[1]} == "--signed-index-store") {
			drivercrate::test::runSignedIndexStoreTests( context) ;
			drivercrate::test::runSignedIndexStoreMigrationTests( context) ;
			std::cout << "Assertions: " << context.assertionCount()
					  << ", failures: " << context.failureCount() << '\n' ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// RAM暗号・実容量・完全fake HTTPの三groupだけを固定順で実行します。
		if( argc == 2 && std::string_view{argv[1]} == "--signed-index-boundaries") {
			const int manifestAssertions = context.assertionCount() ;	// Manifest群前の原件数です。
			const int manifestFailures	 = context.failureCount() ;		// Manifest群前の原失敗数です。
			drivercrate::test::runSignedIndexManifestTests( context) ;
			std::cout << "Signed index boundary group manifest: assertions: "
					  << context.assertionCount() - manifestAssertions
					  << ", failures: " << context.failureCount() - manifestFailures << '\n' ;
			const int assetAssertions = context.assertionCount() ;	// Asset群前の原件数です。
			const int assetFailures	  = context.failureCount() ;	// Asset群前の原失敗数です。
			drivercrate::test::runSignedIndexAssetBytesTests( context) ;
			std::cout << "Signed index boundary group asset bytes: assertions: "
					  << context.assertionCount() - assetAssertions
					  << ", failures: " << context.failureCount() - assetFailures << '\n' ;
			const int refreshAssertions = context.assertionCount() ;	// Refresh群前の原件数です。
			const int refreshFailures	= context.failureCount() ;		// Refresh群前の原失敗数です。
			drivercrate::test::runSignedIndexRefreshTests( context) ;
			std::cout << "Signed index boundary group refresh: assertions: "
					  << context.assertionCount() - refreshAssertions
					  << ", failures: " << context.failureCount() - refreshFailures << '\n' ;
			std::cout << "Assertions: " << context.assertionCount()
					  << ", failures: " << context.failureCount() << '\n' ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 固定索引refreshの完全fake groupだけを実行します。
		// 通常worker queueの非通信回帰を明示groupとして実到達へ結びます。
		if( argc == 2 && std::string_view{argv[1]} == "--provider-preparation-worker") {
			drivercrate::test::runProviderPreparationWorkerTests( context) ;
			std::cout << "Assertions: " << context.assertionCount()
					  << ", failures: " << context.failureCount() << '\n' ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// P4の元固定HTTP/codec/store glue回帰だけを実行します。
		if( argc == 2 && std::string_view{argv[1]} == "--signed-index-refresh") {
			drivercrate::test::runSignedIndexRefreshTests( context) ;
			std::cout << "Assertions: " << context.assertionCount()
					  << ", failures: " << context.failureCount() << '\n' ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// RAM内のmanifest認証groupだけを実行し、保存や機器を扱うgroupへ進みません。
		if( argc == 2 && std::string_view{argv[1]} == "--signed-index-manifest") {
			drivercrate::test::runSignedIndexManifestTests( context) ;
			std::cout << "Assertions: " << context.assertionCount()
					  << ", failures: " << context.failureCount() << '\n' ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 全体INF件数の修正前後を同じ表示・delegated groupで再現します。
		if( argc == 2 && std::string_view{argv[1]} == "--preparation-content-count") {
			drivercrate::test::runPreparedAuditDisplayTests( context) ;
			drivercrate::test::runOfficialDelegatedPackageInspectionTests( context) ;
			std::cout << "Assertions: " << context.assertionCount()
					  << ", failures: " << context.failureCount() << '\n' ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 取得前のMIME回帰確認では既存公式policy groupだけを選択します。
		if( argc == 2 && std::string_view{argv[1]} == "--official-source-policy") {
			drivercrate::test::runOfficialSourcePolicyTests( context) ;
			std::cout << "Assertions: " << context.assertionCount()
					  << ", failures: " << context.failureCount() << '\n' ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		// 新しいseamの選択試験だけを実行し、旧成功済み全groupの反復を避ける。
		if( argc == 2 && (std::string_view{argv[1]} == "--signed-index-record-lookup" ||
						 std::string_view{argv[1]} == "--index-candidate-binding")) {
			drivercrate::test::runSignedIndexRecordLookupTests( context) ;
			std::cout << "Assertions: " << context.assertionCount()
					  << ", failures: " << context.failureCount() << '\n' ;
			return context.failureCount() == 0 ? 0 : 1 ;
		}

		drivercrate::test::runOperationControllerTests( context) ;
		drivercrate::test::runCandidateAuditTests( context) ;
		drivercrate::test::runOfficialWorkflowEvaluationTests( context) ;
		drivercrate::test::runCandidateSelectionTests( context) ;
		drivercrate::test::runCandidateSourceGroupTests( context) ;
		drivercrate::test::runLocalCoverageTests( context) ;
		drivercrate::test::runMetadataSearchTests( context) ;
		drivercrate::test::runMetadataSearchRunnerTests( context) ;
		drivercrate::test::runMetadataSearchBudgetTests( context) ;
		drivercrate::test::runMetadataSearchHttpTests( context) ;
		drivercrate::test::runMetadataInventoryTests( context) ;
		drivercrate::test::runOfficialDiscoveryTests( context) ;
		drivercrate::test::runOfficialDiscoveryEulaTests( context) ;
		drivercrate::test::runOfficialDiscoveryProviderAdapterTests( context) ;
		drivercrate::test::runOfficialDiscoveryRecordAdapterTests( context) ;
		drivercrate::test::runScanMeasurementTests( context) ;
		drivercrate::test::runScanMeasurementDiagnosticsTests( context) ;
		drivercrate::test::runPackageSelectionTests( context) ;
		drivercrate::test::runProviderRegistryTests( context) ;
		drivercrate::test::runOfficialValidationTests( context) ;
		drivercrate::test::runLiveSearchDiagnosticsTests( context) ;
		drivercrate::test::runOfficialSourcePolicyTests( context) ;
		drivercrate::test::runOfficialAcquisitionTests( context) ;
		drivercrate::test::runOfficialDelegatedPackageInspectionTests( context) ;
		drivercrate::test::runOfficialDownloadGrantTests( context) ;
		drivercrate::test::runOfficialDriverClosureTests( context) ;
		drivercrate::test::runOfficialGzipTests( context) ;
		drivercrate::test::runOfficialMsiTests( context) ;
		drivercrate::test::runOfficialDriverPackageTests( context) ;
		drivercrate::test::runOfficialDriverRankTests( context) ;
		drivercrate::test::runOfficialRecordPayloadRoutingTests( context) ;
		drivercrate::test::runOfficialSevenZipTests( context) ;
		drivercrate::test::runOfficialSfxTests( context) ;
		drivercrate::test::runMaintenanceEmbeddedFileTableTests( context) ;
		drivercrate::test::runIndexedDriverPackageInspectionTests( context) ;
		drivercrate::test::runOfficialZipTests( context) ;
		drivercrate::test::runOpenpgpSignatureVerifierTests( context) ;
		drivercrate::test::runSignedIndexManifestTests( context) ;
		drivercrate::test::runSignedIndexAssetBytesTests( context) ;
		drivercrate::test::runSignedIndexRefreshTests( context) ;
		drivercrate::test::runSignedIndexRecordsTests( context) ;
		drivercrate::test::runSignedIndexStoreTests( context) ;
		drivercrate::test::runSignedIndexStoreMigrationTests( context) ;
		drivercrate::test::runSignedIndexRecordLookupTests( context) ;
		drivercrate::test::runProtectedInstallTests( context) ;
		drivercrate::test::runNvidiaCatalogParserTests( context) ;
		drivercrate::test::runNvidiaWinof2CatalogParserTests( context) ;
		drivercrate::test::runNvidiaWinof2DriverAuditTests( context) ;
		drivercrate::test::runNvidiaWinof2DriverPackageTests( context) ;
		drivercrate::test::runAmdCatalogParserTests( context) ;
		drivercrate::test::runAsixCatalogParserTests( context) ;
		drivercrate::test::runAsrockCatalogParserTests( context) ;
		drivercrate::test::runAsrockSystemIdentityTests( context) ;
		drivercrate::test::runBroadcomOfficialProviderTests( context) ;
		drivercrate::test::runOfficialReleaseMetadataTests( context) ;
		drivercrate::test::runOfficialReleaseLocalProbeTests( context) ;
		drivercrate::test::runOfficialReleaseObservationTests( context) ;
		drivercrate::test::runOfficialReleaseObservationStoreTests( context) ;
		drivercrate::test::runOfficialPreparationTests( context) ;
		drivercrate::test::runOfficialPreparedAcquisitionTests( context) ;
		drivercrate::test::runOfficialPreparationOperationTests( context) ;
		drivercrate::test::runPreparedAuditDisplayTests( context) ;
		drivercrate::test::runProviderPreparationWorkerTests( context) ;
		drivercrate::test::runAsusCatalogParserTests( context) ;
		drivercrate::test::runAsusSystemIdentityTests( context) ;
		drivercrate::test::runDellCatalogParserTests( context) ;
		drivercrate::test::runDellServerCatalogParserTests( context) ;
		drivercrate::test::runLenovoCatalogParserTests( context) ;
		drivercrate::test::runHpCatalogParserTests( context) ;
		drivercrate::test::runIntelEthernetServerPageParserTests( context) ;
		drivercrate::test::runIntelCollectorIdentityParserTests( context) ;
		drivercrate::test::runIntelWirelessPackageTests( context) ;
		drivercrate::test::runProlificSerialPackageTests( context) ;
		drivercrate::test::runProlificOfficialProviderTests( context) ;
		drivercrate::test::runSiliconLabsOfficialProviderTests( context) ;
		drivercrate::test::runWchOfficialProviderTests( context) ;
		drivercrate::test::runSiliconLabsSerialPackageTests( context) ;
		drivercrate::test::runUserSelectedInfPackageProviderTests( context) ;
		drivercrate::test::runWchSerialPackageTests( context) ;
		drivercrate::test::runIntelWirelessPageParserTests( context) ;
		drivercrate::test::runIntelDownloadOnlyPageTests( context) ;
		drivercrate::test::runVaioCatalogParserTests( context) ;
		drivercrate::test::runWindowsUpdateProviderTests( context) ;
#endif
	} catch( const std::exception &error) {
		std::cerr << "Unhandled test exception: " << error.what() << '\n' ;
		return 1 ;
	} catch( ...) {
		// test process boundary で型不明例外を成功として扱わない。
		std::cerr << "Unhandled non-standard test exception.\n" ;
		return 1 ;
	}

	std::cout << "Assertions: " << context.assertionCount()
			  << ", failures: " << context.failureCount() << '\n' ;
	return context.failureCount() == 0 ? 0 : 1 ;
}
