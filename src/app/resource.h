//------------------------------------------------------------------------------
/**
 * @file resource.h
 * @brief DriverCrateリソースID定義。
 * @version 01.13.01
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/09  ASIX候補発行と指定導入の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  段階別scan計測の表示文字列IDを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Intel Server最終確認文字列IDを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  候補発行状態と件数resourceを追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Intel Ethernetの取得前提確認と選択取得を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Release観測差分resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査後の候補有無表示を正確化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  監査合格候補の表示を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の表示境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文と取得再確認の境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得確認と独立した操作状態を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  共通配布情報とIntel公式検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  NetXtreme-E表示専用検索を接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  公式serial取得と新版受入境界を更新。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  TreeTable resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  復元ポイント文字列追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  推奨更新filter resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  一括選択resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Operation進捗resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  下部全幅progress帯resource整理。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Install後の結果保持resource整理。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  公式catalog検索resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  取得元選択とscan状態resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  同一版取得元表示resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Provider coverage表示追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Local候補到達dialog resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  Windows Server install resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  OEM未検証候補警告resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  公式探索経路表示resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  Manufacturer intake表示resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Intel ZIP選択resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Prolific ZIP選択resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH ZIP選択resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  WCH CH342／CH343系resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Silicon Labs ZIP resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  汎用署名済みINF ZIP resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  候補監査状態resource追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の条件・取消し・表示専用結果を接続。
 * Ver.01.01.00 Shunji Ogawa  2026/09/14  種類別一覧の分類件数と失効表示を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  観測・検証理由・導入方式の固定表示を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  共通package入力と内容検査の説明を更新。
 * Ver.01.04.00 Shunji Ogawa  2026/09/15  通常scanの公式探索統一確認IDを追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/15  通常scanの協調取消し表示IDを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/12  索引の取得・内容・未接続結果表示IDを追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.08.00 Shunji Ogawa  2026/10/12  初回操作名と実行可否を候補監査へ分離。
 * Ver.01.09.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  必要構成の確認と役割別結果の表示IDを追加。
 * Ver.01.10.01 Shunji Ogawa  2026/10/13  必要構成九macroのコメント種別を規約へ合わせる。
 * Ver.01.11.00 Shunji Ogawa  2026/10/16  通常索引refreshと非通信worker/UI境界を接続。
 * Ver.01.12.00 Shunji Ogawa  2026/10/16  索引通信結果の可視導線と同版publicationの画面受入を追加。
 * Ver.01.13.00 Shunji Ogawa  2026/10/16  索引通信詳細の全文と数値末尾の実control観測を追加。
 * Ver.01.13.01 Shunji Ogawa  2026/10/24  索引の期限・発行時刻拒否を説明するIDを追加。
 * </pre>
 *
 * @note Win32 control、icon、および日本語文字列のresource IDを定義します。
 */
//------------------------------------------------------------------------------

#pragma once

// 基本INFと必要役割を一計画として確認する表示IDです。
#define IDS_INDEX_REQUIRED_PLAN 1416
// 選択基本driverの役割名を表示するIDです。
#define IDS_INDEX_ROLE_BASE 1417
// 必要Extensionの役割名を表示するIDです。
#define IDS_INDEX_ROLE_EXTENSION 1418
// 必要driver-only SWC子の役割名を表示するIDです。
#define IDS_INDEX_ROLE_COMPONENT 1419
// queuedや再起動後の反映を保証しない適用未確認を表示するIDです。
#define IDS_INDEX_ROLE_PENDING 1420
// 実状態観測とは別の指定device API完了を表示するIDです。
#define IDS_INDEX_ROLE_API_COMPLETED 1421
// Stageのみを導入成功へ変換せず表示するIDです。
#define IDS_INDEX_ROLE_STAGED 1422
// 一候補の必要構成個別結果を表示するIDです。
#define IDS_INDEX_PLAN_RESULTS 1423
// 指定APIのFALSE/Windows診断欠落と内部補完を区別して表示するIDです。
#define IDS_INDEX_ROLE_DIAGNOSTIC_MISSING 1424
// 更新済みでも適用性や導入済みを保証しない索引refreshの表示です。
#define IDS_INDEX_REFRESHED 1450
// 更新失敗と明示的な有効cache再認証を同時に表示します。
#define IDS_INDEX_REFRESH_CACHED 1451
// 更新拒否を候補なし成功や最新へ読み替えない表示です。
#define IDS_INDEX_REFRESH_REJECTED 1452
// 取消しと既commitの独立事実を併記する表示です。
#define IDS_INDEX_REFRESH_CANCELLED 1453
// 原HTTP/診断/commit/世代だけの非機密な事実です。
#define IDS_INDEX_REFRESH_FACTS 1454
// 取得計画から独立して確定した通信結果を開くmenuとdialogの名称です。
#define IDS_INDEX_REFRESH_DETAILS 1455
// 元通信失敗の診断値と説明です。
#define IDS_INDEX_REFRESH_HTTP_ERROR 1456
// 索引更新自体の診断値と説明です。
#define IDS_INDEX_REFRESH_ERROR 1457
// 保護storeのcommit区分です。
#define IDS_INDEX_REFRESH_COMMIT 1458
// 試行manifestの観測世代です。
#define IDS_INDEX_REFRESH_ATTEMPTED 1459
// 保護storeの観測済み保存世代です。
#define IDS_INDEX_REFRESH_PERSISTED 1460
// 期限切れを含む発行日時・期限の検証拒否と次の確認操作を説明します。
#define IDS_INDEX_REFRESH_INVALID_TIME 1461
// 同じ非機密summaryだけを読む独立commandです。
#define IDM_INDEX_REFRESH_DETAILS 3101

#define IDS_DEVICE_PRESENCE_UNKNOWN 1282		// 現在ドライバー未確認。
#define IDS_DEVICE_PRESENCE_REGISTERED 1283		// 登録済み。
#define IDS_DEVICE_PRESENCE_NOT_INSTALLED 1284	// 未導入。
#define IDS_DEVICE_PROBLEM 1285					// Windows 問題コード %1。
#define IDS_DEVICE_OBSERVATION_MISSING 1286		// 現在ドライバー未確認（観測未収集）。
#define IDS_DEVICE_STATUS_UNVERIFIED 1287		// 問題状態を確認できませんでした。
#define IDS_DEVICE_ATTRIBUTE_FAILURE 1288		// 属性の一部を確認できませんでした。
#define IDS_DEVICE_OBSERVATION_NOTE                                                                \
	1289									// 検索時点の観測です。登録済みや問題コードなしは、正常動作・最新・導入適合性の保証ではありません。。
#define IDS_DEVICE_READ_NOT_READ 1290		// 未照会。
#define IDS_DEVICE_READ_VALUE 1291			// 値を取得。
#define IDS_DEVICE_READ_EMPTY 1292			// 空の値。
#define IDS_DEVICE_READ_MISSING 1293		// 属性なし。
#define IDS_DEVICE_READ_FAILED 1294			// 読取り失敗。
#define IDS_DEVICE_READ_INVALID 1295		// 型・内容が不正。
#define IDS_DEVICE_READ_LIMIT 1296			// 容量上限・取得中のサイズ変化。
#define IDS_DEVICE_FIELD_FRIENDLY 1297		// 表示名。
#define IDS_DEVICE_FIELD_DESCRIPTION 1298	// デバイス説明。
#define IDS_DEVICE_FIELD_MANUFACTURER 1299	// 製造元。
#define IDS_DEVICE_FIELD_CLASS 1300			// クラス。
#define IDS_DEVICE_FIELD_KEY 1301			// ドライバー登録属性。
#define IDS_DEVICE_FIELD_INF 1302			// INF名の取得。
#define IDS_DEVICE_FIELD_PROVIDER 1303		// Provider名。
#define IDS_DEVICE_FIELD_VERSION 1304		// 現在版。
#define IDS_DEVICE_FIELD_DATE 1305			// 現在日付。
#define IDS_DEVICE_FIELD_IDENTITY 1306		// 端末内ID解決。
#define IDS_DEVICE_FIELD_NODE 1307			// デバイスの問題状態。
#define IDS_DEVICE_ACCESS_DENIED 1308		// アクセス拒否。
#define IDS_DEVICE_DISAPPEARED 1309			// デバイス消失。
#define IDS_ASSESSMENT_UNCOLLECTED 1310		// 詳細未収集（従来の検証範囲を表示）。
#define IDS_ASSESSMENT_TITLE 1311			// デバイスと候補の詳細。
#define IDS_ASSESSMENT_HINT 1312			// 候補行で Enter またはダブルクリックすると詳細を表示します。。
#define IDS_ASSESSMENT_INCONSISTENT 1313	// 観測・検証の結合を確認できません。再検索してください。。
#define IDS_ASSESSMENT_NEXT                                                                        \
	1314											// 観測を更新するには再検索してください。この画面の確認だけでは取得・導入を行いません。。
#define IDS_ASSESSMENT_STATE_NOT_CHECKED 1315		// 未確認。
#define IDS_ASSESSMENT_STATE_PASSED 1316			// 検証合格。
#define IDS_ASSESSMENT_STATE_REJECTED 1317			// 条件不成立。
#define IDS_ASSESSMENT_STATE_FAILED 1318			// 確認できませんでした。
#define IDS_ASSESSMENT_STATE_UNSUPPORTED 1319		// この検査・方式は未対応。
#define IDS_ASSESSMENT_STATE_NOT_APPLICABLE 1320	// 検査範囲で非該当。
#define IDS_ASSESSMENT_STATE_WINDOWS 1321			// Windows管理。
#define IDS_ASSESSMENT_AXIS_ORIGIN 1322				// 由来。
#define IDS_ASSESSMENT_AXIS_ACQUISITION 1323		// 取得・参照ファイル。
#define IDS_ASSESSMENT_AXIS_SIGNATURE 1324			// 署名。
#define IDS_ASSESSMENT_AXIS_APPLICABILITY 1325		// PnP・OS・x64適合。
#define IDS_ASSESSMENT_AXIS_SELECTION 1326			// Windowsの選択・順位。
#define IDS_ASSESSMENT_AXIS_DRIVER_ONLY 1327		// ドライバーのみの構成。
#define IDS_ASSESSMENT_AXIS_REQUIREMENTS 1328		// 明示必須条件。
#define IDS_ASSESSMENT_AXIS_METHOD 1329				// 導入方式。
#define IDS_ASSESSMENT_METHOD_UNKNOWN 1330			// 方式未確定。
#define IDS_ASSESSMENT_METHOD_WINDOWS 1331			// Windows管理。
#define IDS_ASSESSMENT_METHOD_INF 1332				// 標準INF。
#define IDS_ASSESSMENT_METHOD_INSTALLER 1333		// 公式installer。
#define IDS_ASSESSMENT_METHOD_MANUAL 1334			// 手動。
#define IDS_ASSESSMENT_EXECUTOR_AVAILABLE 1335		// 実行経路あり（導入許可とは別）。
#define IDS_ASSESSMENT_EXECUTOR_UNAVAILABLE 1336	// 実行経路なし。
#define IDS_ACTION_INITIAL_INSTALL 1337				// 根拠付き初回導入またはblocked初回候補の操作名です。
#define IDS_ASSESSMENT_REASON_NOT_EXAMINED 1338		// この詳細は未検査です。
#define IDS_ASSESSMENT_REASON_VALIDATED 1339		// 当該軸を検証しました。
#define IDS_ASSESSMENT_REASON_WINDOWS 1340			// Windowsの管理処理に委譲します。
#define IDS_ASSESSMENT_REASON_API_FAILURE 1341		// APIが失敗し、合否を確認できませんでした。
#define IDS_ASSESSMENT_REASON_FORMAT                                                               \
	1342												// 必要な形式の検査が未対応です。不適合の判定ではありません。
#define IDS_ASSESSMENT_REASON_ORIGIN_UNKNOWN 1343		// 公式由来が未確認です。
#define IDS_ASSESSMENT_REASON_USER 1344					// 利用者持込みです。公式由来は証明していません。
#define IDS_ASSESSMENT_REASON_ORIGIN_REJECTED 1345		// 公式起点の検証で拒否されました。
#define IDS_ASSESSMENT_REASON_DELEGATION 1346			// 公式recordから取得先への委譲が未確認です。
#define IDS_ASSESSMENT_REASON_NOT_ACQUIRED 1347			// 検査対象は未取得です。
#define IDS_ASSESSMENT_REASON_MISSING_FILE 1348			// 参照ファイルが不足しています。
#define IDS_ASSESSMENT_REASON_HASH 1349					// 期待hashと内容が一致しません。
#define IDS_ASSESSMENT_REASON_SIGNATURE 1350			// Windows policyの署名検証で拒否されました。
#define IDS_ASSESSMENT_REASON_PUBLISHER 1351			// 必要な署名者の根拠が未確認です。
#define IDS_ASSESSMENT_REASON_PNP 1352					// 実PnP照合で一致しません。
#define IDS_ASSESSMENT_REASON_OS 1353					// 対象OS条件が一致しません。
#define IDS_ASSESSMENT_REASON_ARCH 1354					// x64条件が一致しません。
#define IDS_ASSESSMENT_REASON_RANK 1355					// 現在の順位を確認できていません。
#define IDS_ASSESSMENT_REASON_LEGACY 1356				// 旧導入policyで保留中です。基礎適合とは別の判断です。
#define IDS_ASSESSMENT_REASON_SAME 1357					// 現在driverから変更がありません。
#define IDS_ASSESSMENT_REASON_NOT_RECOMMENDED 1358		// Windowsの推奨選択ではありません。
#define IDS_ASSESSMENT_REASON_FIRMWARE 1359				// 対象そのものがfirmwareです。
#define IDS_ASSESSMENT_REASON_MIXED 1360				// 選択driverとfirmware更新を分離できません。
#define IDS_ASSESSMENT_REASON_NO_REQUIREMENT 1361		// 確認した範囲に明示必須条件がありません。
#define IDS_ASSESSMENT_REASON_REQUIREMENT_MISSING 1362	// 明示必須条件を満たしていません。
#define IDS_ASSESSMENT_REASON_REQUIREMENT_UNKNOWN 1363	// 明示必須条件の必要値が未確認です。
#define IDS_ASSESSMENT_REASON_EXECUTOR 1364				// この方式の実行経路は未実装です。
#define IDS_ASSESSMENT_REASON_SCOPE 1365				// 実行範囲が未確認です。
#define IDS_ASSESSMENT_REQUIRED 1366					// 必須。
#define IDS_ASSESSMENT_OPTIONAL 1367					// 任意・推奨（不足だけで導入を保留しません）。
#define IDS_ASSESSMENT_REQUIREMENT_SATISFIED 1368		// 充足。
#define IDS_ASSESSMENT_REQUIREMENT_UNSATISFIED 1369		// 不足。
#define IDS_ASSESSMENT_REQUIREMENT_UNVERIFIED 1370		// 必要値未確認。
#define IDS_ASSESSMENT_ROLE_BASE 1371					// 基本driver。
#define IDS_ASSESSMENT_ROLE_EXTENSION 1372				// extension INF。
#define IDS_ASSESSMENT_ROLE_COMPONENT 1373				// component。
#define IDS_ASSESSMENT_ROLE_UTILITY 1374				// utility。
#define IDS_ASSESSMENT_ROLE_FIRMWARE 1375				// NVM等の既存状態（更新指示ではありません）。
#define IDS_DIAGNOSTIC_WIN32 1376						// Win32。
#define IDS_DIAGNOSTIC_CONFIGRET 1377					// CONFIGRET。
#define IDS_DIAGNOSTIC_HRESULT 1378						// HRESULT。
#define IDS_GENERIC_INF_FILTER_PATTERN 1379				// 共通local入力の非実行archive形式。
#define IDS_ASSESSMENT_COMPONENT_ROLE 1380				// 当該packageの検査済み構成役割。
#define IDS_ASSESSMENT_PACKAGE_SCOPE 1381				// Local package内だけを確認した範囲。
#define IDS_OFFICIAL_DISCOVERY_SCAN_TITLE 1382			// 一scan限定の公式探索確認見出し。
#define IDS_OFFICIAL_DISCOVERY_SCAN_INSTRUCTION 1383	// Metadata限定または検査用取得の選択。
#define IDS_OFFICIAL_DISCOVERY_SCAN_CONTENT 1384		// Provider範囲・固定予算・非導入性の説明。
#define IDS_OFFICIAL_DISCOVERY_METADATA_BUTTON 1385		// Payloadを取得しない選択。
#define IDS_OFFICIAL_DISCOVERY_PACKAGE_BUTTON 1386		// Driver packageの検査用取得を許可する選択。
#define IDS_OFFICIAL_DISCOVERY_RESTRICTED_NETWORK 1387	// 制限／不明回線の今回限り許可。
#define IDS_PROVIDER_PAYLOAD_NOT_APPROVED 1388			// Metadata確定後のpayload未取得状態。
#define IDS_PROVIDER_NETWORK_NOT_APPROVED 1389			// 制限／不明回線未許可状態。
#define IDS_OFFICIAL_DISCOVERY_FALLBACK 1390			// 統一選択dialogを表示できない際の中止説明。
#define IDS_SCAN_CANCEL_BUTTON 1391						// 通常scanの協調取消しbutton。
#define IDS_SCAN_CANCEL_WAIT_BUTTON 1392				// 通常scanの取消し待ちbutton。
#define IDS_SCAN_CANCELLING 1393						// 同期Providerの安全な終端を待つ説明。
#define IDS_SCAN_CANCELLED 1394							// 通常scan取消しの非導入終端。
#define IDS_SCAN_CLOSE 1395								// 通常scan取消し後の安全なWindow終了確認。

#define IDD_PREPARATION_EULA 2100				// EULA全文の同期確認dialog。
#define IDC_PREPARATION_EULA_REVISION 2101		// 同意対象revisionの読取り専用表示。
#define IDC_PREPARATION_EULA_TEXT 2102			// EULA全文のread-only edit。
#define IDC_PREPARATION_PREREQUISITES 2103		// 本文の取得前提を満たすことの明示確認。
#define IDC_PREPARATION_PREREQUISITE_NOTE 2104	// 既存契約・権限・用途条件の注意表示。
#define IDS_PREPARATION_EULA_READY 1201			// 全文確認が必要な対象の状態。

//------------------------------------------------------------------------------
// Icon resource定義。
//------------------------------------------------------------------------------
#define IDI_DRIVERCRATE 101	// Executableとtop-level Windowへ設定するapplication icon。

//------------------------------------------------------------------------------
// 日本語文字列resource定義。
//------------------------------------------------------------------------------
#define IDS_APP_TITLE 1000								// Application名。
#define IDS_HEADER_TEXT 1001							// Main Window上部の機能説明。
#define IDS_SCAN_BUTTON 1002							// Driver候補scan buttonのcaption。
#define IDS_INSTALL_BUTTON 1003							// 選択候補install buttonのcaption。
#define IDS_STATUS_IDLE 1004							// Operation待機中のstatus。
#define IDS_STATUS_SCANNING 1005						// Driver候補scan中のstatus。
#define IDS_STATUS_DOWNLOADING 1006						// Driver payload download中のstatus。
#define IDS_STATUS_INSTALLING 1007						// Driver install中のstatus。
#define IDS_STATUS_NO_UPDATES 1008						// Install可能候補が0件のstatus。
#define IDS_STATUS_SCAN_COUNT 1009						// Install可能候補件数を含むstatus format。
#define IDS_STATUS_SCAN_WARNING 1010					// 一部provider scan失敗時のstatus format。
#define IDS_STATUS_COMPLETED 1011						// 全選択候補成功時のstatus。
#define IDS_STATUS_FAILED 1012							// 一件以上失敗した場合のstatus。
#define IDS_ERROR_TITLE 1013							// Error dialogのtitle。
#define IDS_SCAN_ERROR_PREFIX 1014						// Scan error code前の説明。
#define IDS_INSTALL_ERROR_PREFIX 1015					// Install error code前の説明。
#define IDS_CONFIRM_TITLE 1016							// Install最終確認dialogのtitle。
#define IDS_CONFIRM_PREFIX 1017							// Install対象一覧前の確認文。
#define IDS_CONFIRM_SUFFIX 1018							// EULAと電源断禁止を示す確認文。
#define IDS_RESULT_SUCCESS 1019							// 再起動不要のinstall成功通知。
#define IDS_RESULT_SUCCESS_REBOOT 1020					// 再起動が必要なinstall成功通知。
#define IDS_RESULT_FAILURE 1021							// 一件以上失敗したinstall結果通知。
#define IDS_CLOSE_TITLE 1022							// Operation中の終了確認dialog title。
#define IDS_CLOSE_BUSY 1023								// 実行中operation完了を待つ終了確認文。
#define IDS_STATUS_STOPPING 1024						// Worker停止待ち中のstatus。
#define IDS_COLUMN_UPDATE 1025							// Driver候補treeの論理column名。
#define IDS_COLUMN_MANUFACTURER 1026					// 製造元を示すlabel。
#define IDS_COLUMN_MODEL 1027							// Device modelを示すlabel。
#define IDS_COLUMN_CLASS 1028							// Device classを示すlabel。
#define IDS_COLUMN_PROVIDER 1029						// Driver providerを示すlabel。
#define IDS_COLUMN_DATE 1030							// Driver日付を示すlabel。
#define IDS_COLUMN_SIZE 1031							// 最大download sizeを示すlabel。
#define IDS_COLUMN_RESULT 1032							// Operation状態または結果を示すlabel。
#define IDS_VALUE_UNKNOWN 1033							// Providerが値を返さない項目の代替表示。
#define IDS_VALUE_PENDING_CACHED 1034					// WUA contentがcache済みの未処理状態。
#define IDS_VALUE_PENDING_DOWNLOAD 1035					// Downloadが必要な未処理状態。
#define IDS_VALUE_OPTIONAL 1036							// Optional driver updateの表示。
#define IDS_DOWNLOAD_FAILED 1037						// 個別download失敗表示のprefix。
#define IDS_INSTALL_FAILED 1038							// 個別install失敗表示のprefix。
#define IDS_INSTALL_SUCCEEDED 1039						// 個別install成功状態。
#define IDS_NOT_INSTALLED 1040							// Download失敗によりinstallしなかった状態。
#define IDS_SELECTION_REQUIRED 1041						// Install対象未選択時の案内。
#define IDS_COMMON_CONTROLS_ERROR 1042					// Common controls初期化失敗の案内。
#define IDS_MAIN_WINDOW_ERROR 1043						// Main Window作成失敗の案内。
#define IDS_SOURCE_LABEL 1044							// Driver取得元を示すlabel。
#define IDS_VERSION_LABEL 1045							// Driver versionを示すlabel。
#define IDS_CURRENT_DRIVER 1046							// 現在使用中driverの状態。
#define IDS_RECOMMENDED_UPDATE 1047						// WUA推奨候補の状態。
#define IDS_ACTION_UPDATE 1048							// 通常更新操作の表示。
#define IDS_ACTION_REINSTALL 1049						// 再導入操作の表示。
#define IDS_ACTION_DOWNGRADE 1050						// 旧版切替操作の表示。
#define IDS_DOWNGRADE_WARNING 1051						// 旧版切替を含む場合の追加警告。
#define IDS_LOCAL_CACHED 1052							// Driver Store取得済み候補の状態。
#define IDS_TREE_DEVICE_SUFFIX 1053						// Device親nodeへ付加する候補種別。
#define IDS_CURRENT_VERSION_LABEL 1054					// Device親nodeの現在版label。
#define IDS_CURRENT_VERSION_UNMATCHED 1055				// WUA候補をlocal deviceへ照合できない状態。
#define IDS_COLUMN_DEVICE_DRIVER 1056					// TreeTable第一columnのdevice/driver label。
#define IDS_COLUMN_CURRENT_VERSION 1057					// TreeTableの現在使用中version label。
#define IDS_COLUMN_CANDIDATE_VERSION 1058				// TreeTableの候補version label。
#define IDS_COLUMN_SOURCE 1059							// TreeTableの取得元とpolicy境界label。
#define IDS_STATUS_CREATING_RESTORE_POINT 1060			// Windows復元ポイント作成中のstatus。
#define IDS_RESTORE_POINT_ERROR_PREFIX 1061				// 復元ポイント作成失敗dialogの説明。
#define IDS_RESTORE_POINT_FINALIZE_ERROR_PREFIX 1062	// 復元ポイント終了失敗の説明。
#define IDS_RESTORE_POINT_NOT_CREATED 1063				// 復元ポイント失敗による未導入状態。
#define IDS_RESTORE_POINT_CREATED 1064					// 作成した復元ポイント番号のformat。
#define IDS_RECOMMENDED_ONLY_FILTER 1065				// 推奨更新だけを表示するfilter名。
#define IDS_STATUS_RECOMMENDED_COUNT 1066				// Filter中の推奨更新件数format。
#define IDS_SELECT_ALL_RECOMMENDED 1067					// 推奨更新一括選択buttonのcaption。
#define IDS_CLEAR_SELECTION 1068						// 全候補選択解除buttonのcaption。
#define IDS_STATUS_SCANNING_DEVICES 1069				// DeviceとDriver Store列挙中のstatus。
#define IDS_STATUS_SEARCHING_WINDOWS_UPDATE 1070		// Windows Update照会中のstatus。
#define IDS_STATUS_MERGING_CANDIDATES 1071				// 複数取得元候補統合中のstatus。
#define IDS_STATUS_FINALIZING_RESTORE_POINT 1072		// 復元ポイント確定中のstatus。
#define IDS_STATUS_SEARCHING_OFFICIAL_CATALOGS 1073		// Hardware maker公式catalog照会中。
#define IDS_PROVIDER_SOURCES 1074						// Provider取得元設定buttonのcaption。
#define IDS_PROVIDER_DISABLED 1075						// Provider無効状態。
#define IDS_PROVIDER_NOT_APPLICABLE 1076				// Provider対象外状態。
#define IDS_PROVIDER_NO_CANDIDATES 1077					// Provider候補なし状態。
#define IDS_PROVIDER_CANDIDATES 1078					// Provider候補あり状態。
#define IDS_PROVIDER_FAILED 1079						// Provider検索失敗状態。
#define IDS_PROVIDER_METADATA_REJECTED 1080				// Provider metadata拒否状態。
#define IDS_PROVIDER_SETTING_CHANGED 1081				// 次回scanから設定を使うstatus。
#define IDS_EQUIVALENT_SOURCES 1082						// 同一版にある取得元候補数format。
#define IDS_PREFERRED_SOURCE 1083						// 同一版内の既定取得元表示。
#define IDS_PROVIDER_COVERAGE 1084						// 対象／判定／候補件数format。
#define IDS_LOCAL_COVERAGE_MENU 1085					// Local候補到達dialogのmenu caption。
#define IDS_LOCAL_COVERAGE_TITLE 1086					// Local候補到達dialogの主見出し。
#define IDS_LOCAL_COVERAGE_SUMMARY 1087					// Device／group件数format。
#define IDS_LOCAL_COVERAGE_EXPLANATION 1088				// 集計値の意味と非保証事項。
#define IDS_LOCAL_COVERAGE_COUNTS 1089					// 取得元別device件数format。
#define IDS_LOCAL_COVERAGE_EXPAND 1090					// 詳細展開buttonのcaption。
#define IDS_LOCAL_COVERAGE_TRUNCATED 1091				// 省略group件数format。
#define IDS_LOCAL_COVERAGE_EMPTY 1092					// Present device集計が空の場合の説明。
#define IDS_SERVER_CONFIRM_SUFFIX 1093					// Server用の復元ポイントなし最終確認。
#define IDS_STATUS_PREPARING_SERVER_INSTALL 1094		// Server install準備中status。
#define IDS_SERVER_NO_RESTORE_POINT_RESULT 1095			// Server復元ポイント未作成の結果説明。
#define IDS_COMPONENT_GENERIC_WARNING 1096				// OEM未検証汎用候補の追加警告。
#define IDS_DISCOVERY_LEVEL_A 1097						// 公式構造化metadata探索経路。
#define IDS_DISCOVERY_LEVEL_B 1098						// 公式Web page探索経路。
#define IDS_DISCOVERY_LEVEL_C 1099						// 利用者指定package探索経路。
#define IDS_RELAXED_DISCOVERY_WARNING 1100				// 区分B／C候補の追加警告。
#define IDS_INTEL_PACKAGE_DIALOG_TITLE 1101				// Intel ZIP選択dialog title。
#define IDS_INTEL_PACKAGE_FILTER_NAME 1102				// Intel ZIP file filter表示名。
#define IDS_INTEL_PACKAGE_SELECTED 1103					// Provider menuのfile選択済み表示。
#define IDS_INTEL_PACKAGE_DIALOG_ERROR 1104				// File dialog失敗の説明format。
#define IDS_INTEL_PACKAGE_FILTER_PATTERN 1105			// Intel ZIP選択用file pattern。
#define IDS_INTEL_PACKAGE_SELECTION_NOTICE 1106			// Intel ZIP選択前の由来・許諾確認。
#define IDS_PROLIFIC_PACKAGE_DIALOG_TITLE 1107			// Prolific ZIP選択dialog title。
#define IDS_PROLIFIC_PACKAGE_FILTER_NAME 1108			// Prolific ZIP filter表示名。
#define IDS_PROLIFIC_PACKAGE_SELECTION_NOTICE 1109		// Prolific ZIP選択前の由来・許諾確認。
#define IDS_WCH_PACKAGE_DIALOG_TITLE 1110				// WCH ZIP選択dialog title。
#define IDS_WCH_PACKAGE_FILTER_NAME 1111				// WCH ZIP filter表示名。
#define IDS_WCH_PACKAGE_SELECTION_NOTICE 1112			// WCH ZIP選択前の由来・許諾確認。
#define IDS_WCH_MULTI_PACKAGE_DIALOG_TITLE 1113			// WCH CH343SER ZIP選択dialog title。
#define IDS_WCH_MULTI_PACKAGE_FILTER_NAME 1114			// WCH CH343SER ZIP filter表示名。
#define IDS_WCH_MULTI_PACKAGE_SELECTION_NOTICE 1115		// WCH CH343SER ZIP選択前確認。
#define IDS_SILABS_PACKAGE_DIALOG_TITLE 1116			// Silicon Labs ZIP選択dialog title。
#define IDS_SILABS_PACKAGE_FILTER_NAME 1117				// Silicon Labs ZIP filter表示名。
#define IDS_SILABS_PACKAGE_SELECTION_NOTICE 1118		// Silicon Labs ZIP選択前確認。
#define IDS_GENERIC_INF_DIALOG_TITLE 1119				// 汎用driver-only ZIP選択dialog title。
#define IDS_GENERIC_INF_FILTER_NAME 1120				// 汎用driver-only ZIP filter表示名。
#define IDS_GENERIC_INF_SELECTION_NOTICE 1121			// 汎用driver-only ZIP選択前確認。
#define IDS_COVERAGE_REVIEWED 1122						// Roadmap審査済みmanufacturer表示。
#define IDS_COVERAGE_PLATFORM 1123						// Windows標準manufacturer表示。
#define IDS_COVERAGE_PENDING_INTAKE 1124				// S63+未列挙manufacturer表示。
#define IDS_COVERAGE_UNIDENTIFIED 1125					// Manufacturer識別不能表示。
#define IDS_LOCAL_COVERAGE_INTAKE_SUMMARY 1126			// S63+対象device／group件数format。
#define IDS_COLUMN_AUDIT 1127							// 候補監査とinstall準備状態label。
#define IDS_AUDIT_ORIGIN_PASSED 1128					// 公式由来確認済み状態。
#define IDS_AUDIT_ORIGIN_PENDING 1129					// 公式由来確認待ち状態。
#define IDS_AUDIT_DOWNLOAD_PASSED 1130					// 検査用download済み状態。
#define IDS_AUDIT_DOWNLOAD_PENDING 1131					// 検査用download待ち状態。
#define IDS_AUDIT_CONTENT_PASSED 1132					// Package内容監査合格状態。
#define IDS_AUDIT_CONTENT_PENDING 1133					// Package内容監査待ち状態。
#define IDS_AUDIT_SYSTEM_PASSED 1134					// System監査合格状態。
#define IDS_AUDIT_SYSTEM_PENDING 1135					// System監査待ち状態。
#define IDS_AUDIT_NOT_APPLICABLE 1136					// 監査対象外状態。
#define IDS_AUDIT_WINDOWS_MANAGED 1137					// Windows管理経路への委譲状態。
#define IDS_AUDIT_PROVIDER_VALIDATED 1138				// Provider固有照合済み状態。
#define IDS_AUDIT_USER_UNVERIFIED 1139					// 利用者指定で取得元未証明の状態。
#define IDS_AUDIT_REJECTED 1140							// 監査条件拒否状態。
#define IDS_AUDIT_FAILED 1141							// 監査処理失敗状態。
#define IDS_INSTALL_READINESS_DISPLAY_ONLY 1142			// 表示専用候補状態。
#define IDS_INSTALL_READINESS_AUDIT_PENDING 1143		// 導入前監査待ち状態。
#define IDS_INSTALL_READINESS_READY 1144				// Install可能状態。
#define IDS_INSTALL_READINESS_BLOCKED 1145				// Install禁止状態。
#define IDS_PROVIDER_SOURCE_REJECTED 1146				// Provider公式origin拒否状態。
#define IDS_PROVIDER_DOWNLOAD_FAILED 1147				// Provider検査用download失敗状態。
#define IDS_PROVIDER_CONTENT_REJECTED 1148				// Provider内容監査拒否状態。
#define IDS_AUDIT_ORIGIN_LABEL 1149						// 取得元監査stage label。
#define IDS_AUDIT_DOWNLOAD_LABEL 1150					// 検査用取得stage label。
#define IDS_AUDIT_CONTENT_LABEL 1151					// 内容監査stage label。
#define IDS_AUDIT_SYSTEM_LABEL 1152						// System適用性stage label。
#define IDS_AUDIT_INSTALL_LABEL 1153					// Install準備stage label。
#define IDS_PROLIFIC_OFFICIAL_INSPECTION 1154			// 今回限りの公式ZIP検査取得確認。
#define IDS_SILABS_OFFICIAL_INSPECTION 1155				// 今回限りのCP210x公式ZIP検査取得確認。
#define IDS_WCH_OFFICIAL_INSPECTION 1156				// 今回限りのCH341SER検査取得確認。
#define IDS_WCH_MULTI_OFFICIAL_INSPECTION 1157			// 今回限りのCH343SER検査取得確認。
#define IDS_OFFICIAL_RELEASE_DISCOVERY_STATE 1158		// 未監査の公式配布情報と現在版を区別する。

//------------------------------------------------------------------------------
// Child control resource定義。
//------------------------------------------------------------------------------
#define IDC_HEADER 2000									// Main Window上部の説明static control。
#define IDC_UPDATE_TREE 2001							// Deviceとdriver候補を表示するTreeView。
#define IDC_SCAN 2002									// Driver候補scan button。
#define IDC_INSTALL 2003								// 選択候補install button。
#define IDC_STATUS 2005									// 件数、進捗、および結果を表示するstatus control。
#define IDC_TREE_HEADER 2006							// TreeViewと列位置を共有するHeader control。
#define IDC_RECOMMENDED_ONLY 2007						// 推奨更新だけを表示するcheckbox。
#define IDC_SELECT_ALL_RECOMMENDED 2008					// 推奨かつinstall可能な候補の一括選択button。
#define IDC_CLEAR_SELECTION 2009						// 全候補の選択を解除するbutton。
#define IDC_PROVIDER_SOURCES 2010						// Provider取得元設定popupを開くbutton。
#define IDC_PREPARATION 2011							// 取得準備確認／取消しbutton。
#define IDC_METADATA_SEARCH 2012						// 情報検索開始／協調取消しbutton。
#define IDD_METADATA_SEARCH 2200						// 専用Provider選択と今回限りの回線同意dialog。
#define IDC_METADATA_PROVIDER_LIST 2201					// Registryから生成する対応／未対応一覧。
#define IDC_METADATA_NETWORK_APPROVAL 2202				// 制限・未知回線への今回限りの追加許可。
#define IDC_METADATA_SELECTION_STATUS 2203				// 明示選択件数と非導入性の説明。
#define IDD_METADATA_DETAILS 2204						// 情報検索の非機密条件・停止理由の詳細dialog。
#define IDC_METADATA_DETAIL_TEXT 2205					// 読み上げとcopyができるread-only標準edit。
#define IDS_PREPARATION_BEGIN_ERROR 1200				// UI側の開始拒否と再検索案内。
#define IDS_PREPARATION_BUTTON 1160						// 取得確認button。
#define IDS_PREPARATION_CANCEL 1161						// 協調取消しbutton。
#define IDS_PREPARATION_CANCELLING 1162					// 取消し待機表示。
#define IDS_PREPARATION_RESULT_BUTTON 1163				// 結果再表示button。
#define IDS_PREPARATION_TITLE 1164						// 取得確認dialog title。
#define IDS_PREPARATION_INTRO 1165						// 取得と導入を分離する説明。
#define IDS_PREPARATION_TARGET 1166						// 一対象の番号表示。
#define IDS_PREPARATION_REFERENCE 1167					// Opaque配布参照表示。
#define IDS_PREPARATION_DEVICES 1168					// 適用性未確認件数。
#define IDS_PREPARATION_CAP 1169						// 一対象の予約上限。
#define IDS_PREPARATION_LIMITS 1170						// 容量予算表示。
#define IDS_PREPARATION_FILES 1171						// 件数予算表示。
#define IDS_PREPARATION_UNRESOLVED 1172					// 未確定条件での取得拒否。
#define IDS_PREPARATION_EULA_BLOCKED 1173				// 本文未提示の取得拒否。
#define IDS_PREPARATION_ELIGIBLE 1174					// 同意不要対象の説明。
#define IDS_PREPARATION_SELECT 1175						// 一対象の選択button。
#define IDS_PREPARATION_SKIP 1176						// 一対象の拒否button。
#define IDS_PREPARATION_NETWORK 1177					// 対象別network明示承認。
#define IDS_PREPARATION_NONE 1178						// 未選択時の表示。
#define IDS_PREPARATION_CONFIRM 1179					// 最終取得確認。
#define IDS_PREPARATION_PROGRESS 1180					// 決定型取得進捗。
#define IDS_PREPARATION_DONE 1181						// 完了説明。
#define IDS_PREPARATION_FAILED 1182						// 失敗時の対応。
#define IDS_PREPARATION_CLOSE 1183						// 取得中の終了確認。
#define IDS_PREPARATION_ACQUIRED 1184					// 取得成功の限定表示。
#define IDS_PREPARATION_NOT_SELECTED 1185				// 未選択の結果。
#define IDS_PREPARATION_AWAITING_NETWORK 1186			// Network同意不足結果。
#define IDS_PREPARATION_CANCELLED 1187					// 取消し結果。
#define IDS_PREPARATION_REJECTED 1188					// 取得拒否結果。
#define IDS_PREPARATION_ITEM_FAILED 1189				// 取得失敗結果。
#define IDS_PREPARATION_ERROR 1190						// 承認と制御異常の診断。
#define IDS_PREPARATION_ACTUAL 1191						// 実取得容量。
#define IDS_PREPARATION_PLAN_ERROR 1192					// 正常scanと独立した計画異常。
#define IDS_PREPARATION_AUDIT_DISPLAY_ONLY 1193			// 選択候補を追加しなかった監査結果の説明。
#define IDS_PREPARATION_AUDIT_INF 1194					// 内容監査の合格INF数と確認INF数。
#define IDS_PREPARATION_AUDIT_PAIRS 1195				// PnP照合の合格・確認・判定不能組合せ数。
#define IDS_PREPARATION_AUDITED_ROW 1196				// 取得済み配布情報行の監査済み表示。
#define IDS_PREPARATION_AUDIT_READY 1197				// 監査合格候補を選択可能にした説明。
#define IDS_PREPARATION_CANDIDATES 1198					// 新規選択可能候補数。
#define IDS_RELEASE_OBSERVATION_FIRST 1202				// 前回観測がない公式release状態。
#define IDS_RELEASE_OBSERVATION_CHANGED 1203			// 前回観測から変化したrelease状態。
#define IDS_RELEASE_OBSERVATION_METADATA_SAME 1204		// 表示metadataだけが一致した状態。
#define IDS_RELEASE_OBSERVATION_HASH_SAME 1205			// 公開hashを含めて一致した状態。
#define IDS_RELEASE_OBSERVATION_REEVALUATED 1206		// 前回観測を利用せず再評価した状態。
#define IDS_PREPARATION_PUBLICATION_NOT_STARTED 1207	// 候補発行未着手の説明。
#define IDS_PREPARATION_PUBLICATION_NONE 1208			// 監査後に発行可能候補がない説明。
#define IDS_PREPARATION_PUBLICATION_FAILED 1209			// 候補発行処理失敗の説明。
#define IDS_PREPARATION_PUBLICATION_COUNTS 1210			// 発行確認、発行、除外件数。
#define IDS_CONFIRM_ACTION_LABEL 1211					// 最終確認内のdriver操作label。
#define IDS_INTEL_ETHERNET_SERVER_INSTALL_NOTICE 1212	// Intel Server NIC固有警告。
#define IDS_INSTALL_CONFIGURATION_INVALID 1213			// 取得元またはServer条件の検証失敗。
#define IDS_ASIX_CLIENT_INSTALL_NOTICE 1214				// ASIX client NICの通信断と復旧条件。
#define IDS_MEASUREMENT_NOT_MEASURED 1215				// 段階別件数の未計測表示。
#define IDS_MEASUREMENT_UNAVAILABLE 1216				// 段階別件数の取得不能表示。
#define IDS_MEASUREMENT_LOWER_BOUND 1217				// 確認済み下限件数format。
#define IDS_MEASUREMENT_STAGES 1218						// T／Q／R／A／Iの件数format。
#define IDS_MEASUREMENT_RECORDS 1219					// 候補・record未照合件数format。
#define IDS_MEASUREMENT_ACQUISITIONS 1220				// 実HTTP取得区分件数format。
#define IDS_MEASUREMENT_SNAPSHOT 1221					// Scan snapshotの版・operation・session表示。
#define IDS_MEASUREMENT_INVENTORY 1222					// OS観測・一覧表現・未収録件数format。
#define IDS_MEASUREMENT_NETWORK_COMBINED 1223			// 全networkの段階別件数format。
#define IDS_MEASUREMENT_NETWORK_MANAGED 1224			// Windows管理境界の段階別件数format。
#define IDS_MEASUREMENT_NETWORK_OFFICIAL 1225			// 公式network境界の段階別件数format。
#define IDS_MEASUREMENT_EXPLANATION 1226				// 計測値の非保証とsnapshot時点説明。
#define IDS_MEASUREMENT_EXPIRED 1227					// Install等でsession失効済みの説明。
#define IDS_MEASUREMENT_NO_SNAPSHOT 1228				// 計測未接続または検証不能表示。
#define IDS_MEASUREMENT_GROUP 1229						// Coverage groupの段階別件数format。
#define IDS_MEASUREMENT_PROVIDER 1230					// Provider menuの段階別件数format。
#define IDS_MEASUREMENT_SCOPE_OUTCOME 1231				// Provider scopeとscan結果format。
#define IDS_MEASUREMENT_SCOPE_UNKNOWN 1232				// 従来adapterのscope表示。
#define IDS_MEASUREMENT_SCOPE_DEVICE 1233				// Device別queryのscope表示。
#define IDS_MEASUREMENT_SCOPE_SYSTEM 1234				// System全体queryのscope表示。
#define IDS_METADATA_SEARCH_BUTTON 1235					// 情報専用検索の入口。
#define IDS_METADATA_CANCEL_BUTTON 1236					// 情報検索の協調取消し。
#define IDS_METADATA_CANCELLING 1237					// 同期APIの安全な終端を待つ説明。
#define IDS_METADATA_DIALOG_TITLE 1238					// 今回の情報検索条件の確認見出し。
#define IDS_METADATA_MODE_COLUMN 1239					// 情報検索の対応状態column。
#define IDS_METADATA_SUPPORTED 1240						// 専用callbackを持つ登録の表示。
#define IDS_METADATA_UNSUPPORTED 1241					// 通常機能と区別した新mode未対応表示。
#define IDS_METADATA_INVENTORY_DEPENDENCY 1242			// 現在属性だけの必須依存表示。
#define IDS_METADATA_SELECTED_COUNT 1243				// 今回の明示Provider数format。
#define IDS_METADATA_SCANNING 1244						// Payload非取得の検索開始表示。
#define IDS_METADATA_COMPLETED 1245						// 全選択検索の正常終端。最新性を保証しない。
#define IDS_METADATA_PARTIAL 1246						// 部分結果を保持する非正常終端。
#define IDS_METADATA_CANCELLED 1247						// 取消し前の確定情報だけを保持する説明。
#define IDS_METADATA_FAILED 1248						// 表示専用情報検索の失敗と安全な次操作。
#define IDS_METADATA_BUDGET_STOP 1249					// 固定予算停止の表示。
#define IDS_METADATA_DEADLINE_STOP 1250					// 有限deadline停止の表示。
#define IDS_METADATA_NETWORK_BLOCKED 1251				// 制限／未知回線への未同意表示。
#define IDS_METADATA_NOT_RUN 1252						// 全体停止後の未実施表示。
#define IDS_METADATA_ROW 1253							// 非取得・非導入の配布情報行状態。
#define IDS_METADATA_DISTRIBUTION_VERSION 1254			// INF版と区別する配布版label。
#define IDS_METADATA_DISTRIBUTION_COLUMN 1255			// 情報検索時の配布版column見出し。
#define IDS_METADATA_DISTRIBUTION_DATE 1256				// 公開日と現在INF日付を区別するlabel。
#define IDS_METADATA_CLOSE 1257							// 協調取消し後の安全な終了確認。
#define IDS_METADATA_DETAILS 1258						// 検索条件と停止内訳を開くbutton名。
#define IDS_METADATA_SUMMARY 1259						// 結果件数・表示専用・未測定の要約format。
#define IDS_METADATA_PROVIDER_USAGE 1260				// Provider別の非返却消費量format。
#define IDS_METADATA_TERMS_UNKNOWN 1261					// 許諾未確定の明示表示。
#define IDS_METADATA_TERMS_REQUIRED 1262				// 別操作で全文確認が必要な許諾状態。
#define IDS_METADATA_TERMS_NOT_REQUIRED 1263			// Metadataによる取得前同意不要の限定表示。
#define IDS_METADATA_VIEW_ONLY 1264						// Metadata snapshotは導入sessionではない説明。
#define IDS_METADATA_CANCEL_WAIT_BUTTON 1265			// 同じoperationの取消し待ちbutton。
#define IDS_METADATA_HEADER 1266						// 通常検索とは別の表示専用用途。
#define IDS_METADATA_DETAIL_CONDITIONS 1267				// 実行したrequestと固定予算の表示。
#define IDS_METADATA_DETAIL_INVENTORY 1268				// Inventoryの完了有無を明示。
#define IDS_METADATA_APPROVED 1269						// 今回限りの制限回線明示許可。
#define IDS_METADATA_NOT_APPROVED 1270					// 制限回線への未同意。
#define IDS_METADATA_INVENTORY_COMPLETE 1271			// 現在属性列挙の完全性。
#define IDS_METADATA_INVENTORY_PARTIAL 1272				// 現在属性列挙の不完全性。
#define IDS_METADATA_CURRENT_ROW 1273					// 現在属性だけを確認した非導入行。
#define IDS_METADATA_RESULT_BUTTON 1274					// 専用条件と結果の閲覧command。
#define IDS_METADATA_EXACT_BYTES 1275					// 正確な公表byte数の説明。
#define IDS_METADATA_APPROXIMATE_SIZE 1276				// 公表概算であることを明示する。
#define IDS_TREE_CLASS_UNKNOWN 1277						// 分類の欠損・不正・Windows説明取得不能の表示。
#define IDS_TREE_CLASS_DEVICE_COUNT 1278				// 表示中device数を分類名へ付加するformat。
#define IDS_TREE_CLASS_UPDATE_COUNT 1279				// 通常更新候補がある表示中device数。
#define IDS_TREE_CLASS_INFORMATION_COUNT 1280			// 適用性未確認の配布情報がある表示中device数。
#define IDS_TREE_CLASS_EXPIRED 1281						// Install後に分類件数を導入可能数と誤認させない表示。
#define IDS_INDEX_TRUST_UNAVAILABLE 1396				// 署名索引trust未配備の表示。
#define IDS_INDEX_SCAN_COMPLETE 1397					// 公開ID照合の読取り完了。適合を示しません。
#define IDS_INDEX_SCAN_PARTIAL 1398						// 未判定・予算停止を含む索引読取り。
#define IDS_INDEX_SCAN_UNAVAILABLE 1399					// 期限・認証・inventory等の索引未成立。
#define IDS_INDEX_SCAN_COUNTS 1400						// 処理record・全record・未判定関係の件数。
#define IDS_INDEX_PLAN_COUNTS 1401						// 取得対象・不足・保持枠超過の件数。
#define IDS_INDEX_ROUTING_PENDING 1402					// Windows適合・候補・導入未接続の説明。
#define IDS_INDEX_CONTENT_COMPLETED 1403				// 共通内容検査の完了。全INF拒否も含みます。
#define IDS_INDEX_CONTENT_FAILED 1404					// 実byte内容検査の失敗または未実施。
#define IDS_INDEX_CONTENT_COUNTS 1405					// 通常file・発見INF・内容署名合格INFの件数。
#define IDS_INDEX_CONTENT_PARTIAL 1406					// 取得と独立した内容拒否・不足の終端表示。
#define IDS_INDEX_CONTENT_ITEM 1407						// 元計画での対象番号。秘密文字列を表示しません。
#define IDS_DISCOVERY_INDEX 1408						// 公式live探索と異なる索引の境界。
#define IDS_INDEX_TERMS_SUBJECT 1409					// 原recordに結合した規約出典主体の表示です。
#define IDS_INDEX_PREREQUISITE_CONFIRM 1410				// EULAと独立した具体的条件の確認です。
#define IDS_INDEX_INSTALLER_WARNING 1411				// 元選択限定の対話引継ぎと導入未確認の最終説明です。
#define IDS_INDEX_INSTALLER_COMPLETED 1412				// 引継ぎprocessの終了だけを示す結果です。
#define IDS_INDEX_INSTALLER_FAILED 1413					// 原起動・終了失敗の結果です。
#define IDS_INDEX_INSTALLER_SELECTION 1414				// 標準INF rank非該当の専用理由です。
#define IDS_INDEX_INSTALLER_SCOPE 1415					// Binary作用証明ではない公式手順の申告です。
