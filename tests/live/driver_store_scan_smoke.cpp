//------------------------------------------------------------------------------
/**
 * @file driver_store_scan_smoke.cpp
 * @brief Driver Store読み取り専用試験。
 * @version 01.00.00
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  関数comment形式統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Setup class GUID検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/01  Scan進捗callback追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  現在版の推奨禁止検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  Local inventory計測の整合性確認を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 実端末のPnP deviceとlocal Driver Storeを読み取り専用で列挙します。System stateを変更せず、端末固有情報を出力しません。
 */
//------------------------------------------------------------------------------

#include "platform/driver_store_provider.h"
#include "platform/windows_error.h"

#include <algorithm>
#include <iostream>
#include <unordered_set>

//------------------------------------------------------------------------------
/**
 * @brief Driver Store scan を一回実行し、個人情報を含まない集計値だけを出力する。
 * @return scan 成功時は 0、失敗時は 1。
 */
//------------------------------------------------------------------------------
int wmain()
{
	drivercrate::DriverStoreProvider			provider ;	// Local Driver Store provider。
	const drivercrate::ProviderProgressCallback progressCallback =
		[]( const drivercrate::ProviderProgress &progress) {
			static_cast<void>( progress) ;
		} ; // 読み取り専用scanの進捗受理先。
	const drivercrate::ScanResult result =
		// 読み取り専用local scan結果。
		provider.scan( 1, {}, progressCallback) ;
	// 列挙失敗を更新なしとは扱わず、Windowsの診断値を残して試験を終了する。
	if( !result.succeeded) {
		std::wcerr << L"Driver Store scan failed: " << drivercrate::formatNativeError( result.error)
				   << L'\n' ;
		return 1 ;
	}

	std::unordered_set<std::wstring> devices ;						// 重複を除いたopaque device identity集合。
	std::size_t						 currentCount{} ;				// 現在使用中として分類された候補数。
	std::size_t						 currentWithVersionCount{} ;	// Versionを取得できた現在候補数。
	std::size_t currentWithoutVersionCount{} ;						// Version propertyが空の現在候補数。
	std::size_t missingManufacturerCount{} ;						// Manufacturerが空の現在候補数。
	std::size_t missingClassCount{} ;								// Setup classが空の現在候補数。
	std::size_t selectableCount{} ;									// Driver Storeから切替可能な候補数。
	std::size_t downgradeCount{} ;									// 現在版より古いと表示分類された候補数。
	std::size_t classGuidCount{} ;									// Canonical setup class GUIDを持つ候補数。
	// 実 inventory を開示せず、現在版を表示できる候補数だけを集計する。
	for( const drivercrate::UpdateCandidate &candidate : result.candidates) {
		// 表示専用の現在版が推奨一括選択へ混入する退行を検出する。
		if( candidate.current && candidate.recommended) {
			// 表示専用の現在版が一括選択へ混入する退行を拒否する。
			std::wcerr << L"Driver Store scan recommended a current driver.\n" ;
			return 1 ;
		}

		// SetupAPIが返すclass GUIDはbrace付き38文字のcanonical表現だけを許可する。
		if( candidate.deviceClassGuid.size() != 38U || candidate.deviceClassGuid.front() != L'{' ||
		   candidate.deviceClassGuid.back() != L'}') {
			std::wcerr << L"Driver Store scan returned invalid class icon metadata.\n" ;
			return 1 ;
		}

		devices.insert( candidate.deviceIdentity) ;
		currentCount += candidate.current ? 1U : 0U ;
		currentWithVersionCount += candidate.current && !candidate.version.empty() ? 1U : 0U ;
		currentWithoutVersionCount += candidate.current && candidate.version.empty() ? 1U : 0U ;
		missingManufacturerCount += candidate.current && candidate.manufacturer.empty() ? 1U : 0U ;
		missingClassCount += candidate.current && candidate.driverClass.empty() ? 1U : 0U ;
		selectableCount += candidate.installable ? 1U : 0U ;
		downgradeCount += candidate.action == drivercrate::DriverAction::DOWNGRADE ? 1U : 0U ;
		++classGuidCount ;
	}

	const drivercrate::DeviceInventoryMeasurement &measurement =
		// 同じscan完了時点の非機密inventory計測。
		provider.inventoryMeasurement() ;
	const bool representedValid =	// 表示済み現在版は候補から再集計した値と一致する場合true。
		measurement.representedDeviceCount.extent == drivercrate::MeasurementExtent::EXACT &&
		measurement.representedDeviceCount.value == currentCount ;
	const bool missingAttributesValid =	// 三属性の欠損値が現在版行と一致する場合true。
		measurement.missingManufacturerCount.extent == drivercrate::MeasurementExtent::EXACT &&
		measurement.missingManufacturerCount.value == missingManufacturerCount &&
		measurement.missingClassCount.extent == drivercrate::MeasurementExtent::EXACT &&
		measurement.missingClassCount.value == missingClassCount &&
		measurement.missingCurrentVersionCount.extent == drivercrate::MeasurementExtent::EXACT &&
		measurement.missingCurrentVersionCount.value == currentWithoutVersionCount ;
	const bool enumerationValueValid =	// 列挙数が確定値または下限値として存在する場合true。
		(measurement.enumeratedDeviceCount.extent == drivercrate::MeasurementExtent::EXACT ||
		 measurement.enumeratedDeviceCount.extent == drivercrate::MeasurementExtent::LOWER_BOUND) &&
		measurement.enumeratedDeviceCount.value.has_value() &&
		measurement.enumeratedDeviceCount.value.value() >= currentCount ;
	const bool
		unrepresentedValid =	// 未収録数が列挙数と現在版行の差を同じ確定度で保持する場合true。
		enumerationValueValid &&
		measurement.unrepresentedDeviceCount.extent == measurement.enumeratedDeviceCount.extent &&
		measurement.unrepresentedDeviceCount.value ==
			measurement.enumeratedDeviceCount.value.value() - currentCount ;
	const bool completedValid =	// 詳細完了時だけ完全列挙と未収録0を要求する検査結果。
		!measurement.detailedEnumerationComplete ||
		(measurement.enumeratedDeviceCount.extent == drivercrate::MeasurementExtent::EXACT &&
		 measurement.unrepresentedDeviceCount.value == 0U) ;
	// 新計測の確定度と候補snapshotが矛盾する場合はread-only smokeを失敗にする。
	if( !representedValid || !missingAttributesValid || !enumerationValueValid ||
	   !unrepresentedValid || !completedValid) {
		std::wcerr << L"Driver Store scan returned inconsistent inventory measurement.\n" ;
		return 1 ;
	}

	std::wcout << L"Driver Store scan succeeded. Devices: " << devices.size() << L", candidates: "
			   << result.candidates.size() << L", current: " << currentCount << L", selectable: "
			   << selectableCount << L", older: " << downgradeCount << L", current with version: "
			   << currentWithVersionCount << L", current without version: "
			   << currentWithoutVersionCount << L", class icon metadata: " << classGuidCount
			   << L'\n' ;
	return 0 ;
}
