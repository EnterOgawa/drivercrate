//------------------------------------------------------------------------------
/**
 * @file asus_driver_package_audit.cpp
 * @brief ASUS監査APIから共通監査への委譲。
 * @version 01.00.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  取得後監査の共通接続。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 公開hash必須のASUS profileだけを受け付け、既存の呼出し契約を維持します。
 */
//------------------------------------------------------------------------------

#include "platform/asus_driver_package_audit.h"
#include "platform/official_driver_package_audit.h"
#include <Windows.h>
#include <span>

namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_driver_package_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError auditAsusDriverPackage( const AsusDriverPackageAuditRequest &request,
								   AsusDriverPackageAudit			   &audit)
{
	// ASUS以外のprofileへ切り替えて公開hash必須条件を回避する要求を拒否する。
	if( request.profile != OfficialDriverAuditProfile::ASUS) {
		// ASUSの公開hash必須契約を別profileで置き換えない。
		audit				= {} ;
		audit.summary.state = AsusDriverPackageAuditState::REJECTED ;
		audit.summary.error = static_cast<NativeError>( E_ACCESSDENIED) ;
		return audit.summary.error ;
	}

	return auditOfficialDriverPackage( request, audit) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_driver_package_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError auditAsusDriverApplicability( const ScanSessionId						  scanSessionId,
										 const std::span<const OfficialCatalogDevice> devices,
										 const AsusOfficialInfRankAuditor			 &rankAuditor,
										 AsusDriverPackageAudit						 &audit)
{
	return auditOfficialDriverApplicability( scanSessionId, devices, rankAuditor, audit) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/asus_driver_package_audit.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
NativeError reverifyAsusAuditedInfPackage( const AsusAuditedInfPackage &auditedPackage)
{
	// 他profileの閉包をASUSへ転用しない。
	if( auditedPackage.profile != OfficialDriverAuditProfile::ASUS) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	return reverifyOfficialAuditedInfPackage( auditedPackage) ;
}

} // namespace drivercrate
