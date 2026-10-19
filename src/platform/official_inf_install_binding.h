//------------------------------------------------------------------------------
/**
 * @file official_inf_install_binding.h
 * @brief 公式INFとDriver Storeの一scan限定binding契約。
 * @version 01.00.00
 * @date 2026/09/07
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/08  Binding指定導入境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 生のPnP ID、device instance ID、INF pathおよびsectionはDriver Store内で所有し、本契約からUI、log、networkまたは永続保存
 *       へ渡しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_driver_rank.h"
#include "core/update_provider.h"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace drivercrate {

class OfficialDownloadWorkspace ;
struct OfficialInfPackage ;

/**
 * @brief 一scan限定の公式INF導入bindingを非機密metadataで表す。
 *
 * @note Tokenと表示可能な版、日付、rankだけをProvider workerへ返す。UI、log、network、
 *       永続保存へ渡してはならない。
 */
struct OfficialInfInstallBinding {
	/// Driver Store内の秘密記録を参照するopaque token。
	std::uint64_t			token{} ;
	/// 発行時に固定した現在driverのProvider表示名。
	std::wstring			currentProvider ;
	/// 発行時に固定した現在driverの原文version。
	std::wstring			currentVersion ;
	/// 発行時に固定した現在driverのYYYY/MM/DD日付。
	std::wstring			currentDate ;
	/// Windows nodeで固定した候補Provider表示名。
	std::wstring			candidateProvider ;
	/// Windows nodeで固定した候補version。
	std::wstring			candidateVersion ;
	/// Windows nodeで固定した候補のYYYY/MM/DD日付。
	std::wstring			candidateDate ;
	/// 発行時に固定したPnP具体性とWindows rank監査。
	OfficialDriverRankAudit rankAudit ;
} ;

/**
 * @brief 監査合格INFを現在device状態と一意なWindows nodeへ拘束する関数である。
 *
 * @note 全入力は呼出し中だけ有効であり、Driver Storeだけが秘密metadataを保持する。
 */
using OfficialInfInstallBinder = std::function<NativeError(
	ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &, const OfficialInfPackage &,
	std::wstring_view, std::wstring_view, std::wstring_view, const OfficialDriverRankAudit &,
	OfficialInfInstallBinding &)> ;

/**
 * @brief 未発行または失効した候補に対応する一つのopaque bindingを破棄する関数である。
 *
 * @note 戻り値falseは既に失効済みまたは別sessionであり、現在bindingを変更しない。
 */
using OfficialInfInstallBindingReleaser = std::function<bool( ScanSessionId, std::uint64_t)> ;

/**
 * @brief Bindingで固定した公式INFをstagingし、指定deviceへ導入する関数である。
 * @par 無名のcallback引数（宣言順）
 * - 入力scan session: Bindingを発行した現在session。
 * - 入力device identity: 候補に対応するopaque identity。
 * - 入力workspace: 再検証済みINF閉包を所有する保護workspace。
 * - 入力package: 再検証済みの一つのINF package。
 * - 入力binding: Provider workerが保持する一scan限定binding。
 * - 入力親Window値: Windows導入dialogの親Window。
 * - 出力再起動要否: 導入完了に再起動が必要な場合はtrue。
 * @return Stagingと指定device導入の成功時は0、それ以外はHRESULT。
 * @note Callbackはbindingを導入直前に再検証し、Windowsが返した登録先だけを使用する。
 */
using OfficialBoundInfInstaller = std::function<NativeError(
	ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &, const OfficialInfPackage &,
	const OfficialInfInstallBinding &, std::uintptr_t, bool &)> ;

} // namespace drivercrate
