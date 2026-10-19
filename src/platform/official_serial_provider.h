//------------------------------------------------------------------------------
/**
 * @file official_serial_provider.h
 * @brief 公式serial ZIP共通Provider契約。
 * @version 01.01.02
 * @date 2026/09/05
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公式2経路とfamily別予算を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  CP210x公式取得とserial共通化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  許可IDの候補監査と回帰確認。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  段階別scan計測根拠を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  実HTTP取得経路の計測要約を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  統一一scan承認とmetadata限定終端を追加。
 * Ver.01.01.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.01.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 署名済み原本を保持し、許可IDだけでdeviceとrankを監査します。未審査IDの許可や既存の監査条件の迂回は行いません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_driver_rank.h"
#include "core/scan_measurement.h"
#include "core/update_provider.h"
#include "core/update_types.h"
#include "platform/intel_wireless_package_provider.h"
#include "platform/official_acquisition.h"
#include "platform/official_catalog_device.h"
#include "platform/official_catalog_provider.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_package.h"
#include "platform/official_http_client.h"
#include "platform/user_selected_inf_package.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace drivercrate {
/** @brief 実装とADRで承認した公式serial family。Runtime追加は許可しない。 */
enum class OfficialSerialFamily {
	/// PL2303G DCHU INF配布。
	PROLIFIC,
	/// CP210x Universal Windows Driver配布。
	SILICON_LABS,
	/// CH340／CH341用CH341SER配布。
	WCH_CH341,
	/// CH342／CH343系用CH343SER配布。
	WCH_CH343,
} ;

/**
 * @brief 現在inventoryと保護INFに対するread-only PnP rank監査関数。
 */
using OfficialSerialRankAuditor =
	std::function<NativeError( ScanSessionId, std::wstring_view, const OfficialDownloadWorkspace &,
							  const OfficialInfPackage &, OfficialDriverRankAudit &)> ;

/**
 * @brief Prolific製品HTMLの唯一のDCHU INF配布行から公式ZIP URLを抽出する。
 * 公式DCHU INF配布行の唯一のZIPリンクを解析する。
 * 任意の最初のZIPを選ばず、EXE用行や外部originを拒否する。
 * @param[in] html 公式landing由来の有限長HTML。端末情報を含めない。 有限長の公式HTML。
 * @param[out] url 成功時のworker内専用URL。失敗時は空。 成功時の内部URL。
 * @return 行とリンクが一意かつ許可構造ならtrue。 一意な配布行と許可pathに一致する場合true。
 * @note HTML構造の確認だけで取得元やpayload内容の検証を代替しない。
 */
[[nodiscard]] bool parseProlificOfficialZipUrl( std::wstring_view html, std::wstring &url) ;

/**
 * @brief 組み込みfamilyごとの公開配布解析を選択する。
 * 未知familyを別のparserへfallbackせず出力を初期化する。
 * @param[in] family 審査済みの配布family。未知値は拒否する。
 * @param[in] html 対応する公式landing本文。 公式起点の本文。
 * @param[in] metadata Family固有metadata。Prolificでは空でなければ拒否する。 補助本文。
 * @param[out] url 成功時のworker内URL。拒否時は空。 成功時だけの取得URL。
 * @return 指定familyのparserが一意な公式配布を確認した場合true。 審査済みparserが一致した場合true。
 * @note 本文の解析だけを行い、取得元証明と内容監査は別途要求する。
 */
[[nodiscard]] bool parseOfficialSerialZipUrl( OfficialSerialFamily family, std::wstring_view html,
											 std::wstring_view metadata, std::wstring &url) ;

/**
 * @brief 内容監査済みINFの許可IDだけでdeviceを照合し、現在のPnP rankを監査する。
 * 許可IDに限定して現在deviceのrankを監査する。
 * 保護fileは改変せず、監査用copyのID集合だけを制限する。古いmatcherの一致だけで許可せず、現在のrank監査も要求する。
 * @param[in] family 審査済みID境界を決める組み込みfamily。 審査済みserial family。
 * @param[in] session 現在inventoryの0ではないsession。 現在inventoryのsession。
 * @param[in] deviceIdentity 対象deviceの空ではないopaque identity。 現在のopaque device identity。
 * @param[in] workspace 内容署名を検証したINFを所有する保護領域。 署名済みINFの保護領域。
 * @param[in] package 内容監査済みmetadata。原本と署名済みfileは変更しない。 内容監査済み原本metadata。変更しない。
 * @param[in] matcher 許可したcatalog側IDを現在deviceへ解決するlocal関数。 許可IDだけを受け取るlocal照合関数。
 * @param[in] rankAuditor 許可IDへ限定したcopyを現在deviceのrankと比較する関数。 現在deviceへのread-only rank監査関数。
 * @param[out] audit 対象外またはrank判定。入力不正／API失敗時は初期値。 対象外またはrank監査結果。
 * @return 判定成功時0、入力不正またはAPI失敗時はHRESULT。 判定成功は0、入力不正／API失敗はHRESULT。
 * @note 0は適用可能を意味しない。Scanと内容再検証後のinstallで共用する。
 */
[[nodiscard]] NativeError auditOfficialSerialDevice(
	OfficialSerialFamily family, ScanSessionId session, std::wstring_view deviceIdentity,
	const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
	const LocalHardwareIdMatcher &matcher, const OfficialSerialRankAuditor &rankAuditor,
	OfficialDriverRankAudit &audit) ;

/**
 * @brief 明示同意された公式serial ZIPを検査して、合格INFだけを導入対象にする。
 * @note 同一worker threadのscan sessionが保護領域と署名済みmetadataを単独所有する。
 */
class OfficialSerialProvider final {
public:
	/**
	 * @brief 未検索のProviderを作成する。
	 * 通信せずfamilyを固定する。未知enumはscan時に拒否する。
	 * @param[in] family 構築後に変更しない組み込みserial family。 このinstanceだけが扱う組み込みfamily。
	 */
	explicit OfficialSerialProvider( OfficialSerialFamily family) noexcept ;

	/**
	 * @brief このinstanceが使用する組み込みProvider IDを返す。
	 * Composite登録と取得契約のProviderを同じ定義へ拘束する。
	 * @return Process寿命中有効なID。未知familyの場合は空。 Process寿命中のID。未知familyは空。
	 */
	[[nodiscard]] std::wstring_view					 providerId() const noexcept ;

	/**
	 * @brief このfamilyの検査用ZIP取得上限を返す。
	 * WCHを既存4 MiBに限定し、他familyの32 MiBへ拡大しない。
	 * @return 一回一ZIPの最大byte数。未知familyは0。 検査取得に使うfamily別byte上限。未知familyは0。
	 */
	[[nodiscard]] std::uint64_t						 maximumArchiveBytes() const noexcept ;

	/**
	 * @brief 直前のscanで観測した対象・metadata record・適用性範囲を取得する。
	 * @return Provider所有のworker内根拠への参照。次のscanまたは明示失効まで有効である。
	 * @note Metadata成立後のpayload／内容監査失敗でも、先に確定したrecordを保持する。
	 */
	[[nodiscard]] const ProviderMeasurementEvidence &measurementEvidence() const noexcept ;

	/**
     * @brief 取得根拠と保護領域を解放する。
     */
	~OfficialSerialProvider() = default ;

	// 取得根拠、展開物、candidate identity表の所有権を別objectへ複製しない。
	/**
	 * @brief 取得根拠・展開物とcandidate identity表の二重管理を防ぐため、コピー構築を禁止する。
	 */
	OfficialSerialProvider( const OfficialSerialProvider &) = delete ;
	/**
	 * @brief 取得根拠・展開物とcandidate identity表を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	OfficialSerialProvider &operator=( const OfficialSerialProvider &) = delete ;
	/**
	 * @brief 取得根拠・展開物とcandidate identity表を元のserial Providerに留めるため、移動構築を禁止する。
	 */
	OfficialSerialProvider( OfficialSerialProvider &&) = delete ;
	/**
	 * @brief 元のserial Providerへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	OfficialSerialProvider	   &operator=( OfficialSerialProvider &&) = delete ;

	/**
	 * @brief 公式製品pageと必要なJSONから一つのserial ZIPを取得して既存監査へ接続する。
	 * 公式ZIP取得と既存監査を接続する。
	 * 明示同意なしにpayload取得せず、取得物を実行しない。
	 * @param[in] session 0ではない現在inventoryのscan session。 現在inventoryのsession。
	 * @param[in] options 今回の検査用取得への明示同意を含むscan設定。 今回の同意。
	 * @param[in] devices 外部送信しない現在device snapshot。上限4096件。 外部送信しないdevice群。
	 * @param[in] matcher 署名済みINFの許可IDだけを現在deviceへ解決するlocal関数。 許可IDのlocal完全一致関数。
	 * @param[in] rankAuditor 署名検証後のINFへ適用するPnP／rank監査関数。 read-only監査。
	 * @param[in] progress Workerからの確定進捗通知先。
	 * @return 監査済み候補、対象外、または段階別失敗。 全gate合格候補、対象外、または失敗。
	 */
	[[nodiscard]] ScanResult	scan( ScanSessionId session, const ScanOptions &options,
									 std::span<const OfficialCatalogDevice> devices,
									 const LocalHardwareIdMatcher		   &matcher,
									 const OfficialSerialRankAuditor	   &rankAuditor,
									 const ProviderProgressCallback		   &progress) ;

	/**
	 * @brief 内容とrankを再確認し、明示選択されたINFを既存導入境界へ渡す。
	 * 選択された公式INFを再監査して導入する。
	 * 外側の保護install処理が復元確認済みであることを前提にする。
	 * @param[in] session 現在のscan session。 保存session。
	 * @param[in] identities 表示済みの一意なcandidate ID集合。 選択済みID群。
	 * @param[in] parentWindow Native HWNDの整数表現。 親Window。
	 * @param[in] matcher 現在scan sessionに閉じた許可IDのlocal照合関数。 現在sessionの許可ID照合関数。
	 * @param[in] rankAuditor 現在状態と保存済みrankの再検証関数。 再監査境界。
	 * @param[in] installer 検証済みINFのWindows標準導入境界。 Windows導入境界。
	 * @param[in] progress 確定済み件数の通知先。 確定進捗。
	 * @return 選択順の個別導入結果。成功失敗によらずsessionを失効させる。 選択順の成否。部分失敗を全体成功にしない。
	 */
	[[nodiscard]] InstallResult install( ScanSessionId						session,
										std::span<const std::wstring>		identities,
										std::uintptr_t						parentWindow,
										const LocalHardwareIdMatcher	   &matcher,
										const OfficialSerialRankAuditor	   &rankAuditor,
										const VerifiedExternalInfInstaller &installer,
										const ProviderProgressCallback	   &progress) ;

private:
	/** @brief 合格INFとopaque deviceを拘束したinstall対象。 */
	struct Target {
		/// 現在inventory内だけで有効なopaque device ID。
		std::wstring			device ;
		/// 検証済みINF集合のindex。
		std::size_t				packageIndex{} ;
		/// Scan時に成立したrank根拠。
		OfficialDriverRankAudit rank ;
	} ;

	/**
	 * @brief 現在のHTTP ledgerを追加通信なしで計測resourceへ反映する。
	 * @note 不正または保持上限超過のledgerは部分公開せずresourceを空にする。
	 */
	void									   refreshMeasurementResources() noexcept ;

	/**
	 * @brief 候補routing、取得物、HTTP sessionだけを解放する。
	 * @note 同じscanで先に確定した計測根拠はCompositeが回収するまで維持する。
	 */
	void									   invalidatePreparedState() noexcept ;

	/**
	 * @brief Session、保護file、および前回scanの計測根拠を失効させる。
	 * 新scanと導入完了で旧候補を再利用させない。
	 */
	void									   invalidate() noexcept ;

	/// 構築時に固定し、別familyへの流用を防ぐ。
	const OfficialSerialFamily				   family_ ;
	/// 登録済みfamilyのhostだけを使用するHTTP client。
	OfficialHttpClient						   http_ ;
	/// 対象・query・record・監査範囲の根拠。
	ProviderMeasurementEvidence				   measurementEvidence_ ;
	/// 検証済み展開物の所有領域。
	std::unique_ptr<OfficialDownloadWorkspace> contentsWorkspace_ ;
	/// 全署名検証を通過したINFとentry集合。
	UserSelectedInfPackageContents			   contents_ ;
	/// UI発行済みIDと導入対象の一対一表。
	std::unordered_map<std::wstring, Target>   targets_ ;
	/// 0の場合はinstallを拒否する。
	ScanSessionId							   session_{} ;
	/// Scanを実行したworker thread。
	std::uint32_t							   ownerThread_{} ;
} ;
} // namespace drivercrate
