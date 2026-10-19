//------------------------------------------------------------------------------
/**
 * @file official_discovery_eula.h
 * @brief 公式自動探索payloadのEULA完全一致groupと短命同意tokenを管理する契約。
 * @version 01.00.01
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  EULA完全一致groupと短命同意tokenを追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 一objectをProvider worker threadだけで直列使用します。EULA本文とtokenは永続化、通常log、
 *       診断保存へ渡さず、新scan、取消し、終了時にsessionごと失効させます。
 * @see docs/adr/0157-automatic-official-discovery-consent-and-cache.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/official_discovery.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

// 一scanでEULA同意対象にできる検査用payload数。
inline constexpr std::size_t OFFICIAL_DISCOVERY_EULA_PACKAGE_LIMIT = 4U ;

/**
 * @brief 一つのEULA groupに対する短命なworker session tokenを表す。
 */
struct OfficialDiscoveryEulaGroupToken {
	/// Tokenを別operation、session、inventoryへ流用させない完全binding。
	OfficialDiscoveryBinding binding ;
	/// 同じsession内で1から単調増加するopaque値。
	std::uint64_t			 value{} ;

	/**
	 * @brief 全fieldを完全一致で比較する。
	 * @param[in] other 比較先のsnapshot。変更しない。
	 * @return 全fieldが一致する場合true、それ以外はfalse。
	 */
	bool operator==( const OfficialDiscoveryEulaGroupToken &other) const = default ;
} ;

/**
 * @brief Group化前の一つの検査用payloadとEULA snapshotを表す。
 */
struct OfficialDiscoveryEulaPackage {
	/// 検証済みrecord fingerprintとpayload ordinalから作ったopaque package ID。
	std::wstring  packageIdentity ;
	/// Provider registryのstable ID。
	std::wstring  providerId ;
	/// Providerが明示した空ではないEULA revision。
	std::wstring  eulaRevision ;
	/// UTF-8化してSHA-256を計算するplain text全文。
	std::wstring  eulaText ;
	/// 今回の検査用取得でこのpayloadに予約するbyte数。
	std::uint64_t maximumBytes{} ;

	/**
	 * @brief 同意対象の全fieldを完全一致で比較する。
	 * @param[in] other 比較先のsnapshot。変更しない。
	 * @return 全fieldが一致する場合true、それ以外はfalse。
	 */
	bool		  operator==( const OfficialDiscoveryEulaPackage &other) const = default ;
} ;

/**
 * @brief Provider、revision、UTF-8本文SHA-256が一致するEULA表示groupを表す。
 */
struct OfficialDiscoveryEulaGroup {
	/// 同じworker session内だけで同意結果を照合するopaque token。
	OfficialDiscoveryEulaGroupToken token ;
	/// Group全packageで完全一致するProvider stable ID。
	std::wstring					providerId ;
	/// Group全packageで完全一致する空ではないEULA revision。
	std::wstring					eulaRevision ;
	/// 利用者へ一度表示するplain text全文。
	std::wstring					eulaText ;
	/// UTF-8化した全文のSHA-256。
	std::array<std::byte, 32U>		eulaTextSha256{} ;
	/// このgroupへ初出順で結合したopaque package ID。
	std::vector<std::wstring>		packageIdentities ;
	/// Group内payloadを全て取得する場合の最大合計byte数。
	std::uint64_t					maximumTotalBytes{} ;
} ;

/**
 * @brief 一scanに限定したEULA group、判断状態、元package snapshotを所有する。
 */
class OfficialDiscoveryEulaSession final {
public:
	/** @brief 無効なEULA sessionを作成する。 */
	OfficialDiscoveryEulaSession() = default ;

	/** @brief 所有する本文、token、判断状態を破棄する。 */
	~OfficialDiscoveryEulaSession() = default ;

	/**
	 * @brief EULA tokenと同意判断のsession結合の二重管理を防ぐため、コピー構築を禁止する。
	 */
	OfficialDiscoveryEulaSession( const OfficialDiscoveryEulaSession &) = delete ;
	/**
	 * @brief EULA tokenと同意判断のsession結合を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	OfficialDiscoveryEulaSession &operator=( const OfficialDiscoveryEulaSession &) = delete ;
	/**
	 * @brief EULA tokenと同意判断のsession結合を元のEULA sessionに留めるため、移動構築を禁止する。
	 */
	OfficialDiscoveryEulaSession( OfficialDiscoveryEulaSession &&) = delete ;
	/**
	 * @brief 元のEULA sessionへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	OfficialDiscoveryEulaSession &operator=( OfficialDiscoveryEulaSession &&) = delete ;

	/**
	 * @brief 新しいscan bindingへEULA対象を固定し完全一致groupを構築する。
	 * @param[in] binding Operation、scan session、inventory generationの開始時binding。
	 * @param[in] packages 今回取得候補にした4件以下の変更不可payload snapshot。
	 * @return 全入力をgroup化できた場合0、それ以外はHRESULT bit pattern。
	 * @post 成功時は全groupが未判断であり、旧tokenは利用できない。
	 */
	[[nodiscard]] NativeError	  beginSession(
			const OfficialDiscoveryBinding				 &binding,
			std::span<const OfficialDiscoveryEulaPackage> packages) noexcept ;

	/**
	 * @brief 一つの完全一致groupへ利用者の許可または拒否を一度だけ記録する。
	 * @param[in] binding 現在画面が保持する開始時binding。
	 * @param[in] token 表示したgroupに含まれる短命token。
	 * @param[in] accepted 利用者が全文と全対象を許可した場合true。
	 * @return 初回判断を記録した場合0、stale、未知、再判断はHRESULT bit pattern。
	 * @note 本判断は検査用取得だけに使用し、installまたはWUA EULA同意へ流用しない。
	 */
	[[nodiscard]] NativeError recordDecision( const OfficialDiscoveryBinding		   &binding,
											 const OfficialDiscoveryEulaGroupToken &token,
											 bool accepted) noexcept ;

	/**
	 * @brief 現在packageが許可済みgroup snapshotと完全一致するか照合する。
	 * @param[in] binding 取得開始直前に再確認する現在binding。
	 * @param[in] token 利用者が判断したgroup token。
	 * @param[in] package 取得直前のProvider、revision、全文、予算を含むsnapshot。
	 * @return 同じgroupが許可済みで全fieldと本文SHA-256が不変の場合true。
	 */
	[[nodiscard]] bool		  isPackageAccepted(
			   const OfficialDiscoveryBinding &binding, const OfficialDiscoveryEulaGroupToken &token,
			   const OfficialDiscoveryEulaPackage &package) const noexcept ;

	/**
	 * @brief 利用者へ表示する未永続のEULA group集合を借用する。
	 * @return 次のbegin、invalidate、object破棄まで有効なgroup span。
	 */
	[[nodiscard]] std::span<const OfficialDiscoveryEulaGroup> groups() const noexcept ;

	/** @brief 新scan、取消し、終了時に本文、token、判断を全て失効させる。 */
	void													  invalidate() noexcept ;

	/**
	 * @brief 現在有効な開始時bindingを返す。
	 * @return 有効sessionのbinding。未開始または失効後は全0。
	 */
	[[nodiscard]] OfficialDiscoveryBinding					  activeBinding() const noexcept ;

private:
	/** @brief 一つのgroupが未判断、許可、拒否のどれかを表す。 */
	enum class Decision {
		/// 利用者へ表示する前または判断待ちである。
		PENDING,
		/// 同じsession内の検査用取得だけを利用者が許可した。
		ACCEPTED,
		/// 利用者が取得を拒否した。
		REJECTED,
	} ;

	/// 現在有効なoperation、scan session、inventory generation。
	OfficialDiscoveryBinding				  binding_ ;
	/// 逆行・再使用を拒否する過去最大operation ID。
	OperationId								  latestOperationId_{} ;
	/// 逆行・再使用を拒否する過去最大scan session ID。
	ScanSessionId							  latestScanSessionId_{} ;
	/// 同意対象の変更検出に使う開始時package所有copy。
	std::vector<OfficialDiscoveryEulaPackage> packages_ ;
	/// UIへ一度ずつ表示する完全一致group。
	std::vector<OfficialDiscoveryEulaGroup>	  groups_ ;
	/// Groupと同じindexで保持する一回限りの判断状態。
	std::vector<Decision>					  decisions_ ;
} ;

} // namespace drivercrate
