//------------------------------------------------------------------------------
/**
 * @file official_preparation.cpp
 * @brief 配布物単位の承認と取得taskの状態管理。
 * @version 01.04.01
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  EULA revisionの表示文字列検証を分離。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  取得前提の独立確認を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  EULA本文と取得再確認の境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  配布物単位の取得承認を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  同一EULAの短命group token検証を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  許諾の共通検証へ明示停止callbackを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.01 Shunji Ogawa  2026/10/12  許諾本文の共通private helper契約を定義側へ補足。
 * </pre>
 *
 * @note URL解決と転送は行わず、ADR 0098の一度限りの承認境界を管理します。
 */
//------------------------------------------------------------------------------

#include "core/official_preparation.h"
#include "core/provider_registry.h"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
//------------------------------------------------------------------------------
// 定数定義。
//------------------------------------------------------------------------------
constexpr std::size_t	MAXIMUM_TARGETS			= 256U ;	// 一計画と一scanで予約できる対象数上限。
constexpr std::size_t	MAXIMUM_IDENTITY_LENGTH = 128U ;	// 非機密opaque IDの文字数上限。
constexpr std::uint32_t MAXIMUM_DEVICE_COUNT	= 4096U ;	// 一対象へまとめるdevice数上限。
constexpr NativeError	CANCELLED_ERROR =
	std::bit_cast<NativeError>( std::uint32_t{0x800704C7U}) ;	// HRESULT_FROM_WIN32(ERROR_CANCELLED)。

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 表示名・URL・秘密情報を識別子へ流用する形式を拒否する。
 *
 * @param[in] value URLやpathを含めないopaque ID。
 * @return ASCII識別子が空でなく上限内ならtrue。
 */
//------------------------------------------------------------------------------
bool validIdentity( const std::wstring_view value)
{
	// 空または無制限の識別子を受理しない。
	if( value.empty() || value.size() > MAXIMUM_IDENTITY_LENGTH) {
		return false ;
	}

	// 有限長ID内の各文字を、固定された非機密token用文字集合へ限定する。
	for( const wchar_t character : value) {
		// URLのslash、空白、制御文字等を拒否する。
		if( !((character >= L'a' && character <= L'z') || (character >= L'A' && character <= L'Z') ||
			 (character >= L'0' && character <= L'9') || character == L'-' || character == L'_' ||
			 character == L':' || character == L'.')) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief Opaque IDではないため空白を許すが、URLや実行文字列としては使用しない。
 *
 * @param[in] value 公式文書から取得した単一行のrevision表示。
 * @return 有限で安全なUTF-16表示文字列の場合true。
 */
//------------------------------------------------------------------------------
bool validEulaRevision( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= MAXIMUM_IDENTITY_LENGTH && value.front() != L' ' &&
		   value.back() != L' ' && value.find_first_of( L"\r\n\t") == std::wstring_view::npos &&
		   validPreparationEulaText( value) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 予約はこの上限内で減算比較し、加算overflowを防ぐ。
 *
 * @param[in] limits Scanに固定する最大容量・件数。
 * @return 0を含まず、包含関係と件数上限が成立すればtrue。
 */
//------------------------------------------------------------------------------
bool validLimits( const OfficialPreparationLimits &limits)
{
	return limits.maximumFileBytes != 0U &&
		   limits.maximumFileBytes <= limits.maximumProviderBytes &&
		   limits.maximumProviderBytes <= limits.maximumSessionBytes &&
		   limits.maximumProviderFiles != 0U &&
		   limits.maximumProviderFiles <= limits.maximumSessionFiles &&
		   limits.maximumSessionFiles <= MAXIMUM_TARGETS ;
}

//------------------------------------------------------------------------------
/**
 * @brief Provider登録は転送許可ではなく、URLとresourceの権限は後続取得層で検証する。
 *
 * @param[in] target workerが保存した一配布物のsnapshot。
 * @param[in] limits 計画の予約上限。
 * @return 既知公式Providerかつ矛盾のない対象ならtrue。
 */
//------------------------------------------------------------------------------
bool validTarget( const OfficialPreparationTarget &target, const OfficialPreparationLimits &limits)
{
	// 不完全snapshotや上限を超えた対象を計画へ入れない。
	if( !validIdentity( target.identity) || !validIdentity( target.providerId) ||
	   !validIdentity( target.resourceId) || !validIdentity( target.releaseIdentity) ||
	   target.parserRevision == 0U || target.maximumBytes == 0U ||
	   target.maximumBytes > limits.maximumFileBytes || target.deviceCount == 0U ||
	   target.deviceCount > MAXIMUM_DEVICE_COUNT) {
		return false ;
	}

	// 利用条件の分類とEULAのsnapshotを照合し、未確定条件への包括同意を防ぐ。
	switch( target.terms) {
		// 未解決の利用条件は同意不要と共通の制約照合へ進む。
		case OfficialPreparationTerms::UNRESOLVED:
			// 未解決条件を具体的な確認同意で補完しません。
			if( target.requiresPrerequisiteConfirmation) {
				return false ;
			}

			[[fallthrough]] ;	// 本文なしの共通整合検査へ進みます。
		case OfficialPreparationTerms::CONFIRMED_NO_CONSENT:
			// 同意対象なしの分類とrevisionの併記は矛盾する。
			if( !target.eulaRevision.empty() || !target.eulaText.empty() ||
			   target.sharedEulaToken != 0U) {
				return false ;
			}

			break ;

		case OfficialPreparationTerms::ACCEPTANCE_REQUIRED:
			// 特定できない利用条件への包括同意を禁止する。
			if( !validEulaRevision( target.eulaRevision) ||
			   !validPreparationEulaText( target.eulaText)) {
				return false ;
			}

			break ;

		// 定義外の利用条件を同意不要として受理しない。
		default:
			// 定義外の条件を同意不要と解釈しない。
			return false ;
	}

	// 従来Providerの同意不要条件を新しい索引専用条件へ暗黙に広げません。
	if( target.providerId != SIGNED_INDEX_PROVIDER_ID &&
	   target.terms == OfficialPreparationTerms::CONFIRMED_NO_CONSENT &&
	   target.requiresPrerequisiteConfirmation) {
		return false ;
	}

	// 同じregistryの用途限定viewだけを参照し、通常scan未接続の取得entryを区別する。
	if( target.providerId == SIGNED_INDEX_PROVIDER_ID) {
		// 原出典と具体的確認文を完全snapshotへ結び、空の包括確認を受理しません。
		if( target.eulaSourceSubject.size() > 2240U || target.prerequisiteText.size() > 16384U ||
		   (target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED &&
			target.eulaSourceSubject.empty()) ||
		   (target.requiresPrerequisiteConfirmation && target.prerequisiteText.empty())) {
			return false ;
		}

		const auto *descriptor =
			// 一つだけの取得entry。
			signedIndexAcquisitionProviderDescriptor() ;
		return descriptor != nullptr && descriptor->id == target.providerId &&
			   (descriptor->capabilities &
				capabilityMask( ProviderCapability::SIGNED_INDEX_ACQUISITION)) != 0U ;
	}

	// 組み込みregistryだけを確認し、別のProvider一覧を持たない。
	for( const ProviderDescriptor &descriptor : builtInProviderDescriptors()) {
		// 登録IDが一致するProviderの能力を確認し、登録されているだけで公式通信を許可しない。
		if( descriptor.id == target.providerId) {
			return (descriptor.capabilities &
					capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) != 0U ;
		}
	}

	return false ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一配布物の複数deviceは一targetのdevice_countへまとめる。
 *
 * @param[in] plan 新しく提示する計画。
 * @return 有限で同一配布物の重複がない場合true。
 */
//------------------------------------------------------------------------------
bool validPlan( const OfficialPreparationPlan &plan)
{
	// 無効sessionや無制限の計画を受理しない。
	if( plan.scanSessionId == 0U || plan.planId == 0U || !validLimits( plan.limits) ||
	   plan.targets.empty() || plan.targets.size() > MAXIMUM_TARGETS) {
		return false ;
	}

	std::size_t eulaCharacters{} ;	// 全対象の本文量。加算前の減算比較で上限を維持する。
	// 最大256対象の各snapshotと、それより前の対象との一意性を確認する。
	for( std::size_t index = 0U; index < plan.targets.size(); ++index) {
		const OfficialPreparationTarget &target = plan.targets[index] ;	// 検証中の配布物。
		// 個別上限と計画全体の保持上限を独立して守る。
		if( !validTarget( target, plan.limits) ||
		   target.eulaText.size() > MAXIMUM_PREPARATION_PLAN_EULA_CHARACTERS - eulaCharacters) {
			return false ;
		}

		eulaCharacters += target.eulaText.size() ;
		// 上限内の既出対象だけを照合し、異なるIDによる同一配布物の重複も拒否する。
		for( std::size_t previous = 0U; previous < index; ++previous) {
			const OfficialPreparationTarget &known = plan.targets[previous] ;	// 既出snapshot。
			// 対象IDまたは同一Providerのreleaseが重複する計画を拒否し、二重取得を防ぐ。
			if( known.identity == target.identity ||
			   (known.providerId == target.providerId &&
				known.releaseIdentity == target.releaseIdentity)) {
				return false ;
			}
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未選択・待機・実行中は転送完了として数えない。
 *
 * @param[in] state 対象の現在または完了状態。
 * @return 選択された対象の確定状態の場合true。
 */
//------------------------------------------------------------------------------
bool terminalState( const OfficialPreparationItemState state) noexcept
{
	// 今回の取得が終了した状態だけを数え、未選択や実行待ちを進捗へ含めない。
	switch( state) {
		// 取得完了は今回の転送試行が終わった状態として共通判定へ進む。
		case OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION:
		// 通信同意待ちは今回の転送試行を終える状態として共通判定へ進む。
		case OfficialPreparationItemState::AWAITING_NETWORK_CONSENT:
		// 取消しは今回の転送試行を終える状態として共通判定へ進む。
		case OfficialPreparationItemState::CANCELLED:
		// 拒否は今回の転送試行を終える状態として共通判定へ進む。
		case OfficialPreparationItemState::REJECTED:
		// 失敗を含む確定状態を転送試行の完了として数える。
		case OfficialPreparationItemState::FAILURE:
			return true ;
		// 未選択・待機・実行中および未知状態を転送試行の完了に数えない。
		default:
			return false ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 許諾本文の有界UTF-16検証を同期停止確認付きで共用します。
 * @param[in] text 呼出し中だけ借用する本文。空または文字上限超過は拒否します。
 * @param[in] checkpoint 旧無制御入口ではnullptr、他では同期停止確認callbackです。
 * @param[in] context callback呼出し中だけ借用する値。checkpointがnullptrなら参照しません。
 * @return 可視文字を含み、禁止制御文字や不正surrogateを含まない場合だけtrueです。
 * @throws 呼出し先callbackが送出した例外を、そのまま呼出し側へ伝えます。
 * @note 本文を変更・保存せず、callbackも同期呼出しだけで保持しません。
 */
//------------------------------------------------------------------------------
static bool validPreparationEulaTextCore( const std::wstring_view   text,
										 PreparationTextCheckpoint checkpoint, void *context)
{
	// 欠落や上限超過の本文を表示済みとしない。
	if( text.empty() || text.size() > MAXIMUM_PREPARATION_EULA_CHARACTERS) {
		return false ;
	}

	bool visible{} ;	// 空白だけの偽本文を拒否するための可視文字検出。
	// UTF-16 code unitを上限内で一度だけ確認し、surrogate pairは二単位で処理する。
	for( std::size_t index = 0U; index < text.size(); ++index) {
		// 対を飛ばしても256単位以下で確認します。
		if( checkpoint != nullptr && index % 128U <= 1U) {
			checkpoint( context) ;
		}

		const wchar_t character = text[index] ;	// 制御文字とsurrogateを検査する単位。
		// 改行とtabだけは本文の構造として維持する。
		if( character == L'\r' || character == L'\n' || character == L'\t') {
			continue ;
		}

		// 非表示制御や双方向表示の上書きを許諾の表示に混ぜない。
		if( character < 0x20 || (character >= 0x7F && character <= 0x9F) ||
		   (character >= 0x202A && character <= 0x202E) ||
		   (character >= 0x2066 && character <= 0x2069) || character == 0x200E ||
		   character == 0x200F || character == 0x061C || character == 0xFEFF ||
		   character == 0x200B || character == 0x2060) {
			return false ;
		}

		// UTF-16の上位surrogateを見つけたら、後続一文字と対で検証する。
		if( character >= 0xD800 && character <= 0xDBFF) {
			// 下位surrogateが欠落した不正な本文を、表示済みの利用条件として受理しない。
			if( index + 1U == text.size() || text[index + 1U] < 0xDC00 ||
			   text[index + 1U] > 0xDFFF) {
				return false ;
			}

			// 上限を確認済みのlow surrogateを次周回で重複処理しない。
			++index ;
		}
		// 対応する上位surrogateなしに現れた下位surrogateを拒否する。
		else if( character >= 0xDC00 && character <= 0xDFFF) {
			return false ;
		}

		// Unicode空白や単独のjoinerだけを本文として承認しない。本文自体は変換しない。
		visible =
			visible || (character != L' ' && character != 0x00A0 && character != 0x1680 &&
						!(character >= 0x2000 && character <= 0x200A) && character != 0x200C &&
						character != 0x200D && character != 0x2028 && character != 0x2029 &&
						character != 0x202F && character != 0x205F && character != 0x3000) ;
	}

	// 最後の短い区間後も確認します。
	if( checkpoint != nullptr) {
		checkpoint( context) ;
	}

	return visible ;
}
/** @see official_preparation.h */
bool validPreparationEulaText( std::wstring_view text) noexcept
{
	return validPreparationEulaTextCore( text, nullptr, nullptr) ;
}

/** @see official_preparation.h */
bool validPreparationEulaTextControlled( std::wstring_view		  text,
										PreparationTextCheckpoint checkpoint, void *context)
{
	// 必須確認を無制御fallbackへ置き換えません。
	if( checkpoint == nullptr || context == nullptr) {
		return false ;
	}

	checkpoint( context) ;
	return validPreparationEulaTextCore( text, checkpoint, context) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationError OfficialPreparationSession::initialize( OfficialPreparationPlan plan)
{
	// 開始した操作の結果を先に確定させる。
	if( !invalidate()) {
		return OfficialPreparationError::BUSY ;
	}

	// ID、snapshot、上限の検証に通らない計画は、承認待ち状態へ登録しない。
	if( !validPlan( plan)) {
		return OfficialPreparationError::INVALID_PLAN ;
	}

	// 古い承認の復活を禁止する。
	if( plan.planId <= latestPlanId_ || plan.scanSessionId < latestSessionId_) {
		return OfficialPreparationError::STALE_PLAN ;
	}

	// 同じscanで予算を拡大させない。
	if( plan.scanSessionId == latestSessionId_ && plan.limits != limits_) {
		return OfficialPreparationError::INVALID_PLAN ;
	}

	// 新しいscan sessionに限って予算を初期化し、同じscan内での使い直しと区別する。
	if( plan.scanSessionId > latestSessionId_) {
		reservations_.clear() ;
		reservedBytes_	 = 0U ;
		reservedFiles_	 = 0U ;
		limits_			 = plan.limits ;
		latestSessionId_ = plan.scanSessionId ;
	}

	latestPlanId_ = plan.planId ;
	plan_		  = std::move( plan) ;
	state_		  = OfficialPreparationState::AWAITING_APPROVAL ;
	return OfficialPreparationError::NONE ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationError OfficialPreparationSession::approve(
	const OfficialPreparationApproval &approval)
{
	// 使用済み計画を再承認しない。
	if( state_ != OfficialPreparationState::AWAITING_APPROVAL) {
		return OfficialPreparationError::NO_PLAN ;
	}

	// ゼロまたは使用済みのoperation IDを拒否し、過去の承認を再実行させない。
	if( approval.operationId == 0U || approval.operationId <= latestOperationId_) {
		return OfficialPreparationError::STALE_OPERATION ;
	}

	// 承認対象のscanと計画が現在のsnapshotに一致しなければ取得を開始しない。
	if( approval.scanSessionId != plan_.scanSessionId || approval.planId != plan_.planId) {
		return OfficialPreparationError::STALE_PLAN ;
	}

	// 省略を暗黙の承認・拒否にしない。
	if( approval.limits != plan_.limits || approval.decisions.size() != plan_.targets.size()) {
		return OfficialPreparationError::INVALID_APPROVAL ;
	}

	// 全照合に成功するまで、本体の予算と対象状態を変更しない。
	std::vector<ProviderReservation>	 reservations = reservations_ ;		// 予約の仮更新先。
	std::uint64_t						 bytes		  = reservedBytes_ ;	// 仮のscan累計予約byte数。
	std::uint32_t						 files		  = reservedFiles_ ;	// 仮のscan累計予約file数。
	std::vector<OfficialPreparationItem> items ;							// 成功時だけ公開する対象別状態。
	std::vector<bool>					 networkApprovals ;					// 計画順へ正規化したnetwork同意。
	items.reserve( plan_.targets.size()) ;
	networkApprovals.reserve( plan_.targets.size()) ;
	// UI側の並べ替えを許し、計画の各対象に対応する判断を一件だけ求める。
	for( const OfficialPreparationTarget &target : plan_.targets) {
		const OfficialPreparationDecision *decision = nullptr ;	// 一致する非所有判断。
		// 最大256判断を照合し、同一IDの重複を拒否する。
		for( const OfficialPreparationDecision &candidate : approval.decisions) {
			// 対象IDが一致する利用者判断を一件へ解決して、別対象の同意を流用しない。
			if( candidate.target.identity == target.identity) {
				// 同じ対象への判断が重複する承認を拒否し、都合のよい一件を選ばない。
				if( decision != nullptr) {
					return OfficialPreparationError::INVALID_APPROVAL ;
				}

				decision = &candidate ;
			}
		}

		// Snapshotと必要同意を固定する。
		if( decision == nullptr || decision->target != target ||
		   (!decision->acquire && (decision->eulaAccepted || decision->restrictedNetworkApproved ||
								   decision->prerequisitesConfirmed)) ||
		   (decision->acquire &&
			(target.terms == OfficialPreparationTerms::UNRESOLVED ||
			 decision->eulaAccepted !=
				 (target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED) ||
			 decision->prerequisitesConfirmed != target.requiresPrerequisiteConfirmation))) {
			return OfficialPreparationError::INVALID_APPROVAL ;
		}

		// 利用者が取得を選んだ対象だけを予算へ予約し、未選択の転送を開始させない。
		if( decision->acquire) {
			// 同じscanで作り直した計画でも、消費済みのProvider予算を引き継ぐ。
			auto reservation = std::find_if( reservations.begin(), reservations.end(),
											[&target]( const ProviderReservation &entry) {
												return entry.providerId == target.providerId ;
											}) ; // この対象が消費するProvider予約。
			// このscanで初めて使用するProviderにだけ予約枠を追加し、既存の消費量を維持する。
			if( reservation == reservations.end()) {
				reservations.push_back( {target.providerId, 0U, 0U}) ;
				reservation = reservations.end() - 1 ;
			}

			// 加算前に上限を確認する。
			if( target.maximumBytes > limits_.maximumSessionBytes - bytes ||
			   target.maximumBytes > limits_.maximumProviderBytes - reservation->bytes ||
			   files >= limits_.maximumSessionFiles ||
			   reservation->files >= limits_.maximumProviderFiles) {
				return OfficialPreparationError::BUDGET_EXCEEDED ;
			}

			bytes += target.maximumBytes ;
			++files ;
			reservation->bytes += target.maximumBytes ;
			++reservation->files ;
		}

		items.push_back( {target.identity,
						 {decision->acquire ? OfficialPreparationItemState::PENDING
											: OfficialPreparationItemState::NOT_SELECTED,
						  0, 0U}}) ;
		networkApprovals.push_back( decision->restrictedNetworkApproved) ;
	}

	reservations_	   = std::move( reservations) ;
	reservedBytes_	   = bytes ;
	reservedFiles_	   = files ;
	items_			   = std::move( items) ;
	networkApprovals_  = std::move( networkApprovals) ;
	latestOperationId_ = approval.operationId ;
	state_			   = progress().total == 0U ? OfficialPreparationState::COMPLETED
												: OfficialPreparationState::PREPARING ;
	return OfficialPreparationError::NONE ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::optional<OfficialPreparationTask> OfficialPreparationSession::claimNext()
{
	// 未承認、取消し済み、二重開始を拒否する。
	if( state_ != OfficialPreparationState::PREPARING || activeTask_.has_value()) {
		return std::nullopt ;
	}

	// 計画順の有限対象から、明示承認された未開始項目だけを探す。
	for( std::size_t index = 0U; index < items_.size(); ++index) {
		// 未開始の承認対象を一件だけclaimし、所有値の準備後に実行中へ移す。
		if( items_[index].result.state == OfficialPreparationItemState::PENDING) {
			OfficialPreparationTask task{latestOperationId_, plan_.scanSessionId, plan_.planId,
										 plan_.targets[index],
										 networkApprovals_[index]} ;	// 呼出し側へ返す所有値。
			activeTask_					   = task ;
			activeIndexAcquisitionClaimed_ = false ;
			activeIndex_				   = index ;
			items_[index].result.state	   = OfficialPreparationItemState::IN_PROGRESS ;
			return std::optional<OfficialPreparationTask>{std::move( task)} ;
		}
	}

	return std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool OfficialPreparationSession::complete( const OfficialPreparationTask			  &task,
										  const OfficialPreparationTransferResult &result)
{
	// 他操作・別対象・再送・未確定通知を適用しない。
	if( !activeTask_.has_value() || *activeTask_ != task || !terminalState( result.state)) {
		return false ;
	}

	// 取得成功の通知は、errorと実byte数が承認範囲に整合するか追加で照合する。
	if( result.state == OfficialPreparationItemState::ACQUIRED_FOR_INSPECTION) {
		// 成功の条件と承認された転送上限の矛盾を拒否する。
		if( result.error != 0 || result.byteCount == 0U ||
		   result.byteCount > task.target.maximumBytes) {
			return false ;
		}
	}
	// 非取得結果を成功や取得済みbyte数で偽装させない。
	else if( result.error >= 0 || result.byteCount != 0U) {
		return false ;
	}

	items_[activeIndex_].result = result ;
	activeTask_.reset() ;
	// 全選択対象の終端結果がそろった時だけ、計画全体を完了へ移す。
	if( progress().completed == progress().total) {
		state_ = OfficialPreparationState::COMPLETED ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void OfficialPreparationSession::cancel() noexcept
{
	// 同意前の取消しでは計画を失効させ、残ったdialogからの承認を再利用させない。
	if( state_ == OfficialPreparationState::AWAITING_APPROVAL) {
		// 同意前の取消しは計画を失効させる。
		static_cast<void>( invalidate()) ;
		return ;
	}

	// 未開始計画や完了結果へ取消しを後付けしない。
	if( state_ != OfficialPreparationState::PREPARING &&
	   state_ != OfficialPreparationState::CANCELLING) {
		return ;
	}

	// 未選択と既に確定した結果を保持し、未開始の選択対象だけを確定させる。
	for( OfficialPreparationItem &item : items_) {
		// 未開始の対象だけを取消し済みにし、実行中の転送結果は取得層の通知を待つ。
		if( item.result.state == OfficialPreparationItemState::PENDING) {
			item.result = {OfficialPreparationItemState::CANCELLED, CANCELLED_ERROR, 0U} ;
		}
	}

	state_ = activeTask_.has_value() ? OfficialPreparationState::CANCELLING
									 : OfficialPreparationState::COMPLETED ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
bool OfficialPreparationSession::invalidate() noexcept
{
	// 取消しまたは完了を先に要求する。
	if( state_ == OfficialPreparationState::PREPARING ||
	   state_ == OfficialPreparationState::CANCELLING) {
		return false ;
	}

	plan_.targets.clear() ;
	plan_.scanSessionId = 0U ;
	plan_.planId		= 0U ;
	items_.clear() ;
	networkApprovals_.clear() ;
	activeTask_.reset() ;
	state_ = OfficialPreparationState::EMPTY ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationState OfficialPreparationSession::state() const noexcept
{
	return state_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
std::span<const OfficialPreparationItem> OfficialPreparationSession::items() const noexcept
{
	return items_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/core/official_preparation.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
OfficialPreparationProgress OfficialPreparationSession::progress() const noexcept
{
	OfficialPreparationProgress result ;	// 確定状態から作る非機密の進捗値。
	// 対象別状態の全件を確認し、取消しも選択済み作業の確定結果に含める。
	for( const OfficialPreparationItem &item : items_) {
		// 利用者が選んだ対象だけを総件数に含め、未選択行で完了率を変えない。
		if( item.result.state != OfficialPreparationItemState::NOT_SELECTED) {
			++result.total ;
		}

		// 成功だけでなく取消しや拒否も処理終了として数え、待機中の対象は増やさない。
		if( terminalState( item.result.state)) {
			++result.completed ;
		}
	}

	return result ;
}

/** @see OfficialPreparationSession 宣言側の契約を正本とする。 */
bool OfficialPreparationSession::ownsActiveTask( const OfficialPreparationTask &task) const noexcept
{
	return state_ == OfficialPreparationState::PREPARING && activeTask_.has_value() &&
		   *activeTask_ == task ;
}

/** @see OfficialPreparationSession 宣言側の契約を正本とする。 */
bool OfficialPreparationSession::claimIndexAcquisition( const OfficialPreparationTask &task) noexcept
{
	// 別adapterや再初期化で同じ実taskの一回発行を回避しません。
	if( activeIndexAcquisitionClaimed_ || !ownsActiveTask( task)) {
		return false ;
	}

	activeIndexAcquisitionClaimed_ = true ;
	return true ;
}

} // namespace drivercrate
