//------------------------------------------------------------------------------
/**
 * @file signed_index_candidate_binding.cpp
 * @brief 索引の私有取得根拠とWindows指定bindingを原子的候補へ接続します。
 * @version 01.06.01
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  同workerの索引候補と指定導入の内部境界を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/12  元grant再結合と収集者由来の局所宣言を説明。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  複数INFと厳密共有taskの全deviceへ独立bindingを発行。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  通常索引の必要構成選択と役割別部分結果へ接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/13  元private node選択後の必要構成発行へ通常索引を接続。
 * Ver.01.05.00 Shunji Ogawa  2026/10/14  記述済みnative部分positiveの一device参照を保持。
 * Ver.01.05.01 Shunji Ogawa  2026/10/15  全体内容INF件数をdevice別導入計画上限から分離。
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  実選択Needs前提を追加INFと分離し候補評価へ接続。
 * Ver.01.06.01 Shunji Ogawa  2026/10/15  再検証成功時も元全体内容検査のHRESULTをreportへ維持。
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_candidate_binding.h"
#include "platform/signed_index_scan.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/driver_store_provider.h"
#include "platform/signed_index_candidate_binding_internal.h"
#include "platform/official_file_verifier.h"
#include "core/candidate_audit.h"
#include "core/candidate_assessment.h"
#include "core/candidate_selection.h"
#include "core/official_preparation_operation.h"
#include "core/official_preparation_audit.h"
#include "core/provider_registry.h"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <filesystem>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace drivercrate::signed_index_candidate_binding_detail {
namespace {
// 製品は全てWindows標準APIの固定表を使用します。
const InstallerNativeCalls NATIVE_INSTALLER_CALLS{
	&CreateProcessW, &WaitForSingleObject, &GetExitCodeProcess, &CloseHandle, &GetSystemDirectoryW} ;
// 内部fixtureの単独所有scopeだけが同threadへ完全表を固定します。
thread_local const ScopedInstallerFixture *activeInstaller{} ;
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
// 明示診断の同thread scopeでだけ有効な同期観測です。
thread_local PublicationObserver publicationObserver{} ;
// Callback呼出し中だけ借用する観測所有者です。
thread_local void				*publicationObserverState{} ;
#endif
}
/** @see ScopedInstallerFixture宣言側の契約を正本とします。 */
ScopedInstallerFixture::ScopedInstallerFixture( InstallerNativeCalls calls) noexcept : calls_( calls)
{
	activeInstaller = this ;
}
/** @see ScopedInstallerFixture宣言側の契約を正本とします。 */
ScopedInstallerFixture::~ScopedInstallerFixture() noexcept
{
	// 別scopeの表を解除しません。
	if( activeInstaller == this) {
		activeInstaller = nullptr ;
	}
}
/** @see ScopedInstallerFixture宣言側の契約を正本とします。 */
const InstallerNativeCalls &ScopedInstallerFixture::calls() const noexcept
{
	return calls_ ;
}
/** @brief 同threadの完全表または固定native表だけを返します。
 * @return 同workerのscope終端まで有効な固定表です。
 */
[[nodiscard]] const InstallerNativeCalls &installerCalls() noexcept
{
	return activeInstaller ? activeInstaller->calls() : NATIVE_INSTALLER_CALLS ;
}
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
/** @see Access::observePublication宣言側の契約を正本とします。 */
void Access::observePublication( const PublicationObserver observer, void *const state) noexcept
{
	publicationObserver		 = observer ;
	publicationObserverState = state ;
}
/** @brief 同byte候補の発行条件だけを同期観測し、元結果へ書込みません。
 * @param[in] stage 内容評価前1、READY検証前3です。
 * @param[in] ordinal 同recordの元INF順序です。
 * @param[in] session 元scanです。
 * @param[in] candidate 同bindingの候補です。
 * @param[in] inf 同byteの内容検査です。
 * @param[in] evidence 同取得の正証拠です。
 * @param[in] origin 元由来のfindingです。
 * @param[in] error Windows観測の元HRESULTです。
 * @param[in] rank Windows観測の元rankです。
 * @param[in] needs 同実計画の検証済みNeeds辺数です。
 * @param[in] members 同実計画の追加INF数です。
 */
void observePublication( const unsigned stage, const std::size_t ordinal,
						const ScanSessionId session, const UpdateCandidate &candidate,
						const CommonInfInspection &inf, const std::uint64_t evidence,
						const CandidateAssessmentFinding &origin, const NativeError error,
						const std::optional<std::uint32_t> rank, const std::size_t needs,
						const std::size_t members) noexcept
{
	// 明示観測がない通常処理では追加評価やcallbackを実行しません。
	if( publicationObserver == nullptr) {
		return ;
	}

	PublicationDiagnostic diagnostic ;	// 原文字列を含まない数値snapshotです。
	diagnostic.stage			  = stage ;
	diagnostic.infOrdinal		  = ordinal ;
	diagnostic.candidateCurrent	  = candidate.current ;
	diagnostic.verifiedNeedsEdges = needs ;
	diagnostic.additionalMembers  = members ;
	diagnostic.contentContextValid =
		inf.scanSessionId == session && inf.state == CommonInfInspectionState::VERIFIED &&
		inf.error == 0U && inf.workspace && inf.closure.packages.size() == 1U && evidence != 0U &&
		!candidate.packageIdentity.empty() ;
	diagnostic.originValid =
		isCandidateAssessmentFindingValid( CandidateAssessmentAxis::ORIGIN, origin) ;
	diagnostic.observationValid = error == 0U || !rank ;
	// 単一の元INFがある場合だけmetadataの完全一致を観測します。
	if( inf.closure.packages.size() == 1U) {
		diagnostic.providerMatches =
			candidate.provider == inf.closure.packages.front().providerName ;
		diagnostic.versionMatches = candidate.version == inf.closure.packages.front().driverVersion ;
	}

	// 未構築の八軸をREADYや条件なしへ補完しません。
	if( candidate.assessment) {
		diagnostic.assessmentReady = isCandidateAssessmentReady( *candidate.assessment) ;
		// 各元必要役割を件数へ投影し、証拠や名称を出力しません。
		for( const auto &requirement : candidate.assessment->explicitRequirements) {
			diagnostic.baseRequirements +=
				requirement.role == CandidateComponentRole::BASE_DRIVER ? 1U : 0U ;
			diagnostic.extensionRequirements +=
				requirement.role == CandidateComponentRole::EXTENSION_INF ? 1U : 0U ;
			diagnostic.componentRequirements +=
				requirement.role == CandidateComponentRole::COMPONENT ? 1U : 0U ;
		}
	}

	publicationObserver( diagnostic, publicationObserverState) ;
}
/** @see Access::createInstaller宣言側の契約を正本とします。 */
std::unique_ptr<ScopedInstallerFixture> Access::createInstaller( InstallerNativeCalls calls)
{
	// 全低位表の欠損とscopeの重複を拒否し、部分native fallbackを設けません。
	if( activeInstaller || !calls.createProcess || !calls.waitProcess || !calls.exitCode ||
	   !calls.closeHandle || !calls.systemDirectory) {
		return nullptr ;
	}

	return std::unique_ptr<ScopedInstallerFixture>( new ScopedInstallerFixture( calls)) ;
}
#endif
} // namespace drivercrate::signed_index_candidate_binding_detail

namespace drivercrate {
namespace {
/** @brief 起動前から終端まで取得済みfileを書換え・削除から固定するRAIIです。 */
class InstallerReadFile final {
public:
	/** @brief 所有fileの複製を禁止します。
	 * @param[in] other 借用元です。本constructorは呼出し禁止です。
	 */
	InstallerReadFile( const InstallerReadFile &other) = delete ;
	/** @brief 所有fileの代入を禁止します。
	 * @param[in] other 借用元です。本演算子は呼出し禁止です。
	 * @return 本演算子は呼出し禁止です。
	 */
	InstallerReadFile &operator=( const InstallerReadFile &other) = delete ;
	/** @brief 元workspaceの実pathだけを読取り共有で開きます。
	 * @param[in] path 私有元取得の完全pathです。
	 */
	explicit InstallerReadFile( const std::wstring &path) noexcept
		: file_( CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL, nullptr))
	{
	}
	/** @brief 同scopeが開いたfileだけを全return・例外経路で閉じます。 */
	~InstallerReadFile() noexcept
	{
		// File生成失敗を所有handleとして閉じません。
		if( file_ != INVALID_HANDLE_VALUE) {
			CloseHandle( file_) ;
		}
	}
	/** @brief Fileを所有できたか確認します。
	 * @return 開けた場合trueです。失敗直後のGetLastErrorは呼出し側が保持します。
	 */
	[[nodiscard]] bool valid() const noexcept
	{
		return file_ != INVALID_HANDLE_VALUE ;
	}

private:
	/// 書換え・削除共有を許さない実取得fileの単独所有handleです。
	HANDLE file_{INVALID_HANDLE_VALUE} ;
} ;
/** @brief 指定した完全表のprocess/thread handleを同scopeで閉じるRAIIです。 */
class InstallerProcess final {
public:
	/** @brief 所有process/threadの複製を禁止します。
	 * @param[in] other 借用元です。本constructorは呼出し禁止です。
	 */
	InstallerProcess( const InstallerProcess &other) = delete ;
	/** @brief 所有process/threadの代入を禁止します。
	 * @param[in] other 借用元です。本演算子は呼出し禁止です。
	 * @return 本演算子は呼出し禁止です。
	 */
	InstallerProcess &operator=( const InstallerProcess &other) = delete ;
	/** @brief 完全表と所有handleを借用・所有します。
	 * @param[in] calls Scope終端まで生存する完全表です。
	 * @param[in] handles 起動APIが返した二handleです。
	 */
	InstallerProcess( const signed_index_candidate_binding_detail::InstallerNativeCalls &calls,
					 PROCESS_INFORMATION handles) noexcept
		: calls_( calls), handles_( handles)
	{
	}
	/** @brief 起動APIが返した二handleだけを閉じます。 */
	~InstallerProcess() noexcept
	{
		// Process生成の二handleを同じ表へ返します。
		if( handles_.hThread) {
			static_cast<void>( calls_.closeHandle( handles_.hThread)) ;
		}

		// Processの終端または取得失敗後に所有handleを解放します。
		if( handles_.hProcess) {
			static_cast<void>( calls_.closeHandle( handles_.hProcess)) ;
		}
	}

private:
	/// 起動に使用した同threadの完全表です。
	const signed_index_candidate_binding_detail::InstallerNativeCalls &calls_ ;
	/// 外へ流出させない所有process/thread handleです。
	PROCESS_INFORMATION												   handles_{} ;
} ;
/** @brief 検証済み公式EXEまたは固定Windows MSI UIだけへ明示的に引継ぎます。
 * @param[in] path 元private workspaceの完全pathです。
 * @param[in] msi 元署名recordのMSI形式だけでtrueです。
 * @param[out] exitCode 原processの終端codeです。起動失敗時は空です。
 * @param[out] reboot 終端codeが明示する再起動だけを保持します。
 * @return Windows APIまたはinstaller原終了codeのHRESULTです。導入成功ではありません。
 */
[[nodiscard]] NativeError launchOfficialInstaller( const std::filesystem::path &path, const bool msi,
												  std::optional<std::uint32_t> &exitCode,
												  bool						   &reboot)
{
	exitCode.reset() ;
	reboot			  = false ;
	const auto &calls = signed_index_candidate_binding_detail::installerCalls() ;	// 全表です。
	std::array<wchar_t, 32768U> system{} ;											// Windows x64標準起動元だけです。
	// 固定Windows標準directoryの実受信長です。切捨てを拒否します。
	const auto length = calls.systemDirectory( system.data(), static_cast<UINT>( system.size())) ;
	// Windows標準directoryの欠損や切捨てを任意pathで補完しません。
	if( length == 0U || length >= system.size()) {
		return static_cast<NativeError>(
			HRESULT_FROM_WIN32( length == 0U ? GetLastError() : ERROR_INSUFFICIENT_BUFFER)) ;
	}

	const auto file = path.native() ;	// 元保護workspaceのopaque pathです。
	// Command文字列の引用を変えるpathを拒否し、任意flagsを受けません。
	if( file.empty() || file.find( L'"') != std::wstring::npos || file.size() > 30000U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 元形式から固定する完全application pathです。検索pathを使用しません。
	const auto application =
		msi ? (std::filesystem::path( system.data()) / L"msiexec.exe").native() : file ;
	// 元保護pathだけを引用した非silent commandです。任意flagsを受けません。
	std::wstring command = L"\"" + application + L"\"" + (msi ? L" /i \"" + file + L"\"" : L"") ;
	// 元scopeだけで使用する有限な検査値です。未知を成功へ補完しません。
	STARTUPINFOW startup{} ;
	// 非silentの既定UIです。
	startup.cb = sizeof( startup) ;
	PROCESS_INFORMATION handles{} ;	// 生成APIだけが所有handleを発行します。
	// 検索path・handle継承・silent flagsを使用しない明示的引継ぎです。
	if( !calls.createProcess( application.c_str(), command.data(), nullptr, nullptr, FALSE, 0U,
							nullptr, system.data(), &startup, &handles)) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	const InstallerProcess process{calls, handles} ;	// 終端後も同API表で閉じます。
	// 受理済みinstallerを強制終了せず、原終端を待ちます。
	if( calls.waitProcess( handles.hProcess, INFINITE) != WAIT_OBJECT_0) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
	}

	DWORD code{} ;	// 元processのcodeを推測せず取得します。
	// 終了codeを取得できない引継ぎを成功へ補完しません。
	if( !calls.exitCode( handles.hProcess, &code) || code == STILL_ACTIVE) {
		return static_cast<NativeError>(
			HRESULT_FROM_WIN32( code == STILL_ACTIVE ? ERROR_BUSY : GetLastError())) ;
	}

	exitCode = code ;
	reboot	 = code == ERROR_SUCCESS_REBOOT_REQUIRED || code == ERROR_SUCCESS_REBOOT_INITIATED ;
	return code == ERROR_SUCCESS || reboot ? 0 : static_cast<NativeError>( HRESULT_FROM_WIN32( code)) ;
}
/** @brief Guard通過済み明示4要素versionをaction分類だけへ使用します。
 * @param[in] value Binderが保持した明示version。
 * @return 正規4要素ならpacked値、それ以外は空です。
 */
[[nodiscard]] std::optional<std::uint64_t> numericVersion( std::wstring_view value) noexcept
{
	std::uint64_t packed{} ;	// 4個の16bit要素。
	// 全4要素だけを読み、適用性やrankの根拠へ使用しません。
	for( std::size_t component = 0U; component < 4U; ++component) {
		const auto	  dot  = value.find( L'.') ;		// 現要素の終端。
		const auto	  part = value.substr( 0U, dot) ;	// 元明示値を正規化しません。
		std::uint64_t number{} ;						// 現要素の有限値。
		// 空の版要素を分類根拠として受理しません。
		if( part.empty()) {
			return std::nullopt ;
		}

		// 数値文字と16bit境界を確認し、桁落ちを補完しません。
		for( const auto character : part) {
			// 非数字と16bit範囲超過を拒否し、版値のoverflowを防ぎます。
			if( character < L'0' || character > L'9' ||
			   number > (65535U - (character - L'0')) / 10U) {
				return std::nullopt ;
			}

			number = number * 10U + static_cast<std::uint64_t>( character - L'0') ;
		}

		packed = (packed << 16U) | number ;
		// 最後の要素だけは区切りなしを要求します。
		if( component == 3U) {
			return dot == std::wstring_view::npos ? std::optional{packed} : std::nullopt ;
		}

		// 四要素に満たない版を推測して補完しません。
		if( dot == std::wstring_view::npos) {
			return std::nullopt ;
		}

		value.remove_prefix( dot + 1U) ;
	}

	return std::nullopt ;
}
/** @brief 取得済み成功を保持した全選択拒否結果を作ります。
 * @param[in] identities 元選択順。
 * @param[in] error 元拒否HRESULT。
 * @return 個別download成功とinstall失敗の結果。
 */
[[nodiscard]] InstallResult rejectedInstall( std::span<const std::wstring> identities,
											NativeError					  error)
{
	InstallResult result ;	// 全selectionへ同じ事前拒否を保持します。
	result.downloadOutcome = OutcomeCode::SUCCESS ;
	result.installOutcome  = OutcomeCode::FAILURE ;
	result.installError	   = error ;
	// 同じ元選択順を保持し、拒否から未選択driverを追加しません。
	for( const auto &identity : identities) {
		result.updates.push_back( {.identity		   = identity,
								  .downloadOutcome = OutcomeCode::SUCCESS,
								  .installOutcome  = OutcomeCode::FAILURE,
								  .installError	   = error}) ;
	}

	return result ;
}
/** @brief 未commitの新tokenを例外経路でも当該issuerへ戻すguardです。 */
class NewTokenGuard final {
public:
	/** @brief 発行済み一tokenを同期scopeへ固定します。
	 * @param[in,out] store 元issuer。
	 * @param[in] session 元scan。
	 * @param[in] token 新token。
	 * @param[in] installer Installer専用guardならtrueです。標準INFとは別issuer集合です。
	 */
	NewTokenGuard( DriverStoreProvider &store, ScanSessionId session, std::uint64_t token,
				  bool installer = false) noexcept
		: store_( store), session_( session), token_( token), installer_( installer)
	{
	}
	/** @brief Pending所有に移していない新tokenだけを破棄します。 */
	~NewTokenGuard() noexcept
	{
		// 別Providerのtokenへ触れず、この同期scopeで作った一tokenだけを戻します。
		if( token_ != 0U) {
			// 別形式のbinding集合を同じtoken値で破棄しません。
			if( installer_) {
				static_cast<void>( store_.discardOfficialInstallerDeviceBinding( session_, token_)) ;
			} else {
				static_cast<void>( store_.discardOfficialInfInstallBinding( session_, token_)) ;
			}
		}
	}
	/** @brief 新tokenの所有をpending transactionへ渡します。 */
	void release() noexcept
	{
		token_ = 0U ;
	}

private:
	/// 元workerのbinding issuer。
	DriverStoreProvider &store_ ;
	/// 元scan session。
	ScanSessionId		 session_ ;
	/// Pendingへ移す前だけ存在する新token。
	std::uint64_t		 token_ ;
	/// 元issuerのinstaller専用集合でだけtrueです。
	bool				 installer_{} ;
} ;
} // namespace

/** @see SignedIndexCandidateBindingSession宣言側の契約を正本とします。 */
void SignedIndexCandidateBindingSession::rollback( DriverStoreProvider &store) noexcept
{
	// 全既存routeのcopyより後の新tokenだけを破棄します。
	for( std::size_t index = routes_.size(); index < pendingRoutes_.size(); ++index) {
		const auto &route = pendingRoutes_[index] ;	// 今回だけの新binding。
		static_cast<void>( store.discardOfficialInfInstallBinding(
			route.candidate.assessment ? route.candidate.assessment->scanSessionId : 0U,
			route.binding.token)) ;
		static_cast<void>( store.discardOfficialInstallerDeviceBinding(
			route.candidate.assessment ? route.candidate.assessment->scanSessionId : 0U,
			route.installerToken)) ;
	}

	pendingRoutes_.clear() ;
	pending_ = false ;
}
/** @see SignedIndexCandidateBindingSession宣言側の契約を正本とします。 */
void SignedIndexCandidateBindingSession::commit() noexcept
{
	// 全reportとComposite mapの検証後だけ、allocationなしでroutingを公開します。
	if( pending_) {
		routes_.swap( pendingRoutes_) ;
		pendingRoutes_.clear() ;
		pending_ = false ;
	}
}
/** @see SignedIndexCandidateBindingSession宣言側の契約を正本とします。 */
void SignedIndexCandidateBindingSession::invalidate( DriverStoreProvider *const store) noexcept
{
	// Issuerが生存している間に新tokenとcommit済みtokenを全て失効します。
	if( store != nullptr) {
		rollback( *store) ;
		// 確定済み全routeの固有tokenを終端で破棄します。
		for( const auto &route : routes_) {
			static_cast<void>( store->discardOfficialInfInstallBinding(
				route.candidate.assessment ? route.candidate.assessment->scanSessionId : 0U,
				route.binding.token)) ;
			static_cast<void>( store->discardOfficialInstallerDeviceBinding(
				route.candidate.assessment ? route.candidate.assessment->scanSessionId : 0U,
				route.installerToken)) ;
		}
	}

	pendingRoutes_.clear() ;
	routes_.clear() ;
	pairs_.clear() ;
	records_.clear() ;
	references_.clear() ;
	pending_	   = false ;
	retainedBytes_ = 0U ;
}
/** @see SignedIndexCandidateBindingSession宣言側の契約を正本とします。 */
std::vector<UpdateCandidate> SignedIndexCandidateBindingSession::makeReferences(
	const std::shared_ptr<const SignedIndexRecordLookup> &lookup,
	const SignedIndexAcquisitionAdapter &adapter, const OfficialPreparationPlan &plan,
	const std::span<const UpdateCandidate>			   candidates,
	const std::span<const OfficialDiscoveryDeviceHint> hints)
{
	std::vector<Reference>		 pending ;	// 原子的に反映する元target一対一対応。
	std::vector<UpdateCandidate> result ;	// 検証後だけ返す非導入行。
	// 別planを既存参照へ再利用しません。
	if( !lookup || !references_.empty() || plan.scanSessionId == 0U || plan.targets.size() > 256U ||
	   candidates.size() > 65536U) {
		throw std::logic_error( "index reference context mismatch") ;
	}

	// 同describeから作ったtargetだけを元relation位置へ照合します。
	for( std::size_t relationIndex = 0U; relationIndex < lookup->relations().size();
		++relationIndex) {
		const auto &relation = lookup->relations()[relationIndex] ;	// 同lookupの原関係。
		const auto	binding	 = std::ranges::find_if( adapter.bindings_, [&]( const auto &value) {
			  return std::ranges::find( value.relationIndices, relationIndex) !=
					 value.relationIndices.end() ;
		  }) ; // 同issuerが原関係全体へ結合した取得binding。
		// 未記述関係から表示参照や取得targetを生成しません。
		if( binding == adapter.bindings_.end()) {
			continue ;
		}

		const auto &targetId = binding->target.identity ;	// URL/名称から作らない元opaque ID。
		const auto	target =
			std::find_if( plan.targets.begin(), plan.targets.end(), [&]( const auto &value) {
				return value.providerId == SIGNED_INDEX_PROVIDER_ID && value.identity == targetId ;
			}) ; // describeの同targetだけ。
		// 同planの対象へ結合できないrelationを候補へ戻しません。
		if( target == plan.targets.end()) {
			continue ;
		}

		const bool eligibleRelation =
			relation.state == IndexRecordMatchState::MATCHED ||
			(relation.state == IndexRecordMatchState::VERIFIED_PARTIAL &&
			 relation.reason == IndexRecordMatchReason::VERIFIED_POSITIVE_PARTIAL &&
			 relation.positiveProof) ;	// Adapterが元tupleとleaseを検証した記述済み関係です。
		// 記述済みの既知一deviceだけへ参照を作り、他node不足を導入可へ変えません。
		if( relation.context.scanSessionId != plan.scanSessionId || !eligibleRelation ||
		   !relation.deviceIdentity || relation.relatedDevices.size() != 1U ||
		   relation.relatedDevices.front() != *relation.deviceIdentity) {
			throw std::logic_error( "index target relation mismatch") ;
		}

		const auto current =
			std::find_if( candidates.begin(), candidates.end(), [&]( const auto &value) {
				return value.current && value.deviceIdentity == *relation.deviceIdentity ;
			}) ; // 同scanの元現在行。
		const auto hint = std::find_if( hints.begin(), hints.end(), [&]( const auto &value) {
			return value.deviceIdentity == *relation.deviceIdentity ;
		}) ; // 同presentの検証済みhint。
		// 未表示deviceやhint欠損から参照行を発行しません。
		if( current == candidates.end() || hint == hints.end()) {
			continue ;
		}

		UpdateCandidate candidate = *current ;	// 表示metadataだけを同deviceへ保持します。
		candidate.identity		  = L"index-reference-" + std::to_wstring( relationIndex) ;
		candidate.providerId	  = SIGNED_INDEX_PROVIDER_ID ;
		candidate.packageIdentity.clear() ;
		candidate.current			= false ;
		candidate.installable		= false ;
		candidate.recommended		= false ;
		candidate.action			= DriverAction::NONE ;
		candidate.defaultPreference = CandidateDefaultPreference::NONE ;
		candidate.discoveryBasis	= CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
		candidate.assessment.reset() ;
		candidate.releaseObservationDifference.reset() ;
		candidate.equivalentSourceCount = 1U ;
		candidate.preferredSource		= true ;
		candidate.deviceObservation.reset() ;
		candidate.metadataDistribution.reset() ;
		candidate.allContentCached = false ;
		candidate.sourceName	   = L"署名索引（収集者確認）" ;
		candidate.sourceLocation   = L"端末内で署名・byte・Windows適合を再検証" ;
		candidate.audit			   = {.sourceOrigin = CandidateAuditGateState::PASSED} ;
		candidate.title			   = L"署名索引（収集者確認・取得前）" ;
		pending.push_back( {relationIndex, *target, candidate, *current, *hint}) ;
		result.push_back( std::move( candidate)) ;
	}

	references_.swap( pending) ;
	return result ;
}
/** @see SignedIndexCandidateBindingSession宣言側の契約を正本とします。 */
NativeError SignedIndexCandidateBindingSession::reverifyRecord(
	const SignedIndexScanSession &owner, const PreparedRecord &record,
	const provider_worker_index_detail::Services &services) const
{
	const auto	now		 = services.utc ? services.utc() : std::nullopt ;	// 元workerの信頼UTC。
	const auto &metadata = record.grant.metadata() ;						// 元grant期限を延長しません。
	// 元claim/private owner/同context/同消費済みgrant以外を受理しません。
	if( !now || now->time_since_epoch().count() <= 0 || record.lookup != owner.acquisitionLookup_ ||
	   record.context != owner.context_ ||
	   record.task.scanSessionId != owner.context_.scanSessionId ||
	   record.task.planId != owner.preparationSummary_.planId || !owner.acquisition_ ||
	   !owner.workspace_ || metadata.state != OfficialDownloadGrantState::CONSUMED ||
	   metadata.outcome != OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION ||
	   metadata.error != 0 ||
	   record.grant.validateSignedIndexAuthority( record.task.scanSessionId) != 0) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto seconds = static_cast<std::uint64_t>( now->time_since_epoch().count()) ;	// 正のUTC秒。
	// 署名元とgrantの元最小期限に再照合し、再承認やinstallで延長しません。
	if( seconds < metadata.issuedUtcSeconds || seconds >= metadata.expiresUtcSeconds) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
	}

	IndexedDriverArchiveHint hint ;		// 同sealから再照合した元index/record/byte。
	DriverArchiveInput		 input ;	// 同保護実archive。
	const auto				 error = owner.adapter_.bindInspectionInput(
		  record.task, record.context, seconds, *owner.acquisition_, *owner.workspace_, record.seal,
		  hint, input) ;	// 実全byteと期限の再検証。
	// 元grant検証のHRESULTを上書きせず返します。
	if( error != 0U) {
		return error ;
	}

	// 全形式が同元seal・原取得byteへ再結合し、成功DTOを権限へ変更しません。
	if( hint.indexSha256 != record.hint.indexSha256 ||
	   hint.recordSha256 != record.hint.recordSha256 ||
	   hint.archiveSha256 != record.hint.archiveSha256 ||
	   hint.archiveBytes != record.hint.archiveBytes ||
	   input.inspectionPath != record.input.inspectionPath || input.sha256 != record.input.sha256 ||
	   input.byteCount != record.input.byteCount) {
		return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	}

	// InstallerはINF用ledgerへ偽装せず、同署名・期待publisherを改めて検査します。
	if( record.installerHandoff) {
		// 未検査・原署名拒否を引継ぎ可能へ補完しません。
		if( record.inspection.state !=
			   IndexedDriverInspectionState::INSTALLER_INSPECTION_COMPLETED ||
		   record.installerError != 0 || !record.inspection.inputBound ||
		   record.publisher.empty()) {
			return record.installerError != 0 ? record.installerError
											  : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		const std::array<std::wstring_view, 1U> publishers{
			record.publisher} ;	// 原完全一致policyです。
		return verifyAuthenticodePublisher( input.inspectionPath, publishers) ;
	}

	DelegatedOfficialPackageInput delegated ;	// 元成功grantの同ledger再結合。
	// 同消費済みgrantと実取得ledgerを再照合した元HRESULT。
	const auto					  delegatedError =
		makeDelegatedOfficialPackageInput( record.acquisition, record.grant, delegated) ;
	// 全元hash/size/pathと同grantを再結合し、公開DTOを権限へ昇格しません。
	if( delegatedError != 0U || hint.indexSha256 != record.hint.indexSha256 ||
	   hint.recordSha256 != record.hint.recordSha256 ||
	   hint.archiveSha256 != record.hint.archiveSha256 ||
	   hint.archiveBytes != record.hint.archiveBytes ||
	   input.inspectionPath != record.input.inspectionPath || input.sha256 != record.input.sha256 ||
	   input.byteCount != record.input.byteCount ||
	   delegated.provenance.downloadGrantId != record.delegated.provenance.downloadGrantId ||
	   delegated.provenance.acquisitionId != record.delegated.provenance.acquisitionId) {
		return delegatedError != 0U ? delegatedError
									: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	}

	return 0U ;
}
/** @see SignedIndexCandidateBindingSession宣言側の契約を正本とします。 */
std::optional<OfficialPreparationAuditReport> SignedIndexCandidateBindingSession::
	auditPreparedRecord( SignedIndexScanSession &owner, DriverStoreProvider &store,
						const provider_worker_index_detail::Services &services,
						const std::wstring_view						  targetIdentity,
						const std::span<const UpdateCandidate>		  displayed)
{
	const auto found = std::find_if( records_.begin(), records_.end(), [&]( const auto &record) {
		return record.task.target.identity == targetIdentity ;
	}) ; // 実取得成功を私有所有した元recordだけ。
	// 完全所有recordと参照の対応がないIDを拒否します。
	if( found == records_.end() || found->referenceIndex >= references_.size()) {
		return std::nullopt ;
	}

	const auto recordIndex = static_cast<std::size_t>( found - records_.begin()) ;	// Stable ordinal。
	auto	  &record	   = *found ;												// 同task/grant/seal/閉包の所有値。
	OfficialPreparationAuditReport report ;											// 非機密reportだけを本体へ渡します。
	report.targetIdentity = targetIdentity ;
	report.providerId	  = SIGNED_INDEX_PROVIDER_ID ;
	const bool finiteInfCount =
		record.inspection.inspection.infs.size() <=
		OFFICIAL_PREPARATION_MAXIMUM_INF_COUNT ;	// Narrowing前にpayload全体の上限を固定します。
	report.infCount =
		finiteInfCount ? static_cast<std::uint32_t>( record.inspection.inspection.infs.size()) : 0U ;
	report.contentError		= finiteInfCount
								  ? reverifyRecord( owner, record, services)
								  : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED)) ;
	report.installerHandoff = record.installerHandoff ;
	// 再検証の成功で元の全体内容失敗を消さず、既存の再検証失敗は優先して保持します。
	if( report.contentError == 0U) {
		report.contentError = record.inspection.error ;
	}

	// 元seal/期限を失った取得物は内容・Windows候補を未合格へ戻します。
	if( report.contentError != 0U) {
		report.content = CandidateAuditGateState::FAILURE ;
	} else {
		// Installerの署名・原作用範囲はINFの内容合格件数へ混入させません。
		if( record.installerHandoff) {
			report.content = CandidateAuditGateState::PASSED ;
		} else {
			// 本体共通検査の個別拒否を独立保持します。
			for( const auto &inf : record.inspection.inspection.infs) {
				report.acceptedInfCount +=
					inf.state == CommonInfInspectionState::VERIFIED && inf.error == 0U ? 1U : 0U ;
				// 最初の内容拒否だけを保持し、後続成功で消しません。
				if( report.firstContentRejection == 0U && inf.error != 0U) {
					report.firstContentRejection = inf.error ;
				}
			}

			report.content = report.acceptedInfCount != 0U ? CandidateAuditGateState::PASSED
														   : CandidateAuditGateState::REJECTED ;
		}
	}

	std::vector<OfficialDiscoveryDeviceHint> hints ;	// 同原承認targetへ結合済みの全device。
	// 元共有taskの全deviceを保持し、未表示deviceを推測追加しません。
	for( const auto &value : references_) {
		// 別taskの参照を同payloadへ無断で追加しません。
		if( value.target == record.task.target) {
			hints.push_back( value.hint) ;
		}
	}

	// 元承認件数と全参照が一致しない場合は共有候補を発行しません。
	if( hints.size() != record.task.target.deviceCount || hints.empty() || hints.size() > 32U) {
		report.applicability	  = CandidateAuditGateState::FAILURE ;
		report.applicabilityError = static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// 内容合格INFごとに全元deviceを照合し、別の非適用INFで正常pairを除外しません。
	if( report.content == CandidateAuditGateState::PASSED && report.applicabilityError == 0U &&
	   !record.installerHandoff) {
		std::vector<DelegatedOfficialDeviceApplicability> applicability ;	// 元observer集計。
		const DelegatedOfficialInfRankObserver			  observer =
			[&]( ScanSessionId session, std::wstring_view device,
				const OfficialDownloadWorkspace &workspace, const OfficialInfPackage &package,
				std::optional<std::uint32_t> &rank) {
				Pair pair ;	// 元HRESULTとoptional rankを件数から推測しません。
				// Extension/SWCを独立した基本INF候補へ発行しません。
				if( package.role != DriverPlanRole::BASE_DRIVER) {
					rank.reset() ;
					return NativeError{} ;
				}

				pair.recordIndex	= recordIndex ;
				pair.deviceIdentity = device ;
				const auto originalReference =
					std::ranges::find_if( references_, [&]( const auto &value) {
						return value.target == record.task.target &&
							   value.candidate.deviceIdentity == device ;
					}) ; // 同元record群と同deviceの独立参照。
				// 同targetに元参照がないdeviceの観測を候補へ使用しません。
				if( originalReference == references_.end()) {
					return static_cast<NativeError>( E_UNEXPECTED) ;
				}

				pair.referenceIndex =
					static_cast<std::size_t>( originalReference - references_.begin()) ;
				const auto inf =
					std::find_if( record.inspection.inspection.infs.begin(),
								 record.inspection.inspection.infs.end(), [&]( const auto &value) {
									 return value.workspace.get() == &workspace ;
								 }) ; // 同実検査の所有INFだけへ結合します。
				// 観測対象INFが所有検査集合に存在しなければ内部不整合を返します。
				if( inf == record.inspection.inspection.infs.end()) {
					return static_cast<NativeError>( E_UNEXPECTED) ;
				}

				pair.infOrdinal =
					static_cast<std::size_t>( inf - record.inspection.inspection.infs.begin()) ;
				pair.observerError =
					store.observeInfCandidateRank( session, device, workspace, package, rank) ;
				pair.observedRank = rank ;
				pairs_.push_back( std::move( pair)) ;
				return pairs_.back().observerError ;
			} ; // 同期callだけ借用し、元recordと元INFのordinalを保持します。
		report.applicabilityError = inspectDelegatedOfficialDriverApplicability(
			record.task.scanSessionId, record.delegated, record.inspection.inspection, hints,
			observer, applicability) ;
		// 全observer完了後だけ完全rank監査とunique bindingを発行します。
		for( auto &pair : pairs_) {
			// 異record・元拒否・rank欠損のpairはbinding作成へ進めません。
			if( pair.recordIndex != recordIndex || pair.observerError != 0U || !pair.observedRank) {
				continue ;
			}

			++report.examinedPairCount ;
			const auto &pairReference = references_[pair.referenceIndex] ;				// 同元承認の当該device。
			auto	   &inf		= record.inspection.inspection.infs[pair.infOrdinal] ;	// 所有閉包。
			const auto &package = inf.closure.packages.front() ;						// 共通処理の単一基本INF。
			pair.bindingError	= reverifyCommonDriverInf( inf) ;
			// 内容再検査に成功したpairだけWindows rankを再照会します。
			if( pair.bindingError == 0U) {
				pair.bindingError =
					store.auditOfficialInfRank( record.task.scanSessionId, pair.deviceIdentity,
											   *inf.workspace, package, pair.rankAudit) ;
			}

			// API完了0だけではAPPLICABLEへ昇格しません。
			if( pair.bindingError != 0U ||
			   pair.rankAudit.decision != OfficialDriverRankDecision::APPLICABLE) {
				report.firstPairError =
					report.firstPairError != 0U ? report.firstPairError : pair.bindingError ;
				report.failedPairCount += pair.bindingError != 0U ? 1U : 0U ;
				continue ;
			}

			++report.applicablePairCount ;
			++report.publication.examinedPairCount ;
			// 明示依存を消さず、実閉包の一意な必要役割から私有計画を構築します。
			if( package.hasExternalDependencies || !inf.requiredInfPackages.empty()) {
				pair.bindingError = store.createRequiredInfInstallBinding(
					record.task.scanSessionId, pair.deviceIdentity, inf, pair.requiredPlan,
					pairReference.current.provider, pairReference.current.version,
					pairReference.current.driverDate, pair.rankAudit, pair.binding) ;
			} else {
				pair.bindingError = store.createOfficialInfInstallBinding(
					record.task.scanSessionId, pair.deviceIdentity, *inf.workspace, package,
					pairReference.current.provider, pairReference.current.version,
					pairReference.current.driverDate, pair.rankAudit, pair.binding) ;
			}

			// 一pairの普通拒否は元診断と除外へ保持し、他Provider結果を捨てません。
			if( pair.bindingError != 0U) {
				++report.publication.excludedPairCount ;
				// 最初のpublication拒否を個別bindingの元HRESULTで保持します。
				if( report.publication.firstError == 0U) {
					report.publication.firstError = pair.bindingError ;
				}

				continue ;
			}

			NewTokenGuard	guard{store, record.task.scanSessionId,
								  pair.binding.token} ;				// 例外時の新token cleanup。
			UpdateCandidate candidate = pairReference.candidate ;	// 元同device表示値。
			candidate.identity =
				L"index-candidate-" + std::to_wstring( record.acquisition.acquisitionId) + L"-" +
				std::to_wstring( pair.infOrdinal) + L"-" + std::to_wstring( pair.referenceIndex) ;
			candidate.packageIdentity =
				L"index-package-" + std::to_wstring( record.acquisition.acquisitionId) ;
			candidate.title		 = L"署名索引（収集者確認）" ;
			candidate.provider	 = pair.binding.candidateProvider ;
			candidate.version	 = pair.binding.candidateVersion ;
			candidate.driverDate = pair.binding.candidateDate ;
			const auto currentVersion =
				// Action分類だけ。
				numericVersion( pair.binding.currentVersion) ;
			const auto candidateVersion =
				// Action分類だけ。
				numericVersion( pair.binding.candidateVersion) ;
			// 既知currentと候補の版を厳密分類できなければ公開を取り消します。
			if( !candidateVersion ||
			   (!currentVersion &&
				pair.binding.rankAudit.currentState != OfficialDriverRankCurrentState::NO_DRIVER)) {
				throw std::logic_error( "index binding version mismatch") ;
			}

			candidate.action =
				pair.binding.rankAudit.currentState == OfficialDriverRankCurrentState::NO_DRIVER
					? DriverAction::INITIAL_INSTALL
				: *candidateVersion > *currentVersion  ? DriverAction::UPDATE
				: *candidateVersion == *currentVersion ? DriverAction::REINSTALL
													   : DriverAction::DOWNGRADE ;
			candidate.installable	   = true ;
			candidate.allContentCached = true ;
			candidate.eulaAccepted =
				record.task.target.terms == OfficialPreparationTerms::CONFIRMED_NO_CONSENT ||
				record.task.target.terms ==
					OfficialPreparationTerms::
						ACCEPTANCE_REQUIRED ;	// 同approve/claim済み元taskだけです。
			candidate.audit = {CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED,
							   CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED,
							   CandidateInstallReadiness::READY} ;
			CandidateAssessment assessment ;							// 元実byteと同tokenへ結合した八軸。
			const auto evidenceId = record.acquisition.acquisitionId ;	// 同実ledgerのopaque証拠。
			// メーカー署名へ読み替えず同取得根拠へ結合する収集者attestation所見。
			const CandidateAssessmentFinding origin{
				CandidateAssessmentState::PASSED, CandidateAssessmentReason::VALIDATED,
				CandidateEvidenceKind::COLLECTOR_ATTESTATION, evidenceId} ;
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
			signed_index_candidate_binding_detail::observePublication(
				1U, pair.infOrdinal, record.task.scanSessionId, candidate, inf, evidenceId, origin,
				pair.observerError, pair.observedRank,
				pair.requiredPlan ? pair.requiredPlan->verifiedNeedsEdgeCount_ : 0U,
				pair.requiredPlan ? pair.requiredPlan->members_.size() : 0U) ;
#endif
			// 実内容/observerを結合後、実binder/token/route確認から専用八軸を確定します。
			if( !makeCommonInfCandidateAssessment( record.task.scanSessionId, candidate, inf,
												 evidenceId, origin, pair.observerError,
												 pair.observedRank, assessment)) {
				throw std::logic_error( "index content assessment mismatch") ;
			}

			assessment.windowsSelection	 = {CandidateAssessmentState::PASSED,
											CandidateAssessmentReason::VALIDATED,
											CandidateEvidenceKind::WINDOWS_API, pair.binding.token} ;
			assessment.method			 = {CandidateAssessmentState::PASSED,
											CandidateAssessmentReason::VALIDATED,
											CandidateEvidenceKind::IMPLEMENTATION_POLICY, pair.binding.token} ;
			assessment.executorAvailable = true ;
			// 内容関係と同issuer bindingを確認したmemberだけを明示構成へ加えます。
			if( pair.requiredPlan) {
				candidate.requiredExtensionCount =
					static_cast<std::uint32_t>( pair.requiredPlan->count( DriverPlanRole::EXTENSION)) ;
				candidate.requiredDriverComponentCount = static_cast<std::uint32_t>(
					pair.requiredPlan->count( DriverPlanRole::DRIVER_COMPONENT)) ;
				assessment.driverOnly	= {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId} ;
				assessment.requirements = {CandidateAssessmentState::NOT_APPLICABLE,
										   CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT,
										   CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId} ;
				// 追加INFのない計画も、実選択graphで充足したNeedsを前提へ保持します。
				if( pair.requiredPlan->verifiedNeedsEdgeCount_ != 0U) {
					assessment.explicitRequirements.push_back(
						{assessment.explicitRequirements.size() + 1U,
						 CandidateComponentRole::BASE_DRIVER, true,
						 CandidateRequirementState::SATISFIED,
						 CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId}) ;
				}

				// 必要性をtitle/公開boolから生成せず元検証memberへ結合します。
				for( const auto &member : pair.requiredPlan->members_) {
					assessment.explicitRequirements.push_back(
						{assessment.explicitRequirements.size() + 1U,
						 member.role == DriverPlanRole::EXTENSION
							 ? CandidateComponentRole::EXTENSION_INF
							 : CandidateComponentRole::COMPONENT,
						 true, CandidateRequirementState::SATISFIED,
						 CandidateEvidenceKind::PACKAGE_INSPECTION, evidenceId}) ;
				}

				// 実選択Needsまたは追加memberがある場合だけ充足を要約します。
				if( !assessment.explicitRequirements.empty()) {
					assessment.requirements = assessment.driverOnly ;
				}
			}

			const auto &original =
				record.lookup->snapshot()
					.schemaReceipt()
					.records()[record.lookup->relations()[pairReference.relationIndex]
								   .recordIndex] ;	// 同原必須条件です。
			// 共通INF閉包の依存を消さず、原taskの確認済み条件だけを別に結びます。
			for( std::size_t condition = 0U;
				condition < original.acquisitionDescriptor->prerequisites.items.size();
				++condition) {
				assessment.explicitRequirements.push_back(
					{assessment.explicitRequirements.size() + 1U,
					 CandidateComponentRole::BASE_DRIVER, true,
					 CandidateRequirementState::SATISFIED, CandidateEvidenceKind::OFFICIAL_RECORD,
					 evidenceId}) ;
			}

			// 実在の明示必須条件を条件なしと表示しません。
			if( !original.acquisitionDescriptor->prerequisites.items.empty()) {
				assessment.requirements = {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::OFFICIAL_RECORD, evidenceId} ;
			}

			candidate.assessment = std::move( assessment) ;
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
			signed_index_candidate_binding_detail::observePublication(
				3U, pair.infOrdinal, record.task.scanSessionId, candidate, inf, evidenceId, origin,
				pair.observerError, pair.observedRank,
				pair.requiredPlan ? pair.requiredPlan->verifiedNeedsEdgeCount_ : 0U,
				pair.requiredPlan ? pair.requiredPlan->members_.size() : 0U) ;
#endif
			// 八軸の不足や未知依存をboolだけでREADYへ補完しません。
			if( !isCandidateAssessmentReady( *candidate.assessment)) {
				throw std::logic_error( "index assessment not ready") ;
			}

			pair.candidate = std::move( candidate) ;
			// 全new routeと表示候補を検証前のtransactionにだけ加えます。
			if( !pending_) {
				pendingRoutes_ = routes_ ;
				pending_	   = true ;
			}

			// route上限を超えた新候補をcommit前に拒否します。
			if( pendingRoutes_.size() >= 4096U) {
				throw std::length_error( "index routing limit") ;
			}

			pendingRoutes_.push_back( pair) ;
			guard.release() ;
			report.publishedCandidates.push_back( pair.candidate) ;
			++report.publication.publishedCount ;
		}

		// 元API個別失敗と基礎非適用を合格へ変換しません。
		report.examinedPairCount = 0U ;
		// 各元deviceの観測・未知を集計し、共有targetの先頭だけを成功へ換算しません。
		for( const auto &value : applicability) {
			report.examinedPairCount += value.examinedPairCount ;
			report.failedPairCount += value.failedPairCount ;
			// 最初のpair拒否を元適合検査のHRESULTで保持します。
			if( report.firstPairError == 0U) {
				report.firstPairError = value.firstPairError ;
			}
		}

		report.applicability = report.applicablePairCount != 0U ? CandidateAuditGateState::PASSED
							   : report.applicabilityError != 0U || report.failedPairCount != 0U
								   ? CandidateAuditGateState::FAILURE
								   : CandidateAuditGateState::REJECTED ;
	}

	// 元公式installerの全原deviceへ独立current guardを発行し、Windows rank合格を捏造しません。
	if( record.installerHandoff && report.content == CandidateAuditGateState::PASSED &&
	   report.applicabilityError == 0) {
		// 各元recordの権限を保ち、同target以外のdeviceを和集合へ追加しません。
		for( std::size_t referenceIndex = 0; referenceIndex < references_.size(); ++referenceIndex) {
			const auto &reference = references_[referenceIndex] ;	// 同原relationです。
			// 別承認targetを当該installerの作用対象にしません。
			if( reference.target != record.task.target) {
				continue ;
			}

			// 一つの原deviceだけに結ぶ未公開のguardとrouteです。
			Pair pair ;
			pair.recordIndex	= recordIndex ;
			pair.referenceIndex = referenceIndex ;
			pair.deviceIdentity = reference.hint.deviceIdentity ;
			++report.examinedPairCount ;
			pair.bindingError = store.createOfficialInstallerDeviceBinding(
				record.task.scanSessionId, pair.deviceIdentity, reference.current.provider,
				reference.current.version, reference.current.driverDate, pair.installerToken) ;
			// 原present/currentの読取失敗を適合やrank成功へ昇格しません。
			if( pair.bindingError != 0) {
				++report.failedPairCount ;
				// 最初の原pair失敗だけを保持し、後続成功で消しません。
				if( report.firstPairError == 0) {
					report.firstPairError = pair.bindingError ;
				}

				continue ;
			}

			// 未commit tokenを全例外経路で元issuerへ返す所有guardです。
			NewTokenGuard guard{store, record.task.scanSessionId, pair.installerToken, true} ;
			// 同認証lookupの未変更原recordだけを借用します。
			const auto	 &original =
				record.lookup->snapshot()
					.schemaReceipt()
					.records()[record.lookup->relations()[reference.relationIndex].recordIndex] ;
			// 明示versionなしを任意の最新版へ補完しません。
			if( !original.version.value) {
				continue ;
			}

			auto candidate = reference.candidate ;	// 元device表示と選択の所有copyです。
			candidate.version =
				std::wstring{original.version.value->begin(), original.version.value->end()} ;
			// 明示候補versionのaction分類値です。適用性の代用ではありません。
			const auto proposed = numericVersion( candidate.version) ;
			// 元現在版のaction分類値です。欠損を更新不要へ補完しません。
			const auto current = numericVersion( reference.current.version) ;
			// 真NO_DRIVER以外の現在版欠損や未分類を初回導入へ変更しません。
			if( !proposed || (!current && !reference.current.version.empty())) {
				continue ;
			}

			candidate.identity = L"index-installer-" +
								 std::to_wstring( record.acquisition.acquisitionId) + L"-" +
								 std::to_wstring( referenceIndex) ;
			candidate.packageIdentity =
				L"index-installer-package-" + std::to_wstring( record.acquisition.acquisitionId) ;
			candidate.title			   = L"署名索引（公式installer引継ぎ・導入状態未確認）" ;
			candidate.provider		   = record.publisher ;
			candidate.driverDate	   = original.publishedDate.value
											 ? std::wstring{original.publishedDate.value->begin(),
														original.publishedDate.value->end()}
											 : L"" ;
			candidate.action		   = !current				 ? DriverAction::INITIAL_INSTALL
										 : *proposed > *current	 ? DriverAction::UPDATE
										 : *proposed == *current ? DriverAction::REINSTALL
																 : DriverAction::DOWNGRADE ;
			candidate.installable	   = true ;
			candidate.allContentCached = true ;
			candidate.eulaAccepted	   = true ;
			candidate.audit = {CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED,
							   CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED,
							   CandidateInstallReadiness::READY} ;
			CandidateAssessment assessment ;	// 引継ぎと標準INFは別の方式・順位です。
			assessment.scanSessionId	 = record.task.scanSessionId ;
			assessment.candidateIdentity = candidate.identity ;
			assessment.deviceIdentity	 = candidate.deviceIdentity ;
			assessment.packageIdentity	 = candidate.packageIdentity ;
			const auto evidence	   = record.acquisition.acquisitionId ;	// 原成功ledgerの同証拠です。
			assessment.origin	   = {CandidateAssessmentState::PASSED,
									  CandidateAssessmentReason::VALIDATED,
									  CandidateEvidenceKind::COLLECTOR_ATTESTATION, evidence} ;
			assessment.acquisition = {CandidateAssessmentState::PASSED,
									  CandidateAssessmentReason::VALIDATED,
									  CandidateEvidenceKind::PACKAGE_INSPECTION, evidence} ;
			assessment.signature   = {CandidateAssessmentState::PASSED,
									  CandidateAssessmentReason::VALIDATED,
									  CandidateEvidenceKind::WINDOWS_API, evidence} ;
			assessment.applicability	= {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::WINDOWS_API, pair.installerToken} ;
			assessment.windowsSelection = {CandidateAssessmentState::NOT_APPLICABLE,
										   CandidateAssessmentReason::INSTALLER_HANDOFF_SELECTION,
										   CandidateEvidenceKind::IMPLEMENTATION_POLICY,
										   pair.installerToken} ;
			assessment.driverOnly		= {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::INSTALLER_SCOPE_ATTESTED,
										   CandidateEvidenceKind::COLLECTOR_ATTESTATION, evidence} ;
			assessment.requirements		= {CandidateAssessmentState::NOT_APPLICABLE,
										   CandidateAssessmentReason::NO_EXPLICIT_REQUIREMENT,
										   CandidateEvidenceKind::OFFICIAL_RECORD, evidence} ;
			// 元必須条件は同task承認または既知LOCAL_CHECKに結合済みです。
			for( std::size_t condition = 0;
				condition < original.acquisitionDescriptor->prerequisites.items.size();
				++condition) {
				assessment.explicitRequirements.push_back(
					{condition + 1U, CandidateComponentRole::BASE_DRIVER, true,
					 CandidateRequirementState::SATISFIED, CandidateEvidenceKind::OFFICIAL_RECORD,
					 evidence}) ;
			}

			// 明示条件の存在を条件なしの合格へ丸めません。
			if( !assessment.explicitRequirements.empty()) {
				assessment.requirements = {CandidateAssessmentState::PASSED,
										   CandidateAssessmentReason::VALIDATED,
										   CandidateEvidenceKind::OFFICIAL_RECORD, evidence} ;
			}

			assessment.method			 = {CandidateAssessmentState::PASSED,
											CandidateAssessmentReason::VALIDATED,
											CandidateEvidenceKind::IMPLEMENTATION_POLICY, pair.installerToken} ;
			assessment.installMethod	 = CandidateInstallMethod::OFFICIAL_INSTALLER ;
			assessment.executorAvailable = true ;
			candidate.assessment		 = std::move( assessment) ;
			// 同意・全八軸・元record結合を検証前に公開しません。
			if( !isCandidateAssessmentReady( *candidate.assessment)) {
				throw std::logic_error( "installer assessment mismatch") ;
			}

			pair.candidate = std::move( candidate) ;
			// 全routeを通常publicationのtransactionへ結合します。
			if( !pending_) {
				pendingRoutes_ = routes_ ;
				pending_	   = true ;
			}

			// 私有route上限を越える候補を公開せず、全transactionを拒否します。
			if( pendingRoutes_.size() >= 4096U) {
				throw std::length_error( "installer routing limit") ;
			}

			pendingRoutes_.push_back( pair) ;
			guard.release() ;
			report.publishedCandidates.push_back( pair.candidate) ;
			++report.applicablePairCount ;
			++report.publication.examinedPairCount ;
			++report.publication.publishedCount ;
		}

		report.applicability = report.applicablePairCount ? CandidateAuditGateState::PASSED
							   : report.failedPairCount	  ? CandidateAuditGateState::FAILURE
														  : CandidateAuditGateState::REJECTED ;
	}

	// 元承認に含まれる全参照行だけへ内容結果を結合し、別targetへ転送しません。
	for( const auto &value : references_) {
		// 同じ未変更targetの参照だけをこのreportで更新します。
		if( value.target == record.task.target) {
			report.candidates.push_back(
				{value.candidate.identity,
				 {CandidateAuditGateState::PASSED, CandidateAuditGateState::PASSED, report.content,
				  report.applicability, CandidateInstallReadiness::BLOCKED}}) ;
		}
	}

	// Candidate publication状態と除外を同reportへ確定します。
	if( !report.publishedCandidates.empty()) {
		report.publication.state =
			OfficialPreparationCandidatePublicationState::CANDIDATES_PUBLISHED ;
		report.candidatePublicationAttempted = true ;
	}
	// 適合観測があっても公開可能なbindingがなければ候補なしを明示します。
	else if( report.applicablePairCount != 0U) {
		report.publication.state =
			OfficialPreparationCandidatePublicationState::NO_ELIGIBLE_CANDIDATES ;
	}

	// 元既表示参照だけへ同reportを結合できなければ全pendingをrollbackします。
	if( !validatePreparationCandidatePublication( report, displayed)) {
		rollback( store) ;
		throw std::logic_error( "index publication mismatch") ;
	}

	return report ;
}
/** @see SignedIndexCandidateBindingSession宣言側の契約を正本とします。 */
NativeError SignedIndexCandidateBindingSession::preflightRequiredInstall(
	const SignedIndexScanSession &owner, const DriverStoreProvider &store,
	const provider_worker_index_detail::Services &services, const ScanSessionId session,
	const std::span<const std::wstring> identities) const
{
	std::set<std::wstring> devices ;	// 元選択親の一意性です。
	const bool			   required = std::ranges::any_of( routes_, [&]( const auto &route) {
		return route.requiredPlan &&
			   std::ranges::find( identities, route.candidate.identity) != identities.end() ;
	}) ; // 必要計画がある時だけ既存single候補の実行順を変更します。
	// 必要計画が無いselectionの既存契約は維持します。
	if( !required) {
		return 0 ;
	}

	// 同selectionの全索引routeを復旧/導入前に検証します。
	for( const auto &identity : identities) {
		const auto route = std::ranges::find_if( routes_, [&]( const auto &r) {
			return r.candidate.identity == identity ;
		}) ; // 元表示IDです。
		// 別Providerは既存dispatcherに委ね、index権限へ変換しません。
		if( route == routes_.end()) {
			continue ;
		}

		// 未表示/異scan/同device重複を復旧前に拒否します。
		if( route->recordIndex >= records_.size() || !route->candidate.installable ||
		   !devices.insert( route->deviceIdentity).second) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		const auto &record = records_[route->recordIndex] ;	// 元byte/期限です。
		// 別scanの導入を許可しません。
		if( session != record.task.scanSessionId) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		auto error =
			// 同原task/期限/sealの再確認診断です。
			reverifyRecord( owner, record, services) ;
		// 元取得未確認では現在状態を導入権限へ使用しません。
		if( error != 0U) {
			return error ;
		}

		// Installerは既存の作用集合とguardを維持します。
		if( record.installerHandoff) {
			error = store.revalidateOfficialInstallerDeviceBinding( session, route->deviceIdentity,
																   route->installerToken) ;
		} else {
			// 所有範囲外INFを参照しません。
			if( route->infOrdinal >= record.inspection.inspection.infs.size()) {
				return static_cast<NativeError>( E_ACCESSDENIED) ;
			}

			const auto &inf = record.inspection.inspection.infs[route->infOrdinal] ;	// 元閉包です。
			error =
				route->requiredPlan
					? store.revalidateRequiredInfInstallBinding( session, route->deviceIdentity, inf,
																route->requiredPlan, route->binding)
					: reverifyCommonDriverInf( inf) ;
			// 必要役割のない同選択INFも元状態を確認します。
			if( error == 0U && !route->requiredPlan) {
				error = store.revalidateOfficialInfInstallBinding(
					session, route->deviceIdentity, *inf.workspace, inf.closure.packages.front(),
					route->binding) ;
			}
		}

		// 一候補の不足を全選択の復旧前停止へ保持します。
		if( error != 0U) {
			return error ;
		}
	}

	return 0 ;
}

/** @see SignedIndexCandidateBindingSession宣言側の契約を正本とします。 */
InstallResult SignedIndexCandidateBindingSession::executeBoundInstall(
	SignedIndexScanSession &owner, DriverStoreProvider &store,
	const provider_worker_index_detail::Services &services, const ScanSessionId session,
	const std::span<const std::wstring> identities, const std::uintptr_t parentWindowNative,
	const ProviderProgressCallback &progress)
{
	std::vector<std::size_t> selected ;	// 元selection順のprivate route ordinal。
	std::set<std::wstring>	 devices ;	// 一device一基本driver。
	// 全選択の元record/実seal/全file/rank/tokenを変更開始前に再検証します。
	for( const auto &identity : identities) {
		const auto route = std::find_if( routes_.begin(), routes_.end(), [&]( const auto &value) {
			return value.candidate.identity == identity ;
		}) ; // 元表示IDへ完全一致したrouteだけ。
		// 未公開・範囲外・同device重複・非導入候補を導入前に拒否します。
		if( route == routes_.end() || route->recordIndex >= records_.size() ||
		   !devices.insert( route->deviceIdentity).second || !route->candidate.installable) {
			return rejectedInstall( identities, static_cast<NativeError>( E_ACCESSDENIED)) ;
		}

		const auto &record = records_[route->recordIndex] ;	// 元claim取得。
		// 異scanと所有INF範囲外の選択を拒否します。
		if( session != record.task.scanSessionId ||
		   (!record.installerHandoff &&
			route->infOrdinal >= record.inspection.inspection.infs.size())) {
			return rejectedInstall( identities, static_cast<NativeError>( E_ACCESSDENIED)) ;
		}

		NativeError error = reverifyRecord( owner, record, services) ;	// 元expiryとseal/byte。
		// Installerでは同present/current guardだけを照合し、INF rankへ偽装しません。
		if( record.installerHandoff) {
			// 原署名・byte再照合に成功した対象だけ現在状態を確認します。
			if( error == 0) {
				error = store.revalidateOfficialInstallerDeviceBinding(
					session, route->deviceIdentity, route->installerToken) ;
			}

			// 一対象の事前拒否でも、全selectionを起動前に拒否します。
			if( error != 0) {
				return rejectedInstall( identities, error) ;
			}

			selected.push_back( static_cast<std::size_t>( route - routes_.begin())) ;
			continue ;
		}

		const auto &inf = record.inspection.inspection.infs[route->infOrdinal] ;	// 同所有閉包です。
		// 同seal再照合に成功した場合だけ全INF memberを再検査します。
		if( error == 0U) {
			error = reverifyCommonDriverInf( inf) ;
		}

		// 内容再検査に成功した場合だけ固有Windows bindingを再検証します。
		if( error == 0U) {
			error =
				route->requiredPlan
					? store.revalidateRequiredInfInstallBinding( session, route->deviceIdentity, inf,
																route->requiredPlan, route->binding)
					: store.revalidateOfficialInfInstallBinding(
						  session, route->deviceIdentity, *inf.workspace,
						  inf.closure.packages.front(), route->binding) ;
		}

		// 事前一括検証の失敗時はProvider導入を呼びません。
		if( error != 0U) {
			return rejectedInstall( identities, error) ;
		}

		selected.push_back( static_cast<std::size_t>( route - routes_.begin())) ;
	}

	// 共有installerは原作用集合全体が明示選択済みの場合だけ一回引継ぎます。
	for( const auto ordinal : selected) {
		// 元明示選択の私有routeだけを借用します。
		const auto &route = routes_[ordinal] ;
		// 同routeの原取得・署名・全byteの所有recordです。
		const auto &record = records_[route.recordIndex] ;
		// 標準INFの個別device導入へ共有installer制約を流用しません。
		if( !record.installerHandoff) {
			continue ;
		}

		// 終端または元集合の有限必要数です。成功数を推測しません。
		const auto count = std::ranges::count_if( selected, [&]( const auto value) {
			return routes_[value].recordIndex == route.recordIndex ;
		}) ;
		// 未選択deviceを同payloadの和集合として変更しません。
		if( static_cast<std::size_t>( count) != record.task.target.deviceCount) {
			return rejectedInstall( identities, static_cast<NativeError>( E_ACCESSDENIED)) ;
		}
	}

	InstallResult result ;	// 個別取得成功/導入成功・失敗を分離します。
	result.downloadOutcome = OutcomeCode::SUCCESS ;
	std::size_t successes{} ;									// 実指定install成功だけ。
	bool		changedRole{} ;									// 指定した役割のAPI完了があり全計画完了ではない事実です。
	std::map<std::size_t, UpdateExecutionResult> handedOff ;	// 同payloadは一回だけ起動します。
	// 元選択順で直前rank/bindingを再取得し、同期API待ちで進捗を増やしません。
	for( const auto ordinal : selected) {
		const auto			 &route	 = routes_[ordinal] ;				// 同private token。
		const auto			 &record = records_[route.recordIndex] ;	// 元取得・内容所有。
		UpdateExecutionResult update{.identity = route.candidate.identity,
									 .downloadOutcome =
										 OutcomeCode::SUCCESS} ;	// 取得と導入を同一状態にしません。
		// Installer引継ぎの原終了結果を保持し、driver導入成功へ変換しません。
		if( record.installerHandoff) {
			const auto previous = handedOff.find( route.recordIndex) ;	// 同原record集合の結果です。
			// 同payloadの後続原deviceは一回だけの原引継ぎ結果を保持します。
			if( previous != handedOff.end()) {
				update			= previous->second ;
				update.identity = route.candidate.identity ;
			} else {
				update.installerHandoff = true ;
				const InstallerReadFile file{
					record.input.inspectionPath} ;	// 終端まで実byteを固定します。
				// 直前の原Windows診断を保持し、後続処理で消しません。
				NativeError error =
					!file.valid() ? static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError()))
								  : 0 ;
				// 起動前から終端まで元全byteを固定し、元期限・署名・全選択guardを再検証します。
				if( error == 0) {
					error = reverifyRecord( owner, record, services) ;
				}

				// 原共有集合の全guardを一度だけ消費し、再起動操作への再利用を拒否します。
				for( const auto selectedOrdinal : selected) {
					const auto &member = routes_[selectedOrdinal] ;	// 原selectionだけです。
					// 別payloadのguardを消費しません。
					if( error == 0 && member.recordIndex == route.recordIndex) {
						error = store.consumeOfficialInstallerDeviceBinding(
							session, member.deviceIdentity, member.installerToken) ;
					}
				}

				// 全原byte・署名・作用範囲・元選択・復旧が有効な場合だけ非silent UIを起動します。
				if( error == 0) {
					error =
						launchOfficialInstaller( record.input.inspectionPath, record.msi,
												update.installerExitCode, update.rebootRequired) ;
				}

				update.handoffOutcome = error == 0 ? OutcomeCode::SUCCESS : OutcomeCode::FAILURE ;
				update.handoffError	  = error ;
				handedOff.emplace( route.recordIndex, update) ;
			}

			successes += update.handoffOutcome == OutcomeCode::SUCCESS ? 1U : 0U ;
			result.rebootRequired |= update.rebootRequired ;
			// 原引継ぎ失敗を後続成功で消しません。
			if( result.installError == 0 && update.handoffError != 0) {
				result.installError = update.handoffError ;
			}

			result.updates.push_back( std::move( update)) ;
			// 起動完了をdriver導入済み件数として通知しません。
			if( progress) {
				progress(
					{ProviderStage::INSTALLING,
					 static_cast<std::uint32_t>( result.updates.size() * 100U / selected.size()),
					 result.updates.size(), selected.size()}) ;
			}

			continue ;
		}

		const auto &inf = record.inspection.inspection.infs[route.infOrdinal] ;	// 標準INFだけです。
		NativeError error =
			// 二対象目も元期限を延長しません。
			reverifyRecord( owner, record, services) ;
		// 同sealが有効な対象だけ全INF memberを再検査します。
		if( error == 0U) {
			error = reverifyCommonDriverInf( inf) ;
		}

		OfficialDriverRankAudit audit ;	// 元Windows現在stateを変更直前に再取得します。
		// 内容が有効な対象だけ直前のWindows rankを再取得します。
		if( error == 0U) {
			error = store.auditOfficialInfRank( session, route.deviceIdentity, *inf.workspace,
											   inf.closure.packages.front(), audit) ;
		}

		// API成功でもAPPLICABLE以外は指定導入へ進めません。
		if( error == 0U && audit.decision != OfficialDriverRankDecision::APPLICABLE) {
			error = static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// 直前rankが適合した対象だけ固有bindingを再検証します。
		if( error == 0U) {
			error = store.revalidateOfficialInfInstallBinding(
				session, route.deviceIdentity, *inf.workspace, inf.closure.packages.front(),
				route.binding) ;
		}

		// 実executorは本体の指定INF bindingだけを使用し、メーカーprofileへ偽装しません。
		if( error == 0U) {
			error = reverifyRecord( owner, record,
								   services) ;	// Rank処理後にも元期限・seal・byteを再照合します。
		}

		// 未選択対象や更新したgrant期限から導入を開始しません。
		if( error == 0U) {
			error =
				route.requiredPlan
					? store.installBoundRequiredInfPlan(
						  session, route.deviceIdentity, inf, route.requiredPlan, route.binding,
						  parentWindowNative, update.requiredRoles, update.rebootRequired)
					: store.installBoundOfficialInf( session, route.deviceIdentity, *inf.workspace,
													inf.closure.packages.front(), route.binding,
													parentWindowNative, update.rebootRequired) ;
		}

		update.installOutcome = error == 0U ? OutcomeCode::SUCCESS
								: error == static_cast<NativeError>( S_FALSE)
									? OutcomeCode::SUCCEEDED_WITH_ERRORS
									: OutcomeCode::FAILURE ;
		update.installError	  = error ;
		successes += error == 0U ? 1U : 0U ;
		changedRole |= std::ranges::any_of( update.requiredRoles, []( const auto &role) {
			return role.reflection == DriverPlanReflectionState::INSTALL_API_COMPLETED ;
		}) ;
		result.rebootRequired |= update.rebootRequired ;
		// 最初の指定導入失敗を保持し、後続結果で消しません。
		if( result.installError == 0U && error != 0U) {
			result.installError = error ;
		}

		result.updates.push_back( std::move( update)) ;
		// 終了した選択件数だけを決定型進捗へ通知します。
		if( progress) {
			progress( {ProviderStage::INSTALLING,
					  static_cast<std::uint32_t>( result.updates.size() * 100U / selected.size()),
					  result.updates.size(), selected.size()}) ;
		}
	}

	result.succeeded	  = !selected.empty() && successes == selected.size() ;
	result.installOutcome = result.succeeded				 ? OutcomeCode::SUCCESS
							: successes != 0U || changedRole ? OutcomeCode::SUCCEEDED_WITH_ERRORS
															 : OutcomeCode::FAILURE ;
	return result ;
}
} // namespace drivercrate
