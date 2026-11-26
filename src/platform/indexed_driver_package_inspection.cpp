//------------------------------------------------------------------------------
/**
 * @file indexed_driver_package_inspection.cpp
 * @brief 索引hintから通常共通検査への非導入結合を実装する
 * @version 01.07.01
 * @date 2026/10/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続
 * Ver.01.02.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.03.00 Shunji Ogawa  2026/11/03  署名原範囲の非実行resource内容を接続
 * Ver.01.03.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.03.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.04.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.05.00 Shunji Ogawa  2026/11/19  独自クラスの再検証を内容専用入口へ接続
 * Ver.01.06.00 Shunji Ogawa  2026/11/22  公式範囲の元署名と現在Windowsの全行を比較
 * Ver.01.07.00 Shunji Ogawa  2026/11/22  保持した元閉包の全ファイルとCATを再検査
 * Ver.01.07.01 Shunji Ogawa  2026/11/22  INFの媒体宣言を一意な元展開位置へ照合
 * </pre>
 *
 * @note File検査は既存共通層へ委譲する。全体失敗時は部分閉包を保持せず、外部取得・
 *       installer実行・staging・Windows設定変更は行わない
 */
//------------------------------------------------------------------------------

#include "indexed_driver_package_inspection.h"
#include "platform/official_file_verifier.h"
#include "platform/official_resource_content.h"
#include "platform/official_download_workspace.h"
#include "platform/signed_index_codec_internal.h"

#include <Windows.h>
#include <algorithm>
#include <array>

#include <new>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

constexpr std::uint64_t MAXIMUM_ARCHIVE_BYTES =
	2ULL * 1024ULL * 1024ULL * 1024ULL ;	// 通常共通層と同じ入力上限

//------------------------------------------------------------------------------
/**
 * @brief 小文字64桁の非秘密hash参照だけを受理する
 * @param[in] value 索引・record・archiveの識別hash
 * @return 全桁がASCII小文字hexならtrue
 */
//------------------------------------------------------------------------------
bool isLowerHash( const std::wstring_view value) noexcept
{
	// 短縮・欠損hashを完全なidentityとして使わない
	if( value.size() != 64U) {
		return false ;
	}

	// 文字列を正規化して別の索引参照を作らない
	for( const wchar_t character : value) {
		// ASCII hex以外をschemaへ混入させない
		if( !((character >= L'0' && character <= L'9') ||
			 (character >= L'a' && character <= L'f'))) {
			return false ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 内部入力へnetwork・device path・ADSを混入させない
 * @param[in] path 既存workspaceが所有するlocal drive上の絶対path
 * @return Drive絶対構文と有限長を満たす場合true
 * @note 保護store所有権の検証は呼出し側の既存取得／copy層が担当する
 */
//------------------------------------------------------------------------------
bool isLocalInputPath( const std::wstring_view path) noexcept
{
	return path.size() >= 4U && path.size() <= 32767U && path[1] == L':' && path[2] == L'\\' &&
		   ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
		   path.find( L':', 2U) == std::wstring_view::npos &&
		   path.find( L'\0') == std::wstring_view::npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全体失敗時の部分閉包を破棄し、入力結合の到達事実だけを残す
 * @param[in,out] result 所有する通常検査結果を失う出力
 * @param[in] state 失敗・取消しの終端段階
 * @param[in] error 0ではない元HRESULT
 * @return 入力の元HRESULT
 */
//------------------------------------------------------------------------------
NativeError fail( IndexedDriverPackageInspection &result, const IndexedDriverInspectionState state,
				 const NativeError error)
{
	result.inspection = {} ;
	result.state	  = state ;
	result.error	  = error ;
	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定32byteハッシュをWindowsファイル検査の小文字hexへ変換します
 * @param[in] digest 元SHA-256です
 * @return 全64桁の元値です
 */
//------------------------------------------------------------------------------
std::wstring scopedHashText( const IndexManifestSha256 &digest)
{
	constexpr std::wstring_view digits = L"0123456789abcdef" ;	// 4bitから一桁の小文字hexへの対応表
	std::wstring				value ;							// 元バイト順のハッシュ文字列
	value.reserve( 64U) ;
	// 元の32バイトを順に上位・下位の二桁へ変換する
	for( const auto byte : digest) {
		value.push_back( digits[byte >> 4U]) ;
		value.push_back( digits[byte & 15U]) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元Models全節の順序、ダイジェストと元Hardware欄の位置を比較します
 * @param[in] expected 元証拠で固定した節と位置です
 * @param[in] actual 同元INFからWindowsが選択した節と位置です
 * @return 全節と全一致行が同じ場合trueです
 * @note 実行中Windowsの観測と比較する場合も元節の比較を省略しません
 */
//------------------------------------------------------------------------------
bool sameScopedModels( const OfficialInfScopedModelsEvidence &expected,
					  const OfficialInfScopedModelsEvidence &actual)
{
	return expected.infSha256 == actual.infSha256 &&
		   std::ranges::equal(
			   expected.sections, actual.sections, []( const auto &left, const auto &right) {
				   return left.modelSection == right.modelSection &&
						  left.modelRows == right.modelRows && left.idFields == right.idFields &&
						  left.orderedRowsSha256 == right.orderedRowsSha256 &&
						  std::ranges::equal( left.matches, right.matches,
											 []( const auto &first, const auto &second) {
												 return first.modelRow == second.modelRow &&
														first.hardwareId == second.hardwareId &&
														first.installBase == second.installBase ;
											 }) ;
			   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原証拠の相対位置を既存のWindows member表記に直します
 * @param[in] value 元codecが検証した配布内の相対位置です
 * @return Windows区切り文字を使う相対位置です
 */
//------------------------------------------------------------------------------
std::wstring scopedMemberPath( const std::string_view value)
{
	std::wstring path( value.begin(), value.end()) ;	// 区切りだけを変える元相対位置のコピー
	std::ranges::replace( path, L'/', L'\\') ;
	return path ;
}

//------------------------------------------------------------------------------
/**
 * @brief INFの媒体宣言をWindowsの比較規則で同じ閉包の元エントリへ解決する
 * @param[in] entries 検査した元ファイルの相対位置とハッシュ。戻り値の使用中は変更しない
 * @param[in] path INFが指定した閉包内の全相対位置
 * @return 一意に一致した元エントリの借用ポインター。欠落・曖昧・範囲外ではnullptr
 * @note 元エントリの表記を保持し、索引の署名済み相対位置を正規化しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] const OfficialZipEntry *findScopedArchiveMember(
	const std::span<const OfficialZipEntry> entries, const std::wstring_view path) noexcept
{
	// 空の名前やWindowsの有限パス長を超える宣言を照合しない
	if( path.empty() || path.size() > 32767U) {
		return nullptr ;
	}

	const int length = static_cast<int>( path.size()) ;	// Windowsのordinal比較に渡す文字数
	const OfficialZipEntry *match{} ;					// 一致した唯一の元エントリを借用
	// 不一致の媒体を飛ばし、大小文字を区別しない全位置の一致が一つだけ存在するか検査する
	for( const auto &entry : entries) {
		// 別位置のファイルを同名候補へ加えず、明示長で比較して途中の終端を採用しない
		if( entry.relativePath.size() != path.size() ||
		   CompareStringOrdinal( entry.relativePath.data(), length, path.data(), length, TRUE) !=
			   CSTR_EQUAL) {
			continue ;
		}

		// 大小文字違いを含む複数一致を任意の先頭へ縮約しない
		if( match != nullptr) {
			return nullptr ;
		}

		match = &entry ;
	}

	return match ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ原証拠が指す選択基本INFと保持閉包の元用途を照合します
 * @param[in] session 同じ配布物を所有するworker scanです
 * @param[in] hint 取得時に固定した配布物と選択INFです
 * @param[in] proof 同じ署名レコードから得た配布と全Modelsの元証拠です
 * @param[in] content 基本INFと全必須INFを保持する元内容検査です
 * @return 同じ配布物、保護閉包、基本INFと同じ元範囲の場合0です
 * @note 元ファイルの実バイトとCATは呼出し側が別に検査します
 */
//------------------------------------------------------------------------------
NativeError matchIndexedScopedContent(
	const ScanSessionId session, const IndexedDriverArchiveHint &hint,
	const signed_index_detail::CollectorScopedModelsEvidence &proof,
	const CollectorDriverPackageContent						 &content)
{
	// 元内容の失敗を索引の不一致として上書きしない
	if( content.error != 0) {
		return content.error ;
	}

	// 取得時のsessionと元CABの同一性、単一の公式Models範囲を求める
	if( session == 0U || content.scanSessionId != session || hint.selectedInfs.size() != 1U ||
	   hint.archiveBytes != proof.archiveBytes ||
	   hint.archiveSha256 != scopedHashText( proof.archiveSha256) ||
	   content.archiveBytes != hint.archiveBytes || content.archiveSha256 != hint.archiveSha256 ||
	   content.infs.size() != 1U || !proof.models.platform || proof.models.sections.empty()) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto &inf		 = content.infs.front() ;		// 元CABから検査した基本INFの内容
	const auto &selector = hint.selectedInfs.front() ;	// 取得時に指定した唯一の相対位置
	// 内容と作用参照の失敗を後段の拒否で隠さない
	if( inf.error != 0 || inf.effectInventoryError != 0) {
		return inf.error != 0 ? inf.error : inf.effectInventoryError ;
	}

	// 同じ保護領域にある元INFと全必須INFの参照を閉包として要求する
	if( inf.scanSessionId != session || inf.state != CommonInfInspectionState::VERIFIED ||
	   !inf.workspace || inf.workspace->protectionMode() != OfficialWorkspaceMode::ADMINISTRATOR ||
	   inf.infRelativePath != selector.infIdentity ||
	   inf.infRelativePath != scopedMemberPath( proof.infIdentity) ||
	   inf.nestedArchivePath != selector.nestedArchive ||
	   inf.nestedArchivePath != scopedMemberPath( proof.nestedArchiveIdentity) ||
	   inf.closure.packages.size() != 1U || inf.closure.entries.empty() ||
	   inf.effects.size() != inf.requiredInfPackages.size() + 1U ||
	   !std::ranges::all_of( inf.effects, []( const auto &effect) {
		   return effect.referenceCoverage == MaintenanceInfReferenceCoverage::COMPLETE ;
	   })) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto		  &package = inf.closure.packages.front() ;	// 検査済みの基本INF構造
	// 元索引のクラスをWindows APIへ渡すための文字列
	const std::wstring expectedClass( proof.classGuid.begin(), proof.classGuid.end()) ;
	// INFの媒体宣言に一意に対応する閉包内の元CAT
	const auto *catalog = findScopedArchiveMember( inf.closure.entries, package.catalogRelativePath) ;
	// INFの宣言に対応する元CATを署名索引の正確な相対位置とハッシュへ結ぶ
	if( package.role != DriverPlanRole::BASE_DRIVER ||
	   package.inspectionPurpose != OfficialInfInspectionPurpose::COLLECTOR_CONTENT ||
	   package.infRelativePath != inf.infRelativePath || catalog == nullptr ||
	   catalog->relativePath != scopedMemberPath( proof.catalogIdentity) ||
	   catalog->sha256 != scopedHashText( proof.catalogSha256) ||
	   CompareStringOrdinal( package.classGuid.c_str(), -1, expectedClass.c_str(), -1, TRUE) !=
		   CSTR_EQUAL ||
	   !package.scopedModels || package.scopedModels->platform != proof.models.platform ||
	   !sameScopedModels( proof.models, *package.scopedModels)) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	return 0 ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 索引hintと固定済み入力の有限identityだけを非I/Oで照合する
 * @param[in] activeScanSessionId 現在の0ではないworker scan session
 * @param[in] hint 呼出し側が選択した期待値。全hashは小文字64桁
 * @param[in] input 既存保護copyまたは共通取得層が固定したarchive
 * @param[in] format ZIP、CABINETまたは非実行SEVEN_ZIP_SFX。実行形式の推測は行わない
 * @return Session・hash・size・local path構文・形式が一致する場合true
 * @note 実byte、索引本文・署名、公式取得根拠や許可の検査を代替しない
 */
//------------------------------------------------------------------------------
bool matchesIndexedDriverArchiveHint( const ScanSessionId			   activeScanSessionId,
									 const IndexedDriverArchiveHint	  &hint,
									 const DriverArchiveInput		  &input,
									 const OfficialDriverArchiveFormat format) noexcept
{
	const bool resource =
		// 元形式の閉じた選択
		format == OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER ;
	const bool planBound =
		resource
			? hint.resourceContent && input.resourceContent &&
				  *hint.resourceContent == *input.resourceContent &&
				  validOfficialResourceContentPlan( *hint.resourceContent) &&
				  hint.resourceContent->rootBytes == hint.archiveBytes &&
				  hint.resourceContent->rootSha256 == hint.archiveSha256 &&
				  hint.selectedInfs.size() == 1U && hint.selectedInfs[0].nestedArchive.empty() &&
				  hint.selectedInfs[0].infIdentity == hint.resourceContent->selectedInf
			: !hint.resourceContent && !input.resourceContent ;	// 別形式への計画流用を拒否
	return planBound && activeScanSessionId != 0 && input.scanSessionId == activeScanSessionId &&
		   hint.selectedInfs.size() <= 128U &&
		   std::ranges::all_of(
			   hint.selectedInfs,
			   []( const auto &selector) {
				   return isSafeOfficialArchiveMember( selector.infIdentity, L'\\') &&
						  (selector.nestedArchive.empty() ||
						   isSafeOfficialArchiveMember( selector.nestedArchive, L'\\')) ;
			   }) &&
		   hint.archiveBytes > 0 && hint.archiveBytes <= MAXIMUM_ARCHIVE_BYTES &&
		   input.byteCount == hint.archiveBytes && isLowerHash( hint.indexSha256) &&
		   isLowerHash( hint.recordSha256) && isLowerHash( hint.archiveSha256) &&
		   input.sha256 == hint.archiveSha256 && isLocalInputPath( input.inspectionPath) &&
		   (format == OfficialDriverArchiveFormat::ZIP ||
			format == OfficialDriverArchiveFormat::CABINET ||
			format == OfficialDriverArchiveFormat::SEVEN_ZIP_SFX ||
			format == OfficialDriverArchiveFormat::PE_RESOURCE_CONTAINER) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 索引の期待値と実fileを再照合し、通常の共通内容・署名検査へ接続する
 * @param[in] activeScanSessionId 現在のworker scan session
 * @param[in] hint 呼出し側が選択した元取得archiveの期待identity
 * @param[in] input 呼出し中に変更しない、既存の保護archive入力
 * @param[in] format ZIP、CABINETまたは非実行SEVEN_ZIP_SFX。未対応形式は拒否する
 * @param[out] result 全体完了時だけ通常検査結果を保持する。失敗時は段階・診断だけ
 * @param[in] cancellation 空またはworker内の非blocking取消し照会
 * @return 通常検査完了時0。それ以外は元HRESULT。0件内容合格も完了に含む
 * @pre Inputの保護workspaceは全呼出し中有効であり、入力はresultとaliasしない
 * @note Blockingする。通常policyを維持し、保守根拠・grant・Windows適合・導入へ昇格しない
 */
//------------------------------------------------------------------------------
NativeError inspectIndexedDriverPackage( const ScanSessionId				  activeScanSessionId,
										const IndexedDriverArchiveHint	 &hint,
										const DriverArchiveInput		 &input,
										const OfficialDriverArchiveFormat format,
										IndexedDriverPackageInspection	 &result,
										const std::function<bool()>		 &cancellation)
{
	result = {} ;
	// 不一致hintではfile I/Oや取消しcallbackを開始しない
	if( !matchesIndexedDriverArchiveHint( activeScanSessionId, hint, input, format)) {
		return fail( result, IndexedDriverInspectionState::INPUT_REJECTED,
					static_cast<NativeError>( E_INVALIDARG)) ;
	}

	try {
		// 事前取消しでは署名検査やfile I/Oを開始しない
		if( cancellation && cancellation()) {
			return fail( result, IndexedDriverInspectionState::CANCELLED,
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
		}

		const NativeError identityError = verifyOfficialFileMetadata(
			input.inspectionPath, {hint.archiveBytes, hint.archiveSha256}) ;	// 実byteの共通再照合
		// 呼出し側の文字列一致だけを実入力検査の成功としない
		if( identityError != 0) {
			return fail( result, IndexedDriverInspectionState::INPUT_REJECTED, identityError) ;
		}

		result.inputBound = true ;
		CommonDriverPackageInspection inspection ;			// 通常の全体・個別結果を一時所有する
		NativeError					  inspectionError{} ;	// 選択集合の最初の全体拒否を保持します
		// 元selectorのない従来hintだけは全INFを検査します
		if( hint.selectedInfs.empty()) {
			inspectionError = inspectCommonDriverPackage( input, format, inspection, cancellation) ;
		} else {
			std::vector<std::pair<std::wstring_view, std::wstring_view>>
				selected ;	// 元署名recordの集合だけです
			selected.reserve( hint.selectedInfs.size()) ;
			// arbitrary UI/pathではなく同じhintへ結ばれた元選択だけを渡します
			for( const auto &selector : hint.selectedInfs) {
				selected.emplace_back( selector.nestedArchive, selector.infIdentity) ;
			}

			inspectionError = inspectSelectedDeviceDriverPackages( input, format, selected,
																  inspection, cancellation) ;
		}

		// 全体失敗では一部の内容合格を外へ持ち出さない
		if( inspectionError != 0) {
			return fail( result,
						inspectionError ==
								static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))
							? IndexedDriverInspectionState::CANCELLED
							: IndexedDriverInspectionState::INSPECTION_FAILED,
						inspectionError) ;
		}

		// 合格閉包は同一通常policyで直前再検査する。個別拒否は保持する
		for( const CommonInfInspection &inf : inspection.infs) {
			// 拒否済みINFを成功扱いで再検査へ渡さない
			if( inf.state != CommonInfInspectionState::VERIFIED) {
				continue ;
			}

			// 各署名API前の取消しも全体結果へ反映する
			if( cancellation && cancellation()) {
				return fail( result, IndexedDriverInspectionState::CANCELLED,
							static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
			}

			const NativeError error =
				// 元用途と署名を再確認する
				reverifyCommonDriverInfContent( inf) ;
			// 参照や署名の変更は検査結果全体を失効させる
			if( error != 0) {
				return fail( result, IndexedDriverInspectionState::INSPECTION_FAILED, error) ;
			}
		}

		// 最後の同期検査中に届いた取消しを取りこぼさない
		if( cancellation && cancellation()) {
			return fail( result, IndexedDriverInspectionState::CANCELLED,
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
		}

		const NativeError finalError = verifyOfficialFileMetadata(
			input.inspectionPath, {hint.archiveBytes, hint.archiveSha256}) ;	// 公開直前の原入力照合
		// 再検査の間に原入力が変わった場合は部分結果を破棄する
		if( finalError != 0) {
			return fail( result, IndexedDriverInspectionState::INSPECTION_FAILED, finalError) ;
		}

		result.inspection = std::move( inspection) ;
		result.state	  = IndexedDriverInspectionState::INSPECTION_COMPLETED ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return fail( result, IndexedDriverInspectionState::INSPECTION_FAILED,
					static_cast<NativeError>( E_OUTOFMEMORY)) ;
	} catch( const std::length_error &) {
		return fail( result, IndexedDriverInspectionState::INSPECTION_FAILED,
					static_cast<NativeError>( E_INVALIDARG)) ;
	} catch( ...) {
		// 外部callback例外をworker外へ漏らさず、部分結果も残さない
		return fail( result, IndexedDriverInspectionState::INSPECTION_FAILED,
					static_cast<NativeError>( E_UNEXPECTED)) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 管理者領域の元CABと記録時および実OSのModels全行を照合します
 * @param[in] activeScanSessionId 同取得を所有するworkerのscanです
 * @param[in] hint 同索引行に結び付く元CABと唯一の選択INFです
 * @param[in] input 取得層が管理者領域に固定した元CABです
 * @param[in] proof 原INF・CAT・公式対象・全Modelsの元証拠です
 * @param[out] content 一致した元署名と全参照を持つ非実行検査結果です
 * @param[in] cancellation 同workerの協調取消しです
 * @return 成功時0です。全体又は個別の原診断を保持し、失敗時は出力を空にします
 * @note 本検査は内容の同一性だけを確認します。機器観測と導入許可には別の検証が必要です
 */
//------------------------------------------------------------------------------
NativeError inspectIndexedScopedDriverPackage(
	const ScanSessionId activeScanSessionId, const IndexedDriverArchiveHint &hint,
	const DriverArchiveInput								 &input,
	const signed_index_detail::CollectorScopedModelsEvidence &proof,
	CollectorDriverPackageContent &content, const std::function<bool()> &cancellation)
{
	content				  = {} ;
	constexpr auto format = OfficialDriverArchiveFormat::CABINET ;	// 公式Models照合で受理する元容器
	// 一つの保護済みCAB選択と有界な公式範囲だけを内容検査へ渡す
	if( !matchesIndexedDriverArchiveHint( activeScanSessionId, hint, input, format) ||
	   hint.selectedInfs.size() != 1U ||
	   input.workspaceMode != OfficialWorkspaceMode::ADMINISTRATOR || !proof.models.platform ||
	   proof.models.sections.empty() ||
	   proof.models.sections.size() > OFFICIAL_SCOPED_MODELS_MAX_SECTIONS ||
	   proof.catalog.packageHardwareIds.empty() ||
	   proof.catalog.packageHardwareIds.size() > OFFICIAL_SCOPED_MODELS_MAX_TARGETS) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		const auto &selector = hint.selectedInfs.front() ;	// 取得時に固定した一件のINF指定
		// 元SHA-256、容量、相対位置が署名索引から変わった場合は展開しない
		if( input.byteCount != proof.archiveBytes ||
		   input.sha256 != scopedHashText( proof.archiveSha256) ||
		   selector.nestedArchive != scopedMemberPath( proof.nestedArchiveIdentity) ||
		   selector.infIdentity != scopedMemberPath( proof.infIdentity)) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		std::vector<std::wstring> hardwareIds ;	// 同じ元公式明細をWindows文字形式で保持
		hardwareIds.reserve( proof.catalog.packageHardwareIds.size()) ;
		// 公式に掲載された完全IDを欠落や並べ替えなしで渡す
		for( const auto &id : proof.catalog.packageHardwareIds) {
			hardwareIds.emplace_back( id.begin(), id.end()) ;
		}

		const auto catalogHash = scopedHashText( proof.catalogSha256) ;	// 同じ選択の元CATの全SHA-256
		// 元CATとINFのダイジェストで一意なModels読取りに結ぶ要求
		const OfficialInfScopedModelsRequest request{.platform		= &*proof.models.platform,
													 .hardwareIds	= hardwareIds,
													 .infSha256		= proof.models.infSha256,
													 .cancellation	= &cancellation,
													 .catalogSha256 = catalogHash} ;
		// 同期中だけ借用する元アーカイブとINFの一組の位置
		const std::array			  selected{std::pair<std::wstring_view, std::wstring_view>{
			 selector.nestedArchive, selector.infIdentity}} ;
		CollectorDriverPackageContent inspected ;	// 全検査に成功するまで公開しない仮の保護閉包
		// 元内容検査から順に結果を保持し、最初の失敗を返す
		auto error = inspectCollectorDriverPackageContent( input, format, selected, inspected,
														  cancellation, &request) ;
		// 元内容検査に失敗した閉包へ索引の資格を与えない
		if( error != 0) {
			return error ;
		}

		error = matchIndexedScopedContent( activeScanSessionId, hint, proof, inspected) ;
		// 元索引が示す同じ閉包だけを現在Windowsの観測へ進める
		if( error != 0) {
			return error ;
		}

		// 配布側の明示観測が揃っても、現在Windowsによる元節の選択を省略しません
		const auto					   &inf = inspected.infs.front() ;
		OfficialInfScopedModelsEvidence current ;	// 現在Windowsが選択した同じ元INFの全Models節
		error =
			readOfficialInfScopedModels( *inf.workspace, inf.infRelativePath, proof.models.infSha256,
										nullptr, hardwareIds, current, cancellation) ;
		// 現在Windowsが選ぶ節と元索引の証拠が異なる場合は閉包を破棄する
		if( error != 0 || !sameScopedModels( proof.models, current)) {
			return error != 0 ? error : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// 検査後の取消しも結果の引渡しを止める
		if( cancellation && cancellation()) {
			return static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED)) ;
		}

		error = verifyOfficialFileMetadata( input.inspectionPath,
										   {hint.archiveBytes, hint.archiveSha256}) ;
		// 検査中に元CABが変わった場合は部分結果を引き渡さない
		if( error != 0) {
			return error ;
		}

		content = std::move( inspected) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		return static_cast<NativeError>( E_UNEXPECTED) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ公式範囲の保護閉包を元ファイルとCAT所属から再検査します
 * @param[in] activeScanSessionId 元CABの取得を所有するworker scanです
 * @param[in] hint 元取得時のCABと選択INFです
 * @param[in] proof 認証済み元レコードに結び付く元INFとCATの証拠です
 * @param[in] content 同取得が保持した全参照付きの検査結果です
 * @return 同じ保護閉包、全ファイルの長さとhash、全CATの署名と所属の再確認に成功した場合0です
 * @pre 呼出し側が同じ元CABと有効な元署名レコードを再確認します
 * @note この関数はファイルの読取りだけを行い、端末適用性や導入資格を作りません
 */
//------------------------------------------------------------------------------
NativeError reverifyIndexedScopedDriverPackage(
	const ScanSessionId activeScanSessionId, const IndexedDriverArchiveHint &hint,
	const signed_index_detail::CollectorScopedModelsEvidence &proof,
	const CollectorDriverPackageContent						 &content)
{
	try {
		// 保護済み閉包と元索引の同一性を先に照合した結果
		const auto matched = matchIndexedScopedContent( activeScanSessionId, hint, proof, content) ;
		// 元の内容・選択が変わった閉包のファイルは開かない
		if( matched != 0) {
			return matched ;
		}

		const auto &inf	 = content.infs.front() ;			// 照合済みの選択INFと保護閉包
		const auto &root = inf.closure.packages.front() ;	// 署名索引が指定した基本INFの構造
		// 署名索引の一意な元選択と同じ表記で保持したINFの実エントリ
		const auto	originalInf = std::ranges::find( inf.closure.entries, root.infRelativePath,
													&OfficialZipEntry::relativePath) ;
		// 選択INFの元表記と実ファイルのハッシュを署名索引へ結ぶ
		if( originalInf == inf.closure.entries.end() ||
		   originalInf->sha256 != proof.models.infSha256) {
			return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
		}

		// 保護閉包の全エントリを元長さと元SHA-256へ再照合する
		for( const auto &entry : inf.closure.entries) {
			// 完全ハッシュがない場合は実ファイル照合の根拠がない
			if( !isLowerHash( entry.sha256)) {
				return static_cast<NativeError>( E_ACCESSDENIED) ;
			}

			// エントリ自身の元表記で開いたファイルの再検査結果
			const auto error = verifyOfficialFileMetadata( inf.workspace->path( entry.relativePath),
														  {entry.uncompressedSize, entry.sha256}) ;
			// 一件でも不一致なら、その元HRESULTで全閉包の署名再検査を止める
			if( error != 0) {
				return error ;
			}
		}

		// 同期中の保護閉包を借用し、各INF宣言が指す全元エントリの存在と署名・所属を確認する
		const auto verifyPackage = [&inf]( const OfficialInfPackage &package) -> NativeError {
			const auto missing = [&inf]( const std::wstring_view path) {
				return findScopedArchiveMember( inf.closure.entries, path) == nullptr ;
			} ; // 同じ閉包内で一意に解決できない宣言を検出する
			// 参照の欠落や曖昧な位置をWindowsの署名検査へ渡さない
			if( missing( package.infRelativePath) || missing( package.catalogRelativePath) ||
			   std::ranges::any_of( package.sourceFiles, missing)) {
				return static_cast<NativeError>( E_ACCESSDENIED) ;
			}

			return verifyWindowsInfPackageIntegrity( *inf.workspace, package) ;
		} ;
		auto error = verifyPackage( root) ;	// 基本INFと必須INFの最初の検査失敗を保持する値
		// 基本INFの署名と所属が成立した場合だけ必須INFへ進む
		if( error != 0) {
			return error ;
		}

		// 元参照で到達した全必須INFの署名と所属を一件ずつ検査する
		for( const auto &required : inf.requiredInfPackages) {
			error = verifyPackage( required) ;
			// 閉包を構成する必須INFの失敗も基本INFと同じ条件で拒否する
			if( error != 0) {
				return error ;
			}
		}

		return 0 ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace drivercrate
