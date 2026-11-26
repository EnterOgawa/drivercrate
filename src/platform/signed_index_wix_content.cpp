//------------------------------------------------------------------------------
/**
 * @file signed_index_wix_content.cpp
 * @brief 署名索引のWiX内容証拠を同じ元配布の実ファイルへ照合する
 * @version 01.01.00
 * @date 2026/11/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/23  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/23  保護された元規約の再照合と本文取得を追加
 * </pre>
 *
 * @note 所有workerの通常署名検査が成功した同じ保護領域だけを移し、途中失敗時は一時領域を回収する
 * @see docs/adr/0572-signed-wix-burn-driver-content.md
 */
//------------------------------------------------------------------------------

#include "platform/signed_index_wix_content.h"

#include "platform/client_min_build_scope.h"
#include "platform/official_download_workspace.h"
#include "platform/official_driver_closure.h"
#include "platform/official_driver_package.h"
#include "platform/official_file_verifier.h"
#include "platform/official_mapped_file.h"
#include "platform/official_rtf_terms.h"
#include "platform/official_wix_package.h"
#include "platform/official_zip.h"
#include "platform/signed_index_manifest.h"
#include "platform/signed_index_records.h"
#include "platform/windows_product_type.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {

//------------------------------------------------------------------------------
// 定数定義
//------------------------------------------------------------------------------

constexpr NativeError INVALID_CONTENT =
	// 元形式の欠落又は不整合
	HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;
constexpr NativeError BAD_DIGEST =
	// 元ハッシュ又はサイズの不一致
	static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
constexpr NativeError	CANCELLED = HRESULT_FROM_WIN32( ERROR_CANCELLED) ;	// 利用者の協調取消し
constexpr std::uint64_t MAX_WIX_TERMS_BYTES =
	1024U * 1024U ;	// 一取得で表示用に読む全言語の元最大bytes

//------------------------------------------------------------------------------
// 内部関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 成立しない検査の診断値を同期検査の終端へ送る
 * @param[in] error 0の場合は検査を続行する
 * @throws NativeError 0以外の元診断値
 */
//------------------------------------------------------------------------------
void check( const NativeError error)
{
	// 途中の保護領域を外へ移さず、最初の診断を返す
	if( error != 0) {
		throw error ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief Win32の失敗直後の最終診断をHRESULTへ変換する
 * @return 失敗時のWin32由来HRESULT。診断値が得られない場合はE_UNEXPECTED
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError lastWin32Failure() noexcept
{
	const auto error = GetLastError() ;	// 直前に失敗したAPIの元DWORD
	return error == ERROR_SUCCESS ? static_cast<NativeError>( E_UNEXPECTED)
								  : static_cast<NativeError>( HRESULT_FROM_WIN32( error)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同操作の取消しを保護領域の引渡し前に確認する
 * @param[in] cancellation 所有workerが同期して呼ぶ協調取消し。空を許す
 * @throws NativeError 停止が要求された場合はERROR_CANCELLEDのHRESULT
 * @throws ... 取消し関数から送出された元例外
 */
//------------------------------------------------------------------------------
void checkCancellation( const PreparationCancellation &cancellation)
{
	// 取消し後は結果を合成せず、ローカルの保護領域を回収する
	if( cancellation && cancellation()) {
		throw CANCELLED ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 索引のUTF-8原文字列を元表記のままWindowsの照合値へ変換する
 * @param[in] value Codecが検証した非空の元文字列
 * @return 変換済みの所有UTF-16文字列
 * @throws NativeError 長さ、UTF-8又は変換の不成立
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring widen( const std::string_view value)
{
	// 正確な元文字列をWindowsの明示長で読み、埋込み終端を使わせない
	if( value.empty() ||
	   value.size() > static_cast<std::size_t>( (std::numeric_limits<int>::max)()) ||
	   value.find( '\0') != value.npos) {
		throw INVALID_CONTENT ;
	}

	const auto inputLength = static_cast<int>( value.size()) ;	// 変換する全UTF-8 byte数
	const auto length	   = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
												 inputLength, nullptr, 0) ;	// 必要なUTF-16要素数
	// 変換不能な文字列を別の照合値で補完しない
	if( length == 0) {
		throw lastWin32Failure() ;
	}

	std::wstring output( static_cast<std::size_t>( length), L'\0') ;	// 元文字列を所有する変換先
	// 要求した全要素を出力できた場合だけ照合に使う
	if( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), inputLength, output.data(),
						   length) != length) {
		throw lastWin32Failure() ;
	}

	return output ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows検証の小文字hexを索引の元32byte SHA-256へ照合する
 * @param[in] observed 取得又は展開の検証で得た小文字64桁のSHA-256
 * @param[in] expected 署名索引の元証拠にあるSHA-256
 * @return 全桁が同じ元値を表す場合だけtrue
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesDigest( const std::wstring_view	observed,
								 const IndexManifestSha256 &expected) noexcept
{
	// 欠けた桁を補完せず全32byteとの比較に限定する
	if( observed.size() != 2U * expected.size()) {
		return false ;
	}

	constexpr std::wstring_view DIGITS = L"0123456789abcdef" ;	// 4bitの小文字表記
	std::size_t					index{} ;						// 比較する次のhex桁位置
	// 各byteを元順に上位桁と下位桁へ照合する
	for( const auto byte : expected) {
		// 一桁でも不一致なら元ハッシュを認めない
		if( observed[index] != DIGITS[byte >> 4U] || observed[index + 1U] != DIGITS[byte & 15U]) {
			return false ;
		}

		index += 2U ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保護領域に保持する直下の実ファイルサイズを合計する
 * @param[in] workspace 共通WiX検査が所有する初期化済み領域
 * @param[in] member 直下にある既知ファイルの相対名
 * @param[in] maximumFiles 共通展開上限から得た正の最大件数
 * @param[in] maximumBytes 共通展開上限から得た正の合計byte数上限
 * @param[in] cancellation 同じ検査操作の協調取消し
 * @return 元領域内に残っている全ファイルの正確な合計byte数
 * @throws NativeError 中止、未知階層、非通常ファイル、列挙失敗又は有限上限超過
 * @note 列挙結果は保持量の計上に使用する。内容証拠は元取得と共通検査から得る
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t measureWorkspace( const OfficialDownloadWorkspace &workspace,
											 const std::wstring_view		  member,
											 const std::size_t				  maximumFiles,
											 const std::uint64_t			  maximumBytes,
											 const PreparationCancellation	 &cancellation)
{
	auto	   root		 = workspace.path( member) ;	// 既知の保持ファイルから得る保護領域内の絶対path
	const auto separator = root.rfind( L'\\') ;			// 保護領域の直下にある葉との境界
	check( separator != root.npos && member.find( L'\\') == member.npos ? 0 : INVALID_CONTENT) ;
	root.resize( separator) ;
	const auto attributes = GetFileAttributesW( root.c_str()) ;	// 保護領域の直接の位置と種別
	// 消失や権限異常で測れない領域を成功へ変換しない
	if( attributes == INVALID_FILE_ATTRIBUTES) {
		throw lastWin32Failure() ;
	}

	check( (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ==
				  FILE_ATTRIBUTE_DIRECTORY
			  ? 0
			  : INVALID_CONTENT) ;
	const auto		 pattern = root + L"\\*" ;	// 保持領域の直下だけを列挙するWin32パターン
	WIN32_FIND_DATAW entry{} ;					// Windowsが返す今回の葉と元ファイルサイズ
	const auto		 found =
		// 成功時のみFindCloseで回収するhandle
		FindFirstFileW( pattern.c_str(), &entry) ;
	// 空又は参照できない領域に対し、ゼロbyteの成功を返さない
	if( found == INVALID_HANDLE_VALUE) {
		throw lastWin32Failure() ;
	}

	const std::unique_ptr<void, decltype( &FindClose)> listing( found,
															  &FindClose) ;	// 列挙の所有handle
	std::size_t										  count{} ;				// 計上した通常ファイル数
	std::uint64_t									  total{} ;				// 計上した通常ファイルの合計byte数
	// 直下の全ファイルを数え、再解析点や未知階層と上限超過で停止する
	do {
		checkCancellation( cancellation) ;
		const std::wstring_view name{entry.cFileName} ;	// Win32が終端する元の葉名
		// OSが返す現在と親の参照を算入しない
		if( name == L"." || name == L"..") {
			continue ;
		}

		check( (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT |
										 FILE_ATTRIBUTE_DEVICE)) == 0U
				  ? 0
				  : INVALID_CONTENT) ;
		check( ++count <= maximumFiles ? 0 : HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
		const auto bytes = (static_cast<std::uint64_t>( entry.nFileSizeHigh) << 32U) |
						   entry.nFileSizeLow ;	// 展開実ファイルの完全な64bit長
		check( bytes <= maximumBytes - total ? 0 : HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
		total += bytes ;
	} while( FindNextFileW( listing.get(), &entry)) ;

	// 正常な列挙終了のときだけ完全なbyte数として扱う
	if( GetLastError() != ERROR_NO_MORE_FILES) {
		throw lastWin32Failure() ;
	}

	check( count != 0U ? 0 : INVALID_CONTENT) ;
	return total ;
}

//------------------------------------------------------------------------------
/**
 * @brief 選択した元Models節の完全Hardware IDを元順の索引証拠へ照合する
 * @param[in] expected 署名索引の原Models節名と公開ID
 * @param[in] actual 同一INFを現在の対象Windows tupleで読み取った全Models節
 * @param[in] cancellation 同じ検査操作の協調取消し
 * @throws NativeError 取消し又は元節・ClassGUID・IDの不一致
 * @note PnP端末を列挙せず、元INFと公開IDだけを照合する
 */
//------------------------------------------------------------------------------
void checkPublishedModels( const IndexPublishedIdentityEvidence &expected,
						  const OfficialInfPublishedIdentity   &actual,
						  const PreparationCancellation		   &cancellation)
{
	const auto classGuid   = widen( expected.classGuid) ;		// 検査対象の原ClassGUID
	const auto sectionName = widen( expected.modelSection) ;	// 選択した原Models節
	const auto section	   = std::ranges::find(
		actual.models, sectionName,
		&OfficialInfPublishedModelSection::modelSection) ;	// 同じWindowsが選択した一節
	check( CompareStringOrdinal( actual.classGuid.c_str(), -1, classGuid.c_str(), -1, TRUE) ==
					  CSTR_EQUAL &&
				  section != actual.models.end()
			  ? 0
			  : INVALID_CONTENT) ;
	std::size_t index{} ;	// 次に照合する元の完全Hardware ID位置
	// 収集と同じ規則で元Hardware欄の完全IDだけを元順に照合する
	for( const auto &hardwareId : section->hardwareIds) {
		checkCancellation( cancellation) ;
		// ワイルドカードの元Hardware IDはv8の完全一致に使わない
		if( hardwareId.find( L'*') != hardwareId.npos) {
			continue ;
		}

		check( index < expected.pnpIds.size() && isExactWixHardwareId( expected.pnpIds[index]) &&
					  hardwareId == widen( expected.pnpIds[index].value)
				  ? 0
				  : INVALID_CONTENT) ;
		++index ;
	}

	check( index != 0U && index == expected.pnpIds.size() ? 0 : INVALID_CONTENT) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 封印済みWiX配布をv8索引の元規約、INFのModelsとドライバー閉包へ照合する
 * @param[in] original 検証済み署名索引から借用する同一v8レコード
 * @param[in] input 同じ配布の保護された元EXEと取得ハッシュ。呼出し中に所有者を保持する
 * @param[in] platform 同スキャンのWindowsクライアントの完全な元観測
 * @param[in] cancellation 同操作の協調取消し。空の場合は取消しを要求しない
 * @param[out] content 全照合が成功した場合だけ移す二つの保護領域と検査結果。失敗時は空
 * @param[out] retainedBytes 二つの領域で保持する実ファイルの合計byte数。元EXEは含まず失敗時は0
 * @return 成功時0、取消し、入出力、信頼又は内容の照合が不成立の場合はHRESULT
 * @throws ... 取消し関数から送出された元例外
 * @pre 呼出workerがCOMを初期化し、元索引と元取得の有効性を確認する
 * @note 通常Windows署名検証を使い、EXEやMSIを実行せず、端末適用性、規約同意や導入許可を発行しない
 */
//------------------------------------------------------------------------------
NativeError inspectSignedIndexWixContent( const IndexDistributionRecord &original,
										 const DriverArchiveInput	   &input,
										 const WindowsHostPlatform	   &platform,
										 const PreparationCancellation &cancellation,
										 OfficialWixDriverContent	   &content,
										 std::uint64_t				   &retainedBytes)
{
	content		  = {} ;
	retainedBytes = 0U ;
	try {
		checkCancellation( cancellation) ;
		const auto &descriptor = original.acquisitionDescriptor ;		// 同じ元EXEの取得と内側CATの署名者
		const auto &source	   = original.packageEvidence ;				// 元配布の実ハッシュとサイズ
		const auto &identity   = original.publishedIdentityEvidence ;	// 同じ元INFとModelsの申告
		check( original.recordSchemaVersion == 8U && original.wixContentEvidence && descriptor &&
					  descriptor->format == IndexPayloadFormat::WIX_BURN_V3 &&
					  descriptor->publisher.value &&
					  original.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
					  identity.state == IndexEvidenceState::PUBLISHED &&
					  identity.kind == IndexIdentityEvidenceKind::INF && identity.evidenceSha256 &&
					  identity.nestedArchiveIdentity.empty() && source.size.value &&
					  source.calculatedHash.sha256 && input.scanSessionId != 0U &&
					  !input.inspectionPath.empty() && !input.resourceContent
				  ? 0
				  : INVALID_CONTENT) ;
		check( input.byteCount != 0U && input.byteCount == *source.size.value &&
					  matchesDigest( input.sha256, *source.calculatedHash.sha256)
				  ? 0
				  : BAD_DIGEST) ;
		const auto host =
			matchWixIndexHost( original, {WindowsHostObservationState::OBSERVED,
										 platform}) ;	// 同scanの観測で対象範囲を確認する
		// 不明又は対象外のWindows観測から実ファイルの検査へ進まない
		if( host.state != IndexHostGateState::ALLOW_UNVERIFIED) {
			return host.error != 0 ? host.error : INVALID_CONTENT ;
		}

		const auto &proof = *original.wixContentEvidence ;	// 元の順序を保持した型付き配布証拠
		std::deque<std::wstring> strings ;					// 同期検査中に参照を保つWiX選択子の文字列所有領域
		const auto retain = [&strings]( const std::string_view value) -> std::wstring_view {
			strings.push_back( widen( value)) ;
			return strings.back() ;
		} ; // 要素を追加しても借用中の既存文字列を移動しない
		const auto member = [&retain]( const IndexWixMember &value) -> OfficialWixMemberSelector {
			return {retain( value.id), retain( value.cabinetMember), retain( value.filePath)} ;
		} ; // 元の三属性を同期検査へ渡す
		std::vector<std::wstring_view> publishers ;	// 署名索引が許可した外側EXEの署名者
		publishers.reserve( proof.acceptedPublishers.size()) ;
		// 外側の許可リストを内側CATの署名者とは独立して保持する
		for( const auto &publisher : proof.acceptedPublishers) {
			checkCancellation( cancellation) ;
			publishers.push_back( retain( publisher)) ;
		}

		std::vector<OfficialWixMsiSelector> packages ;	// 原Chain順で照合する全MSI
		packages.reserve( proof.packages.size()) ;
		// 元Chainの条件を評価せず、属性とMSI実値を同じ順序で照合する
		for( const auto &package : proof.packages) {
			checkCancellation( cancellation) ;
			packages.push_back( {member( package.member), retain( package.installCondition),
								package.amd64 ? OfficialWixMsiArchitecture::AMD64
											  : OfficialWixMsiArchitecture::X86,
								package.language}) ;
		}

		std::vector<OfficialWixMemberSelector> licenses ;	// 元言語の順序を保つRTFの指定
		licenses.reserve( proof.licenses.size()) ;
		// 規約の言語付き元証拠を元マニフェストの役割へ結ぶ
		for( const auto &license : proof.licenses) {
			checkCancellation( cancellation) ;
			licenses.push_back( member( license.member)) ;
		}

		std::vector<OfficialWixDriverFile> files ;	// 内側の元Fileキーと論理ファイル名の全対応
		files.reserve( proof.driverFiles.size()) ;
		// 元選択の順序と大文字小文字を保持し、全AMD64から同じ内容を抽出させる
		for( const auto &file : proof.driverFiles) {
			checkCancellation( cancellation) ;
			files.push_back( {retain( file.cabinetMember), retain( file.targetName)}) ;
		}

		const auto infName = retain( identity.infIdentity) ;	// 同じ元証拠に結ぶ単一INFの完全名
		const OfficialWixDriverSelection			selection{retain( proof.streamName), files,
													  infName} ;	// 内側CABの元選択
		constexpr std::array<std::wstring_view, 1U> CLASSES{
			L"SCSIAdapter"} ;	// 現行WiX収集と同じ内容検査Class
		const auto policy =
			// 共通の展開と非実行INF検査の有限上限
			makeOfficialWixInspectionPolicy( CLASSES) ;
		const OfficialWixPackageRequest request{
			// 封印済み元バイトと元用途をWindowsの通常署名検査へ渡す
			{input.inspectionPath, input.byteCount, input.sha256, publishers, false},
			input.scanSessionId,
			input.workspaceMode,
			packages,
			licenses} ;
		OfficialWixDriverContent
			inspected ;	// 元ハッシュ・全署名・内容の一致までこの呼出し内で所有する
		checkCancellation( cancellation) ;
		const auto inspection =
			inspectOfficialWixDriverContent( request, policy.package, selection, policy.driver,
											inspected) ;	// 同じEXEの実サイズとSHA-256も検証する
		checkCancellation( cancellation) ;
		check( inspection) ;
		check( inspected.windowsInfPolicyVerified && inspected.package.workspace &&
					  inspected.package.workspace->protectionMode() == input.workspaceMode &&
					  inspected.driverWorkspace &&
					  inspected.driverWorkspace->protectionMode() == input.workspaceMode &&
					  !inspected.package.databases.empty() &&
					  inspected.package.databases.size() == packages.size() &&
					  inspected.package.licenses.size() == licenses.size() &&
					  inspected.closure.packages.size() == 1U &&
					  inspected.closure.entries.size() == files.size()
				  ? 0
				  : INVALID_CONTENT) ;

		// 表示する言語順の全RTFを元役割と原バイトのサイズ・SHA-256へ照合する
		for( std::size_t index = 0U; index < licenses.size(); ++index) {
			checkCancellation( cancellation) ;
			const auto &expected = proof.licenses[index] ;				// 同じ順序の言語別原規約
			const auto &actual	 = inspected.package.licenses[index] ;	// 共通検査が保持した原RTF
			check( actual.relativePath == licenses[index].cabinetMember &&
						  actual.uncompressedSize == expected.sizeBytes &&
						  matchesDigest( actual.sha256, expected.sha256)
					  ? 0
					  : BAD_DIGEST) ;
		}

		// INF・CAT・全参照ファイルを元論理名の順序、実サイズとSHA-256へ照合する
		for( std::size_t index = 0U; index < files.size(); ++index) {
			checkCancellation( cancellation) ;
			const auto &expected = proof.driverFiles[index] ;	// 同じ元File対応の原閉包証拠
			const auto &actual =
				inspected.closure.entries[index] ;	// 全AMD64で一致した一件の実ファイル
			check( actual.relativePath == files[index].targetName &&
						  actual.uncompressedSize == expected.sizeBytes &&
						  matchesDigest( actual.sha256, expected.sha256)
					  ? 0
					  : BAD_DIGEST) ;
		}

		const auto &driver =
			// 通常のWindows CAT検証を通過した元INF
			inspected.closure.packages.front() ;
		const auto inf =
			std::ranges::find( inspected.closure.entries, infName,
							  &OfficialZipEntry::relativePath) ;	// 一意に選択した元INFの実バイト証拠
		check( driver.infRelativePath == infName && inf != inspected.closure.entries.end() &&
					  matchesDigest( inf->sha256, *identity.evidenceSha256)
				  ? 0
				  : BAD_DIGEST) ;
		check( original.version.value && driver.driverVersion == widen( *original.version.value)
				  ? 0
				  : INVALID_CONTENT) ;

		checkCancellation( cancellation) ;
		OfficialInfPublishedIdentity models ;	// 同端末の現在OSが元INFから選択する公開Models
		check( readOfficialInfPublishedIdentity( *inspected.driverWorkspace, driver, models)) ;
		checkCancellation( cancellation) ;
		check( models.infSha256 == inf->sha256 ? 0 : BAD_DIGEST) ;
		checkPublishedModels( identity, models, cancellation) ;

		std::wstring publisher ;	// 同じ元INF・CATを再照合して読んだ実DigitalSigner
		checkCancellation( cancellation) ;
		check( readWindowsInfPackagePublisher( *inspected.driverWorkspace, driver, publisher)) ;
		checkCancellation( cancellation) ;
		check( publisher == widen( *descriptor->publisher.value)
				  ? 0
				  : static_cast<NativeError>( TRUST_E_SUBJECT_NOT_TRUSTED)) ;

		// 外側の二つのCAB、マニフェスト、元MSIと複写、全規約の実保持量を計上する
		const auto &cabinet	   = policy.package.cabinet ;	// 外側の各CABに適用済みの共通上限
		const auto	outerBytes = measureWorkspace(
			 *inspected.package.workspace, inspected.package.databases.front().file.relativePath,
			 2U * static_cast<std::size_t>( cabinet.maximumEntryCount),
			 input.byteCount + 3U * cabinet.maximumTotalExpandedBytes +
				 cabinet.maximumSingleFileBytes,
			 cancellation) ;	// 元EXE中の二つのCABと別々に展開したファイルの合計長
		const auto closureBytes =
			measureWorkspace( *inspected.driverWorkspace, infName, inspected.closure.entries.size(),
							 policy.driver.maximumClosureBytes,
							 cancellation) ;	// 元CATの検査を終えて保持するドライバー閉包の合計長
		check( closureBytes == inspected.closure.expandedBytes ? 0 : INVALID_CONTENT) ;
		checkCancellation( cancellation) ;
		content		  = std::move( inspected) ;
		retainedBytes = outerBytes + closureBytes ;
		return 0 ;
	} catch( const NativeError error) {
		return error ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じWiX保護領域の各言語の元規約を再照合し、表示用の全文を作る
 * @param[in] original 同じ取得と検査に対応する認証済み元v8レコードです
 * @param[in] content 元署名とINFを確認済みの所有内容です。同期呼出しの間は解放できません
 * @param[in] cancellation 同操作の協調取消しです。空の場合は取消しを要求しません
 * @param[out] documents 元の言語順で全件を返します。一件でも失敗した場合は空です
 * @return 全原バイトと本文の確認成功0、失敗時は元I/O、形式、信頼又は取消しのHRESULT
 * @throws ... 取消し関数が送出する元例外
 * @note 表示に使う文字列だけを返します。元期限・機器の確定と同意は呼出し側で別に行います
 */
//------------------------------------------------------------------------------
NativeError readSignedIndexWixTerms( const IndexDistributionRecord  &original,
									const OfficialWixDriverContent &content,
									const PreparationCancellation  &cancellation,
									std::vector<WixTermsDocument>  &documents)
{
	documents.clear() ;
	try {
		checkCancellation( cancellation) ;
		check( original.recordSchemaVersion == 8U && original.wixContentEvidence &&
					  content.windowsInfPolicyVerified && content.package.workspace
				  ? 0U
				  : INVALID_CONTENT) ;
		const auto &licenses = original.wixContentEvidence->licenses ;	// 同じ元署名の言語順です
		const auto &package	 = content.package ;						// 先に検査した保護領域を同期処理中だけ借用します
		check( !licenses.empty() && licenses.size() == package.licenses.size() ? 0U
																			  : INVALID_CONTENT) ;

		std::uint64_t remaining = MAX_WIX_TERMS_BYTES ;	// 全元規約を合わせた残り読取り枠です
		std::vector<WixTermsDocument> verified ;		// 全言語が表示可能な場合だけ呼出し側へ移します
		verified.reserve( licenses.size()) ;
		// 元順で固定した全規約を再読取りし、別メンバーや途中までの本文を表示しない
		for( std::size_t index{}; index < licenses.size(); ++index) {
			checkCancellation( cancellation) ;
			const auto &expected = licenses[index] ;			// 元言語別の役割、完全長とSHA-256です
			const auto &entry	 = package.licenses[index] ;	// 一回目の展開で得た同じ元RTFです
			check( expected.sizeBytes != 0U && expected.sizeBytes <= remaining
					  ? 0U
					  : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE))) ;
			check( entry.relativePath == widen( expected.member.cabinetMember) &&
						  entry.uncompressedSize == expected.sizeBytes &&
						  matchesDigest( entry.sha256, expected.sha256)
					  ? 0U
					  : BAD_DIGEST) ;
			const auto path =
				// 元保護領域の同じファイルです
				package.workspace->path( entry.relativePath) ;
			OfficialMappedFile mapping ;	// 照合から変換が終わるまで書込みと置換を拒否します
			check( mapping.open( path, expected.sizeBytes)) ;
			check( verifyOfficialFileMetadata( path, {expected.sizeBytes, entry.sha256})) ;
			WixTermsDocument document{widen( expected.locale),
									  {}} ;	// 元言語名と検査した全文を所有します
			check( decodeOfficialRtfTerms( mapping.bytes(), document.body)
					  ? 0U
					  : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED))) ;
			remaining -= expected.sizeBytes ;
			verified.push_back( std::move( document)) ;
		}

		checkCancellation( cancellation) ;
		documents = std::move( verified) ;
		return 0U ;
	} catch( const NativeError error) {
		return error ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace drivercrate
