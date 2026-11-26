//------------------------------------------------------------------------------
/**
 * @file official_wix_package.cpp
 * @brief 署名済み元WiX配布と外側CAB、MSI、規約の原内容を照合する
 * @version 01.02.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/11/23  全AMD64 MSIの元ドライバーを比較して共通CAT検査へ接続
 * Ver.01.02.00 Shunji Ogawa  2026/11/23  外側と内側の非実行WiX検査条件を共通化
 * </pre>
 *
 * @note 元ファイルを固定して読み取り、全照合成功まで一時出力をworker外へ渡さない
 * @see docs/adr/0572-signed-wix-burn-driver-content.md
 */
//------------------------------------------------------------------------------
#include "platform/official_wix_package.h"

#include "platform/official_catalog_validation.h"
#include "platform/official_file_verifier.h"
#include "platform/official_mapped_file.h"
#include "platform/official_msi.h"

#include <Windows.h>
#include <wintrust.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

constexpr std::wstring_view MANIFEST			   = L"0" ;						// 起動用CABの固定マニフェスト名
constexpr std::wstring_view UX_CABINET			   = L"ux.cab" ;				// 読取り用の起動CAB一時名
constexpr std::wstring_view ATTACHED_CABINET	   = L"attached.cab" ;			// 読取り用の添付CAB一時名
constexpr std::uint64_t		MAXIMUM_MANIFEST_BYTES = 65536U ;					// UTF-8の元XMLだけに適用する上限
constexpr NativeError INVALID_DATA = HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;	// 不明・不整合な内容

//------------------------------------------------------------------------------
/**
 * @brief 内部同期検査の失敗を元診断で終端へ送る
 * @param[in] error 検査結果。0の場合は処理を継続する
 * @throws NativeError 0以外の元エラー
 */
//------------------------------------------------------------------------------
void				  check( const NativeError error)
{
	// 一件でも不成立なら途中の所有結果を外へ渡さない
	if( error != 0U) {
		throw error ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 固定した元のbyte列を保護領域の新規ファイルに複写する
 * @param[in,out] workspace 新規ファイルと失敗後の回収を追跡する領域
 * @param[in] name 検査側が定める安全な一時相対名
 * @param[in] bytes 複写完了まで借用する元の通常ファイル内容
 * @throws NativeError 上限、書込み、長さまたはcloseの失敗
 */
//------------------------------------------------------------------------------
void writeNewFile( OfficialDownloadWorkspace &workspace, const std::wstring_view name,
				  const std::span<const std::byte> bytes)
{
	check( bytes.empty() || bytes.size() > std::numeric_limits<DWORD>::max()
			  ? static_cast<NativeError>( E_INVALIDARG)
			  : 0U) ;
	HANDLE output{INVALID_HANDLE_VALUE} ;	// 作成から閉じるまで所有するファイルhandle
	check( workspace.createFile( name, output)) ;
	DWORD		written{} ;	// WriteFileが確定した実byte数
	const BOOL	saved = WriteFile( output, bytes.data(), static_cast<DWORD>( bytes.size()), &written,
								  nullptr) ;							// 同期書込み結果
	const DWORD writeError = saved ? ERROR_SUCCESS : GetLastError() ;	// close前の元の診断値
	const BOOL	closed	   = CloseHandle( output) ;						// 後続の読取り専用固定へ移れるか
	// 書込みを完了できなければclose診断で元の失敗を隠さない
	if( !saved || written != bytes.size()) {
		check( HRESULT_FROM_WIN32( writeError == ERROR_SUCCESS ? ERROR_WRITE_FAULT : writeError)) ;
	}

	// 出力を閉じるまでこのファイルの検査を開始しない
	if( !closed) {
		check( HRESULT_FROM_WIN32( GetLastError())) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元配布のCAB範囲を保護領域へ複写し、複写内容と元範囲を固定して照合する
 * @param[in,out] workspace 元と同じ内容のCABの一時ファイルを所有する領域
 * @param[in] name 一時領域内だけのCABの固定名
 * @param[in] bytes 元EXEと同じ固定範囲のCAB全体
 * @param[in] maximumBytes 署名検査と別に適用するCABの格納長上限
 * @param[in,out] mapping 成功後、CAB処理が終わるまで複写を固定する所有者
 * @return 固定済み一時CABの絶対path
 * @throws NativeError 複写、固定または元内容との照合失敗
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring stageCabinet( OfficialDownloadWorkspace		&workspace,
										const std::wstring_view			 name,
										const std::span<const std::byte> bytes,
										const std::uint64_t				 maximumBytes,
										OfficialMappedFile				&mapping)
{
	check( bytes.size() > maximumBytes ? HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) : 0U) ;
	writeNewFile( workspace, name, bytes) ;
	auto path = workspace.path( name) ;	// 読取り専用のCAB処理へ渡す同じ一時ファイル
	check( mapping.open( path, maximumBytes)) ;
	check( std::ranges::equal( bytes, mapping.bytes()) ? 0U : TRUST_E_BAD_DIGEST) ;
	return path ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAB内の大文字小文字を含む元名から一意な情報を取得する
 * @param[in] entries 共通CAB検査済みで重複を含まない一覧
 * @param[in] name 元マニフェストまたは検査側が指定した正規名
 * @return 呼出し中だけ借用する一致項目
 * @throws NativeError 必須メンバーが見つからない場合
 */
//------------------------------------------------------------------------------
[[nodiscard]] const OfficialZipEntry &findEntry( const std::span<const OfficialZipEntry> entries,
												const std::wstring_view					name)
{
	const auto item =
		// 完全一致した行
		std::ranges::find( entries, name, &OfficialZipEntry::relativePath) ;
	check( item == entries.end() ? INVALID_DATA : 0U) ;
	return *item ;
}

//------------------------------------------------------------------------------
/**
 * @brief CAB内のメンバー集合と個々の展開長を元マニフェストの宣言に一致させる
 * @param[in] entries 共通CABで検査した全通常ファイル
 * @param[in] declared マニフェストの元宣言。元XML自体を含まない
 * @param[in] containsManifest 起動用CABだけでtrue
 * @throws NativeError 件数・名前・長さの不一致
 */
//------------------------------------------------------------------------------
void checkCabinetInventory( const std::span<const OfficialZipEntry>			entries,
						   const std::span<const OfficialWixManifestMember> declared,
						   const bool										containsManifest)
{
	check( entries.size() == declared.size() + (containsManifest ? 1U : 0U) ? 0U : INVALID_DATA) ;
	// 全宣言を元CABに照合し、無宣言の追加項目や元展開長の不一致を残さない
	for( const auto &member : declared) {
		check( findEntry( entries, member.cabinetMember).uncompressedSize == member.bytes
				  ? 0U
				  : TRUST_E_BAD_DIGEST) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 保護領域で固定したファイルを署名済みマニフェストの元SHA-1と照合する
 * @param[in] path 固定handleと同じファイルの絶対path
 * @param[in] expectedSha1 署名付き元マニフェストの小文字SHA-1
 * @throws NativeError 読取りまたは元ハッシュの不一致
 */
//------------------------------------------------------------------------------
void checkManifestHash( const std::wstring_view path, const std::wstring_view expectedSha1)
{
	std::wstring sha1 ;	// 署名付き元宣言との比較にだけ使う実バイトのdigest
	check( computeFileSha1ForSignedManifest( path, sha1)) ;
	check( sha1 == expectedSha1 ? 0U : TRUST_E_BAD_DIGEST) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開済み元メンバーを固定し、元宣言と展開時に得たSHA-256を両方照合する
 * @param[in] path 保護領域内の展開済みファイルの絶対path
 * @param[in] entry 元CABを共通処理で展開した結果
 * @param[in] member 同じメンバーの署名付きマニフェスト宣言
 * @param[in,out] mapping 照合後も元bytesを利用する間だけ固定する所有者
 * @throws NativeError 展開名、展開長、hash、固定状態の不一致
 */
//------------------------------------------------------------------------------
void openVerifiedMember( const std::wstring_view path, const OfficialZipEntry &entry,
						const OfficialWixManifestMember &member, OfficialMappedFile &mapping)
{
	check( entry.relativePath == member.cabinetMember && entry.uncompressedSize == member.bytes &&
				  !entry.sha256.empty()
			  ? 0U
			  : INVALID_DATA) ;
	check( mapping.open( path, member.bytes)) ;
	check( verifyOfficialFileMetadata( path, {member.bytes, entry.sha256})) ;
	checkManifestHash( path, member.sha1) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsのファイル名の大文字小文字を無視して同一位置を判定する
 * @param[in] left 検証済みの有限ファイル名または拡張子
 * @param[in] right 検証済みの有限ファイル名または拡張子
 * @return 文字列が同じWindows上の名前を指す場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sameFileName( const std::wstring_view left,
								const std::wstring_view right) noexcept
{
	return left.size() == right.size() && !left.empty() &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief 内容検査の対象を安全な一意の元キーと論理名に固定する
 * @param[in] selection 内側CABと対象OS用ファイルの指定
 * @param[in] policy 収集内容検査と展開の有限条件
 * @throws NativeError 対象、上限、パス、用途の指定が不正な場合
 */
//------------------------------------------------------------------------------
void checkDriverSelection( const OfficialWixDriverSelection &selection,
						  const OfficialWixDriverPolicy	   &policy)
{
	check( selection.files.size() >= 3U &&
				  selection.files.size() <= policy.inventory.maximumFileCount &&
				  selection.files.size() <= policy.cabinet.maximumEntryCount &&
				  policy.maximumClosureBytes != 0U &&
				  policy.inf.purpose == OfficialInfInspectionPurpose::COLLECTOR_CONTENT
			  ? 0
			  : static_cast<NativeError>( E_INVALIDARG)) ;
	std::size_t infCount{} ;	// 一致する選択INF名の数
	// CAB名、論理名の衝突を先に拒否し、別OSの同名ファイルを推測で選ばない
	for( std::size_t index = 0U; index < selection.files.size(); ++index) {
		const auto &file = selection.files[index] ;	// 今回照合する元File対応
		check( isSafeOfficialArchiveMember( file.cabinetMember, L'\\') &&
					  isSafeOfficialArchiveMember( file.targetName, L'\\') &&
					  file.cabinetMember.find( L'\\') == file.cabinetMember.npos &&
					  file.targetName.find( L'\\') == file.targetName.npos
				  ? 0
				  : INVALID_DATA) ;
		// これまでの役割と重複する元キーまたは論理名を拒否する
		for( const auto &previous : selection.files.first( index)) {
			check( sameFileName( file.cabinetMember, previous.cabinetMember) ||
						  sameFileName( file.targetName, previous.targetName)
					  ? INVALID_DATA
					  : 0) ;
		}

		infCount += file.targetName == selection.infName ? 1U : 0U ;
	}

	check( infCount == 1U ? 0 : INVALID_DATA) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一件のAMD64 MSIを元hashに照合し、選択したドライバー内容だけを論理名で保持する
 * @param[in] package 検証済みの元WiX配布とMSIの保護領域
 * @param[in] database 元Chainから選択した検査済みAMD64 MSI
 * @param[in] selection 内側の元stream、元File名対応とINF
 * @param[in] policy 内側MSI、CABと閉包の有限上限
 * @param[in] session 同じ保護検査の非ゼロ識別子
 * @param[in,out] destination 選択した論理名ファイルを所有する初期化済み領域
 * @return 選択順の元ファイルサイズとSHA-256
 * @throws NativeError 元MSI、File表、内側CAB、選択または複写の不一致
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<OfficialZipEntry> stageDriverVariant(
	const OfficialWixPackageContent &package, const OfficialWixVerifiedDatabase &database,
	const OfficialWixDriverSelection &selection, const OfficialWixDriverPolicy &policy,
	const ScanSessionId session, OfficialDownloadWorkspace &destination)
{
	const auto path = package.workspace->path( database.file.relativePath) ;	// 元MSIの固定path
	OfficialMsiCabinetInventory inventory ;										// 同じMSIから読んだ全File対応
	check( inspectOfficialMsiCabinetInventory(
		{path, database.file.uncompressedSize, database.file.sha256, selection.streamName},
		policy.inventory, inventory)) ;
	OfficialDownloadWorkspace raw ;	// 元CABと元Fileキーの限定展開を所有する領域
	check( raw.initialize( L"wix-driver-files", session, destination.protectionMode())) ;
	constexpr std::wstring_view INNER_CAB = L"embedded.cab" ;	// 照合用だけの内側CAB名
	OfficialMsiStreamEntry		cabinet ;						// MSI元streamを取得したhashとサイズ
	check( extractOfficialMsiStream( {path, database.file.uncompressedSize, database.file.sha256,
									selection.streamName, INNER_CAB},
								   policy.stream, raw, cabinet)) ;
	const auto		   cabinetPath = raw.path( INNER_CAB) ;	// 共通CAB検査用の保護path
	OfficialMappedFile cabinetGuard ;						// 事前の一覧検査から選択展開まで同じCABを固定する
	check( cabinetGuard.open( cabinetPath, policy.cabinet.maximumArchiveBytes)) ;
	check( verifyOfficialFileMetadata( cabinetPath, {cabinet.streamSize, cabinet.sha256})) ;
	std::vector<OfficialZipEntry> entries ;	// 内側CABの全通常ファイル
	check( inspectOfficialCab( cabinetPath, policy.cabinet, entries)) ;
	check( entries.size() == inventory.files.size() ? 0 : INVALID_DATA) ;
	// File表にある全キーと展開長をCAB実項目へ照合する
	for( const auto &mapping : inventory.files) {
		check( findEntry( entries, mapping.cabinetRelativePath).uncompressedSize ==
					  mapping.uncompressedSize
				  ? 0
				  : INVALID_DATA) ;
	}

	std::vector<std::wstring_view> keys ;	// 宣言と一致した対象OS用CABキー
	keys.reserve( selection.files.size()) ;
	std::uint64_t total{} ;	// 抽出前に必ず確定する閉包合計byte数
	// 同名の別OSや別役割を混ぜず、選択分だけを予算へ計上する
	for( const auto &file : selection.files) {
		const auto mapping = std::ranges::find(
			inventory.files, file.cabinetMember,
			&OfficialMsiCabinetFileEntry::cabinetRelativePath) ;	// 選択した元Fileの対応行
		check( mapping != inventory.files.end() && mapping->targetRelativePath == file.targetName
				  ? 0
				  : INVALID_DATA) ;
		check( mapping->uncompressedSize <= policy.maximumClosureBytes - total
				  ? 0
				  : HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
		total += mapping->uncompressedSize ;
		keys.push_back( file.cabinetMember) ;
	}

	check( extractOfficialCabFiles( cabinetPath, policy.cabinet, keys, raw, entries)) ;
	std::vector<OfficialZipEntry> driver ;	// 論理名で固定したファイル比較用の順序付き閉包
	driver.reserve( selection.files.size()) ;
	// 各元キーを独立に固定し、複写した論理ファイルのhashも照合する
	for( const auto &file : selection.files) {
		const auto		  &entry  = findEntry( entries, file.cabinetMember) ;	// 展開済みの元File
		const auto		   source = raw.path( entry.relativePath) ;				// 展開した元Fileの保護path
		OfficialMappedFile member ;												// 照合中に元Fileを固定する
		check( member.open( source, policy.cabinet.maximumSingleFileBytes)) ;
		const OfficialFileMetadataPolicy identity{entry.uncompressedSize,
												  entry.sha256} ;	// 元Fileの実値
		check( verifyOfficialFileMetadata( source, identity)) ;
		writeNewFile( destination, file.targetName, member.bytes()) ;
		check( verifyOfficialFileMetadata( destination.path( file.targetName), identity)) ;
		driver.push_back( {std::wstring( file.targetName), entry.uncompressedSize, entry.sha256}) ;
	}

	return driver ;
}

//------------------------------------------------------------------------------
/**
 * @brief 全AMD64で一致する内容を、共通INF構造検査とCATの全メンバー検査へ渡す
 * @param[in] workspace 一致が成立した論理名のファイルを保持する領域
 * @param[in] selection プロファイルが固定した選択INF名とファイル対応
 * @param[in] policy 収集専用の内容条件と有限展開上限
 * @param[in] cachedOnly trueの場合はCAT信頼確認のURL取得もキャッシュへ制限する
 * @param[in,out] closure 同一ファイル一覧。成功時だけ構造検査済みINFと合計を保持する
 * @throws NativeError 内容閉包または署名が成立しない場合
 */
//------------------------------------------------------------------------------
void verifyDriverClosure( const OfficialDownloadWorkspace  &workspace,
						 const OfficialWixDriverSelection &selection,
						 const OfficialWixDriverPolicy &policy, const bool cachedOnly,
						 OfficialDriverClosure &closure)
{
	std::vector<std::unique_ptr<OfficialMappedFile>> guards ;	// 全署名確認まで元ファイルを固定する
	guards.reserve( closure.entries.size()) ;
	// 構造、署名のWindows照会中に同じ論理ファイルを保持する
	for( const auto &entry : closure.entries) {
		auto	   file = std::make_unique<OfficialMappedFile>() ;	// 今回固定する閉包ファイル
		const auto path = workspace.path( entry.relativePath) ;		// 同じ保護領域内の絶対path
		check( file->open( path, policy.cabinet.maximumSingleFileBytes)) ;
		check( verifyOfficialFileMetadata( path, {entry.uncompressedSize, entry.sha256})) ;
		guards.push_back( std::move( file)) ;
		closure.expandedBytes += entry.uncompressedSize ;
	}

	OfficialInfPackage driver ;							// 共通検査が原INFから読み出すClass、版、参照
	auto			   contentPolicy   = policy.inf ;	// 既存の収集内容用境界を維持する
	contentPolicy.requireDriverBinary  = true ;
	contentPolicy.rejectInstallActions = true ;
	check( inspectOfficialInfPackage( workspace, closure.entries, selection.infName, contentPolicy,
									driver)) ;
	check( closure.entries.size() == driver.sourceFiles.size() + 2U ? 0 : INVALID_DATA) ;
	const auto &cat = findEntry( closure.entries, driver.catalogRelativePath) ;	// 元INFが宣言したCAT
	std::vector<std::wstring> members{											// 同じCATへ結ぶ元INFと全参照
									  workspace.path( selection.infName)} ;
	// 元INFが実際に参照する全ファイルとAMD64 SYSを検査する
	for( const auto &name : driver.sourceFiles) {
		const auto &entry = findEntry( closure.entries, name) ;		// 共通INF検査で判明した元参照
		const auto	path  = workspace.path( entry.relativePath) ;	// 同じCATへ渡す保護path
		const std::wstring_view fileName = entry.relativePath ;		// 拡張子照合中に借用する名称
		// 同梱SYSのCPU形式をMSIの表示値だけで判断しない
		if( fileName.size() > 4U && sameFileName( fileName.substr( fileName.size() - 4U), L".sys")) {
			check( verifyAmd64PeFile( path)) ;
		}

		members.push_back( path) ;
	}

	const auto catalogPath = workspace.path( cat.relativePath) ;	// 全メンバーを結合する元CAT
	check( cachedOnly ? verifyOfficialCatalogMembersCachedOnly( catalogPath, members)
					 : verifyWindowsInfPackageIntegrity( workspace, driver)) ;
	closure.packages.push_back( std::move( driver)) ;
	closure.archiveDepth = 1U ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 元EXEの署名に結び付く全MSIの原バイトと実属性および規約の原バイトを照合する
 * @param[in] request 元の取得証拠、元Chainと規約の指定、保護用途
 * @param[in] policy 元ファイル、外側CAB、各MSIの独立した有限上限
 * @param[out] content 全照合が成立した場合だけ移す所有結果。失敗時は空
 * @return 成功0、先に発生した構造、信頼、内容またはI/O失敗のHRESULT
 * @pre 呼出workerがCOMを初期化する
 * @note EXEとMSIは実行しない。共通INF閉包、CAT信頼、規約提示と同意は別途必要
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialWixPackageContent( const OfficialWixPackageRequest &request,
											 const OfficialWixPackagePolicy	 &policy,
											 OfficialWixPackageContent		 &content)
{
	content = {} ;
	// 続くネイティブ検査に必要な有限上限と元用途を先に照合する
	if( request.scanSessionId == 0U || request.packages.empty() || request.licenses.empty() ||
	   policy.maximumDatabaseBytes == 0U || policy.cabinet.maximumArchiveBytes == 0U) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		OfficialMappedFile	  executable ;	// 署名を検証した元ファイルを一連の照合中に固定する
		OfficialWixBurnLayout layout ;		// 固定した元ファイルにある二つのCAB範囲
		check( openVerifiedOfficialWixBurn( request.source, policy.bundle, executable, layout)) ;
		OfficialWixPackageContent inspected ;	// 全件の検査成功までこの呼出し内に保持する
		inspected.workspace = std::make_unique<OfficialDownloadWorkspace>() ;
		auto &workspace		= *inspected.workspace ;	// 元内容を写す一時ファイルの所有者
		check( workspace.initialize( L"wix-package", request.scanSessionId, request.workspaceMode)) ;

		OfficialMappedFile ux ;	// 元範囲と照合した起動用CABを固定する
		const auto		   uxPath =
			stageCabinet( workspace, UX_CABINET,
						 executable.bytes().subspan( layout.uxCabinetOffset, layout.uxCabinetSize),
						 policy.cabinet.maximumArchiveBytes, ux) ;	// 固定した起動用CABの一時path
		constexpr std::array MANIFEST_ONLY{MANIFEST} ;				// 選択役割の根拠を外側CABから先に読む
		std::vector<OfficialZipEntry> manifests ;					// 元XMLの展開時情報
		check( extractOfficialCabFiles( uxPath, policy.cabinet, MANIFEST_ONLY, workspace, manifests)) ;
		const auto		  &manifestEntry = findEntry( manifests, MANIFEST) ;	// 起動用CABの元XML一件
		const auto		   manifestPath	 = workspace.path( MANIFEST) ;			// 共通UTF-8読取りへ渡す元XML
		OfficialMappedFile manifestFile ;										// 展開時の元XMLのSHA-256を照合中に固定する
		check( manifestFile.open( manifestPath, MAXIMUM_MANIFEST_BYTES)) ;
		check( verifyOfficialFileMetadata( manifestPath,
										 {manifestEntry.uncompressedSize, manifestEntry.sha256})) ;
		std::wstring xml ;	// 既存の有限UTF-8読取りと安全なDOMへ渡す元テキスト
		check( readOfficialUtf8Xml( manifestPath, MAXIMUM_MANIFEST_BYTES, xml)) ;
		OfficialWixManifest manifest ;	// 全MSIと規約の名前・長さ・原ハッシュ
		check( inspectOfficialWixManifest( xml, request.packages, request.licenses, manifest)) ;
		check( manifest.attachedCabinetBytes == layout.attachedCabinetSize ? 0U
																		  : TRUST_E_BAD_DIGEST) ;

		OfficialMappedFile attached ;	// 元範囲と照合した添付CABを固定する
		const auto		   attachedPath = stageCabinet(
			workspace, ATTACHED_CABINET,
			executable.bytes().subspan( layout.attachedCabinetOffset, layout.attachedCabinetSize),
			policy.cabinet.maximumArchiveBytes, attached) ;	// 固定した添付CABの一時path
		checkManifestHash( attachedPath, manifest.attachedCabinetSha1) ;
		std::vector<OfficialZipEntry> inventory ;	// 再利用する外側CABの全件情報
		check( inspectOfficialCab( uxPath, policy.cabinet, inventory)) ;
		checkCabinetInventory( inventory, manifest.uxMembers, true) ;
		check( inspectOfficialCab( attachedPath, policy.cabinet, inventory)) ;
		checkCabinetInventory( inventory, manifest.msiMembers, false) ;

		std::vector<std::wstring_view> selected ;	// 選択展開する元CAB内名
		selected.reserve( manifest.licenseIndices.size()) ;
		// 規約は渡された言語順で元マニフェストに照合した項目だけを展開する
		for( const auto index : manifest.licenseIndices) {
			selected.push_back( manifest.uxMembers[index].cabinetMember) ;
		}

		std::vector<OfficialZipEntry> extracted ;	// 展開結果。原バイト照合後に分けて保持する
		check( extractOfficialCabFiles( uxPath, policy.cabinet, selected, workspace, extracted)) ;
		// 原バイトまで一致した規約を利用者へ案内する順序で保持する
		for( const auto index : manifest.licenseIndices) {
			const auto		  &member = manifest.uxMembers[index] ;						// 規約一件の元宣言
			const auto		  &entry  = findEntry( extracted, member.cabinetMember) ;	// 展開結果
			OfficialMappedFile license ;												// 原バイト照合中に規約だけを固定する
			openVerifiedMember( workspace.path( entry.relativePath), entry, member, license) ;
			inspected.licenses.push_back( entry) ;
		}

		selected.clear() ;
		// AMD64閉包の選定前にx86も含む全MSIを元宣言へ照合する
		for( const auto &member : manifest.msiMembers) {
			check( member.bytes <= policy.maximumDatabaseBytes
					  ? 0U
					  : HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE)) ;
			selected.push_back( member.cabinetMember) ;
		}

		check(
			extractOfficialCabFiles( attachedPath, policy.cabinet, selected, workspace, extracted)) ;
		// 各MSIの保護コピーはネイティブSummaryInformationと元ハッシュを対で確認する
		for( std::size_t index = 0U; index < manifest.msiMembers.size(); ++index) {
			const auto &member	  = manifest.msiMembers[index] ;					// 元Chainの一件
			const auto &selection = request.packages[index] ;						// 同じ順序で照合した実属性
			const auto &entry	  = findEntry( extracted, member.cabinetMember) ;	// 共通CABの抽出結果
			OfficialMappedFile raw ;												// SHA照合から拡張子付き複写まで原バイトを固定する
			openVerifiedMember( workspace.path( entry.relativePath), entry, member, raw) ;
			auto databaseName =
				entry.relativePath + L".msi" ;	// ネイティブAPI用に既知の相対名を生成する
			writeNewFile( workspace, databaseName, raw.bytes()) ;
			const auto platform = selection.architecture == OfficialWixMsiArchitecture::AMD64
									  ? OfficialMsiPlatform::AMD64
									  : OfficialMsiPlatform::X86 ;	// 元Chainと一致した属性条件
			check( verifyOfficialMsiTemplate( workspace.path( databaseName), entry.uncompressedSize,
											entry.sha256, policy.maximumDatabaseBytes, platform,
											selection.language)) ;
			inspected.databases.push_back(
				{{std::move( databaseName), entry.uncompressedSize, entry.sha256},
				 selection.architecture,
				 selection.language}) ;
		}

		content = std::move( inspected) ;
		return 0U ;
	} catch( const NativeError error) {
		return error ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 収集と端末が同じWiXドライバー内容を読むための有限な検査条件を返します
 * @param[in] acceptedClasses 元配布のINFに適用する明示クラスです。呼出し側が検査終了まで所有します
 * @return 外側と内側の固定上限と、指定クラスだけの非実行INF検査条件です
 * @note Windowsの信頼確認と導入許可は別です。返却値はacceptedClassesの参照を保持します
 */
//------------------------------------------------------------------------------
OfficialWixInspectionPolicy makeOfficialWixInspectionPolicy(
	const std::span<const std::wstring_view> acceptedClasses) noexcept
{
	constexpr std::uint64_t MAXIMUM_PACKAGE_BYTES =
		2ULL * 1024ULL * 1024ULL * 1024ULL ;	// 元EXEと単一CABの上限です
	constexpr std::uint64_t MAXIMUM_MEMBER_BYTES =
		512ULL * 1024ULL * 1024ULL ;	// 一ファイルの展開上限です
	constexpr std::uint64_t MAXIMUM_EXPANDED_BYTES =
		3ULL * 1024ULL * 1024ULL * 1024ULL ;	// 有限な閉包上限です
	constexpr OfficialCabExtractionPolicy CABINET{MAXIMUM_PACKAGE_BYTES, MAXIMUM_MEMBER_BYTES,
												  MAXIMUM_EXPANDED_BYTES,
												  1024U} ;	// 内外の安全上限です
	static constexpr std::array<std::wstring_view, 1U> SIGNATURES{
		L"$Windows NT$"} ;	// 検査全体で借用できるx64用INF形式です
	return {{{MAXIMUM_PACKAGE_BYTES, MAXIMUM_PACKAGE_BYTES}, CABINET, MAXIMUM_MEMBER_BYTES},
			{{MAXIMUM_MEMBER_BYTES, MAXIMUM_MEMBER_BYTES, 1024U},
			 {MAXIMUM_MEMBER_BYTES, MAXIMUM_MEMBER_BYTES, 32768U},
			 CABINET,
			 {.maximumHardwareIds		  = 4096U,
			  .maximumSourceFiles		  = 1024U,
			  .acceptedClasses			  = acceptedClasses,
			  .acceptedProviders		  = {},
			  .acceptedSignatures		  = SIGNATURES,
			  .acceptAnyProvider		  = true,
			  .rejectExternalDependencies = true,
			  .purpose					  = OfficialInfInspectionPurpose::COLLECTOR_CONTENT},
			 MAXIMUM_EXPANDED_BYTES}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元WiX配布の全AMD64 MSIから同一の署名付きドライバー内容を分離する
 * @param[in] request 同じ公式EXE、元Chain、規約、保護用途
 * @param[in] packagePolicy 元EXEと外側CABに使う有限上限
 * @param[in] selection 内側の元stream、元File対応と対象INF
 * @param[in] driverPolicy 内側MSI、CAB、INFと閉包の上限およびClass等の条件
 * @param[out] content 全照合とCAT検査が成立した場合だけ移す結果。失敗時は空
 * @return 成功0、取得、署名、宣言、実内容が不成立の場合はHRESULT
 * @pre 呼出workerがCOMを初期化する
 * @note キャッシュ限定の内容確認から通常のWindows署名合格を発行しない
 * @note 規約同意、端末適用性、登録の作用、導入資格は別途検査する
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialWixDriverContent( const OfficialWixPackageRequest	 &request,
											const OfficialWixPackagePolicy	 &packagePolicy,
											const OfficialWixDriverSelection &selection,
											const OfficialWixDriverPolicy	 &driverPolicy,
											OfficialWixDriverContent		 &content)
{
	content = {} ;
	try {
		checkDriverSelection( selection, driverPolicy) ;
		OfficialWixDriverContent inspected ;	// すべての候補が合致するまで内部に保持する
		check( inspectOfficialWixPackageContent( request, packagePolicy, inspected.package)) ;
		// 宣言を照合した全AMD64 MSIを読み、一件でも異なる内容なら閉包を公開しない
		for( const auto &database : inspected.package.databases) {
			// x86は外側で元ハッシュとMSI属性だけを確認済みであり、ドライバー展開を行わない
			if( database.architecture != OfficialWixMsiArchitecture::AMD64) {
				continue ;
			}

			auto variant = std::make_unique<OfficialDownloadWorkspace>() ;	// 現在MSIだけの展開領域
			check( variant->initialize( L"wix-driver", request.scanSessionId, request.workspaceMode)) ;
			auto files =
				stageDriverVariant( inspected.package, database, selection, driverPolicy,
								   request.scanSessionId, *variant) ;	// 展開した全ファイルの実値
			// 最初の閉包を保持し、続くすべてのMSIを同じ順序で比較する
			if( inspected.driverWorkspace == nullptr) {
				inspected.driverWorkspace = std::move( variant) ;
				inspected.closure.entries = std::move( files) ;
			} else {
				// 論理位置・長さ・全バイトSHA-256の一致だけを認める
				check( std::ranges::equal(
						  files, inspected.closure.entries,
						  []( const OfficialZipEntry &left, const OfficialZipEntry &right) {
							  return left.relativePath == right.relativePath &&
									 left.uncompressedSize == right.uncompressedSize &&
									 left.sha256 == right.sha256 ;
						  })
						  ? 0
						  : static_cast<NativeError>( TRUST_E_BAD_DIGEST)) ;
			}

			++inspected.matchingDatabaseCount ;
		}

		check( inspected.driverWorkspace != nullptr ? 0 : INVALID_DATA) ;
		verifyDriverClosure( *inspected.driverWorkspace, selection, driverPolicy,
							request.source.cachedOnly, inspected.closure) ;
		inspected.windowsInfPolicyVerified = !request.source.cachedOnly ;
		content							   = std::move( inspected) ;
		return 0 ;
	} catch( const NativeError error) {
		return error ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace drivercrate
