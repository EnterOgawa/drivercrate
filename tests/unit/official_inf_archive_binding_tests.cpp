//------------------------------------------------------------------------------
/**
 * @file official_inf_archive_binding_tests.cpp
 * @brief 封印ZIP／PE内INF結合の非通信・非導入境界試験。
 * @version 01.03.01
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  架空ZIPの閉集合・派生・改変・非昇格試験を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  明示PE形式の全INF原範囲とZIP内経路の試験を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/06  封印native由来と使用中固定の隔離試験を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/06  原CATの保持・未使用固定・非封印拒否を試験。
 * Ver.01.03.01 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * </pre>
 *
 * @note 架空取得と自身の保護workspaceだけを使用し、署名・実device・導入を呼ばない。
 * @see docs/adr/0274-sealed-zip-inf-member-binding.md
 */
//------------------------------------------------------------------------------
#include "platform/official_inf_archive_binding.h"
#include "platform/official_pe_inf_extraction.h"
#include "platform/official_file_verifier.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "test_framework.h"
#ifdef DRIVERCRATE_ACQUIRED_INF_NATIVE_TESTING
#include "support/inf_dependency_native_test_api.h"
#endif

#include <Windows.h>
#include <winioctl.h>
#include <miniz.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {
constexpr OfficialAcquisitionLimits LIMITS{128ULL * 1024ULL * 1024ULL,
										   256ULL * 1024ULL * 1024ULL,
										   256ULL * 1024ULL * 1024ULL,
										   1U,
										   2U,
										   2U} ;	// 架空取得二件の上限。
constexpr std::string_view			INF_TEXT =
	"[Version]\r\nSignature=\"$Windows NT$\"\r\n" ;	// 署名未検査の架空INF。

/** @brief Memory ZIPへ格納する架空entry。 */
struct BindingZipEntry {
	/// 終端を追加してwriterへ渡す相対名。
	std::string name ;
	/// ZIPへ原byteのまま格納する内容。
	std::string body ;
} ;

/** @brief 架空ZIPをmemoryで生成する。
 * @param[in] entries 架空の名前と本文。空ZIPも許可する。
 * @return 完成したmemory ZIP。生成失敗では例外。
 * @throws std::runtime_error Miniz writerに失敗した場合。
 */
std::vector<std::byte> bindingZip( std::span<const BindingZipEntry> entries)
{
	mz_zip_archive writer{} ;	// Memory writerの内部所有状態。
	// Writer初期化失敗を空ZIPにしない。
	if( !mz_zip_writer_init_heap( &writer, 0U, 0U)) {
		throw std::runtime_error( "fixture init") ;
	}

	// 全指定entryを原順序で格納する。
	for( const auto &entry : entries) {
		// 部分ZIPは公開せずwriterを回収する。
		if( !mz_zip_writer_add_mem( &writer, entry.name.c_str(), entry.body.data(), entry.body.size(),
								  MZ_BEST_COMPRESSION)) {
			mz_zip_writer_end( &writer) ;
			throw std::runtime_error( "fixture entry") ;
		}
	}

	void	   *data{} ;	// Minizが確保する完成byte。
	std::size_t size{} ;	// 完成ZIPのbyte数。
	// Finalize失敗を正常fixtureにしない。
	if( !mz_zip_writer_finalize_heap_archive( &writer, &data, &size)) {
		mz_zip_writer_end( &writer) ;
		throw std::runtime_error( "fixture finalize") ;
	}

	std::vector<std::byte> bytes ;	// 呼出し側へ所有を移すmemory。
	try {
		const auto *begin = static_cast<const std::byte *>( data) ;	// 生存Miniz allocationの借用。
		bytes.assign( begin, begin + size) ;
	} catch( ...) {
		mz_free( data) ;
		mz_zip_writer_end( &writer) ;
		throw ;
	}

	mz_free( data) ;
	mz_zip_writer_end( &writer) ;
	return bytes ;
}

/** @brief 本文byteを原値のstringへ複写する。
 * @param[in] bytes memory ZIP。
 * @return NULを含めて同じbyte列。
 */
std::string zipBody( const std::vector<std::byte> &bytes)
{
	// Byte列とchar列の表現境界だけを借用する。
	return {reinterpret_cast<const char *>( bytes.data()), bytes.size()} ;
}

/** @brief Memory本文と架空source根拠だけの非通信transport。 */
class BindingTransport final : public IOfficialAcquisitionTransport {
public:
	/// Acquire中だけ借用する架空全byte。
	std::span<const std::byte> bytes ;
	/** @brief 架空全byteを所有外fileへ保存する。
	 * @param[in] url 使用しない架空URL。
	 * @param[in] resourceId 使用しない組込みresource名。
	 * @param[in] maximumBytes 有限取得上限。
	 * @param[in] outputFile 呼出し側が所有する新file。
	 * @param[in] progressCallback 使用しない進捗通知先。
	 * @param[in] cancellationCallback 使用しない取消し先。
	 * @return 全保存0、過大または書込API失敗のHRESULT。
	 */
	NativeError				   download( std::wstring_view url, std::wstring_view resourceId,
										std::uint64_t maximumBytes, HANDLE outputFile,
										const HttpDownloadProgressCallback &progressCallback,
										const HttpCancellationCallback	   &cancellationCallback) override
	{
		(void)url ;
		(void)resourceId ;
		(void)progressCallback ;
		(void)cancellationCallback ;
		// DWORDと取得の有限容量を超えるfixtureは保存しない。
		if( bytes.size() > maximumBytes || bytes.size() > 128ULL * 1024ULL * 1024ULL) {
			return E_INVALIDARG ;
		}

		DWORD written{} ;	// 保存したbyte数。
		// 低位API失敗とshort writeは元診断で返す。
		if( !WriteFile( outputFile, bytes.data(), static_cast<DWORD>( bytes.size()), &written,
					  nullptr)) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		return written == bytes.size() ? 0 : E_FAIL ;
	}
	/** @brief このfixtureでは委譲取得を実行しない。
	 * @param[in,out] request 使用しない一回request。
	 * @param[in] outputFile 使用しない所有外handle。
	 * @param[in] progressCallback 使用しない通知先。
	 * @param[in] cancellationCallback 使用しない取消し先。
	 * @param[out] destinationEvidence 常に空。
	 * @return E_NOTIMPL。
	 */
	NativeError downloadDelegated( OfficialDelegatedGetRequest &request, HANDLE outputFile,
								  const HttpDownloadProgressCallback &progressCallback,
								  const HttpCancellationCallback	 &cancellationCallback,
								  OfficialPublicDestinationEvidence	 &destinationEvidence) override
	{
		(void)request ;
		(void)outputFile ;
		(void)progressCallback ;
		(void)cancellationCallback ;
		destinationEvidence = {} ;
		return E_NOTIMPL ;
	}
	/** @brief 正常fixtureだけの架空source認証を返す。
	 * @param[in] scanSessionId 使用しないsession。
	 * @param[in] providerId 使用しないProvider。
	 * @param[in] resourceId 使用しないresource。
	 * @return true。実sourceの認証ではない。
	 */
	bool hasSourceEvidence( ScanSessionId scanSessionId, std::wstring_view providerId,
						   std::wstring_view resourceId) const noexcept override
	{
		(void)scanSessionId ;
		(void)providerId ;
		(void)resourceId ;
		return true ;
	}
} ;

/** @brief 実回線へ依存しないcost fixture。 */
class BindingCost final : public IOfficialNetworkCostReader {
public:
	/** @brief 非課金の架空回線を返す。
	 * @param[out] cost 常にUNRESTRICTED。
	 * @return 0。
	 */
	NativeError read( OfficialNetworkCostKind &cost) noexcept override
	{
		cost = OfficialNetworkCostKind::UNRESTRICTED ;
		return 0 ;
	}
} ;

/** @brief 一件の架空取得と封印を所有する。 */
struct BindingFixture {
	/// 自身だけが所有する元取得領域。
	OfficialDownloadWorkspace					workspace ;
	/// 失効を明示試験するsession所有者。
	std::unique_ptr<OfficialAcquisitionSession> session{
		std::make_unique<OfficialAcquisitionSession>()} ;
	/// 最後の成功取得から発行した証拠。
	OfficialAcquiredFileEvidence evidence ;
	/// 元fixture改変試験にだけ使う公開結果。
	OfficialAcquisitionResult	 result ;
	/** @brief 非通信取得から証拠発行までを実行する。
	 * @param[in] bytes 生存memory ZIP。
	 * @return 全成功0、最初の境界失敗のHRESULT。
	 */
	NativeError					 start( std::span<const std::byte> bytes)
	{
		auto error = workspace.initialize( L"inf-binding-test", 8401U) ;	// 元取得領域の保護開始。
		// 初期化失敗のまま取得へ進まない。
		if( error == 0) {
			error = session->initialize( 8401U, LIMITS) ;
		}

		BindingTransport transport ;	// 生存memoryを借用する架空転送。
		transport.bytes = bytes ;
		BindingCost						 cost ;	// 実NLMを使わないcost。
		const OfficialAcquisitionRequest request{
			.url			   = L"https://us.download.nvidia.com/fixture.bin",
			.providerId		   = NVIDIA_PROVIDER_ID,
			.resourceId		   = OFFICIAL_PAYLOAD_RESOURCE_ID,
			.workspaceFileName = L"fixture.bin",
			.maximumFileBytes  = LIMITS.maximumFileBytes} ;	// 組込みpolicy fixture。
		// 私有成功記録を正常取得からだけ作る。
		if( error == 0) {
			// 共通取得契約が必須にする非blockingの進捗通知を供給する。
			error = session->acquire(
				request, workspace, transport, cost, []( std::uint64_t, std::uint64_t) {}, {},
				result) ;
		}

		return error != 0 ? error
						  : session->bindAcquiredFile( workspace, result.acquisitionId, evidence) ;
	}
} ;

/** @brief 自身のfixtureだけの通常fileを改変する。
 * @param[in] path 自身が所有するfixture file。
 * @param[in] bytes 書き換える架空全byte。
 * @return 全保存とclose成功の場合true。
 */
bool changeBindingFile( const std::wstring &path, std::string_view bytes)
{
	HANDLE file = CreateFileW( path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
							  FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 既存の自身fixtureだけ。
	// Open失敗時は別pathを作成しない。
	if( file == INVALID_HANDLE_VALUE) {
		return false ;
	}

	DWORD	   written{} ;	// 実保存量。
	const bool saved =
		WriteFile( file, bytes.data(), static_cast<DWORD>( bytes.size()), &written, nullptr) &&
		// 完全な新本文。
		written == bytes.size() && SetEndOfFile( file) ;
	return CloseHandle( file) && saved ;
}

/** @brief 正常全INF・改変・writer・別session・moveと失効を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testBindingDirect( TestContext &context)
{
	const std::array<BindingZipEntry, 4U> source{
		{{"driver/a.inf", std::string( INF_TEXT)},
		 {"driver/b.INF", std::string( INF_TEXT)},
		 {"driver/a.sys", "never extracted"},
		 {"setup.exe", "never executed"}}} ;	// 二INFと非選択実行file。
	const auto	   raw = bindingZip( source) ;	// 架空全byte。
	BindingFixture fixture ;					// 元取得証拠を所有する。
	DRIVERCRATE_EXPECT( context, fixture.start( raw) == 0) ;
	OfficialInfArchiveBinding binding ;	// 既定結果は認証不能。
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) != 0) ;
	DRIVERCRATE_EXPECT( context, binding.workspace() == nullptr && binding.members().empty()) ;
	DRIVERCRATE_EXPECT( context, binding.bind( *fixture.session, std::move( fixture.evidence),
											 fixture.workspace, {}) == 0) ;
	DRIVERCRATE_EXPECT( context, !fixture.evidence.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, binding.members().size() == 2U) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) == 0) ;
	// 生成失敗でもtest processを不正dereferenceしない。
	if( binding.workspace() == nullptr || binding.members().size() != 2U) {
		return ;
	}

	DRIVERCRATE_EXPECT( context,
					   GetFileAttributesW( binding.workspace()->path( L"driver\\a.sys").c_str()) ==
						   INVALID_FILE_ATTRIBUTES) ;
	DRIVERCRATE_EXPECT( context,
					   GetFileAttributesW( binding.workspace()->path( L"setup.exe").c_str()) ==
						   INVALID_FILE_ATTRIBUTES) ;
	std::vector<InfDependencyPackageMember> detached(
		// 公開値の複写は証拠にならない。
		binding.members().begin(), binding.members().end()) ;
	detached.front().sha256 = L"forged" ;
	detached.pop_back() ;
	DRIVERCRATE_EXPECT( context, binding.members().size() == 2U &&
									binding.verify( *fixture.session, fixture.workspace) == 0) ;
	OfficialAcquisitionSession other ;	// 同数値IDでも異なる私有issuer。
	DRIVERCRATE_EXPECT( context, other.initialize( 8401U, LIMITS) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.verify( other, fixture.workspace) != 0) ;
	OfficialDownloadWorkspace otherWorkspace ;	// 同じtagでも別取得領域。
	DRIVERCRATE_EXPECT( context, otherWorkspace.initialize( L"inf-binding-test", 8401U) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, otherWorkspace) != 0) ;
	const auto path =
		// 自身の派生INF。
		binding.workspace()->path( binding.members().front().relativePath) ;
	HANDLE writer =
		CreateFileW( path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
					FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 一時的な既存writer。
	DRIVERCRATE_EXPECT( context, writer != INVALID_HANDLE_VALUE) ;
	DRIVERCRATE_EXPECT( context,
					   binding.verify( *fixture.session, fixture.workspace) ==
						   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_SHARING_VIOLATION))) ;
	// 作成失敗は元assertionへ残し、無効handleを解放しない。
	if( writer != INVALID_HANDLE_VALUE) {
		const BOOL closed = CloseHandle( writer) ;	// 解放結果だけを一回assertする。
		DRIVERCRATE_EXPECT( context, closed != FALSE) ;
	}

	std::string changed( INF_TEXT) ;	// 同size・異なる内容。
	changed.front() = '!' ;
	DRIVERCRATE_EXPECT( context, changeBindingFile( path, changed)) ;
	DRIVERCRATE_EXPECT( context,
					   binding.verify( *fixture.session, fixture.workspace) == TRUST_E_BAD_DIGEST) ;
	DRIVERCRATE_EXPECT( context, changeBindingFile( path, INF_TEXT)) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) == 0) ;
	OfficialInfArchiveBinding moved( std::move( binding)) ;	// Moveによる所有移設。
	DRIVERCRATE_EXPECT( context, moved.verify( *fixture.session, fixture.workspace) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) != 0) ;
	DRIVERCRATE_EXPECT( context, changeBindingFile( fixture.result.inspectionPath, "changed")) ;
	DRIVERCRATE_EXPECT( context, moved.verify( *fixture.session, fixture.workspace) != 0) ;
	DRIVERCRATE_EXPECT( context, changeBindingFile( fixture.result.inspectionPath, zipBody( raw))) ;
	DRIVERCRATE_EXPECT( context, moved.verify( *fixture.session, fixture.workspace) == 0) ;
	fixture.session.reset() ;
	DRIVERCRATE_EXPECT( context, moved.verify( other, fixture.workspace) != 0) ;
}

/** @brief 明示一段・二段ZIPと誤った経路の非昇格を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testBindingNested( TestContext &context)
{
	const std::array<BindingZipEntry, 1U> innerEntries{
		{{"x/a.inf", std::string( INF_TEXT)}}} ;								// 最終全INF。
	const auto							  inner = bindingZip( innerEntries) ;	// 一つ目のZIP。
	const std::array<BindingZipEntry, 2U> middleEntries{
		{{"nested/inner.zip", zipBody( inner)},
		 {"other.inf", "outer scope"}}} ;										// 明示branch外のINF。
	const auto							  middle = bindingZip( middleEntries) ;	// 一段内側ZIP。
	const std::array<BindingZipEntry, 1U> outerEntries{
		{{"outer.zip", zipBody( middle)}}} ;		// 二段原ZIP。
	const auto outer = bindingZip( outerEntries) ;	// 二段fixture。
	// 一段・二段それぞれ独立取得し、最終ZIP全INFだけを認証する。
	for( std::size_t depth = 1U; depth <= 2U; ++depth) {
		BindingFixture fixture ;	// このdepthだけの元証拠。
		DRIVERCRATE_EXPECT( context, fixture.start( depth == 1U ? middle : outer) == 0) ;
		const std::vector<std::wstring> names =
			depth == 1U
				? std::vector<std::wstring>{L"nested\\inner.zip"}
				: std::vector<std::wstring>{L"outer.zip", L"nested\\inner.zip"} ;	// 明示経路。
		OfficialInfArchiveBinding binding ;											// 最終INFだけの私有結果。
		DRIVERCRATE_EXPECT( context, binding.bind( *fixture.session, std::move( fixture.evidence),
												 fixture.workspace, names) == 0) ;
		DRIVERCRATE_EXPECT( context, binding.members().size() == 1U) ;
		DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) == 0) ;
		// 実装の拒否時もfixture自身が空一覧を参照しない。
		if( !binding.members().empty()) {
			DRIVERCRATE_EXPECT( context, binding.members().front().relativePath == L"x\\a.inf") ;
		}
	}

	BindingFixture fixture ;	// 誤経路試験の証拠は失敗後も生存する。
	DRIVERCRATE_EXPECT( context, fixture.start( middle) == 0) ;
	OfficialInfArchiveBinding		   rejected ;					// 全拒否で空に保つ。
	const std::array<std::wstring, 1U> missing{L"missing.zip"} ;	// 未存在経路。
	DRIVERCRATE_EXPECT( context, rejected.bind( *fixture.session, std::move( fixture.evidence),
											  fixture.workspace, missing) != 0) ;
	DRIVERCRATE_EXPECT( context, fixture.evidence.issuerAlive()) ;
	const std::array<std::wstring, 1U> traversal{L"..\\nested\\inner.zip"} ;	// 原名を正規化しない。
	DRIVERCRATE_EXPECT( context, rejected.bind( *fixture.session, std::move( fixture.evidence),
											  fixture.workspace, traversal) != 0) ;
	const std::array<std::wstring, 3U> tooDeep{L"a", L"b", L"c"} ;	// 明示上限超過。
	DRIVERCRATE_EXPECT( context, rejected.bind( *fixture.session, std::move( fixture.evidence),
											  fixture.workspace, tooDeep) != 0) ;
	const std::array<std::wstring, 1U> notZip{L"other.inf"} ;	// 名前に依存しない内容拒否。
	DRIVERCRATE_EXPECT( context, rejected.bind( *fixture.session, std::move( fixture.evidence),
											  fixture.workspace, notZip) != 0) ;
	DRIVERCRATE_EXPECT( context, rejected.members().empty() && rejected.workspace() == nullptr) ;
	DRIVERCRATE_EXPECT(
		context, fixture.session->verifyAcquiredFile( fixture.evidence, fixture.workspace) == 0) ;
}

/** @brief 危険・過多・欠落・未対応形式を一部成功にしないことを確認する。
 * @param[in,out] context Assertion集計先。
 */
void testBindingRejections( TestContext &context)
{
	std::vector<std::vector<BindingZipEntry>> cases{
		{},
		{{"a.sys", "no INF"}},
		{{"../a.inf", "unsafe"}},
		{{"a.inf", "one"}, {"A.INF", "two"}},
		{{"empty.inf", ""}},
		{{"a.inf", std::string( 4U * 1024U * 1024U + 1U, 'x')}},
		{{"safe.inf", "one"},
		 {"unsafe/../escape.exe", "never extracted"}}} ;	// 全entry preflightを要求する。
	std::vector<BindingZipEntry> tooMany ;					// 全INF上限を超える65件。
	// 一部64件だけの認証にしないfixtureを作る。
	for( std::size_t index = 0U; index < 65U; ++index) {
		tooMany.push_back( {"f" + std::to_string( index) + ".inf", "fixture"}) ;
	}

	cases.push_back( std::move( tooMany)) ;
	std::vector<BindingZipEntry> tooLarge ;	// 単体上限内でも合計上限を超える集合。
	// 四MiB五件で合計16 MiB境界を越える。
	for( std::size_t index = 0U; index < 5U; ++index) {
		tooLarge.push_back(
			{"f" + std::to_string( index) + ".inf", std::string( 4U * 1024U * 1024U, 'x')}) ;
	}

	cases.push_back( std::move( tooLarge)) ;
	// 各拒否fixtureも共通取得は成功させ、archive層の原因へ切り分ける。
	for( const auto &entries : cases) {
		const auto	   raw = bindingZip( entries) ;	// 一つの拒否対象全byte。
		BindingFixture fixture ;					// 取得sessionは正常。
		DRIVERCRATE_EXPECT( context, fixture.start( raw) == 0) ;
		OfficialInfArchiveBinding rejected ;	// 部分結果を公開しない。
		DRIVERCRATE_EXPECT( context, rejected.bind( *fixture.session, std::move( fixture.evidence),
												  fixture.workspace, {}) != 0) ;
		DRIVERCRATE_EXPECT( context, rejected.members().empty() && rejected.workspace() == nullptr) ;
		DRIVERCRATE_EXPECT(
			context, fixture.session->verifyAcquiredFile( fixture.evidence, fixture.workspace) == 0) ;
	}

	const std::vector<std::byte> pe{std::byte{'M'}, std::byte{'Z'},
									std::byte{1U}} ;	// 未対応PEをZIPにしない。
	BindingFixture				 fixture ;				// 非ZIPも取得と内容を区別する。
	DRIVERCRATE_EXPECT( context, fixture.start( pe) == 0) ;
	OfficialInfArchiveBinding rejected ;	// 形式拒否を空に保持する。
	DRIVERCRATE_EXPECT( context, rejected.bind( *fixture.session, std::move( fixture.evidence),
											  fixture.workspace, {}) != 0) ;
	DRIVERCRATE_EXPECT( context, rejected.members().empty()) ;
	OfficialAcquiredFileEvidence forged ;	// 公開boolから作れない既定証拠。
	DRIVERCRATE_EXPECT(
		context, rejected.bind( *fixture.session, std::move( forged), fixture.workspace, {}) != 0) ;
	DRIVERCRATE_EXPECT( context, rejected.workspace() == nullptr) ;
}

/** @brief 件数境界・CRC拒否・取得後改変と再bind時の空化を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testBindingBoundaries( TestContext &context)
{
	std::vector<BindingZipEntry> entries ;	// 正例の件数境界64 INF。
	// 全INFを容量内で作り、64件ちょうどの受理を確認する。
	for( std::size_t index = 0U; index < 64U; ++index) {
		entries.push_back( {"f" + std::to_string( index) + ".inf", "fixture"}) ;
	}

	const auto	   raw = bindingZip( entries) ;	// 一意64件のmemory。
	BindingFixture fixture ;					// 架空取得の私有記録。
	DRIVERCRATE_EXPECT( context, fixture.start( raw) == 0) ;
	OfficialInfArchiveBinding binding ;	// 件数上限で一部だけに縮約しない結果。
	DRIVERCRATE_EXPECT( context, binding.bind( *fixture.session, std::move( fixture.evidence),
											 fixture.workspace, {}) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.members().size() == 64U) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) == 0) ;
	OfficialInfArchiveBinding assigned ;	// Move代入も単独所有を維持する。
	assigned = std::move( binding) ;
	DRIVERCRATE_EXPECT( context, assigned.verify( *fixture.session, fixture.workspace) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) != 0) ;
	const std::array<BindingZipEntry, 1U> aliasEntries{
		{{"f0.inf", zipBody( raw)}}} ;						// 明示内側ZIPを借用原名へ結ぶfixture。
	const auto	   aliasRaw = bindingZip( aliasEntries) ;	// 内側に元64 INFを持つarchive。
	BindingFixture aliasFixture ;							// 再bindする別の正常取得。
	DRIVERCRATE_EXPECT( context, aliasFixture.start( aliasRaw) == 0) ;
	// 自身の全member原名をborrowしても、旧領域回収より先に入力を保存する。
	if( !assigned.members().empty()) {
		const std::span<const std::wstring> borrowed( &assigned.members().front().relativePath,
													 1U) ;	// 回収される自身のstorage。
		DRIVERCRATE_EXPECT( context,
						   assigned.bind( *aliasFixture.session, std::move( aliasFixture.evidence),
										 aliasFixture.workspace, borrowed) == 0) ;
		DRIVERCRATE_EXPECT( context, assigned.members().size() == 64U) ;
		DRIVERCRATE_EXPECT( context,
						   assigned.verify( *aliasFixture.session, aliasFixture.workspace) == 0) ;
	}

	OfficialAcquiredFileEvidence empty ;	// 既定証拠から再bindしない。
	DRIVERCRATE_EXPECT(
		context, assigned.bind( *fixture.session, std::move( empty), fixture.workspace, {}) != 0) ;
	DRIVERCRATE_EXPECT( context, assigned.members().empty() && assigned.workspace() == nullptr) ;
	const std::array<BindingZipEntry, 1U> small{
		{{"a.inf", std::string( INF_TEXT)}}} ;	// CRCを変える一member。
	auto damaged = bindingZip( small) ;			// この取得では改変したarchive自体が元byte。
	const std::array<std::byte, 4U> centralMagic{std::byte{0x50U}, std::byte{0x4bU},
												 std::byte{0x01U},
												 std::byte{0x02U}} ;	// Central headerの固定識別。
	const auto central = std::ranges::search( damaged, centralMagic) ;	// 一entryの中央metadata位置。
	DRIVERCRATE_EXPECT( context, !central.empty()) ;
	// 圧縮streamの未使用bitではなく、検証対象CRCそのものを不一致にする。
	if( !central.empty()) {
		*(central.begin() + 16U) ^= std::byte{1U} ;
	}

	BindingFixture crcFixture ;	// Source hash一致とZIP内容のCRCを分離する。
	DRIVERCRATE_EXPECT( context, crcFixture.start( damaged) == 0) ;
	DRIVERCRATE_EXPECT( context, assigned.bind( *crcFixture.session, std::move( crcFixture.evidence),
											  crcFixture.workspace, {}) != 0) ;
	DRIVERCRATE_EXPECT( context, crcFixture.session->verifyAcquiredFile( crcFixture.evidence,
																	   crcFixture.workspace) == 0) ;
	BindingFixture changedFixture ;					// 証拠発行後の原file差替え。
	const auto	   original = bindingZip( small) ;	// 元byte復元にだけ使う自身のmemory。
	DRIVERCRATE_EXPECT( context, changedFixture.start( original) == 0) ;
	DRIVERCRATE_EXPECT( context, changeBindingFile( changedFixture.result.inspectionPath, "changed")) ;
	DRIVERCRATE_EXPECT( context,
					   assigned.bind( *changedFixture.session, std::move( changedFixture.evidence),
									 changedFixture.workspace, {}) != 0) ;
	DRIVERCRATE_EXPECT( context,
					   assigned.workspace() == nullptr && changedFixture.evidence.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context,
					   changeBindingFile( changedFixture.result.inspectionPath, zipBody( original))) ;
	DRIVERCRATE_EXPECT( context,
					   assigned.bind( *changedFixture.session, std::move( changedFixture.evidence),
									 changedFixture.workspace, {}) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   assigned.verify( *changedFixture.session, changedFixture.workspace) == 0) ;
}

/** @brief 所有する試験directoryだけのmount-point API入力。 */
struct BindingJunctionData {
	/// Mount pointの固定tag。
	DWORD									 tag{IO_REPARSE_TAG_MOUNT_POINT} ;
	/// 後続offset群とpathのbyte数。
	WORD									 length{} ;
	/// 零固定の予約値。
	WORD									 reserved{} ;
	/// NT代替名の開始byte offset。
	WORD									 substituteOffset{} ;
	/// NT代替名の終端を除くbyte数。
	WORD									 substituteLength{} ;
	/// 表示名の開始byte offset。
	WORD									 printOffset{} ;
	/// 表示名の終端を除くbyte数。
	WORD									 printLength{} ;
	/// 両名前と終端を保持する有限buffer。
	std::array<wchar_t, 2U * MAX_PATH + 10U> paths{} ;
} ;
// Windowsの固定offset確認。
static_assert( offsetof( BindingJunctionData, paths) == 16U) ;

/** @brief 実junctionの祖先拒否を自身の架空領域だけで確認する。
 * @param[in,out] context Assertion集計先。
 * @note 作成したtagは同じhandleで解除する。元driverやWindows領域へ触れない。
 */
void testBindingJunction( TestContext &context)
{
	const std::array<BindingZipEntry, 1U> entries{
		{{"driver/a.inf", std::string( INF_TEXT)}}} ;	// 祖先を持つ一INF。
	const auto	   raw = bindingZip( entries) ;			// 自身の試験byte。
	BindingFixture fixture ;							// 元領域はjunction参照先にも使う自身の所有領域。
	DRIVERCRATE_EXPECT( context, fixture.start( raw) == 0) ;
	OfficialInfArchiveBinding binding ;	// 派生INFだけの所有結果。
	DRIVERCRATE_EXPECT( context, binding.bind( *fixture.session, std::move( fixture.evidence),
											 fixture.workspace, {}) == 0) ;
	// 前段失敗でも試験がnullptrを参照しない。
	if( binding.workspace() == nullptr) {
		return ;
	}

	DRIVERCRATE_EXPECT( context,
					   DeleteFileW( binding.workspace()->path( L"driver\\a.inf").c_str()) != FALSE) ;
	const auto directory = binding.workspace()->path( L"driver") ;	// 自身が作った空directory。
	const auto target	 = fixture.result.inspectionPath.substr(
		   0U, fixture.result.inspectionPath.find_last_of( L'\\')) ;			// 自身の元領域。
	const auto			substitute = L"\\??\\" + target ;						// APIのNT形式。
	BindingJunctionData data ;													// 全byte零初期化のreparse入力。
	const auto			characters = substitute.size() + target.size() + 2U ;	// 両終端を含む容量。
	// 固定bufferを超えるfixtureを切詰めしない。
	if( characters > data.paths.size()) {
		throw std::runtime_error( "junction fixture capacity") ;
	}

	data.substituteLength = static_cast<WORD>( substitute.size() * sizeof( wchar_t)) ;
	data.printOffset	  = static_cast<WORD>( (substitute.size() + 1U) * sizeof( wchar_t)) ;
	data.printLength	  = static_cast<WORD>( target.size() * sizeof( wchar_t)) ;
	data.length			  = static_cast<WORD>( 8U + characters * sizeof( wchar_t)) ;
	std::ranges::copy( substitute, data.paths.begin()) ;
	std::ranges::copy( target, data.paths.begin() + substitute.size() + 1U) ;
	HANDLE handle = CreateFileW(
		directory.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
		nullptr) ;	// 空の所有directoryだけ。
	DRIVERCRATE_EXPECT( context, handle != INVALID_HANDLE_VALUE) ;
	// Open失敗ではtagを作成しない。
	if( handle == INVALID_HANDLE_VALUE) {
		return ;
	}

	DWORD	   returned{} ;	// 元APIが返したbyte数。
	const bool created = DeviceIoControl( handle, FSCTL_SET_REPARSE_POINT, &data,
										 static_cast<DWORD>( 8U + data.length), nullptr, 0U,
										 &returned, nullptr) != FALSE ;	// 実tag作成。
	DRIVERCRATE_EXPECT( context, created) ;
	// 作成失敗では通常directoryのままhandleを回収する。
	if( !created) {
		CloseHandle( handle) ;
		return ;
	}

	const auto error =
		// Leaf不在より先に祖先reparse拒否。
		binding.verify( *fixture.session, fixture.workspace) ;
	BindingJunctionData removal ;	// 同じtagを解除する有限header。
	const bool			removed =
		DeviceIoControl( handle, FSCTL_DELETE_REPARSE_POINT, &removal, 8U, nullptr, 0U, &returned,
						nullptr) != FALSE ;		// 参照先fileは削除しない。
	const BOOL closed = CloseHandle( handle) ;	// Reparse解除後の所有handleを一回だけ解放する。
	DRIVERCRATE_EXPECT( context, closed != FALSE) ;
	DRIVERCRATE_EXPECT( context, removed) ;
	DRIVERCRATE_EXPECT( context, error == E_ACCESSDENIED) ;
	DRIVERCRATE_EXPECT( context,
					   fixture.workspace.path( L"fixture.bin") == fixture.result.inspectionPath) ;
}
/** @brief 架空PEの有効fieldを独立little-endianで構築する。
 * @param[in,out] raw 確保済みの所有memory。
 * @param[in] offset 有効field位置。
 * @param[in] value uint32値。
 * @param[in] count 2または4のfield幅。
 */
void writePeBindingValue( std::vector<std::byte> &raw, std::size_t offset, std::uint32_t value,
						 std::size_t count = 4U)
{
	// Fixtureのfield幅だけを原byteへ配置する。
	for( std::size_t index = 0U; index < count; ++index) {
		raw.at( offset + index) = static_cast<std::byte>( (value >> (index * 8U)) & 0xffU) ;
	}
}

/** @brief 架空名・marker・本文を原byteへ配置する。
 * @param[in,out] raw 確保済みのzero memory。
 * @param[in] offset 有効先頭位置。
 * @param[in] text 架空の原byte。
 */
void writePeBindingText( std::vector<std::byte> &raw, std::size_t offset, std::string_view text)
{
	// 符号付きcharをbyteの同じbit表現へ移す。
	for( std::size_t index = 0U; index < text.size(); ++index) {
		raw.at( offset + index) = static_cast<std::byte>( static_cast<unsigned char>( text[index])) ;
	}
}

/** @brief 一つ以上のINFと非選択PE／placeholderを持つ架空全表を作る。
 * @param[in] count 1～65のINF数。65は容量拒否試験用。
 * @return 非実行readonly data内の260名＋uint32長表を持つPE32+ x64。
 */
std::vector<std::byte> bindingPe( std::size_t count)
{
	std::string peMember( 88U, '\0') ;	// 実行しない最低限のSYS／EXE形状。
	peMember[0]	  = 'M' ;
	peMember[1]	  = 'Z' ;
	peMember[60U] = 64 ;
	peMember[64U] = 'P' ;
	peMember[65U] = 'E' ;
	std::vector<BindingZipEntry> files{
		{"driver.cat", std::string( "\x30\x82\x00\x01\x00", 5U)}} ;	// CATは形状だけ。
	// 全INFを別々の原名で作り、候補表を一つに保つ。
	for( std::size_t index = 0U; index < count; ++index) {
		files.push_back( {"f" + std::to_string( index) + ".INF", std::string( INF_TEXT)}) ;
	}

	files.push_back( {"driver.sys", peMember}) ;
	files.push_back( {"placeholder.dll", ""}) ;
	files.push_back( {"utility.exe", peMember}) ;
	const std::size_t blob	= 0x240U + files.size() * 264U ;	// 原項目表直後のdata。
	std::size_t		  bytes = blob ;							// 全fileとzero paddingの合計範囲。
	// 原fileの4 byte整列を独立に計算する。
	for( const auto &file : files) {
		bytes += (file.body.size() + 3U) / 4U * 4U ;
	}

	std::vector<std::byte> raw( (bytes + 511U) / 512U * 512U) ;	// 全rangeを含むzero初期化PE。
	writePeBindingText( raw, 0U, "MZ") ;
	writePeBindingValue( raw, 60U, 0x80U) ;
	writePeBindingText( raw, 0x80U, "PE") ;
	writePeBindingValue( raw, 0x84U, 0x8664U, 2U) ;
	writePeBindingValue( raw, 0x86U, 1U, 2U) ;
	writePeBindingValue( raw, 0x94U, 240U, 2U) ;
	writePeBindingValue( raw, 0x98U, 0x20bU, 2U) ;
	writePeBindingValue( raw, 0x98U + 60U, 0x200U) ;
	writePeBindingValue( raw, 0x98U + 108U, 16U) ;
	writePeBindingText( raw, 0x188U, ".fixture") ;
	writePeBindingValue( raw, 0x188U + 16U, static_cast<std::uint32_t>( raw.size() - 0x200U)) ;
	writePeBindingValue( raw, 0x188U + 20U, 0x200U) ;
	writePeBindingValue( raw, 0x188U + 36U, 0x40000040U) ;
	std::size_t header = 0x240U ;	// 次の固定項目先頭。
	std::size_t data   = blob ;		// 次の本文先頭。
	// 全項目を原順で記述し、既定zero paddingを維持する。
	for( const auto &file : files) {
		writePeBindingText( raw, header, file.name) ;
		writePeBindingValue( raw, header + 260U, static_cast<std::uint32_t>( file.body.size())) ;
		writePeBindingText( raw, data, file.body) ;
		header += 264U ;
		data += (file.body.size() + 3U) / 4U * 4U ;
	}

	return raw ;
}

/** @brief PE全表と原INF範囲・非実行member未抽出を確認する。
 * @param[in,out] context Assertion集計先。
 */
void testPeBindingDirect( TestContext &context)
{
	const auto					 raw = bindingPe( 2U) ;	// 複数INFとCAT・SYS・placeholder・EXE。
	MaintenanceEmbeddedFileTable layout ;				// 原範囲の構造観測だけ。
	DRIVERCRATE_EXPECT( context, inspectMaintenanceEmbeddedFileTable( raw, layout) == 0) ;
	DRIVERCRATE_EXPECT( context, layout.files.size() == 6U) ;
	BindingFixture fixture ;	// 元取得は非通信でだけ成功させる。
	DRIVERCRATE_EXPECT( context, fixture.start( raw) == 0) ;
	OfficialInfArchiveBinding binding ;	// 由来能力は生存sessionからだけ得る。
	DRIVERCRATE_EXPECT( context, binding.bind( *fixture.session, std::move( fixture.evidence),
											 fixture.workspace, {}) != 0) ;
	DRIVERCRATE_EXPECT( context, fixture.evidence.issuerAlive()) ;
	DRIVERCRATE_EXPECT( context, binding.bind( *fixture.session, std::move( fixture.evidence),
											 fixture.workspace, {},
											 OfficialInfContainerFormat::PE_FLAT_TABLE) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.members().size() == 2U) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) == 0) ;
	// 正例の取得失敗でも空結果を参照して試験を停止しない。
	if( binding.workspace() == nullptr || binding.members().size() != 2U) {
		return ;
	}

	DRIVERCRATE_EXPECT( context, binding.catalogs().size() == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   GetFileAttributesW( binding.workspace()->path( L"driver.cat").c_str()) !=
						   INVALID_FILE_ATTRIBUTES) ;
	// 署名補助以外の非INFはfileへ抽出しない。
	for( const auto name : std::array{L"driver.sys", L"placeholder.dll", L"utility.exe"}) {
		DRIVERCRATE_EXPECT( context, GetFileAttributesW( binding.workspace()->path( name).c_str()) ==
										INVALID_FILE_ATTRIBUTES) ;
	}

	DRIVERCRATE_EXPECT( context, binding.members()[0U].relativePath == L"f0.INF") ;
	DRIVERCRATE_EXPECT( context, binding.members()[1U].relativePath == L"f1.INF") ;
	DRIVERCRATE_EXPECT( context, binding.members()[0U].byteCount == INF_TEXT.size()) ;
	std::wstring expected ;	// 原INF範囲の共通SHA-256。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( INF_TEXT, expected) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.members()[0U].sha256 == expected &&
									binding.members()[1U].sha256 == expected) ;
	const auto	path = binding.workspace()->path( L"f1.INF") ;	// 二番目の派生INFだけを改変する。
	std::string changed( INF_TEXT) ;							// Sizeは同じで原byteを一つ変える。
	changed.front() = '!' ;
	DRIVERCRATE_EXPECT( context, changeBindingFile( path, changed)) ;
	DRIVERCRATE_EXPECT( context,
					   binding.verify( *fixture.session, fixture.workspace) == TRUST_E_BAD_DIGEST) ;
	DRIVERCRATE_EXPECT( context, changeBindingFile( path, INF_TEXT)) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) == 0) ;
	OfficialAcquisitionSession other ;	// 同じ数値IDでも異なるissuer。
	DRIVERCRATE_EXPECT( context, other.initialize( 8401U, LIMITS) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.verify( other, fixture.workspace) != 0) ;
	fixture.session.reset() ;
	DRIVERCRATE_EXPECT( context, binding.verify( other, fixture.workspace) != 0) ;
}

/** @brief 明示ZIP経路一段・二段からだけPEへ接続する。
 * @param[in,out] context Assertion集計先。
 */
void testPeBindingNested( TestContext &context)
{
	const auto							  pe = bindingPe( 2U) ;	// 最終containerだけがPE。
	const std::array<BindingZipEntry, 2U> entries{
		{{"inside/not-an-exe.zip", zipBody( pe)},
		 {"other.inf", "branch outside"}}} ;								// 形式を拡張子で推測しない。
	const auto							  first = bindingZip( entries) ;	// 明示一段の元ZIP。
	const std::array<BindingZipEntry, 1U> outerEntries{
		{{"outer.zip", zipBody( first)}}} ;			// 二段の元ZIP。
	const auto second = bindingZip( outerEntries) ;	// 最大二段の正例。
	// 各経路を独立の正常取得sessionへ結合する。
	for( std::size_t depth = 1U; depth <= 2U; ++depth) {
		BindingFixture fixture ;	// この経路だけの取得証拠。
		DRIVERCRATE_EXPECT( context, fixture.start( depth == 1U ? first : second) == 0) ;
		const std::vector<std::wstring> names =
			depth == 1U ? std::vector<std::wstring>{L"inside\\not-an-exe.zip"}
						: std::vector<std::wstring>{L"outer.zip",
													L"inside\\not-an-exe.zip"} ;	// 原member経路。
		OfficialInfArchiveBinding binding ;											// ZIPと同じ所有・検証型。
		DRIVERCRATE_EXPECT( context, binding.bind( *fixture.session, std::move( fixture.evidence),
												 fixture.workspace, names,
												 OfficialInfContainerFormat::PE_FLAT_TABLE) == 0) ;
		DRIVERCRATE_EXPECT( context, binding.members().size() == 2U) ;
		DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) == 0) ;
		DRIVERCRATE_EXPECT( context, changeBindingFile( fixture.result.inspectionPath, "changed")) ;
		DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) != 0) ;
	}
}

/** @brief 未対応・危険全表・形式違いと容量超過を部分成功にしない。
 * @param[in,out] context Assertion集計先。
 */
void testPeBindingRejections( TestContext &context)
{
	const auto							original = bindingPe( 1U) ;	// 各拒否で元正例へ戻る。
	std::vector<std::vector<std::byte>> cases ;						// 取得は正常で、PE構造だけを拒否する集合。
	auto								changed = original ;		// 原byteをコピーした変更用fixture。
	writePeBindingValue( changed, 0x84U, 0xaa64U, 2U) ;
	cases.push_back( changed) ;
	changed = original ;
	writePeBindingValue( changed, 0x98U, 0x10bU, 2U) ;
	cases.push_back( changed) ;
	changed = original ;
	writePeBindingValue( changed, 0x188U + 36U, 0x60000040U) ;
	cases.push_back( changed) ;
	changed = original ;
	std::fill_n( changed.begin() + 0x240U, 260U, std::byte{}) ;
	writePeBindingText( changed, 0x240U, "../driver.cat") ;
	cases.push_back( changed) ;
	changed = original ;
	writePeBindingValue( changed, 0x240U + 264U + 260U, 1024U * 1024U + 1U) ;
	cases.push_back( changed) ;
	MaintenanceEmbeddedFileTable table ;	// Paddingと原範囲を取得する構造結果。
	DRIVERCRATE_EXPECT( context, inspectMaintenanceEmbeddedFileTable( original, table) == 0) ;
	changed							  = original ;
	changed.at( table.blobOffset + 5U) = std::byte{1U} ;
	cases.push_back( changed) ;
	changed = original ;
	changed.resize( 0x4000U) ;
	std::copy( original.begin() + 0x240U, original.end(), changed.begin() + 0x2000U) ;
	writePeBindingValue( changed, 0x188U + 16U, 0x3e00U) ;
	cases.push_back( changed) ;
	cases.push_back( bindingPe( 65U)) ;
	// 全表の一つの異常でも全INF結果とworkspaceを空にする。
	for( const auto &raw : cases) {
		BindingFixture fixture ;	// Source hashはこの原byteへ一致する。
		DRIVERCRATE_EXPECT( context, fixture.start( raw) == 0) ;
		OfficialInfArchiveBinding rejected ;	// 部分認証を残さない。
		DRIVERCRATE_EXPECT( context, rejected.bind( *fixture.session, std::move( fixture.evidence),
												  fixture.workspace, {},
												  OfficialInfContainerFormat::PE_FLAT_TABLE) != 0) ;
		DRIVERCRATE_EXPECT( context, rejected.workspace() == nullptr && rejected.members().empty()) ;
		DRIVERCRATE_EXPECT(
			context, fixture.session->verifyAcquiredFile( fixture.evidence, fixture.workspace) == 0) ;
	}

	BindingFixture fixture ;	// 未定義形式値の拒否。
	DRIVERCRATE_EXPECT( context, fixture.start( original) == 0) ;
	OfficialInfArchiveBinding rejected ;	// 空のまま拒否する。
	DRIVERCRATE_EXPECT(
		context, rejected.bind( *fixture.session, std::move( fixture.evidence), fixture.workspace, {},
							   static_cast<OfficialInfContainerFormat>( 90U)) == E_INVALIDARG) ;
	DRIVERCRATE_EXPECT(
		context, fixture.session->verifyAcquiredFile( fixture.evidence, fixture.workspace) == 0) ;
	const std::array<BindingZipEntry, 1U> zipEntries{
		{{"a.inf", std::string( INF_TEXT)}}} ;		// ZIPをPEへfallbackしない。
	const auto	   zip = bindingZip( zipEntries) ;	// 別形式の原byte。
	BindingFixture zipFixture ;						// ZIP取得は正常。
	DRIVERCRATE_EXPECT( context, zipFixture.start( zip) == 0) ;
	DRIVERCRATE_EXPECT( context, rejected.bind( *zipFixture.session, std::move( zipFixture.evidence),
											  zipFixture.workspace, {},
											  OfficialInfContainerFormat::PE_FLAT_TABLE) != 0) ;
	DRIVERCRATE_EXPECT( context, rejected.members().empty()) ;
	const auto	   boundary = bindingPe( 64U) ;	// 全INF件数境界の正例。
	BindingFixture boundaryFixture ;			// 64件を欠かさず認証する。
	DRIVERCRATE_EXPECT( context, boundaryFixture.start( boundary) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   rejected.bind( *boundaryFixture.session, std::move( boundaryFixture.evidence),
									 boundaryFixture.workspace, {},
									 OfficialInfContainerFormat::PE_FLAT_TABLE) == 0) ;
	DRIVERCRATE_EXPECT( context, rejected.members().size() == 64U) ;
	DRIVERCRATE_EXPECT( context,
					   rejected.verify( *boundaryFixture.session, boundaryFixture.workspace) == 0) ;
}
#ifdef DRIVERCRATE_ACQUIRED_INF_NATIVE_TESTING
/** @brief 架空CATを試験所有領域へ作成する。実署名を発行しない。
 * @param[in,out] binding 非constの試験所有者。CATは封印INF集合へ追加しない。
 * @return 作成・保存・close完了ならtrue。
 */
bool createBindingNativeCat( OfficialInfArchiveBinding &binding)
{
	// 所有者自身が非constのfixtureであるため、追加fileのcleanup追跡だけへアクセスする。
	auto  *workspace = const_cast<OfficialDownloadWorkspace *>( binding.workspace()) ;
	HANDLE file		 = INVALID_HANDLE_VALUE ;	// このfixtureだけの新CAT writer。
	// 既存fileを上書きせず、部分作成もworkspaceが追跡する。
	if( workspace == nullptr || workspace->createFile( L"unbound.cat", file) != 0) {
		return false ;
	}

	const char value = 'x' ;																// 専用APIが署名を注入する架空CAT byte。
	DWORD	   written{} ;																	// 実保存量。
	const bool saved = WriteFile( file, &value, 1U, &written, nullptr) && written == 1U ;	// 全保存。
	return CloseHandle( file) && saved ;
}

/** @brief 全固定fileのwriter／deleteを試験する。
 * @param[in,out] context Assertion集計先。
 * @param[in] path 自身のfixtureの原fileまたは祖先。
 * @param[in] directory 祖先directoryならtrue。
 */
void expectBindingPinned( TestContext &context, const std::wstring &path, bool directory)
{
	// DirectoryのDELETE openはrename拒否の代用ではないため、実renameを検査する。
	if( directory) {
		const std::wstring destination = path + L".rename" ;	// 同じfixture親内の明示位置。
		DRIVERCRATE_EXPECT( context, validInfDependencyPath( path, true) &&
										validInfDependencyPath( destination, true)) ;
		const bool renamed =
			// 上書きなし。
			MoveFileExW( path.c_str(), destination.c_str(), 0U) != FALSE ;
		const DWORD error = GetLastError() ;	// 復旧前の元診断。
		DRIVERCRATE_EXPECT( context, !renamed) ;
		DRIVERCRATE_EXPECT( context,
						   error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED) ;
		// 想定外のrename成功時も同じfixture名へ戻し、元byteを壊さない。
		if( renamed) {
			DRIVERCRATE_EXPECT( context,
							   MoveFileExW( destination.c_str(), path.c_str(), 0U) != FALSE) ;
		}

		return ;
	}

	// 全元／派生leafのwriterを拒否する。
	HANDLE handle = CreateFileW(
		path.c_str(), directory ? DELETE : GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0U), nullptr) ;
	const DWORD error = GetLastError() ;	// Close前の元診断。
	DRIVERCRATE_EXPECT( context, handle == INVALID_HANDLE_VALUE) ;
	DRIVERCRATE_EXPECT( context, error == ERROR_SHARING_VIOLATION) ;
	// 想定外の取得成功でも所有handleを漏らさない。
	if( handle != INVALID_HANDLE_VALUE) {
		CloseHandle( handle) ;
	}
}

/** @brief 封印集合と旧経路の由来を、架空署名・実byte・使用中固定で分離する。
 * @param[in,out] context Assertion集計先。
 */
void testBindingNative( TestContext &context)
{
	const std::array<BindingZipEntry, 5U> entries{
		{{"root.inf",
		  std::string( INF_TEXT) +
			  "[Install]\r\nInclude=peer.inf\r\nNeeds=Shared\r\n[Missing]\r\nNeeds=Absent\r\n"},
		 {"peer.inf", std::string( INF_TEXT) + "[Shared]\r\n"},
		 {"unused.inf", std::string( INF_TEXT)},
		 {"fixture.cat", "x"},
		 {"unused.cat", "x"}}} ;			// 未訪問INF／CATも全体固定の対象。
	const auto zip = bindingZip( entries) ;	// 共通核に明示する参照を持つ原ZIP。
	const auto pe  = bindingPe( 1U) ;		// 未発見seedを持つPEの形式正例。
	// 直接・内側一／二段ZIPと直接／内側PEで同じ封印native入口を通す。
	for( std::size_t kind = 0U; kind < 5U; ++kind) {
		std::vector<std::byte>	  raw = kind >= 3U ? pe : zip ;	// 最終containerの原byte。
		std::vector<std::wstring> nested ;						// 明示経路だけの固定一覧。
		// 一段内側の最終containerを追加する。
		if( kind == 1U || kind == 2U || kind == 4U) {
			const std::array<BindingZipEntry, 1U> inner{
				{{"inner.bin", zipBody( raw)}}} ;	// 原member。
			raw = bindingZip( inner) ;
			nested.push_back( L"inner.bin") ;
		}

		// 二段の明示経路を先頭へ追加し、名前や拡張子で形式を推測しない。
		if( kind == 2U) {
			const std::array<BindingZipEntry, 1U> outer{{{"outer.bin", zipBody( raw)}}} ;	// 二段目。
			raw = bindingZip( outer) ;
			nested.insert( nested.begin(), L"outer.bin") ;
		}

		BindingFixture			  fixture ;	// 原取得と生存issuerの所有者。
		OfficialInfArchiveBinding binding ;	// 全INF封印の所有者。
		DRIVERCRATE_EXPECT( context, fixture.start( raw) == 0) ;
		DRIVERCRATE_EXPECT( context,
						   binding.bind( *fixture.session, std::move( fixture.evidence),
										fixture.workspace, nested,
										kind >= 3U ? OfficialInfContainerFormat::PE_FLAT_TABLE
												   : OfficialInfContainerFormat::ZIP) == 0) ;
		DRIVERCRATE_EXPECT( context, createBindingNativeCat( binding)) ;
		const std::array<std::wstring, 1U> seeds{L"Install"} ;	// 原明示節だけ。
		InfDependencyNativeResult		   result ;				// 非実行の確認結果。
		InfDependencyNativeTestApi		   api ;				// 専用compileだけの架空OS／署名。
		bool signedInf		   = true ;							// 署名失敗を由来から独立させる試験設定。
		bool throwSignature	   = false ;						// Callback例外で部分結果を破棄する。
		bool checkLocks		   = true ;							// 一runの最初の署名callbackで全固定を検査する。
		bool useUnboundCatalog = false ;						// 後から追加されたCATを署名元にしない拒否試験。
		api.version			   = []( OSVERSIONINFOEXW &version, SYSTEM_INFO &native) {
			   // 架空x64 clientの開始／終了文脈を同じ値で返す。
			   version.dwMajorVersion		 = 10U ;
			   version.dwBuildNumber		 = 26100U ;
			   version.wProductType			 = VER_NT_WORKSTATION ;
			   native.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 ;
			   return NativeError{} ;
		} ;
		api.windowsDirectory = [&fixture]( std::wstring &path) {
			// 実Windows起点を使わず、自身の未作成directoryだけへ限定する。
			path = fixture.workspace.path( L"windows") ;
			return NativeError{} ;
		} ;
		api.infSignature = [&]( const std::wstring &path, SP_INF_SIGNER_INFO_W &signer) {
			(void)path ;
			// 未訪問INFと元取得物の固定も、native使用中に検査する。
			if( checkLocks) {
				checkLocks = false ;
				expectBindingPinned( context, fixture.result.inspectionPath, false) ;
				// 全INFのwriterを拒否し、未訪問memberを固定から省略しない。
				for( const auto &member : binding.members()) {
					expectBindingPinned( context, binding.workspace()->path( member.relativePath),
										false) ;
				}

				// 未使用CATも同じ元byteで固定され、writerが拒否される。
				for( const auto &member : binding.catalogs()) {
					expectBindingPinned( context, binding.workspace()->path( member.relativePath),
										false) ;
				}

				const auto first =
					// 祖先位置。
					binding.workspace()->path( binding.members().front().relativePath) ;
				expectBindingPinned( context, first.substr( 0U, first.find_last_of( L'\\')), true) ;
			}

			// Callback例外を成功graphへ弱めない。
			if( throwSignature) {
				throw std::runtime_error( "fixture callback") ;
			}

			// 署名不合格でも公式由来の独立観測は維持する。
			if( !signedInf) {
				return static_cast<NativeError>( E_ACCESSDENIED) ;
			}

			const auto catalog = binding.workspace()->path(
				useUnboundCatalog ? L"unbound.cat"
								  : binding.catalogs()
										.front()
										.relativePath) ;	// 元CATと後付けCATを明示的に区別する。
			std::ranges::copy( catalog, signer.CatalogFile) ;
			signer.CatalogFile[catalog.size()] = L'\0' ;
			signer.DigitalSigner[0]			   = L'x' ;
			signer.DigitalSigner[1]			   = L'\0' ;
			return NativeError{} ;
		} ;
		api.catalogSignature = []( const std::wstring &, std::span<const std::wstring>) {
			// 実trust検査を行わない架空正例。実署名数へ加算しない。
			return NativeError{} ;
		} ;
		api.driverStore = []( const std::wstring &, std::wstring &) {
			// 今回はpackageの根拠だけを扱い、標準由来を捏造しない。
			return static_cast<NativeError>( E_NOTIMPL) ;
		} ;
		DRIVERCRATE_EXPECT( context, inspectAcquiredInfDependenciesWithTestApi(
										api, binding, *fixture.session, fixture.workspace, 0U,
										seeds, 9201U, result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.front().provenance ==
										InfDependencyEvidence::VERIFIED) ;
		DRIVERCRATE_EXPECT( context, result.dependency.plan.rootEvidenceVerified) ;
		DRIVERCRATE_EXPECT( context, result.dependency.plan.referencesResolved == (kind < 3U)) ;
		DRIVERCRATE_EXPECT( context, result.dependency.plan.actionCoverage ==
										InfDependencyEvidence::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT( context, result.dependency.plan.deviceApplicability ==
										InfDependencyEvidence::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT( context, result.dependency.plan.installRoute ==
										InfDependencyEvidence::NOT_CHECKED) ;
		// 同じworkspace内でも元containerにないCATを公式署名根拠にしない。
		useUnboundCatalog = true ;
		DRIVERCRATE_EXPECT( context, inspectAcquiredInfDependenciesWithTestApi(
										api, binding, *fixture.session, fixture.workspace, 0U,
										seeds, 9212U, result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.front().signature ==
											InfDependencyEvidence::FAILED &&
										result.dependency.documents.front().provenance ==
											InfDependencyEvidence::VERIFIED) ;
		DRIVERCRATE_EXPECT( context, result.findings.front().signatureError == E_ACCESSDENIED &&
										!result.dependency.plan.rootEvidenceVerified) ;
		useUnboundCatalog = false ;
		DRIVERCRATE_EXPECT( context, inspectAcquiredInfDependenciesWithTestApi(
										api, binding, *fixture.session, fixture.workspace, 0U,
										seeds, 9213U, result) == 0) ;
		// 原CATの改変は、署名結果以前に全体を拒否して空snapshotにする。
		const auto &catMember = binding.catalogs().back() ;	// ZIPでは未使用CATも選ぶ。
		const auto	catPath =
			// 自身の原CAT copy。
			binding.workspace()->path( catMember.relativePath) ;
		DRIVERCRATE_EXPECT( context, changeBindingFile( catPath, "changed")) ;
		DRIVERCRATE_EXPECT( context, inspectAcquiredInfDependenciesWithTestApi(
										api, binding, *fixture.session, fixture.workspace, 0U,
										seeds, 9214U, result) != 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.empty() && result.findings.empty()) ;
		const std::string originalCat =
			kind >= 3U ? std::string( "\x30\x82\x00\x01\x00", 5U) : "x" ;	// 架空原byte。
		DRIVERCRATE_EXPECT( context, changeBindingFile( catPath, originalCat)) ;
		DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) == 0) ;
		DRIVERCRATE_EXPECT( context, inspectAcquiredInfDependenciesWithTestApi(
										api, binding, *fixture.session, fixture.workspace, 0U,
										seeds, 9215U, result) == 0) ;
		// CAT復元後に再観測した全package INFの由来を同じ封印集合へ結合する。
		for( const auto &document : result.dependency.documents) {
			DRIVERCRATE_EXPECT( context, document.origin == InfDependencyOrigin::PACKAGE) ;
			DRIVERCRATE_EXPECT( context, document.provenance == InfDependencyEvidence::VERIFIED) ;
		}

		// ZIPの明示peer参照は、三証拠の正例でだけ解決済みとなる。
		if( kind < 3U) {
			DRIVERCRATE_EXPECT( context, result.dependency.edges.size() == 2U) ;
			// Include／Needsとも同じpeerの原byteへ結合したことを確認する。
			for( const auto &edge : result.dependency.edges) {
				DRIVERCRATE_EXPECT( context, edge.state == InfDependencyState::RESOLVED_PACKAGE) ;
			}
		}

		// 旧引数APIを同じbyte・架空署名で呼んでも公式由来を復元しない。
		checkLocks = false ;
		DRIVERCRATE_EXPECT( context, inspectInfDependenciesWithTestApi( api, *binding.workspace(),
																	  binding.members(), 0U, seeds,
																	  9202U, result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.front().provenance ==
										InfDependencyEvidence::NOT_CHECKED) ;
		DRIVERCRATE_EXPECT( context, !result.dependency.plan.rootEvidenceVerified) ;
		const std::array<std::wstring, 1U> missingSeeds{L"Missing"} ;	// 欠落Needsまたは欠落seed。
		DRIVERCRATE_EXPECT( context, inspectAcquiredInfDependenciesWithTestApi(
										api, binding, *fixture.session, fixture.workspace, 0U,
										missingSeeds, 9208U, result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.plan.rootEvidenceVerified &&
										!result.dependency.plan.referencesResolved) ;
		// 同じ封印結果でも署名失敗を導入可能へ昇格しない。
		signedInf = false ;
		DRIVERCRATE_EXPECT( context, inspectAcquiredInfDependenciesWithTestApi(
										api, binding, *fixture.session, fixture.workspace, 0U,
										seeds, 9203U, result) == 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.front().provenance ==
										InfDependencyEvidence::VERIFIED) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.front().signature ==
										InfDependencyEvidence::FAILED) ;
		DRIVERCRATE_EXPECT( context, result.findings.front().signatureError == E_ACCESSDENIED) ;
		DRIVERCRATE_EXPECT( context, !result.dependency.plan.rootEvidenceVerified &&
										!result.dependency.plan.referencesResolved) ;
		OfficialAcquisitionSession other ;	// 同じnumeric IDでも異なるissuer。
		DRIVERCRATE_EXPECT( context, other.initialize( 8401U, LIMITS) == 0) ;
		DRIVERCRATE_EXPECT( context, binding.inspectDependencies( other, fixture.workspace, 0U, seeds,
																9204U, result) != 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.empty() && result.findings.empty()) ;
		OfficialDownloadWorkspace otherWorkspace ;	// 同じbyteでも元位置が異なる領域。
		DRIVERCRATE_EXPECT( context, otherWorkspace.initialize( L"native-other", 8401U) == 0) ;
		DRIVERCRATE_EXPECT( context,
						   binding.inspectDependencies( *fixture.session, otherWorkspace, 0U, seeds,
													   9209U, result) == E_ACCESSDENIED) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.empty() && result.findings.empty()) ;
		DRIVERCRATE_EXPECT( context, binding.inspectDependencies( *fixture.session, fixture.workspace,
																binding.members().size(), seeds,
																9205U, result) == E_INVALIDARG) ;
		DRIVERCRATE_EXPECT( context,
						   binding.inspectDependencies( *fixture.session, fixture.workspace, 0U,
													   seeds, 0U, result) == E_INVALIDARG) ;
		// Callback例外は正の観測を全部破棄する。
		throwSignature = true ;
		DRIVERCRATE_EXPECT( context, inspectAcquiredInfDependenciesWithTestApi(
										api, binding, *fixture.session, fixture.workspace, 0U,
										seeds, 9206U, result) != 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.empty() && result.findings.empty()) ;
		// 同期borrowが終わってからsessionを破棄し、履歴や数値IDで復元できないことを試す。
		throwSignature = false ;
		DRIVERCRATE_EXPECT( context, inspectAcquiredInfDependenciesWithTestApi(
										api, binding, *fixture.session, fixture.workspace, 0U,
										seeds, 9210U, result) == 0) ;
		// 未訪問INFの改変も全体拒否し、修復後だけ同じ証拠の再照合ができる。
		const auto &last	 = binding.members().back() ;						// 一意の未訪問またはroot member。
		const auto	lastPath = binding.workspace()->path( last.relativePath) ;	// 自身の派生位置。
		DRIVERCRATE_EXPECT( context, changeBindingFile( lastPath, "changed")) ;
		DRIVERCRATE_EXPECT( context, binding.inspectDependencies( *fixture.session, fixture.workspace,
																0U, seeds, 9211U, result) != 0) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.empty() && result.findings.empty()) ;
		DRIVERCRATE_EXPECT( context, changeBindingFile( lastPath, INF_TEXT)) ;
		DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) == 0) ;
		fixture.session.reset() ;
		DRIVERCRATE_EXPECT( context, binding.inspectDependencies( other, fixture.workspace, 0U, seeds,
																9207U, result) == E_ACCESSDENIED) ;
		DRIVERCRATE_EXPECT( context, result.dependency.documents.empty() && result.findings.empty()) ;
	}
}
#endif

/** @brief CATの全byte・容量・CRC・失効と旧PE入口の互換性を検査する。
 * @param[in,out] context 署名実績とは別の構造assertion集計。
 */
void testCatalogBinding( TestContext &context)
{
	const std::array<BindingZipEntry, 4U> source{
		{{"driver/root.inf", std::string( INF_TEXT)},
		 {"driver/root.CaT", "original"},
		 {"driver/unused.cat", "unused"},
		 {"driver/ignored.sys", "never extracted"}}} ;		// 全CATを閉じる。
	const auto				  raw = bindingZip( source) ;	// 正常原ZIP。
	BindingFixture			  fixture ;						// 架空取得からのみissuerを発行する。
	OfficialInfArchiveBinding binding ;						// 同じ原metadataの所有者。
	DRIVERCRATE_EXPECT( context, fixture.start( raw) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.bind( *fixture.session, std::move( fixture.evidence),
											 fixture.workspace, {}) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.members().size() == 1U && binding.catalogs().size() == 2U) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) == 0) ;
	// Fixtureの先行失敗で非nullを仮定しない。
	if( binding.workspace() == nullptr || binding.catalogs().size() != 2U) {
		return ;
	}

	const auto &catalog = binding.catalogs().back() ;							// 使用されなくても再照合するCAT。
	const auto	path	= binding.workspace()->path( catalog.relativePath) ;	// 試験所有の派生file。
	DRIVERCRATE_EXPECT(
		context, verifyOfficialFileMetadata( path, {catalog.uncompressedSize, catalog.sha256}) == 0) ;
	DRIVERCRATE_EXPECT( context, changeBindingFile( path, "change")) ;
	DRIVERCRATE_EXPECT( context,
					   binding.verify( *fixture.session, fixture.workspace) == TRUST_E_BAD_DIGEST) ;
	DRIVERCRATE_EXPECT( context, changeBindingFile( path, "unused")) ;
	HANDLE writer =
		CreateFileW( path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
					FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 既存CATのwriter競合。
	DRIVERCRATE_EXPECT( context, writer != INVALID_HANDLE_VALUE) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) ==
									static_cast<drivercrate::NativeError>(
										HRESULT_FROM_WIN32( ERROR_SHARING_VIOLATION))) ;
	// 先行open失敗時に無効handleをcloseしない。
	if( writer != INVALID_HANDLE_VALUE) {
		const BOOL closed = CloseHandle( writer) ;	// 競合検証を終えた所有writerを一回だけ解放する。
		DRIVERCRATE_EXPECT( context, closed != FALSE) ;
	}

	OfficialInfArchiveBinding moved( std::move( binding)) ;	// INF／CATを一緒に移設する。
	DRIVERCRATE_EXPECT( context, moved.catalogs().size() == 2U &&
									moved.verify( *fixture.session, fixture.workspace) == 0) ;
	DRIVERCRATE_EXPECT( context, binding.verify( *fixture.session, fixture.workspace) != 0) ;

	std::vector<std::vector<BindingZipEntry>> cases{
		{{"root.inf", "root"}, {"empty.cat", ""}},
		{{"root.cat", "CAT only"}},
		{{"root.inf", "root"}, {"a.cat", "one"}, {"A.CAT", "two"}},
		{{"root.inf", "root"}, {"../unsafe.cat", "no extraction"}},
		{{"root.inf", "root"},
		 {"large.cat", std::string( 32U * 1024U * 1024U + 1U, 'x')}}} ;	// 個別CAT境界。
	std::vector<BindingZipEntry> many{{"root.inf", "root"}} ;			// CAT数65の拒否入力。
	// 全CAT件数境界を越える原集合を作る。
	for( std::size_t index = 0U; index < 65U; ++index) {
		many.push_back( {"c" + std::to_string( index) + ".cat", "x"}) ;
	}

	cases.push_back( std::move( many)) ;
	cases.push_back(
		{{"root.inf", "root"},
		 {"a.cat", std::string( 32U * 1024U * 1024U, 'x')},
		 {"b.cat", std::string( 32U * 1024U * 1024U, 'x')}}) ;	// INFも含め合計64 MiBを超える。
	// 各拒否でも元取得は正常にし、抽出結果と取得認証を分離する。
	for( const auto &entries : cases) {
		const auto				  rejectedRaw = bindingZip( entries) ;	// 架空拒否archive。
		BindingFixture			  rejectedFixture ;						// 元byteの取得証拠は正常。
		OfficialInfArchiveBinding rejected ;							// 部分INF／CATを公開しない。
		DRIVERCRATE_EXPECT( context, rejectedFixture.start( rejectedRaw) == 0) ;
		DRIVERCRATE_EXPECT( context, rejected.bind( *rejectedFixture.session,
												  std::move( rejectedFixture.evidence),
												  rejectedFixture.workspace, {}) != 0) ;
		DRIVERCRATE_EXPECT( context, rejected.members().empty() && rejected.catalogs().empty() &&
										rejected.workspace() == nullptr) ;
		DRIVERCRATE_EXPECT( context, rejectedFixture.evidence.issuerAlive()) ;
	}

	const std::array<BindingZipEntry, 2U> crcEntries{
		{{"root.inf", "root"}, {"root.cat", "cat"}}} ;	// CAT CRC拒否。
	auto damagedCat = bindingZip( crcEntries) ;			// 自身の原ZIP宣言だけを変更する。
	const std::array<std::byte, 4U> magic{std::byte{0x50U}, std::byte{0x4bU}, std::byte{0x01U},
										  std::byte{0x02U}} ;			// Central header。
	const auto firstHeader = std::ranges::search( damagedCat, magic) ;	// INFの中央宣言。
	DRIVERCRATE_EXPECT( context, !firstHeader.empty()) ;
	// 架空ZIPに二番目のCAT宣言が存在する場合だけCRCを変更する。
	if( !firstHeader.empty()) {
		const auto secondHeader = std::ranges::search(
			std::span( damagedCat)
				.subspan( static_cast<std::size_t>( firstHeader.begin() - damagedCat.begin()) + 46U),
			magic) ;	// CAT宣言。
		DRIVERCRATE_EXPECT( context, !secondHeader.empty()) ;
		// 元payloadとCRC宣言の差を認証hashの一致で救済しない。
		if( !secondHeader.empty()) {
			*(secondHeader.begin() + 16U) ^= std::byte{1U} ;
		}
	}

	BindingFixture			  crcFixture ;	// 改変後のarchive自体を原取得として固定する。
	OfficialInfArchiveBinding rejectedCat ;	// INFの部分成功も公開しない。
	DRIVERCRATE_EXPECT( context, crcFixture.start( damagedCat) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   rejectedCat.bind( *crcFixture.session, std::move( crcFixture.evidence),
										crcFixture.workspace, {}) != 0) ;
	DRIVERCRATE_EXPECT( context, rejectedCat.catalogs().empty() && rejectedCat.members().empty() &&
									rejectedCat.workspace() == nullptr &&
									crcFixture.evidence.issuerAlive()) ;
	std::vector<BindingZipEntry> boundary{{"root.inf", "root"}} ;	// CAT64の件数正例。
	// CAT64件を省略せず元byteへ結合する。
	for( std::size_t index = 0U; index < 64U; ++index) {
		boundary.push_back( {"c" + std::to_string( index) + ".cat", "x"}) ;
	}

	const auto				  boundaryRaw = bindingZip( boundary) ;	// 正常件数境界。
	BindingFixture			  boundaryFixture ;						// 64件を全て取得する架空issuer。
	OfficialInfArchiveBinding bounded ;								// CATをINF一覧へ混ぜない。
	DRIVERCRATE_EXPECT( context, boundaryFixture.start( boundaryRaw) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   bounded.bind( *boundaryFixture.session, std::move( boundaryFixture.evidence),
									boundaryFixture.workspace, {}) == 0) ;
	DRIVERCRATE_EXPECT( context, bounded.members().size() == 1U && bounded.catalogs().size() == 64U) ;
	DRIVERCRATE_EXPECT( context,
					   bounded.verify( *boundaryFixture.session, boundaryFixture.workspace) == 0) ;

	const auto				  pe = bindingPe( 2U) ;	// 同じ原表を旧入口と新入口で使う。
	OfficialDownloadWorkspace oldWorkspace ;		// 旧APIのINF-only領域。
	DRIVERCRATE_EXPECT( context, oldWorkspace.initialize( L"old-pe-inf", 8401U) == 0) ;
	std::vector<OfficialZipEntry> oldEntries ;	// 全INFだけの旧出力。
	MaintenanceEmbeddedFileTable  table ;		// 認証ではない原表。
	DRIVERCRATE_EXPECT( context, extractPeTableInfFiles( pe, oldWorkspace, oldEntries, table) == 0) ;
	DRIVERCRATE_EXPECT( context, oldEntries.size() == 2U &&
									GetFileAttributesW( oldWorkspace.path( L"driver.cat").c_str()) ==
										INVALID_FILE_ATTRIBUTES) ;
	OfficialDownloadWorkspace newWorkspace ;	// 新しい共通metadata領域。
	DRIVERCRATE_EXPECT( context, newWorkspace.initialize( L"new-pe-catalog", 8401U) == 0) ;
	std::vector<OfficialZipEntry> metadata ;	// 全INF＋CATの出力。
	DRIVERCRATE_EXPECT( context,
					   extractOfficialInfMetadata( pe, OfficialInfContainerFormat::PE_FLAT_TABLE,
												  newWorkspace, metadata) == 0) ;
	DRIVERCRATE_EXPECT( context, metadata.size() == 3U &&
									GetFileAttributesW( newWorkspace.path( L"driver.cat").c_str()) !=
										INVALID_FILE_ATTRIBUTES) ;
	// 共通metadataの原範囲と旧全INFのbyteを全て照合する。
	for( const auto &entry : oldEntries) {
		const auto found = std::ranges::find_if( metadata, [&entry]( const auto &candidate) {
			// 同じ原名だけを比較し、CATをINFとして数えない。
			return candidate.relativePath == entry.relativePath ;
		}) ; // 原範囲から得た同期metadata。
		DRIVERCRATE_EXPECT( context, found != metadata.end()) ;
		DRIVERCRATE_EXPECT( context, found != metadata.end() && found->sha256 == entry.sha256 &&
										found->uncompressedSize == entry.uncompressedSize) ;
	}
}
/** @brief 用途別hashの既存上限と新container上限を独立して検証する。
 * @param[in,out] context driver署名実績とは別のhash集計。
 */
void testContainerHash( TestContext &context)
{
	const std::string bytes( 2U * 1024U * 1024U, 'x') ;	// 旧原byte上限を越える架空入力。
	std::wstring	  hash ;							// 各失敗で空へ戻る共通結果。
	DRIVERCRATE_EXPECT( context, computeDriverContainerSha256( bytes, hash) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   hash == L"6932fd31e5daf4739b9fa78ff777b2831b0995cc1d0b0093cac80601902013bc") ;
	DRIVERCRATE_EXPECT( context, computeBytesSha256( bytes, hash) == E_INVALIDARG && hash.empty()) ;
	const std::string boundary( 128U * 1024U * 1024U + 1U, 'x') ;	// 上限＋一byteの同じ架空入力。
	DRIVERCRATE_EXPECT( context,
					   computeDriverContainerSha256(
						   std::string_view( boundary).substr( 0U, boundary.size() - 1U), hash) == 0) ;
	DRIVERCRATE_EXPECT( context,
					   hash == L"8fb4c93e9cdd636cfe06929df7ec7cc521fe3fd3affdfe81fc13d8fcb737d26a") ;
	DRIVERCRATE_EXPECT( context, computeDriverContainerSha256( boundary, hash) == E_INVALIDARG &&
									hash.empty()) ;
	DRIVERCRATE_EXPECT( context,
					   computeDriverContainerSha256( {}, hash) == E_INVALIDARG && hash.empty()) ;
	DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( boundary, hash) == E_INVALIDARG &&
									hash.empty()) ;
}
} // namespace
} // namespace drivercrate::test

/** @brief 架空取得から全INF封印と拒否境界を独立試験する。
 * @return 全assertion成功0、失敗または例外1。
 */
int main()
{
	static_assert( !std::is_copy_constructible_v<drivercrate::OfficialInfArchiveBinding>) ;
	static_assert( std::is_nothrow_move_constructible_v<drivercrate::OfficialInfArchiveBinding>) ;
	try {
		drivercrate::test::TestContext context ;	// このprocessの集計だけ。
		drivercrate::test::testBindingDirect( context) ;
		drivercrate::test::testBindingNested( context) ;
		drivercrate::test::testBindingRejections( context) ;
		drivercrate::test::testBindingBoundaries( context) ;
		drivercrate::test::testBindingJunction( context) ;
		std::cout << "Sealed ZIP assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		drivercrate::test::TestContext peContext ;	// 旧ZIP件数と分離するPEの新しい集計。
		drivercrate::test::testPeBindingDirect( peContext) ;
		drivercrate::test::testPeBindingNested( peContext) ;
		drivercrate::test::testPeBindingRejections( peContext) ;
		std::cout << "Sealed PE assertions: " << peContext.assertionCount()
				  << ", failures: " << peContext.failureCount() << '\n' ;
		drivercrate::test::TestContext catalogContext ;	// CAT抽出と原byteの独立集計。
		drivercrate::test::testCatalogBinding( catalogContext) ;
		std::cout << "Sealed catalog assertions: " << catalogContext.assertionCount()
				  << ", failures: " << catalogContext.failureCount() << '\n' ;
		drivercrate::test::testContainerHash( catalogContext) ;
		std::cout << "Catalog and container hash assertions: " << catalogContext.assertionCount()
				  << ", failures: " << catalogContext.failureCount() << '\n' ;
#ifdef DRIVERCRATE_ACQUIRED_INF_NATIVE_TESTING
		drivercrate::test::TestContext nativeContext ;	// 架空native接続だけの独立集計。
		drivercrate::test::testBindingNative( nativeContext) ;
		std::cout << "Sealed native assertions: " << nativeContext.assertionCount()
				  << ", failures: " << nativeContext.failureCount() << '\n' ;
		// 新規接続の拒否／正例を旧形式試験と同じ終了値へ結合する。
		if( nativeContext.failureCount() != 0) {
			return 1 ;
		}
#endif
		return context.failureCount() == 0 && peContext.failureCount() == 0 &&
					   catalogContext.failureCount() == 0
				   ? 0
				   : 1 ;
	} catch( ...) {
		// Fixtureのraw path・本文を出さず、例外を失敗終了値で保持する。
		std::cerr << "Sealed ZIP fixture failure.\n" ;
		return 1 ;
	}
}
