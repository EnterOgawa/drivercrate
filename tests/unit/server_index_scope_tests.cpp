//------------------------------------------------------------------------------
/**
 * @file server_index_scope_tests.cpp
 * @brief 同INFのServer版/product条件と非権限Models tupleを決定的に検査します
 * @version 01.02.01
 * @date 2026/11/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/17  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/17  未終端hiddenと共通数値空白参照の正負を追加
 * Ver.01.02.00 Shunji Ogawa  2026/11/18  P3同scan fullhost観測と取得直前拒否を接続
 * Ver.01.02.01 Shunji Ogawa  2026/11/18  SDK fakeの引数ABIとcatch外の全呼出し期待を固定
 * </pre>
 * @note 架空INF出典と条件だけです。host/Models API/HTTP/driver/導入を実行しません
 * @see docs/adr/0508-exact-server-release-collection-and-acquisition.md
 */
//------------------------------------------------------------------------------
#include "platform/server_index_scope.h"
#include "platform/windows_product_type_internal.h"
#include "test_framework.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>

namespace {
using namespace drivercrate ;
using drivercrate::test::TestContext ;

/** @brief 一呼出しの全SDK fake値をthread内だけで所有します */
struct HostApiState {
	/// 0正常、1module拒否、2entry拒否、3例外です
	unsigned	  mode{} ;
	/// 原Win32 codeです。0も失敗のまま保持します
	DWORD		  error{} ;
	/// 元NTSTATUSのbit patternです
	std::uint32_t status{} ;
	/// SDKへ返す元suiteです
	WORD		  suite{} ;
	/// SDKへ返す元architectureです
	WORD		  architecture{9U} ;
	/// void APIを実際に呼んだ回数です
	unsigned	  architectureCalls{} ;
	/// 引数又はABI違反を製品側catchから独立に保持します
	bool		  contractValid{true} ;
	/// module境界へ到達した回数です
	unsigned	  moduleCalls{} ;
	/// entry境界へ到達した回数です
	unsigned	  entryCalls{} ;
	/// version境界へ到達した回数です
	unsigned	  versionCalls{} ;
	/// 原Win32 error読取り境界へ到達した回数です
	unsigned	  errorCalls{} ;
	/// versionのbufferが非nullだった原観測です
	bool		  versionBufferNonNull{} ;
	/// versionがwrite前に読んだ元cbSizeです
	DWORD		  versionBufferBytes{} ;
	/// architectureのbufferが非nullだった原観測です
	bool		  architectureBufferNonNull{} ;
} ;
thread_local HostApiState hostApi ;	// native依存を持たない完全fakeです

//------------------------------------------------------------------------------
/**
 * @brief 元SDK署名のversion情報を人工値だけで満たします
 * @param[in,out] value 非nullかつ元cbSizeがsizeof(OSVERSIONINFOEXW)の同期bufferです
 * @return 正しいABIだけ人工NTSTATUSです。引数不正は書込みなしのSTATUS_INVALID_PARAMETERです
 */
//------------------------------------------------------------------------------
LONG WINAPI				  hostVersion( PRTL_OSVERSIONINFOW value)
{
	++hostApi.versionCalls ;
	hostApi.versionBufferNonNull = value != nullptr ;
	// NULLのbufferを読まず、意図した例外より前に契約違反を固定します
	if( !value) {
		hostApi.contractValid = false ;
		return static_cast<LONG>( 0xC000000DU) ;
	}

	hostApi.versionBufferBytes = value->dwOSVersionInfoSize ;
	// 小さい旧structへ拡張fieldを書かず、observerのcatchで違反を隠させません
	if( value->dwOSVersionInfoSize != sizeof( OSVERSIONINFOEXW)) {
		hostApi.contractValid = false ;
		return static_cast<LONG>( 0xC000000DU) ;
	}

	// mode3だけは正しい引数とABIの確認後に意図した例外を発生させます
	if( hostApi.mode == 3U) {
		throw std::runtime_error( "fake version") ;
	}

	auto &extended			= *reinterpret_cast<OSVERSIONINFOEXW *>( value) ;	// 実SDK layoutです
	extended.dwMajorVersion = 10U ;
	extended.dwMinorVersion = 0U ;
	extended.dwBuildNumber	= 26100U ;
	extended.wProductType	= 3U ;
	extended.wSuiteMask		= hostApi.suite ;
	return static_cast<LONG>( hostApi.status) ;
}
//------------------------------------------------------------------------------
/**
 * @brief ntdllの非所有人工handle又は失敗を返します
 * @param[in] name literal L"ntdll.dll"だけを受理する同期module名です
 * @return 正しい名前だけ人工handle又は指定失敗です。不正名はnullptrで契約違反を保持します
 */
//------------------------------------------------------------------------------
HMODULE WINAPI hostModule( LPCWSTR name)
{
	++hostApi.moduleCalls ;
	// 元module名の誤りを同じfake成功へ変換しません
	if( !name || std::wstring_view{name} != L"ntdll.dll") {
		hostApi.contractValid = false ;
		return nullptr ;
	}

	return hostApi.mode == 1U ? nullptr : reinterpret_cast<HMODULE>( 1U) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 人工RtlGetVersionのaddressだけを返します
 * @param[in] module 直前に返したfake HMODULE1だけを受理します
 * @param[in] name literal "RtlGetVersion"だけを受理する同期entry名です
 * @return 正しい引数だけ完全fake又は指定失敗です。不正引数はnullptrで契約違反を保持します
 */
//------------------------------------------------------------------------------
FARPROC WINAPI hostEntry( HMODULE module, LPCSTR name)
{
	++hostApi.entryCalls ;
	// 別moduleや別entryを同じversion観測へ通しません
	if( module != reinterpret_cast<HMODULE>( 1U) || !name ||
	   std::string_view{name} != "RtlGetVersion") {
		hostApi.contractValid = false ;
		return nullptr ;
	}

	return hostApi.mode == 2U ? nullptr : reinterpret_cast<FARPROC>( &hostVersion) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 最後の人工Win32 codeを返します
 * @return 0を含む固定の元値です
 */
//------------------------------------------------------------------------------
DWORD WINAPI hostError()
{
	++hostApi.errorCalls ;
	return hostApi.error ;
}
//------------------------------------------------------------------------------
/**
 * @brief SDKのvoid境界へ人工native architectureを返します
 * @param[out] value 非nullのSYSTEM_INFOだけへ書きます。不正時は書込みなしで契約違反を保持します
 */
//------------------------------------------------------------------------------
void WINAPI hostArchitecture( LPSYSTEM_INFO value)
{
	++hostApi.architectureCalls ;
	hostApi.architectureBufferNonNull = value != nullptr ;
	// void APIのNULL引数は書かず、永続flagをcatch外のassertで検出します
	if( !value) {
		hostApi.contractValid = false ;
		return ;
	}

	value->wProcessorArchitecture = hostApi.architecture ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原domain/codeと観測成功を独立した十一入力で確認します
 * @param[in,out] context 共通assertion集計先です
 */
//------------------------------------------------------------------------------
void testFullHostObserver( TestContext &context)
{
	const std::array<std::string_view, 11U> ids{
		"COMPLETE_SUITE0",		 "COMPLETE_NONZERO_SUITE", "MODULE_WIN32_126", "ENTRY_WIN32_127",
		"RTL_NTSTATUS_C0000001", "MODULE_FAILED_RAW0",	   "MISSING_CALLBACK", "THROWING_CALLBACK",
		"OBSERVED_ARCH_UNKNOWN", "OBSERVED_ARM64",		   "OBSERVED_X86"} ;	// 独立分母です
	const std::array<std::array<unsigned, 5U>, 11U> expectedCalls{
		{{1U, 1U, 1U, 0U, 1U},
		 {1U, 1U, 1U, 0U, 1U},
		 {1U, 0U, 0U, 1U, 0U},
		 {1U, 1U, 0U, 1U, 0U},
		 {1U, 1U, 1U, 0U, 0U},
		 {1U, 0U, 0U, 1U, 0U},
		 {0U, 0U, 0U, 0U, 0U},
		 {1U, 1U, 1U, 0U, 0U},
		 {1U, 1U, 1U, 0U, 1U},
		 {1U, 1U, 1U, 0U, 1U},
		 {1U, 1U, 1U, 0U, 1U}}} ;	// module/entry/version/error/architectureの独立literal期待です
	// 実OS APIへのfallbackを作らず各完全SDK fakeだけを呼びます
	for( std::size_t index = 0U; index < ids.size(); ++index) {
		// 前caseの成功を借りません
		hostApi = {} ;
		WindowsHostPlatformApi api{&hostModule, &hostEntry, &hostError,
								   &hostArchitecture} ;	// 四境界を全置換します
		// 固定caseに対応する元値だけを変更します
		if( index == 1U) {
			hostApi.suite = 256U ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( index == 2U || index == 5U) {
			hostApi.mode  = 1U ;
			hostApi.error = index == 2U ? 126U : 0U ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( index == 3U) {
			hostApi.mode  = 2U ;
			hostApi.error = 127U ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( index == 4U) {
			hostApi.status = 0xC0000001U ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( index == 6U) {
			api.architecture = nullptr ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( index == 7U) {
			hostApi.mode = 3U ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( index >= 8U) {
			hostApi.architecture = index == 8U ? 0xFFFFU : index == 9U ? 12U : 0U ;
		}

		const auto		 result = observeWindowsHostPlatform( api) ;	// 実SDK型のpure fake経路です
		const std::array actualCalls{hostApi.moduleCalls, hostApi.entryCalls, hostApi.versionCalls,
									 hostApi.errorCalls,
									 hostApi.architectureCalls} ;	// catchを越えて残る実呼出しです
		DRIVERCRATE_EXPECT( context, hostApi.contractValid) ;
		DRIVERCRATE_EXPECT( context, actualCalls == expectedCalls[index]) ;
		DRIVERCRATE_EXPECT( context,
						   hostApi.versionBufferNonNull == (expectedCalls[index][2] != 0U) &&
							   hostApi.versionBufferBytes ==
								   (expectedCalls[index][2] != 0U ? sizeof( OSVERSIONINFOEXW) : 0U)) ;
		DRIVERCRATE_EXPECT( context,
						   hostApi.architectureBufferNonNull == (expectedCalls[index][4] != 0U)) ;
		// 最初の二入力は六fieldと原NTSTATUS0を独立literalへ照合します
		if( index < 2U) {
			const WindowsHostPlatform expected{10U, 0U, 26100U, 9U, 3U,
											   // helper由来でない全tupleです
											   static_cast<std::uint16_t>( index == 1U ? 256U : 0U)} ;
			DRIVERCRATE_EXPECT( context, result.state == WindowsHostObservationState::OBSERVED &&
											result.value && *result.value == expected &&
											result.domain == WindowsHostErrorDomain::NTSTATUS &&
											result.rawBits == 0U &&
											hostApi.architectureCalls == 1U) ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( index == 2U || index == 3U || index == 5U) {	// 原code0でも失敗のままです
			DRIVERCRATE_EXPECT( context, result.state == WindowsHostObservationState::API_FAILED &&
											!result.value &&
											result.domain == WindowsHostErrorDomain::WIN32_CODE &&
											result.rawBits == (index == 2U	 ? 126U
															   : index == 3U ? 127U
																			 : 0U) &&
											hostApi.architectureCalls == 0U) ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( index == 4U) {	// HRESULTへ変換して元codeと呼びません
			DRIVERCRATE_EXPECT(
				context, result.state == WindowsHostObservationState::API_FAILED && !result.value &&
							 result.domain == WindowsHostErrorDomain::NTSTATUS &&
							 result.rawBits == 0xC0000001U && hostApi.architectureCalls == 0U) ;
		}
		// 元固定faultだけを設定し、他caseの成功や分類を借りません
		else if( index == 6U || index == 7U) {	// 欠落/例外をnative APIで補完しません
			DRIVERCRATE_EXPECT( context,
							   result.state == WindowsHostObservationState::UNOBSERVED &&
								   !result.value && result.domain == WindowsHostErrorDomain::NONE &&
								   result.rawBits == 0U && hostApi.architectureCalls == 0U) ;
		} else {										 // API観測成功とローカル対応可否を分けます
			const auto gate = classifyIndexHost( result) ;	// 実分類だけを照合します
			DRIVERCRATE_EXPECT(
				context, result.state == WindowsHostObservationState::OBSERVED && result.value &&
							 result.value->nativeArchitecture == hostApi.architecture &&
							 hostApi.architectureCalls == 1U &&
							 gate.state == (index == 8U ? IndexHostGateState::UNKNOWN
														: IndexHostGateState::UNSUPPORTED)) ;
		}

		std::cout << "P3 observer " << ids[index] << '\n' ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 架空の一INF根拠を作ります
 * @return 二種類の架空PnP IDと元INF hashを持つ所有申告です
 */
//------------------------------------------------------------------------------
IndexPublishedIdentityEvidence fixtureIdentity()
{
	IndexPublishedIdentityEvidence value ;	// 同recordに結ぶ人工INFです
	value.state			 = IndexEvidenceState::PUBLISHED ;
	value.kind			 = IndexIdentityEvidenceKind::INF ;
	value.classGuid		 = "{11111111-2222-3333-4444-555555555555}" ;
	value.infIdentity	 = "fixture.inf" ;
	value.modelSection	 = "Fixture.NTamd64.10.0" ;
	value.pnpIds		 = {{IndexPnpIdKind::HARDWARE, "SYNTHETIC\\P1_FIXTURE"},
							{IndexPnpIdKind::COMPATIBLE, "SYNTHETIC\\P1_COMPAT"}} ;
	value.evidenceUrl	 = "https://vendor.example/fixture.inf" ;
	value.evidenceSha256 = IndexManifestSha256{} ;
	value.evidenceSha256->fill( 0x42U) ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief producer builderを使わず独立したraw条件の期待を作ります
 * @param[in] name canonical版名または負例literalです
 * @param[in] product productの原literalです
 * @param[in] identity 同recordの人工INF根拠です
 * @return 各literalを同根拠へ結んだ最大三条件です
 */
//------------------------------------------------------------------------------
IndexAcquisitionPrerequisites literalConditions( const std::string_view				  name,
												const std::string_view				  product,
												const IndexPublishedIdentityEvidence &identity)
{
	IndexAcquisitionPrerequisites value ;	// 実scope builderから期待値を逆算しません
	value.state = IndexDescriptorState::KNOWN ;
	value.items = {{IndexPrerequisiteKind::LOCAL_CHECK,
					"DriverCrate:target-os=" + std::string{name}, identity.evidenceUrl,
					*identity.evidenceSha256},
				   {IndexPrerequisiteKind::LOCAL_CHECK,
					"DriverCrate:target-product-type=" + std::string{product}, identity.evidenceUrl,
					*identity.evidenceSha256},
				   {IndexPrerequisiteKind::LOCAL_CHECK, "DriverCrate:models-observed-suite=0",
					identity.evidenceUrl, *identity.evidenceSha256}} ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 四版のDC/Server八scopeを同generic Modelsでも分離して確認します
 * @param[in,out] context 全期待の集計先です
 */
//------------------------------------------------------------------------------
void testEightScopes( TestContext &context)
{
	const auto		 identity = fixtureIdentity() ;	// 同一INF/Modelsのままproductを分けます
	const std::array names{"WINDOWS_SERVER_2016", "WINDOWS_SERVER_2019", "WINDOWS_SERVER_2022",
						   "WINDOWS_SERVER_2025"} ;				// 独立期待です
	const std::array builds{14393U, 17763U, 20348U, 26100U} ;	// 最低build範囲ではありません
	// 四releaseそれぞれでDCとServerを独立したclaimとして確認します
	for( std::size_t index = 0U; index < names.size(); ++index) {
		std::optional<ServerIndexScope> previous ;	// 同じINFのDC/Server差を保持します
		// 明示した2/3以外のproductを生成しません
		for( const auto product : {2U, 3U}) {
			const auto literal = literalConditions( names[index], std::to_string( product),
												   identity) ;	// 原wire期待です
			const auto scope =
				// 同INFの条件を読む実経路です
				readServerIndexScope( identity, literal) ;
			DRIVERCRATE_EXPECT( context, scope.has_value()) ;
			// 前段拒否をdereferenceで隠さず、当該期待の残りだけを止めます
			if( !scope) {
				continue ;
			}

			DRIVERCRATE_EXPECT( context,
							   scope->productType == product && scope->modelsObservedSuite == 0U) ;
			DRIVERCRATE_EXPECT( context, serverIndexReleaseName( scope->release) == names[index]) ;
			const auto platform = serverIndexModelsPlatform( *scope) ;	// APIを呼ばない完全tupleです
			DRIVERCRATE_EXPECT( context, platform.has_value()) ;
			// build/major/minor/archとproductを全て独立期待へ照合します
			if( platform) {
				DRIVERCRATE_EXPECT(
					context, platform->majorVersion == 10U && platform->minorVersion == 0U &&
								 platform->buildNumber == builds[index] &&
								 platform->processorArchitecture == 9U &&
								 platform->productType == product && platform->suiteMask == 0U) ;
			}

			const auto built =
				// producer側の独立検査です
				makeServerIndexPrerequisites( *scope, identity) ;
			DRIVERCRATE_EXPECT( context, built && built->items.size() == 3U) ;
			// 生成条件は順序とINF根拠を原literalに全件照合します
			if( built && built->items.size() == 3U) {
				// 同一indexの三条件だけを比較し、省略や他productへの丸めを検出します
				for( std::size_t condition = 0U; condition < 3U; ++condition) {
					DRIVERCRATE_EXPECT( context, built->items[condition].description ==
														literal.items[condition].description &&
													built->items[condition].evidenceUrl ==
														identity.evidenceUrl &&
													built->items[condition].evidenceSha256 ==
														*identity.evidenceSha256) ;
				}
			}

			// 同generic節/同INFでもproduct2と3は同じscopeではありません
			if( previous) {
				DRIVERCRATE_EXPECT( context, *previous != *scope) ;
			}

			previous = scope ;
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 各条件の欠落/重複/別INF根拠と上限・未知値を拒否します
 * @param[in,out] context 全期待の集計先です
 */
//------------------------------------------------------------------------------
void testScopeRejections( TestContext &context)
{
	const auto identity = fixtureIdentity() ;	// 元scopeを変えず条件だけを故障させます
	const auto original =
		// 同client buildのServerです
		literalConditions( "WINDOWS_SERVER_2025", "3", identity) ;
	// 各必須条件を独立に壊し、他の二条件で補完されないことを確認します
	for( std::size_t index = 0U; index < 3U; ++index) {
		auto missing = original ;	// 欠落の人工入力です
		missing.items.erase( missing.items.begin() + static_cast<std::ptrdiff_t>( index)) ;
		DRIVERCRATE_EXPECT( context, !readServerIndexScope( identity, missing)) ;
		auto duplicate = original ;	// 同じliteralでも重複を許しません
		duplicate.items.push_back( original.items[index]) ;
		DRIVERCRATE_EXPECT( context, !readServerIndexScope( identity, duplicate)) ;
		auto otherUrl					  = original ;	// hashだけ一致する別INF URLです
		otherUrl.items[index].evidenceUrl = "https://vendor.example/other.inf" ;
		DRIVERCRATE_EXPECT( context, !readServerIndexScope( identity, otherUrl)) ;
		auto otherHash = original ;	// 同URLでも別byteの条件です
		otherHash.items[index].evidenceSha256[0] ^= 1U ;
		DRIVERCRATE_EXPECT( context, !readServerIndexScope( identity, otherHash)) ;
	}

	// client/generic/未採用版をexact Serverへ変換しません
	for( const auto *name : {"WINDOWS_11", "WINDOWS_SERVER", "WINDOWS_SERVER_2040"}) {
		DRIVERCRATE_EXPECT( context,
						   !readServerIndexScope( identity, literalConditions( name, "3", identity))) ;
	}

	// 非1という判定や数字prefixで未知productを通しません
	for( const auto *product : {"1", "0", "4", "02", "3x"}) {
		DRIVERCRATE_EXPECT( context,
						   !readServerIndexScope( identity, literalConditions( "WINDOWS_SERVER_2025",
																			 product, identity))) ;
	}

	auto unknown = original ;	// 未登録LOCAL_CHECKは同意へ読み替えません
	unknown.items.push_back( {IndexPrerequisiteKind::LOCAL_CHECK, "DriverCrate:future-check=1",
							 identity.evidenceUrl, *identity.evidenceSha256}) ;
	DRIVERCRATE_EXPECT( context, !readServerIndexScope( identity, unknown)) ;
	auto generic = original ;	// exact/generic併記も重複成功へ丸めません
	generic.items.push_back( {IndexPrerequisiteKind::LOCAL_CHECK,
							 "DriverCrate:target-os=WINDOWS_SERVER", identity.evidenceUrl,
							 *identity.evidenceSha256}) ;
	DRIVERCRATE_EXPECT( context, !readServerIndexScope( identity, generic)) ;
	auto suite = original ;	// producer非zero観測は未採用で、host suiteの試験ではありません
	suite.items[2].description = "DriverCrate:models-observed-suite=2" ;
	DRIVERCRATE_EXPECT( context, !readServerIndexScope( identity, suite)) ;
	auto otherInf = identity ;	// 元INF byte自体が異なる場合です
	otherInf.evidenceSha256->at( 0U) ^= 1U ;
	DRIVERCRATE_EXPECT( context, !readServerIndexScope( otherInf, original)) ;
	otherInf	  = identity ;
	otherInf.kind = IndexIdentityEvidenceKind::CATALOG ;
	DRIVERCRATE_EXPECT( context, !readServerIndexScope( otherInf, original)) ;
	otherInf	   = identity ;
	otherInf.state = IndexEvidenceState::UNKNOWN ;
	DRIVERCRATE_EXPECT( context, !readServerIndexScope( otherInf, original)) ;
	auto unknownState  = original ;	// 条件UNKNOWNも空成功へしません
	unknownState.state = IndexDescriptorState::UNKNOWN ;
	DRIVERCRATE_EXPECT( context, !readServerIndexScope( identity, unknownState)) ;
	std::array<IndexAcquisitionPrerequisite, 14U> extras ;	// 13件なら三条件と合計16、14件なら17です
	// 元USER_CONFIRMATIONを全件保持する上限境界です
	for( auto &condition : extras) {
		condition = {IndexPrerequisiteKind::USER_CONFIRMATION, "Confirm fixture prerequisite",
					 identity.evidenceUrl, *identity.evidenceSha256} ;
	}

	const ServerIndexScope scope{ServerIndexRelease::WINDOWS_SERVER_2025, 3U, 0U} ;	// 明示scopeです
	const auto			   maximum =
		// 合計16です
		makeServerIndexPrerequisites( scope, identity, std::span{extras}.first( 13U)) ;
	DRIVERCRATE_EXPECT( context, maximum && maximum->items.size() == 16U &&
									readServerIndexScope( identity, *maximum)) ;
	DRIVERCRATE_EXPECT( context, !makeServerIndexPrerequisites( scope, identity, extras)) ;
	auto seventeen = original ;	// readerも17件を走査前に拒否します
	seventeen.items.insert( seventeen.items.end(), extras.begin(), extras.end()) ;
	DRIVERCRATE_EXPECT( context, !readServerIndexScope( identity, seventeen)) ;
	DRIVERCRATE_EXPECT(
		context, !serverIndexModelsPlatform( {ServerIndexRelease::WINDOWS_SERVER_2025, 1U, 0U})) ;
	DRIVERCRATE_EXPECT( context, !serverIndexModelsPlatform( {ServerIndexRelease::UNKNOWN, 3U, 0U})) ;
	DRIVERCRATE_EXPECT(
		context, !serverIndexModelsPlatform( {ServerIndexRelease::WINDOWS_SERVER_2025, 3U, 2U})) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Catalogのexact名と非本文/generic/別版を区別します
 * @param[in,out] context 全期待の集計先です
 */
//------------------------------------------------------------------------------
void testCatalogEvidence( TestContext &context)
{
	const auto release = ServerIndexRelease::WINDOWS_SERVER_2025 ;	// actual hostではありません
	DRIVERCRATE_EXPECT( context,
					   catalogHasServerIndexRelease( L"AMD64 Windows Server 2025", release)) ;
	DRIVERCRATE_EXPECT( context,
					   catalogHasServerIndexRelease( L"AMD64 Windows&#32;Server&#32;2025", release)) ;
	DRIVERCRATE_EXPECT(
		context, catalogHasServerIndexRelease( L"AMD64 Windows&#x20;Server&#x20;2025", release)) ;
	DRIVERCRATE_EXPECT(
		context, catalogHasServerIndexRelease( L"AMD64 Windows&#00032;Server&#X020;2025", release)) ;
	DRIVERCRATE_EXPECT( context, catalogHasServerIndexRelease(
									L"<div>WINDOWS&nbsp;SERVER <b>2025</b></div>", release)) ;
	// 別版/将来継承/client同buildや非本文をexact版根拠へ転用しません
	for( const auto *text :
		{L"AMD64 Windows Server", L"Windows Server 2022 and later", L"Windows 11 26100",
		 L"<script>Windows Server 2025</script>Windows Server 2022",
		 L"<!-- Windows Server 2025 --> Windows Server", L"Windows Server 20250"}) {
		DRIVERCRATE_EXPECT( context, !catalogHasServerIndexRelease( text, release)) ;
	}

	// 未終端の非本文だけにある版名はtag除去後にも根拠へしません
	for( const auto *hidden : {L"script", L"style", L"template", L"noscript"}) {
		const auto body =
			L"AMD64 <" + std::wstring{hidden} + L">Windows Server 2025" ;	// 閉じない固定負例です
		DRIVERCRATE_EXPECT( context, !catalogHasServerIndexRelease( body, release)) ;
	}

	DRIVERCRATE_EXPECT( context,
					   !catalogHasServerIndexRelease( L"AMD64 <!--Windows Server 2025", release)) ;
	DRIVERCRATE_EXPECT( context,
					   catalogHasServerIndexRelease( L"AMD64 Windows Server 2022 and later",
													ServerIndexRelease::WINDOWS_SERVER_2022)) ;

	DRIVERCRATE_EXPECT( context, !catalogHasServerIndexRelease( L"Windows Server 2025",
															  ServerIndexRelease::UNKNOWN)) ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 全非通信scope試験を実行し集計します
 * @return 全期待成立0、失敗/例外1です
 * @note 外部driver本文や実host/API/取得/導入へ接続しません
 */
//------------------------------------------------------------------------------
int main()
{
	try {
		TestContext context ;	// このprocessの集計だけを所有します
		testEightScopes( context) ;
		testScopeRejections( context) ;
		testCatalogEvidence( context) ;
		testFullHostObserver( context) ;
		std::cout << "Assertions: " << context.assertionCount()
				  << ", failures: " << context.failureCount() << '\n' ;
		return context.failureCount() == 0 ? 0 : 1 ;
	} catch( const std::exception &error) {
		std::cerr << "Server scope fixture exception: " << error.what() << '\n' ;
		return 1 ;
	} catch( ...) {
		std::cerr << "Server scope fixture unknown exception\n" ;
		return 1 ;
	}
}
