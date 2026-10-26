//------------------------------------------------------------------------------
/**
 * @file local_collector_collection_store_tests.cpp
 * @brief 親writer・子lease・保護階層を自身の実file fixtureで検査します。
 * @version 01.01.05
 * @date 2026/10/01
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/01  親排他・寿命・marker／ACL／link拒否を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  同親history配置の独立引数と保護拒否fixtureを追加。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.01.02   Shunji Ogawa  2026/10/18 既知fixtureの本文・保護・改変I/Oを長path表記へ揃える。
 * Ver.01.01.03   Shunji Ogawa  2026/10/18 既知fixtureの存在照会で長pathと不存在の判定を区別する。
 * Ver.01.01.04   Shunji Ogawa  2026/10/18 関数localのmount point wire型に所有権と配置契約を追記。
 * Ver.01.01.05 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * </pre>
 *
 * @note 自身がwork/tmpに新規作成した架空fileだけを変更し、実通信・導入は行いません。
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_collection_store.h"
#include "test_framework.h"
#include <Windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winioctl.h>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::test {
namespace {
/** @brief OSが返したsecurity descriptorを解放します。 */
struct FreeMemory {
	/** @brief LocalAlloc系のbufferを返します。
	 * @param[in] value 所有している非null buffer。
	 */
	void operator()( void *value) const noexcept
	{
		LocalFree( value) ;
	}
} ;
/**
 * @brief LocalAlloc系の所有領域をscope終端でLocalFreeへ返す。
 */
using Memory = std::unique_ptr<void, FreeMemory> ;
/** @brief Fixtureで開いたWin32 handleを回収します。 */
struct FreeHandle {
	/** @brief 有効handleを一回閉じます。
	 * @param[in] value nullへ正規化済みownerの非null値。
	 */
	void operator()( void *value) const noexcept
	{
		CloseHandle( value) ;
	}
} ;
/**
 * @brief 所有したWindows handleをscope終端で解放する。解放手順と無効値はFreeHandleに従う。
 */
using Handle = std::unique_ptr<void, FreeHandle> ;
/** @brief Fixture setupの不成立を試験失敗として停止します。
 * @param[in] ok 必須の作成・照会が成立した場合true。
 * @throws std::runtime_error 必須setupが不成立の場合。
 */
void require( bool ok)
{
	// 未実施条件をassertion成功へ数えません。
	if( !ok) {
		throw std::runtime_error( "collection store fixture setup failed") ;
	}
}
/** @brief 架空keyを有限ASCII hash表現で作ります。
 * @param[in] number Fixture内の小さい非秘密identity。
 * @return 64桁の架空key。実SHA証明ではありません。
 */
std::wstring key( std::size_t number)
{
	const auto suffix = std::to_wstring( number) ;	// Fixtureだけの一意な末尾です。
	return std::wstring( 64U - suffix.size(), L'0') + suffix ;
}
/** @brief 自身の既知fixtureだけをextended DOS表記へ揃えます。
 * @param[in] path 専用rootと固定名から構築した絶対DOS path。
 * @return 同じ対象を示すbackslash付きextended path。
 * @pre 不正入力の拒否や通常表記との比較へは使用しません。
 */
[[nodiscard]] std::filesystem::path collectionFixtureIoPath( const std::filesystem::path &path)
{
	return L"\\\\?\\" + std::filesystem::path( path).make_preferred().native() ;
}

/** @brief 既知fixtureの存在を長pathでも同じthrowing照会で判定します。
 * @param[in] path 自身の固定名から構築した通常表記の絶対fixture path。
 * @return 対象が存在すればtrue。不在の場合だけfalse。
 * @throws std::filesystem::filesystem_error 存在照会が不存在以外のerrorを返した場合。
 * @pre 不正入力や既にextended表記のpathへは使用しません。
 * @note 参照先を辿るexistsの意味を保持し、照会errorをfalseへ変換しません。
 */
[[nodiscard]] bool collectionFixtureExists( const std::filesystem::path &path)
{
	return std::filesystem::exists( collectionFixtureIoPath( path)) ;
}

/** @brief 自身のfixture本文をそのまま読みます。
 * @param[in] path Fixture内の通常file。
 * @return 比較用の元byte。
 */
std::string contents( const std::filesystem::path &path)
{
	std::ifstream stream( collectionFixtureIoPath( path),
						 std::ios::binary) ;	// 既知fixtureだけを読みます。
	require( static_cast<bool>( stream)) ;
	return std::string( std::istreambuf_iterator<char>( stream), std::istreambuf_iterator<char>()) ;
}
/** @brief 自身のfixtureの内容だけを改変します。
 * @param[in] path 存在するfixture file。ACLは保持します。
 * @param[in] bytes 改変試験の有限非秘密本文。
 */
void change( const std::filesystem::path &path, std::string_view bytes)
{
	std::ofstream stream( collectionFixtureIoPath( path),
						 std::ios::binary | std::ios::trunc) ;	// Native改変fixtureだけの書込みです。
	require( static_cast<bool>( stream)) ;
	stream.write( bytes.data(), static_cast<std::streamsize>( bytes.size())) ;
	require( static_cast<bool>( stream)) ;
}
/** @brief FixtureのownerとDACLを同じ比較表現へ取得します。
 * @param[in] path 自身が作成した検査対象。
 * @return Logへ出さない比較専用SDDL。
 */
std::wstring security( const std::filesystem::path &path)
{
	PSECURITY_DESCRIPTOR raw{} ;	// APIが返すdescriptorを直後に所有します。
	require( GetNamedSecurityInfoW( collectionFixtureIoPath( path).c_str(), SE_FILE_OBJECT,
								  OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr,
								  nullptr, nullptr, nullptr, &raw) == 0U) ;
	const Memory owner( raw) ;	// SIDとDACLの寿命を照合中保持します。
	LPWSTR		 text{} ;		// Windowsが確保する比較文字列です。
	require( ConvertSecurityDescriptorToStringSecurityDescriptorW(
				owner.get(), SDDL_REVISION_1,
				OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text, nullptr) != FALSE) ;
	const Memory buffer( text) ;	// 例外時もSDDLを回収します。
	return std::wstring( text) ;
}
/** @brief 自身のfixtureのDACLだけを意図的に緩めます。
 * @param[in] path 自身の通常fileかdirectory。
 * @param[in] directory OICI directory flagを含む場合true。
 */
void broaden( const std::filesystem::path &path, bool directory)
{
	PSECURITY_DESCRIPTOR raw{} ;	// 不正fixture専用descriptorです。
	require( ConvertStringSecurityDescriptorToSecurityDescriptorW(
				directory ? L"D:P(A;OICI;FA;;;WD)" : L"D:P(A;;FA;;;WD)", SDDL_REVISION_1, &raw,
				nullptr) != FALSE) ;
	const Memory owner( raw) ;	// 既存system設定へ適用しません。
	require( SetFileSecurityW( collectionFixtureIoPath( path).c_str(),
							 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
							 owner.get()) != FALSE) ;
}
/** @brief 自分の保護directoryのSDを複製して空containerを作ります。
 * @param[in] path 未存在fixture path。
 * @param[in] model Fixtureの正規保護directory。
 */
void protectedDirectory( const std::filesystem::path &path, const std::filesystem::path &model)
{
	PSECURITY_DESCRIPTOR raw{} ;	// 自分の固定owner／DACLだけを複製します。
	require( GetNamedSecurityInfoW( collectionFixtureIoPath( model).c_str(), SE_FILE_OBJECT,
								  OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr,
								  nullptr, nullptr, nullptr, &raw) == 0U) ;
	const Memory		owner( raw) ;	// 新規作成が終わるまでdescriptorを保持します。
	SECURITY_ATTRIBUTES attributes{sizeof( SECURITY_ATTRIBUTES), owner.get(),
								   FALSE} ;	// 作成時から保護します。
	require( CreateDirectoryW( collectionFixtureIoPath( path).c_str(), &attributes) != FALSE) ;
}
/** @brief 自分の空directoryへ実junctionを設定します。
 * @param[in] path 自身が作成した空directory。
 * @param[in] target Fixture内の参照先。
 */
void junction( const std::filesystem::path &path, const std::filesystem::path &target)
{
	const HANDLE file =
		CreateFileW( collectionFixtureIoPath( path).c_str(), GENERIC_WRITE, 0U, nullptr,
					OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
					nullptr) ;										// Fixtureだけの更新handle。
	Handle handle( file == INVALID_HANDLE_VALUE ? nullptr : file) ;	// Setup例外でも回収します。
	require( static_cast<bool>( handle)) ;
	const std::wstring substitute =
		L"\\??\\" + target.native() ;				// 有限fixtureのmount point表現です。
	const std::wstring print = target.native() ;	// 同じ参照先の表示表現です。
	/**
	 * @brief junction内でmount point設定の固定16 byte wire headerを表します。
	 *
	 * header直後のUTF-16文字列領域を基準とするsubstitute名とprint名のoffsetと、
	 * 終端nullを含まないbyte長を保持します。bytesは先頭8 byteを除いた全data長です。
	 * @note 値だけを保持し、文字列・buffer・directory handleを所有しません。
	 *       headerをbufferへ複写し、DeviceIoControlの同期呼出しが戻るまで、
	 *       junctionがbufferとhandleの寿命を維持します。
	 */
	struct Header {
		/// Mount point tag。
		DWORD tag ;
		/// 固定8 byteの後ろの長さ。
		WORD  bytes ;
		/// 予約値0。
		WORD  reserved ;
		/// Substituteのoffset。
		WORD  offset ;
		/// Substituteのbyte長。
		WORD  length ;
		/// Printのoffset。
		WORD  printOffset ;
		/// Printのbyte長。
		WORD  printLength ;
	} ;
	static_assert( sizeof( Header) == 16U) ;
	std::vector<BYTE> buffer( 16U + (substitute.size() + print.size() + 2U) *
									   // Fixture長を有限wireへ収めます。
									   sizeof( wchar_t)) ;
	require( buffer.size() < MAXIMUM_REPARSE_DATA_BUFFER_SIZE) ;
	const Header header{IO_REPARSE_TAG_MOUNT_POINT, static_cast<WORD>( buffer.size() - 8U), 0U, 0U,
						static_cast<WORD>( substitute.size() * sizeof( wchar_t)),
						static_cast<WORD>( (substitute.size() + 1U) * sizeof( wchar_t)),
						// OSの固定wire layoutです。
						static_cast<WORD>( print.size() * sizeof( wchar_t))} ;
	std::memcpy( buffer.data(), &header, sizeof( header)) ;
	std::memcpy( buffer.data() + 16U, substitute.c_str(),
				(substitute.size() + 1U) * sizeof( wchar_t)) ;
	std::memcpy( buffer.data() + 16U + header.printOffset, print.c_str(),
				(print.size() + 1U) * sizeof( wchar_t)) ;
	DWORD	   returned{} ;	// 実FSCTLの完了byte数です。
	const BOOL ok = DeviceIoControl( handle.get(), FSCTL_SET_REPARSE_POINT, buffer.data(),
									static_cast<DWORD>( buffer.size()), nullptr, 0U, &returned,
									nullptr) ;	// Resource解放後にsetupを判定します。
	handle.reset() ;
	require( ok != FALSE) ;
}
/** @brief 正常I/O・二重writer・lease強所有の寿命を検査します。
 * @param[in,out] c Assertion集計。
 * @param[in] root 新規専用collection path。
 */
void ownership( TestContext &c, const std::filesystem::path &root)
{
	auto parent =
		std::make_unique<LocalCollectorCollectionStore>() ;	// Wrapperを先に破棄する寿命試験です。
	std::unique_ptr<LocalCollectorSegmentLease> lease ;		// 親を強所有する子です。
	DRIVERCRATE_EXPECT( c, parent->borrowSegment( key( 2U), true, lease) == 87U && !lease) ;
	DRIVERCRATE_EXPECT( c, parent->initialize( root, key( 1U)) == 0U) ;
	const auto marker =
		// 以後の拒否で不変です。
		contents( root / L"current/collector-campaign-mode-v1.json") ;
	LocalCollectorCollectionStore other ;	// 同じcollectionの二つ目のwriterです。
	DRIVERCRATE_EXPECT( c, other.initialize( root, key( 1U)) == ERROR_SHARING_VIOLATION) ;
	DRIVERCRATE_EXPECT( c, parent->borrowSegment( L"../bad", true, lease) == 87U && !lease) ;
	DRIVERCRATE_EXPECT( c, parent->borrowSegment( key( 2U), false, lease) == ERROR_FILE_NOT_FOUND &&
							  !lease) ;
	DRIVERCRATE_EXPECT( c, !collectionFixtureExists( root / L"segments" / key( 2U))) ;
	DRIVERCRATE_EXPECT( c, parent->borrowSegment( key( 2U), true, lease) == 0U && lease) ;
	require( static_cast<bool>( lease)) ;
	const auto original = lease.get() ;	// 非空outを拒否しても元leaseを保持します。
	DRIVERCRATE_EXPECT( c, parent->borrowSegment( key( 3U), true, lease) == 170U &&
							  lease.get() == original) ;
	std::unique_ptr<LocalCollectorSegmentLease> duplicate ;	// 空outでも二重借用を拒否します。
	DRIVERCRATE_EXPECT( c, parent->borrowSegment( key( 3U), true, duplicate) == 170U && !duplicate) ;
	DRIVERCRATE_EXPECT( c, parent->close() == 170U) ;
	DRIVERCRATE_EXPECT( c, parent->initialize( root, key( 1U)) == 170U) ;
	DRIVERCRATE_EXPECT( c, lease->store().initialize( root, false) == 170U &&
							  lease->store().isWritable()) ;
	DRIVERCRATE_EXPECT( c, lease->store().write( L"runs/a.json", "fixture") == 0U) ;
	DRIVERCRATE_EXPECT( c, lease->store().write( L"../escape.json", "bad") == 87U) ;
	DRIVERCRATE_EXPECT( c, rejectLocalCollectorCampaignMode( lease->store()) == 13U) ;
	DRIVERCRATE_EXPECT( c,
					   !MoveFileExW( root.c_str(), (root.parent_path() / L"renamed").c_str(), 0U)) ;
	LocalCollectorStateStore legacy ;	// 子lockだけを使う旧writerです。
	DRIVERCRATE_EXPECT( c, legacy.initialize( root / L"segments" / key( 2U), true) == 13U) ;
	parent.reset() ;
	DRIVERCRATE_EXPECT( c, other.initialize( root, key( 1U)) == ERROR_SHARING_VIOLATION) ;
	DRIVERCRATE_EXPECT( c, lease->store().write( L"runs/a.json", "kept-parent") == 0U) ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( c, other.initialize( root, key( 1U)) == 0U) ;
	DRIVERCRATE_EXPECT( c, other.borrowSegment( key( 2U), false, lease) == 0U) ;
	std::string bytes ;		// 同じ検証済みfileの読戻しです。
	bool		found{} ;	// 欠損を成功本文にしません。
	DRIVERCRATE_EXPECT( c, lease->store().read( L"runs/a.json", bytes, found) == 0U && found &&
							  bytes == "kept-parent") ;
	DRIVERCRATE_EXPECT( c, contents( root / L"current/collector-campaign-mode-v1.json") == marker) ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( c, other.close() == 0U) ;
	DRIVERCRATE_EXPECT( c, legacy.initialize( root / L"segments" / key( 2U), true) == 13U) ;
}
/** @brief 既存markerの差替え・欠損を非変更で拒否します。
 * @param[in,out] c Assertion集計。
 * @param[in] root 架空collection path。
 */
void markers( TestContext &c, const std::filesystem::path &root)
{
	LocalCollectorCollectionStore parent ;	// 親登録を保持します。
	require( parent.initialize( root, key( 1U)) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 選択した一子だけを検査します。
	require( parent.borrowSegment( key( 2U), true, lease) == 0U) ;
	require( lease->store().write( L"runs/a.json", "keep") == 0U) ;
	lease.reset() ;
	const auto child = root / L"segments" / key( 2U) ;	// 自分の子fixtureです。
	const auto original =
		// 拒否後に自分のfixtureだけ復元します。
		contents( child / L"current/collector-campaign-mode-v1.json") ;
	change( child / L"current/collector-campaign-mode-v1.json", "wrong-marker") ;
	DRIVERCRATE_EXPECT( c, parent.borrowSegment( key( 2U), false, lease) == 13U && !lease) ;
	DRIVERCRATE_EXPECT( c, contents( child / L"current/collector-campaign-mode-v1.json") ==
							  "wrong-marker") ;
	DRIVERCRATE_EXPECT( c, contents( child / L"runs/a.json") == "keep") ;
	change( child / L"current/collector-campaign-mode-v1.json", original) ;
	DRIVERCRATE_EXPECT( c, parent.borrowSegment( key( 2U), false, lease) == 0U) ;
	lease.reset() ;
	require( DeleteFileW( collectionFixtureIoPath( child / L"current/collector-campaign-mode-v1.json")
							.c_str()) != FALSE) ;
	DRIVERCRATE_EXPECT( c, parent.borrowSegment( key( 2U), true, lease) == 13U && !lease) ;
	DRIVERCRATE_EXPECT(
		c, !collectionFixtureExists( child / L"current/collector-campaign-mode-v1.json")) ;
	require( parent.close() == 0U) ;
	const auto before =
		// 親の差替えも修復しません。
		contents( root / L"current/collector-campaign-mode-v1.json") ;
	change( root / L"current/collector-campaign-mode-v1.json", "wrong-parent") ;
	DRIVERCRATE_EXPECT( c, parent.initialize( root, key( 1U)) == 13U) ;
	DRIVERCRATE_EXPECT( c, contents( root / L"current/collector-campaign-mode-v1.json") ==
							  "wrong-parent") ;
	change( root / L"current/collector-campaign-mode-v1.json", before) ;
	require( DeleteFileW( collectionFixtureIoPath( root / L"current/collector-campaign-mode-v1.json")
							.c_str()) != FALSE) ;
	DRIVERCRATE_EXPECT( c, parent.initialize( root, key( 1U)) == 13U) ;
	DRIVERCRATE_EXPECT( c,
					   !collectionFixtureExists( root / L"current/collector-campaign-mode-v1.json")) ;
	DRIVERCRATE_EXPECT( c, contents( child / L"runs/a.json") == "keep") ;
}
/** @brief Directory／fileのACL緩和を元のまま拒否します。
 * @param[in,out] c Assertion集計。
 * @param[in] root 新規collection path。
 * @param[in] kind root／segments／子container／子fileの四条件です。
 */
void acl( TestContext &c, const std::filesystem::path &root, std::size_t kind)
{
	LocalCollectorCollectionStore parent ;	// 正規fixtureを作ってから自身のDACLだけを緩めます。
	require( parent.initialize( root, key( 1U)) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 子markerも正規作成します。
	require( parent.borrowSegment( key( 2U), true, lease) == 0U) ;
	lease.reset() ;
	require( parent.close() == 0U) ;
	const std::array<std::filesystem::path, 4> targets{
		root, root / L"segments", root / L"segments" / key( 2U),
		root / L"segments" / key( 2U) /
			L"current/collector-campaign-mode-v1.json"} ;	// 対応は固定fixtureだけです。
	const auto target = targets.at( kind) ;					// 条件ごとに異なる新規rootです。
	broaden( target, kind != 3U) ;
	const auto	before = security( target) ;					// 拒否でACLが変更されないことを比較します。
	const DWORD code   = parent.initialize( root, key( 1U)) ;	// 未選択子fileだけは使用時の検査です。
	// 親起動は過去全fileを読まないため子fileを選択時に検査します。
	if( kind == 3U) {
		DRIVERCRATE_EXPECT( c, code == 0U) ;
		DRIVERCRATE_EXPECT( c, parent.borrowSegment( key( 2U), false, lease) == ERROR_ACCESS_DENIED &&
								  !lease) ;
	} else {
		DRIVERCRATE_EXPECT( c, code == ERROR_ACCESS_DENIED) ;
	}

	DRIVERCRATE_EXPECT( c, security( target) == before) ;
}
/** @brief 未知階層・hard linkと実junctionを非変更で拒否します。
 * @param[in,out] c Assertion集計。
 * @param[in] root 新規collection path。
 * @param[in] kind 未知container／子内階層／hard link／segments junctionです。
 */
void shapes( TestContext &c, const std::filesystem::path &root, std::size_t kind)
{
	LocalCollectorCollectionStore parent ;	// 正規親からだけfixtureを作ります。
	require( parent.initialize( root, key( 1U)) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// Kind1だけ選択子を作成します。
	// 子内の未知階層は利用時にだけ検査します。
	if( kind == 1U) {
		require( parent.borrowSegment( key( 2U), true, lease) == 0U) ;
		lease.reset() ;
	}

	require( parent.close() == 0U) ;
	const auto before =
		// Markerを上書きしません。
		contents( root / L"current/collector-campaign-mode-v1.json") ;
	// Kindごとに自分のfixtureだけを不正化します。
	if( kind == 0U) {
		require( CreateDirectoryW( collectionFixtureIoPath( root / L"segments/unknown").c_str(),
								 nullptr) != FALSE) ;
	}

	// JSON直下の未知directoryは選択時に拒否します。
	if( kind == 1U) {
		require(
			CreateDirectoryW(
				collectionFixtureIoPath( root / L"segments" / key( 2U) / L"current/nested").c_str(),
				nullptr) != FALSE) ;
	}

	// 同じfileへの別名linkでlink数を二つにします。
	if( kind == 2U) {
		require(
			CreateHardLinkW(
				collectionFixtureIoPath( root / L"current/alias.json").c_str(),
				collectionFixtureIoPath( root / L"current/collector-campaign-mode-v1.json").c_str(),
				nullptr) != FALSE) ;
	}

	// 空segmentsへ実junctionを設定し参照先の不変を確認します。
	if( kind == 3U) {
		const auto target = root.parent_path() / L"target" ;	// Fixture外へ参照を作りません。
		require( CreateDirectoryW( collectionFixtureIoPath( target).c_str(), nullptr) != FALSE) ;
		junction( root / L"segments", target) ;
	}

	const DWORD code = parent.initialize( root, key( 1U)) ;	// 第一の実拒否codeです。
	// 未選択子内部は親起動の合格へ流用しません。
	if( kind == 1U) {
		DRIVERCRATE_EXPECT( c, code == 0U) ;
		DRIVERCRATE_EXPECT( c, parent.borrowSegment( key( 2U), false, lease) == ERROR_INVALID_NAME &&
								  !lease) ;
	} else {
		DRIVERCRATE_EXPECT(
			c, code == static_cast<DWORD>( kind == 0U ? ERROR_INVALID_NAME : ERROR_ACCESS_DENIED)) ;
	}

	DRIVERCRATE_EXPECT( c, contents( root / L"current/collector-campaign-mode-v1.json") == before) ;
}
/** @brief 1024containerと1025個目の非作成拒否を確認します。
 * @param[in,out] c Assertion集計。
 * @param[in] root 架空collection path。
 */
void capacity( TestContext &c, const std::filesystem::path &root)
{
	LocalCollectorCollectionStore parent ;	// 新規親の保護SDを再利用します。
	require( parent.initialize( root, key( 1U)) == 0U) ;
	require( parent.close() == 0U) ;
	// 全containerは空fixtureであり、1024完了区間のsealではありません。
	for( std::size_t i = 0U; i < 1024U; ++i) {
		protectedDirectory( root / L"segments" / key( i + 2U), root / L"segments") ;
	}

	DRIVERCRATE_EXPECT( c, parent.initialize( root, key( 1U)) == 0U) ;
	const auto before = contents(
		root / L"current/collector-campaign-mode-v1.json") ;	// 容量拒否で元markerを保持します。
	std::unique_ptr<LocalCollectorSegmentLease> lease ;			// 1025個目は発行しません。
	DRIVERCRATE_EXPECT( c, parent.borrowSegment( key( 9000U), true, lease) == 68U && !lease) ;
	DRIVERCRATE_EXPECT( c, !collectionFixtureExists( root / L"segments" / key( 9000U))) ;
	DRIVERCRATE_EXPECT( c, contents( root / L"current/collector-campaign-mode-v1.json") == before) ;
	const DWORD existingCode =
		// 元拒否codeを数値だけ記録します。
		parent.borrowSegment( key( 2U), true, lease) ;
	std::cout << "Existing container borrow Win32 code: " << existingCode << '\n' ;
	const auto file = root / L"segments" / key( 2U) /
					  L"current/collector-campaign-mode-v1.json" ;	// 元readと同じ絶対pathです。
	const auto extended = L"\\\\?\\" +
						  // Extended APIへ区切りを揃えます。
						  std::filesystem::path( file).make_preferred().native() ;
	const HANDLE plainRaw =
		CreateFileW( file.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
					OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
					nullptr) ;	// 元readと同じAPIです。
	const DWORD plainCode =
		// 第一API codeです。
		plainRaw == INVALID_HANDLE_VALUE ? GetLastError() : 0U ;
	const Handle plain( plainRaw == INVALID_HANDLE_VALUE ? nullptr
														: plainRaw) ;	// 万一成功時も閉じます。
	const HANDLE extendedRaw =
		CreateFileW( extended.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
					OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
					nullptr) ;	// 同じ対象のprefix比較です。
	const DWORD extendedCode =
		// 型付き比較値です。
		extendedRaw == INVALID_HANDLE_VALUE ? GetLastError() : 0U ;
	const Handle expanded(
		// 比較handleも回収します。
		extendedRaw == INVALID_HANDLE_VALUE ? nullptr : extendedRaw) ;
	std::cout << "Mode path characters: " << file.native().size() << ", plain open: " << plainCode
			  << ", extended open: " << extendedCode << '\n' ;
	DRIVERCRATE_EXPECT( c, existingCode == 0U) ;
	const auto staging =
		// 元writeが使用する名前です。
		std::filesystem::path( file.native() + L".tmp") ;
	const HANDLE stageRaw =
		CreateFileW( staging.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
					FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 不在fileの非作成比較です。
	const DWORD stageCode =
		// 元pathでの第一errorです。
		stageRaw == INVALID_HANDLE_VALUE ? GetLastError() : 0U ;
	const Handle stageOwner( stageRaw == INVALID_HANDLE_VALUE ? nullptr
															 : stageRaw) ;	// 成功時も回収します。
	const auto	 stageExtended = L"\\\\?\\" +
							   // 同じstagingの内部表現です。
							   std::filesystem::path( staging).make_preferred().native() ;
	const HANDLE stageLongRaw =
		CreateFileW( stageExtended.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
					FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 同じ対象を非作成で比較します。
	const DWORD	 stageLongCode = stageLongRaw == INVALID_HANDLE_VALUE
									 ? GetLastError()
									 : 0U ;	// Extended namespaceの第一errorです。
	const Handle stageLongOwner( stageLongRaw == INVALID_HANDLE_VALUE
									? nullptr
									: stageLongRaw) ;	// 成功時のlease外ownerです。
	std::cout << "Staging path characters: " << staging.native().size()
			  << ", plain open: " << stageCode << ", extended open: " << stageLongCode << '\n' ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( c, parent.close() == 0U) ;
	protectedDirectory( root / L"segments" / key( 9000U), root / L"segments") ;
	DRIVERCRATE_EXPECT( c, parent.initialize( root, key( 1U)) == 68U) ;
	DRIVERCRATE_EXPECT( c, contents( root / L"current/collector-campaign-mode-v1.json") == before) ;
}
/** @brief 旧別modeの拒否で新階層を追加しないことを検査します。
 * @param[in,out] c Assertion集計。
 * @param[in] root 通常storeだけの架空領域です。
 * @param[in] withMarker 旧別modeあり、falseなら非空なのにmarker欠損です。
 */
void registration( TestContext &c, const std::filesystem::path &root, bool withMarker)
{
	{
		LocalCollectorStateStore old ;	// 旧登録領域を自身のfixture内へ作ります。
		require( old.initialize( root, true) == 0U) ;
		require(
			old.write( withMarker ? L"current/collector-campaign-mode-v1.json" : L"runs/old.json",
					  "legacy-mode") == 0U) ;
	}
	LocalCollectorCollectionStore parent ;	// 異なる既存modeへの更新を拒否します。
	DRIVERCRATE_EXPECT( c, parent.initialize( root, key( 1U)) == 13U) ;
	DRIVERCRATE_EXPECT( c, !collectionFixtureExists( root / L"segments")) ;
	DRIVERCRATE_EXPECT( c, contents( root / (withMarker ? L"current/collector-campaign-mode-v1.json"
													  : L"runs/old.json")) == "legacy-mode") ;
}

/** @brief 固定historyと親writerの寿命・排他・非変更再借用を検査します。
 * @param[in,out] c 独立枠のassertion集計。
 * @param[in] root 自身の新collection。
 */
void historyOwnership( TestContext &c, const std::filesystem::path &root)
{
	auto parent = std::make_unique<LocalCollectorCollectionStore>() ;	// 親wrapperを先に解放します。
	std::unique_ptr<LocalCollectorSegmentLease> lease ;					// 親を強所有する専用子です。
	DRIVERCRATE_EXPECT( c, parent->borrowHistorySegment( key( 2U), true, lease) == 87U && !lease) ;
	require( parent->initialize( root, key( 1U)) == 0U) ;
	DRIVERCRATE_EXPECT( c, parent->borrowHistorySegment( L"../bad", true, lease) == 87U && !lease) ;
	DRIVERCRATE_EXPECT( c, parent->borrowHistorySegment( key( 2U), false, lease) == 2U && !lease) ;
	DRIVERCRATE_EXPECT( c, !collectionFixtureExists( root / L"segments" / key( 2U))) ;
	require( parent->borrowHistorySegment( key( 2U), true, lease) == 0U) ;
	auto *history = lease->history() ;	// Leaseと同じ寿命だけの非所有pointerです。
	DRIVERCRATE_EXPECT( c, history && history->isWritable()) ;
	// 借用に失敗したfixtureをdereferenceせず、元setup失敗を維持します。
	if( history == nullptr) {
		throw std::runtime_error( "collection store fixture setup failed") ;
	}

	const auto location = root / L"segments" / key( 2U) / L"history" ;	// Caller pathを採用しません。
	DRIVERCRATE_EXPECT( c, history->root() == location) ;
	// 再借用で同じ子schemaとidentityを維持する元canonical markerです。
	const auto marker =
		contents( lease->store().root() / L"current/collector-campaign-mode-v1.json") ;
	DRIVERCRATE_EXPECT(
		c, marker == "{\"schema\":\"collector-segment-history-store-v1\",\"collection\":\"" +
						 std::string( 64U - 1U, '0') + "1\",\"segment\":\"" + std::string( 63U, '0') +
						 "2\",\"history\":\"history\"}") ;
	DRIVERCRATE_EXPECT( c, parent->close() == 170U) ;
	const auto *original = lease.get() ;	// 非空出力拒否でも保持する元leaseです。
	DRIVERCRATE_EXPECT( c, parent->borrowHistorySegment( key( 3U), true, lease) == 170U &&
							  lease.get() == original) ;
	DRIVERCRATE_EXPECT( c, lease->store().initialize( root.parent_path() / L"other", true) == 170U) ;
	DRIVERCRATE_EXPECT( c, history->initialize( root.parent_path() / L"other", true) == 170U) ;
	LocalCollectorStateStore direct ;	// 固定historyの直開きはwriter能力を発行しません。
	DRIVERCRATE_EXPECT( c, direct.initialize( location, true) == 13U) ;
	DRIVERCRATE_EXPECT( c, direct.initialize( lease->store().root(), true) == 13U) ;
	LocalCollectorCollectionStore other ;	// Leaseが残る間は同親を二重取得できません。
	DRIVERCRATE_EXPECT( c, other.initialize( root, key( 1U)) == 32U) ;
	parent.reset() ;
	DRIVERCRATE_EXPECT( c, other.initialize( root, key( 1U)) == 32U) ;
	DRIVERCRATE_EXPECT(
		c, history->write( L"current/collector-campaign-mode-v1.json", "unverified-v3") == 0U) ;
	DRIVERCRATE_EXPECT( c, history->write( L"runs/a.json", "keep") == 0U) ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( c, other.initialize( root, key( 1U)) == 0U) ;
	// 補助lockが閉じた後もWindows大小文字別名で通常writerを取得できません。
	DRIVERCRATE_EXPECT( c,
					   direct.initialize( root / L"SEGMENTS" / key( 2U) / L"HISTORY", true) == 13U) ;
	DRIVERCRATE_EXPECT( c, !direct.isWritable()) ;
	DRIVERCRATE_EXPECT( c, other.borrowHistorySegment( key( 2U), false, lease) == 0U) ;
	require( lease && lease->history()) ;
	std::string raw ;		// 再起動後の同じfileだけを確認します。
	bool		found{} ;	// 欠損をread成功へ数えません。
	DRIVERCRATE_EXPECT( c, lease->history()->read( L"runs/a.json", raw, found) == 0U && found &&
							  raw == "keep") ;
	DRIVERCRATE_EXPECT(
		c, contents( lease->store().root() / L"current/collector-campaign-mode-v1.json") == marker) ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( c, other.close() == 0U) ;
}

/** @brief 旧・新schemaの交差と欠損登録の非変更拒否を検査します。
 * @param[in,out] c 独立枠の集計。
 * @param[in] root 自身の新collection。
 * @param[in] oldMode 旧schemaを初回登録する場合true。
 */
void historyMarkers( TestContext &c, const std::filesystem::path &root, const bool oldMode)
{
	LocalCollectorCollectionStore parent ;	// 同じ親の明示modeを選びます。
	require( parent.initialize( root, key( 1U)) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 交差拒否後は空のままです。
	require( (oldMode ? parent.borrowSegment( key( 2U), true, lease)
					 : parent.borrowHistorySegment( key( 2U), true, lease)) == 0U) ;
	DRIVERCRATE_EXPECT( c, oldMode ? lease->history() == nullptr : lease->history() != nullptr) ;
	const auto child	= lease->store().root() ;								// 元の登録領域です。
	const auto mode		= child / L"current/collector-campaign-mode-v1.json" ;	// 固定子marker。
	const auto original = contents( mode) ;										// 交差拒否で変えません。
	lease.reset() ;
	const auto code = oldMode
						  ? parent.borrowHistorySegment( key( 2U), true, lease)
						  : parent.borrowSegment( key( 2U), true,
												 lease) ;	// 旧入口は未知directoryの123で停止します。
	DRIVERCRATE_EXPECT( c, code == static_cast<DWORD>( oldMode ? 13U : 123U) && !lease) ;
	DRIVERCRATE_EXPECT( c, contents( mode) == original) ;
	DRIVERCRATE_EXPECT( c, collectionFixtureExists( child / L"history") != oldMode) ;
	// 新子の不正markerは固定履歴を作り直さず拒否します。
	if( !oldMode) {
		change( mode, "wrong") ;
		DRIVERCRATE_EXPECT( c, parent.borrowHistorySegment( key( 2U), true, lease) == 13U && !lease) ;
		DRIVERCRATE_EXPECT( c, contents( mode) == "wrong") ;
		change( mode, original) ;
		require( DeleteFileW( collectionFixtureIoPath( mode).c_str()) != FALSE) ;
		DRIVERCRATE_EXPECT( c, parent.borrowHistorySegment( key( 2U), true, lease) == 13U && !lease) ;
		DRIVERCRATE_EXPECT( c, !collectionFixtureExists( mode)) ;
	}
}

/** @brief 新historyだけの不正保護・未知階層と欠損を個別に検査します。
 * @param[in,out] c 独立枠の集計。
 * @param[in] root 自身の新collection。
 * @param[in] kind ACL directory／file、未知子、hard link、junction、mode欠損、history欠損です。
 */
void historyFault( TestContext &c, const std::filesystem::path &root, const std::size_t kind)
{
	LocalCollectorCollectionStore parent ;	// 本番作成の保護fixtureだけを使用します。
	require( parent.initialize( root, key( 1U)) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 改変前に全handleを解放します。
	require( parent.borrowHistorySegment( key( 2U), true, lease) == 0U) ;
	auto *history = lease->history() ;	// Setup中だけの非所有借用です。
	// 借用不成立は元fixture失敗のまま止め、write/rootを参照しません。
	if( history == nullptr) {
		throw std::runtime_error( "collection store fixture setup failed") ;
	}

	require( history->write( L"current/collector-campaign-mode-v1.json", "unverified-v3") == 0U) ;
	require( history->write( L"runs/a.json", "keep") == 0U) ;
	const auto path = history->root() ;	// 元固定配置だけを変更します。
	lease.reset() ;
	// Directory全体のDACL拒否を独立測定します。
	if( kind == 0U) {
		broaden( path, true) ;
	}

	// FileごとのDACLを緩めても修復されません。
	if( kind == 1U) {
		broaden( path / L"runs/a.json", false) ;
	}

	// 孫historyは新子の例外を再帰的に引き継ぎません。
	if( kind == 2U) {
		protectedDirectory( path / L"history", path) ;
	}

	// Link count二以上は本文が同じでも拒否します。
	if( kind == 3U) {
		require( CreateHardLinkW( collectionFixtureIoPath( path / L"runs/b.json").c_str(),
								collectionFixtureIoPath( path / L"runs/a.json").c_str(),
								nullptr) != FALSE) ;
	}

	// Runsの実reparseを通常directoryへ読み替えません。
	if( kind == 4U) {
		require( DeleteFileW( collectionFixtureIoPath( path / L"runs/a.json").c_str()) != FALSE) ;
		const auto target = root.parent_path() / L"target" ;	// 自分の領域外へ参照しません。
		require( CreateDirectoryW( collectionFixtureIoPath( target).c_str(), nullptr) != FALSE) ;
		junction( path / L"runs", target) ;
	}

	// 非空historyのmode欠損は初回へ変換しません。
	if( kind == 5U) {
		require(
			DeleteFileW( collectionFixtureIoPath( path / L"current/collector-campaign-mode-v1.json")
							.c_str()) != FALSE) ;
	}

	// 空historyだけを自身の明示試験で除去し非作成借用を検査します。
	if( kind == 6U) {
		require( DeleteFileW( collectionFixtureIoPath( path / L"runs/a.json").c_str()) != FALSE) ;
		require(
			DeleteFileW( collectionFixtureIoPath( path / L"current/collector-campaign-mode-v1.json")
							.c_str()) != FALSE) ;
		require( DeleteFileW( collectionFixtureIoPath( path / L"collector.lock").c_str()) != FALSE) ;
		require( RemoveDirectoryW( collectionFixtureIoPath( path / L"current").c_str()) != FALSE) ;
		require( RemoveDirectoryW( collectionFixtureIoPath( path / L"runs").c_str()) != FALSE) ;
		require( RemoveDirectoryW( collectionFixtureIoPath( path).c_str()) != FALSE) ;
	}

	const auto expected = kind == 2U   ? 123U
						  : kind == 5U ? 13U
						  : kind == 6U ? 2U
									   : 5U ;	// 元の型別拒否です。
	const auto result =
		// 故障を修復しません。
		parent.borrowHistorySegment( key( 2U), kind != 6U, lease) ;
	DRIVERCRATE_EXPECT( c, result == expected && !lease) ;
	// 欠損非作成の後に明示createだけが空履歴を再作成できます。
	if( kind == 6U) {
		DRIVERCRATE_EXPECT( c, !collectionFixtureExists( path)) ;
		DRIVERCRATE_EXPECT( c, parent.borrowHistorySegment( key( 2U), true, lease) == 0U && lease &&
								  lease->history()) ;
	} else {
		DRIVERCRATE_EXPECT( c, collectionFixtureExists( path)) ;
	}
}
} // namespace
} // namespace drivercrate::test

/** @brief 自身の専用fixtureで独立native suiteを実行します。
 * @param[in] argumentCount 実行名込みの引数数。
 * @param[in] arguments 無引数は旧枠、--history-layoutは独立新枠です。
 * @return 全合格0、assertion失敗1、setup不成立2、未知引数87。
 */
int wmain( const int argumentCount, wchar_t **arguments)
{
	const bool historyOnly =
		// 明示新枠。
		argumentCount == 2 && std::wstring_view( arguments[1]) == L"--history-layout" ;
	// 未知引数はfile作成前に拒否します。
	if( argumentCount != 1 && !historyOnly) {
		return ERROR_INVALID_PARAMETER ;
	}

	try {
		drivercrate::test::TestContext c ;	// 固定fixtureの結果だけを集計します。
		// 新配置だけの独立分母を旧68項目へ合算しません。
		if( historyOnly) {
			const auto base =
				std::filesystem::absolute( std::filesystem::path( L"work/tmp") /
										  (L"hc-" + std::to_wstring( GetCurrentProcessId()) + L"-" +
										   // 短い専用領域。
										   std::to_wstring( GetTickCount64()))) ;
			drivercrate::test::require( std::filesystem::create_directories( base)) ;
			drivercrate::test::historyOwnership( c, base / L"o" / drivercrate::test::key( 1U)) ;
			drivercrate::test::historyMarkers( c, base / L"m0" / drivercrate::test::key( 1U), true) ;
			drivercrate::test::historyMarkers( c, base / L"m1" / drivercrate::test::key( 1U), false) ;
			// 七反証を別領域で測り、故障状態を混合しません。
			for( std::size_t i = 0U; i < 7U; ++i) {
				drivercrate::test::historyFault(
					c, base / (L"f" + std::to_wstring( i)) / drivercrate::test::key( 1U), i) ;
			}

			std::cout << "History layout assertions: " << c.assertionCount()
					  << ", failures: " << c.failureCount() << '\n' ;
			return c.failureCount() == 0U ? 0 : 1 ;
		}

		const auto base = std::filesystem::absolute( std::filesystem::path( L"work/tmp") /
													(L"collector-collection-" +
													 std::to_wstring( GetCurrentProcessId()) + L"-" +
													 // 自身だけの未存在rootです。
													 std::to_wstring( GetTickCount64()))) ;
		drivercrate::test::require( std::filesystem::create_directories( base)) ;
		drivercrate::test::ownership( c, base / L"owner" / drivercrate::test::key( 1U)) ;
		drivercrate::test::markers( c, base / L"markers" / drivercrate::test::key( 1U)) ;
		// 四保護対象を独立したrootで検査します。
		for( std::size_t i = 0U; i < 4U; ++i) {
			drivercrate::test::acl(
				c, base / (L"acl-" + std::to_wstring( i)) / drivercrate::test::key( 1U), i) ;
		}

		// 四種類の不正形状を元fixtureから独立して作ります。
		for( std::size_t i = 0U; i < 4U; ++i) {
			drivercrate::test::shapes(
				c, base / (L"shape-" + std::to_wstring( i)) / drivercrate::test::key( 1U), i) ;
		}

		drivercrate::test::capacity( c, base / L"capacity" / drivercrate::test::key( 1U)) ;
		drivercrate::test::registration( c, base / L"registration" / drivercrate::test::key( 1U),
										true) ;
		drivercrate::test::registration(
			c, base / L"missing-registration" / drivercrate::test::key( 1U), false) ;
		std::cout << "Collection store assertions: " << c.assertionCount()
				  << ", failures: " << c.failureCount() << '\n' ;
		return c.failureCount() == 0U ? 0 : 1 ;
	} catch( const std::exception &error) {
		std::cerr << error.what() << '\n' ;
		return 2 ;
	}
}
