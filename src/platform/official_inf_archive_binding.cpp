//------------------------------------------------------------------------------
/**
 * @file official_inf_archive_binding.cpp
 * @brief 封印取得と閉じたZIP／PE内INF・署名補助CAT集合の非実行結合。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  元byteと全祖先を固定したZIP派生結合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  明示PE形式の全INF原範囲を共通所有へ接続。
 * Ver.01.02.00 Shunji Ogawa  2026/10/06  全fileをnative使用終了まで固定し由来へ接続。
 * Ver.01.03.00 Shunji Ogawa  2026/10/06  全CATも原byte再照合と使用中固定へ追加。
 * Ver.01.03.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 同期workerだけで使用する。native署名の失効照会はOSに委ね、導入許可を発行しない。
 * @see docs/adr/0274-sealed-zip-inf-member-binding.md
 */
//------------------------------------------------------------------------------
#include "platform/official_inf_archive_binding.h"
#include "platform/official_file_verifier.h"
#include "platform/official_inf_metadata_extraction.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
//------------------------------------------------------------------------------
// 有限容量とhandle所有定義。
//------------------------------------------------------------------------------
constexpr std::uint64_t MAX_ARCHIVE_BYTES = 128ULL * 1024ULL * 1024ULL ;	// 一archive上限。
constexpr OfficialZipExtractionPolicy ZIP_POLICY =
	OFFICIAL_INF_ARCHIVE_POLICY ;	// 全宣言の共通予算。

/** @brief 通常Windows handleを単独所有する。 */
struct BindingHandleCloser {
	/** @brief 有効handleだけを閉じる。
	 * @param[in] value 所有するfileまたはdirectory handle。
	 */
	void operator()( void *value) const noexcept
	{
		// 未取得handleをOSへ渡さない。
		if( value != nullptr && value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
} ;
/**
 * @brief scope限定のhandle所有。
 */
using BindingHandle = std::unique_ptr<void, BindingHandleCloser> ;

/** @brief Ordinal case非依存で同じ有限名を照合する。
 * @param[in] left 一つ目の原名。
 * @param[in] right 二つ目の原名。
 * @return 同じ長さとordinal名の場合true。
 */
bool equalBindingName( std::wstring_view left, std::wstring_view right) noexcept
{
	return left.size() < MAX_PATH && right.size() < MAX_PATH &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

/** @brief 実handleが通常位置と期待種別を示すことを確認する。
 * @param[in] handle 生存中の所有handle。
 * @param[in] path 終端付き通常DOS位置。
 * @param[in] directory directoryを期待する場合true。
 * @return 完了0、reparse・位置差・API失敗のHRESULT。
 */
NativeError checkBindingHandle( HANDLE handle, const std::wstring &path, bool directory)
{
	FILE_ATTRIBUTE_TAG_INFO attributes{} ;	// 名前ではなく実handleの属性。
	// 属性を取得できないfileは認証しない。
	if( !GetFileInformationByHandleEx( handle, FileAttributeTagInfo, &attributes,
									 sizeof( attributes))) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	// Reparseを辿った結果で元位置を救済しない。
	if( GetFileType( handle) != FILE_TYPE_DISK ||
	   (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
	   ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) != directory) {
		return HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED) ;
	}

	std::array<wchar_t, MAX_PATH + 4U> name{} ;	// DOS接頭辞を含む有限応答。
	const DWORD						   count =
		GetFinalPathNameByHandleW( handle, name.data(), static_cast<DWORD>( name.size()),
								  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 実最終位置。
	// 切詰めや未取得を原位置との一致にしない。
	if( count == 0U || count >= name.size()) {
		return count == 0U ? HRESULT_FROM_WIN32( GetLastError())
						   : HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	const std::wstring_view actual( name.data(), count) ;	// 終端を除く応答借用。
	return actual.starts_with( L"\\\\?\\") && equalBindingName( actual.substr( 4U), path)
			   ? 0
			   : HRESULT_FROM_WIN32( ERROR_FILE_INVALID) ;
}

/**
 * @brief 全祖先とleafを固定し、共通hash検証後に任意で同じhandleの全byteを読む。
 * @param[in] path 原通常DOS位置。
 * @param[in] bytes 期待する正のbyte数。最大128 MiB。
 * @param[in] hash 期待SHA-256。
 * @param[out] raw nullptrならhash再確認だけ、非nullなら成功時の全byte。
 * @param[out] retained Hash再確認時だけ全handleの所有を末尾へ移す任意出力。
 * @return 完了0、位置・容量・byte差・API失敗のHRESULT。
 * @note Rawは先行検証前に変更しない。retained指定時以外のhandle固定は本呼出し中に限る。
 */
NativeError readBoundFile( const std::wstring &path, std::uint64_t bytes, std::wstring_view hash,
						  std::vector<std::byte>	 *raw,
						  std::vector<BindingHandle> *retained = nullptr)
{
	// 認証結果から得た入力でも実位置と絶対容量を再確認する。
	if( !validInfDependencyPath( path, true) || bytes == 0U || bytes > MAX_ARCHIVE_BYTES ||
	   hash.size() != 64U || (raw != nullptr && retained != nullptr)) {
		return E_INVALIDARG ;
	}

	std::vector<BindingHandle> parents ;	// 呼出し中の全祖先renameを拒否する所有列。
	// Drive rootからleaf親まで、reparseを辿らず順に固定する。
	for( std::size_t end = 3U; end < path.size(); ++end) {
		// Component境界だけを開く。
		if( end != 3U && path[end] != L'\\') {
			continue ;
		}

		const std::wstring parent = path.substr( 0U, end) ;	// Rootには終端separatorを含む。
		BindingHandle	   handle( CreateFileW( parent.c_str(), FILE_READ_ATTRIBUTES,
											  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
											  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
											  nullptr)) ;	// 削除を共有しない。
		// 明示open失敗は元診断のまま返す。
		if( handle.get() == INVALID_HANDLE_VALUE) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		const auto error = checkBindingHandle( handle.get(), parent, true) ;	// 種別・最終位置。
		// 祖先の一つでも異常ならleafへ進まない。
		if( error != 0) {
			return error ;
		}

		parents.push_back( std::move( handle)) ;
	}

	BindingHandle file( CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
								   OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
								   nullptr)) ;	// Writer・削除を共有しないleaf。
	// Writer競合を成功履歴で補わない。
	if( file.get() == INVALID_HANDLE_VALUE) {
		return HRESULT_FROM_WIN32( GetLastError()) ;
	}

	auto error = checkBindingHandle( file.get(), path, false) ;	// 原位置の通常file確認。
	// 共通file検証を私有固定metadataへ適用する。
	if( error == 0) {
		error = verifyOfficialFileMetadata( path, {bytes, hash}) ;
	}

	// 全成功の位置・byteだけを呼出し側の使用中固定へ移す。
	if( error == 0 && retained != nullptr) {
		retained->reserve( retained->size() + parents.size() + 1U) ;
		// 全祖先のrename拒否をleafと同じ使用scopeへ引き継ぐ。
		for( auto &parent : parents) {
			retained->push_back( std::move( parent)) ;
		}

		retained->push_back( std::move( file)) ;
	}

	// 読取不要または先行拒否ではmemoryを作らない。
	if( error != 0 || raw == nullptr) {
		return error ;
	}

	std::vector<std::byte> captured( static_cast<std::size_t>( bytes)) ;	// 固定済みsizeだけのmemory。
	std::size_t			   offset{} ;										// 読取成功したbyte位置。
	// 全byteを有限chunkで同じ固定handleから読み取る。
	while( offset < captured.size()) {
		const DWORD requested = static_cast<DWORD>(
			std::min<std::size_t>( 65536U, captured.size() - offset)) ;	// 一chunk量。
		DWORD received{} ;												// 実読取量。
		// Short readも全byte取得として扱わない。
		if( !ReadFile( file.get(), captured.data() + offset, requested, &received, nullptr)) {
			return HRESULT_FROM_WIN32( GetLastError()) ;
		}

		// EOFを期待sizeまでの読取成功へ変換しない。
		if( received != requested) {
			return HRESULT_FROM_WIN32( ERROR_HANDLE_EOF) ;
		}

		offset += received ;
	}

	// 終了時も同じ固定byteを確認。
	error = verifyOfficialFileMetadata( path, {bytes, hash}) ;
	// 全確認完了時だけmemoryを公開する。
	if( error == 0) {
		*raw = std::move( captured) ;
	}

	return error ;
}
} // namespace

NativeError OfficialInfArchiveBinding::bind( const OfficialAcquisitionSession &session,
											OfficialAcquiredFileEvidence	&&evidence,
											const OfficialDownloadWorkspace	 &archiveWorkspace,
											std::span<const std::wstring>	  nestedMembers,
											OfficialInfContainerFormat		  format)
{
	try {
		// 明示経路の上限と生存証拠を展開前に必須化する。
		if( nestedMembers.size() > 2U || (format != OfficialInfContainerFormat::ZIP &&
										 format != OfficialInfContainerFormat::PE_FLAT_TABLE)) {
			*this = OfficialInfArchiveBinding{} ;
			return E_INVALIDARG ;
		}

		// 自身の公開memberからのborrowも回収前に構文確認し、過長copyを防ぐ。
		for( const auto &name : nestedMembers) {
			// 原名の危険構文は旧領域を回収して拒否する。
			if( !validInfDependencyPath( name, false)) {
				*this = OfficialInfArchiveBinding{} ;
				return E_INVALIDARG ;
			}
		}

		const std::vector<std::wstring> names( nestedMembers.begin(),
											  // 入力borrowを有限所有へ移す。
											  nestedMembers.end()) ;
		*this = OfficialInfArchiveBinding{} ;

		auto error = session.verifyAcquiredFile( evidence, archiveWorkspace) ;	// 私有issuer・元byte。
		// 公開boolや履歴だけでは元archiveを開かない。
		if( error != 0) {
			return error ;
		}

		const auto			  &original = evidence.observation() ;	// 生存私有証拠のread-only借用。
		std::vector<std::byte> raw ;								// 現層の固定memory archive。
		error = readBoundFile( original.inspectionPath, original.byteCount, original.sha256, &raw) ;
		OfficialInfArchiveBinding pending ;	// 全成功前は自身へ移さない部分所有者。
		// 最大二段の明示内側memberだけを辿り、再帰探索をしない。
		for( const auto &name : names) {
			// 前段拒否を後段展開で消さない。
			if( error != 0) {
				return error ;
			}

			std::vector<OfficialZipEntry> entries ;	// 全entryのpreflight結果。
			error = inspectOfficialZip( raw, ZIP_POLICY, entries) ;
			// 原相対位置の構文も公式entryの存在も必須とする。
			if( error != 0 || !validInfDependencyPath( name, false)) {
				return error != 0 ? error : E_INVALIDARG ;
			}

			const auto found =
				std::ranges::find_if( entries, [&name]( const OfficialZipEntry &entry) {
					// 原memberをordinal名で一意に解決する。
					return equalBindingName( entry.relativePath, name) ;
				}) ; // Parserが全重複を事前拒否した一覧。
			// 同名に似たmemberや別branchへfallbackしない。
			if( found == entries.end() || found->uncompressedSize == 0U ||
			   found->uncompressedSize > MAX_ARCHIVE_BYTES) {
				return HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
			}

			auto derived = std::make_unique<OfficialDownloadWorkspace>() ;	// この層だけの保護領域。
			error		 = derived->initialize( L"sealed-zip", original.scanSessionId) ;
			const std::array<std::wstring_view, 1U> selected{
				found->relativePath} ;					// 一原memberだけの明示選択。
			std::vector<OfficialZipEntry> extracted ;	// CRCとhashを固定した実member。
			// 領域確保後にだけ共通選択展開へ進む。
			if( error == 0) {
				error = extractOfficialZipFiles( raw, ZIP_POLICY, selected, *derived, extracted) ;
			}

			// 完全に一件固定されなければ派生を記録しない。
			if( error != 0 || extracted.size() != 1U) {
				return error != 0 ? error : E_UNEXPECTED ;
			}

			const auto &member = extracted.front() ;	// 生存抽出metadataの同期借用。
			error = readBoundFile( derived->path( member.relativePath), member.uncompressedSize,
								  member.sha256, &raw) ;
			pending.archiveMembers_.push_back( member) ;
			pending.archiveWorkspaces_.push_back( std::move( derived)) ;
		}

		// 最終層までのbyte固定に失敗したら全INFを列挙しない。
		if( error != 0) {
			return error ;
		}

		std::vector<OfficialZipEntry> extracted ;	// 全INF／CATの原byte metadata。
		pending.infWorkspace_ = std::make_unique<OfficialDownloadWorkspace>() ;
		error = pending.infWorkspace_->initialize( L"sealed-inf", original.scanSessionId) ;
		// 生存取得からの同じ最終memoryへ共通metadata抽出を適用する。
		if( error == 0) {
			error = extractOfficialInfMetadata( raw, format, *pending.infWorkspace_, extracted) ;
		}

		// 明示形式の失敗や空集合を別形式の成功へfallbackしない。
		if( error != 0 || extracted.empty()) {
			return error != 0 ? error : E_UNEXPECTED ;
		}

		// 実抽出だけから私有固定集合を作り、外部memberを取り込まない。
		for( const auto &entry : extracted) {
			error = readBoundFile( pending.infWorkspace_->path( entry.relativePath),
								  entry.uncompressedSize, entry.sha256, nullptr) ;
			// 抽出後の実byteまで一致することを要求する。
			if( error != 0) {
				return error ;
			}

			// CATを開始INF一覧へ混ぜず、同じ原metadataを私有の補助一覧へ保存する。
			if( equalBindingName(
				   std::wstring_view( entry.relativePath).substr( entry.relativePath.size() - 4U),
				   L".cat")) {
				pending.catalogMembers_.push_back( entry) ;
			} else {
				pending.infMembers_.push_back(
					{entry.relativePath, entry.sha256, entry.uncompressedSize}) ;
			}
		}

		error = session.verifyAcquiredFile( evidence, archiveWorkspace) ;
		// 全派生成功後も同じ生存issuerへ結合してからcommitする。
		if( error != 0) {
			return error ;
		}

		pending.evidence_ = std::move( evidence) ;
		*this			  = std::move( pending) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		*this = OfficialInfArchiveBinding{} ;
		return E_OUTOFMEMORY ;
	} catch( ...) {
		*this = OfficialInfArchiveBinding{} ;
		return E_UNEXPECTED ;
	}
}

NativeError OfficialInfArchiveBinding::verify(
	const OfficialAcquisitionSession &session,
	const OfficialDownloadWorkspace	 &archiveWorkspace) const
{
	try {
		// 空／move元／部分集合を有効な認証結果にしない。
		if( !infWorkspace_ || infMembers_.empty() ||
		   archiveWorkspaces_.size() != archiveMembers_.size()) {
			return E_INVALIDARG ;
		}

		auto error =
			// 同じ生存issuer必須。
			session.verifyAcquiredFile( evidence_, archiveWorkspace) ;
		// 元取得を再確認できないときは派生成功を返さない。
		if( error != 0) {
			return error ;
		}

		const auto &original = evidence_.observation() ;	// 私有原byte identity。
		error =
			readBoundFile( original.inspectionPath, original.byteCount, original.sha256, nullptr) ;
		// 全明示内側ZIPを順に原memberの固定byteへ再照合する。
		for( std::size_t index = 0U; error == 0 && index < archiveMembers_.size(); ++index) {
			const auto &member = archiveMembers_[index] ;	// 該当層の私有metadata。
			error			   = readBoundFile( archiveWorkspaces_[index]->path( member.relativePath),
											   member.uncompressedSize, member.sha256, nullptr) ;
		}

		// 最終ZIPの全INFを一部成功に縮約せず再照合する。
		for( const auto &member : infMembers_) {
			// 先行失敗の元診断を保持する。
			if( error != 0) {
				return error ;
			}

			error = readBoundFile( infWorkspace_->path( member.relativePath), member.byteCount,
								  member.sha256, nullptr) ;
		}

		// 未使用CATも含め全署名補助byteを再照合する。
		for( const auto &member : catalogMembers_) {
			// 元失敗の診断を維持して部分成功を返さない。
			if( error != 0) {
				return error ;
			}

			error = readBoundFile( infWorkspace_->path( member.relativePath), member.uncompressedSize,
								  member.sha256, nullptr) ;
		}

		return error != 0 ? error : session.verifyAcquiredFile( evidence_, archiveWorkspace) ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}

const OfficialDownloadWorkspace *OfficialInfArchiveBinding::workspace() const noexcept
{
	return infWorkspace_.get() ;
}

std::span<const InfDependencyPackageMember> OfficialInfArchiveBinding::members() const noexcept
{
	return infMembers_ ;
}

std::span<const OfficialZipEntry> OfficialInfArchiveBinding::catalogs() const noexcept
{
	return catalogMembers_ ;
}

NativeError OfficialInfArchiveBinding::inspectDependencies(
	const OfficialAcquisitionSession &session, const OfficialDownloadWorkspace &archiveWorkspace,
	std::size_t rootIndex, std::span<const std::wstring> seeds, std::uint64_t observationId,
	InfDependencyNativeResult &result) const
{
	result = {} ;
	try {
		auto error = verify( session, archiveWorkspace) ;	// 元issuer・全固定集合の開始確認。
		// 空結果や失効をnative署名の検査で救済しない。
		if( error != 0) {
			return error ;
		}

		std::vector<BindingHandle> pins ;					// 使用終了まで全元／派生と祖先を固定する。
		const auto &original = evidence_.observation() ;	// 外部入力ではない原取得metadata。
		error = readBoundFile( original.inspectionPath, original.byteCount, original.sha256, nullptr,
							  &pins) ;
		// 最終PEを含む明示経路の全memberを同じscopeで固定する。
		for( std::size_t index = 0U; error == 0 && index < archiveMembers_.size(); ++index) {
			const auto &member = archiveMembers_[index] ;	// 当該層の私有原metadata。
			error			   = readBoundFile( archiveWorkspaces_[index]->path( member.relativePath),
											   member.uncompressedSize, member.sha256, nullptr, &pins) ;
		}

		// 未訪問INFも含めた全封印集合を、native照会の前に固定する。
		for( const auto &member : infMembers_) {
			// 先行失敗の元診断を別fileの確認で上書きしない。
			if( error != 0) {
				return error ;
			}

			error = readBoundFile( infWorkspace_->path( member.relativePath), member.byteCount,
								  member.sha256, nullptr, &pins) ;
		}

		InfDependencyNativeResult observed ;	// 全再確認まで外部へ出さないsnapshot。
		// 署名で参照されないCATもnative使用の前に全て固定する。
		for( const auto &member : catalogMembers_) {
			// 先行失敗を別CATの確認で救済しない。
			if( error != 0) {
				return error ;
			}

			error = readBoundFile( infWorkspace_->path( member.relativePath), member.uncompressedSize,
								  member.sha256, nullptr, &pins) ;
		}

		// 全固定成功時だけ同じnative loaderへ公式由来を接続する。
		if( error == 0) {
			error = AcquiredInfNativeAccess::inspect( *this, session, archiveWorkspace, rootIndex,
													 seeds, observationId, observed) ;
		}

		// native使用後も、生存issuerと全固定byteを確認する。
		if( error == 0) {
			error = verify( session, archiveWorkspace) ;
		}

		// 全成功の非実行観測だけを返し、導入用計画に変換しない。
		if( error == 0) {
			result = std::move( observed) ;
		}

		return error ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}
} // namespace drivercrate
