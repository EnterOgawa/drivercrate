//------------------------------------------------------------------------------
/**
 * @file official_resource_content.cpp
 * @brief 固定親sliceと7z一memberから共通driver内容を非実行で読む。
 * @version 01.00.01
 * @date 2026/11/03
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  親hash結合と有界memory内包fileを追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note 中間EXEを保存・ロード・実行せず、取得由来や導入権限を発行しない。
 */
//------------------------------------------------------------------------------
#include "platform/official_resource_content.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/official_mapped_file.h"
#include "platform/official_seven_zip.h"
#include <Windows.h>
#include <algorithm>
#include <new>
#include <utility>

namespace drivercrate {
namespace {
constexpr std::uint64_t					   MIB		   = 1024ULL * 1024ULL ;	// small形式の容量単位。
constexpr std::uint64_t					   SMALL_BYTES = 64ULL * MIB ;			// 原親/innerの有限上限。
constexpr OfficialSevenZipExtractionPolicy SEVEN_POLICY{
	64ULL * MIB,  64ULL * MIB, 128ULL * MIB, 64ULL * MIB, 64ULL * MIB,
	128ULL * MIB, 64ULL * MIB, 4096U,		 260U,		  0U} ;	// 中間EXEはheap上の一memberだけ。
//------------------------------------------------------------------------------
/**
 * @brief 完全な小文字hashだけを識別値へ使う。
 * @param[in] text 元hash。
 * @return 正確な64桁ならtrue。
 */
//------------------------------------------------------------------------------
bool validHash( const std::wstring_view text) noexcept
{
	return text.size() == 64U && std::ranges::all_of( text, []( const wchar_t c) {
			   return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ;
		   }) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原resource atomの閉じた表現を検査する。
 * @param[in] value 数値または原UTF-16名。
 * @return 原契約が成立する場合true。
 */
//------------------------------------------------------------------------------
bool validAtom( const OfficialResourceIdentifier &value) noexcept
{
	// 数値を名前や不足値から推測しない。
	if( !value.named) {
		return value.id <= 65535U && value.text.empty() ;
	}

	return value.id == 0U && !value.text.empty() && value.text.size() <= 64U &&
		   value.text.find( L'\0') == std::wstring::npos &&
		   WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, value.text.data(),
							   static_cast<int>( value.text.size()), nullptr, 0, nullptr,
							   nullptr) > 0 ;
}
//------------------------------------------------------------------------------
/**
 * @brief 原sliceの静的範囲を親長へ結ぶ。
 * @param[in] slice 原範囲/hash/tuple。
 * @param[in] parentBytes 直近親の正確な長さ。
 * @return 正の有界範囲と完全な証拠ならtrue。
 */
//------------------------------------------------------------------------------
bool validSlice( const OfficialResourceSlice &slice, const std::uint64_t parentBytes) noexcept
{
	return validAtom( slice.resource.type) && validAtom( slice.resource.name) &&
		   slice.resource.language <= 65535U && slice.length > 0U && slice.length <= SMALL_BYTES &&
		   slice.offset <= parentBytes && slice.length <= parentBytes - slice.offset &&
		   validHash( slice.sha256) ;
}
//------------------------------------------------------------------------------
/**
 * @brief flatな原logical file名だけを認める。
 * @param[in] name 元basename。
 * @return 安全なASCII basenameならtrue。
 */
//------------------------------------------------------------------------------
bool flatName( const std::wstring_view name) noexcept
{
	return isSafeOfficialArchiveMember( name, L'\\') &&
		   name.find_first_of( L"/\\") == std::wstring_view::npos ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元memory全体を共通CNGへ渡す。
 * @param[in] bytes 固定原byte。
 * @param[in] expected 原期待hash。
 * @return 一致0、CNG失敗またはCRC不一致。
 */
//------------------------------------------------------------------------------
NativeError hashMatches( const std::span<const std::byte> bytes, const std::wstring_view expected)
{
	std::wstring hash ;	// 正規化しない実SHA-256。
	const auto	 error = computeDriverContainerSha256(
		  {reinterpret_cast<const char *>( bytes.data()), bytes.size()}, hash) ;	// 共通有界hash。
	return error != 0 ? error : hash == expected ? 0 : HRESULT_FROM_WIN32( ERROR_CRC) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元7z一memberをhash/CRCへ結んでmemoryだけへ読む。
 * @param[in] root 固定原outer。
 * @param[in] plan 原選択。
 * @param[out] inner 全成功時だけ返す原中間byte。
 * @param[in] cancellation 元workerの取消し照会。
 * @return 完了0、元HRESULT。
 */
//------------------------------------------------------------------------------
NativeError readInner( const std::span<const std::byte>	 root,
					  const OfficialResourceContentPlan &plan, std::vector<std::byte> &inner,
					  const std::function<bool()> &cancellation)
{
	// decode前の取消しを保持する。
	if( cancellation && cancellation()) {
		return HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
	}

	std::span<const std::byte> archive ;									// 親ownerの寿命内だけの7z。
	auto error = bindOfficialResourceSlice( root, plan.archive, archive) ;	// 範囲/hashの元診断。
	std::vector<OfficialSevenZipEntry> entries ;							// 全事前検査済み元entry。
	// 原slice失敗時にdecoderを起動しない。
	if( error == 0) {
		error = inspectOfficialSevenZip( archive, SEVEN_POLICY, entries) ;
	}

	// 全archive破損を一member選択で無視しない。
	if( error != 0) {
		return error ;
	}

	const auto found = std::ranges::find_if( entries, [&]( const auto &entry) {
		return entry.relativePath == plan.memberPath ;
	}) ; // 原名の唯一一致。
	// 名前/size不一致を先頭memberへ補完しない。
	if( found == entries.end() || found->uncompressedSize != plan.memberBytes) {
		return HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
	}

	error = extractOfficialSevenZipFile( archive, SEVEN_POLICY, found->archiveIndex, inner,
										cancellation) ;
	// 全decoder CRCと取消しを成功したbyteだけへhashを付ける。
	if( error == 0) {
		error = hashMatches( inner, plan.memberSha256) ;
	}

	// 不一致の中間byteを呼出し側へ残さない。
	if( error != 0) {
		inner.clear() ;
	}

	return error ;
}
/** @brief 同期書込みfileのhandleを例外時も解放する。 */
struct RoleHandle {
	/// CREATE_NEWした現在file。
	HANDLE value{INVALID_HANDLE_VALUE} ;
	/**
	 * @brief 開いている現在handleだけを閉じる。
	 */
	~RoleHandle()
	{
		// 未取得の値をWin32へ渡さない。
		if( value != INVALID_HANDLE_VALUE) {
			CloseHandle( value) ;
		}
	}
} ;
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 形式・byte数・親範囲・役割の有限な静的契約を検査する。
 * @param[in] plan 元recordに結んだ計画。
 * @return 全静的契約を満たす場合true。I/O・署名検証はしない。
 */
//------------------------------------------------------------------------------
bool validOfficialResourceContentPlan( const OfficialResourceContentPlan &plan) noexcept
{
	// byte宣言と原名/hashが全て揃ってからfile保存を許可する。
	if( plan.rootBytes == 0U || plan.rootBytes > SMALL_BYTES || !validHash( plan.rootSha256) ||
	   !validSlice( plan.archive, plan.rootBytes) ||
	   !isSafeOfficialArchiveMember( plan.memberPath, L'\\') || plan.memberBytes == 0U ||
	   plan.memberBytes > SMALL_BYTES || !validHash( plan.memberSha256) || plan.files.size() < 2U ||
	   plan.files.size() > 32U || !flatName( plan.selectedInf)) {
		return false ;
	}

	std::size_t	  infs{} ;		// 明示INFの件数。
	std::size_t	  catalogs{} ;	// 明示CATの件数。
	std::uint64_t total{} ;		// 実保存するrole長の共同枠。
	// 同名と未知roleを含め、全inventoryを保存前に検査する。
	for( std::size_t index = 0U; index < plan.files.size(); ++index) {
		const auto &file = plan.files[index] ;	// 元fileの閉じた宣言。
		// 親範囲と一file/共同容量を減算で確認する。
		if( !flatName( file.basename) || !validSlice( file.slice, plan.memberBytes) ||
		   file.slice.length > 32ULL * MIB || file.slice.length > SMALL_BYTES - total) {
			return false ;
		}

		total += file.slice.length ;
		// 保存先はWindowsのcase非依存identityで一意とする。
		for( std::size_t prior = 0U; prior < index; ++prior) {
			// 原資源のaliasを禁じず、出力名の衝突だけを拒否する。
			if( CompareStringOrdinal( file.basename.data(), static_cast<int>( file.basename.size()),
									plan.files[prior].basename.data(),
									static_cast<int>( plan.files[prior].basename.size()),
									TRUE) == CSTR_EQUAL) {
				return false ;
			}
		}

		// 元roleを拡張子から暗黙推測しない。
		switch( file.role) {
			// 一件の選択INF。
			case OfficialResourceRole::INF:
				++infs ;
				// role名と選択原名を一致させる。
				if( file.basename != plan.selectedInf || file.slice.length > MIB ||
				   file.basename.size() < 4U ||
				   _wcsicmp( file.basename.c_str() + file.basename.size() - 4U, L".inf") != 0) {
					return false ;
				}

				break ;

			// 元CATは一件だけ。
			case OfficialResourceRole::CATALOG:
				++catalogs ;
				// 役割を別形式へ偽装しない。
				if( file.basename.size() < 4U ||
				   _wcsicmp( file.basename.c_str() + file.basename.size() - 4U, L".cat") != 0) {
					return false ;
				}

				break ;

			// 本体の作用と必要性は元INF/共通closureが検査する。
			case OfficialResourceRole::DRIVER_FILE:
				break ;

			// 未知roleは選択しない。
			default:
				return false ;
		}
	}

	return infs == 1U && catalogs == 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定親の範囲と子hashを検査し、借用viewだけを返す。
 * @param[in] parent 呼出し後も借用viewより長く生存する固定親。
 * @param[in] slice 署名record由来の正の範囲とhash。
 * @param[out] result 成功時だけ借用する原範囲。失敗時は空。
 * @return 全範囲/hash一致0、元HRESULT。PE treeは解析しない。
 */
//------------------------------------------------------------------------------
NativeError bindOfficialResourceSlice( const std::span<const std::byte> parent,
									  const OfficialResourceSlice	  &slice,
									  std::span<const std::byte>	  &result)
{
	result = {} ;
	// 原親外と不完全hashを借用viewへ変換しない。
	if( parent.empty() || parent.size() > SMALL_BYTES || !validSlice( slice, parent.size())) {
		return E_INVALIDARG ;
	}

	const auto selected = parent.subspan( static_cast<std::size_t>( slice.offset),
										 // 検査済み減算範囲。
										 static_cast<std::size_t>( slice.length)) ;
	const auto error	= hashMatches( selected, slice.sha256) ;	// 原子byteの共通hash。
	// 一致する原範囲だけを返す。
	if( error == 0) {
		result = selected ;
	}

	return error ;
}

/** @brief readerの借用viewより長く生存する所有状態。 */
struct OfficialResourceContentReader::State {
	/// 原outerを固定するowner。
	OfficialMappedFile			  outer ;
	/// 原7zからCRC検証した一member。file化しない。
	std::vector<std::byte>		  inner ;
	/// 元recordから複写した不変の選択。
	OfficialResourceContentPlan	  plan ;
	/// 全roleの原名/size/hash。
	std::vector<OfficialZipEntry> entries ;
	/// 元同期操作の取消し照会。
	std::function<bool()>		  cancellation ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 空のownerを作る。
 */
//------------------------------------------------------------------------------
OfficialResourceContentReader::OfficialResourceContentReader() noexcept = default ;
//------------------------------------------------------------------------------
/**
 * @brief 全借用viewより後に原ownerを回収する。
 */
//------------------------------------------------------------------------------
OfficialResourceContentReader::~OfficialResourceContentReader() = default ;
//------------------------------------------------------------------------------
/**
 * @brief 全親子hash/CRCを検証してflat role inventoryを確定する。
 * @param[in] path 非reparse原outer絶対path。
 * @param[in] plan 原record由来の完全な計画。
 * @param[in] cancellation 任意の非blocking取消し照会。
 * @return 全検証成功0、元HRESULT。中間EXEはfile化しない。
 */
//------------------------------------------------------------------------------
NativeError OfficialResourceContentReader::initialize( const std::wstring_view			 path,
													  const OfficialResourceContentPlan &plan,
													  const std::function<bool()> &cancellation)
{
	state_.reset() ;
	// file I/O前に全静的契約と取消しを検査する。
	if( !validOfficialResourceContentPlan( plan)) {
		return E_INVALIDARG ;
	}

	try {
		// 開始前の取消しを保存失敗等で上書きしない。
		if( cancellation && cancellation()) {
			return HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
		}

		auto next		   = std::make_unique<State>() ;	// 全成功前には公開しないowner。
		next->plan		   = plan ;
		next->cancellation = cancellation ;
		auto error		   = next->outer.open( path, SMALL_BYTES) ;	// 原非reparse固定入力。
		// 固定失敗時は別pathや歴史fileへfallbackしない。
		if( error != 0) {
			return error ;
		}

		// 同じ固定handleで読む原親のsize/hash。
		if( next->outer.bytes().size() != plan.rootBytes) {
			return HRESULT_FROM_WIN32( ERROR_CRC) ;
		}

		error = hashMatches( next->outer.bytes(), plan.rootSha256) ;
		// 親改変時は7zを読む前に終了する。
		if( error != 0) {
			return error ;
		}

		error = readInner( next->outer.bytes(), plan, next->inner, cancellation) ;
		// 中間hash/CRC失敗時は部分roleを公開しない。
		if( error != 0) {
			return error ;
		}

		// 端末はinner PE treeを走査せず、署名原範囲/hashだけを検査する。
		for( const auto &file : plan.files) {
			// roleごとの取消しを確認する。
			if( cancellation && cancellation()) {
				return HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
			}

			std::span<const std::byte> bytes ;	// inner ownerを借用する原role。
			error = bindOfficialResourceSlice( next->inner, file.slice, bytes) ;
			// 元byte不一致を検査済みinventoryへ入れない。
			if( error != 0) {
				return error ;
			}

			next->entries.push_back( {file.basename, file.slice.length, file.slice.sha256}) ;
		}

		// 最後のhash中に届いた取消しも成功へ公開しない。
		if( cancellation && cancellation()) {
			return HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
		}

		state_ = std::move( next) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 全原hashに結んだrole一覧を借用する。
 * @return owner生存中の原名/size/hash。未初期化では空。
 */
//------------------------------------------------------------------------------
std::span<const OfficialZipEntry> OfficialResourceContentReader::entries() const noexcept
{
	return state_ ? std::span<const OfficialZipEntry>( state_->entries)
				  : std::span<const OfficialZipEntry>{} ;
}
//------------------------------------------------------------------------------
/**
 * @brief 選択roleだけを所有workspaceへ新規保存する。
 * @param[in] selected inventory内の重複しない原名集合。
 * @param[in,out] workspace 初期化済みの出力所有者。
 * @param[out] entries 全成功時だけ保存済み原名/size/hash。
 * @return 全保存成功0、取消し/保存失敗時は今回所有分だけ回収し元HRESULT。
 */
//------------------------------------------------------------------------------
NativeError OfficialResourceContentReader::extract(
	const std::span<const std::wstring_view> selected, OfficialDownloadWorkspace &workspace,
	std::vector<OfficialZipEntry> &entries)
{
	entries.clear() ;
	// 無効ownerや空選択を保存処理へ渡さない。
	if( !state_ || selected.empty() || selected.size() > 32U) {
		return E_INVALIDARG ;
	}

	std::size_t created{} ;	// 今回作成した先頭file数。
	NativeError error{} ;	// 最初の保存/取消し失敗。
	try {
		std::vector<const OfficialResourceRoleFile *> files ;	// 保存前に全選択を一意解決。
		// 任意名や重複を作成前に拒否する。
		for( const auto name : selected) {
			const auto found = std::ranges::find_if( state_->plan.files, [&]( const auto &file) {
				return file.basename == name ;
			}) ; // 元原名一致。
			// 既存未知fileを触る前に選択全体を拒否する。
			if( found == state_->plan.files.end() ||
			   std::ranges::find( files, &*found) != files.end()) {
				return E_INVALIDARG ;
			}

			files.push_back( &*found) ;
		}

		std::vector<OfficialZipEntry> output ;	// 全成功前には公開しない保存結果。
		output.reserve( files.size()) ;
		// 必要roleだけをCREATE_NEWする。
		for( const auto *file : files) {
			// 作成直前の取消しも所有cleanupへ送る。
			if( state_->cancellation && state_->cancellation()) {
				error = HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
				break ;
			}

			{
				RoleHandle handle ;	// 例外より先に閉じる現在file。
				error = workspace.createFile( file->basename, handle.value) ;
				// 未作成なら既存未知fileをcleanupしない。
				if( error != 0) {
					break ;
				}

				++created ;
				const auto bytes =
					std::span<const std::byte>( state_->inner)
						.subspan( static_cast<std::size_t>( file->slice.offset),
								 static_cast<std::size_t>(
									 file->slice.length)) ;	// 初期化時hash検査済み原view。
				std::size_t offset{} ;						// 現在fileの確定書込み量。
				// 有界chunkごとに取消しと実書込み長を確認する。
				while( offset < bytes.size()) {
					// 同期workerの取消しを実書込み前に確認する。
					if( state_->cancellation && state_->cancellation()) {
						error = HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
						break ;
					}

					const auto count = static_cast<DWORD>(
						std::min<std::size_t>( bytes.size() - offset, MIB)) ;	// 一回の有界書込み。
					DWORD	   written{} ;										// Win32の実書込みbyte。
					// 短い書込みも成功へ補完しない。
					const BOOL saved = WriteFile( handle.value, bytes.data() + offset, count,
												 &written, nullptr) ;	// 元API成否を保持。
					// falseの元診断と成功した短い書込みを区別する。
					if( !saved || written != count) {
						error = HRESULT_FROM_WIN32( !saved ? GetLastError() : ERROR_WRITE_FAULT) ;
						break ;
					}

					offset += written ;
				}
			}
			// file handleを閉じてから実保存内容を再照合する。
			if( error == 0) {
				error = verifyOfficialFileMetadata( workspace.path( file->basename),
												   {file->slice.length, file->slice.sha256}) ;
			}

			// 保存/byte不一致は全体失敗として今回分を回収する。
			if( error != 0) {
				break ;
			}

			output.push_back( {file->basename, file->slice.length, file->slice.sha256}) ;
		}

		// 終端の取消しを部分成功にしない。
		if( error == 0 && state_->cancellation && state_->cancellation()) {
			error = HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
		}

		// 全成功時だけ所有file一覧を公開する。
		if( error == 0) {
			entries = std::move( output) ;
			return 0 ;
		}
	} catch( const std::bad_alloc &) {
		error = E_OUTOFMEMORY ;
	} catch( ...) {
		error = E_UNEXPECTED ;
	}

	// 作成順と逆に今回所有fileだけを削除し、未知既存fileを残す。
	while( created > 0U) {
		static_cast<void>( workspace.discardFile( selected[--created])) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief collector専用に親identityと既知leaf hashから正式範囲を解決する。
 * @param[in] path 非reparseの原outer絶対path。
 * @param[in] requested 原root/7z/member/role size/hashとouter tuple。inner範囲は未確定可。
 * @param[out] result 全原byte検証後だけinnerの一意tuple/offsetを確定する。
 * @param[in] cancellation 任意の非blocking取消し照会。
 * @return 解決成功0、曖昧・不一致・取消し等はHRESULT。中間EXEは保存しない。
 */
//------------------------------------------------------------------------------
NativeError resolveOfficialResourceContentPlan( const std::wstring_view			  path,
											   const OfficialResourceContentPlan &requested,
											   OfficialResourceContentPlan		 &result,
											   const std::function<bool()>		 &cancellation)
{
	result = {} ;
	// callerが直接作った入力でも、解決前の宣言数/量/hashを有限契約へ結ぶ。
	if( requested.files.size() < 2U || requested.files.size() > 32U) {
		return E_INVALIDARG ;
	}

	try {
		auto skeleton			= requested ;	// inner位置だけ未確定を許す静的検査用copy。
		skeleton.archive.offset = 0U ;
		// 未確認位置を正式値として採用せず、役割/宣言/hashだけを事前検査する。
		for( auto &file : skeleton.files) {
			file.slice.offset	= 0U ;
			file.slice.resource = {} ;
		}

		// 不完全な原期待値でI/O/decoderを始めない。
		if( !validOfficialResourceContentPlan( skeleton)) {
			return E_INVALIDARG ;
		}

		OfficialMappedFile outer ;									// collectorの原非reparse固定owner。
		auto			   error = outer.open( path, SMALL_BYTES) ;	// 原入力アクセスの元診断。
		// アクセス拒否を別toolや保存済みmiddleへ回避しない。
		if( error != 0) {
			return error ;
		}

		// 原outerの完全identityを解決前に要求する。
		if( outer.bytes().size() != requested.rootBytes || !validHash( requested.rootSha256)) {
			return E_INVALIDARG ;
		}

		error = hashMatches( outer.bytes(), requested.rootSha256) ;
		// 不一致の原親をresource証拠へ使わない。
		if( error != 0) {
			return error ;
		}

		std::vector<OfficialResourceSlice> resources ;	// nativeに読んだ原tuple/range。
		error = collectOfficialPeResourceRanges( outer.bytes(), resources) ;
		// 原PE構造失敗をrange推測へfallbackしない。
		if( error != 0) {
			return error ;
		}

		const auto archive = std::ranges::find_if( resources, [&]( const auto &item) {
			return item.resource == requested.archive.resource ;
		}) ; // 明示原tupleのみ。
		// 同名の別言語を既定選択しない。
		if( archive == resources.end() || archive->length != requested.archive.length) {
			return HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
		}

		auto plan			= requested ;	// 全成功前には公開しない解決値。
		plan.archive.offset = archive->offset ;
		std::vector<std::byte> inner ;	// 元EXE memberはmemory内だけ。
		error = readInner( outer.bytes(), plan, inner, cancellation) ;
		// CRC/hash失敗の中間byteをnative証拠へ使わない。
		if( error != 0) {
			return error ;
		}

		error = collectOfficialPeResourceRanges( inner, resources) ;
		// listing文字列や仮tupleで不完全値を補完しない。
		if( error != 0) {
			return error ;
		}

		// 既知の原file size/hashごとにnative leafを唯一解決する。
		for( auto &file : plan.files) {
			std::size_t			  matches{} ;	// 複数同一hash leafを曖昧のまま選ばない。
			OfficialResourceSlice resolved ;	// 一意成功時だけ使うtuple/range。
			// 選択外resourceをfile化せず原範囲のhashだけ照合する。
			for( const auto &leaf : resources) {
				// sizeが一致する候補だけをhashする。
				if( leaf.length == file.slice.length) {
					auto candidate	 = leaf ;	// 元native tuple/rangeに期待hashを結ぶ。
					candidate.sha256 = file.slice.sha256 ;
					std::span<const std::byte> bytes ;	// 同期中だけの原leaf。
					// 既知hashと一致する元leafだけを数える。
					if( bindOfficialResourceSlice( inner, candidate, bytes) == 0) {
						resolved = std::move( candidate) ;
						++matches ;
					}
				}
			}

			// 欠損と曖昧を正式recipeへ変換しない。
			if( matches != 1U) {
				return HRESULT_FROM_WIN32( matches == 0U ? ERROR_NOT_FOUND : ERROR_DUP_NAME) ;
			}

			file.slice = std::move( resolved) ;
		}

		// 完全な親子/role証拠と終端取消しを最後に確認する。
		if( !validOfficialResourceContentPlan( plan)) {
			return E_INVALIDARG ;
		}

		// 取消し後の正式recipeを公開しない。
		if( cancellation && cancellation()) {
			return HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
		}

		result = std::move( plan) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}
} // namespace drivercrate
