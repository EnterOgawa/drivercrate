//------------------------------------------------------------------------------
/**
 * @file mtd_queue_internal.cpp
 * @brief MTDの原queueと制御queueを全原COPYへ結合します
 * @version 01.00.00
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
 * </pre>
 *
 * @note 原queueの公開tupleと非公開事項の別検査を混同しません
 */
//------------------------------------------------------------------------------
#include "platform/mtd_queue_internal.h"
#include "platform/driver_store_inf_transport_internal.h"
#include "platform/official_download_workspace.h"

#include <algorithm>
#include <cwchar>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
using driver_store_inf_detail::MtdTransport ;

//------------------------------------------------------------------------------
/**
 * @brief 元Windows errorを非零HRESULTに変換します
 * @param[in] error 直前の原Windows errorです
 * @return 非零diagnosticを持つHRESULTです
 */
//------------------------------------------------------------------------------
NativeError queueError( DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error ? error : ERROR_INVALID_DATA)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 完全な二文字列をWindows ordinal規則で比較します
 * @param[in] left 比較元です
 * @param[in] right 比較先です
 * @return 完全一致だけtrueです
 */
//------------------------------------------------------------------------------
bool queueSame( std::wstring_view left, std::wstring_view right) noexcept
{
	return !left.empty() && left.size() == right.size() && left.size() < 32768U &&
		   CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windows callbackの有限null終端文字列を借用します
 * @param[in] text callbackが返す文字列です
 * @return 有効な全文字列です。不正なら空です
 */
//------------------------------------------------------------------------------
std::wstring_view queueString( const wchar_t *text) noexcept
{
	// null callback文字列を不正な空値として返します
	if( !text) {
		return {} ;
	}

	// Windows文字列の有限長です
	const auto size = wcsnlen_s( text, 32768U) ;
	return size == 0U || size >= 32768U ? std::wstring_view{} : std::wstring_view{text, size} ;
}

/** @brief 原順に対応させるSCAN callbackの状態です */
struct ScanState {
	/// 元INFから得た原COPY行です
	const std::vector<SelectedStorageCopyFact> &copies ;
	/// 原queueのsource順です
	const std::vector<std::wstring>			   &originalSources ;
	/// SYSの正規targetです
	const std::wstring						   &systemTarget ;
	/// 制御queueの照合時はtrueです
	bool										controlled{} ;
	/// 各行に対応した観測sourceです
	std::vector<std::wstring>					sources ;
	/// 一対一照合済みの行です
	std::vector<bool>							seen ;
	/// callbackが保持する元Windows errorです
	DWORD										error{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief queueが返すcopy tupleを元行へ一対一に結びます
 * @param[in,out] context 同期中のSCAN状態です
 * @param[in] notification Windowsの公開通知です
 * @param[in] first FILEPATHS_Wの借用値です
 * @param[in] second Windowsの追加値です
 * @return 全継続は0、不正値は非零です
 */
//------------------------------------------------------------------------------
UINT CALLBACK scanCallback( PVOID context, UINT notification, UINT_PTR first, UINT_PTR second)
{
	// 同期SCAN callbackの借用状態です
	auto &state = *static_cast<ScanState *>( context) ;
	try {
		// 未知通知や予期しない追加値から原queue一致を合成しません
		if( notification != SPFILENOTIFY_QUEUESCAN_EX || !first || second != 0U) {
			state.error = ERROR_INVALID_DATA ;
			return state.error ;
		}

		// Windows通知から借用した原path tupleです
		const auto &path = *reinterpret_cast<const FILEPATHS_W *>( first) ;
		// 通知sourceの有限文字列です
		const auto	source = queueString( path.Source) ;
		// 通知targetの有限文字列です
		const auto	target = queueString( path.Target) ;
		// 同targetに対応する元COPY行です
		const auto	it = std::ranges::find_if(
			 state.copies, [&]( const auto &copy) { return queueSame( copy.target, target) ; }) ;
		// 元行にないtargetや空sourceを拒否します
		if( source.empty() || it == state.copies.end()) {
			state.error = ERROR_INVALID_DATA ;
			return state.error ;
		}

		// 原行の順序に対応するindexです
		const auto	index = static_cast<std::size_t>( it - state.copies.begin()) ;
		// SYSと共有DLLで区別する期待flagsです
		const DWORD flags = state.controlled && !queueSame( it->target, state.systemTarget)
								? SP_COPY_FORCE_NOOVERWRITE
								: 0U ;
		// 原行の重複、flags差、制御queueのsource差を拒否します
		if( state.seen[index] || path.Flags != flags ||
		   (state.controlled && !queueSame( source, state.originalSources[index]))) {
			state.error = ERROR_INVALID_DATA ;
			return state.error ;
		}

		state.seen[index]	 = true ;
		state.sources[index] = source ;
		return NO_ERROR ;
	} catch( ...) {
		state.error = ERROR_NOT_ENOUGH_MEMORY ;
		return state.error ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief copy/delete/rename件数と全公開copy tupleを照合します
 * @param[in] api 同workerの完全低位表です
 * @param[in] queue 同操作が所有するqueueです
 * @param[in,out] state 元行と照合結果です
 * @return 全件一致0、未知操作又は元API失敗はHRESULTです
 */
//------------------------------------------------------------------------------
NativeError scanMtdQueue( const MtdTransport &api, HSPFILEQ queue, ScanState &state)
{
	// copy以外のdeleteとrenameがないことも独立に確認します
	for( const auto kind : {FILEOP_COPY, FILEOP_DELETE, FILEOP_RENAME}) {
		// Windows queueが返す同操作種別の件数です
		UINT count{} ;
		// 件数照会の元Windows失敗を保持します
		if( !api.queueCount( queue, kind, &count)) {
			return queueError( GetLastError()) ;
		}

		// COPY全件と余分actionなしの個数を照合します
		if( count != (kind == FILEOP_COPY ? state.copies.size() : 0U)) {
			return queueError( ERROR_INVALID_DATA) ;
		}
	}

	// scan APIが返す結果値です
	DWORD result{} ;
	SetLastError( ERROR_SUCCESS) ;
	// callbackと合わせて確認するscan APIの成否です
	const auto ok =
		api.scanQueue( queue, SPQ_SCAN_USE_CALLBACKEX, nullptr, &scanCallback, &state, &result) ;
	// callbackが観測した最初の拒否を優先します
	if( state.error) {
		return queueError( state.error) ;
	}

	// scan APIの失敗を元Windows診断に結びます
	if( !ok) {
		return queueError( GetLastError()) ;
	}

	// 不一致または未照合の行が残るqueueを拒否します
	if( result != 0U || std::ranges::any_of( state.seen, []( bool seen) { return !seen ; })) {
		return queueError( ERROR_INVALID_DATA) ;
	}

	return 0U ;
}

/** @brief commit callbackの有限原結果です */
struct CommitState {
	/// 元INFから得た原COPY行です
	const std::vector<SelectedStorageCopyFact> &copies ;
	/// 保持した原sourceです
	const std::vector<std::wstring>			   &sources ;
	/// SYSの正規targetです
	const std::wstring						   &systemTarget ;
	/// 同operationの保持済みfileです
	MtdSharedFileOperation					   &files ;
	/// 内部操作の任意取消し判定です
	const std::function<bool()>				   &cancelled ;
	/// 同commitの部分結果です
	MtdQueueResult							   &result ;
	/// copy開始を観測した原行です
	std::vector<bool>							started ;
	/// copy終端を観測した原行です
	std::vector<bool>							ended ;
	/// queue開始通知を観測した場合trueです
	bool										queueStarted{} ;
	/// copy subqueue開始を観測した場合trueです
	bool										subqueueStarted{} ;
	/// queue終端通知を観測した場合trueです
	bool										queueEnded{} ;
	/// callbackが保持する元Windows errorです
	DWORD										error{} ;
	/// 元検証が返したHRESULTです
	NativeError									verificationError{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief callbackの対象を同原source/targetと制御flagsへ照合します
 * @param[in] state 同操作の原copy集合です
 * @param[in] path Windowsから借用したtupleです
 * @return 対応する原index、不一致はcopy数です
 */
//------------------------------------------------------------------------------
std::size_t commitIndex( const CommitState &state, const FILEPATHS_W &path)
{
	// 通知targetの有限文字列です
	const auto target = queueString( path.Target) ;
	// 通知sourceの有限文字列です
	const auto source = queueString( path.Source) ;
	// 通知されたtupleを同原COPY集合から探します
	for( std::size_t i = 0U; i < state.copies.size(); ++i) {
		// 同indexの原COPY行です
		const auto &copy = state.copies[i] ;
		// そのtargetに対する制御queueの期待flagsです
		const auto	flags =
			 queueSame( copy.target, state.systemTarget) ? 0U : SP_COPY_FORCE_NOOVERWRITE ;
		// source・target・制御flagsが同じ原行だけを採用します
		if( queueSame( target, copy.target) && queueSame( source, state.sources[i]) &&
		   path.Flags == flags) {
			return i ;
		}
	}

	return state.copies.size() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元memberだけの媒体とcopyを許し未知操作を中止します
 * @param[in,out] context 同期中のcommit状態です
 * @param[in] notification Windowsの通知です
 * @param[in] first 通知に応じた借用値です
 * @param[in] second 通知に応じた借用値です
 * @return 正規継続は1、拒否は0です
 */
//------------------------------------------------------------------------------
UINT CALLBACK commitCallback( PVOID context, UINT notification, UINT_PTR first, UINT_PTR second)
{
	// 同期commit callbackの借用状態です
	auto &state = *static_cast<CommitState *>( context) ;
	try {
		// 内部取消しでは既に生じた作用を残してcommitを中止します
		if( state.cancelled && state.cancelled()) {
			state.error = ERROR_CANCELLED ;
			return FILEOP_ABORT ;
		}

		// 公開された各通知を順序と元tupleごとに検査します
		switch( notification) {
			// queue全体の開始通知を検査します
			case SPFILENOTIFY_STARTQUEUE:
				// queue開始の重複や想定外引数を拒否します
				if( state.queueStarted || first || second) {
					break ;
				}

				state.queueStarted = true ;
				return TRUE ;
			// COPY subqueueの開始通知を検査します
			case SPFILENOTIFY_STARTSUBQUEUE:
				// COPY subqueueの順序と原件数を確認します
				if( !state.queueStarted || state.subqueueStarted || first != FILEOP_COPY ||
				   second != state.copies.size()) {
					break ;
				}

				state.subqueueStarted = true ;
				return TRUE ;
			// COPY subqueueの終了通知を検査します
			case SPFILENOTIFY_ENDSUBQUEUE:
				// 開始済みCOPY subqueueだけを終端します
				if( !state.subqueueStarted || first != FILEOP_COPY || second) {
					break ;
				}

				state.subqueueStarted = false ;
				return TRUE ;
			// queue全体の終了通知を検査します
			case SPFILENOTIFY_ENDQUEUE:
				// subqueue終了後の正規queue終端だけを認めます
				if( !state.queueStarted || state.subqueueStarted || state.queueEnded || !first ||
				   second) {
					break ;
				}

				state.queueEnded = true ;
				return TRUE ;
			// 同原sourceだけの媒体要求を検査します
			case SPFILENOTIFY_NEEDMEDIA: {
				// COPY subqueue中の媒体要求だけを評価します
				if( !state.subqueueStarted || !first) {
					break ;
				}

				// Windowsが要求した媒体情報です
				const auto &media = *reinterpret_cast<const SOURCE_MEDIA_W *>( first) ;
				// 要求媒体のsource directoryです
				const auto	directory = queueString( media.SourcePath) ;
				// 要求された媒体file名です
				const auto	leaf = queueString( media.SourceFile) ;
				// 未知媒体、tagや不正な媒体名を参照しません
				if( directory.empty() || leaf.empty() || (media.Tagfile && *media.Tagfile) ||
				   leaf.find_first_of( L"\\/:") != leaf.npos) {
					break ;
				}

				// 要求媒体の完全source文字列です
				const std::wstring source = std::wstring{directory} + L"\\" + std::wstring{leaf} ;
				// 媒体要求のsourceとflagsを保持済み原行に結びます
				for( std::size_t i = 0U; i < state.sources.size(); ++i) {
					// 同原行に必要な制御queue flagsです
					const DWORD flags = queueSame( state.copies[i].target, state.systemTarget)
											? 0U
											: SP_COPY_FORCE_NOOVERWRITE ;
					// 同原sourceだけUIなしで媒体要求を継続します
					if( queueSame( source, state.sources[i]) && media.Flags == flags) {
						return FILEOP_DOIT ;
					}
				}

				break ;
			}
			// 原copyの開始を照合します
			case SPFILENOTIFY_STARTCOPY:
			// 原copyの終了を照合します
			case SPFILENOTIFY_ENDCOPY:
			// 原copyの失敗を保持します
			case SPFILENOTIFY_COPYERROR:
			// SYSとDLLの遅延通知を区別します
			case SPFILENOTIFY_FILEOPDELAYED: {
				// 予期しない順序のcopy通知を拒否します
				if( !state.subqueueStarted || !first) {
					break ;
				}

				// Windows通知から借用したcopy tupleです
				const auto &path = *reinterpret_cast<const FILEPATHS_W *>( first) ;
				// source・target・flagsが一致した原行indexです
				const auto	index = commitIndex( state, path) ;
				// 同原tupleに一致しないcopy通知を拒否します
				if( index >= state.copies.size()) {
					break ;
				}

				// 同原行がSYSか共有DLLかの区別です
				const bool system = queueSame( state.copies[index].target, state.systemTarget) ;
				// copy開始時に一回性と保持状態を確認します
				if( notification == SPFILENOTIFY_STARTCOPY) {
					// 重複開始、終了後の再開始、開始時errorを拒否します
					if( state.started[index] || state.ended[index] || path.Win32Error) {
						break ;
					}

					// 共有DLLはcopy開始前にも保持した原byteを照合します
					if( !system) {
						state.verificationError = state.files.verify() ;
						// 共有先の変化を検出したら元診断でcommitを中止します
						if( state.verificationError != 0U) {
							return FILEOP_ABORT ;
						}
					}

					state.started[index] = true ;
					return FILEOP_DOIT ;
				}

				// copyの元Windows errorを保持して処理を中止します
				if( notification == SPFILENOTIFY_COPYERROR) {
					state.error = path.Win32Error ? path.Win32Error : ERROR_INVALID_DATA ;
					return FILEOP_ABORT ;
				}

				// 遅延通知はSYSと共有DLLで別の結果として扱います
				if( notification == SPFILENOTIFY_FILEOPDELAYED) {
					// 共有DLLの遅延はこの経路の成功にしません
					if( !system) {
						break ;
					}

					state.result.systemDelayed = true ;
					return TRUE ;
				}

				// 開始のない終端、重複終端、元errorを拒否します
				if( !state.started[index] || state.ended[index] || path.Win32Error) {
					// Windowsのcopy errorを一般的な不正値より優先します
					if( path.Win32Error) {
						state.error = path.Win32Error ;
					}

					break ;
				}

				state.ended[index] = true ;
				return TRUE ;
			}
			// 未評価の通知を許可しません
			default:
				break ;
		}

		// 既に元errorがなければ未知通知を不正値として保持します
		if( !state.error) {
			state.error = ERROR_INVALID_DATA ;
		}

		return FILEOP_ABORT ;
	} catch( ...) {
		state.error = ERROR_NOT_ENOUGH_MEMORY ;
		return FILEOP_ABORT ;
	}
}
} // namespace

/** @brief 元に結合したqueueと同operationの借用状態です */
struct MtdQualifiedQueue::State {
	/**
	 * @brief 同operationの保持を借りてqueue状態を作ります
	 * @param[in,out] original 終端まで有効なfile保持です
	 */
	explicit State( MtdSharedFileOperation &original)
		: api( driver_store_inf_detail::transport().mtd), files( original)
	{
	}
	/**
	 * @brief この状態が所有するqueueとINFだけを閉じます
	 */
	~State()
	{
		// この状態が開いた有効queueだけを閉じます
		if( queue && queue != INVALID_HANDLE_VALUE) {
			api.closeQueue( queue) ;
		}

		// この状態が開いた有効INFだけを閉じます
		if( inf && inf != INVALID_HANDLE_VALUE) {
			api.closeInf( inf) ;
		}
	}
	/// 同workerの完全低位API表です
	const MtdTransport					&api ;
	/// 同operationのsourceとtarget保持です
	MtdSharedFileOperation				&files ;
	/// 所有する制御queueです
	HSPFILEQ							 queue{INVALID_HANDLE_VALUE} ;
	/// 同元登録INFの所有handleです
	HINF								 inf{INVALID_HANDLE_VALUE} ;
	/// 原INFに結んだ全COPY行です
	std::vector<SelectedStorageCopyFact> copies ;
	/// 原queueで確認したsourceです
	std::vector<std::wstring>			 sources ;
	/// SYSの正規targetです
	std::wstring						 systemTarget ;
	/// commitを開始した場合trueです
	bool								 attempted{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 保持した同operationの未公開queue状態を作ります
 * @param[in,out] files 同operation終端まで有効な保持です
 */
//------------------------------------------------------------------------------
MtdQualifiedQueue::MtdQualifiedQueue( MtdSharedFileOperation &files)
	: state_( std::make_unique<State>( files))
{
}

//------------------------------------------------------------------------------
/**
 * @brief 自分が開いたINFと制御queueだけを閉じます
 */
//------------------------------------------------------------------------------
MtdQualifiedQueue::~MtdQualifiedQueue() noexcept = default ;

//------------------------------------------------------------------------------
/**
 * @brief 元と制御queueの全copyを一対一に照合しsourceを固定します
 * @param[in] original 同選択DIF_INSTALLDEVICEFILESが構築した未commit queueです
 * @param[in] registeredInf 同原byteとして保持中の登録INFです
 * @param[in] workspace 同原ADMIN所有領域です
 * @param[in] facts 全原COPY行とCAT memberです
 * @param[in,out] files 同operationの共有先とsource保持です
 * @param[out] qualified 全照合時だけの所有queueです
 * @return 全tuple成立0、元API/未知作用/不一致はHRESULTです
 * @note この関数は原queueをcommitせず、共有先も変更しません
 */
//------------------------------------------------------------------------------
NativeError MtdQualifiedQueue::prepare( HSPFILEQ original, std::wstring_view registeredInf,
									   OfficialDownloadWorkspace		  &workspace,
									   const SelectedStorageServiceFacts  &facts,
									   MtdSharedFileOperation			  &files,
									   std::unique_ptr<MtdQualifiedQueue> &qualified)
{
	qualified.reset() ;
	// 不完全な低位表や原行欠損から制御queueを作りません
	if( !driver_store_inf_detail::mtdTransportReady() || !original ||
	   original == INVALID_HANDLE_VALUE || facts.mtdCopies.empty() ||
	   facts.mtdCopies.size() > 4096U || facts.binaryTarget.empty()) {
		return queueError( ERROR_INVALID_PARAMETER) ;
	}

	try {
		// 構築成功時だけ呼出し元へ渡すqueue所有です
		auto  made = std::unique_ptr<MtdQualifiedQueue>{new MtdQualifiedQueue( files)} ;
		// 構築中のqueue状態です
		auto &state		   = *made->state_ ;
		state.copies	   = facts.mtdCopies ;
		state.systemTarget = facts.binaryTarget ;
		state.sources.reserve( state.copies.size()) ;
		// 全原COPYについてsource・target・sectionを確認します
		for( const auto &copy : state.copies) {
			// 同原COPYのworkspace sourceです
			const auto source = workspace.path( copy.source) ;
			// workspace外や空の原COPY fieldを許可しません
			if( source.empty() || copy.target.empty() || copy.section.empty()) {
				return queueError( ERROR_INVALID_DATA) ;
			}

			state.sources.push_back( source) ;
		}

		// 原queueと全COPY行の照合状態です
		ScanState originalScan{state.copies,
							   state.sources,
							   state.systemTarget,
							   false,
							   std::vector<std::wstring>( state.copies.size()),
							   std::vector<bool>( state.copies.size())} ;
		// 原queue照合から保持する最初の診断です
		auto	  error = scanMtdQueue( state.api, original, originalScan) ;
		// 元queueの不一致があれば制御queueの構築を止めます
		if( error != 0U) {
			return error ;
		}

		error = files.bindQueueSources( registeredInf, originalScan.sources) ;
		// 原sourceの保持に失敗した診断を返します
		if( error != 0U) {
			return error ;
		}

		// 同原INFのworkspace pathです
		const auto infPath = workspace.path( facts.infRelativePath) ;
		// INF親directoryを切り出す区切り位置です
		const auto slash = infPath.find_last_of( L'\\') ;
		// 元INFの正規workspace pathと親が必要です
		if( infPath.empty() || slash == infPath.npos) {
			return queueError( ERROR_INVALID_NAME) ;
		}

		// 同原INFのsource directoryです
		const auto root = infPath.substr( 0U, slash) ;
		state.inf		= state.api.openInf( infPath.c_str(), nullptr,
											INF_STYLE_WIN4 | INF_STYLE_CACHE_DISABLE, nullptr) ;
		// 登録INFを開けない場合は原Windows診断を返します
		if( !state.inf || state.inf == INVALID_HANDLE_VALUE) {
			return queueError( GetLastError()) ;
		}

		state.queue = state.api.openQueue() ;
		// 制御queueを作れない場合は原Windows診断を返します
		if( !state.queue || state.queue == INVALID_HANDLE_VALUE) {
			return queueError( GetLastError()) ;
		}

		// 追加済みsectionとSYS区分の集合です
		std::vector<std::pair<std::wstring, bool>> sections ;
		// 原sectionを一回ずつ制御queueへ追加します
		for( const auto &copy : state.copies) {
			// 原行がSYSへ作用する場合trueです
			const bool system = queueSame( copy.target, state.systemTarget) ;
			// 同名sectionを追加済みかの検索結果です
			const auto found = std::ranges::find_if( sections, [&]( const auto &section) {
				return queueSame( section.first, copy.section) ;
			}) ;
			// 同sectionが既に登録済みなら重複追加しません
			if( found != sections.end()) {
				// 一つのsectionにSYSと共有DLLの異なるflagを混在させません
				if( found->second != system) {
					return queueError( ERROR_INVALID_DATA) ;
				}

				continue ;
			}

			sections.emplace_back( copy.section, system) ;
			// 元sectionを構成できない場合は原Windows失敗を保持します
			if( !state.api.queueSection( state.queue, root.c_str(), state.inf, nullptr,
									   copy.section.c_str(),
									   system ? 0U : SP_COPY_FORCE_NOOVERWRITE)) {
				return queueError( GetLastError()) ;
			}
		}

		// 制御queueと元tupleの照合状態です
		ScanState controlled{state.copies,
							 state.sources,
							 state.systemTarget,
							 true,
							 std::vector<std::wstring>( state.copies.size()),
							 std::vector<bool>( state.copies.size())} ;
		error = scanMtdQueue( state.api, state.queue, controlled) ;
		// 再構成したqueueの全tuple不一致を拒否します
		if( error != 0U) {
			return error ;
		}

		qualified = std::move( made) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 共有DLLを充足した後だけ同制御queueのSYS更新をcommitします
 * @param[in] parent 同明示操作の親windowです
 * @param[in] cancelled 同operationの取消し照会です
 * @param[in] authorization 同原record/UTCの作用直前再検証です
 * @param[out] result 部分配置、commit状態とSYS遅延を保持します
 * @return 全元作用の有限copy成立0、失敗又は取消しは元HRESULTです
 * @note 原queueはcommitせず、DLLの遅延通知は失敗と部分作用として扱います
 */
//------------------------------------------------------------------------------
NativeError MtdQualifiedQueue::commit( HWND parent, const std::function<bool()> &cancelled,
									  const std::function<NativeError()> &authorization,
									  MtdQueueResult					 &result)
{
	result.shared		   = {} ;
	result.systemDelayed   = false ;
	result.commitStarted   = false ;
	result.commitCompleted = false ;
	// 同operationが保持する制御queue状態です
	auto &state = *state_ ;
	// 再commitや期限照合のない操作を始めません
	if( state.attempted || !authorization || !state.queue || state.queue == INVALID_HANDLE_VALUE ||
	   !driver_store_inf_detail::mtdTransportReady()) {
		return queueError( ERROR_INVALID_STATE) ;
	}

	state.attempted = true ;
	try {
		// 元record再検証からの最初の診断です
		auto error = authorization() ;
		// 原recordが有効な場合だけ共有DLLの充足を開始します
		if( error == 0U) {
			error = state.files.satisfy( cancelled, authorization, result.shared) ;
		}

		// 充足済み件数を保持したまま最初の失敗を返します
		if( error != 0U) {
			return error ;
		}

		error = state.files.verify() ;
		// 保持fileの検証失敗後にqueueをcommitしません
		if( error != 0U) {
			return error ;
		}

		error = authorization() ;
		// commit直前の失効を元診断のまま返します
		if( error != 0U) {
			return error ;
		}

		// 同commitの通知順序と部分結果を保持するcallback状態です
		CommitState callback{state.copies,
							 state.sources,
							 state.systemTarget,
							 state.files,
							 cancelled,
							 result,
							 std::vector<bool>( state.copies.size()),
							 std::vector<bool>( state.copies.size())} ;
		result.commitStarted = true ;
		SetLastError( ERROR_SUCCESS) ;
		// 同期commit APIの成否です
		const auto	ok = state.api.commitQueue( parent, state.queue, &commitCallback, &callback) ;
		// API失敗直後に保持した元Windows errorです
		const DWORD nativeError = ok ? ERROR_SUCCESS : GetLastError() ;
		// callback内のfile再検証失敗を優先して保持します
		if( callback.verificationError) {
			return callback.verificationError ;
		}

		// callbackが記録した元Windows errorを保持します
		if( callback.error) {
			return queueError( callback.error) ;
		}

		// commit API自体の元失敗を返します
		if( !ok) {
			return queueError( nativeError) ;
		}

		// SYSに対応する同原COPY行です
		const auto system = std::ranges::find_if( state.copies, [&]( const auto &copy) {
			return queueSame( copy.target, state.systemTarget) ;
		}) ;
		// SYSの終端通知とqueue終端を確認できなければ成功にしません
		if( !callback.queueEnded || system == state.copies.end() ||
		   !callback.ended[static_cast<std::size_t>( system - state.copies.begin())]) {
			return queueError( ERROR_INVALID_DATA) ;
		}

		error = state.files.verify() ;
		// commit後に保持fileが変化した場合は元診断を返します
		if( error != 0U) {
			return error ;
		}

		result.commitCompleted = true ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}
} // namespace drivercrate
