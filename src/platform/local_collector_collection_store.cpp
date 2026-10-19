//------------------------------------------------------------------------------
/**
 * @file local_collector_collection_store.cpp
 * @brief 親保護writerの寿命と固定markerを子leaseへ結合します。
 * @version 01.08.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/01  親writer・marker・単一子leaseを実装。
 * Ver.01.01.00 Shunji Ogawa  2026/10/02  初回共有保存へ同一親／子能力を私有借用。
 * Ver.01.02.00 Shunji Ogawa  2026/10/02  専用子markerと同親の固定history所有を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/02  同親切替holdの強所有と排他保持を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/02  同一holdの準備保存借用と再入拒否を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/02  元intent保存後だけの私有新子writerを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/03  ROOT未保存の連続準備prefix回復と検査を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/03  初回reader専用の同親四handle所有を追加。
 * </pre>
 *
 * @note 自動移行・削除・通信は行いません。実fileの保護は既存storeを再利用します。
 */
//------------------------------------------------------------------------------
#include "local_collector_collection_store.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <new>
#include <utility>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
/** @brief 子に循環参照を作らず親writerを所有します。 */
struct CollectorCollectionSession {
	/// 親lock・ancestor handleを単独所有する保護store。
	std::shared_ptr<LocalCollectorStateStore> parent ;
	/// Manifestや区間から独立した恒久collection hash。
	std::wstring							  collection ;
	/// 最大一子が借用している間true。単一thread限定です。
	bool									  borrowed{} ;
	/// 共有保存／読戻しの再入を拒否する単一threadの借用状態。
	bool									  sharedBorrowed{} ;
	/// 切替holdが同親handleを保持中はtrue。単一thread限定です。
	bool									  switchHeld{} ;
} ;
/** @brief 元wrapper／leaseより長く同親handleと切替排他を保持します。 */
struct CollectorCollectionSwitchHold {
	/// 最後に解放する元親writer sessionです。
	std::shared_ptr<CollectorCollectionSession>		  session ;
	/// 固定historyより長く保持する元子writerです。
	std::shared_ptr<LocalCollectorStateStore>		  child ;
	/// HTTP閉鎖の返却まで保持する元固定history writerです。
	std::shared_ptr<LocalCollectorStateStore>		  history ;
	/// 新規準備または実回復が同親へ結合した新子の完全keyです。
	std::wstring									  nextKey ;
	/// 新子作成開始または既存二子の回復handle取得後だけtrueです。
	mutable bool									  newCreationStarted{} ;
	/// 固定新historyより長く保持する私有新子writerです。
	mutable std::shared_ptr<LocalCollectorStateStore> nextChild ;
	/// 新規の空履歴または専用初期ROOTだけの回復履歴を強所有します。
	mutable std::shared_ptr<LocalCollectorStateStore> nextHistory ;
	/// 全成功後だけtrue。途中確保の解放で元排他を変更しません。
	bool											  armed{} ;
	/// 同じholdの保存呼出し中だけtrue。元監督threadで使用します。
	mutable bool									  storageBorrowed{} ;
	/** @brief 同じholdの排他だけを解除します。fileは削除しません。 */
	~CollectorCollectionSwitchHold()
	{
		// 取得済みの一能力だけを最後の参照解放で返します。
		if( armed) {
			session->switchHeld = false ;
		}
	}
} ;
/** @brief 非作成readerの四handleだけを元親へ結合します。 */
struct CollectorCollectionReadHold {
	/// 最後のhandleより長く保持する同親sessionです。
	std::shared_ptr<CollectorCollectionSession> session ;
	/// 旧seal／inventoryを読む旧子です。旧historyを持ちません。
	std::shared_ptr<LocalCollectorStateStore>	oldChild ;
	/// 現在の新子です。公開mutable借用を発行しません。
	std::shared_ptr<LocalCollectorStateStore>	newChild ;
	/// 固定初期ROOTだけを読む新historyです。
	std::shared_ptr<LocalCollectorStateStore>	newHistory ;
	/// 全成功後だけ元親の排他を返す許可です。
	bool										armed{} ;
	/** @brief 四handleを閉じてから、最後の元所有の排他だけを返します。 */
	~CollectorCollectionReadHold()
	{
		newHistory.reset() ;
		newChild.reset() ;
		oldChild.reset() ;
		// 途中失敗の未発行所有から元親状態を変更しません。
		if( armed) {
			session->switchHeld = false ;
		}
	}
} ;
namespace {
/** @brief canonical markerに直接埋め込める完全hashを検査します。
 * @param[in] key 相対directoryにも使う小文字hash。
 * @return 有限ASCII hashならtrue。
 */
bool hashKey( std::wstring_view key)
{
	return key.size() == 64U && std::all_of( key.begin(), key.end(), []( wchar_t letter) {
			   return (letter >= L'0' && letter <= L'9') || (letter >= L'a' && letter <= L'f') ;
		   }) ;
}
/** @brief 検査済みASCII hashのbyteを作ります。
 * @param[in] key hashKey成立済みのborrowed key。
 * @return 一文字一byteの保存表現。
 */
std::string asciiHash( std::wstring_view key)
{
	std::string result ;	// 検査済み64 ASCII文字だけを格納します。
	result.reserve( key.size()) ;
	// 検査済みASCII範囲を一文字一byteへ明示変換します。
	for( const wchar_t letter : key) {
		result.push_back( static_cast<char>( letter)) ;
	}

	return result ;
}
/** @brief 親登録markerを固定順で作ります。
 * @param[in] key 検査済み恒久collection hash。
 * @return 完全一致検査に使用するcanonical本文。
 */
std::string parentMarker( std::wstring_view key)
{
	return "{\"schema\":\"collector-collection-store-v1\",\"mode\":\"SEGMENTED_METADATA_V1\",\"collection\":\"" +
		   asciiHash( key) + "\"}" ;
}
/** @brief 子markerをcollectionとsegmentへ結合します。
 * @param[in] collection 検査済み親key。
 * @param[in] segment 検査済み子key。
 * @param[in] withHistory 専用historyを持つmodeだけの場合true。
 * @return 固定順canonical本文。sealの証明ではありません。
 */
std::string childMarker( std::wstring_view collection, std::wstring_view segment,
						const bool withHistory = false)
{
	// 新配置を明示したcallerだけ別schemaに固定します。旧byteは変更しません。
	if( withHistory) {
		return "{\"schema\":\"collector-segment-history-store-v1\",\"collection\":\"" +
			   asciiHash( collection) + "\",\"segment\":\"" + asciiHash( segment) +
			   "\",\"history\":\"history\"}" ;
	}

	return "{\"schema\":\"collector-segment-store-v1\",\"collection\":\"" + asciiHash( collection) +
		   "\",\"segment\":\"" + asciiHash( segment) + "\"}" ;
}
/** @brief 同じ保護handle I/Oからmarkerを完全照合します。
 * @param[in,out] store 書込み初期化済みの保護store。
 * @param[in] expected 固定schemaのcanonical本文。
 * @param[in] create 空初回領域にmarker登録を許す場合true。
 * @param[in,out] remaining 指定時は同handle実sizeを先払いする共有raw残予算。
 * @return 成功0、非空欠損／差替え13、または第一I/O error。
 */
DWORD marker( LocalCollectorStateStore &store, std::string_view expected, bool create,
			 std::uint64_t *remaining = nullptr)
{
	std::string bytes ;		// 成功した同じ実fileの本文です。
	bool		found{} ;	// 欠損と不正本文を区別します。
	DWORD		code =
		  remaining
				  ? store.read( L"current/collector-campaign-mode-v1.json", bytes, found, *remaining)
				  : store.read( L"current/collector-campaign-mode-v1.json", bytes, found) ;	// 元I/O error。
	// 読めないmarkerを初回へ変更しません。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	// 既存markerはbyte一致でだけ受理します。
	if( found) {
		return bytes == expected ? ERROR_SUCCESS : ERROR_INVALID_DATA ;
	}

	// 非作成借用では欠損を登録しません。
	if( !create) {
		return ERROR_INVALID_DATA ;
	}

	CollectorStoreUsage usage ;	// 残留stagingも初回扱いへ含めません。
	code = store.inspectUsage( usage) ;
	// 非空の元fileを上書きしません。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	// 欠損markerの非空領域は後続回復契約まで停止します。
	if( usage.currentEntries != 0U || usage.runEntries != 0U) {
		return ERROR_INVALID_DATA ;
	}

	return store.write( L"current/collector-campaign-mode-v1.json", expected) ;
}
} // namespace

/** @see local_collector_collection_store.h */
LocalCollectorSegmentLease::LocalCollectorSegmentLease(
	std::shared_ptr<CollectorCollectionSession> session,
	std::shared_ptr<LocalCollectorStateStore>	child,
	std::unique_ptr<LocalCollectorStateStore>	history)
	: session_( std::move( session)), child_( std::move( child)), history_( std::move( history))
{
}
/** @see local_collector_collection_store.h */
LocalCollectorSegmentLease::~LocalCollectorSegmentLease()
{
	history_.reset() ;
	child_.reset() ;
	session_->borrowed = false ;
}
/** @see local_collector_collection_store.h */
LocalCollectorStateStore &LocalCollectorSegmentLease::store() noexcept
{
	return *child_ ;
}
/** @see local_collector_collection_store.h */
LocalCollectorStateStore *LocalCollectorSegmentLease::history() noexcept
{
	return history_.get() ;
}
/** @see local_collector_collection_store.h */
LocalCollectorCollectionStore::LocalCollectorCollectionStore() = default ;
/** @see local_collector_collection_store.h */
LocalCollectorCollectionStore::~LocalCollectorCollectionStore() = default ;
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::initialize( const std::filesystem::path &root,
												std::wstring_view			 key) noexcept
{
	// 借用中の親能力を新rootへ差し替えません。
	if( session_ && (session_->borrowed || session_->switchHeld)) {
		return ERROR_BUSY ;
	}

	try {
		// Pathとcollection identityを同じ登録へ結合します。
		if( !hashKey( key) || root.filename().native() != key) {
			return ERROR_INVALID_NAME ;
		}

		auto next =
			std::make_shared<CollectorCollectionSession>() ;	// 全成功後だけwrapperへ公開します。
		next->parent	 = std::make_shared<LocalCollectorStateStore>() ;
		next->collection = key ;
		DWORD code =
			// 私有layoutの親writerを先に取得します。
			next->parent->initializeCollection( root, parentMarker( key)) ;
		// 保護階層／単一writer不成立ではmarkerへ進みません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		std::vector<std::wstring> children ;	// 親markerなしの既存子を初回扱いにしません。
		code = next->parent->listSegments( children) ;
		// 最大1024のcontainer検査が全成立してから登録します。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		std::string existing ;	// 親marker欠損だけを区別します。
		bool		found{} ;	// 不正本文は後の完全一致照合が拒否します。
		code = next->parent->read( L"current/collector-campaign-mode-v1.json", existing, found) ;
		// 欠損親に子が残る状態を新規作成に読み替えません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		// 子の存在を無視して元collectionを再登録しません。
		if( !found && !children.empty()) {
			return ERROR_INVALID_DATA ;
		}

		code = marker( *next->parent, parentMarker( key), true) ;
		// 全保護とmarker一致後だけ能力を公開します。
		if( code == ERROR_SUCCESS) {
			session_ = std::move( next) ;
		}

		return code ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::close() noexcept
{
	// Leaseが持つ親能力は途中で解放しません。
	if( session_ && (session_->borrowed || session_->switchHeld)) {
		return ERROR_BUSY ;
	}

	session_.reset() ;
	return ERROR_SUCCESS ;
}
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::borrowSegment(
	std::wstring_view key, bool create, std::unique_ptr<LocalCollectorSegmentLease> &lease) noexcept
{
	return borrowSegmentImpl( key, create, false, lease) ;
}
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::borrowHistorySegment(
	std::wstring_view key, bool create, std::unique_ptr<LocalCollectorSegmentLease> &lease) noexcept
{
	return borrowSegmentImpl( key, create, true, lease) ;
}
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::borrowSegmentImpl(
	std::wstring_view key, bool create, const bool withHistory,
	std::unique_ptr<LocalCollectorSegmentLease> &lease) noexcept
{
	// Callerの元leaseを失敗時に破棄しません。
	if( lease || (session_ && (session_->borrowed || session_->switchHeld))) {
		return ERROR_BUSY ;
	}

	// 未初期化と不正keyから子storeを発行しません。
	if( !session_ || !hashKey( key)) {
		return ERROR_INVALID_PARAMETER ;
	}

	try {
		DWORD code = marker( *session_->parent, parentMarker( session_->collection),
							false) ;	// 借用前に親markerを再照合します。
		// 親の登録が変わった状態で子を開きません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		std::vector<std::wstring> children ;	// 全containerを同じ保護境界で検査します。
		code = session_->parent->listSegments( children) ;
		// 不正階層を見落として新しい子を作りません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		const bool exists = std::binary_search( children.begin(), children.end(),
											   // 元のkeyだけを選択します。
											   std::wstring( key)) ;
		// 非作成借用は欠損を非変更で返します。
		if( !exists && !create) {
			return ERROR_FILE_NOT_FOUND ;
		}

		// 上限ちょうどの既存子借用は許し、新しい1025個目は作りません。
		if( !exists && children.size() >= 1024U) {
			return ERROR_TOO_MANY_NAMES ;
		}

		auto child = std::make_shared<
			LocalCollectorStateStore>() ;	// 固定履歴にも強所有される独立子stateです。
		code = child->initializeOwnedSegment( session_->parent, key, create,
											 childMarker( session_->collection, key, withHistory),
											 withHistory) ;
		// 同じ子のACL・entry・補助lockが成立してからmarkerを照合します。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		code = marker( *child, childMarker( session_->collection, key, withHistory), create) ;
		// 子identity不一致はleaseを公開せず停止します。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		std::unique_ptr<LocalCollectorStateStore> history ;	// 旧leaseには別履歴を追加しません。
		// 新schemaの子だけ固定pathを同親所有で開きます。
		if( withHistory) {
			history = std::make_unique<LocalCollectorStateStore>() ;
			code	= history->initializeOwnedHistory( child, create) ;
			// 履歴の保護と排他が成立しない限りleaseを公開しません。
			if( code != ERROR_SUCCESS) {
				return code ;
			}
		}

		std::unique_ptr<LocalCollectorSegmentLease> next( new LocalCollectorSegmentLease(
			session_, std::move( child), std::move( history))) ;	// 私有constructorの一回所有です。
		session_->borrowed = true ;
		lease			   = std::move( next) ;
		return ERROR_SUCCESS ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::sharedParent( LocalCollectorSegmentLease &lease,
												  LocalCollectorStateStore	*&parent,
												  std::uint64_t				 &remaining)
{
	parent = nullptr ;
	// 別親のleaseと未初期化の能力を混在させません。
	if( !session_ || !session_->borrowed || lease.session_ != session_ || !lease.child_) {
		return ERROR_INVALID_PARAMETER ;
	}

	// 診断callbackから同じ保存処理へ再入させません。
	if( session_->sharedBorrowed || session_->switchHeld) {
		return ERROR_BUSY ;
	}

	DWORD code = marker( *session_->parent, parentMarker( session_->collection), false,
						&remaining) ;	// 元親marker。
	// 元I/O／mode errorを優先して保持します。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	std::vector<std::wstring> children ;	// 初回bootstrapは唯一の子へ限定します。
	code = session_->parent->listSegments( children) ;
	// 別子候補を初回に取り込みません。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	const auto key = lease.child_->root().filename().native() ;	// 検査済み子identity。
	// 初回専用入口なので複数区間を受理しません。
	if( children.size() != 1U || children.front() != key) {
		return ERROR_INVALID_DATA ;
	}

	code = marker( *lease.child_, childMarker( session_->collection, key, lease.history_ != nullptr),
				  false, &remaining) ;
	// 同じ子の登録まで成立してから親を借用します。
	if( code == ERROR_SUCCESS) {
		session_->sharedBorrowed = true ;
		parent					 = session_->parent.get() ;
	}

	return code ;
}
/** @see local_collector_collection_store.h */
void LocalCollectorCollectionStore::releaseSharedParent() noexcept
{
	session_->sharedBorrowed = false ;
}
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::reserveSwitch(
	LocalCollectorSegmentLease &lease, const std::wstring_view nextKey,
	std::shared_ptr<const CollectorCollectionSwitchHold> &hold,
	std::array<CollectorStoreUsage, 2U>					 &usage) noexcept
{
	hold.reset() ;
	usage = {} ;
	// 不正能力から親の排他や新しいdirectoryを作りません。
	if( !lease.history_ || !hashKey( nextKey)) {
		return ERROR_INVALID_PARAMETER ;
	}

	try {
		LocalCollectorStateStore *parent{} ;						// 同じ親だけの一時借用です。
		std::uint64_t			  remaining = 16U * 1024U * 1024U ;	// Markerを読む独立raw予算です。
		auto code = sharedParent( lease, parent, remaining) ;		// 唯一containerとmarkerを再照合します。
		// 不正親や再入をhold取得へ補完しません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		const auto release = []( CollectorCollectionSession *session) {
			session->sharedBorrowed = false ;
		} ; // 同期呼出し中だけの非所有借用を全終了経路で返します。
		std::unique_ptr<CollectorCollectionSession, decltype( release)> borrowed(
			// 元sessionはwrapperと旧leaseが強所有します。
			session_.get(), release) ;
		// 存在済みの唯一旧区間を新しい候補として開きません。
		if( nextKey == lease.child_->root().filename().native()) {
			return ERROR_INVALID_DATA ;
		}

		std::array<CollectorStoreUsage, 2U> actual ;	// 全成功後だけ公開する実容量です。
		code = parent->inspectUsage( actual[0]) ;
		// 第一I/O／容量codeを保持します。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		code = lease.child_->inspectUsage( actual[1]) ;
		// 旧子の未知stagingや容量を無視しません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		auto next = std::make_shared<CollectorCollectionSwitchHold>() ;	// 非公開の元能力だけです。
		next->session		 = session_ ;
		next->child			 = lease.child_ ;
		next->history		 = lease.history_ ;
		next->nextKey		 = nextKey ;
		next->armed			 = true ;
		session_->switchHeld = true ;
		usage				 = actual ;
		hold				 = std::move( next) ;
		return ERROR_SUCCESS ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::recoveryParent( LocalCollectorStateStore *&parent) noexcept
{
	parent = nullptr ;
	// 未初期化の親能力を補完しません。
	if( !session_) {
		return ERROR_INVALID_PARAMETER ;
	}

	// 別lease／保存借用／回復への再入は同じ170で拒否します。
	if( session_->borrowed || session_->sharedBorrowed || session_->switchHeld) {
		return ERROR_BUSY ;
	}

	parent = session_->parent.get() ;
	return ERROR_SUCCESS ;
}

/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::openSegmentRead(
	const std::wstring_view oldKey, const std::wstring_view newKey,
	std::shared_ptr<const CollectorCollectionReadHold> &hold,
	std::array<LocalCollectorStateStore *, 4U>		   &stores,
	std::array<std::string, 3U>						   &markers) noexcept
{
	hold.reset() ;
	stores	= {} ;
	markers = {} ;
	// 他leaseと切替予約の排他を読取り能力で迂回しません。
	if( session_ && (session_->borrowed || session_->sharedBorrowed || session_->switchHeld)) {
		return ERROR_BUSY ;
	}

	// 同親能力以外から任意子pathを生成しません。
	if( !session_ || !hashKey( oldKey) || !hashKey( newKey) || oldKey == newKey) {
		return ERROR_INVALID_PARAMETER ;
	}

	try {
		auto next	  = std::make_shared<CollectorCollectionReadHold>() ;	// 成功まで未発行です。
		next->session = session_ ;
		std::vector<std::wstring> names ;											// 固定二子の属性検査だけです。
		auto					  code = session_->parent->listSegments( names) ;	// 第一保護I/Oです。
		// 列挙の元障害を内容拒否へ読み替えません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		std::vector<std::wstring> expected{std::wstring( oldKey),
										   // 同intent由来です。
										   std::wstring( newKey)} ;
		std::sort( expected.begin(), expected.end()) ;
		// 欠損・第三子を作成や削除で補完しません。
		if( names != expected) {
			return ERROR_INVALID_DATA ;
		}

		next->oldChild = std::make_shared<LocalCollectorStateStore>() ;
		code		   = next->oldChild->initializeReadSegment( session_->parent, oldKey) ;
		// 旧子の保護とlockの第一失敗で停止します。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		next->newChild = std::make_shared<LocalCollectorStateStore>() ;
		code		   = next->newChild->initializeReadSegment( session_->parent, newKey) ;
		// 新子を非作成で開けない場合は全未発行所有を返します。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		next->newHistory = std::make_shared<LocalCollectorStateStore>() ;
		code			 = next->newHistory->initializeReadHistory( next->newChild) ;
		// 新historyの欠損から空初回を作りません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		markers				 = {parentMarker( session_->collection),
								childMarker( session_->collection, oldKey, true),
								childMarker( session_->collection, newKey, true)} ;
		stores				 = {session_->parent.get(), next->oldChild.get(), next->newChild.get(),
								next->newHistory.get()} ;
		next->armed			 = true ;
		session_->switchHeld = true ;
		hold				 = std::move( next) ;
		return ERROR_SUCCESS ;
	} catch( const std::bad_alloc &) {
		markers = {} ;
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		markers = {} ;
		return ERROR_INVALID_DATA ;
	}
}

/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::verifySegmentRead(
	const std::shared_ptr<const CollectorCollectionReadHold> &hold)
{
	// 変更不能contextの元所有以外からstore能力を再取得しません。
	if( !hold || !hold->armed || !hold->session || !hold->session->switchHeld || !hold->oldChild ||
	   !hold->newChild || !hold->newHistory) {
		return ERROR_INVALID_PARAMETER ;
	}

	std::vector<std::wstring> names ;								// 同じ親handleの現在二子集合です。
	const auto code = hold->session->parent->listSegments( names) ;	// 第一属性I/Oです。
	// 部分一覧を成功集合へ補完しません。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	std::vector<std::wstring> expected{hold->oldChild->root().filename().native(),
									   // 元同親二子です。
									   hold->newChild->root().filename().native()} ;
	std::sort( expected.begin(), expected.end()) ;
	return names == expected ? ERROR_SUCCESS : ERROR_INVALID_DATA ;
}
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::openRecoverySwitch(
	const std::wstring_view oldKey, const std::wstring_view newKey,
	std::shared_ptr<const CollectorCollectionSwitchHold> &hold, const bool preparation) noexcept
{
	hold.reset() ;
	// 生存leaseや切替所有のある親で別回復を開始しません。
	if( session_ && (session_->borrowed || session_->sharedBorrowed || session_->switchHeld)) {
		return ERROR_BUSY ;
	}

	// 任意path・同一子や不正keyからhandleを発行しません。
	if( !session_ || !hashKey( oldKey) || !hashKey( newKey) || oldKey == newKey) {
		return ERROR_INVALID_PARAMETER ;
	}

	try {
		auto code =
			// 元親登録です。
			marker( *session_->parent, parentMarker( session_->collection), false) ;
		// 第一保護I/Oを維持します。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		std::vector<std::wstring> children ;	// 同じ保護親からの全子です。
		code = session_->parent->listSegments( children) ;
		// 不正階層を内容検査へ渡しません。
		if( code != ERROR_SUCCESS) {
			return code ;
		}

		// 同intentの新子が存在する場合だけ、その非作成handleを要求します。
		const bool newExists = std::binary_search( children.begin(), children.end(), newKey) ;
		// ROOT未保存だけは、未作成新子を読み取りのために作成しません。
		std::vector<std::wstring> expected{std::wstring( oldKey)} ;
		// ROOT保存済みでは二子、新子作成済み準備では同じ二子を必須にします。
		if( !preparation || newExists) {
			expected.emplace_back( newKey) ;
		}

		std::sort( expected.begin(), expected.end()) ;
		// 第三子・欠損を初回回復で補完しません。
		if( children != expected) {
			return ERROR_INVALID_DATA ;
		}

		auto next	  = std::make_shared<CollectorCollectionSwitchHold>() ;	// 全成功まで未発行です。
		next->session = session_ ;
		next->nextKey = newKey ;
		// 旧／新二子と固定historyを非作成で開き、途中失敗は全handleを返します。
		for( const bool isNew : {false, true}) {
			// 未作成新子は専用準備保存の段階まで欠損のまま保持します。
			if( isNew && !newExists) {
				continue ;
			}

			const auto key	 = isNew ? newKey : oldKey ;						// Intent由来の同親keyです。
			auto	   child = std::make_shared<LocalCollectorStateStore>() ;	// 親を強所有します。
			code			 = child->initializeOwnedSegment(
				session_->parent, key, false, childMarker( session_->collection, key, true), true) ;
			// 保護・排他の第一失敗で停止します。
			if( code != ERROR_SUCCESS) {
				return code ;
			}

			code = marker( *child, childMarker( session_->collection, key, true), false) ;
			// 元専用marker以外へfallbackしません。
			if( code != ERROR_SUCCESS) {
				return code ;
			}

			auto history = std::make_shared<LocalCollectorStateStore>() ;	// 固定historyだけです。
			code		 = isNew ? history->initializeRecoveryHistory( child, preparation)
								 : history->initializeOwnedHistory( child, false) ;
			// 欠損historyを新規作成しません。
			if( code != ERROR_SUCCESS) {
				return code ;
			}

			// 同じholdが旧／新handleをそれぞれ強所有します。
			if( isNew) {
				next->nextChild	  = std::move( child) ;
				next->nextHistory = std::move( history) ;
			} else {
				next->child	  = std::move( child) ;
				next->history = std::move( history) ;
			}
		}

		next->newCreationStarted = newExists ;
		next->armed				 = true ;
		session_->switchHeld	 = true ;
		hold					 = std::move( next) ;
		return ERROR_SUCCESS ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::borrowSwitchStorage(
	const std::shared_ptr<const CollectorCollectionSwitchHold> &hold, const bool acquire,
	std::array<LocalCollectorStateStore *, 3U> &stores,
	std::array<LocalCollectorStateStore *, 2U> *next)
{
	stores = {} ;
	// 未作成または拒否の場合は新子handleを公開しません。
	if( next) {
		*next = {} ;
	}

	// 生存中の元能力以外から親handleを取り出しません。
	if( !hold || !hold->armed || !hold->session || !hold->session->switchHeld || !hold->child ||
	   !hold->history) {
		return ERROR_INVALID_PARAMETER ;
	}

	// 同じ保存への再入と、借用なしの再検査を拒否します。
	if( acquire == hold->storageBorrowed) {
		return ERROR_BUSY ;
	}

	std::uint64_t remaining = 16U * 1024U * 1024U ;	// Markerの独立raw上限です。
	const auto	 &session	= *hold->session ;		// 元wrapper解放後もholdが強所有します。
	auto		  code		= marker( *session.parent, parentMarker( session.collection), false,
									 &remaining) ;	// 第一I/O結果です。
	// 親markerの元I/O errorを優先します。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	std::vector<std::wstring> children ;	// 元旧子と開始済みの固定新子だけを照合します。
	code = session.parent->listSegments( children) ;
	// 不正containerを無視して保存しません。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	const auto key = hold->child->root().filename().native() ;	// 元同親の旧子identityです。
	std::vector<std::wstring> expected{key} ;					// 新子は同じholdの開始済みkeyだけです。
	// 元新子が存在する場合だけ固定二containerを検査します。
	if( hold->newCreationStarted &&
	   std::binary_search( children.begin(), children.end(), hold->nextKey)) {
		expected.push_back( hold->nextKey) ;
		std::sort( expected.begin(), expected.end()) ;
	}

	// 第三子・開始前の新子と保持中handleの欠損を無視しません。
	if( children != expected || (hold->nextChild && children.size() != 2U)) {
		return ERROR_INVALID_DATA ;
	}

	code = marker( *hold->child, childMarker( session.collection, key, true), false, &remaining) ;
	// 保持済みの新子markerも毎passの同handleで照合します。
	if( code == ERROR_SUCCESS && hold->nextChild) {
		code = marker( *hold->nextChild, childMarker( session.collection, hold->nextKey, true), false,
					  &remaining) ;
	}

	// 全検査後だけ同じ能力の借用を取得します。
	if( code == ERROR_SUCCESS) {
		hold->storageBorrowed = true ;
		stores				  = {session.parent.get(), hold->child.get(), hold->history.get()} ;
		// 私有新子保存入口だけへ生存中の固定二handleを渡します。
		if( next) {
			*next = {hold->nextChild.get(), hold->nextHistory.get()} ;
		}
	}

	return code ;
}
/** @see local_collector_collection_store.h */
void LocalCollectorCollectionStore::releaseSwitchStorage(
	const std::shared_ptr<const CollectorCollectionSwitchHold> &hold) noexcept
{
	hold->storageBorrowed = false ;
}
/** @see local_collector_collection_store.h */
DWORD LocalCollectorCollectionStore::createSwitchStorage(
	const std::shared_ptr<const CollectorCollectionSwitchHold> &hold,
	const std::wstring_view intentName, const std::string_view intentRaw,
	std::array<LocalCollectorStateStore *, 2U> &next)
{
	next = {} ;
	// 同期保存借用以外から新しい子を作りません。
	if( !hold || !hold->armed || !hold->storageBorrowed || !hashKey( hold->nextKey)) {
		return ERROR_INVALID_PARAMETER ;
	}

	std::string raw ;															// 同じ親に保存済みの元intentです。
	bool		found{} ;														// 未保存intentは新子作成へ進めません。
	auto		code = hold->session->parent->read( intentName, raw, found) ;	// 第一保護I/O結果です。
	// 別byte・欠損を元予約から上書き補完しません。
	if( code != ERROR_SUCCESS || !found || raw != intentRaw) {
		return code != ERROR_SUCCESS ? code : ERROR_INVALID_DATA ;
	}

	// 同じholdが既に所有している二handleだけを再利用します。
	if( hold->nextChild && hold->nextHistory) {
		next = {hold->nextChild.get(), hold->nextHistory.get()} ;
		return ERROR_SUCCESS ;
	}

	std::vector<std::wstring> children ;	// 元新子の存在を保護parentから確認します。
	code = hold->session->parent->listSegments( children) ;
	// 未検査containerから作成許可を作りません。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	// 保護parentの全名から元固定新子の存在だけを判定します。
	const bool exists = std::binary_search( children.begin(), children.end(), hold->nextKey) ;
	// 元holdが開始していない既存子は取り込みません。
	if( exists && !hold->newCreationStarted) {
		return ERROR_INVALID_DATA ;
	}

	auto child	 = std::make_shared<LocalCollectorStateStore>() ;	// I/O前に二所有者を確保します。
	auto history = std::make_shared<LocalCollectorStateStore>() ;	// 私有の空履歴writerです。
	hold->newCreationStarted = true ;
	// 元同親と新子identityに結合した固定marker本文です。
	const auto expected = childMarker( hold->session->collection, hold->nextKey, true) ;
	code = child->initializeOwnedSegment( hold->session->parent, hold->nextKey, !exists, expected,
										 true) ;
	// 既存不完全directory／lockは修復せず第一errorを保持します。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	std::vector<std::wstring> current ;	// Handle発行前は空または固定markerだけに限定します。
	std::vector<std::wstring> runs ;	// 初回扱いで未登録準備を無視しません。
	code = child->listCurrentNames( current) ;
	// 全名検査の第一失敗を保持します。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	code = child->listRunNames( runs) ;
	// 非空準備やstagingを初回marker登録へ取り込みません。
	if( code != ERROR_SUCCESS || !runs.empty() ||
	   (!current.empty() &&
		current != std::vector<std::wstring>{L"collector-campaign-mode-v1.json"})) {
		return code != ERROR_SUCCESS ? code : ERROR_INVALID_DATA ;
	}

	CollectorStoreUsage usage ;	// Staging込み実量です。
	code = child->inspectUsage( usage) ;
	// Directoryの名だけで残留stagingを見逃しません。
	if( code != ERROR_SUCCESS || usage.runEntries != 0U || usage.currentEntries != current.size() ||
	   usage.bytes != (current.empty() ? 0U : expected.size())) {
		return code != ERROR_SUCCESS ? code : ERROR_INVALID_DATA ;
	}

	code = marker( *child, expected, true) ;
	// 固定marker保存が成立してからhistoryを作成します。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	// 存在確認用の固定history絶対名であり、保護handleの許可を代替しません。
	const auto historyPath =
		L"\\\\?\\" + std::filesystem::path( child->root() / L"history").make_preferred().native() ;
	const auto attributes =
		// 存在照会だけで保護許可に使いません。
		GetFileAttributesW( historyPath.c_str()) ;
	// 存在照会の第一errorだけを直後に取得します。
	const auto attributesError =
		attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS ;
	// 不明な存在照会を新規作成へfallbackしません。
	if( attributes == INVALID_FILE_ATTRIBUTES && attributesError != ERROR_FILE_NOT_FOUND &&
	   attributesError != ERROR_PATH_NOT_FOUND) {
		return attributesError ;
	}

	code = history->initializeOwnedHistory( child, attributes == INVALID_FILE_ATTRIBUTES) ;
	// 既存historyの欠損階層も自動修復しません。
	if( code != ERROR_SUCCESS) {
		return code ;
	}

	code = history->inspectUsage( usage) ;
	// 新historyは空だけで、初期ROOTや元予算を推測生成しません。
	if( code != ERROR_SUCCESS || usage.bytes != 0U || usage.currentEntries != 0U ||
	   usage.runEntries != 0U) {
		return code != ERROR_SUCCESS ? code : ERROR_INVALID_DATA ;
	}

	hold->nextChild	  = std::move( child) ;
	hold->nextHistory = std::move( history) ;
	next			  = {hold->nextChild.get(), hold->nextHistory.get()} ;
	return ERROR_SUCCESS ;
}
} // namespace drivercrate
