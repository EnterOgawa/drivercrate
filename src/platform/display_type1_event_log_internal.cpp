//------------------------------------------------------------------------------
/**
 * @file display_type1_event_log_internal.cpp
 * @brief DeviceSetupManagerの固定チャネルからType 1の実行記録を有限に取得する
 * @version 01.01.00
 * @date 2026/11/27
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/27  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/27  元境界と現在の子から実行結果を一度だけ照合
 * </pre>
 *
 * @note Windowsイベントログを読取り専用で同じworkerから開く。部分取得した結果は返さない
 */
//------------------------------------------------------------------------------
#include "platform/display_type1_event_log_internal.h"

#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <Windows.h>
#include <winevt.h>

namespace drivercrate {
namespace {
constexpr wchar_t CHANNEL[] =
	L"Microsoft-Windows-DeviceSetupManager/Admin" ;							// 固定のローカルAdminチャネル
constexpr wchar_t PROVIDER[] = L"Microsoft-Windows-DeviceSetupManager" ;	// 同じWindowsの記録元
constexpr GUID	  PROVIDER_GUID{
	   0xfcbb06bb,
	   0x6a2a,
	   0x46e3,
	   {0xab, 0xaa, 0x24, 0x6c, 0xb4, 0xe5, 0x08, 0xb2}} ;			// 同名別providerを区別
constexpr DWORD			MAX_RENDER_BYTES   = 64U * 1024U ;			// 一記録で受け取る最大バイト数
constexpr DWORD			NEXT_TIMEOUT_MS	   = 100U ;					// EvtNextの一回の待機上限
constexpr std::size_t	BOOKMARK_CHARS	   = 1024U ;				// 終端を含むネイティブブックマークの最大文字数
constexpr std::uint64_t MAX_WINDOW_RECORDS = 4096U ;				// 下限を除く一回の全列挙上限
constexpr std::size_t	MAX_TARGET_RECORDS = 512U ;					// worker内に保持する固定イベントの上限
constexpr auto			READ_BUDGET = std::chrono::seconds( 5) ;	// 一回の読取りで次の記録を待てる時間

using EventHandle =
	std::unique_ptr<void, decltype( &EvtClose)> ;	// 所有しているローカルイベントログハンドル

/** @brief EvtRenderが返す型付きプロパティの格納領域 */
struct EventValues {
	/// 固定サイズでEVT_VARIANTに整列した、値と文字列を含む領域
	std::array<EVT_VARIANT, MAX_RENDER_BYTES / sizeof( EVT_VARIANT)> buffer ;
	/// 最後の成功したレンダリングで使用したバイト数
	DWORD															bytes{} ;
	/// 先頭にある型付きプロパティの数
	DWORD															count{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief イベントログAPIの元Win32診断を失敗HRESULTとして扱う
 * @param[in] code APIが失敗直後に返した元診断
 * @return 元診断を保持するHRESULT。診断がない場合は不正データ
 */
//------------------------------------------------------------------------------
NativeError eventError( const DWORD code) noexcept
{
	return static_cast<NativeError>(
		HRESULT_FROM_WIN32( code == ERROR_SUCCESS ? ERROR_INVALID_DATA : code)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief チャネルが記録可能であることを確認し、世代比較用の作成時刻を読む
 * @param[out] created 成功時にWindowsログの作成FILETIME
 * @return 有効かつ空きのあるチャネルを確認した場合0、読取り・型・状態の失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readLogCreation( std::uint64_t &created) noexcept
{
	const EventHandle config( EvtOpenChannelConfig( nullptr, CHANNEL, 0U),
							 EvtClose) ;	// 固定チャネルの構成参照
	// 無効または読めないチャネルから完全な記録は得られない
	if( !config) {
		return eventError( GetLastError()) ;
	}

	EVT_VARIANT value{} ;	// 読み取った固定型の設定またはメタデータ
	DWORD		used{} ;	// APIが使用したバイト数
	// チャネル設定から現在の有効状態を取得する
	if( !EvtGetChannelConfigProperty( config.get(), EvtChannelConfigEnabled, 0U, sizeof( value),
									&value, &used)) {
		return eventError( GetLastError()) ;
	}

	// 型が異なる値から記録可能状態を推測しない
	if( used != sizeof( value) || value.Type != EvtVarTypeBoolean || !value.BooleanVal) {
		return eventError( ERROR_INVALID_DATA) ;
	}

	const EventHandle log( EvtOpenLog( nullptr, CHANNEL, EvtOpenChannelPath),
						  EvtClose) ;	// 同じローカルチャネルの情報
	// チャネルの所有情報を読み取れなければ境界を確定しない
	if( !log) {
		return eventError( GetLastError()) ;
	}

	// 新規記録を書けない状態を正常な空区間から区別する
	if( !EvtGetLogInfo( log.get(), EvtLogFull, sizeof( value), &value, &used)) {
		return eventError( GetLastError()) ;
	}

	// 保持上限に達したチャネルには後続の完全性を認めない
	if( used != sizeof( value) || value.Type != EvtVarTypeBoolean || value.BooleanVal) {
		return eventError( ERROR_INVALID_DATA) ;
	}

	// チャネルの作成時刻を別の読取りと照合できる形で取得する
	if( !EvtGetLogInfo( log.get(), EvtLogCreationTime, sizeof( value), &value, &used)) {
		return eventError( GetLastError()) ;
	}

	// 不正または欠損の時刻から世代を補わない
	if( used != sizeof( value) || value.Type != EvtVarTypeFileTime || value.FileTimeVal == 0U) {
		return eventError( ERROR_INVALID_DATA) ;
	}

	created = value.FileTimeVal ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 有界待機で順序カーソルから次の実記録を一件読む
 * @param[in] query 実行中の同じスレッドで所有するチャネルクエリ
 * @param[out] event 成功時に記録ハンドルを所有。失敗時は閉じる
 * @return 一件の取得成功で0、終端・タイムアウトを含む取得失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readNextEvent( const EVT_HANDLE query, EventHandle &event) noexcept
{
	EVT_HANDLE raw{} ;		// EvtNextから取得し同じworkerで閉じる一件
	DWORD	   received{} ;	// Windowsが格納したハンドル数
	const auto error = EvtNext( query, 1U, &raw, NEXT_TIMEOUT_MS, 0U, &received)
						   ? 0
						   : eventError( GetLastError()) ;	// 失敗直後の元診断
	event.reset( raw) ;
	// 欠落や不正な数を正常な後続記録として扱わない
	if( error != 0 || received != 1U || !event) {
		event.reset() ;
		return error != 0 ? error : eventError( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実記録を格納領域の上限内でEVT_VARIANTへ変換する
 * @param[in] context 固定のWindowsシステム欄またはユーザー欄を指定する借用コンテキスト
 * @param[in] event 同じスレッドで保持する元イベントを同期中だけ借用
 * @param[out] values 成功時のみ使用可能な値配列とバイト範囲
 * @return 変換成功時0、元診断またはバッファ形状の拒否はHRESULT
 */
//------------------------------------------------------------------------------
NativeError renderEventValues( const EVT_HANDLE context, const EVT_HANDLE event,
							  EventValues &values) noexcept
{
	// 上限を超える出力のための再割当ては行わない
	if( !EvtRender( context, event, EvtRenderEventValues, MAX_RENDER_BYTES, values.buffer.data(),
				  &values.bytes, &values.count)) {
		return eventError( GetLastError()) ;
	}

	// 実際の格納範囲内に収まる値配列だけを参照する
	if( values.bytes > MAX_RENDER_BYTES || values.count > values.bytes / sizeof( EVT_VARIANT)) {
		return eventError( ERROR_INVALID_DATA) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief WinEvtが返した可変長プロパティへのポインターが持つ実際の残バイト数を求める
 * @param[in] values Windowsが最後にレンダリングした型付きバッファ
 * @param[in] raw 同じバッファを指すはずのWindowsのポインター
 * @return 値配列の後ろからバッファ終端までの有効なバイト数。域外は0
 */
//------------------------------------------------------------------------------
std::size_t eventBytesAvailable( const EventValues &values, const void *raw) noexcept
{
	// WinEvtのC APIが型付き値に格納するポインターの所属を整数アドレスで確認する
	const auto begin = reinterpret_cast<std::uintptr_t>( values.buffer.data()) ;	// 格納領域の開始
	const auto item	 = reinterpret_cast<std::uintptr_t>( raw) ;						// WinEvtが返した可変長値の開始
	// 値配列そのものや返却領域の外を可変長プロパティとして参照しない
	if( item < begin || item - begin < values.count * sizeof( EVT_VARIANT) ||
	   item - begin >= values.bytes) {
		return 0U ;
	}

	return values.bytes - (item - begin) ;
}

//------------------------------------------------------------------------------
/**
 * @brief WinEvtが返した文字列値から終端までを上限内で読む
 * @param[in] values 元イベントの型付きバッファ
 * @param[in] field 項目位置を検査済みのWindows値
 * @return 同じバッファを借用する文字列。型・範囲・終端の不正または空値は空
 */
//------------------------------------------------------------------------------
std::wstring_view eventText( const EventValues &values, const EVT_VARIANT &field) noexcept
{
	// 文字列型以外のunionメンバーには触れない
	if( field.Type != EvtVarTypeString) {
		return {} ;
	}

	const auto text = field.StringVal ;											// 同じEventValues内を参照するNUL終端の文字列
	const auto size = eventBytesAvailable( values, text) / sizeof( wchar_t) ;	// 確認済みの最大文字数
	// WinEvt APIからのワイド文字列が型の配置条件を満たすことを確認する
	if( size == 0U || reinterpret_cast<std::uintptr_t>( text) % alignof( wchar_t) != 0U) {
		return {} ;
	}

	const std::wstring_view bounded( text, size) ;			// 終端を探索できる読取り専用の範囲
	const auto				end = bounded.find( L'\0') ;	// 同じ領域の最初の終端
	return end == std::wstring_view::npos ? std::wstring_view{} : bounded.substr( 0U, end) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ローカル固定チャネルのイベントから境界比較に使うシステム項目を読む
 * @param[in] context 同じworkerで開いたシステム項目のコンテキスト
 * @param[in] event 同じworkerで所有する元イベント
 * @param[in,out] values レンダリングに使う所有バッファ
 * @param[out] identity 成功時に一致を確認した元イベントのシステム項目
 * @return 固定チャネル・provider・型の確認成功で0、それ以外はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readEventIdentity( const EVT_HANDLE context, const EVT_HANDLE event, EventValues &values,
							  DisplayType1EventBoundary &identity) noexcept
{
	const auto error = renderEventValues( context, event, values) ;	// 元のAPI診断
	// 必須のシステム項目が揃った場合だけ各位置を照合する
	if( error != 0 || values.count != EvtSystemPropertyIdEND) {
		return error != 0 ? error : eventError( ERROR_INVALID_DATA) ;
	}

	const auto &v = values.buffer ;	// 固定System項目の並び
	// 異なる発行元または項目型の記録を対象チャネルの証拠へ混ぜない
	if( eventText( values, v[EvtSystemProviderName]) != PROVIDER ||
	   eventText( values, v[EvtSystemChannel]) != CHANNEL ||
	   v[EvtSystemProviderGuid].Type != EvtVarTypeGuid ||
	   eventBytesAvailable( values, v[EvtSystemProviderGuid].GuidVal) < sizeof( GUID) ||
	   v[EvtSystemEventID].Type != EvtVarTypeUInt16 || v[EvtSystemVersion].Type != EvtVarTypeByte ||
	   v[EvtSystemTimeCreated].Type != EvtVarTypeFileTime ||
	   v[EvtSystemEventRecordId].Type != EvtVarTypeUInt64 ||
	   v[EvtSystemTimeCreated].FileTimeVal == 0U || v[EvtSystemEventRecordId].UInt64Val == 0U) {
		return eventError( ERROR_INVALID_DATA) ;
	}

	GUID guid{} ;	// WinEvtの可変長領域から取得した既知型の発行元識別
	std::memcpy( &guid, v[EvtSystemProviderGuid].GuidVal, sizeof( guid)) ;
	const auto &process = v[EvtSystemProcessID] ;	// 欠損を区別するWindows発行プロセス
	const auto &thread	= v[EvtSystemThreadID] ;	// 欠損を区別するWindows発行スレッド
	// 欠損可能な実行コンテキストも別型の値を解釈しない
	if( !IsEqualGUID( guid, PROVIDER_GUID) ||
	   (process.Type != EvtVarTypeUInt32 && process.Type != EvtVarTypeNull) ||
	   (thread.Type != EvtVarTypeUInt32 && thread.Type != EvtVarTypeNull)) {
		return eventError( ERROR_INVALID_DATA) ;
	}

	identity.record	 = v[EvtSystemEventRecordId].UInt64Val ;
	identity.created = v[EvtSystemTimeCreated].FileTimeVal ;
	identity.eventId = v[EvtSystemEventID].UInt16Val ;
	identity.version = v[EvtSystemVersion].ByteVal ;
	identity.process = process.Type == EvtVarTypeUInt32 ? process.UInt32Val : 0U ;
	identity.thread	 = thread.Type == EvtVarTypeUInt32 ? thread.UInt32Val : 0U ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じチャネルの全記録から最新の実在する記録を採取する
 * @param[in] system 同じworkerで所有するシステム項目のレンダリングコンテキスト
 * @param[in,out] values 一件分の再利用可能なレンダリング領域
 * @param[out] reverse 末尾記録の有効期間を保持する逆順クエリを所有する
 * @param[out] tail 成功時に末尾記録の閲覧用ハンドルを所有する
 * @param[out] identity 成功時の末尾記録の項目とログ作成時刻
 * @return 実在する末尾を採取した場合0、空・停止・API失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError readEventTail( const EVT_HANDLE system, EventValues &values, EventHandle &reverse,
						  EventHandle &tail, DisplayType1EventBoundary &identity) noexcept
{
	const auto status = readLogCreation( identity.logCreated) ;	// 有効な同チャネルの作成時刻
	// 状態を確認できないチャネルは境界に使わない
	if( status != 0) {
		return status ;
	}

	reverse.reset( EvtQuery( nullptr, CHANNEL, L"*", EvtQueryChannelPath | EvtQueryReverseDirection)) ;
	// クエリを開けない場合は空の成功を合成しない
	if( !reverse) {
		return eventError( GetLastError()) ;
	}

	const auto error = readNextEvent( reverse.get(), tail) ;	// 末尾一件の取得診断
	return error != 0 ? error : readEventIdentity( system, tail.get(), values, identity) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じチャネルの実記録を下限または上限として再確認する
 * @param[in] expected 別のクエリで保存した境界
 * @param[in] observed 現在のクエリで取得した記録
 * @return システム項目による同じ記録を確認した場合true
 */
//------------------------------------------------------------------------------
bool sameEvent( const DisplayType1EventBoundary &expected,
			   const DisplayType1EventBoundary &observed) noexcept
{
	return expected.record == observed.record && expected.created == observed.created &&
		   expected.process == observed.process && expected.thread == observed.thread &&
		   expected.eventId == observed.eventId && expected.version == observed.version ;
}

//------------------------------------------------------------------------------
/**
 * @brief ソフトウェア記録に含まれる32bitの元Windows診断の型を判定する
 * @param[in] field 型と配置を受け取った元イベントの一項目
 * @return 元値を保持できる固定のunsignedまたは32bit十六進型ならtrue
 */
//------------------------------------------------------------------------------
bool isRawError( const EVT_VARIANT &field) noexcept
{
	return field.Type == EvtVarTypeUInt32 || field.Type == EvtVarTypeHexInt32 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定のID・版・型に従いDeviceSetupManagerのユーザー項目を検査して移す
 * @param[in] identity 発行元とチャネルを確認した同じイベントのシステム項目
 * @param[in] values 同じイベントの位置順のユーザー項目。割当て中だけ借用する
 * @param[out] result 成功時に必要なソフトウェア名、子、コマンド、診断を所有する
 * @return 既知の版と全必須項目を確認した場合0、不明の版・型はHRESULT
 * @throws std::bad_alloc 文字列の所有バッファの確保に失敗した場合
 */
//------------------------------------------------------------------------------
NativeError decodeInstallEvent( const DisplayType1EventBoundary &identity, const EventValues &values,
							   DisplayType1InstallEvent &result)
{
	const auto &fields	= values.buffer ;					// providerマニフェストの順序で得たユーザー項目
	const auto	invalid = eventError( ERROR_INVALID_DATA) ;	// 欠損・未知版・別型の場合の診断
	const auto	count	= values.count ;					// 実際に格納された項目数
	const auto	version = identity.version ;				// 固定イベントのスキーマ版
	// 固定のうち最小のイベントでもソフトウェア名と第二項目がある
	if( count < 2U || version > 1U) {
		return invalid ;
	}

	const auto software = eventText( values, fields[0]) ;	// すべての固定イベントのソフトウェア名
	// 別型や空のソフトウェア名から同じ実行を推測しない
	if( software.empty()) {
		return invalid ;
	}

	result.record  = identity.record ;
	result.process = identity.process ;
	result.thread  = identity.thread ;

	// プロバイダーの固定テンプレートごとに、完全な項目数と元の型を照合する
	switch( identity.eventId) {
		// 160は対象デバイス用の導入完了と所要ミリ秒を表す
		case 160U:
			// 固定版の完了記録からデバイス欄や所要時間の型を補わない
			if( version != 0U || count != 3U || fields[2].Type != EvtVarTypeUInt64) {
				return invalid ;
			}

			result.kind = DisplayType1EventKind::COMPLETED ;
			break ;

		// 161は新たな構成が行われなかったことを表す
		case 161U:
			// 元マニフェストの新旧バージョンの各4要素を検査する
			if( version != 0U || count != 9U) {
				return invalid ;
			}

			// すべての新旧バージョン要素を順に確認し、別型で停止する
			for( std::size_t index = 1U; index < count; ++index) {
				// 版の数値を別型から変換して固定スキーマを補わない
				if( fields[index].Type != EvtVarTypeUInt32) {
					return invalid ;
				}
			}

			result.kind = DisplayType1EventKind::NOT_CONFIGURED ;
			break ;

		// 162は元の失敗理由を保持する
		case 162U:
		// 163は元の失敗理由に加えてプロセス終了値を持つ
		case 163U:
		// 164は一時エラーによるWindows側の再試行を表す
		case 164U: {
			const auto code	   = version == 0U ? 1U : 2U ;	// 版1の追加デバイス欄に続く元診断の位置
			const bool hasExit = identity.eventId == 163U ;	// 同じ記録が別に保持するプロセス終了値
			// 版別の元診断と、163で必須のプロセス終了値の型を検査する
			if( count != code + 1U + (hasExit ? 1U : 0U) || !isRawError( fields[code]) ||
			   (hasExit && !isRawError( fields[code + 1U]))) {
				return invalid ;
			}

			result.kind	 = identity.eventId == 164U ? DisplayType1EventKind::RETRY_PENDING
													: DisplayType1EventKind::FAILED ;
			result.error = std::bit_cast<NativeError>( fields[code].UInt32Val) ;
			break ;
		}
		// 165はWindowsが起動しようとした元のコマンドを表す
		case 165U:
			// 既知の起動記録は固定の版と二項目を要求する
			if( version != 0U || count != 2U) {
				return invalid ;
			}

			result.kind = DisplayType1EventKind::STARTED ;
			break ;

		// 呼出し元の範囲から外れた型は受付けない
		default:
			return invalid ;
	}

	// 子を持つ版だけ元の完全デバイスIDを連結する
	if( identity.eventId == 160U || version == 1U) {
		const auto child = eventText( values, fields[1]) ;	// 版がデバイス欄を保証する元の値
		// 空や別型のデバイス欄から完了や失敗を結び付けない
		if( child.empty()) {
			return invalid ;
		}

		result.childInstance.assign( child) ;
	}

	// 起動記録の元コマンドはworker内の相関だけに使用する
	if( result.kind == DisplayType1EventKind::STARTED) {
		const auto command = eventText( values, fields[1]) ;	// Windowsが記録した実行文字列
		// 実コマンドを読み取れない起動を候補に含めない
		if( command.empty()) {
			return invalid ;
		}

		result.command.assign( command) ;
	}

	result.software.assign( software) ;
	return 0 ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同じWindowsチャネルの変更前の実記録をブックマークとして固定する
 * @param[out] boundary 成功時に実記録の照合情報とWindowsのブックマークを所有する
 * @return 実在する末尾の固定成功時0、固定を確認できない場合はHRESULT
 * @note 読取りとブックマーク生成を同じスレッドで行い、失敗時の出力は空
 */
//------------------------------------------------------------------------------
NativeError captureDisplayType1EventBoundary( DisplayType1EventBoundary &boundary) noexcept
{
	boundary = {} ;
	try {
		const EventHandle system( EvtCreateRenderContext( 0U, nullptr, EvtRenderContextSystem),
								 EvtClose) ;	// System欄への固定コンテキスト
		// システム項目を読めなければ境界を確定しない
		if( !system) {
			return eventError( GetLastError()) ;
		}

		const auto values =
			std::make_unique<EventValues>() ;					// 大きいレンダリング領域はheapに一つだけ確保
		EventHandle				  reverse( nullptr, EvtClose) ;	// 末尾の記録を閉じるまで保つ親クエリ
		EventHandle				  tail( nullptr, EvtClose) ;	// 最後の実記録を同じworkerで所有
		DisplayType1EventBoundary observed ;					// 成功した場合だけ出力へ移す候補境界
		const auto				  status =
			// 実在する観測の診断
			readEventTail( system.get(), *values, reverse, tail, observed) ;
		// 空または読めない履歴を変更前の根拠として採用しない
		if( status != 0) {
			return status ;
		}

		const EventHandle bookmark( EvtCreateBookmark( nullptr),
								   EvtClose) ;	// OSが実記録を指定できる位置
		// 未固定の位置を有効な境界にしない
		if( !bookmark || !EvtUpdateBookmark( bookmark.get(), tail.get())) {
			return eventError( GetLastError()) ;
		}

		std::array<wchar_t, BOOKMARK_CHARS> text ;		// Windows生成XMLの固定バッファ。終端を含む
		DWORD								used{} ;	// APIが書き込んだバイト数
		DWORD								fields{} ;	// OSが返す件数。単一bookmarkでも0又は1
		// 同じ実記録で生成された有限のブックマークだけを後で開く
		if( !EvtRender( nullptr, bookmark.get(), EvtRenderBookmark, static_cast<DWORD>( sizeof( text)),
					  text.data(), &used, &fields)) {
			return eventError( GetLastError()) ;
		}

		// 実バイト数と文字列の終端を検査し、途中で切れた位置を使わない
		if( fields > 1U || used > sizeof( text) || used < 2U * sizeof( wchar_t) ||
		   used % sizeof( wchar_t) != 0U || text[used / sizeof( wchar_t) - 1U] != L'\0') {
			return eventError( ERROR_INVALID_DATA) ;
		}

		observed.bookmarkXml.assign( text.data(), used / sizeof( wchar_t) - 1U) ;
		// 両側のチャネル状態が一致した場合だけ境界を有効にする
		std::uint64_t logCreated{} ;							// 末尾の採取後に独立して確認するログ作成時刻
		const auto	  verify = readLogCreation( logCreated) ;	// 読取り中の入替えや無効化の診断
		// 途中でチャネルが変わった際に候補境界を返さない
		if( verify != 0 || logCreated != observed.logCreated) {
			return verify != 0 ? verify : eventError( ERROR_EVT_QUERY_RESULT_STALE) ;
		}

		boundary = std::move( observed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return eventError( ERROR_OUTOFMEMORY) ;
	} catch( ...) {
		return eventError( ERROR_GEN_FAILURE) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じチャネルの固定済み前後境界内にあるType 1の全記録を含む読取りを行う
 * @param[in] before 変更前に採取した境界を同期中だけ借用する
 * @param[out] events 前後境界と順序が成立した場合だけ昇順の記録を所有する。失敗時は空
 * @return 完全な読取り成功時0、範囲切れ・欠損・異なる世代や型・元APIの失敗はHRESULT
 * @note Windowsの遅延実行は待ち続けず、読取り開始時に固定した末尾まで検査する
 */
//------------------------------------------------------------------------------
NativeError readDisplayType1InstallEvents( const DisplayType1EventBoundary		&before,
										  std::vector<DisplayType1InstallEvent> &events) noexcept
{
	events.clear() ;
	// 実記録から固定した下限以外を読取り開始位置へ使わない
	if( before.record == 0U || before.created == 0U || before.logCreated == 0U ||
	   before.bookmarkXml.empty() || before.bookmarkXml.size() >= BOOKMARK_CHARS ||
	   before.bookmarkXml.find( L'\0') != std::wstring::npos) {
		return eventError( ERROR_INVALID_PARAMETER) ;
	}

	try {
		const auto deadline =
			// 壁時計の変更に依存しない予算
			std::chrono::steady_clock::now() + READ_BUDGET ;
		const EventHandle system( EvtCreateRenderContext( 0U, nullptr, EvtRenderContextSystem),
								 EvtClose) ;	// 項目の型が固定されたSystemコンテキスト
		// 固定した発行元を検証できない場合は読取りを開始しない
		if( !system) {
			return eventError( GetLastError()) ;
		}

		const EventHandle user( EvtCreateRenderContext( 0U, nullptr, EvtRenderContextUser),
							   EvtClose) ;	// 固定マニフェスト順のユーザー項目
		// 型付きユーザー項目の読取りを準備できない場合は停止する
		if( !user) {
			return eventError( GetLastError()) ;
		}

		const auto values =
			std::make_unique<EventValues>() ;					// 一件ずつ再利用する所有レンダリング領域
		EventHandle				  reverse( nullptr, EvtClose) ;	// 末尾の記録を閉じるまで保つ親クエリ
		EventHandle				  tail( nullptr, EvtClose) ;	// 後着を除外する現在の末尾記録の所有
		DisplayType1EventBoundary upper ;						// 独立した逆方向クエリで取得した固定の上限
		const auto				  status =
			// 現在末尾の観測結果
			readEventTail( system.get(), *values, reverse, tail, upper) ;
		// 上限を確認できない場合、正常に記録がなかったと扱わない
		if( status != 0) {
			return status ;
		}

		// 元チャネルから切り替わった末尾を同じ範囲とみなさない
		if( upper.logCreated != before.logCreated || upper.record < before.record) {
			return eventError( ERROR_EVT_QUERY_RESULT_STALE) ;
		}

		// 上限に達しない有限範囲から結果を合成しない
		if( upper.record - before.record > MAX_WINDOW_RECORDS) {
			return eventError( ERROR_BUFFER_OVERFLOW) ;
		}

		const EventHandle lower( EvtCreateBookmark( before.bookmarkXml.c_str()),
								EvtClose) ;	// 元記録からOSが生成した下限
		// 破損または読み戻せないブックマークを現在の位置に代替しない
		if( !lower) {
			return eventError( GetLastError()) ;
		}

		const EventHandle query(
			EvtQuery( nullptr, CHANNEL, L"*", EvtQueryChannelPath | EvtQueryForwardDirection),
			EvtClose) ;	// 下限を含む全記録の順方向クエリ
		// 部分一致や消失時の近似位置を許可せず、下限そのものを読み戻す
		if( !query ||
		   !EvtSeek( query.get(), 0, lower.get(), 0U, EvtSeekRelativeToBookmark | EvtSeekStrict)) {
			return eventError( GetLastError()) ;
		}

		EventHandle				  event( nullptr, EvtClose) ;	// 順方向で読み取る一件の元記録
		DisplayType1EventBoundary current ;						// 元記録のシステム項目。範囲内で一件ずつ更新
		auto error = readNextEvent( query.get(), event) ;		// 読取りまたは型検査の最初の元診断
		// 下限のシステム項目を取得できたときだけ記録の同一性を比べる
		if( error == 0) {
			error = readEventIdentity( system.get(), event.get(), *values, current) ;
		}

		// 別の記録へ移った境界や読めない境界から後続を認めない
		if( error != 0 || !sameEvent( before, current)) {
			return error != 0 ? error : eventError( ERROR_EVT_QUERY_RESULT_STALE) ;
		}

		std::vector<DisplayType1InstallEvent> observed ;	// 上限の照合に成功した場合だけ返す記録群
		// 下限より後を全件列挙し、独立に採取した末尾の照合で停止する
		while( current.record < upper.record) {
			// 記録が増え続ける場合や読取りが遅い場合でも一回の同期処理を終える
			if( std::chrono::steady_clock::now() >= deadline) {
				return eventError( ERROR_TIMEOUT) ;
			}

			const auto next = current.record + 1U ;	// 固定チャネル内で次に期待する位置
			error			= readNextEvent( query.get(), event) ;
			// 区間内の記録を取得できた場合にのみ元の連番を検証する
			if( error == 0) {
				error = readEventIdentity( system.get(), event.get(), *values, current) ;
			}

			// 終端・ロールオーバー・番号飛びを完全な観測の根拠にしない
			if( error != 0 || current.record != next) {
				return error != 0 ? error : eventError( ERROR_EVT_QUERY_RESULT_STALE) ;
			}

			// その他の記録は区間の連続性だけに使い、本文を読み取らない
			if( current.eventId < 160U || current.eventId > 165U) {
				continue ;
			}

			// 対象イベントの上限に達した場合は部分結果を返さない
			if( observed.size() >= MAX_TARGET_RECORDS) {
				return eventError( ERROR_BUFFER_OVERFLOW) ;
			}

			error = renderEventValues( user.get(), event.get(), *values) ;
			// 正式な型のユーザー項目を一件のworker内記録へ移す
			if( error == 0) {
				error = decodeInstallEvent( current, *values, observed.emplace_back()) ;
			}

			// 対象イベントの欠損やスキーマ不一致を成功に読み替えない
			if( error != 0) {
				return error ;
			}
		}

		std::uint64_t logCreated{} ;						// 取得終了時の同じチャネルの作成時刻
		const auto verify = readLogCreation( logCreated) ;	// 検査中に変更されたチャネルを拒否する診断
		// 上限も照合し、途中でチャネルが変わった場合はすべての記録を破棄する
		if( verify != 0 || logCreated != upper.logCreated || !sameEvent( upper, current)) {
			return verify != 0 ? verify : eventError( ERROR_EVT_QUERY_RESULT_STALE) ;
		}

		events = std::move( observed) ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return eventError( ERROR_OUTOFMEMORY) ;
	} catch( ...) {
		return eventError( ERROR_GEN_FAILURE) ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 同じ導入の元境界と確認済みの子から実行・反映を一度だけ観測する
 * @param[in] before 変更前に採取した同じ操作の元境界
 * @param[in] observation 確認した元宣言、登録済み実行物と子の事後状態
 * @param[in] readEvents 元境界以降を読む同期関数。通常は固定Windowsチャネルを使う
 * @return 照合した事後状態。取得不能時は未確認と元診断
 * @note 境界と取得の完全性は読取りの結果から定め、実行や再試行は行わない
 */
//------------------------------------------------------------------------------
DisplayType1InstallResult observeDisplayType1InstallEvents(
	const DisplayType1EventBoundary &before, DisplayType1InstallObservation observation,
	const DisplayType1EventRead readEvents) noexcept
{
	// 元操作の実記録がなければ事後の最新位置を境界として補わない
	if( before.record == 0U || before.bookmarkXml.empty() || !readEvents) {
		return {DisplayType1InstallState::UNCONFIRMED, E_INVALIDARG} ;
	}

	std::vector<DisplayType1InstallEvent> events ;		// 同じチャネルの同じ操作に限る同期読取り
	const auto error = readEvents( before, events) ;	// 元境界と事後上限を検査する結果
	// 取得エラーと正常な空区間を分け、部分取得を照合しない
	if( error != 0U) {
		return {DisplayType1InstallState::UNCONFIRMED, error} ;
	}

	observation.afterRecord	 = before.record ;
	observation.streamIntact = true ;
	return classifyDisplayType1Install( observation, events) ;
}
} // namespace drivercrate
