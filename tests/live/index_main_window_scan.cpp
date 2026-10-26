//------------------------------------------------------------------------------
/**
 * @file index_main_window_scan.cpp
 * @brief 明示通常MainWindowの実索引照合と対象限定の規約・検査用取得を観測します。
 * @version 01.05.01
 * @date 2026/10/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/14  実既定workerのscan-only有限観測を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/14  既存の索引拒否診断と有限処理件数を匿名観測へ追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/14  検証済み部分関係の通常参照・Tree focus・規約本文件数を分離。
 * Ver.01.03.00 Shunji Ogawa  2026/10/15  通常準備commandから実規約controlと未同意取消を観測。
 * Ver.01.04.00 Shunji Ogawa  2026/10/15  承認済み一対象の通常dialogと実検査用取得を接続。
 * Ver.01.04.01 Shunji Ogawa  2026/10/15  実取得完了eventの非機密監査件数を通常handler前に観測。
 * Ver.01.04.02 Shunji Ogawa  2026/10/15  正規更新世代5の固定観測と選択INF ordinalの通常表示を確認。
 * Ver.01.05.00 Shunji Ogawa  2026/10/15  入れ子dialogの実worker配送を一回観測し非通信拒否で確認。
 * Ver.01.05.01 Shunji Ogawa  2026/10/24  通常refreshの原HTTP・署名・保存拒否を匿名観測へ追加。
 * </pre>
 *
 * @note Fake DTO/factoryを使いません。通常workerの固定record規約metadataだけを明示scopeで読みます。
 *       明示review-onlyでは通常準備一覧だけを閉じ、原規約dialogを観測後に取消します。
 *       明示取得modeだけは固定規約への既存利用者同意を通常dialogへ結合します。
 *       導入・installer・復旧commandは発行しません。
 * @see docs/adr/0339-common-static-html-terms-binding.md
 */
//------------------------------------------------------------------------------

#include "app/main_window.h"
#include "app/resource.h"
#include "core/official_preparation.h"
#include "core/provider_registry.h"
#include "local_index_acceptance.h"
#include "platform/com_raii.h"

#include <array>
#include <bcrypt.h>
#include <chrono>
#include <commctrl.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <future>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <windows.h>
#include <UIAutomationClient.h>
#include <wrl/client.h>

namespace drivercrate {
namespace {

/** @brief 実同期dialogの観測と未同意取消だけを保持します。 */
struct PreparationReviewObservation {
	/// 今回の通常MainWindowだけを対象にする非所有handleです。
	HWND		 owner{} ;
	/// 同実worker計画が保持する原規約全文です。出力や永続保存をしません。
	std::wstring expectedText ;
	/// 同実worker計画が保持する出典主体と元revisionの表示全文です。
	std::wstring expectedRevisionLabel ;
	/// 実既存resourceから読んだ準備dialogのcaptionです。
	std::wstring expectedDialogTitle ;
	/// 同じownerの非dialog popupを操作対象から除いた回数です。
	std::size_t	 ignoredOwnedNonDialogWindows{} ;
	/// 実一覧が標準dialog classである場合trueです。
	bool		 overviewStandardDialogClass{} ;
	/// 実一覧captionが既存準備resourceと一致した場合trueです。
	bool		 overviewTitleMatches{} ;
	/// 実一覧に直接IDOK child handleが存在した場合trueです。
	bool		 overviewDirectOkControl{} ;
	/// 取得許諾ではない一覧閲覧を実dialogで確認した場合trueです。
	bool		 overviewObserved{} ;
	/// 実規約全文controlを観測した場合trueです。
	bool		 eulaObserved{} ;
	/// 実表示全文と今回の元計画が完全一致した場合trueです。
	bool		 textMatches{} ;
	/// 実表示revisionと今回の元計画が完全一致した場合trueです。
	bool		 revisionMatches{} ;
	/// 元計画のrevisionが今回固定したIntel OBL改訂と完全一致した場合trueです。
	bool		 fixedRevisionMatches{} ;
	/// 実本文controlがread-onlyの場合trueです。
	bool		 readOnlyText{} ;
	/// 実規約dialogの初期focusが取消buttonの場合trueです。
	bool		 cancelFocused{} ;
	/// 実規約dialogへ取消commandだけを送信した場合trueです。
	bool		 cancelSent{} ;
	/// 想定外dialogやcallback例外を成功へ換算しない拒否状態です。
	bool		 failed{} ;
	/// 実本文controlから読んだUTF-16文字数です。
	std::size_t	 displayedCharacters{} ;
	/// 実本文controlを厳密UTF-8へ変換したbyte数です。
	std::size_t	 displayedUtf8Bytes{} ;
	/// 実表示全文のUTF-8 SHA-256です。本文自体を出力しません。
	std::string	 displayedTextSha256 ;
	/// 同実worker計画のUTF-8 SHA-256です。
	std::string	 originalPlanTextSha256 ;
	/// 元205の固定抽出全文SHA-256と実表示が一致した場合trueです。
	bool		 originalTextHashMatches{} ;
	/// Modal待機を有限に保つGetTickCount64の期限です。
	ULONGLONG	 deadline{} ;
} ;

// 同UI threadの同期review中だけ借用し、timer破棄後に必ず解除します。
thread_local PreparationReviewObservation *activeReview{} ;

/** @brief 実controlの文字列を有限長で端末内比較用に読みます。
 * @param[in] control 同じ実dialog内の非所有control handleです。
 * @return 実表示文字列です。上限違反または読出失敗は空です。
 */
[[nodiscard]] std::wstring				   readDialogText( const HWND control)
{
	const int length = GetWindowTextLengthW( control) ;	// 実controlが申告したUTF-16長です。
	// 元契約の本文上限を超えるcontrolや空の表示を成功へ換算しません。
	if( length <= 0 || static_cast<std::size_t>( length) > MAXIMUM_PREPARATION_EULA_CHARACTERS) {
		return {} ;
	}

	std::wstring text( static_cast<std::size_t>( length) + 1U, L'\0') ;	// 終端を含む有限bufferです。
	// 完全な原表示だけを返し、部分読出しを一致へ換算しません。
	if( GetWindowTextW( control, text.data(), length + 1) != length) {
		return {} ;
	}

	text.resize( static_cast<std::size_t>( length)) ;
	return text ;
}

/** @brief 実表示全文のUTF-8 SHA-256だけを公開hash APIで計算します。
 * @param[in] text 上限確認済みの短命端末内全文です。
 * @return 原UTF-8 byteの小文字hex SHA-256です。変換・hash失敗は空です。
 * @note BCryptの非所有pseudo algorithm handleだけを使い、鍵や永続CNG storeへ触れません。
 */
[[nodiscard]] std::string dialogTextSha256( const std::wstring &text)
{
	// 空または元契約の上限を超える本文をhash成功へ変換しません。
	if( text.empty() || text.size() > MAXIMUM_PREPARATION_EULA_CHARACTERS) {
		return {} ;
	}

	const int characters = static_cast<int>( text.size()) ;	// 本文上限からint内と確認済みです。
	const int length = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), characters,
										   nullptr, 0, nullptr, nullptr) ;	// 原UTF-8 byte数です。
	// Unicode変換失敗では別表現のhashを補完しません。
	if( length <= 0) {
		return {} ;
	}

	std::vector<unsigned char> bytes( static_cast<std::size_t>( length)) ;	// 原全文の短命UTF-8です。
	// BCryptへのbyte buffer境界では同じownerのunsigned byteをchar viewへ限定変換します。
	if( WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), characters,
						   reinterpret_cast<char *>( bytes.data()), length, nullptr,
						   nullptr) != length) {
		return {} ;
	}

	std::array<unsigned char, 32U> digest{} ;	// SHA-256の固定32byte出力です。
	// 非所有pseudo algorithm handleでbyte hashだけを計算し、CNG key操作を行いません。
	if( BCryptHash( BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, bytes.data(),
				  static_cast<ULONG>( bytes.size()), digest.data(),
				  static_cast<ULONG>( digest.size())) < 0) {
		return {} ;
	}

	constexpr std::string_view digits = "0123456789abcdef" ;	// 固定小文字hex変換表です。
	std::string				   result ;							// 固定64文字の公開hashだけです。
	result.reserve( 64U) ;
	// 固定32byteを順序を保ってhexへ変換します。
	for( const auto byte : digest) {
		result.push_back( digits[byte >> 4U]) ;
		result.push_back( digits[byte & 0x0FU]) ;
	}

	return result ;
}

/** @brief 同通常画面の実一覧または規約dialogだけを観測し、同意を送りません。
 * @param[in] dialog 同UI threadが所有する列挙中の非所有handleです。
 * @param[in] parameter 同期timer呼出し中だけ有効な観測snapshotです。
 * @return 列挙を継続するTRUEです。
 * @note Callback例外は失敗として保持し、同意や取得commandへ変換しません。
 */
BOOL CALLBACK observePreparationDialog( const HWND dialog, const LPARAM parameter) noexcept
{
	// Win32 callbackのopaque整数には同期列挙中だけ生存するsnapshot pointerを渡します。
	auto &observation = *reinterpret_cast<PreparationReviewObservation *>( parameter) ;
	// 他画面、非表示、通常画面本体は操作対象にしません。
	if( !IsWindowVisible( dialog) || GetWindow( dialog, GW_OWNER) != observation.owner) {
		return TRUE ;
	}

	std::array<wchar_t, 64U> className{} ;	// 標準class判定だけに使用する有限bufferです。
	// 同じownerのtooltip等を規約dialogと誤認せず、内容やcaptionを出力しません。
	if( GetClassNameW( dialog, className.data(), static_cast<int>( className.size())) <= 0 ||
	   std::wstring_view{className.data()} != L"#32770") {
		++observation.ignoredOwnedNonDialogWindows ;
		return TRUE ;
	}

	// 期限超過または既存観測失敗では空controlも未同意取消で閉じます。
	if( observation.failed) {
		static_cast<void>( PostMessageW( dialog, WM_CLOSE, 0, 0)) ;
		return TRUE ;
	}

	try {
		const HWND body =
			// 実規約の全文controlです。
			GetDlgItem( dialog, IDC_PREPARATION_EULA_TEXT) ;
		// 本文controlを持つ実規約dialogは元計画と比較した後、取消だけを送ります。
		if( body != nullptr) {
			const auto text = readDialogText( body) ;	// 実表示全文です。端末外やstdoutへ出しません。
			// 実dialogの出典主体と元revisionの表示全文です。出力しません。
			const auto revision = readDialogText( GetDlgItem( dialog, IDC_PREPARATION_EULA_REVISION)) ;
			// 初期化中の空controlを早期に操作せず、次の有限timerまで待ちます。
			if( text.empty() || revision.empty()) {
				return TRUE ;
			}

			observation.eulaObserved		= true ;
			observation.textMatches			= text == observation.expectedText ;
			observation.revisionMatches		= revision == observation.expectedRevisionLabel ;
			observation.displayedCharacters = text.size() ;
			const int utf8Bytes				= WideCharToMultiByte(
				CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>( text.size()), nullptr,
				0, nullptr, nullptr) ;	// 原表示のUTF-8 byte数です。
			observation.displayedUtf8Bytes =
				utf8Bytes > 0 ? static_cast<std::size_t>( utf8Bytes) : 0U ;
			observation.displayedTextSha256 = dialogTextSha256( text) ;
			observation.originalTextHashMatches =
				observation.displayedTextSha256 ==
				"619c0d4dd837a6b4d3db41c876b869e07370a0cee6275f6f6b7abeacc56c0b6a" ;
			observation.readOnlyText  = (GetWindowLongPtrW( body, GWL_STYLE) & ES_READONLY) != 0 ;
			observation.cancelFocused = GetFocus() == GetDlgItem( dialog, IDCANCEL) ;
			observation.cancelSent	  = PostMessageW( dialog, WM_COMMAND, IDCANCEL, 0) != FALSE ;
			return TRUE ;
		}

		// 一覧閲覧のOKだけで原規約表示へ進み、取得対象選択や同意buttonを操作しません。
		if( !observation.overviewObserved &&
		   readDialogText( dialog) == observation.expectedDialogTitle) {
			observation.overviewStandardDialogClass = true ;
			observation.overviewTitleMatches		= true ;
			observation.overviewDirectOkControl		= GetDlgItem( dialog, IDOK) != nullptr ;
			observation.overviewObserved			= true ;
			observation.failed = PostMessageW( dialog, TDM_CLICK_BUTTON, IDOK, 0) == FALSE ;
			return TRUE ;
		}

		// 想定外dialogでは承認に相当するbuttonを選ばず、今回の観測を失敗にします。
		observation.failed = true ;
		static_cast<void>( PostMessageW( dialog, WM_CLOSE, 0, 0)) ;
	} catch( ...) {
		// Callback境界の例外は記録し、元dialogを未同意取消で閉じます。
		observation.failed = true ;
		static_cast<void>( PostMessageW( dialog, WM_CLOSE, 0, 0)) ;
	}

	return TRUE ;
}

/** @brief 実modal message loopから有限なdialog観測を行います。
 * @param[in] window Thread timerなので通常はnullです。
 * @param[in] message Win32 timer messageです。
 * @param[in] identifier 今回作成した非所有timer IDです。
 * @param[in] elapsed Win32が渡すtick値です。期限はGetTickCount64を使用します。
 * @note 同UI threadの短命snapshotだけへアクセスし、EULA同意を発行しません。
 */
void CALLBACK observePreparationTimer( const HWND window, const UINT message,
									  const UINT_PTR identifier, const DWORD elapsed) noexcept
{
	static_cast<void>( window) ;
	static_cast<void>( message) ;
	static_cast<void>( identifier) ;
	static_cast<void>( elapsed) ;
	// 同期review外の遅延timerは借用snapshotへアクセスしません。
	if( activeReview == nullptr) {
		return ;
	}

	// Modal期限超過を成功へ変換せず、同じ画面のdialogを取消します。
	if( GetTickCount64() >= activeReview->deadline) {
		activeReview->failed = true ;
	}

	// Win32 LPARAMは同期EnumThreadWindows中だけ有効な非所有pointerの搬送境界です。
	EnumThreadWindows( GetCurrentThreadId(), observePreparationDialog,
					  reinterpret_cast<LPARAM>( activeReview)) ;
}

/** @brief 同期dialogの原表示一件を比較する短命な借用状態です。 */
struct DialogTextMatch {
	/// 同期列挙中だけ有効な期待全文です。
	std::wstring_view expected ;
	/// 原表示が完全一致した場合だけtrueです。
	bool			  found{} ;
} ;

/** @brief 有限なchild controlの原表示を比較します。
 * @param[in] control 同じdialogから列挙した非所有handleです。
 * @param[in] parameter 同期列挙中だけ生存する比較状態です。
 * @return 一致を検出した場合FALSE、それ以外はTRUEです。
 * @note 例外は比較不成立として保持し、本文を出力しません。
 */
BOOL CALLBACK matchDialogText( const HWND control, const LPARAM parameter) noexcept
{
	// LPARAMは同期EnumChildWindowsの非所有pointer搬送境界です。
	auto &match = *reinterpret_cast<DialogTextMatch *>( parameter) ;
	try {
		match.found = readDialogText( control) == match.expected ;
	} catch( ...) {
		match.found = false ;
	}

	return match.found ? FALSE : TRUE ;
}

/** @brief 同じdialogの標準controlに原全文が表示されているか確認します。
 * @param[in] dialog 同期観測する非所有dialogです。
 * @param[in] expected 本呼出し中だけ借用する原全文です。
 * @return 完全一致したcontrolがあればtrueです。
 */
[[nodiscard]] bool dialogHasText( const HWND dialog, const std::wstring_view expected)
{
	DialogTextMatch match{expected} ;	// 同期列挙だけが借用します。
	// LPARAMは同呼出しの間だけ有効な比較状態を搬送します。
	EnumChildWindows( dialog, matchDialogText, reinterpret_cast<LPARAM>( &match)) ;
	return !expected.empty() && match.found ;
}

/** @brief 別MTA threadから同じ実dialogの仮想control名を有限に照合します。
 * @param[in] dialog 元UI threadが応答まで保持する非所有handleです。
 * @param[in] requiredNames 同期呼出し中だけ参照する表示全文です。
 * @return 全ての原表示名が存在すればtrueです。COM失敗・不一致はfalseです。
 * @note UI threadから呼びません。接続・各transactionに500msを指定し、操作patternを使いません。
 */
[[nodiscard]] bool accessibleDialogHasNames( const HWND						 dialog,
											const std::vector<std::wstring> &requiredNames)
{
	const ComApartment apartment{COINIT_MULTITHREADED} ;	// この短命MTAだけでCOMを所有します。
	// MTA初期化失敗を表示一致にしません。
	if( FAILED( apartment.result()) || requiredNames.empty() || requiredNames.size() > 2U) {
		return false ;
	}

	Microsoft::WRL::ComPtr<IUIAutomation2> automation ;	// 同MTAだけが所有するread-only clientです。
	// 対応するWindows標準UIAと有限timeoutが成立しなければ承認しません。
	if( FAILED( CoCreateInstance( __uuidof( CUIAutomation8), nullptr, CLSCTX_INPROC_SERVER,
							   IID_PPV_ARGS( automation.GetAddressOf()))) ||
	   FAILED( automation->put_ConnectionTimeout( 500U)) ||
	   FAILED( automation->put_TransactionTimeout( 500U))) {
		return false ;
	}

	Microsoft::WRL::ComPtr<IUIAutomationElement> root ;	// 実dialogから取得した短命elementです。
	// 別Windowへのfallbackやdesktop全体の探索を行いません。
	if( FAILED( automation->ElementFromHandle( dialog, root.GetAddressOf())) || !root) {
		return false ;
	}

	// 固定した最大二つの表示全文だけをName属性へ完全一致で照合します。
	for( const auto &name : requiredNames) {
		UniqueBstr text{name} ;	// 元全文の短命COM引数です。
		VARIANT	   value{} ;	// BSTRの所有権はtextに残す借用VARIANTです。
		value.vt	  = VT_BSTR ;
		value.bstrVal = text.get() ;
		Microsoft::WRL::ComPtr<IUIAutomationCondition> condition ;	// 原全文だけの照合条件です。
		Microsoft::WRL::ComPtr<IUIAutomationElement>   found ;		// 同dialog内のread-only一致です。
		// 欠落・不一致・timeoutから表示成功を補完しません。
		if( !text.get() ||
		   FAILED( automation->CreatePropertyCondition( UIA_NamePropertyId, value,
													  condition.GetAddressOf())) ||
		   FAILED( root->FindFirst( TreeScope_Descendants, condition.Get(), found.GetAddressOf())) ||
		   !found) {
			return false ;
		}
	}

	return true ;
}

/** @brief 既存利用者承認を固定一record・全文・原期限へ限定します。
 * @param[in] target 実workerが同scanで発行した未変更targetです。
 * @param[in] now 現在の信頼UTC秒です。
 * @return 元record、規約、予算、期限が全て固定値に一致した場合だけtrueです。
 * @note 通信・導入権限を生成せず、通常workerが全承認を再検証します。
 */
[[nodiscard]] bool approvedIntelTarget( const OfficialPreparationTarget &target,
									   const std::chrono::sys_seconds	now)
{
	const auto observed = std::chrono::sys_days{std::chrono::year{2026} / 10 / 15} +
						  std::chrono::hours{2} + std::chrono::minutes{59} +
						  std::chrono::seconds{37} ;		// 223/014の新しい実収集です。
	const auto expires = observed + std::chrono::days{1} ;	// 元索引とattestationの期限です。
	return now >= observed && now < expires && target.providerId == SIGNED_INDEX_PROVIDER_ID &&
		   target.resourceId == L"index-static-zip" &&
		   target.identity.starts_with( L"index-acquisition-") &&
		   target.releaseIdentity ==
			   L"6f0a27d58871e0f322ec0c430b3281a6682ef8e8c5d197f63bd5b1a655b11b18" &&
		   target.parserRevision == 1U && target.maximumBytes == 134217728U &&
		   target.deviceCount == 1U &&
		   target.terms == OfficialPreparationTerms::ACCEPTANCE_REQUIRED &&
		   target.eulaSourceSubject == L"intel-ethernet-win11 (https://www.intel.com/)" &&
		   target.eulaRevision ==
			   L"Intel OBL Distribution (Commercial Use) License Agreement [v2025.02.12]" &&
		   dialogTextSha256( target.eulaText) ==
			   "619c0d4dd837a6b4d3db41c876b869e07370a0cee6275f6f6b7abeacc56c0b6a" &&
		   !target.requiresPrerequisiteConfirmation && target.prerequisiteText.empty() ;
}

/** @brief 同通常画面の承認済み取得dialogを順序・原全文へ結合します。 */
struct ApprovedAcquisitionObservation {
	/// 今回の通常MainWindowだけを対象にする非所有handleです。
	HWND					  owner{} ;
	/// 応答済みの旧dialogへ重複commandを送らない非所有handleです。
	HWND					  acknowledged{} ;
	/// 固定targetの原全文・revisionです。
	OfficialPreparationTarget target ;
	/// 通常resourceから生成したcaptionです。
	std::wstring			  title ;
	/// 概要の原表示全文です。
	std::wstring			  overview ;
	/// 同targetの取得前明細全文です。
	std::wstring			  targetDetails ;
	/// 取得一件だけの最終確認全文です。
	std::wstring			  finalConfirmation ;
	/// 通常handlerが同UI threadで生成する結果本文への短命な借用です。
	const std::wstring		 *resultText{} ;
	/// 概要、原規約、対象選択、最終確認、結果表示の順に0から5へ進みます。
	unsigned				  phase{} ;
	/// 原全文と元revisionを実表示で再確認した場合trueです。
	bool					  exactTermsDisplayed{} ;
	/// 原規約の既定取消focusとread-only表示を確認した場合trueです。
	bool					  termsSafeDefaults{} ;
	/// 実結果dialogの原全文を確認して閉じた場合trueです。
	bool					  resultDisplayed{} ;
	/// 想定外表示・期限切れ・callback例外を失敗として保持します。
	bool					  failed{} ;
	/// 全取得観測を有限にする単調時計の期限です。
	ULONGLONG				  deadline{} ;
	/// 別MTAが所有copyだけで照合する未来値です。UIは準備状態だけを確認します。
	std::future<bool>		  accessibleMatch ;
	/// 未来値を要求した同dialogです。別dialogへ結果を流用しません。
	HWND					  pendingDialog{} ;
	/// 一照合を最大五秒で不受入にする単調期限です。
	ULONGLONG				  accessibleDeadline{} ;
} ;

// 同UI threadの取得確認から実結果dialogまでだけ借用します。
thread_local ApprovedAcquisitionObservation *activeAcquisition{} ;

/** @brief 承認済み取得の実dialogだけへ原表示を確認して応答します。
 * @param[in] dialog 同UI threadが所有する列挙中の非所有handleです。
 * @param[in] parameter 同期timer中だけ有効な観測状態です。
 * @return 列挙を継続するTRUEです。
 * @note 想定外表示は取消し、導入確認やnetwork例外へ同意しません。
 */
BOOL CALLBACK observeApprovedAcquisitionDialog( const HWND dialog, const LPARAM parameter) noexcept
{
	// LPARAMは同期列挙中だけ有効な非所有観測pointerです。
	auto &observation = *reinterpret_cast<ApprovedAcquisitionObservation *>( parameter) ;
	// 他画面・非表示・応答済み旧dialogを操作しません。
	if( !IsWindowVisible( dialog) || GetWindow( dialog, GW_OWNER) != observation.owner ||
	   dialog == observation.acknowledged) {
		return TRUE ;
	}

	std::array<wchar_t, 64U> className{} ;	// 標準dialog classだけを扱う有限bufferです。
	// Tooltip等を取得確認と誤認しません。
	if( GetClassNameW( dialog, className.data(), static_cast<int>( className.size())) <= 0 ||
	   std::wstring_view{className.data()} != L"#32770") {
		return TRUE ;
	}

	try {
		const auto now = std::chrono::floor<std::chrono::seconds>(
			// 実UTCです。
			std::chrono::system_clock::now()) ;
		// 元期限・対象・captionの変更では承認を流用しません。
		if( observation.failed || !approvedIntelTarget( observation.target, now) ||
		   (observation.phase != 1U && readDialogText( dialog) != observation.title)) {
			observation.failed = true ;
			static_cast<void>( PostMessageW( dialog, WM_CLOSE, 0, 0)) ;
			return TRUE ;
		}

		bool accessibleMatched{} ;	// TaskDialogの仮想本文だけの別MTA結果です。
		// 概要・対象・結果の原表示を非同期read-only UIAへ渡し、UI threadを待機させません。
		if( observation.phase == 0U || observation.phase == 2U || observation.phase == 4U) {
			// 新dialogにだけ最大二つの原表示の所有copyを貸します。
			if( !observation.accessibleMatch.valid()) {
				std::vector<std::wstring> names ;	// 別MTAが単独所有する表示条件です。
				// 概要では全体予算と固定一対象の両全文を照合します。
				if( observation.phase == 0U) {
					names = {observation.overview, observation.targetDetails + L"\r\n\r\n"} ;
				}
				// 対象選択は同targetの原明細だけを照合します。
				else if( observation.phase == 2U) {
					names = {observation.targetDetails} ;
				}
				// 元handlerが確定した空でない実結果だけを照合します。
				else if( observation.resultText && !observation.resultText->empty()) {
					names = {*observation.resultText} ;
				}

				observation.pendingDialog	   = dialog ;
				observation.accessibleDeadline = GetTickCount64() + 5000U ;
				observation.accessibleMatch =
					std::async( std::launch::async, [dialog, names = std::move( names)] {
						return accessibleDialogHasNames( dialog, names) ;
					}) ; // UI stateを借用しない短命MTAです。
				return TRUE ;
			}

			// 別dialog・照合期限超過では結果を流用せず取消します。
			if( observation.pendingDialog != dialog ||
			   GetTickCount64() >= observation.accessibleDeadline) {
				observation.failed = true ;
				static_cast<void>( PostMessageW( dialog, WM_CLOSE, 0, 0)) ;
				return TRUE ;
			}

			// 未完了の未来値をUI threadで同期waitせず、実modal loopへ返します。
			if( observation.accessibleMatch.wait_for( std::chrono::milliseconds{0}) !=
			   std::future_status::ready) {
				return TRUE ;
			}

			accessibleMatched = observation.accessibleMatch.get() ;
			std::printf( "APPROVED_DIALOG_READ phase=%u matched=%u separateMta=1\n",
						observation.phase, static_cast<unsigned>( accessibleMatched)) ;
			// 原表示の不一致またはCOM失敗から承認を補完しません。
			if( !accessibleMatched) {
				observation.failed = true ;
				static_cast<void>( PostMessageW( dialog, WM_CLOSE, 0, 0)) ;
				return TRUE ;
			}
		}

		UINT button{} ;				// 完全一致後だけ送る既存button IDです。
		bool taskDialog = true ;	// 原規約と最終MessageBoxだけはWM_COMMANDを使います。
		// 同一targetの概要全文を確認して原規約表示へ進みます。
		if( observation.phase == 0U && accessibleMatched) {
			button = IDOK ;
		}
		// 実表示本文・revision・既定取消・read-onlyを照合して既存利用者同意を結びます。
		else if( observation.phase == 1U && GetDlgItem( dialog, IDC_PREPARATION_EULA_TEXT)) {
			const HWND body = GetDlgItem( dialog, IDC_PREPARATION_EULA_TEXT) ;	// 実原文controlです。
			const auto revision = observation.target.eulaSourceSubject + L"\r\n" +
								  observation.target.eulaRevision ;	// 元表示です。
			observation.exactTermsDisplayed =
				readDialogText( body) == observation.target.eulaText &&
				readDialogText( GetDlgItem( dialog, IDC_PREPARATION_EULA_REVISION)) == revision ;
			observation.termsSafeDefaults =
				(GetWindowLongPtrW( body, GWL_STYLE) & ES_READONLY) != 0 &&
				GetFocus() == GetDlgItem( dialog, IDCANCEL) ;
			// 不一致を承認へ補完せず、通常取消しで閉じます。
			if( !observation.exactTermsDisplayed || !observation.termsSafeDefaults) {
				observation.failed = true ;
				button			   = IDCANCEL ;
			} else {
				button = IDYES ;
			}

			taskDialog = false ;
		}
		// 同じ一対象の取得だけを選び、network例外checkboxは選択しません。
		else if( observation.phase == 2U && accessibleMatched) {
			button = IDYES ;
		}
		// 原件数一件の最終確認だけへ応答し、導入確認を扱いません。
		else if( observation.phase == 3U && dialogHasText( dialog, observation.finalConfirmation) &&
				GetDlgItem( dialog, IDYES)) {
			button	   = IDYES ;
			taskDialog = false ;
		}
		// 実worker完了後に通常handlerが生成した原結果を実dialogで確認します。
		else if( observation.phase == 4U && accessibleMatched) {
			observation.resultDisplayed = true ;
			button						= IDOK ;
		} else {
			observation.failed = true ;
			static_cast<void>( PostMessageW( dialog, WM_CLOSE, 0, 0)) ;
			return TRUE ;
		}

		observation.acknowledged = dialog ;
		++observation.phase ;
		// 同一dialogの既存button routingだけを使い、成功DTOやworker taskを注入しません。
		if( !PostMessageW( dialog, taskDialog ? TDM_CLICK_BUTTON : WM_COMMAND, button, 0)) {
			observation.failed = true ;
		}
	} catch( ...) {
		observation.failed = true ;
		static_cast<void>( PostMessageW( dialog, WM_CLOSE, 0, 0)) ;
	}

	return TRUE ;
}

/** @brief 有限な同UI threadのdialog観測を実modal loopへ接続します。
 * @param[in] window Thread timerの未使用handleです。
 * @param[in] message 未使用timer messageです。
 * @param[in] identifier 未使用timer IDです。
 * @param[in] elapsed 未使用tickです。期限はGetTickCount64を使います。
 * @note 期限超過時は取消しへ進み、既存workerを再起動しません。
 */
void CALLBACK observeApprovedAcquisitionTimer( const HWND window, const UINT message,
											  const UINT_PTR identifier,
											  const DWORD	 elapsed) noexcept
{
	static_cast<void>( window) ;
	static_cast<void>( message) ;
	static_cast<void>( identifier) ;
	static_cast<void>( elapsed) ;
	// 同期観測外の遅延timerを無視します。
	if( !activeAcquisition) {
		return ;
	}

	// 元期限と独立した有限観測枠を越えたらdialogを取消します。
	if( GetTickCount64() >= activeAcquisition->deadline) {
		activeAcquisition->failed = true ;
	}

	// LPARAMは同UI threadの同期列挙中だけ有効な借用pointerです。
	EnumThreadWindows( GetCurrentThreadId(), observeApprovedAcquisitionDialog,
					  reinterpret_cast<LPARAM>( activeAcquisition)) ;
}

/** @brief 実TaskDialogの非通信read-only正負確認だけを所有します。 */
struct DialogReadSelfCheck {
	/// 別MTAだけで実表示の正例と改変表示の負例を確認する未来値です。
	std::future<bool> query ;
	/// 正負が両方成立した場合だけtrueです。
	bool			  passed{} ;
	/// 未完了・例外・取消しを成功へ数えない状態です。
	bool			  failed{} ;
	/// 実dialog一件の五秒観測期限です。
	ULONGLONG		  deadline{} ;
} ;

/** @brief 非通信の実TaskDialogから別MTA表示確認を開始します。
 * @param[in] dialog 今回の非所有実dialog handleです。
 * @param[in] message TaskDialogの作成・timer通知です。
 * @param[in] wordParameter 未使用button通知値です。
 * @param[in] longParameter 未使用通知値です。
 * @param[in] data 同期dialog中だけ有効な自己検査状態です。
 * @return 通常通知処理を続けるS_OKです。
 * @note Provider・実inventory・HTTP・同意・導入を開始しません。
 */
HRESULT CALLBACK selfCheckDialogRead( const HWND dialog, const UINT message,
									 const WPARAM wordParameter, const LPARAM longParameter,
									 const LONG_PTR data) noexcept
{
	static_cast<void>( wordParameter) ;
	static_cast<void>( longParameter) ;
	// TaskDialogの同期callbackへ貸した短命な非所有状態です。
	auto &check = *reinterpret_cast<DialogReadSelfCheck *>( data) ;
	try {
		// 原表示が構築された実dialogだけを別MTAから確認します。
		if( message == TDN_CREATED) {
			check.deadline = GetTickCount64() + 5000U ;
			check.query	   = std::async( std::launch::async, [dialog] {
				   return accessibleDialogHasNames( dialog, {L"finite overview\nsecond",
															L"finite details\r\nsecond\r\n\r\n"}) &&
						  !accessibleDialogHasNames( dialog, {L"changed unapproved details"}) ;
			   }) ; // 所有copyと同実dialog handleだけを短命MTAへ渡します。
		}
		// Modal loopのtimerでは準備状態だけを確認します。
		else if( message == TDN_TIMER && check.query.valid()) {
			// 未完了や不一致を合格へ変換せず五秒で取消します。
			if( GetTickCount64() >= check.deadline) {
				check.failed = true ;
				static_cast<void>( PostMessageW( dialog, TDM_CLICK_BUTTON, IDCANCEL, 0)) ;
			}
			// 別MTAで正負が確定してから実dialogを閉じます。
			else if( check.query.wait_for( std::chrono::milliseconds{0}) ==
					std::future_status::ready) {
				check.passed = check.query.get() ;
				static_cast<void>( PostMessageW( dialog, TDM_CLICK_BUTTON, IDOK, 0)) ;
			}
		}
	} catch( ...) {
		check.failed = true ;
		static_cast<void>( PostMessageW( dialog, TDM_CLICK_BUTTON, IDCANCEL, 0)) ;
	}

	return S_OK ;
}

/** @brief 実TaskDialogの仮想本文を正例・改変負例へ照合する非通信入口です。
 * @return 二条件とも成立なら0、取消し・表示不足・timeoutは2です。
 * @note 実MainWindowやProviderを生成せず、作成した非通信dialogだけを閉じます。
 */
[[nodiscard]] int runDialogReadSelfCheck()
{
	DialogReadSelfCheck check ;		// 同期dialogの終了まで生存する非通信状態です。
	TASKDIALOGCONFIG	config{} ;	// 通常経路と同じ仮想本文を持つ標準dialogです。
	config.cbSize  = sizeof( config) ;
	config.dwFlags = TDF_CALLBACK_TIMER | TDF_ALLOW_DIALOG_CANCELLATION | TDF_EXPANDED_BY_DEFAULT ;
	config.dwCommonButtons		  = TDCBF_OK_BUTTON | TDCBF_CANCEL_BUTTON ;
	config.pszWindowTitle		  = L"DriverCrate dialog read check" ;
	config.pszContent			  = L"finite overview\nsecond" ;
	config.pszExpandedInformation = L"finite details\r\nsecond\r\n\r\n" ;
	config.pfCallback			  = selfCheckDialogRead ;
	// 同期callbackだけが短命状態を借用します。
	config.lpCallbackData = reinterpret_cast<LONG_PTR>( &check) ;
	int		   button{} ;	// 実dialogが返す終了buttonです。
	const auto error =
		// 実表示の元HRESULTです。
		TaskDialogIndirect( &config, &button, nullptr, nullptr) ;
	std::printf(
		"DIALOG_READ_SELF_CHECK checks=2 passed=%u failed=%u error=0x%08lx inventory=0 http=0\n",
		static_cast<unsigned>( check.passed), static_cast<unsigned>( check.failed),
		static_cast<unsigned long>( error)) ;
	return SUCCEEDED( error) && check.passed && !check.failed && button == IDOK ? 0 : 2 ;
}

} // namespace

/** @brief 明示live targetだけで通常画面の匿名件数と同じTree選択を検査します。 */
struct MainWindowLiveIndexTestAccess {
	/** @brief 同UI thread内だけで実queue配送の回数と拒否値を保持します。 */
	struct WorkerCapture {
		/// 通常handlerを持つ非所有画面です。
		MainWindow *window{} ;
		/// 同期dialog中に到着した実終端数です。
		unsigned	completed{} ;
		/// 通常handlerへ配送を完了した実終端数です。
		unsigned	forwarded{} ;
		/// 元workerの拒否値です。
		NativeError controlError{} ;
		/// 元eventの索引summary件数です。
		std::size_t summaryItems{} ;
		/// callback例外を成功へ換算しません。
		bool		failed{} ;
		/// 非通信dialogだけの絶対終了tickです。
		ULONGLONG	deadline{} ;
		/** @brief 借用先画面が生存中に同じsubclassだけを外します。 */
		~WorkerCapture()
		{
			// 同じ画面へ登録した観測だけを解除します。
			if( window) {
				RemoveWindowSubclass( window->window_, captureWorker, 223U) ;
			}
		}
	} ;

	/** @brief 入れ子modal loopでも元queueの実eventを一度だけ通常handlerへ送ります。
	 * @param[in] handle 通常画面です。
	 * @param[in] message 元message番号です。
	 * @param[in] first 元WPARAMです。
	 * @param[in] second 元LPARAMです。
	 * @param[in] identity 登録したsubclass識別子です。
	 * @param[in] data 同UI thread内で生存する借用観測です。
	 * @return 通常subclass chainの戻り値です。
	 */
	static LRESULT CALLBACK captureWorker( HWND handle, UINT message, WPARAM first, LPARAM second,
										  UINT_PTR identity, DWORD_PTR data) noexcept
	{
		auto *capture = reinterpret_cast<WorkerCapture *>( data) ;	// Win32が同threadへ返す借用です。
		// 対象通知だけを移し、通常WndProcが同じeventを二重受信しないようにします。
		if( capture && identity == 223U && message == MainWindow::WORKER_NOTIFICATION_MESSAGE) {
			try {
				const auto events = capture->window->worker_->takeEvents() ;	// 元queueの所有値です。
				// 到着順を保ち、人工結果・候補へ置換しません。
				for( const auto &event : events) {
					// 実取得終端だけを数値で観測します。
					if( event.kind == WorkerEventKind::PREPARATION_COMPLETED) {
						++capture->completed ;
						capture->controlError = event.preparationResult.controlError ;
						capture->summaryItems = event.indexPreparation.items.size() ;
						std::printf(
							"WORKER_CAPTURE before=1 items=%zu audits=%zu summary=%zu controlError=0x%08lx\n",
							event.preparationResult.items.size(),
							event.preparationResult.auditReports.size(), capture->summaryItems,
							static_cast<unsigned long>( capture->controlError)) ;
						// 同じ実取得itemの元結果だけを記録し、byte表示から成功を推測しません。
						for( const auto &item : event.preparationResult.items) {
							std::printf( "WORKER_CAPTURE_ITEM state=%u error=0x%08lx bytes=%llu\n",
										static_cast<unsigned>( item.result.state),
										static_cast<unsigned long>( item.result.error),
										static_cast<unsigned long long>( item.result.byteCount)) ;
						}

						// 全reportの内容・rank・発行を別々に保存します。
						for( const auto &report : event.preparationResult.auditReports) {
							std::printf(
								"NORMAL_MAIN_WINDOW_AUDIT content=%u contentError=0x%08lx infs=%u accepted=%u applicability=%u applicabilityError=0x%08lx examined=%u applicable=%u failed=%u publication=%u publicationExamined=%u publicationExcluded=%u publicationError=0x%08lx published=%zu\n",
								static_cast<unsigned>( report.content),
								static_cast<unsigned long>( report.contentError), report.infCount,
								report.acceptedInfCount,
								static_cast<unsigned>( report.applicability),
								static_cast<unsigned long>( report.applicabilityError),
								report.examinedPairCount, report.applicablePairCount,
								report.failedPairCount,
								static_cast<unsigned>( report.publication.state),
								report.publication.examinedPairCount,
								report.publication.excludedPairCount,
								static_cast<unsigned long>( report.publication.firstError),
								report.publishedCandidates.size()) ;
						}
					}

					capture->window->processWorkerEvent( event) ;
					// 通常handler後の状態を元eventとは分けて残します。
					if( event.kind == WorkerEventKind::PREPARATION_COMPLETED) {
						++capture->forwarded ;
						std::printf(
							"WORKER_CAPTURE after=1 forwarded=%u state=%u summary=%zu candidates=%zu\n",
							capture->forwarded,
							static_cast<unsigned>( capture->window->controller_.state()),
							capture->window->indexPreparationSummary_.items.size(),
							capture->window->candidates_.size()) ;
					}
				}
			} catch( ...) {
				capture->failed = true ;
			}
		}

		return DefSubclassProc( handle, message, first, second) ;
	}

	/** @brief scan権限のない実commandの拒否を実modal queueで一度だけ観測します。
	 * @param[in,out] window 未scanの通常画面です。
	 * @return 元拒否保持・一回配送・重複通知無作用が揃えば0です。
	 */
	[[nodiscard]] static int verifyWorkerCapture( MainWindow &window)
	{
		WorkerCapture capture ;	// 同期dialog終了まで生存する借用観測です。
		capture.window	 = &window ;
		capture.deadline = GetTickCount64() + 5000U ;
		// 観測未登録では実commandを送信しません。
		if( !SetWindowSubclass( window.window_, captureWorker, 223U,
							  reinterpret_cast<DWORD_PTR>( &capture))) {
			return 2 ;
		}

		OfficialPreparationApproval approval ;	// sessionのない一件はworkerが拒否する実入力です。
		approval.operationId   = 1U ;
		approval.scanSessionId = 1U ;
		approval.planId		   = 1U ;
		approval.decisions.emplace_back() ;
		const auto before = window.controller_.state() ;	// 未scanの元状態です。
		// queue自身の受理失敗を配送成功へ換算しません。
		if( !window.worker_->requestPreparation( approval)) {
			return 2 ;
		}

		TASKDIALOGCONFIG config{} ;	// timer付き実modal loopです。
		config.cbSize		   = sizeof( config) ;
		config.hwndParent	   = window.window_ ;
		config.dwFlags		   = TDF_CALLBACK_TIMER ;
		config.dwCommonButtons = TDCBF_CANCEL_BUTTON ;
		config.pszWindowTitle  = L"Worker queue observation" ;
		config.pszContent	   = L"Non-network rejection observation" ;
		config.lpCallbackData  = reinterpret_cast<LONG_PTR>( &capture) ;
		config.pfCallback	   = []( HWND dialog, UINT notification, WPARAM, LPARAM,
								LONG_PTR data) -> HRESULT {
			 auto *observed =
				 reinterpret_cast<WorkerCapture *>( data) ;	// 同期dialog生存中の借用です。
			 // 実受信または絶対期限で閉じ、無通知を無限待機しません。
			 if( notification == TDN_TIMER &&
				(observed->completed > 0U || GetTickCount64() >= observed->deadline)) {
				 SendMessageW( dialog, TDM_CLICK_BUTTON, IDCANCEL, 0) ;
			 }

			 return S_OK ;
		} ;
		const HRESULT error =
			// 実modal結果です。
			TaskDialogIndirect( &config, nullptr, nullptr, nullptr) ;
		SendMessageW( window.window_, MainWindow::WORKER_NOTIFICATION_MESSAGE, 0, 0) ;
		const bool passed = SUCCEEDED( error) && !capture.failed && capture.completed == 1U &&
							capture.forwarded == 1U && capture.controlError != 0 &&
							capture.summaryItems == 0U && window.controller_.state() == before &&
							// 元拒否保持です。
							window.indexPreparationSummary_.items.empty() ;
		std::printf(
			"WORKER_CAPTURE_SELF_CHECK passed=%u completed=%u forwarded=%u controlError=0x%08lx inventory=0 http=0 successDto=0\n",
			static_cast<unsigned>( passed), capture.completed, capture.forwarded,
			static_cast<unsigned long>( capture.controlError)) ;
		return passed ? 0 : 2 ;
	}
	/** @brief 通常画面で同じ固定storeと実Driver Storeだけのscanを開始します。
	 * @param[in,out] window 未scanの通常画面です。
	 */
	static void begin( MainWindow &window)
	{
		window.enabledProviderIds_ = {std::wstring{DRIVER_STORE_PROVIDER_ID},
									  std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		window.beginScan() ;
	}

	/** @brief 同じ通常controllerの未完了状態をread-onlyで返します。
	 * @param[in] window 実message dispatch先です。
	 * @return 通常scanが未完了ならtrueです。
	 */
	[[nodiscard]] static bool scanning( const MainWindow &window)
	{
		return window.controller_.state() == ApplicationState::SCANNING ;
	}

	/** @brief 既存Tree controlの選択だけを操作し、件数を匿名表示します。
	 * @param[in,out] window 実scan終端を通常event handlerで受理した画面です。
	 * @return 固定一recordの既存導入候補選択、または実参照・Tree focus・規約準備を確認すれば0です。
	 *         取得前参照を導入可能候補へ換算せず、不足は2です。
	 */
	[[nodiscard]] static int observeAndSelect( MainWindow &window)
	{
		std::uint64_t devices{} ;		// 今回の実coverageから集計したpresent数です。
		std::size_t	  candidates{} ;	// 参照行や現在版を除く実索引候補数です。
		std::size_t	  selected{} ;		// 同じ通常Treeが選択を保持した索引候補数です。
		std::size_t	  references{} ;	// 同workerが元準備targetへ結んだ表示専用参照数です。
		std::size_t
			referencesFocused{} ;	// 通常Treeがfocusを保持した参照数です。導入checkboxではありません。
		std::size_t
			termsVerifiedTargets{} ;		// 共通HTTPで全文を検証し、実計画が保持した索引規約数です。
		std::uint64_t termsCharacters{} ;	// 実planの全文UTF-16文字数だけです。本文は出力しません。
		// 実coverageの匿名件数だけを出し、生IDや表示名を出しません。
		for( const auto &entry : window.localCoverage_) {
			devices += entry.deviceCount ;
		}

		SendMessageW( window.recommendedOnlyCheckbox_, BM_SETCHECK, BST_UNCHECKED, 0) ;
		window.handleRecommendedFilterChange() ;
		// 表示済みでinstallableな同じ実索引候補だけを通常Treeで選択します。
		for( std::size_t index = 0; index < window.candidates_.size(); ++index) {
			const auto &candidate = window.candidates_[index] ;	// 同scanの実DTOです。
			// 現在版、参照行、他Provider、表示されない候補は成功へ数えません。
			if( candidate.providerId != SIGNED_INDEX_PROVIDER_ID || candidate.current ||
			   index >= window.candidateItems_.size() || window.candidateItems_[index] == nullptr) {
				continue ;
			}

			// 取得前参照は既存Treeのfocusだけを確認し、導入checkbox選択へ昇格しません。
			if( !candidate.installable) {
				// 私有bindingが元準備対象へ結んだ参照だけを数えます。
				if( candidate.identity.starts_with( L"index-reference-")) {
					++references ;
					TreeView_SelectItem( window.updateTree_, window.candidateItems_[index]) ;
					referencesFocused +=
						TreeView_GetSelection( window.updateTree_) == window.candidateItems_[index]
							? 1U
							: 0U ;
				}

				continue ;
			}

			++candidates ;
			const auto item = window.candidateItems_[index] ;	// 同実候補のTree handleです。
			TreeView_SetCheckState( window.updateTree_, item, TRUE) ;
			window.handleTreeCheckChange( item, true) ;
			// 内部選択を強制せず、既存controller/UIが受理した結果だけを数えます。
			if( window.candidateSelected_[index]) {
				++selected ;
			}
		}

		const auto *plan =
			// 同通常eventの実準備snapshotだけです。
			window.controller_.preparationPlan() ;
		// 共通検証後の実計画だけを読み、EULA同意や取得commandを発行しません。
		if( plan != nullptr) {
			// 有限256targetの文字数だけを積算し、本文や出典identityを出力しません。
			for( const auto &target : plan->targets) {
				// 同意必須の元索引規約本文を実計画が保持した場合だけ数えます。
				if( target.providerId == SIGNED_INDEX_PROVIDER_ID && !target.eulaText.empty() &&
				   !target.eulaRevision.empty()) {
					++termsVerifiedTargets ;
					termsCharacters += target.eulaText.size() ;
				}
			}
		}

		const auto &summary = window.indexScanSummary_ ;	// 同実eventの索引件数です。
		// 同workerが保持した非機密なrefresh結果だけを出し、URLや索引本文は保存しません。
		if( summary.refresh) {
			const auto &refresh = *summary.refresh ;	// 実refreshの元結果を借用します。
			std::printf( "NORMAL_INDEX_REFRESH status=%u sends=%u receivedBytes=%llu httpStatus=%u "
						"httpError=0x%08lx error=0x%08lx manifestObserved=%u manifestStatus=%u "
						"assetObserved=%u assetStatus=%u recordsObserved=%u recordsStatus=%u "
						"storeStatus=%u storeError=0x%08lx usedAuthenticatedCache=%u\n",
						static_cast<unsigned>( refresh.status), refresh.sends,
						static_cast<unsigned long long>( refresh.receivedBytes), refresh.httpStatus,
						static_cast<unsigned long>( refresh.httpError),
						static_cast<unsigned long>( refresh.error),
						static_cast<unsigned>( refresh.manifestStatus.has_value()),
						refresh.manifestStatus ? static_cast<unsigned>( *refresh.manifestStatus)
											   : 0U,
						static_cast<unsigned>( refresh.assetStatus.has_value()),
						refresh.assetStatus ? static_cast<unsigned>( *refresh.assetStatus) : 0U,
						static_cast<unsigned>( refresh.recordsStatus.has_value()),
						refresh.recordsStatus ? static_cast<unsigned>( *refresh.recordsStatus) : 0U,
						static_cast<unsigned>( refresh.store.status),
						static_cast<unsigned long>( refresh.store.error),
						static_cast<unsigned>( refresh.usedAuthenticatedCache)) ;
		}

		std::printf(
			"NORMAL_MAIN_WINDOW_SCAN state=%u devices=%llu records=%zu processed=%zu "
			"matched=%zu undetermined=%zu indexCandidates=%zu indexSelected=%zu "
			"planned=%zu authorityError=0x%08lx indexError=0x%08lx "
			"storeObserved=%u storeStatus=%u lookupObserved=%u lookupStatus=%u "
			"remaining=%zu relations=%zu relatedDevices=%zu nonUnique=%zu resolverCalls=%zu "
			"verifiedPartial=%zu indexReferences=%zu indexReferenceFocused=%zu "
			"termsVerifiedTargets=%zu termsCharacters=%llu "
			"normalContentPositive=0 payloadGet=0 "
			"install=0 restore=0 fake=0\n",
			static_cast<unsigned>( summary.status), static_cast<unsigned long long>( devices),
			summary.totalRecords, summary.processedRecords, summary.matchedRelations,
			summary.undeterminedRelations, candidates, selected,
			window.indexPreparationSummary_.plannedTargets,
			static_cast<unsigned long>( window.indexPreparationSummary_.authorityError),
			static_cast<unsigned long>( summary.error),
			static_cast<unsigned>( summary.storeStatus.has_value()),
			summary.storeStatus ? static_cast<unsigned>( *summary.storeStatus) : 0U,
			static_cast<unsigned>( summary.lookupStatus.has_value()),
			summary.lookupStatus ? static_cast<unsigned>( *summary.lookupStatus) : 0U,
			summary.remainingRecords, summary.relationCount, summary.relatedDeviceCount,
			summary.nonUniqueRelations, summary.resolverCalls, summary.verifiedPartialRelations,
			references, referencesFocused, termsVerifiedTargets,
			static_cast<unsigned long long>( termsCharacters)) ;
		return window.controller_.state() == ApplicationState::SCAN_READY &&
					   summary.totalRecords == 1 && summary.processedRecords == 1 &&
					   ((candidates > 0 && selected > 0) ||
						(summary.verifiedPartialRelations > 0U && references > 0U &&
						 referencesFocused > 0U &&
						 window.indexPreparationSummary_.plannedTargets > 0U &&
						 termsVerifiedTargets > 0U))
				   ? 0
				   : 2 ;
	}

	/** @brief 通常準備commandで元規約を実表示し、未同意の取消状態だけを観測します。
	 * @param[in,out] window 同実scanの元計画を保持する通常画面です。
	 * @return 原規約表示、runtime button、未同意停止が確認できれば0、不足は2です。
	 * @note Worker取得command、EULA同意、導入commandは発行しません。
	 */
	[[nodiscard]] static int observePreparationReview( MainWindow &window)
	{
		const auto *plan = window.controller_.preparationPlan() ;	// 同scanの元準備snapshotです。
		// 取得許諾を意味しない実buttonの利用可能表示です。
		const bool	enabled = IsWindowEnabled( window.preparationButton_) != FALSE ;
		// 固定対象の元計画が一件でない場合はdialogを操作しません。
		if( !enabled || plan == nullptr || plan->targets.size() != 1U ||
		   plan->targets[0].providerId != SIGNED_INDEX_PROVIDER_ID ||
		   plan->targets[0].terms != OfficialPreparationTerms::ACCEPTANCE_REQUIRED) {
			std::printf( "NORMAL_MAIN_WINDOW_PREPARATION_REVIEW buttonEnabled=%u planRejected=1 "
						"payloadGet=0 normalContentPositive=0 eulaAccept=0 fake=0\n",
						static_cast<unsigned>( enabled)) ;
			return 2 ;
		}

		const auto &target = plan->targets[0] ;		// Dialog中も元controllerが保持する実targetです。
		PreparationReviewObservation observation ;	// 同期reviewだけで生存する観測です。
		observation.owner				   = window.window_ ;
		observation.expectedText		   = target.eulaText ;
		observation.originalPlanTextSha256 = dialogTextSha256( target.eulaText) ;
		observation.expectedRevisionLabel =
			target.eulaSourceSubject.empty()
				? target.eulaRevision
				: target.eulaSourceSubject + L"\r\n" + target.eulaRevision ;
		observation.expectedDialogTitle = window.loadString( IDS_PREPARATION_TITLE) ;
		observation.fixedRevisionMatches =
			target.eulaRevision ==
			L"Intel OBL Distribution (Commercial Use) License Agreement [v2025.02.12]" ;
		observation.deadline = GetTickCount64() + 20000U ;
		const auto beforeOperation =
			// Scan後の元operationです。
			window.controller_.activeOperationId() ;
		const UINT_PTR timer =
			// 有限の実modal観測です。
			SetTimer( nullptr, 0, 100U, observePreparationTimer) ;
		// Timerを作成できなければ承認dialogを開始しません。
		if( timer == 0U) {
			std::printf( "NORMAL_MAIN_WINDOW_PREPARATION_REVIEW timerRejected=1 payloadGet=0 "
						"normalContentPositive=0 eulaAccept=0 fake=0\n") ;
			return 2 ;
		}

		activeReview = &observation ;
		// 実既存WM_COMMAND routingを通し、直接review呼出しや人工承認を使いません。
		SendMessageW( window.window_, WM_COMMAND, MAKEWPARAM( IDC_PREPARATION, BN_CLICKED),
					 reinterpret_cast<LPARAM>( window.preparationButton_)) ;
		KillTimer( nullptr, timer) ;
		activeReview = nullptr ;
		// 未同意取消後に新たな取得operationが開始されていない実状態です。
		const bool operationUnchanged = window.controller_.activeOperationId() == beforeOperation ;
		const bool approvalEmpty	  = window.preparationApproval_.operationId == 0U &&
								   // Worker送信前の未承認状態です。
								   window.preparationApproval_.decisions.empty() ;
		// 未同意取消後も元scanを閲覧できる実controller状態です。
		const bool scanReady = window.controller_.state() == ApplicationState::SCAN_READY ;
		const bool reviewClosed =
			!window.preparationReviewOpen_ ;	// 実handlerが再入guardを解除した状態です。
		std::printf(
			"NORMAL_MAIN_WINDOW_PREPARATION_REVIEW buttonEnabled=%u command=1 "
			"overviewObserved=%u eulaObserved=%u textMatches=%u revisionMatches=%u "
			"ignoredOwnedNonDialogWindows=%zu overviewStandardDialogClass=%u "
			"overviewTitleMatches=%u overviewDirectOkControl=%u "
			"fixedRevisionMatches=%u readOnlyText=%u cancelFocused=%u cancelSent=%u "
			"displayedCharacters=%zu displayedUtf8Bytes=%zu displayedTextSha256=%s originalPlanTextSha256=%s "
			"originalTextHashMatches=%u failed=%u operationUnchanged=%u approvalEmpty=%u "
			"scanReady=%u reviewClosed=%u payloadGet=0 normalContentPositive=0 "
			"eulaAccept=0 acquisitionSelection=0 preparationTask=0 install=0 restore=0 fake=0\n",
			static_cast<unsigned>( enabled), static_cast<unsigned>( observation.overviewObserved),
			static_cast<unsigned>( observation.eulaObserved),
			static_cast<unsigned>( observation.textMatches),
			static_cast<unsigned>( observation.revisionMatches),
			observation.ignoredOwnedNonDialogWindows,
			static_cast<unsigned>( observation.overviewStandardDialogClass),
			static_cast<unsigned>( observation.overviewTitleMatches),
			static_cast<unsigned>( observation.overviewDirectOkControl),
			static_cast<unsigned>( observation.fixedRevisionMatches),
			static_cast<unsigned>( observation.readOnlyText),
			static_cast<unsigned>( observation.cancelFocused),
			static_cast<unsigned>( observation.cancelSent), observation.displayedCharacters,
			observation.displayedUtf8Bytes, observation.displayedTextSha256.c_str(),
			observation.originalPlanTextSha256.c_str(),
			static_cast<unsigned>( observation.originalTextHashMatches),
			static_cast<unsigned>( observation.failed), static_cast<unsigned>( operationUnchanged),
			static_cast<unsigned>( approvalEmpty), static_cast<unsigned>( scanReady),
			static_cast<unsigned>( reviewClosed)) ;
		return !observation.failed && observation.overviewObserved && observation.eulaObserved &&
					   observation.textMatches && observation.revisionMatches &&
					   observation.fixedRevisionMatches && observation.originalTextHashMatches &&
					   observation.readOnlyText && observation.cancelFocused &&
					   observation.cancelSent && operationUnchanged && approvalEmpty && scanReady &&
					   reviewClosed
				   ? 0
				   : 2 ;
	}

	/** @brief 既に承認された一recordの通常確認から実取得・実結果までを観測します。
	 * @param[in,out] window 同じ実scanと未使用計画を保持する通常画面です。
	 * @return 実取得・内容合格・表示候補・実結果dialogが揃えば0、不足は2です。
	 * @note 導入commandを送らず、元計画と実worker結果を置き換えません。
	 */
	[[nodiscard]] static int acquireApproved( MainWindow &window)
	{
		WorkerCapture capture ;	// 入れ子dialogを含む通常配送を同じthreadで観測します。
		capture.window = &window ;
		// 実通知の観測未登録では新規取得を開始しません。
		if( !SetWindowSubclass( window.window_, captureWorker, 223U,
							  reinterpret_cast<DWORD_PTR>( &capture))) {
			return 2 ;
		}

		const auto *plan = window.controller_.preparationPlan() ;	// 同scanの実元計画です。
		const auto	now	 = std::chrono::floor<std::chrono::seconds>(
			  // 実UTCです。
			  std::chrono::system_clock::now()) ;
		// 全対象を固定一recordに結合できない場合は通常dialogへ同意を送りません。
		if( !plan || plan->targets.size() != 1U || !approvedIntelTarget( plan->targets[0], now) ||
		   !IsWindowEnabled( window.preparationButton_)) {
			std::printf(
				"NORMAL_MAIN_WINDOW_ACQUIRE fixedTargetRejected=1 realPayloadAcquired=0 normalContentPositive=0\n") ;
			return 2 ;
		}

		const auto &target		= plan->targets[0] ;	// 同期確認中もcontrollerが保持する元対象です。
		unsigned	guardChecks = 1U ;					// 元targetの正例と各独立改変の拒否数です。
		unsigned	guardFailures{} ;					// 既存承認を広げた誤受理件数です。
		// 固定対象の各属性改変を独立に拒否し、元targetを変更しません。
		for( unsigned change = 0U; change < 9U; ++change) {
			auto changed	= target ;	// 一条件だけ変更する短命copyです。
			auto changedNow = now ;		// 期限の正負だけで変更する検証時計です。
			// Provider、record、規約全文・版、容量、件数、前提、期限を別々に確認します。
			switch( change) {
				// 別Providerへの承認流用を拒否します。
				case 0U:
					changed.providerId = L"other" ;
					break ;

				// 別配布recordへの承認流用を拒否します。
				case 1U:
					changed.releaseIdentity[0] = L'0' ;
					break ;

				// 新しいrevisionへの承認流用を拒否します。
				case 2U:
					changed.eulaRevision += L" changed" ;
					break ;

				// 同revisionでの本文差替えも拒否します。
				case 3U:
					changed.eulaText += L" " ;
					break ;

				// 異なる転送予算への承認流用を拒否します。
				case 4U:
					++changed.maximumBytes ;
					break ;

				// 未承認device集合の追加を拒否します。
				case 5U:
					++changed.deviceCount ;
					break ;

				// 新しい前提条件を包括承認しません。
				case 6U:
					changed.requiresPrerequisiteConfirmation = true ;
					break ;

				// 原観測より前の時計を有効へ補完しません。
				case 7U:
					changedNow = std::chrono::sys_seconds{} ;
					break ;

				// 元期限以降の再署名・再承認を許可しません。
				default:
					changedNow = now + std::chrono::days{1} ;
					break ;
			}

			++guardChecks ;
			guardFailures += approvedIntelTarget( changed, changedNow) ? 1U : 0U ;
		}

		std::printf( "APPROVED_TARGET_GUARDS checks=%u failures=%u\n", guardChecks, guardFailures) ;
		// Guard不合格では実取得を開始しません。
		if( guardFailures != 0U) {
			return 2 ;
		}

		ApprovedAcquisitionObservation observation ;	// 同UI threadで結果dialogまで生存します。
		observation.owner			  = window.window_ ;
		observation.target			  = target ;
		observation.title			  = window.loadString( IDS_PREPARATION_TITLE) ;
		observation.targetDetails	  = window.formatPreparationTarget( target, 0U) ;
		observation.finalConfirmation = window.formatResource( IDS_PREPARATION_CONFIRM, L"1") ;
		observation.resultText		  = &window.preparationResultText_ ;
		const auto capacities		  = std::to_wstring( plan->limits.maximumFileBytes) + L" / " +
								std::to_wstring( plan->limits.maximumProviderBytes) + L" / " +
								// 通常概要の元容量snapshotです。
								std::to_wstring( plan->limits.maximumSessionBytes) ;
		const auto counts = std::to_wstring( plan->limits.maximumProviderFiles) + L" / " +
							// 通常概要の元件数snapshotです。
							std::to_wstring( plan->limits.maximumSessionFiles) ;
		observation.overview = window.loadString( IDS_PREPARATION_INTRO) + L"\r\n\r\n" +
							   window.formatResource( IDS_PREPARATION_LIMITS, capacities) + L"\r\n" +
							   window.formatResource( IDS_PREPARATION_FILES, counts) ;
		observation.deadline		   = GetTickCount64() + 240000U ;
		const auto	   beforeOperation = window.controller_.activeOperationId() ;	// 元scan操作です。
		const UINT_PTR timer =
			// 実modal観測です。
			SetTimer( nullptr, 0, 100U, observeApprovedAcquisitionTimer) ;
		// 観測timerを作成できなければ実同意を送りません。
		if( timer == 0U) {
			return 2 ;
		}

		activeAcquisition = &observation ;
		// 通常button routingだけを使い、取得taskや承認DTOを直接送信しません。
		SendMessageW( window.window_, WM_COMMAND, MAKEWPARAM( IDC_PREPARATION, BN_CLICKED),
					 reinterpret_cast<LPARAM>( window.preparationButton_)) ;
		// 実worker通知を通常handlerへ配信し、取得・検査・結果dialogの終端を待ちます。
		while( window.controller_.state() == ApplicationState::PREPARING ||
			  window.controller_.state() == ApplicationState::CANCELLING_PREPARATION) {
			MSG message{} ;	// 同threadの実Window messageです。
			// 有限queueの既存通知を通常dispatchで消費します。
			while( PeekMessageW( &message, nullptr, 0, 0, PM_REMOVE)) {
				TranslateMessage( &message) ;
				DispatchMessageW( &message) ;
			}

			// 観測枠超過は協調取消しへ進み、同条件の取得を再起動しません。
			if( GetTickCount64() >= observation.deadline) {
				observation.failed = true ;
				// 元取得が実行中の場合だけ既存commandで取消要求を送ります。
				if( window.controller_.state() == ApplicationState::PREPARING) {
					window.handlePreparationCommand() ;
				}
			}

			std::this_thread::sleep_for( std::chrono::milliseconds{10}) ;
		}

		KillTimer( nullptr, timer) ;
		activeAcquisition = nullptr ;
		const auto &summary =
			window.indexPreparationSummary_ ;		// 通常UIが元結果と照合した実summaryです。
		std::size_t acquired{} ;					// 実取得成功の対象数です。request hop数ではありません。
		std::size_t contentPositive{} ;				// 入力hash結合と通常署名・閉包合格を持つ対象数です。
		std::size_t verifiedInfs{} ;				// 個別INFの通常内容合格数です。
		std::size_t published{} ;					// 同通常Treeへ追加された選択可能候補数です。
		std::size_t fixedSelectedInfCandidates{} ;	// 同原SHAの棚卸しでe2fnへ帰属したordinal16です。
		// 元一件の実取得と内容検査を別々に数え、失敗を成功で補完しません。
		for( const auto &item : summary.items) {
			acquired += item.acquisition == OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION &&
								item.acquisitionError == 0
							? 1U
							: 0U ;
			contentPositive += item.content == IndexedDriverInspectionState::INSPECTION_COMPLETED &&
									   item.contentError == 0 && item.inputBound &&
									   item.acceptedInfCount > 0U
								   ? 1U
								   : 0U ;
			verifiedInfs += item.acceptedInfCount ;
			std::printf(
				"NORMAL_MAIN_WINDOW_ACQUIRE_ITEM acquisition=%u acquisitionError=0x%08lx content=%u contentError=0x%08lx inputBound=%u files=%zu infs=%zu parsed=%zu signatureRejected=%zu accepted=%zu firstInfRejection=0x%08lx\n",
				static_cast<unsigned>( item.acquisition),
				static_cast<unsigned long>( item.acquisitionError),
				static_cast<unsigned>( item.content), static_cast<unsigned long>( item.contentError),
				static_cast<unsigned>( item.inputBound), item.inventoryFileCount, item.infCount,
				item.parsedInfCount, item.signatureRejectedInfCount, item.acceptedInfCount,
				static_cast<unsigned long>( item.firstInfRejection)) ;
		}

		// 同じ取得後監査に合格し、通常一覧に実表示された索引候補だけを数えます。
		for( std::size_t index = 0U; index < window.candidates_.size(); ++index) {
			const auto &candidate = window.candidates_[index] ;	// 通常handlerが受理した実候補です。
			const bool	displayed =
				candidate.providerId == SIGNED_INDEX_PROVIDER_ID && candidate.installable &&
				candidate.allContentCached &&
				candidate.audit.contentIntegrity == CandidateAuditGateState::PASSED &&
				candidate.audit.systemApplicability == CandidateAuditGateState::PASSED &&
				index < window.candidateItems_.size() &&
				window.candidateItems_[index] != nullptr ;	// 通常handlerが作った実Tree rowだけです。
			published += displayed ? 1U : 0U ;
			// 元実検査のopaque候補構造を診断にだけ読み、導入先や権限は組み立てません。
			if( displayed && candidate.identity.starts_with( L"index-candidate-")) {
				const auto last =
					// 元reference ordinalの境界です。
					candidate.identity.find_last_of( L'-') ;
				const auto prior = last != std::wstring::npos && last > 0U
									   ? candidate.identity.find_last_of( L'-', last - 1U)
									   : std::wstring::npos ;	// 元INF ordinal境界です。
				// 同SHA/sizeの実棚卸しと同じordinalと版だけを選択INF正例へ数えます。
				if( prior != std::wstring::npos && last != std::wstring::npos &&
				   candidate.identity.substr( prior + 1U, last - prior - 1U) == L"16" &&
				   candidate.version == L"2.1.5.7") {
					++fixedSelectedInfCandidates ;
				}
			}
		}

		const bool bytesDisplayed = window.preparationResultText_.find( window.formatResource(
										IDS_PREPARATION_ACTUAL, L"40477087")) !=
									std::wstring::npos ;	// 実転送結果の原表示です。
		const bool newOperation =
			summary.operationId > beforeOperation && summary.operationId ==
														 // 同取得操作への結合です。
														 window.controller_.activeOperationId() ;
		std::printf(
			"NORMAL_MAIN_WINDOW_ACQUIRE phases=%u exactTermsDisplayed=%u safeDefaults=%u resultDisplayed=%u failed=%u operationBound=%u resultItems=%zu realPayloadAcquired=%zu normalContentPositive=%zu verifiedInfs=%zu displayedCandidates=%zu fixedSelectedInfCandidates=%zu expectedBytesDisplayed=%u completed=%u total=%u install=0 restore=0 fake=0 networkException=0\n",
			observation.phase, static_cast<unsigned>( observation.exactTermsDisplayed),
			static_cast<unsigned>( observation.termsSafeDefaults),
			static_cast<unsigned>( observation.resultDisplayed),
			static_cast<unsigned>( observation.failed), static_cast<unsigned>( newOperation),
			summary.items.size(), acquired, contentPositive, verifiedInfs, published,
			fixedSelectedInfCandidates, static_cast<unsigned>( bytesDisplayed),
			window.preparationCompleted_, window.preparationTotal_) ;
		return !capture.failed && capture.completed == 1U && capture.forwarded == 1U &&
					   !observation.failed && observation.phase == 5U &&
					   observation.exactTermsDisplayed && observation.termsSafeDefaults &&
					   observation.resultDisplayed && newOperation && summary.items.size() == 1U &&
					   acquired == 1U && contentPositive == 1U && published > 0U &&
					   fixedSelectedInfCandidates == 1U && bytesDisplayed &&
					   window.preparationCompleted_ == 1U && window.preparationTotal_ == 1U
				   ? 0
				   : 2 ;
	}
} ;

} // namespace drivercrate

/** @brief 明示optionで通常scan・未同意取消または承認済み一対象の検査用取得を送ります。
 * @param[in] count 引数個数です。
 * @param[in] arguments 実process引数です。
 * @return 選んだ観測の合格0、取得・内容・候補等の不足2、起動拒否1です。
 */
int wmain( const int count, wchar_t **arguments)
{
	// Default起動や未知optionで実deviceを列挙しません。
	if( count != 2 ||
	   (std::wstring_view{arguments[1]} != L"--fixed-index-scan-only" &&
		std::wstring_view{arguments[1]} != L"--fixed-index-preparation-review-only" &&
		std::wstring_view{arguments[1]} != L"--fixed-index-acquire-approved-intel727998" &&
		std::wstring_view{arguments[1]} != L"--verify-acquisition-dialog-guards" &&
		std::wstring_view{arguments[1]} != L"--verify-worker-event-capture")) {
		return 1 ;
	}

	// 通常profileの旧optional artifactから取得・実inventoryを開始しません。
	if( std::wstring_view{arguments[1]} == L"--fixed-index-acquire-approved-intel727998" &&
	   (drivercrate::local_index_profile::ACQUISITION_KEYS.empty() ||
		drivercrate::local_index_profile::PUBLIC_FINGERPRINT !=
			"68ab95e96e45db00c62a241d733d29a2e347ef074949aec01293ed2ab024f18d")) {
		return 1 ;
	}

	INITCOMMONCONTROLSEX controls{} ;	// 通常画面と同じCommon Controlsです。
	controls.dwSize = sizeof( controls) ;
	controls.dwICC	= ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES ;
	// 初期化失敗ではworkerを開始しません。
	if( !InitCommonControlsEx( &controls)) {
		return 1 ;
	}

	// 表示照合の正負だけを実dialogで確認し、実workerやinventoryを生成しません。
	if( std::wstring_view{arguments[1]} == L"--verify-acquisition-dialog-guards") {
		return drivercrate::runDialogReadSelfCheck() ;
	}

	drivercrate::MainWindow window ;	// 通常constructor、通常workerを単独所有します。
	// 非表示Windowの作成失敗は実scan成功へ変換しません。
	if( !window.create( GetModuleHandleW( nullptr))) {
		return 1 ;
	}

	// 非通信自己検査は実scan前に終え、inventoryやHTTPを要求しません。
	if( std::wstring_view{arguments[1]} == L"--verify-worker-event-capture") {
		return drivercrate::MainWindowLiveIndexTestAccess::verifyWorkerCapture( window) ;
	}

	drivercrate::MainWindowLiveIndexTestAccess::begin( window) ;
	const auto deadline =
		// 有限read枠です。
		std::chrono::steady_clock::now() + std::chrono::seconds{120} ;
	// 実notificationを通常Win32 dispatchへ渡し、人工eventは作りません。
	while( drivercrate::MainWindowLiveIndexTestAccess::scanning( window)) {
		MSG message{} ;	// 同threadの通常Window messageです。
		// 有限queue内の実messageだけを通常handlerへ配信します。
		while( PeekMessageW( &message, nullptr, 0, 0, PM_REMOVE)) {
			TranslateMessage( &message) ;
			DispatchMessageW( &message) ;
		}

		// 観測枠超過でもprocessを強制終了せず、通常destructorの安全停止を待ちます。
		if( std::chrono::steady_clock::now() >= deadline) {
			std::printf( "NORMAL_MAIN_WINDOW_SCAN limitReached=1 normalContentPositive=0\n") ;
			return 2 ;
		}

		std::this_thread::sleep_for( std::chrono::milliseconds{10}) ;
	}

	// 同実scanの匿名観測と通常Tree focusの終端結果です。
	const int scan = drivercrate::MainWindowLiveIndexTestAccess::observeAndSelect( window) ;
	// 元scanの不足では規約操作へ進まず、同じ分母一件の失敗を保持します。
	if( scan != 0 || std::wstring_view{arguments[1]} == L"--fixed-index-scan-only") {
		return scan ;
	}

	return std::wstring_view{arguments[1]} == L"--fixed-index-acquire-approved-intel727998"
			   ? drivercrate::MainWindowLiveIndexTestAccess::acquireApproved( window)
			   : drivercrate::MainWindowLiveIndexTestAccess::observePreparationReview( window) ;
}
