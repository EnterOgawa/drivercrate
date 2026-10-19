//------------------------------------------------------------------------------
/**
 * @file indexed_driver_package_inspection.cpp
 * @brief 索引hintから通常共通検査への非導入結合を実装する。
 * @version 01.00.00
 * @date 2026/10/05
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/05  実identityと通常policyの再検査を追加。
 * </pre>
 *
 * @note File検査は既存共通層へ委譲する。全体失敗時は部分閉包を保持せず、外部取得・
 *       installer実行・staging・Windows設定変更は行わない。
 */
//------------------------------------------------------------------------------

#include "indexed_driver_package_inspection.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>

#include <new>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace drivercrate {
namespace {

constexpr std::uint64_t MAXIMUM_ARCHIVE_BYTES =
	128ULL * 1024ULL * 1024ULL ;	// 通常共通層と同じ入力上限。

/**
 * @brief 小文字64桁の非秘密hash参照だけを受理する。
 * @param[in] value 索引・record・archiveの識別hash。
 * @return 全桁がASCII小文字hexならtrue。
 */
bool isLowerHash( const std::wstring_view value) noexcept
{
	// 短縮・欠損hashを完全なidentityとして使わない。
	if( value.size() != 64U) {
		return false ;
	}

	// 文字列を正規化して別の索引参照を作らない。
	for( const wchar_t character : value) {
		// ASCII hex以外をschemaへ混入させない。
		if( !((character >= L'0' && character <= L'9') ||
			 (character >= L'a' && character <= L'f'))) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief 内部入力へnetwork・device path・ADSを混入させない。
 * @param[in] path 既存workspaceが所有するlocal drive上の絶対path。
 * @return Drive絶対構文と有限長を満たす場合true。
 * @note 保護store所有権の検証は呼出し側の既存取得／copy層が担当する。
 */
bool isLocalInputPath( const std::wstring_view path) noexcept
{
	return path.size() >= 4U && path.size() <= 32767U && path[1] == L':' && path[2] == L'\\' &&
		   ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
		   path.find( L':', 2U) == std::wstring_view::npos &&
		   path.find( L'\0') == std::wstring_view::npos ;
}

/**
 * @brief 全体失敗時の部分閉包を破棄し、入力結合の到達事実だけを残す。
 * @param[in,out] result 所有する通常検査結果を失う出力。
 * @param[in] state 失敗・取消しの終端段階。
 * @param[in] error 0ではない元HRESULT。
 * @return 入力の元HRESULT。
 */
NativeError fail( IndexedDriverPackageInspection &result, const IndexedDriverInspectionState state,
				 const NativeError error)
{
	result.inspection = {} ;
	result.state	  = state ;
	result.error	  = error ;
	return error ;
}

} // namespace

/** @see src/platform/indexed_driver_package_inspection.h 宣言側を正本とする。 */
bool matchesIndexedDriverArchiveHint( const ScanSessionId			   activeScanSessionId,
									 const IndexedDriverArchiveHint	  &hint,
									 const DriverArchiveInput		  &input,
									 const OfficialDriverArchiveFormat format) noexcept
{
	return activeScanSessionId != 0 && input.scanSessionId == activeScanSessionId &&
		   hint.archiveBytes > 0 && hint.archiveBytes <= MAXIMUM_ARCHIVE_BYTES &&
		   input.byteCount == hint.archiveBytes && isLowerHash( hint.indexSha256) &&
		   isLowerHash( hint.recordSha256) && isLowerHash( hint.archiveSha256) &&
		   input.sha256 == hint.archiveSha256 && isLocalInputPath( input.inspectionPath) &&
		   (format == OfficialDriverArchiveFormat::ZIP ||
			format == OfficialDriverArchiveFormat::CABINET) ;
}

/** @see src/platform/indexed_driver_package_inspection.h 宣言側を正本とする。 */
NativeError inspectIndexedDriverPackage( const ScanSessionId				  activeScanSessionId,
										const IndexedDriverArchiveHint	 &hint,
										const DriverArchiveInput		 &input,
										const OfficialDriverArchiveFormat format,
										IndexedDriverPackageInspection	 &result,
										const std::function<bool()>		 &cancellation)
{
	result = {} ;
	// 不一致hintではfile I/Oや取消しcallbackを開始しない。
	if( !matchesIndexedDriverArchiveHint( activeScanSessionId, hint, input, format)) {
		return fail( result, IndexedDriverInspectionState::INPUT_REJECTED,
					static_cast<NativeError>( E_INVALIDARG)) ;
	}

	try {
		// 事前取消しでは署名検査やfile I/Oを開始しない。
		if( cancellation && cancellation()) {
			return fail( result, IndexedDriverInspectionState::CANCELLED,
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
		}

		const NativeError identityError = verifyOfficialFileMetadata(
			input.inspectionPath, {hint.archiveBytes, hint.archiveSha256}) ;	// 実byteの共通再照合。
		// 呼出し側の文字列一致だけを実入力検査の成功としない。
		if( identityError != 0) {
			return fail( result, IndexedDriverInspectionState::INPUT_REJECTED, identityError) ;
		}

		result.inputBound = true ;
		CommonDriverPackageInspection inspection ;	// 通常の全体・個別結果を一時所有する。
		const NativeError			  inspectionError = inspectCommonDriverPackage(
			input, format, inspection, cancellation) ;	// 保守入口へfallbackしない。
		// 全体失敗では一部の内容合格を外へ持ち出さない。
		if( inspectionError != 0) {
			return fail( result,
						inspectionError ==
								static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))
							? IndexedDriverInspectionState::CANCELLED
							: IndexedDriverInspectionState::INSPECTION_FAILED,
						inspectionError) ;
		}

		// 合格閉包は同一通常policyで直前再検査する。個別拒否は保持する。
		for( const CommonInfInspection &inf : inspection.infs) {
			// 拒否済みINFを成功扱いで再検査へ渡さない。
			if( inf.state != CommonInfInspectionState::VERIFIED) {
				continue ;
			}

			// 各署名API前の取消しも全体結果へ反映する。
			if( cancellation && cancellation()) {
				return fail( result, IndexedDriverInspectionState::CANCELLED,
							static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
			}

			const NativeError error = reverifyCommonDriverInf( inf) ;	// 旧内容合格を再利用しない。
			// 参照や署名の変更は検査結果全体を失効させる。
			if( error != 0) {
				return fail( result, IndexedDriverInspectionState::INSPECTION_FAILED, error) ;
			}
		}

		// 最後の同期検査中に届いた取消しを取りこぼさない。
		if( cancellation && cancellation()) {
			return fail( result, IndexedDriverInspectionState::CANCELLED,
						static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))) ;
		}

		const NativeError finalError = verifyOfficialFileMetadata(
			input.inspectionPath,
			{hint.archiveBytes, hint.archiveSha256}) ;	// 公開直前の原入力照合。
		// 再検査の間に原入力が変わった場合は部分結果を破棄する。
		if( finalError != 0) {
			return fail( result, IndexedDriverInspectionState::INSPECTION_FAILED, finalError) ;
		}

		result.inspection = std::move( inspection) ;
		result.state	  = IndexedDriverInspectionState::INSPECTION_COMPLETED ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return fail( result, IndexedDriverInspectionState::INSPECTION_FAILED,
					static_cast<NativeError>( E_OUTOFMEMORY)) ;
	} catch( const std::length_error &) {
		return fail( result, IndexedDriverInspectionState::INSPECTION_FAILED,
					static_cast<NativeError>( E_INVALIDARG)) ;
	} catch( ...) {
		// 外部callback例外をworker外へ漏らさず、部分結果も残さない。
		return fail( result, IndexedDriverInspectionState::INSPECTION_FAILED,
					static_cast<NativeError>( E_UNEXPECTED)) ;
	}
}

} // namespace drivercrate
