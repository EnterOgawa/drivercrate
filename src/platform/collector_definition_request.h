//------------------------------------------------------------------------------
/**
 * @file collector_definition_request.h
 * @brief ローカル定義から渡す未認証の収集選択を定義します。
 * @version 01.03.00
 * @date 2026/11/04
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/04  未認証選択と同run metadata実数を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/11/04  通常runの公開family/OSと必須EULAの再照合を同取得へ追加。
 * Ver.01.02.00 Shunji Ogawa  2026/11/05  NVIDIA同release再確認の未認証hintを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/11/05  独立静的規約の原文書・公式リンクと既存同意を共通接続。
 * </pre>
 * @note 本DTOはHTTP結果・公式性・取得権限・導入権限を持ちません。
 * @see docs/adr/0435-definition-folder-collector-engine.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/collector_inspection_acquisition.h"
#include "platform/official_cdn_token.h"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace drivercrate {

/** @brief 定義に記述できる閉じたmetadata形式です。 */
enum class CollectorDefinitionProtocol {
	/// 実公開HTMLのanchorを再確認します。
	PUBLIC_LINK,
	/// 登録済みCatalog検索とdetails/downloadを再確認します。
	CATALOG_SEARCH,
	/// 既存Intel release parserを使用します。
	INTEL_RELEASE,
	/// 公開model情報とsession限定CDN解決を使用します。
	MODEL_CDN,
	/// NVIDIAの公開API query・同releaseと明示した独立規約を再確認します。
	NVIDIA_DRIVER_JSON,
} ;

/** @brief Python等が選んだ未認証候補であり、nativeが実metadataを再取得します。 */
struct CollectorDefinitionRequest {
	/// 未定義の整数値は拒否する閉形式です。
	CollectorDefinitionProtocol protocol{CollectorDefinitionProtocol::PUBLIC_LINK} ;
	/// 同じ公開起点と候補URLの未認証文字列です。
	CollectorInspectionSource	source ;
	/// Catalogの同じ公開検索で選択したupdate GUIDです。
	std::wstring				catalogUpdateId ;
	/// 同じ検索語から生成した公開検索URLです。
	std::wstring				catalogSearchUrl ;
	/// 同じupdate GUIDのdetails URLです。
	std::wstring				catalogDetailsUrl ;
	/// 同じupdate GUIDのdownload dialog URLです。
	std::wstring				catalogDownloadUrl ;
	/// 通常定義runが固定する同じ検索行の公開family条件です。空は従来APIのままです。
	std::vector<std::wstring>	catalogRequiredTitleTerms ;
	/// 同detailsの宣言対象OS。適用性は通常INF検査へ残します。
	std::vector<std::wstring>	catalogTargetOs ;
	/// 現定義snapshotへ明示同意した必須EULAの原revision。空は同要件なしです。
	std::wstring				expectedEulaRevision ;
	/// 同じ既存parserが返す原全文UTF-8のSHA-256。必須EULAでは空を許しません。
	std::wstring				expectedEulaTextSha256 ;
	/// 公表hashの未認証hint。nativeの原本文と再比較します。
	std::wstring				publishedSha256 ;
	/// Intel等が明示した公表SHA-512の未認証hintです。
	std::wstring				publishedSha512 ;
	/// 公開model/pathだけを持つsession解決の入力です。
	OfficialAnonymousCdnPlan	anonymousCdn ;
	/// 同queryで選択したNVIDIA公開download IDです。取得権限ではありません。
	std::wstring				nvidiaDownloadId ;
	/// NVIDIA原marketing版です。INF四要素版へ転用しません。
	std::wstring				nvidiaVersion ;
	/// strict共通codecで再検査する独立規約宣言JSONです。本文や同意証明ではありません。
	std::string					staticTermsJson ;
	/// 今回の正のpayload上限。最大2GiBです。
	std::uint64_t				maximumBytes{} ;
} ;

/** @brief API観測と独立規約の原HTTPを配布pageから分離します。 */
struct CollectorDefinitionStaticTermsObservation {
	/// 現在の規約原byte/リンク根拠へ更新した宣言です。元bootstrapを変更しません。
	std::string						   termsJson ;
	/// API形式だけの原metadata観測です。通常の静的pageでは空です。
	CollectorInspectionPageObservation apiPage ;
	/// 同runの規約原byte/hash/UTC/sizeです。
	CollectorInspectionPageObservation documentPage ;
} ;

/** @brief 同native取得で確認した非秘密metadata。取得証拠や通常logではありません。 */
struct CollectorDefinitionPublicMetadata {
	/// 認証queryを含まない元の公開URL集合です。
	CollectorInspectionSource								 source ;
	/// 実metadataと照合した公表SHA-256。未公表は空です。
	std::wstring											 publishedSha256 ;
	/// 実metadataと照合した公表SHA-512。未公表は空です。
	std::wstring											 publishedSha512 ;
	/// 同取得APIの既存parserで確認した必須EULA revisionです。
	std::wstring											 eulaRevision ;
	/// 同parserが返した原全文のUTF-8 SHA-256です。
	std::wstring											 eulaTextSha256 ;
	/// 独立規約profileだけの現在観測です。旧Intelでは空です。
	std::optional<CollectorDefinitionStaticTermsObservation> staticTerms ;
} ;

/** @brief 同じnative I/Oのmetadata実数。本文やURLを通常logへ渡しません。 */
struct CollectorDefinitionMetadataObservation {
	/// 実send直前まで到達したmetadata要求数です。
	std::uint32_t requests{} ;
	/// 同じmetadata I/Oが読んだ本文byte数です。
	std::uint64_t bodyBytes{} ;
	/// 最後のmetadata HTTP状態。未受信は0です。
	std::uint32_t httpStatus{} ;
} ;

} // namespace drivercrate
