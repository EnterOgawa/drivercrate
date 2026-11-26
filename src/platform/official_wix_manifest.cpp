//------------------------------------------------------------------------------
/**
 * @file official_wix_manifest.cpp
 * @brief 署名付きWiX v3マニフェストのコンテナーと内容役割の検査
 * @version 01.00.00
 * @date 2026/11/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/23  新規作成
 * </pre>
 *
 * @note 固定の名前空間と閉じた内容指定を使う。宣言の検査で同意、署名信頼、実行許可は発行しない
 * @see docs/adr/0572-signed-wix-burn-driver-content.md
 */
//------------------------------------------------------------------------------

#include "platform/official_wix_manifest.h"

#include "platform/com_raii.h"
#include "platform/official_catalog_validation.h"
#include "platform/official_download_workspace.h"

#include <Windows.h>

#include <algorithm>
#include <new>
#include <utility>

namespace drivercrate {
namespace {

using Microsoft::WRL::ComPtr ;

//------------------------------------------------------------------------------
// 定数定義
//------------------------------------------------------------------------------

constexpr std::size_t		MAXIMUM_XML_CHARACTERS		 = 65536U ;	// DOMへ渡す元XMLの文字数上限
constexpr long				MAXIMUM_PACKAGES			 = 32L ;	// 取り扱う全MSI宣言数
constexpr long				MAXIMUM_UX_MEMBERS			 = 64L ;	// 取り扱う起動用CABのPayload数
constexpr std::size_t		MAXIMUM_LICENSES			 = 16U ;	// 一配布の閲覧規約数
constexpr std::size_t		MAXIMUM_ATTRIBUTE_CHARACTERS = 256U ;	// 読み取る個別属性の上限
constexpr std::wstring_view WIX_NAMESPACE =
	L"xmlns:w='http://schemas.microsoft.com/wix/2008/Burn'" ;				// 固定XPath名前空間
constexpr NativeError INVALID = HRESULT_FROM_WIN32( ERROR_INVALID_DATA) ;	// 曖昧または不正な元宣言

//------------------------------------------------------------------------------
// 内部関数定義
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 検査失敗を診断値として同じ同期検査の呼出し元へ返す
 * @param[in] valid 元値または範囲の検査結果
 * @throws NativeError 構造や照合が成立しない場合
 */
//------------------------------------------------------------------------------
void				  require( const bool valid)
{
	// 元宣言が不明な場合は部分結果を公開せず停止する
	if( !valid) {
		throw INVALID ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief COMの失敗HRESULTを元値のまま検査の終端へ渡す
 * @param[in] result DOMの同期呼出し結果
 * @throws NativeError COMの失敗HRESULT
 */
//------------------------------------------------------------------------------
void check( const HRESULT result)
{
	// APIの失敗を単なる値の欠落へ置き換えない
	if( FAILED( result)) {
		throw static_cast<NativeError>( result) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 固定XPathの直下の該当ノードを件数上限付きで取得する
 * @param[in] parent 検証済みDOMの選択元
 * @param[in] xpath 呼出し側が固定したXPath。XMLの値を含めない
 * @param[in] maximum 許容件数。0は一件も許さない検査
 * @return 文書順の所有COMノード群
 * @throws NativeError XPathの失敗、上限超過または不正なノード群
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<ComPtr<IXMLDOMNode>> nodes( IXMLDOMNode			&parent,
													 const std::wstring_view xpath,
													 const long				 maximum)
{
	const UniqueBstr query( xpath) ;	// 同期呼出し中の固定XPath
	require( query.get() != nullptr) ;
	ComPtr<IXMLDOMNodeList> list ;	// 元DOMが返す順序付きの一致ノード一覧
	check( parent.selectNodes( query.get(), &list)) ;
	require( list != nullptr) ;
	long count{} ;	// 一覧内の総ノード数
	check( list->get_length( &count)) ;
	require( count >= 0L && count <= maximum) ;
	std::vector<ComPtr<IXMLDOMNode>> selected ;	// 元文書順を保つ返却値
	selected.reserve( static_cast<std::size_t>( count)) ;
	// 全ノードを有限件数内で読み、取得できない位置を読み飛ばさない
	for( long index = 0L; index < count; ++index) {
		ComPtr<IXMLDOMNode> node ;	// 今回の元ノード
		check( list->get_item( index, &node)) ;
		require( node != nullptr) ;
		selected.push_back( std::move( node)) ;
	}

	return selected ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一件必須の元ノードを取り出す
 * @param[in] parent 検証済みDOMの選択元
 * @param[in] xpath 呼出し側が固定したXPath
 * @return 一意に見つかった所有COMノード
 * @throws NativeError 欠落、重複またはCOMの失敗
 */
//------------------------------------------------------------------------------
[[nodiscard]] ComPtr<IXMLDOMNode> single( IXMLDOMNode &parent, const std::wstring_view xpath)
{
	auto matches = nodes( parent, xpath, 1L) ;	// 一件だけ受理する元ノード
	require( matches.size() == 1U) ;
	return std::move( matches.front()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元ノードの無修飾属性をASCIIの照合値として読む
 * @param[in] node 属性を読む元ノード
 * @param[in] xpath 無修飾属性を一つ指定する固定XPath
 * @return 文字数上限内の非空属性。元の大文字小文字と空白を保持する
 * @throws NativeError 欠落、非ASCII、制御文字、上限またはCOMエラー
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring attribute( IXMLDOMNode &node, const std::wstring_view xpath)
{
	const auto field = single( node, xpath) ;	// XMLが宣言した無修飾属性
	UniqueBstr raw ;							// COMが返す元UTF-16属性
	check( field->get_text( raw.put())) ;
	const auto length = SysStringLen( raw.get()) ;	// NUL終端に頼らない属性長
	require( length > 0U && length <= MAXIMUM_ATTRIBUTE_CHARACTERS) ;
	std::wstring value( raw.get(), length) ;	// 呼出し後も所有する照合値
	require( std::ranges::all_of(
		value, []( wchar_t character) { return character >= L' ' && character <= L'~' ; })) ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正の10進宣言値を桁数と上限内で読み取る
 * @param[in] value 元サイズ属性。符号、空白、先頭のゼロを許さない
 * @return 正の64-bit値。元の32-bit上限も確認する
 * @throws NativeError 数値表記または上限不正
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t byteCount( const std::wstring_view value)
{
	require( !value.empty() && value.size() <= 10U && value.front() != L'0') ;
	std::uint64_t count{} ;	// 10桁以内から切詰めずに求めるサイズ
	// 文字列の全体がASCII数字である場合だけ数値へ変換する
	for( const auto character : value) {
		require( character >= L'0' && character <= L'9') ;
		count = count * 10U + static_cast<std::uint64_t>( character - L'0') ;
	}

	require( count <= UINT32_MAX) ;
	return count ;
}

//------------------------------------------------------------------------------
/**
 * @brief ロケールに依存せずASCII大文字だけを小文字へ変換する
 * @param[in] value 元のASCII文字
 * @return 比較用の小文字。ASCII大文字以外は同じ値
 */
//------------------------------------------------------------------------------
[[nodiscard]] wchar_t lowerAscii( const wchar_t value) noexcept
{
	return value >= L'A' && value <= L'Z' ? static_cast<wchar_t>( value + (L'a' - L'A')) : value ;
}

//------------------------------------------------------------------------------
/**
 * @brief SHA-1の元宣言を40桁の小文字へ正規化する
 * @param[in] value 検査する40桁の元16進表記を所有する
 * @return 照合用小文字SHA-1。原本の信頼性は証明しない
 * @throws NativeError 桁数または16進表記不正
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring sha1Text( std::wstring value)
{
	require( value.size() == 40U) ;
	// ASCIIの16進文字以外を読み飛ばさず、大小の表記だけを揃える
	for( auto &character : value) {
		character = lowerAscii( character) ;
		require( (character >= L'0' && character <= L'9') ||
				(character >= L'a' && character <= L'f')) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 英数字とWiXで使用する区切り文字だけのIDを確認する
 * @param[in] value 元Payloadまたは条件にあるASCIIの識別子
 * @return 上限内の単純な識別子ならtrue
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool identifier( const std::wstring_view value) noexcept
{
	return !value.empty() && value.size() <= 96U &&
		   std::ranges::all_of( value, []( wchar_t character) {
			   const auto lower = lowerAscii( character) ;	// 大文字小文字に依存しない文字種
			   return (lower >= L'a' && lower <= L'z') || (lower >= L'0' && lower <= L'9') ||
					  character == L'_' || character == L'-' || character == L'.' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 指定したarchitectureに対応する元条件の閉じた表記を検証する
 * @param[in] package 読み取る全MSIのうちの一件の選択指定
 * @return 一つの識別子と既知のarchitecture条件だけから成る場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validCondition( const OfficialWixMsiSelector &package) noexcept
{
	// 指定範囲外のアーキテクチャ値から条件を組み立てない
	if( package.architecture != OfficialWixMsiArchitecture::AMD64 &&
	   package.architecture != OfficialWixMsiArchitecture::X86) {
		return false ;
	}

	const std::wstring_view suffix = package.architecture == OfficialWixMsiArchitecture::AMD64
										 ? L" AND VersionNT64"
										 : L" AND NOT VersionNT64" ;	// 完全一致のarchitecture部分
	return package.installCondition.ends_with( suffix) &&
		   identifier( package.installCondition.substr( 0U, package.installCondition.size() -
															  suffix.size())) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 起動用または添付CABの一つのPayloadを閉じた属性から読む
 * @param[in] node 元名前空間のPayloadノード
 * @param[in] container 添付CABの元ID。起動用CABでは空
 * @param[in] lead SourcePathが持つ元CAB別の先頭文字
 * @return 一件の元宣言。FilePathは展開先へ渡さない
 * @throws NativeError 未知属性、外部参照、名前、サイズ、ハッシュまたは階層の不成立
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialWixManifestMember payload( IXMLDOMNode			   &node,
												const std::wstring_view container,
												const wchar_t			lead)
{
	const long expectedAttributes = container.empty() ? 6L : 7L ;	// 署名文書の許可属性数
	require( nodes( node, L"@*", expectedAttributes).size() ==
			static_cast<std::size_t>( expectedAttributes)) ;
	static_cast<void>( nodes( node, L"*", 0L)) ;
	require( attribute( node, L"@Packaging") == L"embedded") ;
	// 添付側のPayloadを別コンテナーへ解決しない
	if( !container.empty()) {
		require( attribute( node, L"@Container") == container) ;
	}

	OfficialWixManifestMember member{
		attribute( node, L"@Id"), attribute( node, L"@SourcePath"), attribute( node, L"@FilePath"),
		// 元Payload
		byteCount( attribute( node, L"@FileSize")), sha1Text( attribute( node, L"@Hash"))} ;
	require( identifier( member.id) && member.cabinetMember.size() > 1U &&
			member.cabinetMember.front() == lead &&
			std::ranges::all_of( std::wstring_view{member.cabinetMember}.substr( 1U),
								[]( wchar_t digit) { return digit >= L'0' && digit <= L'9' ; }) &&
			isSafeOfficialArchiveMember( member.filePath, L'\\')) ;
	return member ;
}

//------------------------------------------------------------------------------
/**
 * @brief 内容指定が同じ元Payloadの三属性全体に一致するか確認する
 * @param[in] member マニフェストで確認した元Payload
 * @param[in] selector 呼出し側の審査済み内容指定
 * @return 大文字小文字を含めて三属性が一致する場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matches( const OfficialWixManifestMember &member,
						   const OfficialWixMemberSelector &selector) noexcept
{
	return member.id == selector.id && member.cabinetMember == selector.cabinetMember &&
		   member.filePath == selector.filePath ;
}

//------------------------------------------------------------------------------
/**
 * @brief PayloadのID、CAB名と論理パスの曖昧な重複を拒否する
 * @param[in] members 既に受理した同じコンテナーの元宣言
 * @param[in] member 次に追加する元宣言
 * @throws NativeError 同一のID、CAB名またはWindowsで衝突する論理名
 */
//------------------------------------------------------------------------------
void requireUnique( const std::vector<OfficialWixManifestMember> &members,
				   const OfficialWixManifestMember				&member)
{
	require( std::ranges::none_of( members, [&member]( const auto &previous) {
		return previous.id == member.id || previous.cabinetMember == member.cabinetMember ||
			   std::ranges::equal( previous.filePath, member.filePath, {}, lowerAscii, lowerAscii) ;
	})) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Chainと添付CABの全MSIが指定順で一対一に対応することを確認する
 * @param[in] root 期待名前空間のBurnManifest
 * @param[in] container 元の添付CAB ID
 * @param[in] packages 審査済みMSIの全選択指定
 * @return 同じ順序の全MSIの所有宣言
 * @throws NativeError 対応、属性、順序または参照が不一致
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<OfficialWixManifestMember> readPackages(
	IXMLDOMNode &root, const std::wstring_view container,
	const std::span<const OfficialWixMsiSelector> packages)
{
	const auto chain = single( root, L"w:Chain") ;	// 一つの元Chain
	static_cast<void>( nodes( *chain.Get(), L"@*[name() != 'DisableSystemRestore']", 0L)) ;
	static_cast<void>( nodes( *chain.Get(), L"*[not(self::w:MsiPackage)]", 0L)) ;
	const auto statements = nodes( *chain.Get(), L"w:MsiPackage", MAXIMUM_PACKAGES) ;	// 元Chain順
	const auto payloads	  = nodes( root, L"w:Payload", MAXIMUM_PACKAGES) ;				// 添付側元Payload順
	require( statements.size() == packages.size() && payloads.size() == packages.size()) ;
	std::vector<OfficialWixManifestMember> result ;	// 一対一対応を確認したMSI群
	// 元の全MSIを照合し、AMD64に関係しない行も除外してから検査を通さない
	for( std::size_t index = 0U; index < packages.size(); ++index) {
		const auto &selector = packages[index] ;									// 現在の元内容指定
		auto		member	 = payload( *payloads[index].Get(), container, L'a') ;	// 元のCAB名とSHA-1
		auto	   &statement = *statements[index].Get() ;							// 同じ順序の元Chain項目
		static_cast<void>( nodes(
			statement,
			L"@*[not(name()='Id' or name()='Cache' or name()='CacheId' or "
			L"name()='InstallSize' or name()='Size' or name()='PerMachine' or name()='Permanent' or "
			L"name()='Vital' or name()='RollbackBoundaryForward' or name()='RollbackBoundaryBackward' or "
			L"name()='LogPathVariable' or name()='RollbackLogPathVariable' or name()='InstallCondition' or "
			L"name()='ProductCode' or name()='Language' or name()='Version' or name()='DisplayInternalUI')]",
			0L)) ;
		require( matches( member, selector.member) && member.filePath.ends_with( L".msi") &&
				member.filePath.find( L'\\') == std::wstring::npos &&
				attribute( statement, L"@Id") == member.id &&
				attribute( statement, L"@InstallCondition") == selector.installCondition &&
				byteCount( attribute( statement, L"@Language")) == selector.language &&
				byteCount( attribute( statement, L"@Size")) == member.bytes) ;
		static_cast<void>( nodes(
			statement,
			L"*[not(self::w:MsiProperty or self::w:Provides or self::w:RelatedPackage or self::w:PayloadRef)]",
			0L)) ;
		const auto reference = single( statement, L"w:PayloadRef") ;	// 同じPayload以外を指せない参照
		require( nodes( *reference.Get(), L"@*", 1L).size() == 1U &&
				attribute( *reference.Get(), L"@Id") == member.id) ;
		static_cast<void>( nodes( *reference.Get(), L"*", 0L)) ;
		requireUnique( result, member) ;
		result.push_back( std::move( member)) ;
	}

	return result ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief WiX v3の元宣言と指定した全MSI・規約の対応を確認する
 * @param[in] xml 保護一時領域で読み取った元UTF-16マニフェスト。同期中だけ借用する
 * @param[in] packages 元Chainの順序で指定したMSI全件。AMD64を一件以上含む
 * @param[in] licenses 同意表示が必要な言語順の元規約指定。一件以上
 * @param[out] manifest 元宣言の構造が全て成立したときだけ設定する所有出力。失敗時は空
 * @return 成功時0、XML、選択指定、形式、境界またはCOMのエラー時はHRESULT
 * @pre 呼出しthreadでCOMを初期化する
 * @note 証明書、CAB・MSI・規約の実バイトの照合は別途必要。条件・設定・実行命令は評価しない
 */
//------------------------------------------------------------------------------
NativeError inspectOfficialWixManifest( const std::wstring_view							xml,
									   const std::span<const OfficialWixMsiSelector>	packages,
									   const std::span<const OfficialWixMemberSelector> licenses,
									   OfficialWixManifest							   &manifest)
{
	manifest = {} ;
	// 不明または未対応の指定から部分的な取得権限を生成しない
	if( packages.empty() || packages.size() > static_cast<std::size_t>( MAXIMUM_PACKAGES) ||
	   licenses.empty() || licenses.size() > MAXIMUM_LICENSES ||
	   !std::ranges::all_of( packages, validCondition) ||
	   std::ranges::none_of( packages, []( const auto &package) {
		   return package.architecture == OfficialWixMsiArchitecture::AMD64 ;
	   })) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	try {
		ComPtr<IXMLDOMDocument2> document ;	// 外部解決なしの共通DOM
		const auto load = loadOfficialXmlDocument( xml, {MAXIMUM_XML_CHARACTERS, WIX_NAMESPACE},
												  document) ;	// XMLおよびCOMの原診断
		// 共通XML検査で停止した理由をそのまま返す
		if( load != 0U) {
			return load ;
		}

		require( document != nullptr) ;
		const auto root = single( *document.Get(), L"/w:BurnManifest") ;	// 元形式だけの根ノード
		static_cast<void>(
			nodes( *root.Get(),
				  L"*[not(self::w:Log or self::w:RelatedBundle or "
				  L"self::w:Variable or self::w:UX or self::w:Container or self::w:Payload or "
				  L"self::w:RollbackBoundary or self::w:Registration or self::w:Chain)]",
				  0L)) ;
		const auto container = single( *root.Get(), L"w:Container") ;	// 一つだけの元添付CAB
		require( nodes( *container.Get(), L"@*", 7L).size() == 7U) ;
		static_cast<void>( nodes( *container.Get(), L"*", 0L)) ;
		const auto containerId = attribute( *container.Get(), L"@Id") ;	// 添付Payloadが指す元ID
		require( identifier( containerId) &&
				isSafeOfficialArchiveMember( attribute( *container.Get(), L"@FilePath"), L'\\') &&
				attribute( *container.Get(), L"@AttachedIndex") == L"1" &&
				attribute( *container.Get(), L"@Attached") == L"yes" &&
				attribute( *container.Get(), L"@Primary") == L"yes") ;

		OfficialWixManifest accepted ;	// 最後の照合まで呼出し元へ渡さない宣言
		accepted.attachedCabinetBytes = byteCount( attribute( *container.Get(), L"@FileSize")) ;
		accepted.attachedCabinetSha1  = sha1Text( attribute( *container.Get(), L"@Hash")) ;
		accepted.msiMembers			  = readPackages( *root.Get(), containerId, packages) ;
		const auto ux				  = single( *root.Get(), L"w:UX") ;	// 一つだけの起動用CAB宣言
		static_cast<void>( nodes( *ux.Get(), L"@*", 0L)) ;
		static_cast<void>( nodes( *ux.Get(), L"*[not(self::w:Payload)]", 0L)) ;
		// 起動側の全メンバー名を照合し、規約候補の重複に備える
		for( const auto &node : nodes( *ux.Get(), L"w:Payload", MAXIMUM_UX_MEMBERS)) {
			auto member = payload( *node.Get(), {}, L'u') ;	// 起動用CABの一件の元内容
			requireUnique( accepted.uxMembers, member) ;
			accepted.uxMembers.push_back( std::move( member)) ;
		}

		// 上位の同意契約が指定した言語ごとの原本を厳密に結ぶ
		for( const auto &selector : licenses) {
			const auto found =
				std::ranges::find_if( accepted.uxMembers, [&selector]( const auto &member) {
					return matches( member, selector) ;
				}) ; // 元三属性が同時に一致する規約
			require( found != accepted.uxMembers.end() && found->filePath.ends_with( L".rtf")) ;
			const auto index =
				// 規約の確定位置
				static_cast<std::size_t>( found - accepted.uxMembers.begin()) ;
			require( std::ranges::find( accepted.licenseIndices, index) ==
					accepted.licenseIndices.end()) ;
			accepted.licenseIndices.push_back( index) ;
		}

		manifest = std::move( accepted) ;
		return 0U ;
	} catch( const NativeError error) {
		return error ;
	} catch( const std::bad_alloc &) {
		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	}
}

} // namespace drivercrate
