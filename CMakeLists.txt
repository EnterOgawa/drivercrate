cmake_minimum_required(VERSION 3.28)

project(
    DriverCrate
    VERSION 0.1.0
    DESCRIPTION "Torrent-free Windows driver update manager"
    LANGUAGES C CXX RC
)

# 別shellからのbuildでも/showIncludesを同じ実在言語に固定する。既存launcherは内側に保持し、
# cacheを書き換えず、再configureでwrapperを重複させない。日本語だけのtoolchainでも
# 存在しない英語resourceを仮定せず、実compilerの接頭辞を毎configureで確認する。
if(MSVC AND CMAKE_GENERATOR MATCHES "Ninja")
    get_filename_component(drivercrate_compiler_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    file(GLOB drivercrate_compiler_languages
        RELATIVE "${drivercrate_compiler_directory}" "${drivercrate_compiler_directory}/*/clui.dll")
    set(drivercrate_compiler_language 1033)
    if(NOT EXISTS "${drivercrate_compiler_directory}/1033/clui.dll"
        AND drivercrate_compiler_languages)
        list(GET drivercrate_compiler_languages 0 drivercrate_compiler_resource)
        get_filename_component(drivercrate_compiler_language "${drivercrate_compiler_resource}" DIRECTORY)
    endif()
    set(ENV{VSLANG} "${drivercrate_compiler_language}")
    set(drivercrate_include_probe "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/DriverCrateShowIncludes")
    file(MAKE_DIRECTORY "${drivercrate_include_probe}")
    file(WRITE "${drivercrate_include_probe}/drivercrate_include_probe.h" "\n")
    file(WRITE "${drivercrate_include_probe}/main.c" "#include \"drivercrate_include_probe.h\"\n")
    execute_process(
        COMMAND "${CMAKE_CXX_COMPILER}" /nologo /showIncludes /EP /TC main.c
        WORKING_DIRECTORY "${drivercrate_include_probe}"
        OUTPUT_VARIABLE drivercrate_include_output
        ERROR_VARIABLE drivercrate_include_error
        RESULT_VARIABLE drivercrate_include_result
        ENCODING AUTO
    )
    if(NOT drivercrate_include_result EQUAL 0)
        message(FATAL_ERROR "MSVC include dependency probe failed: ${drivercrate_include_result}")
    endif()
    string(REGEX MATCH "(^|\n)([^\n]+: +)[A-Za-z]:[/\\\\]" drivercrate_include_match
        "${drivercrate_include_output}\n${drivercrate_include_error}")
    if(NOT drivercrate_include_match)
        message(FATAL_ERROR "MSVC include dependency prefix could not be detected.")
    endif()
    set(drivercrate_include_prefix "${CMAKE_MATCH_2}")
    # 日本語resourceの固定接頭辞は、CMakeのpipe／console文字コードの誤変換から分離する。
    # Compiler自身の応答確認を省かず、他の言語では実測した接頭辞をそのまま用いる。
    if(drivercrate_compiler_language STREQUAL "1041")
        set(drivercrate_include_prefix "メモ: インクルード ファイル: ")
    endif()
    foreach(drivercrate_language IN ITEMS C CXX)
        set(CMAKE_${drivercrate_language}_COMPILER_LAUNCHER
            "${CMAKE_COMMAND}" -E env "VSLANG=${drivercrate_compiler_language}"
            ${CMAKE_${drivercrate_language}_COMPILER_LAUNCHER}
        )
        set(CMAKE_${drivercrate_language}_CL_SHOWINCLUDES_PREFIX "${drivercrate_include_prefix}")
    endforeach()
    set(CMAKE_CL_SHOWINCLUDES_PREFIX "${drivercrate_include_prefix}")
endif()

if(NOT WIN32)
    message(FATAL_ERROR "DriverCrate supports Windows only.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "DriverCrate supports x64 builds only.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
# DriverCrate は C++ module を使用しない。MSVC/Ninja の module scanner に依存せず、通常の
# include dependency tracking で transitive header 変更を確実に再コンパイルする。
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)
include(FetchContent)
include(cmake/DriverCrateCompilerOptions.cmake)

option(
    DRIVERCRATE_ENABLE_ANALYZE
    "Enable MSVC static analysis for DriverCrate-owned source targets."
    OFF
)

# 撤去済みAI設定は黙って無視せず拒否し、OFFの旧cacheだけ除去する。
include(cmake/RejectRetiredAiOptions.cmake)
include(cmake/LocalIndexAcceptance.cmake)

# Dell Enterprise CatalogのGZipと公式ZIP packageの展開は、固定版・固定hashのminizを静的linkする。
# Application実行時に第三者DLLや外部展開toolを要求しない。MinizはC/C++両対応の
# sourceであり、DriverCrateのMSVC toolchainを一つに保つためC++として個別compileする。
FetchContent_Declare(
    miniz
    URL https://github.com/richgel999/miniz/archive/refs/tags/3.1.2.tar.gz
    URL_HASH SHA256=98468F8924934B723276680F85238B6C78BF1F8B49B4459CC9B7214A20E2E9FB
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    SOURCE_SUBDIR drivercrate-no-upstream-cmake
)
FetchContent_MakeAvailable(miniz)
set(drivercrate_miniz_sources
    ${miniz_SOURCE_DIR}/miniz.c
    ${miniz_SOURCE_DIR}/miniz_tdef.c
    ${miniz_SOURCE_DIR}/miniz_tinfl.c
    ${miniz_SOURCE_DIR}/miniz_zip.c
)
set_source_files_properties(${drivercrate_miniz_sources} PROPERTIES LANGUAGE CXX)
add_library(drivercrate_miniz STATIC ${drivercrate_miniz_sources})
include(GenerateExportHeader)
generate_export_header(
    drivercrate_miniz
    BASE_NAME miniz
    EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/generated/miniz_export.h
    STATIC_DEFINE MINIZ_STATIC_DEFINE
)
target_compile_definitions(drivercrate_miniz PUBLIC MINIZ_STATIC_DEFINE)
target_include_directories(
    drivercrate_miniz
    PUBLIC
        ${miniz_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/generated
)

# PE末尾7zの非実行展開に使用するLZMA SDKは、公式26.03 archiveとhashへ固定する。
# Archive内のsample、tool、SFX、precompiled binaryは実行・link・配布せず、C decoderの
# 必要sourceだけを第三者専用targetでCとしてcompileする。DriverCrate自作sourceの警告設定は
# このtargetへ流用せず、application側の/W4、/WXを維持する。
FetchContent_Declare(
    lzma_sdk
    URL https://github.com/ip7z/7zip/releases/download/26.03/lzma2603.7z
    URL_HASH SHA256=86C213F752520AB5325C310F50BEF63EC344B56DD1C80B0246D06DC6CEC953B2
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    SOURCE_SUBDIR drivercrate-no-upstream-cmake
)
FetchContent_MakeAvailable(lzma_sdk)
set(drivercrate_lzma_sdk_sources
    ${lzma_sdk_SOURCE_DIR}/C/7zArcIn.c
    ${lzma_sdk_SOURCE_DIR}/C/7zBuf.c
    ${lzma_sdk_SOURCE_DIR}/C/7zCrc.c
    ${lzma_sdk_SOURCE_DIR}/C/7zCrcOpt.c
    ${lzma_sdk_SOURCE_DIR}/C/7zDec.c
    ${lzma_sdk_SOURCE_DIR}/C/7zStream.c
    ${lzma_sdk_SOURCE_DIR}/C/Bcj2.c
    ${lzma_sdk_SOURCE_DIR}/C/Bra.c
    ${lzma_sdk_SOURCE_DIR}/C/Bra86.c
    ${lzma_sdk_SOURCE_DIR}/C/BraIA64.c
    ${lzma_sdk_SOURCE_DIR}/C/CpuArch.c
    ${lzma_sdk_SOURCE_DIR}/C/Delta.c
    ${lzma_sdk_SOURCE_DIR}/C/Lzma2Dec.c
    ${lzma_sdk_SOURCE_DIR}/C/LzmaDec.c
)
add_library(drivercrate_lzma_sdk STATIC ${drivercrate_lzma_sdk_sources})
target_compile_definitions(drivercrate_lzma_sdk PRIVATE Z7_EXTRACT_ONLY)
target_include_directories(drivercrate_lzma_sdk PUBLIC ${lzma_sdk_SOURCE_DIR}/C)
if(MSVC)
    target_compile_options(drivercrate_lzma_sdk PRIVATE /W3 /sdl)
endif()

# Windows Updateや公式vendorへ通信するread-only live testは、明示的に有効化した場合だけ生成する。
option(
    DRIVERCRATE_BUILD_LIVE_TESTS
    "Build read-only tests that contact Windows Update or official vendor services."
    OFF
)

# 収集用成果物は通信測定用testと独立して明示buildできるようにする。
option(
    DRIVERCRATE_BUILD_COLLECTOR
    "Build the collector and its manual setup preview independently of live tests."
    OFF
)

configure_file(
    cmake/DriverCrateVersion.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/drivercrate_version.h
    @ONLY
)

add_library(drivercrate_core STATIC
    src/core/candidate_audit.cpp
    src/core/candidate_assessment.cpp
    src/core/candidate_selection.cpp
    src/core/candidate_source_group.cpp
    src/core/device_observation.cpp
    src/core/local_coverage.cpp
    src/core/metadata_search.cpp
    src/core/metadata_search_report.cpp
    src/core/metadata_search_budget.cpp
    src/core/official_discovery.cpp
    src/core/official_discovery_execution.cpp
    src/core/official_discovery_planner.cpp
    src/core/scan_measurement.cpp
    src/core/official_driver_rank.cpp
    src/core/official_release_observation.cpp
    src/core/official_preparation.cpp
    src/core/official_preparation_operation.cpp
    src/core/official_preparation_audit.cpp
    src/core/official_source_policy.cpp
    src/core/operation_controller.cpp
    src/core/package_selection.cpp
    src/core/provider_registry.cpp
    src/core/protected_install.cpp
    src/core/update_provider.cpp
)
target_include_directories(drivercrate_core PUBLIC src)
drivercrate_apply_compiler_options(drivercrate_core)

add_library(drivercrate_platform STATIC
    src/platform/amd_catalog_parser.cpp
    src/platform/amd_update_provider.cpp
    src/platform/asix_catalog_parser.cpp
    src/platform/asix_preparation.cpp
    src/platform/asix_update_provider.cpp
    src/platform/asrock_catalog_parser.cpp
    src/platform/asrock_system_identity.cpp
    src/platform/asrock_update_provider.cpp
    src/platform/broadcom_catalog_parser.cpp
    src/platform/broadcom_update_provider.cpp
    src/platform/broadcom_preparation.cpp
    src/platform/asus_catalog_parser.cpp
    src/platform/asus_collector_target_assessment.cpp
    src/platform/local_collector_metadata_projection.cpp
    src/platform/local_collector_projected_executor.cpp
    src/platform/local_collector_metadata_codec.cpp
    src/platform/local_collector_projected_response.cpp
    src/platform/local_collector_projected_cache.cpp
    src/platform/local_collector_projected_json.cpp
    src/platform/asus_network_record_adapter.cpp
    src/platform/asus_driver_package_audit.cpp
    src/platform/official_driver_package_audit.cpp
    src/platform/official_prepared_audit_report.cpp
    src/platform/official_prepared_install.cpp
    src/platform/official_bound_preparation.cpp
    src/platform/asus_package_acquisition.cpp
    src/platform/asus_system_identity.cpp
    src/platform/asus_update_provider.cpp
    src/platform/composite_update_provider.cpp
    src/platform/common_driver_package.cpp
    src/platform/common_inf_plan.cpp
    src/platform/indexed_driver_package_inspection.cpp
    src/platform/metadata_search_runner.cpp
    src/platform/dell_catalog_parser.cpp
    src/platform/dell_server_catalog_parser.cpp
    src/platform/dell_server_catalog_source.cpp
    src/platform/dell_server_update_provider.cpp
    src/platform/dell_update_provider.cpp
    src/platform/driver_store_provider.cpp
    src/platform/generic_inf_package.cpp
    src/platform/hp_catalog_parser.cpp
    src/platform/hp_update_provider.cpp
    src/platform/intel_wireless_package.cpp
    src/platform/intel_wireless_package_provider.cpp
    src/platform/intel_ethernet_server_page_parser.cpp
    src/platform/intel_collector_identity_parser.cpp
    src/platform/intel_ethernet_windows11_record_adapter.cpp
    src/platform/intel_download_license_parser.cpp
    src/platform/prolific_serial_package.cpp
    src/platform/official_serial_provider.cpp
    src/platform/official_release_metadata.cpp
    src/platform/official_release_discovery_provider.cpp
    src/platform/official_release_preparation.cpp
    src/platform/official_release_local_probe.cpp
    src/platform/official_release_observation_store.cpp
    src/platform/official_record_resolution.cpp
    src/platform/official_record_payload_routing.cpp
    src/platform/official_static_record_parser.cpp
    src/platform/focusrite_download_page_parser.cpp
    src/platform/ricoh_universal_print_page_parser.cpp
    src/platform/wacom_driver_page_parser.cpp
    src/platform/silicon_labs_catalog_parser.cpp
    src/platform/wch_catalog_parser.cpp
    src/platform/silicon_labs_serial_package.cpp
    src/platform/wch_serial_package.cpp
    src/platform/intel_wireless_page_parser.cpp
    src/platform/intel_download_only_page.cpp
    src/platform/lenovo_catalog_parser.cpp
    src/platform/lenovo_update_provider.cpp
    src/platform/nvidia_catalog_parser.cpp
    src/platform/nvidia_update_provider.cpp
    src/platform/nvidia_winof2_catalog_parser.cpp
    src/platform/nvidia_winof2_driver_audit.cpp
    src/platform/nvidia_winof2_driver_package.cpp
    src/platform/nvidia_winof2_update_provider.cpp
    src/platform/official_cab.cpp
    src/platform/official_catalog_cache.cpp
    src/platform/official_catalog_validation.cpp
    src/platform/official_driver_closure.cpp
    src/platform/official_driver_package.cpp
    src/platform/inf_dependency_plan.cpp
    src/platform/inf_dependency_native.cpp
    src/platform/official_download_workspace.cpp
    src/platform/official_acquisition.cpp
    src/platform/collector_inspection_acquisition.cpp
    src/platform/official_record_utilities.cpp
    src/platform/official_download_grant.cpp
    src/platform/official_collector_public_text.cpp
    src/platform/official_delegated_package_inspection.cpp
    src/platform/official_discovery_inventory.cpp
    src/platform/official_discovery_cache.cpp
    src/platform/official_discovery_eula.cpp
    src/platform/official_discovery_package.cpp
    src/platform/official_discovery_provider_adapter.cpp
    src/platform/official_discovery_record_adapter.cpp
    src/platform/official_delegated_http_request.cpp
    src/platform/official_public_destination.cpp
    src/platform/official_collector_dns.cpp
    src/platform/secret_official_url.cpp
    src/platform/official_prepared_acquisition.cpp
    src/platform/official_file_verifier.cpp
    src/platform/official_gzip.cpp
    src/platform/official_http_client.cpp
    src/platform/official_html_terms.cpp
    src/platform/openpgp_signature_verifier.cpp
    src/platform/signed_index_manifest.cpp
    src/platform/signed_index_refresh.cpp
    src/platform/signed_index_asset_bytes.cpp
    src/platform/signed_index_records.cpp
    src/platform/signed_index_acquisition_adapter.cpp
    src/platform/signed_index_acquisition_descriptor_internal.cpp
    src/platform/signed_index_store.cpp
    src/platform/signed_index_record_lookup.cpp
    src/platform/signed_index_scan.cpp
    src/platform/signed_index_candidate_binding.cpp
    src/platform/official_msi.cpp
    src/platform/official_seven_zip.cpp
    src/platform/official_sfx.cpp
    src/platform/maintenance_embedded_file_table.cpp
    src/platform/official_zip.cpp
    src/platform/official_inf_archive_binding.cpp
    src/platform/official_pe_inf_extraction.cpp
    src/platform/official_inf_metadata_extraction.cpp
    src/platform/provider_worker.cpp
    src/platform/vaio_catalog_parser.cpp
    src/platform/vaio_update_provider.cpp
    src/platform/windows_restore_point_service.cpp
    src/platform/windows_product_type.cpp
    src/platform/windows_error.cpp
    src/platform/windows_update_provider.cpp
)
target_include_directories(drivercrate_platform
    PUBLIC src
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_link_libraries(drivercrate_platform
    PUBLIC
        drivercrate_core
    PRIVATE
        advapi32
        bcrypt
        cfgmgr32
        crypt32
        cryptxml
        drivercrate_lzma_sdk
        drivercrate_miniz
        msxml6
        msi
        shell32
        shlwapi
        userenv
        windowsapp
        winhttp
        wintrust
        ws2_32
        ole32
        oleaut32
        setupapi
        newdev
        normaliz
        wuguid
)
drivercrate_apply_compiler_options(drivercrate_platform)

add_executable(DriverCrate WIN32
    src/app/app.manifest
    src/app/app.rc
    src/app/assets/drivercrate.ico
    src/app/assets/drivercrate-icon-master.png
    src/app/main.cpp
    src/app/main_window.cpp
    src/app/main_window_preparation.cpp
    src/app/main_window_metadata_search.cpp
    src/app/main_window_assessment.cpp
)
# RC compilerのdependency出力にはICON fileが含まれないため、画像変更時にresourceを再構築する。
set_property(
    SOURCE src/app/app.rc
    APPEND
    PROPERTY OBJECT_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/app/assets/drivercrate.ico"
)
target_include_directories(DriverCrate PRIVATE src ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(DriverCrate
    PRIVATE
        drivercrate_core
        drivercrate_platform
        comdlg32
        comctl32
        dwmapi
        ole32
        setupapi
        uxtheme
)
drivercrate_apply_compiler_options(DriverCrate)
drivercrate_apply_linker_options(DriverCrate)
target_link_options(DriverCrate
    PRIVATE
        "SHELL:/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
)

# 実linkしたEXEとprofileを結合し、package入口でlocal buildを拒否する。
set_property(TARGET DriverCrate APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/RecordIndexBuildProfile.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/index_distribution_trust.h")
add_custom_command(TARGET DriverCrate POST_BUILD
    COMMAND "${CMAKE_COMMAND}" "-DEXECUTABLE=$<TARGET_FILE:DriverCrate>"
        "-DLOCAL_PROFILE=${DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE}"
        "-DDISTRIBUTION_FINGERPRINT=${drivercrate_distribution_fingerprint}"
        "-DACQUISITION_POLICY_REVISION=${drivercrate_distribution_acquisition_revision}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/RecordIndexBuildProfile.cmake"
    VERBATIM)

# 明示build/実行だけで旧storeを認証移動する。通常ALL/packageへ含めない。
add_executable(DriverCrateIndexStoreMigrator EXCLUDE_FROM_ALL
    src/app/index_store_migration_main.cpp src/app/app.manifest)
target_link_libraries(DriverCrateIndexStoreMigrator PRIVATE drivercrate_platform)
drivercrate_apply_compiler_options(DriverCrateIndexStoreMigrator)
drivercrate_apply_linker_options(DriverCrateIndexStoreMigrator)
target_link_options(DriverCrateIndexStoreMigrator PRIVATE
    "SHELL:/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")

if(DRIVERCRATE_BUILD_LOCAL_INDEX_SIGNER)
    # 明示操作だけで鍵を作る開発tool。通常本体・setup/packageには含めない。
    add_library(drivercrate_local_index_signing STATIC src/platform/local_index_signing.cpp)
    target_include_directories(drivercrate_local_index_signing PUBLIC src)
    target_link_libraries(drivercrate_local_index_signing PRIVATE drivercrate_platform ncrypt advapi32 crypt32)
    drivercrate_apply_compiler_options(drivercrate_local_index_signing)
    add_executable(DriverCrateLocalIndexSigner src/app/local_index_signing_main.cpp)
    target_include_directories(DriverCrateLocalIndexSigner PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_link_libraries(DriverCrateLocalIndexSigner PRIVATE drivercrate_local_index_signing drivercrate_platform)
    drivercrate_apply_compiler_options(DriverCrateLocalIndexSigner)
    drivercrate_apply_linker_options(DriverCrateLocalIndexSigner)
    if(BUILD_TESTING)
        add_executable(drivercrate_local_index_signing_tests tests/unit/local_index_signing_tests.cpp)
        target_include_directories(drivercrate_local_index_signing_tests PRIVATE src "${CMAKE_CURRENT_BINARY_DIR}/generated")
        target_link_libraries(drivercrate_local_index_signing_tests PRIVATE drivercrate_local_index_signing drivercrate_platform drivercrate_miniz)
        drivercrate_apply_compiler_options(drivercrate_local_index_signing_tests)
        drivercrate_apply_linker_options(drivercrate_local_index_signing_tests)
        # 既存keyだけを使う明示受入試験。CTest/CIからpersistent keyを作らない。
    endif()
endif()

if(BUILD_TESTING)
    target_compile_definitions(drivercrate_platform PRIVATE DRIVERCRATE_INTERNAL_INDEX_TESTS)
    add_executable(drivercrate_published_inf_identity_tests tests/unit/published_inf_identity_tests.cpp)
    target_link_libraries(drivercrate_published_inf_identity_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_published_inf_identity_tests)
    drivercrate_apply_linker_options(drivercrate_published_inf_identity_tests)
    add_test(NAME drivercrate_published_inf_identity_tests COMMAND drivercrate_published_inf_identity_tests)
    add_executable(drivercrate_official_html_terms_tests tests/unit/official_html_terms_tests.cpp)
    target_link_libraries(drivercrate_official_html_terms_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_official_html_terms_tests)
    drivercrate_apply_linker_options(drivercrate_official_html_terms_tests)
    add_test(NAME drivercrate_official_html_terms_tests COMMAND drivercrate_official_html_terms_tests)
    # 製品と同じWin32画面を非通信Providerと復旧fakeでだけ動かす。実行は明示option必須。
    # CTestも明示optionを渡し、製品の管理者manifestを継承しない内部UI試験専用targetとする。
    add_executable(drivercrate_metadata_ui_tests
        tests/ui/metadata_ui_tests.cpp
        # UI専用observer版が全定義を供給する。通常platformの同objectはこのEXEでlinkしない。
        # Services/class layoutは共通で、通常productへtarget固有macroを伝播させない。
        src/platform/signed_index_scan.cpp
        tests/support/metadata_ui_fixture.cpp
        tests/unit/signed_index_candidate_binding_tests.cpp
        src/app/main_window.cpp
        src/app/main_window_metadata_search.cpp
        src/app/main_window_preparation.cpp
        src/app/main_window_assessment.cpp
        src/app/app.rc
    )
    target_compile_definitions(drivercrate_metadata_ui_tests PRIVATE
        DRIVERCRATE_INTERNAL_UI_TESTS DRIVERCRATE_INTERNAL_INDEX_TESTS
        DRIVERCRATE_INTERNAL_INDEX_TASK_OBSERVER)
    target_include_directories(drivercrate_metadata_ui_tests
        PRIVATE src tests tests/unit ${CMAKE_CURRENT_BINARY_DIR}/generated
    )
    target_link_libraries(drivercrate_metadata_ui_tests PRIVATE
        drivercrate_core drivercrate_platform drivercrate_miniz
        comdlg32 comctl32 dwmapi ole32 setupapi uxtheme windowscodecs
    )
    drivercrate_apply_compiler_options(drivercrate_metadata_ui_tests)
    drivercrate_apply_linker_options(drivercrate_metadata_ui_tests)
    target_link_options(drivercrate_metadata_ui_tests PRIVATE
        # 既存独立objectとarchive選択の有限なlink証拠を標準出力へ保持する。
        /VERBOSE:LIB
        "SHELL:/MANIFESTUAC:\"level='asInvoker' uiAccess='false'\""
        "SHELL:/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\""
    )
    # 全modeは非通信Providerと復旧fakeだけを使う。長時間suiteを一processへ集約せず、
    # 元のdefaultと全依存modeを独立した有限CTestとして保持する。
    add_test(NAME drivercrate_metadata_ui_default_tests
        COMMAND drivercrate_metadata_ui_tests --run-ui-tests)
    set_tests_properties(drivercrate_metadata_ui_default_tests PROPERTIES
        RUN_SERIAL TRUE TIMEOUT 600 LABELS "ui;nonnetwork")
    foreach(drivercrate_ui_mode IN ITEMS close queue index binding multi unknown
            components needs extension formats preparation refresh)
        add_test(NAME drivercrate_metadata_ui_${drivercrate_ui_mode}_tests
            COMMAND drivercrate_metadata_ui_tests --run-ui-tests ${drivercrate_ui_mode})
        set_tests_properties(drivercrate_metadata_ui_${drivercrate_ui_mode}_tests PROPERTIES
            RUN_SERIAL TRUE TIMEOUT 600 LABELS "ui;nonnetwork")
    endforeach()

    add_executable(drivercrate_unit_tests
        tests/unit/signed_index_candidate_binding_tests.cpp
        tests/support/live_search_diagnostics.cpp
        tests/support/scan_measurement_diagnostics.cpp
        tests/unit/live_search_diagnostics_tests.cpp
        tests/unit/amd_catalog_parser_tests.cpp
        tests/unit/asix_catalog_parser_tests.cpp
        tests/unit/asrock_catalog_parser_tests.cpp
        tests/unit/asrock_system_identity_tests.cpp
        tests/unit/broadcom_official_provider_tests.cpp
        tests/unit/official_release_metadata_tests.cpp
        tests/unit/official_release_local_probe_tests.cpp
        tests/unit/official_release_observation_tests.cpp
        tests/unit/official_release_observation_store_tests.cpp
        tests/unit/official_preparation_tests.cpp
        tests/unit/official_prepared_acquisition_tests.cpp
        tests/unit/official_preparation_operation_tests.cpp
        tests/unit/prepared_audit_display_tests.cpp
        tests/unit/provider_preparation_worker_tests.cpp
        tests/unit/asus_catalog_parser_tests.cpp
        tests/unit/asus_system_identity_tests.cpp
        tests/unit/candidate_audit_tests.cpp
        tests/unit/official_workflow_evaluation_tests.cpp
        tests/unit/candidate_selection_tests.cpp
        tests/unit/candidate_source_group_tests.cpp
        tests/unit/dell_catalog_parser_tests.cpp
        tests/unit/dell_server_catalog_parser_tests.cpp
        tests/unit/hp_catalog_parser_tests.cpp
        tests/unit/intel_wireless_package_tests.cpp
        tests/unit/intel_ethernet_server_page_parser_tests.cpp
        tests/unit/intel_collector_identity_parser_tests.cpp
        tests/unit/intel_wireless_page_parser_tests.cpp
        tests/unit/intel_download_only_page_tests.cpp
        tests/unit/local_coverage_tests.cpp
        tests/unit/scan_measurement_diagnostics_tests.cpp
        tests/unit/scan_measurement_tests.cpp
        tests/unit/metadata_search_tests.cpp
        tests/unit/metadata_search_runner_tests.cpp
        tests/unit/metadata_search_budget_tests.cpp
        tests/unit/metadata_search_http_tests.cpp
        tests/unit/metadata_inventory_tests.cpp
        tests/unit/official_discovery_tests.cpp
        tests/unit/official_discovery_eula_tests.cpp
        tests/unit/official_discovery_provider_adapter_tests.cpp
        tests/unit/official_discovery_record_adapter_tests.cpp
        tests/unit/lenovo_catalog_parser_tests.cpp
        tests/unit/nvidia_catalog_parser_tests.cpp
        tests/unit/nvidia_winof2_catalog_parser_tests.cpp
        tests/unit/nvidia_winof2_driver_audit_tests.cpp
        tests/unit/nvidia_winof2_driver_package_tests.cpp
        tests/unit/official_acquisition_tests.cpp
        tests/unit/official_delegated_package_inspection_tests.cpp
        tests/unit/official_download_grant_tests.cpp
        tests/unit/official_driver_closure_tests.cpp
        tests/unit/official_driver_package_tests.cpp
        tests/unit/official_driver_rank_tests.cpp
        tests/unit/official_record_payload_routing_tests.cpp
        tests/unit/official_validation_tests.cpp
        tests/unit/official_gzip_tests.cpp
        tests/unit/official_msi_tests.cpp
        tests/unit/official_source_policy_tests.cpp
        tests/unit/official_seven_zip_tests.cpp
        tests/unit/official_sfx_tests.cpp
        tests/unit/maintenance_embedded_file_table_tests.cpp
        tests/unit/indexed_driver_package_inspection_tests.cpp
        tests/unit/official_zip_tests.cpp
        tests/unit/openpgp_signature_verifier_tests.cpp
        tests/unit/signed_index_manifest_tests.cpp
        tests/unit/signed_index_refresh_tests.cpp
        tests/unit/operation_controller_tests.cpp
        tests/unit/package_selection_tests.cpp
        tests/unit/provider_registry_tests.cpp
        tests/unit/protected_install_tests.cpp
        tests/unit/prolific_serial_package_tests.cpp
        tests/unit/prolific_official_provider_tests.cpp
        tests/unit/silicon_labs_official_provider_tests.cpp
        tests/unit/wch_official_provider_tests.cpp
        tests/unit/silicon_labs_serial_package_tests.cpp
        tests/unit/user_selected_inf_package_provider_tests.cpp
        tests/unit/wch_serial_package_tests.cpp
        tests/unit/test_main.cpp
        tests/unit/vaio_catalog_parser_tests.cpp
        tests/unit/windows_update_provider_tests.cpp
    )
    target_include_directories(drivercrate_unit_tests PRIVATE src tests tests/unit)
    target_compile_definitions(drivercrate_unit_tests PRIVATE DRIVERCRATE_INTERNAL_INDEX_TESTS)
    target_link_libraries(
        drivercrate_unit_tests
        PRIVATE
            drivercrate_miniz
            drivercrate_platform
			bcrypt
            crypt32
            msi
    )
    drivercrate_apply_compiler_options(drivercrate_unit_tests)

    target_include_directories(drivercrate_unit_tests PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
    add_test(NAME drivercrate_unit_tests COMMAND drivercrate_unit_tests)

    # 変更moduleの独立process gate。通常aggregateの限定optionを独立target合格へ数えない。
    add_executable(drivercrate_index_binding_tests
        tests/unit/test_main.cpp
        tests/unit/metadata_inventory_tests.cpp
        tests/unit/signed_index_manifest_tests.cpp
        tests/unit/signed_index_candidate_binding_tests.cpp
        tests/unit/official_acquisition_tests.cpp
        tests/unit/official_preparation_tests.cpp
        tests/unit/official_preparation_operation_tests.cpp
        tests/unit/official_prepared_acquisition_tests.cpp
        tests/unit/official_driver_rank_tests.cpp
        tests/unit/candidate_audit_tests.cpp
    )
    target_include_directories(drivercrate_index_binding_tests PRIVATE src tests tests/unit "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_compile_definitions(drivercrate_index_binding_tests PRIVATE
        DRIVERCRATE_INTERNAL_INDEX_TESTS DRIVERCRATE_INDEX_BINDING_STANDALONE)
    target_link_libraries(drivercrate_index_binding_tests PRIVATE
        drivercrate_miniz drivercrate_platform bcrypt crypt32 msi)
    drivercrate_apply_compiler_options(drivercrate_index_binding_tests)
    add_test(NAME drivercrate_index_binding_tests COMMAND drivercrate_index_binding_tests)

    # 既存架空INFと保守構造だけの有限回帰。実device・通信・導入を呼ばない。
    add_executable(drivercrate_maintenance_inf_structure_tests
        tests/unit/maintenance_inf_structure_main.cpp
        tests/unit/official_driver_package_tests.cpp)
    target_include_directories(drivercrate_maintenance_inf_structure_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_maintenance_inf_structure_tests PRIVATE drivercrate_platform drivercrate_miniz)
    drivercrate_apply_compiler_options(drivercrate_maintenance_inf_structure_tests)
    drivercrate_apply_linker_options(drivercrate_maintenance_inf_structure_tests)
    add_test(NAME drivercrate_maintenance_inf_structure_tests COMMAND drivercrate_maintenance_inf_structure_tests)
    set_tests_properties(drivercrate_maintenance_inf_structure_tests PROPERTIES TIMEOUT 120)

    # 署名／native応答だけをEXE内へ分離し、既存の閉包・保守射影本体をそのまま検証する。
    # PRIVATE定義はこのtargetだけに適用し、製品platform libraryと通常targetへ伝播させない。
    add_executable(drivercrate_maintenance_inf_integrity_tests
        tests/unit/maintenance_inf_integrity_tests.cpp
        tests/live/maintenance_reached_reference_observation.cpp
        src/platform/official_driver_closure.cpp
        src/platform/common_driver_package.cpp)
    # 必須unitは除外された旧研究directoryを入力にせず、writer leafの祖先だけをbuild内へ作る。
    # leaf自体の生成・reparse拒否・固定stem・CreateNew・個別cleanupは既存unit/writerが担当する。
    set(drivercrate_integrity_test_scratch
        "${CMAKE_CURRENT_BINARY_DIR}/test-scratch/maintenance-inf-integrity")
    file(MAKE_DIRECTORY "${drivercrate_integrity_test_scratch}")
    target_compile_definitions(drivercrate_maintenance_inf_integrity_tests PRIVATE
        DRIVERCRATE_MAINTENANCE_INTEGRITY_TESTING
        DRIVERCRATE_REACHED_REFERENCE_RESEARCH
        DRIVERCRATE_REACHED_WORKSPACE=L"${drivercrate_integrity_test_scratch}/reached-$<CONFIG>"
        DRIVERCRATE_RESIDUAL_WORKSPACE=L"${drivercrate_integrity_test_scratch}/residual-$<CONFIG>"
        verifyWindowsInfPackageIntegrity=verifyMaintenanceInfIntegrityForTest
        inspectNativeInfDependencies=inspectMaintenanceInfDependenciesForTest)
    target_include_directories(drivercrate_maintenance_inf_integrity_tests PRIVATE src tests/unit tests/live)
    target_link_libraries(drivercrate_maintenance_inf_integrity_tests PRIVATE drivercrate_platform drivercrate_miniz)
    drivercrate_apply_compiler_options(drivercrate_maintenance_inf_integrity_tests)
    drivercrate_apply_linker_options(drivercrate_maintenance_inf_integrity_tests)
    add_test(NAME drivercrate_maintenance_inf_integrity_tests COMMAND drivercrate_maintenance_inf_integrity_tests)
    set_tests_properties(drivercrate_maintenance_inf_integrity_tests PROPERTIES TIMEOUT 120)

    # 保存HTMLを明示引数で読む非通信smoke。ignored資料が必須なのでCTestへ自動登録しない。
    add_executable(drivercrate_intel_collector_saved_smoke
        tests/live/intel_collector_saved_page_smoke.cpp
    )
    target_include_directories(drivercrate_intel_collector_saved_smoke PRIVATE src)
    target_link_libraries(drivercrate_intel_collector_saved_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_intel_collector_saved_smoke)

    # 明示local ZIPの選択INF棚卸し。非通信・非導入であり実物入力をCTestへ登録しない。
    add_executable(drivercrate_selected_inf_inventory_smoke
        tests/live/selected_inf_inventory_smoke.cpp
    )
    target_include_directories(drivercrate_selected_inf_inventory_smoke PRIVATE src)
    target_link_libraries(drivercrate_selected_inf_inventory_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_selected_inf_inventory_smoke)
    drivercrate_apply_linker_options(drivercrate_selected_inf_inventory_smoke)

    # 保存済み公式byteで取得後全経路を再生する。実CAT/rankを維持し、CTestへ自動登録しない。
    add_executable(drivercrate_signed_index_publication_replay
        tests/live/signed_index_publication_replay.cpp)
    target_compile_definitions(drivercrate_signed_index_publication_replay PRIVATE
        DRIVERCRATE_INTERNAL_INDEX_TESTS)
    target_include_directories(drivercrate_signed_index_publication_replay PRIVATE
        src ${CMAKE_CURRENT_BINARY_DIR}/generated)
    target_link_libraries(drivercrate_signed_index_publication_replay PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_signed_index_publication_replay)
    drivercrate_apply_linker_options(drivercrate_signed_index_publication_replay)

    # 旧128節世代のbinaryを保持する、有限容量拡張後の独立非導入測定target。
    add_executable(drivercrate_inf_inventory_expanded_smoke
        tests/live/selected_inf_inventory_smoke.cpp
    )
    target_include_directories(drivercrate_inf_inventory_expanded_smoke PRIVATE src)
    target_link_libraries(drivercrate_inf_inventory_expanded_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_inventory_expanded_smoke)
    drivercrate_apply_linker_options(drivercrate_inf_inventory_expanded_smoke)

    # 中間512節世代も保持する、1,024節の最終有限上限の独立非導入測定target。
    add_executable(drivercrate_inf_inventory_large_smoke
        tests/live/selected_inf_inventory_smoke.cpp
    )
    target_include_directories(drivercrate_inf_inventory_large_smoke PRIVATE src)
    target_link_libraries(drivercrate_inf_inventory_large_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_inventory_large_smoke)
    drivercrate_apply_linker_options(drivercrate_inf_inventory_large_smoke)

    # 偽loaderだけを使う共通依存核試験。実INF・network・導入を呼ばない。
    add_executable(drivercrate_inf_dependency_tests tests/unit/inf_dependency_plan_tests.cpp)
    target_include_directories(drivercrate_inf_dependency_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_inf_dependency_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_tests)
    drivercrate_apply_linker_options(drivercrate_inf_dependency_tests)
    add_test(NAME drivercrate_inf_dependency_tests COMMAND drivercrate_inf_dependency_tests)

    # 架空の全証拠組合せ・差替えと確認計画の非実行境界を検証する独立target。
    add_executable(drivercrate_inf_dependency_review_boundary_tests
        tests/unit/inf_dependency_review_boundary_tests.cpp)
    target_include_directories(drivercrate_inf_dependency_review_boundary_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_inf_dependency_review_boundary_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_review_boundary_tests)
    drivercrate_apply_linker_options(drivercrate_inf_dependency_review_boundary_tests)
    add_test(NAME drivercrate_inf_dependency_review_boundary_tests COMMAND drivercrate_inf_dependency_review_boundary_tests)

    # 共通計画の独立fake内容境界。製品の通常検査をtest専用関数で置換しない。
    add_executable(drivercrate_common_inf_plan_tests tests/unit/common_inf_plan_tests.cpp)
    target_include_directories(drivercrate_common_inf_plan_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_common_inf_plan_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_common_inf_plan_tests)
    drivercrate_apply_linker_options(drivercrate_common_inf_plan_tests)
    add_test(NAME drivercrate_common_inf_plan_tests COMMAND drivercrate_common_inf_plan_tests)

    # 共通選択adapterの境界試験。実内容・Windows導入を当該EXEのfakeで代替する。
    add_executable(drivercrate_common_inf_batch_tests tests/unit/common_inf_batch_tests.cpp)
    target_include_directories(drivercrate_common_inf_batch_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_common_inf_batch_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_common_inf_batch_tests)
    drivercrate_apply_linker_options(drivercrate_common_inf_batch_tests)
    add_test(NAME drivercrate_common_inf_batch_tests COMMAND drivercrate_common_inf_batch_tests)

    # 旧発行試験EXEを保持しつつ、同じ86 assertionを現在のlibraryへ再linkして回帰確認する。
    add_executable(drivercrate_common_inf_factory_regression_tests tests/unit/common_inf_plan_tests.cpp)
    target_include_directories(drivercrate_common_inf_factory_regression_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_common_inf_factory_regression_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_common_inf_factory_regression_tests)
    drivercrate_apply_linker_options(drivercrate_common_inf_factory_regression_tests)
    add_test(NAME drivercrate_common_inf_factory_regression_tests COMMAND drivercrate_common_inf_factory_regression_tests)

    # 旧325項目EXEを保持し、同じfixtureへ34定義の実装範囲別試験を専用compile境界で追加する。
    add_executable(drivercrate_common_inf_contract_tests tests/unit/common_inf_batch_tests.cpp)
    target_compile_definitions(drivercrate_common_inf_contract_tests PRIVATE DRIVERCRATE_COMMON_INF_CONTRACT_TESTS=1)
    target_include_directories(drivercrate_common_inf_contract_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_common_inf_contract_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_common_inf_contract_tests)
    drivercrate_apply_linker_options(drivercrate_common_inf_contract_tests)
    add_test(NAME drivercrate_common_inf_contract_tests COMMAND drivercrate_common_inf_contract_tests)

    # 架空transportだけで取得証拠を検証する独立非通信target。
    add_executable(drivercrate_acquired_file_evidence_tests
        tests/unit/acquired_file_evidence_main.cpp tests/unit/official_acquisition_tests.cpp)
    target_include_directories(drivercrate_acquired_file_evidence_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_acquired_file_evidence_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_acquired_file_evidence_tests)
    drivercrate_apply_linker_options(drivercrate_acquired_file_evidence_tests)
    add_test(NAME drivercrate_acquired_file_evidence_tests COMMAND drivercrate_acquired_file_evidence_tests)

    # 封印取得から全INFへ結合するZIP／内側ZIPの独立非通信試験。
    add_executable(drivercrate_inf_archive_binding_tests tests/unit/official_inf_archive_binding_tests.cpp)
    target_include_directories(drivercrate_inf_archive_binding_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_inf_archive_binding_tests PRIVATE drivercrate_platform drivercrate_miniz)
    drivercrate_apply_compiler_options(drivercrate_inf_archive_binding_tests)
    drivercrate_apply_linker_options(drivercrate_inf_archive_binding_tests)
    add_test(NAME drivercrate_inf_archive_binding_tests COMMAND drivercrate_inf_archive_binding_tests)

    # 架空取得と専用compileの署名APIだけで、封印native接続を検証する。
    add_executable(drivercrate_acquired_inf_native_binding_tests
        tests/unit/official_inf_archive_binding_tests.cpp
        src/platform/inf_dependency_native.cpp)
    target_compile_definitions(drivercrate_acquired_inf_native_binding_tests PRIVATE
        DRIVERCRATE_INF_DEPENDENCY_TESTING DRIVERCRATE_ACQUIRED_INF_NATIVE_TESTING)
    target_include_directories(drivercrate_acquired_inf_native_binding_tests PRIVATE src tests tests/unit)
    target_link_libraries(drivercrate_acquired_inf_native_binding_tests PRIVATE drivercrate_platform drivercrate_miniz)
    drivercrate_apply_compiler_options(drivercrate_acquired_inf_native_binding_tests)
    drivercrate_apply_linker_options(drivercrate_acquired_inf_native_binding_tests)
    add_test(NAME drivercrate_acquired_inf_native_binding_tests COMMAND drivercrate_acquired_inf_native_binding_tests)

    # 明示local PEの原範囲と全INF抽出だけを測る。自動CTestや実通信に接続しない。
    add_executable(drivercrate_pe_inf_range_smoke tests/live/pe_inf_range_smoke.cpp)
    target_include_directories(drivercrate_pe_inf_range_smoke PRIVATE src)
    target_link_libraries(drivercrate_pe_inf_range_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_pe_inf_range_smoke)
    drivercrate_apply_linker_options(drivercrate_pe_inf_range_smoke)

    # 初回測定binaryを保持する診断補正世代。自動CTestや実通信に接続しない。
    add_executable(drivercrate_pe_inf_range_rechecked_smoke tests/live/pe_inf_range_smoke.cpp)
    target_include_directories(drivercrate_pe_inf_range_rechecked_smoke PRIVATE src)
    target_link_libraries(drivercrate_pe_inf_range_rechecked_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_pe_inf_range_rechecked_smoke)
    drivercrate_apply_linker_options(drivercrate_pe_inf_range_rechecked_smoke)

    # 明示local ZIPだけの独立測定器。自動CTest・live network testには登録しない。
    add_executable(drivercrate_acquired_inf_dependency_smoke tests/live/acquired_inf_dependency_smoke.cpp)
    target_include_directories(drivercrate_acquired_inf_dependency_smoke PRIVATE src)
    target_link_libraries(drivercrate_acquired_inf_dependency_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_acquired_inf_dependency_smoke)
    drivercrate_apply_linker_options(drivercrate_acquired_inf_dependency_smoke)

    # 旧測定binaryを保持する、研究ZIPの未認証入口と署名補助metadataの独立対照世代。
    add_executable(drivercrate_untrusted_inf_dependency_smoke tests/live/acquired_inf_dependency_smoke.cpp)
    target_compile_definitions(drivercrate_untrusted_inf_dependency_smoke PRIVATE DRIVERCRATE_UNTRUSTED_INF_PROBE)
    target_include_directories(drivercrate_untrusted_inf_dependency_smoke PRIVATE src)
    target_link_libraries(drivercrate_untrusted_inf_dependency_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_untrusted_inf_dependency_smoke)
    drivercrate_apply_linker_options(drivercrate_untrusted_inf_dependency_smoke)

    # Macroなしの旧分岐はobjectだけを新規compileし、旧測定EXEを上書きしない。
    add_executable(drivercrate_collector_inspection_tests tests/unit/collector_inspection_acquisition_tests.cpp)
    target_include_directories(drivercrate_collector_inspection_tests PRIVATE src)
    target_link_libraries(drivercrate_collector_inspection_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_collector_inspection_tests)
    drivercrate_apply_linker_options(drivercrate_collector_inspection_tests)
    add_test(NAME drivercrate_collector_inspection_tests COMMAND drivercrate_collector_inspection_tests)

    add_library(drivercrate_inf_dependency_legacy_compile_check OBJECT tests/live/acquired_inf_dependency_smoke.cpp)
    target_include_directories(drivercrate_inf_dependency_legacy_compile_check PRIVATE src)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_legacy_compile_check)

    # 封印所有者と同じ共通抽出APIの非実行実測。旧二十測定binaryを保持する。
    add_executable(drivercrate_common_inf_metadata_smoke tests/live/acquired_inf_dependency_smoke.cpp)
    target_compile_definitions(drivercrate_common_inf_metadata_smoke PRIVATE DRIVERCRATE_COMMON_INF_METADATA_PROBE)
    target_include_directories(drivercrate_common_inf_metadata_smoke PRIVATE src)
    target_link_libraries(drivercrate_common_inf_metadata_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_common_inf_metadata_smoke)
    drivercrate_apply_linker_options(drivercrate_common_inf_metadata_smoke)

    # 初回のhash用途誤りを記録した測定EXEも上書きせず、最終共有hashで再測定する。
    add_executable(drivercrate_common_inf_metadata_rechecked_smoke tests/live/acquired_inf_dependency_smoke.cpp)
    target_compile_definitions(drivercrate_common_inf_metadata_rechecked_smoke PRIVATE DRIVERCRATE_COMMON_INF_METADATA_PROBE)
    target_include_directories(drivercrate_common_inf_metadata_rechecked_smoke PRIVATE src)
    target_link_libraries(drivercrate_common_inf_metadata_rechecked_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_common_inf_metadata_rechecked_smoke)
    drivercrate_apply_linker_options(drivercrate_common_inf_metadata_rechecked_smoke)

    add_executable(drivercrate_inf_dependency_native_tests tests/unit/inf_dependency_native_tests.cpp)
    target_include_directories(drivercrate_inf_dependency_native_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_inf_dependency_native_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_native_tests)
    drivercrate_apply_linker_options(drivercrate_inf_dependency_native_tests)
    add_test(NAME drivercrate_inf_dependency_native_tests COMMAND drivercrate_inf_dependency_native_tests)

    # 同じadapterを専用compileする。製品platformに注入口を含めない。
    add_executable(drivercrate_inf_dependency_native_api_tests
        tests/unit/inf_dependency_native_api_tests.cpp
        tests/unit/official_driver_package_service_contract_tests.cpp
        src/platform/inf_dependency_native.cpp
    )
    target_compile_definitions(drivercrate_inf_dependency_native_api_tests PRIVATE DRIVERCRATE_INF_DEPENDENCY_TESTING)
    target_include_directories(drivercrate_inf_dependency_native_api_tests PRIVATE src tests tests/unit)
    target_link_libraries(drivercrate_inf_dependency_native_api_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_native_api_tests)
    drivercrate_apply_linker_options(drivercrate_inf_dependency_native_api_tests)
    add_test(NAME drivercrate_inf_dependency_native_api_tests COMMAND drivercrate_inf_dependency_native_api_tests)

    # 前世代の標準測定binary二つを保持する独立回帰世代。CTestへ登録しない。
    add_executable(drivercrate_inf_dependency_native_regression_smoke tests/unit/inf_dependency_native_tests.cpp)
    target_compile_definitions(drivercrate_inf_dependency_native_regression_smoke PRIVATE DRIVERCRATE_NATIVE_WINDOWS_PROBE)
    target_include_directories(drivercrate_inf_dependency_native_regression_smoke PRIVATE src tests/unit)
    target_link_libraries(drivercrate_inf_dependency_native_regression_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_native_regression_smoke)
    drivercrate_apply_linker_options(drivercrate_inf_dependency_native_regression_smoke)

    # CTestに登録せず明示optionでだけ標準INFを読む。旧測定targetは再構築しない。
    add_executable(drivercrate_inf_dependency_native_smoke tests/unit/inf_dependency_native_tests.cpp)
    target_compile_definitions(drivercrate_inf_dependency_native_smoke PRIVATE DRIVERCRATE_NATIVE_WINDOWS_PROBE)
    target_include_directories(drivercrate_inf_dependency_native_smoke PRIVATE src tests/unit)
    target_link_libraries(drivercrate_inf_dependency_native_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_native_smoke)
    drivercrate_apply_linker_options(drivercrate_inf_dependency_native_smoke)

    # 旧三世代のbinaryを保持する、参照元hash・有限不足だけの非導入測定世代。
    add_executable(drivercrate_inf_inventory_context_smoke tests/live/selected_inf_inventory_smoke.cpp)
    target_include_directories(drivercrate_inf_inventory_context_smoke PRIVATE src)
    target_compile_definitions(drivercrate_inf_inventory_context_smoke PRIVATE DRIVERCRATE_INF_CONTEXT_OUTPUT=1)
    target_link_libraries(drivercrate_inf_inventory_context_smoke PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_inventory_context_smoke)
    drivercrate_apply_linker_options(drivercrate_inf_inventory_context_smoke)

    # 実filesystemの架空台帳だけを使う非通信ACL試験。製品へlinkしない。
    add_executable(drivercrate_collector_state_tests
        tests/unit/local_collector_state_tests.cpp
        src/platform/local_collector_state_store.cpp
    )
    target_include_directories(drivercrate_collector_state_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_collector_state_tests PRIVATE advapi32 ole32)
    drivercrate_apply_compiler_options(drivercrate_collector_state_tests)
    drivercrate_apply_linker_options(drivercrate_collector_state_tests)
    add_test(NAME drivercrate_collector_state_tests COMMAND drivercrate_collector_state_tests)
    set_tests_properties(drivercrate_collector_state_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 30
    )

    # 公式networkを使わず、時計・HTTP注入によるrun再開を検査する開発fixture。
    add_executable(drivercrate_collector_run_tests
        tests/unit/local_driver_collector_tests.cpp
        src/platform/local_collector_http_control.cpp
        src/platform/local_collector_http_client.cpp
        src/platform/local_collector_projected_job.cpp
        src/platform/local_collector_projected_input.cpp
        src/platform/local_collector_projected_start.cpp
        src/platform/local_collector_http_observation.cpp
        src/platform/local_driver_collector.cpp
        src/platform/local_collector_campaign.cpp
        src/platform/local_collector_recovery.cpp
        src/platform/local_collector_state_store.cpp
    )
    target_include_directories(drivercrate_collector_run_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_collector_run_tests PRIVATE drivercrate_platform ole32 normaliz)
    drivercrate_apply_compiler_options(drivercrate_collector_run_tests)
    drivercrate_apply_linker_options(drivercrate_collector_run_tests)
    add_test(NAME drivercrate_collector_run_tests COMMAND drivercrate_collector_run_tests)
    set_tests_properties(drivercrate_collector_run_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 30
    )

    # 非通信campaign core。共有予算と二file保存窓を実filesystemの架空台帳で検査する。
    add_executable(drivercrate_collector_campaign_tests
        tests/unit/local_collector_campaign_tests.cpp
        tests/unit/local_collector_projected_recovery_tests.cpp
        tests/unit/local_collector_projected_json_tests.cpp
        tests/unit/local_collector_metadata_codec_tests.cpp
        tests/unit/local_collector_projected_response_tests.cpp
        tests/unit/local_collector_projected_cache_tests.cpp
        src/platform/local_collector_projected_storage_rules.cpp
        src/platform/local_collector_projected_job.cpp
        src/platform/local_collector_projected_input.cpp
        src/platform/local_collector_projected_start.cpp
        src/platform/local_collector_http_observation.cpp
        tests/unit/local_collector_http_tests.cpp
        tests/unit/local_collector_executor_tests.cpp
        src/platform/local_collector_http_control.cpp
        src/platform/local_collector_http_client.cpp
        src/platform/local_collector_executor.cpp
        src/platform/local_collector_campaign.cpp
        src/platform/local_collector_recovery.cpp
        src/platform/local_driver_collector.cpp
        src/platform/local_collector_state_store.cpp
        src/platform/local_collector_collection_store.cpp
        src/platform/local_collector_shared_store.cpp
        src/platform/local_collector_segment_inventory.cpp
        src/platform/local_collector_segment_preparation.cpp
        src/platform/local_collector_segment_storage.cpp
        src/platform/local_collector_segment_recovery.cpp
        src/platform/local_collector_segment_read.cpp
        src/platform/local_collector_segment_switch.cpp
        src/platform/local_collector_shared_operation.cpp
        src/platform/local_collector_shared_update.cpp
        src/platform/local_collector_shared_ledger.cpp
    )
    target_include_directories(drivercrate_collector_campaign_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_collector_campaign_tests PRIVATE drivercrate_platform ole32 normaliz)
    drivercrate_apply_compiler_options(drivercrate_collector_campaign_tests)
    drivercrate_apply_linker_options(drivercrate_collector_campaign_tests)
    # 従来の基本fixtureを重複・省略せず二分し、各CTestの有限300秒枠を維持する。
    add_test(NAME drivercrate_collector_campaign_tests
        COMMAND drivercrate_collector_campaign_tests --without-projected-http)
    set_tests_properties(drivercrate_collector_campaign_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        # 全完了履歴の原byte再照合を含む有限非通信suite。製品のHTTP期限とは独立。
        TIMEOUT 300
    )
    add_test(NAME drivercrate_collector_projected_http_tests
        COMMAND drivercrate_collector_campaign_tests --projected-http-only)
    # 保護rawからの完了封印だけを旧分母へ重複させず独立検査する。
    add_test(NAME drivercrate_collector_completed_inventory_tests
        COMMAND drivercrate_collector_campaign_tests --completed-inventory-only)
    # 同親historyのv3保存と個別readerだけ。共有値一致・区間sealの合格ではありません。
    add_test(NAME drivercrate_collector_history_layout_v3_tests
        COMMAND drivercrate_collector_campaign_tests --history-layout-v3-only)
    set_tests_properties(drivercrate_collector_history_layout_v3_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 120)
    # 値一致と同時借用の区間根拠を既存個別readerの分母から分離します。
    add_test(NAME drivercrate_collector_segment_inventory_tests
        COMMAND drivercrate_collector_campaign_tests --segment-inventory-only)
    set_tests_properties(drivercrate_collector_segment_inventory_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # ROOT未保存の全69prefixと旧全raw改変を独立枠で測り、既存期限を変更しません。
    add_test(NAME drivercrate_collector_segment_preparation_recovery_tests
        COMMAND drivercrate_collector_campaign_tests --segment-preparation-recovery-only)
    set_tests_properties(drivercrate_collector_segment_preparation_recovery_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 600)
    # 全能力解放後の実handle回復をbyte codecの分母と分けます。
    add_test(NAME drivercrate_collector_segment_recovery_storage_tests
        COMMAND drivercrate_collector_campaign_tests --segment-recovery-storage-only)
    set_tests_properties(drivercrate_collector_segment_recovery_storage_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 初回readyのbyte codecだけの枠。実handle・能力発行を合格へ含めません。
    add_test(NAME drivercrate_collector_segment_read_context_tests
        COMMAND drivercrate_collector_campaign_tests --segment-read-context-only)
    set_tests_properties(drivercrate_collector_segment_read_context_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # byte codecの分母は実handle readerと重複加算しません。
    add_test(NAME drivercrate_collector_segment_initial_read_codec_tests
        COMMAND drivercrate_collector_campaign_tests --segment-initial-read-codec-only)
    set_tests_properties(drivercrate_collector_segment_initial_read_codec_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 既存回復codecを初回読取りcodecの分母から分けます。
    add_test(NAME drivercrate_collector_segment_recovery_codec_tests
        COMMAND drivercrate_collector_campaign_tests --segment-recovery-codec-only)
    set_tests_properties(drivercrate_collector_segment_recovery_codec_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 親head保存だけの枠。固定記録からの再起動回復とは分離します。
    add_test(NAME drivercrate_collector_parent_head_storage_tests
        COMMAND drivercrate_collector_campaign_tests --parent-head-storage-only)
    set_tests_properties(drivercrate_collector_parent_head_storage_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 専用初期ROOTの実保存だけの枠。親head・再起動回復には数えません。
    add_test(NAME drivercrate_collector_initial_root_storage_tests
        COMMAND drivercrate_collector_campaign_tests --initial-root-storage-only)
    set_tests_properties(drivercrate_collector_initial_root_storage_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 私有新子の69準備保存だけの枠。ROOT／head・再起動回復には数えません。
    add_test(NAME drivercrate_collector_new_segment_storage_tests
        COMMAND drivercrate_collector_campaign_tests --new-segment-storage-only)
    set_tests_properties(drivercrate_collector_new_segment_storage_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 固定切替準備の実保存だけの枠。新子／head切替・再起動回復には数えません。
    add_test(NAME drivercrate_collector_segment_preparation_storage_tests
        COMMAND drivercrate_collector_campaign_tests --segment-preparation-storage-only)
    set_tests_properties(drivercrate_collector_segment_preparation_storage_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 同親handle保持・固定role先払いの非保存枠。実保存の合格へ流用しません。
    add_test(NAME drivercrate_collector_segment_storage_tests
        COMMAND drivercrate_collector_campaign_tests --segment-storage-only)
    set_tests_properties(drivercrate_collector_segment_storage_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 実HTTP所有閉鎖の専用枠。保存・CLI接続の合格には数えません。
    add_test(NAME drivercrate_collector_http_quiescence_tests
        COMMAND drivercrate_collector_campaign_tests --http-quiescence-only)
    set_tests_properties(drivercrate_collector_http_quiescence_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 実根拠からの非保存準備だけを独立枠へ分離します。切替保存の試験ではありません。
    add_test(NAME drivercrate_collector_segment_preparation_tests
        COMMAND drivercrate_collector_campaign_tests --segment-preparation-only)
    set_tests_properties(drivercrate_collector_segment_preparation_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    set_tests_properties(drivercrate_collector_completed_inventory_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    set_tests_properties(drivercrate_collector_projected_http_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300
    )
    # 旧二枠を変更せず、未応答次世代の新規fixtureだけを非重複で追加する。
    add_test(NAME drivercrate_collector_next_recovery_tests
        COMMAND drivercrate_collector_campaign_tests --next-recovery-only)
    # 部分開始の保存窓は旧三収集CTestへ重複せず、同じ有限枠で観測します。
    add_test(NAME drivercrate_collector_partial_start_tests
        COMMAND drivercrate_collector_campaign_tests --partial-start-only)
    set_tests_properties(drivercrate_collector_partial_start_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 全完了からの日次切替だけを旧四収集枠へ重複せず追加する。
    add_test(NAME drivercrate_collector_day_roll_tests
        COMMAND drivercrate_collector_campaign_tests --day-roll-only)
    set_tests_properties(drivercrate_collector_day_roll_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 末尾完了保存窓だけを旧五収集枠へ重複せず追加する。
    add_test(NAME drivercrate_collector_finish_recovery_tests
        COMMAND drivercrate_collector_campaign_tests --finish-recovery-only)
    set_tests_properties(drivercrate_collector_finish_recovery_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 正常300世代と301開始拒否だけを旧六収集枠へ重複せず追加する。
    add_test(NAME drivercrate_collector_generation_boundary_tests
        COMMAND drivercrate_collector_campaign_tests --generation-boundary-only)
    set_tests_properties(drivercrate_collector_generation_boundary_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 本番二世代と未受領予約の基礎履歴は旧七収集枠へ重複させない。
    add_test(NAME drivercrate_collector_operation_history_tests
        COMMAND drivercrate_collector_campaign_tests --operation-history-only)
    set_tests_properties(drivercrate_collector_operation_history_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 合成299操作と本番未受領一枠の上限だけを独立の有限枠で検査する。
    add_test(NAME drivercrate_collector_operation_capacity_tests
        COMMAND drivercrate_collector_campaign_tests --operation-capacity-only)
    set_tests_properties(drivercrate_collector_operation_capacity_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 新requestの通常受領・未受領二枠復旧だけを独立の有限枠で検査する。
    add_test(NAME drivercrate_collector_cache_growth_tests
        COMMAND drivercrate_collector_campaign_tests --cache-growth-only)
    set_tests_properties(drivercrate_collector_cache_growth_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 大量新requestの合成全完了履歴を、上限を変えず固定段階だけで測る。
    add_test(NAME drivercrate_collector_cache_capacity_tests
        COMMAND drivercrate_collector_campaign_tests --cache-capacity-only)
    set_tests_properties(drivercrate_collector_cache_capacity_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)
    # 同じ四要求の全完了世代の厳密境界と、通常起動の非変更を別枠で検査する。
    add_test(NAME drivercrate_collector_cache_startup_tests
        COMMAND drivercrate_collector_campaign_tests --cache-startup-only)
    set_tests_properties(drivercrate_collector_cache_startup_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        # 八回の全履歴起動を含む独立枠。旧300秒枠と製品期限は維持する。
        TIMEOUT 600)
    set_tests_properties(drivercrate_collector_next_recovery_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300
    )

    # 新modeのpure共有台帳だけを検査する独立fixture。旧campaign／本体へ接続しない。
    add_executable(drivercrate_collector_shared_ledger_tests
        tests/unit/local_collector_shared_ledger_tests.cpp
        src/platform/local_collector_shared_ledger.cpp
        src/platform/local_collector_campaign.cpp
        src/platform/local_collector_state_store.cpp
    )
    target_include_directories(drivercrate_collector_shared_ledger_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_collector_shared_ledger_tests PRIVATE drivercrate_platform ole32 normaliz)
    drivercrate_apply_compiler_options(drivercrate_collector_shared_ledger_tests)
    drivercrate_apply_linker_options(drivercrate_collector_shared_ledger_tests)
    add_test(NAME drivercrate_collector_shared_ledger_tests
        COMMAND drivercrate_collector_shared_ledger_tests)
    set_tests_properties(drivercrate_collector_shared_ledger_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 120)

    # 親／子保護storeだけの実filesystem fixture。実HTTP・本体・共有commitへ接続しない。
    add_executable(drivercrate_collector_collection_store_tests
        tests/unit/local_collector_collection_store_tests.cpp
        src/platform/local_collector_collection_store.cpp
        src/platform/local_collector_state_store.cpp
    )
    target_include_directories(drivercrate_collector_collection_store_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_collector_collection_store_tests PRIVATE advapi32 ole32)
    drivercrate_apply_compiler_options(drivercrate_collector_collection_store_tests)
    drivercrate_apply_linker_options(drivercrate_collector_collection_store_tests)
    add_test(NAME drivercrate_collector_collection_store_tests
        COMMAND drivercrate_collector_collection_store_tests)
    set_tests_properties(drivercrate_collector_collection_store_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 120)

    # 同親history配置の分母を無引数の旧collection fixtureから分離します。
    add_test(NAME drivercrate_collector_history_layout_tests
        COMMAND drivercrate_collector_collection_store_tests --history-layout)
    set_tests_properties(drivercrate_collector_history_layout_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 120)

    # 初回66本文の実保存／136 atomic保存後停止だけ。旧CLI・通常更新・通信へ接続しない。
    add_executable(drivercrate_collector_shared_store_tests
        tests/unit/local_collector_shared_store_tests.cpp
        src/platform/local_collector_shared_store.cpp
        src/platform/local_collector_shared_operation.cpp
        src/platform/local_collector_shared_update.cpp
        src/platform/local_collector_shared_ledger.cpp
        src/platform/local_collector_collection_store.cpp
        src/platform/local_collector_campaign.cpp
        src/platform/local_collector_state_store.cpp
    )
    target_include_directories(drivercrate_collector_shared_store_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_collector_shared_store_tests PRIVATE drivercrate_platform ole32 normaliz)
    drivercrate_apply_compiler_options(drivercrate_collector_shared_store_tests)
    drivercrate_apply_linker_options(drivercrate_collector_shared_store_tests)
    add_test(NAME drivercrate_collector_shared_store_tests COMMAND drivercrate_collector_shared_store_tests)
    set_tests_properties(drivercrate_collector_shared_store_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)

    # 同親の読取り共有根拠だけを独立検査します。ROOT／switch／通信を許可しません。
    add_executable(drivercrate_collector_shared_inventory_tests
        tests/unit/local_collector_shared_inventory_tests.cpp
        src/platform/local_collector_shared_store.cpp
        src/platform/local_collector_shared_operation.cpp
        src/platform/local_collector_shared_update.cpp
        src/platform/local_collector_shared_ledger.cpp
        src/platform/local_collector_collection_store.cpp
        src/platform/local_collector_campaign.cpp
        src/platform/local_collector_state_store.cpp
    )
    target_include_directories(drivercrate_collector_shared_inventory_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_collector_shared_inventory_tests PRIVATE drivercrate_platform ole32 normaliz)
    drivercrate_apply_compiler_options(drivercrate_collector_shared_inventory_tests)
    drivercrate_apply_linker_options(drivercrate_collector_shared_inventory_tests)
    add_test(NAME drivercrate_collector_shared_inventory_tests COMMAND drivercrate_collector_shared_inventory_tests)
    set_tests_properties(drivercrate_collector_shared_inventory_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)

    # 元予約精算の区間commitだけを独立した非通信native fixtureで検査します。
    add_executable(drivercrate_collector_shared_update_tests
        tests/unit/local_collector_shared_update_tests.cpp
        src/platform/local_collector_shared_store.cpp
        src/platform/local_collector_shared_operation.cpp
        src/platform/local_collector_shared_update.cpp
        src/platform/local_collector_shared_ledger.cpp
        src/platform/local_collector_collection_store.cpp
        src/platform/local_collector_campaign.cpp
        src/platform/local_collector_state_store.cpp
    )
    target_include_directories(drivercrate_collector_shared_update_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_collector_shared_update_tests PRIVATE drivercrate_platform ole32 normaliz)
    drivercrate_apply_compiler_options(drivercrate_collector_shared_update_tests)
    drivercrate_apply_linker_options(drivercrate_collector_shared_update_tests)
    add_test(NAME drivercrate_collector_shared_update_tests COMMAND drivercrate_collector_shared_update_tests)
    set_tests_properties(drivercrate_collector_shared_update_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 300)

    # 追加三操作の210保存窓を独立した有限枠で検査します。実HTTP・CLIは接続しません。
    add_executable(drivercrate_collector_shared_operation_tests
        tests/unit/local_collector_shared_operation_tests.cpp
        src/platform/local_collector_shared_store.cpp
        src/platform/local_collector_shared_operation.cpp
        src/platform/local_collector_shared_update.cpp
        src/platform/local_collector_shared_ledger.cpp
        src/platform/local_collector_collection_store.cpp
        src/platform/local_collector_campaign.cpp
        src/platform/local_collector_state_store.cpp
    )
    target_include_directories(drivercrate_collector_shared_operation_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_collector_shared_operation_tests PRIVATE drivercrate_platform ole32 normaliz)
    drivercrate_apply_compiler_options(drivercrate_collector_shared_operation_tests)
    drivercrate_apply_linker_options(drivercrate_collector_shared_operation_tests)
    add_test(NAME drivercrate_collector_shared_operation_tests COMMAND drivercrate_collector_shared_operation_tests)
    set_tests_properties(drivercrate_collector_shared_operation_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 600)

    # 元20番目の分母・期限を変えず、混在鎖の総合検証だけを別枠で測ります。
    add_test(NAME drivercrate_collector_shared_combined_tests
        COMMAND drivercrate_collector_shared_operation_tests --combined-recovery)
    set_tests_properties(drivercrate_collector_shared_combined_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 600)

    # 非保存の切替draftだけを検査します。seal・実保存・本体／CLIへ接続しません。
    add_executable(drivercrate_collector_segment_switch_tests
        tests/unit/local_collector_segment_switch_tests.cpp
        src/platform/local_collector_segment_switch.cpp
        src/platform/local_collector_shared_ledger.cpp
        src/platform/local_collector_campaign.cpp
        src/platform/local_collector_state_store.cpp
    )
    target_include_directories(drivercrate_collector_segment_switch_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_collector_segment_switch_tests PRIVATE drivercrate_platform ole32 normaliz)
    drivercrate_apply_compiler_options(drivercrate_collector_segment_switch_tests)
    drivercrate_apply_linker_options(drivercrate_collector_segment_switch_tests)
    add_test(NAME drivercrate_collector_segment_switch_tests COMMAND drivercrate_collector_segment_switch_tests)
    set_tests_properties(drivercrate_collector_segment_switch_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 120)

    if(DRIVERCRATE_BUILD_LIVE_TESTS)
        # ADR0340: 明示local受入とliveの両方だけで秘密resolverの匿名分岐診断を含める。
        if(DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE)
            set_property(SOURCE src/platform/driver_store_provider.cpp APPEND PROPERTY
                COMPILE_DEFINITIONS DRIVERCRATE_INTERNAL_LIVE_INDEX_DIAGNOSTICS)
        endif()
        # 明示scan/review-onlyと承認済み一対象の取得modeで通常MainWindow/既定workerを観測する。
        # Fake seam・CTestを使わず、原規約/対象/期限に限定して実取得する。導入・復旧は行わない。
        add_executable(drivercrate_live_index_main_window_scan
            tests/live/index_main_window_scan.cpp
            src/app/main_window.cpp
            src/app/main_window_metadata_search.cpp
            src/app/main_window_preparation.cpp
            src/app/main_window_assessment.cpp
            src/app/app.rc
        )
        target_compile_definitions(drivercrate_live_index_main_window_scan PRIVATE
            DRIVERCRATE_INTERNAL_LIVE_INDEX_TESTS)
        target_include_directories(drivercrate_live_index_main_window_scan PRIVATE
            src ${CMAKE_CURRENT_BINARY_DIR}/generated)
        target_link_libraries(drivercrate_live_index_main_window_scan PRIVATE
            drivercrate_core drivercrate_platform drivercrate_miniz
            comdlg32 comctl32 dwmapi ole32 setupapi uxtheme windowscodecs)
        drivercrate_apply_compiler_options(drivercrate_live_index_main_window_scan)
        drivercrate_apply_linker_options(drivercrate_live_index_main_window_scan)
        target_link_options(drivercrate_live_index_main_window_scan PRIVATE
            "SHELL:/MANIFESTUAC:\"level='asInvoker' uiAccess='false'\""
            "SHELL:/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")

        # 明示操作だけの実HTTP取得・封印native測定器。自動CTestに登録しない。
        add_executable(drivercrate_live_sealed_prolific_smoke tests/live/acquired_inf_dependency_smoke.cpp)
        target_compile_definitions(drivercrate_live_sealed_prolific_smoke PRIVATE DRIVERCRATE_LIVE_SEALED_INF_PROBE)
        target_include_directories(drivercrate_live_sealed_prolific_smoke PRIVATE src)
        target_link_libraries(drivercrate_live_sealed_prolific_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_live_sealed_prolific_smoke)
        drivercrate_apply_linker_options(drivercrate_live_sealed_prolific_smoke)

        # 初回直接指定の結果／EXEを保持し、全内側ZIPの明示計画を別世代で確認する。
        add_executable(drivercrate_live_sealed_prolific_nested_smoke tests/live/acquired_inf_dependency_smoke.cpp)
        target_compile_definitions(drivercrate_live_sealed_prolific_nested_smoke PRIVATE
            DRIVERCRATE_LIVE_SEALED_INF_PROBE DRIVERCRATE_LIVE_SEALED_NESTED_PROBE)
        target_include_directories(drivercrate_live_sealed_prolific_nested_smoke PRIVATE src)
        target_link_libraries(drivercrate_live_sealed_prolific_nested_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_live_sealed_prolific_nested_smoke)
        drivercrate_apply_linker_options(drivercrate_live_sealed_prolific_nested_smoke)

        # 外部台帳の一recordを実公式HTML／payload／封印nativeへ接続する別測定世代。
        add_executable(drivercrate_live_collector_inspection_smoke tests/live/acquired_inf_dependency_smoke.cpp)
        target_compile_definitions(drivercrate_live_collector_inspection_smoke PRIVATE
            DRIVERCRATE_LIVE_SEALED_INF_PROBE DRIVERCRATE_COLLECTOR_INSPECTION_PROBE)
        target_include_directories(drivercrate_live_collector_inspection_smoke PRIVATE src)
        target_link_libraries(drivercrate_live_collector_inspection_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_live_collector_inspection_smoke)
        drivercrate_apply_linker_options(drivercrate_live_collector_inspection_smoke)

        # 初回MIME／href停止のEXEを保持した別世代。厳密UTF-8は維持する。
        add_executable(drivercrate_live_collector_inspection_html_smoke tests/live/acquired_inf_dependency_smoke.cpp)
        target_compile_definitions(drivercrate_live_collector_inspection_html_smoke PRIVATE
            DRIVERCRATE_LIVE_SEALED_INF_PROBE DRIVERCRATE_COLLECTOR_INSPECTION_PROBE)
        target_include_directories(drivercrate_live_collector_inspection_html_smoke PRIVATE src)
        target_link_libraries(drivercrate_live_collector_inspection_html_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_live_collector_inspection_html_smoke)
        drivercrate_apply_linker_options(drivercrate_live_collector_inspection_html_smoke)

        add_executable(drivercrate_metadata_search_smoke
            tests/live/metadata_search_smoke.cpp
        )
        target_include_directories(drivercrate_metadata_search_smoke
            PRIVATE src ${CMAKE_CURRENT_BINARY_DIR}/generated
        )
        target_link_libraries(drivercrate_metadata_search_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_metadata_search_smoke)

        add_executable(drivercrate_scan_measurement_smoke
            tests/support/scan_measurement_diagnostics.cpp
            tests/live/scan_measurement_smoke.cpp
        )
        target_include_directories(
            drivercrate_scan_measurement_smoke
            PRIVATE src tests ${CMAKE_CURRENT_BINARY_DIR}/generated
        )
        target_link_libraries(
            drivercrate_scan_measurement_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_scan_measurement_smoke)

        add_executable(drivercrate_wua_scan_smoke
            tests/live/wua_scan_smoke.cpp
        )
        target_include_directories(drivercrate_wua_scan_smoke PRIVATE src)
        target_link_libraries(drivercrate_wua_scan_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_wua_scan_smoke)

        add_executable(drivercrate_driver_store_scan_smoke
            tests/live/driver_store_scan_smoke.cpp
        )
        target_include_directories(drivercrate_driver_store_scan_smoke PRIVATE src)
        target_link_libraries(drivercrate_driver_store_scan_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_driver_store_scan_smoke)

        add_executable(drivercrate_composite_scan_smoke
            tests/live/composite_scan_smoke.cpp
        )
        target_include_directories(drivercrate_composite_scan_smoke PRIVATE src)
        target_link_libraries(drivercrate_composite_scan_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_composite_scan_smoke)

        add_executable(drivercrate_intel_ethernet_windows11_discovery_smoke
            tests/live/intel_ethernet_windows11_discovery_smoke.cpp
        )
        target_include_directories(
            drivercrate_intel_ethernet_windows11_discovery_smoke
            PRIVATE src
        )
        target_link_libraries(
            drivercrate_intel_ethernet_windows11_discovery_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(
            drivercrate_intel_ethernet_windows11_discovery_smoke
        )

        add_executable(drivercrate_catalog_member_smoke
            tests/live/catalog_member_smoke.cpp
        )
        target_include_directories(drivercrate_catalog_member_smoke PRIVATE src)
        target_link_libraries(drivercrate_catalog_member_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_catalog_member_smoke)

        add_executable(drivercrate_lenovo_catalog_smoke
            tests/live/lenovo_catalog_smoke.cpp
        )
        target_include_directories(drivercrate_lenovo_catalog_smoke PRIVATE src)
        target_link_libraries(drivercrate_lenovo_catalog_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_lenovo_catalog_smoke)

        add_executable(drivercrate_hp_catalog_smoke
            tests/live/hp_catalog_smoke.cpp
        )
        target_include_directories(drivercrate_hp_catalog_smoke PRIVATE src)
        target_link_libraries(drivercrate_hp_catalog_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_hp_catalog_smoke)

        add_executable(drivercrate_vaio_catalog_smoke
            tests/live/vaio_catalog_smoke.cpp
        )
        target_include_directories(drivercrate_vaio_catalog_smoke PRIVATE src)
        target_link_libraries(drivercrate_vaio_catalog_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_vaio_catalog_smoke)

        add_executable(drivercrate_amd_catalog_smoke
            tests/live/amd_catalog_smoke.cpp
        )
        target_include_directories(drivercrate_amd_catalog_smoke PRIVATE src)
        target_link_libraries(drivercrate_amd_catalog_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_amd_catalog_smoke)

        add_executable(drivercrate_intel_ethernet_server_catalog_smoke
            tests/support/live_search_diagnostics.cpp
            tests/live/intel_ethernet_server_catalog_smoke.cpp
        )
        target_include_directories(
            drivercrate_intel_ethernet_server_catalog_smoke
            PRIVATE src tests
        )
        target_link_libraries(
            drivercrate_intel_ethernet_server_catalog_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_intel_ethernet_server_catalog_smoke)

        add_executable(drivercrate_intel_ethernet_windows11_record_smoke
            tests/live/intel_ethernet_windows11_record_smoke.cpp
        )
        target_include_directories(
            drivercrate_intel_ethernet_windows11_record_smoke
            PRIVATE src
        )
        target_link_libraries(
            drivercrate_intel_ethernet_windows11_record_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_intel_ethernet_windows11_record_smoke)

        add_executable(drivercrate_nvidia_display_catalog_smoke
            tests/live/nvidia_display_catalog_smoke.cpp
        )
        target_include_directories(drivercrate_nvidia_display_catalog_smoke PRIVATE src)
        target_link_libraries(drivercrate_nvidia_display_catalog_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_nvidia_display_catalog_smoke)

        add_executable(drivercrate_focusrite_catalog_smoke
            tests/live/focusrite_catalog_smoke.cpp
        )
        target_include_directories(drivercrate_focusrite_catalog_smoke PRIVATE src)
        target_link_libraries(drivercrate_focusrite_catalog_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_focusrite_catalog_smoke)

        add_executable(drivercrate_nvidia_winof2_catalog_smoke
            tests/live/nvidia_winof2_catalog_smoke.cpp
        )
        target_include_directories(drivercrate_nvidia_winof2_catalog_smoke PRIVATE src)
        target_link_libraries(drivercrate_nvidia_winof2_catalog_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_nvidia_winof2_catalog_smoke)

        add_executable(drivercrate_dell_poweredge_catalog_smoke
            tests/live/dell_poweredge_catalog_smoke.cpp
        )
        target_include_directories(drivercrate_dell_poweredge_catalog_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_dell_poweredge_catalog_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_dell_poweredge_catalog_smoke)

        add_executable(drivercrate_intel_wireless_package_smoke
            tests/live/intel_wireless_package_smoke.cpp
        )
        target_include_directories(drivercrate_intel_wireless_package_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_intel_wireless_package_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_intel_wireless_package_smoke)

        add_executable(drivercrate_prolific_serial_package_smoke
            tests/live/prolific_serial_package_smoke.cpp
        )
        target_include_directories(drivercrate_prolific_serial_package_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_prolific_serial_package_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_prolific_serial_package_smoke)

        add_executable(drivercrate_prolific_serial_provider_smoke
            tests/live/prolific_serial_provider_smoke.cpp
        )
        target_include_directories(drivercrate_prolific_serial_provider_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_prolific_serial_provider_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_prolific_serial_provider_smoke)

        add_executable(drivercrate_silicon_labs_serial_package_smoke
            tests/live/silicon_labs_serial_package_smoke.cpp
        )
        target_include_directories(drivercrate_silicon_labs_serial_package_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_silicon_labs_serial_package_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_silicon_labs_serial_package_smoke)

        add_executable(drivercrate_silicon_labs_serial_provider_smoke
            tests/live/silicon_labs_serial_provider_smoke.cpp
        )
        target_include_directories(drivercrate_silicon_labs_serial_provider_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_silicon_labs_serial_provider_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_silicon_labs_serial_provider_smoke)

        add_executable(drivercrate_common_driver_package_smoke
            tests/live/common_driver_package_smoke.cpp
        )
        target_include_directories(drivercrate_common_driver_package_smoke PRIVATE src)
        target_link_libraries(drivercrate_common_driver_package_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_common_driver_package_smoke)

        # 同じsmoke sourceを研究専用compileとし、通常platformと製品へ観測型を公開しない。
        add_executable(drivercrate_maintenance_reached_reference_smoke
            tests/live/common_driver_package_smoke.cpp
            tests/live/maintenance_reached_reference_observation.cpp
            src/platform/common_driver_package.cpp)
        target_compile_definitions(drivercrate_maintenance_reached_reference_smoke PRIVATE
            DRIVERCRATE_REACHED_REFERENCE_RESEARCH
            DRIVERCRATE_REACHED_WORKSPACE=L"${CMAKE_CURRENT_SOURCE_DIR}/work/analysis/20261008-maintenance-reached-reference-53"
            DRIVERCRATE_RESIDUAL_WORKSPACE=L"${CMAKE_CURRENT_SOURCE_DIR}/work/analysis/20261008-maintenance-residual-reference-54")
        target_include_directories(drivercrate_maintenance_reached_reference_smoke PRIVATE src tests/live)
        target_link_libraries(drivercrate_maintenance_reached_reference_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_maintenance_reached_reference_smoke)
        drivercrate_apply_linker_options(drivercrate_maintenance_reached_reference_smoke)

        add_executable(drivercrate_indexed_driver_package_smoke
            tests/live/indexed_driver_package_smoke.cpp
        )
        target_include_directories(drivercrate_indexed_driver_package_smoke PRIVATE src)
        target_link_libraries(drivercrate_indexed_driver_package_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_indexed_driver_package_smoke)

        add_executable(drivercrate_maintenance_embedded_files_smoke
            tests/live/maintenance_embedded_files_smoke.cpp
        )
        target_include_directories(drivercrate_maintenance_embedded_files_smoke PRIVATE src)
        target_link_libraries(drivercrate_maintenance_embedded_files_smoke PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_maintenance_embedded_files_smoke)

        add_executable(drivercrate_official_sfx_structure_smoke
            tests/live/official_sfx_structure_smoke.cpp
        )
        target_include_directories(drivercrate_official_sfx_structure_smoke PRIVATE src)
        target_link_libraries(drivercrate_official_sfx_structure_smoke PRIVATE drivercrate_platform drivercrate_miniz)
        drivercrate_apply_compiler_options(drivercrate_official_sfx_structure_smoke)

        add_executable(drivercrate_generic_inf_package_smoke
            tests/live/generic_inf_package_smoke.cpp
        )
        target_include_directories(drivercrate_generic_inf_package_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_generic_inf_package_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_generic_inf_package_smoke)

        add_executable(drivercrate_generic_inf_provider_smoke
            tests/live/generic_inf_provider_smoke.cpp
        )
        target_include_directories(drivercrate_generic_inf_provider_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_generic_inf_provider_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_generic_inf_provider_smoke)

        add_executable(drivercrate_wch_serial_package_smoke
            tests/live/wch_serial_package_smoke.cpp
        )
        target_include_directories(drivercrate_wch_serial_package_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_wch_serial_package_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_wch_serial_package_smoke)

        add_executable(drivercrate_wch_serial_provider_smoke
            tests/live/wch_serial_provider_smoke.cpp
        )
        target_include_directories(drivercrate_wch_serial_provider_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_wch_serial_provider_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_wch_serial_provider_smoke)

        add_executable(drivercrate_wch_multi_serial_package_smoke
            tests/live/wch_multi_serial_package_smoke.cpp
        )
        target_include_directories(drivercrate_wch_multi_serial_package_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_wch_multi_serial_package_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_wch_multi_serial_package_smoke)

        add_executable(drivercrate_wch_multi_serial_provider_smoke
            tests/live/wch_multi_serial_provider_smoke.cpp
        )
        target_include_directories(drivercrate_wch_multi_serial_provider_smoke PRIVATE src)
        target_link_libraries(
            drivercrate_wch_multi_serial_provider_smoke
            PRIVATE drivercrate_platform
        )
        drivercrate_apply_compiler_options(drivercrate_wch_multi_serial_provider_smoke)
    endif()
endif()

# 製品用の明示buildと従来のlive構成を同じ定義へ接続し、二重target生成を避ける。
if(DRIVERCRATE_BUILD_COLLECTOR OR (BUILD_TESTING AND DRIVERCRATE_BUILD_LIVE_TESTS))
    # 開発用metadata collector。通常のDriverCrate.exe、installへlinkしない。
    add_executable(DriverCrateCollector
        src/app/local_driver_collector_main.cpp
        src/platform/local_driver_collector.cpp
        src/platform/local_collector_state_store.cpp
    )
    target_include_directories(DriverCrateCollector PRIVATE src)
    target_link_libraries(DriverCrateCollector PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(DriverCrateCollector)
    drivercrate_apply_linker_options(DriverCrateCollector)

    # 収集用の手動セットアップ。非昇格、非通信、通常本体と独立した開発preview。
    add_executable(DriverCrateCollectorSetup
        src/app/collector_setup_main.cpp
        src/platform/collector_setup_workspace.cpp
        src/platform/collector_setup_workspace.h
        src/platform/collector_setup_transport.cpp
        src/platform/collector_setup_transport.h
        src/platform/collector_setup_admission.cpp
        src/platform/collector_setup_admission.h
        src/platform/local_driver_collector.cpp
        # Descriptor predicateを既存実装からread-onlyで再利用し、保護規則を複製しない。
        src/platform/local_collector_state_store.cpp
        src/app/collector_setup.rc
        src/app/collector_setup.manifest
    )
    target_include_directories(DriverCrateCollectorSetup PRIVATE src "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_link_libraries(DriverCrateCollectorSetup PRIVATE drivercrate_platform shell32)
    drivercrate_apply_compiler_options(DriverCrateCollectorSetup)
    drivercrate_apply_linker_options(DriverCrateCollectorSetup)
    target_compile_options(DriverCrateCollectorSetup PRIVATE /guard:cf)
    target_link_options(DriverCrateCollectorSetup PRIVATE "/MANIFESTUAC:level='asInvoker' uiAccess='false'")

    # CLIへ故障注入を公開せず、独立TUから保護workspaceの内部境界を検査する。
    if(BUILD_TESTING)
        add_executable(drivercrate_collector_setup_workspace_tests
            tests/unit/collector_setup_workspace_tests.cpp
            src/platform/collector_setup_transport.cpp
            src/platform/collector_setup_admission.cpp
            src/platform/local_driver_collector.cpp
            src/platform/local_collector_state_store.cpp)
        target_include_directories(drivercrate_collector_setup_workspace_tests PRIVATE src)
        target_link_libraries(drivercrate_collector_setup_workspace_tests PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_collector_setup_workspace_tests)
        drivercrate_apply_linker_options(drivercrate_collector_setup_workspace_tests)
        add_test(NAME drivercrate_collector_setup_workspace_tests COMMAND drivercrate_collector_setup_workspace_tests)
        add_executable(drivercrate_collector_setup_transport_tests
            tests/unit/collector_setup_transport_tests.cpp
            src/platform/collector_setup_transport.cpp)
        target_include_directories(drivercrate_collector_setup_transport_tests PRIVATE src)
        target_compile_definitions(drivercrate_collector_setup_transport_tests PRIVATE DRIVERCRATE_INTERNAL_INDEX_TESTS)
        target_link_libraries(drivercrate_collector_setup_transport_tests PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_collector_setup_transport_tests)
        drivercrate_apply_linker_options(drivercrate_collector_setup_transport_tests)
        add_test(NAME drivercrate_collector_setup_transport_tests COMMAND drivercrate_collector_setup_transport_tests)
        add_executable(drivercrate_collector_setup_admission_tests
            tests/unit/collector_setup_admission_tests.cpp
            tests/unit/collector_setup_admission_tests.manifest
            src/platform/collector_setup_admission.cpp
            src/platform/local_collector_state_store.cpp)
        target_include_directories(drivercrate_collector_setup_admission_tests PRIVATE src)
        target_link_libraries(drivercrate_collector_setup_admission_tests PRIVATE drivercrate_platform)
        drivercrate_apply_compiler_options(drivercrate_collector_setup_admission_tests)
        drivercrate_apply_linker_options(drivercrate_collector_setup_admission_tests)
        add_test(NAME drivercrate_collector_setup_admission_tests COMMAND drivercrate_collector_setup_admission_tests)
        set_tests_properties(drivercrate_collector_setup_admission_tests PROPERTIES TIMEOUT 180)
    endif()

    foreach(drivercrate_index_profile_target IN ITEMS DriverCrateCollector DriverCrateCollectorSetup)
        set_property(TARGET ${drivercrate_index_profile_target} APPEND PROPERTY LINK_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/RecordIndexBuildProfile.cmake"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/index_distribution_trust.h")
        add_custom_command(TARGET ${drivercrate_index_profile_target} POST_BUILD
            COMMAND "${CMAKE_COMMAND}" "-DEXECUTABLE=$<TARGET_FILE:${drivercrate_index_profile_target}>"
                "-DLOCAL_PROFILE=${DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE}"
                "-DDISTRIBUTION_FINGERPRINT=${drivercrate_distribution_fingerprint}"
                "-DACQUISITION_POLICY_REVISION=${drivercrate_distribution_acquisition_revision}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/RecordIndexBuildProfile.cmake"
            VERBATIM)
    endforeach()

    # 配布する二targetの診断文字列から開発workspaceを除去する。通常本体・libraryへは伝播しない。
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" drivercrate_collector_source_root)
    foreach(drivercrate_collector_distribution_target IN ITEMS DriverCrateCollector DriverCrateCollectorSetup)
        target_compile_options(${drivercrate_collector_distribution_target} PRIVATE
            "$<$<COMPILE_LANGUAGE:CXX>:/experimental:deterministic>"
            "$<$<COMPILE_LANGUAGE:CXX>:/pathmap:${drivercrate_collector_source_root}=.>"
        )
    endforeach()
endif()
