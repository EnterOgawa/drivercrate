# DriverCrate の source target に共通の警告と hardening option を適用する。
# Windows.Data.Jsonを使うparserは、Windows SDK WindowsNumerics.inlのSAL差に限って
# header展開区間で28252／28253／6101を局所制御する。CP210x／WCH／Broadcomも既存VAIOと同じ境界。
# Application sourceへの/W4、/WX、/analyzeは維持し、target全体の警告を抑止しない。
# analyze時は選定Windows SDKのInclude rootだけを外部headerとして扱う。
# CPP内pragmaより前にwinrt/base.hが展開される場合もSDKのSAL差をown解析から分離し、
# 通常warning W4と自作templateの診断を維持する。source/buildを外部指定へ含めない。

function(drivercrate_apply_compiler_options target_name)
    if(NOT MSVC)
        message(FATAL_ERROR "DriverCrate currently requires the Microsoft C++ compiler.")
    endif()

    target_compile_definitions(${target_name}
        PRIVATE
            NOMINMAX
            UNICODE
            _UNICODE
            WIN32_LEAN_AND_MEAN
    )

    # 自作CXXの診断文字列を共通の相対source pathへ揃える。静的libraryにも同じ規則を適用する。
    file(TO_NATIVE_PATH "${CMAKE_SOURCE_DIR}" drivercrate_source_root)
    target_compile_options(${target_name}
        PRIVATE
            /W4
            /WX
            /EHsc
            /permissive-
            /Zc:__cplusplus
            /utf-8
            /sdl
            "$<$<COMPILE_LANGUAGE:CXX>:/experimental:deterministic>"
            "$<$<COMPILE_LANGUAGE:CXX>:/pathmap:${drivercrate_source_root}=.>"
    )

    # 固定hashの第三者sourceを除き、DriverCrate自作sourceだけをrelease静的解析gateへ渡す。
    if(DRIVERCRATE_ENABLE_ANALYZE)
        if(NOT IS_ABSOLUTE "${CMAKE_MT}")
            message(FATAL_ERROR "MSVC analyze requires an absolute selected Windows SDK mt.exe.")
        endif()
        get_filename_component(drivercrate_sdk_arch_directory "${CMAKE_MT}" DIRECTORY)
        get_filename_component(drivercrate_sdk_version_directory "${drivercrate_sdk_arch_directory}" DIRECTORY)
        get_filename_component(drivercrate_sdk_version "${drivercrate_sdk_version_directory}" NAME)
        get_filename_component(drivercrate_sdk_bin_directory "${drivercrate_sdk_version_directory}" DIRECTORY)
        get_filename_component(drivercrate_sdk_root_directory "${drivercrate_sdk_bin_directory}" DIRECTORY)
        set(drivercrate_sdk_include_directory "${drivercrate_sdk_root_directory}/Include/${drivercrate_sdk_version}")
        if(NOT EXISTS "${drivercrate_sdk_include_directory}/um/WindowsNumerics.inl"
            OR NOT EXISTS "${drivercrate_sdk_include_directory}/cppwinrt/winrt/base.h")
            message(FATAL_ERROR "MSVC analyze selected Windows SDK include root is unverified.")
        endif()
        file(REAL_PATH "${drivercrate_sdk_include_directory}" drivercrate_sdk_include_directory)
        file(REAL_PATH "${CMAKE_SOURCE_DIR}" drivercrate_own_source_directory)
        file(REAL_PATH "${CMAKE_BINARY_DIR}" drivercrate_own_build_directory)
        string(TOLOWER "${drivercrate_sdk_include_directory}" drivercrate_sdk_include_comparison)
        string(TOLOWER "${drivercrate_own_source_directory}" drivercrate_source_comparison)
        string(TOLOWER "${drivercrate_own_build_directory}" drivercrate_build_comparison)
        cmake_path(IS_PREFIX drivercrate_sdk_include_comparison "${drivercrate_source_comparison}" NORMALIZE drivercrate_source_in_sdk)
        cmake_path(IS_PREFIX drivercrate_source_comparison "${drivercrate_sdk_include_comparison}" NORMALIZE drivercrate_sdk_in_source)
        cmake_path(IS_PREFIX drivercrate_sdk_include_comparison "${drivercrate_build_comparison}" NORMALIZE drivercrate_build_in_sdk)
        cmake_path(IS_PREFIX drivercrate_build_comparison "${drivercrate_sdk_include_comparison}" NORMALIZE drivercrate_sdk_in_build)
        if(drivercrate_source_in_sdk OR drivercrate_sdk_in_source OR drivercrate_build_in_sdk OR drivercrate_sdk_in_build)
            message(FATAL_ERROR "MSVC analyze SDK include root overlaps project source or generated headers.")
        endif()
        # 親Include rootを検索へ足すとwinrt/Windows.Data.Json.hがABI headerへshadowされる。
        # 選定SDKの実INCLUDE leafだけを元の順序で外部化し、header選択と自作解析を維持する。
        set(drivercrate_toolchain_include_directories "$ENV{INCLUDE}")
        set(drivercrate_sdk_include_leaves)
        set(drivercrate_sdk_external_options)
        foreach(drivercrate_include_entry IN LISTS drivercrate_toolchain_include_directories)
            file(REAL_PATH "${drivercrate_include_entry}" drivercrate_include_entry)
            string(TOLOWER "${drivercrate_include_entry}" drivercrate_include_comparison)
            cmake_path(IS_PREFIX drivercrate_sdk_include_comparison "${drivercrate_include_comparison}" NORMALIZE drivercrate_include_in_sdk)
            if(drivercrate_include_in_sdk)
                file(RELATIVE_PATH drivercrate_sdk_include_leaf "${drivercrate_sdk_include_directory}" "${drivercrate_include_entry}")
                if(NOT drivercrate_sdk_include_leaf MATCHES "^(ucrt|um|shared|winrt|cppwinrt)$")
                    message(FATAL_ERROR "MSVC analyze selected SDK INCLUDE entry is not a known include leaf.")
                endif()
                list(APPEND drivercrate_sdk_include_leaves "${drivercrate_sdk_include_leaf}")
                list(APPEND drivercrate_sdk_external_options "/external:I${drivercrate_include_entry}")
            endif()
        endforeach()
        set(drivercrate_sdk_sorted_leaves "${drivercrate_sdk_include_leaves}")
        list(SORT drivercrate_sdk_sorted_leaves)
        if(NOT drivercrate_sdk_sorted_leaves STREQUAL "cppwinrt;shared;ucrt;um;winrt")
            message(FATAL_ERROR "MSVC analyze selected SDK INCLUDE leaves are incomplete or duplicated.")
        endif()
        target_compile_options(${target_name} PRIVATE
            /analyze
            ${drivercrate_sdk_external_options}
            /external:W4
            /external:templates-
            /analyze:external-
        )
    endif()
endfunction()

# Release executable の Windows mitigation を linker option として明示する。
function(drivercrate_apply_linker_options target_name)
    if(MSVC)
        target_link_options(${target_name}
            PRIVATE
                /DYNAMICBASE
                /HIGHENTROPYVA
                /NXCOMPAT
                /guard:cf
        )
    endif()
endfunction()
