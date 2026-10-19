# DriverCrate の source target に共通の警告と hardening option を適用する。
# Windows.Data.Jsonを使うparserは、Windows SDK WindowsNumerics.inlのSAL差に限って
# header展開区間で28252／28253／6101を局所制御する。CP210x／WCH／Broadcomも既存VAIOと同じ境界。
# Application sourceへの/W4、/WX、/analyzeは維持し、target全体の警告を抑止しない。

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

    target_compile_options(${target_name}
        PRIVATE
            /W4
            /WX
            /EHsc
            /permissive-
            /Zc:__cplusplus
            /utf-8
            /sdl
    )

    # 固定hashの第三者sourceを除き、DriverCrate自作sourceだけをrelease静的解析gateへ渡す。
    if(DRIVERCRATE_ENABLE_ANALYZE)
        target_compile_options(${target_name} PRIVATE /analyze)
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
