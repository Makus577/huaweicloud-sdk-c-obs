@echo off
setlocal enabledelayedexpansion

:: 错误处理函数
:error_handler
echo.
echo 错误: 在执行过程中发生错误，错误代码: %ERRORLEVEL%
echo.
echo 正在清理临时文件...
:: 可以在这里添加更多清理操作
goto exit

:: 检查命令是否成功执行
:check_command
call %*
if %ERRORLEVEL% neq 0 (
    call :error_handler
)
goto :eof

:: 检查文件/目录是否存在
:check_exists
if not exist "%~1" (
    echo 错误: %~1 不存在
    call :error_handler
)
goto :eof

echo =========== 开始编译 CURL ===========

:: 设置默认CURL版本
set curl_version=curl-7.64.1

:: 检查是否提供了版本参数（可选）
if not "%2" == "" (
    set curl_version=%2
)

SET LIBCURL_PATH=%cd%\..\..\..\third_party_groupware\eSDK_Storage_Plugins\%curl_version%

:: 检查CURL目录是否存在
call :check_exists "%LIBCURL_PATH%"

SET SOLUTION_LIBCURL="%LIBCURL_PATH%\projects\Windows\VC10\lib\libcurl.sln"
call :check_exists %SOLUTION_LIBCURL%

:: 解析架构参数
if {x64} == {%~1} (
    SET SOLUTION_CONFIG="DLL Release - DLL Windows SSPI - DLL WinIDN|x64"
    set OUTPUT_TAG=win64_x64_msvc
    set BUILD_PLATFORM=Win64
) else if {win32} == {%~1} (
    SET SOLUTION_CONFIG="DLL Release - DLL Windows SSPI - DLL WinIDN|Win32"
    set OUTPUT_TAG=win32_x86_msvc
    set BUILD_PLATFORM=Win32
) else (
    echo 错误: 第一个参数必须是 x64 或 win32
    echo 用法: build_curl.bat x64 [版本号] 或 build_curl.bat win32 [版本号]
    echo 示例: build_curl.bat x64 curl-7.64.1
    goto exit
)

SET ACTION=Rebuild

echo.
echo -----------开始编译 curl-----------

echo.
echo 正在使用Visual Studio编译CURL库...
call :check_command "C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\IDE\devenv" %SOLUTION_LIBCURL% /%ACTION% %SOLUTION_CONFIG%

echo.
echo 正在复制编译产物到build目录...

:: 确保目标目录存在
if not exist "%LIBCURL_PATH%\..\build\%curl_version%\%OUTPUT_TAG%\lib" mkdir "%LIBCURL_PATH%\..\build\%curl_version%\%OUTPUT_TAG%\lib"
if not exist "%LIBCURL_PATH%\..\build\%curl_version%\%OUTPUT_TAG%\bin" mkdir "%LIBCURL_PATH%\..\build\%curl_version%\%OUTPUT_TAG%\bin"
if not exist "%LIBCURL_PATH%\..\build\%curl_version%\include\curl" mkdir "%LIBCURL_PATH%\..\build\%curl_version%\include\curl"

:: 复制编译产物
call :check_command xCOPY "%LIBCURL_PATH%\build\%BUILD_PLATFORM%\VC10\DLL Release - DLL Windows SSPI - DLL WinIDN\*.lib" "%LIBCURL_PATH%\..\build\%curl_version%\%OUTPUT_TAG%\lib\" /y
call :check_command xCOPY "%LIBCURL_PATH%\build\%BUILD_PLATFORM%\VC10\DLL Release - DLL Windows SSPI - DLL WinIDN\*.dll" "%LIBCURL_PATH%\..\build\%curl_version%\%OUTPUT_TAG%\bin\" /y
call :check_command xCOPY "%LIBCURL_PATH%\include\curl\*.h" "%LIBCURL_PATH%\..\build\%curl_version%\include\curl\" /y

echo.
echo 正在复制编译产物到SDK目录...

:: 确保SDK目录存在
if not exist "%LIBCURL_PATH%\lib\%OUTPUT_TAG%\release" mkdir "%LIBCURL_PATH%\lib\%OUTPUT_TAG%\release"
if not exist "%LIBCURL_PATH%\bin\%OUTPUT_TAG%\release" mkdir "%LIBCURL_PATH%\bin\%OUTPUT_TAG%\release"
if not exist "%LIBCURL_PATH%\include\curl" mkdir "%LIBCURL_PATH%\include\curl"

if not exist "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\lib\%OUTPUT_TAG%\release" mkdir "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\lib\%OUTPUT_TAG%\release"
if not exist "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\bin\%OUTPUT_TAG%\release" mkdir "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\bin\%OUTPUT_TAG%\release"
if not exist "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\include\curl" mkdir "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\include\curl"

:: 复制到SDK目录
call :check_command xCOPY "%LIBCURL_PATH%\build\%BUILD_PLATFORM%\VC10\DLL Release - DLL Windows SSPI - DLL WinIDN\*.lib" "%LIBCURL_PATH%\lib\%OUTPUT_TAG%\release\" /y
call :check_command xCOPY "%LIBCURL_PATH%\build\%BUILD_PLATFORM%\VC10\DLL Release - DLL Windows SSPI - DLL WinIDN\*.dll" "%LIBCURL_PATH%\bin\%OUTPUT_TAG%\release\" /y
call :check_command xCOPY "%LIBCURL_PATH%\include\curl\*.h" "%LIBCURL_PATH%\include\curl\" /y

call :check_command xCOPY "%LIBCURL_PATH%\build\%BUILD_PLATFORM%\VC10\DLL Release - DLL Windows SSPI - DLL WinIDN\*.lib" "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\lib\%OUTPUT_TAG%\release\" /y
call :check_command xCOPY "%LIBCURL_PATH%\build\%BUILD_PLATFORM%\VC10\DLL Release - DLL Windows SSPI - DLL WinIDN\*.dll" "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\bin\%OUTPUT_TAG%\release\" /y
call :check_command xCOPY "%LIBCURL_PATH%\include\curl\*.h" "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\include\curl\" /y

echo.
echo =========== CURL编译完成 ===========

:exit
endlocal