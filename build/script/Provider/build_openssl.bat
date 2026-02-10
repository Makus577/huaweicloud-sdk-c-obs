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

:: 检查是否以管理员权限运行（可选，但推荐）
:: net session >nul 2>&1
:: if %ERRORLEVEL% neq 0 (
::     echo 警告: 建议以管理员权限运行此脚本
::     pause
:: )

echo =========== 开始编译 OpenSSL ===========

:: 设置默认版本为Tongsuo（支持国密）
set OPENSSL_VERSION=openssl-1.0.2r

:: 检查是否提供了版本参数（可选）
if not "%2" == "" (
    set OPENSSL_VERSION=%2
)

set OPENSSL_PATH=%cd%\..\..\..\third_party_groupware\eSDK_Storage_Plugins\%OPENSSL_VERSION%

:: 检查OpenSSL目录是否存在
call :check_exists "%OPENSSL_PATH%"

:: 解析架构参数
if {x64} == {%~1} (
    set VCVARS="%VS100COMNTOOLS%\..\..\VC\bin\amd64\vcvars64.bat"
    set OPENSSL_CONFIG=VC-WIN64A
    set OPENSSL_CONFIG_BAT="ms/do_win64a.bat"
    set OUTPUT_TAG=win64_x64_msvc
) else if {win32} == {%~1} (
    set VCVARS="%VS100COMNTOOLS%\..\..\VC\bin\vcvars32.bat"
    set OPENSSL_CONFIG=VC-WIN32
    set OPENSSL_CONFIG_BAT="ms/do_ms.bat"
    set OUTPUT_TAG=win32_x86_msvc
) else (
    echo 错误: 第一个参数必须是 x64 或 win32
    echo 用法: build_openssl.bat x64 [版本号] 或 build_openssl.bat win32 [版本号]
    echo 示例: build_openssl.bat x64 openssl-1.0.2r
    goto exit
)

:: 检查Visual Studio环境变量
if not defined VS100COMNTOOLS (
    echo 错误: 未找到Visual Studio 2010环境变量 VS100COMNTOOLS
    echo 请确保已正确安装Visual Studio 2010
    goto exit
)

call :check_exists "%VCVARS%"

echo.
echo 正在进入OpenSSL目录: %OPENSSL_PATH%
cd %OPENSSL_PATH%

echo.
echo 正在设置Visual Studio编译环境...
call %VCVARS%

echo.
echo 正在配置OpenSSL编译参数...
call :check_command perl Configure %OPENSSL_CONFIG% no-asm --prefix=..\openssl

echo.
echo 正在执行OpenSSL配置脚本...
call :check_command call %OPENSSL_CONFIG_BAT%

echo.
echo 正在清理之前的编译结果...
call :check_command nmake -f ms/ntdll.mak clean

echo.
echo 正在编译OpenSSL...
call :check_command nmake -f ms/ntdll.mak

echo.
echo 正在安装OpenSSL...
call :check_command nmake -f ms/ntdll.mak install

echo.
echo 正在复制编译产物到build目录...

:: 确保目标目录存在
if not exist "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\bin\%OUTPUT_TAG%" mkdir "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\bin\%OUTPUT_TAG%"
if not exist "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\lib\%OUTPUT_TAG%" mkdir "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\lib\%OUTPUT_TAG%"
if not exist "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\lib\%OUTPUT_TAG%\engines" mkdir "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\lib\%OUTPUT_TAG%\engines"
if not exist "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\include\openssl" mkdir "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\include\openssl"

:: 复制编译产物
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\bin\*.dll" "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\bin\%OUTPUT_TAG%\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\lib\*.lib" "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\lib\%OUTPUT_TAG%\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\bin\*.exe" "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\bin\%OUTPUT_TAG%\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\lib\engines\*.dll" "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\lib\%OUTPUT_TAG%\engines\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\include\openssl\*.h" "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\include\openssl\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\include\openssl\*.c" "%OPENSSL_PATH%\..\build\%OPENSSL_VERSION%\include\openssl\" /s /e /y

echo.
echo 正在复制编译产物到SDK目录...

:: 确保SDK目录存在
if not exist "%OPENSSL_PATH%\bin\%OUTPUT_TAG%\release" mkdir "%OPENSSL_PATH%\bin\%OUTPUT_TAG%\release"
if not exist "%OPENSSL_PATH%\lib\%OUTPUT_TAG%\release" mkdir "%OPENSSL_PATH%\lib\%OUTPUT_TAG%\release"
if not exist "%OPENSSL_PATH%\include\openssl" mkdir "%OPENSSL_PATH%\include\openssl"

if not exist "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\bin\%OUTPUT_TAG%\release" mkdir "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\bin\%OUTPUT_TAG%\release"
if not exist "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\include\openssl" mkdir "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\include\openssl"
if not exist "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\lib\%OUTPUT_TAG%\release" mkdir "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\lib\%OUTPUT_TAG%\release"

:: 复制到SDK目录
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\bin\*.dll" "%OPENSSL_PATH%\bin\%OUTPUT_TAG%\release\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\lib\*.lib" "%OPENSSL_PATH%\lib\%OUTPUT_TAG%\release\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\include\openssl\*.h" "%OPENSSL_PATH%\include\openssl\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\include\openssl\*.c" "%OPENSSL_PATH%\include\openssl\" /s /e /y

call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\bin\*.dll" "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\bin\%OUTPUT_TAG%\release\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\include\openssl\*.h" "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\include\openssl\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\include\openssl\*.c" "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\include\openssl\" /s /e /y
call :check_command xCOPY "%OPENSSL_PATH%\..\openssl\lib\*.lib" "%cd%\..\..\..\source\eSDK_OBS_API\eSDK_OBS_API_C++\lib\%OUTPUT_TAG%\release\" /s /e /y

echo.
echo 正在返回脚本所在目录...
cd "%cd%\..\..\..\build\script\Provider"

echo.
echo =========== OpenSSL编译完成 ===========

:exit
endlocal