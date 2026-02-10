#!/bin/bash

# 错误处理函数
error_handler() {
    echo "错误: 在第 $1 行发生错误"
    echo "正在清理..."
    # 可以在这里添加清理操作，如删除临时文件等
    exit 1
}

# 检查命令是否成功执行
check_command() {
    local cmd="$1"
    local desc="$2"

    echo "正在执行: $desc"
    if eval "$cmd"; then
        echo "成功: $desc"
        return 0
    else
        echo "失败: $desc"
        error_handler ${BASH_LINENO[0]}
    fi
}

# 设置错误陷阱
trap 'error_handler ${LINENO}' ERR

echo =========== compile curl ==================
open_src_path=`pwd`
if [ "NULL"${curl_version} = "NULL" ]; then
   curl_version=curl-8.11.1
fi
curl_dir=./../../../third_party_groupware/eSDK_Storage_Plugins/${curl_version}
curl_lib=`pwd`/build/${curl_version}/lib
curl_include=`pwd`/build/${curl_version}/include/curl
static_curl_lib=`pwd`/build/${curl_version}/static_package/lib

# 检查CURL目录是否存在
if [ ! -d "$curl_dir" ]; then
    echo "错误: CURL目录 $curl_dir 不存在"
    echo "请检查third_party_groupware目录下是否包含CURL源代码"
    error_handler ${LINENO}
fi

# 定义Tongsuo版本（支持国密）
if [ "NULL"${tongsuo_version} = "NULL" ]; then
   tongsuo_version=tongsuo-8.3.0
fi

# === 给curl打patch以支持Tongsuo国密 ===
# Tongsuo在配置时设置环境变量，让curl能识别SM算法
export PKG_CONFIG_PATH=/usr/local/openssl/lib/pkgconfig
export LD_LIBRARY_PATH=/usr/local/openssl/lib:$LD_LIBRARY_PATH

# 检查Tongsuo是否已正确安装
if [ ! -d "/usr/local/openssl" ] || [ ! -d "/usr/local/openssl/lib" ] || [ ! -d "/usr/local/openssl/include" ]; then
    echo "错误: Tongsuo未正确安装在 /usr/local/openssl 目录"
    echo "请先运行 build_openssl.sh 来安装Tongsuo"
    error_handler ${LINENO}
fi

cd $curl_dir || error_handler ${LINENO}
check_command "chmod 777 configure" "设置configure脚本权限"

# 配置CURL
if [ $# = 0 ]; then
    if [ "$BUILD_FOR_ARM" = "true" ];then
        check_command "CFLAGS=\"-fstack-protector-all -Wl,-z,relro,-z,now\" \
        ./configure \
        --prefix=/usr/local/curl \
        --with-ssl=/usr/local/openssl \
        --with-ssl-backend=openssl \
        --enable-threaded-resolver \
        --host=aarch64-linux-gnu \
        --build=aarch64-gnu-linux \
        --with-gnu-ld" "配置CURL for ARM"
        lib_out="aarch64"
    elif [ "$BUILD_FOR_NDK_AARCH64" = "true" ];then
        check_command "CFLAGS=\"-fstack-protector-all\" \
        LDFLAGS=\"-Wl,-z,relro,-z,now\" \
        ./configure \
        --prefix=/usr/local/curl \
        --with-ssl=/usr/local/openssl \
        --with-ssl-backend=openssl \
        --enable-threaded-resolver \
        --host=aarch64-linux-android \
        CC=aarch64-linux-android-gcc" "配置CURL for NDK AARCH64"
        lib_out="ndk-aarch64"
    elif [ "$BUILD_FOR_MACOS" = "true" ];then
        check_command "CFLAGS=\"-fstack-protector-all\" \
        ./configure \
        --prefix=/usr/local/curl \
        --with-ssl=/usr/local/openssl \
        --with-ssl-backend=openssl \
        --enable-threaded-resolver" "配置CURL for macOS"
        lib_out="macos"
    else
        # Linux x86_64 配置，使用Tongsuo支持国密算法
        check_command "CFLAGS=\"-fstack-protector-all -Wl,-z,relro,-z,now\" \
        LDFLAGS=\"-L/usr/local/openssl/lib -Wl,-rpath,/usr/local/openssl/lib\" \
        PKG_CONFIG_PATH=\"/usr/local/openssl/lib/pkgconfig\" \
        ./configure \
        --prefix=/usr/local/curl \
        --with-ssl=/usr/local/openssl \
        --with-ssl-backend=openssl \
        --enable-threaded-resolver \
        --enable-optimize \
        --disable-debug" "配置CURL for Linux x86_64"
        lib_out="linux_x64"
	fi
elif [ "$1" = "BUILD_FOR_ARM" ]; then
    check_command "CFLAGS=\"-fstack-protector-all -Wl,-z,relro,-z,now\" \
    ./configure \
    --prefix=/usr/local/curl \
    --with-ssl=/usr/local/openssl \
    --with-ssl-backend=openssl \
    --enable-threaded-resolver \
    --host=aarch64-linux-gnu \
    --build=aarch64-gnu-linux \
    --with-gnu-ld" "配置CURL for ARM"
    lib_out="aarch64"
elif [ "$1" = "BUILD_FOR_NDK_AARCH64" ]; then
    check_command "CFLAGS=\"-fstack-protector-all\" \
    LDFLAGS=\"-Wl,-z,relro,-z,now\" \
    ./configure \
    --prefix=/usr/local/curl \
    --with-ssl=/usr/local/openssl \
    --with-ssl-backend=openssl \
    --enable-threaded-resolver \
    --host=aarch64-linux-android \
    CC=aarch64-linux-android-gcc" "配置CURL for NDK AARCH64"
    lib_out="ndk-aarch64"
elif [ "$1" = "BUILD_FOR_MACOS" ]; then
    check_command "CFLAGS=\"-fstack-protector-all\" \
    ./configure \
    --prefix=/usr/local/curl \
    --with-ssl=/usr/local/openssl \
    --with-ssl-backend=openssl \
    --enable-threaded-resolver" "配置CURL for macOS"
    lib_out="macos"
fi

check_command "make clean" "清理之前的编译结果"
check_command "make -j$(nproc 2>/dev/null || echo 4)" "编译CURL"
check_command "make install" "安装CURL"

cd $open_src_path || error_handler ${LINENO}
check_command "mkdir -p $curl_lib $curl_include $static_curl_lib" "创建输出目录"

if [ "$1" = "BUILD_FOR_MACOS" ] || [ "$BUILD_FOR_MACOS" = "true" ]; then
    check_command "cp -a $open_src_path/$curl_dir/lib/.libs/*.dylib $curl_lib" "复制macOS库文件"
else
    check_command "cp $open_src_path/$curl_dir/lib/.libs/libcurl.so* $curl_lib" "复制libcurl库文件"
fi
check_command "cp $open_src_path/$curl_dir/include/curl/*.h $curl_include" "复制头文件"
check_command "cp $open_src_path/$curl_dir/lib/.libs/*.a $static_curl_lib" "复制静态库文件"

echo "CURL编译和安装完成"
cd $open_src_path
