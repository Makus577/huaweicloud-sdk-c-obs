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

open_src_path=`pwd`
# 修改为使用 Tongsuo
echo_openssl_version=`echo ${tongsuo_version}NULL`
if [ ${echo_openssl_version} = "NULL" ]; then
  tongsuo_version=tongsuo-8.3.0
fi
tongsuo_dir=./../../../third_party_groupware/eSDK_Storage_Plugins/${tongsuo_version}
tongsuo_lib=`pwd`/build/${tongsuo_version}/lib
static_tongsuo_lib=`pwd`/build/${tongsuo_version}/static_package/lib
tongsuo_include=`pwd`/build/${tongsuo_version}/include/openssl

# 检查Tongsuo目录是否存在
if [ ! -d "$tongsuo_dir" ]; then
    echo "错误: Tongsuo目录 $tongsuo_dir 不存在"
    echo "请检查third_party_groupware目录下是否包含Tongsuo源代码"
    error_handler ${LINENO}
fi

cd $tongsuo_dir || error_handler ${LINENO}
check_command "chmod 777 Configure" "设置Configure脚本权限"
check_command "chmod 777 util/point.sh" "设置point.sh脚本权限"
check_command "chmod 777 util/pod2mantest" "设置pod2mantest脚本权限"

# 配置Tongsuo
if [ $# = 0 ]; then
    if [ "$BUILD_FOR_ARM" = "true" ];then
        check_command "CFLAGS=\"-Wall -O3 -fstack-protector-all -Wl,-z,relro,-z,now\" \
        ./Configure threads shared enable-sm2 enable-sm3 enable-sm4 enable-sm9 \
        --prefix=/usr/local/openssl --openssldir=/usr/local/ssl/ linux-aarch64" "配置Tongsuo for ARM"
    elif [ "$BUILD_FOR_NDK_AARCH64" = "true" ];then
               export ANDROID_NDK_HOME=/tmp/ndk-aarch64
        check_command "CFLAGS=\"-Wall -O3 -fstack-protector-all\" \
        LDFLAGS=\"-Wl,-z,relro,-z,now\" \
        ./Configure threads shared enable-sm2 enable-sm3 enable-sm4 enable-sm9 \
        --prefix=/usr/local/openssl --openssldir=/usr/local/ssl/ android-arm64" "配置Tongsuo for NDK AARCH64"
    elif [ "$BUILD_FOR_MACOS" = "true" ];then
        check_command "CFLAGS=\"-Wall -O3 -fstack-protector-all\" \
        ./config threads shared enable-sm2 enable-sm3 enable-sm4 enable-sm9 \
        --prefix=/usr/local/openssl --openssldir=/usr/local/ssl/" "配置Tongsuo for macOS"
    else
        # Tongsuo 支持 SM 算法 - 启用所有国密特性
        check_command "CFLAGS=\"-Wall -O3 -fstack-protector-all -Wl,-z,relro,-z,now\" \
        ./Configure threads shared \
        enable-sm2 enable-sm3 enable-sm4 enable-sm9 \
        --prefix=/usr/local/openssl --openssldir=/usr/local/ssl/ linux-x86_64 -DOPENSSL_NO_ASM" "配置Tongsuo for Linux x86_64"
    fi
elif [ "$1" = "BUILD_FOR_ARM" ]; then
    check_command "CFLAGS=\"-Wall -O3 -fstack-protector-all -Wl,-z,relro,-z,now\" \
    ./Configure threads shared enable-sm2 enable-sm3 enable-sm4 enable-sm9 \
    --prefix=/usr/local/openssl --openssldir=/usr/local/ssl/ linux-aarch64" "配置Tongsuo for ARM"
elif [ "$1" = "BUILD_FOR_NDK_AARCH64" ]; then
    export ANDROID_NDK_HOME=/tmp/ndk-aarch64
    check_command "CFLAGS=\"-Wall -O3 -fstack-protector-all\" \
    LDFLAGS=\"-Wl,-z,relro,-z,now\" \
    ./Configure threads shared enable-sm2 enable-sm3 enable-sm4 enable-sm9 \
    --prefix=/usr/local/openssl --openssldir=/usr/local/ssl/ android-arm64" "配置Tongsuo for NDK AARCH64"
elif [ "$1" = "BUILD_FOR_MACOS" ]; then
    check_command "CFLAGS=\"-Wall -O3 -fstack-protector-all\" \
    ./config threads shared enable-sm2 enable-sm3 enable-sm4 enable-sm9 \
    --prefix=/usr/local/openssl --openssldir=/usr/local/ssl/" "配置Tongsuo for macOS"
fi

check_command "make clean" "清理之前的编译结果"
check_command "make -j$(nproc 2>/dev/null || echo 4)" "编译Tongsuo"
check_command "make install" "安装Tongsuo"

cd $open_src_path || error_handler ${LINENO}
check_command "mkdir -p $tongsuo_lib $tongsuo_include $static_tongsuo_lib" "创建输出目录"

if [ "$1" = "BUILD_FOR_MACOS" ] || [ "$BUILD_FOR_MACOS" = "true" ]; then
    check_command "cp -a ${open_src_path}/${tongsuo_dir}/*.dylib $tongsuo_lib" "复制macOS库文件"
else
    check_command "cp ${open_src_path}/${tongsuo_dir}/libcrypto.so* $tongsuo_lib" "复制libcrypto库文件"
    check_command "cp ${open_src_path}/${tongsuo_dir}/libssl.so* $tongsuo_lib" "复制libssl库文件"
fi
check_command "cp ${open_src_path}/${tongsuo_dir}/include/openssl/*.h $tongsuo_include" "复制头文件"
check_command "cp ${open_src_path}/${tongsuo_dir}/*.a $static_tongsuo_lib" "复制静态库文件"

echo "Tongsuo编译和安装完成"
cd $open_src_path
