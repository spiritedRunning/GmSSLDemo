#!/bin/bash
#
# Copyright 2016 leenjewel
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -u
set -ex

source ./_shared.sh

# Setup architectures, library name and other vars + cleanup from previous runs
LIB_NAME="GmSSL-master"
LIB_DEST_DIR=${TOOLS_ROOT}/gmssl_out/libs
[ -d ${LIB_DEST_DIR} ] && rm -rf ${LIB_DEST_DIR}

# 这里判断了master.zip压缩包是否存在，如果不存在则下载最新的包,这里建议修改为判断解压后的文件夹是否存在，如果不存在才去重新下载.
# 因为版本中要修改`Configure`和`test/build.info`两个文件后才可以正常使用，因此在下载完毕master包后，需要对zip压缩包内的两个文件进行修改，后续解压后该代码才可正常执行。
[ -f "GmSSL-master.zip" ]  || wget https://github.com/guanzhi/GmSSL/archive/master.zip;


configure_make() {
  ARCH=$1; ABI=$2;
  #  rm -rf "${LIB_NAME}"
  
  # Unarchive library, then configure and make for specified architectures
  #if [![-f "GmSSL-master"]]; then
  #unzip -o "master.zip"
  #fi

  # 切换到此目录
  pushd "${LIB_NAME}"

  configure $*

  #support openssl-1.0.x
  if [[ $LIB_NAME != "GmSSL-master" ]]; then
    if [[ $ARCH == "android-armeabi" ]]; then
        ARCH="android-armv7"
    elif [[ $ARCH == "android64" ]]; then 
        ARCH="linux-x86_64 shared no-ssl2 no-ssl3 no-hw "
    elif [[ "$ARCH" == "android64-aarch64" ]]; then
        ARCH="android shared no-ssl2 no-ssl3 no-hw "
    fi
  fi

echo "use android api:${ANDROID_API}"

  ./Configure $ARCH \
              --prefix=${LIB_DEST_DIR}/${ABI} \
              --with-zlib-include=$SYSROOT/usr/include \
              --with-zlib-lib=$SYSROOT/usr/lib \
              zlib \
              no-asm \
              no-shared \
              no-unit-test\
              no-serpent

  PATH=$TOOLCHAIN_PATH:$PATH

  if make -j4; then
    make install

    OUTPUT_ROOT=${TOOLS_ROOT}/../output/android/gmssl-${ABI}
    [ -d ${OUTPUT_ROOT}/include ] || mkdir -p ${OUTPUT_ROOT}/include
    cp -r ${LIB_DEST_DIR}/${ABI}/include/openssl ${OUTPUT_ROOT}/include

    [ -d ${OUTPUT_ROOT}/lib ] || mkdir -p ${OUTPUT_ROOT}/lib
    cp ${LIB_DEST_DIR}/${ABI}/lib/libcrypto.a ${OUTPUT_ROOT}/lib
    cp ${LIB_DEST_DIR}/${ABI}/lib/libssl.a ${OUTPUT_ROOT}/lib
  fi;
  popd

}



for ((i=0; i < ${#ARCHS[@]}; i++))
do
  if [[ $# -eq 0 ]] || [[ "$1" == "${ARCHS[i]}" ]]; then
    # Do not build 64 bit arch if ANDROID_API is less than 21 which is
    # the minimum supported API level for 64 bit.
    [[ ${ANDROID_API} < 21 ]] && ( echo "${ABIS[i]}" | grep 64 > /dev/null ) && continue;
    configure_make "${ARCHS[i]}" "${ABIS[i]}"
  fi
  
  # 每次循环体结束，删除后缀为 -android-toolchain的文件，防止占用存储空间过大
  rm -rf ${TOOLS_ROOT}/*-android-toolchain
done

