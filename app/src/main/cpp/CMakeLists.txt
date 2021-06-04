cmake_minimum_required(VERSION 3.4.1)

add_library(
        native-lib
        SHARED
        native-lib.cpp
        utils.cpp

        GmSSL.c
        gmssl_err.c)


include_directories(${CMAKE_SOURCE_DIR}/gmssl/include)

add_library(crypto STATIC IMPORTED)
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/gmssl/lib/${ANDROID_ABI}/libcrypto.a)


target_link_libraries(native-lib
        crypto
        log)
