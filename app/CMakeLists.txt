cmake_minimum_required(VERSION 3.4.1)
add_library(native-lib
            SHARED
            src/main/cpp/native-lib.cpp
            src/main/cpp/ByteArray.cpp
            src/main/cpp/NativeByteBuffer.cpp
            src/main/cpp/BuffersStorage.cpp
            src/main/cpp/connections/ConnectionManager.cpp
            src/main/cpp/protocol/ProtocolSend.cpp
            )

find_library(log-lib log)

include_directories(boringssl/include)
add_library(ssl-lib STATIC IMPORTED)
set_target_properties(ssl-lib PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/boringssl/libssl.a)
add_library(crypto-lib STATIC IMPORTED)
set_target_properties(crypto-lib PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/boringssl/libcrypto.a)

target_link_libraries(native-lib
                      ${log-lib}
                      ssl-lib
                      crypto-lib
                      )