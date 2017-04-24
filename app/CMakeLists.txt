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

add_subdirectory(boringssl)
include_directories(boringssl/include)


target_link_libraries(native-lib
                      ${log-lib}
                      crypto
                      )