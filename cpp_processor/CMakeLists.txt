cmake_minimum_required(VERSION 3.16)
project(cpp_processor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(cpp_processor
  src/main.cpp

  #grpc
  src/grpc/txn_client.cpp
  src/grpc/grpc_client.cpp
  src/grpc/grpc_service.cpp
  src/grpc/guardians_client.cpp
  src/grpc/guardians_service.cpp

  #events
  src/events/zera_events.cpp
  src/events/solana_events.cpp
  src/events/gov_events.cpp

  #payload
  src/payload/payload.cpp

  #metadata
  src/metadata/metedata_program.cpp

  #database
  src/database/database.cpp
  src/database/db_base.cpp
  src/database/db_config.cpp

  #util
  src/util/wallets.cpp
  src/util/signatures.cpp
  src/util/threadpool.cpp
  src/util/base58.cpp
  src/util/base64.cpp
  src/util/guardian_config.cpp
  src/util/hex.cpp
  src/util/strings.cpp
  src/util/threadpool.cpp
  src/util/wallets.cpp
  src/util/solana_subscriber.cpp

  #blake3
  src/blake3/blake3.c
  src/blake3/blake3_portable.c
  src/blake3/blake3_dispatch.c

)

target_include_directories(cpp_processor PRIVATE 
src 
src/util 
src/grpc
src/events
src/database
src/metadata
/usr/include
/usr/local/lib
/usr/local/include 
src/metadata
src/payload
src/blake3

${CMAKE_CURRENT_SOURCE_DIR}/generated
)

link_directories(/usr/lib/x86_64-linux-gnu)

# Add generated protobuf/grpc sources if any
file(GLOB PROTO_SRCS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/generated/*.cc")

target_sources(cpp_processor PRIVATE ${PROTO_SRCS})

# Require linking against the Rust shared library at build time
find_library(RUST_SO NAMES rust_subscriber PATHS ../rust_subscriber/target/debug NO_DEFAULT_PATH)
if(NOT RUST_SO)
  message(FATAL_ERROR "Rust shared library (librust_subscriber.so) not found in ../rust_subscriber/target/debug")
endif()
message(STATUS "Linking with Rust shared lib: ${RUST_SO}")

# Set compile options
add_compile_options(
    -Wswitch
    -Wno-deprecated-declarations
    -Wempty-body
    -Wreturn-type
    -Wparentheses
    -Wno-format
    -Wuninitialized
    -Wunreachable-code
    -Wall
    -fno-strict-aliasing
    -g2
    -gdwarf-2
    -O0
    -fno-omit-frame-pointer
    -fexceptions
    -D_TIME_BITS=64
    -D_FILE_OFFSET_BITS=64
)

target_link_libraries(cpp_processor
  PRIVATE
  ${RUST_SO}
  ${SOLANA_TXN_FFI}
  pthread
  protobuf 
  grpc++ 
  sodium 
  ssl
  crypto
  rocksdb
  leveldb
  nlohmann_json::nlohmann_json
  CURL::libcurl
)


