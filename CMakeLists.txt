cmake_minimum_required(VERSION 3.10)
project(delta_compression_framework)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 99)
find_package(Glog REQUIRED)

# +++ 新增：查找 OpenSSL 库 +++
find_package(OpenSSL REQUIRED)

set(CMAKE_BUILD_TYPE Release)

include_directories(${CMAKE_SOURCE_DIR})
# +++ 新增：将 OpenSSL 的头文件目录加入包含路径 +++
include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(chunk)
add_subdirectory(feature)
add_subdirectory(utils)
add_subdirectory(index)
add_subdirectory(storage)
add_subdirectory(3party/xdelta3)
add_subdirectory(encoder)
# add_subdirectory(experiments)
add_library(delta_compression STATIC delta_compression.cpp pipeline_delta_compression.cpp)
#target_link_libraries(delta_compression chunker feature index storage utils xdelta3 glog gflags)
# +++ 修改：在链接列表中加入 OpenSSL 的库文件 (${OPENSSL_LIBRARIES}) +++
target_link_libraries(delta_compression chunker feature index storage utils xdelta3 glog gflags ${OPENSSL_LIBRARIES})

add_executable(delta main.cpp recover_file.cpp)
target_link_libraries(delta delta_compression stdc++fs)
