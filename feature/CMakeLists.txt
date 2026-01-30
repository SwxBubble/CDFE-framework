add_library(feature STATIC features.cpp)
# +++ 修改：添加 ${OPENSSL_LIBRARIES} +++
target_link_libraries(feature glog gflags ${OPENSSL_LIBRARIES})
#target_link_libraries(feature glog gflags)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
