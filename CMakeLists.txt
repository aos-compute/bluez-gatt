cmake_minimum_required(VERSION 3.0)

project(bluez-gatt)

find_package (PkgConfig REQUIRED)


PKG_SEARCH_MODULE( NETWORKMANAGER NetworkManager )
PKG_SEARCH_MODULE( NM-UTIL libnm-util )

include_directories(includes)
include_directories(includes/src/shared)
include_directories(includes/lib)

add_subdirectory(libbluetooth)
add_subdirectory(libshared)


file(GLOB SRC
            "*.h"
            "*.c"
            "libbluetooth/*.c"
            "libshared/*.c"
            "includes/*.h"
            "includes/src/shared/*.h"
            "includes/lib/*.h"
    )

set(CMAKE_C_FLAGS "-no-pie -Wno-unused-but-set-parameter -Wno-unused-variable -Wno-unused-parameter -Wno-format -Wno-unused-const-variable -Wno-unused-result -Wno-pointer-sign")

SET(DBUILD_SHARED_LIBS ON)

# btgatt-server
add_executable(main main.c)


add_library(${PROJECT_NAME} SHARED ${SRC})

target_link_libraries(main ${PROJECT_NAME})

message(STATUS "installation path: ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/shared_libs")

install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/shared_libs)
install(DIRECTORY includes DESTINATION ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/include)

