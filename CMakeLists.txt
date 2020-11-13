cmake_minimum_required(VERSION 3.0)

project(bluez-gatt)

find_package (PkgConfig REQUIRED)
pkg_check_modules (GLIB REQUIRED glib-2.0)

pkg_check_modules(DBUS dbus-1) # This calls pkgconfig with appropriate arguments
# Use results of pkg_check_modules() call.
include_directories(${DBUS_INCLUDE_DIRS})
link_directories(${DBUS_LIBRARY_DIRS})

PKG_SEARCH_MODULE( NETWORKMANAGER NetworkManager )
PKG_SEARCH_MODULE( NM-UTIL libnm-util )

include_directories (${GLIB_INCLUDE_DIRS})
link_directories (${GLIB_LIBRARY_DIRS})

include_directories (${NETWORKMANAGER_INCLUDE_DIRS})
link_directories (${NETWORKMANAGER_LIBRARY_DIRS})

set(DBUS_GLIB_INCLUDE_DIRS
    "${DBUS_GLIB_INCLUDE_DIR}/dbus-1.0" "${DBUS_GLIB_LOWLEVEL_INCLUDE_DIR}"
)

include_directories(includes)
include_directories(includes/src/shared)
include_directories(includes/lib)


#include_directories(includes/glib-2.0)
#include_directories(${DBUS_INCLUDE_DIR})
#include_directories(${DBUS_GLIB_INCLUDE_DIRS})
#link_directories (${DBUS_GLIB_INCLUDE_DIRS})
#include_directories(${NETWORKMANAGER_INCLUDE_DIRS})
#include_directories(${DBUS_GLIB_INCLUDE_DIR})


add_subdirectory(libbluetooth)
add_subdirectory(libshared)

set(CMAKE_C_FLAGS "-Wno-unused-but-set-parameter -Wno-unused-variable -Wno-unused-parameter -Wno-format -Wno-unused-const-variable -Wno-unused-result -Wno-pointer-sign")

# btgatt-client
add_executable(btgatt-client
    btgatt-client.c)

target_link_libraries(btgatt-client bluetooth shared)

# btgatt-server
add_executable(btgatt-server
    btgatt-server.c btgatt-server.h)

target_link_libraries(btgatt-server bluetooth shared)
#target_link_libraries(btgatt-server ${GLIB_LIBRARIES} ${NMLIB_LIBRARIES} ${NMLIB_LIBRARY_DIRS} ${NM-UTIL_LIBRARY_DIRS} ${NETWORKMANAGER_LIBRARIES} ${NETWORKMANAGER_LIBRARY_DIRS} ${NM-UTIL_LIBRARY_DIRS})


pkg_check_modules(LIB_NM REQUIRED dbus-1 glib-2.0 dbus-glib-1 libnm-glib libnm-util)
include_directories(${LIB_NM_INCLUDE_DIRS})
link_directories(${LIB_NM_LIBRARY_DIRS})
target_link_libraries(btgatt-server ${GLIB_LIBRARIES}  ${LIB_NM_LIBRARIES})

# thingy.c
add_executable(thingy
    thingy.c)

target_link_libraries(thingy bluetooth shared)

add_library(${PROJECT_NAME} SHARED btgatt-server.c btgatt-server.h)

include_directories(${PROJECT_NAME} ${NETWORKMANAGER_INCLUDE_DIRS})

