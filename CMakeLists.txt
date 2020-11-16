cmake_minimum_required(VERSION 3.0)

project(bluez-gatt)

find_package (PkgConfig REQUIRED)
#pkg_check_modules (GLIB REQUIRED glib-2.0)

#pkg_check_modules(DBUS dbus-1) # This calls pkgconfig with appropriate arguments
# Use results of pkg_check_modules() call.
#include_directories(${DBUS_INCLUDE_DIRS})
#link_directories(${DBUS_LIBRARY_DIRS})

PKG_SEARCH_MODULE( NETWORKMANAGER NetworkManager )
PKG_SEARCH_MODULE( NM-UTIL libnm-util )

#include_directories (${GLIB_INCLUDE_DIRS})
#link_directories (${GLIB_LIBRARY_DIRS})

#include_directories (${NETWORKMANAGER_INCLUDE_DIRS})
#link_directories (${NETWORKMANAGER_LIBRARY_DIRS})

#set(DBUS_GLIB_INCLUDE_DIRS
#    "${DBUS_GLIB_INCLUDE_DIR}/dbus-1.0" "${DBUS_GLIB_LOWLEVEL_INCLUDE_DIR}"
#)

include_directories(includes)
include_directories(includes/src/shared)
include_directories(includes/lib)

add_subdirectory(libbluetooth)
add_subdirectory(libshared)


file(GLOB SRC
            "*.h"
            "*.c"
            "includes/*.h"
            "includes/src/shared/*.h"
            "includes/lib/*.h"
    )

set(CMAKE_C_FLAGS "-no-pie -Wno-unused-but-set-parameter -Wno-unused-variable -Wno-unused-parameter -Wno-format -Wno-unused-const-variable -Wno-unused-result -Wno-pointer-sign")

SET(DBUILD_SHARED_LIBS ON)

# btgatt-server
#add_executable(btgatt-server
#    btgatt-server.c includes/btgatt-server.h)

#target_link_libraries(btgatt-server aos_bluetooth aos_bt_shared)

#pkg_check_modules(LIB_NM REQUIRED dbus-1 glib-2.0 dbus-glib-1 libnm-glib libnm-util)
#include_directories(${LIB_NM_INCLUDE_DIRS})
#link_directories(${LIB_NM_LIBRARY_DIRS})
#target_link_libraries(btgatt-server ${GLIB_LIBRARIES}  ${LIB_NM_LIBRARIES})

add_library(${PROJECT_NAME} SHARED ${SRC})
target_link_libraries(${PROJECT_NAME} aos_bluetooth aos_bt_shared)

#include_directories(${PROJECT_NAME} ${NETWORKMANAGER_INCLUDE_DIRS})

install(TARGETS aos_bt_shared LIBRARY DESTINATION shared_libs)
install(TARGETS aos_bluetooth LIBRARY DESTINATION shared_libs)
install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION shared_libs)
install(DIRECTORY includes DESTINATION include)

