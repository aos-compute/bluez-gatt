file(GLOB SRC
            "*.c"
            "../includes/src/shared/*.h"
    )

add_library(aos_bt_shared SHARED ${SRC} )
