file(GLOB SRC
            "*.c"
            "../includes/src/shared/*.h"
    )

add_library(shared SHARED ${SRC} )
