file(GLOB SRC
            "*.c"
            "../includes/lib/*.h"
    )

add_library(bluetooth SHARED ${SRC}
)
