file(GLOB SRC
            "*.c"
            "../includes/lib/*.h"
    )

add_library(aos_bluetooth SHARED ${SRC}
)
