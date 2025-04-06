# Embed the server root certificate into the final binary
#
# (If this was a component, we would set COMPONENT_EMBED_TXTFILES here.)
idf_component_register(SRCS "ppp_connect.c" "https_request_example_main.c" "time_sync.c" "stdin_out.c" "addr_from_stdin.c" "connect.c" "wifi_connect.c" "protocol_examples_utils.c"
                    INCLUDE_DIRS "include"
                    EMBED_TXTFILES index.html)
if(CONFIG_EXAMPLE_PROVIDE_WIFI_CONSOLE_CMD)
                    idf_component_optional_requires(PRIVATE console)
endif()
                