idf_component_register(SRCS app_main.c
                       INCLUDE_DIRS .
                       REQUIRES im_core im_platform_esp nvs_flash esp_wifi esp_netif esp_event
                                app_update esp_timer)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
