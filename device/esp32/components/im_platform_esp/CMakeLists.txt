set(srcs
    im_crypto_mbedtls.c identity_nvs.c platform_storage.c im_tls.c est_client.c
    mqtt_transport.c ota_ab.c telemetry.c hardening.c)
set(requires im_core mbedtls nvs_flash nvs_sec_provider esp_partition app_update
    esp_http_client esp_https_ota mqtt esp_timer esp_wifi esp_netif lwip driver esp_hw_support
    bootloader_support efuse espressif__libsodium espressif__esp_secure_cert_mgr)
if(CONFIG_IRONMESH_SE_ATECC608)
    list(APPEND srcs identity_atecc.c)
    list(APPEND requires espressif__esp-cryptoauthlib)
endif()
if(CONFIG_IRONMESH_DUT_CONTROL)
    list(APPEND srcs dut_control.c)
    list(APPEND requires esp_driver_usb_serial_jtag)
endif()
idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS include
                       REQUIRES ${requires})
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror -fstack-protector-strong)
