# Portable protocol core: no ESP-IDF dependencies (also built on the host by host/core-tests).
# The DUT dispatcher is only compiled into images that enable the test hook.
set(srcs
    im_agent.c im_attest.c im_cbor.c im_cose.c im_delta.c im_envelope.c im_fields.c
    im_hpke.c im_ids.c im_json.c im_keyslot.c im_manifest.c im_mqtt.c im_ota.c im_ringbuf.c
    im_util.c)
if(CONFIG_IRONMESH_DUT_CONTROL)
    list(APPEND srcs im_dut.c)
endif()
idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS include
                       PRIV_INCLUDE_DIRS .)
# Same strictness as the host build (-Wall -Wextra -Werror is the IDF default + these).
target_compile_options(${COMPONENT_LIB} PRIVATE -std=gnu99 -Wall -Wextra -Werror -Wshadow
                       -Wconversion -Wno-sign-conversion -fstack-protector-strong)
