#include <string.h>
#include "fsl_sss_se05x_apis.h"
#include "se05x_session.h"
#include "se05x_spake2p.h"

#define SE051H_SPAKE2P_KEY_SALT_LIST_ID (0x7FFF2000)

#define BCD_TO_DEC(x) (x - 6 * ((x) >> 4))

typedef struct __attribute__((packed)) {
    uint8_t key[SE05X_SPAKE2P_PASSCODE_SIZE];
    uint8_t salt[SE05X_SPAKE2P_SALT_SIZE];
} se05x_spake2p_key_salt_entry_t;

typedef struct __attribute__((packed)) {
    se05x_spake2p_key_salt_entry_t key_salt_1;
    se05x_spake2p_key_salt_entry_t key_salt_2;
    se05x_spake2p_key_salt_entry_t key_salt_3;
} se05x_spake2p_key_salt_list_t;

static ssize_t se05x_get_binary(uint32_t key_id, uint8_t *buf, size_t buf_size)
{
    sss_se05x_session_t *session = se05x_default_session_open();
    if (!session) {
        return -1;
    }

    sss_status_t status = kStatus_SSS_Fail;
    sss_se05x_key_store_t keystore;    

    status = sss_se05x_key_store_context_init(&keystore, session);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    sss_se05x_object_t object;
    status = sss_se05x_key_object_init(&object, &keystore);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    status = sss_se05x_key_object_get_handle(&object, key_id);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    size_t byte_sz = buf_size;
    size_t bit_sz = buf_size * 8;
    status = sss_se05x_key_store_get_key(&keystore, &object, buf, &byte_sz, &bit_sz);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    se05x_default_session_close(session);

    return (ssize_t)byte_sz;
error:
    se05x_default_session_close(session);

    return -1;
}

int se05x_spake2p_get_passcode(se05x_spake2p_passcode_type_t passcode_type, 
                               uint32_t *passcode)
{
    se05x_spake2p_key_salt_list_t data;
    ssize_t size = se05x_get_binary(SE051H_SPAKE2P_KEY_SALT_LIST_ID, (uint8_t *)&data, sizeof(data));
    if (size <= 0) {
        goto error;
    }

    se05x_spake2p_key_salt_entry_t *entry = &data.key_salt_1;
    if (passcode_type == SE05X_SPAKE2P_PASSCODE_2) {
        entry = &data.key_salt_2;
    } else if (passcode_type == SE05X_SPAKE2P_PASSCODE_3) {
        entry = &data.key_salt_3;
    }

    uint32_t passcode_bcd = 0;
    for (int i = 0; i < SE05X_SPAKE2P_PASSCODE_SIZE; i++) {
        passcode_bcd *= 100;
        passcode_bcd += BCD_TO_DEC(entry->key[i]);
    }

    *passcode = passcode_bcd;

    return 0;
error:
    return -1;
}

int se05x_spake2p_get_salt(se05x_spake2p_passcode_type_t passcode_type, 
                           uint8_t salt[SE05X_SPAKE2P_SALT_SIZE])
{
    se05x_spake2p_key_salt_list_t data;
    ssize_t size = se05x_get_binary(SE051H_SPAKE2P_KEY_SALT_LIST_ID, (uint8_t *)&data, sizeof(data));
    if (size <= 0) {
        goto error;
    }

    se05x_spake2p_key_salt_entry_t *entry = &data.key_salt_1;
    if (passcode_type == SE05X_SPAKE2P_PASSCODE_2) {
        entry = &data.key_salt_2;
    } else if (passcode_type == SE05X_SPAKE2P_PASSCODE_3) {
        entry = &data.key_salt_3;
    }

    memcpy(salt, entry->salt, SE05X_SPAKE2P_SALT_SIZE);

    return 0;
error:
    return -1;
}