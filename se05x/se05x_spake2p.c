#include <assert.h>
#include <string.h>
#include "fsl_sss_se05x_apis.h"
#include "se05x_session.h"
#include "se05x_spake2p.h"

typedef enum {
    ERROR_GENERIC = -100,
    ERROR_WRONG_PARAM,
    ERROR_SESSION = -200,
    ERROR_SESSION_OPEN,
    ERROR_KEYOBJECT = -300,
    ERROR_KEYOBJECT_INIT,
    ERROR_KEYOBJECT_ALLOCATE,
    ERROR_KEYOBJECT_NOT_EXIST,
    ERROR_KEYOBJECT_EMPTY,
    ERROR_KEYOBJECT_WRONG_SIZE,
    ERROR_KEYOBJECT_GET,
    ERROR_KEYOBJECT_SET,
} se05x_spake2p_error_t;

#define SE05X_SPAKE2P_CUSTOM_KEY_ID        (0x20000000)
#define SE05X_SPAKE2P_CUSTOM_SALT_ID       (0x20000001)
#define SE05X_SPAKE2P_CUSTOM_W0_ID         (0x20000002)
#define SE05X_SPAKE2P_CUSTOM_L_ID          (0x20000003)
#define SE05X_SPAKE2P_CUSTOM_ITER_COUNT_ID (0x20000004)

#define SE05X_SPAKE2P_RESERVED_KEY_SALT_LIST_ID (0x7FFF2000)
#define SE05X_SPAKE2P_RESERVED_W0_LIST_ID       (0x7FFF2011)
#define SE05X_SPAKE2P_RESERVED_L_LIST_ID        (0x7FFF2021)

#define SE05X_RESERVED_PASSCODE_NUM  (3)
#define SE05X_RESERVED_PASSCODE_SIZE (4)
#define SE05X_RESERVED_SALT_SIZE     (32)

#define BCD_TO_DEC(x) ((x) - 6 * ((x) >> 4))
#define DEC_TO_BCD(x) ((((x) / 10) << 4) | ((x) % 10))

typedef struct __attribute__((packed)) {
    uint8_t key[SE05X_RESERVED_PASSCODE_SIZE];
    uint8_t salt[SE05X_RESERVED_SALT_SIZE];
} se05x_spake2p_key_salt_entry_t;

typedef struct __attribute__((packed)) {
    se05x_spake2p_key_salt_entry_t entries[SE05X_RESERVED_PASSCODE_NUM];
} se05x_spake2p_key_salt_list_t;

static int se05x_set_binary(uint32_t key_id, const uint8_t *buf, size_t buf_size)
{
    se05x_spake2p_error_t rc = ERROR_GENERIC;

    sss_se05x_session_t *session = se05x_default_session_open();
    if (!session) {
        return ERROR_SESSION_OPEN;
    }

    sss_status_t status = kStatus_SSS_Fail;

    sss_se05x_key_store_t keystore;
    status = sss_se05x_key_store_context_init(&keystore, session);
    if (status != kStatus_SSS_Success) {
        rc = ERROR_KEYOBJECT_INIT;
        goto error;
    }

    sss_se05x_object_t object;
    status = sss_se05x_key_object_init(&object, &keystore);
    if (status != kStatus_SSS_Success) {
        rc = ERROR_KEYOBJECT_INIT;
        goto error;
    }

    status = sss_se05x_key_object_get_handle(&object, key_id);
    if (status != kStatus_SSS_Success) {
        status = sss_se05x_key_object_allocate_handle(&object, key_id, kSSS_KeyPart_Default, 
                                                      kSSS_CipherType_Binary, buf_size, 
                                                      kKeyObject_Mode_Persistent);
        if (status != kStatus_SSS_Success) {
            rc = ERROR_KEYOBJECT_ALLOCATE;
            goto error;
        }
    }

    status = sss_se05x_key_store_set_key(&keystore, &object, buf, buf_size, 0, NULL, 0);
    if (status != kStatus_SSS_Success) {
        rc = ERROR_KEYOBJECT_SET;
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return rc;
}


static int se05x_get_binary(uint32_t key_id, uint8_t *buf, size_t *buf_size)
{
    se05x_spake2p_error_t rc = ERROR_GENERIC;

    sss_se05x_session_t *session = se05x_default_session_open();
    if (!session) {
        return ERROR_SESSION_OPEN;
    }

    sss_status_t status = kStatus_SSS_Fail;

    sss_se05x_key_store_t keystore;    
    status = sss_se05x_key_store_context_init(&keystore, session);
    if (status != kStatus_SSS_Success) {
        rc = ERROR_KEYOBJECT_INIT;
        goto error;
    }

    sss_se05x_object_t object;
    status = sss_se05x_key_object_init(&object, &keystore);
    if (status != kStatus_SSS_Success) {
        rc = ERROR_KEYOBJECT_INIT;
        goto error;
    }

    status = sss_se05x_key_object_get_handle(&object, key_id);
    if (status != kStatus_SSS_Success) {
        rc = ERROR_KEYOBJECT_NOT_EXIST;
        goto error;
    }

    size_t bit_size = (*buf_size) * 8;
    status = sss_se05x_key_store_get_key(&keystore, &object, buf, buf_size, &bit_size);
    if (status != kStatus_SSS_Success) {
        rc = ERROR_KEYOBJECT_GET;
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return rc;
}

static int se05x_spake2p_get_custom_passcode(uint32_t *passcode)
{
    uint8_t passcode_bcd[SE05X_RESERVED_PASSCODE_SIZE];
    size_t passcode_bcd_size = sizeof(passcode_bcd);

    memset(passcode_bcd, 0, sizeof(passcode_bcd));
    
    int err = se05x_get_binary(SE05X_SPAKE2P_CUSTOM_KEY_ID, passcode_bcd, &passcode_bcd_size);
    if (err) {
        return err;
    }
    if (passcode_bcd_size != SE05X_RESERVED_PASSCODE_SIZE) {
        return ERROR_KEYOBJECT_WRONG_SIZE;
    }

    uint32_t _passcode = 0;
    for (int i = 0; i < SE05X_RESERVED_PASSCODE_SIZE; i++) {
        _passcode *= 100;
        _passcode += BCD_TO_DEC(passcode_bcd[i]);
    }

    *passcode = _passcode;

    return 0;
}

static int se05x_spake2p_get_reserved_passcode(int id, uint32_t *passcode)
{
    se05x_spake2p_key_salt_list_t key_list;
    size_t key_list_size = sizeof(key_list);

    int err = se05x_get_binary(SE05X_SPAKE2P_RESERVED_KEY_SALT_LIST_ID, (uint8_t *)&key_list, &key_list_size);
    if (err) {
        return err;
    }
    if (key_list_size < sizeof(se05x_spake2p_key_salt_list_t)) {
        return ERROR_KEYOBJECT_WRONG_SIZE;
    }

    se05x_spake2p_key_salt_entry_t *entry = &key_list.entries[id - 1];

    uint32_t _passcode = 0;
    for (int i = 0; i < SE05X_RESERVED_PASSCODE_SIZE; i++) {
        _passcode *= 100;
        _passcode += BCD_TO_DEC(entry->key[i]);
    }

    *passcode = _passcode;

    return 0;
}

int se05x_spake2p_get_passcode(se05x_spake2p_passcode_type_t passcode_type, uint32_t *passcode)
{
    assert(passcode_type < SE05X_SPAKE2P_PASSCODE_TYPE_MAX);
    assert(passcode);

    if (passcode_type == SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM) {
        return se05x_spake2p_get_custom_passcode(passcode);
    } else {
        int id = passcode_type - SE05X_SPAKE2P_PASSCODE_TYPE_RESERVED_1 + 1;
        return se05x_spake2p_get_reserved_passcode(id, passcode);
    }
}

int se05x_spake2p_set_passcode(se05x_spake2p_passcode_type_t passcode_type, 
                               uint32_t passcode)
{
    assert(passcode_type < SE05X_SPAKE2P_PASSCODE_TYPE_MAX);

    if (passcode_type != SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM) {
        return ERROR_WRONG_PARAM;
    }

    uint8_t passcode_bcd[SE05X_RESERVED_PASSCODE_SIZE];
    for (int i = SE05X_RESERVED_PASSCODE_SIZE; i > 0; i--) {
        uint8_t two_digit = passcode % 100;
        passcode /= 100;

        passcode_bcd[i - 1] = DEC_TO_BCD(two_digit);
    }

    return se05x_set_binary(SE05X_SPAKE2P_CUSTOM_KEY_ID, passcode_bcd, SE05X_RESERVED_PASSCODE_SIZE);
}

int se05x_spake2p_get_verifier(se05x_spake2p_passcode_type_t passcode_type, 
                               uint8_t w0[SE05X_SPAKE2P_W0_SIZE],
                               uint8_t l[SE05X_SPAKE2P_L_SIZE])
{
    assert(passcode_type < SE05X_SPAKE2P_PASSCODE_TYPE_MAX);
    assert(w0);
    assert(l);

    if (passcode_type != SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM) {
        return ERROR_WRONG_PARAM;
    }

    size_t w0_size = SE05X_SPAKE2P_W0_SIZE;
    int err = se05x_get_binary(SE05X_SPAKE2P_CUSTOM_W0_ID, w0, &w0_size);
    if (err) {
        return err;
    }
    if (w0_size != SE05X_SPAKE2P_W0_SIZE) {
        return ERROR_KEYOBJECT_WRONG_SIZE;
    }

    size_t l_size = SE05X_SPAKE2P_L_SIZE;
    err = se05x_get_binary(SE05X_SPAKE2P_CUSTOM_L_ID, l, &l_size);
    if (err) {
        return err;
    }
    if (l_size != SE05X_SPAKE2P_L_SIZE) {
        return ERROR_KEYOBJECT_WRONG_SIZE;
    }

    return 0;
}

int se05x_spake2p_set_verifier(se05x_spake2p_passcode_type_t passcode_type, 
                               const uint8_t w0[SE05X_SPAKE2P_W0_SIZE],
                               const uint8_t l[SE05X_SPAKE2P_L_SIZE])
{
    assert(passcode_type < SE05X_SPAKE2P_PASSCODE_TYPE_MAX);
    assert(w0);
    assert(l);

    if (passcode_type != SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM) {
        return ERROR_WRONG_PARAM;
    }

    int err = se05x_set_binary(SE05X_SPAKE2P_CUSTOM_W0_ID, w0, SE05X_SPAKE2P_W0_SIZE);
    if (err) {
        return err;
    }

    err = se05x_set_binary(SE05X_SPAKE2P_CUSTOM_L_ID, l, SE05X_SPAKE2P_L_SIZE);
    if (err) {
        return err;
    }

    return 0;
}

static int se05x_spake2p_get_custom_salt(uint8_t salt[SE05X_RESERVED_SALT_SIZE], size_t *salt_size)
{
    int err = se05x_get_binary(SE05X_SPAKE2P_CUSTOM_SALT_ID, salt, salt_size);
    if (err) {
        return err;
    }
    if (*salt_size == 0) {
        return ERROR_KEYOBJECT_EMPTY;
    }

    return 0;
}

static int se05x_spake2p_get_reserved_salt(int id, uint8_t *salt, size_t *salt_size)
{
    se05x_spake2p_key_salt_list_t salt_list;
    size_t salt_list_size = sizeof(salt_list);

    int err = se05x_get_binary(SE05X_SPAKE2P_RESERVED_KEY_SALT_LIST_ID, (uint8_t *)&salt_list, &salt_list_size);
    if (err) {
        return err;
    }
    if (salt_list_size < sizeof(se05x_spake2p_key_salt_list_t)) {
        return ERROR_KEYOBJECT_WRONG_SIZE;
    }

    se05x_spake2p_key_salt_entry_t *entry = &salt_list.entries[id - 1];
    memcpy(salt, entry->salt, SE05X_RESERVED_SALT_SIZE);

    *salt_size = SE05X_RESERVED_SALT_SIZE;

    return 0;
}

int se05x_spake2p_get_salt(se05x_spake2p_passcode_type_t passcode_type, 
                           uint8_t *salt, size_t *salt_size)
{
    assert(passcode_type < SE05X_SPAKE2P_PASSCODE_TYPE_MAX);
    assert(salt);
    assert(salt_size);

    if (passcode_type == SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM) {
        return se05x_spake2p_get_custom_salt(salt, salt_size);
    } else {
        int id = passcode_type - SE05X_SPAKE2P_PASSCODE_TYPE_RESERVED_1 + 1;
        return se05x_spake2p_get_reserved_salt(id, salt, salt_size);
    }
}

int se05x_spake2p_set_salt(se05x_spake2p_passcode_type_t passcode_type, 
                           const uint8_t *salt, size_t salt_size)
{
    assert(passcode_type < SE05X_SPAKE2P_PASSCODE_TYPE_MAX);
    assert(salt);

    if (passcode_type != SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM) {
        return ERROR_WRONG_PARAM;
    }

    return se05x_set_binary(SE05X_SPAKE2P_CUSTOM_SALT_ID, salt, salt_size);
}

int se05x_spake2p_get_iter_count(se05x_spake2p_passcode_type_t passcode_type, uint32_t *round)
{
    assert(passcode_type < SE05X_SPAKE2P_PASSCODE_TYPE_MAX);
    assert(round);

    if (passcode_type != SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM) {
        return ERROR_WRONG_PARAM;
    }

    uint8_t iter_count[4];
    size_t iter_count_size = sizeof(iter_count);

    int err = se05x_get_binary(SE05X_SPAKE2P_CUSTOM_ITER_COUNT_ID, iter_count, &iter_count_size);
    if (err) {
        return err;
    }
    if (iter_count_size != 4) {
        return ERROR_KEYOBJECT_WRONG_SIZE;
    }
    
    uint32_t _round = 0;
    for (int i = 0; i < 4; i++) {
        _round <<= 8;
        _round |= (uint32_t)iter_count[i];

    }
    *round = _round;

    return 0;
}

int se05x_spake2p_set_iter_count(se05x_spake2p_passcode_type_t passcode_type, uint32_t round)
{
    assert(passcode_type < SE05X_SPAKE2P_PASSCODE_TYPE_MAX);

    if (passcode_type != SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM) {
        return ERROR_WRONG_PARAM;
    }

    uint8_t iter_count[4];
    for (int i = 4 - 1; i >= 0; i--) {
        iter_count[i] = (uint8_t)(round & 0xFF);
        round >>= 8;
    }
    
    int err = se05x_set_binary(SE05X_SPAKE2P_CUSTOM_ITER_COUNT_ID, iter_count, sizeof(iter_count));
    if (err) {
        return err;
    }

    return 0;
}