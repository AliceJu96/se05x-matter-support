#pragma once

typedef enum {
    SE05X_SPAKE2P_PASSCODE_1,
    SE05X_SPAKE2P_PASSCODE_2,
    SE05X_SPAKE2P_PASSCODE_3,
    SE05x_SPAKE2P_PASSCODE_MAX,
} se05x_spake2p_passcode_type_t;

#define SE05X_SPAKE2P_PASSCODE_SIZE (4)
#define SE05X_SPAKE2P_SALT_SIZE     (32)

#ifdef __cplusplus
extern "C" {
#endif

int se05x_spake2p_get_passcode(se05x_spake2p_passcode_type_t passcode_type, 
                               uint32_t *passcode);

int se05x_spake2p_get_salt(se05x_spake2p_passcode_type_t passcode_type, 
                           uint8_t salt[SE05X_SPAKE2P_SALT_SIZE]);

#ifdef __cplusplus
}
#endif