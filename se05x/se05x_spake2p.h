#pragma once

#include <stddef.h>
#include <stdint.h>

typedef enum {
    SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM,
    SE05X_SPAKE2P_PASSCODE_TYPE_RESERVED_1,
    SE05X_SPAKE2P_PASSCODE_TYPE_RESERVED_2,
    SE05X_SPAKE2P_PASSCODE_TYPE_RESERVED_3,
    SE05X_SPAKE2P_PASSCODE_TYPE_MAX,
} se05x_spake2p_passcode_type_t;

#define SE05X_SPAKE2P_W0_SIZE           (32)
#define SE05X_SPAKE2P_L_SIZE            (65)

#ifdef __cplusplus
extern "C" {
#endif

int se05x_spake2p_get_passcode(se05x_spake2p_passcode_type_t passcode_type, 
                               uint32_t *passcode);
int se05x_spake2p_set_passcode(se05x_spake2p_passcode_type_t passcode_type, 
                               uint32_t passcode);

int se05x_spake2p_get_verifier(se05x_spake2p_passcode_type_t passcode_type, 
                               uint8_t w0[SE05X_SPAKE2P_W0_SIZE],
                               uint8_t l[SE05X_SPAKE2P_L_SIZE]);
int se05x_spake2p_set_verifier(se05x_spake2p_passcode_type_t passcode_type, 
                               const uint8_t w0[SE05X_SPAKE2P_W0_SIZE],
                               const uint8_t l[SE05X_SPAKE2P_L_SIZE]);

int se05x_spake2p_get_salt(se05x_spake2p_passcode_type_t passcode_type, 
                           uint8_t *salt, size_t *salt_size);
int se05x_spake2p_set_salt(se05x_spake2p_passcode_type_t passcode_type, 
                           const uint8_t *salt, size_t salt_size);

int se05x_spake2p_get_iter_count(se05x_spake2p_passcode_type_t passcode_type, 
                                 uint32_t *round);
int se05x_spake2p_set_iter_count(se05x_spake2p_passcode_type_t passcode_type, 
                                 uint32_t round);

#ifdef __cplusplus
}
#endif