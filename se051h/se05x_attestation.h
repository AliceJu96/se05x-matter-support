#pragma once

#include <stddef.h>
#include <stdint.h>

#include "se05x_config.h"

#if (SE05X_TYPE == SE05X_TYPE_SE051HV2)
#define SE05X_ATTESTATION_DEVICE_KEY_PAIR_ID    (0x7FFF3007)
#define SE05X_ATTESTATION_DEVICE_CERT_ID        (0x7FFF3003)
#define SE05X_ATTESTATION_INTERMEDIATE_CERT_ID  (0x7FFF3004)
#else
#define SE05X_ATTESTATION_DEVICE_KEY_PAIR_ID    (0x40000000)
#define SE05X_ATTESTATION_DEVICE_CERT_ID        (0x40000001)
#define SE05X_ATTESTATION_INTERMEDIATE_CERT_ID  (0x40000002)
#define SE05X_ATTESTATION_CD_ID                 (0x40000003)
#endif

#define SE05X_ATTESTATION_PRIVATE_KEY_SIZE (32)
#define SE05X_ATTESTATION_PUBLIC_KEY_SIZE  (65)
#define SE05X_ATTESTATION_CERT_MAX_SIZE    (604)

#ifdef __cplusplus
extern "C" {
#endif

int se05x_attestation_get_device_key(uint8_t pub_key[SE05X_ATTESTATION_PUBLIC_KEY_SIZE]);

int se05x_attestation_get_device_cert(uint8_t *cert, size_t *cert_size);

int se05x_attestation_get_intermediate_cert(uint8_t *cert, size_t *cert_size);

int se05x_attestation_get_cd(uint8_t *cd, size_t *cd_size);

int se05x_attestation_set_device_key(const uint8_t pub_key[SE05X_ATTESTATION_PUBLIC_KEY_SIZE],
                                     const uint8_t priv_key[SE05X_ATTESTATION_PRIVATE_KEY_SIZE]);

int se05x_attestation_set_device_cert(const uint8_t *cert, size_t cert_size);

int se05x_attestation_set_intermediate_cert(const uint8_t *cert, size_t cert_size);

int se05x_attestation_set_cd(const uint8_t *cd, size_t cd_size);

int se05x_attestation_sign(const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len);

#ifdef __cplusplus
}
#endif