#include <string.h>
#include "fsl_sss_policy.h"
#include "fsl_sss_se05x_apis.h"
#include "se05x_session.h"
#include "se05x_attestation.h"

static const uint8_t keypair_p256_version[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20,
};
static const uint8_t keypair_p256_oid[] = {
    0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x03, 0x01, 0x07, 0xA1, 0x44, 0x03, 0x42,
    0x00,
};

#define KEYPAIR_P256_TYPE (256)
#define KEYPAIR_P256_SIZE (SE05X_ATTESTATION_PUBLIC_KEY_SIZE + SE05X_ATTESTATION_PRIVATE_KEY_SIZE + sizeof(keypair_p256_version) + sizeof(keypair_p256_oid))
#define PUBKEY_P256_SIZE  (SE05X_ATTESTATION_PUBLIC_KEY_SIZE + 26)

int se05x_attestation_get_device_key(uint8_t pub_key[SE05X_ATTESTATION_PUBLIC_KEY_SIZE])
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

    status = sss_se05x_key_object_get_handle(&object, SE05X_ATTESTATION_DEVICE_KEY_PAIR_ID);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    static uint8_t buf[PUBKEY_P256_SIZE];
    size_t byte_size = PUBKEY_P256_SIZE;
    size_t bit_size = PUBKEY_P256_SIZE * 8;
    status = sss_se05x_key_store_get_key(&keystore, &object, buf, &byte_size, &bit_size);
    if (status != kStatus_SSS_Success) {
        goto error;
    }
    size_t pub_key_offset = byte_size - SE05X_ATTESTATION_PUBLIC_KEY_SIZE;
    memcpy(pub_key, buf + pub_key_offset, SE05X_ATTESTATION_PUBLIC_KEY_SIZE);

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}

int se05x_attestation_get_device_cert(uint8_t *cert, size_t *cert_size)
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

    status = sss_se05x_key_object_get_handle(&object, SE05X_ATTESTATION_DEVICE_CERT_ID);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    size_t bit_size = (*cert_size) * 8;
    status = sss_se05x_key_store_get_key(&keystore, &object, cert, cert_size, &bit_size);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}

int se05x_attestation_get_intermediate_cert(uint8_t *cert, size_t *cert_size)
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

    status = sss_se05x_key_object_get_handle(&object, SE05X_ATTESTATION_INTERMEDIATE_CERT_ID);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    size_t bit_size = (*cert_size) * 8;
    status = sss_se05x_key_store_get_key(&keystore, &object, cert, cert_size, &bit_size);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}

int se05x_attestation_get_cd(uint8_t *cd, size_t *cd_size)
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

    status = sss_se05x_key_object_get_handle(&object, SE05X_ATTESTATION_CD_ID);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    size_t bit_size = (*cd_size) * 8;
    status = sss_se05x_key_store_get_key(&keystore, &object, cd, cd_size, &bit_size);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}

int se05x_attestation_set_device_key(const uint8_t pub_key[SE05X_ATTESTATION_PUBLIC_KEY_SIZE],
                                     const uint8_t priv_key[SE05X_ATTESTATION_PRIVATE_KEY_SIZE])
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

    static const int NIST_P256_KEY_SIZE = 256 / 8;
    status = sss_se05x_key_object_get_handle(&object, SE05X_ATTESTATION_DEVICE_KEY_PAIR_ID);
    if (status != kStatus_SSS_Success) {
        status = sss_se05x_key_object_allocate_handle(&object, SE05X_ATTESTATION_DEVICE_KEY_PAIR_ID,
                                                      kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P,
                                                      NIST_P256_KEY_SIZE, kKeyObject_Mode_Persistent);
        if (status != kStatus_SSS_Success) {
            goto error;
        }
    }

    uint8_t keypair[KEYPAIR_P256_SIZE];
    uint8_t *p_keypair = keypair;
    
    memcpy(p_keypair, keypair_p256_version, sizeof(keypair_p256_version));
    p_keypair += sizeof(keypair_p256_version);

    memcpy(p_keypair, priv_key, SE05X_ATTESTATION_PRIVATE_KEY_SIZE);
    p_keypair += SE05X_ATTESTATION_PRIVATE_KEY_SIZE;

    memcpy(p_keypair, keypair_p256_oid, sizeof(keypair_p256_oid));
    p_keypair += sizeof(keypair_p256_oid);

    memcpy(p_keypair, pub_key, SE05X_ATTESTATION_PUBLIC_KEY_SIZE);

    status = sss_se05x_key_store_set_key(&keystore, &object, keypair, KEYPAIR_P256_SIZE, KEYPAIR_P256_TYPE, NULL, 0);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}

int se05x_attestation_set_device_cert(const uint8_t *cert, size_t cert_size)
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

    status = sss_se05x_key_object_get_handle(&object, SE05X_ATTESTATION_DEVICE_CERT_ID);
    if (status != kStatus_SSS_Success) {
        status = sss_se05x_key_object_allocate_handle(&object, SE05X_ATTESTATION_DEVICE_CERT_ID,
                                                      kSSS_KeyPart_Default, kSSS_CipherType_Binary,
                                                      SE05X_ATTESTATION_CERT_MAX_SIZE, 
                                                      kKeyObject_Mode_Persistent);
        if (status != kStatus_SSS_Success) {
            goto error;
        }
    }

    status = sss_se05x_key_store_set_key(&keystore, &object, cert, cert_size, 0, NULL, 0);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}

int se05x_attestation_set_intermediate_cert(const uint8_t *cert, size_t cert_size)
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

    status = sss_se05x_key_object_get_handle(&object, SE05X_ATTESTATION_INTERMEDIATE_CERT_ID);
    if (status != kStatus_SSS_Success) {
        status = sss_se05x_key_object_allocate_handle(&object, SE05X_ATTESTATION_INTERMEDIATE_CERT_ID,
                                                      kSSS_KeyPart_Default, kSSS_CipherType_Binary,
                                                      SE05X_ATTESTATION_CERT_MAX_SIZE, 
                                                      kKeyObject_Mode_Persistent);
        if (status != kStatus_SSS_Success) {
            goto error;
        }
    }

    status = sss_se05x_key_store_set_key(&keystore, &object, cert, cert_size, 0, NULL, 0);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}

int se05x_attestation_set_cd(const uint8_t *cd, size_t cd_size)
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

    status = sss_se05x_key_object_get_handle(&object, SE05X_ATTESTATION_CD_ID);
    if (status != kStatus_SSS_Success) {
        status = sss_se05x_key_object_allocate_handle(&object, SE05X_ATTESTATION_CD_ID,
                                                      kSSS_KeyPart_Default, kSSS_CipherType_Binary,
                                                      SE05X_ATTESTATION_CERT_MAX_SIZE, 
                                                      kKeyObject_Mode_Persistent);
        if (status != kStatus_SSS_Success) {
            goto error;
        }
    }

    status = sss_se05x_key_store_set_key(&keystore, &object, cd, cd_size, 0, NULL, 0);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}

#define ECDSA_P256_SIG_DER_SIZE (72)
#define ECDSA_P256_SIG_SIZE     (64)
#define ECDSA_P256_KEY_SIZE     (32)

static int parse_ecdsa_der_p256(uint8_t sig[ECDSA_P256_SIG_SIZE],
                                const uint8_t sig_der[ECDSA_P256_SIG_DER_SIZE])
{
    size_t idx = 0;

    if (sig_der[idx++] != 0x30) {
        return -1;
    }

    uint8_t sig_len = sig_der[idx++];
    if (sig_len + 2 > ECDSA_P256_SIG_DER_SIZE) {
        return -2;
    }

    if (sig_der[idx++] != 0x02) {
        return -3;
    }
    size_t r_len = sig_der[idx++];
    const uint8_t *r = &sig_der[idx];
    
    idx += r_len;;

    if (sig_der[idx++] != 0x02) {
        return -5;
    }
    size_t s_len = sig_der[idx++];
    const uint8_t *s = &sig_der[idx];
    
    memset(sig, 0, ECDSA_P256_SIG_SIZE);

    /* r -> sig[0..31] */
    {
        size_t copy_r = (r_len > ECDSA_P256_KEY_SIZE) ? ECDSA_P256_KEY_SIZE : r_len;
        size_t off_r  = (r_len > ECDSA_P256_KEY_SIZE) ? (r_len - ECDSA_P256_KEY_SIZE) : 0u;

        memcpy(sig + (ECDSA_P256_KEY_SIZE - copy_r), r + off_r, copy_r);
    }

    /* s -> sig[32..63] */
    {
        size_t copy_s = (s_len > ECDSA_P256_KEY_SIZE) ? ECDSA_P256_KEY_SIZE : s_len;
        size_t off_s  = (s_len > ECDSA_P256_KEY_SIZE) ? (s_len - ECDSA_P256_KEY_SIZE) : 0u;

        memcpy(sig + ECDSA_P256_KEY_SIZE + (ECDSA_P256_KEY_SIZE - copy_s),
               s + off_s, copy_s);
    }

    return 0;
}

int se05x_attestation_sign(const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len)
{
    sss_se05x_session_t *session = se05x_default_session_open();
    if (!session) {
        return -1;
    }

    sss_status_t status = kStatus_SSS_Fail;

    sss_se05x_digest_t digest_context;
    status = sss_se05x_digest_context_init(&digest_context, session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    uint8_t sha256_buf[32];
    memset(sha256_buf, 0, sizeof(sha256_buf));

    size_t sha256_buf_len = 32;
    status = sss_se05x_digest_one_go(&digest_context, msg, msg_len, sha256_buf, &sha256_buf_len);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

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

    status = sss_se05x_key_object_get_handle(&object, SE05X_ATTESTATION_DEVICE_KEY_PAIR_ID);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    sss_se05x_asymmetric_t assymetric_context;
    status = sss_se05x_asymmetric_context_init(&assymetric_context, session, &object, 
                                               kAlgorithm_SSS_ECDSA_SHA256, kMode_SSS_Sign);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    uint8_t sig_buf[72];
    size_t sig_buf_len = 72;
    status = sss_se05x_asymmetric_sign_digest(&assymetric_context, sha256_buf, sha256_buf_len, sig_buf, &sig_buf_len);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    sss_se05x_asymmetric_context_free(&assymetric_context);

    if (*sig_len < ECDSA_P256_SIG_SIZE) {
        goto error;
    }

    int err = parse_ecdsa_der_p256(sig, sig_buf);
    if (err) {
        goto error;
    }
    *sig_len = ECDSA_P256_SIG_SIZE;

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}