#include "fsl_sss_se05x_apis.h"
#include "fsl_sss_se05x_types.h"
#include "se05x_platform.h"
#include "se05x_session.h"

#define SE05X_I2C_ADDR (0x48)

void *se05x_default_session_open(void)
{
    se05x_platform_open();

    sss_status_t status = kStatus_SSS_Fail;

    static sss_se05x_session_t session;
    SE05x_Connect_Ctx_t session_context = (SE05x_Connect_Ctx_t) {
        .sizeOfStucture = sizeof(SE05x_Connect_Ctx_t),
        .auth = (SE_AuthCtx_t) {
            .authType = kSSS_AuthType_None,
        },
        .connType = kType_SE_Conn_Type_T1oI2C,
        .i2cAddress = SE05X_I2C_ADDR,
    };

    status = sss_se05x_session_open(&session, kType_SSS_SE_SE05x, 0, 
                              kSSS_ConnectionType_Plain, &session_context);
    if (status != kStatus_SSS_Success) {
        goto error;
    }

    return &session;

error:
    se05x_platform_close();

    return NULL;
}

void se05x_default_session_close(void *session)
{
    sss_se05x_session_close((sss_se05x_session_t *)session);
    se05x_platform_close();
}