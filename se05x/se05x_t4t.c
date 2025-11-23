#include <string.h>
#include "fsl_sss_se05x_apis.h"
#include "fsl_sss_se05x_types.h"
#include "se05x_T4T_APDU_apis.h"
#include "se05x_session.h"
#include "se05x_t4t.h"

static uint8_t ndef_file_id[] = { 0xE1, 0x01 };
static uint8_t ndef_file_header[] = { 0x00, 0x00, 0xD1, 0x01, 0x01, 0x55, 0x00, };

static int build_ndef_file(uint8_t *buf, size_t *buf_size, const uint8_t *data, size_t data_size)
{
    const size_t ndef_header_size = sizeof(ndef_file_header) - 2; // Header: 0xD1 0x01 0x01 0x55 0x00
    size_t ndef_file_size = ndef_header_size + data_size;

    if (*buf_size < (ndef_file_size + 2)) {
        *buf_size = 0;
        return -1;
    }

    memcpy(buf, ndef_file_header, sizeof(ndef_file_header));
    buf[0] = (ndef_file_size >> 8) & 0xFF;
    buf[1] = (ndef_file_size) & 0xFF;
    buf[4] += data_size;

    memcpy(buf + sizeof(ndef_file_header), data, data_size);
    *buf_size = (ndef_file_size + 2);

    return 0;
}

int se05x_t4t_read(uint8_t *data, size_t *data_size)
{
    sss_se05x_session_t *session = se05x_default_session_open();
    if (!session) {
        return -1;
    }

    smStatus_t status = SM_NOT_OK;

    status = Se05x_T4T_API_SelectT4TApplet(&session->s_ctx);
    if (status != SM_OK) {
        goto error;
    }

    status = Se05x_T4T_API_SelectFile(&session->s_ctx, ndef_file_id, sizeof(ndef_file_id));
    if (status != SM_OK) {
        goto error;
    }

    status = Se05x_T4T_API_ReadBinary(&session->s_ctx, data, data_size);
    if (status != SM_OK) {
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}

int se05x_t4t_write(uint8_t *data, size_t data_size)
{  
    sss_se05x_session_t *session = se05x_default_session_open();
    if (!session) {
        return -1;
    }

    smStatus_t status = SM_NOT_OK;


    uint8_t buf[100];
    size_t buf_size = 100;
    build_ndef_file(buf, &buf_size, data, data_size);
    
    status = Se05x_T4T_API_SelectT4TApplet(&session->s_ctx);
    if (status != SM_OK) {
        goto error;
    }

    status = Se05x_T4T_API_SelectFile(&session->s_ctx, ndef_file_id, sizeof(ndef_file_id));
    if (status != SM_OK) {
        goto error;
    }

    status = Se05x_T4T_API_UpdateBinary(&session->s_ctx, buf, buf_size);
    if (status != SM_OK) {
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;
}

int se05x_t4t_get_access_policy(se05x_t4t_interface_t interface, 
                                bool *is_read_allowed, bool *is_write_allowed)
{
    sss_se05x_session_t *session = se05x_default_session_open();
    if (!session) {
        return -1;
    }

    smStatus_t status = SM_NOT_OK;
    
    status = Se05x_T4T_API_SelectT4TApplet(&session->s_ctx);
    if (status != SM_OK) {
        goto error;
    }
    
    SE05x_T4T_Interface_Const_t t4t_interface = (interface == SE05X_T4T_CONTACT_INTERFACE) ? \
        kSE05x_T4T_Interface_Contact : kSE05x_T4T_Interface_Contactless;

    SE05x_T4T_Access_Ctrl_t read_access, write_access;
    status = Se05x_T4T_API_ReadAccessCtrl(&session->s_ctx, t4t_interface, &read_access, &write_access);
    if (status != SM_OK) {
        goto error;
    }

    if (read_access == kSE05x_T4T_AccessCtrl_Granted) {
        *is_read_allowed = true;
    } else {
        *is_read_allowed = false;
    }

    if (write_access == kSE05x_T4T_AccessCtrl_Granted) {
        *is_write_allowed = true;
    } else {
        *is_write_allowed = false;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;   
}

int se05x_t4t_set_access_policy(se05x_t4t_interface_t interface, 
                                bool is_read_allowed, bool is_write_allowed)
{
    sss_se05x_session_t *session = se05x_default_session_open();
    if (!session) {
        return -1;
    }

    smStatus_t status = SM_NOT_OK;
    
    status = Se05x_T4T_API_SelectT4TApplet(&session->s_ctx);
    if (status != SM_OK) {
        goto error;
    }

    SE05x_T4T_Interface_Const_t t4t_interface = (interface == SE05X_T4T_CONTACT_INTERFACE) ? \
        kSE05x_T4T_Interface_Contact : kSE05x_T4T_Interface_Contactless;

    SE05x_T4T_Access_Ctrl_t read_access = is_read_allowed ? kSE05x_T4T_AccessCtrl_Granted : kSE05x_T4T_AccessCtrl_Denied;
    status = Se05x_T4T_API_ConfigureAccessCtrl(&session->s_ctx, t4t_interface, 
                                               kSE05x_T4T_Operation_Read, read_access);
    if (status != SM_OK) {
        goto error;
    }

    SE05x_T4T_Access_Ctrl_t write_access = is_write_allowed ? kSE05x_T4T_AccessCtrl_Granted : kSE05x_T4T_AccessCtrl_Denied;
    status = Se05x_T4T_API_ConfigureAccessCtrl(&session->s_ctx, t4t_interface, 
                                               kSE05x_T4T_Operation_Write, write_access);
    if (status != SM_OK) {
        goto error;
    }

    se05x_default_session_close(session);

    return 0;
error:
    se05x_default_session_close(session);

    return -1;  
}