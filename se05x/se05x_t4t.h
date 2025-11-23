#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SE05X_T4T_CONTACT_INTERFACE,
    SE05X_T4T_CONTACTLESS_INTERFACE,
    SE05X_T4T_MAX_INTERFACE,
} se05x_t4t_interface_t;

int se05x_t4t_read(uint8_t *data, size_t *data_size);   // read operation via I2C will not work
int se05x_t4t_write(uint8_t *data, size_t data_size);

int se05x_t4t_get_access_policy(se05x_t4t_interface_t interface, 
                                bool *is_read_allowed, bool *is_write_allowed);
int se05x_t4t_set_access_policy(se05x_t4t_interface_t interface, 
                                bool is_read_allowed, bool is_write_allowed);

#ifdef __cplusplus
}
#endif