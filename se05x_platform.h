#ifndef _SE05X_PLATFORM_H
#define _SE05X_PLATFORM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int se05x_platform_init(void);

int se05x_platform_open(void);
void se05x_platform_close(void);

int se05x_platform_i2c_read(uint8_t *buf, size_t buf_sz);
int se05x_platform_i2c_write(const uint8_t *buf, size_t buf_sz);

void se05x_platform_mutex_lock(void);
void se05x_platform_mutex_unlock(void);

void se05x_platform_sleep(uint32_t millis);

void se05x_platform_printf(const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif // _SE05X_PLATFORM_H