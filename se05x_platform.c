#include <stdbool.h>
#include <stdarg.h>
#include "i2c_a7.h"
#include "sm_timer.h"
#include "nxLog.h"
#include "se05x_platform.h"

int __attribute__((weak)) se05x_platform_init(void) { return -1; }
int __attribute__((weak)) se05x_platform_open(void) { return -1; }
void __attribute__((weak)) se05x_platform_close(void) { }
int __attribute__((weak)) se05x_platform_i2c_read(uint8_t *buf, size_t buf_sz) { return -1; }
int __attribute__((weak)) se05x_platform_i2c_write(const uint8_t *buf, size_t buf_sz) { return -1; }
void __attribute__((weak)) se05x_platform_mutex_lock(void) { }
void __attribute__((weak)) se05x_platform_mutex_unlock(void) { }
void __attribute__((weak)) se05x_platform_sleep(uint32_t millis) { }
void __attribute__((weak)) se05x_platform_printf(const char *format, ...) { }

static int backoff_delay_ms;

void sm_sleep(uint32_t msec)
{
    se05x_platform_sleep(msec);
}

i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName)
{
    backoff_delay_ms = 1;

    return I2C_OK;
}

i2c_error_t axI2CRead(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pRx, unsigned short rxLen)
{
    int err = se05x_platform_i2c_read(pRx, rxLen);
    if (err) {
        return I2C_FAILED;
    }
    return I2C_OK;
}

i2c_error_t axI2CWrite(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pTx, unsigned short txLen)
{
    int err = se05x_platform_i2c_write(pTx, txLen);
    if (err) {
        return I2C_FAILED;
    }
    return I2C_OK;
}

void axI2CResetBackoffDelay(void)
{
    backoff_delay_ms *= 2;

    se05x_platform_sleep(backoff_delay_ms);
}

void axI2CTerm(void* conn_ctx, int mode)
{
    // nothing to do
}

uint8_t nLog_Init(void)
{
    // nothing to do
    return 0;
}

void nLog_DeInit(void)
{
    // nothing to do
}

void nLog(const char *comp, int level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    se05x_platform_printf(fmt, args);
    se05x_platform_printf("\n");
    va_end(args);
}

void nLog_au8(const char *comp, int level, const char *message, const unsigned char *array, size_t array_len)
{
    // TODO
}

void sm_printf(unsigned char dev, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    se05x_platform_printf(fmt, args);
    va_end(args);
}

void AssertZeroAllocation(void)
{
    // TODO
}

int se05x_host_gpio_init(void)
{
    return 0;
}

int se05x_host_gpio_deinit()
{
    return 0;
}

int se05x_host_gpio_set_value(bool value)
{
    if (value) {
        se05x_platform_open();
    } else {
        se05x_platform_close();
    }

    return 0;
}