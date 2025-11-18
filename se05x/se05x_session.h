#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void *se05x_default_session_open(void);
void se05x_default_session_close(void *session);

#ifdef __cplusplus
}
#endif