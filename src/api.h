#pragma once

#include <stdint.h>

#include "http.h"

#define APP_VERSION "1.1.0"

void api_set_port(uint16_t port);
void api_handle(http_req_t *r);
