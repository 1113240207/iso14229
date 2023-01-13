#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "iso14229.h"

#ifdef __cplusplus
extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t);
#else
int LLVMFuzzerTestOneInput(const uint8_t*, size_t);
#endif

uint8_t retval = kPositiveResponse;

static uint8_t fn(UDSServer_t *srv, UDSServerEvent_t ev, const void *arg) {
    return retval;
}

struct Impl {
    uint8_t buf[8192];
    size_t size;
};

static ssize_t _recv(UDSTpHandle_t *hdl, void *buf, size_t count, UDSTpAddr_t *ta_type) {
    struct Impl *pL_Impl = (struct Impl *)hdl->impl;
    if (pL_Impl->size < count) {
        count = pL_Impl->size;
    }
    memmove(buf, pL_Impl->buf, count);
    pL_Impl->size = 0;
    return count;
}

static void printhex(const uint8_t *addr, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x,", addr[i]);
    }
    printf("\n");
}

ssize_t _send(struct UDSTpHandle *hdl, const void *buf, size_t count, UDSTpAddr_t ta_type) {
    // printhex(buf, count);
    return count;
}

UDSTpStatus_t _poll(struct UDSTpHandle *hdl) {
    return 0;
}

static struct Impl Impl;
static UDSTpHandle_t hdl = {
    .recv = _recv,
    .send = _send,
    .poll = _poll,
    .impl = &Impl,
};

static uint32_t g_ms = 0;
uint32_t UDSMillis() {
    return g_ms;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    UDSServer_t srv;
    UDSServerConfig_t cfg = {
        .fn = fn,
        .tp = &hdl,
    };
    if (size < 1) {
        return 0;
    }

    retval = data[0];
    size = size - 1;

    if (size > sizeof(Impl.buf)) {
        size = sizeof(Impl.buf);
    }
    memmove(&Impl.buf, data, size);
    Impl.size = size;
    UDSServerInit(&srv, &cfg);
    for (g_ms = 0; g_ms < 100; g_ms++) {
        UDSServerPoll(&srv);
    }
    return 0;
}
