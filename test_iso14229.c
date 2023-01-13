#include "iso14229.h"
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#define ANSI_RESET "\033[0m"
#define ANSI_BOLD "\033[1m"
#define ANSI_BRIGHT_GREEN "\033[92m"
#define ANSI_BRIGHT_MAGENTA "\033[95m"

#define _ASSERT_INT_COND(a, b, cond)                                                               \
    {                                                                                              \
        int _a = a;                                                                                \
        int _b = b;                                                                                \
        if (!((_a)cond(_b))) {                                                                     \
            printf("%s:%d (%d %s %d)\n", __FILE__, __LINE__, _a, #cond, _b);                       \
            fflush(stdout);                                                                        \
            assert(0);                                                                             \
        }                                                                                          \
    }

#define ASSERT_INT_LT(a, b) _ASSERT_INT_COND(a, b, <)
#define ASSERT_INT_LE(a, b) _ASSERT_INT_COND(a, b, <=)
#define ASSERT_INT_GE(a, b) _ASSERT_INT_COND(a, b, >=)
#define ASSERT_INT_EQUAL(a, b) _ASSERT_INT_COND(a, b, ==)
#define ASSERT_INT_NE(a, b) _ASSERT_INT_COND(a, b, !=)

#define ASSERT_PTR_EQUAL(a, b)                                                                     \
    {                                                                                              \
        const void *_a = a;                                                                        \
        const void *_b = b;                                                                        \
        if ((_a) != (_b)) {                                                                        \
            printf("%s:%d (%p != %p)\n", __FILE__, __LINE__, _a, _b);                              \
            fflush(stdout);                                                                        \
            assert(0);                                                                             \
        }                                                                                          \
    }

#define ASSERT_MEMORY_EQUAL(a, b, len)                                                             \
    {                                                                                              \
        const uint8_t *_a = (const uint8_t *)a;                                                    \
        const uint8_t *_b = (const uint8_t *)b;                                                    \
        if (memcmp(_a, _b, len)) {                                                                 \
            printf("A:");                                                                          \
            for (unsigned int i = 0; i < len; i++) {                                               \
                printf("%02x,", _a[i]);                                                            \
            }                                                                                      \
            printf(" (%s)\nB:", #a);                                                               \
            for (unsigned int i = 0; i < len; i++) {                                               \
                printf("%02x,", _b[i]);                                                            \
            }                                                                                      \
            printf(" (%s)\n", #b);                                                                 \
            fflush(stdout);                                                                        \
            assert(0);                                                                             \
        }                                                                                          \
    }

#define SERVER_SEND_ID (0x7E8)      /* server sends */
#define SERVER_PHYS_RECV_ID (0x7E0) /* server listens for physically (1:1) addressed messages */
#define SERVER_FUNC_RECV_ID (0x7DF) /* server listens for functionally (1:n) addressed messages */

#define CLIENT_PHYS_SEND_ID SERVER_PHYS_RECV_ID /* client sends physically (1:1) by default */
#define CLIENT_SEND_ID CLIENT_PHYS_SEND_ID
#define CLIENT_FUNC_SEND_ID SERVER_FUNC_RECV_ID
#define CLIENT_RECV_ID SERVER_SEND_ID

#define CLIENT_DEFAULT_P2_MS 150
#define CLIENT_DEFAULT_P2_STAR_MS 1500
#define SERVER_DEFAULT_P2_MS 50
#define SERVER_DEFAULT_P2_STAR_MS 2000
#define SERVER_DEFAULT_S3_MS 5000

// TODO: parameterize and fuzz this
#define DEFAULT_ISOTP_BUFSIZE (2048U)

struct IsoTpLinkConfig {
    uint16_t send_id;
    uint8_t *send_buffer;
    uint16_t send_buf_size;
    uint8_t *recv_buffer;
    uint16_t recv_buf_size;
    uint32_t (*user_get_ms)(void);
    int (*user_send_can)(uint32_t arbitration_id, const uint8_t *data, uint8_t size);
    void (*user_debug)(const char *message, ...);
};

static void printhex(const uint8_t *addr, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x,", addr[i]);
    }
    printf("\n");
}

#define DEFAULT_SERVER_CONFIG()                                                                    \
    { .tp = &g.mock_tp.hdl, }

#define DEFAULT_CLIENT_CONFIG()                                                                    \
    { .tp = &g.mock_tp.hdl, }

#define TEST_SETUP()                                                                               \
    memset(&g, 0, sizeof(g));                                                                      \
    initMockTransports();                                                                          \
    printf("%s\n", __PRETTY_FUNCTION__);

#define TEST_TEARDOWN() printf(ANSI_BOLD "OK\n" ANSI_RESET);

#define TEST_SETUP_PARAMETRIZED(params_list)                                                       \
    for (size_t i = 0; i < sizeof(params_list) / sizeof(params_list[0]); i++) {                    \
        memset(&g, 0, sizeof(g));                                                                  \
        initMockTransports();                                                                      \
        printf("%s [%ld]\n", __PRETTY_FUNCTION__, i);

#define TEST_TEARDOWN_PARAMETRIZED()                                                               \
    printf(ANSI_BOLD "OK\n" ANSI_RESET);                                                           \
    }

/**
 * @brief minimal transport mock
 */
struct MockTransport {
    UDSTpHandle_t hdl;
    uint8_t recv_buf[DEFAULT_ISOTP_BUFSIZE];
    uint8_t send_buf[DEFAULT_ISOTP_BUFSIZE];
    uint16_t recv_size;
    uint16_t send_size;
    UDSTpAddr_t recv_ta_type;
    UDSTpAddr_t send_ta_type;
    UDSTpStatus_t status;
};

static ssize_t mock_transport_recv(UDSTpHandle_t *hdl, void *buf, size_t bufsize,
                                   UDSTpAddr_t *ta_type) {
    assert(hdl);
    struct MockTransport *tp = (struct MockTransport *)hdl;
    size_t size = tp->recv_size;

    if (bufsize < size) {
        return -ENOBUFS;
    }

    if (size) {
        memmove(buf, tp->recv_buf, size);
        tp->recv_size = 0;
        memset(tp->recv_buf, 0, sizeof(tp->recv_buf));
        printf(ANSI_BRIGHT_MAGENTA "<-tp_recv- [%02ld] ", size);
        printhex(buf, size);
        printf(ANSI_RESET);
    }
    return size;
}

static ssize_t mock_transport_send(UDSTpHandle_t *hdl, const void *buf, size_t count,
                                   UDSTpAddr_t ta_type) {
    assert(hdl);
    struct MockTransport *tp = (struct MockTransport *)hdl;
    assert(0 == tp->send_size); // should be clear, right?
    assert(count);              // why send zero?
    memmove(tp->send_buf, buf, count);
    tp->send_size = count;
    printf(ANSI_BRIGHT_GREEN "-tp_send-> [%02ld] ", count);
    printhex(buf, count);
    printf(ANSI_RESET);
    return count;
}

static UDSTpStatus_t mock_transport_poll(UDSTpHandle_t *hdl) {
    assert(hdl);
    struct MockTransport *tp = (struct MockTransport *)hdl;
    return tp->status;
}

static void mockTransportRecv(struct MockTransport *tp, const void *buf, size_t count,
                              UDSTpAddr_t ta_type) {
    assert(tp);
    assert(0 == tp->recv_size); // else busy
    memmove(tp->recv_buf, buf, count);
    tp->recv_ta_type = ta_type;
    tp->recv_size = count;
}

#define PHYS_TP_RECV(tp, buf) mockTransportRecv(&tp, buf, sizeof(buf), kTpAddrTypePhysical)
#define FUNC_TP_RECV(tp, buf) mockTransportRecv(&tp, buf, sizeof(buf), kTpAddrTypeFunctional)
#define ASSERT_TP_SENT(tp, buf)                                                                    \
    ASSERT_INT_EQUAL(tp.send_size, sizeof(buf));                                                   \
    ASSERT_MEMORY_EQUAL(tp.send_buf, buf, sizeof(buf));                                            \
    tp.send_size = 0;                                                                              \
    memset(tp.send_buf, 0, sizeof(tp.send_buf));

#define ASSERT_SRV_RESP_WITHIN_MS(reltime)                                                         \
    {                                                                                              \
        int deadline = g.ms + reltime;                                                             \
        while (0 == g.mock_tp.send_size) {                                                         \
            UDSServerPoll(&server);                                                                \
            g.ms++;                                                                                \
            ASSERT_INT_LE(g.ms, deadline);                                                         \
        }                                                                                          \
    }
#define ASSERT_SRV_NO_RESP_WITHIN_MS(reltime)                                                      \
    {                                                                                              \
        int deadline = g.ms + reltime;                                                             \
        while (g.ms++ < deadline) {                                                                \
            UDSServerPoll(&server);                                                                \
            ASSERT_INT_EQUAL(0, g.mock_tp.send_size);                                              \
        }                                                                                          \
    }

// ================================================
// Global Variables
// ================================================

struct Condition {
    bool (*cb)();
    const uint8_t *req;
    uint32_t req_len;
    UDSTpAddr_t req_type;
    const uint8_t *expected_resp;
    uint32_t expected_resp_len;
    uint32_t expected_resp_timeout;
    struct Condition *next;
};

// global state: memset() to zero in TEST_SETUP();
static struct {
    int ms; // simulated absolute time
    int t0; // marks a time point

    struct MockTransport mock_tp; // server and client tests use this independently

    int callCount;

    uint8_t srvRecvBuf[DEFAULT_ISOTP_BUFSIZE];
    uint8_t srvSendBuf[DEFAULT_ISOTP_BUFSIZE];
    uint8_t clientRecvBuf[DEFAULT_ISOTP_BUFSIZE];
    uint8_t clientSendBuf[DEFAULT_ISOTP_BUFSIZE];

    uint8_t scratch[DEFAULT_ISOTP_BUFSIZE];
    uint16_t size;
    int ret;
    uint8_t userResponse;
    struct Condition *cond;
} g;

static void appendCondition(struct Condition *cond) {
    if (NULL == g.cond) {
        g.cond = cond;
    } else {
        struct Condition *tmp = g.cond;
        while (tmp && tmp->next) {
            tmp = tmp->next;
        }
        tmp->next = cond;
    }
}

#define EXPECT_CONDITION(d1, reqType, d2, timeout)                                                 \
    {                                                                                              \
        struct Condition *cond = calloc(1, sizeof(struct Condition));                              \
        cond->req = d1;                                                                            \
        cond->req_len = sizeof(d1);                                                                \
        cond->req_type = reqType;                                                                  \
        cond->expected_resp = d2;                                                                  \
        cond->expected_resp_len = sizeof(d2);                                                      \
        cond->expected_resp_timeout = timeout;                                                     \
        cond->next = NULL;                                                                         \
        appendCondition(cond);                                                                     \
    }

#define EXPECT_FUNC(cbFunc)                                                                        \
    {                                                                                              \
        struct Condition *cond = calloc(1, sizeof(struct Condition));                              \
        cond->cb = cbFunc;                                                                         \
        appendCondition(cond);                                                                     \
    }

#define PHYS_SEND_EXPECT(d1, d2, timeout) EXPECT_CONDITION(d1, kTpAddrTypePhysical, d2, timeout);

#define FUNC_SEND_EXPECT(d1, d2, timeout) EXPECT_CONDITION(d1, kTpAddrTypeFunctional, d2, timeout);

static void checkCondition(UDSServer_t *srv, struct Condition *cond) {
    assert(cond);
    if (cond->cb) {
        bool result = cond->cb();
        ASSERT_INT_EQUAL(result, 0);
    } else {
        if (cond->req) {
            mockTransportRecv(&g.mock_tp, cond->req, cond->req_len, cond->req_type);
        }
        int deadline = g.ms + cond->expected_resp_timeout;
        while (0 == g.mock_tp.send_size && g.ms <= deadline) {
            UDSServerPoll(srv);
            g.ms++;
            if (cond->expected_resp) {
                ASSERT_INT_LE(g.ms, deadline);
            }
        }
        if (cond->expected_resp) {
            ASSERT_INT_EQUAL(g.mock_tp.send_size, cond->expected_resp_len);
            ASSERT_MEMORY_EQUAL(g.mock_tp.send_buf, cond->expected_resp, cond->expected_resp_len);
        } else {
            ASSERT_INT_EQUAL(g.mock_tp.send_size, 0);
        }
        g.mock_tp.send_size = 0;
        memset(g.mock_tp.send_buf, 0, sizeof(g.mock_tp.send_buf));
    }
}

#define EVAL()                                                                                     \
    while (g.cond) {                                                                               \
        checkCondition(&server, g.cond);                                                           \
        struct Condition *tmp = g.cond;                                                            \
        g.cond = g.cond->next;                                                                     \
        free(tmp);                                                                                 \
    }

// ================================================
//
// ================================================

void initMockTransports() {
    g.mock_tp.hdl.recv = mock_transport_recv;
    g.mock_tp.hdl.send = mock_transport_send;
    g.mock_tp.hdl.poll = mock_transport_poll;
}

// ================================================
// common mock functions
// ---
// these are used in all tests
// ================================================

uint32_t UDSMillis() { return g.ms; }

// ================================================
// Server tests
// ================================================

void testServerInit() {
    TEST_SETUP();
    UDSServer_t srv;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&srv, &cfg);
    TEST_TEARDOWN();
}

void testServer0x10DiagSessCtrlIsDisabledByDefault() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);

    const uint8_t IN[] = {0x10, 0x02};
    const uint8_t OUT[] = {0x7f, 0x10, 0x11};
    PHYS_SEND_EXPECT(IN, OUT, CLIENT_DEFAULT_P2_MS);

    EVAL();
    TEST_TEARDOWN();
}

void testServer0x10DiagSessCtrlFunctionalRequest() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);

    // sending a diagnostic session control request functional broadcast
    const uint8_t IN[] = {0x10, 0x03};
    const uint8_t OUT[] = {0x7f, 0x10, 0x11};
    FUNC_SEND_EXPECT(IN, OUT, CLIENT_DEFAULT_P2_MS);

    EVAL();
    TEST_TEARDOWN();
}

uint8_t fn1_callCount = 0;
uint8_t fn1(UDSServer_t *srv, UDSServerEvent_t ev, const void *arg) {
    switch (ev) {
        case UDS_SRV_EVT_EcuReset:
            fn1_callCount += 1;
            return kPositiveResponse;
        default:
            ASSERT_INT_EQUAL(UDS_SRV_EVT_DoScheduledReset, ev);
            return kPositiveResponse;
    }
}

// Special-case of ECU reset service
// ISO-14229-1 2013 9.3.1:
// on the behaviour of the ECU from the time following the positive response message to the ECU
// reset request: It is recommended that during this time the ECU does not accept any request
// messages and send any response messages.
void testServer0x11DoesNotSendOrReceiveMessagesAfterECUReset() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);
    server.fn = fn1;

    const uint8_t IN[] = {0x11, 0x01};
    const uint8_t OUT[] = {0x51, 0x01};

    // Sending the first ECU reset should result in a response
    PHYS_SEND_EXPECT(IN, OUT, CLIENT_DEFAULT_P2_MS);
    // Sending subsequent ECU reset requests should not receive any response
    PHYS_SEND_EXPECT(IN, NULL, CLIENT_DEFAULT_P2_MS * 3);
    EVAL();

    // The ECU reset handler should have been called once.
    ASSERT_INT_EQUAL(fn1_callCount, 1);
    TEST_TEARDOWN();
}

uint8_t fn2(UDSServer_t *srv, UDSServerEvent_t ev, const void *arg) {
    ASSERT_INT_EQUAL(UDS_SRV_EVT_ReadDataByIdent, ev);
    const uint8_t vin[] = {0x57, 0x30, 0x4C, 0x30, 0x30, 0x30, 0x30, 0x34, 0x33,
                           0x4D, 0x42, 0x35, 0x34, 0x31, 0x33, 0x32, 0x36};
    const uint8_t data_0x010A[] = {0xA6, 0x66, 0x07, 0x50, 0x20, 0x1A,
                                   0x00, 0x63, 0x4A, 0x82, 0x7E};
    const uint8_t data_0x0110[] = {0x8C};

    UDSRDBIArgs_t *r = (UDSRDBIArgs_t *)arg;
    switch (r->dataId) {
    case 0xF190:
        return r->copy(srv, vin, sizeof(vin));
    case 0x010A:
        return r->copy(srv, data_0x010A, sizeof(data_0x010A));
    case 0x0110:
        return r->copy(srv, data_0x0110, sizeof(data_0x0110));
    default:
        return kRequestOutOfRange;
    }
    return kPositiveResponse;
}

void testServer0x22RDBI1() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);
    server.fn = fn2;

    const uint8_t IN[] = {0x22, 0xF1, 0x90};
    const uint8_t OUT[] = {0x62, 0xF1, 0x90, 0x57, 0x30, 0x4C, 0x30, 0x30, 0x30, 0x30,
                           0x34, 0x33, 0x4D, 0x42, 0x35, 0x34, 0x31, 0x33, 0x32, 0x36};
    PHYS_SEND_EXPECT(IN, OUT, CLIENT_DEFAULT_P2_MS);

    const uint8_t IN_2[] = {0x22, 0xF1, 0x91};
    const uint8_t OUT_2[] = {0x7F, 0x22, 0x31};
    PHYS_SEND_EXPECT(IN_2, OUT_2, CLIENT_DEFAULT_P2_MS);

    EVAL();
    TEST_TEARDOWN();
}

uint8_t fn4(UDSServer_t *srv, UDSServerEvent_t ev, const void *arg) {
    switch (ev) {
    case UDS_SRV_EVT_SecAccessRequestSeed: {
        UDSSecAccessRequestSeedArgs_t *r = (UDSSecAccessRequestSeedArgs_t *)arg;
        const uint8_t seed[] = {0x36, 0x57};
        ASSERT_INT_NE(r->level, srv->securityLevel);
        return r->copySeed(srv, seed, sizeof(seed));
        break;
    }
    case UDS_SRV_EVT_SecAccessValidateKey: {
        UDSSecAccessValidateKeyArgs_t *r = (UDSSecAccessValidateKeyArgs_t *)arg;
        const uint8_t expected_key[] = {0xC9, 0xA9};
        ASSERT_INT_EQUAL(r->len, sizeof(expected_key));
        ASSERT_MEMORY_EQUAL(r->key, expected_key, sizeof(expected_key));
        break;
    }
    default:
        assert(0);
    }
    return kPositiveResponse;
}

uint8_t fn10(UDSServer_t *srv, UDSServerEvent_t ev, const void *arg) {
    ASSERT_INT_EQUAL(ev, UDS_SRV_EVT_ReadMemByAddr);
    UDSReadMemByAddrArgs_t *r = (UDSReadMemByAddrArgs_t *)arg;
    //                                      1 2 3 4 5 6 7 8
    ASSERT_PTR_EQUAL(r->memAddr, (void *)0x000055555555f0c8);
    ASSERT_INT_EQUAL(r->memSize, 4);
    uint8_t FakeData[4] = {0x01, 0x02, 0x03, 0x04};
    return r->copy(srv, FakeData, r->memSize);
}

void testServer0x23ReadMemoryByAddress() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);
    server.fn = fn10;

    const uint8_t IN[] = {0x23, 0x18, 0x00, 0x00, 0x55, 0x55, 0x55, 0x55, 0xf0, 0xc8, 0x04};
    const uint8_t OUT[] = {0x63, 0x01, 0x02, 0x03, 0x04};
    PHYS_SEND_EXPECT(IN, OUT, CLIENT_DEFAULT_P2_MS);

    EVAL();

    TEST_TEARDOWN();
}

// UDS-1 2013 9.4.5.2
// UDS-1 2013 9.4.5.3
void testServer0x27SecurityAccess() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);
    server.fn = fn4;

    // the server security level after initialization should be 0
    ASSERT_INT_EQUAL(server.securityLevel, 0);

    // sending a seed request should get this response
    const uint8_t SEED_REQUEST[] = {0x27, 0x01};
    const uint8_t SEED_RESPONSE[] = {0x67, 0x01, 0x36, 0x57};
    PHYS_SEND_EXPECT(SEED_REQUEST, SEED_RESPONSE, CLIENT_DEFAULT_P2_MS);

    // subsequently sending an unlock request should get this response
    const uint8_t UNLOCK_REQUEST[] = {0x27, 0x02, 0xC9, 0xA9};
    const uint8_t UNLOCK_RESPONSE[] = {0x67, 0x02};
    PHYS_SEND_EXPECT(UNLOCK_REQUEST, UNLOCK_RESPONSE, CLIENT_DEFAULT_P2_MS);

    // sending the same seed request should now result in the "already unlocked" response
    const uint8_t ALREADY_UNLOCKED_RESPONSE[] = {0x67, 0x01, 0x00, 0x00};
    PHYS_SEND_EXPECT(SEED_REQUEST, ALREADY_UNLOCKED_RESPONSE, CLIENT_DEFAULT_P2_MS);

    EVAL();

    // Additionally, the security level should now be 1
    ASSERT_INT_EQUAL(server.securityLevel, 1);
    TEST_TEARDOWN();
}

static uint8_t fn5_retval = kRequestCorrectlyReceived_ResponsePending;
static uint8_t fn5(UDSServer_t *srv, UDSServerEvent_t ev, const void *arg) { return fn5_retval; }
static bool changeToPositiveResponse() {
    fn5_retval = kPositiveResponse;
    return 0;
}

// ISO-14229-1 2013 Table A.1 Byte Value 0x78: requestCorrectlyReceived-ResponsePending
// "This NRC is in general supported by each diagnostic service".
void testServer0x31RCRRP() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);

    // When a server handler func initially returns RRCRP
    server.fn = fn5;

    // sending a request to the server should return RCRRP
    const uint8_t REQUEST[] = {0x31, 0x01, 0x12, 0x34};
    const uint8_t RCRRP[] = {0x7F, 0x31, 0x78};
    PHYS_SEND_EXPECT(REQUEST, RCRRP, CLIENT_DEFAULT_P2_MS);

    // The server should again respond within p2_star ms, and keep responding
    PHYS_SEND_EXPECT(NULL, RCRRP, CLIENT_DEFAULT_P2_MS);
    PHYS_SEND_EXPECT(NULL, RCRRP, CLIENT_DEFAULT_P2_MS);
    PHYS_SEND_EXPECT(NULL, RCRRP, CLIENT_DEFAULT_P2_MS);
    PHYS_SEND_EXPECT(NULL, RCRRP, CLIENT_DEFAULT_P2_MS);
    PHYS_SEND_EXPECT(NULL, RCRRP, CLIENT_DEFAULT_P2_MS);
    PHYS_SEND_EXPECT(NULL, RCRRP, CLIENT_DEFAULT_P2_MS);

    // When the server handler func now returns a positive response
    EXPECT_FUNC(changeToPositiveResponse);

    // the server's next response should be a positive one
    const uint8_t POSITIVE_RESPONSE[] = {0x71, 0x01, 0x12, 0x34};
    PHYS_SEND_EXPECT(NULL, POSITIVE_RESPONSE, CLIENT_DEFAULT_P2_MS);

    EVAL();
    TEST_TEARDOWN();
}

void testServer0x34NotEnabled() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);

    // when no requestDownloadHandler is installed,
    // sending this request to the server
    const uint8_t IN[] = {0x34, 0x11, 0x33, 0x60, 0x20, 0x00, 0x00, 0xFF, 0xFF};
    // should return a kServiceNotSupported response
    const uint8_t OUT[] = {0x7F, 0x34, 0x11};
    PHYS_SEND_EXPECT(IN, OUT, CLIENT_DEFAULT_P2_MS);
    EVAL();

    TEST_TEARDOWN();
}

uint8_t fn7(UDSServer_t *srv, UDSServerEvent_t ev, const void *arg) {
    switch (ev) {
    case UDS_SRV_EVT_RequestDownload: {
        UDSRequestDownloadArgs_t *r = (UDSRequestDownloadArgs_t *)arg;
        ASSERT_INT_EQUAL(0x11, r->dataFormatIdentifier);
        ASSERT_PTR_EQUAL((void *)0x602000, r->addr);
        ASSERT_INT_EQUAL(0x00FFFF, r->size);
        ASSERT_INT_EQUAL(r->maxNumberOfBlockLength, UDS_SERVER_DEFAULT_XFER_DATA_MAX_BLOCKLENGTH);
        r->maxNumberOfBlockLength = 0x0081;
        break;
    }
    case UDS_SRV_EVT_TransferData: {
        break;
    }
    case UDS_SRV_EVT_RequestTransferExit: {
        break;
    }
    default:
        assert(0);
    }
    return kPositiveResponse;
}

void testServer0x34DownloadData() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);
    // when a handler is installed that implements UDS-1:2013 Table 415
    server.fn = fn7;

    // sending this request to the server
    const uint8_t IN[] = {0x34, 0x11, 0x33, 0x60, 0x20, 0x00, 0x00, 0xFF, 0xFF};
    // should receive a positive response matching UDS-1:2013 Table 415
    const uint8_t OUT[] = {0x74, 0x20, 0x00, 0x81};
    PHYS_SEND_EXPECT(IN, OUT, CLIENT_DEFAULT_P2_MS);
    EVAL();
    TEST_TEARDOWN();
}

// #define TEST_0x36_MOCK_DATA 0xF0, 0x00, 0xBA, 0xBA
// static uint8_t
// testServer0x36TransferDataMockHandlerOnTransfer(UDSServer_t *srv,
//                                                 void *userCtx, const uint8_t *data, uint32_t len)
//                                                 {
//     (void)srv;
//     (void)userCtx;
//     const uint8_t MOCK_DATA[] = {TEST_0x36_MOCK_DATA};
//     ASSERT_INT_EQUAL(sizeof(MOCK_DATA), len);
//     ASSERT_MEMORY_EQUAL(MOCK_DATA, data, len);
//     return kPositiveResponse;
// }

// UDSDownloadHandler testServer0x36TransferDataMockHandler = {
//     .onTransfer = testServer0x36TransferDataMockHandlerOnTransfer,
// };

// void testServer0x36TransferData() {
//     UDSServer_t server;
//     UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
//     // when a handler is installed that implements UDS-1:2013 Table 415
//     cfg.RequestDownload = testServer0x34DownloadDataMockRequestDownload;
//     UDSServerInit(&server, &cfg);
//     IsoTpInitLink(&g.clientLink, &CLIENT_LINK_DEFAULT_CONFIG);

//     SERVER_TEST_SETUP();
//     server.downloadHandler = &testServer0x36TransferDataMockHandler;
//     UDSDownloadHandlerInit(server.downloadHandler, 0xFFFF);
//     const uint8_t TRANSFER_DATA_REQUEST[] = {0x36, 0x01, TEST_0x36_MOCK_DATA};
// #undef TEST_0x36_MOCK_DATA
//     const uint8_t TRANSFER_DATA_RESPONSE[] = {0x76, 0x01};
//     SERVER_TEST_SEQUENCE_BEGIN();
// case 0:
//     SERVER_TEST_CLIENT_SEND(TRANSFER_DATA_REQUEST);
//     break;
// case 1:
//     SERVER_TEST_AWAIT_RESPONSE(TRANSFER_DATA_RESPONSE);
//     break;
// case 2:
//     done = true;
//     break;
//     SERVER_TEST_SEQUENCE_END(server.cfg->p2_ms * 3);
//     ASSERT_INT_EQUAL(server.downloadHandler->numBytesTransferred, 4);
//     ASSERT_INT_EQUAL(server.downloadHandler->blockSequenceCounter, 2);
//     TEST_TEARDOWN();
// }

uint8_t fn8(UDSServer_t *srv, UDSServerEvent_t ev, const void *arg) { return kPositiveResponse; }

/* UDS-1 2013 Table 72 */
void testServer0x3ESuppressPositiveResponse() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);
    server.fn = fn8;
    // when the suppressPositiveResponse bit is set
    const uint8_t IN[] = {0x3E, 0x80};
    // there should be no response
    PHYS_SEND_EXPECT(IN, NULL, CLIENT_DEFAULT_P2_MS * 5);
    EVAL();
    TEST_TEARDOWN();
}

uint8_t fn3(UDSServer_t *srv, UDSServerEvent_t ev, const void *arg) {
    ASSERT_INT_EQUAL(UDS_SRV_EVT_DiagSessCtrl, ev);
    return kPositiveResponse;
}

void testServer0x83DiagnosticSessionControl() {
    TEST_SETUP();
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    UDSServerInit(&server, &cfg);
    server.fn = fn3;
    // the server sessionType after initialization should be kDefaultSession.
    ASSERT_INT_EQUAL(server.sessionType, kDefaultSession);

    // When the suppressPositiveResponse bit is set, there should be no response.
    const uint8_t IN[] = {0x10, 0x83};
    PHYS_SEND_EXPECT(IN, NULL, CLIENT_DEFAULT_P2_MS * 5);
    EVAL();
    // and the server sessionType should have changed
    ASSERT_INT_EQUAL(server.sessionType, kExtendedDiagnostic);
    TEST_TEARDOWN();
}

uint8_t fn9(UDSServer_t *srv, UDSServerEvent_t ev, const void *arg) {
    ASSERT_INT_EQUAL(UDS_SRV_EVT_SessionTimeout, ev);
    g.callCount++;
    return kPositiveResponse;
}

void testServerSessionTimeout() {
    struct {
        uint8_t sessionType;
        int expectedCallCount;
    } p[] = {{kDefaultSession, 0}, {kProgrammingSession, 1}};
    TEST_SETUP_PARAMETRIZED(p);
    UDSServer_t server;
    UDSServerConfig_t cfg = DEFAULT_SERVER_CONFIG();
    cfg.fn = fn9;
    UDSServerInit(&server, &cfg);
    server.sessionType = p[i].sessionType;
    while (g.ms++ < server.s3_ms * 2) {
        UDSServerPoll(&server);
    }
    ASSERT_INT_GE(g.callCount, p[i].expectedCallCount);
    TEST_TEARDOWN_PARAMETRIZED();
}

// ================================================
// Client tests
// ================================================

void testClientInit() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);
    TEST_TEARDOWN();
}

void testClientP2TimeoutExceeded() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);

    // Sending an ECU reset
    UDSSendECUReset(&client, kHardReset);

    // and not receiving a response after approximately p2 ms
    while (g.ms++ < client.p2_ms + 3) {
        UDSClientPoll(&client);
    }

    // should result in UDS_ERR_TIMEOUT
    ASSERT_INT_EQUAL(UDS_ERR_TIMEOUT, client.err);
    ASSERT_INT_EQUAL(kRequestStateIdle, client.state);
    TEST_TEARDOWN();
}

void testClientP2TimeoutNotExceeded() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);

    // a client that sends an ECU reset
    UDSSendECUReset(&client, kHardReset);

    // which receives a positive response
    const uint8_t POSITIVE_RESPONSE[] = {0x51, 0x01};
    PHYS_TP_RECV(g.mock_tp, POSITIVE_RESPONSE);

    // should return to the idle state
    while (kRequestStateIdle != client.state) {
        UDSClientPoll(&client);
        assert(g.ms++ < client.p2_ms); // before p2 ms has elapsed
    }

    // and should have no error.
    ASSERT_INT_EQUAL(UDS_OK, client.err);
    TEST_TEARDOWN();
}

void testClientSuppressPositiveResponse() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);

    // Setting the suppressPositiveResponse flag before sending a request
    client.options |= SUPPRESS_POS_RESP;
    UDSSendECUReset(&client, kHardReset);

    // and not receiving a response after approximately p2 ms
    while (g.ms++ < client.p2_ms + 3) {
        UDSClientPoll(&client);
    }

    // should not result in an error.
    ASSERT_INT_EQUAL(UDS_OK, client.err);
    ASSERT_INT_EQUAL(kRequestStateIdle, client.state);
    TEST_TEARDOWN();
}

void testClientBusy() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);

    // Sending a request should not return an error
    ASSERT_INT_EQUAL(UDS_OK, UDSSendECUReset(&client, kHardReset));

    // unless there is an existing unresolved request
    ASSERT_INT_EQUAL(UDS_ERR_BUSY, UDSSendECUReset(&client, kHardReset));

    TEST_TEARDOWN();
}

void testClientUnexpectedResponse() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);

    // sending an ECU reset
    UDSSendECUReset(&client, kHardReset);

    // The correct response SID to EcuReset (0x11) is 0x51.
    const uint8_t WEIRD_RESPONSE[] = {0x50, 0x01}; // incorrect, unexpected

    PHYS_TP_RECV(g.mock_tp, WEIRD_RESPONSE);

    // should return to the idle state
    while (kRequestStateIdle != client.state) {
        UDSClientPoll(&client);
        assert(g.ms++ < client.p2_ms); // before p2 ms has elapsed
    }

    // with a UDS_ERR_SID_MISMATCH error.
    ASSERT_INT_EQUAL(UDS_ERR_SID_MISMATCH, client.err);
    TEST_TEARDOWN();
}

void testClient0x11ECUReset() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);

    // sending an ECUReset of type kHardReset
    UDSSendECUReset(&client, kHardReset);

    // should send these bytes to the ISO-TP layer
    const uint8_t HARD_RESET_REQUEST[] = {0x11, 0x01};
    ASSERT_TP_SENT(g.mock_tp, HARD_RESET_REQUEST);
    TEST_TEARDOWN();
}

void testClient0x11ECUResetNegativeResponse() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);

    // A client that sets the negativeResponseIsError flag
    client.options |= NEG_RESP_IS_ERR;
    // before sending an ECU reset
    UDSSendECUReset(&client, kHardReset);

    // and receiving a negative response
    const uint8_t NEG_RESPONSE[] = {0x7F, 0x11, 0x10};
    PHYS_TP_RECV(g.mock_tp, NEG_RESPONSE);

    // should return to the idle state
    while (kRequestStateIdle != client.state) {
        UDSClientPoll(&client);
        assert(g.ms++ < client.p2_ms); // before p2 ms has elapsed
    }

    // with a UDS_ERR_NEG_RESP error
    ASSERT_INT_EQUAL(UDS_ERR_NEG_RESP, client.err);
    TEST_TEARDOWN();
}

void testClient0x11ECUResetNegativeResponseNoError() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);

    // A client that sends an ECU reset
    UDSSendECUReset(&client, kHardReset);

    // and receives a negative response
    const uint8_t NEG_RESPONSE[] = {0x7F, 0x11, 0x10};
    PHYS_TP_RECV(g.mock_tp, NEG_RESPONSE);

    // should return to the idle state
    while (kRequestStateIdle != client.state) {
        UDSClientPoll(&client);
        assert(g.ms++ < client.p2_ms); // before p2 ms has elapsed
    }

    // with no error
    ASSERT_INT_EQUAL(UDS_OK, client.err);
    TEST_TEARDOWN();
}

void testClient0x22RDBITxBufferTooSmall() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);

    // attempting to send a request payload of 6 bytes
    uint16_t didList[] = {0x0001, 0x0002, 0x0003};

    // which is larger than the underlying buffer
    client.send_buf_size = 4;

    // should return an error
    ASSERT_INT_EQUAL(UDS_ERR_INVALID_ARG,
                     UDSSendRDBI(&client, didList, sizeof(didList) / sizeof(didList[0])))

    // and no data should be sent
    ASSERT_INT_EQUAL(client.send_size, 0);
    TEST_TEARDOWN();
}

void testClient0x22RDBIUnpackResponse() {
    TEST_SETUP();
    uint8_t RESPONSE[] = {0x72, 0x12, 0x34, 0x00, 0x00, 0xAA, 0x00, 0x56, 0x78, 0xAA, 0xBB};
    UDSClient_t client;
    memmove(client.recv_buf, RESPONSE, sizeof(RESPONSE));
    client.recv_size = sizeof(RESPONSE);
    uint8_t buf[4];
    uint16_t offset = 0;
    int err = 0;
    err = UDSUnpackRDBIResponse(&client, 0x1234, buf, 4, &offset);
    ASSERT_INT_EQUAL(err, UDS_OK);
    uint32_t d0 = (buf[0] << 24) + (buf[1] << 16) + (buf[2] << 8) + buf[3];
    ASSERT_INT_EQUAL(d0, 0x0000AA00);
    err = UDSUnpackRDBIResponse(&client, 0x1234, buf, 2, &offset);
    ASSERT_INT_EQUAL(err, UDS_ERR_DID_MISMATCH);
    err = UDSUnpackRDBIResponse(&client, 0x5678, buf, 20, &offset);
    ASSERT_INT_EQUAL(err, UDS_ERR_RESP_TOO_SHORT);
    err = UDSUnpackRDBIResponse(&client, 0x5678, buf, 2, &offset);
    ASSERT_INT_EQUAL(err, UDS_OK);
    uint16_t d1 = (buf[0] << 8) + buf[1];
    ASSERT_INT_EQUAL(d1, 0xAABB);
    err = UDSUnpackRDBIResponse(&client, 0x5678, buf, 1, &offset);
    ASSERT_INT_EQUAL(err, UDS_ERR_RESP_TOO_SHORT);
    ASSERT_INT_EQUAL(offset, sizeof(RESPONSE));
    TEST_TEARDOWN();
}

void testClient0x31RequestCorrectlyReceivedResponsePending() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    client.p2_ms = 10;
    client.p2_star_ms = 50;
    UDSClientInit(&client, &cfg);

    // When a request is sent
    UDSSendRoutineCtrl(&client, kStartRoutine, 0x1234, NULL, 0);

    // that receives an RCRRP response
    const uint8_t RCRRP[] = {0x7F, 0x31, 0x78}; // RequestCorrectly-ReceievedResponsePending
    PHYS_TP_RECV(g.mock_tp, RCRRP);

    // that remains unresolved at a time between p2 ms and p2 star ms
    while (g.ms++ < 30) {
        UDSClientPoll(&client);
    }

    // the client should still be pending.
    ASSERT_INT_EQUAL(kRequestStateAwaitResponse, client.state)

    // When the server sends a positive response
    const uint8_t POSITIVE_RESPONSE[] = {0x71, 0x01, 0x12, 0x34};
    PHYS_TP_RECV(g.mock_tp, POSITIVE_RESPONSE);
    g.t0 = g.ms;

    // the client should return to the idle state
    while (kRequestStateIdle != client.state) {
        UDSClientPoll(&client);
        assert(g.ms++ - g.t0 < client.p2_ms); // before p2 ms has elapsed
    }

    // with no error
    ASSERT_INT_EQUAL(client.err, UDS_OK);
    TEST_TEARDOWN();
}

void testClient0x34RequestDownload() {
    TEST_SETUP();
    UDSClient_t client;
    UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
    UDSClientInit(&client, &cfg);

    // When RequestDownload is called with these arguments
    ASSERT_INT_EQUAL(UDS_OK, UDSSendRequestDownload(&client, 0x11, 0x33, 0x602000, 0x00FFFF));

    // the bytes sent should match UDS-1 2013 Table 415
    const uint8_t CORRECT_REQUEST[] = {0x34, 0x11, 0x33, 0x60, 0x20, 0x00, 0x00, 0xFF, 0xFF};
    ASSERT_TP_SENT(g.mock_tp, CORRECT_REQUEST);
    TEST_TEARDOWN();
}

void testClient0x34UDSUnpackRequestDownloadResponse() {
    TEST_SETUP();
    struct RequestDownloadResponse resp;

    // When the following raw bytes are received
    uint8_t RESPONSE[] = {0x74, 0x20, 0x00, 0x81};
    UDSClient_t client;
    memmove(client.recv_buf, RESPONSE, sizeof(RESPONSE));
    client.recv_size = sizeof(RESPONSE);

    UDSClientError_t err = UDSUnpackRequestDownloadResponse(&client, &resp);

    // they should unpack without error
    ASSERT_INT_EQUAL(err, UDS_OK);
    ASSERT_INT_EQUAL(resp.maxNumberOfBlockLength, 0x81);
    TEST_TEARDOWN();
}

// void testClient0x36TransferData() {
//     TEST_SETUP();
//     IsoTpInitLink(&g.srvLink, &SRV_PHYS_LINK_DEFAULT_CONFIG);
//     UDSClient_t client;
//     UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
//     UDSClientInit(&client, &cfg);

//     // This test is large because it implements UDS-1 2013 14.5.5
//     // It would be perhaps be better implemented with the
//     // udsSequenceRunBlocking API instead.

// #define MemorySize (0x00FFFF)

//     // Create some source data and write it to a file
//     const char *fname = "testClient0x36TransferData2.dat";
//     uint8_t SRC_DATA[MemorySize] = {0};
//     for (unsigned int i = 0; i < sizeof(SRC_DATA); i++) {
//         SRC_DATA[i] = i & 0xFF;
//     }
//     FILE *fd = fopen(fname, "wb+");
//     assert(sizeof(SRC_DATA) == fwrite(SRC_DATA, 1, sizeof(SRC_DATA), fd));
//     rewind(fd);

//     // see example
//     const uint16_t maximumNumberOfBlockLength = 0x0081;
//     uint32_t blockNr = 0;

//     // when RequestDownload is called
//     UDSSendRequestDownload(&client, 0x11, 0x33, 0x602000, MemorySize);

//     // the server link should receive it
//     while (ISOTP_RET_OK != isotp_receive(&g.srvLink, g.scratch, sizeof(g.scratch), &g.size))
//     {
//         fixtureSrvLinksProcess();
//         UDSClientPoll(&client);
//         assert(g.ms++ < client.p2_ms); // in p2 ms
//     }

//     // The bytes received should match Table 415
//     ASSERT_INT_EQUAL(g.size, 9);
//     const uint8_t CORRECT_0x34_REQUEST[] = {0x34, 0x11, 0x33, 0x60, 0x20, 0x00, 0x00, 0xFF,
//     0xFF}; ASSERT_MEMORY_EQUAL(g.srvLinkRxBuf, CORRECT_0x34_REQUEST,
//     sizeof(CORRECT_0x34_REQUEST));

//     // when the server sends this positive response
//     const uint8_t RESPONSE[] = {0x74, 0x20, 0x00, 0x81};
//     isotp_send(&g.srvLink, RESPONSE, sizeof(RESPONSE));

//     // the client should return to the idle state in under p2 ms
//     g.t0 = g.ms;
//     while (kRequestStateIdle != client.state) {
//         fixtureSrvLinksProcess();
//         UDSClientPoll(&client);
//         assert(g.ms++ - g.t0 < client.p2_ms);
//     }
//     // and have no errors.
//     ASSERT_INT_EQUAL(UDS_OK, client.err);

//     assert(!ferror(fd));

//     // Until the file has been exhausted. . .
//     while (!feof(fd)) {

//         // the client should send chunks of data from the file.
//         UDSSendTransferDataStream(&client, ++blockNr & 0xFF, maximumNumberOfBlockLength, fd);

//         // When the server responds positively,
//         const uint8_t RESPONSE[] = {0x76, blockNr};
//         isotp_send(&g.srvLink, RESPONSE, sizeof(RESPONSE));

//         g.t0 = g.ms;
//         // The client should return to the idle state
//         while (kRequestStateIdle != client.state) {
//             fixtureSrvLinksProcess();
//             UDSClientPoll(&client);
//             assert(g.ms++ - g.t0 < client.p2_ms); // in under p2 ms
//         }
//         ASSERT_INT_EQUAL(UDS_OK, client.err); // with no error.

//         // and the server link should have received data
//         g.ret = isotp_receive(&g.srvLink, g.scratch, sizeof(g.scratch), &g.size);
//         ASSERT_INT_EQUAL(ISOTP_RET_OK, g.ret);

//         assert(g.ms < 60000); // timeout: TransferDataStream isn't reading the fd.
//     }

//     // The transfer is complete.
//     // The last message contains the final three bytes of the source data.
//     // Create a reference:
//     uint8_t REQUEST[5] = {0x36, 0x05, 0x0, 0x0, 0x0};
//     for (int i = 0; i < 3; i++) {
//         REQUEST[2 + i] = SRC_DATA[(MemorySize - 1) - 2 + i];
//     }
//     // The data received by the server at the should match the reference.
//     ASSERT_INT_EQUAL(g.srvLink.receive_size, sizeof(REQUEST));
//     ASSERT_MEMORY_EQUAL(g.srvLinkRxBuf, REQUEST, sizeof(REQUEST)); // Table 419
//     ASSERT_INT_EQUAL(blockNr, 517);                                    // 14.5.5.1.1

//     // When RequestTransferExit is called
//     UDSSendRequestTransferExit(&client);

//     // the server link should receive data
//     g.t0 = g.ms;

//     do {
//         g.size = g.srvFuncLink.read(g.scratch, sizeof(g.scratch), g.srvFuncLink.arg);
//         fixtureSrvLinksProcess();
//         UDSClientPoll(&client);
//         assert(g.ms++ - g.t0 < client.p2_ms); // in p2 ms
//     } while(0 == g.size);

//     while (ISOTP_RET_OK != isotp_receive(&g.srvLink, g.scratch, sizeof(g.scratch), &g.size))
//     {
//         fixtureSrvLinksProcess();
//         UDSClientPoll(&client);
//         assert(g.ms++ - g.t0 < client.p2_ms); // in p2 ms
//     }

//     // and the data should look like this
//     const uint8_t CORRECT_0x37_REQUEST[] = {0x37};
//     ASSERT_INT_EQUAL(g.size, sizeof(CORRECT_0x37_REQUEST));
//     ASSERT_MEMORY_EQUAL(g.srvLinkRxBuf, CORRECT_0x37_REQUEST, sizeof(CORRECT_0x37_REQUEST));

// #undef MemorySize
//     fclose(fd);
//     remove(fname);
//     TEST_TEARDOWN();
// }

// class SimpleServer {
//   protected:
//     MockTransport &_tp;
//     virtual void _OnMsg(const uint8_t *data, size_t count) = 0;

//   public:
//     SimpleServer(MockTransport &tp) : _tp(tp) {}
//     void Poll() {
//         if (_tp.send_size) {
//             printf("got %d bytes\n", _tp.send_size);
//             _OnMsg(_tp.send_buf, _tp.send_size);
//             _tp.send_size = 0;
//             memset(_tp.send_buf, 0, sizeof(_tp.send_buf));
//         }
//     }
// };

// class TestClientDownloadServer : public SimpleServer {
//     std::vector<uint8_t> _received_data;

//   public:
//     using SimpleServer::SimpleServer;
//     void _OnMsg(const uint8_t *data, size_t count) {
//         ASSERT_INT_GE(count, 1);
//         printhex(_tp.send_buf, _tp.send_size);
//         if (0x34 == data[0]) {
//             const uint8_t REQ[] = {0x34, 0x11, 0x33, 0x60, 0x20, 0x00, 0x00, 0xFF, 0xFF};
//             ASSERT_INT_EQUAL(count, sizeof(REQ));
//             ASSERT_MEMORY_EQUAL(REQ, data, count);
//             const uint8_t buf[] = {0x74, 0x20, 0x00, 0x81};
//             PHYS_TP_RECV(_tp, buf);
//         } else if (0x36 == data[0]) {
//             const uint8_t buf[] = {0x76, data[1]};
//             PHYS_TP_RECV(_tp, buf);
//         } else if (0x37 == data[0]) {
//             const uint8_t buf[] = {0x77};
//             PHYS_TP_RECV(_tp, buf);
//         } else {
//             assert(0);
//         }
//     }
// };

// parameterize: bytes sent vs err code

// void testClientDownload() {
//     TEST_SETUP();
//     {
//         FILE *fd = fopen("testdata.bin", "wb");
//         uint8_t buf[0xFFFF];
//         for (long unsigned int i = 0; i < sizeof(buf); i++) {
//             buf[i] = i;
//         }
//         fwrite(buf, 1, sizeof(buf), fd);
//         fclose(fd);
//     }

//     UDSClient_t client;
//     UDSClientConfig_t cfg = DEFAULT_CLIENT_CONFIG();
//     UDSClientDownloadSequence_t seq;
//     TestClientDownloadServer srv(g.mock_tp);

//     UDSClientInit(&client, &cfg);
//     UDSClientError_t err =
//         UDSConfigDownload(&seq, 0x11, 0x33, 0x602000, 0x00FFFF, fopen("testdata.bin", "rb"));
//     ASSERT_INT_EQUAL(err, UDS_OK);

//     while (g.ms++ < 5000) {
//         UDSSequenceError_t err = UDSSequencePoll(&client, (UDSSequence_t *)&seq);
//         srv.Poll();
//         ASSERT_INT_GE(client.err, 0);
//         ASSERT_INT_GE(err, 0);
//     }

//     ASSERT_INT_EQUAL(seq.err, kUDS_SEQ_COMPLETE);
//     remove("testdata.txt");
//     TEST_TEARDOWN();
// }

/**
 * @brief run all tests
 */
int main(int argc, char **argv) {
    testServerInit();

    testServer0x10DiagSessCtrlIsDisabledByDefault();

    testServer0x10DiagSessCtrlFunctionalRequest();
    testServer0x11DoesNotSendOrReceiveMessagesAfterECUReset();
    testServer0x22RDBI1();
    testServer0x23ReadMemoryByAddress();
    testServer0x27SecurityAccess();
    testServer0x31RCRRP();
    testServer0x34NotEnabled();
    testServer0x34DownloadData();
    // testServer0x36TransferData();
    testServer0x3ESuppressPositiveResponse();
    testServer0x83DiagnosticSessionControl();
    testServerSessionTimeout();

    testClientInit();
    testClientP2TimeoutExceeded();
    testClientP2TimeoutNotExceeded();
    testClientSuppressPositiveResponse();
    testClientBusy();
    testClientUnexpectedResponse();
    testClient0x11ECUReset();
    testClient0x11ECUResetNegativeResponse();
    testClient0x11ECUResetNegativeResponseNoError();
    testClient0x22RDBITxBufferTooSmall();
    testClient0x22RDBIUnpackResponse();
    testClient0x31RequestCorrectlyReceivedResponsePending();
    testClient0x34RequestDownload();
    testClient0x34UDSUnpackRequestDownloadResponse();
    // testClient0x36TransferData();
    // testClientDownload();
}
