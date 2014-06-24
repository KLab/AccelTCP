/*
 * AccelTCP (ACCELerate TCP proxy)
 *
 * Copyright (c) 2013,2014, KLab Inc.
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef acceltcp_h
#define acceltcp_h
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <ev.h>
#include "evsock.h"
#include "http_handler.h"

#define APP_NAME "acceltcp"
#define APP_DESCRIPTION "ACCELerate TCP proxy"
#define APP_VERSION "0.2"
#define APP_AUTHOR "Masaya YAMAMOTO <yamamoto-ma@klab.com>"

#define DEFAULT_SSL_CERITIFICATE_FILE "server.crt"
#define DEFAULT_SSL_PRIVATEKEY_FILE "server.key"

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#define ACCELTCP_TCP_KEEPIDLE  90
#define ACCELTCP_TCP_KEEPINTVL 30
#define ACCELTCP_TCP_KEEPCNT    6

#define ACCELTCP_HDR_MAGIC   0xacce1381
#define ACCELTCP_HDR_FLG_SYN 0x0100
#define ACCELTCP_HDR_FLG_FIN 0x0200
#define ACCELTCP_HDR_FLG_RST 0x0300

#define DEBUG(fmt, ...) \
    do { \
        if (config.debug) { \
            fprintf(stderr, fmt, ## __VA_ARGS__); \
        } \
    } while (0);

#define STRSAFEPRINT(x) ((x) ? (x) : "")

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define BACKLOG 1024

struct hdr {
    uint32_t ___;
    uint32_t xid;
    uint16_t flg;
    uint16_t len;
};

#define HDR_LEN (sizeof(struct hdr))

struct config_tunnel {
    int ipv4only;
    int ipv6only;
    int http;
    char *http_host;
    int server;
    int ssl_accept;
    char *ssl_certificate;
    char *ssl_privatekey;
    int ssl_connect;
    int rbuf;
    int sbuf;
    int connection_num;
    char *self_addr;
    char *self_port;
    char *peer_addr;
    char *peer_port;
    struct config_tunnel *next;
};

struct config {
    int debug;
    int quiet;
    int verbose;
    struct config_tunnel *tunnels;
};

struct ssock {
    struct evsock sock;
    struct tunnel *tunnel;
    struct ssock *next;
};

struct econn {
    struct evsock sock;
    struct {
        http_parser parser;
        struct http_handler_env env;
    } http;
    struct tunnel *tunnel;
    struct session *session;
    struct econn *next;
};

struct pconn {
    int ready;
    struct evsock sock;
    struct tunnel *tunnel;
    struct session *session;
    struct pconn *next;
};

struct session {
    uint32_t xid;
    struct {
        int closed;
        struct buffer buf;
        size_t bytes;
    } e2p;
    struct {
        int closed;
        struct buffer buf;
        size_t bytes;
    } p2e;
    struct econn *econn;
    struct pconn *pconn;
};

struct tunnel {
    int id;
    struct {
        SSL_CTX *server_ctx;
        SSL_CTX *client_ctx;
    } ssl;
    struct config_tunnel *config;
    struct ssock *ssocks;
    struct pconn *pconns;
    struct tunnel *next;
};

extern struct config config;
extern struct tunnel *tunnels;

extern void
usage (void);

extern int
option_parse_tunnel (char *s, struct config_tunnel *c);

extern int
option_parse (int argc, char *argv[], struct config *config);

extern struct tunnel *
tunnel_setup (struct ev_loop *loop, struct config_tunnel *c);

extern void
timeout_cb (struct ev_loop *loop, struct ev_timer *w, int revents);

extern void
signal_cb (struct ev_loop *loop, struct ev_signal *w, int revents);

extern int
acceltcp (int argc, char *argv[]);

#ifdef __cplusplus
}
#endif
#endif
