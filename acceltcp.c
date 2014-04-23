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
#define APP_VERSION "0.1"
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

static struct config config;
static struct tunnel *tunnels;

void
hexdump (FILE *fp, void *data, size_t size) {
    unsigned char *src;
    int offset, index;

    src = (unsigned char *)data;
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
    for(offset = 0; offset < (int)size; offset += 16) {
        fprintf(fp, "| %04x | ", offset);
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                fprintf(fp, "%02x ", 0xff & src[offset + index]);
            } else {
                fprintf(fp, "   ");
            }
        }
        fprintf(fp, "| ");
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                if(isascii(src[offset + index]) && isprint(src[offset + index])) {
                    fprintf(fp, "%c", src[offset + index]);
                } else {
                    fprintf(fp, ".");
                }
            } else {
                fprintf(fp, " ");
            }
        }
        fprintf(fp, " |\n");
    }
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
}

static int
getclientsock (int family, const char *node, const char *service) {
    struct addrinfo hints, *ais, *ai;
    int err, fd, opt;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    err = getaddrinfo(node, service, &hints, &ais);
    if (err) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }
    for (ai = ais; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == -1) {
            perror("socket");
            continue;
        }
        opt = 1;
        if (ioctl(fd, FIONBIO, &opt) == -1) {
            perror("ioctl");
            close(fd);
            continue;
        }
        opt = 1;
        if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
            perror("setsockopt");
            close(fd);
            return -1;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
            if (errno != EINPROGRESS) {
                perror("connect");
                close(fd);
                continue;
            }
        }
        freeaddrinfo(ais);
        return fd;
    }
    freeaddrinfo(ais);
    return -1;
}

const char *
sockaddr_ntop (const struct sockaddr *sa, char *buf, socklen_t size) {
    switch (sa->sa_family) {
    case AF_INET:
        return inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, buf, size);
    case AF_INET6:
        return inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, buf, size);
    default:
        return NULL;
    }
}

static void
econn_destroy_cb (void *arg) {
    struct econn *e;
    struct ssock *s;

    e = (struct econn *)arg;
    DEBUG("[%10.3f] econn_destroy_cb\n", ev_now(e->sock.loop));
    DEBUG("tunnel->id=%u\n", e->tunnel->id);
    if (e->session) {
        DEBUG("session->xid=%u\n", e->session->xid);
        if (e->session->pconn) {
            if (e->sock.state == EVSOCK_STATE_ESTABLISHED) {
                e->session->econn = NULL;
                if (!e->session->e2p.closed || !e->session->p2e.closed) {
                    DEBUG("session free\n");
                    e->session->pconn->session = NULL;
                    free(e->session);
                }
            } else {
                e->session->pconn->session = NULL;
                free(e->session);
            }
        } else {
            free(e->session);
        }
    }
    for (s = e->tunnel->ssocks; s; s = s->next) {
        if (!ev_is_active(&s->sock.w)) {
            ev_io_start(s->sock.loop, &s->sock.w);
        }
    }
    free(e);
}

static ssize_t
econn_read_cb (struct evsock *sock, const char *buf, size_t len, int *stop) {
    struct econn *e;
    size_t n, nparsed;

    DEBUG("[%10.3f] econn_read_cb\n", ev_now(sock->loop));
    e = (struct econn *)sock->data.ptr;
    DEBUG("tunnel->id=%u\n", e->tunnel->id);
    if (!e->session) {
        return -1;
    }
    DEBUG("session->xid=%u\n", e->session->xid);
    n = MIN(sizeof(e->session->e2p.buf.data) - e->session->e2p.buf.n, len);
    DEBUG("n=%zu (session->e2p.buf.n=%zu, len=%zu)\n", n, e->session->e2p.buf.n, len);
    if (n) {
        if (!e->tunnel->config->server && e->tunnel->config->http) {
            nparsed = http_parser_execute(&e->http.parser, &http_request_settings, buf, n);
            if (nparsed != n) {
                fprintf(stderr, "http_perser_execute: error\n");
                return -1;
            }
        } else {
            memcpy(e->session->e2p.buf.data + e->session->e2p.buf.n, buf, n);
            e->session->e2p.buf.n += n;
        }
    } else {
        if (!len) {
            e->session->e2p.closed = 1;
        } else {
            *stop = 1;
        }
    }
    if (e->session->pconn) {
        evsock_wakeup(&e->session->pconn->sock, EVSOCK_HOW_TX);
    }
    return (ssize_t)n;
}

static ssize_t
econn_write_cb (struct evsock *sock, char *buf, size_t size, int *closed) {
    struct econn *e;
    size_t n;

    DEBUG("[%10.3f] econn_write_cb\n", ev_now(sock->loop));
    e = (struct econn *)sock->data.ptr;
    DEBUG("tunnel->id=%u\n", e->tunnel->id);
    if (!e->session) {
        return -1;
    }
    DEBUG("session->xid=%u\n", e->session->xid);
    n = MIN(e->session->p2e.buf.n, size);
    DEBUG("n=%zu (session->p2e.buf.n=%zu, size=%zu)\n", n, e->session->p2e.buf.n, size);
    if (n) {
        memcpy(buf, e->session->p2e.buf.data, n);
        memmove(e->session->p2e.buf.data, e->session->p2e.buf.data + n, e->session->p2e.buf.n - n);
        e->session->p2e.buf.n -= n;
    }
    if (e->session->p2e.closed && !e->session->p2e.buf.n) {
        if (e->session->e2p.closed && !e->session->e2p.buf.n) {
            if (!n) {
                e->session->econn = NULL;
                if (!e->session->pconn) {
                    free(e->session);
                }
                e->session = NULL;
                return -1;
            }
        }
        *closed = 1;
    }
    if (e->session->pconn) {
        evsock_wakeup(&e->session->pconn->sock, EVSOCK_HOW_RX);
    }
    return (ssize_t)n;
}

static int
econn_connected_cb (struct evsock *sock) {
    struct econn *e;

    DEBUG("[%10.3f] econn_connected_cb\n", ev_now(sock->loop));
    e = (struct econn *)sock->data.ptr;
    DEBUG("tunnel->id=%u, session->xid=%u\n", e->tunnel->id, e->session->xid);
    return 0;
}

static int
econn_accept_cb (struct evsock *sock) {
    struct econn *e;
    int opt;
    static uint32_t xid = 0;

    DEBUG("[%10.3f] econn_accept_cb\n", ev_now(sock->loop));
    e = (struct econn *)sock->data.ptr;
    DEBUG("tunnel->id=%u\n", e->tunnel->id);
#ifndef TCP_KEEPIDLE
    opt = 10;
#else
    opt = 1;
#endif
    if (setsockopt(e->sock.fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        return -1;
    }
#ifdef TCP_KEEPIDLE
    opt = 10;
    if (setsockopt(e->sock.fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        return -1;
    }
#endif
    opt = 5;
    if (setsockopt(e->sock.fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        return -1;
    }
    opt = 4;
    if (setsockopt(e->sock.fd, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        return -1;
    }
    if (e->tunnel->config->http) {
        http_parser_init(&e->http.parser, HTTP_REQUEST);
        e->http.parser.data = &e->http.env;
        sockaddr_ntop((struct sockaddr *)&e->sock.peer, e->http.env.client, sizeof(e->http.env.client));
        e->http.env.host = e->tunnel->config->http_host;
        e->http.env.buf = &e->session->e2p.buf;
    }
    e->session->xid = xid++;
    DEBUG("session->xid=%u\n", e->session->xid);
    return 0;
}

static struct evsock *
econn_pre_accept_cb (struct evsock *sock) {
    struct ssock *s;
    struct pconn *p;
    struct econn *e;

    DEBUG("[%10.3f] econn_pre_accept_cb\n", ev_now(sock->loop));
    s = (struct ssock *)sock->data.ptr;
    DEBUG("tunnel->id=%u\n", s->tunnel->id);
    for (p = s->tunnel->pconns; p; p = p->next) {
        if (p->ready && !p->session) {
            break;
        }
    }
    if (!p) {
        DEBUG("accept pennding\n");
        return NULL;
    }
    e = calloc(1, sizeof(*e));
    if (!e) {
        fprintf(stderr, "calloc: error\n");
        return NULL;
    }
    e->session = calloc(1, sizeof(*e->session));
    if (!e->session) {
        fprintf(stderr, "calloc: error\n");
        free(e);
        return NULL;
    }
    e->tunnel = s->tunnel;
    e->session->econn = e;
    e->session->pconn = p;
    p->session = e->session;
    e->sock.data.ptr = e;
    e->sock.data.destroy = econn_destroy_cb;
    return &e->sock;
}

static void
pconn_destroy_cb (void *arg) {
    struct pconn *p, *tmp;

    p = (struct pconn *)arg;
    DEBUG("[%10.3f] pconn_destroy_cb\n", ev_now(p->sock.loop));
    DEBUG("tunnel->id=%u\n", p->tunnel->id);
    if (p->session) {
        DEBUG("session->xid=%u\n", p->session->xid);
        if (p->session->econn) {
            p->session->pconn = NULL;
        } else {
            free(p->session);
        }
    }
    if (p->tunnel->pconns == p) {
        p->tunnel->pconns = p->next;
    } else {
        for (tmp = p->tunnel->pconns; tmp; tmp = tmp->next) {
            if (tmp->next == p) {
                tmp->next = p->next;
                break;
            }
        }
    }
    free(p);
}

static ssize_t
pconn_read_cb (struct evsock *sock, const char *buf, size_t len, int *stop) {
    struct pconn *p;
    struct econn *e;
    size_t n, bs, bl;
    struct hdr *hdr;

    DEBUG("[%10.3f] pconn_read_cb\n", ev_now(sock->loop));
    p = (struct pconn *)sock->data.ptr;
    DEBUG("tunnel->id=%u\n", p->tunnel->id);
    if (p->session) {
        DEBUG("session->xid=%u\n", p->session->xid);
    }
    DEBUG("len=%zu\n", len);
    if (!len) {
        if (!p->session) {
            return -1;
        }
        p->session->p2e.closed = 1;
        if (p->session->econn) {
            evsock_wakeup(&p->session->econn->sock, EVSOCK_HOW_TX);
        }
        return 0;
    }
    n = len;
    while (n >= HDR_LEN) {
        DEBUG("n=%zu\n", n);
        hdr = (struct hdr *)(buf + (len - n));
        if (ntohl(hdr->___) != ACCELTCP_HDR_MAGIC) {
            fprintf(stderr, "invalid header\n");
            return -1;
        }
        if (!p->session) {
            if (ntohs(hdr->flg) == ACCELTCP_HDR_FLG_SYN) {
                DEBUG("SYN recv, xid=%u\n", ntohl(hdr->xid));
                e = calloc(1, sizeof(*e));
                if (!e) {
                    fprintf(stderr, "calloc: error\n");
                    return -1;
                }
                e->sock.fd = getclientsock(AF_INET, p->tunnel->config->peer_addr, p->tunnel->config->peer_port);
                if (e->sock.fd == -1) {
                    fprintf(stderr, "getclientsock: error\n");
                    free(e);
                    return -1;
                }
                DEBUG("getclientsock: fd=%d\n", e->sock.fd);
                e->sock.state = EVSOCK_STATE_CONNECT;
                e->sock.ctx = p->tunnel->ssl.client_ctx;
                e->sock.loop = sock->loop;
                e->sock.w.data = &e->sock;
                e->sock.on_connect = econn_connected_cb;
                e->sock.on_read = econn_read_cb;
                e->sock.on_write = econn_write_cb;
                ev_io_init(&e->sock.w, evsock_handler, e->sock.fd, EV_READ | EV_WRITE);
                ev_io_start(e->sock.loop, &e->sock.w);
                e->sock.data.ptr = e;
                e->sock.data.destroy = econn_destroy_cb;
                e->session = calloc(1, sizeof(*e->session));
                if (!e->session) {
                    fprintf(stderr, "calloc: error\n");
                    close(e->sock.fd);
                    ev_io_stop(e->sock.loop, &e->sock.w);
                    free(e);
                    return -1;
                }
                e->tunnel = p->tunnel;
                p->session = e->session;
                p->session->xid = ntohl(hdr->xid);
                p->session->pconn = p;
                p->session->econn = e;
            }
        }
        bl = ntohs(hdr->len);
        bs = HDR_LEN + bl;
        if (n < bs) {
            DEBUG("more read (need block size)\n");
            p->sock.rx.more_read = 1;
            break;
        }
        if (ntohs(hdr->flg) == ACCELTCP_HDR_FLG_RST) {
            DEBUG("RST recv, xid=%u\n", ntohl(hdr->xid));
            if (p->session && ntohl(hdr->xid) == p->session->xid) {
                if (p->session->econn) {
                    p->session->econn->session = NULL;
                    evsock_wakeup(&p->session->econn->sock, EVSOCK_HOW_RX | EVSOCK_HOW_TX);
                }
                free(p->session);
                p->session = NULL;
            }
            n -= bs;
            continue;
        }
        if (!p->session || ntohl(hdr->xid) != p->session->xid) {
            DEBUG("another session block\n");
            if ((sizeof(p->sock.tx.buf.data) - p->sock.tx.buf.n) >= HDR_LEN) {
                DEBUG("RST send, xid=%u\n", ntohl(hdr->xid));
                hdr = (struct hdr *)(p->sock.tx.buf.data + p->sock.tx.buf.n);
                hdr->___ = htonl(ACCELTCP_HDR_MAGIC);
                hdr->xid = hdr->xid;
                hdr->flg = htons(ACCELTCP_HDR_FLG_RST);
                hdr->len = htons(0);
                p->sock.tx.buf.n += HDR_LEN;
                evsock_wakeup(&p->sock, EVSOCK_HOW_TX);
            }
            n -= bs;
            continue;
        }
        if (ntohs(hdr->flg) == ACCELTCP_HDR_FLG_FIN) {
            DEBUG("FIN recv\n");
            p->session->p2e.closed = 1;
            if (p->session->econn) {
                evsock_wakeup(&p->session->econn->sock, EVSOCK_HOW_TX);
            }
            if (p->session->e2p.closed == 2 && !p->session->e2p.buf.n) {
                p->session->pconn = NULL;
                p->session = NULL;
            }
            n -= bs;
            continue;
        }
        if (sizeof(p->session->p2e.buf.data) - p->session->p2e.buf.n < bl) {
            *stop = 1;
            if (p->session->econn) {
                evsock_wakeup(&p->session->econn->sock, EVSOCK_HOW_TX);
            }
            return len - n;
        }
        p->session->p2e.bytes += bl;
        memcpy(p->session->p2e.buf.data + p->session->p2e.buf.n, hdr + 1, bl);
        p->session->p2e.buf.n += bl;
        n -= bs;
        if (p->session->econn && p->session->econn->sock.state != EVSOCK_STATE_CONNECT) {
            evsock_wakeup(&p->session->econn->sock, EVSOCK_HOW_TX);
        }
    }
    if (n && n < HDR_LEN) {
        DEBUG("more read (need header size)\n");
        p->sock.rx.more_read = 1;
    }
    return len - n;
}

static ssize_t
pconn_write_cb (struct evsock *sock, char *buf, size_t size, int *closed) {
    struct pconn *p;
    struct hdr *hdr;
    size_t n;

    DEBUG("[%10.3f] pconn_write_cb\n", ev_now(sock->loop));
    p = (struct pconn *)sock->data.ptr;
    DEBUG("tunnel->id=%u\n", p->tunnel->id);
    if (!p->session) {
        DEBUG("session not attached\n");
        return 0;
    }
    DEBUG("session->xid=%u\n", p->session->xid);
    DEBUG("size=%zu, session->e2p.buf.n=%zu\n", size, p->session->e2p.buf.n);
    if (!p->session->e2p.buf.n) {
        if (p->session->e2p.closed == 1) {
            DEBUG("FIN send\n");
            p->session->e2p.closed = 2;
            hdr = (struct hdr *)buf;
            hdr->___ = htonl(ACCELTCP_HDR_MAGIC);
            hdr->xid = htonl(p->session->xid);
            hdr->flg = htons(ACCELTCP_HDR_FLG_FIN);
            hdr->len = htons(0);
            return HDR_LEN;
        } else if (p->session->e2p.closed == 2) {
            if (p->session->p2e.closed) {
                DEBUG("session dettach\n");
                if (p->session->econn) {
                    p->session->pconn = NULL;
                } else {
                    DEBUG("session free\n");
                    free(p->session);
                }
                p->session = NULL;
                return 0;
            }
        }
    } else {
        n = MIN(p->session->e2p.buf.n, size - HDR_LEN);
        DEBUG("n=%zu\n", n);
        if (n) {
            hdr = (struct hdr *)buf;
            hdr->___ = htonl(ACCELTCP_HDR_MAGIC);
            hdr->xid = htonl(p->session->xid);
            hdr->flg = htons((!p->tunnel->config->server && !p->session->e2p.bytes) ? ACCELTCP_HDR_FLG_SYN : 0);
            hdr->len = htons(n);
            memcpy(hdr + 1, p->session->e2p.buf.data, n);
            memmove(p->session->e2p.buf.data, p->session->e2p.buf.data + n, p->session->e2p.buf.n - n);
            p->session->e2p.buf.n -= n;
            p->session->e2p.bytes += n;
            if (p->session->econn) {
                evsock_wakeup(&p->session->econn->sock, EVSOCK_HOW_RX);
            }
            return HDR_LEN + n;
        }
    }
    return 0;
}

static int
pconn_connected_cb (struct evsock *sock) {
    struct pconn *p;
    struct ssock *s;

    DEBUG("[%10.3f] pconn_connected_cb\n", ev_now(sock->loop));
    p = (struct pconn *)sock->data.ptr;
    DEBUG("tunnel->id=%u\n", p->tunnel->id);
    p->ready = 1;
    for (s = p->tunnel->ssocks; s; s = s->next) {
        if (!ev_is_active(&s->sock.w)) {
            ev_io_start(s->sock.loop, &s->sock.w);
        }
    }
    return 0;
}

static int
pconn_accept_cb (struct evsock *sock) {
    struct pconn *p;

    DEBUG("[%10.3f] pconn_accept_cb\n", ev_now(sock->loop));
    p = (struct pconn *)sock->data.ptr;
    DEBUG("tunnel->id=%u\n", p->tunnel->id);
    p->ready = 1;
    return 0;
}

static struct evsock *
pconn_pre_accept_cb (struct evsock *sock) {
    struct ssock *s;
    struct pconn *p;

    DEBUG("[%10.3f] pconn_pre_accept_cb\n", ev_now(sock->loop));
    s = (struct ssock *)sock->data.ptr;
    DEBUG("tunnel->id=%u\n", s->tunnel->id);
    p = calloc(1, sizeof(*p));
    if (!p) {
        fprintf(stderr, "calloc: error\n");
        return NULL;
    }
    p->tunnel = s->tunnel;
    p->next = p->tunnel->pconns;
    p->tunnel->pconns = p;
    p->sock.data.ptr = p;
    p->sock.data.destroy = pconn_destroy_cb;
    return &p->sock;
}

static void
usage (void) {
    printf("usage: %s [options] -- [tunnel_options] tunnel\n", APP_NAME);
    printf("  Options:\n");
    printf("    -d, --debug                # debug mode\n");
    printf("    -h, --help                 # show this message\n");
    printf("    -q, --quiet                # quiet mode\n");
    printf("    -v, --verbose              # verbose mode\n");
    printf("    -V, --version              # show version\n");
    printf("  Tunnel Options:\n");
    printf("    -4, --ipv4only             # IPv4 only\n");
    printf("    -6, --ipv6only             # IPv6 only\n");
    printf("        --connection-num=num   # connection pool num (default: 0)\n");
    printf("        --http                 # enable http mode\n");
    printf("        --http-host=host       # http HOST header value\n");
    printf("        --rbuf=size            # recieve socket buffer (default: system default)\n");
    printf("        --sbuf=size            # send socket buffer (default: system default)\n");
    printf("        --server               # enable server mode\n");
    printf("        --ssl-accept           # enable SSL accept\n");
    printf("        --ssl-certificate=file # SSL certificate file (default: ./server.crt)\n");
    printf("        --ssl-privatekey=file  # SSL private-key file (default: ./server.key)\n");
    printf("        --ssl-connect          # enable SSL connect\n");
    printf("  Tunnel: (addr and port is numeric only)\n");
    printf("    [local_addr:]local_port:remote_addr:remote_port\n");
    printf("  Example:\n");
    printf("    [user@10.10.0.100]$ %s -- --server --ssl-accept --ssl-connect 40381:133.242.5.116:443\n", APP_NAME);
    printf("    [user@10.10.0.200]$ %s -- --http --http-host=www.klab.com --connection-num=100 --ssl-accept --ssl-connect 8443:10.10.0.100:40381\n", APP_NAME);
}

static void
version (void) {
    printf("%s (%s) version %s\n", APP_NAME, APP_DESCRIPTION, APP_VERSION);
    printf("  Author: %s\n", APP_AUTHOR);
}

static char *
hptok (char **p) {
    char *s, *e;

    if (!p || !(*p)) {
        return NULL;
    }
    s = *p;
    if (*s == '[') {
        e = strchr(s, ']');
        if (!e) {
            return NULL;
        }
        e++;
    } else {
        e = strchr(s, ':');
        if (!e) {
            e = s + strlen(s);
        }
    }
    switch (*e) {
    case '\0':
        *p = NULL;
        break;
    case ':':
        *e = '\0';
        *p = e + 1;
        break;
    default:
        return NULL;
    }
    return s;
}

static int
strisdigit (const char *s) {
    if (!s || !*s) {
        return 0;
    }
    while (*s) {
        if (!isdigit(*(s++))) {
            return 0;
        }
    }
    return 1;
}

static int
option_parse_tunnel (char *s, struct config_tunnel *c) {
    char *p, *t[4];
    size_t n;

    p = s;
    for (n = 0; n < 4; n++) {
        t[n] = hptok(&p);
        if (!t[n]) {
            break;
        }
    }
    if (p) {
        return -1;
    }
    switch (n) {
    case 3:
        if (!*t[0] || !*t[1] || !*t[2]) {
            return -1;
        }
        c->self_port = t[0];
        c->peer_addr = t[1];
        c->peer_port = t[2];
        break;
    case 4:
        if (!*t[0] || !*t[1] || !*t[2] || !*t[3]) {
            return -1;
        }
        c->self_addr = t[0];
        c->self_port = t[1];
        c->peer_addr = t[2];
        c->peer_port = t[3];
        break;
    default:
        return -1;
    }
    return 0;
}

static int
option_parse (int argc, char *argv[], struct config *config) {
    int opt;
    struct config_tunnel *c;

    static struct option long_options[] = {
        {"debug",     0, NULL, 'd'},
        {"help",      0, NULL, 'h'},
        {"quiet",     0, NULL, 'q'},
        {"verbose",   0, NULL, 'v'},
        {"version",   0, NULL, 'V'},
        { NULL,       0, NULL,  0 }
    };
    static struct option long_tunnel_options[] = {
        {"http",            0, NULL, 100},
        {"http-host",       1, NULL, 101},
        {"ipv4only",        0, NULL, '4'},
        {"ipv6only",        0, NULL, '6'},
        {"connection-num",  1, NULL, 105},
        {"rbuf",            1, NULL, 102},
        {"sbuf",            1, NULL, 103},
        {"server",          0, NULL, 104},
        {"ssl-accept",      0, NULL, 301},
        {"ssl-certificate", 1, NULL, 302},
        {"ssl-privatekey",  1, NULL, 303},
        {"ssl-connect",     0, NULL, 304},
        { NULL,             0, NULL,  0 }
    };

    while ((opt = getopt_long_only(argc, argv, "dhqvV", long_options, NULL)) != -1) {
        switch (opt) {
        case 'd':
            config->debug = 1;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case 'q':
            config->quiet = 1;
            break;
        case 'v':
            config->verbose = 1;
            break;
        case 'V':
            version();
            exit(EXIT_SUCCESS);
        default:
            return -1;
        }
    }
    while (optind < argc) {
        c = calloc(1, sizeof(*c));
        if (!c) {
            fprintf(stderr, "calloc: error\n");
            return -1;
        }
        while ((opt = getopt_long_only(argc, argv, "46", long_tunnel_options, NULL)) != -1) {
            switch (opt) {
            case '4':
                c->ipv4only = 1;
                break;
            case '6':
                c->ipv6only = 1;
                break;
            case 100:
                c->http = 1;
                break;
            case 101:
                c->http_host = optarg;
                break;
            case 102:
                if (!strisdigit(optarg)) {
                    return -1;
                }
                c->rbuf = strtol(optarg, NULL, 10);
                if (c->rbuf < 0) {
                    return -1;
                }
                break;
            case 103:
                if (!strisdigit(optarg)) {
                    return -1;
                }
                c->sbuf = strtol(optarg, NULL, 10);
                if (c->sbuf < 0) {
                    return -1;
                }
                break;
            case 104:
                c->server = 1;
                break;
            case 105:
                if (!strisdigit(optarg)) {
                    return -1;
                }
                c->connection_num = strtol(optarg, NULL, 10);
                if (c->connection_num < 0) {
                    return -1;
                }
                break;
            case 301:
                c->ssl_accept = 1;
                if (!c->ssl_certificate) {
                    c->ssl_certificate = DEFAULT_SSL_CERITIFICATE_FILE;
                }
                if (!c->ssl_privatekey) {
                    c->ssl_privatekey = DEFAULT_SSL_PRIVATEKEY_FILE;
                }
                break;
            case 302:
                c->ssl_certificate = optarg;
                break;
            case 303:
                c->ssl_privatekey = optarg;
                break;
            case 304:
                c->ssl_connect = 1;
                break;
            default:
                free(c);
                return -1;
            }
        }
        if (c->ssl_accept && (!c->ssl_certificate || !c->ssl_privatekey)) {
            free(c);
            return -1;
        }
        if (optind >= argc) {
            free(c);
            return -1;
        }
        if (option_parse_tunnel(argv[optind], c) == -1) {
            free(c);
            return -1;
        }
        if (!c->connection_num) {
            c->connection_num = 1;
        }
        c->next = config->tunnels;
        config->tunnels = c;
        optind++;
    }
    if (!config->tunnels) {
        return -1;
    }
    return 0;
}

static void
config_debug (struct config *config) {
    struct config_tunnel *c;

    printf("config_debug():\n");
    printf("debug: %d\n", config->debug);
    printf("quiet: %d\n", config->quiet);
    printf("verbose: %d\n", config->verbose);
    for (c = config->tunnels; c; c = c->next) {
        printf("--\n");
        printf("http: %d\n", c->http);
        printf("http_host: %s\n", STRSAFEPRINT(c->http_host));
        printf("ipv4only: %d\n", c->ipv4only);
        printf("ipv4only: %d\n", c->ipv6only);
        printf("connection_num: %d\n", c->connection_num);
        printf("rbuf: %d\n", c->rbuf);
        printf("sbuf: %d\n", c->sbuf);
        printf("server: %d\n", c->server);
        printf("ssl_accept: %d\n", c->ssl_accept);
        printf("ssl_certificate: %s\n", STRSAFEPRINT(c->ssl_certificate));
        printf("ssl_privatekey: %s\n", STRSAFEPRINT(c->ssl_privatekey));
        printf("ssl_connect: %d\n", c->ssl_connect);
        printf("self_addr: %s\n", STRSAFEPRINT(c->self_addr));
        printf("self_port: %s\n", STRSAFEPRINT(c->self_port));
        printf("peer_addr: %s\n", STRSAFEPRINT(c->peer_addr));
        printf("peer_port: %s\n", STRSAFEPRINT(c->peer_port));
    }
}

static void
tunnel_cleanup (struct tunnel *tunnel) {
    struct ssock *s;
    struct pconn *p;

    while ((s = tunnel->ssocks)) {
        tunnel->ssocks = s->next;
        close(s->sock.fd);
        free(s);
    }
    while ((p = tunnel->pconns)) {
        tunnel->pconns = p->next;
        close(p->sock.fd);
        free(p);
    }
    free(tunnel);
}

static int
tunnel_setup_ssocks (struct ev_loop *loop, struct tunnel *tunnel) {
    struct addrinfo hints, *ais, *ai;
    int err, fd, opt, count = 0;
    struct ssock *s;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = tunnel->config->ipv4only ? AF_INET : (tunnel->config->ipv6only ? AF_INET6 : AF_UNSPEC);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE,
    err = getaddrinfo(tunnel->config->self_addr, tunnel->config->self_port, &hints, &ais);
    if (err) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }
    for (ai = ais; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == -1) {
            perror("socket");
            continue;
        }
        opt = 1;
        if (ioctl(fd, FIONBIO, &opt) == -1) {
            perror("ioctl");
            close(fd);
            continue;
        }
        opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
            perror("setsockopt");
            close(fd);
            continue;
        }
        opt = 1;
        if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
            perror("setsockopt");
            close(fd);
            continue;
        }
        if (tunnel->config->server){
            if (tunnel->config->rbuf) {
                opt = tunnel->config->rbuf;
#ifdef SO_RCVBUFFORCE
                if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &opt, sizeof(opt)) == -1) {
#endif
                if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1) {
                    perror("setsockopt");
                    close(fd);
                    continue;
                }
#ifdef SO_RCVBUFFORCE
                }
#endif
            }
            if (tunnel->config->sbuf) {
                opt = tunnel->config->sbuf;
#ifdef SO_SNDBUFFORCE
                if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &opt, sizeof(opt)) == -1) {
#endif
                if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) == -1) {
                    perror("setsockopt");
                    close(fd);
                    continue;
                }
#ifdef SO_SNDBUFFORCE
                }
#endif
            }
#ifndef TCP_KEEPIDLE
            opt = ACCELTCP_TCP_KEEPIDLE;
#else
            opt = 1;
#endif
            if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == -1) {
                perror("setsockopt");
                close(fd);
                continue;
            }
#ifdef TCP_KEEPIDLE
            opt = ACCELTCP_TCP_KEEPIDLE;
            if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(opt)) == -1) {
                perror("setsockopt");
                close(fd);
                continue;
            }
#endif
            opt = ACCELTCP_TCP_KEEPINTVL;
            if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(opt)) == -1) {
                perror("setsockopt");
                close(fd);
                continue;
            }
            opt = ACCELTCP_TCP_KEEPCNT;
            if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(opt)) == -1) {
                perror("setsockopt");
                close(fd);
                continue;
            }
        }
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
            perror("bind");
            close(fd);
            continue;
        }
        s = calloc(1, sizeof(*s));
        if (!s) {
            perror("calloc");
            close(fd);
            continue;
        }
        s->sock.fd = fd;
        s->sock.state = EVSOCK_STATE_ACCEPT;
        s->sock.ctx = tunnel->ssl.server_ctx;
        s->sock.loop = loop;
        s->sock.w.data = s;
        ev_io_init(&s->sock.w, evsock_handler, s->sock.fd, EV_READ);
        if (tunnel->config->server) {
            s->sock.on_pre_accept = pconn_pre_accept_cb;
            s->sock.on_accept = pconn_accept_cb;
            s->sock.on_read = pconn_read_cb;
            s->sock.on_write = pconn_write_cb;
        } else {
            s->sock.on_pre_accept = econn_pre_accept_cb;
            s->sock.on_accept = econn_accept_cb;
            s->sock.on_read = econn_read_cb;
            s->sock.on_write = econn_write_cb;
        }
        s->sock.data.ptr = s;
        s->sock.data.destroy = free;
        s->tunnel = tunnel;
        s->next = tunnel->ssocks;
        tunnel->ssocks = s;
        count++;
    }
    freeaddrinfo(ais);
    return count;
}

static int
tunnel_setup_pconns (struct ev_loop *loop, struct tunnel *tunnel) {
    struct addrinfo hints, *ais, *ai;
    int err, fd, opt, count;
    struct pconn *p;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = tunnel->config->ipv4only ? AF_INET : (tunnel->config->ipv6only ? AF_INET6 : AF_UNSPEC);
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(tunnel->config->peer_addr, tunnel->config->peer_port, &hints, &ais);
    if (err) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }
    ai = ais;
    for (count = 0; count < tunnel->config->connection_num; count++) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == -1) {
            perror("socket");
            break;
        }
        opt = 1;
        if (ioctl(fd, FIONBIO, &opt) == -1) {
            perror("ioctl");
            close(fd);
            break;
        }
        opt = 1;
        if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
            perror("setsockopt");
            close(fd);
            break;
        }
        if (tunnel->config->rbuf) {
            opt = tunnel->config->rbuf;
#ifdef SO_RCVBUFFORCE
            if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &opt, sizeof(opt)) == -1) {
#endif
            if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1) {
                perror("setsockopt");
                close(fd);
                break;
            }
#ifdef SO_RCVBUFFORCE
            }
#endif
        }
        if (tunnel->config->sbuf) {
            opt = tunnel->config->sbuf;
#ifdef SO_SNDBUFFORCE
            if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &opt, sizeof(opt)) == -1) {
#endif
            if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) == -1) {
                perror("setsockopt");
                close(fd);
                break;
            }
#ifdef SO_SNDBUFFORCE
            }
#endif
        }
#ifndef TCP_KEEPIDLE
        opt = ACCELTCP_TCP_KEEPIDLE;
#else
        opt = 1;
#endif
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == -1) {
            perror("setsockopt");
            close(fd);
            break;
        }
#ifdef TCP_KEEPIDLE
        opt = ACCELTCP_TCP_KEEPIDLE;
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(opt)) == -1) {
            perror("setsockopt");
            close(fd);
            break;
        }
#endif
        opt = ACCELTCP_TCP_KEEPINTVL;
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(opt)) == -1) {
            perror("setsockopt");
            close(fd);
            break;
        }
        opt = ACCELTCP_TCP_KEEPCNT;
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(opt)) == -1) {
            perror("setsockopt");
            close(fd);
            break;
        }
        p = calloc(1, sizeof(*p));
        if (!p) {
            fprintf(stderr, "calloc: error\n");
            close(fd);
            break;
        }
        p->sock.fd = fd;
        p->sock.state = EVSOCK_STATE_CONNECT;
        p->sock.ctx = tunnel->ssl.client_ctx;
        memcpy(&p->sock.peer, ai->ai_addr, ai->ai_addrlen);
        p->sock.peerlen = ai->ai_addrlen;
        p->sock.on_connect = pconn_connected_cb;
        p->sock.on_read = pconn_read_cb;
        p->sock.on_write = pconn_write_cb;
        p->sock.loop = loop;
        p->sock.w.data = &p->sock;
        ev_io_init(&p->sock.w, evsock_handler, p->sock.fd, EV_WRITE);
        p->sock.data.ptr = p;
        p->sock.data.destroy = pconn_destroy_cb;
        p->tunnel = tunnel;
        p->next = tunnel->pconns;
        tunnel->pconns = p;
    }
    freeaddrinfo(ais);
    return count;
}

static struct tunnel *
tunnel_setup (struct ev_loop *loop, struct config_tunnel *c) {
    struct tunnel *tunnel;
    int ret;
    static int id = 0;

    tunnel = calloc(1, sizeof(*tunnel));
    if (!tunnel) {
        return NULL;
    }
    tunnel->config = c;
    if (tunnel->config->ssl_accept) {
        tunnel->ssl.server_ctx = SSL_CTX_new(SSLv23_server_method());
        if (!tunnel->ssl.server_ctx) {
            fprintf(stderr, "SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
            free(tunnel);
            return NULL;
        }
        if (SSL_CTX_use_certificate_file(tunnel->ssl.server_ctx, tunnel->config->ssl_certificate, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "SSL_CTX_use_certificate_file: %s\n", ERR_error_string(ERR_get_error(), NULL));
            free(tunnel);
            return NULL;
        }
        if (SSL_CTX_use_PrivateKey_file(tunnel->ssl.server_ctx, tunnel->config->ssl_privatekey, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "SSL_CTX_use_certificate_file: %s\n", ERR_error_string(ERR_get_error(), NULL));
            free(tunnel);
            return NULL;
        }
    }
    if (tunnel->config->ssl_connect) {
        tunnel->ssl.client_ctx = SSL_CTX_new(SSLv23_client_method());
        if (!tunnel->ssl.client_ctx) {
            fprintf(stderr, "SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
            free(tunnel);
            return NULL;
        }
    }
    ret = tunnel_setup_ssocks(loop, tunnel);
    if (ret <= 0) {
        tunnel_cleanup(tunnel);
        return NULL;
    }
    if (tunnel->config->server) {
        tunnel->id = id++;
        return tunnel;
    }
    ret = tunnel_setup_pconns(loop, tunnel);
    if (ret <= 0) {
        tunnel_cleanup(tunnel);
        return NULL;
    }
    tunnel->id = id++;
    return tunnel;
}

static void
timeout_cb (struct ev_loop *loop, struct ev_timer *w, int revents) {
    struct tunnel *t;
    struct pconn *p;
    size_t count, active, used;

    for (t = tunnels; t; t = t->next) {
        count = active = used = 0;
        for (p = t->pconns; p; p = p->next) {
            if (p->ready) {
                active++;
                if (p->session) {
                    used++;
                }
            }
            count++;
        }
        printf("[%d] pconn: count=%zu, active=%zu, used=%zu\n", t->id, count, active, used);
    }
}

int
main (int argc, char *argv[]) {
    struct sigaction sig; 
    struct ev_loop *loop;
    struct ev_timer timer_w;
    struct config_tunnel *c;
    struct tunnel *t;
    struct ssock *s;
    struct pconn *p;

    sig.sa_handler = SIG_IGN;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags= 0;
    sigaction(SIGPIPE, &sig, NULL);
    if (option_parse(argc, argv, &config) == -1) {
        usage();
        return -1;
    }
    if (config.debug) {
        config_debug(&config);
    }
    loop = ev_loop_new(0);
    if (!loop) {
        return -1;
    }
    ev_timer_init(&timer_w, timeout_cb, 0.0, 1.0);
    ev_timer_start(loop, &timer_w);
    SSL_load_error_strings();
    SSL_library_init();
    RAND_poll();
    if (!RAND_status()) {
        srand(time(NULL));
        do {
            unsigned short r = (u_short)rand();
            RAND_seed(&r, sizeof(r));
        } while (!RAND_status());
    }
    for (c = config.tunnels; c; c = c->next) {
        t = tunnel_setup(loop, c);
        if (!t) {
            return -1;
        }
        t->next = tunnels;
        tunnels = t;
    }
    for (t = tunnels; t; t = t->next) {
        for (s = t->ssocks; s; s = s->next) {
            if (listen(s->sock.fd, BACKLOG) == -1) {
                perror("listen");
                return -1;
            }
            ev_io_start(s->sock.loop, &s->sock.w);
        }
        for (p = t->pconns; p; p = p->next) {
            if (connect(p->sock.fd, (struct sockaddr *)&p->sock.peer, p->sock.peerlen) == -1) {
                if (errno != EINPROGRESS) {
                    perror("connect");
                    return -1;
                }
            }
            ev_io_start(p->sock.loop, &p->sock.w);
        }
    }
    ev_loop(loop, 0);
    ev_loop_destroy(loop);
    return 0;
}
