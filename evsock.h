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

#ifndef _EVSOCK_H_
#define _EVSOCK_H_

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <ev.h>
#include "buffer.h"

#define EVSOCK_HOW_RX 1
#define EVSOCK_HOW_TX 2

#define EVSOCK_STATE_LISTEN      1
#define EVSOCK_STATE_ACCEPT      2
#define EVSOCK_STATE_CONNECT     3
#define EVSOCK_STATE_ESTABLISHED 4

struct evsock_data {
    void *ptr;
    void (*destroy)(void *);
};

struct evsock {
    int fd;
    int state;
    SSL_CTX *ctx;
    SSL *ssl;
    struct sockaddr_storage peer;
    socklen_t peerlen;
    struct ev_loop *loop;
    struct ev_io w;
    struct evsock *(*on_pre_accept)(struct evsock *);
    int (*on_accept)(struct evsock *);
    int (*on_connect)(struct evsock *);
    ssize_t (*on_read)(struct evsock *, const char *, size_t, int *);
    ssize_t (*on_write)(struct evsock *, char *, size_t, int *);
    struct {
        int events;
        int suspend;
        int closed;
        int eof;
        int more_read;
        struct buffer buf;
    } rx;
    struct {
        int events;
        int suspend;
        int closed;
        int eof;
        struct buffer buf;
    } tx;
    struct evsock_data data;
};

extern void
evsock_handler (struct ev_loop *loop, struct ev_io *w, int revents);
extern void
evsock_suspend (struct evsock *sock, int how);
extern void
evsock_wakeup (struct evsock *sock, int how);

#endif
