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
#include <errno.h>
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

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#define EVSOCK_NEED_EVENTS(x) \
    ((!(x)->rx.suspend && !(x)->rx.closed ? (x)->rx.events : 0) | \
     (!(x)->tx.suspend && !(x)->tx.closed ? (x)->tx.events : 0))

#define EV_IO_RESET(x, y, z) \
    do { \
        ev_io_stop((x), (y)); \
        ev_io_set((y), (y)->fd, (z)); \
        ev_io_start((x), (y)); \
    } while (0);

void
evsock_suspend (struct evsock *sock, int how) {
    if (how & EVSOCK_HOW_RX) {
        sock->rx.suspend = 1;
    }
    if (how & EVSOCK_HOW_TX) {
        sock->tx.suspend = 1;
    }
    EV_IO_RESET(sock->loop, &sock->w, EVSOCK_NEED_EVENTS(sock));
}

void
evsock_wakeup (struct evsock *sock, int how) {
    if (how & EVSOCK_HOW_RX) {
        sock->rx.suspend = 0;
    }
    if (how & EVSOCK_HOW_TX) {
        sock->tx.suspend = 0;
    }
    EV_IO_RESET(sock->loop, &sock->w, EVSOCK_NEED_EVENTS(sock));
    if (how & EVSOCK_HOW_RX) {
        if (sock->rx.eof || sock->rx.buf.n || (sock->ssl && SSL_pending(sock->ssl))) {
            ev_feed_event(sock->loop, &sock->w, sock->rx.events);
        }
    }
}

static void
evsock_accept_handler (struct evsock *sock) {
    struct evsock *nsock;
    int ret, err, opt;
    unsigned long e;

    if (sock->ssl) {
        ret = SSL_accept(sock->ssl);
        if (ret <= 0) {
            err = SSL_get_error(sock->ssl, ret);
            switch (err) {
            case SSL_ERROR_WANT_READ:
                EV_IO_RESET(sock->loop, &sock->w, EV_READ);
                return;
            case SSL_ERROR_WANT_WRITE:
                EV_IO_RESET(sock->loop, &sock->w, EV_READ);
                return;
            case SSL_ERROR_SYSCALL:
                e = ERR_get_error();
                if (!e) {
                    if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
                        return;
                    }
                }
            default:
                fprintf(stderr, "SSL_accept: error\n");
                SSL_free(sock->ssl);
                close(sock->fd);
                ev_io_stop(sock->loop, &sock->w);
                if (sock->data.destroy) {
                    sock->data.destroy(sock->data.ptr);
                }
                return;
            }
        }
    } else {
        nsock = sock->on_pre_accept(sock);
        if (!nsock) {
            return;
        }
        nsock->fd = accept(sock->fd, (struct sockaddr *)&nsock->peer, &nsock->peerlen);
        if (nsock->fd == -1) {
            perror("accept");
            if (nsock->data.destroy) {
                nsock->data.destroy(nsock->data.ptr);
            }
            return;
        }
        opt = 1;
        if (ioctl(nsock->fd, FIONBIO, &opt) == -1) {
            perror("ioctl");
            close(nsock->fd);
            if (nsock->data.destroy) {
                nsock->data.destroy(nsock->data.ptr);
            }
            return;
        }
        opt = 1;
        if (setsockopt(nsock->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
            perror("setsockopt");
            close(nsock->fd);
            if (nsock->data.destroy) {
                nsock->data.destroy(nsock->data.ptr);
            }
            return;
        }
        nsock->state = EVSOCK_STATE_ACCEPT;
        nsock->ctx = sock->ctx;
        nsock->loop = sock->loop;
        nsock->w.data = nsock;
        ev_io_init(&nsock->w, evsock_handler, nsock->fd, EV_READ | EV_WRITE);
        ev_io_start(nsock->loop, &nsock->w);
        nsock->on_accept = sock->on_accept;
        nsock->on_read = sock->on_read;
        nsock->on_write = sock->on_write;
        if (nsock->ctx) {
            nsock->ssl = SSL_new(nsock->ctx);
            if (!nsock->ssl) {
                ERR_print_errors_fp(stderr);
                close(nsock->fd);
                ev_io_stop(nsock->loop, &nsock->w);
                if (nsock->data.destroy) {
                    nsock->data.destroy(nsock->data.ptr);
                }
                return;
            }
            if (!SSL_set_fd(nsock->ssl, nsock->fd)) {
                ERR_print_errors_fp(stderr);
                SSL_free(nsock->ssl);
                close(nsock->fd);
                ev_io_stop(nsock->loop, &nsock->w);
                if (nsock->data.destroy) {
                    nsock->data.destroy(nsock->data.ptr);
                }
                return;
            }
            return;
        }
        sock = nsock;
    }
    if (sock->on_accept && sock->on_accept(sock) == -1) {
        if (sock->ssl) {
            SSL_shutdown(sock->ssl);
            SSL_free(sock->ssl);
        }
        close(sock->fd);
        ev_io_stop(sock->loop, &sock->w);
        if (sock->data.destroy) {
            sock->data.destroy(sock->data.ptr);
        }
        return;
    }
    sock->state = EVSOCK_STATE_ESTABLISHED;
    sock->rx.events = EV_READ;
    sock->tx.events = EV_WRITE;
    EV_IO_RESET(sock->loop, &sock->w, EVSOCK_NEED_EVENTS(sock));
}

static void
evsock_connect_handler (struct evsock *sock) {
    int ret, err;
    socklen_t errlen;
    unsigned long e;

    if (sock->ssl) {
        ret = SSL_connect(sock->ssl);
        if (ret <= 0) {
            err = SSL_get_error(sock->ssl, ret);
            switch (err) {
            case SSL_ERROR_WANT_READ:
                EV_IO_RESET(sock->loop, &sock->w, EV_READ);
                return;
            case SSL_ERROR_WANT_WRITE:
                EV_IO_RESET(sock->loop, &sock->w, EV_WRITE);
                return;
            case SSL_ERROR_SYSCALL:
                e = ERR_get_error();
                if (!e) {
                    if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
                        return;
                    }
                }
            default:
                fprintf(stderr, "SSL_connect: errro\n");
                SSL_free(sock->ssl);
                close(sock->fd);
                ev_io_stop(sock->loop, &sock->w);
                if (sock->data.destroy) {
                    sock->data.destroy(sock->data.ptr);
                }
                return;
            }
        }
    } else {
        errlen = sizeof(err);
        if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
            perror("getsockpot");
            close(sock->fd);
            ev_io_stop(sock->loop, &sock->w);
            if (sock->data.destroy) {
                sock->data.destroy(sock->data.ptr);
            }
            return;
        }
        if (err) {
            fprintf(stderr, "connect: %s\n", strerror(err));
            close(sock->fd);
            ev_io_stop(sock->loop, &sock->w);
            if (sock->data.destroy) {
                sock->data.destroy(sock->data.ptr);
            }
            return;
        }
        if (sock->ctx) {
            sock->ssl = SSL_new(sock->ctx);
            if (!sock->ssl) {
                ERR_print_errors_fp(stderr);
                close(sock->fd);
                ev_io_stop(sock->loop, &sock->w);
                if (sock->data.destroy) {
                    sock->data.destroy(sock->data.ptr);
                }
                return;
            }
            if (!SSL_set_fd(sock->ssl, sock->fd)) {
                ERR_print_errors_fp(stderr);
                SSL_free(sock->ssl);
                close(sock->fd);
                ev_io_stop(sock->loop, &sock->w);
                if (sock->data.destroy) {
                    sock->data.destroy(sock->data.ptr);
                }
                return;
            }
            EV_IO_RESET(sock->loop, &sock->w, EV_READ | EV_WRITE);
            return;
        }
    }
    if (sock->on_connect && sock->on_connect(sock) == -1) {
        if (sock->ssl) {
            SSL_shutdown(sock->ssl);
            SSL_free(sock->ssl);
        }
        close(sock->fd);
        ev_io_stop(sock->loop, &sock->w);
        if (sock->data.destroy) {
            sock->data.destroy(sock->data.ptr);
        }
        return;
    }
    sock->state = EVSOCK_STATE_ESTABLISHED;
    sock->rx.events = EV_READ;
    sock->tx.events = EV_WRITE;
    EV_IO_RESET(sock->loop, &sock->w, EV_READ | EV_WRITE);
}

static int
evsock_read_handler (struct evsock *sock) {
    ssize_t n;
    int err, stop = 0;
    unsigned long e;

    if (!sock->rx.eof && (!sock->rx.buf.n || sock->rx.more_read)) {
        if (sock->ssl) {
            n = SSL_read(sock->ssl, sock->rx.buf.data + sock->rx.buf.n, sizeof(sock->rx.buf.data) - sock->rx.buf.n);
            if (n <= 0) {
                err = SSL_get_error(sock->ssl, n);
                switch (err) {
                case SSL_ERROR_WANT_READ:
                    sock->rx.events = EV_READ;
                    EV_IO_RESET(sock->loop, &sock->w, EVSOCK_NEED_EVENTS(sock));
                    return 0;
                case SSL_ERROR_WANT_WRITE:
                    sock->rx.events = EV_WRITE;
                    EV_IO_RESET(sock->loop, &sock->w, EVSOCK_NEED_EVENTS(sock));
                    return 0;
                case SSL_ERROR_ZERO_RETURN:
                    //SSL_set_shutdown(sock->ssl, SSL_RECEIVED_SHUTDOWN);
                    sock->rx.eof = 1;
                    break;
                case SSL_ERROR_SYSCALL:
                    e = ERR_get_error();
                    if (!e) {
                        if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
                            return 0;
                        }
                    }
                default:
                    fprintf(stderr, "SSL_read: error\n");
                    SSL_shutdown(sock->ssl);
                    SSL_free(sock->ssl);
                    close(sock->fd);
                    ev_io_stop(sock->loop, &sock->w);
                    if (sock->data.destroy) {
                        sock->data.destroy(sock->data.ptr);
                    }
                    return -1;
                }
            }
        } else {
            n = recv(sock->fd, sock->rx.buf.data + sock->rx.buf.n, sizeof(sock->rx.buf.data) - sock->rx.buf.n, 0);
            switch (n) {
            case -1:
                if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
                    return 0;
                }
                perror("recv");
                close(sock->fd);
                ev_io_stop(sock->loop, &sock->w);
                if (sock->data.destroy) {
                    sock->data.destroy(sock->data.ptr);
                }
                return -1;
            case  0:
                sock->rx.eof = 1;
                shutdown(sock->fd, SHUT_RD);
                break;
            }
        }
        sock->rx.more_read = 0;
        sock->rx.buf.n += n;
    }
    n = sock->on_read(sock, sock->rx.buf.data, sock->rx.buf.n, &stop);
    if (n == -1) {
        if (sock->ssl) {
            SSL_shutdown(sock->ssl);
            SSL_free(sock->ssl);
        }
        close(sock->fd);
        ev_io_stop(sock->loop, &sock->w);
        if (sock->data.destroy) {
            sock->data.destroy(sock->data.ptr);
        }
        return -1;
    }
    if (n) {
        memmove(sock->rx.buf.data, sock->rx.buf.data + n, sock->rx.buf.n - n);
        sock->rx.buf.n -= n;
    }
    if (sock->rx.eof && !sock->rx.buf.n) {
        if (sock->tx.closed) {
            if (sock->ssl) {
                SSL_shutdown(sock->ssl);
                SSL_free(sock->ssl);
            }
            close(sock->fd);
            ev_io_stop(sock->loop, &sock->w);
            if (sock->data.destroy) {
                sock->data.destroy(sock->data.ptr);
            }
            return -1;
        }
        sock->rx.closed = 1;
    } else {
        sock->rx.events = EV_READ;
        if (stop) {
            evsock_suspend(sock, EVSOCK_HOW_RX);
            return 0;
        }
    }
    EV_IO_RESET(sock->loop, &sock->w, EVSOCK_NEED_EVENTS(sock));
    return 0;
}

static int
evsock_write_handler (struct evsock *sock) {
    int closed = 0;
    ssize_t n;
    int err;
    unsigned long e;

    if (!sock->tx.eof && !sock->tx.buf.n) {
        n = sock->on_write(sock, sock->tx.buf.data, sizeof(sock->tx.buf.data), &closed);
        if (n == -1) {
            if (sock->ssl) {
                SSL_shutdown(sock->ssl);
                SSL_free(sock->ssl);
            }
            close(sock->fd);
            ev_io_stop(sock->loop, &sock->w);
            if (sock->data.destroy) {
                sock->data.destroy(sock->data.ptr);
            }
            return -1;
        }
        if (closed) {
            sock->tx.eof = 1;
        }
        if (!n && !sock->tx.eof) {
            sock->tx.suspend = 1;
            EV_IO_RESET(sock->loop, &sock->w, EVSOCK_NEED_EVENTS(sock));
            return 0;
        }
        sock->tx.buf.n += n;
    }
    if (sock->tx.buf.n) {
        if (sock->ssl) {
            n = SSL_write(sock->ssl, sock->tx.buf.data, sock->tx.buf.n);
            if (n <= 0) {
                err = SSL_get_error(sock->ssl, n);
                switch (err) {
                case SSL_ERROR_WANT_READ:
                    sock->tx.events = EV_READ;
                    EV_IO_RESET(sock->loop, &sock->w, EVSOCK_NEED_EVENTS(sock));
                    return 0;
                case SSL_ERROR_WANT_WRITE:
                    sock->tx.events = EV_WRITE;
                    EV_IO_RESET(sock->loop, &sock->w, EVSOCK_NEED_EVENTS(sock));
                    return 0;
                case SSL_ERROR_SYSCALL:
                    e = ERR_get_error();
                    if (!e) {
                        if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
                            return 0;
                        }
                    }
                default:
                    fprintf(stderr, "SSL_write: error\n");
                    SSL_shutdown(sock->ssl);
                    SSL_free(sock->ssl);
                    close(sock->fd);
                    ev_io_stop(sock->loop, &sock->w);
                    if (sock->data.destroy) {
                        sock->data.destroy(sock->data.ptr);
                    }
                    return -1;
                }
            }
            if ((!sock->rx.suspend && !sock->rx.closed) && SSL_pending(sock->ssl)) {
                ev_feed_event(sock->loop, &sock->w, sock->rx.events);
            }
        } else {
            n = send(sock->fd, sock->tx.buf.data, sock->tx.buf.n, 0);
            if (n == -1) {
                if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
                    return 0;
                }
                perror("send");
                close(sock->fd);
                ev_io_stop(sock->loop, &sock->w);
                if (sock->data.destroy) {
                    sock->data.destroy(sock->data.ptr);
                }
                return -1;
            }
        }
        memmove(sock->tx.buf.data, sock->tx.buf.data + n, sock->tx.buf.n - n);
        sock->tx.buf.n -= n;
    }
    if (sock->tx.eof && !sock->tx.buf.n) {
        if (sock->rx.closed) {
            if (sock->ssl) {
                if (!(SSL_get_shutdown(sock->ssl) & SSL_SENT_SHUTDOWN)) {
                    SSL_shutdown(sock->ssl);
                }
                SSL_free(sock->ssl);
            }
            close(sock->fd);
            ev_io_stop(sock->loop, &sock->w);
            if (sock->data.destroy) {
                sock->data.destroy(sock->data.ptr);
            }
            return -1;
        }
        if (sock->ssl) {
            if (!(SSL_get_shutdown(sock->ssl) & SSL_SENT_SHUTDOWN)) {
                SSL_shutdown(sock->ssl);
            }
        } else {
            shutdown(sock->fd, SHUT_WR);
        }
        sock->tx.closed = 1;
    } else {
        sock->tx.events = EV_WRITE;
    }
    EV_IO_RESET(sock->loop, &sock->w, EVSOCK_NEED_EVENTS(sock));
    return 0;
}

void
evsock_handler (struct ev_loop *loop, struct ev_io *w, int revents) {
    struct evsock *sock;

    (void)loop;
    sock = (struct evsock *)w->data;
    if (revents & EV_ERROR) {
        perror("EV_ERROR");
        if (sock->ssl) {
            SSL_shutdown(sock->ssl);
            SSL_free(sock->ssl);
        }
        close(sock->fd);
        ev_io_stop(sock->loop, &sock->w);
        if (sock->data.destroy) {
            sock->data.destroy(sock->data.ptr);
        }
        return;
    }
    switch (sock->state) {
    case EVSOCK_STATE_ACCEPT:
        evsock_accept_handler(sock);
        break;
    case EVSOCK_STATE_CONNECT:
        evsock_connect_handler(sock);
        break;
    case EVSOCK_STATE_ESTABLISHED:
        if (revents & EV_READ) {
            if (sock->tx.events & EV_READ) {
                if (evsock_write_handler(sock) == -1) {
                    return;
                }
            }
            if (sock->rx.events & EV_READ) {
                if (evsock_read_handler(sock) == -1) {
                    return;
                }
            }
        }
        if (revents & EV_WRITE) {
            if (sock->rx.events & EV_WRITE) {
                if (evsock_read_handler(sock) == -1) {
                    return;
                }
            }
            if (sock->tx.events & EV_WRITE) {
                if (evsock_write_handler(sock) == -1) {
                    return;
                }
            }
        }
        break;
    default:
        if (sock->ssl) {
            SSL_shutdown(sock->ssl);
            SSL_free(sock->ssl);
        }
        close(sock->fd);
        ev_io_stop(sock->loop, &sock->w);
        if (sock->data.destroy) {
            sock->data.destroy(sock->data.ptr);
        }
    }
}
