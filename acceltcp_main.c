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

#include "acceltcp.h"

int
main (int argc, char *argv[]) {
    struct sigaction sig; 
    struct ev_loop *loop;
    struct ev_signal signal_w;
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
    ev_signal_init(&signal_w, signal_cb, SIGUSR1);
    ev_signal_start(loop, &signal_w);
    if (!config.quiet) {
        ev_timer_init(&timer_w, timeout_cb, 0.0, 1.0);
        ev_timer_start(loop, &timer_w);
    }
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
