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
#include "http_handler.h"

#define HTTP_HEADER_NONE   0
#define HTTP_HEADER_URL    1
#define HTTP_HEADER_STATUS 2
#define HTTP_HEADER_FIELD  3
#define HTTP_HEADER_VALUE  4
#define HTTP_EOL "\r\n"
#define HTTP_EOL_LEN 2
 
static int
http_cb_message_begin (http_parser *parser) {
    struct http_handler_env *e;

    e = (struct http_handler_env *)parser->data;
    e->field.name.n = 0;
    e->field.skip = 0;
    e->xff = 0;
    e->stat = 0;
    e->last_element = HTTP_HEADER_NONE;
    return 0;
}

static int
http_cb_request_url (http_parser *parser, const char *p, size_t len) {
    struct http_handler_env *e;
    size_t capacity, n;

    e = (struct http_handler_env *)parser->data;
    if (e->last_element != HTTP_HEADER_URL) {
        capacity = sizeof(e->buf->data) - e->buf->n;
        n = snprintf(e->buf->data + e->buf->n, capacity, "%s ", http_method_str(parser->method));
        if (n > capacity) {
            return -1;
        }
        e->buf->n += n;
    }
    capacity = sizeof(e->buf->data) - e->buf->n;
    if (len > capacity) {
        return -1;
    }
    memcpy(e->buf->data + e->buf->n, p, len);
    e->buf->n += len;
    e->last_element = HTTP_HEADER_URL;
    return 0;
}

static int
http_cb_response_status (http_parser *parser, const char *p, size_t len) {
    struct http_handler_env *e;
    size_t capacity, n;

    e = (struct http_handler_env *)parser->data;
    if (e->last_element != HTTP_HEADER_STATUS) {
        capacity = sizeof(e->buf->data) - e->buf->n;
        n = snprintf(e->buf->data + e->buf->n, capacity, "HTTP/%u.%u %03u ", parser->http_major, parser->http_minor, parser->status_code);
        if (n > capacity) {
            return -1;
        }
        e->buf->n += n;
    }
    capacity = sizeof(e->buf->data) - e->buf->n;
    if (len > capacity) {
        return -1;
    }
    memcpy(e->buf->data + e->buf->n, p, len);
    e->buf->n += len;
    e->last_element = HTTP_HEADER_STATUS;
    return 0;
}

static int
http_cb_header_field (http_parser *parser, const char *p, size_t len) {
    struct http_handler_env *e;
    size_t capacity, n;

    e = (struct http_handler_env *)parser->data;
    switch (e->last_element) {
    case HTTP_HEADER_URL:
        capacity = sizeof(e->buf->data) - e->buf->n;
        n = snprintf(e->buf->data + e->buf->n, capacity, " HTTP/%u.%u%s", parser->http_major, parser->http_minor, HTTP_EOL);
        if (n > capacity) {
            return -1;
        }
        e->buf->n += n;
        break;
    case HTTP_HEADER_STATUS:
        capacity = sizeof(e->buf->data) - e->buf->n;
        if (HTTP_EOL_LEN > capacity) {
            return -1;
        }
        memcpy(e->buf->data + e->buf->n, HTTP_EOL, HTTP_EOL_LEN);
        e->buf->n += HTTP_EOL_LEN;
        break;
    case HTTP_HEADER_VALUE:
        if (!e->field.skip) {
            if (e->field.name.n == 15 && strncasecmp(e->field.name.data, "X-Forwarded-For", 15) == 0) {
                capacity = sizeof(e->buf->data) - e->buf->n;
                n = snprintf(e->buf->data + e->buf->n, capacity, ", %s", e->client);
                if (n > capacity) {
                    return -1;
                }
                e->buf->n += n;
                e->xff = 1;
            }
            capacity = sizeof(e->buf->data) - e->buf->n;
            if (HTTP_EOL_LEN > capacity) {
                return -1;
            }
            memcpy(e->buf->data + e->buf->n, HTTP_EOL, HTTP_EOL_LEN);
            e->buf->n += HTTP_EOL_LEN;
        }
        e->field.name.n = 0;
        e->field.skip = 0;
        break;
    }
    capacity = sizeof(e->field.name.data) - e->field.name.n;
    if (len > capacity) {
        return -1;
    }
    memcpy(e->field.name.data + e->field.name.n, p, len);
    e->field.name.n += len;
    e->last_element = HTTP_HEADER_FIELD;
    return 0;
}

static int
http_cb_header_value (http_parser *parser, const char *p, size_t len) {
    struct http_handler_env *e;
    size_t capacity;

    e = (struct http_handler_env *)parser->data;
    if (e->last_element != HTTP_HEADER_VALUE) {
        if (e->field.name.n == 4 && strncasecmp(e->field.name.data, "Host", 4) == 0) {
            e->field.skip = 1;
        } else {
            capacity = sizeof(e->buf->data) - e->buf->n;
            if ((e->field.name.n + 2) > capacity) {
                return -1;
            }
            memcpy(e->buf->data + e->buf->n, e->field.name.data, e->field.name.n);
            e->buf->n += e->field.name.n;
            memcpy(e->buf->data + e->buf->n, ": ", 2);
            e->buf->n += 2;
        }
    }
    if (!e->field.skip) {
        capacity = sizeof(e->buf->data) - e->buf->n;
        if (len > capacity) {
            return -1;
        }
        memcpy(e->buf->data + e->buf->n, p, len);
        e->buf->n += len;
    }
    e->last_element = HTTP_HEADER_VALUE;
    return 0;
}

static int
http_cb_headers_complete (http_parser *parser) {
    struct http_handler_env *e;
    size_t capacity, n;

    e = (struct http_handler_env *)parser->data;
    switch (e->last_element) {
    case HTTP_HEADER_URL:
        capacity = sizeof(e->buf->data) - e->buf->n;
        n = snprintf(e->buf->data + e->buf->n, capacity, " HTTP/%u.%u%s", parser->http_major, parser->http_minor, HTTP_EOL);
        if (n > capacity) {
            return -1;
        }
        e->buf->n += n;
        break;
    case HTTP_HEADER_STATUS:
        capacity = sizeof(e->buf->data) - e->buf->n;
        if (HTTP_EOL_LEN > capacity) {
            return -1;
        }
        memcpy(e->buf->data + e->buf->n, HTTP_EOL, HTTP_EOL_LEN);
        e->buf->n += HTTP_EOL_LEN;
        break;
    default:
        if (!e->field.skip) {
            capacity = sizeof(e->buf->data) - e->buf->n;
            if (HTTP_EOL_LEN > capacity) {
                return -1;
            }
            memcpy(e->buf->data + e->buf->n, HTTP_EOL, HTTP_EOL_LEN);
            e->buf->n += HTTP_EOL_LEN;
        }
        break;
    }
    if (e->host) {
        capacity = sizeof(e->buf->data) - e->buf->n;
        n = snprintf(e->buf->data + e->buf->n, capacity, "Host: %s%s", e->host, HTTP_EOL);
        if (n > capacity) {
            return -1;
        }
        e->buf->n += n;
    }
    if (!e->xff) {
        capacity = sizeof(e->buf->data) - e->buf->n;
        n = snprintf(e->buf->data + e->buf->n, capacity, "X-Forwarded-For: %s%s", e->client, HTTP_EOL);
        if (n > capacity) {
            return -1;
        }
        e->buf->n += n;
    }
    capacity = sizeof(e->buf->data) - e->buf->n;
    if (HTTP_EOL_LEN > capacity) {
        return -1;
    }
    memcpy(e->buf->data + e->buf->n, HTTP_EOL, HTTP_EOL_LEN);
    e->buf->n += HTTP_EOL_LEN;
    return 0;
}

static int
http_cb_body (http_parser *parser, const char *p, size_t len) {
    struct http_handler_env *e;
    size_t capacity;

    e = (struct http_handler_env *)parser->data;
    capacity = sizeof(e->buf->data) - e->buf->n;
    if (len > capacity) {
        return -1;
    }
    memcpy(e->buf->data + e->buf->n, p, len);
    e->buf->n += len;
    return 0;
}

static int
http_cb_message_complete (http_parser *parser) {
    struct http_handler_env *e;

    e = (struct http_handler_env *)parser->data;
    e->stat = HTTP_STATUS_MESSAGE_COMPLETE;
    return 0;
}

struct http_parser_settings http_request_settings = {
    .on_message_begin = http_cb_message_begin,
    .on_url = http_cb_request_url,
    .on_status = http_cb_response_status,
    .on_header_field = http_cb_header_field,
    .on_header_value = http_cb_header_value,
    .on_headers_complete = http_cb_headers_complete,
    .on_body = http_cb_body,
    .on_message_complete = http_cb_message_complete
};
