/*
 * Copyright (c) 2015 Kazuho Oku, DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include "neverbleed.h"

static neverbleed_t nb;
static char errbuf[NEVERBLEED_ERRBUF_SIZE];
static const char *certfn, *keyfn;
static int use_privsep, reload = 1;

static void setup_ecc_key(SSL_CTX *ssl_ctx)
{
    int nid = NID_X9_62_prime256v1;
    EC_KEY *key = EC_KEY_new_by_curve_name(nid);
    if (key == NULL) {
        fprintf(stderr, "Failed to create curve \"%s\"\n", OBJ_nid2sn(nid));
        return;
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, key);
    EC_KEY_free(key);
}

int dumb_https_server(unsigned short port)
{
    int listen_fd, conn_fd, reuse_flag;
    struct sockaddr_in sin = {};
    SSL_CTX *ctx = NULL;

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "failed to create socket:%s\n", strerror(errno));
        return 111;
    }
    reuse_flag = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_flag, sizeof(reuse_flag));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0x7f000001);
    sin.sin_port = htons(port);
    if (bind(listen_fd, (void *)&sin, sizeof(sin)) != 0) {
        fprintf(stderr, "bind failed:%s\n", strerror(errno));
        return 111;
    }
    if (listen(listen_fd, SOMAXCONN) != 0) {
        fprintf(stderr, "listen failed:%s\n", strerror(errno));
        return 111;
    }

    while (1) {
        /* (re)load SSL context */
        if (reload) {
            reload = 0;
            if (ctx != NULL)
                SSL_CTX_free(ctx);
            fprintf(stderr, "loading certificate and private key\n");
            ctx = SSL_CTX_new(SSLv23_server_method());
            SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
            setup_ecc_key(ctx);
            if (SSL_CTX_use_certificate_chain_file(ctx, certfn) != 1) {
                fprintf(stderr, "failed to load certificate chain file:%s\n", certfn);
                return 111;
            }
            if (use_privsep) {
                if (neverbleed_load_private_key_file(&nb, ctx, keyfn, errbuf) != 1) {
                    fprintf(stderr, "failed to load private key from file:%s:%s\n", keyfn, errbuf);
                    exit(111);
                }
            } else {
                if (SSL_CTX_use_PrivateKey_file(ctx, keyfn, SSL_FILETYPE_PEM) != 1) {
                    fprintf(stderr, "failed to load private key from file:%s\n", keyfn);
                    exit(111);
                }
            }
        }
        /* accept connection */
        if ((conn_fd = accept(listen_fd, NULL, NULL)) != -1) {
            char buf[4096];
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, conn_fd);
            if (SSL_accept(ssl) == 1) {
                SSL_read(ssl, buf, sizeof(buf));
                const char *resp =
                    "HTTP/1.0 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nhello\n";
                SSL_write(ssl, resp, strlen(resp));
                SSL_shutdown(ssl);
            } else {
                fprintf(stderr, "SSL_accept failed\n");
            }
            SSL_free(ssl);
            close(conn_fd);
        }
    }
}

static void on_sighup(int signo)
{
    write(2, "sighup!\n", 8);
    reload = 1;
}

int main(int argc, char **argv)
{
    unsigned short port;

    /* initialization */
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    if (neverbleed_init(&nb, errbuf) != 0) {
        fprintf(stderr, "openssl_privsep_init: %s\n", errbuf);
        return 111;
    }
    /* parse args */
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <internal|privsep> <port> <certificate-chain-file> <private-key-file>\n", argv[0]);
        return 111;
    }
    if (strcmp(argv[1], "internal") == 0) {
        use_privsep = 0;
    } else if (strcmp(argv[1], "privsep") == 0) {
        use_privsep = 1;
    } else {
        fprintf(stderr, "unknown mode:%s\n", argv[1]);
        return 111;
    }
    if (sscanf(argv[2], "%hu", &port) != 1) {
        fprintf(stderr, "failed to parse port:%s\n", argv[2]);
        return 111;
    }
    certfn = argv[3];
    keyfn = argv[4];

    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = on_sighup;
        sigaction(SIGHUP, &sa, NULL);
    }

    /* start the httpd */
    return dumb_https_server(port);
}
