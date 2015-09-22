openssl-privsep
===============

openssl-privsep is an OpenSSL engine that runs RSA private key operations in an isolated process, thereby minimizing the risk of private key leak in case of vulnerability such as Heartbleed.

The engine can be used together with existing versions of OpenSSL or LibreSSL, with minimal changes to the server source code.

FAQ
---

### Q. How much is the overhead?

Virtually none.

Generally speaking, private key operations are much more heavier than the overhead of inter-process communication.
On my Linux VM running on Core i7 @ 2.4GHz (MacBook Pro 15" Late 2013), OpenSSL 1.0.2 without privilege separation processes 319.56 TLS handshakes per second, whereas OpenSSL with privilege separation processes 316.72 handshakes per second (note: RSA key length: 2,048 bits, selected cipher-suite: ECDHE-RSA-AES128-GCM-SHA256).

### Q. Why does the library only separate private key operations?

Because private keys are the only _long-term_ secret being used.

Depending on how OpenSSL is used it might be benefitial to separate symmetric cipher operations or TLS operations as a whole.  But even in such case it would still be a good idea to isolate private key operations from them considering the impact of private key leaks.

How-to
------

The library exposes two functions: `openssl_privsep_init` and `openssl_privsep_load_private_key_file`.

The first function spawns an external process dedicated to private key operations, and the second function assigns a RSA private key stored in the specified file to an existing SSL context (`SSL_CTX`).

By

1. adding call to `openssl_privsep_init`
2. replacing call to `SSL_CTX_use_PrivateKey_file` with `openssl_privsep_load_private_key_file`

the privilege separation engine will be used for all the incoming TLS connections.

```
  openssl_privsep_t psep;
  char errbuf[OPENSSL_PRIVSEP_ERRBUF_SIZE];

  /* initialize the OpenSSL library and the privilege separation engine */
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  if (openssl_privsep_init(&psep, errbuf) != 0) {
    fprintf(stderr, "openssl_privsep_init failed: %s\n", errbuf);
    ...
  }

  ...

  /* load certificate chain and private key */
  if (SSL_CTX_use_certificate_chain_file(ssl_ctx, certchain_fn) != 1) {
    fprintf(stderr, "failed to load certificate chain file:%s\n", certchain_fn);
    ...
  }
  if (openssl_privsep_load_private_key_file(&psep, ctx, privkey_fn, errbuf) != 1) {
    fprintf(stderr, "failed to load private key from file:%s:%s\n", privkey_fn, errbuf);
    ...
  }
```
