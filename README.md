openssl-privsep
===============

openssl-privsep is an OpenSSL engine that runs RSA private key operations in an isolated process, thereby minimizing the risk of private key leak in case of vulnerability such as Heartbleed.

The engine can be used together with existing versions of OpenSSL or LibreSSL, with minimal changes to the server source code.

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
