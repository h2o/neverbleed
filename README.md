openssl-privsep
===============

openssl-privsep is an OpenSSL engine that runs RSA private key operations in an isolated process, thereby minimizing the risk of private key leak in case of an vulnerability such as Heartbleed.

The engine can be used together with existing versions of OpenSSL or LibreSSL, with minimal changes to the server source code.
