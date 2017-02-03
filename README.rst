================
 acme-cert-tool
================

Simple one-stop tool to manage X.509/TLS certs and all the ACME CA
authorization stuff.

- P-384 (secp384r1) ECC keys and certs are supported and the default,
  with RSA only being supported as a fallback option where still necessary
  (e.g. certs for old clients that can't do ECC).

- Single python3 script implementation,
  only dependent on `cryptography.io <https://cryptography.io/>`_ module.

- Does not use openssl cli tools nor ever needs user to call them.

- Designed with automated "setup and forget" operation in mind,
  all with a single command if possible.

- Does not do anything with httpd or any other daemons and their configuration.

Under heavy development, not really usable yet.
