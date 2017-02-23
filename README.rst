================
 acme-cert-tool
================

Simple one-stop tool to manage X.509/TLS certs and all the ACME CA
authorization stuff.

.. contents::
  :backlinks: none


Main features
-------------

- P-384 (secp384r1) ECC keys and certs are supported and the default,
  with RSA only being supported as a fallback option where still necessary
  (e.g. certs for old clients that can't do ECC).

- Single python3 script implementation,
  only dependent on `cryptography.io <https://cryptography.io/>`_ module.

- Does not use openssl command-line tools nor ever requires user to run them.

- Designed with automated non-interactive "setup cert, auto-renewal and forget"
  operation in mind, all with a single command if possible.

- Does not do anything with httpd or any other daemons and their configuration.

Can generate/use/roll-over account keys (ec-384/rsa-2048/rsa-4096,
pem pkcs8 or openssl/pkcs1), register/query/deactivate accounts,
authorize/deauthorize domains (via http-01 challenge), generate configurable
X.509 CSRs (ec-384/rsa-2048/rsa-4096 keys, pem openssl/pkcs1 for certs and keys),
sign these through ACME CA.

Hook scripts can be used at multiple points to integrate script into whatever
setup (e.g. sync challenge files, reload httpd, introduce delays, etc),
see ``./acme-cert-tool.py --hook-list`` for more info on these.


Usage example
-------------

::

  % ./acme-cert-tool.py --debug -gk le-staging.acc.key cert-issue \
      -d /srv/www/.well-known/acme-challenge le-staging.cert.pem mydomain.com

EC P-384 (default) account key (along with some metadata, as comments)
will be stored in "le-staging.acc.key" file, certificate and its key
(also P-384 by default) in "le-staging.cert.pem".

Can be re-run to generate new certificate there (i.e. renew) with the same
account key and domain authorization (-g/--gen-key-if-missing does not regen key files).

To use non-staging server with "legit" intermediate
(be sure to check ToS and limits first!), simply add "-s le" there.

Run ``./acme-cert-tool.py -h`` to get more information on all supported commands
and options, and e.g. ``./acme-cert-tool.py cert-issue -h`` to see info and options
for a specific command.


Installation
------------

Install python3 and `cryptography <https://cryptography.io/>`_ module::

  # pacman -S python python-cryptography

Download and run the script::

  % curl -O https://raw.githubusercontent.com/mk-fg/acme-cert-tool/master/acme-cert-tool.py
  % chmod +x acme-cert-tool.py
  % ./acme-cert-tool.py --help

Unless some errors pop-up immediately, everything is installed correctly and ready to use.

There is no need to run this script as root, use -m/--mode, --challenge-file-mode
options and ACLs (``setfacl -m d:...``) to share files between different uids/gids.


Links
-----

- `Let's Encrypt <https://letsencrypt.org/>`_

  Original public Certificate Authority, issuing certificates for websites via
  ACME protocol to anyone at no cost.

- `ACME client list <https://letsencrypt.org/docs/client-options/>`_

  List of clients compatible with Let's Encrypt and similar ACME CA services.

- `certbot <https://github.com/certbot/certbot/>`_

  Official Let's Encrypt client, has a lot of options and plugins to e.g. mess
  with httpd configuration files, fairly heavyweight.

- `acme-tiny <https://github.com/diafygi/acme-tiny>`_

  200-line Python (2/3) ACME client, main source of inspiration behind this one.

  Fairly bare-bones, have to be supplemented with openssl cli stuff to generate
  CSRs, relies on parsing openssl cli output, lacks (as of 2017-02-05) elliptic
  curve key support, etc.

- `easy-rsa <https://github.com/OpenVPN/easy-rsa/>`_

  Good set of scripts to easily setup and maintain local X.509 PKI (e.g. that
  has nothing to do with global TLS trust roots) - i.e. create CA, intermediates,
  client/server certs - all with one or two trivial commands, very configurable.

- Web TLS setup "Best Practices" checklists (updated every few months):

  - `Qualys SSL Labs <https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices>`_
  - `Mozilla <https://wiki.mozilla.org/Security/Server_Side_TLS>`_
