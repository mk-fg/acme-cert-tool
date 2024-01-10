================
 acme-cert-tool
================

Simple one-stop tool to manage X.509/TLS certs and all the ACME CA
authorization stuff with minimum dependencies.

Should work in unix-like environments like Linux/\*BSD/OSX and WSL2.

.. contents::
  :backlinks: none

This repository URLs:

- https://github.com/mk-fg/acme-cert-tool
- https://codeberg.org/mk-fg/acme-cert-tool
- https://fraggod.net/code/git/acme-cert-tool


Main features
-------------

- P-384 (secp384r1) ECC keys and certs are supported and the default,
  with RSA also supported as a fallback option where still necessary
  (e.g. certs for old clients that can't do ECC).

- Can issue multiple certificates for diff key types in one command.

- Single python3 script implementation,
  only dependent on `cryptography.io <https://cryptography.io/>`_ module.

- Does not use openssl command-line tools nor ever requires user to run them.

- Designed with automated non-interactive "setup cert, auto-renewal and forget"
  operation in mind, all with a single command, if possible.

- Does not do anything with httpd or any other daemons and their configuration.

- Uses "ACME v2" protocol supported by Let's Encrypt since after April 2018.

Can generate/use/roll-over account keys (ec-384/rsa-2048/rsa-4096,
pem pkcs8 or openssl/pkcs1), register/query/deactivate accounts,
generate configurable X.509 CSRs (ec-384/rsa-2048/rsa-4096 keys, pem
openssl/pkcs1 for certs and keys), sign these through ACME CA.

Hook scripts can be used at multiple points to integrate script into whatever
setup (e.g. sync challenge files, reload httpd, process keys, introduce delays, etc),
see ``./acme-cert-tool.py --hook-list`` for more info on these.


Usage example
-------------

::

  % ./acme-cert-tool.py --debug -gk le-staging.acc cert-issue \
     le-staging.cert.pem /srv/www/.well-known/acme-challenge mydomain.com

EC P-384 (default) account key (along with some metadata, as comments) will be
stored in "le-staging.acc" file (note: account key has nothing to do with
certificate), certificate (chain) and its key (also P-384 by default) in
"le-staging.cert.pem" file.

Can be re-run to generate new certificate there (i.e. renew) with same account key
and domain authorization (``-g/--gen-key-if-missing`` does not regen key files).

To use non-staging server with "legit" intermediate
(be sure to check ToS and limits first!), simply add ``-s le`` there.

When configuring Web Server after that, it should use resulting \*.pem
as both certificate chain and key (see also ``-s/--split-key-file`` option).

Run ``./acme-cert-tool.py -h`` to get more information on all supported commands
and options, and e.g. ``./acme-cert-tool.py cert-issue -h`` to see info and options
for a specific command.


Installation
------------

This is a python (3.8+) script, using `cryptography <https://cryptography.io/>`_ module.
It's not in a PyPI_ registry.

pipx_ can be used to run the tool via "pipx run", auto-installing "cryptography" to an ad-hoc venv::

  % curl -OL https://raw.githubusercontent.com/mk-fg/acme-cert-tool/master/acme-cert-tool.py
  % pipx run acme-cert-tool.py --help

Alternatively, OS/distro package manager can be used to install necessary dependencies::

  archlinux# pacman -S python python-cryptography
  debian/ubuntu# apt-get install --no-install-recommends python3-minimal python3-cryptography

Then just download (or git-clone) and run the script::

  % curl -OL https://raw.githubusercontent.com/mk-fg/acme-cert-tool/master/acme-cert-tool.py
  % chmod +x acme-cert-tool.py
  % ./acme-cert-tool.py --help

Unless any errors pop-up immediately, everything is installed correctly and ready to use.

There is no need to run this script as root, use its ``-m/--mode``, ``--challenge-file-mode``
options and/or ACLs (``setfacl -m d:...``) to share files between different uids/gids easily.

.. _PyPI: https://pypi.org/
.. _pipx: https://pypa.github.io/pipx/


ACME-related bugs and vulnerabilities
-------------------------------------

Ones that I'm aware of wrt either ACME protocol or this specific implementation
are listed here, let me know if there are any other relevant problems.

- `Critical vulnerability in JSON Web Encryption (2017-03-13)
  <http://blog.intothesymmetry.com/2017/03/critical-vulnerability-in-json-web.html>`_

  | An Invalid Curve Attack on JWE ECDH-ES key agreement.
  | Does not affect ACME protocol, as ECDH-ES is not used there at all.

- `Chaining Remote Web Vulnerabilities to Abuse Let's Encrypt (2017-08-29)
  <https://www.mike-gualtieri.com/posts/chaining-remote-web-vulnerabilities-to-abuse-lets-encrypt>`_

  Not strictly a protocol vulnerability, but more of a note on how leaving
  something like poor path permissions or insecure site uploads which can drop
  files to e.g. /var/www/htdocs/.well-known/acme-challenge can lead to someone
  else issuing valid certs for the site for phishing purposes or such - beware.

- `ACME TLS-SNI-01 validation vulnerability (2018-01-12)
  <https://labs.detectify.com/2018/01/12/how-i-exploited-acme-tls-sni-01-issuing-lets-encrypt-ssl-certs-for-any-domain-using-shared-hosting/>`_

  | Does not affect this app, as it only uses http-01 validation.
  | TLS-SNI-01 itself was immediately disabled due to vulnerability to such attacks.

- `CAA Rechecking Incident (2020-02-29) <https://letsencrypt.org/caaproblem/>`_

  Server-side issue with Let's Encrypt. Revocation of ~3mil certs was planned,
  but was cancelled when it became apparent that they won't get updated in time.

  Shows that you probably should use ``-e/--contact-email`` option if possible,
  though then again, they didn't go through with the revocation, so maybe not.


Links
-----

- ACME certificate providers

  - `Let's Encrypt <https://letsencrypt.org/>`_

    Original public Certificate Authority, issuing certificates for websites via
    ACME protocol to anyone at no cost.

    Supports IETF v2 version of ACME protocol, as described in
    `RFC 8555 <https://tools.ietf.org/html/rfc8555>`_.

  - `ZeroSSL <https://zerossl.com/>`_ - another cert provider.

  - `Buypass Go SSL <https://www.buypass.com/ssl/products/acme>`_

  - `SSL.com <https://www.ssl.com/>`_ - seem to provide ACME certs
    `after free registration <https://scotthelme.co.uk/heres-another-free-ca-as-an-alternative-to-lets-encrypt/>`_.

  I've only used LE myself, so no idea if others are any good, though note that
  since all private keys are always client-side only, practical differences between
  them should be cert expiration time (i.e. how often this script needs to run), Terms of Service,
  `Certificate Transparency logs <https://en.wikipedia.org/wiki/Certificate_Transparency>`_
  (see `crt.sh <https://crt.sh>`_ and such), ACME API reliability (uptime, bugs, etc), and how long -
  if any - is their intermediate certificate chain (affecting size of cert bundle served to clients).

- `RFC 8555 describing ACME protocol <https://tools.ietf.org/html/rfc8555>`_

- `Let's Encrypt "Chain of Trust" page <https://letsencrypt.org/certificates/>`_

  Links to LE root and intermediate certificates, which should be supplied in
  resulting PEM files already, and usually shipped in browsers too.

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

- EdDSA (ed25519) support info:

  - `Not supported for ACME account keys yet
    <https://github.com/letsencrypt/boulder/issues/4213>`_

  - Not supported and/or standardized properly in browsers yet

    - `community.letsencrypt.org thread #69868
      <https://community.letsencrypt.org/t/support-ed25519-and-ed448/69868>`_

    - `github letsencrypt/boulder issue #3649
      <https://github.com/letsencrypt/boulder/issues/3649>`_

Last updated on 2021-08-20,
please open an issue if you notice any outdated info/links.
