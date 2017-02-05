#!/usr/bin/env python3

import itertools as it, operator as op, functools as ft
import os, sys, stat, tempfile, pathlib, contextlib, logging, re
import time, math, base64, hashlib, json, email.utils, textwrap

from urllib.request import urlopen, Request, URLError, HTTPError

import cryptography # cryptography.io
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.backends import default_backend
crypto_backend = default_backend()


acme_ca_shortcuts = dict(
	le='https://acme-v01.api.letsencrypt.org/directory',
	le_staging='https://acme-staging.api.letsencrypt.org/directory' )


class LogMessage:
	def __init__(self, fmt, a, k): self.fmt, self.a, self.k = fmt, a, k
	def __str__(self): return self.fmt.format(*self.a, **self.k) if self.a or self.k else self.fmt

class LogStyleAdapter(logging.LoggerAdapter):
	def __init__(self, logger, extra=None):
		super(LogStyleAdapter, self).__init__(logger, extra or {})
	def log(self, level, msg, *args, **kws):
		if not self.isEnabledFor(level): return
		log_kws = {} if 'exc_info' not in kws else dict(exc_info=kws.pop('exc_info'))
		msg, kws = self.process(msg, kws)
		self.logger._log(level, LogMessage(msg, args, kws), (), log_kws)

get_logger = lambda name: LogStyleAdapter(logging.getLogger(name))

@contextlib.contextmanager
def safe_replacement(path, *open_args, mode=None, **open_kws):
	path = str(path)
	if mode is None:
		try: mode = stat.S_IMODE(os.lstat(path).st_mode)
		except OSError: pass
	open_kws.update( delete=False,
		dir=os.path.dirname(path), prefix=os.path.basename(path)+'.' )
	if not open_args: open_kws['mode'] = 'w'
	with tempfile.NamedTemporaryFile(*open_args, **open_kws) as tmp:
		try:
			if mode is not None: os.fchmod(tmp.fileno(), mode)
			yield tmp
			if not tmp.closed: tmp.flush()
			os.rename(tmp.name, path)
		finally:
			try: os.unlink(tmp.name)
			except OSError: pass


def p(*a, file=None, end='\n', flush=False, **k):
	if len(a) > 0:
		fmt, a = a[0], a[1:]
		a, k = ( ([fmt.format(*a,**k)], dict())
			if isinstance(fmt, str) and (a or k)
			else ([fmt] + list(a), k) )
	print(*a, file=file, end=end, flush=flush, **k)

indent_lines = lambda text,indent='  ',prefix='\n': ( (prefix if text else '') +
	''.join('{}{}'.format(indent, line) for line in text.splitlines(keepends=True)) )

p_err = lambda *a,**k: p(*a, file=sys.stderr, **k) or 1
p_err_for_req = lambda res: p_err(
	'Server response: {} {}\nHeaders: {}Body: {}',
	res.code or '-', res.reason or '-',
	indent_lines(''.join( '{}: {}\n'.format(k, v)
		for k, v in (res.headers.items() if res.headers else list()) )),
	indent_lines(res.body.decode()) )



def b64_b2a_jose(data, uint_len=None):
	# https://jose.readthedocs.io/en/latest/
	if uint_len in [True, 'auto']:
		uint_len = divmod(math.log(data, 2), 8)
		uint_len = int(uint_len[0]) + 1 * (uint_len[1] != 0)
	if uint_len is not None:
		data = data.to_bytes(uint_len, 'big', signed=False)
		# print(':'.join('{:02x}'.format(b) for b in data))
	if isinstance(data, str): data = data.encode()
	return base64.urlsafe_b64encode(data).replace(b'=', b'').decode()

def generate_crypto_key(key_type):
	if key_type.startswith('rsa-'):
		key_bits = int(key_type[4:])
		if key_bits not in [2048, 4096]: return
		return rsa.generate_private_key(65537, key_bits, crypto_backend)
	elif key_type.startswith('ec-'):
		if key_type != 'ec-384': return
		return ec.generate_private_key(ec.SECP384R1(), crypto_backend)


class AccKey:
	_slots = 't sk pk_hash jwk jwk_thumbprint jws_alg sign_func'.split()
	def __init__(self, *args, **kws):
		for k,v in it.chain(zip(self._slots, args), kws.items()): setattr(self, k, v)
		self.jwk, self.jwk_thumbprint = self._jwk()
		self.jws_alg, self.sign_func = self._sign_func()
		self.pk_hash = self._pk_hash() # only used to id keys in this script

	def _jwk(self):
		# https://tools.ietf.org/html/rfc7517 + rfc7518
		pk_nums = self.sk.public_key().public_numbers()
		if self.t.startswith('rsa-'):
			jwk = dict( kty='RSA',
				n=b64_b2a_jose(pk_nums.n, True),
				e=b64_b2a_jose(pk_nums.e, True) )
		elif self.t == 'ec-384':
			jwk = dict( kty='EC', crv='P-384',
				x=b64_b2a_jose(pk_nums.x, 48),
				y=b64_b2a_jose(pk_nums.y, 48) )
		else: raise ValueError(self.t)
		digest = hashes.Hash(hashes.SHA256(), crypto_backend)
		digest.update(json.dumps(jwk, sort_keys=True, separators=(',', ':')).encode())
		return jwk, b64_b2a_jose(digest.finalize())

	def _pk_hash(self, trunc_len=8):
		digest = hashes.Hash(hashes.SHA256(), crypto_backend)
		digest.update('\0'.join([self.t, self.jwk_thumbprint]).encode())
		return b64_b2a_jose(digest.finalize())[:trunc_len]

	def _sign_func(self):
		# https://tools.ietf.org/html/rfc7518#section-3.1
		if self.t.startswith('rsa-'):
			# https://tools.ietf.org/html/rfc7518#section-3.1 mandates pkcs1.5
			alg, sign_func = 'RS256', ft.partial( self.sk.sign,
				padding=padding.PKCS1v15(), algorithm=hashes.SHA256() )
		elif self.t == 'ec-384':
			alg, sign_func = 'ES384', ft.partial(self._sign_func_es384, self.sk)
		else: raise ValueError(self.t)
		return alg, sign_func

	@staticmethod
	def _sign_func_es384(sk, data):
		# cryptography produces ASN.1 DER signature only,
		#  while ACME expects "r || s" values from there, so it have to be decoded.
		# Resulting DER struct: 0x30 b1 ( 0x02 b2 (vr) 0x02 b3 (vs) )
		#  where: b1 = length of stuff after it, b2 = len(vr), b3 = len(vs)
		#  vr and vs are encoded as signed ints, so can have extra leading 0x00
		sig_der = sk.sign(data, signature_algorithm=ec.ECDSA(hashes.SHA384()))
		rs_len, rn, r_len = sig_der[1], 4, sig_der[3]
		sn, s_len = rn + r_len + 2, sig_der[rn + r_len + 1]
		assert sig_der[0] == 0x30 and sig_der[rn-2] == sig_der[sn-2] == 0x02
		assert rs_len + 2 == len(sig_der) == r_len + s_len + 6
		r, s = sig_der[rn:rn+r_len].lstrip(b'\0'), sig_der[sn:sn+s_len].lstrip(b'\0')
		return r + s

	@classmethod
	def generate_to_file(cls, p_acc_key, key_type, file_mode=None):
		acc_key = generate_crypto_key(key_type)
		if acc_key:
			acc_key_pem = acc_key.private_bytes(
				serialization.Encoding.PEM,
				serialization.PrivateFormat.PKCS8, serialization.NoEncryption() )
			p_acc_key.parent.mkdir(parents=True, exist_ok=True)
			with safe_replacement( p_acc_key,
				'wb', mode=file_mode ) as dst: dst.write(acc_key_pem)
			acc_key = cls(key_type, acc_key)
		return acc_key

	@classmethod
	def load_from_file(cls, p_acc_key):
		acc_key = serialization.load_pem_private_key(
			p_acc_key.read_bytes(), None, crypto_backend )
		if isinstance(acc_key, rsa.RSAPrivateKey):
			assert acc_key.key_size in [2048, 4096]
			acc_key_t = 'rsa-{}'.format(acc_key.key_size)
		elif isinstance(acc_key, ec.EllipticCurvePrivateKey)\
			and acc_key.curve.name == 'secp384r1': acc_key_t = 'ec-384'
		else: return None
		return cls(acc_key_t, acc_key)


class AccMeta(dict):

	re_meta = re.compile(r'^\s*## acme\.(\S+?): (.*)?\s*$')

	__slots__ = 'p mode'.split()
	def __init__(self, *args, **kws):
		for k,v in it.chain(zip(self.__slots__, args), kws.items()): setattr(self, k, v)

	@classmethod
	def load_from_key_file(cls, p_acc_key, file_mode=None):
		self = cls(p_acc_key, file_mode)
		with p_acc_key.open() as src:
			for line in src:
				m = self.re_meta.search(line)
				if not m: continue
				k, v = m.groups()
				self[k] = json.loads(v)
		return self

	def save(self):
		with safe_replacement(self.p, mode=self.mode) as dst:
			with self.p.open() as src:
				final_newline = True
				for line in src:
					m = self.re_meta.search(line)
					if m: continue
					dst.write(line)
					final_newline = line.endswith('\n')
			if not final_newline: dst.write('\n')
			for k, v in self.items():
				if v is None: continue
				dst.write('## acme.{}: {}\n'.format(k, json.dumps(v)))


class HTTPResponse:
	__slots__ = 'code reason headers body'.split()
	def __init__(self, *args, **kws):
		for k,v in it.chain( zip(self.__slots__, it.repeat(None)),
			zip(self.__slots__, args), kws.items() ): setattr(self, k, v)

http_req_headers = { 'Content-Type': 'application/jose+json',
		'User-Agent': 'acme-cert-tool/1.0 (+https://github.com/mk-fg/acme-cert-tool)' }

def http_req(url, data=None, headers=None, **req_kws):
	req_headers = http_req_headers.copy()
	if headers: req_headers.update(headers)
	req = Request(url, data, req_headers, **req_kws)
	try:
		try: r = urlopen(req)
		except HTTPError as err: r = err
		res = HTTPResponse(r.getcode(), r.reason, r.headers, r.read())
		r.close()
	except URLError as r: res = HTTPResponse(reason=r.reason)
	return res

def signed_req_body( acc_key, payload, kid=None,
		nonce=None, url=None, resource=None, encode=True ):
	# For all of the boulder-specific quirks implemented here, see:
	#  letsencrypt/boulder/blob/d26a54b/docs/acme-divergences.md
	kid = None # 2017-02-03: for letsencrypt/boulder, always requires jwk
	protected = dict(alg=acc_key.jws_alg, url=url)
	if not kid: protected['jwk'] = acc_key.jwk
	else: protected['kid'] = kid
	if nonce: protected['nonce'] = nonce
	if url: protected['url'] = url
	protected = b64_b2a_jose(json.dumps(protected))
	# 2017-02-03: "resource" is for letsencrypt/boulder
	if ( resource and isinstance(payload, dict)
		and 'resource' not in payload ): payload['resource'] = resource
	if not isinstance(payload, str):
		if not isinstance(payload, bytes): payload = json.dumps(payload)
		payload = b64_b2a_jose(payload)
	signature = b64_b2a_jose(
		acc_key.sign_func('{}.{}'.format(protected, payload).encode()) )
	body = dict(protected=protected, payload=payload, signature=signature)
	if encode: body = json.dumps(body).encode()
	return body

def signed_req( acc_key, url, payload, kid=None,
		nonce=None, resource=None, acme_url=None ):
	url_full = url if ':' in url else None
	if not url_full or not nonce:
		# 2017-02-03: letsencrypt/boulder does not implement
		#  new-nonce, so query directory instead, when it is needed.
		assert acme_url, [url, acme_url] # need to query directory
		log.debug('Sending acme-directory http request to: {!r}', acme_url)
		with urlopen(acme_url) as r:
			assert r.getcode() == 200
			acme_dir = json.load(r)
			nonce = r.headers['Replay-Nonce']
		if not url_full: url_full = acme_dir[url]
		if not resource: resource = url
	body = signed_req_body( acc_key, payload,
		kid=kid, nonce=nonce, url=url_full, resource=resource )
	log.debug('Sending signed http request to URL: {!r} ...', url_full)
	res = http_req(url_full, body)
	log.debug('... http reponse: {} {}', res.code or '-', res.reason or '?')
	return res


class AccHooks(dict):
	points = {
		'domain-auth.start-all':
			'Before starting authorization process for domain(s), once per script run.\n'
			'args: all domains to be authorized, in the same order.',
		'domain-auth.start':
			'Before authorization of each individual domain.'
			'args: domain to be authorized.',
		'domain-auth.publish-challenge':
			'After http-01 challenge-file has been stored in acme-dir and before\n'
				' checking local httpd for it (if not disabled) or notifying CA about it.\n'
			'args: domain to be authorized, challenge-file path.',
		'domain-auth.poll-attempt':
			'After notifying ACME CA about http-01 challenge completion\n'
				' and before each attempt to check domain authorization results.\n'
			'args: authorized domain, challenge-file path, number of poll-attempt (1, 2, 3, ...).',
		'domain-auth.poll-delay':
			'After each check for domain authorization result, if it is not available yet.\n'
			'args: authorized domain, challenge-file path, number of poll-attempt (1, 2, 3, ...),\n'
				'      delay as specified by ACME server in Retry-After header or "0" if none.',
		'domain-auth.done':
			'After authorization of each individual domain.\n'
			'args: domain that was authorized.',
		'domain-auth.done-all':
			'After authorization process for domain(s), once per script run.\n'
			'args: all domains that were authorized, in the same order.',
		'cert.csr-check':
			'Before submitting any of Cert Signing Requests (CSR) to ACME CA for signing.\n'
			'args: key type (e.g. ec-384, rsa-2048, etc), cert domain(s).\n'
			'stdin: DER-encoded CSR, exactly same as will be submitted to CA.',
		'cert.issued':
			'After signing (all) CSR(s) (one per key type, if >1)\n'
				' with the server, but before storing any of certs/keys on fs.\n'
			'args: cert domain(s).',
		'cert.stored':
			'After storing all cert/key files on filesystem, but before any cleanup (if enabled).\n'
			'args: paths of all cert/key files.',
	}
	__slots__ = 'timeout'.split()
	def __init__(self, *args, **kws):
		for k,v in it.chain(zip(self.__slots__, args), kws.items()): setattr(self, k, v)
		if self.timeout <= 0: self.timeout = None

	def run(self, hook, *hook_args, **run_kws):
		import subprocess
		hook_script = self.get(hook)
		if not hook_script: return
		kws = dict(check=True, timeout=self.timeout)
		kws.update(run_kws)
		hook_args = list(map(str, hook_args))
		log.debug('Running {} hook: {} (args: {})', hook, hook_script, hook_args)
		return subprocess.run([hook_script] + hook_args, **kws)

class AccSetup:
	__slots__ = 'key meta hooks req'.split()
	def __init__(self, *args, **kws):
		for k,v in it.chain(zip(self.__slots__, args), kws.items()): setattr(self, k, v)

class X509CertInfo:
	__slots__ = 'key csr cert_str'.split()
	def __init__(self, *args, **kws):
		for k,v in it.chain(zip(self.__slots__, args), kws.items()): setattr(self, k, v)


def domain_auth_parse_tos_url(res):
	for header in res.headers.get_all('Link'):
		for v in re.split(', *<', header):
			try: url, params = v.split(';', 1)
			except ValueError: url, params = v, ''
			for param in params.split(';'):
				try: k, v = param.split('=')
				except ValueError: break
				if k.strip(' \'"') == 'rel' and v.strip(' \'"') == 'terms-of-service':
					return url.strip('<> \'"')

def domain_auth_filter(acc, domains):
	for domain in domains:
		if 'auth.domain:{}'.format(domain) in acc.meta:
			log.debug('Skipping pre-authorized domain: {!r}', domain)
			continue
		yield domain

def cmd_domain_auth_batch( acc, domains,
		opt_acme_dir, opt_challenge_file_mode, opt_poll_params,
		auth_log=None, force=False, query_httpd=True ):
	p_acme_dir = pathlib.Path(opt_acme_dir)
	p_acme_dir.mkdir(parents=True, exist_ok=True)
	token_mode = int(opt_challenge_file_mode, 8) & 0o777
	if not force: domains = list(domain_auth_filter(acc, domains))
	if opt_poll_params:
		delay, attempts = opt_poll_params.split(':', 1)
		poll_opts = dict(poll_interval=float(delay), poll_attempts=int(attempts))
	else: poll_opts = dict()
	acc.hooks.run('domain-auth.start-all', *domains)
	for domain in domains:
		log.debug('Authorizing access to domain: {!r}', domain)
		acc.hooks.run('domain-auth.start', domain)
		err = cmd_domain_auth( acc, p_acme_dir, domain,
			token_mode=token_mode, query_httpd=query_httpd, **poll_opts )
		if err: return err
		acc.hooks.run('domain-auth.done', domain)
		(auth_log or log.debug)('Authorized access to domain: {!r}', domain)
	acc.hooks.run('domain-auth.done-all', domains)

def cmd_domain_auth( acc, p_acme_dir, domain,
		token_mode=0o600, query_httpd=True,
		poll_interval=lambda n: min(60, (2**n - 1) / 5), poll_attempts=15 ):
	payload_domain = dict(identifier=dict(type='dns', value=domain))
	res = acc.req('new-authz', payload_domain)
	if res.code == 403:
		try: tos_error = json.loads(res.body)['type'] == 'urn:acme:error:unauthorized'
		except: tos_error = False
		if tos_error:
			log.debug(
				'Got http-403 (error:unauthorized),'
				' trying to update account ToS agreement' )
			# 2017-02-03: letsencrypt/boulder uses "agreement" in payload, not "terms-of-service-agreed"
			# 2017-02-03: Trying to send "agreement" with wrong (e.g. old) URL
			#  causes generic http-400 "malformed" error in letsencrypt/boulder,
			#  so always trying to fetch fresh URL here before sending "agreement" payload.
			payload, acc_tos = dict(resource='reg'), None
			res = acc.req(acc.meta['acc.url'], payload)
			if res.code in [200, 201, 202]: acc_tos = domain_auth_parse_tos_url(res)
			if not acc_tos:
				p_err('ERROR: ACME account ToS probe failed')
				return p_err_for_req(res)
			payload.update({'terms-of-service-agreed': True, 'agreement': acc_tos})
			res = acc.req(acc.meta['acc.url'], payload)
			if res.code not in [200, 201, 202]:
				p_err('ERROR: ACME account tos agreement update failed')
				return p_err_for_req(res)
			log.debug('Account ToS agreement updated, retrying new-authz')
			res = acc.req('new-authz', payload_domain)
	if res.code != 201:
		p_err('ERROR: ACME new-authz request failed for domain: {!r}', domain)
		return p_err_for_req(res)

	for ch in json.loads(res.body.decode())['challenges']:
		if ch['type'] == 'http-01': break
	else:
		p_err('ERROR: No supported challenge types offered for domain: {!r}', domain)
		return p_err('Challenge-offer JSON:{}', indent_lines(res.body.decode()))
	token, token_url, auth_url = ch['token'], ch['uri'], res.headers['Location']
	if re.search(r'[^\w\d_\-]', token):
		return p_err( 'ERROR: Refusing to create path for'
			' non-alphanum/b64 token value (security issue): {!r}', token )
	key_authz = '{}.{}'.format(token, acc.key.jwk_thumbprint)
	p_token = p_acme_dir / token
	with safe_replacement(p_token, mode=token_mode) as dst: dst.write(key_authz)

	acc.hooks.run('domain-auth.publish-challenge', domain, p_token)
	if query_httpd:
		url = 'http://{}/.well-known/acme-challenge/{}'.format(domain, token)
		res = http_req(url)
		if not (res.code == 200 and res.body.decode() == key_authz):
			return p_err( 'ERROR: Token-file created in'
				' -d/--acme-dir is not available at domain URL: {}', url )

	res = acc.req( token_url,
		dict(resource='challenge', type='http-01', keyAuthorization=key_authz) )
	if res.code not in [200, 202]:
		p_err('ERROR: http-01 challenge response was not accepted')
		return p_err_for_req(res)

	for n in range(1, poll_attempts+1):
		acc.hooks.run('domain-auth.poll-attempt', domain, p_token, n)
		log.debug('Polling domain-auth [{:02d}]: {!r}', n, domain)
		res = http_req(token_url)
		if res.code in [200, 202]:
			status = json.loads(res.body.decode())['status']
			if status == 'invalid':
				p_err('ERROR: http-01 challenge response was rejected by ACME CA')
				return p_err_for_req(res)
			if status == 'valid': break
		elif res.code != 503:
			p_err('ERROR: http-01 challenge-status-poll request failed')
			return p_err_for_req(res)

		retry_delay = res.headers.get('Retry-After')
		if retry_delay:
			if re.search(r'^[-+\d.]+$', retry_delay): retry_delay = float(retry_delay)
			else:
				retry_delay = email.utils.parsedate_to_datetime(retry_delay)
				if retry_delay: retry_delay = retry_delay.timestamp() - time.time()
			retry_delay = max(0, retry_delay)
		retry_delay_acme = retry_delay or '0'
		if not retry_delay:
			retry_delay = poll_interval(n) if callable(poll_interval) else poll_interval
		delay_until = time.monotonic() + max(0, retry_delay)
		acc.hooks.run('domain-auth.poll-delay', domain, p_token, n, retry_delay_acme)
		retry_delay = max(0, delay_until - time.monotonic())
		if retry_delay > 0:
			log.debug('Polling domain-auth delay [{:02d}]: {:.2f}', n, retry_delay)
			time.sleep(retry_delay)
	p_token.unlink()

	acc.meta['auth.domain:{}'.format(domain)] = auth_url
	acc.meta.save()


def cmd_cert_issue( acc, p_cert_dir, p_cert_base,
		key_type_list, cert_domain_list, cert_name_attrs,
		file_mode=0o600, split_key_file=False, remove_files_for_prefix=False ):
	from cryptography import x509
	from cryptography.x509.oid import NameOID

	csr = x509.CertificateSigningRequestBuilder()
	csr_name = list()
	for k, v in cert_name_attrs:
		csr_name.append(x509.NameAttribute(getattr(NameOID, k.upper()), v))
	csr_name.append(x509.NameAttribute(
		NameOID.COMMON_NAME, cert_domain_list[0] ))
	csr = csr.subject_name(x509.Name(csr_name))
	csr = csr.add_extension(x509.SubjectAlternativeName(
		list(map(x509.DNSName, cert_domain_list)) ), critical=False)

	certs = dict((k, X509CertInfo()) for k in key_type_list)
	for key_type, ci in certs.items():
		log.debug('Generating {} key for certificate...', key_type)
		ci.key = generate_crypto_key(key_type)
		if not ci.key:
			parser.error('Unknown/unsupported --cert-key-type value: {!r}'.format(key_type))
		ci.csr = csr.sign(ci.key, hashes.SHA256(), crypto_backend)

	csr_ders = dict()
	for key_type, ci in certs.items():
		csr_der = ci.csr.public_bytes(serialization.Encoding.DER)
		acc.hooks.run('cert.csr-check', key_type, *cert_domain_list, stdin=csr_der)
		csr_ders[key_type] = csr_der

	for key_type, ci in certs.items():
		res = acc.req('new-cert', dict(csr=b64_b2a_jose(csr_ders[key_type])))
		if res.code != 201:
			p_err('ERROR: Failed to get signed cert from ACME CA', domain)
			return p_err_for_req(res)
		ci.cert_str = '-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n'\
			.format('\n'.join(textwrap.wrap(base64.b64encode(res.body).decode(), 64)))
		log.debug('Signed {} certificate', key_type)
	acc.hooks.run('cert.issued', *cert_domain_list)

	files_used, key_type_suffix = set(), len(certs) > 1
	for key_type, ci in certs.items():
		key_str = ci.key.private_bytes( serialization.Encoding.PEM,
			serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption() ).decode()
		p = p_cert_base
		if key_type_suffix:
			p = '{}.{}'.format(p.rstrip('.'), key_type)
			if not split_key_file: p += '.pem'
		p_cert, p_key = (p, None) if not split_key_file else\
			('{}.{}'.format(p.rstrip('.'), ext) for ext in ['crt', 'key'])
		with safe_replacement(p_cert_dir / p_cert, mode=file_mode) as dst:
			dst.write(ci.cert_str)
			if not p_key: dst.write(key_str)
		if p_key:
			with safe_replacement(p_cert_dir / p_key, mode=file_mode) as dst: dst.write(key_str)
		files_used.update((p_cert, p_key))
		log.info( 'Stored {} certificate/key: {}{}',
			key_type, p_cert, ' / {}'.format(p_key) if p_key else '' )
	acc.hooks.run('cert.stored', *filter(None, files_used))

	if remove_files_for_prefix:
		for p in p_cert_dir.iterdir():
			if p.is_dir() or p.name in files_used: continue
			log.debug('Removing unused matching-prefix file: {}', p.name)
			p.unlink()


def main(args=None):
	import argparse

	class SmartHelpFormatter(argparse.HelpFormatter):
		def _fill_text(self, text, width, indent):
			return super(SmartHelpFormatter, self)._fill_text(text, width, indent)\
				if '\n' not in text else ''.join(indent + line for line in text.splitlines(keepends=True))
		def _split_lines(self, text, width):
			return super(SmartHelpFormatter, self)._split_lines(text, width)\
				if '\n' not in text else text.splitlines()

	parser = argparse.ArgumentParser(
		formatter_class=SmartHelpFormatter,
		description='Lets Encrypt CA interaction tool to make'
			' it authorize domain (via http-01 challenge) and sign/renew/revoke TLS certs.',
		epilog=textwrap.dedent('''
			Usage examples:

			  - Generate/register new account key, generate certificate for "mydomain.com"
			    and authorize/sign it with Let's Encrypt "Fake LE Intermediate X1" staging CA:

			      % ./acme-cert-tool.py --debug -gk le-staging.acc.key cert-issue \\
			          -d /srv/www/.well-known/acme-challenge le-staging.cert.pem mydomain.com

			    EC P-384 (default) account key (along with some metadata, as comments) will be
			    stored in "le-staging.acc.key" file, certificate and its key (also P-384 by default)
			    in "le-staging.cert.pem".

			    Can be run again to generate new certificate with the same account key and
			    domain authorization (-g/--gen-key-if-missing does not regen key files).

			    To use non-staging server with "legit" intermediate (be sure to check ToS
			    and limits first!), simply add "-s le" there.

			  - Update account contact email and print some account info:
			      % ./acme-cert-tool.py -k le-staging.acc.key -e me@mydomain.com account-info

			  - Deactivate (remove) account:
			      % ./acme-cert-tool.py -k le-staging.acc.key account-deactivate

			See more info at: https://github.com/mk-fg/acme-cert-tool
		'''))

	group = parser.add_argument_group('ACME authentication')
	group.add_argument('-k', '--account-key-file', metavar='path', help=textwrap.dedent('''\
			Path to ACME domain-specific private key to use (pem with pkcs8/openssl/pkcs1).
			All operations wrt current domain will be authenticated using this key.
			It has nothing to do with actual issued TLS certs and cannot be reused in them.
			Has no default value on purpose, must be explicitly specified.
			If registered with ACME server, account URL will also be stored in the file alongside key.
			If --gen-key (or -g/--gen-key-if-missing) is also specified,
			 will be generated and path (incl. directories) will be created.'''))
	group.add_argument('-s', '--acme-service',
		metavar='url-or-name', default='le-staging', help=textwrap.dedent('''\
			ACME directory URL (or shortcut) of Cert Authority (CA) service to interact with.
			Available shortcuts: le - Let\'s Encrypt, le-staging - Let\'s Encrypt staging server.
			Default: %(default)s'''))

	group = parser.add_argument_group('Domain-specific key (-k/--account-key-file) generation',
		description='Generated keys are always stored in pem/pkcs8 format with no encryption.')
	group.add_argument('-g', '--gen-key-if-missing', action='store_true',
		help='Generate ACME authentication key before operation, if it does not exist already.')
	group.add_argument('--gen-key', action='store_true',
		help='Generate new ACME authentication'
			' key regardless of whether -k/--account-key-file path exists.')
	group.add_argument('-t', '--key-type',
		metavar='type', choices=['rsa-2048', 'rsa-4096', 'ec-384'], default='ec-384',
		help='ACME authentication key type to generate.'
			' Possible values: rsa-2048, rsa-4096, ec-384 (secp384r1). Default: %(default)s')

	group = parser.add_argument_group('Account/key registration and update options')
	group.add_argument('-r', '--register', action='store_true',
		help='Register key with CA before verifying domains. Must be done at least once for key.'
			' Should be safe to try doing that more than once,'
				' CA will just return "409 Conflict" error (ignored by this script).'
			' Performed automatically if -k/--account-key-file does not have account URL stored there.')
	group.add_argument('-e', '--contact-email', metavar='email',
		help='Email address for any account-specific issues,'
				' warnings and notifications to register along with the key.'
			' If was not specified previously or differs from that, will be automatically updated.')
	group.add_argument('-o', '--account-key-file-old', metavar='path',
		help='Issue a key-change command from an old key specified with this option.'
			' Overrides -r/--register option - if old key is specified, new one'
				' (specified as -k/--account-key-file) will attached to same account as the old one.')

	group = parser.add_argument_group('Hook options')
	group.add_argument('-x', '--hook', action='append', metavar='hook:path',
		help='Hook-script to run at the specified point.'
			' Specified path must be executable (chmod +x ...), will be run synchronously,'
				' and must exit with 0 for tool to continue operation, and non-zero to abort immediately.'
			' Hooks are run with same uid/gid and env as the main script, can use PATH-lookup.'
			' See --hook-list output to get full list of'
				' all supported hook-points and arguments passed to them.'
			' Example spec: -x domain-auth.publish-challenge:/etc/nginx/sync-frontends.sh')
	group.add_argument('--hook-timeout', metavar='seconds', type=float, default=120,
		help='Timeout for waiting for hook-script to finish running,'
				' before aborting the operation (treated as hook error).'
			' Zero or negative value will disable timeout. Default: %(default)s')
	group.add_argument('--hook-list', action='store_true',
		help='Print the list of all supported hooks with descriptions/parameters and exit.')

	group = parser.add_argument_group('Misc other options')
	group.add_argument('-u', '--umask', metavar='octal', default='0077',
		help='Umask to set for creating any directories, if missing/necessary.'
			' Default is 0077 to create 0700 (user-only access) dirs.'
			' Special value "-" (dash) will make script leave umask unchanged.')
	group.add_argument('-m', '--mode', metavar='octal', default='0600',
		help='Mode (octal) to use for storing cert and key files.'
			' Default is 0600 to have user-only access to these files.')
	group.add_argument('--debug', action='store_true', help='Verbose operation mode.')


	cmds = parser.add_subparsers(title='Commands', dest='call')


	cmd = cmds.add_parser('account-info',
		help='Request and print info for ACME account associated with the specified key.')

	cmd = cmds.add_parser('account-deactivate',
		help='Deactivate (block/remove) ACME account'
			' associated with the key. It cannot be reactivated again.')


	cmd = cmds.add_parser('domain-list',
		help='List domains that key is authorized to manage certs for.',
		description='One per line to stdout, from local metadata only.')

	cmd = cmds.add_parser('domain-auth',
		formatter_class=SmartHelpFormatter,
		help='Authorize use of key (-k/--account-key-file) to manage certs for specified domain(s).')
	cmd.add_argument('acme_dir', help=textwrap.dedent('''\
		Directory that is served by domain\'s httpd at "/.well-known/acme-challenge/".
		Will be created, if does not exist already.'''))
	cmd.add_argument('domain', nargs='+',
		help='Domain(s) to authorize for use with specified key (-k/--account-key-file).')
	group.add_argument('-f', '--auth-force', action='store_true',
		help='Dont skip domains which are already recorded as authorized in local acc metadata.')
	group.add_argument('--auth-poll-params', metavar='delay:attempts',
		help='Specific auth-result polling interval value (if ACME server'
				' does not provide one, in seconds) and number of attempts to use.'
			' Default is to use exponential backoff, with 60s limit and 15 attempts max over ~10min.')
	cmd.add_argument('--dont-query-local-httpd', action='store_true',
		help='Skip querying challege response at a local'
				' "well-known" URLs created by this script before submitting them to ACME CA.'
			' Default is to query e.g. "example.com/.well-known/acme-challenge/some-token" URL'
				' immediately after script creates "some-token" file in acme_dir directory,'
				' to make sure it would be accessible to ACME CA servers as well.'
			' Can be skipped in configurations where local host should not be able to query that URL.')
	cmd.add_argument('-m', '--challenge-file-mode', metavar='octal', default='0644',
		help='Separate access mode (octal) value to use for ACME challenge file in acme_dir directory.'
			' Default is 0644 to allow read access for any uid (e.g. httpd) to these files.')

	cmd = cmds.add_parser('domain-deauth', help='Remove authorization for specified domain(s).')
	cmd.add_argument('domain', nargs='+', help='Domain(s) to deauthenticate.')


	cmd = cmds.add_parser('cert-issue',
		formatter_class=SmartHelpFormatter,
		help='Generate new X.509 v3 (TLS) certificate/key pair'
			' for specified domain(s), with cert signed by ACME CA.')

	group = cmd.add_argument_group('Certificate key and files')
	group.add_argument('file_prefix',
		help='Resulting PEM filename or filename prefix'
			' (if >1 files/certs are requested, see options below).')
	group.add_argument('-c', '--cert-key-type',
		metavar='type', choices=['rsa-2048', 'rsa-4096', 'ec-384'], default='ec-384',
		help=textwrap.dedent('''\
			Certificate key type(s) to generate.
			Can be used multiple times to issue same certificate for
			 multiple different keys, e.g. ec-384 cert and a fallback
			 rsa-2048 one for (rare) clients that do not support ecc.
			If more than one key type is specified, each cert/key
			 pair will be stored to different .pem file(s), with corresponding filename
			 suffixes and an extra dot separator (if prefix does not end with one),
			 e.g. "mycert.ec-384.pem" and "mycert.rsa-2048.pem".
			Possible values: rsa-2048, rsa-4096, ec-384 (secp384r1). Default: %(default)s'''))
	group.add_argument('-s', '--split-key-file', action='store_true',
		help='Store private key in a separate .key file, while certificate to a .crt file, both'
				' with specified filename prefix plus a dot separator, e.g. "mycert.crt" + "mycert.key".'
			' Default is to store both cert and key in the same (specified) file.')
	group.add_argument('-r', '--remove-files-for-prefix', action='store_true',
		help='After storing new cert/key files, remove all files with specified prefix'
			' that were there previously. Only done after successful operation,'
			' idea is to cleanup any old files to avoid confusion.')

	group = cmd.add_argument_group('Certificate info')
	group.add_argument('domain',
		help='Main domain to issue certificate for.'
			' Will be used in a certificate Common Name field (CN) and SubjectAltName.')
	group.add_argument('altname', nargs='*',
		help='Extra domain(s) that certificate should be valid for.'
			' Will be used in a certificate SubjectAltName extension field.')
	group.add_argument('-i', '--cert-name-attrs',
		action='append', metavar='attr:value', help=textwrap.dedent('''\
			Additional attributes to include in the X.509 Name, in attr=value format.
			This option can be used multiple times, attributes
			 will be added in the same order with CN from "domain" arg at the end.
			See list of recognized "attr" names (case-insensitive) in cryptography.io docs:
			 https://cryptography.io/en/latest/x509/reference/#object-identifiers
			For example, to have country and email attrs in the cert, use:
			 -i country_name:US -i  email_address:user@myhost.com'''))

	group = cmd.add_argument_group('Certificate domain authorization options',
		description='Options for automatic authorization of'
			' domain(s) used in a certificate, same as in "domain-auth" command.')
	group.add_argument('-d', '--acme-dir', help=textwrap.dedent('''\
		Directory that is served by domain\'s httpd at "/.well-known/acme-challenge/".
		Must be specified in order for authomatic
		 authorization for cert domain(s) to be performed.
		If not specified, domains are assumed to be pre-authorized.
		Will be created, if does not exist already.'''))
	group.add_argument('-f', '--auth-force', action='store_true',
		help='Dont skip domains which are already recorded as authorized in local acc metadata.')
	group.add_argument('--auth-poll-params', metavar='delay:attempts',
		help='Specific auth-result polling interval value (if ACME server'
				' does not provide one, in seconds) and number of attempts to use.'
			' Default is to use exponential backoff, with 60s limit and 15 attempts max over ~10min.')
	group.add_argument('--dont-query-local-httpd', action='store_true',
		help='Skip querying challege response at a local'
				' "well-known" URLs created by this script before submitting them to ACME CA.'
			' See more info in the description of this option for "domain-auth" command.')
	group.add_argument('-m', '--challenge-file-mode', metavar='octal', default='0644',
		help='Separate access mode (octal) value to use for ACME challenge file in acme_dir directory.'
			' Default is 0644 to allow read access for any uid (e.g. httpd) to these files.')

	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	logging.basicConfig( datefmt='%Y-%m-%d %H:%M:%S',
		format='%(asctime)s :: %(name)s %(levelname)s :: %(message)s',
		level=logging.DEBUG if opts.debug else logging.WARNING )
	log = get_logger('main')

	acc_hooks = AccHooks(opts.hook_timeout)
	if opts.hook_list:
		p('Available hook points:\n')
		for hp, desc in acc_hooks.points.items():
			p('  {}:', hp)
			indent = ' '*4
			desc = textwrap.fill(desc, width=100, initial_indent=indent, subsequent_indent=indent)\
				if '\n' not in desc else ''.join(indent + line for line in desc.splitlines(keepends=True))
			p(desc + '\n')
		p('Hooks are run synchronously, waiting for subprocess to exit before continuing.')
		p('All hooks must exit with status 0 to continue operation.')
		p('Some hooks get passed arguments, as mentioned in hook descriptions.')
		p('Setting --hook-timeout (defaults to 120s) can be used to abort when hook-scripts hang.')
		return
	for v in opts.hook or list():
		if ':' not in v: parser.error('Invalid --hook spec (must be hook:path): {!r}'.format(v))
		hp, path = v.split(':', 1)
		if hp not in acc_hooks.points:
			parser.error('Invaluid hook name: {!r} (see --hook-list)'.format(hp))
		acc_hooks[hp] = path

	if opts.umask != '-': os.umask(int(opts.umask, 8) & 0o777)
	file_mode = int(opts.mode, 8) & 0o777

	acme_url = opts.acme_service
	if ':' not in acme_url:
		try: acme_url = acme_ca_shortcuts[acme_url.replace('-', '_')]
		except KeyError: parser.error('Unkown --acme-service shortcut: {!r}'.format(acme_url))

	if not opts.account_key_file:
		parser.error('Path for -k/--account-key-file must be specified.')
	p_acc_key = pathlib.Path(opts.account_key_file)
	if opts.gen_key or (opts.gen_key_if_missing and not p_acc_key.exists()):
		acc_key = AccKey.generate_to_file(p_acc_key, opts.key_type, file_mode=file_mode)
		if not acc_key:
			parser.error('Unknown/unsupported --key-type value: {!r}'.format(opts.key_type))
	elif p_acc_key.exists():
		acc_key = AccKey.load_from_file(p_acc_key)
		if not acc_key: parser.error('Unknown/unsupported key type: {}'.format(p_acc_key))
	else: parser.error('Specified --account-key-file path does not exists: {!r}'.format(p_acc_key))
	acc_meta = AccMeta.load_from_key_file(p_acc_key, file_mode=file_mode)
	log.debug( 'Using {} domain key: {} (acme acc url: {})',
		acc_key.t, acc_key.pk_hash, acc_meta.get('acc.url') )


	### Handle account status

	acc_key_old = opts.account_key_file_old
	acc_register = opts.register or acc_key_old or not acc_meta.get('acc.url')
	acc_contact = opts.contact_email and 'mailto:{}'.format(opts.contact_email)

	# 2017-02-03: letsencrypt/boulder uses "agreement", "terms-of-service-agreed" is ignored
	payload_reg = {'terms-of-service-agreed': True}
	if acc_register:
		if not os.access(p_acc_key, os.W_OK):
			return p_err( 'ERROR: Account registration required,'
				' but key file is not writable (to store new-reg url there): {}', p_acc_key )
		if acc_meta.get('acc.url'):
			log.warning( 'Specified --account-key-file already marked as'
				' registered (url: {}), proceeding regardless.', acc_meta['acc.url'] )
		if acc_key_old:
			if opts.register:
				log.debug( 'Both -r/--register and'
					' -o/--account-key-file-old are specified, acting according to latter option.' )
			p_acc_key_old = pathlib.Path(acc_key_old)
			acc_key_old = AccKey.load_from_file(p_acc_key_old)
			if not acc_key_old:
				parser.error('Unknown/unsupported key type'
					' specified with -o/--account-key-file-old: {}'.format(p_acc_key))
			acc_meta_old = AccMeta.load_from_key_file(p_acc_key_old)
			acc_url_old = acc_meta_old.get('acc.url')
			if not acc_url_old:
				log.debug( 'Old key file (-o/--account-key-file-old) does'
					' not have registration URL, will be fetched via new-reg request' )
				res = signed_req(acc_key_old, 'new-reg', payload_reg, acme_url=acme_url)
				if res.code not in [201, 409]:
					p_err('ERROR: ACME new-reg'
						' request for old key (-o/--account-key-file-old) failed')
					return p_err_for_req(res)
				acc_url_old = res.headers['Location']

		if not acc_key_old: # new-reg
			if acc_contact: payload_reg['contact'] = [acc_contact]
			res = signed_req(acc_key, 'new-reg', payload_reg, acme_url=acme_url)
			if res.code not in [201, 409]:
				p_err('ERROR: ACME new-reg (key registration) request failed')
				return p_err_for_req(res)
			log.debug('Account registration status: {} {}', res.code, res.reason)
			acc_meta['acc.url'] = res.headers['Location']
			if res.code == 201: acc_meta['acc.contact'] = acc_contact
		else: # key-change
			with urlopen(acme_url) as r: # need same URL for both inner and outer payloads
				assert r.getcode() == 200
				resource, acme_dir = 'key-change', json.load(r)
				url, nonce = acme_dir[resource], r.headers['Replay-Nonce']
			payload = dict(account=acc_url_old, newKey=acc_key.jwk)
			payload = signed_req_body(acc_key, payload, url=url, encode=False)
			# According to https://tools.ietf.org/html/draft-ietf-acme-acme-04#section-5.2 ,
			#  only new-reg and revoke-cert should have jwk instead of kid,
			#  but 6.3.2 explicitly mentions jwks, so guess it should also be exception here.
			res = signed_req(acc_key_old, url, payload, nonce=nonce, resource=resource)
			if res.code not in [200, 201, 202]:
				p_err('ERROR: ACME account key-change request failed')
				return p_err_for_req(res)
			log.debug('Account key-change success: {} -> {}', acc_key_old.pk_hash, acc_key.pk_hash)
			acc_meta['acc.url'] = acc_url_old
			acc_meta['acc.contact'] = acc_meta_old.get('acc.contact')
		acc_meta.save()

	if acc_contact and acc_contact != acc_meta.get('acc.contact'):
		log.debug('Updating account contact information')
		res = signed_req( acc_key, acc_meta['acc.url'],
			dict(resource='reg', contact=[acc_contact]),
			kid=acc_meta['acc.url'], acme_url=acme_url )
		if res.code not in [200, 201, 202]:
			p_err('ERROR: ACME account contact info update request failed')
			return p_err_for_req(res)
		log.debug('Account contact info updated: {!r} -> {!r}', acc_meta['acc.contact'], acc_contact)
		acc_meta['acc.contact'] = acc_contact
		acc_meta.save()

	acc = AccSetup( acc_key, acc_meta, acc_hooks,
		ft.partial(signed_req, acc_key, acme_url=acme_url, kid=acc_meta['acc.url']) )


	### Handle commands

	if opts.call == 'account-info':
		res = acc.req(acc.meta['acc.url'], dict(resource='reg'))
		if res.code not in [200, 201, 202]:
			p_err('ERROR: ACME account info request failed')
			return p_err_for_req(res)
		p(res.body.decode())

	elif opts.call == 'account-deactivate':
		res = acc.req(acc.meta['acc.url'], dict(resource='reg', status='deactivated'))
		if res.code != 200:
			p_err('ERROR: ACME account deactivation request failed')
			return p_err_for_req(res)
		p(res.body.decode())


	elif opts.call == 'domain-list':
		for k in acc.meta.keys():
			if k.startswith('auth.domain:'): p(k[12:])

	elif opts.call == 'domain-auth':
		return cmd_domain_auth_batch(
			acc, opts.domain, opts.acme_dir, opts.challenge_file_mode, opts.auth_poll_params,
			auth_log=log.info, force=opts.auth_force, query_httpd=not opts.dont_query_local_httpd )

	elif opts.call == 'domain-deauth':
		for domain in opts.domain:
			log.debug('Deauthorizing access to domain: {!r}', domain)
			res = acc.req(
				acc.meta['auth.domain:{}'.format(domain)],
				dict(resource='authz', status='deactivated') )
			if res.code != 200:
				p_err('ERROR: deauth request failed for domain: {}', domain)
				return p_err_for_req(res)
			log.info('Deauthorized access to domain: {!r}', domain)
			try: acc.meta.pop('auth.domain:{}'.format(domain))
			except KeyError: pass
			else: acc.meta.save()


	elif opts.call == 'cert-issue':
		key_type_list = ( [opts.cert_key_type]
			if isinstance(opts.cert_key_type, str) else opts.cert_key_type )
		p_cert_base = pathlib.Path(opts.file_prefix)
		p_cert_dir, p_cert_base = p_cert_base.parent, p_cert_base.name
		cert_domain_list = [opts.domain] + (opts.altname or list())
		cert_name_attrs = list()
		for v in opts.cert_name_attrs or list():
			if ':' not in v:
				parser.error( 'Invalid --cert-subject-info'
					' spec (must be attr:value): {!r}'.format(v) )
			cert_name_attrs.append(map(str.strip, v.split(':', 1)))

		if opts.acme_dir:
			log.debug('Checking authorization for {} cert-domain(s)...', len(cert_domain_list))
			err = cmd_domain_auth_batch( acc, cert_domain_list, opts.acme_dir, opts.challenge_file_mode,
				opts.auth_poll_params, force=opts.auth_force, query_httpd=not opts.dont_query_local_httpd )
			if err: return err

		return cmd_cert_issue( acc, p_cert_dir, p_cert_base,
			key_type_list, cert_domain_list, cert_name_attrs,
			file_mode=file_mode, split_key_file=opts.split_key_file,
			remove_files_for_prefix=opts.remove_files_for_prefix )


	elif not opts.call: parser.error('No command specified')
	else: parser.error('Unrecognized command: {!r}'.format(opts.call))


if __name__ == '__main__': sys.exit(main())
