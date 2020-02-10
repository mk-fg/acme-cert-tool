#!/usr/bin/env python3

import itertools as it, operator as op, functools as ft
import os, sys, stat, tempfile, contextlib, logging, re, pathlib as pl
import time, math, base64, hashlib, json, email.utils, textwrap

from urllib.request import urlopen, Request, URLError, HTTPError

import cryptography # cryptography.io
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.backends import default_backend
crypto_backend = default_backend()


acme_ca_shortcuts = dict(
	le='https://acme-v02.api.letsencrypt.org/directory',
	le_staging='https://acme-staging-v02.api.letsencrypt.org/directory' )


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
		try: mode = stat.S_IMODE(os.stat(path).st_mode)
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


class adict(dict):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.__dict__ = self

def p(*a, file=None, end='\n', flush=False, **k):
	if len(a) > 0:
		fmt, a = a[0], a[1:]
		a, k = ( ([fmt.format(*a,**k)], dict())
			if isinstance(fmt, str) and (a or k)
			else ([fmt] + list(a), k) )
	print(*a, file=file, end=end, flush=flush, **k)

indent_lines = lambda text,indent='  ',prefix='\n': (
	(prefix if text else '') +
		''.join(f'{indent}{line}' for line in text.splitlines(keepends=True)) )

p_err = lambda *a,**k: p(*a, file=sys.stderr, **k) or 1

def retries_within_timeout( tries, timeout,
		backoff_func=lambda e,n: ((e**n-1)/e), slack=1e-2 ):
	'Return list of delays to make exactly n tires within timeout, with backoff_func.'
	a, b = 0, timeout
	while True:
		m = (a + b) / 2
		delays = list(backoff_func(m, n) for n in range(tries))
		error = sum(delays) - timeout
		if abs(error) < slack: return delays
		elif error > 0: b = m
		else: a = m

def p_err_for_req(res, final=False):
	if not final: # any known retry-quirks should be identified here
		# Check for Replay Protection issue
		#  https://tools.ietf.org/html/rfc8555#section-6.5
		if res.code == 400:
			try: res_json = json.loads(res.body.decode())
			except ValueError: pass
			else:
				if ( res_json['status'] == 400 and
						res_json['type'] == 'urn:acme:error:badNonce' ):
					raise ACMEAuthRetry('bad_nonce', res)
	return p_err(
		'Server response: {} {}\nHeaders: {}Body: {}',
		res.code or '-', res.reason or '-',
		indent_lines(''.join( f'{k}: {v}\n'
			for k, v in (res.headers.items() if res.headers else list()) )),
		indent_lines((res.body or b'').decode()) )


def zero_pad(data, bs):
	data = data.lstrip(b'\0')
	if len(data) < bs: data = b'\0'*(bs - len(data)) + data
	assert len(data) == bs
	return data

def b64_b2a_jose(data, uint_len=None):
	# https://jose.readthedocs.io/en/latest/
	# https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#appendix-C
	if uint_len is not None:
		data = data.to_bytes(uint_len, 'big', signed=False)
		# print(':'.join(f'{b:02x}' for b in data))
	if isinstance(data, str): data = data.encode()
	return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

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
				n=b64_b2a_jose(pk_nums.n, int(self.t[4:]) // 16),
				e=b64_b2a_jose(pk_nums.e, 3) )
		elif self.t == 'ec-384':
			jwk = dict( kty='EC', crv='P-384',
				x=b64_b2a_jose(pk_nums.x, 48),
				y=b64_b2a_jose(pk_nums.y, 48) )
		else: raise ValueError(self.t)
		digest = hashes.Hash(hashes.SHA256(), crypto_backend)
		digest.update(json.dumps(jwk, sort_keys=True, separators=(',', ':')).encode())
		# log.debug('Key JWK: {}', jwk)
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
		# See JWA - https://tools.ietf.org/html/rfc7518#section-3.4
		sig_der = sk.sign(data, signature_algorithm=ec.ECDSA(hashes.SHA384()))
		rs_len, rn, r_len = sig_der[1], 4, sig_der[3]
		sn, s_len = rn + r_len + 2, sig_der[rn + r_len + 1]
		assert sig_der[0] == 0x30 and sig_der[rn-2] == sig_der[sn-2] == 0x02
		assert rs_len + 2 == len(sig_der) == r_len + s_len + 6
		r, s = zero_pad(sig_der[rn:rn+r_len], 48), zero_pad(sig_der[sn:sn+s_len], 48)
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
			acc_key_t = f'rsa-{acc_key.key_size}'
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
				dst.write(f'## acme.{k}: {json.dumps(v)}\n')


class ACMEServer(str): __slots__ = 'd', # /directory cache

class HTTPResponse:

	# Note: headers are set as-is from urllib response headers,
	#  which are HTTPMessage, based on email.message.Message,
	#  and are matched there in case-insensitive manner.
	__slots__ = 'code reason headers body'.split()

	def __init__(self, *args, **kws):
		for k,v in it.chain( zip(self.__slots__, it.repeat(None)),
			zip(self.__slots__, args), kws.items() ): setattr(self, k, v)

	def json(self): return json.loads(self.body.decode())

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

def signed_req_body(acc_key, payload, nonce=None, kid=None, url=None, encode=True):
	protected = dict(alg=acc_key.jws_alg, url=url)
	if not kid: protected['jwk'] = acc_key.jwk
	else: protected['kid'] = kid
	if nonce: # only keyChange requires no-nonce payload
		if not re.search(r'^[-_a-zA-Z0-9]+$', nonce):
			# rfc8555#section-6.5.1 says that client MUST validate nonce
			raise ACMEError(f'Invalid nonce format: {nonce}')
		protected['nonce'] = nonce
	if url: protected['url'] = url
	protected = b64_b2a_jose(json.dumps(protected))
	if not isinstance(payload, str):
		if not isinstance(payload, bytes): payload = json.dumps(payload)
		payload = b64_b2a_jose(payload)
	signature = b64_b2a_jose(
		acc_key.sign_func(f'{protected}.{payload}'.encode()) )
	body = dict(protected=protected, payload=payload, signature=signature)
	if encode: body = json.dumps(body).encode()
	return body

def signed_req(acc_key, url, payload='', kid=None, nonce=None, acme_url=None):
	url_full = url if ':' in url else None
	if not url_full or not nonce:
		assert acme_url, [url, acme_url] # need to query directory
		if not acme_url.d:
			log.debug('Sending acme-directory http request to: {!r}', acme_url)
			with urlopen(acme_url) as r:
				assert r.getcode() == 200
				acme_url.d = adict(json.load(r))
		if not url_full:
			try: url_full = acme_url.d[url]
			except KeyError:
				log.debug('Missing directory entry {!r}: {}', url, acme_url.d)
				raise
		if not nonce:
			with urlopen(acme_url.d.newNonce) as r:
				nonce = r.headers['Replay-Nonce']
	body = signed_req_body(acc_key, payload, kid=kid, nonce=nonce, url=url_full)
	log.debug('Sending signed http request to URL: {!r} ...', url_full)
	# log.debug('Signed request body: {}', indent_lines(
	# 	json.dumps(json.loads(body), sort_keys=True, indent=2) ))
	res = http_req(url_full, body)
	log.debug('... http response: {} {}', res.code or '-', res.reason or '?')
	return res


class AccHooks(dict):
	points = {
		'auth.start-all':
			'Before starting authorization process for domain(s), once per script run.\n'
			'args: all domains to be checked/authorized, in the same order.',
		'auth.start':
			'Before authorization of each individual domain.\n'
			'args: domain to be authorized.',
		'auth.publish-challenge':
			'After http-01 challenge-file has been stored in acme-dir and before\n'
				' checking local httpd for it (if not disabled) or notifying CA about it.\n'
			'args: domain to be authorized, challenge-file path.',
		'auth.poll-attempt':
			'After notifying ACME CA about http-01 challenge completion\n'
				' and before each attempt to check domain authorization results.\n'
			'args: authorized domain, challenge-file path, number of poll-attempt (1, 2, 3, ...).',
		'auth.poll-delay':
			'After each check for domain authorization status, if it is not available yet.\n'
			'args: authorized domain, challenge-file path, number of poll-attempt (1, 2, 3, ...),\n'
				'      delay as specified by ACME server in Retry-After header or "0" if none.',
		'auth.done':
			'After authorization of each individual domain.\n'
			'args: domain that was authorized.',
		'auth.done-all':
			'After authorization process for domain(s), once per script run.\n'
			'args: all domains that were checked/authorized, in the same order.',
		'cert.csr-check':
			'Before submitting any of Cert Signing Requests (CSR) to ACME CA for signing.\n'
			'args: key type (e.g. ec-384, rsa-2048, etc), cert domain(s).\n'
			'stdin: DER-encoded CSR, exactly same as will be submitted to CA.',
		'cert.poll-delay':
			'After each check for cert signing status, if it is not available yet.\n'
			'args: number of poll-attempt (1, 2, 3, ...), delay from ACME server\n'
				'      (as per Retry-After header) or "0" if none, cert domain(s).',
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
	__slots__ = 'key_type key csr cert_str'.split()
	def __init__(self, *args, **kws):
		for k,v in it.chain(zip(self.__slots__, args), kws.items()): setattr(self, k, v)


class ACMEError(Exception): pass
class ACMEAuthRetry(Exception): pass

def acme_auth_retry(func, *args, retry_n=0, retry_timeout=0, **kws):
	'Wrapper to retry requests for bad nonces or any known server issues.'
	delays = ( retries_within_timeout(retry_n, retry_timeout)
		if (retry_n or 0) > 0 and (retry_timeout or 0) > 0 else list() )
	kws_for_attempt = dict()
	for delay in delays + [0]:
		func_kws = kws.copy()
		if kws_for_attempt:
			func_kws.update(kws_for_attempt)
			kws_for_attempt.clear()
		try: func_res = func(*args, **func_kws)
		except ACMEAuthRetry as err:
			err_type, err_res = err.args
			log.debug( 'Got known ACME auth issue {!r}, retry in: {}',
				err_type, f'{delay:.1f}s' if delay else 'no-retries-left' )
			if err_type == 'bad_nonce' and 'Replay-Nonce' in res.headers:
				kws_for_attempt['nonce'] = res.headers['Replay-Nonce']
		else: return func_res
		if delay: time.sleep(delay)
	return p_err_for_req(err_res, final=True)

def acme_auth_poll_delay(n, poll_interval, retry_delay=None, delay_hook=None):
	'Sleep according to Retry-After response header value (retry_delay) or poll_interval.'
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
	if delay_hook: delay_hook(retry_delay_acme)
	retry_delay = max(0, delay_until - time.monotonic())
	if retry_delay > 0:
		log.debug('Polling auth delay [{:02d}]: {:.2f}', n, retry_delay)
		time.sleep(retry_delay)


def cert_gen(key_type_list, cert_domain_list, cert_name_attrs):
	'Generate list of X509CertInfo objects with keys and CSRs for specified key types.'
	x509, NameOID = cryptography.x509, cryptography.x509.oid.NameOID
	csr = x509.CertificateSigningRequestBuilder()
	csr_name = list()
	for k, v in cert_name_attrs:
		csr_name.append(x509.NameAttribute(getattr(NameOID, k.upper()), v))
	csr_name.append(x509.NameAttribute(
		NameOID.COMMON_NAME, cert_domain_list[0] ))
	csr = csr.subject_name(x509.Name(csr_name))
	csr = csr.add_extension(x509.SubjectAlternativeName(
		list(map(x509.DNSName, cert_domain_list)) ), critical=False)

	certs = list()
	for key_type in key_type_list:
		ci = X509CertInfo(key_type=key_type)
		log.debug('Generating {} key for certificate...', key_type)
		ci.key = generate_crypto_key(key_type)
		if not ci.key:
			raise ACMEError('Unknown/unsupported --cert-key-type value: {key_type!r}')
		ci.csr = csr.sign(ci.key, hashes.SHA256(), crypto_backend)
		certs.append(ci)
	return certs


def domain_auth( acc, domain_set, auth_url,
		p_acme_dir, token_mode=0o644, poll=None, query_httpd=True ):
	'Complete http-01 challenge authorization sequence for domain.'
	res = acc.req(auth_url, '')
	if res.code != 200:
		p_err('ERROR: Auth info request failed: {}', auth_url)
		return p_err_for_req(res)
	domain = res.json()['identifier']['value']
	if domain not in domain_set:
		p_err('ERROR: Auth-URL domain {!r} not in requested set: {!r}', domain, domain_set)
		return p_err_for_req(res)
	res = res.json()
	if res['status'] == 'valid':
		log.debug('Pre-authorized access to domain: {!r}', domain)
		return

	log.debug('Authorizing access to domain: {!r}', domain)
	acc.hooks.run('auth.start', domain)

	for ch in res['challenges']:
		if ch['type'] == 'http-01': break
	else:
		p_err('ERROR: No supported challenge types offered for domain: {!r}', domain)
		return p_err('Challenge-offer JSON:{}', indent_lines(res.body.decode()))
	token, token_url = ch['token'], ch['url']
	if re.search(r'[^\w\d_\-]', token):
		return p_err( 'ERROR: Refusing to create path for'
			' non-alphanum/b64 token value (security issue): {!r}', token )
	key_authz = f'{token}.{acc.key.jwk_thumbprint}'
	p_token = p_acme_dir / token
	with safe_replacement(p_token, mode=token_mode) as dst: dst.write(key_authz)
	try:

		acc.hooks.run('auth.publish-challenge', domain, p_token)
		if query_httpd:
			url = f'http://{domain}/.well-known/acme-challenge/{token}'
			res = http_req(url)
			if not (res.code == 200 and res.body.decode() == key_authz):
				return p_err( 'ERROR: Token-file created in'
					' -d/--acme-dir is not available at domain URL: {}', url )

		res = acc.req(token_url, dict())
		if res.code not in [200, 202]:
			p_err('ERROR: http-01 challenge response was not accepted')
			return p_err_for_req(res)

		for n in range(1, poll.attempts+1):
			acc.hooks.run('auth.poll-attempt', domain, p_token, n)
			log.debug('Polling auth [{:02d}]: {!r}', n, domain)
			res = http_req(token_url)
			if res.code not in [200, 202]:
				p_err('ERROR: http-01 challenge-status-poll request failed')
				return p_err_for_req(res)

			data, retry_delay = res.json(), res.headers.get('Retry-After')
			if data['status'] == 'invalid':
				p_err('ERROR: http-01 challenge response was rejected by ACME CA')
				return p_err_for_req(res)
			if data['status'] == 'valid':
				try:
					idn = data.get('identifier')
					if idn is not None:
						if idn['type'] != 'dns' or idn['value'] != domain: raise KeyError
					else: # 2019-10-07 - LE returns non-RFC validationRecord list, use that
						for vr in data['validationRecord']:
							if vr['hostname'] == domain: break
						else: raise KeyError
				except:
					return p_err('ERROR: Auth ID mismatch for domain {!r}: {!r}', domain, data)
				break
			if data['status'] not in ['pending', 'processing']:
				return p_err('ERROR: unknown http-01 challenge status for domain {!r}: {!r}', domain, data)

			acme_auth_poll_delay( n, poll.interval, retry_delay,
				ft.partial(acc.hooks.run, 'auth.poll-delay', domain, p_token, n) )

	finally:
		try: p_token.unlink()
		except OSError: pass

	acc.hooks.run('auth.done', domain)
	log.debug('Authorized access to domain: {!r}', domain)


def cert_issue(acc, ci, cert_domain_list, auth_opts, acme_retry=dict()):
	'Return signed-pem-certificate-chain str for X509CertInfo object (CSR).'
	acme_retry_wrap = ft.partial(acme_auth_retry, **acme_retry)
	csr_der = ci.csr.public_bytes(serialization.Encoding.DER)
	acc.hooks.run('cert.csr-check', ci.key_type, *cert_domain_list, stdin=csr_der)

	# 2019-10-07 - passing any non-empty notBefore/notAfter is not supported:
	#  https://github.com/letsencrypt/boulder/blob/a3c3f521/wfe2/wfe.go#L1936-L1958
	res = acme_retry_wrap( acc.req, 'newOrder',
		dict(identifiers=list(dict(type='dns', value=d) for d in cert_domain_list)) )
	if res.code != 201:
		p_err('ERROR: ACME newOrder request failed for domains: {!r}', cert_domain_list)
		return p_err_for_req(res)
	res = res.json()
	auth_domains = list(d['value'] for d in res['identifiers'] if d['type'] == 'dns')
	if set(auth_domains).difference(cert_domain_list):
		return p_err( 'ERROR: ACME newOrder response'
			' identifiers list mismatch {!r}: {!r}', cert_domain_list, res )
	auth_url_final = res['finalize']

	acc.hooks.run('auth.start-all', *auth_domains)
	for auth_url in res['authorizations']:
		err = acme_retry_wrap( domain_auth, acc,
			set(auth_domains), auth_url, **auth_opts )
		if err: return err
	acc.hooks.run('auth.done-all', *auth_domains)

	log.debug('Submitting CSR({}) for signing', ci.key_type)
	res = acme_retry_wrap( acc.req,
		auth_url_final, dict(csr=b64_b2a_jose(csr_der)) )
	if res.code != 200:
		p_err('ERROR: Failed to finalize ACME challenge')
		return p_err_for_req(res)
	res = res.json()

	if res['status'] == 'processing':
		for n in range(1, auth_opts.poll.attempts+1):
			acme_auth_poll_delay(
				n, auth_opts.poll.interval, res.headers.get('Retry-After'),
				lambda d: acc.hooks.run('cert.poll-delay', n, d, *cert_domain_list) )
			log.debug('Checking cert({}) signing status [{:02d}]', ci.key_type, n)
			res = acme_retry_wrap(acc.req, auth_url_final)
			if res.code not in 200:
				p_err('ERROR: signing-status-poll request failed')
				return p_err_for_req(res)
			res = res.json()
			if res['status'] != 'processing': break

	if res['status'] != 'valid':
		p_err('ERROR: Error response to challenge finalize request')
		return p_err_for_req(res)

	res = acme_retry_wrap(acc.req, res['certificate'])
	if res.code != 200 or res.headers.get('Content-Type') != 'application/pem-certificate-chain':
		p_err('ERROR: Failed to download pem certificate chain')
		return p_err_for_req(res)
	return res.body.decode().strip() + '\n' # pem cert chain


def cmd_cert_issue(
		acc, p_cert_dir, p_cert_base, key_type_list, cert_domain_list, cert_name_attrs,
		split_key_file=False, file_mode=0o600, remove_files_for_prefix=False, **issue_kws ):

	certs = cert_gen(key_type_list, cert_domain_list, cert_name_attrs)
	for n, ci in enumerate(certs, 1):
		cert_str = cert_issue(acc, ci, cert_domain_list, **issue_kws)
		if not isinstance(cert_str, str): return 1 # error code from wrapper
		ci.cert_str = cert_str
		log.debug('Signed cert({}) [{}/{}]', ci.key_type, n, len(certs))
	acc.hooks.run('cert.issued', *cert_domain_list)

	files_used, key_type_suffix = set(), len(certs) > 1
	for ci in certs:
		key_str = ci.key.private_bytes( serialization.Encoding.PEM,
			serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption() ).decode()
		p = p_cert_base
		if key_type_suffix:
			p = '{}.{}'.format(p.rstrip('.'), ci.key_type)
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
			ci.key_type, p_cert, f' / {p_key}' if p_key else '' )
	acc.hooks.run('cert.stored', *filter(None, files_used))

	if remove_files_for_prefix:
		p_prefix = f'{p_cert_base}.'
		for p in p_cert_dir.iterdir():
			if p.is_dir() or p.name in files_used or not p.name.startswith(p_prefix): continue
			log.debug('Removing unused matching-prefix file: {}', p.name)
			p.unlink()


def main(args=None):
	import argparse

	dedent = lambda text: (textwrap.dedent(text).strip('\n') + '\n').replace('\t', '  ')
	class SmartHelpFormatter(argparse.HelpFormatter):
		def __init__(self, *args, **kws):
			return super().__init__(*args, **kws, width=100)
		def _fill_text(self, text, width, indent):
			if '\n' not in text: return super()._fill_text(text, width, indent)
			return ''.join(indent + line for line in text.splitlines(keepends=True))
		def _split_lines(self, text, width):
			return super()._split_lines(text, width)\
				if '\n' not in text else dedent(text).splitlines()

	parser = argparse.ArgumentParser(
		formatter_class=SmartHelpFormatter,
		description='Lets Encrypt CA interaction tool to make'
			' it authorize domain (via http-01 challenge) and sign/renew/revoke TLS certs.',
		epilog=dedent('''
			Usage examples:

				- Generate/register new account key, generate certificate for "mydomain.com"
					and authorize/sign it with Let's Encrypt "Fake LE Intermediate X1" staging CA:

						% ./acme-cert-tool.py --debug -gk le-staging.acc.key cert-issue \\
								le-staging.cert.pem /srv/www/.well-known/acme-challenge mydomain.com

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

			See more info at: https://github.com/mk-fg/acme-cert-tool'''))

	group = parser.add_argument_group('ACME service options')
	group.add_argument('-k', '--account-key-file', metavar='path', help='''
			Path to ACME domain-specific private key to use (pem with pkcs8/openssl/pkcs1).
			All operations wrt current domain will be authenticated using this key.
			It has nothing to do with actual issued TLS certs and cannot be reused in them.
			Has no default value on purpose, must be explicitly specified.
			If registered with ACME server, account URL will also be stored in the file alongside key.
			If --gen-key (or -g/--gen-key-if-missing) is also specified,
				will be generated and path (incl. directories) will be created.''')
	group.add_argument('-s', '--acme-service',
		metavar='url-or-name', default='le-staging', help='''
			ACME directory URL (or shortcut) of Cert Authority (CA) service to interact with.
			Available shortcuts: le - Let's Encrypt, le-staging - Let's Encrypt staging server.
			Default: %(default)s''')
	group.add_argument('--acme-auth-retries',
		metavar='n:timeout', default='5:300', help='''
			Number of authentication retries with exp-backoff to make within
				specified timeout for defined ACME protocol quirks like nonce-retries.
			Specific nonce-retry issue is https://tools.ietf.org/html/rfc8555#section-6.5
				but any other known bugs and similar things will also use this count/timer.
			Setting this to 0 or empty value will disable such retry logic. Default: %(default)s''')

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
		help='''
			Issue a key-change command from an old key specified with this option.
			Can be used for importing account keys from other sources.
			Overrides -r/--register option - if old key is specified, new one
				(specified as -k/--account-key-file) will attached to same account as the old one.''')

	group = parser.add_argument_group('Hook options')
	group.add_argument('-x', '--hook', action='append', metavar='hook:path',
		help='''
			Hook-script to run at the specified point.
			Specified path must be executable (chmod +x ...), will be run synchronously, and
				must exit with 0 for tool to continue operation, and non-zero to abort immediately.
			Hooks are run with same uid/gid and env as the main script, can use PATH-lookup.
			See --hook-list output to get full list of
				all supported hook-points and arguments passed to them.
			Example spec: -x domain-auth.publish-challenge:/etc/nginx/sync-frontends.sh''')
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


	cmds = parser.add_subparsers(title='Commands',
		description='Use -h/--help with these to list command-specific options.', dest='call')


	cmd = cmds.add_parser('account-info',
		help='Request and print info for ACME account associated with the specified key.')

	cmd = cmds.add_parser('account-deactivate',
		help='Deactivate (block/remove) ACME account'
			' associated with the key. It cannot be reactivated again.')


	cmd = cmds.add_parser('cert-issue',
		formatter_class=SmartHelpFormatter,
		help='Generate new X.509 v3 (TLS) certificate/key pair'
			' for specified domain(s), with cert signed by ACME CA.')

	group = cmd.add_argument_group('Certificate key and files')
	group.add_argument('file_prefix',
		help='Resulting PEM filename or filename prefix'
			' (if >1 files/certs are requested, see options below).')
	group.add_argument('-c', '--cert-key-type',
		action='append', metavar='type', choices=['rsa-2048', 'rsa-4096', 'ec-384'],
		help='''
			Certificate key type(s) to generate.
			Can be used multiple times to issue same certificate for
			 multiple different keys, e.g. ec-384 cert and a fallback
			 rsa-2048 one for (rare) clients that do not support ecc.
			If more than one key type is specified, each cert/key
			 pair will be stored to different .pem file(s), with corresponding filename
			 suffixes and an extra dot separator (if prefix does not end with one),
			 e.g. "mycert.ec-384.pem" and "mycert.rsa-2048.pem".
			Possible values: rsa-2048, rsa-4096, ec-384 (secp384r1). Default: ec-384''')
	group.add_argument('-s', '--split-key-file', action='store_true',
		help='Store private key in a separate .key file, while certificate to a .crt file, both'
				' with specified filename prefix plus a dot separator, e.g. "mycert.crt" + "mycert.key".'
			' Default is to store both cert and key in the same (specified) file.')
	group.add_argument('-r', '--remove-files-for-prefix', action='store_true',
		help='After storing new cert/key files, remove all files with specified prefix'
			' that were there previously. Only done after successful operation,'
			' idea is to cleanup any old files to avoid confusion.')

	group = cmd.add_argument_group('Certificate info')
	group.add_argument('acme_dir', help='''
		Directory that is served by domain's httpd at "/.well-known/acme-challenge/".
		Will be created, if does not exist already.''')
	group.add_argument('domain',
		help='Main domain to issue certificate for.'
			' Will be used in a certificate Common Name field (CN) and SubjectAltName.')
	group.add_argument('altname', nargs='*',
		help='Extra domain(s) that certificate should be valid for.'
			' Will be used in a certificate SubjectAltName extension field.')
	group.add_argument('-i', '--cert-name-attrs',
		action='append', metavar='attr:value', help='''
			Additional attributes to include in the X.509 Name, in attr=value format.
			This option can be used multiple times, attributes
			 will be added in the same order with CN from "domain" arg at the end.
			See list of recognized "attr" names (case-insensitive) in cryptography.io docs:
			 https://cryptography.io/en/latest/x509/reference/#object-identifiers
			For example, to have country and email attrs in the cert, use:
			 -i country_name:US -i  email_address:user@myhost.com''')

	group = cmd.add_argument_group('Certificate authorization options')
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
		p('Some/most hooks get passed arguments, as mentioned in hook descriptions.')
		p('Setting --hook-timeout (defaults to 120s) can be used to abort when hook-scripts hang.')
		return
	for v in opts.hook or list():
		if ':' not in v: parser.error(f'Invalid --hook spec (must be hook:path): {v!r}')
		hp, path = v.split(':', 1)
		if hp not in acc_hooks.points:
			parser.error(f'Invaluid hook name: {hp!r} (see --hook-list)')
		acc_hooks[hp] = path

	if opts.umask != '-': os.umask(int(opts.umask, 8) & 0o777)
	file_mode = int(opts.mode, 8) & 0o777

	acme_url = opts.acme_service
	if ':' not in acme_url:
		try: acme_url = acme_ca_shortcuts[acme_url.replace('-', '_')]
		except KeyError: parser.error(f'Unkown --acme-service shortcut: {acme_url!r}')
	acme_url = ACMEServer(acme_url)
	acme_url.d = None

	if not opts.account_key_file:
		parser.error('Path for -k/--account-key-file must be specified.')
	p_acc_key = pl.Path(opts.account_key_file)
	if opts.gen_key or (opts.gen_key_if_missing and not p_acc_key.exists()):
		acc_key = AccKey.generate_to_file(p_acc_key, opts.key_type, file_mode=file_mode)
		if not acc_key:
			parser.error(f'Unknown/unsupported --key-type value: {opts.key_type!r}')
	elif p_acc_key.exists():
		acc_key = AccKey.load_from_file(p_acc_key)
		if not acc_key: parser.error(f'Unknown/unsupported key type: {p_acc_key}')
	else: parser.error(f'Specified --account-key-file path does not exists: {p_acc_key!r}')
	acc_meta = AccMeta.load_from_key_file(p_acc_key, file_mode=file_mode)
	log.debug( 'Using {} domain key: {} (acme acc url: {})',
		acc_key.t, acc_key.pk_hash, acc_meta.get('acc.url') )

	acme_retry_opts = dict(retry_n=0, retry_timeout=0)
	if opts.acme_auth_retries:
		try: n, timeout = opts.acme_auth_retries.split(':', 1)
		except ValueError: n, timeout = opts.acme_auth_retries, 300
		acme_retry_opts.update(retry_n=int(n), retry_timeout=float(timeout))
	acme_retry_wrap = ft.partial(acme_auth_retry, **acme_retry_opts)


	### Handle account status

	acc_key_old = opts.account_key_file_old
	acc_register = opts.register or acc_key_old or not acc_meta.get('acc.url')
	acc_contact = opts.contact_email
	if not acc_contact.startswith('mailto:'): acc_contact = f'mailto:{acc_contact}'

	payload_reg = {'termsOfServiceAgreed': True}
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
			p_acc_key_old = pl.Path(acc_key_old)
			acc_key_old = AccKey.load_from_file(p_acc_key_old)
			if not acc_key_old:
				parser.error( f'Unknown/unsupported key type'
					' specified with -o/--account-key-file-old: {p_acc_key}' )
			acc_meta_old = AccMeta.load_from_key_file(p_acc_key_old)
			acc_url_old = acc_meta_old.get('acc.url')
			if not acc_url_old:
				log.debug( 'Old key file (-o/--account-key-file-old) does'
					' not have registration URL, will be fetched via newAccount request' )
				res = acme_retry_wrap( signed_req,
					acc_key_old, 'newAccount', payload_reg, acme_url=acme_url )
				if res.code not in [200, 201, 409]:
					p_err('ERROR: ACME new-reg'
						' request for old key (-o/--account-key-file-old) failed')
					return p_err_for_req(res)
				acc_url_old = res.headers['Location']

		if not acc_key_old: # newAccount
			if acc_contact: payload_reg['contact'] = [acc_contact]
			res = acme_retry_wrap( signed_req,
				acc_key, 'newAccount', payload_reg, acme_url=acme_url )
			if res.code not in [201, 409]:
				p_err('ERROR: ACME newAccount (key registration) request failed')
				return p_err_for_req(res)
			log.debug('Account registration status: {} {}', res.code, res.reason)
			acc_meta['acc.url'] = res.headers['Location']
			if res.code == 201: acc_meta['acc.contact'] = acc_contact
		else: # keyChange
			with urlopen(acme_url) as r: # need same-url for both inner and outer payloads
				assert r.getcode() == 200
				acme_url.d = adict(json.load(r))
			payload = dict(account=acc_url_old, oldKey=acc_key_old.jwk)
			payload = signed_req_body( # "inner" JWS with jwk and no nonce
				acc_key, payload, url=acme_url.d.keyChange, encode=False )
			res = acme_retry_wrap( signed_req, acc_key_old,
				acme_url.d.keyChange, payload, kid=acc_url_old, acme_url=acme_url )
			if res.code not in [200, 201, 202]:
				p_err('ERROR: ACME account key-change request failed')
				return p_err_for_req(res)
			log.debug('Account key-change success: {} -> {}', acc_key_old.pk_hash, acc_key.pk_hash)
			acc_meta['acc.url'] = acc_url_old
			acc_meta['acc.contact'] = acc_meta_old.get('acc.contact')
		acc_meta.save()

	if acc_contact and acc_contact != acc_meta.get('acc.contact'):
		log.debug('Updating account contact information')
		res = acme_retry_wrap( signed_req, acc_key, acc_meta['acc.url'],
			dict(contact=[acc_contact]), kid=acc_meta['acc.url'], acme_url=acme_url )
		if res.code not in [200, 201, 202]:
			p_err('ERROR: ACME account contact info update request failed')
			return p_err_for_req(res)
		log.debug(
			'Account contact info updated: {!r} -> {!r}',
			acc_meta.get('acc.contact'), acc_contact )
		acc_meta['acc.contact'] = acc_contact
		acc_meta.save()

	acc = AccSetup( acc_key, acc_meta, acc_hooks,
		ft.partial(signed_req, acc_key, acme_url=acme_url, kid=acc_meta['acc.url']) )


	### Handle commands

	if opts.call == 'account-info':
		res = acme_retry_wrap(acc.req, acc.meta['acc.url'])
		if res.code not in [200, 201, 202]:
			p_err('ERROR: ACME account info request failed')
			return p_err_for_req(res)
		p(res.body.decode())

	elif opts.call == 'account-deactivate':
		res = acme_retry_wrap( acc.req,
			acc.meta['acc.url'], dict(status='deactivated') )
		if res.code != 200:
			p_err('ERROR: ACME account deactivation request failed')
			return p_err_for_req(res)
		p(res.body.decode())


	elif opts.call == 'cert-issue':
		key_type_list = opts.cert_key_type or ['ec-384']
		p_cert_base = pl.Path(opts.file_prefix)
		p_cert_dir, p_cert_base = p_cert_base.parent, p_cert_base.name
		cert_domain_list = [opts.domain] + (opts.altname or list())
		cert_name_attrs = list()
		for v in opts.cert_name_attrs or list():
			if ':' not in v:
				parser.error(f'Invalid --cert-subject-info spec (must be attr:value): {v!r}')
			cert_name_attrs.append(map(str.strip, v.split(':', 1)))

		p_acme_dir = pl.Path(opts.acme_dir)
		p_acme_dir.mkdir(parents=True, exist_ok=True)
		token_mode = int(opts.challenge_file_mode, 8) & 0o777
		if opts.auth_poll_params:
			delay, attempts = opts.auth_poll_params.split(':', 1)
			poll_opts = adict(interval=float(delay), attempts=int(attempts))
		else:
			poll_opts = adict( attempts=15,
				interval=lambda n: min(60, (2**n - 1) / 5) )
		auth_opts = adict( p_acme_dir=p_acme_dir,
			token_mode=token_mode, poll=poll_opts,
			query_httpd=not opts.dont_query_local_httpd )

		return cmd_cert_issue( acc, p_cert_dir, p_cert_base,
			key_type_list, cert_domain_list, cert_name_attrs,
			file_mode=file_mode, split_key_file=opts.split_key_file,
			remove_files_for_prefix=opts.remove_files_for_prefix,
			auth_opts=auth_opts, acme_retry=acme_retry_opts )

	elif not opts.call: parser.error('No command specified')
	else: parser.error(f'Unrecognized command: {opts.call!r}')


if __name__ == '__main__': sys.exit(main())
