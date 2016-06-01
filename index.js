'use strict';
// Sync crypto helpers
const crypto = require('crypto');
const DEFAULT_CIPHER_ALGORITHM = 'aes-256-ctr';
const DEFAULT_HASH_ALGORITHM = 'md5';
const DEFAULT_HMAC_ALGORITHM = 'HS256';
const DEFAULT_ENCODING = 'hex';

function encrypt (data, secret, algorithm, encoding) {
	data = data instanceof Buffer ? data : new Buffer(data);
	secret = secret instanceof Buffer ? secret : new Buffer(secret);

	const cipher = crypto.createCipher(algorithm || DEFAULT_CIPHER_ALGORITHM, secret);
	const parts = [];
	parts.push(cipher.update(data));
	parts.push(cipher.final());
	const result = Buffer.concat(parts);
	return null === encoding ? result : result.toString(encoding || DEFAULT_ENCODING);
}

function decrypt (data, secret, algorithm, encoding) {

	if (!(data instanceof Buffer)) {
		data = 'string' === typeof data ? new Buffer(data, DEFAULT_ENCODING) : new Buffer(data);
	}
	secret = secret instanceof Buffer ? secret : new Buffer(secret);

	const decipher = crypto.createDecipher(algorithm || DEFAULT_CIPHER_ALGORITHM, secret);
	const parts = [];
	parts.push(decipher.update(data));
	parts.push(decipher.final());
	const result = Buffer.concat(parts);
	return null === encoding ? result : result.toString(encoding || 'utf8');
}

decrypt.base64 = function (data, secret, algorithm, encoding) {
	return decrypt(new Buffer(data, 'base64'), secret, algorithm, encoding);
};

decrypt.hex = function (data, secret, algorithm, encoding) {
	return decrypt(new Buffer(data, 'hex'), secret, algorithm, encoding);
};

function hash (data, algorithm, encoding) {
	data = data instanceof Buffer ? data : new Buffer(data);
	const _hash = crypto.createHash(algorithm || DEFAULT_HASH_ALGORITHM);
	_hash.end(data);
	const result = _hash.read();
	return null === encoding ? result : result.toString(encoding || DEFAULT_ENCODING);
}

function sign (data, key, algorithm, encoding) {
	data = data instanceof Buffer ? data : new Buffer(data);
	const _sign = crypto.createSign(algorithm);
	_sign.update(data);
	const result = _sign.sign(key);
	return null === encoding ? result : result.toString(encoding || DEFAULT_ENCODING);
}

function hmac (data, secret, algorithm, encoding) {
	data = data instanceof Buffer ? data : new Buffer(data);
	const _hmac = crypto.createHmac(algorithm || DEFAULT_HMAC_ALGORITHM, secret);
	_hmac.end(data);
	const result = _hmac.read();
	return null === encoding ? result : result.toString(encoding || DEFAULT_ENCODING);
}


['md5', 'sha', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'].forEach( algorithm => {
	exports[`${algorithm}sum`] = function (data, encoding) {
		return hash(data, algorithm, encoding);
	};
});

[256, 384, 512].forEach( bits => {
	exports[`hs${bits}`] = function (data, secret, encoding) {
		return hmac(data, secret, `sha${bits}`, encoding);
	};
	exports[`rs${bits}`] = function (data, key, encoding) {
		return sign(data, key, `RSA-SHA${bits}`, encoding)
	};
});

['aes192', 'aes256', 'aes512'].forEach(algorithm => {
	decrypt[algorithm] = function (data, password, encoding) {
		return decrypt(data , password, algorithm, encoding)
	};
	decrypt.hex[algorithm] = function (data, password, encoding) {
		return decrypt.hex(data, password, algorithm, encoding);
	}
	decrypt.base64[algorithm] = function (data, password, encoding) {
		return decrypt.base64(data, password, algorithm, encoding);
	}
	encrypt[algorithm] = function (data, password, encoding) {
		return encrypt(data, password, algorithm, encoding);
	};
});

exports.sign = sign;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.hmac = hmac;
exports.hash = hash;
