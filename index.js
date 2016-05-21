'use strict';
// Sync crypto helpers
const crypto = require('crypto');
const DEFAULT_CIPHER_ALGORITHM = 'aes-256-ctr';
const DEFAULT_HASH_ALGORITHM = 'md5';
const DEFAULT_HMAC_ALGORITHM = 'HS256';
const DEFAULT_HMAC_ENCODING = 'hex';
const DEFAULT_HASH_ENCODING = 'hex';

function checkData (data) {
	if (data instanceof Buffer) {
		return data;
	}
	else if ('string' == typeof data) {
		return new Buffer(data);
	}
	throw new TypeError('Data is not buffer');
}

function encrypt (data, secret, algorithm) {
	data = checkData(data);
	const cipher = crypto.createCipher(algorithm || DEFAULT_CIPHER_ALGORITHM, secret);
	const parts = [];
	parts.push(cipher.update(data));
	parts.push(cipher.final());
	return Buffer.concat(parts);
}

function decrypt (data, secret, algorithm) {
	data = checkData(data);
	const decipher = crypto.createDecipher(algorithm || DEFAULT_CIPHER_ALGORITHM, secret);
	const parts = [];
	parts.push(decipher.update(data));
	parts.push(decipher.final());
	return Buffer.concat(parts);
}

function hash (data, algorithm) {
	data = checkData(data);
	const _hash = crypto.createHash(algorithm || DEFAULT_HASH_ALGORITHM);
	_hash.end(data);
	return _hash.read();
}

function sign (data, key, algorithm) {
	data = checkData(data);
	const _sign = crypto.createSign(algorithm);
	_sign.update(data);
	return _sign.sign(key);
}

function hmac (data, secret, algorithm) {
	data = checkData(data);
	const _hmac = crypto.createHmac(algorithm || DEFAULT_HMAC_ALGORITHM, secret);
	_hmac.end(data);
	return _hmac.read();
}

module.exports = {
	sign,
	encrypt,
	decrypt,
	hmac,
	hash
};

['md5', 'sha', 'sha1', 'sha224', 'sha384', 'sha512'].forEach( alg => {
	module.exports[`${alg}sum`] = function (data, encoding) {
		return hash(data, alg).toString(encoding || DEFAULT_HASH_ENCODING);
	};
});

[256, 384, 512].forEach( bits => {
	module.exports[`hs${bits}`] = function (data, secret, encoding) {
		return hmac(data, secret, `sha${bits}`).toString(encoding || DEFAULT_HMAC_ENCODING);
	};
	module.exports[`rs${bits}`] = function (data, key, encoding) {
		return sign(data, key, `RSA-SHA${bits}`).toString(encoding || DEFAULT_HMAC_ENCODING);
	};
});

['aes192', 'aes256', 'aes512'].forEach(alg => {
	module.exports.decrypt[alg] = function (data, password, encoding) {
		return decrypt(data, secret, alg).toString(encoding || 'hex');
	};
	module.exports.encrypt[alg] = function (data, password, encoding) {
		return encrypt(data, secret, alg).toString(encoding || 'hex');
	};
});
