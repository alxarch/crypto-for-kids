'use strict';
// Sync crypto helpers
const crypto = require('crypto');
const DEFAULT_CIPHER_ALGORITHM = 'aes-256-ctr';
const DEFAULT_HASH_ALGORITHM = 'md5';
const DEFAULT_HMAC_ALGORITHM = 'HS256';
const DEFAULT_ENCODING = 'hex';

function Crypto (input_encoding, output_encoding) {
	if (!(this instanceof Crypto)) {
		return new Crypto(input_encoding, output_encoding);
	}
	this.input_encoding = input_encoding === false ? null : (input_encoding || DEFAULT_ENCODING);
	this.output_encoding = output_encoding === false ? null : (output_encoding || DEFAULT_ENCODING);
}

Crypto.prototype.output = function (result) {
	return this.output_encoding ? result.toString(this.output_encoding) : result;
}

Crypto.prototype.encrypt = function encrypt (data, secret, algorithm) {
	data = data instanceof Buffer ? data : new Buffer(data);
	secret = secret instanceof Buffer ? secret : new Buffer(secret);

	const cipher = crypto.createCipher(algorithm || DEFAULT_CIPHER_ALGORITHM, secret);
	const parts = [];
	parts.push(cipher.update(data));
	parts.push(cipher.final());
	return this.output(Buffer.concat(parts));
};

Crypto.prototype.decrypt = function decrypt (data, secret, algorithm) {

	if (!(data instanceof Buffer)) {
		data = 'string' === typeof data && this.input_encoding ?
			new Buffer(data, this.input_encoding) : new Buffer(data);
	}
	secret = secret instanceof Buffer ? secret : new Buffer(secret);

	const decipher = crypto.createDecipher(algorithm || DEFAULT_CIPHER_ALGORITHM, secret);
	const parts = [];
	parts.push(decipher.update(data));
	parts.push(decipher.final());
	const result = Buffer.concat(parts);
	return this.output_encoding ? result.toString() : result;
};

Crypto.prototype.hash = function hash (data, algorithm) {
	data = data instanceof Buffer ? data : new Buffer(data);
	const _hash = crypto.createHash(algorithm || DEFAULT_HASH_ALGORITHM);
	_hash.end(data);
	const result = _hash.read();
	return this.output(result);
};

Crypto.prototype.sign = function sign (data, key, algorithm) {
	data = data instanceof Buffer ? data : new Buffer(data);
	const _sign = crypto.createSign(algorithm);
	_sign.update(data);
	const result = _sign.sign(key);
	return this.output(result);
};

Crypto.prototype.hmac = function hmac (data, secret, algorithm) {
	data = data instanceof Buffer ? data : new Buffer(data);
	const _hmac = crypto.createHmac(algorithm || DEFAULT_HMAC_ALGORITHM, secret);
	_hmac.end(data);
	const result = _hmac.read();
	return this.output(result);
};


['md5', 'sha', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'].forEach( algorithm => {
	Crypto.prototype[`${algorithm}sum`] = function (data) {
		return this.hash(data, algorithm);
	};
});

[256, 384, 512].forEach( bits => {
	Crypto.prototype[`hs${bits}`] = function (data, secret) {
		return this.hmac(data, secret, `sha${bits}`);
	};
	Crypto.prototype[`rs${bits}`] = function (data, key) {
		return this.sign(data, key, `RSA-SHA${bits}`);
	};
});

['aes192', 'aes256', 'aes512'].forEach(algorithm => {
	Crypto.prototype[`${algorithm}decrypt`] = function (data, password) {
		return this.decrypt(data , password, algorithm);
	};
	Crypto.prototype[`${algorithm}encrypt`] = function (data, password) {
		return this.encrypt(data, password, algorithm);
	};
});


module.exports = Crypto;
Object.setPrototypeOf(module.exports, Object.create(Crypto.prototype, {
	output_encoding: { value: 'hex', writable: false },
	input_encoding: { value: 'hex', writable: false }
}));

module.exports.Crypto = Crypto;
module.exports.hex = Crypto('hex', 'hex');
module.exports.buffer = Crypto(false, false);
module.exports.base64 = Crypto('base64', 'base64');
