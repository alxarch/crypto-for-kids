'use strict';
// Sync crypto helpers
const crypto = require('crypto');

function parseOptions (options, defaults) {
	options = 'string' == typeof options ? {secret: options} : options;
	options = Object.assign({}, defaults, options);
	if (!options.secret) throw new TypeError('No secret specified');
	return options;
};

function encrypt (data, options) {
	options = parseOptions(options, {
		algorithm: 'aes-256-ctr',
		format: 'hex'
	});
	const cipher = crypto.createCipher(options.algorithm, options.secret);
	cipher.end(data);
	const result = cipher.read();
	return result != null ? result.toString(options.format) : result;
}

function decrypt (data, options) {
	options = parseOptions(options, {
		algorithm: 'aes-256-ctr',
		format: 'hex'
	});
	const decipher = crypto.createDecipher(options.algorithm, options.secret);
	decipher.end(new Buffer(data, options.format));
	const result = decipher.read();
	return result != null ? result.toString() : result;
}

function hash (data, options) {
	options = parseOptions(options, {
		format: 'hex',
		algorithm: 'md5',
		secret: 'foo'
	});
	const _hash = crypto.createHash(options.algorithm);
	_hash.end(data);
	const result = _hash.read();
	return result != null ? result.toString(options.format) : result;
}
function md5sum (data, options) {
	options = Object.assign({}, options, {algorithm: 'md5'});
	return hash(data, options);
}

function hmac (data, options) {
	options = parseOptions(options, {
		algorithm: 'sha256',
		format: 'base64'
	});
	const _hmac = crypto.createHmac(options.algorithm, options.secret);
	_hmac.end(data);
	const result = _hmac.read();
	return result != null ? result.toString(options.format) : null;
}

module.exports = {encrypt, decrypt, md5sum, hmac, md5sum, hash, parseOptions};
