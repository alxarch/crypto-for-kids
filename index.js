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
		format: 'hex',
		encoding: 'utf8'
	});
	const cipher = crypto.createCipher(options.algorithm, options.secret);
	data = data instanceof Buffer ? data : `${data}`;
	const parts = [];
	parts.push(cipher.update(data, options.encoding));
	parts.push(cipher.final());
	const result = Buffer.concat(parts);
	return result ? result.toString(options.format) : result;
}

function decrypt (data, options) {
	options = parseOptions(options, {
		algorithm: 'aes-256-ctr',
		format: 'hex',
		encoding: 'utf8'
	});
	const decipher = crypto.createDecipher(options.algorithm, options.secret);
	const parts = [];
	parts.push(decipher.update(data, options.format));
	parts.push(decipher.final());
	const result = Buffer.concat(parts);
	return result ? result.toString(options.encoding) : result;
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
