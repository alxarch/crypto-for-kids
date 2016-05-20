'use strict';
const crypto = require('.');
const assert = require('assert');
describe('Crypto for kids module', () => {
	describe('crypto.hmac()', () => {
		it('Signs string data with default settings', () => {
			assert.equal(
					crypto.hmac('Foo bar baz', 'secretsauce'),
					'zZ/HU0VoLD31Fg+ms9s09ZNAFYqwom9SHr8NOeLoV/k=');
		});
		it('Signs string data with hex encoding', () => {
			assert.equal(
					crypto.hmac('Foo bar baz', {format: 'hex', secret: 'secretsauce'}),
					'cd9fc75345682c3df5160fa6b3db34f59340158ab0a26f521ebf0d39e2e857f9');
		});

		it('Signs buffer data', () => {
			assert.equal(
					crypto.hmac(new Buffer('Foo bar baz'), 'secretsauce'),
					'zZ/HU0VoLD31Fg+ms9s09ZNAFYqwom9SHr8NOeLoV/k=');
		});
	});
	describe('crypto.encrypt()', () => {
		it('Encrypts/decrypts data with default settings', () => {
			const encrypted = crypto.encrypt('Foo bar baz', 'secretesauce');
			const decrypted = crypto.decrypt(encrypted, 'secretesauce');
			assert.equal('Foo bar baz', decrypted, 'OK');
		});
	});
	describe('crypto.hash', () => {
		it('Signs data with default settings', () => {
			const msg = 'Foo bar baz';
			const secret = 'secretesauce';
			const hash = crypto.hash(new Buffer(msg), {format: 'hex', secret: secret});
			const hashMD5 = crypto.md5sum(new Buffer(msg));
			assert.equal(hash, hashMD5, 'OK');
		});
		it('Signs data with DSA hash', () => {
			const msg = 'Foo bar baz';
			const secret = 'secretesauce';
			const hashDSA = crypto.hash(new Buffer(msg), {format: 'hex', algorithm:'DSA', secret: secret});
			assert.equal(hashDSA, 'b861fddd3d1262c9102b69025accbf5fe887db2f', 'OK');
		});

		// SHA1 and DSA algorithms produce the same hash

		it('Signs data with SHA1 hash', () => {
			const msg = 'Foo bar baz';
			const secret = 'secretesauce';
			const hashSHA1 = crypto.hash(new Buffer(msg), {format: 'hex', algorithm:'DSA', secret: secret});
			assert.equal(hashSHA1, 'b861fddd3d1262c9102b69025accbf5fe887db2f', 'OK');
		});
		it('Signs data with SHA1 hash', () => {
			const msg = 'Foo bar baz';
			const secret = 'secretesauce';
			const hashSHA1 = crypto.hash(new Buffer(msg), {format: 'hex', algorithm:'DSA', secret: secret});
			assert.equal(hashSHA1, 'b861fddd3d1262c9102b69025accbf5fe887db2f', 'OK');
		});
		it('Signs data with SHA1 hash', () => {
			const msg = 'Foo bar baz';
			const secret = 'secretesauce';
			const hashWhirlpool = crypto.hash(new Buffer(msg), {format: 'hex', algorithm:'whirlpool', secret: secret});
			assert.equal(hashWhirlpool, '74a6baf1a6eaba0064c8dee162b25cb745c84869811e9b06332da25431136cfd263ab18e957e93b33cf97374d184f71ea90b9358b0126bc8c9ea7a3928d9361c', 'OK');
		});
		it('Signs data with SHA256 hash', () => {
			const msg = 'Foo bar baz';
			const secret = 'secretesauce';
			const hashSHA256 = crypto.hash(new Buffer(msg), {format: 'hex', algorithm:'SHA256', secret: secret});
			assert.equal(hashSHA256, '4653841ef41adb4f201cc4e019409e5c2a8fce1fa88e22d6dbf6549e4965c9a1', 'OK');
		});
	});
	describe('crypto.md5sum', () => {
		it('Signs data with default settings', () => {
			const msg = 'Foo bar baz';
			const secret = 'secretesauce';
			const md5sum = crypto.md5sum(new Buffer(msg), {format: 'hex', secret: secret});
			assert.equal(md5sum, '520c28a8ac3459af817a1abfb3bd152e', 'OK');
		});
	});
	describe('parseOptions test', () => {
		it('throws error when no secret is provided', () => {
			assert.throws(function(){crypto.parseOptions({secret: null})}, TypeError, 'Does not throw error');
		});
		it('does not throw error if no secret is provided for hash', () => {
			const msg = 'Foo bar baz';
			let options = {};
			const hash_no_secret = crypto.hash(new Buffer(msg), options);
			const hash_default = crypto.hash(new Buffer(msg));
			assert.equal(hash_no_secret, hash_default, 'Secret not foo');
		});
	});
});
