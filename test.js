'use strict';
const crypto = require('.');
const assert = require('assert');
describe('Crypto for kids module', () => {
	describe('crypto.hs384()', () => {
		it('Signs string data with default settings', () => {
			assert.equal(
				crypto.hs384('Foo bar baz', 'secretsauce'),
				'53a317119120f8353fd3feebb2adf5c0dab2894a1ca7368f746f0ce11d96f8d2464879261d2e9034f969ec73ef70f05e');
		});

	});
	describe('crypto.hs512()', () => {
		it('Signs string data with default settings', () => {
			assert.equal(
				crypto.hs512('Foo bar baz', 'secretsauce'),
				'1a4ce2b1b331c7c506bbc293cf16b78772a8201e09e9dba4151e96c4cfab5e6160907925c6cfd9cc7282c78e0707eab38fa9aad94f826d72cd6f5395f2964ba2');
		});

	});
	describe('crypto.hs256()', () => {
		it('Signs string data with base64', () => {
			assert.equal(

				crypto.base64.hs256('Foo bar baz', 'secretsauce'),
				'zZ/HU0VoLD31Fg+ms9s09ZNAFYqwom9SHr8NOeLoV/k=');
		});
		it('Signs string data with default settings', () => {
			assert.equal(
				crypto.hs256('Foo bar baz', 'secretsauce'),
				'cd9fc75345682c3df5160fa6b3db34f59340158ab0a26f521ebf0d39e2e857f9');
		});

		it('Signs buffer data with base64', () => {
			assert.equal(
					crypto.base64.hs256(new Buffer('Foo bar baz'), 'secretsauce'),
					'zZ/HU0VoLD31Fg+ms9s09ZNAFYqwom9SHr8NOeLoV/k=');
		});
		it('Signs buffer data with default to hex', () => {
			assert.equal(
				crypto.hs256(new Buffer('Foo bar baz'), 'secretsauce'),
				'cd9fc75345682c3df5160fa6b3db34f59340158ab0a26f521ebf0d39e2e857f9');
		});
	});

	describe('crypto.encrypt()', () => {
		it('Encrypts/decrypts data with default settings', () => {
			const encrypted = crypto.encrypt('Foo bar baz', 'secretesauce');
			assert('string' == typeof encrypted , 'encrypt returns string');
			const decrypted = crypto.decrypt(encrypted, 'secretesauce');
			assert('string' == typeof decrypted , 'decrypt returns string');
			assert.equal('Foo bar baz', decrypted, 'OK');
		});
		it('Encrypts/decrypts buffer data with default settings', () => {
			const encrypted = crypto.encrypt('Foo bar baz', 'secretesauce');
			const decrypted = crypto.decrypt.hex(encrypted, 'secretesauce');
			assert.equal('Foo bar baz', decrypted, 'OK');
		});
	});
	describe('crypto.encrypt.aes192()', () => {
		it('Encrypts/decrypts data with default settings', () => {
			const encrypted = crypto.encrypt.aes192('Foo bar baz', 'secretsauce');
			assert.equal(typeof encrypted, 'string',  'encrypt.aes192 returns string');
			const decrypted = crypto.decrypt.aes192(encrypted, 'secretsauce');
			assert.equal(typeof decrypted, 'string',  'decrypt.aes192 returns string');
			assert.equal('Foo bar baz', decrypted, 'OK');
		});
	});

	describe('crypto.hash', () => {
		it('Defaults to MD5', () => {
			const hash = crypto.hash('Foo bar baz');
			assert.equal(hash, '520c28a8ac3459af817a1abfb3bd152e');
		});
	});
	describe('crypto.md5sum', () => {
		it('Computes hash', () => {
			assert.equal(crypto.md5sum('Foo bar baz'), '520c28a8ac3459af817a1abfb3bd152e');
		});
	});
});
