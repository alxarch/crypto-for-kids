'use strict';
const crypto = require('.');
const assert = require('assert');
describe('Crypto for kids module', () => {
	describe('crypto.hmac()', () => {
		it('Signs string data with default settings', () => {
			const msg = 'Foo bar baz'
			const secret = 'secretsauce'
			assert.equal(
					crypto.hmac(msg, {format: 'hex', secret: secret}),
					'cd9fc75345682c3df5160fa6b3db34f59340158ab0a26f521ebf0d39e2e857f9');
			assert.equal(
					crypto.hmac(msg, {format: 'base64', secret: secret}),
					'zZ/HU0VoLD31Fg+ms9s09ZNAFYqwom9SHr8NOeLoV/k=');
		});

		it('Signs buffer data with default settings', () => {
			const msg = new Buffer('Foo bar baz');
			const secret = 'secretsauce';
			assert.equal(
					crypto.hmac(msg, {format: 'hex', secret: secret}),
					'cd9fc75345682c3df5160fa6b3db34f59340158ab0a26f521ebf0d39e2e857f9');
			assert.equal(
					crypto.hmac(msg, {format: 'base64', secret: secret}),
					'zZ/HU0VoLD31Fg+ms9s09ZNAFYqwom9SHr8NOeLoV/k=');
		});
	});
});
