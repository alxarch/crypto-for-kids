'use strict';
const Crypto = require('.');
const assert = require('assert');
describe('Crypto for kids module', () => {
	['hex', 'buffer', 'base64'].forEach( encoding => {
		let crypto = Crypto[encoding];
		// describe( `tests crypto-for-kids hash in ${encoding}`, () => {
		// 	const data = 'Foo bar baz';
		// 	const expect = {
		// 		hex: {
		// 			md5: '520c28a8ac3459af817a1abfb3bd152e',
		// 			sha: '158c9ec82a0234ee5cb39f04ff593cf11384b733',
		// 			sha1: 'b861fddd3d1262c9102b69025accbf5fe887db2f',
		// 			sha224: 'f45cb9c6df9fdaa939322dd17d3ba74f72c90054d9c2cef0343f235d',
		// 			sha256: '4653841ef41adb4f201cc4e019409e5c2a8fce1fa88e22d6dbf6549e4965c9a1',
		// 			sha384: '807494c000f5c008b726a8cf88c1bd2a16629cea38a97f036d327ca1bc9fbf15430a81891c412c17ae0d8858b5419449',
		// 			sha512: 'c578847922fb6b92abcdc1c23d9d43cdf5e966fab8af8eb65a6055f753fd2693aa0ca7b06c7f71988732f57a6875552d4a0e2370cd01adcb0b70a725e8f919d6'
		// 		},
		// 		base64: {
		// 			md5: 'UgwoqKw0Wa+Behq/s70VLg==',
		// 			sha: 'FYyeyCoCNO5cs58E/1k88ROEtzM=',
		// 			sha1: 'uGH93T0SYskQK2kCWsy/X+iH2y8=',
		// 			sha224: '9Fy5xt+f2qk5Mi3RfTunT3LJAFTZws7wND8jXQ==',
		// 			sha256: 'RlOEHvQa208gHMTgGUCeXCqPzh+ojiLW2/ZUnkllyaE=',
		// 			sha384: 'gHSUwAD1wAi3JqjPiMG9KhZinOo4qX8DbTJ8obyfvxVDCoGJHEEsF64NiFi1QZRJ',
		// 			sha512: 'xXiEeSL7a5KrzcHCPZ1DzfXpZvq4r462WmBV91P9JpOqDKewbH9xmIcy9XpodVUtSg4jcM0BrcsLcKcl6PkZ1g=='
		// 		},
		// 		buffer: {
		// 			md5: new Buffer('UgwoqKw0Wa+Behq/s70VLg==', 'base64'),
		// 			sha: new Buffer('FYyeyCoCNO5cs58E/1k88ROEtzM=', 'base64'),
		// 			sha1: new Buffer('uGH93T0SYskQK2kCWsy/X+iH2y8=', 'base64'),
		// 			sha224: new Buffer('9Fy5xt+f2qk5Mi3RfTunT3LJAFTZws7wND8jXQ==', 'base64'),
		// 			sha256: new Buffer('RlOEHvQa208gHMTgGUCeXCqPzh+ojiLW2/ZUnkllyaE=', 'base64'),
		// 			sha384: new Buffer('gHSUwAD1wAi3JqjPiMG9KhZinOo4qX8DbTJ8obyfvxVDCoGJHEEsF64NiFi1QZRJ', 'base64'),
		// 			sha512: new Buffer('xXiEeSL7a5KrzcHCPZ1DzfXpZvq4r462WmBV91P9JpOqDKewbH9xmIcy9XpodVUtSg4jcM0BrcsLcKcl6PkZ1g==', 'base64')
		// 		}
		// 	};
		// 	['md5', 'sha', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'].forEach( alg => {
		// 		it(`test hash algorithm ${alg}`, () => {
		// 			const method = `${alg}sum`;
		// 			if  (encoding === 'buffer') {
		// 				assert.ok((crypto[method](data).compare(expect[encoding][alg])) === 0, 'Buffers not equal')
		// 			} else {
		// 				assert.equal(crypto[method](data), expect[encoding][alg], 'Not equal');
		// 			}
		// 		});
		// 	});
		// });
		describe( `tests crypto-for-kids hmac and sign methods in ${encoding}`, () => {
			const data = 'Foo bar baz';
			const secret = 'secretsauce';
			const expect = {
				hex: {
					hs256: 'cd9fc75345682c3df5160fa6b3db34f59340158ab0a26f521ebf0d39e2e857f9',
					hs384: '53a317119120f8353fd3feebb2adf5c0dab2894a1ca7368f746f0ce11d96f8d2464879261d2e9034f969ec73ef70f05e',
					hs512: '1a4ce2b1b331c7c506bbc293cf16b78772a8201e09e9dba4151e96c4cfab5e6160907925c6cfd9cc7282c78e0707eab38fa9aad94f826d72cd6f5395f2964ba2',

					rs256: '../data/private256',
					rs384: '../data/private384',
					rs512: '../data/private512'
				},
				base64: {
					hs256: 'zZ/HU0VoLD31Fg+ms9s09ZNAFYqwom9SHr8NOeLoV/k=',
					hs384: 'U6MXEZEg+DU/0/7rsq31wNqyiUocpzaPdG8M4R2W+NJGSHkmHS6QNPlp7HPvcPBe',
					hs512: 'GkzisbMxx8UGu8KTzxa3h3KoIB4J6dukFR6WxM+rXmFgkHklxs/ZzHKCx44HB+qzj6mq2U+CbXLNb1OV8pZLog==',

					rs256: '',
					rs384: '',
					rs512: ''
				},
				buffer: {
					hs256: new Buffer('zZ/HU0VoLD31Fg+ms9s09ZNAFYqwom9SHr8NOeLoV/k=', 'base64'),
					hs384: new Buffer('U6MXEZEg+DU/0/7rsq31wNqyiUocpzaPdG8M4R2W+NJGSHkmHS6QNPlp7HPvcPBe', 'base64'),
					hs512: new Buffer('GkzisbMxx8UGu8KTzxa3h3KoIB4J6dukFR6WxM+rXmFgkHklxs/ZzHKCx44HB+qzj6mq2U+CbXLNb1OV8pZLog==', 'base64'),

					rs256: '',
					rs384: '',
					rs512: ''
				},
				private_keys: {
					rs256: '../data/key256',
					rs384: '../data/key384',
					rs512: '../data/key512'
				},
				public_keys: {
					rs256: '../data/key256.pub',
					rs384: '../data/key384.pub',
					rs512: '../data/key512.pub'
				}
			};
			[256, 384, 512].forEach( bits => {
				// it(`tests hmac method in ${bits} bits`, () => {
				// 	const data = 'Foo bar baz';
				// 	const secret = 'secretsauce';
				// 	const hmac = `hs${bits}`;
				// 	console.log(crypto[hmac](data, secret));
				// 	if  (encoding === 'buffer') {
				// 		assert.ok((crypto[hmac](data).compare(expect[encoding][hmac])) === 0, 'Buffers not equal')
				// 	} else {
				// 		assert.equal(crypto[hmac](data, secret), expect[encoding][hmac], 'Not equal');
				// 	}
				// });
				it(`tests sign method in ${bits} bits`, () => {
					const data = 'Foo bar baz';
					const sign = `rs${bits}`;
					const key =  expect.private_keys[sign];
					console.log(crypto[sign](data, key));
					assert.ok(crypto[sign](data, key), 'Signature failed');
					});
			});
		});
		// describe( `tests crypto-for-kids encrypt and decrypt methods in ${encoding}`, () => {
		// 	const data = 'Foo bar baz';
		// 	const secret = 'secretsauce';
		// 	const expect = {
		// 		hex: {
		// 			aes128encrypt: '62e3025c27fd629e96e772a32eca5168',
		// 			aes192encrypt: '1ddc1ca875f717ccb5c654c1a05ba256',
		// 			aes256encrypt: 'e4fda48edad3ecd2a5c0e89c0087ac50'
		// 		},
		// 		base64: {
		// 			aes128encrypt: 'YuMCXCf9Yp6W53KjLspRaA==',
		// 			aes192encrypt: 'HdwcqHX3F8y1xlTBoFuiVg==',
		// 			aes256encrypt: '5P2kjtrT7NKlwOicAIesUA=='
		// 		},
		// 		buffer: {
		// 			aes128encrypt: new Buffer('YuMCXCf9Yp6W53KjLspRaA==', 'base64'),
		// 			aes192encrypt: new Buffer('HdwcqHX3F8y1xlTBoFuiVg==', 'base64'),
		// 			aes256encrypt: new Buffer('5P2kjtrT7NKlwOicAIesUA==', 'base64')
		// 		}
		// 	};
		// 	['aes128', 'aes192', 'aes256'].forEach( alg => {
		// 		it(`tests encrypt method with ${alg} algorithm`, () => {
		// 			const data = 'Foo bar baz';
		// 			const password = 'secretsauce';
		// 			const alg_enc = `${alg}encrypt`;
		// 			const encrypted = crypto[alg_enc](data, password);
		// 			console.log('encrypted', encrypted);
		// 			if  (encoding === 'buffer') {
		// 				assert.ok((encrypted.compare(expect[encoding][alg_enc])) === 0, 'Buffers not equal')
		// 			} else {
		// 				assert.equal(encrypted, expect[encoding][alg_enc], 'Not equal');
		// 			}
		// 		});
		// 		it(`tests decrypt methods with ${alg} algorithm`, () => {
		// 			const actual = 'Foo bar baz';
		// 			const password = 'secretsauce';
		// 			const alg_dec = `${alg}decrypt`;
		// 			const data = expect[encoding][`${alg}encrypt`];
		// 			const decrypted = crypto[alg_dec](data, password);
		// 			console.log('decrypted', decrypted);
		// 			assert.equal(decrypted, actual, 'Not equal');
		// 		});
		// 	});
		// });
	});
});
