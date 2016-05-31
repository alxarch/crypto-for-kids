# crypto-for-kids

Node's `crypto` wrapper a child could use

## Hashing

### crypto.md5sum(data, [encoding])
### crypto.shasum(data, [encoding])
### crypto.sha1sum(data, [encoding])
### crypto.sha256sum(data, [encoding])
### crypto.sha384sum(data, [encoding])
### crypto.sha512sum(data, [encoding])

  - `data` <Buffer> or {String} with data to hash
  - encoding {String} output encoding (default: 'hex')

Returns a string with the hash of `data` using the corresponding algorithm (md5, sha, sha1, sha256, sha384, sha512sum)


## Signing

### crypto.hs256(data, secret, [encoding])
### crypto.hs384(data, secret, [encoding])
### crypto.hs512(data, secret, [encoding])
### crypto.rs256(data, privateKey, [encoding])
### crypto.rs384(data, privateKey, [encoding])
### crypto.rs512(data, privateKey, [encoding])

  - `data` <Buffer> or {String} with data to hash
  - `secret` <Buffer> or {String} with secret to use
  - `privateKey` <Buffer> or {String} or {Object} with private key to use
  - `encoding` {String} output encoding (default: 'hex')

Returns a signature for the data using either hmac or rsa signing
For `rsXXX` functions key can be an Object with passprhrase like in node's crypto module

## Encryption

### crypto.encrypt(data, secret, algorithm, [encoding])
### crypto.encrypt.aes192(data, secret, [encoding])
### crypto.encrypt.aes256(data, secret, [encoding])
### crypto.encrypt.aes512(data, secret, [encoding])

### crypto.decrypt(data, secret, algorithm, [encoding])

### crypto.decrypt.aes192(data, secret, [encoding])
### crypto.decrypt.aes256(data, secret, [encoding])
### crypto.decrypt.aes512(data, secret, [encoding])

### crypto.decrypt.hex(data, secret, algorithm, [encoding])
### crypto.decrypt.hex.aes192(data, secret, [encoding])
### crypto.decrypt.hex.aes256(data, secret, [encoding])
### crypto.decrypt.hex.aes512(data, secret, [encoding])

### crypto.decrypt.base64(data, secret, algorithm, [encoding])
### crypto.decrypt.base64.aes192(data, secret, [encoding])
### crypto.decrypt.base64.aes256(data, secret, [encoding])
### crypto.decrypt.base64.aes512(data, secret, [encoding])

