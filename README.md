# node-tfa

<p align="center">
  <a href="https://www.npmjs.com/package/node-tfa" target="_blank"><img src="https://img.shields.io/npm/v/node-tfa.svg" alt="NPM Version"></a>
  <a href="https://www.npmjs.com/package/node-tfa" target="_blank"><img src="https://img.shields.io/npm/l/node-tfa.svg" alt="Package License"></a>
  <a href="https://www.npmjs.com/package/node-tfa" target="_blank"><img src="https://img.shields.io/npm/dm/node-tfa.svg" alt="NPM Downloads"></a>
</p>

## Installation

```bash
npm i node-tfa
```

## Usage

### Hotp

```ts
import Secret, { hotpGenerate, hotpVerify } from 'node-tfa';

const secret = new Secret({ label: 'USER_NAME', issuer: 'APP_NAME' })

const token = hotpGenerate({ secret: secret.base32, counter: 1 })

hotpVerify({ secret: secret.base32, counter: 1, token })
```

### Totp

```ts
import Secret, { totpGenerate, totpVerify } from 'node-tfa';

const secret = new Secret({ label: 'USER_NAME', issuer: 'APP_NAME' })

const token = totpGenerate({ secret: secret.base32 })

totpVerify({ secret: secret.base32, token })
```

### Google Authenticator

```ts
import Secret, { totpVerify } from 'node-tfa';

const secret = new Secret({ label: 'USER_NAME', issuer: 'APP_NAME', qr_code: true, type: 'totp' })

secret.qr_code

totpVerify({ secret: secret.base32, token: 'TOKEN_FROM_GOOGLE_AUTHENTICATOR' })
```
