import Secret, { hotpGenerate, hotpVerify, totpGenerate, totpVerify } from '../index';

/**
 * Hotp
 */

const hotp_secret = new Secret({ label: 'USER_NAME', issuer: 'APP_NAME' })

console.log('hotp_secret', hotp_secret.base32)

const hotp_token = hotpGenerate({ secret: hotp_secret.base32, counter: 1 })

const hotp_res = hotpVerify({ secret: hotp_secret.base32, counter: 1, token: hotp_token })

console.log('hotp_res', hotp_res)

/**
 * Totp
 */

const totp_secret = new Secret({ label: 'USER_NAME', issuer: 'APP_NAME' })

console.log('totp_secret', totp_secret.base32)

const totp_token = totpGenerate({ secret: totp_secret.base32 })

const totp_res = totpVerify({ secret: totp_secret.base32, token: totp_token })

console.log('totp_res', totp_res)

/**
 * Google Authenticator
 */

const ga_totp_secret = new Secret({ label: 'USER_NAME', issuer: 'APP_NAME', qr_code: true, type: 'totp' })

console.log('ga_totp_secret', ga_totp_secret.base32)
console.log('ga_totp_secret - qr_code', ga_totp_secret.qr_code)
