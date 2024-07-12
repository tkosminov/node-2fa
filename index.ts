import { encode, decode } from 'hi-base32';
import { format } from 'url';
import { createHmac } from 'crypto';
import { nanoid } from 'nanoid';

const defaultOptions = {
  counter: 0, // Authenticate attempt
  algorithm: 'SHA1',
  digits: 6, // Token length
  period: 30, // Token life time
  encoding: 'base32'
};

type TAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';
type TEncoding = 'ascii' | 'hex' | 'base32';
type TType = 'totp' | 'hotp';

interface IHmacDigest {
  algorithm?: TAlgorithm;
  encoding?: TEncoding;
  counter?: number;
}

type THmacDigest = IHmacDigest & { secret: string; };

interface IHotp {
  digits?: number;
}

type THotp = THmacDigest & IHotp;
type TTotp = Omit<THotp, 'counter'>;

interface IHotpVerefy {
  token: string;
}

type THotpVerify = THotp & IHotpVerefy;
type TTotpVerify = Omit<THotpVerify, 'counter'>;

interface IOtpauthURLOptions {
  type: TType;
  period: number;
}

type TOtpauthURLOptions = IOtpauthURLOptions & IHotp & Omit<THmacDigest, 'encoding' | 'secret'>;

interface ISecretOptions {
  label?: string; // User name in authenticator
  issuer?: string; // App name in authenticator
  qr_code?: boolean; // Generate qr_code for authenticator?
  symbols?: boolean; // Use special symbols in secret key?
}

type TSecretOptions = ISecretOptions & Partial<TOtpauthURLOptions>

type TOtpauthURLQuery = Omit<TSecretOptions, 'type'> & { secret: string; }

class Secret {
  public ascii: string;
  public hex: string;
  public base32: string;

  public qr_code?: string;

  private qr_code_url: string = 'https://api.qrserver.com/v1/create-qr-code/?size=166x166&data=';
  private label: string = '2FA_Test';
  private issuer: string = '2FA_Test';

  constructor(options?: TSecretOptions) {
    this.ascii = nanoid(32);
    this.hex = Buffer.from(this.ascii, 'ascii').toString('hex');
    this.base32 = encode(Buffer.from(this.ascii)).toString().replace(/=/g, '');

    if (options) {
      if (options.label) {
        this.label = options.label;
      }

      if (options.issuer) {
        this.issuer = options.issuer;
      }

      if (options.qr_code) {
        const otpauthURL = this.otpauthURL({ ...options } as TOtpauthURLOptions)
        this.qr_code = `${this.qr_code_url}${encodeURIComponent(otpauthURL)}`;
      }
    }
  }

  private otpauthURL(options: TOtpauthURLOptions) {
    const data = { ...defaultOptions, ...options } as TOtpauthURLOptions;

    if (!data.type) {
      throw new Error('Type must be `hotp` or `totp`')
    }

    if (data.type === 'hotp' && !data.counter) {
      throw new Error('Missing counter value for HOTP')
    }

    const query: TOtpauthURLQuery = {
      secret: this.base32,
      issuer: this.issuer,
      algorithm: data.algorithm,
      digits: data.digits,
      period: data.period,
    }

    if (data.type === 'hotp') {
      query.counter = data.counter;
    }

    return format({
      protocol: 'otpauth',
      slashes: true,
      hostname: data.type,
      pathname: encodeURIComponent(this.label),
      query,
    })
  }
}

const hmacDigest = function(options: THmacDigest) {
  const data = { ...defaultOptions, ...options } as THmacDigest;

  if (!Buffer.isBuffer(data.secret)) {
    if (data.encoding === 'base32') {
      data.secret = decode(data.secret);
    }
  }

  let buf = Buffer.alloc(8);
  let tmp = data.counter;

  for (let i = 0; i < 8; i++) {
    buf[7 - i] = tmp & 0xff;
    tmp = tmp >> 8;
  }

  let hmac = createHmac(data.algorithm, data.secret);

  hmac.update(buf);

  return hmac.digest();
}

/**
 * Generate password \
 * https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_algorithm
 */
export const hotpGenerate = function(options: THotp) {
  const data = { ...defaultOptions, ...options } as THotp;

  if (!data.secret) {
    throw new Error('Secret must exist');
  }

  let digest = hmacDigest(options)

  let offset = digest[digest.length - 1] & 0xf;

  const code = (digest[offset] & 0x7f) << 24 |
    (digest[offset + 1] & 0xff) << 16 |
    (digest[offset + 2] & 0xff) << 8 |
    (digest[offset + 3] & 0xff);

  const codeString = new Array(data.digits + 1).join('0') + code.toString(10);

  return codeString.substr(-data.digits);
}

/**
 * Verify password
 */
export const hotpVerify = function(options: THotpVerify) {
  const data = { ...defaultOptions, ...options} as THotpVerify;

  if (!data.secret) {
    throw new Error('Secret must exist')
  }

  if (!data.token) {
    throw new Error('Token must exist')
  }

  if (data.token.length != data.digits) {
    return false;
  }

  const tokenNum = parseInt(data.token, 10)

  if (isNaN(tokenNum)) {
    return false;
  }

  if (parseInt(hotpGenerate(data), 10) === tokenNum) {
    return true;
  }

  return false;
}

function totpCounter(period: number) {
  const time = Date.now();

  return Math.floor(time / period / 1000);
}

/**
 * Generate password \
 * https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm
 */
export const totpGenerate = function(options: TTotp) {
  const data: THotp = { ...options }

  data.counter = totpCounter(defaultOptions.period);

  return hotpGenerate(data);
}

/**
 * Verify password
 */
export const totpVerify = function(options: TTotpVerify) {
  const data: THotpVerify = { ...options }

  data.counter = totpCounter(defaultOptions.period);

  return hotpVerify(data);
}

export default Secret;
