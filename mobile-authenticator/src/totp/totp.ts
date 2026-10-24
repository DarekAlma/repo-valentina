// TOTP (RFC 6238) paso a paso, tal como lo pide la guía de laboratorio.
import { decodeBase32 } from './base32';
import { hmacSha1 } from './sha1';

export const PERIOD_SECONDS = 30;
export const DIGITS = 6;

/** Paso 2: C = floor(UnixTime / 30). */
export function timeCounter(unixSeconds: number): number {
  return Math.floor(unixSeconds / PERIOD_SECONDS);
}

/** Paso 3: C como entero de 8 bytes (64 bits) big-endian. */
export function counterToBytes(counter: number): Uint8Array {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, Math.floor(counter / 2 ** 32)); // 32 bits altos
  view.setUint32(4, counter >>> 0); // 32 bits bajos
  return bytes;
}

/** Pasos 4 y 5: HMAC-SHA1(K, C) + truncamiento dinámico. */
export function hotp(key: Uint8Array, counter: number, digits = DIGITS): string {
  const hash = hmacSha1(key, counterToBytes(counter)); // 20 bytes
  const offset = hash[19] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) | // sin bit de signo -> entero positivo de 31 bits
    (hash[offset + 1] << 16) |
    (hash[offset + 2] << 8) |
    hash[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** Paso 1 + todo lo anterior para el instante dado (por defecto, ahora). */
export function generateTotp(secretBase32: string, unixSeconds = Date.now() / 1000): string {
  return hotp(decodeBase32(secretBase32), timeCounter(unixSeconds));
}

export function secondsRemaining(unixSeconds = Date.now() / 1000): number {
  return PERIOD_SECONDS - (Math.floor(unixSeconds) % PERIOD_SECONDS);
}
