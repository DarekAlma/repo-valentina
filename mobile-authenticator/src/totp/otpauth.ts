// Parser de URIs otpauth://totp/Issuer:cuenta?secret=...&issuer=...
import { decodeBase32, normalizeBase32 } from './base32';

export type ParsedOtpAuth = {
  secret: string;
  issuer: string;
  label: string;
};

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

export function parseOtpAuthUri(uri: string): ParsedOtpAuth {
  const match = /^otpauth:\/\/totp\/([^?]*)\?(.*)$/i.exec(uri.trim());
  if (!match) throw new Error('El QR no es una URI otpauth://totp/');

  const params: Record<string, string> = {};
  for (const pair of match[2].split('&')) {
    const [key, value = ''] = pair.split('=');
    if (key) params[key.toLowerCase()] = safeDecode(value);
  }

  if (params.algorithm && params.algorithm.toUpperCase() !== 'SHA1') {
    throw new Error(`Algoritmo no soportado: ${params.algorithm}`);
  }
  if (params.digits && params.digits !== '6') throw new Error('Solo se soportan códigos de 6 dígitos');
  if (params.period && params.period !== '30') throw new Error('Solo se soporta un periodo de 30 s');

  const secret = normalizeBase32(params.secret ?? '');
  decodeBase32(secret); // valida el secreto o lanza error

  const rawLabel = safeDecode(match[1]);
  const [labelIssuer, account] = rawLabel.includes(':') ? rawLabel.split(':', 2) : ['', rawLabel];
  return {
    secret,
    issuer: params.issuer || labelIssuer || 'Sin emisor',
    label: (account || rawLabel).trim(),
  };
}
