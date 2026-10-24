// Decodificador Base32 (RFC 4648), el formato del parámetro `secret`.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function normalizeBase32(input: string): string {
  return input.replace(/[\s=-]/g, '').toUpperCase();
}

export function decodeBase32(input: string): Uint8Array {
  const clean = normalizeBase32(input);
  if (clean.length === 0) throw new Error('El secreto está vacío');

  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of clean) {
    const value = ALPHABET.indexOf(char);
    if (value === -1) throw new Error(`Carácter Base32 inválido: "${char}"`);
    buffer = (buffer << 5) | value; // cada carácter aporta 5 bits
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 0xff);
    }
    buffer &= (1 << bits) - 1; // descartar los bits ya emitidos
  }
  return Uint8Array.from(bytes);
}
