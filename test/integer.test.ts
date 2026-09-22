import { describe, expect, it } from 'vitest';
import {
  decodeEnumerated,
  decodeInteger,
  decodeTlv,
  encodeEnumerated,
  encodeInteger,
  encodeTlv,
  TAG_ENUMERATED,
  TAG_INTEGER,
} from '../src/index.js';

const hex = (s: string): Uint8Array =>
  Uint8Array.from(s.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array): string =>
  [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

// value -> unique shortest DER content octets
const vectors: Array<[bigint, string]> = [
  [0n, '00'],
  [1n, '01'],
  [127n, '7f'],
  [128n, '0080'],
  [255n, '00ff'],
  [256n, '0100'],
  [-1n, 'ff'],
  [-2n, 'fe'],
  [-128n, '80'],
  [-129n, 'ff7f'],
  [-255n, 'ff01'],
  [-256n, 'ff00'],
  [-257n, 'feff'],
  [32767n, '7fff'],
  [32768n, '008000'],
  [-32768n, '8000'],
  [-32769n, 'ff7fff'],
];

const hugePos = 1n << 255n; // 32 bytes, high bit set -> needs 0x00 prefix
const hugeNeg = -(1n << 255n) - 1n;
const hugeNegPow2 = -(1n << 256n); // exact power of two, negative

describe('decodeInteger (two\'s complement)', () => {
  it.each(vectors)('decodes %s from %s', (value, h) => {
    expect(decodeInteger(hex(h))).toBe(value);
  });

  it('decodes 0x80 as -128, not 128 (original bug)', () => {
    expect(decodeInteger(hex('80'))).toBe(-128n);
  });

  it('decodes huge positive and negative values exactly', () => {
    expect(decodeInteger(encodeInteger(hugePos))).toBe(hugePos);
    expect(decodeInteger(encodeInteger(hugeNeg))).toBe(hugeNeg);
    expect(decodeInteger(encodeInteger(hugeNegPow2))).toBe(hugeNegPow2);
  });

  it('rejects empty payload in both modes', () => {
    expect(() => decodeInteger(new Uint8Array(0))).toThrow(/empty/);
    expect(() => decodeInteger(new Uint8Array(0), { der: false })).toThrow(/empty/);
  });
});

describe('DER minimal-form enforcement', () => {
  it.each(['007f', '0001', '000080', 'ffff', 'ff80', 'ffffffff'])(
    'rejects non-minimal %s in DER mode (default)',
    (h) => {
      expect(() => decodeInteger(hex(h))).toThrow(/non-minimal/);
      expect(() => decodeInteger(hex(h), { der: true })).toThrow(/non-minimal/);
    },
  );

  it.each([
    ['007f', 127n],
    ['0001', 1n],
    ['ffff', -1n],
    ['ff80', -128n],
    ['00000001', 1n],
    ['ffffffff', -1n],
  ])('accepts %s as %s in BER mode', (h, value) => {
    expect(decodeInteger(hex(h), { der: false })).toBe(value);
  });

  it.each(['0080', '00ff', 'ff7f', 'ff00', '8000'])(
    'does not reject minimal boundary form %s',
    (h) => {
      expect(() => decodeInteger(hex(h))).not.toThrow();
    },
  );
});

describe('encodeInteger (unique shortest form)', () => {
  it.each(vectors)('encodes %s to %s', (value, h) => {
    expect(toHex(encodeInteger(value))).toBe(h);
  });

  it('prefixes 0x00 for positive values with the high bit set', () => {
    expect(toHex(encodeInteger(128n))).toBe('0080');
    expect(toHex(encodeInteger(hugePos))).toBe(
      '00' + '80' + '00'.repeat(31),
    );
  });

  it('produces minimal sign extension for negatives', () => {
    expect(toHex(encodeInteger(-129n))).toBe('ff7f');
    // -2^255 fits exactly in 32 bytes; -2^256 needs a 33rd 0xff byte
    expect(toHex(encodeInteger(-(1n << 255n)))).toBe('80' + '00'.repeat(31));
    expect(toHex(encodeInteger(hugeNegPow2))).toBe('ff' + '00'.repeat(32));
  });
});

describe('round-trip', () => {
  it.each(vectors)('round-trips %s exactly', (value) => {
    expect(decodeInteger(encodeInteger(value))).toBe(value);
  });

  it('round-trips huge values exactly', () => {
    for (const v of [hugePos, hugeNeg, hugeNegPow2, (1n << 4096n) - 1n, -((1n << 4096n) - 1n)])
      expect(decodeInteger(encodeInteger(v))).toBe(v);
  });

  it('round-trips pseudo-random bigints and stays minimal', () => {
    let state = 0x123456789abcdefn;
    const next = () =>
      (state = (state * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n));
    for (let i = 0; i < 500; i++) {
      const byteLen = 1 + Number(next() % 64n);
      let v = 0n;
      for (let j = 0; j < byteLen; j++) v = (v << 8n) | (next() & 0xffn);
      if (next() & 1n) v = -v;
      const enc = encodeInteger(v);
      expect(decodeInteger(enc)).toBe(v); // exact value
      expect(() => decodeInteger(enc, { der: true })).not.toThrow(); // DER-minimal
      expect(encodeInteger(decodeInteger(enc))).toEqual(enc); // canonical
    }
  });

  it('round-trips through TLV with the INTEGER tag', () => {
    for (const v of [0n, -1n, 128n, -129n, hugePos, hugeNeg]) {
      const tlv = decodeTlv(encodeTlv(TAG_INTEGER, encodeInteger(v)));
      expect(tlv.tag).toBe(TAG_INTEGER);
      expect(decodeInteger(tlv.value)).toBe(v);
    }
  });
});

describe('ENUMERATED', () => {
  const colorSchema = { min: 0n, max: 2n }; // red=0 green=1 blue=2
  const statusSchema = { values: [1n, 2n, 3n, 5n, 8n] };

  it('reuses integer content encoding', () => {
    expect(encodeEnumerated(2n, colorSchema)).toEqual(encodeInteger(2n));
    expect(toHex(encodeEnumerated(200n, { min: 0n, max: 255n }))).toBe('00c8');
  });

  it('round-trips within schema range', () => {
    for (const v of [0n, 1n, 2n])
      expect(decodeEnumerated(encodeEnumerated(v, colorSchema), colorSchema)).toBe(v);
  });

  it('applies its own schema range on encode and decode', () => {
    expect(() => encodeEnumerated(3n, colorSchema)).toThrow(/above schema max/);
    expect(() => encodeEnumerated(-1n, colorSchema)).toThrow(/below schema min/);
    expect(() => decodeEnumerated(encodeInteger(3n), colorSchema)).toThrow(/above schema max/);
    expect(() => decodeEnumerated(encodeInteger(4n), statusSchema)).toThrow(/not in schema/);
    expect(decodeEnumerated(encodeInteger(5n), statusSchema)).toBe(5n);
  });

  it('schemas are independent per type', () => {
    const bytes = encodeInteger(3n);
    expect(() => decodeEnumerated(bytes, colorSchema)).toThrow();
    expect(decodeEnumerated(bytes, statusSchema)).toBe(3n);
  });

  it('decodes from a TLV with the ENUMERATED tag', () => {
    const tlv = decodeTlv(encodeTlv(TAG_ENUMERATED, encodeEnumerated(1n, colorSchema)));
    expect(tlv.tag).toBe(TAG_ENUMERATED);
    expect(decodeEnumerated(tlv.value, colorSchema)).toBe(1n);
  });

  it('enforces DER minimal form for enumerated content too', () => {
    expect(() => decodeEnumerated(hex('0001'), colorSchema)).toThrow(/non-minimal/);
  });
});
