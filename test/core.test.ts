import { describe, expect, it } from 'vitest';
import {
  decodeTlv,
  decodeInteger,
  encodeInteger,
  decodeEnumerated,
  encodeEnumerated,
} from '../src/index.js';

it('decodes tlv', () =>
  expect(decodeTlv(Uint8Array.from([2, 1, 5])).value[0]).toBe(5));

const HUGE_POS = (1n << 200n) + 0x1234567890abcdefn;
const HUGE_NEG = -HUGE_POS;

// [contents octets, value] pairs in the unique shortest (DER) form.
const CANONICAL: [number[], bigint][] = [
  [[0xff], -1n],
  [[0x80], -128n],
  [[0xff, 0x7f], -129n],
  [[0xff, 0x00], -256n],
  [[0xff, 0x01], -255n],
  [[0x00], 0n],
  [[0x01], 1n],
  [[0x7f], 127n],
  [[0x00, 0x80], 128n],
  [[0x00, 0xff], 255n],
  [[0x01, 0x00], 256n],
];

describe('decodeInteger (two\'s complement)', () => {
  it.each(CANONICAL)('decodes %j as %s', (bytes, expected) => {
    expect(decodeInteger(Uint8Array.from(bytes))).toBe(expected);
  });

  it('decodes arbitrary-length magnitudes', () => {
    expect(decodeInteger(encodeInteger(HUGE_POS))).toBe(HUGE_POS);
    expect(decodeInteger(encodeInteger(HUGE_NEG))).toBe(HUGE_NEG);
  });

  it('rejects empty contents', () => {
    expect(() => decodeInteger(new Uint8Array(0))).toThrow(/at least one octet/);
    expect(() => decodeInteger(new Uint8Array(0), { der: true })).toThrow(/at least one octet/);
  });

  it('tolerates non-minimal sign extension outside DER mode', () => {
    expect(decodeInteger(Uint8Array.from([0x00, 0x7f]))).toBe(127n);
    expect(decodeInteger(Uint8Array.from([0x00, 0x00, 0x80]))).toBe(128n);
    expect(decodeInteger(Uint8Array.from([0xff, 0x80]))).toBe(-128n);
    expect(decodeInteger(Uint8Array.from([0xff, 0xff, 0x7f]))).toBe(-129n);
  });
});

describe('decodeInteger DER strictness', () => {
  it('rejects redundant leading 0x00', () => {
    expect(() => decodeInteger(Uint8Array.from([0x00, 0x7f]), { der: true }))
      .toThrow(/redundant leading 0x00/);
    expect(() => decodeInteger(Uint8Array.from([0x00, 0x00, 0x80]), { der: true }))
      .toThrow(/redundant leading 0x00/);
  });

  it('rejects redundant leading 0xff', () => {
    expect(() => decodeInteger(Uint8Array.from([0xff, 0x80]), { der: true }))
      .toThrow(/redundant leading 0xff/);
    expect(() => decodeInteger(Uint8Array.from([0xff, 0xff, 0x7f]), { der: true }))
      .toThrow(/redundant leading 0xff/);
  });

  it('accepts required sign octets', () => {
    expect(decodeInteger(Uint8Array.from([0x00, 0x80]), { der: true })).toBe(128n);
    expect(decodeInteger(Uint8Array.from([0xff, 0x7f]), { der: true })).toBe(-129n);
  });
});

describe('encodeInteger (unique shortest form)', () => {
  it.each(CANONICAL)('encodes value of %j', (bytes, value) => {
    expect([...encodeInteger(value)]).toEqual(bytes);
  });

  it('round-trips exactly', () => {
    const values = [
      -1n, -128n, -129n, 0n, 127n, 128n,
      -256n, -255n, 255n, 256n, 32767n, -32768n, -32769n,
      HUGE_POS, HUGE_NEG, -(1n << 8n), 1n << 8n,
    ];
    for (const v of values) {
      const encoded = encodeInteger(v);
      expect(decodeInteger(encoded), `round-trip ${v}`).toBe(v);
      expect(decodeInteger(encoded, { der: true }), `DER round-trip ${v}`).toBe(v);
    }
  });
});

describe('ENUMERATED', () => {
  const schema = { min: -129n, max: 255n };

  it('reuses integer encoding including sign handling', () => {
    expect([...encodeEnumerated(128n, schema)]).toEqual([0x00, 0x80]);
    expect([...encodeEnumerated(-129n, schema)]).toEqual([0xff, 0x7f]);
    expect(decodeEnumerated(Uint8Array.from([0x80]), schema)).toBe(-128n);
  });

  it('round-trips within the schema range', () => {
    for (const v of [-129n, -1n, 0n, 127n, 128n, 255n])
      expect(decodeEnumerated(encodeEnumerated(v, schema), schema)).toBe(v);
  });

  it('rejects values outside the schema range', () => {
    expect(() => encodeEnumerated(256n, schema)).toThrow(/outside schema range/);
    expect(() => encodeEnumerated(-130n, schema)).toThrow(/outside schema range/);
    expect(() => decodeEnumerated(Uint8Array.from([0x01, 0x00]), schema))
      .toThrow(/outside schema range/);
  });

  it('passes DER strictness through to the integer layer', () => {
    expect(() => decodeEnumerated(Uint8Array.from([0x00, 0x7f]), schema, { der: true }))
      .toThrow(/redundant leading 0x00/);
  });
});
