export type Tlv = { tag: number; length: number; value: Uint8Array };

export const TAG_INTEGER = 0x02;
export const TAG_ENUMERATED = 0x0a;

export function decodeTlv(data: Uint8Array): Tlv {
  if (data.length < 2) throw new Error('truncated');
  const tag = data[0], length = data[1];
  if (length & 128) throw new Error('long length unsupported');
  if (data.length < 2 + length) throw new Error('truncated');
  return { tag, length, value: data.slice(2, 2 + length) };
}

export function encodeTlv(tag: number, value: Uint8Array): Uint8Array {
  if (value.length >= 128) throw new Error('long length unsupported');
  return Uint8Array.from([tag, value.length, ...value]);
}

export interface IntegerDecodeOptions {
  /**
   * DER (default) rejects non-minimal sign extension per X.690 §8.3.2.
   * Pass { der: false } for BER-tolerant decoding.
   */
  der?: boolean;
}

/**
 * Decode INTEGER/ENUMERATED content octets as two's complement into an
 * exact bigint of arbitrary magnitude.
 */
export function decodeInteger(bytes: Uint8Array, options: IntegerDecodeOptions = {}): bigint {
  const der = options.der ?? true;
  if (bytes.length === 0) throw new Error('INTEGER content is empty');
  if (der && bytes.length > 1) {
    const first = bytes[0], second = bytes[1];
    // Redundant when the first 9 bits are all 0 or all 1 (X.690 §8.3.2).
    if (first === 0x00 && (second & 0x80) === 0)
      throw new Error('non-minimal INTEGER: redundant leading 0x00');
    if (first === 0xff && (second & 0x80) !== 0)
      throw new Error('non-minimal INTEGER: redundant leading 0xff');
  }
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  // Negative: subtract 2^(8n) to undo the two's-complement offset.
  if (bytes[0] & 0x80) value -= 1n << BigInt(bytes.length * 8);
  return value;
}

/**
 * Encode a bigint as the unique shortest two's-complement form (DER):
 * no redundant leading 0x00/0xff, positive values with the high bit set
 * get a 0x00 prefix, negative values are sign-extended with 0xff only
 * as far as needed.
 */
export function encodeInteger(value: bigint): Uint8Array {
  if (value === 0n) return Uint8Array.of(0x00);
  const negative = value < 0n;
  // Minimal big-endian magnitude of (negative ? ~value : value); for
  // negatives, inverting the bits of ~value yields value directly.
  let v = negative ? ~value : value;
  const bytes: number[] = [];
  while (v > 0n) {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  if (bytes.length === 0) bytes.push(0x00); // value === -1
  if (negative) {
    for (let i = 0; i < bytes.length; i++) bytes[i] ^= 0xff;
    if ((bytes[0] & 0x80) === 0) bytes.unshift(0xff);
  } else if (bytes[0] & 0x80) {
    bytes.unshift(0x00);
  }
  return Uint8Array.from(bytes);
}

/** Per-type allowed range for an ENUMERATED, independent of INTEGER. */
export interface EnumeratedSchema {
  readonly min?: bigint;
  readonly max?: bigint;
  readonly values?: readonly bigint[];
}

function checkEnumeratedRange(value: bigint, schema: EnumeratedSchema): void {
  if (schema.values && !schema.values.includes(value))
    throw new Error(`ENUMERATED value ${value} not in schema values`);
  if (schema.min !== undefined && value < schema.min)
    throw new Error(`ENUMERATED value ${value} below schema min ${schema.min}`);
  if (schema.max !== undefined && value > schema.max)
    throw new Error(`ENUMERATED value ${value} above schema max ${schema.max}`);
}

/** Same content encoding as INTEGER, validated against the type's own schema. */
export function encodeEnumerated(value: bigint, schema: EnumeratedSchema = {}): Uint8Array {
  checkEnumeratedRange(value, schema);
  return encodeInteger(value);
}

export function decodeEnumerated(
  bytes: Uint8Array,
  schema: EnumeratedSchema = {},
  options: IntegerDecodeOptions = {},
): bigint {
  const value = decodeInteger(bytes, options);
  checkEnumeratedRange(value, schema);
  return value;
}
