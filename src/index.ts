export type Tlv = { tag: number; length: number; value: Uint8Array };

export function decodeTlv(data: Uint8Array): Tlv {
  if (data.length < 2) throw new Error('truncated');
  const tag = data[0], length = data[1];
  if (length & 128) throw new Error('long length unsupported');
  if (data.length < 2 + length) throw new Error('truncated');
  return { tag, length, value: data.slice(2, 2 + length) };
}

export const TAG_INTEGER = 0x02;
export const TAG_ENUMERATED = 0x0a;

export interface IntegerDecodeOptions {
  /** Enforce DER: reject non-minimal two's-complement contents (X.690 8.3.2). */
  der?: boolean;
}

/**
 * Decode INTEGER contents octets as two's-complement bigint of any length.
 * The top bit of the first octet is the sign bit.
 */
export function decodeInteger(bytes: Uint8Array, opts: IntegerDecodeOptions = {}): bigint {
  if (bytes.length === 0) throw new Error('INTEGER contents must be at least one octet');
  if (opts.der && bytes.length > 1) {
    // First 9 bits all 0 or all 1 means a redundant sign-extension octet.
    if (bytes[0] === 0x00 && bytes[1] < 0x80)
      throw new Error('non-minimal INTEGER: redundant leading 0x00');
    if (bytes[0] === 0xff && bytes[1] >= 0x80)
      throw new Error('non-minimal INTEGER: redundant leading 0xff');
  }
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  if (bytes[0] & 0x80) value -= 1n << BigInt(bytes.length * 8);
  return value;
}

/**
 * Encode a bigint as INTEGER contents octets in the unique shortest
 * two's-complement form required by DER.
 */
export function encodeInteger(value: bigint): Uint8Array {
  const out: number[] = [];
  let v = value;
  // Bigint shifts are arithmetic, so v converges to 0 (positive) or -1 (negative).
  do {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  } while (v !== 0n && v !== -1n);
  // Add a sign octet only when the top byte's sign bit would be misread.
  if (v === 0n && (out[0] & 0x80)) out.unshift(0x00);
  else if (v === -1n && !(out[0] & 0x80)) out.unshift(0xff);
  return Uint8Array.from(out);
}

export interface EnumeratedSchema {
  min: bigint;
  max: bigint;
}

function checkRange(value: bigint, schema: EnumeratedSchema): void {
  if (value < schema.min || value > schema.max)
    throw new Error(`ENUMERATED value ${value} outside schema range [${schema.min}, ${schema.max}]`);
}

/** ENUMERATED reuses the INTEGER wire encoding but validates against its own schema. */
export function decodeEnumerated(
  bytes: Uint8Array,
  schema: EnumeratedSchema,
  opts: IntegerDecodeOptions = {},
): bigint {
  const value = decodeInteger(bytes, opts);
  checkRange(value, schema);
  return value;
}

export function encodeEnumerated(value: bigint, schema: EnumeratedSchema): Uint8Array {
  checkRange(value, schema);
  return encodeInteger(value);
}
