# ASN.1 DER core

TypeScript library for DER encoding and decoding.

Run `npm install`, then `npm test` and `npm run build`.

## INTEGER / ENUMERATED

Content octets are two's complement, decoded to exact `bigint` of any size:

```ts
import { decodeInteger, encodeInteger, encodeEnumerated, decodeEnumerated } from 'asn1-integer-sign-core';

decodeInteger(Uint8Array.from([0x80]));        // -128n
encodeInteger(128n);                            // [0x00, 0x80] (0x00 prefix keeps it positive)
encodeInteger(-129n);                           // [0xff, 0x7f]
```

- `decodeInteger(bytes, { der: false })` — BER-tolerant mode; the DER default
  rejects non-minimal sign extension (redundant leading `0x00`/`0xff`) and
  empty content (X.690 §8.3).
- `encodeInteger` always emits the unique shortest form.
- `encodeEnumerated` / `decodeEnumerated` reuse the integer codec but validate
  against the type's own schema: `{ min, max }` and/or `{ values: [...] }`.
- `TAG_INTEGER` (0x02) / `TAG_ENUMERATED` (0x0a) and `encodeTlv`/`decodeTlv`
  handle the TLV wrapper (short-form lengths).
