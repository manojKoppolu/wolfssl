# LMS/HSS key and signature sizes (wolfSSL native implementation)

Notes for the parameters used by `lmscertgen.c`:

```
levels     (l)  = 1
height     (h)  = 10
winternitz (w)  = 8
hash       (H)  = SHA-256  ->  hLen = 32 bytes
```

## hLen

`hLen` is the output length, in bytes, of the underlying hash function
(`n` in RFC 8554 notation). Every hash chain value, tree node, and the
root are all `hLen` bytes wide. It comes from which LMS/LM-OTS type pair
is selected:

| Hash family      | hLen |
|------------------|------|
| SHA-256/256      | 32   |
| SHA-256/192      | 24   |
| SHAKE256/256     | 32   |
| SHAKE256/192     | 24   |

This build only has SHA-256/256 compiled in (default). SHA-256/192 and
SHAKE256 variants require `WOLFSSL_LMS_SHA256_192` / `WOLFSSL_LMS_SHAKE256`.

## LMS tree types (`lmsType`) and LM-OTS types (`lmOtsType`)

Defined in `wolfssl/wolfcrypt/wc_lms.h`. High bits are an internal-only
wolfSSL "hash family" flag (masked out by `LMS_H_W_MASK` before touching
the wire format); low bits are the RFC-registered numeric type code.

LMS tree type (height variant), by hash family:

| Hash family     | H5 | H10 | H15 | H20 | H25 |
|-----------------|----|-----|-----|-----|-----|
| SHA-256/256     | `LMS_SHA256_M32_H5` (0x05) | `LMS_SHA256_M32_H10` (0x06) | `LMS_SHA256_M32_H15` (0x07) | `LMS_SHA256_M32_H20` (0x08) | `LMS_SHA256_M32_H25` (0x09) |
| SHA-256/192     | `LMS_SHA256_M24_H5` | `LMS_SHA256_M24_H10` | `LMS_SHA256_M24_H15` | `LMS_SHA256_M24_H20` | `LMS_SHA256_M24_H25` |
| SHAKE256/256    | `LMS_SHAKE_M32_H5` | `LMS_SHAKE_M32_H10` | `LMS_SHAKE_M32_H15` | `LMS_SHAKE_M32_H20` | `LMS_SHAKE_M32_H25` |
| SHAKE256/192    | `LMS_SHAKE_M24_H5` | `LMS_SHAKE_M24_H10` | `LMS_SHAKE_M24_H15` | `LMS_SHAKE_M24_H20` | `LMS_SHAKE_M24_H25` |

This project uses `LMS_SHA256_M32_H10` (height=10).

LM-OTS type (Winternitz width variant), by hash family:

| Hash family     | W1 | W2 | W4 | W8 |
|-----------------|----|----|----|----|
| SHA-256/256     | `LMOTS_SHA256_N32_W1` (0x01) | `LMOTS_SHA256_N32_W2` (0x02) | `LMOTS_SHA256_N32_W4` (0x03) | `LMOTS_SHA256_N32_W8` (0x04) |
| SHA-256/192     | `LMOTS_SHA256_N24_W1` | `LMOTS_SHA256_N24_W2` | `LMOTS_SHA256_N24_W4` | `LMOTS_SHA256_N24_W8` |
| SHAKE256/256    | `LMOTS_SHAKE_N32_W1` | `LMOTS_SHAKE_N32_W2` | `LMOTS_SHAKE_N32_W4` | `LMOTS_SHAKE_N32_W8` |
| SHAKE256/192    | `LMOTS_SHAKE_N24_W1` | `LMOTS_SHAKE_N24_W2` | `LMOTS_SHAKE_N24_W4` | `LMOTS_SHAKE_N24_W8` |

This project uses `LMOTS_SHA256_N32_W8` (winternitz=8).

`W` = bits of hash consumed per Winternitz chain "digit":
- `W1` -> longest chains, smallest signature, slowest sign/verify.
- `W8` -> shortest chains, fastest sign/verify, largest signature.

## Public key - 60 bytes

RFC 8554 sec 3.3 / 6.1 format: `u32str(L) || pub[0]`, where
`pub[0] = u32str(lmsType) || u32str(lmOtsType) || I || T[1]`.

| Field      | Size (bytes)        | Meaning                                  |
|------------|---------------------|-------------------------------------------|
| `L`        | `LMS_L_LEN` = 4     | Number of HSS levels (1)                  |
| `lmsType`  | `LMS_TYPE_LEN` = 4  | LMS tree variant                          |
| `lmOtsType`| `LMS_TYPE_LEN` = 4  | LM-OTS Winternitz variant                 |
| `I`        | `LMS_I_LEN` = 16    | Tree identifier                           |
| `T[1]`     | `hLen` = 32         | Merkle tree root                          |
| **Total**  | **60**              |                                            |

Doesn't change with `levels` (public key is always for the top-level
tree only) or `height`/`winternitz` (only the root hash size, driven by
`hLen`, matters here).

## Private key (persisted state) - 64 bytes

`PRIV = Q || PARAMS || SEED || I` (see `wc_lms.c`/`wc_lms.h`).
This is a *seed-based* private key (RFC 8554 Appendix A): it stores just
enough to deterministically regenerate every one-time key on demand, not
the one-time keys themselves.

| Field    | Size (bytes)                       | Meaning                                    |
|----------|-------------------------------------|---------------------------------------------|
| `Q`      | `HSS_Q_LEN` = 8                    | Current leaf index (64-bit, across all levels) |
| `PARAMS` | `HSS_PRIV_KEY_PARAM_SET_LEN` = 8    | 1 byte per level (up to `HSS_MAX_LEVELS`=8), see below |
| `SEED`   | `hLen` = 32                         | Master secret; every `x_q[i]` is derived from this |
| `I`      | `LMS_I_LEN` = 16                    | Tree identifier (same value as in public key) |
| **Total**| **64**                              |                                              |

Size does NOT depend on `levels`/`height`/`winternitz` at all (that's the
whole point of the seed-based design) - only `hLen` changes it
(SHA-256/192 -> 56 bytes instead of 64).

### PARAMS field detail

One byte per possible HSS level (`wc_hss_make_key()` in `wc_lms_impl.c`):

```c
p[i] = (byte)(((params->lmsType & LMS_H_W_MASK) << 4) +
              (params->lmOtsType & LMS_H_W_MASK));   /* per used level */
p[i] = 0xff;                                          /* per unused level */
```

- Upper nibble = low 4 bits of `lmsType`, lower nibble = low 4 bits of
  `lmOtsType`. This is a lossy/low-fidelity tag (`LMS_H_W_MASK` is
  actually 12 bits, truncated to a nibble here) - nothing in wolfSSL
  actually reads it back to reconstruct parameters; the caller must
  already know and re-supply params via `wc_LmsKey_SetParameters()`
  before `wc_LmsKey_Reload()`. Looks like a vestige of the RFC-style HSS
  private key layout more than something actively consumed.
- For this project (levels=1): byte 0 = `0x64` (`lmsType`=6, `lmOtsType`=4
  in the low nibbles), bytes 1-7 = `0xff` (unused levels 2-8).

Observed on disk (`lms_priv.key`, 64 bytes):
```
00000000: 0000 0000 0000 0001 64ff ffff ffff ffff   Q(8) + PARAMS(8)
00000010: a784 09ba d8a5 ac47 624e 80e4 e598 f3d8   SEED bytes 0-15
00000020: 6f14 f9ca 0b66 9a05 ad71 05f5 6ad2 a4a6   SEED bytes 16-31
00000030: 95c5 7533 4822 09c8 ecda d128 a5cb b323   I (16 bytes)
```
`Q = 1` here means leaf `q=0` was already consumed (one signature made);
the key is ready to sign again with `q=1` on next use.

## Signature - 1456 bytes

```c
#define LMS_PARAMS_SIG_LEN(l, h, p, hLen) \
    (4 + (l) * (4 + 4 + 4 + (hLen) * (1 + (p) + (h))) + \
     ((l) - 1) * LMS_PUBKEY_LEN(hLen))
```

`p` (number of Winternitz chain elements) from RFC 8554 Appendix B:
```c
p = LMS_U(w, hLen) + LMS_V(w, wb)     /* w=8, wb=3, hLen=32 -> p = 32+2 = 34 */
```

| Component                                            | Bytes |
|-------------------------------------------------------|-------|
| `Nspk` (number of signed public keys, = `levels - 1`) | 4     |
| `q` (leaf index used for this signature)              | 4     |
| LM-OTS type                                            | 4     |
| LMS type                                               | 4     |
| OTS randomizer `C`  (`hLen` x 1)                       | 32    |
| Winternitz chain values (`hLen` x `p`=34)              | 1088  |
| Authentication path (`hLen` x `h`=10)                  | 320   |
| Signed sub-tree public keys (`(levels-1)` x pubkey_len)| 0     |
| **Total**                                              | **1456** |

### Nspk (number of signed public keys)

`Nspk = levels - 1`, NOT `levels`. Only the bottom HSS tree signs the
actual message; every level above it signs the public key of the level
below, chaining trust down to the root (which becomes the cert's public
key). With `levels=1` there's nothing above the single tree, so `Nspk=0`
and it signs the message directly.

```
Level 0 (top, root = cert's public key)
   | signs pubkey of ->
Level 1
   | signs pubkey of ->
   ...
Level L-1 (bottom)
   | signs -> your actual message
```

### HSS wire format vs bare RFC 8554 sec 4.5 LMS signature

RFC 8554 defines two distinct signature formats:

- **sec 4.5 - LMS signature**: `u32str(q) || ots_signature ||
  u32str(type) || path[0..h-1]`. No `Nspk`, no signed public keys - the
  signature of a single, standalone LMS tree.
- **sec 6.2 - HSS signature**: `u32str(Nspk) || signed_pub_key[0] ||
  ... || signed_pub_key[Nspk-1] || sig[Nspk]`, where `sig[Nspk]` is a
  sec-4.5-format LMS signature for the bottom tree.

wolfSSL does not implement sec 4.5 as a separate, standalone wire
format. `wc_LmsKey_Sign()`/`wc_LmsKey_Verify()` always route through
`wc_hss_sign()`/`wc_hss_verify()`, i.e. "HSS with a configurable `L`" -
`levels=1` is just the degenerate case where `Nspk=0` and there are no
signed sub-tree public keys, not a different code path. Confirmed in
`wc_hss_sign()` (`wc_lms_impl.c`):

```c
/* Set number of signed public keys. */
c32toa((word32)(params->levels - 1), sig);   /* unconditional - no
                                                 "if levels > 1" guard */
sig += params->sig_len;
```

So the `Nspk` *field* (4 bytes) is always present in wolfSSL's output,
even for `levels=1` - only its *payload* (the `(levels-1)` signed
sub-tree public keys) shrinks to 0 bytes. The 1456-byte total above
already includes that 4-byte `Nspk=0`. There is no wolfSSL API to
obtain a smaller, bare sec-4.5-only signature (1452 bytes, without the
Nspk field) - if some other library needed that exact format for
interop, you'd have to strip the first 4 bytes yourself.

### Full certificate size

The example program's generated cert came out to 1790 bytes DER total.
`1790 - 1456 = 334` bytes is everything else in the X.509 structure: TBS
fields (version, serial, issuer/subject DNs, validity), the 60-byte
public key plus its `SubjectPublicKeyInfo` ASN.1 wrapper, the signature
algorithm OID (appears twice - inner + outer), and the `BIT STRING`
tag/length wrapping the 1456-byte signature.

## How size scales with parameter choices

- More `levels`: public/private key size unchanged; signature grows by
  `(hLen x (4+4+4+hLen) + pubkey_len)` per extra level (extra Nspk chain
  link + one more signed public key).
- More `height`: public/private key size unchanged; signature grows
  linearly by `hLen` bytes per extra level of height (longer auth path).
  Available one-time signatures double (`2^height`).
- Smaller `winternitz` (e.g. W8 -> W1): `p` grows a lot (34 -> 265 for
  W1), roughly 4x'ing signature size. Smaller `W` = smaller/faster
  keygen but much bigger signatures; larger `W` = bigger/slower keygen
  but smaller signatures.
- Smaller hash (`hLen` 32 -> 24, SHA-256/192): shrinks every `hLen`-sized
  field proportionally (public key 60->52 bytes, private key 64->56
  bytes, signature shrinks too), at reduced security margin.

## Signing modes: raw bytes vs. openssl.cnf-style certificate

After LMS key setup, `lmscertgen.c` asks interactively which to do:

1. **Sign raw bytes typed at the prompt.** Calls `wc_LmsKey_Sign()` then
   `wc_LmsKey_Verify()` directly over whatever line you type - no
   certificate is produced or written to disk. This is the "message" from
   the `Q = H(I || u32str(q) || u16str(D_MESG) || C || message)` formula
   discussed earlier - raw bytes, no separate prehash step (LMS has no
   such concept; see the "what is prehashed" discussion in this project's
   history).

   Asks for an input format first:
   - **Character string** - the line you type is signed literally, as its
     raw ASCII bytes. Typing `hello world` signs those 11 bytes exactly,
     including the space - there is no byte-separator parsing in this
     mode.
   - **Hex bytes** - the line you type is hex-decoded into real bytes
     before signing. Whitespace is ignored wherever it falls, so
     `DEADBEEF`, `DE AD BE EF`, and `DE ADBE EF` all decode identically to
     the same 4 bytes `0xDE 0xAD 0xBE 0xEF` - only pairs of hex digits
     matter, not how they're grouped. An odd digit count or a non-hex
     character is reported as an error rather than silently
     truncated/ignored. Implemented in `DecodeHexBytes()`, reusing the
     same `HexNibble()` decoder that `FORMAT:HEX,OCT:` config values use
     (mode 2 below) - one hex-digit parser for the whole file.

2. **Generate and sign a certificate from an openssl.cnf-style file.**
   Give it a path (see `sample.cnf`, a copy of a TI secure-boot
   certificate template) and it:
   - Reads `[req]` -> `distinguished_name` and maps
     `C/ST/L/O/OU/CN/emailAddress` from that section onto the cert's
     subject fields.
   - Reads `[req]` -> `x509_extensions` and, from that section:
     - `basicConstraints = CA:true` -> `cert.isCA = 1`.
     - `<dotted-OID> = ASN1:SEQUENCE:<section>` -> builds a DER `SEQUENCE`
       from `<section>`'s entries (each `INTEGER:<dec-or-0x-hex>` or
       `FORMAT:HEX,OCT:<hex>`) and attaches it as a custom X.509v3
       extension via `wc_SetCustomExtension()`.
   - Runs the normal `wc_MakeCert_ex()`/`wc_SignCert_ex()` flow, writing
     `lms_cert.crt`/`lms_cert.pem` as usual.

### wolfSSL support this relies on

- `wc_SetCustomExtension(Cert*, int critical, const char* oid,
  const byte* der, word32 derSz)` (`wolfssl/wolfcrypt/asn_public.h`) -
  attaches an arbitrary-OID X.509v3 extension with a caller-supplied,
  already-DER-encoded value. It stores **pointers**, not copies, so the
  OID string and DER buffer must outlive `wc_MakeCert_ex()` - handled here
  with static storage (`cnfEntries[]`, `customExtSeq[]`).
- Requires `WOLFSSL_CERT_EXT`, `WOLFSSL_CUSTOM_OID`, `HAVE_OID_ENCODING`
  (added to `IDE/WIN/user_settings.h` for this feature) plus
  `WOLFSSL_ASN_TEMPLATE`, which is already wolfSSL's default ASN backend.
- Custom extensions are encoded generically during TBS-body construction
  (`wolfcrypt/src/asn.c`, `customCertExt[]` handling), independent of the
  signing key type - the same mechanism works identically for LMS, RSA,
  ECC, etc.

### What's NOT supported (by design - see scope note)

wolfSSL has no config-file-to-certificate translator of its own (that
logic lives only in OpenSSL's `apps/req.c`, not in `libcrypto`/`libssl`,
so nothing here or in wolfSSL "comes for free"). This parser/encoder
implements exactly the directives used in `sample.cnf` - not a general
OpenSSL config grammar. Not supported (and reported/skipped if
encountered, rather than silently ignored): `subjectAltName`, `keyUsage`
and other named extensions, `$ENV` variable substitution, `.include`,
`oid_section`, and any `ASN1:` typed value other than `SEQUENCE` (e.g. no
`BOOLEAN`, `UTF8String`, `BITSTRING`, ...). The typed-value encoder
(`BuildSequenceFromSection()` in `lmscertgen.c`) is a small dispatch over
value prefixes, so adding another `TYPE:` is a matter of adding one more

## `OID:` typed values (2026-10-30)

Added `OID:<dotted-decimal>` as a third supported typed value in
`BuildSequenceFromSection()`, alongside the existing `INTEGER:` and
`FORMAT:HEX,OCT:`, via a new `DerOid()` encoder. Standard DER OBJECT
IDENTIFIER encoding: the first two arcs combine into one byte
(`40*X + Y`), every arc after that is base-128 big-endian with the
continuation bit set on every byte but the last.

This was needed because `sample.cnf`'s `[image_integrity]` section
already had `shaType = OID:2.16.840.1.101.3.4.2.3` (the SHA-512 OID,
matching the real TI firmware's `image_integrity` extension format,
`SEQUENCE { OID shaType, OCTET STRING shaValue }`) - before this change
that line was silently skipped (`BuildSequenceFromSection()` only
recognized `INTEGER:`/`FORMAT:HEX,OCT:`), so any custom extension
needing an embedded OID value was unsupported. This specifically unblocks
driving `lmscertgen.exe` from `tools/boot/signing/
mcu_appimage_x509_cert_gen.py` in the TIFS firmware repo (see that
script's own `notes.md` for the full picture), whose config template
also encodes a hash-algorithm OID the same way.

## Non-interactive CLI mode (2026-10-30)

Added an argv-driven mode, activated whenever any command-line argument
is present (no arguments at all still gives the original fully
interactive prompts, unchanged):
```
lmscertgen --priv-key <path> --pub-key <path> --cnf <path> --out-crt <path> [--out-pem <path>]
```
Added so a build script (`mcu_appimage_x509_cert_gen.py`, TIFS firmware
repo) can drive certificate signing without a human typing prompts.
`--priv-key`/`--pub-key` default to `lms_priv.key`/`lms_pub.key` in the
current directory (the interactive mode's own filenames) if omitted.

**Deliberately refuses to generate a new LMS key pair** if `--priv-key`
doesn't already exist (`LoadProvisionedLmsKey()`) - this mode only
reloads an already-provisioned key. Rationale: LMS/HSS is a *stateful*
signature scheme (every signature consumes a one-time key and advances
a leaf index that must be persisted, RFC 8554's core security property),
so a silently-generated key in an unattended build would produce a
certificate whose public key was never registered in the device's
keyring (`tools/keyring_cert/keys.json`, TIFS repo) - the resulting
signed image would then fail on-device verification for a reason with
no obvious cause from the build log. Provisioning a key is a deliberate,
one-time, interactive step that must happen before this mode is ever
used against that key's path.

`GenerateCertFromCnfFile()` gained `outCrtPath`/`outPemPath` parameters
(previously hardcoded to `CERT_CRT_FILE`/`CERT_PEM_FILE`) so the CLI
mode can write to caller-chosen paths; `outPemPath` may be `NULL` to
skip writing a PEM copy entirely, since a build script driving this
tool only needs the DER `.crt` to concatenate onto an application image.
The interactive mode's own call site is unchanged in behavior - it still
always writes both `lms_cert.crt` and `lms_cert.pem`.
`else if` and a matching `Der*()` encoder - not a redesign.
