/* lmscertgen.c
 *
 * Generates a self-signed X.509 certificate signed with an LMS/HSS key
 * (RFC 9802), using wolfSSL's native LMS implementation.
 *
 * Requires the wolfssl project to be built with WOLFSSL_HAVE_LMS,
 * WOLFSSL_CERT_EXT, WOLFSSL_CUSTOM_OID and HAVE_OID_ENCODING defined
 * (see IDE/WIN/user_settings.h) and wolfcrypt/src/wc_lms.c /
 * wc_lms_impl.c added to wolfssl.vcxproj.
 *
 * Interactively offers two signing modes:
 *   1) Sign raw bytes typed at the prompt (no certificate produced).
 *   2) Generate and sign a certificate from an openssl.cnf-style config
 *      file - supports [req] distinguished_name/x509_extensions pointers,
 *      C/ST/L/O/OU/CN/emailAddress, basicConstraints, and custom-OID
 *      extensions written as "<oid> = ASN1:SEQUENCE:<section>" where
 *      <section>'s entries are typed INTEGER:<val> / FORMAT:HEX,OCT:<hex>
 *      values (see sample.cnf). This is NOT a general OpenSSL config
 *      parser - other directives (subjectAltName, keyUsage, $ENV vars,
 *      .include, other ASN1: types, etc.) are reported and skipped.
 */

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/* levels=1, height=10, Winternitz=8 -> 2^10 = 1024 one-time signatures.
 * Bump 'levels'/'height' for a larger HSS tree if more signatures are
 * needed; each extra level of height doubles generation/signing cost. */
#define LMS_LEVELS      1
#define LMS_HEIGHT      10
#define LMS_WINTERNITZ  8

#define LMS_PRIV_KEY_FILE "lms_priv.key"
#define LMS_PUB_KEY_FILE  "lms_pub.key"
#define CERT_CRT_FILE     "lms_cert.crt"
#define CERT_PEM_FILE     "lms_cert.pem"

/*-----------------------------------------------------------------------
 * LMS key persistence callbacks
 *
 * LMS is a stateful signature scheme: every wc_LmsKey_Sign() call
 * advances the private key's leaf index, and that new state MUST be
 * persisted before the signature is used. Re-signing with an old copy
 * of the state reuses a one-time key and breaks the scheme's security
 * completely, so wc_LmsKey_MakeKey()/Sign() refuse to run without a
 * write callback.
 *---------------------------------------------------------------------*/
static int LmsWritePrivKey(const byte* priv, word32 privSz, void* ctx)
{
    FILE* f = fopen((const char*)ctx, "wb");
    size_t written;

    if (f == NULL) {
        printf("LmsWritePrivKey: fopen(%s) failed: %s\n",
                (const char*)ctx, strerror(errno));
        return WC_LMS_RC_WRITE_FAIL;
    }

    written = fwrite(priv, 1, privSz, f);
    if (written != (size_t)privSz) {
        printf("LmsWritePrivKey: fwrite wrote %zu of %u bytes: %s\n",
                written, privSz, strerror(errno));
    }
    fclose(f);

    return (written == (size_t)privSz) ?
            WC_LMS_RC_SAVED_TO_NV_MEMORY : WC_LMS_RC_WRITE_FAIL;
}

static int LmsReadPrivKey(byte* priv, word32 privSz, void* ctx)
{
    FILE* f = fopen((const char*)ctx, "rb");
    size_t readSz;

    if (f == NULL)
        return WC_LMS_RC_READ_FAIL;

    readSz = fread(priv, 1, privSz, f);
    fclose(f);

    return (readSz == (size_t)privSz) ?
            WC_LMS_RC_READ_TO_MEMORY : WC_LMS_RC_READ_FAIL;
}

/*-----------------------------------------------------------------------
 * Minimal openssl.cnf-style INI parser
 *
 * Loads the whole file into a flat, file-order list of
 * {section, key, value} entries. Order is preserved because building a
 * DER SEQUENCE from a section's entries must respect the file's
 * declaration order.
 *---------------------------------------------------------------------*/
#define MAX_CNF_NAME    64
#define MAX_CNF_VALUE   512
#define MAX_CNF_ENTRIES 128

typedef struct {
    char section[MAX_CNF_NAME];
    char key[MAX_CNF_NAME];
    char value[MAX_CNF_VALUE];
} CnfEntry;

static CnfEntry cnfEntries[MAX_CNF_ENTRIES];
static int      cnfEntryCount = 0;

static void CnfStripTrailing(char* s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
            s[len - 1] == ' ' || s[len - 1] == '\t')) {
        s[--len] = '\0';
    }
}

static int LoadCnfFile(const char* path)
{
    FILE* f = fopen(path, "r");
    char  line[MAX_CNF_VALUE + MAX_CNF_NAME];
    char  section[MAX_CNF_NAME] = "";

    if (f == NULL) {
        printf("Could not open config file: %s (%s)\n", path,
                strerror(errno));
        return -1;
    }

    cnfEntryCount = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        char* p = line;
        char* eq;

        CnfStripTrailing(line);
        while (*p == ' ' || *p == '\t')
            p++;

        if (*p == '\0' || *p == '#' || *p == ';')
            continue; /* blank line or comment */

        if (*p == '[') {
            /* Section header: [ name ] */
            char*  close = strchr(p, ']');
            char*  nameStart = p + 1;
            size_t nameLen;

            if (close == NULL) {
                printf("Malformed section header, skipping: %s\n", p);
                continue;
            }
            while (*nameStart == ' ' || *nameStart == '\t')
                nameStart++;
            nameLen = (size_t)(close - nameStart);
            while (nameLen > 0 && (nameStart[nameLen - 1] == ' ' ||
                    nameStart[nameLen - 1] == '\t')) {
                nameLen--;
            }
            if (nameLen >= sizeof(section))
                nameLen = sizeof(section) - 1;
            memcpy(section, nameStart, nameLen);
            section[nameLen] = '\0';
            continue;
        }

        eq = strchr(p, '=');
        if (eq == NULL) {
            printf("Skipping unrecognized line (no '='): %s\n", p);
            continue;
        }

        if (cnfEntryCount >= MAX_CNF_ENTRIES) {
            printf("Too many config entries (max %d) - truncating file "
                    "read\n", MAX_CNF_ENTRIES);
            break;
        }

        {
            char*  keyStart = p;
            char*  keyEnd = eq;
            char*  valStart = eq + 1;
            size_t keyLen;
            CnfEntry* entry = &cnfEntries[cnfEntryCount];

            while (keyEnd > keyStart && (keyEnd[-1] == ' ' ||
                    keyEnd[-1] == '\t')) {
                keyEnd--;
            }
            keyLen = (size_t)(keyEnd - keyStart);
            if (keyLen >= sizeof(entry->key))
                keyLen = sizeof(entry->key) - 1;

            while (*valStart == ' ' || *valStart == '\t')
                valStart++;

            strncpy(entry->section, section, sizeof(entry->section) - 1);
            entry->section[sizeof(entry->section) - 1] = '\0';
            memcpy(entry->key, keyStart, keyLen);
            entry->key[keyLen] = '\0';
            strncpy(entry->value, valStart, sizeof(entry->value) - 1);
            entry->value[sizeof(entry->value) - 1] = '\0';

            cnfEntryCount++;
        }
    }

    fclose(f);
    return 0;
}

static const char* CnfGet(const char* section, const char* key)
{
    int i;

    for (i = 0; i < cnfEntryCount; i++) {
        if (strcmp(cnfEntries[i].section, section) == 0 &&
                strcmp(cnfEntries[i].key, key) == 0) {
            return cnfEntries[i].value;
        }
    }
    return NULL;
}

/*-----------------------------------------------------------------------
 * Minimal DER TLV encoding helpers.
 *
 * wolfSSL exposes no public API for generic ASN.1 encoding (those are
 * internal/static in asn.c) - this implements exactly the subset the
 * sample config's "ASN1:SEQUENCE:<section>" extensions need: INTEGER,
 * OCTET STRING (from a hex string), and the outer SEQUENCE wrapper.
 * Each Der*() function returns the number of bytes written (or would
 * write, if 'out' is NULL), or 0 on error/overflow.
 *---------------------------------------------------------------------*/
static word32 DerLen(byte* out, word32 len)
{
    if (len < 128) {
        if (out != NULL)
            out[0] = (byte)len;
        return 1;
    }
    else if (len < 256) {
        if (out != NULL) {
            out[0] = 0x81;
            out[1] = (byte)len;
        }
        return 2;
    }
    else {
        if (out != NULL) {
            out[0] = 0x82;
            out[1] = (byte)(len >> 8);
            out[2] = (byte)len;
        }
        return 3;
    }
}

static word32 DerInt(byte* out, word32 outLen, unsigned long long val)
{
    byte    content[9];
    int     contentLen;
    int     i;
    word32  lenLen;
    word32  total;
    unsigned long long v;

    /* Minimal big-endian byte count (at least 1, for value 0). */
    contentLen = 1;
    v = val;
    while (v > 0xffULL) {
        v >>= 8;
        contentLen++;
    }

    for (i = contentLen - 1; i >= 0; i--) {
        content[i] = (byte)(val & 0xff);
        val >>= 8;
    }

    /* DER INTEGER must not have its high bit set unless the value is
     * actually negative; we only encode unsigned values here, so pad
     * with a leading 0x00 whenever that would otherwise happen. */
    if ((content[0] & 0x80) != 0 && contentLen < (int)sizeof(content)) {
        for (i = contentLen; i > 0; i--)
            content[i] = content[i - 1];
        content[0] = 0x00;
        contentLen++;
    }

    lenLen = DerLen(NULL, (word32)contentLen);
    total = 1 + lenLen + (word32)contentLen;

    if (out != NULL) {
        if (total > outLen)
            return 0;
        out[0] = 0x02; /* INTEGER tag */
        DerLen(out + 1, (word32)contentLen);
        memcpy(out + 1 + lenLen, content, (size_t)contentLen);
    }

    return total;
}

static int HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static word32 DerOctetStringHex(byte* out, word32 outLen, const char* hex)
{
    size_t hexLen = strlen(hex);
    size_t byteLen;
    byte   content[256];
    size_t i;
    word32 lenLen;
    word32 total;

    if ((hexLen % 2) != 0) {
        printf("DerOctetStringHex: odd-length hex string: %s\n", hex);
        return 0;
    }
    byteLen = hexLen / 2;
    if (byteLen > sizeof(content)) {
        printf("DerOctetStringHex: hex string too long (%zu bytes): "
                "%s\n", byteLen, hex);
        return 0;
    }

    for (i = 0; i < byteLen; i++) {
        int hi = HexNibble(hex[2 * i]);
        int lo = HexNibble(hex[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            printf("DerOctetStringHex: invalid hex digit in: %s\n", hex);
            return 0;
        }
        content[i] = (byte)((hi << 4) | lo);
    }

    lenLen = DerLen(NULL, (word32)byteLen);
    total = 1 + lenLen + (word32)byteLen;

    if (out != NULL) {
        if (total > outLen)
            return 0;
        out[0] = 0x04; /* OCTET STRING tag */
        DerLen(out + 1, (word32)byteLen);
        memcpy(out + 1 + lenLen, content, byteLen);
    }

    return total;
}

static word32 DerSequenceWrap(byte* out, word32 outLen, const byte* content,
        word32 contentLen)
{
    word32 lenLen = DerLen(NULL, contentLen);
    word32 total = 1 + lenLen + contentLen;

    if (out != NULL) {
        if (total > outLen)
            return 0;
        out[0] = 0x30; /* SEQUENCE tag */
        DerLen(out + 1, contentLen);
        memcpy(out + 1 + lenLen, content, contentLen);
    }

    return total;
}

/* Build a DER SEQUENCE from every "key = TYPE:value" entry in
 * 'sectionName', in file order. Supports exactly the two typed-value
 * forms the sample config uses: "INTEGER:<dec-or-0x-hex>" and
 * "FORMAT:HEX,OCT:<hex>". Anything else is reported and skipped. */
static word32 BuildSequenceFromSection(const char* sectionName,
        byte* out, word32 outLen)
{
    byte   content[1024];
    word32 contentLen = 0;
    int    i;

    for (i = 0; i < cnfEntryCount; i++) {
        const char* val;
        word32      written;

        if (strcmp(cnfEntries[i].section, sectionName) != 0)
            continue;

        val = cnfEntries[i].value;

        if (strncmp(val, "INTEGER:", 8) == 0) {
            unsigned long long v = strtoull(val + 8, NULL, 0);

            written = DerInt(content + contentLen,
                    (word32)sizeof(content) - contentLen, v);
        }
        else if (strncmp(val, "FORMAT:HEX,OCT:", 15) == 0) {
            written = DerOctetStringHex(content + contentLen,
                    (word32)sizeof(content) - contentLen, val + 15);
        }
        else {
            printf("Skipping unsupported typed value in [%s] %s = %s\n",
                    sectionName, cnfEntries[i].key, val);
            continue;
        }

        if (written == 0) {
            printf("Failed to encode [%s] %s = %s\n",
                    sectionName, cnfEntries[i].key, val);
            return 0;
        }
        contentLen += written;
    }

    return DerSequenceWrap(out, outLen, content, contentLen);
}

/*-----------------------------------------------------------------------
 * openssl.cnf-style config -> Cert translation
 *---------------------------------------------------------------------*/
static void ApplyCnfDistinguishedName(Cert* cert, const char* dnSection)
{
    const char* v;

    if ((v = CnfGet(dnSection, "C")) != NULL)
        strncpy(cert->subject.country, v, CTC_NAME_SIZE - 1);
    if ((v = CnfGet(dnSection, "ST")) != NULL)
        strncpy(cert->subject.state, v, CTC_NAME_SIZE - 1);
    if ((v = CnfGet(dnSection, "L")) != NULL)
        strncpy(cert->subject.locality, v, CTC_NAME_SIZE - 1);
    if ((v = CnfGet(dnSection, "O")) != NULL)
        strncpy(cert->subject.org, v, CTC_NAME_SIZE - 1);
    if ((v = CnfGet(dnSection, "OU")) != NULL)
        strncpy(cert->subject.unit, v, CTC_NAME_SIZE - 1);
    if ((v = CnfGet(dnSection, "CN")) != NULL)
        strncpy(cert->subject.commonName, v, CTC_NAME_SIZE - 1);
    if ((v = CnfGet(dnSection, "emailAddress")) != NULL)
        strncpy(cert->subject.email, v, CTC_NAME_SIZE - 1);
}

/* Custom-extension DER buffers must outlive wc_MakeCert_ex() below, since
 * wc_SetCustomExtension() stores pointers, not copies (documented in
 * wolfcrypt/src/asn.c). Static storage sidesteps any scope concerns. */
static byte customExtSeq[NUM_CUSTOM_EXT][512];

static void ApplyCnfExtensions(Cert* cert, const char* extSection)
{
    int i;
    int customIdx = 0;

    for (i = 0; i < cnfEntryCount; i++) {
        const char* key;
        const char* val;

        if (strcmp(cnfEntries[i].section, extSection) != 0)
            continue;

        key = cnfEntries[i].key;
        val = cnfEntries[i].value;

        if (strcmp(key, "basicConstraints") == 0) {
            if (strstr(val, "CA:true") != NULL ||
                    strstr(val, "CA:TRUE") != NULL) {
                cert->isCA = 1;
                printf("basicConstraints: CA:TRUE\n");
            }
            continue;
        }

        if (isdigit((unsigned char)key[0]) &&
                strncmp(val, "ASN1:SEQUENCE:", 14) == 0) {
            const char* subSection = val + 14;
            word32      seqLen;
            int         ret;

            if (customIdx >= NUM_CUSTOM_EXT) {
                printf("Too many custom extensions (max %d) - skipping "
                        "OID %s\n", NUM_CUSTOM_EXT, key);
                continue;
            }

            seqLen = BuildSequenceFromSection(subSection,
                    customExtSeq[customIdx],
                    (word32)sizeof(customExtSeq[0]));
            if (seqLen == 0) {
                printf("Failed to build extension for OID %s "
                        "(section [%s])\n", key, subSection);
                continue;
            }

            /* 'key' points into the static cnfEntries[] array, so it
             * (like customExtSeq[customIdx]) remains valid through
             * wc_MakeCert_ex() below. */
            ret = wc_SetCustomExtension(cert, 0, key,
                    customExtSeq[customIdx], seqLen);
            if (ret != 0) {
                printf("wc_SetCustomExtension failed for OID %s: %d\n",
                        key, ret);
                continue;
            }

            printf("Added custom extension OID %s from [%s] (%u "
                    "bytes)\n", key, subSection, seqLen);
            customIdx++;
            continue;
        }

        printf("Skipping unsupported directive in [%s]: %s = %s\n",
                extSection, key, val);
    }
}

static int GenerateCertFromCnfFile(LmsKey* lmsKey, WC_RNG* rng,
        const char* path, byte* der, word32 derCap)
{
    Cert        cert;
    int         derSz;
    int         pemSz;
    const char* dnSection;
    const char* extSection;
    FILE*       f;
    byte        pem[8192];

    if (LoadCnfFile(path) != 0)
        return -1;

    wc_InitCert(&cert);
    cert.isCA      = 0;
    cert.sigType   = CTC_HSS_LMS;
    cert.daysValid = 365;

    dnSection = CnfGet("req", "distinguished_name");
    if (dnSection != NULL) {
        ApplyCnfDistinguishedName(&cert, dnSection);
    }
    else {
        printf("Warning: [req] distinguished_name not found in %s\n",
                path);
    }

    extSection = CnfGet("req", "x509_extensions");
    if (extSection != NULL) {
        ApplyCnfExtensions(&cert, extSection);
    }
    else {
        printf("Warning: [req] x509_extensions not found in %s\n", path);
    }

    derSz = wc_MakeCert_ex(&cert, der, derCap, LMS_TYPE, lmsKey, rng);
    if (derSz < 0) {
        printf("wc_MakeCert_ex failed: %d\n", derSz);
        return derSz;
    }

    derSz = wc_SignCert_ex(cert.bodySz, cert.sigType, der, derCap,
            LMS_TYPE, lmsKey, rng);
    if (derSz < 0) {
        printf("wc_SignCert_ex failed: %d\n", derSz);
        return derSz;
    }
    printf("Signed certificate is %d bytes (DER)\n", derSz);

    f = fopen(CERT_CRT_FILE, "wb");
    if (f == NULL) {
        printf("Could not open %s for writing\n", CERT_CRT_FILE);
        return -1;
    }
    fwrite(der, 1, (size_t)derSz, f);
    fclose(f);
    printf("Wrote %s\n", CERT_CRT_FILE);

    pemSz = wc_DerToPem(der, (word32)derSz, pem, sizeof(pem), CERT_TYPE);
    if (pemSz < 0) {
        printf("wc_DerToPem failed: %d\n", pemSz);
        return pemSz;
    }

    f = fopen(CERT_PEM_FILE, "wb");
    if (f == NULL) {
        printf("Could not open %s for writing\n", CERT_PEM_FILE);
        return -1;
    }
    fwrite(pem, 1, (size_t)pemSz, f);
    fclose(f);
    printf("Wrote %s\n", CERT_PEM_FILE);

    return 0;
}

/*-----------------------------------------------------------------------
 * Raw-bytes signing mode
 *---------------------------------------------------------------------*/

/* Decode a hex string into raw bytes. Whitespace is skipped wherever it
 * appears, so both "DEADBEEF" and "DE AD BE EF" (or any other spacing)
 * decode identically - pairs of hex digits are what matter, not their
 * grouping. Reuses HexNibble() (defined above, used by
 * DerOctetStringHex()). Returns 0 on success, -1 on bad input. */
static int DecodeHexBytes(const char* in, byte* out, size_t outCap,
        size_t* outLen)
{
    size_t n = 0;
    int    haveHi = 0;
    int    hiVal = 0;

    *outLen = 0;
    for (; *in != '\0'; in++) {
        int v;

        if (*in == ' ' || *in == '\t')
            continue;

        v = HexNibble(*in);
        if (v < 0) {
            printf("Invalid hex character '%c' in input\n", *in);
            return -1;
        }

        if (!haveHi) {
            hiVal = v;
            haveHi = 1;
        }
        else {
            if (n >= outCap) {
                printf("Hex input too long (max %zu bytes)\n", outCap);
                return -1;
            }
            out[n++] = (byte)((hiVal << 4) | v);
            haveHi = 0;
        }
    }

    if (haveHi) {
        printf("Odd number of hex digits in input\n");
        return -1;
    }

    *outLen = n;
    return 0;
}

static int SignRawMessageInteractive(LmsKey* lmsKey)
{
    char        choice[16];
    char        input[512];
    byte        hexBytes[512];
    const byte* msg;
    size_t      len;
    byte        sig[2048];
    word32      sigSz = sizeof(sig);
    int         ret;
    int         asHex = 0;

    printf("Message input format:\n");
    printf("  1) Character string (literal ASCII text)\n");
    printf("  2) Bytes as hex, space-separated or contiguous "
            "(e.g. \"DE AD BE EF\" or \"DEADBEEF\")\n");
    printf("Choice [1/2]: ");
    fflush(stdout);
    if (fgets(choice, sizeof(choice), stdin) != NULL && atoi(choice) == 2)
        asHex = 1;

    printf("Enter message to sign: ");
    fflush(stdout);
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("Failed to read message\n");
        return -1;
    }
    CnfStripTrailing(input);

    if (asHex) {
        if (DecodeHexBytes(input, hexBytes, sizeof(hexBytes), &len) != 0)
            return -1;
        msg = hexBytes;
        printf("Signing %zu byte(s) decoded from hex input\n", len);
    }
    else {
        msg = (const byte*)input;
        len = strlen(input);
        printf("Signing message: \"%s\" (%zu bytes)\n", input, len);
    }

    ret = wc_LmsKey_Sign(lmsKey, sig, &sigSz, msg, (int)len);
    printf("wc_LmsKey_Sign done: %d, sigSz=%u\n", ret, sigSz);
    if (ret != 0)
        return ret;

    ret = wc_LmsKey_Verify(lmsKey, sig, sigSz, msg, (int)len);
    printf("wc_LmsKey_Verify done: %d%s\n", ret,
            (ret == 0) ? " (signature is valid)" : " (FAILED)");

    return ret;
}

int main(void)
{
    int    ret;
    LmsKey lmsKey;
    WC_RNG rng;
    byte   der[4096];
    FILE*  f;

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("start\n");

    ret = wolfSSL_Init();
    printf("wolfSSL_Init done: %d\n", ret);
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_Init failed: %d\n", ret);
        return ret;
    }

    ret = wc_InitRng(&rng);
    printf("wc_InitRng done: %d\n", ret);
    if (ret != 0) {
        printf("wc_InitRng failed: %d\n", ret);
        return ret;
    }

    ret = wc_LmsKey_Init(&lmsKey, NULL, INVALID_DEVID);
    printf("wc_LmsKey_Init done: %d\n", ret);
    if (ret != 0) {
        printf("wc_LmsKey_Init failed: %d\n", ret);
        return ret;
    }

    ret = wc_LmsKey_SetParameters(&lmsKey, LMS_LEVELS, LMS_HEIGHT,
            LMS_WINTERNITZ);
    printf("wc_LmsKey_SetParameters done: %d\n", ret);
    if (ret != 0) {
        printf("wc_LmsKey_SetParameters failed: %d\n", ret);
        return ret;
    }

    ret = wc_LmsKey_SetWriteCb(&lmsKey, LmsWritePrivKey);
    if (ret == 0)
        ret = wc_LmsKey_SetReadCb(&lmsKey, LmsReadPrivKey);
    if (ret == 0)
        ret = wc_LmsKey_SetContext(&lmsKey, (void*)LMS_PRIV_KEY_FILE);
    printf("LMS key callback setup done: %d\n", ret);
    if (ret != 0) {
        printf("LMS key callback setup failed: %d\n", ret);
        return ret;
    }

    {
        FILE* existing = fopen(LMS_PRIV_KEY_FILE, "rb");
        int   generateNew = 1;

        if (existing != NULL) {
            char line[16];

            fclose(existing);
            printf("Existing LMS key found at %s.\n", LMS_PRIV_KEY_FILE);
            printf("Generate a NEW Merkle tree? This discards the existing "
                   "key and any one-time signatures still left in it.\n"
                   "Generate new? [y/N]: ");
            fflush(stdout);

            generateNew = 0;
            if (fgets(line, sizeof(line), stdin) != NULL &&
                    (line[0] == 'y' || line[0] == 'Y')) {
                generateNew = 1;
            }
        }
        else {
            printf("No existing LMS key found at %s.\n", LMS_PRIV_KEY_FILE);
        }

        if (generateNew) {
            printf("Generating a NEW LMS key pair (levels=%d height=%d "
                   "w=%d, %d one-time signatures available)...\n",
                   LMS_LEVELS, LMS_HEIGHT, LMS_WINTERNITZ, 1 << LMS_HEIGHT);
            ret = wc_LmsKey_MakeKey(&lmsKey, &rng);
            printf("wc_LmsKey_MakeKey done: %d\n", ret);

            /* wc_LmsKey_MakeKey() is the only call that populates
             * key->pub/pubSet. Persist the public key now so it can be
             * restored after a future Reload (see below - Reload does
             * NOT repopulate it, by wolfSSL's own documented design). */
            if (ret == 0) {
                byte  pub[128];
                word32 pubLen = sizeof(pub);

                ret = wc_LmsKey_ExportPubRaw(&lmsKey, pub, &pubLen);
                if (ret == 0) {
                    f = fopen(LMS_PUB_KEY_FILE, "wb");
                    if (f == NULL) {
                        printf("Could not open %s for writing\n",
                                LMS_PUB_KEY_FILE);
                        ret = -1;
                    }
                    else {
                        fwrite(pub, 1, pubLen, f);
                        fclose(f);
                        printf("Wrote %s\n", LMS_PUB_KEY_FILE);
                    }
                }
            }
        }
        else {
            byte   savedPub[128];
            byte   reloadedPub[128];
            size_t savedPubLen;
            word32 reloadedPubLen = sizeof(reloadedPub);

            printf("Reusing existing LMS key - reloading state from %s...\n",
                   LMS_PRIV_KEY_FILE);
            ret = wc_LmsKey_Reload(&lmsKey);
            printf("wc_LmsKey_Reload done: %d\n", ret);
            if (ret == BAD_STATE_E) {
                printf("This key has no one-time signatures left; rerun "
                       "and choose to generate a new one.\n");
            }

            /* wc_LmsKey_Reload() (patched in wolfcrypt/src/wc_lms.c) now
             * recomputes the tree root and repopulates key->pub/pubSet
             * itself - it does this by rebuilding the Merkle tree from
             * (I, SEED) via wc_hss_init_auth_path(), the exact same
             * computation it already has to do to prepare the
             * authentication path needed for signing, so nothing extra
             * is computed just to get the public key. As a sanity check,
             * compare that freshly-recomputed public key against the copy
             * saved to disk when this key was first created - they must
             * be bit-for-bit identical, since the tree is a pure
             * deterministic function of (I, SEED, params). */
            if (ret == 0) {
                ret = wc_LmsKey_ExportPubRaw(&lmsKey, reloadedPub,
                        &reloadedPubLen);
                if (ret != 0) {
                    printf("wc_LmsKey_ExportPubRaw failed: %d\n", ret);
                }
            }
            if (ret == 0) {
                f = fopen(LMS_PUB_KEY_FILE, "rb");
                if (f == NULL) {
                    printf("Could not open %s for reading\n",
                            LMS_PUB_KEY_FILE);
                    ret = -1;
                }
                else {
                    savedPubLen = fread(savedPub, 1, sizeof(savedPub), f);
                    fclose(f);
                    if (savedPubLen != reloadedPubLen ||
                            memcmp(savedPub, reloadedPub, reloadedPubLen)
                                    != 0) {
                        printf("MISMATCH: public key recomputed by reload "
                               "does not match %s\n", LMS_PUB_KEY_FILE);
                        ret = -1;
                    }
                    else {
                        printf("Verified: recomputed Merkle tree root "
                               "matches saved public key (%zu bytes)\n",
                               savedPubLen);
                    }
                }
            }
        }
    }
    if (ret != 0) {
        printf("LMS key setup failed: %d\n", ret);
        return ret;
    }
    printf("LMS private key state saved to %s\n", LMS_PRIV_KEY_FILE);

    {
        char choice[16];
        int  mode = 0;

        printf("\nChoose signing mode:\n");
        printf("  1) Sign raw bytes typed at the prompt (no certificate "
                "produced)\n");
        printf("  2) Generate and sign a certificate from an "
                "openssl.cnf-style file\n");
        printf("Choice [1/2]: ");
        fflush(stdout);

        if (fgets(choice, sizeof(choice), stdin) != NULL)
            mode = atoi(choice);

        if (mode == 2) {
            char path[512];

            printf("Enter path to config file: ");
            fflush(stdout);
            if (fgets(path, sizeof(path), stdin) != NULL) {
                CnfStripTrailing(path);
                ret = GenerateCertFromCnfFile(&lmsKey, &rng, path, der,
                        sizeof(der));
            }
            else {
                printf("Failed to read config file path\n");
                ret = -1;
            }
        }
        else {
            ret = SignRawMessageInteractive(&lmsKey);
        }
    }
    if (ret != 0) {
        printf("Signing failed: %d\n", ret);
        return ret;
    }

    wc_LmsKey_Free(&lmsKey);
    wc_FreeRng(&rng);
    wolfSSL_Cleanup();

    return 0;
}
