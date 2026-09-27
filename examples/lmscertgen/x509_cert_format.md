 -- Top-level certificate structure (matches offset 0)
Certificate ::= SEQUENCE {
tbsCertificate          TBSCertificate,
signatureAlgorithm      AlgorithmIdentifier,
signatureValue          BIT STRING
}

-- "To Be Signed" payload (matches offset 4)
TBSCertificate ::= SEQUENCE {
version         [0]     EXPLICIT Version DEFAULT v1,        -- offset 8
serialNumber            CertificateSerialNumber,            -- offset 13
signature               AlgorithmIdentifier,                -- offset 35
issuer                  Name,                               -- offset 50
validity                Validity,
subject                 Name,
subjectPublicKeyInfo    SubjectPublicKeyInfo,
issuerUniqueID    [1]   IMPLICIT UniqueIdentifier OPTIONAL, -- If present (v2/v3)
subjectUniqueID   [2]   IMPLICIT UniqueIdentifier OPTIONAL, -- If present (v2/v3)
extensions        [3]   EXPLICIT Extensions OPTIONAL        -- If present (v3 only)
}

-- Version definition
Version ::= INTEGER { v1(0), v2(1), v3(2) }

-- Serial Number definition
CertificateSerialNumber ::= INTEGER

-- Algorithm definition (matches offset 35 and top-level signatureAlgorithm)
AlgorithmIdentifier ::= SEQUENCE {
algorithm               OBJECT IDENTIFIER,
parameters              ANY DEFINED BY algorithm OPTIONAL
}

-- Name definition (matches Issuer at offset 50 and Subject)
Name ::= CHOICE {
rdnSequence             RDNSequence
}

RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::= SET OF AttributeTypeAndValue

AttributeTypeAndValue ::= SEQUENCE {
type                    OBJECT IDENTIFIER,
value                   ANY DEFINED BY type
}

-- Validity definition
Validity ::= SEQUENCE {
notBefore               Time,
notAfter                Time
}

Time ::= CHOICE {
utcTime                 UTCTime,
generalTime             GeneralizedTime
}

-- Public Key definition (e.g. RSA 4096-bit key)
SubjectPublicKeyInfo ::= SEQUENCE {
algorithm               AlgorithmIdentifier,
subjectPublicKey        BIT STRING
}

-- Extensions definition (v3 only)
Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension

Extension ::= SEQUENCE {
extnID                  OBJECT IDENTIFIER,
critical                BOOLEAN DEFAULT FALSE,
extnValue               OCTET STRING
}