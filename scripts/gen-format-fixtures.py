#!/usr/bin/env python3
"""Generate single-cert fixtures for the attestation certificate *format*
check (ATT-1 / ATT-6), mirroring connectedhomeip's
`VerifyAttestationCertificateFormat` (CHIPCryptoPALOpenSSL.cpp:1227).

Each fixture is ONE DER-encoded certificate. A `*-valid` cert is a
fully well-formed DAC/PAI (SKID + AKID + role-correct BasicConstraints
and KeyUsage); every other fixture is that same well-formed cert with
exactly one deliberate profile flaw, so a unit test can assert the flaw
is the reason for rejection.

Output: test-vectors/certs/attestation/format/<name>.der

Run once, by a human, from the repo root; the output is committed. CI
does not re-run it. Requires: Python 3.10+, cryptography>=41.

    python3 scripts/gen-format-fixtures.py

The existing negative-chain fixtures (gen-negative-fixtures.py) are NOT
touched — the format check is a separate peer step (as in chip's device
attestation verifier), so those chain fixtures stay byte-stable.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

AT = datetime.fromtimestamp(1_800_000_000, tz=timezone.utc)  # 2027-01-15
OUT_DIR = Path(__file__).resolve().parent.parent / "test-vectors" / "certs" / "attestation" / "format"

MATTER_VID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.37244.2.1")
MATTER_PID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.37244.2.2")


def key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def dn(cn: str, vid: int, pid: int | None) -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(MATTER_VID_OID, f"{vid:04X}"),
    ]
    if pid is not None:
        attrs.append(x509.NameAttribute(MATTER_PID_OID, f"{pid:04X}"))
    return x509.Name(attrs)


# A single shared, well-formed PAA/PAI so every DAC fixture chains
# plausibly (the format check only looks at one cert at a time, but a
# realistic issuer keeps the fixtures honest).
PAA_KEY = key()
PAA_SUBJ = dn("Matter Format-Test PAA", 0xFFF1, None)
PAA = (
    x509.CertificateBuilder()
    .subject_name(PAA_SUBJ).issuer_name(PAA_SUBJ).public_key(PAA_KEY.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(AT - timedelta(days=365)).not_valid_after(AT + timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
    .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                 key_encipherment=False, data_encipherment=False,
                                 key_agreement=False, key_cert_sign=True, crl_sign=True,
                                 encipher_only=False, decipher_only=False), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(PAA_KEY.public_key()), critical=False)
    .sign(PAA_KEY, hashes.SHA256())
)

PAI_KEY = key()


def build_pai(*, ca=True, path_length=0, skid=True, akid=True,
              key_cert_sign=True, crl_sign=True, digital_signature=False) -> x509.Certificate:
    b = (
        x509.CertificateBuilder()
        .subject_name(dn("Matter Format-Test PAI", 0xFFF1, None))
        .issuer_name(PAA_SUBJ).public_key(PAI_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(AT - timedelta(days=180)).not_valid_after(AT + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=digital_signature, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=key_cert_sign, crl_sign=crl_sign,
                                     encipher_only=False, decipher_only=False), critical=True)
    )
    if skid:
        b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(PAI_KEY.public_key()), critical=False)
    if akid:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(PAA_KEY.public_key()), critical=False)
    return b.sign(PAA_KEY, hashes.SHA256())


def build_dac(*, is_ca=False, path_length=None, skid=True, akid=True,
              digital_signature=True, key_cert_sign=False, crl_sign=False,
              ku_critical=True, bc_critical=True) -> x509.Certificate:
    dac_key = key()
    b = (
        x509.CertificateBuilder()
        .subject_name(dn("Matter Format-Test DAC", 0xFFF1, 0x8000))
        .issuer_name(dn("Matter Format-Test PAI", 0xFFF1, None)).public_key(dac_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(AT - timedelta(days=30)).not_valid_after(AT + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=path_length), critical=bc_critical)
        .add_extension(x509.KeyUsage(digital_signature=digital_signature, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=key_cert_sign, crl_sign=crl_sign,
                                     encipher_only=False, decipher_only=False), critical=ku_critical)
    )
    if skid:
        b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(dac_key.public_key()), critical=False)
    if akid:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(PAI_KEY.public_key()), critical=False)
    return b.sign(PAI_KEY, hashes.SHA256())


def w(name: str, cert: x509.Certificate) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / f"{name}.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))
    print(f"wrote {name}.der")


def main() -> None:
    # Well-formed baselines (must PASS the format check).
    w("dac-valid", build_dac())
    w("pai-valid", build_pai())

    # DAC flaws (must be REJECTED).
    w("dac-keycertsign", build_dac(key_cert_sign=True))        # KU != exactly digitalSignature
    w("dac-missing-skid", build_dac(skid=False))               # SKID mandatory
    w("dac-missing-akid", build_dac(akid=False))               # AKID mandatory on DAC
    w("dac-ku-not-critical", build_dac(ku_critical=False))     # KeyUsage must be critical
    w("dac-is-ca", build_dac(is_ca=True))                      # DAC must not be a CA

    # PAI flaws (must be REJECTED).
    w("pai-pathlen-nonzero", build_pai(path_length=1))         # PAI pathLen must be 0
    w("pai-not-ca", build_pai(ca=False, path_length=None))     # PAI must be a CA
    w("pai-missing-crlsign", build_pai(crl_sign=False))        # PAI KU needs keyCertSign+crlSign

    print(f"\nDone -> {OUT_DIR}")


if __name__ == "__main__":
    main()
