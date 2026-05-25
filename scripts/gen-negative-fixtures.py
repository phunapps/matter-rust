#!/usr/bin/env python3
"""Generate the 8 M6.2.2 negative-path attestation chain fixtures.

Each fixture is a self-contained (PAA, PAI, DAC) triple where one
attribute is deliberately broken to exercise a specific
AttestationError variant. Output goes under
test-vectors/certs/attestation/negative/<fixture>/.

This script is run ONCE, by a human, and the output is committed.
CI does NOT re-run it (would require a Python toolchain in CI).

Re-run when:
- The spec adds or removes a fixture.
- An upstream cryptographic library changes its default output format
  enough to break our fixture parsing.

Requires: Python 3.10+, cryptography>=41.

Run from the repo root:
    python3 scripts/gen-negative-fixtures.py

Anchor timestamp (`AT`): all chains are constructed relative to a
fixed point so the `expired-dac` and `not-yet-valid-dac` fixtures'
relative validity windows survive regeneration. The same timestamp
must be threaded into the integration test (tests/attestation_negative.rs).
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

# Anchor: tests pin `at` to this. Encoded as Matter-time seconds
# (offset from 2000-01-01T00:00:00Z) — see crates/matter-cert/src/time.rs.
AT_UNIX = 1_800_000_000  # 2027-01-15T08:00:00Z — round number, mid-decade.
AT = datetime.fromtimestamp(AT_UNIX, tz=timezone.utc)

OUT_DIR = Path(__file__).resolve().parent.parent / "test-vectors" / "certs" / "attestation" / "negative"

MATTER_VID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.37244.2.1")
MATTER_PID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.37244.2.2")


def matter_vid(v: int) -> x509.NameAttribute:
    return x509.NameAttribute(MATTER_VID_OID, f"{v:04X}")


def matter_pid(p: int) -> x509.NameAttribute:
    return x509.NameAttribute(MATTER_PID_OID, f"{p:04X}")


def new_p256_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def build_paa(
    common_name: str = "Matter Test PAA (synthetic)",
    vid: int | None = 0xFFF1,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = new_p256_key()
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if vid is not None:
        attrs.append(matter_vid(vid))
    subj = x509.Name(attrs)
    nb = not_before or (AT - timedelta(days=365))
    na = not_after or (AT + timedelta(days=365 * 10))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)  # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def build_pai(
    paa_cert: x509.Certificate,
    paa_key: ec.EllipticCurvePrivateKey,
    common_name: str = "Matter Test PAI (synthetic)",
    vid: int = 0xFFF1,
    pid: int | None = 0x8000,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = new_p256_key()
    attrs = [
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        matter_vid(vid),
    ]
    if pid is not None:
        attrs.append(matter_pid(pid))
    subj = x509.Name(attrs)
    nb = not_before or (AT - timedelta(days=180))
    na = not_after or (AT + timedelta(days=365 * 5))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(paa_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(paa_key, hashes.SHA256())
    )
    return cert, key


def build_dac(
    pai_cert: x509.Certificate,
    pai_key: ec.EllipticCurvePrivateKey,
    common_name: str = "Matter Test DAC (synthetic)",
    vid: int = 0xFFF1,
    pid: int = 0x8000,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    include_client_auth_eku: bool = True,
    eku_override: list[x509.ObjectIdentifier] | None = None,
    is_ca: bool = False,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = new_p256_key()
    subj = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        matter_vid(vid),
        matter_pid(pid),
    ])
    nb = not_before or (AT - timedelta(days=30))
    na = not_after or (AT + timedelta(days=365))
    b = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(pai_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    if eku_override is not None:
        b = b.add_extension(x509.ExtendedKeyUsage(eku_override), critical=False)
    elif include_client_auth_eku:
        b = b.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    cert = b.sign(pai_key, hashes.SHA256())
    return cert, key


def write_fixture(name: str, paa: x509.Certificate, pai: x509.Certificate, dac: x509.Certificate) -> None:
    d = OUT_DIR / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "paa.der").write_bytes(paa.public_bytes(serialization.Encoding.DER))
    (d / "pai.der").write_bytes(pai.public_bytes(serialization.Encoding.DER))
    (d / "dac.der").write_bytes(dac.public_bytes(serialization.Encoding.DER))
    print(f"wrote {name}/  ({d})")


def flip_signature_byte(cert_der: bytes) -> bytes:
    """Flip one bit in the signatureValue at the end of an X.509 cert.

    X.509 DER structure: SEQUENCE { tbsCertificate, signatureAlgorithm,
    signatureValue (BIT STRING) }. The signatureValue is the last
    element; the BIT STRING content is the last ~70 bytes for ECDSA
    P-256. Flipping any byte in that range invalidates the signature
    without altering the cert structure.
    """
    arr = bytearray(cert_der)
    arr[-2] ^= 0x01
    return bytes(arr)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. expired-dac
    paa, paa_key = build_paa()
    pai, pai_key = build_pai(paa, paa_key)
    dac, _ = build_dac(pai, pai_key, not_after=AT - timedelta(days=1))
    write_fixture("expired-dac", paa, pai, dac)

    # 2. not-yet-valid-dac
    paa, paa_key = build_paa()
    pai, pai_key = build_pai(paa, paa_key)
    dac, _ = build_dac(pai, pai_key, not_before=AT + timedelta(days=30))
    write_fixture("not-yet-valid-dac", paa, pai, dac)

    # 3. broken-dac-sig
    paa, paa_key = build_paa()
    pai, pai_key = build_pai(paa, paa_key)
    dac, _ = build_dac(pai, pai_key)
    dac_broken_der = flip_signature_byte(dac.public_bytes(serialization.Encoding.DER))
    d = OUT_DIR / "broken-dac-sig"
    d.mkdir(parents=True, exist_ok=True)
    (d / "paa.der").write_bytes(paa.public_bytes(serialization.Encoding.DER))
    (d / "pai.der").write_bytes(pai.public_bytes(serialization.Encoding.DER))
    (d / "dac.der").write_bytes(dac_broken_der)
    print("wrote broken-dac-sig/")

    # 4. broken-pai-sig
    paa, paa_key = build_paa()
    pai, pai_key = build_pai(paa, paa_key)
    dac, _ = build_dac(pai, pai_key)
    pai_broken_der = flip_signature_byte(pai.public_bytes(serialization.Encoding.DER))
    d = OUT_DIR / "broken-pai-sig"
    d.mkdir(parents=True, exist_ok=True)
    (d / "paa.der").write_bytes(paa.public_bytes(serialization.Encoding.DER))
    (d / "pai.der").write_bytes(pai_broken_der)
    (d / "dac.der").write_bytes(dac.public_bytes(serialization.Encoding.DER))
    print("wrote broken-pai-sig/")

    # 5. wrong-vid-dac
    paa, paa_key = build_paa(vid=0xFFF1)
    pai, pai_key = build_pai(paa, paa_key, vid=0xFFF1, pid=0x8000)
    dac, _ = build_dac(pai, pai_key, vid=0xFFF2, pid=0x8000)  # different VID
    write_fixture("wrong-vid-dac", paa, pai, dac)

    # 6. untrusted-paa
    # Chain is internally valid but rooted in a PAA the trust store
    # won't have. The integration test puts a *different* (valid)
    # synthetic PAA into the trust store.
    paa, paa_key = build_paa(common_name="Matter Test PAA-OTHER (synthetic)")
    pai, pai_key = build_pai(paa, paa_key)
    dac, _ = build_dac(pai, pai_key)
    write_fixture("untrusted-paa", paa, pai, dac)

    # 7. dac-with-ca-bit
    paa, paa_key = build_paa()
    pai, pai_key = build_pai(paa, paa_key)
    dac, _ = build_dac(pai, pai_key, is_ca=True)
    write_fixture("dac-with-ca-bit", paa, pai, dac)

    # 8. wrong-eku
    # DAC has an EKU extension but with id-kp-serverAuth instead of
    # id-kp-clientAuth. webpki's `KeyUsage::client_auth()` rejects this
    # because it requires the leaf cert's EKU to contain clientAuth.
    # An *absent* EKU would actually pass (RFC 5280 §4.2.1.12: no
    # constraint means all usages permitted) — so a "missing-eku"
    # fixture wouldn't exercise the rejection path.
    paa, paa_key = build_paa()
    pai, pai_key = build_pai(paa, paa_key)
    dac, _ = build_dac(
        pai, pai_key,
        include_client_auth_eku=False,
        eku_override=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    write_fixture("wrong-eku", paa, pai, dac)

    print(f"\nDone. Tests should pin `at` to MatterTime::from_unix_secs({AT_UNIX})")


if __name__ == "__main__":
    main()
