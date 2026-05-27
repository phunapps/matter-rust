#!/usr/bin/env python3
"""
Generate the 8 negative-path NOCSR fixtures for matter-commissioning's
M6.3.2 integration test (`tests/noc_negative.rs`).

Run once; output is committed under
`test-vectors/commissioning/noc/negative/`. CI does NOT recompute.

Each fixture is a JSON document with:
  - kind: identifier matching the Rust test's match arm
  - nocsr_elements_b64: base64 of the (possibly tampered) NOCSR TLV blob
  - attestation_signature_b64: base64 of the 64-byte raw ECDSA sig
  - expected_csr_nonce_hex: 64-hex-char (32 byte) commissioner nonce
  - attestation_challenge_hex: 32-hex-char (16 byte) PASE attestation challenge
  - dac_public_key_b64: base64 of the 65-byte SEC1 uncompressed DAC pubkey

Dependencies: `cryptography>=42`.
"""
import base64
import json
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography import x509
except ImportError:
    sys.stderr.write("install with: pip install cryptography\n")
    sys.exit(1)


OUT_DIR = Path(__file__).resolve().parent.parent / "test-vectors" / "commissioning" / "noc" / "negative"


def sec1_uncompressed(pubkey: ec.EllipticCurvePublicKey) -> bytes:
    return pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def raw_ecdsa_sign(privkey: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    sig_der = privkey.sign(msg, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def make_pkcs10(csr_key: ec.EllipticCurvePrivateKey) -> bytes:
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
    csr = builder.sign(csr_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER)


def encode_tlv_struct(fields):
    """Encode an anonymous TLV structure with context-tagged octet strings.

    Matter TLV control byte for an anonymous structure is 0x15; ending byte is
    0x18. Context-tagged octet strings use:
      0x30 (octet string, 1-byte length, context tag) + tag + len(1B) + bytes
      0x31 (octet string, 2-byte length, context tag) + tag + len(2B,LE) + bytes
    """
    out = bytearray([0x15])  # structure, anonymous
    for tag, value in fields:
        ln = len(value)
        if ln <= 0xFF:
            out.append(0x30)
            out.append(tag)
            out.append(ln)
        elif ln <= 0xFFFF:
            out.append(0x31)
            out.append(tag)
            out += struct.pack("<H", ln)
        else:
            raise ValueError("test fixture: octet string too large")
        out += value
    out.append(0x18)  # end of container
    return bytes(out)


def build_fixture(kind, csr_priv_seed, dac_priv_seed, nonce, challenge, *, mutate=None):
    csr_key = ec.derive_private_key(csr_priv_seed, ec.SECP256R1())
    dac_key = ec.derive_private_key(dac_priv_seed, ec.SECP256R1())
    dac_pub = sec1_uncompressed(dac_key.public_key())

    csr_der = make_pkcs10(csr_key)
    elements = encode_tlv_struct([(1, csr_der), (2, nonce)])

    tbs = elements + challenge
    att_sig = raw_ecdsa_sign(dac_key, tbs)

    if mutate is not None:
        elements, att_sig, dac_pub, nonce, challenge = mutate(elements, att_sig, dac_pub, nonce, challenge)

    return {
        "kind": kind,
        "nocsr_elements_b64": base64.b64encode(elements).decode(),
        "attestation_signature_b64": base64.b64encode(att_sig).decode(),
        "expected_csr_nonce_hex": nonce.hex(),
        "attestation_challenge_hex": challenge.hex(),
        "dac_public_key_b64": base64.b64encode(dac_pub).decode(),
    }


def _flip_byte(buf, idx):
    arr = bytearray(buf)
    arr[idx] ^= 0x80
    return bytes(arr)


def write_fixture(d):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{d['kind']}.json"
    path.write_text(json.dumps(d, indent=2) + "\n")
    print(f"wrote {path}")


def main():
    nonce = bytes.fromhex("33" * 32)
    challenge = bytes.fromhex("77" * 16)

    # 1. bad-csr-self-sig: flip a byte inside the CSR signature, then re-sign attestation.
    # The NOCSR TLV layout is: 0x15 | 0x30 tag | 0x01 | len(csr_der) | csr_der | 0x30 0x02 0x20 | nonce | 0x18
    # The CSR DER starts at offset 4 (after the 1-byte struct header + 3-byte field header).
    # We flip a byte near the END of the CSR DER (4 bytes before csr ends) to corrupt its signature.
    # That index in elements = 4 + len(csr_der) - 4 = len(csr_der).
    def mut_bad_csr_self_sig(elements, att_sig, dac_pub, n, c):
        # Determine CSR DER length from the elements TLV header (bytes [2] is the 1-byte length).
        csr_der_len = elements[3]  # 0x15, 0x30, 0x01, <len>, csr_bytes...
        # Flip a byte 4 bytes before the end of the CSR DER to corrupt its signature.
        flip_idx = 4 + csr_der_len - 4
        elements = _flip_byte(elements, flip_idx)
        return elements, att_sig, dac_pub, n, c

    f1 = build_fixture("bad-csr-self-sig", 0x101, 0x201, nonce, challenge, mutate=mut_bad_csr_self_sig)
    dac_key_f1 = ec.derive_private_key(0x201, ec.SECP256R1())
    mutated_elements_f1 = base64.b64decode(f1["nocsr_elements_b64"])
    new_sig_f1 = raw_ecdsa_sign(dac_key_f1, mutated_elements_f1 + challenge)
    f1["attestation_signature_b64"] = base64.b64encode(new_sig_f1).decode()
    write_fixture(f1)

    # 2. wrong-nonce-echo: device echoes a different nonce; commissioner expects `nonce`.
    different_nonce = bytes.fromhex("AA" * 32)

    def mut_wrong_nonce(elements, att_sig, dac_pub, n, c):
        csr_key = ec.derive_private_key(0x102, ec.SECP256R1())
        new_csr = make_pkcs10(csr_key)
        new_elements = encode_tlv_struct([(1, new_csr), (2, different_nonce)])
        dac_key = ec.derive_private_key(0x202, ec.SECP256R1())
        new_sig = raw_ecdsa_sign(dac_key, new_elements + c)
        new_dac_pub = sec1_uncompressed(dac_key.public_key())
        return new_elements, new_sig, new_dac_pub, n, c

    f2 = build_fixture("wrong-nonce-echo", 0x102, 0x202, nonce, challenge, mutate=mut_wrong_nonce)
    write_fixture(f2)

    # 3. bad-att-sig: flip a byte in attestation_signature.
    def mut_bad_att_sig(elements, att_sig, dac_pub, n, c):
        att_sig = _flip_byte(att_sig, 0)
        return elements, att_sig, dac_pub, n, c

    f3 = build_fixture("bad-att-sig", 0x103, 0x203, nonce, challenge, mutate=mut_bad_att_sig)
    write_fixture(f3)

    # 4. non-p256-csr-key: a deliberately-invalid CSR.
    def mut_non_p256_csr_key(elements, att_sig, dac_pub, n, c):
        elements = encode_tlv_struct([(1, b"\x30\x03\x02\x01\x00"), (2, n)])
        dac_key = ec.derive_private_key(0x204, ec.SECP256R1())
        new_sig = raw_ecdsa_sign(dac_key, elements + c)
        new_dac_pub = sec1_uncompressed(dac_key.public_key())
        return elements, new_sig, new_dac_pub, n, c

    f4 = build_fixture("non-p256-csr-key", 0x104, 0x204, nonce, challenge, mutate=mut_non_p256_csr_key)
    write_fixture(f4)

    # 5. malformed-nocsr-tlv: truncate the elements buffer.
    def mut_malformed_nocsr_tlv(elements, att_sig, dac_pub, n, c):
        elements = elements[:-2]
        return elements, att_sig, dac_pub, n, c

    f5 = build_fixture("malformed-nocsr-tlv", 0x105, 0x205, nonce, challenge, mutate=mut_malformed_nocsr_tlv)
    write_fixture(f5)

    # 6. malformed-pkcs10: truncate the embedded CSR DER.
    def mut_malformed_pkcs10(elements, att_sig, dac_pub, n, c):
        csr_key = ec.derive_private_key(0x106, ec.SECP256R1())
        full_csr = make_pkcs10(csr_key)
        elements = encode_tlv_struct([(1, full_csr[:20]), (2, n)])
        dac_key = ec.derive_private_key(0x206, ec.SECP256R1())
        new_sig = raw_ecdsa_sign(dac_key, elements + c)
        new_dac_pub = sec1_uncompressed(dac_key.public_key())
        return elements, new_sig, new_dac_pub, n, c

    f6 = build_fixture("malformed-pkcs10", 0x106, 0x206, nonce, challenge, mutate=mut_malformed_pkcs10)
    write_fixture(f6)

    # 7. oversized-dn-attribute: emit a structurally-OK NOCSR; the Rust test
    # exercises the DN overflow path via issue_noc directly.
    f7 = build_fixture("oversized-dn-attribute", 0x107, 0x207, nonce, challenge)
    write_fixture(f7)

    # 8. wrong-challenge: commissioner passes a different challenge than the
    # device signed over. Mutate only the JSON's challenge field.
    def mut_wrong_challenge(elements, att_sig, dac_pub, n, c):
        return elements, att_sig, dac_pub, n, bytes(16)

    f8 = build_fixture("wrong-challenge", 0x108, 0x208, nonce, challenge, mutate=mut_wrong_challenge)
    write_fixture(f8)


if __name__ == "__main__":
    main()
