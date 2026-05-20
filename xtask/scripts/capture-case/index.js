// xtask/scripts/capture-case/index.js
//
// Drive matter.js's CASE primitives with FIXED scalars and capture
// every wire message as JSON fixtures consumed by
// crates/matter-crypto/tests/case_byte_parity.rs.
//
// IMPLEMENTATION NOTES (M4.3 Task 3):
//
// Strategy: generate certs with normal crypto (different each run), capture
// all key material in the JSON fixture, then build CASE messages using the
// fixed scalars from `scalars_hex_in_order` for the ephemeral keypairs.
//
// WHY NOT USE FixedRng FOR THIS:
//   matter.js's NodeJsStyleCrypto.createKeyPair() calls ECDH.generateKeys()
//   internally — it does NOT consume from randomBytes(). So the FixedRng
//   monkey-patch cannot control the ephemeral keypairs via createKeyPair().
//   Instead we build ephemeral keypairs directly from the fixed scalar bytes
//   using Node.js's ECDH.setPrivateKey(), bypassing the RNG entirely.
//
// APPROACH FOR SIGMA1 (and later Sigma2/Sigma3):
//   1. Create fresh RCAC + ICAC + NOCs via CertificateAuthority (normal RNG)
//   2. Capture all cert bytes + private key PKCS8 bytes in the fixture
//   3. Build ephemeral keypairs from the fixed scalar bytes
//   4. Compute dest_id, encode Sigma1 with TlvCaseSigma1
//
// The RCAC public key bytes in the fixture match what Rust's compute_dest_id
// receives, so dest_id is identical on both sides for the same inputs.

import { createRequire } from 'node:module';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { NodeJsStyleCrypto } from '@matter/general';
import { CertificateAuthority } from '@matter/protocol';
import { FabricId, NodeId } from '@matter/types';
// @noble/curves/nist.js provides RFC 6979 DETERMINISTIC ECDSA-P256-SHA256.
// Node.js's crypto.createSign does NOT use RFC 6979 (random nonce each call).
// Ring (Rust) uses RFC 6979. We must use noble/curves to get matching signatures.
import { p256 as nobleP256 } from '@noble/curves/nist.js';

const require = createRequire(import.meta.url);
const nodeCrypto = require('crypto');

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const OUT_DIR = join(REPO_ROOT, 'test-vectors', 'case');
mkdirSync(OUT_DIR, { recursive: true });

// @matter/protocol does not re-export the internal session/case/ modules in its
// package.json "exports" map, so we import by absolute file path.
const CASE_MESSAGES_PATH = join(
    __dirname,
    'node_modules/@matter/protocol/dist/esm/session/case/CaseMessages.js',
);
const {
    TlvCaseSigma1,
    TlvCaseSigma2,
    TlvCaseSigma3,
    TlvCaseSigma2Resume,
    TlvEncryptedDataSigma2,
    TlvEncryptedDataSigma3,
    TlvSignedData,
    KDFSR2_INFO,
    KDFSR3_INFO,
    KDFSR2_KEY_INFO,
    RESUME2_MIC_NONCE,
    TBE_DATA2_NONCE,
    TBE_DATA3_NONCE,
} = await import(CASE_MESSAGES_PATH);

// ---------------------------------------------------------------------------
// Helpers: raw crypto via Node.js (not matter.js wrappers)
// These work on Buffer/Uint8Array directly.
// ---------------------------------------------------------------------------

/** HMAC-SHA256(key, data) → 32-byte Buffer */
function hmacSha256(key, data) {
    const hmac = nodeCrypto.createHmac('sha256', key);
    hmac.update(data);
    return hmac.digest();
}

/** HKDF-SHA256(ikm, salt, info, length) → Buffer of `length` bytes */
function hkdf(ikm, salt, info, length) {
    return new Promise((resolve, reject) => {
        nodeCrypto.hkdf('sha256', ikm, salt, info, length, (err, derived) => {
            if (err) reject(err);
            else resolve(Buffer.from(derived));
        });
    });
}

/** SHA-256(data) → 32-byte Buffer. `data` may be a single Buffer or Array of Buffers. */
function sha256(...chunks) {
    const h = nodeCrypto.createHash('sha256');
    for (const c of chunks) h.update(c);
    return h.digest();
}

/**
 * AES-128-CCM encrypt: ciphertext || 16-byte tag.
 * Matches matter.js: encrypt(key, plaintext, nonce, aad?).
 */
function aesCcmEncrypt(key, plaintext, nonce, aad) {
    const cipher = nodeCrypto.createCipheriv('aes-128-ccm', key, nonce, {
        authTagLength: 16,
    });
    if (aad && aad.length > 0) {
        cipher.setAAD(aad, { plaintextLength: plaintext.length });
    }
    const ct = cipher.update(plaintext);
    cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([ct, tag]);
}

/**
 * Derive an ephemeral P-256 keypair from a fixed 32-byte private key scalar.
 * Returns { privateKey: Buffer(32), publicKey: Buffer(65) }.
 */
function ephKeypairFromScalar(privKeyHex) {
    const priv = Buffer.from(privKeyHex, 'hex');
    const ecdh = nodeCrypto.createECDH('prime256v1');
    ecdh.setPrivateKey(priv);
    return {
        privateKey: priv,
        publicKey: ecdh.getPublicKey(), // 65 bytes, uncompressed
    };
}

/**
 * ECDH shared secret: X-coordinate of scalar * peerPublicKey.
 * Returns 32-byte Buffer.
 */
function ecdhSharedSecret(privKey, peerPubKey) {
    const ecdh = nodeCrypto.createECDH('prime256v1');
    ecdh.setPrivateKey(privKey);
    return ecdh.computeSecret(peerPubKey); // returns 32-byte X coordinate
}

/**
 * Export a P-256 private key (raw 32-byte scalar) as PKCS#8 DER bytes.
 * ring's EcdsaKeyPair::from_pkcs8 requires this format.
 */
function toPkcs8Der(privKeyBytes, pubKeyBytes) {
    const xBytes = pubKeyBytes.slice(1, 33);
    const yBytes = pubKeyBytes.slice(33, 65);
    const jwk = {
        kty: 'EC',
        crv: 'P-256',
        d: privKeyBytes.toString('base64url'),
        x: xBytes.toString('base64url'),
        y: yBytes.toString('base64url'),
    };
    const privKeyNode = nodeCrypto.createPrivateKey({ key: jwk, format: 'jwk' });
    return Buffer.from(privKeyNode.export({ type: 'pkcs8', format: 'der' }));
}

/**
 * Sign data with an ECDSA-P256 private key; returns 64-byte r||s (IEEE P1363 format).
 * Mirrors matter.js's NodeJsStyleCrypto.signEcdsa which uses dsaEncoding: 'ieee-p1363'.
 */
function ecdsaSign(privKeyPkcs8OrBytes, pubKeyBytes, data) {
    // Build a JWK and import via Node's createPrivateKey
    let privKeyNode;
    const xBytes = pubKeyBytes.slice(1, 33);
    const yBytes = pubKeyBytes.slice(33, 65);
    const jwk = {
        kty: 'EC',
        crv: 'P-256',
        d: privKeyBytes(privKeyPkcs8OrBytes).toString('base64url'),
        x: xBytes.toString('base64url'),
        y: yBytes.toString('base64url'),
    };
    privKeyNode = nodeCrypto.createPrivateKey({ key: jwk, format: 'jwk' });
    const signer = nodeCrypto.createSign('sha256');
    signer.update(data);
    return signer.sign({
        key: privKeyNode,
        dsaEncoding: 'ieee-p1363',
    });
}

/** Extract raw 32-byte private key scalar from a Buffer that is either raw 32 bytes or PKCS#8. */
function privKeyBytes(input) {
    if (input.length === 32) return input;
    // Parse PKCS#8 DER: the raw scalar is at a fixed offset.
    // Standard PKCS#8 P-256 structure: ... ECPrivateKey ... where the scalar is at offset 36.
    // Use Node.js to extract.
    const key = nodeCrypto.createPrivateKey({ key: input, format: 'der', type: 'pkcs8' });
    const jwk = key.export({ format: 'jwk' });
    return Buffer.from(jwk.d, 'base64url');
}

/**
 * Sign `data` with a raw 32-byte P-256 private key scalar.
 * Returns 64-byte r||s (compact format, IEEE P1363).
 *
 * IMPORTANT: Uses @noble/curves RFC 6979 DETERMINISTIC ECDSA.
 * Node.js crypto.createSign is NOT deterministic (uses random nonce per call).
 * ring (Rust) uses p256::ecdsa which IS deterministic (RFC 6979). Using noble/curves
 * ensures the JS and Rust signatures are identical for the same key + data.
 *
 * @noble/curves p256.sign(msg, key) hashes `msg` internally with SHA-256 before
 * RFC 6979 nonce generation (default prehash = true). The Rust p256::ecdsa::Signer
 * trait's sign(message) also hashes internally. Both compute sign(SHA-256(data))
 * with the same RFC 6979 nonce, producing identical signatures.
 *
 * DO NOT pre-hash `data` before calling this function — that would cause
 * double-hashing (sign(SHA-256(SHA-256(data)))) which mismatches Rust.
 */
function ecdsaSignRaw(privKeyRaw, _pubKey65, data) {
    // Pass raw `data` — noble/curves hashes it internally with SHA-256.
    // The Rust p256 signer also hashes internally. Both produce the same signature.
    const sig = nobleP256.sign(data, new Uint8Array(privKeyRaw));
    // sig is a compact 64-byte Uint8Array (r || s)
    return Buffer.from(sig);
}

// ---------------------------------------------------------------------------
// Fabric setup
// ---------------------------------------------------------------------------

/**
 * Set up a test fabric using matter.js's CertificateAuthority.
 * Returns all fabric parameters needed by both captureHandshake() and
 * the Rust fixture inputs.
 *
 * The crypto used here is the real system RNG — certs differ per run.
 * All the material is captured in the fixture so Rust can reproduce it.
 *
 * @param {number|bigint} fabricId
 * @param {number|bigint} initiatorNodeId
 * @param {number|bigint} responderNodeId
 * @param {Buffer} ipk  — 16-byte Identity Protection Key (fixed per scenario)
 */
async function setUpTestFabric(fabricId, initiatorNodeId, responderNodeId, ipk) {
    const crypto = new NodeJsStyleCrypto(nodeCrypto);

    // Build a 3-tier CA: RCAC (self-signed) → ICAC → NOC.
    const ca = await CertificateAuthority.create(crypto, undefined, true);
    await ca.construction;

    const rcacBytes = Buffer.from(ca.rootCert);
    // The RCAC public key lives in ca.config.rootKeyPair.publicKey (65-byte SEC1 uncompressed).
    // When the CA was created with generateIntermediateCert=true the rootKeyPair may not be
    // directly available (the ICAC key is used for signing NOCs). We still need the RCAC
    // public key for compute_dest_id. Extract it from the config.
    const caConfig = ca.config;
    // `rootKeyPair` is exposed in caConfig as BinaryKeyPair { publicKey, privateKey }
    // when generateIntermediateCert=true. See CertificateAuthority.js line 99.
    const rcacPublicKey = Buffer.from(caConfig.rootKeyPair.publicKey);

    // Generate initiator NOC keypair + NOC.
    const initEcdhForNoc = nodeCrypto.createECDH('prime256v1');
    initEcdhForNoc.generateKeys();
    const initNocPrivRaw = initEcdhForNoc.getPrivateKey();
    // Pad to 32 bytes (Node may return fewer MSBs if they are 0).
    const initNocPriv = Buffer.alloc(32);
    initNocPriv.set(initNocPrivRaw, 32 - initNocPrivRaw.length);
    const initNocPub = Buffer.from(initEcdhForNoc.getPublicKey()); // 65 bytes
    const initNocBytes = Buffer.from(
        await ca.generateNoc(
            new Uint8Array(initNocPub),
            FabricId(BigInt(fabricId)),
            NodeId(BigInt(initiatorNodeId)),
            undefined,
        ),
    );

    // Generate responder NOC keypair + NOC.
    const respEcdhForNoc = nodeCrypto.createECDH('prime256v1');
    respEcdhForNoc.generateKeys();
    const respNocPrivRaw = respEcdhForNoc.getPrivateKey();
    const respNocPriv = Buffer.alloc(32);
    respNocPriv.set(respNocPrivRaw, 32 - respNocPrivRaw.length);
    const respNocPub = Buffer.from(respEcdhForNoc.getPublicKey()); // 65 bytes
    const respNocBytes = Buffer.from(
        await ca.generateNoc(
            new Uint8Array(respNocPub),
            FabricId(BigInt(fabricId)),
            NodeId(BigInt(responderNodeId)),
            undefined,
        ),
    );

    // Export NOC private keys as PKCS#8 DER so the Rust RingSigner can load them.
    const initNocPkcs8 = toPkcs8Der(initNocPriv, initNocPub);
    const respNocPkcs8 = toPkcs8Der(respNocPriv, respNocPub);

    // Extract ICAC bytes if the CA generated one (3-tier PKI).
    // The ICAC must be included in Sigma2/Sigma3 TBEData so the peer can verify
    // the NOC chain: NOC → ICAC → RCAC.
    let icacBytes = null;
    try {
        const icacCert = ca.icacCert;
        if (icacCert) icacBytes = Buffer.from(icacCert);
    } catch (_) {
        // No ICAC in 2-tier PKI; leave icacBytes as null.
    }

    return {
        fabricId: BigInt(fabricId),
        initiatorNodeId: BigInt(initiatorNodeId),
        responderNodeId: BigInt(responderNodeId),
        ipk,
        rcacBytes,
        rcacPublicKey,
        icacBytes,
        initiatorNocBytes: initNocBytes,
        initiatorNocPrivRaw: initNocPriv,
        initiatorNocPub: initNocPub,
        initiatorNocPkcs8: initNocPkcs8,
        responderNocBytes: respNocBytes,
        responderNocPrivRaw: respNocPriv,
        responderNocPub: respNocPub,
        responderNocPkcs8: respNocPkcs8,
    };
}

// ---------------------------------------------------------------------------
// Sigma1 builder
// ---------------------------------------------------------------------------

/**
 * Compute DestinationId for Sigma1.
 *
 * Matter Core Spec §4.13.2.4 / matter.js Fabric.#generateSalt:
 *   salt = initiatorRandom(32) || rcacPublicKey(65) || fabricId_le8 || nodeId_le8
 *   DestinationId = HMAC-SHA256(IPK, salt)
 */
function computeDestId(ipk, rcacPublicKey, fabricId, nodeId, initiatorRandom) {
    // fabric_id and node_id are stored as LE 8-byte (uint64).
    const fabricIdBuf = Buffer.alloc(8);
    fabricIdBuf.writeBigUInt64LE(BigInt(fabricId));
    const nodeIdBuf = Buffer.alloc(8);
    nodeIdBuf.writeBigUInt64LE(BigInt(nodeId));

    const salt = Buffer.concat([
        Buffer.from(initiatorRandom),
        Buffer.from(rcacPublicKey),
        fabricIdBuf,
        nodeIdBuf,
    ]);
    return hmacSha256(ipk, salt);
}

/**
 * Build and encode Sigma1.
 * Returns a Buffer of the TLV-encoded Sigma1 struct.
 */
function buildSigma1(initiatorRandom, initiatorSessionId, destId, ephPub, resumptionFields) {
    const struct = {
        initiatorRandom: new Uint8Array(initiatorRandom),
        initiatorSessionId,
        destinationId: new Uint8Array(destId),
        initiatorEcdhPublicKey: new Uint8Array(ephPub),
    };
    if (resumptionFields) {
        struct.resumptionId = new Uint8Array(resumptionFields.resumptionId);
        struct.initiatorResumeMic = new Uint8Array(resumptionFields.initiatorResumeMic);
    }
    return Buffer.from(TlvCaseSigma1.encode(struct));
}

// ---------------------------------------------------------------------------
// Sigma2 builder
// ---------------------------------------------------------------------------

/**
 * Build and encode Sigma2.
 *
 * Steps (mirrors matter.js CaseServer.js #newSession):
 *   1. ECDH shared secret from responder eph priv + initiator eph pub.
 *   2. Sigma2 salt = IPK(16) || responderRandom(32) || responderEphPub(65) || SHA-256(sigma1Bytes)
 *   3. S2K = HKDF(secret=sharedSecret, salt=sigma2Salt, info="Sigma2", len=16)
 *   4. Generate new 16-byte resumptionId.
 *   5. TBSData2 = TlvSignedData { responderNoc, responderIcac?, responderPub, initiatorPub }
 *   6. signature = ECDSA(responder NOC private key, TBSData2)
 *   7. TBEData2 = TlvEncryptedDataSigma2 { responderNoc, responderIcac?, signature, resumptionId }
 *   8. encrypted = AES-CCM(S2K, TBEData2, nonce="NCASE_Sigma2N")
 *   9. Sigma2 = TlvCaseSigma2 { responderRandom, responderSessionId=0, responderEphPub, encrypted }
 */
async function buildSigma2(fabric, respEphPriv, respEphPub, initEphPub, responderRandom, sigma1Bytes, newResumptionId) {
    // 1. ECDH
    const sharedSecret = ecdhSharedSecret(respEphPriv, initEphPub);

    // 2. Sigma2 salt
    const sigma1Hash = sha256(sigma1Bytes);
    const sigma2Salt = Buffer.concat([
        fabric.ipk,
        Buffer.from(responderRandom),
        Buffer.from(respEphPub),
        sigma1Hash,
    ]);

    // 3. S2K
    const s2k = await hkdf(sharedSecret, sigma2Salt, Buffer.from(KDFSR2_INFO), 16);

    // 4. resumptionId already supplied as parameter

    // 5. TBSData2 — signed data structure
    // Include ICAC when present (matter.js CaseServer includes it when the CA has one).
    const tbsData2Fields = {
        responderNoc: new Uint8Array(fabric.responderNocBytes),
        responderPublicKey: new Uint8Array(respEphPub),
        initiatorPublicKey: new Uint8Array(initEphPub),
    };
    if (fabric.icacBytes) {
        tbsData2Fields.responderIcac = new Uint8Array(fabric.icacBytes);
    }
    const tbsData2 = Buffer.from(TlvSignedData.encode(tbsData2Fields));

    // 6. signature — ECDSA-P256-SHA256 over TBSData2
    const signature = ecdsaSignRaw(fabric.responderNocPrivRaw, fabric.responderNocPub, tbsData2);

    // 7. TBEData2
    const tbeData2Fields = {
        responderNoc: new Uint8Array(fabric.responderNocBytes),
        signature: new Uint8Array(signature),
        resumptionId: new Uint8Array(newResumptionId),
    };
    if (fabric.icacBytes) {
        tbeData2Fields.responderIcac = new Uint8Array(fabric.icacBytes);
    }
    const tbeData2 = Buffer.from(TlvEncryptedDataSigma2.encode(tbeData2Fields));

    // 8. AES-CCM encrypt
    const nonce = Buffer.from(TBE_DATA2_NONCE);
    const encrypted = aesCcmEncrypt(s2k, tbeData2, nonce, Buffer.alloc(0));

    // 9. Sigma2 struct
    const sigma2Struct = {
        responderRandom: new Uint8Array(responderRandom),
        responderSessionId: 0,
        responderEcdhPublicKey: new Uint8Array(respEphPub),
        encrypted: new Uint8Array(encrypted),
    };

    return {
        bytes: Buffer.from(TlvCaseSigma2.encode(sigma2Struct)),
        sharedSecret,
        resumptionId: newResumptionId,
    };
}

// ---------------------------------------------------------------------------
// Sigma3 builder
// ---------------------------------------------------------------------------

/**
 * Build and encode Sigma3.
 *
 * Steps (mirrors matter.js CaseClient.js):
 *   1. Sigma3 salt = IPK(16) || SHA-256(sigma1Bytes || sigma2Bytes)
 *   2. S3K = HKDF(secret=sharedSecret, salt=sigma3Salt, info="Sigma3", len=16)
 *   3. TBSData3 = TlvSignedData { initiatorNoc, initiatorIcac?, initiatorEphPub, responderEphPub }
 *      NOTE: In Sigma3, initiator plays the "responder" role in TlvSignedData field names
 *            (field names were defined from Sigma2's perspective). So:
 *              responderNoc = initiator's NOC
 *              responderPublicKey = initiator's eph pub
 *              initiatorPublicKey = responder's eph pub
 *   4. signature = ECDSA(initiator NOC private key, TBSData3)
 *   5. TBEData3 = TlvEncryptedDataSigma3 { initiatorNoc, initiatorIcac?, signature }
 *      NOTE: field is named responderNoc in TlvEncryptedDataSigma3 but holds initiator's NOC
 *   6. encrypted = AES-CCM(S3K, TBEData3, nonce="NCASE_Sigma3N")
 *   7. Sigma3 = TlvCaseSigma3 { encrypted }
 */
async function buildSigma3(fabric, initEphPriv, initEphPub, respEphPub, sharedSecret, sigma1Bytes, sigma2Bytes) {
    // 1. Sigma3 salt
    const transcript12 = sha256(sigma1Bytes, sigma2Bytes);
    const sigma3Salt = Buffer.concat([fabric.ipk, transcript12]);

    // 2. S3K
    const s3k = await hkdf(sharedSecret, sigma3Salt, Buffer.from(KDFSR3_INFO), 16);

    // 3. TBSData3 — initiator signs with its NOC key
    //    responderNoc = initiator's NOC (field names from Sigma2 perspective)
    //    responderPublicKey = initiator's eph pub
    //    initiatorPublicKey = responder's eph pub
    //    Include ICAC when present (same CA for both nodes in this test fabric).
    const tbsData3Fields = {
        responderNoc: new Uint8Array(fabric.initiatorNocBytes),
        responderPublicKey: new Uint8Array(initEphPub),
        initiatorPublicKey: new Uint8Array(respEphPub),
    };
    if (fabric.icacBytes) {
        tbsData3Fields.responderIcac = new Uint8Array(fabric.icacBytes);
    }
    const tbsData3 = Buffer.from(TlvSignedData.encode(tbsData3Fields));

    // 4. signature
    const signature = ecdsaSignRaw(fabric.initiatorNocPrivRaw, fabric.initiatorNocPub, tbsData3);

    // 5. TBEData3
    //    responderNoc field holds initiator's NOC; include ICAC when present.
    const tbeData3Fields = {
        responderNoc: new Uint8Array(fabric.initiatorNocBytes),
        signature: new Uint8Array(signature),
    };
    if (fabric.icacBytes) {
        tbeData3Fields.responderIcac = new Uint8Array(fabric.icacBytes);
    }
    const tbeData3 = Buffer.from(TlvEncryptedDataSigma3.encode(tbeData3Fields));

    // 6. AES-CCM encrypt
    const nonce = Buffer.from(TBE_DATA3_NONCE);
    const encrypted = aesCcmEncrypt(s3k, tbeData3, nonce, Buffer.alloc(0));

    // 7. Sigma3 struct
    return Buffer.from(TlvCaseSigma3.encode({
        encrypted: new Uint8Array(encrypted),
    }));
}

// ---------------------------------------------------------------------------
// Drive a single handshake scenario (new-session path)
// ---------------------------------------------------------------------------

async function captureHandshake(scenario) {
    const {
        fabricId,
        initiatorNodeId,
        responderNodeId,
        ipkHex,
        initiatorEphPrivHex,
        initiatorRandomHex,
        responderEphPrivHex,
        responderRandomHex,
        newResumptionIdHex,
        resumptionRecord, // optional, for resumption scenarios
    } = scenario;

    const ipk = Buffer.from(ipkHex, 'hex');

    // Step 1: Generate test fabric (normal system RNG for certs).
    const fabric = await setUpTestFabric(fabricId, initiatorNodeId, responderNodeId, ipk);

    // Step 2: Derive ephemeral keypairs from fixed scalars.
    const initEph = ephKeypairFromScalar(initiatorEphPrivHex);
    const respEph = ephKeypairFromScalar(responderEphPrivHex);

    const initiatorRandom = Buffer.from(initiatorRandomHex, 'hex');
    const responderRandom = Buffer.from(responderRandomHex, 'hex');

    // Step 3: Build Sigma1.
    const destId = computeDestId(
        fabric.ipk,
        fabric.rcacPublicKey,
        fabric.fabricId,
        fabric.responderNodeId,
        initiatorRandom,
    );

    let resumptionFields = null;
    if (resumptionRecord) {
        // Compute sigma1_resume_mic for the resumption path.
        // Mirrors matter.js CaseClient.js (and Rust compute_sigma1_resume_mic):
        //   S1RK = HKDF(sharedSecret, initiatorRandom || resumptionId, "Sigma1_Resume", 16)
        //   mic = AES-CCM(S1RK, plaintext=[], nonce="NCASE_SigmaS1") → 16-byte tag only
        const sigma1ResumeKey = await hkdf(
            Buffer.from(resumptionRecord.sharedSecret, 'hex'),
            Buffer.concat([
                initiatorRandom,
                Buffer.from(resumptionRecord.resumptionId, 'hex'),
            ]),
            Buffer.from('Sigma1_Resume'),
            16,
        );
        const nonceSigmaS1 = Buffer.from('NCASE_SigmaS1');
        const mic = aesCcmEncrypt(sigma1ResumeKey, Buffer.alloc(0), nonceSigmaS1, Buffer.alloc(0));
        resumptionFields = {
            resumptionId: Buffer.from(resumptionRecord.resumptionId, 'hex'),
            initiatorResumeMic: mic, // 16-byte tag
        };
    }

    const sigma1Bytes = buildSigma1(initiatorRandom, 0, destId, initEph.publicKey, resumptionFields);

    // Step 4: Build Sigma2.
    const newResumptionId = Buffer.from(newResumptionIdHex, 'hex');
    const { bytes: sigma2Bytes, sharedSecret } = await buildSigma2(
        fabric,
        respEph.privateKey,
        respEph.publicKey,
        initEph.publicKey,
        responderRandom,
        sigma1Bytes,
        newResumptionId,
    );

    // Step 5: Build Sigma3.
    const sigma3Bytes = await buildSigma3(
        fabric,
        initEph.privateKey,
        initEph.publicKey,
        respEph.publicKey,
        sharedSecret,
        sigma1Bytes,
        sigma2Bytes,
    );

    const inputs = {
        fabric_id: Number(fabric.fabricId),
        initiator_node_id: Number(fabric.initiatorNodeId),
        responder_node_id: Number(fabric.responderNodeId),
        ipk: fabric.ipk.toString('hex'),
        rcac_noc: fabric.rcacBytes.toString('hex'),
        rcac_public_key: fabric.rcacPublicKey.toString('hex'),
        initiator_noc: fabric.initiatorNocBytes.toString('hex'),
        initiator_pkcs8: fabric.initiatorNocPkcs8.toString('hex'),
        responder_noc: fabric.responderNocBytes.toString('hex'),
        responder_pkcs8: fabric.responderNocPkcs8.toString('hex'),
        initiator_eph_priv: initiatorEphPrivHex,
        initiator_random: initiatorRandomHex,
        responder_eph_priv: responderEphPrivHex,
        responder_random: responderRandomHex,
    };

    if (fabric.icacBytes) {
        inputs.icac_noc = fabric.icacBytes.toString('hex');
    }

    if (resumptionRecord) {
        inputs.resumption_id = resumptionRecord.resumptionId;
        inputs.resumption_shared_secret = resumptionRecord.sharedSecret;
    }

    return {
        inputs,
        messages: {
            sigma1: sigma1Bytes.toString('hex'),
            sigma2: sigma2Bytes.toString('hex'),
            sigma3: sigma3Bytes.toString('hex'),
        },
    };
}

// ---------------------------------------------------------------------------
// Resumption scenario: compute the sigma2_resume path.
// For simplicity, share the fabric setup and capture only sigma2_resume.
// ---------------------------------------------------------------------------

async function captureResumptionAccepted(scenario) {
    // Derive fabric + sigma1 (same as new-session but with resumption fields).
    const {
        fabricId,
        initiatorNodeId,
        responderNodeId,
        ipkHex,
        initiatorEphPrivHex,
        initiatorRandomHex,
        responderRandomHex,
        newResumptionIdHex,
        resumptionRecord,
    } = scenario;

    const ipk = Buffer.from(ipkHex, 'hex');
    const fabric = await setUpTestFabric(fabricId, initiatorNodeId, responderNodeId, ipk);

    const initEph = ephKeypairFromScalar(initiatorEphPrivHex);
    const initiatorRandom = Buffer.from(initiatorRandomHex, 'hex');

    const destId = computeDestId(
        fabric.ipk,
        fabric.rcacPublicKey,
        fabric.fabricId,
        fabric.responderNodeId,
        initiatorRandom,
    );

    const sigma1ResumeKey = await hkdf(
        Buffer.from(resumptionRecord.sharedSecret, 'hex'),
        Buffer.concat([
            initiatorRandom,
            Buffer.from(resumptionRecord.resumptionId, 'hex'),
        ]),
        Buffer.from('Sigma1_Resume'),
        16,
    );
    const nonceSigmaS1 = Buffer.from('NCASE_SigmaS1');
    const mic = aesCcmEncrypt(sigma1ResumeKey, Buffer.alloc(0), nonceSigmaS1, Buffer.alloc(0));

    const sigma1Bytes = buildSigma1(initiatorRandom, 0, destId, initEph.publicKey, {
        resumptionId: Buffer.from(resumptionRecord.resumptionId, 'hex'),
        initiatorResumeMic: mic,
    });

    // Sigma2_Resume:
    //   new_resumption_id = given in scenario
    //   S2RK = HKDF(sharedSecret, initiatorRandom || newResumptionId, "Sigma2_Resume", 16)
    //   resumeMic = AES-CCM(S2RK, [], "NCASE_SigmaS2") → 16-byte tag
    const newResumptionId = Buffer.from(newResumptionIdHex, 'hex');
    const sigma2ResumeKey = await hkdf(
        Buffer.from(resumptionRecord.sharedSecret, 'hex'),
        Buffer.concat([
            initiatorRandom,
            newResumptionId,
        ]),
        Buffer.from(KDFSR2_KEY_INFO),
        16,
    );
    const nonceSigmaS2 = Buffer.from(RESUME2_MIC_NONCE);
    const resumeMic = aesCcmEncrypt(sigma2ResumeKey, Buffer.alloc(0), nonceSigmaS2, Buffer.alloc(0));

    const sigma2ResumeBytes = Buffer.from(TlvCaseSigma2Resume.encode({
        resumptionId: new Uint8Array(newResumptionId),
        resumeMic: new Uint8Array(resumeMic),
        responderSessionId: 0,
    }));

    const inputs = {
        fabric_id: Number(fabric.fabricId),
        initiator_node_id: Number(fabric.initiatorNodeId),
        responder_node_id: Number(fabric.responderNodeId),
        ipk: fabric.ipk.toString('hex'),
        rcac_noc: fabric.rcacBytes.toString('hex'),
        rcac_public_key: fabric.rcacPublicKey.toString('hex'),
        initiator_noc: fabric.initiatorNocBytes.toString('hex'),
        initiator_pkcs8: fabric.initiatorNocPkcs8.toString('hex'),
        responder_noc: fabric.responderNocBytes.toString('hex'),
        responder_pkcs8: fabric.responderNocPkcs8.toString('hex'),
        initiator_eph_priv: initiatorEphPrivHex,
        initiator_random: initiatorRandomHex,
        responder_eph_priv: 'cc'.repeat(32), // not used in resumption accepted path
        responder_random: responderRandomHex,
        resumption_id: resumptionRecord.resumptionId,
        resumption_shared_secret: resumptionRecord.sharedSecret,
    };

    if (fabric.icacBytes) {
        inputs.icac_noc = fabric.icacBytes.toString('hex');
    }

    return {
        inputs,
        messages: {
            sigma1: sigma1Bytes.toString('hex'),
            sigma2_resume: sigma2ResumeBytes.toString('hex'),
        },
    };
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

// Fixed IPK: all 0x77 (avoids RNG consumption before cert generation).
const FIXED_IPK_HEX = '77'.repeat(16);
// Fixed fabric and node IDs.
const FABRIC_ID = 1n;
const INITIATOR_NODE_ID = 1n;
const RESPONDER_NODE_ID = 2n;

// Fixed ephemeral scalars and randoms.
// These are what the Rust test injects via case_initiator_with_eph_key /
// case_responder_with_eph_key. Must be valid non-zero P-256 scalars.
const INIT_EPH_PRIV_HEX = 'aa'.repeat(32);
const INIT_RANDOM_HEX   = 'bb'.repeat(32);
const RESP_EPH_PRIV_HEX = 'cc'.repeat(32);
const RESP_RANDOM_HEX   = 'dd'.repeat(32);
// New resumption ID generated by the responder in Sigma2.
// MUST match Rust: responder.rs hardcodes [0u8; 16] in M4.1.
const NEW_RESUMPTION_ID_HEX = '00'.repeat(16);

// Resumption scenario: a prior session with known shared_secret + resumption_id.
const PRIOR_RESUMPTION_ID_HEX = '11'.repeat(16);
const PRIOR_SHARED_SECRET_HEX = '22'.repeat(16);

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const scenarios = [
    {
        id: 'handshake-new-session',
        runner: captureHandshake,
        params: {
            fabricId: FABRIC_ID,
            initiatorNodeId: INITIATOR_NODE_ID,
            responderNodeId: RESPONDER_NODE_ID,
            ipkHex: FIXED_IPK_HEX,
            initiatorEphPrivHex: INIT_EPH_PRIV_HEX,
            initiatorRandomHex: INIT_RANDOM_HEX,
            responderEphPrivHex: RESP_EPH_PRIV_HEX,
            responderRandomHex: RESP_RANDOM_HEX,
            newResumptionIdHex: NEW_RESUMPTION_ID_HEX,
        },
    },
    {
        id: 'handshake-resumption-accepted',
        runner: captureResumptionAccepted,
        params: {
            fabricId: FABRIC_ID,
            initiatorNodeId: INITIATOR_NODE_ID,
            responderNodeId: RESPONDER_NODE_ID,
            ipkHex: FIXED_IPK_HEX,
            initiatorEphPrivHex: INIT_EPH_PRIV_HEX,
            initiatorRandomHex: INIT_RANDOM_HEX,
            responderRandomHex: RESP_RANDOM_HEX,
            newResumptionIdHex: NEW_RESUMPTION_ID_HEX,
            resumptionRecord: {
                resumptionId: PRIOR_RESUMPTION_ID_HEX,
                sharedSecret: PRIOR_SHARED_SECRET_HEX,
            },
        },
    },
    {
        id: 'handshake-resumption-declined',
        runner: captureHandshake,
        params: {
            fabricId: FABRIC_ID,
            initiatorNodeId: INITIATOR_NODE_ID,
            responderNodeId: RESPONDER_NODE_ID,
            ipkHex: FIXED_IPK_HEX,
            initiatorEphPrivHex: INIT_EPH_PRIV_HEX,
            initiatorRandomHex: INIT_RANDOM_HEX,
            responderEphPrivHex: RESP_EPH_PRIV_HEX,
            responderRandomHex: RESP_RANDOM_HEX,
            newResumptionIdHex: NEW_RESUMPTION_ID_HEX,
            // Bogus resumption record: responder will decline.
            // Sigma1 includes resumption fields (same as accepted path Sigma1).
            resumptionRecord: {
                resumptionId: PRIOR_RESUMPTION_ID_HEX,
                sharedSecret: PRIOR_SHARED_SECRET_HEX,
            },
        },
    },
];

for (const scenario of scenarios) {
    try {
        const out = await scenario.runner(scenario.params);
        const outPath = join(OUT_DIR, `${scenario.id}.json`);
        writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);
        console.log(`captured ${scenario.id} -> ${outPath}`);
    } catch (err) {
        console.error(`failed ${scenario.id}: ${err.message}`);
        if (err.stack) console.error(err.stack);
        process.exitCode = 1;
    }
}
