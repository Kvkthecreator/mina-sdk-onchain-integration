// Real-circuit ECDSA verification tests for the new `verifySignedClaim`
// method.
//
// Unlike `Reclaim.test.ts` which runs with `proofsEnabled = false` to keep
// the suite fast, this file compiles the SmartContract and exercises the
// full zk path against a synthesized attestor key. One test ~60-90s on a
// modern laptop.
//
// Co-located with the existing test file so `npm test` picks it up
// automatically; not gated by env var since it's the canonical proof
// that the in-circuit ECDSA primitive actually verifies. If runtime
// becomes an issue for CI, gate with `RECLAIM_FAST_TESTS=1` and skip.

import {
  Reclaim,
  Secp256k1,
  EcdsaSecp256k1,
  AttestorDigest,
} from './Reclaim';
import {
  Bytes,
  Field,
  Keccak,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
} from 'o1js';

describe('Reclaim.verifySignedClaim (real circuit, ECDSA)', () => {
  let deployerAccount: Mina.TestPublicKey;
  let deployerKey: PrivateKey;
  let senderAccount: Mina.TestPublicKey;
  let senderKey: PrivateKey;
  let zkAppAddress: PublicKey;
  let zkAppPrivateKey: PrivateKey;
  let zkApp: Reclaim;

  // Real circuit compilation. Slow first time; subsequent test runs in the
  // same process reuse the cached prover key.
  beforeAll(async () => {
    await Reclaim.compile();
  }, 600_000);

  beforeEach(async () => {
    const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
    Mina.setActiveInstance(Local);

    deployerAccount = Local.testAccounts[0];
    deployerKey = deployerAccount.key;
    senderAccount = Local.testAccounts[1];
    senderKey = senderAccount.key;

    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new Reclaim(zkAppAddress);

    const txn = await Mina.transaction(deployerAccount, async () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      await zkApp.deploy();
    });
    await txn.prove();
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  });

  it('verifies a real ECDSA-signed claim and binds the Ethereum address', async () => {
    // 1. Generate a synthesized attestor key (would be a real Reclaim
    //    attestor in production — this test verifies the primitive
    //    independent of attestor infrastructure).
    const attestorPriv = Secp256k1.Scalar.random();
    const attestorPubBig = Secp256k1.generator.scale(attestorPriv);
    const attestorPubKey = Secp256k1.from({
      x: attestorPubBig.x.toBigInt(),
      y: attestorPubBig.y.toBigInt(),
    });

    // 2. Build a claim, hash it to a 32-byte keccak digest (Reclaim's
    //    canonical serialization: provider + "\n" + parameters + "\n" +
    //    context).
    const provider = 'http';
    const parameters = '{"url":"https://api.github.com/user"}';
    const context = '{"contextAddress":"0x0","contextMessage":"demo"}';
    const claimString = provider + '\n' + parameters + '\n' + context;
    const digestKeccak = Keccak.ethereum(Bytes.fromString(claimString));
    const digestBytes = Uint8Array.from(
      digestKeccak.bytes.map((b) => Number(b.toBigInt()))
    );
    const claimDigest = AttestorDigest.from(digestBytes);

    // 3. Sign the digest with the attestor key. signHash takes the
    //    message hash as a bigint scalar, mirroring how Reclaim attestors
    //    treat the keccak digest: as the message hash, not as bytes that
    //    get hashed again.
    const sigBig = EcdsaSecp256k1.signHash(
      digestBytesToBigInt(digestBytes),
      attestorPriv.toBigInt()
    );
    const signature = EcdsaSecp256k1.from({
      r: sigBig.r.toBigInt(),
      s: sigBig.s.toBigInt(),
    });

    // 4. Compute the attestor's expected Ethereum address off-circuit
    //    (keccak256(pubkey)[12:]) and pass as the public input the
    //    method will compare against.
    const expectedAddress = ethAddressFromPubKey(attestorPubKey);
    const expectedAddressField = Reclaim.ethAddressToField(expectedAddress);

    // 5. Submit the verifying transaction. Should prove + send cleanly —
    //    Mina.transaction / prove / send throw on failure, so reaching
    //    the post-send state without throwing is the success signal.
    const txn = await Mina.transaction(senderAccount, async () => {
      await zkApp.verifySignedClaim(
        claimDigest,
        signature,
        attestorPubKey,
        expectedAddressField
      );
    });
    await txn.prove();
    const result = await txn.sign([senderKey]).send();
    expect(result.status).toBe('pending');
  }, 600_000);

  it('rejects a signature from a different attestor key', async () => {
    const realPriv = Secp256k1.Scalar.random();
    const attackerPriv = Secp256k1.Scalar.random();
    const realPubBig = Secp256k1.generator.scale(realPriv);
    const attestorPubKey = Secp256k1.from({
      x: realPubBig.x.toBigInt(),
      y: realPubBig.y.toBigInt(),
    });

    const claimString = 'tampered\n{}\n{}';
    const digestKeccak = Keccak.ethereum(Bytes.fromString(claimString));
    const digestBytes = Uint8Array.from(
      digestKeccak.bytes.map((b) => Number(b.toBigInt()))
    );
    const claimDigest = AttestorDigest.from(digestBytes);

    // Forge with attacker key — should not validate against attestor pubkey
    const forgedSigBig = EcdsaSecp256k1.signHash(
      digestBytesToBigInt(digestBytes),
      attackerPriv.toBigInt()
    );
    const forgedSig = EcdsaSecp256k1.from({
      r: forgedSigBig.r.toBigInt(),
      s: forgedSigBig.s.toBigInt(),
    });

    const expectedAddress = ethAddressFromPubKey(attestorPubKey);
    const expectedAddressField = Reclaim.ethAddressToField(expectedAddress);

    await expect(async () => {
      const txn = await Mina.transaction(senderAccount, async () => {
        await zkApp.verifySignedClaim(
          claimDigest,
          forgedSig,
          attestorPubKey,
          expectedAddressField
        );
      });
      await txn.prove();
      await txn.sign([senderKey]).send();
    }).rejects.toThrow();
  }, 600_000);

  it('rejects a valid signature when expectedAttestorAddress does not match the pubkey', async () => {
    // Exercises the in-circuit address-binding assertion independently
    // from the signature path: signature itself is valid, but the
    // expected address binds to a different pubkey. The Ethereum-address
    // derivation inside verifySignedClaim should fail the assertEquals.
    const attestorPriv = Secp256k1.Scalar.random();
    const attestorPubBig = Secp256k1.generator.scale(attestorPriv);
    const attestorPubKey = Secp256k1.from({
      x: attestorPubBig.x.toBigInt(),
      y: attestorPubBig.y.toBigInt(),
    });

    const claimString = 'http\n{}\n{}';
    const digestKeccak = Keccak.ethereum(Bytes.fromString(claimString));
    const digestBytes = Uint8Array.from(
      digestKeccak.bytes.map((b) => Number(b.toBigInt()))
    );
    const claimDigest = AttestorDigest.from(digestBytes);

    const sigBig = EcdsaSecp256k1.signHash(
      digestBytesToBigInt(digestBytes),
      attestorPriv.toBigInt()
    );
    const validSig = EcdsaSecp256k1.from({
      r: sigBig.r.toBigInt(),
      s: sigBig.s.toBigInt(),
    });

    // Wrong expected address — hardcoded zeros so it cannot accidentally
    // match the derived address from a random pubkey.
    const wrongAddressField = Reclaim.ethAddressToField(
      '0x0000000000000000000000000000000000000000'
    );

    await expect(async () => {
      const txn = await Mina.transaction(senderAccount, async () => {
        await zkApp.verifySignedClaim(
          claimDigest,
          validSig,
          attestorPubKey,
          wrongAddressField
        );
      });
      await txn.prove();
      await txn.sign([senderKey]).send();
    }).rejects.toThrow();
  }, 600_000);
});

// Off-circuit helper: interpret a 32-byte big-endian digest as a bigint.
// Mirrors the in-circuit `digestToSecp256k1Scalar` so off-chain signing
// and on-chain verification agree on the message hash representation.
function digestBytesToBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (let i = 0; i < bytes.length; i++) acc = (acc << 8n) + BigInt(bytes[i]);
  return acc;
}

// Off-circuit helper: derive Ethereum address from a Secp256k1 pubkey.
// Reproduces the in-circuit derivation `keccak256(pubkey_be)[12:]` so the
// test can prepare the expected public input.
function ethAddressFromPubKey(pubKey: Secp256k1): string {
  const x = pubKey.x.toBigInt();
  const y = pubKey.y.toBigInt();
  const bytes = new Uint8Array(64);
  for (let i = 0; i < 32; i++) {
    bytes[31 - i] = Number((x >> BigInt(i * 8)) & 0xffn);
    bytes[63 - i] = Number((y >> BigInt(i * 8)) & 0xffn);
  }
  const digestKeccak = Keccak.ethereum(Bytes.from(Array.from(bytes)));
  let addrHex = '';
  for (let i = 12; i < 32; i++) {
    const v = Number(digestKeccak.bytes[i].toBigInt());
    addrHex += v.toString(16).padStart(2, '0');
  }
  return '0x' + addrHex;
}
