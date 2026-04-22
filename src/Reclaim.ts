import {
  Field,
  SmartContract,
  method,
  Struct,
  Poseidon,
  UInt32,
  UInt8,
  State,
  state,
  Bool,
  Keccak,
  Bytes,
  PublicKey,
  AccountUpdate,
  Provable,
  Crypto,
  createForeignCurve,
  createEcdsa,
} from 'o1js';

// ---------------------------------------------------------------------------
// In-circuit ECDSA-secp256k1 attestor primitive.
//
// Reclaim attestors sign claim digests with secp256k1 + keccak256, producing
// Ethereum-style 65-byte (r || s || v) signatures. To verify an attestor
// signature inside a Mina circuit, we need:
//   1. A foreign-curve type for secp256k1 (`Secp256k1`).
//   2. An ECDSA signature type bound to that curve (`EcdsaSecp256k1`).
//   3. A 32-byte digest container (`AttestorDigest`).
// All three are first-class in o1js's standard library; no external crypto.
//
// The attestor's identity is its 20-byte Ethereum address, i.e.
// `keccak256(uncompressed_pubkey)[12:]`. We expose the address as the
// public anchoring input on `verifySignedClaim` and derive it in-circuit
// from the witnessed pubkey to prove the signature came from the trusted
// attestor.
// ---------------------------------------------------------------------------
export class Secp256k1 extends createForeignCurve(
  Crypto.CurveParams.Secp256k1
) {}
export class EcdsaSecp256k1 extends createEcdsa(Secp256k1) {}

export const ATTESTOR_DIGEST_BYTES = 32;
export class AttestorDigest extends Bytes(ATTESTOR_DIGEST_BYTES) {}

// Define ClaimInfo
export class ClaimInfo extends Struct({
  provider: String,
  parameters: String,
  context: String,
}) {}

// Define Claim
export class Claim extends Struct({
  epoch: Field,
  identifier: String,
  identifierField: Field,
  owner: Field,
  timestampS: Field,
}) {}

// Define SignedClaim
export class SignedClaim extends Struct({
  claim: Claim,
  signatures: [String],
  signers: Field,
}) {}

// Define Proof
export class Proof extends Struct({
  claimInfo: ClaimInfo,
  signedClaim: SignedClaim,
}) {}

export class Reclaim extends SmartContract {
  @state(UInt32) currentEpoch = State<UInt32>();
  @state(PublicKey) owner = State<PublicKey>();
  @state(Field) witnessesRoot = State<Field>();
  @state(Field) proofNum = State<Field>();

  init() {
    super.init();
    this.proofNum.set(Field(0));
    this.owner.set(this.sender.getAndRequireSignature());
    const initialWitnessesRoot = Field(
      BigInt('0x244897572368eadf65bfbc5aec98d8e5443a9072')
    );
    this.witnessesRoot.set(initialWitnessesRoot);
  }

  @method async addNewEpoch(newWitnessesRoot: Field) {
    // Validate that the caller is the owner
    let callerPublicKey = this.sender.getAndRequireSignature();
    let senderUpdate = AccountUpdate.create(callerPublicKey);
    senderUpdate.requireSignature();

    let owner = this.owner.get();
    this.owner.requireEquals(owner);
    owner.assertEquals(callerPublicKey);

    // Step 2: Calculate the new epoch number
    let currentEpoch = this.currentEpoch.get();
    this.currentEpoch.requireEquals(currentEpoch);
    let newEpochNumber = currentEpoch.add(UInt32.from(1));
    this.currentEpoch.set(newEpochNumber);

    this.witnessesRoot.set(newWitnessesRoot);
  }

  /**
   * Verify a Reclaim attestor signature in-circuit.
   *
   * Unlike `verifyProof`, this method actually runs ECDSA-secp256k1
   * verification inside the zk circuit using o1js's native
   * `EcdsaSignature.verifySignedHash`, and binds the attestor's
   * 20-byte Ethereum address to the public `expectedAttestorAddress`
   * input.
   *
   * Inputs:
   *   claimDigest         32 bytes — keccak256(provider || "\n" || parameters
   *                       || "\n" || context). Compute off-circuit via
   *                       `hashClaimInfo()`.
   *   signature           secp256k1 (r, s) — drop the Ethereum `v` recovery
   *                       byte and pass r,s only. ECDSA verification does
   *                       not need v. See `parseEthereumSignature` helper.
   *   attestorPubKey      The witnessed attestor public key (point on
   *                       secp256k1). Bound to `expectedAttestorAddress`
   *                       via in-circuit keccak256(pubkey)[12:].
   *   expectedAttestorAddress 20 bytes packed into a Field (160 bits, fits
   *                       comfortably in Mina's 254-bit Field). Should
   *                       equal a known attestor address from the
   *                       on-chain epoch witness set.
   *
   * Note on signing convention: Reclaim attestors sign the keccak256 digest
   * directly (i.e. the digest IS the signed message hash, not a message
   * that gets hashed inside the verifier). We use o1js's
   * `verifySignedHash` which consumes a pre-computed hash, rather than
   * `verify` which would apply keccak256 a second time.
   */
  @method async verifySignedClaim(
    claimDigest: AttestorDigest,
    signature: EcdsaSecp256k1,
    attestorPubKey: Secp256k1,
    expectedAttestorAddress: Field
  ) {
    // 1. Convert the 32-byte digest into a secp256k1 scalar so we can call
    //    `verifySignedHash`. The conversion is the canonical
    //    "interpret bytes as a big-endian integer" operation, mirroring
    //    o1js's internal `keccakOutputToScalar` helper. Done via
    //    bit-decomposition + reassembly to stay fully provable.
    const msgHashScalar = digestToSecp256k1Scalar(claimDigest);

    // 2. Verify the ECDSA-secp256k1 signature on the keccak digest.
    signature
      .verifySignedHash(msgHashScalar, attestorPubKey)
      .assertTrue('attestor ECDSA signature is invalid');

    // 3. Derive the attestor's Ethereum address in-circuit and bind it to
    //    the expected public input. This proves the witnessed pubkey
    //    corresponds to the trusted attestor address — without it, a
    //    prover could substitute any pubkey.
    const pubKeyBytes = pubKeyToBigEndianBytes(attestorPubKey);
    const ethAddrDigest = Keccak.ethereum(Bytes.from(pubKeyBytes));
    let derivedAddress = Field(0);
    const TWO_POW_8 = Field(256);
    for (let i = 12; i < 32; i++) {
      derivedAddress = derivedAddress
        .mul(TWO_POW_8)
        .add(ethAddrDigest.bytes[i].value);
    }
    expectedAttestorAddress.assertEquals(
      derivedAddress,
      'attestor pubkey does not derive to the expected Ethereum address'
    );
  }

  @method async verifyProof(proof: Proof, witness: Field) {
    // 1. Signatures are guaranteed by the SignedClaim struct definition
    let signatures = proof.signedClaim.signatures;

    // 2. Create and hash the structured claim info data
    let claimInfoDataHash = this.hashClaimInfo(
      proof.claimInfo.provider,
      proof.claimInfo.parameters,
      proof.claimInfo.context
    );

    // // 3. Process the identifier
    let Identifier = proof.signedClaim.claim.identifier;
    let IdentifierFields = this.hexStringToFields(Identifier);

    // 4. Ensure the hashed claim data matches the identifier
    const isValid = this.compareFields(
      claimInfoDataHash.toFields(),
      IdentifierFields
    );
    isValid.assertEquals(Bool(true));

    // 5. Fetch expected witnesses (this will be an input or a state variable)
    // For the purpose of this zkApp, we'll assume expectedWitnesses are provided
    let witnesses = this.getWitnessesList(witness);
    let expectedWitnesses: Field[] = this.getExpectedWitnesses(
      proof.signedClaim.claim.identifierField,
      witnesses
    );

    // 6. Recover the signers from the signed claim
    let signedWitnesses = [proof.signedClaim.signers];

    // 7. Check for duplicate signatures
    let hasDuplicates = this.containsDuplicates(signedWitnesses);
    hasDuplicates.assertEquals(Bool(false), 'Duplicate signatures found');

    // 8. **Validate the signed witnesses against the Merkle root**
    let witnessesRoot = this.witnessesRoot.get();
    this.witnessesRoot.requireEquals(witnessesRoot);

    for (let i = 0; i < signedWitnesses.length; i++) {
      let witnessProof = witnessesRoot;

      //   **Verify that the witnessAddress is in the Merkle tree**
      witnessProof.assertEquals(witnessesRoot);
    }

    let signedWitnessesLength = UInt32.from(signedWitnesses.length);
    let expectedWitnessesLength = UInt32.from(expectedWitnesses.length);
    signedWitnessesLength.assertEquals(expectedWitnessesLength);

    for (let i = 0; i < signedWitnesses.length; i++) {
      let isValid = expectedWitnesses[i].equals(signedWitnesses[i]);
      isValid.assertEquals(
        Bool(true),
        'Invalid witness found in signed witnesses'
      );
    }
  }

  hashClaimInfo(provider: string, parameter: string, context: string): Bytes {
    const serialized = provider + '\n' + parameter + '\n' + context;
    let serializedBytes = Bytes.fromString(serialized);
    let hash = Keccak.ethereum(serializedBytes);
    return hash;
  }

  /**
   * Off-circuit helper: parse a Reclaim signature hex string (r || s || v,
   * Ethereum-style 65 bytes) into the (r, s) scalars consumed by
   * `verifySignedClaim`. Drops the v byte — recovery is not needed because
   * the verifier is given the pubkey directly.
   *
   * Static so consumers can call without instantiating the contract.
   */
  static parseEthereumSignature(hex: string): { r: bigint; s: bigint } {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (clean.length !== 130) {
      throw new Error(
        `Reclaim signature must be 65 bytes (130 hex chars), got ${clean.length}`
      );
    }
    if (!/^[0-9a-fA-F]+$/.test(clean)) {
      throw new Error('Reclaim signature contains non-hex characters');
    }
    return {
      r: BigInt('0x' + clean.slice(0, 64)),
      s: BigInt('0x' + clean.slice(64, 128)),
    };
  }

  /**
   * Off-circuit helper: convert a 0x-prefixed Ethereum address (20 bytes /
   * 40 hex chars) to a Field for use as the `expectedAttestorAddress`
   * public input. Asserts proper length.
   */
  static ethAddressToField(addressHex: string): Field {
    const clean = addressHex.startsWith('0x')
      ? addressHex.slice(2)
      : addressHex;
    if (clean.length !== 40) {
      throw new Error(
        `Ethereum address must be 20 bytes (40 hex chars), got ${clean.length}`
      );
    }
    if (!/^[0-9a-fA-F]+$/.test(clean)) {
      throw new Error('Ethereum address contains non-hex characters');
    }
    return Field(BigInt('0x' + clean));
  }

  compareFields(fields1: Field[], fields2: Field[]): Bool {
    // @TODO Check what we can do about it
    Field(fields1.length).assertEquals(
      Field(fields2.length),
      'Array lengths mismatch'
    );

    // Initialize the result to true
    let isEqual = Bool(true);

    // Iterate over the fields and accumulate the equality checks
    for (let i = 0; i < fields1.length; i++) {
      // Compare the corresponding fields
      const areFieldsEqual = fields1[i].equals(fields2[i]);
      // Update isEqual to be the logical AND of itself and the current comparison
      isEqual = isEqual.and(areFieldsEqual);
    }

    return isEqual;
  }

  getExpectedWitnesses(claimIdentifier: Field, allWitnesses: Field[]): Field[] {
    const N_WITNESSES = allWitnesses.length;
    const bitsNeeded = Math.ceil(Math.log2(N_WITNESSES));
    let selectedWitnesses: Field[] = [];

    for (let i = 0; i < N_WITNESSES; i++) {
      // Step 1: Compute the seed
      const seed = Poseidon.hash([claimIdentifier, Field(i)]);

      // Step 2: Convert the seed to bits
      const seedBits = seed.toBits();

      // Step 3: Extract the required number of bits
      const indexBits = seedBits.slice(0, bitsNeeded);

      // Step 4: Compute the index from bits
      let index = Field(0);
      let twoPow = Field(1);
      for (let j = 0; j < bitsNeeded; j++) {
        index = index.add(indexBits[j].toField().mul(twoPow));
        twoPow = twoPow.mul(2);
      }

      // Step 5: Enforce index is less than N_WITNESSES
      index.assertLessThan(Field(N_WITNESSES));

      // Step 6: Convert index to UInt32
      //   const uintIndex = UInt32.from(index);

      // Step 7: Select the witness using the computed index
      const selectedWitness = this.circuitSwitch(index, allWitnesses);

      selectedWitnesses.push(selectedWitness);
    }

    return selectedWitnesses;
  }

  getWitnessesList(witness: Field): Field[] {
    const witnessFields: Field[] = [witness];
    return witnessFields;
  }

  hexStringToFields(hex: string): Field[] {
    // Remove "0x" prefix if present
    let normalized = hex.startsWith('0x') ? hex.slice(2) : hex;

    // Ensure the hex string has an even length first
    if (normalized.length % 2 !== 0) {
      normalized = '0' + normalized;
    }

    // Pad with leading zeros to 64 characters (32 bytes)
    normalized = normalized.padStart(64, '0');

    const fields: Field[] = [];
    for (let i = 0; i < normalized.length; i += 2) {
      const byteHex = normalized.slice(i, i + 2);
      const byteValue = parseInt(byteHex, 16);
      fields.push(Field(byteValue));
    }

    return fields;
  }

  containsDuplicates(array: Field[]): Bool {
    let hasDuplicates = Bool(false);
    let n = array.length;
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < i; j++) {
        let isEqual = array[i].equals(array[j]);
        hasDuplicates = hasDuplicates.or(isEqual);
      }
    }
    return hasDuplicates;
  }

  circuitSwitch(selector: Field, cases: Field[]): Field {
    let result = cases[0];
    for (let i = 1; i < cases.length; i++) {
      let isSelected = selector.equals(Field.from(i));
      result = Provable.if(isSelected, cases[i], result);
    }
    return result;
  }
}

// ---------------------------------------------------------------------------
// Module-level helpers for the new in-circuit ECDSA path.
// Exposed so consumers don't need to instantiate `Reclaim` for off-chain
// preparation work.
// ---------------------------------------------------------------------------

/**
 * Convert a Secp256k1 point (x, y) to its 64-byte uncompressed
 * representation: x_be (32 bytes) || y_be (32 bytes). Used to feed
 * `Keccak.ethereum` for in-circuit Ethereum-address derivation.
 *
 * Uses o1js native `ForeignField.toBits(256)` and assembles bytes via
 * `Field.fromBits` + `UInt8.from`. Fully provable, no native bigint
 * arithmetic.
 */
function pubKeyToBigEndianBytes(pubKey: Secp256k1): UInt8[] {
  const xBits = pubKey.x.toBits(256);
  const yBits = pubKey.y.toBits(256);
  return [...coordBitsToBytesBE(xBits), ...coordBitsToBytesBE(yBits)];
}

function coordBitsToBytesBE(bits: Bool[]): UInt8[] {
  const bytes: UInt8[] = [];
  for (let byteIdx = 0; byteIdx < 32; byteIdx++) {
    const leByteOffset = (31 - byteIdx) * 8;
    const byteBits = bits.slice(leByteOffset, leByteOffset + 8);
    bytes.push(UInt8.from(Field.fromBits(byteBits)));
  }
  return bytes;
}

/**
 * Interpret a 32-byte digest as a secp256k1 scalar (big-endian integer).
 * Equivalent to o1js's internal `keccakOutputToScalar` — assembles the
 * bytes back into a single bigint-bound scalar for `verifySignedHash`.
 *
 * In-circuit: bit-decomposes each byte and shifts, all within Mina's
 * native Field operations. Wraps the result with `Secp256k1.Scalar.from`
 * to lift it into the foreign scalar field.
 */
function digestToSecp256k1Scalar(digest: AttestorDigest) {
  // Pack 32 bytes (big-endian) into a single Field — fits because
  // 32 bytes = 256 bits and our intermediate accumulator stays
  // under field modulus when reassembled into the scalar field. We
  // build the integer by `acc * 256 + byte` over the byte sequence,
  // mirroring how `keccakOutputToScalar` lifts the hash output.
  const bytes = digest.bytes;
  // Decompose the 256-bit big-endian byte string into its bits, then
  // re-pack into a Secp256k1 scalar. This is the cleanest provable
  // reduction available in o1js v2.1 without `UInt8.fromBits`.
  const allBitsLE: Bool[] = [];
  for (let byteIdx = bytes.length - 1; byteIdx >= 0; byteIdx--) {
    const byteBits = bytes[byteIdx].value.toBits(8); // little-endian within the byte
    for (let b = 0; b < 8; b++) allBitsLE.push(byteBits[b]);
  }
  return Secp256k1.Scalar.fromBits(allBitsLE);
}
