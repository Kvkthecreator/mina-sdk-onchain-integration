import {
  Field,
  SmartContract,
  method,
  Struct,
  Poseidon,
  UInt32,
  State,
  state,
  Bool,
  Keccak,
  Bytes,
  PublicKey,
  AccountUpdate,
  Provable,
} from 'o1js';

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

    // Pad with leading zeros to 64 characters
    while (normalized.length < 64) {
      normalized = '00' + normalized;
    }

    // Ensure the hex string has an even length
    if (normalized.length % 2 !== 0) {
      normalized = '0' + normalized;
    }

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
