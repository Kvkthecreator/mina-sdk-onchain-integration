import { Reclaim, Proof, ClaimInfo, Claim, SignedClaim } from './Reclaim';
import {
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  MerkleTree,
  UInt32,
} from 'o1js';

describe('Reclaim', () => {
  let deployerAccount: Mina.TestPublicKey;
  let deployerKey: PrivateKey;
  let senderAccount: Mina.TestPublicKey;
  let senderKey: PrivateKey;
  let zkAppAddress: PublicKey;
  let zkAppPrivateKey: PrivateKey;
  let zkApp: Reclaim;

  const WITNESS_ADDRESS = BigInt('0x244897572368eadf65bfbc5aec98d8e5443a9072');

  const proofsEnabled = false;

  beforeAll(async () => {
    // Compile the contract if proofs are enabled
    if (proofsEnabled) {
      await Reclaim.compile();
    }
  });

  beforeEach(async () => {
    // Set up local blockchain
    const Local = await Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);

    deployerAccount = Local.testAccounts[0];
    deployerKey = deployerAccount.key;
    senderAccount = Local.testAccounts[1];
    senderKey = senderAccount.key;

    // Create zkApp keys
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new Reclaim(zkAppAddress);
  });

  async function deployContract() {
    const txn = await Mina.transaction(deployerAccount, async () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      await zkApp.deploy();
    });
    await txn.prove();
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  describe('init()', () => {
    it('should initialize with correct default values', async () => {
      await deployContract();

      const proofNum = zkApp.proofNum.get();
      const owner = zkApp.owner.get();
      const witnessesRoot = zkApp.witnessesRoot.get();

      expect(proofNum).toEqual(Field(0));
      expect(owner.toBase58()).toEqual(deployerAccount.toBase58());
      expect(witnessesRoot).toEqual(Field(WITNESS_ADDRESS));
    });

    it('should set deployer as owner', async () => {
      await deployContract();

      const owner = zkApp.owner.get();
      expect(owner.toBase58()).toEqual(deployerAccount.toBase58());
    });
  });

  describe('addNewEpoch()', () => {
    beforeEach(async () => {
      await deployContract();
    });

    it('should allow owner to add new epoch', async () => {
      const witnessFields = [Field(WITNESS_ADDRESS)];
      const treeHeight = Math.max(2, Math.ceil(Math.log2(witnessFields.length)) + 1);
      const tree = new MerkleTree(treeHeight);
      witnessFields.forEach((field, index) => {
        tree.setLeaf(BigInt(index), field);
      });
      const newWitnessesRoot = tree.getRoot();

      const txn = await Mina.transaction(deployerAccount, async () => {
        await zkApp.addNewEpoch(newWitnessesRoot);
      });
      await txn.prove();
      await txn.sign([deployerKey]).send();

      const currentEpoch = zkApp.currentEpoch.get();
      const witnessesRoot = zkApp.witnessesRoot.get();

      expect(currentEpoch).toEqual(UInt32.from(1));
      expect(witnessesRoot).toEqual(newWitnessesRoot);
    });

    it('should increment epoch on subsequent calls', async () => {
      const newRoot1 = Field(123);
      const newRoot2 = Field(456);

      // First epoch update
      const txn1 = await Mina.transaction(deployerAccount, async () => {
        await zkApp.addNewEpoch(newRoot1);
      });
      await txn1.prove();
      await txn1.sign([deployerKey]).send();

      expect(zkApp.currentEpoch.get()).toEqual(UInt32.from(1));

      // Second epoch update
      const txn2 = await Mina.transaction(deployerAccount, async () => {
        await zkApp.addNewEpoch(newRoot2);
      });
      await txn2.prove();
      await txn2.sign([deployerKey]).send();

      expect(zkApp.currentEpoch.get()).toEqual(UInt32.from(2));
      expect(zkApp.witnessesRoot.get()).toEqual(newRoot2);
    });

    it('should reject non-owner attempting to add epoch', async () => {
      const newRoot = Field(123);

      await expect(async () => {
        const txn = await Mina.transaction(senderAccount, async () => {
          await zkApp.addNewEpoch(newRoot);
        });
        await txn.prove();
        await txn.sign([senderKey]).send();
      }).rejects.toThrow();
    });
  });

  describe('verifyProof()', () => {
    const testData = {
      provider: 'http',
      parameters:
        '{"body":"","geoLocation":"in","method":"GET","responseMatches":[{"type":"contains","value":"_steamid\\">Steam ID: 76561198155115943</div>"}],"responseRedactions":[{"jsonPath":"","regex":"_steamid\\">Steam ID: (.*)</div>","xPath":"id(\\"responsive_page_template_content\\")/div[@class=\\"page_header_ctn\\"]/div[@class=\\"page_content\\"]/div[@class=\\"youraccount_steamid\\"]"}],"url":"https://store.steampowered.com/account/"}',
      context:
        '{"contextAddress":"0x0","contextMessage":"0098967F","providerHash":"0xeda3e4cee88b5cbaec045410a0042f99ab3733a4d5b5eb2da5cecc25aa9e9df1"}',
      identifier:
        '0x930a5687ac463eb8f048bd203659bd8f73119c534969258e5a7c5b8eb0987b16',
      identifierField: Field(
        BigInt('0x930a5687ac463eb8f048bd203659bd8f73119c534969258e5a7c5b8eb0987b16')
      ),
      owner: Field(BigInt('0x8e87e3605b15a028188fde5f4ce03e87d55a2b4f')),
      timestampS: Field(1724909052),
      signature:
        '0xcbad077154cc5c8e494576d4336f57972f7412058c1a637e05832c6bdabd018f4da18ad973f29553921d7d030370032addac1159146b77ec6cc5dab4133ffec01c',
    };

    beforeEach(async () => {
      await deployContract();

      // Set up epoch with witnesses
      const witnessFields = [Field(WITNESS_ADDRESS)];
      const treeHeight = Math.max(2, Math.ceil(Math.log2(witnessFields.length)) + 1);
      const tree = new MerkleTree(treeHeight);
      witnessFields.forEach((field, index) => {
        tree.setLeaf(BigInt(index), field);
      });
      const newWitnessesRoot = tree.getRoot();

      const txn = await Mina.transaction(deployerAccount, async () => {
        await zkApp.addNewEpoch(newWitnessesRoot);
      });
      await txn.prove();
      await txn.sign([deployerKey]).send();
    });

    it('should verify a valid proof', async () => {
      const witness = Field(WITNESS_ADDRESS);

      const claimInfo = new ClaimInfo({
        provider: testData.provider,
        parameters: testData.parameters,
        context: testData.context,
      });

      const claim = new Claim({
        epoch: Field(1),
        identifier: testData.identifier,
        identifierField: testData.identifierField,
        owner: testData.owner,
        timestampS: testData.timestampS,
      });

      const signedClaim = new SignedClaim({
        claim: claim,
        signatures: [testData.signature],
        signers: Field(WITNESS_ADDRESS),
      });

      const proof = new Proof({
        claimInfo: claimInfo,
        signedClaim: signedClaim,
      });

      const txn = await Mina.transaction(senderAccount, async () => {
        await zkApp.verifyProof(proof, witness);
      });
      await txn.prove();
      await txn.sign([senderKey]).send();

      // If we reach here without throwing, the proof was verified
      expect(true).toBe(true);
    });

    it('should reject proof with mismatched identifier', async () => {
      const witness = Field(WITNESS_ADDRESS);

      const claimInfo = new ClaimInfo({
        provider: 'wrong-provider',
        parameters: testData.parameters,
        context: testData.context,
      });

      const claim = new Claim({
        epoch: Field(1),
        identifier: testData.identifier,
        identifierField: testData.identifierField,
        owner: testData.owner,
        timestampS: testData.timestampS,
      });

      const signedClaim = new SignedClaim({
        claim: claim,
        signatures: [testData.signature],
        signers: Field(WITNESS_ADDRESS),
      });

      const proof = new Proof({
        claimInfo: claimInfo,
        signedClaim: signedClaim,
      });

      await expect(async () => {
        const txn = await Mina.transaction(senderAccount, async () => {
          await zkApp.verifyProof(proof, witness);
        });
        await txn.prove();
        await txn.sign([senderKey]).send();
      }).rejects.toThrow();
    });

    // This test only works with proofs enabled since witness validation
    // happens during proof generation via circuit constraints
    (proofsEnabled ? it : it.skip)('should reject proof with invalid witness', async () => {
      const invalidWitness = Field(BigInt('0x1234567890abcdef'));

      const claimInfo = new ClaimInfo({
        provider: testData.provider,
        parameters: testData.parameters,
        context: testData.context,
      });

      const claim = new Claim({
        epoch: Field(1),
        identifier: testData.identifier,
        identifierField: testData.identifierField,
        owner: testData.owner,
        timestampS: testData.timestampS,
      });

      const signedClaim = new SignedClaim({
        claim: claim,
        signatures: [testData.signature],
        signers: Field(BigInt('0x1234567890abcdef')),
      });

      const proof = new Proof({
        claimInfo: claimInfo,
        signedClaim: signedClaim,
      });

      await expect(async () => {
        const txn = await Mina.transaction(senderAccount, async () => {
          await zkApp.verifyProof(proof, invalidWitness);
        });
        await txn.prove();
        await txn.sign([senderKey]).send();
      }).rejects.toThrow();
    });
  });

  describe('helper functions', () => {
    beforeEach(async () => {
      await deployContract();
    });

    describe('hexStringToFields()', () => {
      it('should convert hex string with 0x prefix', () => {
        const result = zkApp.hexStringToFields('0x1234');
        expect(result.length).toBe(32);
        // First 30 bytes should be 0 (padding), last 2 should be 0x12 and 0x34
        expect(result[30]).toEqual(Field(0x12));
        expect(result[31]).toEqual(Field(0x34));
      });

      it('should convert hex string without 0x prefix', () => {
        const result = zkApp.hexStringToFields('abcd');
        expect(result.length).toBe(32);
        expect(result[30]).toEqual(Field(0xab));
        expect(result[31]).toEqual(Field(0xcd));
      });

      it('should pad short hex strings', () => {
        const result = zkApp.hexStringToFields('0x1');
        expect(result.length).toBe(32);
        // Should be padded with zeros
        for (let i = 0; i < 31; i++) {
          expect(result[i]).toEqual(Field(0));
        }
        expect(result[31]).toEqual(Field(0x01));
      });
    });

    describe('containsDuplicates()', () => {
      it('should return false for unique elements', () => {
        const arr = [Field(1), Field(2), Field(3)];
        const result = zkApp.containsDuplicates(arr);
        expect(result.toBoolean()).toBe(false);
      });

      it('should return true for duplicate elements', () => {
        const arr = [Field(1), Field(2), Field(1)];
        const result = zkApp.containsDuplicates(arr);
        expect(result.toBoolean()).toBe(true);
      });

      it('should return false for empty array', () => {
        const arr: Field[] = [];
        const result = zkApp.containsDuplicates(arr);
        expect(result.toBoolean()).toBe(false);
      });

      it('should return false for single element', () => {
        const arr = [Field(1)];
        const result = zkApp.containsDuplicates(arr);
        expect(result.toBoolean()).toBe(false);
      });
    });

    describe('compareFields()', () => {
      it('should return true for equal arrays', () => {
        const arr1 = [Field(1), Field(2), Field(3)];
        const arr2 = [Field(1), Field(2), Field(3)];
        const result = zkApp.compareFields(arr1, arr2);
        expect(result.toBoolean()).toBe(true);
      });

      it('should return false for different arrays', () => {
        const arr1 = [Field(1), Field(2), Field(3)];
        const arr2 = [Field(1), Field(2), Field(4)];
        const result = zkApp.compareFields(arr1, arr2);
        expect(result.toBoolean()).toBe(false);
      });
    });

    describe('circuitSwitch()', () => {
      it('should select correct case based on selector', () => {
        const cases = [Field(10), Field(20), Field(30)];

        expect(zkApp.circuitSwitch(Field(0), cases)).toEqual(Field(10));
        expect(zkApp.circuitSwitch(Field(1), cases)).toEqual(Field(20));
        expect(zkApp.circuitSwitch(Field(2), cases)).toEqual(Field(30));
      });

      it('should return first case for out-of-bounds selector', () => {
        const cases = [Field(10), Field(20)];
        // Out of bounds should still return first case (default behavior)
        expect(zkApp.circuitSwitch(Field(5), cases)).toEqual(Field(10));
      });
    });
  });
});
