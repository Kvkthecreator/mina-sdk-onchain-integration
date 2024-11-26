/* eslint-disable */
import { Reclaim, Proof, ClaimInfo, Claim, SignedClaim } from './Reclaim.js';
import {
  Field,
  Mina,
  PrivateKey,
  AccountUpdate,
  MerkleTree,
  assert,
  Signature,
  Poseidon,
  Circuit,
  Bytes,
  Keccak,
} from 'o1js';

const useProof = true;
const Local = await Mina.LocalBlockchain({ proofsEnabled: useProof });
Mina.setActiveInstance(Local);
const deployerAccount = Local.testAccounts[0];
const deployerKey = deployerAccount.key;
const senderAccount = Local.testAccounts[1];
const senderKey = senderAccount.key;

// ----------------------------------------------------
// Create a public/private key pair. The public key is your address and where you deploy the zkApp to
const zkAppPrivateKey = PrivateKey.random();
const zkAppAddress = zkAppPrivateKey.toPublicKey();

// create an instance of Square - and deploy it to zkAppAddress
const zkAppInstance = new Reclaim(zkAppAddress);
const deployTxn = await Mina.transaction(deployerAccount, async () => {
  AccountUpdate.fundNewAccount(deployerAccount);
  await zkAppInstance.deploy();
});
await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();

// ----------------------------------------------------
const witnessFields: Field[] = [
  Field(BigInt('0x244897572368eadf65bfbc5aec98d8e5443a9072')),
];
const witness = witnessFields[0];

const leafCount = witnessFields.length;
const tree = new MerkleTree(leafCount);
witnessFields.forEach((field, index) => {
  tree.setLeaf(BigInt(index), field);
});
const newWitnessesRoot = tree.getRoot();

const txn1 = await Mina.transaction(deployerAccount, async () => {
  await zkAppInstance.addNewEpoch(newWitnessesRoot);
});
await txn1.prove();
await txn1.sign([deployerKey]).send();

// ---------------------- VerifyProof ------------------------------
function stringToField(str: String) {
  const bytes = Buffer.from(str, 'utf8');
  const bytesArray = Array.from(bytes);
  const fields = bytesArray.map((byte) => Field(byte));
  //   const fields = bytes.map((byte) => Field(byte));
  return Poseidon.hash(fields);
}

let provider = 'http';

let parameter =
  '{"body":"","geoLocation":"in","method":"GET","responseMatches":[{"type":"contains","value":"_steamid\\">Steam ID: 76561198155115943</div>"}],"responseRedactions":[{"jsonPath":"","regex":"_steamid\\">Steam ID: (.*)</div>","xPath":"id(\\"responsive_page_template_content\\")/div[@class=\\"page_header_ctn\\"]/div[@class=\\"page_content\\"]/div[@class=\\"youraccount_steamid\\"]"}],"url":"https://store.steampowered.com/account/"}';
let context =
  '{"contextAddress":"0x0","contextMessage":"0098967F","providerHash":"0xeda3e4cee88b5cbaec045410a0042f99ab3733a4d5b5eb2da5cecc25aa9e9df1"}';
let identifier =
  '0x930a5687ac463eb8f048bd203659bd8f73119c534969258e5a7c5b8eb0987b16';
let identifierField =
  Field(0x930a5687ac463eb8f048bd203659bd8f73119c534969258e5a7c5b8eb0987b16);
const claimInfo = new ClaimInfo({
  provider: provider,
  parameters: parameter,
  context: context,
});

const claim = new Claim({
  epoch: Field(1),
  identifier: identifier,
  identifierField: identifierField,
  owner: Field(BigInt('0x8e87e3605b15a028188fde5f4ce03e87d55a2b4f')),
  timestampS: Field(1724909052),
});

const signatures = [
  '0xcbad077154cc5c8e494576d4336f57972f7412058c1a637e05832c6bdabd018f4da18ad973f29553921d7d030370032addac1159146b77ec6cc5dab4133ffec01c',
];

const signedClaim = new SignedClaim({
  claim: claim,
  signatures: signatures,
  signers: Field(BigInt('0x244897572368eadf65bfbc5aec98d8e5443a9072')),
});

const treee = new MerkleTree(2);

const proof = new Proof({
  claimInfo: claimInfo,
  signedClaim: signedClaim,
});

const txn2 = await Mina.transaction(senderAccount, async () => {
  await zkAppInstance.verifyProof(proof, witness);
});
await txn2.prove();
await txn2.sign([senderKey]).send();
