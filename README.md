# Mina SDK
## Overview

This repository contains the zkApp smart contract. The smart contract verifies proofs submitted by users via the Reclaim Protocol and maintains state on the Mina blockchain.

## Deployments

| Chain Name | Deployed Address | Explorer Link |
|:-----------|:-----------------|:--------------|
| Mina Testnet | B62qkKdUy6fJ2qjedmZDUpEwQHpc4owmTGzDzEkdubcM8WRr4kPixi9 | https://minascan.io/devnet/account/B62qkKdUy6fJ2qjedmZDUpEwQHpc4owmTGzDzEkdubcM8WRr4kPixi9/zk-txs |

## Prerequisites

Before you begin, ensure you have the following installed:

- **Mina zkApp CLI**: Install the zkApp CLI globally:
    
    ```bash
    npm install -g zkapp-cli
    ```
    
- **Mina Protocol Dependencies**: Follow the [Mina documentation](https://docs.minaprotocol.com/zkapps) to install any additional dependencies.
- **Mina Account**: Create a Mina account and fund it using the [Mina Faucet](https://faucet.minaprotocol.com/).

## Setup Instructions

1. **Clone the Repository**
    
    ```bash
    git clone https://gitlab.reclaimprotocol.org/integrations/onchain/mina-sdk.git
    cd mina-sdk
    ```
    
2. **Install Dependencies**
    
    ```bash
    npm install
    ```
    

## Configuration

### 1. Initialize zkApp Configuration

Run the following command to set up the deployment configuration:

```bash
zk config
```

You will be prompted to create a deploy alias and configure deployment settings.

**Sample Configuration:**

- **Deploy Alias Name**: `devnet`
- **Target Network Kind**: `Testnet`
- **Mina GraphQL API URL**: `https://api.minascan.io/node/devnet/v1/graphql`
- **Transaction Fee**: `0.1`

When prompted to choose an account to pay transaction fees:

- **Select**: `Create a new fee payer key pair`
- **Alias for Fee Payer Account**: `deploy-account`

**Note**: The private key will be stored in plain text on your computer. Do not use an account that holds significant funds.

### 2. Fund Your Fee Payer Account

After configuring, you need to fund your fee payer account:

- Visit the Mina Faucet: `https://faucet.minaprotocol.com/?address=YOUR_FEE_PAYER_PUBLIC_KEY`
- Select the **Devnet** network.
- Click **Request** to receive test funds.

Wait a few minutes for the transaction to be included in a block.

## Deployment

To deploy your zkApp smart contract to the Mina Devnet, follow these steps:

1. **Compile the Smart Contract**
    
    ```bash
    npm run build
    ```
    
    This command compiles your smart contract and generates necessary artifacts.
    
2. **Deploy the zkApp**
    
    ```bash
    zk deploy
    ```
    
    When prompted, select the deploy alias you created earlier (e.g., `devnet`).
    
3. **Confirm Deployment Details**
    
    Review the deployment details provided by the CLI:
    
    ```
    |-----------------|------------------------------------------------|
    | Deploy alias    | devnet                                         |
    |-----------------|------------------------------------------------|
    | Network kind    | testnet                                        |
    |-----------------|------------------------------------------------|
    | URL             | https://api.minascan.io/node/devnet/v1/graphql |
    |-----------------|------------------------------------------------|
    | Fee payer       | Alias   : deploy-account                       |
    |                 | Account : YOUR_FEE_PAYER_PUBLIC_KEY            |
    |-----------------|------------------------------------------------|
    | zkApp           | Smart contract: Reclaim                        |
    |                 | Account       : YOUR_ZKAPP_PUBLIC_KEY          |
    |-----------------|------------------------------------------------|
    | Transaction fee | 0.1 Mina                                       |
    |-----------------|------------------------------------------------|
    
    ```
    
    Type `yes` to confirm and proceed with the deployment.
    
4. **Wait for Deployment Confirmation**
    
    After sending the transaction, wait for it to be included in a block. You will receive a transaction hash that you can use to track the deployment:
    
    ```
    Success! Deploy transaction sent.
    
    Next step:
      Your smart contract will be live (or updated)
      at YOUR_ZKAPP_PUBLIC_KEY
      as soon as the transaction is included in a block:
      https://minascan.io/devnet/tx/YOUR_TRANSACTION_HASH
    ```
    
5. **Verify Deployment**
    
    Visit the provided URL to verify that your zkApp has been deployed successfully.
    
5. **Test**
    
    ```bash
    npm run test
    ```

## Important Notes

- **Network Configuration**: Ensure that the Mina GraphQL API URL points to the correct network (Devnet in this case).
- **Transaction Fees**: Make sure your fee payer account has enough funds to cover the transaction fees.
- **Private Keys**: Keep your private keys secure. Do not expose them or commit them to version control.

## Smart Contract Overview

The `Reclaim` smart contract verifies proofs submitted by users. It maintains state variables such as `currentEpoch`, `owner`, `witnessesRoot`, and `proofNum`.

### Key Methods

- `init()`: Initializes the contract state.
- `addNewEpoch(newWitnessesRoot: Field)`: Allows the owner to update the witnesses root and increment the epoch.
- `verifyProof(proof: Proof, witness: Field)`: Verifies the provided proof against the contract's state.

### Important Classes

- **ClaimInfo**: Contains information about the claim, including the provider, parameters, and context.
- **Claim**: Represents a claim with fields like epoch, identifier, owner, and timestamp.
- **SignedClaim**: Contains the claim, signatures, and signers.
- **Proof**: Combines `ClaimInfo` and `SignedClaim` for verification.
