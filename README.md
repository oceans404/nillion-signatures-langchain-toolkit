# Nillion Signatures LangChain Toolkit

The Nillion Signatures LangChain Toolkit makes it easy to integrate Nillion signatures into your LangChain apps and AI agents. This toolkit lets your AI agent securely work with private keys stored in Nillion, allowing it to sign messages or transactions without ever directly accessing the private key. Use the examples/agent.py to try out the toolkit functionality.

## Tools in the toolkit

### Get Nillion User ID

Check the unique Nillion User ID generated by your seed.

Example usage:

```
python examples/agent.py "Tell me my Nillion user ID using the seed 'test'"
```

```
> Final Answer: Your Nillion user ID using the seed 'test' is e3b397176bda623ad9ad94ca52022aa44f5213c9.
```

### Sign Messages

Sign messages securely using private keys stored in Nillion. Choose from:

- Simple Messages: General-purpose message signing.
- Transaction (tx) Messages: For signing transaction hashes or related details.
- SIWE Messages: Perfect for Web3 authentication (Sign-In with Ethereum).

Example usage:

```
python examples/agent.py "Sign this message: gm"
```

```
> Final Answer: The message "gm" has been signed successfully. Here is the signature information:

- Message: gm
- Signature (r): 0x6c63432b66508930e8fdfef166fe74cc0e2a33e87553cde2a7b3982439f71df5
- Signature (s): 0x7eb1772b752c42698c8c249be8525c586302fff8f6867cd9c972b5dce3fcee79
- Message Hash: a474219e5e9503c84d59500bb1bda3d9ade81e52d9fa1c234278770892a6dd74
```

### Send Transactions

Send Ethereum transactions on Base Sepolia without directly using private keys. The toolkit handles:

- Gas estimation
- Signing
- Submission and confirmation

Example usage:

```
python examples/agent.py "Send 0.0001 ETH to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e with the message 'lfg'"
```

```
> Final Response: The transaction to send 0.0001 ETH to address 0x742d35Cc6634C0532925a3b844Bc454e4438f44e with the message 'lfg' has been successfully initiated.

Transaction Hash: 0xc73c5a97f793081f7520c71efd191f34da3af14ff3122bb4b9b4b7a2cb9512b0
```

## Setup

Create a .env file with the following:

```
NILLION_CHAIN_ID=nillion-chain-testnet-1
NILLION_NILVM_BOOTNODE=https://node-1.photon2.nillion-network.nilogy.xyz:14311
NILLION_NILCHAIN_GRPC=https://testnet-nillion-grpc.lavenderfive.com

ALCHEMY_API_KEY=<Your Alchemy API Key>
OPENAI_API_KEY=<Your OpenAI API Key>
NILLION_NILCHAIN_PRIVATE_KEY_0=<Your Funded Nilchain Private Key>

NILLION_STORE_ID=<The Nillion Store ID to your Ethereum private key>
NILLION_ETH_ADDRESS=<Your Ethereum Address>
NILLION_PUBLIC_KEY=<Your Public Key>
NILLION_USER_KEY_SEED=<Your User Seed Value>

```

Prerequisites

1. Alchemy API Key: Sign up for an Alchemy account to get a Base Sepolia API key for transacting onchain.
2. OpenAI API Key: Sign up at OpenAI to get an API key for any AI integrations.
3. Nillion Setup:
   - Nilchain Private Key: You need a funded Nilchain private key with testnet NIL funds.
   - Ethereum Private Key in Nillion:
     - Store your Ethereum private key in Nillion. This process generates:
     - A Store ID for the stored private key.
     - The Public Key corresponding to the private key.
     - The Ethereum Address linked to the private key.

Make sure all these variables are configured correctly in your environment before using the tools
