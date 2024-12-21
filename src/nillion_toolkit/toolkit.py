from typing import Optional, Type, Union
from uuid import UUID
from datetime import datetime
import os
from pydantic import BaseModel, Field
from langchain.tools import BaseTool
from langchain.callbacks.manager import AsyncCallbackManagerForToolRun, CallbackManagerForToolRun

# Fix import paths to use full package paths
from nillion_toolkit.nillion_utils import (
    get_user_id_from_seed,
    sign_message,
    SimpleMessageParams,
    SiweMessageParams,
    TxMessageParams
)
from nillion_toolkit.nillion_tx_utils import send_transaction

class UserIdInput(BaseModel):
    """Input schema for getting a Nillion user ID."""
    user_key_seed: str = Field(
        default="demo",
        description="The seed used to generate the user key"
    )

class SignMessageInput(BaseModel):
    """Input schema for signing messages with Nillion."""
    message_type: str = Field(
        description="Type of message to sign: 'simple', 'siwe', or 'tx'"
    )
    # Simple message fields
    message: Optional[str] = Field(
        None,
        description="The message content for simple or tx messages"
    )
    # Transaction message fields
    tx_hash: Optional[bytes] = Field(
        None,
        description="The transaction hash for tx messages"
    )
    # SIWE message fields
    domain: Optional[str] = Field(None)
    ethereum_address: Optional[str] = Field(None)
    uri: Optional[str] = Field(None)
    version: Optional[str] = Field(None)
    chain_id: Optional[int] = Field(None)
    nonce: Optional[str] = Field(None)
    issued_at: Optional[str] = Field(None)
    expiration_time: Optional[str] = Field(None)
    not_before: Optional[str] = Field(None)
    request_id: Optional[str] = Field(None)
    resources: Optional[list[str]] = Field(None)
    statement: Optional[str] = Field(None)

class SendTransactionInput(BaseModel):
    """Input schema for sending transactions."""
    amount_in_eth: float = Field(
        description="Amount of ETH to send"
    )
    to_address: str = Field(
        description="Destination Ethereum address"
    )
    data: str = Field(
        default="LFG 🚀",
        description="Transaction data (hex string or UTF-8 text)"
    )
    chain_id: int = Field(
        default=84532,
        description="Ethereum chain ID (default: Base Sepolia)"
    )
    priority_fee_gwei: int = Field(
        default=10,
        description="Priority fee in GWEI"
    )
class NillionUserIdTool(BaseTool):
    """Tool for getting a Nillion user ID from a seed."""
    name: str = "get_nillion_user_id"
    description: str = """Used to retrieve a Nillion user ID by providing a seed value. Use this tool when you need to:
    - Get a user ID from any seed value
    - Look up a Nillion ID using a seed
    - Find out what user ID corresponds to a seed
    
Required parameter:
    - user_key_seed: A string value used as the seed (e.g., "test123", "demo", "custom_seed")
    
Examples of when to use this tool:
    - "Get me a user ID for seed xyz"
    - "What's the Nillion ID for seed test123"
    - "Find the user ID associated with seed custom_seed"
    - "Get user ID from seed demo"
    """
    args_schema: Type[BaseModel] = UserIdInput

    def _run(
        self,
        user_key_seed: str = "demo",
        run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> str:
        """Synchronous run not supported."""
        raise NotImplementedError("get_nillion_user_id does not support synchronous execution")

    async def _arun(
        self,
        user_key_seed: str = "demo",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None
    ) -> str:
        """Get the Nillion user ID asynchronously."""
        return await get_user_id_from_seed(user_key_seed)

class NillionSignMessageTool(BaseTool):
    """Tool for signing messages using Nillion."""
    name: str = "sign_nillion_message"
    description: str = """Used to sign messages using a private key securely stored in Nillion. 
If no message type is specified, assumes SIMPLE message signing.

Common usage (Simple Messages):
   When someone just says "sign this message" or similar, use:
   - message_type: "simple"
   - message: The text to sign
   
   Examples of simple message requests:
   - "Sign this message: Hello World"
   - "Sign: gm"
   - "Create a signature for: Testing 123"
   - "I need this message signed: Welcome to Nillion"
   - "Sign 'Hello' for me"

Advanced Message Types:

1. Transaction (tx) Messages:
   Must explicitly request tx signing with:
   - message_type: "tx"
   - tx_hash: The transaction hash to sign
   - message: Optional message to include
   
2. Sign-In with Ethereum (SIWE) Messages:
   Must explicitly request SIWE signing with:
   - message_type: "siwe"
   - domain: The requesting domain
   - ethereum_address: The signing address

For any request that doesn't specifically mention tx or SIWE, use simple message signing."""
    args_schema: Type[BaseModel] = SignMessageInput

    def _run(
        self,
        message_type: str,
        **kwargs
    ) -> dict:
        """Synchronous run not supported."""
        raise NotImplementedError("sign_nillion_message does not support synchronous execution")

    async def _arun(
        self,
        message_type: str,
        **kwargs
    ) -> dict:
        """Sign a message asynchronously."""
        store_id = os.getenv('NILLION_STORE_ID')
        if not store_id:
            raise ValueError("NILLION_STORE_ID not found in environment variables")
        
        seed = os.getenv('NILLION_USER_KEY_SEED')
        if not seed:
            raise ValueError("NILLION_USER_KEY_SEED not found in environment variables")

        # Prepare message parameters based on type
        if message_type == "simple":
            if not kwargs.get("message"):
                raise ValueError("message parameter is required for simple messages")
            message_params = SimpleMessageParams(message=kwargs["message"])
        
        elif message_type == "tx":
            if not kwargs.get("tx_hash"):
                raise ValueError("tx_hash parameter is required for transaction messages")
            message_params = TxMessageParams(
                message=kwargs.get("message", ""),
                tx_hash=kwargs["tx_hash"]
            )
        
        elif message_type == "siwe":
            required_fields = ["domain", "ethereum_address"]
            missing_fields = [f for f in required_fields if not kwargs.get(f)]
            if missing_fields:
                raise ValueError(f"Missing required SIWE parameters: {', '.join(missing_fields)}")
            
            message_params = SiweMessageParams(
                domain=kwargs["domain"],
                ethereum_address=kwargs["ethereum_address"],
                uri=kwargs.get("uri"),
                version=kwargs.get("version"),
                chain_id=kwargs.get("chain_id"),
                nonce=kwargs.get("nonce"),
                issued_at=kwargs.get("issued_at"),
                expiration_time=kwargs.get("expiration_time"),
                not_before=kwargs.get("not_before"),
                request_id=kwargs.get("request_id"),
                resources=kwargs.get("resources"),
                statement=kwargs.get("statement")
            )
        
        else:
            raise ValueError(f"Unsupported message type: {message_type}. Must be one of: simple, tx, siwe")

        return await sign_message(
            store_id_private_key=store_id,
            message_params=message_params,
            user_key_seed=seed
        )

class NillionSendTransactionTool(BaseTool):
    """Tool for sending transactions using Nillion."""
    name: str = "send_nillion_transaction"
    description: str = """Used to send Ethereum transactions on Base Sepolia using a private key stored in Nillion.

Required parameters:
   - amount_in_eth: The amount of ETH to send (e.g., 0.0001, 1.5)
   - to_address: The destination Ethereum address (must start with 0x)

Optional parameters (with defaults):
   - data: A message to include with the transaction (default: "LFG 🚀")
   - priority_fee_gwei: Priority fee in GWEI for faster processing (default: 10)

Examples of when to use this tool:
   - "Send 0.0001 ETH to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
   - "Transfer 0.5 ETH to 0x123... with message 'payment for services'"
   - "Send 0.1 ETH to 0xabc..."
   - "Make a payment of 0.05 ETH to 0x456..."

The tool automatically handles:
   - Gas estimation and fee calculation
   - Transaction signing
   - Transaction submission and confirmation
   - Base Sepolia network configuration"""
    args_schema: Type[BaseModel] = SendTransactionInput

    def _run(
        self,
        amount_in_eth: float,
        to_address: str,
        from_address: str,
        user_key_seed: str = "demo",
        data: str = "LFG 🚀",
        chain_id: int = 84532,
        priority_fee_gwei: int = 10,
        run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> dict:
        """Synchronous run not supported."""
        raise NotImplementedError("send_nillion_transaction does not support synchronous execution")

    async def _arun(
        self,
        amount_in_eth: float,
        to_address: str,
        data: str = "LFG 🚀",
        chain_id: int = 84532,
        priority_fee_gwei: int = 10,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None
    ) -> dict:
        """Send a transaction asynchronously."""
        store_id = os.getenv('NILLION_STORE_ID')
        if not store_id:
            raise ValueError("NILLION_STORE_ID not found in environment variables")

        from_address = os.getenv('NILLION_ETH_ADDRESS')
        if not from_address:
            raise ValueError("NILLION_ETH_ADDRESS not found in environment variables")
        
        seed = os.getenv('NILLION_USER_KEY_SEED')
        if not seed:
            raise ValueError("NILLION_USER_KEY_SEED not found in environment variables")
        
        return await send_transaction(
            amount_in_eth=amount_in_eth,
            to_address=to_address,
            from_address=from_address,
            store_id_private_key=store_id,
            user_key_seed=seed,
            data=data,
            chain_id=chain_id,
            priority_fee_gwei=priority_fee_gwei
        )

class NillionToolkit:
    """Toolkit for Nillion operations."""
    
    def get_tools(self):
        """Get all tools in the toolkit."""
        return [
            NillionUserIdTool(),
            NillionSignMessageTool(),
            NillionSendTransactionTool()
        ]