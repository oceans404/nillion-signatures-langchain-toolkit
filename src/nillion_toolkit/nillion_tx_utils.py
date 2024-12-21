import requests
import time
from web3 import Web3
from eth_utils import keccak
from eth_account.datastructures import SignedTransaction
from hexbytes import HexBytes
import rlp
from nillion_toolkit.nillion_utils import sign_message, TxMessageParams
import os
from dotenv import load_dotenv

# Load environment variables at the start of the file
load_dotenv()

RPC_URL = f"https://base-sepolia.g.alchemy.com/v2/{os.getenv('ALCHEMY_API_KEY')}"

w3 = Web3()

def make_rpc_call(method, params):
    """Make a JSON-RPC call to the Ethereum node."""
    payload = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": method,
        "params": params
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }
    response = requests.post(RPC_URL, json=payload, headers=headers)
    json_response = response.json()
    
    if "error" in json_response:
        raise Exception(f"RPC error: {json_response['error']}")
    if "result" not in json_response:
        raise Exception(f"Invalid RPC response: {json_response}")
        
    return json_response["result"]

def get_balance(address):
    """Get the ETH balance of an address."""
    balance_hex = make_rpc_call(
        "eth_getBalance",
        [address, "latest"]
    )
    balance_wei = int(balance_hex, 16)
    balance_eth = balance_wei / 10**18
    return balance_eth

def create_transaction_message_hash(unsigned_tx):
    """
    Create a message hash from an unsigned transaction following EIP-1559 format.
    Returns both the message and its hash for signing.
    """
    def to_int(value):
        if isinstance(value, str) and value.startswith('0x'):
            return int(value, 16)
        return value

    fields = [
        to_int(unsigned_tx['chainId']),
        to_int(unsigned_tx['nonce']),
        to_int(unsigned_tx['maxPriorityFeePerGas']),
        to_int(unsigned_tx['maxFeePerGas']),
        to_int(unsigned_tx['gas']),
        bytes.fromhex(unsigned_tx['to'][2:]),
        to_int(unsigned_tx['value']),
        unsigned_tx['data'],
        []  # Empty access list
    ]
    
    tx_type = bytes([to_int(unsigned_tx['type'])])
    encoded_fields = rlp.encode(fields)
    message_to_hash = tx_type + encoded_fields
    
    return {
        'message': message_to_hash, 
        'hashed': keccak(message_to_hash)
    }

async def get_dynamic_gas_price():
    # Fetch the current gas price using RPC call
    current_gas_price = int(make_rpc_call("eth_gasPrice", []), 16)

    # Set a minimum and maximum gas price (in wei)
    min_gas_price = int(current_gas_price * 0.9)  # 10% lower than current
    max_gas_price = int(current_gas_price * 1.5)  # 50% higher than current

    # Return the adjusted gas price
    return int(max(min_gas_price, min(max_gas_price, current_gas_price)))

async def send_payment(to_address, amount_in_eth, from_address):
    # Get balance using the existing RPC method
    balance_eth = get_balance(from_address)
    balance_wei = int(balance_eth * 10**18)
    
    # Get gas price using our updated method
    gas_price = await get_dynamic_gas_price()
    estimated_gas = 21000  # Standard ETH transfer gas limit
    
    # Calculate total required amount in wei
    amount_wei = int(amount_in_eth * 10**18)
    total_cost_wei = amount_wei + (estimated_gas * gas_price)
    
    if balance_wei < total_cost_wei:
        raise Exception(f"Insufficient funds. Have: {balance_eth} ETH, Need: {total_cost_wei / 10**18} ETH (including gas)")

    # Create transaction
    tx = {
        'nonce': int(make_rpc_call("eth_getTransactionCount", [from_address, "latest"]), 16),
        'to': to_address,
        'value': amount_wei,
        'gas': estimated_gas,
        'gasPrice': gas_price,
        'chainId': 84532  # Base Sepolia chain ID
    }

    # Send the transaction using RPC
    tx_hash = make_rpc_call("eth_sendTransaction", [tx])
    return tx_hash

async def send_transaction(
    amount_in_eth: float,
    to_address: str,
    from_address: str,
    store_id_private_key: str,
    user_key_seed: str = "demo",
    data: str = "LFG 🚀",
    chain_id: int = 84532,
    priority_fee_gwei: int = 2
) -> dict:
    """
    Transfer ETH using a private key stored in Nillion with a Nillion tECDSA signature.
    Uses generous gas estimates to ensure transaction success.
    """
    if data.startswith('0x'):
        data_bytes = bytes.fromhex(data[2:])
    else:
        data_bytes = data.encode('utf-8')
    
    hex_data = '0x' + data_bytes.hex()
    balance = get_balance(from_address)
    
    if balance < amount_in_eth:
        raise Exception(f"Insufficient balance: have {balance:.4f} ETH, trying to send {amount_in_eth} ETH")
    
    nonce = int(make_rpc_call("eth_getTransactionCount", [from_address, "latest"]), 16)
    block = make_rpc_call("eth_getBlockByNumber", ["latest", False])
    base_fee = int(block["baseFeePerGas"], 16)
    
    # Increase priority fee for faster inclusion
    priority_fee = max(priority_fee_gwei, 3) * 10**9
    
    # More generous max fee calculation (12x base fee + priority fee)
    max_fee = (12 * base_fee) + priority_fee

    # More generous gas limit calculation
    base_gas = 100000  # Increased from 50000
    data_gas_cost = len(hex_data[2:]) // 2 * 32  # Doubled from 16
    gas_limit = base_gas if (hex_data == '0x' or not hex_data) else base_gas + data_gas_cost

    tx = {
        'nonce': nonce,
        'to': to_address,
        'value': int(amount_in_eth * 10**18),
        'gas': gas_limit,
        'maxFeePerGas': max_fee,
        'maxPriorityFeePerGas': priority_fee,
        'chainId': chain_id,
        'type': 2,
        'data': data_bytes
    }

    # Calculate max cost with generous gas limit
    max_tx_cost_eth = (max_fee * gas_limit) / 10**18
    total_required = amount_in_eth + max_tx_cost_eth
    
    if balance < total_required:
        raise Exception(f"Insufficient balance for tx + gas: have {balance:.4f} ETH, need {total_required:.4f} ETH")

    tx_hash_data = create_transaction_message_hash(tx)
    signed = await sign_message(
        store_id_private_key=store_id_private_key,
        message_params=TxMessageParams(
            tx_hash=tx_hash_data['hashed'],
            message=tx_hash_data['message']
        ),
        user_key_seed=user_key_seed
    )
    
    r = int(signed['signature']['r'], 16)
    s = int(signed['signature']['s'], 16)
    v = 0  # EIP-1559 signature
    
    signed_fields = [
        tx['chainId'],
        tx['nonce'],
        tx['maxPriorityFeePerGas'],
        tx['maxFeePerGas'],
        tx['gas'],
        bytes.fromhex(tx['to'][2:]),
        tx['value'],
        tx['data'],
        [],
        v, r, s
    ]
    
    encoded_fields = rlp.encode(signed_fields)
    raw_tx = bytes([tx['type']]) + encoded_fields
    
    signed_tx = SignedTransaction(
        raw_transaction=HexBytes(raw_tx),
        hash=HexBytes(tx_hash_data['hashed']),
        r=r,
        s=s,
        v=v
    )
    
    tx_hash = make_rpc_call(
        "eth_sendRawTransaction",
        [Web3.to_hex(signed_tx.raw_transaction)]
    )
    
    # Wait for receipt with longer timeout
    max_attempts = 60  # 1 minute timeout
    attempts = 0
    while attempts < max_attempts:
        receipt = make_rpc_call(
            "eth_getTransactionReceipt",
            [tx_hash]
        )
        if receipt is not None:
            return receipt
        time.sleep(1)
        attempts += 1
    
    raise Exception("Transaction not mined within 60 seconds")