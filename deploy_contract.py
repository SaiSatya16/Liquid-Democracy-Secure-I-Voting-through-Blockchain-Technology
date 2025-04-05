# deploy_contract.py
import json
import os
from web3 import Web3
from solcx import compile_standard, install_solc
from dotenv import load_dotenv

load_dotenv()

# Install specific Solidity compiler version
install_solc('0.8.0')

def deploy_contract():
    # Connect to local Ganache blockchain
    w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
    
    # Verify connection
    if not w3.is_connected():
        print("Failed to connect to Ganache. Make sure it's running.")
        return
    
    print(f"Connected to local blockchain. Chain ID: {w3.eth.chain_id}")
    
    # Compile the contract
    with open("contracts/VotingContract.sol", "r") as file:
        contract_source_code = file.read()
    
    compiled_sol = compile_standard(
        {
            "language": "Solidity",
            "sources": {"VotingContract.sol": {"content": contract_source_code}},
            "settings": {
                "outputSelection": {
                    "*": {"*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]}
                }
            },
        },
        solc_version="0.8.0",
    )
    
    # Save the compiled contract
    with open("compiled_contract.json", "w") as file:
        json.dump(compiled_sol, file)
    
    # Get bytecode and ABI
    bytecode = compiled_sol["contracts"]["VotingContract.sol"]["VotingContract"]["evm"]["bytecode"]["object"]
    abi = compiled_sol["contracts"]["VotingContract.sol"]["VotingContract"]["abi"]
    
    # Save ABI to a file
    with open("contract_abi.json", "w") as file:
        json.dump(abi, file)
    
    # Create contract instance
    VotingContract = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    # Get the first account from Ganache
    account = w3.eth.accounts[0]
    
    # Get transaction count
    nonce = w3.eth.get_transaction_count(account)
    
    # Get gas price (use a reasonable value for local development)
    gas_price = w3.eth.gas_price
    
    print(f"Deploying contract from account: {account}")
    
    # Build deployment transaction
    transaction = VotingContract.constructor().build_transaction(
        {
            "chainId": w3.eth.chain_id,
            "gas": 3000000,  # Higher gas limit for local testing
            "gasPrice": gas_price,
            "nonce": nonce,
            "from": account
        }
    )
    
    # For local Ganache, we can use the unlocked account directly
    tx_hash = w3.eth.send_transaction(transaction)
    print(f"Deployment transaction sent: {tx_hash.hex()}")
    
    # Wait for transaction receipt
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Contract deployed at address: {tx_receipt.contractAddress}")
    
    # Save contract address to .env file
    with open(".env", "a") as env_file:
        env_file.write(f"\nCONTRACT_ADDRESS={tx_receipt.contractAddress}")
    
    # Update blockchain_config.py with the new contract address
    with open("blockchain_config.py", "r") as config_file:
        config_content = config_file.read()
    
    # Replace the CONTRACT_ADDRESS line
    updated_content = config_content.replace(
        "CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS', 'YOUR_CONTRACT_ADDRESS')",
        f"CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS', '{tx_receipt.contractAddress}')"
    )
    
    # Replace the INFURA_URL line
    updated_content = updated_content.replace(
        "INFURA_URL = 'https://sepolia.infura.io/v3/b2d54daac63446b2b4f4ea5f18babef1'",
        "INFURA_URL = 'http://localhost:8545'"
    )
    
    with open("blockchain_config.py", "w") as config_file:
        config_file.write(updated_content)
    
    print("blockchain_config.py updated with local settings and new contract address")
    
    return tx_receipt.contractAddress

if __name__ == "__main__":
    deploy_contract()
