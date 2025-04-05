# blockchain_config.py
import os
import json
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

# Load environment variables
INFURA_URL = 'http://localhost:8545'  # Updated to use local Ganache
PRIVATE_KEY = os.getenv('PRIVATE_KEY', '0x40ebed728dfb45ebef989f0b65e378be0a97e1df8c9699046ec146a94eeeae9a')
CONTRACT_ADDRESS =  '0x6eDE39444B689F059A49Cb7302281E09CBde8d25'

# Initialize Web3
w3 = Web3(Web3.HTTPProvider(INFURA_URL))

# Load contract ABI
try:
    with open('contract_abi.json', 'r') as f:
        contract_abi = json.load(f)
except FileNotFoundError:
    print("Warning: contract_abi.json not found. Deploy the contract first.")
    contract_abi = []

# Add mock objects for testing if contract address is not set
import unittest.mock as mock

# If contract address is not set or invalid


    # Initialize contract
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)
    
    # Account setup

# Get the first account from Ganache
from eth_account import Account

# In blockchain_config.py
PRIVATE_KEY = '0x40ebed728dfb45ebef989f0b65e378be0a97e1df8c9699046ec146a94eeeae9a'
account = Account.from_key(PRIVATE_KEY)


   