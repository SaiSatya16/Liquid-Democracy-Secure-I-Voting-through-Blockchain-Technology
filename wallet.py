from web3 import Web3
import os
import json
from eth_account import Account
import secrets
from model import db, User

class WalletManager:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        self.app = app
        # Ensure the wallets directory exists
        os.makedirs('wallets', exist_ok=True)
    
    def create_wallet(self, user_id, password):
        """Create a new Ethereum wallet for a user."""
        # Generate a random private key
        private_key = "0x" + secrets.token_hex(32)
        
        # Create account from private key
        account = Account.from_key(private_key)
        
        # Encrypt private key with password
        encrypted_key = Account.encrypt(private_key, password)
        
        # Save encrypted key to file
        wallet_path = f'wallets/wallet_{user_id}.json'
        with open(wallet_path, 'w') as f:
            json.dump(encrypted_key, f)
        
        # Return address and private key
        return {
            'address': account.address,
            'private_key': private_key
        }
    
    def get_wallet(self, user_id, password):
        """Get a user's wallet by decrypting their keystore file."""
        wallet_path = f'wallets/wallet_{user_id}.json'
        
        # Check if wallet exists
        if not os.path.exists(wallet_path):
            return None
        
        # Load encrypted key
        with open(wallet_path, 'r') as f:
            encrypted_key = json.load(f)
        
        try:
            # Decrypt private key
            private_key = Account.decrypt(encrypted_key, password)
            account = Account.from_key(private_key)
            
            return {
                'address': account.address,
                'private_key': private_key.hex()
            }
        except ValueError:
            # Incorrect password
            return None
    
    def wallet_exists(self, user_id):
        """Check if a wallet exists for a user."""
        wallet_path = f'wallets/wallet_{user_id}.json'
        return os.path.exists(wallet_path)

# Create wallet manager instance
wallet_manager = WalletManager()
