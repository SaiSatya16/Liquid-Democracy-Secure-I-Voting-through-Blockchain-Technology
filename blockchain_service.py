# blockchain_service.py
from blockchain_config import w3, contract, account
from web3.exceptions import ContractLogicError
PRIVATE_KEY = '0x40ebed728dfb45ebef989f0b65e378be0a97e1df8c9699046ec146a94eeeae9a'
class BlockchainService:
    @staticmethod
    def create_scheme(name, description):
        try:
            # Build transaction
            tx = contract.functions.createScheme(name, description).build_transaction({
                'from': account.address,
                'nonce': w3.eth.get_transaction_count(account.address),
                'gas': 2000000,
                'gasPrice': w3.eth.gas_price
            })
            
            # Sign transaction
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
            
            # Send transaction
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
            # Wait for transaction receipt
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            # Get the scheme ID from the event logs
            scheme_created_event = contract.events.SchemeCreated().process_receipt(receipt)
            scheme_id = scheme_created_event[0]['args']['id']
            
            return scheme_id, True, None
        except ContractLogicError as e:
            return None, False, str(e)
        except Exception as e:
            return None, False, str(e)
    
    @staticmethod
    def cast_vote(user_address, scheme_id, vote_value):
        try:
            # Convert scheme_id to integer
            scheme_id = int(scheme_id)
            
            # Build transaction
            tx = contract.functions.castVote(scheme_id, vote_value).build_transaction({
                'from': account.address,
                'nonce': w3.eth.get_transaction_count(account.address),
                'gas': 2000000,
                'gasPrice': w3.eth.gas_price
            })
            
            # Sign transaction
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
            
            # Send transaction
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
            # Wait for transaction receipt
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return True, None
        except ContractLogicError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def delegate_vote(delegator_address, delegatee_address, scheme_id):
        try:
            # Build transaction
            tx = contract.functions.delegate(delegatee_address, scheme_id).build_transaction({
                'from': account.address,
                'nonce': w3.eth.get_transaction_count(account.address),
                'gas': 2000000,
                'gasPrice': w3.eth.gas_price
            })
            
            # Sign transaction
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
            
            # Send transaction
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
            # Wait for transaction receipt
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return True, None
        except ContractLogicError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def get_vote_count(scheme_id):
        try:
            result = contract.functions.getVoteCount(scheme_id).call()
            return result[0], result[1], True, None
        except Exception as e:
            return 0, 0, False, str(e)
    
    @staticmethod
    def get_voter_weight(voter_address, scheme_id):
        try:
            # For string addresses, we can pass them directly to the contract function
            weight = contract.functions.getVoterWeight(voter_address, scheme_id).call()
            return weight, True, None
        except Exception as e:
            return 0, False, str(e)
