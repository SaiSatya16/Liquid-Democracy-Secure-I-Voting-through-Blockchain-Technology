# api.py
from flask_restful import Resource, Api, fields, marshal_with, reqparse
from model import *
from werkzeug.exceptions import HTTPException
from flask_cors import CORS
import json
from flask import make_response, request
from flask_security import auth_required, roles_required
import os
from functools import wraps
from flask import abort
from flask_security import roles_accepted
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import boto3 
from Crypto.Util.Padding import unpad
import numpy as np
from botocore.exceptions import ClientError
from blockchain_service import BlockchainService
from web3 import Web3
from blockchain_config import w3

api = Api()

def any_role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            if not roles_accepted(*roles):
                abort(403, description="Insufficient permissions")
            return fn(*args, **kwargs)
        return decorator
    return wrapper

#==========================Validation========================================================
class NotFoundError(HTTPException):
    def __init__(self,status_code):
        message = {"error_code":"BE1009","error_message":"Not Found"}
        self.response = make_response(json.dumps(message), status_code)

class BusinessValidationError(HTTPException):
    def __init__(self, status_code, error_code, error_message):
        message = {"error_code":error_code,"error_message":error_message}
        self.response = make_response(json.dumps(message), status_code)


#==============================output fields========================================
scheme_fields = {
    'id': fields.Integer,
    'name': fields.String,
    'description': fields.String
}

vote_filelds = {
    'id': fields.Integer,
    'user_id': fields.Integer,
    'scheme_id': fields.Integer,
    'vote': fields.Boolean
}

#====================Create Scheme and Votes request pares=======================================
create_scheme_parser = reqparse.RequestParser()
create_scheme_parser.add_argument('name')
create_scheme_parser.add_argument('description')

create_vote_parser = reqparse.RequestParser()
create_vote_parser.add_argument('user_id')
create_vote_parser.add_argument('scheme_id')
create_vote_parser.add_argument('vote')

#====================Update Scheme and Votes request pares=======================================
update_scheme_parser = reqparse.RequestParser()
update_scheme_parser.add_argument('name')
update_scheme_parser.add_argument('description')

update_vote_parser = reqparse.RequestParser()
update_vote_parser.add_argument('user_id')
update_vote_parser.add_argument('scheme_id')
update_vote_parser.add_argument('vote')

class SecureVoting:
    def __init__(self):
        # Use a constant master key for simplicity - in production, use a more secure approach
        # This should be stored securely, possibly as an environment variable
        self.master_key = os.environ.get('MASTER_KEY', 'ThisIsA32ByteMasterKeyForEncryption').encode()[:32]
        
    def generate_data_key(self):
        # Generate a random data key
        data_key = get_random_bytes(32)
        
        # Encrypt the data key with the master key
        cipher = AES.new(self.master_key, AES.MODE_GCM)
        encrypted_key, tag = cipher.encrypt_and_digest(data_key)
        
        return data_key, encrypted_key, cipher.nonce, tag
        
    def encrypt_vote(self, vote_value):
        # Generate and encrypt a data key
        data_key, encrypted_key, nonce, tag = self.generate_data_key()
        
        # Use the data key to encrypt the vote
        vote_cipher = AES.new(data_key, AES.MODE_GCM)
        vote_ciphertext, vote_tag = vote_cipher.encrypt_and_digest(vote_value.encode())
        
        # Combine the encrypted vote components for storage
        encrypted_vote = base64.b64encode(vote_cipher.nonce + vote_tag + vote_ciphertext).decode()
        
        return encrypted_vote, encrypted_key, nonce, tag
        
    def decrypt_vote(self, encrypted_vote, encrypted_key, nonce, tag):
        try:
            # Decrypt the data key using the master key
            cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=nonce)
            data_key = cipher.decrypt_and_verify(encrypted_key, tag)
            
            # Decrypt the vote using the data key
            encrypted_data = base64.b64decode(encrypted_vote)
            vote_nonce = encrypted_data[:16]
            vote_tag = encrypted_data[16:32]
            vote_ciphertext = encrypted_data[32:]
            
            vote_cipher = AES.new(data_key, AES.MODE_GCM, nonce=vote_nonce)
            decrypted_vote = vote_cipher.decrypt_and_verify(vote_ciphertext, vote_tag)
            
            return decrypted_vote.decode()
        except Exception as e:
            print(f"Error decrypting vote: {e}")
            raise

class SchemeApi(Resource):
    def __init__(self):
        self.secure_voting = SecureVoting()
        self.blockchain_service = BlockchainService()

    @auth_required('token')
    @any_role_required('admin', 'voter')
    def get(self, id):
        data = []
        schemes = Scheme.query.all()

        for scheme in schemes:
            allowed_to_vote = False
            usercurrentvote_count = 0
            usercurrentvote = Usercurrentvote.query.filter_by(user_id=id, scheme_id=scheme.id).first()
            usercurrentvote_count = Usercurrentvote.query.filter_by(user_id=id, scheme_id=scheme.id).count()

            if usercurrentvote:
                allowed_to_vote = True

            # Get vote counts from blockchain
            true_vote_count, false_vote_count, success, error = self.blockchain_service.get_vote_count(scheme.id)
            
            if not success:
                # Fallback to database if blockchain call fails
                true_vote_count = 0
                false_vote_count = 0
                
                # Calculate true and false vote count from database
                for vote in scheme.votes:
                    try:
                        if vote.encryption_key:
                            decrypted_vote = self.secure_voting.decrypt_vote(
                                vote.vote, 
                                vote.encryption_key.encrypted_key,
                                vote.encryption_key.nonce,
                                vote.encryption_key.tag
                            )
                            if decrypted_vote == 'true':
                                true_vote_count += 1
                            elif decrypted_vote == 'false':
                                false_vote_count += 1
                    except Exception as e:
                        print(f"Error decrypting vote {vote.id}: {e}")

            total_votes = true_vote_count + false_vote_count

            true_vote_percentage = 0
            false_vote_percentage = 0
            if total_votes > 0:
                true_vote_percentage = round((true_vote_count / total_votes) * 100, 2)
                false_vote_percentage = round((false_vote_count / total_votes) * 100, 2)

            delegation = Delegation.query.filter_by(delegator_id=id, scheme_id=scheme.id).first()
            delegated_to = None
            if delegation:
                delegatee = User.query.get(delegation.delegatee_id)
                delegated_to = {
                    'id': delegatee.id,
                    'username': delegatee.username
                }

            not_delegated_users = User.query.filter(User.roles.any(Role.name == 'Voter'))\
                .filter(~User.id.in_(db.session.query(Delegation.delegator_id)\
                .filter(Delegation.scheme_id == scheme.id)))\
                .filter(~User.id.in_(db.session.query(Vote.user_id)\
                .filter(Vote.scheme_id == scheme.id)))\
                .filter(User.id != id)\
                .all()

            # Get user weight from blockchain
            user = User.query.get(id)
            user_address = f"0x{id:040x}"  # Create a dummy Ethereum address from user ID
            user_weight, success, error = self.blockchain_service.get_voter_weight(user_address, scheme.id)
            
            if not success:
                # Fallback to database calculation
                user_weight = user.calculate_weight(scheme.id)
            
            # Calculate delegation chain
            chain = []
            current_user = user
            while True:
                delegation = Delegation.query.filter_by(delegator_id=current_user.id, scheme_id=scheme.id).first()
                if delegation:
# api.py (continued)
                    delegatee = User.query.get(delegation.delegatee_id)
                    chain.append(delegatee.username)
                    current_user = delegatee
                else:
                    break
            
            delegation_chain_length = len(chain)

            # Calculate Gini coefficient
            all_weights = [u.calculate_weight(scheme.id) for u in User.query.filter(User.roles.any(Role.name == 'Voter')).all()]
            gini_coefficient = self.calculate_gini(all_weights)

            data.append({
                'id': scheme.id,
                'name': scheme.name,
                'description': scheme.description,
                'allowed_to_vote': allowed_to_vote,
                'true_vote_percentage': true_vote_percentage,
                'false_vote_percentage': false_vote_percentage,
                'true_vote_count': true_vote_count,
                'false_vote_count': false_vote_count,
                'usercurrentvote_count': usercurrentvote_count,
                'not_delegated_users': [{'id': user.id, 'username': user.username} for user in not_delegated_users],
                'delegated_to': delegated_to,
                'userWeight': user_weight,
                'delegationChainLength': delegation_chain_length,
                'giniCoefficient': gini_coefficient,
                'blockchain_verified': success  # Add blockchain verification status
            })

        return data

    def calculate_gini(self, weights):
        sorted_weights = sorted(weights)
        height, area = 0, 0
        for weight in sorted_weights:
            height += weight
            area += height - weight / 2.
        fair_area = height * len(weights) / 2.
        return (fair_area - area) / fair_area
    
    @marshal_with(scheme_fields)
    @auth_required('token')
    @any_role_required('admin')
    def post(self):
        args = create_scheme_parser.parse_args()
        name = args.get('name', None)
        description = args.get('description', None)
        if not name:
            raise BusinessValidationError(400, "BE1001", "Name is required")
        if not description:
            raise BusinessValidationError(400, "BE1002", "Description is required")
        
        # Create scheme in blockchain
        scheme_id, success, error = self.blockchain_service.create_scheme(name, description)
        
        if not success:
            raise BusinessValidationError(500, "BE1010", f"Blockchain error: {error}")
        
        # Create scheme in database
        scheme = Scheme(name=name, description=description)
        db.session.add(scheme)
        db.session.commit()
        
        scheme = Scheme.query.filter_by(name=name).first()
        s_id = scheme.id
        
        # Query only users with role voter
        users = User.query.filter(User.roles.any(Role.name == 'Voter')).all()
        for user in users:
            usercurrentvote = Usercurrentvote(user_id=user.id, scheme_id=s_id, vote=None)
            db.session.add(usercurrentvote)
        db.session.commit()
        return scheme
class VoteApi(Resource):
    def __init__(self):
        self.secure_voting = SecureVoting()
        self.blockchain_service = BlockchainService()

    @marshal_with(vote_filelds)
    @auth_required('token')
    @any_role_required('voter')
    def post(self):
        args = create_vote_parser.parse_args()
        user_id = args.get('user_id', None)
        scheme_id = args.get('scheme_id', None)
        vote_value = args.get('vote', None)
        
        if not user_id:
            raise BusinessValidationError(400, "BE1003", "User id is required")
        if not scheme_id:
            raise BusinessValidationError(400, "BE1004", "Scheme id is required")
        if vote_value is None:
            raise BusinessValidationError(400, "BE1005", "Vote is required")
        
        # Convert vote to boolean for blockchain
        vote_bool = vote_value.lower() == 'true'
        
        # Create Ethereum address from user ID (in a real app, users would have real addresses)
        user_address = f"0x{int(user_id):040x}"
        
        # Submit vote to blockchain
        success, error = self.blockchain_service.cast_vote(user_address, scheme_id, vote_bool)
        
        if not success:
            # If blockchain fails, continue with database only but log the error
            print(f"Blockchain voting failed: {error}")
        
        user_current_votes_count = Usercurrentvote.query.filter_by(user_id=user_id, scheme_id=scheme_id).count()
        last_vote = None
        
        for i in range(user_current_votes_count):
            # Encrypt the vote
            encrypted_vote, encrypted_key, nonce, tag = self.secure_voting.encrypt_vote(vote_value)
            
            # Create and save the vote
            vote_obj = Vote(user_id=user_id, scheme_id=scheme_id, vote=encrypted_vote)
            db.session.add(vote_obj)
            db.session.flush()  # Flush to get the vote ID
            
            # Create and save the encryption key
            key_obj = EncryptionKey(
                vote_id=vote_obj.id,
                encrypted_key=encrypted_key,
                nonce=nonce,
                tag=tag
            )
            db.session.add(key_obj)
            last_vote = vote_obj
        
        # Delete all the entries from usercurrentvote table
        user_current_votes = Usercurrentvote.query.filter_by(user_id=user_id, scheme_id=scheme_id).all()
        for user_current_vote in user_current_votes:
            db.session.delete(user_current_vote)
        
        db.session.commit()
        return last_vote
class DelegationApi(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('delegator_id', type=int, required=True, help='Delegator user ID is required')
        self.parser.add_argument('delegatee_id', type=int, required=True, help='Delegatee user ID is required')
        self.parser.add_argument('scheme_id', type=int, required=True, help='Scheme ID is required')
        self.blockchain_service = BlockchainService()

    @auth_required('token')
    def post(self):
        args = self.parser.parse_args()
        delegator_id = args['delegator_id']
        delegatee_id = args['delegatee_id']
        scheme_id = args['scheme_id']

        delegator = User.query.get(delegator_id)
        delegatee = User.query.get(delegatee_id)
        scheme = Scheme.query.get(scheme_id)

        if not delegator or not delegatee or not scheme:
            return {'error_message': 'Invalid user ID(s) or scheme ID'}, 400
            
        if delegator.is_delegating_to(delegatee, scheme_id):
            return {'error_message': 'Delegation already exists for this scheme'}, 400
        
        existing_delegation = Delegation.query.filter_by(delegator_id=delegatee_id, delegatee_id=delegator_id, scheme_id=scheme_id).first()
        if existing_delegation:
            return {'error_message': 'Cannot delegate to a user who has already delegated to you for this scheme'}, 400

        # Create Ethereum addresses from user IDs
        delegator_address = f"0x{delegator_id:040x}"
        delegatee_address = f"0x{delegatee_id:040x}"
        
        # Submit delegation to blockchain
        success, error = self.blockchain_service.delegate_vote(delegator_address, delegatee_address, scheme_id)
        
        if not success:
            # If blockchain fails, continue with database only but log the error
            print(f"Blockchain delegation failed: {error}")

        # Transfer all delegator's current vote to delegatee's current vote
        delegator_current_votes = Usercurrentvote.query.filter_by(user_id=delegator_id, scheme_id=scheme.id).all()
        for vote in delegator_current_votes:
            delegatee_current_vote = Usercurrentvote(user_id=delegatee_id, scheme_id=scheme.id, vote=vote.vote)
            db.session.add(delegatee_current_vote)
            db.session.delete(vote)
        db.session.commit()

        delegator.delegate_to(delegatee, scheme_id)
        return {'message': 'Delegation added successfully'}, 201
class BlockchainStatusApi(Resource):
    def __init__(self):
        self.blockchain_service = BlockchainService()
    
    @auth_required('token')
    def get(self):
        try:
            # Check if connected to blockchain
            connected = w3.is_connected()
            
            # Get blockchain network info
            network_id = w3.net.version
            latest_block = w3.eth.block_number
            gas_price = w3.eth.gas_price

            CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS', 'YOUR_CONTRACT_ADDRESS')
            
            return {
                'connected': connected,
                'network_id': network_id,
                'latest_block': latest_block,
                'gas_price': str(gas_price),
                'contract_address': CONTRACT_ADDRESS
            }
        except Exception as e:
            return {
                'connected': False,
                'error': str(e)
            }

# Add the new API resource
api.add_resource(BlockchainStatusApi, '/blockchain-status')
api.add_resource(SchemeApi, '/scheme', '/scheme/<int:id>')
api.add_resource(VoteApi, '/vote')
api.add_resource(DelegationApi, '/delegation', '/delegation/<int:user_id>')


