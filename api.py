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
#relove conflict
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




#=================================Scheme api======================================================


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


class SecureVoting:
    def __init__(self):
        self.kms = boto3.client('kms', region_name='ap-south-1')
        self.kms_key_id = os.environ.get('KMS_KEY_ID')
        self.secrets_manager = boto3.client('secretsmanager', region_name='ap-south-1')

    def generate_data_key(self):
        try:
            response = self.kms.generate_data_key(
                KeyId=self.kms_key_id,
                KeySpec='AES_256'
            )
            return response['Plaintext'], response['CiphertextBlob']
        except ClientError as e:
            print(f"Error generating data key: {e}")
            raise

    def encrypt_vote(self, vote):
        try:
            plaintext_key, encrypted_key = self.generate_data_key()
            cipher = AES.new(plaintext_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(vote.encode())
            
            # Store encrypted key in AWS Secrets Manager
            secret_name = f"vote_key_{os.urandom(16).hex()}"
            self.secrets_manager.create_secret(
                Name=secret_name,
                SecretBinary=encrypted_key
            )
            
            return base64.b64encode(cipher.nonce + tag + ciphertext).decode(), secret_name
        except Exception as e:
            print(f"Error encrypting vote: {e}")
            raise

    def decrypt_vote(self, encrypted_vote, secret_name):
        try:
            # Retrieve encrypted key from AWS Secrets Manager
            response = self.secrets_manager.get_secret_value(SecretId=secret_name)
            encrypted_key = response['SecretBinary']
            
            # Decrypt the data key
            key_response = self.kms.decrypt(CiphertextBlob=encrypted_key)
            plaintext_key = key_response['Plaintext']
            
            # Decrypt the vote
            encrypted_data = base64.b64decode(encrypted_vote)
            nonce = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            cipher = AES.new(plaintext_key, AES.MODE_GCM, nonce=nonce)
            decrypted_vote = cipher.decrypt_and_verify(ciphertext, tag)
            
            return decrypted_vote.decode()
        except Exception as e:
            print(f"Error decrypting vote: {e}")
            raise







class SchemeApi(Resource):
    def __init__(self):
       self.secure_voting = SecureVoting()

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

            true_vote_count = 0
            false_vote_count = 0

            # Calculate true and false vote count
            for vote in scheme.votes:
                decrypted_vote = self.secure_voting.decrypt_vote(vote.vote, vote.key_secret_name)
                if decrypted_vote == 'true':
                    true_vote_count += 1
                elif decrypted_vote == 'false':
                    false_vote_count += 1

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

            # Calculate user weight and delegation chain length
            user = User.query.get(id)
            user_weight = user.calculate_weight(scheme.id)
            
            # Calculate delegation chain
            chain = []
            current_user = user
            while True:
                delegation = Delegation.query.filter_by(delegator_id=current_user.id, scheme_id=scheme.id).first()
                if delegation:
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
                'giniCoefficient': gini_coefficient
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
        scheme = Scheme(name=name, description=description)
        db.session.add(scheme)
        db.session.commit()
        scheme = Scheme.query.filter_by(name=name).first()
        s_id = scheme.id

        #query only users with role voter
        users = User.query.filter(User.roles.any(Role.name == 'Voter')).all()
        for user in users:
            usercurrentvote = Usercurrentvote(user_id=user.id, scheme_id=s_id, vote=None)
            db.session.add(usercurrentvote)
        db.session.commit()
        return scheme   
    
    @marshal_with(scheme_fields)
    @auth_required('token')
    @any_role_required('admin')
    def put(self, id):
        args = update_scheme_parser.parse_args()
        name = args.get('name', None)
        description = args.get('description', None)
        scheme = Scheme.query.filter_by(id=id).first()
        if not scheme:
            raise NotFoundError(404)
        if name:
            scheme.name = name
        if description:
            scheme.description = description
        db.session.commit()
        return scheme
    
    @auth_required('token')
    @any_role_required('admin')
    def delete(self, id):
        scheme = Scheme.query.filter_by(id=id).first()
        if not scheme:
            raise NotFoundError(404)
        db.session.query(Vote).filter(Vote.scheme_id == id).delete()
        db.session.query(Usercurrentvote).filter(Usercurrentvote.scheme_id == id).delete()
        db.session.delete(scheme)
        db.session.commit()
        return {'message': 'Scheme deleted successfully'}

#=================================Vote api======================================================
    
class VoteApi(Resource):
    def __init__(self):
        self.secure_voting = SecureVoting()

    @marshal_with(vote_filelds)
    @auth_required('token')
    @any_role_required('voter')
    def post(self):
        args = create_vote_parser.parse_args()
        user_id = args.get('user_id', None)
        scheme_id = args.get('scheme_id', None)
        vote = args.get('vote', None)
        if not user_id:
            raise BusinessValidationError(400, "BE1003", "User id is required")
        if not scheme_id:
            raise BusinessValidationError(400, "BE1004", "Scheme id is required")
        if vote is None:
            raise BusinessValidationError(400, "BE1005", "Vote is required")
        
        user_current_votes_count = Usercurrentvote.query.filter_by(user_id=user_id, scheme_id=scheme_id).count()
        for i in range(user_current_votes_count):
            encrypted_vote, secret_name = self.secure_voting.encrypt_vote(vote)
            vote_ = Vote(user_id=user_id, scheme_id=scheme_id, vote=encrypted_vote, key_secret_name=secret_name)
            db.session.add(vote_)
        #delete all the entries from usercurrentvote table
        user_current_votes = Usercurrentvote.query.filter_by(user_id=user_id, scheme_id=scheme_id).all()
        for user_current_vote in user_current_votes:
            db.session.delete(user_current_vote)
        db.session.commit()

        return vote_
    

class DelegationApi(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('delegator_id', type=int, required=True, help='Delegator user ID is required')
        self.parser.add_argument('delegatee_id', type=int, required=True, help='Delegatee user ID is required')
        self.parser.add_argument('scheme_id', type=int, required=True, help='Scheme ID is required')

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

        # Transfer all delegator's current vote to delegatee's current vote
        delegator_current_votes = Usercurrentvote.query.filter_by(user_id=delegator_id, scheme_id=scheme.id).all()
        for vote in delegator_current_votes:
            delegatee_current_vote = Usercurrentvote(user_id=delegatee_id, scheme_id=scheme.id, vote=vote.vote)
            db.session.add(delegatee_current_vote)
            db.session.delete(vote)
        db.session.commit()

        delegator.delegate_to(delegatee, scheme_id)
        return {'message': 'Delegation added successfully'}, 201

    @auth_required('token')
    def delete(self):
        args = self.parser.parse_args()
        delegator_id = args['delegator_id']
        delegatee_id = args['delegatee_id']
        scheme_id = args['scheme_id']

        delegator = User.query.get(delegator_id)
        delegatee = User.query.get(delegatee_id)
        scheme = Scheme.query.get(scheme_id)

        if not delegator or not delegatee or not scheme:
            return {'message': 'Invalid user ID(s) or scheme ID'}, 400

        if not delegator.is_delegating_to(delegatee, scheme_id):
            return {'message': 'No delegation found for this scheme'}, 400

        delegator.undelegate_to(delegatee, scheme_id)
        return {'message': 'Delegation removed successfully'}

    @auth_required('token')
    def get(self, user_id):
        user = User.query.get(user_id)
        if not user:
            return {'message': 'Invalid user ID'}, 400

        delegations = {}
        for scheme in Scheme.query.all():
            delegated_to = user.delegates.filter_by(scheme_id=scheme.id).first()
            if delegated_to:
                delegatee = User.query.get(delegated_to.delegatee_id)
                delegations[scheme.id] = {
                    'delegatee_id': delegatee.id,
                    'delegatee_username': delegatee.username
                }
            else:
                delegations[scheme.id] = {}

        return delegations

class DelegationChainApi(Resource):
    @auth_required('token')
    def get(self, user_id, scheme_id):
        user = User.query.get(user_id)
        scheme = Scheme.query.get(scheme_id)
        
        if not user or not scheme:
            return {'error': 'Invalid user or scheme'}, 400
        
        chain = [user.username]
        current_user = user
        while True:
            delegation = Delegation.query.filter_by(delegator_id=current_user.id, scheme_id=scheme_id).first()
            if delegation:
                delegatee = User.query.get(delegation.delegatee_id)
                chain.append(delegatee.username)
                current_user = delegatee
            else:
                break
        
        return chain

class VotingPowerDistributionApi(Resource):
    @auth_required('token')
    def get(self, scheme_id):
        scheme = Scheme.query.get(scheme_id)
        
        if not scheme:
            return {'error': 'Invalid scheme'}, 400
        
        users = User.query.filter(User.roles.any(Role.name == 'Voter')).all()
        weights = [user.calculate_weight(scheme_id) for user in users]
        
        # Create bins for the histogram
        max_weight = max(weights)
        bin_count = min(10, len(set(weights)))  # Use at most 10 bins
        bins = [i * max_weight / bin_count for i in range(bin_count + 1)]
        
        # Count weights in each bin
        hist, _ = np.histogram(weights, bins=bins)
        
        # Prepare labels for each bin
        labels = [f"{bins[i]:.2f}-{bins[i+1]:.2f}" for i in range(len(bins)-1)]
        
        return {
            'labels': labels,
            'data': hist.tolist()
        }

# Add the new API resources
api.add_resource(SchemeApi, '/scheme', '/scheme/<int:id>')
api.add_resource(VoteApi, '/vote')
api.add_resource(DelegationApi, '/delegation', '/delegation/<int:user_id>')
api.add_resource(DelegationChainApi, '/delegation-chain/<int:user_id>/<int:scheme_id>')
api.add_resource(VotingPowerDistributionApi, '/voting-power-distribution/<int:scheme_id>')

    
    
