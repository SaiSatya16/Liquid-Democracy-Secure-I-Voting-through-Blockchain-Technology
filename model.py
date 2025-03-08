from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin
from sqlalchemy.orm import aliased
db = SQLAlchemy()


class RolesUsers(db.Model):
    __tablename__ = 'roles_users'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column('user_id', db.Integer(), db.ForeignKey('user.id'))
    role_id = db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=False)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    roles = db.relationship('Role', secondary='roles_users', backref=db.backref('users', lazy='dynamic'))
    currentvote = db.relationship('Usercurrentvote', backref='user', lazy='dynamic')

    # Delegation relationship
    delegates = db.relationship('Delegation',
                                foreign_keys='Delegation.delegator_id',
                                backref='delegator',
                                lazy='dynamic')

    def delegate_to(self, user, scheme_id):
        if not self.is_delegating_to(user, scheme_id):
            delegation = Delegation(delegator_id=self.id, delegatee_id=user.id, scheme_id=scheme_id)
            db.session.add(delegation)
            db.session.commit()

    def is_delegating_to(self, user, scheme_id):
        return self.delegates.filter_by(delegatee_id=user.id, scheme_id=scheme_id).count() > 0

    def undelegate_to(self, user, scheme_id):
        delegation = self.delegates.filter_by(delegatee_id=user.id, scheme_id=scheme_id).first()
        if delegation:
            db.session.delete(delegation)
            db.session.commit()
    
    def calculate_weight(self, scheme_id, visited=None):
        if visited is None:
            visited = set()

        if self.id in visited:
            return 0  # We've encountered a circular delegation, so we stop here

        visited.add(self.id)
        weight = 1

        # Use a subquery to avoid recursive queries
        subq = db.session.query(Delegation.delegator_id).filter(
            Delegation.scheme_id == scheme_id,
            Delegation.delegatee_id == self.id
        ).subquery()

        delegator_alias = aliased(User)
        delegators = db.session.query(delegator_alias).join(
            subq, subq.c.delegator_id == delegator_alias.id
        ).all()

        for delegator in delegators:
            weight += delegator.calculate_weight(scheme_id, visited.copy())

        return weight
class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False, unique=True)
    description = db.Column(db.String, nullable=False)


class Scheme(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    description = db.Column(db.String(255))
    votes = db.relationship('Vote', backref='scheme', lazy='dynamic')

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    scheme_id = db.Column(db.Integer, db.ForeignKey('scheme.id'))
    vote = db.Column(db.String(32), nullable=False)
    key_secret_name = db.Column(db.String(255), nullable=False)

class Usercurrentvote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    scheme_id = db.Column(db.Integer, db.ForeignKey('scheme.id'))
    vote = db.Column(db.Boolean)

class Delegation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    delegator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    delegatee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    scheme_id = db.Column(db.Integer, db.ForeignKey('scheme.id'), nullable=False)

