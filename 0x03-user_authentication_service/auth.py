#!/usr/bin/env python3

"""
 Hash password
"""
import uuid
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """
    This function hashes a password
    """
    salted_hash = bcrypt.gensalt()
    psswd_bytes = password.encode('utf-8')
    hash_psswrd = bcrypt.hashpw(psswd_bytes, salted_hash)
    return hash_psswrd


def _generate_uuid() -> str:
    """
    This method generates a new UUID from uuid module
    Return:
        string uuid
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """
        Initialize database
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        This function registers anew user with their email and password
        """
        # first check if user exist
        try:
            new_user = self._db.find_user_by(email=email)
            if new_user:
                raise ValueError(f"User {email} already exists")
            # user exist so hash password and create user
        except KeyError:
            hashed_psswd = self._hash_password(password)
            new_user = self._db.add_user(email, hashed_psswd)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """
        This function checks if credentials are valid
        Args:
            email: The users email
            passwrd: The users password
        Return:
            A Boolean
        """
        try:
            user = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
                return True
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
        This functin creates a session ID as a string
        Args:
            email: The email of the user
        Returns:
            session ID: string
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, email=email, session_id=session_id)
        return session_id
