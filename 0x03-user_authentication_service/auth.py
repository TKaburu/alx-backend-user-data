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
