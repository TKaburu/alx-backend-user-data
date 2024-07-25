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
