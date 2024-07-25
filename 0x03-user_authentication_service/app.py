#!/usr/bin/env python3

"""
Basic Flask app
"""

from flask import Flask, jsonify, request
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def msg():
    """
    This method returns a json response
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users():
    """
    This function registers users
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if email or password:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"})

    else:
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
