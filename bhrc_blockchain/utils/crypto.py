import hashlib

def sign_data(data, private_key=None):
    return hashlib.sha256(data.encode()).hexdigest()

def verify_signature(data, signature, public_key=None):
    expected_signature = sign_data(data)
    return signature == expected_signature

