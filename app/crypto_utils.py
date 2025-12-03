from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(key_size: int = 4096):
    """
    Generate RSA key pair
    
    Returns:
        Tuple of (private_key, public_key) objects

    Implementation:
    - Generates a 4096-bit RSA key
    - Uses public exponent 65537
    - Serializes to PEM format
    - Saves student_private.pem and student_public.pem
    """
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # Serialize private key (PEM)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key (PEM)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save to files
    with open("student_private.pem", "wb") as f:
        f.write(private_pem)

    with open("student_public.pem", "wb") as f:
        f.write(public_pem)

    return private_key, private_key.public_key()
