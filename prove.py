import hashlib
import zipfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization


def calculate_checksum(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    return private_key, public_key


def sign_file(private_key, file_path):
    with open(file_path, "rb") as file:
        file_data = file.read()

    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def save_keys(private_key, public_key):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as file:
        file.write(pem_private_key)

    with open("public_key.pem", "wb") as file:
        file.write(pem_public_key)


def create_zip(file_path, checksum):
    with zipfile.ZipFile("output.zip", "w") as zip_file:
        zip_file.write(file_path)
        zip_file.write("public_key.pem")
        zip_file.write("checksum.txt")


# Accept user input for the file path
file_path = input("Enter the file path: ")

# Calculate checksum
checksum = calculate_checksum(file_path)

# Generate key pair
private_key, public_key = generate_key_pair()

# Sign the file
signature = sign_file(private_key, file_path)

# Save private and public keys
save_keys(private_key, public_key)

# Save checksum to a file
with open("checksum.txt", "w") as file:
    file.write(checksum)

# Create a zip file with the public key, checksum, and the file
create_zip(file_path, checksum)

print("Private key saved as private_key.pem")
print("Public key saved as public_key.pem")
print("Checksum saved as checksum.txt")
print("Output zip file created as output.zip")
