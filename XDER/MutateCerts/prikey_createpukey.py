"""
crypto.TYPE_RSA : RSA Algorithm, OID 1.2.840.113549.1.1.1
crypto.TYPE_DSA: DSA Algorithm, OID 1.2.840.10040.4.1
crypto.TYPE_EC (for ECDSA): ECDSA Algorithm, OID 1.2.840.10045.2.1
Object Identifier (OID) for Diffie-Hellman (DH) Algorithm: 1.2.840.113549.1.3.1
Generate fixed public key from private key
"""
from OpenSSL import crypto
import binascii
from cryptography.hazmat.primitives.asymmetric import dsa, ec, dh, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os.path
import sys

def prikey_topublic(key_type, len):
    """
    Select a preset private key based on certificate public key info,
    then generate new public key using the preset private key
    Note: This function returns pub_key_hex, prikey in DERcert_util; returns prikey only in extractor_run
    @param key_type: Public key type of certificate, e.g. 1.2.840.10040.4.1=dsa
    @param len: Public key length of certificate, e.g. 2048
    @return: Hex value of new public key, path of selected preset private key
    """
    if key_type == 'rsaa':
        with open('./private_key.pem', 'rb') as f:
            private_key = f.read()

        priv_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
        public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, priv_key)
        print(len(public_key))
        pubkey = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)
        print(type(pubkey))
        der_pubkey = crypto.dump_publickey(crypto.FILETYPE_ASN1, pubkey)
        pub_key_hex = binascii.b2a_hex(der_pubkey).decode('utf-8')
        print(pub_key_hex)
        return pub_key_hex
    elif key_type == '1.2.840.10040.4.1':  # dsa
        prikey = "dsa_pri_" + str(len) + ".pem"
        try:
            with open("./MutateCerts/about_key/" + prikey, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # no password set
                    backend=default_backend()
                )
            # DSA code
            # Create private key and encode as -----BEGIN PRIVATE KEY-----
            # private_key = dsa.generate_private_key(key_size=2048)
            priv_key_hex = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            # print(priv_key_hex)

            # Generate public key from private key and encode as -----BEGIN PUBLIC KEY-----
            public_key = private_key.public_key()
            pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_key_hex = pem.decode('utf-8')
            # print(pub_key_hex)

            # Encode public key to hex string
            der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key_hex = binascii.hexlify(der)
            pub_key_hexstr = pub_key_hex.decode('ascii')
            # print(pub_key_hexstr)

            # Return
            return pub_key_hex, prikey
        except FileNotFoundError:
            if os.path.exists('./MutateCerts/about_key'):
                print("Failed to create public key")
                sys.exit()
            else:
                return prikey

    elif key_type == '1.2.840.113549.1.3.1':  # dh
        prikey = "dh_pri_" + str(len) + ".pem"
        try:
            with open("./MutateCerts/about_key/" + prikey, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # no password set
                    backend=default_backend()
                )
            # DH code
            # Create private key and encode as -----BEGIN PRIVATE KEY-----
            # parameters = dh.generate_parameters(generator=2, key_size=1024)
            # private_key = parameters.generate_private_key()
            priv_key_hex = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            # print(priv_key_hex)

            # Generate public key from private key and encode as -----BEGIN PUBLIC KEY-----
            public_key = private_key.public_key()
            pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_key_hex = pem.decode('utf-8')
            # print(pub_key_hex)

            # Encode public key to hex string
            der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key_hex = binascii.hexlify(der)
            pub_key_hexstr = pub_key_hex.decode('ascii')
            # print(pub_key_hexstr)

            return pub_key_hex, prikey
        except FileNotFoundError:
            if os.path.exists('./MutateCerts/about_key'):
                print("Failed to create public key")
                sys.exit()
            else:
                return prikey
    elif key_type == '1.2.840.10045.2.1':  # ec
        prikey = "ec_pri_" + str(len) + ".pem"
        try:
            with open("./MutateCerts/about_key/" + prikey, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # no password set
                    backend=default_backend()
                )
            # ECDSA code
            # Create private key and encode as -----BEGIN PRIVATE KEY-----
            # private_key = ec.generate_private_key(ec.SECP384R1())
            # private_key = ec.generate_private_key(ec.SECP256R1())
            priv_key_hex = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            # print(priv_key_hex)

            # Generate public key from private key and encode as -----BEGIN PUBLIC KEY-----
            public_key = private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_key_hex = pem.decode('utf-8')
            # print(pub_key_hex)

            # Encode public key to hex string
            der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key_hex = binascii.hexlify(der)
            pub_key_hexstr = pub_key_hex.decode('ascii')
            # print(pub_key_hexstr)

            # Return
            return pub_key_hex, prikey
        except FileNotFoundError:
            if os.path.exists('./MutateCerts/about_key'):
                print("Failed to create public key")
                sys.exit()
            else:
                return prikey

    elif key_type == '1.2.840.113549.1.1.1':  # rsa
        prikey = "rsa_pri_" + str(len) + ".pem"
        try:
            # Read private key (not create)
            with open("./MutateCerts/about_key/" + prikey, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # no password set
                    backend=default_backend()
                )
            # RSA code
            # Create private key and encode as -----BEGIN PRIVATE KEY-----
            # private_key = rsa.generate_private_key(
            #     public_exponent=65537,
            #     key_size=2048
            # )
            priv_key_hex = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            # print(priv_key_hex)

            # Generate public key from private key and encode as -----BEGIN PUBLIC KEY-----
            public_key = private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key_hex = pem.decode('utf-8')
            # print(pub_key_hex)

            # Encode public key to hex string
            der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key_hex = binascii.hexlify(der)
            pub_key_hexstr = pub_key_hex.decode('ascii')
            # print(pub_key_hexstr)

            # Return
            return pub_key_hex, prikey
        except FileNotFoundError:
            if os.path.exists('./MutateCerts/about_key'):
                print("Failed to create public key")
                sys.exit()
            else:
                return prikey

# Used by CC below
def prikey_topublic_cc(key_type, prikey):
    if key_type == 'rsaa':
        with open('./private_key.pem', 'rb') as f:
            private_key = f.read()

        priv_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
        public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, priv_key)
        print(len(public_key))
        pubkey = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)
        print(type(pubkey))
        der_pubkey = crypto.dump_publickey(crypto.FILETYPE_ASN1, pubkey)
        pub_key_hex = binascii.b2a_hex(der_pubkey).decode('utf-8')
        print(pub_key_hex)
        return pub_key_hex
    elif key_type == '1.2.840.10040.4.1':  # dsa
        try:
            with open(prikey, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # no password set
                    backend=default_backend()
                )
            # DSA code
            # Create private key and encode as -----BEGIN PRIVATE KEY-----
            # private_key = dsa.generate_private_key(key_size=2048)
            priv_key_hex = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            # print(priv_key_hex)

            # Generate public key from private key and encode as -----BEGIN PUBLIC KEY-----
            public_key = private_key.public_key()
            pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_key_hex = pem.decode('utf-8')
            # print(pub_key_hex)

            # Encode public key to hex string
            der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key_hex = binascii.hexlify(der)
            pub_key_hexstr = pub_key_hex.decode('ascii')
            # print(pub_key_hexstr)

            # Return
            return pub_key_hex
        except FileNotFoundError:
            if os.path.exists('./MutateCerts/about_key'):
                print("Failed to create public key")
                sys.exit()
            else:
                return prikey

    elif key_type == '1.2.840.113549.1.3.1':  # dh
        try:
            with open(prikey, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # no password set
                    backend=default_backend()
                )
            # DH code
            # Create private key and encode as -----BEGIN PRIVATE KEY-----
            # parameters = dh.generate_parameters(generator=2, key_size=1024)
            # private_key = parameters.generate_private_key()
            priv_key_hex = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            # print(priv_key_hex)

            # Generate public key from private key and encode as -----BEGIN PUBLIC KEY-----
            public_key = private_key.public_key()
            pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_key_hex = pem.decode('utf-8')
            # print(pub_key_hex)

            # Encode public key to hex string
            der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key_hex = binascii.hexlify(der)
            pub_key_hexstr = pub_key_hex.decode('ascii')
            # print(pub_key_hexstr)

            return pub_key_hex
        except FileNotFoundError:
            if os.path.exists('./MutateCerts/about_key'):
                print("Failed to create public key")
                sys.exit()
            else:
                return prikey
    elif key_type == '1.2.840.10045.2.1':  # ec
        try:
            with open(prikey, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # no password set
                    backend=default_backend()
                )
            # ECDSA code
            # Create private key and encode as -----BEGIN PRIVATE KEY-----
            # private_key = ec.generate_private_key(ec.SECP384R1())
            # private_key = ec.generate_private_key(ec.SECP256R1())
            priv_key_hex = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            # print(priv_key_hex)

            # Generate public key from private key and encode as -----BEGIN PUBLIC KEY-----
            public_key = private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_key_hex = pem.decode('utf-8')
            # print(pub_key_hex)

            # Encode public key to hex string
            der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key_hex = binascii.hexlify(der)
            pub_key_hexstr = pub_key_hex.decode('ascii')
            # print(pub_key_hexstr)

            # Return
            return pub_key_hex
        except FileNotFoundError:
            if os.path.exists('./MutateCerts/about_key'):
                print("Failed to create public key")
                sys.exit()
            else:
                return prikey

    elif key_type == '1.2.840.113549.1.1.1':  # rsa
        try:
            # Read private key (not create)
            with open(prikey, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # no password set
                    backend=default_backend()
                )
            # RSA code
            # Create private key and encode as -----BEGIN PRIVATE KEY-----
            # private_key = rsa.generate_private_key(
            #     public_exponent=65537,
            #     key_size=2048
            # )
            priv_key_hex = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            # print(priv_key_hex)

            # Generate public key from private key and encode as -----BEGIN PUBLIC KEY-----
            public_key = private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key_hex = pem.decode('utf-8')
            # print(pub_key_hex)

            # Encode public key to hex string
            der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key_hex = binascii.hexlify(der)
            pub_key_hexstr = pub_key_hex.decode('ascii')
            # print(pub_key_hexstr)

            # Return
            return pub_key_hex
        except FileNotFoundError:
            if os.path.exists('./MutateCerts/about_key'):
                print("Failed to create public key")
                sys.exit()
            else:
                return prikey