import base64
import hmac
import json
import os
from binascii import unhexlify
from multiprocessing.context import AuthenticationError
from Crypto import Random
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad, unpad
from backports.pbkdf2 import pbkdf2_hmac

# Taking file path along with filename as user input
filename = input("Please enter file path:")
# Replacing backslash to forward slash
newPath = filename.replace(os.sep, '/')

# Number of Iterations for KDF
itr = int(100000)


def initial_steps():
    """
    This method will help to provide password and hash algorithm as user input
    :return: password, HASH_ALGO
    """
    # Taking password as user input
    password = input("Please enter password: ")
    # password = password.encode("utf8")

    # Taking hash algorithm as user input
    HASH_ALGO = input("Select any one hash algorithms:" '\n1. sha256\n2. sha512\n\n')
    if HASH_ALGO == '1':
        HASH_ALGO = 'sha256'
    elif HASH_ALGO == '2':
        HASH_ALGO = 'sha512'

    return password, HASH_ALGO


def gen_master_key(password, HASH_ALGO):
    """
    This method will generate master key using pbkdf2_hmac library
    :return: master key
    """
    master_key = (pbkdf2_hmac(HASH_ALGO, password.encode("utf8"), unhexlify(os.urandom(32).hex()), iterations=itr)).hex()
    return master_key


def gen_encryption_key(HASH_ALGO):
    """
    This method will generate encryption key using pbkdf2_hmac library, derived master key and fixed salt value
    :return:encryption key
    """
    encryption_key = (pbkdf2_hmac(HASH_ALGO, Km.encode("utf8"), 'Encryption Key'.encode("utf8"), iterations=1)).hex()
    return encryption_key


def gen_hmac_key(HASH_ALGO):
    """
    This method will generate hmac key using pbkdf2_hmac library, derived master key and fixed salt value
    :return:hmac key
    """
    hmac_key = (pbkdf2_hmac(HASH_ALGO, Km.encode("utf8"), 'HMAC Key'.encode("utf8"), iterations=1)).hex()
    return hmac_key


def gen_initialization_vector():
    """
    This method will generate Initialization vector
    :return:Initialization vector
    """
    iv = Random.get_random_bytes(16)
    return iv


def compare_hmac(hmac, hmac_verif):
    """
    This method will compare the HMAC prior to decrypting the file
    :param hmac:
    :param hmac_verif:
    :return: result
    """
    if len(hmac) != len(hmac_verif):
        print("HMAC size is invalid")
        return False

    result = 0
    for x, y in zip(hmac, hmac_verif):
        result |= ord(x) ^ ord(y)
    return result == 0


def select_encrypt_algo():
    """
    This method will help user to select the encryption algorithm
    :return: ENCRYPTION_ALGO
    """
    # Taking encryption algorithm as user input
    ENCRYPTION_ALGO = input("Select any one encryption algorithms:" '\n1. 3des\n2. aes-128\n3. aes-256\n\n')
    if ENCRYPTION_ALGO == '1':
        ENCRYPTION_ALGO = 'triple_des'
        triple_des_encrypt_hmac_decrypt(HASH_ALGO, ENCRYPTION_ALGO)
    elif ENCRYPTION_ALGO == '2':
        ENCRYPTION_ALGO = 'aes_128'
        aes128_encrypt_hmac_decrypt(HASH_ALGO, ENCRYPTION_ALGO)
    else:
        ENCRYPTION_ALGO = 'aes_256'
        aes256_encrypt_hmac_decrypt(HASH_ALGO, ENCRYPTION_ALGO)

    return ENCRYPTION_ALGO

def triple_des_encrypt_hmac_decrypt(HASH_ALGO, ENCRYPTION_ALGO):
    """
    This method will encrypt, validate hmac and decrypt file using 3des algorithm
    :param HASH_ALGO:
    :param ENCRYPTION_ALGO:
    :return: decrypted 3des file
    """
    with open(newPath, "rb") as f:
        file = f.read()
    # Encrypting data in file using 3des
    triple_des_cipher = DES3.new(Ke[:16].encode("utf-8"), mode=DES3.MODE_CBC, IV=IV[:8])
    triple_des_encrypted = (triple_des_cipher.encrypt(pad(file, DES3.block_size)))
    iv_data = IV[:8] + triple_des_encrypted
    hmac_3des = hmac.new(bytes.fromhex(Kh), iv_data, digestmod=HASH_ALGO).hexdigest()

    metadata = {
        'encryption_algorithm': ENCRYPTION_ALGO,
        'hashing_algorithm': HASH_ALGO,
        'Iterations for KDF': itr,
        'master_key': Km,
        'encryption_key': Ke[:16],
        'hmac_key': Kh,
        'iv': IV[:8].hex(),
        'hmac_sign_3des': hmac_3des,
        'triple_des_encrypted': triple_des_encrypted.hex()
    }
    # writing encrypted data, key and other factors in json format to compare the hmac signature
    with open('encrypted_3des.txt.enc', 'w') as encrypted_file:
        json.dump(metadata, encrypted_file, indent=9)

    f = open('encrypted_3des.txt.enc', "r")
    data = json.loads(f.read())

    # Calculating HMAC to compare with previously generated hmac of encrypted data and IV
    iv_data = bytes.fromhex(data['iv']) + bytes.fromhex(data['triple_des_encrypted'])
    if not compare_hmac(hmac.new(bytes.fromhex(Kh), iv_data, digestmod=HASH_ALGO).hexdigest(),
                        data['hmac_sign_3des']):
        raise AuthenticationError("message authentication failed")
    else:
        print(
            "\n--------HMAC signature has been validated for 3des and now decrypting file using 3des--------")

    enc = bytes.fromhex(data['triple_des_encrypted'])
    # Decrypting data in file using 3des
    triple_des_cipher = DES3.new(data['encryption_key'], mode=DES3.MODE_CBC, IV=bytes.fromhex(data['iv']))
    triple_des_decrypted = unpad(triple_des_cipher.decrypt(enc), DES3.block_size)
    print("3DES decrypt:", triple_des_decrypted.decode('utf-8'))
    return triple_des_decrypted


def aes128_encrypt_hmac_decrypt(HASH_ALGO, ENCRYPTION_ALGO):
    """
    This method will encrypt, validate hmac and decrypt file using aes-128 algorithm
    :param HASH_ALGO:
    :param ENCRYPTION_ALGO:
    :return: decrypted aes-128 file
    """
    with open(newPath, "rb") as f:
        file = f.read()
    # Encrypting file data using aes-128
    cipher = AES.new(Ke[:16].encode("utf-8"), AES.MODE_CBC, IV)
    aes128_encrypted = base64.b64encode(cipher.encrypt(pad(file, AES.block_size)))
    iv_data = IV[:16] + aes128_encrypted
    hmac_aes128 = hmac.new(bytes.fromhex(Kh), iv_data, digestmod=HASH_ALGO).hexdigest()
    metadata = {
        'encryption_algorithm': ENCRYPTION_ALGO,
        'hashing_algorithm': HASH_ALGO,
        'Iterations for KDF': itr,
        'master_key': Km,
        'encryption_key': Ke[:16],
        'hmac_key': Kh,
        'iv': IV.hex(),
        'hmac_sign_aes128': hmac_aes128,
        'aes128_encrypted': aes128_encrypted.hex()
    }
    # writing encrypted data, key and other factors in json format to compare the hmac signature
    with open('encrypted_aes128.txt.enc', 'w') as encrypted_file:
        json.dump(metadata, encrypted_file, indent=9)

    f = open('encrypted_aes128.txt.enc', "r")
    data = json.loads(f.read())

    iv_data = bytes.fromhex(data['iv']) + bytes.fromhex(data['aes128_encrypted'])
    if not compare_hmac(hmac.new(bytes.fromhex(Kh), iv_data, digestmod=HASH_ALGO).hexdigest(),
                        data['hmac_sign_aes128']):
        raise AuthenticationError("message authentication failed")
    else:
        print(
            "\n--------HMAC signature has been validated for aes128 and now decrypting file using aes128--------")

    enc = bytes.fromhex(data['aes128_encrypted'])
    # Decrypting file data using aes-128
    enc = base64.b64decode(enc)
    cipher = AES.new(data['encryption_key'].encode('utf-8'), AES.MODE_CBC, bytes.fromhex(data['iv']))
    aes128_decrypted = unpad(cipher.decrypt(enc), AES.block_size)
    print('AES 128 decrypt:', aes128_decrypted.decode('utf-8'))
    return aes128_decrypted


def aes256_encrypt_hmac_decrypt(HASH_ALGO, ENCRYPTION_ALGO):
    """
    This method will encrypt, validate hmac and decrypt file using aes-256 algorithm
    :param HASH_ALGO:
    :param ENCRYPTION_ALGO:
    :return: decrypted aes-256 file
    """
    with open(newPath, "rb") as f:
        file = f.read()
    # Encrypting file data using aes-256
    raw = pad(file, AES.block_size)
    cipher = AES.new(Ke[:32].encode("utf8"), AES.MODE_CBC, IV)
    aes256_encrypted = base64.b64encode(IV + cipher.encrypt(raw))
    iv_data = IV[:32] + aes256_encrypted
    hmac_aes256 = hmac.new(bytes.fromhex(Kh), iv_data, digestmod=HASH_ALGO).hexdigest()
    metadata = {
        'encryption_algorithm': ENCRYPTION_ALGO,
        'hashing_algorithm': HASH_ALGO,
        'Iterations for KDF': itr,
        'master_key': Km,
        'encryption_key': Ke[:32],
        'hmac_key': Kh,
        'iv': IV.hex(),
        'hmac_sign_aes256': hmac_aes256,
        'aes256_encrypted': aes256_encrypted.hex()
    }
    # writing encrypted data, key and other factors in json format to compare the hmac signature
    with open('encrypted_aes256.txt.enc', 'w') as encrypted_file:
        json.dump(metadata, encrypted_file, indent=9)

    f = open('encrypted_aes256.txt.enc', "r")
    data = json.loads(f.read())

    iv_data = bytes.fromhex(data['iv']) + bytes.fromhex(data['aes256_encrypted'])
    if not compare_hmac(hmac.new(bytes.fromhex(Kh), iv_data, digestmod=HASH_ALGO).hexdigest(),
                        data['hmac_sign_aes256']):
        raise AuthenticationError("message authentication failed")
    else:
        print(
            "\n--------HMAC signature has been validated for aes256 and now decrypting file using aes256--------")

    enc = bytes.fromhex(data['aes256_encrypted'])
    # Decrypting file data using aes-256
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(data['encryption_key'].encode('utf-8'), AES.MODE_CBC, iv)
    aes256_decrypted = unpad(cipher.decrypt(enc[16:]), AES.block_size)
    print("AES 256 decrypt:", aes256_decrypted.decode('utf-8'))
    return aes256_decrypted


if __name__ == '__main__':
    password, HASH_ALGO = initial_steps()
    Km = gen_master_key(password, HASH_ALGO)
    Ke = gen_encryption_key(HASH_ALGO)
    Kh = gen_hmac_key(HASH_ALGO)
    IV = gen_initialization_vector()
    ENCRYPTION_ALGO = select_encrypt_algo()
