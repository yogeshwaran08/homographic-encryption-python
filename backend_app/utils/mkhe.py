import time
import sys
import seal
import pickle
from seal import EncryptionParameters, SEALContext, KeyGenerator, IntegerEncoder, Encryptor, Decryptor, Evaluator, Ciphertext, Plaintext, PublicKey, SecretKey

def multi_key_encryption(input_string):
    start_encrypt_time = time.time()

    parms = EncryptionParameters()
    parms.set_poly_modulus("1x^2048 + 1")
    parms.set_coeff_modulus(seal.coeff_modulus_128(2048))
    parms.set_plain_modulus(1 << 8)  # Plaintext modulus

    context = SEALContext(parms)
    keygen = KeyGenerator(context)
    
    # Generate two key pairs (public and secret) for multi-key encryption
    public_key_1 = keygen.public_key()
    secret_key_1 = keygen.secret_key()
    keygen_2 = KeyGenerator(context)
    public_key_2 = keygen_2.public_key()
    secret_key_2 = keygen_2.secret_key()

    # Create encryptors and decryptors
    encryptor_1 = Encryptor(context, public_key_1)
    encryptor_2 = Encryptor(context, public_key_2)
    decryptor_1 = Decryptor(context, secret_key_1)
    decryptor_2 = Decryptor(context, secret_key_2)

    evaluator = Evaluator(context)
    encoder = IntegerEncoder(context.plain_modulus())

    # Convert input string to ASCII values
    ascii_values = [ord(c) for c in input_string]
    print("ASCII Values:", ascii_values)

    # Encrypt the ASCII values with different public keys
    ciphertexts_1 = []
    ciphertexts_2 = []

    for value in ascii_values:
        plaintext = encoder.encode(value)
        
        # Encrypt using the first public key
        ciphertext_1 = Ciphertext()
        encryptor_1.encrypt(plaintext, ciphertext_1)
        ciphertexts_1.append(ciphertext_1)

        # Encrypt using the second public key
        ciphertext_2 = Ciphertext()
        encryptor_2.encrypt(plaintext, ciphertext_2)
        ciphertexts_2.append(ciphertext_2)

    encryption_memory = sum(sys.getsizeof(c) for c in ciphertexts_1 + ciphertexts_2)
    
    end_encrypt_time = time.time()
    encryption_time = end_encrypt_time - start_encrypt_time

    print("Encrypted ciphertexts (Key 1):", ciphertexts_1)
    print("Encrypted ciphertexts (Key 2):", ciphertexts_2)

    start_decrypt_time = time.time()

    decrypted_string = ""

    # Decrypt ciphertexts using the corresponding secret keys
    for c1, c2 in zip(ciphertexts_1, ciphertexts_2):
        decrypted_plaintext_1 = Plaintext()
        decrypted_plaintext_2 = Plaintext()

        decryptor_1.decrypt(c1, decrypted_plaintext_1)
        decryptor_2.decrypt(c2, decrypted_plaintext_2)

        # Decode the decrypted values
        decrypted_number_1 = encoder.decode_int32(decrypted_plaintext_1)
        decrypted_number_2 = encoder.decode_int32(decrypted_plaintext_2)

        # Convert the numbers back to characters and build the decrypted string
        decrypted_string += chr(decrypted_number_1) + chr(decrypted_number_2)

    decryption_memory = sum(sys.getsizeof(p) for p in decrypted_string)

    end_decrypt_time = time.time()
    decryption_time = end_decrypt_time - start_decrypt_time

    print("Decrypted string:", decrypted_string)

    throughput_encrypt = (len(input_string) * 8) / encryption_time if encryption_time > 0 else 0
    throughput_decrypt = (len(input_string) * 8) / decryption_time if decryption_time > 0 else 0

    enc_metrics = {
        'time_taken': encryption_time,
        'memory_usage': encryption_memory,
        'throughput': throughput_encrypt
    }
    
    dec_metrics = {
        'time_taken': decryption_time,
        'memory_usage': decryption_memory,
        'throughput': throughput_decrypt
    }

    # Serialize ciphertexts for transport
    serialized_ciphertexts_1 = pickle.dumps(ciphertexts_1)
    serialized_ciphertexts_2 = pickle.dumps(ciphertexts_2)

    return {
        "message": "Content processed",
        "original_content": input_string,
        "decrypted_content": decrypted_string,
        "encrypted_content": [str(serialized_ciphertexts_1), str(serialized_ciphertexts_2)],  
        "encryption_metrics": enc_metrics,
        "decryption_metrics": dec_metrics,
    }
