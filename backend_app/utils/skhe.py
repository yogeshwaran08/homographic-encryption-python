import time
import sys
import seal
import pickle 
from seal import EncryptionParameters, SEALContext, KeyGenerator, IntegerEncoder, Encryptor, Decryptor, Evaluator, Ciphertext, Plaintext

def single_key_encryption(input_string):
    start_encrypt_time = time.time()
    
    parms = EncryptionParameters()
    parms.set_poly_modulus("1x^2048 + 1")
    parms.set_coeff_modulus(seal.coeff_modulus_128(2048))
    parms.set_plain_modulus(1 << 8) 

    context = SEALContext(parms)
    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()

    encryptor = Encryptor(context, public_key)
    decryptor = Decryptor(context, secret_key)
    evaluator = Evaluator(context)

    encoder = IntegerEncoder(context.plain_modulus())

    ascii_values = [ord(c) for c in input_string]
    print("ASCII Values:", ascii_values)

    ciphertexts = []  

    for value in ascii_values:
        plaintext = encoder.encode(value)
        ciphertext = Ciphertext()
        encryptor.encrypt(plaintext, ciphertext)
        ciphertexts.append(ciphertext)

    encryption_memory = sum(sys.getsizeof(c) for c in ciphertexts)
    
    end_encrypt_time = time.time()
    encryption_time = end_encrypt_time - start_encrypt_time

    print("Encrypted ciphertexts:", ciphertexts)

    start_decrypt_time = time.time()

    decrypted_string = ""  
    for ciphertext in ciphertexts:
        decrypted_plaintext = Plaintext()
        decryptor.decrypt(ciphertext, decrypted_plaintext)
        decrypted_number = encoder.decode_int32(decrypted_plaintext)
        decrypted_string += chr(decrypted_number)

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

    serialized_ciphertexts = pickle.dumps(ciphertexts)

    return {
        "message": "Content processed",
        "original_content": input_string,
        "decrypted_content": decrypted_string,
        "encrypted_content": [str(serialized_ciphertexts)],  
        "encryption_metrics": enc_metrics,
        "decryption_metrics": dec_metrics,
    }