import seal
from seal import *
import time
import sys

def string_to_integers(string):
    """Convert a string into a list of ASCII integers."""
    return [ord(char) for char in string]

def integers_to_string(integers):
    """Convert a list of ASCII integers back into a string."""
    return ''.join(chr(i) for i in integers)

def encode_string(encoder, string):
    """Encode a string into a SEAL plaintext."""
    integers = string_to_integers(string)
    encoded_list = [encoder.encode(i) for i in integers]
    return encoded_list  # A list of plaintexts

def decode_string(encoder, encoded_list):
    """Decode SEAL plaintext back into a string."""
    integers = [encoder.decode_int32(plain) for plain in encoded_list]
    return integers_to_string(integers)

def memory_usage(obj):
    """Calculate the memory usage of an object."""
    return sys.getsizeof(obj)

def FHE(data):
    parms = EncryptionParameters()
    parms.set_poly_modulus("1x^2048 + 1")
    parms.set_coeff_modulus(seal.coeff_modulus_128(2048))
    parms.set_plain_modulus(1 << 8)
    context = SEALContext(parms)
    encoder = IntegerEncoder(context.plain_modulus())
    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    
    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    string = data
    
    start_time = time.time()
    encoded_list = encode_string(encoder, string)
    encoding_time = time.time() - start_time
    print(f"Encoded '{string}' into plaintexts: {[plain.to_string() for plain in encoded_list]}")
    print(f"Encoding time: {encoding_time:.6f} seconds")

    encoding_memory = sum(memory_usage(plain) for plain in encoded_list)
    print(f"Memory usage for encoded plaintexts: {encoding_memory} bytes")

    start_time = time.time()
    encrypted_list = [Ciphertext() for _ in encoded_list]
    for i, plain in enumerate(encoded_list):
        encryptor.encrypt(plain, encrypted_list[i])
    encryption_time = time.time() - start_time
    print(f"Encryption time: {encryption_time:.6f} seconds")

    encryption_memory = sum(memory_usage(enc) for enc in encrypted_list)
    print(f"Memory usage for encrypted ciphertexts: {encryption_memory} bytes")

    start_time = time.time()
    decrypted_list = [Plaintext() for _ in encrypted_list]
    for i, enc in enumerate(encrypted_list):
        decryptor.decrypt(enc, decrypted_list[i])
    decryption_time = time.time() - start_time
    print(f"Decryption time: {decryption_time:.6f} seconds")

    decryption_memory = sum(memory_usage(plain) for plain in decrypted_list)
    print(f"Memory usage for decrypted plaintexts: {decryption_memory} bytes")

    start_time = time.time()
    decoded_string = decode_string(encoder, decrypted_list)
    decoding_time = time.time() - start_time
    print(f"Decoded string: {decoded_string}")
    print(f"Decoding time: {decoding_time:.6f} seconds")

    throughput = len(string) / (encoding_time + encryption_time + decryption_time + decoding_time)
    print(f"Throughput: {throughput:.2f} characters/second")
    enc_metrics = {
        'time_taken': encryption_time,
        'memory_usage': encryption_memory,
        'throughput': throughput
    }
    dec_metrics = {
        'time_taken': decryption_time,
        'memory_usage': decryption_memory,
        'throughput': throughput
    }
    return {
            "message": "Content prossecced",
            "original_content": data,
            "decrypted_content": decoded_string,
            "encrypted_content": [plain.to_string() for plain in encoded_list],
            "encryption_metrics": enc_metrics,
            "decryption_metrics": dec_metrics,
        }