import time
import psutil
import os
from phe import paillier

class PartialHomomorphicEnc:
    def __init__(self):
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
        self.enc_metrics = {}  
        self.dec_metrics = {}  
        
    def encrypt(self, data):
        """Encrypt the data using the Paillier public key"""
        start_time = time.time()
        data_int = [ord(c) for c in data]
        encrypted_data = [self.public_key.encrypt(d) for d in data_int]
        
        # Convert encrypted data to a string representation
        encrypted_data_str = [str(e.ciphertext()) for e in encrypted_data]
        
        elapsed_time = time.time() - start_time
        memory_usage = psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)  # MB
        throughput = len(data) / elapsed_time if elapsed_time > 0 else 0
        self.enc_metrics = {
            'time_taken': elapsed_time,
            'memory_usage': memory_usage,
            'throughput': throughput
        }
        
        return {
            'original': encrypted_data,
            'encrypted': encrypted_data_str
        }

    def decrypt(self, encrypted_data):
        """Decrypt the data using the Paillier private key"""
        start_time = time.time()
        
        decrypted_data = ''.join([chr(self.private_key.decrypt(e)) for e in encrypted_data])
        
        elapsed_time = time.time() - start_time
        memory_usage = psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)  # MB
        
        throughput = len(encrypted_data) / elapsed_time if elapsed_time > 0 else 0
        
        self.dec_metrics = {
            'time_taken': elapsed_time,
            'memory_usage': memory_usage,
            'throughput': throughput
        }
        
        return decrypted_data
