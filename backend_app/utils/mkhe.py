from backend_app.models.models import Uploads
import seal
from seal import EncryptionParameters, SEALContext, KeyGenerator, IntegerEncoder, Encryptor, Decryptor, Ciphertext, Plaintext
import pickle
from sqlalchemy.orm import Session


class MultiKeyHE:
    def __init__(self):
        self.context = None
        self.keys = {}
        self.encoder = None

    def setup_context(self):
        """Set up SEAL context and initialize encryption parameters."""
        parms = EncryptionParameters()
        parms.set_poly_modulus("1x^2048 + 1")
        parms.set_coeff_modulus(seal.coeff_modulus_128(2048))
        parms.set_plain_modulus(1 << 8)

        self.context = SEALContext(parms)
        self.encoder = IntegerEncoder(self.context.plain_modulus())

    def generate_keys(self, user_id: int):
        """Generate and store public and secret keys for a specific user."""
        if not self.context:
            self.setup_context()

        keygen = KeyGenerator(self.context)
        self.keys[user_id] = {
            "public_key": keygen.public_key(),
            "secret_key": keygen.secret_key()
        }

    def encrypt(self, input_string: str, user_id: int):
        """Encrypts a string using the public key of a specific user."""
        if user_id not in self.keys:
            self.generate_keys(user_id)

        public_key = self.keys[user_id]["public_key"]
        encryptor = Encryptor(self.context, public_key)

        ascii_values = [ord(c) for c in input_string]
        ciphertexts = []

        for value in ascii_values:
            plaintext = self.encoder.encode(value)
            ciphertext = Ciphertext()
            encryptor.encrypt(plaintext, ciphertext)
            ciphertexts.append(ciphertext)

        serialized_ciphertexts = pickle.dumps(ciphertexts)

        serialized_data = {
            "ciphertexts": serialized_ciphertexts,
            "user_id": user_id,
            "context": pickle.dumps(self.context),
            "keys": self.keys
        }

        return serialized_data

    def decrypt(self, encryption_result):
        """Decrypts ciphertexts using the secret key of the user."""
        serialized_ciphertexts = encryption_result["ciphertexts"]
        user_id = encryption_result["user_id"]

        if user_id not in self.keys:
            raise ValueError(f"No keys found for user ID: {user_id}")

        secret_key = self.keys[user_id]["secret_key"]
        decryptor = Decryptor(self.context, secret_key)
        ciphertexts = pickle.loads(serialized_ciphertexts)

        decrypted_string = ""

        for ciphertext in ciphertexts:
            decrypted_plaintext = Plaintext()
            decryptor.decrypt(ciphertext, decrypted_plaintext)
            decrypted_number = self.encoder.decode_int32(decrypted_plaintext)
            decrypted_string += chr(decrypted_number)

        return decrypted_string

    def save_to_db(self, filename: str, encryption_result: dict, db_session: Session, user_id: int):
        """Saves encrypted data into the database."""
        encrypted_content = pickle.dumps({
            "ciphertexts": encryption_result['ciphertexts'],
            "user_id": user_id,
            "context": encryption_result['context'],
            "keys": encryption_result['keys']
        })

        upload = Uploads(
            user_id=user_id,
            contents=encrypted_content,
            type="mkhe",
            fileName=filename
        )

        db_session.add(upload)
        db_session.commit()
        return upload

    def load_from_db(self, db_session: Session, upload_id: int):
        upload = db_session.query(Uploads).filter(
            Uploads.id == upload_id).first()

        if upload:
            encrypted_content = pickle.loads(upload.contents)

            context = pickle.loads(encrypted_content["context"])
            keys = encrypted_content["keys"]

            self.context = context
            self.keys = keys

            encryption_result = {
                "ciphertexts": encrypted_content["ciphertexts"],
                "user_id": encrypted_content["user_id"]
            }

            print(f"Encrypted data loaded from database (ID: {upload_id})")
            return encryption_result, upload.user_id
        else:
            print(f"No encrypted data found with ID: {upload_id}")
            return None
