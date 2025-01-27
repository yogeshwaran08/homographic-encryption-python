from backend_app.models.models import Uploads
import seal
from seal import EncryptionParameters, SEALContext, KeyGenerator, IntegerEncoder, Encryptor, Decryptor, Ciphertext, Plaintext
import pickle
from sqlalchemy.orm import Session


class FullHomomorphicEncryption:
    def __init__(self):
        self.context = None
        self.public_key = None
        self.secret_key = None
        self.encoder = None

    def setup_context(self):
        """Setup the SEAL context and generate keys."""
        parms = EncryptionParameters()
        parms.set_poly_modulus("1x^2048 + 1")
        parms.set_coeff_modulus(seal.coeff_modulus_128(2048))
        parms.set_plain_modulus(1 << 8)

        self.context = SEALContext(parms)
        keygen = KeyGenerator(self.context)
        self.public_key = keygen.public_key()
        self.secret_key = keygen.secret_key()
        self.encoder = IntegerEncoder(self.context.plain_modulus())

    def encrypt(self, input_string):
        """Encrypts a string using SEAL."""
        if not self.context or not self.public_key or not self.encoder:
            self.setup_context()

        encryptor = Encryptor(self.context, self.public_key)
        ascii_values = [ord(c) for c in input_string]
        ciphertexts = []

        for value in ascii_values:
            plaintext = self.encoder.encode(value)
            ciphertext = Ciphertext()
            encryptor.encrypt(plaintext, ciphertext)
            ciphertexts.append(ciphertext)

        serialized_ciphertexts = pickle.dumps(ciphertexts)
        serialized_secret_key = pickle.dumps(self.secret_key)

        return {
            "ciphertexts": serialized_ciphertexts,
            "secret_key": serialized_secret_key,
            "context": self.context
        }

    def decrypt(self, encryption_result):
        """Decrypts ciphertexts back into a string."""
        serialized_ciphertexts = encryption_result["ciphertexts"]
        secret_key = pickle.loads(encryption_result["secret_key"])
        context = encryption_result["context"]

        ciphertexts = pickle.loads(serialized_ciphertexts)
        decryptor = Decryptor(context, secret_key)
        decrypted_string = ""

        for ciphertext in ciphertexts:
            decrypted_plaintext = Plaintext()
            decryptor.decrypt(ciphertext, decrypted_plaintext)
            decrypted_number = self.encoder.decode_int32(decrypted_plaintext)
            decrypted_string += chr(decrypted_number)

        return decrypted_string

    def save_to_db(self, filename, encryption_result, db_session: Session, user_id: int):
        """Saves the encryption result to the database."""
        encrypted_content = pickle.dumps({
            "ciphertexts": encryption_result['ciphertexts'],
            "secret_key": encryption_result['secret_key'],
            "context": encryption_result['context']
        })

        upload = Uploads(
            user_id=user_id,
            contents=encrypted_content,
            type="fhe",
            fileName=filename
        )

        db_session.add(upload)
        db_session.commit()
        return upload

    def load_from_db(self, db_session: Session, upload_id: int):
        """Loads encrypted data from the database."""
        upload = db_session.query(Uploads).filter(
            Uploads.id == upload_id).first()

        if upload:
            encrypted_content = pickle.loads(upload.contents)
            encryption_result = {
                "ciphertexts": encrypted_content["ciphertexts"],
                "secret_key": encrypted_content["secret_key"],
                "context": encrypted_content["context"]
            }
            print(f"Encrypted data loaded from database (ID: {upload_id})")
            return encryption_result, upload.user_id
        else:
            print(f"No encrypted data found with ID: {upload_id}")
            return None
