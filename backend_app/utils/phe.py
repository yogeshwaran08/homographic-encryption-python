from phe import paillier
from backend_app.models.models import Uploads
import pickle
from sqlalchemy.orm import Session


class PartialHomomorphicEncryption:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        self.public_key, self.private_key = paillier.generate_paillier_keypair()

    def encrypt(self, input_string):
        if not self.public_key:
            self.generate_keys()

        ascii_values = [ord(char) for char in input_string]
        ciphertexts = [self.public_key.encrypt(
            value) for value in ascii_values]

        return {
            "ciphertexts": ciphertexts,
            "public_key": self.public_key,
            "private_key": self.private_key
        }

    def decrypt(self, encryption_result):
        if not self.private_key:
            raise ValueError("Private key is not available.")

        ciphertexts = encryption_result["ciphertexts"]

        decrypted_ascii_values = [self.private_key.decrypt(
            ciphertext) for ciphertext in ciphertexts]
        decrypted_string = ''.join(chr(int(value))
                                   for value in decrypted_ascii_values)

        return decrypted_string

    def save_to_db(self, filename, encryption_result, db_session: Session, user_id: int):
        encrypted_content = pickle.dumps({
            "ciphertexts": encryption_result['ciphertexts'],
            "public_key": encryption_result['public_key'],
            "private_key": encryption_result['private_key']
        })

        upload = Uploads(
            user_id=user_id,
            contents=encrypted_content,
            type="phe",
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
            print(f"Encrypted data loaded from database (ID: {upload_id})")
            return encrypted_content, upload.user_id
        else:
            print(f"No encrypted data found with ID: {upload_id}")
            return None
