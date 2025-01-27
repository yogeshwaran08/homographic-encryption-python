import pickle
from backend_app.controllers.jwt import get_current_user
from backend_app.dantic.Auth import UploadContent
from backend_app.db.user import get_db
from backend_app.models.models import Uploads
from backend_app.utils.enc.skhe import SingleKeyHE
from backend_app.utils.fhe_utils import FHE
from backend_app.utils.mkhe import multi_key_encryption
from backend_app.utils.phe_utils import PartialHomomorphicEnc
from backend_app.utils.skhe import single_key_encryption
from backend_app.database import engine
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker
import time
import psutil
import os


router = APIRouter()


@router.post("/user/uploads")
def encrypt(
    content: UploadContent,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    data = content.content
    mode = content.mode
    if (mode == "phe"):
        he = PartialHomomorphicEnc()

        encrypted_data = he.encrypt(data)
        decrypted_data = he.decrypt(encrypted_data["original"])

        enc_metrics = he.enc_metrics
        dec_metrics = he.dec_metrics

        return {
            "message": "Content pros ",
            "original_content": data,
            "decrypted_content": decrypted_data,
            "encrypted_content": encrypted_data["encrypted"],
            "encryption_metrics": enc_metrics,
            "decryption_metrics": dec_metrics,
        }

    elif mode == "skhe":
        metrics = single_key_encryption(content.content)
        return metrics

    elif mode == "mkhe":
        metrics = multi_key_encryption("Hello")
        return metrics

    elif mode == "fhe":
        metrics = FHE(content.content)
        return metrics
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mode. Accepted values are: 'phe', 'skhe', 'mkhe', 'fhe'."
        )


@router.get("/user/my-files")
def get_my_files(
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    files = db.query(Uploads).filter(
        Uploads.user_id == current_user["user_id"])
    return {
        "files": [
            {
                "id": file.id,
                "type": file.type,
                "content": str(file.contents),
                "name": file.fileName
            } for file in files
        ]
    }


@router.post("/user/mode/skhe")
def encrypt_skhe(
    content: UploadContent,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    seal_encryption = SingleKeyHE()

    start_time = time.time()
    process = psutil.Process(os.getpid())
    start_memory = process.memory_info().rss

    encryption_result = seal_encryption.encrypt(content.content)

    end_time = time.time()
    end_memory = process.memory_info().rss
    content_size = len(content.content) / (1024 * 1024)

    time_taken = end_time - start_time
    memory_usage = (end_memory - start_memory) / (1024 * 1024)
    throughput = content_size / start_time

    uploaded = seal_encryption.save_to_db(
        content.filename, encryption_result, db, user_id=current_user["user_id"])

    return {
        "metrics": {
            "originalContent": content.content,
            "encryptedContent": str(uploaded.contents),
            "encryption_metrics": {
                "time_taken": time_taken,
                "memory_usage": memory_usage,
                "throughput": throughput
            }
        },
        "files": [{
            "id": uploaded.id,
            "content": str(uploaded.contents),
            "type": uploaded.type,
            "name": uploaded.fileName
        }]
    }


@router.get('/user/mode/skhe/{upload_id}')
def decrypt_skhe(
    upload_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    seal_decryption = SingleKeyHE()
    seal_decryption.setup_context()
    encryption_result, user_id = seal_decryption.load_from_db(
        db, upload_id=upload_id)
    if (user_id != current_user["user_id"]):
        raise HTTPException(
            status_code=401, detail="You are not allowed to access this resource")
    decrypted_content = seal_decryption.decrypt(encryption_result)
    return {"data": decrypted_content}
