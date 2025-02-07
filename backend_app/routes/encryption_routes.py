import pickle
from backend_app.controllers.jwt import get_current_user
from backend_app.dantic.Auth import UploadContent
from backend_app.db.user import get_db
from backend_app.models.models import Uploads
from backend_app.utils.fhe import FullHomomorphicEncryption
from backend_app.utils.mkhe import MultiKeyHE
from backend_app.utils.phe import PartialHomomorphicEncryption
from backend_app.utils.skhe import SingleKeyHE
from backend_app.database import engine
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker
import time
import psutil
import os
import tracemalloc



router = APIRouter()


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
    # process = psutil.Process(os.getpid())
    # start_memory = process.memory_info().rss
    tracemalloc.start()

    encryption_result = seal_encryption.encrypt(content.content)

    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    content_size = len(content.content) / (1024 * 1024)

    time_taken = end_time - start_time
    memory_usage = peak / (1024 * 1024) 
    # memory_usage = (end_memory - start_memory) / (1024 * 1024)
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


@router.post("/user/mode/phe")
def encrypt_phe(
    content: UploadContent,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    seal_encryption = PartialHomomorphicEncryption()

    # Start memory tracking
    tracemalloc.start()
    start_time = time.time()

    encryption_result = seal_encryption.encrypt(content.content)

    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    content_size = len(content.content) / (1024 * 1024)
    time_taken = end_time - start_time
    memory_usage = peak / (1024 * 1024) 
    throughput = content_size / time_taken if time_taken > 0 else 0

    uploaded = seal_encryption.save_to_db(
        content.filename, encryption_result, db, user_id=current_user["user_id"]
    )

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


@router.get("/user/mode/phe/{upload_id}")
def decrypt_phe(
    upload_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    seal_decryption = PartialHomomorphicEncryption()
    encryption_result, user_id = seal_decryption.load_from_db(
        db, upload_id=upload_id)
    if (user_id != current_user["user_id"]):
        raise HTTPException(
            status_code=401, detail="You are not allowed to access this resource")
    print(encryption_result.keys())
    seal_decryption.private_key = encryption_result["private_key"]
    decrypted_content = seal_decryption.decrypt(encryption_result)
    return {"data": decrypted_content}


@router.post("/user/mode/fhe")
def encrypt_fhe(
    content: UploadContent,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    seal_encryption = FullHomomorphicEncryption()

    start_time = time.time()
    tracemalloc.start()


    encryption_result = seal_encryption.encrypt(content.content)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    end_time = time.time()
    content_size = len(content.content) / (1024 * 1024)
    memory_usage = peak / (1024 * 1024) 

    time_taken = end_time - start_time
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


@router.get("/user/mode/fhe/{upload_id}")
def decrypt_fhe(
    upload_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    seal_decryption = FullHomomorphicEncryption()
    encryption_result, user_id = seal_decryption.load_from_db(
        db, upload_id=upload_id)
    if (user_id != current_user["user_id"]):
        raise HTTPException(
            status_code=401, detail="You are not allowed to access this resource")
    seal_decryption.setup_context()
    decrypted_content = seal_decryption.decrypt(encryption_result)
    return {"data": decrypted_content}


@router.post("/user/mode/mkhe")
def encrypt_mkhe(
    content: UploadContent,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    seal_encryption = MultiKeyHE()

    start_time = time.time()
    tracemalloc.start()
    

    encryption_result = seal_encryption.encrypt(
        content.content, current_user["user_id"])
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    end_time = time.time()
    content_size = len(content.content) / (1024 * 1024)

    time_taken = end_time - start_time
    throughput = content_size / start_time
    memory_usage = peak / (1024 * 1024) 

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


@router.get("/user/mode/mkhe/{upload_id}")
def decrypt_fhe(
    upload_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    seal_decryption = MultiKeyHE()
    encryption_result, user_id = seal_decryption.load_from_db(
        db, upload_id=upload_id)
    if (user_id != current_user["user_id"]):
        raise HTTPException(
            status_code=401, detail="You are not allowed to access this resource")
    seal_decryption.setup_context()
    decrypted_content = seal_decryption.decrypt(encryption_result)
    return {"data": decrypted_content}
