from backend_app.db.user import get_db
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend_app.controllers.auth_controller import create_user, get_user, verify_password
from backend_app.dantic.Auth import UserCreate, UserLogin
from backend_app.controllers.jwt import create_access_token, get_current_user
from backend_app.models.models import User

router = APIRouter()


@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = get_user(db, user.username)
    if existing_user:
        raise HTTPException(
            status_code=400, detail="Username already registered")

    new_user = create_user(db=db, username=user.username,
                           password=user.password)

    access_token = create_access_token(
        data={"sub": new_user.username, "user_id": new_user.id})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "id": new_user.id,
        "username": new_user.username
    }


@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    user_data = get_user(db, user.username)
    if not user_data or not verify_password(user.password, user_data.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(
        data={"sub": user_data.username, "user_id": user_data.id})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "id": user_data.id,
        "username": user_data.username
    }


@router.get("/about-me")
def get_user_data(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username ==
                                 current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.id, "username": user.username}
