from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  
from backend_app.routes import auth_routes
from backend_app.database import Base, engine
import seal

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)

app.include_router(auth_routes.router)
