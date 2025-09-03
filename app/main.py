from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, scan, socket, contact  
app = FastAPI(
    title="Nmap Scanner Server",
    description="API for scanning domains and managing users",
    version="1.0.0"
)

origins = ["*"]  

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scan.router)
# app.include_router(socket.router)
# app.include_router(contact.router)

@app.get("/")
def root():
    return {"message": "Welcome to the Nmap Scanner API"}
