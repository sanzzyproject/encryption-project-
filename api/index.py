from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import base64
import os

# Library Kriptografi
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

app = FastAPI(title="CipherLab API", docs_url=None, redoc_url=None)

# --- MODELS ---
class CryptoRequest(BaseModel):
    method: str
    text: str
    password: Optional[str] = None
    action: str  # 'encrypt' atau 'decrypt'

# --- HELPER FUNCTIONS ---

def get_aes_key_iv(password: str):
    # Derivasi key 32 byte (AES-256) dan IV 16 byte dari password
    salt = b'cipherlab_static_salt' # In prod, use random salt & store it
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32 + 16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived = kdf.derive(password.encode())
    return derived[:32], derived[32:]

def aes_encrypt(text: str, password: str) -> str:
    key, iv = get_aes_key_iv(password)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ct).decode()

def aes_decrypt(text: str, password: str) -> str:
    try:
        data = base64.b64decode(text)
        key, iv = get_aes_key_iv(password)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        original = unpadder.update(padded_data) + unpadder.finalize()
        return original.decode()
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted data.")

def xor_cipher(text: str, key: str) -> str:
    # Simple XOR
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

def rot13_cipher(text: str) -> str:
    # Custom implementation to handle full unicode if needed, usually codecs is enough
    import codecs
    return codecs.encode(text, 'rot_13')

# --- ENDPOINTS ---

@app.post("/api/process")
async def process_crypto(req: CryptoRequest):
    try:
        result = ""
        
        # Validasi Password
        if req.method in ["AES", "XOR"] and not req.password:
            return JSONResponse(status_code=400, content={"success": False, "error": "Password diperlukan untuk metode ini."})

        # Logic Mapping
        if req.method == "Base64":
            if req.action == "encrypt":
                result = base64.b64encode(req.text.encode()).decode()
            else:
                result = base64.b64decode(req.text).decode()
                
        elif req.method == "ROT13":
            result = rot13_cipher(req.text) # Symmetric
            
        elif req.method == "XOR":
            # XOR is symmetric logic-wise, but output needs base64 handling for safety
            if req.action == "encrypt":
                xor_res = xor_cipher(req.text, req.password)
                result = base64.b64encode(xor_res.encode('utf-8')).decode() # Encode result to be copy-pasteable
            else:
                try:
                    decoded_input = base64.b64decode(req.text).decode('utf-8')
                    result = xor_cipher(decoded_input, req.password)
                except:
                    # Fallback if user tries to decrypt raw string (rare)
                    result = xor_cipher(req.text, req.password)

        elif req.method == "AES":
            if req.action == "encrypt":
                result = aes_encrypt(req.text, req.password)
            else:
                result = aes_decrypt(req.text, req.password)
                
        # Note: RSA and DES omitted for brevity in this single file demo 
        # but follow the same structure using cryptography library.
        
        return {"success": True, "result": result}

    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})

@app.get("/")
async def read_root():
    # Membaca template HTML dan me-return sebagai string
    # Ini cara paling aman di Vercel Serverless untuk single file frontend
    file_path = os.path.join(os.path.dirname(__file__), "../templates/index.html")
    with open(file_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)
