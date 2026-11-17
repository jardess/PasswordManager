import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def generate_salt():
    salt = secrets.token_bytes(16)
    return salt

def derive_key(senha_mestra, salt):
    senha_bytes = senha_mestra.encode()

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=65536,
    )

    chave = kdf.derive(senha_bytes)

    return chave

def encryption(chave, texto):
    texto_bytes = texto.encode()
    nonce = secrets.token_bytes(12)

    aesgcm = AESGCM(
        key=chave
    )

    cifrado = aesgcm.encrypt(nonce, texto_bytes, None)

    return nonce + cifrado


#TESTE  
if __name__ == "__main__": 
    salt = generate_salt()
    chave = derive_key("minha senha", salt)
    resultado = encryption(chave, "meu segredo")
    print(resultado)
    print(len(resultado))

    