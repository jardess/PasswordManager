import secrets
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


#Salt = 16 bytes
#Chave de saida = 32 bytes

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


##TESTE PRA VER SE TA CERTINHO
if __name__ == "__main__": 
    salt = generate_salt()
    a = derive_key("minha senha", salt)
    b = derive_key("minha senha", salt)
    c = derive_key("outra senha completamente diferente", salt)
    print(a == c)
    print(a == b)
    print(len(a))