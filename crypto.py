import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

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

def decryption(chave, dados):
    nonce = dados[:12]
    cifrado = dados[12:]

    aesgcm = AESGCM(
        key=chave
    )

    decifrado_bytes = aesgcm.decrypt(nonce, cifrado, None)
    decifrado = decifrado_bytes.decode()
    
    return decifrado


#TESTES
if __name__ == "__main__": 
    salt = generate_salt()
    chave = derive_key("minha senha", salt)
    chave_errada = derive_key("senha aleatoria", salt)
    resultado = encryption(chave, "meu segredo")

    # Teste 1 (Deve funcionar)
    print("Teste 1:", decryption(chave, resultado))

    # Teste 2 (senha errada ,precisa falhar)
    try:
        decryption(chave_errada, resultado)
        print("Teste 2 FALHOU, a chave errada foi aceita pelo sistema.")
    except InvalidTag:
        print("Teste 2 OK, chave errada foi rejeitada.")

    # Teste 3 (Dado adulterado, precisa falhar)
    adulterado = bytearray(resultado)
    adulterado[12] = adulterado[12] ^ 1  # Utilizando XOR para garantir que o byte novo é diferente do original!!!
    try: 
        decryption(chave, bytes(adulterado))
        print("Teste 3 FALHOU, dado adulterado foi aceito.")
    except InvalidTag:
        print("Teste 3 OK, adulteração detectada.")
    