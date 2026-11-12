import secrets

#Salt = 16 bytes
#Chave de saida = 32 bytes

def generateSalt():
    secrets.token_bytes(16)
    pass

def deriveKey():
    
    pass
