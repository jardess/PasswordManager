import os
import sqlite3
from crypto import generate_salt, derive_key, encryption, decryption

def criar_cofre(caminho, senha_mestra):
    if os.path.exists(caminho):
        raise FileExistsError("O caminho ja existe.")

    salt = generate_salt()
    chave = derive_key(senha_mestra, salt)

    verificacao = encryption(chave, "teclado1")

    conexao = sqlite3.connect(caminho)
    cursor = conexao.cursor()

    cursor.execute("CREATE TABLE config (salt BLOB, verificacao BLOB)")
    cursor.execute("CREATE TABLE entradas (id INTEGER PRIMARY KEY AUTOINCREMENT, site BLOB, usuario BLOB, senha BLOB)")
    cursor.execute("INSERT INTO config (salt, verificacao) VALUES (?, ?)", (salt, verificacao))


    conexao.commit()
    conexao.close()

if __name__ == "__main__":
    criar_cofre("teste.db", "minha senha")
    print("Cofre criado")
