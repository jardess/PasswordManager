import os
import sqlite3
from crypto import generate_salt, derive_key, encryption, decryption
from cryptography.exceptions import InvalidTag


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

def abrir_cofre(caminho, senha_mestra):
    if not os.path.exists(caminho):
        raise FileNotFoundError("O caminho não existe.")
    conexao = sqlite3.connect(caminho)
    cursor = conexao.cursor()
    cursor.execute("SELECT salt, verificacao FROM config")
    linha = cursor.fetchone()
    conexao.close()

    salt = linha[0]
    verificacao = linha[1]

    chave = derive_key(senha_mestra, salt)
    try:
        decryption(chave, verificacao)
    except InvalidTag:
        raise ValueError("Senha incorreta.") 

    return chave

def adicionar_entrada(caminho, chave, site, usuario, senha):
    site_cifrado = encryption(chave, site)
    usuario_cifrado = encryption(chave, usuario)
    senha_cifrada = encryption(chave, senha)

    conexao = sqlite3.connect(caminho)
    cursor = conexao.cursor()
    cursor.execute("INSERT INTO entradas (site, usuario, senha) VALUES (?, ?, ?)", (site_cifrado, usuario_cifrado, senha_cifrada))
    conexao.commit()
    conexao.close()

def listar_entradas(caminho, chave):
    conexao = sqlite3.connect(caminho)
    cursor = conexao.cursor()
    cursor.execute("SELECT id, site, usuario FROM entradas")
    linhas = cursor.fetchall()
    conexao.close()

    entradas = []
    for linha in linhas:
        id_entrada = linha[0]
        site_cifrado = linha[1]
        usuario_cifrado = linha[2]

        site = decryption(chave, site_cifrado)
        usuario = decryption(chave, usuario_cifrado)
        entradas.append((id_entrada, site, usuario))

    return entradas

def remover_entrada(caminho, id_entrada):
    conexao = sqlite3.connect(caminho)
    cursor = conexao.cursor()
    cursor.execute("DELETE FROM entradas WHERE id = ?", (id_entrada,))
    num = cursor.rowcount
    conexao.commit()
    conexao.close()

    if num == 0:
        raise ValueError("Entrada não encontrada.")

def buscar_senha(caminho, chave, id_entrada):
    conexao = sqlite3.connect(caminho)
    cursor = conexao.cursor()
    cursor.execute("SELECT senha FROM entradas WHERE id = ?", (id_entrada,))
    linha = cursor.fetchone()
    conexao.close()

    if linha is None:
        raise ValueError("Senha não encontrada.")

    senha = decryption(chave, linha[0])

    return senha




if __name__ == "__main__":