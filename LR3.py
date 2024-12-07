import socket
import os
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from cryptography.x509 import CertificateBuilder, NameOID
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Функція для логування подій
def log(message):
    print(f"[LOG] {message}")
    time.sleep(0.7)

# Приймає точну кількість байтів
def recv_exact(conn, n):
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before receiving expected bytes.")
        data += chunk
    return data

# Відправляє блок даних
def send_block(conn, data):
    length = len(data)
    conn.sendall(length.to_bytes(4, 'big'))
    conn.sendall(data)

# Приймає блок даних
def recv_block(conn):
    length_data = conn.recv(4)
    if len(length_data) < 4:
        raise ConnectionError("Connection closed before reading block length.")
    length = int.from_bytes(length_data, 'big')
    if length == 0:
        return b''
    return recv_exact(conn, length)

# Генерує сертифікат Центру Сертифікації (CA)
def generate_ca():
    log("Генерація приватного ключа CA...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    log("Генерація сертифіката CA...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Local CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureApp Inc.")
    ])
    cert = (CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .sign(private_key, hashes.SHA256()))

    with open("ca_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    log("Приватний ключ CA збережено у 'ca_key.pem'.")

    with open("ca_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    log("Сертифікат CA збережено у 'ca_cert.pem'.")

    return private_key, cert

# Генерує сертифікат для сервера або клієнта
def generate_certificate(entity_name, ca_key, ca_cert):
    log(f"Генерація приватного ключа для {entity_name}...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    log(f"Генерація сертифіката для {entity_name}...")
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, entity_name),
    ])
    cert = (CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(ca_key, hashes.SHA256()))

    with open(f"{entity_name}_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    log(f"Приватний ключ для {entity_name} збережено у '{entity_name}_key.pem'.")

    with open(f"{entity_name}_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    log(f"Сертифікат для {entity_name} збережено у '{entity_name}_cert.pem'.")

    return private_key, cert

# ECDHE рукостискання для встановлення спільного секрету
def ecdhe_handshake(conn, private_key, cert, is_server):
    log("Генерація тимчасового ключа ECDHE...")
    ecdhe_key = ec.generate_private_key(ec.SECP256R1())
    public_key = ecdhe_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if is_server:
        log("Сервер відправляє свій сертифікат та публічний ключ...")
        server_cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        send_block(conn, server_cert_pem)
        send_block(conn, public_key_pem)

        log("Сервер очікує сертифікат та публічний ключ клієнта...")
        client_cert_pem = recv_block(conn)
        client_public_key_pem = recv_block(conn)

        log("Сервер отримав сертифікат та публічний ключ клієнта.")
        peer_cert = x509.load_pem_x509_certificate(client_cert_pem)
        peer_public_key = serialization.load_pem_public_key(client_public_key_pem)
    else:
        log("Клієнт отримує сертифікат та публічний ключ сервера...")
        server_cert_pem = recv_block(conn)
        server_public_key_pem = recv_block(conn)

        log("Клієнт відправляє свій сертифікат та публічний ключ...")
        client_cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        send_block(conn, client_cert_pem)
        send_block(conn, public_key_pem)

        log("Клієнт отримав сертифікат та публічний ключ сервера.")
        peer_cert = x509.load_pem_x509_certificate(server_cert_pem)
        peer_public_key = serialization.load_pem_public_key(server_public_key_pem)

    log("Обчислення спільного секрету...")
    shared_secret = ecdhe_key.exchange(ec.ECDH(), peer_public_key)

    log("Перевірка сертифіката за допомогою CA...")
    ca_cert = x509.load_pem_x509_certificate(open("ca_cert.pem", "rb").read())
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        peer_cert.signature,
        peer_cert.tbs_certificate_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    log("Сертифікат успішно перевірено.")

    return shared_secret

# Функція для отримання ключів із спільного секрету
def derive_keys(shared_secret):
    log("Використання HKDF для отримання симетричних ключів...")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    )
    key = hkdf.derive(shared_secret)
    log(f"Симетричний ключ: {key.hex()}")
    return key

# Шифрує повідомлення за допомогою AES-GCM
def encrypt_message(key, plaintext):
    log(f"Шифрування повідомлення: {plaintext.decode()}")
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    log(f"Зашифроване повідомлення: {ciphertext.hex()}")
    log(f"IV: {iv.hex()}, Tag: {tag.hex()}")
    return iv, ciphertext, tag

# Дешифрує повідомлення за допомогою AES-GCM
def decrypt_message(key, iv, ciphertext, tag):
    log(f"Розшифровка повідомлення...")
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    log(f"Розшифроване повідомлення: {plaintext.decode()}")
    return plaintext

# Відправляє зашифроване повідомлення
def send_encrypted_message(conn, key, plaintext):
    log(f"Підготовка до відправки повідомлення: {plaintext.decode()}")
    iv, ciphertext, tag = encrypt_message(key, plaintext)
    length = len(ciphertext)
    conn.sendall(length.to_bytes(4, 'big'))
    conn.sendall(iv)
    conn.sendall(ciphertext)
    conn.sendall(tag)
    log("Повідомлення відправлено.")

# Отримує зашифроване повідомлення
def recv_encrypted_message(conn, key):
    log("Очікування зашифрованого повідомлення...")
    length_data = conn.recv(4)
    if not length_data or len(length_data) < 4:
        log("Повідомлення не отримано.")
        return None
    ciphertext_length = int.from_bytes(length_data, 'big')
    if ciphertext_length == 0:
        log("Отримано порожнє повідомлення.")
        return None
    iv = recv_exact(conn, 12)
    ciphertext = recv_exact(conn, ciphertext_length)
    tag = recv_exact(conn, 16)
    log(f"Отримано зашифроване повідомлення: {ciphertext.hex()}")
    return decrypt_message(key, iv, ciphertext, tag)

# Логіка сервера
def server():
    log("Запуск сервера...")
    with open("server_key.pem", "rb") as f:
        server_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("server_cert.pem", "rb") as f:
        server_cert = x509.load_pem_x509_certificate(f.read())

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 5555))
    server_socket.listen(5)
    log("Сервер очікує підключень на 127.0.0.1:5555.")

    conn, addr = server_socket.accept()
    log(f"З'єднання встановлено з {addr}.")

    try:
        log("Початок ECDHE рукостискання...")
        shared_secret = ecdhe_handshake(conn, server_key, server_cert, is_server=True)
        key = derive_keys(shared_secret)
        log("Захищений канал успішно встановлено.")
    except Exception as e:
        log(f"Помилка під час рукостискання: {e}")
        conn.close()
        return

    while True:
        try:
            plaintext = recv_encrypted_message(conn, key)
            if plaintext is None:
                log("Клієнт відключився.")
                break
            log(f"Клієнт надіслав: {plaintext.decode()}")
            response_text = f"Сервер отримав: {plaintext.decode()}"
            send_encrypted_message(conn, key, response_text.encode())
        except ConnectionError:
            log("Клієнт відключився.")
            break
        except Exception as e:
            log(f"Помилка при отриманні/розшифруванні повідомлення: {e}")
            break

    conn.close()
    log("Сервер завершив роботу.")

# Логіка клієнта
def client():
    log("Запуск клієнта...")
    with open("client_key.pem", "rb") as f:
        client_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("client_cert.pem", "rb") as f:
        client_cert = x509.load_pem_x509_certificate(f.read())

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 5555))
    log("З'єднання з сервером встановлено.")

    try:
        log("Початок ECDHE рукостискання...")
        shared_secret = ecdhe_handshake(client_socket, client_key, client_cert, is_server=False)
        key = derive_keys(shared_secret)
        log("Захищений канал успішно встановлено.")
    except Exception as e:
        log(f"Помилка під час рукостискання: {e}")
        client_socket.close()
        return

    while True:
        message = input("Введіть повідомлення (або залиште порожнім для виходу): ").strip()
        if not message:
            log("Клієнт завершив роботу.")
            break
        send_encrypted_message(client_socket, key, message.encode('utf-8'))
        response = recv_encrypted_message(client_socket, key)
        if response is None:
            log("Сервер відключився.")
            break
        log(f"Сервер відповів: {response.decode()}")

    client_socket.close()

# Головна функція
if __name__ == "__main__":
    role = input("Введіть роль (server/client): ").strip()

    if role == "server":
        if not (os.path.exists("ca_cert.pem") and
                os.path.exists("server_cert.pem") and
                os.path.exists("client_cert.pem")):
            log("Сертифікати не знайдено. Генерація нових...")
            ca_key, ca_cert = generate_ca()
            generate_certificate("server", ca_key, ca_cert)
            generate_certificate("client", ca_key, ca_cert)

        server()
    elif role == "client":
        if not (os.path.exists("ca_cert.pem") and
                os.path.exists("server_cert.pem") and
                os.path.exists("client_cert.pem")):
            log("Сертифікати відсутні. Спочатку запустіть сервер для генерації сертифікатів.")
        else:
            client()
    else:
        log("Невідома роль. Будь ласка, введіть 'server' або 'client'.")