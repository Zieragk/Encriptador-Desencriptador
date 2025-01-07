import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from colorama import init, Fore, Style
import shutil


init(autoreset=True)


logo = """
███████╗██╗███████╗██████╗░░█████╗░░██████╗░██╗░░██╗
╚════██║██║██╔════╝██╔══██╗██╔══██╗██╔════╝░██║░██╔╝
░░███╔═╝██║█████╗░░██████╔╝███████║██║░░██╗░█████═╝░
██╔══╝░░██║██╔══╝░░██╔══██╗██╔══██║██║░░╚██╗██╔═██╗░
███████╗██║███████╗██║░░██║██║░░██║╚██████╔╝██║░╚██╗
╚══════╝╚═╝╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝░╚═════╝░╚═╝░░╚═╝
"""


def print_centered(text):
    terminal_width = shutil.get_terminal_size().columns 
    centered_text = text.center(terminal_width) 
    print(centered_text)


def generate_key_from_password(password: str):
    salt = os.urandom(16)  
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))  
    return key, salt


def encrypt_file(input_file, output_file, key, salt):
    iv = os.urandom(16)  
    
    with open(input_file, 'rb') as f:
        data = f.read()

   
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

  
    with open(output_file, 'wb') as f:
        f.write(salt + iv + encrypted_data)


def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        salt = f.read(16) 
        iv = f.read(16)    
        encrypted_data = f.read()

    
    key = generate_key_from_password(password)[0]

 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    
    with open(output_file, 'wb') as f:
        f.write(data)


def get_valid_file_path(prompt):
    while True:
        file_path = input(prompt).strip()
        if os.path.exists(file_path):
            return file_path
        else:
            print(f"Error: El archivo en la ruta {file_path} no existe. Intenta de nuevo.")


def show_menu():
    print_centered(Fore.RED + Style.BRIGHT + logo)  
    print(Style.DIM + "1. Cifrar un archivo")
    print("2. Descifrar un archivo")
    print("3. Salir")
    print(Fore.RED + Style.BRIGHT + "=========================================")

# Función principal
def main():
    print(Fore.RED + Style.BRIGHT + "Bienvenido a la herramienta de cifrado y descifrado de archivos")
    print(Style.DIM + "==============================================")
    
    while True:
        show_menu()
        option = input("Ingrese el número de la opción: ")

        if option == '1':
            password = input("Por favor, ingrese una contraseña para generar su clave: ")
            key, salt = generate_key_from_password(password)
            input_file = get_valid_file_path("Ingrese la ruta del archivo a cifrar: ")
            output_file = input("Ingrese el nombre del archivo cifrado de salida: ")
            try:
                encrypt_file(input_file, output_file, key, salt)
                print(f"Archivo cifrado correctamente. Guardado en: {output_file}")
            except Exception as e:
                print(f"Error al cifrar el archivo: {e}")

        elif option == '2':
            password = input("Por favor, ingrese la contraseña utilizada para generar la clave: ")
            input_file = get_valid_file_path("Ingrese la ruta del archivo a descifrar: ")
            output_file = input("Ingrese el nombre del archivo descifrado de salida: ")
            try:
                decrypt_file(input_file, output_file, password)
                print(f"Archivo descifrado correctamente. Guardado en: {output_file}")
            except Exception as e:
                print(f"Error al descifrar el archivo: {e}")

        elif option == '3':
            print("Saliendo...")
            break

        else:
            print("Opción no válida, por favor intente de nuevo.")

if __name__ == '__main__':
    main()
