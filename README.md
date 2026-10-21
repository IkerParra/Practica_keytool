# Practica_keytool

## 1. Integrantes
- Dan Vergara
- Iker Parra

## 2. Instalación

Requisitos: Python 3.14, PowerShell y el archivo `mykeytool.py`.
Crear el entorno virtual (adapta la ruta de Python):
& "RUTA_DE_TU_PYTHON\python.exe" -m venv venv

Activarlo y instalar las dependencias:
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
pip install cryptography

Comprobar que funciona:
python mykeytool.py --help


## 3. Uso de la CLI

Ejecuta los comandos desde la carpeta del proyecto, con el entorno virtual activado.

| Comando | Función |
|---|---|
| `python mykeytool.py --genkey` | Genera un par de claves y lo guarda en el KeyStore. |
| `python mykeytool.py --certreq` | Genera una solicitud CSR. |
| `python mykeytool.py --list` | Muestra las entradas del almacén. |
| `python mykeytool.py --delete` | Elimina un alias. |
| `python mykeytool.py --storepasswd` | Cambia la contraseña del KeyStore. |
| `python mykeytool.py --keypasswd` | Cambia la contraseña de un alias. |
| `python mykeytool.py --help` | Muestra la ayuda. |

Ejemplo de consola:

python mykeytool.py --help
usage: mykeytool [-h] (--genkey | --certreq | --list | --delete | --storepasswd | --keypasswd)

Al ejecutar cada comando, sigue las preguntas que aparecen en pantalla.

## 4. Matriz de pruebas

Marca el estado después de ejecutar cada prueba; no indiques que una prueba ha pasado sin comprobarla.

| Prueba | Resultado esperado | Estado |
|---|---|---|
| Mostrar ayuda (`--help`) | Muestra los comandos disponibles. | Pendiente |
| Generar claves (`--genkey`) | Crea el alias y el archivo `keystore.txt`. | Pendiente |
| Listar (`--list`) | Muestra las entradas y su huella. | Pendiente |
| Generar CSR (`--certreq`) | Crea un archivo `.csr`. | Pendiente |
| Contraseña incorrecta | Muestra un error. | Pendiente |
| Eliminar alias (`--delete`) | Elimina el alias si se confirma. | Pendiente |
| Cambiar contraseña (`--storepasswd`) | Guarda el almacén con la nueva contraseña. | Pendiente |
