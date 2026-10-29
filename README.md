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
pip install -r requirements.txt

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
| `python mykeytool.py --exportcert` | Exporta el certificado del alias a un archivo `alias.cer` (PEM). |
| `python mykeytool.py --printcert` | Muestra el contenido de un certificado (`.cer`, `.crt` o `.pem`). |
| `python mykeytool.py --printcertreq` | Muestra el contenido de un CSR y comprueba su firma. |
| `python mykeytool.py --changealias` | Cambia el nombre del alias. |
| `python mykeytool.py --help` | Muestra la ayuda. |

Ejemplo de consola:

python mykeytool.py --help
usage: mykeytool [-h]
                 (--genkey | --certreq | --list | --delete | --storepasswd | --keypasswd | --exportcert | --printcert | --printcertreq | --changealias)
                 [--keystore ARCHIVO]

Al ejecutar cada comando, sigue las preguntas que aparecen en pantalla.

Por defecto el KeyStore es `keystore.p12`. Para usar otro archivo, añade `--keystore otro.p12` a cualquier comando.

### Funciones añadidas

Son equivalentes a comandos del keytool de Java:

| Comando | Equivalente en keytool | Necesita contraseña |
|---|---|---|
| `--exportcert` | `keytool -exportcert -rfc` | Sí, la del KeyStore |
| `--printcert` | `keytool -printcert -file` | No |
| `--printcertreq` | `keytool -printcertreq -file` | No |
| `--changealias` | `keytool -changealias` | Sí, la del KeyStore |

`--exportcert` solo exporta el certificado con la clave pública; la clave privada nunca sale del `.p12`. `--printcert` y `--printcertreq` no usan el KeyStore: piden la ruta del archivo y aceptan formato PEM o DER.

## 4. Matriz de pruebas

Marca el estado después de ejecutar cada prueba; no indiques que una prueba ha pasado sin comprobarla.

| Prueba | Resultado esperado | Estado |
|---|---|---|
| Mostrar ayuda (`--help`) | Muestra los comandos disponibles. | Pendiente |
| Generar claves (`--genkey`) | Crea el alias y el archivo `keystore.p12`. | Pendiente |
| Listar (`--list`) | Muestra las entradas y su huella. | Pendiente |
| Generar CSR (`--certreq`) | Crea un archivo `.csr`. | Pendiente |
| Contraseña incorrecta | Muestra un error. | Pendiente |
| Eliminar alias (`--delete`) | Elimina el alias si se confirma. | Pendiente |
| Cambiar contraseña (`--storepasswd`) | Guarda el almacén con la nueva contraseña. | Pendiente |
| Exportar certificado (`--exportcert`) | Crea el archivo `alias.cer`. | Pendiente |
| Ver certificado (`--printcert`) | Muestra propietario, emisor, validez y huella del `.cer`. | Pendiente |
| Ver CSR (`--printcertreq`) | Muestra el titular del `.csr` y "Firma: válida". | Pendiente |
| CSR modificado (`--printcertreq`) | Muestra "Firma: NO VÁLIDA". | Pendiente |
| Archivo que no es un certificado (`--printcert`) | Muestra un error. | Pendiente |
| Cambiar alias (`--changealias`) | `--list` muestra el alias nuevo con la misma huella. | Pendiente |