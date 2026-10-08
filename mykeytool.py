import argparse
import base64
import json
import os
import sys
from getpass import getpass

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID

KEYSTORE_FILE = "keystore.txt"
PEM_HEADER = "-----BEGIN MYKEYTOOL KEYSTORE-----"
PEM_FOOTER = "-----END MYKEYTOOL KEYSTORE-----"


def derivar_clave(password: str, salt: bytes) -> bytes:
    """Deriva una clave simétrica de 256 bits a partir de la contraseña usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode("utf-8"))


def cargar_keystore(password: str) -> dict:
    """Carga y descifra el KeyStore (PEM con Base64 de salt + nonce + AES-GCM).

    Si el archivo no existe devuelve un diccionario vacío (se creará al guardar).
    """
    if not os.path.exists(KEYSTORE_FILE):
        return {}

    try:
        with open(KEYSTORE_FILE, "r", encoding="utf-8") as f:
            lineas = [
                l.strip() for l in f
                if l.strip() and not l.startswith("-----")
            ]
        contenido = base64.b64decode("".join(lineas), validate=True)
    except (OSError, ValueError):
        print("\nError: No se pudo leer el archivo KeyStore o está dañado.")
        sys.exit(1)

    # 16 bytes de salt + 12 bytes de nonce + 16 bytes mínimo de etiqueta GCM
    if len(contenido) < 44:
        print("\nError: El archivo KeyStore está corrupto o incompleto.")
        sys.exit(1)

    salt = contenido[:16]
    nonce = contenido[16:28]
    datos_cifrados = contenido[28:]

    try:
        clave = derivar_clave(password, salt)
        aesgcm = AESGCM(clave)
        datos_descifrados = aesgcm.decrypt(nonce, datos_cifrados, None)
        return json.loads(datos_descifrados.decode("utf-8"))
    except (InvalidTag, ValueError):
        print("\nError: Contraseña del KeyStore incorrecta o el archivo está dañado.")
        sys.exit(1)


def guardar_keystore(password: str, datos: dict):
    """Cifra la estructura del KeyStore y la guarda en formato PEM (Base64)."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    clave = derivar_clave(password, salt)

    aesgcm = AESGCM(clave)
    datos_bytes = json.dumps(datos).encode("utf-8")
    datos_cifrados = aesgcm.encrypt(nonce, datos_bytes, None)

    b64 = base64.b64encode(salt + nonce + datos_cifrados).decode("ascii")
    lineas = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    pem = PEM_HEADER + "\n" + "\n".join(lineas) + "\n" + PEM_FOOTER + "\n"

    with open(KEYSTORE_FILE, "w", encoding="utf-8") as f:
        f.write(pem)


def comando_genkey():
    """Genera par RSA de 2048 bits y guarda el alias con su Distinguished Name."""
    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    keystore = cargar_keystore(password)

    alias = input("Introduce el alias para identificar la clave: ").strip()
    if not alias:
        print("\nError: El alias no puede estar vacío.")
        return

    if alias in keystore:
        print(f"\nError: El alias '{alias}' ya existe en el KeyStore.")
        return

    print("\nIntroduce los datos del titular (Distinguished Name):")
    cn = input("Nombre y apellidos (CN): ").strip()
    ou = input("Unidad Organizativa (OU): ").strip()
    o = input("Organización (O): ").strip()
    l = input("Ciudad/Localidad (L): ").strip()
    st = input("Estado/Provincia (ST): ").strip()
    c = input("Código del País - 2 letras (C): ").strip()

    if c and len(c) != 2:
        print("\nError: El código de país debe tener exactamente 2 letras.")
        return

    alias_pass = getpass("Introduce la contraseña para el alias (o Enter para usar la del KeyStore): ")
    if not alias_pass:
        alias_pass = password

    print("\nGenerando par de claves RSA de 2048 bits...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Exportación cifrada de la clave privada en estándar PKCS#8
    clave_privada_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(alias_pass.encode("utf-8")),
    ).decode("utf-8")

    keystore[alias] = {
        "dn": {"CN": cn, "OU": ou, "O": o, "L": l, "ST": st, "C": c.upper()},
        "private_key": clave_privada_pem,
    }

    guardar_keystore(password, keystore)
    print(f"Par de claves generado y guardado correctamente bajo el alias '{alias}'.")


def comando_certreq():
    """Genera una Solicitud de Firma de Certificado (CSR) válida en formato PEM."""
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    keystore = cargar_keystore(password)

    alias = input("Introduce el alias del par de claves: ").strip()
    if alias not in keystore:
        print(f"\nError: El alias '{alias}' no existe en el KeyStore.")
        return

    alias_pass = getpass("Introduce la contraseña del alias: ")

    try:
        clave_privada_pem = keystore[alias]["private_key"].encode("utf-8")
        private_key = serialization.load_pem_private_key(
            clave_privada_pem,
            password=alias_pass.encode("utf-8"),
        )
    except (ValueError, TypeError):
        print("\nError: Contraseña del alias incorrecta.")
        return

    dn = keystore[alias]["dn"]

    # Mapeo del Distinguished Name a objetos OID estándar X.509
    atributos = []
    if dn.get("CN"):
        atributos.append(x509.NameAttribute(NameOID.COMMON_NAME, dn["CN"]))
    if dn.get("OU"):
        atributos.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, dn["OU"]))
    if dn.get("O"):
        atributos.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, dn["O"]))
    if dn.get("L"):
        atributos.append(x509.NameAttribute(NameOID.LOCALITY_NAME, dn["L"]))
    if dn.get("ST"):
        atributos.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, dn["ST"]))
    if dn.get("C"):
        atributos.append(x509.NameAttribute(NameOID.COUNTRY_NAME, dn["C"]))

    if not atributos:
        print("\nError: No se encontraron datos del titular (DN) válidos para generar el CSR.")
        return

    subject = x509.Name(atributos)

    # Construcción y firma de la solicitud CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    archivo_csr = f"{alias}.csr"
    with open(archivo_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"\nSolicitud de Firma de Certificado (CSR) generada con éxito: '{archivo_csr}'")


# =============================================================================
# AMPLIACIÓN: --list
# Equivalente a "keytool -list". Muestra los alias del KeyStore con su DN.
# =============================================================================
def comando_list():
    """Descifra el KeyStore y muestra los alias, su DN y la clave privada en PEM."""
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    keystore = cargar_keystore(password)

    if not keystore:
        print("\nEl KeyStore está vacío.")
        return

    print(f"\nEl KeyStore contiene {len(keystore)} entrada(s):")
    for alias, entrada in keystore.items():
        dn = entrada["dn"]
        dn_texto = ", ".join(f"{k}={v}" for k, v in dn.items() if v)
        print(f"\n--- Alias: {alias} ---")
        print(f"Titular: {dn_texto}")
        print(entrada["private_key"])


# =============================================================================
# AMPLIACIÓN: --delete
# Equivalente a "keytool -delete". Elimina un alias del KeyStore.
# =============================================================================
def comando_delete():
    """Elimina una entrada (alias) del KeyStore."""
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    keystore = cargar_keystore(password)

    alias = input("Introduce el alias que quieres eliminar: ").strip()
    if alias not in keystore:
        print(f"\nError: El alias '{alias}' no existe en el KeyStore.")
        return

    confirmacion = input(f"¿Seguro que quieres eliminar '{alias}'? Esta acción no se puede deshacer (s/N): ").strip().lower()
    if confirmacion != "s":
        print("\nOperación cancelada. No se ha eliminado nada.")
        return

    del keystore[alias]
    guardar_keystore(password, keystore)
    print(f"\nAlias '{alias}' eliminado correctamente del KeyStore.")


# =============================================================================
# AMPLIACIÓN: --storepasswd
# Equivalente a "keytool -storepasswd". Cambia la contraseña del KeyStore.
# Al guardar se generan un salt y un nonce nuevos, y se re-cifra todo el almacén.
# =============================================================================
def comando_storepasswd():
    """Cambia la contraseña que protege el KeyStore."""
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña actual del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    keystore = cargar_keystore(password)

    nueva = getpass("Introduce la nueva contraseña del KeyStore: ")
    if not nueva:
        print("\nError: La nueva contraseña no puede estar vacía.")
        return

    repetir = getpass("Repite la nueva contraseña: ")
    if nueva != repetir:
        print("\nError: Las contraseñas no coinciden. No se ha cambiado nada.")
        return

    guardar_keystore(nueva, keystore)
    print("\nContraseña del KeyStore cambiada correctamente.")


# =============================================================================
# AMPLIACIÓN: --keypasswd
# Equivalente a "keytool -keypasswd". Cambia la contraseña de un alias.
# Se descifra la clave privada (PKCS#8) con la contraseña antigua y se vuelve
# a exportar cifrada con la nueva.
# =============================================================================
def comando_keypasswd():
    """Cambia la contraseña de la clave privada de un alias."""
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    keystore = cargar_keystore(password)

    alias = input("Introduce el alias: ").strip()
    if alias not in keystore:
        print(f"\nError: El alias '{alias}' no existe en el KeyStore.")
        return

    alias_pass = getpass("Introduce la contraseña actual del alias: ")

    try:
        private_key = serialization.load_pem_private_key(
            keystore[alias]["private_key"].encode("utf-8"),
            password=alias_pass.encode("utf-8"),
        )
    except (ValueError, TypeError):
        print("\nError: Contraseña del alias incorrecta.")
        return

    nueva = getpass("Introduce la nueva contraseña del alias: ")
    if not nueva:
        print("\nError: La nueva contraseña no puede estar vacía.")
        return

    repetir = getpass("Repite la nueva contraseña: ")
    if nueva != repetir:
        print("\nError: Las contraseñas no coinciden. No se ha cambiado nada.")
        return

    keystore[alias]["private_key"] = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(nueva.encode("utf-8")),
    ).decode("utf-8")

    guardar_keystore(password, keystore)
    print(f"\nContraseña del alias '{alias}' cambiada correctamente.")


def main():
    parser = argparse.ArgumentParser(
        prog="mykeytool",
        description="Simulador CLI de Java Keytool desarrollado en Python.",
    )

    # --help / -h lo genera argparse automáticamente
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--genkey", action="store_true", help="Genera un par de claves y las almacena.")
    group.add_argument("--certreq", action="store_true", help="Genera un CSR a partir de una clave.")
    # --- AMPLIACIÓN: comandos adicionales ---
    group.add_argument("--list", action="store_true", help="[Ampliación] Muestra el contenido del KeyStore.")
    group.add_argument("--delete", action="store_true", help="[Ampliación] Elimina un alias del KeyStore.")
    group.add_argument("--storepasswd", action="store_true", help="[Ampliación] Cambia la contraseña del KeyStore.")
    group.add_argument("--keypasswd", action="store_true", help="[Ampliación] Cambia la contraseña de un alias.")

    args = parser.parse_args()

    try:
        if args.genkey:
            comando_genkey()
        elif args.certreq:
            comando_certreq()
        # --- AMPLIACIÓN ---
        elif args.list:
            comando_list()
        elif args.delete:
            comando_delete()
        elif args.storepasswd:
            comando_storepasswd()
        elif args.keypasswd:
            comando_keypasswd()
    except KeyboardInterrupt:
        print("\n\nOperación cancelada por el usuario.")
        sys.exit(1)


if __name__ == "__main__":
    main()
