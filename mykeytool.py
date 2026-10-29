import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from getpass import getpass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

# El KeyStore es un archivo PKCS#12 (.p12), el mismo formato que usa el keytool real de Java.
# Se puede cambiar con la opción --keystore otro.p12
KEYSTORE_FILE = "keystore.p12"

# Longitud mínima de las contraseñas nuevas (igual que el keytool real de Java)
MIN_PASSWORD = 6

# Días de validez del certificado autofirmado que se genera con --genkey
VALIDEZ_DIAS = 365

# Iteraciones de PBKDF2 al cifrar el .p12: más iteraciones = fuerza bruta más lenta
# (por defecto la librería usa 20.000 y el keytool de Java 10.000)
ITERACIONES_KDF = 100_000


def password_valida(password: str) -> bool:
    """Comprueba que una contraseña NUEVA tenga al menos MIN_PASSWORD caracteres."""
    if len(password) < MIN_PASSWORD:
        print(f"\nError: La contraseña debe tener al menos {MIN_PASSWORD} caracteres.")
        return False
    return True


def cargar_keystore(password: str):
    """Abre el archivo .p12 con la contraseña y devuelve (clave_privada, certificado, alias).

    El .p12 está cifrado: sin la contraseña correcta no se puede leer nada.
    """
    try:
        with open(KEYSTORE_FILE, "rb") as f:
            datos = f.read()
        p12 = pkcs12.load_pkcs12(datos, password.encode("utf-8"))
    except OSError:
        print("\nError: No se pudo leer el archivo KeyStore.")
        sys.exit(1)
    except ValueError:
        print("\nError: Contraseña del KeyStore incorrecta o el archivo está dañado.")
        sys.exit(1)

    if p12.key is None or p12.cert is None:
        print("\nError: El KeyStore no contiene ningún par de claves con certificado.")
        sys.exit(1)

    friendly = p12.cert.friendly_name
    alias = friendly.decode("utf-8") if friendly else "(sin alias)"
    return p12.key, p12.cert.certificate, alias


def guardar_keystore(password: str, alias: str, clave_privada, certificado):
    """Guarda clave privada + certificado en un .p12 cifrado con la contraseña.

    Cifrado: PBES2 (PBKDF2-HMAC-SHA256 con ITERACIONES_KDF iteraciones + AES-256-CBC).
    Integridad: MAC HMAC-SHA256, que detecta si alguien modifica el archivo.
    """
    cifrado = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(ITERACIONES_KDF)
        .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
        .hmac_hash(hashes.SHA256())
        .build(password.encode("utf-8"))
    )
    datos = pkcs12.serialize_key_and_certificates(
        name=alias.encode("utf-8"),       # el "friendly name" del .p12 es el alias
        key=clave_privada,
        cert=certificado,
        cas=None,
        encryption_algorithm=cifrado,
    )
    with open(KEYSTORE_FILE, "wb") as f:
        f.write(datos)


def comando_genkey():
    """Genera par RSA de 2048 bits + certificado autofirmado y los guarda en el .p12."""
    # Con esta librería un .p12 guarda una sola clave: no se sobrescribe uno existente
    if os.path.exists(KEYSTORE_FILE):
        print(f"\nError: Ya existe '{KEYSTORE_FILE}' (un .p12 guarda una sola clave).")
        print("Usa --keystore otro.p12 para crear otro KeyStore, o --delete para borrar este.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return
    if not password_valida(password):
        return

    alias = input("Introduce el alias para identificar la clave: ").strip()
    if not alias:
        print("\nError: El alias no puede estar vacío.")
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

    # Mapeo del Distinguished Name a objetos OID estándar X.509 (se omiten los campos vacíos)
    campos = [
        (NameOID.COMMON_NAME, cn),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        (NameOID.ORGANIZATION_NAME, o),
        (NameOID.LOCALITY_NAME, l),
        (NameOID.STATE_OR_PROVINCE_NAME, st),
        (NameOID.COUNTRY_NAME, c.upper()),
    ]
    atributos = [x509.NameAttribute(oid, valor) for oid, valor in campos if valor]
    if not atributos:
        print("\nError: Hay que rellenar al menos un dato del titular (DN).")
        return
    nombre = x509.Name(atributos)

    print("\nGenerando par de claves RSA de 2048 bits...")
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Certificado autofirmado (como hace keytool -genkeypair): emisor = titular
    ahora = datetime.now(timezone.utc)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)
        .public_key(clave_privada.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora)
        .not_valid_after(ahora + timedelta(days=VALIDEZ_DIAS))
        .sign(clave_privada, hashes.SHA256())
    )

    guardar_keystore(password, alias, clave_privada, certificado)
    print(f"Par de claves generado y guardado correctamente en '{KEYSTORE_FILE}' bajo el alias '{alias}'.")


def comando_certreq():
    """Genera una Solicitud de Firma de Certificado (CSR) válida en formato PEM."""
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    clave_privada, certificado, alias_guardado = cargar_keystore(password)

    alias = input("Introduce el alias del par de claves: ").strip()
    if alias.lower() != alias_guardado.lower():
        print(f"\nError: El alias '{alias}' no existe en el KeyStore.")
        return

    # El CSR usa el mismo titular (DN) del certificado y se firma con la clave privada
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(certificado.subject)
        .sign(clave_privada, hashes.SHA256())
    )

    archivo_csr = f"{alias_guardado}.csr"
    with open(archivo_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"\nSolicitud de Firma de Certificado (CSR) generada con éxito: '{archivo_csr}'")


def formatear_dn(nombre: x509.Name) -> str:
    """Convierte el DN del certificado en una cadena tipo 'CN=..., OU=..., O=...'."""
    orden = [
        ("CN", NameOID.COMMON_NAME),
        ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
        ("O", NameOID.ORGANIZATION_NAME),
        ("L", NameOID.LOCALITY_NAME),
        ("ST", NameOID.STATE_OR_PROVINCE_NAME),
        ("C", NameOID.COUNTRY_NAME),
    ]
    partes = []
    for etiqueta, oid in orden:
        for atributo in nombre.get_attributes_for_oid(oid):
            partes.append(f"{etiqueta}={atributo.value}")
    return ", ".join(partes)


def huella_sha256(certificado: x509.Certificate) -> str:
    """Huella SHA-256 del certificado (como la que muestra keytool -list)."""
    return ":".join(f"{b:02X}" for b in certificado.fingerprint(hashes.SHA256()))


def comando_list():
    """Equivalente a 'keytool -list': abre el .p12 con la contraseña y muestra su contenido."""
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    _, certificado, alias = cargar_keystore(password)

    # not_valid_before_utc existe en versiones nuevas de cryptography; si no, se usa la antigua
    inicio = getattr(certificado, "not_valid_before_utc", None) or certificado.not_valid_before
    fin = getattr(certificado, "not_valid_after_utc", None) or certificado.not_valid_after

    print("\nTipo de almacén de claves: PKCS12")
    print("El almacén de claves contiene 1 entrada:")
    print(f"\nAlias: {alias}")
    print(f"Fecha de creación: {inicio.strftime('%d/%m/%Y %H:%M:%S')} (UTC)")
    print("Tipo de entrada: PrivateKeyEntry")
    print(f"Titular: {formatear_dn(certificado.subject)}")
    print(f"Válido desde {inicio.strftime('%d/%m/%Y')} hasta {fin.strftime('%d/%m/%Y')}")
    print(f"Huella del certificado (SHA-256): {huella_sha256(certificado)}")


def comando_delete():
    """Equivalente a 'keytool -delete': elimina el alias (y como el .p12 solo tiene uno, el archivo)."""
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    _, _, alias_guardado = cargar_keystore(password)

    alias = input("Introduce el alias que quieres eliminar: ").strip()
    if alias.lower() != alias_guardado.lower():
        print(f"\nError: El alias '{alias}' no existe en el almacén.")
        return

    confirmacion = input(
        f"¿Seguro que quieres eliminar '{alias_guardado}'? Esta acción no se puede deshacer (s/N): "
    ).strip().lower()
    if confirmacion != "s":
        print("Operación cancelada. No se ha eliminado nada.")
        return

    # Un .p12 vacío no tiene sentido: al quitar su única entrada se borra el archivo
    os.remove(KEYSTORE_FILE)
    print(f"Alias '{alias_guardado}' eliminado correctamente. Se ha borrado '{KEYSTORE_FILE}'.")


def comando_storepasswd():
    """Equivalente a 'keytool -storepasswd': cambia la contraseña del KeyStore."""
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña actual del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    clave_privada, certificado, alias = cargar_keystore(password)

    nueva = getpass("Introduce la nueva contraseña del KeyStore: ")
    if not password_valida(nueva):
        return

    repetir = getpass("Repite la nueva contraseña: ")
    if nueva != repetir:
        print("\nError: Las contraseñas no coinciden. No se ha cambiado nada.")
        return

    # Se vuelve a generar el .p12 cifrado con la nueva contraseña (salt nuevo incluido)
    guardar_keystore(nueva, alias, clave_privada, certificado)
    print("\nContraseña del KeyStore cambiada correctamente.")


def comando_keypasswd():
    """Equivalente a 'keytool -keypasswd'.

    En un KeyStore PKCS12 la clave privada y el almacén comparten la misma contraseña
    (el keytool real también lo avisa: "Different store and key passwords not supported
    for PKCS12 KeyStores"). Por eso aquí solo se informa y se remite a --storepasswd.
    """
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    _, _, alias = cargar_keystore(password)

    print(f"\nAviso: en un KeyStore PKCS12 la clave del alias '{alias}' usa la misma contraseña que el KeyStore.")
    print("No se admiten contraseñas distintas. Para cambiarla usa --storepasswd.")


# ---------------------------------------------------------------------------
# Funciones nuevas: exportcert, printcert, printcertreq y changealias
# ---------------------------------------------------------------------------

def leer_archivo(ruta: str) -> bytes:
    """Lee un archivo en binario; si no existe, muestra un error y termina."""
    if not ruta:
        print("\nError: Hay que indicar un archivo.")
        sys.exit(1)
    if not os.path.exists(ruta):
        print(f"\nError: No existe el archivo '{ruta}'.")
        sys.exit(1)
    with open(ruta, "rb") as f:
        return f.read()


def comando_exportcert():
    """Equivalente a 'keytool -exportcert -rfc': exporta el certificado del alias a un .cer en PEM.

    Solo se exporta el certificado (con la clave pública). La clave privada nunca sale del .p12.
    """
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    _, certificado, alias_guardado = cargar_keystore(password)

    alias = input("Introduce el alias del certificado a exportar: ").strip()
    if alias.lower() != alias_guardado.lower():
        print(f"\nError: El alias '{alias}' no existe en el KeyStore.")
        return

    archivo_cer = f"{alias_guardado}.cer"
    with open(archivo_cer, "wb") as f:
        f.write(certificado.public_bytes(serialization.Encoding.PEM))

    print(f"\nCertificado almacenado en el archivo '{archivo_cer}'")


def comando_printcert():
    """Equivalente a 'keytool -printcert -file': muestra el contenido de un certificado.

    No necesita KeyStore ni contraseña: un certificado es información pública.
    Acepta el certificado en PEM (texto) o en DER (binario).
    """
    ruta = input("Introduce el archivo del certificado (.cer/.crt/.pem): ").strip()
    datos = leer_archivo(ruta)

    try:
        certificado = x509.load_pem_x509_certificate(datos)
    except ValueError:
        try:
            certificado = x509.load_der_x509_certificate(datos)
        except ValueError:
            print(f"\nError: '{ruta}' no es un certificado X.509 válido.")
            sys.exit(1)

    inicio = getattr(certificado, "not_valid_before_utc", None) or certificado.not_valid_before
    fin = getattr(certificado, "not_valid_after_utc", None) or certificado.not_valid_after
    clave_publica = certificado.public_key()
    tamano = getattr(clave_publica, "key_size", "desconocido")
    hash_firma = certificado.signature_hash_algorithm
    nombre_hash = hash_firma.name.upper() if hash_firma else "desconocido"

    print(f"\nPropietario: {formatear_dn(certificado.subject)}")
    print(f"Emisor: {formatear_dn(certificado.issuer)}")
    print(f"Número de serie: {certificado.serial_number:x}")
    print(f"Válido desde {inicio.strftime('%d/%m/%Y %H:%M:%S')} hasta {fin.strftime('%d/%m/%Y %H:%M:%S')} (UTC)")
    print(f"Huella del certificado (SHA-256): {huella_sha256(certificado)}")
    print(f"Algoritmo de firma: {nombre_hash} con RSA")
    print(f"Clave pública: RSA de {tamano} bits")

    # Si emisor y titular son el mismo, es autofirmado: se comprueba su firma con su propia clave
    if certificado.issuer == certificado.subject:
        try:
            certificado.verify_directly_issued_by(certificado)
            print("Tipo: certificado autofirmado (firma válida)")
        except Exception:
            print("Tipo: certificado autofirmado (¡FIRMA NO VÁLIDA!)")


def comando_printcertreq():
    """Equivalente a 'keytool -printcertreq -file': muestra el contenido de un CSR y comprueba su firma."""
    ruta = input("Introduce el archivo de la solicitud (.csr): ").strip()
    datos = leer_archivo(ruta)

    try:
        csr = x509.load_pem_x509_csr(datos)
    except ValueError:
        try:
            csr = x509.load_der_x509_csr(datos)
        except ValueError:
            print(f"\nError: '{ruta}' no es una solicitud CSR válida.")
            sys.exit(1)

    tamano = getattr(csr.public_key(), "key_size", "desconocido")
    hash_firma = csr.signature_hash_algorithm
    nombre_hash = hash_firma.name.upper() if hash_firma else "desconocido"

    print("\nSolicitud de Firma de Certificado (PKCS #10):")
    print(f"Titular: {formatear_dn(csr.subject)}")
    print(f"Clave pública: RSA de {tamano} bits")
    print(f"Algoritmo de firma: {nombre_hash} con RSA")
    # La firma demuestra que quien hizo el CSR tiene la clave privada correspondiente
    if csr.is_signature_valid:
        print("Firma: válida")
    else:
        print("Firma: NO VÁLIDA (el archivo ha sido modificado)")


def comando_changealias():
    """Equivalente a 'keytool -changealias': cambia el nombre (alias) de la entrada del KeyStore."""
    if not os.path.exists(KEYSTORE_FILE):
        print(f"\nError: No existe el archivo KeyStore '{KEYSTORE_FILE}'. Ejecuta primero --genkey.")
        return

    password = getpass("Introduce la contraseña del KeyStore: ")
    if not password:
        print("\nError: La contraseña del KeyStore no puede estar vacía.")
        return

    clave_privada, certificado, alias_guardado = cargar_keystore(password)

    alias = input("Introduce el alias actual: ").strip()
    if alias.lower() != alias_guardado.lower():
        print(f"\nError: El alias '{alias}' no existe en el KeyStore.")
        return

    nuevo = input("Introduce el nuevo alias: ").strip()
    if not nuevo:
        print("\nError: El alias no puede estar vacío.")
        return
    if nuevo.lower() == alias_guardado.lower():
        print("\nError: El nuevo alias es igual al actual. No se ha cambiado nada.")
        return

    # Se vuelve a guardar la misma clave y certificado con el nuevo "friendly name"
    guardar_keystore(password, nuevo, clave_privada, certificado)
    print(f"\nAlias '{alias_guardado}' cambiado a '{nuevo}' correctamente.")


def main():
    global KEYSTORE_FILE

    parser = argparse.ArgumentParser(
        prog="mykeytool",
        description="Simulador CLI de Java Keytool desarrollado en Python.",
    )

    # --help / -h lo genera argparse automáticamente
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--genkey", action="store_true", help="Genera un par de claves y las almacena.")
    group.add_argument("--certreq", action="store_true", help="Genera un CSR a partir de una clave.")
    group.add_argument("--list", action="store_true", help="Lista las entradas del KeyStore.")
    group.add_argument("--delete", action="store_true", help="Elimina un alias del KeyStore.")
    group.add_argument("--storepasswd", action="store_true", help="Cambia la contraseña del KeyStore.")
    group.add_argument("--keypasswd", action="store_true", help="Cambia la contraseña de un alias.")
    group.add_argument("--exportcert", action="store_true", help="Exporta el certificado del alias a un archivo .cer.")
    group.add_argument("--printcert", action="store_true", help="Muestra el contenido de un archivo de certificado.")
    group.add_argument("--printcertreq", action="store_true", help="Muestra el contenido de un archivo CSR.")
    group.add_argument("--changealias", action="store_true", help="Cambia el nombre del alias.")

    parser.add_argument(
        "--keystore",
        default=KEYSTORE_FILE,
        metavar="ARCHIVO",
        help=f"Archivo .p12 del KeyStore (por defecto: {KEYSTORE_FILE}).",
    )

    args = parser.parse_args()
    KEYSTORE_FILE = args.keystore

    try:
        if args.genkey:
            comando_genkey()
        elif args.certreq:
            comando_certreq()
        elif args.list:
            comando_list()
        elif args.delete:
            comando_delete()
        elif args.storepasswd:
            comando_storepasswd()
        elif args.keypasswd:
            comando_keypasswd()
        elif args.exportcert:
            comando_exportcert()
        elif args.printcert:
            comando_printcert()
        elif args.printcertreq:
            comando_printcertreq()
        elif args.changealias:
            comando_changealias()
    except KeyboardInterrupt:
        print("\n\nOperación cancelada por el usuario.")
        sys.exit(1)


if __name__ == "__main__":
    main()