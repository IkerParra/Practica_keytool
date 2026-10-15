import argparse
import json
import os
import getpass
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography import x509
from cryptography.x509.oid import NameOID


class GestorMagatzem:
    # Format del fitxer (binari): MAGIC | sal (16 B) | nonce (12 B) | dades xifrades (AES-256-GCM)
    MAGIC = b"PYKS\x01"
    MIDA_SAL = 16
    MIDA_NONCE = 12
    ITERACIONS = 600_000

    def __init__(self, ruta_fitxer="keystore.ks"):
        self.ruta_fitxer = ruta_fitxer

    def _derivar_clau(self, contrasenya, sal):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=sal,
            iterations=self.ITERACIONS,
        )
        return kdf.derive(contrasenya.encode("utf-8"))

    def _carregar_dades(self, contrasenya):
        with open(self.ruta_fitxer, "rb") as fitxer:
            contingut = fitxer.read()

        if not contingut.startswith(self.MAGIC):
            raise ValueError("El fitxer no és un magatzem de claus vàlid.")

        inici = len(self.MAGIC)
        sal = contingut[inici:inici + self.MIDA_SAL]
        nonce = contingut[inici + self.MIDA_SAL:inici + self.MIDA_SAL + self.MIDA_NONCE]
        xifrat = contingut[inici + self.MIDA_SAL + self.MIDA_NONCE:]

        clau = self._derivar_clau(contrasenya, sal)
        try:
            # GCM verifica la integritat: si la contrasenya és incorrecta
            # o algú ha modificat el fitxer, el desxifratge falla.
            pla = AESGCM(clau).decrypt(nonce, xifrat, self.MAGIC)
        except InvalidTag:
            raise ValueError("La contrasenya del magatzem és incorrecta o el fitxer està corrupte.")

        return json.loads(pla.decode("utf-8"))

    def _desar_dades(self, dades, contrasenya):
        sal = secrets.token_bytes(self.MIDA_SAL)
        nonce = secrets.token_bytes(self.MIDA_NONCE)
        clau = self._derivar_clau(contrasenya, sal)
        pla = json.dumps(dades).encode("utf-8")
        xifrat = AESGCM(clau).encrypt(nonce, pla, self.MAGIC)

        with open(self.ruta_fitxer, "wb") as fitxer:
            fitxer.write(self.MAGIC + sal + nonce + xifrat)

    def _obrir_magatzem(self, contrasenya):
        if not os.path.exists(self.ruta_fitxer):
            dades = {"keys": {}}
            self._desar_dades(dades, contrasenya)
            return dades
        return self._carregar_dades(contrasenya)

    def _construir_dn(self, dades_dn):
        atributs = []
        if dades_dn.get("CN"):
            atributs.append(x509.NameAttribute(NameOID.COMMON_NAME, dades_dn["CN"]))
        if dades_dn.get("OU"):
            atributs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, dades_dn["OU"]))
        if dades_dn.get("O"):
            atributs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, dades_dn["O"]))
        if dades_dn.get("L"):
            atributs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, dades_dn["L"]))
        if dades_dn.get("ST"):
            atributs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, dades_dn["ST"]))
        if dades_dn.get("C"):
            atributs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, dades_dn["C"]))
        return x509.Name(atributs)

    def generar_claus(self, contrasenya, alies, dn_valors):
        if not alies.strip():
            raise ValueError("L'àlies no pot estar buit.")

        dades = self._obrir_magatzem(contrasenya)

        if alies in dades["keys"]:
            raise ValueError(f"L'àlies '{alies}' ja existeix.")

        clau_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        clau_publica = clau_privada.public_key()

        pem_privada = clau_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(contrasenya.encode('utf-8'))
        ).decode('utf-8')

        pem_publica = clau_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        cadena_dname = f"CN={dn_valors.get('CN','')}, OU={dn_valors.get('OU','')}, O={dn_valors.get('O','')}, L={dn_valors.get('L','')}, ST={dn_valors.get('ST','')}, C={dn_valors.get('C','')}"

        dades["keys"][alies] = {
            "private_key": pem_privada,
            "public_key": pem_publica,
            "dname": cadena_dname,
            "dn_dict": dn_valors
        }
        self._desar_dades(dades, contrasenya)

    def generar_csr(self, contrasenya, alies):
        dades = self._obrir_magatzem(contrasenya)

        if alies not in dades["keys"]:
            raise ValueError(f"L'àlies '{alies}' no existeix al magatzem.")

        dades_clau = dades["keys"][alies]
        clau_privada = serialization.load_pem_private_key(
            dades_clau["private_key"].encode('utf-8'),
            password=contrasenya.encode('utf-8')
        )

        nom_subjecte = self._construir_dn(dades_clau["dn_dict"])
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            nom_subjecte
        ).sign(clau_privada, hashes.SHA256())

        nom_fitxer_csr = f"{alies}.csr"
        with open(nom_fitxer_csr, "wb") as fitxer_csr:
            fitxer_csr.write(csr.public_bytes(serialization.Encoding.PEM))

        return nom_fitxer_csr


class InterficieCLI:
    def __init__(self):
        self.gestor = GestorMagatzem()

    def processar_genkeypair(self):
        contrasenya = getpass.getpass("Introdueix la contrasenya del magatzem de claus: ")
        alies = input("Introdueix l'àlies per a la nova clau: ")

        print("Introdueix les dades del titular (Distinguished Name):")
        dn_valors = {
            "CN": input("Nom i cognoms (CN): "),
            "OU": input("Unitat organitzativa (OU): "),
            "O": input("Organització (O): "),
            "L": input("Localitat o ciutat (L): "),
            "ST": input("Estat o província (ST): "),
            "C": input("Codi de país (C): ")
        }

        try:
            self.gestor.generar_claus(contrasenya, alies, dn_valors)
            print(f"Parell de claus per a l'àlies '{alies}' generat i desat correctament.")
        except Exception as error:
            print(f"Error: {str(error)}")

    def processar_certreq(self):
        contrasenya = getpass.getpass("Introdueix la contrasenya del magatzem de claus: ")
        alies = input("Introdueix l'àlies de la clau per generar el CSR: ")

        try:
            ruta_fitxer = self.gestor.generar_csr(contrasenya, alies)
            print(f"Sol·licitud de signatura de certificat (CSR) exportada a '{ruta_fitxer}'.")
        except Exception as error:
            print(f"Error: {str(error)}")


def main():
    parser = argparse.ArgumentParser(
        description="Simulació de la utilitat Java Keytool en Python.",
        add_help=True
    )

    parser.add_argument(
        '--genkeypair',
        action='store_true',
        help="Genera un parell de claus RSA de 2048 bits i el desa al magatzem."
    )

    parser.add_argument(
        '--certreq',
        action='store_true',
        help="Genera una sol·licitud de signatura de certificat (CSR) en format PEM."
    )

    args = parser.parse_args()
    interficie = InterficieCLI()

    if args.genkeypair:
        interficie.processar_genkeypair()
    elif args.certreq:
        interficie.processar_certreq()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()