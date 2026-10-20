from cryptography.hazmat.primitives import serialization, hashes
 
 

class GestorAlmacen:
 
    def _huella_sha256(self, pem_publica):
        """Huella SHA-256 de la clave pública (como la que muestra keytool -list)."""
        clave = serialization.load_pem_public_key(pem_publica.encode("utf-8"))
        der = clave.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        resumen = hashes.Hash(hashes.SHA256())
        resumen.update(der)
        return ":".join(f"{b:02X}" for b in resumen.finalize())
 
    def listar(self, contrasena):
        """Devuelve una lista con la información pública de cada entrada."""
        datos = self._abrir_almacen(contrasena)
        entradas = []
        for alias, entrada in datos["keys"].items():
            entradas.append({
                "alias": alias,
                "dname": entrada.get("dname", ""),
                "fecha_creacion": entrada.get("fecha_creacion", "desconocida"),
                "huella": self._huella_sha256(entrada["public_key"]),
            })
        return entradas
 
    def existe_alias(self, contrasena, alias):
        datos = self._abrir_almacen(contrasena)
        return alias in datos["keys"]
 
    def eliminar(self, contrasena, alias):
        datos = self._abrir_almacen(contrasena)
        if alias not in datos["keys"]:
            raise ValueError(f"El alias '{alias}' no existe en el almacén.")
        del datos["keys"][alias]
        self._guardar_datos(datos, contrasena)
 
 

class InterfazCLI:
 
    def procesar_list(self):
        """Equivalente a 'keytool -list'."""
        contrasena = self._pedir_contrasena()
 
        try:
            entradas = self.gestor.listar(contrasena)
        except Exception as error:
            print(f"Error: {error}")
            return
 
        if not entradas:
            print("\nEl almacén de claves está vacío.")
            return
 
        print(f"\nEl almacén de claves contiene {len(entradas)} entrada(s):")
        for entrada in entradas:
            print(f"\nAlias: {entrada['alias']}")
            print(f"Fecha de creación: {entrada['fecha_creacion']}")
            print("Tipo de entrada: PrivateKeyEntry")
            print(f"Titular: {entrada['dname']}")
            print(f"Huella de la clave pública (SHA-256): {entrada['huella']}")
 
    def procesar_delete(self):
        """Equivalente a 'keytool -delete'."""
        contrasena = self._pedir_contrasena()
        alias = input("Introduce el alias que quieres eliminar: ").strip()
 
        try:
            if not self.gestor.existe_alias(contrasena, alias):
                print(f"Error: El alias '{alias}' no existe en el almacén.")
                return
 
            confirmacion = input(
                f"¿Seguro que quieres eliminar '{alias}'? Esta acción no se puede deshacer (s/N): "
            ).strip().lower()
            if confirmacion != "s":
                print("Operación cancelada. No se ha eliminado nada.")
                return
 
            self.gestor.eliminar(contrasena, alias)
            print(f"Alias '{alias}' eliminado correctamente del almacén.")
        except Exception as error:
            print(f"Error: {error}")
 