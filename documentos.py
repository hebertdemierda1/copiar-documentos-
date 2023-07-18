import os
import shutil
import hashlib
import tkinter as tk
from tkinter import filedialog
import logging

# Configurar el registro (logging)
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')

class CopiadorDocumentos(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Copiador y Renombrador de Documentos")
        self.geometry("600x250")
        self.crear_widgets()
        
    def crear_widgets(self):
        self.crear_widgets_origen()
        self.crear_widgets_destino()
        self.crear_widgets_tipo_documento()
        self.crear_boton_copiar()
        self.crear_boton_ver_log()

    def crear_widgets_origen(self):
        tk.Label(self, text="Carpeta de Origen:").grid(row=0, column=0)
        self.entry_origen = tk.Entry(self, width=50)
        self.entry_origen.grid(row=0, column=1)
        tk.Button(self, text="Seleccionar Carpeta", command=self.seleccionar_carpeta_origen).grid(row=0, column=2)

    def seleccionar_carpeta_origen(self):
        carpeta_origen = filedialog.askdirectory(title="Selecciona la Carpeta de Origen")
        if carpeta_origen:
            self.entry_origen.delete(0, tk.END)
            self.entry_origen.insert(0, carpeta_origen)

    def crear_widgets_destino(self):
        tk.Label(self, text="Carpeta de Destino:").grid(row=1, column=0)
        self.entry_destino = tk.Entry(self, width=50)
        self.entry_destino.grid(row=1, column=1)
        tk.Button(self, text="Seleccionar Carpeta", command=self.seleccionar_carpeta_destino).grid(row=1, column=2)

    def seleccionar_carpeta_destino(self):
        carpeta_destino = filedialog.askdirectory(title="Selecciona la Carpeta de Destino")
        if carpeta_destino:
            self.entry_destino.delete(0, tk.END)
            self.entry_destino.insert(0, carpeta_destino)

    def crear_widgets_tipo_documento(self):
        tk.Label(self, text="Seleccionar Tipo de Documento:").grid(row=2, column=0)
        self.variable_tipo_documento = tk.StringVar()
        self.variable_tipo_documento.set("Word")
        tipos_documentos = ["Word", "Excel", "PowerPoint"]
        combobox_tipo_documento = tk.OptionMenu(self, self.variable_tipo_documento, *tipos_documentos)
        combobox_tipo_documento.grid(row=2, column=1)

    def crear_boton_copiar(self):
        tk.Button(self, text="Copiar y Renombrar Documentos", command=self.copiar_y_renombrar_documentos).grid(row=3, column=0, columnspan=3)

    def crear_boton_ver_log(self):
        tk.Button(self, text="Ver Registro", command=self.ver_log).grid(row=4, column=0, columnspan=3)

    def copiar_y_renombrar_documentos(self):
        carpeta_origen = self.entry_origen.get()
        carpeta_destino = self.entry_destino.get()

        if not os.path.exists(carpeta_origen):
            self.mostrar_mensaje_error("La carpeta de origen no existe.")
            logging.error("La carpeta de origen no existe.")
            return

        if not os.path.exists(carpeta_destino):
            try:
                os.makedirs(carpeta_destino)
            except OSError:
                self.mostrar_mensaje_error("No se pudo crear la carpeta de destino.")
                logging.error("No se pudo crear la carpeta de destino.")
                return

        tipo_documento = self.variable_tipo_documento.get()
        extensiones_documentos = {
            "Word": (".doc", ".docx"),
            "Excel": (".xls", ".xlsx"),
            "PowerPoint": (".ppt", ".pptx")
        }

        documentos_copiados_hashes = {}  # Diccionario para almacenar el hash de los documentos copiados

        try:
            for nombre_archivo in os.listdir(carpeta_origen):
                for tipo_doc, extensiones in extensiones_documentos.items():
                    if tipo_documento == tipo_doc and nombre_archivo.lower().endswith(extensiones):
                        ruta_origen = os.path.join(carpeta_origen, nombre_archivo)
                        ruta_destino = os.path.join(carpeta_destino, nombre_archivo)

                        # Verificar si el archivo ya existe en el destino antes de copiar
                        if os.path.exists(ruta_destino):
                            self.mostrar_mensaje_info(f"El archivo {nombre_archivo} ya existe en el destino. Se omitirá.")
                            continue

                        try:
                            shutil.copy(ruta_origen, ruta_destino)
                        except shutil.Error:
                            self.mostrar_mensaje_error(f"Error al copiar {nombre_archivo}.")
                            logging.error(f"Error al copiar {nombre_archivo}.")
                            continue

                        # Calcular el hash del documento copiado y almacenarlo en el diccionario
                        try:
                            hash_archivo = self.calcular_hash_archivo(ruta_destino)
                            documentos_copiados_hashes[nombre_archivo] = hash_archivo
                        except Exception:
                            self.mostrar_mensaje_error(f"Error al calcular el hash para {nombre_archivo}.")
                            logging.error(f"Error al calcular el hash para {nombre_archivo}.")
                            continue

            # Mostrar los hashes de los documentos copiados
            if documentos_copiados_hashes:
                self.mostrar_mensaje_info("Documentos copiados y renombrados correctamente.")
                logging.info("Documentos copiados y renombrados correctamente.")
                self.mostrar_mensaje_info("Hashes de los documentos copiados:")
                for nombre_archivo, hash_archivo in documentos_copiados_hashes.items():
                    self.mostrar_mensaje_info(f"{nombre_archivo}: {hash_archivo}")
                    logging.info(f"{nombre_archivo}: {hash_archivo}")
            else:
                self.mostrar_mensaje_info("No se encontraron documentos para copiar.")

        except Exception as e:
            self.mostrar_mensaje_error(f"Ocurrió un error inesperado: {str(e)}")
            logging.error(f"Ocurrió un error inesperado: {str(e)}")

    @staticmethod
    def calcular_hash_archivo(ruta_archivo):
        sha256_hash = hashlib.sha256()
        with open(ruta_archivo, "rb") as archivo:
            for bloque_bytes in iter(lambda: archivo.read(4096), b""):
                sha256_hash.update(bloque_bytes)
        return sha256_hash.hexdigest()

    def ver_log(self):
        try:
            with open('app.log', 'r') as archivo_log:
                contenido_log = archivo_log.read()
            ventana_log = tk.Toplevel(self)
            ventana_log.title("Registro")
            ventana_log.geometry("800x400")
            texto_log = tk.Text(ventana_log, wrap=tk.WORD)
            texto_log.insert(tk.END, contenido_log)
            texto_log.pack(fill=tk.BOTH, expand=True)
        except FileNotFoundError:
            self.mostrar_mensaje_info("Registro no encontrado.")
        except Exception:
            self.mostrar_mensaje_error("Error al ver el registro.")

    @staticmethod
    def mostrar_mensaje_info(mensaje):
        tk.messagebox.showinfo("Información", mensaje)

    @staticmethod
    def mostrar_mensaje_error(mensaje):
        tk.messagebox.showerror("Error", mensaje)

if __name__ == "__main__":
    app = CopiadorDocumentos()
    app.mainloop()
