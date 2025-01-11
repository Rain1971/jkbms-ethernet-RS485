#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import time
import binascii

HOST = "10.48.130.149"    # IP del Elfin
PORT = 8899              # Puerto TCP
READ_SIZE = 512          # Cantidad de bytes a leer por iteración
TIMEOUT_S = 1.0          # Timeout de socket

FRAME_SIZE = 300         # Según syssi: "the frame is 300 bytes"
PREAMBLE = b'\x55\xAA\xEB\x90'  # si la doc indica 55 AA EB 90

def calc_crc_syssi(data: bytes) -> int:
    """
    Ejemplo de CRC a lo 'syssi':
    Suma de bytes & 0xFF (o algo similar).
    Ajustar si la doc indica otra fórmula concreta.
    """
    # Por ejemplo, sum mod 256 de data:
    return sum(data) & 0xFF

def main():
    # 1) Crear socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT_S)
    print(f"Conectando a {HOST}:{PORT} ...")
    s.connect((HOST, PORT))
    print("Conectado.")

    frame_buffer = bytearray()  # Buffer para la "trama actual"
    read_buffer = bytearray()   # Buffer para data que llega en trozos

    try:
        while True:
            # 2) Recibir data
            try:
                data = s.recv(READ_SIZE)
            except socket.timeout:
                data = b''

            if data:
                print(f"\nRecibido (hex): {binascii.hexlify(data).decode('ascii')}")
                read_buffer.extend(data)

                # 3) Procesar read_buffer
                # Buscar "preambles" y ensamblar "frames" de 300 bytes
                i = 0
                while i < len(read_buffer):
                    # a) Buscar preámbulo 55 AA EB 90
                    if (len(frame_buffer) == 0
                        and i + 4 <= len(read_buffer)
                        and read_buffer[i:i+4] == PREAMBLE):
                        # "Flush" = iniciar nuevo frame
                        frame_buffer.clear()
                        # Copiamos la secuencia de 4 bytes
                        frame_buffer.extend(read_buffer[i:i+4])
                        i += 4
                    elif len(frame_buffer) > 0:
                        # Ya estamos en medio de armar un frame de 300 bytes
                        needed = FRAME_SIZE - len(frame_buffer)
                        # Cuántos bytes disponibles en read_buffer a partir de i
                        available = len(read_buffer) - i
                        # b) Tomar min(needed, available) y agregarlos
                        take = min(needed, available)
                        frame_buffer.extend(read_buffer[i:i+take])
                        i += take

                        # c) Si frame_buffer llega a 300
                        if len(frame_buffer) == FRAME_SIZE:
                            # Check CRC
                            # El doc syssi: "computed_crc = crc(raw, frame_size - 1)"
                            # frame_buffer[frame_size - 1] es el remote_crc
                            computed_crc = calc_crc_syssi(frame_buffer[:FRAME_SIZE - 1])
                            remote_crc = frame_buffer[FRAME_SIZE - 1]
                            if computed_crc == remote_crc:
                                # 4) Es un frame válido => imprimir
                                print("\n--- TRAMA COMPLETA (300 bytes) ---")
                                hex_frame = binascii.hexlify(frame_buffer).decode('ascii')
                                print(f"Trama: {hex_frame}")
                                print(f"computed_crc=0x{computed_crc:02X}, remote_crc=0x{remote_crc:02X}")
                            else:
                                print(f"\n--- TRAMA INVÁLIDA (CRC fail) ---")
                                print(f" computed=0x{computed_crc:02X}, remote=0x{remote_crc:02X}")
                                print(f" data: {binascii.hexlify(frame_buffer).decode('ascii')}")
                            # Limpia para siguiente frame
                            frame_buffer.clear()
                    else:
                        # Ni estamos armando frame ni coincidió preámbulo
                        i += 1

                # Descarta lo procesado en read_buffer
                if i > 0:
                    read_buffer = read_buffer[i:]
            else:
                time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nDetenido por usuario.")
    finally:
        s.close()
        print("Socket cerrado.")

if __name__ == "__main__":
    main()
