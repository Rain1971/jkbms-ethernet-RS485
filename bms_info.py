#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import time
import binascii
import sys
import logging
import json

# ANSI color codes para resaltar min y max
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_RESET = "\033[0m"

# Parámetros BLE JK-BMS (basado en syssi)
FRAME_SIZE = 300

# Tipos de frame
RECORD_TYPE_SETTINGS = 0x01
RECORD_TYPE_DATA = 0x02
RECORD_TYPE_INFO = 0x03

def load_config(config_file='config.json'):
    """Carga la configuración JSON (ip, port, frame_header...)."""
    with open(config_file, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    # Convierte la cabecera hex a bytes
    cfg['communication']['frame_header'] = bytes.fromhex(cfg['communication']['frame_header'])
    return cfg

def config_logger(config):
    """Configura logger a fichero y consola."""
    logger = logging.getLogger("jk_bms_logger")
    log_level = getattr(logging, config['logging']['level'])
    logger.setLevel(log_level)

    formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    file_handler = logging.FileHandler(config['logging']['filename'], mode='w', encoding='utf-8')
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

def crc_syssi(data: bytes) -> int:
    """Cálculo de CRC (1 byte) estilo syssi: sum(data) & 0xFF."""
    return sum(data) & 0xFF

def get_16bit_le(frame: bytes, index: int) -> int:
    """Obtiene un valor de 16 bits en little endian desde el frame."""
    return frame[index] | (frame[index + 1] << 8)

def get_32bit_le(frame: bytes, index: int) -> int:
    """Obtiene un valor de 32 bits en little endian desde el frame."""
    return (frame[index] |
            (frame[index + 1] << 8) |
            (frame[index + 2] << 16) |
            (frame[index + 3] << 24))

def check_bit(byte_val, bit_pos):
    """Chequea si un bit específico está activo en un byte."""
    return (byte_val & (1 << bit_pos)) != 0

# -------------------------
# PARSE: FRAME TYPE = 0x02
# -------------------------
def get_16bit_le(frame, offset):
    return frame[offset] | (frame[offset + 1] << 8)

def get_32bit_le(frame, offset):
    return frame[offset] | (frame[offset + 1] << 8) | (frame[offset + 2] << 16) | (frame[offset + 3] << 24)

def parse_data_frame(frame: bytes, logger):
    """
    frame_type=0x02 => celdas, temps, voltaje total, potencias, alarmas, resistencias, etc.
    Ajustado para 24 celdas.
    Los offsets y cálculos se basan en la función C++ proporcionada.
    """
    try:
        # 1. Celdas (24 celdas, 2 bytes cada una, little endian)
        cell_count = 24
        cell_available = 16
        offset_cells = 6
        cell_voltages = []
        for i in range(cell_count):
            raw_mv = get_16bit_le(frame, offset_cells + i * 2)
            cell_voltages.append(raw_mv / 1000.0)  # Convertir de mV a V
            if i >= cell_available-1:
                break

        # 2. Temperaturas (2 sensores, 2 bytes cada uno, little endian)
        offset_temps = offset_cells + cell_count * 2
        temp1_raw = get_16bit_le(frame, offset_temps)
        temp2_raw = get_16bit_le(frame, offset_temps + 2)
        temp1 = temp1_raw / 10.0  # Convertir de decimas de °C a °C
        temp2 = temp2_raw / 10.0

        # 3. Total Voltage Sensor (4 bytes, little endian)
        offset_total_voltage = offset_temps + 4
        total_voltage_raw = get_32bit_le(frame, offset_total_voltage)
        total_voltage = total_voltage_raw / 1000.0

        # 4. Current Sensor (4 bytes, little endian, signed)
        offset_current = offset_total_voltage + 4
        current_raw = get_32bit_le(frame, offset_current)
        if current_raw >= 0x80000000:
            current_raw -= 0x100000000
        current_a = current_raw / 1000.0

        # 5. Power Sensor (4 bytes, little endian)
        offset_power = offset_current + 4
        power_raw = get_32bit_le(frame, offset_power)
        power_kw = power_raw / 1000.0

        # 6. Charging Power Sensor (4 bytes, little endian)
        offset_charging_power = offset_power + 4
        charging_power_raw = get_32bit_le(frame, offset_charging_power)
        charging_power_kw = charging_power_raw / 1000.0

        # 7. Discharging Power Sensor (4 bytes, little endian)
        offset_discharging_power = offset_charging_power + 4
        discharging_power_raw = get_32bit_le(frame, offset_discharging_power)
        discharging_power_kw = discharging_power_raw / 1000.0

        # 8. Resistencias internas (24 celdas, 2 bytes cada una, little endian)
        offset_resistances = offset_discharging_power + 6
        internal_resistances = []
        for i in range(cell_count):
            resistance_raw = get_16bit_le(frame, offset_resistances + i * 2)
            internal_resistances.append(resistance_raw / 1000.0)
            if i >= cell_available-1:
                break


        # 9. System Alarms (1 byte)
        offset_alarms = offset_resistances + cell_count * 2
        system_alarms = frame[offset_alarms]

        # 10. Battery Address (asumiendo que está en el byte 270)
        battery_address = frame[270] if len(frame) > 270 else None

        data = {
            "battery_address": battery_address,
            "cell_voltages": cell_voltages,
            "temp1": temp1,
            "temp2": temp2,
            "total_voltage_sensor": total_voltage,
            "current_sensor": current_a,
            "power_sensor": power_kw,
            "charging_power_sensor": charging_power_kw,
            "discharging_power_sensor": discharging_power_kw,
            "internal_resistances": internal_resistances,
            "system_alarms": system_alarms,
        }

        return data

    except Exception as e:
        logger.error(f"Error durante el parsing: {e}", exc_info=True)
        return None


# -------------------------
# PARSE: FRAME TYPE = 0x01
# -------------------------
def parse_settings_frame(frame: bytes, logger):
    """
    frame_type=0x01 => Ajustes BMS.
    Extrae todos los ajustes según la función C++ proporcionada.
    """

    data = {}

    # 1. Smart Sleep Voltage (4 bytes, little endian)
    data['smart_sleep_voltage'] = get_32bit_le(frame, 6) * 0.001  # V

    # 2. Cell UVP (Undervoltage Protection) (4 bytes, little endian)
    data['cell_uvp'] = get_32bit_le(frame, 10) * 0.001  # V

    # 3. Cell UVPR (Undervoltage Protection Recovery) (4 bytes, little endian)
    data['cell_uvpr'] = get_32bit_le(frame, 14) * 0.001  # V

    # 4. Cell OVP (Overvoltage Protection) (4 bytes, little endian)
    data['cell_ovp'] = get_32bit_le(frame, 18) * 0.001  # V

    # 5. Cell OVPR (Overvoltage Protection Recovery) (4 bytes, little endian)
    data['cell_ovpr'] = get_32bit_le(frame, 22) * 0.001  # V

    # 6. Balance Trigger Voltage (4 bytes, little endian)
    data['balance_trigger_voltage'] = get_32bit_le(frame, 26) * 0.001  # V

    # 7. SOC 100% Voltage (4 bytes, little endian)
    data['soc_100_voltage'] = get_32bit_le(frame, 30) * 0.001  # V

    # 8. SOC 0% Voltage (4 bytes, little endian)
    data['soc_0_voltage'] = get_32bit_le(frame, 34) * 0.001  # V

    # 9. Voltage Cell Request Charge Voltage [RCV] (4 bytes, little endian)
    data['voltage_cell_request_charge_voltage'] = get_32bit_le(frame, 38) * 0.001  # V

    # 10. Voltage Cell Request Float Voltage [RFV] (4 bytes, little endian)
    data['voltage_cell_request_float_voltage'] = get_32bit_le(frame, 42) * 0.001  # V

    # 11. Power Off Voltage (4 bytes, little endian)
    data['power_off_voltage'] = get_32bit_le(frame, 46) * 0.001  # V

    # 12. Max Charge Current (4 bytes, little endian)
    data['max_charge_current'] = get_32bit_le(frame, 50) * 0.001  # A

    # 13. Charge OCP Delay (4 bytes, little endian)
    data['charge_ocp_delay'] = get_32bit_le(frame, 54)  # s

    # 14. Charge OCP Recovery Time (4 bytes, little endian)
    data['charge_ocp_recovery_time'] = get_32bit_le(frame, 58)  # s

    # 15. Max Discharge Current (4 bytes, little endian)
    data['max_discharge_current'] = get_32bit_le(frame, 62) * 0.001  # A

    # 16. Discharge OCP Delay (4 bytes, little endian)
    data['discharge_ocp_delay'] = get_32bit_le(frame, 66)  # s

    # 17. Discharge OCP Recovery Time (4 bytes, little endian)
    data['discharge_ocp_recovery_time'] = get_32bit_le(frame, 70)  # s

    # 18. Short Circuit Protection Recovery Time (4 bytes, little endian)
    data['short_circuit_protection_recovery_time'] = get_32bit_le(frame, 74)  # s

    # 19. Max Balance Current (4 bytes, little endian)
    data['max_balance_current'] = get_32bit_le(frame, 78) * 0.001  # A

    # 20. Charge OTP (Overtemperature Protection) (4 bytes, little endian)
    data['charge_otp'] = get_32bit_le(frame, 82) * 0.1  # °C

    # 21. Charge OTP Recovery (4 bytes, little endian)
    data['charge_otp_recovery'] = get_32bit_le(frame, 86) * 0.1  # °C

    # 22. Discharge OTP (Overtemperature Protection) (4 bytes, little endian)
    data['discharge_otp'] = get_32bit_le(frame, 90) * 0.1  # °C

    # 23. Discharge OTP Recovery (4 bytes, little endian)
    data['discharge_otp_recovery'] = get_32bit_le(frame, 94) * 0.1  # °C

    # 24. Charge UTP (Undertemperature Protection) (4 bytes, little endian)
    data['charge_utp'] = get_32bit_le(frame, 98) * 0.1  # °C

    # 25. Charge UTP Recovery (4 bytes, little endian)
    data['charge_utp_recovery'] = get_32bit_le(frame, 102) * 0.1  # °C

    # 26. MOS OTP (Overtemperature Protection) (4 bytes, little endian)
    data['mos_otp'] = get_32bit_le(frame, 106) * 0.1  # °C

    # 27. MOS OTP Recovery (4 bytes, little endian)
    data['mos_otp_recovery'] = get_32bit_le(frame, 110) * 0.1  # °C

    # 28. Cell Count (4 bytes, little endian)
    data['cell_count'] = get_32bit_le(frame, 114)

    # 29. Charge Switch (4 bytes, little endian)
    data['charge_switch'] = bool(get_32bit_le(frame, 118))

    # 30. Discharge Switch (4 bytes, little endian)
    data['discharge_switch'] = bool(get_32bit_le(frame, 122))

    # 31. Balancer Switch (4 bytes, little endian)
    data['balancer_switch'] = bool(get_32bit_le(frame, 126))

    # 32. Nominal Battery Capacity (4 bytes, little endian)
    data['nominal_battery_capacity'] = get_32bit_le(frame, 130) * 0.001  # Ah

    # 33. SCP Delay (Short Circuit Protection Delay) (4 bytes, little endian)
    data['scp_delay'] = get_32bit_le(frame, 134)  # us

    # 34. Start Balance Voltage (4 bytes, little endian)
    data['start_balance_voltage'] = get_32bit_le(frame, 138) * 0.001  # V

    # 35. Con Wire Resistances (desde byte 142 en adelante, cada 4 bytes)
    # Suponiendo 24 resistencias
    internal_wire_resistances = []
    for i in range(24):
        resistance = get_32bit_le(frame, 142 + i*4) * 0.001  # Ohms
        internal_wire_resistances.append(resistance)
    data['con_wire_resistances'] = internal_wire_resistances

    # 36. Device Address (1 byte at 270)
    data['device_address'] = frame[270]  # Ajusta según tu estructura real

    # 37. Precharge Time (1 byte at 274)
    data['precharge_time'] = frame[274]  # s

    # 38. Bitmask Controls (2 bytes at 282)
    bitmask_controls = get_16bit_le(frame, 282)
    data['bitmask_controls'] = bitmask_controls

    # 39. Smart Sleep (1 byte at 286)
    data['smart_sleep'] = frame[286]  # h

    # 40. Data Field Enable Control 0 (1 byte at 287)
    data['data_field_enable_control_0'] = frame[287]

    # Puedes añadir más campos si es necesario, siguiendo el patrón

    return data

# -------------------------
# PARSE: FRAME TYPE = 0x03
# -------------------------
def parse_info_frame(frame: bytes, logger):
    """
    frame_type=0x03 => Info hardware/software.
    Extrae la información según la función C++ proporcionada.
    """
    data = {}

    # 1. Vendor ID (8 bytes, ASCII)
    data['vendor'] = frame[6:14].decode('ascii', errors='ignore').strip('\x00')

    # 2. Hardware Version (2 bytes, little endian)
    hw_major = get_16bit_le(frame, 20)
    data['hardware_version'] = f"{hw_major >> 8}.{hw_major & 0xFF}"

    # 3. Software Version (3 bytes, little endian)
    sw_major = frame[22]
    sw_minor = frame[23]
    sw_patch = frame[24]
    data['software_version'] = f"{sw_major}.{sw_minor}.{sw_patch}"

    # 4. Uptime (4 bytes, little endian)
    data['uptime_s'] = get_32bit_le(frame, 25)

    return data

def analyze_frame(frame: bytes, logger):
    """Verifica CRC y parsea la trama según el record_type."""
    if len(frame) < FRAME_SIZE:
        logger.debug("Frame incompleto (<300).")
        return

    # Verificar CRC
    computed_crc = crc_syssi(frame[:FRAME_SIZE-1])
    remote_crc = frame[FRAME_SIZE-1]

    if computed_crc != remote_crc:
        logger.info(f"CRC fail: computed=0x{computed_crc:02X}, remote=0x{remote_crc:02X}")
        return

    # Record Type y Frame Counter
    record_type = frame[4]
    frame_counter = frame[5]

    hex_frame = binascii.hexlify(frame).decode('ascii')
    logger.info(f"\nTrama BLE (300 bytes): {hex_frame}")
    logger.info(f"Record type=0x{record_type:02X}, frame_counter={frame_counter}")

    if record_type == RECORD_TYPE_DATA:  # 0x02
        data = parse_data_frame(frame, logger)
        if data:
            # Extraer e imprimir
            battery_address = data["battery_address"]
            celdas = data["cell_voltages"]
            t1 = data["temp1"]
            t2 = data["temp2"]
            tv_sensor = data["total_voltage_sensor"]
            current = data["current_sensor"]
            power = data["power_sensor"]
            charging_power = data["charging_power_sensor"]
            discharging_power = data["discharging_power_sensor"]
            alarms = data["system_alarms"]
            resistances = data["internal_resistances"]

            total_v = sum(celdas)
            min_v = min(celdas)
            max_v = max(celdas)
            avg_v = total_v / len(celdas)
            delta_v = max_v - min_v

            logger.info(f"  [Batería {battery_address}] Voltaje total (suma celdas): {total_v:.2f} V")
            logger.info(f"  [Batería {battery_address}] 'Total voltage sensor': {tv_sensor:.2f} V")
            logger.info(f"  [Batería {battery_address}] Corriente: {current:.2f} A")
            logger.info(f"  [Batería {battery_address}] Potencia: {power:.2f} kW")
            logger.info(f"  [Batería {battery_address}] Potencia de carga: {charging_power:.2f} kW")
            logger.info(f"  [Batería {battery_address}] Potencia de descarga: {discharging_power:.2f} kW")
            logger.info(f"  [Batería {battery_address}] Alarms: 0x{alarms:02X} => {'Sin alarmas' if alarms == 0 else 'Ver bits en documentación'}")

            logger.info(f"  [Batería {battery_address}] Voltaje medio celdas: {avg_v:.3f} V")
            logger.info(f"  [Batería {battery_address}] Delta celdas: {delta_v:.3f} V")
            logger.info(f"  [Batería {battery_address}] Temperatura #1: {t1:.1f}°C, #2: {t2:.1f}°C")

            logger.info(f"  [Batería {battery_address}] Celdas (16):")
            for i, v in enumerate(celdas, 1):
                if abs(v - min_v) < 1e-4:
                    logger.info(f"    Celda {i:2d}: {COLOR_GREEN}{v:.3f} V (MIN){COLOR_RESET}")
                elif abs(v - max_v) < 1e-4:
                    logger.info(f"    Celda {i:2d}: {COLOR_RED}{v:.3f} V (MAX){COLOR_RESET}")
                else:
                    logger.info(f"    Celda {i:2d}: {v:.3f} V")

            logger.info(f"  [Batería {battery_address}] Resistencias internas (16 celdas):")
            for i, r in enumerate(resistances, 1):
                logger.info(f"    R{i:2d}: {r:.3f} Ohms")

    elif record_type == RECORD_TYPE_SETTINGS:  # 0x01
        data = parse_settings_frame(frame, logger)
        if data:
            # Extraer e imprimir
            device_address = data.get('device_address', 'Unknown')
            logger.info(f"  [Batería {device_address}] Ajustes BMS:")
            logger.info(f"    Smart Sleep Voltage: {data.get('smart_sleep_voltage', 0):.3f} V")
            logger.info(f"    Cell UVP: {data.get('cell_uvp', 0):.3f} V")
            logger.info(f"    Cell UVPR: {data.get('cell_uvpr', 0):.3f} V")
            logger.info(f"    Cell OVP: {data.get('cell_ovp', 0):.3f} V")
            logger.info(f"    Cell OVPR: {data.get('cell_ovpr', 0):.3f} V")
            logger.info(f"    Balance Trigger Voltage: {data.get('balance_trigger_voltage', 0):.3f} V")
            logger.info(f"    SOC 100% Voltage: {data.get('soc_100_voltage', 0):.3f} V")
            logger.info(f"    SOC 0% Voltage: {data.get('soc_0_voltage', 0):.3f} V")
            logger.info(f"    Voltage Cell Request Charge Voltage [RCV]: {data.get('voltage_cell_request_charge_voltage', 0):.3f} V")
            logger.info(f"    Voltage Cell Request Float Voltage [RFV]: {data.get('voltage_cell_request_float_voltage', 0):.3f} V")
            logger.info(f"    Power Off Voltage: {data.get('power_off_voltage', 0):.3f} V")
            logger.info(f"    Max Charge Current: {data.get('max_charge_current', 0):.3f} A")
            logger.info(f"    Charge OCP Delay: {data.get('charge_ocp_delay', 0)} s")
            logger.info(f"    Charge OCP Recovery Time: {data.get('charge_ocp_recovery_time', 0)} s")
            logger.info(f"    Max Discharge Current: {data.get('max_discharge_current', 0):.3f} A")
            logger.info(f"    Discharge OCP Delay: {data.get('discharge_ocp_delay', 0)} s")
            logger.info(f"    Discharge OCP Recovery Time: {data.get('discharge_ocp_recovery_time', 0)} s")
            logger.info(f"    Short Circuit Protection Recovery Time: {data.get('short_circuit_protection_recovery_time', 0)} s")
            logger.info(f"    Max Balance Current: {data.get('max_balance_current', 0):.3f} A")
            logger.info(f"    Charge OTP: {data.get('charge_otp', 0):.1f} °C")
            logger.info(f"    Charge OTP Recovery: {data.get('charge_otp_recovery', 0):.1f} °C")
            logger.info(f"    Discharge OTP: {data.get('discharge_otp', 0):.1f} °C")
            logger.info(f"    Discharge OTP Recovery: {data.get('discharge_otp_recovery', 0):.1f} °C")
            logger.info(f"    Charge UTP: {data.get('charge_utp', 0):.1f} °C")
            logger.info(f"    Charge UTP Recovery: {data.get('charge_utp_recovery', 0):.1f} °C")
            logger.info(f"    MOS OTP: {data.get('mos_otp', 0):.1f} °C")
            logger.info(f"    MOS OTP Recovery: {data.get('mos_otp_recovery', 0):.1f} °C")
            logger.info(f"    Cell Count: {data.get('cell_count', 0)}")
            logger.info(f"    Charge Switch: {'ON' if data.get('charge_switch') else 'OFF'}")
            logger.info(f"    Discharge Switch: {'ON' if data.get('discharge_switch') else 'OFF'}")
            logger.info(f"    Balancer Switch: {'ON' if data.get('balancer_switch') else 'OFF'}")
            logger.info(f"    Nominal Battery Capacity: {data.get('nominal_battery_capacity', 0):.3f} Ah")
            logger.info(f"    SCP Delay: {data.get('scp_delay', 0)} us")
            logger.info(f"    Start Balance Voltage: {data.get('start_balance_voltage', 0):.3f} V")

            # Resistencias internas de cables
            resistances = data.get('con_wire_resistances', [])
            if resistances:
                logger.info(f"    Con Wire Resistances:")
                for i, r in enumerate(resistances, 1):
                    logger.info(f"      R{i:2d}: {r:.3f} Ohms")
            
            # Bitmask Controls
            bitmask = data.get('bitmask_controls', 0)
            logger.info(f"    Bitmask Controls: 0x{bitmask:04X}")
            logger.info(f"      Heating switch: {'ON' if check_bit(bitmask, 0) else 'OFF'}")
            logger.info(f"      Disable temperature sensors: {'ON' if check_bit(bitmask, 1) else 'OFF'}")
            logger.info(f"      GPS Heartbeat: {'ON' if check_bit(bitmask, 2) else 'OFF'}")
            logger.info(f"      Port switch: {'RS485' if check_bit(bitmask, 3) else 'CAN'}")
            logger.info(f"      Display always on: {'ON' if check_bit(bitmask, 4) else 'OFF'}")
            logger.info(f"      Special charger: {'ON' if check_bit(bitmask, 5) else 'OFF'}")
            logger.info(f"      Smart sleep: {'ON' if check_bit(bitmask, 6) else 'OFF'}")
            logger.info(f"      Disable PCL module: {'ON' if check_bit(bitmask, 7) else 'OFF'}")
            logger.info(f"      Timed stored data: {'ON' if check_bit(bitmask, 8) else 'OFF'}")
            logger.info(f"      Charging float mode: {'ON' if check_bit(bitmask, 9) else 'OFF'}")
            # Añade más bits según sea necesario

            # Smart Sleep and Data Field Enable Control
            smart_sleep = data.get('smart_sleep', 0)
            data_field_enable = data.get('data_field_enable_control_0', 0)
            logger.info(f"    Smart Sleep: {smart_sleep} h")
            logger.info(f"    Data Field Enable Control 0: {data_field_enable}")

    elif record_type == RECORD_TYPE_INFO:  # 0x03
        data = parse_info_frame(frame, logger)
        if data:
            logger.info("  Info hardware/software:")
            logger.info(f"    Vendor: {data['vendor']}")
            logger.info(f"    Hardware Version: {data['hardware_version']}")
            logger.info(f"    Software Version: {data['software_version']}")
            logger.info(f"    Uptime: {data['uptime_s']} s")

    else:
        logger.info(f"  Record type=0x{record_type:02X} no implementado")

def main():
    # Carga config y logger
    config = load_config()
    logger = config_logger(config)
    logger.info("INICIANDO CAPTURA (JK-BMS BLE por socket)")

    ip = config['communication']['ip']
    port = config['communication']['port']
    frame_header = config['communication']['frame_header']
    read_size = config['communication']['read_size']

    # 1) Conexión socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(config['communication']['timeout'])
    try:
        logger.info(f"Conectando a {ip}:{port}")
        s.connect((ip, port))
        logger.info("Conectado.")
    except Exception as e:
        logger.error(f"Error al conectar al socket: {e}")
        sys.exit(1)

    frame_buffer = bytearray()

    try:
        while True:
            # Leer chunk del socket
            try:
                chunk = s.recv(read_size)
            except socket.timeout:
                chunk = b''

            if chunk:
                logger.debug(f"Bytes recibidos (hex): {binascii.hexlify(chunk).decode('ascii')}")
                i = 0
                while i < len(chunk):
                    # Detectar cabecera => flush
                    if (len(frame_buffer) == 0
                        and i + len(frame_header) <= len(chunk)
                        and chunk[i:i+len(frame_header)] == frame_header):
                        frame_buffer.clear()
                        frame_buffer.extend(chunk[i : i+len(frame_header)])
                        i += len(frame_header)
                    elif len(frame_buffer) > 0:
                        needed = FRAME_SIZE - len(frame_buffer)
                        avail = len(chunk) - i
                        take = min(needed, avail)
                        frame_buffer.extend(chunk[i : i+take])
                        i += take

                        if len(frame_buffer) >= FRAME_SIZE:
                            # Tenemos 300 bytes
                            analyze_frame(bytes(frame_buffer), logger)
                            frame_buffer.clear()
                    else:
                        i += 1
            else:
                time.sleep(0.1)

    except KeyboardInterrupt:
        logger.info("CAPTURA DETENIDA POR USUARIO")
    except Exception as e:
        logger.error(f"Error durante la captura: {e}", exc_info=True)
    finally:
        s.close()
        logger.info("Socket cerrado.")
        sys.exit(0)

if __name__ == "__main__":
    main()
