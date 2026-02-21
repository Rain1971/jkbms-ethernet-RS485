#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import time
import binascii
import sys
import logging
import json
from typing import Optional, Dict, List
from influxdb import InfluxDBClient


class JKBattery:
    def __init__(self, address: int, debug: bool = False):
        self.address = address
        self.debug = debug
        
        # Frame type 0x02 (Data) attributes
        self.cell_voltages: List[float] = []
        self.temp1: float = 0.0
        self.temp2: float = 0.0
        self.total_voltage: float = 0.0
        self.current: float = 0.0
        self.power: float = 0.0
        self.charging_power: float = 0.0
        self.discharging_power: float = 0.0
        self.internal_resistances: List[float] = []
        self.system_alarms: int = 0
        self.state_of_charge: float = 0.0  # Añadido para capturar SOC
        
        # Frame type 0x01 (Settings) attributes
        self.smart_sleep_voltage: float = 0.0
        self.cell_uvp: float = 0.0             # Under Voltage Protection
        self.cell_uvpr: float = 0.0            # Under Voltage Protection Recovery
        self.cell_ovp: float = 0.0             # Over Voltage Protection
        self.cell_ovpr: float = 0.0            # Over Voltage Protection Recovery
        self.balance_trigger_voltage: float = 0.0
        self.soc_100_voltage: float = 0.0
        self.soc_0_voltage: float = 0.0
        self.cell_request_charge_voltage: float = 0.0  # RCV
        self.cell_request_float_voltage: float = 0.0   # RFV
        self.power_off_voltage: float = 0.0
        self.max_charge_current: float = 0.0
        self.charging_cicles: float = 0.0
        self.charge_ocp_delay: int = 0         # Over Current Protection delay
        self.charge_ocp_recovery_time: int = 0
        self.max_discharge_current: float = 0.0
        self.discharge_ocp_delay: int = 0
        self.discharge_ocp_recovery_time: int = 0
        self.short_circuit_protection_recovery_time: int = 0
        self.max_balance_current: float = 0.0
        self.charge_otp: float = 0.0           # Over Temperature Protection
        self.charge_otp_recovery: float = 0.0
        self.discharge_otp: float = 0.0
        self.discharge_otp_recovery: float = 0.0
        self.charge_utp: float = 0.0           # Under Temperature Protection
        self.charge_utp_recovery: float = 0.0
        self.mos_otp: float = 0.0              # MOS Over Temperature Protection
        self.mos_otp_recovery: float = 0.0
        self.cell_count: int = 0
        self.charge_switch: bool = False
        self.discharge_switch: bool = False
        self.balancer_switch: bool = False
        self.nominal_battery_capacity: float = 0.0
        self.scp_delay: int = 0                # Short Circuit Protection delay
        self.start_balance_voltage: float = 0.0
        self.wire_resistances: List[float] = []
        self.bitmask_controls: int = 0
        self.smart_sleep_hours: int = 0
        self.data_field_enable_control: int = 0
        
        # Frame type 0x03 (Info) attributes
        self.vendor: str = ""
        self.hardware_version: str = ""
        self.software_version: str = ""
        self.uptime: int = 0
        
        # Calculated statistics
        self.min_cell_voltage: float = 0.0
        self.max_cell_voltage: float = 0.0
        self.avg_cell_voltage: float = 0.0
        self.delta_cell_voltage: float = 0.0
        
    def update_from_data_frame(self, data: Dict) -> None:
        """Update battery attributes from data frame (type 0x02)"""
        self.cell_voltages = data["cell_voltages"]
        self.temp1 = data["temp1"]
        self.temp2 = data["temp2"]
        self.temp4 = data["temp4"]
        self.temp5 = data["temp5"]
        self.tempMosFET = data["tempMosFET"]
        self.total_voltage = data["total_voltage_sensor"]
        self.current = data["current_sensor"]
        self.power = data["power_sensor"]
        self.charging_cicles = data["charging_cicles"]
        self.charging_power = data["charging_power_sensor"]
        self.discharging_power = data["discharging_power_sensor"]
        self.internal_resistances = data["internal_resistances"]
        self.system_alarms = data["system_alarms"]
        self.state_of_charge = data["state_of_charge"]
        
        # Calculate statistics
        if self.cell_voltages:
            self.min_cell_voltage = min(self.cell_voltages)
            self.max_cell_voltage = max(self.cell_voltages)
            self.avg_cell_voltage = sum(self.cell_voltages) / len(self.cell_voltages)
            self.delta_cell_voltage = self.max_cell_voltage - self.min_cell_voltage
            
    def update_from_settings_frame(self, data: Dict) -> None:
        """Update battery settings from settings frame (type 0x01)"""
        self.smart_sleep_voltage = data.get('smart_sleep_voltage', 0.0)
        self.cell_uvp = data.get('cell_uvp', 0.0)
        self.cell_uvpr = data.get('cell_uvpr', 0.0)
        self.cell_ovp = data.get('cell_ovp', 0.0)
        self.cell_ovpr = data.get('cell_ovpr', 0.0)
        self.balance_trigger_voltage = data.get('balance_trigger_voltage', 0.0)
        self.soc_100_voltage = data.get('soc_100_voltage', 0.0)
        self.soc_0_voltage = data.get('soc_0_voltage', 0.0)
        self.cell_request_charge_voltage = data.get('voltage_cell_request_charge_voltage', 0.0)
        self.cell_request_float_voltage = data.get('voltage_cell_request_float_voltage', 0.0)
        self.power_off_voltage = data.get('power_off_voltage', 0.0)
        self.max_charge_current = data.get('max_charge_current', 0.0)
        self.charge_ocp_delay = data.get('charge_ocp_delay', 0)
        self.charge_ocp_recovery_time = data.get('charge_ocp_recovery_time', 0)
        self.max_discharge_current = data.get('max_discharge_current', 0.0)
        self.discharge_ocp_delay = data.get('discharge_ocp_delay', 0)
        self.discharge_ocp_recovery_time = data.get('discharge_ocp_recovery_time', 0)
        self.short_circuit_protection_recovery_time = data.get('short_circuit_protection_recovery_time', 0)
        self.max_balance_current = data.get('max_balance_current', 0.0)
        self.charge_otp = data.get('charge_otp', 0.0)
        self.charge_otp_recovery = data.get('charge_otp_recovery', 0.0)
        self.discharge_otp = data.get('discharge_otp', 0.0)
        self.discharge_otp_recovery = data.get('discharge_otp_recovery', 0.0)
        self.charge_utp = data.get('charge_utp', 0.0)
        self.charge_utp_recovery = data.get('charge_utp_recovery', 0.0)
        self.mos_otp = data.get('mos_otp', 0.0)
        self.mos_otp_recovery = data.get('mos_otp_recovery', 0.0)
        self.cell_count = data.get('cell_count', 0)
        self.charge_switch = data.get('charge_switch', False)
        self.discharge_switch = data.get('discharge_switch', False)
        self.balancer_switch = data.get('balancer_switch', False)
        self.nominal_battery_capacity = data.get('nominal_battery_capacity', 0.0)
        self.scp_delay = data.get('scp_delay', 0)
        self.start_balance_voltage = data.get('start_balance_voltage', 0.0)
        self.wire_resistances = data.get('con_wire_resistances', [])
        self.bitmask_controls = data.get('bitmask_controls', 0)
        self.smart_sleep_hours = data.get('smart_sleep', 0)
        self.data_field_enable_control = data.get('data_field_enable_control_0', 0)
        
    def update_from_info_frame(self, data: Dict) -> None:
        """Update battery info from info frame (type 0x03)"""
        self.vendor = data["vendor"]
        self.hardware_version = data["hardware_version"]
        self.software_version = data["software_version"]
        self.uptime = data["uptime_s"]

    @property
    def heating_switch(self) -> bool:
        return bool(self.bitmask_controls & (1 << 0))
        
    @property
    def temp_sensors_disabled(self) -> bool:
        return bool(self.bitmask_controls & (1 << 1))
        
    @property
    def gps_heartbeat(self) -> bool:
        return bool(self.bitmask_controls & (1 << 2))
        
    @property
    def port_type(self) -> str:
        return "RS485" if self.bitmask_controls & (1 << 3) else "CAN"
        
    @property
    def display_always_on(self) -> bool:
        return bool(self.bitmask_controls & (1 << 4))
        
    @property
    def special_charger(self) -> bool:
        return bool(self.bitmask_controls & (1 << 5))
        
    @property
    def smart_sleep_enabled(self) -> bool:
        return bool(self.bitmask_controls & (1 << 6))
        
    @property
    def pcl_module_disabled(self) -> bool:
        return bool(self.bitmask_controls & (1 << 7))
        
    @property
    def timed_stored_data(self) -> bool:
        return bool(self.bitmask_controls & (1 << 8))
        
    @property
    def charging_float_mode(self) -> bool:
        return bool(self.bitmask_controls & (1 << 9))
    
    def print_status(self, logger):
        """
        Print all battery data both to screen and log file.
        """
        logger.info(f"\n=== Battery Status (Battery Number: {self.address}) ===")
        print(f"\n=== Battery Status (Battery Number: {self.address}) ===")

        status_data = {
            "state_of_charge": self.state_of_charge,
            "Cell Voltages": self.cell_voltages,
            "Temperature 1": self.temp1,
            "Temperature 2": self.temp2,
            "Temperature 4": self.temp4,
            "Temperature 5": self.temp5,
            "Temperature MosFET": self.tempMosFET,
            "Total Voltage": self.total_voltage,
            "Current": self.current,
            "Power": self.power,
            "charging_cicles": self.charging_cicles,
            "Charging Power": self.charging_power,
            "Discharging Power": self.discharging_power,
            "Internal Resistances": self.internal_resistances,
            "charging_cicles": self.charging_cicles,
            "System Alarms": self.system_alarms,
            "Min Cell Voltage": self.min_cell_voltage,
            "Max Cell Voltage": self.max_cell_voltage,
            "Average Cell Voltage": self.avg_cell_voltage,
            "Delta Cell Voltage": self.delta_cell_voltage,
            "Smart Sleep Voltage": self.smart_sleep_voltage,
            "Cell UVP": self.cell_uvp,
            "Cell UVPR": self.cell_uvpr,
            "Cell OVP": self.cell_ovp,
            "Cell OVPR": self.cell_ovpr,
            "Balance Trigger Voltage": self.balance_trigger_voltage,
            "SOC 100% Voltage": self.soc_100_voltage,
            "SOC 0% Voltage": self.soc_0_voltage,
            "RCV": self.cell_request_charge_voltage,
            "RFV": self.cell_request_float_voltage,
            "Power Off Voltage": self.power_off_voltage,
            "Max Charge Current": self.max_charge_current,
            "Max Discharge Current": self.max_discharge_current,
            "Cell Count": self.cell_count,
            "Nominal Battery Capacity": self.nominal_battery_capacity,
            "Vendor": self.vendor,
            "Hardware Version": self.hardware_version,
            "Software Version": self.software_version,
            "Uptime (s)": self.uptime
        }

        for key, value in status_data.items():
            logger.info(f"{key}: {value}")
            print(f"{key}: {value}")

    def to_influx_points(self) -> List[Dict]:
        timestamp = int(time.time() * 1000000000)  # Nanosecond precision
        points = []
        
        # Prepara el diccionario de campos para el "status"
        status_fields = {
            "state_of_charge": float(self.state_of_charge),
            "temp1": float(self.temp1),
            "temp2": float(self.temp2),
            "temp4": float(self.temp4),
            "temp5": float(self.temp5),
            "temp_mosfet": float(self.tempMosFET),
            "total_voltage": float(self.total_voltage),
            "current": float(self.current),
            "power": float(self.power),
            "charging_cycles": float(self.charging_power),  # <-- verifica si en realidad querías "charging_cycles" = "charging_power"
            "charging_power": float(self.charging_power),
            "discharging_power": float(self.discharging_power),
            "system_alarms": float(self.system_alarms),
            "min_cell_voltage": float(self.min_cell_voltage),
            "max_cell_voltage": float(self.max_cell_voltage),
            "avg_cell_voltage": float(self.avg_cell_voltage),
            "delta_cell_voltage": float(self.delta_cell_voltage),
        }
        
        # Agrega cada celda como un campo diferente: cell_voltage_1, cell_voltage_2, ...
        for i, voltage in enumerate(self.cell_voltages, start=1):
            status_fields[f"cell_voltage_{i}"] = float(voltage)

        # Agrega cada resistencia interna como un campo diferente: internal_resistance_1, ...
        for i, resistance in enumerate(self.internal_resistances, start=1):
            status_fields[f"internal_resistance_{i}"] = float(resistance)

        # Crea el punto de "status"
        status_point = {
            "measurement": f"jk.batteries.{self.address}.status",
            "time": timestamp,
            "fields": status_fields
        }
        points.append(status_point)

        # Prepara el diccionario de campos para el "setup"
        setup_fields = {
            "smart_sleep_voltage": float(self.smart_sleep_voltage),
            "cell_uvp": float(self.cell_uvp),
            "cell_uvpr": float(self.cell_uvpr),
            "cell_ovp": float(self.cell_ovp),
            "cell_ovpr": float(self.cell_ovpr),
            "balance_trigger_voltage": float(self.balance_trigger_voltage),
            "soc_100_voltage": float(self.soc_100_voltage),
            "soc_0_voltage": float(self.soc_0_voltage),
            "rcv": float(self.cell_request_charge_voltage),
            "rfv": float(self.cell_request_float_voltage),
            "power_off_voltage": float(self.power_off_voltage),
            "max_charge_current": float(self.max_charge_current),
            "max_discharge_current": float(self.max_discharge_current),
            "cell_count": float(self.cell_count),
            "nominal_battery_capacity": float(self.nominal_battery_capacity),
            "vendor": str(self.vendor),
            "hardware_version": str(self.hardware_version),
            "software_version": str(self.software_version),
            "uptime": float(self.uptime)
        }

        # Crea el punto de "setup"
        setup_point = {
            "measurement": f"jk.batteries.{self.address}.setup",
            "time": timestamp,
            "fields": setup_fields
        }
        points.append(setup_point)

        return points

class BatteryMonitor:
    def __init__(self, config_file: str = 'config.json', debug: bool = False):
        self.config = self._load_config(config_file)
        self.logger = self._config_logger()
        self.batteries: Dict[int, JKBattery] = {}
        self.frame_buffer = bytearray()
        self.trama_bateria = -1
        self.debug = debug
        self.type2_frame_count = 0
        self.influx_client = None
        self.write_api = None
        self.influx_config = self._load_influx_config()
        self.influx_client = InfluxDBClient(
            host=self.influx_config['host'],
            port=self.influx_config['port'],
            username=self.influx_config['username'],
            password=self.influx_config['password'],
            database=self.influx_config['database']
        )

    def __del__(self):
        if isinstance(self.influx_client, InfluxDBClient):
            self.influx_client.close()

    def _load_influx_config(self) -> Dict:
        """Load InfluxDB configuration from secret.json"""
        try:
            with open('secret.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.error("secret.json not found. Please create it with InfluxDB configuration.")
            sys.exit(1)
            
    def _init_influx_client(self):
        """Initialize InfluxDB client"""
        try:
            # Change to use InfluxDBClient with username/password auth
            self.influx_client = InfluxDBClient(
                host=self.influx_config['url'].split('://')[1].split(':')[0],
                port=8086,
                username=self.influx_config['username'],
                password=self.influx_config['password'],
                database=self.influx_config['database']
            )
            # Test connection
            self.influx_client.ping()
            self.logger.info("InfluxDB client initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize InfluxDB client: {e}")
            sys.exit(1)
        
    def _write_to_influx(self, battery: JKBattery):
        """Write battery data to InfluxDB"""
        try:
            if not self.influx_client:
                self._init_influx_client()
                
            points = battery.to_influx_points()
            self.influx_client.write_points(
                points,
                time_precision='n'  # nanosecond precision
            )
            #self.logger.debug(f"Data written to InfluxDB for battery {battery.address}")
        except Exception as e:
            self.logger.error(f"Failed to write to InfluxDB: {e}")
        
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file"""
        with open(config_file, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        cfg['communication']['frame_header'] = bytes.fromhex(cfg['communication']['frame_header'])
        return cfg
        
    def _config_logger(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("jk_bms_logger")
        log_level = getattr(logging, self.config['logging']['level'])
        logger.setLevel(log_level)

        formatter = logging.Formatter(
            fmt='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        file_handler = logging.FileHandler(
            self.config['logging']['filename'], 
            mode='w', 
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
        
    def _get_or_create_battery(self, address: int) -> JKBattery:
        """Get existing battery or create new one if it doesn't exist"""
        if address not in self.batteries:
            self.batteries[address] = JKBattery(address)
        return self.batteries[address]
        
    def run(self):
        """Main monitoring loop"""
        self.logger.info("INICIANDO CAPTURA (JK-BMS BLE por socket)")
        
        # Create socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.config['communication']['timeout'])
        
        try:
            ip = self.config['communication']['ip']
            port = self.config['communication']['port']
            self.logger.info(f"Conectando a {ip}:{port}")
            s.connect((ip, port))
            self.logger.info("Conectado.")
            
            # Main loop
            while True:
                try:
                    chunk = s.recv(self.config['communication']['read_size'])
                except socket.timeout:
                    chunk = b''
                    
                if chunk:
                    self._process_chunk(chunk)
                else:
                    time.sleep(0.1)
                    
        except KeyboardInterrupt:
            self.logger.info("CAPTURA DETENIDA POR USUARIO")
        except Exception as e:
            self.logger.error(f"Error durante la captura: {e}", exc_info=True)
        finally:
            s.close()
            self.logger.info("Socket cerrado.")
            
            
            
            
    # -------------------------
    # PARSE: FRAME TYPE = 0x02
    # -------------------------
    def get_16bit_le(self, frame, offset):
        return frame[offset] | (frame[offset + 1] << 8)

    def get_32bit_le(self, frame, offset):
        return frame[offset] | (frame[offset + 1] << 8) | (frame[offset + 2] << 16) | (frame[offset + 3] << 24)

    def parse_data_frame(self, frame: bytes, logger, frame_counter):
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
            tmp_offset = 0
            for i in range(cell_count):
                tmp_offset = offset_cells + i * 2
                raw_mv = self.get_16bit_le(frame, tmp_offset)
                cell_voltages.append(raw_mv / 1000.0)  # Convertir de mV a V
                if i >= cell_available-1:
                    break

            # 2. Temperaturas (2 sensores, 2 bytes cada uno, little endian)
            # Ajuste de offsets de temperatura
            offset_temp1 = 162
            offset_temp2 = 164
            offset_temp4 = 256
            offset_temp5 = 258
            offset_temp_mosfet = 144

            # Leer las temperaturas
            temp1_raw = self.get_16bit_le(frame, offset_temp1)
            temp2_raw = self.get_16bit_le(frame, offset_temp2)
            temp4_raw = self.get_16bit_le(frame, offset_temp4)
            temp5_raw = self.get_16bit_le(frame, offset_temp5)
            tempMosFET_raw = self.get_16bit_le(frame, offset_temp_mosfet)

            temp1 = temp1_raw / 10.0  # Convertir de decimas de °C a °C
            temp2 = temp2_raw / 10.0
            temp4 = temp4_raw / 10.0
            temp5 = temp5_raw / 10.0
            tempMosFET = tempMosFET_raw / 10.0

            offset_temps = offset_cells + cell_count * 2
            # 3. Total Voltage Sensor (4 bytes, little endian)
            offset_total_voltage = 150
            total_voltage_raw = self.get_32bit_le(frame, offset_total_voltage)
            total_voltage = total_voltage_raw / 1000.0

            # 4. Current Sensor (4 bytes, little endian, signed)
            offset_current = offset_total_voltage + 8
            current_raw = self.get_32bit_le(frame, offset_current)
            if current_raw >= 0x80000000:
                current_raw -= 0x100000000
            current_a = current_raw / 1000.0

            power_kw = total_voltage * current_a
            
            charging_cicles = self.get_32bit_le(frame, 182)

            # 6. Charging Power Sensor (4 bytes, little endian)
            offset_charging_power = offset_current + 16
            charging_power_raw = self.get_32bit_le(frame, offset_charging_power)
            charging_power_kw = charging_power_raw / 1000.0

            # 7. Discharging Power Sensor (4 bytes, little endian)
            offset_discharging_power = offset_charging_power + 8
            discharging_power_raw = self.get_32bit_le(frame, offset_discharging_power)
            discharging_power_kw = discharging_power_raw / 1000.0

            # 8. Resistencias internas (24 celdas, 2 bytes cada una, little endian)
            offset_resistances = offset_discharging_power + 6
            offset_resistances = 80
            internal_resistances = []
            for i in range(cell_count):
                resistance_raw = self.get_16bit_le(frame, offset_resistances + i * 2)
                internal_resistances.append(resistance_raw / 1000.0)
                if i >= cell_available-1:
                    break


            # 9. System Alarms (1 byte)
            offset_alarms = offset_resistances + cell_count * 2
            system_alarms = frame[offset_alarms]

            # 10. Battery Address ( va por orden de direccion el mensaje en la linea )
            if self.trama_bateria == -1:
                if frame_counter == 0:
                    self.trama_bateria = 0
            else:
                if frame_counter == 0:
                    self.trama_bateria = 0
                else:
                    self.trama_bateria += 1
            
            battery_address = self.trama_bateria
            
            # Corrección: Ajuste del offset para state_of_charge
            offset_soc = 173
            if len(frame) > offset_soc:
                state_of_charge_raw = frame[offset_soc]
                state_of_charge = state_of_charge_raw
            else:
                logger.error("Offset fuera del rango de la trama")
                state_of_charge = 0.0

            data = {
                "battery_address": battery_address,
                "cell_voltages": cell_voltages,
                "temp1": temp1,
                "temp2": temp2,
                "temp4": temp4,
                "temp5": temp5,
                "tempMosFET": tempMosFET,
                "total_voltage_sensor": total_voltage,
                "current_sensor": current_a,
                "power_sensor": power_kw,
                "charging_power_sensor": charging_power_kw,
                "discharging_power_sensor": discharging_power_kw,
                "internal_resistances": internal_resistances,
                "system_alarms": system_alarms,
                "state_of_charge": state_of_charge,
                "charging_cicles": charging_cicles
            }

            return data

        except Exception as e:
            logger.error(f"Error durante el parsing: {e}", exc_info=True)
            return None


    # -------------------------
    # PARSE: FRAME TYPE = 0x01
    # -------------------------
    def parse_settings_frame(self, frame: bytes, logger):
        """
        frame_type=0x01 => Ajustes BMS.
        Extrae todos los ajustes según la función C++ proporcionada.
        """

        data = {}

        # 1. Smart Sleep Voltage (4 bytes, little endian)
        data['smart_sleep_voltage'] = self.get_32bit_le(frame, 6) * 0.001  # V

        # 2. Cell UVP (Undervoltage Protection) (4 bytes, little endian)
        data['cell_uvp'] = self.get_32bit_le(frame, 10) * 0.001  # V

        # 3. Cell UVPR (Undervoltage Protection Recovery) (4 bytes, little endian)
        data['cell_uvpr'] = self.get_32bit_le(frame, 14) * 0.001  # V

        # 4. Cell OVP (Overvoltage Protection) (4 bytes, little endian)
        data['cell_ovp'] = self.get_32bit_le(frame, 18) * 0.001  # V

        # 5. Cell OVPR (Overvoltage Protection Recovery) (4 bytes, little endian)
        data['cell_ovpr'] = self.get_32bit_le(frame, 22) * 0.001  # V

        # 6. Balance Trigger Voltage (4 bytes, little endian)
        data['balance_trigger_voltage'] = self.get_32bit_le(frame, 26) * 0.001  # V

        # 7. SOC 100% Voltage (4 bytes, little endian)
        data['soc_100_voltage'] = self.get_32bit_le(frame, 30) * 0.001  # V

        # 8. SOC 0% Voltage (4 bytes, little endian)
        data['soc_0_voltage'] = self.get_32bit_le(frame, 34) * 0.001  # V

        # 9. Voltage Cell Request Charge Voltage [RCV] (4 bytes, little endian)
        data['voltage_cell_request_charge_voltage'] = self.get_32bit_le(frame, 38) * 0.001  # V

        # 10. Voltage Cell Request Float Voltage [RFV] (4 bytes, little endian)
        data['voltage_cell_request_float_voltage'] = self.get_32bit_le(frame, 42) * 0.001  # V

        # 11. Power Off Voltage (4 bytes, little endian)
        data['power_off_voltage'] = self.get_32bit_le(frame, 46) * 0.001  # V

        # 12. Max Charge Current (4 bytes, little endian)
        data['max_charge_current'] = self.get_32bit_le(frame, 50) * 0.001  # A

        # 13. Charge OCP Delay (4 bytes, little endian)
        data['charge_ocp_delay'] = self.get_32bit_le(frame, 54)  # s

        # 14. Charge OCP Recovery Time (4 bytes, little endian)
        data['charge_ocp_recovery_time'] = self.get_32bit_le(frame, 58)  # s

        # 15. Max Discharge Current (4 bytes, little endian)
        data['max_discharge_current'] = self.get_32bit_le(frame, 62) * 0.001  # A

        # 16. Discharge OCP Delay (4 bytes, little endian)
        data['discharge_ocp_delay'] = self.get_32bit_le(frame, 66)  # s

        # 17. Discharge OCP Recovery Time (4 bytes, little endian)
        data['discharge_ocp_recovery_time'] = self.get_32bit_le(frame, 70)  # s

        # 18. Short Circuit Protection Recovery Time (4 bytes, little endian)
        data['short_circuit_protection_recovery_time'] = self.get_32bit_le(frame, 74)  # s

        # 19. Max Balance Current (4 bytes, little endian)
        data['max_balance_current'] = self.get_32bit_le(frame, 78) * 0.001  # A

        # 20. Charge OTP (Overtemperature Protection) (4 bytes, little endian)
        data['charge_otp'] = self.get_32bit_le(frame, 82) * 0.1  # °C

        # 21. Charge OTP Recovery (4 bytes, little endian)
        data['charge_otp_recovery'] = self.get_32bit_le(frame, 86) * 0.1  # °C

        # 22. Discharge OTP (Overtemperature Protection) (4 bytes, little endian)
        data['discharge_otp'] = self.get_32bit_le(frame, 90) * 0.1  # °C

        # 23. Discharge OTP Recovery (4 bytes, little endian)
        data['discharge_otp_recovery'] = self.get_32bit_le(frame, 94) * 0.1  # °C

        # 24. Charge UTP (Undertemperature Protection) (4 bytes, little endian)
        data['charge_utp'] = self.get_32bit_le(frame, 98) * 0.1  # °C

        # 25. Charge UTP Recovery (4 bytes, little endian)
        data['charge_utp_recovery'] = self.get_32bit_le(frame, 102) * 0.1  # °C

        # 26. MOS OTP (Overtemperature Protection) (4 bytes, little endian)
        data['mos_otp'] = self.get_32bit_le(frame, 106) * 0.1  # °C

        # 27. MOS OTP Recovery (4 bytes, little endian)
        data['mos_otp_recovery'] = self.get_32bit_le(frame, 110) * 0.1  # °C

        # 28. Cell Count (4 bytes, little endian)
        data['cell_count'] = self.get_32bit_le(frame, 114)

        # 29. Charge Switch (4 bytes, little endian)
        data['charge_switch'] = bool(self.get_32bit_le(frame, 118))

        # 30. Discharge Switch (4 bytes, little endian)
        data['discharge_switch'] = bool(self.get_32bit_le(frame, 122))

        # 31. Balancer Switch (4 bytes, little endian)
        data['balancer_switch'] = bool(self.get_32bit_le(frame, 126))

        # 32. Nominal Battery Capacity (4 bytes, little endian)
        data['nominal_battery_capacity'] = self.get_32bit_le(frame, 130) * 0.001  # Ah

        # 33. SCP Delay (Short Circuit Protection Delay) (4 bytes, little endian)
        data['scp_delay'] = self.get_32bit_le(frame, 134)  # us

        # 34. Start Balance Voltage (4 bytes, little endian)
        data['start_balance_voltage'] = self.get_32bit_le(frame, 138) * 0.001  # V

        # 35. Con Wire Resistances (desde byte 142 en adelante, cada 4 bytes)
        # Suponiendo 24 resistencias
        internal_wire_resistances = []
        for i in range(24):
            resistance = self.get_32bit_le(frame, 142 + i*4) * 0.001  # Ohms
            internal_wire_resistances.append(resistance)
        data['con_wire_resistances'] = internal_wire_resistances

        # 36. Device Address (1 byte at 270)
        data['device_address'] = frame[270]  # Ajusta según tu estructura real

        # 37. Precharge Time (1 byte at 274)
        data['precharge_time'] = frame[274]  # s

        # 38. Bitmask Controls (2 bytes at 282)
        bitmask_controls = self.get_16bit_le(frame, 282)
        data['bitmask_controls'] = bitmask_controls

        # 39. Smart Sleep (1 byte at 286)
        data['smart_sleep'] = frame[286]  # h

        # 40. Data Field Enable Control 0 (1 byte at 287)
        data['data_field_enable_control_0'] = frame[287]

        # Si el numero de bateria es > -1 logueo los datos capturados en esta función
        if data["device_address"] >= 0 and False:
            logger.info(f"\n\n=== Ajustes BMS (Batería Número: {data['device_address']}) ===")
            # solo logueo los datos de la bateria que se han capturado en esta función
            logger.info(f"Smart Sleep Voltage: {data['smart_sleep_voltage']} V")
            logger.info(f"Cell UVP: {data['cell_uvp']} V")
            logger.info(f"Cell UVPR: {data['cell_uvpr']} V")
            logger.info(f"Cell OVP: {data['cell_ovp']} V")
            logger.info(f"Cell OVPR: {data['cell_ovpr']} V")
            logger.info(f"Balance Trigger Voltage: {data['balance_trigger_voltage']} V")
            logger.info(f"SOC 100% Voltage: {data['soc_100_voltage']} V")
            logger.info(f"SOC 0% Voltage: {data['soc_0_voltage']} V")
            logger.info(f"RCV: {data['voltage_cell_request_charge_voltage']} V")
            logger.info(f"RFV: {data['voltage_cell_request_float_voltage']} V")
            logger.info(f"Power Off Voltage: {data['power_off_voltage']} V")
            logger.info(f"Max Charge Current: {data['max_charge_current']} A")
            logger.info(f"Charge OCP Delay: {data['charge_ocp_delay']} s")
            logger.info(f"Charge OCP Recovery Time: {data['charge_ocp_recovery_time']} s")
            logger.info(f"Max Discharge Current: {data['max_discharge_current']} A")
            logger.info(f"Discharge OCP Delay: {data['discharge_ocp_delay']} s")
            logger.info(f"Discharge OCP Recovery Time: {data['discharge_ocp_recovery_time']} s")
            logger.info(f"Short Circuit Protection Recovery Time: {data['short_circuit_protection_recovery_time']} s")
            logger.info(f"Max Balance Current: {data['max_balance_current']} A")
            logger.info(f"Charge OTP: {data['charge_otp']} °C")
            logger.info(f"Charge OTP Recovery: {data['charge_otp_recovery']} °C")
            logger.info(f"Discharge OTP: {data['discharge_otp']} °C")
            logger.info(f"Discharge OTP Recovery: {data['discharge_otp_recovery']} °C")
            logger.info(f"Charge UTP: {data['charge_utp']} °C")
            logger.info(f"Charge UTP Recovery: {data['charge_utp_recovery']} °C")
            logger.info(f"MOS OTP: {data['mos_otp']} °C")
            logger.info(f"MOS OTP Recovery: {data['mos_otp_recovery']} °C")
            logger.info(f"Cell Count: {data['cell_count']}")
            logger.info(f"Charge Switch: {data['charge_switch']}")
            logger.info(f"Discharge Switch: {data['discharge_switch']}")
            logger.info(f"Balancer Switch: {data['balancer_switch']}")
            logger.info(f"Nominal Battery Capacity: {data['nominal_battery_capacity']} Ah")
            logger.info(f"SCP Delay: {data['scp_delay']} us")
            logger.info(f"Start Balance Voltage: {data['start_balance_voltage']} V")
            logger.info(f"Con Wire Resistances: {data['con_wire_resistances']} Ohms")
            logger.info(f"Device Address: {data['device_address']}")
            logger.info(f"Precharge Time: {data['precharge_time']} s")
            logger.info(f"Bitmask Controls: {data['bitmask_controls']}")
            logger.info(f"Smart Sleep: {data['smart_sleep']} h")
            logger.info(f"Data Field Enable Control 0: {data['data_field_enable_control_0']}")
            
        
             

        return data

    # -------------------------
    # PARSE: FRAME TYPE = 0x03
    # -------------------------
    def parse_info_frame(self, frame: bytes, logger):
        """
        frame_type=0x03 => Info hardware/software.
        Extrae la información según la función C++ proporcionada.
        """
        data = {}

        # 1. Vendor ID (8 bytes, ASCII)
        data['vendor'] = frame[6:14].decode('ascii', errors='ignore').strip('\x00')

        # 2. Hardware Version (2 bytes, little endian)
        hw_major = self.get_16bit_le(frame, 20)
        data['hardware_version'] = f"{hw_major >> 8}.{hw_major & 0xFF}"

        # 3. Software Version (3 bytes, little endian)
        sw_major = frame[22]
        sw_minor = frame[23]
        sw_patch = frame[24]
        data['software_version'] = f"{sw_major}.{sw_minor}.{sw_patch}"

        # 4. Uptime (4 bytes, little endian)
        data['uptime_s'] = self.get_32bit_le(frame, 25)

        return data

    def _process_chunk(self, chunk: bytes):
        """Process received data chunk"""
        frame_header = self.config['communication']['frame_header']
        i = 0
        while i < len(chunk):
            # Detect header
            if (len(self.frame_buffer) == 0 and
                i + len(frame_header) <= len(chunk) and
                chunk[i:i+len(frame_header)] == frame_header):
                
                self.frame_buffer.clear()
                self.frame_buffer.extend(chunk[i:i+len(frame_header)])
                i += len(frame_header)
            elif len(self.frame_buffer) > 0:
                needed = 300 - len(self.frame_buffer)
                avail = len(chunk) - i
                take = min(needed, avail)
                self.frame_buffer.extend(chunk[i:i+take])
                i += take

                if len(self.frame_buffer) >= 300:
                    self._analyze_frame(bytes(self.frame_buffer))
                    self.frame_buffer.clear()
            else:
                i += 1
                
    def _analyze_frame(self, frame: bytes):
        """Analyze complete frame and update corresponding battery"""
        # Verify CRC
        computed_crc = sum(frame[:299]) & 0xFF
        remote_crc = frame[299]
        
        if computed_crc != remote_crc:
            self.logger.info(f"CRC fail: computed=0x{computed_crc:02X}, remote=0x{remote_crc:02X}")
            return
            
        record_type = frame[4]
        frame_counter = frame[5]
        
        hex_frame = binascii.hexlify(frame).decode('ascii')
        if self.debug:
            self.logger.info(f"\nTrama BLE (300 bytes): {hex_frame}")
            self.logger.info(f"Record type=0x{record_type:02X}, frame_counter={frame_counter}")
        
        # Import parsing functions from original code
        if record_type == 0x02:  # Data frame
            data = self.parse_data_frame(frame, self.logger, frame_counter)
            if data:
                battery = self._get_or_create_battery(data["battery_address"])
                battery.update_from_data_frame(data)
                #battery.print_status(self.logger)
                
                if self.type2_frame_count >= 8:
                    self._write_to_influx(battery)
                else:
                    self.type2_frame_count += 1
                
        elif record_type == 0x01:  # Settings frame
            data = self.parse_settings_frame(frame, self.logger)
            if data:
                battery = self._get_or_create_battery(data["device_address"])
                battery.update_from_settings_frame(data)
                
        elif record_type == 0x03:  # Info frame
            data = self.parse_info_frame(frame, self.logger)
            if data:
                # For info frame, we'll assume it's for battery 0 if we can't determine
                battery = self._get_or_create_battery(0)
                battery.update_from_info_frame(data)
        
def main():
    monitor = BatteryMonitor()
    monitor.run()

if __name__ == "__main__":
    main()