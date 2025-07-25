# i2c_handler.py
from pyftdi.ftdi import Ftdi
from pyftdi import i2c
from pyftdi.i2c import I2cController
import time

class I2CHandler:
    def __init__(self, device_url, eeprom_address):
        self.device_url = device_url
        self.eeprom_address = eeprom_address
        self.ctrl = I2cController()  # Create an I2C controller
        self.ctrl.configure(self.device_url)  # Configure the controller with the FTDI device
        self.i2c_port = self.ctrl.get_port(self.eeprom_address)  # Get the I2C port for the EEPROM
        
    def write_data(self, data, mem_addr):
        # Write data to EEPROM at a certain address
        # Send one byte for the memory address and then the data bytes
        self.i2c_port.write([mem_addr >> 8, mem_addr & 0xFF] + list(data))
        print("Data written to EEPROM:", data)
        time.sleep(0.1)

    def read_data(self, mem_addr, length):
        # Read data from EEPROM at a certain address
        # Send one byte for the memory address and then read the given length of data

        self.i2c_port.write([mem_addr >> 8, mem_addr & 0xFF])
        data = self.i2c_port.read(length)
        print("Data read from EEPROM:", data)
        return data
    
class parse_data:
    def __init__(self, data):
        self.data = data

    def split(self):
        # data should be a list or bytes-like object of length 52
        assert len(self.data) == 52, "Data must be 52 bytes"
        result = {}
        idx = 0
        result['block1_12'] = self.data[idx:idx+12]
        idx += 12
        result['block2_10'] = self.data[idx:idx+10]
        idx += 10
        result['block3_2s'] = [self.data[idx+i:idx+i+2] for i in range(0, 18, 2)]  # 9 blocks of 2 bytes
        idx += 18
        result['block4_4'] = self.data[idx:idx+4]
        idx += 4
        result['block5_1s'] = [self.data[idx], self.data[idx+1], self.data[idx+2]]
        idx += 3
        result['ol_voltage_factor'] = self.data[idx]
        # Add CRC (last 4 bytes, little-endian)
        result['crc'] = self.data[idx:idx+4]
        return result
    
class convert_data:
    def __init__(self, data):
        self.data = data
    def to_ascii(self):
        for i in range(0,10,1):
            self.data[i] = chr(self.data[i])
        print("Converted data to ASCII:", self.data)
        for i in range(11,21,1):
            self.data[i] = chr(self.data[i])
        print("Converted data to ASCII:", self.data)