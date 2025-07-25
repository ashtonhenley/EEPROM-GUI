MESSAGE_BINARY = 65535

CRC_POLY = 0x04C11DB7 # Here, we are using a 32 bit CRC polynomial

class CRC_Calculator:
    def __init__(self, CRC_POLY, MESSAGE_BINARY):
        self.CRC_POLY = CRC_POLY
        self.MESSAGE_BINARY = MESSAGE_BINARY
        self.MSB = self.highest_bit_position()
    def calculate_crc(self):
        # First, shift the message left by the highest bit position
        shifted_message = self.MESSAGE_BINARY << self.MSB
        print(shifted_message)
        # Then, we can divide the shifted message by the CRC polynomial
        crc = shifted_message
        while crc.bit_length() >= self.CRC_POLY.bit_length():
            crc ^= self.CRC_POLY << (crc.bit_length() - self.CRC_POLY.bit_length())
        print(crc)
    def highest_bit_position(self):
        if self.MESSAGE_BINARY == 0:
            return -1
        return self.MESSAGE_BINARY.bit_length() - 1

if __name__ == "__main__":
    crc_calc = CRC_Calculator(CRC_POLY, MESSAGE_BINARY)
    print(crc_calc.MSB)
    crc_calc.calculate_crc()
