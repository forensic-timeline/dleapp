import unittest
import struct
from scripts.artifacts.DjiDat import check_sum, DATRecord

class TetsDJIparser(unittest.TestCase):
    def test_checksum_accuracy(self):
        """
        Validate bit shifting algorithm and XOR on CRC.
        Byte b'\x55\x10\x00\x00' represent standard header with 
        Magic Byte (0x55) and record length 16 byte (0x10).
        """
        header_bytes = b'\x55\x10\x00\x00'
        expected_value = 43806
        computed = check_sum(header_bytes)
        
        self.assertEqual(computed, expected_value, f"[ERROR] Expected {expected_value}, got {computed}")
        
    def dat_test_record_instantiation(self):
        """
        Validate information extraction from raw byte block using struck.unpack
        Construct byte to represent:
        - Start offset: 0
        - Magic byte: 0x55
        - Record length: 16 byte(0x10)
        - Record type: 1 (0x01 0x00 pada offset 4-5)
        - Ticket number: 10 (0x0A 0x00 0x00 0x00 on offset 6-9)
        """
        
        raw_record = b'\x55\x10\x00\x00\x01\x00\x0A\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        start_position = 0
        record_length = 16
        
        object_record = DATRecord(raw_record, start_position, record_length)
        
        self.assertEqual(object_record.start, 0)
        self.assertEqual(object_record.len, 16)
        self.assertEqual(object_record.type, 1, "Extraction for Little-Endian record type failed")
        self.assertEqual(object_record.ticket_no, 10, "Extraction for 4 byte ticket number ")
        
        