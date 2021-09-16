#!/usr/bin/python3

import unittest
from pypcep.pcep_parser import parse_pcep, PCEPMessageType


PCEP_OPEN_MSG = [
    '0x20', '0x01', '0x00', '0x50', '0x01', '0x10', '0x00', '0x4c',
    '0x20', '0x1e', '0x78', '0x01', '0x00', '0x10', '0x00', '0x04',
    '0x00', '0x00', '0x01', '0xc5', '0x00', '0x18', '0x00', '0x10',
    '0xfc', '0x01', '0xff', '0x00', '0x00', '0x00', '0x00', '0x00',
    '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00', '0x00',
    '0x00', '0x1a', '0x00', '0x04', '0x00', '0x00', '0x00', '0x0b',
    '0x00', '0x65', '0x00', '0x04', '0x00', '0x00', '0x00', '0x00',
    '0x00', '0x06', '0x00', '0x02', '0x00', '0x00', '0x00', '0x00',
    '0x00', '0x72', '0x00', '0x04', '0x00', '0x00', '0x00', '0x02',
    '0x00', '0x67', '0x00', '0x02', '0x00', '0x00', '0x00', '0x00']

PCEP_KEEPALIVE_MSG = [
    '0x20', '0x02', '0x00', '0x04']

PCEP_NOTIFICATION_MSG = [
    '0x20', '0x05', '0x00', '0x0c', '0x0c', '0x10', '0x00', '0x08',
    '0x00', '0x00', '0x02', '0x01']


class ParsePCEPTestCase(unittest.TestCase):

    def _test_bytes(self, msg):
        return bytes([int(i, 16) for i in msg])

    def test_parse_keepalive(self):
        keepalive_msg_bytes = self._test_bytes(PCEP_KEEPALIVE_MSG)
        keepalive_msg = parse_pcep(keepalive_msg_bytes)
        self.assertEqual(1, keepalive_msg.header.pcep_version)
        self.assertEqual(PCEPMessageType.KEEPALIVE, PCEPMessageType(keepalive_msg.header.pcep_type))

    def test_parse_open(self):
        open_msg_bytes = self._test_bytes(PCEP_OPEN_MSG)
        open_msg = parse_pcep(open_msg_bytes)
        self.assertEqual(1, open_msg.header.pcep_version)
        self.assertEqual(PCEPMessageType.OPEN, PCEPMessageType(open_msg.header.pcep_type))

    def test_parse_notification(self):
        notification_msg_bytes = self._test_bytes(PCEP_NOTIFICATION_MSG)
        notification_msg = parse_pcep(notification_msg_bytes)
        self.assertEqual(1, notification_msg.header.pcep_version)
        self.assertEqual(PCEPMessageType.NOTIFICATION, PCEPMessageType(notification_msg.header.pcep_type))

