#!/usr/bin/python3

import unittest
from pypcep.pcep_parser import parse_pcep, parse_tlvs, PCEPTLV, PCEPMessageType


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

PCEP_CLOSE_MSG = [
    '0x20', '0x07', '0x00', '0x0c', '0x0f', '0x10', '0x00', '0x08',
    '0x00', '0x00', '0x00', '0x02']

PCEP_KEEPALIVE_MSG = [
    '0x20', '0x02', '0x00', '0x04']

PCEP_NOTIFICATION_MSG = [
    '0x20', '0x05', '0x00', '0x0c', '0x0c', '0x10', '0x00', '0x08',
    '0x00', '0x00', '0x02', '0x01']

PCEP_LSP_STATE_REPORT_MSG = [
    '0x20', '0x0a', '0x00', '0x10', '0x20', '0x12', '0x00', '0x08',
    '0x00', '0x00', '0x00', '0x00', '0x07', '0x10', '0x00', '0x04']


class ParsePCEPTestCase(unittest.TestCase):

    def _test_bytes(self, msg):
        return bytes([int(i, 16) for i in msg])

    def test_parse_tlv(self):
        test_tlv = PCEPTLV(123, 'abcd'.encode('utf-8'))
        serialized_tlv = test_tlv.serialized()
        parsed_tlvs = parse_tlvs(serialized_tlv)
        self.assertEqual(1, len(parsed_tlvs))
        parsed_test_tlv = parsed_tlvs[0]
        self.assertEqual(serialized_tlv, parsed_test_tlv.serialized())

    def test_parse_keepalive(self):
        keepalive_msg_bytes = self._test_bytes(PCEP_KEEPALIVE_MSG)
        keepalive_msg = parse_pcep(keepalive_msg_bytes)
        parsed_header = keepalive_msg.header
        serialized_header = parsed_header.serialized()
        self.assertEqual(serialized_header, keepalive_msg_bytes[:len(serialized_header)])
        self.assertEqual(1, keepalive_msg.header.pcep_version)
        self.assertEqual(PCEPMessageType.KEEPALIVE, PCEPMessageType(keepalive_msg.header.pcep_type))

    def test_parse_open(self):
        open_msg_bytes = self._test_bytes(PCEP_OPEN_MSG)
        open_msg = parse_pcep(open_msg_bytes)
        self.assertEqual(1, open_msg.header.pcep_version)
        self.assertEqual(PCEPMessageType.OPEN, PCEPMessageType(open_msg.header.pcep_type))
        objs = open_msg.pcep_objs
        self.assertEqual(1, len(objs))
        obj = objs[0]
        self.assertEqual(1, obj.obj_fields['version'])
        self.assertEqual(1, obj.obj_fields['sid'])
        self.assertEqual(30, obj.obj_fields['keepalive'])
        self.assertEqual(120, obj.obj_fields['deadtime'])
        tlvs = obj.obj_fields['tlvs']
        self.assertEqual(7, len(tlvs))

    def test_parse_close(self):
        close_msg_bytes = self._test_bytes(PCEP_CLOSE_MSG)
        close_msg = parse_pcep(close_msg_bytes)
        self.assertEqual(1, close_msg.header.pcep_version)
        self.assertEqual(PCEPMessageType.CLOSE, PCEPMessageType(close_msg.header.pcep_type))
        self.assertEqual(2, close_msg.pcep_objs[0].obj_fields['reason'])

    def test_parse_notification(self):
        notification_msg_bytes = self._test_bytes(PCEP_NOTIFICATION_MSG)
        notification_msg = parse_pcep(notification_msg_bytes)
        self.assertEqual(1, notification_msg.header.pcep_version)
        self.assertEqual(PCEPMessageType.NOTIFICATION, PCEPMessageType(notification_msg.header.pcep_type))
        self.assertEqual(0, notification_msg.pcep_objs[0].obj_fields['reserved'])

    def test_parse_lsp_state_report(self):
        lsp_state_report_msg_bytes = self._test_bytes(PCEP_LSP_STATE_REPORT_MSG)
        lsp_state_report_msg = parse_pcep(lsp_state_report_msg_bytes)
        self.assertEqual(1, lsp_state_report_msg.header.pcep_version)
        self.assertEqual(PCEPMessageType.LSP_STATE_REPORT, PCEPMessageType(lsp_state_report_msg.header.pcep_type))
