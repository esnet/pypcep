#!/usr/bin/python3

import struct
from enum import Enum


class PCEPMessageType(Enum):
    """PCEP Message Type."""
    # https://www.rfc-editor.org/rfc/rfc5440.html#section-6.1

    OPEN = 1
    KEEPALIVE = 2
    PATH_COMPUTATION_REQUEST = 3
    PATH_COMPUTATION_REPLY = 4
    NOTIFICATION = 5
    ERROR = 6
    CLOSE = 7
    LSP_STATE_REPORT = 10


class PCEPObjectClass(Enum):
    """PCEP Object Class."""

    OPEN = 1
    EXPLICIT_ROUTE = 7
    NOTIFICATION = 12
    CLOSE = 15


PCEP_OBJECT_FIELDS = {
    # https://www.rfc-editor.org/rfc/rfc5440.html#section-7.3
    # indexed on class, type
    (PCEPObjectClass.OPEN.value, 1): {
        'version': lambda obj_bytes: ((obj_bytes[4] & 0xe0) >> 5),
        'flags': lambda obj_bytes: (obj_bytes[4] & 0x1f),
        'keepalive': lambda obj_bytes: obj_bytes[5],
        'deadtime': lambda obj_bytes: obj_bytes[6],
        'sid': lambda obj_bytes: obj_bytes[7],
        'tlvs': lambda obj_bytes: parse_tlvs(obj_bytes[8:]),
    },
    (PCEPObjectClass.CLOSE.value, 1): {
        'reserved': lambda obj_bytes: obj_bytes[4:6],
        'flags': lambda obj_bytes: obj_bytes[6],
        'reason': lambda obj_bytes: obj_bytes[7],
    },
    (PCEPObjectClass.EXPLICIT_ROUTE.value, 1): {
    },
    (PCEPObjectClass.NOTIFICATION.value, 1): {
         'reserved': lambda obj_bytes: obj_bytes[4],
         'flags': lambda obj_bytes: obj_bytes[5],
         'value': lambda obj_bytes: obj_bytes[6],
         'type': lambda obj_bytes: obj_bytes[7],
    }
}


class PCEPParserException(Exception):
    pass


class PCEPMessage:

    def __init__(self, header, pcep_objs):
        self.header = header
        self.pcep_objs = pcep_objs

    def __str__(self):
        return f'PCEP Message header {self.header}, objects: {self.pcep_objs}'

    def __repr__(self):
        return self.__str__()


class PCEPHeader:

    def __init__(self, pcep_version, pcep_flags, pcep_type, pcep_len):
        self.pcep_version = pcep_version
        self.pcep_flags = pcep_flags
        self.pcep_type = pcep_type
        self.pcep_len = pcep_len

    def __str__(self):
        return f'PCEP Header version: {self.pcep_version}, flags: {self.pcep_flags}, type: {PCEPMessageType(self.pcep_type)}, len: {self.pcep_len}'

    def __repr__(self):
        return self.__str__()

    def serialized(self):
        pcep_version_flags = ((self.pcep_version & 0x7) << 5) | (self.pcep_flags & 0x31)
        return struct.pack('!BBH', pcep_version_flags, self.pcep_type, self.pcep_len)


class PCEPObj:

    def __init__(self, obj_class, obj_type, obj_fields):
        self.obj_class = obj_class
        self.obj_type = obj_type
        self.obj_fields = obj_fields

    def __str__(self):
        return f'PCEP object class: {self.obj_class}, type: {self.obj_type}, fields: {self.obj_fields}'

    def __repr__(self):
        return self.__str__()


class PCEPTLV:

    def __init__(self, tlv_type, tlv_payload):
        self.tlv_type = tlv_type
        self.tlv_payload = tlv_payload

    def __str__(self):
        return f'PCEP TLV type: {self.tlv_type} payload: {self.tlv_payload}'

    def __repr__(self):
        return self.__str__()

    def serialized(self):
        return struct.pack('!HH', self.tlv_type, len(self.tlv_payload)) + self.tlv_payload


def parse_header(header_bytes):
    """Parse PCEP header."""
    # https://www.rfc-editor.org/rfc/rfc5440.html#section-6.1
    pcep_flags, pcep_type, pcep_len = struct.unpack('!BBH', header_bytes)
    pcep_version = pcep_flags >> 5
    pcep_flags &= 0x1f
    if pcep_version != 1:
        raise PCEPParserException(f'Unsupported PCEP version: {pcep_version}')
    return PCEPHeader(pcep_version, pcep_flags, pcep_type, pcep_len)


def parse_tlvs(tlv_bytes):
    tlvs = []
    p = 0
    while p < len(tlv_bytes):
        tlv_type, tlv_len = struct.unpack('!HH', tlv_bytes[p:p+4])
        p += 4
        tlv_payload = tlv_bytes[p:p+tlv_len]
        tlvs.append(PCEPTLV(tlv_type, tlv_payload))
        p += tlv_len + (tlv_len % 4)
    return tlvs


def parse_object(p, obj_bytes):
    obj_class, obj_flags, obj_len = struct.unpack('!BBH', obj_bytes[p:p+4])
    obj_type = (obj_flags & 0xf0) >> 4
    if p + obj_len > len(obj_bytes):
        raise PCEPParserException('Invalid object length')
    obj_fields = {}
    field_parsers = PCEP_OBJECT_FIELDS.get((obj_class, obj_type), None)
    if field_parsers is not None:
        for field, parser in field_parsers.items():
            obj_fields[field] = parser(obj_bytes)
    return (PCEPObj(obj_class, obj_type, obj_fields), obj_len)


def parse_objects(obj_bytes):
    pcep_len = len(obj_bytes)
    objs = []
    p = 0
    while p < len(obj_bytes):
        obj, obj_len = parse_object(p, obj_bytes)
        objs.append(obj)
        p += obj_len
    if p != pcep_len:
        raise PCEPParserException('PCEP packet too short (missing object(s))')
    return objs


def parse_pcep(raw_bytes):
    if len(raw_bytes) < 4:
        raise PCEPParserException('PCEP packet too short')
    header = parse_header(raw_bytes[:4])
    pcep_objs = parse_objects(raw_bytes[4:])
    pcep_msg = PCEPMessage(header, pcep_objs)
    return pcep_msg
