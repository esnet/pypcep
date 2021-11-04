#!/usr/bin/python3


import argparse
import asyncio
import binascii
import logging
import queue
from pcep_parser import PCEPParserException, parse_header, parse_pcep


class PCEPPCEServerProtocol(asyncio.Protocol):

    def __init__(self, keepalive_time_sec):
        self.keepalive_time_sec = keepalive_time_sec
        self.transport = None
        self.peername = None
        self.buffer = bytearray()
        self.alive = True
        self.receive_q = queue.Queue()
        self._schedule_keepalive()

    def connection_made(self, transport):
        peername = ':'.join([str(i) for i in transport.get_extra_info('peername')])
        logging.info('Connection from %s', peername)
        self.peername = peername
        self.transport = transport

    def data_received(self, data):
        self.buffer += data
        logging.debug('%u bytes received from %s, %u total: %s',
        len(data), self.peername, len(self.buffer), binascii.hexlify(data))
        while len(self.buffer) > 4:
            try:
                header = parse_header(self.buffer[:4])
                if len(self.buffer) < header.pcep_len:
                    logging.debug('need %u more bytes from %s',
                        header.pcep_len - len(self.buffer), self.peername)
                    break
                message = parse_pcep(self.buffer[:header.pcep_len])
                logging.info('received %s from %s', message, self.peername)
                self.receive_q.put(message)
                self.buffer = self.buffer[header.pcep_len:]
                continue
            except PCEPParserException as err:
                logging.error('%s from %s', err, self.peername)
                self._shutdown()
                break

    def _shutdown(self):
        self.alive = False
        self.transport.close()

    def connection_lost(self, exc):
        logging.info('Connection from %s closed', self.peername)
        self._shutdown()

    def _schedule_keepalive(self):
        if not self.alive:
            return
        loop = asyncio.get_running_loop()
        self.keepalive_handle = loop.call_later(
            self.keepalive_time_sec, self._keepalive,
        )

    def _keepalive(self):
        self._schedule_keepalive()
        logging.info('keepalive for %s', self.peername)


async def server_loop(server_addr, server_port, keepalive_time_sec):
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: PCEPPCEServerProtocol(keepalive_time_sec),
        server_addr, server_port)

    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description='pypcep PCE server')
    parser.add_argument('--server_port', default=4189, type=int, help='server port')
    parser.add_argument('--server_addr', default='::', type=str, help='server address')
    parser.add_argument('--keepalive_time_sec', default=10, type=int,
        help='PCEP keepalive time interval')
    debug_parser = parser.add_mutually_exclusive_group(required=False)
    debug_parser.add_argument('--debug', dest='debug', action='store_true', help='debug')
    debug_parser.add_argument('--no-debug', dest='debug', action='store_false', help='no debug')
    args = parser.parse_args()
    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(level=level, format='%(asctime)s %(message)s')
    asyncio.run(server_loop(args.server_addr, args.server_port, args.keepalive_time_sec))


if __name__ == '__main__':
    main()
