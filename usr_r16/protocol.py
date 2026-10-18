import asyncio
import logging
from collections import deque
from socket import *


class USR16Protocol(asyncio.Protocol):
    """USR-R16 relay control protocol."""

    transport = None  # type: asyncio.Transport

    def __init__(self, client, loop, disconnect_callback=None, logger=None):
        """Initialize the USR-R16 protocol."""
        self.client = client
        self.loop = loop
        self.logger = logger
        self._buffer = b''
        self.disconnect_callback = disconnect_callback
        self._timeout = None
        self._cmd_timeout = None
        self._keep_alive = None

    def connection_made(self, transport):
        """Initialize protocol transport."""
        self.transport = transport
        self._reset_timeout()

    def _send_keepalive_packet(self):
        """Send a keep alive packet."""
        if not self.client.in_transaction:
            packet = self.format_packet('0a')
            self.logger.debug('sending keep alive packet')
            self.transport.write(packet)

    def _reset_timeout(self):
        """Reset timeout for date keep alive."""
        if self._timeout:
            self._timeout.cancel()
        self._timeout = self.loop.call_later(
            self.client.timeout, self.transport.close)
        if self._keep_alive:
            self._keep_alive.cancel()
        self._keep_alive = self.loop.call_later(
            self.client.keep_alive_interval,
            self._send_keepalive_packet)
        self.logger.debug(f'timeout reset')

    def reset_cmd_timeout(self):
        """Reset timeout for command execution."""
        if self._cmd_timeout:
            self._cmd_timeout.cancel()
        self._cmd_timeout = self.loop.call_later(
            self.client.timeout, self.transport.close)
        self.logger.debug(f'cmd timeout reset')

    def data_received(self, data):
        """Add incoming data to buffer."""
        try:
            self.logger.debug(f"Received: {data.decode()}")
        except:
            self.logger.debug(f"Received: {data}")
        self._buffer = data
        self.handle_buffer()

    def handle_buffer(self):
        """Assemble incoming data into per-line packets."""
        lines = self._buffer.split(b'\xaa\x55')
        for line in lines:
            if len(line) != 0:
                if self._valid_packet(line):
                    self._handle_raw_packet(line)
                else:
                    self.logger.warning(f'dropping invalid data: {line.hex()}')

    @staticmethod
    def _valid_packet(raw_packet):
        """Validate incoming packet."""
        if len(raw_packet) == 2:
            return True
        elif len(raw_packet) != 6 and len(raw_packet) != 7:
            return False
        checksum = 0
        for i in range(len(raw_packet)-1):
            checksum += raw_packet[i]
        if checksum.to_bytes(2, 'big')[1] != raw_packet[-1]:
            return False
        return True

    def _handle_raw_packet(self, raw_packet):
        """Parse incoming packet."""
        self._reset_timeout()
        states = {}
        changes = []
        if len(raw_packet) == 2:
            if raw_packet.decode() == 'OK':
                self.logger.info(f'Successful Authorization')
            elif raw_packet.decode() == 'NO':
                self.logger.info(f'Password Incorrect')
                self.transport.close
        else:
            return_cmd = raw_packet[3:4]
            if return_cmd in [b'\x81', b'\x82', b'\x83']:
                if raw_packet[5] == 1:
                    states[format(raw_packet[4], 'd')] = True
                    if (self.client.states.get(format(raw_packet[4], 'd'), None) is not True):
                        changes.append(format(raw_packet[4], 'd'))
                        self.client.states[format(raw_packet[4], 'd')] = True
                elif raw_packet[5] == 0:
                    states[format(raw_packet[4], 'd')] = False
                    if (self.client.states.get(format(raw_packet[4], 'd'), None) is not False):
                        changes.append(format(raw_packet[4], 'd'))
                        self.client.states[format(raw_packet[4], 'd')] = False
            elif return_cmd in [b'\x84', b'\x85']:
                if raw_packet[4] == 1:
                    for switch in range(1, 17):
                        states[format(switch, 'd')] = True
                        if (self.client.states.get(format(switch, 'd'), None) is not True):
                            changes.append(format(switch, 'd'))
                            self.client.states[format(switch, 'd')] = True
                elif raw_packet[4] == 0:
                    for switch in range(1, 17):
                        states[format(switch, 'd')] = False
                        if (self.client.states.get(format(switch, 'd'), None) is not False):
                            changes.append(format(switch, 'd'))
                            self.client.states[format(switch, 'd')] = False
            elif return_cmd in [b'\x86', b'\x8a']:
                state1_8 = bin(raw_packet[4])[2:]
                state9_16 = bin(raw_packet[5])[2:]
                while len(state1_8) < 8:
                    state1_8 = '0' + state1_8
                while len(state9_16) < 8:
                    state9_16 = '0' + state9_16
                states_str = state1_8[::-1] + state9_16[::-1]
                for i, state in enumerate(states_str):
                    if state == '1':
                        states[format(i+1, 'd')] = True
                        if (self.client.states.get(format(i+1, 'd'), None) is not True):
                            changes.append(format(i+1, 'd'))
                            self.client.states[format(i+1, 'd')] = True
                    elif state == '0':
                        states[format(i+1, 'd')] = False
                        if (self.client.states.get(format(i+1, 'd'), None) is not False):
                            changes.append(format(i+1, 'd'))
                            self.client.states[format(i+1, 'd')] = False
            elif return_cmd == b'\xff':
                self.logger.debug(f'recevied heart packet')
            else:
                self.logger.warning(
                    f'received unknown packet: {self._buffer.hex()}')
        for switch in changes:
            for status_cb in self.client.status_callbacks.get(switch, []):
                status_cb(states[switch])
        if self.client.in_transaction:
            self.client.in_transaction = False
            self.client.active_packet = None
            self.client.active_transaction.set_result(states)
            while self.client.status_waiters:
                waiter = self.client.status_waiters.popleft()
                waiter.set_result(states)
            if self.client.waiters:
                self.send_packet()
            else:
                self._cmd_timeout.cancel()
        elif self._cmd_timeout:
            self._cmd_timeout.cancel()
        self._reset_timeout()

    def connection_lost(self, exc):
        """Log when connection is closed, if needed call callback."""
        if exc:
            self.logger.error('disconnected due to error')
        else:
            self.logger.info('disconnected because of close/abort.')
        if self._keep_alive:
            self._keep_alive.cancel()
        if self.disconnect_callback:
            asyncio.ensure_future(self.disconnect_callback(), loop=self.loop)

    def send_packet(self):
        """Write next packet in send queue."""
        waiter, packet = self.client.waiters.popleft()
        self.logger.debug('sending packet: %s', packet.hex())
        self.client.active_transaction = waiter
        self.client.in_transaction = True
        self.client.active_packet = packet
        self.reset_cmd_timeout()
        self.transport.write(packet)

    @staticmethod
    def format_packet(cmd_str, param_str=''):
        """Format packet to be sent."""
        head_str = '55aa'
        id_str = '00'
        cmd_int = int(cmd_str, 16)
        param_int = 0
        for b in range(int(len(param_str)/2)):
            param_int = param_int + int(param_str[2*b:2*b+2], 16)
        length_int = len(bytes.fromhex(id_str+cmd_str+param_str))
        length_str = (length_int).to_bytes(2, 'big').hex()
        checksum_int = cmd_int + param_int + length_int
        checksum_str = (checksum_int).to_bytes(2, 'big').hex()[2:]
        formated_cmd = f'{head_str}{length_str}{id_str}{cmd_str}{param_str}{checksum_str}'
        return bytes.fromhex(formated_cmd)


class USR16Client:
    """USR-R16 client wrapper class."""

    def __init__(self, host, port=8899, password='admin',
                 disconnect_callback=None, reconnect_callback=None,
                 loop=None, logger=None, timeout=10, reconnect_interval=10,
                 keep_alive_interval=3):
        """Initialize the USR-R16 client wrapper."""
        if loop:
            self.loop = loop
        else:
            self.loop = asyncio.get_event_loop()
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger(__name__)

        self.host = host
        self.port = port
        self.password = password.encode()+b'\x0d'+b'\x0a'
        self.timeout = timeout
        self.reconnect = True
        self.reconnect_interval = reconnect_interval
        self.reconnect_callback = reconnect_callback
        self.disconnect_callback = disconnect_callback
        self.transport = None
        self.protocol = None
        self.is_connected = False
        self.keep_alive_interval = keep_alive_interval
        self.waiters = deque()
        self.status_waiters = deque()
        self.active_transaction = None
        self.in_transaction = False
        self.active_packet = None
        self.states = {}
        self.status_callbacks = {}

    async def setup(self):
        """Set up the connection with authorization, automatic retry and get status."""
        while True:
            fut = self.loop.create_connection(
                lambda: USR16Protocol(
                    self,
                    disconnect_callback=self.handle_disconnect_callback,
                    loop=self.loop, logger=self.logger),
                host=self.host,
                port=self.port)
            try:
                self.transport, self.protocol = \
                    await asyncio.wait_for(fut, timeout=self.timeout)
            except asyncio.TimeoutError:
                self.logger.warning("Could not connect due to timeout error.")
            except OSError as exc:
                self.logger.warning("Could not connect due to error: %s",
                                    str(exc))
            else:
                self.is_connected = True
                resp = await self._send(self.password)
                self.states = await self.status()
                if self.reconnect and self.reconnect_callback:
                    self.reconnect_callback()
                break
            await asyncio.sleep(self.reconnect_interval)

    def register_status_callback(self, callback, switch):
        """Register a callback which will fire when state changes."""
        if self.status_callbacks.get(switch, None) is None:
            self.status_callbacks[switch] = []
        self.status_callbacks[switch].append(callback)

    def stop(self):
        """Shut down transport."""
        self.reconnect = False
        self.logger.debug("Shutting down.")
        if self.transport:
            self.transport.close()

    def _send(self, packet):
        """Add packet to send queue."""
        fut = self.loop.create_future()
        self.waiters.append((fut, packet))
        if self.waiters and self.in_transaction is False:
            self.protocol.send_packet()
        return fut

    async def handle_disconnect_callback(self):
        """Reconnect automatically unless stopping."""
        self.is_connected = False
        self.active_transaction = None
        self.in_transaction = False
        self.active_packet = None
        if self.disconnect_callback:
            self.disconnect_callback()
        if self.reconnect:
            self.logger.debug("Protocol disconnected...reconnecting")
            await self.setup()
            self.protocol.reset_cmd_timeout()
            if self.in_transaction:
                self.protocol.transport.write(self.active_packet)
            else:
                await self.status()

    async def status(self, switch=None):
        """Get current relay status."""
        if switch is not None:
            if self.waiters or self.in_transaction:
                fut = self.loop.create_future()
                self.status_waiters.append(fut)
                states = await fut
                state = states[str(switch)]
            else:
                packet = self.protocol.format_packet('0a')
                states = await self._send(packet)
                state = states[str(switch)]
        else:
            if self.waiters or self.in_transaction:
                fut = self.loop.create_future()
                self.status_waiters.append(fut)
                state = await fut
            else:
                packet = self.protocol.format_packet('0a')
                state = await self._send(packet)
        return state

    async def turn_on(self, switch=None):
        """Turn on relay."""
        if switch is not None:
            swtich_str = (int(switch)).to_bytes(1, 'big').hex()
            packet = self.protocol.format_packet('02', swtich_str)
        else:
            packet = self.protocol.format_packet('05')
        states = await self._send(packet)
        return states

    async def turn_off(self, switch=None):
        """Turn off relay."""
        if switch is not None:
            swtich_str = (int(switch)).to_bytes(1, 'big').hex()
            packet = self.protocol.format_packet('01', swtich_str)
        else:
            packet = self.protocol.format_packet('04')
        states = await self._send(packet)
        return states

    async def toggle(self, switch=None):
        """Toggle relay."""
        if switch is not None:
            swtich_str = (int(switch)).to_bytes(1, 'big').hex()
            packet = self.protocol.format_packet('03', swtich_str)
        else:
            packet = self.protocol.format_packet('06')
        states = await self._send(packet)
        return states


class DiscoverProtocol:
    """Discovery Protocol"""

    def __init__(self, loop, logger=None):
        self.message = "ff010102"
        self.port = 1901
        self.loop = loop
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger(__name__)
        self.transport = None
        self.devices = asyncio.Future()
        self.list = []

    def connection_made(self, transport):
        self.transport = transport
        self.logger.warning('Send:', self.message)
        self.transport.sendto(bytes.fromhex(self.message), ('<broadcast>', self.port))

    def datagram_received(self, data, addr):
        if data == bytes.fromhex(self.message):
            self.logger.warning("Local Echo")
        elif data[0] == 255 and data[1] == len(data):
            ip = f'{data[5]}.{data[6]}.{data[7]}.{data[8]}'
            name = data[19:35].decode("ascii").replace('\x00', '')
            self.list.append((name, ip))
            self.devices.set_result(self.list)
            self.logger.warning(f'{name}: {ip}')

    def error_received(self, exc):
        self.logger.error('Error received:', exc)

    def connection_lost(self, exc):
        self.logger.warning("Socket closed, stop the event loop")
        loop = asyncio.get_event_loop()
        loop.stop()

async def discover():
    """Discover USR-R16 on local network"""
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DiscoverProtocol(loop),
        local_addr=('0.0.0.0', 1901),
        allow_broadcast=True)
    try:
        i = 0
        while i < 254:
            devices = await protocol.devices
            i = i+1
        transport.close()
        return devices
    except:
        transport.close()

async def create_usr_r16_client_connection(host=None, port=None, password=None,
                                           disconnect_callback=None,
                                           reconnect_callback=None, loop=None,
                                           logger=None, timeout=None,
                                           reconnect_interval=None,
                                           keep_alive_interval=None):
    """Create USR-R16 Client class."""
    client = USR16Client(host, port=port, password=password,
                         disconnect_callback=disconnect_callback,
                         reconnect_callback=reconnect_callback,
                         loop=loop, logger=logger,
                         timeout=timeout, reconnect_interval=reconnect_interval,
                         keep_alive_interval=keep_alive_interval)
    await client.setup()

    return client
