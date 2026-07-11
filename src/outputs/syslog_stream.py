import asyncio
import socket
import logging

import time

logger = logging.getLogger("BSES.SyslogStream")

class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        super().__init__()
        self.transport = None
        self._last_error_time = 0.0

    def connection_made(self, transport):
        self.transport = transport
        logger.info("Syslog UDP transport established.")

    def connection_lost(self, exc):
        if exc:
            logger.debug(f"Syslog UDP transport lost: {exc}")
        else:
            logger.info("Syslog UDP transport closed.")

    def error_received(self, exc):
        now = time.time()
        if now - self._last_error_time > 10.0:
            logger.warning(f"Syslog UDP packet delivery refused (no listener on port?): {exc}")
            self._last_error_time = now

class SyslogStream:
    def __init__(self, host: str = "127.0.0.1", port: int = 514):
        self.host = host
        self.port = port
        self.transport = None
        self.protocol = None
        self._lock = asyncio.Lock()

    async def connect(self):
        async with self._lock:
            if self.transport is not None:
                return
            try:
                loop = asyncio.get_running_loop()
                self.transport, self.protocol = await loop.create_datagram_endpoint(
                    lambda: SyslogProtocol(),
                    remote_addr=(self.host, self.port)
                )
            except Exception as e:
                logger.warning(f"Failed to initialize Syslog UDP socket to {self.host}:{self.port} - {e}")
                self.transport = None

    async def emit(self, message: str):
        if self.transport is None:
            await self.connect()
        
        if self.transport is not None:
            # Syslog RFC 5424 PRI value 13 represents Facility 1 (user-level logs) and Severity 5 (Notice)
            # Format: <13>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
            # To preserve strict JSON parsing in SIEMs, we send standard PRI followed by raw JSON message
            payload = f"<13>{message}\n".encode('utf-8')
            try:
                self.transport.sendto(payload)
            except Exception as e:
                logger.error(f"Failed to transmit UDP syslog payload: {e}")
                # Force reconnect on next send if socket is broken
                self.close()
        else:
            # Log to local stdout or logger if target syslog host is offline
            pass

    def close(self):
        if self.transport is not None:
            self.transport.close()
            self.transport = None
            self.protocol = None
