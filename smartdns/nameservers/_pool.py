from generic_connection_pool.asyncio import BaseConnectionManager
from generic_connection_pool.contrib.socket_async import SocketAlivenessCheckingMixin


class TCPConnectionManager(BaseConnectionManager, SocketAlivenessCheckingMixin):
    def __init__(
        self, ssl_context=None, tls: bool = False, connect_timeout: float = 5.0
    ) -> None:
        self._tls = tls
        self._ssl_context = ssl_context
        self._connect_timeout = connect_timeout
