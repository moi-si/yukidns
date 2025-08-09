import contextvars
import logging
import asyncio

conn_id = contextvars.ContextVar('connection_id', default='?')

class CustomLogRecord(logging.LogRecord):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.conn_id = conn_id.get()

logging.setLogRecordFactory(CustomLogRecord)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(conn_id)s %(levelname)-8s %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('YukiDNS')

_count = 0
_lock = asyncio.Lock()
async def set_id(custom_id=None):
    if custom_id:
        conn_id.set(custom_id)
    else:
        global _count
        async with _lock:
            _count += 1
            if _count > 0xffff:
                _count = 0
                conn_id.set(f'{_count:04x}')
                logger.info('Counter overflowed, reset')
            else:
                conn_id.set(f'{_count:04x}')
