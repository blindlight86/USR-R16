import asyncio
import logging
import usr_r16

async def connect():
    client = await usr_r16.create_usr_r16_client_connection(host, port=8899, password='admin', loop=loop, timeout=60, reconnect_interval=10)

host, name = usr_r16.USR16Protocol.discover()
print(host)
print(name)
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
if host:
    loop = asyncio.get_event_loop()
    loop.create_task(connect())
    loop.run_forever()