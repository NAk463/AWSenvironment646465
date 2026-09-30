import threading

import boto3
import pytest
from botocore.config import Config

from awsemu.server import make_server


@pytest.fixture(scope="session")
def server():
    srv = make_server("127.0.0.1", 0, verbose=False)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()


@pytest.fixture
def emulator(server):
    emu = server.emulator
    for svc in emu.services.values():
        svc.reset()
    emu.faults.clear()
    emu.events.clear()
    emu.clock.offset = 0
    return emu


@pytest.fixture
def endpoint(server):
    return f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def client(endpoint, emulator):
    def make(service):
        return boto3.client(
            service, endpoint_url=endpoint, region_name="ap-northeast-1",
            aws_access_key_id="test", aws_secret_access_key="test",
            config=Config(retries={"total_max_attempts": 1}),
        )
    return make
