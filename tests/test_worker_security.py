import importlib
import io
import logging
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
TOKEN = 'cd' * 32
KEY = Fernet.generate_key()
with patch.dict(os.environ, {'ENCRYPTION_KEY': KEY.decode()}):
    worker = importlib.import_module('task_runner')


class WorkerSecurityTests(unittest.TestCase):
    def test_request_uses_timeout_and_does_not_log_token(self):
        response = type('Response', (), {'status_code': 200, 'close': lambda self: None})()
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        worker.logging.getLogger().addHandler(handler)
        self.addCleanup(worker.logging.getLogger().removeHandler, handler)
        with patch.object(worker.requests, 'get', return_value=response) as get:
            worker.refresh_one(worker.cipher.encrypt(TOKEN.encode()))
        get.assert_called_once_with(
            worker.ENDPOINT,
            params={'sessionToken': TOKEN},
            timeout=(5, 15),
            allow_redirects=False,
        )
        self.assertNotIn(TOKEN, stream.getvalue())
        self.assertNotIn('sessionToken=', stream.getvalue())

    def test_request_exception_text_is_suppressed(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        worker.logging.getLogger().addHandler(handler)
        self.addCleanup(worker.logging.getLogger().removeHandler, handler)
        with patch.object(worker.requests, 'get', side_effect=worker.requests.Timeout(TOKEN)):
            worker.refresh_one(worker.cipher.encrypt(TOKEN.encode()))
        self.assertNotIn(TOKEN, stream.getvalue())


if __name__ == '__main__':
    unittest.main()
