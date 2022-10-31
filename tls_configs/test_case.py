import os.path
from dataclasses import dataclass
from typing import Iterator


@dataclass
class TestCase:
    name: str
    output_dir: str

    test_versions: bool = False
    test_alpn: bool = False
    test_ciphers: bool = False
    test_preference: bool = False
    test_session_ticket: bool = False
    test_ocsp: bool = False
    test_nothing: bool = False

    def get_output_dir(self):
        return os.path.join(self.output_dir, self.name)


def create_test_cases(output_dir: str) -> Iterator[TestCase]:
    yield TestCase('tls_versions', output_dir, test_versions=True)
    yield TestCase('tls_ciphers', output_dir, test_ciphers=True)
    yield TestCase('tls_alpn', output_dir, test_alpn=True)
    yield TestCase('tls_server_preferences', output_dir, test_preference=True)
    yield TestCase('tls_ticket', output_dir, test_session_ticket=True)
    yield TestCase('tls_ocsp', output_dir, test_ocsp=True)
    yield TestCase('tls_server', output_dir, test_nothing=True)
