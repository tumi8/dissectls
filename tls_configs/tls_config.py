from itertools import chain, combinations, permutations
from typing import List


class TLSConfig:
    ssl_prefer_server_ciphers: bool = True
    ssl_stapling: bool = False
    ssl_session_tickets: bool = False
    http2: bool = True

    ssl_protocols: List[str] = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']

    ssl_ciphers: List[str] = ['HIGH', 'MEDIUM']

    # ssl_ciphers = ['ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-CHACHA20-POLY1305', 'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-CHACHA20-POLY1305', 'ECDHE-ECDSA-AES128-SHA256', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-ECDSA-AES128-SHA', 'ECDHE-RSA-AES128-SHA', 'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-RSA-AES256-SHA384', 'ECDHE-ECDSA-AES256-SHA', 'ECDHE-RSA-AES256-SHA', 'DHE-RSA-AES128-SHA256', 'DHE-RSA-AES256-SHA256', 'AES128-GCM-SHA256', 'AES256-GCM-SHA384', 'AES128-SHA256', 'AES256-SHA256', 'AES128-SHA', 'AES256-SHA', 'DES-CBC3-SHA']


def generate_configs(test_case):
    """Generator for all configs for a test case (currently not combining the different arguments from the test case)"""
    if test_case.test_versions:
        default_config = TLSConfig()
        for versions in powerset(default_config.ssl_protocols):
            if len(versions) > 0:
                config = TLSConfig()
                config.ssl_protocols = versions
                yield config

    if test_case.test_ciphers:
        test_ciphers = ['ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-SHA384', 'ECDHE-RSA-CHACHA20-POLY1305', 'ECDHE-RSA-AES256-SHA', 'AES256-GCM-SHA384', 'AES256-SHA256']
        for ciphers in powerperm(test_ciphers):
            if len(ciphers) > 0:
                config = TLSConfig()
                config.ssl_protocols = config.ssl_protocols[:3]
                config.ssl_ciphers = list(ciphers) + ['AES256-SHA']
                yield config

    if test_case.test_preference:
        config = TLSConfig()
        yield config
        config = TLSConfig()
        config.ssl_prefer_server_ciphers = False
        yield config

    if test_case.test_ocsp:
        config = TLSConfig()
        yield config
        config = TLSConfig()
        config.ssl_stapling = True
        yield config

    if test_case.test_session_ticket:
        config = TLSConfig()
        yield config
        config = TLSConfig()
        config.ssl_session_tickets = True
        yield config

    if test_case.test_alpn:
        config = TLSConfig()
        yield config
        config = TLSConfig()
        config.http2 = False
        yield config

    if test_case.test_nothing:
        yield TLSConfig()


def powerperm(iterable):
    """powerperm([1,2,3]) --> [], [1], [2], [3], [1,2], [2,1], [1,3], [3,1], [2,3], ..."""
    s = list(iterable)
    return chain.from_iterable(permutations(s, r) for r in range(len(s) + 1))


def powerset(iterable):
    """powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"""
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))
