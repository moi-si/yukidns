import ipaddress
import json
import argparse

from .log import logger

class DomainMatcher:
    class _TrieNode:
        __slots__ = ('children', 'value')

        def __init__(self):
            self.children = {}
            self.value = None


    __slots__ = ('_exact_domains', '_trie_root')

    def __init__(self):
        self._exact_domains = {}
        self._trie_root = self._TrieNode()

    def _trie_insert(self, domain: str, value: dict):
        node = self._trie_root
        lables = domain.split('.')
        lables.reverse()
        for lable in lables:
            if lable not in node.children:
                node.children[lable] = self._TrieNode()
            node = node.children[lable]
        node.value = value

    def add(self, pattern: str, value):
        if '.' not in pattern:
            raise ValueError(f'Invalid pattern: {pattern}')
        if pattern.endswith('.'):
            pattern = pattern[:-1]
        if pattern.startswith('*.'):
            self._trie_insert(pattern[2:], value)
        elif pattern.startswith('*'):
            domain = pattern[1:]
            self._exact_domains[domain] = value
            self._trie_insert(domain, value)
        elif '*' in pattern:
            raise ValueError(f'Invalid pattern: {pattern}')
        else:
            self._exact_domains[pattern] = value

    def find(self, domain: str):
        if domain.endswith('.'):
            domain = domain[:-1]
        if (value := self._exact_domains.get(domain)) is not None:
            return value
        node = self._trie_root
        lables = domain.split('.')
        lables.reverse()
        for lable in lables:
            if lable not in node.children:
                break
            node = node.children[lable]
            if node.value is not None:
                value = node.value
        return value

class Trie:
    class _TrieNode:
        __slots__ = ('children', 'val')
        def __init__(self):
            self.children = [None, None]
            self.val = None

    __slots__ = ('_root',)
    def __init__(self):
        self._root = self._TrieNode()

    def insert(self, prefix, value):
        node = self._root
        for bit in prefix:
            index = int(bit)
            if not node.children[index]:
                node.children[index] = self._TrieNode()
            node = node.children[index]
        node.val = value

    def search(self, prefix):
        node = self._root
        ans = None
        for bit in prefix:
            index = int(bit)
            if not node.children[index]:
                break
            node = node.children[index]
            if node.val is not None:
                ans = node.val
        return ans


def ip_to_binary_prefix(ip_or_network: str):
    try:
        network = ipaddress.ip_network(ip_or_network, strict=False)
        network_address = network.network_address
        prefix_length = network.prefixlen
        if isinstance(network_address, ipaddress.IPv4Address):
            binary_network = bin(int(network_address))[2:].zfill(32)
        elif isinstance(network_address, ipaddress.IPv6Address):
            binary_network = bin(int(network_address))[2:].zfill(128)
        binary_prefix = binary_network[:prefix_length]
        return binary_prefix
    except ValueError:
        try:
            ip = ipaddress.ip_address(ip_or_network)
            if isinstance(ip, ipaddress.IPv4Address):
                binary_ip = bin(int(ip))[2:].zfill(32)
                binary_prefix = binary_ip[:32]
            elif isinstance(ip, ipaddress.IPv6Address):
                binary_ip = bin(int(ip))[2:].zfill(128)
                binary_prefix = binary_ip[:128]
            return binary_prefix
        except ValueError:
            raise ValueError(f"Invalid IP or network: {ip_or_network}")

ipv4 = Trie()
with open('c_ip_list.txt') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        ipv4.insert(ip_to_binary_prefix(line), True)

def match_ip(ip):
    if ipv4.search(ip_to_binary_prefix(ip)):
        return True
    return False

def _load_config(file_path, sites):
    c_sites, f_sites = set(), set()
    current = None
    skip = False
    with open(file_path) as f:
        for i, line in enumerate(f, 1):
            if line.startswith('-'):
                skip = False if skip else True
                continue
            if skip:
                continue
            line = line.strip()
            if not line or line.startswith(('#', ';')):
                continue
            if line.startswith('[') and line.endswith(']'):
                current = line[1:-1]
                if current not in ('c_sites', 'f_sites'):
                    raise ValueError(f'Invalid line {i}: {line}')
            elif '[' in line or ']' in line:
                raise ValueError(f'Invalid line {i}: {line}')
            elif current == 'c_sites':
                c_sites.add(line)
            elif current == 'f_sites':
                f_sites.add(line)
            else:
                raise ValueError(f'Invalid line {i}: {line}')
    for c_site in c_sites:
        sites.add(c_site, True)
    for f_site in f_sites:
        sites.add(f_site, False)

sites = DomainMatcher()
_load_config('sites.conf', sites)

sites_cache, old_sites_cache ={}, {}

def load_cache():
    try:
        with open('sites_cache.json') as f:
            sites_cache.update(json.load(f))
        global old_sites_cache
        old_sites_cache = sites_cache.copy()
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.info('Failed to open sites_cache.json: %s', repr(e))

def save_cache():
    if old_sites_cache != sites_cache:
        try:
            with open('sites_cache.json', 'w') as f:
                json.dump(sites_cache, f)
            logger.info('Saved sites cache')
        except Exception as e:
            logger.error('Failed to save sites cache: %s', repr(e))

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--host', type=str, metavar='host',
        default='127.0.0.1', help='Server host')
    parser.add_argument(
        '--port', type=int, metavar='port', default=5300, help='Server port')
    parser.add_argument(
        '--doh-url', type=str, metavar='url',
        default='https://cloudflare-dns.com/dns-query',
        help='DNS over HTTPS URL')
    parser.add_argument(
        '--proxy-protocol', type=str, metavar='protocol', default='socks5',
        help='Proxy protocol (HTTP or SOCKS5)')
    parser.add_argument(
        '--proxy-host', type=str, metavar='host', default='127.0.0.1',
        help='Proxy host')
    parser.add_argument(
        '--proxy-port', type=int, metavar='port', default=3500,
        help='Proxy port')
    return parser.parse_args()    
