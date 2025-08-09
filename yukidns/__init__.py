__version__ = '0.0.1'

import asyncio
import logging
import contextvars
import dns.message
import dns.asyncresolver
import dns.nameserver
import dns.rrset

from .log import logger, set_id
from .doh_extension import ProxiedDoHClient
from .setting import (parse_args,
                      load_cache,
                      match_ip, sites,
                      sites_cache,
                      save_cache)

def query_to_resp(data):
    try:
        message = dns.message.from_wire(data)
    except Exception as e:
        logger.info('Not a DNS message: %s', e)
        return None, None
    if (message.flags & dns.flags.QR) != 0:
        logger.info('Not a DNS query message')
        return None, None
    try:
        return message, dns.message.make_response(message)
    except Exception as e:
        logger.error('Failed to make response: %s', e)
        return None, None

class Do53ServerProtocol:
    def __init__(self, sites_cache_lock):
        self.sites_cache_lock = sites_cache_lock

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.handle(data, addr))

    def error_received(self, exc):
        logger.error(exc)

    def connection_lost(self, exc):
        if exc:
            logger.error('Connection lost: %s', exc)
        else:
            logger.info('Connection closed')

    async def handle(self, data, addr):
        await set_id()
        host, port = addr[:2]
        logger.info('Received %s:%d', host, port)
        query, resp = query_to_resp(data)
        if not resp:
            return

        try:
            for question in query.question:
                if question.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    continue
                domain = question.name.to_text()
                logger.info('Resolving %s', domain)
                is_c_site = sites.find(domain)
                if is_c_site is True:
                    logger.info('%s is c_site', domain)
                    ip, ttl = await c_query(domain, question.rdtype)
                elif is_c_site is False:
                    logger.info('%s is f_site', domain)
                    ip, ttl = await doh_query(domain, question.rdtype)
                else:
                    is_c_site = sites_cache.get(domain)
                    if is_c_site is True:
                        logger.info('%s is c_site cached', domain)
                        ip, ttl = await c_query(domain, question.rdtype)
                    elif is_c_site is False:
                        logger.info('%s is f_site cached', domain)
                        ip, ttl = await doh_query(domain, question.rdtype)
                    else:
                        ip, ttl = await c_query(domain, question.rdtype)
                        is_c_site = match_ip(ip)
                        if is_c_site:
                            async with self.sites_cache_lock:
                                sites_cache[domain] = is_c_site
                            logger.info('Cached %s to c_sites', domain)
                        else:
                            async with self.sites_cache_lock:
                                sites_cache[domain] = False
                            logger.info('Cached %s to f_sites', domain)
                            ip, ttl = await doh_query(domain, question.rdtype)
                logger.info('Resolved %s to %s', domain, ip)
                record = dns.rrset.from_text(question.name, ttl,
                                             'IN', question.rdtype, ip)
                resp.answer.append(record)

            self.transport.sendto(resp.to_wire(), addr)
            logger.info('Sent response')

        except Exception as e:
            logger.error(e)


async def c_query(qname, qtype):
    answer = await c_resolver.resolve(qname, qtype)
    ip = answer[0].to_text()
    ttl = answer.ttl
    logger.info('c_DNS resolved %s to %s (TTL=%d)', qname, ip, ttl)
    return ip, ttl

async def doh_query(qname, qtype):
    qtype = 'A' if qtype == dns.rdatatype.A else 'AAAA'
    ip, ttl = await doh_resolver.resolve(qname, qtype)
    logger.info('DoH resolved %s to %s (TTL=%d)', qname, ip, ttl)
    return ip, ttl

async def main():
    print(f'YukiDNS v{__version__} Copyright (C) 2025  moi-si')
    await set_id('INIT')
    args = parse_args()
    load_cache()
    loop = asyncio.get_running_loop()

    c_nameservers = ('223.5.5.5:53', '223.6.6.6:53')
    global c_resolver
    c_resolver = dns.asyncresolver.Resolver(configure=False)
    c_resolver.cache = dns.resolver.LRUCache()
    for nameserver in c_nameservers:
        if nameserver.startswith('https://'):
            c_resolver.nameservers.append(
                dns.nameserver.DoHNameserver(nameserver)
            )
        else:
            host, port = nameserver.split(':')
            port = int(port)
            c_resolver.nameservers.append(
                dns.nameserver.Do53Nameserver(host, port)
            )

    global doh_resolver
    doh_resolver = ProxiedDoHClient(args.doh_url, args.proxy_protocol,
                                    args.proxy_host, args.proxy_port)
    try:
        await doh_resolver.init_session()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: Do53ServerProtocol(asyncio.Lock()),
            local_addr=(args.host, args.port)
        )
        logger.info('Listening on %s:%d', args.host, args.port)
        await loop.create_future()
    finally:
        await set_id('EXIT')
        save_cache()
        transport.close()
        await doh_resolver.close_session()
