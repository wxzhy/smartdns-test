# /usr/bin/env python3
#
# Copyright (C) 2017 Brian Hartvigsen
# Copyright (C) 2025 Lesedi Kekana
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.


"""dnspython compatible DNSCrypt library"""

from time import time
import logging
import socket
import struct
from typing import Optional, Union

from dns.flags import TC
from dns.inet import is_multicast
import dns.name
import dns.message
from dns.message import QueryMessage
import dns.query
from dns.rcode import YXDOMAIN, NXDOMAIN
import dns.rdatatype
import dns.rdataclass
import dns.resolver
from dns.exception import Timeout, FormError

from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import VerifyKey
from nacl.utils import random
from nacl.exceptions import BadSignatureError
from nacl.encoding import HexEncoder

import regex

DNSCRYPT_MINIMUM_SIZE = 256
DNSCRYPT_MODULO_SIZE = 64
DNSCRYPT_NONCE_SIZE = 12
DNSCRYPT_RESOLVER_MAGIC = b"r6fnvWj8"
DNSCRYPT_CERT_MAGIC = b"DNSC"


class Resolver(object):
    def __init__(
        self,
        address: str,
        provider_name: str,
        provider_pk: str,
        private_key: Optional[str] = None,
        port: int = 53,
        timeout: float = 5,
    ) -> None:
        self.address: str = address
        self.port: int = port
        self.publickey: Optional[PublicKey] = None
        self.serial: Optional[int] = None
        self.tcp_only: bool = False
        self.timeout: float = timeout

        # if address has port at the end, fix address and port
        if regex.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$", address):
            self.address, self.port = address.split(":")
            self.port = int(self.port)

        if not private_key:
            self.private: PrivateKey = PrivateKey.generate()
            logging.info("Private Key: %s" % self.private.encode(HexEncoder))  # noqa
            logging.info("Public Key : %s" % self.private.public_key.encode(HexEncoder))  # noqa
        else:
            self.private: PrivateKey = PrivateKey(private_key, HexEncoder)

        try:
            vk: VerifyKey = VerifyKey(provider_pk.replace(":", "").lower(), HexEncoder)
        except Exception:
            # assume this means we have an address instead of a public key
            try:
                answer = dns.resolver.resolve(provider_pk, rdtype=dns.rdatatype.TXT)
                fp = b"".join(answer.response.answer[0][0].strings)
                vk = VerifyKey(fp.decode("ascii").replace(":", "").lower(), HexEncoder)
            except Exception:
                raise TypeError("No valid public key for %s" % provider_name)

        question = dns.message.make_query(provider_name, rdtype=dns.rdatatype.TXT)
        # print("Question: " + str(question))
        try:
            # print((str(question), self.address, self.port, self.timeout))
            answer = dns.query.udp(
                question, self.address, port=self.port, timeout=self.timeout
            )
            if answer.flags & TC:
                answer = dns.query.tcp(
                    question, self.address, port=self.port, timeout=self.timeout
                )
        except Timeout:
            logging.debug("Failed over UDP, trying TCP")
            self.tcp_only = True
            answer = dns.query.tcp(
                question, self.address, port=self.port, timeout=self.timeout
            )

        now = time()
        for possible in answer.answer[0]:
            possible = b"".join(possible.strings)
            logging.debug("Possible cert %s" % possible.hex())
            (magic, es_version, minor_version, signed) = struct.unpack(
                "!4sHH%ss" % (len(possible) - 8), possible
            )

            logging.debug("Crypto version %s" % es_version)

            if magic != DNSCRYPT_CERT_MAGIC:
                logging.warning("Bad certificate magic: %s" % magic)
                continue

            if es_version != 1:
                logging.warning("Not using es_version 1")
                continue

            try:
                data = vk.verify(signed)
            except BadSignatureError:
                logging.warning("Signature did not match")
                continue

            (pk, client_magic, serial, start, expire, _) = struct.unpack(
                "!32s8sIII%ss" % (len(data) - 52), data
            )

            if start > now:
                logging.warning("Certification not yet valid: %s" % start)
                continue

            if expire < now:
                logging.warning("Certificate expired %s" % expire)
                continue

            if self.serial is None or serial > self.serial:
                self.publickey = PublicKey(pk)
                self.serial = serial
                self.client_magic = client_magic

        if not self.publickey:
            raise TypeError(
                "No valid certificate found for %s:%s (%s)"
                % (self.address, self.port, provider_name)
            )

        logging.info("Selected certificate %s" % self.serial)
        self.__secretbox: Box = Box(self.private, self.publickey)

    def query(
        self,
        qname: Union[dns.name.Name, str],
        rdtype: Union[dns.rdatatype.RdataType, str] = dns.rdatatype.A,
        rdclass: Union[dns.rdataclass.RdataClass, str] = dns.rdataclass.IN,
        tcp: bool = False,
        source: Optional[str] = None,
        raise_on_no_answer: bool = True,
        source_port: int = 0,
    ) -> dns.resolver.Answer:
        if isinstance(qname, str):
            qname = dns.name.from_text(qname, None)
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype)
        if dns.rdatatype.is_metatype(rdtype):
            raise dns.resolver.NoMetaqueries
        if isinstance(rdclass, str):
            rdclass = dns.rdataclass.from_text(rdclass)
        if dns.rdataclass.is_metaclass(rdclass):
            raise dns.resolver.NoMetaqueries

        if not qname.is_absolute():
            qname = qname.concatenate(dns.name.root)

        query: QueryMessage = dns.message.make_query(
            qname, rdtype=rdtype, rdclass=rdclass
        )
        response = None
        try:
            tcp_attempt = False
            if tcp or self.tcp_only:
                tcp_attempt = True
                response = self.tcp(
                    query, timeout=self.timeout, source=source, source_port=source_port
                )
            else:
                response = self.udp(
                    query, timeout=self.timeout, source=source, source_port=source_port
                )
                if response.flags & TC:
                    tcp_attempt = True
                    response = self.tcp(
                        query,
                        timeout=self.timeout,
                        source=source,
                        source_port=source_port,
                    )
        except (
            socket.error,
            Timeout,
            FormError,
            dns.query.UnexpectedSource,
            EOFError,
        ) as ex:
            raise dns.resolver.NoNameservers(
                request=query,
                errors=[(self.address, tcp_attempt, self.port, ex, response)],
            )

        rcode = response.rcode()
        if rcode == YXDOMAIN:
            raise dns.resolver.YXDOMAIN()
        elif rcode == NXDOMAIN:
            raise dns.resolver.NXDOMAIN(qnames=[qname], responses=[response])

        return dns.resolver.Answer(qname, rdtype, rdclass, response, raise_on_no_answer)

    def __encrypt_query(self, query: QueryMessage) -> bytes:
        message = query.to_wire()

        # Technically for TCP there is no requirement for DNSCRYPT_MINIMUM_SIZE
        # but it simplified my logic so fuck it
        if len(message) < DNSCRYPT_MINIMUM_SIZE:
            padding = DNSCRYPT_MINIMUM_SIZE - len(message)
        elif not len(message) % DNSCRYPT_MODULO_SIZE:
            padding = len(message) % DNSCRYPT_MODULO_SIZE
        else:
            padding = 0

        if padding:
            message += b"\x80" + b"\x00" * padding

        nonce = random(DNSCRYPT_NONCE_SIZE)
        encrypted = self.__secretbox.encrypt(
            message, nonce + b"\x00" * DNSCRYPT_NONCE_SIZE
        )
        # Remove the server nonce
        encrypted = encrypted[0:12] + encrypted[24:]
        return self.client_magic + self.private.public_key.encode() + encrypted

    def __decrypt_response(
        self, wire: bytes, one_rr_per_rrset: bool
    ) -> dns.message.Message:
        (magic, nonce, data) = struct.unpack("!8s24s%ss" % (len(wire) - 32), wire)
        if magic != DNSCRYPT_RESOLVER_MAGIC:
            raise TypeError("This does not appear to be DNSCrypt")

        payload = self.__secretbox.decrypt(data, nonce)
        # we could try to find the padding, but easier just to ignore it
        return dns.message.from_wire(
            payload, ignore_trailing=True, one_rr_per_rrset=one_rr_per_rrset
        )

    def tcp(
        self,
        query: QueryMessage,
        timeout: Optional[float] = None,
        af: Optional[int] = None,
        source: Optional[str] = None,
        source_port: int = 0,
        one_rr_per_rrset: bool = False,
    ) -> dns.message.Message:
        wire = self.__encrypt_query(query)
        (af, destination, source) = dns.query._destination_and_source(
            af, self.address, self.port, source, source_port
        )
        s = dns.query.socket_factory(af, socket.SOCK_STREAM)
        begin_time = None
        try:
            (_, expiration) = dns.query._compute_times(timeout)
            s.setblocking(0)
            if source is not None:
                s.bind(source)
            dns.query._connect(s, destination)
            l = len(wire)
            tcpmsg = struct.pack("!H", l) + wire
            dns.query._net_write(s, tcpmsg, expiration)
            ldata = dns.query._net_read(s, 2, expiration)
            (l,) = struct.unpack("!H", ldata)
            wire = dns.query._net_read(s, l, expiration)
        finally:
            if begin_time is None:
                response_time = 0
            else:
                response_time = time() - begin_time
            s.close()

        r = self.__decrypt_response(wire, one_rr_per_rrset)
        r.time = response_time
        if not query.is_response(r):
            raise dns.query.BadResponse
        return r

    def udp(
        self,
        query: QueryMessage,
        timeout: Optional[float] = None,
        af: Optional[int] = None,
        source: Optional[str] = None,
        source_port: int = 0,
        ignore_unexpected: bool = False,
        one_rr_per_rrset: bool = False,
    ) -> dns.message.Message:
        wire = self.__encrypt_query(query)
        (af, destination, source) = dns.query._destination_and_source(
            self.address, self.port, source, source_port
        )

        s = dns.query.socket_factory(af, socket.SOCK_DGRAM)
        begin_time = None
        try:
            (_, expiration) = dns.query._compute_times(timeout)
            s.setblocking(0)
            if source is not None:
                s.bind(source)
            dns.query._wait_for_writable(s, expiration)
            begin_time = time()
            s.sendto(wire, destination)
            while 1:
                dns.query._wait_for_readable(s, expiration)
                (wire, from_address) = s.recvfrom(65535)
                if dns.query._addresses_equal(af, from_address, destination) or (
                    is_multicast(self.address) and from_address[1:] == destination[1:]
                ):
                    break
                if not ignore_unexpected:
                    raise dns.query.UnexpectedSource(
                        f"got a response from {from_address} instead of {destination}"
                    )
        finally:
            if begin_time is None:
                response_time = 0
            else:
                response_time = time() - begin_time
            s.close()

        r = self.__decrypt_response(wire, one_rr_per_rrset)
        r.time = response_time
        if not query.is_response(r):
            raise dns.query.BadResponse
        return r


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    Resolver(
        "208.67.220.220",
        "2.dnscrypt-cert.opendns.com",
        "B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79",
        port=443,
    ).query("google.com")

    # i think this was intended to be a test that's expected to fail
    Resolver(
        "146.185.167.43",
        "2.dnscrypt-cert.securedns.eu",
        "2.dnscrypt-cert.securedns.eu",
        port=5353,
    )
