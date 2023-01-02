#!/usr/bin/env python3
from __future__ import annotations
from abc import ABC, abstractmethod
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dataclasses import dataclass, field
import datetime
try:
    from disnake.utils import escape_markdown
except ImportError:
    import sys
    sys.stderr.write("WARNING: Failed to import escape_markdown.\n")
    sys.stderr.write("Install disnake, find a replacement, or write it yourself\n")
    sys.stderr.write("Without an escape_markdown function, emitting interactions as Markdown might be wonky :)\n")

    def escape_markdown(s):
        return s
import json
import secrets
from string import ascii_lowercase, digits
import requests
from typing import Optional, Dict, Generator, Union
import uuid


def random_string(length: int, haystack: str = ascii_lowercase + digits) -> str:
    return "".join(secrets.choice(haystack) for _ in range(length))


public_interactsh_servers = [
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
]


class InteractshSessionRegistrationError(Exception):
    pass


class InteractshSessionRegistrationDuplicateCidError(InteractshSessionRegistrationError):
    pass


class InteractshSessionPollError(Exception):
    pass


class InteractshSessionPollCidNotRegisteredError(InteractshSessionPollError):
    pass


def datetime_from_isoformat_liberally(isoformat: str) -> datetime.datetime:
    """
    Liberally convert an ISO-8601 formatted datetime to a datetime.datetime

    See https://discuss.python.org/t/parse-z-timezone-suffix-in-datetime/2220

    >>> dt = datetime.datetime(year=2020, month=3, day=20, hour=16, minute=40)
    >>> datetime_from_isoformat_liberally(dt.isoformat()) == dt
    True
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.133713371Z")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 133713, tzinfo=datetime.timezone.utc)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00")
    datetime.datetime(2020, 4, 20, 16, 20)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.1")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 100000)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.12")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 120000)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.123")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 123000)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.1234")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 123400)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.12345")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 123450)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.123456")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 123456)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.1234567")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 123456)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.12345678")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 123456)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.123456789")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 123456)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.1234567891")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 123456)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.12345678912")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 123456)
    >>> datetime_from_isoformat_liberally("2020-04-20T16:20:00.123456789123")
    datetime.datetime(2020, 4, 20, 16, 20, 0, 123456)
    """
    # Replace trailing 'Z' with '+00:00'
    if isoformat.endswith("Z"):
        isoformat = isoformat[:-1] + "+00:00"
    if "." in isoformat:
        # Truncate or zero-pad fractional second to a precision that's acceptable to Python
        a, b = isoformat.rsplit(".", maxsplit=1)
        if "+" in b:
            b, c = b.rsplit("+", maxsplit=1)
        else:
            c = None
        len_b = len(b)
        if len_b < 3:
            b = b.ljust(3, "0")
        elif len_b < 6:
            b = b.ljust(6, "0")
        else:
            b = b[:6]
        if c is None:
            isoformat = f"{a}.{b}"
        else:
            isoformat = f"{a}.{b}+{c}"
    return datetime.datetime.fromisoformat(isoformat)


@dataclass
class InteractshSession:
    """
    Register a CID with an Interactsh server, generate Interactsh canary hostnames, and poll for interactions

    CID is registered with the server upon instantiation of an instance of this class, and .poll() will re-register CID
    if the CID becomes unregistered (Fixes https://github.com/projectdiscovery/interactsh/issues/422 ?)

    >>> isession = InteractshSession.new(server_hostname="oast.fun")
    >>> sum(True for _ in isession.poll()) == 0
    True
    >>> d = isession.to_dict()
    >>> d   # doctest: +ELLIPSIS
    {'server_hostname': 'oast.fun', 'server_proto': 'https', 'server_token': None, 'cid': '...', 'cid_nonce_length': 13, 'secret_key': '...', 'private_key': '-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----\\n'}
    >>> isession = InteractshSession.from_dict(d)
    >>> h = isession.generate_hostname()
    >>> h   # doctest: +ELLIPSIS
    '...oast.fun'
    >>> h   # doctest: +SKIP
    'j6i2vmwo6ezrywhesaaqyh0fu5dfadadl.oast.fun'
    >>> requests.get("https://" + h).text   # doctest: +ELLIPSIS
    '<html><head></head><body>...</body></html>'
    >>> interactions = sorted(list(isession.poll()), key=lambda x: x.timestamp)
    >>> for i in interactions:
    ...     print(i)    # doctest: +ELLIPSIS
    InteractshDNSInteraction(unique_id='...', full_id='...', host_basename='oast.fun', raw_request=';; opcode: QUERY, status: NOERROR, id: ...\\n;; flags: cd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\\n\\n;; QUESTION SECTION:\\n;....oast.fun.\\tIN\\t A\\n\\n;; ADDITIONAL SECTION:\\n\\n;; OPT PSEUDOSECTION:\\n; EDNS: version 0; flags: do; udp: 4096\\n', remote_address='...', timestamp=datetime.datetime(...), q_type='A', raw_response=';; opcode: QUERY, status: NOERROR, id: ...\\n;; flags: qr aa cd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2\\n\\n;; QUESTION SECTION:\\n;....oast.fun.\\tIN\\t A\\n\\n;; ANSWER SECTION:\\n....oast.fun.\\t3600\\tIN\\tA\\t...\\n\\n;; AUTHORITY SECTION:\\n...\\t3600\\tIN\\tNS\\tns1.oast.fun.\\n...\\t3600\\tIN\\tNS\\tns2.oast.fun.\\n\\n;; ADDITIONAL SECTION:\\nns1.oast.fun.\\t3600\\tIN\\tA\\t206.189.156.69\\nns2.oast.fun.\\t3600\\tIN\\tA\\t...\\n')
    InteractshHTTPInteraction(unique_id='...', full_id='...', host_basename='oast.fun', raw_request='GET / HTTP/1.1\\r\\nHost: ....oast.fun\\r\\nAccept: */*\\r\\nAccept-Encoding: gzip, deflate\\r\\nConnection: keep-alive\\r\\nUser-Agent: python-requests/...\\r\\n\\r\\n', remote_address='...', timestamp=datetime.datetime(...), raw_response='HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Type: text/html; charset=utf-8\\r\\nServer: oast.fun\\r\\n\\r\\n<html><head></head><body>...</body></html>')
    >>> for i in interactions:
    ...     print(i.to_markdown())    # doctest: +ELLIPSIS
    ...     print("---")
    **DNS** (A) request from ... for ....oast.fun at ...
    ---
    **HTTP** request from ... to ....oast.fun at ...

    ```
    GET / HTTP/1.1
    Host: ....oast.fun
    Accept: */*
    Accept-Encoding: gzip, deflate
    Connection: keep-alive
    User-Agent: python-requests/...


    ```

    ```
    HTTP/1.1 200 OK
    Connection: close
    Content-Type: text/html; charset=utf-8
    Server: oast.fun

    <html><head></head><body>...</body></html>
    ```
    ---
    """
    server_hostname: str
    server_proto: str
    server_token: str
    cid: str
    cid_nonce_length: int
    secret_key: str
    private_key: rsa.RSAPrivateKey
    session: requests.Session = field(default_factory=requests.Session)

    def __post_init__(self):
        if self.server_token is not None:
            self.session.headers["Authorization"] = self.server_token
        self.register(duplicate_cid_ok=True)

    @classmethod
    def new(cls,
            server_hostname: str,
            server_proto: str = "https",
            server_token: Optional[str] = None,
            cid_length: int = 20,
            cid_nonce_length: int = 13):
        """
        Generate a new InteractshSession with a random cid, secret key and private key
        """
        cid = random_string(cid_length)
        privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return cls(server_hostname=server_hostname,
                   server_proto=server_proto,
                   server_token=server_token,
                   cid=cid,
                   cid_nonce_length=cid_nonce_length,
                   secret_key=str(uuid.uuid4()),
                   private_key=privkey)

    def to_dict(self) -> Dict[str, Union[str|int]]:
        """
        Serialize self to a dictionary, useful for persisting a session as JSON or YAML. Can be loaded with .from_dict()
        """
        return {
            "server_hostname": self.server_hostname,
            "server_proto": self.server_proto,
            "server_token": self.server_token,
            "cid": self.cid,
            "cid_nonce_length": self.cid_nonce_length,
            "secret_key": self.secret_key,
            "private_key": self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                          format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                          encryption_algorithm=serialization.NoEncryption()).decode()
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Union[str|int]]) -> InteractshSession:
        """
        Deserialize from a dictionary and return a new InteractshSession. Useful for reviving persisted sessions
        saved by .to_dict()
        """
        return cls(server_hostname=d["server_hostname"],
                   server_proto=d["server_proto"],
                   server_token=d["server_token"],
                   cid=d["cid"],
                   cid_nonce_length=d["cid_nonce_length"],
                   secret_key=d["secret_key"],
                   private_key=serialization.load_pem_private_key(d["private_key"].encode(), password=None))

    def register(self, duplicate_cid_ok: bool = False):
        """
        Register self's CID with the server
        """
        pubkey_pem = self.private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        registration = {
            "public-key": base64.b64encode(pubkey_pem).decode(),
            "secret-key": self.secret_key,
            "correlation-id": self.cid,
        }

        r = self.session.post(url=f"{self.server_proto}://{self.server_hostname}/register",
                              json=registration,
                              timeout=10)
        if r.status_code == 400 and "already exists" in r.json()["error"]:
            if duplicate_cid_ok:
                return
            raise InteractshSessionRegistrationDuplicateCidError()
        r.raise_for_status()
        json = r.json()
        success = "registration successful"
        if success not in json["message"]:
            raise InteractshSessionRegistrationError(f"Didn't get {success!r} from server")

    def _get_interactions(self) -> Generator[Dict, None, None]:
        r = self.session.get(f"{self.server_proto}://{self.server_hostname}/poll",
                             params={
                                 "id": self.cid,
                                 "secret": self.secret_key,
                             },
                             timeout=10)
        if r.status_code == 400 and "could not get correlation-id from cache" in r.json()["error"]:
            raise InteractshSessionPollCidNotRegisteredError()
        r.raise_for_status()
        j = r.json()
        aes_key = j["aes_key"]
        datas = j["data"]

        if datas:
            aes_key = self.private_key.decrypt(ciphertext=base64.b64decode(aes_key),
                                               padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(),
                                                                    label=None))
            aes = algorithms.AES(aes_key)
            block_size = aes.block_size // 8
            for data in datas:
                data = base64.b64decode(data)
                iv, ct = data[:block_size], data[block_size:]
                cipher = Cipher(aes, modes.CFB(iv))
                decryptor = cipher.decryptor()
                pt = decryptor.update(ct) + decryptor.finalize()
                yield json.loads(pt.rstrip(b"\n").decode())

    def poll(self, register_if_needed: bool = True) -> Generator[InteractshInteraction, None, None]:
        """
        Yield interactions from the server
        """
        try:
            for d in self._get_interactions():
                yield InteractshInteraction.from_dict(d, host_basename=self.server_hostname)
        except InteractshSessionPollCidNotRegisteredError as e:
            if not register_if_needed:
                raise e
            self.register()
            for d in self._get_interactions():
                yield InteractshInteraction.from_dict(d, host_basename=self.server_hostname)

    def generate_hostname(self, suffix: str = ""):
        """
        Generate a hostname for interaction
        """
        if len(suffix) >= self.cid_nonce_length:
            raise ValueError("Suffix too long")
        return f"{self.cid}{random_string(self.cid_nonce_length - len(suffix))}{suffix}.{self.server_hostname}"


@dataclass
class InteractshInteraction(ABC):
    unique_id: str
    full_id: str
    host_basename: str
    raw_request: str
    remote_address: str
    timestamp: datetime.datetime

    @staticmethod
    @abstractmethod
    def from_dict(d: Dict, host_basename: str) -> InteractshInteraction:
        proto = d["protocol"]
        if proto == "dns":
            return InteractshDNSInteraction.from_dict(d, host_basename=host_basename)
        elif proto == "http":
            return InteractshHTTPInteraction.from_dict(d, host_basename=host_basename)
        elif proto == "smtp":
            return InteractshSMTPInteraction.from_dict(d, host_basename=host_basename)
        else:
            raise NotImplementedError(f"proto not implemented: {proto}")

    def full_hostname(self):
        return f"{self.full_id}.{self.host_basename}"

    @abstractmethod
    def to_markdown(self) -> str:
        pass


@dataclass
class InteractshHTTPInteraction(InteractshInteraction):
    raw_response: str

    @staticmethod
    def from_dict(d: Dict, host_basename: str) -> InteractshHTTPInteraction:
        return InteractshHTTPInteraction(unique_id=d["unique-id"],
                                         full_id=d["full-id"],
                                         host_basename=host_basename,
                                         raw_request=d["raw-request"],
                                         raw_response=d["raw-response"],
                                         remote_address=d["remote-address"],
                                         timestamp=datetime_from_isoformat_liberally(d["timestamp"]))

    def to_markdown(self) -> str:
        req_defanged = self.raw_request.replace("```", r"\`\`\`")
        resp_defanged = self.raw_response.replace("```", r"\`\`\`")
        return (f"**HTTP** request from {escape_markdown(self.remote_address)} "
                f"to {escape_markdown(self.full_hostname())} at {self.timestamp}\n\n"
                f"```\n{req_defanged}\n```\n\n```\n{resp_defanged}\n```")


@dataclass
class InteractshDNSInteraction(InteractshInteraction):
    q_type: str
    raw_response: str

    @staticmethod
    def from_dict(d: Dict, host_basename: str) -> InteractshDNSInteraction:
        return InteractshDNSInteraction(unique_id=d["unique-id"],
                                        full_id=d["full-id"],
                                        host_basename=host_basename,
                                        q_type=d.get("q-type", "UNKNOWN"),
                                        raw_request=d["raw-request"],
                                        raw_response=d["raw-response"],
                                        remote_address=d["remote-address"],
                                        timestamp=datetime_from_isoformat_liberally(d["timestamp"]))

    def to_markdown(self) -> str:
        return (f"**DNS** ({escape_markdown(self.q_type)}) request from {escape_markdown(self.remote_address)} "
                f"for {escape_markdown(self.full_hostname())} at {self.timestamp}")


@dataclass
class InteractshSMTPInteraction(InteractshInteraction):
    smtp_from: str

    @staticmethod
    def from_dict(d: Dict, host_basename: str) -> InteractshSMTPInteraction:
        return InteractshSMTPInteraction(unique_id=d["unique-id"],
                                         full_id=d["full-id"],
                                         host_basename=host_basename,
                                         smtp_from=d["smtp-from"],
                                         raw_request=d["raw-request"],
                                         remote_address=d["remote-address"],
                                         timestamp=datetime_from_isoformat_liberally(d["timestamp"]))

    def to_markdown(self) -> str:
        message_defanged = self.raw_request.replace("```", r"\`\`\`")
        return (f"**SMTP** from {escape_markdown(self.smtp_from)} at {escape_markdown(self.remote_address)} "
                f"to {escape_markdown(self.full_hostname())} at {self.timestamp}\n\n"
                f"```\n{message_defanged}\n```")

