from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .network import detect_private_ipv4_addresses

ROOT_COMMON_NAME = "OctaneDrop LAN Local CA"
LEAF_COMMON_NAME = "OctaneDrop LAN"
TLS_DIR_NAME = ".tls"
CA_VALIDITY_DAYS = 3650
SERVER_VALIDITY_DAYS = 825


@dataclass(slots=True, frozen=True)
class LocalTlsBundle:
    ca_cert_path: Path
    ca_key_path: Path
    cert_path: Path
    key_path: Path
    trusted_on_host: bool
    san_hosts: tuple[str, ...]
    san_ips: tuple[str, ...]



def _normalize_hex(text: str) -> str:
    return re.sub(r"[^A-Fa-f0-9]", "", text).upper()



def _build_subject(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OctaneDrop LAN"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )



def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)



def _write_private_pem(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass



def _load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())



def _load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)



def _ordered_unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if not item or item in seen:
            continue
        ordered.append(item)
        seen.add(item)
    return ordered



def detect_tls_subjects(primary_lan_ip: str | None) -> tuple[list[str], list[str]]:
    hostname = socket.gethostname().strip()
    fqdn = socket.getfqdn().strip()

    host_candidates = _ordered_unique(
        [
            "localhost",
            hostname,
            fqdn,
            hostname.split(".", 1)[0] if hostname else "",
        ]
    )

    hosts: list[str] = []
    for candidate in host_candidates:
        if not candidate:
            continue
        if any(ch.isspace() for ch in candidate):
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            hosts.append(candidate)

    ip_candidates = ["127.0.0.1", "::1"]
    if primary_lan_ip:
        ip_candidates.append(primary_lan_ip)
    ip_candidates.extend(detect_private_ipv4_addresses())

    ips: list[str] = []
    for candidate in _ordered_unique(ip_candidates):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        ips.append(candidate)

    return hosts, ips



def _generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)



def _serialize_private_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )



def _build_root_ca_certificate(key: rsa.RSAPrivateKey) -> x509.Certificate:
    subject = issuer = _build_subject(ROOT_COMMON_NAME)
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )



def ensure_root_ca(tls_dir: Path) -> tuple[Path, Path]:
    _ensure_dir(tls_dir)
    ca_cert_path = tls_dir / "ca-cert.pem"
    ca_key_path = tls_dir / "ca-key.pem"

    if ca_cert_path.exists() and ca_key_path.exists():
        return ca_cert_path, ca_key_path

    key = _generate_rsa_key()
    cert = _build_root_ca_certificate(key)
    _write_private_pem(ca_key_path, _serialize_private_key(key))
    ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return ca_cert_path, ca_key_path



def _build_leaf_certificate(
    ca_cert: x509.Certificate,
    ca_key,
    leaf_key,
    *,
    hosts: list[str],
    ips: list[str],
) -> x509.Certificate:
    now = datetime.now(UTC)
    san_entries: list[x509.GeneralName] = [x509.DNSName(host) for host in hosts]
    san_entries.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips)

    builder = (
        x509.CertificateBuilder()
        .subject_name(_build_subject(LEAF_COMMON_NAME))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=SERVER_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
    )
    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())



def ensure_server_certificate(
    tls_dir: Path,
    *,
    primary_lan_ip: str | None,
) -> tuple[Path, Path, list[str], list[str]]:
    ca_cert_path, ca_key_path = ensure_root_ca(tls_dir)
    ca_cert = _load_certificate(ca_cert_path)
    ca_key = _load_private_key(ca_key_path)

    cert_path = tls_dir / "server-cert.pem"
    key_path = tls_dir / "server-key.pem"
    hosts, ips = detect_tls_subjects(primary_lan_ip)

    leaf_key = _generate_rsa_key()
    leaf_cert = _build_leaf_certificate(ca_cert, ca_key, leaf_key, hosts=hosts, ips=ips)
    _write_private_pem(key_path, _serialize_private_key(leaf_key))
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path, hosts, ips



def _windows_root_store_contains(ca_cert_path: Path) -> bool:
    if sys.platform != "win32":
        return False

    thumbprint = _load_certificate(ca_cert_path).fingerprint(hashes.SHA1()).hex().upper()
    try:
        result = subprocess.run(
            ["certutil", "-user", "-store", "Root"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return False

    haystack = _normalize_hex(result.stdout + result.stderr)
    return thumbprint in haystack



def install_windows_root_ca(ca_cert_path: Path) -> bool:
    if sys.platform != "win32":
        return False

    if _windows_root_store_contains(ca_cert_path):
        return True

    try:
        result = subprocess.run(
            ["certutil", "-user", "-f", "-addstore", "Root", str(ca_cert_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return False

    if result.returncode != 0:
        return False
    return _windows_root_store_contains(ca_cert_path)



def ensure_local_tls_bundle(
    data_dir: Path,
    *,
    primary_lan_ip: str | None,
    trust_windows_host: bool = True,
) -> LocalTlsBundle:
    tls_dir = data_dir / TLS_DIR_NAME
    ca_cert_path, ca_key_path = ensure_root_ca(tls_dir)
    cert_path, key_path, hosts, ips = ensure_server_certificate(tls_dir, primary_lan_ip=primary_lan_ip)
    trusted_on_host = False
    if trust_windows_host:
        trusted_on_host = install_windows_root_ca(ca_cert_path)
    return LocalTlsBundle(
        ca_cert_path=ca_cert_path,
        ca_key_path=ca_key_path,
        cert_path=cert_path,
        key_path=key_path,
        trusted_on_host=trusted_on_host,
        san_hosts=tuple(hosts),
        san_ips=tuple(ips),
    )
