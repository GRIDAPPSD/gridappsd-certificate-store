"""Test fixtures for certificate store tests."""

import pytest
import os
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from gridappsd_certs import DeviceCertificateGenerator

@pytest.fixture
def cert_generator():
    """Return a certificate generator for testing."""
    return DeviceCertificateGenerator(key_type='rsa', key_size=2048)

@pytest.fixture
def ca_cert(cert_generator):
    """Create a CA certificate for testing."""
    ca_attrs = {
        'common_name': 'Test CA',
        'organization': 'Test Organization',
        'country': 'US',
    }
    return cert_generator.create_ca_certificate(ca_attrs, valid_days=365)

@pytest.fixture
def device_cert(cert_generator, ca_cert):
    """Create a device certificate for testing."""
    ca_cert_obj, ca_key = ca_cert
    device_attrs = {
        'common_name': 'Test Device',
        'organization': 'Test Organization',
        'country': 'US',
        'serial_number': 'DEVICE123'
    }
    return cert_generator.create_device_certificate(
        device_attrs, ca_cert_obj, ca_key, device_id="11111111-2222-3333-4444-555555555555"
    )

@pytest.fixture
def web_cert(cert_generator, ca_cert):
    """Create a web server certificate for testing."""
    ca_cert_obj, ca_key = ca_cert
    web_attrs = {
        'common_name': 'example.com',
        'organization': 'Test Organization',
        'country': 'US',
    }
    return cert_generator.create_web_certificate(
        web_attrs, ca_cert_obj, ca_key, domains=['example.com', 'www.example.com']
    )

@pytest.fixture
def temp_dir():
    """Create a temporary directory for certificate storage."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir