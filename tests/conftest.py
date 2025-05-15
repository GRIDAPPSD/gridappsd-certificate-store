"""Shared fixtures for testing the GridAppSD Certificate Store."""

import os
import tempfile
import pytest
from ipaddress import ip_address
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from gridappsd_certs import DeviceCertificateGenerator


@pytest.fixture
def cert_generator():
    """Return a basic certificate generator with default settings."""
    return DeviceCertificateGenerator(key_type='rsa', key_size=2048)


@pytest.fixture
def ec_cert_generator():
    """Return a certificate generator with EC keys."""
    return DeviceCertificateGenerator(key_type='ec')


@pytest.fixture
def ca_attrs():
    """Return attributes for a test CA."""
    return {
        'common_name': 'Test CA',
        'organization': 'Test Organization',
        'country': 'US',
        'organizational_unit': 'Testing Unit'
    }


@pytest.fixture
def device_attrs():
    """Return attributes for a test device."""
    return {
        'common_name': 'Test Device',
        'organization': 'Test Organization',
        'country': 'US',
        'organizational_unit': 'IoT Devices',
        'serial_number': 'DEV123456'
    }


@pytest.fixture
def web_attrs():
    """Return attributes for a test web server."""
    return {
        'common_name': 'example.com',
        'organization': 'Test Organization',
        'country': 'US',
        'organizational_unit': 'Web Services'
    }


@pytest.fixture
def ca_certificate(cert_generator, ca_attrs):
    """Create and return a CA certificate and key."""
    return cert_generator.create_ca_certificate(ca_attrs, valid_days=365)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for file operations."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir