"""Tests for certificate identity extraction functionality."""

import pytest
from cryptography import x509

from gridappsd_certs.store import (
    extract_identity_from_certificate,
    extract_client_id_from_certificate
)

def test_extract_identity_from_certificate(device_cert):
    """Test extracting identity information from certificate."""
    cert, _ = device_cert
    
    identity = extract_identity_from_certificate(cert)
    
    # Check basic identity fields
    assert identity['common_name'] == 'Test Device'
    assert identity['organization'] == 'Test Organization'
    assert identity['country'] == 'US'
    assert not identity['is_ca']
    
    # Check IEEE 2030.5 fields
    assert 'lfdi' in identity
    assert 'sfdi' in identity
    assert len(identity['lfdi']) == 40
    assert identity['sfdi'].isdigit()

def test_extract_client_id_from_certificate_with_uri(device_cert):
    """Test extracting client ID from certificate with URI SAN."""
    cert, _ = device_cert
    
    client_id = extract_client_id_from_certificate(cert)
    
    # The certificate has a UUID, so should extract that
    assert client_id == "11111111-2222-3333-4444-555555555555"

def test_extract_client_id_from_certificate_fallbacks(cert_generator):
    """Test extracting client ID with fallbacks."""
    import re
    
    # Create a certificate without explicitly setting URI SAN
    cert, _ = cert_generator.create_self_signed_device_cert({
        'common_name': 'Test Device No URI',
        'organization': 'Test Organization',
        'country': 'US'
    })
    
    client_id = extract_client_id_from_certificate(cert)
    
    # Should be either the common name, an LFDI prefix, or a UUID format
    assert client_id is not None
    
    # Since the DeviceCertificateGenerator automatically adds a UUID,
    # we need to accept that as a valid result
    import uuid

    try:
        # Check if it's a valid UUID
        uuid_obj = uuid.UUID(client_id)
        is_uuid = True
    except ValueError:
        is_uuid = False
    
    assert (client_id == 'Test Device No URI' or
            client_id.startswith('lfdi:') or
            is_uuid), f"Unexpected client ID format: {client_id}"
    
def test_extract_client_id_from_certificate_with_explicit_id(cert_generator):
    """Test extracting client ID with explicit device ID."""
    # Create a certificate with an explicit device ID
    explicit_id = "explicit-device-id"
    cert, _ = cert_generator.create_self_signed_device_cert({
        'common_name': 'Test Device',
        'organization': 'Test Organization',
        'country': 'US'
    }, device_id=explicit_id)
    
    client_id = extract_client_id_from_certificate(cert)
    
    # Should extract the explicit ID
    assert client_id == explicit_id