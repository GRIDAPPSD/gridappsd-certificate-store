"""Tests for IEEE 2030.5-specific certificate functionality."""

import pytest
import binascii
from cryptography import x509

from gridappsd_certs.store import (
    calculate_lfdi_from_certificate,
    calculate_sfdi_from_lfdi,
    extract_device_information_from_certificate,
    format_lfdi,
    format_sfdi
)

def test_calculate_lfdi_from_certificate(device_cert):
    """Test calculating LFDI from certificate."""
    cert, _ = device_cert
    
    lfdi = calculate_lfdi_from_certificate(cert)
    
    # LFDI should be a 40-character hex string (SHA-1 hash)
    assert len(lfdi) == 40
    assert all(c in '0123456789ABCDEF' for c in lfdi)
    
    # Verify we get the same result with the same certificate
    lfdi2 = calculate_lfdi_from_certificate(cert)
    assert lfdi == lfdi2

def test_calculate_sfdi_from_lfdi(device_cert):
    """Test calculating SFDI from LFDI."""
    cert, _ = device_cert
    
    lfdi = calculate_lfdi_from_certificate(cert)
    sfdi = calculate_sfdi_from_lfdi(lfdi)
    
    # SFDI should be numeric string
    assert sfdi.isdigit()
    
    # Verify calculation
    lfdi_bytes = binascii.unhexlify(lfdi)
    sfdi_bytes = lfdi_bytes[-5:]  # Last 5 bytes
    sfdi_int = int.from_bytes(sfdi_bytes, byteorder='big')
    assert str(sfdi_int) == sfdi

def test_extract_device_information_from_certificate(device_cert):
    """Test extracting device information from certificate."""
    cert, _ = device_cert
    
    device_info = extract_device_information_from_certificate(cert)
    
    assert 'lfdi' in device_info
    assert 'sfdi' in device_info
    assert 'device_id' in device_info
    
    # Verify LFDI and SFDI
    assert len(device_info['lfdi']) == 40
    assert device_info['sfdi'].isdigit()
    
    # The certificate has a UUID in it
    assert device_info['device_id'] == "11111111-2222-3333-4444-555555555555"

def test_format_lfdi():
    """Test formatting LFDI."""
    lfdi = "0123456789ABCDEF0123456789ABCDEF01234567"
    
    # Format without colons
    formatted = format_lfdi(lfdi)
    assert formatted == lfdi
    assert ':' not in formatted
    
    # Format with colons
    formatted = format_lfdi(lfdi, with_colons=True)
    assert ':' in formatted
    assert formatted == "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67"
    
    # Remove colons and it should match original
    assert formatted.replace(':', '') == lfdi

def test_format_sfdi():
    """Test formatting SFDI."""
    sfdi = "1234567890"
    
    # Format without dashes
    formatted = format_sfdi(sfdi)
    assert formatted == sfdi
    assert '-' not in formatted
    
    # Format with dashes
    formatted = format_sfdi(sfdi, with_dashes=True)
    assert '-' in formatted
    assert formatted == "1234-5678-90"
    
    # Remove dashes and it should match original
    assert formatted.replace('-', '') == sfdi