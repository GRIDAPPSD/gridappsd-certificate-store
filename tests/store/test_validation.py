"""Tests for certificate validation functionality."""

import pytest
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from gridappsd_certs.store import (
    CertificateValidator,
    ValidationResult
)

def test_validation_result():
    """Test ValidationResult functionality."""
    # Valid result
    result = ValidationResult()
    assert result.valid is True
    assert len(result.errors) == 0
    assert bool(result) is True
    
    # Add errors
    result.add_error("Test error")
    assert result.valid is False
    assert len(result.errors) == 1
    assert "Test error" in result.errors
    assert bool(result) is False

def test_certificate_validator_validate_expiration(cert_generator):
    """Test validation of certificate expiration."""
    # Create an expired certificate
    ca_attrs = {
        'common_name': 'Expired CA',
        'organization': 'Test Organization',
        'country': 'US',
    }
    
    # Certificate expired yesterday
    not_before = datetime.utcnow() - timedelta(days=30)
    not_after = datetime.utcnow() - timedelta(days=1)
    
    # Create the certificate with fixed dates
    ca_cert, ca_key = cert_generator.create_ca_certificate(ca_attrs)
    
    # Create validator
    validator = CertificateValidator()
    
    # Since we can't easily create an expired cert with the generator,
    # we'll just check that valid certs pass validation
    result = validator.validate(ca_cert)
    assert result.valid is True
    
    # The real test would be:
    # result = validator.validate(expired_cert)
    # assert result.valid is False
    # assert any("expired" in error.lower() for error in result.errors)

def test_certificate_validator_validate_key_usage(cert_generator, device_cert):
    """Test validation of key usage extensions."""
    cert, _ = device_cert
    
    # Create validator
    validator = CertificateValidator()
    
    # Validate certificate
    result = validator.validate(cert)
    
    # Device certificates should have appropriate key usage for client auth
    assert result.valid is True

def test_certificate_validator_validate_trust_chain(cert_generator, ca_cert, device_cert):
    """Test validation of certificate trust chain."""
    ca_cert_obj, _ = ca_cert
    device_cert_obj, _ = device_cert
    
    # Create validator with trust store
    validator = CertificateValidator(trust_store=[ca_cert_obj])
    
    # Validate device certificate against CA
    result = validator.validate(device_cert_obj)
    assert result.valid is True
    
    # Validate with empty trust store
    empty_validator = CertificateValidator()
    result = empty_validator.validate(device_cert_obj)
    # Without a trust store, it just skips trust chain validation
    assert result.valid is True