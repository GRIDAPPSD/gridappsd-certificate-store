"""Tests for certificate and key persistence operations."""

import os
from cryptography import x509


def test_save_and_load_certificate(cert_generator, ca_certificate, temp_dir):
    """Test saving and loading a certificate."""
    ca_cert, _ = ca_certificate
    
    # Save the certificate
    cert_path = os.path.join(temp_dir, 'test_cert.pem')
    cert_generator.save_certificate(ca_cert, cert_path)
    
    # Verify the file exists
    assert os.path.exists(cert_path)
    
    # Load the certificate back
    loaded_cert = cert_generator.load_certificate(cert_path)
    
    # Compare original and loaded certificates
    assert ca_cert.subject == loaded_cert.subject
    assert ca_cert.issuer == loaded_cert.issuer
    assert ca_cert.serial_number == loaded_cert.serial_number
    assert ca_cert.not_valid_before == loaded_cert.not_valid_before
    assert ca_cert.not_valid_after == loaded_cert.not_valid_after
    assert ca_cert.signature == loaded_cert.signature


def test_save_and_load_private_key(cert_generator, ca_certificate, temp_dir):
    """Test saving and loading a private key."""
    _, ca_key = ca_certificate
    
    # Save the key without password
    key_path = os.path.join(temp_dir, 'test_key_no_pass.pem')
    cert_generator.save_private_key(ca_key, key_path)
    
    # Verify the file exists
    assert os.path.exists(key_path)
    
    # Load the key back
    loaded_key = cert_generator.load_private_key(key_path)
    
    # Compare original and loaded keys (by comparing their public keys)
    assert ca_key.public_key().public_numbers().n == loaded_key.public_key().public_numbers().n
    assert ca_key.public_key().public_numbers().e == loaded_key.public_key().public_numbers().e


def test_save_and_load_private_key_with_password(cert_generator, ca_certificate, temp_dir):
    """Test saving and loading a password-protected private key."""
    _, ca_key = ca_certificate
    password = "test-password123!"
    
    # Save the key with password
    key_path = os.path.join(temp_dir, 'test_key_with_pass.pem')
    cert_generator.save_private_key(ca_key, key_path, password=password)
    
    # Verify the file exists
    assert os.path.exists(key_path)
    
    # Load the key back with password
    loaded_key = cert_generator.load_private_key(key_path, password=password)
    
    # Compare original and loaded keys (by comparing their public keys)
    assert ca_key.public_key().public_numbers().n == loaded_key.public_key().public_numbers().n
    assert ca_key.public_key().public_numbers().e == loaded_key.public_key().public_numbers().e


def test_loading_key_with_wrong_password(cert_generator, ca_certificate, temp_dir):
    """Test that loading a key with the wrong password fails."""
    _, ca_key = ca_certificate
    password = "correct-password"
    wrong_password = "wrong-password"
    
    # Save the key with password
    key_path = os.path.join(temp_dir, 'test_key_pwd.pem')
    cert_generator.save_private_key(ca_key, key_path, password=password)
    
    # Verify the file exists
    assert os.path.exists(key_path)
    
    # Attempt to load with wrong password should fail
    try:
        cert_generator.load_private_key(key_path, password=wrong_password)
        password_check_failed = False
    except Exception:
        password_check_failed = True
        
    assert password_check_failed