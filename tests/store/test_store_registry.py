"""Tests for client registry functionality."""

import pytest
import os
import json
from cryptography import x509

from gridappsd_certs.store import (
    CertificateStore,
    ClientRegistry,
    ClientProfile,
    AccessControl,
    calculate_lfdi_from_certificate
)

@pytest.fixture
def acl():
    """Create a test access control list."""
    acl = AccessControl()
    acl.add_rule("/dcap", "GET", allow=True)
    acl.add_rule("/edev/*", "GET", allow=True)
    acl.add_rule("/edev/*", "POST", allow=False)
    acl.add_rule("/drp/*", "*", allow=True)
    return acl

@pytest.fixture
def client_profile(acl):
    """Create a test client profile."""
    return ClientProfile(
        client_id="test-client-1",
        acl=acl
    )

def test_access_control_check_access(acl):
    """Test access control check functionality."""
    # Check allowed access
    assert acl.check_access("/dcap", "GET") is True
    assert acl.check_access("/edev/123", "GET") is True
    assert acl.check_access("/drp/456", "GET") is True
    assert acl.check_access("/drp/456", "POST") is True
    
    # Check denied access
    assert acl.check_access("/edev/123", "POST") is False
    assert acl.check_access("/unknown", "GET") is False

def test_access_control_to_from_dict(acl):
    """Test converting access control to/from dictionary."""
    acl_dict = acl.to_dict()
    
    # Convert back to AccessControl
    new_acl = AccessControl.from_dict(acl_dict)
    
    # Check access rules are preserved
    assert new_acl.check_access("/dcap", "GET") == acl.check_access("/dcap", "GET")
    assert new_acl.check_access("/edev/123", "GET") == acl.check_access("/edev/123", "GET")
    assert new_acl.check_access("/edev/123", "POST") == acl.check_access("/edev/123", "POST")

def test_client_profile_can_access(client_profile):
    """Test client profile access check."""
    assert client_profile.can_access("/dcap", "GET") is True
    assert client_profile.can_access("/edev/123", "POST") is False

def test_client_profile_to_from_dict(client_profile):
    """Test converting client profile to/from dictionary."""
    profile_dict = client_profile.to_dict()
    
    # Convert back to ClientProfile
    new_profile = ClientProfile.from_dict(profile_dict)
    
    assert new_profile.client_id == client_profile.client_id
    assert new_profile.can_access("/dcap", "GET") == client_profile.can_access("/dcap", "GET")
    assert new_profile.can_access("/edev/123", "POST") == client_profile.can_access("/edev/123", "POST")

def test_client_registry_add_client(device_cert):
    """Test adding a client to registry."""
    cert, key = device_cert
    cert_store = CertificateStore()
    registry = ClientRegistry(cert_store=cert_store)
    
    # Add client with certificate
    profile = registry.add_client("test-client-1", certificate=cert)
    
    assert "test-client-1" in registry.clients
    assert profile.certificate_fingerprint is not None
    assert profile.certificate_fingerprint in registry.cert_to_client
    assert registry.cert_to_client[profile.certificate_fingerprint] == "test-client-1"
    
    # Check IEEE 2030.5 device info was extracted
    assert 'lfdi' in profile.device_info
    assert 'sfdi' in profile.device_info

def test_client_registry_get_client_by_id():
    """Test getting a client by ID."""
    registry = ClientRegistry()
    
    # Add a client
    registry.add_client("test-client-1")
    
    # Get client by ID
    client = registry.get_client_by_id("test-client-1")
    assert client is not None
    assert client.client_id == "test-client-1"
    
    # Try getting nonexistent client
    assert registry.get_client_by_id("nonexistent") is None

def test_client_registry_get_client_by_certificate(device_cert):
    """Test getting a client by certificate."""
    cert, _ = device_cert
    cert_store = CertificateStore()
    registry = ClientRegistry(cert_store=cert_store)
    
    # Add client with certificate
    registry.add_client("test-client-1", certificate=cert)
    
    # Get client by certificate
    client = registry.get_client_by_certificate(cert)
    assert client is not None
    assert client.client_id == "test-client-1"

def test_client_registry_get_client_by_lfdi(device_cert):
    """Test getting a client by LFDI."""
    cert, _ = device_cert
    cert_store = CertificateStore()
    registry = ClientRegistry(cert_store=cert_store)
    
    # Add client with certificate
    registry.add_client("test-client-1", certificate=cert)
    
    # Get LFDI
    lfdi = calculate_lfdi_from_certificate(cert)
    
    # Get client by LFDI
    client = registry.get_client_by_lfdi(lfdi)
    assert client is not None
    assert client.client_id == "test-client-1"

def test_client_registry_save_load(device_cert, temp_dir):
    """Test saving and loading client registry."""
    cert, _ = device_cert
    cert_store = CertificateStore()
    registry = ClientRegistry(cert_store=cert_store)
    
    # Add client with certificate
    registry.add_client("test-client-1", certificate=cert)
    
    # Add client with ACL
    acl = AccessControl()
    acl.add_rule("/dcap", "GET", allow=True)
    registry.add_client("test-client-2", profile=ClientProfile(
        client_id="test-client-2",
        acl=acl
    ))
    
    # Save registry
    registry_path = os.path.join(temp_dir, "registry.json")
    registry.save(registry_path)
    
    # Check file exists
    assert os.path.exists(registry_path)
    
    # Load registry
    new_registry = ClientRegistry.load(registry_path, cert_store=cert_store)
    
    # Check clients were loaded
    assert "test-client-1" in new_registry.clients
    assert "test-client-2" in new_registry.clients
    
    # Check ACL was preserved
    client2 = new_registry.get_client_by_id("test-client-2")
    assert client2.can_access("/dcap", "GET") is True