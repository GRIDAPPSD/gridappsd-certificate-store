"""
Certificate storage functionality for managing X.509 certificates.
"""

import os
import json
import base64
from pathlib import Path
from typing import Dict, List, Optional, Union, Set, Tuple
from datetime import datetime
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from .ieee2030_5 import calculate_lfdi_from_certificate, calculate_sfdi_from_lfdi

logger = logging.getLogger("gridappsd.certs.store")


class CertificateStore:
    """
    Store for X.509 certificates with lookup capabilities.
    
    This class provides methods to:
    - Add certificates to the store
    - Look up certificates by various attributes
    - Store certificates in a filesystem or database backend
    - Load certificates from storage
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize the certificate store.
        
        Args:
            storage_path: Path to directory for certificate storage
                If None, certificates are kept in memory only
        """
        self.storage_path = Path(storage_path) if storage_path else None
        self.certificates: Dict[str, x509.Certificate] = {}  # By fingerprint
        self.private_keys: Dict[str, Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]] = {}
        self.common_name_index: Dict[str, Set[str]] = {}  # CN -> set of fingerprints
        self.subject_alt_name_index: Dict[str, str] = {}  # SAN value -> fingerprint
        self.lfdi_index: Dict[str, str] = {}  # LFDI -> fingerprint
        self.sfdi_index: Dict[str, str] = {}  # SFDI -> fingerprint
        
        # Load certificates if storage path exists
        if self.storage_path and self.storage_path.exists():
            self.load_certificates()
    
    def add_certificate(
        self, 
        certificate: x509.Certificate,
        private_key: Optional[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]] = None,
        alias: Optional[str] = None
    ) -> str:
        """
        Add a certificate to the store.
        
        Args:
            certificate: X.509 certificate to add
            private_key: Optional private key for the certificate
            alias: Optional friendly name for the certificate
            
        Returns:
            Fingerprint of the certificate (SHA-256)
        """
        # Calculate fingerprint
        fingerprint = self._get_fingerprint(certificate)
        
        # Store certificate
        self.certificates[fingerprint] = certificate
        
        # Store private key if provided
        if private_key:
            self.private_keys[fingerprint] = private_key
        
        # Index by common name
        common_name = self._get_common_name(certificate)
        if common_name:
            if common_name not in self.common_name_index:
                self.common_name_index[common_name] = set()
            self.common_name_index[common_name].add(fingerprint)
        
        # Index by subject alternative names
        for san in self._get_subject_alt_names(certificate):
            self.subject_alt_name_index[san] = fingerprint

        try:
            lfdi = calculate_lfdi_from_certificate(certificate)
            if lfdi:
                self.lfdi_index[lfdi] = fingerprint
                
                # Also index by SFDI
                sfdi = calculate_sfdi_from_lfdi(lfdi)
                if sfdi:
                    self.sfdi_index[sfdi] = fingerprint
        except Exception as e:
            logger.warning(f"Failed to calculate LFDI/SFDI for certificate: {e}")
        
        # Persist to storage if enabled
        if self.storage_path:
            self._save_certificate(certificate, fingerprint, private_key, alias)
        
        logger.info(f"Added certificate with fingerprint {fingerprint} to store")
        return fingerprint
    
    def get_certificate_by_lfdi(self, lfdi: str) -> Optional[x509.Certificate]:
        """
        Get a certificate by Long Form Device Identifier (LFDI).
        
        Args:
            lfdi: LFDI to search for
            
        Returns:
            Certificate if found, None otherwise
        """
        fingerprint = self.lfdi_index.get(lfdi)
        if fingerprint:
            return self.certificates.get(fingerprint)
        return None
    
    def get_certificate_by_sfdi(self, sfdi: str) -> Optional[x509.Certificate]:
        """
        Get a certificate by Short Form Device Identifier (SFDI).
        
        Args:
            sfdi: SFDI to search for
            
        Returns:
            Certificate if found, None otherwise
        """
        fingerprint = self.sfdi_index.get(sfdi)
        if fingerprint:
            return self.certificates.get(fingerprint)
        return None
    
    def get_certificate_by_fingerprint(self, fingerprint: str) -> Optional[x509.Certificate]:
        """
        Get a certificate by its fingerprint.
        
        Args:
            fingerprint: SHA-256 fingerprint of the certificate
            
        Returns:
            Certificate if found, None otherwise
        """
        return self.certificates.get(fingerprint)
    
    def get_certificate_by_common_name(self, common_name: str) -> List[x509.Certificate]:
        """
        Get certificates by common name.
        
        Args:
            common_name: Common Name (CN) to search for
            
        Returns:
            List of matching certificates (may be empty)
        """
        fingerprints = self.common_name_index.get(common_name, set())
        return [self.certificates[fp] for fp in fingerprints if fp in self.certificates]
    
    def get_certificate_by_san(self, san_value: str) -> Optional[x509.Certificate]:
        """
        Get a certificate by Subject Alternative Name value.
        
        Args:
            san_value: SAN value to search for (e.g., email, DNS name, URI)
            
        Returns:
            Certificate if found, None otherwise
        """
        fingerprint = self.subject_alt_name_index.get(san_value)
        if fingerprint:
            return self.certificates.get(fingerprint)
        return None
    
    def get_private_key(self, certificate: Union[x509.Certificate, str]) -> Optional[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]]:
        """
        Get private key for a certificate.
        
        Args:
            certificate: Certificate or fingerprint
            
        Returns:
            Private key if found, None otherwise
        """
        if isinstance(certificate, x509.Certificate):
            fingerprint = self._get_fingerprint(certificate)
        else:
            fingerprint = certificate
        
        return self.private_keys.get(fingerprint)
    
    def list_certificates(self) -> List[Tuple[str, str, int, int]]:
        """
        List all certificates in the store.
        
        Returns:
            List of tuples (fingerprint, subject, not_before, not_after)
            where times are seconds since the Unix epoch
        """
        result = []
        for fingerprint, cert in self.certificates.items():
            subject = self._format_subject(cert.subject)
            result.append((
                fingerprint,
                subject,
                int(cert.not_valid_before.timestamp()),  # Convert to IEEE 2030.5 time
                int(cert.not_valid_after.timestamp())    # Convert to IEEE 2030.5 time
            ))
        return result
    
    def load_certificates(self):
        """Load certificates from storage."""
        if not self.storage_path or not self.storage_path.exists():
            return
        
        # Load certificate index
        index_path = self.storage_path / "index.json"
        if not index_path.exists():
            return
        
        try:
            with open(index_path, 'r') as f:
                index = json.load(f)
            
            for entry in index.get('certificates', []):
                fingerprint = entry['fingerprint']
                cert_path = self.storage_path / entry['cert_file']
                
                if cert_path.exists():
                    with open(cert_path, 'rb') as f:
                        cert_data = f.read()
                        cert = x509.load_pem_x509_certificate(cert_data)
                        self.certificates[fingerprint] = cert
                        
                        # Index by common name
                        common_name = self._get_common_name(cert)
                        if common_name:
                            if common_name not in self.common_name_index:
                                self.common_name_index[common_name] = set()
                            self.common_name_index[common_name].add(fingerprint)
                        
                        # Index by subject alternative names
                        for san in self._get_subject_alt_names(cert):
                            self.subject_alt_name_index[san] = fingerprint
                
                # Load private key if exists
                if 'key_file' in entry:
                    key_path = self.storage_path / entry['key_file']
                    if key_path.exists():
                        with open(key_path, 'rb') as f:
                            key_data = f.read()
                            if entry.get('key_encrypted', False):
                                # You'd need a password callback here for encrypted keys
                                continue
                            private_key = serialization.load_pem_private_key(
                                key_data,
                                password=None
                            )
                            self.private_keys[fingerprint] = private_key
            
            logger.info(f"Loaded {len(self.certificates)} certificates from storage")
            
        except Exception as e:
            logger.error(f"Error loading certificates: {e}")

        # Populate LFDI/SFDI indices
        for fingerprint, cert in self.certificates.items():
            try:
                lfdi = calculate_lfdi_from_certificate(cert)
                if lfdi:
                    self.lfdi_index[lfdi] = fingerprint
                    
                    # Also index by SFDI
                    sfdi = calculate_sfdi_from_lfdi(lfdi)
                    if sfdi:
                        self.sfdi_index[sfdi] = fingerprint
            except Exception as e:
                logger.warning(f"Failed to calculate LFDI/SFDI for certificate {fingerprint}: {e}")
    
    def _save_certificate(
        self,
        certificate: x509.Certificate,
        fingerprint: str,
        private_key: Optional[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]] = None,
        alias: Optional[str] = None
    ):
        """Save a certificate to storage."""
        if not self.storage_path:
            return
        
        # Create storage directory if it doesn't exist
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Generate filenames
        safe_fingerprint = fingerprint.replace(':', '_')
        cert_filename = f"{safe_fingerprint}.cert.pem"
        key_filename = f"{safe_fingerprint}.key.pem" if private_key else None
        
        # Save certificate
        cert_path = self.storage_path / cert_filename
        with open(cert_path, 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        # Save private key if provided
        if private_key and key_filename:
            key_path = self.storage_path / key_filename
            with open(key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        
        # Update or create index file
        index_path = self.storage_path / "index.json"
        index = {'certificates': []}
        if index_path.exists():
            try:
                with open(index_path, 'r') as f:
                    index = json.load(f)
            except json.JSONDecodeError:
                pass
        
        # Find existing entry or create new one
        entry = None
        for e in index.get('certificates', []):
            if e['fingerprint'] == fingerprint:
                entry = e
                break
        
        if not entry:
            entry = {'fingerprint': fingerprint}
            index.setdefault('certificates', []).append(entry)
        
        entry.update({
            'cert_file': cert_filename,
            'subject': self._format_subject(certificate.subject),
            'not_before': int(certificate.not_valid_before.timestamp()),  # As integer
            'not_after': int(certificate.not_valid_after.timestamp()),    # As integer
            'alias': alias
        })
        
        if key_filename:
            entry.update({
                'key_file': key_filename,
                'key_encrypted': False  # We're not encrypting keys in this example
            })
        
        with open(index_path, 'w') as f:
            json.dump(index, f, indent=2)
    
    def _get_fingerprint(self, certificate: x509.Certificate) -> str:
        """Calculate SHA-256 fingerprint of a certificate."""
        fingerprint = certificate.fingerprint(hashes.SHA256())
        return fingerprint.hex(':')
    
    def _get_common_name(self, certificate: x509.Certificate) -> Optional[str]:
        """Extract Common Name from certificate subject."""
        for attr in certificate.subject:
            if attr.oid == NameOID.COMMON_NAME:
                return attr.value
        return None
    
    def _get_subject_alt_names(self, certificate: x509.Certificate) -> List[str]:
        """Extract Subject Alternative Name values."""
        result = []
        try:
            san_ext = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    result.append(f"DNS:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    result.append(f"EMAIL:{name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    result.append(f"URI:{name.value}")
                # Add other SAN types as needed
        except x509.extensions.ExtensionNotFound:
            pass
        
        return result
    
    def _format_subject(self, subject: x509.Name) -> str:
        """Format certificate subject as string."""
        parts = []
        for attr in subject:
            oid_name = attr.oid._name
            parts.append(f"{oid_name}={attr.value}")
        return ", ".join(parts)