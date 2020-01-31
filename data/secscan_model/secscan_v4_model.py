import logging

from collections import namedtuple

from data.secscan_model.interface import SecurityScannerInterface
from data.secscan_model.datatypes import ScanLookupStatus, SecurityInformationLookupResult
from registry_model import registry_model

from data.database import ManifestSecurityStatus, IndexStatus, IndexerVersion, Manifest


class V4SecurityScanner(SecurityScannerInterface):
    """
    Implementation of the security scanner interface for Clair V4 API-compatible implementations.
    """

    def __init__(self):
        # TODO(alecmerdler)
        pass 
      

    def load_security_information(self, manifest_or_legacy_image, include_vulnerabilities=False):
        status = registry_model.security_status_for(manifest_or_legacy_image)

        if status is None:
            return SecurityInformationLookupResult.with_status(ScanLookupStatus.UNKNOWN_MANIFEST_OR_IMAGE)
        # TODO(alecmerdler)
        raise NotImplementedError


    def perform_indexing(self, start_token=None):
        # TODO(alecmerdler): Randomly fetch `Manifests` that do not have an associated `ManifestSecurityStatus` object, call the Clair v4 API to index them, and create a `ManifestSecurityStatus` object using the response.
        Manifest.select()
        raise NotImplementedError


    def register_model_cleanup_callbacks(self, data_model_config):
        # TODO(alecmerdler)
        raise NotImplementedError


    @property
    def legacy_api_handler(self):
        """ 
        Exposes the legacy security scan API for legacy workers that need it. 
        """
        return self._legacy_secscan_api
