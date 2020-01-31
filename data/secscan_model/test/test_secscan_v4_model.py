from data.secscan_model.datatypes import ScanLookupStatus
from data.secscan_model.secscan_v2_model import V2SecurityScanner
from data.registry_model import registry_model
from data.registry_model.datatypes import SecurityScanStatus
from data.database import Manifest
from data.model.oci import shared

from test.fixtures import *

from app import app, instance_keys, storage


def test_load_security_information_unknown_manifest(initialized_db):
    # TODO(alecmerdler)
    