from peewee import fn
import mock

from data.secscan_model.secscan_v4_model import V4SecurityScanner, IndexReportState
from data.secscan_model.datatypes import ScanLookupStatus
from data.database import (
    Manifest,
    Repository,
    ManifestSecurityStatus,
    IndexStatus,
    IndexerVersion,
    User,
)
from data.registry_model.datatypes import Manifest as ManifestDataType
from data.registry_model import registry_model

from test.fixtures import *

from app import app, instance_keys, storage


def test_load_security_information_queued(initialized_db):
    repository_ref = registry_model.lookup_repository("devtable", "simple")
    tag = registry_model.get_repo_tag(repository_ref, "latest", include_legacy_image=True)
    manifest = registry_model.get_manifest_for_tag(tag, backfill_if_necessary=True)

    secscan = V4SecurityScanner(app, instance_keys, storage)
    assert secscan.load_security_information(manifest).status == ScanLookupStatus.NOT_YET_INDEXED


def test_load_security_information_failed_to_index(initialized_db):
    repository_ref = registry_model.lookup_repository("devtable", "simple")
    tag = registry_model.get_repo_tag(repository_ref, "latest", include_legacy_image=True)
    manifest = registry_model.get_manifest_for_tag(tag, backfill_if_necessary=True)

    mss = ManifestSecurityStatus(
        manifest=manifest._db_id,
        repository=repository_ref._db_id,
        error_json='failed to fetch layers: encountered error while fetching a layer: fetcher: unknown content-type "binary/octet-stream"',
        index_status=IndexStatus.FAILED,
        indexer_hash="",
        indexer_version=IndexerVersion.V4,
        metadata_json={},
    )
    mss.save()

    secscan = V4SecurityScanner(app, instance_keys, storage)
    assert secscan.load_security_information(manifest).status == ScanLookupStatus.FAILED_TO_INDEX


def test_perform_indexing_whitelist(initialized_db):
    app.config["SECURITY_SCANNER_V4_NAMESPACE_WHITELIST"] = ["devtable"]
    expected_manifests = (
        Manifest.select().join(Repository).join(User).where(User.username == "devtable")
    )

    secscan = V4SecurityScanner(app, instance_keys, storage)
    secscan._secscan_api = mock.Mock()
    secscan._secscan_api.state.return_value = "abc"
    secscan._secscan_api.index.return_value = (
        {"err": None, "state": IndexReportState.INDEX_FINISHED},
        "abc",
    )

    next_token = secscan.perform_indexing()

    assert secscan._secscan_api.index.call_count == expected_manifests.count()
    for mss in ManifestSecurityStatus.select():
        assert mss.repository.namespace_user.username == "devtable"
    assert ManifestSecurityStatus.select().count() == expected_manifests.count()
    assert (
        Manifest.get_by_id(next_token.min_id - 1).repository.namespace_user.username == "devtable"
    )


def test_perform_indexing_no_whitelist(initialized_db):
    app.config["SECURITY_SCANNER_V4_NAMESPACE_WHITELIST"] = []
    secscan = V4SecurityScanner(app, instance_keys, storage)
    secscan._secscan_api = mock.Mock()
    secscan._secscan_api.state.return_value = "abc"
    secscan._secscan_api.index.return_value = (
        {"err": None, "state": IndexReportState.INDEX_FINISHED},
        "abc",
    )

    next_token = secscan.perform_indexing()

    assert secscan._secscan_api.index.call_count == Manifest.select().count()
    assert ManifestSecurityStatus.select().count() == Manifest.select().count()
    assert next_token.min_id == Manifest.select(fn.Max(Manifest.id)).scalar() + 1
