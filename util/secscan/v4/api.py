from abc import ABCMeta, abstractmethod
from six import add_metaclass
from urlparse import urljoin
import logging
import requests
import json

from data.registry_model.datatypes import Manifest as ManifestDataType
from data.model.storage import get_storage_locations


logger = logging.getLogger(__name__)


class APIRequestFailure(Exception):
    """
    Exception raised when there is a failure to conduct an API request.
    """


class Non200ResponseException(Exception):
    """
    Exception raised when the upstream API returns a non-200 HTTP status code.
    """

    def __init__(self, response):
        super(Non200ResponseException, self).__init__()
        self.response = response


@add_metaclass(ABCMeta)
class SecurityScannerAPIInterface(object):
    @abstractmethod
    def state(self):
        """
        The state endpoint returns a json structure indicating the indexer's internal configuration state. 
        A client may be interested in this as a signal that manifests may need to be re-indexed.
        """
        pass

    @abstractmethod
    def index(self, manifest, layers):
        """
        By submitting a Manifest object to this endpoint Clair will fetch the layers, 
        scan each layer's contents, and provide an index of discovered packages, repository and distribution information.
        Returns a tuple of the `IndexReport` and the indexer state.
        """
        pass

    @abstractmethod
    def index_report(self, manifest_hash):
        """
        Given a Manifest's content addressable hash an IndexReport will be retrieved if exists.
        """
        pass

    @abstractmethod
    def vulnerability_report(self, manifest_hash):
        """
        Given a Manifest's content addressable hash a VulnerabilityReport will be created. 
        The Manifest must have been Indexed first via the Index endpoint.
        """
        pass


class ClairSecurityScannerAPI(SecurityScannerAPIInterface):
    def __init__(self, endpoint, client, storage):
        self._client = client
        self._storage = storage
        self.secscan_api_endpoint = urljoin(endpoint, "/api/v1/")

    def state(self):
        try:
            resp = self._call("GET", "state")
        except Non200ResponseException as ex:
            msg = (
                "Security scanner endpoint responded with non-200 HTTP status code: %s"
                % ex.message.status_code
            )
            logger.exception(msg)
            raise Exception(msg)
        except requests.exceptions.ConnectionError as ce:
            logger.exception("Connection error when trying to connect to security scanner endpoint")
            msg = (
                "Connection error when trying to connect to security scanner endpoint: %s"
                % ce.message
            )
            raise Exception(msg)

        return resp.json()

    def index(self, manifest, layers):
        assert isinstance(manifest, ManifestDataType) and not manifest.is_manifest_list

        uri_for = lambda layer: self._storage.get_direct_download_url(
            self._storage.locations, l.blob.storage_path
        )
        body = {
            "hash": manifest.digest,
            "layers": [
                {
                    "hash": l.layer_info.blob_digest,
                    "uri": uri_for(l),
                    "headers": {"Accept": ["application/gzip"],},
                }
                for l in layers
            ],
        }

        try:
            resp = self._call("POST", "index_report", body=body)
        except requests.exceptions.ConnectionError as ce:
            logger.exception("Connection error when trying to connect to security scanner endpoint")
            msg = (
                "Connection error when trying to connect to security scanner endpoint: %s"
                % ce.message
            )
            raise Exception(msg)
        except Non200ResponseException as ex:
            raise APIRequestFailure(ex.message)

        return (resp.json(), resp.headers["etag"])

    def index_report(self, manifest_hash):
        try:
            resp = self._call("GET", "index_report/" + manifest_hash)
        except Non200ResponseException as ex:
            return None

        return resp.json()

    def vulnerability_report(self, manifest_hash):
        try:
            resp = self._call("GET", "vulnerability_report/" + manifest_hash)
        except Non200ResponseException as ex:
            return None

        return resp.json()

    def _call(self, method, path, params=None, body=None):
        url = urljoin(self.secscan_api_endpoint, path)

        logger.debug("%sing security URL %s", method.upper(), url)
        resp = self._client.request(method, url, params=params, json=body)

        if resp.status_code // 100 != 2:
            raise Non200ResponseException(resp)

        return resp
