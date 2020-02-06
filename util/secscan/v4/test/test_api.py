from util.secscan.v4.api import ClairSecurityScannerAPI


# TODO(alecmerdler): Mock `requests` client (see how we do it in other tests)...
client = None
endpoint = "http://clair-indexer:80"


def test_state():
    api = ClairSecurityScannerAPI(endpoint, client)
    pass
