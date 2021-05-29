import requests
from requests.exceptions import SSLError

from api.errors import (
    SumoLogicSSLError,
    CriticalSumoLogicResponseError
)


class SumoLogicClient:
    def __init__(self, credentials):
        self._credentials = credentials

    @property
    def _url(self):
        return self._credentials.get("sumo_api_endpoint").rstrip("/")

    def health(self):
        return self._request('healthEvents', params={'limit': 1})

    def _request(self, path, method='GET',
                 body=None, params=None, data_extractor=lambda r: r.json()):
        url = '/'.join([self._url, path.lstrip('/')])

        try:
            auth = (
                self._credentials.get("accessId"),
                self._credentials.get("accessKey")
            )
            response = requests.request(method, url, json=body,
                                        params=params, auth=auth)
        except SSLError as error:
            raise SumoLogicSSLError(error)

        if response.ok:
            return data_extractor(response)

        raise CriticalSumoLogicResponseError(response)
