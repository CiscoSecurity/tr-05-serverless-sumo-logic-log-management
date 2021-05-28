from base64 import b64encode

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

    @property
    def _headers(self):
        encoded = b64encode(f'{self._credentials.get("accessId")}:'
                            f'{self._credentials.get("accessKey")}'.encode())
        return {'Authorization': f'Basic {encoded.decode()}'}

    def health(self):
        return self._request('healthEvents')

    def _request(self, path, method='GET',
                 body=None, params=None, data_extractor=lambda r: r.json()):
        url = '/'.join([self._url, path.lstrip('/')])

        try:
            response = requests.request(method, url, headers=self._headers,
                                        json=body, params=params)
        except SSLError as error:
            raise SumoLogicSSLError(error)

        if response.ok:
            return data_extractor(response)

        raise CriticalSumoLogicResponseError(response)
