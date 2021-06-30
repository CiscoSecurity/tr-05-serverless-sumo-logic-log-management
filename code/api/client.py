import time
from abc import ABC, abstractmethod

import requests
from requests.exceptions import SSLError, ConnectionError, MissingSchema

from api.errors import (
    SumoLogicSSLError,
    SumoLogicConnectionError,
    CriticalSumoLogicResponseError,
    SearchJobWrongStateError,
    SearchJobNotStartedError,
    SearchJobDidNotFinishWarning,
    MoreMessagesAvailableWarning)
from api.utils import add_error


class SumoLogicClient(ABC):
    DONE_GATHERING_RESULTS = 'DONE GATHERING RESULTS'
    FORCE_PAUSED = 'FORCE PAUSED'
    CANCELLED = 'CANCELLED'
    NOT_STARTED = 'NOT STARTED'
    SEARCH_JOB_MAX_TIME = 50
    CTR_ENTITIES_LIMIT = 100

    def __init__(self, credentials):
        self._credentials = credentials

    @property
    def _url(self):
        return self._credentials.get('sumo_api_endpoint').rstrip('/')

    @property
    def _auth(self):
        return (self._credentials.get('access_id'),
                self._credentials.get('access_key'))

    @property
    @abstractmethod
    def _search_query(self):
        """Returns the query search."""

    @property
    @abstractmethod
    def _search_time_range(self):
        """Returns the time range for search."""

    @property
    @abstractmethod
    def _check_request_delay(self):
        """Returns the delay between status checks in seconds."""

    @property
    @abstractmethod
    def _first_check_request_delay(self):
        """Returns the delay between first status checks in seconds."""

    def health(self):
        return self._request(path='healthEvents', params={'limit': 1})

    def _request(self, path, method='GET', body=None,
                 params=None, data_extractor=lambda r: r.json()):
        url = '/'.join([self._url, path.lstrip('/')])

        try:
            response = requests.request(method, url, json=body,
                                        params=params, auth=self._auth)
        except SSLError as error:
            raise SumoLogicSSLError(error)
        except (ConnectionError, MissingSchema):
            raise SumoLogicConnectionError(self._url)

        if response.ok:
            return data_extractor(response)

        raise CriticalSumoLogicResponseError(response)

    def get_data(self, observable):
        search_id = self._create_search(observable)
        status_response = self._check_status(search_id)
        time.sleep(self._first_check_request_delay)
        start_time = time.time()

        while status_response['state'] != self.DONE_GATHERING_RESULTS:
            if status_response['state'] in [self.FORCE_PAUSED, self.CANCELLED]:
                raise SearchJobWrongStateError(
                    observable,
                    status_response['state'])
            if time.time() - start_time > self.SEARCH_JOB_MAX_TIME:
                if status_response['state'] == self.NOT_STARTED:
                    raise SearchJobNotStartedError(
                        observable,
                        status_response['state'])
                add_error(SearchJobDidNotFinishWarning(observable))
                break
            status_response = self._check_status(search_id)
            time.sleep(self._check_request_delay)

        if status_response['messageCount'] > self.CTR_ENTITIES_LIMIT:
            add_error(MoreMessagesAvailableWarning(observable))
        messages = self._get_messages(search_id)
        self._delete_job(search_id)
        return messages

    def _create_search(self, observable):
        path = 'search/jobs'
        current_time = int(time.time()) * 10**3
        payload = {
            'query': self._search_query.format(observable),
            # 'from': current_time - self._search_time_range,
            # 'to': current_time
            'from': 1617261824000,
            'to': 1622532224000
        }
        search_result = self._request(path=path, method='POST', body=payload)
        return search_result.get('id')

    def _check_status(self, search_id):
        path = f'search/jobs/{search_id}'
        status_result = self._request(path=path)
        return status_result

    def _get_messages(self, search_id):
        path = f'search/jobs/{search_id}/messages'
        params = {
            'offset': 0,
            'limit': self.CTR_ENTITIES_LIMIT
        }
        messages_result = self._request(path=path, params=params)
        return messages_result['messages']

    def _delete_job(self, search_id):
        path = f'search/jobs/{search_id}'
        self._request(path=path, method='DELETE')


class Sighting(SumoLogicClient):
    @property
    def _search_query(self):
        return '"{}" | limit 101'

    @property
    def _search_time_range(self):
        return 30 * 24 * 60 * 60 * 10**3  # 30 days in milliseconds

    @property
    def _check_request_delay(self):
        return 3

    @property
    def _first_check_request_delay(self):
        return 0  # do not need to delay first request


class JudgementVerdict(SumoLogicClient):
    @property
    def _search_query(self):
        return '| limit 1 | "{}" as observable | lookup raw from sumo://threat/cs on threat=observable'

    @property
    def _search_time_range(self):
        return 15 * 60 * 10**3  # 15 minutes in milliseconds

    @property
    def _check_request_delay(self):
        return 5

    @property
    def _first_check_request_delay(self):
        return 1
