import time

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


class SumoLogicClient:
    DONE_GATHERING_RESULTS = 'DONE GATHERING RESULTS'
    FORCE_PAUSED = 'FORCE PAUSED'
    CANCELLED = 'CANCELLED'
    NOT_STARTED = 'NOT STARTED'
    SEARCH_JOB_MAX_TIME = 50
    CTR_ENTITIES_LIMIT = 100

    def __init__(self, credentials, query_params):
        self._credentials = credentials
        self._search_query = query_params['search_query']
        self._search_time_range = query_params['search_time_range']
        self._check_request_delay = query_params['check_request_delay']
        self._first_check_request_delay = query_params['first_check_request_delay']

    @property
    def _url(self):
        return self._credentials.get('sumo_api_endpoint').rstrip('/')

    def health(self):
        return self._request(path='healthEvents', params={'limit': 1})

    def _request(self, path, method='GET', body=None,
                 params=None, data_extractor=lambda r: r.json()):
        url = '/'.join([self._url, path.lstrip('/')])

        try:
            auth = (
                self._credentials.get('access_id'),
                self._credentials.get('access_key')
            )
            response = requests.request(method, url, json=body,
                                        params=params, auth=auth)
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
            'from': current_time - self._search_time_range,
            'to': current_time
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
    pass


class JudgementVerdict(SumoLogicClient):
    pass
