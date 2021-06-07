from unittest.mock import MagicMock
from http import HTTPStatus

import jwt
from pytest import fixture

from app import app
from api.errors import INVALID_ARGUMENT
from tests.unit.payloads_for_tests import PRIVATE_KEY


DONE_GATHERING_RESULTS = 'DONE GATHERING RESULTS'
FORCE_PAUSED = 'FORCE PAUSED'
CANCELLED = 'CANCELLED'
NOT_STARTED = 'NOT STARTED'
GATHERING_RESULTS = 'GATHERING RESULTS'


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            access_id='some_id',
            access_key='some_key',
            sumo_api_endpoint='https://api.us2.sumologic.com/api/v1/',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False,
            missing_jwks_host=False
    ):
        payload = {
            'accessId': access_id,
            'accessKey': access_key,
            'sumo_api_endpoint': sumo_api_endpoint,
            'jwks_host': jwks_host,
            'aud': aud,
        }

        if wrong_structure:
            payload.pop('accessKey')

        if missing_jwks_host:
            payload.pop('jwks_host')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='module')
def invalid_json_expected_payload():
    def _make_message(message):
        return {
            'errors': [{
                'code': INVALID_ARGUMENT,
                'message': message,
                'type': 'fatal'
            }]
        }

    return _make_message


@fixture
def api_response():
    def _make_mock(payload=None, text=None, status_code=HTTPStatus.OK):
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.ok = status_code == HTTPStatus.OK
        mock_response.json = lambda: payload
        mock_response.text = text
        return mock_response
    return _make_mock


def mock_api_response(status_code=HTTPStatus.OK, payload=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.json = lambda: payload

    return mock_response


@fixture(scope='module')
def search_id():
    return '347A844D53240C86'


@fixture(scope='module')
def response_payload_for_create_job_request(search_id):
    response = {
        'id': search_id,
        'link': {
            'rel': 'self',
            'href': f'https://api.us2.sumologic.com/api/v1'
                    f'/search/jobs/{search_id}'
        }
    }
    return response


@fixture(scope='module')
def response_payload_for_check_status_request():
    def _make_response_payload(state, messages_count=None):
        response = {
            'state': state
        }
        if state in [DONE_GATHERING_RESULTS, GATHERING_RESULTS]:
            response['messageCount'] = messages_count
        return response
    return _make_response_payload


@fixture(scope='module')
def response_payload_for_get_messages_request():
    return {
        'fields': [],
        'messages': [
            {
                'map':
                    {
                        'msg': 'TCP access denied by ACL from 188.163.104.233'
                               '/18488 to outside:24.141.139.103/80',
                        '_collector': 'devbox-collector',
                        '_messageid': '702686314684941315',
                        '_size': '100',
                        'protocol': 'TCP',
                        'action': 'access denied',
                        'dest_port': '80',
                        'log_level': '3',
                        '_sourceid': '1426092243',
                        'dest_ip': '24.141.139.103',
                        '_source': 'qradar',
                        '_raw': '<163>%ASA-3-710003: TCP access denied by ACL '
                                'from 188.163.104.233/18488 to '
                                'outside:24.141.139.103/80',
                        '_collectorid': '226880368',
                        '_sourcehost': '10.100.20.1',
                        'dest_zone': 'outside',
                        'src_ip': '10.100.20.1',
                        '_format': 't:fail:o:-1:l:0:p:null',
                        '_blockid': '702686118961939456',
                        '_messagetime': '1619720153842',
                        '_messagecount': '667',
                        'message_id': '710003',
                        'src_ipv6': '',
                        '_sourcename': 'local use 4  (local4)',
                        '_receipttime': '1619720153842',
                        '_sourcecategory': 'syslog'
                    }
            }
        ]
    }


@fixture(scope='module')
def general_response_payload_for_sumo_api_request(
        search_id, response_payload_for_get_messages_request):
    def _make_general_response(state=None, messages_count=None):
        response = {
            'id': search_id,
            'link': {
                'rel': 'self',
                'href': f'https://api.us2.sumologic.com/api/v1/search/jobs'
                        f'/{search_id}'
            },
            'state': state,
            'messageCount': messages_count,
        }
        response.update(response_payload_for_get_messages_request)
        return response
    return _make_general_response


@fixture
def expected_relay_response(sighting_base_payload):
    def _make_payload(state=None, messages_count=0):
        sighting_base_payload['errors'] = []
        if state == GATHERING_RESULTS:
            sighting_base_payload['errors'].append(
                {
                    'code': 'search job did not finish',
                    'message': 'The search job did not finish in the time '
                               'required for cisco.com',
                    'type': 'warning'
                }
            )
        if state in [CANCELLED, FORCE_PAUSED]:
            sighting_base_payload['errors'].append(
                {
                    'code': state.lower(),
                    'message': f'The job was {state.lower()} before results '
                               f'could be retrieved for cisco.com',
                    'type': 'fatal'
                }
            )
            sighting_base_payload.pop('data')
        if state == NOT_STARTED:
            sighting_base_payload['errors'].append(
                {
                    'code': state.lower(),
                    'message': f'The job was {state.lower()} within the '
                               f'required time for cisco.com',
                    'type': 'fatal'
                }
            )
            sighting_base_payload.pop('data')
        if messages_count > 100:
            sighting_base_payload['errors'].append(
                {
                    'code': 'more messages are available',
                    'message': 'There are more messages in Sumo Logic '
                               'for cisco.com '
                               'than can be displayed in Threat Response.',
                    'type': 'warning'
                }
            )
        if not sighting_base_payload['errors']:
            sighting_base_payload.pop('errors')
        return sighting_base_payload
    return _make_payload


@fixture
def sighting_base_payload():
    return {
        'data': {
            'sightings': {
                'count': 1,
                'docs': [
                    {
                        'confidence': 'High',
                        'count': 667,
                        'data': {
                            'columns': [
                                {
                                    'name': 'msg',
                                    'type': 'string'
                                },
                                {
                                    'name': 'protocol',
                                    'type': 'string'
                                },
                                {
                                    'name': 'action',
                                    'type': 'string'
                                },
                                {
                                    'name': 'dest_port',
                                    'type': 'string'
                                },
                                {
                                    'name': 'log_level',
                                    'type': 'string'
                                },
                                {
                                    'name': 'dest_ip',
                                    'type': 'string'
                                },
                                {
                                    'name': 'dest_zone',
                                    'type': 'string'
                                },
                                {
                                    'name': 'src_ip',
                                    'type': 'string'
                                },
                                {
                                    'name': 'message_id',
                                    'type': 'string'
                                }
                            ],
                            'rows': [
                                [
                                    'TCP access denied by ACL '
                                    'from 188.163.104.233/18488 '
                                    'to outside:24.141.139.103/80',
                                    'TCP',
                                    'access denied',
                                    '80',
                                    '3',
                                    '24.141.139.103',
                                    'outside',
                                    '10.100.20.1',
                                    '710003'
                                ]
                            ]
                        },
                        'description': '```\n<163>%ASA-3-710003: TCP access '
                                       'denied by ACL '
                                       'from 188.163.104.233/18488 '
                                       'to outside:24.141.139.103/80\n```',
                        'external_ids': ['702686314684941315'],
                        'id': '702686314684941315',
                        'internal': True,
                        'observables': [
                            {
                                'type': 'domain',
                                'value': 'cisco.com'
                            }
                        ],
                        'observed_time': {
                            'start_time': '2021-04-29T18:15:53.842+00:00'
                        },
                        'relations': [
                            {
                                'origin': 'qradar',
                                'related': {
                                    'type': 'ip',
                                    'value': '24.141.139.103'
                                },
                                'relation': 'Connected_To',
                                'source': {
                                    'type': 'ip',
                                    'value': '10.100.20.1'
                                }
                            }
                        ],
                        'schema_version': '1.1.5',
                        'short_description': 'devbox-collector received a log '
                                             'from qradar - local use 4  '
                                             '(local4) containing the '
                                             'observable',
                        'source': 'Sumo Logic',
                        'title': 'Log message from last 30 days in Sumo Logic '
                                 'contains observable',
                        'type': 'sighting'
                    }
                ]
            }
        }
    }


@fixture(scope='module')
def bad_request_expected_relay_response():
    return {
        'errors':
            [
                {
                    'code': 'Bad Request',
                    'message': 'Unexpected response from SumoLogic: '
                               'Bad request to Sumo Logic',
                    'type': 'fatal'
                }
            ]
    }


@fixture(scope='module')
def ssl_error_expected_relay_response():
    return {
        'errors':
            [
                {
                    'code': 'unknown',
                    'message':
                        'Unable to verify SSL certificate: '
                        'Self signed certificate',
                    'type': 'fatal'
                }
            ]
    }


@fixture
def mock_exception_for_ssl_error():
    mock_response = MagicMock()
    mock_response.reason.args.__getitem__().verify_message = 'self signed' \
                                                             ' certificate'
    return mock_response
