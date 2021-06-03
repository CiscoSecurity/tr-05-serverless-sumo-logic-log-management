import jwt

from app import app
from pytest import fixture
from http import HTTPStatus
from unittest.mock import MagicMock
from api.errors import INVALID_ARGUMENT
from tests.unit.payloads_for_tests import PRIVATE_KEY


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            accessId='some_id',
            accessKey='some_key',
            sumo_api_endpoint='https://api.us2.sumologic.com/api/v1/',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False,
            missing_jwks_host=False
    ):
        payload = {
            'accessId': accessId,
            'accessKey': accessKey,
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


@fixture(scope='function')
def rsa_api_response():
    def _make_mock(payload):
        mock_response = MagicMock()
        mock_response.json = lambda: payload
        return mock_response
    return _make_mock


@fixture(scope='module')
def sumo_logic_health_ok():
    return sumo_logic_api_response_mock(
        HTTPStatus.OK, payload=[{"success": True}]
    )


def mock_api_response(status_code=HTTPStatus.OK, payload=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.json = lambda: payload

    return mock_response


def sumo_logic_api_response_mock(status_code=HTTPStatus.OK, payload=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.json = lambda: payload

    return mock_response
