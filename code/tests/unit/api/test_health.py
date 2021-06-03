from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture

from .utils import get_headers
from tests.unit.payloads_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@patch('requests.request')
@patch('requests.get')
def test_health_call_success(mock_get, mock_request,
                             route, client, rsa_api_response,
                             sumo_logic_health_ok, valid_jwt):
    mock_get.return_value = rsa_api_response(
        EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.return_value = sumo_logic_health_ok
    response = client.post(route, headers=get_headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}
