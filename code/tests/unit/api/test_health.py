from unittest.mock import patch
from http import HTTPStatus

from pytest import fixture

from tests.unit.api.utils import get_headers
from tests.unit.payloads_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@patch('requests.request')
@patch('requests.get')
def test_health_call_success(mock_get, mock_request, api_response,
                             client, route, valid_jwt):
    mock_get.return_value = api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.return_value = api_response()
    response = client.post(route, headers=get_headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}
