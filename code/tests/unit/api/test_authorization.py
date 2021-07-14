from unittest.mock import patch
from http import HTTPStatus

from pytest import fixture
from requests.exceptions import InvalidURL, ConnectionError

from tests.unit.api.utils import get_headers
from tests.unit.payloads_for_tests import (
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
    RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY)
from api.errors import AUTH_ERROR
from api.utils import (
    WRONG_PAYLOAD_STRUCTURE,
    WRONG_KEY,
    WRONG_AUDIENCE,
    KID_NOT_FOUND,
    JWKS_HOST_MISSING,
    WRONG_JWKS_HOST,
    WRONG_JWT_STRUCTURE,
    WRONG_AUTH_TYPE,
    NO_AUTH_HEADER)


def routes():
    yield '/health'
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def wrong_jwt_structure():
    return 'wrong_jwt_structure'


@fixture(scope='module')
def authorization_errors_expected_payload(route):
    def _make_payload_message(message):
        payload = {
            'errors': [
                {
                    'code': AUTH_ERROR,
                    'message': f'Authorization failed: {message}',
                    'type': 'fatal'
                }
            ]

        }
        return payload

    return _make_payload_message


def test_call_with_authorization_header_failure(
        route, client,
        authorization_errors_expected_payload):

    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        NO_AUTH_HEADER)


def test_call_with_wrong_authorization_type(
        route, client, valid_jwt,
        authorization_errors_expected_payload):

    response = client.post(
        route, headers=get_headers(valid_jwt(), auth_type='wrong_type'))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUTH_TYPE)


def test_call_with_wrong_jwt_structure(
        route, client, wrong_jwt_structure,
        authorization_errors_expected_payload):

    response = client.post(route, headers=get_headers(wrong_jwt_structure))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_JWT_STRUCTURE)


@patch('requests.get')
def test_call_with_jwt_encoded_by_wrong_key(
        mock_request, route, api_response,
        client, valid_jwt, authorization_errors_expected_payload):

    mock_request.return_value = api_response(
        RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY)
    response = client.post(route, headers=get_headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(WRONG_KEY)


@patch('requests.get')
def test_call_with_wrong_jwt_payload_structure(
        mock_request, api_response,
        route, client, valid_jwt,
        authorization_errors_expected_payload):

    mock_request.return_value = api_response(
        EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    response = client.post(route, headers=get_headers(
        valid_jwt(wrong_structure=True)))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_PAYLOAD_STRUCTURE)


@patch('requests.get')
def test_call_with_wrong_audience(
        mock_request, api_response,
        route, client, valid_jwt,
        authorization_errors_expected_payload):
    mock_request.return_value = api_response(
        EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(route, headers=get_headers(
        valid_jwt(aud='wrong_aud')))
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUDIENCE)


@patch('requests.get')
def test_call_with_wrong_kid(
        mock_request, api_response,
        route, client, valid_jwt,
        authorization_errors_expected_payload):

    mock_request.return_value = api_response(
        EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(route, headers=get_headers(
        valid_jwt(kid='wrong_kid')))
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        KID_NOT_FOUND)


@patch('requests.get')
def test_call_with_missing_jwks_host(
        mock_request, api_response,
        route, client, valid_jwt,
        authorization_errors_expected_payload):

    mock_request.return_value = api_response(
        EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(route, headers=get_headers(
        valid_jwt(missing_jwks_host=True)))
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        JWKS_HOST_MISSING)


@patch('requests.get')
def test_call_with_wrong_jwks_host(
        mock_request, route, client, valid_jwt,
        authorization_errors_expected_payload):

    for error in (ConnectionError, InvalidURL):
        mock_request.side_effect = error()

        response = client.post(route, headers=get_headers(valid_jwt()))

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            WRONG_JWKS_HOST)
