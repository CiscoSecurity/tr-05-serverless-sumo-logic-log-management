from unittest.mock import patch
from http import HTTPStatus

from pytest import fixture, mark
from requests.exceptions import SSLError

from tests.unit.api.utils import get_headers
from tests.unit.payloads_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
from tests.unit.conftest import (
    DONE_GATHERING_RESULTS,
    FORCE_PAUSED,
    CANCELLED,
    NOT_STARTED,
    GATHERING_RESULTS)


def routes():
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json_value():
    return [{'type': 'ip', 'value': ''}]


@patch('requests.get')
def test_enrich_call_with_valid_jwt_but_invalid_json_value(
        mock_get, api_response, client, route, valid_jwt,
        invalid_json_value, invalid_json_expected_payload):
    mock_get.return_value = api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=invalid_json_value)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        "{0: {'value': ['Field may not be blank.']}}"
    )


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'cisco.com'}]


@mark.parametrize(
    "messages_count",
    [99, 101],
)
@patch('requests.request')
@patch('requests.get')
def test_enrich_call_status_done(mock_get, mock_request, api_response,
                                 response_payload_for_create_job_request,
                                 response_payload_for_check_status_request,
                                 response_payload_for_get_messages_request,
                                 client, route, valid_jwt, valid_json,
                                 expected_relay_response, messages_count):

    mock_get.return_value = api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.side_effect = [
        api_response(response_payload_for_create_job_request),
        api_response(response_payload_for_check_status_request(
            DONE_GATHERING_RESULTS,
            messages_count)),
        api_response(response_payload_for_get_messages_request),
        api_response()
    ]
    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == expected_relay_response(
        messages_count=messages_count)


@mark.parametrize(
    "state",
    [CANCELLED, FORCE_PAUSED],
)
@patch('requests.request')
@patch('requests.get')
def test_enrich_call_status_cancelled_or_force_paused(
        mock_get, mock_request, api_response,
        response_payload_for_create_job_request,
        response_payload_for_check_status_request,
        client, route, valid_jwt, valid_json,
        expected_relay_response, state):

    mock_get.return_value = api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.side_effect = [
        api_response(response_payload_for_create_job_request),
        api_response(response_payload_for_check_status_request(state=state))
    ]
    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == expected_relay_response(state=state)


@patch('api.client.SumoLogicClient.SEARCH_JOB_MAX_TIME', 2)
@patch('requests.request')
@patch('requests.get')
def test_enrich_call_not_started(mock_get, mock_request, api_response,
                                 general_response_payload_for_sumo_api_request,
                                 client, route, valid_jwt, valid_json,
                                 expected_relay_response):

    mock_get.return_value = api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.return_value = api_response(
        general_response_payload_for_sumo_api_request(NOT_STARTED))
    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == expected_relay_response(state=NOT_STARTED)


@mark.parametrize(
    "messages_count",
    [99, 101],
)
@patch('api.client.SumoLogicClient.SEARCH_JOB_MAX_TIME', 2)
@patch('requests.request')
@patch('requests.get')
def test_enrich_call_status_gathering_results(
        mock_get, mock_request, api_response,
        general_response_payload_for_sumo_api_request,
        client, route, valid_jwt, valid_json,
        expected_relay_response, messages_count):

    mock_get.return_value = api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.return_value = api_response(
        general_response_payload_for_sumo_api_request(
            GATHERING_RESULTS, messages_count))
    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == expected_relay_response(
        state=GATHERING_RESULTS,
        messages_count=messages_count)


@patch('requests.request')
@patch('requests.get')
def test_enrich_call_with_ssl_error(mock_get, mock_request, api_response,
                                    mock_exception_for_ssl_error,
                                    client, route, valid_jwt, valid_json,
                                    ssl_error_expected_relay_response):
    mock_get.return_value = api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.side_effect = SSLError(mock_exception_for_ssl_error)

    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == ssl_error_expected_relay_response


@patch('requests.request')
@patch('requests.get')
def test_enrich_call_with_bad_request_sumo_logic_error(
        mock_get, mock_request, api_response,
        client, route, valid_jwt, valid_json,
        bad_request_expected_relay_response):

    mock_get.return_value = api_response(EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.return_value = api_response(
        text='Bad request to Sumo Logic',
        status_code=HTTPStatus.BAD_REQUEST)

    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == bad_request_expected_relay_response
