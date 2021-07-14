from http import HTTPStatus

INVALID_ARGUMENT = 'invalid argument'
UNKNOWN = 'unknown'
AUTH_ERROR = 'authorization error'
CONNECTION_ERROR = 'connection error'


class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class AuthorizationError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            AUTH_ERROR,
            f'Authorization failed: {message}'
        )


class InvalidArgumentError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            INVALID_ARGUMENT,
            str(message)
        )


class WatchdogError(TRFormattedError):
    def __init__(self):
        super().__init__(
            code='health check failed',
            message='Invalid Health Check'
        )


class SumoLogicSSLError(TRFormattedError):
    def __init__(self, error):
        error = error.args[0].reason.args[0]
        message = getattr(error, 'verify_message', error.args[0]).capitalize()
        super().__init__(
            UNKNOWN,
            f'Unable to verify SSL certificate: {message}'
        )


class SumoLogicConnectionError(TRFormattedError):
    def __init__(self, url):
        super().__init__(
            CONNECTION_ERROR,
            'Unable to connect to Sumo Logic,'
            f' validate the configured API endpoint: {url}'
        )


class CriticalSumoLogicResponseError(TRFormattedError):
    """
    https://api.us2.sumologic.com/docs/#section/Getting-Started/Status-Codes
    """
    def __init__(self, response):
        possible_statuses = (
            HTTPStatus.UNAUTHORIZED,
            HTTPStatus.FORBIDDEN,
            HTTPStatus.NOT_FOUND,
            HTTPStatus.METHOD_NOT_ALLOWED,
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            HTTPStatus.TOO_MANY_REQUESTS,
            HTTPStatus.INTERNAL_SERVER_ERROR,
            HTTPStatus.SERVICE_UNAVAILABLE,
            HTTPStatus.BAD_REQUEST
        )
        status_code_map = {status: status.phrase
                           for status
                           in possible_statuses}

        super().__init__(
            status_code_map.get(response.status_code),
            f'Unexpected response from SumoLogic: {response.text}'
        )


class SearchJobDidNotFinishWarning(TRFormattedError):
    def __init__(self, observable, search_type):
        super().__init__(
            'search job did not finish',
            f'The {search_type} search job did not finish '
            f'in the time required for {observable}',
            type_='warning'
        )


class MoreMessagesAvailableWarning(TRFormattedError):
    def __init__(self, observable):
        super().__init__(
            'too-many-messages-warning',
            f'There are more messages in Sumo Logic for {observable}'
            ' than can be displayed in Threat Response. Login to the '
            'Sumo Logic console to see all messages.',
            type_='warning'
        )


class SearchJobWrongStateError(TRFormattedError):
    def __init__(self, observable, job_state):
        super().__init__(
            job_state.lower(),
            f'The job was {job_state.lower()} '
            f'before results could be retrieved for {observable}'
        )


class SearchJobNotStartedError(TRFormattedError):
    def __init__(self, observable, job_state):
        super().__init__(
            job_state.lower(),
            f'The job was {job_state.lower()} '
            f'within the required time for {observable}',
        )
