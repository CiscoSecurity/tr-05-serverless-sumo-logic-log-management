from http import HTTPStatus

INVALID_ARGUMENT = 'invalid argument'
UNKNOWN = 'unknown'
AUTH_ERROR = 'authorization error'


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
            HTTPStatus.SERVICE_UNAVAILABLE
        )
        status_code_map = {}
        for status in possible_statuses:
            status_code_map[status] = status.phrase

        super().__init__(
            status_code_map.get(response.status_code),
            f'Unexpected response from SumoLogic: {response.text}'
        )
