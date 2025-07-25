from collections import defaultdict
from http import HTTPStatus

INVALID_ARGUMENT = "invalid argument"
UNKNOWN = "unknown"
AUTH_ERROR = "authorization error"
CONNECTION_ERROR = "connection error"
INVALID_CREDENTIALS = "wrong access_id or access_key"
URL_NOT_FOUND = "URL {url} is not found"


class TRFormattedError(Exception):
    def __init__(self, code, message, type_="fatal"):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or "Something went wrong."
        self.type_ = type_

    @property
    def json(self):
        return {"type": self.type_, "code": self.code, "message": self.message}


class AuthorizationError(TRFormattedError):
    def __init__(self, message):
        super().__init__(AUTH_ERROR, f"Authorization failed: {message}")


class InvalidArgumentError(TRFormattedError):
    def __init__(self, message):
        super().__init__(INVALID_ARGUMENT, str(message))


class WatchdogError(TRFormattedError):
    def __init__(self):
        super().__init__(code="health check failed", message="Invalid Health Check")


class SumoLogicSSLError(TRFormattedError):
    def __init__(self, error):
        error = error.args[0].reason.args[0]
        message = getattr(error, "verify_message", error.args[0]).capitalize()
        super().__init__(UNKNOWN, f"Unable to verify SSL certificate: {message}")


class SumoLogicConnectionError(TRFormattedError):
    def __init__(self, url):
        super().__init__(
            CONNECTION_ERROR, f"Unable to connect to Sumo Logic, validate the configured API endpoint: {url}"
        )


class CriticalSumoLogicResponseError(TRFormattedError):
    """https://api.us2.sumologic.com/docs/#section/Getting-Started/Status-Codes"""

    def __init__(self, status_code, response_text=None, url=None):
        status_codes = {
            HTTPStatus.UNAUTHORIZED: INVALID_CREDENTIALS,
            HTTPStatus.NOT_FOUND: URL_NOT_FOUND.format(url=url),
        }
        status_codes = defaultdict(lambda: response_text, status_codes)

        super().__init__(
            HTTPStatus(status_code).phrase, f"Unexpected response from SumoLogic: {status_codes[status_code]}"
        )


class SearchJobDidNotFinishWarning(TRFormattedError):
    def __init__(self, observable, search_type):
        super().__init__(
            "search job did not finish",
            f"The {search_type} search job did not finish in the time required for {observable}",
            type_="warning",
        )


class MoreMessagesAvailableWarning(TRFormattedError):
    def __init__(self, observable):
        super().__init__(
            "too-many-messages-warning",
            f"There are more messages in Sumo Logic for {observable} than can be displayed in Threat Response."
            " Login to the Sumo Logic console to see all messages.",
            type_="warning",
        )


class SearchJobWrongStateError(TRFormattedError):
    def __init__(self, observable, job_state):
        super().__init__(
            job_state.lower(), f"The job was {job_state.lower()} before results could be retrieved for {observable}"
        )


class SearchJobNotStartedError(TRFormattedError):
    def __init__(self, observable, job_state):
        super().__init__(
            job_state.lower(),
            f"The job was {job_state.lower()} within the required time for {observable}",
        )
