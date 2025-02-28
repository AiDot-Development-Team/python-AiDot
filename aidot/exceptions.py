"""aidot Exceptions."""


class AidotError(Exception):
    """Aidot api exception."""


class InvalidURL(AidotError):
    """Invalid url exception."""


class HTTPError(AidotError):
    """Invalid host exception."""


class InvalidHost(AidotError):
    """Invalid host exception."""


class AidotAuthTokenExpired(AidotError):
    """Authentication failed because token is invalid or expired."""


class AidotAuthFailed(AidotError):
    """Authentication failed"""


class AidotNotLogin(AidotError):
    """Aidot not login"""


class AidotUserOrPassIncorrect(AidotError):
    """Authentication failed"""


class AidotOSError(Exception):
    """Aidot exception."""
