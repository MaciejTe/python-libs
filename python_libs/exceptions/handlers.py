"""
This file contains common exceptions handlers made with use of decorators.
"""
from requests.exceptions import Timeout, RequestException
from zeep import exceptions

from python_libs.misc.colored_print import ColoredPrint

COLORED_PRINT = ColoredPrint()


def catch_requests_errors(api_func):
    """
    Decorator which executes wrapped function, bundled with try and
    except clause

    Args:
        api_func (method): API method to be executed

    Returns:
        wrapper (function): result from wrapped function
    """

    def wrapper(*args, **kwargs):
        try:
            return api_func(*args, **kwargs)
        except Timeout as tout_err:
            COLORED_PRINT("TIMEOUT! DETAILS : {}".format(tout_err), level="error")
            raise
        except RequestException as err:
            COLORED_PRINT(
                "FAILED TO ESTABLISH NEW CONNECTION! DETAILS: " "{}".format(err),
                level="error",
            )
            raise

    return wrapper


def catch_zeep_errors(func):
    """
    Decorator which executes wrapped function, bundled with try and
    except clause

    Args:
        func (method): method to be executed

    Returns:
        wrapper (function): result from wrapped function
    """

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError as err:
            COLORED_PRINT("Error! Details: {}".format(err.__repr__()), level="error")
            raise
        except exceptions.Fault as soap_err:
            COLORED_PRINT(
                "Error! Details: {}".format(soap_err.__repr__()), level="error"
            )
            raise

    return wrapper
