"""
This file contains common functions which are widely used across
avid-ecd-tests project.
"""
import logging
import os

from python_libs.misc.colored_print import ColoredPrint

LOGGER = logging.getLogger()
COLORED_PRINT = ColoredPrint()


def save_data_to_file(file, data):
    """ Save given data to file. By default saves in ECD_TM report directory.

    Args:
        data (str): data to be stored in file
        file (str): path to file where data will be stored
    """
    msg = "Saving data to file {}...".format(file)
    LOGGER.info(msg)
    COLORED_PRINT(msg)
    os.makedirs(os.path.dirname(file), exist_ok=True)
    with open(file, "a+") as f:
        f.write(data)


def check_if_env_var_exists(env):
    """ Check if given evironment variable exists.

    Args:
        env (str): environment variable name
    """
    LOGGER.info("Environment variables checking...")
    if env in os.environ:
        LOGGER.info("Environment variable %s found!", env)
    else:
        err_msg = "Environment variable {} was not found!".format(env)
        LOGGER.error(err_msg)
        raise Exception(err_msg)
