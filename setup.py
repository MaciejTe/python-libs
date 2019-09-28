"""
This file contains avid_ecd_test's packaging configuration.
"""
import re
from setuptools import setup, find_packages


def get_latest_version():
    """ Get latest application version from the CHANGELOG.md file.
        Returns:
            latest_version(str): latest version of the application,
                                 or ?.?.? in case of incorrectly formatted file.
    """
    changelog_file_path = "CHANGELOG.md"
    with open(changelog_file_path, "r") as change_file:
        changes = change_file.readlines()

    ver_regex = r"(?P<ver>\d{1}.\d{1}.\d{1})\s+\(\d+.\d+.\d+\)\s*\Z"
    versions = [
        re.match(ver_regex, line).groupdict()["ver"]
        for line in changes
        if re.match(ver_regex, line)
    ]

    versions_splitted = [tuple(ver.split(".")) for ver in versions]
    versions_splitted.sort(key=lambda x: (x[0], x[1], x[2]))
    try:
        latest_version = ".".join(versions_splitted.pop())
    except IndexError:
        latest_version = "?.?.?"

    return latest_version


def get_requirements():
    """ Get installation requirements from file.

        Returns:
            requirements(list): required packages
    """
    requirements = list()
    with open("requirements.txt", "r") as req:
        requirements = [package.strip() for package in req.readlines()]
    return requirements


setup(
    name="python-libs",
    version=get_latest_version(),
    packages=find_packages(),
    include_package_data=True,
    author="Maciej Tomczuk",
    author_email="tomczukmaciej@gmail.com",
    install_requires=get_requirements(),
)
