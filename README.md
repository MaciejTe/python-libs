[![Coverage Status](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)

# Python libraries

This repository contains my collection of Python classes and libraries.

Currently Python 3.5.6 version is supported.

## Project Structure
At this moment project contains following categories of libraries:

- `azure_cloud` module contains libraries related to Azure cloud provider services
    * ARM driver - common resource group operations (complete documentation in arm_driver.py)
    * Azure credentials manager - Simple class for reading .yaml file with Azure credentials
    * Storage Account - class containing common operations on Azure Storage Accounts
- `exceptions` module contains useful decorators used by other modules and custom exceptions
- `network` module contains network-related classes
    * SSH manager - class responsible for establishing and managing SSH connections
    * WinRM manager - class responsible for establishing and managing WinRM connections
- `misc` module contains other, hard to categorize libraries
    * colored_print.py - class for writing colored output in command line / Jenkins
    * common.py - other functions
    * string_generator.py - simple string generator class
    * yaml_oper.py - YAML-related operation functions


## How to use
Put following line in your project requirements.txt (in this case we use *master* branch):
```bash
git+https://github.com/MaciejTe/python-libs.git@master#egg=python-libs
```

You can also specify tag (0.1):
```bash
git+https://github.com/MaciejTe/python-libs.git0.1#egg=avid-libs
```

Specify commit hash (41b95ec):
```bash
git+https://github.com/MaciejTe/python-libs.git@41b95ec#egg=avid-libs
```

Note: #egg=python-libs is not comment here, it is to explicitly state the package name.

### Docker solutions
In order to make libraries work with __python-alpine__ docker images, following Linux libraries need to be installed:
```commandline
RUN apk add gcc linux-headers libc-dev libffi-dev openssl-dev make
RUN apk add ccache libsodium-dev
# for zeep Python library
RUN apk add libxml2-dev libxslt-dev git
```

Ordinary python docker images do not require any additional Linux libraries.

### Code quality

#### Pylint
In order to keep shared Python code quality high, pylint should be used with .pylintrc file which is present in project repository: 

```commandline
pylint --rcfile=avid-python-libs/.pylintrc avid-python-libs/
```

#### Coding style
Black Python code formatter is used in this project: [Black GitHub repo](https://github.com/ambv/black)
Note: Black can be installed only using Python 3.6 or higher (can be done i.e. in another docker image)
