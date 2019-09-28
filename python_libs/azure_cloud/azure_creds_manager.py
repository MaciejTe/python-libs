"""
This file contains Azure credential manager class for credentials operations.
"""
from python_libs.misc.colored_print import ColoredPrint
from python_libs.misc import yaml_oper


class AzureCredentialsManager:
    """
    Class containing credential related methods and properties.
    """

    def __init__(self, config_path):
        self.config_path = config_path
        self._azure_credentials = None
        self.colored_print = ColoredPrint()

    @property
    def credentials(self):
        """
        Property returning Azure credentials object.

        Returns:
            self._azure_credentials (dict): Azure credentials
        """
        if self._azure_credentials is None:
            cfg_data = yaml_oper.read_yaml(self.config_path)
            self._azure_credentials = cfg_data["sp_credentials"]
            for key, cred in self._azure_credentials.items():
                if cred is None:
                    msg = "{} not found in credentials file!".format(key)
                    self.colored_print(msg, level="error")
                    raise Exception(msg)
        return self._azure_credentials
