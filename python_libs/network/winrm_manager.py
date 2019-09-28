""" Module responsible for establishing and managing WinRM connections.

    Classes:
        WinRMManager
"""
import logging

import winrm

LOGGER = logging.getLogger(__name__)


class WinRMManager:
    """
    Class responsible for WinRM connections.
    There are two ways to use this class:
    1. Use context manager
        with WinRMManager(creds) as winrm_mgr:
            std_out, std_err, status_code = winrm_mgr.run_command('ipconfig', ['/all'])
            // do necessary stuff here

    2. Manual mode
        winrm_mgr = WinRMManager(creds)
        std_out, std_err, status_code = winrm_mgr.run_command(ipconfig', ['/all'])
        // do necessary stuff here
        winrm_mgr.close_shell()
    """

    def __init__(
        self, credentials, transport="credssp", server_cert_validation="ignore"
    ):
        """ Constructor of the WinRMManager class.

        Args:
            credentials(dict): user, password, host and port data
            transport(str): transport option, more info at https://github.com/diyan/pywinrm/#valid-transport-options
            server_cert_validation(str): whether server certificate should be
                                         validated on Python versions that suppport it;
                                         one of 'validate' (default), 'ignore'
        """
        endpoint = "https://{}:{}/wsman".format(
            credentials["host"], str(credentials["port"])
        )
        self.process = winrm.protocol.Protocol(
            endpoint=endpoint,
            transport=transport,
            username=credentials["user"],
            password=credentials["password"],
            server_cert_validation=server_cert_validation,
        )
        self._shell_id = None

    @property
    def shell_id(self):
        """ Property method for opening shell on the destination host.

        Returns:
            self._shell_id(string): Shell ID
        """
        if self._shell_id is None:
            self._shell_id = self.process.open_shell()
        return self._shell_id

    def __enter__(self):
        """
        Context manager function implementing the behaviour
        at the beginning of object usage with the 'with' statement.
        """
        LOGGER.info("Executing __enter__ function of WinRMManager class.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager function implementing the behaviour
        at the end of object usage with the 'with' statement.
        """
        LOGGER.info("Executing __exit__ function of WinRMManager class.")
        if exc_type:
            LOGGER.error("Exception type: %s", exc_type)
        if exc_val:
            LOGGER.error("Exception value: %s", exc_val)
        if exc_tb:
            LOGGER.error("Traceback: %s", exc_tb)

        self.process.close_shell(self.shell_id)
        self._shell_id = None

    def close_shell(self):
        """
        Closes the shell. Uses 'cleanup_command' and 'close_Shell' methdods
        from pywinrm library.
        """
        self.process.close_shell(self.shell_id)

    def run_command(self, cmd, arguments=(), shell_type='powershell'):
        """ Run a command on a machine with an opened shell.

        Args:
            cmd(str): The command to run on the remote machine
            arguments(list): A list of string arguments for this command
            shell_type(str): Windows shell type (powershell or win_cmd)

        Returns:
            std_out(str): executed command's standard output
            std_err(str): executed command's standard error
            status_code(int): executed command's status code
        """
        shell_types = ["powershell", "win_cmd"]
        if shell_type not in shell_types:
            err_msg = "Improper shell type selected! Possible shell types: " \
                      "{}".format(shell_types)
            raise Exception(err_msg)
        encoding = "utf-8"
        if shell_type == "powershell":
            # user needs to use 'path' instead of "path" in commands
            LOGGER.info("Running command using WinRM: ", cmd)
            cmd = "powershell " + "\"{}\"".format(cmd)
        command_id = self.process.run_command(self.shell_id, cmd, arguments)
        std_out, std_err, status_code = self.process.get_command_output(
            self.shell_id, command_id
        )
        self.process.cleanup_command(self.shell_id, command_id)
        return std_out.decode(encoding), std_err.decode(encoding), status_code
