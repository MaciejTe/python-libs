""" Module responsible for establishing and managing SSH connections.

    Classes:
        SshManager
"""
import atexit
import re
import logging
import time
from queue import Queue

import click
import paramiko


LOGGER = logging.getLogger(__name__)


class SshManager:
    """ SSH connection and command execution manager class.

        Context manager example:
            with SshManager(credentials, config) as ssh_mngr:
                ssh_mngr.execute_command(command)
                while ssh_mngr.output_queue.empty():
                    print(ssh_mngr.output_queue.get())
        (connection is established at the time object is created)

        Standard usage example:
            ssh_mngr = SshManager(credentials, config)
            <do some stuff>
            ssh_mngr.ssh_mngr.execute_command(command)
            while ssh_mngr.output_queue.empty():
                    print(ssh_mngr.output_queue.get())
            ssh_mngr.close_connection()
        (connection is established during execute_command execution)
    """

    def __init__(
        self, credentials, auto_connect=True, connect_timeout=20, private_key_path=None
    ):
        """ Constructor for the SshManager class.
            Credentials and config arguments are usually taken
            from Click context object.

            Args:
                credentials(dict): user, password and host data
                auto_connect(bool): if set as False, connection is establised
                                    during command execution,
                                    not during __enter__ method execution.
        """
        self._username = credentials["user"]
        self._password = credentials["password"]
        self._port = credentials["port"]
        self._host = credentials["host"]
        self._auto_connect = auto_connect
        self._connect_timeout = connect_timeout
        self._connection = None
        self._output_queue = None
        self._err_queue = None
        self.output_ready = False
        self.running_process = False
        self.private_key_path = private_key_path

    def __enter__(self):
        """ Context manager function implementing the behaviour
            at the beginning of object usage with the 'with' statement.
        """
        LOGGER.info("Executing __enter__ function of SshManager class.")
        atexit.register(self.close_connection)
        if self._auto_connect:
            self.connection
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """ Context manager function implementing the behaviour
            at the end of object usage with the 'with' statement.
        """
        LOGGER.info("Executing __exit__ function of SshManager class.")
        if exc_type:
            LOGGER.error("Exception type: %s", exc_type)
        if exc_value:
            LOGGER.error("Exception value: %s", exc_value)
        if traceback:
            LOGGER.error("Traceback: %s", traceback)

        self.running_process = False
        if self._connection is not None:
            self.close_connection()

    @property
    def output_queue(self):
        """ Property method for creating queue object for stdout content.

            Returns:
                self._output_queue(Queue): FIFO queue object.
        """
        if self._output_queue is None:
            self._output_queue = Queue()
        return self._output_queue

    @output_queue.setter
    def output_queue(self, item):
        """ Setter for the output_queue property.

            If attribute is a Queue object, replaces whole variable.

            Args:
                item(object): argument to set

            Returns:
                self._output_queue(Queue): FIFO queue object
        """
        if not isinstance(item, Queue):
            item.strip("\n")
            self._output_queue.put(item)
        else:
            self._output_queue = item
        return self._output_queue

    @property
    def err_queue(self):
        """ Property method for creating queue object for stderr content.

            Returns:
                self._err_queue(Queue): FIFO queue object.
        """
        if self._err_queue is None:
            self._err_queue = Queue()
        return self._err_queue

    @err_queue.setter
    def err_queue(self, item):
        """ Setter for the err_queue property.

            If attribute is a Queue object, replaces whole variable.

            Args:
                item(object): argument to set

            Returns:
                self.err_queue(Queue): FIFO queue object
        """
        if not isinstance(item, Queue):
            item.strip("\n")
            self._err_queue.put(item)
        else:
            self._err_queue = item
        return self._err_queue

    @property
    def connection(self):
        """ Property method for establishing ssh connection to the server.
            Connection is established only once in objects lifetime.

            Returns:
                self._connection(SSHClient): ssh connection object
        """
        if self._connection is None:
            LOGGER.info("Establishing SSH connection to %s", self._host)
            ssh = paramiko.SSHClient()
            # TODO: change to key exchange handled by user!
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=self._host,
                username=self._username,
                password=self._password,
                timeout=self._connect_timeout,
                key_filename=self.private_key_path,
                port=self._port,
            )
            self._connection = ssh
            self.running_process = True
        return self._connection

    def execute_command(self, command, timeout=30):
        """ Command execution.

            Args:
                command(str): command to execute.
                timeout(int): timeout in seconds.
        """
        LOGGER.info("Executing command: %s", command)
        ssh_transp = self.connection.get_transport()
        channel = ssh_transp.open_channel(kind="session", timeout=int(timeout))
        channel.settimeout(int(timeout))
        channel.get_pty()
        channel.exec_command(command=command)
        self._get_channel_output(channel, extra_wait=0)
        self.running_process = False

    def execute_interactive_command(
        self,
        command,
        interaction=None,
        ending=None,
        timeout=300,
        extra_wait=None,
        ending_err=None,
    ):
        """ Command execution with interaction - suited for interactive
            commands execution.

            Args:
                command(str): command to execute.
                interaction(dict): expected string as a key, string to pass
                                   to the command as a value
                ending(str): string that is expected after all interactions
                             execution
                extra_wait(int): extends timeout during checking output
                ending_err(str): string that ins expected as an error
                timeout(int): timeout in seconds.

            Raises:
                ValueError: if expected string was not found
                ClickException: if expected ending string was not found
        """
        LOGGER.info("Executing command: %s", command)

        ssh_transp = self.connection.get_transport()
        channel = ssh_transp.open_channel(kind="session", timeout=int(timeout))
        channel.settimeout(int(timeout))
        channel.get_pty()
        channel.invoke_shell()

        channel.send(command + "\n")

        if interaction:
            for expected, answer in interaction.items():
                time.sleep(1)
                temp_output = self._get_channel_output(channel)
                if expected in temp_output:
                    channel.send(answer + "\n")
                else:
                    channel.close()
                    msg = 'Expected string: "{}" not found in output.'.format(expected)
                    LOGGER.error(msg)
                    raise ValueError(msg)

        temp_output = self._get_channel_output(
            channel, wait_time=10, extra_wait=extra_wait
        )
        ssh_transp.close()
        self.running_process = False

        if ending and not re.search(ending, repr(temp_output)):
            msg = 'Expected ending: "{}" not found in commands output.'.format(ending)
            LOGGER.error(msg)
            raise click.ClickException(msg)

        if ending_err and re.search(ending_err, repr(temp_output)):
            msg = 'Error ending: "{}" found in commands output.'.format(ending_err)
            LOGGER.error(msg)
            raise click.ClickException(msg)

    def close_connection(self):
        """ Close ssh connection to the server. """
        LOGGER.info("Closing SSH connection.")
        self.running_process = False
        if self._connection:
            self._connection.close()
            self._connection = None

    def _get_channel_output(self, channel, wait_time=2, extra_wait=None):
        """ Receive output from opened channel.
            Output is passed to respective queue and stored in a variable.

            Args:
                channel(Channel): opened paramiko channel
                wait_time(int): standard sleep time
                extra_wait(int): additional sleep time

            Returns:
                temp_output(str): concatenated channel output
        """
        if extra_wait:
            extra_wait_repeats = 6
            extra_wait_time = extra_wait // extra_wait_repeats

        extra_wait_actual_step = 0

        temp_output = str()
        repeat = True
        while True:
            if len(temp_output) >= 2000:
                temp_output = temp_output[2000:]
            time.sleep(wait_time)

            while channel.recv_ready():
                extra_wait_actual_step = 0
                repeat = True
                output = channel.recv(1024)
                if isinstance(output, bytes):
                    output = output.decode("utf-8")
                self.output_queue.put(output)
                temp_output += output

            while channel.recv_stderr_ready():
                extra_wait_actual_step = 0
                repeat = True
                output = channel.recv(1024)
                if isinstance(output, bytes):
                    output = output.decode("utf-8")
                self.err_queue.put(output)
                temp_output += output

            # TODO: Check if channel.recv_ready() is not causing the
            # problem with breaking too early
            if channel.exit_status_ready() or not channel.recv_ready():
                if repeat:
                    time.sleep(wait_time)
                    if extra_wait and extra_wait_actual_step < extra_wait_repeats:
                        msg = "Extra wait: repeat {}".format(extra_wait_actual_step)
                        LOGGER.info(msg)
                        time.sleep(extra_wait_time)
                        extra_wait_actual_step += 1
                        continue
                    repeat = False
                    continue
                else:
                    break

        return temp_output

    def _wait_for_output_ready(self, max_time=15):
        """ Wait untill self.output_ready variable will be True,
            or untill max_time will be exceeded.

            Must be used together with threaded wait_for_output function
            with self.output_ready handling.

            Args:
                max_time(int): maximum wait time
        """
        current_time = 0
        while not self.output_ready:
            time.sleep(1)
            current_time += 1
            if current_time >= max_time:
                break

    def _clean_queues(self):
        """ Clean the output queues. """
        self.output_queue = Queue()
        self.err_queue = Queue()
