"""
This file contains ColoredPrint class which is useful for coloured printing
inside Jenkins jobs.
"""
from colorama import Fore, Back, Style


class ColoredPrint:
    """
    This class enables user to print colored messages using __call__ magic
    method.

    Example:
    jenkins_print = ColoredPrint()
    jenkins_print('message', level='error')
    """

    def __call__(self, msg, level="debug"):
        """
        Prints colored messages.

        Args:
            msg (str): message to be printed on the screen
            level (str): message level

        Available message levels:
        1. debug: cyan colored text
        2. pass: green text background
        3. warning: yellow text background
        4. error: red text background

        Returns:
            None
        """
        level_dict = {
            "debug": Fore.CYAN,
            "pass": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
        }
        if level in level_dict.keys():
            print(level_dict[level] + msg + Style.RESET_ALL, flush=True)
        else:
            print(Back.MAGENTA + "ColoredPrint: unrecognized level!" + Style.RESET_ALL)
