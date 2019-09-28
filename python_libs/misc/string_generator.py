"""
This file contains simple string generator class.
"""
import string
from random import choice, randint


class StringGenerator:
    """
    Simple string generator class.
    """

    def __init__(
        self,
        min_length=5,
        max_length=5,
        letters=True,
        case="both",
        punctuation=False,
        digits=True,
    ):
        """
        Prepare necessary arguments for random string generation.

        Args:
            min_length (int): Minimal length for generated string
            max_length (int): Maximal length for generated string
            letters (bool): Boolean paramater deciding if letters should be
                            included into generated string
            case (str): case size option
                - 'both' for both uppercase and lowercase letters
                - 'uppercase' for generating only uppercase letters
                - 'lowercase' for generating only lowercase letters
            punctuation (bool): Boolean paramater deciding if punctuation
                                should be included into generated string
            digits (bool): Boolean paramater deciding if digits should be
                           included into generated string

        Raises:
            Exception: when following conditions are met:
                * if min_length is greater than max_length
                * if given case does not exist in cases_dict
                * when all character types are set to False
        """
        if min_length > max_length:
            raise Exception("min_length has to be lower than max_length!")
        cases_dict = {
            "both": string.ascii_letters,
            "uppercase": string.ascii_uppercase,
            "lowercase": string.ascii_lowercase,
        }
        if case not in cases_dict.keys():
            raise Exception("Improper case option!")
        else:
            self.signs_list = [
                (letters, cases_dict[case]),
                (punctuation, string.punctuation),
                (digits, string.digits),
            ]
        self.signs_bool_list = [letters, punctuation, digits]
        if not any(self.signs_bool_list):
            raise Exception("All signs types cannot be False!")

        self.min_length = min_length
        self.max_length = max_length
        self.allchar = str()

    @property
    def generate(self):
        """
        Property returning generated random string.

        Returns:
            random_string (str): generated string
        """
        for char_type_tuple in self.signs_list:
            if char_type_tuple[0] is True:
                self.allchar += char_type_tuple[1]
        random_string = "".join(
            choice(self.allchar)
            for _ in range(randint(self.min_length, self.max_length))
        )
        return random_string
