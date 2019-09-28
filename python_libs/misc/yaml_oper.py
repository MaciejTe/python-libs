"""
This file contains YAML-related operation functions.
"""
import yaml


def read_yaml(yaml_path):
    """
    Read YAML file on given path.

    Args:
        yaml_path (str): YAML file path

    Returns:
        Data structure represented by YAML file
    """
    with open(yaml_path, "r") as stream:
        try:
            return yaml.load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            raise yaml.YAMLError(exc)
