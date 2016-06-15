import yaml
import json


def load_and_merge(file_path=None, defaults=None):
    """
    Load a given file and apply defaults as specified to any values not present in the file.
    Does a merge of the file and defaults and returns a dict with the results
    :param file_path: file to load. Supports .yaml and .json files
    :param defaults: dict with defaults in correct structure to compare and overlay with the values from the file
    :return: a new dict with the merged results
    """

    ret = None
    if defaults is not None:
        ret = defaults.copy()

    file_data = None
    if file_path is not None:
        with open(file_path) as f:
            if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                file_data = yaml.safe_load(f)
            elif file_path.endswith('.json'):
                file_data = json.load(f.read())
    else:
        file_data = {}

    if file_data is not None:
        if ret is not None:
            ret.update(file_data)
            return ret
        else:
            return file_data
    else:
        return ret
