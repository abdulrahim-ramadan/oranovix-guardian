import hashlib
import pickle

import yaml


def load(expression, blob, document):
    digest = hashlib.md5(blob)
    value = eval(expression)
    restored = pickle.loads(blob)
    config = yaml.load(document)
    return digest, value, restored, config
