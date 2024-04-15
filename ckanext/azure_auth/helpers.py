from ckan.common import config


def get_config_value(key, default=None):
    return config.get(key, default)
