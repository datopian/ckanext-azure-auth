'''
Plugin for ADFS authentication
'''
import base64
import logging

import requests

from flask_login import login_user

from ckan.common import _, g, request, session, config
from ckan.lib import base, helpers
import ckan.model as model
from ckanext.azure_auth.auth_backend import AdfsAuthBackend
from ckanext.azure_auth.auth_config import ADFS_SESSION_PREFIX, ProviderConfig
from ckanext.azure_auth.exceptions import (
    AzureReloginRequiredException,
    CreateUserException,
    MFARequiredException,
    RuntimeIssueException,
)

log = logging.getLogger(__name__)
requests.packages.urllib3.add_stderr_logger()


def login_callback():
    '''
    Handles ADFS callback
    received auth code or auth tokens
    '''
    code = request.params.get('code') or request.args.get('code')
    provider_config = ProviderConfig()
    auth_backend = AdfsAuthBackend(provider_config=provider_config)

    try:
        user = auth_backend.authenticate_with_code(authorization_code=code)
        user_obj = model.User.get(user['name'])
        login_user(user_obj)
    except MFARequiredException:
        return helpers.redirect_to(
            provider_config.build_authorization_endpoint(
                request, force_mfa=True
            )  # no params needed - FIXME
        )
    except CreateUserException as e:
        log.debug(str(e))
        base.abort(403, str(e))
    except (AzureReloginRequiredException, RuntimeIssueException) as e:
        log.debug(str(e))
        base.abort(403, str(e))
    except Exception as e:
        log.debug(str(e))
        base.abort(400, 'No authorization code was provided.')

    if user:
        if user['state'] == 'active':
            g.user = user['name']
            session[f'{ADFS_SESSION_PREFIX}user'] = user['name']
            session.save()

            return helpers.redirect_to(config.get('ckanext.azure_auth.login_redirect_blueprint', 'user.me'))
        else:
            # Return a 'disabled account' error message
            base.abort(403, 'Your account is disabled.')
    else:
        # Return an 'invalid login' error message
        base.abort(401, 'Login failed.')
