import sys
import os
import re
import json
import getpass
import click

from anchore.cli.common import anchore_print, anchore_print_err
from anchore.util import contexts
from anchore import anchore_utils, anchore_auth

@click.command(name='login', short_help='Log in to the Anchore service.')
@click.pass_obj
def login(anchore_config):
    """
    Log into Anchore service using your username/password from anchore.io.
    """
    config = anchore_config
    ecode = 0

    try:
        username = raw_input("Username: ")
        password = getpass.getpass("Password: ")
        aa = contexts['anchore_auth']

        new_anchore_auth = anchore_auth.anchore_auth_init(username, password, aa['auth_file'], aa['client_info_url'], aa['token_url'], aa['conn_timeout'], aa['max_retries'])
        rc, ret = anchore_auth.anchore_auth_refresh(new_anchore_auth)
        if not rc:
            anchore_print("Failed to log in: check your username/password and try again!")
            anchore_print("Message from server: " + ret['text'])
        else:
            contexts['anchore_auth'].update(new_anchore_auth)
            anchore_print("Login successful.")

    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@click.command(name='logout', short_help='Log out of the Anchore service.')
@click.pass_obj
def logout(anchore_config):
    """
    Log out of Anchore service
    """
    ecode = 0
    try:
        aa = contexts['anchore_auth']
        if aa:
            anchore_auth.anchore_auth_invalidate(aa)
            if 'auth_file' in aa:
                os.remove(aa['auth_file'])
        print "Logout successful."
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)


        

