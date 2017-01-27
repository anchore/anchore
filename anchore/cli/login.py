import sys
import os
import getpass
import click

from anchore.cli.common import anchore_print, anchore_print_err
from anchore.util import contexts
from anchore import anchore_auth


@click.command(name='login', short_help='Log in to the Anchore service.')
@click.pass_obj
def login(anchore_config):
    """
    Log into Anchore service using your username/password from anchore.io.
    """
    config = anchore_config
    ecode = 0

    try:
        if os.getenv('ANCHOREUSER'):
            anchore_print("Using user from environment (ANCHOREUSER)")
            username = os.getenv('ANCHOREUSER')
        else:
            username = raw_input("Username: ")

        if os.getenv('ANCHOREPASS'):
            anchore_print("Using password from environment (ANCHOREPASS)")
            password = os.getenv('ANCHOREPASS')
        else:
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


@click.command(name='whoami', short_help='Show user data for current logged-in user if available')
@click.pass_obj
def whoami(anchore_config):
    """
    Show user data for current user if available
    :param anchore_config:
    :return:
    """
    ecode = 0
    try:
        aa = contexts['anchore_auth']
        if aa and 'username' in aa and 'password' in aa:
            info = {'Current user': aa['user_info'] if aa['user_info'] else 'anonymous'}

            anchore_print(info, do_formatting=True)
        else:
            anchore_print_err('No anchore auth context found. Cannot get user info. Try logging in first')
            ecode = 1

    except Exception as err:
        anchore_print_err('Cannot get user info')
        ecode = 1

    sys.exit(ecode)

        

