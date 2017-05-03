import sys
import os
import getpass
import click
import json

from anchore.cli.common import anchore_print, anchore_print_err
from anchore.util import contexts
from anchore import anchore_auth


@click.command(name='login', short_help='Log in to the Anchore service.')
@click.option('--user', help='Login with specified anchore.io username')
@click.option('--passfile', help='Read single line from specified file and use as password')
@click.pass_obj
def login(anchore_config, user, passfile):
    """
    Log into Anchore service using your username/password from anchore.io.
    """
    config = anchore_config
    ecode = 0

    try:
        anchore_creds_file = os.path.join(anchore_config.config_dir, 'anchore_creds.json')
        anchore_stored_username = None
        anchore_stored_password = None
        if os.path.exists(anchore_creds_file):
            try:
                with open(anchore_creds_file, 'r') as FH:
                    anchore_stored_creds = json.loads(FH.read())
                    anchore_stored_username = anchore_stored_creds.pop('username', None)
                    anchore_stored_password = anchore_stored_creds.pop('password', None)
            except Exception as err:
                raise err

        if user:
            anchore_print("Using user from cmdline option: " + str(user))
            username = user
        elif os.getenv('ANCHOREUSER'):
            anchore_print("Using user from environment (ANCHOREUSER)")
            username = os.getenv('ANCHOREUSER')
        elif anchore_stored_username:
            anchore_print("Using stored username from anchore_creds.json")
            username = anchore_stored_username
        else:
            username = raw_input("Username: ")

        if passfile:
            anchore_print("Using password from cmdline option: " + str(passfile))
            with open(passfile, "r") as FH:
                password = FH.read().strip()
        elif os.getenv('ANCHOREPASS'):
            anchore_print("Using password from environment (ANCHOREPASS)")
            password = os.getenv('ANCHOREPASS')
        elif anchore_stored_password:
            anchore_print("Using stored password from anchore_creds.json")
            password = anchore_stored_password
        else:
            password = getpass.getpass("Password: ")
            
        aa = contexts['anchore_auth']

        new_anchore_auth = anchore_auth.anchore_auth_init(username, password, aa['auth_file'], aa['client_info_url'], aa['token_url'], aa['conn_timeout'], aa['max_retries'])
        rc, ret = anchore_auth.anchore_auth_refresh(new_anchore_auth)
        if not rc:
            anchore_print("Failed to log in: check your username/password and try again!")
            raise Exception("Login failure - message from server: " + str(ret['text']))
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

        

