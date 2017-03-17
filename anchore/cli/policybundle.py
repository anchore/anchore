import sys
import click
import time
import calendar
import datetime
import collections 

from anchore.cli.common import anchore_print, anchore_print_err
from anchore import anchore_auth, anchore_policy
from anchore.anchore_utils import contexts

config = {}

@click.group(name='policybundle', short_help='Manage syncing and application of your anchore.io policy bundles.')
@click.pass_obj
def policybundle(anchore_config):
    global config
    config = anchore_config

    ecode = 0
    emsg = ""
    success = True

    try:
        rc, msg = anchore_policy.check()
        if not rc:
            anchore_print("initializing policy metadata: ...")
            rc, ret = anchore_policy.sync_policymeta()
            if not rc:
                emsg = "could not sync policy metadata from service: " + ret['text']
                success = False

    except Exception as err:
        anchore_print_err('operation failed')
        sys.exit(1)

    if not success:
        anchore_print_err(emsg)
        sys.exit(1)

@policybundle.command(name='show', short_help='Show detailed info on specific policy')
@click.argument('policyname')
def show(policyname):
    """
    Show detailed policy information

    """
    ecode = 0
    try:
        policymeta = anchore_policy.load_policymeta()
        if policyname in policymeta:
            result = policymeta[policyname]
            anchore_print({policyname: result}, do_formatting=True)
        else:
            anchore_print_err('Unknown policy name. Valid policies can be seen withe the "list" command')
            ecode = 1
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@policybundle.command(name='list', short_help="List all policies.")
@click.option('--showdetail', help='Along with the policy name, show all details for all policies', is_flag=True)
def list(showdetail):
    """
    Show list of Anchore data policies.

    """

    ecode = 0
    try:
        policymeta = anchore_policy.load_policymeta()

        if showdetail:
            anchore_print(policymeta, do_formatting=True)
        else:
            output = {}
            for policy in policymeta.keys():
                output[policy] = {}
                output[policy]['policies'] = policymeta[policy]['policies'].keys()
                output[policy]['whitelists'] = policymeta[policy]['whitelists'].keys()
                output[policy]['global_whitelists'] = policymeta[policy]['global_whitelists'].keys()
                #output[policy]['mappings'] = policymeta[policy]['mappings']
            anchore_print(output, do_formatting=True)
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@policybundle.command(name='sync', short_help="Sync (download) latest policies from the Anchore.io service.")
def sync():
    """
    Sync (download) latest policies from the Anchore.io service.

    """

    ecode = 0
    try:
        rc, ret = anchore_policy.sync_policymeta()
        if not rc:
            anchore_print_err(ret['text'])
            ecode = 1
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)
