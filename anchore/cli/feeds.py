import sys
import os
import re
import json
import getpass
import click

from anchore.cli.common import anchore_print, anchore_print_err
from anchore.util import contexts
from anchore import anchore_utils, anchore_auth, anchore_feeds

config = {}

@click.group(name='feeds', short_help='Manage syncing of and subscriptions to Anchore data feeds.')
@click.pass_obj
def feeds(anchore_config):
    global config
    config = anchore_config
    pass


@feeds.command(name='list', short_help="List all feeds.")
#@click.option('--dontask', help='Will delete the image from Anchore DB without asking for coinfirmation', is_flag=True)
def list():
    """
    Show list of Anchore data feeds.
    """

    ecode = 0
    try:
        rc, msg = anchore_feeds.check()
        if rc:

            subscribed = {}
            available = {}
            feedmeta = anchore_feeds.load_anchore_feedmeta()
            for feed in feedmeta.keys():
                if feedmeta[feed]['subscribed']:
                    subscribed[feed] = feedmeta[feed]
                else:
                    available[feed] = feedmeta[feed]

            anchore_print("Available:")
            for feed in available.keys():
                anchore_print("")
                anchore_print("  "+feed+" ("+available[feed]['description']+"):")
                for group in available[feed]['groups'].keys():
                    anchore_print("    - " + str(group))

            anchore_print("")
            anchore_print("Subscribed:")
            for feed in subscribed.keys():
                anchore_print("  "+feed+" ("+subscribed[feed]['description']+"):")
                for group in subscribed[feed]['groups'].keys():
                    anchore_print("    - " + str(group))
        else:
            anchore_print_err(msg)
            ecode = 1
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@feeds.command(name='sub', short_help="Subscribe to specified feed(s).")
@click.argument('feednames', nargs=-1, metavar='<feedname> <feedname> ...')
def sub(feednames):
    """
    Subscribe to the specified feed(s).
    """

    ecode = 0
    try:
        for feed in feednames:
            rc = anchore_feeds.subscribe_anchore_feed(feed)
            if not rc:
                ecode = 1
            else:
                anchore_print(feed + ": subscribed.")

    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@feeds.command(name='unsub', short_help="Unsubscribe from specified feed(s).")
@click.argument('feednames', nargs=-1, metavar='<feedname> <feedname> ...')
def unsub(feednames):
    """
    Unsubscribe from the specified feed(s).
    """

    ecode = 0
    try:
        for feed in feednames:
            rc = anchore_feeds.unsubscribe_anchore_feed(feed)
            if not rc:
                ecode = 1
            else:
                anchore_print(feed + ": unsubscribed.")

    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@feeds.command(name='sync', short_help="Sync (download) latest data for all subscribed feeds from the Anchore service.")
def sync():
    """
    Sync (download) latest data for all subscribed feeds from the Anchore service.
    """

    ecode = 0
    try:
        rc, ret = anchore_feeds.sync_feedmeta()
        if not rc:
            anchore_print_err(ret['text'])
            ecode = 1
        else:
            rc, ret = anchore_feeds.sync_feeds()
            if not rc:
                anchore_print_err(ret['text'])
                ecode = 1
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)
