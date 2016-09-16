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
        subscribed = {}
        available = {}
        feedmeta = anchore_feeds.load_anchore_feedmeta()
        for feed in feedmeta.keys():
            if feedmeta[feed]['subscribed']:
                subscribed[feed] = feedmeta[feed]
            else:
                available[feed] = feedmeta[feed]

        print "Available:"
        for feed in available.keys():
            print ""
            print "  "+feed+" ("+available[feed]['description']+"):"
            for group in available[feed]['groups'].keys():
                print "    - " + str(group)

        print ""
        print "Subscribed:"
        for feed in subscribed.keys():
            print "  "+feed+" ("+subscribed[feed]['description']+"):"
            for group in subscribed[feed]['groups'].keys():
                print "    - " + str(group)

    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@feeds.command(name='sub', short_help="Subscribe to specified feed.")
@click.argument('feednames', nargs=-1, metavar='<feedname> <feedname> ...')
def sub(feednames):
    """
    Subscribe to the specified feed.
    """

    ecode = 0
    try:
        for feed in feednames:
            rc = anchore_feeds.subscribe_anchore_feed(feed)
            if not rc:
                ecode = 1
            else:
                print feed + ": subscribed."

    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@feeds.command(name='unsub', short_help="Unsubscribe to specified feed.")
@click.argument('feednames', nargs=-1, metavar='<feedname> <feedname> ...')
def unsub(feednames):
    """
    Unsubscribe to the specified feed.
    """

    ecode = 0
    try:
        for feed in feednames:
            rc = anchore_feeds.unsubscribe_anchore_feed(feed)
            if not rc:
                ecode = 1
            else:
                print feed + ": unsubscribed."

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
        rc = anchore_feeds.sync_feedmeta()
        if not rc:
            ecode = 1
        else:
            rc = anchore_feeds.sync_feeds()
            if not rc:
                ecode = 1
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

