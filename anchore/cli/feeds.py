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
@click.option('--showgroups', help='Along with the feed, show all groups within the feed.', is_flag=True)
def list(showgroups):
    """
    Show list of Anchore data feeds.
    """
    ecode = 0
    try:
        rc, msg = anchore_feeds.check()
        if not rc:
            anchore_print("initializing feed metadata: ...")
            rc, ret = anchore_feeds.sync_feedmeta()
            if not rc:
                anchore_print_err(ret['text'])
                rc = False
                msg = "could not sync feed metadata from service: " + ret['text']
            else:
                rc = True

        if rc:
            result = {}
            subscribed = {}
            available = {}
            feedmeta = anchore_feeds.load_anchore_feedmeta()
            for feed in feedmeta.keys():
                if feedmeta[feed]['subscribed']:
                    subscribed[feed] = {}
                    subscribed[feed]['description'] = feedmeta[feed]['description']
                    if showgroups:
                        subscribed[feed]['groups'] = feedmeta[feed]['groups'].keys()

                else:
                    available[feed] = {}
                    available[feed]['description'] = feedmeta[feed]['description']
                    if showgroups:
                        available[feed]['groups'] = feedmeta[feed]['groups'].keys()

            
            if available:
                result['Available'] = available
            if subscribed:
                result['Subscribed'] = subscribed

            anchore_print(result, do_formatting=True)

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
@click.option('--since', help='Force a feed sync from the given timestamp to today.', metavar='<unix timestamp>')
def sync(since):
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
            rc, ret = anchore_feeds.sync_feeds(force_since=since)
            if not rc:
                anchore_print_err(ret['text'])
                ecode = 1
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)
