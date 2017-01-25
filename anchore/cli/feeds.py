import sys
import click
import time
import calendar
import datetime

from anchore.cli.common import anchore_print, anchore_print_err
from anchore import anchore_auth, anchore_feeds
from anchore.anchore_utils import contexts

config = {}

@click.group(name='feeds', short_help='Manage syncing of and subscriptions to Anchore data feeds.')
@click.pass_obj
def feeds(anchore_config):
    global config
    config = anchore_config

    ecode = 0
    emsg = ""
    success = True

    try:
        rc, msg = anchore_feeds.check()
        if not rc:
            anchore_print("initializing feed metadata: ...")
            rc, ret = anchore_feeds.sync_feedmeta()
            if not rc:
                emsg = "could not sync feed metadata from service: " + ret['text']
                success = False

    except Exception as err:
        anchore_print_err('operation failed')
        sys.exit(1)

    if not success:
        anchore_print_err(emsg)
        sys.exit(1)

@feeds.command(name='show', short_help='Show detailed info on a specific feed')
@click.argument('feed')
def show(feed):
    """
    Show detailed feed information

    """
    ecode = 0
    try:
        feedmeta = anchore_feeds.load_anchore_feedmeta()
        if feed in feedmeta:
            result = {}
            groups = feedmeta[feed].get('groups',{}).values()
            result['name'] = feed
            result['access_tier'] = int(feedmeta[feed].get('access_tier'))
            result['description'] = feedmeta[feed].get('description')
            result['groups'] = {}
            if 'subscribed' not in feedmeta[feed]:
                result['subscribed'] = False
            else:
                result['subscribed'] = feedmeta[feed]['subscribed']

            for g in groups:
                result['groups'][g['name']] = {
                    'access_tier': int(g.get('access_tier')),
                    'description': g.get('description'),
                    'last_sync': datetime.datetime.fromtimestamp(g.get('last_update')).isoformat() if 'last_update' in g else 'None'
                }

            anchore_print(result, do_formatting=True)
        else:
            anchore_print_err('Unknown feed name. Valid feeds can be seen withe the "list" command')
            ecode = 1
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@feeds.command(name='list', short_help="List all feeds.")
@click.option('--showgroups', help='Along with the feed, show all groups within the feed.', is_flag=True)
def list(showgroups):
    """
    Show list of Anchore data feeds.
    """

    ecode = 0
    try:
        result = {}
        subscribed = {}
        available = {}
        unavailable = {}
        current_user_data = contexts['anchore_auth']['user_info']
        feedmeta = anchore_feeds.load_anchore_feedmeta()

        for feed in feedmeta.keys():
            if feedmeta[feed]['subscribed']:
                subscribed[feed] = {}
                subscribed[feed]['description'] = feedmeta[feed]['description']
                if showgroups:
                    subscribed[feed]['groups'] = feedmeta[feed]['groups'].keys()

            else:
                if current_user_data:
                    tier = int(current_user_data['tier'])
                else:
                    tier = 0

                if int(feedmeta[feed]['access_tier']) > tier:
                    collection = unavailable
                else:
                    collection = available

                collection[feed] = {}

                collection[feed]['description'] = feedmeta[feed]['description']
                if showgroups and collection == available:
                    collection[feed]['groups'] = feedmeta[feed]['groups'].keys()

        if available:
            result['Available'] = available
        if subscribed:
            result['Subscribed'] = subscribed
        if unavailable:
            result['Unavailable/Insufficient Access Tier'] = unavailable

        anchore_print(result, do_formatting=True)
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
    current_user_data = contexts.get('anchore_auth', {}).get('user_info', None)
    if not current_user_data:
        current_user_tier = 0
    else:
        current_user_tier = int(current_user_data['tier'])

    try:
        for feed in feednames:
            rc, msg = anchore_feeds.subscribe_anchore_feed(feed, current_user_tier)
            if not rc:
                ecode = 1
                anchore_print_err(msg)
            else:
                anchore_print(msg)

    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@feeds.command(name='unsub', short_help="Unsubscribe from specified feed(s).")
@click.argument('feednames', nargs=-1, metavar='<feedname> <feedname> ...')
@click.option('--delete', help='Delete all feed data after unsubscribing', is_flag=True)
@click.option('--dontask', help='Used with --delete, will not prompt before deleting all feed data', is_flag=True)
def unsub(feednames, delete, dontask):
    """
    Unsubscribe from the specified feed(s).
    """

    ecode = 0
    try:
        for feed in feednames:
            rc, msg = anchore_feeds.unsubscribe_anchore_feed(feed)
            if not rc:
                ecode = 1
                anchore_print_err(msg)
            else:
                anchore_print(msg)
                if delete:
                    dodelete = False
                    if dontask:
                        dodelete = True
                    else:
                        try:
                            answer = raw_input("Really delete feed data ("+str(feed)+"'? (y/N)")
                        except:
                            answer = "n"
                        if 'y' == answer.lower():
                            dodelete = True
                        else:
                            anchore_print(str(feed) + ": skipping delete.")

                    if dodelete:
                        anchore_print(str(feed) + ": deleting feed.")
                        rc = anchore_feeds.delete_anchore_feed(feed)

    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@feeds.command(name='sync', short_help="Sync (download) latest data for all subscribed feeds from the Anchore service.")
@click.option('--since', help='Force a feed sync from the given timestamp to today.', metavar='<unix timestamp>')
@click.option('--do-compact', help='After syncing, process feed data to eliminate duplicate entries and store only latest data records', is_flag=True)
def sync(since, do_compact):
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
            rc, ret = anchore_feeds.sync_feeds(force_since=since, do_combine=do_compact)
            if not rc:
                anchore_print_err(ret['text'])
                ecode = 1
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)
