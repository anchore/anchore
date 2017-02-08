import os
import sys
import shutil
import requests
import re
import json
import time
import logging

import anchore.anchore_auth
from anchore.util import contexts

# network operations
_logger = logging.getLogger(__name__)


def get_feed_list():
    ret = {'success': False, 'status_code': 1, 'text': ""}

    feedurl = contexts['anchore_config']['feeds_url']
    feed_timeout = contexts['anchore_config']['feeds_conn_timeout']
    feed_maxretries = contexts['anchore_config']['feeds_max_retries']

    baseurl = feedurl
    url = baseurl

    retlist = list()

    done = False
    while not done:
        record = anchore.anchore_auth.anchore_auth_get(contexts['anchore_auth'], url, timeout=feed_timeout,
                                                       retries=feed_maxretries)
        ret.update(record)
        if record['success']:
            data = json.loads(record['text'])
            if data and 'feeds' in data:
                retlist = retlist + data['feeds']

                if 'next_token' in data and data['next_token']:
                    url = baseurl + "?next_token=" + data['next_token']
                else:
                    done = True
            else:
                done = True
        else:
            done = True

    return (retlist, ret)


def get_group_list(feed):
    ret = {'success': False, 'status_code': 1, 'text': ""}

    feedurl = contexts['anchore_config']['feeds_url']
    feed_timeout = contexts['anchore_config']['feeds_conn_timeout']
    feed_maxretries = contexts['anchore_config']['feeds_max_retries']

    baseurl = '/'.join([feedurl, feed])
    url = baseurl

    retlist = list()

    done = False
    while not done:
        record = anchore.anchore_auth.anchore_auth_get(contexts['anchore_auth'], url, timeout=feed_timeout,
                                                       retries=feed_maxretries)
        ret.update(record)
        if record['success']:
            data = json.loads(record['text'])
            retlist = retlist + data['groups']
            if 'next_token' in data and data['next_token']:
                url = baseurl + "?next_token=" + data['next_token']
            else:
                done = True
        else:
            done = True
    return (retlist, record)


def get_group_data(feed, group, since="1970-01-01"):
    feedurl = contexts['anchore_config']['feeds_url']
    feed_timeout = contexts['anchore_config']['feeds_conn_timeout']
    feed_maxretries = contexts['anchore_config']['feeds_max_retries']

    baseurl = '/'.join([feedurl, feed, group, "?since=" + since])
    url = baseurl

    updatetime = int(time.time())

    ret = list()
    last_token = ""
    success = True
    done = False
    while not done:
        _logger.debug("data group url: " + str(url))
        record = anchore.anchore_auth.anchore_auth_get(contexts['anchore_auth'], url, timeout=feed_timeout,
                                                       retries=feed_maxretries)
        if record['success']:
            data = json.loads(record['text'])
            if 'data' in data:
                ret = ret + data['data']
                if 'next_token' in data and data['next_token']:
                    url = baseurl + "&next_token=" + data['next_token']
                    if last_token == data['next_token']:
                        done = True
                    last_token = data['next_token']
                else:
                    done = True
            else:
                success = False
                done = True
        else:
            success = False
            if record and 'err_msg' in record:
                ret = record.get('err_msg')
            done = True
    return (success, ret)


def create_feed(feed):
    if not feed:
        return (False)

    return (contexts['anchore_db'].create_feed(feed))


def create_feedgroup(feed, group):
    if not feed or not group:
        return (False)

    return (contexts['anchore_db'].create_feedgroup(feed, group))


def sync_feedmeta(default_sublist=['vulnerabilities']):
    ret = {'success': False, 'text': "", 'status_code': 1}

    try:
        feedmeta = load_anchore_feedmeta()

        feeds, record = get_feed_list()
        if feeds:
            for feedrecord in feeds:
                feed = feedrecord['name']
                if feed not in feedmeta:
                    feedmeta[feed] = {}
                feedmeta[feed].update(feedrecord)

                if 'groups' not in feedmeta[feed]:
                    feedmeta[feed]['groups'] = {}

                if 'subscribed' not in feedmeta[feed]:
                    if feed in default_sublist:
                        feedmeta[feed]['subscribed'] = True
                    else:
                        feedmeta[feed]['subscribed'] = False

                rc = create_feed(feed)

                groups, record = get_group_list(feed)
                if groups:
                    for grouprecord in groups:
                        group = grouprecord['name']
                        if group not in feedmeta[feed]['groups']:
                            feedmeta[feed]['groups'][group] = {}

                        feedmeta[feed]['groups'][group].update(grouprecord)

                        rc = create_feedgroup(feed, group)
                else:
                    ret['text'] = "WARN: cannot get list of groups from feed: " + str(feed)

            ret['success'] = True
            ret['status_code'] = 0

        else:
            ret['text'] = "cannot get list of feeds from service\nMessage from server: " + record['text']
            return (False, ret)

        save_anchore_feedmeta(feedmeta)

    except Exception as err:
        import traceback
        traceback.print_exc()
        _logger.debug("exception: " + str(err))
        ret['text'] = "exception: " + str(err)
        return (False, ret)

    return (True, ret)


def feed_group_data_exists(feed, group, datafile):
    feedmeta = load_anchore_feedmeta()
    if feed in feedmeta.keys() and group in feedmeta[feed]['groups'].keys() and 'datafiles' in feedmeta[feed]['groups'][
        group] and datafile in feedmeta[feed]['groups'][group]['datafiles']:
        return (True)
    return (False)


def sync_feeds(force_since=None, do_combine=False):
    ret = {'success': False, 'text': "", 'status_code': 1}

    feedmeta = load_anchore_feedmeta()

    feedurl = contexts['anchore_config']['feeds_url']
    try:
        for feed in feedmeta.keys():
            if feedmeta[feed]['subscribed']:
                _logger.info("syncing data for subscribed feed (" + str(feed) + ") ...")
                groups = feedmeta[feed]['groups'].keys()
                if groups:
                    for group in groups:
                        sincets = 0
                        group_meta = {}
                        if group in feedmeta[feed]['groups']:
                            group_meta = feedmeta[feed]['groups'][group]
                            if 'last_update' in group_meta:
                                sincets = group_meta['last_update']

                        if force_since:
                            sincets = float(force_since)

                        if 'datafiles' not in group_meta:
                            group_meta['datafiles'] = list()

                        updatetime = int(time.time())

                        since = time.strftime("%Y-%m-%d", time.gmtime(sincets))
                        now = time.strftime("%Y-%m-%d", time.gmtime(updatetime))

                        datafilename = "data_" + since + "_to_" + now + ".json"
                        if feed_group_data_exists(feed, group, datafilename):
                            _logger.info("\tskipping group data: " + str(group) + ": already synced")
                        else:
                            _logger.info("\tsyncing group data: " + str(group) + ": ...")
                            success, data = get_group_data(feed, group, since=since)
                            if success:
                                rc = save_anchore_feed_group_data(feed, group, datafilename, data)

                                group_meta['prev_update'] = sincets
                                group_meta['last_update'] = updatetime
                                if datafilename not in group_meta['datafiles']:
                                    group_meta['datafiles'].append(datafilename)

                                # finally, do any post download feed/group handler actions
                                rc, msg = handle_anchore_feed_post(feed, group)
                            else:
                                if data and isinstance(data, str):
                                    err_msg = data
                                else:
                                    err_msg = 'check --debug output and/or try again'

                                _logger.warn("\t\tWARN: failed to download feed/group data (" + str(feed) + "/" + str(
                                    group) + "): {}".format(err_msg))

            else:
                _logger.info("skipping data sync for unsubscribed feed (" + str(feed) + ") ...")

        ret['status_code'] = 0
        ret['success'] = True
    except Exception as err:
        import traceback
        traceback.print_exc()
        _logger.debug("exception: " + str(err))
        ret['text'] = "ERROR: " + str(err)
        return (False, ret)

    if not save_anchore_feedmeta(feedmeta):
        ret['text'] = "\t\tWARN: failed to store metadata on synced feed data"

    # if user has asked for data compress, do it now
    if do_combine:
        handle_datafile_combine()

    return (True, ret)


def check():
    if not load_anchore_feedmeta():
        return (False, "feeds are not initialized: please run 'anchore feeds sync' and try again")

    if not load_anchore_feeds_list():
        return (False, "feeds list is empty: please run 'anchore feeds sync' and try again")

    return (True, "success")


def load_anchore_feeds_list():
    ret = []
    feedmeta = load_anchore_feedmeta()
    if feedmeta:
        ret = feedmeta.values()

    return (ret)


def load_anchore_feed_groups_list(feed):
    ret = []
    feedmeta = load_anchore_feedmeta()
    if feedmeta:
        if feed in feedmeta.keys():
            ret = feedmeta[feed]['groups'].values()

    return (ret)


def load_anchore_feed_group_datameta(feed, group):
    ret = {}
    feedmeta = load_anchore_feedmeta()
    if feedmeta:
        if feed in feedmeta.keys() and group in feedmeta[feed]['groups'].keys():
            ret = feedmeta[feed]['groups'][group]

    return (ret)


def load_anchore_feedmeta():
    return (contexts['anchore_db'].load_feedmeta())


def save_anchore_feedmeta(feedmeta):
    return (contexts['anchore_db'].save_feedmeta(feedmeta))


def subscribe_anchore_feed(feed, user_tier=0):
    success = True
    msg = str(feed) + ": subscribed."

    feedmeta = load_anchore_feedmeta()
    if feed in feedmeta:
        if user_tier >= int(feedmeta[feed]['access_tier']):
            if not feedmeta[feed]['subscribed']:
                feedmeta[feed]['subscribed'] = True
                if not save_anchore_feedmeta(feedmeta):
                    msg = str(feed) + ": failed to subscribe to feed (check debug output)."
                    success = False
        else:
            msg = 'Current user does not have sufficient access tier to subscribe to feed {0}. Current tier is {1}, must be {2} to access feed'.format(feed, user_tier, feedmeta[feed]['access_tier'])
            success = False
    else:
        msg = "cannot find specified feed (" + str(feed) + "): please review the feeds list and try again"
        success = False
    return (success, msg)


def unsubscribe_anchore_feed(feed):
    success = True
    msg = str(feed) + ": unsubscribed."

    feedmeta = load_anchore_feedmeta()
    if feed in feedmeta:
        if feedmeta[feed]['subscribed']:
            feedmeta[feed]['subscribed'] = False
            if not save_anchore_feedmeta(feedmeta):
                msg = str(feed) + ": failed to unsubscribe to feed (check debug output)."
                success = False
    else:
        msg = "cannot find specified feed (" + str(feed) + "): please review the feeds list and try again"
        success = False

    return (success, msg)


def save_anchore_feed_group_data(feed, group, datafile, data):
    return (contexts['anchore_db'].save_feed_group_data(feed, group, datafile, data))


def load_anchore_feed_group_data(feed, group, datafile):
    return (contexts['anchore_db'].load_feed_group_data(feed, group, datafile))

def delete_anchore_feed_group_data(feed, group, datafile):
    return (contexts['anchore_db'].delete_feed_group_data(feed, group, datafile))

def load_anchore_feed(feed, group, ensure_unique=False):
    ret = {'success': False, 'msg': "", 'data': list()}
    datameta = {}
    doupdate = False
    feedmeta = load_anchore_feedmeta()
    if not feedmeta:
        ret['msg'] = "feed data does not exist: please sync feed data"
    elif feed in feedmeta and not feedmeta[feed]['subscribed']:
        ret['msg'] = "not currently subscribed to feed (" + str(feed) + "): please subscribe, sync, and try again"
    else:
        if feed in feedmeta and group in feedmeta[feed]['groups']:
            datameta = feedmeta[feed]['groups'][group]

        if datameta and 'datafiles' in datameta:
            unique_hash = {}
            revfiles = sorted(datameta['datafiles'])
            revfiles.reverse()
            #for datafile in sorted(datameta['datafiles']):
            for datafile in revfiles:
                thelist = load_anchore_feed_group_data(feed, group, datafile)
                if ensure_unique:
                    thelist.reverse()
                    for el in thelist:
                        if isinstance(el, dict) and len(el.keys()) == 1:
                            if feed == 'vulnerabilities':
                                elkey = el['Vulnerability']['Name']
                            else:
                                elkey = el.keys()[0]
                            #elkey = el.keys()[0]
                            if elkey in unique_hash:
                                _logger.debug("FOUND duplicate entry during scan for unique data values: " + str(elkey))
                            else:
                                unique_hash[elkey] = el

                ret['data'] = ret['data'] + thelist
                ret['success'] = True
                ret['msg'] = "success"

            if ret['success'] and ensure_unique:
                ret['data'] = unique_hash.values()

        else:
            ret['msg'] = "no data exists for given feed/group (" + str(feed) + "/" + str(group) + ")"

    return (ret)


def delete_anchore_feed(feed):
    feedmeta = load_anchore_feedmeta()
    if feed in feedmeta.keys():
        if not feedmeta[feed]['subscribed']:
            try:
                for group in feedmeta[feed]['groups'].keys():
                    feedmeta[feed]['groups'][group].pop('datafiles', [])
                    feedmeta[feed]['groups'][group].pop('last_update', 0)
                    feedmeta[feed]['groups'][group].pop('prev_update', 0)

                save_anchore_feedmeta(feedmeta)
                contexts['anchore_db'].delete_feed(feed)
            except Exception as err:
                _logger.warn("could not complete delete of feed - message from service: " + str(err))

            return (True)
        else:
            _logger.warn(
                "skipping delete of feed that is marked as subscribed - please unsubscribe first and then retry the delete")

    return (True)


# TODO wip
def handle_anchore_feed_pre(feed):
    ret = True
    msg = ""
    feedmeta = load_anchore_feedmeta()
    if feed in feedmeta:
        if feed == 'vulnerabilities':
            if not feedmeta[feed]['subscribed']:
                rc, msg = subscribe_anchore_feed(feed)
                ret = rc
    return (ret, msg)


def handle_anchore_feed_post(feed, group):
    ret = True
    msg = ""
    if feed == 'imagedata':
        # handler
        d = load_anchore_feed(feed, group)
        if d and d['success']:
            for record in d['data']:
                if 'redirecturl' in record.keys():
                    for tag in record['redirecturl'].keys():
                        url = record['redirecturl'][tag]
                        imageId = tag
                        if not contexts['anchore_db'].is_image_present(imageId):
                            try:
                                r = requests.get(url, timeout=10)
                                if r.status_code == 200:
                                    data = json.loads(r.text)
                                    for imagedata in data:
                                        imagerecord = imagedata['image']['imagedata']
                                        _logger.info("\t\tpopulating anchore DB with image data: " + imageId)
                                        contexts['anchore_db'].save_image_new(imageId, report=imagerecord)
                            except Exception as err:
                                _logger.error("exception: " + str(err))
                                ret = False
                                msg = "failed to download/import image: " + imageId
                        else:
                            _logger.info("\t\tskipping: " + str(imageId) + ": already in DB")
    else:
        # no handler
        pass

    return (ret, msg)

def handle_datafile_combine():
    ret = True

    feedmeta = load_anchore_feedmeta()

    for feed in feedmeta.keys():
        if 'groups' in feedmeta[feed] and 'subscribed' in feedmeta[feed] and feedmeta[feed]['subscribed']:
            _logger.info("combining data for feed ("+str(feed)+") ...")
            for group in feedmeta[feed]['groups']:
                rawdata = load_anchore_feed(feed, group, ensure_unique=False)
                data = rawdata['data']
                uniqhash = {}
                uniq = list()
                collisions = 0
                for v in data:
                    vid = None
                    try:
                        if feed == 'vulnerabilities':
                            vid = v['Vulnerability']['Name']
                        else:
                            vid = v.keys()[0]
                    except:
                        vid = None
                        pass

                    if vid:
                        if vid not in uniqhash:
                            uniqhash[vid] = True
                            uniq.append(v)
                        else:
                            collisions = collisions + 1

                rawdata.clear()
                _logger.info("\tprocessing group data: " + str(group) + ": removed " + str(collisions) + " records as duplicate or out-of-date")

                # datafile updates
                updatetime = int(time.time())
                now = time.strftime("%Y-%m-%d", time.gmtime(updatetime))

                datafilename = "data_" + now + "_to_" + now + ".json"
                rc = save_anchore_feed_group_data(feed, group, datafilename, uniq)
                if rc:
                    if 'datafiles' in feedmeta[feed]['groups'][group]:
                        for dfile in feedmeta[feed]['groups'][group]['datafiles']:
                            if dfile != datafilename:
                                delete_anchore_feed_group_data(feed, group, dfile)

                    feedmeta[feed]['groups'][group]['datafiles'] = [datafilename]
                    save_anchore_feedmeta(feedmeta)

    return(ret)
