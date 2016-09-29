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
    ret = {'success':False, 'status_code':1, 'text':""}

    feedurl = contexts['anchore_config']['feeds_url']
    feed_timeout = contexts['anchore_config']['feeds_conn_timeout']
    feed_maxretries = contexts['anchore_config']['feeds_max_retries']

    baseurl = feedurl
    url = baseurl

    retlist = list()

    done = False
    while not done:
        record = anchore.anchore_auth.anchore_auth_get(contexts['anchore_auth'], url, timeout=feed_timeout, retries=feed_maxretries)
        ret.update(record)
        if record['success']:
            data = json.loads(record['text'])
            if data and 'feeds' in data:
                retlist = retlist + data['feeds']

                if 'next_token' in data and data['next_token']:
                    url = baseurl + "?next_token="+data['next_token']
                else:
                    done=True
            else:
                done=True
        else:
            done=True

    return(retlist, ret)

def get_group_list(feed):
    ret = {'success':False, 'status_code':1, 'text':""}

    feedurl = contexts['anchore_config']['feeds_url']
    feed_timeout = contexts['anchore_config']['feeds_conn_timeout']
    feed_maxretries = contexts['anchore_config']['feeds_max_retries']

    baseurl = '/'.join([feedurl, feed])
    url = baseurl

    retlist = list()

    done = False
    while not done:
        record = anchore.anchore_auth.anchore_auth_get(contexts['anchore_auth'], url, timeout=feed_timeout, retries=feed_maxretries)
        ret.update(record)
        if record['success']:
            data = json.loads(record['text'])
            retlist = retlist + data['groups']
            if 'next_token' in data and data['next_token']:
                url = baseurl + "?next_token="+data['next_token']
            else:
                done=True
        else:
            done=True
    return(retlist, record)
    

def get_group_data(feed, group, since="1970-01-01"):    
    feedurl = contexts['anchore_config']['feeds_url']
    feed_timeout = contexts['anchore_config']['feeds_conn_timeout']
    feed_maxretries = contexts['anchore_config']['feeds_max_retries']

    baseurl = '/'.join([feedurl, feed, group, "?since="+since])
    url = baseurl

    updatetime = int(time.time())

    ret = list()
    last_token = ""
    success = True
    done=False
    while not done:
        _logger.debug("data group url: " + str(url))
        record = anchore.anchore_auth.anchore_auth_get(contexts['anchore_auth'], url, timeout=feed_timeout, retries=feed_maxretries)
        if record['success']:
            data = json.loads(record['text'])
            if 'data' in data:
                ret = ret + data['data']
                if 'next_token' in data and data['next_token']:
                    url = baseurl + "&next_token="+data['next_token']
                    if last_token == data['next_token']:
                        done=True
                    last_token = data['next_token']
                else:
                    done=True
            else:
                success = False
                done=True
        else:
            success = False
            done=True
    return(success, ret)


def sync_feedmeta():
    ret = {'success':False, 'text':"", 'status_code':1}

    basedir = contexts['anchore_config']['feeds_dir']
    feedurl = contexts['anchore_config']['feeds_url']
    try:
        if not os.path.exists(basedir):
            os.makedirs(basedir)

        _logger.info("getting feed list from server ...")
        feeds, record = get_feed_list()
        _logger.debug("feed list record: " + str(record))

        if feeds:
            with open(os.path.join(basedir, "feeds.json"), 'w') as OFH:
                OFH.write(json.dumps(feeds))

            for feedrecord in feeds:
                feed = feedrecord['name']
                _logger.info("getting group list for feed: " + str(feed))
                feeddir = os.path.join(basedir, feed)
                if not os.path.exists(feeddir):
                    os.makedirs(feeddir)

                groups, record = get_group_list(feed)
                _logger.debug("group list record: " + str(record))
                if groups:
                    with open(os.path.join(feeddir, "groups.json"), 'w') as OFH:
                        OFH.write(json.dumps(groups))

                    for grouprecord in groups:
                        group = grouprecord['name']
                        groupdir = os.path.join(feeddir, group)
                        if not os.path.exists(groupdir):
                            os.makedirs(groupdir)
                else:
                    ret['text'] = "WARN: cannot get list of groups from feed: " + str(feed)

            ret['success'] = True
            ret['status_code'] = 0
        else:
            ret['text'] = "cannot get list of feeds from service\nMessage from server: " + record['text']
            return(False, ret)
    except Exception as err:
        import traceback
        traceback.print_exc()
        _logger.debug("exception: " + str(err))
        ret['text'] = "exception: " + str(err)
        return(False, ret)

    return(True, ret)

def sync_feeds(force_since=None):
    ret = {'success':False, 'text':"", 'status_code':1}

    feedmeta = load_anchore_feedmeta()
    basedir = contexts['anchore_config']['feeds_dir']
    feedurl = contexts['anchore_config']['feeds_url']
    try:
        for feed in feedmeta.keys():
            if feedmeta[feed]['subscribed']:
                _logger.info("syncing data for subscribed feed ("+str(feed)+") ...")
                feeddir = os.path.join(basedir, feed)
                groups = feedmeta[feed]['groups'].keys()
                if groups:
                    for group in groups:
                        groupdir = os.path.join(feeddir, group)
                        if not os.path.exists(groupdir):
                            os.makedirs(groupdir)

                        sincets = 0
                        group_meta = {}
                        metafile = os.path.join(groupdir, "group_meta.json")
                        if os.path.exists(metafile):
                            # pull out the latest update timestamp
                            with open(metafile, 'r') as FH:
                                group_meta.update(json.loads(FH.read()))
                                sincets = group_meta['last_update']

                            # ensure that all datafiles exist
                            doupdate = False
                            for datafile in group_meta['datafiles']:
                                thefile = os.path.join(groupdir, datafile)
                                if not os.path.exists(thefile):
                                    group_meta['datafiles'].remove(datafile)
                                    doupdate = True
                            if doupdate:
                                with open(metafile, 'w') as OFH:
                                    OFH.write(json.dumps(group_meta))

                        if force_since:
                            sincets = float(force_since)

                        if 'files' not in group_meta:
                            group_meta['datafiles'] = list()

                        updatetime = int(time.time())

                        since=time.strftime("%Y-%m-%d", time.gmtime(sincets))
                        now = time.strftime("%Y-%m-%d", time.gmtime(updatetime))

                        datafilename = "data_"+since+"_to_"+now+".json"
                        datafile = os.path.join(groupdir, datafilename)
                        if os.path.exists(datafile):
                            _logger.info("\tskipping group data: " + str(group) + ": already synced")
                        else:
                            _logger.info("\tsyncing group data: " + str(group) + ": ...")
                            success, data = get_group_data(feed, group, since=since)
                            if success:
                                with open(datafile, 'w') as OFH:
                                    OFH.write(json.dumps(data))

                                with open(metafile, 'w') as OFH:
                                    group_meta['prev_update'] = sincets
                                    group_meta['last_update'] = updatetime
                                    for d in os.listdir(groupdir):
                                        if d not in group_meta['datafiles'] and re.match("^data_.*\.json", d):
                                            group_meta['datafiles'].append(d)
                                    if datafilename not in group_meta['datafiles']:
                                        group_meta['datafiles'].append(datafilename)
                                    OFH.write(json.dumps(group_meta))

                                # finally, do any post download feed/group handler actions
                                rc, msg = handle_anchore_feed_post(feed, group)
                            else:
                                _logger.warn("\t\tWARN: failed to download feed/group data ("+str(feed)+"/"+str(group)+"): check --debug output and/or try again") 
                            rc, msg = handle_anchore_feed_post(feed, group)

            else:
                _logger.info("skipping data sync for unsubscribed feed ("+str(feed)+") ...")            

        ret['status_code'] = 0
        ret['success'] = True
    except Exception as err:
        _logger.debug("exception: " + str(err))

        ret['text'] = "ERROR: " + str(err)
        return(False, ret)

    return(True, ret)

# on disk data operations

def check():
    basedir = contexts['anchore_config']['feeds_dir']
    if not os.path.exists(basedir):
        return(False, "feeds directory ("+str(basedir)+") does not yet exist: please run 'anchore feeds sync' and try again")
        
    if not load_anchore_feeds_list():
        return(False, "feeds list is empty: please run 'anchore feeds sync' and try again")

    return(True, "success")

def load_anchore_feeds_list():
    basedir = contexts['anchore_config']['feeds_dir']
    ret = list()
    
    feedsfile = os.path.join(basedir, "feeds.json")
    if os.path.exists(feedsfile):
        with open(feedsfile, 'r') as FH:
            ret = json.loads(FH.read())
    return(ret)

def load_anchore_feed_groups_list(feed):
    basedir = contexts['anchore_config']['feeds_dir']
    ret = list()
    feeddir = os.path.join(basedir, feed)
    
    fname = os.path.join(feeddir, "groups.json")
    if os.path.exists(fname):
        with open(fname, 'r') as FH:
            ret = json.loads(FH.read())
    return(ret)

def load_anchore_feed_group_datameta(feed, group):
    basedir = contexts['anchore_config']['feeds_dir']
    ret = {}
    
    groupdir = os.path.join(basedir, feed, group)
    
    fname = os.path.join(groupdir, "group_meta.json")
    if os.path.exists(fname):
        try:
            with open(fname, 'r') as FH:
                ret = json.loads(FH.read())
        except:
            ret = {}
    return(ret)

def load_anchore_feedmeta():
    ret = {}

    basedir = contexts['anchore_config']['feeds_dir']
    feedfile = os.path.join(basedir, "feedmeta.json")
    feedmeta = {}
    if os.path.exists(feedfile):
        with open(feedfile, 'r') as FH:
            feedmeta = json.loads(FH.read())

    # ensure feed meta is up-to-date
    update_anchore_feedmeta(feedmeta, default_sublist=['vulnerabilities'])

    return(feedmeta)

def update_anchore_feedmeta(feedmeta, default_sublist=None):
    feeds = load_anchore_feeds_list()
    for feedrecord in feeds:
        feed = feedrecord['name']
        if feed not in feedmeta:
            feedmeta[feed] = {'subscribed':False, 'description':"NA", 'groups':{}}
            if default_sublist and feed in default_sublist:
                feedmeta[feed]['subscribed'] = True

        feedmeta[feed]['description'] = feedrecord['description']

        groups = load_anchore_feed_groups_list(feed)
        for grouprecord in groups:
            group = grouprecord['name']
            if group not in feedmeta[feed]['groups']:
                feedmeta[feed]['groups'][group] = {}

            datameta = load_anchore_feed_group_datameta(feed, group)
            if feedmeta[feed]['groups'][group] != datameta:
                feedmeta[feed]['groups'][group].update(datameta)
    save_anchore_feedmeta(feedmeta)
    return(True)

def save_anchore_feedmeta(feedmeta):
    basedir = contexts['anchore_config']['feeds_dir']
    feedfile = os.path.join(basedir, "feedmeta.json")
    if feedmeta:
        with open(feedfile, 'w') as OFH:
            OFH.write(json.dumps(feedmeta))
        return(True)
    return(False)

def subscribe_anchore_feed(feed):
    success = True
    msg = str(feed) + ": subscribed."

    feedmeta = load_anchore_feedmeta()
    if feed in feedmeta:
        if not feedmeta[feed]['subscribed']:
            feedmeta[feed]['subscribed'] = True
            if not save_anchore_feedmeta(feedmeta):
                msg = str(feed) + ": failed to subscribe to feed (check debug output)."
                success = False
    else:
        msg = "cannot find specified feed ("+str(feed)+"): please review the feeds list and try again"
        success = False
    return(success, msg)

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
        msg = "cannot find specified feed ("+str(feed)+"): please review the feeds list and try again"
        success = False

    return(success, msg)

def load_anchore_feed(feed, group):
    basedir = contexts['anchore_config']['feeds_dir']
    ret = {'success':False, 'msg':"", 'data':list()}
    datameta = {}
    doupdate = False
    feedmeta = load_anchore_feedmeta()
    if not feedmeta:
        ret['msg'] = "feed data does not exist: please sync feed data"
    elif feed in feedmeta and not feedmeta[feed]['subscribed']:
        ret['msg'] = "not currently subscribed to feed ("+str(feed)+"): please subscribe, sync, and try again"
    else:
        if feed in feedmeta and group in feedmeta[feed]['groups']:
            datameta = feedmeta[feed]['groups'][group]
            datadir = os.path.join(basedir, feed, group)
        
        if datameta and 'datafiles' in datameta:
            for datafile in datameta['datafiles']:
                thefile = os.path.join(datadir, datafile)
                with open(thefile, 'r') as FH:
                    thelist = json.loads(FH.read())
                ret['data'] = ret['data'] + thelist
                ret['success'] = True
                ret['msg'] = "success"
        else:
            ret['msg'] = "no data exists for given feed/group ("+str(feed)+"/"+str(group)+")"
            
    return(ret)

def delete_anchore_feed(feed):
    basedir = contexts['anchore_config']['feeds_dir']

    feedmeta = load_anchore_feedmeta()
    if feed in feedmeta:
        if not feedmeta[feed]['subscribed']:
            feeddir = os.path.join(basedir, feed)
            if os.path.exists(feeddir):
                shutil.rmtree(feeddir)

    return(True)

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
    return(ret, msg)


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

    return(ret, msg)
