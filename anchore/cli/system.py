import sys
import os
import re
import json
import getpass
import click
import yaml
import time
import shutil

from anchore.cli.common import anchore_print, anchore_print_err
from anchore.util import contexts
from anchore import anchore_utils, anchore_auth, anchore_feeds

config = {}

@click.group(name='system', short_help='System level operations.')
@click.pass_obj
def system(anchore_config):
    global config
    config = anchore_config

@system.command(name='status', short_help="Show system status.")
@click.option('--conf', is_flag=True, help='Output the currently used configuration yaml content')
def status(conf):
    """
    Show anchore system status.
    """

    ecode = 0
    try:
        if conf:
            if config.cliargs['json']:
                anchore_print(config.data, do_formatting=True)
            else:
                anchore_print(yaml.safe_dump(config.data, indent=True, default_flow_style=False))
        else:
            result = {}
            if contexts['anchore_db'].check():
                result["anchore_db"] = "OK"
            else:
                result["anchore_db"] = "NOTINITIALIZED"

            if anchore_feeds.check():
                result["anchore_feeds"] = "OK"
            else:
                result["anchore_feeds"] = "NOTSYNCED"

            afailed = False
            latest = 0
            for imageId in contexts['anchore_db'].load_all_images().keys():
                amanifest = anchore_utils.load_analyzer_manifest(imageId)
                for module_name in amanifest.keys():
                    try:
                        if amanifest[module_name]['timestamp'] > latest:
                            latest = amanifest[module_name]['timestamp']
                        if amanifest[module_name]['status'] != 'SUCCESS':
                            analyzer_failed_imageId = imageId
                            analyzer_failed_name = module_name
                            afailed = True
                    except:
                        pass

            if latest == 0:
                result["analyzer_status"] = "NODATA"
            elif afailed:
                result["analyzer_status"] = "FAIL ("+analyzer_failed_imageId+")"
                result["analyzer_latest_run"] = time.ctime(latest)
            else:
                result["analyzer_status"] = "OK"
                result["analyzer_latest_run"] = time.ctime(latest)
   
            anchore_print(result, do_formatting=True)

    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@system.command(name='backup', short_help="Backup an anchore installation to a tarfile.")
@click.argument('outputdir', type=click.Path())
def backup(outputdir):
    """
    Backup an anchore installation to a tarfile.
    """

    ecode = 0
    try:
        anchore_print('Backing up anchore system to directory '+str(outputdir)+' ...')
        backupfile = config.backup(outputdir)
        anchore_print({"anchore_backup_tarball":str(backupfile)}, do_formatting=True)
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@system.command(name='restore', short_help="Restore an anchore installation from a previously backed up tar file.")
@click.argument('inputfile', type=click.File('rb'))
@click.argument('destination_root', type=click.Path(), default='/')
def restore(inputfile, destination_root):
    """
    Restore an anchore installation from a previously backed up tar file.
    """

    ecode = 0
    try:
        anchore_print('Restoring anchore system from backup file %s ...' % (str(inputfile.name)))
        restoredir = config.restore(destination_root, inputfile)
        anchore_print("Anchore restored.")
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)

@system.command(name='exportdb')
@click.option('--outdir', help='output directory for exported anchore DB', required=True, metavar='<export directory>')
def exportdb(outdir):
    """Export all anchore images to JSON files"""
    ecode = 0
    try:
        imgdir = os.path.join(outdir, "images")
        feeddir = os.path.join(outdir, "feeds")
        storedir = os.path.join(outdir, "storedfiles")

        for d in [outdir, imgdir, feeddir, storedir]:
            if not os.path.exists(d):
                os.makedirs(d)

        anchore_print("exporting images...")
        imagelist = anchore_utils.get_image_list().keys()
        for imageId in imagelist:
            thefile = os.path.join(imgdir, imageId+".json")
            if not os.path.exists(thefile):
                with open(thefile, 'w') as OFH:
                    OFH.write(json.dumps(contexts['anchore_db'].load_image_new(imageId)))

            stored_namespaces = contexts['anchore_db'].load_files_namespaces(imageId)
            for namespace in stored_namespaces:
                stored_files = contexts['anchore_db'].load_files_tarfile(imageId, namespace)
                if os.path.exists(stored_files):
                    thedir = os.path.join(storedir, imageId, namespace)
                    if not os.path.exists(thedir):
                        os.makedirs(thedir)
                    thefile = os.path.join(thedir, "stored_files.tar.gz")
                    shutil.copy(stored_files, thefile)

        anchore_print("exporting feeds...")
        feedmeta = contexts['anchore_db'].load_feedmeta()
        thefile = os.path.join(feeddir, "feedmeta.json")
        with open(thefile, 'w') as OFH:
            OFH.write(json.dumps(feedmeta))

        for feed in feedmeta:
            feedobj = feedmeta[feed]
            for group in feedobj['groups']:
                groupobj = feedobj['groups'][group]
                datafiles = groupobj.pop('datafiles', [])
                for datafile in datafiles:
                    thedir = os.path.join(feeddir, feed, group)
                    if not os.path.exists(thedir):
                        os.makedirs(thedir)
                    thefile = os.path.join(thedir, datafile)
                    if not os.path.exists(thefile):
                        with open(thefile, 'w') as OFH:
                            OFH.write(json.dumps(contexts['anchore_db'].load_feed_group_data(feed, group, datafile)))

    except Exception as err:
        anchore_print_err("operation failed: " + str(err))
        ecode = 1

    sys.exit(ecode)

@system.command(name='importdb')
@click.option('--indir', help='directory from previously exported anchore DB', required=True, metavar='<export directory>')
def importdb(indir):
    """Import a previously exported anchore DB"""
    ecode = 0
    try:
        imgdir = os.path.join(indir, "images")
        feeddir = os.path.join(indir, "feeds")
        storedir = os.path.join(indir, "storedfiles")

        for d in [indir, imgdir, feeddir, storedir]:
            if not os.path.exists(d):
                raise Exception ("specified directory "+str(indir)+" does not appear to be complete (missing "+str(d)+")")

                
        anchore_print("importing images...")
        #imagelist = []
        for ifile in os.listdir(imgdir):
            patt = re.match("(.*)\.json", ifile)
            if patt:
                imageId = patt.group(1)

                if contexts['anchore_db'].is_image_present(imageId):
                    anchore_print("\timage ("+str(imageId)+") already exists in DB, skipping import.")
                else:
                    #imagelist.append(patt.group(1))
                    thefile = os.path.join(imgdir, ifile)
                    with open(thefile, 'r') as FH:
                        imagedata = json.loads(FH.read())
                    try:
                        rc = contexts['anchore_db'].save_image_new(imageId, report=imagedata)
                        if not rc:
                            contexts['anchore_db'].delete_image(imageId)
                            raise Exception("save to anchore DB failed")
                    except Exception as err:
                        contexts['anchore_db'].delete_image(imageId)
                        raise err

                    thedir = os.path.join(storedir, imageId)
                    if os.path.exists(thedir):
                        for namespace in os.listdir(thedir):
                            thefile = os.path.join(thedir, namespace, "stored_files.tar.gz")
                            if os.path.exists(thefile):
                                contexts['anchore_db'].save_files_tarfile(imageId, namespace, thefile)

                    anchore_print("\timage ("+str(imageId)+") imported.")

        anchore_print("importing feeds...")
        thefile = os.path.join(feeddir, "feedmeta.json")
        with open(thefile, 'r') as FH:
            feedmeta = json.loads(FH.read())

        if feedmeta:
            contexts['anchore_db'].save_feedmeta(feedmeta)

        for feed in feedmeta:
            feedobj = feedmeta[feed]
            for group in feedobj['groups']:
                groupobj = feedobj['groups'][group]
                datafiles = groupobj.pop('datafiles', [])
                for datafile in datafiles:
                    thedir = os.path.join(feeddir, feed, group)
                    thefile = os.path.join(thedir, datafile)
                    if not os.path.exists(thefile):
                        pass
                    else:
                        with open(thefile, 'r') as FH:
                            contexts['anchore_db'].save_feed_group_data(feed, group, datafile, json.loads(FH.read()))
                    anchore_print("\tfeed ("+feed+" " + group + " " + datafile + ") imported")

        #TODO import stored files

    except Exception as err:
        anchore_print_err("operation failed: " + str(err))
        ecode = 1

    sys.exit(ecode)

