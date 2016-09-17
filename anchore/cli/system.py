import sys
import os
import re
import json
import getpass
import click
import yaml
import time

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

