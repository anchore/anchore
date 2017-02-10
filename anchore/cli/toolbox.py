import sys
import os
import re
import shutil
import collections
import datetime
import json

from textwrap import fill
import click

from anchore.cli.common import anchore_print, anchore_print_err
from anchore import navigator, controller, anchore_utils, anchore_auth, anchore_feeds
from anchore.util import contexts, scripting

config = {}
imagelist = []

@click.group(short_help='Useful tools and operations on images and containers')
@click.option('--image', help='Process specified image ID', metavar='<imageid>')
@click.pass_context
@click.pass_obj
def toolbox(anchore_config, ctx, image):
    """
    A collection of tools for operating on images and containers and building anchore modules.

    Subcommands operate on the specified image passed in as --image <imgid>

    """

    global config, imagelist, nav
    config = anchore_config
    ecode = 0

    imagelist = [image]

    if ctx.invoked_subcommand not in ['import', 'delete', 'kubesync', 'images']:
        if not image:
            anchore_print_err("for this operation, you must specify an image with '--image'")
            ecode = 1
        else:
            try:
                try:
                    ret = anchore_utils.discover_imageIds(imagelist)
                except ValueError as err:
                    raise err
                else:
                    imagelist = ret
            except Exception as err:
                anchore_print_err("could not load any images")
                sys.exit(1)

            try:
                nav = navigator.Navigator(anchore_config=config, imagelist=imagelist, allimages=contexts['anchore_allimages'])
            except Exception as err:
                anchore_print_err('operation failed')
                nav = None
                ecode = 1

        if ecode:
            sys.exit(ecode)

@toolbox.command(name='delete', short_help="Delete input image(s) from the Anchore DB")
@click.option('--dontask', help='Will delete the image from Anchore DB without asking for coinfirmation', is_flag=True)
def delete(dontask):
    ecode = 0

    try:
        for i in imagelist:
            imageId = None
            if contexts['anchore_db'].is_image_present(i):
                imageId = i
            else:
                try:
                    ret = anchore_utils.discover_imageId(i)
                    #imageId = ret.keys()[0]
                    imageId = ret
                except:
                    imageId = None

            if imageId:
                dodelete = False
                if dontask:
                    dodelete = True
                else:
                    try:
                        answer = raw_input("Really delete image '"+str(i)+"'? (y/N)")
                    except:
                        answer = "n"
                    if 'y' == answer.lower():
                        dodelete = True
                    else:
                        anchore_print("Skipping delete.")
                if dodelete:
                    try:
                        anchore_print("Deleting image '"+str(i)+"'")
                        contexts['anchore_db'].delete_image(imageId)
                    except Exception as err:
                        raise err
    except Exception as err:
        anchore_print_err('operation failed')
        ecode = 1
    sys.exit(ecode)

@toolbox.command(name='savebundle', short_help="Create a tarball of a local docker image in a way that can be loaded into anchore elsewhere for analysis")
@click.option('--destdir', help='Destination directory for bundled container images', metavar='<path>')
def savebundle(destdir):

    if not nav:
        sys.exit(1)

    if not destdir:
        destdir = "/tmp/"

    imagedir = anchore_utils.make_anchoretmpdir(destdir)

    ecode = 0
    try:
        anchore_print("Bundling images: " + ' '.join(nav.get_images()) + " to " + imagedir)

        anchoreDB = contexts['anchore_db']
        docker_cli = contexts['docker_cli']
        
        for imageId in nav.get_images():
            try:
                container = docker_cli.create_container(imageId, 'true')
            except Exception as err:
                _logger.error("unable to run create container for exporting: " + str(self.meta['imageId']) + ": error: " + str(err))
                return(False)
            else:
                bundle_rootfs = os.path.join(imagedir, imageId + "_dockerexport.tar")
                with open(bundle_rootfs, 'w') as FH:
                    tar = docker_cli.export(container.get('Id'))
                    while not tar.closed:
                        FH.write(tar.read(4096*16))
            try:
                docker_cli.remove_container(container=container.get('Id'), force=True)
            except:
                _logger.error("unable to delete (cleanup) temporary container - proceeding but zombie container may be left in docker: " + str(err))

            image_report_final = os.path.join(imagedir, 'image_report.json')
            rdata = contexts['anchore_allimages'][imageId].generate_image_report()
            with open(image_report_final, 'w') as FH:
                FH.write(json.dumps(rdata))

            rootfsdir = anchore_utils.make_anchoretmpdir(imagedir)

            bundle_rootfs_final = os.path.join(imagedir, 'squashed.tar')
            bundle_final = os.path.join(imagedir, imageId + "_anchore.tar")

            tarcmd = ["tar", "-C", rootfsdir, "-x", "-f", bundle_rootfs]
            try:
                import subprocess
                subprocess.check_output(tarcmd)
            except Exception as err:
                print str(err)

            tarcmd = ["tar", "-C", rootfsdir, "-c", "-f", bundle_rootfs_final, '.']
            try:
                import subprocess
                subprocess.check_output(tarcmd)
            except Exception as err:
                print str(err)

            os.remove(bundle_rootfs)
            shutil.rmtree(rootfsdir)

            tarcmd = ["tar", "-C", imagedir, "-c", "-f", bundle_final, 'squashed.tar', 'image_report.json']
            try:
                import subprocess
                subprocess.check_output(tarcmd)
            except Exception as err:
                print str(err)

            os.remove(bundle_rootfs_final)
            os.remove(image_report_final)

    except:
        anchore_print_err("operation failed")
        ecode = 1
        
    sys.exit(ecode)
    

@toolbox.command(name='unpack', short_help="Unpack the specified image into a temp location")
@click.option('--destdir', help='Destination directory for unpacked container image', metavar='<path>')
def unpack(destdir):
    """Unpack and Squash image to local filesystem"""

    if not nav:
        sys.exit(1)

    ecode = 0
    try:
        anchore_print("Unpacking images: " + ' '.join(nav.get_images()))
        result = nav.unpack(destdir=destdir)
        if not result:
            anchore_print_err("no images unpacked")
            ecode = 1
        else:
            for imageId in result:
                anchore_print("Unpacked image: " + imageId)
                anchore_print("Unpack directory: "+ result[imageId])
    except:
        anchore_print_err("operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()
    
    sys.exit(ecode)

@toolbox.command(name='setup-module-dev', short_help='Setup a module development environment')
@click.option('--destdir', help='Destination directory for module development environment', metavar='<path>')
def setup_module_dev(destdir):
    """
    Sets up a development environment suitable for working on anchore modules (queries, etc) in the specified directory.
    Creates a copied environment in the destination containing the module scripts, unpacked image(s) and helper scripts
    such that a module script that works in the environment can be copied into the correct installation environment and
    run with anchore explore <modulename> invocation and should work.

    """

    if not nav:
        sys.exit(1)

    ecode = 0
    try:
        anchore_print("Anchore Module Development Environment\n")
        helpstr = "This tool has set up an environment that represents what anchore will normally set up before running an analyzer, gate and/or query module.  Each section below includes some information along with a string that you can use to help develop your own anchore modules.\n"
        anchore_print(fill(helpstr, 80))
        anchore_print("")

        anchore_print("Setting up environment...")
        anchore_print("")

        result = nav.unpack(destdir=destdir)
        if not result:
            raise Exception("unable to unpack input image")

        for imageId in result:
            unpackdir = result[imageId]

            # copy anchore imageDB dir into unpacked environment
            imgdir = '/'.join([config.data['image_data_store'], imageId])
            tmpdatastore = '/'.join([unpackdir, 'data'])
            dstimgdir = '/'.join([tmpdatastore, imageId])

            if not os.path.exists(imgdir):
                anchore_print_err("Image must exist and have been analyzed before being used for module development.")
                break
            if not os.path.exists(tmpdatastore):
                os.makedirs(tmpdatastore)
            shutil.copytree(imgdir, dstimgdir, symlinks=True)

            # copy examples into the unpacked environment            
            examples = {}
            basedir = '/'.join([unpackdir, "anchore-modules"])
            if not os.path.exists(basedir):
                os.makedirs(basedir)

                # copy the shell-utils
                os.makedirs('/'.join([basedir, 'shell-utils']))
                for s in os.listdir('/'.join([config.data['scripts_dir'], 'shell-utils'])):
                    shutil.copy('/'.join([config.data['scripts_dir'], 'shell-utils', s]), '/'.join([basedir, 'shell-utils', s]))
                            
            # copy any examples that exist in the anchore egg into the unpack dir
            for d in os.listdir(config.data['scripts_dir']):
                scriptdir = '/'.join([basedir, d])

                if os.path.exists(config.data['scripts_dir'] + "/examples/" + d):
                    if not os.path.exists(scriptdir):
                        os.makedirs(scriptdir)
                    for s in os.listdir(config.data['scripts_dir'] + "/examples/" + d):
                        thefile = '/'.join([config.data['scripts_dir'], "examples", d, s])
                        thefiledst = '/'.join([scriptdir, s])
                        if re.match(".*(\.sh)$", thefile):
                            examples[d] = thefiledst
                            shutil.copy(thefile, thefiledst)

            # all set, show how to use them
            anchore_print("\tImage: " + imageId[0:12])
            anchore_print("\tUnpack Directory: " +result[imageId])
            anchore_print("")
            analyzer_string = ' '.join([examples['analyzers'], imageId, tmpdatastore, dstimgdir, result[imageId]])
            anchore_print("\tAnalyzer Command:\n\n\t" +analyzer_string)
            anchore_print("")

            anchore_utils.write_plainfile_fromstr(result[imageId] + "/queryimages", imageId+"\n")

            queryoutput = '/'.join([result[imageId], "querytmp/"])
            if not os.path.exists(queryoutput):
                os.makedirs(queryoutput)

            query_string = ' '.join([examples['queries'], result[imageId] + "/queryimages", tmpdatastore, queryoutput, "passwd"])
            anchore_print("Query Command:\n\n\t" + query_string)
            anchore_print("")
 
            anchore_print("Next Steps: ")
            anchore_print("\tFirst: run the above analyzer command and note the RESULT output")
            anchore_print("\tSecond: run the above query command and note the RESULT output, checking that the query was able to use the analyzer data to perform its search")
            anchore_print("\tThird: modify the analyzer/query modules as you wish, including renaming them and continue running/inspecting output until you are satisfied")
            anchore_print("\tFinally: when you're happy with the analyzer/query, copy them to next to existing anchore analyzer/query modules and anchore will start calling them as part of container analysis/query:\n")
            anchore_print("\tcp " + examples['analyzers'] + " " + config.data['scripts_dir'] + "/analyzers/99_analyzer-example.sh")
            anchore_print("\tcp " + examples['queries'] + " " + config.data['scripts_dir'] + "/queries/")
            anchore_print("\tanchore analyze --force --image " + imageId + " --imagetype none")
            anchore_print("\tanchore query --image " + imageId + " query-example")
            anchore_print("\tanchore query --image " + imageId + " query-example passwd")
            anchore_print("\tanchore query --image " + imageId + " query-example pdoesntexist")
            
    except:
        anchore_print_err("operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()
    
    sys.exit(ecode)

@toolbox.command(name='show-dockerfile')
def show_dockerfile():
    """Generate (or display actual) image Dockerfile"""

    if not nav:
        sys.exit(1)

    ecode = 0
    try:
        result = nav.run_query(['show-dockerfile', 'all'])
        if result:
            anchore_utils.print_result(config, result)

    except:
        anchore_print_err("operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()
    sys.exit(ecode)



@toolbox.command(name='show-layers')
def show_layers():
    """Show image layer IDs"""

    if not nav:
        sys.exit(1)

    ecode = 0
    try:
        result = nav.run_query(['show-layers', 'all'])
        if result:
            anchore_utils.print_result(config, result)

    except:
        anchore_print_err("operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()
    sys.exit(ecode)


@toolbox.command(name='show-familytree')
def show_familytree():
    """Show image family tree image IDs"""
    if not nav:
        sys.exit(1)

    ecode = 0
    try:
        result = nav.run_query(['show-familytree', 'all'])
        if result:
            anchore_utils.print_result(config, result)

    except:
        anchore_print_err("operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()    
    sys.exit(ecode)


@toolbox.command(name='show-taghistory')
def show_taghistory():
    """Show history of all known repo/tags for image"""


    if not nav:
        sys.exit(1)

    ecode = 0
    try:
        result = nav.get_taghistory()
        if result:
            anchore_utils.print_result(config, result)

    except:
        anchore_print_err("operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()
    sys.exit(ecode)

@toolbox.command(name='show-analyzer-status')
def show_analyzer_status():
    """Show analyzer status for specified image"""

    ecode = 0
    try:
        image=contexts['anchore_allimages'][imagelist[0]]
        analyzer_status = contexts['anchore_db'].load_analyzer_manifest(image.meta['imageId'])
        result = {image.meta['imageId']:{'result':{'header':['Analyzer', 'Status', '*Type', 'LastExec', 'Exitcode', 'Checksum'], 'rows':[]}}}
        for script in analyzer_status.keys():
            adata = analyzer_status[script]
            nicetime = datetime.datetime.fromtimestamp(adata['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            try:
                row = [script.split('/')[-1], adata['status'], adata['atype'], nicetime, str(adata['returncode']), adata['csum']]
                result[image.meta['imageId']]['result']['rows'].append(row)        
            except:
                pass
        if result:
            anchore_utils.print_result(config, result)
    except:
        anchore_print_err("operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()
    sys.exit(ecode)

@toolbox.command(name='export')
@click.option('--outfile', help='output file for exported image', required=True, metavar='<file.json>')
def export(outfile):
    """Export image anchore data to a JSON file."""

    if not nav:
        sys.exit(1)

    ecode = 0
    savelist = list()
    for imageId in imagelist:

        try:
            record = {}
            record['image'] = {}
            record['image']['imageId'] = imageId
            record['image']['imagedata'] = contexts['anchore_db'].load_image_new(imageId)
        
            savelist.append(record)
        except Exception as err:
            anchore_print_err("could not find record for image ("+str(imageId)+")")
            ecode = 1

    if ecode == 0:
        try:
            with open(outfile, 'w') as OFH:
                OFH.write(json.dumps(savelist))
        except Exception as err:
            anchore_print_err("operation failed: " + str(err))
            ecode = 1

    sys.exit(ecode)

@toolbox.command(name='kubesync')
def kubesync():
    """Communicate with kubernetes deployment via kubectl and save image names/IDs to local files"""

    ecode = 0

    try:
        images = anchore_utils.get_images_from_kubectl()
        if images:
            anchore_print("Writing image IDs to ./anchore_imageIds.kube")
            with open("anchore_imageIds.kube", 'w') as OFH:
                for imageId in images:
                    OFH.write(imageId + "\n")
            anchore_print("Writing image names to ./anchore_imageNames.kube")
            with open("anchore_imageNames.kube", 'w') as OFH:
                for imageId in images:
                    OFH.write(images[imageId] + "\n")
                    
    except Exception as err:
        anchore_print_err("operation failed: " + str(err))
        ecode = 1

    sys.exit(ecode)

@toolbox.command(name='import')
@click.option('--infile', help='input file that contains anchore image data from a previous export', type=click.Path(exists=True), metavar='<file.json>', required=True)
def image_import(infile):
    """Import image anchore data from a JSON file."""
    ecode = 0
    
    try:
        with open(infile, 'r') as FH:
            savelist = json.loads(FH.read())
    except Exception as err:
        anchore_print_err("could not load input file: " + str(err))
        ecode = 1

    if ecode == 0:
        for record in savelist:
            try:
                imageId = record['image']['imageId']
                if contexts['anchore_db'].is_image_present(imageId):
                    anchore_print("image ("+str(imageId)+") already exists in DB, skipping import.")
                else:
                    imagedata = record['image']['imagedata']
                    try:
                        rc = contexts['anchore_db'].save_image_new(imageId, report=imagedata)
                        if not rc:
                            contexts['anchore_db'].delete_image(imageId)
                            raise Exception("save to anchore DB failed")
                    except Exception as err:
                        contexts['anchore_db'].delete_image(imageId)
                        raise err
            except Exception as err:
                anchore_print_err("could not store image ("+str(imageId)+") from import file: "+ str(err))
                ecode = 1

    sys.exit(ecode)

@toolbox.command(name='images')
@click.option('--no-trunc', help='Do not truncate imageIds', is_flag=True)
def images(no_trunc):
    ecode = 0

    import datetime
    
    try:
        anchoreDB = contexts['anchore_db']

        header = ["Repository", "Tag", "Image ID", "Distro", "Last Analyzed", "Size"]
        result = {"multi":{'result':{'header':header, 'rows':[]}}}

        hasData = False
        for image in anchoreDB.load_all_images_iter():
            try:
                imageId = image[0]
                imagedata = image[1]
                meta = imagedata['meta']

                name = meta['humanname']
                shortId = meta['shortId']
                size = meta['sizebytes']

                if no_trunc:
                    printId = imageId
                else:
                    printId = shortId

                patt = re.match("(.*):(.*)", name)
                if patt:
                    repo = patt.group(1)
                    tag = patt.group(2)
                else:
                    repo = "<none>"
                    tag = "<none>"

                oldtags = ','.join(imagedata['anchore_all_tags'])

                if meta['usertype']:
                    atype = meta['usertype']
                else:
                    atype = "<none>"

                distrometa = anchore_utils.get_distro_from_imageId(imageId)
                distro = distrometa['DISTRO'] + "/" + distrometa['DISTROVERS']

                amanifest = anchoreDB.load_analyzer_manifest(imageId)
                latest = 0;
                if amanifest:
                    for a in amanifest.keys():
                        ts = amanifest[a]['timestamp']
                        if ts > latest:
                            latest = ts
                
                if latest:
                    timestr = datetime.datetime.fromtimestamp(int(latest)).strftime('%m-%d-%Y %H:%M:%S')
                else:
                    timestr = "Not Analyzed"
                    
                row = [repo, tag, printId, distro, timestr, str(round(float(size) / 1024.0 / 1024.0, 2)) + "M"]
                result['multi']['result']['rows'].append(row)
                #t.add_row(row)
                hasData = True
            except Exception as err:
                raise err

        anchore_utils.print_result(config, result)

    except:
        anchore_print_err("operation failed")
        ecode = 1            

    sys.exit(ecode)

@toolbox.command(name='show')
def show():
    """Show image summary information"""

    if not nav:
        sys.exit(1)

    ecode = 0
    try:
        image=contexts['anchore_allimages'][imagelist[0]]

        o = collections.OrderedDict()
        mymeta = {}
        mymeta.update(image.meta)
        o['IMAGEID'] = mymeta.pop('imageId', "N/A")
        o['REPOTAGS'] = image.get_alltags_current()
        o['DISTRO'] = image.get_distro()
        o['DISTROVERS'] = image.get_distro_vers()
        o['HUMANNAME'] = mymeta.pop('humanname', "N/A")
        o['SHORTID'] = mymeta.pop('shortId', "N/A")
        o['PARENTID'] = mymeta.pop('parentId', "N/A")
        o['BASEID'] = image.get_earliest_base()
        o['IMAGETYPE'] = mymeta.pop('usertype', "N/A")

        for k in o.keys():
            if type(o[k]) is list:
                s = ' '.join(o[k])
            else:
                s = str(o[k])
            print k+"='"+s+"'"

    except:
        anchore_print_err("operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()

    sys.exit(ecode)

