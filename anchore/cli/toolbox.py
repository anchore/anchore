import sys
import os
import re
import shutil
from textwrap import fill
import click

from anchore.cli.common import anchore_print, anchore_print_err
from anchore import visualizer, navigator, anchore_utils
from anchore.util import contexts

config = {}
imagelist = []

@click.group(short_help='Useful tools and operations on images and containers')
@click.option('--image', help='Process specified image ID', required=True, metavar='<imageid>')
@click.pass_obj
def toolbox(anchore_config, image):
    """
    A collection of tools for operating on images and containers and building anchore modules.

    Subcommands operate on the specified image passed in as --image <imgid>

    """
    global config, imagelist, nav
    config = anchore_config
    ecode = 0

    imagelist = [image]

    try:
        nav = navigator.Navigator(anchore_config=config, imagelist=imagelist, allimages=contexts['anchore_allimages'])
    except Exception as err:
        anchore_print_err('operation failed')
        nav = None
        ecode = 1


@toolbox.command(name='unpack')
@click.option('--destdir', help='Destination directory for unpacked container image', metavar='<path>')
def unpack(destdir):
    """Unpack and Squash image to local filesystem"""

    if not nav:
        sys.exit(1)

    ecode = 0
    try:
        anchore_print("Unpacking images: " + ' '.join(nav.get_images()))
        result = nav.unpack(destdir=destdir)
        for imageId in result:
            anchore_print("Unpacked image: " + imageId)
            anchore_print("Unpack directory: "+ result[imageId])
    except:
        anchore_print_err("operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()
    
    sys.exit(ecode)

@toolbox.command(name='setup-module-dev', short_help='Setup a module development environment')
@click.option('--destdir', help='Destination directory for module development environment')
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
        helpstr = "This tool has set up and environment that represents what anchore will normally set up before running and analyzer, gate and/or query module.  Each section below includes some information along with a string that you can use to help develop your own anchore modules.\n"
        anchore_print(fill(helpstr, 80))
        anchore_print("")

        anchore_print("Setting up environment...")
        anchore_print("")

        result = nav.unpack(destdir=destdir)
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
            #analyzer_string = ' '.join([examples['analyzers'], imageId, config.data['image_data_store'], config.data['image_data_store'] + "/" + imageId, result[imageId]])
            analyzer_string = ' '.join([examples['analyzers'], imageId, tmpdatastore, dstimgdir, result[imageId]])
            anchore_print("\tAnalyzer Command:\n\n\t" +analyzer_string)
            anchore_print("")

            anchore_utils.write_plainfile_fromstr(result[imageId] + "/queryimages", imageId+"\n")

#            gate_string = ' '.join([examples['gates'], result[imageId] + "/queryimages", config.data['image_data_store'], config.data['image_data_store'] + "/"+imageId+"/gates_output", "all"])
#            anchore_print("***Gate***\n")
#            anchore_print("\tCommand:\n\n\t" + gate_string)
#            anchore_print("")

            queryoutput = '/'.join([result[imageId], "querytmp/"])
            if not os.path.exists(queryoutput):
                os.makedirs(queryoutput)

            #query_string = ' '.join([examples['queries'], result[imageId] + "/queryimages", config.data['image_data_store'], queryoutput, "passwd"])
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
            anchore_print("\tanchore explore --image " + imageId + " query query-example")
            anchore_print("\tanchore explore --image " + imageId + " query query-example passwd")
            anchore_print("\tanchore explore --image " + imageId + " query query-example pdoesntexist")
            
    except:
        anchore_print_err("operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()
    
    sys.exit(ecode)


@toolbox.command(name='show-dockerfile')
def generate_dockerfile():
    """Generate (or display actual) image Dockerfile"""

    if not nav:
        sys.exit(1)

    ecode = 0
    try:
        result = nav.get_dockerfile_contents()
        if result:
            anchore_utils.print_result(config, result, outputmode='raw')

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
        result = nav.get_layers()
        if result:
            anchore_utils.print_result(config, result)

    except:
        anchore_print_err("operation failed")
        #import traceback
        #traceback.print_exc()
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
        result = nav.get_familytree()
        if result:
            anchore_utils.print_result(config, result)

    except:
        anchore_print_err("operation failed")
        #import traceback
        #traceback.print_exc()
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

