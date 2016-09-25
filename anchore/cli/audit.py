import sys
import click

from anchore.cli.common import build_image_list, anchore_print, anchore_print_err, extended_help_option
from anchore import navigator, anchore_image_db, anchore_utils
from anchore.util import contexts

config = {}
imagelist = []
nav = None

@click.group(short_help='Commands to generate/review audit reports')
@click.option('--image', help='Process specified image ID', metavar='<imageid>')
@click.option('--imagefile', help='Process image IDs listed in specified file', type=click.Path(exists=True), metavar='<file>')
@click.option('--include-allanchore', help='Include all images known by anchore', is_flag=True)
@click.pass_obj
@extended_help_option()
def audit(anchore_config, image, imagefile, include_allanchore):
    """
    Image IDs can be specified as hash ids, repo names (e.g. centos), or tags (e.g. centos:latest).
    """

    global config, imagelist, nav
    ecode = 0
    success = True
    config = anchore_config

    if image and imagefile:
        raise click.BadOptionUsage('Can only use one of --image, --imagefile')

    try:
        imagedict = build_image_list(anchore_config, image, imagefile, not (image or imagefile), include_allanchore)
        imagelist = imagedict.keys()

        try:
            ret = anchore_utils.discover_imageIds(imagelist)
        except ValueError as err:
            raise err
        else:
            imagelist = ret.keys()

    except Exception as err:
        anchore_print_err("could not load input images")
        sys.exit(1)

def init_nav_contexts():
    try:
        # use the obj from the current click context. This is a bit hacky, but works as long as this method is
        # invoked in an execution context of click
        anchore_config = click.get_current_context().obj
        nav = navigator.Navigator(anchore_config=anchore_config, imagelist=imagelist, allimages=contexts['anchore_allimages'])
        return nav
    except Exception as err:
        anchore_print_err("explore operation failed")
        success = False
        ecode = 1

    if not success:
        contexts['anchore_allimages'].clear()
        sys.exit(ecode)

@audit.command(short_help='Generate summarized report of specified images.')
@extended_help_option()
def report():
    """
    Show analysis report of the specified image(s).

    The analysis report includes information on:

    \b
    Image Id - The image id (as a hash)

    Type - The type of image (--imagetype option used when anchore analyze was run)

    CurrentTags - The current set of repo tags on the image

    AllTags - The set of all repo tags that have been on the image during analysis passes

    GateStatus - The overall aggregate gate output status: GO|STOP|WARN

    Size - The size in bytes of the image on disk
    
    Counts - The counts for various attributes of the images such as packages, files, and suid files

    BaseDiffs - Differences of this image from its base image

    Report outputs these entries in a table format by default.
    """
    ecode = 0

    try:
        nav = init_nav_contexts()

        result = nav.generate_reports()
        if result:
            anchore_utils.print_result(config, result)

    except:
        anchore_print_err("operation failed")

        ecode = 1

    contexts['anchore_allimages'].clear()
    sys.exit(ecode)
