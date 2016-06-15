import sys
import click

from anchore.cli.common import build_image_list, anchore_print, anchore_print_err, extended_help_option
from anchore import visualizer, navigator, anchore_image_db, anchore_utils
from anchore.util import contexts

config = {}
imagelist = []
nav = None
vis = None

@click.group(short_help='Search, report and query specified image IDs.')
@click.option('--image', help='Process specified image ID', metavar='<imageid>')
@click.option('--imagefile', help='Process image IDs listed in specified file', type=click.Path(exists=True), metavar='<file>')
@click.option('--include-allanchore', help='Include all images known by anchore', is_flag=True)
@click.pass_obj
@extended_help_option()
def explore(anchore_config, image, imagefile, include_allanchore):
    """
    Explore image content via queries, visualizations and reports for the selected image(s).

    Image IDs can be specified as hash ids, repo names (e.g. centos), or tags (e.g. centos:latest).

    """
    global config, imagelist, nav, vis
    ecode = 0
    success = True
    config = anchore_config

    if image and imagefile:
        raise click.BadOptionUsage('Can only use one of --image, --imagefile')

    try:
        imagedict = build_image_list(anchore_config, image, imagefile, not (image or imagefile), include_allanchore)
        imagelist = imagedict.keys()
    except Exception as err:
        anchore_print_err("could not load any images")
        sys.exit(1)

def init_nav_vis_contexts():
    try:
        # use the obj from the current click context. This is a bit hacky, but works as long as this method is
        # invoked in an execution context of click
        anchore_config = click.get_current_context().obj
        nav = navigator.Navigator(anchore_config=anchore_config, imagelist=imagelist, allimages=contexts['anchore_allimages'])
        vis = visualizer.Visualizer(config=anchore_config, imagelist=imagelist, allimages=contexts['anchore_allimages'])
        return nav, vis
    except Exception as err:
        anchore_print_err("explore operation failed")
        success = False
        ecode = 1

    if not success:
        contexts['anchore_allimages'].clear()
        sys.exit(ecode)

@explore.command(short_help='Generate relationship graph of images.')
@extended_help_option()
def visualize():
    """
    Visualization provides a graphical representation of the relationship between images.

    Output is a set of image files in the tmp dir specified in the anchore config.yaml file or /tmp by default.

    """
    ecode = 0
    args={}
    try:
        nav, vis = init_nav_vis_contexts()
        vis.run()
    except:
        anchore_print_err("visualize operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()

    sys.exit(ecode)


@explore.command(short_help='Run specified query (leave blank to show list).')
@click.argument('module', nargs=-1, metavar='<modulename>')
@extended_help_option()
def query(module):
    """
    Execute the specified query (module) with any parameters it requires. Modules are scripts in a specific location.

    Each query has its own parameters and outputs.

    Examples using pre-defined queries:

    Query all images to see which have the package 'wget' installed:
    'anchore explore query has-package wget'

    """
    ecode = 0
    try:
        nav, vis = init_nav_vis_contexts()

        result = nav.run_query(list(module))
        if result:
            anchore_utils.print_result(config, result)

    except:
        anchore_print_err("query operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()
    sys.exit(ecode)


@explore.command(short_help='Show analysis report of the specified image(s).')
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

    Counts - The counts for various attributes of the images such as packages, files, and suid files

    BaseDiffs - Differences of this image from its base image

    Report outputs these entries in a table format by default.
    """
    ecode = 0

    try:
        nav, vis = init_nav_vis_contexts()

        result = nav.generate_reports()
        if result:
            anchore_utils.print_result(config, result)

    except:
        anchore_print_err("operation failed")

        ecode = 1

    contexts['anchore_allimages'].clear()
    sys.exit(ecode)


