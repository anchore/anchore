import sys
import click

from anchore.cli.common import build_image_list, anchore_print, anchore_print_err, extended_help_option
from anchore import navigator, anchore_utils
from anchore.util import contexts

config = {}
imagelist = []
nav = None

@click.command(short_help='Run specified query (leave blank to show list).')
@click.option('--image', help='Process specified image ID', metavar='<imageid>')
@click.option('--imagefile', help='Process image IDs listed in specified file', type=click.Path(exists=True), metavar='<file>')
@click.option('--include-allanchore', help='Include all images known by anchore', is_flag=True)
@click.argument('module', nargs=-1, metavar='<modulename>')
@click.pass_obj
@extended_help_option()
def query(anchore_config, image, imagefile, include_allanchore, module):
    """
    Image IDs can be specified as hash ids, repo names (e.g. centos), or tags (e.g. centos:latest).

    Execute the specified query (module) with any parameters it requires. Modules are scripts in a specific location.

    Each query has its own parameters and outputs.

    Examples using pre-defined queries:

    'anchore query --image nginx:latest list-packages all'
    'anchore query has-package wget'
    'anchore query --image nginx:latest list-files-detail all'
    'anchore query cve-scan all'

    """

    global config, imagelist, nav
    ecode = 0
    success = True
    config = anchore_config

    if module:
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
                #imagelist = ret.keys()
                imagelist = ret

        except Exception as err:
            anchore_print_err("could not load input images")
            sys.exit(1)

    try:
        nav = init_nav_contexts()

        result = nav.run_query(list(module))
        if result:
            anchore_utils.print_result(config, result)

        if nav.check_for_warnings(result):
            ecode = 2

    except:
        anchore_print_err("query operation failed")
        ecode = 1

    contexts['anchore_allimages'].clear()
    sys.exit(ecode)

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
