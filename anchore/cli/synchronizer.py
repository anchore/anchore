import click

from anchore.catalog import AnchoreCatalog
from anchore.cli.common import anchore_print, anchore_print_err, extended_help_option

working_catalog = None

sync_direction = ['input', 'output', 'both']

sync_extended_help="""
Manage synchronization activities of the local anchore instance with the anchore service. The primary
operation is the catalog sync, which downloads metadata from the anchore web service and pulls the subscribed images
from dockerhub.com.

user-image sync manages the execution of user-supplied scripts to fetch images for local analysis.

There are two basic kinds of syncs: catalog syncs and user-image syncs.

A catalog sync pulls down the latest metadata from the anchore web service as well as any images from Docker Hub as
specified in the current subscriptions list. See anchore-subscriptions(1) for commands to manage the current
set of subscribed containers.

An initial catalog sync is the first command required to initialize the system upon installation. Until a catalog
sync has occured, the local system has no information about what subscriptions are available from the web service.

Requiring explicit sync invocation is by design so that all of the anchore tools can run without connecting to the
Anchore web service once a sync has been completed to enable the administrator to explicitly control when network
access is needed and used.
"""

@click.group(short_help='Synchronize images and metadata')
@click.pass_obj
@extended_help_option(extended_help=sync_extended_help)
def sync(anchore_config):
    """
    Synchronization of images and metadata with the Anchore web service and image sources.

    The first command run on a new installation of anchore must be 'anchore sync catalog' to initialize the local system.
    See the catalog subcommand help for more information.
    """

    # Initialize the registry object
    global working_catalog
    try:
        working_catalog = AnchoreCatalog(config=anchore_config)
    except:
        anchore_print_err('Failed to initialize catalog internal structures. Cannot continue')
        exit(1)


@sync.command(short_help='Show status of local system for synchronizations')
@click.pass_obj
def status(anchore_config):
    """
    Show state of local anchore images and artifacts.

    Returns structure output with the results of checks of local resources and their staleness compared to
    the upstream service artifacts for items such as vulnerability data and analysis db entries for subscription images.

    The output of this command can be used to determine if/when to run a catalog sync and check if new service data is
    available. This command will use the network to check the service status.
    """

    assert anchore_config is not None

    try:
        result = working_catalog.check_status()
        for k,v in result.items():
            if 'sync' in v:
                result[k] = v['sync']

        anchore_print(result, do_formatting=True)
    except:
        anchore_print_err('Failed checking catalog configuration. Please check config file: %s' % anchore_config.config_file)
        exit(1)


@sync.command(name='catalog', short_help='Update the local catalog with new data from the service')
def sync_catalog():
    """
    Updates the local catalog with the latest from the Anchore web service. Pulls CVE data, analysis metadata for images
    subscribed to as well as updates to subscribed images directly from Docker Hub.
    """

    try:
        working_catalog.pull()
    except:
        anchore_print_err('Catalog sync failed')
        exit(1)


@sync.command(name='user-images', short_help='Execute user-provided input/output scripts.')
@click.argument('operation', type=click.Choice(sync_direction))
@extended_help_option()
def user_images(operation):
    """
    Manages fetching and pushing user images. The operations are: 'input', 'output', 'both'.

    By default, 'both' is invoked and will execute 'input' then 'output' operations in that order.

    Scripts are located as follows, assuming $INSTALL_LOC = distro-specific location where pip installs python packages

    input: $INSTALL_LOC/anchore/anchore-modules/inputs/
    output: $INSTALL_LOC/anchore/anchore-modules/outputs/

    Scripts are executed in lexicographic order by filename and scripts must be marked as executable to be run.
    See the README file in each directory for more information.

    """

    if operation == 'input' or operation == 'all':
        try:
            anchore_print('Executing input scripts')
            working_catalog.inputs.execute()
            anchore_print('Execution of input scripts complete')
        except:
            anchore_print_err('Failed executing input scripts')
            exit(1)

    if operation == 'output' or operation == 'all':
        try:
            anchore_print('Executing output scripts')
            working_catalog.outputs.execute()
            anchore_print('Execution of output scripts complete')
        except:
            anchore_print_err('Failed executing output scripts')
            exit(1)

