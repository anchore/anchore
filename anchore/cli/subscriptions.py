# Main entry point for the registry manager cli
import click

from anchore.catalog import AnchoreCatalog
from anchore.cli.common import anchore_print, anchore_print_err

working_catalog = None


@click.group()
@click.pass_obj
def subscriptions(anchore_config):
    """
    Manage local subscriptions. Subscriptions are selections from the anchore service for images to pull. These commands
    affect the set of images that will get pulled down during a catalog sync. see anchore-sync-catalog(1).

    The list of available tags must be populated from the anchore service, so you first must run 'anchore sync catalog'
    to get populate the list of options.

    Examples:
    \b
    anchore subscriptions show --tags ubuntu
    anchore subscriptions add ubuntu:wiley

    """
    assert anchore_config is not None

    # Initialize the registry object
    global working_catalog
    try:
        working_catalog = AnchoreCatalog(config=anchore_config)
    except:
        anchore_print_err('Failed loading catalog. Please check config file: %s' % anchore_config.config_file)
        exit(2)


@subscriptions.command(short_help='Show available subscription options.')
@click.option('--subscribed', is_flag=True, default=False, help='Show only the current subscription values')
@click.option('--tags', is_flag=True, default=False, help='Show available tags, not just repo names')
@click.argument('filters', nargs=-1, default=None, metavar='<repo>')
def show(subscribed, tags, filters):
    """
    Show the subscription options available and/or the current subscription list.

    Examples:

    Show all tags for all available repos for subscription: 'anchore subscriptions show --tags'
    Show all tags for centos available for subscription: 'anchore subscriptions show centos --tags'
    Show only the current subscriptions: 'anchore subscriptions show --subscribed'

    """

    if not working_catalog.has_db():
        anchore_print_err('No local analysis db detected. You probably need to run "anchore sync catalog" first to initialize')
        exit(5)

    results = {}
    try:
        if filters:
            results['Current Subscription'] = filter(lambda x: x in filters, working_catalog.subscription.get())
        else:
            results['Current Subscription'] = working_catalog.subscription.get()

    except:
        anchore_print_err('Failed getting subscription data.')
        exit(1)

    if not subscribed:
        repos = working_catalog.metadata.engine_repos
        tag_set = working_catalog.metadata.engine_tags
        if filters:
            filtered_repos = filter(lambda x: (x in repos) or (x in tag_set), filters)
        else:
            filtered_repos = repos

        if not tags:
            results['Available'] = filtered_repos
        else:
            results['Available'] = {}
            for r in filtered_repos:
                results['Available'][r] = filter(lambda x: x.startswith(r), tag_set)

    anchore_print(results, do_formatting=True)
    return


@subscriptions.command(short_help='Add image tags to the subscription list')
@click.argument('repos', nargs=-1, metavar='<repo or tag>')
def add(repos):
    """
    Adds the specified images/tags to the subscription. Tags are formatted as docker image tags. Values are checked
    against the list of available tags from the service. Run 'anchore subscriptions show' to get the list of available
    options. Because of this, you must run an initial 'anchore sync catalog' before subscription data is available.

    Duplicate entries are prevented and will not result in an error, but will be discarded.

    Tag/repo examples: ubuntu, centos:7, nginx:latest

    """

    if not working_catalog.has_db():
        anchore_print_err('No local analysis db detected. You probably need to run "anchore sync catalog" first to initialize')
        exit(5)

    repo_list = list(repos)

    try:
        working_catalog.subscribe(repo_list)
        if working_catalog.configuration().cliargs['json']:
            anchore_print(working_catalog.subscription.get(), do_formatting=True)
        else:
            anchore_print('\n'.join(working_catalog.subscription.get()))
    except:
        anchore_print_err('Failed adding %s to subscription' % repo_list)
        exit(1)


@subscriptions.command(name='rm', short_help='Remove entries from the subscription list')
@click.argument('repos', nargs=-1, metavar='<repo or tag>')
def remove_subscription(repos):
    """
    Removes the specified images/tags to the subscription. Tags are formatted as docker image tags. Accepts values from
    the list of current subscriptions, reachable with 'anchore subscriptions show --subscribed'.
    """

    if not working_catalog.has_db():
        anchore_print_err('No local analysis db detected. You probably need to run "anchore sync catalog" first to initialize')
        exit(5)

    repo_list = list(repos)
    try:
        working_catalog.unsubscribe(repo_list)
        if working_catalog.configuration().cliargs['json']:
            anchore_print(working_catalog.subscription.get(), do_formatting=True)
        else:
            anchore_print('\n'.join(working_catalog.subscription.get()))

    except:
        anchore_print_err('Failed adding %s to subscription' % repo_list)
        exit(1)




