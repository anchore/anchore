# Changelog

## 1.1.3 (2017-03-29)

+ New option to analyze (--layerstrategy) which allows the user to select which intermediate images are analyzed between the specified image and the earliest image in the familytree.  The default behavior now is to analyze only images marked as 'base' in the familytree, as well as the specified image and the earliest image in the tree.
+ Added ability to use a prefix wildcard (*) character in anchore global whitelists
+ Added new triggers (PKGVULN*) to the ANCHORESEC gate, which allows global whitelisting of CVE+PKG vulnerabilities
	
## 1.1.2 (2017-03-08)

+ Lots of new anchore modules (run 'anchore query' for a list of new queries, and 'anchore gate --show-gatehelp' for a list of new policy/gate items)
+ Added gate modules for checking status of NPM and GEM packages (npm_check and gem_check)
+ Added gate modules for specifying license and package blacklists (license_blacklist and package_blacklist)
+ Added gate module that checks for package existance (check_package_info)
+ Added gate module that checks that base image up-to-date (check_image)
+ Added trigger to the dockerfile gate module for ensuring HEALTHCHECK is present in Dockerfiles
+ Added trigger to the dockerfile gate module for ensuring that a Dockerfile exists
+ Added query for listing files that are not known to be owned by any installed package
+ Added queries for getting more detail about installed packages (list-package-detail, list-package-licenses)
+ Minor bug fixes and error reporting improvements

## 1.1.1 (2017-02-14)

+ Added analyzer, gate, and query modules that allow searching and gating based on regular expression matches of file contents 
  and file names (for finding secrets/keys/other items in files)
+ Added 'anchore toolbox images' feature to give a quick tabular view of all analyzed images in the anchore DB
+ Improved query list time by only re-running query modules for help output if the query module has changed
+ Improved CVE scan feed handling to allow for ensuring unique data values in the feed, which happens if CVE data for a given CVE is updated
+ Fixed issue in where a CVE scan would show no warning if a container appears to be a supported distro but has no package information present
	
## 1.1.0 (2017-02-03)

+ Added Ruby GEM package analyzer and queries (list-gems, list-gem-detail)
+ Added Alpine Linux to vulnerability feed in order to perform CVE scans against Alpine-based container images
+ New feature 'global whitelist' which enables the ability to filter policy triggers during container gate checking for all images
+ Improved analyzer performance by switching to new method of 'squashing' image layers into complete root filesystem
+ Improved CVE data feed by including Ubuntu 16.10 vulnerability data
+ Removed the need to specify '--imagetype' during image analysis (default is now set to 'none' if --imagetype is not supplied)
+ Fixed issue in Debian-based CVE scanning which was showing only 'source' package names instead of installed package names
+ Fixed issue in Alpine package analysis which was truncating results if the license field was not present in the package manifest
+ Fixed issue in shell-based queries (list-files) which would sometimes cause output to contain image summary data instead of file listing

## 1.0.3 (2016-12-07)

+ Adding dockerfiles that are used to build anchore container images hosted on github
+ Fixed bug preventing some ubuntu image distro values from being correctly detected, preventing CVE scan queries/gates from functioning
+ Fixed bug preventing some alpine packages from being correctly analyzed/displayed

## 1.0.2 (2016-12-06)

+ Added Node Package Manager (NPM) analyzer and queries (list-npms, list-npm-detail)
+ Added new 'show' operation to feeds command which displays detailed information about the given feed
+ Added new 'whoami' command to show details about currently logged in (or anonymous) user
+ Added new 'export' command to generate complete data dump of anchore image, and 'import' to load an exported image from a file
+ Added ability to override anchore configuration items on the CLI - for example when using/specifying a custom module directory
+ New anchore gate option '--show-policytemplate' which dynamically generates a complete policy template based on currently available gates
+ New anchore DB subsystem that is modular and configurable, initial driver is compatible with 1.0.X anchore data stores
+ Improved performance of input image name to unique image ID mapping/detection
+ Improved ability for anchore to run without docker installed/running
+ Improved anchore gate option '--show-gatehelp' which displays description, trigger, and parameter information
+ Improved help and usage strings for queries, gates, and many operations
+ Improved several queries to generate better warnings when query could not correct execute for known reasons
+ Improved 'show-file-diffs' query now supports ability to exclude/filter results
+ Improved 'retrieved-files' analyzer/queries that support namespacing when multiple analyzers potentially store the same file
+ Fixed issue preventing anchore from working against older docker API versions
+ Fixed issue preventing image OS detection from working when a container image's 'likedistro' contained a list
+ Fixed issue that caused non-ascii strings from being correctly stored for file analysis

## 1.0.1 (2016-10-06)

+ Fixed issue preventing certain CVEs from being correctly identified when package version strings omitted a release number

## 1.0.0 (2016-10-01)

+ Many new analyzer, gate, and query modules available
+ Many UX improvements,	clarifications and reductions of length	of CLI commands
+ Many new toolbox operations for quick	image summary information and other useful commands
+ Added	anchore	gate options to	allow for a policy file to be passed as a parameter for	one-time evaluation
+ Added	anchore	gate options to	create,	read, update, delete anchore policies
+ Added	anchore	gate option to dynamically generate description, trigger and parameter options for all installed gate modules
+ Added	support	for 'spaces in strings'	for anchore module header and metadata fields
+ Added	sha256 checksum	support	for container image file checksumming
+ Added	support	for user modules (analyzer/gate/queries)
+ New data feeds subsystem with more granular subscription/listing/and syncing operations
+ New login/logout commands for	signing	in with	credentials from anchore.io
+ New anchore release artifacts	now available -	RPM, DEB, and container	images hosted on dockerhub
+ New ability for anchore queries to produce warning output, to	differentiate between module execution failure and more	fine grained known failures
+ New analyzer execution subsystem that	only re-executes analyzers when	module has changed
+ Improved ability to correctly detect container image OS distributions
+ Improved analyzer performance	significantly
+ Improved configuration options including customizable	timeouts and retries between anchore and dependent subsystems
+ Fixed	many corner case bugs in query modules from initial implementation
+ Fixed	many non-ascii string handling issues

## 0.9.0 (2016-06-15)

+ Initial Release
