.. image:: https://anchore.io/service/badges/image/f017354b717234ebfe1cf1c5d538ddc8618f3ab0d8c67e290cf37f578093d121
    :target: https://anchore.io/image/dockerhub/f017354b717234ebfe1cf1c5d538ddc8618f3ab0d8c67e290cf37f578093d121?repo=anchore%2Fcli&tag=latest#overview



Anchore
=======

Anchore is a container inspection and analytics platform to enable
operators to deploy containers with confidence. The Anchore toolset in
this repository provides the ability to inspect, reason about, and
evaluate policy against containers present on the local Docker host.

Using Anchore via Docker
========================
Anchore is available as a `Docker image <https://hub.docker.com/r/anchore/cli/>`_. 

1. ``docker pull anchore/cli``
2. ``docker run -d -v /var/run/docker.sock:/var/run/docker.sock --name anchore anchore/cli:latest``
3. ``docker exec anchore anchore feeds sync``
4. Use docker exec to run anchore commands in the container, such as: ``docker exec anchore anchore analyze --image <myimage> --dockerfile </path/to/Dockerfile>``

The general model is to run the container in detached mode to provide the environment and use 'docker exec' to execute anchore commands within the container. See the above link on how to use the container specifically and options that are container specific. 


Using Anchore Installed Directly on Host
========================================

To get started on CentOS 7 as root:

1) install docker (see docker documentation for CentOS 7 install instructions)

``https://docs.docker.com/engine/installation/linux/centos/``

2) install some packages that full functionality of anchore will require (run as root or with sudo)

``yum install epel-release``

``yum install python-pip rpm-python dpkg``

To get started on Ubuntu >= 15.10  as root:

1) install docker engine >= 1.10 (see docker documentation for Ubuntu >= 15.10 install instructions)

``https://docs.docker.com/engine/installation/linux/ubuntulinux/``

2) install some packages that full functionality of anchore will require (run as root or with sudo)

``apt-get install python-pip python-rpm yum``

Next, on either distro:

3) install Anchore to ~/.local/

``cd <where you checked out anchore>``

``pip install --upgrade --user .``

``export PATH=~/.local/bin:$PATH``

4) run anchore!  Here is a quick sequence of commands to help get going

``anchore --help``

``docker pull nginx:latest``

``anchore feeds list``

``anchore feeds sync``

``anchore analyze --image nginx:latest --imagetype base``

``anchore audit --image nginx:latest report``

``anchore query --image nginx:latest has-package curl wget``

``anchore query --image nginx:latest list-files-detail all``

``anchore query --image nginx:latest cve-scan all``

``anchore toolbox --image nginx:latest show``

For more information, to learn about how to analyze your own
application containers, and how to customize/extend Anchore, please
visit our github page wiki at https://github.com/anchore

Jenkins
=======

If you are a Jenkins user, please visit our github wiki installation
documentation at
https://github.com/anchore/anchore/wiki/Installing-Anchore to learn
more about using the Jenkins Anchore build-step plugin.


Vagrant
=======

* Install Vagrant and Virtualbox
* Download the Vagrantfile
* ``vagrant up``
* ``vagrant ssh``
* ``sudo -i``
* Continue with step 4)

Manual Pages
============
Man pages for most of the anchore commands are available in: $anchore/doc/man, where $anchore is the install
location of the python code for your distro (e.g. /usr/local/lib/python2.7/dist-packages/anchore for ubuntu).
To install them, copy them to the appropriate location for your distro. The man pages are generated from --help
and --extended-help options to anchore commands, so similar content is available direclty from the CLI as well.

