#!/bin/bash

yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

cat <<EOF
EOF >/etc/yum.repos.d/docker-main.repo
[docker-main-repo]
name=Docker main Repository
baseurl=https://yum.dockerproject.org/repo/main/centos/7
enabled=1
gpgcheck=1
gpgkey=https://yum.dockerproject.org/gpg
EOF

yum -y install docker-engine
service docker start

yum -y install python-pip graphviz dpkg

rsync -azP --delete /home/centos/anchore/ /root/anchore/
rsync -azP --delete /home/centos/dockerfiles/ /root/dockerfiles/

cd ~/anchore/anchore-cli
pip install --user --upgrade .
cd ~/anchore/anchore-registry
pip install --user --upgrade .

#rsync -azP --delete /home/centos/cve-data/ /root/.local/var/anchore/cve-data/

export ANCHOREROOT=/root/.local
export PATH=$ANCHOREROOT/bin:$PATH
anchore --help

anchore-registry init
anchore-registry sync
docker tag centos:latest centos:old                                            

#docker pull centos
#docker pull ubuntu
#docker tag centos:latest centos:old
#anchore --fromdocker analyze
#for i in `docker images --no-trunc | grep -v dev | grep -v IMAGE | awk '{print $3}' | sort | uniq`; do touch ~/.local/var/anchore/data/$i/Anchorefile; done
#anchore --fromdocker analyze

cd ~/dockerfiles
buildem.sh
for i in `\ls -1 | grep dev`; do anchore --image $i analyze --dockerfile ~/dockerfiles/$i/Dockerfile; done
anchore --alldocker analyze

echo
echo
echo
echo "READY TO RUN ANCHORE: Try this..."
echo "export ANCHOREROOT=/root/.local"
echo "export PATH=$ANCHOREROOT/bin:\$PATH"
echo "anchore --alldocker navigate --search --has_package --package sudo"
