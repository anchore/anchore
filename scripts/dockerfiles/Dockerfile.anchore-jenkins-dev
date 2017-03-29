FROM centos:latest
ENV LANG=en_US.UTF-8
COPY anchore/ /root/anchore/
COPY update-anchore.sh /root/
RUN yum -y update && yum -y install epel-release && yum -y install python-pip rpm-python dpkg && yum clean all && cd /root/anchore && pip install --upgrade . && anchore feeds sync && rm -rf /root/.anchore/data/* && echo >> /root/.anchore/conf/config.yaml && echo "log_file: '/var/log/anchore.log'" >> /root/.anchore/conf/config.yaml && echo "debug_log_file: '/var/log/anchore.log'" >> /root/.anchore/conf/config.yaml && anchore query
CMD /root/update-anchore.sh

