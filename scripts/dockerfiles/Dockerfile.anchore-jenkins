FROM centos:latest
ENV LANG=en_US.UTF-8
COPY update-anchore.sh /root/
RUN yum -y update && yum -y install epel-release https://repo.ancho.re/anchore/1.1/centos/7/noarch/anchore-release-1.1.0-1.el7.centos.noarch.rpm && yum -y install anchore && yum clean all && anchore feeds sync && rm -rf /root/.anchore/data/* && echo >> /root/.anchore/conf/config.yaml && echo "log_file: '/var/log/anchore.log'" >> /root/.anchore/conf/config.yaml && echo "debug_log_file: '/var/log/anchore.log'" >> /root/.anchore/conf/config.yaml && anchore query
CMD /root/update-anchore.sh
