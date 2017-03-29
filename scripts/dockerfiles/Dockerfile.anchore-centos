FROM centos:latest
ENV LANG=en_US.UTF-8
RUN yum -y update && yum -y install epel-release https://repo.ancho.re/anchore/1.1/centos/7/noarch/anchore-release-1.1.0-1.el7.centos.noarch.rpm && yum -y install anchore && yum clean all && anchore query && echo >> /root/.anchore/conf/config.yaml && echo "log_file: '/var/log/anchore.log'" >> /root/.anchore/conf/config.yaml && echo "debug_log_file: '/var/log/anchore.log'" >> /root/.anchore/conf/config.yaml && anchore query
CMD tail -F /var/log/anchore.log
