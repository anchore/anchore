# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"
  config.vm.hostname="anchore"

  config.vm.provision "shell", inline: <<-SHELL
     apt-get update -y
     sudo apt-get install -y \
       apt-transport-https \
       ca-certificates \
       curl \
       software-properties-common
     curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
     sudo add-apt-repository \
       "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
       $(lsb_release -cs) \
       stable"

     sudo apt-get update
     sudo apt-get install -y docker-ce

     apt-get install -y python-pip python-rpm yum git
     echo 'export LC_CTYPE="en_US.UTF-8"' > /etc/profile.d/locale.sh
     echo 'export LC_ALL=C' > /etc/profile.d/locale.sh
     chmod 755 /etc/profile.d/locale.sh
     echo "export PATH=~/.local/bin:$PATH" > /etc/profile.d/anchore.sh
     chmod 755 /etc/profile.d/anchore.sh
     docker pull nginx:latest
     source /etc/profile.d/anchore.sh
     export LC_CTYPE="en_US.UTF-8"
     export LC_ALL=C
     git clone https://github.com/anchore/anchore.git
     cd anchore
     pip install --upgrade --user .
     anchore feeds list
     anchore feeds sync
   SHELL

  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider "virtualbox" do |v|
       	v.name = "anchore"
	v.memory = 786
	v.cpus=1
	v.customize ["modifyvm", :id, "--uartmode1", "disconnected" ]	
  end
end
