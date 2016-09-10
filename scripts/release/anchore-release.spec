Name:           anchore-release
Version:        1.0.0
Release:        1%{?dist}
Source0:        anchore.repo
Source1:        RPM-GPG-KEY-anchore
Summary:        Anchore Release Repo Files
License:        Apache License 2.0
URL:            http://www.anchore.com
BuildArch:      noarch

%description
Package installs the /etc/yum.repos.d/anchore.repo file and associated files to enable the system to download and install Anchore CLI tools.

%install
mkdir -p $RPM_BUILD_ROOT/etc/yum.repos.d
cp -a %{SOURCE0} $RPM_BUILD_ROOT/etc/yum.repos.d/anchore.repo
mkdir -p $RPM_BUILD_ROOT/etc/pki/rpm-gpg
cp -a %{SOURCE1} $RPM_BUILD_ROOT/etc/pki/rpm-gpg

%files
/etc/pki/rpm-gpg/RPM-GPG-KEY-anchore
%config(noreplace) /etc/yum.repos.d/anchore.repo
