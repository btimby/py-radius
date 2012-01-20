%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%define bname py-radius

Name:           python-%{bname}
Version:        1.0.2
Release:        2%{?dist}
Summary:        Python RADIUS authentication module
Group:          Development/Languages
License:        BSD
URL:            https://github.com/btimby/py-radius
Source0:        https://github.com/downloads/btimby/%{bname}/%{bname}-%{version}.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
%if 0%{?fedora} >= 8
BuildRequires: python-setuptools-devel
%else
BuildRequires: python-setuptools
%endif
BuildArch:      noarch


%description
This module provides basic RADIUS client capabilities, allowing your
Python code to authenticate against any RFC2138 compliant RADIUS server.


%prep
%setup -q -n %{bname}-%{version}


%build
echo -n


%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install --root %{buildroot}


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
#%doc LICENSE.txt README.md RFC2138
%{python_sitelib}/radius.py*
%{python_sitelib}/py_radius-%{version}-py2.7.egg-info


%changelog
* Fri Jan 20 2012 Ben Timby <btimby@gmail.com> 1.0.2-2
- Added bname and .egg-info

* Tue Jan 17 2012 Luiz Viana <luizxx@gmail.com> 1.0.2-1
- Initial build
