%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           python-py-radius
Version:        1.0.2
Release:        1%{?dist}
Summary:        Python RADIUS authentication module
Group:          Development/Languages
License:        BSD
URL:            https://github.com/btimby/py-radius
Source0:        https://github.com/downloads/btimby/py-radius/py-radius-%{version}.tar.gz
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
%setup -q -n py-radius-%{version}


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


%changelog
* Tue Jan 17 2012 Luiz Viana <luizxx@gmail.com> 1.0.2-1
- Initial build
