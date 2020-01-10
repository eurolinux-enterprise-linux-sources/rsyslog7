%global mysql_config_path %{_libdir}/mysql
%global _exec_prefix %{nil}
%global _libdir %{_exec_prefix}/%{_lib}
%define rsyslog_pkidir %{_sysconfdir}/pki/rsyslog
%global rsyslog_statedir /var/lib/rsyslog

Summary: Enhanced system logging and kernel message trapping daemon
Name: rsyslog7
Version: 7.4.10
Release: 3%{?dist}
License: (GPLv3+ and ASL 2.0)
Group: System Environment/Daemons
URL: http://www.rsyslog.com/
Source0: http://www.rsyslog.com/files/download/rsyslog/rsyslog-%{version}.tar.gz
Source1: rsyslog.init
Source2: rsyslog.conf
Source3: rsyslog.sysconfig
Source4: rsyslog.log
Patch0: rsyslog-7.4.10-rhbz820311-debug-mode-description.patch
Patch1: rsyslog-7.4.10-rhbz886117-numerical-uid-guid.patch
Patch2: rsyslog-7.4.10-remove-liblogging-stdlog.patch
Patch3: rsyslog-7.4.10-rhbz1009048-imrelp-keepalive.patch
Patch4: rsyslog-7.4.10-omelasticsearch-atomic-inst.patch
Patch5: rsyslog-7.4.10-rhbz994127-file-sync-description.patch
Patch6: rsyslog-7.4.10-rhbz1020431-imuxsock-missing-msg.patch
Patch7: rsyslog-7.4.10-rhbz996862-division-by-zero.patch
Patch8: rsyslog-7.4.10-rhbz1009882-pid-file.patch
Patch9: rsyslog-7.4.10-rhbz1030040-remove-ads.patch
Patch10: rsyslog-7.4.10-rhbz1030206-add-mmcount.patch
Patch11: rsyslog-7.4.10-rhbz1096732-imuxsock-socket-limit.patch
Patch12: rsyslog-7.4.10-rhbz1142373-cve-2014-3634.patch
BuildRequires: bison
BuildRequires: flex
BuildRequires: json-c-devel
BuildRequires: libestr-devel >= 0.1.9
BuildRequires: libuuid-devel
BuildRequires: pkgconfig
BuildRequires: zlib-devel
Requires: logrotate >= 3.5.2
Requires: bash >= 2.0
Requires(post): /sbin/chkconfig coreutils
Requires(preun): /sbin/chkconfig /sbin/service
Requires(postun): /sbin/service
Provides: syslog
Obsoletes: sysklogd <= 1.4.1-46
Conflicts: rsyslog
# newer version of selinux-policy is needed, reference: #838148
Conflicts: selinux-policy < 3.7.19-128
BuildRoot: %{_tmppath}/rsyslog-%{version}-%{release}-root-%(%{__id_u} -n)

%package elasticsearch
Summary: ElasticSearch output module for rsyslog
Group: System Environment/Daemons
Requires: %name = %version-%release
BuildRequires: libcurl-devel

%package mysql
Summary: MySQL support for rsyslog
Group: System Environment/Daemons
Requires: %name = %version-%release
BuildRequires: mysql-devel >= 4.0

%package pgsql
Summary: PostgresSQL support for rsyslog
Group: System Environment/Daemons
Requires: %name = %version-%release
BuildRequires: postgresql-devel

%package gssapi
Summary: GSSAPI authentication and encryption support for rsyslog
Group: System Environment/Daemons
Requires: %name = %version-%release
BuildRequires: krb5-devel 

%package relp
Summary: RELP protocol support for rsyslog
Group: System Environment/Daemons
Requires: %name = %version-%release
# earlier versions segfault if KEEPALIVE is enabled
BuildRequires: librelp-devel >= 1.2.7-2

%package gnutls
Summary: TLS protocol support for rsyslog
Group: System Environment/Daemons
Requires: %name = %version-%release
BuildRequires: gnutls-devel

%package snmp
Summary: SNMP protocol support for rsyslog
Group: System Environment/Daemons
Requires: %name = %version-%release
BuildRequires: net-snmp-devel

%description
Rsyslog is an enhanced, multi-threaded syslog daemon. It supports MySQL,
syslog/TCP, RFC 3195, permitted sender lists, filtering on any message part,
and fine grain output format control. It is compatible with stock sysklogd
and can be used as a drop-in replacement. Rsyslog is simple to set up, with
advanced features suitable for enterprise-class, encryption-protected syslog
relay chains.

%description elasticsearch
This module provides the capability for rsyslog to feed logs directly into
Elasticsearch.

%description mysql
The rsyslog-mysql package contains a dynamic shared object that will add
MySQL database support to rsyslog.

%description pgsql
The rsyslog-pgsql package contains a dynamic shared object that will add
PostgreSQL database support to rsyslog.

%description gssapi
The rsyslog-gssapi package contains the rsyslog plugins which support GSSAPI 
authentication and secure connections. GSSAPI is commonly used for Kerberos 
authentication.

%description relp
The rsyslog-relp package contains the rsyslog plugins that provide
the ability to receive syslog messages via the reliable RELP
protocol. 

%description gnutls
The rsyslog-gnutls package contains the rsyslog plugins that provide the
ability to receive syslog messages via upcoming syslog-transport-tls
IETF standard protocol.

%description snmp
The rsyslog-snmp package contains the rsyslog plugin that provides the
ability to send syslog messages as SNMPv1 and SNMPv2c traps.

%prep
%setup -q -n rsyslog-%{version}
%patch0 -p1 -b .rhbz820311
%patch1 -p1 -b .rhbz886117
%patch2 -p1 -b .liblogging-stdlog
%patch3 -p1 -b .rhbz1009048
%patch4 -p1 -b .omelasticsearch-atomic-inst
%patch5 -p1 -b .rhbz994127
%patch6 -p1 -b .rhbz1020431
%patch7 -p1 -b .rhbz996862
%patch8 -p1 -b .rhbz1009882
%patch9 -p1 -b .rhbz1030040
%patch10 -p1 -b .rhbz1030206
%patch11 -p1 -b .rhbz1096732
%patch12 -p1 -b .rhbz1142373

%build
# workaround for mysql_conf multilib issue, bug #694414
export PATH="%{mysql_config_path}:$PATH"

export CFLAGS="$RPM_OPT_FLAGS -fpie -DSYSLOGD_PIDNAME=\\\"syslogd.pid\\\""
export LDFLAGS="-pie -Wl,-z,relro -Wl,-z,now"
%configure \
	--disable-libgcrypt \
	--disable-static \
	--disable-testbench \
	--disable-usertools \
	--enable-elasticsearch \
	--enable-gnutls \
	--enable-gssapi-krb5 \
	--enable-imdiag \
	--enable-imfile \
	--enable-impstats \
	--enable-imptcp \
	--enable-mail \
	--enable-mmanon \
	--enable-mmcount \
	--enable-mmjsonparse \
	--enable-mmsnmptrapd \
	--enable-mysql \
	--enable-omprog \
	--enable-omuxsock \
	--enable-pgsql \
	--enable-pmaixforwardedfrom \
	--enable-pmcisconames \
	--enable-pmlastmsg \
	--enable-pmsnare \
	--enable-relp \
	--enable-snmp \
	--enable-unlimited-select \

make V=1

%install
rm -rf $RPM_BUILD_ROOT

make install DESTDIR=$RPM_BUILD_ROOT

install -d -m 755 $RPM_BUILD_ROOT%{_initrddir}
install -d -m 755 $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
install -d -m 755 $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
install -d -m 755 $RPM_BUILD_ROOT%{_sysconfdir}/rsyslog.d
install -d -m 700 $RPM_BUILD_ROOT%{rsyslog_statedir}
install -d -m 700 $RPM_BUILD_ROOT%{rsyslog_pkidir}

install -p -m 755 %{SOURCE1} $RPM_BUILD_ROOT%{_initrddir}/rsyslog
install -p -m 644 %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/rsyslog.conf
install -p -m 644 %{SOURCE3} $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/rsyslog
install -p -m 644 %{SOURCE4} $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/syslog

#get rid of *.la
rm $RPM_BUILD_ROOT/%{_libdir}/rsyslog/*.la

# convert line endings from "\r\n" to "\n"
cat tools/recover_qi.pl | tr -d '\r' > $RPM_BUILD_ROOT%{_bindir}/rsyslog-recover-qi.pl

# get rid of unused images
rm -f \
	doc/queue_msg_state.jpeg \
	doc/rsyslog-vers.png \
	doc/rsyslog_queue_pointers.jpeg \
	doc/rsyslog_queue_pointers2.jpeg \
	doc/tls_cert.jpg \
	doc/tls_cert_100.jpg \
	doc/tls_cert_ca.jpg \

%post
/sbin/chkconfig --add rsyslog
for n in /var/log/{messages,secure,maillog,spooler}
do
	[ -f $n ] && continue
	umask 066 && touch $n
done

%preun
if [ $1 = 0 ]; then
	service rsyslog stop >/dev/null 2>&1 ||:
	/sbin/chkconfig --del rsyslog
fi

%postun
if [ "$1" -ge "1" ]; then
	service rsyslog condrestart > /dev/null 2>&1 ||:
fi	

%triggerun -- rsyslog < 4.6.2-5
# previous versions used a different lock file, which would break condrestart
[ -f /var/lock/subsys/rsyslogd ] || exit 0
mv /var/lock/subsys/rsyslogd /var/lock/subsys/rsyslog
[ -f /var/run/rklogd.pid ] || exit 0
/bin/kill `cat /var/run/rklogd.pid 2> /dev/null` > /dev/null 2>&1 ||:

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING* ChangeLog NEWS README
%doc doc/*html doc/*.jpg doc/*.png
%dir %{_libdir}/rsyslog
%{_libdir}/rsyslog/imdiag.so
%{_libdir}/rsyslog/imklog.so
%{_libdir}/rsyslog/immark.so
%{_libdir}/rsyslog/impstats.so
%{_libdir}/rsyslog/imptcp.so
%{_libdir}/rsyslog/imtcp.so
%{_libdir}/rsyslog/imudp.so
%{_libdir}/rsyslog/imuxsock.so
%{_libdir}/rsyslog/imfile.so
%{_libdir}/rsyslog/lmnet.so
%{_libdir}/rsyslog/lmregexp.so
%{_libdir}/rsyslog/lmtcpclt.so
%{_libdir}/rsyslog/lmtcpsrv.so
%{_libdir}/rsyslog/lmnetstrms.so
%{_libdir}/rsyslog/lmnsd_ptcp.so
%{_libdir}/rsyslog/lmstrmsrv.so
%{_libdir}/rsyslog/lmzlibw.so
%{_libdir}/rsyslog/mmanon.so
%{_libdir}/rsyslog/mmcount.so
%{_libdir}/rsyslog/mmjsonparse.so
%{_libdir}/rsyslog/mmsnmptrapd.so
%{_libdir}/rsyslog/ommail.so
%{_libdir}/rsyslog/omprog.so
%{_libdir}/rsyslog/omruleset.so
%{_libdir}/rsyslog/omtesting.so
%{_libdir}/rsyslog/omuxsock.so
%{_libdir}/rsyslog/pmaixforwardedfrom.so
%{_libdir}/rsyslog/pmcisconames.so
%{_libdir}/rsyslog/pmlastmsg.so
%{_libdir}/rsyslog/pmsnare.so
%config(noreplace) %{_sysconfdir}/rsyslog.conf
%config(noreplace) %{_sysconfdir}/sysconfig/rsyslog
%config(noreplace) %{_sysconfdir}/logrotate.d/syslog
%dir %{_sysconfdir}/rsyslog.d
%dir %{rsyslog_statedir}
%dir %{rsyslog_pkidir}
%{_initrddir}/rsyslog
%{_sbindir}/rsyslogd
%attr(755,root,root) %{_bindir}/rsyslog-recover-qi.pl
%{_mandir}/*/*

%files elasticsearch
%defattr(-,root,root)
%{_libdir}/rsyslog/omelasticsearch.so

%files mysql
%defattr(-,root,root)
%doc plugins/ommysql/createDB.sql
%{_libdir}/rsyslog/ommysql.so

%files pgsql
%defattr(-,root,root)
%doc plugins/ompgsql/createDB.sql
%{_libdir}/rsyslog/ompgsql.so

%files gssapi
%defattr(-,root,root)
%{_libdir}/rsyslog/lmgssutil.so
%{_libdir}/rsyslog/imgssapi.so
%{_libdir}/rsyslog/omgssapi.so

%files relp
%defattr(-,root,root)
%{_libdir}/rsyslog/imrelp.so
%{_libdir}/rsyslog/omrelp.so

%files gnutls
%defattr(-,root,root)
%{_libdir}/rsyslog/lmnsd_gtls.so

%files snmp
%defattr(-,root,root)
%{_libdir}/rsyslog/omsnmp.so

%changelog
* Thu Oct 09 2014 Tomas Heinrich <theinric@redhat.com> 7.4.10-3
- fix CVE-2014-3634
  resolves: #1149150

* Fri Jun 06 2014 Tomas Heinrich <theinric@redhat.com> 7.4.10-2
- amend rsyslog.conf man page with information on omitting file sync
  resolves: #994127
- add a patch to support TCP KEEPALIVE in imrelp
  resolves: #1009048
- add a patch to fix missing note about message repetition in imuxsock
  resolves: #1020431
- add a patch to prevent division-by-zero errors
  resolves: #996862
- add a patch to fix the name of the PID file in man page
  resolves: #1009882
- add a patch to remove references to Google ads from the html docs
  resolves: #1030040
- add missing image files referenced from the html docs
  resolves: #1031673
- add a patch to backport the mmcount module
  resolves: #1030206
- add a patch to support arbitrary number of listeners in imuxsock
  resolves: #1096732
- remove clean section
  resolves: #869600
- add a list of bugs fixed by rebasing to 7.4.10
  resolves: #996857, #1007409, #1029910, #1061614, #1070689

* Sat May 10 2014 Tomas Heinrich <theinric@redhat.com> 7.4.10-1
- initial import of rsyslog7
  changes since rsyslog-5.8.10-8:
  - rebase to 7.4.10
  - drop patches merged upstream
  - regenerate patches for rhbz820311, rhbz886117
  - add a patch to remove dependency on liblogging-stdlog
  - add a patch to fix compilation of omelasticsearch
    on platforms without atomic instructions
  - mark package as conlicting with rsyslog
  - update specification of dependencies
  - add the rsyslog-recover-qi.pl script
  - add new plugins
    imdiag, mmanon, mmjsonparse, mmsnmptrapd, omelasticsearch,
    pmaixforwardedfrom, pmcisconames, pmsnare
  - add new subpackage rsyslog-elasticsearch
  - make the build more verbose by adding 'V=1' to make
  - update conf file for new omusrmsg syntax
    for details, see http://www.rsyslog.com/doc/v6compatibility.html
  - drop default compatibility mode from SYSLOGD_OPTIONS
    for details, see http://www.rsyslog.com/doc/v6compatibility.html
  - fix typos in the spec file
  resolves: #869600
