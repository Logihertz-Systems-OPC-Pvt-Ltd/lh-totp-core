Name:           lh-totp-core
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-totp - RFC 6238 Time-Based One-Time Password Counter & Truncate
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-totp-core
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
Pure PHP 8.2+ RFC 6238 TOTP and RFC 4226 HOTP two-factor authentication engine with RFC 4648 Base32 encoding, SHA-1/SHA-256/SHA-512 support, replay-cache guard, PBKDF2 backup codes, and MFA posture auditor.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-totp ]; then
    install -m 0755 bin/lh-totp %{buildroot}%{_bindir}/lh-totp
elif [ -f lh-totp ]; then
    install -m 0755 lh-totp %{buildroot}%{_bindir}/lh-totp
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
