@echo off

rem Set the DNS servers to be applied to each interface.
set IPv4PrimaryDNS=194.242.2.6
set IPv4SecondaryDNS=1.1.1.3
set IPv6PrimaryDNS=2a07:e340::6
set IPv6SecondaryDNS=2606:4700:4700::1113

rem Checks for administrative permissions.
net.exe session 1>NUL 2>NUL || (echo This script requires administrative permissions. Please run as administrator. & pause & exit /B 1)

echo Using the following DNS servers:
echo IPv4:
echo Primary - %IPv4PrimaryDNS%
echo Secondary - %IPv4SecondaryDNS%
echo/
echo IPv6:
echo Primary - %IPv6PrimaryDNS%
echo Secondary - %IPv6SecondaryDNS%
echo/

rem Clears existing DoH settings.
reg delete "HKLM\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters" /f 1>NUL
echo Cleared any existing DoH settings.
echo/

rem The following for loops get a given interface's InterfaceIndex and GUID. We use the InterfaceIndex to set DNS, and the GUID to set DoH in the registry.
rem We only care about network interfaces that have a GUID.
for /f %%X in ('wmic nic where "GUID!=NULL" Get InterfaceIndex /value') do (
    rem We have to use a second for loop to remove the extra carrige returns from wmic output.
    rem InterfaceIndex is stored at %%I.
    for /f "tokens=1* delims==" %%H in ("%%X") do (
        for /f %%X in ('wmic nic where "InterfaceIndex=%%I" Get GUID /value') do (
            rem GUID is stored at %%G.
            for /f "tokens=1* delims==" %%F in ("%%X") do (

                rem Prints the name of the interface being modified.
                for  /f "tokens=*" %%X in ('wmic nic where "InterfaceIndex=%%I" Get NetConnectionID /value') do (
                    for /f "tokens=1* delims==" %%B in ("%%X") do (
                        for  /f "tokens=*" %%X in ('wmic nic where "InterfaceIndex=%%I" Get Name /value') do (
                            for /f "tokens=1* delims==" %%M in ("%%X") do echo %%C ^(%%N^):
                        )
                    )
                )
                echo/

                rem Clears existing DNS servers.
                netsh interface ipv4 set dnsservers %%I dhcp 1>NUL
                echo Cleared any existing IPv4 DNS servers.
                netsh interface ipv6 set dnsservers %%I dhcp 1>NUL
                echo Cleared any existing IPv6 DNS servers.
                echo/

                netsh interface ipv4 set dnsservers %%I static %IPv4PrimaryDNS% primary no 1>NUL
                echo Set primary IPv4 DNS server to: %IPv4PrimaryDNS%
                netsh interface ipv4 add dnsservers %%I %IPv4SecondaryDNS% index=2 no 1>NUL
                echo Set secondary IPv4 DNS server to: %IPv4SecondaryDNS%
                echo/

                netsh interface ipv6 set dnsservers %%I static %IPv6PrimaryDNS% primary no 1>NUL
                echo Set primary IPv6 DNS server to: %IPv6PrimaryDNS%
                netsh interface ipv6 add dnsservers %%I %IPv6SecondaryDNS% index=2 no 1>NUL
                echo Set secondary IPv6 DNS server to: %IPv6SecondaryDNS%
                echo/

                reg add "HKLM\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\%%G\DohInterfaceSettings\Doh\%IPv4PrimaryDNS%" /v "DohFlags" /t REG_QWORD /d "1" /f 1>NUL
                reg add "HKLM\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\%%G\DohInterfaceSettings\Doh\%IPv4SecondaryDNS%" /v "DohFlags" /t REG_QWORD /d "1" /f 1>NUL
                echo Enabled DoH for IPv4.

                reg add "HKLM\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\%%G\DohInterfaceSettings\Doh6\%IPv6PrimaryDNS%" /v "DohFlags" /t REG_QWORD /d "1" /f 1>NUL
                reg add "HKLM\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\%%G\DohInterfaceSettings\Doh6\%IPv6SecondaryDNS%" /v "DohFlags" /t REG_QWORD /d "1" /f 1>NUL
                echo Enabled DoH for IPv6.
                echo/
            )
         
        )
    )
)

ipconfig /flushdns 1>NUL
echo Flushed DNS.
echo/

pause