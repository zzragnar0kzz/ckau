# ckau
Console KMS Activation Utility


![HveMuYMY68](https://user-images.githubusercontent.com/60903639/107022007-b452af00-6759-11eb-96d1-bf7ece664d1d.gif)


# What ckau is
ckau is essentially [QDPS](https://github.com/zzragnar0kzz/qdps) with extensions, combined with a HTML parser and an extremely rudimentary frontend for some functions of the [SLMGR](https://docs.microsoft.com/en-us/windows-server/get-started/activation-slmgr-vbs-options) VB script. It can perform a network scan of specified IP address(es) and port(s), and by utilizing SLMGR, it can attempt to activate Windows against any host(s) found during such a scan, or against any host(s) identified in a previous scan. It can also be used to display the current and/or legacy set(s) of recognized public KMS client setup keys, or to get a quick count of the number of IP address(es) in a given range.


# What ckau ain't
ckau is not an "advance directly to Go" means of bypassing activation. Beyond network scanning and data output, any KMS-related abilities of ckau are basically useless without access to a KMS host. ckau is not a KMS host, and it does not and will not provide access to any KMS host services which the user does not already possess.


# What ckau will never be
See above. ckau relies on existing KMS infrastructure, which is up to the user to provide. This infrastructure is not provided by ckau, nor will it ever be. The setup of such infrastructure is beyond the scope of this project, and any inquiries regarding the same will be summarily ignored.


# Installation
The latest release, and previous releases, can be found [here](https://github.com/zzragnar0kzz/ckau/releases). Download the desired release package and extract it to a directory of your choice. ckau is fairly portable, so as long as all of its files are present, it can be moved to and launched from virtually anywhere.


# Usage
ckau can be launched from the terminal, or via a shortcut, with zero or more supported arguments. Syntax is as follows:

`ckau.exe [-f] [-l] [-L] [-n] [-p <port_nums>] [-q <mask>] [-s <hosts>] [-S <interval>] [-t <interval>] [-U] [-v] [-w <edition>]`

- or

`ckau.exe -V [-L] [-U]`

- or

`ckau.exe -? [all] [<argument>]`

Supported arguments and a brief description of each:

`-f (--force)` Automatically bypass any prompts for user input; disabled by default.

`-l (--local)` Add any IP address(es) assigned to localhost to the scan list; disabled by default.

`-L (--legacykeys)` Include KMS client setup keys for legacy and esoteric editions of Windows; disabled by default.

`-n (--noscan)` Disable network scan if the local scan results file exists and is not empty, and feed the contents of that file to SLMGR for activation, overriding any value(s) provided for `-p` and `-s`. If the file does not exist, or it is empty, ignore this argument and perform a network scan with the other supplied argument(s).

`-p (--ports)` A space-delineated list of the port(s) to scan on the supplied address(es). Specify one or more integer(s) X for `<port_nums>`; for each, 0 ≤ X ≤ 65535. Any  values supplied for `<port_nums>` which are outside of this range will be discarded; if there are no valid supplied values, or if this argument is omitted, `<port_nums>` will default to 1688.

`-q (--quick)` For each IPv4 address assigned to localhost, use `<mask>` to create a range of addresses, and add that range to the scan list. Specify an integer X for `<mask>`, where 0 ≤ X ≤ 32.

`-s (--servers)` A space-delineated list of server(s) to scan. Specify one or more of the following for `<hosts>`:
1. a single DNS hostname or IP address;
2. a range of IPv4 addresses as `a.b.c.d/xx`, where 0 ≤ `xx` ≤ 32; or
3. a range of IPv4 addresses as `a.b.c.d-w.x.y.z`.

`-S (--sleep)` Time to wait (in milliseconds) before querying the status of an individual scan. Specify an integer X for `<interval>`, where 10 ≤ X ≤ 65535; if the value supplied is invalid, or if this argument is omitted, `<interval>` defaults to 10.

`-t (--timeout)` Time to wait (in milliseconds) before automatically cancelling an individual scan. Specify an integer X for `<interval>`, where 10 ≤ X ≤ 65535; if the value supplied is invalid, or if this argument is omitted, `<interval>` defaults to 100.

`-U (--updatekeys)` Update the local keys files from the Internet.

`-v (--verbose)` Display comprehensive program output.

`-V (--validkeys)` Display supported edition(s) and matching KMS client setup key(s).

`-w (--windows)` The edition of Windows to activate against. Specify a non-null, non-whitespace string for `<edition>`. This must match a valid edition in the program's internal dictionary; if it does not, or if this argument is omitted, `<edition>` will default to the edition installed on localhost.

`-? (-h, --help)` Display this help screen, or display detailed help for `all` arguments or for a specific `<argument>`.

Launching the program with zero arguments is equivalent to launching it with `-?` as the only argument.

After an initial run, program data and output files are located at `~/.ckau`:
- `ckau.log` is a text file containing a continuing record of program activity.
- `scan.results` is a CSV-formatted file containing the results of the most recent successful scan.
- `windows.gvlk` is a CSV-formatted file containing supported Windows edition/KMS key pairs.
- `windows-legacy.gvlk` is a CSV-formatted file containing supported legacy Windows edition/KMS key pairs.


# Compiling for Windows
ckau is developed using Visual Studio on a x64 Windows 10 platform, and all provided [releases](https://github.com/zzragnar0kzz/ckau/releases) are compiled using the same. Support capabilities are limited.
1. Clone the [repository](https://github.com/zzragnar0kzz/ckau.git) using your preferred tool, or download the [latest archive](https://github.com/zzragnar0kzz/ckau/archive/main.zip) and extract it to the desired location.
2. Open the project solution file.
3. Add the following NuGet packages:
    - [Html Agility Pack (HAP)](https://www.nuget.org/packages/HtmlAgilityPack/)
    - [IPAddressRange](https://www.nuget.org/packages/IPAddressRange/)
    - [System.Management](https://www.nuget.org/packages/System.Management/)
4. Select "Release" from the Solution Configurations dropdown
5. Compile


# License
ckau is made available under the terms of the GPLv3. ™ and © 2020-2021 Jeff Guziak. All rights reserved.


# Credits
[KMS client setup keys for current editions](https://docs.microsoft.com/en-us/windows-server/get-started/kmsclientkeys).

[KMS client setup keys for legacy editions](https://py-kms.readthedocs.io/en/latest/Keys.html).

[Html Agility Pack (HAP)](https://html-agility-pack.net/) is the property of its owners. All rights reserved.

Icon for the executable sourced from [icon-icons.com](https://icon-icons.com/icon/cow-face/98730), and is the property of its owners. All rights reserved.

[IPAddressRange](https://github.com/jsakamoto/ipaddressrange) is the property of its owners. All rights reserved.

[Progress bar](https://gist.github.com/DanielSWolf/0ab6a96899cc5377bf54) original code is the property of its owners. All rights reserved.


# Addendum

Certain arguments are rife with the potential for abuse:
- Most KMS-related functions require elevated privileges.
- Do not use `-e` with an `<edition>` value that differs from the installed edition unless you know what you are doing.
- Do not use `-q` with a `<mask>` value less than or equal to 8 unless you are prepared to wait. For a long time.
- The preceding also applies to CIDR IPv4 ranges supplied as any of `<hosts>` with `-s`.

