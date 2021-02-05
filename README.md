# ckau
Console KMS Activation Utility

![HveMuYMY68](https://user-images.githubusercontent.com/60903639/107022007-b452af00-6759-11eb-96d1-bf7ece664d1d.gif)

# What ckau is
ckau is essentially [QDPS](https://github.com/zzragnar0kzz/qdps) combined with an extremely rudimentary frontend for some functions of the SLMGR VB script. It can perform a network scan of specified IP address(es) and port(s), and by utilizing SLMGR, it can attempt to activate Windows against any host(s) found during such a scan, or against any host(s) identified in a previous scan. It can also be used to display the current and/or legacy set(s) of recognized public KMS client setup keys, or to get a quick count of the number of IP address(es) in a given range.

# What ckau ain't
ckau is not an "advance directly to Go" means of bypassing activation. Beyond network scanning and data output, any KMS-related abilities of ckau are basically useless without access to a KMS host. ckau is not a KMS host, and it does not and will not provide access to any KMS host services which the user does not already possess.

# What ckau will never be
See above. ckau relies on existing KMS infrastructure, which is up to the user to provide. This infrastructure is not provided by ckau, nor will it ever be. The setup of such infrastructure is beyond the scope of this project, and any inquiries regarding the same will be summarily ignored.

# Installation
The latest release, and previous releases, can be found [here](https://github.com/zzragnar0kzz/ckau/releases). Download the desired release package and extract it to a directory of your choice. ckau is fairly portable, so as long as all of its files are present, it can be moved to and launched from virtually anywhere.

# Usage
ckau can be launched from the terminal, or via a shortcut, with zero or more supported arguments. Syntax is as follows:

``ckau.exe [-e <edition>] [-f] [-l] [-L] [-n] [-p <ports>] [-q <mask>] [-s <servers>] [-S <tick>] [-t <timeout>] [-U] [-v]``

`ckau.exe -V [-L] [-U]`

`ckau.exe -? [all] [<argument>]`

Supported arguments and a brief description of each:

`-e (--edition)` The edition of Windows to activate against. Specify a non-null, non-whitespace string for `<edition>`. This must match a valid edition in the program's internal dictionary; if it does not, or if this argument is omitted, `<edition>` will default to the edition installed on localhost.

`-f (--force)` Automatically bypass any prompts for user input; disabled by default.

`-l (--local)` Add any IP address(es) assigned to localhost to the scan list; disabled by default.

`-L (--legacykeys)` Include KMS client setup keys for legacy and esoteric editions of Windows; disabled by default.

`-n (--noscan)` Disable network scan if the local scan results file exists and is not empty, and feed the contents of that file to SLMGR for activation, overriding any value(s) provided for `-p` and `-s`. If the file does not exist, or it is empty, ignore this argument and perform a network scan with the other supplied argument(s).

`-p (--ports)` A space-delineated list of the port(s) to scan on the supplied address(es). Specify one or more integer(s) X for `<ports>`; for each, 0 ≤ X ≤ 65535. Any  values supplied for `<ports>` which are outside of this range will be discarded; if there are no valid supplied values, or if this argument is omitted, `<ports>` will default to 1688.

`-q (--quick)` For each IPv4 address assigned to localhost, use `<mask>` to create a range of addresses, and add that range to the scan list. Specify an integer X for `<mask>`, where 0 ≤ X ≤ 32.

`-s (--servers)` A space-delineated list of server(s) to scan. Specify one or more of the following for `<servers>`:
1. a single DNS hostname or IP address;
2. a range of IPv4 addresses as `a.b.c.d/xx`, where 0 ≤ `xx` ≤ 32; or
3. a range of IPv4 addresses as `a.b.c.d-w.x.y.z`.

`-S (--sleep)` Time to wait (in milliseconds) before querying the status of an individual scan. Specify an integer X for `<tick>`, where 10 ≤ X ≤ 65535; if the value supplied is invalid, or if this argument is omitted, `<tick>` defaults to 10.

`-t (--timeout)` Time to wait (in milliseconds) before automatically cancelling an individual scan. Specify an integer X for `<timeout>`, where 10 ≤ X ≤ 65535; if the value supplied is invalid, or if this argument is omitted, `<timeout>` defaults to 100.

`-U (--updatekeys)` Update the local keys files from the Internet.

`-v (--verbose)` Display comprehensive program output.

`-V (--validkeys)` Display supported edition(s) and matching KMS client setup key(s).

`-? (-h, --help)` Display this help screen, or display detailed help for `all` arguments or for a specific `<argument>`.

Launching the program with zero arguments is equivalent to launching it with `-?` as the only argument.

After an initial run, program data and output files are located at `~/.ckau`:
- `ckau.log` is a text file containing a continuing record of program activity.
- `scan.results` is a CSV-formatted file containing the results of the most recent successful scan.
- `windows.gvlk` is a CSV-formatted file containing supported Windows edition/KMS key pairs.
- `windows-legacy.gvlk` is a CSV-formatted file containing supported legacy Windows edition/KMS key pairs.


# Compiling for Windows
ckau is developed with Visual Studio, and provided [releases](https://github.com/zzragnar0kzz/ckau/releases) are compiled with same. To compile ckau on Windows, it is recommended that you also do so with VS. Support capabilities are limited.
1. Clone the [repository](https://github.com/zzragnar0kzz/ckau.git) using your preferred tool, or download the [latest archive](https://github.com/zzragnar0kzz/ckau/archive/main.zip) and extract it to the desired location.
2. Open the solution file.
3. Add the following NuGet packages:
    - [Html Agility Pack (HAP)](https://html-agility-pack.net/)
    - [IPAddressRange](https://github.com/jsakamoto/ipaddressrange)
4. ?
5. Compile


# Credits
[Html Agility Pack (HAP)](https://html-agility-pack.net/) is the property of its owners. All rights reserved.

Icon for the executable sourced from [icon-icons.com](https://icon-icons.com/icon/cow-face/98730), and is the property of its owners. All rights reserved.

[IPAddressRange](https://github.com/jsakamoto/ipaddressrange) is the property of its owners. All rights reserved.

[Progress bar](https://gist.github.com/DanielSWolf/0ab6a96899cc5377bf54) original code is the property of its owners. All rights reserved.

Remaining code is licensed under the GPLv3, 2020-2021. All rights reserved.


# to-do

