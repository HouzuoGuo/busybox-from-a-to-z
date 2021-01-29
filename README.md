### Foreword
Be aware that, busybox tries to imitate popular feature extensions from GNU's implementation of programs and utilities, though busybox often differs from GNU's implementation in subtle ways.

`> ` denotes command input, and a line without the prefix denotes the output from that command.

### Launch busybox
    > docker run -it --rm alpine:latest

### [
    # File tests
    > [ -e /etc/passwd ] && echo good
    > [ -e /etc/passwd -a -f /etc/passwd -a -r /etc/passwd ] && echo good

### [[
    # Similar file tests
    > [[ -e /etc/passwd -a -f /etc/passwd -a -r /etc/passwd ]] && echo good

    # More versatile syntax
    > [[ true && true ]] && echo good
    > [[ true || false ]] && echo good
    > [[ -e /etc/passwd && -f /etc/passwd && -r /etc/passwd ]] && echo good

### acpid
    # Try to launch acpid
    > mkdir -p /etc/acpi && acpid -d -f
    acpid: /dev/input/event0: No such file or directory

### adjtimex
    # Print out kernel clock tuning adjustments
    > adjtimex
    ...
    time.tv_sec:  1603782690
    time.tv_usec: 522862482
    ...

### arch
    # Print out system architecture
    > arch
    x86_64

### arp
    # Print out ARP table entries (GNU calls this "BSD style")
    > arp -a
    ? (10.0.78.1) at 02:98:0a:0c:68:4f [ether]  on eth0

### arping
    # Ask an IP address to respond with its MAC address
    > arping 10.0.78.1
    ARPING 10.0.78.1 from 10.0.78.238 eth0
    Unicast reply from 10.0.78.1 [02:98:0a:0c:68:4f] 0.060ms
    Unicast reply from 10.0.78.1 [02:98:0a:0c:68:4f] 0.082ms
    ...

### ash
    # Shell safety options similar to those used in bash, busybox ash does not support set -E.
    > set -euxo pipefail

    # Capture program output
    > echo $(cat /etc/os-release)
    NAME="Alpine Linux" ID=alpine VERSION_ID=3.12.1 PRETTY_NAME="Alpine Linux v3.12" HOME_URL="https://alpinelinux.org/" BUG_REPORT_URL="https://bugs.alpinelinux.org/"

    # Read lines of a file
    > while read -r line; do echo "$line"; done < /etc/os-release
    ...
    PRETTY_NAME="Alpine Linux v3.12"
    HOME_URL="https://alpinelinux.org/"
    ...

    # Command group and subshell
    > { echo a; echo b; } > out.txt && cat out.txt
    a
    b
    > { a=1; ( a=2; echo "$a" ); echo "$a"; }
    2
    1

    # Integer arithmetic
    > echo $((123+345)) $((123<456)) $((123>456))
    468 1 0

    # For loop, busybox ash does not support bash shortcut "for i in {0..2}"
    > for i in 1 2 3; do echo $i; done
    1
    2
    3
    > for i in $(seq 0 2); do echo $i; done
    0
    1
    2

    # Function
    > myfun() { local p1="$1"; local p2="$2"; echo $(($p1+$p2)); }
    > myfun 1 2
    3

    # Join lines, busybox ash does not support "printf -v myvar"
    > printf "%s\n" line1 line2 line3
    line1
    line2
    line3

    # String substitution
    > str='### good 123 stuff ###'
    > echo "${str#####}" # Remove the longest ### from prefix
     good 123 stuff ###
    > echo "${str%%###}" # Remove the longest ### from suffix
    ### good 123 stuff
    > echo "${str//good/ok}" # Replace all occurrences of "good" by "ok"
    ### ok 123 stuff ###

    # Parameter substitution
    > echo "${non_existing_var:-default123}"
    default123
    > echo "${PWD:+gotpwd}"
    gotpwd

    # Use IFS for the field separator used by "read"
    > echo 'field 1, field 2, field 3' | while IFS=', ' read -r a b c; do echo "<$a> <$b> <$c>"; done
    <field> <1> <field 2, field 3>

    # Use IFS for trimming spaces and expanding parameters
    > str='field 1 + field 2 + field 3'
    > IFS=' +'
    > printf "<%s>\n" $str
    <field>
    <1>
    <field>
    <2>
    <field>
    <3>

### awk
    # Customise field separator and feed awk script as a program argument
    > awk -F ':' -e '{print $1}' /etc/passwd
    ...
    ftp
    sshd
    ...

    # Slightly more advanced scripting
    > awk -v OFS=' --- ' -F ':' -e '{ sh_cnt[$7]++ } END { for (sh in sh_cnt) { print sh, sh_cnt[sh] } }' /etc/passwd
    ...
    /sbin/halt --- 1
    /sbin/nologin --- 23
    ...

### basename
    # Determine the name excluding extension name of a file identified by its path
    > basename /etc/a/b/myfile.txt .txt
    myfile

### bc
    # Floating point math
    > echo '1.1 + 2.2 * 3.3 / 4.4' | bc
    2.1

    # The classic puzzle in C
    > echo 'i = 1; i++ + ++i; i' | bc
    4
    3

### blkid
    # Print the attributes of all block devices
    > blkid
    /dev/root: LABEL="cloudimg-rootfs" UUID="f387d281-b162-4d60-84b5-e7e94687e6b8" TYPE="ext4"
    /dev/nvme0n1p1: LABEL="cloudimg-rootfs" UUID="f387d281-b162-4d60-84b5-e7e94687e6b8" TYPE="ext4"
    ...

    # Print the attributes of a specified block device
    > blkid /dev/loop7
    /dev/loop7: TYPE="squashfs"

### blkdiscard
    # Discard (trim) all blocks on an SSD
    > blkdiscard /dev/root # will not run in that docker container

### blockdev
    # Flush block device buffers
    > blockdev --flushbufs /dev/root # will not run in that docker container

### brctl
    # The much newer busybox (version >1.13) can list network bridges in addition to creating/deleting them
    > brctl show
    ...

### bunzip2
    # Decompress data
    > echo 'abcdefghijklmnopqrstuvwxyz' | bzip2 -9 | bunzip2
    abcdefghijklmnopqrstuvwxyz

### bzcat
    # Print decompressed data
    > echo 'abcdefghijklmnopqrstuvwxyz' | bzip2 -9 | bzcat
    abcdefghijklmnopqrstuvwxyz

### bzip2
    # Compress data and inspect the compressed data using hexdump
    > echo 'abcdefghijklmnopqrstuvwxyz' | bzip2 -9 | hexdump -C
    00000000  42 5a 68 39 31 41 59 26  53 59 df 1d 4d 7f 00 00  |BZh91AY&SY..M...|
    ....

### cal
    # Print the entire year's calendar
    > cal -y
    2020
    January               February               March
    ...

### cat
    # Print input data, including non-printable characters (dispalyed as ^x or M-x), and number the lines in the output
    > echo 'abcdefghijklmnopqrstuvwxyz' | bzip2 -9 | cat -v -n
    # 1  BZh91AY&SYM-_^]M^?^@^@^@M-AM-^@^@^P?M-^?M-^?M-p ^@1M^Z^@M-P^@^D ^@^@^FM-^

### chgrp
    # Recursively change group to "nobody" for everything underneath /var
    > chgrp -R nobody /var && ls -lR /var
    drwxr-xr-x    1 root     nobody        4096 Oct 21 09:23 cache
    dr-xr-xr-x    1 root     nobody        4096 Oct 21 09:23 empty
    ...

### chmod
    # Recursively change mode to 0700 for everything underneath /var, print out entries that are changed.
    > chmod -c -R 0700 /var
    mode of '/var' changed to 0700 (rwx------)
    mode of '/var/empty' changed to 0700 (rwx------)
    ...

### chpasswd
    # Use plain text to change the password of nobody
    > echo 'nobody:passwordofnobody' | chpasswd
    chpasswd: password for 'nobody' changed
    > grep nobody /etc/shadow
    nobody:$6$RS84MTWHARoSMBQZ$9tpbATw.pa6Bk476ysBewpgNhyPaX7LiK.jpQP4z6XpAGWu3mJMyvNY51zOozIm6YQMJ9onifFt2tjbbpu6MT/:18564:0:::::

    # Use an already hashed password to change the password of nobody
    > echo 'nobody:$6$RS84MTWHARoSMBQZ$9tpbATw.pa6Bk476ysBewpgNhyPaX7LiK.jpQP4z6XpAGWu3mJMyvNY51zOozIm6YQMJ9onifFt2tjbbpu6MT/' | chpasswd -e
    chpasswd: password for 'nobody' changed
    > grep nobody /etc/shadow
    nobody:$6$RS84MTWHARoSMBQZ$9tpbATw.pa6Bk476ysBewpgNhyPaX7LiK.jpQP4z6XpAGWu3mJMyvNY51zOozIm6YQMJ9onifFt2tjbbpu6MT/:18564:0:::::
    # Be aware that busybox's getent does not support "shadow" database

### chroot
    # The alpine linux container must have sys_chroot capability, which docker already grants to it by default.
    > chroot / /bin/sh
    / #

### chvt
    # Try to switch to /dev/tty1 (does not exist)
    > chvt 1
    chvt: can't open console

### clear
    # Clear screen
    > clear

### cmp
    # Print the first occurrence of content difference between two files
    > cmp /etc/passwd /etc/shadow
    /etc/passwd /etc/shadow differ: char 6, line 1

    # Print byte number and byte value of all differing bytes in a table output format
    > cmp -l /etc/passwd /etc/shadow
    6 170  41
    ...
    422 151  12
    cmp: EOF on /etc/shadow

### cp
    # Make a backup of /etc while trying to preserve file modes, ownerships, and timestamps.
    > cp -p -R /etc /etc-bakup

### cpio
    # Create an archive for all files underneath /etc
    > find /etc -print | cpio -H newc -o -v > archive.cpio

    # List archive content
    > cat ./archive.cpio | cpio -t
    etc
    etc/apk
    ...
    etc/resolv.conf
    573 blocks

    # Extract the archive
    > mkdir /restoring-etc
    > mv archive.cpio /restoring-etc
    > cat ./archive.cpio | cpio -i -v -d
    etc
    etc/apk
    ...
    etc/resolv.conf
    573 blocks

### cttyhack
    # This exercise is carried out on the container host, instead of the alpine linux in docker container.
    # Without cttyhack...
    > busybox sh
    > stty
    speed 38400 baud; line = 0;
    eol = M-^?; eol2 = M-^?;
    -brkint -imaxbel
    > tty
    /dev/pts/2

    # With cttyhack
    > busybox cttyhack sh
    # This hack does not provide all of TTY's capabilities, evident from malfunctioning tab completion, malfunctioning arrow keys, etc.
    > stty
    speed 38400 baud; line = 0;
    eol = M-^?; eol2 = M-^?;
    -brkint -imaxbel
    > tty
    /dev/tty

### cut
    # Print the first column of /etc/passwd
    > cut -d ':' -d 1 /etc/passwd
    root
    bin
    ...
    nobody


    # Print the first 5 characters of each line of /etc/passwd
    > cut -c 1-5 /etc/passwd
    root:
    bin:x
    ...
    nobod

### date
    # Print UTC date
    > date -u '+%Y%m%d %H%M%S'
    20201029 152416

### dc
    # Use reverse polish notation to calculate 1.1 + 2.2
    > echo '1.1 2.2 + p' | dc
    3.3

### dd
    # Create an empty file 100MB in size
    > dd if=/dev/zero of=./empty bs=1M count=100

### deallocvt
    # Not quite sure what this is for
    > deallocvt
    deallocvt: can't open console

### depmod
    # "Generate modules.dep, alias, and symbol files"
    > depmod
    depmod: can't change directory to 'lib/modules/5.4.0-1028-aws': No such file or directory

### devmem
    # Read 8 bytes (32 bits) from memory location 0, this has to run on container host.
    > sudo busybox devmem 0 32
    0xF000FF53

### df
    # Print file system type and file system usage in a friendly readable format
    > df -T -h
    Filesystem           Type            Size      Used Available Use% Mounted on
    overlay              overlay        77.5G     24.3G     53.1G  31% /
    tmpfs                tmpfs          64.0M         0     64.0M   0% /dev
    ...

### diff
    # Print the differences (- belongs to the first file, + belongs to the second file)
    > diff -w /etc/passwd /etc/shadow
    --- /etc/passwd
    +++ /etc/shadow
    @@ -1,27 +1,27 @@
    -root:x:0:0:root:/root:/bin/ash
    -bin:x:1:1:bin:/bin:/sbin/nologin
    ...

### dirname
    # Get the directory name of a path
    > dirname /etc/config.txt
    /etc

### dmesg
    # Read kernel messages
    > dmesg
    ...
    ...
    [1219562.256341] docker0: port 2(veth3b1b773) entered forwarding state

### dnsdomainname
    # Print system's NIS/YP domain name
    > dnsdomainname
    (empty)

### dos2unix
    # Convert lines from stadard input to UNIX line ending
    > echo abc | dos2unix | hexdump -C
    00000000  61 62 63 0a                                       |abc.|
    00000004

### du
    # Calculate the grand total of storage capacity consumed by /etc and /var
    > du -hcs /etc /var # h - readable size output; c - print grand total; s - sum each FILE/DIR
    536.0K  /etc/
    72.0K   /var
    608.0K  total

### dumpkmap
    # "Print a binary keyboard translation table to stdout" not quite sure how to use the output
    > dumpkmap
    (bunch of binary stuff)

### dumpleases
    # It probably works best with busybox's own udhcpc client
    > dumpleases
    dumpleases: can't open '': No such file or directory
    # Be aware that systemd stores DHCP leases in /run/systemd/netif/leases/NUMBER
    # Systemd's DHCP lease report is not supposed to be stable for machine-parsing

### echo
    # Print a line, interpret backslash escaped characters.
    > echo -e 'a\tb\nc'
    a       b
    c

### egrep
    # Use grep -E instead, grep -E is more universally available.

### env
    # Start shell with an empty environment and couple of custom assignments
    > env -i VarA=123 VarB=haha sh
    > printenv VarA VarB
    123
    haha

### expand
    # Expand every tab to 5 spaces
    > echo -e 'a\tb' | expand -t 5
    a    b

### expr
    # Basic integer path
    > expr 1 + 2 - 3 + 4
    4

    # Integer comparison
    > expr '1' '<' '3' && echo good
    1
    good

    # Test regular expression match. Note that expr only understands the regular regex in contrast to extended regex.
    > str='### good 123 stuff ###'
    > expr match "$str" '.*good.*$' && echo good
    22
    good
    > expr match "$str" '.*doesnotexist.*$' && echo good
    0

    # Extract regex match from string The regex processing behaviour is also highly unusual with expr, nobody wouldn't wirte regex this way with bash match or grep -E.
    > expr "$str" : '.*\([0-9a-z][0-9a-z\ ]\+\)\+'
    good 123 stuff # there is a trailing space

### factor
    # Print prime factors of an integer
    > factor 12
    12: 2 2 3

### fallocate
    # Preallocate space for a file
    > fallocate -l 123 my.txt
    > stat my.txt
    ...
    Size: 123             Blocks: 8          IO Block: 4096   regular file
    ...

### false
    # Get a process exit code of 1
    > false
    > echo $?
    1

### fatattr
    # Change file attributes on a FAT system... I don't have one

### fgrep
    # fgrep is equivalent to grep -F, which interprets input pattern as regular string instead of regular expression.

### find
    # Find all files executable by everyone, throw in a -print0 for some additional complication.
    > find / -type f -perm -a=x -print0 | tr '\0' '\n'
    /lib/libcrypto.so.1.1
    /lib/ld-musl-x86_64.so.1
    ...

### findfs
    # Look for the /dev/xxx device node that belongs to a block device identified by LABEL
    > findfs LABEL="cloudimg-rootfs"
    /dev/root

### flock
    # Hold onto an advisory exclusive lock on a file while spawning a shell
    > flock -x /etc/passwd -c sh
    # Be aware that the locks are strictly advisory, a process with suitable permissions may ignore the lock's presence entirely.

### fold
    # Print file content, wrap lines at maximum length of 20.
    > fold -w 20 /etc/passwd
    root:x:0:0:root:/roo
    t:/bin/ash
    ...

### free
    # Print memory and swap usage information, round numbers to the nearest megabytes.
    > free -m
                  total        used        free      shared  buff/cache   available
    Mem:           7882        1345        3254           0        3281        6229
    Swap:          2047           0        2047

### fstrim
    # Discard (trim) unused blocks in the file system identified by mount point, print discard stats. Useful for SSDs.
    > fstrim -v /
    fstrim: ioctl 0xc0185879 failed: Not a tty # hehe wtf

### fsync
    # Write all buffered blocks of a file to disk
    > fsync /etc/os-release

### fuser
    # Find the processes currently using file /etc/os-release
    > flock -x /etc/os-release -c sh
    > fuser /etc/os-release
    6 7
    # flock itself, and sh spawned from it.

### getopt
    # TODO: ...come back to this one later

### getty
    # Spawn a TTY number 1 operating at 38400 bauds/sec
    > getty 38400 tty1
    getty: setsid: Operation not permitted

### grep
                # Use extended regex to look for lines of X="Y" which has an upper case letter in the value part. Display line number.
    > grep -n -E '".*[A-Z]+' /etc/os-release
    1:NAME="Alpine Linux"
    4:PRETTY_NAME="Alpine Linux v3.12"

### groups
    # Print the primary group and secondary groups a user belongs to
    > groups nobody
    nobody
    > groups root
    root bin daemon sys adm disk wheel floppy dialout tape video

### gunzip
    # Decompress data
    > echo 'abcdefghijklmnopqrstuvwxyz' | gzip -9 | gunzip
    abcdefghijklmnopqrstuvwxyz

### gzip
    # Compress data and inspect the compressed data using hexdump
    > echo 'abcdefghijklmnopqrstuvwxyz' | gzip -9 | hexdump -C
    00000000  1f 8b 08 00 00 00 00 00  02 03 4b 4c 4a 4e 49 4d  |..........KLJNIM|
    ....

### halt
    # Halt the system doesn't really work from a container
    > halt -d 3 -f # delay 3 seconds and then force halt without going through initi
    halt: Operation not permitted

### hd
    # hd is an alias of hexdump -C, print the content of input in both hex and ASCII.
    > echo 'abcdefghijklmnopqrstuvwxyz' | gzip -9 | hd
    00000000  1f 8b 08 00 00 00 00 00  02 03 4b 4c 4a 4e 49 4d  |..........KLJNIM|
    ...

### hdparm
    # Check the number of readahead sectors of a hard drive
    > hdparm -a /dev/root
    /dev/root:
     readahead      = 256 (on)

### head
    # Print the first 3 lines
    > head -n 3 /etc/passwd
    root:x:0:0:root:/root:/bin/ash
    bin:x:1:1:bin:/bin:/sbin/nologin
    daemon:x:2:2:daemon:/sbin:/sbin/nologin

    # Print all lines except the last 20
    > head -n -20 /etc/passwd
    root:x:0:0:root:/root:/bin/ash
    bin:x:1:1:bin:/bin:/sbin/nologin
    daemon:x:2:2:daemon:/sbin:/sbin/nologin
    ...
    shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown

### hexdump
    # Print the hex and ASCII representation of the first 20 bytes of /etc/passwd
    > hexdump -n 20 -C /etc/passwd
    00000000  72 6f 6f 74 3a 78 3a 30  3a 30 3a 72 6f 6f 74 3a  |root:x:0:0:root:|
    00000010  2f 72 6f 6f                                       |/roo|
    00000014

### hostid
    # Print the hex representation of the 32-bit UNIX machine ID
    > hostid
    00000000

### hostname
    # Print the host FQDN
    > hostname -f
    f2abc39a5794

    # Print the IP address of the host name
    > hostname -i
    172.17.0.2

    # Print the static host name - what kernel believes to be the host name in the UTS namespace.
    > hostname
    f2abc39a5794

    # Related to this, host names managed by systemd are:
    # - Pretty host name - more like a computer description, this has little to do with UTS host name.
    # - Static host name - what kernel believes to be the host name in that UTS namespace, this is "kernel.hostname", gethostname(2), as well as /etc/hostname.
    # - Transient host name - what network configuration beleives to be the host name.

### hwclock
    # Display the hardware clock time
    > hwclock -r
    Sat Oct 31 16:00:17 2020  0.000000 seconds

### id
    # Get the effective user ID
    > id -u
    0

    # Get the real user ID
    > id -r -u
    0

    # Tip: real UID is the owner of the process, the owner of /proc/PROC_ID.
    # Effective UID is used for OS to decide what the process can do.
    # Saved UID is used by kernel to restore effective UID after it has executed a setuid program.

### ifconfig
    # Print information of all configured network interface
    > ifconfig
    eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02
              inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0
    ...

### ifdown
    # Do a dry-run (print what would be done but otherwise noop) to bring offline ("deconfigure") all network interfaces
    > ifdown -n -r
    ifdown: can't open '/etc/network/interfaces': No such file or directory # hehehehe

### ifenslave
    # "Configure network interfaces for parallel routing" not quite sure how to use this

### ifup
    # Do a dry-run (print what would be done but otherwise noop) to bring online ("configure") all network interfaces
    > ifup -n -a
    ifup: can't open '/etc/network/interfaces': No such file or directory # hehehehe

### init
    # Spawn the init (the-first-process) that never exits, the init process spawns initial set of processes specified in /etc/inittab.
    > init
    init: must be run as PID 1 # hehehe

### inotifyd
    # Monitor file system changes for a file, print the changes (read/access/open/delete/move/etc) to stdout.
    > inotifyd - /etc/passwd &
    > # press enter
    r       /etc/passwd # r means file is opened
    a       /etc/passwd # a means file is "accessed"
    0       /etc/passwd # 0 means file was not written into, and it is closed.

### insmod
    # insmod - load a kernel module file
    > insmod /etc/os-release
    insmod: can't insert '/etc/os-release': Operation not permitted # hehe

### install
    # Create directory /a/b/c, set owner, group, and mode.
    > install -d -o nobody -g nogroup -m 0700 /a/b
    > stat /a
    ...
    Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)
    ...
    > ls -lR /a
    ...
    drwx------    2 nobody   nogroup       4096 Oct 31 16:33 b
    ...

    # Copy file /etc/os-release to /bak/haha/os.txt, set owner, group, and mode.
    > install -D -o nobody -g nogroup -m 0700 /etc/os-release /bak/haha/os.txt
    > ls -lR /bak
    /bak:
    total 4
    drwxr-xr-x    2 root     root          4096 Oct 31 16:35 haha
    /bak/haha:
    total 4
    -rwx------    1 nobody   nogroup        164 Oct 31 16:35 os.txt

### ionice
    # Start a shell using IO priority class idle (3), a regular user may also use IO class best-effort (2).
    > ionice -c 3 sh

    # Set IO priority class of a running process (PID 1)
    > ionice -c 3 -p 1

### iostat
    # Print the system time, CPU usage, and IO activity stats (prefer MB/s) from all block devices.
    > iostat -t -c -d -m
    Linux 5.4.0-1029-aws (496a1090587a)     11/02/20        _x86_64_        (2 CPU)
    11/02/20 17:46:00
    avg-cpu:  %user   %nice %system %iowait  %steal   %idle
               0.95    0.00    0.42    0.06    0.08   98.49
    Device:            tps    MB_read/s    MB_wrtn/s    MB_read    MB_wrtn
    ...
    nvme0n1p1         7.15         0.03         0.09       4815      15721
    ...

    # Note that busybox iostat does not support "-x" flag for displaying extended stats such as queue size.

### ip
    # Create a pair of interconnected veth interfaces
    > ip link add myeth type veth peer name veth1
    > ip addr add 10.1.0.0/16 dev myeth
    > ip link set myeth up
    > ip addr add 10.2.0.0/16 dev veth1
    > ip link set veth1 up
    > ping -c 1 10.1.0.0
    ... 1 packets transmitted, 1 packets received, 0% packet loss
    > ping -c 2 10.1.0.0
    ... 1 packets transmitted, 1 packets received, 0% packet loss

### ipaddr
    # ipaddr is "ip addr"

### ipcalc
    # Calculate the net mask, braodcast address, and network address of 192.168.1.0/24
    > ipcalc -n -b -m 192.168.1.0/24
    NETMASK=255.255.255.0
    BROADCAST=192.168.1.255
    NETWORK=192.168.1.0

### ipcrm
    # busybox is missing "ipcmk", do this exercise using the fully featured container host OS.
    > ipcmk -M 123
    Shared memory id: 2
    > ipcmk -S 3
    Semaphore id: 0
    > ipcmk -Q
    Message queue id: 2

    > ipcs
    ------ Message Queues --------
    key        msqid      owner      perms      used-bytes   messages
    0x95de7a0f 2          howard     644        0            0

    ------ Shared Memory Segments --------
    key        shmid      owner      perms      bytes      nattch     status
    0x199f0173 2          howard     644        123        0

    ------ Semaphore Arrays --------
    key        semid      owner      perms      nsems
    0x4d05ffec 0          howard     644        3

    > ipcrm -Q 0x95de7a0f
    > ipcrm -M 0x199f0173
    > ipcrm -S 0x4d05ffec
    > ipcs
    (empty in each category)

### ipcs
    # See above

### iplink
    # iplink is "ip link"

### ipneigh
    # ipneigh is "ip neighbour". Display the entries from ARP table
    > ipneigh
    172.17.0.1 dev eth0 lladdr 02:42:e5:bb:4e:7c used 0/0/0 probes 4 STALE

### iproute
    # iproute is "ip route". Display the entries from IP routing table.
    > iproute
    default via 172.17.0.1 dev eth0
    172.17.0.0/16 dev eth0 scope link  src 172.17.0.2

### iprule
    # iprule is "ip rule"

### iptunnel
    # iptunnel is "ip tunnel"

### kbd_mode
    # Set VT console keyoard mode to UTF-8
    > kbd_mode -u
    > kbd_mode
    The keyboard is in Unicode (UTF-8) mode

### kill
    # Start a background job and force-killing it
    > sleep 100 &
    > jobs -l
    [1]+  34 Running                 sleep 100
    > /bin/kill -s 9 -34 # negative PID finds the process group
    [1]+  Killed                     sleep 100

### killall
    # Kill all "sleep" processes with signal KILL (9)
    > for i in $(seq 0 10); do sleep 100 & done
    > killall -s KILL sleep

### killall5
    # Kill all proceses except the ones in caller's own session
    > for i in $(seq 0 10); do sleep 100 & done
    > killall5 -9
    [8]+  Stopped (signal)           sleep 100
    [10]-  Stopped (signal)          sleep 100
    [11]   Stopped (signal)          sleep 100
    ...
    # killall5 doesn't quite work

### klogd
    # Run a foreground program that logs kernel messages to syslog
    > klogd -n

### less
    # Use a pager to view /etc/os-release
    > less -I -F -R -S /etc/os-release # I - ignore case in search, F - quit if file already fits in a single screen, R - remove colour escape codes, S - truncate long lines.

### link
    # Create a hard link for /etc/passwd (the original) at path /etc/passwd2 (the link)
    > link /etc/passwd /etc/passwd2

### linux32
    # No help available

### linux64
    # No help available

### ln
    # Create a symbol link for /etc/passwd (the original) at path /etc/passwd2 (the link), override existing link/file at the path.
    > ln -sf /etc/passwd /etc/passwd2
    > stat /etc/passwd2
      File: '/etc/passwd2' -> '/etc/passwd'
      Size: 11              Blocks: 0          IO Block: 4096   symbolic link
      ...
      Access: (0777/lrwxrwxrwx)  Uid: (    0/    root)   Gid: (    0/    root)
      ...

### loadfont
    # Load a VT console font from stdin
    > echo whatever | loadfont
    loadfont: input file: bad length or unsupported font type

### loadkmap
    # Load a VT keyboard binary translation table from stdin
    > echo whatever | loadkmap
    loadkmap: not a valid binary keymap

### logger
    # Send a message to syslog and print it out to stderr too
    > logger -s this is a message
    root: this is a message

### login
    # Login as root in the current console
    > login -f root
    Welcome to Alpine!
    ...
    login[28]: root login on 'pts/0'
    cbeef31aa40f:~#

### logread
    # Follow the latest messages in syslog circular buffer
    > logread -f
    logread: can't find syslogd buffer: No such file or directory

### losetup
    # Do this exercise on container host
    > dd if=/dev/zero of=/diskimg bs=1M count=10
    > losetup -P /dev/loop9 /diskimg # -P tells losetup to probe for partitions
    > losetup -a
    ...
    /dev/loop9: [66305]:28541 (/file)
    ...
    > losetup -D /dev/loop9

### ls
    # List files by last modified - latest first
    > ls -lt /etc
    lrwxrwxrwx    1 root     root            11 Nov  3 16:31 passwd2 -> /etc/passwd
    ...
    -rw-r--r--    1 root     root            53 May 30 17:17 sysctl.conf

    # List files by size - largest first
    > ls -lS /etc
    -rw-r--r--    1 root     root         14464 May 30 17:17 services
    ...
    -rw-r--r--    1 root     root             7 Oct 21 09:22 alpine-release

### lsmod
    # List loaded kernel modules and their dependencies

### lsof
    # Show all open files
    > lsof
    1       /bin/busybox    /dev/pts/0
    ...
    28      /bin/busybox    /dev/tty

    # The regular lsof is far more powerful, but the features are not present in busybox lsof.
    > lsof -n -i tcp:80 # Look for all TCP sockets whose peer is port 80
    laitos.li 933 root    8u  IPv4 4944780      0t0  TCP 10.0.78.238:46930->35.207.39.2:http (ESTABLISHED)
    laitos.li 933 root   16u  IPv6   24602      0t0  TCP *:http (LISTEN)
    ...
    > lsof -n -p 933 # Look for all sockets, pipes, and open files made by PID 933
    laitos.li 933 root  txt       REG   259,1 22324228 6912049 /hg/bin/laitos.linux
    ...
    laitos.li 933 root    6u     IPv4 4946704      0t0     TCP 10.0.78.238:32106->149.154.167.220:https (ESTABLISHED)
    laitos.li 933 root   16u     IPv6   24602      0t0     TCP *:http (LISTEN)

### lspci
    # Print information about devices on PCI buses in a parsable format, along with the driver name.
    > lspci -m -k
    00:00.0 "Host bridge" "Intel Corporation" "440FX - 82441FX PMC [Natoma]" "Amazon.com, Inc." "440FX - 82441FX PMC [Natoma]"
    ...

### lsusb
    # Print information about devices on USB buses
    > lsusb
    # Looks a bit empty

### lzcat
    # Don't know how to make it work
    > echo 'abc' | lzop -5 - | lzcat
    lzcat: corrupted data

### lzma
    # Don't know how to make it work
    > echo 'abc' | lzop -5 - | lzma -d -c
    lzma: corrupted data

### lzop
    # Compress and decompress from pipe
    > echo 'abcdefghijklmnopqrstuvwxyz' | lzop -5 - | lzopcat
    abcdefghijklmnopqrstuvwxyz

### lzopcat
    # Compress and decompress from pipe
    > echo 'abcdefghijklmnopqrstuvwxyz' | lzop -5 - | lzopcat
    abcdefghijklmnopqrstuvwxyz

### makemime
    # Create multipart MIME-encoded message from input file list
    > makemime /etc/os-release /etc/alpine-release
    Mime-Version: 1.0
    Content-Type: multipart/mixed; boundary="1858163020-1256360926-1801041304"

    --1858163020-1256360926-1801041304
    Content-Type: application/octet-stream; charset=us-ascii
    Content-Disposition: inline; filename="os-release"
    Content-Transfer-Encoding: base64
    ...
    Content-Disposition: inline; filename="alpine-release"
    ...

### md5sum
    # Calculate the MD5 checksum of input from pipe
    > echo -n | md5sum
    d41d8cd98f00b204e9800998ecf8427e  -

### mdev
    # Create a log file for mdev
    > > /dev/mdev.log

    # Ask mdev to auto-populate /dev when peripherals are hot-plugged/unplugged
    > echo /sbin/mdev >/proc/sys/kernel/hotplug

    # Manually execute mdev at time of boot to populate /dev
    > mdev -s

### mesg
    # When other users send me a talk/wall message, allow that message to be displayed in my terminal.
    > mesg y

### microcom
    # Interactively chat with a serial TTY-capable device
    > microcom -s 38400 $(tty)
    # Hehe - doesn't really work..

### mkdir
    # Make a new directory including any new intermediate parent directories in between.
    > mkdir -m 0700 -p /a/b/c
    > stat /a/b/c
    ...
    Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)
    ...

### mkdosfs
    # Make a fat32 file system, same as mkfs.vfat.
    # TODO

### mkfifo
    # Create a named pipe and read from it
    > mkfifo /myfifo
    > cat /myfifo &

    # Write to it
    > echo 'aa' >> /myfifo
    aa
    [1]+  Done                       cat /myfifo

    # Writing to the file blocks when there is no reader
    > echo 'aa' >> /myfifo
    (Ctrl+C)
    /bin/sh: can't create /myfifo: Interrupted system call

### mkfs.vfat
    # See above mkdosfs

### mknod
    # Create my own "zero" character device
    > mknod -m 0400 /myzero c 1 5

### mkpasswd
    # Calculate hashed password conforming to crypt(3)
    > echo 'pass' | mkpasswd -m sha512 -S grainofsalt -P 0
    $6$grainofsalt$NADWtRPlvlRArLOHrhjpwx0TZ3xkgJGzmF7suF/x7DbEyEA9Yv78POjRHfeA9a/mN3zcLhJKjGFuMFQ18gc8Q.

### mkswap
    # Prepare (format) a block device to be used as swap partition
    > dd if=/dev/zero of=/myswap bs=1M count=10
    10+0 records in
    10+0 records out
    > mkswap /myswap
    Setting up swapspace version 1, size = 10481664 bytes
    UUID=4ce4a68b-cd1a-43f6-9f7b-7cd202ed6c52

### mktemp
    # Create a temporary file and print out the temporary file path
    > mktemp /tmp/helloworld-XXXXXX
    > /tmp/helloworld-dpkgbI

### modinfo
    # Print kernel module information (do this exercise on container host)
    > modinfo drm
    filename:       /lib/modules/5.8.0-1010-aws/kernel/drivers/gpu/drm/drm.ko
    license:        GPL and additional rights
    description:    DRM shared core routines
    ...

### modprobe
    # Add or remove modules from the running kernel
    # TODO

### more
    # more is a rudimentary pager program
    > more /etc/os-release
    NAME="Alpine Linux"
    ...

### mount
    # mount is able to auto-detect file system present on the device, given that /proc is available.
    # Mount all file systems according to /etc/fstab
    > mount -a

### mountpoint
    # Check whether a directory is a mount point
    > mountpoint /
    / is a mountpoint
    > mountpoint -q /etc/os-release || echo not-mount-point
    not-mount-point

### mpstat
    # Report interrupt stats, processor stats, and utilisation fromall processors.
    > mpstat -I ALL -p ALL -u
    Linux 5.8.0-1010-aws (cfdfa48aa979)     11/06/20        _x86_64_        (2 CPU)
    ...
    07:25:22     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest   %idle
    ...
    07:25:22       0    0.95    0.04    0.44    0.10    0.00    0.02    0.05    0.00   98.40
    ...
    07:25:22     CPU    intr/s
    ...
    07:25:22       1     13.53
    ...

### mv
    # Rename/move a file
    > mv /etc/os-release /haha

### nameif
    # Create an ethernet peer
    > ip link add myeth type veth peer name veth1
    > ip link
    3: myeth@veth0: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN qlen 1000
        link/ether 0a:60:da:56:ee:9f brd ff:ff:ff:ff:ff:ff
    > nameif neweth mac=0a:60:da:56:ee:9f brd ff:ff:ff:ff:ff:ff
    > ip link
    3: neweth@veth0: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN qlen 1000
        link/ether 0a:60:da:56:ee:9f brd ff:ff:ff:ff:ff:ff

### nanddump
    # Dump an "MTD" device, not sure how to use it.

### nandwrite
    # Write to an "MTD" device, not sure how to use it.

### nbd-client
    # nbd-client connects to an nbd-server (not available on busybox) using raw diskspace of the server as a block device on the client.

### nc
    # Start a disposable single-use TCP server to copy the content of /etc/os-release to TCP client
    > nc -l -p 1234 -e cat /etc/os-release &
    > nc localhost 1234
    NAME="Alpine Linux"
    ...
    BUG_REPORT_URL="https://bugs.alpinelinux.org/"
    [1]+  Done                       nc -l -p 1234 -e cat /etc/os-release

### netstat
    # Print all IP connection servers
    > netstat -lptun # listening, get process name, tcp, udp, do not resolve address.
    Active Internet connections (only servers)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    ...

### nice
    # Switch to a less privileged user and try out nice
    > su -s /bin/sh nobody
    > nice -n -10 sh
    nice: setpriority(-10): Permission denied
    > nice -n 10 sh
    > nice
    10

### nl
    # Display file content with line numbers
    > nl /etc/os-release
         1  NAME="Alpine Linux"
         ...
         6  BUG_REPORT_URL="https://bugs.alpinelinux.org/"

### nmeter
    # At interval of one second, print several key system stats
    > nmeter -d 1000 'IRQ rate %i Ctx switch %x Forks %p block IO %b'
    IRQ rate  208 Ctx switch  392 Forks    2 block IO    0  24k
    IRQ rate  319 Ctx switch  757 Forks   49 block IO    0    0
    IRQ rate  177 Ctx switch  390 Forks    0 block IO    0 192k

### nohup
    # Run a program and make it immune to terminal hangup (SIGHUP)
    > nohup yes &>/dev/null &

### nologin
    # Inform logged-in user that shell is not available for this user
    > nologin
    This account is not available
    (and hangs there)

### nproc
    # Print the number of available CPUs
    > nproc --all
    2
    
### nsenter
    # Do this exercise outside of alpine container.
    # Create a new user namespace
    > unshare -r -p --fork --mount-proc
    # In another shell of the logon user, print a list of all namespaces.
    > lsns
    # Identify the process ID of the newly created user namespace and enter it
    > sudo nsenter --all --target 625537
    
### nslookup
    # Look up the A records of a DNS name
    > nslookup -type=a hz.gl
    Server:         9.9.9.9
    Address:        9.9.9.9:53
    Non-authoritative answer:
    Name:   hz.gl
    Address: 13.48.0.5
    
    # Look up the TXT records of a DNS name
    > nslookup -type txt hz.gl
    Server:         9.9.9.9
    Address:        9.9.9.9:53
    Non-authoritative answer:
    hz.gl   text = "v=spf1 mx a mx:hz.gl mx:howard.gg mx:houzuo.net mx:ard.how ?all"
    ...

### ntpd
    # Synchronise system clock with an NTP server
    # (verbose, do not daemonize, quit after setting clock, peer server name)
    > ntpd -d -n -q -p ca.pool.ntp.org
    ntpd: 'ca.pool.ntp.org' is 209.115.181.113
    ntpd: sending query to 209.115.181.113
    ntpd: reply from 209.115.181.113: offset:-0.008284 delay:0.165039 status:0x24 strat:2 refid:0x83006cce rootdelay:0.035508 reach:0x01 

### od
    # Print printable characters and escape sequences of the standard input
    > echo 'haha' od --format c -
    0000000   h   a   h   a  \n
    0000005

### openvt
    # Start a program on a new virtual terminal
    > openvt -c 1 -s -w
    can't find open VT (hehe)
    
### partprobe
    # Ask kernel to rescan partition table
    > partprobe

### passwd
    # Lock and disable a user account
    > passwd -l root

### paste
    # Paste lines from each input file, separated by a comma.
    > paste -d ',' /etc/os-release /etc/os-release
    NAME="Alpine Linux",NAME="Alpine Linux"
    ID=alpine,ID=alpine
    ...
    
### pgrep
    # Find the newest PID from sleep process
    > sleep 1000 &
    > pgrep -n sleep
    124
    
    # Find the newest PID from a process that mentions "1000" in its command line
    > pgrep -n -f 1000
    124

### pidof
    # Find exactly one process that runs the sleep program
    > sleep 1000 &
    > pidof sleep
    133

### ping
    # Send exactly one ping request to hz.gl
    > ping -c 1 hz.gl
    PING hz.gl (13.48.0.5): 56 data bytes
    ...
    1 packets transmitted, 1 packets received, 0% packet loss
    ...

### ping6
    # Send exactly one ICMPv6 ping request to localhost
    > ping6 -c 1 ::1
    PING ::1(::1) 56 data bytes
    ...
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    
### pipe_progress
    # Print a dot every second while a program is running
    > sh -c "while IFS='' read -d $'\n' line; do echo \$line; sleep 1; done < /etc/os-release" | pipe_progress
    NAME="Alpine Linux"
    .ID=alpine
    .VERSION_ID=3.13.0
    .PRETTY_NAME="Alpine Linux v3.13"
    (and so on)
    
### pivot_root
    # move the current root file system to ... what?!

### pkill
    # Similar to pgrep, kill the sleep program by matching its command line.
    > sleep 1000 &
    > pkill -KILL -f 1000
    [1]+  Killed                     sleep 1000

### pmap
    # Display the memory mapping of a process
    > pmap -x 1
    Address           Kbytes     PSS   Dirty    Swap  Mode  Mapping
    0000564b38826000      48       0       0       0  r--p  /bin/busybox
    0000564b38832000     612     214       0       0  r-xp  /bin/busybox
    ...
    0000564b39904000       4       0       0       0  ---p  [heap]
    0000564b39905000       4       4       4       0  rw-p  [heap]
    ...
    00007ffdcc1d9000     132       8       8       4  rw-p  [stack]
    ...
    ----------------  ------  ------  ------  ------
    total               1700     632     136      20
    

### poweroff
    # Poweroff the computer in two seconds, do not sync, do not go through init.
    > poweroff -d 2 -n -f

### printenv
    # Print an environment variable by name
    > printenv HOME
    /root

### printf
    # Print right-justified text using minimum field width of 5
    > printf '|%5s|%5d|\n' adam 123
    | adam|  123|
    > printf '|%5s|%5d|\n' adamandeve 12345678
    |adamandeve|12345678|
    
    # Print left-justified text using minimum field width of 5
    > printf '|%-5s|%-5d|\n' adam 123
    |adam |123  |
    > printf '|%-5s|%-5d|\n' adamandeve 12345678
    |adamandeve|12345678|
    
    # Print with "precision" - max length for a string, min length for an integer.
    > printf '|%.5s|%.5d|\n' adam 123
    |adam|00123|
    > printf '|%.5s|%.5d|\n' adamandeve 12345678
    |adama|12345678|
    
### ps
    # Print information about processes and threads
    > ps -T -o pid,ppid,pgid,sid,user,group,tty,args
    PID   PPID  PGID  SID   USER     GROUP    TT     COMMAND
    1     0     1     1     root     root     136,0  /bin/sh
    193   1     193   1     root     root     136,0  ps -T -o pid,ppid,pgid,sid,user,group,tty,ar

### pscan
    # Scan for open ports between 1 and 100, using a timeout of 100ms, and display closed/blocked ports too.
    > pscan -p 1 -P 100 -t 100 -b -c hz.gl
    Scanning hz.gl ports 1 to 100
     Port   Proto   State   Service
        1   tcp     open    tcpmux
        2   tcp     blocked unknown
        ...
        7   tcp     blocked echo
        8   tcp     blocked unknown
        9   tcp     blocked discard
       10   tcp     blocked unknown
       11   tcp     open    systat
       12   tcp     blocked unknown
       ...
       22   tcp     open    ssh
       23   tcp     open    telnet
       ...
       53   tcp     open    domain
       ...
       80   tcp     open    http
       ...
       99   tcp     blocked unknown
      100   tcp     blocked unknown
    0 closed, 8 open, 92 timed out (or blocked) ports
    / #

### pstree
    # Display process tree along with process PIDs, starting from PID 1
    > sleep 1000 & pstree -p 1
    sh(1)-+-pstree(202)
          `-sleep(201)

### pwd
    # Display the logical path of working directory, i.e. with symlink intact and unresolved.
    > pwd
    /

### pwdx
    # Print the current working directory of a process identified by its PID
    > cd /etc/ && sleep 100 &
    > pwdx $(pgrep -n sleep)
    209: /etc

### raidautorun
    # Tell the kernel to automatically search and start RAID arrays
    
### rdate
    # Print or set system clock on a remote computer

### rdev
    # Print the device node associated with the filesystem mounted at /

### readahead
    # Preload a file into memory cache
    > dd if=/dev/urandom of=./largefile bs=1M count=400
    400+0 records out
    > sudo sysctl -w vm.drop_caches=3 # execute on container host
    vm.drop_caches = 3
    > free -m
    total        used        free      shared  buff/cache   available
    Mem:            953         464         186           0         302         366
    Swap:          2047         177        1870
    > readahead ./largefile
    > free -m
    total        used        free      shared  buff/cache   available
    Mem:            953         463         185           0         304         367
    Swap:          2047         177        1870
    # Apparently readahead preloaded the first 2 MB of the file

### readlink
    # Resolve all symlinks to discover the absolute path to a file
    > ln -sf /etc/passwd /tmp/hahapass
    > readlink -f /tmp/../tmp/hahapass
    /etc/passwd

### realpath
    # Resolve all symlinks to discover the absolute path to a file, similar to readlink.
    > ln -sf /etc/passwd /tmp/hahapass
    > realpath /tmp/../tmp/hahapass
    /etc/passwd

### reboot
    # Reboot the computer in two seconds, do not sync, do not go through init.
    > poweroff -d 2 -n -f
    reboot: (null): Operation not permitted

### reformime
    # Extract content of an MIME section (does not appear to work)
    > makemime /etc/os-release | reformime
    (empty output)

### remove-shell
    # Remove a shell from /etc/shells
    > remove-shell /bin/ash
    > cat /etc/shells
    /bin/sh

### renice
    # Change the scheduling priority of a live process
    > sleep 1000 &
    > ps -T -o pid,ppid,user,group,tty,nice,args
     PID   PPID  USER     GROUP    TT     NI    COMMAND
      308     1  root     root     136,0      0 sleep 1000
    > renice 17 -g 308 # the ceiling of priority number only goes to 19 (lowest priority)
    > ps -T -o pid,ppid,user,group,tty,nice,args
     PID   PPID  USER     GROUP    TT     NI    COMMAND
      308     1  root     root     136,0     17 sleep 1000

### reset
    # Reset the TTY
    > reset
    (no output)

### resize
    # Determine the current TTY size and print shell statements that export COLUMNS and LINES
    > eval $(resize)
    > printenv COLUMNS LINES
    94
    41
    
### rev
    # Reverse the characters on each line of file
    > rev /etc/os-release
    "xuniL eniplA"=EMAN
    enipla=DI
    0.31.3=DI_NOISREV
    "31.3v xuniL eniplA"=EMAN_YTTERP
    "/gro.xunilenipla//:sptth"=LRU_EMOH
    "/gro.xunilenipla.sgub//:sptth"=LRU_TROPER_GUB
    
### rfkill
    # Enable/disable wireless devices
    > rfkill list all
    rfkill: /dev/rfkill: No such file or directory

### rm
    # Remove (unlink) files and directories (hehe surely I don't need an example here)

### rmdir
    # Remove empty directories, including the empty parent directories
    > mkdir -p a/b/c
    > rmdir -p a/b/c
    (parent directory a no longer exists)

### rmmod
### route
### run-parts
### sed
### sendmail
### seq
### setconsole
### setfont
### setkeycodes
### setlogcons
### setpriv
### setserial
### setsid
### sh
### sha1sum
### sha256sum
### sha3sum
### sha512sum
### showkey
### shred
### shuf
### slattach
### sleep
### smemcap
### sort
### split
### stat
### strings
### stty
### su
### sum
### swapoff
### swapon
### switch_root
### sync
### sysctl
### syslogd
### tac
### tail
### tar
### tee
### test
### time
### timeout
### top
### touch
### tr
### traceroute
### traceroute6
### true
### truncate
### tty
### ttysize
### tunctl
### udhcpc
### udhcpc6
### umount
### uname
### unexpand
### uniq
### unix2dos
### unlink
### unlzma
### unlzop
### unshare
### unxz
### unzip
### uptime
### usleep
### uudecode
### uuencode
### vconfig
### vi
### vlock
### volname
### watch
### watchdog
### wc
### wget
### which
### whoami
### whois
### xargs
### xxd
### xz
### xzcat
### yes
### zcat
