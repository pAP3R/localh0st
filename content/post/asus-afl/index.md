---
title: "Asus, Qemu, AFL++ Notes"
date: 2022-12-29T01:00:00Z
draft: true
tags: ["AFL", "Asus", "qemu", "emulation"]
---

This post is just a collection of my notes and experiences reversing, compiling and emulating Asus proprietary and Asuswrt-Merlin software, on an Ubuntu 20.04 box. It's a bit of a pain really, I thought it would be pretty easy but everything's been an issue, which is also what makes it sorta fun.

Worked primarily with https://github.com/RMerl/asuswrt-merlin.ng for the RT-AX88U router, but some binaries are just closed-source :/<!--more-->

----------

Various, helpful and unhelpful links:

- https://resources.infosecinstitute.com/topic/fundamentals-of-iot-firmware-reverse-engineering/
- https://gitbook.seguranca-informatica.pt/arm/reverse-iot-devices/reverse-asus-rt-ac5300#emulation-nvram
- https://www.zerodayinitiative.com/blog/2020/5/27/mindshare-how-to-just-emulate-it-with-qemu

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

`arm-linux-gcc-5.5.0 -shared -nostdlib nvram.c -o libnvram.so -ldl && chmod 777 libnvram.so && ~/amng-build/release/src-rt-5.02axhnd/targets/94908HND/fs && cp ~/libnvram/libnvram.so firmadyne/`

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

Fought a bit more with nvram, created "debug_cprintf_file" key in libnvram.override/

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
pcVar2 = (char *)func_nvram_Check-2("cfg_dbg");
iVar4 = strcmp(pcVar2,"1");
if (iVar4 == 0) {
cprintf("[%s(%d)]:auth check success\n",&DAT_000800e1,0x2864);
}
pcVar2 = (char *)func_nvram_Check-2("cfg_syslog");
iVar4 = strcmp(pcVar2,"1");
if (iVar4 == 0) {
asusdebuglog(6,"cfg_mnt.log",0,1,0,"[%s(%d)]:auth check success\n",&DAT_000800e1,0x2864);
}
memset(cm_ctrlBlock,0,0x8c);
kill_pidfile_s("/var/run/cfg_server.pid",0xf);
sleep(1);
_Var5 = fork();
```

FUN_0001e608 == auth_check()
Line 31: checks auth_check return val, patched this to flip it by patching in ghidra, then exporting the program as an elf and writing it back to the file system annnnd:

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

Looking at the cprintf file, now seeing more stuff, and some stuff about received packets:
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

^ runs... exits :/ Might be OK?

Need a seed, previously captured some 7788/udp traffic

[...]

## httpd... crash?

The httpd crash is from sending a digit as the first character of the payload body happens in httpd.c, around line 1605 in handler->output(file, conn_fp);
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

Set up host system to create core dumps with ulimit

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
	conn_fp = fopen(inputFile, "rw+"); // <-- this
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


### AFL -> httpd

Used afl++ in qemu mode to begin fuzzing the httpd bin using a few example requests and a dictionary file from: https://github.com/antonio-morales/Apache-HTTP-Fuzzing

install AFLplusplus: https://aflplus.plus/building/

Compile for QEMU with arm support:

`~/AFLplusplus/qemu_mode$ CPU_TARGET=arm ./build_qemu_support.sh`

Using mime_handlers and httpd.c and httpd.h I created a small dictionary which contains the contents of /www/, common headers, specific headers and anything else interesting, based off of the dict mentioned above

Then:

`tester@asuserlin-ubuntu20:~/amng-build/release/src-rt-5.02axhnd/targets/94908HND/fs$ QEMU_LD_PREFIX=/home/tester/amng-build/release/src-rt-5.02axhnd/targets/94908HND/fs/ /home/tester/AFLplusplus/afl-fuzz -Q -i /home/tester/afl-in/ -o /home/tester/afl-out/ -x /home/tester/http.dict -- usr/sbin/httpd @@`

This works... sorta, but since AFL is built for fuzzing random binary data it's not "context aware" and has no idea how to fuzz data with any structure, or grammar, so it just throws fuck all at it and watches what happens. To perform more targetted fuzzing for languages like HTTP, which expect requests to be in specific formats and are parsed for specific keywords and structures, there are cool AFL tools like [Grammar Mutator](https://github.com/AFLplusplus/Grammar-Mutator). 

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