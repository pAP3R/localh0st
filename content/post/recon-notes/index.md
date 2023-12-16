---
title: "External Recon, Discovery Notes"
date: 2023-12-15T12:27:00Z
draft: true
tags: ["notes", "recon", "osint", "discovery"]
---

Had a few questions lately at work about recon-- what it looks like, how people do "discovery", and what that entails. There's some awesome posts like [this one](https://www.offensity.com/en/blog/just-another-recon-guide-pentesters-and-bug-bounty-hunters/) and [this one](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology) which have great resources, so I usually send these over to people along with various tips and tricks. Through the years though, some of my favorite resources haven't stood test of time and `404` or timeout. So, I'll now add to the information vacuum.

Note that this is by no means all encompassing, it's primarily for me to have a file to look at periodically and think "oh yeah I guess I should run this, too".

### Basic Host Discovery

Host discovery is the process of attempting to identify hosts and (sometimes) subsidiary organizations belonging to a client or target. This process tends to be cyclic, as new data yields additional resources. Below are some ideas and a process for getting going on some external recon. There are a lot of resources out there and largely they're all relevant-- the tools have changed over the years but the fundamentals still apply. 

I usually end up rerunning tools, regardless of new assets being discovered as they'll sometimes find different stuff. Enumeration / discovery efforts usually go from "passive discovery" to "active discovery", then flip between the two as time progresses. 

#### Passive Discovery

Passive discovery gathers information from tools which have already found it (google, `amass -passive`), so as to not query resources *belonging to the client*. This is especially important in "stealth" style engagements or red teams, where we want to avoid alerting anyone of our activities.

#### Active Discovery

When we switch to "active" techniques, we begin doing more involved things like subdomain bruteforcing, port scanning, vulnerability scanning, etc. Stuff that's actively reaching out and touching / scanning resources is considered "active".

### Passive

Given a company, e.g., Aon, the process usually begins by identifying any easily found domains and hosts. 
- aon.com
- aon.cn
- aontrust.com
- aonprograms.com
- etc.

#### Example of Domain / Host Discovery

These aren't in any particular order... also, pretty much anything from [ProjectDiscovery](https://github.com/projectdiscovery) is great

1. Attempt to identify possible domains, e.g. aon.com, aon.cn, aontrust.com
	- Google, bing, duckduckgo
		- google dorks, etc 
	- [Shodan](https://www.shodan.io/)
    - [Censys](https://www.censys.io/)
	- `Optional:` Google "aon subsidiary", or similar, to find acquisitions and companies owned by the targetmay not be necessary
	- Wikipedia as well
	- [DNSDumster](https://dnsdumpster.com/) is a great site for finding aggregated DNS data
	- `whois <domain>` / `whois IP`
	- [Phonebook.cz](https://phonebook.cz/) <-- dope site

2. Review DNS records
	- MX, SPF, etc. These records may point to externally managed stuff, but they might also point towards a client owned host
        - `dig -txt aon.com`

3. Determine if M365 managed or federated org-- tools like AADInternals can be used to gather a good amount of info:
	- `Invoke-AADIntReconAsOutsider -Domain "aon.com" | Format-Table`
    - Check for domain (replace TARGET)
	    - https://login.microsoftonline.com/getuserrealm.srf?login=user@TARGET&xml=1

4. Run tools like the following, which search aggregated info for domains and other stuff:
    - `subfinder -d aon.com  -v`
	- `amass enum -d aon.com -passive`
    - `amass intel -d aon.com`
	- `theHarvester -d aon.com -t <search engines>`
	- `gau -subs aon.com` -- there's also [waymore](https://github.com/xnl-h4ck3r/waymore) which has way more :P
	- `fierce.py` This used to be a pretty popular tool, haven't used it in a long time
	- `dnsrecon -d aon.com`
    - `dnsx -d aon.com` (or `-l list.txt`, etc)

5. Attempt to ID registered ASNs (autonomous system number) and take note of IP addresses which are returned by the above tools
    - For instance, aon.com resolves to 165.125.80.231; a `whois 165.125.80.231` finds it to be a member of ASN `AS16875`, and the IP registered to a `AON Corporation (AON-1-Z)`. These are things you can continue to search off of
	- Each additional IP might ALSO be part of a registered subnet, or the same ASN, w/e. It's not always clear if an IP (or even a host sometimes) belongs to an organization, so do your best to ID these.

6. Make sure to also check reverse DNS (rDNS) and reverse whois stuff as well. Some tools like `dnsrecon`, `amass` (even nmap) can automate this for you. 
7. Client's SSL certificates can also yield a ton of info, and can be found through various sources such as crt.sh, shodan, censys, etc
8. Check github!
    - Github search for the org, users / employees. Sometimes employees will have their orgs listed. If that's the case, troll around for secretz
    - Github dork helpers:
        - https://cipher387.github.io/code_repository_google_custom_search_engines/
        - https://vsec7.github.io

At a certain point there will either be nothing left to find for just subdomains, or there will be a sort of "diminishing return" aspect. Moving on to active stuff tends to discover additional places to look, anyway.

### Active

The active phase takes the info we've been gathering, and starts to work with it to discover the associated IPs, URLs, subdomains etc. This part starts to brush up against actual testing, as some discovery is intended to find websites, low hanging fruit etc. You can usually do all this without running nmap, httpx, eyewitness etc, as those tools start to uncover the actual "Attack surface" rather than just the assets themselves.

This is also where stuff can start to become sprawling on large networks, but keep track of what you've run by making sure to save the output in some capacity. I like to `command | tee command-domain.txt` or similar for just about everything I do.

#### Subdomain enumeration 
1. Run subdomain enum 
	- `sublist3r -d aon.com`
	- `subfinder -d aon.com` 
	- `amass enum -d aon.com -brute`
	- `assetfinder aon.com`
	- `dnsrecon -d aon.com`
	- `dnsenum aon.com`
    - `dnsx -d aon.com`

2. This process is more involved and will cause you to go back and forth quite a bit 
3. ffuf is a great tool for fuzzing web servers, but did you know if can be used to fuzz for virtual hosts and subdomains, too?
	- `ffuf -w subdomain-wordlist.txt -u https://<IP> -H "Host: FUZZ.aon.com"`

4. With the prevalence of cloud technologies, (Azure, AWS, etc), it's a good idea to start digging for insecure cloud resources like Azure Blob Storage and AWS S3 Buckets. This isn't super straight forward but there are some tools like:
	- `bucket_finder`
	- `s3-buckets-finder`
	- `cloud_enum`
	- `S3scanner`
    - `AADInternals`
    - [goblob](https://github.com/Macmod/goblob)

#### Scanning / exploitation / etc

Eventually the engagement moves into actively scanning resources (or NOT if it's a red team / stealth), but the process will continue to follow this "cyclic" pattern where you discover more resources, then have to walk back and make sure they're enum'd and scanned.