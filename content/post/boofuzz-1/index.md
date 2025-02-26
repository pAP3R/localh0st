---
title: "Boofuzz Checksums"
date: 2025-02-25T19:21:09-05:00
draft: true
tags: ["notes"]
---

## boofuzz

It's been a bit since I did much fuzzing, and recently at work I was tasked with fuzzing some medical device protocols-- HL7, ASTM and POCT1A for a device that was ingesting them. It was a bit of a strange set up, and ended up requiring me to fuzz over TCP.

In an ideal fuzzing scenario, you're *definitely not* fuzzing over the network, as that requires interacting with the network stack and everything that comes with it... creating sockets, sending data, waiting for responses, closing sockets, etc. Then looping that. All this to say: it's (very) slow. A best case scenario is having source, and changing the app to instead take input from stdin. 

If you don't have source and can't easily patch a bin, the next best thing is desocking it (de-socketing). This usually entails hooking the networking functions or defining them elsewhere and doing something like `LD_PRELOAD`-- this technique is seen commonly in conjuction with afl.

Anyway, I was stuck doing some network fuzzing and it sucked. So, to make it suck a *bit* less I used [boofuzz](https://github.com/jtpereyda/boofuzz), a network capable fuzzer written in python3. I've used boofuzz a lot in the past-- it's a bit confusing at first, but it allows a lot of extensibility. 

Of the three protocols I was poking at, only one required a checksum, and although boofuzz didn't support the exact alg I needed ((sum % 256) + 16), it was easily implemented.

## Checksums with boofuzz

boofuzz supports the `Checksum()` function (essentially a data type), that can be used to create a checksum of one or two bytes width. Checksums accept a block as an argument, so using them is crucial for the proper calculation.

Here's an example:

```python
from boofuzz import *

# enq packet
enq = b"\x05"

# a silly ASTM packet
stx = b"2P"
frame = b"2|blah^blah^^2.0+70+1.0|12|||R^32^||V||1201639|20240225051522|2333352156323|19\r"
etx = b"\x03"
end = b"\r\n"

def main():
    print(checksum_bytes(frame + etx))

def checksum_bytes(data):
    checksum = 0
    for i in data:
        checksum += i
    c = hex(checksum % 256)[2:]
    return c

if __name__ == "__main__":
    main()
```

Running this produces a result of `7e` for that frame. Assembling an ASTM packet is then trivial, `stx + frame + etx + checksum + end`

This can be converted into a boofuzz script easily as well, as the packet sections can be treated as blocks. In `main()` boofuzz will be initialized:

```python
def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("192.168.1.2", 80)),
    )

    define_proto(session=session)
    session.fuzz()
```

`define_proto` is, well, where the protocol will be "defined" to boofuzz. `Request`s are literal requests, they're an individual packet. `Request`s can contain `Block`s, an additional way to organize data within the packet. The code below creates two requests, an ENQ request, followed by the astm data. The second block within the `data` request contains the checksum, which is calculated off the data in the `frame` block.

The `algorithm` argument specifies the algorithm used. According to some [documentation](boofuzz/blocks/checksum.py), boofuzz either accepts a pre-defined list of algs, or a function can be specified, documented as `Function signature:  <function_name>(data_bytes). Returns a number represented as a bytes type.`

These packets are then sent to the application via the calls to `session.connect()`. It's not a mistake that `session.connect` is called twice, it's just how boofuzz does it.

```python
def define_proto(session):
    # "start" packet
    start_req = Request("start", children=(
        Static(name="enq", default_value="\x05")
    ))

    # "data" packet
    # calcs a checksum off data_block
    # custom "summod256" checksum algorithm
    data_req = Request("data", children=(
        Static(name="stx", default_value="\x2P"),
        Block(name="frame", children=(
            String(name="frame-data", default_value="2|blah^blah^^2.0+70+1.0|12|||R^32^||V||1201639|20240225051522|2333352156323|19\r"),
            Static(name="etx", default_value="\x03")
        )),
        Block(name="checksum", children=(
            Checksum(name="checksum", block_name="frame", algorithm="summod256"),
            Static(name="end", default_value="\r\n")
        ))        
    ))

    session.connect(start_req)
    session.connect(start_req, data_req)
```

The `algorithm` argument is seemingly as simple as `algorithm=checksum(x)` but I wasn't able to ascertain the actual argument to pass to it. Instead, another possiblity is editing the `checksum.py` boofuzz file. Inserting some code at line 191 adds the `summod256` checksum type, below:

```sh
diff --git a/boofuzz/blocks/checksum.py b/boofuzz/blocks/checksum.py
index 4712dc8..69cbaf1 100644
--- a/boofuzz/blocks/checksum.py
+++ b/boofuzz/blocks/checksum.py
@@ -188,6 +188,13 @@ class Checksum(primitives.BasePrimitive):

                 check = digest

+            # sum of bytes % 256
+            elif self._algorithm == "summod256":
+                checksum = 0
+                for i in data:
+                    checksum += i
+                check = hex(checksum % 256)[2:]
+
             else:
                 raise exception.SullyRuntimeError("INVALID CHECKSUM ALGORITHM SPECIFIED: %s" % self._algorithm)
         else:
```

Now, boofuzz will calculate a checksum of the `frame` block and append it after the `ETX`. From here, the actual ASTM frame data can be broken into it's component parts and fuzzed. 

Here's a full example script for fuzzing ASTM frames with boofuzz.

```python
#!/usr/bin/env python3

# boofuzz ASTM w/ checksum example
# two request variants incoporating blocks and checksums
#   
# checksum uses a  "sum % 256" algorithm, added to boofuzz/blocks/checksum.py
# summod256 is basically checksum_bytes()

from boofuzz import *
'''
# a silly ASTM packet
stx = b"2P"
frame = b"2|blah^blah^^2.0+70+1.0|12|||R^32^||V||1201639|20240225051522|2333352156323|19"
etx = b"\x03"
end = b"\r\n"
'''

def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("192.168.1.9", 80)),
    )

    define_proto(session=session)
    session.fuzz()

    # checksum tests -- string and byte input, respectively
    #checksum_string("test")
    #checksum_bytes(frame + etx)

def define_proto(session):
    # ENQ packet
    start_req = Request("start", children=(
        Static(name="enq", default_value="\x05")
    ))

    # Example ASTM frame w/ checksum
    # calcs a checksum off "frame" block
    data_req = Request("data", children=(
        Static(name="stx", default_value="2P"),
        Block(name="frame", children=(
            String(name="frame-data", default_value="2|blah^blah^^2.0+70+1.0|12|||R^32^||V||1201639|20240225051522|2333352156323|19"),
            Static(name="cr", default_value="\r"),
            Static(name="etx", default_value="\x03")
        )),
        Block(name="checksum", children=(
            Checksum(name="checksum", block_name="frame", algorithm="summod256"),
            Static(name="end", default_value="\r\n")
        ))        
    ))

    session.connect(data_req)
    session.connect(start_req, data_req)

def checksum_string(data):
    checksum = 0
    for i in data:
        checksum += ord(i)
    c = hex(checksum % 256)[2:]
    return c

def checksum_bytes(data):
    checksum = 0
    for i in data:
        checksum += i
    c = hex(checksum % 256)[2:]
    return c

if __name__ == "__main__":
    main()
```