---
title: "Catpi"
date: 2020-04-20T17:23:59Z
draft: true
tags: ["raspberrypi", "tensorflow"]
---

{{< video src="catpivideo" height="200" >}}

Alright, so I've had an RPi for a while, and it's had various... uses. One time I thought it might be fun to set up a streaming box, so I did that for a bit, but then some dependency issues came up with netflix and widevine and, well, it became easier to just buy a Google Home. So, next it lived a short life as a paperweight and didn't get any attention until the day we got an automated cat feeder to help alleviate waking up in the morning to loud cat-wall-scratchies.

Well, we soon discovered that merely buying the auto feeder didn't fix the problem. Sure, the feeder goes off, and *A* cat gets fed. But, one is on a slightly more extreme diet than the other... Depending on who gets the robo-kibbles we still have a cat scratching the wall in the morning. Additionally, in order to not overfeed, we need to feed the one that didn't get robo-breakfast their normal portion. Which begs the all too common question (right?): Who got robo-breakfast?

## The goal

The goal here is pretty self-explanatory: I wanted to identify which cat gets the kibble from the robo-feeder using the RPi. Since the Pi needs to be mounted at the 'food station' with the end-goal being pseudo automation, it's gotta be headless. Now, that's fairly common for devices like these, but it just adds its own difficulties-- there's a million computer vision projects on the pi, but if you pay attention, most of them aren't headless, they typically use the [pygame](https://www.pygame.org/news) and [OpenCV](https://opencv.org/) libraries or something similar to output to a screen. This isn't a huge problem, I can take pictures or video and push them to another machine on my network to look at, it just made troubleshooting a bit more involved and tedious.

There are multiple ways around this, as I explored more and more projects I got more and more ideas, some of which can be easily implemented, others not so much.

## Pre-Reqs

The feeder is currently set to two early morning, arbitrarily decided times. At both times the feeder spits out a small portion of kibble, about half the cats' normal serving of kibble (the amount they'd receive if the robo-feeder didn't feed them). So, if cat A gets both servings, cat B gets a normal breakfast helping, while cat A gets only wet food (and gets sad I guess because he forgets he already ate??) Anyway, obviously cats don't listen to instructions, so some days both A and B get a robo-serving, some days both A, etc. 

So based on this, it was easy to make some initial criteria:

- Mount the Pi somewhere near the robo feeder
- Power connection only-- basically needs an unattend.txt
- Take photo / video at breakfast time
- We'll call this 'evidence'
- Obtain the evidence
- Using PiCamera, specifically
- Send the video somewhere it can be viewed in the morning

- OPTIONAL:
- Run Tensorflow against output- Text the results
- Extensible
- Able to easily integrate more cameras

That's a pretty easy starting point, with some added difficulty on the end.

## A PoC Emerges

It's actually been a while that the CatPi has been up and running. Maybe I'll document some of the hardships at some point, but I think most of the issues I had can be put into four categories (not graded by difficulty):

- Getting the desired input / output- Learning how to use OpenCV, and - Learning to use Tensorflow

As it stands, the positioning of the camera itself could use a little work, due to the current placement of the cats' food, there's not an easy way for me to obtain a silhouette of the cats, we just don't have any way to mount it, so an overhead shot is the only thing that will work at present. Because of this, the CatPi thinks the cats are skateboards or bananas. Which is awesome.

## Immediate Changes

Initially, I really wanted a one-and-done script; one script you could just run and get all the output, etc. While it was possible, I found that using PiCamera introduced some arbitrary difficulty in terms of video conversion. PiCamera shoots video in a couple formats, but most are considered 'raw' and none work natively in web browsers. For instance, .h264 actually contains a whole bunch more data than just the raw frames... some of it is vector data, such as vectors of moving objects.

[ffmpeg](https://www.ffmpeg.org/) offered a relatively painless conversion between formats, but as anything else you try to do with a computer, it wasn't as simple as just converting from h264 to mp4. I didn't know that h264 had 'extra frames', for instance, if I tell the Pi to record at 10 FPS, the h264 format technically IS 10 FPS, but when you split it apart by frame, you find that three frames have been created for each 'frame'. So, my mp4 output ended up being three times longer than my input videos, and super wonky as far as the framerate went. 

After some fiddling, I found that setting the FPS for the input video (recorded at 10 FPS) to 30, and the output MP4 to 10 FPS did the trick. This was quite a bit of weird troubleshooting though as I knew nothing about video formats. I also quickly realized that doing the initial recording via raspivid was more reliable than recording via the PiCamera. Both work, but for whatever reason, raspivid seems to convert better.

## How it works

Well, it's pretty simple.

- At a predetermined time, breakfa.sh is called with a flag indicating if it is the first or second run of the day.
- Due to a slight discrepancy between the robo-feeder's clock and the CatPi, a small delay is added if is run #2
- raspivid takes a 10 second video, which is output to an evidence directory.
- breakfast.py takes the raspivid output and does some post-processing with Tensorflow against it, writing the detected objects onto each frame.
- ffmpeg is called to convert, specifying the input framerate of 30 FPS, and output video framerate of 10 FPS.
- The videos's are scp'd to the mightbeacat.org webserver, where they're encapsulated within an iframe.
- The local evidence directory is then cleaned.

I'll put the code up on github with a template crontab as well.

Looks like a CCTV cam!

![cctv](http://4.bp.blogspot.com/-HGyLPlJMj8U/Xp2f93hBfYI/AAAAAAAAA8o/Xyoto8n5SGcbcWqeZ3zlgP1_HBhDNcHsgCK4BGAYYCw/s1600/IMG_2645.jpg)

53% Banana, 100% awesome:

![banana](http://2.bp.blogspot.com/-68oINedYfpQ/Xp2gqQehkgI/AAAAAAAAA9A/nD2-BwvQEjATKqK2Qd50Jcp_KSQ7A3zsACK4BGAYYCw/s1600/unknown.png)
