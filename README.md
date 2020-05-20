### Features

- Basic & Digest authentication brute force
- Multi-threaded port scanning
- Credentials-first & Route-first devices are supported
- Masscan support


This is a **Proof of Concept** that took me exactly 4 days to complete. The source code is sloppy -yet working but not as it should- and requires a lot of work to become a complete project.

### Help is needed to complete the following:

- Source code complete refactoring (Threading, Variables, Logic etc)
- Add script parameters
- Extensive tests **especially for Route-first devices** (devices that require the stream path to be known) from people who actually own such devices
- Extensive tests for **DIGEST AUTH devices**
- Implement an export function (M3U8 files for VLC, or even iSpy if possible)
- Add support for other protocols (anything that iSpy supports)
- Add support for devices that do not require authentication
- Create a requirements.txt for easy installation
- Create a single executable


# PyLLyWOOD
##### Hollywood-style CCTV hacking - PoC


![](https://i.ibb.co/zXJbtVV/cctvhacking.png)


[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/analyserdmz/Pyllywood/issues) ![HitCount](http://hits.dwyl.com/analyserdmz/Pyllywood.svg)

### Contribution notes:
- **DO NOT** use PyCurl for RTSP! There is no support for RTSP in PyCurl yet! I thought there was and I had to completely re-write the poc and make it use sockets.
- Some devices respond with 200 even if the path is wrong.
- Some devices terminate the connection when a valid path with valid credentials is accessed with "DESCRIBE" request, not respecting RFC. If we want to find even more paths or more credentials, the connections have to be looped again and again.
- Some devices require a valid username and password at first place, while others require a valid path.
- Some devices respond with 401 when a valid path is found, while others respond with 403.
- A complete RFC-respective conversation can be used to validate streams ("SETUP" and "PLAY" requests), but it doesn't seem to matter at all. I am using only "DESCRIBE" requests.
- Some devices respond with 200 no matter what. I assume these are devices with either no authentication or honeypots (?).

### Special thanks to:

- [Ullaakut](https://github.com/Ullaakut) for his **AWESOME** project [Cameradar](https://github.com/Ullaakut/cameradar) which was my inspiration and for helping me understand how the RTSP logic flows!
- [iSpy Software Developers](https://github.com/ispysoftware) for their huge list of [CCTV XML](https://raw.githubusercontent.com/ispysoftware/iSpy/master/XML/Sources.xml)!
- Any of you for contributing!
