# janus

Python script to create an Android APK exploiting the Janus vulnerability.

[Credit to GuardSquare for the writeup.](https://www.guardsquare.com/en/blog/new-android-vulnerability-allows-attackers-modify-apps-without-affecting-their-signatures)

## Usage
```
usage: janus.py [-h] original-apk dex-file output-apk

Creates an APK exploiting the Janus vulnerability.

positional arguments:
  original-apk  the source apk to use
  dex-file      the dex file to prepend
  output-apk    the file to output to

optional arguments:
  -h, --help    show this help message and exit
```