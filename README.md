# nvidia-driver

This is a version of FreeBSD's nvidia driver which contains
nvidia-drm.ko, normally a linux only kernel module.

The original goal of this project was to get EGL rendering working on
nvidia without using X11. I (wrongly) assumed that if I ported
nvidia-drm to FreeBSD then I could get EGL to display direct to the
display.

Fortunately the libEGL that nvidia ships for FreeBSD does not rely on
any drm code. This means my original goal is impossible. Since then
I've kept hacking on this solely because it's fun.

## Progress

At the moment this can run anything that displays *only using
libdrm*. If it uses EGL (like kmscube) it will not work. Unfortunately
I lost the program I normally test with when my previous hard drive died.

## Relevant Links
* https://badland.io/nvidia-drm.md
* https://badland.io/nvidia.md

## Warning
This is highly unstable, and not that useful. Please do not use this
for anything important.

## Compiling

You will need to download and build the FreeBSD source and the kms-drm code for
(Ideally version 5.0 or higher). You will also need to change
the include directories specified in `src/nvidia-drm/Makefile` to
match where you've built kms-drm. After that you can just type `make
install`. Make sure to install kms-drm as well.

*note* - This requires a kernel built without INVARIANTS. The nvidia
 locks will panic if witness is enabled.