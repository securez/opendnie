-----------------------------------------------------------
#### How to DNIe in 10 steps ##############################
-----------------------------------------------------------

0. Prepare your system for build Debian packages:
apt-get update
apt-get install devscripts dpkg-dev fakeroot
apt-get build-dep opensc

1. Get into your favorite release directory:
cd opensc-dnie-xx.xx.xx/

2. Check and install new build dependences if it exists:
dpkg-checkbuilddeps
apt-get install ...

3. Get the current binary for that release:
uscan --download-current-version

4. Build it:
debuild -rfakeroot -us -uc -tc

5. Install it:
dpkg -i ../libopensc_*.deb ../dnie-support*.deb 

6. Install all unmet dependences:
apt-get -f install

7. Plug your card reader to your PC.

8. Insert your DNIe card.

9. Enjoy! ;)
