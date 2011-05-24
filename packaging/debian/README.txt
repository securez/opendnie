-----------------------------------------------------------
#### How to build and install this Debian package #########
-----------------------------------------------------------

0. Prepare your system for build Debian packages:
apt-get update
apt-get install devscripts dpkg-dev fakeroot svn-buildpackage
apt-get build-dep opensc

1. Get into your favorite release directory:
cd tags/xx.xx.xx/

or, if you want the bleeding edge:
cd trunk/

2. Check and install new build dependences if they exist:
dpkg-checkbuilddeps
apt-get install ...

3. Get the current tarball for that release:
svn-buildpackage -rfakeroot -us -uc -tc --svn-download-orig

4. Install it:
dpkg -i ../build-area/libopensc_*.deb ../build-area/opensc_*.deb 

5. Install all unmet dependences:
apt-get -f install

6. Consider to configure your application (internet browser, etc) to support OpenSC
and install on it the needed certificates, if any.

7. Enjoy! ;)
