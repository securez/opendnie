-----------------------------------------------------------
#### How to build and install this Debian package #########
-----------------------------------------------------------

0. Prepare your system for build Debian packages:
apt-get update
apt-get install devscripts dpkg-dev fakeroot
apt-get build-dep opensc

1. Get into your favorite release directory:
cd tags/opensc-opendnie-xx.xx.xx/

or, if you want the bleeding edge:
cd trunk/

2. Check and install new build dependences if they exist:
dpkg-checkbuilddeps
apt-get install ...

3. Get the current tarball for that release:
uscan --download-current-version

4. Untar it:
tar xzvf ../opensc-opendnie_*.orig.tar.gz --show-transformed-names --transform 's|^[^/]*||'

5. Build it:
debuild -rfakeroot -us -uc -tc

6. Install it:
dpkg -i ../libopensc_*.deb ../opensc_*.deb 

7. Install all unmet dependences:
apt-get -f install

8. Consider to configure your application (internet browser, etc) to support OpenSC
and install on it the needed certificates, if any.

9. Enjoy! ;)
