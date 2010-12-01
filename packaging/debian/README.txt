-----------------------------------------------------------
#### How to DNIe in 10 steps ##############################
-----------------------------------------------------------

0. Prepare your system for build Debian packages:
apt-get update
apt-get install devscripts dpkg-dev fakeroot
apt-get build-dep opensc

1. Get into your favorite release directory:
cd branches/opensc-dnie-xx.xx.xx/

or, if you want the bleeding edge:
cd trunk/

2. Check and install new build dependences if they exist:
dpkg-checkbuilddeps
apt-get install ...

3. Get the current tarball for that release:
uscan --download-current-version

4. Untar it:
tar xzvf ../opensc-dnie_*.orig.tar.gz --show-transformed-names --transform 's|^[^/]*||'

5. Build it:
debuild -rfakeroot -us -uc -tc

6. Install it:
dpkg -i ../libopensc_*.deb ../dnie-support*.deb 

7. Install all unmet dependences:
apt-get -f install

8. Plug your card reader to your PC and insert your DNIe card.

9. Check your installation loading this URL with Mozilla Firefox:
firefox http://www.dnielectronico.es/como_utilizar_el_dnie/verificar.html
(click on 'Comprobación de certificados' at bottom of page)

10. Enjoy! ;)
