#!/bin/bash
# execute these commands (as root) 
# to get Fedora RPM files from repositories
#
if [ $UID -ne 0 ]; then
  echo "must be root to execute this script"
  exit 0
fi

cd /root/rpmbuild/SOURCES
svn checkout https://svn.forge.morfeo-project.org/opendnie/dgp-devel-svntrunk
svn co http://www.opensc-project.org/svn/opensc/trunk opensc
tar -C dgp-devel-svntrunk --exclude-vcs -zcvf opensc-0.12.0-dnie.tar.gz src
tar --exclude-vcs -zcvf opensc-0.12.0-svn4874.tar.gz opensc
cp dgp-devel-svntrunk/opensc-0.12.x-dnie.patch .
cp dgp-devel-svntrunk/fedora/opensc-dnie.spec ../SPECS
cd ../SPECS
rpmbuild -ba opensc-dnie.spec
