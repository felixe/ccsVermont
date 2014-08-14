#!/usr/bin/env sh

# Link vermont so it can use libzero. (hacky; should be done by cmake)
# usage: 1) run make 2) run this to link again

/usr/bin/c++ CMakeFiles/vermont.dir/src/vermont.o -o vermont -rdynamic -L/home/martin/vermont/src/modules -L/home/martin/vermont/src/core -L/home/martin/vermont/src/common/anon -L /home/martin/vermont/src/common/ipfixlolib -L/home/martin/vermont/src/common -L/home/martin/vermont/src/osdep -L/usr/local/lib src/modules/libmodules.a src/core/libcore.a src/common/anon/libanon.a src/common/ipfixlolib/libipfixlolib.a src/common/libcommon.a src/osdep/libosdep.a /home/martin/ntop/userland/lib/libpfring.a -lpthread -lboost_regex-mt -lboost_filesystem-mt -lboost_system-mt -lxml2 -lpcap /usr/local/lib/libpcap.so /usr/local/lib/libpcap.so -Wl,-rpath,/usr/local/lib:
