Installation:
1) Download and install the Pidgin instant messenger from the website http://www.pidgin.im
2) Place the binary file hka_plugin.so in the ~/.purple/plugins directory

Runing:
1) Open Pidgin
2) Choose from the menu Tools -> Plugins
3) Find the Human Key Agreement protocol on the list and activate it

Usage:
1) Right-click on a friend's name and choose the “Establish a secure key” option from the menu

Manual Compilation:
1) Enter pidgin_plugin directory
2) Open Makefile.am file and modify PIDGIN_HOME variable to point to your copy of pidgin sources
3) Run the following commands:

./autogen.sh
mkdir build
cd build
../configure
make

4) Place the binary file .libs/hka_plugin.so in the ~/.purple/plugins directory