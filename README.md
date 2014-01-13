Cave Canem
=========

Cave Canem is an extensible monitoring and intrusion detection system based on the Object Management Group (OMG) Data Distribution Service (DDS) standard.

## Building Cave Canem

Cave Canem uses CMake to generate Makefiles or Visual Studio solutions to build both the application and its plug-ins, which makes it easier to port the application to different platforms. 

Note that Cave Canem requires CMake 2.8.7 or higher.

### Installing CMake

#### Installing CMake on Linux
Many distributions include CMake in their repositories. In Debian-based distributions, such as Ubuntu, you can install CMake via apt-get:

    $ apt-get install cmake

In Fedora or RedHat based distributions, such as CentOS, run:

    $ yum install cmake

You can also download an installer with CMake's latest version from [Kitware's webpage](http://www.cmake.org/cmake/resources/software.html).

    $ chmod +x cmake-<current_version>-Linux-386.sh
    ./cmake-<current_version>-Linux-386.sh

The self-extracting installer will install CMake in a location of your choice.

#### Installing CMake on Windows

Kitware provides a simple installer for Windows. You can download this installer from [Kitware's webpage](http://www.cmake.org/cmake/resources/software.html). Make sure to add cmake to your path to make it easier to use the tool via command line. 

#### Installing CMake on OS X

Kitware provides two [two different dmg images](http://www.cmake.org/cmake/resources/software.html) for OS X. If you run Snow Leopard or later, use _cmake-\<version\>-Darwin64-universal.dmg_, if you run an earlier version of OS X, install _cmake-\<version\>-Darwin-universal.dmg_ instead. Both images contain a pkg file. Double click on it and follow the installation wizard to complete the installation.

You can also install CMake on OS X via Macports running:

    $ port install cmake

### Building Cave Canem

Once you have installed CMake in your environment, you can run the CMake script to generate makefiles or Visual Studio solutions to build Cave Canem. The CMake scripts require you to set two parameters:

* `NDDSHOME` -- Path to your RTI Connext DDS installation.
* `ARCHITECTURE` -- Connext DDS architecture you are using (e.g., i86Linux2.6gcc4.4.5).

These variables can be passed either as parameters to the CMake scripts or set as environment variables.

#### Building Cave Canem on Linux

Assuming the CMake script is in your path and the Connext DDS architecture you are running is i86Linux2.6gcc4.4.5, change to the src directory and run:

    $ cd cavecanem/src
    $ cmake -DNDDSHOME=/path/to/your/connext/installation/ndds.x.x.x -DARCHITECTURE=i86Linux2.6gcc4.4.5

CMake will generate a makefile under the src directory capable of building Cave Canem and its plug-ins. Run this makefile to build the application from the src directory:

    $ make
    
#### Building Cave Canem on Windows

Assuming the CMake script is in your path and the Connext DDS architecture you want to use is i86Win32VS2010, change to the _src_ directory and run:

    > cd cavecanem\src
    > cmake.exe -DNDDSHOME=C:\path\to\your\connext\installation\ndds.x.x.x -DARCHITECTURE=i86Win32VS2010

CMake will generate a Visual Studio solution under the src directory called _cavecanem.sln_ that you can use to build Cave Canem and its plug-ins. Open the solution, right click on "Solution cavecanem" and click on build.

#### Building Cave Canem on OS X

Assuming the CMake script is in your path and the Connext DDS architecture you want to use is x64Darwin10gcc4.2.1, change to the src directory and run:

    $ cd cavecanem/src
    $ cmake -DNDDSHOME=/path/to/your/connext/installation/ndds.x.x.x -DARCHITECTURE=x64Darwin10gcc4.2.1

CMake will generate a makefile under the src directory capable of building Cave Canem and its plug-ins. To start building the application, just enter make from the src directory 

    $ make

## Running Cave Canem

The Makefiles and Visual Studio projects generated will create an executable under the src directory called _cavecanem_ or _cavecanem.exe_. They will also create shared libraries containing the different plug-ins that gather monitoring information under the _src/plugins_ directory (e.g., _src/plugins/cpu/libcpu.so_).

To run Cave Canem, just run the cavecanem executable file—it will automatically load the plug-ins it is configured to load (see _config/cavecanem.xml_ configuration file) based on their location.

On Linux and OSX run:

    $ ./cavecanem

On Windows run:

    > cavecanem.exe

