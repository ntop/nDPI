# How to use？

You need to first compile the nDPI library as usual:

- ./autogen.sh
- ./configure
- make

Then open the Xcode project and you are ready to go. The default behavior is to analyze an embeded pcap file `capture.pcap`. You can change the behavior by changing command line input in `ViewController.m` file.

# What does the XCode project do?

It's a dummy Mac App project with a **Run** button. It doesn't modify any nDPI code except that it renamed the `main` function to `orginal_main` in `ndpiReader.c` (because the Mac App has it's own main function) and call the `orginal_main` with synthetic command line input from `ViewController.m` file when the **Run** button is clicked. 

It also fixes some problems when compiling with Xcode. Some are listed below:
- Add missed `NDPI_LOG_DEBUG2` macro definition implementation (defined as `NDPI_LOG_DEBUG2_XCODE_PROJ` in `ViewController.m`)
- Add an empty ndpi_utils.h file to make `protocols/attic/ftp.c` and `protocols/attic/secondlife.c` can compile
- Specially treat `ndpi_patricia.c` by not adding it into compilation source, since it's directly included in `ndpi_main.c`
