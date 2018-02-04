/*
 *
 * Copyright (C) 2011-18 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#import "ViewController.h"
#include "ndpi_api.h"

// Declare the orginal_main defined in ndpiReader.c here
extern int orginal_main(int argc, char **argv);

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    // Do any additional setup after loading the view.
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}


- (IBAction)onRunButtonClicked:(id)sender
{
    char* args[10];
    
    extern int optind;
    optind = 1; // reset the parse of getopt_long
    
    // Check the "nDPI_QuickStartGuide.pdf" for comand option explanation.
    
    /* Following code it to execute below command (remember to change args[2] to
    *  absolute path):
    *  ./ndpiReader -i capture.pcap
    */
    args[0] = (char*)"ndpiReader";
    args[1] = (char*)"-i";
    NSString* pcap_file = [[NSBundle mainBundle]pathForResource:@"capture" ofType:@"pcap"];
    args[2] = (char*)[pcap_file cStringUsingEncoding:NSUTF8StringEncoding];
    // Change to you pcap file path if you want.
    //args[2] = (char*)"/Users/zengyingpei/Documents/code/nDPI/example/MacOS/ndpiExample/ndpiExample/capture.pcap";
    // Remember to change below number of args when you change to other command inputs.
    orginal_main(3, args);
    
    
    
    /* Following code it to execute below command:
    *  ./ndpiReader -i en1 -s 10 -p protos.txt
    *  The process seems to be not support re-entering. You may have to re-run the App.
    */
    /*
    args[0] = (char*)"ndpiReader";
    args[1] = (char*)"-i";
    args[2] = (char*)"en0";
    args[3] = (char*)"-s";
    args[4] = (char*)"10";
    args[5] = (char*)"-p";
    NSString* proto_file = [[NSBundle mainBundle]pathForResource:@"protos" ofType:@"txt"];
    args[6] = (char*)[proto_file cStringUsingEncoding:NSUTF8StringEncoding];
    //args[6] = (char*)"/Users/zengyingpei/Documents/code/nDPI/example/protos.txt";
    orginal_main(7, args);
     */
}


// In order to fix the missing of NDPI_LOG_DEBUG2 (used in ndpi_main.c), we define
// NDPI_LOG_DEBUG2 as NDPI_LOG_DEBUG2_XCODE_PROJ.

void vNDPI_LOG_DEBUG2_XCODE_PROJ(struct ndpi_detection_module_struct * ndpi_struct,
                                 const char *format, va_list ap)
{
    vprintf(format, ap);
}

void NDPI_LOG_DEBUG2_XCODE_PROJ(struct ndpi_detection_module_struct * ndpi_struct,
                                const char *format, ...)
{
    va_list ap;
    va_start (ap, format);
    vNDPI_LOG_DEBUG2_XCODE_PROJ(ndpi_struct, format, ap);
    va_end (ap);
}

@end
