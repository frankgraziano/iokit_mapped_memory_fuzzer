//#include <stdio.h>
//OS X IOKit Mapped Memory Fuzzer
//This fuzzer found CVE-2015-1137 specifically
//By --FG
//@iamreallyfrank
//
//Notes:
//Compile:
//$llvm-gcc -o iokit_enum -framework IOKit main.c
//
//NULL PAGE exploit PoC stuff would need to be compiled differently
//This may not work anymore...
//$llvm-gcc -o iokit_enum -ggdb -m32 -Wall -pagezero_size,0 main.c


#define IOKIT                                   // to unlock device/device_types..
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFSerialize.h>
#include <IOKit/IOKitLib.h>
#include "IOKitLibPrivate.h"
#include <IOKit/IOCFPlugIn.h>
#include <sys/ioctl.h>
#include <device/device_types.h>                // for io_name, io_string
#include <mach/mach.h>                          // NULL page mapping exploit stuff
#include <mach/vm_map.h>                        // NULL page mapping exploit stuff

// from IOKit/IOKitLib.h
extern const mach_port_t kIOMasterPortDefault;

// from IOKit/IOTypes.h
typedef mach_port_t     io_object_t;
typedef io_object_t     io_connect_t;
typedef io_object_t     io_enumerator_t;
typedef io_object_t     io_iterator_t;
typedef io_object_t     io_registry_entry_t;
typedef io_object_t     io_service_t;

kern_return_t IOServiceGetMatchingServices( mach_port_t masterPort, CFDictionaryRef matching, io_iterator_t * existing );

CFMutableDictionaryRef IOServiceMatching(const char *    name );

//take in the device/service name to open via IOServiceOpen and return a handle to the device
//This is kind of redundant to some of the code in main() but it is working so....
io_connect_t open_service(char *service_name)
{
    CFMutableDictionaryRef matchingDict;
    kern_return_t kernResult;
    mach_port_t masterPort;
    io_iterator_t iter;
    io_service_t service;
    io_connect_t connect;
    int j;                                      //IOServiceOpen type
    int i;                                      //IOConnectMapMemory type
    
    kernResult = IOMasterPort(MACH_PORT_NULL, &masterPort);
    if (kernResult != KERN_SUCCESS) printf("IOMasterPort failed\n");
    
    matchingDict = IOServiceMatching(service_name);
    if (matchingDict == NULL) printf("matchingDict is NULL\n");
    
    kernResult = IOServiceGetMatchingServices(masterPort, matchingDict, &iter);
    if (kernResult != KERN_SUCCESS) printf("IOServiceGetMatchingServices failed\n");
    
    service = IOIteratorNext(iter);

    for (j=0; j <=300; j++ )
    {
        //connect 0-300 variable j
        kernResult = IOServiceOpen(service, mach_task_self(), j, &connect);
    
    if (kernResult != KERN_SUCCESS)
    {
        printf("IOServiceOpen failed %s\n", service_name);
        return -1;
    
    }
    
    else
    {
        printf("IOServiceOpen opened %s\n", service_name);
        //do stuff to our device/service...
     
/*   
        //NULL Page mapping
        vm_deallocate(mach_task_self(),0x0,0x1000);
        mach_vm_address_t boom = 0;
        vm_allocate(mach_task_self(), &boom, 0x1000,0);
        memset((void*)boom,'A',1024);
*/        
        mach_vm_address_t addr32 = 0x41414141;
        //add some fuzzy stuff here, could be interesting
        mach_vm_address_t addr64 = 0x4444444444444444;
        mach_vm_size_t size = 0x400;
        
        //IOConnectCallMethod would be fun here too

        //0-1000
        for (i=0; i <= 1000; i++)
        {
  
/*
        This is just random API stuff that you can throw at the various devices
        AAPL changes them frequently and YMMV as far as how useful they are to your efforts
*/
        printf("Fuzzing IOConnectTrap0\r\n");
        kernResult = IOConnectTrap0(connect, i);
        
        //I Think AAPL may have changed some logic here to prevent NULL ptr stuff? This was written in 2015 and shelved...
        printf("Fuzzing IOConnectMapMemory type %d:\r\n", i);
        kernResult = IOConnectMapMemory(connect, i, mach_task_self(), &addr64, &size, NULL);
        printf("Mapping 64-Bit Memory kIOCacheMask on %d at %p\r\n", connect, (void *)addr64);
        
        kernResult = IOConnectMapMemory(connect, i, mach_task_self(), &addr64, &size, kIOMapAnywhere);
        printf("Mapping 64-Bit Memory kIOCacheMask on %d at %p\r\n", connect, (void *)addr64);
            
        kernResult = IOConnectUnmapMemory(connect, i, mach_task_self(), addr64);
        printf("Un-mapping Memory on %d at %p\r\n", connect, (void *)addr64);
            
        kernResult = IOConnectUnmapMemory(connect, i, mach_task_self(), addr64);
        printf("Un-mapping Memory on %d at %p\r\n", connect, (void *)addr64);
        
        kernResult = IOConnectUnmapMemory(connect, i, mach_task_self(), addr64);
        printf("Un-mapping Memory on %d at %p\r\n", connect, (void *)addr64);
        /*
        //Example logic to skip a device if you wanted to keep fuzzing...
        if (service_name == "nvAccelerator")
        {
            printf("SKIPPING nvAccelerator");
        }
        else
        {
        */
  //      printf("%s j=%d i=%d", service_name, j, i);
  //      kernResult = IOConnectMapMemory(connect, i, mach_task_self(), &boom, &size, kIOMapAnywhere);
  //      printf("%s Mapping 32-Bit NULL Page kIOMA on %d at %p\r\n", service_name, connect, (void *)boom);
  //      }
        kernResult = IOConnectMapMemory(connect, i, mach_task_self(), &addr32, &size, kIOMapAnywhere);
        printf("%s Mapping 32-Bit Memory kIOMA on %d at %p\r\n", service_name, connect, (void *)addr32);
            
        //kernResult = IOConnectMapMemory(connect, i, mach_task_self(), &addr64, &size, kIOMapAnywhere);
        //printf("%s Mapping 64-Bit Memory on %d at %p\r\n", service_name, connect, (void *)addr64);
        
        //this method triggers the nvaccelerator bug as well connect-1
        //kernResult = IOConnectMapMemory64(connect, i, mach_task_self(), &addr64, &size, kIOMapAnywhere);
        //printf("%s Mapping 64-Bit Memory on %d at %p\r\n", service_name, connect, (void *)addr64);
        
        //kernResult = IOConnectUnmapMemory(connect, i, mach_task_self(), addr32);
        //printf("%s Un-mapping Memory on %d at %p\r\n", service_name, connect, (void *)addr32);
        
        //kernResult = IOConnectUnmapMemory64(connect, i, mach_task_self(), addr32); if (service_name != "nvAccelerator");
        //kernResult = IOConnectUnmapMemory64(connect, i, mach_task_self(), addr64); if (service_name != "nvAccelerator");
            
        //printf("%s Un-mapping Memory on %d at %p\r\n", service_name, connect, (void *)addr64);
            
        //kernResult = IOConnectMapMemory(connect, i, mach_task_self(), &addr32, &size, kIOMapDefaultCache);
        //printf("%s Mapping 32-Bit Memory kIODC on %d at %p\r\n", service_name, connect, (void *)addr32);

        //kernResult = IOConnectMapMemory(connect, i, mach_task_self(), &addr32, &size, kIOMapCopybackCache);
        //printf("%s Mapping 32-Bit Memory kIOCopybackC on %d at %p\r\n", service_name, connect, (void *)addr32);
            
        //kernResult = IOConnectMapMemory(connect, i, mach_task_self(), &addr32, &size, kIOMapInhibitCache);
        //printf("%s Mapping 32-Bit Memory kIOCopybackC on %d at %p\r\n", service_name, connect, (void *)addr32);
            
        }//i loop
    }//j loop
}//else
return connect;

}//function


//List all of the properties for a given io_service object
//The CFPropertyListCreateXMLData method is now deprecated on OSX 10.10 but for now it still works
void listProps(io_service_t	Service)
{
        CFMutableDictionaryRef propertiesDict;
    
        kern_return_t kr = IORegistryEntryCreateCFProperties( Service,
                                                             &propertiesDict,
                                                             kCFAllocatorDefault,
                                                             kNilOptions );
        CFDataRef xml = CFPropertyListCreateXMLData(kCFAllocatorDefault,
                                                    (CFPropertyListRef)propertiesDict);
        if (xml) {
            write(1, CFDataGetBytePtr(xml), CFDataGetLength(xml));
            CFRelease(xml);
        }
        
        printf ("KR: %d\n", kr);
}

int main(int argc, char **argv)
{
    io_connect_t  connect;
    io_iterator_t deviceList;
    io_service_t  device;
    io_name_t     deviceName;
    io_string_t   devicePath;
    char	 *ioPlaneName = "IOService";
    int 	  dev = 0;
    
    kern_return_t kr;
    
    if (argv[1]) ioPlaneName = argv[1];
    printf("So far..\n");
    
    // Iterate over all services matching user provided class.
    // Note the call to IOServiceMatching, to create the dictionary
    
    kr = IOServiceGetMatchingServices(kIOMasterPortDefault,
                                      IOServiceMatching("IOService"),
                                      &deviceList);
    if (kr)
    {
        fprintf(stderr,"IOServiceGetMatchingServices: error\n");
        exit(1);
    }
    if (!deviceList) {  fprintf(stderr,"No devices matched\n"); exit(2); }
    
    printf("So far..\n");
    while ( IOIteratorIsValid(deviceList) &&
           (device = IOIteratorNext(deviceList))) {
        
        kr = IORegistryEntryGetName(device, deviceName);
        if (kr)
        {
            fprintf (stderr,"Error getting name for device\n");
            IOObjectRelease(device);
            continue;
        }
        
        kr = IORegistryEntryGetPath(device, ioPlaneName, devicePath);
        
        if (kr) {
            // Device does not exist on this plane
            IOObjectRelease(device);
            continue;
        }
        
        
        dev++;
        printf("%s\t%s\n",deviceName, devicePath);

    //CHANGE ME BASED ON WHAT YOU WANT TO ACCOMPLISH
	//Enumeration/Information
        //Call to list our properties
        //listProps(device);
        
	//Actual Fuzzing
        //Call to open a connection to our device/service
        connect = open_service(deviceName);
    }
    
    if (device) {
        fprintf (stderr,
                 "The Iterator failed. Did hardware configuration change?\n");
    }
    return kr;
}
