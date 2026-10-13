#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>

static void print_cf_string(const char *label, CFTypeRef value) {
    if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) {
        printf("%s=<none>\n", label);
        return;
    }

    char buffer[1024];
    if (!CFStringGetCString((CFStringRef)value, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
        printf("%s=<unprintable>\n", label);
        return;
    }
    printf("%s=%s\n", label, buffer);
}

int main(void) {
    io_service_t platform = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching("IOPlatformExpertDevice")
    );
    CFTypeRef platform_serial = NULL;
    if (platform != IO_OBJECT_NULL) {
        platform_serial = IORegistryEntryCreateCFProperty(
            platform,
            CFSTR("IOPlatformSerialNumber"),
            kCFAllocatorDefault,
            0
        );
    }
    print_cf_string("platform_serial", platform_serial);

    DASessionRef session = DASessionCreate(kCFAllocatorDefault);
    CFURLRef root_url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault,
        (const UInt8 *)"/",
        1,
        true
    );
    DADiskRef disk = session && root_url
        ? DADiskCreateFromVolumePath(kCFAllocatorDefault, session, root_url)
        : NULL;
    io_registry_entry_t media = disk ? DADiskCopyIOMedia(disk) : IO_OBJECT_NULL;
    CFTypeRef disk_serial = media != IO_OBJECT_NULL
        ? IORegistryEntrySearchCFProperty(
              media,
              kIOServicePlane,
              CFSTR("Serial Number"),
              kCFAllocatorDefault,
              kIORegistryIterateRecursively | kIORegistryIterateParents
          )
        : NULL;
    print_cf_string("disk_serial", disk_serial);

    if (disk_serial) CFRelease(disk_serial);
    if (media != IO_OBJECT_NULL) IOObjectRelease(media);
    if (disk) CFRelease(disk);
    if (root_url) CFRelease(root_url);
    if (session) CFRelease(session);
    if (platform_serial) CFRelease(platform_serial);
    if (platform != IO_OBJECT_NULL) IOObjectRelease(platform);
    return 0;
}
