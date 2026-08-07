/**
 * Nexsiz Frida Coverage Agent
 * Author  : Revana / Nexsiz Toolsmith
 * Date    : 05/08/2026
 *
 * Writes AFL-style edge coverage into a POSIX shared-memory region that
 * Nexsiz's SharedMapCoverage provider reads each execution.
 *
 * SHM layout:
 *   name : /nexsiz-cov  or  /nexsiz-cov-<id>  (from NEXSIZ_SHM_ID)
 *   size : 65536 bytes
 *   cell : saturating hit count (u8)
 *
 * Edge index:  (prev_loc >> 1) ^ cur_loc   (AFL classic)
 *
 * Usage:
 *   # Terminal A – start target under Frida
 *   export NEXSIZ_SHM_ID=ftp1
 *   frida -l agents/frida/nexsiz_cov.js -f /path/to/target --no-pause
 *
 *   # Terminal B – run Nexsiz against the same target
 *   export NEXSIZ_SHM_ID=ftp1
 *   ./target/release/nexsiz -h 127.0.0.1 -p 21 -m ftp -C map --shm ftp1 -v
 *
 * Optional env:
 *   NEXSIZ_SHM_ID     – SHM suffix / full name
 *   NEXSIZ_COV_MODULE – limit Stalker to this module name (substring match)
 *   NEXSIZ_COV_MODE   – "stalker" (default) | "exports" (lighter Interceptor)
 */

'use strict';

const MAP_SIZE = 65536;

function shmName() {
  const id = Process.getEnv('NEXSIZ_SHM_ID') || '';
  if (!id) return '/nexsiz-cov';
  if (id.charAt(0) === '/') return id;
  return '/nexsiz-cov-' + id;
}

function openCoverageMap() {
  const name = shmName();
  const libc = Process.getModuleByName('libc.so') || Process.getModuleByName('libc.so.6');
  if (!libc) {
    console.error('[nexsiz-cov] libc not found');
    return null;
  }

  const shm_open = new NativeFunction(
    Module.findExportByName(libc.name, 'shm_open'),
    'int', ['pointer', 'int', 'int']
  );
  const ftruncate = new NativeFunction(
    Module.findExportByName(libc.name, 'ftruncate'),
    'int', ['int', 'long']
  );
  const mmap = new NativeFunction(
    Module.findExportByName(libc.name, 'mmap'),
    'pointer', ['pointer', 'ulong', 'int', 'int', 'int', 'long']
  );
  const closeFn = new NativeFunction(
    Module.findExportByName(libc.name, 'close'),
    'int', ['int']
  );

  const O_RDWR = 0x2;
  const O_CREAT = 0x40;
  const PROT_READ = 0x1;
  const PROT_WRITE = 0x2;
  const MAP_SHARED = 0x1;
  const MAP_FAILED = ptr(-1);

  const nameBuf = Memory.allocUtf8String(name);
  let fd = shm_open(nameBuf, O_RDWR, 0o600);
  if (fd < 0) {
    fd = shm_open(nameBuf, O_RDWR | O_CREAT, 0o600);
    if (fd < 0) {
      console.error('[nexsiz-cov] shm_open failed for ' + name);
      return null;
    }
    ftruncate(fd, MAP_SIZE);
  }

  const mapPtr = mmap(ptr(0), MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mapPtr.equals(MAP_FAILED)) {
    console.error('[nexsiz-cov] mmap failed');
    closeFn(fd);
    return null;
  }

  // Keep fd open for the lifetime of the process (map stays valid).
  console.log('[nexsiz-cov] SHM attached: ' + name + ' @ ' + mapPtr);
  return mapPtr;
}

function hitEdge(mapPtr, prev, cur) {
  // AFL-style edge: (prev >> 1) ^ cur
  const idx = ((prev >>> 1) ^ cur) & (MAP_SIZE - 1);
  const p = mapPtr.add(idx);
  const v = p.readU8();
  if (v < 255) p.writeU8(v + 1);
}

function startStalker(mapPtr) {
  const filterMod = Process.getEnv('NEXSIZ_COV_MODULE') || '';
  let prevLoc = 0;

  const threads = Process.enumerateThreads();
  threads.forEach(function (t) {
    try {
      Stalker.follow(t.id, {
        events: { call: false, ret: false, exec: false, block: true, compile: false },
        onReceive: function (events) {
          // unused — we use transform for inline hits
        },
        transform: function (iterator) {
          let instruction = iterator.next();
          const startAddr = instruction.address;

          // Optional module filter
          if (filterMod) {
            const m = Process.findModuleByAddress(startAddr);
            if (!m || m.name.indexOf(filterMod) === -1) {
              do {
                iterator.keep();
              } while ((instruction = iterator.next()) !== null);
              return;
            }
          }

          // Insert coverage probe at block start
          iterator.putCallout(function (context) {
            // Use low bits of PC as location id
            const cur = startAddr.toInt32() >>> 0;
            hitEdge(mapPtr, prevLoc, cur);
            prevLoc = cur;
          });

          do {
            iterator.keep();
          } while ((instruction = iterator.next()) !== null);
        }
      });
    } catch (e) {
      // Some threads cannot be followed
    }
  });

  console.log('[nexsiz-cov] Stalker attached to ' + threads.length + ' thread(s)' +
    (filterMod ? ' (module filter: ' + filterMod + ')' : ''));
}

function startExportsMode(mapPtr) {
  // Lighter alternative: intercept a set of interesting functions and
  // treat each call site as an edge. Good for protocol parsers.
  const names = [
    'recv', 'recvfrom', 'read', 'write', 'send', 'sendto',
    'parse', 'process', 'handle', 'dispatch'
  ];
  let prev = 0;
  let hooked = 0;

  Process.enumerateModules().forEach(function (mod) {
    if (mod.name.indexOf('linux-vdso') !== -1) return;
    mod.enumerateExports().forEach(function (exp) {
      if (exp.type !== 'function') return;
      const lower = exp.name.toLowerCase();
      let match = false;
      for (let i = 0; i < names.length; i++) {
        if (lower.indexOf(names[i]) !== -1) { match = true; break; }
      }
      if (!match) return;
      try {
        Interceptor.attach(exp.address, {
          onEnter: function () {
            const cur = exp.address.toInt32() >>> 0;
            hitEdge(mapPtr, prev, cur);
            prev = cur;
          }
        });
        hooked++;
      } catch (e) {}
    });
  });
  console.log('[nexsiz-cov] exports mode: hooked ' + hooked + ' functions');
}

function main() {
  const mapPtr = openCoverageMap();
  if (!mapPtr) return;

  const mode = (Process.getEnv('NEXSIZ_COV_MODE') || 'stalker').toLowerCase();
  if (mode === 'exports') {
    startExportsMode(mapPtr);
  } else {
    startStalker(mapPtr);
  }

  console.log('[nexsiz-cov] agent ready — Nexsiz can now collect grey-box edges');
}

setImmediate(main);
