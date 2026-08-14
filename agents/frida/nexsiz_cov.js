/**
 * Nexsiz Frida Coverage Agent (cross-platform)
 * Author  : Revana / Nexsiz Toolsmith
 * Date    : 14/08/2026
 *
 * Writes AFL-style edge coverage into a platform shared-memory region that
 * Nexsiz's SharedMapCoverage provider reads each execution.
 *
 * Transport:
 *   Linux:   POSIX SHM   → /nexsiz-cov  or  /nexsiz-cov-<id>
 *   Windows: File Mapping → Local\nexsiz-cov  or  Local\nexsiz-cov-<id>
 *
 * Layout (identical on both):
 *   size : 65536 bytes
 *   cell : saturating hit count (u8)
 *   edge : (prev_loc >> 1) ^ cur_loc   (AFL classic)
 *
 * Usage (Linux):
 *   export NEXSIZ_SHM_ID=ftp1
 *   frida -l agents/frida/nexsiz_cov.js -f /path/to/target --no-pause
 *   ./target/release/nexsiz -h 127.0.0.1 -p 21 -m ftp -C map --shm ftp1 -v
 *
 * Usage (Windows):
 *   $env:NEXSIZ_SHM_ID = "ftp1"
 *   frida -l agents/frida/nexsiz_cov.js -f .\target.exe
 *   .\target\release\nexsiz.exe -h 127.0.0.1 -p 21 -m ftp -C map --shm ftp1 -v
 *
 * Optional env:
 *   NEXSIZ_SHM_ID     – SHM suffix / full name
 *   NEXSIZ_COV_MODULE – limit Stalker to this module name (substring match)
 *   NEXSIZ_COV_MODE   – "stalker" (default) | "exports" (lighter Interceptor)
 */

'use strict';

const MAP_SIZE = 65536;

function isWindows() {
  // Frida: Process.platform is 'windows' | 'linux' | 'darwin' | …
  return Process.platform === 'windows';
}

function shmName() {
  const id = Process.getEnv('NEXSIZ_SHM_ID') || '';
  if (isWindows()) {
    if (!id) return 'Local\\nexsiz-cov';
    // Already a full object name?
    if (id.indexOf('Local\\') === 0 || id.indexOf('Global\\') === 0) return id;
    // Strip POSIX-style leading slash if the operator reused a Linux id
    const cleaned = id.replace(/^[/\\]+/, '');
    if (cleaned.indexOf('nexsiz-cov') === 0) return 'Local\\' + cleaned;
    return 'Local\\nexsiz-cov-' + cleaned;
  }
  // Linux / POSIX
  if (!id) return '/nexsiz-cov';
  if (id.charAt(0) === '/') return id;
  return '/nexsiz-cov-' + id;
}

// ---------------------------------------------------------------------------
// Linux: POSIX shared memory
// ---------------------------------------------------------------------------

function openCoverageMapLinux() {
  const name = shmName();
  const libc =
    Process.findModuleByName('libc.so.6') ||
    Process.findModuleByName('libc.so') ||
    Process.findModuleByName('libc.so.7');
  if (!libc) {
    console.error('[nexsiz-cov] libc not found');
    return null;
  }

  const shm_open = new NativeFunction(
    Module.findExportByName(libc.name, 'shm_open'),
    'int',
    ['pointer', 'int', 'int']
  );
  const ftruncate = new NativeFunction(
    Module.findExportByName(libc.name, 'ftruncate'),
    'int',
    ['int', 'long']
  );
  const mmap = new NativeFunction(
    Module.findExportByName(libc.name, 'mmap'),
    'pointer',
    ['pointer', 'ulong', 'int', 'int', 'int', 'long']
  );
  const closeFn = new NativeFunction(
    Module.findExportByName(libc.name, 'close'),
    'int',
    ['int']
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

  console.log('[nexsiz-cov] SHM attached (Linux): ' + name + ' @ ' + mapPtr);
  return mapPtr;
}

// ---------------------------------------------------------------------------
// Windows: named File Mapping (kernel32)
// ---------------------------------------------------------------------------

function openCoverageMapWindows() {
  const name = shmName();

  const k32 = Process.findModuleByName('kernel32.dll');
  if (!k32) {
    console.error('[nexsiz-cov] kernel32.dll not found');
    return null;
  }

  const OpenFileMappingW = new NativeFunction(
    Module.findExportByName('kernel32.dll', 'OpenFileMappingW'),
    'pointer',
    ['uint32', 'int', 'pointer']
  );
  const CreateFileMappingW = new NativeFunction(
    Module.findExportByName('kernel32.dll', 'CreateFileMappingW'),
    'pointer',
    ['pointer', 'pointer', 'uint32', 'uint32', 'uint32', 'pointer']
  );
  const MapViewOfFile = new NativeFunction(
    Module.findExportByName('kernel32.dll', 'MapViewOfFile'),
    'pointer',
    ['pointer', 'uint32', 'uint32', 'uint32', 'ulong']
  );
  const GetLastError = new NativeFunction(
    Module.findExportByName('kernel32.dll', 'GetLastError'),
    'uint32',
    []
  );

  const FILE_MAP_ALL_ACCESS = 0x000f001f;
  const PAGE_READWRITE = 0x04;
  const INVALID_HANDLE_VALUE = ptr(-1);

  const nameBuf = Memory.allocUtf16String(name);

  // Prefer attach to an existing mapping created by Nexsiz.
  let handle = OpenFileMappingW(FILE_MAP_ALL_ACCESS, 0, nameBuf);
  if (handle.isNull()) {
    // Create pagefile-backed mapping if Nexsiz has not started yet.
    handle = CreateFileMappingW(
      INVALID_HANDLE_VALUE,
      ptr(0),
      PAGE_READWRITE,
      0,
      MAP_SIZE,
      nameBuf
    );
    if (handle.isNull()) {
      console.error(
        '[nexsiz-cov] CreateFileMappingW failed for ' +
          name +
          ' err=' +
          GetLastError()
      );
      return null;
    }
  }

  const mapPtr = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, MAP_SIZE);
  if (mapPtr.isNull()) {
    console.error(
      '[nexsiz-cov] MapViewOfFile failed for ' + name + ' err=' + GetLastError()
    );
    return null;
  }

  // Keep the mapping handle open for the process lifetime.
  console.log('[nexsiz-cov] SHM attached (Windows): ' + name + ' @ ' + mapPtr);
  return mapPtr;
}

function openCoverageMap() {
  if (isWindows()) {
    return openCoverageMapWindows();
  }
  return openCoverageMapLinux();
}

// ---------------------------------------------------------------------------
// Coverage instrumentation (platform-agnostic)
// ---------------------------------------------------------------------------

function hitEdge(mapPtr, prev, cur) {
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
        onReceive: function (/* events */) {},
        transform: function (iterator) {
          let instruction = iterator.next();
          const startAddr = instruction.address;

          if (filterMod) {
            const m = Process.findModuleByAddress(startAddr);
            if (!m || m.name.indexOf(filterMod) === -1) {
              do {
                iterator.keep();
              } while ((instruction = iterator.next()) !== null);
              return;
            }
          }

          iterator.putCallout(function (/* context */) {
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

  console.log(
    '[nexsiz-cov] Stalker attached to ' +
      threads.length +
      ' thread(s)' +
      (filterMod ? ' (module filter: ' + filterMod + ')' : '')
  );
}

function startExportsMode(mapPtr) {
  const names = [
    'recv', 'recvfrom', 'read', 'write', 'send', 'sendto',
    'WSARecv', 'WSASend', 'WSARecvFrom', 'WSASendTo',
    'parse', 'process', 'handle', 'dispatch'
  ];
  let prev = 0;
  let hooked = 0;

  Process.enumerateModules().forEach(function (mod) {
    // Skip obvious system noise
    const skip =
      mod.name.indexOf('linux-vdso') !== -1 ||
      mod.name.toLowerCase() === 'ntdll.dll' ||
      mod.name.toLowerCase() === 'kernel32.dll' ||
      mod.name.toLowerCase() === 'kernelbase.dll';
    if (skip) return;

    mod.enumerateExports().forEach(function (exp) {
      if (exp.type !== 'function') return;
      const lower = exp.name.toLowerCase();
      let match = false;
      for (let i = 0; i < names.length; i++) {
        if (lower.indexOf(names[i].toLowerCase()) !== -1) {
          match = true;
          break;
        }
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

  console.log(
    '[nexsiz-cov] agent ready on ' +
      Process.platform +
      ' — Nexsiz can now collect grey-box edges'
  );
}

setImmediate(main);
