'use strict';

/* =========================
 *      공통/설정/유틸
 * ========================= */

/* 설정(토글/상태) */
let state = {
  mode: "auto",        // "auto"=차단 기본, "free"=전부 허용
  back: "block",       // "block" | "free"
  finish: "block",     // "block" | "free"
  uiforce: false,      // 버튼 setEnabled/Clickable 강제 true
  navblock: false,     // 전체 startActivity 차단
  scanblock: false,    // 검사화면 이동만 차단
  navfilter: "ScanActivity", // 검사 화면 클래스 키워드

  // 보강 옵션
  dumpdir: null,       // 기본 null -> 앱 내부 files 디렉터리 사용
  sanitize: false,     // true면 key_hex/iv_hex 마스킹
  sampleEvery: 1,      // N회 중 1회만 jlog
  ratelimitMs: 0,      // 최소 로그 간격(ms), 0이면 미사용
  hookUpdate: false    // Cipher.update 훅 활성화 여부(기본 off)
};

function shouldBlock(kind) {
  const v = state[kind];
  if (v === "block") return true;
  if (v === "free") return false;
  return (state.mode !== "free");
}

/* 로그/도우미 */
let __lastLogTs = 0, __logCount = 0;

function jlog(obj) {
  try {
    // 샘플링
    if (state.sampleEvery > 1) {
      __logCount = (__logCount + 1) % state.sampleEvery;
      if (__logCount !== 0) return;
    }
    // 레이트 리밋
    const now = Date.now();
    if (state.ratelimitMs > 0 && (now - __lastLogTs) < state.ratelimitMs) return;
    __lastLogTs = now;

    obj.time = new Date(now).toISOString();
    send(obj);
    // 필요 시 호스트 콘솔로도 출력 원하면 주석 해제
    // console.log(JSON.stringify(obj));
  } catch (e) {}
}

function toHex(b) {
  try {
    const n = b.length | 0; const s = [];
    for (let i = 0; i < n; i++) {
      let v = (b[i] & 0xff).toString(16);
      if (v.length < 2) v = '0' + v;
      s.push(v);
    }
    return s.join('');
  } catch (e) { return "" + e; }
}

function _mask(hex, keep = 4) {
  if (!hex) return "";
  const n = hex.length;
  return (n > keep * 2) ? (hex.slice(0, keep) + "..." + hex.slice(-keep)) : hex;
}

/* 앱 내부 files 디렉터리 경로 */
function appFilesDir() {
  try {
    const AT = Java.use('android.app.ActivityThread');
    const ctx = AT.currentApplication().getApplicationContext();
    return String(ctx.getFilesDir().getAbsolutePath());
  } catch (e) { return "/data/local/tmp"; }
}

/* =========================
 *         메인 훅
 * ========================= */
Java.perform(function () {

  /* ---------- 종료/뒤로가기 제어 ---------- */
  try {
    const Activity = Java.use('android.app.Activity');

    Activity.finish.overloads.forEach(function (ovl) {
      ovl.implementation = function () {
        const b = shouldBlock("finish");
        jlog({ type: "event", sub: "finish()", blocked: b, activity: this.getClass().getName() });
        if (b) return;
        return ovl.apply(this, arguments);
      };
    });

    if (Activity.onBackPressed) {
      Activity.onBackPressed.overloads.forEach(function (ovl) {
        ovl.implementation = function () {
          const b = shouldBlock("back");
          jlog({ type: "event", sub: "back()", blocked: b, activity: this.getClass().getName() });
          if (b) return;
          return ovl.apply(this, arguments);
        };
      });
    }

    try {
      Activity.finishAffinity.overloads.forEach(function (ovl) {
        ovl.implementation = function () {
          const b = shouldBlock("finish");
          jlog({ type: "event", sub: "finishAffinity()", blocked: b, activity: this.getClass().getName() });
          if (b) return;
          return ovl.apply(this, arguments);
        };
      });
    } catch (_) { }

    try {
      Activity.finishAfterTransition.overloads.forEach(function (ovl) {
        ovl.implementation = function () {
          const b = shouldBlock("finish");
          jlog({ type: "event", sub: "finishAfterTransition()", blocked: b, activity: this.getClass().getName() });
          if (b) return;
          return ovl.apply(this, arguments);
        };
      });
    } catch (_) { }

    try {
      Activity.moveTaskToBack.overload('boolean').implementation = function (nonRoot) {
        const b = shouldBlock("back");
        jlog({ type: "event", sub: "moveTaskToBack(" + nonRoot + ")", blocked: b, activity: this.getClass().getName() });
        if (b) return true;
        return this.moveTaskToBack(nonRoot);
      };
    } catch (_) { }

  } catch (e) { jlog({ type: "warn", sub: "Activity hooks failed", error: String(e) }); }

  /* ---------- 프로세스 종료 경로 ---------- */
  try {
    const Proc = Java.use('android.os.Process');
    Proc.killProcess.implementation = function (pid) {
      const block = (state.mode !== "free");
      jlog({ type: "event", sub: "killProcess", pid: pid, blocked: block });
      if (block) return;
      return this.killProcess.call(this, pid);
    };
  } catch (e) { jlog({ type: "warn", sub: "killProcess hook failed", error: String(e) }); }

  try {
    const System = Java.use('java.lang.System');
    System.exit.overload('int').implementation = function (code) {
      const block = (state.mode !== "free");
      jlog({ type: "event", sub: "System.exit", code: code, blocked: block });
      if (block) return;
      return this.exit(code);
    };
  } catch (e) { jlog({ type: "warn", sub: "System.exit hook failed", error: String(e) }); }

  /* ---------- UI 강제 활성화 ---------- */
  try {
    const View = Java.use('android.view.View');
    View.setEnabled.overload('boolean').implementation = function (b) {
      const nb = state.uiforce ? true : b;
      jlog({ type: "ui", sub: "setEnabled", view: this.getClass().getName(), from: b, to: nb });
      return View.setEnabled.call(this, nb);
    };
    View.setClickable.overload('boolean').implementation = function (b) {
      const nb = state.uiforce ? true : b;
      jlog({ type: "ui", sub: "setClickable", view: this.getClass().getName(), from: b, to: nb });
      return View.setClickable.call(this, nb);
    };
  } catch (e) { jlog({ type: "warn", sub: "UI hooks failed", error: String(e) }); }

  /* ---------- 내비게이션(검사 화면 이동) 제어 ---------- */
  try {
    const Activity = Java.use('android.app.Activity');

    function targetName(intent) {
      try { const c = intent.getComponent(); if (c) return "" + c.getClassName(); } catch (_) { }
      try { const a = intent.getAction(); if (a) return "" + a; } catch (_) { }
      return "";
    }

    function wrapStart(ovl) {
      return function () {
        const intent = arguments[0];
        const tgt = targetName(intent);
        let block = false;
        if (state.navblock) block = true;
        if (state.scanblock && tgt.indexOf(state.navfilter) >= 0) block = true;
        jlog({ type: "nav", sub: ovl.methodName || "start", target: tgt, blocked: block });
        if (block) return;
        return ovl.apply(this, arguments);
      };
    }

    Activity.startActivity.overloads.forEach(function (ovl) { ovl.implementation = wrapStart(ovl); });
    Activity.startActivityForResult.overloads.forEach(function (ovl) { ovl.implementation = wrapStart(ovl); });
  } catch (e) { jlog({ type: "warn", sub: "startActivity hooks failed", error: String(e) }); }

  /* ---------- Crypto 로깅 (암/복 라운드트립 증빙) ---------- */
  try {
    const Cipher = Java.use('javax.crypto.Cipher');

    // WeakMap 폴백 (비 v8 런타임)
    let Meta;
    try { Meta = new WeakMap(); } catch (_) { Meta = new Map(); }

    const G = { cid: 0 };
    function opmodeToStr(m) {
      switch (m) {
        case 1: return "ENCRYPT";
        case 2: return "DECRYPT";
        case 3: return "WRAP";
        case 4: return "UNWRAP";
        default: return "UNKNOWN(" + m + ")";
      }
    }

    function dumpToFile(bin, label) {
      try {
        if (!bin) return null;
        const Arrays = Java.use('java.util.Arrays');
        const cap = Math.min(bin.length, 65536); // 64 KiB cap
        const slice = Arrays.copyOf(bin, cap);
        const FileOutputStream = Java.use('java.io.FileOutputStream');
        const base = state.dumpdir || appFilesDir();
        const path = base + "/" + label + "-" + Date.now() + ".bin";
        const fos = FileOutputStream.$new(path); fos.write(slice); fos.close();
        jlog({ type: "cryptodump", sub: label, path: path, size: slice.length });
        return path;
      } catch (e) { jlog({ type: "error", sub: "cryptodump-failed", error: String(e) }); return null; }
    }

    // init(*) — 키/IV/모드/알고리즘 + 인스턴스 ID 저장
    Cipher.init.overloads.forEach(function (ovl) {
      ovl.implementation = function () {
        const opm = arguments[0], key = arguments[1];
        let alg = this.getAlgorithm(); let kenc = ""; let iv = ""; let tlen = null; let ptype = null;

        try {
          const kb = key.getEncoded();
          if (kb) kenc = toHex(kb);
        } catch (_) {}

        if (arguments.length >= 3) {
          const p = arguments[2];
          if (p && p.$className) {
            ptype = p.$className;
            try {
              if (ptype === "javax.crypto.spec.IvParameterSpec") { iv = toHex(p.getIV()); }
              else if (ptype === "javax.crypto.spec.GCMParameterSpec") { iv = toHex(p.getIV()); tlen = p.getTLen(); } // tlen in bits
            } catch (_) {}
          }
        }

        if (kenc && state.sanitize) kenc = _mask(kenc);
        if (iv && state.sanitize) iv = _mask(iv);

        let rec = Meta.get(this);
        if (!rec) { rec = { id: ++G.cid, opm: opm, alg: alg }; Meta.set(this, rec); }
        else { rec.opm = opm; rec.alg = alg; }

        jlog({ type: "crypto", sub: "init", id: rec.id, opmode: opmodeToStr(opm), algo: alg, key_hex: kenc, iv_hex: iv, tlen_bits: tlen, params: ptype });
        return ovl.apply(this, arguments);
      };
    });

    // doFinal([B)
    if (Cipher.doFinal && Cipher.doFinal.overload && Cipher.doFinal.overload('[B')) {
      Cipher.doFinal.overload('[B').implementation = function (b) {
        const rec = Meta.get(this) || { id: -1, opm: 0, alg: this.getAlgorithm() };
        const phase = opmodeToStr(rec.opm);
        const in_path = dumpToFile(b, "crypto-in-" + phase);
        const ret = this.doFinal(b);
        const out_path = dumpToFile(ret, "crypto-out-" + phase);
        jlog({ type: "crypto", sub: "doFinal([B)", id: rec.id, phase: phase, algo: rec.alg, in_len: b ? b.length : -1, out_len: ret ? ret.length : -1, in_path: in_path, out_path: out_path });
        return ret;
      };
    }

    // doFinal([B,int,int)
    if (Cipher.doFinal && Cipher.doFinal.overload && Cipher.doFinal.overload('[B', 'int', 'int')) {
      Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (b, o, l) {
        const rec = Meta.get(this) || { id: -1, opm: 0, alg: this.getAlgorithm() };
        const phase = opmodeToStr(rec.opm);
        const Arrays = Java.use('java.util.Arrays');
        const in_slice = (b && l > 0) ? Arrays.copyOfRange(b, o, o + l) : null;
        const in_path = dumpToFile(in_slice, "crypto-in-" + phase);
        const ret = this.doFinal(b, o, l);
        const out_path = dumpToFile(ret, "crypto-out-" + phase);
        jlog({ type: "crypto", sub: "doFinal([B,int,int)", id: rec.id, phase: phase, algo: rec.alg, in_len: l, out_len: ret ? ret.length : -1, in_path: in_path, out_path: out_path });
        return ret;
      };
    }

    // (선택) Cipher.update 훅
    if (state.hookUpdate) {
      try {
        if (Cipher.update && Cipher.update.overload && Cipher.update.overload('[B')) {
          Cipher.update.overload('[B').implementation = function (b) {
            const rec = Meta.get(this) || { id: -1, opm: 0, alg: this.getAlgorithm() };
            const phase = opmodeToStr(rec.opm);
            const in_path = dumpToFile(b, "crypto-upd-in-" + phase);
            const ret = this.update(b);
            const out_path = dumpToFile(ret, "crypto-upd-out-" + phase);
            jlog({ type: "crypto", sub: "update([B)", id: rec.id, phase: phase, algo: rec.alg, in_len: b ? b.length : -1, out_len: ret ? ret.length : -1, in_path: in_path, out_path: out_path });
            return ret;
          };
        }
      } catch (e) { jlog({ type: "warn", sub: "Cipher.update hook failed", error: String(e) }); }
    }

  } catch (e) { jlog({ type: "warn", sub: "Cipher hooks failed", error: String(e) }); }

  /* ---------- DEX 감시 & 덤프 ---------- */
  function dumpDex(byteArray, tag) {
    try {
      const Arrays = Java.use('java.util.Arrays');
      const max = Math.min(byteArray.length, 10 * 1024 * 1024); // 10MB cap
      const bytes = Arrays.copyOf(byteArray, max);
      // 간단 매직 확인
      const headHex = toHex(bytes).slice(0, 16);
      const looksDex = headHex.indexOf("6465780a") === 0; // "dex\n"
      const FileOutputStream = Java.use('java.io.FileOutputStream');
      const base = state.dumpdir || appFilesDir();
      const path = base + "/dump-" + tag + "-" + Date.now() + (looksDex ? ".dex" : ".bin");
      const fos = FileOutputStream.$new(path); fos.write(bytes); fos.close();
      jlog({ type: "dexdump", sub: "dump", path: path, size: bytes.length, looksDex: looksDex });
    } catch (e) { jlog({ type: "error", sub: "dump-failed", error: String(e) }); }
  }

  try {
    const IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
    IMDCL.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader').implementation = function (buffers, ldr) {
      for (let i = 0; i < buffers.length; i++) {
        try {
          let arr = null;
          try { arr = buffers[i].array(); }
          catch (e) {
            const cap = buffers[i].remaining();
            const BA = Java.use('[B'); const tmp = BA.$new(cap); buffers[i].get(tmp); arr = tmp;
          }
          dumpDex(Java.array('byte', arr), "IMDCL" + i);
        } catch (_) { }
      }
      jlog({ type: "dex", sub: "InMemoryDexClassLoader.init", count: buffers.length });
      return this.$init(buffers, ldr);
    };
  } catch (e) { jlog({ type: "warn", sub: "IMDCL hook failed", error: String(e) }); }

  try {
    const BDL = Java.use('dalvik.system.BaseDexClassLoader');
    BDL.$init.overload('java.lang.String', 'java.io.File', 'java.lang.String', 'java.lang.ClassLoader').implementation = function (a, b, c, d) {
      jlog({ type: "dex", sub: "BaseDexClassLoader.init", apk: a, lib: c });
      return this.$init(a, b, c, d);
    };
  } catch (e) { jlog({ type: "warn", sub: "BDL hook failed", error: String(e) }); }

});

/* =========================
 *           RPC
 * ========================= */
rpc.exports = {
  // 기본 토글
  mode: function (m) { state.mode = m; jlog({ type: "rpc", sub: "mode", val: m }); },
  back: function (v) { state.back = v; jlog({ type: "rpc", sub: "back", val: v }); },
  finish: function (v) { state.finish = v; jlog({ type: "rpc", sub: "finish", val: v }); },
  uiforce: function (v) { state.uiforce = (v === "on" || v === true); jlog({ type: "rpc", sub: "uiforce", val: state.uiforce }); },

  // 내비게이션 제어
  navblock: function (v) { state.navblock = (v === "on" || v === true); jlog({ type: "rpc", sub: "navblock", val: state.navblock }); },
  scanblock: function (v) { state.scanblock = (v === "on" || v === true); jlog({ type: "rpc", sub: "scanblock", val: state.scanblock }); },
  navfilter: function (s) { state.navfilter = String(s || "ScanActivity"); jlog({ type: "rpc", sub: "navfilter", val: state.navfilter }); },

  // 프리셋
  freeall: function () { state.mode = "free"; state.back = "free"; state.finish = "free"; jlog({ type: "rpc", sub: "freeall" }); },
  blockall: function () { state.mode = "auto"; state.back = "block"; state.finish = "block"; jlog({ type: "rpc", sub: "blockall" }); },
  profile: function (name) {
    if (name === "scan") { // 검사모드: 뒤로/종료 차단 + 버튼 활성
      state.mode = "auto"; state.back = "block"; state.finish = "block"; state.uiforce = true;
    } else if (name === "free") { // 자유모드: 모두 허용 + 버튼 활성
      state.mode = "free"; state.back = "free"; state.finish = "free"; state.uiforce = true;
    }
    jlog({ type: "rpc", sub: "profile", val: name });
  },

  // 잠깐 허용 후 자동 복귀
  pulsefree: function (ms, which) {
    ms = ms || 1200; which = which || "both";
    const prev = { mode: state.mode, back: state.back, finish: state.finish };
    state.mode = "free";
    if (which === "both" || which === "back") state.back = "free";
    if (which === "both" || which === "finish") state.finish = "free";
    jlog({ type: "rpc", sub: "pulsefree.start", ms: ms, which: which });
    setTimeout(function () {
      state.mode = prev.mode; state.back = prev.back; state.finish = prev.finish;
      jlog({ type: "rpc", sub: "pulsefree.end" });
    }, ms);
  },

  // 보강 옵션들
  dumpdir: function (p) { state.dumpdir = (p && String(p)) || null; jlog({ type: "rpc", sub: "dumpdir", val: state.dumpdir || "(appFilesDir)" }); },
  sanitize: function (v) { state.sanitize = (v === "on" || v === true); jlog({ type: "rpc", sub: "sanitize", val: state.sanitize }); },
  ratelimit: function (ms) { state.ratelimitMs = (ms | 0); jlog({ type: "rpc", sub: "ratelimit", val: state.ratelimitMs }); },
  sampleevery: function (n) { state.sampleEvery = Math.max(1, n | 0); jlog({ type: "rpc", sub: "sampleEvery", val: state.sampleEvery }); },
  hookupdate: function (v) { state.hookUpdate = (v === "on" || v === true); jlog({ type: "rpc", sub: "hookUpdate", val: state.hookUpdate }); },

  // 상태 조회
  getstate: function () { jlog({ type: "rpc", sub: "getstate", val: state }); return state; }
};
