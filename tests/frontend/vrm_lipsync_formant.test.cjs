// 五元音共振峰口型分析器（FormantLipSyncAnalyzer）的 Node 行为测试。
//
// 放在 tests/frontend/ 并由 tests/unit/test_vrm_lipsync_formant_static_contracts.py
// 通过 `node --test` 拉起，与 tests/frontend/vrm_motion_*.test.cjs 的做法一致。
// 早先这份测试放在 tests/unit/*.test.js，仓库里没有任何 runner 会收集该后缀，
// 十条断言从未在 CI 里执行过。
//
// 用 vm 把经典脚本加载进一个带 window 的上下文，再用合成频谱驱动 mock AnalyserNode，
// 验证：F1/F2 共振峰 → 正确元音（含圆唇 お/う）、top-2 混合、静音门限、
// 词内间隙保持、释放确实慢于攻击、帧率无关平滑、脏 delta 不污染状态。
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const projectRoot = path.resolve(__dirname, '..', '..');
const modulePath = path.join(projectRoot, 'static', 'vrm', 'vrm-lipsync-formant.js');
const moduleSource = fs.readFileSync(modulePath, 'utf8');

// 宿主 analyser 的真实参数：app-audio-playback 的 S.globalAnalyser 建出来就是
// fftSize=2048 / 默认 smoothingTimeConstant。分析器必须适配这个格式而不是改写它。
const SAMPLE_RATE = 48000;
const HOST_FFT_SIZE = 2048;
const HOST_SMOOTHING = 0.8;

// 加载经典脚本，返回 { FormantLipSyncAnalyzer, VOWEL_KEYS, setNow, context }。
function loadModule() {
    let nowMs = 0;
    const context = {
        console,
        performance: { now: () => nowMs },
        Math,
        Number,
        Object,
        Uint8Array,
        window: {},
    };
    vm.createContext(context);
    vm.runInContext(moduleSource, context, { filename: modulePath });
    return {
        FormantLipSyncAnalyzer: context.window.FormantLipSyncAnalyzer,
        VOWEL_KEYS: context.window.VRM_LIPSYNC_VOWEL_KEYS,
        setNow: (v) => { nowMs = v; },
        loadAgain: () => vm.runInContext(moduleSource, context, { filename: modulePath }),
        context,
    };
}

// 构造 mock AnalyserNode：给定若干 {hz, level} 谱峰，合成 byte 频谱。
// 每个峰带 ±2 bin 的裙边，比单 bin 冲激更接近真实共振峰。
function makeAnalyser(peaks, overrides = {}) {
    const binCount = HOST_FFT_SIZE / 2;
    const nyquist = SAMPLE_RATE / 2;
    const bins = new Uint8Array(binCount);
    for (const { hz, level } of peaks) {
        const center = Math.round((hz / nyquist) * binCount);
        for (let d = -2; d <= 2; d++) {
            const i = center + d;
            if (i >= 0 && i < binCount) {
                bins[i] = Math.max(bins[i], Math.round(level * (1 - Math.abs(d) * 0.18)));
            }
        }
    }
    return {
        fftSize: HOST_FFT_SIZE,
        smoothingTimeConstant: HOST_SMOOTHING,
        frequencyBinCount: binCount,
        context: { sampleRate: SAMPLE_RATE },
        getByteFrequencyData(out) { out.set(bins.subarray(0, out.length)); },
        ...overrides,
    };
}

// 某元音的一帧发声：F1 最强、F2 次强，再加谐波与高频底噪。
function vowelAnalyser(f1, f2) {
    return makeAnalyser([
        { hz: f1, level: 210 },
        { hz: f2, level: 170 },
        { hz: f1 * 2, level: 70 },
        { hz: 2600, level: 55 },
        { hz: 3400, level: 40 },
    ]);
}

// 驱动 analyzer 若干帧，同步推进被 mock 的 performance.now()。
// 时钟必须跟着走：IDLE_MS 的判定读的是 performance.now()，不推进的话
// idleExpired 恒为 false，release 分支永远不会被执行到。
function runFrames(analyzer, setNow, frames, { delta = 1 / 60, startNow = 0 } = {}) {
    let now = startNow;
    let out = null;
    for (let i = 0; i < frames; i++) {
        now += delta * 1000;
        setNow(now);
        out = analyzer.update(delta);
    }
    return { out, now };
}

function ranked(out) {
    return Object.entries(out).sort((a, b) => b[1] - a[1]);
}

test('加载后挂载 window.FormantLipSyncAnalyzer 与五元音键表', () => {
    const { FormantLipSyncAnalyzer, VOWEL_KEYS } = loadModule();
    assert.equal(typeof FormantLipSyncAnalyzer, 'function');
    assert.deepEqual([...VOWEL_KEYS].sort(), ['aa', 'ee', 'ih', 'oh', 'ou']);
});

test('重复加载幂等：第二次执行不抛、类身份不变', () => {
    // 该脚本同时挂在四条模块加载链上，model_manager 的 runtime-loaders.js
    // 更是在 VRM/MMD 两个并行 IIFE 里各列一次。顶层 const 重复声明会抛
    // "Identifier 'VOWEL_FORMANTS' has already been declared" 并打断整条链。
    const { FormantLipSyncAnalyzer, loadAgain, context } = loadModule();
    assert.doesNotThrow(() => loadAgain());
    assert.equal(context.window.FormantLipSyncAnalyzer, FormantLipSyncAnalyzer);
});

// ─────────────── 五元音判别（含 greptile 指出的圆唇元音）───────────────

const VOWEL_CASES = [
    ['aa', 850, 1400],
    ['ee', 550, 2100],
    ['ih', 350, 2700],
    ['oh', 500, 900],
    ['ou', 350, 800],
];

for (const [want, f1, f2] of VOWEL_CASES) {
    test(`共振峰指向 ${want}(F1=${f1} F2=${f2}) 时该元音权重最高`, () => {
        const { FormantLipSyncAnalyzer, setNow } = loadModule();
        const a = new FormantLipSyncAnalyzer(vowelAnalyser(f1, f2));
        const { out } = runFrames(a, setNow, 40);
        const top = ranked(out);
        assert.equal(top[0][0], want, `期望 ${want} 最强，实际 ${JSON.stringify(out)}`);
        assert.ok(out[want] > 0, `${want} 应被激活`);
    });
}

test('圆唇元音 ou 不会被误判成 ih —— 两者 F1 相同，只能靠 F2 区分', () => {
    // 回归锁：ou(350,800) 与 ih(350,2700) 的 F1 完全一致。F2 搜索窗若从
    // 1000Hz 起搜，ou 的参考中心 800Hz 永远落在窗外，距离项恒大于零，
    // 结果必然翻给 ih —— 嘴型从"圆唇闭后"跳成"展唇闭前"，正好相反。
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const a = new FormantLipSyncAnalyzer(vowelAnalyser(350, 800));
    const { out } = runFrames(a, setNow, 40);
    assert.ok(out.ou > out.ih,
        `ou=${out.ou} 应强于 ih=${out.ih}（F2 搜索窗必须覆盖 800Hz）`);
});

test('top-2：最多两个元音有非零权重', () => {
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const a = new FormantLipSyncAnalyzer(vowelAnalyser(650, 1150));
    const { out } = runFrames(a, setNow, 40);
    const nonZero = Object.values(out).filter((v) => v > 0.001);
    assert.ok(nonZero.length <= 2, `top-2 应至多两个非零，实际 ${JSON.stringify(out)}`);
    assert.ok(nonZero.length >= 1, '至少一个元音应激活');
});

// ─────────────── 静音 / idle 窗口 ───────────────

test('静音超过 IDLE_MS 后所有元音收敛到 0', () => {
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const a = new FormantLipSyncAnalyzer(makeAnalyser([]));
    // 30 帧 × 16.7ms ≈ 500ms > IDLE_MS(160ms)
    const { out } = runFrames(a, setNow, 30);
    for (const [k, v] of Object.entries(out)) {
        assert.ok(v <= 0.001, `静音时 ${k} 应为 0，实际 ${v}`);
    }
});

test('idle 窗口内短暂静音不归零，保持当前嘴型', () => {
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const a = new FormantLipSyncAnalyzer(vowelAnalyser(850, 1400));
    const voiced = runFrames(a, setNow, 60);
    assert.ok(voiced.out.aa > 0.1, `有声稳态 aa=${voiced.out.aa} 应 > 0.1`);
    const steadyAa = voiced.out.aa;

    a.attach(makeAnalyser([]));
    // 8 帧 ≈ 133ms < IDLE_MS(160ms)
    const idle = runFrames(a, setNow, 8, { startNow: voiced.now });
    assert.ok(idle.out.aa > steadyAa * 0.7,
        `idle 窗口内 aa=${idle.out.aa} 应保持接近稳态 ${steadyAa}，不应归零`);
});

// ─────────────── 平滑特性 ───────────────

test('平滑是渐进的：单帧不会从 0 跳到目标（攻击平滑）', () => {
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const a = new FormantLipSyncAnalyzer(vowelAnalyser(850, 1400));
    const first = runFrames(a, setNow, 1);
    const steady = runFrames(a, setNow, 60, { startNow: first.now });
    assert.ok(first.out.aa < steady.out.aa,
        `首帧 ${first.out.aa} 应小于稳态 ${steady.out.aa}`);
});

test('释放慢于攻击：同一段位移，闭嘴耗时严格多于张嘴', () => {
    // 这条断言必须让时钟真正越过 IDLE_MS，否则分析器走的是"idle 窗口内保持
    // state"分支（target === state），位移恒为 0，断言会对任意 RELEASE 取值
    // 都成立 —— 早先的版本正是这样空转通过的。
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const delta = 1 / 60;

    // 张嘴：从 0 升到稳态的一半需要几帧
    const opening = new FormantLipSyncAnalyzer(vowelAnalyser(850, 1400));
    const warm = runFrames(opening, setNow, 90);
    const steadyAa = warm.out.aa;
    assert.ok(steadyAa > 0.05, `稳态 aa=${steadyAa} 太小，用例失去分辨力`);

    const fresh = new FormantLipSyncAnalyzer(vowelAnalyser(850, 1400));
    let now = 0;
    let openFrames = 0;
    while (fresh.state.aa < steadyAa / 2 && openFrames < 600) {
        now += delta * 1000;
        setNow(now);
        fresh.update(delta);
        openFrames++;
    }

    // 闭嘴：先跑到稳态，再切静音并把时钟推过 IDLE_MS，让 release 分支真正生效
    const closing = new FormantLipSyncAnalyzer(vowelAnalyser(850, 1400));
    const hot = runFrames(closing, setNow, 90);
    closing.attach(makeAnalyser([]));
    now = hot.now + 400; // 越过 IDLE_MS(160ms)，进入真停顿
    setNow(now);
    const closeFrom = closing.state.aa;
    let closeFrames = 0;
    while (closing.state.aa > closeFrom / 2 && closeFrames < 600) {
        now += delta * 1000;
        setNow(now);
        closing.update(delta);
        closeFrames++;
    }

    assert.ok(closeFrames < 600, 'release 分支未生效：嘴一直没有闭合');
    assert.ok(closeFrames > openFrames,
        `闭嘴用了 ${closeFrames} 帧，张嘴用了 ${openFrames} 帧；` +
        `攻击(${'50'})应快于释放(${'30'})，故闭嘴帧数必须更多`);
});

test('帧率无关：60fps 与 30fps 在相同时长后到达相近权重', () => {
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const a60 = new FormantLipSyncAnalyzer(vowelAnalyser(850, 1400));
    runFrames(a60, setNow, 60, { delta: 1 / 60 }); // 1 秒

    const a30 = new FormantLipSyncAnalyzer(vowelAnalyser(850, 1400));
    runFrames(a30, setNow, 30, { delta: 1 / 30 }); // 1 秒

    const diff = Math.abs(a60.state.aa - a30.state.aa);
    assert.ok(diff < 0.05,
        `帧率无关性：60fps ${a60.state.aa} vs 30fps ${a30.state.aa} 差异 ${diff} 应 < 0.05`);
});

// ─────────────── 宿主 analyser 归属 ───────────────

test('绝不改写宿主 analyser 的 fftSize / smoothingTimeConstant', () => {
    // S.globalAnalyser 是全局共享节点，Live2D 与 PNGTuber 的口型循环都在启动时
    // 按当时的 fftSize 预分配一次时域缓冲。在这里改配置会静默改掉它们的采样窗口。
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const host = vowelAnalyser(850, 1400);
    const a = new FormantLipSyncAnalyzer(host);
    runFrames(a, setNow, 10);
    assert.equal(host.fftSize, HOST_FFT_SIZE, 'fftSize 被改写了');
    assert.equal(host.smoothingTimeConstant, HOST_SMOOTHING, 'smoothingTimeConstant 被改写了');
});

test('宿主运行期改 fftSize 时采样缓冲跟着重建', () => {
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const host = vowelAnalyser(850, 1400);
    const a = new FormantLipSyncAnalyzer(host);
    runFrames(a, setNow, 5);
    assert.equal(a.bins.length, HOST_FFT_SIZE / 2);

    host.fftSize = 512;
    host.frequencyBinCount = 256;
    runFrames(a, setNow, 5);
    assert.equal(a.bins.length, 256, '缓冲长度未跟随宿主 fftSize');
});

test('analyser 缺少 context 时不抛异常（回退默认 sampleRate）', () => {
    // mmd-animation.getLipSyncValue 对同一件事有显式防御，说明宿主实现
    // 并不保证 .context 存在；构造期抛异常会一路冒泡打断 startLipSync。
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const host = makeAnalyser([{ hz: 850, level: 200 }], { context: undefined });
    let a;
    assert.doesNotThrow(() => { a = new FormantLipSyncAnalyzer(host); });
    const { out } = runFrames(a, setNow, 10);
    for (const v of Object.values(out)) assert.ok(Number.isFinite(v));
});

// ─────────────── 脏输入 ───────────────

test('非有限 delta 不会把 NaN latch 进平滑状态', () => {
    // NaN 一旦进 state 就永久留在那里（NaN 参与任何运算仍是 NaN），
    // 之后每帧把 NaN 写进 blendshape / morph influence，模型脸会崩。
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const a = new FormantLipSyncAnalyzer(vowelAnalyser(850, 1400));
    setNow(100);
    for (const bad of [NaN, undefined, -1, Infinity, '0.016']) {
        a.update(bad);
        for (const [k, v] of Object.entries(a.state)) {
            assert.ok(Number.isFinite(v), `delta=${String(bad)} 让 state.${k} 变成 ${v}`);
        }
    }
    // 脏输入之后仍能正常收敛到 aa
    const { out } = runFrames(a, setNow, 40, { startNow: 100 });
    assert.equal(ranked(out)[0][0], 'aa', `脏 delta 之后未能恢复：${JSON.stringify(out)}`);
});

test('delta === 0 时不推进平滑（合法输入，不是脏值）', () => {
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const a = new FormantLipSyncAnalyzer(vowelAnalyser(850, 1400));
    const warm = runFrames(a, setNow, 30);
    const before = { ...a.state };
    setNow(warm.now);
    a.update(0);
    for (const key of Object.keys(before)) {
        assert.equal(a.state[key], before[key], `delta=0 不应改变 state.${key}`);
    }
});

test('输出恒在 [0,1] 且不超过 CAP', () => {
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    // 全频段拉满，逼出最大可能的振幅
    const loud = makeAnalyser(
        Array.from({ length: 40 }, (_, i) => ({ hz: 200 + i * 100, level: 255 }))
    );
    const a = new FormantLipSyncAnalyzer(loud);
    const { out } = runFrames(a, setNow, 120);
    for (const [k, v] of Object.entries(out)) {
        assert.ok(v >= 0 && v <= 0.7 + 1e-9, `${k}=${v} 超出 [0, CAP=0.7]`);
    }
});

test('reset 清空平滑状态', () => {
    const { FormantLipSyncAnalyzer, setNow } = loadModule();
    const a = new FormantLipSyncAnalyzer(vowelAnalyser(850, 1400));
    runFrames(a, setNow, 30);
    assert.ok(a.state.aa > 0, 'reset 前应有状态');
    a.reset();
    assert.equal(a.state.aa, 0);
    assert.equal(a.lastActiveAt, 0);
});

test('无 analyser 时 update 返回全零（安全降级）', () => {
    const { FormantLipSyncAnalyzer } = loadModule();
    const a = new FormantLipSyncAnalyzer(null);
    const out = a.update(1 / 60);
    for (const v of Object.values(out)) assert.equal(v, 0);
});
