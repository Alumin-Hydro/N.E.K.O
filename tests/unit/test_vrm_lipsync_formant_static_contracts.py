"""VRM 五元音共振峰口型（formant lip-sync）的静态契约测试。

锁定结构约定，防止后续改动把关键接线弄断：
  - vrm-lipsync-formant.js 必须先于 vrm-animation.js 加载（运行期实例化依赖）；
  - _updateLipSync 优先走五元音共振峰路径，分析器缺失时回退旧单通道音量驱动；
  - 五元音路径把全部五个元音每帧显式写入（含 0），覆盖待机 VRMA 口型轨道残留。
"""
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _read(rel):
    return (PROJECT_ROOT / rel).read_text(encoding="utf-8")


def test_formant_module_loaded_before_animation():
    """vrm-init.js 的并行模块列表里，formant 模块须排在 vrm-animation.js 之前。"""
    init_source = _read("static/vrm/vrm-init.js")
    formant_idx = init_source.index("/static/vrm/vrm-lipsync-formant.js")
    animation_idx = init_source.index("/static/vrm/vrm-animation.js")
    assert formant_idx < animation_idx


def test_formant_module_exposes_global_and_no_esm():
    """经典脚本架构：挂 window，不使用 ESM export（与 vrm-animation.js 一致）。"""
    source = _read("static/vrm/vrm-lipsync-formant.js")
    assert "window.FormantLipSyncAnalyzer = FormantLipSyncAnalyzer;" in source
    assert "\nexport " not in source
    assert "\nimport " not in source


def test_animation_lazy_instantiates_analyzer_with_fallback():
    """startLipSync 运行期惰性实例化；构造期不引用 window（并行加载顺序不保证）。"""
    source = _read("static/vrm/vrm-animation.js")
    assert "new window.FormantLipSyncAnalyzer(analyser)" in source
    # 构造器里只声明字段，不在加载期触碰全局类
    constructor = source.split("constructor(", 1)[1].split("startLipSync(", 1)[0]
    assert "new window.FormantLipSyncAnalyzer" not in constructor


def test_update_lipsync_prefers_formant_then_falls_back():
    """_updateLipSync 先尝试五元音路径，分析器为 null 时回退单通道音量驱动。"""
    source = _read("static/vrm/vrm-animation.js")
    method = source.split("_updateLipSync(delta) {", 1)[1]
    formant_branch = method.index("this._updateLipSyncFormant(expressionManager, delta);")
    fallback_branch = method.index("getByteFrequencyData(this.frequencyData)")
    assert formant_branch < fallback_branch


def test_formant_path_writes_all_five_vowels():
    """五元音路径遍历 mouthExpressions 全表逐帧写入（含 0），天然覆盖 VRMA 残留。"""
    source = _read("static/vrm/vrm-animation.js")
    formant_method = source.split("_updateLipSyncFormant(expressionManager, delta) {", 1)[1]
    assert "Object.entries(this.mouthExpressions)" in formant_method
    assert "const target = weights[vowel] ?? 0;" in formant_method
    assert "expressionManager.setValue(name, target);" in formant_method


def test_fallback_path_still_clears_other_vowels_before_aa():
    """回退单通道路径保留原有"先清零其他元音再写 aa"的防 VRMA 残留机制。"""
    source = _read("static/vrm/vrm-animation.js")
    method = source.split("_updateLipSync(delta) {", 1)[1].split(
        "_updateLipSyncFormant(expressionManager, delta) {", 1
    )[0]
    assert "if (!name || vowel === 'aa') continue;" in method
    assert "expressionManager.setValue(name, 0);" in method
