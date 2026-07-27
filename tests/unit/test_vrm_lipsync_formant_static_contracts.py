"""Static-contract tests for the VRM formant (five-vowel) lip-sync.

Locks the structural wiring so later refactors cannot silently break it:
  - vrm-lipsync-formant.js must load before vrm-animation.js (runtime dep);
  - _updateLipSync prefers the formant path and falls back to the legacy
    single-channel volume driver when the analyzer is unavailable;
  - the formant path writes all five vowels every frame (including 0),
    which overrides idle-VRMA mouth-track residue.
"""
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _read(rel):
    return (PROJECT_ROOT / rel).read_text(encoding="utf-8")


def test_formant_module_loaded_before_animation():
    """In vrm-init.js the formant module is listed before vrm-animation.js."""
    init_source = _read("static/vrm/vrm-init.js")
    formant_idx = init_source.index("/static/vrm/vrm-lipsync-formant.js")
    animation_idx = init_source.index("/static/vrm/vrm-animation.js")
    assert formant_idx < animation_idx


def test_formant_module_exposes_global_and_no_esm():
    """Classic-script architecture: attach to window, no ESM import/export."""
    source = _read("static/vrm/vrm-lipsync-formant.js")
    assert "window.FormantLipSyncAnalyzer = FormantLipSyncAnalyzer;" in source
    assert "\nexport " not in source
    assert "\nimport " not in source


def test_animation_lazy_instantiates_analyzer_with_fallback():
    """startLipSync instantiates lazily; the constructor must not touch window."""
    source = _read("static/vrm/vrm-animation.js")
    assert "new window.FormantLipSyncAnalyzer(analyser)" in source
    # Constructor only declares the field; it must not reference the global
    # class at load time because parallel module load order is not guaranteed.
    constructor = source.split("constructor(", 1)[1].split("startLipSync(", 1)[0]
    assert "new window.FormantLipSyncAnalyzer" not in constructor


def test_update_lipsync_prefers_formant_then_falls_back():
    """_updateLipSync tries the formant path first, then falls back to volume."""
    source = _read("static/vrm/vrm-animation.js")
    method = source.split("_updateLipSync(delta) {", 1)[1]
    formant_branch = method.index("this._updateLipSyncFormant(expressionManager, delta);")
    fallback_branch = method.index("getByteFrequencyData(this.frequencyData)")
    assert formant_branch < fallback_branch


def test_formant_path_writes_all_five_vowels():
    """Formant path iterates the whole mouthExpressions table, writing 0s too."""
    source = _read("static/vrm/vrm-animation.js")
    formant_method = source.split("_updateLipSyncFormant(expressionManager, delta) {", 1)[1]
    assert "Object.entries(this.mouthExpressions)" in formant_method
    assert "const target = weights[vowel] ?? 0;" in formant_method
    assert "expressionManager.setValue(name, target);" in formant_method


def test_fallback_path_still_clears_other_vowels_before_aa():
    """Fallback single-channel path keeps the clear-others-then-write-aa guard."""
    source = _read("static/vrm/vrm-animation.js")
    method = source.split("_updateLipSync(delta) {", 1)[1].split(
        "_updateLipSyncFormant(expressionManager, delta) {", 1
    )[0]
    assert "if (!name || vowel === 'aa') continue;" in method
    assert "expressionManager.setValue(name, 0);" in method
