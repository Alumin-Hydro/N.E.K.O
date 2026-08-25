"""Static-contract tests for the VRM/MMD formant (five-vowel) lip-sync.

Two layers guard this feature:

* The behaviour suite ``tests/frontend/vrm_lipsync_formant.test.cjs`` runs the
  real analyzer under node and is launched by ``test_formant_behaviour_suite``
  below.  It used to live at ``tests/unit/vrm_lipsync_formant.test.js``, where
  no runner in this repo collects that suffix, so none of its assertions had
  ever executed in CI.
* The string-level contracts here lock structural wiring that the behaviour
  suite cannot see: which loader chains ship the shared analyzer, that the
  analyzer stays lazily constructed behind a fallback, and that both avatar
  pipelines write every vowel each frame.
"""
import shutil
import subprocess
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Every loader chain that can end up owning a VRM or MMD avatar. The shared
# analyzer attaches to window, so a chain that omits it silently degrades to
# the legacy single-channel driver with no error anywhere.
LOADER_CHAINS = (
    "static/vrm/vrm-init.js",
    "static/mmd/mmd-init.js",
    "static/js/model_manager/runtime-loaders.js",
    "static/js/character_card_manager/model-previews.js",
)

FORMANT_MODULE = "/static/vrm/vrm-lipsync-formant.js"

# Mirrors VOWEL_KEYS in static/vrm/vrm-lipsync-formant.js.
EXPECTED_VOWEL_KEYS = ("aa", "ee", "ih", "oh", "ou")


def _read(rel):
    return (PROJECT_ROOT / rel).read_text(encoding="utf-8")


# ─────────────────────────── node behaviour suite ───────────────────────────


def test_formant_behaviour_suite():
    """The node suite for the analyzer passes."""
    node_path = shutil.which("node")
    if not node_path:
        pytest.skip("node not found")

    test_path = PROJECT_ROOT / "tests" / "frontend" / "vrm_lipsync_formant.test.cjs"
    # encoding is pinned explicitly: the suite names its cases in Chinese and a
    # stock English Windows runner decodes subprocess output as cp1252, which
    # turns a passing suite into a UnicodeDecodeError.
    result = subprocess.run(
        [node_path, "--test", str(test_path)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ─────────────────────────────── loader chains ───────────────────────────────


@pytest.mark.parametrize("chain", LOADER_CHAINS)
def test_every_loader_chain_ships_the_shared_analyzer(chain):
    """Each VRM/MMD loader chain lists the shared formant analyzer.

    Enumerating the chains here (rather than spot-checking vrm-init.js) is the
    point: the first version of this feature wired only vrm-init.js and
    mmd-init.js, so the model-manager page and the card-maker preview kept the
    legacy driver. Both of those chains set the ``_vrmModulesLoading`` /
    ``_mmdModulesLoading`` flags that make the init IIFEs return early, so they
    cannot inherit the entry from vrm-init.js.
    """
    assert FORMANT_MODULE in _read(chain), (
        f"{chain} does not load {FORMANT_MODULE}; VRM/MMD lip-sync there "
        f"silently falls back to the legacy single-channel driver"
    )


def test_shared_analyzer_is_reentrant():
    """The module tolerates being loaded twice.

    runtime-loaders.js lists the analyzer in both its VRM and its MMD chain,
    and those two IIFEs run concurrently. A classic script whose top level
    declares ``const`` throws "already been declared" on the second execution
    and takes the whole chain down with it, so the implementation must sit
    inside a guarded IIFE.
    """
    source = _read("static/vrm/vrm-lipsync-formant.js")
    assert "(function initFormantLipSync() {" in source
    guard = source.split("(function initFormantLipSync() {", 1)[1].split("const VOWEL_FORMANTS", 1)[0]
    assert "typeof window.FormantLipSyncAnalyzer === 'function'" in guard
    assert "return;" in guard


def test_formant_module_exposes_global_and_no_esm():
    """Classic-script architecture: attach to window, no ESM import/export."""
    source = _read("static/vrm/vrm-lipsync-formant.js")
    assert "window.FormantLipSyncAnalyzer = FormantLipSyncAnalyzer;" in source
    assert "\nexport " not in source
    assert "\nimport " not in source


# ──────────────────────────── shared vowel key table ────────────────────────


def test_vowel_key_tables_agree():
    """The three vowel-key tables in the codebase stay in sync.

    Without pinning the literal here, a reviewer changing the analyzer's
    VOWEL_KEYS would change this test's own expectation at the same time and
    the derived comparison below would keep passing vacuously.
    """
    analyzer = _read("static/vrm/vrm-lipsync-formant.js")
    animation = _read("static/vrm/vrm-animation.js")
    expression = _read("static/mmd/mmd-expression.js")

    analyzer_keys = analyzer.split("const VOWEL_KEYS = Object.freeze([", 1)[1].split("]", 1)[0]
    fallback_keys = animation.split("static FALLBACK_VOWEL_KEYS = Object.freeze([", 1)[1].split("]", 1)[0]

    def parsed(chunk):
        return tuple(part.strip().strip("'\"") for part in chunk.split(",") if part.strip())

    assert parsed(analyzer_keys) == EXPECTED_VOWEL_KEYS
    assert parsed(fallback_keys) == EXPECTED_VOWEL_KEYS

    # vrm-animation reads the shared table at runtime and only falls back to
    # its own copy when the analyzer script has not executed yet.
    assert "window.VRM_LIPSYNC_VOWEL_KEYS" in animation
    # The MMD map is keyed by the analyzer's vowel keys.
    mmd_map = expression.split("const FORMANT_TO_MMD_VOWEL = Object.freeze(", 1)[1].split(")", 1)[0]
    for vowel in EXPECTED_VOWEL_KEYS:
        assert f"{vowel}:" in mmd_map, f"MMD map is missing analyzer key {vowel}"


# ───────────────────────────── host analyser ownership ───────────────────────


def test_analyzer_never_writes_host_analyser_config():
    """The analyzer must not reconfigure the AnalyserNode it is handed.

    The node it receives is app-audio-playback's shared S.globalAnalyser, which
    Live2D and PNGTuber also read; both size their time-domain buffer once from
    ``analyser.fftSize`` at start, so rewriting it changes their sampling
    window with no restore point.
    """
    source = _read("static/vrm/vrm-lipsync-formant.js")
    assert "analyser.fftSize =" not in source
    assert "analyser.smoothingTimeConstant =" not in source
    # It adapts to whatever the host provides instead.
    assert "analyser.frequencyBinCount" in source


# ───────────────────────────────── VRM wiring ────────────────────────────────


def test_animation_lazy_instantiates_analyzer_with_fallback():
    """startLipSync instantiates lazily; the constructor must not touch window."""
    source = _read("static/vrm/vrm-animation.js")
    assert "new window.FormantLipSyncAnalyzer(analyser)" in source
    # Constructor only declares the field; it must not reference the global
    # class at load time because parallel module load order is not guaranteed.
    constructor = source.split("constructor(", 1)[1].split("startLipSync(", 1)[0]
    assert "new window.FormantLipSyncAnalyzer" not in constructor


def test_vrm_analyzer_construction_is_guarded():
    """A throwing analyzer must degrade to the legacy path, not escape.

    startLipSync is called from scheduleAudioChunks; an exception there aborts
    the rest of that chunk's scheduling bookkeeping. mmd-animation already
    wraps the same construction, so VRM has to match.
    """
    source = _read("static/vrm/vrm-animation.js")
    start = source.split("startLipSync(analyser) {", 1)[1].split("stopLipSync()", 1)[0]
    construct_at = start.index("new window.FormantLipSyncAnalyzer(analyser)")
    try_at = start.index("try {")
    catch_at = start.index("} catch (e) {")
    assert try_at < construct_at < catch_at
    assert "this._lipSyncAnalyzer = null;" in start[catch_at:]


def test_update_lipsync_prefers_formant_then_falls_back():
    """_updateLipSync tries the formant path first, then falls back to volume."""
    source = _read("static/vrm/vrm-animation.js")
    method = source.split("_updateLipSync(delta) {", 1)[1]
    formant_branch = method.index("this._updateLipSyncFormant(expressionManager, delta);")
    fallback_branch = method.index("getByteFrequencyData(this.frequencyData)")
    assert formant_branch < fallback_branch


def test_formant_path_writes_all_five_vowels_with_preset_fallback():
    """Formant path writes every vowel each frame and keeps the preset fallback.

    The legacy path drove ``this.mouthExpressions.aa || 'aa'``, so a model whose
    expression list could not be enumerated still moved its mouth. Skipping
    unmapped vowels instead would freeze the mouth shut without even logging,
    because setValue would never be called.
    """
    source = _read("static/vrm/vrm-animation.js")
    formant_method = source.split("_updateLipSyncFormant(expressionManager, delta) {", 1)[1]
    formant_method = formant_method.split("\n    }", 1)[0]
    assert "VRMAnimation.VOWEL_KEYS" in formant_method
    assert "this.mouthExpressions[vowel] || vowel" in formant_method
    assert "expressionManager.setValue(name, target);" in formant_method
    assert "continue;" not in formant_method, "unmapped vowels must not be skipped"


def test_fallback_path_still_clears_other_vowels_before_aa():
    """Fallback single-channel path keeps the clear-others-then-write-aa guard."""
    source = _read("static/vrm/vrm-animation.js")
    method = source.split("_updateLipSync(delta) {", 1)[1].split(
        "_updateLipSyncFormant(expressionManager, delta) {", 1
    )[0]
    assert "if (!name || vowel === 'aa') continue;" in method
    assert "expressionManager.setValue(name, 0);" in method


# ─────────────────────── MMD side (shares the same analyzer) ─────────────────


def test_mmd_animation_lazy_instantiates_formant_analyzer():
    """mmd-animation.startLipSync lazily builds the analyzer, with fallback."""
    source = _read("static/mmd/mmd-animation.js")
    assert "new window.FormantLipSyncAnalyzer(analyser)" in source
    assert "this._formantAnalyzer = null;" in source
    assert "startLipSync(analyser) {" in source


def test_mmd_expression_prefers_formant_then_falls_back():
    """mmd-expression.update tries formant path first, then legacy setMouth."""
    source = _read("static/mmd/mmd-expression.js")
    method = source.split("update(delta) {", 1)[1]
    formant_branch = method.index("anim._formantAnalyzer")
    fallback_branch = method.index("anim.getLipSyncValue()")
    assert formant_branch < fallback_branch


def test_mmd_expression_formant_maps_all_five_vowels():
    """Formant path maps analyzer keys to MMD vowels and writes every one."""
    source = _read("static/mmd/mmd-expression.js")
    for analyzer_key, mmd_key in (("aa", "a"), ("ih", "i"), ("ou", "u"), ("ee", "e"), ("oh", "o")):
        assert f"{analyzer_key}: '{mmd_key}'" in source

    formant_method = source.split("if (anim._formantAnalyzer) {", 1)[1].split(
        "anim.getLipSyncValue()", 1
    )[0]
    assert "weights[formantKey] ?? 0" in formant_method
    assert "this.setMorphWeight(name, target);" in formant_method


def test_mmd_formant_map_is_hoisted_not_rebuilt_per_frame():
    """The key map is a frozen module constant, not a literal built per frame.

    update() reads it on every rendered frame; returning a fresh object literal
    from the static getter allocated a new map plus a new Object.keys array
    ~60 times a second per model.
    """
    source = _read("static/mmd/mmd-expression.js")
    assert "const FORMANT_TO_MMD_VOWEL = Object.freeze(" in source
    assert "const FORMANT_KEYS = Object.freeze(Object.keys(FORMANT_TO_MMD_VOWEL));" in source
    getter = source.split("static get FORMANT_TO_MMD_VOWEL() {", 1)[1].split("}", 1)[0]
    assert "Object.freeze" not in getter, "getter must return the hoisted constant"


def test_mmd_expression_does_not_reclamp_delta():
    """delta hygiene lives in the analyzer, not duplicated at each call site."""
    source = _read("static/mmd/mmd-expression.js")
    formant_method = source.split("if (anim._formantAnalyzer) {", 1)[1].split(
        "anim.getLipSyncValue()", 1
    )[0]
    assert "anim._formantAnalyzer.update(delta)" in formant_method
    assert "Number.isFinite(delta)" not in formant_method


def test_analyzer_clamps_delta_internally():
    """The analyzer is the single place that sanitises delta."""
    source = _read("static/vrm/vrm-lipsync-formant.js")
    update = source.split("update(delta) {", 1)[1]
    assert "Number.isFinite(delta)" in update
    assert "Math.min(Math.max(delta, 0), MAX_DELTA)" in update
    # A non-finite smoothing result must never be written back into state.
    assert "Number.isFinite(next)" in update


def test_mmd_expression_has_reset_all_lip_morphs():
    """resetAllLipMorphs() exists and zeroes every vowel morph."""
    source = _read("static/mmd/mmd-expression.js")
    assert "resetAllLipMorphs()" in source
    method = source.split("resetAllLipMorphs()", 1)[1].split("\n    }", 1)[0]
    assert "Object.keys(this.lipMorphNames)" in method
    assert "this.setMorphWeight(name, 0)" in method


def test_mmd_stop_lip_sync_calls_reset_all():
    """stopLipSync clears all five vowel morphs, not just setMouth(0)."""
    source = _read("static/mmd/mmd-animation.js")
    stop_method = source.split("stopLipSync()", 1)[1].split("\n    }", 1)[0]
    assert "resetAllLipMorphs()" in stop_method
    assert "setMouth(0)" not in stop_method
