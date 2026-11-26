"""Static accessibility/usability invariants for the chat UI (server/static/index.html).

Pins the fixes from the UI audit so they cannot silently regress:
labelled controls, no nested interactive elements, motion respecting the
user's reduced-motion setting, status not conveyed by colour alone, and the
suggestion button that used to send its own tip text to the model.
"""
import re
from pathlib import Path

import pytest

HTML = (Path(__file__).resolve().parents[2] / "server" / "static" / "index.html").read_text(encoding="utf-8")
CSS = HTML[HTML.index("<style>"):HTML.index("</style>")]
JS = HTML[HTML.rindex("<script>"):HTML.rindex("</script>")]


def test_skip_link_and_landmarks():
    assert 'class="skip-link" href="#input"' in HTML
    assert '<nav id="sidebar" aria-label="Engagements">' in HTML
    assert 'id="chat" role="log"' in HTML


@pytest.mark.parametrize("control_id", ["input", "role-select", "ne-client", "ne-name", "ne-notes"])
def test_form_controls_have_labels(control_id):
    assert f'<label for="{control_id}"' in HTML


@pytest.mark.parametrize("dialog_id", ["dlg-new-eng", "dlg-model", "dlg-del-eng"])
def test_dialogs_are_labelled(dialog_id):
    assert re.search(rf'<dialog id="{dialog_id}" aria-labelledby="{dialog_id}-title"', HTML)
    assert f'id="{dialog_id}-title"' in HTML


def test_no_clickable_divs_or_nested_buttons():
    # the engagement item used to be a role="button" div wrapping a button
    markup = HTML[:HTML.rindex("<script>")]
    assert 'role="button"' not in markup
    assert not re.search(r"\.role\s*=\s*['\"]button|setAttribute\(\s*['\"]role['\"],\s*['\"]button", JS)
    assert not re.search(r"<li[^>]*role=|class=\"eng-select\"[^>]*role=", JS)
    # model tiers used to be clickable divs with no keyboard access
    assert "document.createElement('button');\n      div.type = 'button';" in JS


def test_decorative_svgs_hidden_from_screen_readers():
    for svg in re.findall(r"<svg[^>]*>", HTML):
        assert 'aria-hidden="true"' in svg, svg


def test_motion_is_opt_in():
    # every hover lift / animation lives under prefers-reduced-motion: no-preference
    transforms = [m.start() for m in re.finditer(r"translateY\(-2px\)", CSS)]
    assert transforms, "hover lift missing"
    for pos in transforms:
        block_start = CSS.rfind("@media", 0, pos)
        assert "prefers-reduced-motion: no-preference" in CSS[block_start:block_start + 60]


def test_every_button_gets_hover_feedback():
    assert re.search(r"(?m)^button:hover:not\(:disabled\)", CSS)
    assert "button::after" in CSS


def test_status_not_colour_only():
    assert 'id="status-text"' in HTML
    assert "'Error: ' + msg" in JS


def test_attach_suggestion_opens_picker_instead_of_sending_tip():
    assert "Tip: use the attach button" not in HTML
    assert 'data-action="attach"' in HTML


def test_cti_mode_selectable():
    # core/rag.py defines a "cti" role preset; the UI previously could not pick it
    assert '<option value="cti">' in HTML
