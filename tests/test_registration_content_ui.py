import os
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


class RegistrationContentUiTests(unittest.TestCase):
    def test_admin_view_has_three_content_uploads(self):
        xml = (ROOT / "default" / "data" / "ui" / "views" / "admin.xml").read_text()
        self.assertIn('id="ctfr-questions-csv"', xml)
        self.assertIn('id="ctfr-answers-csv"', xml)
        self.assertIn('id="ctfr-hints-csv"', xml)
        self.assertIn('id="ctfr-use-event-window"', xml)

    def test_javascript_submits_content_fields_independently(self):
        js = (ROOT / "appserver" / "static" / "registration_admin.js").read_text()
        self.assertIn("if (selectedFiles[0]) { payload.questions_csv = files[0]; }", js)
        self.assertIn("if (selectedFiles[1]) { payload.answers_csv = files[1]; }", js)
        self.assertIn("if (selectedFiles[2]) { payload.hints_csv = files[2]; }", js)
        self.assertNotIn("Select questions, answers, and hints CSV files together", js)
        self.assertIn("use_event_window", js)

    def test_admin_view_restores_image_upload_without_removing_content_uploads(self):
        xml = (ROOT / "default" / "data" / "ui" / "views" / "admin.xml").read_text()
        self.assertIn('id="ctfr-image-file"', xml)
        self.assertIn('id="ctfr-image-preview"', xml)
        self.assertIn('id="ctfr-use-default-image"', xml)
        self.assertIn('id="ctfr-image-url"', xml)
        self.assertIn('accept="image/png,image/jpeg,image/webp"', xml)
        self.assertIn('id="ctfr-questions-csv"', xml)
        self.assertIn('id="ctfr-answers-csv"', xml)
        self.assertIn('id="ctfr-hints-csv"', xml)

    def test_javascript_uploads_image_and_keeps_content_import(self):
        js = (ROOT / "appserver" / "static" / "registration_admin.js").read_text()
        self.assertIn('/admin/upload-image', js)
        self.assertIn('reader.readAsDataURL(file)', js)
        self.assertIn('resp.image_url', js)
        self.assertIn('payload.questions_csv', js)
        self.assertIn('payload.answers_csv', js)
        self.assertIn('payload.hints_csv', js)

    def test_backend_restores_image_upload_route_and_validation(self):
        py = (ROOT / "bin" / "registration_rest.py").read_text()
        self.assertIn('UPLOAD_DIR = BASE / "appserver" / "static" / "images" / "uploads"', py)
        self.assertIn('MAX_IMAGE_BYTES = 5 * 1024 * 1024', py)
        self.assertIn('if path == "admin/upload-image" and method == "POST":', py)
        self.assertIn('def _admin_upload_image', py)
        self.assertIn('def _detect_image_type', py)
        self.assertIn('def _decode_image_data', py)
        self.assertIn('def _save_event_image', py)

    def test_backend_targets_all_content_at_admin_app(self):
        py = (ROOT / "bin" / "registration_rest.py").read_text()
        self.assertIn('SCOREBOARD_ADMIN_APP = "SA-ctf_scoreboard_admin"', py)
        self.assertIn('"questions": (SCOREBOARD_ADMIN_APP, "ctf_questions", ("Number",))', py)
        self.assertIn('"answers": (SCOREBOARD_ADMIN_APP, "ctf_answers", ("Number",))', py)
        self.assertIn('"hints": (SCOREBOARD_ADMIN_APP, "ctf_hints", ("Number", "HintNumber"))', py)

    def test_backend_verifies_content_after_write(self):
        py = (ROOT / "bin" / "registration_rest.py").read_text()
        self.assertIn("def _verify_ctf_content", py)
        self.assertIn("Content verification failed", py)
        self.assertIn("Verified CTF content", py)

    def test_registration_event_cards_are_compact_and_images_are_not_cropped(self):
        js = (ROOT / "appserver" / "static" / "registration.js").read_text()
        css = (ROOT / "appserver" / "static" / "registration.css").read_text()
        self.assertIn('addClass("ctfr-event-card")', js)
        self.assertIn('attr("tabindex", "0")', js)
        self.assertIn('grid-template-columns:repeat(auto-fill,minmax(280px,360px))', css)
        self.assertIn('object-fit:contain', css)
        self.assertIn('aspect-ratio:16 / 9', css)
        self.assertIn('.ctfr-event-card.is-selected', css)


if __name__ == "__main__":
    unittest.main()
