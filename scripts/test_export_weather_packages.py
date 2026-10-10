"""Host-side tests for catalog confinement and atomic no-replace publication."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("export_weather_packages", Path(__file__).with_name("export_weather_packages.py"))
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class ExportTests(unittest.TestCase):
    def test_atomic_publication_and_no_replace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage, target = root / "stage", root / "target"
            stage.mkdir()
            (stage / "manifest.json").write_text("test catalog")
            exporter.publish_directory(stage, target)
            self.assertFalse(stage.exists())
            self.assertEqual((target / "manifest.json").read_text(), "test catalog")
            stage.mkdir()
            with self.assertRaises(OSError):
                exporter.publish_directory(stage, target)
            self.assertTrue(stage.exists())
            self.assertEqual((target / "manifest.json").read_text(), "test catalog")
            empty = root / "empty"
            empty.mkdir()
            with self.assertRaises(OSError):
                exporter.publish_directory(stage, empty)
            self.assertTrue(stage.exists())

    def test_payload_confinement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "payload").write_bytes(b"public payload")
            self.assertEqual(exporter.read_source(root, "payload"), b"public payload")
            for name in ("../payload", "/payload", "a/../payload", "./payload", "a\\payload"):
                with self.assertRaises(ValueError):
                    exporter.read_source(root, name)
            try:
                (root / "link").symlink_to(root / "payload")
            except OSError:
                return
            with self.assertRaises(ValueError):
                exporter.read_source(root, "link")


if __name__ == "__main__":
    unittest.main()
