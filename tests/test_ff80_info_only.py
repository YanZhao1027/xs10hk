"""Purely synthetic FF80 protocol gate tests; no physical camera accessed."""
import pathlib
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from ff80_info_only import InfoOnlyFF80, safe_parse_text, VENDOR, SERVICE_PID


class TestFF80InfoOnly(unittest.TestCase):
    def test_utf16_response_is_truncated_before_serial(self):
        encoded = ("X-S10" + chr(0) + "do-not-publish").encode("utf-16-le")
        self.assertEqual(safe_parse_text(encoded), "X-S10")

    def test_long_text_rejected(self):
        with self.assertRaises(ValueError):
            safe_parse_text(("A" * 101).encode("utf-16-le"))

    def test_rejects_normal_camera_pid_without_traffic(self):
        device = Mock()
        device.idVendor = VENDOR
        device.idProduct = 0x02EA
        client = InfoOnlyFF80(device)
        with self.assertRaises(ValueError):
            client.verify_interface()
        device.get_active_configuration.assert_not_called()
        device.ctrl_transfer.assert_not_called()

    def test_denies_serial_tag_without_device_traffic(self):
        device = Mock()
        client = InfoOnlyFF80(device)
        with self.assertRaises(ValueError):
            client.request_info(0x20)
        device.ctrl_transfer.assert_not_called()
        device.write.assert_not_called()

    def test_denies_unrecognized_command_tag_without_session(self):
        client = InfoOnlyFF80(Mock())
        for value in (0x01, 0x02, 0x10, 0x40, 0xF0002):
            with self.assertRaises(ValueError):
                client.request_info(value)

    def test_no_hardware_seen_does_not_send_command(self):
        with patch("ff80_info_only.usb.core.find", return_value=None):
            with patch.object(sys, "argv", ["ff80_info_only.py", "--read-info"]):
                from ff80_info_only import main
                self.assertEqual(main(), 2)


if __name__ == "__main__":
    unittest.main()
