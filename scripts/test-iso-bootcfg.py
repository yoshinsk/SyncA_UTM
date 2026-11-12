#!/usr/bin/env python3
"""scripts/test-iso-bootcfg.py - 実際のGRUB変換処理でネストした既存メニューの除去を検証する。"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class IsoBootConfigTests(unittest.TestCase):
    """ISO生成スクリプトに埋め込まれた変換処理を一時ファイルだけに適用する。"""

    def test_nested_vendor_menus_leave_valid_product_config(self):
        builder = (ROOT / 'scripts/build-synca-utm-iso.sh').read_text(encoding='utf-8')
        # ビルド全体やOSコマンドは起動せず、製品が使用するPython変換部分をそのまま実行する。
        function = builder.split('patch_grub() {', 1)[1]
        transform = function.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        original = '''set default="0"
set timeout=60
function load_video {
  insmod efi_gop
}
load_video
search --no-floppy --set=root -l 'ALMA_OLD'
menuentry 'Original install' {
  linuxefi /old/kernel
}
submenu 'Original troubleshooting' {
  menuentry 'Original test' {
    linuxefi /old/kernel quiet
  }
  submenu 'Original advanced' {
    menuentry 'Original rescue' {
      linuxefi /old/kernel rescue
    }
  }
}
set preserved_after_menu=yes
'''
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'grub.cfg'
            config.write_text(original, encoding='utf-8')
            subprocess.run([sys.executable, '-c', transform, str(config), 'SYNCA_UTM_9'], check=True)
            text = config.read_text(encoding='utf-8')
            self.assertNotIn('Original', text)
            self.assertNotIn('/old/kernel', text)
            self.assertIn('function load_video {\n  insmod efi_gop\n}', text)
            self.assertIn('set preserved_after_menu=yes', text)
            self.assertEqual(text.count("menuentry '"), 3)
            self.assertIn('set default="synca-utm"', text)
            self.assertIn("search --no-floppy --set=root -l 'SYNCA_UTM_9'", text)
            # 余った閉じ括弧は総数一致だけでは見逃すため、各行の時点でも深さを確認する。
            depth = 0
            for line in text.splitlines():
                depth += line.count('{') - line.count('}')
                self.assertGreaterEqual(depth, 0, line)
            self.assertEqual(depth, 0)


if __name__ == '__main__':
    unittest.main()
