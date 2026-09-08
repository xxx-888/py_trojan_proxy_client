"""config 模块的单元测试（不依赖网络）。"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import find_config, load_config  # noqa: E402

BASE_CONFIG = {
    'trojan_host': 'example.com',
    'trojan_port': 443,
    'trojan_password': 'secret',
    'listen_host': '127.0.0.1',
    'listen_port': 10800,
}


def write_config(tmpdir, data, name='config.json'):
    path = os.path.join(tmpdir, name)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f)
    return path


class TestLoadConfig(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_defaults_filled(self):
        path = write_config(self.tmp.name, dict(BASE_CONFIG))
        config = load_config(path)
        self.assertEqual(config['timeout'], 10)
        self.assertEqual(config['idle_timeout'], 300)
        self.assertEqual(config['buffer_size'], 65536)
        self.assertEqual(config['users'], {})
        self.assertFalse(config['ssl_verify'])

    def test_missing_required_field(self):
        data = dict(BASE_CONFIG)
        del data['trojan_password']
        path = write_config(self.tmp.name, data)
        with self.assertRaises(ValueError):
            load_config(path)

    def test_invalid_port(self):
        data = dict(BASE_CONFIG, listen_port=70000)
        path = write_config(self.tmp.name, data)
        with self.assertRaises(ValueError):
            load_config(path)

    def test_invalid_log_level(self):
        data = dict(BASE_CONFIG, log_level='VERBOSE')
        path = write_config(self.tmp.name, data)
        with self.assertRaises(ValueError):
            load_config(path)

    def test_invalid_users(self):
        data = dict(BASE_CONFIG, users={'user': 123})
        path = write_config(self.tmp.name, data)
        with self.assertRaises(ValueError):
            load_config(path)

    def test_bad_json(self):
        path = os.path.join(self.tmp.name, 'config.json')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('{ not json ]')
        with self.assertRaises(json.JSONDecodeError):
            load_config(path)

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_config(os.path.join(self.tmp.name, 'nope.json'))


class TestFindConfig(unittest.TestCase):

    def test_explicit_path_missing(self):
        self.assertIsNone(find_config('Z:/definitely/not/here/config.json'))

    def test_explicit_path_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_config(tmp, dict(BASE_CONFIG))
            self.assertEqual(find_config(path), path)


if __name__ == '__main__':
    unittest.main()
