"""Tests for hasher module."""

import hashlib

from fim.hasher import calculate_sha256


def test_calculate_sha256_simple_file(tmp_path):
    file_path = tmp_path / "hello.txt"
    file_path.write_bytes(b"hello world")

    expected = hashlib.sha256(b"hello world").hexdigest()
    assert calculate_sha256(str(file_path)) == expected
